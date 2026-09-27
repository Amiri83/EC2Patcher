"""CVE applicability: Canonical source-package status x installed packages x APT candidates.

Model: CVE -> Ubuntu *source* package(s) Canonical tracks for the server's release ->
installed *binary* packages built from that source (dpkg's source mapping) -> installed
source version -> Canonical fixed version (Debian version comparison) -> APT candidate for
each binary -> exact .deb plan.

Nothing is guessed: whenever a step cannot be answered with the available data the finding
says so explicitly (needs evaluation / candidate unavailable / error) instead of looking green.
"""

import re
from collections.abc import Callable
from dataclasses import dataclass, field

from ec2patcher.services import debversion
from ec2patcher.services.apt_planner import Candidate, DownloadPlan
from ec2patcher.services.security_metadata import CveRecord, VexEntry
from ec2patcher.services.server_state import InstalledPackage, ServerFacts
from ec2patcher.services.severity import normalize_severity

PATCH_REQUIRED = "PATCH_REQUIRED"
ALREADY_FIXED = "ALREADY_FIXED"
NOT_AFFECTED = "NOT_AFFECTED"
PACKAGE_NOT_INSTALLED = "PACKAGE_NOT_INSTALLED"
FIX_NOT_AVAILABLE = "FIX_NOT_AVAILABLE"
FIX_REQUIRES_PRO = "FIX_REQUIRES_PRO"
CANDIDATE_UNAVAILABLE = "CANDIDATE_UNAVAILABLE"
NEEDS_EVALUATION = "NEEDS_EVALUATION"
IGNORED = "IGNORED"
ANALYSIS_ERROR = "ANALYSIS_ERROR"

STATUS_LABELS = {
    PATCH_REQUIRED: "Patch required",
    ALREADY_FIXED: "Already fixed",
    NOT_AFFECTED: "Not affected",
    PACKAGE_NOT_INSTALLED: "Package not installed",
    FIX_NOT_AVAILABLE: "Fix not available",
    FIX_REQUIRES_PRO: "Fix requires Ubuntu Pro / ESM",
    CANDIDATE_UNAVAILABLE: "Fix known - suitable APT candidate not available",
    NEEDS_EVALUATION: "Under investigation / needs evaluation",
    IGNORED: "Ignored / no fix planned",
    ANALYSIS_ERROR: "Analysis error",
}

# When one CVE maps to several source packages, the CVE's overall status is the most
# action-relevant one (highest in this list).
STATUS_PRIORITY = [
    ANALYSIS_ERROR,
    PATCH_REQUIRED,
    CANDIDATE_UNAVAILABLE,
    FIX_REQUIRES_PRO,
    NEEDS_EVALUATION,
    FIX_NOT_AVAILABLE,
    IGNORED,
    ALREADY_FIXED,
    NOT_AFFECTED,
    PACKAGE_NOT_INSTALLED,
]

KERNEL_BINARY_RE = re.compile(
    r"^linux-(?:image|image-unsigned|modules|modules-extra|headers|tools|cloud-tools|buildinfo)"
    r"-\d+\.\d+\.\d+-\d+"
)
KERNEL_REBOOT_RE = re.compile(r"^linux-(?:image|modules|modules-extra)-(?:unsigned-)?\d+\.\d+")
REBOOT_HELP = (
    "Expected based on the planned package set. Final reboot requirement will be verified "
    "after installation in Phase 3."
)


@dataclass
class Finding:
    cve: str
    source: str | None
    status: str
    detail: str = ""
    installed_version: str | None = None
    fixed_version: str | None = None
    binaries: list[str] = field(default_factory=list)
    pocket: str | None = None  # distro the fixed version was published in
    priority: str | None = None  # raw Canonical priority, persisted as-is
    is_kernel: bool = False

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def severity(self) -> str:
        return normalize_severity(self.priority)


@dataclass
class PlanEntry:
    package: str
    architecture: str
    current_version: str | None
    target_version: str
    source: str | None = None
    deb_filename: str | None = None
    uri: str | None = None
    size: int | None = None
    checksum: str | None = None
    is_dependency: bool = False
    reboot_impact: str = "No reboot expected"
    requests_reboot: bool = False
    status: str = "planned"  # planned | unresolved
    reason: str | None = None
    cves: list[str] = field(default_factory=list)


def rollup_status(statuses: list[str]) -> str:
    for status in STATUS_PRIORITY:
        if status in statuses:
            return status
    return ANALYSIS_ERROR


def cve_statuses(findings: list[Finding]) -> dict[str, str]:
    """Overall status per CVE (in report order)."""
    grouped: dict[str, list[str]] = {}
    for f in findings:
        grouped.setdefault(f.cve, []).append(f.status)
    return {cve: rollup_status(statuses) for cve, statuses in grouped.items()}


def is_kernel_source(packages: list[InstalledPackage]) -> bool:
    return any(KERNEL_BINARY_RE.match(p.base_name) for p in packages)


def _max_version(versions: list[str]) -> str:
    return max(versions, key=debversion.version_key)


def _min_version(versions: list[str]) -> str:
    return min(versions, key=debversion.version_key)


def _installed_version(packages: list[InstalledPackage], kernel: str, is_kernel: bool):
    """(version compared against the fix, note). For kernels the *running* kernel matters."""
    versions = [p.source_version for p in packages]
    if not is_kernel:
        # Binaries of one source normally share a version; if not, the oldest is vulnerable.
        return _min_version(versions), None
    running = [p.source_version for p in packages if p.base_name.endswith(f"-{kernel}")]
    newest = _max_version(versions)
    if running:
        return _max_version(running), newest
    return newest, None


def _is_ignored(entry: VexEntry) -> bool:
    note = entry.note.lower()
    return (
        "decided to not fix" in note
        or "no longer supported" in note
        or "deferred" in note
        or "will not fix" in note
    )


def _unfixed_status(entry: VexEntry) -> tuple[str, str]:
    """Status for a statement that is not 'fixed' / 'not_affected'."""
    note = entry.note.strip()
    if _is_ignored(entry):
        return IGNORED, note or "Canonical does not plan to fix this package in this release."
    if entry.status == "under_investigation":
        return NEEDS_EVALUATION, note or "Canonical is still evaluating this CVE."
    if entry.status == "affected":
        return FIX_NOT_AVAILABLE, note or "Vulnerable; Canonical has not published a fix yet."
    return NEEDS_EVALUATION, f"Unrecognised Canonical status '{entry.status}'."


def _pick(entries: list[VexEntry], pro: bool) -> VexEntry | None:
    chosen = [e for e in entries if e.is_pro == pro]
    if not chosen:
        return None
    fixed = [e for e in chosen if e.status == "fixed"]
    if fixed:
        return max(fixed, key=lambda e: debversion.version_key(e.version))
    order = {"affected": 0, "under_investigation": 1, "not_affected": 2}
    return sorted(chosen, key=lambda e: order.get(e.status, -1))[0]


def resolve_source(
    cve: str,
    source: str,
    entries: list[VexEntry],
    installed: list[InstalledPackage],
    facts: ServerFacts,
) -> Finding:
    """Decide the status of one (CVE, source package) pair for this server."""
    finding = Finding(cve=cve, source=source, status=NEEDS_EVALUATION)
    finding.binaries = sorted(p.name for p in installed)
    finding.is_kernel = is_kernel_source(installed)
    standard, pro = _pick(entries, pro=False), _pick(entries, pro=True)
    finding.priority = next((e.priority for e in entries if e.priority), None)

    if not installed:
        finding.status = PACKAGE_NOT_INSTALLED
        finding.detail = f"No installed binary package is built from source '{source}'."
        return finding
    try:
        version, newest = _installed_version(installed, facts.kernel, finding.is_kernel)
    except debversion.InvalidVersionError as exc:
        finding.status, finding.detail = ANALYSIS_ERROR, str(exc)
        return finding
    finding.installed_version = version

    def fixed_by(entry: VexEntry) -> bool:
        return debversion.compare_versions(version, entry.version) >= 0

    try:
        if standard and standard.status == "fixed":
            finding.fixed_version, finding.pocket = standard.version, standard.distro
            if fixed_by(standard):
                finding.status = ALREADY_FIXED
                finding.detail = "Installed version is at or above Canonical's fixed version."
            else:
                finding.status = PATCH_REQUIRED
                finding.detail = "Installed version is older than Canonical's fixed version."
        elif standard and standard.status == "not_affected":
            finding.status = NOT_AFFECTED
            reason = standard.justification.replace("_", " ") or "not affected"
            finding.detail = f"Canonical: not affected ({reason})."
        elif pro and pro.status == "fixed":
            finding.fixed_version, finding.pocket = pro.version, pro.distro
            if fixed_by(pro):
                finding.status = ALREADY_FIXED
                finding.detail = f"Installed version includes the Ubuntu Pro fix ({pro.distro})."
            else:
                finding.status = FIX_REQUIRES_PRO
                finding.detail = f"The fix is only published in Ubuntu Pro ({pro.distro})." + (
                    f" Standard archive: {standard.note}" if standard and standard.note else ""
                )
        elif pro and pro.status == "not_affected" and standard is None:
            finding.status = NOT_AFFECTED
            reason = pro.justification.replace("_", " ") or "not affected"
            finding.detail = f"Canonical: not affected ({reason})."
        else:
            entry = standard or pro
            finding.status, finding.detail = _unfixed_status(entry)
    except debversion.InvalidVersionError as exc:
        finding.status, finding.detail = ANALYSIS_ERROR, str(exc)
        return finding

    # Kernels: the comparison above used the *running* kernel. If a fixed kernel is already
    # installed there is nothing to download - but the server stays vulnerable until reboot.
    if (
        finding.is_kernel
        and finding.status in (PATCH_REQUIRED, FIX_REQUIRES_PRO)
        and newest
        and debversion.compare_versions(newest, finding.fixed_version) >= 0
    ):
        finding.status = ALREADY_FIXED
        finding.detail = (
            f"A fixed kernel ({newest}) is installed but the running kernel ({facts.kernel}) "
            "is older. A reboot into the new kernel is still pending."
        )
    return finding


def resolve_cve(cve: str, record: CveRecord | None, facts: ServerFacts) -> list[Finding]:
    """All findings (one per relevant source package) for one reported CVE."""
    if record is None:
        return [
            Finding(
                cve=cve,
                source=None,
                status=NEEDS_EVALUATION,
                detail="CVE not found in Canonical's Ubuntu security metadata.",
            )
        ]
    by_source = facts.by_source()
    release_entries: dict[str, list[VexEntry]] = {}
    for entry in record.for_release(facts.codename):
        release_entries.setdefault(entry.source, []).append(entry)

    findings = [
        resolve_source(cve, source, entries, by_source.get(source, []), facts)
        for source, entries in sorted(release_entries.items())
    ]
    # Source packages Canonical tracks for other releases only: if one is installed here we
    # cannot tell whether it is affected - never report that as safe.
    for source in sorted(record.sources() - set(release_entries)):
        installed = by_source.get(source, [])
        if installed:
            findings.append(
                Finding(
                    cve=cve,
                    source=source,
                    status=NEEDS_EVALUATION,
                    installed_version=_min_version([p.source_version for p in installed]),
                    binaries=sorted(p.name for p in installed),
                    detail=(
                        f"Canonical lists '{source}' for other Ubuntu releases but has no "
                        f"statement for {facts.codename}."
                    ),
                )
            )
    if not findings and record.entries:
        findings.append(
            Finding(
                cve=cve,
                source=None,
                status=PACKAGE_NOT_INSTALLED,
                detail="None of the source packages Canonical tracks for this CVE are installed.",
            )
        )
    elif not findings:
        # Only statements for releases EC2Patcher does not support (e.g. xenial): no evidence
        # either way for this server, so do not report it as safe.
        findings.append(
            Finding(
                cve=cve,
                source=None,
                status=NEEDS_EVALUATION,
                detail=(
                    "Canonical's metadata has no statement for any supported Ubuntu release "
                    f"(including {facts.codename}) for this CVE."
                ),
            )
        )
    return findings


# --- APT candidates -------------------------------------------------------------------


def needs_candidate_check(finding: Finding) -> bool:
    return finding.status in (PATCH_REQUIRED, FIX_REQUIRES_PRO) and bool(finding.fixed_version)


def meta_packages(facts: ServerFacts) -> list[str]:
    """Installed kernel meta packages (e.g. linux-aws) - the upgrade path to a new kernel."""
    return sorted(p.name for p in facts.packages if p.source.startswith("linux-meta"))


def candidate_query_packages(findings: list[Finding], facts: ServerFacts) -> list[str]:
    names: set[str] = set()
    for f in findings:
        if not needs_candidate_check(f):
            continue
        names.update(meta_packages(facts) if f.is_kernel else f.binaries)
    return sorted(names)


def kernel_meta_version(kernel_version: str) -> str:
    """Ubuntu kernel meta packages use '.' where the kernel uses the ABI '-':
    kernel 6.8.0-1024.26 -> meta 6.8.0.1024.26."""
    return kernel_version.replace("-", ".", 1)


def apply_candidates(
    findings: list[Finding],
    candidates: dict[str, Candidate],
    facts: ServerFacts,
) -> list[tuple[str, str]]:
    """Check APT candidates; update statuses; return the (package, version) upgrade requests."""
    requests: dict[str, str] = {}
    stale = next((w for w in facts.warnings if "APT package lists" in w), None)
    for f in findings:
        if not needs_candidate_check(f):
            continue
        names = meta_packages(facts) if f.is_kernel else f.binaries
        if not names:
            f.status = CANDIDATE_UNAVAILABLE
            f.detail = (
                "No kernel meta package (e.g. linux-aws) is installed to select the fixed kernel."
            )
            continue
        wanted = kernel_meta_version(f.fixed_version) if f.is_kernel else f.fixed_version
        ok: dict[str, str] = {}
        problems: list[str] = []
        for name in names:
            cand = candidates.get(name)
            if cand is None or not cand.candidate:
                problems.append(f"{name}: no installation candidate in the configured APT sources")
                continue
            compare_to = cand.candidate if f.is_kernel else (cand.source_version or cand.candidate)
            try:
                good = debversion.compare_versions(compare_to, wanted) >= 0
            except debversion.InvalidVersionError:
                good = False
            if good:
                if cand.candidate != cand.installed:
                    ok[name] = cand.candidate
            else:
                problems.append(f"{name}: APT candidate {cand.candidate} is older than {wanted}")
        if problems:
            reasons = "; ".join(problems)
            if f.status == FIX_REQUIRES_PRO:
                f.detail = f"{f.detail} APT has no suitable candidate: {reasons}."
                continue
            f.status = CANDIDATE_UNAVAILABLE
            hint = f" {stale}" if stale else " Possible causes: APT lists not updated, repository"
            if not stale:
                hint += " missing from the APT configuration, or architecture mismatch."
            f.detail = f"Fixed version {f.fixed_version} is known but {reasons}.{hint}"
            continue
        if f.status == FIX_REQUIRES_PRO:
            f.status = PATCH_REQUIRED
            f.detail = (
                f"Fix available from Ubuntu Pro ({f.pocket}), which is enabled on this server."
            )
        if not ok:
            f.status = ANALYSIS_ERROR
            f.detail = "APT candidate equals the installed version although a fix is required."
            continue
        requests.update(ok)
    return sorted(requests.items())


# --- package plan ---------------------------------------------------------------------


def reboot_impact(package: str, requests_reboot: bool) -> str | None:
    base = package.split(":", 1)[0]
    if KERNEL_REBOOT_RE.match(base):
        return "Reboot expected (new kernel)"
    if requests_reboot:
        return "Reboot expected (package requests a reboot on upgrade)"
    return None


def build_plan(
    findings: list[Finding],
    download: DownloadPlan,
    candidates: dict[str, Candidate],
    facts: ServerFacts,
) -> list[PlanEntry]:
    """One entry per binary package / .deb, each linked to every CVE it helps fix."""
    installed = facts.by_name()
    cves_by_source: dict[str, set[str]] = {}
    kernel_cves: set[str] = set()
    for f in findings:
        if f.status == PATCH_REQUIRED and f.source:
            cves_by_source.setdefault(f.source, set()).add(f.cve)
            if f.is_kernel:
                kernel_cves.add(f.cve)
    requested = {name.split(":", 1)[0] for name, _ in download_requests(download)}
    # apt prints native-arch packages without the ":arch" suffix dpkg uses.
    by_base = {name.split(":", 1)[0]: cand for name, cand in candidates.items()}
    metas = {m.split(":", 1)[0] for m in meta_packages(facts)}

    entries: dict[tuple[str, str], PlanEntry] = {}
    for deb in download.packages:
        base = deb.package.split(":", 1)[0]
        inst = installed.get(deb.package) or installed.get(base)
        source = inst.source if inst else None
        cves = set(cves_by_source.get(source, set())) if source else set()
        if KERNEL_REBOOT_RE.match(base) or base in metas:
            cves |= kernel_cves
        cand = candidates.get(deb.package) or by_base.get(base)
        hook = bool(cand and cand.requests_reboot)
        impact = reboot_impact(base, hook)
        key = (base, deb.architecture)
        entry = PlanEntry(
            package=base,
            architecture=deb.architecture,
            current_version=deb.current_version,
            target_version=deb.target_version,
            source=source,
            deb_filename=deb.deb_filename,
            uri=deb.uri,
            size=deb.size,
            checksum=deb.checksum,
            is_dependency=base not in requested,
            reboot_impact=impact or "No reboot expected",
            requests_reboot=impact is not None,
            status="planned" if deb.deb_filename else "unresolved",
            reason=(f"Unable to resolve package download plan: {deb.error}" if deb.error else None),
            cves=sorted(cves),
        )
        entries[key] = entry
    return sorted(entries.values(), key=lambda e: (e.is_dependency, e.package))


def download_requests(download: DownloadPlan) -> list[tuple[str, str]]:
    """Recover the pinned (package, version) requests from the stored apt arguments."""
    result = []
    after = False
    for arg in download.apt_arguments:
        if arg == "--":
            after = True
            continue
        if after and "=" in arg:
            name, version = arg.split("=", 1)
            result.append((name, version))
    return result


def expected_reboot(plan: list[PlanEntry]) -> tuple[bool, str]:
    reasons = sorted({f"{e.package}: {e.reboot_impact}" for e in plan if e.requests_reboot})
    if reasons:
        return True, "; ".join(reasons)
    return False, "No planned package is known to require a reboot."


def resolve_all(
    cves: list[str], lookup: Callable[[str], CveRecord | None], facts: ServerFacts
) -> list[Finding]:
    findings: list[Finding] = []
    for cve in cves:
        try:
            findings.extend(resolve_cve(cve, lookup(cve), facts))
        except Exception as exc:  # noqa: BLE001 - one bad CVE must not break the server report
            findings.append(
                Finding(
                    cve=cve, source=None, status=ANALYSIS_ERROR, detail=f"Analysis error: {exc}"
                )
            )
    return findings
