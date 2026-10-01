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
from ec2patcher.services.nvd import CvssResult
from ec2patcher.services.security_metadata import CveRecord, VexEntry
from ec2patcher.services.server_state import InstalledPackage, ServerFacts
from ec2patcher.services.severity import normalize_severity

PATCH_AVAILABLE = "PATCH_AVAILABLE"
ALREADY_FIXED = "ALREADY_FIXED"
NOT_AFFECTED = "NOT_AFFECTED"
PACKAGE_NOT_INSTALLED = "PACKAGE_NOT_INSTALLED"
NO_FIX_PUBLISHED = "NO_FIX_PUBLISHED"
PRO_OR_ESM_REQUIRED = "PRO_OR_ESM_REQUIRED"
FIX_NOT_IN_CONFIGURED_REPOS = "FIX_NOT_IN_CONFIGURED_REPOS"
PENDING_OR_DEFERRED = "PENDING_OR_DEFERRED"
UNKNOWN = "UNKNOWN"
METADATA_UNAVAILABLE = "METADATA_UNAVAILABLE"
ANALYSIS_ERROR = "ANALYSIS_ERROR"

STATUS_LABELS = {
    PATCH_AVAILABLE: "Patch available",
    ALREADY_FIXED: "Already fixed",
    NOT_AFFECTED: "Not affected",
    PACKAGE_NOT_INSTALLED: "Package not installed",
    NO_FIX_PUBLISHED: "No fix published for this release",
    PRO_OR_ESM_REQUIRED: "Ubuntu Pro / ESM required",
    FIX_NOT_IN_CONFIGURED_REPOS: "Fixed version not in configured repositories",
    PENDING_OR_DEFERRED: "Pending or deferred by Canonical",
    UNKNOWN: "Canonical status unknown",
    METADATA_UNAVAILABLE: "Canonical metadata unavailable",
    ANALYSIS_ERROR: "Analysis error",
}

# Older stored snapshots remain readable under the current vocabulary. An old
# PATCH_REQUIRED row has no saved APT decision, so its historical meaning is ambiguous.
LEGACY_STATUSES = {
    "PATCH_REQUIRED": PATCH_AVAILABLE,
    "CANDIDATE_UNAVAILABLE": FIX_NOT_IN_CONFIGURED_REPOS,
    "FIX_REQUIRES_PRO": PRO_OR_ESM_REQUIRED,
    "FIX_NOT_AVAILABLE": NO_FIX_PUBLISHED,
    "NEEDS_EVALUATION": UNKNOWN,
    "IGNORED": PENDING_OR_DEFERRED,
}


def current_status(status: str) -> str:
    return LEGACY_STATUSES.get(status, status)


# When one CVE maps to several source packages, the CVE's overall status is the most
# action-relevant one (highest in this list).
STATUS_PRIORITY = [
    ANALYSIS_ERROR,
    PATCH_AVAILABLE,
    FIX_NOT_IN_CONFIGURED_REPOS,
    PRO_OR_ESM_REQUIRED,
    METADATA_UNAVAILABLE,
    UNKNOWN,
    PENDING_OR_DEFERRED,
    NO_FIX_PUBLISHED,
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
    # Contract for the patcher: act ONLY when status == PATCH_AVAILABLE, and only through an
    # analysis plan deduplicated by (package, target_version) - never by iterating raw CVE IDs.
    # Every other status (including FIX_NOT_IN_CONFIGURED_REPOS and PRO_OR_ESM_REQUIRED) is
    # informational; one package upgrade typically fixes many CVEs and must be applied once.
    status: str
    detail: str = ""
    installed_version: str | None = None
    fixed_version: str | None = None
    apt_candidate: str | None = None
    canonical_status: str | None = None
    binaries: list[str] = field(default_factory=list)
    pocket: str | None = None  # distro the fixed version was published in
    priority: str | None = None  # raw Canonical priority, persisted as-is ("Ubuntu Priority")
    is_kernel: bool = False
    # NVD CVSS enrichment (analysis_service); never affects the status above.
    cvss: CvssResult | None = None

    @property
    def status_label(self) -> str:
        return STATUS_LABELS.get(self.status, self.status)

    @property
    def severity(self) -> str:
        return normalize_severity(self.cvss.severity if self.cvss else None)


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
        entry.status in {"deferred", "pending", "ignored"}
        or "ignored" in note
        or "decided to not fix" in note
        or "no longer supported" in note
        or "deferred" in note
        or "pending" in note
        or "will not fix" in note
    )


def _unfixed_status(entry: VexEntry) -> tuple[str, str]:
    """Status for a statement that is not 'fixed' / 'not_affected'."""
    note = entry.note.strip()
    if _is_ignored(entry):
        return PENDING_OR_DEFERRED, note or f"Canonical marked this fix {entry.status}."
    if entry.status == "under_investigation":
        return NO_FIX_PUBLISHED, note or "Canonical is still evaluating this CVE."
    if entry.status == "affected":
        return NO_FIX_PUBLISHED, note or "Canonical has not published a fix for this release."
    return UNKNOWN, f"Unrecognised Canonical status '{entry.status}'."


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
    finding = Finding(cve=cve, source=source, status=UNKNOWN)
    finding.binaries = sorted(p.name for p in installed)
    finding.is_kernel = is_kernel_source(installed)
    standard, pro = _pick(entries, pro=False), _pick(entries, pro=True)
    authoritative = standard or pro
    finding.canonical_status = authoritative.status if authoritative else None
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
                finding.status = FIX_NOT_IN_CONFIGURED_REPOS
                finding.detail = "Installed version is older than Canonical's fixed version."
        elif standard and standard.status == "not_affected":
            finding.status = NOT_AFFECTED
            reason = standard.justification.replace("_", " ") or "not affected"
            finding.detail = f"Canonical: not affected ({reason})."
        elif pro and pro.status == "fixed":
            finding.canonical_status = pro.status
            finding.fixed_version, finding.pocket = pro.version, pro.distro
            if fixed_by(pro):
                finding.status = ALREADY_FIXED
                finding.detail = f"Installed version includes the Ubuntu Pro fix ({pro.distro})."
            else:
                finding.status = PRO_OR_ESM_REQUIRED
                finding.detail = f"The fix is only published in Ubuntu Pro ({pro.distro})." + (
                    f" Standard archive: {standard.note}" if standard and standard.note else ""
                )
        elif pro and pro.status == "not_affected" and standard is None:
            finding.canonical_status = pro.status
            finding.status = NOT_AFFECTED
            reason = pro.justification.replace("_", " ") or "not affected"
            finding.detail = f"Canonical: not affected ({reason})."
        else:
            entry = standard or pro
            finding.status, finding.detail = (
                _unfixed_status(entry)
                if entry
                else (UNKNOWN, "Canonical has no usable statement for this source package.")
            )
    except debversion.InvalidVersionError as exc:
        finding.status, finding.detail = ANALYSIS_ERROR, str(exc)
        return finding

    # Kernels: the comparison above used the *running* kernel. If a fixed kernel is already
    # installed there is nothing to download - but the server stays vulnerable until reboot.
    if (
        finding.is_kernel
        and finding.status in (FIX_NOT_IN_CONFIGURED_REPOS, PRO_OR_ESM_REQUIRED)
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
                status=UNKNOWN,
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
                    status=UNKNOWN,
                    installed_version=_min_version([p.source_version for p in installed]),
                    binaries=sorted(p.name for p in installed),
                    detail=(
                        f"Canonical lists '{source}' for other Ubuntu releases but has no "
                        f"statement for {facts.codename}."
                    ),
                )
            )
    if not findings and record.sources():
        # Canonical tracks this CVE only for other releases (for this release the sources
        # are e.g. DNE) and none of those sources is installed here: nothing to act on.
        findings.append(
            Finding(
                cve=cve,
                source=None,
                status=PACKAGE_NOT_INSTALLED,
                detail=(
                    "None of the source packages Canonical tracks for this CVE are installed "
                    f"({', '.join(sorted(record.sources()))})."
                ),
            )
        )
    elif not findings:
        # No usable statement for any supported release (e.g. xenial only): no evidence
        # either way for this server, so do not report it as safe.
        findings.append(
            Finding(
                cve=cve,
                source=None,
                status=UNKNOWN,
                detail=(
                    "Canonical's metadata has no statement for any supported Ubuntu release "
                    f"(including {facts.codename}) for this CVE."
                ),
            )
        )
    return findings


# --- APT candidates -------------------------------------------------------------------


def needs_candidate_check(finding: Finding) -> bool:
    return finding.status in (FIX_NOT_IN_CONFIGURED_REPOS, PRO_OR_ESM_REQUIRED) and bool(
        finding.fixed_version
    )


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
    """Check APT candidates; update statuses; return the (package, version) upgrade requests.

    Candidates come from the workstation's private, freshly updated APT lists for the server's
    release and architecture (see local_apt), so a candidate older than Canonical's fix means
    the fix is genuinely not published in <release>, -updates or -security."""
    requests: dict[str, str] = {}
    installed = facts.by_name()
    archive = f"{facts.codename}, {facts.codename}-updates, {facts.codename}-security"
    for f in findings:
        if not needs_candidate_check(f):
            continue
        names = meta_packages(facts) if f.is_kernel else f.binaries
        if not names:
            f.status = FIX_NOT_IN_CONFIGURED_REPOS
            f.detail = (
                "No kernel meta package (e.g. linux-aws) is installed to select the fixed kernel."
            )
            continue
        wanted = kernel_meta_version(f.fixed_version) if f.is_kernel else f.fixed_version
        ok: dict[str, str] = {}
        problems: list[str] = []
        at_target: list[str] = []
        for name in names:
            cand = candidates.get(name)
            if cand and cand.candidate:
                f.apt_candidate = (
                    f"{f.apt_candidate}; {name}: {cand.candidate}"
                    if f.apt_candidate
                    else f"{name}: {cand.candidate}"
                )
            if cand is None or not cand.candidate:
                problems.append(f"{name}: no installation candidate in the Ubuntu archive")
                continue
            compare_to = cand.candidate if f.is_kernel else (cand.source_version or cand.candidate)
            try:
                good = debversion.compare_versions(compare_to, wanted) >= 0
            except debversion.InvalidVersionError:
                good = False
            if good:
                pkg = installed.get(name) or installed.get(name.split(":", 1)[0])
                current = pkg.version if pkg else cand.installed  # the server's dpkg decides
                if at_or_above_target(current, cand.candidate):
                    at_target.append(f"{name} {current}")
                else:
                    ok[name] = cand.candidate
            else:
                problems.append(f"{name}: APT candidate {cand.candidate} is older than {wanted}")
        if problems:
            reasons = "; ".join(problems)
            if f.status == PRO_OR_ESM_REQUIRED:
                f.detail = f"{f.detail} The Ubuntu archive has no suitable candidate: {reasons}."
                continue
            f.status = FIX_NOT_IN_CONFIGURED_REPOS
            f.detail = (
                f"Fixed version {f.fixed_version} is known but {reasons}. The workstation's "
                f"private APT lists ({archive}, {facts.architecture}) were current for this "
                "analysis, so the fix is not published in those pockets."
            )
            continue
        if f.status == PRO_OR_ESM_REQUIRED:
            f.status = PATCH_AVAILABLE
            f.detail = f"The Ubuntu archive ({archive}) already offers a fixed version."
        if not ok:
            # Every binary is already at (or above) a candidate that carries the fix: nothing
            # to install for this CVE, which must not block the rest of the server's plan.
            f.status = ALREADY_FIXED
            f.detail = (
                "Installed binary package(s) already at or above the fixed APT candidate: "
                + ", ".join(at_target)
                + "."
            )
            continue
        f.status = PATCH_AVAILABLE
        requests.update(ok)
    return sorted(requests.items())


# --- package plan ---------------------------------------------------------------------


def same_version(installed: str | None, target: str | None) -> bool:
    """True if a package installed at ``installed`` is already at ``target`` (Debian
    comparison, so '0:1.0' equals '1.0')."""
    if not installed or not target:
        return False
    try:
        return debversion.compare_versions(installed, target) == 0
    except debversion.InvalidVersionError:
        return installed == target


def at_or_above_target(installed: str | None, target: str | None) -> bool:
    """True if a package installed at ``installed`` needs no upgrade to ``target`` (equal or
    newer by Debian comparison). Such a package is excluded from plans, never an error."""
    if not installed or not target:
        return False
    try:
        return debversion.compare_versions(installed, target) >= 0
    except debversion.InvalidVersionError:
        return installed == target


def already_at_target(download: DownloadPlan) -> list[str]:
    """Packages APT listed whose installed version is at or above the target (excluded from
    plans)."""
    return sorted(
        {
            f"{d.package.split(':', 1)[0]} {d.target_version}"
            for d in download.packages
            if at_or_above_target(d.current_version, d.target_version)
        }
    )


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
        if f.status == PATCH_AVAILABLE and f.source:
            cves_by_source.setdefault(f.source, set()).add(f.cve)
            if f.is_kernel:
                kernel_cves.add(f.cve)
    requested = {name.split(":", 1)[0] for name, _ in download_requests(download)}
    # apt prints native-arch packages without the ":arch" suffix dpkg uses.
    by_base = {name.split(":", 1)[0]: cand for name, cand in candidates.items()}
    metas = {m.split(":", 1)[0] for m in meta_packages(facts)}

    entries: dict[tuple[str, str], PlanEntry] = {}
    for deb in download.packages:
        if at_or_above_target(deb.current_version, deb.target_version):
            continue  # nothing to upgrade: never planned (see already_at_target)
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
            record = lookup(cve)
        except Exception as exc:  # noqa: BLE001 - one bad CVE must not break the server report
            findings.append(
                Finding(
                    cve=cve,
                    source=None,
                    status=METADATA_UNAVAILABLE,
                    detail=f"Canonical metadata lookup failed: {exc}",
                )
            )
            continue
        try:
            resolved = resolve_cve(cve, record, facts)
        except Exception as exc:  # noqa: BLE001 - one bad CVE must not break the server report
            findings.append(
                Finding(
                    cve=cve, source=None, status=ANALYSIS_ERROR, detail=f"Analysis error: {exc}"
                )
            )
            continue
        note = record.cache_note if record is not None else None
        if note:  # ubuntu.com was unreachable: say which verdicts rest on older data
            for finding in resolved:
                finding.detail = f"{finding.detail} ({note})" if finding.detail else note
        findings.extend(resolved)
    return findings
