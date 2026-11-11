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
# Amazon Linux: no security advisory (ALAS) references the CVE for the server's release.
NO_ADVISORY = "NO_ADVISORY"
# Opt-in fallbacks (Settings -> APT Repositories), never set by default. Both are planned like a
# patch but never approved without the operator's explicit confirmation (patch_service).
# No Canonical metadata could be had, but the mirror offers a newer candidate for an installed
# source package the CVE is linked to (allow_unconfirmed_candidates).
CANDIDATE_WITHOUT_METADATA = "CANDIDATE_WITHOUT_METADATA"
# Canonical says the fix is pending publication with a version the mirror's candidate already
# reaches (allow_pending_candidates).
FIX_AVAILABLE_PENDING_PUBLICATION = "FIX_AVAILABLE_PENDING_PUBLICATION"
UNCONFIRMED_STATUSES = frozenset({CANDIDATE_WITHOUT_METADATA, FIX_AVAILABLE_PENDING_PUBLICATION})
PLANNED_STATUSES = frozenset({PATCH_AVAILABLE}) | UNCONFIRMED_STATUSES
# Detail of an Amazon Linux FIX_NOT_IN_CONFIGURED_REPOS finding (kept in report groups).
NEWER_RELEASEVER_REQUIRED = "The fix needs a newer releasever"

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
    NO_ADVISORY: "No Amazon Linux advisory",
    CANDIDATE_WITHOUT_METADATA: "Newer candidate, no Canonical metadata (needs confirmation)",
    FIX_AVAILABLE_PENDING_PUBLICATION: "Fix available, pending publication (needs confirmation)",
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
    FIX_AVAILABLE_PENDING_PUBLICATION,
    CANDIDATE_WITHOUT_METADATA,
    FIX_NOT_IN_CONFIGURED_REPOS,
    PRO_OR_ESM_REQUIRED,
    METADATA_UNAVAILABLE,
    UNKNOWN,
    NO_ADVISORY,
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
# Built from the kernel source but userspace only: upgrading them never needs a reboot.
KERNEL_USERSPACE_RE = re.compile(r"^linux-(?:tools|cloud-tools|headers)-")
NO_REBOOT = "No reboot expected"
KERNEL_TOOLS_NO_REBOOT = "Tools only, no reboot (kernel userspace package, not a new kernel)"
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
    # The source that resolved it (oval, notices, changelog, cve-json, updateinfo), or why none did.
    resolution_source: str | None = None
    failure_reason: str | None = None
    # KEV / EPSS enrichment (analysis_service): priority only, never affects the status either.
    kev: bool | None = None
    epss: float | None = None
    # The APT mirror(s) its lookups used: "changelog: <url>", "apt: <url> <suite>" ("; ").
    mirror: str | None = None

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


def _pending_version(entry: VexEntry) -> bool:
    """Canonical says a fix is pending publication and names its version."""
    return entry.justification == "pending" and debversion.is_valid_version(entry.version or "")


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
            if entry is not None and _pending_version(entry):
                # Kept for the report and the opt-in candidate check (apply_unconfirmed).
                finding.fixed_version, finding.pocket = entry.version, entry.distro
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


def kernel_meta_source(source: str) -> str:
    """The meta source package of a kernel source: linux -> linux-meta,
    linux-aws-7.0 -> linux-meta-aws-7.0 (linux-signed-aws -> linux-meta-aws)."""
    flavour = source.removeprefix("linux").removeprefix("-signed")
    return f"linux-meta{flavour}"


_ABI_RE = re.compile(r"^(\d+\.\d+\.\d+-\d+)")


def kernel_abi(version_or_release: str) -> str | None:
    """The kernel ABI: 7.0.0-1014.14~24.04.1 -> 7.0.0-1014, 7.0.0-1013-aws -> 7.0.0-1013."""
    m = _ABI_RE.match(version_or_release or "")
    return m.group(1) if m else None


def kernel_abi_targets(facts: ServerFacts, finding: Finding) -> dict[str, str]:
    """{new package: installed package} for a kernel line without any meta package: every
    installed package of this kernel line (its source or its signed source) carrying the
    running kernel's ABI, renamed to the ABI of the fixed version
    (linux-image-7.0.0-1013-aws -> linux-image-7.0.0-1014-aws). Empty when the fix is not a
    newer ABI of the running kernel."""
    old, new = kernel_abi(facts.kernel or ""), kernel_abi(finding.fixed_version or "")
    if not old or not new or old == new or not finding.source:
        return {}
    flavour = finding.source.removeprefix("linux").removeprefix("-signed")
    sources = {finding.source, f"linux{flavour}", f"linux-signed{flavour}"}
    targets = {}
    for p in facts.packages:
        if p.source in sources and old in p.base_name:
            targets[p.base_name.replace(old, new)] = p.base_name
    return dict(sorted(targets.items()))


def kernel_upgrade_packages(facts: ServerFacts, finding: Finding) -> list[str]:
    """What selects the fixed kernel: the meta packages of its line, else (no meta package
    installed, e.g. removed by 'apt-get install -f') the fixed ABI's own packages."""
    metas = kernel_meta_packages(facts, finding.source)
    return metas or list(kernel_abi_targets(facts, finding))


def kernel_meta_packages(facts: ServerFacts, source: str | None) -> list[str]:
    """Installed meta packages of *this* kernel source. A server often has several kernel
    lines (e.g. linux-aws 6.8 and linux-aws-7.0); another line's meta package can never
    reach this source's fixed version, so it must not decide the finding. Falls back to all
    meta packages when none matches the source."""
    meta_source = kernel_meta_source(source) if source else None
    own = sorted(p.name for p in facts.packages if meta_source and p.source == meta_source)
    return own or meta_packages(facts)


def candidate_query_packages(findings: list[Finding], facts: ServerFacts) -> list[str]:
    names: set[str] = set()
    for f in findings:
        if not needs_candidate_check(f):
            continue
        names.update(kernel_upgrade_packages(facts, f) if f.is_kernel else f.binaries)
    return sorted(names)


def kernel_meta_target(fixed_version: str, meta_candidate: str) -> str:
    """The version a kernel meta package must reach for ``fixed_version``. Older meta packages
    use the dotted scheme (kernel 6.8.0-1024.26 -> meta 6.8.0.1024.26); newer ones (e.g.
    noble's linux-aws 7.0.0-1014.14~24.04.1) carry the kernel version unchanged. Comparing a
    dash-scheme candidate with the dotted target would always find it older."""
    upstream = meta_candidate.split(":", 1)[-1]
    return fixed_version if "-" in upstream else kernel_meta_version(fixed_version)


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
        names = kernel_upgrade_packages(facts, f) if f.is_kernel else f.binaries
        if not names:
            f.status = FIX_NOT_IN_CONFIGURED_REPOS
            f.detail = (
                "No kernel meta package (e.g. linux-aws) is installed to select the fixed "
                "kernel, and the fix is not a newer ABI of the running kernel."
            )
            continue
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
                add_mirrors(f, candidate_mirrors(cand))
            if cand is None or not cand.candidate:
                problems.append(f"{name}: no installation candidate in the Ubuntu archive")
                continue
            compare_to = cand.candidate if f.is_kernel else (cand.source_version or cand.candidate)
            wanted = (
                kernel_meta_target(f.fixed_version, cand.candidate)
                if f.is_kernel
                else f.fixed_version
            )
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


def candidate_mirrors(cand: Candidate) -> list[str]:
    """Each repository line offering the candidate, as "apt: <mirror> <suite>"."""
    result = []
    for origin in cand.origins:
        parts = origin.split()
        if parts and parts[0].startswith(("http://", "https://")):
            suite = parts[1].split("/", 1)[0] if len(parts) > 1 else ""
            result.append(f"apt: {parts[0]} {suite}".rstrip())
    return result


def add_mirrors(finding: Finding, mirrors: list[str]) -> None:
    known = finding.mirror.split("; ") if finding.mirror else []
    finding.mirror = "; ".join(dict.fromkeys([*known, *mirrors])) or None


# --- opt-in fallbacks (Settings -> APT Repositories), off by default ------------------------


def expand_unconfirmed(
    findings: list[Finding], facts: ServerFacts, related: Callable[[str], list[str]]
) -> list[Finding]:
    """Give each METADATA_UNAVAILABLE finding without a source package one finding per installed
    source package the CVE is linked to (``related``: the pasted list, OVAL of other releases,
    the USNs), so their candidates can be checked. They stay METADATA_UNAVAILABLE until then."""
    by_source = facts.by_source()
    result: list[Finding] = []
    for f in findings:
        sources = []
        if f.status == METADATA_UNAVAILABLE and f.source is None:
            sources = [s for s in dict.fromkeys(related(f.cve)) if by_source.get(s)]
        if not sources:
            result.append(f)
            continue
        for source in sources:
            installed = by_source[source]
            try:
                version = _min_version([p.source_version for p in installed])
            except debversion.InvalidVersionError:
                version = None
            result.append(
                Finding(
                    cve=f.cve,
                    source=source,
                    status=METADATA_UNAVAILABLE,
                    detail=f.detail,
                    installed_version=version,
                    binaries=sorted(p.name for p in installed),
                    is_kernel=is_kernel_source(installed),
                    failure_reason=f.failure_reason,
                    mirror=f.mirror,
                )
            )
    return result


def needs_unconfirmed_check(f: Finding, allow_unconfirmed: bool, allow_pending: bool) -> bool:
    """A finding the opt-in fallbacks check against the mirror's candidates. Kernels never are:
    their upgrade path (meta packages, ABI) is only decided by Canonical's fixed version."""
    if f.is_kernel or not f.source or not f.binaries:
        return False
    if allow_unconfirmed and f.status == METADATA_UNAVAILABLE:
        return True
    return allow_pending and f.status == PENDING_OR_DEFERRED and bool(f.fixed_version)


def unconfirmed_query_packages(
    findings: list[Finding], allow_unconfirmed: bool, allow_pending: bool
) -> list[str]:
    names: set[str] = set()
    for f in findings:
        if needs_unconfirmed_check(f, allow_unconfirmed, allow_pending):
            names.update(f.binaries)
    return sorted(names)


def _newer(candidate: str, current: str | None) -> bool:
    if not current:
        return True
    try:
        return debversion.compare_versions(candidate, current) > 0
    except debversion.InvalidVersionError:
        return False


def apply_unconfirmed(
    findings: list[Finding],
    candidates: dict[str, Candidate],
    facts: ServerFacts,
    allow_unconfirmed: bool,
    allow_pending: bool,
) -> list[tuple[str, str]]:
    """The opt-in candidate checks; update statuses and return the (package, version) upgrade
    requests. Nothing here is ever approved without the operator's explicit confirmation.

    - METADATA_UNAVAILABLE (``allow_unconfirmed``): a candidate newer than the installed
      binary -> CANDIDATE_WITHOUT_METADATA. Whether it fixes the CVE is not confirmed.
    - Pending publication with a version (``allow_pending``): every binary's candidate at or
      above that version -> FIX_AVAILABLE_PENDING_PUBLICATION."""
    requests: dict[str, str] = {}
    installed = facts.by_name()
    for f in findings:
        if not needs_unconfirmed_check(f, allow_unconfirmed, allow_pending):
            continue
        pending = f.status == PENDING_OR_DEFERRED
        newer: dict[str, str] = {}
        problems: list[str] = []
        for name in f.binaries:
            cand = candidates.get(name)
            if cand is None or not cand.candidate:
                problems.append(f"{name}: no installation candidate in the configured mirrors")
                continue
            entry = f"{name}: {cand.candidate}"
            f.apt_candidate = f"{f.apt_candidate}; {entry}" if f.apt_candidate else entry
            add_mirrors(f, candidate_mirrors(cand))
            pkg = installed.get(name) or installed.get(name.split(":", 1)[0])
            current = pkg.version if pkg else cand.installed
            if pending:
                compare_to = cand.source_version or cand.candidate
                try:
                    good = debversion.compare_versions(compare_to, f.fixed_version) >= 0
                except debversion.InvalidVersionError:
                    good = False
                if not good:
                    problems.append(
                        f"{name}: APT candidate {cand.candidate} is older than the pending "
                        f"version {f.fixed_version}"
                    )
                    continue
            if _newer(cand.candidate, current):
                newer[name] = cand.candidate
        if pending:
            _pending_outcome(f, newer, problems, requests)
        else:
            _unconfirmed_outcome(f, newer, requests)
    return sorted(requests.items())


def _unconfirmed_outcome(f: Finding, newer: dict[str, str], requests: dict[str, str]) -> None:
    if not newer:
        f.detail = f"{f.detail} The configured mirrors offer no newer version of {f.source}."
        return
    offered = ", ".join(f"{name} {version}" for name, version in sorted(newer.items()))
    f.status = CANDIDATE_WITHOUT_METADATA
    f.detail = (
        f"No Canonical metadata could be had for this CVE, but the configured mirrors offer a "
        f"newer version of {f.source} ({offered}). Whether it fixes the CVE is not confirmed: "
        "patching it needs an explicit confirmation."
    )
    requests.update(newer)


def _pending_outcome(
    f: Finding, newer: dict[str, str], problems: list[str], requests: dict[str, str]
) -> None:
    if problems:
        f.detail = f"{f.detail} Pending version {f.fixed_version}: {'; '.join(problems)}."
        return
    if not newer:
        f.detail = (
            f"{f.detail} The installed binary package(s) are already at or above the APT "
            f"candidate, which reaches the pending version {f.fixed_version}."
        )
        return
    f.status = FIX_AVAILABLE_PENDING_PUBLICATION
    f.detail = (
        f"Canonical lists the fix as pending publication ({f.fixed_version}); the configured "
        "mirrors already offer it. Patching it needs an explicit confirmation."
    )
    requests.update(newer)


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


def no_reboot_label(package: str) -> str:
    """Reboot impact text of a package that needs no reboot: kernel tools/headers say so, so
    they are not mistaken for a kernel patch."""
    base = package.split(":", 1)[0]
    return KERNEL_TOOLS_NO_REBOOT if KERNEL_USERSPACE_RE.match(base) else NO_REBOOT


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
        if f.status in PLANNED_STATUSES and f.source:
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
            reboot_impact=impact or no_reboot_label(base),
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


def mark_origin(findings: list[Finding], origin: str) -> None:
    """Record the source behind each finding, or what that source could not say."""
    for finding in findings:
        if finding.status == UNKNOWN:
            finding.failure_reason = f"{origin}: no usable statement for this release"
        elif finding.status == METADATA_UNAVAILABLE:
            finding.failure_reason = f"{origin}: data unavailable"
        elif finding.status == ANALYSIS_ERROR:
            finding.failure_reason = f"{origin}: analysis error"
        else:
            finding.resolution_source = origin


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
                    failure_reason=getattr(exc, "failure_reason", None) or f"cve-json: {exc}",
                )
            )
            continue
        try:
            resolved = resolve_cve(cve, record, facts)
        except Exception as exc:  # noqa: BLE001 - one bad CVE must not break the server report
            findings.append(
                Finding(
                    cve=cve,
                    source=None,
                    status=ANALYSIS_ERROR,
                    detail=f"Analysis error: {exc}",
                    failure_reason="analysis error",
                )
            )
            continue
        if record is None:
            mark_origin(resolved, "cve-json")
            for finding in resolved:
                finding.failure_reason = "no source knows this CVE"
        else:
            mark_origin(resolved, record.origin)
        note = record.cache_note if record is not None else None
        if note:  # ubuntu.com was unreachable: say which verdicts rest on older data
            for finding in resolved:
                finding.detail = f"{finding.detail} ({note})" if finding.detail else note
        mirror = getattr(record, "mirror", None)
        if mirror:  # the changelog fallback read this mirror
            for finding in resolved:
                add_mirrors(finding, [mirror])
        findings.extend(resolved)
    return findings
