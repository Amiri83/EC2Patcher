"""Amazon Linux 2023: rpm inventory and Amazon's security advisories (ALAS, repository
updateinfo.xml fetched on the workstation). Read-only analysis only - planning and patching
are not supported yet (Amazon Linux 2 is end of life and not supported at all).

Model: CVE -> advisories that reference it in the updateinfo of the server's releasever (the
repository dnf uses on the server) and of the ``latest`` release -> fixed binary packages
(name, arch) grouped by source rpm -> installed versions (rpm EVR comparison):

* installed older than a fix in the server's own releasever: PATCH_AVAILABLE
* fixed only in a newer release: FIX_NOT_IN_CONFIGURED_REPOS (needs a newer releasever)
* installed at or above the fix: ALREADY_FIXED
* none of the fixed packages installed: PACKAGE_NOT_INSTALLED
* no advisory references the CVE: NO_ADVISORY (investigate; Amazon publishes no
  "not affected" statements in updateinfo)
"""

import re

from ec2patcher.services import amazon_state, amazon_updateinfo, cve_resolver, rpmversion
from ec2patcher.services.amazon_updateinfo import Advisory, AdvisoryPackage, UpdateInfo
from ec2patcher.services.cve_resolver import Finding
from ec2patcher.services.os_adapters.base import AnalysisContext, Assessment, OsAdapter
from ec2patcher.services.server_state import InstalledPackage, ServerFacts

PATCHING_UNSUPPORTED = "Patching not supported yet for Amazon Linux 2023 (analysis only)."
KERNEL_RE = re.compile(r"^kernel(?:\d+\.\d+)?$")
SEVERITY_ORDER = ("critical", "important", "medium", "low")
EXPLORER_URL = "https://explore.alas.aws.amazon.com/{cve}.html"


def _evr_key(version: str):
    return rpmversion.version_key(version)


def _severity_rank(severity: str | None) -> int:
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)


# (name, arch) -> (fixed package with the highest EVR, advisories fixing that binary)
Fixes = dict[tuple[str, str], tuple[AdvisoryPackage, list[Advisory]]]


def _fixes_by_source(
    advisories: list[Advisory], installed: dict[tuple[str, str], list], arch: str
) -> dict[str, Fixes]:
    """Fixed binaries per source rpm, for the server's architecture (and noarch)."""
    result: dict[str, Fixes] = {}
    for advisory in advisories:
        for pkg in advisory.packages:
            key = (pkg.name, pkg.arch)
            if pkg.arch not in (arch, "noarch") and key not in installed:
                continue  # src / other-architecture builds
            fixes = result.setdefault(pkg.source, {})
            if key not in fixes:
                fixes[key] = (pkg, [advisory])
                continue
            best, sources = fixes[key]
            order = rpmversion.compare_versions(pkg.evr, best.evr)
            if order > 0:
                fixes[key] = (pkg, [advisory])
            elif order == 0 and advisory not in sources:
                sources.append(advisory)
    return result


def _installed_version(
    name: str, packages: list[InstalledPackage], kernel: str
) -> tuple[str, str | None]:
    """(version compared against the fix, newest installed kernel if the running one is
    older). Kernels: the *running* kernel matters; other duplicates: the oldest."""
    versions = [p.version for p in packages]
    if not KERNEL_RE.match(name):
        return min(versions, key=_evr_key), None
    newest = max(versions, key=_evr_key)
    running = [p.version for p in packages if f"{p.version.split(':', 1)[-1]}.{p.architecture}"
               == kernel]  # fmt: skip
    if running:
        return max(running, key=_evr_key), newest
    return newest, None


def _ids(advisories: list[Advisory]) -> str:
    return ", ".join(sorted({a.id for a in advisories}))


def _max_fix(entries: list[tuple[AdvisoryPackage, list[Advisory]]]):
    return max(entries, key=lambda e: _evr_key(e[0].evr))


def resolve_source(
    cve: str,
    source: str,
    current: Fixes,
    newer: Fixes,
    installed: dict[tuple[str, str], list[InstalledPackage]],
    facts: amazon_state.AmazonFacts,
) -> Finding:
    """Status of one (CVE, source rpm) pair: ``current`` are the fixes published for the
    server's releasever, ``newer`` those of the latest release."""
    finding = Finding(cve=cve, source=source, status=cve_resolver.UNKNOWN)
    advisories = [a for _, advs in [*current.values(), *newer.values()] for a in advs]
    keys = sorted(set(current) | set(newer))
    present = [k for k in keys if installed.get(k)]
    finding.binaries = sorted({name for name, _ in present})
    finding.is_kernel = any(KERNEL_RE.match(name) for name, _ in present)
    if not present:
        best, advs = _max_fix([*current.values(), *newer.values()])
        finding.status = cve_resolver.PACKAGE_NOT_INSTALLED
        finding.fixed_version, finding.pocket = best.evr, _ids(advs)
        names = ", ".join(sorted({name for name, _ in keys}))
        finding.detail = f"{_ids(advisories)} fixes {names}; none of these packages is installed."
        return finding

    releasever = facts.releasever
    vulnerable_here, vulnerable_newer, fixed, pending_reboot = [], [], [], []
    versions = []
    for key in present:
        version, newest = _installed_version(key[0], installed[key], facts.kernel)
        versions.append(version)
        here, later = current.get(key), newer.get(key)
        if here and rpmversion.compare_versions(version, here[0].evr) < 0:
            entry = here
            target = vulnerable_here
        elif later and rpmversion.compare_versions(version, later[0].evr) < 0:
            entry = later
            target = vulnerable_newer
        else:
            fixed.append(here or later)
            continue
        if newest and rpmversion.compare_versions(newest, entry[0].evr) >= 0:
            pending_reboot.append((key[0], newest))  # a fixed kernel is installed, not running
            fixed.append(entry)
            continue
        target.append(entry)
    finding.installed_version = min(versions, key=_evr_key)

    if vulnerable_here:
        best, advs = _max_fix(vulnerable_here)
        finding.status = cve_resolver.PATCH_AVAILABLE
        finding.detail = (
            f"{_ids(advs)}: installed {finding.installed_version} is older than the fixed "
            f"{best.evr}, which is published in the repository of this server's release "
            f"({releasever})."
        )
    elif vulnerable_newer:
        best, advs = _max_fix(vulnerable_newer)
        finding.status = cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS
        finding.detail = (
            f"{_ids(advs)}: the fixed {best.evr} is only published for a newer Amazon Linux "
            f"2023 release, not in the repository of this server's releasever {releasever}. "
            f"{cve_resolver.NEWER_RELEASEVER_REQUIRED} (e.g. dnf upgrade --releasever=latest)."
        )
    else:
        best, advs = _max_fix(fixed)
        finding.status = cve_resolver.ALREADY_FIXED
        finding.detail = f"Installed version is at or above the fixed {best.evr} ({_ids(advs)})."
        if pending_reboot:
            name, newest = pending_reboot[0]
            finding.detail = (
                f"A fixed {name} ({newest}) is installed but the running kernel "
                f"({facts.kernel}) is older. A reboot into the new kernel is still pending."
            )
    finding.fixed_version, finding.pocket = best.evr, _ids(advs)
    return finding


def resolve_cve(
    cve: str,
    facts: amazon_state.AmazonFacts,
    current: UpdateInfo,
    latest: UpdateInfo | None,
) -> list[Finding]:
    """All findings (one per fixed source rpm) of one reported CVE. ``latest`` is None when
    the server itself follows the latest release."""
    cve = cve.strip().upper()
    newer_ok = latest is not None and latest.available
    if not current.available and not newer_ok:
        return [
            Finding(
                cve=cve, source=None, status=cve_resolver.METADATA_UNAVAILABLE,
                detail="Amazon Linux security advisories (updateinfo) are unavailable.",
            )
        ]  # fmt: skip
    here = current.for_cve(cve) if current.available else []
    later = latest.for_cve(cve) if newer_ok else []
    if not here and not later:
        checked = f"release {facts.releasever}" + (" or the latest release" if newer_ok else "")
        detail = (
            f"No Amazon Linux 2023 security advisory (ALAS) references this CVE in the "
            f"repository of {checked}: Amazon has not published a fix, or the CVE does not "
            f"affect Amazon Linux 2023 packages. See {EXPLORER_URL.format(cve=cve)}"
        )
        if not current.available:
            detail += f" (the advisories of release {facts.releasever} were unavailable)"
        elif latest is not None and not newer_ok:
            detail += " (newer releases could not be checked)"
        return [Finding(cve=cve, source=None, status=cve_resolver.NO_ADVISORY, detail=detail)]

    installed: dict[tuple[str, str], list[InstalledPackage]] = {}
    for pkg in facts.packages:
        installed.setdefault((pkg.name, pkg.architecture), []).append(pkg)
    current_fixes = _fixes_by_source(here, installed, facts.architecture)
    newer_fixes = _fixes_by_source(later, installed, facts.architecture)
    findings = []
    for source in sorted(set(current_fixes) | set(newer_fixes)):
        finding = resolve_source(
            cve, source, current_fixes.get(source, {}), newer_fixes.get(source, {}), installed,
            facts,
        )  # fmt: skip
        # Amazon's rating of the CVE: the highest of every advisory fixing this source.
        severities = [a.severity for a in here + later if a.severity
                      and any(p.source == source for p in a.packages)]  # fmt: skip
        finding.priority = min(severities, key=_severity_rank, default=None)
        if not current.available and finding.status == cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS:
            finding.status = cve_resolver.METADATA_UNAVAILABLE
            finding.detail = (
                f"Fixed in {finding.fixed_version} ({finding.pocket}), but the advisories of "
                f"release {facts.releasever} were unavailable, so whether the fix is published "
                "for this server's release is unknown."
            )
        findings.append(finding)
    if not findings:  # advisories list no package of this architecture
        findings.append(
            Finding(
                cve=cve, source=None, status=cve_resolver.PACKAGE_NOT_INSTALLED,
                detail=f"{_ids(here + later)} lists no {facts.architecture} package.",
            )
        )  # fmt: skip
    return findings


class AmazonLinuxAdapter(OsAdapter):
    os_id = "amzn"
    name = "Amazon Linux"
    supports_patching = False
    patching_unsupported = PATCHING_UNSUPPORTED

    # --- detection and facts ---------------------------------------------------------

    def matches(self, os_release: dict[str, str]) -> bool:
        return (
            os_release.get("ID", "") == self.os_id
            and os_release.get("VERSION_ID", "") == amazon_state.SUPPORTED_VERSION_ID
        )

    @property
    def facts_command(self) -> str:
        return amazon_state.FACTS_COMMAND

    def parse_facts(self, stdout: str) -> ServerFacts:
        return amazon_state.parse_facts(stdout)

    def check_supported(self, facts: ServerFacts) -> str | None:
        return amazon_state.check_supported(facts)

    def blocker(self, facts: ServerFacts) -> str | None:
        return None  # nothing is planned, so no package manager state blocks a plan

    def is_blocker(self, error: str) -> bool:
        return False

    # --- advisories --------------------------------------------------------------------

    def assess(
        self, facts: ServerFacts, reported_cves: list[str], ctx: AnalysisContext
    ) -> Assessment:
        source: amazon_updateinfo.UpdateInfoSource = ctx.advisories
        releasever, arch = facts.releasever, facts.architecture
        warnings = list(facts.warnings)
        if not reported_cves:
            return Assessment([], plan=[], warnings=warnings)  # nothing to look up
        ctx.progress(f"Fetching Amazon Linux advisories ({releasever}/{arch})")
        current = source.lookup(releasever, arch)
        latest = None
        if releasever != amazon_updateinfo.LATEST:
            ctx.progress(f"Fetching Amazon Linux advisories (latest/{arch})")
            latest = source.lookup(amazon_updateinfo.LATEST, arch)
        for label, info in ((f"release {releasever}", current), ("the latest release", latest)):
            if info is None:
                continue
            if info.status == amazon_updateinfo.STALE:
                warnings.append(
                    f"Amazon Linux advisories of {label} could not be refreshed ({info.error}); "
                    f"using cached data from {info.fetched_at}."
                )
            elif not info.available:
                warnings.append(f"Amazon Linux advisories of {label} are unavailable: {info.error}")
        if latest is not None and not latest.available and current.available:
            warnings.append("Fixes that need a newer releasever could not be detected.")
        findings: list[Finding] = []
        for cve in reported_cves:
            try:
                findings.extend(resolve_cve(cve, facts, current, latest))
            except Exception as exc:  # noqa: BLE001 - one bad CVE must not break the report
                findings.append(
                    Finding(
                        cve=cve, source=None, status=cve_resolver.ANALYSIS_ERROR,
                        detail=f"Analysis error: {exc}",
                    )
                )  # fmt: skip
        if facts.system_release and facts.system_release != releasever:
            warnings.append(
                f"dnf uses releasever {releasever} ({facts.releasever_source}); the installed "
                f"release is {facts.system_release}."
            )
        return Assessment(findings, plan=[], warnings=warnings)

    def expected_reboot(self, plan: list) -> tuple[bool | None, str | None]:
        return None, PATCHING_UNSUPPORTED  # nothing is planned

    # --- patch execution (not supported yet) -----------------------------------------

    def release_fields(self, analysis) -> list[tuple[str, str | None]]:
        return [
            ("Amazon Linux version", analysis.os_version_id),
            ("releasever", analysis.os_codename),
        ]

    def os_drift(self, facts: ServerFacts, analysis) -> list[str]:
        drift = []
        for label, now, then in (
            ("Hostname", facts.hostname, analysis.remote_hostname),
            ("Amazon Linux VERSION_ID", facts.version_id, analysis.os_version_id),
            ("releasever", facts.codename, analysis.os_codename),
            ("Architecture", facts.architecture, analysis.architecture),
        ):
            if now != then:
                drift.append(f"{label} changed: {then} -> {now}")
        if facts.os_id != self.os_id:
            drift.append(f"Operating system is not Amazon Linux ({facts.os_id or 'unknown'}).")
        return drift

    def plan_row_problems(self, row, architecture: str | None) -> list[str]:
        return [PATCHING_UNSUPPORTED]

    def compare_versions(self, a: str, b: str) -> int:
        return rpmversion.compare_versions(a, b)

    def version_key(self, version: str):
        return rpmversion.version_key(version)

    def at_or_above_target(self, current: str | None, target: str | None) -> bool:
        if not current or not target:
            return False
        try:
            return rpmversion.compare_versions(current, target) >= 0
        except rpmversion.InvalidVersionError:
            return current == target

    def same_version(self, a: str | None, b: str | None) -> bool:
        if not a or not b:
            return False
        try:
            return rpmversion.compare_versions(a, b) == 0
        except rpmversion.InvalidVersionError:
            return a == b

    def is_kernel_package(self, name: str) -> bool:
        return bool(KERNEL_RE.match(name))

    def _unsupported(self, *_args, **_kwargs):
        raise NotImplementedError(PATCHING_UNSUPPORTED)

    simulate_command = _unsupported
    check_simulation = _unsupported
    install_command = _unsupported
    parse_install = _unsupported
    post_install_command = _unsupported
    parse_post_install = _unsupported
    parse_reboot_check = _unsupported

    @property
    def reboot_check_command(self) -> str:
        raise NotImplementedError(PATCHING_UNSUPPORTED)
