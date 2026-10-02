"""Ubuntu: dpkg inventory, Canonical security metadata, workstation APT planning and the
install of explicit, verified local .deb files with apt-get.

A thin adapter over the existing Ubuntu modules (server_state, cve_resolver, local_apt,
apt_planner, patch_remote, debversion); module attributes are read at call time so the
behaviour is exactly that of those modules.
"""

from datetime import datetime, timezone

from ec2patcher.services import (
    apt_planner,
    cve_resolver,
    debversion,
    downloader,
    local_apt,
    patch_remote,
    server_state,
    staging,
)
from ec2patcher.services.os_adapters.base import AnalysisContext, Assessment, OsAdapter
from ec2patcher.services.server_state import ServerFacts


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class UbuntuAdapter(OsAdapter):
    os_id = "ubuntu"
    name = "Ubuntu"

    # --- detection and facts ---------------------------------------------------------

    def matches(self, os_release: dict[str, str]) -> bool:
        return os_release.get("ID", "") == self.os_id

    @property
    def facts_command(self) -> str:
        return server_state.FACTS_COMMAND

    def parse_facts(self, stdout: str) -> ServerFacts:
        return server_state.parse_facts(stdout)

    def check_supported(self, facts: ServerFacts) -> str | None:
        return server_state.check_supported(facts)

    def blocker(self, facts: ServerFacts) -> str | None:
        return server_state.dpkg_blocker(facts)

    def is_blocker(self, error: str) -> bool:
        return error.startswith(server_state.DPKG_BLOCKER)

    # --- Canonical metadata + workstation APT plan -------------------------------------

    def assess(
        self, facts: ServerFacts, reported_cves: list[str], ctx: AnalysisContext
    ) -> Assessment:
        metadata, apt, lookup = ctx.metadata, ctx.packages, ctx.lookup
        warnings = list(facts.warnings)
        metadata_status = metadata.status()
        if not metadata_status.available:
            lookup = lambda _cve: None  # noqa: E731
        elif lookup is None:
            lookup = metadata.lookup
        findings = cve_resolver.resolve_all(reported_cves, lookup, facts)
        if not metadata_status.available:
            warning = f"Canonical security metadata is unavailable: {metadata_status.error}"
            warnings.append(warning)
            for finding in findings:
                finding.status = cve_resolver.METADATA_UNAVAILABLE
                finding.detail = warning
        elif any(f.status == cve_resolver.METADATA_UNAVAILABLE for f in findings):
            warnings.append("Some Canonical metadata lookups failed; those CVEs remain unresolved.")
        elif any(f.status == cve_resolver.UNKNOWN for f in findings):
            warnings.append("Some CVEs have no usable Canonical statement for this Ubuntu release.")
        candidates: dict[str, apt_planner.Candidate] = {}
        requests: list[tuple[str, str]] = []
        state: local_apt.AptState | None = None
        query = cve_resolver.candidate_query_packages(findings, facts)
        if query:
            ctx.progress(
                f"Resolving APT candidates locally ({facts.codename}/{facts.architecture})"
            )
            try:
                state = apt.prepare(facts.codename, facts.architecture)
                ctx.record(
                    apt_updated_at=state.updated_at.isoformat(),
                    apt_age_hours=max(0.0, (_utcnow() - state.updated_at).total_seconds() / 3600),
                )
                candidates = apt.candidates(state, facts, query)
            except (local_apt.AptResolutionError, ValueError) as exc:
                warnings.append(f"Local APT resolution failed: {exc}")
                for f in findings:
                    if cve_resolver.needs_candidate_check(f):
                        f.status = cve_resolver.ANALYSIS_ERROR
                        f.detail = f"APT candidate check failed: {exc}"
            else:
                requests = cve_resolver.apply_candidates(findings, candidates, facts)

        plan: list[cve_resolver.PlanEntry] = []
        apt_arguments: list[str] = []
        if requests and state is not None:
            download = apt.plan(state, facts, requests)
            apt_arguments = download.apt_arguments
            if download.removals:
                warnings.append(
                    "APT would REMOVE these packages as part of the upgrade: "
                    + ", ".join(download.removals)
                )
            warnings.extend(f"APT: {m}" for m in download.messages[:10])
            same = cve_resolver.already_at_target(download)
            if same:
                warnings.append(
                    "Excluded from the plan (already at target: installed version is equal to "
                    "or newer than the target version): " + ", ".join(same)
                )
            if download.ok:
                plan = cve_resolver.build_plan(findings, download, candidates, facts)
            else:
                plan = self._unresolved_plan(findings, requests, candidates, facts, download.error)
        return Assessment(findings, plan, apt_arguments, warnings)

    @staticmethod
    def _unresolved_plan(findings, requests, candidates, facts, error) -> list:
        """Keep the required upgrades visible even when the .deb plan cannot be resolved."""
        installed = facts.by_name()
        cves_by_source: dict[str, set[str]] = {}
        for f in findings:
            if f.status == cve_resolver.PATCH_AVAILABLE and f.source:
                cves_by_source.setdefault(f.source, set()).add(f.cve)
        entries = []
        for name, version in requests:
            pkg = installed.get(name)
            source = pkg.source if pkg else None
            cand = candidates.get(name)
            impact = cve_resolver.reboot_impact(name, bool(cand and cand.requests_reboot))
            entries.append(
                cve_resolver.PlanEntry(
                    package=name.split(":", 1)[0],
                    architecture=pkg.architecture if pkg else facts.architecture,
                    current_version=pkg.version if pkg else None,
                    target_version=version,
                    source=source,
                    status="unresolved",
                    reason=f"Unable to resolve package download plan: {error}",
                    reboot_impact=impact or "No reboot expected",
                    requests_reboot=impact is not None,
                    cves=sorted(cves_by_source.get(source, set())),
                )
            )
        return entries

    def expected_reboot(self, plan: list) -> tuple[bool, str | None]:
        return cve_resolver.expected_reboot(plan)

    # --- patch execution -------------------------------------------------------------

    def release_fields(self, analysis) -> list[tuple[str, str | None]]:
        return [("Ubuntu version", analysis.os_version_id), ("codename", analysis.os_codename)]

    def os_drift(self, facts: ServerFacts, analysis) -> list[str]:
        drift = []
        for label, now, then in (
            ("Hostname", facts.hostname, analysis.remote_hostname),
            ("Ubuntu VERSION_ID", facts.version_id, analysis.os_version_id),
            ("Codename", facts.codename, analysis.os_codename),
            ("Architecture", facts.architecture, analysis.architecture),
        ):
            if now != then:
                drift.append(f"{label} changed: {then} -> {now}")
        if facts.os_id != self.os_id:
            drift.append(f"Operating system is not Ubuntu ({facts.os_id or 'unknown'}).")
        return drift

    def plan_row_problems(self, row, architecture: str | None) -> list[str]:
        name, p = row.binary_package, row
        reasons = []
        if not p.deb_filename or not staging.DEB_FILENAME_RE.match(p.deb_filename):
            reasons.append(f"{name}: .deb file name is missing or invalid.")
        if downloader.check_uri(p.uri):
            reasons.append(f"{name}: download URI is missing or unsupported.")
        if downloader.parse_sha256(p.checksum) is None:
            reasons.append(f"{name}: SHA256 checksum is unavailable.")
        if not p.size or p.size <= 0:
            reasons.append(f"{name}: download size is unknown.")
        if not p.target_version or not debversion.is_valid_version(p.target_version):
            reasons.append(f"{name}: target version is unresolved.")
            return reasons
        if not p.architecture or p.architecture not in (architecture, "all"):
            reasons.append(f"{name}: architecture {p.architecture or '?'} is unresolved.")
            return reasons
        if not apt_planner.PKG_NAME_RE.match(name) or ":" in name:
            reasons.append(f"{name}: unexpected package name.")
            return reasons
        expected = apt_planner.expected_deb_filename(name, p.target_version, p.architecture)
        if p.deb_filename and p.deb_filename != expected:
            reasons.append(f"{name}: plan is inconsistent (.deb {p.deb_filename} != {expected}).")
        elif p.uri and not apt_planner.uri_basename_matches(p.uri, expected):
            reasons.append(f"{name}: plan is inconsistent (URI does not point at {expected}).")
        if not p.is_dependency and not p.current_version:
            reasons.append(f"{name}: plan is inconsistent (installed version unknown).")
        if p.current_version and not debversion.is_valid_version(p.current_version):
            reasons.append(f"{name}: installed version is invalid.")
        return reasons

    def compare_versions(self, a: str, b: str) -> int:
        return debversion.compare_versions(a, b)

    def version_key(self, version: str):
        return debversion.version_key(version)

    def at_or_above_target(self, current: str | None, target: str | None) -> bool:
        return cve_resolver.at_or_above_target(current, target)

    def same_version(self, a: str | None, b: str | None) -> bool:
        return cve_resolver.same_version(a, b)

    def is_kernel_package(self, name: str) -> bool:
        return bool(cve_resolver.KERNEL_REBOOT_RE.match(name))

    def simulate_command(self, remote_dir: str, filenames: list[str]) -> str:
        return patch_remote.simulate_command(remote_dir, filenames)

    def check_simulation(self, stdout: str, expected: dict):
        parsed = patch_remote.parse_apt(stdout, "simulate")
        return parsed.output, patch_remote.check_simulation(parsed, expected)

    def install_command(self, remote_dir: str, filenames: list[str]) -> str:
        return patch_remote.install_command(remote_dir, filenames)

    def parse_install(self, stdout: str) -> patch_remote.AptResult:
        return patch_remote.parse_apt(stdout, "install")

    def post_install_command(self, packages: list[str]) -> str:
        return patch_remote.post_install_command(packages)

    def parse_post_install(self, stdout: str) -> patch_remote.PostInstallState | None:
        return patch_remote.parse_post_install(stdout)

    @property
    def reboot_check_command(self) -> str:
        return patch_remote.REBOOT_CHECK_COMMAND

    def parse_reboot_check(self, stdout: str) -> patch_remote.RebootCheck | None:
        return patch_remote.parse_reboot_check(stdout)
