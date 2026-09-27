"""Phase 2 orchestration: analyze the latest report, server by server, and persist results.

Read-only by design. For each server the analyzer runs three fixed ssh commands as the
unprivileged ``ubuntu`` user (no sudo): collect facts (dpkg-query, os-release, uname, ...),
query APT candidates (apt-cache), and plan the upgrade (apt-get -s / --print-uris). Nothing
is downloaded, copied, installed or restarted.

Canonical's metadata alone decides applicability, fixed versions and statuses. NVD is only
queried afterwards for the CVSS severity of the server's CVEs (each unique CVE once per run,
shared by all servers); an NVD failure leaves the severity Unknown and nothing else changes.

Servers are analyzed sequentially in one background thread; one failing server (or CVE)
never aborts the others.
"""

import logging
import subprocess
import threading
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from ec2patcher.database import Database
from ec2patcher.models import ServerAnalysis, StoredReport
from ec2patcher.services import apt_planner, cve_resolver, nvd, server_state, ssh_service
from ec2patcher.services.security_metadata import SecurityMetadata
from ec2patcher.services.severity import SEVERITIES, UNKNOWN

logger = logging.getLogger(__name__)

FACTS_TIMEOUT_SECONDS = 90
CANDIDATE_TIMEOUT_SECONDS = 90
PLAN_TIMEOUT_SECONDS = 180
DISPLAY_NAME_TAG = "display_name"

Starter = Callable[[Callable[[], None]], None]


def thread_starter(target: Callable[[], None]) -> None:
    threading.Thread(target=target, name="ec2patcher-analysis", daemon=True).start()


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


class AnalysisService:
    def __init__(
        self,
        db: Database,
        metadata: SecurityMetadata,
        runner: ssh_service.Runner = subprocess.run,
        starter: Starter = thread_starter,
        nvd_client: nvd.NvdClient | None = None,
    ):
        self.db = db
        self.metadata = metadata
        self.nvd = nvd_client or nvd.NvdClient()
        self.runner = runner
        self.starter = starter
        self._lock = threading.Lock()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    def start(self, report: StoredReport) -> int | None:
        """Create a new run for ``report`` and analyze it in the background.

        Returns the run id, or None if another analysis is still running.
        """
        with self._lock:
            if self._running:
                return None
            self._running = True
        try:
            servers = []
            for name in report.servers:
                match = self.db.get_server_by_name(name)
                # Report keys must equal the canonical Server Name; display_name never matches.
                server = self.db.get_server(match.id) if match and match.name == name else None
                display = None
                if server:
                    display = next(
                        (t.value for t in server.tags if t.key.casefold() == DISPLAY_NAME_TAG),
                        None,
                    )
                servers.append((name, server, display))
            run_id = self.db.create_analysis_run(report, servers)
        except Exception:
            self._running = False
            raise
        logger.info("Analysis run %s started for report %s", run_id, report.filename)
        try:
            self.starter(lambda: self._run_safely(run_id))
        except Exception:
            self._running = False
            self.db.update_analysis_run(
                run_id, status="failed", completed_at=_now(), error="Could not start the analysis."
            )
            raise
        return run_id

    def _run_safely(self, run_id: int) -> None:
        try:
            self.run(run_id)
        except Exception as exc:
            logger.exception("Analysis run %s crashed", run_id)
            self.db.update_analysis_run(
                run_id, status="failed", completed_at=_now(), progress_message=None,
                error=f"Unexpected error: {exc}",
            )  # fmt: skip
        finally:
            self._running = False

    def run(self, run_id: int) -> None:
        run = self.db.get_analysis_run(run_id, details=False)

        def progress(message: str) -> None:
            self.db.update_analysis_run(run_id, progress_message=message)

        progress("Checking Canonical security metadata")
        meta = self.metadata.ensure_fresh(progress)
        self.db.update_analysis_run(
            run_id,
            metadata_source=meta.source,
            metadata_updated_at=meta.updated_label if meta.available else None,
            metadata_checked_at=meta.checked_at or meta.downloaded_at,
            metadata_stale=meta.stale,
            metadata_warning=meta.warning,
        )
        if not meta.available:
            message = f"Canonical security metadata is unavailable: {meta.error}"
            for analysis in run.servers:
                self.db.update_server_analysis(
                    analysis.id, status="failed", completed_at=_now(), error=message
                )
            self.db.update_analysis_run(
                run_id, status="failed", completed_at=_now(), progress_message=None, error=message
            )
            logger.warning("Analysis run %s failed: %s", run_id, message)
            return

        self.nvd.start_run()
        failures = 0
        for index, analysis in enumerate(run.servers, start=1):
            label = f"{analysis.server_name} ({index} of {len(run.servers)})"
            progress(f"Analyzing {label}")
            if not self.analyze_server(analysis, lambda m, label=label: progress(f"{label}: {m}")):
                failures += 1
        self.db.update_analysis_run(
            run_id,
            status="completed_with_errors" if failures else "completed",
            completed_at=_now(),
            progress_message=None,
        )
        logger.info("Analysis run %s finished (%d server failure(s))", run_id, failures)

    # --- one server -----------------------------------------------------------------

    def analyze_server(
        self, analysis: ServerAnalysis, progress: Callable[[str], None] | None = None
    ) -> bool:
        self.db.update_server_analysis(analysis.id, status="analyzing", started_at=_now())
        try:
            error = self._analyze(analysis, progress or (lambda message: None))
        except Exception as exc:
            logger.exception("Analysis of %s failed unexpectedly", analysis.server_name)
            error = f"Unexpected error: {exc}"
        if error:
            logger.warning("Analysis of %s failed: %s", analysis.server_name, error)
            self.db.update_server_analysis(
                analysis.id, status="failed", completed_at=_now(), error=error
            )
            return False
        logger.info("Analysis of %s complete", analysis.server_name)
        return True

    def _remote(self, server, command: str, timeout: int) -> ssh_service.RemoteResult:
        return ssh_service.run_remote(
            server.ip_address, server.pem_path, command, runner=self.runner, timeout=timeout
        )

    def _analyze(self, analysis: ServerAnalysis, progress: Callable[[str], None]) -> str | None:
        """Analyze one server; return an error message if the whole server failed."""
        server = self.db.get_server(analysis.server_id) if analysis.server_id else None
        if server is None:
            return "This server is no longer configured in EC2Patcher."

        result = self._remote(server, server_state.FACTS_COMMAND, FACTS_TIMEOUT_SECONDS)
        if not result.ok:
            return result.error
        try:
            facts = server_state.parse_facts(result.stdout)
        except server_state.RemoteOutputError as exc:
            return f"Malformed remote output: {exc}"
        self.db.update_server_analysis(
            analysis.id,
            remote_hostname=facts.hostname,
            os_pretty_name=facts.pretty_name,
            os_version_id=facts.version_id,
            os_codename=facts.codename,
            architecture=facts.architecture,
            running_kernel=facts.kernel,
            current_reboot_required=facts.reboot_required,
            reboot_required_packages=facts.reboot_required_pkgs,
            apt_updated_at=facts.apt_updated_at,
            apt_age_hours=facts.apt_age_hours,
        )
        unsupported = server_state.check_supported(facts)
        if unsupported:
            return unsupported

        warnings = list(facts.warnings)
        findings = cve_resolver.resolve_all(analysis.reported_cves, self.metadata.lookup, facts)
        candidates: dict[str, apt_planner.Candidate] = {}
        requests: list[tuple[str, str]] = []
        query = cve_resolver.candidate_query_packages(findings, facts)
        if query:
            result = self._remote(
                server, apt_planner.build_candidate_command(query), CANDIDATE_TIMEOUT_SECONDS
            )
            try:
                if not result.ok:
                    raise ValueError(result.error)
                candidates = apt_planner.parse_candidates(result.stdout, query)
            except ValueError as exc:
                for f in findings:
                    if cve_resolver.needs_candidate_check(f):
                        f.status = cve_resolver.ANALYSIS_ERROR
                        f.detail = f"APT candidate check failed: {exc}"
            else:
                requests = cve_resolver.apply_candidates(findings, candidates, facts)

        plan: list[cve_resolver.PlanEntry] = []
        apt_arguments: list[str] = []
        if requests:
            download = self._plan(server, requests)
            apt_arguments = download.apt_arguments
            if download.removals:
                warnings.append(
                    "APT would REMOVE these packages as part of the upgrade: "
                    + ", ".join(download.removals)
                )
            warnings.extend(f"APT: {m}" for m in download.messages[:10])
            if download.ok:
                plan = cve_resolver.build_plan(findings, download, candidates, facts)
            else:
                plan = self._unresolved_plan(findings, requests, candidates, facts, download.error)

        self._enrich_severity(findings, progress)
        reboot, reason = cve_resolver.expected_reboot(plan)
        self.db.save_server_results(
            analysis.id,
            findings,
            plan,
            status="complete",
            completed_at=_now(),
            expected_reboot=reboot,
            expected_reboot_reason=reason,
            apt_arguments=apt_arguments,
            warnings=warnings,
        )
        return None

    def _enrich_severity(self, findings: list, progress: Callable[[str], None]) -> None:
        """Attach NVD CVSS data to the findings. Statuses and plans are never touched."""
        cves = list(dict.fromkeys(f.cve for f in findings))
        for index, cve in enumerate(cves, start=1):
            progress(f"Fetching NVD severity data ({index} of {len(cves)})")
            result = self.nvd.lookup(cve)  # never raises; cached / memoized per run
            for f in findings:
                if f.cve == cve:
                    f.cvss = result

    def _plan(self, server, requests) -> apt_planner.DownloadPlan:
        try:
            command = apt_planner.build_plan_command(requests)
        except apt_planner.UnsafeArgumentError as exc:
            return apt_planner.DownloadPlan(ok=False, error=str(exc))
        result = self._remote(server, command, PLAN_TIMEOUT_SECONDS)
        if not result.ok:
            return apt_planner.DownloadPlan(
                ok=False,
                apt_arguments=["install", *apt_planner.plan_arguments(requests)],
                error=result.error,
            )
        return apt_planner.parse_plan(result.stdout, requests)

    @staticmethod
    def _unresolved_plan(findings, requests, candidates, facts, error) -> list:
        """Keep the required upgrades visible even when the .deb plan cannot be resolved."""
        installed = facts.by_name()
        cves_by_source: dict[str, set[str]] = {}
        for f in findings:
            if f.status == cve_resolver.PATCH_REQUIRED and f.source:
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


# --- presentation helpers -------------------------------------------------------------


@dataclass
class ServerSummary:
    reported: int
    by_status: dict[str, int]
    cve_status: dict[str, str]
    packages: int
    debs: int
    unresolved: int
    download_bytes: int
    by_severity: dict[str, int]  # per reported CVE; independent of the patch status

    def count(self, *statuses: str) -> int:
        return sum(self.by_status.get(s, 0) for s in statuses)


@dataclass
class FindingGroup:
    cve: str
    status: str
    rows: list  # findings shown individually
    not_installed: list  # PACKAGE_NOT_INSTALLED rows, collapsed when other rows exist


def group_findings(analysis: ServerAnalysis) -> list[FindingGroup]:
    """Findings per CVE in report order. Kernel CVEs list dozens of flavour source packages;
    the not-installed ones are collapsed into one expandable row to keep the table readable."""
    by_cve: dict[str, list] = {}
    for f in analysis.findings:
        by_cve.setdefault(f.cve, []).append(f)
    groups = []
    for cve in [*analysis.reported_cves, *(c for c in by_cve if c not in analysis.reported_cves)]:
        findings = by_cve.get(cve, [])
        if not findings:
            continue
        shown = [f for f in findings if f.status != cve_resolver.PACKAGE_NOT_INSTALLED]
        hidden = [f for f in findings if f.status == cve_resolver.PACKAGE_NOT_INSTALLED]
        if not shown or len(hidden) == 1:
            shown, hidden = findings, []
        status = cve_resolver.rollup_status([f.status for f in findings])
        groups.append(FindingGroup(cve, status, shown, hidden))
    return groups


def summarize(analysis: ServerAnalysis) -> ServerSummary:
    """Per-CVE rollup; totals always reconcile with the number of reported CVEs."""
    grouped: dict[str, list[str]] = {}
    severity: dict[str, str] = {}
    for f in analysis.findings:
        grouped.setdefault(f.cve, []).append(f.status)
        severity.setdefault(f.cve, f.severity)  # CVSS is per CVE: same on every row
    cve_status = {}
    for cve in analysis.reported_cves:
        statuses = grouped.get(cve)
        cve_status[cve] = cve_resolver.rollup_status(statuses) if statuses else "NOT_ANALYZED"
    by_severity = dict.fromkeys(SEVERITIES, 0)
    for cve in cve_status:
        by_severity[severity.get(cve, UNKNOWN)] += 1
    return ServerSummary(
        reported=len(analysis.reported_cves),
        by_status=dict(Counter(cve_status.values())),
        cve_status=cve_status,
        packages=len(analysis.plan),
        debs=len({p.deb_filename for p in analysis.plan if p.deb_filename}),
        unresolved=sum(1 for p in analysis.plan if p.status != "planned"),
        download_bytes=sum(p.size or 0 for p in analysis.plan if p.deb_filename),
        by_severity=by_severity,
    )
