"""Phase 2 orchestration: analyze the latest report, server by server, and persist results.

Read-only by design. Each server receives exactly one fixed ssh command as the unprivileged
``ubuntu`` user (no sudo) that collects facts (dpkg-query, os-release, uname, ...). APT
candidates and the upgrade plan (apt-get -s / --print-uris) are resolved on the workstation
against a private APT state for the server's release and architecture (local_apt). Nothing
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
import weakref
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.models import ServerAnalysis, StoredReport
from ec2patcher.services import (
    apt_planner,
    cve_resolver,
    debversion,
    local_apt,
    nvd,
    server_state,
    ssh_service,
)
from ec2patcher.services.security_metadata import FAILED as FAILED_LOOKUP
from ec2patcher.services.security_metadata import MetadataUnreachable, SecurityMetadata
from ec2patcher.services.severity import SEVERITIES, UNKNOWN, normalize_severity

logger = logging.getLogger(__name__)

FACTS_TIMEOUT_SECONDS = 90
DISPLAY_NAME_TAG = "display_name"

# Runs the job in the background; may return the worker thread so liveness can be checked.
Starter = Callable[[Callable[[], None]], threading.Thread | None]


def thread_starter(target: Callable[[], None]) -> threading.Thread:
    worker = threading.Thread(target=target, name="ec2patcher-analysis", daemon=True)
    worker.start()
    return worker


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _now() -> str:
    return _utcnow().isoformat()


# Every AnalysisService of this process: a worker of one counts as live for all on that database.
_SERVICES: "weakref.WeakSet[AnalysisService]" = weakref.WeakSet()


class AnalysisService:
    def __init__(
        self,
        db: Database,
        metadata: SecurityMetadata,
        runner: ssh_service.Runner = subprocess.run,
        starter: Starter = thread_starter,
        nvd_client: nvd.NvdClient | None = None,
        apt: local_apt.LocalApt | None = None,
    ):
        self.db = db
        self.metadata = metadata
        self.nvd = nvd_client or nvd.NvdClient(db)
        self.apt = apt or local_apt.LocalApt(
            config.get_apt_state_dir(config.get_data_dir()), config.get_apt_max_age()
        )
        self.runner = runner
        self.starter = starter
        self._lock = threading.Lock()
        self._running = False
        self._worker: threading.Thread | None = None
        _SERVICES.add(self)

    @property
    def is_running(self) -> bool:
        """True only while a worker of this process is alive. A run whose database status
        still says 'running' without one is stale (see ``reconcile``)."""
        if not self._running:
            return False
        worker = self._worker
        return not isinstance(worker, threading.Thread) or worker.is_alive()

    def _launch(self, job: Callable[[], None]) -> None:
        worker = self.starter(job)
        if isinstance(worker, threading.Thread) and self._running:
            self._worker = worker

    def _clear_stale(self) -> int:
        """Caller holds ``self._lock``. Mark runs the database still shows as running while no
        worker is alive (the worker crashed or the app restarted) as interrupted."""
        if self.is_running:
            return 0
        self._running, self._worker = False, None
        if any(s.is_running for s in list(_SERVICES) if s.db.path == self.db.path):
            return 0  # another service of this process (same database) is analyzing
        count = self.db.mark_interrupted_runs()
        if count:
            logger.warning("Marked %d analysis run(s) without a live worker as interrupted", count)
        return count

    def reconcile(self) -> int:
        """Clear a stale 'running' state so Analyze / Re-analyze are never left disabled."""
        with self._lock:
            return self._clear_stale()

    def start(self, report: StoredReport) -> int | None:
        """Create a new run for ``report`` and analyze it in the background.

        Returns the run id, or None if another analysis is still running.
        """
        with self._lock:
            self._clear_stale()
            if self._running:
                return None
            self._running, self._worker = True, None
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
            self._launch(lambda: self._run_safely(run_id))
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
        self.metadata.start_run()
        meta = self.metadata.ensure_fresh(progress)
        metadata_warning = meta.warning
        if not meta.available:
            metadata_warning = f"Canonical security metadata is unavailable: {meta.error}"
        self.db.update_analysis_run(
            run_id,
            metadata_source=meta.source,
            metadata_updated_at=meta.updated_label if meta.available else None,
            metadata_checked_at=meta.checked_at or meta.downloaded_at,
            metadata_stale=meta.stale,
            metadata_warning=metadata_warning,
        )

        self.nvd.start_run()
        self.apt.start_run()
        failures = 0
        for index, analysis in enumerate(run.servers, start=1):
            label = f"{analysis.server_name} ({index} of {len(run.servers)})"
            progress(f"Analyzing {label}")
            if not self.analyze_server(analysis, lambda m, label=label: progress(f"{label}: {m}")):
                failures += 1
            # Tallies after every server, so the status panel follows the run.
            self.db.update_analysis_run(run_id, metadata_lookups=self.metadata.run_outcomes())
        self.db.update_analysis_run(
            run_id,
            status="completed_with_errors" if failures else "completed",
            completed_at=_now(),
            progress_message=None,
        )
        logger.info("Analysis run %s finished (%d server failure(s))", run_id, failures)

    # --- follow-up actions on a finished run -----------------------------------------
    # Retry failed lookups (whole run), Retry these CVEs (Investigate bucket of one server)
    # and Re-analyze (one server) run in the background with the run marked as running, and
    # force-refresh their CVEs from ubuntu.com (bypassing the memo and the cache).

    def _start_followup(self, run_id: int, message: str, job: Callable[[str], None]) -> bool:
        """Run ``job(previous_status)`` in the background; False if an analysis is running."""
        with self._lock:
            self._clear_stale()  # a stale 'running' run must not refuse the action forever
            if self._running:
                return False
            run = self.db.get_analysis_run(run_id, details=False)
            if run is None or run.is_running:
                return False
            self._running, self._worker = True, None
        try:
            self.db.update_analysis_run(run_id, status="running", progress_message=message)
            self._launch(lambda: self._followup_safely(run_id, run.status, job))
        except Exception:
            self._running = False
            self.db.update_analysis_run(run_id, status=run.status, progress_message=None)
            raise
        return True

    def _followup_safely(self, run_id: int, previous_status: str, job) -> None:
        try:
            job(previous_status)
        except Exception:
            logger.exception("Follow-up action on run %s crashed", run_id)
            self.db.update_analysis_run(run_id, status=previous_status, progress_message=None)
        finally:
            self._running = False

    def retry_failed_lookups(self, run_id: int) -> int | None:
        """Re-resolve the CVEs of ``run_id`` whose Canonical lookup failed, in the background.

        Returns the number of CVEs retried (0 = nothing to retry), or None if an analysis
        is already running. Only the failed CVEs are requested from ubuntu.com again."""
        run = self.db.get_analysis_run(run_id, details=False)
        failed = set(run.failed_lookups) if run else set()
        return self.retry_cves(run_id, failed, message="Retrying failed Canonical lookups")

    def retry_cves(
        self,
        run_id: int,
        cves: set[str],
        analysis_ids: set[int] | None = None,
        message: str = "Retrying Canonical lookups",
    ) -> int | None:
        """Force-refresh ``cves`` from ubuntu.com and re-analyze the completed servers (all,
        or ``analysis_ids``) that reported them. Returns the number of CVEs retried (0 =
        nothing to retry), or None if an analysis is already running."""
        cves = {c.strip().upper() for c in cves}
        if not cves:
            return 0

        def job(previous_status: str) -> None:
            self.retry_lookups(run_id, cves, previous_status, analysis_ids)

        if not self._start_followup(run_id, message, job):
            return None
        logger.info("Retrying %d Canonical lookup(s) of run %s", len(cves), run_id)
        return len(cves)

    def retry_lookups(
        self,
        run_id: int,
        failed: set[str],
        previous_status: str,
        analysis_ids: set[int] | None = None,
    ) -> None:
        """Re-analyze the completed servers that reported a CVE in ``failed``.

        Canonical is queried again (force refresh) for ``failed`` only; every other CVE is
        resolved from the memo / cache (network only if it is missing there, e.g. after
        Clear Security Cache). A server that cannot be re-analyzed keeps its previous
        results, and its failed CVEs stay failed."""
        run = self.db.get_analysis_run(run_id, details=True)
        self.metadata.start_run(force_refresh=True, cves=failed)
        self.nvd.start_run()
        self.apt.start_run()

        def lookup(cve: str):
            if cve.strip().upper() in failed:
                return self.metadata.lookup(cve)
            try:
                return self.metadata.lookup(cve, network=False)
            except MetadataUnreachable:
                return self.metadata.lookup(cve)

        affected = [
            s for s in run.servers
            if s.status == "complete" and failed.intersection(s.reported_cves)
            and (analysis_ids is None or s.id in analysis_ids)
        ]  # fmt: skip
        still_failed: set[str] = set()
        for index, analysis in enumerate(affected, start=1):
            label = f"{analysis.server_name} ({index} of {len(affected)})"
            self.db.update_analysis_run(run_id, progress_message=f"Retrying lookups for {label}")
            try:
                error = self._analyze(analysis, lambda m: None, lookup)
            except Exception as exc:
                logger.exception("Retry for %s failed unexpectedly", analysis.server_name)
                error = f"Unexpected error: {exc}"
            if error:  # previous results are still stored and remain valid
                logger.warning("Retry for %s failed: %s", analysis.server_name, error)
                still_failed |= failed.intersection(analysis.reported_cves)

        lookups = dict(run.metadata_lookups)
        lookups.update(self.metadata.run_outcomes())
        lookups.update(dict.fromkeys(still_failed, FAILED_LOOKUP))
        self.db.update_analysis_run(
            run_id,
            status=previous_status,
            progress_message=None,
            metadata_checked_at=_now(),
            metadata_lookups=lookups,
        )
        logger.info(
            "Retried lookups of run %s: %d of %d still failed", run_id,
            sum(1 for cve in failed if lookups.get(cve) == FAILED_LOOKUP), len(failed),
        )  # fmt: skip

    def reanalyze_server(self, run_id: int, analysis_id: int) -> bool:
        """Re-analyze one server of ``run_id`` in the background, force-refreshing all of
        its CVEs from ubuntu.com. False if an analysis is running (or the server is not
        part of the run)."""
        analysis = self.db.get_server_analysis(analysis_id)
        if analysis is None or analysis.run_id != run_id:
            return False

        def job(previous_status: str) -> None:
            self.reanalyze(run_id, analysis_id, previous_status)

        message = f"Re-analyzing {analysis.server_name}"
        if not self._start_followup(run_id, message, job):
            return False
        logger.info("Re-analyzing %s of run %s", analysis.server_name, run_id)
        return True

    def reanalyze(self, run_id: int, analysis_id: int, previous_status: str) -> None:
        """Re-collect facts and re-resolve every CVE of one server (read-only, as a run).

        A server that was complete keeps its previous results if the re-analysis fails."""
        analysis = self.db.get_server_analysis(analysis_id)
        run = self.db.get_analysis_run(run_id, details=False)
        self.metadata.start_run(force_refresh=True)
        self.nvd.start_run()
        self.apt.start_run()
        label = analysis.server_name

        def progress(message: str) -> None:
            self.db.update_analysis_run(run_id, progress_message=f"Re-analyzing {label}: {message}")

        try:
            error = self._analyze(analysis, progress)
        except Exception as exc:
            logger.exception("Re-analysis of %s failed unexpectedly", label)
            error = f"Unexpected error: {exc}"
        if not error:
            self.db.update_server_analysis(analysis_id, error=None)
        elif analysis.status == "complete" and not error.startswith(server_state.DPKG_BLOCKER):
            # the previous results are still stored (a dpkg blocker invalidates their plan)
            logger.warning("Re-analysis of %s failed: %s", label, error)
            self.db.update_server_analysis(
                analysis_id,
                warnings=[*analysis.warnings, f"Re-analysis at {_now()} failed: {error}"],
            )
        else:
            logger.warning("Re-analysis of %s failed: %s", label, error)
            self.db.update_server_analysis(
                analysis_id, status="failed", completed_at=_now(), error=error
            )

        status = previous_status
        if previous_status in ("completed", "completed_with_errors"):
            servers = self.db.get_analysis_run(run_id, details=False).servers
            failed = any(s.status == "failed" for s in servers)
            status = "completed_with_errors" if failed else "completed"
        lookups = {**run.metadata_lookups, **self.metadata.run_outcomes()}
        self.db.update_analysis_run(
            run_id,
            status=status,
            progress_message=None,
            metadata_checked_at=_now(),
            metadata_lookups=lookups,
        )

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

    def _analyze(
        self,
        analysis: ServerAnalysis,
        progress: Callable[[str], None],
        lookup: Callable[[str], object] | None = None,
    ) -> str | None:
        """Analyze one server; return an error message if the whole server failed.

        ``lookup`` replaces the Canonical lookup (used to retry only the failed CVEs)."""
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
        )
        unsupported = server_state.check_supported(facts)
        if unsupported:
            return unsupported
        blocker = server_state.dpkg_blocker(facts)
        if blocker:  # no plan: apt cannot upgrade anything until dpkg is repaired
            return blocker

        warnings = list(facts.warnings)
        metadata_status = self.metadata.status()
        if not metadata_status.available:
            lookup = lambda _cve: None  # noqa: E731
        elif lookup is None:
            lookup = self.metadata.lookup
        findings = cve_resolver.resolve_all(analysis.reported_cves, lookup, facts)
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
            progress(f"Resolving APT candidates locally ({facts.codename}/{facts.architecture})")
            try:
                state = self.apt.prepare(facts.codename, facts.architecture)
                self.db.update_server_analysis(
                    analysis.id,
                    apt_updated_at=state.updated_at.isoformat(),
                    apt_age_hours=max(0.0, (_utcnow() - state.updated_at).total_seconds() / 3600),
                )
                candidates = self.apt.candidates(state, facts, query)
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
            download = self.apt.plan(state, facts, requests)
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


# --- presentation helpers -------------------------------------------------------------


@dataclass
class RemediationGroup:
    source: str | None
    cves: list[str]
    cve_count: int
    severity: str
    cvss_score: float | None
    cvss_label: str
    ubuntu_priority: str | None
    installed_version: str | None
    fixed_version: str | None
    candidate_version: str | None
    status: str
    detail: str | None
    binary_packages: list[str]
    pockets: list[str]
    rows: list
    highest_row: object


def remediation_groups(findings: list) -> list[RemediationGroup]:
    """Collapse findings with the same source, fix and status for report presentation only.

    The status is part of the key so a group only ever counts CVEs that share one remediation
    outcome: rows that are already fixed / not affected / not installed never inflate the CVE
    count or raise the severity of an actionable group with the same source and fix.
    """
    grouped: dict[tuple[str, str, str], list] = {}
    ungrouped = []
    for finding in findings:
        if finding.source_package and finding.fixed_version:
            key = (finding.source_package, finding.fixed_version, finding.status)
            grouped.setdefault(key, []).append(finding)
        else:
            ungrouped.append([finding])

    result = []
    for rows in [*([grouped[key] for key in sorted(grouped)]), *ungrouped]:
        first = rows[0]
        versions = [f.installed_version for f in rows if f.installed_version]
        candidates = []
        for f in rows:
            for item in (f.apt_candidate or "").split("; "):
                if ": " in item:
                    version = item.rsplit(": ", 1)[1]
                    if debversion.is_valid_version(version):
                        candidates.append(version)
        status = cve_resolver.rollup_status([f.status for f in rows])
        highest = max(rows, key=lambda f: f.cvss_score if f.cvss_score is not None else -1)
        detail = next((f.detail for f in rows if f.status == status and f.detail), None)
        if status == cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS:
            detail = "The configured repositories do not offer the fixed version."
        result.append(
            RemediationGroup(
                source=first.source_package,
                cves=sorted({f.cve for f in rows}),
                cve_count=len({f.cve for f in rows}),
                severity=min((normalize_severity(f.severity) for f in rows), key=SEVERITIES.index),
                cvss_score=highest.cvss_score,
                cvss_label=highest.cvss_label,
                ubuntu_priority=next((f.priority for f in rows if f.priority), None),
                installed_version=min(versions, key=debversion.version_key) if versions else None,
                fixed_version=first.fixed_version,
                candidate_version=(
                    max(candidates, key=debversion.version_key) if candidates else None
                ),
                status=status,
                detail=detail,
                binary_packages=sorted({b for f in rows for b in f.binary_packages}),
                pockets=sorted({f.pocket for f in rows if f.pocket}),
                rows=rows,
                highest_row=highest,
            )
        )
    return result


ACTION_REQUIRED = "action"
INVESTIGATE = "investigate"
NO_ACTION = "no_action"

BUCKETS = (
    (
        ACTION_REQUIRED,
        "Action required",
        (
            cve_resolver.PATCH_AVAILABLE,
            cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS,
            cve_resolver.PRO_OR_ESM_REQUIRED,
        ),
    ),
    (
        INVESTIGATE,
        "Investigate",
        (
            cve_resolver.UNKNOWN,
            cve_resolver.METADATA_UNAVAILABLE,
            cve_resolver.ANALYSIS_ERROR,
            cve_resolver.PENDING_OR_DEFERRED,
            cve_resolver.NO_FIX_PUBLISHED,
        ),
    ),
    (
        NO_ACTION,
        "No action",
        (
            cve_resolver.ALREADY_FIXED,
            cve_resolver.NOT_AFFECTED,
            cve_resolver.PACKAGE_NOT_INSTALLED,
        ),
    ),
)
_BUCKET_OF_STATUS = {status: key for key, _, statuses in BUCKETS for status in statuses}


@dataclass
class FindingBucket:
    key: str
    title: str
    groups: list[RemediationGroup]

    @property
    def count(self) -> int:
        return len(self.groups)

    @property
    def cve_count(self) -> int:
        return len({cve for g in self.groups for cve in g.cves})


def bucket_for_status(status: str | None) -> str:
    """Report bucket of a remediation status. Unrecognised statuses need investigation."""
    return _BUCKET_OF_STATUS.get(cve_resolver.current_status(status or ""), INVESTIGATE)


def bucket_groups(groups: list[RemediationGroup]) -> list[FindingBucket]:
    """Split remediation groups into the three report buckets (always all three, in order).

    Presentation only: statuses are read, never changed."""
    buckets = {key: FindingBucket(key, title, []) for key, title, _ in BUCKETS}
    for group in groups:
        buckets[bucket_for_status(group.status)].groups.append(group)
    return list(buckets.values())


def investigate_cves(analysis: ServerAnalysis) -> set[str]:
    """CVEs listed in the Investigate bucket of a server report ('Retry these CVEs')."""
    groups = remediation_groups(analysis.findings)
    return {cve for g in groups if bucket_for_status(g.status) == INVESTIGATE for cve in g.cves}


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
    by_bucket: dict[str, int]  # reported CVEs per report bucket (bucket_for_status of cve_status)

    def count(self, *statuses: str) -> int:
        return sum(self.by_status.get(s, 0) for s in statuses)

    @property
    def buckets(self) -> list[tuple[str, str, int]]:
        """(key, title, CVE count) for every report bucket, in report order."""
        return [(key, title, self.by_bucket[key]) for key, title, _ in BUCKETS]


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
    by_bucket = {key: 0 for key, _, _ in BUCKETS}
    for status in cve_status.values():
        by_bucket[bucket_for_status(status)] += 1
    return ServerSummary(
        reported=len(analysis.reported_cves),
        by_status=dict(Counter(cve_status.values())),
        cve_status=cve_status,
        packages=len(analysis.plan),
        debs=len({p.deb_filename for p in analysis.plan if p.deb_filename}),
        unresolved=sum(1 for p in analysis.plan if p.status != "planned"),
        download_bytes=sum(p.size or 0 for p in analysis.plan if p.deb_filename),
        by_severity=by_severity,
        by_bucket=by_bucket,
    )
