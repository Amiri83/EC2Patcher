"""Phase 2 orchestration: analyze the latest report, server by server, and persist results.

Read-only by design. Each server receives exactly one fixed ssh command as the server's
unprivileged SSH user (no sudo) that collects facts (os-release, dpkg-query, uname, ...). The
OS is detected from /etc/os-release and everything OS-specific is done by its adapter
(os_adapters: Ubuntu, and Amazon Linux 2023 - analysis only - whose own read-only facts
command (rpm -qa, needs-restarting -r) is a second ssh command; other systems are reported as
"OS not supported yet"). Amazon Linux advisories (updateinfo.xml) are fetched on the
workstation (amazon_updateinfo). APT
candidates and the upgrade plan (apt-get -s / --print-uris) are resolved on the workstation
against a private APT state for the server's release and architecture (local_apt). Nothing
is downloaded, copied, installed or restarted.

Canonical's data alone decides applicability, fixed versions and statuses; it comes from the
first source that answers (cve_sources: OVAL, USN notices, changelog, per-CVE JSON), each probed
once when the run starts. NVD is only queried afterwards for the CVSS severity of the server's
CVEs (each unique CVE once per run, shared by all servers), KEV and EPSS for their priority; a
failure of those leaves the value empty and nothing else changes.

Each run records how many lookups of the NVD, Canonical and Amazon updateinfo caches were
answered from the cache, live or failed (``cache_stats``; follow-ups add theirs).

Servers are analyzed sequentially in one background thread; one failing server (or CVE)
never aborts the others. Each step writes progress events and honours a cancel request and the
per-step timeout (run_events): a step that overruns fails its server, and the run moves on.
"""

import logging
import subprocess
import threading
import weakref
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.models import (
    CACHE_AMAZON,
    CACHE_CANONICAL,
    CACHE_NVD,
    AnalysisRun,
    CacheStats,
    ServerAnalysis,
    StoredReport,
)
from ec2patcher.services import (
    amazon_updateinfo,
    apt_repos,
    cache_settings,
    cve_resolver,
    cve_sources,
    debversion,
    local_apt,
    nvd,
    os_adapters,
    patch_report,
    rpmversion,
    run_events,
    secret_store,
    server_state,
    ssh_service,
    ssm_service,
)
from ec2patcher.services.security_metadata import FAILED as FAILED_LOOKUP
from ec2patcher.services.security_metadata import MetadataUnreachable, SecurityMetadata
from ec2patcher.services.severity import SEVERITIES, UNKNOWN, normalize_severity

logger = logging.getLogger(__name__)

FACTS_TIMEOUT_SECONDS = 90
ENRICHMENT_BUDGET_SECONDS = 20  # KEV and EPSS never hold a server up for longer than this
DISPLAY_NAME_TAG = "display_name"
UNSUPPORTED = os_adapters.UNSUPPORTED_STATUS  # OS without an adapter (not a failure)

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


def _ref(run_id: int) -> run_events.RunRef:
    return run_events.RunRef(run_events.KIND_ANALYSIS, run_id)


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
        advisories: amazon_updateinfo.UpdateInfoSource | None = None,
        credentials: secret_store.SecretStore | None = None,
        step_timeout: float | None = None,
        sources: cve_sources.SourceResolver | None = None,
    ):
        self.db = db
        self.credentials = credentials or secret_store.SecretStore(db)  # encrypted passwords
        self.step_timeout = step_timeout  # None: the value saved in Settings
        self.metadata = metadata
        self.repos = apt_repos.provider(db)  # Settings -> APT Repositories, read per run
        self.sources = sources or cve_sources.SourceResolver(db, metadata, repos=self.repos)
        self.nvd = nvd_client or nvd.NvdClient(db)
        self.apt = apt or local_apt.LocalApt(
            config.get_apt_state_dir(config.get_data_dir()),
            config.get_apt_max_age(),
            repos=self.repos,
        )
        self.advisories = advisories or amazon_updateinfo.UpdateInfoSource(db)
        self.runner = runner
        self.transports = ssm_service.TransportResolver(db, runner)
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

    def _steps(self, run_id: int, server: str | None = None) -> run_events.Steps:
        timeout = self.step_timeout
        if timeout is None:
            timeout = cache_settings.step_timeout(self.db)
        return run_events.Steps(self.db, _ref(run_id), server, timeout)

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
            self._steps(run_id).end(run_events.FAILED, f"Unexpected error: {exc}", run_events.ERROR)
            self.db.update_analysis_run(
                run_id, status="failed", completed_at=_now(), progress_message=None,
                error=f"Unexpected error: {exc}",
            )  # fmt: skip
        finally:
            run_events.clear_cancel(self.db, _ref(run_id))
            self._running = False

    def run(self, run_id: int) -> None:
        run = self.db.get_analysis_run(run_id, details=False)

        def progress(message: str) -> None:
            self.db.update_analysis_run(run_id, progress_message=message)

        overall = self._steps(run_id)
        progress("Checking Canonical security metadata")
        self.metadata.start_run()
        check = overall.begin(
            run_events.LOOKUPS, "Checking Canonical security metadata", cancellable=False
        )
        meta = self.metadata.ensure_fresh(progress)
        check.finish(meta.source if meta.available else f"Unavailable: {meta.error}")
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
        self.advisories.start_run()
        self.transports.start_run()
        progress("Probing the security data sources")
        self._probe_sources(run_id)
        failures = 0
        for index, analysis in enumerate(run.servers, start=1):
            if run_events.cancel_requested(self.db, _ref(run_id)):
                break
            label = f"{analysis.server_name} ({index} of {len(run.servers)})"
            progress(f"Analyzing {label}")
            if not self.analyze_server(analysis, lambda m, label=label: progress(f"{label}: {m}")):
                failures += 1
            # Tallies after every server, so the status panel follows the run.
            self.db.update_analysis_run(
                run_id, metadata_lookups=self.metadata.run_outcomes(),
                cache_stats=self._cache_stats(),
            )  # fmt: skip
        servers = self.db.get_analysis_run(run_id, details=False).servers
        if any(s.status in ("waiting", "cancelled") for s in servers):
            self._finish_cancelled(run_id, servers, overall)
            return
        total = len(servers)
        # Unresolved CVEs and skipped sources: the run must not read as if nothing was missed.
        gaps = run_gaps(self.db.get_analysis_run(run_id, details=True))
        if failures:
            overall.end(
                run_events.DONE, f"Run finished: {failures} of {total} server(s) failed{gaps}.",
                run_events.WARNING,
            )  # fmt: skip
        elif gaps:
            overall.end(
                run_events.DONE, f"Run finished: {total} server(s) analyzed{gaps}.",
                run_events.WARNING,
            )  # fmt: skip
        else:
            overall.end(run_events.DONE, f"Run finished: {total} server(s) analyzed.")
        self.db.update_analysis_run(
            run_id,
            status="completed_with_errors" if failures else "completed",
            completed_at=_now(),
            progress_message=None,
        )
        logger.info("Analysis run %s finished (%d server failure(s))", run_id, failures)

    def _probe_sources(self, run_id: int) -> None:
        """Probe every source once (the clients' start_run came first): one event per source, and
        a blocked one is skipped for this run."""
        steps = self._steps(run_id)
        results = self.sources.start_run()
        for result in results:
            level = run_events.INFO if result.reachable else run_events.WARNING
            steps.record(run_events.PROBE_SOURCES, result.message, level, result.duration_ms)
        blocked = self.sources.blocked(cve_sources.NVD)
        if blocked:
            self.nvd.skip_for_run(blocked)
        self.db.update_analysis_run(run_id, source_probes=[r.as_dict() for r in results])

    def _finish_cancelled(self, run_id: int, servers: list, overall: run_events.Steps) -> None:
        """Finished servers keep their results; the ones not reached are marked as such."""
        skipped = [s for s in servers if s.status == "waiting"]
        for analysis in skipped:
            self.db.update_server_analysis(
                analysis.id, status="cancelled", completed_at=_now(),
                error=run_events.SERVER_SKIPPED,
            )  # fmt: skip
            self._steps(run_id, analysis.server_name).record(
                run_events.CANCELLED, run_events.SERVER_SKIPPED, run_events.WARNING
            )
        finished = sum(s.status in ("complete", "failed", "unsupported") for s in servers)
        overall.end(
            run_events.CANCELLED,
            f"Run cancelled: {finished} finished server(s) keep their results, "
            f"{len(servers) - finished} did not finish.",
            run_events.WARNING,
        )
        self.db.update_analysis_run(
            run_id, status="cancelled", completed_at=_now(), progress_message=None
        )
        logger.info("Analysis run %s cancelled", run_id)

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
            run_events.clear_cancel(self.db, _ref(run_id))
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
            run_events.clear_cancel(self.db, _ref(run_id))
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
        self.advisories.start_run()
        self.transports.start_run()
        self._probe_sources(run_id)

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
            if run_events.cancel_requested(self.db, _ref(run_id)):
                still_failed |= failed.intersection(s for a in affected for s in a.reported_cves)
                break
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
        self._steps(run_id).end(run_events.DONE, "Retry of the lookups finished.")
        self.db.update_analysis_run(
            run_id,
            status=previous_status,
            progress_message=None,
            metadata_checked_at=_now(),
            metadata_lookups=lookups,
            cache_stats=self._cache_stats(run.cache_stats),
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
        self.advisories.start_run(force_refresh=True)
        self.transports.start_run()
        self._probe_sources(run_id)
        label = analysis.server_name

        def progress(message: str) -> None:
            self.db.update_analysis_run(run_id, progress_message=f"Re-analyzing {label}: {message}")

        try:
            error = self._analyze(analysis, progress)
        except Exception as exc:
            logger.exception("Re-analysis of %s failed unexpectedly", label)
            error = f"Unexpected error: {exc}"
        if error == run_events.SERVER_CANCELLED:
            logger.info("Re-analysis of %s cancelled", label)  # earlier results stay as they were
        elif not error:
            if self.db.get_server_analysis(analysis_id).status != UNSUPPORTED:
                self.db.update_server_analysis(analysis_id, error=None)
        elif analysis.status == "complete" and not os_adapters.is_blocker(error):
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
            patch_report.safely(patch_report.record_analysis, self.db, analysis_id)

        status = previous_status
        if previous_status in ("completed", "completed_with_errors"):
            servers = self.db.get_analysis_run(run_id, details=False).servers
            failed = any(s.status == "failed" for s in servers)
            status = "completed_with_errors" if failed else "completed"
        lookups = {**run.metadata_lookups, **self.metadata.run_outcomes()}
        self._steps(run_id).end(run_events.DONE, f"Re-analysis of {label} finished.")
        self.db.update_analysis_run(
            run_id,
            status=status,
            progress_message=None,
            metadata_checked_at=_now(),
            metadata_lookups=lookups,
            cache_stats=self._cache_stats(run.cache_stats),
        )

    def _cache_stats(self, stored: dict | None = None) -> dict:
        """Cache / live / failed lookups per cache since the clients' start_run, added to the
        ``stored`` statistics of the run (follow-up actions)."""
        stored = stored or {}
        current = {
            CACHE_NVD: self.nvd.run_cache_stats(),
            CACHE_CANONICAL: self.metadata.run_cache_stats(),
            CACHE_AMAZON: self.advisories.run_cache_stats(),
        }
        return {
            name: (CacheStats.from_dict(stored.get(name)) + stats).as_dict()
            for name, stats in current.items()
        }

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
        if error == run_events.SERVER_CANCELLED:
            self.db.update_server_analysis(
                analysis.id, status="cancelled", completed_at=_now(), error=error
            )
            return True  # not a failure: the run stops because it was asked to
        if error:
            logger.warning("Analysis of %s failed: %s", analysis.server_name, error)
            self.db.update_server_analysis(
                analysis.id, status="failed", completed_at=_now(), error=error
            )
            patch_report.safely(patch_report.record_analysis, self.db, analysis.id)
            return False
        logger.info("Analysis of %s complete", analysis.server_name)
        return True

    def _remote(
        self, server, command: str, timeout: int, ssm: ssm_service.SsmTarget | None
    ) -> ssh_service.RemoteResult:
        password, error = ssh_service.server_password(server, self.credentials)
        if error:
            return ssh_service.RemoteResult(ok=False, error=error)
        result = ssh_service.run_remote(
            server.ip_address, server.pem_path, command, runner=self.runner, timeout=timeout,
            user=server.ssh_user, password=password, ssm=ssm,
        )  # fmt: skip
        if not result.ok:
            self.transports.note_failure(ssm, result.stderr)
        return result

    def _analyze(
        self,
        analysis: ServerAnalysis,
        progress: Callable[[str], None],
        lookup: Callable[[str], object] | None = None,
    ) -> str | None:
        """Analyze one server; return an error message if the whole server failed
        (``run_events.SERVER_CANCELLED`` if a cancel request stopped it).

        ``lookup`` replaces the Canonical lookup (used to retry only the failed CVEs).
        A server whose OS has no adapter is marked unsupported (and None is returned)."""
        steps = self._steps(analysis.run_id, analysis.server_name)
        try:
            error = self._analyze_steps(analysis, steps, progress, lookup)
        except run_events.StepTimeoutError as exc:
            error = str(exc)  # the next server is not held up
        except run_events.RunCancelled:
            steps.end(run_events.CANCELLED, run_events.SERVER_CANCELLED, run_events.WARNING)
            return run_events.SERVER_CANCELLED
        except Exception as exc:
            steps.end(run_events.FAILED, f"Unexpected error: {exc}", run_events.ERROR)
            raise
        if error:
            steps.end(run_events.FAILED, error, run_events.ERROR)
        else:
            steps.end(run_events.DONE, "Analysis finished.")
        return error

    def _analyze_steps(
        self,
        analysis: ServerAnalysis,
        steps: run_events.Steps,
        progress: Callable[[str], None],
        lookup: Callable[[str], object] | None,
    ) -> str | None:
        server = self.db.get_server(analysis.server_id) if analysis.server_id else None
        if server is None:
            return "This server is no longer configured in EC2Patcher."

        transport = run_events.resolve_transport(steps, lambda: self.transports.for_server(server))
        self.db.update_server_analysis(analysis.id, transport=transport.label)
        logger.info("Analysis of %s: transport: %s", analysis.server_name, transport.label)
        if transport.error:
            return transport.error
        ssm = transport.target

        def remote(command: str, phase: str) -> ssh_service.RemoteResult:
            timeout = steps.command_timeout(FACTS_TIMEOUT_SECONDS)
            return steps.guard(lambda: self._remote(server, command, timeout, ssm), phase)

        with steps.step(run_events.OPEN_SSH, "Connecting and collecting the facts") as step:
            result = remote(os_adapters.DEFAULT.facts_command, run_events.OPEN_SSH)
            if not result.ok:
                step.fail(result.error)
                return result.error
            step.finish("Connected; facts collected")
        with steps.step(run_events.DETECT_OS, "Reading /etc/os-release") as step:
            os_release = os_adapters.os_release_from_output(result.stdout)
            adapter = os_adapters.detect(os_release)
            if adapter is None:
                self._mark_unsupported(analysis, result.stdout, os_release)
                patch_report.safely(patch_report.record_analysis, self.db, analysis.id)
                step.finish(os_adapters.unsupported_message(os_release))
                return None
            step.finish(os_release.get("PRETTY_NAME") or os_adapters.describe(os_release))
        with steps.step(run_events.LIST_PACKAGES, "Listing the installed packages") as step:
            if adapter is not os_adapters.DEFAULT:  # the OS's own read-only facts command
                result = remote(adapter.facts_command, run_events.LIST_PACKAGES)
                if not result.ok:
                    step.fail(result.error)
                    return result.error
            try:
                facts = adapter.parse_facts(result.stdout)
            except server_state.RemoteOutputError as exc:
                step.fail(f"Malformed remote output: {exc}")
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
                os_id=adapter.os_id,
            )
            unsupported = adapter.check_supported(facts)
            if unsupported:
                step.fail(unsupported)
                return unsupported
            blocker = adapter.blocker(facts)
            if blocker:  # no plan: the package manager cannot upgrade anything until repaired
                step.fail(blocker)
                return blocker
            step.finish(f"{len(facts.packages)} packages installed")
        with steps.step(run_events.MAP_CVES, "Matching the reported CVEs") as step:
            cves = len(analysis.reported_cves)
            step.finish(f"{cves} reported CVEs against {len(facts.packages)} installed packages")

        assessment = self._assess(analysis, adapter, facts, steps, progress, lookup)
        reboot, reason = adapter.expected_reboot(assessment.plan)
        self.db.save_server_results(
            analysis.id,
            assessment.findings,
            assessment.plan,
            status="complete",
            completed_at=_now(),
            expected_reboot=reboot,
            expected_reboot_reason=reason,
            apt_arguments=assessment.apt_arguments,
            warnings=assessment.warnings,
        )
        patch_report.safely(patch_report.record_analysis, self.db, analysis.id)
        return None

    def _assess(self, analysis, adapter, facts, steps, progress, lookup):
        """The lookups and the fix versions. One adapter call does both, so it says when the
        lookups are over (``lookups_done``); the NVD severities are fetched at that point."""
        lookups = steps.begin(run_events.LOOKUPS, "Looking up the reported CVEs")
        current = [lookups]

        def report(message: str) -> None:
            progress(message)
            current[-1].note(message)

        def lookups_done(findings: list) -> None:
            self._enrich_severity(findings, progress, steps, lookups)
            self._enrich_priority(findings, lookups)
            lookups.finish(self._lookup_summary())
            current.append(steps.begin(run_events.COMPUTE_FIXES, "Computing the fix versions"))

        repos = self.repos()
        context = os_adapters.AnalysisContext(
            metadata=self.metadata,
            packages=steps.guarded(self.apt, run_events.COMPUTE_FIXES),
            progress=report,
            record=lambda **fields: self.db.update_server_analysis(analysis.id, **fields),
            lookup=self._reported_lookup(analysis, facts, steps, lookups, progress, lookup),
            advisories=steps.guarded(self.advisories, run_events.LOOKUPS),
            lookups_done=lookups_done,
            allow_unconfirmed_candidates=repos.allow_unconfirmed_candidates,
            allow_pending_candidates=repos.allow_pending_candidates,
            related_sources=self._related_sources(analysis, facts),
        )
        try:
            if adapter.os_id == os_adapters.DEFAULT.os_id:
                self.sources.prepare(facts.codename, lookups.note, steps.check_cancelled)
            assessment = adapter.assess(facts, analysis.reported_cves, context)
            if len(current) == 1:  # this adapter had nothing to look up
                lookups_done(assessment.findings)
            self._enrich_severity(assessment.findings, progress, steps, current[-1])
            self._enrich_priority(assessment.findings, current[-1])
        except run_events.RunCancelled:
            current[-1].finish()
            raise
        except (run_events.StepTimeoutError, Exception) as exc:
            current[-1].fail(str(exc))
            raise
        current[-1].finish(
            f"{len(assessment.findings)} findings, {len(assessment.plan)} packages planned"
        )
        return assessment

    def _reported_lookup(self, analysis, facts, steps, step, progress, lookup):
        """The resolver's lookup with its step event ("CVE-2000-0001 (3 of 12): resolved by
        oval"), the step timeout and the cancel check between two CVEs. ``lookup`` replaces the
        per-CVE lookup at the end of the chain (a retry forces only the failed CVEs)."""
        base = lookup or self.metadata.lookup
        hints = self._package_hints(analysis)
        total = len(analysis.reported_cves)
        count = 0

        def reported(cve: str):
            nonlocal count
            count += 1
            label = f"{cve} ({count} of {total})"
            steps.check_cancelled()
            progress(f"Canonical lookup of {label}")
            before = self.metadata.run_cache_stats()
            packages = hints.get(cve, ())
            try:
                record = steps.guard(
                    lambda: self.sources.lookup(cve, facts, base, packages), run_events.LOOKUPS
                )
            except Exception as exc:
                step.note(f"{label}: lookup failed: {exc}", run_events.WARNING)
                raise
            if record is not None and record.origin != cve_sources.CVE_JSON:
                step.note(f"{label}: resolved by {record.origin}")
            else:
                step.note(f"{label}: {_lookup_source(before, self.metadata.run_cache_stats())}")
            return record

        return reported

    def _related_sources(self, analysis, facts) -> Callable[[str], list[str]]:
        """CVE -> installed source packages it is linked to, for the opt-in fallback."""
        related = getattr(self.sources, "related_sources", None)
        if related is None:
            return lambda cve: []
        hints: dict[str, tuple[str, ...]] | None = None

        def sources(cve: str) -> list[str]:
            nonlocal hints
            if hints is None:  # only read when the fallback asks
                hints = self._package_hints(analysis)
            return related(cve, facts, hints.get(cve, ()))

        return sources

    def _package_hints(self, analysis) -> dict[str, tuple[str, ...]]:
        """CVE -> the packages a pasted security list names for it, for the changelog search."""
        try:
            rows = self.db.list_patch_report(server=analysis.server_name)
        except Exception as exc:  # noqa: BLE001 - only a hint
            logger.warning("Cannot read the package hints of %s: %s", analysis.server_name, exc)
            return {}
        return {r.cve: tuple(r.package.replace(",", " ").split()) for r in rows if r.package}

    def _lookup_summary(self) -> str:
        """Cache hits, misses and API calls of this run so far, from the run's own tallies."""
        parts = []
        for name, label in ((CACHE_CANONICAL, "Canonical"), (CACHE_NVD, "NVD"),
                            (CACHE_AMAZON, "Amazon")):  # fmt: skip
            stats = CacheStats.from_dict(self._cache_stats().get(name))
            if stats.total:
                parts.append(
                    f"{label}: {stats.cache} cache hits, {stats.live + stats.failed} misses, "
                    f"{stats.live} API calls, {stats.failed} failed"
                )
        return "; ".join(parts) or "Nothing to look up"

    def _mark_unsupported(self, analysis: ServerAnalysis, stdout: str, os_release: dict) -> None:
        """Record what was learned about a server whose OS has no adapter (not a failure)."""
        message = os_adapters.unsupported_message(os_release)
        sections = server_state.split_sections(stdout)
        hostname = next((ln.strip() for ln in sections.get("hostname", []) if ln.strip()), None)
        logger.info("Analysis of %s skipped: %s", analysis.server_name, message)
        self.db.update_server_analysis(
            analysis.id,
            status=UNSUPPORTED,
            completed_at=_now(),
            error=message,
            remote_hostname=hostname,
            os_pretty_name=os_release.get("PRETTY_NAME") or os_adapters.describe(os_release),
            os_version_id=os_release.get("VERSION_ID") or None,
            os_codename=os_release.get("VERSION_CODENAME") or None,
            os_id=os_release.get("ID") or None,
        )

    def _enrich_severity(
        self,
        findings: list,
        progress: Callable[[str], None],
        steps: run_events.Steps,
        step: run_events.Step,
    ) -> None:
        """Attach NVD CVSS data to the findings. Statuses and plans are never touched."""
        cves = list(dict.fromkeys(f.cve for f in findings if f.cvss is None))
        for index, cve in enumerate(cves, start=1):
            steps.check_cancelled()
            progress(f"Fetching NVD severity data ({index} of {len(cves)})")
            before = self.nvd.run_cache_stats()
            # never raises; cached / memoized per run
            result = steps.guard(lambda cve=cve: self.nvd.lookup(cve), run_events.LOOKUPS)
            source = _lookup_source(before, self.nvd.run_cache_stats())
            step.note(f"NVD {cve} ({index} of {len(cves)}): {source}")
            for f in findings:
                if f.cve == cve:
                    f.cvss = result

    def _enrich_priority(self, findings: list, step: run_events.Step) -> None:
        """Attach KEV and EPSS to the findings, as far as they can be had in a bounded time and
        from what is cached. Statuses and plans are never touched, and nothing here can fail."""
        cves = list(dict.fromkeys(f.cve for f in findings))
        if not cves:
            return
        try:
            run_events.run_with_timeout(
                lambda: self.sources.refresh_enrichment(cves),
                ENRICHMENT_BUDGET_SECONDS,
                "KEV/EPSS enrichment",
            )
        except (Exception, run_events.StepTimeoutError) as exc:
            logger.warning("KEV/EPSS enrichment incomplete: %s", exc)
            step.note(f"KEV/EPSS enrichment incomplete: {exc}", run_events.WARNING)
        try:
            self.sources.annotate(findings)
        except Exception as exc:  # noqa: BLE001 - enrichment must never break analysis
            logger.warning("Could not attach KEV/EPSS: %s", exc)


def _lookup_source(before: CacheStats, after: CacheStats) -> str:
    """Where one lookup's answer came from, by what it added to the run's tallies. Without an
    addition the answer was already known this run."""
    if after.live > before.live:
        return "API call"
    if after.failed > before.failed:
        return "lookup failed"
    return "cache hit"


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
    resolution_sources: list[str] = field(default_factory=list)
    failure_reasons: list[str] = field(default_factory=list)
    kev: bool | None = None  # any CVE of the group is listed; None: not known
    epss: float | None = None  # the highest score of the group
    mirrors: list[str] = field(default_factory=list)  # the APT mirror(s) its lookups used

    @property
    def kev_label(self) -> str:
        return "" if self.kev is None else ("yes" if self.kev else "no")


def _oldest(versions: list[str]) -> str:
    """Oldest version; rpm versions (Amazon Linux) that are not valid Debian versions are
    ordered as rpm EVRs."""
    try:
        return min(versions, key=debversion.version_key)
    except debversion.InvalidVersionError:
        return min(versions, key=rpmversion.version_key)


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
        newer_release = cve_resolver.NEWER_RELEASEVER_REQUIRED in (detail or "")
        if status == cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS and not newer_release and not detail:
            detail = "The configured repositories do not offer the fixed version."
        known_kev = [f.kev for f in rows if f.kev is not None]
        scores = [f.epss for f in rows if f.epss is not None]
        result.append(
            RemediationGroup(
                source=first.source_package,
                cves=sorted({f.cve for f in rows}),
                cve_count=len({f.cve for f in rows}),
                severity=min((normalize_severity(f.severity) for f in rows), key=SEVERITIES.index),
                cvss_score=highest.cvss_score,
                cvss_label=highest.cvss_label,
                ubuntu_priority=next((f.priority for f in rows if f.priority), None),
                installed_version=_oldest(versions) if versions else None,
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
                resolution_sources=sorted({f.resolution_source or "" for f in rows} - {""}),
                failure_reasons=sorted({f.failure_reason or "" for f in rows} - {""}),
                kev=any(known_kev) if known_kev else None,
                epss=max(scores) if scores else None,
                mirrors=sorted(
                    {m for f in rows for m in (getattr(f, "mirror", None) or "").split("; ") if m}
                ),
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
            cve_resolver.FIX_AVAILABLE_PENDING_PUBLICATION,
            cve_resolver.CANDIDATE_WITHOUT_METADATA,
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
            cve_resolver.NO_ADVISORY,
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


MAX_WARNING_CVES = 10  # CVEs listed per reason in a run warning; the rest are counted


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def unresolved_cves(analyses: list[ServerAnalysis]) -> dict[str, list[str]]:
    """CVE -> the reasons (per source, from ``failure_reason``) why no source resolved it."""
    reasons: dict[str, set[str]] = {}
    for analysis in analyses:
        for f in analysis.findings:
            if cve_resolver.current_status(f.status) == cve_resolver.METADATA_UNAVAILABLE:
                reasons.setdefault(f.cve, set()).add(f.failure_reason or "no reason recorded")
    return {cve: sorted(found) for cve, found in sorted(reasons.items())}


def run_warnings(run: AnalysisRun, analyses: list[ServerAnalysis] | None = None) -> list[str]:
    """Run-level warnings for the run banner and the xlsx export: the CVEs no source could
    resolve (of ``analyses``, default every server of the run) with each source's reason, and
    the sources the run skipped or found slow / degraded."""
    unresolved = unresolved_cves(run.servers if analyses is None else analyses)
    warnings = []
    if unresolved:
        by_reason: dict[str, list[str]] = {}
        for cve, reasons in unresolved.items():
            for reason in reasons:
                by_reason.setdefault(reason, []).append(cve)
        parts = []
        for reason, cves in sorted(by_reason.items(), key=lambda item: (-len(item[1]), item[0])):
            listed = ", ".join(cves[:MAX_WARNING_CVES])
            if len(cves) > MAX_WARNING_CVES:
                listed += f" and {len(cves) - MAX_WARNING_CVES} more"
            parts.append(f"{listed} ({reason})")
        head = f"{_plural(len(unresolved), 'CVE')} unresolved: no security data source answered"
        warnings.append(f"{head}. " + "; ".join(parts))
    for probe in run.skipped_sources:
        warnings.append(
            f"Source {probe['source']} ({probe.get('endpoint') or '-'}) was skipped for this run: "
            f"{probe.get('reason') or 'blocked'}."
        )
    for probe in run.impaired_sources:
        warnings.append(
            f"Source {probe['source']} ({probe.get('endpoint') or '-'}) was {probe['state']} "
            f"({probe.get('reason') or '-'}) but still used."
        )
    return warnings


def run_gaps(run: AnalysisRun) -> str:
    """A suffix for the run's end message: unresolved CVEs and skipped sources ("" if none)."""
    parts = []
    unresolved = unresolved_cves(run.servers)
    if unresolved:
        parts.append(f"{_plural(len(unresolved), 'CVE')} unresolved")
    skipped = [p["source"] for p in run.skipped_sources]
    if skipped:
        parts.append(f"{_plural(len(skipped), 'source')} skipped ({', '.join(skipped)})")
    return "".join(f"; {part}" for part in parts)


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
