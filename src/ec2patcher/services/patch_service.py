"""Phase 3: approve or reject one server's analysis and execute the approved package plan.

Pipeline (one server, one execution at a time; every step must pass before the next):

  APPROVED -> REVALIDATING (reconnect, compare OS/arch/hostname/package versions, sudo -n)
  -> DOWNLOADING (approved URIs only, .part + atomic rename after size/SHA256 check)
  -> VERIFYING_DOWNLOADS (re-hash on disk) -> TRANSFERRING (remote /tmp/<server>, scp)
  -> VERIFYING_TRANSFER (remote size + sha256sum) -> SIMULATING_INSTALL (apt-get -s)
  -> INSTALLING (apt-get install of the explicit local .debs) -> VERIFYING_INSTALL (versions,
  dpkg --audit, Canonical fixed versions, /run/reboot-required) -> CLEANING_UP -> SUCCESS.

A package already installed at (or above) its target version is excluded, never an error:
plan rows recorded that way are not checked or copied, and revalidation drops packages
patched since the analysis (e.g. by hand). Only when nothing is left to install is the
server not patched (not eligible, or ALREADY_PATCHED after revalidation).

Each scp copy is retried once; a copy that still fails ends the pipeline after cleaning up
both staging directories (exit code and stderr of every attempt are kept).

Any other failure stops the pipeline, preserves local and remote staging files and records why.
After the install may have started nothing is assumed: the outcome is verified on the
server or recorded as UNKNOWN. There is no rollback and no upgrade/dist-upgrade.
NVD is never contacted here; CVE checks use the Canonical fixed versions stored at analysis.

Reboot (after a verified patch and cleanup; recorded in ``reboot_status``, the execution
state is not changed): only if /run/reboot-required exists on the server right then and the
operator did not choose "Skip reboot". ``sudo reboot`` is issued, then SSH is polled until
the server answers with a new boot id (at most REBOOT_TIMEOUT_SECONDS); the post-reboot
uptime and kernel are recorded.

"Patch All" runs the same pipeline (plus reboot) for the eligible servers of one analysis
run, one server at a time, and stops the queue at the first failed server. A server that was
analyzed again after that run is patched from its latest analysis.
"""

import logging
import subprocess
import threading
import time
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ec2patcher.database import Database, DecisionExistsError, ExecutionActiveError
from ec2patcher.models import (
    DEFAULT_SSH_USER,
    AnalysisRun,
    PatchExecution,
    PatchPackageResult,
    ServerAnalysis,
)
from ec2patcher.services import (
    cve_resolver,
    downloader,
    os_adapters,
    patch_remote,
    server_state,
    ssh_service,
    staging,
)
from ec2patcher.services import patch_state as ps

logger = logging.getLogger(__name__)

STAGING_SETTING = "local_staging_template"
REVALIDATE_TIMEOUT_SECONDS = 90
SHORT_TIMEOUT_SECONDS = 60
SIMULATE_TIMEOUT_SECONDS = 180
INSTALL_TIMEOUT_SECONDS = 1800
REBOOT_TIMEOUT_SECONDS = 600  # SSH must be back within 10 minutes of "sudo reboot"
REBOOT_POLL_SECONDS = 10
REBOOT_ATTEMPT_TIMEOUT_SECONDS = 30
MAX_STORED_OUTPUT = 20000
SCP_ATTEMPTS = 2  # one retry per .deb
MAX_STORED_SCP_STDERR = 2000
ALREADY_AT_TARGET = "ALREADY AT TARGET"

SERVER_CHANGED = "PATCH ABORTED — SERVER STATE CHANGED"
PATCH_FAILED = "PATCH FAILED"
PARTIAL_STATE = "PATCH FAILED — PARTIAL STATE POSSIBLE"
STATE_UNKNOWN = "EXECUTION STATE UNKNOWN"
NEWER_ANALYSIS = "A newer analysis exists. Use the latest analysis before patching."
DRIFT_MESSAGE = (
    "Package state changed since this report was analyzed. Run a new analysis before patching."
)

# Runs the job in the background; may return the worker thread so liveness can be checked.
Starter = Callable[[Callable[[], None]], threading.Thread | None]


def thread_starter(target: Callable[[], None]) -> threading.Thread:
    worker = threading.Thread(target=target, name="ec2patcher-patch", daemon=True)
    worker.start()
    return worker


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _tail(lines: list[str] | str, limit: int = MAX_STORED_OUTPUT) -> str:
    text = lines if isinstance(lines, str) else "\n".join(lines)
    return text if len(text) <= limit else "[... output truncated ...]\n" + text[-limit:]


class PatchNotAllowedError(Exception):
    """Approval/rejection refused; the message is shown to the user."""


class PatchAbort(Exception):  # noqa: N818 - control flow, not an error in the code
    def __init__(
        self,
        message: str,
        title: str = PATCH_FAILED,
        package: str | None = None,
        state: str = ps.FAILED,
        partial: bool = False,
        cleanup: bool = False,  # delete the staging files instead of preserving them
    ):
        super().__init__(message)
        self.title, self.package, self.state, self.partial = title, package, state, partial
        self.cleanup = cleanup


# --- plan validation -----------------------------------------------------------------


def _adapter(analysis: ServerAnalysis) -> os_adapters.OsAdapter:
    """The OS adapter of an analysis (only analyses of a supported OS have a plan)."""
    return os_adapters.for_analysis(analysis) or os_adapters.DEFAULT


def at_target(row, adapter: os_adapters.OsAdapter | None = None) -> bool:
    """A plan row whose recorded installed version is already at or above its target (e.g.
    stored before the planner excluded such rows): excluded from patching, never an error."""
    adapter = adapter or os_adapters.DEFAULT
    return adapter.at_or_above_target(row.current_version, row.target_version)


def installable(analysis: ServerAnalysis) -> list:
    """The plan rows that still need installing (``at_target`` rows excluded)."""
    adapter = _adapter(analysis)
    return [p for p in analysis.plan if not at_target(p, adapter)]


def excluded_warning(analysis: ServerAnalysis) -> str | None:
    adapter = _adapter(analysis)
    rows = [p for p in analysis.plan if at_target(p, adapter)]
    if not rows:
        return None
    names = ", ".join(
        f"{p.binary_package} (installed {p.current_version}, target {p.target_version})"
        for p in rows
    )
    return f"{len(rows)} package(s) already at target are excluded and not installed: {names}."


def unique_debs(analysis: ServerAnalysis) -> dict[str, list]:
    """deb file name -> plan rows using it (a shared .deb is downloaded once)."""
    debs: dict[str, list] = {}
    for p in installable(analysis):
        if p.deb_filename:
            debs.setdefault(p.deb_filename, []).append(p)
    return debs


def check_plan(analysis: ServerAnalysis) -> list[str]:
    """Reasons why this analysis must not be patched (empty list: plan is complete)."""
    if analysis.status == "failed":
        return ["The analysis of this server failed."]
    if analysis.status == os_adapters.UNSUPPORTED_STATUS:
        return [analysis.error or f"{os_adapters.UNSUPPORTED_PREFIX}."]
    if analysis.status != "complete":
        return ["The analysis of this server is not complete."]
    adapter = os_adapters.for_analysis(analysis)
    if adapter is None:
        return [f"{os_adapters.UNSUPPORTED_PREFIX}: {analysis.os_pretty_name or analysis.os_id}"]
    if not adapter.supports_patching:
        return [adapter.patching_unsupported]
    reasons: list[str] = []
    missing = [
        label
        for label, value in (
            ("IP address", analysis.ip_address),
            ("remote hostname", analysis.remote_hostname),
            *adapter.release_fields(analysis),
            ("architecture", analysis.architecture),
        )
        if not value
    ]
    if missing:
        reasons.append("Incomplete SSH analysis (missing " + ", ".join(missing) + ").")
    errors = sorted({f.cve for f in analysis.findings if f.status == cve_resolver.ANALYSIS_ERROR})
    if errors:
        reasons.append(
            "Analysis errors (required package mapping failed) for: " + ", ".join(errors) + "."
        )
    unavailable = sorted(
        {f.cve for f in analysis.findings if f.status == cve_resolver.METADATA_UNAVAILABLE}
    )
    if unavailable:
        reasons.append(
            f"{len(unavailable)} CVE(s) not checked / Canonical metadata unavailable: "
            + ", ".join(unavailable)
            + ". Run a new analysis once the metadata is reachable."
        )
    rows = installable(analysis)
    if not analysis.plan:
        reasons.append("There are no package updates to install.")
    elif not rows:
        reasons.append(
            "There are no package updates to install: every planned package is already at "
            "(or above) its target version."
        )
    for p in rows:
        name = p.binary_package
        if p.status != "planned":
            reasons.append(f"{name}: package download plan is unresolved.")
            continue
        reasons += adapter.plan_row_problems(p, analysis.architecture)
    for filename, debs in unique_debs(analysis).items():
        if len({(r.uri, r.checksum, r.size) for r in debs}) > 1:
            reasons.append(f"{filename}: plan is inconsistent (conflicting URI/checksum/size).")
    covered = {cve for p in analysis.plan for cve in p.cves}  # at-target rows cover theirs
    for f in analysis.findings:
        if f.status != cve_resolver.PATCH_AVAILABLE:
            continue
        if not f.fixed_version:
            reasons.append(f"{f.cve}: fixed version is unresolved.")
        elif f.cve not in covered:
            reasons.append(f"{f.cve}: patch required but there is no exact package plan.")
    return list(dict.fromkeys(reasons))


NOT_CHECKED_STATUSES = frozenset(
    {cve_resolver.UNKNOWN, cve_resolver.METADATA_UNAVAILABLE, cve_resolver.ANALYSIS_ERROR}
)


def not_checked_cves(analysis: ServerAnalysis) -> list[str]:
    """Reported CVEs whose fix status was not evaluated; the plan says nothing about them."""
    cves = {f.cve for f in analysis.findings if f.status in NOT_CHECKED_STATUSES}
    evaluated = {f.cve for f in analysis.findings}
    cves.update(cve for cve in analysis.reported_cves if cve not in evaluated)
    return sorted(cves)


def not_checked_warning(analysis: ServerAnalysis) -> str | None:
    """Keeps an empty or reduced package plan from reading as 'all clean'."""
    count = len(not_checked_cves(analysis))
    if not count:
        return None
    return (
        f"{count} CVE{'' if count == 1 else 's'} not checked (metadata/key status unavailable). "
        "The package plan does not cover them; this report does not mean the server is clean."
    )


@dataclass
class Eligibility:
    allowed: bool
    reasons: list[str] = field(default_factory=list)
    execution: PatchExecution | None = None
    local_path: str | None = None
    remote_path: str | None = None
    packages: int = 0
    debs: int = 0
    download_bytes: int = 0
    unpatched_notes: list[str] = field(default_factory=list)
    not_checked_warning: str | None = None
    excluded_warning: str | None = None  # plan rows already at target (not installed)
    # "Patch All": the run's own (older) analysis this one replaces, if any.
    superseded: ServerAnalysis | None = None


# --- execution context --------------------------------------------------------------


@dataclass
class _Context:
    execution: PatchExecution
    analysis: ServerAnalysis
    ip: str
    pem: str
    local_dir: Path
    remote_dir: str
    packages: list[PatchPackageResult]
    debs: dict[str, dict]  # filename -> {uri, size, sha256, package_ids}
    user: str = DEFAULT_SSH_USER  # SSH login user of the server
    adapter: os_adapters.OsAdapter = os_adapters.DEFAULT  # OS the analysis was made for
    notes: list[str] = field(default_factory=list)
    reboot_required: bool = False  # /run/reboot-required seen by the post-install check
    dropped: list[PatchPackageResult] = field(default_factory=list)  # already at target
    transfer_attempts: list[dict] = field(default_factory=list)

    @property
    def filenames(self) -> list[str]:
        return sorted(self.debs)


# Every PatchService of this process: a worker of one counts as live for all on that database.
_SERVICES: "weakref.WeakSet[PatchService]" = weakref.WeakSet()


class PatchService:
    def __init__(
        self,
        db: Database,
        runner: ssh_service.Runner = subprocess.run,
        starter: Starter = thread_starter,
        fetcher: downloader.Fetcher | None = None,
        analysis_running: Callable[[], bool] = lambda: False,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.db = db
        self.runner = runner
        self.starter = starter
        self.fetcher = fetcher or downloader.urllib_fetcher
        self.analysis_running = analysis_running
        self.sleep, self.clock = sleep, clock  # reboot wait; replaceable in tests
        # Re-entrant: approve()/start_queue() hold it while eligibility() reconciles.
        self._lock = threading.RLock()
        self._running = False
        self._worker: threading.Thread | None = None
        _SERVICES.add(self)

    @property
    def is_running(self) -> bool:
        """True only while a worker of this process is alive. Executions or queues that the
        database still shows as active without one are stale (see ``reconcile``)."""
        if not self._running:
            return False
        worker = self._worker
        return not isinstance(worker, threading.Thread) or worker.is_alive()

    def _launch(self, job: Callable[[], None]) -> None:
        worker = self.starter(job)
        if isinstance(worker, threading.Thread) and self._running:
            self._worker = worker

    def _clear_stale(self) -> None:
        """Caller holds ``self._lock``. With no live worker (in any service of this process
        using the same database), executions/queues still active in the database were cut
        short: record them as interrupted so nothing stays locked."""
        if self.is_running:
            return
        self._running, self._worker = False, None
        if any(s.is_running for s in list(_SERVICES) if s.db.path == self.db.path):
            return
        executions = self.db.mark_interrupted_executions()
        queues = self.db.mark_interrupted_queues()
        if executions or queues:
            logger.warning(
                "No live patch worker: marked %d execution(s) and %d Patch All queue(s) as "
                "interrupted", executions, queues,
            )  # fmt: skip

    def reconcile(self) -> None:
        """Clear a stale 'patch running' state so Approve / Patch All are never left disabled
        after a crash or restart."""
        with self._lock:
            self._clear_stale()

    # --- settings ---------------------------------------------------------------------

    def staging_template(self) -> str:
        return self.db.get_setting(STAGING_SETTING) or staging.DEFAULT_LOCAL_TEMPLATE

    # --- eligibility -------------------------------------------------------------------

    def eligibility(self, analysis: ServerAnalysis, own_run: bool = False) -> Eligibility:
        """``own_run``: called by the running "Patch All" queue (its own busy flag is set)."""
        if not own_run:
            self.reconcile()  # a dead worker must not leave patching locked
        result = Eligibility(allowed=False)
        result.execution = self.db.get_execution_for_analysis(analysis.id)
        debs = unique_debs(analysis)
        result.packages, result.debs = len(installable(analysis)), len(debs)
        result.excluded_warning = excluded_warning(analysis)
        result.download_bytes = sum(rows[0].size or 0 for rows in debs.values())
        not_patchable = (
            cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS,
            cve_resolver.PRO_OR_ESM_REQUIRED,
            cve_resolver.PENDING_OR_DEFERRED,
        )
        result.unpatched_notes = [
            f"{f.cve} ({f.source_package or '-'}): {cve_resolver.STATUS_LABELS[f.status]}"
            for f in analysis.findings
            if f.status in not_patchable
        ]
        result.not_checked_warning = not_checked_warning(analysis)
        reasons = result.reasons
        try:
            result.remote_path = staging.remote_dir(analysis.server_name)
            local = staging.resolve_local(self.staging_template(), analysis.server_name)
            result.local_path = str(local)
        except staging.StagingError as exc:
            reasons.append(str(exc))
        if result.execution is not None:
            reasons.append(
                "A decision was already recorded for this report: "
                f"{ps.LABELS.get(result.execution.state, result.execution.state)}."
            )
            return result
        if self.db.newer_analysis_exists(analysis):
            reasons.append(NEWER_ANALYSIS)
        reasons.extend(check_plan(analysis))
        server = self.db.get_server(analysis.server_id) if analysis.server_id else None
        if server is None:
            reasons.append("This server is no longer configured in EC2Patcher.")
        elif server.name != analysis.server_name or server.ip_address != analysis.ip_address:
            reasons.append(
                "The server's name or IP address changed since the analysis. Run a new analysis."
            )
        if self.analysis_running():
            reasons.append("An analysis is currently running. Wait for it to finish.")
        active = self.db.active_execution_id()
        if active is not None:
            reasons.append(f"Another patch execution is running (#{active}).")
        elif self._running and not own_run:
            reasons.append("Another patch execution is running.")
        result.reasons = list(dict.fromkeys(reasons))
        result.allowed = not result.reasons
        return result

    # --- decisions -------------------------------------------------------------------

    def reject(self, analysis_id: int) -> int:
        """Record REJECTED. No download, staging, ssh, scp or cleanup happens."""
        analysis = self.db.get_server_analysis(analysis_id)
        if analysis is None:
            raise PatchNotAllowedError("This analysis no longer exists.")
        try:
            execution_id = self.db.create_patch_decision(analysis, ps.REJECTED)
        except DecisionExistsError as exc:
            raise PatchNotAllowedError("A decision was already recorded for this report.") from exc
        logger.info(
            "Patch REJECTED: server=%s analysis=%s (execution record %s)",
            analysis.server_name, analysis.id, execution_id,
        )  # fmt: skip
        return execution_id

    def approve(self, analysis_id: int, skip_reboot: bool = True) -> int:
        """Record APPROVED (after re-checking eligibility) and start the execution.

        ``skip_reboot`` defaults to True so only an explicit operator choice (the unchecked
        "Skip reboot" box in the web UI) lets EC2Patcher reboot a server.
        """
        analysis = self.db.get_server_analysis(analysis_id)
        if analysis is None:
            raise PatchNotAllowedError("This analysis no longer exists.")
        with self._lock:
            self._clear_stale()
            if self._running:
                raise PatchNotAllowedError("Another patch execution is running.")
            execution_id = self._record_approval(analysis, skip_reboot)
            self._running, self._worker = True, None
        try:
            self._launch(lambda: self._run_safely(execution_id))
        except Exception:
            self._running = False
            self.db.transition_execution(
                execution_id, ps.APPROVED, ps.FAILED, finished_at=_now(),
                error_title=PATCH_FAILED, error_summary="Could not start the patch execution.",
                failure_stage=ps.APPROVED, cleanup_status="NOT_NEEDED",
                reboot_status=ps.REBOOT_SKIPPED if skip_reboot else ps.REBOOT_NOT_RUN,
            )  # fmt: skip
            raise
        return execution_id

    def _record_approval(
        self,
        analysis: ServerAnalysis,
        skip_reboot: bool,
        queue_id: int | None = None,
        own_run: bool = False,
    ) -> int:
        """Re-check eligibility and persist APPROVED (caller holds ``self._lock``)."""
        check = self.eligibility(analysis, own_run=own_run)
        if not check.allowed:
            raise PatchNotAllowedError(" ".join(check.reasons))
        packages = [
            {
                "binary_package": p.binary_package,
                "architecture": p.architecture,
                "before_version": p.current_version,
                "target_version": p.target_version,
                "deb_filename": p.deb_filename,
                "size": p.size,
                "checksum": p.checksum,
                "is_dependency": p.is_dependency,
            }
            for p in analysis.plan
        ]
        try:
            execution_id = self.db.create_patch_decision(
                analysis, ps.APPROVED, check.local_path, check.remote_path, packages,
                skip_reboot=skip_reboot, queue_id=queue_id,
            )  # fmt: skip
        except DecisionExistsError as exc:
            raise PatchNotAllowedError("A decision was already recorded for this report.") from exc
        except ExecutionActiveError as exc:
            raise PatchNotAllowedError("Another patch execution is running.") from exc
        logger.info(
            "Patch APPROVED: server=%s analysis=%s execution=%s local=%s remote=%s "
            "skip_reboot=%s queue=%s",
            analysis.server_name, analysis.id, execution_id, check.local_path, check.remote_path,
            skip_reboot, queue_id,
        )  # fmt: skip
        return execution_id

    def _run_safely(self, execution_id: int) -> None:
        try:
            self.execute(execution_id)
        except Exception:
            # execute() records every failure itself; this only triggers if the database
            # is unusable. Once this worker is gone, reconcile() (or the next startup)
            # records the execution as INTERRUPTED/UNKNOWN.
            logger.exception("Patch execution %s could not record its result", execution_id)
        finally:
            self._running = False

    # --- execution ---------------------------------------------------------------------

    def execute(self, execution_id: int) -> None:
        execution = self.db.get_execution(execution_id)
        state = execution.state
        name = execution.server_name

        def move(target: str, **fields) -> None:
            nonlocal state
            self.db.transition_execution(execution_id, state, target, **fields)
            logger.info("Patch execution %s (%s): %s -> %s", execution_id, name, state, target)
            state = target

        ctx = None
        try:
            move(ps.REVALIDATING, started_at=_now())
            ctx = self._context(execution)
            self._revalidate(ctx)
            if not ctx.packages:  # every approved package is already at its target version
                fields = {}
                if ctx.execution.reboot_status == ps.REBOOT_PENDING:
                    fields = {
                        "reboot_status": ps.REBOOT_NOT_RUN,
                        "reboot_detail": "Nothing was installed; the server was not rebooted.",
                    }
                move(
                    ps.ALREADY_PATCHED, finished_at=_now(), cleanup_status="NOT_NEEDED",
                    notes=ctx.notes, **fields,
                )  # fmt: skip
                return
            move(ps.DOWNLOADING)
            self._download(ctx)
            move(ps.VERIFYING_DOWNLOADS)
            self._verify_downloads(ctx)
            move(ps.TRANSFERRING)
            self._transfer(ctx)
            move(ps.VERIFYING_TRANSFER)
            self._verify_transfer(ctx)
            move(ps.SIMULATING_INSTALL)
            self._simulate(ctx)
            move(ps.INSTALLING, install_started_at=_now())
            post = self._install(ctx)
            move(ps.VERIFYING_INSTALL)
            self._verify_install(ctx, post)
            # Results are persisted; only now may the staging files go.
            move(ps.CLEANING_UP, notes=ctx.notes)
            warning = self._cleanup(ctx)
            final = ps.SUCCESS_WITH_CLEANUP_WARNING if warning else ps.SUCCESS
            move(
                final, finished_at=_now(), cleanup_status="WARNING" if warning else "DELETED",
                cleanup_detail=warning,
            )  # fmt: skip
            logger.info("Patch execution %s (%s) finished: %s", execution_id, name, final)
        except PatchAbort as abort:
            final = self._fail(execution_id, state, abort, ctx)
        except Exception as exc:
            logger.exception("Patch execution %s (%s) crashed in %s", execution_id, name, state)
            post_install = state in ps.POST_INSTALL
            final = self._fail(
                execution_id,
                state,
                PatchAbort(
                    f"Unexpected error: {exc}",
                    title=STATE_UNKNOWN if post_install else PATCH_FAILED,
                    state=ps.UNKNOWN if post_install else ps.FAILED,
                    partial=post_install,
                ),
                ctx,
            )
        if final in ps.SUCCESSFUL:  # installation verified (a cleanup error does not matter)
            self._reboot_safely(ctx)

    def _fail(self, execution_id: int, state: str, abort: PatchAbort, ctx) -> str:
        """Record the failure; returns the state the execution ended in."""
        execution = self.db.get_execution(execution_id)
        target = abort.state
        if state == ps.CLEANING_UP:
            target = ps.SUCCESS_WITH_CLEANUP_WARNING  # installation was already verified
        elif not ps.is_allowed(state, target):
            target = ps.UNKNOWN if ps.is_allowed(state, ps.UNKNOWN) else ps.FAILED
        preserved = [
            p
            for p, used in (
                (execution.local_staging_path, execution.local_staging_created),
                (execution.remote_staging_path, execution.remote_staging_created),
            )
            if used
        ]
        fields = {
            "finished_at": _now(),
            "failure_stage": state,
            "error_title": abort.title,
            "error_summary": str(abort),
            "error_package": abort.package,
            "partial_state_possible": abort.partial,
            "cleanup_status": "PRESERVED" if preserved else "NOT_NEEDED",
            "cleanup_detail": (
                "Temporary files preserved for troubleshooting: " + ", ".join(preserved)
                if preserved
                else None
            ),
        }
        if abort.cleanup and ctx is not None and target != ps.SUCCESS_WITH_CLEANUP_WARNING:
            try:
                warning = self._cleanup(ctx)
            except Exception as exc:
                logger.exception("Patch execution %s: cleanup after failure crashed", execution_id)
                warning = f"Cleanup error: {exc}"
            fields["cleanup_status"] = "WARNING" if warning else "DELETED"
            fields["cleanup_detail"] = warning
        if target == ps.SUCCESS_WITH_CLEANUP_WARNING:
            fields = {
                "finished_at": _now(),
                "cleanup_status": "WARNING",
                "cleanup_detail": f"Cleanup error: {abort}",
            }
        elif execution.reboot_status == ps.REBOOT_PENDING:
            fields["reboot_status"] = ps.REBOOT_NOT_RUN  # never reboot after a failed patch
        if ctx is not None and ctx.notes:
            fields["notes"] = ctx.notes
        self.db.transition_execution(execution_id, state, target, **fields)
        logger.warning(
            "Patch execution %s (%s): %s -> %s: %s",
            execution_id, execution.server_name, state, target, abort,
        )  # fmt: skip
        return target

    def _context(self, execution: PatchExecution) -> _Context:
        analysis = self.db.get_server_analysis(execution.server_analysis_id)
        if analysis is None:
            raise PatchAbort("The approved analysis no longer exists.")
        server = self.db.get_server(execution.server_id) if execution.server_id else None
        if server is None:
            raise PatchAbort("This server is no longer configured in EC2Patcher.")
        if server.name != execution.server_name or server.ip_address != execution.ip_address:
            raise PatchAbort(
                "The server's name or IP address changed since the analysis. "
                "Run a new analysis before patching.",
                title=SERVER_CHANGED,
            )
        if execution.remote_staging_path != staging.remote_dir(execution.server_name):
            raise PatchAbort("Unexpected remote staging path.")
        debs: dict[str, dict] = {}
        for plan in installable(analysis):  # at-target rows are dropped at revalidation
            sha = downloader.parse_sha256(plan.checksum)
            if not plan.deb_filename or sha is None or not plan.size:
                raise PatchAbort(f"{plan.binary_package}: approved plan is incomplete.")
            staging.check_deb_filename(plan.deb_filename)
            debs.setdefault(plan.deb_filename, {"uri": plan.uri, "size": plan.size, "sha256": sha})
        return _Context(
            execution=execution,
            analysis=analysis,
            ip=server.ip_address,
            pem=server.pem_path,
            local_dir=Path(execution.local_staging_path),
            remote_dir=execution.remote_staging_path,
            packages=execution.packages,
            debs=debs,
            user=server.ssh_user,
            adapter=_adapter(analysis),
        )

    def _remote(self, ctx: _Context, command: str, timeout: int) -> ssh_service.RemoteResult:
        return ssh_service.run_remote(
            ctx.ip, ctx.pem, command, runner=self.runner, timeout=timeout, user=ctx.user
        )

    def _packages_with(self, ctx: _Context, filename: str) -> list[PatchPackageResult]:
        return [p for p in ctx.packages if p.deb_filename == filename]

    def _set_all(self, ctx: _Context, **fields) -> None:
        for p in ctx.packages:
            self.db.update_execution_package(p.id, **fields)

    # --- steps ------------------------------------------------------------------------

    def _check_sudo(self, ctx: _Context) -> None:
        result = self._remote(ctx, patch_remote.SUDO_CHECK_COMMAND, SHORT_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Sudo preflight failed: {result.error}")
        if not patch_remote.parse_sudo(result.stdout):
            raise PatchAbort(
                f"Passwordless sudo (sudo -n) is not available for the {ctx.user} user. "
                "EC2Patcher never asks for a sudo password; configure non-interactive sudo and "
                "retry."
            )

    def _revalidate(self, ctx: _Context) -> None:
        adapter = ctx.adapter
        result = self._remote(ctx, adapter.facts_command, REVALIDATE_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Pre-patch revalidation failed: {result.error}")
        try:
            facts = adapter.parse_facts(result.stdout)
        except server_state.RemoteOutputError as exc:
            raise PatchAbort(f"Pre-patch revalidation failed: {exc}") from exc
        drift = adapter.os_drift(facts, ctx.analysis)
        installed = {(p.base_name, p.architecture): p.version for p in facts.packages}
        remaining, dropped = [], []
        for pkg in ctx.packages:
            current = installed.get((pkg.binary_package, pkg.architecture))
            if adapter.at_or_above_target(current, pkg.target_version):
                dropped.append((pkg, current))  # already at (or above) target: nothing to do
                continue
            remaining.append(pkg)
            if current != pkg.before_version:
                drift.append(
                    f"{pkg.binary_package} ({pkg.architecture}): installed "
                    f"{current or 'not installed'}, analysis recorded "
                    f"{pkg.before_version or 'not installed'}"
                )
        if drift:
            raise PatchAbort(f"{DRIFT_MESSAGE} " + "; ".join(drift), title=SERVER_CHANGED)
        if dropped:
            self._drop_already_installed(ctx, dropped, remaining)
        if not remaining:
            logger.info(
                "Patch execution %s: all %d package(s) already at target; nothing to install",
                ctx.execution.id, len(dropped),
            )  # fmt: skip
            return
        self._check_sudo(ctx)
        logger.info("Patch execution %s: revalidation passed", ctx.execution.id)

    def _drop_already_installed(
        self,
        ctx: _Context,
        dropped: list[tuple[PatchPackageResult, str]],
        remaining: list[PatchPackageResult],
    ) -> None:
        """Take packages already at (or above) their target version out of this execution's
        plan: a warning, never a failure."""
        for pkg, current in dropped:
            detail = "Already installed at the target version at revalidation; not reinstalled."
            if not ctx.adapter.same_version(current, pkg.target_version):
                detail = (
                    f"Already installed at {current}, newer than the target version, at "
                    "revalidation; not reinstalled."
                )
            self.db.update_execution_package(
                pkg.id, after_version=current, install_result=ALREADY_AT_TARGET,
                verification_result="VERIFIED", detail=detail,
            )  # fmt: skip
            pkg.after_version, pkg.verification_result = current, "VERIFIED"
        ctx.dropped, ctx.packages = [pkg for pkg, _ in dropped], remaining
        needed = {p.deb_filename for p in remaining}
        ctx.debs = {name: deb for name, deb in ctx.debs.items() if name in needed}
        names = ", ".join(f"{p.binary_package} {current}" for p, current in dropped)
        ctx.notes.append(
            f"{len(dropped)} package(s) already at the target version (or newer) were dropped "
            f"from the plan: {names}."
        )
        logger.info(
            "Patch execution %s: dropped %d package(s) already at target: %s",
            ctx.execution.id, len(dropped), names,
        )  # fmt: skip

    def _download(self, ctx: _Context) -> None:
        try:
            local = staging.prepare_local(
                ctx.local_dir, ctx.execution.server_name, ctx.execution.id
            )
        except (staging.StagingError, OSError) as exc:
            raise PatchAbort(f"Local staging directory: {exc}") from exc
        self.db.update_execution(ctx.execution.id, local_staging_created=True)
        if local.leftovers:
            ctx.notes.append(
                f"Local staging directory held {len(local.leftovers)} file(s) from an earlier "
                "EC2Patcher run; they were left in place."
            )
        for filename in ctx.filenames:
            deb = ctx.debs[filename]
            try:
                downloader.download(
                    deb["uri"], ctx.local_dir, filename, deb["size"], deb["sha256"], self.fetcher
                )
            except downloader.DownloadError as exc:
                for p in self._packages_with(ctx, filename):
                    self.db.update_execution_package(
                        p.id, download_result="FAILED", detail=str(exc)
                    )
                raise PatchAbort(f"Download failed: {exc}", package=filename) from exc
            for p in self._packages_with(ctx, filename):
                self.db.update_execution_package(p.id, download_result="DOWNLOADED")
            logger.info("Patch execution %s: downloaded %s", ctx.execution.id, filename)

    def _verify_downloads(self, ctx: _Context) -> None:
        for filename in ctx.filenames:
            deb = ctx.debs[filename]
            problem = downloader.verify_file(ctx.local_dir / filename, deb["size"], deb["sha256"])
            result = "FAILED" if problem else "VERIFIED"
            for p in self._packages_with(ctx, filename):
                self.db.update_execution_package(p.id, checksum_result=result, detail=problem)
            if problem:
                raise PatchAbort(f"Local verification failed: {problem}", package=filename)
        logger.info("Patch execution %s: %d download(s) verified", ctx.execution.id, len(ctx.debs))

    def _transfer(self, ctx: _Context) -> None:
        command = patch_remote.stage_command(ctx.remote_dir)
        result = self._remote(ctx, command, SHORT_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Could not prepare the remote staging directory: {result.error}")
        stage = patch_remote.parse_stage(result.stdout)
        if stage.status == "exists":
            others = [e for e in stage.entries if e != staging.MARKER]
            managed = staging.MARKER in stage.entries and all(
                staging.MANAGED_RE.match(e) for e in others
            )
            if others and not managed:
                raise PatchAbort(
                    f"Remote staging directory {ctx.remote_dir} is not empty and contains "
                    "unmanaged files. Nothing was deleted."
                )
            if others:
                ctx.notes.append(
                    f"Remote staging directory held {len(others)} file(s) from an earlier "
                    "EC2Patcher run; matching names were overwritten by verified copies."
                )
        elif stage.status != "created":
            messages = {
                "symlink": "is a symbolic link",
                "notdir": "exists and is not a directory",
                "foreign-owner": "is owned by another user",
                "mkdir-failed": "could not be created",
            }
            raise PatchAbort(
                f"Remote staging directory {ctx.remote_dir} "
                f"{messages.get(stage.status, 'could not be inspected')}."
            )
        self.db.update_execution(ctx.execution.id, remote_staging_created=True)
        result = self._remote(ctx, patch_remote.mark_command(ctx.remote_dir), SHORT_TIMEOUT_SECONDS)
        if not result.ok or "ok" not in result.stdout.split():
            raise PatchAbort(f"Could not write to {ctx.remote_dir}: {result.error or 'no output'}")
        for filename in ctx.filenames:
            sent = self._copy(ctx, filename)
            outcome = "TRANSFERRED" if sent.ok else "FAILED"
            for p in self._packages_with(ctx, filename):
                self.db.update_execution_package(p.id, transfer_result=outcome)
            if not sent.ok:
                exit_code = "none" if sent.returncode is None else sent.returncode
                # A partial copy is useless: remove local and remote staging files.
                raise PatchAbort(
                    f"Transfer of {filename} failed after {SCP_ATTEMPTS} attempts "
                    f"(scp exit {exit_code}): {sent.error}",
                    package=filename, cleanup=True,
                )  # fmt: skip
            logger.info("Patch execution %s: transferred %s", ctx.execution.id, filename)

    def _copy(self, ctx: _Context, filename: str) -> ssh_service.RemoteResult:
        """scp one .deb, retrying once; every attempt is recorded on the execution."""
        timeout = min(3600, 120 + ctx.debs[filename]["size"] // (256 * 1024))
        for attempt in range(1, SCP_ATTEMPTS + 1):
            sent = ssh_service.run_scp(
                ctx.ip, ctx.pem, [str(ctx.local_dir / filename)], ctx.remote_dir,
                runner=self.runner, timeout=timeout, user=ctx.user,
            )  # fmt: skip
            ctx.transfer_attempts.append(
                {
                    "filename": filename,
                    "attempt": attempt,
                    "ok": sent.ok,
                    "exit_code": sent.returncode,
                    "stderr": _tail(sent.stderr.strip(), MAX_STORED_SCP_STDERR) or None,
                    "error": sent.error,
                }
            )
            self.db.update_execution(ctx.execution.id, transfer_attempts=ctx.transfer_attempts)
            if sent.ok:
                return sent
            logger.warning(
                "Patch execution %s: scp of %s failed (attempt %d/%d, exit %s): %s",
                ctx.execution.id, filename, attempt, SCP_ATTEMPTS, sent.returncode, sent.error,
            )  # fmt: skip
        return sent

    def _verify_transfer(self, ctx: _Context) -> None:
        command = patch_remote.verify_transfer_command(ctx.remote_dir, ctx.filenames)
        result = self._remote(ctx, command, SIMULATE_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Remote verification failed: {result.error}")
        files = patch_remote.parse_verify_transfer(result.stdout, ctx.remote_dir)
        if files is None:
            raise PatchAbort("Remote verification output was incomplete.")
        for filename in ctx.filenames:
            deb, remote = ctx.debs[filename], files.get(filename)
            problem = None
            if remote is None or not (remote.kind or "").startswith("regular"):
                problem = f"{filename} is missing on the server."
            elif remote.size != deb["size"]:
                problem = f"{filename}: remote size {remote.size} != approved {deb['size']}."
            elif remote.sha256 != deb["sha256"]:
                problem = f"{filename}: remote SHA256 checksum mismatch."
            for p in self._packages_with(ctx, filename):
                self.db.update_execution_package(
                    p.id, transfer_result="FAILED" if problem else "VERIFIED"
                )
            if problem:
                raise PatchAbort(f"Remote verification failed: {problem}", package=filename)
        logger.info("Patch execution %s: remote copies verified", ctx.execution.id)

    def _expected(self, ctx: _Context) -> dict[tuple[str, str], tuple]:
        return {
            (p.binary_package, p.architecture): (p.before_version, p.target_version)
            for p in ctx.packages
        }

    def _simulate(self, ctx: _Context) -> None:
        self._check_sudo(ctx)
        command = ctx.adapter.simulate_command(ctx.remote_dir, ctx.filenames)
        result = self._remote(ctx, command, SIMULATE_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Install simulation failed: {result.error}")
        output, check = ctx.adapter.check_simulation(result.stdout, self._expected(ctx))
        self.db.update_execution(ctx.execution.id, simulation_output=_tail(output))
        if not check.ok:
            raise PatchAbort("Install simulation rejected: " + "; ".join(check.problems))
        logger.info("Patch execution %s: install simulation passed", ctx.execution.id)

    def _install(self, ctx: _Context) -> patch_remote.PostInstallState:
        command = ctx.adapter.install_command(ctx.remote_dir, ctx.filenames)
        logger.info("Patch execution %s: installing %d .deb(s)", ctx.execution.id, len(ctx.debs))
        result = self._remote(ctx, command, INSTALL_TIMEOUT_SECONDS)
        parsed = ctx.adapter.parse_install(result.stdout)
        output = parsed.output or (result.stdout or "").splitlines()
        if result.stderr and not parsed.complete:
            output = [*output, *result.stderr.splitlines()[-20:]]
        self.db.update_execution(
            ctx.execution.id,
            install_finished_at=_now(),
            install_exit_status=parsed.returncode if parsed.complete else None,
            install_output=_tail(output),
        )
        # One read-only query of the resulting state (after a lost connection this is the
        # single controlled reconnect).
        post = self._query_post(ctx)
        if parsed.complete and parsed.returncode == 0:
            self._set_all(ctx, install_result="INSTALLED")
            if post is None:
                raise PatchAbort(
                    "The installation finished but the resulting state could not be verified. "
                    "Manual review / a new analysis is required.",
                    title=STATE_UNKNOWN, state=ps.UNKNOWN, partial=True,
                )  # fmt: skip
            return post
        if parsed.complete:
            errors = [ln.strip() for ln in parsed.output if ln.strip().startswith("E:")]
            self._set_all(ctx, install_result="FAILED")
            if post is not None:
                self._record_post(ctx, post)
            raise PatchAbort(
                f"apt-get install failed (exit {parsed.returncode})"
                + (f": {'; '.join(errors[:3])}" if errors else ".")
                + " No automatic retry or rollback was attempted. Run a new analysis before "
                "retrying.",
                title=PARTIAL_STATE, partial=True,
            )  # fmt: skip
        # The connection was lost or timed out: the outcome of apt is not known.
        ctx.notes.append(f"Connection lost during installation: {result.error or 'no result'}.")
        if post is None or post.busy:
            self._set_all(ctx, install_result="UNKNOWN")
            if post is not None:
                self._record_post(ctx, post)
            reason = "the package manager is still running" if post else "reconnecting failed"
            raise PatchAbort(
                f"The connection was lost during installation and {reason}. The server's "
                "package state is unknown: review it manually and run a new analysis.",
                title=STATE_UNKNOWN, state=ps.UNKNOWN, partial=True,
            )  # fmt: skip
        problems = self._record_post(ctx, post)
        if problems:
            self._set_all(ctx, install_result="UNKNOWN")
            raise PatchAbort(
                "The connection was lost during installation; after reconnecting: "
                + "; ".join(problems),
                title=PARTIAL_STATE, partial=True,
            )  # fmt: skip
        self._set_all(ctx, install_result="INSTALLED (verified after reconnect)")
        ctx.notes.append("All packages were verified after reconnecting.")
        return post

    def _query_post(self, ctx: _Context) -> patch_remote.PostInstallState | None:
        # Dropped packages are queried too: their CVEs are verified like the installed ones.
        names = [p.binary_package for p in [*ctx.packages, *ctx.dropped]]
        command = ctx.adapter.post_install_command(names)
        result = self._remote(ctx, command, SIMULATE_TIMEOUT_SECONDS)
        if not result.ok:
            logger.warning("Patch execution %s: state query failed", ctx.execution.id)
            return None
        return ctx.adapter.parse_post_install(result.stdout)

    def _record_post(self, ctx: _Context, post: patch_remote.PostInstallState) -> list[str]:
        """Persist versions, CVE checks, dpkg health and reboot state; return problems."""
        problems: list[str] = []
        for pkg in ctx.packages:
            state = post.packages.get((pkg.binary_package, pkg.architecture))
            after = state.version if state and state.installed else None
            detail = None
            if after is None:
                result, detail = "FAILED", "Package is not installed after the patch."
            else:
                cmp = ctx.adapter.compare_versions(after, pkg.target_version)
                if cmp < 0:
                    result = "FAILED"
                    detail = f"Installed {after} is below the approved target {pkg.target_version}."
                else:
                    result = "VERIFIED"
                    if cmp > 0:
                        detail = "Installed version is newer than the approved target."
            if result == "FAILED":
                problems.append(f"{pkg.binary_package}: {detail}")
            self.db.update_execution_package(
                pkg.id, after_version=after, verification_result=result, detail=detail
            )
            pkg.after_version, pkg.verification_result = after, result

        cve_rows = self._check_cves(ctx, post)
        self.db.replace_execution_cves(ctx.execution.id, cve_rows)
        problems += [
            f"{r['cve']} ({r['source_package']}): {r['detail']}"
            for r in cve_rows
            if r["result"] != "VERIFIED"
        ]
        if not post.audit_ok:
            problems.append("dpkg --audit reports broken or incomplete packages.")
        if post.busy:
            problems.append("The package manager is still running on the server.")
        self.db.update_execution(
            ctx.execution.id,
            audit_ok=post.audit_ok,
            audit_output=_tail(post.audit_output, 5000) or None,
            reboot_required_after=post.reboot_required,
            reboot_required_packages=post.reboot_packages,
        )
        return problems

    def _check_cves(self, ctx: _Context, post: patch_remote.PostInstallState) -> list[dict]:
        """For every PATCH_AVAILABLE finding: resulting source version >= Canonical fixed."""
        rows = []
        seen = set()
        plan_cves = {(p.binary_package, p.architecture): p.cves for p in ctx.analysis.plan}
        for f in ctx.analysis.findings:
            if f.status != cve_resolver.PATCH_AVAILABLE or (f.cve, f.source_package) in seen:
                continue
            seen.add((f.cve, f.source_package))
            states = [post.packages.get(key) for key, cves in plan_cves.items() if f.cve in cves]
            matches = [s for s in states if s and s.installed and s.source == f.source_package]
            row = {
                "cve": f.cve,
                "source_package": f.source_package,
                "fixed_version": f.fixed_version,
                "resulting_version": None,
                "result": "FAILED",
                "detail": None,
            }
            if not matches:
                row["detail"] = (
                    f"No installed package built from {f.source_package} was found among the "
                    "approved packages."
                )
            else:
                adapter = ctx.adapter
                resulting = min((s.source_version for s in matches), key=adapter.version_key)
                row["resulting_version"] = resulting
                if adapter.compare_versions(resulting, f.fixed_version) >= 0:
                    row["result"] = "VERIFIED"
                    if any(adapter.is_kernel_package(s.name) for s in matches):
                        row["detail"] = "Fixed kernel installed; takes effect after a reboot."
                else:
                    row["detail"] = f"Resulting version {resulting} is below {f.fixed_version}."
            rows.append(row)
        return rows

    def _verify_install(self, ctx: _Context, post: patch_remote.PostInstallState) -> None:
        problems = self._record_post(ctx, post)
        if problems:
            raise PatchAbort(
                "Post-install verification failed: " + "; ".join(problems),
                title=PARTIAL_STATE, partial=True,
            )  # fmt: skip
        ctx.reboot_required = post.reboot_required
        logger.info(
            "Patch execution %s: installation verified (reboot required: %s)",
            ctx.execution.id, "YES" if post.reboot_required else "NO",
        )  # fmt: skip

    def _cleanup(self, ctx: _Context) -> str | None:
        """Delete local + remote staging (success only). Returns a warning or None."""
        warnings = []
        local = staging.cleanup_local(ctx.local_dir, ctx.filenames)
        if local:
            warnings.append(f"Local ({ctx.local_dir}): {local}")
        result = self._remote(
            ctx, patch_remote.cleanup_command(ctx.remote_dir, ctx.filenames), SHORT_TIMEOUT_SECONDS
        )
        if not result.ok:
            warnings.append(f"Remote ({ctx.remote_dir}): cleanup failed: {result.error}")
        else:
            removed, message = patch_remote.parse_cleanup(result.stdout)
            if not removed:
                warnings.append(f"Remote ({ctx.remote_dir}): {message}")
        if warnings:
            logger.warning("Patch execution %s: cleanup warning", ctx.execution.id)
        else:
            logger.info("Patch execution %s: staging cleaned up", ctx.execution.id)
        return " ".join(warnings) or None

    # --- reboot (after a verified patch and cleanup) -----------------------------------

    def _reboot_safely(self, ctx: _Context) -> None:
        try:
            self._reboot(ctx)
        except Exception as exc:
            logger.exception("Patch execution %s: reboot step crashed", ctx.execution.id)
            self.db.update_execution(
                ctx.execution.id, reboot_status=ps.REBOOT_FAILED, reboot_finished_at=_now(),
                reboot_detail=f"Unexpected error in the reboot step: {exc}",
            )  # fmt: skip

    def _reboot(self, ctx: _Context) -> None:
        execution_id = ctx.execution.id
        if ctx.execution.reboot_status == ps.REBOOT_SKIPPED:
            detail = "Skip reboot was selected."
            if ctx.reboot_required:
                detail += (
                    " The server reports a pending reboot (/run/reboot-required); "
                    "schedule a reboot yourself."
                )
            self.db.update_execution(execution_id, reboot_detail=detail)
            logger.info("Patch execution %s: reboot skipped by the operator", execution_id)
            return
        if ctx.execution.reboot_status != ps.REBOOT_PENDING:
            return

        def finish(status: str, detail: str, **fields) -> None:
            self.db.update_execution(
                execution_id, reboot_status=status, reboot_detail=detail,
                reboot_finished_at=_now(), **fields,
            )  # fmt: skip
            logger.info("Patch execution %s: reboot %s: %s", execution_id, status, detail)

        result = self._remote(ctx, ctx.adapter.reboot_check_command, SHORT_TIMEOUT_SECONDS)
        check = ctx.adapter.parse_reboot_check(result.stdout) if result.ok else None
        if check is None:
            finish(
                ps.REBOOT_FAILED,
                "Could not check /run/reboot-required: "
                f"{result.error or 'incomplete output'}. The server was not rebooted.",
            )
            return
        if not check.required:
            finish(ps.REBOOT_NOT_REQUIRED, "/run/reboot-required does not exist on the server.")
            return
        self.db.update_execution(
            execution_id, reboot_status=ps.REBOOT_REQUESTED, reboot_requested_at=_now(),
            reboot_detail="sudo reboot issued; waiting for SSH to come back.",
        )  # fmt: skip
        logger.info("Patch execution %s: rebooting %s", execution_id, ctx.execution.server_name)
        result = self._remote(ctx, patch_remote.REBOOT_COMMAND, SHORT_TIMEOUT_SECONDS)
        refused = patch_remote.parse_reboot_refused(result.stdout)
        if refused:
            finish(ps.REBOOT_FAILED, refused + " The server was not rebooted.")
            return
        state, same_boot = self._wait_for_reboot(ctx, check.boot_id)
        if state is None:
            minutes = REBOOT_TIMEOUT_SECONDS // 60
            finish(
                ps.REBOOT_FAILED,
                f"The server still reported the same boot {minutes} minutes after sudo reboot; "
                "it did not reboot. Check it manually."
                if same_boot
                else f"SSH did not come back within {minutes} minutes after sudo reboot. "
                "Check the server manually (e.g. the EC2 console).",
            )
            return
        finish(
            ps.REBOOT_DONE,
            "Rebooted; SSH is back.",
            post_reboot_uptime=state.uptime or None,
            post_reboot_kernel=state.kernel or None,
        )

    def _wait_for_reboot(
        self, ctx: _Context, old_boot_id: str
    ) -> tuple[patch_remote.BootState | None, bool]:
        """Poll SSH until the server answers with a new boot id or the timeout passes.

        Returns (state or None, whether the last answer still came from the old boot).
        """
        deadline = self.clock() + REBOOT_TIMEOUT_SECONDS
        same_boot = False
        while True:
            remaining = deadline - self.clock()
            if remaining <= 0:
                return None, same_boot
            self.sleep(min(REBOOT_POLL_SECONDS, remaining))
            remaining = deadline - self.clock()
            if remaining <= 0:
                return None, same_boot
            timeout = max(1, int(min(REBOOT_ATTEMPT_TIMEOUT_SECONDS, remaining)))
            result = self._remote(ctx, patch_remote.BOOT_STATE_COMMAND, timeout)
            state = patch_remote.parse_boot_state(result.stdout) if result.ok else None
            if state is None:
                same_boot = False
                continue
            if state.boot_id != old_boot_id:
                return state, False
            same_boot = True  # still up on the old boot: the reboot has not started yet

    # --- "Patch All" -------------------------------------------------------------------

    def queue_preview(self, run: AnalysisRun) -> list[tuple[ServerAnalysis, Eligibility]]:
        """Every server of the run in queue order, with its eligibility (read-only).

        A server analyzed again after this run is represented by its latest analysis (the
        run's own one is kept in ``Eligibility.superseded``).
        """
        preview = []
        for analysis in run.servers:
            latest = None
            if self.db.newer_analysis_exists(analysis):
                latest = self.db.latest_analysis_for_server(analysis.server_name)
            if latest is None or latest.id == analysis.id:
                preview.append((analysis, self.eligibility(analysis)))
                continue
            check = self.eligibility(latest)
            check.superseded = analysis
            preview.append((latest, check))
        return preview

    def start_queue(self, run_id: int, confirmed_ids: list[int], skip_reboot: bool) -> int:
        """Record a queue for the confirmed, still eligible servers of the run and start it.

        Every server of the run gets an item; the ones not patched are SKIPPED with reasons.
        """
        run = self.db.get_analysis_run(run_id, details=True)
        if run is None:
            raise PatchNotAllowedError("This analysis no longer exists.")
        confirmed = set(confirmed_ids)
        with self._lock:
            self._clear_stale()
            if self._running:
                raise PatchNotAllowedError("Another patch execution is running.")
            items = []
            for analysis, check in self.queue_preview(run):
                status, detail = ps.ITEM_PENDING, None
                ids = {analysis.id} | ({check.superseded.id} if check.superseded else set())
                if not check.allowed:
                    status, detail = ps.ITEM_SKIPPED, " ".join(check.reasons)
                elif confirmed.isdisjoint(ids):
                    status, detail = ps.ITEM_SKIPPED, "Not in the confirmed server list."
                if check.superseded:
                    latest = f"Uses the latest analysis #{analysis.run_id} (newer than this run)."
                    detail = f"{latest} {detail}" if detail else latest
                if status == ps.ITEM_PENDING and check.excluded_warning:
                    detail = (
                        f"{detail} {check.excluded_warning}" if detail else check.excluded_warning
                    )
                items.append(
                    {
                        "server_analysis_id": analysis.id,
                        "server_name": analysis.server_name,
                        "display_name": analysis.display_name,
                        "status": status,
                        "detail": detail,
                    }
                )
            if not any(item["status"] == ps.ITEM_PENDING for item in items):
                raise PatchNotAllowedError("No eligible servers to patch.")
            queue_id = self.db.create_patch_queue(run_id, skip_reboot, items)
            self._running, self._worker = True, None
        logger.info(
            "Patch All queue %s started for analysis run %s: %d server(s), skip_reboot=%s",
            queue_id, run_id, sum(i["status"] == ps.ITEM_PENDING for i in items), skip_reboot,
        )  # fmt: skip
        try:
            self._launch(lambda: self._run_queue_safely(queue_id))
        except Exception:
            self._running = False
            self._stop_queue(queue_id, None, "Could not start the queue.")
            raise
        return queue_id

    def _run_queue_safely(self, queue_id: int) -> None:
        try:
            self._run_queue(queue_id)
        except Exception:
            logger.exception("Patch All queue %s crashed", queue_id)
            try:
                self._stop_queue(queue_id, None, "Unexpected error; see the application log.")
            except Exception:
                logger.exception("Patch All queue %s could not record its result", queue_id)
        finally:
            self._running = False

    def _run_queue(self, queue_id: int) -> None:
        """Patch the PENDING servers in order; stop at the first failure."""
        queue = self.db.get_patch_queue(queue_id)
        for item in queue.items:
            if item.status != ps.ITEM_PENDING:
                continue
            analysis = self.db.get_server_analysis(item.server_analysis_id)
            try:
                if analysis is None:
                    raise PatchNotAllowedError("This analysis no longer exists.")
                with self._lock:
                    execution_id = self._record_approval(
                        analysis, queue.skip_reboot, queue_id=queue_id, own_run=True
                    )
            except PatchNotAllowedError as exc:
                # Nothing was done on this server: like any ineligible server, it is skipped.
                self.db.update_queue_item(
                    item.id, status=ps.ITEM_SKIPPED, detail=f"Not eligible at its turn: {exc}"
                )
                continue
            self.db.update_queue_item(item.id, status=ps.ITEM_RUNNING, execution_id=execution_id)
            self.execute(execution_id)
            failure = queue_failure(self.db.get_execution(execution_id))
            if failure:
                self.db.update_queue_item(item.id, status=ps.ITEM_FAILED, detail=failure)
                self._stop_queue(queue_id, item.server_name, failure)
                return
            done: dict = {"status": ps.ITEM_SUCCESS}
            if self.db.get_execution(execution_id).state == ps.ALREADY_PATCHED:
                note = "Already patched: every package was already at its target version."
                done["detail"] = f"{item.detail} {note}" if item.detail else note
            self.db.update_queue_item(item.id, **done)
        self.db.update_patch_queue(queue_id, state=ps.QUEUE_COMPLETED, finished_at=_now())
        logger.info("Patch All queue %s completed", queue_id)

    def _stop_queue(self, queue_id: int, failed_server: str | None, reason: str) -> None:
        queue = self.db.get_patch_queue(queue_id)
        after = f" after {failed_server} failed" if failed_server else ""
        for item in queue.items:
            if item.status == ps.ITEM_PENDING:
                self.db.update_queue_item(
                    item.id, status=ps.ITEM_NOT_RUN, detail=f"Not run: the queue stopped{after}."
                )
            elif item.status == ps.ITEM_RUNNING:  # only after an unexpected crash
                self.db.update_queue_item(
                    item.id, status=ps.ITEM_FAILED,
                    detail="The queue stopped while this server was being patched; "
                    "check its execution.",
                )  # fmt: skip
        self.db.update_patch_queue(
            queue_id, state=ps.QUEUE_STOPPED, finished_at=_now(),
            stop_reason=f"{failed_server}: {reason}" if failed_server else reason,
        )  # fmt: skip
        logger.warning("Patch All queue %s stopped%s: %s", queue_id, after, reason)


def queue_failure(execution: PatchExecution) -> str | None:
    """Why this execution stops a "Patch All" queue (None: the server is done)."""
    if execution.state not in ps.DONE:
        title = execution.error_title or ps.LABELS.get(execution.state, execution.state)
        return f"{title}: {execution.error_summary or 'no details'}"
    if execution.reboot_status == ps.REBOOT_FAILED:
        return f"REBOOT FAILED: {execution.reboot_detail or 'no details'}"
    return None


# --- presentation -------------------------------------------------------------------


@dataclass
class ProgressStep:
    label: str
    status: str  # done | running | failed | pending


def progress_steps(execution: PatchExecution) -> list[ProgressStep]:
    """The step list shown while/after patching (no raw terminal output)."""
    if execution.decision != ps.APPROVED:
        return []
    if execution.state == ps.ALREADY_PATCHED:
        return [
            ProgressStep("Preflight revalidation", "done"),
            ProgressStep("All packages already at the target version; nothing to install", "done"),
        ]
    debs: dict[str, PatchPackageResult] = {}
    for p in execution.packages:
        if p.install_result != ALREADY_AT_TARGET:  # dropped at revalidation: never copied
            debs.setdefault(p.deb_filename, p)
    total = len(debs)
    downloaded = sum(1 for p in debs.values() if p.download_result == "DOWNLOADED")
    transferred = sum(1 for p in debs.values() if p.transfer_result in ("TRANSFERRED", "VERIFIED"))
    steps = [
        ("Preflight revalidation", ps.REVALIDATING),
        (f"Downloaded {downloaded}/{total}", ps.DOWNLOADING),
        ("Checksums verified", ps.VERIFYING_DOWNLOADS),
        (f"Transferred {transferred}/{total}", ps.TRANSFERRING),
        ("Remote checksums verified", ps.VERIFYING_TRANSFER),
        ("Install simulation", ps.SIMULATING_INSTALL),
        ("Installing", ps.INSTALLING),
        ("Verifying", ps.VERIFYING_INSTALL),
        ("Checking reboot", ps.VERIFYING_INSTALL),
        ("Cleanup", ps.CLEANING_UP),
    ]
    order = ps.PIPELINE.index
    if execution.state in ps.SUCCESSFUL:
        current, current_status = len(ps.PIPELINE), "done"
    elif execution.state in ps.ACTIVE:
        current, current_status = order(execution.state), "running"
    else:  # FAILED / UNKNOWN
        stage = execution.failure_stage if execution.failure_stage in ps.PIPELINE else ps.APPROVED
        current, current_status = order(stage), "failed"
    result = []
    for label, stage in steps:
        index = order(stage)
        if index < current:
            status = "done"
        elif index == current:
            status = current_status
        else:
            status = "pending"
        if label == "Checking reboot" and execution.reboot_required_after is not None:
            status = "done"  # reboot state was captured
        if execution.state == ps.SUCCESS_WITH_CLEANUP_WARNING and stage == ps.CLEANING_UP:
            status = "warning"
        result.append(ProgressStep(label, status))
    return result
