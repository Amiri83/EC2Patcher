"""Phase 3: approve or reject one server's analysis and execute the approved package plan.

Pipeline (one server, one execution at a time; every step must pass before the next):

  APPROVED -> REVALIDATING (reconnect, compare OS/arch/hostname/package versions, sudo -n)
  -> DOWNLOADING (approved URIs only, .part + atomic rename after size/SHA256 check)
  -> VERIFYING_DOWNLOADS (re-hash on disk) -> TRANSFERRING (remote /tmp/<server>, scp)
  -> VERIFYING_TRANSFER (remote size + sha256sum) -> SIMULATING_INSTALL (apt-get -s)
  -> INSTALLING (apt-get install of the explicit local .debs) -> VERIFYING_INSTALL (versions,
  dpkg --audit, Canonical fixed versions, /run/reboot-required) -> CLEANING_UP -> SUCCESS.

Any failure stops the pipeline, preserves local and remote staging files and records why.
After the install may have started nothing is assumed: the outcome is verified on the
server or recorded as UNKNOWN. There is no rollback, no upgrade/dist-upgrade and no reboot.
NVD is never contacted here; CVE checks use the Canonical fixed versions stored at analysis.
"""

import logging
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from ec2patcher.database import Database, DecisionExistsError, ExecutionActiveError
from ec2patcher.models import PatchExecution, PatchPackageResult, ServerAnalysis
from ec2patcher.services import (
    apt_planner,
    cve_resolver,
    debversion,
    downloader,
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
MAX_STORED_OUTPUT = 20000

SERVER_CHANGED = "PATCH ABORTED — SERVER STATE CHANGED"
PATCH_FAILED = "PATCH FAILED"
PARTIAL_STATE = "PATCH FAILED — PARTIAL STATE POSSIBLE"
STATE_UNKNOWN = "EXECUTION STATE UNKNOWN"
NEWER_ANALYSIS = "A newer analysis exists. Use the latest analysis before patching."
DRIFT_MESSAGE = (
    "Package state changed since this report was analyzed. Run a new analysis before patching."
)

Starter = Callable[[Callable[[], None]], None]


def thread_starter(target: Callable[[], None]) -> None:
    threading.Thread(target=target, name="ec2patcher-patch", daemon=True).start()


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
    ):
        super().__init__(message)
        self.title, self.package, self.state, self.partial = title, package, state, partial


# --- plan validation -----------------------------------------------------------------


def unique_debs(analysis: ServerAnalysis) -> dict[str, list]:
    """deb file name -> plan rows using it (a shared .deb is downloaded once)."""
    debs: dict[str, list] = {}
    for p in analysis.plan:
        if p.deb_filename:
            debs.setdefault(p.deb_filename, []).append(p)
    return debs


def check_plan(analysis: ServerAnalysis) -> list[str]:
    """Reasons why this analysis must not be patched (empty list: plan is complete)."""
    if analysis.status == "failed":
        return ["The analysis of this server failed."]
    if analysis.status != "complete":
        return ["The analysis of this server is not complete."]
    reasons: list[str] = []
    missing = [
        label
        for label, value in (
            ("IP address", analysis.ip_address),
            ("remote hostname", analysis.remote_hostname),
            ("Ubuntu version", analysis.os_version_id),
            ("codename", analysis.os_codename),
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
    if not analysis.plan:
        reasons.append("There are no package updates to install.")
    for p in analysis.plan:
        name = p.binary_package
        if p.status != "planned":
            reasons.append(f"{name}: package download plan is unresolved.")
            continue
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
            continue
        if not p.architecture or p.architecture not in (analysis.architecture, "all"):
            reasons.append(f"{name}: architecture {p.architecture or '?'} is unresolved.")
            continue
        if not apt_planner.PKG_NAME_RE.match(name) or ":" in name:
            reasons.append(f"{name}: unexpected package name.")
            continue
        expected = apt_planner.expected_deb_filename(name, p.target_version, p.architecture)
        if p.deb_filename and p.deb_filename != expected:
            reasons.append(f"{name}: plan is inconsistent (.deb {p.deb_filename} != {expected}).")
        elif p.uri and not apt_planner.uri_basename_matches(p.uri, expected):
            reasons.append(f"{name}: plan is inconsistent (URI does not point at {expected}).")
        if not p.is_dependency and not p.current_version:
            reasons.append(f"{name}: plan is inconsistent (installed version unknown).")
        if p.current_version:
            try:
                if debversion.compare_versions(p.target_version, p.current_version) <= 0:
                    reasons.append(
                        f"{name}: plan is inconsistent (target {p.target_version} is not newer "
                        f"than installed {p.current_version})."
                    )
            except debversion.InvalidVersionError:
                reasons.append(f"{name}: installed version is invalid.")
    for filename, rows in unique_debs(analysis).items():
        if len({(r.uri, r.checksum, r.size) for r in rows}) > 1:
            reasons.append(f"{filename}: plan is inconsistent (conflicting URI/checksum/size).")
    covered = {cve for p in analysis.plan for cve in p.cves}
    for f in analysis.findings:
        if f.status != cve_resolver.PATCH_AVAILABLE:
            continue
        if not f.fixed_version:
            reasons.append(f"{f.cve}: fixed version is unresolved.")
        elif f.cve not in covered:
            reasons.append(f"{f.cve}: patch required but there is no exact package plan.")
    return list(dict.fromkeys(reasons))


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
    notes: list[str] = field(default_factory=list)

    @property
    def filenames(self) -> list[str]:
        return sorted(self.debs)


class PatchService:
    def __init__(
        self,
        db: Database,
        runner: ssh_service.Runner = subprocess.run,
        starter: Starter = thread_starter,
        fetcher: downloader.Fetcher | None = None,
        analysis_running: Callable[[], bool] = lambda: False,
    ):
        self.db = db
        self.runner = runner
        self.starter = starter
        self.fetcher = fetcher or downloader.urllib_fetcher
        self.analysis_running = analysis_running
        self._lock = threading.Lock()
        self._running = False

    @property
    def is_running(self) -> bool:
        return self._running

    # --- settings ---------------------------------------------------------------------

    def staging_template(self) -> str:
        return self.db.get_setting(STAGING_SETTING) or staging.DEFAULT_LOCAL_TEMPLATE

    # --- eligibility -------------------------------------------------------------------

    def eligibility(self, analysis: ServerAnalysis) -> Eligibility:
        result = Eligibility(allowed=False)
        result.execution = self.db.get_execution_for_analysis(analysis.id)
        debs = unique_debs(analysis)
        result.packages, result.debs = len(analysis.plan), len(debs)
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
        if active is not None or self._running:
            reasons.append(f"Another patch execution is running (#{active}).")
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

    def approve(self, analysis_id: int) -> int:
        """Record APPROVED (after re-checking eligibility) and start the execution."""
        analysis = self.db.get_server_analysis(analysis_id)
        if analysis is None:
            raise PatchNotAllowedError("This analysis no longer exists.")
        with self._lock:
            if self._running:
                raise PatchNotAllowedError("Another patch execution is running.")
            check = self.eligibility(analysis)
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
                    analysis, ps.APPROVED, check.local_path, check.remote_path, packages
                )
            except DecisionExistsError as exc:
                raise PatchNotAllowedError(
                    "A decision was already recorded for this report."
                ) from exc
            except ExecutionActiveError as exc:
                raise PatchNotAllowedError("Another patch execution is running.") from exc
            self._running = True
        logger.info(
            "Patch APPROVED: server=%s analysis=%s execution=%s local=%s remote=%s",
            analysis.server_name, analysis.id, execution_id, check.local_path, check.remote_path,
        )  # fmt: skip
        try:
            self.starter(lambda: self._run_safely(execution_id))
        except Exception:
            self._running = False
            self.db.transition_execution(
                execution_id, ps.APPROVED, ps.FAILED, finished_at=_now(),
                error_title=PATCH_FAILED, error_summary="Could not start the patch execution.",
                failure_stage=ps.APPROVED, cleanup_status="NOT_NEEDED",
            )  # fmt: skip
            raise
        return execution_id

    def _run_safely(self, execution_id: int) -> None:
        try:
            self.execute(execution_id)
        except Exception:
            # execute() records every failure itself; this only triggers if the database
            # is unusable. The execution then stays active until the next startup, where
            # mark_interrupted_executions() records it as FAILED/UNKNOWN.
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
            self._fail(execution_id, state, abort, ctx)
        except Exception as exc:
            logger.exception("Patch execution %s (%s) crashed in %s", execution_id, name, state)
            post_install = state in ps.POST_INSTALL
            self._fail(
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

    def _fail(self, execution_id: int, state: str, abort: PatchAbort, ctx) -> None:
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
        if target == ps.SUCCESS_WITH_CLEANUP_WARNING:
            fields = {
                "finished_at": _now(),
                "cleanup_status": "WARNING",
                "cleanup_detail": f"Cleanup error: {abort}",
            }
        if ctx is not None and ctx.notes:
            fields["notes"] = ctx.notes
        self.db.transition_execution(execution_id, state, target, **fields)
        logger.warning(
            "Patch execution %s (%s): %s -> %s: %s",
            execution_id, execution.server_name, state, target, abort,
        )  # fmt: skip

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
        for plan in analysis.plan:
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
        )

    def _remote(self, ctx: _Context, command: str, timeout: int) -> ssh_service.RemoteResult:
        return ssh_service.run_remote(ctx.ip, ctx.pem, command, runner=self.runner, timeout=timeout)

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
                "Passwordless sudo (sudo -n) is not available for the ubuntu user. EC2Patcher "
                "never asks for a sudo password; configure non-interactive sudo and retry."
            )

    def _revalidate(self, ctx: _Context) -> None:
        a = ctx.analysis
        result = self._remote(ctx, server_state.FACTS_COMMAND, REVALIDATE_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Pre-patch revalidation failed: {result.error}")
        try:
            facts = server_state.parse_facts(result.stdout)
        except server_state.RemoteOutputError as exc:
            raise PatchAbort(f"Pre-patch revalidation failed: {exc}") from exc
        drift = []
        for label, now, then in (
            ("Hostname", facts.hostname, a.remote_hostname),
            ("Ubuntu VERSION_ID", facts.version_id, a.os_version_id),
            ("Codename", facts.codename, a.os_codename),
            ("Architecture", facts.architecture, a.architecture),
        ):
            if now != then:
                drift.append(f"{label} changed: {then} -> {now}")
        if facts.os_id != "ubuntu":
            drift.append(f"Operating system is not Ubuntu ({facts.os_id or 'unknown'}).")
        installed = {(p.base_name, p.architecture): p.version for p in facts.packages}
        for pkg in ctx.packages:
            current = installed.get((pkg.binary_package, pkg.architecture))
            if current != pkg.before_version:
                drift.append(
                    f"{pkg.binary_package} ({pkg.architecture}): installed "
                    f"{current or 'not installed'}, analysis recorded "
                    f"{pkg.before_version or 'not installed'}"
                )
        if drift:
            raise PatchAbort(f"{DRIFT_MESSAGE} " + "; ".join(drift), title=SERVER_CHANGED)
        self._check_sudo(ctx)
        logger.info("Patch execution %s: revalidation passed", ctx.execution.id)

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
            size = ctx.debs[filename]["size"]
            timeout = min(3600, 120 + size // (256 * 1024))
            sent = ssh_service.run_scp(
                ctx.ip, ctx.pem, [str(ctx.local_dir / filename)], ctx.remote_dir,
                runner=self.runner, timeout=timeout,
            )  # fmt: skip
            outcome = "TRANSFERRED" if sent.ok else "FAILED"
            for p in self._packages_with(ctx, filename):
                self.db.update_execution_package(p.id, transfer_result=outcome)
            if not sent.ok:
                raise PatchAbort(f"Transfer of {filename} failed: {sent.error}", package=filename)
            logger.info("Patch execution %s: transferred %s", ctx.execution.id, filename)

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
        command = patch_remote.simulate_command(ctx.remote_dir, ctx.filenames)
        result = self._remote(ctx, command, SIMULATE_TIMEOUT_SECONDS)
        if not result.ok:
            raise PatchAbort(f"Install simulation failed: {result.error}")
        parsed = patch_remote.parse_apt(result.stdout, "simulate")
        self.db.update_execution(ctx.execution.id, simulation_output=_tail(parsed.output))
        check = patch_remote.check_simulation(parsed, self._expected(ctx))
        if not check.ok:
            raise PatchAbort("Install simulation rejected: " + "; ".join(check.problems))
        logger.info("Patch execution %s: install simulation passed", ctx.execution.id)

    def _install(self, ctx: _Context) -> patch_remote.PostInstallState:
        command = patch_remote.install_command(ctx.remote_dir, ctx.filenames)
        logger.info("Patch execution %s: installing %d .deb(s)", ctx.execution.id, len(ctx.debs))
        result = self._remote(ctx, command, INSTALL_TIMEOUT_SECONDS)
        parsed = patch_remote.parse_apt(result.stdout, "install")
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
        command = patch_remote.post_install_command([p.binary_package for p in ctx.packages])
        result = self._remote(ctx, command, SIMULATE_TIMEOUT_SECONDS)
        if not result.ok:
            logger.warning("Patch execution %s: state query failed", ctx.execution.id)
            return None
        return patch_remote.parse_post_install(result.stdout)

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
                cmp = debversion.compare_versions(after, pkg.target_version)
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
                resulting = min((s.source_version for s in matches), key=debversion.version_key)
                row["resulting_version"] = resulting
                if debversion.compare_versions(resulting, f.fixed_version) >= 0:
                    row["result"] = "VERIFIED"
                    if any(cve_resolver.KERNEL_REBOOT_RE.match(s.name) for s in matches):
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


# --- presentation -------------------------------------------------------------------


@dataclass
class ProgressStep:
    label: str
    status: str  # done | running | failed | pending


def progress_steps(execution: PatchExecution) -> list[ProgressStep]:
    """The step list shown while/after patching (no raw terminal output)."""
    if execution.decision != ps.APPROVED:
        return []
    debs: dict[str, PatchPackageResult] = {}
    for p in execution.packages:
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
