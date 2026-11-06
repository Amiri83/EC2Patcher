"""Live progress of analysis and patch runs: step events, the step timeout and cancelling.

Every run writes step events to the ``run_events`` table as it goes; this module is the only
writer. A failing write is logged and ignored: progress must never break a run. Messages are
cleaned on the way in (one line, trimmed, no traceback, no ARN, no credential).

A step is a start event (no ``duration_ms``), any number of notes, and an end event with its
``duration_ms``, at ``level="error"`` if it failed. A run is named by a :class:`RunRef`, as analysis
run, patch execution and Patch All queue ids are separate number ranges: ``12``, ``patch-12`` and
``queue-3`` are three different runs. A patch execution of a queue reports to its queue.

Timeouts bound single blocking calls, never a whole loop: every CVE lookup gets its own, so a long
list of CVEs is not cut off while it makes progress. The call runs in a helper thread that is
abandoned when it overruns, so a child process that never returns cannot hang the run. Only calls
that write nothing to the run's results are guarded, so an abandoned one cannot change them.

Cancel requests live in the database and are checked between steps. :class:`StepInterrupt` is a
BaseException so that the ``except Exception`` around a single CVE, which keeps one bad CVE from
breaking a report, does not swallow it; the services catch it around each server.
"""

import logging
import math
import re
import threading
import time
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass

from ec2patcher.database import Database
from ec2patcher.services import patch_state as ps
from ec2patcher.services import ssm_service

logger = logging.getLogger(__name__)

KIND_ANALYSIS, KIND_PATCH, KIND_QUEUE = "analysis", "patch", "queue"

INFO, WARNING, ERROR = "info", "warning", "error"
LEVELS = (INFO, WARNING, ERROR)

# Analysis steps, in order.
RESOLVE_INSTANCE = "resolve_instance"
SSM_CHECK = "ssm_check"
OPEN_SSH = "open_ssh"
DETECT_OS = "detect_os"
LIST_PACKAGES = "list_packages"
MAP_CVES = "map_cves"
LOOKUPS = "lookups"
COMPUTE_FIXES = "compute_fixes"
# How a server (server set) or the whole run (no server) ended.
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"
# Patch steps after the shared RESOLVE_INSTANCE and SSM_CHECK, in order.
REVALIDATE = "revalidate"
DOWNLOAD = "download"
VERIFY_DOWNLOADS = "verify_downloads"
TRANSFER = "transfer"
VERIFY_TRANSFER = "verify_transfer"
SIMULATE = "simulate"
INSTALL = "install"
VERIFY_INSTALL = "verify_install"
CLEANUP = "cleanup"
REBOOT = "reboot"

ANALYSIS_PHASES = (
    RESOLVE_INSTANCE, SSM_CHECK, OPEN_SSH, DETECT_OS, LIST_PACKAGES, MAP_CVES, LOOKUPS,
    COMPUTE_FIXES,
)  # fmt: skip
PATCH_PHASES = (
    RESOLVE_INSTANCE, SSM_CHECK, REVALIDATE, DOWNLOAD, VERIFY_DOWNLOADS, TRANSFER, VERIFY_TRANSFER,
    SIMULATE, INSTALL, VERIFY_INSTALL, CLEANUP, REBOOT,
)  # fmt: skip
TERMINAL_PHASES = (DONE, FAILED, CANCELLED)
PHASES = frozenset({*ANALYSIS_PHASES, *PATCH_PHASES, *TERMINAL_PHASES})

PHASE_LABELS = {
    RESOLVE_INSTANCE: "Resolve instance ID",
    SSM_CHECK: "SSM check",
    OPEN_SSH: "Open SSH/SCP",
    DETECT_OS: "Detect OS/release",
    LIST_PACKAGES: "List installed packages",
    MAP_CVES: "Map CVEs to packages",
    LOOKUPS: "Canonical/NVD/Amazon lookups",
    COMPUTE_FIXES: "Compute fix versions",
    DONE: "Done",
    FAILED: "Failed",
    CANCELLED: "Cancelled",
    REVALIDATE: "Revalidate server state",
    DOWNLOAD: "Download packages",
    VERIFY_DOWNLOADS: "Verify downloads",
    TRANSFER: "Transfer packages",
    VERIFY_TRANSFER: "Verify transfer",
    SIMULATE: "Simulate install",
    INSTALL: "Install",
    VERIFY_INSTALL: "Verify install",
    CLEANUP: "Clean up",
    REBOOT: "Reboot",
}

# The command timeouts sit just above the step timeout, so that the step's own message wins.
TIMEOUT_GRACE_SECONDS = 5
MAX_MESSAGE = 500
MAX_EVENTS_PER_POLL = 500

SERVER_CANCELLED = "The run was cancelled before this server finished."
SERVER_SKIPPED = "The run was cancelled before this server was analyzed."

_REF_RE = re.compile(r"(?:(patch|queue)-)?([1-9]\d{0,17})")
_TRACEBACK = "Traceback (most recent call last)"
_PROFILE_RE = re.compile(r"\bprofile[ =]+([A-Za-z0-9_@-][A-Za-z0-9_.@-]*)")
_SSM_RE = re.compile(r"\bssm\b|systems manager|session-manager-plugin|start-session", re.IGNORECASE)
_SSH_AUTH_RE = re.compile(
    r"permission denied|publickey|authentication failed|too many authentication|password was "
    r"rejected|ssh password",
    re.IGNORECASE,
)
_REDACTIONS = (
    (
        re.compile(
            r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)",
            re.DOTALL,
        ),
        "<private key>",
    ),
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "<aws key>"),
    (
        re.compile(
            r"\b(password|passwd|pwd|secret|token|api[_-]?key|sshpass)(\s*[=:]\s*)\S+",
            re.IGNORECASE,
        ),
        r"\1\2<redacted>",
    ),
)
SSM_HINT = (
    "Check SSH over SSM in Settings > Connection: the Session Manager plugin, the AWS profile and "
    "region, and that the instance is online in Systems Manager."
)
SSH_AUTH_HINT = (
    "Check the SSH user and the PEM key or stored password of this server on the Servers page."
)


@dataclass(frozen=True)
class RunRef:
    kind: str
    id: int

    @property
    def text(self) -> str:
        return str(self.id) if self.kind == KIND_ANALYSIS else f"{self.kind}-{self.id}"


def parse_ref(text: str) -> RunRef | None:
    """``12``, ``patch-12`` or ``queue-3``; None for anything else."""
    match = _REF_RE.fullmatch(text or "")
    if not match:
        return None
    return RunRef(match.group(1) or KIND_ANALYSIS, int(match.group(2)))


def execution_ref(execution) -> RunRef:
    """The run a patch execution reports to."""
    if execution.queue_id:
        return RunRef(KIND_QUEUE, execution.queue_id)
    return RunRef(KIND_PATCH, execution.id)


# --- writing ------------------------------------------------------------------------------


def clean_message(text) -> str:
    """One short line without a traceback, an ARN or a credential."""
    message = str(text or "")
    if _TRACEBACK in message:
        message = message.split(_TRACEBACK)[0].strip() or "Unexpected error; see the log."
    message = ssm_service.clean_session_stderr(message)
    for pattern, replacement in _REDACTIONS:
        message = pattern.sub(replacement, message)
    message = " ".join(message.split())
    return message if len(message) <= MAX_MESSAGE else message[: MAX_MESSAGE - 1] + "…"


def emit(
    db: Database,
    ref: RunRef,
    phase: str,
    message: str,
    server: str | None = None,
    level: str = INFO,
    duration_ms: int | None = None,
) -> int | None:
    """Write one event now. Never raises: returns None when it could not be written."""
    try:
        if phase not in PHASES or level not in LEVELS:
            raise ValueError(f"unknown phase or level: {phase}, {level}")
        return db.add_run_event(
            ref.kind, ref.id, server, phase, clean_message(message), level, duration_ms
        )
    except Exception as exc:  # noqa: BLE001 - progress must never break a run
        logger.warning("Could not write a progress event of run %s: %s", ref.text, exc)
        return None


def cancel_requested(db: Database, ref: RunRef) -> bool:
    try:
        return db.run_cancel_requested(ref.kind, ref.id)
    except Exception as exc:  # noqa: BLE001 - progress must never break a run
        logger.warning("Could not read the cancel request of run %s: %s", ref.text, exc)
        return False


def clear_cancel(db: Database, ref: RunRef) -> None:
    try:
        db.clear_run_cancel(ref.kind, ref.id)
    except Exception as exc:  # noqa: BLE001 - progress must never break a run
        logger.warning("Could not clear the cancel request of run %s: %s", ref.text, exc)


# --- steps --------------------------------------------------------------------------------


class StepInterrupt(BaseException):  # noqa: N818 - control flow, see the module docstring
    pass


class StepTimeoutError(StepInterrupt):
    """A blocking call of a step overran the step timeout. The message is user-facing."""


class RunCancelled(StepInterrupt):  # noqa: N818 - control flow
    pass


def run_with_timeout(fn: Callable[[], object], timeout: float, step: str) -> object:
    """``fn()``'s result or exception. Raises :class:`StepTimeoutError` when it overruns."""
    outcome: dict = {}
    finished = threading.Event()

    def target() -> None:
        try:
            outcome["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the caller below
            outcome["error"] = exc
        finally:
            finished.set()

    threading.Thread(target=target, name="ec2patcher-step", daemon=True).start()
    if not finished.wait(timeout):
        raise StepTimeoutError(
            f"Step '{step}' timed out after {timeout:g} s (per-step timeout, see Settings)."
        )
    if "error" in outcome:
        raise outcome["error"]
    return outcome.get("value")


class Step:
    """One running step of a server. Ended once; later calls do nothing."""

    def __init__(self, steps: "Steps", phase: str):
        self.steps, self.phase = steps, phase
        self.started = steps.clock()
        self.ended = False

    def note(self, message: str, level: str = INFO) -> None:
        self.steps.record(self.phase, message, level=level)

    def _end(self, message: str, level: str, duration_ms: int | None) -> None:
        if self.ended:
            return
        self.ended = True
        if duration_ms is None:
            duration_ms = int((self.steps.clock() - self.started) * 1000)
        self.steps.record(self.phase, message, level=level, duration_ms=duration_ms)

    def finish(self, message: str | None = None, duration_ms: int | None = None) -> None:
        self._end(message or f"{PHASE_LABELS[self.phase]}: done", INFO, duration_ms)

    def fail(self, message: str) -> None:
        self._end(message, ERROR, None)


class Steps:
    """The steps of one server (or, without a server, of the run itself)."""

    def __init__(
        self,
        db: Database,
        ref: RunRef,
        server: str | None,
        timeout: float,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.db, self.ref, self.server, self.timeout = db, ref, server, timeout
        self.clock = clock
        self.started = clock()

    def record(
        self, phase: str, message: str, level: str = INFO, duration_ms: int | None = None
    ) -> None:
        emit(self.db, self.ref, phase, message, self.server, level, duration_ms)

    def check_cancelled(self) -> None:
        if cancel_requested(self.db, self.ref):
            raise RunCancelled()

    def begin(self, phase: str, message: str, cancellable: bool = True) -> Step:
        """Start a step; a requested cancel stops the run here, between two steps."""
        if cancellable:
            self.check_cancelled()
        self.record(phase, message)
        return Step(self, phase)

    @contextmanager
    def step(self, phase: str, message: str):
        """A step that ends with the block: failed if it raises, unless it was ended before."""
        current = self.begin(phase, message)
        try:
            yield current
        except RunCancelled:
            current.finish()
            raise
        except (StepTimeoutError, Exception) as exc:
            current.fail(str(exc))
            raise
        current.finish()

    def guard(self, fn: Callable[[], object], phase: str | None = None) -> object:
        """Run a blocking call under the step timeout."""
        label = PHASE_LABELS.get(phase, "command") if phase else "command"
        return run_with_timeout(fn, self.timeout, label)

    def command_timeout(self, own_seconds: int) -> int:
        """The timeout of a child process: its own, at most just above the step timeout."""
        return min(own_seconds, math.ceil(self.timeout) + TIMEOUT_GRACE_SECONDS)

    def end(self, phase: str, message: str, level: str = INFO) -> None:
        """How the server (or run) ended, with its total duration."""
        duration = int((self.clock() - self.started) * 1000)
        self.record(phase, message, level=level, duration_ms=duration)

    def guarded(self, target: object, phase: str) -> "_GuardedCalls":
        return _GuardedCalls(target, self, phase)


class _GuardedCalls:
    """``target`` with every method call under the step timeout."""

    def __init__(self, target: object, steps: Steps, phase: str):
        self._target, self._steps, self._phase = target, steps, phase

    def __getattr__(self, name: str):
        attribute = getattr(self._target, name)
        if not callable(attribute):
            return attribute

        def call(*args, **kwargs):
            return self._steps.guard(lambda: attribute(*args, **kwargs), self._phase)

        return call


def resolve_transport(steps: Steps, resolve: Callable[[], ssm_service.Transport]):
    """The transport of a server, reported as the resolve-instance and SSM-check steps.

    The resolver checks SSM first, as instance lookups need working credentials, and does both in
    one call: the two steps are written when it returns, each with the time it really took."""
    step = steps.begin(RESOLVE_INSTANCE, "Choosing the transport and looking up the instance ID")
    transport = steps.guard(resolve, RESOLVE_INSTANCE)
    total = int((steps.clock() - step.started) * 1000)
    preflight = transport.preflight_ms
    if preflight is None:
        if transport.error:
            step.fail(transport.error)
        else:
            step.finish("Not needed: direct SSH", duration_ms=total)
            steps.record(SSM_CHECK, "Not needed: direct SSH", duration_ms=0)
        return transport
    lookup_ms = max(0, total - preflight)
    if transport.preflight_failed:
        step.finish("Not looked up: the SSM check failed", duration_ms=lookup_ms)
        steps.record(SSM_CHECK, transport.error, level=ERROR, duration_ms=preflight)
        return transport
    if transport.error:
        step._end(transport.error, ERROR, lookup_ms)
    else:
        step.finish(transport.target.instance_id, duration_ms=lookup_ms)
    steps.record(SSM_CHECK, "AWS CLI, Session Manager plugin and profile OK", duration_ms=preflight)
    return transport


# --- reading ------------------------------------------------------------------------------


def hint_for(message: str | None) -> str | None:
    """What to do about an error, by its cause: SSO expired, SSM, SSH login; otherwise None."""
    text = message or ""
    match = _PROFILE_RE.search(text)
    profile = match.group(1).rstrip(".") if match else "<profile>"
    if ssm_service.is_sso_expired(text):
        return f"Run `aws sso login --profile {profile}`, then start the run again."
    known = ssm_service.describe_aws_error(text, profile)
    if known:
        return SSM_HINT if known.lower() in text.lower() else known
    if _SSM_RE.search(text):
        return SSM_HINT
    if _SSH_AUTH_RE.search(text):
        return SSH_AUTH_HINT
    return None


def _analysis_view(db: Database, ref: RunRef) -> dict | None:
    run = db.get_analysis_run(ref.id, details=False)
    if run is None:
        return None
    finished = ("complete", "failed", "unsupported", "cancelled")
    cves_done = 0
    for server in run.servers:
        if server.status in finished:
            cves_done += len(server.reported_cves)
        elif server.status == "analyzing":
            seen = db.count_cve_lookup_events(ref.kind, ref.id, server.server_name)
            cves_done += min(seen, len(server.reported_cves))
    return {
        "status": run.status,
        "done": not run.is_running,
        "cancelled": run.status == "cancelled",
        "started_at": run.started_at,
        "finished_at": run.completed_at,
        "servers": [{"name": s.server_name, "status": s.status} for s in run.servers],
        "servers_done": sum(s.status in finished for s in run.servers),
        "servers_total": len(run.servers),
        "cves_done": cves_done,
        "cves_total": sum(len(s.reported_cves) for s in run.servers),
        "phases": ANALYSIS_PHASES,
    }


def _execution_view(db: Database, ref: RunRef) -> dict | None:
    execution = db.get_execution(ref.id)
    if execution is None:
        return None
    done = not ps.in_progress(execution.state, execution.reboot_status)
    total = sum(db.reported_cve_counts([execution.server_analysis_id]).values())
    return {
        "status": execution.state,
        "done": done,
        "cancelled": execution.state == ps.CANCELLED,
        "started_at": execution.started_at or execution.decided_at,
        "finished_at": execution.finished_at,
        "servers": [{"name": execution.server_name, "status": execution.state}],
        "servers_done": int(done),
        "servers_total": 1,
        "cves_done": total if done else 0,
        "cves_total": total,
        "phases": PATCH_PHASES,
    }


def _queue_view(db: Database, ref: RunRef) -> dict | None:
    queue = db.get_patch_queue(ref.id)
    if queue is None:
        return None
    counts = db.reported_cve_counts([i.server_analysis_id for i in queue.items])
    open_items = (ps.ITEM_PENDING, ps.ITEM_RUNNING)
    finished = [i for i in queue.items if i.status not in open_items]
    return {
        "status": queue.state,
        "done": not queue.is_running,
        "cancelled": queue.state == ps.QUEUE_CANCELLED,
        "started_at": queue.created_at,
        "finished_at": queue.finished_at,
        "servers": [{"name": i.server_name, "status": i.status} for i in queue.items],
        "servers_done": len(finished),
        "servers_total": len(queue.items),
        "cves_done": sum(counts.get(i.server_analysis_id, 0) for i in finished),
        "cves_total": sum(counts.values()),
        "phases": PATCH_PHASES,
    }


_VIEWS = {KIND_ANALYSIS: _analysis_view, KIND_PATCH: _execution_view, KIND_QUEUE: _queue_view}


def run_view(db: Database, ref: RunRef) -> dict | None:
    """The state of a run for the progress bars; None for an unknown run."""
    return _VIEWS[ref.kind](db, ref)


def _event_json(row) -> dict:
    return {
        "id": row["id"],
        "ts": row["ts"],
        "server": row["server"],
        "phase": row["phase"],
        "phase_label": PHASE_LABELS.get(row["phase"], row["phase"]),
        "message": row["message"],
        "level": row["level"],
        "duration_ms": row["duration_ms"],
        "hint": hint_for(row["message"]) if row["level"] == ERROR else None,
    }


def events_payload(db: Database, ref: RunRef, after: int) -> dict | None:
    """The answer of the events endpoint: events newer than ``after`` and the state of the run.
    An analysis run writes its last event before its final status; a patch execution right after
    its final state, so the panel reads the events anew once it sees the run done."""
    view = run_view(db, ref)
    if view is None:
        return None
    rows = db.list_run_events(ref.kind, ref.id, after, MAX_EVENTS_PER_POLL + 1)
    more = len(rows) > MAX_EVENTS_PER_POLL
    events = [_event_json(row) for row in rows[:MAX_EVENTS_PER_POLL]]
    phases = view.pop("phases")
    return {
        "run": ref.text,
        "kind": ref.kind,
        "events": events,
        "next": events[-1]["id"] if events else after,
        "more": more,
        "cancel_requested": not view["done"] and db.run_cancel_requested(ref.kind, ref.id),
        "phases": [{"id": p, "label": PHASE_LABELS[p]} for p in phases],
        "terminal_phases": list(TERMINAL_PHASES),
        **view,
    }


def request_cancel(db: Database, ref: RunRef) -> dict | None:
    """Ask a running run to stop after its current step (kept in the database). A no-op on a
    finished run or when already asked. None for an unknown run."""
    view = run_view(db, ref)
    if view is None:
        return None
    answer = {"run": ref.text, "status": view["status"], "cancelled": view["cancelled"]}
    if view["done"]:
        message = "This run has already finished; there is nothing to cancel."
        return {**answer, "accepted": False, "message": message}
    if not db.request_run_cancel(ref.kind, ref.id):
        message = "Cancel was already requested; the run stops after the current step."
        return {**answer, "accepted": False, "message": message}
    message = "Cancel requested: the run stops after the current step."
    if ref.kind == KIND_PATCH and view["status"] in ps.POST_INSTALL | ps.SUCCESSFUL:
        message = (
            "Cancel requested, but the install has already started: it finishes and is verified. "
            "The server is not rebooted."
        )
    emit(db, ref, CANCELLED, message, level=WARNING)
    logger.info("Cancel requested for run %s", ref.text)
    return {**answer, "accepted": True, "message": message}
