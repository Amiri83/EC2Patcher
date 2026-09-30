"""Phase 3 patch execution states and the only transitions allowed between them.

``PENDING_REVIEW`` is the implicit state of an analysis without a decision (no execution
row). Every persisted change goes through ``check_transition`` and a compare-and-set UPDATE
(see ``Database.transition_execution``), so e.g. REJECTED -> INSTALLING, SUCCESS ->
INSTALLING or PENDING_REVIEW -> INSTALLING can never happen.
"""

PENDING_REVIEW = "PENDING_REVIEW"
REJECTED = "REJECTED"
APPROVED = "APPROVED"
REVALIDATING = "REVALIDATING"
DOWNLOADING = "DOWNLOADING"
VERIFYING_DOWNLOADS = "VERIFYING_DOWNLOADS"
TRANSFERRING = "TRANSFERRING"
VERIFYING_TRANSFER = "VERIFYING_TRANSFER"
SIMULATING_INSTALL = "SIMULATING_INSTALL"
INSTALLING = "INSTALLING"
VERIFYING_INSTALL = "VERIFYING_INSTALL"
CLEANING_UP = "CLEANING_UP"
SUCCESS = "SUCCESS"
SUCCESS_WITH_CLEANUP_WARNING = "SUCCESS_WITH_CLEANUP_WARNING"
FAILED = "FAILED"
UNKNOWN = "UNKNOWN"

# Pipeline order (used for progress display).
PIPELINE = [
    APPROVED,
    REVALIDATING,
    DOWNLOADING,
    VERIFYING_DOWNLOADS,
    TRANSFERRING,
    VERIFYING_TRANSFER,
    SIMULATING_INSTALL,
    INSTALLING,
    VERIFYING_INSTALL,
    CLEANING_UP,
]

ALLOWED_TRANSITIONS: dict[str, frozenset[str]] = {
    PENDING_REVIEW: frozenset({APPROVED, REJECTED}),
    APPROVED: frozenset({REVALIDATING, FAILED}),
    REVALIDATING: frozenset({DOWNLOADING, FAILED}),
    DOWNLOADING: frozenset({VERIFYING_DOWNLOADS, FAILED}),
    VERIFYING_DOWNLOADS: frozenset({TRANSFERRING, FAILED}),
    TRANSFERRING: frozenset({VERIFYING_TRANSFER, FAILED}),
    VERIFYING_TRANSFER: frozenset({SIMULATING_INSTALL, FAILED}),
    SIMULATING_INSTALL: frozenset({INSTALLING, FAILED}),
    # From here on packages may have changed: an unprovable outcome is UNKNOWN, never FAILED
    # or SUCCESS by assumption.
    INSTALLING: frozenset({VERIFYING_INSTALL, FAILED, UNKNOWN}),
    VERIFYING_INSTALL: frozenset({CLEANING_UP, FAILED, UNKNOWN}),
    CLEANING_UP: frozenset({SUCCESS, SUCCESS_WITH_CLEANUP_WARNING}),
    REJECTED: frozenset(),
    SUCCESS: frozenset(),
    SUCCESS_WITH_CLEANUP_WARNING: frozenset(),
    FAILED: frozenset(),
    UNKNOWN: frozenset(),
}

TERMINAL = frozenset(s for s, targets in ALLOWED_TRANSITIONS.items() if not targets)
ACTIVE = frozenset(PIPELINE)  # an approved execution that has not finished
SUCCESSFUL = frozenset({SUCCESS, SUCCESS_WITH_CLEANUP_WARNING})
# States in which remote packages may already have been modified.
POST_INSTALL = frozenset({INSTALLING, VERIFYING_INSTALL, CLEANING_UP})

LABELS = {
    PENDING_REVIEW: "Pending review",
    REJECTED: "Rejected",
    APPROVED: "Approved",
    REVALIDATING: "Revalidating server state",
    DOWNLOADING: "Downloading packages",
    VERIFYING_DOWNLOADS: "Verifying downloads",
    TRANSFERRING: "Transferring packages",
    VERIFYING_TRANSFER: "Verifying transfer",
    SIMULATING_INSTALL: "Simulating install",
    INSTALLING: "Installing",
    VERIFYING_INSTALL: "Verifying installation",
    CLEANING_UP: "Cleaning up",
    SUCCESS: "PATCH SUCCESSFUL",
    SUCCESS_WITH_CLEANUP_WARNING: "PATCH SUCCESSFUL (cleanup warning)",
    FAILED: "PATCH FAILED",
    UNKNOWN: "EXECUTION STATE UNKNOWN",
}

BADGES = {
    REJECTED: "badge-neutral",
    SUCCESS: "badge-success",
    SUCCESS_WITH_CLEANUP_WARNING: "badge-success",
    FAILED: "badge-danger",
    UNKNOWN: "badge-danger",
}


class InvalidTransitionError(RuntimeError):
    """A state change that the execution state machine does not allow."""


def is_allowed(current: str, target: str) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, frozenset())


def check_transition(current: str, target: str) -> None:
    if not is_allowed(current, target):
        raise InvalidTransitionError(f"Transition {current} -> {target} is not allowed.")
