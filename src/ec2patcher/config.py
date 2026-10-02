"""Application configuration: data locations and defaults."""

import math
import os
from datetime import timedelta
from pathlib import Path

from platformdirs import user_data_dir, user_log_dir

APP_NAME = "ec2patcher"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DB_FILENAME = "ec2patcher.db"
LOG_FILENAME = "ec2patcher.log"
DATA_DIR_ENV = "EC2PATCHER_DATA_DIR"
# Default log directory (the Settings page can choose another one, stored in the database).
LOG_DIR_ENV = "EC2PATCHER_LOG_DIR"

# Private APT state used to resolve candidates and .deb plans on the workstation.
APT_STATE_DIRNAME = "apt"  # under the data directory
APT_STATE_DIR_ENV = "EC2PATCHER_APT_STATE_DIR"
APT_MAX_AGE_ENV = "EC2PATCHER_APT_MAX_AGE_HOURS"
DEFAULT_APT_MAX_AGE_HOURS = 6.0  # 0 = run the private apt-get update on every analysis run

# Canonical per-CVE lookups (unset = the defaults in services.security_metadata).
CANONICAL_TIMEOUT_ENV = "EC2PATCHER_CANONICAL_TIMEOUT_SECONDS"  # per request, default 20
CANONICAL_CACHE_TTL_ENV = "EC2PATCHER_CANONICAL_CACHE_TTL_HOURS"  # settled CVEs, default 24
CANONICAL_BREAKER_ENV = "EC2PATCHER_CANONICAL_BREAKER_THRESHOLD"  # consecutive, default 3


def get_data_dir(override: str | None = None) -> Path:
    """Persistent per-user data directory (e.g. ~/.local/share/ec2patcher on Linux)."""
    raw = override or os.environ.get(DATA_DIR_ENV) or user_data_dir(APP_NAME, appauthor=False)
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_default_log_dir() -> Path:
    """Default log directory: $EC2PATCHER_LOG_DIR, else the per-user log dir from platformdirs
    (e.g. ~/.local/state/ec2patcher/log on Linux). Not created here."""
    raw = os.environ.get(LOG_DIR_ENV) or user_log_dir(APP_NAME, appauthor=False)
    return Path(raw).expanduser()


def get_apt_state_dir(data_dir: Path, override: str | None = None) -> Path:
    """Root of the private per-release APT states (default: <data dir>/apt)."""
    raw = override or os.environ.get(APT_STATE_DIR_ENV)
    return Path(raw).expanduser() if raw else Path(data_dir) / APT_STATE_DIRNAME


def get_apt_max_age(override: float | None = None) -> timedelta:
    """How old the private APT lists may be before analysis refreshes them."""
    raw = override if override is not None else os.environ.get(APT_MAX_AGE_ENV)
    hours = DEFAULT_APT_MAX_AGE_HOURS if raw in (None, "") else float(raw)
    if not math.isfinite(hours) or hours < 0:
        raise ValueError(f"APT max age must be a non-negative number of hours, got {raw!r}")
    return timedelta(hours=hours)


def _env_number(name: str, minimum: float) -> float | None:
    raw = os.environ.get(name)
    if raw in (None, ""):
        return None
    value = float(raw)
    if not math.isfinite(value) or value < minimum:
        raise ValueError(f"{name} must be a number >= {minimum:g}, got {raw!r}")
    return value


def get_canonical_timeout() -> float | None:
    """Per-request timeout (seconds) of the Canonical Security API, or None for the default."""
    return _env_number(CANONICAL_TIMEOUT_ENV, 1)


def get_canonical_cache_ttl() -> timedelta | None:
    """How long a cached Canonical CVE document is used without a request (None = default)."""
    hours = _env_number(CANONICAL_CACHE_TTL_ENV, 0)
    return None if hours is None else timedelta(hours=hours)


def get_canonical_breaker_threshold() -> int | None:
    """Consecutive failed lookups that stop further Canonical requests for the run."""
    value = _env_number(CANONICAL_BREAKER_ENV, 1)
    return None if value is None else int(value)
