"""Application configuration: data locations and defaults."""

import math
import os
from datetime import timedelta
from pathlib import Path

from platformdirs import user_config_dir, user_data_dir, user_log_dir

APP_NAME = "ec2patcher"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DB_FILENAME = "ec2patcher.db"
LOG_FILENAME = "ec2patcher.log"
DATA_DIR_ENV = "EC2PATCHER_DATA_DIR"
PLUGIN_BIN_DIRNAME = "bin"  # under the data directory
# Default log directory (the Settings page can choose another one, stored in the database).
LOG_DIR_ENV = "EC2PATCHER_LOG_DIR"
# Shared DadsOps log directory: the default when EC2PATCHER_LOG_DIR is unset.
SHARED_LOG_DIR_ENV = "DADSOPS_LOG_DIR"
# Shared AWS defaults (the AWS CLI's own variables): the default profile and region when none is
# saved in Settings. Only read, never stored in the settings.
AWS_PROFILE_ENV = "AWS_PROFILE"
AWS_REGION_ENV = "AWS_REGION"
# Config directory holding the Fernet key file of the stored secrets (never the database).
CONFIG_DIR_ENV = "EC2PATCHER_CONFIG_DIR"
SECRET_KEY_FILENAME = "secret.key"  # noqa: S105 - a file name, not a secret
# The AWS CLI's own variable for its config file: read here for the profile names, never written.
AWS_CONFIG_FILE_ENV = "AWS_CONFIG_FILE"
DEFAULT_AWS_CONFIG_FILE = "~/.aws/config"

# Private APT state used to resolve candidates and .deb plans on the workstation.
APT_STATE_DIRNAME = "apt"  # under the data directory
APT_STATE_DIR_ENV = "EC2PATCHER_APT_STATE_DIR"
APT_MAX_AGE_ENV = "EC2PATCHER_APT_MAX_AGE_HOURS"
DEFAULT_APT_MAX_AGE_HOURS = 6.0  # 0 = run the private apt-get update on every analysis run

# Canonical per-CVE lookups (unset = the defaults in services.security_metadata).
CANONICAL_TIMEOUT_ENV = "EC2PATCHER_CANONICAL_TIMEOUT_SECONDS"  # per request, default 5
CANONICAL_CACHE_TTL_ENV = "EC2PATCHER_CANONICAL_CACHE_TTL_HOURS"  # settled CVEs, default 24
CANONICAL_BREAKER_ENV = "EC2PATCHER_CANONICAL_BREAKER_THRESHOLD"  # consecutive, default 3


def get_data_dir(override: str | None = None) -> Path:
    """Persistent per-user data directory (e.g. ~/.local/share/ec2patcher on Linux)."""
    raw = override or os.environ.get(DATA_DIR_ENV) or user_data_dir(APP_NAME, appauthor=False)
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path


def get_plugin_bin_dir() -> Path:
    """Where the app keeps the session-manager-plugin it installed: <data dir>/bin (not created)."""
    return get_data_dir() / PLUGIN_BIN_DIRNAME


def get_config_dir() -> Path:
    """Per-user config directory (e.g. ~/.config/ec2patcher on Linux), or
    $EC2PATCHER_CONFIG_DIR. Not created here."""
    raw = os.environ.get(CONFIG_DIR_ENV) or user_config_dir(APP_NAME, appauthor=False)
    return Path(raw).expanduser()


def get_secret_key_path() -> Path:
    """Fernet key file that encrypts the stored secrets (kept outside the database)."""
    return get_config_dir() / SECRET_KEY_FILENAME


def get_aws_config_path() -> Path:
    """The config file the AWS CLI uses: $AWS_CONFIG_FILE, else ~/.aws/config."""
    return Path(os.environ.get(AWS_CONFIG_FILE_ENV) or DEFAULT_AWS_CONFIG_FILE).expanduser()


def get_default_log_dir() -> Path:
    """Default log directory: $EC2PATCHER_LOG_DIR, else $DADSOPS_LOG_DIR, else the per-user log
    dir from platformdirs (e.g. ~/.local/state/ec2patcher/log on Linux). Not created here."""
    return Path(default_log_dir_source()[0]).expanduser()


def default_log_dir_source() -> tuple[str, str | None]:
    """(raw directory, name of the environment variable it came from or None)."""
    for name in (LOG_DIR_ENV, SHARED_LOG_DIR_ENV):
        if raw := os.environ.get(name):
            return raw, name
    return user_log_dir(APP_NAME, appauthor=False), None


def get_env_aws_default(name: str) -> str | None:
    """$AWS_PROFILE / $AWS_REGION stripped, or None when unset or empty."""
    return os.environ.get(name, "").strip() or None


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
