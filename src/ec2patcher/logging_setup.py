"""Application log file: a size-rotated file in a configurable directory.

The directory is chosen on the Settings page (stored as the ``log_dir`` setting) and defaults
to the per-user log directory from platformdirs. Only one application file handler exists at
a time; changing the directory moves logging to the new file immediately.
"""

import logging
import os
import sys
import tempfile
from logging.handlers import RotatingFileHandler
from pathlib import Path

from ec2patcher import config

LOG_DIR_SETTING = "log_dir"
LOG_MAX_BYTES = 5 * 1024 * 1024  # rotate at 5 MB ...
LOG_BACKUP_COUNT = 5  # ... keeping 5 old files (ec2patcher.log.1 .. .5)
LOG_DIR_MAX_LENGTH = 1024
LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"

_MARKER = "_ec2patcher_log_file"  # attribute set on the handler installed by this module


def setup_console_logging() -> None:
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    root.addHandler(handler)


def check_log_dir(raw: str) -> tuple[Path | None, str | None]:
    """(directory, error): ``raw`` must be an absolute path (``~`` expanded) to a directory
    that exists or can be created and that a file can actually be written to."""
    raw = (raw or "").strip()
    if not raw:
        return None, "Log directory is required."
    if len(raw) > LOG_DIR_MAX_LENGTH or "\x00" in raw:
        return None, "Log directory path is invalid or too long."
    path = Path(os.path.expanduser(raw))
    if not path.is_absolute():
        return None, f"Log directory must be an absolute path: {raw}"
    if path.exists() and not path.is_dir():
        return None, f"Log directory is not a directory: {path}"
    try:
        path.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return None, f"Log directory cannot be created: {path} ({exc.strerror or exc})"
    try:
        with tempfile.TemporaryFile(dir=path):
            pass
    except OSError as exc:
        return None, f"Log directory is not writable: {path} ({exc.strerror or exc})"
    return path, None


def log_dir_for(saved: str | None) -> Path:
    """The configured log directory (saved setting), else the default."""
    if saved:
        return Path(os.path.expanduser(saved))
    return config.get_default_log_dir()


def log_file_in(log_dir: Path) -> Path:
    return Path(log_dir) / config.LOG_FILENAME


def _app_handlers() -> list[logging.Handler]:
    return [h for h in logging.getLogger().handlers if getattr(h, _MARKER, False)]


def active_log_file() -> Path | None:
    """The file the application currently logs to, or None (no file logging)."""
    handlers = _app_handlers()
    return Path(handlers[0].baseFilename) if handlers else None


def configure_file_logging(log_dir: Path) -> Path:
    """Log to ``<log_dir>/ec2patcher.log`` (rotating), replacing the previous app file handler.

    Raises OSError if the file cannot be opened; the previous handler is kept then."""
    path = log_file_in(log_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(
        path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT, encoding="utf-8"
    )
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    setattr(handler, _MARKER, True)
    root = logging.getLogger()
    for old in _app_handlers():
        root.removeHandler(old)
        old.close()
    root.addHandler(handler)
    return path


def stop_file_logging() -> None:
    root = logging.getLogger()
    for old in _app_handlers():
        root.removeHandler(old)
        old.close()
