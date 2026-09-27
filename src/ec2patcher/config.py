"""Application configuration: data locations and defaults."""

import os
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "ec2patcher"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DB_FILENAME = "ec2patcher.db"
LOG_FILENAME = "ec2patcher.log"
DATA_DIR_ENV = "EC2PATCHER_DATA_DIR"


def get_data_dir(override: str | None = None) -> Path:
    """Persistent per-user data directory (e.g. ~/.local/share/ec2patcher on Linux)."""
    raw = override or os.environ.get(DATA_DIR_ENV) or user_data_dir(APP_NAME, appauthor=False)
    path = Path(raw).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    return path
