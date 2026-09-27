"""Validation of user-supplied server settings."""

import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ec2patcher.database import Database

# Server names are later used to match CVE reports and to name per-server
# directories, so keep them to a filesystem- and shell-safe character set.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
NAME_MAX_LENGTH = 64
PEM_PATH_MAX_LENGTH = 1024


@dataclass
class ServerInput:
    name: str
    ip_address: str
    pem_path: str
    errors: dict[str, str] = field(default_factory=dict)

    @property
    def is_valid(self) -> bool:
        return not self.errors


def expand_pem_path(pem_path: str) -> Path:
    return Path(os.path.expanduser(pem_path.strip()))


def check_pem_path(pem_path: str) -> str | None:
    """Return an error message, or None if the path points to a readable regular file.

    Only file metadata is inspected; the key contents are never opened.
    """
    if not pem_path or not pem_path.strip():
        return "PEM file path is required."
    if len(pem_path) > PEM_PATH_MAX_LENGTH:
        return "PEM file path is too long."
    path = expand_pem_path(pem_path)
    if not path.exists():
        return f"PEM file does not exist: {path}"
    if not path.is_file():
        return f"PEM path is not a regular file: {path}"
    if not os.access(path, os.R_OK):
        return f"PEM file is not readable (check file permissions): {path}"
    return None


def check_ip_address(ip: str) -> tuple[str | None, str | None]:
    """Return (normalized_ip, error)."""
    ip = (ip or "").strip()
    if not ip:
        return None, "IP address is required."
    try:
        return str(ipaddress.ip_address(ip)), None
    except ValueError:
        return None, f"'{ip}' is not a valid IP address."


def check_name(name: str) -> str | None:
    if not name:
        return "Server name is required."
    if len(name) > NAME_MAX_LENGTH:
        return f"Server name must be at most {NAME_MAX_LENGTH} characters."
    if not NAME_RE.match(name):
        return (
            "Server name may only contain letters, digits, '.', '_' and '-', "
            "and must start with a letter or digit."
        )
    return None


def validate_server_input(
    db: Database, name: str, ip_address: str, pem_path: str, exclude_id: int | None = None
) -> ServerInput:
    """Validate and normalize server form input. Uniqueness is checked against the DB."""
    result = ServerInput(
        name=(name or "").strip(),
        ip_address=(ip_address or "").strip(),
        pem_path=(pem_path or "").strip(),
    )

    name_error = check_name(result.name)
    if name_error is None:
        existing = db.get_server_by_name(result.name)
        if existing is not None and existing.id != exclude_id:
            name_error = f"A server named '{existing.name}' already exists. Names must be unique."
    if name_error:
        result.errors["name"] = name_error

    normalized_ip, ip_error = check_ip_address(result.ip_address)
    if ip_error:
        result.errors["ip_address"] = ip_error
    else:
        result.ip_address = normalized_ip

    pem_error = check_pem_path(result.pem_path)
    if pem_error:
        result.errors["pem_path"] = pem_error

    return result
