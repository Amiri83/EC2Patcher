"""Validation of user-supplied server settings and server tags."""

import ipaddress
import os
import re
from dataclasses import dataclass, field
from itertools import zip_longest
from pathlib import Path

from ec2patcher.database import Database
from ec2patcher.models import AUTH_METHODS, AUTH_PASSWORD, AUTH_PEM, DEFAULT_SSH_USER

# Server names are later used to match CVE reports and to name per-server
# directories, so keep them to a filesystem- and shell-safe character set.
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
NAME_MAX_LENGTH = 64
# SSH login user: a portable POSIX user name (it ends up in ``user@host`` on the ssh/scp
# command line, after ``--``, so it can never be read as an option or contain '@' / ':').
SSH_USER_RE = re.compile(r"[a-z_][a-z0-9_.-]*")  # fullmatch: no trailing newline
SSH_USER_MAX_LENGTH = 32
PEM_PATH_MAX_LENGTH = 1024
TAG_KEY_MAX_LENGTH = 64
TAG_VALUE_MAX_LENGTH = 256
MAX_TAGS_PER_SERVER = 50


@dataclass
class ServerInput:
    name: str
    ip_address: str
    pem_path: str
    tags: list[tuple[str, str]] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    ssh_user: str = DEFAULT_SSH_USER
    auth_method: str = AUTH_PEM

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


def check_ssh_user(user: str) -> str | None:
    """Return an error message, or None if ``user`` is a valid SSH login user name."""
    if not user:
        return "SSH user is required."
    if len(user) > SSH_USER_MAX_LENGTH:
        return f"SSH user must be at most {SSH_USER_MAX_LENGTH} characters."
    if not SSH_USER_RE.fullmatch(user):
        return (
            "SSH user may only contain lowercase letters, digits, '.', '_' and '-', "
            "and must start with a lowercase letter or '_'."
        )
    return None


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


def tag_rows(keys: list[str] | None, values: list[str] | None) -> list[dict[str, str]]:
    """Pair up submitted tag keys/values (parallel form arrays), trimmed.

    Rows where both key and value are blank are dropped. Mismatched array lengths are
    padded with empty strings instead of failing.
    """
    rows = []
    for key, value in zip_longest(keys or [], values or [], fillvalue=""):
        key, value = str(key or "").strip(), str(value or "").strip()
        if key or value:
            rows.append({"key": key, "value": value})
    return rows


def check_tags(rows: list[dict[str, str]]) -> str | None:
    """Return an error message for invalid tag rows, or None. Keys are case-insensitive."""
    if len(rows) > MAX_TAGS_PER_SERVER:
        return f"A server can have at most {MAX_TAGS_PER_SERVER} tags."
    problems = []
    seen: set[str] = set()
    for number, row in enumerate(rows, start=1):
        key, value = row["key"], row["value"]
        if not key:
            problems.append(f"Tag {number}: key is required.")
        elif len(key) > TAG_KEY_MAX_LENGTH:
            problems.append(f"Tag {number}: key must be at most {TAG_KEY_MAX_LENGTH} characters.")
        elif key.casefold() in seen:
            problems.append(f"Duplicate tag key: {key}")
        if len(value) > TAG_VALUE_MAX_LENGTH:
            problems.append(
                f"Tag {number}: value must be at most {TAG_VALUE_MAX_LENGTH} characters."
            )
        seen.add(key.casefold())
    return " ".join(problems) or None


def validate_server_input(
    db: Database,
    name: str,
    ip_address: str,
    pem_path: str,
    exclude_id: int | None = None,
    tag_keys: list[str] | None = None,
    tag_values: list[str] | None = None,
    ssh_user: str = DEFAULT_SSH_USER,
    auth_method: str = AUTH_PEM,
) -> ServerInput:
    """Validate and normalize server form input. Uniqueness is checked against the DB.

    Password login needs no PEM file (the path is cleared); the password itself is never
    part of the server input."""
    result = ServerInput(
        name=(name or "").strip(),
        ip_address=(ip_address or "").strip(),
        pem_path=(pem_path or "").strip(),
        ssh_user=(ssh_user or "").strip(),
        auth_method=(auth_method or AUTH_PEM).strip(),
    )
    if result.auth_method not in AUTH_METHODS:
        result.errors["auth_method"] = "Choose PEM key or username + password login."

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

    if result.auth_method == AUTH_PASSWORD:
        result.pem_path = ""
    else:
        pem_error = check_pem_path(result.pem_path)
        if pem_error:
            result.errors["pem_path"] = pem_error

    user_error = check_ssh_user(result.ssh_user)
    if user_error:
        result.errors["ssh_user"] = user_error

    rows = tag_rows(tag_keys, tag_values)
    tags_error = check_tags(rows)
    if tags_error:
        result.errors["tags"] = tags_error
    else:
        result.tags = [(row["key"], row["value"]) for row in rows]

    return result
