"""Local and remote staging directories for approved .deb files.

Safety rules (both sides):

* The local directory comes from a user template that must contain ``${server_name}`` and
  resolve to an absolute, traversal-free path that is not a system/home/temp root.
* The remote directory is always ``/tmp/<server_name>`` (not configurable).
* An existing directory is only reused if it is empty, or if it carries EC2Patcher's marker
  file and holds nothing but EC2Patcher-managed .deb files (an earlier failed run). Anything
  else aborts the execution; unknown files are never touched.
* Cleanup never removes a tree: it unlinks the exact file names EC2Patcher staged, then the
  marker, then ``rmdir`` (which fails on a non-empty directory).
"""

import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

from ec2patcher.validation import check_name

PLACEHOLDER = "${server_name}"
DEFAULT_LOCAL_TEMPLATE = "/tmp/${server_name}"  # noqa: S108 - per-server subdirectory
REMOTE_BASE = "/tmp"  # noqa: S108 - remote staging is always /tmp/<server_name>
MARKER = ".ec2patcher-staging"
TEMPLATE_MAX_LENGTH = 512

# <package>_<version with ':' as %3a>_<arch>.deb exactly as APT names archive files.
DEB_FILENAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*_[0-9][A-Za-z0-9.+~%-]*_[a-z0-9]+\.deb$")
MANAGED_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*_[0-9][A-Za-z0-9.+~%-]*_[a-z0-9]+\.deb(\.part)?$")

_FORBIDDEN_EXACT = {
    "/", "/tmp", "/var/tmp", "/dev/shm", "/home", "/root", "/bin", "/boot", "/dev", "/etc",  # noqa: S108
    "/lib", "/lib32", "/lib64", "/libx32", "/media", "/mnt", "/opt", "/proc", "/run",
    "/sbin", "/snap", "/srv", "/sys", "/usr", "/var", "/Users", "/private", "/private/tmp",
    "/Volumes", "/System", "/Library", "/Applications",
}  # fmt: skip


class StagingError(ValueError):
    """Unsafe staging path or unexpected staging directory content."""


def safe_component(server_name: str) -> str:
    """The canonical server name as one filesystem path component (validated, unchanged)."""
    name = server_name or ""
    if "\x00" in name or "/" in name or "\\" in name or name in (".", ".."):
        raise StagingError(f"Server name {name!r} cannot be used as a directory name.")
    error = check_name(name)
    if error:
        raise StagingError(f"Server name {name!r} cannot be used as a directory name: {error}")
    return name


def safe_name_error(server_name: str) -> str | None:
    try:
        safe_component(server_name)
    except StagingError as exc:
        return str(exc)
    return None


def _forbidden_paths() -> set[str]:
    forbidden = set(_FORBIDDEN_EXACT)
    home = Path(os.path.expanduser("~"))
    if home.is_absolute():
        forbidden.add(os.path.normpath(str(home)))
        forbidden.update(os.path.normpath(str(p)) for p in home.parents)
    return forbidden


def check_template(template: str) -> str | None:
    """Return an error message for an unusable template, or None."""
    value = (template or "").strip()
    if not value:
        return "The local patch download directory is required."
    if len(value) > TEMPLATE_MAX_LENGTH:
        return f"The directory template must be at most {TEMPLATE_MAX_LENGTH} characters."
    if "\x00" in value or "\n" in value or "\r" in value:
        return "The directory template contains invalid characters."
    if PLACEHOLDER not in value:
        return f"The directory template must contain {PLACEHOLDER}."
    if "$" in value.replace(PLACEHOLDER, ""):
        return f"Only the {PLACEHOLDER} placeholder is supported."
    if value.startswith("~") and not (value == "~" or value.startswith("~/")):
        return "Only '~' (your home directory) is supported, not '~user'."
    if ".." in value.replace("\\", "/").split("/"):
        return "Path traversal ('..') is not allowed in the directory template."
    try:
        resolve_local(value, "example-server")
    except StagingError as exc:
        return str(exc)
    return None


def resolve_local(template: str, server_name: str) -> Path:
    """Resolve the template for one server. Raises StagingError for unsafe results."""
    value = (template or "").strip()
    if PLACEHOLDER not in value:
        raise StagingError(f"The directory template must contain {PLACEHOLDER}.")
    if ".." in value.replace("\\", "/").split("/"):
        raise StagingError("Path traversal ('..') is not allowed in the directory template.")
    component = safe_component(server_name)
    expanded = os.path.expanduser(value.replace(PLACEHOLDER, component))
    if not os.path.isabs(expanded):
        raise StagingError(
            "The directory template must resolve to an absolute path (e.g. /tmp/${server_name})."
        )
    normalized = os.path.normpath(expanded)
    if normalized in _forbidden_paths():
        raise StagingError(f"Refusing to use {normalized} as a staging directory.")
    if not any(component in part for part in Path(normalized).parts[1:]):
        raise StagingError("The resolved path does not contain the server name.")
    if len(Path(normalized).parts) < 3:  # "/" + at least two components
        raise StagingError(
            f"Refusing to use {normalized}: use a per-server subdirectory such as "
            f"{DEFAULT_LOCAL_TEMPLATE}."
        )
    return Path(normalized)


def remote_dir(server_name: str) -> str:
    return f"{REMOTE_BASE}/{safe_component(server_name)}"


def check_deb_filename(filename: str) -> str:
    if not DEB_FILENAME_RE.match(filename or "") or "/" in filename:
        raise StagingError(f"Unexpected .deb file name: {filename!r}")
    return filename


# --- local directory -------------------------------------------------------------------


@dataclass
class LocalStaging:
    path: Path
    created: bool
    leftovers: list[str]  # managed files of an earlier failed run (kept, never deleted)


def _assert_safe_dir(path: Path) -> None:
    normalized = os.path.normpath(str(path))
    forbidden = _forbidden_paths()
    if normalized in forbidden or os.path.realpath(normalized) in forbidden:
        raise StagingError(f"Refusing to use {normalized} as a staging directory.")
    if len(Path(normalized).parts) < 3:
        raise StagingError(f"Refusing to use {normalized} as a staging directory.")


def prepare_local(path: Path, server_name: str, execution_id: int) -> LocalStaging:
    """Create or validate the local staging directory. Never deletes anything."""
    _assert_safe_dir(path)
    created = False
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.mkdir(mode=0o700)
        created = True
    else:
        if stat.S_ISLNK(info.st_mode):
            raise StagingError(f"Staging path {path} is a symbolic link; refusing to use it.")
        if not stat.S_ISDIR(info.st_mode):
            raise StagingError(f"Staging path {path} exists and is not a directory.")
        if hasattr(os, "getuid") and info.st_uid != os.getuid():
            raise StagingError(f"Staging directory {path} is owned by another user.")
    _assert_safe_dir(Path(os.path.realpath(path)))
    entries = sorted(os.listdir(path))
    leftovers = [e for e in entries if e != MARKER]
    if leftovers:
        managed = MARKER in entries and all(
            MANAGED_RE.match(e) and stat.S_ISREG(os.lstat(path / e).st_mode) for e in leftovers
        )
        if not managed:
            raise StagingError(
                f"Staging directory is not empty and contains unmanaged files: {path}"
            )
    marker = {"tool": "ec2patcher", "server_name": server_name, "execution_id": execution_id}
    (path / MARKER).write_text(json.dumps(marker) + "\n")
    return LocalStaging(path=path, created=created, leftovers=leftovers)


def cleanup_local(path: Path, filenames: list[str]) -> str | None:
    """Delete exactly the staged files, the marker and the (then empty) directory.

    Returns None on success or a warning message. Unknown files are never removed.
    """
    try:
        _assert_safe_dir(path)
        if not os.path.lexists(path):
            return None
        if os.path.islink(path) or not path.is_dir():
            return f"{path} is not a directory; nothing was deleted."
        names = []
        for name in filenames:
            check_deb_filename(name)
            names += [name, f"{name}.part"]
        for name in names:
            target = path / name
            if os.path.lexists(target):
                if not stat.S_ISREG(os.lstat(target).st_mode):
                    return f"{target} is not a regular file; it was not deleted."
                target.unlink()
        remaining = sorted(e for e in os.listdir(path) if e != MARKER)
        if remaining:
            # The marker stays so the leftovers remain recognisable as EC2Patcher files.
            return (
                f"Local staging directory {path} was kept: it still contains "
                f"{len(remaining)} other file(s) ({', '.join(remaining[:5])})."
            )
        marker = path / MARKER
        if os.path.lexists(marker):
            if not stat.S_ISREG(os.lstat(marker).st_mode):
                return f"{marker} is not a regular file; it was not deleted."
            marker.unlink()
        path.rmdir()
    except (OSError, StagingError) as exc:
        return f"Local cleanup of {path} failed: {exc}"
    return None
