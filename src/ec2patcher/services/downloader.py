"""Download approved .deb files exactly as recorded in the analysis plan and verify them.

Only the stored URI is fetched (no local APT, no "latest" lookup). Data is streamed into
``<name>.deb.part``; the file is renamed to ``<name>.deb`` only after the size and SHA256
match the approved plan. A failed download leaves the ``.part`` file for troubleshooting.
"""

import hashlib
import os
import re
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from ec2patcher import __version__
from ec2patcher.services.apt_planner import uri_basename_matches

CHUNK_SIZE = 1024 * 256
DOWNLOAD_TIMEOUT_SECONDS = 60  # per socket operation, not per file
SHA256_RE = re.compile(r"^(?:SHA256:)?([0-9a-fA-F]{64})$")

# fetcher(url, out, max_bytes, timeout): write the response body to ``out``.
Fetcher = Callable[[str, BinaryIO, int, float], None]


class DownloadError(RuntimeError):
    pass


def parse_sha256(checksum: str | None) -> str | None:
    """'SHA256:<hex>' (as printed by apt --print-uris) -> lowercase hex, else None."""
    m = SHA256_RE.match((checksum or "").strip())
    return m.group(1).lower() if m else None


def check_uri(uri: str | None) -> str | None:
    """Return an error message unless the URI is a plain http(s) URL."""
    parts = urlsplit(uri or "")
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return f"Unsupported download URI: {(uri or '')[:200]!r}"
    return None


def urllib_fetcher(url: str, out: BinaryIO, max_bytes: int, timeout: float) -> None:
    if check_uri(url):
        raise DownloadError(check_uri(url))
    request = urllib.request.Request(url, headers={"User-Agent": f"EC2Patcher/{__version__}"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - http(s) only
        total = 0
        while True:
            chunk = response.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise DownloadError(f"Server sent more than the expected {max_bytes} bytes.")
            out.write(chunk)


def file_sha256(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(CHUNK_SIZE), b""):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def verify_file(path: Path, size: int, sha256: str) -> str | None:
    """Return an error message if the file does not match the approved size and checksum."""
    if not path.is_file() or path.is_symlink():
        return f"{path.name} is missing."
    actual_size, actual_sha = file_sha256(path)
    if actual_size != size:
        return f"{path.name}: size mismatch (expected {size} bytes, got {actual_size})."
    if actual_sha != sha256:
        return f"{path.name}: SHA256 checksum mismatch (expected {sha256}, got {actual_sha})."
    return None


def download(
    uri: str,
    directory: Path,
    filename: str,
    size: int,
    sha256: str,
    fetcher: Fetcher = urllib_fetcher,
    timeout: float = DOWNLOAD_TIMEOUT_SECONDS,
) -> Path:
    """Download one approved .deb atomically. Raises DownloadError with a clear message."""
    error = check_uri(uri)
    if error:
        raise DownloadError(error)
    if not uri_basename_matches(uri, filename):
        raise DownloadError(f"URI does not point at {filename}: {uri[:200]}")
    final = directory / filename
    part = directory / f"{filename}.part"
    try:
        with open(part, "wb") as out:
            fetcher(uri, out, size, timeout)
            out.flush()
            os.fsync(out.fileno())
    except DownloadError as exc:
        raise DownloadError(f"{filename}: {exc}") from exc
    except TimeoutError as exc:
        raise DownloadError(f"{filename}: download timed out.") from exc
    except OSError as exc:
        reason = getattr(exc, "reason", None) or exc
        raise DownloadError(f"{filename}: download failed: {reason}") from exc
    problem = verify_file(part, size, sha256)
    if problem:
        raise DownloadError(problem.replace(f"{filename}.part", filename, 1))
    os.replace(part, final)
    return final
