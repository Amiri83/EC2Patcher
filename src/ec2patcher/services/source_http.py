"""HTTP for the security data sources: JSON, streamed files and reachability probes.

Module functions are looked up at call time, so tests replace them here and never reach the
network. The opener is built per request so that HTTPS_PROXY / NO_PROXY are always honored.
"""

import http.client
import json
import time
import urllib.error
import urllib.request
from typing import BinaryIO

from ec2patcher.services.downloader import check_uri

USER_AGENT = "ec2patcher"
JSON_TIMEOUT_SECONDS = 15.0
PROBE_TIMEOUT_SECONDS = 5.0
MAX_JSON_BYTES = 32 * 1024 * 1024
TRANSFER_DEADLINE_SECONDS = 600.0  # one streamed file, whatever its socket timeouts allow
PROBE_READ_BYTES = 1024
CHUNK_SIZE = 256 * 1024
# The host answered: the path may simply not exist, or it asks us to slow down.
REACHABLE_ERROR_CODES = frozenset({404, 405, 416, 429})


def _open(url: str, timeout: float, headers: dict[str, str] | None = None):
    problem = check_uri(url)
    if problem:
        raise ValueError(problem)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})  # noqa: S310
    opener = urllib.request.build_opener(urllib.request.ProxyHandler())
    return opener.open(request, timeout=timeout)


def describe_error(exc: BaseException) -> str:
    """A short reason for a failed request: 'HTTP 504', 'timed out', the network error."""
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code}"
    if isinstance(exc, urllib.error.URLError):
        return str(exc.reason) or type(exc).__name__
    if isinstance(exc, TimeoutError):
        return "timed out"
    return str(exc) or type(exc).__name__


def fetch_json(url: str, timeout: float = JSON_TIMEOUT_SECONDS) -> dict:
    """One bounded JSON response. Network failures are OSError, bad content ValueError."""
    try:
        with _open(url, timeout, {"Accept": "application/json"}) as response:
            raw = response.read(MAX_JSON_BYTES + 1)
    except http.client.HTTPException as exc:
        raise OSError(f"incomplete response: {exc}") from exc
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("response is unexpectedly large")
    return json.loads(raw)


def fetch_to_file(url: str, out: BinaryIO, max_bytes: int, timeout: float) -> None:
    """Stream the response body to ``out``, never holding it in memory."""
    deadline = time.monotonic() + TRANSFER_DEADLINE_SECONDS
    received = 0
    try:
        with _open(url, timeout) as response:
            expected = response.headers.get("Content-Length")
            while chunk := response.read(CHUNK_SIZE):
                received += len(chunk)
                if received > max_bytes:
                    raise ValueError(f"response is larger than {max_bytes} bytes")
                if time.monotonic() > deadline:
                    raise TimeoutError("the download took too long")
                out.write(chunk)
    except http.client.HTTPException as exc:
        raise OSError(f"incomplete response: {exc}") from exc
    if expected and expected.isdigit() and int(expected) != received:
        raise OSError(f"incomplete response: {received} of {expected} bytes")


def probe(url: str, timeout: float = PROBE_TIMEOUT_SECONDS) -> str | None:
    """A small bounded request. None if the source is reachable, else why it is not."""
    try:
        with _open(url, timeout, {"Range": f"bytes=0-{PROBE_READ_BYTES - 1}"}) as response:
            response.read(PROBE_READ_BYTES)
    except urllib.error.HTTPError as exc:
        return None if exc.code in REACHABLE_ERROR_CODES else describe_error(exc)
    except (OSError, ValueError, http.client.HTTPException) as exc:
        return describe_error(exc)
    return None
