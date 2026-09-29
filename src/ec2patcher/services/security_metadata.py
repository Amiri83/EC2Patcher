"""Per-CVE Canonical Security API lookups for supported Ubuntu releases."""

import json
import re
import threading
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ec2patcher.services.server_state import SUPPORTED_RELEASES

API_URL = "https://ubuntu.com/security/cves/{cve}.json"
SOURCE_LABEL = "Canonical Security API (online per-CVE lookup)"
REQUEST_TIMEOUT_SECONDS = 20
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
PRIORITY_RE = re.compile(r"classified this CVE as of (\w+) priority", re.IGNORECASE)
PRO_PREFIXES = ("esm-infra", "esm-apps", "esm-infra-legacy", "esm-apps-legacy")
# Non-Pro archive pockets. Canonical reports fixes that shipped in the original
# release (e.g. openssl 3.0.2-0ubuntu1 for jammy in CVE-2022-0778) as "security".
STANDARD_POCKETS = (None, "security", "updates")
STATUSES = {
    "released": "fixed",
    "not-affected": "not_affected",
    "needs-triage": "under_investigation",
    "needed": "affected",
    "pending": "affected",
    "deferred": "affected",
    "ignored": "affected",
}


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def classify_distro(distro: str) -> tuple[str, bool] | None:
    """Map a Canonical distro to (codename, is_pro), or None if unsupported."""
    if distro in SUPPORTED_RELEASES.values():
        return distro, False
    if "/" in distro:
        prefix, rest = distro.split("/", 1)
        if prefix in PRO_PREFIXES and rest in SUPPORTED_RELEASES.values():
            return rest, True
        if rest == "esm" and prefix in SUPPORTED_RELEASES.values():
            return prefix, True
    return None


@dataclass
class VexEntry:
    source: str
    version: str
    distro: str
    status: str
    justification: str = ""
    note: str = ""

    @property
    def codename(self) -> str:
        info = classify_distro(self.distro)
        return info[0] if info else ""

    @property
    def is_pro(self) -> bool:
        info = classify_distro(self.distro)
        return bool(info and info[1])

    @property
    def priority(self) -> str | None:
        match = PRIORITY_RE.search(self.note)
        return match.group(1).capitalize() if match else None


@dataclass
class CveRecord:
    cve: str
    timestamp: str = ""
    description: str = ""
    entries: list[VexEntry] = field(default_factory=list)

    def for_release(self, codename: str) -> list[VexEntry]:
        return [entry for entry in self.entries if entry.codename == codename]

    def sources(self) -> set[str]:
        return {entry.source for entry in self.entries}


def parse_cve_document(doc: dict, cve: str) -> CveRecord:
    """Map Canonical's source-package release statuses to the resolver model."""
    if not isinstance(doc, dict) or doc.get("id", "").upper() != cve:
        raise ValueError(f"Invalid Canonical response for {cve}")
    packages = doc.get("packages")
    if not isinstance(packages, list):
        raise ValueError(f"Canonical response for {cve} has no packages list")
    record = CveRecord(
        cve=cve,
        timestamp=str(doc.get("updated_at") or doc.get("published_at") or ""),
        description=str(doc.get("description") or "")[:1000],
    )
    for package in packages:
        if not isinstance(package, dict) or not isinstance(package.get("statuses"), list):
            continue
        source = package.get("name")
        if not isinstance(source, str) or not source:
            continue
        for release in package["statuses"]:
            if not isinstance(release, dict):
                continue
            codename = release.get("release_codename")
            if codename not in SUPPORTED_RELEASES.values():
                continue
            pocket = release.get("pocket")
            if pocket in STANDARD_POCKETS:
                distro = codename
            elif pocket in PRO_PREFIXES:
                distro = f"{pocket}/{codename}"
            else:
                continue
            canonical_status = str(release.get("status") or "").lower()
            status = STATUSES.get(canonical_status)
            if status is None:
                continue  # DNE, upstream and unknown statuses provide no usable statement
            priority = str(
                release.get("priority") or package.get("priority") or doc.get("priority") or ""
            ).strip()
            note = canonical_status
            if priority:
                note += f"; Ubuntu Security Team classified this CVE as of {priority} priority."
            record.entries.append(
                VexEntry(
                    source=source,
                    version=str(release.get("description") or ""),
                    distro=distro,
                    status=status,
                    justification=canonical_status,
                    note=note,
                )
            )
    return record


@dataclass
class MetadataStatus:
    available: bool
    source: str = SOURCE_LABEL
    url: str = API_URL
    checked_at: str | None = None
    cve_count: int = 0
    stale: bool = False
    warning: str | None = None
    error: str | None = None

    @property
    def updated_label(self) -> str:
        return self.checked_at or "online"


def http_get(url: str) -> dict:
    """Read one Canonical JSON response, bounded to avoid unexpected large replies."""
    request = urllib.request.Request(url, headers={"User-Agent": "ec2patcher"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Canonical CVE response is unexpectedly large")
    return json.loads(raw)


Fetcher = Callable[[str], dict]


class MetadataUnreachable(OSError):
    """Lookup skipped because ubuntu.com already failed at the network level."""


class SecurityMetadata:
    """Online lookups with a process-local memo for repeated CVEs.

    After the first network failure, further lookups fail fast without HTTP until
    :meth:`start_run` (next analysis run) or :meth:`clear` resets the breaker."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        fetcher: Fetcher = http_get,
        url: str = API_URL,
        max_age: timedelta | None = None,
    ):
        # Accept legacy constructor arguments for callers; no files or refresh are used.
        self.fetcher = fetcher
        self._memo: dict[str, CveRecord | None] = {}
        self._lock = threading.Lock()
        self._unreachable: str | None = None

    def start_run(self) -> None:
        """Reset the 'ubuntu.com unreachable' circuit breaker for a new analysis run."""
        with self._lock:
            self._unreachable = None

    def lookup(self, cve: str) -> CveRecord | None:
        cve = cve.upper()
        with self._lock:
            if cve in self._memo:
                return self._memo[cve]
            if self._unreachable is not None:
                raise MetadataUnreachable(
                    f"skipped after earlier network error: {self._unreachable}"
                )
        try:
            doc = self.fetcher(API_URL.format(cve=cve))
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                self._trip(exc)
                raise
            record = None
        except OSError as exc:  # URLError, timeouts, connection errors
            self._trip(exc)
            raise
        else:
            record = parse_cve_document(doc, cve)
        with self._lock:
            self._memo[cve] = record
        return record

    def _trip(self, exc: Exception) -> None:
        with self._lock:
            if self._unreachable is None:
                self._unreachable = str(exc) or type(exc).__name__

    def status(self) -> MetadataStatus:
        return MetadataStatus(available=True, checked_at=_now().isoformat())

    def ensure_fresh(self, progress: Callable[[str], None] | None = None) -> MetadataStatus:
        return self.status()

    def clear(self) -> bool:
        with self._lock:
            had_entries = bool(self._memo) or self._unreachable is not None
            self._memo.clear()
            self._unreachable = None
            return had_entries
