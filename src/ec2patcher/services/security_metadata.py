"""Per-CVE Canonical Security API lookups for supported Ubuntu releases.

Resilience: each request is retried (``MAX_ATTEMPTS`` in total, exponential backoff) on
network errors, timeouts, HTTP 429 and 5xx. Only ``BREAKER_THRESHOLD`` *consecutive* failed
lookups trip the per-run circuit breaker, so one transient timeout never skips the rest of a
run. Every fetched CVE document is cached on disk (``<cache dir>/canonical/<CVE>.json``):
entries younger than the TTL are used without a request, older ones are refreshed and only
used as a fallback - marked with their age - when ubuntu.com cannot be reached.

Requests go through urllib's ``ProxyHandler``, built per request, so ``HTTPS_PROXY`` /
``NO_PROXY`` from the environment are always honored.
"""

import json
import logging
import os
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path

from platformdirs import user_cache_dir

from ec2patcher.services.server_state import SUPPORTED_RELEASES

logger = logging.getLogger(__name__)

API_URL = "https://ubuntu.com/security/cves/{cve}.json"
SOURCE_LABEL = "Canonical Security API (online per-CVE lookup)"
REQUEST_TIMEOUT_SECONDS = 30
MAX_ATTEMPTS = 3  # per request, for network errors / timeouts / HTTP 429 / 5xx
BACKOFF_SECONDS = 1.0  # waits 1 s, then 2 s between attempts
BREAKER_THRESHOLD = 3  # consecutive failed lookups before the rest of the run skips HTTP
CACHE_TTL = timedelta(hours=24)
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Per-run lookup outcomes (tallied per unique CVE for the status panel).
OK = "ok"  # current data: network, or disk cache younger than the TTL
CACHED = "cached"  # ubuntu.com unreachable; older cached data used as a fallback
FAILED = "failed"  # no data: the CVE stays METADATA_UNAVAILABLE
_OUTCOME_RANK = {OK: 0, CACHED: 1, FAILED: 2}  # the worst outcome of a run wins
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


def default_cache_dir() -> Path:
    override = os.environ.get("EC2PATCHER_CACHE_DIR")
    base = Path(override).expanduser() if override else Path(user_cache_dir("ec2patcher"))
    return base / "canonical"


def format_age(age: timedelta) -> str:
    minutes = max(0, int(age.total_seconds()) // 60)
    days, minutes = divmod(minutes, 24 * 60)
    hours, minutes = divmod(minutes, 60)
    if days:
        return f"{days}d {hours}h"
    return f"{hours}h {minutes}m" if hours else f"{minutes}m"


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
    # Set only when ubuntu.com could not be reached and an expired cache entry was used.
    cache_age: timedelta | None = None

    @property
    def cache_note(self) -> str | None:
        if self.cache_age is None:
            return None
        return f"Canonical metadata from cache (age {format_age(self.cache_age)})"

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
    cache_dir: Path | None = None
    cache_ttl_hours: float = CACHE_TTL.total_seconds() / 3600
    timeout_seconds: float = REQUEST_TIMEOUT_SECONDS
    attempts: int = MAX_ATTEMPTS
    breaker_threshold: int = BREAKER_THRESHOLD

    @property
    def updated_label(self) -> str:
        return self.checked_at or "online"


def http_get(url: str, timeout: float | None = None) -> dict:
    """Read one Canonical JSON response, bounded to avoid unexpected large replies.

    The opener is built per request so its ProxyHandler reads HTTPS_PROXY / NO_PROXY from
    the current environment (urlopen caches a global opener on first use)."""
    request = urllib.request.Request(url, headers={"User-Agent": "ec2patcher"})  # noqa: S310
    opener = urllib.request.build_opener(urllib.request.ProxyHandler())
    timeout = REQUEST_TIMEOUT_SECONDS if timeout is None else timeout
    with opener.open(request, timeout=timeout) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Canonical CVE response is unexpectedly large")
    return json.loads(raw)


Fetcher = Callable[[str], dict]


class MetadataUnreachable(OSError):
    """Lookup skipped because ubuntu.com already failed at the network level."""


class SecurityMetadata:
    """Online lookups with a process-local memo, a disk cache and a per-run circuit breaker.

    After ``breaker_threshold`` consecutive failed lookups (each already retried), further
    lookups skip HTTP - falling back to the disk cache where possible - until
    :meth:`start_run` (next analysis run / retry) or :meth:`clear` resets the breaker."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        fetcher: Fetcher | None = None,
        url: str = API_URL,
        max_age: timedelta | None = None,
        timeout: float | None = None,
        attempts: int | None = None,
        backoff: float | None = None,
        breaker_threshold: int | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = _now,
    ):
        # None = the module default, read here (not at import) so it can be overridden.
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self.max_age = CACHE_TTL if max_age is None else max_age
        self.timeout = REQUEST_TIMEOUT_SECONDS if timeout is None else timeout
        self.fetcher = fetcher or partial(http_get, timeout=self.timeout)
        self.attempts = max(1, MAX_ATTEMPTS if attempts is None else attempts)
        self.backoff = BACKOFF_SECONDS if backoff is None else backoff
        self.breaker_threshold = max(
            1, BREAKER_THRESHOLD if breaker_threshold is None else breaker_threshold
        )
        self.sleep, self.now = sleep, now
        self._memo: dict[str, CveRecord | None] = {}
        self._lock = threading.Lock()
        self._unreachable: str | None = None
        self._consecutive_failures = 0
        self._outcomes: dict[str, str] = {}

    def start_run(self) -> None:
        """Reset the circuit breaker and the lookup tallies for a new run (or retry)."""
        with self._lock:
            self._unreachable = None
            self._consecutive_failures = 0
            self._outcomes = {}

    @property
    def breaker_open(self) -> bool:
        return self._unreachable is not None

    def run_outcomes(self) -> dict[str, str]:
        """CVE -> ok / cached / failed for every lookup since :meth:`start_run`."""
        with self._lock:
            return dict(self._outcomes)

    def lookup(self, cve: str, network: bool = True) -> CveRecord | None:
        """Canonical record for ``cve`` (None if Canonical does not know it).

        Raises when no data is available. With ``network=False`` only the memo and the disk
        cache (any age) are consulted and nothing is tallied."""
        cve = cve.strip().upper()
        with self._lock:
            if cve in self._memo:
                if network:
                    self._record(cve, OK)
                return self._memo[cve]
            skipped = self._unreachable
        cached = self._read_cache(cve)
        if cached is not None:
            record, fetched = cached
            age = self.now() - fetched
            if age < self.max_age:
                with self._lock:
                    self._memo[cve] = record
                    if network:
                        self._record(cve, OK)
                return record
            if not network:
                if record is not None:
                    record.cache_age = age
                return record
        if not network:
            raise MetadataUnreachable("not looked up again (only failed lookups are retried)")

        error: Exception
        if skipped is not None:
            error = MetadataUnreachable(
                f"skipped after {self.breaker_threshold} consecutive network errors: {skipped}"
            )
        else:
            try:
                record = self._fetch(cve)
            except (OSError, ValueError) as exc:
                error = exc
            else:
                with self._lock:
                    self._memo[cve] = record
                    self._record(cve, OK)
                return record
        if cached is not None:
            record, fetched = cached
            if record is not None:
                record.cache_age = self.now() - fetched
            logger.warning("Canonical lookup of %s failed (%s); using cached data", cve, error)
            with self._lock:
                self._record(cve, CACHED)
            return record
        with self._lock:
            self._record(cve, FAILED)
        raise error

    def _fetch(self, cve: str) -> CveRecord | None:
        """One lookup with retries. Only network-level failures count toward the breaker."""
        url = API_URL.format(cve=cve)
        for attempt in range(1, self.attempts + 1):
            try:
                doc = self.fetcher(url)
            except urllib.error.HTTPError as exc:
                if exc.code == 404:  # Canonical does not know the CVE: cached as null
                    self._network_ok()
                    self._write_cache(cve, None)
                    return None
                error: OSError = exc
                retryable = exc.code == 429 or exc.code >= 500
            except OSError as exc:  # URLError, timeouts, connection errors
                error, retryable = exc, True
            else:
                self._network_ok()
                record = parse_cve_document(doc, cve)  # ValueError: not a network failure
                self._write_cache(cve, doc)
                return record
            if not retryable or attempt == self.attempts:
                break
            delay = self.backoff * 2 ** (attempt - 1)
            logger.info("Canonical lookup of %s failed (%s); retrying in %g s", cve, error, delay)
            self.sleep(delay)
        self._network_failed(error)
        raise error

    def _network_ok(self) -> None:
        with self._lock:
            self._consecutive_failures = 0

    def _network_failed(self, exc: Exception) -> None:
        with self._lock:
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.breaker_threshold and self._unreachable is None:
                self._unreachable = str(exc) or type(exc).__name__
                logger.warning(
                    "Canonical unreachable after %d consecutive failures; skipping further "
                    "lookups this run: %s", self._consecutive_failures, self._unreachable,
                )  # fmt: skip

    def _record(self, cve: str, outcome: str) -> None:
        # Caller holds the lock. A CVE that failed for any server this run stays failed.
        previous = self._outcomes.get(cve)
        if previous is None or _OUTCOME_RANK[outcome] >= _OUTCOME_RANK[previous]:
            self._outcomes[cve] = outcome

    # --- disk cache: <cache_dir>/<CVE>.json = {"cve", "fetched_at", "document"} ---------
    # "document" is the raw Canonical JSON, or null for a CVE Canonical answered 404 for.

    def _cache_path(self, cve: str) -> Path | None:
        return self.cache_dir / f"{cve}.json" if CVE_ID_RE.match(cve) else None

    def _read_cache(self, cve: str) -> tuple[CveRecord | None, datetime] | None:
        path = self._cache_path(cve)
        if path is None:
            return None
        try:
            entry = json.loads(path.read_text())
            if entry.get("cve") != cve:
                raise ValueError("mismatched cache entry")
            fetched = datetime.fromisoformat(entry["fetched_at"])
            doc = entry["document"]
            return (parse_cve_document(doc, cve) if doc is not None else None), fetched
        except FileNotFoundError:
            return None
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
            logger.warning("Ignoring unreadable Canonical cache entry for %s: %s", cve, exc)
            return None

    def _write_cache(self, cve: str, doc: dict | None) -> None:
        path = self._cache_path(cve)
        if path is None:
            return
        entry = {"cve": cve, "fetched_at": self.now().isoformat(), "document": doc}
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(entry))
            tmp.replace(path)
        except OSError as exc:
            logger.warning("Could not write Canonical cache entry for %s: %s", cve, exc)

    def status(self) -> MetadataStatus:
        return MetadataStatus(
            available=True,
            checked_at=_now().isoformat(),
            cache_dir=self.cache_dir,
            cache_ttl_hours=self.max_age.total_seconds() / 3600,
            timeout_seconds=self.timeout,
            attempts=self.attempts,
            breaker_threshold=self.breaker_threshold,
        )

    def ensure_fresh(self, progress: Callable[[str], None] | None = None) -> MetadataStatus:
        return self.status()

    def clear(self) -> bool:
        """Forget the memo, the breaker and the disk cache."""
        with self._lock:
            had_entries = bool(self._memo) or self._unreachable is not None
            self._memo.clear()
            self._unreachable = None
            self._consecutive_failures = 0
        for path in self.cache_dir.glob("CVE-*.json"):
            try:
                path.unlink()
                had_entries = True
            except OSError as exc:
                logger.warning("Could not remove Canonical cache entry %s: %s", path, exc)
        return had_entries
