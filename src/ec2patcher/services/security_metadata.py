"""Per-CVE Canonical Security API lookups for supported Ubuntu releases.

Resilience: each request is retried (``MAX_ATTEMPTS`` in total, exponential backoff) on
network errors, timeouts, HTTP 429 and 5xx. Only ``BREAKER_THRESHOLD`` *consecutive* failed
lookups trip the per-run circuit breaker, so one transient timeout never skips the rest of a
run. Outbound requests are paced (``PACE_SECONDS`` apart; the first request of a run and
memo / cache hits never wait).

Every fetched CVE document (or Canonical's confirmed 404) is cached in the application
database (table ``cve_metadata_cache``): entries younger than the TTL are used without a
request - by default 24 h, or 1 h while Canonical still has a release of the CVE under
investigation (both set in Settings -> Caches) - older ones are refreshed and only used as a
fallback, marked with their age, when ubuntu.com cannot be reached. Failed lookups are never
cached, and a cache error never fails a lookup. Each run counts its lookups answered from the
cache (memo, table or stale fallback) / live / failed (:meth:`SecurityMetadata.run_cache_stats`).

Lookup order: memo -> cache (skipped on force refresh) -> circuit breaker -> pacing -> HTTP.

Requests go through urllib's ``ProxyHandler``, built per request, so ``HTTPS_PROXY`` /
``NO_PROXY`` from the environment are always honored.
"""

import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import partial
from pathlib import Path

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.models import FROM_CACHE, FROM_LIVE, LOOKUP_FAILED, CacheStats, record_source
from ec2patcher.services.server_state import SUPPORTED_RELEASES

logger = logging.getLogger(__name__)

API_URL = "https://ubuntu.com/security/cves/{cve}.json"
SOURCE_LABEL = "Canonical Security API (online per-CVE lookup)"
REQUEST_TIMEOUT_SECONDS = 20
MAX_ATTEMPTS = 3  # per request, for network errors / timeouts / HTTP 429 / 5xx
BACKOFF_SECONDS = 1.0  # waits 1 s, then 2 s between attempts
PACE_SECONDS = 1.0  # minimum gap between outbound requests to ubuntu.com
BREAKER_THRESHOLD = 3  # consecutive failed lookups before the rest of the run skips HTTP
CACHE_TTL = timedelta(hours=24)  # settled CVEs
INVESTIGATING_CACHE_TTL = timedelta(hours=1)  # any cached entry under_investigation
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Per-run lookup outcomes (tallied per unique CVE for the status panel).
OK = "ok"  # current data: network, or cache younger than the TTL
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
    cache_db: Path | None = None
    cache_ttl_hours: float = CACHE_TTL.total_seconds() / 3600
    investigating_ttl_hours: float = INVESTIGATING_CACHE_TTL.total_seconds() / 3600
    timeout_seconds: float = REQUEST_TIMEOUT_SECONDS
    pace_seconds: float = PACE_SECONDS
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
    """Online lookups with a process-local memo, a SQLite cache and a per-run circuit breaker.

    After ``breaker_threshold`` consecutive failed lookups (each already retried), further
    lookups skip HTTP - falling back to the cache where possible - until :meth:`start_run`
    (next analysis run / retry) or :meth:`clear` resets the breaker. Any successful request
    resets the consecutive-failure count."""

    def __init__(
        self,
        cache_db: Database | Path | None = None,
        fetcher: Fetcher | None = None,
        url: str = API_URL,
        max_age: timedelta | None = None,
        timeout: float | None = None,
        attempts: int | None = None,
        backoff: float | None = None,
        breaker_threshold: int | None = None,
        pace: float | None = None,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = _now,
        monotonic: Callable[[], float] = time.monotonic,
        investigating_max_age: timedelta | None = None,
    ):
        # cache_db: the application Database (or its path); None = the default data dir DB,
        # opened on first use. None elsewhere = the module default, read here (not at
        # import) so it can be overridden.
        if isinstance(cache_db, Database):
            self._db: Database | None = cache_db
            self.cache_db_path = cache_db.path
        else:
            self._db = None
            self.cache_db_path = (
                Path(cache_db) if cache_db else config.get_data_dir() / config.DB_FILENAME
            )
        self.max_age = CACHE_TTL if max_age is None else max_age
        self.investigating_max_age = (
            INVESTIGATING_CACHE_TTL if investigating_max_age is None else investigating_max_age
        )
        self.timeout = REQUEST_TIMEOUT_SECONDS if timeout is None else timeout
        self.fetcher = fetcher or partial(http_get, timeout=self.timeout)
        self.attempts = max(1, MAX_ATTEMPTS if attempts is None else attempts)
        self.backoff = BACKOFF_SECONDS if backoff is None else backoff
        self.pace = PACE_SECONDS if pace is None else pace
        self.breaker_threshold = max(
            1, BREAKER_THRESHOLD if breaker_threshold is None else breaker_threshold
        )
        self.sleep, self.now, self.monotonic = sleep, now, monotonic
        # CVE -> (record or None for a 404, fetched_at); expires like the cache.
        self._memo: dict[str, tuple[CveRecord | None, datetime]] = {}
        self._lock = threading.Lock()
        self._pace_lock = threading.Lock()
        self._last_request: float | None = None  # monotonic time of the last outbound request
        self._unreachable: str | None = None
        self._consecutive_failures = 0
        self._outcomes: dict[str, str] = {}
        self._sources: dict[str, str] = {}  # CVE -> cache / live / failed, this run
        self._force_refresh: frozenset[str] | None = frozenset()  # None = every CVE
        self._refreshed: set[str] = set()

    def start_run(self, force_refresh: bool = False, cves: Iterable[str] | None = None) -> None:
        """Reset the circuit breaker, the failure count, the pacing clock and the lookup
        tallies for a new run (or retry).

        With ``force_refresh`` the run fetches ``cves`` (default: every CVE) from ubuntu.com
        once, bypassing the memo and the cache; later lookups of the run reuse that result."""
        forced: frozenset[str] | None = frozenset()
        if force_refresh:
            forced = None if cves is None else frozenset(c.strip().upper() for c in cves)
        with self._lock:
            self._unreachable = None
            self._consecutive_failures = 0
            self._outcomes = {}
            self._sources = {}
            self._force_refresh = forced
            self._refreshed = set()
        with self._pace_lock:
            self._last_request = None

    @property
    def breaker_open(self) -> bool:
        return self._unreachable is not None

    def run_outcomes(self) -> dict[str, str]:
        """CVE -> ok / cached / failed for every lookup since :meth:`start_run`."""
        with self._lock:
            return dict(self._outcomes)

    def run_cache_stats(self) -> CacheStats:
        """Lookups since :meth:`start_run`: from cache (memo, table or a stale fallback) /
        live / failed, one count per CVE."""
        with self._lock:
            return CacheStats.from_sources(self._sources)

    def ttl(self, record: CveRecord | None) -> timedelta:
        """How long a cached answer is used without a request: shorter while any release
        of the CVE is still under investigation, as Canonical's verdict is likely to change."""
        if record is not None and any(e.status == "under_investigation" for e in record.entries):
            return min(self.max_age, self.investigating_max_age)
        return self.max_age

    def lookup(
        self, cve: str, network: bool = True, force_refresh: bool = False
    ) -> CveRecord | None:
        """Canonical record for ``cve`` (None if Canonical does not know it).

        Order: memo -> cache -> circuit breaker -> pacing -> HTTP. ``force_refresh`` (or a
        :meth:`start_run` force refresh covering ``cve``) skips the memo and the cache;
        they are still the fallback if the request fails. Raises when no data is available.
        With ``network=False`` only the memo and the cache (any age) are consulted and
        nothing is tallied."""
        cve = cve.strip().upper()
        now = self.now()
        with self._lock:
            forced = network and (force_refresh or self._run_forces(cve))
            memo = None if forced else self._memo.get(cve)
            if memo is not None and (not network or now - memo[1] < self.ttl(memo[0])):
                if network:
                    self._record(cve, OK, FROM_CACHE)
                return memo[0]
            skipped = self._unreachable
        cached = None if forced else self._read_cache(cve)
        if cached is not None:
            record, fetched = cached
            age = now - fetched
            if age < self.ttl(record):
                with self._lock:
                    self._memo[cve] = cached
                    if network:
                        self._record(cve, OK, FROM_CACHE)
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
                    self._memo[cve] = (record, self.now())
                    self._refreshed.add(cve)
                    self._record(cve, OK, FROM_LIVE)
                return record
        if forced:
            cached = self._read_cache(cve)
        if cached is not None:
            record, fetched = cached
            if record is not None:
                record.cache_age = self.now() - fetched
            logger.warning("Canonical lookup of %s failed (%s); using cached data", cve, error)
            with self._lock:
                self._record(cve, CACHED, FROM_CACHE)
            return record
        with self._lock:
            self._record(cve, FAILED, LOOKUP_FAILED)
        raise error

    def _fetch(self, cve: str) -> CveRecord | None:
        """One lookup with retries. Only network-level failures count toward the breaker."""
        url = API_URL.format(cve=cve)
        for attempt in range(1, self.attempts + 1):
            self._throttle()
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

    def _throttle(self) -> None:
        """Keep outbound requests ``pace`` seconds apart (the first one of a run never waits)."""
        with self._pace_lock:
            now = self.monotonic()
            if self._last_request is not None:
                wait = self._last_request + self.pace - now
                if wait > 0:
                    self.sleep(wait)
                    now += wait
            self._last_request = now

    def _run_forces(self, cve: str) -> bool:
        # Caller holds the lock. A forced CVE is fetched once per run, then memoized.
        if cve in self._refreshed:
            return False
        return self._force_refresh is None or cve in self._force_refresh

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

    def _record(self, cve: str, outcome: str, source: str) -> None:
        # Caller holds the lock. A CVE that failed for any server this run stays failed.
        previous = self._outcomes.get(cve)
        if previous is None or _OUTCOME_RANK[outcome] >= _OUTCOME_RANK[previous]:
            self._outcomes[cve] = outcome
        record_source(self._sources, cve, source)

    # --- cache: table cve_metadata_cache (cve, document, fetched_at) ---------------------
    # "document" is the raw Canonical JSON, or NULL for a CVE Canonical answered 404 for.
    # Any cache error is logged and treated as a miss: the lookup then uses the network.

    def _cache(self) -> Database:
        if self._db is None:
            self._db = Database(self.cache_db_path)
        return self._db

    def _read_cache(self, cve: str) -> tuple[CveRecord | None, datetime] | None:
        try:
            entry = self._cache().get_cve_metadata(cve)
            if entry is None:
                return None
            document, fetched_at = entry
            fetched = datetime.fromisoformat(fetched_at)
            if document is None:
                return None, fetched
            return parse_cve_document(json.loads(document), cve), fetched
        except Exception as exc:  # noqa: BLE001 - a cache problem must never fail a lookup
            logger.warning("Ignoring unreadable Canonical cache entry for %s: %s", cve, exc)
            return None

    def _write_cache(self, cve: str, doc: dict | None) -> None:
        try:
            document = None if doc is None else json.dumps(doc)
            self._cache().put_cve_metadata(cve, document, self.now().isoformat())
        except Exception as exc:  # noqa: BLE001 - the fetched data is still returned
            logger.warning("Could not write Canonical cache entry for %s: %s", cve, exc)

    def status(self) -> MetadataStatus:
        return MetadataStatus(
            available=True,
            checked_at=_now().isoformat(),
            cache_db=self.cache_db_path,
            cache_ttl_hours=self.max_age.total_seconds() / 3600,
            investigating_ttl_hours=(
                min(self.max_age, self.investigating_max_age).total_seconds() / 3600
            ),
            timeout_seconds=self.timeout,
            pace_seconds=self.pace,
            attempts=self.attempts,
            breaker_threshold=self.breaker_threshold,
        )

    def ensure_fresh(self, progress: Callable[[str], None] | None = None) -> MetadataStatus:
        return self.status()

    def clear(self) -> bool:
        """Forget the memo, the breaker and the cache table."""
        with self._lock:
            had_entries = bool(self._memo) or self._unreachable is not None
            self._memo.clear()
            self._refreshed.clear()
            self._unreachable = None
            self._consecutive_failures = 0
        try:
            had_entries = self._cache().clear_cve_metadata() > 0 or had_entries
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not clear the Canonical cache: %s", exc)
        return had_entries
