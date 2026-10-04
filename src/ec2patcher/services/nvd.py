"""CVSS severity enrichment from the official NVD CVE API 2.0 (never HTML scraping).

NVD only supplies the CVSS severity / base score / version / vector shown in the reports.
Whether a CVE affects a server, which package fixes it and the patch status come exclusively
from Canonical's metadata (``cve_resolver``); a failed NVD lookup only makes the severity
Unknown and never changes a finding's status.

One request per CVE (``cveId`` query parameter), sequential and rate limited: NVD allows
5 requests per rolling 30 s without an API key and 50 with one, so requests are spaced 6 s /
0.6 s apart. The optional API key (saved encrypted in Settings, else the ``NVD_API_KEY``
environment variable) is sent in the ``apiKey`` request header, as the 2.0 API requires; it is
never shown, logged or exported. What NVD last said about the key (valid / rejected / unknown)
is persisted in the settings table, never the key. Responses
are cached per CVE in the application database (table ``nvd_cache``; raw ``metrics`` kept, so
the selection is recomputed on reuse): entries younger than the TTL are used without a
request, older entries are refreshed and used as a fallback (marked stale) when NVD cannot be
reached. The TTL (default 30 days) is set in Settings -> Caches. Failed lookups are never
cached, and a cache error never fails a lookup (it falls back to the network). The former
on-disk JSON cache is neither read nor written. Each run counts its lookups answered from the
cache / live / failed (:meth:`NvdClient.run_cache_stats`).

The key check retries once on HTTP 429 / 5xx (honouring Retry-After) before it settles for
"unknown"; the reason (HTTP status or network error) is persisted with the result.
"""

import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.models import FROM_CACHE, FROM_LIVE, LOOKUP_FAILED, CacheStats, record_source
from ec2patcher.services.severity import CRITICAL, HIGH, LOW, MEDIUM

logger = logging.getLogger(__name__)

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY_ENV = "NVD_API_KEY"
NVD_SOURCE = "nvd@nist.gov"
REQUEST_TIMEOUT_SECONDS = 20
CACHE_MAX_AGE = timedelta(days=30)
INTERVAL_PUBLIC = 6.0  # 5 requests / 30 s without a key
INTERVAL_WITH_KEY = 0.6  # 50 requests / 30 s with a key
MAX_ATTEMPTS = 3  # for 429 / 5xx
MAX_RETRY_AFTER = 60.0
CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Lookup outcomes, persisted per finding (cve_findings.nvd_status).
OK = "ok"  # fresh NVD data (cache or network)
STALE = "stale"  # NVD unreachable; older cached NVD data used
NO_CVSS = "no_cvss"  # NVD knows the CVE but has no usable CVSS metric
NOT_FOUND = "not_found"  # NVD returned zero vulnerabilities
FAILED = "failed"  # lookup failed and nothing was cached

# API key state for the UI badge (the key itself is never shown). The result of the last
# keyed request (key check or live lookup) is persisted in the settings table, so it survives
# restarts and cached lookups that send no request.
KEY_NOT_SET = "not_set"  # no key in Settings or NVD_API_KEY
KEY_UNKNOWN = "unknown"  # key configured, not checked yet or NVD unreachable at the check
KEY_VALID = "valid"  # NVD accepted the key (HTTP 200)
KEY_REJECTED = "rejected"  # HTTP 403, or 404 with NVD's invalid-apiKey message
KEY_UNREADABLE = "unreadable"  # a key is saved in Settings but cannot be decrypted
_KEY_RESULTS = (KEY_UNKNOWN, KEY_VALID, KEY_REJECTED)

# Settings row with the last key check: {"result", "checked_at", "source"} plus "reason"
# (HTTP status / network error) for an unknown result; never the key.
KEY_CHECK_SETTING = "nvd_api_key_check"
KEY_CHECK_CVE = "CVE-2021-44228"  # any well-known CVE: one small keyed request
KEY_CHECK_ATTEMPTS = 2  # the key check retries once on HTTP 429 / 5xx
KEY_RECHECK_AGE = timedelta(hours=24)  # at start, older checks (and unknown ones) are redone
MAX_REASON_LENGTH = 200
# NVD answers an invalid key with HTTP 404 and a "message: Invalid apiKey." header.
_INVALID_KEY_RE = re.compile(rb"invalid\s*api\s*-?key|api\s*-?key\s+(?:is\s+)?invalid", re.I)

# Where the key in use comes from: a key saved in Settings overrides NVD_API_KEY.
KEY_SOURCE_SETTINGS = "settings"
KEY_SOURCE_ENV = "env"

STATUS_LABELS = {
    OK: "NVD",
    STALE: "NVD (stale cache)",
    NO_CVSS: "NVD has no CVSS score",
    NOT_FOUND: "CVE not found in NVD",
    FAILED: "NVD lookup failed",
}

# Metric collections by preference; v2 is a legacy fallback used only without v3/v4.
MODERN_METRICS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"))
LEGACY_METRICS = (("cvssMetricV2", "2.0"),)
_VERSION_RANK = {v: i for i, (_, v) in enumerate((*MODERN_METRICS, *LEGACY_METRICS))}
_SUPPLIED = {"LOW": LOW, "MEDIUM": MEDIUM, "HIGH": HIGH, "CRITICAL": CRITICAL, "NONE": None}


@dataclass(frozen=True)
class CvssResult:
    status: str
    severity: str | None = None  # Critical / High / Medium / Low; None = Unknown (incl. 0.0)
    score: float | None = None
    version: str | None = None
    vector: str | None = None
    source: str | None = None
    source_type: str | None = None
    last_modified: str | None = None
    note: str | None = None  # diagnostics: error, inconsistency, stale cache age


class NvdError(Exception):
    """The NVD API could not be queried (network, HTTP or payload error)."""


class NvdUnreachable(NvdError):
    """Connection failure or timeout: NVD is treated as unavailable for the rest of the run."""


# --- CVSS selection and severity -------------------------------------------------------------


def severity_for_score(score: float, version: str) -> str | None:
    """Official CVSS qualitative rating; 0.0 is "None" -> None (never Low)."""
    if score <= 0:
        return None
    if score < 4.0:
        return LOW
    if score < 7.0:
        return MEDIUM
    if score < 9.0 or version == "2.0":  # CVSS v2 has no Critical rating
        return HIGH
    return CRITICAL


def _score(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if 0 <= value <= 10 else None


def _text(value) -> str | None:
    return value.strip() or None if isinstance(value, str) else None


def _candidates(metrics: dict, collections) -> list[dict]:
    found = []
    for key, version in collections:
        entries = metrics.get(key)
        for metric in entries if isinstance(entries, list) else []:
            data = metric.get("cvssData") if isinstance(metric, dict) else None
            score = _score(data.get("baseScore")) if isinstance(data, dict) else None
            if score is None:
                continue  # malformed / unscored metric: never guess a score
            source = _text(metric.get("source"))
            source_type = _text(metric.get("type"))
            supplied = data.get("baseSeverity")
            if version == "2.0":
                supplied = metric.get("baseSeverity", supplied)
            if source and source.casefold() == NVD_SOURCE:
                group = 0
            elif source_type and source_type.casefold() == "primary":
                group = 1
            else:
                group = 2
            found.append(
                {
                    "group": group,
                    "rank": _VERSION_RANK[version],
                    "version": version,
                    "score": score,
                    "vector": _text(data.get("vectorString")),
                    "source": source,
                    "source_type": source_type,
                    "supplied": _text(supplied),
                }
            )
    return found


def select_metric(metrics) -> dict | None:
    """Deterministic choice among all CVSS assessments of one CVE.

    Source first: NVD/NIST (nvd@nist.gov), else the Primary assessment, else any other;
    within a group CVSS v4.0 > v3.1 > v3.0; ties are broken by source name, then score and
    vector, so the result never depends on the API's array order. v2 only if no v3/v4 exists.
    """
    if not isinstance(metrics, dict):
        return None
    for collections in (MODERN_METRICS, LEGACY_METRICS):
        found = _candidates(metrics, collections)
        if found:
            return min(
                found,
                key=lambda c: (
                    c["group"], c["rank"], (c["source"] or "").casefold(), -c["score"],
                    c["vector"] or "",
                ),
            )  # fmt: skip
    return None


def normalize(metric: dict) -> tuple[str | None, str | None]:
    """(severity, note) for a selected metric. The numeric score is authoritative: a missing
    or inconsistent baseSeverity is replaced by the official rating for the score."""
    expected = severity_for_score(metric["score"], metric["version"])
    supplied = metric["supplied"]
    if supplied is None:
        return expected, "NVD supplied no baseSeverity; rating derived from the base score."
    if supplied.upper() not in _SUPPLIED or _SUPPLIED[supplied.upper()] != expected:
        note = (
            f"NVD baseSeverity '{supplied}' is inconsistent with base score "
            f"{metric['score']} (CVSS {metric['version']}); rating derived from the score."
        )
        logger.warning("%s", note)
        return expected, note
    return expected, None


def result_from_cve(cve: dict | None, status: str = OK, note: str | None = None) -> CvssResult:
    """CvssResult from one ``vulnerabilities[].cve`` object (None = not in NVD)."""
    if cve is None:
        return CvssResult(status=NOT_FOUND, note=note)
    last_modified = _text(cve.get("lastModified"))
    metric = select_metric(cve.get("metrics"))
    if metric is None:
        return CvssResult(status=NO_CVSS, last_modified=last_modified, note=note)
    severity, diagnostic = normalize(metric)
    if metric["score"] == 0 and diagnostic is None:
        diagnostic = "CVSS base score 0.0 (None): no severity rating."
    return CvssResult(
        status=status,
        severity=severity,
        score=metric["score"],
        version=metric["version"],
        vector=metric["vector"],
        source=metric["source"],
        source_type=metric["source_type"],
        last_modified=last_modified,
        note="; ".join(n for n in (diagnostic, note) if n) or None,
    )


def parse_response(body: bytes, cve_id: str) -> dict | None:
    """The ``cve`` object for ``cve_id`` from an API 2.0 response, or None if absent."""
    try:
        doc = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NvdError(f"invalid JSON from NVD: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("vulnerabilities", []), list):
        raise NvdError("unexpected NVD response structure")
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve") if isinstance(item, dict) else None
        if isinstance(cve, dict) and str(cve.get("id", "")).upper() == cve_id:
            return cve
    return None


# --- HTTP ------------------------------------------------------------------------------------

# (url, headers, timeout) -> (HTTP status, response headers, body). Raises OSError/TimeoutError
# on connection problems.
Transport = Callable[[str, dict[str, str], float], tuple[int, dict[str, str], bytes]]


def http_get(url: str, headers: dict[str, str], timeout: float) -> tuple[int, dict, bytes]:
    request = urllib.request.Request(url, headers=headers)  # noqa: S310 - fixed https URL
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()  # an error body may explain it (e.g. an invalid API key)
        except OSError:
            body = b""
        return exc.code, dict(exc.headers or {}), body or b""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _retry_after(headers: dict[str, str], fallback: float) -> float:
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    try:
        return min(max(float(value), 0.0), MAX_RETRY_AFTER)
    except (TypeError, ValueError):
        return fallback


def key_verdict(status: int, headers: dict[str, str], body: bytes) -> str | None:
    """What a reply to a keyed request says about the key: KEY_VALID, KEY_REJECTED or None
    (nothing, e.g. 429 / 5xx)."""
    if status == 200:
        return KEY_VALID
    if status == 403:
        return KEY_REJECTED
    if status == 404:
        text = b" ".join([str(v).encode("utf-8", "replace") for v in headers.values()] + [body])
        if _INVALID_KEY_RE.search(text):
            return KEY_REJECTED
    return None


class NvdClient:
    """Per-CVE CVSS lookup with a persistent cache. Not thread-safe; analysis runs are
    serialized. Call :meth:`start_run` at the start of each analysis run."""

    def __init__(
        self,
        cache_db: Database | Path | None = None,
        transport: Transport | None = None,
        api_key: str | None = None,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = _now,
        max_age: timedelta = CACHE_MAX_AGE,
    ):
        # cache_db: the application Database (or its path); None = the default data dir DB,
        # opened on first use.
        if isinstance(cache_db, Database):
            self._db: Database | None = cache_db
            self.cache_db_path = cache_db.path
        else:
            self._db = None
            self.cache_db_path = (
                Path(cache_db) if cache_db else config.get_data_dir() / config.DB_FILENAME
            )
        self.transport = transport
        # The key without a Settings override: the argument, else NVD_API_KEY.
        self._default_key = api_key if api_key is not None else os.environ.get(API_KEY_ENV) or None
        self.sleep, self.monotonic, self.now, self.max_age = sleep, monotonic, now, max_age
        self.requests = 0  # HTTP requests sent (for diagnostics/tests)
        self._last_request: float | None = None
        self._use_key(self._default_key, KEY_SOURCE_ENV)
        self.start_run()

    def __repr__(self) -> str:
        return f"NvdClient(key_status={self._key_state!r}, key_source={self.key_source!r})"

    def _use_key(self, key: str | None, source: str, state: str | None = None) -> None:
        self._api_key = key or None
        self.key_source = source if self._api_key or state else None
        self.interval = INTERVAL_WITH_KEY if self._api_key else INTERVAL_PUBLIC
        # None: the last persisted key check is read on first use (see key_status).
        self._key_state = state or (None if self._api_key else KEY_NOT_SET)
        self._key_checked_at: str | None = None
        self._key_reason: str | None = None

    def use_settings_key(self, key: str | None, unreadable: bool = False) -> None:
        """Apply the key saved in Settings; it overrides NVD_API_KEY. ``None`` (no key saved)
        falls back to NVD_API_KEY. ``unreadable``: a key is saved but cannot be decrypted;
        no key is sent then (the badge asks to enter it again)."""
        if unreadable:
            self._use_key(None, KEY_SOURCE_SETTINGS, KEY_UNREADABLE)
        elif key:
            self._use_key(key, KEY_SOURCE_SETTINGS)
        else:
            self._use_key(self._default_key, KEY_SOURCE_ENV)

    @property
    def has_key(self) -> bool:
        return self._api_key is not None

    @property
    def key_status(self) -> str:
        """KEY_NOT_SET / KEY_UNKNOWN / KEY_VALID / KEY_REJECTED / KEY_UNREADABLE (never the key
        itself)."""
        if self._key_state is None:
            self._key_state, self._key_checked_at, self._key_reason = self._load_key_check()
        return self._key_state

    @property
    def key_checked_at(self) -> str | None:
        """UTC ISO time of the last key check behind :attr:`key_status`, or None."""
        return self._key_checked_at if self.key_status in _KEY_RESULTS else None

    @property
    def key_reason(self) -> str | None:
        """Why the key state is unknown (HTTP status, network error, or not checked yet);
        None in any other state."""
        if self.key_status != KEY_UNKNOWN:
            return None
        if self._key_checked_at is None:
            return "not checked yet"
        return self._key_reason or "no details recorded"

    def key_check_due(self) -> bool:
        """True if a usable key is configured and its last check is unknown, missing,
        unreadable or older than :data:`KEY_RECHECK_AGE` (the app re-checks it at start)."""
        if not self._api_key:
            return False
        if self.key_status == KEY_UNKNOWN or self._key_checked_at is None:
            return True
        try:
            checked = datetime.fromisoformat(self._key_checked_at)
            return self.now() - checked >= KEY_RECHECK_AGE
        except (TypeError, ValueError):
            return True

    def _load_key_check(self) -> tuple[str, str | None, str | None]:
        """The persisted result of the last key check, if it was made with a key from the
        current source (a check of the NVD_API_KEY key says nothing about a Settings key)."""
        try:
            value = self._cache().get_setting(KEY_CHECK_SETTING)
            check = json.loads(value) if value else {}
            if (
                isinstance(check, dict)
                and check.get("source") == self.key_source
                and check.get("result") in _KEY_RESULTS
            ):
                reason = _text(check.get("reason")) if check["result"] == KEY_UNKNOWN else None
                return check["result"], _text(check.get("checked_at")), reason
        except Exception as exc:  # noqa: BLE001 - the badge then just shows "unknown"
            logger.warning("Ignoring the unreadable NVD API key check: %s", exc)
        return KEY_UNKNOWN, None, None

    def _record_key_check(self, result: str, reason: str | None = None) -> None:
        """Remember (and persist) what NVD said about the key: result, time and key source,
        plus the reason of an unknown result."""
        self._key_state, self._key_checked_at = result, self.now().isoformat()
        self._key_reason = reason if result == KEY_UNKNOWN else None
        check = {"result": result, "checked_at": self._key_checked_at, "source": self.key_source}
        if self._key_reason:
            check["reason"] = self._key_reason
        try:
            self._cache().set_setting(KEY_CHECK_SETTING, json.dumps(check))
        except Exception as exc:  # noqa: BLE001 - the in-memory state is still right
            logger.warning("Could not save the NVD API key check: %s", exc)

    def forget_key_check(self) -> None:
        """Drop the persisted key check (e.g. the checked key was removed)."""
        try:
            self._cache().delete_setting(KEY_CHECK_SETTING)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not remove the NVD API key check: %s", exc)
        if self._api_key:
            self._key_state, self._key_checked_at, self._key_reason = KEY_UNKNOWN, None, None

    def _key_label(self) -> str:
        return "Settings" if self.key_source == KEY_SOURCE_SETTINGS else API_KEY_ENV

    def _reason(self, text: str) -> str:
        """A short, key-free reason for the UI and the settings table."""
        if self._api_key:
            text = text.replace(self._api_key, "***")
        return text[:MAX_REASON_LENGTH]

    def check_key(self) -> str:
        """Send a keyed request now and persist what it says about the key: KEY_VALID
        (HTTP 200), KEY_REJECTED (403, or 404 with the invalid-apiKey message) or KEY_UNKNOWN
        (NVD unreachable or any other answer, with the reason). HTTP 429 / 5xx is retried
        once (after Retry-After, if given) before the result is unknown. Without a usable
        key nothing is sent and KEY_NOT_SET / KEY_UNREADABLE is returned."""
        if not self._api_key:
            return self.key_status
        url = f"{API_URL}?{urllib.parse.urlencode({'cveId': KEY_CHECK_CVE})}"
        transport = self.transport or http_get
        result, reason = KEY_UNKNOWN, None
        for attempt in range(1, KEY_CHECK_ATTEMPTS + 1):
            self._throttle()
            self.requests += 1
            try:
                status, headers, body = transport(url, self._headers(), REQUEST_TIMEOUT_SECONDS)
            except (OSError, TimeoutError) as exc:
                reason = self._reason(f"network error: {exc or type(exc).__name__}")
                logger.warning("NVD API key check from %s: %s", self._key_label(), reason)
                break
            result = key_verdict(status, headers, body) or KEY_UNKNOWN
            logger.info(
                "NVD API key check from %s: HTTP %s -> %s", self._key_label(), status, result
            )
            if result != KEY_UNKNOWN:
                reason = None
                break
            reason = f"HTTP {status}" + (" (after a retry)" if attempt > 1 else "")
            if (status == 429 or status >= 500) and attempt < KEY_CHECK_ATTEMPTS:
                delay = _retry_after(headers, self.interval * 2)
                logger.info("NVD API key check: HTTP %s; retrying in %.0f s", status, delay)
                self.sleep(delay)
                continue
            break
        self._record_key_check(result, reason)
        return result

    def start_run(self) -> None:
        """Forget per-run state: the in-run memo and the 'NVD unreachable' circuit breaker."""
        self._memo: dict[str, CvssResult] = {}
        self._unreachable: str | None = None
        self._sources: dict[str, str] = {}  # CVE -> cache / live / failed, this run

    def run_cache_stats(self) -> CacheStats:
        """Lookups since :meth:`start_run`: from cache (fresh or stale) / live / failed."""
        return CacheStats.from_sources(self._sources)

    # --- cache -------------------------------------------------------------------------

    def _cache(self) -> Database:
        if self._db is None:
            self._db = Database(self.cache_db_path)
        return self._db

    def _read_cache(self, cve_id: str) -> dict | None:
        """{"cve": slim cve object or None (unknown to NVD), "fetched", "fetched_at"}, or None
        when not cached or unreadable (the network is used then)."""
        try:
            entry = self._cache().get_nvd_cache(cve_id)
            if entry is None:
                return None
            metrics, last_modified, fetched_at = entry
            fetched = datetime.fromisoformat(fetched_at)
            cve = None
            if metrics is not None:
                cve = {"id": cve_id, "lastModified": last_modified, "metrics": json.loads(metrics)}
                if not isinstance(cve["metrics"], dict):
                    raise ValueError("cached metrics are not an object")
            return {"cve": cve, "fetched": fetched, "fetched_at": fetched_at}
        except Exception as exc:  # noqa: BLE001 - a cache problem must never fail a lookup
            logger.warning("Ignoring unreadable NVD cache entry for %s: %s", cve_id, exc)
            return None

    def _write_cache(self, cve_id: str, cve: dict | None) -> None:
        # Only what later reuse needs: the raw metrics and lastModified.
        try:
            metrics = None if cve is None else json.dumps(cve.get("metrics") or {})
            last_modified = None if cve is None else _text(cve.get("lastModified"))
            self._cache().put_nvd_cache(cve_id, metrics, last_modified, self.now().isoformat())
        except Exception as exc:  # noqa: BLE001 - the fetched data is still returned
            logger.warning("Could not write NVD cache entry for %s: %s", cve_id, exc)

    def clear(self) -> bool:
        """Forget the in-run memo, the breaker and the ``nvd_cache`` table. True if anything
        was removed."""
        had_entries = bool(self._memo) or self._unreachable is not None
        self.start_run()
        try:
            had_entries = self._cache().clear_nvd_cache() > 0 or had_entries
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not clear the NVD cache: %s", exc)
        return had_entries

    # --- network -----------------------------------------------------------------------

    def _throttle(self) -> None:
        if self._last_request is not None:
            wait = self._last_request + self.interval - self.monotonic()
            if wait > 0:
                self.sleep(wait)
        self._last_request = self.monotonic()

    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": "ec2patcher", "Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        return headers

    def fetch(self, cve_id: str) -> dict | None:
        """Query NVD for one CVE; the ``cve`` object or None if NVD has no such CVE (an empty
        HTTP 200 answer: any other status, e.g. a 404 for an invalid key, raises)."""
        url = f"{API_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
        headers = self._headers()
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._throttle()
            self.requests += 1
            try:
                transport = self.transport or http_get  # resolved late so tests can disable it
                status, response_headers, body = transport(url, headers, REQUEST_TIMEOUT_SECONDS)
            except (OSError, TimeoutError) as exc:  # URLError is an OSError
                raise NvdUnreachable(f"NVD unreachable: {exc}") from exc
            verdict = key_verdict(status, response_headers, body) if self._api_key else None
            if verdict:
                self._record_key_check(verdict)
            if verdict == KEY_REJECTED:
                logger.warning(
                    "NVD rejected the configured API key from %s (HTTP %s)",
                    self._key_label(), status,
                )  # fmt: skip
                raise NvdError(f"NVD rejected the API key (HTTP {status})")
            if status == 200:
                return parse_response(body, cve_id)
            backoff = self.interval * 2**attempt
            if status == 429 or status >= 500:
                if attempt < MAX_ATTEMPTS:
                    delay = _retry_after(response_headers, backoff) if status == 429 else backoff
                    logger.info("NVD HTTP %s for %s; retrying in %.0f s", status, cve_id, delay)
                    self.sleep(delay)
                    continue
                raise NvdError(f"NVD HTTP {status} after {MAX_ATTEMPTS} attempts")
            raise NvdError(f"NVD HTTP {status}")
        raise NvdError("NVD request failed")  # unreachable: the last attempt always raises

    # --- lookup ------------------------------------------------------------------------

    def lookup(self, cve_id: str) -> CvssResult:
        """CVSS data for one CVE. Never raises; one call per CVE per run."""
        cve_id = cve_id.strip().upper()
        if cve_id not in self._memo:
            try:
                self._memo[cve_id] = self._lookup(cve_id)
            except Exception as exc:  # noqa: BLE001 - enrichment must never break analysis
                logger.exception("NVD lookup for %s failed unexpectedly", cve_id)
                self._memo[cve_id] = CvssResult(status=FAILED, note=f"NVD lookup failed: {exc}")
                record_source(self._sources, cve_id, LOOKUP_FAILED)
        return self._memo[cve_id]

    def _lookup(self, cve_id: str) -> CvssResult:
        if not CVE_ID_RE.match(cve_id):
            return CvssResult(status=FAILED, note="Not a valid CVE identifier.")
        cached = self._read_cache(cve_id)
        if cached and self.now() - cached["fetched"] < self.max_age:
            record_source(self._sources, cve_id, FROM_CACHE)
            return result_from_cve(cached["cve"])
        error = self._unreachable
        if error is None:
            try:
                cve = self.fetch(cve_id)
            except NvdError as exc:
                error = str(exc)
                logger.warning("NVD lookup for %s failed: %s", cve_id, error)
                if isinstance(exc, NvdUnreachable):
                    self._unreachable = error  # don't wait for a timeout on every CVE
            else:
                self._write_cache(cve_id, cve)
                record_source(self._sources, cve_id, FROM_LIVE)
                return result_from_cve(cve)
        if cached:
            record_source(self._sources, cve_id, FROM_CACHE)
            note = f"NVD lookup failed ({error}); using cached data from {cached['fetched_at']}."
            return result_from_cve(cached["cve"], status=STALE, note=note)
        record_source(self._sources, cve_id, LOOKUP_FAILED)
        return CvssResult(status=FAILED, note=error)
