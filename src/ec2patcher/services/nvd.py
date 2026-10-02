"""CVSS severity enrichment from the official NVD CVE API 2.0 (never HTML scraping).

NVD only supplies the CVSS severity / base score / version / vector shown in the reports.
Whether a CVE affects a server, which package fixes it and the patch status come exclusively
from Canonical's metadata (``cve_resolver``); a failed NVD lookup only makes the severity
Unknown and never changes a finding's status.

One request per CVE (``cveId`` query parameter), sequential and rate limited: NVD allows
5 requests per rolling 30 s without an API key and 50 with one, so requests are spaced 6 s /
0.6 s apart. The optional ``NVD_API_KEY`` environment variable is sent in the ``apiKey``
request header, as the 2.0 API requires; it is never stored, logged or exported. Responses
are cached per CVE in the application database (table ``nvd_cache``; raw ``metrics`` kept, so
the selection is recomputed on reuse): entries younger than 30 days are used without a
request, older entries are refreshed and used as a fallback (marked stale) when NVD cannot be
reached. Failed lookups are never cached, and a cache error never fails a lookup (it falls
back to the network). The former on-disk JSON cache is neither read nor written.
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

# NVD_API_KEY state for the UI badge (this process only; the key itself is never shown).
KEY_NOT_SET = "not_set"  # no NVD_API_KEY
KEY_SET = "set"  # key configured, no keyed request answered yet
KEY_IN_USE = "in_use"  # the last keyed request succeeded
KEY_REJECTED = "rejected"  # NVD answered HTTP 403 to the last keyed request

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
        return exc.code, dict(exc.headers or {}), b""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _retry_after(headers: dict[str, str], fallback: float) -> float:
    value = next((v for k, v in headers.items() if k.lower() == "retry-after"), None)
    try:
        return min(max(float(value), 0.0), MAX_RETRY_AFTER)
    except (TypeError, ValueError):
        return fallback


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
        self._api_key = api_key if api_key is not None else os.environ.get(API_KEY_ENV) or None
        self.interval = INTERVAL_WITH_KEY if self._api_key else INTERVAL_PUBLIC
        self.sleep, self.monotonic, self.now, self.max_age = sleep, monotonic, now, max_age
        self.requests = 0  # HTTP requests sent (for diagnostics/tests)
        self._key_state = KEY_SET if self._api_key else KEY_NOT_SET
        self._last_request: float | None = None
        self.start_run()

    @property
    def key_status(self) -> str:
        """KEY_NOT_SET / KEY_SET / KEY_IN_USE / KEY_REJECTED (never the key itself)."""
        return self._key_state

    def start_run(self) -> None:
        """Forget per-run state: the in-run memo and the 'NVD unreachable' circuit breaker."""
        self._memo: dict[str, CvssResult] = {}
        self._unreachable: str | None = None

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

    def fetch(self, cve_id: str) -> dict | None:
        """Query NVD for one CVE; the ``cve`` object or None if NVD has no such CVE."""
        url = f"{API_URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
        headers = {"User-Agent": "ec2patcher", "Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key
        for attempt in range(1, MAX_ATTEMPTS + 1):
            self._throttle()
            self.requests += 1
            try:
                transport = self.transport or http_get  # resolved late so tests can disable it
                status, response_headers, body = transport(url, headers, REQUEST_TIMEOUT_SECONDS)
            except (OSError, TimeoutError) as exc:  # URLError is an OSError
                raise NvdUnreachable(f"NVD unreachable: {exc}") from exc
            if self._api_key and status == 200:
                self._key_state = KEY_IN_USE
            elif self._api_key and status == 403:
                self._key_state = KEY_REJECTED
                logger.warning("NVD rejected the configured NVD_API_KEY (HTTP 403)")
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
        return self._memo[cve_id]

    def _lookup(self, cve_id: str) -> CvssResult:
        if not CVE_ID_RE.match(cve_id):
            return CvssResult(status=FAILED, note="Not a valid CVE identifier.")
        cached = self._read_cache(cve_id)
        if cached and self.now() - cached["fetched"] < self.max_age:
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
                return result_from_cve(cve)
        if cached:
            note = f"NVD lookup failed ({error}); using cached data from {cached['fetched_at']}."
            return result_from_cve(cached["cve"], status=STALE, note=note)
        return CvssResult(status=FAILED, note=error)
