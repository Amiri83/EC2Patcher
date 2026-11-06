"""Priority enrichment: CISA KEV and FIRST EPSS, cached in SQLite. Never changes a status.

Best-effort: a failure is logged and leaves the value empty; nothing here may fail a run, and the
caller bounds how long the requests may take.
"""

import logging
import re
import time
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from ec2patcher.database import Database
from ec2patcher.services import source_http
from ec2patcher.services.source_breaker import BreakerBoard

logger = logging.getLogger(__name__)

KEV, EPSS = "kev", "epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"
TTL = timedelta(hours=24)
EPSS_BATCH_SIZE = 50  # the API takes a query of about 2000 characters
EPSS_PACE_SECONDS = 1.0
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def _score(value) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _parse_scores(document: dict) -> dict[str, tuple[float | None, float | None]]:
    scores = {}
    for item in document["data"]:
        cve = str(item["cve"]).upper()
        scores[cve] = (_score(item.get("epss")), _score(item.get("percentile")))
    return scores


class Enrichment:
    def __init__(
        self,
        db: Database,
        breakers: BreakerBoard | None = None,
        fetcher: Callable[[str], dict] | None = None,
        now: Callable[[], datetime] = _now,
        max_age: timedelta = TTL,
        sleep: Callable[[float], None] = time.sleep,
        batch_size: int = EPSS_BATCH_SIZE,
        pace: float = EPSS_PACE_SECONDS,
    ):
        self.db, self.fetcher, self.now, self.max_age = db, fetcher, now, max_age
        self.sleep, self.batch_size, self.pace = sleep, max(1, batch_size), pace
        self.breakers = breakers or BreakerBoard()
        self.start_run()

    def start_run(self) -> None:
        self._kev_tried = False
        self._epss_failed = False

    def _get(self, source: str, url: str) -> dict | None:
        """One request under the source's breaker; None if it failed (logged)."""
        breaker = self.breakers.get(source, urlsplit(url).hostname or "")
        if not breaker.allow():
            logger.info("enrichment source=%s skipped=backoff reason=%s", source, breaker.reason)
            return None
        fetch = self.fetcher or source_http.fetch_json
        try:
            document = fetch(url)
        except _ERRORS as exc:
            reason = source_http.describe_error(exc)
            breaker.failure(reason)
            logger.warning("enrichment source=%s failed=true reason=%s", source, reason)
            return None
        breaker.success()
        return document

    def _is_fresh(self, stamp: str | None) -> bool:
        if not stamp:
            return False
        return self.now() - datetime.fromisoformat(stamp) < self.max_age

    # --- KEV: one catalogue file --------------------------------------------------------

    def refresh_kev(self, blocked: str | None = None) -> None:
        feed = self.db.get_source_feed(KEV)
        if self._kev_tried or blocked or (feed and self._is_fresh(feed["fetched_at"])):
            return
        self._kev_tried = True
        document = self._get(KEV, KEV_URL)
        if document is None:
            return
        try:
            rows = [
                (str(item["cveID"]).strip().upper(), item.get("dateAdded"))
                for item in document["vulnerabilities"]
            ]
        except _ERRORS as exc:
            logger.warning("enrichment source=kev unusable=true reason=%s", exc)
            return
        rows = [row for row in rows if _CVE_RE.match(row[0])]
        if not rows:
            logger.warning("enrichment source=kev unusable=true reason=empty catalogue")
            return
        self.db.replace_kev(rows, self.now().isoformat())
        logger.info("enrichment source=kev stored=%d", len(rows))

    # --- EPSS: comma-batched ------------------------------------------------------------

    def refresh_epss(self, cves: Iterable[str], blocked: str | None = None) -> None:
        if blocked or self._epss_failed:
            return
        wanted = sorted({c.strip().upper() for c in cves if _CVE_RE.match(c.strip().upper())})
        cached = self.db.get_epss(wanted)
        missing = [c for c in wanted if c not in cached or not self._is_fresh(cached[c][2])]
        for start in range(0, len(missing), self.batch_size):
            if start:
                self.sleep(self.pace)
            batch = missing[start : start + self.batch_size]
            document = self._get(EPSS, f"{EPSS_URL}?cve={','.join(batch)}")
            if document is None:
                self._epss_failed = True
                return
            try:
                scores = _parse_scores(document)
            except _ERRORS as exc:
                logger.warning("enrichment source=epss unusable=true reason=%s", exc)
                self._epss_failed = True
                return
            stamp = self.now().isoformat()
            # A CVE without a score is stored too, so it is not asked for again within the TTL.
            self.db.put_epss([(cve, *scores.get(cve, (None, None)), stamp) for cve in batch])

    # --- findings -----------------------------------------------------------------------

    def annotate(self, findings: list) -> None:
        """Set KEV (None: no catalogue stored) and the EPSS score on the findings from what is
        stored; no request. Priority only: statuses and plans are not touched."""
        cves = sorted({f.cve for f in findings})
        if not cves:
            return
        has_kev = self.db.get_source_feed(KEV) is not None
        listed = self.db.kev_listed(cves) if has_kev else set()
        scores = self.db.get_epss(cves)
        for finding in findings:
            finding.kev = finding.cve in listed if has_kev else None
            stored = scores.get(finding.cve)
            finding.epss = stored[0] if stored else None
