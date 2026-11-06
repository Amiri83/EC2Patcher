"""USN notices from ubuntu.com/security/notices.json, stored in SQLite with a 24 h TTL.

The feed is paged (limit 20) until a short page or its total. A run gives it a bounded amount of
time and the next run resumes at the stored offset, so a large first download never holds a run
up. After one complete pull a refresh stops as soon as every notice is known, whatever the order
of the pages.

A CVE can appear in several USNs: all links are kept, :func:`best_usn` picks one for the report
deterministically. A USN also names the fixed source package versions per release, which makes
this the resolver's second source.
"""

import logging
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from ec2patcher.database import Database
from ec2patcher.services import debversion, source_http
from ec2patcher.services.security_metadata import CveRecord, status_entry
from ec2patcher.services.server_state import SUPPORTED_RELEASES
from ec2patcher.services.source_breaker import BreakerBoard

logger = logging.getLogger(__name__)

SOURCE = "notices"
URL = "https://ubuntu.com/security/notices.json"
PAGE_SIZE = 20
TTL = timedelta(hours=24)
RUN_BUDGET_SECONDS = 120.0
PACE_SECONDS = 0.2
_NOTICE_ID_RE = re.compile(r"^[A-Z]{2,5}-\d+(?:-\d+)?$")
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _no_check() -> None:
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


@dataclass(frozen=True)
class Usn:
    id: str
    title: str | None
    published: str | None


def parse_notice(notice) -> dict | None:
    """The stored fields of one notice; None if it has no usable ID."""
    if not isinstance(notice, dict):
        return None
    usn_id = str(notice.get("id") or "").strip().upper()
    if not _NOTICE_ID_RE.match(usn_id):
        return None
    cves = notice.get("cves_ids")
    if not isinstance(cves, list):
        listed = notice.get("cves")
        cves = [c.get("id") if isinstance(c, dict) else c for c in listed or []]
    packages = []
    releases = notice.get("release_packages")
    for codename, items in (releases if isinstance(releases, dict) else {}).items():
        if codename not in SUPPORTED_RELEASES.values() or not isinstance(items, list):
            continue
        for item in items:
            if isinstance(item, dict) and item.get("is_source") and item.get("name"):
                packages.append((codename, str(item["name"]), str(item.get("version") or "")))
    return {
        "id": usn_id,
        "title": str(notice.get("title") or "")[:500] or None,
        "published": str(notice.get("published") or "") or None,
        "cves": sorted({str(c).upper() for c in cves if c and _CVE_RE.match(str(c).upper())}),
        "packages": packages,
    }


def _usn_order(usn_id: str) -> tuple[int, ...]:
    return tuple(int(part) for part in re.findall(r"\d+", usn_id))


def best_usn(db: Database, cve: str, codename: str | None) -> Usn | None:
    """The USN to report for a CVE: one for this release first, then the latest published, then
    the highest number. The same stored data always gives the same answer."""
    rows = db.usn_candidates(cve, codename or "")
    if not rows:
        return None
    best = max(
        rows,
        key=lambda r: (bool(r["for_release"]), r["published"] or "", _usn_order(r["usn_id"])),
    )
    return Usn(best["usn_id"], best["title"], best["published"])


class UsnNotices:
    def __init__(
        self,
        db: Database,
        breakers: BreakerBoard | None = None,
        fetcher: Callable[[str], dict] | None = None,
        now: Callable[[], datetime] = _now,
        max_age: timedelta = TTL,
        sleep: Callable[[float], None] = time.sleep,
        monotonic: Callable[[], float] = time.monotonic,
        budget: float = RUN_BUDGET_SECONDS,
        pace: float = PACE_SECONDS,
    ):
        self.db, self.fetcher, self.now, self.max_age = db, fetcher, now, max_age
        self.sleep, self.monotonic, self.budget, self.pace = sleep, monotonic, budget, pace
        self.breakers = breakers or BreakerBoard()

    def _is_fresh(self, feed: dict | None) -> bool:
        if not feed or not feed["complete"] or not feed["fetched_at"]:
            return False
        return self.now() - datetime.fromisoformat(feed["fetched_at"]) < self.max_age

    def refresh(self, blocked: str | None = None, check: Callable[[], None] = _no_check) -> str:
        """Bring the stored notices up to date as far as this run can; says how that went.
        A failure keeps what is stored and is picked up by the next run."""
        feed = self.db.get_source_feed(SOURCE)
        if self._is_fresh(feed):
            return f"stored notices are current ({self.db.count_usn_notices()} notices)"
        if blocked:
            return f"using the {self.db.count_usn_notices()} stored notices: blocked ({blocked})"
        breaker = self.breakers.get(SOURCE, urlsplit(URL).hostname or "")
        fetch = self.fetcher or source_http.fetch_json
        was_complete = bool(feed and feed["fetched_at"])
        offset = feed["next_offset"] if feed and not feed["complete"] else 0
        deadline = self.monotonic() + self.budget
        pages = 0
        while True:
            check()
            if not breaker.allow():
                return self._stop(feed, offset, f"backing off ({breaker.reason})")
            try:
                page = fetch(f"{URL}?limit={PAGE_SIZE}&offset={offset}")
                notices = page["notices"]
                if not isinstance(notices, list):
                    raise ValueError("no notices list")
            except (OSError, ValueError, KeyError, TypeError) as exc:
                reason = source_http.describe_error(exc)
                breaker.failure(reason)
                return self._stop(feed, offset, reason)
            breaker.success()
            self.db.store_usn_page([n for n in map(parse_notice, notices) if n])
            offset += len(notices)
            pages += 1
            total = page.get("total_results", page.get("total"))
            total = total if isinstance(total, int) else None
            if (
                len(notices) < PAGE_SIZE
                or (total is not None and offset >= total)
                or (was_complete and total is not None and self.db.count_usn_notices() >= total)
            ):
                break
            if self.monotonic() >= deadline:
                self.db.put_source_feed(
                    SOURCE,
                    fetched_at=feed["fetched_at"] if feed else None,
                    complete=False,
                    next_offset=offset,
                )
                return f"{pages} pages read, the next run continues at offset {offset}"
            self.sleep(self.pace)
        count = self.db.count_usn_notices()
        self.db.put_source_feed(
            SOURCE, fetched_at=self.now().isoformat(), entries=count, complete=True, next_offset=0
        )
        logger.info("usn_notices pages=%d stored=%d", pages, count)
        return f"{pages} pages read, {count} notices stored"

    def _stop(self, feed: dict | None, offset: int, reason: str) -> str:
        self.db.put_source_feed(
            SOURCE,
            fetched_at=feed["fetched_at"] if feed else None,
            complete=False,
            next_offset=offset,
        )
        logger.warning("usn_notices stopped_at=%d reason=%s", offset, reason)
        return f"could not refresh ({reason}); using {self.db.count_usn_notices()} stored notices"

    def has_data(self) -> bool:
        return self.db.count_usn_notices() > 0

    def lookup(self, cve: str, codename: str) -> CveRecord | None:
        """Fixed source packages of this release named by the USNs of ``cve``."""
        versions: dict[str, str] = {}
        for package, version in self.db.usn_packages(cve, codename):
            if not debversion.is_valid_version(version):
                continue
            current = versions.get(package)
            if current is None or debversion.compare_versions(version, current) > 0:
                versions[package] = version
        if not versions:
            return None
        record = CveRecord(cve=cve, origin=SOURCE)
        for package, version in sorted(versions.items()):
            record.entries.append(status_entry(package, version, codename, "released", None))
        return record

    def packages_for(self, cve: str) -> list[str]:
        """Packages any release of the USNs of ``cve`` names: a hint for the changelog search."""
        return self.db.usn_packages_any_release(cve)
