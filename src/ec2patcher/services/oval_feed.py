"""Canonical's OVAL CVE feed: one file per Ubuntu release, stored in SQLite.

The primary source of the resolver. ``com.ubuntu.<codename>.cve.oval.xml.bz2`` is downloaded at
most once per TTL to a temporary file, decompressed as a stream and parsed with ``iterparse``,
elements being discarded as they are read. After that CVE -> package -> status / fixed version
is answered locally, without a request per CVE.

Rows are written in batches under a new generation that only becomes current once the whole
file parsed: a truncated or corrupt download is discarded and the previous copy stays in use.
"""

import bz2
import dataclasses
import logging
import re
import tempfile
import time
import urllib.error
import xml.etree.ElementTree as ET  # noqa: S405 - trusted HTTPS source; no DTDs/entities used
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import BinaryIO
from urllib.parse import urlsplit

from ec2patcher.database import Database
from ec2patcher.services import debversion, source_http
from ec2patcher.services.security_metadata import CveRecord, format_age, status_entry
from ec2patcher.services.server_state import SUPPORTED_RELEASES
from ec2patcher.services.source_breaker import BreakerBoard

logger = logging.getLogger(__name__)

SOURCE = "oval"
URL = "https://security-metadata.canonical.com/oval/com.ubuntu.{codename}.cve.oval.xml.bz2"
TTL = timedelta(hours=24)
DOWNLOAD_TIMEOUT_SECONDS = 30.0  # per socket operation
DOWNLOAD_RETRIES = 2  # after a network failure, before the stored copy is kept
RETRY_BACKOFF_SECONDS = 2.0  # waits 2 s, then 4 s
# HTTP answers that say the request may succeed if repeated; any other status is definite.
RETRYABLE_HTTP_CODES = frozenset({408, 425, 429, 500, 502, 503, 504})
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_XML_BYTES = 8 * 1024 * 1024 * 1024
BATCH_ROWS = 2000
MAX_NOTE_CHARS = 200

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_COMMENT_RE = re.compile(
    r"^(?:\(CVE-[\d-]+\)\s*)?(?P<package>[a-z0-9][a-z0-9+.-]*)(?P<rest>\s+package\b.*|:\s.*)$",
    re.DOTALL,
)
_NOTE_RE = re.compile(r"\(note: '(?P<note>.*)'\)\.?\s*$", re.DOTALL)
_TITLE_PRIORITY_RE = re.compile(r" - (\w+)\.?\s*$")
# The wording of Canonical's criterion comments, first match wins. None: no statement.
_STATUS_PHRASES = (
    ("does not exist", None),
    ("decision has been made to ignore", "ignored"),
    ("is not affected", "not-affected"),
    ("has been fixed", "released"),
    ("pending publication", "pending"),
    ("defer", "deferred"),
    ("may need fixing", "needs-triage"),
    ("needs fixing", "needed"),
    ("affected", "needed"),
)


class OvalParseError(ValueError):
    """The feed is not usable: nothing in it could be stored."""


@dataclass(frozen=True)
class OvalEntry:
    cve: str
    package: str  # source package
    status: str  # Canonical's: released, not-affected, needed, needs-triage, pending, ...
    fixed_version: str | None = None  # released: the fix; pending: the version to be published
    note: str | None = None
    priority: str | None = None


@dataclass(frozen=True)
class FeedState:
    usable: bool  # a copy can be read, however old
    message: str
    problem: str | None = None  # why it could not be brought up to date


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _classify(comment: str) -> tuple[str, str | None, str | None] | None:
    """(package, status, note) of one criterion comment; None if it makes no statement."""
    match = _COMMENT_RE.match(" ".join(comment.split()))
    if not match:
        return None
    rest = match.group("rest").lower()
    status = next((s for phrase, s in _STATUS_PHRASES if phrase in rest), None)
    if status is None:
        return None
    note = _NOTE_RE.search(match.group("rest"))
    return match.group("package"), status, note.group("note").strip() if note else None


def _definition_entries(definition: ET.Element) -> list[tuple[OvalEntry, str | None]]:
    """The (entry, test reference) pairs of one CVE definition."""
    cve = priority = title = None
    criteria = []
    for node in definition.iter():
        name = _local(node.tag)
        if name == "reference" and (node.get("source") or "").upper() == "CVE":
            cve = cve or node.get("ref_id")
        elif name == "title":
            title = node.text or ""
        elif name == "severity":
            priority = (node.text or "").strip() or None
        elif name == "criterion":
            criteria.append((node.get("comment") or "", node.get("test_ref")))
    if not (cve and CVE_RE.fullmatch(cve)):
        found = CVE_RE.search(title or "")
        cve = found.group(0) if found else None
    if not cve:
        return []
    if priority is None:
        found = _TITLE_PRIORITY_RE.search(title or "")
        priority = found.group(1) if found else None
    entries: dict[str, tuple[OvalEntry, str | None]] = {}
    for comment, test_ref in criteria:
        statement = _classify(comment)
        if statement is None:
            continue
        package, status, note = statement
        # A fix pending publication keeps its version too (cve_resolver: opt-in candidate check).
        version = note if status in ("released", "pending") and _is_version(note) else None
        entry = OvalEntry(
            cve=cve.upper(),
            package=package,
            status=status,
            fixed_version=version,
            note=note[:MAX_NOTE_CHARS] if note else None,
            priority=priority,
        )
        entries.setdefault(package, (entry, test_ref))
    return list(entries.values())


def _is_version(text: str | None) -> bool:
    return bool(text) and debversion.is_valid_version(text)


def parse_oval(stream) -> Iterator[OvalEntry]:
    """The CVE statements of an OVAL XML stream. Parsed elements are discarded as it goes.

    The fixed version normally comes with the criterion's comment; a fixed package without one
    takes it from the ``dpkginfo_state`` its test points to, later in the file."""
    waiting: dict[str, list[OvalEntry]] = {}  # test id -> entries that need its version
    state_tests: dict[str, str] = {}  # state id -> test id
    stack: list[ET.Element] = []
    for event, element in ET.iterparse(stream, events=("start", "end")):  # noqa: S314 - see import
        if event == "start":
            stack.append(element)
            continue
        stack.pop()
        name = _local(element.tag)
        if name == "definition" and element.get("class", "vulnerability") == "vulnerability":
            for entry, test_ref in _definition_entries(element):
                if entry.status == "released" and not entry.fixed_version and test_ref:
                    waiting.setdefault(test_ref, []).append(entry)
                else:
                    yield entry
        elif name == "dpkginfo_test" and element.get("id") in waiting:
            for child in element:
                if _local(child.tag) == "state" and child.get("state_ref"):
                    state_tests[child.get("state_ref")] = element.get("id")
        elif name == "dpkginfo_state" and element.get("id") in state_tests:
            test_id = state_tests.pop(element.get("id"))
            evrs = [(c.text or "").strip() for c in element if _local(c.tag) == "evr"]
            version = evrs[0].removeprefix("0:") if evrs else ""
            for entry in waiting.pop(test_id, []):
                fixed = version if _is_version(version) else None
                yield dataclasses.replace(entry, fixed_version=fixed)
        # Depth 2 is an item of a section, depth 1 a section: nothing below them is needed again.
        if len(stack) in (1, 2):
            stack[-1].clear()
    for entries in waiting.values():
        yield from entries  # fixed, but Canonical names no version


class _Capped:
    """Fails instead of reading more than ``limit`` decompressed bytes."""

    def __init__(self, stream: BinaryIO, limit: int):
        self.stream, self.limit, self.total = stream, limit, 0

    def read(self, size: int = 65536) -> bytes:
        data = self.stream.read(size)
        self.total += len(data)
        if self.total > self.limit:
            raise OvalParseError(f"decompressed feed is larger than {self.limit} bytes")
        return data


def _retryable(exc: OSError) -> bool:
    if isinstance(exc, urllib.error.HTTPError):
        return exc.code in RETRYABLE_HTTP_CODES
    return True  # timeouts, refused / reset connections, DNS failures, truncated transfers


def _no_check() -> None:
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class OvalFeed:
    def __init__(
        self,
        db: Database,
        breakers: BreakerBoard | None = None,
        fetcher: Callable[[str, BinaryIO, int, float], None] | None = None,
        now: Callable[[], datetime] = _now,
        max_age: timedelta = TTL,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.db, self.fetcher, self.now, self.max_age = db, fetcher, now, max_age
        self.sleep = sleep
        self.breakers = breakers or BreakerBoard()
        self.downloads = 0

    @staticmethod
    def feed_name(codename: str) -> str:
        return f"{SOURCE}:{codename}"

    def _age(self, feed: dict | None) -> timedelta | None:
        if not feed or not feed["fetched_at"]:
            return None
        return self.now() - datetime.fromisoformat(feed["fetched_at"])

    def ensure(
        self, codename: str, blocked: str | None = None, check: Callable[[], None] = _no_check
    ) -> FeedState:
        """Make sure the stored copy of ``codename`` is current, if it can be."""
        if codename not in SUPPORTED_RELEASES.values():
            problem = f"no OVAL feed for release {codename!r}"
            return FeedState(False, problem, problem)
        feed = self.db.get_source_feed(self.feed_name(codename))
        age = self._age(feed)
        if age is not None and age < self.max_age:
            text = f"{codename}: stored copy is current (age {format_age(age)})"
            return FeedState(True, f"{text}, {feed['entries']} entries")
        url = URL.format(codename=codename)
        breaker = self.breakers.get(SOURCE, urlsplit(url).hostname or "")
        if blocked:
            return self._keep(codename, age, f"blocked ({blocked})")
        if not breaker.allow():
            return self._keep(codename, age, f"backing off ({breaker.reason})")
        fetch = self.fetcher or source_http.fetch_to_file
        with tempfile.TemporaryFile() as download:
            self.downloads += 1
            try:
                self._download(fetch, url, download, check)
            except (OSError, ValueError) as exc:
                reason = source_http.describe_error(exc)
                breaker.failure(reason)
                return self._keep(codename, age, f"download failed: {reason}")
            breaker.success()
            download.seek(0)
            try:
                count = self._store(codename, download, check)
            except (OSError, EOFError, ET.ParseError, ValueError) as exc:
                logger.warning("oval_feed codename=%s corrupt=true error=%s", codename, exc)
                return self._keep(codename, age, f"corrupt download discarded: {exc}")
        logger.info("oval_feed codename=%s stored=%d", codename, count)
        return FeedState(True, f"{codename}: downloaded, {count} entries")

    def _download(self, fetch, url: str, out: BinaryIO, check: Callable[[], None]) -> None:
        """Fetch the feed into ``out``; a network failure is retried ``DOWNLOAD_RETRIES`` times,
        waiting ``RETRY_BACKOFF_SECONDS`` and then twice as long. Bad content (ValueError) and
        a definite HTTP answer (404, 403, ...) are not retried."""
        retries = DOWNLOAD_RETRIES
        for attempt in range(retries + 1):
            out.seek(0)
            out.truncate()
            try:
                fetch(url, out, MAX_DOWNLOAD_BYTES, DOWNLOAD_TIMEOUT_SECONDS)
                return
            except OSError as exc:
                if attempt == retries or not _retryable(exc):
                    raise
                delay = RETRY_BACKOFF_SECONDS * 2**attempt
                logger.info(
                    "oval_feed url=%s attempt=%d failed (%s); retrying in %g s",
                    url, attempt + 1, source_http.describe_error(exc), delay,
                )  # fmt: skip
            check()
            self.sleep(delay)

    def _keep(self, codename: str, age: timedelta | None, reason: str) -> FeedState:
        logger.warning("oval_feed codename=%s kept_previous=%s reason=%s", codename, age, reason)
        if age is None:
            return FeedState(False, f"{codename}: no stored copy: {reason}", reason)
        text = f"{codename}: using the stored copy (age {format_age(age)}): {reason}"
        return FeedState(True, text, reason)

    def _store(self, codename: str, compressed: BinaryIO, check: Callable[[], None]) -> int:
        """Parse into a new generation; it becomes current only if the whole file parsed. Any
        failure, a cancel request included, removes what was written of it."""
        generation = self.db.next_oval_generation(codename)
        count = 0
        batch: list[tuple] = []
        try:
            with bz2.open(compressed, "rb") as xml:
                for entry in parse_oval(_Capped(xml, MAX_XML_BYTES)):
                    batch.append(dataclasses.astuple(entry))
                    count += 1
                    if len(batch) >= BATCH_ROWS:
                        check()
                        self.db.add_oval_rows(codename, generation, batch)
                        batch = []
            if not count:
                raise OvalParseError("the feed holds no CVE statement")
            self.db.add_oval_rows(codename, generation, batch)
            self.db.activate_oval_generation(codename, generation, self.now().isoformat(), count)
        except BaseException:
            self.db.discard_oval_generation(codename, generation)
            raise
        return count

    def lookup(self, cve: str, codename: str) -> CveRecord | None:
        """The stored statements of ``cve`` for this release (None: not listed)."""
        rows = self.db.oval_rows(cve, codename, self.feed_name(codename))
        if not rows:
            return None
        record = CveRecord(cve=cve, origin=SOURCE)
        for row in rows:
            record.entries.append(
                status_entry(
                    row["package"], row["fixed_version"], codename, row["status"], row["priority"]
                )
            )
        age = self._age(self.db.get_source_feed(self.feed_name(codename)))
        if age is not None and age >= self.max_age:
            record.cache_age = age
        return record

    def packages_for(self, cve: str) -> list[str]:
        """Packages any stored release lists for ``cve``: a hint for the changelog search."""
        return self.db.oval_packages(cve)
