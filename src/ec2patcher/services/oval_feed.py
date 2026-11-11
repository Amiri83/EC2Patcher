"""Canonical's OVAL CVE feed: one file per Ubuntu release, stored in SQLite.

The primary source of the resolver. ``com.ubuntu.<codename>.cve.oval.xml.bz2`` is downloaded at
most once per TTL to a temporary file, decompressed as a stream and parsed with ``iterparse``,
elements being discarded as they are read. After that CVE -> package -> status / fixed version
is answered locally, without a request per CVE.

Rows are written in batches under a new generation that only becomes current once the whole
file parsed: a truncated or corrupt download is discarded and the previous copy stays in use.

Criterion comments come in several wordings (all accepted, see ``_classify``)::

    openssl package in noble was vulnerable but has been fixed (note: '3.0.13-0ubuntu3.6').
    openssl source package in noble, was vulnerable but has been fixed (note: '...').
    example-package source package in esm-apps/noble, is affected and has been fixed (...).
    'linux-aws' kernel in noble is affected and has been fixed (note: '6.8.0-1015.16').

``Is kernel 'linux-aws' running?`` only says when a kernel definition applies and is skipped.
An Ubuntu Pro pocket (``esm-apps/``, ``esm-infra/``) is kept in the stored note as
``pocket:<name>``; a statement for the release itself wins over one for its Pro pocket. If fewer
than half of the vulnerability definitions hold a recognised statement the wording has changed:
the download is discarded as "OVAL format not recognised (parser out of date)".
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
from ec2patcher.services.security_metadata import (
    PRO_PREFIXES,
    CveRecord,
    format_age,
    status_entry,
)
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

MIN_PARSED_SHARE = 0.5  # of the vulnerability definitions; below it the wording is unknown
FORMAT_UNRECOGNISED = "OVAL format not recognised (parser out of date)"

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_PACKAGE = r"[a-z0-9][a-z0-9+.-]*"
_RELEASE = r"(?:(?P<pocket>esm-[a-z-]+)/)?(?P<codename>[a-z]+)\b"
# "<pkg> source package in [esm-apps/]<codename>, <status>" (the current feed)
_SOURCE_PACKAGE_RE = re.compile(
    rf"^(?:\(CVE-[\d-]+\)\s*)?(?P<package>{_PACKAGE})\s+source\s+package\s+in\s+{_RELEASE}"
    r",?\s*(?P<rest>.*)$",
    re.DOTALL,
)
# "'<kernel source>' kernel in [esm-infra/]<codename> <status>"
_KERNEL_RE = re.compile(
    rf"^['\"](?P<package>{_PACKAGE})['\"]\s+kernel\s+in\s+{_RELEASE},?\s*(?P<rest>.*)$",
    re.DOTALL,
)
# The older wording: "<pkg> package in <codename> <status>", "<pkg>: <status>"
_COMMENT_RE = re.compile(
    rf"^(?:\(CVE-[\d-]+\)\s*)?(?P<package>{_PACKAGE})(?P<rest>\s+package\b.*|:\s.*)$",
    re.DOTALL,
)
_APPLICABILITY_RE = re.compile(r"^is\s+kernel\b.*\brunning\b", re.IGNORECASE)
_NOTE_RE = re.compile(r"\(note: '(?P<note>.*)'\)\.?\s*$", re.DOTALL)
_TITLE_PRIORITY_RE = re.compile(r" - (\w+)\.?\s*$")
POCKET_PREFIX = "pocket:"
# The wording of Canonical's criterion comments, first match wins (the note is not searched).
# None: a recognised comment that makes no statement. "has been fixed" must come before the
# generic phrases: "is affected and has been fixed" is a fix, not "affected".
_STATUS_PHRASES = (
    ("does not exist", None),
    ("decision has been made to ignore", "ignored"),
    ("is not affected", "not-affected"),
    ("was vulnerable but has been fixed", "released"),
    ("is affected and has been fixed", "released"),
    ("has been fixed", "released"),
    ("pending publication", "pending"),
    ("defer", "deferred"),
    ("might be affected and may need fixing", "needs-triage"),
    ("may need fixing", "needs-triage"),
    ("needs fixing", "needed"),
    ("affected", "needed"),
)
_UNKNOWN_PHRASE = object()


class OvalParseError(ValueError):
    """The feed is not usable: nothing in it could be stored."""


class OvalFormatError(OvalParseError):
    """The feed downloaded fine but its wording is not understood: the parser is out of date."""


@dataclass(frozen=True)
class OvalEntry:
    cve: str
    package: str  # source package
    status: str  # Canonical's: released, not-affected, needed, needs-triage, pending, ...
    fixed_version: str | None = None  # released: the fix; pending: the version to be published
    note: str | None = None
    priority: str | None = None


_Pairs = list[tuple[OvalEntry, str | None]]  # (entry, test reference) of one definition


@dataclass(frozen=True)
class FeedState:
    usable: bool  # a copy can be read, however old
    message: str
    problem: str | None = None  # why it could not be brought up to date


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


@dataclass(frozen=True)
class _Statement:
    package: str
    status: str | None  # None: recognised, but no statement (the package does not exist)
    note: str | None
    pocket: str | None  # esm-apps / esm-infra; None: the release itself


def _classify(comment: str) -> _Statement | None:
    """The package statement of one criterion comment; None if the comment is not one (an
    applicability check such as "Is kernel 'linux-aws' running?") or its wording is unknown."""
    text = " ".join(comment.split())
    if not text or _APPLICABILITY_RE.match(text):
        return None
    match = _SOURCE_PACKAGE_RE.match(text) or _KERNEL_RE.match(text) or _COMMENT_RE.match(text)
    if not match:
        return None
    groups = match.groupdict()
    rest = match.group("rest")
    note = _NOTE_RE.search(rest)
    wording = (rest[: note.start()] if note else rest).lower()
    status = next((s for phrase, s in _STATUS_PHRASES if phrase in wording), _UNKNOWN_PHRASE)
    if status is _UNKNOWN_PHRASE:
        return None
    return _Statement(
        package=match.group("package"),
        status=status,
        note=note.group("note").strip() if note else None,
        pocket=groups.get("pocket"),
    )


def _stored_note(note: str | None, pocket: str | None) -> str | None:
    """The note column: Canonical's note, prefixed with the Pro pocket of the statement."""
    if pocket:
        note = f"{POCKET_PREFIX}{pocket}; {note}" if note else f"{POCKET_PREFIX}{pocket}"
    return note[:MAX_NOTE_CHARS] if note else None


def stored_pocket(note: str | None) -> str | None:
    """The Pro pocket recorded by :func:`_stored_note`; None for the release itself."""
    if not note or not note.startswith(POCKET_PREFIX):
        return None
    return note[len(POCKET_PREFIX) :].split(";", 1)[0].strip() or None


def _definition_entries(definition: ET.Element) -> tuple[_Pairs, bool]:
    """The (entry, test reference) pairs of one CVE definition, and whether any criterion in it
    was a recognised package statement (for the format check of :func:`parse_oval`)."""
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
    statements = [(_classify(comment), test_ref) for comment, test_ref in criteria]
    recognised = any(statement is not None for statement, _ in statements)
    if not cve:
        return [], recognised
    if priority is None:
        found = _TITLE_PRIORITY_RE.search(title or "")
        priority = found.group(1) if found else None
    entries: dict[str, tuple[OvalEntry, str | None, str | None]] = {}
    for statement, test_ref in statements:
        if statement is None or statement.status is None:
            continue
        status, note = statement.status, statement.note
        # A fix pending publication keeps its version too (cve_resolver: opt-in candidate check).
        version = note if status in ("released", "pending") and _is_version(note) else None
        entry = OvalEntry(
            cve=cve.upper(),
            package=statement.package,
            status=status,
            fixed_version=version,
            note=_stored_note(note, statement.pocket),
            priority=priority,
        )
        current = entries.get(statement.package)
        # First statement per package wins, except that the release beats its Pro pocket.
        if current is None or (current[2] and not statement.pocket):
            entries[statement.package] = (entry, test_ref, statement.pocket)
    return [(entry, test_ref) for entry, test_ref, _ in entries.values()], recognised


def _is_version(text: str | None) -> bool:
    return bool(text) and debversion.is_valid_version(text)


def parse_oval(stream) -> Iterator[OvalEntry]:
    """The CVE statements of an OVAL XML stream. Parsed elements are discarded as it goes.

    The fixed version normally comes with the criterion's comment; a fixed package without one
    takes it from the ``dpkginfo_state`` its test points to, later in the file. Raises
    :class:`OvalFormatError` at the end if fewer than ``MIN_PARSED_SHARE`` of the vulnerability
    definitions held a recognised statement (Canonical changed the wording)."""
    waiting: dict[str, list[OvalEntry]] = {}  # test id -> entries that need its version
    state_tests: dict[str, str] = {}  # state id -> test id
    stack: list[ET.Element] = []
    definitions = parsed = 0
    for event, element in ET.iterparse(stream, events=("start", "end")):  # noqa: S314 - see import
        if event == "start":
            stack.append(element)
            continue
        stack.pop()
        name = _local(element.tag)
        if name == "definition" and element.get("class", "vulnerability") == "vulnerability":
            pairs, recognised = _definition_entries(element)
            definitions += 1
            parsed += recognised
            for entry, test_ref in pairs:
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
    if definitions and parsed < definitions * MIN_PARSED_SHARE:
        raise OvalFormatError(
            f"{FORMAT_UNRECOGNISED}: {parsed} of {definitions} vulnerability definitions parsed"
        )


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
            except OvalFormatError as exc:  # the download is fine; the parser is not
                logger.error("oval_feed codename=%s format_unrecognised=true %s", codename, exc)
                return self._keep(codename, age, str(exc))
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
            pocket = stored_pocket(row["note"])
            if pocket and pocket not in PRO_PREFIXES:
                pocket = "esm-apps"  # an unknown esm-* pocket is still Ubuntu Pro, never standard
            distro = f"{pocket}/{codename}" if pocket else codename  # esm-apps/noble: Ubuntu Pro
            record.entries.append(
                status_entry(
                    row["package"], row["fixed_version"], distro, row["status"], row["priority"]
                )
            )
        age = self._age(self.db.get_source_feed(self.feed_name(codename)))
        if age is not None and age >= self.max_age:
            record.cache_age = age
        return record

    def packages_for(self, cve: str) -> list[str]:
        """Packages any stored release lists for ``cve``: a hint for the changelog search."""
        return self.db.oval_packages(cve)
