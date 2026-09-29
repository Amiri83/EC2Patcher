"""Canonical Ubuntu security metadata (OpenVEX) - download, local index and lookup.

Source: https://security-metadata.canonical.com/vex/vex-all.tar.xz (one OpenVEX JSON document
per CVE under ``vex/cve/<year>/``). The archive is ~70 MB compressed but ~26 GB uncompressed,
so it is never extracted: it is streamed once per refresh and reduced to a small SQLite index
holding, per CVE, the Ubuntu *source* package statements for the releases EC2Patcher supports
(plus their Ubuntu Pro / ESM pockets). Analyses query that index locally.

Each VEX product is a purl such as
``pkg:deb/ubuntu/openssh@1:9.6p1-3ubuntu13.5?arch=source&distro=noble``. Only ``arch=source``
products are used: Ubuntu tracks vulnerabilities per source package; the server's dpkg data
maps installed binary packages to their source package.
"""

import json
import logging
import os
import re
import sqlite3
import tarfile
import threading
import urllib.error
import urllib.request
import zlib
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import unquote

from platformdirs import user_cache_dir

from ec2patcher.services.server_state import SUPPORTED_RELEASES

logger = logging.getLogger(__name__)

VEX_URL = "https://security-metadata.canonical.com/vex/vex-all.tar.xz"
SOURCE_LABEL = "Canonical Ubuntu OpenVEX (security-metadata.canonical.com)"
ARCHIVE_NAME = "vex-all.tar.xz"
INDEX_NAME = "ubuntu-vex-index.sqlite"
INDEX_FORMAT = 1
DOWNLOAD_TIMEOUT_SECONDS = 60  # per network operation (connect / each read)
MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
MAX_AGE_HOURS = 24  # try to refresh when the last successful check is older than this
MAX_DOCUMENT_BYTES = 64 * 1024 * 1024

CVE_MEMBER_RE = re.compile(r"(?:^|/)cve/\d{4}/(CVE-\d{4}-\d{4,})\.json$")
PURL_RE = re.compile(r"^pkg:deb/ubuntu/([^@?#]+)@([^?#]+)\?(.*)$")
PRIORITY_RE = re.compile(r"classified this CVE as of (\w+) priority", re.IGNORECASE)

# Standard archive pockets are identified by the bare codename; these prefixes (or the
# legacy "<codename>/esm" form) are Ubuntu Pro / ESM pockets. Other variants (fips*,
# realtime, bluefield, ...) are specialised products and are ignored.
PRO_PREFIXES = ("esm-infra", "esm-apps", "esm-infra-legacy", "esm-apps-legacy")


def default_cache_dir() -> Path:
    override = os.environ.get("EC2PATCHER_CACHE_DIR")
    base = Path(override).expanduser() if override else Path(user_cache_dir("ec2patcher"))
    return base / "security-metadata"


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def classify_distro(distro: str) -> tuple[str, bool] | None:
    """Map a VEX distro to (codename, is_pro), or None if not relevant."""
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
    """One Canonical statement about one source package in one release/pocket."""

    source: str
    version: str
    distro: str
    status: str  # fixed | not_affected | affected | under_investigation
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
        m = PRIORITY_RE.search(self.note or "")
        return m.group(1).capitalize() if m else None


@dataclass
class CveRecord:
    cve: str
    timestamp: str = ""
    description: str = ""
    entries: list[VexEntry] = field(default_factory=list)

    def for_release(self, codename: str) -> list[VexEntry]:
        return [e for e in self.entries if e.codename == codename]

    def sources(self) -> set[str]:
        return {e.source for e in self.entries}


def parse_purl(purl: str) -> tuple[str, str, dict[str, str]] | None:
    m = PURL_RE.match(purl or "")
    if not m:
        return None
    name, version, query = m.groups()
    qualifiers = {}
    for part in query.split("&"):
        key, _, value = part.partition("=")
        qualifiers[key] = unquote(value)
    return unquote(name), unquote(version), qualifiers


def _note(statement: dict) -> str:
    text = " ".join(
        str(statement.get(k) or "").strip()
        for k in ("status_notes", "action_statement")
        if statement.get(k)
    )
    return text[:500]


def parse_vex_document(doc: dict, keep_all_distros: bool = False) -> CveRecord | None:
    """Reduce one OpenVEX document to source-package entries for supported releases."""
    statements = doc.get("statements")
    if not isinstance(statements, list) or not statements:
        return None
    # A few documents wrap the header fields in a "metadata" object.
    header = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else doc
    record = None
    seen: set[tuple] = set()
    for statement in statements:
        if not isinstance(statement, dict):
            continue
        vuln = statement.get("vulnerability") or {}
        name = str(vuln.get("name") or "").strip().upper()
        if record is None:
            if not name.startswith("CVE-"):
                return None
            record = CveRecord(
                cve=name,
                timestamp=str(header.get("timestamp") or statement.get("timestamp") or ""),
                description=str(vuln.get("description") or "")[:1000],
            )
        status = str(statement.get("status") or "")
        for product in statement.get("products") or []:
            pid = product.get("@id") if isinstance(product, dict) else product
            if not isinstance(pid, str) or "arch=source" not in pid:
                continue  # binary products vastly outnumber source ones; skip them cheaply
            parsed = parse_purl(pid)
            if parsed is None:
                continue
            pkg, version, qualifiers = parsed
            if qualifiers.get("arch") != "source":
                continue
            distro = qualifiers.get("distro", "")
            if not keep_all_distros and classify_distro(distro) is None:
                continue
            key = (pkg, version, distro, status)
            if key in seen:
                continue
            seen.add(key)
            record.entries.append(
                VexEntry(
                    source=pkg,
                    version=version,
                    distro=distro,
                    status=status,
                    justification=str(statement.get("justification") or ""),
                    note=_note(statement),
                )
            )
    return record


def _encode(record: CveRecord) -> bytes:
    rows = [
        [e.source, e.version, e.distro, e.status, e.justification, e.note] for e in record.entries
    ]
    payload = {"t": record.timestamp, "d": record.description, "e": rows}
    return zlib.compress(json.dumps(payload, separators=(",", ":")).encode(), 6)


def _decode(cve: str, blob: bytes) -> CveRecord:
    data = json.loads(zlib.decompress(blob))
    entries = [VexEntry(*row) for row in data["e"]]
    return CveRecord(
        cve=cve, timestamp=data.get("t", ""), description=data.get("d", ""), entries=entries
    )


def build_index(
    archive: Path,
    index_path: Path,
    info: dict[str, str],
    progress: Callable[[int], None] | None = None,
) -> int:
    """Stream the archive and write a fresh index file. Returns the number of CVEs indexed."""
    tmp = index_path.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)
    count = 0
    newest = ""
    conn = sqlite3.connect(tmp)
    try:
        conn.executescript(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE cve (id TEXT PRIMARY KEY, data BLOB NOT NULL);"
        )
        with tarfile.open(archive, mode="r:xz") as tar:
            for member in tar:
                if not member.isfile() or not CVE_MEMBER_RE.search(member.name):
                    continue
                if member.size > MAX_DOCUMENT_BYTES:
                    logger.warning("Skipping oversized VEX document %s", member.name)
                    continue
                handle = tar.extractfile(member)
                if handle is None:
                    continue
                try:
                    record = parse_vex_document(json.loads(handle.read()))
                except (ValueError, TypeError, AttributeError):
                    logger.warning("Skipping unreadable VEX document %s", member.name)
                    continue
                if record is None:
                    continue
                conn.execute(
                    "INSERT OR REPLACE INTO cve (id, data) VALUES (?, ?)",
                    (record.cve, _encode(record)),
                )
                newest = max(newest, record.timestamp)
                count += 1
                if progress and count % 2000 == 0:
                    progress(count)
        if count == 0:
            raise ValueError("The archive did not contain any CVE documents.")
        meta = dict(info)
        meta.update(
            format=str(INDEX_FORMAT),
            cve_count=str(count),
            newest_document=newest,
            indexed_at=_now().isoformat(),
        )
        conn.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", list(meta.items()))
        conn.commit()
    except BaseException:
        conn.close()
        tmp.unlink(missing_ok=True)
        raise
    conn.close()
    os.replace(tmp, index_path)
    return count


@dataclass
class MetadataStatus:
    """What the analyzer tells the user about the metadata it used."""

    available: bool
    source: str = SOURCE_LABEL
    url: str = VEX_URL
    last_modified: str | None = None  # publication time reported by Canonical's server
    downloaded_at: str | None = None
    checked_at: str | None = None
    indexed_at: str | None = None
    newest_document: str | None = None
    cve_count: int = 0
    stale: bool = False
    warning: str | None = None
    error: str | None = None

    @property
    def updated_label(self) -> str:
        return self.last_modified or self.newest_document or self.downloaded_at or "unknown"


Fetcher = Callable[[str, Path, dict[str, str]], dict[str, str] | None]


def http_fetch(url: str, dest: Path, headers: dict[str, str]) -> dict[str, str] | None:
    """Download ``url`` to ``dest``. Returns response metadata, or None if not modified (304)."""
    request = urllib.request.Request(url, headers={"User-Agent": "ec2patcher", **headers})  # noqa: S310 - fixed https URL
    try:
        response = urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT_SECONDS)  # noqa: S310
    except urllib.error.HTTPError as exc:
        if exc.code == 304:
            return None
        raise
    with response:
        length = int(response.headers.get("Content-Length") or 0)
        if length > MAX_ARCHIVE_BYTES:
            raise ValueError("The metadata archive is unexpectedly large.")
        total = 0
        with open(dest, "wb") as out:
            while chunk := response.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise ValueError("The metadata archive is unexpectedly large.")
                out.write(chunk)
        return {
            "last_modified": response.headers.get("Last-Modified") or "",
            "etag": response.headers.get("ETag") or "",
        }


class SecurityMetadata:
    """Local cache of Canonical's VEX data with refresh + stale-data handling."""

    def __init__(
        self,
        cache_dir: Path | None = None,
        fetcher: Fetcher = http_fetch,
        url: str = VEX_URL,
        max_age: timedelta = timedelta(hours=MAX_AGE_HOURS),
    ):
        self.cache_dir = Path(cache_dir) if cache_dir else default_cache_dir()
        self.fetcher = fetcher
        self.url = url
        self.max_age = max_age
        self._lock = threading.Lock()
        self._last_error: str | None = None

    @property
    def index_path(self) -> Path:
        return self.cache_dir / INDEX_NAME

    @property
    def archive_path(self) -> Path:
        return self.cache_dir / ARCHIVE_NAME

    def clear(self) -> bool:
        """Remove the persistent security metadata cache."""
        with self._lock:
            removed = False
            for path in (
                self.index_path,
                self.archive_path,
                self.archive_path.with_suffix(".part"),
            ):
                if path.exists():
                    path.unlink()
                    removed = True
            self._last_error = None
            return removed

    # --- index access ------------------------------------------------------------

    def _meta(self) -> dict[str, str]:
        if not self.index_path.exists():
            return {}
        try:
            conn = sqlite3.connect(f"file:{self.index_path}?mode=ro", uri=True)
            try:
                return dict(conn.execute("SELECT key, value FROM meta").fetchall())
            finally:
                conn.close()
        except sqlite3.Error:
            logger.exception("Security metadata index is unreadable")
            return {}

    def _set_meta(self, values: dict[str, str]) -> None:
        conn = sqlite3.connect(self.index_path)
        try:
            with conn:
                conn.executemany("INSERT OR REPLACE INTO meta VALUES (?, ?)", list(values.items()))
        finally:
            conn.close()

    def lookup(self, cve: str) -> CveRecord | None:
        conn = sqlite3.connect(f"file:{self.index_path}?mode=ro", uri=True)
        try:
            row = conn.execute("SELECT data FROM cve WHERE id = ?", (cve.upper(),)).fetchone()
        finally:
            conn.close()
        return _decode(cve.upper(), row[0]) if row else None

    def status(self) -> MetadataStatus:
        meta = self._meta()
        usable = bool(meta) and meta.get("format") == str(INDEX_FORMAT)
        result = MetadataStatus(
            available=usable,
            url=meta.get("url", self.url),
            last_modified=meta.get("last_modified") or None,
            downloaded_at=meta.get("downloaded_at") or None,
            checked_at=meta.get("checked_at") or None,
            indexed_at=meta.get("indexed_at") or None,
            newest_document=meta.get("newest_document") or None,
            cve_count=int(meta.get("cve_count") or 0),
        )
        if not usable:
            result.error = (
                self._last_error or "No Canonical security metadata has been downloaded yet."
            )
            return result
        checked = result.checked_at or result.downloaded_at
        try:
            age = _now() - datetime.fromisoformat(checked) if checked else None
        except ValueError:
            age = None
        if self._last_error or age is None or age > self.max_age:
            result.stale = True
            when = checked or "an unknown time"
            reason = f" The latest refresh failed: {self._last_error}" if self._last_error else ""
            result.warning = (
                f"STALE DATA: using cached Canonical security metadata last confirmed current at "
                f"{when}.{reason}"
            )
        return result

    # --- refresh ----------------------------------------------------------------

    def needs_refresh(self) -> bool:
        st = self.status()
        if not st.available:
            return True
        checked = st.checked_at or st.downloaded_at
        try:
            return _now() - datetime.fromisoformat(checked) >= self.max_age
        except (TypeError, ValueError):
            return True

    def ensure_fresh(self, progress: Callable[[str], None] | None = None) -> MetadataStatus:
        """Refresh if too old; fall back to the cached index (flagged stale) on failure."""
        if self.needs_refresh():
            self.refresh(progress)
        return self.status()

    def refresh(self, progress: Callable[[str], None] | None = None) -> None:
        """Download (conditionally) and re-index. Errors are recorded, not raised."""
        with self._lock:
            say = progress or (lambda _msg: None)
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            meta = self._meta()
            headers = {}
            have_index = bool(meta) and meta.get("format") == str(INDEX_FORMAT)
            if have_index and self.archive_path.exists():
                if meta.get("etag"):
                    headers["If-None-Match"] = meta["etag"]
                if meta.get("last_modified"):
                    headers["If-Modified-Since"] = meta["last_modified"]
            part = self.archive_path.with_suffix(".part")
            try:
                say("Downloading Canonical security metadata")
                logger.info("Checking Canonical security metadata: %s", self.url)
                response = self.fetcher(self.url, part, headers)
                now = _now().isoformat()
                if response is None:
                    logger.info("Canonical security metadata not modified")
                    self._set_meta({"checked_at": now})
                    self._last_error = None
                    return
                os.replace(part, self.archive_path)
                say("Indexing Canonical security metadata (this can take several minutes)")
                info = {
                    "url": self.url,
                    "last_modified": response.get("last_modified", ""),
                    "etag": response.get("etag", ""),
                    "downloaded_at": now,
                    "checked_at": now,
                }
                count = build_index(
                    self.archive_path,
                    self.index_path,
                    info,
                    progress=lambda n: say(f"Indexing Canonical security metadata: {n:,} CVEs"),
                )
                logger.info("Canonical security metadata indexed: %d CVEs", count)
                self._last_error = None
            except (OSError, ValueError, tarfile.TarError, sqlite3.Error, EOFError) as exc:
                part.unlink(missing_ok=True)
                self._last_error = _describe_error(exc)
                logger.warning("Canonical security metadata refresh failed: %s", self._last_error)


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, urllib.error.HTTPError):
        return f"HTTP {exc.code} from the metadata server."
    if isinstance(exc, urllib.error.URLError):
        return f"Network error: {exc.reason}"
    if isinstance(exc, TimeoutError):
        return "The download timed out."
    if isinstance(exc, (tarfile.TarError, EOFError)):
        return "The downloaded archive is corrupt or incomplete."
    return str(exc)[:300] or type(exc).__name__
