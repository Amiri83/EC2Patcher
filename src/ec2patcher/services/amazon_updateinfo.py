"""Amazon Linux 2023 security advisories (ALAS) from the repository's ``updateinfo.xml``.

Fetched on the workstation, never on the server (like Canonical's metadata for Ubuntu): the
AL2023 ``core`` repository of one release (``releasever``, e.g. ``2023.6.20241010``, or
``latest``) and architecture is located through its public mirror list on
cdn.amazonlinux.com, then ``repodata/repomd.xml`` names the ``updateinfo`` file. Each
advisory (``<update>``) references CVEs and lists the fixed binary packages (name, epoch,
version, release, arch, source rpm).

Only advisories that reference a CVE are kept, slimmed to what the analysis needs, and cached
per repository in the application database (table ``amazon_updateinfo_cache``) with the NVD
rules: entries younger than the TTL (default 24 h, set in Settings -> Caches) are used without
a request, older entries are refreshed and used as a fallback (marked stale) when the download
fails. Failed downloads are never cached, and a cache error never fails a lookup (it falls
back to the network). Each run counts its repositories answered from the cache / live /
failed (:meth:`UpdateInfoSource.run_cache_stats`).
"""

import bz2
import gzip
import io
import json
import logging
import lzma
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET  # noqa: S405 - trusted HTTPS source; no DTDs/entities used
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.models import FROM_CACHE, FROM_LIVE, LOOKUP_FAILED, CacheStats, record_source
from ec2patcher.services import rpmversion

logger = logging.getLogger(__name__)

MIRROR_LIST_URL = "https://cdn.amazonlinux.com/al2023/core/mirrors/{releasever}/{arch}/mirror.list"
LATEST = "latest"
RELEASEVER_RE = re.compile(r"^2023\.\d+\.\d{8}$")
ARCHITECTURES = ("x86_64", "aarch64")
CACHE_MAX_AGE = timedelta(hours=24)  # default; Settings -> Caches overrides it
REQUEST_TIMEOUT_SECONDS = 60
MAX_DOWNLOAD_BYTES = 256 * 1024 * 1024
MAX_XML_BYTES = 1024 * 1024 * 1024  # decompressed updateinfo.xml
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Lookup outcomes.
OK = "ok"  # fresh data (cache or network)
STALE = "stale"  # download failed; older cached data used
FAILED = "failed"  # download failed and nothing was cached


class UpdateInfoError(Exception):
    """The repository metadata could not be downloaded or understood."""


class UpdateInfoUnreachable(UpdateInfoError):
    """Connection failure or timeout: not retried for the rest of the run."""


@dataclass(frozen=True)
class AdvisoryPackage:
    name: str
    epoch: str
    version: str
    release: str
    arch: str
    source: str  # source rpm name (the binary name when updateinfo has no src attribute)

    @property
    def evr(self) -> str:
        return rpmversion.format_evr(self.epoch, self.version, self.release)


@dataclass(frozen=True)
class Advisory:
    id: str  # e.g. ALAS2023-2024-512
    severity: str | None  # Amazon's rating: critical / important / medium / low
    issued: str | None
    cves: tuple[str, ...]
    packages: tuple[AdvisoryPackage, ...]


@dataclass
class UpdateInfo:
    """Advisories of one repository (None when unavailable) and how they were obtained."""

    repo: str  # "<releasever>/<arch>"
    status: str
    advisories: list[Advisory] | None = None
    repo_url: str | None = None
    fetched_at: str | None = None
    error: str | None = None
    from_cache: bool = False  # True when answered by a fresh cache entry (no download)
    _by_cve: dict[str, list[Advisory]] | None = field(default=None, repr=False)

    @property
    def available(self) -> bool:
        return self.advisories is not None

    def for_cve(self, cve: str) -> list[Advisory]:
        if self._by_cve is None:
            self._by_cve = {}
            for advisory in self.advisories or []:
                for ref in advisory.cves:
                    self._by_cve.setdefault(ref, []).append(advisory)
        return self._by_cve.get(cve.strip().upper(), [])


def repo_key(releasever: str, arch: str) -> str:
    return f"{releasever}/{arch}"


def check_repo(releasever: str, arch: str) -> None:
    """Only well-formed values ever reach a URL."""
    if releasever != LATEST and not RELEASEVER_RE.match(releasever or ""):
        raise UpdateInfoError(f"invalid Amazon Linux 2023 releasever {releasever!r}")
    if arch not in ARCHITECTURES:
        raise UpdateInfoError(f"unsupported architecture {arch!r}")


# --- parsing ---------------------------------------------------------------------------------


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_mirror_list(body: bytes) -> str:
    """The first HTTPS repository URL of a mirror list (with a trailing '/')."""
    for line in body.decode("utf-8", "replace").splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        if urllib.parse.urlsplit(url).scheme != "https":
            raise UpdateInfoError(f"mirror list names a non-HTTPS repository: {url[:200]}")
        return url if url.endswith("/") else url + "/"
    raise UpdateInfoError("mirror list is empty")


def parse_repomd(body: bytes) -> str:
    """Relative location of the ``updateinfo`` file named by repomd.xml."""
    try:
        root = ET.fromstring(body)  # noqa: S314 - see the import
    except ET.ParseError as exc:
        raise UpdateInfoError(f"invalid repomd.xml: {exc}") from exc
    for data in root:
        if _local(data.tag) != "data" or data.get("type") != "updateinfo":
            continue
        for child in data:
            if _local(child.tag) == "location" and child.get("href"):
                href = child.get("href")
                if href.startswith("/") or ".." in href.split("/") or "://" in href:
                    raise UpdateInfoError(f"unexpected updateinfo location {href!r}")
                return href
    raise UpdateInfoError("repomd.xml lists no updateinfo")


class _Limited(io.RawIOBase):
    """Read-only stream that fails once more than ``limit`` bytes were read."""

    def __init__(self, stream, limit: int):
        self.stream, self.limit, self.count = stream, limit, 0

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        data = self.stream.read(len(buffer))
        self.count += len(data)
        if self.count > self.limit:
            raise UpdateInfoError("updateinfo is too large")
        buffer[: len(data)] = data
        return len(data)


def open_compressed(body: bytes):
    """A stream of the decompressed file (gzip, bzip2, xz, zstd or plain; by magic bytes)."""
    raw = io.BytesIO(body)
    if body[:2] == b"\x1f\x8b":
        stream = gzip.GzipFile(fileobj=raw)
    elif body[:3] == b"BZh":
        stream = bz2.BZ2File(raw)
    elif body[:6] == b"\xfd7zXZ\x00":
        stream = lzma.LZMAFile(raw)
    elif body[:4] == b"\x28\xb5\x2f\xfd":
        try:
            from compression import zstd  # Python 3.14+
        except ImportError as exc:
            raise UpdateInfoError("updateinfo is zstd-compressed (needs Python 3.14+)") from exc
        stream = zstd.ZstdFile(raw)
    else:
        stream = raw
    return io.BufferedReader(_Limited(stream, MAX_XML_BYTES))


def _source_name(src: str | None, fallback: str) -> str:
    """'openssl-3.0.8-1.amzn2023.0.14.src.rpm' -> 'openssl'."""
    if not src:
        return fallback
    stem = src.removesuffix(".rpm").removesuffix(".src").removesuffix(".nosrc")
    parts = stem.rsplit("-", 2)
    return parts[0] if len(parts) == 3 and parts[0] else fallback


def _advisory(update: ET.Element) -> Advisory | None:
    fields: dict[str, str | None] = {"id": None, "severity": None, "issued": None}
    cves: list[str] = []
    packages: list[AdvisoryPackage] = []
    for child in update.iter():
        tag = _local(child.tag)
        if tag in ("id", "severity") and child is not update:
            fields[tag] = (child.text or "").strip() or None
        elif tag == "issued":
            fields["issued"] = child.get("date")
        elif tag == "reference" and (child.get("type") or "").lower() == "cve":
            ref = (child.get("id") or child.get("title") or "").strip().upper()
            if CVE_RE.match(ref):
                cves.append(ref)
        elif tag == "package" and child.get("name") and child.get("version"):
            packages.append(
                AdvisoryPackage(
                    name=child.get("name"),
                    epoch=child.get("epoch") or "0",
                    version=child.get("version"),
                    release=child.get("release") or "",
                    arch=child.get("arch") or "",
                    source=_source_name(child.get("src"), child.get("name")),
                )
            )
    if not fields["id"] or not cves:
        return None  # bug fix / enhancement advisories reference no CVE
    return Advisory(
        id=fields["id"],
        severity=(fields["severity"] or "").lower() or None,
        issued=fields["issued"],
        cves=tuple(dict.fromkeys(cves)),
        packages=tuple(dict.fromkeys(packages)),
    )


def parse_updateinfo(stream) -> list[Advisory]:
    """The CVE-referencing advisories of an updateinfo.xml stream (parsed incrementally)."""
    advisories = []
    try:
        for _event, element in ET.iterparse(stream, events=("end",)):  # noqa: S314
            if _local(element.tag) != "update":
                continue
            advisory = _advisory(element)
            if advisory is not None:
                advisories.append(advisory)
            element.clear()
    except (ET.ParseError, EOFError, OSError, lzma.LZMAError) as exc:
        raise UpdateInfoError(f"invalid updateinfo: {exc}") from exc
    return advisories


def to_json(advisories: list[Advisory]) -> str:
    return json.dumps(
        [
            {
                "id": a.id, "severity": a.severity, "issued": a.issued, "cves": list(a.cves),
                "packages": [
                    [p.name, p.epoch, p.version, p.release, p.arch, p.source] for p in a.packages
                ],
            }
            for a in advisories
        ],
        separators=(",", ":"),
    )  # fmt: skip


def from_json(text: str) -> list[Advisory]:
    data = json.loads(text)
    if not isinstance(data, list):
        raise ValueError("cached advisories are not a list")
    return [
        Advisory(
            id=item["id"],
            severity=item.get("severity"),
            issued=item.get("issued"),
            cves=tuple(item["cves"]),
            packages=tuple(AdvisoryPackage(*p) for p in item["packages"]),
        )
        for item in data
    ]


# --- HTTP ------------------------------------------------------------------------------------

# (url, timeout) -> response body. Raises UpdateInfoError for HTTP errors and OSError /
# TimeoutError for connection problems.
Transport = Callable[[str, float], bytes]


def http_get(url: str, timeout: float) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "ec2patcher"})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read(MAX_DOWNLOAD_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise UpdateInfoError(f"HTTP {exc.code} for {url}") from exc
    if len(body) > MAX_DOWNLOAD_BYTES:
        raise UpdateInfoError(f"download too large: {url}")
    return body


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


class UpdateInfoSource:
    """Advisories per (releasever, arch) with a persistent cache. Not thread-safe; analysis
    runs are serialized. Call :meth:`start_run` at the start of each analysis run."""

    def __init__(
        self,
        cache_db: Database | Path | None = None,
        transport: Transport | None = None,
        now: Callable[[], datetime] = _now,
        max_age: timedelta = CACHE_MAX_AGE,
    ):
        if isinstance(cache_db, Database):
            self._db: Database | None = cache_db
            self.cache_db_path = cache_db.path
        else:
            self._db = None
            self.cache_db_path = (
                Path(cache_db) if cache_db else config.get_data_dir() / config.DB_FILENAME
            )
        self.transport = transport
        self.now, self.max_age = now, max_age
        self.requests = 0  # HTTP requests sent (for diagnostics/tests)
        self.start_run()

    def start_run(self, force_refresh: bool = False) -> None:
        """Forget per-run state (memo, unreachable breaker); ``force_refresh`` downloads every
        repository again once in this run even if the cache is fresh."""
        self._memo: dict[str, UpdateInfo] = {}
        self._unreachable: str | None = None
        self._force = force_refresh
        self._sources: dict[str, str] = {}  # repository -> cache / live / failed, this run

    def run_cache_stats(self) -> CacheStats:
        """Repositories since :meth:`start_run`: from cache (fresh or stale) / live / failed."""
        return CacheStats.from_sources(self._sources)

    # --- cache -------------------------------------------------------------------------

    def _cache(self) -> Database:
        if self._db is None:
            self._db = Database(self.cache_db_path)
        return self._db

    def _read_cache(self, key: str) -> dict | None:
        try:
            entry = self._cache().get_updateinfo_cache(key)
            if entry is None:
                return None
            advisories, repo_url, fetched_at = entry
            return {
                "advisories": from_json(advisories),
                "repo_url": repo_url,
                "fetched": datetime.fromisoformat(fetched_at),
                "fetched_at": fetched_at,
            }
        except Exception as exc:  # noqa: BLE001 - a cache problem must never fail a lookup
            logger.warning("Ignoring unreadable updateinfo cache entry for %s: %s", key, exc)
            return None

    def _write_cache(self, key: str, advisories: list[Advisory], repo_url: str) -> str:
        fetched_at = self.now().isoformat()
        try:
            self._cache().put_updateinfo_cache(key, to_json(advisories), repo_url, fetched_at)
        except Exception as exc:  # noqa: BLE001 - the fetched data is still returned
            logger.warning("Could not write updateinfo cache entry for %s: %s", key, exc)
        return fetched_at

    def clear(self) -> bool:
        """Forget the memo and the ``amazon_updateinfo_cache`` table. True if anything was
        removed."""
        had_entries = bool(self._memo)
        self.start_run()
        try:
            had_entries = self._cache().clear_updateinfo_cache() > 0 or had_entries
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not clear the updateinfo cache: %s", exc)
        return had_entries

    # --- network -----------------------------------------------------------------------

    def _get(self, url: str) -> bytes:
        self.requests += 1
        transport = self.transport or http_get  # resolved late so tests can disable it
        try:
            return transport(url, REQUEST_TIMEOUT_SECONDS)
        except (OSError, TimeoutError) as exc:  # URLError is an OSError
            raise UpdateInfoUnreachable(f"cdn.amazonlinux.com unreachable: {exc}") from exc

    def fetch(self, releasever: str, arch: str) -> tuple[list[Advisory], str]:
        """Download and parse the advisories of one repository: (advisories, repo URL)."""
        check_repo(releasever, arch)
        mirror = MIRROR_LIST_URL.format(releasever=releasever, arch=arch)
        base = parse_mirror_list(self._get(mirror))
        href = parse_repomd(self._get(urllib.parse.urljoin(base, "repodata/repomd.xml")))
        body = self._get(urllib.parse.urljoin(base, href))
        return parse_updateinfo(open_compressed(body)), base

    # --- lookup ------------------------------------------------------------------------

    def lookup(self, releasever: str, arch: str) -> UpdateInfo:
        """Advisories of one repository. Never raises; one download per repository per run."""
        key = repo_key(releasever, arch)
        if key not in self._memo:
            try:
                self._memo[key] = self._lookup(releasever, arch, key)
            except Exception as exc:  # noqa: BLE001 - one repository must not break analysis
                logger.exception("updateinfo lookup for %s failed unexpectedly", key)
                self._memo[key] = UpdateInfo(key, FAILED, error=str(exc))
            status = self._memo[key].status
            source = {OK: FROM_LIVE, STALE: FROM_CACHE}.get(status, LOOKUP_FAILED)
            if status == OK and self._memo[key].from_cache:
                source = FROM_CACHE
            record_source(self._sources, key, source)
        return self._memo[key]

    def _lookup(self, releasever: str, arch: str, key: str) -> UpdateInfo:
        cached = self._read_cache(key)
        if cached and not self._force and self.now() - cached["fetched"] < self.max_age:
            return UpdateInfo(
                key, OK, cached["advisories"], cached["repo_url"], cached["fetched_at"],
                from_cache=True,
            )  # fmt: skip
        error = self._unreachable
        if error is None:
            try:
                advisories, repo_url = self.fetch(releasever, arch)
            except UpdateInfoError as exc:
                error = str(exc)
                logger.warning("updateinfo download for %s failed: %s", key, error)
                if isinstance(exc, UpdateInfoUnreachable):
                    self._unreachable = error  # don't wait for a timeout on every repository
            else:
                fetched_at = self._write_cache(key, advisories, repo_url)
                return UpdateInfo(key, OK, advisories, repo_url, fetched_at)
        if cached:
            return UpdateInfo(
                key, STALE, cached["advisories"], cached["repo_url"], cached["fetched_at"],
                error=error,
            )  # fmt: skip
        return UpdateInfo(key, FAILED, error=error)
