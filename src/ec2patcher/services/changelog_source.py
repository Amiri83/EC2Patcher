"""Fallback: search the changelog.Debian.gz of a package's candidate .deb for the CVE.

For a CVE OVAL and the USNs do not answer. The Packages index of the release's pockets on
security.ubuntu.com gives the candidate .deb of the source package; the smallest binary is
fetched (size and SHA256 checked against the index) and only its changelog is read, never
installed or unpacked to disk. If the CVE is mentioned, the changelog entry that first mentions
it is the fix version.

Bounded: indexes are read once per run, a package's changelog once per run however many CVEs ask,
and requests and packages have a per-run budget. It runs in the analysis worker, never in a web
request. Package data comes over plain HTTP as for APT, but this only ever supplies a version
to compare; what gets installed still comes from the signed APT lists (local_apt).
"""

import gzip
import hashlib
import io
import logging
import re
import subprocess
import tarfile
import tempfile
import urllib.error
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import BinaryIO
from urllib.parse import urlsplit

from ec2patcher.services import debversion, source_http
from ec2patcher.services.local_apt import PORTS_MIRROR, SECURITY_MIRROR
from ec2patcher.services.source_breaker import BreakerBoard

logger = logging.getLogger(__name__)

SOURCE = "changelog"
POCKETS = ("security", "updates")
COMPONENTS = ("main", "universe")
TIMEOUT_SECONDS = 20.0
MAX_INDEX_BYTES = 64 * 1024 * 1024
MAX_DEB_BYTES = 32 * 1024 * 1024
MAX_CHANGELOG_GZ_BYTES = 4 * 1024 * 1024
MAX_CHANGELOG_BYTES = 16 * 1024 * 1024
MAX_DEBS_PER_PACKAGE = 2
MAX_PACKAGES_PER_RUN = 25
MAX_REQUESTS_PER_RUN = 60
DPKG_DEB_TIMEOUT_SECONDS = 60

_FILENAME_RE = re.compile(r"^pool/[A-Za-z0-9+._~%/-]+\.deb$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*$")
_ENTRY_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]* \(([^()\s]+)\)", re.MULTILINE)
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_WANTED_FIELDS = frozenset({"Package", "Source", "Version", "Filename", "Size", "SHA256"})


class ChangelogError(RuntimeError):
    """The changelog of a package could not be read; the message says why."""


@dataclass(frozen=True)
class DebRef:
    package: str
    version: str
    source_version: str
    filename: str
    size: int
    sha256: str


def parse_packages(stream: BinaryIO) -> dict[str, list[DebRef]]:
    """Source package -> its binaries, from a (decompressed) Packages index stream."""
    index: dict[str, list[DebRef]] = {}
    fields: dict[str, str] = {}

    def flush() -> None:
        source_field = fields.get("Source", fields.get("Package", ""))
        parts = source_field.split()
        size = fields.get("Size", "")
        if (
            parts
            and fields.get("Package")
            and fields.get("Version")
            and _FILENAME_RE.match(fields.get("Filename", ""))
            and ".." not in fields.get("Filename", "")
            and _SHA256_RE.match(fields.get("SHA256", ""))
            and size.isdigit()
        ):
            source_version = parts[1].strip("()") if len(parts) > 1 else fields["Version"]
            index.setdefault(parts[0], []).append(
                DebRef(
                    fields["Package"],
                    fields["Version"],
                    source_version,
                    fields["Filename"],
                    int(size),
                    fields["SHA256"],
                )
            )
        fields.clear()

    for raw in io.TextIOWrapper(stream, encoding="utf-8", errors="replace"):
        line = raw.rstrip("\n")
        if not line:
            flush()
        elif line[0] not in " \t":
            key, _, value = line.partition(":")
            if key in _WANTED_FIELDS:
                fields[key] = value.strip()
    flush()
    return index


def fix_versions(changelog: str) -> dict[str, str]:
    """CVE -> version of the oldest changelog entry mentioning it (entries run newest first)."""
    fixes: dict[str, str] = {}
    heads = list(_ENTRY_RE.finditer(changelog))
    for position, head in enumerate(heads):
        end = heads[position + 1].start() if position + 1 < len(heads) else len(changelog)
        version = head.group(1)
        if not debversion.is_valid_version(version):
            continue
        for cve in _CVE_RE.findall(changelog, head.end(), end):
            fixes[cve.upper()] = version
    return fixes


def _data_member(deb: BinaryIO) -> str:
    """Move ``deb`` (an ar archive) to its data.tar member; returns the member's name."""
    if deb.read(8) != b"!<arch>\n":
        raise ChangelogError("not a .deb file")
    while True:
        header = deb.read(60)
        if len(header) < 60:
            raise ChangelogError("the .deb has no data member")
        name = header[:16].decode("ascii", "replace").strip().rstrip("/")
        try:
            size = int(header[48:58].strip())
        except ValueError as exc:
            raise ChangelogError("malformed .deb") from exc
        if name.startswith("data.tar"):
            return name
        deb.seek(size + (size & 1), io.SEEK_CUR)


def _changelog_from_tar(fileobj: BinaryIO, package: str) -> bytes | None:
    """The gzipped changelog in a data.tar stream. A symlinked doc directory gives None."""
    wanted = {f"usr/share/doc/{package}/changelog.{kind}gz" for kind in ("Debian.", "")}
    with tarfile.open(fileobj=fileobj, mode="r|*") as tar:
        for member in tar:
            if member.name.removeprefix("./") in wanted and member.isfile():
                if member.size > MAX_CHANGELOG_GZ_BYTES:
                    raise ChangelogError(f"the changelog of {package} is too large")
                handle = tar.extractfile(member)
                return handle.read() if handle else None
    return None


class ChangelogSource:
    def __init__(
        self,
        breakers: BreakerBoard | None = None,
        fetcher: Callable[[str, BinaryIO, int, float], None] | None = None,
        runner: Callable = subprocess.run,
    ):
        self.breakers = breakers or BreakerBoard()
        self.fetcher, self.runner = fetcher, runner
        self.start_run()

    def start_run(self) -> None:
        self._indexes: dict[tuple[str, str, str, str], dict[str, list[DebRef]]] = {}
        self._packages: dict[tuple[str, str, str], dict[str, str] | ChangelogError] = {}
        self.requests = 0

    def find(
        self, cve: str, codename: str, architecture: str, sources: Iterable[str]
    ) -> tuple[dict[str, str], list[str]]:
        """(source package -> fix version, why packages could not be read) for one CVE."""
        fixes: dict[str, str] = {}
        errors: list[str] = []
        for source in sources:
            known = self._changelog_fixes(codename, architecture, source)
            if isinstance(known, ChangelogError):
                errors.append(f"{source}: {known}")
            elif cve in known:
                fixes[source] = known[cve]
        return fixes, errors

    def _changelog_fixes(
        self, codename: str, architecture: str, source: str
    ) -> dict[str, str] | ChangelogError:
        key = (codename, architecture, source)
        if key not in self._packages:
            if len(self._packages) >= MAX_PACKAGES_PER_RUN:
                return ChangelogError("the changelog budget of this run is used up")
            try:
                self._packages[key] = self._read_package(codename, architecture, source)
            except ChangelogError as exc:
                logger.info("changelog_source package=%s error=%s", source, exc)
                self._packages[key] = exc
        return self._packages[key]

    @staticmethod
    def _mirror(architecture: str) -> str:
        return SECURITY_MIRROR if architecture in ("amd64", "i386") else PORTS_MIRROR

    def _fetch(self, url: str, out: BinaryIO, max_bytes: int) -> None:
        """One request, under this run's budget and the endpoint's breaker."""
        if self.requests >= MAX_REQUESTS_PER_RUN:
            raise ChangelogError("the request budget of this run is used up")
        breaker = self.breakers.get(SOURCE, urlsplit(url).hostname or "")
        if not breaker.allow():
            raise ChangelogError(f"backing off ({breaker.reason})")
        self.requests += 1
        fetch = self.fetcher or source_http.fetch_to_file
        try:
            fetch(url, out, max_bytes, TIMEOUT_SECONDS)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                breaker.success()  # the host answered: this path simply does not exist
            else:
                breaker.failure(source_http.describe_error(exc))
            raise
        except OSError as exc:
            breaker.failure(source_http.describe_error(exc))
            raise
        breaker.success()

    def _index(
        self, codename: str, pocket: str, component: str, architecture: str
    ) -> dict[str, list[DebRef]]:
        key = (codename, pocket, component, architecture)
        if key in self._indexes:
            return self._indexes[key]
        url = (
            f"{self._mirror(architecture)}/dists/{codename}-{pocket}/{component}/"
            f"binary-{architecture}/Packages.gz"
        )
        with tempfile.TemporaryFile() as download:
            try:
                self._fetch(url, download, MAX_INDEX_BYTES)
            except urllib.error.HTTPError as exc:
                if exc.code != 404:
                    raise ChangelogError(f"index: {source_http.describe_error(exc)}") from exc
                index: dict[str, list[DebRef]] = {}
            except (OSError, ValueError) as exc:
                raise ChangelogError(f"index: {source_http.describe_error(exc)}") from exc
            else:
                download.seek(0)
                try:
                    with gzip.GzipFile(fileobj=download) as stream:
                        index = parse_packages(stream)
                except (OSError, EOFError) as exc:
                    raise ChangelogError(f"corrupt Packages index: {exc}") from exc
        self._indexes[key] = index
        return index

    def _candidates(self, codename: str, architecture: str, source: str) -> list[DebRef]:
        """The smallest binaries of the newest version in the first pocket that has the source."""
        for pocket in POCKETS:
            refs: list[DebRef] = []
            for component in COMPONENTS:
                refs += self._index(codename, pocket, component, architecture).get(source, [])
            usable = [r for r in refs if debversion.is_valid_version(r.source_version)]
            if not usable:
                continue
            newest = max(debversion.version_key(r.source_version) for r in usable)
            latest = [r for r in usable if debversion.version_key(r.source_version) == newest]
            small = [r for r in latest if r.size <= MAX_DEB_BYTES]
            if not small:
                raise ChangelogError("every candidate .deb is too large to fetch")
            return sorted(small, key=lambda r: (r.size, r.package))[:MAX_DEBS_PER_PACKAGE]
        raise ChangelogError(f"no candidate .deb in {codename}-{'/-'.join(POCKETS)}")

    def _read_package(self, codename: str, architecture: str, source: str) -> dict[str, str]:
        if not _PACKAGE_RE.match(source):
            raise ChangelogError("unexpected package name")
        for ref in self._candidates(codename, architecture, source):
            text = self._changelog_of(ref, architecture)
            if text is not None:
                return fix_versions(text)
        raise ChangelogError("the candidate .deb holds no changelog")

    def _changelog_of(self, ref: DebRef, architecture: str) -> str | None:
        url = f"{self._mirror(architecture)}/{ref.filename}"
        with tempfile.NamedTemporaryFile(suffix=".deb") as deb:
            try:
                self._fetch(url, deb, ref.size)
            except (OSError, ValueError) as exc:
                raise ChangelogError(f".deb: {source_http.describe_error(exc)}") from exc
            deb.flush()
            deb.seek(0)
            digest = hashlib.sha256()
            size = 0
            while chunk := deb.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
            if size != ref.size or digest.hexdigest() != ref.sha256:
                raise ChangelogError(".deb does not match the size and SHA256 of the index")
            deb.seek(0)
            raw = self._gzipped_changelog(deb, ref.package)
        if raw is None:
            return None
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
                return stream.read(MAX_CHANGELOG_BYTES).decode("utf-8", "replace")
        except (OSError, EOFError) as exc:
            raise ChangelogError(f"corrupt changelog: {exc}") from exc

    def _gzipped_changelog(self, deb, package: str) -> bytes | None:
        try:
            member = _data_member(deb)
            if not member.endswith(".zst"):
                return _changelog_from_tar(deb, package)
            # The standard library of every supported Python cannot read zstd: dpkg-deb can, and
            # the workstation has it, as it has apt-get. It only writes the tar to our file.
            with tempfile.TemporaryFile() as tar:
                result = self.runner(
                    ["dpkg-deb", "--fsys-tarfile", deb.name],
                    stdout=tar,
                    stderr=subprocess.DEVNULL,
                    timeout=DPKG_DEB_TIMEOUT_SECONDS,
                    check=False,
                )
                if result.returncode != 0:
                    raise ChangelogError(f"dpkg-deb exited with {result.returncode}")
                tar.seek(0)
                return _changelog_from_tar(tar, package)
        except (OSError, EOFError, tarfile.TarError, subprocess.SubprocessError) as exc:
            raise ChangelogError(f"unreadable .deb: {exc}") from exc
