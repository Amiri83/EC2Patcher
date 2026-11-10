"""Settings -> APT Repositories: the Ubuntu archive mirrors this workstation reads.

Corporate networks often only reach an internal APT proxy mirror (e.g. Nexus) and block
Canonical's hosts. The archive, security and ports mirror URLs (each may contain the only
placeholder ``${codename}``) and the keyring of the private APT state can be set here; an empty
field keeps Canonical's default. With nothing saved every URL, path and command is exactly the
one used without this setting (``DEFAULT``).

Saved as one JSON value (``apt_repos``) in the settings table. The resolved URLs feed:

- local_apt: the private sources.list (release, -updates and -security pockets);
- changelog_source and the changelog probe (cve_sources), when "use mirrors for changelog" is on;
- the opt-in fallbacks of cve_resolver (``allow_unconfirmed_candidates`` for CVEs without
  Canonical metadata, ``allow_pending_candidates`` for fixes still pending publication). Both are
  off by default, and a finding they produce is never patched without an explicit confirmation.

Every URL is validated (http/https, no credentials, no query string, no whitespace or quotes,
no placeholder but ``${codename}``) on save and again on load.
"""

import io
import json
import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass
from typing import BinaryIO
from urllib.parse import urlsplit

from ec2patcher.database import Database
from ec2patcher.services import source_http
from ec2patcher.services.local_apt import (
    ARCHIVE_ARCHITECTURES,
    ARCHIVE_MIRROR,
    KEYRING,
    PORTS_MIRROR,
    SECURITY_MIRROR,
    pockets,
    sources_list,
)
from ec2patcher.services.server_state import SUPPORTED_RELEASES

logger = logging.getLogger(__name__)

SETTING = "apt_repos"
PLACEHOLDER = "${codename}"
MAX_URL_CHARS = 512
MAX_PATH_CHARS = 1024
ARCHITECTURES = ("amd64", "arm64")  # the preview / Test choices: archive vs. ports mirrors
DEFAULT_RELEASE = "noble"
DEFAULT_ARCHITECTURE = "amd64"
TEST_TIMEOUT_SECONDS = 10.0
MAX_INRELEASE_BYTES = 16 * 1024 * 1024

# Form fields (and keys of the saved JSON).
ARCHIVE = "archive_mirror"
SECURITY = "security_mirror"
PORTS = "ports_mirror"
KEYRING_FIELD = "keyring"
MIRROR_CHANGELOG = "mirror_changelog"
ALLOW_UNCONFIRMED = "allow_unconfirmed_candidates"
ALLOW_PENDING = "allow_pending_candidates"
URL_FIELDS = (ARCHIVE, SECURITY, PORTS)
TEXT_FIELDS = (*URL_FIELDS, KEYRING_FIELD)
FLAG_FIELDS = (MIRROR_CHANGELOG, ALLOW_UNCONFIRMED, ALLOW_PENDING)
LABELS = {
    ARCHIVE: "Archive mirror URL",
    SECURITY: "Security mirror URL",
    PORTS: "Ports mirror URL",
    KEYRING_FIELD: "Keyring path",
}
_QUOTES = "\"'`"
_PATH_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-/")


@dataclass(frozen=True)
class AptRepos:
    archive_mirror: str = ARCHIVE_MIRROR
    security_mirror: str = SECURITY_MIRROR
    ports_mirror: str = PORTS_MIRROR
    keyring: str = KEYRING
    mirror_changelog: bool = False
    allow_unconfirmed_candidates: bool = False
    allow_pending_candidates: bool = False

    @staticmethod
    def resolve(template: str, codename: str) -> str:
        return template.replace(PLACEHOLDER, codename)

    def mirrors(self, codename: str, architecture: str) -> list[str]:
        """The mirror of each pocket (release, -updates, -security) of one architecture."""
        if architecture in ARCHIVE_ARCHITECTURES:
            archive = self.resolve(self.archive_mirror, codename)
            return [archive, archive, self.resolve(self.security_mirror, codename)]
        return [self.resolve(self.ports_mirror, codename)] * 3

    def changelog_mirror(self, codename: str, architecture: str) -> str:
        """Where the changelog fallback reads Packages indexes and .debs: the security mirror
        (ports for other architectures) when "use mirrors for changelog" is on, else Canonical's."""
        if not self.mirror_changelog:
            return SECURITY_MIRROR if architecture in ARCHIVE_ARCHITECTURES else PORTS_MIRROR
        return self.mirrors(codename, architecture)[2]

    @property
    def uses_mirrors(self) -> bool:
        defaults = (ARCHIVE_MIRROR, SECURITY_MIRROR, PORTS_MIRROR)
        return (self.archive_mirror, self.security_mirror, self.ports_mirror) != defaults

    @property
    def is_default(self) -> bool:
        return self == DEFAULT


DEFAULT = AptRepos()


# --- validation -------------------------------------------------------------------------


def check_url(value: str) -> str | None:
    """Why ``value`` cannot be a mirror URL, or None. Empty is checked by the caller."""
    if len(value) > MAX_URL_CHARS:
        return f"The URL is longer than {MAX_URL_CHARS} characters."
    if any(c.isspace() for c in value) or any(c in _QUOTES for c in value):
        return "The URL must not contain spaces or quotes."
    if "$" in value.replace(PLACEHOLDER, ""):
        return "Only the ${codename} placeholder is allowed (no other ${...} or $)."
    parts = urlsplit(value.replace(PLACEHOLDER, DEFAULT_RELEASE))
    if parts.scheme not in ("http", "https") or "://" not in value:
        return "Only http:// and https:// URLs are supported."
    if "@" in parts.netloc:
        return (
            "The URL must not contain credentials (user:password@). Use a mirror that needs "
            "no login, or a proxy (HTTPS_PROXY)."
        )
    if "?" in value or parts.query:
        return "The URL must not have a query string."
    if "#" in value or parts.fragment:
        return "The URL must not have a fragment (#)."
    try:
        parts.port  # noqa: B018 - raises ValueError for an invalid port
    except ValueError:
        return "The URL has an invalid port."
    if not parts.hostname:
        return "The URL needs a host name."
    return None


def check_keyring(value: str) -> str | None:
    if len(value) > MAX_PATH_CHARS:
        return f"The path is longer than {MAX_PATH_CHARS} characters."
    if not value.startswith("/"):
        return "The keyring must be an absolute path (e.g. /usr/share/keyrings/example.gpg)."
    if not set(value) <= _PATH_CHARS or ".." in value.split("/"):
        return "The keyring path may only contain letters, digits and . _ + - / (no ..)."
    return None


def _normalize_url(value: str) -> str:
    return value.strip().rstrip("/")


def _flag(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in ("1", "on", "yes", "true")


def validate_form(form: dict[str, str]) -> tuple[AptRepos | None, dict[str, str]]:
    """(settings, {}) for a valid form, else (None, field -> message). An empty URL or keyring
    field means Canonical's default."""
    values: dict[str, object] = {}
    errors: dict[str, str] = {}
    defaults = asdict(DEFAULT)
    for name in URL_FIELDS:
        text = _normalize_url(str(form.get(name) or ""))
        if not text:
            values[name] = defaults[name]
        elif error := check_url(text):
            errors[name] = error
        else:
            values[name] = text
    keyring = str(form.get(KEYRING_FIELD) or "").strip()
    if not keyring:
        values[KEYRING_FIELD] = KEYRING
    elif error := check_keyring(keyring):
        errors[KEYRING_FIELD] = error
    else:
        values[KEYRING_FIELD] = keyring
    for name in FLAG_FIELDS:
        values[name] = _flag(form.get(name))
    if errors:
        return None, errors
    return AptRepos(**values), {}


def form_values(repos: AptRepos) -> dict[str, object]:
    """What the form shows: a default is an empty field (the default is its placeholder)."""
    defaults = asdict(DEFAULT)
    current = asdict(repos)
    values: dict[str, object] = {
        name: "" if current[name] == defaults[name] else current[name] for name in TEXT_FIELDS
    }
    values.update({name: current[name] for name in FLAG_FIELDS})
    return values


# --- storage ----------------------------------------------------------------------------


def load(db: Database) -> AptRepos:
    """The saved settings; DEFAULT when nothing (or nothing usable) is saved. A saved value
    that no longer validates falls back to its default instead of reaching sources.list."""
    raw = db.get_setting(SETTING)
    if not raw:
        return DEFAULT
    try:
        saved = json.loads(raw)
        if not isinstance(saved, dict):
            raise ValueError("not an object")
    except ValueError as exc:
        logger.warning("Ignoring unreadable APT repository settings: %s", exc)
        return DEFAULT
    repos, errors = validate_form({k: v for k, v in saved.items() if k in asdict(DEFAULT)})
    if repos is None:
        logger.warning("Ignoring invalid APT repository settings: %s", "; ".join(errors.values()))
        good = {k: v for k, v in saved.items() if k in asdict(DEFAULT) and k not in errors}
        repos, _ = validate_form(good)
    return repos or DEFAULT


def save(db: Database, repos: AptRepos) -> None:
    db.set_setting(SETTING, json.dumps(asdict(repos), sort_keys=True))


def reset(db: Database) -> None:
    db.delete_setting(SETTING)


def provider(db: Database) -> Callable[[], AptRepos]:
    """Zero-argument loader for the services: each run reads the current settings."""
    return lambda: load(db)


# --- preview and test -------------------------------------------------------------------


def choice(release: str | None, architecture: str | None) -> tuple[str, str]:
    """A supported (codename, architecture) for the preview / Test; defaults otherwise."""
    codename = release if release in SUPPORTED_RELEASES.values() else DEFAULT_RELEASE
    arch = architecture if architecture in ARCHITECTURES else DEFAULT_ARCHITECTURE
    return codename, arch


def preview(repos: AptRepos, codename: str, architecture: str) -> str:
    """The private sources.list these settings give for one release and architecture."""
    mirrors = repos.mirrors(codename, architecture)
    return sources_list(codename, architecture, repos.keyring, mirrors)


@dataclass(frozen=True)
class PocketCheck:
    suite: str
    url: str
    ok: bool
    detail: str


def _looks_like_inrelease(head: bytes) -> bool:
    return head.startswith(b"-----BEGIN PGP SIGNED MESSAGE-----") or b"\nSuite:" in head


def check_pockets(
    repos: AptRepos,
    codename: str,
    architecture: str,
    fetcher: Callable[[str, BinaryIO, int, float], None] | None = None,
) -> list[PocketCheck]:
    """Fetch ``dists/<pocket>/InRelease`` of every pocket from its mirror (the Test button).
    Read-only: the file is checked in memory and thrown away."""
    fetch = fetcher or source_http.fetch_to_file
    results = []
    mirrors = repos.mirrors(codename, architecture)
    for mirror, suite in zip(mirrors, pockets(codename), strict=True):
        url = f"{mirror}/dists/{suite}/InRelease"
        out = io.BytesIO()
        try:
            fetch(url, out, MAX_INRELEASE_BYTES, TEST_TIMEOUT_SECONDS)
        except Exception as exc:  # noqa: BLE001 - every failure is a result, never a crash
            results.append(PocketCheck(suite, url, False, source_http.describe_error(exc)))
            continue
        data = out.getvalue()
        if not _looks_like_inrelease(data[:4096]):
            results.append(PocketCheck(suite, url, False, "the answer is not an InRelease file"))
        else:
            results.append(PocketCheck(suite, url, True, f"OK ({len(data)} bytes)"))
        logger.info("apt_mirror_test suite=%s url=%s ok=%s", suite, url, results[-1].ok)
    return results
