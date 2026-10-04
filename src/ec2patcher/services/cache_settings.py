"""Cache TTLs (Settings -> Caches) and the figures shown by the cache badges.

The TTLs are stored in the settings table (``cache_ttl``: JSON, whole hours per cache) and
applied to the lookup clients. Without a saved value a cache keeps its client's default: NVD
30 days, Canonical 24 h for settled CVEs (or ``EC2PATCHER_CANONICAL_CACHE_TTL_HOURS``) and
1 h while a release is still under investigation, Amazon updateinfo 24 h. Every TTL must be
between 1 hour and 365 days.

A TTL only decides when an entry is refreshed: changing it never deletes cache entries;
entries older than the new TTL are refreshed on their next lookup.
"""

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from ec2patcher.database import Database
from ec2patcher.models import CACHE_AMAZON, CACHE_CANONICAL, CACHE_NVD, CacheStats
from ec2patcher.services.security_metadata import format_age

logger = logging.getLogger(__name__)

SETTING = "cache_ttl"
MIN_HOURS = 1
MAX_HOURS = 365 * 24

# Form fields / keys of the saved JSON.
NVD = "nvd"
CANONICAL = "canonical"
CANONICAL_UNSETTLED = "canonical_unsettled"
AMAZON = "amazon"
FIELDS = (NVD, CANONICAL, CANONICAL_UNSETTLED, AMAZON)
LABELS = {
    NVD: "NVD CVSS",
    CANONICAL: "Canonical (settled CVEs)",
    CANONICAL_UNSETTLED: "Canonical (under investigation)",
    AMAZON: "Amazon updateinfo",
}

_TTL_RE = re.compile(r"^(\d{1,7})\s*([hd]?)$", re.IGNORECASE)


def parse_ttl(text: str) -> tuple[int | None, str | None]:
    """(hours, None) for "36", "36h" or "30d"; (None, error) otherwise. Bounds: 1 h - 365 d."""
    match = _TTL_RE.match((text or "").strip())
    if not match:
        return None, "Enter a whole number of hours (e.g. 24h) or days (e.g. 30d)."
    hours = int(match.group(1)) * (24 if match.group(2).lower() == "d" else 1)
    if not MIN_HOURS <= hours <= MAX_HOURS:
        return None, "The TTL must be between 1 hour and 365 days."
    return hours, None


def format_ttl(hours: float) -> str:
    """30 d / 24 h / 0.5 h."""
    if hours >= 24 and hours % 24 == 0:
        return f"{int(hours // 24)} d"
    return f"{hours:g} h"


def _hours(value: timedelta) -> float:
    hours = value.total_seconds() / 3600
    return int(hours) if hours == int(hours) else hours


class CacheTtls:
    """The TTLs of the NVD, Canonical and Amazon updateinfo clients, as saved in Settings.

    The clients' TTLs at construction are the defaults that apply while nothing is saved
    (and after Reset to Default / Reset Database)."""

    def __init__(self, db: Database, metadata, nvd_client, advisories):
        self.db, self.metadata, self.nvd, self.advisories = db, metadata, nvd_client, advisories
        self.defaults = self.current()
        self.apply_saved()

    def current(self) -> dict[str, float]:
        """The TTLs in use, in hours."""
        return {
            NVD: _hours(self.nvd.max_age),
            CANONICAL: _hours(self.metadata.max_age),
            CANONICAL_UNSETTLED: _hours(self.metadata.investigating_max_age),
            AMAZON: _hours(self.advisories.max_age),
        }

    def saved(self) -> dict[str, int]:
        """Valid saved TTLs (hours); an unreadable or out-of-range value is ignored."""
        try:
            data = json.loads(self.db.get_setting(SETTING) or "{}")
        except (TypeError, ValueError) as exc:
            logger.warning("Ignoring the unreadable cache TTL setting: %s", exc)
            return {}
        if not isinstance(data, dict):
            return {}
        saved = {}
        for key in FIELDS:
            value = data.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                if MIN_HOURS <= value <= MAX_HOURS:
                    saved[key] = value
                    continue
            if value is not None:
                logger.warning("Ignoring the invalid saved cache TTL %s=%r", key, value)
        return saved

    def apply_saved(self) -> None:
        self._apply({**self.defaults, **self.saved()})

    def save(self, hours: dict[str, int]) -> None:
        self.db.set_setting(SETTING, json.dumps({key: hours[key] for key in FIELDS}))
        self._apply(hours)
        logger.info(
            "Cache TTLs saved: %s",
            ", ".join(f"{key}={format_ttl(hours[key])}" for key in FIELDS),
        )

    def reset(self) -> None:
        self.db.delete_setting(SETTING)
        self._apply(self.defaults)
        logger.info("Cache TTLs reset to default")

    def _apply(self, hours: dict[str, float]) -> None:
        self.nvd.max_age = timedelta(hours=hours[NVD])
        self.metadata.max_age = timedelta(hours=hours[CANONICAL])
        self.metadata.investigating_max_age = timedelta(hours=hours[CANONICAL_UNSETTLED])
        self.advisories.max_age = timedelta(hours=hours[AMAZON])

    def form_values(self) -> dict[str, str]:
        """The current TTLs as form input values ("30d", "24h")."""
        return {key: format_ttl(value).replace(" ", "") for key, value in self.current().items()}


def validate_form(form: dict[str, str]) -> tuple[dict[str, int], dict[str, str]]:
    """(hours per field, errors per field) of the Caches form."""
    hours, errors = {}, {}
    for key in FIELDS:
        value, error = parse_ttl(form.get(key, ""))
        if error:
            errors[key] = error
        else:
            hours[key] = value
    if not errors and hours[CANONICAL_UNSETTLED] > hours[CANONICAL]:
        errors[CANONICAL_UNSETTLED] = "Must not be longer than the TTL of settled CVEs."
    return hours, errors


# --- cache badges ------------------------------------------------------------------------------

_BADGES = (
    (CACHE_NVD, "NVD cache", ("CVE", "CVEs")),
    (CACHE_CANONICAL, "Canonical cache", ("CVE", "CVEs")),
    (CACHE_AMAZON, "Amazon updateinfo cache", ("repository", "repositories")),
)


@dataclass
class CacheBadge:
    name: str  # nvd / canonical / amazon
    label: str
    count: int
    unit: str
    oldest_age: str | None
    ttl: str
    last_run_id: int | None  # the latest analysis run, if any
    last_run: CacheStats | None  # its lookups of this cache (None: not recorded)

    @property
    def empty(self) -> bool:
        return self.count == 0

    @property
    def used_cache(self) -> bool:
        """The latest analysis run answered lookups from this cache."""
        return self.last_run is not None and self.last_run.cache > 0

    @property
    def css(self) -> str:
        return "badge-info" if self.used_cache and not self.empty else "badge-neutral"

    @property
    def text(self) -> str:
        if self.empty:
            return f"{self.label}: empty, TTL {self.ttl}"
        age = self.oldest_age or "unknown"
        return f"{self.label}: {self.count} {self.unit}, oldest {age}, TTL {self.ttl}"

    @property
    def title(self) -> str:
        if self.last_run_id is None:
            run = "No analysis run yet"
        elif self.last_run is None or not self.last_run.total:
            run = f"Last analysis (#{self.last_run_id}) did not use this cache"
        else:
            run = f"Last analysis (#{self.last_run_id}): {self.last_run.label}"
        return f"{run}. Manage caches and TTLs in Settings."


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def badges(db: Database, ttls: CacheTtls, now: Callable[[], datetime] = _now) -> list[CacheBadge]:
    """One badge per cache: entries, age of the oldest entry, TTL and whether the latest
    analysis run used it. Never raises (a broken figure is shown as unknown)."""
    current = ttls.current()
    ttl_text = {
        CACHE_NVD: format_ttl(current[NVD]),
        CACHE_CANONICAL: (
            f"{format_ttl(current[CANONICAL])} / "
            f"{format_ttl(min(current[CANONICAL], current[CANONICAL_UNSETTLED]))} unsettled"
        ),
        CACHE_AMAZON: format_ttl(current[AMAZON]),
    }
    try:
        latest = db.latest_cache_stats()
    except Exception as exc:  # noqa: BLE001 - a badge must never break a page
        logger.warning("Cannot read the cache statistics of the latest run: %s", exc)
        latest = None
    result = []
    for name, label, (one, many) in _BADGES:
        try:
            count, oldest = db.cache_summary(name)
            age = format_age(now() - datetime.fromisoformat(oldest)) if oldest else None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Cannot summarize the %s cache: %s", name, exc)
            count, age = 0, None
        stats = None
        if latest is not None and name in latest[1]:
            stats = CacheStats.from_dict(latest[1][name])
        result.append(
            CacheBadge(
                name=name, label=label, count=count, unit=one if count == 1 else many,
                oldest_age=age, ttl=ttl_text[name],
                last_run_id=latest[0] if latest else None, last_run=stats,
            )
        )  # fmt: skip
    return result
