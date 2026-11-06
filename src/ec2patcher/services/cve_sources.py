"""The multi-source CVE resolver: OVAL -> USN notices -> changelog -> per-CVE JSON.

At the start of a run every source is probed in parallel (one small request each); a blocked
source is skipped for the run, with its reason recorded, instead of being retried per CVE. Data
already stored from a blocked source is still used. The first source that answers resolves the
CVE, recorded as ``CveRecord.origin``; when none does, the reason says which source failed.
Circuit breakers are per source and endpoint: no source ever disables another (source_breaker).

NVD, KEV and EPSS are only probed here: they supply priority and never a status.
"""

import logging
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, wait
from dataclasses import dataclass
from time import monotonic
from urllib.parse import urlsplit

from ec2patcher.database import Database
from ec2patcher.services import (
    changelog_source,
    enrichment,
    nvd,
    oval_feed,
    source_http,
    usn_notices,
)
from ec2patcher.services.local_apt import SECURITY_MIRROR
from ec2patcher.services.security_metadata import (
    API_URL,
    CveRecord,
    MetadataUnreachable,
    SecurityMetadata,
    status_entry,
)
from ec2patcher.services.source_breaker import BreakerBoard

logger = logging.getLogger(__name__)

OVAL = oval_feed.SOURCE
NOTICES = usn_notices.SOURCE
CHANGELOG = changelog_source.SOURCE
CVE_JSON = "cve-json"
NVD = "nvd"
KEV = enrichment.KEV
EPSS = enrichment.EPSS

_PROBE_RELEASE = "noble"  # any supported release: only the host and path are being tested
_PROBE_CVE = "CVE-2000-0001"  # unknown CVEs answer 404, which still shows the path works
PROBE_TARGETS = (
    (OVAL, oval_feed.URL.format(codename=_PROBE_RELEASE)),
    (NOTICES, f"{usn_notices.URL}?limit=1&offset=0"),
    (CHANGELOG, f"{SECURITY_MIRROR}/dists/{_PROBE_RELEASE}-security/Release"),
    (CVE_JSON, API_URL.format(cve=_PROBE_CVE)),
    (NVD, f"{nvd.API_URL}?cveId={_PROBE_CVE}"),
    (KEV, enrichment.KEV_URL),
    (EPSS, f"{enrichment.EPSS_URL}?cve={_PROBE_CVE}"),
)
PROBE_GRACE_SECONDS = 2.0
MAX_CHANGELOG_PACKAGES_PER_CVE = 5
MAX_REASON_CHARS = 300


@dataclass(frozen=True)
class ProbeResult:
    source: str
    endpoint: str
    reachable: bool
    reason: str | None = None
    duration_ms: int = 0

    @property
    def message(self) -> str:
        state = "reachable" if self.reachable else f"blocked: {self.reason}, skipped for this run"
        return f"{self.source} ({self.endpoint}): {state}"

    def as_dict(self) -> dict:
        return {
            "source": self.source,
            "endpoint": self.endpoint,
            "reachable": self.reachable,
            "reason": self.reason,
            "duration_ms": self.duration_ms,
        }


class SourceFailure(Exception):
    """A source could not answer (as opposed to not listing the CVE)."""


def _no_check() -> None:
    return None


def _no_note(message: str, level: str = "info") -> None:
    return None


def probe_all(prober: Callable[[str, float], str | None], timeout: float) -> list[ProbeResult]:
    """Probe every source in parallel; one that does not answer in time counts as blocked."""

    def one(url: str) -> tuple[str | None, int]:
        started = monotonic()
        try:
            reason = prober(url, timeout)
        except Exception as exc:  # noqa: BLE001 - a broken probe is a blocked source
            reason = source_http.describe_error(exc)
        return reason, int((monotonic() - started) * 1000)

    executor = ThreadPoolExecutor(max_workers=len(PROBE_TARGETS), thread_name_prefix="source-probe")
    futures = [executor.submit(one, url) for _, url in PROBE_TARGETS]
    wait(futures, timeout=timeout + PROBE_GRACE_SECONDS)
    results = []
    for (source, url), future in zip(PROBE_TARGETS, futures, strict=True):
        endpoint = urlsplit(url).hostname or ""
        if future.done():
            reason, duration = future.result()
        else:
            reason, duration = f"no answer within {timeout:g} s", int(timeout * 1000)
        results.append(ProbeResult(source, endpoint, reason is None, reason, duration))
        logger.info(
            "source_probe source=%s endpoint=%s reachable=%s duration_ms=%d reason=%s",
            source, endpoint, reason is None, duration, reason,
        )  # fmt: skip
    executor.shutdown(wait=False)
    return results


class SourceResolver:
    def __init__(
        self,
        db: Database,
        metadata: SecurityMetadata,
        oval: oval_feed.OvalFeed | None = None,
        notices: usn_notices.UsnNotices | None = None,
        changelog: changelog_source.ChangelogSource | None = None,
        priority: enrichment.Enrichment | None = None,
        prober: Callable[[str, float], str | None] | None = None,
        breakers: BreakerBoard | None = None,
        probe_timeout: float = source_http.PROBE_TIMEOUT_SECONDS,
    ):
        self.db, self.metadata = db, metadata
        self.breakers = breakers or BreakerBoard()
        self.oval = oval or oval_feed.OvalFeed(db, self.breakers)
        self.notices = notices or usn_notices.UsnNotices(db, self.breakers)
        self.changelog = changelog or changelog_source.ChangelogSource(self.breakers)
        self.priority = priority or enrichment.Enrichment(db, self.breakers)
        self.prober, self.probe_timeout = prober, probe_timeout
        self.probes: dict[str, ProbeResult] = {}
        self._reset()

    def _reset(self) -> None:
        self._oval_states: dict[str, oval_feed.FeedState] = {}
        self._notices_refreshed = False

    def start_run(self) -> list[ProbeResult]:
        """Forget the per-run state and probe the sources. Metadata's own start_run comes first."""
        self._reset()
        self.breakers.reset()
        self.changelog.start_run()
        self.priority.start_run()
        results = probe_all(self.prober or source_http.probe, self.probe_timeout)
        self.probes = {r.source: r for r in results}
        reason = self.blocked(CVE_JSON)
        if reason:
            self.metadata.block_for_run(reason)
        return results

    def blocked(self, source: str) -> str | None:
        """Why ``source`` is skipped this run; None if it was reachable or not probed."""
        probe = self.probes.get(source)
        return probe.reason if probe and not probe.reachable else None

    def clear(self) -> bool:
        """Forget all stored source data (Clear Security Cache)."""
        self._reset()
        self.changelog.start_run()
        self.priority.start_run()
        self.breakers.reset()
        return self.db.clear_source_caches() > 0

    # --- preparing the stored data ------------------------------------------------------

    def prepare(
        self,
        codename: str,
        note: Callable[..., None] = _no_note,
        check: Callable[[], None] = _no_check,
    ) -> None:
        """Bring the OVAL copy of this release and the notices up to date; at most once per run.
        Never raises except to stop the run (``check``): a source that fails is only skipped."""
        if codename not in self._oval_states:
            try:
                state = self.oval.ensure(codename, self.blocked(OVAL), check)
            except Exception as exc:  # noqa: BLE001 - a broken source must not fail the server
                logger.exception("OVAL feed of %s failed", codename)
                problem = str(exc) or type(exc).__name__
                state = oval_feed.FeedState(False, problem, problem)
            self._oval_states[codename] = state
            note(f"OVAL {state.message}", "warning" if state.problem else "info")
        if not self._notices_refreshed:
            self._notices_refreshed = True
            try:
                note(f"USN notices: {self.notices.refresh(self.blocked(NOTICES), check)}")
            except Exception as exc:  # noqa: BLE001 - see above
                logger.exception("USN notices failed")
                note(f"USN notices: {exc}", "warning")

    # --- the chain ----------------------------------------------------------------------

    def lookup(
        self,
        cve: str,
        facts,
        metadata_lookup: Callable[[str], CveRecord | None] | None = None,
        hints: Iterable[str] = (),
    ) -> CveRecord | None:
        """Canonical's data on ``cve`` for this server's release, from the first source that has
        it. Raises like the metadata lookup, with ``failure_reason`` set, if none could answer."""
        cve = cve.strip().upper()
        self.prepare(facts.codename)
        failures: dict[str, str] = {}
        for name, step in (
            (OVAL, lambda: self._from_oval(cve, facts.codename)),
            (NOTICES, lambda: self._from_notices(cve, facts.codename)),
            (CHANGELOG, lambda: self._from_changelog(cve, facts, hints)),
        ):
            try:
                record = step()
            except SourceFailure as exc:
                failures[name] = str(exc)
                continue
            except Exception as exc:  # noqa: BLE001 - a broken source must not stop the others
                logger.exception("%s lookup of %s failed", name, cve)
                failures[name] = str(exc) or type(exc).__name__
                continue
            if record is not None:
                self.metadata.note_resolved(cve)
                return record
        try:
            return (metadata_lookup or self.metadata.lookup)(cve)
        except Exception as exc:
            blocked = self.blocked(CVE_JSON)
            if blocked and isinstance(exc, MetadataUnreachable):
                failures[CVE_JSON] = f"blocked ({blocked})"
            else:
                failures[CVE_JSON] = source_http.describe_error(exc)
            reason = "; ".join(f"{name}: {why}" for name, why in failures.items())
            exc.failure_reason = reason[:MAX_REASON_CHARS]
            logger.info("cve_unresolved cve=%s release=%s %s", cve, facts.codename, reason)
            raise

    def _from_oval(self, cve: str, codename: str) -> CveRecord | None:
        record = self.oval.lookup(cve, codename)
        if record is not None:
            return record
        state = self._oval_states.get(codename)
        if state is not None and not state.usable:
            raise SourceFailure(state.problem or state.message)
        return None

    def _from_notices(self, cve: str, codename: str) -> CveRecord | None:
        record = self.notices.lookup(cve, codename)
        if record is not None:
            return record
        blocked = self.blocked(NOTICES)
        if blocked and not self.notices.has_data():
            raise SourceFailure(f"blocked ({blocked})")
        return None

    def _candidate_sources(self, cve: str, facts, hints: Iterable[str]) -> list[str]:
        """Installed source packages that may hold the fix, from what is known of the CVE: the
        pasted list, other releases in OVAL, the USNs. A CVE nobody links to a package is not
        searched for: that would mean fetching a changelog per installed package."""
        names = {*hints, *self.notices.packages_for(cve), *self.oval.packages_for(cve)}
        by_source = facts.by_source()
        by_binary = {p.base_name: p.source for p in facts.packages}
        sources = {name if name in by_source else by_binary.get(name) for name in names}
        sources.discard(None)
        return sorted(sources)[:MAX_CHANGELOG_PACKAGES_PER_CVE]

    def _from_changelog(self, cve: str, facts, hints: Iterable[str]) -> CveRecord | None:
        blocked = self.blocked(CHANGELOG)
        if blocked:
            raise SourceFailure(f"blocked ({blocked})")
        sources = self._candidate_sources(cve, facts, hints)
        if not sources:
            return None
        fixes, errors = self.changelog.find(cve, facts.codename, facts.architecture, sources)
        if not fixes:
            if errors:
                raise SourceFailure(errors[0])
            return None
        record = CveRecord(cve=cve, origin=CHANGELOG)
        for source, version in sorted(fixes.items()):
            record.entries.append(status_entry(source, version, facts.codename, "released", None))
        return record

    # --- enrichment ---------------------------------------------------------------------

    def refresh_enrichment(self, cves: Iterable[str]) -> None:
        """May be abandoned by the caller's time limit: it only writes to the caches."""
        self.priority.refresh_kev(self.blocked(KEV))
        self.priority.refresh_epss(cves, self.blocked(EPSS))

    def annotate(self, findings: list) -> None:
        self.priority.annotate(findings)
