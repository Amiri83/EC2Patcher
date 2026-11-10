"""The multi-source resolver: OVAL, USN notices, changelog, per-CVE JSON, KEV, EPSS, breakers."""

import bz2
import gzip
import hashlib
import io
import json
import sqlite3
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError

import pytest
from fastapi.testclient import TestClient
from openpyxl import load_workbook
from phase2_fixtures import ScriptedSSH, facts_output, make_metadata
from phase3_fixtures import IP, SERVER, FakeFetcher, FakeUbuntu, make_analysis

from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import PatchReportRow
from ec2patcher.services import (
    changelog_source,
    cve_resolver,
    cve_sources,
    enrichment,
    oval_feed,
    patch_report,
    patch_service,
    run_events,
    usn_notices,
)
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.security_metadata import CveRecord, SecurityMetadata
from ec2patcher.services.server_state import parse_facts
from ec2patcher.services.source_breaker import CLOSED, HALF_OPEN, OPEN, BreakerBoard, SourceBreaker

FIXTURES = Path(__file__).parent / "fixtures"
OVAL_XML = (FIXTURES / "oval_sample.cve.oval.xml").read_bytes()
NOTICES = json.loads((FIXTURES / "notices_sample.json").read_text())
START = datetime(2000, 1, 1, tzinfo=timezone.utc)
ALL_REACHABLE = lambda url, timeout: None  # noqa: E731


class Clock:
    def __init__(self):
        self.value = START

    def __call__(self):
        return self.value

    def advance(self, **kwargs):
        self.value += timedelta(**kwargs)


class FileFetcher:
    """fetcher(url, out, max_bytes, timeout): bytes per URL substring, in the given order."""

    def __init__(self, replies):
        self.replies, self.calls = replies, []

    def __call__(self, url, out, max_bytes, timeout):
        self.calls.append(url)
        for part, reply in self.replies.items():
            if part in url:
                if isinstance(reply, BaseException):
                    raise reply
                out.write(reply)
                return
        raise HTTPError(url, 404, "Not Found", None, None)


def oval_fetcher(data=None):
    return FileFetcher({".cve.oval.xml.bz2": bz2.compress(OVAL_XML) if data is None else data})


def facts():
    return parse_facts(facts_output())


def fail_lookup(cve):
    raise AssertionError("the last resort must not be reached")


# --- OVAL -------------------------------------------------------------------------------------


def test_parse_oval_statuses_versions_and_inventory_definitions():
    entries = {(e.cve, e.package): e for e in oval_feed.parse_oval(io.BytesIO(OVAL_XML))}
    assert entries[("CVE-2000-0001", "openssl")].status == "released"
    assert entries[("CVE-2000-0001", "openssl")].fixed_version == "3.0.13-0ubuntu3.6"
    assert entries[("CVE-2000-0001", "openssl")].priority == "Medium"
    assert entries[("CVE-2000-0001", "curl")].status == "not-affected"
    assert entries[("CVE-2000-0001", "curl")].note == "code not present"
    assert entries[("CVE-2000-0001", "vim")].status == "needed"
    assert entries[("CVE-2000-0001", "sudo")].status == "needs-triage"
    assert entries[("CVE-2000-0001", "bash")].status == "deferred"
    assert ("CVE-2000-0001", "zlib") not in entries  # does not exist in this release
    # No version in the comment: it comes from the state of the package's test.
    assert entries[("CVE-2000-0002", "example-package")].fixed_version == "1.2.3-1ubuntu1"
    assert entries[("CVE-2000-0002", "example-package")].priority == "high"  # from the title
    assert entries[("CVE-2000-0002", "libxml2")].fixed_version is None
    assert {e.cve for e in entries.values()} == {"CVE-2000-0001", "CVE-2000-0002"}


def test_parse_oval_discards_elements_as_it_goes(monkeypatch):
    """A parsed definition no longer hangs off its section: memory stays flat on a large feed."""
    sections = []
    real = oval_feed.ET.iterparse

    def spying(stream, events):
        for event, element in real(stream, events=events):
            if event == "start" and element.tag.endswith("}definitions"):
                sections.append(element)
            yield event, element

    monkeypatch.setattr(oval_feed.ET, "iterparse", spying)
    held = [len(sections[0]) for _ in oval_feed.parse_oval(io.BytesIO(OVAL_XML))]
    assert held and max(held) <= 1  # the three definitions were never all in memory


def test_oval_store_and_local_lookup_needs_no_request_per_cve(db):
    fetcher = oval_fetcher()
    feed = oval_feed.OvalFeed(db, fetcher=fetcher, now=Clock())
    state = feed.ensure("noble")
    assert state.usable and "downloaded" in state.message
    assert fetcher.calls == [
        "https://security-metadata.canonical.com/oval/com.ubuntu.noble.cve.oval.xml.bz2"
    ]
    record = feed.lookup("CVE-2000-0001", "noble")
    assert record.origin == "oval" and record.cache_age is None
    by_source = {e.source: e for e in record.for_release("noble")}
    assert (by_source["openssl"].status, by_source["openssl"].version) == (
        "fixed",
        "3.0.13-0ubuntu3.6",
    )
    assert by_source["openssl"].priority == "Medium"
    assert by_source["curl"].status == "not_affected"
    assert by_source["vim"].status == "affected"
    assert by_source["sudo"].status == "under_investigation"
    assert by_source["bash"].status == "affected" and "deferred" in by_source["bash"].note
    # Fixed without a version: nothing to compare, so never a "fixed" statement.
    other = {e.source: e for e in feed.lookup("CVE-2000-0002", "noble").entries}
    assert other["libxml2"].status == "under_investigation"
    assert feed.lookup("CVE-2000-9999", "noble") is None
    assert feed.lookup("CVE-2000-0001", "jammy") is None
    assert len(fetcher.calls) == 1


def test_oval_ttl_per_codename_and_stale_copy_is_marked(db):
    clock, fetcher = Clock(), oval_fetcher()
    feed = oval_feed.OvalFeed(db, fetcher=fetcher, now=clock)
    feed.ensure("noble")
    clock.advance(hours=23)
    assert "current" in feed.ensure("noble").message
    assert len(fetcher.calls) == 1  # within the TTL
    feed.ensure("jammy")
    assert len(fetcher.calls) == 2  # one file per codename
    clock.advance(hours=2)
    assert "downloaded" in feed.ensure("noble").message
    assert len(fetcher.calls) == 3  # stale: downloaded again
    assert db.get_source_feed("oval:noble")["generation"] == 2


@pytest.mark.parametrize(
    "broken",
    [
        bz2.compress(OVAL_XML)[:200],  # truncated download
        b"this is not bzip2",
        bz2.compress(OVAL_XML[: len(OVAL_XML) // 2]),  # truncated XML
        bz2.compress(b"<oval_definitions/>"),  # nothing in it
    ],
    ids=["truncated-bz2", "not-bz2", "truncated-xml", "empty"],
)
def test_corrupt_download_keeps_the_previous_copy(db, broken):
    clock = Clock()
    feed = oval_feed.OvalFeed(db, fetcher=oval_fetcher(), now=clock)
    feed.ensure("noble")
    clock.advance(hours=25)
    feed.fetcher = oval_fetcher(broken)
    state = feed.ensure("noble")
    assert state.usable and "corrupt download discarded" in state.problem
    record = feed.lookup("CVE-2000-0001", "noble")
    assert record is not None and record.cache_age == timedelta(hours=25)
    with db.connect() as conn:
        generations = conn.execute("SELECT DISTINCT generation FROM oval_cve_packages").fetchall()
    assert [g[0] for g in generations] == [1]  # nothing of the partial parse is left


def test_corrupt_first_download_leaves_no_copy(db):
    feed = oval_feed.OvalFeed(db, fetcher=oval_fetcher(b"garbage"), now=Clock())
    state = feed.ensure("noble")
    assert not state.usable and feed.lookup("CVE-2000-0001", "noble") is None


def test_cancel_while_parsing_discards_the_partial_parse(db, monkeypatch):
    class Stop(BaseException):
        pass

    checks = []

    def stop():
        checks.append(1)
        if len(checks) == 2:  # the first batch is already stored
            raise Stop()

    monkeypatch.setattr(oval_feed, "BATCH_ROWS", 1)
    feed = oval_feed.OvalFeed(db, fetcher=oval_fetcher(), now=Clock())
    with pytest.raises(Stop):
        feed.ensure("noble", check=stop)
    with db.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM oval_cve_packages").fetchone()[0] == 0


def test_unsupported_codename_is_never_put_in_a_url(db):
    fetcher = oval_fetcher()
    feed = oval_feed.OvalFeed(db, fetcher=fetcher, now=Clock())
    assert not feed.ensure("../evil").usable and fetcher.calls == []


# --- USN notices ------------------------------------------------------------------------------


def paged(total, calls=None):
    """A notices.json with ``total`` notices, by offset and limit."""

    def fetch(url):
        if calls is not None:
            calls.append(url)
        query = dict(part.split("=") for part in url.split("?")[1].split("&"))
        offset, limit = int(query["offset"]), int(query["limit"])
        notices = [
            {
                "id": f"USN-{n:04d}-1",
                "title": f"example-package {n}",
                "published": f"2000-01-01T00:00:{n % 60:02d}",
                "cves_ids": [f"CVE-2000-{n:04d}"],
                "release_packages": {
                    "noble": [{"name": "curl", "version": "8.5.0-3", "is_source": True}]
                },
            }
            for n in range(offset, min(offset + limit, total))
        ]
        return {"notices": notices, "offset": offset, "limit": limit, "total_results": total}

    return fetch


def test_notices_follow_pages_until_total_with_limit_20(db):
    calls = []
    source = usn_notices.UsnNotices(db, fetcher=paged(40, calls), now=Clock(), sleep=lambda s: None)
    source.refresh()
    assert calls == [
        f"https://ubuntu.com/security/notices.json?limit=20&offset={offset}" for offset in (0, 20)
    ]
    assert db.count_usn_notices() == 40


def test_notices_stop_at_a_short_page(db):
    calls = []
    source = usn_notices.UsnNotices(db, fetcher=paged(25, calls), now=Clock(), sleep=lambda s: None)
    source.refresh()
    assert len(calls) == 2 and db.count_usn_notices() == 25


def test_notices_ttl_and_refresh_after_it(db):
    clock, calls = Clock(), []
    source = usn_notices.UsnNotices(db, fetcher=paged(45, calls), now=clock, sleep=lambda s: None)
    source.refresh()
    assert len(calls) == 3
    clock.advance(hours=23)
    assert "current" in source.refresh()
    assert len(calls) == 3  # within the TTL
    clock.advance(hours=2)
    source.refresh()
    assert len(calls) == 4  # stale; the first page shows every notice is already known
    clock.advance(hours=25)
    source.fetcher = paged(46, calls)
    source.refresh()
    assert db.count_usn_notices() == 46


def test_notices_budget_is_resumed_by_the_next_run(db):
    ticks = iter(range(0, 1000, 100))
    calls = []
    source = usn_notices.UsnNotices(
        db, fetcher=paged(100, calls), now=Clock(), sleep=lambda s: None,
        monotonic=lambda: next(ticks), budget=150,
    )  # fmt: skip
    assert "continues at offset 40" in source.refresh()
    assert not db.get_source_feed("notices")["complete"]
    source.monotonic = lambda: 0
    source.refresh()
    assert calls[2].endswith("offset=40") and db.count_usn_notices() == 100
    assert db.get_source_feed("notices")["complete"]


def test_notices_failure_keeps_what_is_stored(db):
    source = usn_notices.UsnNotices(db, fetcher=lambda url: NOTICES, now=Clock())
    source.refresh()

    def down(url):
        raise OSError("connection refused")

    source.fetcher, source.now = down, lambda: START + timedelta(days=2)
    assert "could not refresh (connection refused)" in source.refresh()
    assert db.count_usn_notices() == 2
    assert source.lookup("CVE-2000-0004", "noble") is not None


def test_a_cve_in_several_usns_keeps_them_all_and_reports_the_best(db):
    db.store_usn_page([usn_notices.parse_notice(n) for n in NOTICES["notices"]])
    assert len(db.usn_candidates("CVE-2000-0003", "noble")) == 2
    # USN-0003-1 is newer, but only USN-0002-1 is about this server's release.
    assert usn_notices.best_usn(db, "CVE-2000-0003", "noble").id == "USN-0002-1"
    assert usn_notices.best_usn(db, "CVE-2000-0003", "jammy").id == "USN-0003-1"
    # No USN for the release: the latest published.
    assert usn_notices.best_usn(db, "CVE-2000-0003", "focal").id == "USN-0003-1"
    assert usn_notices.best_usn(db, "CVE-2000-0009", "noble") is None
    # Whatever the order of the rows, the same stored data gives the same answer.
    same_day = dict(published="2000-01-01T00:00:00", cves=["CVE-2000-0005"], packages=[])
    for usn_id in ("USN-0010-1", "USN-0009-2", "USN-0010-2"):
        db.store_usn_page([dict(id=usn_id, title=usn_id, **same_day)])
    assert usn_notices.best_usn(db, "CVE-2000-0005", "noble").id == "USN-0010-2"


def test_notice_lookup_gives_source_packages_of_the_release(db):
    db.store_usn_page([usn_notices.parse_notice(n) for n in NOTICES["notices"]])
    source = usn_notices.UsnNotices(db, now=Clock())
    record = source.lookup("CVE-2000-0004", "noble")
    assert record.origin == "notices"
    (entry,) = record.for_release("noble")
    assert (entry.source, entry.version, entry.status) == ("curl", "8.5.0-2ubuntu10.99", "fixed")
    assert source.lookup("CVE-2000-0004", "jammy") is None


# --- changelog --------------------------------------------------------------------------------


CHANGELOG_TEXT = """example-source (1.2-3) noble-security; urgency=medium

  * SECURITY UPDATE: another issue
    - CVE-2000-0007

 -- Maintainer <maintainer@example.com>  Sat, 01 Jan 2000 00:00:00 +0000

example-source (1.2-2) noble-security; urgency=medium

  * SECURITY UPDATE: an issue
    - debian/patches/CVE-2000-0006.patch: fix it.
    - CVE-2000-0006

 -- Maintainer <maintainer@example.com>  Sat, 01 Jan 2000 00:00:00 +0000

example-source (1.2-1) noble; urgency=medium

  * Mentions CVE-2000-00061, a longer number, and nothing else.
"""


def build_deb(package="example-binary", text=CHANGELOG_TEXT, data_name=b"data.tar.gz"):
    """A real .deb: ar archive with a gzipped data.tar holding the gzipped changelog."""
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w:gz") as tar:
        raw = gzip.compress(text.encode())
        info = tarfile.TarInfo(f"./usr/share/doc/{package}/changelog.Debian.gz")
        info.size = len(raw)
        tar.addfile(info, io.BytesIO(raw))
    deb = io.BytesIO()
    deb.write(b"!<arch>\n")
    control = (b"control.tar.gz", b"xx")
    for name, body in ((b"debian-binary", b"2.0\n"), control, (data_name, data.getvalue())):
        header = name + b"/" + b" " * (16 - len(name) - 1) + b"0" * 12 + b"0" * 6 + b"0" * 6
        header += b"100644  " + str(len(body)).encode().ljust(10) + b"`\n"
        deb.write(header + body)
        if len(body) % 2:
            deb.write(b"\n")
    return deb.getvalue()


def packages_gz(*debs):
    stanzas = []
    for package, source, version, filename, data in debs:
        source_line = f"Source: {source}\n" if source != package else ""
        stanzas.append(
            f"Package: {package}\n{source_line}Version: {version}\nArchitecture: amd64\n"
            f"Description: an example\n continued line\nFilename: {filename}\n"
            f"Size: {len(data)}\nSHA256: {hashlib.sha256(data).hexdigest()}\n"
        )
    return gzip.compress("\n".join(stanzas).encode())


POOL = "pool/main/e/example-source"


def changelog_fetcher(deb=None):
    deb = build_deb() if deb is None else deb
    index = packages_gz(
        ("example-binary", "example-source", "1.2-3", f"{POOL}/example-binary_1.2-3_amd64.deb", deb)
    )
    return FileFetcher({"noble-security/main/binary-amd64/Packages.gz": index, POOL: deb})


def test_fix_versions_takes_the_oldest_mention_and_exact_ids():
    fixes = changelog_source.fix_versions(CHANGELOG_TEXT)
    assert fixes == {"CVE-2000-0007": "1.2-3", "CVE-2000-0006": "1.2-2", "CVE-2000-00061": "1.2-1"}


def test_changelog_grep_hit_is_bounded_per_package(db):
    fetcher = changelog_fetcher()
    source = changelog_source.ChangelogSource(fetcher=fetcher)
    assert source.find("CVE-2000-0006", "noble", "amd64", ["example-source"]) == (
        {"example-source": "1.2-2"},
        [],
    )
    assert fetcher.calls == [
        "http://security.ubuntu.com/ubuntu/dists/noble-security/main/binary-amd64/Packages.gz",
        "http://security.ubuntu.com/ubuntu/dists/noble-security/universe/binary-amd64/Packages.gz",
        f"http://security.ubuntu.com/ubuntu/{POOL}/example-binary_1.2-3_amd64.deb",
    ]
    # Another CVE of the same package, and a CVE the changelog does not mention: no new request.
    source.find("CVE-2000-0007", "noble", "amd64", ["example-source"])
    assert source.find("CVE-2000-0008", "noble", "amd64", ["example-source"]) == ({}, [])
    assert len(fetcher.calls) == 3
    source.start_run()
    source.find("CVE-2000-0007", "noble", "amd64", ["example-source"])
    assert len(fetcher.calls) == 6  # per run


def test_changelog_refuses_a_deb_that_does_not_match_the_index(db):
    deb = build_deb()
    fetcher = changelog_fetcher(deb)
    fetcher.replies[POOL] = deb[:-1] + b"X"
    source = changelog_source.ChangelogSource(fetcher=fetcher)
    fixes, errors = source.find("CVE-2000-0006", "noble", "amd64", ["example-source"])
    assert fixes == {} and "does not match" in errors[0]


def test_changelog_reports_a_source_without_a_candidate(db):
    source = changelog_source.ChangelogSource(fetcher=FileFetcher({}))
    fixes, errors = source.find("CVE-2000-0006", "noble", "amd64", ["example-source"])
    assert fixes == {} and "no candidate .deb" in errors[0]


def test_zstd_deb_goes_through_dpkg_deb_with_an_argument_list(db, tmp_path):
    class Tar:
        def __init__(self):
            self.args = None

        def __call__(self, args, stdout, stderr, timeout, check):
            self.args = args
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode="w") as tar:
                raw = gzip.compress(CHANGELOG_TEXT.encode())
                info = tarfile.TarInfo("./usr/share/doc/example-binary/changelog.Debian.gz")
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
            stdout.write(data.getvalue())

            class Result:
                returncode = 0

            return Result()

    runner = Tar()
    deb = build_deb(data_name=b"data.tar.zst")
    source = changelog_source.ChangelogSource(fetcher=changelog_fetcher(deb), runner=runner)
    fixes, errors = source.find("CVE-2000-0006", "noble", "amd64", ["example-source"])
    assert (fixes, errors) == ({"example-source": "1.2-2"}, [])
    assert runner.args[:2] == ["dpkg-deb", "--fsys-tarfile"]


# --- the fallthrough order --------------------------------------------------------------------


class FakeSource:
    def __init__(self, record=None, packages=()):
        self.record, self.packages, self.calls = record, list(packages), []

    def lookup(self, cve, codename):
        self.calls.append(cve)
        return self.record

    def packages_for(self, cve):
        return self.packages

    def ensure(self, codename, blocked=None, check=None):
        problem = f"blocked ({blocked})" if blocked else None
        return oval_feed.FeedState(not blocked, problem or "ok", problem)

    def refresh(self, blocked=None, check=None):
        return "ok"

    def has_data(self):
        return True

    def find(self, cve, codename, architecture, sources):
        self.calls.append((cve, list(sources)))
        return self.record if self.record is not None else ({}, [])

    def start_run(self):
        pass


def record_from(origin):
    return CveRecord(cve="CVE-2000-0001", origin=origin)


def chain(db, oval=None, notices=None, changelog=None, prober=ALL_REACHABLE, meta=None):
    resolver = cve_sources.SourceResolver(
        db,
        meta or SecurityMetadata(db, fetcher=lambda url: {}),
        oval=oval or FakeSource(),
        notices=notices or FakeSource(),
        changelog=changelog or FakeSource(),
        priority=enrichment.Enrichment(db, fetcher=lambda url: {}),
        prober=prober,
    )
    resolver.start_run()
    return resolver


def test_oval_hit_needs_no_fallback(db):
    oval = FakeSource(record_from("oval"))
    notices, changelog = FakeSource(), FakeSource()
    resolver = chain(db, oval, notices, changelog)
    assert resolver.lookup("CVE-2000-0001", facts(), fail_lookup).origin == "oval"
    assert notices.calls == [] and changelog.calls == []


def test_oval_miss_then_notices(db):
    oval, notices = FakeSource(), FakeSource(record_from("notices"))
    changelog = FakeSource()
    resolver = chain(db, oval, notices, changelog)
    assert resolver.lookup("CVE-2000-0001", facts(), fail_lookup).origin == "notices"
    assert oval.calls == ["CVE-2000-0001"] and changelog.calls == []


def test_notices_miss_then_changelog_on_installed_packages_only(db):
    changelog = FakeSource(({"curl": "9.9-1"}, []))
    notices = FakeSource(packages=["curl", "not-installed"])
    resolver = chain(db, FakeSource(), notices, changelog)
    record = resolver.lookup(
        "CVE-2000-0001", facts(), fail_lookup, hints=("libssl3t64", "example-package")
    )
    assert record.origin == "changelog"
    (entry,) = record.for_release("noble")
    assert (entry.source, entry.version, entry.status) == ("curl", "9.9-1", "fixed")
    # libssl3t64 is a binary of openssl: the search is by source package.
    assert changelog.calls == [("CVE-2000-0001", ["curl", "openssl"])]


def test_a_cve_no_source_links_to_a_package_fetches_no_changelog(db):
    changelog = FakeSource()
    expected = record_from("cve-json")
    resolver = chain(db, changelog=changelog)
    assert resolver.lookup("CVE-2000-0001", facts(), lambda cve: expected) is expected
    assert changelog.calls == []


def test_changelog_miss_then_cve_json(db):
    changelog = FakeSource(({}, []))
    resolver = chain(db, FakeSource(packages=["curl"]), FakeSource(), changelog)
    calls = []

    def last(cve):
        calls.append(cve)
        return record_from("cve-json")

    assert resolver.lookup("CVE-2000-0001", facts(), last).origin == "cve-json"
    assert calls == ["CVE-2000-0001"] and len(changelog.calls) == 1


def test_every_source_failing_records_the_reason_with_the_source(db):
    def probe(url, timeout):
        return "HTTP 504" if "/security/cves/" in url or "oval" in url else None

    meta = SecurityMetadata(db, fetcher=fail_lookup)
    resolver = chain(db, prober=probe, meta=meta)
    findings = cve_resolver.resolve_all(
        ["CVE-2000-0001"], lambda cve: resolver.lookup(cve, facts()), facts()
    )
    (finding,) = findings
    assert finding.status == cve_resolver.METADATA_UNAVAILABLE
    assert finding.resolution_source is None
    assert "oval: blocked (HTTP 504)" in finding.failure_reason
    assert "cve-json: blocked (HTTP 504)" in finding.failure_reason


def test_the_resolved_record_marks_its_source_on_the_findings(db):
    oval = oval_feed.OvalFeed(db, fetcher=oval_fetcher(), now=Clock())
    resolver = chain(db, oval=oval)
    findings = cve_resolver.resolve_all(
        ["CVE-2000-0001"], lambda cve: resolver.lookup(cve, facts(), fail_lookup), facts()
    )
    by_source = {f.source: f for f in findings}
    assert by_source["openssl"].status == cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS
    assert by_source["openssl"].fixed_version == "3.0.13-0ubuntu3.6"
    assert by_source["openssl"].resolution_source == "oval"
    assert by_source["curl"].status == cve_resolver.NOT_AFFECTED
    assert by_source["vim"].resolution_source == "oval"


# --- probing and skipping ---------------------------------------------------------------------


def test_probe_one_result_per_source_with_the_reason(db):
    def probe(url, timeout):
        assert timeout == cve_sources.source_http.PROBE_TIMEOUT_SECONDS
        return "HTTP 504" if url.startswith("https://ubuntu.com/security/cves/") else None

    results = cve_sources.probe_all(probe, cve_sources.source_http.PROBE_TIMEOUT_SECONDS)
    assert [r.source for r in results] == [
        "oval", "notices", "changelog", "cve-json", "nvd", "kev", "epss",
    ]  # fmt: skip
    blocked = [r for r in results if not r.reachable]
    assert [(r.source, r.endpoint, r.reason) for r in blocked] == [
        ("cve-json", "ubuntu.com", "HTTP 504")
    ]
    assert "blocked: HTTP 504" in blocked[0].message


def test_probes_run_in_parallel_and_a_silent_source_counts_as_blocked(monkeypatch):
    import threading

    monkeypatch.setattr(cve_sources, "PROBE_GRACE_SECONDS", 0.2)
    release = threading.Event()

    def probe(url, timeout):
        if "first.org" in url:
            release.wait(5)
        return None

    results = {r.source: r for r in cve_sources.probe_all(probe, 0.05)}
    release.set()
    assert not results["epss"].reachable and "no answer within" in results["epss"].reason
    assert results["oval"].reachable


def test_a_failing_probe_is_a_blocked_source_not_an_error():
    def probe(url, timeout):
        raise OSError("Name or service not known")

    results = cve_sources.probe_all(probe, 1)
    assert not any(r.reachable for r in results)
    assert results[0].reason == "Name or service not known"


def test_blocked_source_is_skipped_for_the_run_with_its_reason(db):
    def probe(url, timeout):
        return "HTTP 403" if "security-metadata.canonical.com" in url else None

    fetcher = oval_fetcher()
    oval = oval_feed.OvalFeed(db, fetcher=fetcher, now=Clock())
    resolver = chain(db, oval=oval, prober=probe)
    assert resolver.blocked("oval") == "HTTP 403" and resolver.blocked("notices") is None
    expected = record_from("cve-json")
    assert resolver.lookup("CVE-2000-0001", facts(), lambda cve: expected) is expected
    resolver.lookup("CVE-2000-0002", facts(), lambda cve: expected)
    assert fetcher.calls == []  # never asked


def test_blocked_oval_still_answers_from_the_stored_copy(db):
    clock = Clock()
    oval = oval_feed.OvalFeed(db, fetcher=oval_fetcher(), now=clock)
    oval.ensure("noble")
    clock.advance(hours=48)
    oval.fetcher = oval_fetcher()

    def probe(url, timeout):
        return "HTTP 403" if "security-metadata.canonical.com" in url else None

    resolver = chain(db, oval=oval, prober=probe)
    record = resolver.lookup("CVE-2000-0001", facts(), fail_lookup)
    assert record.origin == "oval" and record.cache_note.startswith("Canonical metadata from cache")
    assert oval.fetcher.calls == []


def test_blocked_cve_json_makes_no_request_per_cve(db, tmp_path):
    calls = []

    def fetch(url):
        calls.append(url)
        raise OSError("must not be asked")

    def probe(url, timeout):
        return "HTTP 504" if "/security/cves/" in url else None

    meta = SecurityMetadata(db, fetcher=fetch)
    meta.start_run()
    resolver = chain(db, prober=probe, meta=meta)
    for cve in ("CVE-2000-0001", "CVE-2000-0002"):
        with pytest.raises(OSError, match="blocked for this run") as caught:
            resolver.lookup(cve, facts())
        assert "cve-json: blocked (HTTP 504)" in caught.value.failure_reason
    assert calls == []
    meta.start_run()  # the next run tries again
    with pytest.raises(OSError, match="must not be asked"):
        meta.lookup("CVE-2000-0003")


def test_analysis_run_records_probes_as_events_and_on_the_run(db, pem_file, monkeypatch):
    def probe(url, timeout):
        return "HTTP 504" if "/security/cves/" in url else None

    monkeypatch.setattr(cve_sources.source_http, "probe", probe)
    db.create_server("ip-10-0-0-1", "192.0.2.1", str(pem_file))
    db.save_report("report.json", {"ip-10-0-0-1": ["CVE-2026-63076"]}, "VALID")
    service = AnalysisService(
        db, make_metadata(None), runner=ScriptedSSH(), starter=lambda fn: fn()
    )
    run = db.get_analysis_run(service.start(db.get_latest_report()))
    rows = db.list_run_events("analysis", run.id, 0, 1000)
    probes = [r for r in rows if r["phase"] == run_events.PROBE_SOURCES]
    assert len(probes) == 7 and all(r["server"] is None for r in probes)
    blocked = next(r for r in probes if r["message"].startswith("cve-json"))
    assert blocked["level"] == "warning" and "HTTP 504" in blocked["message"]
    assert {p["source"]: p["reachable"] for p in run.source_probes}["cve-json"] is False
    # Blocked per-CVE JSON and offline OVAL: unresolved with the reason, no request per CVE.
    (finding,) = run.servers[0].findings
    assert finding.status == cve_resolver.METADATA_UNAVAILABLE
    assert "cve-json: blocked (HTTP 504)" in finding.failure_reason


# --- breakers ---------------------------------------------------------------------------------


class Ticks:
    def __init__(self):
        self.value = 0.0

    def __call__(self):
        return self.value


def test_breaker_half_open_with_backoff_and_logged_transitions(caplog):
    clock = Ticks()
    breaker = SourceBreaker("cve-json", "ubuntu.com", threshold=2, backoff=10, monotonic=clock)
    breaker.failure("HTTP 504")
    assert breaker.state == CLOSED and breaker.allow()
    with caplog.at_level("WARNING", logger="ec2patcher.services.source_breaker"):
        breaker.failure("HTTP 504")
        assert breaker.state == OPEN and not breaker.allow()
        clock.value = 10
        assert breaker.allow() and breaker.state == HALF_OPEN
        assert not breaker.allow()  # one trial per backoff
        breaker.failure("HTTP 504")
        assert breaker.state == OPEN and breaker.backoff == 20  # doubled
        clock.value = 25
        assert not breaker.allow()
        clock.value = 30
        assert breaker.allow()
        breaker.success()
    assert breaker.state == CLOSED and breaker.backoff == 10
    transitions = [r.getMessage().split("transition=")[1].split()[0] for r in caplog.records]
    assert transitions == [
        "closed->open", "open->half-open", "half-open->open", "open->half-open",
        "half-open->closed",
    ]  # fmt: skip


def test_the_breaker_is_per_source_and_per_endpoint_never_global():
    board = BreakerBoard(threshold=1, backoff=60, monotonic=Ticks())
    board.get("cve-json", "ubuntu.com").failure("HTTP 504")
    assert not board.get("cve-json", "ubuntu.com").allow()
    assert board.get("notices", "ubuntu.com").allow()  # same host, another source
    assert board.get("changelog", "security.ubuntu.com").allow()
    assert board.get("kev", "www.cisa.gov").allow() and board.get("epss", "api.first.org").allow()


def test_a_blocked_ubuntu_com_does_not_stop_security_ubuntu_com(db):
    """Failing per-CVE lookups open their breaker; the changelog host is still asked."""

    def always_down(url):
        raise OSError("connection timed out")

    meta = SecurityMetadata(db, fetcher=always_down, attempts=1, breaker_threshold=1)
    meta.start_run()
    fetcher = changelog_fetcher()
    changelog = changelog_source.ChangelogSource(fetcher=fetcher)
    resolver = chain(db, changelog=changelog, meta=meta)
    with pytest.raises(OSError, match="connection timed out"):
        resolver.lookup("CVE-2000-0001", facts())
    assert meta.breaker_open
    hints = ("example-source",)
    facts_with_source = _facts_with_example_source()
    record = resolver.lookup("CVE-2000-0006", facts_with_source, hints=hints)
    assert record.origin == "changelog" and fetcher.calls


def _facts_with_example_source():
    packages = [("example-binary", "1.2-1", "example-source", "1.2-1", "amd64", "ii ")]
    return parse_facts(facts_output(packages=packages))


def test_a_half_open_per_cve_lookup_makes_one_trial():
    calls = []
    clock = Ticks()

    def fetch(url):
        calls.append(url)
        raise OSError("connection timed out")

    meta = SecurityMetadata(fetcher=fetch, breaker_threshold=1, monotonic=clock, pace=0)
    with pytest.raises(OSError, match="connection timed out"):
        meta.lookup("CVE-2000-0001")
    assert len(calls) == 3 and meta.breaker_open  # every attempt of a normal lookup
    with pytest.raises(OSError, match="skipped after 1 consecutive"):
        meta.lookup("CVE-2000-0002")
    assert len(calls) == 3
    clock.value = 61
    with pytest.raises(OSError, match="connection timed out"):
        meta.lookup("CVE-2000-0002")
    assert len(calls) == 4  # one trial, no retries


def test_the_per_cve_timeout_is_five_seconds():
    assert SecurityMetadata().timeout == 5


# --- enrichment -------------------------------------------------------------------------------


def epss_fetcher(calls, scores=None):
    def fetch(url):
        calls.append(url)
        cves = url.split("?cve=")[1].split(",")
        data = [
            {"cve": c, "epss": str((scores or {}).get(c, "0.5")), "percentile": "0.9"}
            for c in cves
            if not c.endswith("9999")
        ]
        return {"status": "OK", "data": data}

    return fetch


def test_epss_requests_are_comma_batched_and_chunked(db):
    calls, sleeps = [], []
    source = enrichment.Enrichment(
        db, fetcher=epss_fetcher(calls), now=Clock(), sleep=sleeps.append, batch_size=2, pace=1.5
    )
    cves = ["CVE-2000-0003", "CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0001"]
    source.refresh_epss(cves)
    assert calls == [
        "https://api.first.org/data/v1/epss?cve=CVE-2000-0001,CVE-2000-0002",
        "https://api.first.org/data/v1/epss?cve=CVE-2000-0003",
    ]
    assert sleeps == [1.5]  # paced between batches


def test_epss_default_batch_size_is_sane(db):
    calls = []
    source = enrichment.Enrichment(
        db, fetcher=epss_fetcher(calls), now=Clock(), sleep=lambda s: None
    )
    source.refresh_epss([f"CVE-2000-{n:04d}" for n in range(1000, 1120)])
    assert [len(c.split(",")) for c in calls] == [50, 50, 20]


def test_epss_cache_ttl_and_unscored_cves_are_not_asked_again(db):
    clock, calls = Clock(), []
    source = enrichment.Enrichment(db, fetcher=epss_fetcher(calls), now=clock, sleep=lambda s: None)
    source.refresh_epss(["CVE-2000-0001", "CVE-2000-9999"])
    assert db.get_epss(["CVE-2000-0001"])["CVE-2000-0001"][0] == 0.5
    assert db.get_epss(["CVE-2000-9999"])["CVE-2000-9999"][0] is None
    source.refresh_epss(["CVE-2000-0001", "CVE-2000-9999"])
    assert len(calls) == 1
    clock.advance(hours=25)
    source.refresh_epss(["CVE-2000-0001"])
    assert len(calls) == 2


def test_kev_is_cached_and_marks_findings_without_changing_status(db):
    clock, calls = Clock(), []
    kev = {"vulnerabilities": [{"cveID": "CVE-2000-0001", "dateAdded": "2000-01-01"}]}

    def fetch(url):
        calls.append(url)
        return kev

    source = enrichment.Enrichment(db, fetcher=fetch, now=clock)
    source.refresh_kev()
    source.start_run()
    source.refresh_kev()
    assert calls == [enrichment.KEV_URL]  # within the TTL
    clock.advance(hours=25)
    source.start_run()
    source.refresh_kev()
    assert len(calls) == 2
    listed = cve_resolver.Finding("CVE-2000-0001", "curl", cve_resolver.ALREADY_FIXED)
    other = cve_resolver.Finding("CVE-2000-0002", "curl", cve_resolver.UNKNOWN)
    source.annotate([listed, other])
    assert (listed.kev, other.kev) == (True, False)
    assert (listed.status, other.status) == (cve_resolver.ALREADY_FIXED, cve_resolver.UNKNOWN)


def test_kev_is_unknown_not_no_without_a_catalogue(db):
    source = enrichment.Enrichment(db, now=Clock())
    finding = cve_resolver.Finding("CVE-2000-0001", "curl", cve_resolver.ALREADY_FIXED)
    source.annotate([finding])
    assert finding.kev is None and finding.epss is None


@pytest.mark.parametrize("document", [{"nope": 1}, [], {"vulnerabilities": [{}]}, {"data": None}])
def test_enrichment_failures_never_raise(db, document):
    source = enrichment.Enrichment(db, fetcher=lambda url: document, now=Clock())
    source.refresh_kev()
    source.refresh_epss(["CVE-2000-0001"])
    assert db.get_source_feed("kev") is None


def test_enrichment_network_failure_is_tried_once_per_run(db):
    calls = []

    def down(url):
        calls.append(url)
        raise OSError("connection refused")

    source = enrichment.Enrichment(db, fetcher=down, now=Clock(), sleep=lambda s: None)
    for _ in range(2):
        source.refresh_kev()
        source.refresh_epss(["CVE-2000-0001", "CVE-2000-0002"])
    assert len(calls) == 2  # one KEV, one EPSS


def test_a_hanging_enrichment_does_not_hold_the_server_up(db, pem_file, monkeypatch):
    import threading

    monkeypatch.setattr("ec2patcher.services.analysis_service.ENRICHMENT_BUDGET_SECONDS", 0.05)
    release = threading.Event()

    class Hanging(enrichment.Enrichment):
        def refresh_kev(self, blocked=None):
            release.wait(5)

    db.create_server("ip-10-0-0-1", "192.0.2.1", str(pem_file))
    db.save_report("report.json", {"ip-10-0-0-1": ["CVE-2026-63076"]}, "VALID")
    meta = make_metadata(None)
    resolver = cve_sources.SourceResolver(db, meta, priority=Hanging(db))
    service = AnalysisService(
        db, meta, runner=ScriptedSSH(), starter=lambda fn: fn(), sources=resolver
    )
    run = db.get_analysis_run(service.start(db.get_latest_report()))
    release.set()
    assert run.servers[0].status == "complete"
    assert run.servers[0].findings[0].status != cve_resolver.METADATA_UNAVAILABLE
    rows = db.list_run_events("analysis", run.id, 0, 1000)
    assert any("KEV/EPSS enrichment incomplete" in r["message"] for r in rows)


# --- report, export, confirm ------------------------------------------------------------------


def saved_row(db, **fields):
    db.merge_patch_report(
        "ip-10-0-0-1", lambda current: [PatchReportRow("ip-10-0-0-1", "CVE-2000-0001", **fields)]
    )


def test_report_row_keeps_source_kev_epss_and_reason(db):
    saved_row(db, source="oval", kev=True, epss=0.25, failure_reason="cve-json: HTTP 504")
    (row,) = db.list_patch_report()
    assert (row.source, row.kev, row.epss, row.failure_reason) == (
        "oval",
        True,
        0.25,
        "cve-json: HTTP 504",
    )


def test_analysis_fills_the_report_row_with_source_kev_epss_and_best_usn(db, pem_file):
    server = db.create_server(SERVER, IP, str(pem_file))
    db.store_usn_page(
        [
            usn_notices.parse_notice(
                {
                    "id": "USN-0001-1",
                    "title": "example-package vulnerability",
                    "published": "2000-01-01T00:00:00",
                    "cves_ids": ["CVE-2026-63076"],
                    "release_packages": {},
                }
            )
        ]
    )
    finding = cve_resolver.Finding(
        "CVE-2026-63076", "openssl", cve_resolver.ALREADY_FIXED, "fixed", "1.0-2", "1.0-1"
    )
    finding.resolution_source, finding.kev, finding.epss = "oval", True, 0.75
    analysis = make_analysis(db, server, plan=[], finding_list=[finding])
    patch_report.record_analysis(db, analysis.id)
    (row,) = db.list_patch_report()
    assert (row.usn, row.title) == ("USN-0001-1", "example-package vulnerability")
    assert (row.source, row.kev, row.epss, row.failure_reason) == ("oval", True, 0.75, None)


def test_a_pasted_usn_is_not_overwritten(db, pem_file):
    server = db.create_server(SERVER, IP, str(pem_file))
    db.store_usn_page(
        [dict(id="USN-0002-1", title="t", published=None, cves=["CVE-2026-63076"], packages=[])]
    )
    db.merge_patch_report(
        SERVER, lambda current: [PatchReportRow(SERVER, "CVE-2026-63076", usn="USN-0001-1")]
    )
    finding = cve_resolver.Finding("CVE-2026-63076", "openssl", cve_resolver.NOT_AFFECTED)
    patch_report.record_analysis(db, make_analysis(db, server, plan=[], finding_list=[finding]).id)
    assert db.list_patch_report()[0].usn == "USN-0001-1"


@pytest.fixture
def web(db_path):
    fake = FakeUbuntu()
    app = create_app(
        db_path=db_path, ssh_runner=fake, analysis_starter=lambda fn: fn(),
        patch_starter=lambda fn: fn(), patch_fetcher=FakeFetcher(),
        shutdown_handler=lambda: None,
    )  # fmt: skip
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client


def test_patch_report_page_and_export_show_the_new_columns(web, db_path):
    db = Database(db_path)
    saved_row(db, source="changelog", kev=False, epss=0.125, failure_reason="oval: blocked")
    page = web.get("/patch-report").text
    for column in ("<th>Source</th>", "<th>KEV</th>", "<th>EPSS</th>", "<th>Failure reason</th>"):
        assert column in page
    assert "<td>changelog</td>" in page and "<td>no</td>" in page and "0.125" in page
    wb = load_workbook(io.BytesIO(web.get("/patch-report/export.xlsx").content))
    rows = list(wb["Details"].values)
    row = dict(zip(rows[0], rows[1], strict=True))
    assert (row["Source"], row["KEV"], row["EPSS"]) == ("changelog", "no", 0.125)
    assert row["Failure Reason"] == "oval: blocked"


def unresolved_analysis(db, pem):
    server = db.create_server(SERVER, IP, str(pem))
    db.set_setting(patch_service.STAGING_SETTING, f"{pem.parent}/stage/${{server_name}}")
    from phase3_fixtures import findings

    unresolved = cve_resolver.Finding(
        "CVE-2000-0001", None, cve_resolver.METADATA_UNAVAILABLE, "unreachable",
        failure_reason="cve-json: HTTP 504",
    )  # fmt: skip
    analysis = make_analysis(db, server, finding_list=[*findings(), unresolved])
    db.update_analysis_run(analysis.run_id, status="completed", completed_at=START.isoformat())
    return analysis


def test_confirm_page_requires_the_unresolved_count_and_the_plan_still_applies(
    web, db_path, pem_file
):
    db = Database(db_path)
    analysis = unresolved_analysis(db, pem_file)
    url = f"/analysis/{analysis.run_id}/servers/{analysis.id}"
    report = web.get(url).text
    assert "Unresolved: 1 (cve-json: HTTP 504: 1)" in report and "key status" not in report
    assert f'href="{url}/approve"' in report  # not blocked
    assert '<td class="finding-source">' in report and "cve-json: HTTP 504" in report
    confirm = web.get(f"{url}/approve").text
    assert '<input type="checkbox" name="acknowledged_unresolved" value="1" required>' in confirm
    assert "1 CVE remains unresolved" in confirm
    refused = web.post(f"{url}/approve", data={"confirm": "yes"})
    assert refused.status_code == 409 and "leaves 1 CVE unresolved" in refused.text
    assert db.get_execution_for_analysis(analysis.id) is None
    wrong = web.post(f"{url}/approve", data={"confirm": "yes", "acknowledged_unresolved": "x"})
    assert wrong.status_code == 409
    done = web.post(
        f"{url}/approve",
        data={"confirm": "yes", "acknowledged_unresolved": "1", "skip_reboot": "1"},
        follow_redirects=False,
    )
    assert done.status_code == 303 and done.headers["location"].startswith("/patch/")
    assert db.get_execution_for_analysis(analysis.id) is not None


def test_patch_all_confirm_requires_the_unresolved_total(web, db_path, pem_file):
    db = Database(db_path)
    analysis = unresolved_analysis(db, pem_file)
    url = f"/analysis/{analysis.run_id}/patch-all"
    confirm = web.get(url).text
    assert 'name="acknowledged_unresolved" value="1" required' in confirm
    assert "1 unresolved CVE across these servers" in confirm
    data = {"confirm": "yes", "skip_reboot": "1", "analysis_id": [str(analysis.id)]}
    refused = web.post(url, data=data)
    assert refused.status_code == 409 and "leaves 1 CVE unresolved" in refused.text
    assert db.latest_queue_id(analysis.run_id) is None
    done = web.post(url, data={**data, "acknowledged_unresolved": "1"}, follow_redirects=False)
    assert done.status_code == 303 and "/patch-all/" in done.headers["location"]


def test_a_plan_without_unresolved_cves_needs_no_extra_confirm(web, db_path, pem_file):
    db = Database(db_path)
    server = db.create_server(SERVER, IP, str(pem_file))
    analysis = make_analysis(db, server)
    url = f"/analysis/{analysis.run_id}/servers/{analysis.id}/approve"
    assert 'name="acknowledged_unresolved"' not in web.get(url).text


def test_unresolved_reasons_are_grouped_most_frequent_first(db, pem_file):
    server = db.create_server(SERVER, IP, str(pem_file))
    rows = [
        cve_resolver.Finding(f"CVE-2000-000{n}", None, cve_resolver.METADATA_UNAVAILABLE, "x")
        for n in range(1, 4)
    ]
    rows[0].failure_reason = rows[1].failure_reason = "cve-json: HTTP 504"
    rows[2].failure_reason = "changelog: no candidate"
    analysis = make_analysis(db, server, plan=[], finding_list=rows)
    assert patch_service.not_checked_warning(analysis).startswith(
        "Unresolved: 4 (cve-json: HTTP 504: 2, changelog: no candidate: 1, not analyzed: 1)"
    )


def test_clear_security_cache_empties_the_source_data(db):
    oval = oval_feed.OvalFeed(db, fetcher=oval_fetcher(), now=Clock())
    oval.ensure("noble")
    db.store_usn_page([usn_notices.parse_notice(n) for n in NOTICES["notices"]])
    db.replace_kev([("CVE-2000-0001", None)], START.isoformat())
    db.put_epss([("CVE-2000-0001", 0.5, 0.5, START.isoformat())])
    resolver = chain(db, oval=oval)
    assert resolver.clear() is True
    assert oval.lookup("CVE-2000-0001", "noble") is None
    assert db.count_usn_notices() == 0 and db.get_epss(["CVE-2000-0001"]) == {}
    assert db.usn_candidates("CVE-2000-0003", "noble") == []
    assert resolver.clear() is False


# --- migration 19 -----------------------------------------------------------------------------


def legacy(db_path, version):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    for v in range(1, version + 1):
        conn.executescript(_MIGRATIONS[v])
    conn.execute(f"PRAGMA user_version = {version}")
    conn.execute(
        "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
        "VALUES ('keep', '10.0.0.1', '/k.pem', 't', 't')"
    )
    return conn


def columns(db_path, table):
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    conn.close()
    return {row[1] for row in rows}


NEW_TABLES = {
    "source_feeds", "oval_cve_packages", "usn_notices", "usn_cves", "usn_packages", "kev_cves",
    "epss_scores",
}  # fmt: skip


def tables(db_path):
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
    conn.close()
    return {row[0] for row in rows}


def test_fresh_database_reaches_v19_with_the_new_schema(db_path):
    Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 20
    conn.close()
    assert NEW_TABLES <= tables(db_path)
    finding_columns = columns(db_path, "cve_findings")
    assert {"resolution_source", "failure_reason", "kev", "epss"} <= finding_columns
    assert {"source", "failure_reason", "kev", "epss"} <= columns(db_path, "patch_report")
    assert "source_probes" in columns(db_path, "analysis_runs")


@pytest.mark.parametrize("version", [1, 18])
def test_upgrade_to_v19_keeps_existing_data(db_path, version):
    conn = legacy(db_path, version)
    if version == 18:
        conn.execute(
            "INSERT INTO patch_report (server_name, cve, status, updated_at) "
            "VALUES ('keep', 'CVE-2000-0001', 'patched', 't')"
        )
    conn.commit()
    conn.close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    check.close()
    assert db.get_server_by_name("keep").ip_address == "10.0.0.1"
    assert NEW_TABLES <= tables(db_path)
    if version == 18:
        (row,) = db.list_patch_report()
        assert (row.status, row.source, row.kev, row.epss) == ("patched", None, None, None)


def test_v19_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "oval_cve_packages" in _MIGRATIONS[19]
    assert all("oval_cve_packages" not in _MIGRATIONS[v] for v in range(1, 19))
