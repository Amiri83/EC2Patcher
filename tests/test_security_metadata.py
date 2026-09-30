"""Canonical Security JSON API mapping and online lookup behavior."""

import http.server
import json
import socket
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError

import pytest
from phase2_fixtures import facts_output, online_fetcher

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import security_metadata
from ec2patcher.services.security_metadata import (
    MetadataUnreachable,
    SecurityMetadata,
    classify_distro,
)
from ec2patcher.services.server_state import parse_facts


@pytest.mark.parametrize(
    "distro, expected",
    [
        ("focal", ("focal", False)),
        ("noble", ("noble", False)),
        ("esm-infra/focal", ("focal", True)),
        ("esm-apps/jammy", ("jammy", True)),
        ("esm-infra-legacy/bionic", ("bionic", True)),
        ("fips-updates/jammy", None),
        ("upstream", None),
        ("xenial", None),
    ],
)
def test_classify_distro(distro, expected):
    assert classify_distro(distro) == expected


def test_direct_canonical_lookup_maps_source_status_and_pocket():
    calls = []
    body = {
        "id": "CVE-2024-6387",
        "priority": "high",
        "packages": [
            {
                "name": "openssh",
                "statuses": [
                    {
                        "release_codename": "noble",
                        "status": "released",
                        "pocket": "security",
                        "description": "1:9.6p1-3ubuntu13.3",
                    },
                    {
                        "release_codename": "focal",
                        "status": "not-affected",
                        "pocket": None,
                        "description": "",
                    },
                    {
                        "release_codename": "noble",
                        "status": "released",
                        "pocket": "esm-infra",
                        "description": "1:9.6p1-3ubuntu13.4",
                    },
                    {
                        "release_codename": "upstream",
                        "status": "released",
                        "pocket": None,
                        "description": "1.0",
                    },
                ],
            }
        ],
    }

    def fetch(url):
        calls.append(url)
        return body

    meta = SecurityMetadata(fetcher=fetch)
    assert meta.ensure_fresh().available
    assert calls == []  # status checks never fetch
    record = meta.lookup("cve-2024-6387")
    assert calls == ["https://ubuntu.com/security/cves/CVE-2024-6387.json"]
    noble = record.for_release("noble")
    assert (noble[0].source, noble[0].status, noble[0].version, noble[0].distro) == (
        "openssh",
        "fixed",
        "1:9.6p1-3ubuntu13.3",
        "noble",
    )
    assert noble[0].priority == "High"
    assert (record.for_release("focal")[0].status, record.for_release("focal")[0].note) == (
        "not_affected",
        "not-affected; Ubuntu Security Team classified this CVE as of high priority.",
    )
    assert noble[1].is_pro and noble[1].distro == "esm-infra/noble"
    assert len(record.entries) == 3
    assert meta.lookup("CVE-2024-6387") is record
    assert len(calls) == 1
    assert meta.clear()
    assert meta.lookup("CVE-2024-6387") is not record
    assert len(calls) == 2
    assert meta.clear()  # memo has one entry again


def test_404_is_memoized_and_clear_requeries():
    calls = []

    def fetch(url):
        calls.append(url)
        raise HTTPError(url, 404, "Not Found", None, None)

    meta = SecurityMetadata(fetcher=fetch)
    assert meta.lookup("CVE-2026-99999") is None
    assert meta.lookup("CVE-2026-99999") is None
    assert len(calls) == 1
    assert meta.clear()
    assert meta.lookup("CVE-2026-99999") is None
    assert len(calls) == 2


def test_network_and_parse_failures_raise_without_memo():
    calls = []

    def fetch(url):
        calls.append(url)
        raise OSError("offline")

    meta = SecurityMetadata(fetcher=fetch, breaker_threshold=2)
    with pytest.raises(OSError, match="offline"):
        meta.lookup("CVE-2024-6387")
    assert len(calls) == 3  # MAX_ATTEMPTS per lookup
    with pytest.raises(OSError, match="offline"):
        meta.lookup("CVE-2024-6387")  # not memoized: asked again (2nd consecutive failure)
    with pytest.raises(MetadataUnreachable, match="offline"):
        meta.lookup("CVE-2024-6387")
    assert len(calls) == 6  # circuit breaker: no further HTTP attempt
    assert meta.run_outcomes() == {"CVE-2024-6387": "failed"}
    meta.start_run()
    assert meta.run_outcomes() == {}
    with pytest.raises(OSError, match="offline"):
        meta.lookup("CVE-2024-6387")
    assert len(calls) == 9
    meta.start_run()
    meta.fetcher = lambda url: {"id": "CVE-2024-6387"}
    with pytest.raises(ValueError, match="packages list"):
        meta.lookup("CVE-2024-6387")


def test_no_bulk_index_reference_in_service():
    source = (
        Path(__file__).parents[1] / "src/ec2patcher/services/security_metadata.py"
    ).read_text()
    assert "security-metadata.canonical.com/vex/vex-all" not in source
    assert "build_index" not in source
    assert "tarfile" not in source
    assert "sqlite3" not in source


def test_fixture_lookup_is_online_per_cve():
    calls = []
    meta = SecurityMetadata(fetcher=online_fetcher(calls=calls))
    record = meta.lookup("CVE-2026-63076")
    assert record.for_release("noble")[0].version == "3.0.13-0ubuntu3.6"
    assert calls == ["https://ubuntu.com/security/cves/CVE-2026-63076.json"]


def test_fix_shipped_in_original_release_resolves_as_standard_archive_fix():
    """Canonical reports a fix present at GA under the "security" pocket; it resolves."""
    body = {
        "id": "CVE-2026-50001",
        "packages": [
            {
                "name": "sudo",
                "statuses": [
                    {
                        "release_codename": "noble",
                        "status": "released",
                        "pocket": "security",
                        "description": "1.9.15p5-3ubuntu5",
                    }
                ],
            }
        ],
    }
    meta = SecurityMetadata(fetcher=lambda url: body)
    record = meta.lookup("CVE-2026-50001")
    (entry,) = record.for_release("noble")
    assert (entry.distro, entry.status, entry.is_pro) == ("noble", "fixed", False)
    findings = cr.resolve_all(["CVE-2026-50001"], meta.lookup, parse_facts(facts_output()))
    assert [(f.source, f.status) for f in findings] == [("sudo", cr.ALREADY_FIXED)]


def test_network_error_trips_breaker_for_rest_of_run_and_clear_resets():
    calls = []

    def fetch(url):
        calls.append(url)
        raise OSError("connection timed out")

    meta = SecurityMetadata(fetcher=fetch)
    cves = [f"CVE-2026-5000{n}" for n in range(1, 7)]
    findings = cr.resolve_all(cves, meta.lookup, parse_facts(facts_output()))
    # BREAKER_THRESHOLD (3) consecutive lookups, each tried MAX_ATTEMPTS (3) times.
    assert calls == [
        f"https://ubuntu.com/security/cves/{cve}.json" for cve in cves[:3] for _ in "123"
    ]
    assert [f.cve for f in findings] == cves  # every CVE still surfaces
    assert all(f.status == cr.METADATA_UNAVAILABLE for f in findings)
    assert all("Canonical metadata lookup failed" in f.detail for f in findings)
    assert all("connection timed out" in f.detail for f in findings[:3])
    assert all("skipped after 3 consecutive network errors" in f.detail for f in findings[3:])
    assert meta.run_outcomes() == dict.fromkeys(cves, "failed")

    assert meta.clear()  # Clear Security Cache un-blocks the network
    with pytest.raises(OSError, match="connection timed out"):
        meta.lookup("CVE-2026-50002")
    assert len(calls) == 12


@pytest.mark.parametrize(
    "timeout_exc",
    [
        TimeoutError("timed out"),  # read timeout from getresponse()/response.read()
        TimeoutError("timed out"),  # alias of TimeoutError since Python 3.10
        URLError(TimeoutError("timed out")),  # connect timeout, wrapped by urlopen
    ],
    ids=["TimeoutError", "socket.timeout", "URLError(TimeoutError)"],
)
def test_request_timeouts_trip_breaker_only_after_consecutive_failures(timeout_exc):
    calls = []

    def fetch(url):
        calls.append(url)
        raise timeout_exc

    meta = SecurityMetadata(fetcher=fetch)
    for cve in ("CVE-2026-50001", "CVE-2026-50002"):
        with pytest.raises(type(timeout_exc)):
            meta.lookup(cve)
        assert not meta.breaker_open  # one (or two) failed lookups never trip it
    with pytest.raises(type(timeout_exc)):
        meta.lookup("CVE-2026-50003")
    assert meta.breaker_open
    for cve in ("CVE-2026-50004", "CVE-2026-50005"):
        with pytest.raises(MetadataUnreachable, match="skipped after 3 consecutive"):
            meta.lookup(cve)
    assert len(calls) == 9  # no HTTP after the breaker tripped

    meta.start_run()
    with pytest.raises(type(timeout_exc)):
        meta.lookup("CVE-2026-50004")
    assert len(calls) == 12


def test_real_http_get_timeout_trips_breaker(monkeypatch):
    """A server that accepts TCP but never answers makes urlopen time out for real."""
    monkeypatch.setattr(security_metadata, "REQUEST_TIMEOUT_SECONDS", 0.2)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(8)  # kernel completes the handshake; nothing ever replies
    url = f"http://127.0.0.1:{server.getsockname()[1]}/cve.json"
    calls = []

    def fetch(_url):
        calls.append(_url)
        return security_metadata.http_get(url)

    try:
        meta = SecurityMetadata(fetcher=fetch, attempts=1, breaker_threshold=2)
        for cve in ("CVE-2026-50001", "CVE-2026-50002"):
            with pytest.raises((TimeoutError, URLError)) as excinfo:
                meta.lookup(cve)
            assert isinstance(excinfo.value, OSError)
        with pytest.raises(MetadataUnreachable):
            meta.lookup("CVE-2026-50003")
        assert len(calls) == 2
    finally:
        server.close()


def test_canonical_config_from_environment(monkeypatch):
    assert config.get_canonical_timeout() is None  # unset: module defaults apply
    assert config.get_canonical_cache_ttl() is None
    assert config.get_canonical_breaker_threshold() is None
    monkeypatch.setenv(config.CANONICAL_TIMEOUT_ENV, "45")
    monkeypatch.setenv(config.CANONICAL_CACHE_TTL_ENV, "0.5")
    monkeypatch.setenv(config.CANONICAL_BREAKER_ENV, "5")
    assert config.get_canonical_timeout() == 45
    assert config.get_canonical_cache_ttl() == timedelta(minutes=30)
    assert config.get_canonical_breaker_threshold() == 5
    for bad in ("0", "nan", "soon"):
        monkeypatch.setenv(config.CANONICAL_TIMEOUT_ENV, bad)
        with pytest.raises(ValueError):
            config.get_canonical_timeout()


def test_default_fetcher_uses_configured_timeout(monkeypatch):
    seen = []
    monkeypatch.setattr(
        security_metadata, "http_get", lambda url, timeout=None: seen.append(timeout) or {}
    )
    assert SecurityMetadata().timeout == 20  # default per-request timeout
    meta = SecurityMetadata(timeout=7)
    with pytest.raises(ValueError):
        meta.lookup("CVE-2026-50001")
    assert seen == [7]


def test_http_5xx_is_retried_and_trips_breaker_but_parse_errors_do_not():
    calls = []

    def fetch(url):
        calls.append(url)
        raise HTTPError(url, 503, "Service Unavailable", None, None)

    meta = SecurityMetadata(fetcher=fetch, breaker_threshold=1)
    with pytest.raises(HTTPError):
        meta.lookup("CVE-2026-50001")
    with pytest.raises(MetadataUnreachable):
        meta.lookup("CVE-2026-50002")
    assert len(calls) == 3  # retried, then the breaker skipped the second CVE

    meta = SecurityMetadata(fetcher=lambda url: {"id": "other"}, breaker_threshold=1)
    for cve in ("CVE-2026-50001", "CVE-2026-50002"):
        with pytest.raises(ValueError, match="Invalid Canonical response"):
            meta.lookup(cve)
    assert not meta.breaker_open


def test_http_4xx_other_than_429_is_not_retried():
    calls = []

    def fetch(url):
        calls.append(url)
        raise HTTPError(url, 403, "Forbidden", None, None)

    meta = SecurityMetadata(fetcher=fetch)
    with pytest.raises(HTTPError):
        meta.lookup("CVE-2026-50001")
    assert len(calls) == 1


# --- retry, circuit breaker and SQLite cache --------------------------------------------

SUDO_DOC = {
    "id": "CVE-2026-50001",
    "packages": [
        {
            "name": "sudo",
            "statuses": [
                {
                    "release_codename": "noble",
                    "status": "released",
                    "pocket": "security",
                    "description": "1.9.15p5-3ubuntu5",
                }
            ],
        }
    ],
}
T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now=T0):
        self.value = now

    def __call__(self):
        return self.value


def doc_for(cve):
    return {**SUDO_DOC, "id": cve}


def failing_fetch(url):
    raise URLError(TimeoutError("timed out"))


def test_one_timeout_then_success_is_retried_without_tripping_breaker():
    calls, sleeps = [], []
    replies = [TimeoutError("timed out")]

    def fetch(url):
        calls.append(url)
        if replies:
            raise replies.pop(0)
        return SUDO_DOC

    meta = SecurityMetadata(fetcher=fetch, backoff=1.0, sleep=sleeps.append)
    findings = cr.resolve_all(["CVE-2026-50001"], meta.lookup, parse_facts(facts_output()))
    assert [(f.source, f.status) for f in findings] == [("sudo", cr.ALREADY_FIXED)]
    assert len(calls) == 2 and sleeps == [1.0]  # one backoff, then the retry succeeded
    assert not meta.breaker_open
    assert meta.run_outcomes() == {"CVE-2026-50001": "ok"}


def test_backoff_doubles_between_attempts():
    sleeps = []
    meta = SecurityMetadata(fetcher=failing_fetch, attempts=4, backoff=0.5, sleep=sleeps.append)
    with pytest.raises(OSError):
        meta.lookup("CVE-2026-50001")
    assert sleeps == [0.5, 1.0, 2.0]


def test_success_between_failures_resets_the_consecutive_count():
    ok = {"CVE-2026-50002", "CVE-2026-50004"}

    def fetch(url):
        cve = url.rsplit("/", 1)[1].removesuffix(".json")
        if cve in ok:
            return doc_for(cve)
        raise TimeoutError("timed out")

    meta = SecurityMetadata(fetcher=fetch, breaker_threshold=2)
    cves = [f"CVE-2026-5000{n}" for n in range(1, 6)]
    cr.resolve_all(cves, meta.lookup, parse_facts(facts_output()))
    assert not meta.breaker_open  # never two failures in a row
    assert meta.run_outcomes() == {
        "CVE-2026-50001": "failed", "CVE-2026-50002": "ok", "CVE-2026-50003": "failed",
        "CVE-2026-50004": "ok", "CVE-2026-50005": "failed",
    }  # fmt: skip


def test_consecutive_failures_trip_breaker_and_cached_copy_is_used(tmp_path):
    clock = Clock()
    cache = tmp_path / "cache.db"
    # A previous run cached CVE-2026-50005, 30 hours ago (older than the 24 h TTL).
    warm = SecurityMetadata(cache, fetcher=lambda url: doc_for("CVE-2026-50005"), now=clock)
    warm.lookup("CVE-2026-50005")
    assert Database(cache).get_cve_metadata("CVE-2026-50005") is not None
    clock.value = T0 + timedelta(hours=30)

    calls = []

    def fetch(url):
        calls.append(url)
        raise TimeoutError("timed out")

    meta = SecurityMetadata(cache, fetcher=fetch, now=clock)
    cves = [f"CVE-2026-5000{n}" for n in range(1, 7)]
    findings = cr.resolve_all(cves, meta.lookup, parse_facts(facts_output()))
    assert meta.breaker_open
    assert len(calls) == 9  # 3 lookups x 3 attempts; the remaining CVEs skip HTTP
    by_cve = {f.cve: f for f in findings}
    for cve in ("CVE-2026-50004", "CVE-2026-50006"):  # skipped, nothing cached
        assert by_cve[cve].status == cr.METADATA_UNAVAILABLE
        assert "skipped after 3 consecutive network errors" in by_cve[cve].detail
    cached = by_cve["CVE-2026-50005"]  # skipped too, but a cached copy exists
    assert (cached.source, cached.status) == ("sudo", cr.ALREADY_FIXED)
    assert "Canonical metadata from cache (age 1d 6h)" in cached.detail
    assert meta.run_outcomes() == {
        **dict.fromkeys(cves, "failed"), "CVE-2026-50005": "cached",
    }  # fmt: skip


def test_cache_fallback_after_retries_marks_age(tmp_path):
    clock = Clock()
    cache = tmp_path / "cache.db"
    SecurityMetadata(cache, fetcher=lambda url: SUDO_DOC, now=clock).lookup("CVE-2026-50001")
    clock.value = T0 + timedelta(hours=26, minutes=5)

    calls = []

    def fetch(url):
        calls.append(url)
        raise URLError("Temporary failure in name resolution")

    meta = SecurityMetadata(cache, fetcher=fetch, now=clock)
    record = meta.lookup("CVE-2026-50001")
    assert len(calls) == 3  # expired copy -> refresh attempted (with retries) first
    assert record.cache_note == "Canonical metadata from cache (age 1d 2h)"
    (finding,) = cr.resolve_all(["CVE-2026-50001"], meta.lookup, parse_facts(facts_output()))
    assert finding.status == cr.ALREADY_FIXED  # not METADATA_UNAVAILABLE
    assert finding.detail.endswith("(Canonical metadata from cache (age 1d 2h))")
    assert meta.run_outcomes() == {"CVE-2026-50001": "cached"}


def test_fresh_cache_is_used_without_request_and_expired_cache_is_refreshed(tmp_path):
    clock = Clock()
    cache = tmp_path / "cache.db"
    db = Database(cache)
    calls = []

    def fetch(url):
        calls.append(url)
        return SUDO_DOC

    SecurityMetadata(db, fetcher=fetch, now=clock).lookup("CVE-2026-50001")
    document, fetched_at = db.get_cve_metadata("CVE-2026-50001")
    assert (json.loads(document), fetched_at) == (SUDO_DOC, T0.isoformat())

    clock.value = T0 + timedelta(hours=23)  # new process, within the TTL: no request
    record = SecurityMetadata(cache, fetcher=fetch, now=clock).lookup("CVE-2026-50001")
    assert len(calls) == 1 and record.cache_note is None

    clock.value = T0 + timedelta(hours=25)  # expired: refreshed from ubuntu.com
    meta = SecurityMetadata(cache, fetcher=fetch, now=clock)
    assert meta.lookup("CVE-2026-50001").cache_note is None
    assert len(calls) == 2
    assert db.get_cve_metadata("CVE-2026-50001")[1] == clock.value.isoformat()
    assert meta.clear()  # clear() empties the table too
    assert db.get_cve_metadata("CVE-2026-50001") is None


def test_404_is_cached_as_null_for_offline_lookups(tmp_path):
    cache = tmp_path / "cache.db"
    SecurityMetadata(cache, fetcher=online_fetcher(docs=[])).lookup("CVE-2026-99999")
    document, _ = Database(cache).get_cve_metadata("CVE-2026-99999")
    assert document is None  # NULL document = Canonical confirmed 404
    offline = SecurityMetadata(cache, fetcher=failing_fetch)
    assert offline.lookup("CVE-2026-99999", network=False) is None
    with pytest.raises(MetadataUnreachable, match="only failed lookups are retried"):
        offline.lookup("CVE-2026-88888", network=False)
    assert offline.run_outcomes() == {}  # offline lookups are not tallied


def test_corrupt_cache_entry_is_ignored(tmp_path):
    db = Database(tmp_path / "cache.db")
    db.put_cve_metadata("CVE-2026-50001", "{not json", T0.isoformat())
    meta = SecurityMetadata(db, fetcher=lambda url: SUDO_DOC)
    assert meta.lookup("CVE-2026-50001").for_release("noble")[0].source == "sudo"
    assert json.loads(db.get_cve_metadata("CVE-2026-50001")[0]) == SUDO_DOC  # rewritten


def test_failures_are_never_cached(tmp_path):
    db = Database(tmp_path / "cache.db")

    def server_error(url):
        raise HTTPError(url, 503, "Service Unavailable", None, None)

    for fetch in (failing_fetch, server_error, lambda url: {"id": "other"}):
        meta = SecurityMetadata(db, fetcher=fetch)
        with pytest.raises((OSError, ValueError)):
            meta.lookup("CVE-2026-50001")
    assert db.get_cve_metadata("CVE-2026-50001") is None


@pytest.mark.parametrize("broken", ["get_cve_metadata", "put_cve_metadata"])
def test_cache_errors_fall_back_to_network(tmp_path, monkeypatch, broken):
    def fail(*args):
        raise sqlite3.OperationalError("database is locked")

    db = Database(tmp_path / "cache.db")
    monkeypatch.setattr(db, broken, fail)
    calls = []
    meta = SecurityMetadata(db, fetcher=online_fetcher(calls=calls))
    assert meta.lookup("CVE-2026-63076").for_release("noble")  # the lookup still succeeds
    assert len(calls) == 1
    assert meta.run_outcomes() == {"CVE-2026-63076": "ok"}


def test_unopenable_cache_database_falls_back_to_network(tmp_path):
    not_a_db = tmp_path / "cache.db"
    not_a_db.write_text("this is not a SQLite database")
    meta = SecurityMetadata(not_a_db, fetcher=lambda url: SUDO_DOC)
    assert meta.lookup("CVE-2026-50001").for_release("noble")[0].source == "sudo"
    meta.clear()  # never raises either


def test_sqlite_cache_is_shared_across_instances_and_force_refresh_bypasses_it(tmp_path):
    db = Database(tmp_path / "cache.db")
    calls = []
    SecurityMetadata(db, fetcher=online_fetcher(calls=calls)).lookup("CVE-2026-63076")
    meta = SecurityMetadata(db, fetcher=online_fetcher(calls=calls))
    meta.lookup("CVE-2026-63076")
    assert len(calls) == 1  # loaded from SQLite, no request
    meta.lookup("CVE-2026-63076", force_refresh=True)
    assert len(calls) == 2  # bypasses memo and SQLite
    meta.lookup("CVE-2026-63076")
    assert len(calls) == 2  # memoized again


def test_force_refresh_run_fetches_each_cve_once_and_only_the_given_cves(tmp_path):
    db = Database(tmp_path / "cache.db")
    calls = []
    meta = SecurityMetadata(db, fetcher=online_fetcher(calls=calls))
    for cve in ("CVE-2026-63076", "CVE-2026-63075"):
        meta.lookup(cve)
    assert len(calls) == 2

    meta.start_run(force_refresh=True, cves=["cve-2026-63076"])
    for _ in range(3):  # e.g. one lookup per server reporting the CVE
        meta.lookup("CVE-2026-63076")
        meta.lookup("CVE-2026-63075")
    # forced once; the other CVE comes from the memo
    assert calls[2:] == [security_metadata.API_URL.format(cve="CVE-2026-63076")]

    meta.start_run(force_refresh=True)  # every CVE
    meta.lookup("CVE-2026-63075")
    meta.lookup("CVE-2026-63076")
    assert len(calls) == 5
    meta.start_run()  # a normal run: memo / cache again
    meta.lookup("CVE-2026-63075")
    assert len(calls) == 5


def test_force_refresh_failure_falls_back_to_cached_copy(tmp_path):
    clock = Clock()
    db = Database(tmp_path / "cache.db")
    SecurityMetadata(db, fetcher=lambda url: SUDO_DOC, now=clock).lookup("CVE-2026-50001")
    clock.value = T0 + timedelta(minutes=5)
    meta = SecurityMetadata(db, fetcher=failing_fetch, now=clock)
    record = meta.lookup("CVE-2026-50001", force_refresh=True)
    assert record.cache_note == "Canonical metadata from cache (age 5m)"
    assert meta.run_outcomes() == {"CVE-2026-50001": "cached"}


def investigating_doc(cve):
    doc = doc_for(cve)
    return {
        **doc,
        "packages": [
            *doc["packages"],
            {
                "name": "curl",
                "statuses": [
                    {"release_codename": "noble", "status": "needs-triage", "pocket": None}
                ],
            },
        ],
    }


@pytest.mark.parametrize(
    "document, ttl_hours",
    [(SUDO_DOC, 24), (investigating_doc("CVE-2026-50001"), 1), (None, 24)],
    ids=["settled", "under_investigation", "confirmed-404"],
)
def test_cache_ttl_is_24h_when_settled_and_1h_under_investigation(tmp_path, document, ttl_hours):
    clock = Clock()
    db = Database(tmp_path / "cache.db")
    stored = None if document is None else json.dumps(document)
    db.put_cve_metadata("CVE-2026-50001", stored, T0.isoformat())
    calls = []

    def fetch(url):
        calls.append(url)
        return SUDO_DOC

    clock.value = T0 + timedelta(hours=ttl_hours) - timedelta(minutes=1)
    SecurityMetadata(db, fetcher=fetch, now=clock).lookup("CVE-2026-50001")
    assert calls == []  # still fresh
    clock.value = T0 + timedelta(hours=ttl_hours)
    SecurityMetadata(db, fetcher=fetch, now=clock).lookup("CVE-2026-50001")
    assert len(calls) == 1  # expired: refreshed


def test_memo_expires_with_the_cache_ttl(tmp_path):
    clock = Clock()
    calls = []

    def fetch(url):
        calls.append(url)
        return investigating_doc("CVE-2026-50001")

    meta = SecurityMetadata(tmp_path / "cache.db", fetcher=fetch, now=clock)
    meta.lookup("CVE-2026-50001")
    meta.lookup("CVE-2026-50001")
    assert len(calls) == 1
    clock.value = T0 + timedelta(hours=1)  # a long-running process: memo is not forever
    meta.lookup("CVE-2026-50001")
    assert len(calls) == 2


# --- pacing and circuit breaker ---------------------------------------------------------


class FakeMonotonic:
    """A monotonic clock that only advances when the code under test sleeps."""

    def __init__(self):
        self.value, self.sleeps = 100.0, []

    def __call__(self):
        return self.value

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.value += seconds


def test_pacing_sleeps_only_between_outbound_fetches(tmp_path):
    clock = FakeMonotonic()
    db = Database(tmp_path / "cache.db")
    db.put_cve_metadata("CVE-2026-63075", None, datetime.now(timezone.utc).isoformat())
    calls = []
    meta = SecurityMetadata(
        db, fetcher=online_fetcher(calls=calls), pace=1.0, sleep=clock.sleep, monotonic=clock
    )
    meta.lookup("CVE-2026-63076")
    assert clock.sleeps == []  # the first fetch of a run never waits
    meta.lookup("CVE-2026-63076")  # memo hit
    meta.lookup("CVE-2026-63075")  # SQLite cache hit
    assert clock.sleeps == [] and len(calls) == 1
    meta.lookup("CVE-2026-54874")
    assert clock.sleeps == [1.0] and len(calls) == 2  # ~1 s after the previous request

    clock.value += 0.4  # time passes between lookups: only the rest is waited
    meta.lookup("CVE-2026-10004")
    assert clock.sleeps == pytest.approx([1.0, 0.6])
    clock.value += 5
    meta.lookup("CVE-2026-10005")
    assert clock.sleeps == pytest.approx([1.0, 0.6])  # already more than 1 s apart

    meta.start_run()  # resets the pacing clock: the first fetch of the run does not wait
    meta.lookup("CVE-2026-10006", force_refresh=True)
    assert clock.sleeps == pytest.approx([1.0, 0.6])


def test_pacing_applies_to_retries_after_short_backoff():
    clock = FakeMonotonic()
    meta = SecurityMetadata(
        fetcher=failing_fetch, pace=1.0, backoff=0.25, sleep=clock.sleep, monotonic=clock
    )
    with pytest.raises(OSError):
        meta.lookup("CVE-2026-50001")
    # attempt 1 immediately; backoff 0.25 + pacing 0.75; backoff 0.5 + pacing 0.5
    assert clock.sleeps == [0.25, 0.75, 0.5, 0.5]


def test_default_pacing_is_one_second():
    # conftest zeroes PACE_SECONDS for speed; the dataclass default captured it at import.
    assert security_metadata.MetadataStatus(available=True).pace_seconds == 1.0


def test_breaker_trips_after_three_consecutive_failures_and_success_resets_count():
    replies = {  # CVE -> fails?
        "CVE-2026-50001": True, "CVE-2026-50002": True, "CVE-2026-50003": False,
        "CVE-2026-50004": True, "CVE-2026-50005": True, "CVE-2026-50006": False,
        "CVE-2026-50007": True, "CVE-2026-50008": True, "CVE-2026-50009": True,
        "CVE-2026-50010": False,
    }  # fmt: skip
    calls = []

    def fetch(url):
        cve = url.rsplit("/", 1)[1].removesuffix(".json")
        calls.append(cve)
        if replies[cve]:
            raise TimeoutError("timed out")
        return doc_for(cve)

    meta = SecurityMetadata(fetcher=fetch, attempts=1)
    for cve in list(replies)[:6]:
        try:
            meta.lookup(cve)
        except OSError:
            pass
        assert not meta.breaker_open  # two failures, then a success resets the count
    for cve in ("CVE-2026-50007", "CVE-2026-50008"):
        with pytest.raises(TimeoutError):
            meta.lookup(cve)
    assert not meta.breaker_open
    with pytest.raises(TimeoutError):
        meta.lookup("CVE-2026-50009")
    assert meta.breaker_open  # third consecutive failure
    with pytest.raises(MetadataUnreachable):
        meta.lookup("CVE-2026-50010")  # skipped although it would have succeeded
    assert "CVE-2026-50010" not in calls

    meta.start_run()  # resets the breaker and the consecutive-failure count
    assert not meta.breaker_open
    for cve in ("CVE-2026-50007", "CVE-2026-50008"):
        with pytest.raises(TimeoutError):
            meta.lookup(cve)
    assert not meta.breaker_open  # counting started again from zero
    assert meta.lookup("CVE-2026-50010") is not None


# --- proxy ------------------------------------------------------------------------------


class _Recorder(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 - http.server API
        self.server.paths.append(self.path)
        body = json.dumps(SUDO_DOC).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def local_http():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Recorder)
    server.paths = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


def test_http_get_honors_proxy_environment(local_http, monkeypatch):
    for name in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{local_http.server_port}")
    doc = security_metadata.http_get("http://ubuntu.example/security/cves/CVE-2026-50001.json")
    assert doc == SUDO_DOC
    # The proxy received the absolute URL, i.e. the request went through it.
    assert local_http.paths == ["http://ubuntu.example/security/cves/CVE-2026-50001.json"]


def test_http_get_honors_no_proxy(local_http, monkeypatch):
    dead = socket.socket()
    dead.bind(("127.0.0.1", 0))  # bound, never listening: a proxy that refuses connections
    try:
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{dead.getsockname()[1]}")
        monkeypatch.setenv("no_proxy", "127.0.0.1")
        url = f"http://127.0.0.1:{local_http.server_port}/security/cves/CVE-2026-50001.json"
        assert security_metadata.http_get(url) == SUDO_DOC
        assert local_http.paths == ["/security/cves/CVE-2026-50001.json"]  # direct request
    finally:
        dead.close()
