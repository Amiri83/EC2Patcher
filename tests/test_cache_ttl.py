"""NVD key badge source / unknown reason / 429 retry / start-up re-check, cache TTLs from
Settings (schema v15 for the per-run cache statistics), cache badges and per-run
"from cache / live" counts. Never the live network: fake transports only."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from amazon_fixtures import RELEASEVER, FakeCdn
from fastapi.testclient import TestClient
from nvd_fixtures import REPORT_CVES, FakeNvd, make_client, response
from phase2_fixtures import ScriptedSSH, make_metadata
from test_analysis import BAD, BAD_IP, GOOD, GOOD_IP, sync
from test_ssh_user import _legacy_db, columns

from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import CacheStats
from ec2patcher.services import amazon_updateinfo, cache_settings, nvd, security_metadata
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.security_metadata import SecurityMetadata

API_KEY = "fake-nvd-key-0123456789abcdef"  # fake test key
ENV_KEY = "fake-env-key-fedcba9876543210"  # fake test key
NOW = datetime(2026, 10, 4, 12, 30, tzinfo=timezone.utc)
OK_REPLY = (200, {}, response())
CVE = "CVE-2026-63076"


class Clock:
    def __init__(self, now=NOW):
        self.now = now

    def __call__(self):
        return self.now


def key_client(db_path, *replies, sleeps=None, now=None):
    fake = FakeNvd(replies=list(replies))
    sleep = sleeps.append if sleeps is not None else (lambda s: None)
    client = nvd.NvdClient(db_path, transport=fake, sleep=sleep, now=now or (lambda: NOW))
    return client, fake


def web(db_path, client=None, **kwargs):
    app = create_app(db_path=db_path, nvd_client=client, shutdown_handler=lambda: None, **kwargs)
    return TestClient(app, base_url="http://127.0.0.1")


def badge(page: str) -> str:
    start = page.rindex("<span", 0, page.index("nvd-key-badge"))
    return page[start : page.index("</span>", start)]


def cache_badge(page: str, name: str) -> str:
    start = page.index(f'data-cache="{name}"')
    start = page.rindex("<a", 0, start)
    return page[start : page.index("</a>", start)]


def store_check(db_path, **check):
    Database(db_path).set_setting(nvd.KEY_CHECK_SETTING, json.dumps(check))


def assert_no_key(*texts):
    for text in texts:
        assert API_KEY not in text and ENV_KEY not in text and API_KEY[-6:] not in text


# --- A1. the badge always shows the key source ---------------------------------------------


@pytest.mark.parametrize("result", ["valid", "rejected", "unknown", None])
@pytest.mark.parametrize(
    "source, text",
    [("settings", "from Settings (DB)"), ("env", "from NVD_API_KEY env var")],
)
def test_badge_shows_the_key_source_in_every_state(db_path, monkeypatch, result, source, text):
    if source == "env":
        monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    else:
        with web(db_path, key_client(db_path, OK_REPLY)[0]) as c:
            c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        Database(db_path).delete_setting(nvd.KEY_CHECK_SETTING)
    if result is not None:  # None: never checked
        store_check(db_path, result=result, checked_at=NOW.isoformat(), source=source)
    client, fake = key_client(db_path)
    with web(db_path, client) as c:
        for url in ("/reports", "/settings"):
            page = c.get(url).text
            assert text in badge(page), (url, badge(page))
            assert f'data-nvd-key-source="{source}"' in badge(page)
            assert_no_key(page)
    assert fake.calls == []


def test_unreadable_settings_key_badge_names_its_source(db_path, tmp_path):
    with web(db_path) as c:
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
    (tmp_path / "config" / "secret.key").unlink()
    with web(db_path) as c:
        page = c.get("/reports").text
        assert 'data-nvd-key="unreadable"' in badge(page)
        assert "from Settings (DB)" in badge(page)


def test_no_key_badge_names_no_source(db_path):
    with web(db_path, key_client(db_path)[0]) as c:
        page = c.get("/reports").text
    assert "NVD API key: not set" in badge(page) and "from " not in badge(page)


# --- A2. unknown reason, 429 / 5xx retry --------------------------------------------------


def test_unknown_reason_in_the_settings_notice_and_the_tooltip(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    client, fake = key_client(db_path, OSError("Connection refused"))
    with web(db_path, client) as c:
        page = c.get("/settings").text
        assert "Not checked yet" in badge(page) and 'data-nvd-key-reason="not checked yet"' in page
        r = c.post("/settings/nvd-key", data={"action": "test"})
        notice = "could not be checked. Reason: network error: Connection refused."
        assert notice in r.text
        assert "NVD could not be reached at the last check" in badge(r.text)
        assert "network error: Connection refused" in badge(r.text)
        assert "from NVD_API_KEY env var" in badge(r.text)
    # the reason is persisted: a new process shows it without any request
    client, fake = key_client(db_path)
    with web(db_path, client) as c:
        assert "network error: Connection refused" in badge(c.get("/reports").text)
    assert fake.calls == []


def test_unknown_reason_http_code(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    client, _ = key_client(db_path, (418, {}, b""))
    assert client.check_key() == nvd.KEY_UNKNOWN and client.key_reason == "HTTP 418"
    stored = json.loads(Database(db_path).get_setting(nvd.KEY_CHECK_SETTING))
    assert stored["reason"] == "HTTP 418"


def test_valid_or_rejected_check_has_no_reason(db_path):
    client, _ = key_client(db_path, OSError("down"), OK_REPLY)
    client.use_settings_key(API_KEY)
    client.check_key()
    assert client.key_reason == "network error: down"
    assert client.check_key() == nvd.KEY_VALID and client.key_reason is None
    assert "reason" not in json.loads(Database(db_path).get_setting(nvd.KEY_CHECK_SETTING))


def test_reason_never_contains_the_key(db_path):
    client, _ = key_client(db_path, OSError(f"proxy said: bad header {API_KEY}"))
    client.use_settings_key(API_KEY)
    client.check_key()
    assert API_KEY not in client.key_reason and "***" in client.key_reason
    assert API_KEY not in Database(db_path).get_setting(nvd.KEY_CHECK_SETTING)


def test_429_is_retried_once_honouring_retry_after(db_path):
    sleeps = []
    client, fake = key_client(db_path, (429, {"Retry-After": "7"}, b""), OK_REPLY, sleeps=sleeps)
    client.use_settings_key(API_KEY)
    assert client.check_key() == nvd.KEY_VALID
    assert len(fake.calls) == 2 and 7.0 in sleeps
    assert all(headers["apiKey"] == API_KEY for _, headers in fake.calls)


def test_5xx_is_retried_once_then_unknown_with_the_code(db_path):
    sleeps = []
    client, fake = key_client(db_path, (502, {}, b""), (503, {}, b""), OK_REPLY, sleeps=sleeps)
    client.use_settings_key(API_KEY)
    assert client.check_key() == nvd.KEY_UNKNOWN
    assert len(fake.calls) == 2  # exactly one retry; the third reply is never requested
    assert client.key_reason == "HTTP 503 (after a retry)" and sleeps


def test_retry_after_is_capped(db_path):
    sleeps = []
    client, _ = key_client(db_path, (429, {"Retry-After": "9999"}, b""), OK_REPLY, sleeps=sleeps)
    client.use_settings_key(API_KEY)
    client.check_key()
    assert max(sleeps) == nvd.MAX_RETRY_AFTER


@pytest.mark.parametrize("reply", [OSError("down"), (404, {}, b"Not Found"), (403, {}, b"")])
def test_no_retry_for_network_errors_404_or_403(db_path, reply):
    client, fake = key_client(db_path, reply, OK_REPLY)
    client.use_settings_key(API_KEY)
    client.check_key()
    assert len(fake.calls) == 1


# --- A2. automatic re-check at start --------------------------------------------------------


@pytest.mark.parametrize(
    "check, due",
    [
        (None, True),
        ({"result": "unknown", "checked_at": NOW.isoformat()}, True),
        ({"result": "valid", "checked_at": (NOW - timedelta(hours=25)).isoformat()}, True),
        ({"result": "valid", "checked_at": (NOW - timedelta(hours=23)).isoformat()}, False),
        ({"result": "rejected", "checked_at": (NOW - timedelta(hours=1)).isoformat()}, False),
    ],
    ids=["never", "unknown", "old-valid", "fresh-valid", "fresh-rejected"],
)
def test_key_check_due(db_path, check, due):
    if check:
        store_check(db_path, source="settings", **check)
    client, _ = key_client(db_path)
    client.use_settings_key(API_KEY)
    assert client.key_check_due() is due


def test_no_check_due_without_a_key(db_path):
    client, _ = key_client(db_path)
    assert not client.key_check_due()


def test_start_rechecks_an_unknown_key_in_the_background(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    store_check(db_path, result="unknown", checked_at=NOW.isoformat(), source="env",
                reason="HTTP 503")  # fmt: skip
    started = []

    def starter(job):
        started.append(job)
        job()

    client, fake = key_client(db_path, OK_REPLY)
    with web(db_path, client, startup_key_check=True, key_check_starter=starter) as c:
        assert len(started) == 1 and len(fake.calls) == 1
        assert "NVD API key: valid" in badge(c.get("/reports").text)


def test_start_skips_a_fresh_check_and_tests_never_check(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    store_check(db_path, result="valid", checked_at=NOW.isoformat(), source="env")
    client, fake = key_client(db_path, OK_REPLY)
    with web(db_path, client, startup_key_check=True, key_check_starter=sync) as c:
        assert c.app.state.recheck_nvd_key() is None
    assert fake.calls == []
    store_check(db_path, result="unknown", checked_at=NOW.isoformat(), source="env")
    client, fake = key_client(db_path, OK_REPLY)
    with web(db_path, client):  # startup_key_check is off by default (the CLI enables it)
        pass
    assert fake.calls == []


# --- B3. cache TTLs from Settings -----------------------------------------------------------


@pytest.mark.parametrize(
    "text, hours",
    [("1", 1), ("24h", 24), ("36 H", 36), ("30d", 720), ("365d", 8760), (" 8760 ", 8760)],
)
def test_parse_ttl(text, hours):
    assert cache_settings.parse_ttl(text) == (hours, None)


@pytest.mark.parametrize("text", ["0", "0h", "366d", "8761", "", "1.5h", "-1", "1w", "abc"])
def test_parse_ttl_rejects_out_of_bounds_and_garbage(text):
    hours, error = cache_settings.parse_ttl(text)
    assert hours is None and error


def test_format_ttl():
    assert [cache_settings.format_ttl(h) for h in (720, 24, 1, 36, 0.5)] == [
        "30 d", "1 d", "1 h", "36 h", "0.5 h",
    ]  # fmt: skip


def test_defaults(db_path):
    with web(db_path) as c:
        ttls = c.app.state.cache_ttls
        assert ttls.current() == {
            "nvd": 720, "canonical": 24, "canonical_unsettled": 1, "amazon": 24,
        }  # fmt: skip
        page = c.get("/settings").text
    for key, value in [("nvd", "30d"), ("canonical", "1d"), ("canonical_unsettled", "1h"),
                       ("amazon", "1d")]:  # fmt: skip
        assert f'name="{key}" value="{value}"' in page


TTL_FORM = {"nvd": "7d", "canonical": "12h", "canonical_unsettled": "2h", "amazon": "48h"}


def test_saved_ttls_are_applied_persisted_and_survive_a_restart(db_path):
    with web(db_path) as c:
        r = c.post("/settings/cache-ttl", data={"action": "save", **TTL_FORM})
        assert r.status_code == 200 and "Cache TTLs saved. No entries were deleted" in r.text
        analyzer = c.app.state.analyzer
        assert analyzer.nvd.max_age == timedelta(days=7)
        assert analyzer.metadata.max_age == timedelta(hours=12)
        assert analyzer.metadata.investigating_max_age == timedelta(hours=2)
        assert analyzer.advisories.max_age == timedelta(hours=48)
    saved = json.loads(Database(db_path).get_setting(cache_settings.SETTING))
    assert saved == {"nvd": 168, "canonical": 12, "canonical_unsettled": 2, "amazon": 48}
    with web(db_path) as c:  # a new process
        assert c.app.state.analyzer.nvd.max_age == timedelta(days=7)
        assert c.app.state.analyzer.metadata.ttl(None) == timedelta(hours=12)
        assert 'name="nvd" value="7d"' in c.get("/settings").text
        r = c.post("/settings/cache-ttl", data={"action": "reset"})
        assert "Cache TTLs reset to default." in r.text
        assert c.app.state.analyzer.nvd.max_age == nvd.CACHE_MAX_AGE
    assert Database(db_path).get_setting(cache_settings.SETTING) is None


@pytest.mark.parametrize(
    "field, value, message",
    [
        ("nvd", "0h", "between 1 hour and 365 days"),
        ("canonical", "366d", "between 1 hour and 365 days"),
        ("amazon", "soon", "whole number of hours"),
        ("canonical_unsettled", "2d", "Must not be longer than the TTL of settled CVEs"),
    ],
)
def test_invalid_ttls_are_rejected_and_nothing_changes(db_path, field, value, message):
    with web(db_path) as c:
        r = c.post("/settings/cache-ttl", data={**TTL_FORM, field: value})
        assert r.status_code == 422 and message in r.text
        assert f'name="{field}" value="{value}"' in r.text  # the typed value is kept
        assert c.app.state.analyzer.nvd.max_age == nvd.CACHE_MAX_AGE
    assert Database(db_path).get_setting(cache_settings.SETTING) is None


def test_invalid_saved_value_falls_back_to_the_default(db_path):
    Database(db_path).set_setting(
        cache_settings.SETTING, json.dumps({"nvd": 0, "canonical": "x", "amazon": 5})
    )
    with web(db_path) as c:
        assert c.app.state.cache_ttls.current() == {
            "nvd": 720, "canonical": 24, "canonical_unsettled": 1, "amazon": 5,
        }  # fmt: skip
    Database(db_path).set_setting(cache_settings.SETTING, "{not json")
    with web(db_path) as c:
        assert c.app.state.cache_ttls.current()["amazon"] == 24


def test_changing_a_ttl_keeps_entries_and_expired_ones_refresh_on_lookup(db_path):
    db = Database(db_path)
    old = (NOW - timedelta(days=3)).isoformat()
    db.put_nvd_cache(CVE, "{}", None, old)
    db.put_cve_metadata("CVE-2026-1", None, old)
    db.put_updateinfo_cache(f"{RELEASEVER}/x86_64", "[]", None, old)
    fake = FakeNvd(REPORT_CVES)
    client = nvd.NvdClient(db, transport=fake, sleep=lambda s: None, now=lambda: NOW)
    with web(db_path, client) as c:
        assert client.lookup(CVE).status == nvd.NO_CVSS and fake.calls == []  # 3 d < 30 d
        c.post("/settings/cache-ttl", data={**TTL_FORM, "nvd": "2d"})
        # nothing was deleted by the change
        assert db.cache_summary("nvd") == (1, old)
        assert db.cache_summary("canonical")[0] == 1 and db.cache_summary("amazon")[0] == 1
        client.start_run()
        assert client.lookup(CVE).severity == "High" and fake.requested() == [CVE]
        assert db.get_nvd_cache(CVE)[2] == NOW.isoformat()  # refreshed


def test_canonical_ttls_from_settings_drive_expiry(db_path):
    clock = Clock()
    calls = []

    def fetch(url):
        calls.append(url)
        return {"id": "CVE-2026-2", "packages": []}

    db = Database(db_path)
    meta = SecurityMetadata(db, fetcher=fetch, now=clock)
    ttls = cache_settings.CacheTtls(
        db, meta, nvd.NvdClient(db), amazon_updateinfo.UpdateInfoSource(db)
    )
    ttls.save({"nvd": 720, "canonical": 2, "canonical_unsettled": 1, "amazon": 24})
    meta.lookup("CVE-2026-2")
    clock.now = NOW + timedelta(hours=1, minutes=59)
    meta.start_run()
    meta.lookup("CVE-2026-2")
    assert len(calls) == 1
    clock.now = NOW + timedelta(hours=2)
    meta.start_run()
    meta.lookup("CVE-2026-2")
    assert len(calls) == 2


def test_amazon_ttl_from_settings_drives_expiry(db_path):
    clock, cdn = Clock(), FakeCdn()
    db = Database(db_path)
    src = amazon_updateinfo.UpdateInfoSource(db, transport=cdn, now=clock)
    ttls = cache_settings.CacheTtls(db, SecurityMetadata(db), nvd.NvdClient(db), src)
    ttls.save({"nvd": 720, "canonical": 24, "canonical_unsettled": 1, "amazon": 3})
    src.lookup(RELEASEVER, "x86_64")
    clock.now = NOW + timedelta(hours=3)
    src.start_run()
    src.lookup(RELEASEVER, "x86_64")
    assert cdn.downloads == 2


# --- B5. hit / live counts per run ----------------------------------------------------------


def test_nvd_counts_cache_live_and_failed(tmp_path):
    clock = Clock()
    fake = FakeNvd(REPORT_CVES)
    client = make_client(tmp_path, fake, now=clock)
    for cve in ("CVE-2026-63076", "CVE-2026-63075"):
        client.lookup(cve)
    assert client.run_cache_stats() == CacheStats(cache=0, live=2, failed=0)
    client.start_run()
    client.lookup("CVE-2026-63076")
    client.lookup("CVE-2026-63076")  # memoized: counted once
    fake.replies = [OSError("down")]
    client.lookup("CVE-2026-10004")
    assert client.run_cache_stats() == CacheStats(cache=1, live=0, failed=1)
    assert client.run_cache_stats().label == "1 from cache / 0 live / 1 failed"
    # a stale entry used because NVD is unreachable counts as from cache
    clock.now = NOW + timedelta(days=31)
    client.start_run()
    fake.replies = [OSError("down")]
    assert client.lookup("CVE-2026-63076").status == nvd.STALE
    assert client.run_cache_stats() == CacheStats(cache=1, live=0, failed=0)


def test_canonical_counts_cache_and_live(tmp_path):
    meta = make_metadata(tmp_path)
    meta.start_run()
    meta.lookup("CVE-2026-63076")
    assert meta.run_cache_stats() == CacheStats(live=1)
    meta.start_run()
    meta.lookup("CVE-2026-63076")  # memo hit
    assert meta.run_cache_stats() == CacheStats(cache=1)
    meta.start_run(force_refresh=True)
    meta.lookup("CVE-2026-63076")
    meta.lookup("CVE-2026-63076")  # live wins over the later memo hit
    assert meta.run_cache_stats() == CacheStats(live=1)


def test_amazon_counts_cache_and_live(tmp_path):
    src = amazon_updateinfo.UpdateInfoSource(
        Database(tmp_path / "a.db"), transport=FakeCdn(), now=Clock()
    )
    src.lookup(RELEASEVER, "x86_64")
    assert src.run_cache_stats() == CacheStats(live=1)
    src.start_run()
    src.lookup(RELEASEVER, "x86_64")
    assert src.run_cache_stats() == CacheStats(cache=1)


@pytest.fixture
def servers(db, pem_file):
    db.create_server(GOOD, GOOD_IP, str(pem_file))
    db.create_server(BAD, BAD_IP, str(pem_file))
    return db


REPORT = {GOOD: ["CVE-2026-63076", "CVE-2026-63075"], BAD: ["CVE-2026-63076"]}


def analyze(db, tmp_path, fake):
    db.save_report("security-report.json", REPORT, "VALID")
    service = AnalysisService(
        db, make_metadata(tmp_path), runner=ScriptedSSH(), starter=sync,
        nvd_client=make_client(tmp_path, fake),
    )  # fmt: skip
    return db.get_analysis_run(service.start(db.get_latest_report()))


def test_run_stores_cache_and_live_counts(servers, tmp_path):
    fake = FakeNvd(REPORT_CVES)
    first = analyze(servers, tmp_path, fake)
    assert first.cache_stats["nvd"] == {"cache": 0, "live": 2, "failed": 0}
    assert first.cache_stats["canonical"] == {"cache": 0, "live": 2, "failed": 0}
    assert first.cache_stats["amazon"] == {"cache": 0, "live": 0, "failed": 0}
    second = analyze(servers, tmp_path, fake)
    assert second.cache_stats["nvd"] == {"cache": 2, "live": 0, "failed": 0}
    assert second.cache_stats["canonical"] == {"cache": 2, "live": 0, "failed": 0}
    assert second.cache_tallies["nvd"].label == "2 from cache / 0 live"


def test_reanalyze_adds_to_the_runs_counts(servers, tmp_path):
    run = analyze(servers, tmp_path, FakeNvd(REPORT_CVES))
    service = AnalysisService(
        servers, make_metadata(tmp_path), runner=ScriptedSSH(), starter=sync,
        nvd_client=make_client(tmp_path, FakeNvd(REPORT_CVES)),
    )  # fmt: skip
    service.reanalyze(run.id, run.servers[0].id, run.status)
    stats = servers.get_analysis_run(run.id).cache_stats
    assert stats["nvd"] == {"cache": 2, "live": 2, "failed": 0}  # 2 live + 2 from cache
    assert stats["canonical"]["live"] == 4  # forced refresh of both CVEs


def test_run_page_and_server_report_show_the_counts(db_path, pem_file, tmp_path):
    db = Database(db_path)
    db.create_server(GOOD, GOOD_IP, str(pem_file))
    db.save_report("r.json", {GOOD: [CVE]}, "VALID")
    run_id = db.create_analysis_run(
        db.get_latest_report(), [(GOOD, db.get_server_by_name(GOOD), None)]
    )
    stats = {"nvd": {"cache": 3, "live": 1, "failed": 0},
             "canonical": {"cache": 0, "live": 4, "failed": 0},
             "amazon": {"cache": 1, "live": 0, "failed": 2}}  # fmt: skip
    db.update_analysis_run(run_id, status="completed", completed_at=NOW.isoformat(),
                           cache_stats=stats)  # fmt: skip
    analysis_id = db.get_analysis_run(run_id).servers[0].id
    db.update_server_analysis(analysis_id, status="complete")
    with web(db_path) as c:
        for url in (f"/analysis/{run_id}", f"/analysis/{run_id}/servers/{analysis_id}"):
            page = c.get(url).text
            assert "NVD: 3 from cache / 1 live" in page
            assert "Canonical: 0 from cache / 4 live" in page
            assert "Amazon updateinfo: 1 from cache / 0 live / 2 failed" in page


def test_older_runs_show_not_recorded(db_path):
    db = Database(db_path)
    db.save_report("r.json", {GOOD: [CVE]}, "VALID")
    run_id = db.create_analysis_run(db.get_latest_report(), [(GOOD, None, None)])
    db.update_analysis_run(run_id, status="completed", completed_at=NOW.isoformat())
    with web(db_path) as c:
        page = c.get(f"/analysis/{run_id}").text
    assert "<dt>Cache lookups</dt>" in page and "not recorded" in page


# --- B4 / B6. cache badges and the Caches section -------------------------------------------


def test_empty_caches_are_gray_badges_linking_to_settings(db_path):
    with web(db_path) as c:
        for url in ("/reports", "/settings"):
            page = c.get(url).text
            for name, text in [("nvd", "NVD cache: empty, TTL 30 d"),
                               ("canonical", "Canonical cache: empty, TTL 1 d / 1 h unsettled"),
                               ("amazon", "Amazon updateinfo cache: empty, TTL 1 d")]:  # fmt: skip
                b = cache_badge(page, name)
                assert text in b and "badge-neutral" in b and 'href="/settings#caches"' in b
                assert "data-cache-empty" in b


def test_badges_show_count_oldest_age_and_ttl_and_turn_blue_after_cache_hits(db_path):
    db = Database(db_path)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    db.put_nvd_cache("CVE-2026-1", "{}", None, (now - timedelta(days=2, hours=3)).isoformat())
    db.put_nvd_cache("CVE-2026-2", "{}", None, now.isoformat())
    db.put_cve_metadata("CVE-2026-1", None, now.isoformat())
    with web(db_path) as c:
        page = c.get("/reports").text
        b = cache_badge(page, "nvd")
        assert "NVD cache: 2 CVEs, oldest 2d 3h, TTL 30 d" in b and "badge-neutral" in b
        assert "No analysis run yet" in b
        assert "Canonical cache: 1 CVE, oldest 0m" in cache_badge(page, "canonical")

        db.save_report("r.json", {GOOD: [CVE]}, "VALID")
        run_id = db.create_analysis_run(db.get_latest_report(), [(GOOD, None, None)])
        stats = {
            "nvd": {"cache": 2, "live": 0, "failed": 0},
            "canonical": {"cache": 0, "live": 1, "failed": 0},
        }
        db.update_analysis_run(
            run_id, status="completed", completed_at=now.isoformat(), cache_stats=stats
        )
        for url in ("/reports", f"/analysis/{run_id}", "/settings"):
            page = c.get(url).text
            nvd_badge, canonical = cache_badge(page, "nvd"), cache_badge(page, "canonical")
            assert "badge-info" in nvd_badge and 'data-cache-used="yes"' in nvd_badge
            assert f"Last analysis (#{run_id}): 2 from cache / 0 live" in nvd_badge
            assert "badge-neutral" in canonical  # the run fetched it live
            assert "badge-neutral" in cache_badge(page, "amazon")  # empty


def test_badge_ttl_follows_the_settings(db_path):
    with web(db_path) as c:
        c.post("/settings/cache-ttl", data=TTL_FORM)
        page = c.get("/reports").text
    assert "TTL 7 d" in cache_badge(page, "nvd")
    assert "TTL 12 h / 2 h unsettled" in cache_badge(page, "canonical")
    assert "TTL 2 d" in cache_badge(page, "amazon")


def test_caches_section_is_first_on_settings_with_the_clear_button(db_path):
    with web(db_path) as c:
        page = c.get("/settings").text
    caches = page.index('id="caches"')
    assert caches < page.index("Patch &amp; Download Settings") < page.index('id="nvd-key"')
    section = page[caches : page.index("Patch &amp; Download Settings")]
    assert 'action="/settings/cache-ttl"' in section
    assert 'action="/settings/clear-cache"' in section and "Clear Security Cache" in section
    assert page.count('action="/settings/clear-cache"') == 1
    assert "nvd_cache" in section and "amazon_updateinfo_cache" in section


def test_clear_cache_empties_all_three_but_keeps_the_ttls(db_path):
    db = Database(db_path)
    db.put_nvd_cache(CVE, "{}", None, NOW.isoformat())
    db.put_cve_metadata(CVE, None, NOW.isoformat())
    db.put_updateinfo_cache("latest/x86_64", "[]", None, NOW.isoformat())
    with web(db_path) as c:
        c.post("/settings/cache-ttl", data=TTL_FORM)
        c.post("/settings/clear-cache")
        assert [db.cache_summary(n)[0] for n in ("nvd", "canonical", "amazon")] == [0, 0, 0]
        assert c.app.state.analyzer.nvd.max_age == timedelta(days=7)
        page = c.get("/reports").text
        assert "data-cache-empty" in cache_badge(page, "nvd")


def test_reset_database_restores_default_ttls(db_path):
    with web(db_path) as c:
        c.post("/settings/cache-ttl", data=TTL_FORM)
        c.post("/settings/reset-database", data={"confirm_text": "RESET"})
        assert c.app.state.analyzer.nvd.max_age == nvd.CACHE_MAX_AGE
        assert c.app.state.analyzer.advisories.max_age == amazon_updateinfo.CACHE_MAX_AGE


def test_canonical_env_ttl_is_the_default_until_settings_override_it(db_path, monkeypatch):
    monkeypatch.setenv("EC2PATCHER_CANONICAL_CACHE_TTL_HOURS", "6")
    with web(db_path) as c:
        assert c.app.state.cache_ttls.current()["canonical"] == 6
        c.post("/settings/cache-ttl", data=TTL_FORM)
        assert c.app.state.analyzer.metadata.max_age == timedelta(hours=12)
        c.post("/settings/cache-ttl", data={"action": "reset"})
        assert c.app.state.analyzer.metadata.max_age == timedelta(hours=6)


def test_defaults_match_the_module_constants():
    assert nvd.CACHE_MAX_AGE == timedelta(days=30)
    assert security_metadata.CACHE_TTL == timedelta(hours=24)
    assert security_metadata.INVESTIGATING_CACHE_TTL == timedelta(hours=1)
    assert amazon_updateinfo.CACHE_MAX_AGE == timedelta(hours=24)


# --- schema v15 -----------------------------------------------------------------------------


def test_fresh_database_is_v15_with_run_cache_stats(db_path):
    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 15
    conn.close()
    assert columns(db_path, "analysis_runs")["cache_stats"] == ("TEXT", 1, "'{}'")
    db.save_report("r.json", {"a": []}, "VALID")
    run_id = db.create_analysis_run(db.get_latest_report(), [("a", None, None)])
    assert db.get_analysis_run(run_id).cache_stats == {}
    db.update_analysis_run(run_id, cache_stats={"nvd": {"cache": 1, "live": 0, "failed": 0}})
    assert db.get_analysis_run(run_id).cache_tallies["nvd"] == CacheStats(cache=1)
    assert db.latest_cache_stats() == (run_id, {"nvd": {"cache": 1, "live": 0, "failed": 0}})


def test_v14_database_upgrades_to_v15_keeping_data(db_path):
    conn = _legacy_db(db_path, 14)
    conn.execute(
        "INSERT INTO analysis_runs (report_filename, report_uploaded_at, report_content, "
        "started_at, status, metadata_lookups) "
        "VALUES ('old.json', 't', '{}', 't', 'completed', '{\"CVE-1\": \"ok\"}')"
    )
    conn.execute("INSERT INTO nvd_cache (cve, metrics, fetched_at) VALUES ('CVE-1', NULL, 't')")
    conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', 't')")
    conn.execute("UPDATE servers SET password_encrypted = 'token'")
    conn.commit()
    conn.close()
    assert "cache_stats" not in columns(db_path, "analysis_runs")

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 15
    check.close()
    run = db.get_latest_analysis_run()
    assert run.report_filename == "old.json" and run.metadata_lookups == {"CVE-1": "ok"}
    assert run.cache_stats == {} and run.cache_tallies["nvd"] == CacheStats()
    assert db.get_nvd_cache("CVE-1") == (None, None, "t")
    assert db.get_setting("k") == "v"
    assert db.get_server_password(db.get_server_by_name("keep").id) == "token"
    assert db.get_latest_report().filename == "r.json"


def test_full_upgrade_path_from_v1_reaches_v15(db_path):
    _legacy_db(db_path, 1).close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 15
    check.close()
    assert "cache_stats" in columns(db_path, "analysis_runs")
    assert db.get_server_by_name("keep") is not None
    assert db.get_latest_report().servers == {"keep": []}
    assert db.latest_cache_stats() is None


def test_v15_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "cache_stats" in _MIGRATIONS[15]
    assert all("cache_stats" not in _MIGRATIONS[v] for v in range(1, 15))
    assert "password_encrypted" in _MIGRATIONS[14]  # v14 left as it was
