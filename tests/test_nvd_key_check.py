"""NVD API key check: saving a key in Settings and the Test key button send one keyed request;
the result (never the key) is persisted in the settings table and drives the badge, so it
survives restarts and cached lookups. A 404 for an invalid key never poisons nvd_cache."""

import io
import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from nvd_fixtures import REPORT_CVES, FakeNvd, make_client, nvd_cache_db, response

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.formatting import format_timestamp
from ec2patcher.services import nvd
from ec2patcher.services.secret_store import NVD_KEY_SETTING

API_KEY = "fake-nvd-key-0123456789abcdef"  # fake test key
ENV_KEY = "fake-env-key-fedcba9876543210"  # fake test key
CVE = "CVE-2026-63076"
NOW = datetime(2026, 10, 4, 12, 30, tzinfo=timezone.utc)
CHECKED = NOW.isoformat()
OK_REPLY = (200, {}, response())
INVALID_KEY_404 = (404, {"message": "Invalid apiKey."}, b"")
REAL_HTTP_GET = nvd.http_get  # before conftest replaces it with the offline stand-in


def nvd_client(db_path, *replies):
    fake = FakeNvd(replies=list(replies))
    client = nvd.NvdClient(db_path, transport=fake, sleep=lambda s: None, now=lambda: NOW)
    return client, fake


def web(db_path, client):
    app = create_app(db_path=db_path, nvd_client=client, shutdown_handler=lambda: None)
    return TestClient(app, base_url="http://127.0.0.1")


def persisted(db_path) -> dict | None:
    value = Database(db_path).get_setting(nvd.KEY_CHECK_SETTING)
    return None if value is None else json.loads(value)


def badge(page: str) -> str:
    start = page.rindex("<span", 0, page.index("nvd-key-badge"))
    return page[start : page.index("</span>", start)]


def assert_key_absent(db_path, *texts):
    raw = b"".join(p.read_bytes() for p in db_path.parent.glob(db_path.name + "*"))
    assert API_KEY.encode() not in raw and ENV_KEY.encode() not in raw
    for text in texts:
        assert API_KEY not in text and ENV_KEY not in text and ENV_KEY[-4:] not in text


# --- 1. check on save --------------------------------------------------------------------------


def test_save_checks_the_key_once_and_persists_valid(db_path, caplog):
    caplog.set_level(logging.DEBUG)
    client, fake = nvd_client(db_path, OK_REPLY)
    with web(db_path, client) as c:
        r = c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        assert "NVD API key saved (encrypted)" in r.text and "NVD accepted it." in r.text
        assert len(fake.calls) == 1
        url, headers = fake.calls[0]
        assert headers["apiKey"] == API_KEY and API_KEY not in url
        assert urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cveId"] == [
            nvd.KEY_CHECK_CVE
        ]
        assert persisted(db_path) == {
            "result": nvd.KEY_VALID, "checked_at": CHECKED, "source": nvd.KEY_SOURCE_SETTINGS,
        }  # fmt: skip
        reports = c.get("/reports").text
        text = f"NVD API key: valid (checked {format_timestamp(CHECKED)}) — from Settings"
        assert text in badge(reports) and "badge-success" in badge(reports)
        assert 'data-nvd-key="valid"' in r.text  # Settings shows the same badge
    assert_key_absent(db_path, r.text, reports, caplog.text)


@pytest.mark.parametrize(
    "reply",
    [
        (403, {}, b""),
        INVALID_KEY_404,
        (404, {}, b'{"message": "Invalid apiKey."}'),
        (404, {"Message": "apiKey is invalid"}, b""),
    ],
    ids=["403", "404-header", "404-body", "404-header-variant"],
)
def test_save_with_a_rejected_key_persists_rejected(db_path, reply, caplog):
    client, fake = nvd_client(db_path, reply)
    with web(db_path, client) as c:
        r = c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        assert "NVD API key saved (encrypted), but NVD rejected it." in r.text
        assert len(fake.calls) == 1 and client.key_status == nvd.KEY_REJECTED
        assert persisted(db_path)["result"] == nvd.KEY_REJECTED
        reports = c.get("/reports").text
        assert "NVD API key rejected — from Settings" in badge(reports)
        assert "badge-danger" in badge(reports)
    assert_key_absent(db_path, r.text, reports, caplog.text)


@pytest.mark.parametrize(
    "replies, reason",
    [
        ([OSError("Network is unreachable")], "network error: Network is unreachable"),
        ([TimeoutError("timed out")], "network error: timed out"),
        ([(404, {}, b"Not Found")], "HTTP 404"),  # a 404 without the invalid-key message
        ([(503, {}, b"")] * 2, "HTTP 503 (after a retry)"),  # 429 / 5xx: retried once
        ([(429, {"Retry-After": "5"}, b"")] * 2, "HTTP 429 (after a retry)"),
    ],
    ids=["oserror", "timeout", "plain-404", "503", "429"],
)
def test_save_when_nvd_cannot_tell_persists_unknown(db_path, replies, reason):
    client, fake = nvd_client(db_path, *replies)
    with web(db_path, client) as c:
        r = c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        assert "NVD could not be reached, so the key is not checked yet." in r.text
        assert f"Reason: {reason}." in r.text
        assert len(fake.calls) == len(replies)
        assert persisted(db_path) == {
            "result": nvd.KEY_UNKNOWN, "checked_at": CHECKED, "source": nvd.KEY_SOURCE_SETTINGS,
            "reason": reason,
        }  # fmt: skip
        reports = c.get("/reports").text
        assert "NVD API key: unknown — from Settings (DB)" in badge(reports)
        assert "badge-neutral" in badge(reports)
        assert "NVD could not be reached at the last check" in badge(reports)
        assert reason in badge(reports)


def test_save_with_the_default_offline_client_is_unknown(db_path):
    app = create_app(db_path=db_path, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        r = c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        assert "NVD could not be reached" in r.text
    assert persisted(db_path)["result"] == nvd.KEY_UNKNOWN


# --- 2. Test key button ------------------------------------------------------------------------


def test_test_key_button_checks_the_key_in_use(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    client, fake = nvd_client(db_path, OK_REPLY, (403, {}, b""), OSError("down"))
    with web(db_path, client) as c:
        page = c.get("/settings").text
        assert 'value="test"' in page and ">Test key</button>" in page
        assert "NVD API key: unknown — from NVD_API_KEY env var" in badge(page)

        r = c.post("/settings/nvd-key", data={"action": "test", "nvd_api_key": ""})
        assert "NVD accepted the API key." in r.text and fake.calls[-1][1]["apiKey"] == ENV_KEY
        assert persisted(db_path)["source"] == nvd.KEY_SOURCE_ENV
        assert "NVD API key: valid (checked" in badge(r.text)

        r = c.post("/settings/nvd-key", data={"action": "test"})
        assert "NVD rejected the API key." in r.text and "NVD API key rejected" in badge(r.text)

        r = c.post("/settings/nvd-key", data={"action": "test"})
        assert "NVD could not be reached, so the API key could not be checked." in r.text
        assert persisted(db_path)["result"] == nvd.KEY_UNKNOWN
        assert len(fake.calls) == 3
    assert_key_absent(db_path, page, r.text)


def test_test_key_without_a_key_sends_nothing(db_path):
    client, fake = nvd_client(db_path, OK_REPLY)
    with web(db_path, client) as c:
        assert 'value="test"' not in c.get("/settings").text
        r = c.post("/settings/nvd-key", data={"action": "test"})
        assert "There is no NVD API key to test." in r.text
        assert "NVD API key: not set" in badge(r.text)
    assert fake.calls == [] and persisted(db_path) is None


def test_test_key_ignores_the_circuit_breaker_of_a_run(db_path):
    client, fake = nvd_client(db_path, OSError("down"), OK_REPLY)
    client.use_settings_key(API_KEY)
    assert client.lookup(CVE).status == nvd.FAILED  # the run now treats NVD as unreachable
    assert client.key_status == nvd.KEY_UNKNOWN  # a live network error changes nothing
    assert persisted(db_path) is None
    assert client.check_key() == nvd.KEY_VALID and len(fake.calls) == 2


# --- 3. badge from the persisted state ---------------------------------------------------------


def store_check(db_path, **check):
    Database(db_path).set_setting(nvd.KEY_CHECK_SETTING, json.dumps(check))


@pytest.mark.parametrize(
    "check, text, css",
    [
        (
            {"result": "valid", "checked_at": CHECKED, "source": "settings"},
            f"NVD API key: valid (checked {format_timestamp(CHECKED)}) — from Settings",
            "badge-success",
        ),
        (
            {"result": "rejected", "checked_at": CHECKED, "source": "settings"},
            "NVD API key rejected — from Settings",
            "badge-danger",
        ),
        (
            {"result": "unknown", "checked_at": CHECKED, "source": "settings"},
            "NVD API key: unknown — from Settings",
            "badge-neutral",
        ),
        (  # a check of the NVD_API_KEY key says nothing about the Settings key
            {"result": "valid", "checked_at": CHECKED, "source": "env"},
            "NVD API key: unknown — from Settings",
            "badge-neutral",
        ),
        (
            {"result": "bogus", "checked_at": CHECKED, "source": "settings"},
            "NVD API key: unknown — from Settings",
            "badge-neutral",
        ),
    ],
    ids=["valid", "rejected", "unknown", "other-source", "garbage"],
)
def test_badge_reads_the_persisted_check_after_a_restart(db_path, check, text, css):
    with web(db_path, nvd_client(db_path)[0]) as c:
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
    store_check(db_path, **check)
    client, fake = nvd_client(db_path)  # a new process
    with web(db_path, client) as c:
        for url in ("/reports", "/settings"):
            page = c.get(url).text
            assert text in badge(page) and f"badge {css} nvd-key-badge" in badge(page)
            assert_key_absent(db_path, page)
    assert fake.calls == []  # rendering never sends a request


def test_badge_without_any_key_ignores_a_persisted_check(db_path):
    store_check(db_path, result="valid", checked_at=CHECKED, source="settings")
    with web(db_path, nvd_client(db_path)[0]) as c:
        assert "NVD API key: not set" in badge(c.get("/reports").text)


def test_unreadable_persisted_check_is_unknown(db_path, caplog):
    Database(db_path).set_setting(nvd.KEY_CHECK_SETTING, "{not json")
    client = nvd.NvdClient(db_path, api_key=API_KEY)
    assert client.key_status == nvd.KEY_UNKNOWN and client.key_checked_at is None
    assert "Ignoring the unreadable NVD API key check" in caplog.text


def test_valid_key_survives_a_restart_with_only_cached_lookups(db_path, tmp_path):
    client, _ = nvd_client(db_path, OK_REPLY)
    with web(db_path, client) as c:
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
    Database(db_path).put_nvd_cache(CVE, "{}", None, CHECKED)  # every CVE cached
    client, fake = nvd_client(db_path)
    with web(db_path, client) as c:
        client.start_run()
        assert client.lookup(CVE).status == nvd.NO_CVSS and fake.calls == []
        assert "NVD API key: valid (checked" in badge(c.get("/reports").text)


def test_live_keyed_requests_update_the_persisted_check(tmp_path):
    later = datetime(2026, 10, 5, 8, 0, tzinfo=timezone.utc)
    fake = FakeNvd(cves=REPORT_CVES, replies=[(403, {}, b"")])
    client = make_client(tmp_path, fake, api_key=API_KEY, now=lambda: later)
    store_check(nvd_cache_db(tmp_path), result="valid", checked_at=CHECKED, source="env")
    assert client.key_status == nvd.KEY_VALID and client.key_checked_at == CHECKED
    assert client.lookup(CVE).status == nvd.FAILED
    stored = persisted(nvd_cache_db(tmp_path))
    assert stored == {"result": "rejected", "checked_at": later.isoformat(), "source": "env"}
    client.start_run()
    assert client.lookup(CVE).status == nvd.OK
    assert persisted(nvd_cache_db(tmp_path))["result"] == nvd.KEY_VALID


def test_unkeyed_requests_never_write_a_check(tmp_path):
    client = make_client(tmp_path, FakeNvd(replies=[(403, {}, b"")]))
    client.lookup(CVE)
    assert client.key_status == nvd.KEY_NOT_SET and persisted(nvd_cache_db(tmp_path)) is None
    assert client.check_key() == nvd.KEY_NOT_SET


def test_clear_forgets_the_check_and_reset_removes_it(db_path):
    client, _ = nvd_client(db_path, OK_REPLY)
    with web(db_path, client) as c:
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        assert persisted(db_path)["result"] == nvd.KEY_VALID
        r = c.post("/settings/nvd-key", data={"action": "clear"})
        assert persisted(db_path) is None and "NVD API key: not set" in badge(r.text)
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        c.post("/settings/reset-database", data={"confirm_text": "RESET"})
        assert persisted(db_path) is None
        assert Database(db_path).get_setting(NVD_KEY_SETTING) is None


# --- 4. an invalid key never poisons nvd_cache -------------------------------------------------


@pytest.mark.parametrize("reply", [INVALID_KEY_404, (403, {}, b"")], ids=["404", "403"])
def test_rejected_key_reply_is_never_cached_as_unknown_cve(tmp_path, reply, caplog):
    fake = FakeNvd(cves=REPORT_CVES, replies=[reply])
    client = make_client(tmp_path, fake, api_key=API_KEY)
    result = client.lookup(CVE)
    assert result.status == nvd.FAILED and result.status != nvd.NOT_FOUND
    assert "rejected the API key" in result.note
    assert Database(nvd_cache_db(tmp_path)).get_nvd_cache(CVE) is None
    assert client.key_status == nvd.KEY_REJECTED and len(fake.calls) == 1  # no retry
    assert f"(HTTP {reply[0]})" in caplog.text and API_KEY not in caplog.text

    client.start_run()  # the next run (e.g. after fixing the key) asks NVD again
    assert client.lookup(CVE).status == nvd.OK and len(fake.calls) == 2
    assert Database(nvd_cache_db(tmp_path)).get_nvd_cache(CVE) is not None


def test_plain_404_is_not_cached_either(tmp_path):
    client = make_client(tmp_path, FakeNvd(replies=[(404, {}, b"")]), api_key=API_KEY)
    assert client.lookup(CVE).status == nvd.FAILED
    assert Database(nvd_cache_db(tmp_path)).get_nvd_cache(CVE) is None
    assert client.key_status == nvd.KEY_UNKNOWN  # says nothing about the key


def test_http_get_returns_the_error_body(monkeypatch):
    def urlopen(request, timeout):
        raise urllib.error.HTTPError(
            request.full_url, 404, "Not Found", {"message": "Invalid apiKey."},
            io.BytesIO(b"invalid apiKey"),
        )  # fmt: skip

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    status, headers, body = REAL_HTTP_GET(nvd.API_URL, {}, 1)
    assert (status, body) == (404, b"invalid apiKey")
    assert nvd.key_verdict(status, headers, body) == nvd.KEY_REJECTED


def test_key_verdict():
    assert nvd.key_verdict(200, {}, b"") == nvd.KEY_VALID
    assert nvd.key_verdict(403, {}, b"") == nvd.KEY_REJECTED
    assert nvd.key_verdict(*INVALID_KEY_404) == nvd.KEY_REJECTED
    for status, headers, body in [
        (404, {}, b""),
        (404, {"x": "CVE not found"}, b""),
        (500, {"message": "Invalid apiKey."}, b""),
        (429, {}, b""),
    ]:
        assert nvd.key_verdict(status, headers, body) is None
