"""NVD CVSS cache in SQLite (table ``nvd_cache``, schema v10; never the live API in tests)."""

import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from nvd_fixtures import FakeNvd, cve_obj, cvss, make_client, nvd_cache_db

from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.services import nvd

CVE = "CVE-2026-1000"
HIGH = cve_obj(CVE, cvssMetricV31=[cvss("3.1", 7.5, "HIGH")])
START = datetime(2026, 9, 27, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self):
        self.value = START

    def __call__(self):
        return self.value


def rows(path):
    with sqlite3.connect(path) as conn:
        return conn.execute(
            "SELECT cve, metrics, last_modified, fetched_at FROM nvd_cache"
        ).fetchall()


def nvd_columns(path):
    with sqlite3.connect(path) as conn:
        return [(r[1], r[2], r[5]) for r in conn.execute("PRAGMA table_info(nvd_cache)")]


# --- hit / miss ------------------------------------------------------------------------------


def test_cache_miss_then_hit(tmp_path):
    clock = Clock()
    fake = FakeNvd({CVE: HIGH})
    assert make_client(tmp_path, fake, now=clock).lookup(CVE).severity == "High"  # miss
    assert len(fake.calls) == 1
    ((cve, metrics, last_modified, fetched_at),) = rows(nvd_cache_db(tmp_path))
    assert (cve, last_modified, fetched_at) == (
        CVE, "2026-09-01T12:17:13.423", "2026-09-27T12:00:00+00:00",
    )  # fmt: skip
    assert json.loads(metrics)["cvssMetricV31"][0]["cvssData"]["baseScore"] == 7.5

    # A new client (= a new process) is served from SQLite without a request.
    r = make_client(tmp_path, fake, now=clock).lookup(CVE)
    assert (r.status, r.severity, r.score, r.last_modified) == (
        nvd.OK, "High", 7.5, "2026-09-01T12:17:13.423",
    )  # fmt: skip
    assert len(fake.calls) == 1


def test_not_found_is_cached_as_null_metrics(tmp_path):
    fake = FakeNvd({})
    assert make_client(tmp_path, fake).lookup(CVE).status == nvd.NOT_FOUND
    assert [(r[0], r[1]) for r in rows(nvd_cache_db(tmp_path))] == [(CVE, None)]
    assert make_client(tmp_path, fake).lookup(CVE).status == nvd.NOT_FOUND
    assert len(fake.calls) == 1


# --- TTL -------------------------------------------------------------------------------------


def test_ttl_is_30_days():
    assert nvd.CACHE_MAX_AGE == timedelta(days=30)


def test_ttl_expiry_refetches(tmp_path):
    clock = Clock()
    fake = FakeNvd({CVE: HIGH})
    make_client(tmp_path, fake, now=clock).lookup(CVE)

    clock.value = START + timedelta(days=29, hours=23)
    assert make_client(tmp_path, fake, now=clock).lookup(CVE).severity == "High"  # still fresh
    assert len(fake.calls) == 1

    clock.value = START + timedelta(days=30)
    fake.cves[CVE] = cve_obj(CVE, cvssMetricV31=[cvss("3.1", 9.8, "CRITICAL")])
    r = make_client(tmp_path, fake, now=clock).lookup(CVE)  # expired -> refreshed
    assert (r.status, r.severity, len(fake.calls)) == (nvd.OK, "Critical", 2)
    ((_, metrics, _, fetched_at),) = rows(nvd_cache_db(tmp_path))
    assert fetched_at == clock.value.isoformat() and "9.8" in metrics


# --- failures are never cached ---------------------------------------------------------------


@pytest.mark.parametrize(
    "reply",
    [OSError("down"), TimeoutError("timed out"), (404, {}, b""), (503, {}, b""),
     (200, {}, b"<html>oops")],
)  # fmt: skip
def test_failure_is_not_cached(tmp_path, reply):
    fake = FakeNvd(replies=[reply] * 5)
    assert make_client(tmp_path, fake).lookup(CVE).status == nvd.FAILED
    assert rows(nvd_cache_db(tmp_path)) == []
    # The next run asks NVD again instead of reusing the failure.
    fake = FakeNvd({CVE: HIGH})
    assert make_client(tmp_path, fake).lookup(CVE).severity == "High"
    assert len(fake.calls) == 1


def test_failure_does_not_overwrite_expired_entry(tmp_path):
    clock = Clock()
    make_client(tmp_path, FakeNvd({CVE: HIGH}), now=clock).lookup(CVE)
    before = rows(nvd_cache_db(tmp_path))
    clock.value = START + timedelta(days=45)
    r = make_client(tmp_path, FakeNvd(replies=[OSError("down")]), now=clock).lookup(CVE)
    assert (r.status, r.severity) == (nvd.STALE, "High")
    assert rows(nvd_cache_db(tmp_path)) == before


# --- cache errors fall back to the network ---------------------------------------------------


@pytest.mark.parametrize(
    ("metrics", "fetched_at"),
    [("{not json", "2026-09-27T12:00:00+00:00"), ("[]", "2026-09-27T12:00:00+00:00"),
     ("{}", "not a timestamp")],
)  # fmt: skip
def test_corrupt_cache_row_falls_back_to_network(tmp_path, metrics, fetched_at):
    Database(nvd_cache_db(tmp_path)).put_nvd_cache(CVE, metrics, None, fetched_at)
    fake = FakeNvd({CVE: HIGH})
    assert make_client(tmp_path, fake, now=Clock()).lookup(CVE).severity == "High"
    assert len(fake.calls) == 1


def test_unusable_cache_database_falls_back_to_network(tmp_path):
    nvd_cache_db(tmp_path).mkdir()  # a directory where the SQLite file should be
    fake = FakeNvd({CVE: HIGH})
    client = make_client(tmp_path, fake)
    assert client.lookup(CVE).severity == "High"
    assert len(fake.calls) == 1
    assert client.clear() is True  # memo forgotten; the broken table does not raise


def test_old_disk_cache_is_ignored_and_not_written(tmp_path, monkeypatch):
    disk = tmp_path / "cache" / "nvd"  # the former default location (EC2PATCHER_CACHE_DIR/nvd)
    disk.mkdir(parents=True)
    old = {"cve_id": CVE, "fetched_at": "2026-09-27T12:00:00+00:00", "cve": HIGH}
    (disk / f"{CVE}.json").write_text(json.dumps(old))
    monkeypatch.setenv("EC2PATCHER_CACHE_DIR", str(tmp_path / "cache"))
    fake = FakeNvd({"CVE-2026-2000": HIGH | {"id": "CVE-2026-2000"}})
    client = make_client(tmp_path, fake, now=Clock())
    assert client.lookup(CVE).status == nvd.NOT_FOUND  # the disk entry was not used
    client.lookup("CVE-2026-2000")
    assert len(fake.calls) == 2
    assert sorted(p.name for p in disk.iterdir()) == [f"{CVE}.json"]  # nothing new on disk


# --- clear -----------------------------------------------------------------------------------


def test_clear_empties_nvd_cache(tmp_path):
    fake = FakeNvd({CVE: HIGH})
    client = make_client(tmp_path, fake)
    client.lookup(CVE)
    assert client.clear() is True
    assert rows(nvd_cache_db(tmp_path)) == []
    client.lookup(CVE)
    assert len(fake.calls) == 2  # neither the memo nor the table served it
    assert make_client(tmp_path, fake).clear() is True
    assert make_client(tmp_path, fake).clear() is False  # nothing left to clear


def test_settings_clear_also_empties_nvd_cache(client, db_path):
    # The app's default NVD client caches in the application database.
    assert client.app.state.analyzer.nvd.cache_db_path == db_path
    Database(db_path).put_nvd_cache(CVE, "{}", None, "2026-09-27T12:00:00+00:00")
    r = client.post("/settings/clear-cache", follow_redirects=True)
    assert r.status_code == 200 and "Security lookup memory and cache cleared" in r.text
    assert rows(db_path) == []
    assert "nvd_cache" in client.get("/settings").text


# --- schema ----------------------------------------------------------------------------------


def test_fresh_database_is_v10_with_nvd_cache(db_path):
    Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 10
    assert nvd_columns(db_path) == [
        ("cve", "TEXT", 1), ("metrics", "TEXT", 0), ("last_modified", "TEXT", 0),
        ("fetched_at", "TEXT", 0),
    ]  # fmt: skip


def test_v9_database_upgrades_to_v10_keeping_data(db_path):
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    for version in range(1, 10):
        conn.executescript(_MIGRATIONS[version])
    conn.execute("PRAGMA user_version = 9")
    conn.execute(
        "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
        "VALUES ('keep', '10.0.0.1', '/k.pem', 't', 't')"
    )
    conn.execute(
        "INSERT INTO cve_metadata_cache (cve, document, fetched_at) "
        "VALUES ('CVE-2026-9', NULL, 't')"
    )
    conn.commit()
    assert "nvd_cache" not in {
        r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
    }
    conn.close()

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == 10
    check.close()
    assert [c[0] for c in nvd_columns(db_path)] == ["cve", "metrics", "last_modified", "fetched_at"]
    assert db.get_server_by_name("keep") is not None
    assert db.get_cve_metadata("CVE-2026-9") == (None, "t")
    # Usable right away, and reopening does not run the migration again.
    db.put_nvd_cache(CVE, "{}", None, "t")
    assert Database(db_path).get_nvd_cache(CVE) == ("{}", None, "t")


def test_full_upgrade_path_from_v1_reaches_v10(db_path):
    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_MIGRATIONS[1])
        conn.execute("PRAGMA user_version = 1")
    conn.close()
    Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    conn.close()
    assert [c[0] for c in nvd_columns(db_path)] == ["cve", "metrics", "last_modified", "fetched_at"]


def test_migration_numbers_are_contiguous():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
