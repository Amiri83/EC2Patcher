"""Amazon Linux 2023 advisories (repository updateinfo.xml) fetched on the workstation:
parsing, the SQLite cache (schema v12) with the NVD rules (30-day TTL, stale fallback, failures
never cached) and the migration."""

import bz2
import gzip
import json
import lzma
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from amazon_fixtures import (
    CURRENT_ADVISORIES,
    RELEASEVER,
    FakeCdn,
    advisory,
    pkg,
    repomd_xml,
    updateinfo_xml,
)

from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.services import amazon_updateinfo as au

T0 = datetime(2026, 9, 1, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


def source(tmp_path, cdn=None, clock=None, **kwargs):
    db = Database(tmp_path / "data" / "ec2patcher.db")
    return au.UpdateInfoSource(db, transport=cdn or FakeCdn(), now=clock or Clock(), **kwargs)


# --- parsing -----------------------------------------------------------------------------


def test_parse_updateinfo_keeps_cve_advisories_only():
    xml = updateinfo_xml(
        [
            *CURRENT_ADVISORIES,
            advisory("ALAS2023-2024-001", [], [pkg("tzdata", "2024a", "1.amzn2023")]),
        ]
    )
    advisories = au.parse_updateinfo(au.open_compressed(xml))
    assert [a.id for a in advisories] == [a["id"] for a in CURRENT_ADVISORIES]  # no bug fix
    openssl = advisories[0]
    assert openssl.cves == ("CVE-2024-0001",) and openssl.severity == "important"
    assert openssl.issued == "2024-10-01 00:00"
    first = openssl.packages[0]
    assert (first.name, first.epoch, first.version, first.release, first.arch, first.source) == (
        "openssl", "1", "3.0.8", "1.amzn2023.0.16", "x86_64", "openssl",
    )  # fmt: skip
    assert first.evr == "1:3.0.8-1.amzn2023.0.16"
    assert openssl.packages[3].source == "openssl"  # empty src attribute: the binary name
    assert advisories[2].cves == ("CVE-2024-0002", "CVE-2024-0003")


def test_parse_updateinfo_with_namespace_and_odd_references():
    xml = (
        b'<?xml version="1.0"?><updates xmlns="http://example.invalid/ns"><update type="security">'
        b"<id>ALAS2023-2024-9</id><severity>Critical</severity><references>"
        b'<reference type="cve" id="cve-2024-1234"/><reference type="CVE" title="CVE-2024-5678"/>'
        b'<reference type="cve" id="not-a-cve"/><reference type="bugzilla" id="CVE-2024-9999"/>'
        b'</references><pkglist><collection><package name="zlib" version="1.2.13" '
        b'release="2.amzn2023" arch="x86_64"/></collection></pkglist></update></updates>'
    )
    (adv,) = au.parse_updateinfo(au.open_compressed(xml))
    assert adv.cves == ("CVE-2024-1234", "CVE-2024-5678") and adv.severity == "critical"
    assert adv.packages[0].epoch == "0" and adv.packages[0].source == "zlib"


@pytest.mark.parametrize("compress", [gzip.compress, bz2.compress, lzma.compress, bytes])
def test_open_compressed_by_magic_bytes(compress):
    xml = updateinfo_xml(CURRENT_ADVISORIES)
    assert len(au.parse_updateinfo(au.open_compressed(compress(xml)))) == 5


def test_invalid_updateinfo_is_an_error():
    with pytest.raises(au.UpdateInfoError):
        au.parse_updateinfo(au.open_compressed(b"<updates><update>"))
    with pytest.raises(au.UpdateInfoError):
        au.parse_updateinfo(au.open_compressed(gzip.compress(b"<updates>")[:-8]))


def test_decompressed_size_is_limited(monkeypatch):
    monkeypatch.setattr(au, "MAX_XML_BYTES", 100)
    with pytest.raises(au.UpdateInfoError, match="too large"):
        au.parse_updateinfo(au.open_compressed(gzip.compress(updateinfo_xml(CURRENT_ADVISORIES))))


def test_source_rpm_name():
    assert au._source_name("openssl-3.0.8-1.amzn2023.0.14.src.rpm", "x") == "openssl"
    assert au._source_name("python3.11-pip-22.3.1-4.amzn2023.0.3.src.rpm", "x") == (
        "python3.11-pip"
    )
    assert au._source_name(None, "fallback") == "fallback"
    assert au._source_name("garbage", "fallback") == "fallback"


def test_parse_mirror_list_and_repomd():
    body = b"# comment\n\nhttps://cdn.amazonlinux.com/al2023/core/guids/abc/x86_64\n"
    assert au.parse_mirror_list(body) == "https://cdn.amazonlinux.com/al2023/core/guids/abc/x86_64/"
    with pytest.raises(au.UpdateInfoError, match="non-HTTPS"):
        au.parse_mirror_list(b"http://cdn.amazonlinux.com/x/\n")
    with pytest.raises(au.UpdateInfoError, match="empty"):
        au.parse_mirror_list(b"\n# nothing\n")
    assert au.parse_repomd(repomd_xml()) == "repodata/0123abcd-updateinfo.xml.gz"
    for bad in ("../../etc/passwd", "/abs/updateinfo.xml.gz", "https://evil/x.gz"):
        with pytest.raises(au.UpdateInfoError, match="unexpected"):
            au.parse_repomd(repomd_xml(href=bad))
    with pytest.raises(au.UpdateInfoError, match="no updateinfo"):
        au.parse_repomd(b'<repomd><data type="primary"><location href="p.xml"/></data></repomd>')
    with pytest.raises(au.UpdateInfoError, match="invalid repomd"):
        au.parse_repomd(b"<repomd")


@pytest.mark.parametrize(
    ("releasever", "arch"),
    [("2023", "x86_64"), ("2023.6.2024101", "x86_64"), ("../x", "x86_64"), ("latest/x", "x86_64"),
     (RELEASEVER, "i686"), (RELEASEVER, "x86_64/../")],
)  # fmt: skip
def test_only_valid_repositories_reach_a_url(tmp_path, releasever, arch):
    cdn = FakeCdn()
    info = source(tmp_path, cdn).lookup(releasever, arch)
    assert info.status == au.FAILED and not info.available and cdn.calls == []


def test_fetch_follows_mirror_list_repomd_and_updateinfo(tmp_path):
    cdn = FakeCdn()
    info = source(tmp_path, cdn).lookup(RELEASEVER, "x86_64")
    assert info.status == au.OK and info.repo == f"{RELEASEVER}/x86_64"
    assert info.repo_url == "https://cdn.amazonlinux.com/al2023/core/guids/" + "0" * 64 + "/x86_64/"
    assert cdn.calls == [
        f"https://cdn.amazonlinux.com/al2023/core/mirrors/{RELEASEVER}/x86_64/mirror.list",
        info.repo_url + "repodata/repomd.xml",
        info.repo_url + "repodata/0123abcd-updateinfo.xml.gz",
    ]
    assert [a.id for a in info.for_cve("cve-2024-0002 ")] == [
        "ALAS2023-2024-500", "ALAS2023-2024-650",
    ]  # fmt: skip
    assert info.for_cve("CVE-2000-0001") == []


# --- cache (same rules as NVD) ---------------------------------------------------------


def test_ttl_is_the_nvd_ttl():
    assert au.CACHE_MAX_AGE == timedelta(days=30)


def test_cache_miss_then_hit_and_memo(tmp_path):
    cdn = FakeCdn()
    src = source(tmp_path, cdn)
    first = src.lookup(RELEASEVER, "x86_64")
    assert src.lookup(RELEASEVER, "x86_64") is first and cdn.downloads == 1  # memo
    src.start_run()
    again = src.lookup(RELEASEVER, "x86_64")
    assert again.status == au.OK and cdn.downloads == 1  # from the SQLite cache
    assert [a.id for a in again.advisories] == [a.id for a in first.advisories]
    assert again.advisories == first.advisories and again.fetched_at == T0.isoformat()
    # A new source (e.g. after an app restart) reads the same cache.
    other = au.UpdateInfoSource(src._cache(), transport=cdn, now=Clock())
    assert other.lookup(RELEASEVER, "x86_64").status == au.OK and cdn.downloads == 1


def test_ttl_expiry_refetches(tmp_path):
    cdn, clock = FakeCdn(), Clock()
    src = source(tmp_path, cdn, clock)
    src.lookup(RELEASEVER, "x86_64")
    clock.now = T0 + timedelta(days=29, hours=23)
    src.start_run()
    src.lookup(RELEASEVER, "x86_64")
    assert cdn.downloads == 1
    clock.now = T0 + timedelta(days=30)
    src.start_run()
    info = src.lookup(RELEASEVER, "x86_64")
    assert info.status == au.OK and cdn.downloads == 2 and info.fetched_at == clock.now.isoformat()


def test_failure_is_not_cached(tmp_path):
    cdn = FakeCdn(fail=OSError("Temporary failure in name resolution"))
    src = source(tmp_path, cdn)
    info = src.lookup(RELEASEVER, "x86_64")
    assert info.status == au.FAILED and info.advisories is None
    assert "unreachable" in info.error and "name resolution" in info.error
    assert src._cache().get_updateinfo_cache(f"{RELEASEVER}/x86_64") is None
    cdn.fail = None
    src.start_run()
    assert src.lookup(RELEASEVER, "x86_64").status == au.OK


def test_http_error_is_not_cached_and_unknown_releasever_fails(tmp_path):
    src = source(tmp_path, FakeCdn())
    info = src.lookup("2023.0.20990101", "x86_64")  # not published
    assert info.status == au.FAILED and "HTTP 404" in info.error
    assert src._cache().get_updateinfo_cache("2023.0.20990101/x86_64") is None


def test_expired_entry_is_used_as_stale_fallback_and_kept(tmp_path):
    cdn, clock = FakeCdn(), Clock()
    src = source(tmp_path, cdn, clock)
    src.lookup(RELEASEVER, "x86_64")
    clock.now = T0 + timedelta(days=45)
    cdn.fail = TimeoutError("timed out")
    src.start_run()
    info = src.lookup(RELEASEVER, "x86_64")
    assert info.status == au.STALE and info.available and info.fetched_at == T0.isoformat()
    assert "timed out" in info.error
    # The failure did not overwrite the old entry.
    assert src._cache().get_updateinfo_cache(f"{RELEASEVER}/x86_64")[2] == T0.isoformat()


def test_unreachable_cdn_is_not_retried_within_a_run(tmp_path):
    cdn = FakeCdn(fail=OSError("Network is unreachable"))
    src = source(tmp_path, cdn)
    assert src.lookup(RELEASEVER, "x86_64").status == au.FAILED
    assert src.lookup("latest", "x86_64").status == au.FAILED
    assert len(cdn.calls) == 1  # the breaker spared the second repository
    src.start_run()
    src.lookup("latest", "x86_64")
    assert len(cdn.calls) == 2


def test_force_refresh_bypasses_a_fresh_cache(tmp_path):
    cdn = FakeCdn()
    src = source(tmp_path, cdn)
    src.lookup(RELEASEVER, "x86_64")
    src.start_run(force_refresh=True)
    src.lookup(RELEASEVER, "x86_64")
    assert cdn.downloads == 2
    src.start_run()
    src.lookup(RELEASEVER, "x86_64")
    assert cdn.downloads == 2


@pytest.mark.parametrize(
    ("advisories", "fetched_at"),
    [("not json", T0.isoformat()), ('{"a": 1}', T0.isoformat()), ("[]", "not a date"),
     ('[{"id": "x"}]', T0.isoformat())],
)  # fmt: skip
def test_corrupt_cache_row_falls_back_to_network(tmp_path, advisories, fetched_at):
    cdn = FakeCdn()
    src = source(tmp_path, cdn)
    src._cache().put_updateinfo_cache(f"{RELEASEVER}/x86_64", advisories, None, fetched_at)
    assert src.lookup(RELEASEVER, "x86_64").status == au.OK and cdn.downloads == 1


def test_unusable_cache_database_falls_back_to_network(tmp_path):
    cdn = FakeCdn()
    src = source(tmp_path, cdn)
    with sqlite3.connect(src._cache().path) as conn:
        conn.execute("DROP TABLE amazon_updateinfo_cache")
    conn.close()
    info = src.lookup(RELEASEVER, "x86_64")
    assert info.status == au.OK and len(info.advisories) == 5


def test_unexpected_error_is_a_failed_lookup(tmp_path):
    def broken(url, timeout):
        raise RuntimeError("boom")

    info = source(tmp_path, broken).lookup(RELEASEVER, "x86_64")
    assert info.status == au.FAILED and info.error == "boom"


def test_clear_empties_the_cache(tmp_path):
    cdn = FakeCdn()
    src = source(tmp_path, cdn)
    assert src.clear() is False
    src.lookup(RELEASEVER, "x86_64")
    assert src.clear() is True
    assert src._cache().get_updateinfo_cache(f"{RELEASEVER}/x86_64") is None
    src.lookup(RELEASEVER, "x86_64")
    assert cdn.downloads == 2


def test_cached_json_is_slim(tmp_path):
    src = source(tmp_path)
    src.lookup(RELEASEVER, "x86_64")
    stored = json.loads(src._cache().get_updateinfo_cache(f"{RELEASEVER}/x86_64")[0])
    assert stored[0] == {
        "id": "ALAS2023-2024-700", "severity": "important", "issued": "2024-10-01 00:00",
        "cves": ["CVE-2024-0001"],
        "packages": [
            ["openssl", "1", "3.0.8", "1.amzn2023.0.16", "x86_64", "openssl"],
            ["openssl-libs", "1", "3.0.8", "1.amzn2023.0.16", "x86_64", "openssl"],
            ["openssl-libs", "1", "3.0.8", "1.amzn2023.0.16", "aarch64", "openssl"],
            ["openssl", "1", "3.0.8", "1.amzn2023.0.16", "src", "openssl"],
        ],
    }  # fmt: skip


def test_settings_clear_also_empties_the_updateinfo_cache(client, db_path):
    Database(db_path).put_updateinfo_cache("latest/x86_64", "[]", None, T0.isoformat())
    response = client.post("/settings/clear-cache", follow_redirects=False)
    assert response.status_code == 303
    assert Database(db_path).get_updateinfo_cache("latest/x86_64") is None


# --- schema v12 --------------------------------------------------------------------------


def columns(path, table):
    with sqlite3.connect(path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    conn.close()
    return {row[1]: (row[2], row[3], row[5]) for row in rows}  # type, not null, pk


def test_fresh_database_is_v12_with_the_updateinfo_cache(db_path):
    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    conn.close()
    assert columns(db_path, "amazon_updateinfo_cache") == {
        "repo": ("TEXT", 0, 1),
        "advisories": ("TEXT", 1, 0),
        "repo_url": ("TEXT", 0, 0),
        "fetched_at": ("TEXT", 1, 0),
    }
    db.put_updateinfo_cache("latest/x86_64", "[]", "https://x/", "t1")
    db.put_updateinfo_cache("latest/x86_64", "[1]", None, "t2")  # upsert
    assert db.get_updateinfo_cache("latest/x86_64") == ("[1]", None, "t2")
    assert db.clear_updateinfo_cache() == 1


def _legacy_db(db_path, version):
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    for v in range(1, version + 1):
        conn.executescript(_MIGRATIONS[v])
    conn.execute(f"PRAGMA user_version = {version}")
    conn.execute(
        "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
        "VALUES ('keep', '10.0.0.1', '/k.pem', 't', 't')"
    )
    conn.execute("INSERT INTO reports (filename, content, uploaded_at, status) "
                 "VALUES ('r.json', '{\"keep\": [\"CVE-2024-0001\"]}', 't', 'VALID')")  # fmt: skip
    conn.commit()
    return conn


def test_v11_database_upgrades_to_v12_keeping_data(db_path):
    conn = _legacy_db(db_path, 11)
    conn.execute("UPDATE servers SET ssh_user = 'ec2-user'")
    conn.execute("INSERT INTO nvd_cache (cve, metrics, fetched_at) VALUES ('CVE-1', NULL, 't')")
    conn.execute("INSERT INTO cve_metadata_cache (cve, document, fetched_at) "
                 "VALUES ('CVE-2', '{}', 't')")  # fmt: skip
    conn.execute(
        "INSERT INTO analysis_runs (report_filename, report_uploaded_at, report_content, "
        "started_at, status) VALUES ('r.json', 't', '{}', 't', 'completed')"
    )
    conn.execute(
        "INSERT INTO server_analyses (run_id, position, server_name, reported_cves, status, "
        "os_id) VALUES (1, 0, 'keep', '[]', 'complete', 'ubuntu')"
    )
    conn.commit()
    conn.close()
    with sqlite3.connect(db_path) as check:
        tables = {r[0] for r in check.execute("SELECT name FROM sqlite_master")}
    check.close()
    assert "amazon_updateinfo_cache" not in tables

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    check.close()
    assert db.get_server_by_name("keep").ssh_user == "ec2-user"
    assert db.get_nvd_cache("CVE-1") == (None, None, "t")
    assert db.get_cve_metadata("CVE-2") == ("{}", "t")
    assert db.get_analysis_run(1).servers[0].os_id == "ubuntu"
    assert db.get_latest_report().servers == {"keep": ["CVE-2024-0001"]}
    assert db.get_updateinfo_cache("latest/x86_64") is None
    db.put_updateinfo_cache("latest/x86_64", "[]", None, "t")
    # Reopening does not migrate again (the cache entry survives).
    assert Database(db_path).get_updateinfo_cache("latest/x86_64") == ("[]", None, "t")


def test_full_upgrade_path_from_v1_reaches_v12(db_path):
    _legacy_db(db_path, 1).close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    check.close()
    server = db.get_server_by_name("keep")
    assert (server.ip_address, server.ssh_user) == ("10.0.0.1", "ubuntu")
    assert db.get_latest_report().servers == {"keep": ["CVE-2024-0001"]}
    assert "repo" in columns(db_path, "amazon_updateinfo_cache")


def test_v12_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "amazon_updateinfo_cache" in _MIGRATIONS[12]
    assert all("amazon_updateinfo_cache" not in _MIGRATIONS[v] for v in range(1, 12))
