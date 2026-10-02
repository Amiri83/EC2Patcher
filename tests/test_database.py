import sqlite3

import pytest

from ec2patcher.database import SCHEMA_VERSION, Database, DuplicateServerNameError


def test_create_and_get_server(db):
    s = db.create_server("app-prod-01", "10.10.20.15", "~/.ssh/prod.pem")
    assert s.id is not None
    got = db.get_server(s.id)
    assert (got.name, got.ip_address, got.pem_path) == (
        "app-prod-01",
        "10.10.20.15",
        "~/.ssh/prod.pem",
    )
    assert got.created_at and got.updated_at
    assert db.get_server_by_name("app-prod-01").id == s.id
    assert db.count_servers() == 1


def test_update_server(db):
    s = db.create_server("app-prod-01", "10.10.20.15", "/k.pem")
    assert db.update_server(s.id, "app-prod-02", "10.10.20.16", "/k2.pem")
    got = db.get_server(s.id)
    assert (got.name, got.ip_address, got.pem_path) == ("app-prod-02", "10.10.20.16", "/k2.pem")
    assert not db.update_server(9999, "x", "10.0.0.1", "/k.pem")


def test_delete_server(db):
    a = db.create_server("a", "10.0.0.1", "/k.pem")
    b = db.create_server("b", "10.0.0.2", "/k.pem")
    assert db.delete_server(a.id)
    assert db.get_server(a.id) is None
    assert [s.name for s in db.list_servers()] == ["b"]
    assert not db.delete_server(a.id)
    assert db.get_server(b.id) is not None


def test_unique_name_enforced(db):
    db.create_server("app-prod-01", "10.0.0.1", "/k.pem")
    with pytest.raises(DuplicateServerNameError):
        db.create_server("app-prod-01", "10.0.0.2", "/k.pem")
    with pytest.raises(DuplicateServerNameError):
        db.create_server("APP-PROD-01", "10.0.0.2", "/k.pem")


def test_unique_name_enforced_on_update(db):
    db.create_server("a", "10.0.0.1", "/k.pem")
    b = db.create_server("b", "10.0.0.2", "/k.pem")
    with pytest.raises(DuplicateServerNameError):
        db.update_server(b.id, "a", "10.0.0.2", "/k.pem")


def test_unique_constraint_in_schema(db):
    with sqlite3.connect(db.path) as conn:
        conn.execute(
            "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
            "VALUES ('x', '1.1.1.1', '/k', 'now', 'now')"
        )
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
                "VALUES ('x', '1.1.1.2', '/k', 'now', 'now')"
            )


def test_clear_servers_keeps_report(db):
    for i in range(3):
        db.create_server(f"s{i}", f"10.0.0.{i + 1}", "/k.pem")
    db.save_report("r.json", {"s0": ["CVE-2026-12345"]}, "VALID")
    assert db.clear_servers() == 3
    assert db.count_servers() == 0
    assert db.get_latest_report() is not None
    db.create_server("new", "10.0.0.9", "/k.pem")
    assert db.count_servers() == 1


def test_persistence_across_reopen(db_path):
    first = Database(db_path)
    for i in range(6):
        first.create_server(f"server-{i}", f"10.0.0.{i + 1}", f"~/.ssh/k{i}.pem")
    first.save_report("security.json", {"server-0": ["CVE-2026-00001"]}, "VALID")

    reopened = Database(db_path)
    servers = reopened.list_servers()
    assert len(servers) == 6
    assert {s.name for s in servers} == {f"server-{i}" for i in range(6)}
    assert reopened.get_server_by_name("server-3").pem_path == "~/.ssh/k3.pem"
    report = reopened.get_latest_report()
    assert report.filename == "security.json"
    assert report.servers == {"server-0": ["CVE-2026-00001"]}


def test_only_latest_report_kept(db):
    db.save_report("one.json", {"a": []}, "VALID")
    db.save_report("two.json", {"b": ["CVE-2026-11111"]}, "VALID")
    report = db.get_latest_report()
    assert report.filename == "two.json"
    assert report.cve_count == 1 and report.server_count == 1
    with sqlite3.connect(db.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0] == 1


def test_schema_version_set(db):
    with sqlite3.connect(db.path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 13


def cache_columns(path):
    with sqlite3.connect(path) as conn:
        return [
            (row[1], row[2], row[5])  # name, type, primary key
            for row in conn.execute("PRAGMA table_info(cve_metadata_cache)")
        ]


def test_v7_migration_creates_cve_metadata_cache(db_path):
    from ec2patcher.database import _MIGRATIONS

    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as conn:
        for version in range(1, 7):
            conn.executescript(_MIGRATIONS[version])
        conn.execute("PRAGMA user_version = 6")
    conn.close()
    db = Database(db_path)
    assert cache_columns(db_path) == [
        ("cve", "TEXT", 1), ("document", "TEXT", 0), ("fetched_at", "TEXT", 0),
    ]  # fmt: skip
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    conn.close()
    db.put_cve_metadata("CVE-2026-50001", '{"id": "CVE-2026-50001"}', "t1")
    db.put_cve_metadata("CVE-2026-50001", None, "t2")  # upsert; NULL = confirmed 404
    db.put_cve_metadata("CVE-2026-50002", "{}", "t1")
    assert db.get_cve_metadata("CVE-2026-50001") == (None, "t2")
    assert db.get_cve_metadata("CVE-2026-59999") is None
    assert db.clear_cve_metadata() == 2
    assert db.get_cve_metadata("CVE-2026-50002") is None


def test_v7_database_without_cache_table_gains_it(db_path):
    """A DB migrated to v7 before the cache table was part of v7 gets it on open."""
    Database(db_path)
    with sqlite3.connect(db_path) as conn:
        conn.execute("DROP TABLE cve_metadata_cache")
    conn.close()
    Database(db_path).put_cve_metadata("CVE-2026-50001", None, "t")
    assert [c[0] for c in cache_columns(db_path)] == ["cve", "document", "fetched_at"]


def test_reset_recreates_current_schema_and_instance_remains_usable(db):
    db.create_server("old", "10.0.0.1", "/k.pem")
    db.save_report("old.json", {"old": ["CVE-2026-12345"]}, "VALID")
    sidecars = [db.path.with_name(db.path.name + suffix) for suffix in ("-journal", "-wal", "-shm")]
    for path in sidecars:
        path.write_bytes(b"old")

    assert db.reset()
    assert all(not path.exists() for path in sidecars)
    assert db.count_servers() == 0 and db.get_latest_report() is None
    with db.connect() as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 13
        tables = {
            row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {
            "servers",
            "reports",
            "server_tags",
            "analysis_runs",
            "server_analyses",
            "cve_findings",
            "package_plans",
            "package_plan_cves",
            "settings",
        } <= tables
        columns = {row[1] for row in conn.execute("PRAGMA table_info(cve_findings)")}
        assert "canonical_status" in columns
        assert "apt_candidate" in columns
    db.create_server("new", "10.0.0.2", "/k.pem")
    assert db.get_server_by_name("new") is not None
