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
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 4
