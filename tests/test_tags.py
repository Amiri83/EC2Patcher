"""Phase 1.5: user-defined server tags (DB, migration, validation, routes)."""

import json
import sqlite3

import pytest

from ec2patcher.database import _MIGRATIONS, Database, DuplicateTagKeyError
from ec2patcher.validation import check_tags, tag_rows, validate_server_input


def pairs(db, server_id):
    return db.tag_pairs(server_id)


def tag_row_count(db, server_id=None):
    with sqlite3.connect(db.path) as conn:
        if server_id is None:
            return conn.execute("SELECT COUNT(*) FROM server_tags").fetchone()[0]
        sql = "SELECT COUNT(*) FROM server_tags WHERE server_id = ?"
        return conn.execute(sql, (server_id,)).fetchone()[0]


def save(client, name, ip, pem, tags=(), action="save", server_id=None):
    """Post the Add/Edit server form with parallel tag_key / tag_value arrays."""
    data = {
        "name": name,
        "ip_address": ip,
        "pem_path": str(pem),
        "action": action,
        "tag_key": [k for k, _ in tags],
        "tag_value": [v for _, v in tags],
    }
    url = "/servers/new" if server_id is None else f"/servers/{server_id}/edit"
    return client.post(url, data=data, follow_redirects=True)


# --- database ------------------------------------------------------------------


def test_server_without_tags(db):
    s = db.create_server("a", "10.0.0.1", "/k.pem")
    assert s.tags == []
    assert db.list_tags(s.id) == []
    assert db.list_servers()[0].tags == []


def test_server_with_one_tag(db):
    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("display_name", "Billing API")])
    assert [(t.key, t.value) for t in s.tags] == [("display_name", "Billing API")]
    assert s.tags[0].server_id == s.id


def test_server_with_multiple_tags_sorted_by_key(db):
    tags = [("owner", "ops"), ("Env", "prod"), ("display_name", "Billing"), ("app", "")]
    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=tags)
    expected = [("app", ""), ("display_name", "Billing"), ("Env", "prod"), ("owner", "ops")]
    assert pairs(db, s.id) == expected
    assert [(t.key, t.value) for t in db.get_server(s.id).tags] == expected
    assert [(t.key, t.value) for t in db.list_servers()[0].tags] == expected


def test_tags_persist_after_reopen(db_path):
    s = Database(db_path).create_server("a", "10.0.0.1", "/k.pem", tags=[("k1", "v1"), ("k2", "")])
    reopened = Database(db_path)
    assert pairs(reopened, s.id) == [("k1", "v1"), ("k2", "")]


def test_set_tags_edit_add_remove(db):
    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "dev"), ("owner", "me")])
    old = {t.key: t for t in db.list_tags(s.id)}

    db.set_tags(s.id, [("env", "prod"), ("team", "sre")])  # edit env, remove owner, add team
    assert pairs(db, s.id) == [("env", "prod"), ("team", "sre")]
    new = {t.key: t for t in db.list_tags(s.id)}
    assert new["env"].id == old["env"].id  # updated in place, not re-created

    db.set_tags(s.id, [])
    assert pairs(db, s.id) == []
    assert tag_row_count(db, s.id) == 0


def test_set_tags_can_change_key_case(db):
    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "prod")])
    db.set_tags(s.id, [("ENV", "prod")])
    assert pairs(db, s.id) == [("ENV", "prod")]


def test_update_server_replaces_tags_only_when_given(db):
    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "dev")])
    assert db.update_server(s.id, "a", "10.0.0.2", "/k.pem")  # tags=None: untouched
    assert pairs(db, s.id) == [("env", "dev")]
    assert db.update_server(s.id, "a", "10.0.0.2", "/k.pem", tags=[("role", "web")])
    assert pairs(db, s.id) == [("role", "web")]


def test_same_key_on_different_servers(db):
    a = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("display_name", "Alpha")])
    b = db.create_server("b", "10.0.0.2", "/k.pem", tags=[("display_name", "Beta")])
    assert pairs(db, a.id) == [("display_name", "Alpha")]
    assert pairs(db, b.id) == [("display_name", "Beta")]


def test_duplicate_key_on_same_server_rejected(db):
    with pytest.raises(DuplicateTagKeyError):
        db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "1"), ("ENV", "2")])
    assert db.count_servers() == 0  # nothing half-written

    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "1")])
    with pytest.raises(DuplicateTagKeyError):
        db.set_tags(s.id, [("env", "1"), ("env", "2")])
    assert pairs(db, s.id) == [("env", "1")]


def test_unique_tag_key_constraint_in_schema(db):
    s = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "1")])
    with sqlite3.connect(db.path) as conn, pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO server_tags (server_id, key, value, created_at, updated_at) "
            "VALUES (?, 'Env', '2', 'now', 'now')",
            (s.id,),
        )


def test_delete_server_removes_its_tags(db):
    a = db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "1"), ("x", "y")])
    b = db.create_server("b", "10.0.0.2", "/k.pem", tags=[("env", "2")])
    assert db.delete_server(a.id)
    assert tag_row_count(db, a.id) == 0
    assert pairs(db, b.id) == [("env", "2")]


def test_clear_servers_removes_all_tags(db):
    db.create_server("a", "10.0.0.1", "/k.pem", tags=[("env", "1")])
    db.create_server("b", "10.0.0.2", "/k.pem", tags=[("env", "2"), ("x", "")])
    db.save_report("r.json", {"a": ["CVE-2026-1234"]}, status="VALID")
    assert db.clear_servers() == 2
    assert tag_row_count(db) == 0
    assert db.get_latest_report() is not None


def test_phase1_database_migrates_in_place(db_path):
    """A Phase-1 DB (user_version 1) gains server_tags without losing servers or reports."""
    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_MIGRATIONS[1])
        conn.execute("PRAGMA user_version = 1")
        conn.execute(
            "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
            "VALUES ('app-prod-01', '10.10.20.15', '/k.pem', 'then', 'then')"
        )
        conn.execute(
            "INSERT INTO reports (filename, content, uploaded_at, status) VALUES (?, ?, ?, ?)",
            ("r.json", json.dumps({"app-prod-01": ["CVE-2026-12345"]}), "then", "VALID"),
        )
    conn.close()

    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3
    conn.close()
    server = db.get_server_by_name("app-prod-01")
    assert (server.ip_address, server.pem_path, server.tags) == ("10.10.20.15", "/k.pem", [])
    assert db.get_latest_report().servers == {"app-prod-01": ["CVE-2026-12345"]}

    db.set_tags(server.id, [("display_name", "Billing API")])
    assert pairs(Database(db_path), server.id) == [("display_name", "Billing API")]
    assert db.delete_server(server.id)
    assert tag_row_count(db) == 0


# --- validation ------------------------------------------------------------------


def test_tag_rows_trim_and_drop_empty():
    rows = tag_rows(["  env ", "", "  ", "owner"], [" prod ", "", "   ", ""])
    assert rows == [{"key": "env", "value": "prod"}, {"key": "owner", "value": ""}]


def test_tag_rows_tolerates_malformed_input():
    assert tag_rows(None, None) == []
    assert tag_rows(["a", "b"], ["1"]) == [{"key": "a", "value": "1"}, {"key": "b", "value": ""}]
    assert tag_rows([], ["orphan"]) == [{"key": "", "value": "orphan"}]


def test_check_tags_rules():
    assert check_tags([{"key": "env", "value": "prod"}, {"key": "x", "value": ""}]) is None
    assert "key is required" in check_tags([{"key": "", "value": "prod"}])
    err = check_tags([{"key": "display_name", "value": "a"}, {"key": "Display_Name", "value": "b"}])
    assert err == "Duplicate tag key: Display_Name"
    assert "at most 64" in check_tags([{"key": "k" * 65, "value": ""}])
    assert "at most 256" in check_tags([{"key": "k", "value": "v" * 257}])
    many = [{"key": f"k{i}", "value": ""} for i in range(51)]
    assert "at most 50 tags" in check_tags(many)


def test_validate_server_input_tags(db, pem_file):
    ok = validate_server_input(
        db, "a", "10.0.0.1", str(pem_file), tag_keys=[" env "], tag_values=[" prod "]
    )
    assert ok.is_valid and ok.tags == [("env", "prod")]

    bad = validate_server_input(
        db, "a", "10.0.0.1", str(pem_file), tag_keys=["env", "env"], tag_values=["1", "2"]
    )
    assert bad.errors == {"tags": "Duplicate tag key: env"}


# --- routes / UI -------------------------------------------------------------------


def test_add_server_with_tags(client, db_path, pem_file):
    tags = [("display_name", "Billing API"), ("env", "prod")]
    r = save(client, "app-prod-01", "10.10.20.15", pem_file, tags=tags)
    assert r.status_code == 200
    assert "Server &#39;app-prod-01&#39; was added." in r.text
    db = Database(db_path)
    assert pairs(db, db.get_server_by_name("app-prod-01").id) == tags


def test_add_server_without_tags_and_blank_rows_ignored(client, db_path, pem_file):
    r = save(client, "a", "10.0.0.1", pem_file)
    assert "was added" in r.text
    r = save(client, "b", "10.0.0.2", pem_file, tags=[("", ""), ("  ", " ")])
    assert "was added" in r.text
    assert tag_row_count(Database(db_path)) == 0


def test_add_server_rejects_blank_key_and_keeps_input(client, db_path, pem_file):
    r = save(client, "a", "10.0.0.1", pem_file, tags=[("", "orphan value"), ("env", "prod")])
    assert r.status_code == 422
    assert "Tag 1: key is required." in r.text
    assert 'value="orphan value"' in r.text and 'value="env"' in r.text
    assert Database(db_path).count_servers() == 0


def test_add_server_rejects_duplicate_key(client, db_path, pem_file):
    r = save(client, "a", "10.0.0.1", pem_file, tags=[("display_name", "x"), ("display_name", "y")])
    assert r.status_code == 422
    assert "Duplicate tag key: display_name" in r.text
    assert Database(db_path).count_servers() == 0


def test_mismatched_tag_arrays_do_not_crash(client, db_path, pem_file):
    data = {"name": "a", "ip_address": "10.0.0.1", "pem_path": str(pem_file),
            "tag_key": ["env", "owner"], "tag_value": ["prod"]}  # fmt: skip
    r = client.post("/servers/new", data=data, follow_redirects=True)
    assert r.status_code == 200
    db = Database(db_path)
    assert pairs(db, db.get_server_by_name("a").id) == [("env", "prod"), ("owner", "")]


def test_edit_form_loads_tags(client, db_path, pem_file):
    save(client, "a", "10.0.0.1", pem_file, tags=[("zone", "b"), ("display_name", "Alpha")])
    sid = Database(db_path).get_server_by_name("a").id
    r = client.get(f"/servers/{sid}/edit")
    assert r.status_code == 200
    assert r.text.index('value="display_name"') < r.text.index('value="zone"')
    assert 'value="Alpha"' in r.text


def test_edit_updates_adds_and_removes_tags(client, db_path, pem_file):
    save(client, "a", "10.0.0.1", pem_file, tags=[("env", "dev"), ("owner", "me")])
    db = Database(db_path)
    sid = db.get_server_by_name("a").id

    r = save(client, "a", "10.0.0.1", pem_file, server_id=sid,
             tags=[("env", "prod"), ("team", "sre")])  # fmt: skip
    assert "was updated" in r.text
    assert pairs(db, sid) == [("env", "prod"), ("team", "sre")]

    r = save(client, "a", "10.0.0.1", pem_file, server_id=sid)  # all rows removed
    assert "was updated" in r.text
    assert pairs(db, sid) == []


def test_edit_duplicate_key_keeps_existing_tags(client, db_path, pem_file):
    save(client, "a", "10.0.0.1", pem_file, tags=[("env", "dev")])
    db = Database(db_path)
    sid = db.get_server_by_name("a").id
    r = save(client, "a", "10.0.0.9", pem_file, server_id=sid, tags=[("x", "1"), ("X", "2")])
    assert r.status_code == 422
    assert "Duplicate tag key: X" in r.text
    assert pairs(db, sid) == [("env", "dev")]
    assert db.get_server(sid).ip_address == "10.0.0.1"


def test_test_connection_keeps_tag_rows(client, fake_ssh, pem_file):
    r = save(client, "a", "10.0.0.1", pem_file, tags=[("env", "prod")], action="test")
    assert r.status_code == 200
    assert 'value="env"' in r.text and 'value="prod"' in r.text
    args = fake_ssh.calls[0][0]
    assert "ubuntu@10.0.0.1" in args


def test_servers_page_shows_first_two_tags(client, pem_file):
    save(client, "a", "10.0.0.1", pem_file, tags=[("env", "prod"), ("display_name", "Billing")])
    r = client.get("/servers")
    assert 'class="server-tags"' in r.text
    assert "display_name:" in r.text and "Billing" in r.text
    assert "env:" in r.text and "prod" in r.text
    assert r.text.index("display_name:") < r.text.index("env:")
    assert "more</span>" not in r.text


def test_servers_page_more_indicator(client, pem_file):
    tags = [("a_key", "1"), ("b_key", "2"), ("c_key", "3"), ("d_key", "4")]
    save(client, "a", "10.0.0.1", pem_file, tags=tags)
    r = client.get("/servers")
    card = r.text[r.text.index('class="server-tags"') :]
    card = card[: card.index("</div>")]
    assert "a_key:" in card and "b_key:" in card
    assert '<span class="tag"><span class="tag-key">c_key' not in card
    assert "+2 more" in card
    assert "c_key=3" in card  # full list in the hover title


def test_servers_page_without_tags_has_no_tag_area(client, pem_file):
    save(client, "a", "10.0.0.1", pem_file)
    assert 'class="server-tags"' not in client.get("/servers").text


def test_tags_are_html_escaped(client, pem_file):
    save(client, "a", "10.0.0.1", pem_file, tags=[("<b>k</b>", "<script>x</script>")])
    r = client.get("/servers")
    assert "<script>x</script>" not in r.text
    assert "&lt;script&gt;x&lt;/script&gt;" in r.text


def test_delete_and_clear_all_remove_tags_via_ui(client, db_path, pem_file):
    save(client, "a", "10.0.0.1", pem_file, tags=[("env", "1")])
    save(client, "b", "10.0.0.2", pem_file, tags=[("env", "2")])
    save(client, "c", "10.0.0.3", pem_file, tags=[("env", "3")])
    db = Database(db_path)
    client.post(f"/servers/{db.get_server_by_name('a').id}/delete", follow_redirects=True)
    assert tag_row_count(db) == 2

    r = client.post("/servers/clear", data={"confirm_text": "nope"})
    assert r.status_code == 400 and tag_row_count(db) == 2
    r = client.post(
        "/servers/clear", data={"confirm_text": "DELETE SERVERS"}, follow_redirects=True
    )
    assert "2 deleted" in r.text
    assert tag_row_count(db) == 0


def test_tags_survive_app_restart(make_client, db_path, pem_file):
    with make_client() as c:
        save(c, "a", "10.0.0.1", pem_file, tags=[("display_name", "Alpha")])
    with make_client() as c:
        assert "Alpha" in c.get("/servers").text


def test_reports_still_match_by_server_name_not_tags(client, pem_file):
    save(client, "app-prod-01", "10.0.0.1", pem_file, tags=[("display_name", "billing")])
    r = client.post(
        "/reports/upload",
        files={"report_file": ("r.json", json.dumps({"billing": ["CVE-2026-1234"]}), "x")},
    )
    assert r.status_code == 422
    r = client.post(
        "/reports/upload",
        files={"report_file": ("r.json", json.dumps({"app-prod-01": ["CVE-2026-1234"]}), "x")},
    )
    assert r.status_code == 200
