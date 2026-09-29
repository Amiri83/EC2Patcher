import json

from conftest import FakeSSH

from ec2patcher.database import Database


def add(client, name, ip, pem, action="save"):
    return client.post(
        "/servers/new",
        data={"name": name, "ip_address": ip, "pem_path": str(pem), "action": action},
        follow_redirects=True,
    )


def upload(client, content, filename="security-report.json"):
    if not isinstance(content, (str, bytes)):
        content = json.dumps(content)
    return client.post(
        "/reports/upload", files={"report_file": (filename, content, "application/json")}
    )


# --- navigation ----------------------------------------------------------------


def test_all_pages_render(client):
    for path, text in [
        ("/", "Configured Servers"),
        ("/servers", "No servers configured"),
        ("/servers/new", "Save Server"),
        ("/reports", "Upload Security CVE Report"),
        ("/history", "No patch operations have been performed yet."),
        ("/settings", "later phases"),
        ("/shutdown", "Stop EC2 Patcher?"),
    ]:
        r = client.get(path)
        assert r.status_code == 200, path
        assert text in r.text, path
        assert "Shutdown App" in r.text


def test_active_nav_marked(client):
    r = client.get("/reports")
    assert '<a href="/reports" class="nav-link active"' in r.text


def test_static_assets_served(client):
    assert client.get("/static/style.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_404_page(client):
    r = client.get("/does-not-exist")
    assert r.status_code == 404
    assert "Page not found" in r.text


def test_dashboard_counts(client, pem_file):
    add(client, "app-prod-01", "10.10.20.15", pem_file)
    add(client, "app-prod-02", "10.10.20.16", pem_file)
    r = client.get("/")
    assert '<div class="stat-value">2</div>' in r.text
    assert "Running" in r.text
    assert "None uploaded" in r.text


# --- server CRUD ------------------------------------------------------------------


def test_add_server(client, pem_file):
    r = add(client, "app-prod-01", "10.10.20.15", pem_file)
    assert r.status_code == 200
    assert "Server &#39;app-prod-01&#39; was added." in r.text
    assert "10.10.20.15" in r.text and str(pem_file) in r.text


def test_add_server_validation_errors(client, tmp_path):
    r = add(client, "", "not-an-ip", tmp_path / "missing.pem")
    assert r.status_code == 422
    assert "Server name is required." in r.text
    assert "is not a valid IP address" in r.text
    assert "PEM file does not exist" in r.text


def test_duplicate_name_rejected(client, pem_file):
    add(client, "app-prod-01", "10.10.20.15", pem_file)
    r = add(client, "app-prod-01", "10.10.20.16", pem_file)
    assert r.status_code == 422
    assert "already exists" in r.text


def test_edit_server(client, db_path, pem_file, tmp_path):
    add(client, "server-b", "10.0.0.2", pem_file)
    server = Database(db_path).get_server_by_name("server-b")
    assert client.get(f"/servers/{server.id}/edit").status_code == 200
    other_pem = tmp_path / "other.pem"
    other_pem.write_text("x")
    r = client.post(
        f"/servers/{server.id}/edit",
        follow_redirects=True,
        data={
            "name": "server-b2",
            "ip_address": "10.0.0.22",
            "pem_path": str(other_pem),
            "action": "save",
        },
    )
    assert "was updated" in r.text
    got = Database(db_path).get_server(server.id)
    assert (got.name, got.ip_address, got.pem_path) == ("server-b2", "10.0.0.22", str(other_pem))


def test_edit_invalid_keeps_original(client, db_path, pem_file):
    add(client, "server-b", "10.0.0.2", pem_file)
    server = Database(db_path).get_server_by_name("server-b")
    r = client.post(
        f"/servers/{server.id}/edit",
        data={"name": "server-b", "ip_address": "999.0.0.1", "pem_path": str(pem_file)},
    )
    assert r.status_code == 422
    assert Database(db_path).get_server(server.id).ip_address == "10.0.0.2"


def test_edit_missing_server_redirects(client):
    r = client.get("/servers/999/edit", follow_redirects=True)
    assert "no longer exists" in r.text


def test_delete_server(client, db_path, pem_file):
    add(client, "server-a", "10.0.0.1", pem_file)
    add(client, "server-b", "10.0.0.2", pem_file)
    server = Database(db_path).get_server_by_name("server-a")
    r = client.post(f"/servers/{server.id}/delete", follow_redirects=True)
    assert "was deleted" in r.text
    names = {s.name for s in Database(db_path).list_servers()}
    assert names == {"server-b"}


def test_clear_all_requires_confirmation(client, db_path, pem_file):
    add(client, "server-a", "10.0.0.1", pem_file)
    add(client, "server-b", "10.0.0.2", pem_file)
    page = client.get("/servers").text
    assert "This will remove all configured servers." in page
    assert 'data-required-text="DELETE SERVERS"' in page

    for wrong in ("", "delete servers", "DELETE"):
        r = client.post("/servers/clear", data={"confirm_text": wrong})
        assert r.status_code == 400
        assert "NOT cleared" in r.text
    assert Database(db_path).count_servers() == 2

    r = client.post(
        "/servers/clear", data={"confirm_text": "DELETE SERVERS"}, follow_redirects=True
    )
    assert "All configured servers were removed (2 deleted)." in r.text
    assert Database(db_path).count_servers() == 0
    assert '<div class="stat-value">0</div>' in client.get("/").text

    add(client, "server-c", "10.0.0.3", pem_file)
    assert Database(db_path).count_servers() == 1


def test_html_is_escaped(client, db_path, pem_file):
    # Name validation blocks markup, but the PEM path is free text and must be escaped.
    weird = pem_file.parent / "<b>x<i>.pem"
    weird.write_text("x")
    add(client, "server-a", "10.0.0.1", weird)
    r = client.get("/servers")
    assert "<b>x<i>" not in r.text
    assert "&lt;b&gt;x&lt;i&gt;" in r.text


# --- SSH test from the GUI -----------------------------------------------------


def test_ssh_test_from_form_success(client, fake_ssh, pem_file):
    r = add(client, "app-prod-01", "10.10.20.15", pem_file, action="test")
    assert r.status_code == 200
    assert "SSH CONNECTION SUCCESSFUL" in r.text
    assert "ip-10-10-20-15" in r.text and "Ubuntu 24.04 LTS" in r.text and "amd64" in r.text
    # Testing does not save, and form values are preserved.
    assert 'value="app-prod-01"' in r.text
    assert "No servers configured" in client.get("/servers").text
    assert len(fake_ssh.calls) == 1


def test_ssh_test_from_form_missing_pem(client, fake_ssh, tmp_path):
    r = add(client, "a", "10.0.0.1", tmp_path / "missing.pem", action="test")
    assert "SSH CONNECTION FAILED" in r.text
    assert "PEM file does not exist" in r.text
    assert fake_ssh.calls == []


def test_ssh_test_saved_server_failure(make_client, db_path, pem_file):
    fake = FakeSSH(returncode=255, stderr="ubuntu@10.0.0.1: Permission denied (publickey).")
    with make_client(ssh=fake) as c:
        add(c, "app-prod-01", "10.0.0.1", pem_file)
        server = Database(db_path).get_server_by_name("app-prod-01")
        r = c.post(f"/servers/{server.id}/test")
    assert r.status_code == 200
    assert "SSH CONNECTION FAILED" in r.text
    assert "Permission denied (publickey)" in r.text
    assert "Traceback" not in r.text


def test_ssh_test_saved_server_success(client, db_path, pem_file):
    add(client, "app-prod-01", "10.10.20.15", pem_file)
    server = Database(db_path).get_server_by_name("app-prod-01")
    r = client.post(f"/servers/{server.id}/test")
    assert "SSH CONNECTION SUCCESSFUL" in r.text


def test_ssh_test_edit_form(client, db_path, pem_file):
    add(client, "app-prod-01", "10.10.20.15", pem_file)
    server = Database(db_path).get_server_by_name("app-prod-01")
    r = client.post(
        f"/servers/{server.id}/edit",
        data={
            "name": "app-prod-01",
            "ip_address": "10.10.20.15",
            "pem_path": str(pem_file),
            "action": "test",
        },
    )
    assert "SSH CONNECTION SUCCESSFUL" in r.text


# --- reports -----------------------------------------------------------------


def test_upload_valid_report_and_persist(make_client, pem_file):
    with make_client() as c:
        add(c, "app-prod-01", "10.0.0.1", pem_file)
        add(c, "database-prod-01", "10.0.0.2", pem_file)
        r = upload(
            c,
            {
                "app-prod-01": ["cve-2026-12345", "CVE-2026-67890"],
                "database-prod-01": ["CVE-2026-22222"],
            },
        )
        assert r.status_code == 200
        assert "VALID" in r.text and "VALIDATION FAILED" not in r.text
        assert "<dt>Servers in report</dt><dd>2</dd>" in r.text
        assert "<dt>CVEs in report</dt><dd>3</dd>" in r.text
        assert "CVE-2026-12345" in r.text and "cve-2026-12345" not in r.text

    # New app instance on the same DB == restart.
    with make_client() as c:
        page = c.get("/reports").text
        assert "security-report.json" in page
        assert "2 CVEs" in page and "1 CVE<" in page
        assert "security-report.json" in c.get("/").text


def test_upload_malformed_json(client, pem_file):
    add(client, "app-prod-01", "10.0.0.1", pem_file)
    r = upload(client, '{"app-prod-01": [')
    assert r.status_code == 422
    assert "VALIDATION FAILED" in r.text
    assert "Malformed JSON" in r.text
    assert "No report uploaded yet" in r.text


def test_upload_unknown_server(client, pem_file):
    add(client, "app-prod-01", "10.0.0.1", pem_file)
    r = upload(client, {"app-prod-01": ["CVE-2026-12345"], "app-prod-99": ["CVE-2026-1111"]})
    assert r.status_code == 422
    assert "VALIDATION FAILED" in r.text
    assert "Unknown server: app-prod-99. This server is not configured in EC2Patcher." in r.text


def test_unknown_server_error_is_specific_and_known_servers_can_still_upload(make_client, pem_file):
    c = make_client()
    add(c, "app-prod-01", "10.0.0.1", pem_file)
    add(c, "app-prod-02", "10.0.0.2", pem_file)
    bad = upload(c, {"app-prod-01": ["CVE-2026-12345"], "missing": ["CVE-2026-11111"]})
    assert bad.status_code == 422
    assert "Unknown server: missing" in bad.text
    assert "Unknown server: app-prod-01" not in bad.text
    assert upload(c, {"app-prod-01": ["CVE-2026-12345"]}).status_code == 200


def test_failed_upload_keeps_previous_report(client, pem_file):
    add(client, "app-prod-01", "10.0.0.1", pem_file)
    upload(client, {"app-prod-01": ["CVE-2026-12345"]}, filename="good.json")
    r = upload(client, {"app-prod-01": ["not-a-cve"]}, filename="bad.json")
    assert "invalid CVE identifier" in r.text
    assert "previously accepted report is still in use" in r.text
    assert "good.json" in client.get("/reports").text


def test_upload_rejects_non_json_file(client):
    r = upload(client, "hello", filename="notes.txt")
    assert r.status_code == 422
    assert "Only .json files are accepted." in r.text


def test_upload_without_file(client):
    r = client.post("/reports/upload", data={})
    assert r.status_code == 400
    assert "Please choose a JSON file." in r.text


def test_report_warns_when_server_removed(client, db_path, pem_file):
    add(client, "app-prod-01", "10.0.0.1", pem_file)
    upload(client, {"app-prod-01": ["CVE-2026-12345"]})
    client.post("/servers/clear", data={"confirm_text": "DELETE SERVERS"})
    assert "no longer configured: app-prod-01" in client.get("/reports").text


# --- shutdown / safety -------------------------------------------------------------


def test_shutdown_requires_confirmation(client, shutdown_calls):
    r = client.post("/shutdown", data={}, follow_redirects=False)
    assert r.status_code == 303
    assert shutdown_calls == []


def test_shutdown_keeps_data(make_client, db_path, pem_file, shutdown_calls):
    with make_client() as c:
        add(c, "app-prod-01", "10.0.0.1", pem_file)
        r = c.post("/shutdown", data={"confirm": "yes"})
        assert r.status_code == 200
        assert "has been shut down" in r.text
    assert shutdown_calls == [True]
    assert db_path.exists()
    with make_client() as c:
        assert "app-prod-01" in c.get("/servers").text


def test_restart_persistence_six_servers(make_client, db_path, pem_file):
    with make_client() as c:
        for i in range(6):
            add(c, f"server-{i}", f"10.0.1.{i + 1}", pem_file)
    with make_client() as c:
        page = c.get("/servers").text
        for i in range(6):
            assert f"server-{i}" in page and f"10.0.1.{i + 1}" in page
        assert '<div class="stat-value">6</div>' in c.get("/").text


def test_cross_site_post_rejected(client, pem_file, db_path):
    add(client, "app-prod-01", "10.0.0.1", pem_file)
    r = client.post(
        "/servers/clear",
        data={"confirm_text": "DELETE SERVERS"},
        headers={"Origin": "http://evil.example"},
    )
    assert r.status_code == 403
    assert Database(db_path).count_servers() == 1


def test_untrusted_host_rejected(make_client):
    with make_client() as c:
        r = c.get("/", headers={"Host": "evil.example"})
    assert r.status_code == 400


def test_unexpected_error_hides_traceback(db_path, monkeypatch):
    from fastapi.testclient import TestClient

    from ec2patcher.app import create_app

    app = create_app(db_path=db_path)

    def boom(self):
        raise RuntimeError("secret internal detail")

    monkeypatch.setattr(Database, "count_servers", boom)
    with TestClient(app, base_url="http://127.0.0.1", raise_server_exceptions=False) as c:
        r = c.get("/")
    assert r.status_code == 500
    assert "unexpected error" in r.text
    assert "secret internal detail" not in r.text and "Traceback" not in r.text


def test_format_timestamp():
    from ec2patcher.app import format_timestamp

    assert format_timestamp("2026-09-26T12:00:00+00:00").startswith("2026-09-2")
    assert format_timestamp("garbage") == "garbage"
