"""Per-server SSH user (schema v11): storage, migration, validation, form and every ssh/scp."""

import sqlite3

import pytest
from conftest import FakeSSH

from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.services import ssh_service
from ec2patcher.validation import check_ssh_user


def columns(path, table):
    with sqlite3.connect(path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    conn.close()
    info = {row[1]: (row[2], row[3], row[4]) for row in rows}  # type, not null, default
    return info


# --- schema -----------------------------------------------------------------------------


def test_fresh_database_is_v11_with_ssh_user_and_os_id(db_path):
    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    conn.close()
    assert columns(db_path, "servers")["ssh_user"] == ("TEXT", 1, "'ubuntu'")
    assert columns(db_path, "server_analyses")["os_id"] == ("TEXT", 0, None)
    assert db.create_server("a", "10.0.0.1", "/k.pem").ssh_user == "ubuntu"
    assert db.create_server("b", "10.0.0.2", "/k.pem", ssh_user="ec2-user").ssh_user == "ec2-user"


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
                 "VALUES ('r.json', '{\"keep\": []}', 't', 'VALID')")  # fmt: skip
    conn.commit()
    return conn


def test_v10_database_upgrades_to_v11_keeping_data(db_path):
    conn = _legacy_db(db_path, 10)
    conn.execute(
        "INSERT INTO analysis_runs (report_filename, report_uploaded_at, report_content, "
        "started_at, status) VALUES ('r.json', 't', '{}', 't', 'completed')"
    )
    conn.execute(
        "INSERT INTO server_analyses (run_id, position, server_name, reported_cves, status, "
        "os_pretty_name) VALUES (1, 0, 'keep', '[]', 'complete', 'Ubuntu 24.04.3 LTS')"
    )
    conn.execute("INSERT INTO nvd_cache (cve, metrics, fetched_at) VALUES ('CVE-1', NULL, 't')")
    conn.commit()
    conn.close()
    assert "ssh_user" not in columns(db_path, "servers")

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    check.close()
    server = db.get_server_by_name("keep")
    assert server.ssh_user == "ubuntu"  # existing servers keep the formerly fixed user
    assert (server.ip_address, server.pem_path) == ("10.0.0.1", "/k.pem")
    analysis = db.get_analysis_run(1).servers[0]
    assert analysis.os_id is None and analysis.os_pretty_name == "Ubuntu 24.04.3 LTS"
    assert db.get_nvd_cache("CVE-1") == (None, None, "t")
    assert db.get_latest_report().filename == "r.json"
    # Reopening does not migrate again.
    assert Database(db_path).get_server_by_name("keep").ssh_user == "ubuntu"


def test_full_upgrade_path_from_v1_reaches_v11(db_path):
    _legacy_db(db_path, 1).close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    check.close()
    assert db.get_server_by_name("keep").ssh_user == "ubuntu"
    assert db.get_latest_report().servers == {"keep": []}
    assert "os_id" in columns(db_path, "server_analyses")


def test_update_server_ssh_user(db):
    server = db.create_server("a", "10.0.0.1", "/k.pem", ssh_user="ec2-user")
    assert db.update_server(server.id, "a", "10.0.0.1", "/k.pem")  # not given: kept
    assert db.get_server(server.id).ssh_user == "ec2-user"
    assert db.update_server(server.id, "a", "10.0.0.1", "/k.pem", ssh_user="admin")
    assert db.get_server(server.id).ssh_user == "admin"


# --- validation -------------------------------------------------------------------------


@pytest.mark.parametrize("user", ["ubuntu", "ec2-user", "admin", "_svc", "deploy.bot", "a" * 32])
def test_valid_ssh_users(user):
    assert check_ssh_user(user) is None


@pytest.mark.parametrize(
    "user",
    ["", "Ubuntu", "-oProxyCommand=x", "root@evil", "a b", "a:b", "1user", "user;id", "a" * 33,
     "$(id)", "ubuntu\n"],
)  # fmt: skip
def test_invalid_ssh_users(user):
    assert check_ssh_user(user)


# --- ssh / scp command lines --------------------------------------------------------------


def test_commands_use_the_given_user_and_port(pem_file):
    cmd = ssh_service.build_ssh_command("10.0.0.1", str(pem_file), "true", user="ec2-user")
    assert cmd[cmd.index("--") + 1 :] == ["ec2-user@10.0.0.1", "true"]
    assert "-p" not in cmd  # default port: no option
    cmd = ssh_service.build_ssh_command("10.0.0.1", str(pem_file), "true", port=2201)
    assert cmd[cmd.index("--") - 2 : cmd.index("--")] == ["-p", "2201"]
    assert cmd[cmd.index("--") + 1] == "ubuntu@10.0.0.1"
    scp = ssh_service.build_scp_command(
        "10.0.0.1", str(pem_file), ["/x/a.deb"], "/tmp/s", user="admin", port=2202
    )
    assert scp[-1] == "admin@10.0.0.1:/tmp/s/" and scp[scp.index("--") - 2] == "-P"


@pytest.mark.parametrize("bad", ["-oProxyCommand=touch /tmp/x", "a@b", ""])
def test_invalid_user_never_reaches_ssh(pem_file, bad):
    fake = FakeSSH()
    with pytest.raises(ValueError):
        ssh_service.build_ssh_command("10.0.0.1", str(pem_file), user=bad)
    remote = ssh_service.run_remote("10.0.0.1", str(pem_file), "true", fake, user=bad)
    assert not remote.ok and "SSH user" in remote.error
    assert not ssh_service.run_scp("10.0.0.1", str(pem_file), ["f"], "/tmp/s", fake, user=bad).ok
    result = ssh_service.check_connection("a", "10.0.0.1", str(pem_file), runner=fake, user=bad)
    assert not result.success and "SSH user" in result.error
    assert fake.calls == []


@pytest.mark.parametrize("port", [0, 65536, "22", True])
def test_invalid_port_rejected(pem_file, port):
    with pytest.raises(ValueError):
        ssh_service.build_ssh_command("10.0.0.1", str(pem_file), port=port)


def test_check_connection_as_custom_user(pem_file):
    fake = FakeSSH(stdout="EC2P_HOSTNAME=al\nEC2P_OS=Amazon Linux 2023\nEC2P_ARCH=x86_64\n")
    result = ssh_service.check_connection(
        "a", "10.0.0.1", str(pem_file), runner=fake, user="ec2-user"
    )
    assert result.success and result.os_release == "Amazon Linux 2023"
    assert fake.calls[0][0][-2] == "ec2-user@10.0.0.1"


# --- web form ---------------------------------------------------------------------------


def test_add_form_defaults_to_ubuntu(client):
    page = client.get("/servers/new").text
    assert 'name="ssh_user" value="ubuntu"' in page


def test_create_edit_and_test_with_ssh_user(client, db_path, pem_file, fake_ssh):
    form = {"name": "al-01", "ip_address": "10.0.0.5", "pem_path": str(pem_file)}
    r = client.post("/servers/new", data={**form, "ssh_user": "ec2-user"}, follow_redirects=False)
    assert r.status_code == 303
    db = Database(db_path)
    server = db.get_server_by_name("al-01")
    assert server.ssh_user == "ec2-user"
    assert "ec2-user" in client.get("/servers").text
    assert 'value="ec2-user"' in client.get(f"/servers/{server.id}/edit").text

    client.post(f"/servers/{server.id}/test")
    assert fake_ssh.calls[-1][0][-2] == "ec2-user@10.0.0.5"
    client.post("/servers/new", data={**form, "name": "x", "ssh_user": "admin", "action": "test"})
    assert fake_ssh.calls[-1][0][-2] == "admin@10.0.0.5"

    # An edit without the field keeps the user; an explicit value changes it.
    client.post(f"/servers/{server.id}/edit", data=form, follow_redirects=False)
    assert db.get_server(server.id).ssh_user == "ec2-user"
    client.post(f"/servers/{server.id}/edit", data={**form, "ssh_user": "admin"})
    assert db.get_server(server.id).ssh_user == "admin"


def test_create_without_field_uses_ubuntu(client, db_path, pem_file):
    client.post(
        "/servers/new", data={"name": "u-01", "ip_address": "10.0.0.6", "pem_path": str(pem_file)}
    )
    assert Database(db_path).get_server_by_name("u-01").ssh_user == "ubuntu"


def test_invalid_ssh_user_is_rejected(client, db_path, pem_file):
    form = {"name": "bad", "ip_address": "10.0.0.7", "pem_path": str(pem_file)}
    r = client.post("/servers/new", data={**form, "ssh_user": "-oProxyCommand=x"})
    assert r.status_code == 422 and "SSH user may only contain" in r.text
    r = client.post("/servers/new", data={**form, "ssh_user": " "})
    assert r.status_code == 422 and "SSH user is required." in r.text
    assert Database(db_path).get_server_by_name("bad") is None
