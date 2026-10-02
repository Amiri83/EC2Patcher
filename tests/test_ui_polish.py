"""NVD API key badge, password login (schema v13, sshpass, session-only password), the log
directory setting with rotating file logs, and the local-only stylesheet."""

import logging
import re
import sqlite3
import subprocess
from logging.handlers import RotatingFileHandler

import pytest
from conftest import SUCCESS_STDOUT, FakeSSH
from fastapi.testclient import TestClient
from nvd_fixtures import FakeNvd, make_client
from phase2_fixtures import make_metadata
from phase3_fixtures import IP, SERVER, FakeClock, FakeFetcher, FakeUbuntu, analysis_plan_output
from test_patch_web import set_staging
from test_ssh_user import _legacy_db, columns
from test_web import upload

from ec2patcher import config, logging_setup
from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import AUTH_PASSWORD, AUTH_PEM
from ec2patcher.services import nvd, ssh_service
from ec2patcher.validation import validate_server_input

SECRET = "S3cr3t-Pa55w0rd!"  # fake test password
API_KEY = "fake-nvd-key-0123456789abcdef"  # fake test key
CVE = "CVE-2026-63076"


def sync(fn):
    fn()


# --- 1. NVD API key badge ---------------------------------------------------------------------


def test_key_status_not_set_and_set(tmp_path):
    assert make_client(tmp_path, FakeNvd()).key_status == nvd.KEY_NOT_SET
    assert make_client(tmp_path, FakeNvd(), api_key=API_KEY).key_status == nvd.KEY_SET


def test_key_status_in_use_after_successful_keyed_request(tmp_path):
    fake = FakeNvd(replies=[(200, {}, b'{"vulnerabilities": []}')])
    client = make_client(tmp_path, fake, api_key=API_KEY)
    client.lookup(CVE)
    assert fake.calls[0][1]["apiKey"] == API_KEY
    assert client.key_status == nvd.KEY_IN_USE


def test_key_status_rejected_on_403(tmp_path):
    client = make_client(tmp_path, FakeNvd(replies=[(403, {}, b"")]), api_key=API_KEY)
    assert client.lookup(CVE).status == nvd.FAILED
    assert client.key_status == nvd.KEY_REJECTED


def test_unkeyed_requests_never_report_in_use(tmp_path):
    client = make_client(tmp_path, FakeNvd(replies=[(200, {}, b'{"vulnerabilities": []}')]))
    client.lookup(CVE)
    assert client.key_status == nvd.KEY_NOT_SET


def badge_app(db_path, nvd_client):
    app = create_app(db_path=db_path, nvd_client=nvd_client, shutdown_handler=lambda: None)
    return TestClient(app, base_url="http://127.0.0.1")


@pytest.mark.parametrize(
    "state, text, css",
    [
        (nvd.KEY_NOT_SET, "NVD API key: not set", "badge-neutral"),
        (nvd.KEY_SET, "NVD API key: set (not used yet)", "badge-neutral"),
        (nvd.KEY_IN_USE, "NVD API key: in use", "badge-success"),
        (nvd.KEY_REJECTED, "NVD API key rejected", "badge-danger"),
    ],
)
def test_badge_on_pre_patch_analysis_pages(tmp_path, db_path, pem_file, state, text, css):
    client = make_client(tmp_path, FakeNvd(), api_key=API_KEY)
    client._key_state = state
    with badge_app(db_path, client) as c:
        page = c.get("/reports").text
        assert text in page and f'class="badge {css} nvd-key-badge"' in page
        c.post("/servers/new", data={"name": "a", "ip_address": "10.0.0.9", "pem_path": pem_file})
        upload(c, {"a": [CVE]})
        db = Database(db_path)
        run_id = db.create_analysis_run(db.get_latest_report(), [("a", None, None)])
        db.update_analysis_run(run_id, status="completed", completed_at="2026-10-01T00:00:00")
        assert text in c.get(f"/analysis/{run_id}").text
        assert API_KEY not in page and API_KEY[:8] not in page and API_KEY[-6:] not in page


def test_badge_never_reveals_the_key_from_the_environment(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, API_KEY)
    app = create_app(db_path=db_path, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        for url in ("/reports", "/settings", "/"):
            page = c.get(url).text
            assert API_KEY not in page and API_KEY[:8] not in page and API_KEY[-6:] not in page
        assert "NVD API key: set (not used yet)" in c.get("/reports").text


# --- 2. password login: schema v13 ------------------------------------------------------------


def test_fresh_database_is_v13_with_auth_method(db_path):
    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 13
    conn.close()
    assert columns(db_path, "servers")["auth_method"] == ("TEXT", 1, "'pem'")
    assert db.create_server("a", "10.0.0.1", "/k.pem").auth_method == AUTH_PEM
    server = db.create_server("b", "10.0.0.2", "", auth_method=AUTH_PASSWORD)
    assert server.auth_method == AUTH_PASSWORD and server.uses_password
    assert db.update_server(server.id, "b", "10.0.0.2", "")  # not given: kept
    assert db.get_server(server.id).auth_method == AUTH_PASSWORD
    assert db.update_server(server.id, "b", "10.0.0.2", "/k.pem", auth_method=AUTH_PEM)
    assert db.get_server(server.id).auth_method == AUTH_PEM


def test_v12_database_upgrades_to_v13_keeping_data(db_path):
    conn = _legacy_db(db_path, 12)
    conn.execute("UPDATE servers SET ssh_user = 'ec2-user'")
    conn.execute("INSERT INTO nvd_cache (cve, metrics, fetched_at) VALUES ('CVE-1', NULL, 't')")
    conn.execute(
        "INSERT INTO amazon_updateinfo_cache (repo, advisories, fetched_at) "
        "VALUES ('2023/x86_64', '[]', 't')"
    )
    conn.commit()
    conn.close()
    assert "auth_method" not in columns(db_path, "servers")

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 13
    check.close()
    server = db.get_server_by_name("keep")
    assert server.auth_method == AUTH_PEM  # existing servers keep logging in with their key
    assert (server.ip_address, server.pem_path, server.ssh_user) == (
        "10.0.0.1", "/k.pem", "ec2-user",
    )  # fmt: skip
    assert db.get_nvd_cache("CVE-1") == (None, None, "t")
    assert db.get_latest_report().filename == "r.json"
    assert Database(db_path).get_server_by_name("keep").auth_method == AUTH_PEM


def test_full_upgrade_path_from_v1_reaches_v13(db_path):
    _legacy_db(db_path, 1).close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 13
    check.close()
    server = db.get_server_by_name("keep")
    assert (server.auth_method, server.ssh_user) == (AUTH_PEM, "ubuntu")
    assert db.get_latest_report().servers == {"keep": []}


def test_v13_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "auth_method" in _MIGRATIONS[13]
    assert all("auth_method" not in _MIGRATIONS[v] for v in range(1, 13))


# --- 2. password login: validation and ssh/scp command lines ----------------------------------


def test_password_login_needs_no_pem(db):
    data = validate_server_input(db, "p", "10.0.0.3", "", auth_method=AUTH_PASSWORD)
    assert data.is_valid and data.pem_path == ""
    data = validate_server_input(db, "p", "10.0.0.3", "/does/not/exist", auth_method="password")
    assert data.is_valid and data.pem_path == ""  # path dropped, never checked
    assert "pem_path" in validate_server_input(db, "k", "10.0.0.3", "").errors
    assert "auth_method" in validate_server_input(db, "x", "10.0.0.3", "", auth_method="x").errors


def test_password_is_never_on_the_ssh_or_scp_command_line():
    cmd = ssh_service.build_ssh_command("10.0.0.1", "", "true", user="admin", password=SECRET)
    assert cmd[:3] == ["sshpass", "-e", "ssh"]
    assert "-i" not in cmd and "BatchMode=yes" not in cmd
    assert "PubkeyAuthentication=no" in cmd and cmd[-2:] == ["admin@10.0.0.1", "true"]
    scp = ssh_service.build_scp_command(
        "10.0.0.1", "", ["/x/a.deb"], "/tmp/s", user="admin", port=2202, password=SECRET
    )
    assert scp[:4] == ["sshpass", "-e", "scp", "-q"] and scp[-1] == "admin@10.0.0.1:/tmp/s/"
    assert scp[scp.index("--") - 2 : scp.index("--")] == ["-P", "2202"]
    assert all(SECRET not in arg for arg in [*cmd, *scp])


def test_password_is_passed_via_sshpass_environment_only():
    fake = FakeSSH(stdout=SUCCESS_STDOUT)
    result = ssh_service.check_connection("p", "10.0.0.1", "", runner=fake, password=SECRET)
    assert result.success
    assert ssh_service.run_remote("10.0.0.1", "", "true", fake, password=SECRET).ok
    assert ssh_service.run_scp("10.0.0.1", "", ["/x/a"], "/tmp/s", fake, password=SECRET).ok
    for args, kwargs in fake.calls:
        assert args[:2] == ["sshpass", "-e"] and all(SECRET not in a for a in args)
        assert kwargs["env"][ssh_service.SSHPASS_ENV] == SECRET
        assert "shell" not in kwargs


def test_key_login_has_no_sshpass_or_env(pem_file):
    fake = FakeSSH(stdout=SUCCESS_STDOUT)
    assert ssh_service.run_remote("10.0.0.1", str(pem_file), "true", fake).ok
    args, kwargs = fake.calls[0]
    assert args[0] == "ssh" and "env" not in kwargs


@pytest.mark.parametrize("call", ["test", "remote", "scp"])
def test_missing_sshpass_gives_a_clear_error(call):
    fake = FakeSSH(exc=FileNotFoundError(2, "No such file or directory", "sshpass"))
    if call == "test":
        error = ssh_service.check_connection("p", "10.0.0.1", "", runner=fake, password=SECRET)
    elif call == "remote":
        error = ssh_service.run_remote("10.0.0.1", "", "true", fake, password=SECRET)
    else:
        error = ssh_service.run_scp("10.0.0.1", "", ["/x/a"], "/tmp/s", fake, password=SECRET)
    assert "'sshpass' command was not found" in error.error
    assert "apt install sshpass" in error.error


def test_wrong_password_is_reported():
    fake = FakeSSH(returncode=ssh_service.SSHPASS_WRONG_PASSWORD)
    result = ssh_service.run_remote("10.0.0.1", "", "true", fake, password=SECRET)
    assert not result.ok and "password was rejected" in result.error
    result = ssh_service.check_connection("p", "10.0.0.1", "", runner=fake, password=SECRET)
    assert not result.success and "password was rejected" in result.error
    denied = FakeSSH(returncode=255, stderr="user@10.0.0.1: Permission denied (password).")
    result = ssh_service.run_remote("10.0.0.1", "", "true", denied, password=SECRET)
    assert "Check the SSH user and password" in result.error


def test_session_passwords_are_memory_only_and_repr_is_safe():
    store = ssh_service.SessionPasswords()
    store.set(3, SECRET)
    assert store.get(3) == SECRET and store.has(3) and not store.has(4)
    assert SECRET not in repr(store) and SECRET not in str(store)
    store.forget(3)
    assert store.get(3) is None
    store.set(1, SECRET)
    store.clear()
    assert not store.has(1)


# --- 2. password login: web flow --------------------------------------------------------------


def password_form(**extra):
    form = {"name": "pw-01", "ip_address": "10.0.0.8", "pem_path": "", "ssh_user": "admin"}
    return {**form, "auth_method": AUTH_PASSWORD, **extra}


def assert_secret_absent(db_path, caplog, *pages):
    for page in pages:
        assert SECRET not in page
    for path in db_path.parent.iterdir():
        if path.is_file():
            assert SECRET.encode() not in path.read_bytes(), path
    assert SECRET not in caplog.text


def test_password_server_web_flow(client, db_path, fake_ssh, caplog):
    caplog.set_level(logging.DEBUG)
    page = client.get("/servers/new").text
    assert 'value="pem" data-auth-method checked' in page  # PEM key is the default
    assert 'type="password" id="ssh_password" name="ssh_password" value=""' in page

    r = client.post("/servers/new", data=password_form(ssh_password=SECRET))
    assert r.status_code == 200 and "was added" in r.text
    server = Database(db_path).get_server_by_name("pw-01")
    assert server.auth_method == AUTH_PASSWORD and server.pem_path == ""
    listing = client.get("/servers").text
    assert "entered this session" in listing and "Forget password" in listing

    # Test SSH uses the session password through sshpass; it never shows up anywhere.
    tested = client.post(f"/servers/{server.id}/test").text
    args, kwargs = fake_ssh.calls[-1]
    assert args[:3] == ["sshpass", "-e", "ssh"] and all(SECRET not in a for a in args)
    assert kwargs["env"]["SSHPASS"] == SECRET
    edit = client.get(f"/servers/{server.id}/edit").text
    assert "Entered for this session" in edit and 'name="ssh_password" value=""' in edit

    # Editing without typing the password keeps the session password.
    r = client.post(f"/servers/{server.id}/edit", data=password_form())
    assert r.status_code == 200 and client.app.state.passwords.get(server.id) == SECRET

    r = client.post(f"/servers/{server.id}/password/forget")
    assert "was forgotten" in r.text and "password needed" in r.text
    missing = client.post(f"/servers/{server.id}/test").text
    assert "No SSH password entered" in missing
    r = client.post(f"/servers/{server.id}/password", data={"ssh_password": SECRET})
    assert "kept in memory for this app session only" in r.text
    assert client.app.state.passwords.get(server.id) == SECRET
    assert_secret_absent(db_path, caplog, page, listing, tested, edit, missing, r.text)

    # Switching to a PEM key forgets the password.
    client.post(f"/servers/{server.id}/edit", data=password_form(auth_method=AUTH_PEM))
    assert client.app.state.passwords.get(server.id) == SECRET  # invalid (no PEM): not saved
    assert Database(db_path).get_server(server.id).auth_method == AUTH_PASSWORD


def test_switching_to_pem_and_deleting_forget_the_password(client, db_path, pem_file):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server = Database(db_path).get_server_by_name("pw-01")
    data = password_form(auth_method=AUTH_PEM, pem_path=str(pem_file))
    client.post(f"/servers/{server.id}/edit", data=data)
    assert Database(db_path).get_server(server.id).auth_method == AUTH_PEM
    assert not client.app.state.passwords.has(server.id)

    client.post(f"/servers/{server.id}/edit", data=password_form(ssh_password=SECRET))
    assert client.app.state.passwords.has(server.id)
    client.post(f"/servers/{server.id}/delete")
    assert not client.app.state.passwords.has(server.id)


def test_form_test_connection_with_typed_password(client, fake_ssh, db_path, caplog):
    caplog.set_level(logging.DEBUG)
    r = client.post("/servers/new", data=password_form(action="test"))
    assert "Enter the SSH password to test the connection." in r.text and fake_ssh.calls == []
    r = client.post("/servers/new", data=password_form(action="test", ssh_password=SECRET))
    assert "SSH CONNECTION SUCCESSFUL" in r.text and "ip-10-10-20-15" in r.text
    assert fake_ssh.calls[-1][1]["env"]["SSHPASS"] == SECRET
    assert Database(db_path).get_server_by_name("pw-01") is None  # test does not save
    assert_secret_absent(db_path, caplog, r.text)


def test_password_is_cleared_on_restart(make_client, db_path):
    with make_client() as c:
        c.post("/servers/new", data=password_form(ssh_password=SECRET))
        server_id = Database(db_path).get_server_by_name("pw-01").id
        assert c.app.state.passwords.has(server_id)
    with make_client() as c:  # a new app process: nothing remembered
        assert not c.app.state.passwords.has(server_id)
        assert "password needed" in c.get("/servers").text


def test_clear_servers_and_reset_forget_all_passwords(client, db_path):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    client.post("/servers/clear", data={"confirm_text": "DELETE SERVERS"})
    assert repr(client.app.state.passwords) == "SessionPasswords(server_ids=[])"
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    client.post("/settings/reset-database", data={"confirm_text": "RESET"})
    assert repr(client.app.state.passwords) == "SessionPasswords(server_ids=[])"


class PasswordGate:
    """Runner that requires sshpass + $SSHPASS, then hands the plain ssh/scp call to ``inner``."""

    def __init__(self, inner, password):
        self.inner, self.password = inner, password
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        assert args[:2] == ["sshpass", "-e"] and all(self.password not in a for a in args)
        assert kwargs.get("env", {}).get("SSHPASS") == self.password
        inner_kwargs = {k: v for k, v in kwargs.items() if k != "env"}
        return self.inner(args[2:], **inner_kwargs)


def test_analysis_and_patching_with_password_login(db_path, tmp_path, fake_apt, caplog):
    caplog.set_level(logging.DEBUG)
    fake_apt.plan = analysis_plan_output()
    ubuntu = FakeUbuntu(plan_output=analysis_plan_output())
    gate = PasswordGate(ubuntu, SECRET)
    app = create_app(
        db_path=db_path, ssh_runner=gate, metadata=make_metadata(tmp_path),
        analysis_starter=sync, patch_starter=sync, patch_fetcher=FakeFetcher(),
        shutdown_handler=lambda: None,
    )  # fmt: skip
    clock = FakeClock()
    app.state.patcher.sleep, app.state.patcher.clock = clock.sleep, clock
    pages = []
    with TestClient(app, base_url="http://127.0.0.1") as c:
        data = {
            "name": SERVER,
            "ip_address": IP,
            "auth_method": AUTH_PASSWORD,
            "ssh_user": "ubuntu",
        }
        c.post("/servers/new", data=data)  # no password yet
        set_staging(c, tmp_path)
        upload(c, {SERVER: ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"]})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        pages.append(c.get(run_url).text)
        assert "No SSH password entered" in pages[-1] and gate.calls == []

        server_id = Database(db_path).get_server_by_name(SERVER).id
        c.post(f"/servers/{server_id}/password", data={"ssh_password": SECRET})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        pages.append(c.get(run_url).text)
        report_url = re.findall(r'href="(/analysis/\d+/servers/\d+)"', pages[-1])[0]
        pages.append(c.get(report_url).text)
        assert "PENDING REVIEW" in pages[-1]

        # Forgetting the password blocks patching before anything is downloaded.
        c.post(f"/servers/{server_id}/password/forget")
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"})
        assert r.status_code == 409 and "No SSH password entered" in r.text
        pages.append(r.text)

        c.post(f"/servers/{server_id}/password", data={"ssh_password": SECRET})
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"}, follow_redirects=False)
        result = c.get(r.headers["location"]).text
        pages.append(result)
        assert "PATCH SUCCESSFUL" in result
    binaries = {args[2] for args, _ in gate.calls}
    assert binaries == {"ssh", "scp"}  # every connection went through sshpass
    assert ubuntu.ops.count("install") == 1
    assert_secret_absent(db_path, caplog, *pages)


# --- 3. log directory setting -----------------------------------------------------------------


@pytest.fixture
def restore_root_handlers():
    root = logging.getLogger()
    before = list(root.handlers)
    yield
    logging_setup.stop_file_logging()
    for handler in list(root.handlers):
        if handler not in before:
            root.removeHandler(handler)


def test_default_log_dir_from_env_or_platformdirs(monkeypatch, tmp_path):
    assert config.get_default_log_dir() == tmp_path / "logs"  # conftest isolation
    monkeypatch.delenv(config.LOG_DIR_ENV)
    monkeypatch.setattr(config, "user_log_dir", lambda app, appauthor: f"/x/{app}/log")
    assert str(config.get_default_log_dir()) == "/x/ec2patcher/log"


def test_check_log_dir(tmp_path):
    path, error = logging_setup.check_log_dir(str(tmp_path / "new" / "logs"))
    assert error is None and path.is_dir()
    assert logging_setup.check_log_dir("")[1] == "Log directory is required."
    assert "absolute path" in logging_setup.check_log_dir("relative/logs")[1]
    a_file = tmp_path / "file"
    a_file.write_text("x")
    assert "cannot be created" in logging_setup.check_log_dir(str(a_file / "sub"))[1]
    assert "not a directory" in logging_setup.check_log_dir(str(a_file))[1]


def test_unwritable_log_dir_rejected(tmp_path):
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        if logging_setup.check_log_dir(str(locked))[1] is None:
            pytest.skip("running with privileges that ignore directory permissions")
        assert "not writable" in logging_setup.check_log_dir(str(locked))[1]
    finally:
        locked.chmod(0o700)


def test_rotating_file_handler_5_by_5mb(tmp_path, restore_root_handlers):
    path = logging_setup.configure_file_logging(tmp_path / "a")
    handlers = [h for h in logging.getLogger().handlers if isinstance(h, RotatingFileHandler)]
    assert len(handlers) == 1 and path == tmp_path / "a" / "ec2patcher.log"
    assert (handlers[0].maxBytes, handlers[0].backupCount) == (5 * 1024 * 1024, 5)
    assert logging_setup.active_log_file() == path
    logging_setup.configure_file_logging(tmp_path / "b")  # replaces, never duplicates
    handlers = [h for h in logging.getLogger().handlers if isinstance(h, RotatingFileHandler)]
    assert (
        len(handlers) == 1 and logging_setup.active_log_file() == tmp_path / "b" / "ec2patcher.log"
    )


def test_rotation_keeps_five_backups(tmp_path, restore_root_handlers, monkeypatch):
    monkeypatch.setattr(logging_setup, "LOG_MAX_BYTES", 200)
    logging_setup.configure_file_logging(tmp_path)
    log = logging.getLogger("ec2patcher.test_rotation")
    log.setLevel(logging.INFO)
    for i in range(100):
        log.info("line %03d %s", i, "x" * 40)
    names = sorted(p.name for p in tmp_path.iterdir())
    assert names == ["ec2patcher.log", *(f"ec2patcher.log.{n}" for n in range(1, 6))]


def test_settings_page_shows_log_file_and_validates(client, tmp_path):
    page = client.get("/settings").text
    assert "Log directory" in page and str(tmp_path / "logs" / "ec2patcher.log") in page
    assert "5 &times; 5 MB" in page and "file logging is not active" in page

    r = client.post("/settings/log-dir", data={"log_dir_path": "relative/dir"})
    assert r.status_code == 422 and "must be an absolute path" in r.text
    assert 'value="relative/dir"' in r.text
    a_file = tmp_path / "file"
    a_file.write_text("x")
    r = client.post("/settings/log-dir", data={"log_dir_path": str(a_file)})
    assert r.status_code == 422 and "not a directory" in r.text

    target = tmp_path / "chosen-logs"
    r = client.post("/settings/log-dir", data={"log_dir_path": str(target)})
    assert r.status_code == 200 and "Log directory saved." in r.text
    assert str(target / "ec2patcher.log") in r.text and target.is_dir()
    assert client.app.state.db.get_setting(logging_setup.LOG_DIR_SETTING) == str(target)
    r = client.post("/settings/log-dir", data={"action": "reset"})
    assert "Log directory reset to default." in r.text
    assert client.app.state.db.get_setting(logging_setup.LOG_DIR_SETTING) is None


def test_file_logging_follows_the_setting(db_path, tmp_path, restore_root_handlers):
    app = create_app(db_path=db_path, shutdown_handler=lambda: None, file_logging=True)
    assert logging_setup.active_log_file() == tmp_path / "logs" / "ec2patcher.log"
    with TestClient(app, base_url="http://127.0.0.1") as c:
        target = tmp_path / "moved"
        page = c.post("/settings/log-dir", data={"log_dir_path": str(target)}).text
        assert logging_setup.active_log_file() == target / "ec2patcher.log"
        assert "file logging is not active" not in page
        logging.getLogger("ec2patcher").warning("after move")
        assert "after move" in (target / "ec2patcher.log").read_text()
    # A restart uses the saved directory.
    create_app(db_path=db_path, shutdown_handler=lambda: None, file_logging=True)
    assert logging_setup.active_log_file() == target / "ec2patcher.log"


def test_unusable_saved_log_dir_falls_back_to_default(db_path, tmp_path, restore_root_handlers):
    a_file = tmp_path / "file"
    a_file.write_text("x")
    Database(db_path).set_setting(logging_setup.LOG_DIR_SETTING, str(a_file))
    create_app(db_path=db_path, shutdown_handler=lambda: None, file_logging=True)
    assert logging_setup.active_log_file() == tmp_path / "logs" / "ec2patcher.log"


def test_main_no_longer_writes_into_the_data_dir(monkeypatch, tmp_path, restore_root_handlers):
    from ec2patcher import main as main_module

    monkeypatch.setattr(main_module.uvicorn.Server, "run", lambda self: None)
    main_module.main(["--no-browser", "--data-dir", str(tmp_path / "data")])
    assert logging_setup.active_log_file() == tmp_path / "logs" / "ec2patcher.log"
    assert not (tmp_path / "data" / "ec2patcher.log").exists()


# --- 4. stylesheet ----------------------------------------------------------------------------


def test_stylesheet_is_local_with_dark_mode(client):
    css = client.get("/static/style.css").text
    assert "prefers-color-scheme: dark" in css
    assert "@import" not in css and "http://" not in css and "https://" not in css
    for url in ("/", "/servers", "/reports", "/settings", "/history", "/shutdown"):
        page = client.get(url).text
        hosts = re.findall(r'(?:href|src)="(?:https?:)?//([^/"]+)', page)
        assert set(hosts) <= {"127.0.0.1"}, (url, hosts)  # only this app's own /static
        assert "<style" not in page or "@import" not in page


def test_shutdown_page_has_inline_dark_mode(client):
    page = client.post("/shutdown", data={"confirm": "yes"}).text
    assert "has been shut down" in page and "prefers-color-scheme: dark" in page
    assert "<link" not in page and "http" not in page.split("<body>")[0]


def test_no_subprocess_shell(monkeypatch):
    """The sshpass path still uses an argument list (never shell=True)."""
    seen = []

    def runner(args, **kwargs):
        seen.append(kwargs)
        return subprocess.CompletedProcess(args, 0, SUCCESS_STDOUT, "")

    ssh_service.run_remote("10.0.0.1", "", "true", runner, password=SECRET)
    assert seen and "shell" not in seen[0]
