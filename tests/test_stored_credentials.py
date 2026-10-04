"""Stored credentials: the NVD API key in Settings (masked, overrides NVD_API_KEY), per-server
SSH passwords stored encrypted (schema v14, replacing the session-only passwords), the Fernet
key file, and secret hygiene (HTML, logs, argv, environment, exports, error messages)."""

import io
import logging
import os
import re
import sqlite3
import stat
import zipfile

import pytest
from conftest import SUCCESS_STDOUT, FakeSSH
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
from nvd_fixtures import FakeNvd
from phase2_fixtures import make_metadata
from phase3_fixtures import IP, SERVER, FakeClock, FakeFetcher, FakeUbuntu, analysis_plan_output
from test_patch_web import set_staging
from test_ssh_user import _legacy_db, columns
from test_web import upload

from ec2patcher import config
from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import AUTH_PASSWORD, AUTH_PEM
from ec2patcher.services import nvd, secret_store, ssh_service
from ec2patcher.services.secret_store import NVD_KEY_SETTING, SecretBox, SecretError, SecretStore
from ec2patcher.validation import check_nvd_api_key, check_ssh_password

SECRET = "S3cr3t-Pa55w0rd!"  # fake test password
NEW_SECRET = "An0ther-Fake-Pa55!"  # fake test password
API_KEY = "fake-nvd-key-0123456789abcdef"  # fake test key
ENV_KEY = "fake-env-key-fedcba9876543210"  # fake test key
MASKED = "•" * 8 + "cdef"


def sync(fn):
    fn()


def key_file(tmp_path):
    return tmp_path / "config" / config.SECRET_KEY_FILENAME  # conftest: EC2PATCHER_CONFIG_DIR


def password_form(**extra):
    form = {"name": "pw-01", "ip_address": "10.0.0.8", "pem_path": "", "ssh_user": "admin"}
    return {**form, "auth_method": AUTH_PASSWORD, **extra}


def stored_token(db_path, server_id):
    return Database(db_path).get_server_password(server_id)


def assert_secrets_absent(db_path, caplog, *texts, secrets=(SECRET, NEW_SECRET, API_KEY)):
    """No secret in any page/text, the raw database files or the captured log."""
    for text in texts:
        for secret in secrets:
            assert secret not in text
    for path in db_path.parent.iterdir():
        if path.is_file():
            raw = path.read_bytes()
            for secret in secrets:
                assert secret.encode() not in raw, path
    for secret in secrets:
        assert secret not in caplog.text


# --- 3. Fernet key file -----------------------------------------------------------------------


def test_key_file_created_on_first_use_with_mode_600(tmp_path):
    box = SecretBox(tmp_path / "cfg" / "secret.key")
    assert not box.key_path.exists()
    token = box.encrypt(SECRET)
    assert box.key_path.is_file() and stat.S_IMODE(box.key_path.stat().st_mode) == 0o600
    assert SECRET not in token and box.decrypt(token) == SECRET
    key = box.key_path.read_bytes()
    assert box.decrypt(box.encrypt(NEW_SECRET)) == NEW_SECRET
    assert box.key_path.read_bytes() == key  # created once, then reused


def test_key_file_lives_in_the_config_dir_not_the_database(tmp_path, monkeypatch):
    assert SecretBox().key_path == key_file(tmp_path)
    assert config.get_config_dir() != config.get_data_dir()
    monkeypatch.delenv(config.CONFIG_DIR_ENV)
    monkeypatch.setattr(config, "user_config_dir", lambda app, appauthor: f"/x/{app}")
    assert str(config.get_secret_key_path()) == "/x/ec2patcher/secret.key"


def test_missing_key_file_is_a_clear_error_and_never_recreated_on_read(tmp_path):
    box = SecretBox(tmp_path / "secret.key")
    token = box.encrypt(SECRET)
    box.key_path.unlink()
    with pytest.raises(SecretError) as exc:
        box.decrypt(token)
    message = str(exc.value)
    assert "is missing" in message and "Enter the secret again" in message
    assert str(box.key_path) in message and SECRET not in message and token not in message
    assert not box.key_path.exists()


def test_wrong_key_file_is_a_clear_error(tmp_path):
    box = SecretBox(tmp_path / "secret.key")
    token = box.encrypt(SECRET)
    box.key_path.write_bytes(Fernet.generate_key())
    with pytest.raises(SecretError, match="does not match the key used to encrypt it"):
        box.decrypt(token)


def test_corrupt_key_file_is_a_clear_error_and_never_overwritten(tmp_path):
    box = SecretBox(tmp_path / "secret.key")
    box.key_path.write_text("not a fernet key")
    with pytest.raises(SecretError, match="is not a valid key"):
        box.decrypt("gAAAA-whatever")
    with pytest.raises(SecretError, match="is not a valid key"):
        box.encrypt(SECRET)
    assert box.key_path.read_text() == "not a fernet key"


def test_loose_key_file_permissions_are_restricted(tmp_path):
    box = SecretBox(tmp_path / "secret.key")
    token = box.encrypt(SECRET)
    box.key_path.chmod(0o644)
    assert box.decrypt(token) == SECRET
    assert stat.S_IMODE(box.key_path.stat().st_mode) == 0o600


# --- 3. schema v14 ----------------------------------------------------------------------------


def test_fresh_database_is_v14_with_encrypted_password_column(db_path):
    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    conn.close()
    assert columns(db_path, "servers")["password_encrypted"] == ("TEXT", 0, None)
    server = db.create_server("p", "10.0.0.2", "", auth_method=AUTH_PASSWORD)
    assert not server.has_password and db.get_server_password(server.id) is None
    assert db.set_server_password(server.id, "token")
    assert db.get_server(server.id).has_password and db.get_server_password(server.id) == "token"
    assert db.update_server(server.id, "p", "10.0.0.3", "")  # an edit keeps the password
    assert db.get_server_password(server.id) == "token"
    assert db.set_server_password(server.id, None) and not db.get_server(server.id).has_password
    assert not db.set_server_password(9999, "token")
    created = db.create_server("q", "10.0.0.4", "", auth_method=AUTH_PASSWORD,
                               password_encrypted="t2")  # fmt: skip
    assert created.has_password and db.get_server_password(created.id) == "t2"
    assert "password_encrypted" not in repr(created) and "t2" not in repr(created)


def test_v13_database_upgrades_to_v14_keeping_data(db_path):
    conn = _legacy_db(db_path, 13)
    conn.execute("UPDATE servers SET auth_method = 'password', ssh_user = 'admin'")
    conn.execute("INSERT INTO nvd_cache (cve, metrics, fetched_at) VALUES ('CVE-1', NULL, 't')")
    conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('k', 'v', 't')")
    conn.commit()
    conn.close()
    assert "password_encrypted" not in columns(db_path, "servers")

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    check.close()
    server = db.get_server_by_name("keep")
    assert (server.auth_method, server.ssh_user, server.has_password) == (
        AUTH_PASSWORD, "admin", False,
    )  # fmt: skip
    assert (server.ip_address, server.pem_path) == ("10.0.0.1", "/k.pem")
    assert db.get_nvd_cache("CVE-1") == (None, None, "t")
    assert db.get_setting("k") == "v"
    assert db.get_latest_report().filename == "r.json"
    assert not Database(db_path).get_server_by_name("keep").has_password  # no re-migration


def test_full_upgrade_path_from_v1_reaches_v14(db_path):
    _legacy_db(db_path, 1).close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 14
    check.close()
    server = db.get_server_by_name("keep")
    assert (server.auth_method, server.ssh_user, server.has_password) == (AUTH_PEM, "ubuntu", False)
    assert db.get_latest_report().servers == {"keep": []}


def test_v14_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "password_encrypted" in _MIGRATIONS[14]
    assert all("password_encrypted" not in _MIGRATIONS[v] for v in range(1, 14))
    assert "auth_method" in _MIGRATIONS[13]  # v13 left as it was


# --- 2. server form: login type ---------------------------------------------------------------


def test_login_type_dropdown_with_noscript_fallback(client):
    page = client.get("/servers/new").text
    assert '<select id="auth_method" name="auth_method" data-auth-method>' in page
    assert '<option value="pem" selected>PEM key</option>' in page  # PEM key is the default
    assert '<option value="password">Username + password</option>' in page
    assert 'data-auth-only="pem"' in page and 'data-auth-only="password"' in page
    assert 'type="password" id="ssh_password" name="ssh_password" value=""' in page
    noscript = re.search(r"<noscript>(.*?)</noscript>", page, re.S).group(1)
    assert "[data-auth-only] { display: block !important; }" in noscript
    assert "Both the PEM key and the password fields are shown" in noscript
    js = client.get("/static/app.js").text
    assert "select[data-auth-method]" in js and "el.hidden" in js


def test_edit_form_preselects_password_login(client, db_path):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server = Database(db_path).get_server_by_name("pw-01")
    page = client.get(f"/servers/{server.id}/edit").text
    assert '<option value="password" selected>Username + password</option>' in page


def test_new_password_server_requires_a_password(client, db_path):
    r = client.post("/servers/new", data=password_form())
    assert r.status_code == 422 and "Enter the SSH password of this server" in r.text
    assert Database(db_path).get_server_by_name("pw-01") is None
    r = client.post("/servers/new", data=password_form(ssh_password="x" * 300))
    assert r.status_code == 422 and "at most 256 characters" in r.text
    assert "x" * 300 not in r.text


def test_password_is_stored_encrypted_per_server(client, db_path, caplog):
    caplog.set_level(logging.DEBUG)
    r = client.post("/servers/new", data=password_form(ssh_password=SECRET))
    assert r.status_code == 200 and "was added" in r.text
    r = client.post("/servers/new", data=password_form(name="pw-02", ssh_password=NEW_SECRET))
    assert "was added" in r.text
    db = Database(db_path)
    one, two = db.get_server_by_name("pw-01"), db.get_server_by_name("pw-02")
    assert one.auth_method == AUTH_PASSWORD and one.pem_path == "" and one.has_password
    tokens = {stored_token(db_path, one.id), stored_token(db_path, two.id)}
    assert all(t and SECRET not in t and NEW_SECRET not in t for t in tokens)
    store = client.app.state.credentials
    assert store.server_password(one.id) == SECRET and store.server_password(two.id) == NEW_SECRET

    listing = client.get("/servers").text
    assert listing.count("stored (encrypted)") == 2 and "password needed" not in listing
    edit = client.get(f"/servers/{one.id}/edit").text
    assert "Password stored" in edit and "Leave empty to keep the stored password" in edit
    assert 'name="ssh_password" value=""' in edit
    assert_secrets_absent(db_path, caplog, listing, edit, r.text)
    for token in tokens:
        assert token not in listing and token not in edit and token not in caplog.text


def test_editing_with_an_empty_password_keeps_the_stored_one(client, db_path):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server = Database(db_path).get_server_by_name("pw-01")
    token = stored_token(db_path, server.id)

    r = client.post(f"/servers/{server.id}/edit", data=password_form(ip_address="10.0.0.9"))
    assert r.status_code == 200 and "was updated" in r.text
    assert stored_token(db_path, server.id) == token  # untouched
    assert Database(db_path).get_server(server.id).ip_address == "10.0.0.9"

    r = client.post(f"/servers/{server.id}/edit", data=password_form(ssh_password=NEW_SECRET))
    assert "was updated" in r.text
    assert client.app.state.credentials.server_password(server.id) == NEW_SECRET


def test_switching_to_pem_removes_the_stored_password(client, db_path, pem_file):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server = Database(db_path).get_server_by_name("pw-01")
    # An invalid edit (no PEM file) changes nothing.
    r = client.post(f"/servers/{server.id}/edit", data=password_form(auth_method=AUTH_PEM))
    assert r.status_code == 422 and stored_token(db_path, server.id) is not None

    data = password_form(auth_method=AUTH_PEM, pem_path=str(pem_file))
    client.post(f"/servers/{server.id}/edit", data=data)
    updated = Database(db_path).get_server(server.id)
    assert updated.auth_method == AUTH_PEM and not updated.has_password
    assert stored_token(db_path, server.id) is None

    # Back to password login: a password must be entered again.
    r = client.post(f"/servers/{server.id}/edit", data=password_form())
    assert r.status_code == 422 and "Enter the SSH password of this server" in r.text


def test_stored_password_survives_a_restart(make_client, db_path, fake_ssh):
    with make_client() as c:
        c.post("/servers/new", data=password_form(ssh_password=SECRET))
    server_id = Database(db_path).get_server_by_name("pw-01").id
    with make_client() as c:  # a new app process: the stored password is still there
        assert "stored (encrypted)" in c.get("/servers").text
        c.post(f"/servers/{server_id}/test")
    args, kwargs = fake_ssh.calls[-1]
    assert args[:3] == ["sshpass", "-e", "ssh"] and kwargs["env"]["SSHPASS"] == SECRET


def test_test_connection_uses_the_typed_or_the_stored_password(client, fake_ssh, db_path):
    r = client.post("/servers/new", data=password_form(action="test"))
    assert "Enter the SSH password to test the connection." in r.text and fake_ssh.calls == []
    r = client.post("/servers/new", data=password_form(action="test", ssh_password=SECRET))
    assert "SSH CONNECTION SUCCESSFUL" in r.text
    assert fake_ssh.calls[-1][1]["env"]["SSHPASS"] == SECRET
    assert Database(db_path).get_server_by_name("pw-01") is None  # a test never saves

    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server_id = Database(db_path).get_server_by_name("pw-01").id
    r = client.post(f"/servers/{server_id}/edit", data=password_form(action="test"))
    assert "SSH CONNECTION SUCCESSFUL" in r.text  # empty field: the stored password
    assert fake_ssh.calls[-1][1]["env"]["SSHPASS"] == SECRET
    data = password_form(action="test", ssh_password=NEW_SECRET)
    client.post(f"/servers/{server_id}/edit", data=data)
    assert fake_ssh.calls[-1][1]["env"]["SSHPASS"] == NEW_SECRET
    assert client.app.state.credentials.server_password(server_id) == SECRET  # not saved


def test_session_password_logic_is_gone(client, db_path):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server_id = Database(db_path).get_server_by_name("pw-01").id
    r = client.post(f"/servers/{server_id}/password", data={"ssh_password": NEW_SECRET})
    assert r.status_code == 404
    assert client.post(f"/servers/{server_id}/password/forget").status_code == 404
    assert not hasattr(ssh_service, "SessionPasswords")
    assert not hasattr(client.app.state, "passwords")
    assert "this session" not in client.get("/servers").text


def test_missing_stored_password_blocks_ssh(client, db_path, fake_ssh):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server_id = Database(db_path).get_server_by_name("pw-01").id
    Database(db_path).set_server_password(server_id, None)
    page = client.post(f"/servers/{server_id}/test").text
    assert ssh_service.PASSWORD_MISSING.split(".")[0] in page and fake_ssh.calls == []
    assert "password needed" in client.get("/servers").text


def test_undecryptable_password_is_a_clear_error_and_can_be_reentered(
    client, db_path, fake_ssh, tmp_path, caplog
):
    client.post("/servers/new", data=password_form(ssh_password=SECRET))
    server_id = Database(db_path).get_server_by_name("pw-01").id
    key_file(tmp_path).unlink()

    page = client.post(f"/servers/{server_id}/test").text
    assert "is missing, so the stored secret cannot be decrypted" in page
    assert "Enter the secret again" in page and fake_ssh.calls == []
    edit = client.get(f"/servers/{server_id}/edit").text
    assert 'class="field-error stored-password-error"' in edit and "is missing" in edit
    assert "cannot be decrypted" in caplog.text

    r = client.post(f"/servers/{server_id}/edit", data=password_form(ssh_password=NEW_SECRET))
    assert "was updated" in r.text and key_file(tmp_path).exists()
    client.post(f"/servers/{server_id}/test")
    assert fake_ssh.calls[-1][1]["env"]["SSHPASS"] == NEW_SECRET

    key_file(tmp_path).write_bytes(Fernet.generate_key())  # a different key
    page = client.post(f"/servers/{server_id}/test").text
    assert "does not match the key used to encrypt it" in page
    assert_secrets_absent(db_path, caplog, page, edit)


class PasswordGate:
    """Runner that requires sshpass + $SSHPASS, then hands the plain ssh/scp call to ``inner``."""

    def __init__(self, inner, password):
        self.inner, self.password = inner, password
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        assert args[:2] == ["sshpass", "-e"] and all(self.password not in a for a in args)
        assert kwargs.get("env", {}).get("SSHPASS") == self.password
        assert "shell" not in kwargs
        inner_kwargs = {k: v for k, v in kwargs.items() if k != "env"}
        return self.inner(args[2:], **inner_kwargs)


def test_analysis_patching_and_export_with_a_stored_password(db_path, tmp_path, fake_apt, caplog):
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
    form = {"name": SERVER, "ip_address": IP, "auth_method": AUTH_PASSWORD, "ssh_user": "ubuntu"}
    with TestClient(app, base_url="http://127.0.0.1") as c:
        c.post("/servers/new", data={**form, "ssh_password": SECRET})
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        server_id = Database(db_path).get_server_by_name(SERVER).id
        set_staging(c, tmp_path)
        upload(c, {SERVER: ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"]})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        pages.append(c.get(run_url).text)
        report_url = re.findall(r'href="(/analysis/\d+/servers/\d+)"', pages[-1])[0]
        pages.append(c.get(report_url).text)
        assert "PENDING REVIEW" in pages[-1]

        # Excel export of the analysis: no secret in any part of the workbook.
        export = c.get(f"{report_url}/export.xlsx")
        assert export.status_code == 200
        with zipfile.ZipFile(io.BytesIO(export.content)) as workbook:
            pages.extend(workbook.read(n).decode("utf-8", "replace") for n in workbook.namelist())

        # A removed password blocks patching before anything is downloaded.
        Database(db_path).set_server_password(server_id, None)
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"})
        assert r.status_code == 409 and "No SSH password is stored for this server" in r.text
        pages.append(r.text)

        c.post(f"/servers/{server_id}/edit", data={**form, "ssh_password": SECRET})
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"}, follow_redirects=False)
        result = c.get(r.headers["location"]).text
        pages.append(result)
        assert "PATCH SUCCESSFUL" in result
        pages.extend(c.get(url).text for url in ("/history", "/servers", "/settings", "/"))
    binaries = {args[2] for args, _ in gate.calls}
    assert binaries == {"ssh", "scp"}  # every connection went through sshpass
    assert ubuntu.ops.count("install") == 1
    assert "SSHPASS" not in os.environ  # only ever in the child's environment
    assert_secrets_absent(db_path, caplog, *pages)


def test_undecryptable_password_fails_the_analysis_with_a_clear_error(db_path, tmp_path):
    gate = PasswordGate(FakeUbuntu(plan_output=analysis_plan_output()), SECRET)
    app = create_app(
        db_path=db_path, ssh_runner=gate, metadata=make_metadata(tmp_path),
        analysis_starter=sync, shutdown_handler=lambda: None,
    )  # fmt: skip
    with TestClient(app, base_url="http://127.0.0.1") as c:
        data = {"name": SERVER, "ip_address": IP, "auth_method": AUTH_PASSWORD}
        c.post("/servers/new", data={**data, "ssh_user": "ubuntu", "ssh_password": SECRET})
        key_file(tmp_path).unlink()
        upload(c, {SERVER: ["CVE-2026-63076"]})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        page = c.get(run_url).text
    assert "cannot be decrypted" in page and "Enter the secret again" in page
    assert gate.calls == [] and SECRET not in page


# --- 1. NVD API key in Settings ---------------------------------------------------------------


def test_nvd_key_saved_encrypted_and_shown_masked(client, db_path, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    page = client.get("/settings").text
    assert 'id="nvd_api_key" name="nvd_api_key" value=""' in page and ">Save</button>" in page
    assert 'value="clear"' not in page  # nothing to clear yet

    r = client.post("/settings/nvd-key", data={"nvd_api_key": f"  {API_KEY}  "})
    assert r.status_code == 200 and "NVD API key saved (encrypted)" in r.text
    assert f'<code class="nvd-key-masked">{MASKED}</code>' in r.text
    assert ">Replace</button>" in r.text and ">Clear</button>" in r.text
    assert 'value="clear"' in r.text
    assert API_KEY not in r.text and API_KEY[-5:] not in r.text and API_KEY[:8] not in r.text
    assert 'name="nvd_api_key" value=""' in r.text
    token = Database(db_path).get_setting(NVD_KEY_SETTING)
    assert token and API_KEY not in token
    assert client.app.state.credentials.nvd_key() == API_KEY
    assert stat.S_IMODE(key_file(tmp_path).stat().st_mode) == 0o600
    assert_secrets_absent(db_path, caplog, page, r.text)
    assert token not in r.text and token not in caplog.text

    r = client.post("/settings/nvd-key", data={"action": "clear"})
    assert "NVD API key removed from Settings." in r.text and MASKED not in r.text
    assert Database(db_path).get_setting(NVD_KEY_SETTING) is None


def test_invalid_nvd_key_is_rejected_and_never_echoed(client, db_path):
    for bad in ("", "short-key", "fake key with spaces 0123456789", "x" * 200, "k\r\nX: 1" * 4):
        r = client.post("/settings/nvd-key", data={"nvd_api_key": bad})
        assert r.status_code == 422 and 'class="field-error"' in r.text
        assert bad.strip() == "" or bad not in r.text
    assert Database(db_path).get_setting(NVD_KEY_SETTING) is None
    assert check_nvd_api_key(API_KEY) is None and check_nvd_api_key("a" * 16) is None


def test_settings_key_overrides_the_environment_and_badge_shows_source(db_path, monkeypatch):
    monkeypatch.setenv(nvd.API_KEY_ENV, ENV_KEY)
    fake = FakeNvd()
    client = nvd.NvdClient(db_path, transport=fake, sleep=lambda s: None)
    app = create_app(db_path=db_path, nvd_client=client, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        page = c.get("/reports").text
        assert "NVD API key: set (not used yet) — from NVD_API_KEY env var" in page
        assert 'data-nvd-key-source="env"' in page
        assert "NVD_API_KEY env var</dt><dd>set" in c.get("/settings").text

        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
        assert client.key_source == nvd.KEY_SOURCE_SETTINGS
        client.lookup("CVE-2026-63076")
        assert fake.calls[-1][1]["apiKey"] == API_KEY  # the Settings key wins
        assert API_KEY not in fake.calls[-1][0] and ENV_KEY not in fake.calls[-1][0]
        reports = c.get("/reports").text
        assert "NVD API key: in use — from Settings" in reports
        settings = c.get("/settings").text
        assert "(overridden by the saved key)" in settings

        c.post("/settings/nvd-key", data={"action": "clear"})  # back to the environment
        assert client.key_source == nvd.KEY_SOURCE_ENV
        client.start_run()
        client.lookup("CVE-2026-54874")
        assert fake.calls[-1][1]["apiKey"] == ENV_KEY
        after = c.get("/reports").text
        assert "NVD API key: in use — from NVD_API_KEY env var" in after
    for text in (page, reports, settings, after):
        assert API_KEY not in text and ENV_KEY not in text and ENV_KEY[-4:] not in text


def test_saved_nvd_key_is_used_after_a_restart_and_reset_clears_it(db_path, monkeypatch):
    app = create_app(db_path=db_path, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
    app = create_app(db_path=db_path, shutdown_handler=lambda: None)
    nvd_client = app.state.analyzer.nvd
    assert nvd_client.key_source == nvd.KEY_SOURCE_SETTINGS
    assert nvd_client.key_status == nvd.KEY_SET and nvd_client.interval == nvd.INTERVAL_WITH_KEY
    with TestClient(app, base_url="http://127.0.0.1") as c:
        assert "NVD API key: set (not used yet) — from Settings" in c.get("/reports").text
        c.post("/settings/reset-database", data={"confirm_text": "RESET"})
        assert nvd_client.key_status == nvd.KEY_NOT_SET and nvd_client.key_source is None
        assert "NVD API key: not set" in c.get("/reports").text


def test_unreadable_saved_nvd_key_is_a_clear_error(db_path, tmp_path, caplog):
    app = create_app(db_path=db_path, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})
    key_file(tmp_path).unlink()

    app = create_app(db_path=db_path, shutdown_handler=lambda: None)
    nvd_client = app.state.analyzer.nvd
    assert nvd_client.key_status == nvd.KEY_UNREADABLE and nvd_client._api_key is None
    assert "The NVD API key saved in Settings cannot be used" in caplog.text
    with TestClient(app, base_url="http://127.0.0.1") as c:
        reports = c.get("/reports").text
        assert "NVD API key in Settings cannot be decrypted" in reports
        assert 'class="badge badge-danger nvd-key-badge" data-nvd-key="unreadable"' in reports
        settings = c.get("/settings").text
        assert 'class="text-danger nvd-key-error"' in settings and "is missing" in settings
        r = c.post("/settings/nvd-key", data={"nvd_api_key": API_KEY})  # re-enter it
        assert MASKED in r.text and nvd_client.key_source == nvd.KEY_SOURCE_SETTINGS
        assert nvd_client.key_status == nvd.KEY_SET
    assert API_KEY not in reports + settings + caplog.text


def test_mask_shows_only_the_last_four_characters():
    assert secret_store.mask(API_KEY) == MASKED
    assert API_KEY[:-4] not in secret_store.mask(API_KEY)


# --- 4. secret hygiene ------------------------------------------------------------------------


def test_reprs_never_contain_secrets(db, tmp_path):
    store = SecretStore(db, SecretBox(tmp_path / "secret.key"))
    server = db.create_server("p", "10.0.0.2", "", auth_method=AUTH_PASSWORD)
    store.set_server_password(server.id, SECRET)
    store.set_nvd_key(API_KEY)
    client = nvd.NvdClient(db, api_key=API_KEY)
    for text in (repr(store), repr(store.box), repr(client), repr(db.get_server(server.id))):
        assert SECRET not in text and API_KEY not in text
    assert store.server_password(server.id) == SECRET and store.nvd_key() == API_KEY


def test_validation_messages_never_contain_the_secret():
    for bad in ("", "p" * 257, "pa\x00ss"):
        message = check_ssh_password(bad)
        assert message and (not bad or bad not in message)
    assert check_ssh_password(SECRET) is None
    message = check_nvd_api_key("bad key " + API_KEY)
    assert message and API_KEY not in message


def test_password_only_in_the_sshpass_environment_never_argv():
    fake = FakeSSH(stdout=SUCCESS_STDOUT)
    ssh_service.check_connection("p", "10.0.0.1", "", runner=fake, password=SECRET)
    ssh_service.run_remote("10.0.0.1", "", "true", fake, password=SECRET)
    ssh_service.run_scp("10.0.0.1", "", ["/x/a"], "/tmp/s", fake, password=SECRET)
    assert len(fake.calls) == 3
    for args, kwargs in fake.calls:
        assert args[:2] == ["sshpass", "-e"] and all(SECRET not in a for a in args)
        assert kwargs["env"][ssh_service.SSHPASS_ENV] == SECRET and "shell" not in kwargs
        others = {k: v for k, v in kwargs["env"].items() if k != ssh_service.SSHPASS_ENV}
        assert SECRET not in others.values()
    assert ssh_service.SSHPASS_ENV not in os.environ


def test_ssh_errors_never_echo_the_password():
    for fake in (
        FakeSSH(returncode=ssh_service.SSHPASS_WRONG_PASSWORD),
        FakeSSH(returncode=255, stderr="admin@10.0.0.1: Permission denied (password)."),
        FakeSSH(exc=FileNotFoundError(2, "No such file or directory", "sshpass")),
    ):
        result = ssh_service.run_remote("10.0.0.1", "", "true", fake, password=SECRET)
        assert not result.ok and SECRET not in result.error
        tested = ssh_service.check_connection("p", "10.0.0.1", "", runner=fake, password=SECRET)
        assert not tested.success and SECRET not in tested.error


def test_nvd_403_log_names_the_source_not_the_key(db, caplog):
    client = nvd.NvdClient(db, transport=FakeNvd(replies=[(403, {}, b"")]), sleep=lambda s: None)
    client.use_settings_key(API_KEY)
    assert client.lookup("CVE-2026-63076").status == nvd.FAILED
    assert client.key_status == nvd.KEY_REJECTED
    assert "API key from Settings (HTTP 403)" in caplog.text and API_KEY not in caplog.text
