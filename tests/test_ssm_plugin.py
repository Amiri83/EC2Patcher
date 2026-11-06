"""The app-managed session-manager-plugin, its PATH, the Settings status, the one transport
builder and fail-fast preflight. Downloads and subprocesses are faked, except the tests marked as
using the local dpkg-deb and gpg, which stay offline in tmp_path."""

import ast
import io
import os
import shutil
import stat
import subprocess
import urllib.error
from pathlib import Path

import pytest
from conftest import FakeSSH
from test_ssm_connection import (
    HOST,
    HOST_IP,
    INSTANCE,
    PROFILE,
    REGION,
    SSO_EXPIRED,
    TARGET,
    FakeAws,
    SsmHarness,
    done,
    make_ssm_app,
    proxy,
    ssm_server,
)
from test_web import upload

from ec2patcher import config
from ec2patcher import main as main_module
from ec2patcher.database import Database
from ec2patcher.models import CONNECTION_SSH, CONNECTION_SSM
from ec2patcher.services import downloader, ssh_service, ssm_plugin, ssm_service
from ec2patcher.services import patch_state as ps
from ec2patcher.services.ssm_plugin import PLUGIN_BINARY, PluginInstallError
from ec2patcher.services.ssm_service import SsmError

SRC = Path(ssm_plugin.__file__).parents[1]
DEB = ssm_plugin.DEB_MAGIC + b"\0" * ssm_plugin.MIN_DEB_BYTES
VERSION = "1.2.3.0"
VALIDSIG = f"[GNUPG:] VALIDSIG {ssm_plugin.SIGNER_FINGERPRINT} 2025-01-22 0 4 0 19 8 00 x\n"


def executable(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\necho 1.2.3.0\n")
    path.chmod(0o755)
    return path


class FakeFetch:
    def __init__(self, body=DEB, signature=b"sig", exc=None, signature_exc=None):
        self.body, self.signature = body, signature
        self.exc, self.signature_exc = exc, signature_exc
        self.urls: list[str] = []

    def __call__(self, url, out, max_bytes, timeout):
        self.urls.append(url)
        is_signature = url.endswith(".sig")
        exc = self.signature_exc if is_signature else self.exc
        if exc:
            raise exc
        out.write(self.signature if is_signature else self.body)


class FakeTools:
    """dpkg-deb, gpg and the unpacked plugin."""

    def __init__(self, fields=None, missing=(), gpg_stdout=VALIDSIG, gpg_rc=0, unpack=True,
                 unpack_rc=0, fields_rc=0, plugin_rc=0):  # fmt: skip
        self.fields = fields or f"Package: {PLUGIN_BINARY}\nArchitecture: amd64\n"
        self.missing, self.gpg_stdout, self.gpg_rc = missing, gpg_stdout, gpg_rc
        self.unpack, self.unpack_rc = unpack, unpack_rc
        self.fields_rc, self.plugin_rc = fields_rc, plugin_rc
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        assert "shell" not in kwargs and "sudo" not in args and "dpkg" not in args
        self.calls.append(list(args))
        if args[0] in self.missing:
            raise FileNotFoundError(args[0])
        if args[0] == "dpkg-deb" and args[1] == "-f":
            return done(args, self.fields, self.fields_rc)
        if args[0] == "dpkg-deb" and args[1] == "-x":
            if self.unpack:
                executable(Path(args[3]) / "usr/local/sessionmanagerplugin/bin" / PLUGIN_BINARY)
            return done(args, rc=self.unpack_rc)
        if args[0] == "gpg" and "--verify" in args:
            return done(args, self.gpg_stdout, self.gpg_rc)
        if args[-1] == "--version" and PLUGIN_BINARY in args[0]:
            return done(args, f"{VERSION}\n", self.plugin_rc)
        return done(args)

    def ran(self, *prefix):
        return any(call[: len(prefix)] == list(prefix) for call in self.calls)


def install(tools=None, fetch=None, machine="x86_64"):
    return ssm_plugin.install(tools or FakeTools(), fetch or FakeFetch(), machine)


def data_dir_is_clean():
    entries = [p.name for p in config.get_data_dir().iterdir()]
    return not any(name.startswith(".ssm-plugin-") for name in entries)


@pytest.fixture
def no_plugin_on_path(monkeypatch, tmp_path):
    empty = tmp_path / "empty-path"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))


# --- detection ------------------------------------------------------------------------------


def test_plugin_not_found_anywhere(no_plugin_on_path):
    assert ssm_plugin.find_plugin() is None


def test_plugin_found_on_path(monkeypatch, tmp_path):
    binary = executable(tmp_path / "tools" / PLUGIN_BINARY)
    monkeypatch.setenv("PATH", str(binary.parent))
    location = ssm_plugin.find_plugin()
    assert location.path == binary and not location.managed


def test_plugin_in_the_app_dir_wins_over_path(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(executable(tmp_path / "tools" / PLUGIN_BINARY).parent))
    managed = executable(config.get_plugin_bin_dir() / PLUGIN_BINARY)
    assert managed.parent == config.get_data_dir() / "bin"
    location = ssm_plugin.find_plugin()
    assert location.path == managed and location.managed


def test_a_file_that_is_not_executable_is_not_the_plugin(no_plugin_on_path):
    managed = executable(config.get_plugin_bin_dir() / PLUGIN_BINARY)
    managed.chmod(0o644)
    assert ssm_plugin.find_plugin() is None


def test_cli_data_dir_reaches_the_plugin_directory(monkeypatch, tmp_path):
    monkeypatch.setattr(main_module, "create_app", lambda **kwargs: None)

    class Server:
        def __init__(self, config):
            pass

        def run(self):
            pass

    monkeypatch.setattr(main_module.uvicorn, "Config", lambda *a, **k: None)
    monkeypatch.setattr(main_module.uvicorn, "Server", Server)
    monkeypatch.setenv(config.DATA_DIR_ENV, str(tmp_path / "other"))  # restored by monkeypatch
    main_module.main(["--data-dir", str(tmp_path / "chosen"), "--no-browser"])
    assert config.get_plugin_bin_dir() == tmp_path / "chosen" / "bin"


# --- PATH of the aws CLI ---------------------------------------------------------------------


def test_aws_env_puts_the_app_dir_first_on_path(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    env = ssm_plugin.aws_env()
    assert env["PATH"] == f"{config.get_plugin_bin_dir()}{os.pathsep}/usr/bin"
    assert env["AWS_PAGER"] == ""


def test_preflight_and_lookup_use_that_path():
    fake = FakeAws()
    seen = []

    def runner(args, **kwargs):
        seen.append(kwargs["env"]["PATH"])
        return fake(args, **kwargs)

    ssm_service.preflight(PROFILE, REGION, runner)
    ssm_service.resolve_instance_id(HOST_IP, PROFILE, REGION, runner)
    assert len(seen) == 4
    assert all(path.startswith(str(config.get_plugin_bin_dir())) for path in seen)


@pytest.mark.parametrize("password", [None, "not-a-real-password"])
@pytest.mark.parametrize(
    "call",
    [
        lambda pem, fake, **kw: ssh_service.run_remote(HOST_IP, pem, "true", fake, **kw),
        lambda pem, fake, **kw: ssh_service.run_scp(HOST_IP, pem, ["a"], "/tmp/x", fake, **kw),
        lambda pem, fake, **kw: ssh_service.check_connection("s", HOST_IP, pem, fake, **kw),
    ],
)
def test_ssh_and_scp_over_ssm_pass_that_path_to_the_proxy_command(call, password, pem_file):
    fake = FakeSSH()
    call(str(pem_file), fake, ssm=TARGET, password=password)
    args, kwargs = fake.calls[0]
    assert proxy() in args
    assert kwargs["env"]["PATH"].startswith(str(config.get_plugin_bin_dir()))
    assert kwargs["env"].get(ssh_service.SSHPASS_ENV) == password
    assert password is None or password not in " ".join(args)


def test_direct_ssh_gets_no_special_environment(pem_file):
    fake = FakeSSH()
    ssh_service.run_remote(HOST_IP, str(pem_file), "true", fake)
    args, kwargs = fake.calls[0]
    assert "env" not in kwargs and not any("ProxyCommand" in a for a in args)


# --- one transport builder -------------------------------------------------------------------


@pytest.mark.parametrize(
    "build",
    [
        lambda pem, ssm: ssh_service.build_ssh_command(HOST_IP, pem, "true", ssm=ssm),
        lambda pem, ssm: ssh_service.build_scp_command(HOST_IP, pem, ["a"], "/tmp/x", ssm=ssm),
    ],
)
def test_builder_adds_the_proxy_only_for_ssm(build, pem_file):
    direct, over_ssm = build(str(pem_file), None), build(str(pem_file), TARGET)
    assert not any("ProxyCommand" in arg for arg in direct)
    split = over_ssm.index(proxy()) - 1
    assert over_ssm[split] == "-o"
    assert over_ssm[:split] + over_ssm[split + 2 :] == direct


def test_only_ssh_service_can_build_an_ssh_or_scp_command():
    """models.py names the "ssh" connection type; it is no command."""
    offenders = []
    for path in SRC.rglob("*.py"):
        if path.name in ("ssh_service.py", "models.py"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Constant) and node.value in ("ssh", "scp", "sshpass"):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
            elif isinstance(node, ast.Attribute) and node.attr in ("SSH_BINARY", "SCP_BINARY"):
                offenders.append(f"{path.relative_to(SRC)}:{node.lineno}")
    assert offenders == []


# --- installing ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "machine, subdir, architecture",
    [("x86_64", "ubuntu_64bit", "amd64"), ("aarch64", "ubuntu_arm64", "arm64")],
)
def test_install_downloads_verifies_and_keeps_the_binary(machine, subdir, architecture):
    fetch = FakeFetch()
    tools = FakeTools(fields=f"Package: {PLUGIN_BINARY}\nArchitecture: {architecture}\n")
    result = install(tools, fetch, machine)
    base = f"https://s3.amazonaws.com/session-manager-downloads/plugin/latest/{subdir}"
    assert fetch.urls == [f"{base}/{PLUGIN_BINARY}.deb", f"{base}/{PLUGIN_BINARY}.deb.sig"]
    assert result.path == config.get_plugin_bin_dir() / PLUGIN_BINARY
    assert result.version == VERSION and result.signature_checked
    assert result.path.stat().st_mode & stat.S_IXUSR
    assert tools.ran("dpkg-deb", "-x") and data_dir_is_clean()
    assert list(result.path.parent.iterdir()) == [result.path]
    assert ssm_plugin.find_plugin().managed


def test_install_never_uses_sudo_or_dpkg_install():
    tools = FakeTools()
    install(tools)
    programs = {Path(call[0]).name for call in tools.calls}
    assert programs == {"dpkg-deb", "gpg", f".{PLUGIN_BINARY}.new"}


def test_signature_is_checked_before_dpkg_deb_reads_the_package():
    tools = FakeTools()
    install(tools)
    order = [call[1] if call[0] == "dpkg-deb" else call[0] for call in tools.calls]
    assert order.index("-f") > max(i for i, step in enumerate(order) if step == "gpg")
    verify = next(call for call in tools.calls if "--verify" in call)
    assert "--homedir" in verify and "--batch" in verify  # a throwaway keyring


@pytest.mark.parametrize(
    "exc, expected",
    [
        (urllib.error.URLError("Name or service not known"), "AWS could not be reached"),
        (urllib.error.HTTPError("u", 403, "Forbidden", {}, io.BytesIO()), "HTTP 403"),
        (TimeoutError(), "timed out"),
        (downloader.DownloadError("too large"), "too large"),
        (ConnectionResetError(104, "Connection reset"), "Connection reset"),
    ],
)
def test_download_failures_are_clear_and_leave_nothing(exc, expected):
    with pytest.raises(PluginInstallError, match=expected):
        install(fetch=FakeFetch(exc=exc))
    assert ssm_plugin.find_plugin() is None or not ssm_plugin.find_plugin().managed
    assert data_dir_is_clean()


@pytest.mark.parametrize("body", [b"<html>AccessDenied</html>", b"", ssm_plugin.DEB_MAGIC])
def test_a_download_that_is_no_deb_is_refused(body):
    tools = FakeTools()
    with pytest.raises(PluginInstallError, match="not a valid"):
        install(tools, FakeFetch(body=body))
    assert not tools.ran("dpkg-deb", "-x") and data_dir_is_clean()


def test_an_unreadable_archive_is_refused():
    with pytest.raises(PluginInstallError, match="not a valid"):
        install(FakeTools(fields_rc=2))


def test_another_package_is_refused():
    with pytest.raises(PluginInstallError, match="not a valid"):
        install(FakeTools(fields="Package: something-else\nArchitecture: amd64\n"))


def test_the_wrong_architecture_is_refused():
    with pytest.raises(PluginInstallError, match="needs amd64"):
        install(FakeTools(fields=f"Package: {PLUGIN_BINARY}\nArchitecture: arm64\n"))


def test_dpkg_deb_missing_is_reported_before_any_download():
    fetch = FakeFetch()
    with pytest.raises(PluginInstallError, match="'dpkg-deb' command was not found"):
        install(FakeTools(missing=("dpkg-deb",)), fetch)
    assert fetch.urls == []


def test_an_unknown_machine_is_refused_before_any_download():
    fetch = FakeFetch()
    with pytest.raises(PluginInstallError, match="riscv64"):
        install(fetch=fetch, machine="riscv64")
    assert fetch.urls == []


@pytest.mark.parametrize(
    "tools",
    [
        FakeTools(gpg_rc=1, gpg_stdout="[GNUPG:] BADSIG 2C4D4AFF6F6757EE x\n"),
        FakeTools(gpg_stdout="[GNUPG:] VALIDSIG " + "A" * 40 + " 2025-01-22\n"),
        FakeTools(gpg_stdout=""),
    ],
)
def test_a_bad_signature_stops_the_install(tools):
    with pytest.raises(PluginInstallError, match="could not be verified"):
        install(tools)
    assert not tools.ran("dpkg-deb", "-x") and not ssm_plugin.managed_binary().exists()


def test_a_signature_that_cannot_be_downloaded_stops_the_install():
    fetch = FakeFetch(signature_exc=urllib.error.HTTPError("u", 404, "x", {}, io.BytesIO()))
    with pytest.raises(PluginInstallError, match="signature download failed.*HTTP 404"):
        install(fetch=fetch)
    assert not ssm_plugin.managed_binary().exists()


def test_without_gpg_the_install_says_the_signature_was_not_checked():
    fetch = FakeFetch()
    result = install(FakeTools(missing=("gpg",)), fetch)
    assert not result.signature_checked and result.path.exists()
    assert not any(url.endswith(".sig") for url in fetch.urls)


def test_a_failed_unpack_is_refused():
    with pytest.raises(PluginInstallError, match="not a valid"):
        install(FakeTools(unpack_rc=2))


def test_a_package_without_the_program_is_refused():
    with pytest.raises(PluginInstallError, match="has no session-manager-plugin"):
        install(FakeTools(unpack=False))


def test_a_program_that_does_not_run_keeps_the_previous_one():
    existing = executable(ssm_plugin.managed_binary())
    before = existing.read_bytes()
    existing.write_bytes(before + b"# previous\n")
    with pytest.raises(PluginInstallError, match="does not run"):
        install(FakeTools(plugin_rc=1))
    assert existing.read_bytes() == before + b"# previous\n"
    assert [p.name for p in existing.parent.iterdir()] == [PLUGIN_BINARY]


# --- with the real local tools (still offline) --------------------------------------------------


@pytest.mark.skipif(not shutil.which("gpg"), reason="needs gpg")
def test_embedded_signing_key_has_the_published_fingerprint(tmp_path):
    home = tmp_path / "gnupg"
    home.mkdir(mode=0o700)
    key = tmp_path / "key.asc"
    key.write_text(ssm_plugin.SIGNER_PUBLIC_KEY)
    base = ["gpg", "--homedir", str(home), "--batch", "--no-tty", "--no-autostart"]
    subprocess.run([*base, "--import", str(key)], check=True, capture_output=True)
    listed = subprocess.run(
        [*base, "--with-colons", "--fingerprint"], check=True, capture_output=True, text=True
    ).stdout
    fingerprints = [line.split(":")[9] for line in listed.splitlines() if line.startswith("fpr:")]
    assert fingerprints[0] == ssm_plugin.SIGNER_FINGERPRINT


@pytest.mark.skipif(not shutil.which("dpkg-deb"), reason="needs dpkg-deb")
def test_install_with_real_dpkg_deb_from_a_local_package(tmp_path):
    root = tmp_path / "pkg"
    executable(root / "usr/local/sessionmanagerplugin/bin" / PLUGIN_BINARY)
    # What the package's maintainer scripts would do must not run or matter.
    (root / "DEBIAN").mkdir()
    (root / "DEBIAN/control").write_text(
        f"Package: {PLUGIN_BINARY}\nVersion: {VERSION}\nArchitecture: amd64\n"
        "Maintainer: Example <nobody@example.com>\nDescription: test package\n"
    )
    marker = tmp_path / "postinst-ran"
    postinst = root / "DEBIAN/postinst"
    postinst.write_text(f"#!/bin/sh\ntouch {marker}\n")
    postinst.chmod(0o755)
    deb = tmp_path / "plugin.deb"
    subprocess.run(["dpkg-deb", "--root-owner-group", "--build", str(root), str(deb)],
                   check=True, capture_output=True)  # fmt: skip
    body = deb.read_bytes()
    assert body.startswith(ssm_plugin.DEB_MAGIC)

    def fetcher(url, out, max_bytes, timeout):
        out.write(body)

    def runner(args, **kwargs):  # gpg is exercised apart: no test signature from the AWS key
        if args[0] == "gpg":
            raise FileNotFoundError(args[0])
        return subprocess.run(args, **kwargs)

    original = ssm_plugin.MIN_DEB_BYTES
    try:
        ssm_plugin.MIN_DEB_BYTES = 0  # a tiny test package
        result = ssm_plugin.install(runner, fetcher, "x86_64")
    finally:
        ssm_plugin.MIN_DEB_BYTES = original
    assert result.version == VERSION and result.path == ssm_plugin.managed_binary()
    assert subprocess.run([str(result.path)], capture_output=True, text=True).stdout.strip() == (
        VERSION
    )
    assert not marker.exists() and data_dir_is_clean()


# --- Settings -----------------------------------------------------------------------------------


def save_defaults(db_path):
    ssm_service.save_defaults(Database(db_path), CONNECTION_SSH, PROFILE, REGION)


def test_settings_offers_the_install_when_the_plugin_is_missing(client, no_plugin_on_path):
    page = client.get("/settings").text
    assert "Install SSM plugin" in page and 'action="/settings/ssm-plugin/install"' in page
    assert "Update SSM plugin" not in page


def test_settings_offers_an_update_of_the_managed_plugin(client):
    executable(ssm_plugin.managed_binary())
    page = client.get("/settings").text
    assert "Update SSM plugin" in page and ">Install SSM plugin<" not in page


def test_settings_offers_nothing_for_a_plugin_on_path(client, monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(executable(tmp_path / "t" / PLUGIN_BINARY).parent))
    page = client.get("/settings").text
    assert "/settings/ssm-plugin/install" not in page


def test_rendering_settings_runs_no_command(make_client, db_path):
    save_defaults(db_path)
    fake = FakeAws()
    with make_client(fake) as c:
        page = c.get("/settings").text
    assert fake.calls == [] and 'data-ssm-status-url="/settings/ssm-status"' in page


def test_status_shows_versions_and_a_working_profile(make_client, db_path, monkeypatch):
    save_defaults(db_path)
    managed = executable(ssm_plugin.managed_binary())
    fake = FakeAws()
    with make_client(fake) as c:
        page = c.get("/settings/ssm-status").text
    assert "version 1" in page  # both --version answers of the fake
    assert "app-managed" in page and str(managed) in page
    assert "Profile OK" in page and PROFILE in page
    assert "123456789012" not in page  # the identity is not shown


def test_status_shows_an_expired_sso_session_with_the_login_hint(make_client, db_path):
    save_defaults(db_path)
    with make_client(FakeAws(sts=(255, SSO_EXPIRED))) as c:
        page = c.get("/settings/ssm-status").text
    assert "SSO expired" in page and f"aws sso login --profile {PROFILE}" in page
    assert "Profile OK" not in page


def test_status_shows_another_profile_failure(make_client, db_path):
    save_defaults(db_path)
    stderr = f"The config profile ({PROFILE}) could not be found\n"
    with make_client(FakeAws(sts=(255, stderr))) as c:
        page = c.get("/settings/ssm-status").text
    assert f"AWS profile {PROFILE} was not found" in page and "SSO expired" not in page


def test_status_with_nothing_installed(make_client, db_path, no_plugin_on_path):
    save_defaults(db_path)
    fake = FakeAws(missing=("aws",))
    with make_client(fake) as c:
        page = c.get("/settings/ssm-status").text
    assert page.count("not found") == 2 and "Needs the AWS CLI" in page
    assert fake.count("aws", "sts") == 0


def test_status_without_a_profile_runs_no_aws_request(make_client, db_path):
    fake = FakeAws()
    with make_client(fake) as c:
        page = c.get("/settings/ssm-status").text
    assert "Set the default AWS profile and region" in page and fake.count("aws", "sts") == 0


def test_check_now_works_without_javascript(make_client, db_path):
    save_defaults(db_path)
    with make_client(FakeAws()) as c:
        page = c.get("/settings?ssm_check=1").text
    assert "Profile OK" in page and "data-ssm-status-url" not in page


def test_install_button_installs_and_reports_the_version(make_client, monkeypatch):
    monkeypatch.setattr(ssm_plugin, "default_fetcher", FakeFetch())
    with make_client(FakeTools()) as c:
        page = c.post("/settings/ssm-plugin/install").text
    assert f"Session Manager plugin {VERSION} installed" in page
    assert "signature was verified" in page and "Update SSM plugin" in page


def test_install_button_says_when_the_signature_was_not_checked(make_client, monkeypatch):
    monkeypatch.setattr(ssm_plugin, "default_fetcher", FakeFetch())
    with make_client(FakeTools(missing=("gpg",))) as c:
        page = c.post("/settings/ssm-plugin/install").text
    assert "signature was not checked" in page


def test_a_failed_install_shows_the_reason_not_a_traceback(make_client, no_plugin_on_path):
    with make_client(FakeTools()) as c:  # conftest: the download has no network
        r = c.post("/settings/ssm-plugin/install")
    assert r.status_code == 502 and "download failed" in r.text
    assert "Traceback" not in r.text and "Install SSM plugin" in r.text


def test_apply_to_all_clears_connection_settings_but_keeps_manual_instance_ids(client, db_path):
    db = Database(db_path)
    db.create_server("a", HOST_IP, "/k.pem", transport={
        "connection_type": CONNECTION_SSM, "aws_profile": "other", "aws_region": "eu-west-1",
        "instance_id_override": INSTANCE,
    })  # fmt: skip
    db.create_server("b", "10.0.0.2", "/k.pem", transport={"aws_profile": "other"})
    db.create_server("c", "10.0.0.3", "/k.pem")
    page = client.post("/settings/connection", data={
        "connection_type": "ssm", "aws_profile": PROFILE, "aws_region": REGION,
        "action": "apply_all",
    }).text  # fmt: skip
    assert "(2 per-server connection setting(s) cleared" in page
    a, b = db.get_server_by_name("a"), db.get_server_by_name("b")
    assert (a.connection_type, a.aws_profile, a.aws_region) == (None, None, None)
    assert a.instance_id_override == INSTANCE and b.aws_profile is None
    assert "Apply to all servers" in client.get("/settings").text


# --- instance ID on the Servers page ------------------------------------------------------------


def test_servers_page_shows_a_resolved_id_after_the_button(make_client, db_path):
    save_defaults(db_path)
    server = ssm_server(Database(db_path))
    fake = FakeAws()
    with make_client(fake) as c:
        assert INSTANCE not in c.get("/servers").text
        assert fake.calls == []  # rendering a page never runs the aws CLI
        page = c.post(f"/servers/{server.id}/resolve-instance").text
        assert "Instance ID resolved" in page and INSTANCE in page and "(resolved)" in page
        assert INSTANCE in c.get(f"/servers/{server.id}/edit").text
    assert Database(db_path).get_instance_mapping(HOST_IP, PROFILE, REGION) == INSTANCE
    assert fake.remote_calls == []


def test_failed_resolution_is_a_short_reason(make_client, db_path):
    save_defaults(db_path)
    server = ssm_server(Database(db_path))
    with make_client(FakeAws(instances=())) as c:
        page = c.post(f"/servers/{server.id}/resolve-instance").text
    assert "Instance ID not resolved" in page and "No EC2 instance has the private IP" in page
    assert "Traceback" not in page


def test_manual_id_wins_and_needs_no_lookup(make_client, db_path):
    save_defaults(db_path)
    server = ssm_server(Database(db_path), instance_id_override="i-0fedcba9876543210")
    fake = FakeAws()
    with make_client(fake) as c:
        page = c.get("/servers").text
        assert "i-0fedcba9876543210" in page and "set manually" in page
        assert f"/servers/{server.id}/resolve-instance" not in page
        assert "i-0fedcba9876543210" in c.get(f"/servers/{server.id}/edit").text
    assert fake.calls == []


def test_direct_server_has_no_resolve_button(client, db_path):
    server = Database(db_path).create_server(HOST, HOST_IP, "/k.pem")
    assert f"/servers/{server.id}/resolve-instance" not in client.get("/servers").text


def test_server_form_labels_the_dropdown_connection(client):
    page = client.get("/servers/new").text
    assert '<label for="connection_type">Connection</label>' in page
    assert "SSH (direct)" in page and "SSH over SSM" in page


# --- preflight fails fast -----------------------------------------------------------------------


@pytest.mark.parametrize(
    "aws, expected",
    [
        (dict(missing=("aws",)), "'aws' command was not found"),
        (dict(missing=(PLUGIN_BINARY,)), "Install SSM plugin in Settings"),
        (dict(sts=(255, SSO_EXPIRED)), f"aws sso login --profile {PROFILE}"),
        (
            dict(sts=(255, f"The config profile ({PROFILE}) could not be found")),
            f"AWS profile {PROFILE} was not found",
        ),
        (
            dict(sts=(255, "Provided region_name 'x' doesn't match a supported format.")),
            "AWS region is not valid",
        ),
        (
            dict(sts=(255, 'Could not connect to the endpoint URL: "https://sts.example"')),
            "the AWS region",
        ),
        (dict(instances=()), "No EC2 instance has the private IP"),
    ],
)
def test_patch_preflight_stops_before_anything_happens(aws, expected, db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path, **aws)
    ex = h.approve()
    assert ex.state == ps.FAILED and expected in ex.error_summary
    assert h.aws.remote_calls == [] and h.fake.calls == []


@pytest.mark.parametrize(
    "aws, expected",
    [
        (dict(missing=("aws",)), "'aws' command was not found"),
        (dict(missing=(PLUGIN_BINARY,)), "Install SSM plugin in Settings"),
        (dict(sts=(255, SSO_EXPIRED)), f"aws sso login --profile {PROFILE}"),
        (dict(instances=()), "No EC2 instance has the private IP"),
    ],
)
def test_analysis_preflight_fails_ssm_servers_and_spares_direct_ones(
    aws, expected, db_path, tmp_path, fake_apt, pem_file
):
    from fastapi.testclient import TestClient
    from phase3_fixtures import IP, SERVER, FakeUbuntu, analysis_plan_output

    fake = FakeAws(inner=FakeUbuntu(plan_output=analysis_plan_output()), **aws)
    app = make_ssm_app(db_path, tmp_path, fake_apt, fake)
    db = Database(db_path)
    ssm_service.save_defaults(db, CONNECTION_SSH, PROFILE, REGION)
    db.create_server(SERVER, IP, str(pem_file))
    ssm_server(db, str(pem_file))
    with TestClient(app, base_url="http://127.0.0.1") as c:
        upload(c, {SERVER: ["CVE-2026-63076"], HOST: ["CVE-2026-63076"]})
        c.post("/reports/analyze")
    run = db.get_latest_analysis_run()
    by_name = {s.server_name: s for s in db.get_analysis_run(run.id, details=False).servers}
    assert by_name[SERVER].status == "complete"
    assert by_name[HOST].status == "failed" and expected in by_name[HOST].error
    assert all("ProxyCommand" not in " ".join(call) for call in fake.remote_calls)


def test_direct_servers_run_no_preflight_even_with_nothing_installed(db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path, missing=("aws", PLUGIN_BINARY))
    db.delete_setting(ssm_service.DEFAULT_CONNECTION_SETTING)
    ex = h.approve()
    assert ex.state == ps.SUCCESS and ex.transport == "SSH (direct)"
    assert h.aws.count("aws") == 0 and h.aws.count(PLUGIN_BINARY) == 0


def test_preflight_missing_plugin_message_names_the_settings_action():
    with pytest.raises(SsmError, match="no sudo"):
        ssm_service.preflight(PROFILE, REGION, FakeAws(missing=(PLUGIN_BINARY,)))
