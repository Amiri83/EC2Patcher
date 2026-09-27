import subprocess

from conftest import SUCCESS_STDOUT, FakeSSH

from ec2patcher.services import ssh_service
from ec2patcher.services.ssh_service import (
    build_ssh_command,
    check_connection,
    describe_ssh_error,
    parse_remote_info,
)


def test_command_is_safe_argument_list(pem_file):
    cmd = build_ssh_command("10.10.20.15", str(pem_file))
    assert isinstance(cmd, list) and all(isinstance(a, str) for a in cmd)
    assert cmd[0] == "ssh"
    assert cmd[cmd.index("-i") + 1] == str(pem_file)
    assert "BatchMode=yes" in cmd
    assert "PasswordAuthentication=no" in cmd
    assert f"ConnectTimeout={ssh_service.CONNECT_TIMEOUT_SECONDS}" in cmd
    # Destination follows "--" so it can never be parsed as an option.
    assert cmd[cmd.index("--") + 1] == "ubuntu@10.10.20.15"
    assert cmd[-1] == ssh_service.REMOTE_COMMAND


def test_pem_path_with_spaces_stays_single_argument(tmp_path):
    pem = tmp_path / "my keys" / "prod key.pem"
    cmd = build_ssh_command("10.0.0.1", str(pem))
    assert str(pem) in cmd


def test_pem_tilde_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    cmd = build_ssh_command("10.0.0.1", "~/.ssh/prod.pem")
    assert cmd[cmd.index("-i") + 1] == str(tmp_path / ".ssh" / "prod.pem")


def test_fixed_ubuntu_user(pem_file):
    fake = FakeSSH(stdout=SUCCESS_STDOUT)
    check_connection("app-prod-01", "10.10.20.15", str(pem_file), runner=fake)
    args, _ = fake.calls[0]
    assert "ubuntu@10.10.20.15" in args
    assert not any(a.startswith("root@") for a in args)


def test_success_parses_remote_details(pem_file):
    fake = FakeSSH(stdout=SUCCESS_STDOUT)
    result = check_connection("app-prod-01", "10.10.20.15", str(pem_file), runner=fake)
    assert result.success
    assert result.hostname == "ip-10-10-20-15"
    assert result.os_release == "Ubuntu 24.04 LTS"
    assert result.architecture == "amd64"
    assert result.error is None
    _, kwargs = fake.calls[0]
    assert kwargs.get("shell", False) is False
    assert kwargs["timeout"] == ssh_service.PROCESS_TIMEOUT_SECONDS
    assert kwargs["stdin"] == subprocess.DEVNULL


def test_success_with_tilde_pem(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "prod.pem").write_text("x")
    fake = FakeSSH(stdout=SUCCESS_STDOUT)
    result = check_connection("a", "10.0.0.1", "~/.ssh/prod.pem", runner=fake)
    assert result.success
    args, _ = fake.calls[0]
    assert args[args.index("-i") + 1] == str(tmp_path / ".ssh" / "prod.pem")


def test_parse_remote_info_ignores_noise():
    info = parse_remote_info("banner\nEC2P_HOSTNAME=host1\nrandom=1\nEC2P_OS=\nEC2P_ARCH=arm64\n")
    assert info == {"hostname": "host1", "architecture": "arm64"}


def test_timeout(pem_file):
    fake = FakeSSH(exc=subprocess.TimeoutExpired(cmd="ssh", timeout=30))
    result = check_connection("a", "10.0.0.1", str(pem_file), runner=fake)
    assert not result.success
    assert "timed out" in result.error


def test_connect_timeout_from_ssh(pem_file):
    fake = FakeSSH(
        returncode=255, stderr="ssh: connect to host 10.0.0.1 port 22: Connection timed out\n"
    )
    result = check_connection("a", "10.0.0.1", str(pem_file), runner=fake)
    assert result.error.startswith("Connection timed out")


def test_auth_failure(pem_file):
    fake = FakeSSH(returncode=255, stderr="ubuntu@10.0.0.1: Permission denied (publickey).\n")
    result = check_connection("a", "10.0.0.1", str(pem_file), runner=fake)
    assert not result.success
    assert result.error.startswith("Permission denied (publickey)")


def test_missing_pem_does_not_run_ssh(tmp_path):
    fake = FakeSSH()
    result = check_connection("a", "10.0.0.1", str(tmp_path / "missing.pem"), runner=fake)
    assert not result.success
    assert "PEM file does not exist" in result.error
    assert fake.calls == []


def test_invalid_ip_does_not_run_ssh(pem_file):
    fake = FakeSSH()
    result = check_connection("a", "-oProxyCommand=touch /tmp/x", str(pem_file), runner=fake)
    assert not result.success
    assert fake.calls == []


def test_ssh_binary_missing(pem_file):
    fake = FakeSSH(exc=FileNotFoundError())
    result = check_connection("a", "10.0.0.1", str(pem_file), runner=fake)
    assert "not found" in result.error


def test_error_descriptions():
    assert "chmod 400" in describe_ssh_error("WARNING: UNPROTECTED PRIVATE KEY FILE!")
    assert "refused" in describe_ssh_error("connect to host x port 22: Connection refused")
    assert "No route" in describe_ssh_error("connect to host x port 22: No route to host")
    assert "host key has changed" in describe_ssh_error(
        "WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!"
    )
    assert describe_ssh_error("something odd\n") == "SSH connection failed: something odd"
    assert "unknown reason" in describe_ssh_error("")


def test_pem_contents_never_read(pem_file, monkeypatch):
    import builtins

    real_open = builtins.open

    def guarded_open(file, *args, **kwargs):
        assert str(file) != str(pem_file), "PEM file must not be opened"
        return real_open(file, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", guarded_open)
    result = check_connection("a", "10.0.0.1", str(pem_file), runner=FakeSSH(stdout=SUCCESS_STDOUT))
    assert result.success
