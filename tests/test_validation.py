import os

import pytest

from ec2patcher.validation import check_ip_address, check_pem_path, validate_server_input


@pytest.mark.parametrize("ip", ["10.10.20.15", "192.168.0.1", " 172.16.5.4 ", "::1", "2001:db8::1"])
def test_valid_ip_accepted(ip):
    normalized, error = check_ip_address(ip)
    assert error is None
    assert normalized == ip.strip()


@pytest.mark.parametrize(
    "ip",
    [
        "",
        "   ",
        "10.10.20",
        "256.1.1.1",
        "abc",
        "10.0.0.1; rm -rf /",
        "-oProxyCommand=x",
        "10.0.0.1 10.0.0.2",
    ],
)
def test_invalid_ip_rejected(ip):
    normalized, error = check_ip_address(ip)
    assert normalized is None
    assert error


def test_valid_input(db, pem_file):
    result = validate_server_input(db, " app-prod-01 ", "10.10.20.15", str(pem_file))
    assert result.is_valid, result.errors
    assert result.name == "app-prod-01"


@pytest.mark.parametrize("name", ["", "   "])
def test_empty_name_rejected(db, pem_file, name):
    result = validate_server_input(db, name, "10.10.20.15", str(pem_file))
    assert "name" in result.errors


@pytest.mark.parametrize("name", ["bad name", "../etc", "-x", "a" * 65, "x;y", "é"])
def test_unsafe_name_rejected(db, pem_file, name):
    assert "name" in validate_server_input(db, name, "10.10.20.15", str(pem_file)).errors


def test_duplicate_name_rejected(db, pem_file):
    existing = db.create_server("app-prod-01", "10.0.0.1", str(pem_file))
    result = validate_server_input(db, "app-prod-01", "10.0.0.2", str(pem_file))
    assert "already exists" in result.errors["name"]
    assert "name" in validate_server_input(db, "App-Prod-01", "10.0.0.2", str(pem_file)).errors
    # Editing the same server keeps its own name.
    assert validate_server_input(
        db, "app-prod-01", "10.0.0.2", str(pem_file), exclude_id=existing.id
    ).is_valid


def test_pem_path_required(db):
    result = validate_server_input(db, "a", "10.0.0.1", "  ")
    assert result.errors["pem_path"] == "PEM file path is required."


def test_pem_path_missing(tmp_path):
    assert "does not exist" in check_pem_path(str(tmp_path / "nope.pem"))


def test_pem_path_directory(tmp_path):
    assert "not a regular file" in check_pem_path(str(tmp_path))


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read any file")
def test_pem_path_unreadable(tmp_path):
    pem = tmp_path / "locked.pem"
    pem.write_text("x")
    pem.chmod(0o000)
    try:
        assert "not readable" in check_pem_path(str(pem))
    finally:
        pem.chmod(0o600)


def test_pem_path_tilde_expanded(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / ".ssh").mkdir()
    (tmp_path / ".ssh" / "prod.pem").write_text("x")
    assert check_pem_path("~/.ssh/prod.pem") is None
    assert "does not exist" in check_pem_path("~/.ssh/other.pem")
