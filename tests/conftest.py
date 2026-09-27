import subprocess
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import nvd


@pytest.fixture(autouse=True)
def isolated_metadata_cache(tmp_path: Path, monkeypatch):
    """Never read or write the user's real Canonical metadata cache during tests."""
    monkeypatch.setenv("EC2PATCHER_CACHE_DIR", str(tmp_path / "cache"))


@pytest.fixture(autouse=True)
def no_live_nvd(monkeypatch):
    """Tests never reach the real NVD API; clients without a fake transport see it offline."""

    def offline(url, headers, timeout):
        raise OSError("network access to NVD is disabled in tests")

    monkeypatch.setattr(nvd, "http_get", offline)
    monkeypatch.delenv(nvd.API_KEY_ENV, raising=False)


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "data" / "ec2patcher.db"


@pytest.fixture
def db(db_path: Path) -> Database:
    return Database(db_path)


@pytest.fixture
def pem_file(tmp_path: Path) -> Path:
    path = tmp_path / "prod.pem"
    path.write_text("dummy key material - never read by the app\n")
    path.chmod(0o400)
    return path


class FakeSSH:
    """Records ssh invocations and returns a canned CompletedProcess."""

    def __init__(self, returncode=0, stdout="", stderr="", exc=None):
        self.returncode, self.stdout, self.stderr, self.exc = returncode, stdout, stderr, exc
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if self.exc is not None:
            raise self.exc
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, self.stderr)


SUCCESS_STDOUT = (
    "Welcome to Ubuntu\nEC2P_HOSTNAME=ip-10-10-20-15\nEC2P_OS=Ubuntu 24.04 LTS\nEC2P_ARCH=amd64\n"
)


@pytest.fixture
def fake_ssh() -> FakeSSH:
    return FakeSSH(stdout=SUCCESS_STDOUT)


@pytest.fixture
def shutdown_calls() -> list:
    return []


@pytest.fixture
def make_client(db_path, fake_ssh, shutdown_calls):
    def factory(ssh=None):
        app = create_app(
            db_path=db_path,
            ssh_runner=ssh or fake_ssh,
            shutdown_handler=lambda: shutdown_calls.append(True),
        )
        return TestClient(app, base_url="http://127.0.0.1")

    return factory


@pytest.fixture
def client(make_client):
    with make_client() as c:
        yield c
