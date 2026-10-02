"""Integration tests against the local SSH test targets (scripts/test-targets).

Deselected by default; run with ``pytest -m integration`` after ``scripts/test-targets/up.sh``.
Real ssh to containers on localhost only (no AWS, no other network): SSH test and OS
detection on Ubuntu 24.04 (user ubuntu) and Amazon Linux 2023 (user ec2-user).

Environment (defaults match compose.yaml / up.sh):
  EC2P_IT_HOST         127.0.0.1
  EC2P_IT_UBUNTU_PORT  2201
  EC2P_IT_AMAZON_PORT  2202
  EC2P_IT_KEY          scripts/test-targets/.keys/id_ed25519
"""

import os
import subprocess
from pathlib import Path

import pytest
from phase2_fixtures import make_metadata

from ec2patcher.services import os_adapters, ssh_service
from ec2patcher.services.analysis_service import AnalysisService

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[1]
HOST = os.environ.get("EC2P_IT_HOST", "127.0.0.1")
KEY = os.environ.get("EC2P_IT_KEY", str(ROOT / "scripts" / "test-targets" / ".keys" / "id_ed25519"))
UBUNTU = ("ubuntu", int(os.environ.get("EC2P_IT_UBUNTU_PORT", "2201")))
AMAZON = ("ec2-user", int(os.environ.get("EC2P_IT_AMAZON_PORT", "2202")))


@pytest.fixture(autouse=True)
def test_target_ssh(tmp_path, monkeypatch):
    """Real ssh, but host keys go to a throwaway known_hosts (containers get new host keys on
    every start; the user's ~/.ssh/known_hosts is never touched)."""
    if not Path(KEY).is_file():
        pytest.fail(f"Test target key {KEY} not found: run scripts/test-targets/up.sh first.")
    assert "StrictHostKeyChecking=accept-new" in ssh_service.SSH_OPTIONS
    monkeypatch.setattr(
        ssh_service,
        "SSH_OPTIONS",
        [*ssh_service.SSH_OPTIONS, "-o", f"UserKnownHostsFile={tmp_path / 'known_hosts'}",
         "-o", "LogLevel=ERROR"],
    )  # fmt: skip


def port_runner(port: int):
    """subprocess.run that sends the app's unchanged ssh/scp command lines to ``port``
    (servers in the inventory have no port: real EC2 servers listen on 22)."""

    def run(args, **kwargs):
        flag = "-P" if args[0] == "scp" else "-p"
        return subprocess.run([args[0], flag, str(port), *args[1:]], **kwargs)  # noqa: S603

    return run


def facts_output(user: str, port: int) -> str:
    result = ssh_service.run_remote(
        HOST, KEY, os_adapters.DEFAULT.facts_command, timeout=90, user=user, port=port
    )
    assert result.ok, result.error
    return result.stdout


# --- SSH test ---------------------------------------------------------------------------


def test_integration_ssh_test_ubuntu():
    user, port = UBUNTU
    result = ssh_service.check_connection("it-ubuntu", HOST, KEY, user=user, port=port)
    assert result.success, result.error
    assert result.hostname == "ec2p-test-ubuntu"
    assert result.os_release.startswith("Ubuntu 24.04")
    assert result.architecture in ("amd64", "arm64")


def test_integration_ssh_test_amazon_linux():
    user, port = AMAZON
    result = ssh_service.check_connection("it-amazon", HOST, KEY, user=user, port=port)
    assert result.success, result.error
    assert result.hostname == "ec2p-test-amazonlinux"
    assert result.os_release.startswith("Amazon Linux 2023")
    assert result.architecture in ("x86_64", "aarch64")


def test_integration_ssh_test_wrong_user_is_refused():
    """Key-only auth per user: 'ubuntu' does not exist on the Amazon Linux target."""
    _, port = AMAZON
    result = ssh_service.check_connection("it-amazon", HOST, KEY, user="ubuntu", port=port)
    assert not result.success and "Permission denied" in result.error


# --- OS detection -----------------------------------------------------------------------


def test_integration_os_detection_ubuntu():
    stdout = facts_output(*UBUNTU)
    os_release = os_adapters.os_release_from_output(stdout)
    assert os_release["ID"] == "ubuntu" and os_release["VERSION_ID"] == "24.04"
    adapter = os_adapters.detect(os_release)
    assert adapter is os_adapters.UBUNTU
    facts = adapter.parse_facts(stdout)  # real dpkg inventory of the container
    assert (facts.version_id, facts.codename) == ("24.04", "noble")
    assert facts.hostname == "ec2p-test-ubuntu" and facts.architecture in ("amd64", "arm64")
    assert any(p.base_name == "openssh-server" for p in facts.packages)
    assert adapter.check_supported(facts) is None


def test_integration_os_detection_amazon_linux():
    stdout = facts_output(*AMAZON)
    os_release = os_adapters.os_release_from_output(stdout)
    assert os_release["ID"] == "amzn" and os_release["VERSION_ID"] == "2023"
    assert os_adapters.detect(os_release) is None
    assert os_adapters.unsupported_message(os_release) == "OS not supported yet: Amazon Linux 2023"


def test_integration_analysis_of_both_targets(db, tmp_path):
    """The analysis service end to end (no CVEs: no Canonical / NVD / APT work needed)."""
    servers = {"it-ubuntu": UBUNTU, "it-amazon": AMAZON}
    results = {}
    for name, (user, port) in servers.items():
        db.create_server(name, HOST, KEY, ssh_user=user)
        db.save_report("it.json", {name: []}, "VALID")
        service = AnalysisService(
            db, make_metadata(tmp_path), runner=port_runner(port), starter=lambda fn: fn()
        )
        run_id = service.start(db.get_latest_report())
        results[name] = db.get_analysis_run(run_id).servers[0]
    ubuntu, amazon = results["it-ubuntu"], results["it-amazon"]
    assert ubuntu.status == "complete", ubuntu.error
    assert (ubuntu.os_id, ubuntu.os_codename) == ("ubuntu", "noble")
    assert ubuntu.remote_hostname == "ec2p-test-ubuntu"
    assert amazon.status == "unsupported"
    assert amazon.error == "OS not supported yet: Amazon Linux 2023"
    assert amazon.os_id == "amzn" and amazon.remote_hostname == "ec2p-test-amazonlinux"
