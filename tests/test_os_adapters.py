"""OS detection and the OsAdapter layer: Ubuntu goes through UbuntuAdapter unchanged, any
other OS named by /etc/os-release is reported as "OS not supported yet" (not a failure)."""

import subprocess

import pytest
from phase2_fixtures import NOBLE_OS_RELEASE, ScriptedSSH, facts_output, make_metadata
from phase3_fixtures import make_analysis

from ec2patcher.services import os_adapters, server_state
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.patch_service import PatchService, check_plan

UBUNTU_IP, AMAZON_IP, DEBIAN_IP = "10.0.0.11", "10.0.0.12", "10.0.0.13"

AMAZON_OS_RELEASE = """NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023.6.20241010"
ANSI_COLOR="0;33"
HOME_URL="https://aws.amazon.com/linux/amazon-linux-2023/\""""

DEBIAN_OS_RELEASE = (
    'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\nNAME="Debian GNU/Linux"\nVERSION_ID="12"\n'
    "VERSION_CODENAME=bookworm\nID=debian"
)


def non_dpkg_facts(os_release: str, hostname: str = "ip-10-0-0-12") -> str:
    """What the (Ubuntu) facts command prints on a server without dpkg: the OS-independent
    sections are there, the dpkg ones are empty (errors go to stderr)."""
    lines = ["   ,     #_", "   ~\\_  ####_        Amazon Linux 2023", ""]  # MOTD
    lines += ["@@EC2P hostname", hostname, "@@EC2P os-release", os_release, "@@EC2P arch"]
    lines += ["@@EC2P kernel", "6.1.112-122.189.amzn2023.x86_64", "@@EC2P reboot", "no"]
    lines += ["@@EC2P reboot-hooks", "@@EC2P dpkg", "@@EC2P audit", "@@EC2P audit-rc", "127"]
    return "\n".join([*lines, "@@EC2P end"]) + "\n"


class FleetSSH(ScriptedSSH):
    """ScriptedSSH with per-IP facts output."""

    def __init__(self, facts_by_ip):
        super().__init__()
        self.facts_by_ip = facts_by_ip

    def __call__(self, args, **kwargs):
        self.facts = self.facts_by_ip.get(args[-2].split("@", 1)[1], "")
        return super().__call__(args, **kwargs)


def sync(fn):
    fn()


@pytest.fixture
def fleet(db, pem_file):
    db.create_server("web-ubuntu", UBUNTU_IP, str(pem_file))
    db.create_server("web-amazon", AMAZON_IP, str(pem_file), ssh_user="ec2-user")
    db.create_server("web-debian", DEBIAN_IP, str(pem_file), ssh_user="admin")
    return db


def analyze(db, ssh, servers=("web-ubuntu", "web-amazon", "web-debian")):
    db.save_report("report.json", {name: ["CVE-2026-63076"] for name in servers}, "VALID")
    service = AnalysisService(db, make_metadata(None), runner=ssh, starter=sync)
    run_id = service.start(db.get_latest_report())
    return service, db.get_analysis_run(run_id)


def fleet_ssh():
    return FleetSSH(
        {
            UBUNTU_IP: facts_output(),
            AMAZON_IP: non_dpkg_facts(AMAZON_OS_RELEASE),
            DEBIAN_IP: non_dpkg_facts(DEBIAN_OS_RELEASE, hostname="deb-1"),
        }
    )


# --- detection ------------------------------------------------------------------------


def test_detect_from_facts_output():
    ubuntu = os_adapters.os_release_from_output(facts_output())
    assert os_adapters.detect(ubuntu) is os_adapters.UBUNTU
    assert isinstance(os_adapters.UBUNTU, os_adapters.OsAdapter)
    amazon = os_adapters.os_release_from_output(non_dpkg_facts(AMAZON_OS_RELEASE))
    assert amazon["ID"] == "amzn" and os_adapters.detect(amazon) is None
    assert os_adapters.unsupported_message(amazon) == "OS not supported yet: Amazon Linux 2023"
    debian = os_adapters.os_release_from_output(non_dpkg_facts(DEBIAN_OS_RELEASE))
    assert os_adapters.unsupported_message(debian) == "OS not supported yet: Debian GNU/Linux 12"


def test_output_without_os_release_is_left_to_the_default_adapter():
    """Garbage / truncated output keeps its old 'Malformed remote output' handling."""
    garbage = os_adapters.os_release_from_output("garbage\n")
    assert garbage == {} and os_adapters.detect(garbage) is os_adapters.DEFAULT
    assert os_adapters.detect({}) is os_adapters.UBUNTU


def test_describe_falls_back_to_pretty_name_or_id():
    assert os_adapters.describe({"ID": "arch", "PRETTY_NAME": "Arch Linux"}) == "Arch Linux"
    assert os_adapters.describe({"ID": "alpine", "VERSION_ID": "3.20"}) == "alpine 3.20"
    assert os_adapters.describe({}) == "unknown"


def test_ubuntu_adapter_delegates_to_the_ubuntu_modules():
    ubuntu = os_adapters.UBUNTU
    assert ubuntu.os_id == "ubuntu" and ubuntu.matches({"ID": "ubuntu"})
    assert not ubuntu.matches({"ID": "debian", "ID_LIKE": "ubuntu"})
    assert ubuntu.facts_command == server_state.FACTS_COMMAND
    facts = ubuntu.parse_facts(facts_output())
    assert facts == server_state.parse_facts(facts_output())
    assert ubuntu.check_supported(facts) is None and ubuntu.blocker(facts) is None
    assert ubuntu.is_blocker(server_state.DPKG_BLOCKER + " on the server")
    assert os_adapters.is_blocker(server_state.DPKG_BLOCKER) and not os_adapters.is_blocker("x")
    assert ubuntu.compare_versions("1:1.0", "2.0") > 0
    assert ubuntu.at_or_above_target("3.0.13-0ubuntu3.6", "3.0.13-0ubuntu3.6")
    assert ubuntu.is_kernel_package("linux-image-6.8.0-1024-aws")
    assert not ubuntu.is_kernel_package("linux-image-aws")
    assert os_adapters.get(None) is ubuntu and os_adapters.get("ubuntu") is ubuntu
    assert os_adapters.get("amzn") is None


# --- analysis -------------------------------------------------------------------------


def test_mixed_fleet_analysis(fleet):
    ssh = fleet_ssh()
    _, run = analyze(fleet, ssh)
    ubuntu, amazon, debian = run.servers
    # Ubuntu: unchanged full analysis, now recording the adapter.
    assert ubuntu.status == "complete" and ubuntu.error is None and ubuntu.os_id == "ubuntu"
    assert ubuntu.os_codename == "noble" and ubuntu.findings
    # Others: not a failure, a clear message and what could be learned.
    assert amazon.status == "unsupported"
    assert amazon.error == "OS not supported yet: Amazon Linux 2023"
    assert (amazon.os_id, amazon.os_version_id) == ("amzn", "2023")
    assert amazon.os_pretty_name == "Amazon Linux 2023.6.20241010"
    assert amazon.remote_hostname == "ip-10-0-0-12" and amazon.findings == []
    assert debian.status == "unsupported"
    assert debian.error == "OS not supported yet: Debian GNU/Linux 12"
    assert debian.os_codename == "bookworm" and debian.remote_hostname == "deb-1"
    # An unsupported OS does not make the run fail.
    assert run.status == "completed"
    # One read-only facts command per server, as each server's own SSH user.
    assert [args[-2] for args in ssh.calls] == [
        f"ubuntu@{UBUNTU_IP}", f"ec2-user@{AMAZON_IP}", f"admin@{DEBIAN_IP}",
    ]  # fmt: skip
    assert all(args[-1] == server_state.FACTS_COMMAND for args in ssh.calls)


def test_ubuntu_release_checks_unchanged(fleet):
    old = NOBLE_OS_RELEASE.replace("24.04", "16.04").replace("noble", "xenial")
    _, run = analyze(fleet, FleetSSH({UBUNTU_IP: facts_output(os_release=old)}), ["web-ubuntu"])
    assert run.servers[0].status == "failed"
    assert "Unsupported Ubuntu release: 16.04" in run.servers[0].error
    assert run.status == "completed_with_errors"


def test_reanalyze_keeps_the_unsupported_message(fleet):
    service, run = analyze(fleet, fleet_ssh())
    amazon = run.servers[1]
    assert service.reanalyze_server(run.id, amazon.id)
    again = fleet.get_server_analysis(amazon.id)
    assert again.status == "unsupported"
    assert again.error == "OS not supported yet: Amazon Linux 2023"
    assert fleet.get_analysis_run(run.id).status == "completed"


def test_unsupported_server_is_never_eligible_for_patching(fleet):
    _, run = analyze(fleet, fleet_ssh())
    amazon = fleet.get_server_analysis(run.servers[1].id)
    assert check_plan(amazon) == ["OS not supported yet: Amazon Linux 2023"]
    service = PatchService(fleet, runner=FleetSSH({}), starter=sync)
    assert not service.eligibility(amazon).allowed


def test_complete_analysis_with_an_unknown_adapter_is_refused(db, pem_file):
    server = db.create_server("srv", UBUNTU_IP, str(pem_file))
    analysis = make_analysis(db, server, os_id="plan9", os_pretty_name="Plan 9")
    assert check_plan(analysis) == ["OS not supported yet: Plan 9"]


def test_web_pages_show_the_unsupported_os(fleet, make_client):
    _, run = analyze(fleet, fleet_ssh())
    amazon = run.servers[1]
    with make_client() as client:
        page = client.get(f"/analysis/{run.id}").text
        assert "OS not supported yet: Amazon Linux 2023" in page
        assert "Not supported" in page
        report = client.get(f"/analysis/{run.id}/servers/{amazon.id}").text
        assert "OS NOT SUPPORTED YET" in report and "ANALYSIS FAILED" not in report
        assert "OS not supported yet: Amazon Linux 2023" in report
        assert "Operating System" in report
        ubuntu = client.get(f"/analysis/{run.id}/servers/{run.servers[0].id}").text
        assert "<dt>Ubuntu</dt>" in ubuntu


def test_ssh_failure_is_still_a_failure_not_unsupported(fleet):
    ssh = FleetSSH({})
    ssh.failures = {AMAZON_IP: subprocess.TimeoutExpired("ssh", 90)}
    _, run = analyze(fleet, ssh, ["web-amazon"])
    assert run.servers[0].status == "failed"
    assert "did not finish within 90s" in run.servers[0].error


def test_patch_execution_uses_the_server_ssh_user(db, pem_file, tmp_path):
    from phase3_fixtures import IP, SERVER, FakeFetcher, FakeUbuntu

    from ec2patcher.services import patch_service
    from ec2patcher.services import patch_state as ps

    server = db.create_server(SERVER, IP, str(pem_file), ssh_user="admin")
    fake = FakeUbuntu()
    db.set_setting(patch_service.STAGING_SETTING, f"{tmp_path}/staging/${{server_name}}")
    service = PatchService(db, runner=fake, starter=sync, fetcher=FakeFetcher())
    analysis = make_analysis(db, server)
    assert analysis.os_id is None  # stored like an analysis made before v11 -> Ubuntu
    ex = db.get_execution(service.approve(analysis.id))
    assert ex.state == ps.SUCCESS
    targets = [args for op, args in fake.calls if op == "scp"]
    assert targets and all(args[-1].startswith(f"admin@{IP}:") for args in targets)


def test_sudo_message_names_the_ssh_user(db, pem_file, tmp_path):
    from phase3_fixtures import IP, SERVER, FakeFetcher, FakeUbuntu

    from ec2patcher.services import patch_service

    server = db.create_server(SERVER, IP, str(pem_file), ssh_user="ec2-user")
    fake = FakeUbuntu()
    fake.sudo = False
    db.set_setting(patch_service.STAGING_SETTING, f"{tmp_path}/staging/${{server_name}}")
    service = PatchService(db, runner=fake, starter=sync, fetcher=FakeFetcher())
    ex = db.get_execution(service.approve(make_analysis(db, server).id))
    assert "not available for the ec2-user user" in ex.error_summary
