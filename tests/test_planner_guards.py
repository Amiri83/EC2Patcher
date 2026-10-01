"""Planner guards: a server whose dpkg reports unconfigured / half-installed packages gets a
blocker instead of a plan, and a package already at its target version is never planned.

The analysis runs for real against FakeUbuntu (fake ssh) and the fake workstation APT backend;
nothing touches a real server or the network.
"""

import pytest
from fastapi.testclient import TestClient
from phase2_fixtures import facts_output, make_metadata
from phase3_fixtures import IP, PLAN, SERVER, FakeUbuntu, analysis_plan_output

from ec2patcher.app import create_app
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import patch_service, server_state
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.apt_planner import DownloadPlan, PlannedDeb

CVES = ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"]
OPENSSL_TARGET = "3.0.13-0ubuntu3.6"


def sync(fn):
    fn()


@pytest.fixture
def env(db, pem_file, tmp_path, fake_apt):
    fake_apt.plan = analysis_plan_output()
    fake = FakeUbuntu()
    db.create_server(SERVER, IP, str(pem_file))
    service = AnalysisService(db, make_metadata(tmp_path), runner=fake, starter=sync)

    def analyze():
        db.save_report("security-report.json", {SERVER: CVES}, "VALID")
        run_id = service.start(db.get_latest_report())
        return db.get_analysis_run(run_id).servers[0]

    return db, fake, fake_apt, service, analyze


def report_page(db_path, runner, analysis):
    app = create_app(db_path=db_path, ssh_runner=runner, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        return client.get(f"/analysis/{analysis.run_id}/servers/{analysis.id}").text


# --- dpkg --audit blocker -------------------------------------------------------------------


def test_unconfigured_package_in_dpkg_audit_blocks_plan(env, db_path):
    db, fake, fake_apt, _, analyze = env
    fake.packages[("openssl", "amd64")][3] = "iU "  # unpacked, not configured
    fake.packages[("libssl3t64", "amd64")][3] = "iF "  # half-configured
    analysis = analyze()
    assert analysis.status == "failed" and analysis.plan == [] and analysis.findings == []
    assert analysis.error.startswith(
        "Server has unconfigured packages: run sudo dpkg --configure -a"
    )
    assert "dpkg --audit reports: libssl3t64, openssl." in analysis.error
    # Facts were collected (read-only), but no APT resolution / plan was attempted.
    assert fake.ops == ["hostname"] and fake_apt.calls == []
    assert patch_service.check_plan(analysis) == ["The analysis of this server failed."]
    html = report_page(db_path, fake, analysis)
    assert "Server has unconfigured packages: run sudo dpkg --configure -a" in html
    assert "/approve" not in html


def test_dpkg_blocker_invalidates_previous_plan_on_reanalysis(env):
    db, fake, _, service, analyze = env
    analysis = analyze()
    assert analysis.status == "complete" and len(analysis.plan) == len(PLAN)

    fake.packages[("openssl", "amd64")][3] = "iU "
    assert service.reanalyze_server(analysis.run_id, analysis.id)
    blocked = db.get_server_analysis(analysis.id)
    assert blocked.status == "failed" and server_state.DPKG_BLOCKER in blocked.error
    assert patch_service.check_plan(blocked) == ["The analysis of this server failed."]

    fake.packages[("openssl", "amd64")][3] = "ii "  # sudo dpkg --configure -a was run
    assert service.reanalyze_server(analysis.run_id, analysis.id)
    repaired = db.get_server_analysis(analysis.id)
    assert repaired.status == "complete" and repaired.error is None
    assert len(repaired.plan) == len(PLAN)


def test_dpkg_audit_parsing():
    healthy = server_state.parse_facts(facts_output())
    assert healthy.dpkg_audit == [] and server_state.dpkg_blocker(healthy) is None
    half = [
        "The following packages are only half installed, due to problems during",
        "installation.  The installation can probably be completed by retrying it;",
        "the packages can be removed using dselect or dpkg --remove:",
        " nginx-common         small, powerful, scalable web/proxy server - common files",
    ]
    facts = server_state.parse_facts(facts_output(audit=half))
    assert server_state.audit_packages(facts.dpkg_audit) == ["nginx-common"]
    assert "dpkg --audit reports: nginx-common." in server_state.dpkg_blocker(facts)
    # A non-zero exit status without output still blocks.
    silent = facts_output().replace("@@EC2P audit-rc\n0", "@@EC2P audit-rc\n2")
    blocker = server_state.dpkg_blocker(server_state.parse_facts(silent))
    assert blocker.startswith(server_state.DPKG_BLOCKER) and "exit status 2" in blocker


def test_facts_command_runs_dpkg_audit_read_only():
    command = server_state.FACTS_COMMAND
    assert "dpkg --audit" in command and "sudo" not in command and "--configure" not in command


# --- same-version packages are never planned ------------------------------------------------


def test_same_version_package_excluded_from_plan(env):
    """openssl was upgraded by hand: dpkg already has the target, libssl3t64 does not. APT
    still lists openssl with an identical old and new version; it must not be planned."""
    db, fake, fake_apt, _, analyze = env
    fake.preinstall(["openssl"])
    fake_apt.plan = analysis_plan_output().replace(
        "Inst openssl [3.0.13-0ubuntu3.4]", f"Inst openssl [{OPENSSL_TARGET}]"
    )
    analysis = analyze()
    assert analysis.status == "complete", analysis.error
    planned = {p.binary_package for p in analysis.plan}
    assert "openssl" not in planned and "libssl3t64" in planned
    assert len(analysis.plan) == len(PLAN) - 1
    assert all(p.current_version != p.target_version for p in analysis.plan)
    assert not any(a.startswith("openssl=") for a in analysis.apt_arguments)
    assert any(a.startswith("libssl3t64") for a in analysis.apt_arguments)
    assert any(
        "Excluded from the plan" in w and f"openssl {OPENSSL_TARGET}" in w
        for w in analysis.warnings
    )
    assert patch_service.check_plan(analysis) == []


def test_build_plan_skips_same_version_debs():
    facts = server_state.parse_facts(facts_output())
    download = DownloadPlan(
        ok=True,
        packages=[
            PlannedDeb("openssl", "amd64", "3.0.13-0ubuntu3.4", OPENSSL_TARGET),
            PlannedDeb("curl", "amd64", "8.5.0-2ubuntu10.6", "0:8.5.0-2ubuntu10.6"),  # epoch 0
        ],
    )
    plan = cr.build_plan([], download, {}, facts)
    assert [e.package for e in plan] == ["openssl"]
    assert cr.already_at_target(download) == ["curl 0:8.5.0-2ubuntu10.6"]
    assert cr.same_version("1.0", "0:1.0") and not cr.same_version(None, "1.0")
