"""Never block a whole server (or the UI) because of one package or a leftover status flag.

* Packages already at (or above) their target version are excluded with a warning and the
  rest is patched; a server is only refused when nothing is left to install.
* "Analysis / patch running" means a live worker thread: a crash or an app restart never
  leaves the Analyze / Approve / Patch All buttons disabled.

Remote interactions go to FakeUbuntu (fake ssh + scp); nothing touches a real server.
"""

import gc
import threading

import pytest
from fastapi.testclient import TestClient
from phase2_fixtures import facts_output, make_metadata
from phase3_fixtures import (
    IP,
    SERVER,
    FakeUbuntu,
    analysis_plan_output,
    deb_content,
    deb_name,
    make_analysis,
    plan_entries,
    plan_uri,
)
from test_patch_execution import REMOTE, Harness, by_name

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import patch_service, server_state
from ec2patcher.services import patch_state as ps
from ec2patcher.services.apt_planner import Candidate, DownloadPlan, PlannedDeb
from ec2patcher.services.patch_service import PatchService

CVES = ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"]
OLD, NEW = "1.0-1ubuntu1", "1.0-1ubuntu2"
SAME = "2.0-1ubuntu3"  # installed == target for the four same-version rows


def sync(fn):
    fn()


def dead_starter(fn):
    """A worker thread that died without running (and so without recording) its job."""
    worker = threading.Thread(target=lambda: None)
    worker.start()
    worker.join()
    return worker


@pytest.fixture
def h(db, pem_file, tmp_path):
    return Harness(db, pem_file, tmp_path)


# --- 1. at-target packages are excluded, the rest is patched -------------------------------


def fleet_plan(real=44, same=4):
    """(package, arch, before, target, source, source version, pool, cves, dependency)."""
    rows = []
    for i in range(real):
        name = f"pkg{i:02d}"
        rows.append((name, "amd64", OLD, NEW, name, NEW, f"p/{name}", [f"CVE-2026-{1000 + i}"],
                     False))  # fmt: skip
    for i in range(same):
        name = f"same{i}"
        rows.append((name, "amd64", SAME, SAME, name, SAME, f"s/{name}", [f"CVE-2026-{2000 + i}"],
                     False))  # fmt: skip
    return rows


def fleet_findings(plan):
    return [
        cr.Finding(cves[0], src, cr.PATCH_AVAILABLE, "old", before, target, binaries=[package])
        for package, _, before, target, src, _, _, cves, _ in plan
    ]


def use_plan(h, plan):
    """Point the harness' FakeUbuntu and fetcher at ``plan`` (server state = ``before``)."""
    h.fake = FakeUbuntu(
        packages=[(p, before, src, before, a, "ii ") for p, a, before, _, src, *_ in plan]
    )
    h.fake.debs = {deb_name(p, t): (p, a, t, src, sv) for p, a, _, t, src, sv, *_ in plan}
    h.service.runner = h.fake
    h.fetcher.data = {
        plan_uri(p, t, pool): deb_content(deb_name(p, t)) for p, _, _, t, _, _, pool, *_ in plan
    }
    return h.analysis(
        plan=plan_entries(plan), finding_list=fleet_findings(plan), expected_reboot=False
    )


def test_plan_with_4_same_version_and_44_real_packages_patches_exactly_44(h):
    plan = fleet_plan()
    analysis = use_plan(h, plan)
    assert len(analysis.plan) == 48

    check = h.service.eligibility(analysis)
    assert check.allowed, check.reasons
    assert (check.packages, check.debs) == (44, 44)
    assert check.excluded_warning.startswith("4 package(s) already at target are excluded")
    assert all(f"same{i} (installed {SAME}, target {SAME})" in check.excluded_warning
               for i in range(4))  # fmt: skip

    ex = h.approve(analysis)
    assert ex.state == ps.SUCCESS and ex.error_title is None
    # Exactly the 44 real .debs were downloaded, copied, simulated and installed.
    assert h.fake.ops.count("fetch") == 44 and h.fake.ops.count("scp") == 44
    install = next(c for op, c in h.fake.calls if op == "install")
    installed_debs = h.fake._files(install)
    assert len(installed_debs) == 44 and not any(d.startswith("same") for d in installed_debs)
    pkgs = by_name(ex)
    assert len(pkgs) == 48
    for i in range(44):
        p = pkgs[f"pkg{i:02d}"]
        assert (p.install_result, p.verification_result, p.after_version) == (
            "INSTALLED", "VERIFIED", NEW,
        )  # fmt: skip
        assert h.fake.installed(f"pkg{i:02d}") == NEW
    for i in range(4):
        p = pkgs[f"same{i}"]
        assert p.install_result == patch_service.ALREADY_AT_TARGET
        assert p.download_result is None and p.transfer_result is None
        assert p.after_version == SAME and p.verification_result == "VERIFIED"
    assert any("4 package(s) already at the target version" in n for n in ex.notes)
    # Every CVE is verified on the server, the excluded packages' ones included.
    assert len(ex.cves) == 48 and all(c.result == "VERIFIED" for c in ex.cves)
    steps = {s.label: s.status for s in patch_service.progress_steps(ex)}
    assert steps["Downloaded 44/44"] == "done" and steps["Transferred 44/44"] == "done"
    assert ex.cleanup_status == "DELETED" and REMOTE not in h.fake.dirs


def test_plan_with_only_at_target_packages_is_blocked(h):
    analysis = use_plan(h, fleet_plan(real=0, same=4))
    check = h.service.eligibility(analysis)
    assert not check.allowed
    assert any("every planned package is already at" in r for r in check.reasons), check.reasons
    assert h.fake.calls == []


def test_planner_excludes_equal_and_newer_installed_versions():
    facts = server_state.parse_facts(facts_output())
    debs = [PlannedDeb(f"pkg{i:02d}", "amd64", OLD, NEW) for i in range(44)]
    debs += [PlannedDeb(f"same{i}", "amd64", SAME, SAME) for i in range(3)]
    debs.append(PlannedDeb("newer", "amd64", "3.0-2", "3.0-1"))  # installed above target
    download = DownloadPlan(ok=True, packages=debs)
    plan = cr.build_plan([], download, {}, facts)
    assert len(plan) == 44 and {e.package for e in plan} == {f"pkg{i:02d}" for i in range(44)}
    assert cr.already_at_target(download) == ["newer 3.0-1", *(f"same{i} {SAME}" for i in range(3))]
    assert cr.at_or_above_target("3.0-2", "3.0-1") and cr.at_or_above_target("1:1.0", "1:1.0")
    assert not cr.at_or_above_target("1.0", "1:0.5") and not cr.at_or_above_target(None, "1")


def test_candidate_check_excludes_installed_above_candidate_without_error():
    """openssl is installed above the candidate, libssl3t64 is not: only libssl3t64 is
    requested. If every binary is at/above the candidate the CVE needs nothing (no error)."""
    rows = [
        ("openssl", "3.0.13-0ubuntu3.7", "openssl", "3.0.13-0ubuntu3.7", "amd64", "ii "),
        ("libssl3t64:amd64", "3.0.13-0ubuntu3.4", "openssl", "3.0.13-0ubuntu3.4", "amd64", "ii "),
    ]
    facts = server_state.parse_facts(facts_output(packages=rows))
    cand = {
        "openssl": Candidate("openssl", "3.0.13-0ubuntu3.7", "3.0.13-0ubuntu3.6", "openssl"),
        "libssl3t64:amd64": Candidate(
            "libssl3t64:amd64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6", "openssl"
        ),
    }

    def finding(binaries):
        return cr.Finding("CVE-2026-63076", "openssl", cr.FIX_NOT_IN_CONFIGURED_REPOS, "old",
                          "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6", binaries=binaries)  # fmt: skip

    mixed = finding(["libssl3t64:amd64", "openssl"])
    assert cr.apply_candidates([mixed], cand, facts) == [("libssl3t64:amd64", "3.0.13-0ubuntu3.6")]
    assert mixed.status == cr.PATCH_AVAILABLE
    only_newer = finding(["openssl"])
    assert cr.apply_candidates([only_newer], cand, facts) == []
    assert only_newer.status == cr.ALREADY_FIXED and "openssl 3.0.13-0ubuntu3.7" in (
        only_newer.detail
    )


def test_revalidation_drops_package_installed_above_target(h):
    """openssl was upgraded past the target by hand: dropped as a warning, the rest is
    patched (not drift, not a failure)."""
    h.fake.packages[("openssl", "amd64")] = [
        "3.0.13-0ubuntu3.7", "openssl", "3.0.13-0ubuntu3.7", "ii ",
    ]  # fmt: skip
    ex = h.approve()
    assert ex.state == ps.SUCCESS and ex.error_title is None
    openssl = by_name(ex)["openssl"]
    assert openssl.install_result == patch_service.ALREADY_AT_TARGET
    assert openssl.after_version == "3.0.13-0ubuntu3.7" and "newer than the target" in (
        openssl.detail
    )
    assert h.fake.ops.count("scp") == 5
    assert deb_name("openssl", "3.0.13-0ubuntu3.6") not in next(
        c for op, c in h.fake.calls if op == "install"
    )
    assert any("openssl 3.0.13-0ubuntu3.7" in n for n in ex.notes)


def test_stored_at_target_row_is_excluded_not_blocking(h, db_path):
    """An older analysis stored openssl with target == installed: excluded with a warning on
    the report and confirmation pages, the other five packages are patched."""
    entries = plan_entries()
    openssl = next(e for e in entries if e.package == "openssl")
    openssl.target_version = openssl.current_version
    openssl.deb_filename = deb_name("openssl", openssl.current_version)
    openssl.uri = openssl.checksum = None  # never downloaded, so never validated
    openssl.cves = []  # its target does not carry the fix; libssl3t64 covers the CVEs
    analysis = h.analysis(plan=entries)
    check = h.service.eligibility(analysis)
    assert check.allowed, check.reasons
    assert check.packages == 5
    assert "openssl (installed 3.0.13-0ubuntu3.4" in check.excluded_warning

    app = create_app(db_path=db_path, ssh_runner=h.fake, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        url = f"/analysis/{analysis.run_id}/servers/{analysis.id}"
        for page in (c.get(url).text, c.get(f"{url}/approve").text):
            assert "excluded-warning" in page and "already at target are excluded" in page
    ex = h.approve(analysis)
    assert ex.state == ps.SUCCESS and h.fake.ops.count("scp") == 5
    assert by_name(ex)["openssl"].install_result == patch_service.ALREADY_AT_TARGET


# --- 2. "running" means a live worker -------------------------------------------------------


@pytest.fixture
def analysis_env(db, pem_file, tmp_path, fake_apt):
    fake_apt.plan = analysis_plan_output()
    db.create_server(SERVER, IP, str(pem_file))
    db.save_report("security-report.json", {SERVER: CVES}, "VALID")
    return FakeUbuntu(), make_metadata(tmp_path)


def app_client(db_path, fake, metadata, starter):
    app = create_app(
        db_path=db_path, ssh_runner=fake, metadata=metadata, analysis_starter=starter,
        patch_starter=starter, shutdown_handler=lambda: None,
    )  # fmt: skip
    return TestClient(app, base_url="http://127.0.0.1")


ANALYZE_DISABLED = "disabled>Analyze Report"


def test_app_restart_mid_analysis_leaves_buttons_enabled(analysis_env, db_path):
    fake, metadata = analysis_env
    pending = []  # the analysis is accepted, then the app stops before it finishes
    with app_client(db_path, fake, metadata, pending.append) as c:
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run_id = int(run_url.rsplit("/", 1)[1])
        server = Database(db_path).get_analysis_run(run_id).servers[0]
        Database(db_path).update_server_analysis(server.id, status="analyzing")
        page = c.get("/reports").text
        assert ANALYZE_DISABLED in page and "RUNNING" in page
        assert '<meta http-equiv="refresh"' in c.get(run_url).text
    pending.clear()  # the old process is gone, its worker with it
    del c
    gc.collect()

    with app_client(db_path, fake, metadata, sync) as c:
        reports = c.get("/reports").text
        assert ANALYZE_DISABLED not in reports and "INTERRUPTED" in reports
        page = c.get(run_url).text
        assert '<meta http-equiv="refresh"' not in page and "INTERRUPTED" in page
        assert 'id="patch-all"' in page
        report = c.get(f"{run_url}/servers/{server.id}").text
        assert f'action="{run_url}/servers/{server.id}/reanalyze"' in report
        # Analyze works again right away.
        new_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        assert new_url != run_url
    db = Database(db_path)
    assert db.get_analysis_run(run_id).status == "interrupted"
    assert db.get_analysis_run(int(new_url.rsplit("/", 1)[1])).status == "completed"


def test_dead_analysis_worker_does_not_keep_buttons_disabled(analysis_env, db_path):
    """No restart: the worker thread is gone while the run still says 'running'."""
    fake, metadata = analysis_env
    with app_client(db_path, fake, metadata, dead_starter) as c:
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        analyzer = c.app.state.analyzer
        assert analyzer._running and not analyzer.is_running  # flag set, worker dead
        reports = c.get("/reports").text
        assert ANALYZE_DISABLED not in reports and "INTERRUPTED" in reports
        assert '<meta http-equiv="refresh"' not in c.get(run_url).text
        analyzer.starter = sync
        assert c.post("/reports/analyze", follow_redirects=False).status_code == 303
    run_id = int(run_url.rsplit("/", 1)[1])
    assert Database(db_path).get_analysis_run(run_id).status == "interrupted"
    assert Database(db_path).get_latest_analysis_run().status == "completed"


def test_dead_patch_worker_does_not_lock_patching(h, db, pem_file, db_path):
    first = h.analysis()
    other = db.create_server("ip-10-0-0-215", "192.0.2.215", str(pem_file))
    second = make_analysis(db, other)
    h.service.starter = dead_starter
    execution_id = h.service.approve(first.id)
    assert db.active_execution_id() == execution_id and not h.service.is_running

    # The next eligibility check sees no live worker: the stale execution is recorded as
    # INTERRUPTED and nothing stays locked.
    check = h.service.eligibility(second)
    assert check.allowed, check.reasons
    stale = db.get_execution(execution_id)
    assert stale.state == ps.INTERRUPTED and stale.failure_stage == ps.APPROVED
    assert stale.error_title == "PATCH INTERRUPTED" and db.active_execution_id() is None
    assert stale.reboot_status == ps.REBOOT_SKIPPED
    h.service.starter = sync
    assert db.get_execution(h.service.approve(second.id)).state == ps.SUCCESS

    app = create_app(db_path=db_path, ssh_runner=h.fake, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        page = c.get(f"/patch/{execution_id}").text
    assert "PATCH INTERRUPTED" in page and '<meta http-equiv="refresh"' not in page


def test_dead_patch_all_worker_does_not_lock_patch_all(h, db, pem_file, db_path):
    run_server = h.analysis()
    h.service.starter = dead_starter
    queue_id = h.service.start_queue(run_server.run_id, [run_server.id], skip_reboot=True)
    assert db.get_patch_queue(queue_id).is_running and not h.service.is_running
    h.service.reconcile()
    queue = db.get_patch_queue(queue_id)
    assert queue.state == ps.QUEUE_STOPPED and not queue.is_running
    # The stopped queue's server was never touched; a new Patch All can start at once.
    h.service.starter = sync
    newer = h.analysis()
    assert db.get_patch_queue(h.service.start_queue(newer.run_id, [newer.id], True)).state == (
        ps.QUEUE_COMPLETED
    )


def test_live_worker_in_another_service_is_respected(h, db, pem_file):
    """Two services on one database in this process: a live worker of either keeps the lock
    (a stale check must never interrupt a running patch)."""
    started = []
    h.service.starter = started.append  # approved, worker owned by h.service
    first = h.analysis()
    execution_id = h.service.approve(first.id)
    other = PatchService(db, runner=h.fake, starter=sync, fetcher=h.fetch)
    other.reconcile()
    assert db.get_execution(execution_id).state == ps.APPROVED
    started[0]()
    assert db.get_execution(execution_id).state == ps.SUCCESS
