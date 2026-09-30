"""Revalidation soft-drop (packages already at target), Patch All over an older analysis run,
and scp failure handling (retry once, stderr/exit code in history, cleanup on both sides).

Every remote interaction goes to FakeUbuntu / Fleet (fake ssh + scp); nothing touches a real
server or the network.
"""

import re

import pytest
from fastapi.testclient import TestClient
from phase3_fixtures import IMAGE, MODULES, SERVER, deb_name, make_run
from test_patch_all import NAMES, QueueHarness
from test_patch_execution import OPENSSL_DEB, REMOTE, Harness, by_name

from ec2patcher.app import create_app
from ec2patcher.services import patch_service
from ec2patcher.services import patch_state as ps

OPENSSL = ("openssl", "libssl3t64")
LIBSSL_DEB = deb_name("libssl3t64", "3.0.13-0ubuntu3.6")


def sync(fn):
    fn()


@pytest.fixture
def h(db, pem_file, tmp_path):
    return Harness(db, pem_file, tmp_path)


@pytest.fixture
def q(db, pem_file, tmp_path):
    return QueueHarness(db, pem_file, tmp_path)


def page(db_path, runner, url):
    app = create_app(db_path=db_path, ssh_runner=runner, shutdown_handler=lambda: None)
    with TestClient(app, base_url="http://127.0.0.1") as client:
        return client.get(url).text


# --- 1. revalidation: packages already at the target version -----------------------------


def test_partial_plan_already_installed_is_dropped_not_drift(h):
    """openssl + libssl3t64 were patched by hand since the analysis: they are dropped from
    the plan (no download/copy/install) and the remaining four packages are patched."""
    h.fake.preinstall(OPENSSL)
    ex = h.approve()
    assert ex.state == ps.SUCCESS and ex.error_title is None
    pkgs = by_name(ex)
    for name in OPENSSL:
        p = pkgs[name]
        assert p.install_result == patch_service.ALREADY_AT_TARGET
        assert p.verification_result == "VERIFIED" and p.after_version == p.target_version
        assert p.download_result is None and p.transfer_result is None
        assert "Already installed at the target version" in p.detail
    for name in ("linux-aws", "linux-image-aws", IMAGE, MODULES):
        assert pkgs[name].install_result == "INSTALLED"
        assert pkgs[name].verification_result == "VERIFIED"
    # Only the four remaining .debs were downloaded, copied, simulated and installed.
    assert h.fake.ops.count("fetch") == 4 and h.fake.ops.count("scp") == 4
    install = next(c for op, c in h.fake.calls if op == "install")
    assert OPENSSL_DEB not in install and LIBSSL_DEB not in install
    assert deb_name(IMAGE, "6.8.0-1024.26") in install
    # The dropped packages' CVEs are still verified on the server.
    assert len(ex.cves) == 4 and all(c.result == "VERIFIED" for c in ex.cves)
    assert any("2 package(s) already at the target version" in n for n in ex.notes)
    assert ex.cleanup_status == "DELETED" and REMOTE not in h.fake.dirs
    steps = {s.label: s.status for s in patch_service.progress_steps(ex)}
    assert steps["Downloaded 4/4"] == "done" and steps["Transferred 4/4"] == "done"


def test_all_packages_already_installed_marks_already_patched(h, db_path):
    h.fake.preinstall()
    analysis = h.analysis()
    ex = h.db.get_execution(h.service.approve(analysis.id, skip_reboot=False))
    assert ex.state == ps.ALREADY_PATCHED and ex.failure_stage is None
    assert ex.error_title is None and ex.error_summary is None and ex.finished_at
    # Revalidation only: no sudo, download, staging, copy, install or reboot.
    assert h.fake.ops == ["hostname"] and h.fetcher.calls == []
    assert not (h.tmp / "staging").exists() and REMOTE not in h.fake.dirs
    assert ex.cleanup_status == "NOT_NEEDED" and ex.reboot_status == ps.REBOOT_NOT_RUN
    assert all(p.install_result == patch_service.ALREADY_AT_TARGET for p in ex.packages)
    assert all(p.verification_result == "VERIFIED" for p in ex.packages)
    assert h.db.active_execution_id() is None and not h.service.is_running
    assert patch_service.queue_failure(ex) is None
    html = page(db_path, h.fake, f"/patch/{ex.id}")
    assert "ALREADY PATCHED" in html and "result-fail" not in html
    assert "Nothing was downloaded, transferred or installed" in html


def test_all_already_installed_does_not_stop_patch_all(q):
    q.fake("srv-a").preinstall()
    queue = q.start(q.run())
    assert queue.state == ps.QUEUE_COMPLETED
    assert [i.status for i in queue.items] == [ps.ITEM_SUCCESS] * 3
    assert q.execution(queue, "srv-a").state == ps.ALREADY_PATCHED
    assert "Already patched" in q.items(queue)["srv-a"].detail
    assert q.fake("srv-a").reboots == 0 and q.fake("srv-b").reboots == 1


# --- 2. Patch All on an older analysis run ---------------------------------------------


def test_patch_all_on_stale_run_uses_latest_analysis(q, db_path):
    old = q.run()
    newer = make_run(q.db, [q.servers[1]])  # srv-b analyzed again later
    latest = newer.servers[0]
    preview = dict((a.server_name, (a, c)) for a, c in q.service.queue_preview(old))
    analysis, check = preview["srv-b"]
    assert analysis.id == latest.id and check.allowed, check.reasons
    assert check.superseded.id == old.servers[1].id
    assert patch_service.NEWER_ANALYSIS not in check.reasons

    # The confirmed ids are those of the (older) run, as with a stale confirmation page.
    queue = q.start(old, skip_reboot=True, ids=[a.id for a in old.servers])
    assert queue.state == ps.QUEUE_COMPLETED
    assert [i.status for i in queue.items] == [ps.ITEM_SUCCESS] * 3
    item = q.items(queue)["srv-b"]
    assert item.server_analysis_id == latest.id
    assert f"latest analysis #{newer.id}" in item.detail
    ex = q.execution(queue, "srv-b")
    assert ex.server_analysis_id == latest.id and ex.analysis_run_id == newer.id
    assert q.db.get_execution_for_analysis(old.servers[1].id) is None
    assert q.execution(queue, "srv-a").analysis_run_id == old.id
    assert all(q.fake(n).ops.count("install") == 1 for n in NAMES)

    link = f'href="/analysis/{newer.id}/servers/{latest.id}"'
    confirm = page(db_path, q.fleet, f"/analysis/{newer.id}/patch-all")
    assert "Patch 1 Server" not in confirm  # srv-b's latest report now has a decision
    html = page(db_path, q.fleet, f"/analysis/{old.id}/patch-all")
    skipped = html.split("patch-all-skipped")[1]
    assert link in skipped and "already recorded" in skipped


def test_patch_all_confirmation_links_latest_analysis(q, db_path):
    old = q.run()
    newer = make_run(q.db, [q.servers[1]])
    html = page(db_path, q.fleet, f"/analysis/{old.id}/patch-all")
    eligible = html.split("patch-all-eligible")[1].split("</table>")[0]
    assert "srv-b" in eligible and "Patch 3 Servers" in html
    assert f'href="/analysis/{newer.id}/servers/{newer.servers[0].id}"' in eligible
    posted = re.findall(r'name="analysis_id" value="(\d+)"', html)
    assert str(newer.servers[0].id) in posted and str(old.servers[1].id) not in posted


# --- 3. scp failure mid-copy -----------------------------------------------------------


def test_scp_fails_then_retry_succeeds(h, db_path):
    h.fake.scp_failures = 1  # the first copy dies mid-transfer, leaving a truncated file
    ex = h.approve()
    assert ex.state == ps.SUCCESS
    assert h.fake.ops.count("scp") == 7  # 6 .debs + 1 retry
    first, retry = ex.transfer_attempts[:2]
    assert first["filename"] == retry["filename"] == LIBSSL_DEB
    assert (first["attempt"], first["ok"], first["exit_code"]) == (1, False, 1)
    assert "Broken pipe" in first["stderr"] and "lost connection" in first["stderr"]
    assert (retry["attempt"], retry["ok"], retry["exit_code"]) == (2, True, 0)
    assert len(ex.transfer_attempts) == 7 and all(t["ok"] for t in ex.transfer_attempts[1:])
    # The retry overwrote the truncated copy: remote checksums verified, install ran.
    assert all(p.transfer_result == "VERIFIED" for p in ex.packages)
    assert ex.cleanup_status == "DELETED"
    html = page(db_path, h.fake, f"/patch/{ex.id}")
    section = html.split("transfer-attempts")[1].split("</table>")[0]
    assert "Broken pipe" in section and ">FAILED<" in section and ">OK<" in section


def test_scp_fails_twice_records_stderr_and_cleans_both_sides(h, db_path):
    h.fake.scp_failures = 2
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.TRANSFERRING
    assert ex.error_package == LIBSSL_DEB
    assert "after 2 attempts (scp exit 1)" in ex.error_summary
    assert h.fake.ops.count("scp") == 2  # no third attempt, no other file copied
    assert not {"stat", "simulate", "install"} & set(h.fake.ops)
    assert [(t["attempt"], t["ok"], t["exit_code"]) for t in ex.transfer_attempts] == [
        (1, False, 1),
        (2, False, 1),
    ]
    assert all("Broken pipe" in t["stderr"] for t in ex.transfer_attempts)
    # Cleanup ran on both sides although the copy failed: the truncated remote file, the
    # marker and the directory are gone, and so are the local downloads.
    assert h.fake.ops[-1] == "cleanup" and REMOTE not in h.fake.dirs
    assert not (h.tmp / "staging" / SERVER).exists()
    assert ex.cleanup_status == "DELETED" and ex.cleanup_detail is None
    assert by_name(ex)["libssl3t64"].transfer_result == "FAILED"
    html = page(db_path, h.fake, f"/patch/{ex.id}")
    assert "after 2 attempts (scp exit 1)" in html
    section = html.split("transfer-attempts")[1].split("</table>")[0]
    assert section.count(">FAILED<") == 2 and "lost connection" in section
    assert "local and remote staging deleted" in html


def test_scp_failure_cleanup_warning_is_recorded(h):
    """The remote cleanup itself fails (connection gone): recorded, never hidden."""
    h.fake.scp_failures = 2
    h.fake.cleanup_fail = True
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.cleanup_status == "WARNING"
    assert REMOTE in ex.cleanup_detail and "cleanup failed" in ex.cleanup_detail
    assert not (h.tmp / "staging" / SERVER).exists()  # local side still cleaned
