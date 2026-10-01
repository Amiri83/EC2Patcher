"""Patch All (sequential queue over one analysis run) and the post-patch reboot step.

Every server is a FakeUbuntu behind one ssh/scp runner (Fleet); the reboot wait uses a fake
clock, so the 10 minute SSH timeout is exercised without really waiting.
"""

import re

import pytest
from fastapi.testclient import TestClient
from phase3_fixtures import (
    IMAGE,
    FakeClock,
    FakeFetcher,
    Fleet,
    findings,
    make_analysis,
    make_run,
    plan_entries,
)

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import patch_service
from ec2patcher.services import patch_state as ps
from ec2patcher.services.patch_service import PatchNotAllowedError, PatchService

NAMES = ["srv-a", "srv-b", "srv-c"]
IPS = {"srv-a": "10.0.0.1", "srv-b": "10.0.0.2", "srv-c": "10.0.0.3"}


def sync(fn):
    fn()


def userland_only():
    """A plan without the kernel: /run/reboot-required is not created by the install."""
    plan = [e for e in plan_entries() if e.package in ("openssl", "libssl3t64")]
    return {
        "plan": plan,
        "finding_list": [f for f in findings() if not f.is_kernel],
        "expected_reboot": False,
    }


def metadata_unavailable():
    finding = cr.Finding("CVE-2026-7", None, cr.METADATA_UNAVAILABLE, "Canonical unreachable")
    return {"finding_list": [*findings(), finding]}


def unresolved_plan():
    entries = plan_entries()
    entries[1].status, entries[1].deb_filename = "unresolved", None
    return {"plan": entries}


class QueueHarness:
    def __init__(self, db, pem, tmp_path):
        self.db = db
        self.servers = [db.create_server(n, IPS[n], str(pem)) for n in NAMES]
        self.fleet = Fleet(IPS.values())
        self.fetcher = FakeFetcher()
        self.clock = FakeClock()
        db.set_setting(patch_service.STAGING_SETTING, f"{tmp_path}/staging/${{server_name}}")
        self.service = PatchService(
            db, runner=self.fleet, starter=sync, fetcher=self.fetcher,
            sleep=self.clock.sleep, clock=self.clock,
        )  # fmt: skip

    def fake(self, name):
        return self.fleet[IPS[name]]

    def run(self, overrides=None):
        return make_run(self.db, self.servers, overrides)

    def start(self, run, skip_reboot=False, ids=None):
        ids = [a.id for a in run.servers] if ids is None else ids
        return self.db.get_patch_queue(self.service.start_queue(run.id, ids, skip_reboot))

    def items(self, queue):
        return {i.server_name: i for i in queue.items}

    def execution(self, queue, name):
        return self.db.get_execution(self.items(queue)[name].execution_id)


@pytest.fixture
def q(db, pem_file, tmp_path):
    return QueueHarness(db, pem_file, tmp_path)


# --- queue order ----------------------------------------------------------------------


def test_queue_order_is_run_order_one_server_at_a_time(q):
    run = q.run()
    # The confirmed ids arrive in any order; the queue follows the analysis run order.
    queue = q.start(run, skip_reboot=True, ids=[a.id for a in reversed(run.servers)])
    assert queue.state == ps.QUEUE_COMPLETED and queue.stop_reason is None
    assert [i.server_name for i in queue.items] == NAMES
    assert [i.status for i in queue.items] == [ps.ITEM_SUCCESS] * 3
    assert q.fleet.ips_in_order() == [IPS[n] for n in NAMES]
    # Strictly sequential: each server's whole pipeline finishes before the next one starts.
    per_server = [ip for ip, _ in q.fleet.log]
    assert per_server == sorted(per_server, key=list(IPS.values()).index)
    execution_ids = [i.execution_id for i in queue.items]
    assert execution_ids == sorted(execution_ids)
    for name in NAMES:
        ex = q.execution(queue, name)
        assert ex.state == ps.SUCCESS and ex.queue_id == queue.id
        # Same per-server pipeline: approve -> revalidate -> ... -> verify -> cleanup.
        ops = q.fake(name).ops
        assert ops[:2] == ["hostname", "sudo"]
        assert ops[-5:] == ["sudo", "simulate", "install", "post", "cleanup"]
    assert not q.service.is_running and q.db.active_execution_id() is None


def test_ineligible_servers_are_skipped_not_patched(q):
    run = q.run({"srv-a": metadata_unavailable(), "srv-c": unresolved_plan()})
    queue = q.start(run)
    items = q.items(queue)
    assert queue.state == ps.QUEUE_COMPLETED
    assert items["srv-a"].status == ps.ITEM_SKIPPED and items["srv-a"].execution_id is None
    assert "Canonical metadata unavailable" in items["srv-a"].detail
    assert items["srv-c"].status == ps.ITEM_SKIPPED
    assert "package download plan is unresolved" in items["srv-c"].detail
    assert items["srv-b"].status == ps.ITEM_SUCCESS
    assert q.fake("srv-a").calls == [] and q.fake("srv-c").calls == []
    assert [e.server_name for e in q.db.list_executions()] == ["srv-b"]


def test_queue_refused_when_nothing_is_eligible(q):
    run = q.run({n: metadata_unavailable() for n in NAMES})
    with pytest.raises(PatchNotAllowedError, match="No eligible servers"):
        q.start(run)
    assert q.fleet.log == [] and not q.service.is_running


def test_other_patch_blocked_while_queue_runs(q):
    q.service.starter = lambda fn: None  # queue recorded, not started
    run = q.run()
    queue = q.start(run)
    assert q.service.is_running and queue.is_running
    with pytest.raises(PatchNotAllowedError, match="Another patch execution is running"):
        q.service.approve(run.servers[0].id)
    with pytest.raises(PatchNotAllowedError, match="Another patch execution is running"):
        q.start(run)


# --- stop on failure --------------------------------------------------------------------


def test_queue_stops_on_first_failure(q):
    q.fake("srv-b").install_mode = "fail"
    queue = q.start(q.run(), skip_reboot=True)
    items = q.items(queue)
    assert queue.state == ps.QUEUE_STOPPED
    assert [i.status for i in queue.items] == [ps.ITEM_SUCCESS, ps.ITEM_FAILED, ps.ITEM_NOT_RUN]
    assert "srv-b" in queue.stop_reason and "apt-get install failed" in queue.stop_reason
    assert items["srv-c"].execution_id is None and "after srv-b failed" in items["srv-c"].detail
    assert q.fake("srv-c").calls == []  # never contacted
    assert q.execution(queue, "srv-b").state == ps.FAILED
    assert not q.service.is_running


def test_revalidation_abort_stops_queue_before_anything_is_installed(q):
    q.fake("srv-a").packages[("openssl", "amd64")][0] = "3.0.13-0ubuntu3.5"  # drift
    queue = q.start(q.run())
    assert [i.status for i in queue.items] == [ps.ITEM_FAILED, ps.ITEM_NOT_RUN, ps.ITEM_NOT_RUN]
    assert patch_service.SERVER_CHANGED in queue.stop_reason
    assert "install" not in q.fake("srv-a").ops
    assert q.execution(queue, "srv-a").reboot_status == ps.REBOOT_NOT_RUN


def test_cleanup_warning_does_not_stop_queue(q):
    q.fake("srv-a").cleanup_fail = True
    queue = q.start(q.run(), skip_reboot=True)
    assert queue.state == ps.QUEUE_COMPLETED
    assert q.execution(queue, "srv-a").state == ps.SUCCESS_WITH_CLEANUP_WARNING


# --- reboot -----------------------------------------------------------------------------


def test_skip_reboot_never_reboots(q):
    queue = q.start(q.run(), skip_reboot=True)
    assert queue.skip_reboot and queue.state == ps.QUEUE_COMPLETED
    for name in NAMES:
        fake = q.fake(name)
        assert fake.reboot_required  # the kernel update requested one ...
        assert not {"reboot-check", "reboot-now", "boot-state"} & set(fake.ops)  # ... skipped
        ex = q.execution(queue, name)
        assert ex.skip_reboot is True and ex.reboot_status == ps.REBOOT_SKIPPED
        assert "pending reboot" in ex.reboot_detail and ex.reboot_requested_at is None
    assert q.clock.sleeps == []


def test_reboot_only_when_reboot_required_exists(q):
    queue = q.start(q.run({"srv-b": userland_only()}), skip_reboot=False)
    assert queue.state == ps.QUEUE_COMPLETED
    # srv-a / srv-c installed a kernel: /run/reboot-required exists -> rebooted.
    for name in ("srv-a", "srv-c"):
        fake, ex = q.fake(name), q.execution(queue, name)
        # Reboot after verify + cleanup; the first 2 polls fail while the server restarts.
        assert fake.ops[-8:] == [
            "install", "post", "cleanup", "reboot-check", "reboot-now",
            "boot-state", "boot-state", "boot-state",
        ]  # fmt: skip
        assert fake.reboots == 1 and not fake.reboot_required
        assert ex.state == ps.SUCCESS and ex.reboot_status == ps.REBOOT_DONE
        assert ex.post_reboot_uptime == "up 1 minute" and ex.post_reboot_kernel == "6.8.0-1024-aws"
        assert ex.reboot_requested_at and ex.reboot_finished_at
    # srv-b: only a read-only check; no /run/reboot-required -> no reboot.
    fake, ex = q.fake("srv-b"), q.execution(queue, "srv-b")
    assert fake.ops[-2:] == ["cleanup", "reboot-check"] and fake.reboots == 0
    assert ex.reboot_status == ps.REBOOT_NOT_REQUIRED and ex.post_reboot_kernel is None
    reboot = next(c for op, c in q.fake("srv-a").calls if op == "reboot-now")
    assert "sudo -n reboot" in reboot


def test_reboot_check_reads_server_now_not_post_install_snapshot(q):
    """The decision is made on the server after cleanup: a flag cleared meanwhile means no
    reboot, even though the post-install check had seen it."""
    run = q.run()
    fake = q.fake("srv-a")
    original = fake._op_cleanup

    def cleanup_then_clear(args, command):
        fake.reboot_required = False
        return original(args, command)

    fake._op_cleanup = cleanup_then_clear
    queue = q.start(run, ids=[run.servers[0].id])
    ex = q.execution(queue, "srv-a")
    assert ex.reboot_required_after is True and ex.reboot_status == ps.REBOOT_NOT_REQUIRED
    assert fake.reboots == 0


def test_reboot_ssh_return_timeout_fails_and_stops_queue(q):
    q.fake("srv-a").reboot_mode = "never-returns"
    queue = q.start(q.run())
    ex = q.execution(queue, "srv-a")
    assert ex.state == ps.SUCCESS  # the patch itself was verified
    assert ex.reboot_status == ps.REBOOT_FAILED
    assert "did not come back within 10 minutes" in ex.reboot_detail
    # Waited the full 10 minutes (fake time), polling every 10 s, and not longer.
    assert q.clock.now == patch_service.REBOOT_TIMEOUT_SECONDS
    assert set(q.clock.sleeps) == {patch_service.REBOOT_POLL_SECONDS}
    assert q.fake("srv-a").ops.count("boot-state") == len(q.clock.sleeps) - 1
    assert [i.status for i in queue.items] == [ps.ITEM_FAILED, ps.ITEM_NOT_RUN, ps.ITEM_NOT_RUN]
    assert "REBOOT FAILED" in queue.stop_reason
    assert q.fake("srv-b").calls == []


def test_reboot_returning_just_before_timeout_is_done(q):
    fake = q.fake("srv-a")
    fake.down_polls = 58  # SSH answers on the 59th poll, at 590 s
    run = q.run()
    queue = q.start(run, ids=[run.servers[0].id])
    ex = q.execution(queue, "srv-a")
    assert ex.reboot_status == ps.REBOOT_DONE and q.clock.now == 590
    assert queue.state == ps.QUEUE_COMPLETED


def test_reboot_that_never_happens_fails(q):
    q.fake("srv-a").reboot_mode = "ignored"  # SSH keeps answering with the old boot id
    run = q.run()
    queue = q.start(run, ids=[run.servers[0].id])
    ex = q.execution(queue, "srv-a")
    assert ex.reboot_status == ps.REBOOT_FAILED and "same boot" in ex.reboot_detail
    assert queue.state == ps.QUEUE_STOPPED


def test_refused_sudo_reboot_fails_without_waiting(q):
    q.fake("srv-a").reboot_mode = "refused"
    run = q.run()
    queue = q.start(run, ids=[run.servers[0].id])
    ex = q.execution(queue, "srv-a")
    assert ex.reboot_status == ps.REBOOT_FAILED
    assert "sudo reboot failed (exit 1)" in ex.reboot_detail
    assert "boot-state" not in q.fake("srv-a").ops and q.clock.sleeps == []


def test_failed_patch_never_reboots(q):
    q.fake("srv-a").install_mode = "fail"
    run = q.run()
    queue = q.start(run, ids=[run.servers[0].id])
    ex = q.execution(queue, "srv-a")
    assert ex.state == ps.FAILED and ex.reboot_status == ps.REBOOT_NOT_RUN
    assert "reboot-check" not in q.fake("srv-a").ops


def test_single_server_approve_reboots_unless_skipped(q):
    fake = q.fake("srv-a")
    rebooted = q.db.get_execution(
        q.service.approve(make_analysis(q.db, q.servers[0]).id, skip_reboot=False)
    )
    assert rebooted.reboot_status == ps.REBOOT_DONE and fake.reboots == 1
    assert rebooted.queue_id is None
    # Default (programmatic) approval never reboots.
    skipped = q.db.get_execution(q.service.approve(make_analysis(q.db, q.servers[1]).id))
    assert skipped.reboot_status == ps.REBOOT_SKIPPED and q.fake("srv-b").reboots == 0


# --- history / restart ------------------------------------------------------------------


def test_reboot_status_recorded_in_history(q, db_path):
    q.fake("srv-c").reboot_mode = "never-returns"
    queue = q.start(q.run({"srv-b": userland_only()}))
    history = {e.server_name: e for e in Database(db_path).list_executions()}
    assert history["srv-a"].reboot_status == ps.REBOOT_DONE
    assert history["srv-b"].reboot_status == ps.REBOOT_NOT_REQUIRED
    assert history["srv-c"].reboot_status == ps.REBOOT_FAILED
    assert queue.state == ps.QUEUE_STOPPED
    reopened = Database(db_path).get_patch_queue(queue.id)
    assert [i.status for i in reopened.items] == [ps.ITEM_SUCCESS, ps.ITEM_SUCCESS, ps.ITEM_FAILED]


def test_interrupted_reboot_and_queue_on_startup(q, db_path):
    q.service.starter = lambda fn: None
    run = q.run()
    queue = q.start(run)
    first = queue.items[0]
    execution_id = q.db.create_patch_decision(
        run.servers[0], ps.APPROVED, skip_reboot=False, queue_id=queue.id
    )
    with q.db.connect() as conn:
        conn.execute(
            "UPDATE patch_executions SET state = ?, reboot_status = ? WHERE id = ?",
            (ps.SUCCESS, ps.REBOOT_REQUESTED, execution_id),
        )
    q.db.update_queue_item(first.id, status=ps.ITEM_RUNNING, execution_id=execution_id)
    assert q.db.active_execution_id() == execution_id  # rebooting still counts as active
    reopened = Database(db_path)
    assert reopened.mark_interrupted_executions() == 1
    assert reopened.mark_interrupted_queues() == 1
    ex = reopened.get_execution(execution_id)
    assert ex.state == ps.SUCCESS and ex.reboot_status == ps.REBOOT_FAILED
    assert reopened.active_execution_id() is None
    stopped = reopened.get_patch_queue(queue.id)
    assert stopped.state == ps.QUEUE_STOPPED
    assert [i.status for i in stopped.items] == [ps.ITEM_FAILED, ps.ITEM_NOT_RUN, ps.ITEM_NOT_RUN]


# --- web UI -------------------------------------------------------------------------------


@pytest.fixture
def web(q, db_path):
    app = create_app(
        db_path=db_path, ssh_runner=q.fleet, patch_starter=sync, patch_fetcher=q.fetcher,
        shutdown_handler=lambda: None,
    )  # fmt: skip
    app.state.patcher.sleep, app.state.patcher.clock = q.clock.sleep, q.clock
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client


def test_web_patch_all_flow(q, web):
    q.fake("srv-b").install_mode = "fail"
    run = q.run({"srv-a": metadata_unavailable()})  # srv-a: SKIPPED
    page = web.get(f"/analysis/{run.id}").text
    assert "Patch All" in page and f'action="/analysis/{run.id}/patch-all"' in page
    assert '<input type="checkbox" name="skip_reboot" value="1"> Skip reboot' in page  # unchecked

    confirm = web.get(f"/analysis/{run.id}/patch-all").text
    eligible = confirm.split("patch-all-eligible")[1].split("</table>")[0]
    skipped = confirm.split("patch-all-skipped")[1].split("</table>")[0]
    assert "srv-b" in eligible and "srv-c" in eligible and "srv-a" not in eligible
    assert "srv-a" in skipped and "SKIPPED" in skipped and "metadata unavailable" in skipped
    assert "Patch 2 Servers" in confirm and "The queue stops at the first failure" in confirm
    assert q.fleet.log == []  # the confirmation page does nothing

    # Without the confirmation field nothing happens.
    r = web.post(f"/analysis/{run.id}/patch-all", follow_redirects=False)
    assert r.status_code == 303 and q.fleet.log == []

    ids = re.findall(r'name="analysis_id" value="(\d+)"', confirm)
    r = web.post(
        f"/analysis/{run.id}/patch-all", data={"confirm": "yes", "analysis_id": ids},
        follow_redirects=False,
    )  # fmt: skip
    assert r.status_code == 303 and r.headers["location"].startswith("/patch-all/")
    result = web.get(r.headers["location"]).text
    assert "PATCH ALL STOPPED" in result and '<meta http-equiv="refresh"' not in result
    assert "Not run (1):</strong> srv-c" in result
    rows = {
        re.search(r"<strong>([\w-]+)</strong>", row).group(1): row
        for row in result.split("patch-all-items")[1].split("<tr")
        if "<strong>" in row
    }
    assert list(rows) == ["srv-a", "srv-b", "srv-c"]
    for name, status in (("srv-a", "SKIPPED"), ("srv-b", "FAILED"), ("srv-c", "NOT_RUN")):
        assert f">{status}</span>" in rows[name], rows[name]
    assert q.fake("srv-c").calls == [] and q.fake("srv-a").calls == []
    assert "Last Patch All Run" in web.get(f"/analysis/{run.id}").text


def test_web_patch_all_skip_reboot_checkbox(q, web):
    run = q.run()
    confirm = web.get(f"/analysis/{run.id}/patch-all?skip_reboot=1").text
    assert 'name="skip_reboot" value="1" checked> Skip reboot' in confirm
    ids = [str(a.id) for a in run.servers]
    r = web.post(
        f"/analysis/{run.id}/patch-all",
        data={"confirm": "yes", "analysis_id": ids, "skip_reboot": "1"},
    )
    assert "PATCH ALL COMPLETED" in r.text and "Skipped (Skip reboot was checked)" in r.text
    assert all(q.fake(n).reboots == 0 for n in NAMES)
    history = web.get("/history").text
    assert history.count("Skipped (operator choice)") == 3


def test_web_patch_all_reboots_by_default(q, web):
    run = q.run()
    ids = [str(a.id) for a in run.servers]
    r = web.post(f"/analysis/{run.id}/patch-all", data={"confirm": "yes", "analysis_id": ids})
    assert "PATCH ALL COMPLETED" in r.text and r.text.count(">Rebooted<") == 3
    assert all(q.fake(n).reboots == 1 for n in NAMES)
    detail = web.get(f"/patch/{q.db.list_executions()[0].id}").text
    assert "Rebooted" in detail and "up 1 minute" in detail and "6.8.0-1024-aws" in detail


def test_web_single_server_skip_reboot(q, web):
    analysis = make_analysis(q.db, q.servers[0])
    url = f"/analysis/{analysis.run_id}/servers/{analysis.id}/approve"
    r = web.post(url, data={"confirm": "yes", "skip_reboot": "1"})
    assert "PATCH SUCCESSFUL" in r.text and "Skipped (operator choice)" in r.text
    assert "schedule a reboot yourself" in r.text and q.fake("srv-a").reboots == 0
    assert IMAGE in r.text


def test_web_patch_all_refused_while_patch_running(q, web):
    run = q.run()
    web.app.state.patcher.starter = lambda fn: None  # approved, not yet started
    web.app.state.patcher.approve(run.servers[0].id)
    r = web.get(f"/analysis/{run.id}/patch-all")
    assert r.status_code == 409 and "Another patch execution is running" in r.text
    ids = [str(a.id) for a in run.servers]
    r = web.post(f"/analysis/{run.id}/patch-all", data={"confirm": "yes", "analysis_id": ids})
    assert r.status_code == 409 and "Patch All was not started" in r.text


def test_web_patch_all_button_hidden_when_nothing_eligible(q, web):
    run = q.run({n: metadata_unavailable() for n in NAMES})
    page = web.get(f"/analysis/{run.id}").text
    assert 'id="patch-all"' in page and "Nothing to patch" in page
    assert f'action="/analysis/{run.id}/patch-all"' not in page
    assert 'name="skip_reboot"' not in page and ">Patch All</button>" not in page
    assert q.fleet.log == [] and q.db.list_executions() == []  # the preview is read-only
    assert q.db.latest_queue_id(run.id) is None


def test_web_patch_all_button_shown_when_one_eligible(q, web):
    run = q.run({"srv-a": metadata_unavailable(), "srv-c": unresolved_plan()})  # srv-b only
    page = web.get(f"/analysis/{run.id}").text
    assert f'action="/analysis/{run.id}/patch-all"' in page and ">Patch All</button>" in page
    assert '<input type="checkbox" name="skip_reboot" value="1"> Skip reboot' in page
    assert "Nothing to patch" not in page
    assert q.fleet.log == [] and q.db.list_executions() == []


def test_unknown_queue_and_run_404(web):
    assert web.get("/patch-all/999").status_code == 404
    assert web.get("/analysis/999/patch-all").status_code == 404
