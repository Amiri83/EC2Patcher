"""Live progress: step events (schema v18), the events endpoint, cancel, the per-step timeout, the
hints on failed steps and the drawer's markup. No network, no real sleeping: a "hung" command waits
on an Event that the test releases, and a tiny injected timeout gives up on it."""

import re
import sqlite3
import subprocess
import threading
import urllib.error
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from phase2_fixtures import ScriptedSSH
from test_patch_all import QueueHarness
from test_patch_report import legacy, version_of

from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import CONNECTION_SSM
from ec2patcher.services import cache_settings, nvd, run_events, ssm_service
from ec2patcher.services import patch_state as ps
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.run_events import RunRef
from ec2patcher.services.security_metadata import SecurityMetadata

NAMES = ["ip-10-0-0-1", "ip-10-0-0-2", "ip-10-0-0-3"]
IPS = dict(zip(NAMES, ["10.0.0.1", "10.0.0.2", "10.0.0.3"], strict=True))
REPORT = {
    "ip-10-0-0-1": ["CVE-2000-0001", "CVE-2000-0002"],
    "ip-10-0-0-2": ["CVE-2000-0003"],
    "ip-10-0-0-3": ["CVE-2000-0004"],
}
TINY = 0.05  # seconds; only ever spent on a call that is hung on purpose


def sync(fn):
    fn()


def unknown_to_canonical(url):
    raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)


@pytest.fixture
def metadata(db):
    # The app's Database as the cache (like the app does) and no pacing: a fresh cache DB
    # migrates on first use, and that or a pacing sleep would overrun a TINY step timeout.
    return SecurityMetadata(db, fetcher=unknown_to_canonical, pace=0)


@pytest.fixture
def setup(db, pem_file):
    for name in NAMES:
        db.create_server(name, IPS[name], str(pem_file))
    db.save_report("list.json", REPORT, "VALID")
    return db


class Hooked:
    """A fake ssh that calls ``hook(ip)`` before answering; a hang never outlives the test."""

    def __init__(self, hook=None, **ssh):
        self.hook, self.ssh = hook, ScriptedSSH(**ssh)

    def __call__(self, args, **kwargs):
        if self.hook:
            self.hook(args[-2].split("@", 1)[1])
        return self.ssh(args, **kwargs)

    @property
    def ips(self):
        return [args[-2].split("@", 1)[1] for args in self.ssh.calls]


@pytest.fixture
def released():
    """An Event hung commands wait on; set at the end of the test so their threads exit."""
    event = threading.Event()
    yield event
    event.set()


def no_throttle_nvd(db):
    """An NVD client on the app's Database that never sleeps between requests: its pacing
    would overrun a TINY step timeout on a server that is not hung."""
    return nvd.NvdClient(db, sleep=lambda seconds: None)


def analyze(db, metadata, runner=None, **service):
    runner = runner or Hooked()
    analyzer = AnalysisService(db, metadata, runner=runner, starter=sync, **service)
    run_id = analyzer.start(db.get_latest_report())
    return db.get_analysis_run(run_id)


def events_of(db, run_id, server="any", kind=run_events.KIND_ANALYSIS):
    rows = db.list_run_events(kind, run_id, 0, 10000)
    return [r for r in rows if server == "any" or r["server"] == server]


def first_seen(rows):
    return list(dict.fromkeys(r["phase"] for r in rows))


def client_for(db_path, runner, metadata, **kwargs):
    app = create_app(
        db_path=db_path, ssh_runner=runner, metadata=metadata, analysis_starter=sync, **kwargs
    )
    return TestClient(app, base_url="http://127.0.0.1")


# --- events: order, durations, CVE progress ---------------------------------------------------


def test_phases_are_emitted_in_order_with_increasing_ids(setup, metadata):
    run = analyze(setup, metadata)
    assert run.status == "completed"
    rows = events_of(setup, run.id, NAMES[0])
    assert first_seen(rows) == [*run_events.ANALYSIS_PHASES, run_events.DONE]
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids) and len(set(ids)) == len(ids)
    every = [r["id"] for r in events_of(setup, run.id)]
    assert every == sorted(every)


def test_completed_steps_carry_their_duration(setup, metadata):
    run = analyze(setup, metadata)
    rows = events_of(setup, run.id, NAMES[0])
    for phase in run_events.ANALYSIS_PHASES:
        ended = [r for r in rows if r["phase"] == phase and r["duration_ms"] is not None]
        assert len(ended) == 1, phase
        assert ended[0]["duration_ms"] >= 0 and ended[0]["level"] == run_events.INFO


def test_cve_lookups_are_logged_n_of_m_with_their_source(setup, metadata):
    run = analyze(setup, metadata)
    messages = [r["message"] for r in events_of(setup, run.id, NAMES[0])]
    assert any(m.startswith("CVE-2000-0001 (1 of 2): ") for m in messages)
    assert any(m.startswith("CVE-2000-0002 (2 of 2): ") for m in messages)
    assert any(re.match(r"NVD CVE-2000-0002 \(2 of 2\): ", m) for m in messages)


def test_lookup_step_reports_cache_hits_misses_and_api_calls(setup, metadata):
    run = analyze(setup, metadata)
    rows = events_of(setup, run.id, NAMES[0])
    summary = next(
        r["message"]
        for r in rows
        if r["phase"] == run_events.LOOKUPS and r["duration_ms"] is not None
    )
    assert re.search(r"Canonical: \d+ cache hits, \d+ misses, \d+ API calls, \d+ failed", summary)
    assert re.search(r"NVD: \d+ cache hits, \d+ misses, \d+ API calls, \d+ failed", summary)
    # The same answers as the figures stored on the run: no second accounting.
    stored = setup.get_analysis_run(run.id).cache_stats["canonical"]
    assert stored["live"] >= 2


def test_second_lookup_of_a_cve_reads_as_a_cache_hit(setup, metadata):
    setup.save_report(
        "list.json", {NAMES[0]: ["CVE-2000-0001"], NAMES[1]: ["CVE-2000-0001"]}, "VALID"
    )
    run = analyze(setup, metadata)
    assert "CVE-2000-0001 (1 of 1): API call" in [
        r["message"] for r in events_of(setup, run.id, NAMES[0])
    ]
    assert "CVE-2000-0001 (1 of 1): cache hit" in [
        r["message"] for r in events_of(setup, run.id, NAMES[1])
    ]


def test_events_are_written_while_the_run_goes(setup, metadata):
    seen = {}

    def hook(ip):
        seen[ip] = len(setup.list_run_events(run_events.KIND_ANALYSIS, 1, 0, 10000))

    analyze(setup, metadata, Hooked(hook))
    assert 0 < seen["10.0.0.1"] < seen["10.0.0.2"] < seen["10.0.0.3"]


def test_progress_message_still_works(setup, metadata):
    messages = []
    original = setup.update_analysis_run

    def spy(run_id, **fields):
        if fields.get("progress_message"):
            messages.append(fields["progress_message"])
        original(run_id, **fields)

    setup.update_analysis_run = spy
    analyze(setup, metadata)
    assert f"Analyzing {NAMES[0]} (1 of 3)" in messages


def test_a_failing_event_write_does_not_break_the_run(setup, metadata, monkeypatch, caplog):
    def broken(*args):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(setup, "add_run_event", broken)
    run = analyze(setup, metadata)
    assert run.status == "completed"
    assert all(s.status == "complete" for s in run.servers)
    assert "Could not write a progress event" in caplog.text


def test_an_unknown_phase_is_not_written_and_does_not_raise(setup):
    assert run_events.emit(setup, RunRef("analysis", 1), "made_up", "text") is None
    assert setup.list_run_events("analysis", 1) == []


def test_ssh_step_failure_is_an_error_event_and_the_run_continues(setup, metadata):
    failure = {"10.0.0.1": (255, "ubuntu@10.0.0.1: Permission denied (publickey).")}
    run = analyze(setup, metadata, Hooked(failures=failure))
    assert run.status == "completed_with_errors"
    assert run.servers[0].status == "failed" and run.servers[1].status == "complete"
    rows = events_of(setup, run.id, NAMES[0])
    failed = [r for r in rows if r["level"] == run_events.ERROR]
    assert [r["phase"] for r in failed] == [run_events.OPEN_SSH, run_events.FAILED]
    assert "Permission denied" in failed[0]["message"] and failed[0]["duration_ms"] is not None
    assert run_events.DETECT_OS not in first_seen(rows)


# --- events endpoint --------------------------------------------------------------------------


def test_endpoint_shape(setup, db_path, metadata):
    runner = Hooked()
    with client_for(db_path, runner, metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run_id = location.rsplit("/", 1)[1]
        response = c.get(f"/runs/{run_id}/events")
    assert response.status_code == 200 and response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["run"] == run_id and data["kind"] == "analysis"
    assert data["done"] is True and data["cancelled"] is False
    assert data["cancel_requested"] is False and data["status"] == "completed"
    assert data["started_at"] and data["finished_at"] and data["now"]
    assert (data["servers_done"], data["servers_total"]) == (3, 3)
    assert (data["cves_done"], data["cves_total"]) == (4, 4)
    assert [s["name"] for s in data["servers"]] == NAMES
    assert [p["id"] for p in data["phases"]] == list(run_events.ANALYSIS_PHASES)
    assert data["next"] == data["events"][-1]["id"]
    event = data["events"][0]
    assert set(event) == {
        "id", "ts", "server", "phase", "phase_label", "message", "level", "duration_ms", "hint",
    }  # fmt: skip


def test_cve_progress_counts_the_server_being_analyzed(setup, metadata):
    observed = []

    def fetch(url):
        run = setup.get_latest_analysis_run()
        observed.append(run_events.run_view(setup, RunRef("analysis", run.id))["cves_done"])
        unknown_to_canonical(url)

    analyze(setup, SecurityMetadata(fetcher=fetch))
    assert observed == [0, 1, 2, 3]  # the second CVE of the first server counts the first


def test_after_returns_only_newer_events_without_duplicates(setup, db_path, metadata):
    with client_for(db_path, Hooked(), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run_id = location.rsplit("/", 1)[1]
        url = f"/runs/{run_id}/events"
        everything = c.get(url).json()["events"]
        assert len(everything) > 4
        collected, after = [], 0
        while True:
            page = c.get(url, params={"after": after}).json()
            if not page["events"]:
                assert page["next"] == after
                break
            collected += page["events"][:3]
            after = page["events"][:3][-1]["id"]
        assert [e["id"] for e in collected] == [e["id"] for e in everything]
        cut = everything[1]["id"]
        newer = c.get(url, params={"after": cut}).json()
        assert [e["id"] for e in newer["events"]] == [e["id"] for e in everything[2:]]
        last = everything[-1]["id"]
        assert c.get(url, params={"after": last}).json()["events"] == []
        assert c.get(url, params={"after": last}).json()["next"] == last


def test_a_long_run_is_paged(setup, db_path, metadata, monkeypatch):
    monkeypatch.setattr(run_events, "MAX_EVENTS_PER_POLL", 2)
    with client_for(db_path, Hooked(), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        url = f"/runs/{location.rsplit('/', 1)[1]}/events"
        first = c.get(url).json()
        assert len(first["events"]) == 2 and first["more"] is True
        second = c.get(url, params={"after": first["next"]}).json()
        assert second["events"][0]["id"] > first["next"]


def test_no_events_of_another_run(setup, db_path, metadata):
    with client_for(db_path, Hooked(), metadata) as c:
        a = c.post("/reports/analyze", follow_redirects=False).headers["location"].rsplit("/", 1)[1]
        b = c.post("/reports/analyze", follow_redirects=False).headers["location"].rsplit("/", 1)[1]
        assert a != b
        ids_a = {e["id"] for e in c.get(f"/runs/{a}/events").json()["events"]}
        ids_b = {e["id"] for e in c.get(f"/runs/{b}/events").json()["events"]}
        assert ids_a and ids_b and not ids_a & ids_b


def test_kinds_with_the_same_number_do_not_share_events(setup, db_path, metadata):
    with client_for(db_path, Hooked(), metadata) as c:
        run_id = int(
            c.post("/reports/analyze", follow_redirects=False).headers["location"].rsplit("/", 1)[1]
        )
        setup.add_run_event("patch", run_id, "other", "install", "secret-free", "info", None)
        messages = [e["message"] for e in c.get(f"/runs/{run_id}/events").json()["events"]]
        assert "secret-free" not in messages
        assert c.get(f"/runs/patch-{run_id}/events").status_code == 404  # no such execution


@pytest.mark.parametrize("ref", ["999", "patch-999", "queue-999", "0", "nope", "patch-x", "-1"])
def test_unknown_run_is_a_json_404(client, ref):
    response = client.get(f"/runs/{ref}/events")
    assert response.status_code == 404
    assert response.headers["content-type"] == "application/json"
    assert response.json() == {"error": "Unknown run."}


@pytest.mark.parametrize("after", ["abc", "-1", "1.5", "", "99999999999999999999"])
def test_bad_after_is_a_422(setup, db_path, metadata, after):
    with client_for(db_path, Hooked(), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        response = c.get(f"/runs/{location.rsplit('/', 1)[1]}/events", params={"after": after})
    assert response.status_code == 422 and "after" in response.json()["error"]


def test_events_are_not_readable_from_another_site(client):
    response = client.get("/runs/1/events", headers={"Sec-Fetch-Site": "cross-site"})
    assert response.status_code == 403


# --- cancel -----------------------------------------------------------------------------------


def test_cancel_stops_after_the_current_step(setup, metadata):
    def hook(ip):
        if ip == "10.0.0.2":
            setup.request_run_cancel("analysis", setup.get_latest_analysis_run().id)

    runner = Hooked(hook)
    run = analyze(setup, metadata, runner)
    assert run.status == "cancelled" and not run.is_running and run.completed_at
    first, second, third = run.servers
    assert first.status == "complete" and first.findings is not None  # results are kept
    assert second.status == "cancelled" and "cancelled" in second.error
    assert third.status == "cancelled" and "cancelled" in third.error
    assert "10.0.0.3" not in runner.ips

    rows = events_of(setup, run.id, NAMES[1])
    # The step in progress ended normally; the next one never started.
    opened = [r for r in rows if r["phase"] == run_events.OPEN_SSH]
    assert opened[-1]["duration_ms"] is not None and opened[-1]["level"] == run_events.INFO
    assert run_events.DETECT_OS not in first_seen(rows)
    assert first_seen(rows)[-1] == run_events.CANCELLED
    assert first_seen(events_of(setup, run.id, NAMES[2])) == [run_events.CANCELLED]
    assert any(
        r["phase"] == run_events.CANCELLED and "2 did not finish" in r["message"]
        for r in events_of(setup, run.id, None)
    )
    assert not setup.run_cancel_requested("analysis", run.id)  # consumed


def test_cancel_between_two_cve_lookups(setup, metadata):
    calls = []

    def fetch(url):
        calls.append(url)
        setup.request_run_cancel("analysis", setup.get_latest_analysis_run().id)
        unknown_to_canonical(url)

    run = analyze(setup, SecurityMetadata(fetcher=fetch))
    assert run.status == "cancelled" and len(calls) == 1
    assert run.servers[0].status == "cancelled"
    lookups = [r for r in events_of(setup, run.id, NAMES[0]) if r["phase"] == run_events.LOOKUPS]
    assert lookups[-1]["duration_ms"] is not None and lookups[-1]["level"] == run_events.INFO


def test_cancel_of_the_last_server_after_its_last_step_changes_nothing(setup, metadata):
    setup.save_report("list.json", {NAMES[0]: ["CVE-2000-0001"]}, "VALID")
    original = setup.save_server_results

    def after_results(*args, **fields):
        original(*args, **fields)
        setup.request_run_cancel("analysis", setup.get_latest_analysis_run().id)

    setup.save_server_results = after_results
    run = analyze(setup, metadata)
    assert run.status == "completed" and run.servers[0].status == "complete"
    assert not setup.run_cancel_requested("analysis", run.id)


def test_request_twice_is_a_no_op(setup, metadata):
    server = setup.get_server_by_name(NAMES[0])
    run_id = setup.create_analysis_run(setup.get_latest_report(), [(NAMES[0], server, None)])
    ref = RunRef("analysis", run_id)
    first = run_events.request_cancel(setup, ref)
    second = run_events.request_cancel(setup, ref)
    assert first["accepted"] is True and second["accepted"] is False
    assert "already" in second["message"]
    recorded = [r for r in events_of(setup, run_id) if r["phase"] == run_events.CANCELLED]
    assert len(recorded) == 1 and recorded[0]["server"] is None
    view = run_events.events_payload(setup, ref, 0)
    assert view["cancel_requested"] is True and view["cancelled"] is False


def test_cancel_endpoint_on_finished_and_unknown_runs(setup, db_path, metadata):
    with client_for(db_path, Hooked(), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run_id = location.rsplit("/", 1)[1]
        for _ in range(2):
            response = c.post(f"/runs/{run_id}/cancel")
            answer = response.json()
            assert response.status_code == 200 and answer["accepted"] is False
            assert answer["status"] == "completed" and "finished" in answer["message"]
        assert c.get(f"/runs/{run_id}/events").json()["cancelled"] is False
        assert c.get(location).status_code == 200
        for ref in ("999", "patch-999", "nope"):
            unknown = c.post(f"/runs/{ref}/cancel")
            assert unknown.status_code == 404 and unknown.json()["accepted"] is False


def test_cancel_endpoint_rejects_other_sites(client):
    response = client.post("/runs/1/cancel", headers={"Origin": "https://example.com"})
    assert response.status_code == 403


def test_the_request_survives_a_restart_and_the_run_ends_cancelled(setup, db_path, metadata):
    server = setup.get_server_by_name(NAMES[0])
    other = setup.get_server_by_name(NAMES[1])
    run_id = setup.create_analysis_run(
        setup.get_latest_report(), [(NAMES[0], server, None), (NAMES[1], other, None)]
    )
    assert setup.request_run_cancel("analysis", run_id)
    setup.update_server_analysis(setup.get_analysis_run(run_id).servers[0].id, status="analyzing")
    assert Database(db_path).run_cancel_requested("analysis", run_id)
    with client_for(db_path, Hooked(), metadata) as c:
        assert c.get(f"/runs/{run_id}/events").json()["cancelled"] is True
    run = Database(db_path).get_analysis_run(run_id)
    assert run.status == "cancelled"
    assert [s.status for s in run.servers] == ["failed", "cancelled"]


def test_followup_clears_an_old_request_and_keeps_results(setup, metadata):
    run = analyze(setup, metadata)
    setup.request_run_cancel("analysis", run.id)  # left over
    analyzer = AnalysisService(setup, metadata, runner=Hooked(), starter=sync)
    assert analyzer.reanalyze_server(run.id, run.servers[0].id)
    done = setup.get_analysis_run(run.id)
    assert done.status == "completed" and done.servers[0].status == "complete"
    assert not setup.run_cancel_requested("analysis", run.id)


def test_cancelled_followup_keeps_the_previous_results(setup, metadata):
    run = analyze(setup, metadata)

    def hook(ip):
        setup.request_run_cancel("analysis", run.id)

    analyzer = AnalysisService(setup, metadata, runner=Hooked(hook), starter=sync)
    assert analyzer.reanalyze_server(run.id, run.servers[0].id)
    done = setup.get_analysis_run(run.id)
    assert done.status == "completed" and done.servers[0].status == "complete"
    assert done.servers[0].error is None


def test_cancelled_run_page(setup, db_path, metadata):
    def hook(ip):
        Database(db_path).request_run_cancel("analysis", 1)

    with client_for(db_path, Hooked(hook), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        page = c.get(location).text
    assert "CANCELLED" in page and "progress-cancelled" in page and "Cancelled" in page


# --- per-step timeout -------------------------------------------------------------------------


def test_hung_ssh_step_times_out_and_the_run_moves_on(setup, metadata, released):
    def hook(ip):
        if ip == "10.0.0.1":
            released.wait(30)

    run = analyze(
        setup, metadata, Hooked(hook), step_timeout=TINY, nvd_client=no_throttle_nvd(setup)
    )
    assert run.status == "completed_with_errors" and not run.is_running
    first, second, third = run.servers
    assert first.status == "failed" and "timed out after 0.05 s" in first.error
    assert second.status == "complete" and third.status == "complete"
    rows = events_of(setup, run.id, NAMES[0])
    failed = [r for r in rows if r["phase"] == run_events.OPEN_SSH and r["level"] == "error"]
    assert len(failed) == 1
    assert "Open SSH/SCP" in failed[0]["message"] and "0.05 s" in failed[0]["message"]
    assert failed[0]["duration_ms"] is not None
    assert first_seen(rows)[-1] == run_events.FAILED
    assert first_seen(events_of(setup, run.id, NAMES[1]))[-1] == run_events.DONE


def test_hung_lookup_times_out_and_the_run_moves_on(setup, released):
    def fetch(url):
        if "CVE-2000-0002" in url:
            released.wait(30)
        unknown_to_canonical(url)

    run = analyze(
        setup,
        SecurityMetadata(setup, fetcher=fetch, pace=0),
        step_timeout=TINY,
        nvd_client=no_throttle_nvd(setup),
    )
    assert run.status == "completed_with_errors"
    assert run.servers[0].status == "failed" and "timed out" in run.servers[0].error
    assert run.servers[1].status == "complete" and run.servers[2].status == "complete"
    failed = [
        r for r in events_of(setup, run.id, NAMES[0])
        if r["phase"] == run_events.LOOKUPS and r["level"] == "error"
    ]  # fmt: skip
    assert len(failed) == 1 and "Canonical/NVD/Amazon lookups" in failed[0]["message"]


def test_hung_transport_lookup_times_out(setup, metadata, monkeypatch, released):
    analyzer = AnalysisService(
        setup,
        metadata,
        runner=Hooked(),
        starter=sync,
        step_timeout=TINY,
        nvd_client=no_throttle_nvd(setup),
    )
    original = analyzer.transports.for_server

    def hanging(server, **kwargs):
        if server.name == NAMES[0]:
            released.wait(30)
        return original(server, **kwargs)

    monkeypatch.setattr(analyzer.transports, "for_server", hanging)
    run = setup.get_analysis_run(analyzer.start(setup.get_latest_report()))
    assert run.servers[0].status == "failed" and "Resolve instance ID" in run.servers[0].error
    assert run.servers[1].status == "complete"


def test_step_timeout_caps_a_command_but_never_extends_it(setup):
    steps = run_events.Steps(setup, RunRef("analysis", 1), None, 30)
    assert steps.command_timeout(90) == 30 + run_events.TIMEOUT_GRACE_SECONDS
    assert steps.command_timeout(20) == 20
    assert run_events.Steps(setup, RunRef("analysis", 1), None, TINY).command_timeout(90) >= 1


def test_guard_passes_on_results_and_errors(setup):
    steps = run_events.Steps(setup, RunRef("analysis", 1), None, 5)
    assert steps.guard(lambda: 42) == 42
    with pytest.raises(ValueError, match="boom"):
        steps.guard(lambda: (_ for _ in ()).throw(ValueError("boom")))


def test_setting_default_bounds_and_bad_saved_value(db):
    assert cache_settings.step_timeout(db) == 300
    db.set_setting(cache_settings.STEP_TIMEOUT_SETTING, "120")
    assert cache_settings.step_timeout(db) == 120
    db.set_setting(cache_settings.STEP_TIMEOUT_SETTING, "1")
    assert cache_settings.step_timeout(db) == 300
    assert cache_settings.parse_step_timeout("10") == (10, None)
    assert cache_settings.parse_step_timeout("3600") == (3600, None)
    for bad in ("9", "3601", "abc", "", "-5", "1.5"):
        assert cache_settings.parse_step_timeout(bad)[0] is None


def test_the_saved_timeout_is_used(setup, metadata):
    setup.set_setting(cache_settings.STEP_TIMEOUT_SETTING, "120")
    analyzer = AnalysisService(setup, metadata, runner=Hooked(), starter=sync)
    assert analyzer._steps(1).timeout == 120


def test_an_unreadable_timeout_setting_does_not_break_a_run(db, monkeypatch):
    def broken(key):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(db, "get_setting", broken)
    assert cache_settings.step_timeout(db) == cache_settings.DEFAULT_STEP_TIMEOUT_SECONDS


# --- the transport steps ----------------------------------------------------------------------


def transport_events(db, transport):
    ref = RunRef("analysis", 1)
    steps = run_events.Steps(db, ref, NAMES[0], 5)
    assert run_events.resolve_transport(steps, lambda: transport) is transport
    return [
        (r["phase"], r["level"], r["message"], r["duration_ms"] is not None)
        for r in db.list_run_events("analysis", 1)
        if r["duration_ms"] is not None
    ]


def test_transport_steps_of_direct_ssh(db):
    done = transport_events(db, ssm_service.Transport("SSH (direct)"))
    assert [(p, lv) for p, lv, *_ in done] == [
        (run_events.RESOLVE_INSTANCE, "info"), (run_events.SSM_CHECK, "info"),
    ]  # fmt: skip
    assert all("Not needed" in m for _, _, m, _ in done)


def test_transport_steps_when_the_ssm_check_fails(db):
    error = "The AWS SSO session of profile my-profile has expired."
    done = transport_events(
        db, ssm_service.Transport("SSM", error=error, preflight_ms=7, preflight_failed=True)
    )
    assert done[0][:2] == (run_events.RESOLVE_INSTANCE, "info") and "Not looked up" in done[0][2]
    assert done[1][:3] == (run_events.SSM_CHECK, "error", error)


def test_transport_steps_when_the_instance_lookup_fails(db):
    error = "No EC2 instance has the private IP 10.0.0.1."
    done = transport_events(db, ssm_service.Transport("SSM", error=error, preflight_ms=7))
    assert done[0][:3] == (run_events.RESOLVE_INSTANCE, "error", error)
    assert done[1][:2] == (run_events.SSM_CHECK, "info")


def test_transport_steps_when_it_works(db):
    target = ssm_service.SsmTarget("i-0123456789abcdef0", "my-profile", "us-east-1")
    done = transport_events(db, ssm_service.Transport("SSM", target, preflight_ms=7))
    assert done[0][:3] == (run_events.RESOLVE_INSTANCE, "info", "i-0123456789abcdef0")
    assert done[1][:2] == (run_events.SSM_CHECK, "info") and "OK" in done[1][2]


def test_transport_steps_with_bad_settings(db):
    done = transport_events(db, ssm_service.Transport("SSM", error="SSH over SSM needs a profile."))
    assert [(p, lv) for p, lv, *_ in done] == [(run_events.RESOLVE_INSTANCE, "error")]


def test_ssm_resolver_reports_its_preflight(db, pem_file):
    server = db.create_server(
        NAMES[0], IPS[NAMES[0]], str(pem_file),
        transport={
            "connection_type": CONNECTION_SSM, "instance_id_override": "i-0123456789abcdef0",
            "aws_profile": "my-profile", "aws_region": "us-east-1",
        },
    )  # fmt: skip

    def refused(args, **kwargs):
        stderr = "Error loading SSO Token: Token has expired and refresh failed"
        if args[1] == "--version":
            return subprocess.CompletedProcess(args, 0, "aws-cli/2.0.0", "")
        return subprocess.CompletedProcess(args, 255, "", stderr)

    resolver = ssm_service.TransportResolver(db, refused)
    transport = resolver.for_server(db.get_server(server.id))
    assert transport.preflight_failed and transport.preflight_ms is not None
    assert "aws sso login --profile my-profile" in transport.error


def test_settings_form(client):
    page = client.get("/settings").text
    assert 'name="step_timeout"' in page and 'value="300"' in page
    saved = client.post("/settings/step-timeout", data={"step_timeout": "120"})
    assert saved.status_code == 200 and 'value="120"' in saved.text
    assert client.app.state.db.get_setting(cache_settings.STEP_TIMEOUT_SETTING) == "120"
    refused = client.post("/settings/step-timeout", data={"step_timeout": "5"})
    assert refused.status_code == 422 and "between 10 and 3600" in refused.text
    assert client.app.state.db.get_setting(cache_settings.STEP_TIMEOUT_SETTING) == "120"
    reset = client.post("/settings/step-timeout", data={"action": "reset"})
    assert reset.status_code == 200 and 'value="300"' in reset.text


# --- errors: real text, hint by cause, no secret ------------------------------------------------


def test_hint_for_expired_sso():
    message = (
        "The AWS SSO session of profile my-profile has expired: "
        "run `aws sso login --profile my-profile`."
    )
    assert "aws sso login --profile my-profile" in run_events.hint_for(message)


def test_hint_for_raw_sso_error_without_a_profile():
    hint = run_events.hint_for("Error loading SSO Token: Token has expired and refresh failed")
    assert "aws sso login --profile <profile>" in hint


def test_hint_for_ssm():
    raw = "An error occurred (TargetNotConnected) when calling the StartSession operation"
    assert "Systems Manager" in run_events.hint_for(raw)
    assert "Systems Manager" in run_events.hint_for(ssm_service.NOT_CONNECTED)
    assert "Session Manager plugin" in run_events.hint_for(ssm_service.PLUGIN_MISSING)


@pytest.mark.parametrize(
    "message",
    [
        "Permission denied (publickey). Check the PEM file matches this server.",
        "Permission denied. Check the SSH user and password of this server.",
        "Permission denied: the SSH password was rejected. Check the user and password.",
    ],
)
def test_hint_for_ssh_login(message):
    assert "SSH user" in run_events.hint_for(message)


@pytest.mark.parametrize(
    "message", ["Unsupported Ubuntu release: 16.04", "Connection refused.", "", None]
)
def test_no_hint_otherwise(message):
    assert run_events.hint_for(message) is None


def test_failed_step_reaches_the_endpoint_with_text_and_hint(setup, db_path, metadata):
    failure = {"10.0.0.1": (255, "ubuntu@10.0.0.1: Permission denied (publickey).")}
    with client_for(db_path, Hooked(failures=failure), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        events = c.get(f"/runs/{location.rsplit('/', 1)[1]}/events").json()["events"]
    failed = [e for e in events if e["level"] == "error" and e["phase"] == run_events.OPEN_SSH]
    assert "Permission denied" in failed[0]["message"]
    assert "SSH user" in failed[0]["hint"]
    assert all(e["hint"] is None for e in events if e["level"] != "error")


def test_messages_hold_no_traceback_or_secret():
    traced = 'boom Traceback (most recent call last):\n  File "x.py", line 1\nValueError: secret'
    assert run_events.clean_message(traced) == "boom"
    assert "Traceback" not in run_events.clean_message("Traceback (most recent call last):\n x")
    assert "hunter2" not in run_events.clean_message("sshpass failed: password=hunter2 rest")
    assert "hunter2" not in run_events.clean_message("SSHPASS: hunter2")
    assert "abcdef" not in run_events.clean_message("api_key=abcdef")
    assert "AKIA" not in run_events.clean_message("key AKIAABCDEFGHIJKLMNOP used")
    assert "MIIE" not in run_events.clean_message(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE\n-----END RSA PRIVATE KEY----- after"
    )
    assert "123456789012" not in run_events.clean_message(
        "denied for arn:aws:iam::123456789012:role/example"
    )


def test_harmless_auth_text_is_kept():
    text = "Permission denied (publickey,password)."
    assert run_events.clean_message(text) == text
    expired = "The token has expired"
    assert run_events.clean_message(expired) == expired


def test_long_stderr_is_trimmed_to_one_line():
    message = run_events.clean_message("line one\nline two " + "x" * 2000)
    assert "\n" not in message and len(message) == run_events.MAX_MESSAGE
    assert message.startswith("line one line two") and message.endswith("…")


def test_stored_password_stays_out_of_the_events(db, db_path, metadata):
    from ec2patcher.models import AUTH_PASSWORD
    from ec2patcher.services import secret_store

    password = "fake-Pa55word"  # a fake test value
    store = secret_store.SecretStore(db)
    server = db.create_server(NAMES[0], IPS[NAMES[0]], "", auth_method=AUTH_PASSWORD)
    store.set_server_password(server.id, password)
    db.save_report("list.json", {NAMES[0]: ["CVE-2000-0001"]}, "VALID")
    run = analyze(db, metadata, credentials=store)
    rows = events_of(db, run.id)
    assert rows and all(password not in r["message"] for r in rows)


# --- patch runs -------------------------------------------------------------------------------


@pytest.fixture
def queue(db, pem_file, tmp_path):
    return QueueHarness(db, pem_file, tmp_path)


def hooked_fleet(harness, hook):
    """The harness's fleet, calling ``hook(ip, op)`` before each ssh command."""
    fleet = harness.fleet

    def runner(args, **kwargs):
        if args[0] == "ssh":
            match = re.match(r"echo '@@EC2P (\S+)'", args[-1])
            hook(args[-2].split("@", 1)[1], match.group(1) if match else "?")
        return fleet(args, **kwargs)

    harness.service.runner = runner
    harness.service.transports.runner = runner


def test_patch_all_emits_its_steps_in_order_for_the_queue(queue):
    run = queue.run()
    q = queue.start(run, skip_reboot=True)
    assert q.state == ps.QUEUE_COMPLETED
    rows = events_of(queue.db, q.id, "srv-a", kind=run_events.KIND_QUEUE)
    expected = list(run_events.PATCH_PHASES)
    assert first_seen(rows) == [*expected, run_events.DONE]
    ids = [r["id"] for r in rows]
    assert ids == sorted(ids)
    for phase in expected:
        assert any(r["phase"] == phase and r["duration_ms"] is not None for r in rows), phase
    view = run_events.events_payload(queue.db, RunRef("queue", q.id), 0)
    assert view["done"] is True and view["cancelled"] is False
    assert (view["servers_done"], view["servers_total"]) == (3, 3)
    assert view["cves_done"] == view["cves_total"] > 0


def test_single_patch_execution_reports_under_its_own_run(queue):
    run = queue.run()
    execution_id = queue.service.approve(run.servers[0].id, skip_reboot=True)
    assert queue.db.get_execution(execution_id).state == ps.SUCCESS
    rows = events_of(queue.db, execution_id, "srv-a", kind=run_events.KIND_PATCH)
    assert first_seen(rows)[:3] == [
        run_events.RESOLVE_INSTANCE, run_events.SSM_CHECK, run_events.REVALIDATE,
    ]  # fmt: skip
    assert first_seen(rows)[-1] == run_events.DONE
    view = run_events.events_payload(queue.db, RunRef("patch", execution_id), 0)
    assert view["done"] is True and view["status"] == ps.SUCCESS
    assert (view["servers_done"], view["servers_total"]) == (1, 1)


def test_cancel_before_the_install_stops_the_execution_cleanly(queue):
    run = queue.run()
    hooked_fleet(
        queue,
        lambda ip, op: op == "simulate" and queue.db.request_run_cancel(run_events.KIND_PATCH, 1),
    )
    execution_id = queue.service.approve(run.servers[0].id, skip_reboot=False)
    assert execution_id == 1
    execution = queue.db.get_execution(execution_id)
    assert execution.state == ps.CANCELLED and execution.error_title == "PATCH CANCELLED"
    assert "install" not in queue.fake("srv-a").ops  # the simulation was the last command
    assert queue.fake("srv-a").reboots == 0
    assert execution.reboot_status == ps.REBOOT_NOT_RUN
    assert queue.db.active_execution_id() is None
    assert all(r.status != "failed" for r in queue.db.list_patch_report())
    rows = events_of(queue.db, execution_id, kind=run_events.KIND_PATCH)
    phases = first_seen([r for r in rows if r["server"] == "srv-a"])
    assert run_events.INSTALL not in phases and phases[-1] == run_events.CANCELLED
    view = run_events.events_payload(queue.db, RunRef("patch", execution_id), 0)
    assert view["cancelled"] is True and view["done"] is True
    assert not queue.db.run_cancel_requested(run_events.KIND_PATCH, execution_id)


def test_cancel_during_the_install_finishes_and_verifies_it_without_a_reboot(queue):
    run = queue.run()
    hooked_fleet(
        queue,
        lambda ip, op: op == "install" and queue.db.request_run_cancel(run_events.KIND_PATCH, 1),
    )
    execution_id = queue.service.approve(run.servers[0].id, skip_reboot=False)
    execution = queue.db.get_execution(execution_id)
    assert execution.state == ps.SUCCESS  # installed and verified, never cut short
    assert "post" in queue.fake("srv-a").ops
    assert execution.reboot_status == ps.REBOOT_NOT_RUN and "cancelled" in execution.reboot_detail
    assert queue.fake("srv-a").reboots == 0


def test_cancel_stops_the_queue_between_servers(queue):
    run = queue.run()

    def hook(ip, op):
        if ip == "10.0.0.2":
            queue.db.request_run_cancel(run_events.KIND_QUEUE, 1)

    hooked_fleet(queue, hook)
    q = queue.start(run, skip_reboot=True)
    assert q.state == ps.QUEUE_CANCELLED and not q.is_running
    a, b, c = q.items
    assert a.status == ps.ITEM_SUCCESS  # finished servers keep their results
    assert b.status == ps.ITEM_CANCELLED and c.status == ps.ITEM_CANCELLED
    assert queue.db.get_execution(a.execution_id).state == ps.SUCCESS
    assert queue.db.get_execution(b.execution_id).state == ps.CANCELLED
    assert c.execution_id is None and queue.fake("srv-c").ops == []
    assert "install" not in queue.fake("srv-b").ops
    view = run_events.events_payload(queue.db, RunRef("queue", q.id), 0)
    assert view["cancelled"] is True and view["servers_done"] == 3
    assert not queue.db.run_cancel_requested(run_events.KIND_QUEUE, q.id)


def test_timeout_before_the_install_fails_the_step_and_never_installs(queue, released):
    run = queue.run()
    queue.service.step_timeout = TINY

    def hook(ip, op):
        if ip == "10.0.0.1":
            released.wait(30)

    hooked_fleet(queue, hook)
    q = queue.start(run, skip_reboot=True)
    # Patch All keeps its rule: the queue stops at the first failed server.
    assert q.state == ps.QUEUE_STOPPED
    execution = queue.db.get_execution(q.items[0].execution_id)
    assert execution.state == ps.FAILED and "timed out after 0.05 s" in execution.error_summary
    assert "install" not in queue.fake("srv-a").ops
    rows = events_of(queue.db, q.id, "srv-a", kind=run_events.KIND_QUEUE)
    failed = [r for r in rows if r["level"] == "error"]
    assert failed[0]["phase"] == run_events.REVALIDATE and "timed out" in failed[0]["message"]


def test_step_timeout_never_shortens_the_install(queue):
    run = queue.run()
    timeouts = {}
    fleet = queue.fleet

    def runner(args, **kwargs):
        if args[0] == "ssh":
            match = re.match(r"echo '@@EC2P (\S+)'", args[-1])
            timeouts[match.group(1) if match else "?"] = kwargs["timeout"]
        return fleet(args, **kwargs)

    queue.service.runner = runner
    queue.db.set_setting(cache_settings.STEP_TIMEOUT_SETTING, "10")
    queue.service.approve(run.servers[0].id, skip_reboot=True)
    assert timeouts["sudo"] == 10 + run_events.TIMEOUT_GRACE_SECONDS
    assert timeouts["install"] == 1800


def test_patch_cancel_states_are_only_reachable_before_the_install():
    before = {ps.APPROVED, ps.REVALIDATING, ps.DOWNLOADING, ps.VERIFYING_DOWNLOADS, ps.TRANSFERRING,
              ps.VERIFYING_TRANSFER, ps.SIMULATING_INSTALL}  # fmt: skip
    assert {s for s, t in ps.ALLOWED_TRANSITIONS.items() if ps.CANCELLED in t} == before
    assert ps.CANCELLED in ps.TERMINAL and ps.CANCELLED not in ps.ACTIVE


def test_cancel_of_a_finished_patch_run_is_a_no_op(queue):
    run = queue.run()
    execution_id = queue.service.approve(run.servers[0].id, skip_reboot=True)
    answer = run_events.request_cancel(queue.db, RunRef("patch", execution_id))
    assert answer["accepted"] is False and "finished" in answer["message"]


# --- pages and static files -------------------------------------------------------------------


def test_analysis_page_has_the_panel_and_the_button(setup, db_path, metadata):
    with client_for(db_path, Hooked(), metadata) as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        page = c.get(location).text
    run_id = location.rsplit("/", 1)[1]
    assert f'data-run-progress="{run_id}"' in page and 'data-active="false"' in page
    assert f'data-events-url="/runs/{run_id}/events"' in page
    assert f'data-cancel-url="/runs/{run_id}/cancel"' in page
    assert ">Show progress</button>" in page and ">Hide</button>" in page
    assert ">Pause</button>" in page and ">Cancel</button>" in page
    assert 'role="log"' in page and 'aria-live="polite"' in page and "data-rp-badge" in page


def test_running_page_opens_the_panel_and_refreshes_only_without_javascript(
    setup, db_path, metadata
):
    def never_runs(job):
        return None  # no worker yet; the app does not know it is dead

    app = create_app(
        db_path=db_path, ssh_runner=Hooked(), metadata=metadata, analysis_starter=never_runs
    )
    with TestClient(app, base_url="http://127.0.0.1") as c:
        location = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        page = c.get(location).text
    assert 'data-active="true"' in page
    assert '<noscript><meta http-equiv="refresh" content="3"></noscript>' in page


def test_patch_pages_point_at_their_run(queue, db_path, metadata):
    run = queue.run()
    q = queue.start(run, skip_reboot=True)
    single = queue.db.get_execution(q.items[0].execution_id)
    app = create_app(db_path=db_path, metadata=metadata, analysis_starter=sync)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        assert f'data-run-progress="queue-{q.id}"' in c.get(f"/patch-all/{q.id}").text
        page = c.get(f"/patch/{single.id}").text
        assert f'data-run-progress="queue-{q.id}"' in page  # reports to its queue


def test_only_local_files_and_safe_rendering():
    root = Path(__file__).parent.parent / "src" / "ec2patcher"
    partial = (root / "templates" / "_run_progress.html").read_text()
    script = (root / "static" / "app.js").read_text()
    assert "http://" not in partial and "https://" not in partial
    assert "http://" not in script and "https://" not in script
    # Event text is only ever written with textContent; innerHTML takes our own page.
    assert re.findall(r"(\w+)\.innerHTML = ", script) == ["ssmStatus", "current"]
    assert "current.innerHTML = fresh.innerHTML" in script


# --- migration 18 -----------------------------------------------------------------------------


def test_fresh_database_has_the_tables(db_path):
    db = Database(db_path)
    assert version_of(db_path) == SCHEMA_VERSION == 20
    event_id = db.add_run_event("analysis", 1, "ip-10-0-0-1", "done", "text", "info", 5)
    row = db.list_run_events("analysis", 1)[0]
    assert (row["id"], row["server"], row["phase"]) == (event_id, "ip-10-0-0-1", "done")
    assert row["ts"] and row["duration_ms"] == 5
    with sqlite3.connect(db_path) as conn:
        indexes = [r[1] for r in conn.execute("PRAGMA index_list(run_events)")]
        columns = [r[2] for r in conn.execute("PRAGMA index_info(idx_run_events_run)")]
    conn.close()
    assert "idx_run_events_run" in indexes and columns == ["run_id", "id"]


@pytest.mark.parametrize("version", [1, 17])
def test_upgrade_keeps_data_and_adds_the_tables(db_path, version):
    legacy(db_path, version).close()
    db = Database(db_path)
    assert version_of(db_path) == SCHEMA_VERSION
    assert db.get_server_by_name("keep").ip_address == "10.0.0.1"
    assert db.get_latest_report().servers == {"keep": []}
    assert db.list_run_events("analysis", 1) == []
    assert db.request_run_cancel("analysis", 1) is True
    assert Database(db_path).run_cancel_requested("analysis", 1) is True


def test_v18_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "run_events" in _MIGRATIONS[18] and "run_cancel_requests" in _MIGRATIONS[18]
    assert all("run_events" not in _MIGRATIONS[v] for v in range(1, 18))


def test_reset_removes_events_and_requests(db):
    db.add_run_event("analysis", 1, None, "done", "text", "info", None)
    db.request_run_cancel("analysis", 1)
    db.reset()
    assert db.list_run_events("analysis", 1) == []
    assert not db.run_cancel_requested("analysis", 1)
