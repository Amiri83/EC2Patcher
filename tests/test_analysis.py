"""Phase 2 analysis: persistence, orchestration (mocked SSH / metadata) and the web UI."""

import json
import re
import sqlite3
import subprocess

import pytest
from fastapi.testclient import TestClient
from phase2_fixtures import (
    ALL_CVES,
    REAL_REPORT,
    ScriptedSSH,
    apt_operands,
    facts_output,
    failing_fetcher,
    make_metadata,
    online_fetcher,
)
from test_tags import save
from test_web import upload

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import server_state
from ec2patcher.services.analysis_service import AnalysisService, investigate_cves, summarize
from ec2patcher.services.security_metadata import SecurityMetadata

GOOD, BAD = "ip-10-0-0-245", "ip-10-0-0-215"
GOOD_IP, BAD_IP = "192.0.2.245", "192.0.2.215"
AUTH_FAILURE = {BAD_IP: (255, "ubuntu@192.0.2.215: Permission denied (publickey).")}


def sync(fn):
    fn()


@pytest.fixture
def metadata(tmp_path):
    return make_metadata(tmp_path)


@pytest.fixture
def setup(db, pem_file):
    """Two servers from the user's real report; the first has a display_name tag."""
    db.create_server(GOOD, GOOD_IP, str(pem_file), tags=[("display_name", "Billing API")])
    db.create_server(BAD, BAD_IP, str(pem_file))
    return db


def run_analysis(db, metadata, ssh, report=None):
    db.save_report("security-report.json", report or REAL_REPORT, "VALID")
    service = AnalysisService(db, metadata, runner=ssh, starter=sync)
    run_id = service.start(db.get_latest_report())
    return db.get_analysis_run(run_id)


# --- orchestration --------------------------------------------------------------------


def test_real_report_shape_end_to_end(setup, metadata):
    ssh = ScriptedSSH(failures=AUTH_FAILURE)
    run = run_analysis(setup, metadata, ssh)
    assert run.status == "completed_with_errors"
    assert (
        run.metadata_source == "Canonical Security API (online per-CVE lookup)"
        and not run.metadata_stale
    )
    good, bad = run.servers
    assert (good.server_name, good.status, good.display_name) == (GOOD, "complete", "Billing API")
    assert (good.os_codename, good.architecture, good.running_kernel) == (
        "noble",
        "amd64",
        "6.8.0-1021-aws",
    )
    assert (
        good.remote_hostname == "ip-10-0-0-245" and good.os_pretty_name == "Ubuntu 24.04.3 LTS"
    )
    assert good.current_reboot_required is False and good.expected_reboot is True
    summary = summarize(good)
    assert summary.reported == 3
    assert summary.cve_status == {
        "CVE-2026-63076": cr.PATCH_AVAILABLE,
        "CVE-2026-54874": cr.PATCH_AVAILABLE,
        "CVE-2026-63075": cr.PATCH_AVAILABLE,
    }
    assert summary.packages == 6 and summary.debs == 6 and summary.unresolved == 0
    assert summary.download_bytes == 1940000 + 1003000 + 30500000 + 14600000 + 2400 + 1700
    # One bad server does not destroy the report.
    assert bad.status == "failed" and "Permission denied (publickey)" in bad.error
    assert summarize(bad).cve_status == {"CVE-2026-63076": "NOT_ANALYZED"}


def test_ssh_is_fixed_user_argument_list_without_shell(setup, metadata, pem_file, fake_apt):
    ssh = ScriptedSSH()
    run_analysis(setup, metadata, ssh)
    assert len(ssh.calls) == 2  # only the read-only facts command, once per server
    for args in ssh.calls:
        assert args[0] == "ssh" and args[1:3] == ["-i", str(pem_file)]
        assert args[-2] in (f"ubuntu@{GOOD_IP}", f"ubuntu@{BAD_IP}")
        remote = args[-1]
        assert remote == server_state.FACTS_COMMAND
        assert "sudo" not in remote and "apt-get" not in remote and "apt-cache" not in remote
        assert "dpkg -i" not in remote and "scp" not in remote and "reboot " not in remote
    # Candidates and the plan were resolved locally instead.
    assert fake_apt.updates and any("--print-uris" in c for c in fake_apt.calls)


def test_no_install_download_or_reboot_anywhere(setup, metadata, monkeypatch):
    """Any subprocess other than the injected ssh runner would be a bug."""

    def forbidden(*args, **kwargs):
        raise AssertionError(f"unexpected subprocess: {args}")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    run = run_analysis(setup, metadata, ScriptedSSH())
    assert run.status == "completed"


def test_unreachable_server(setup, metadata):
    ssh = ScriptedSSH(
        failures={
            GOOD_IP: (255, "ssh: connect to host 192.0.2.245 port 22: Connection timed out")
        }
    )
    good = run_analysis(setup, metadata, ssh).servers[0]
    assert good.status == "failed" and "Connection timed out" in good.error


def test_ssh_timeout(setup, metadata):
    ssh = ScriptedSSH(failures={GOOD_IP: subprocess.TimeoutExpired("ssh", 90)})
    good = run_analysis(setup, metadata, ssh).servers[0]
    assert good.status == "failed" and "did not finish within 90s" in good.error


def test_missing_pem(setup, metadata, pem_file):
    pem_file.chmod(0o600)
    pem_file.unlink()
    ssh = ScriptedSSH()
    run = run_analysis(setup, metadata, ssh)
    assert all("PEM file does not exist" in s.error for s in run.servers)
    assert ssh.calls == []


def test_unsupported_ubuntu(setup, metadata):
    old = 'ID=ubuntu\nVERSION_ID="16.04"\nVERSION_CODENAME=xenial\nPRETTY_NAME="Ubuntu 16.04.7 LTS"'
    good = run_analysis(setup, metadata, ScriptedSSH(facts=facts_output(os_release=old))).servers[0]
    assert good.status == "failed" and "Unsupported Ubuntu release: 16.04" in good.error
    assert good.os_pretty_name == "Ubuntu 16.04.7 LTS"  # facts collected so far are kept


def test_malformed_remote_output(setup, metadata):
    good = run_analysis(setup, metadata, ScriptedSSH(facts="garbage\n")).servers[0]
    assert good.status == "failed" and "Malformed remote output" in good.error


def test_lookup_failure_reports_unknown_and_continues_discovery(setup, tmp_path):
    meta = SecurityMetadata(fetcher=failing_fetcher())
    ssh = ScriptedSSH()
    run = run_analysis(setup, meta, ssh)
    assert run.status == "completed"
    assert all(s.status == "complete" for s in run.servers)
    assert all(f.status == cr.METADATA_UNAVAILABLE for s in run.servers for f in s.findings)
    assert len(ssh.calls) == 2  # facts only; no candidate check or package plan


API = "https://ubuntu.com/security/cves/{}.json"


def flaky_fetcher(calls, failing):
    """online_fetcher that times out for the CVEs in ``failing`` (mutable)."""
    base = online_fetcher()

    def fetch(url):
        calls.append(url)
        if url.rsplit("/", 1)[1].removesuffix(".json") in failing:
            raise TimeoutError("timed out")
        return base(url)

    return fetch


def test_run_persists_lookup_tallies(setup, tmp_path):
    calls, failing = [], {"CVE-2026-54874"}
    meta = SecurityMetadata(setup, fetcher=flaky_fetcher(calls, failing))
    run = run_analysis(setup, meta, ScriptedSSH())
    assert run.metadata_lookups == {
        "CVE-2026-63076": "ok", "CVE-2026-54874": "failed", "CVE-2026-63075": "ok",
    }  # fmt: skip
    assert run.lookup_tally.label == "2 ok / 0 cached / 1 failed"
    assert run.lookup_tally.state == "Degraded"
    assert run.failed_lookups == ["CVE-2026-54874"]
    # One failed CVE did not trip the breaker: the other CVEs still resolved.
    assert summarize(run.servers[0]).cve_status == {
        "CVE-2026-63076": cr.PATCH_AVAILABLE,
        "CVE-2026-54874": cr.METADATA_UNAVAILABLE,
        "CVE-2026-63075": cr.PATCH_AVAILABLE,
    }


def test_retry_failed_lookups_re_runs_only_the_failed_cves(setup, tmp_path):
    calls, failing = [], {"CVE-2026-54874"}
    cache = setup  # the application database holds the Canonical cache
    run = run_analysis(
        setup, SecurityMetadata(cache, fetcher=flaky_fetcher(calls, failing)), ScriptedSSH()
    )
    assert run.failed_lookups == ["CVE-2026-54874"]

    # ubuntu.com is back. A fresh instance (as after a restart) proves the CVEs that
    # succeeded come from the SQLite cache, not from the network.
    failing.clear()
    calls.clear()
    ssh = ScriptedSSH()
    service = AnalysisService(
        setup, SecurityMetadata(cache, fetcher=flaky_fetcher(calls, failing)), runner=ssh,
        starter=sync,
    )  # fmt: skip
    assert service.retry_failed_lookups(run.id) == 1
    assert calls == [API.format("CVE-2026-54874")]  # only the failed CVE hit ubuntu.com
    assert len(ssh.calls) == 1  # only GOOD reported the failed CVE; BAD is untouched

    run = setup.get_analysis_run(run.id)
    assert run.status == "completed" and not run.is_running
    assert run.lookup_tally.label == "3 ok / 0 cached / 0 failed"
    assert run.lookup_tally.state == "Online"
    assert summarize(run.servers[0]).cve_status["CVE-2026-54874"] == cr.PATCH_AVAILABLE
    assert summarize(run.servers[1]).cve_status == {"CVE-2026-63076": cr.PATCH_AVAILABLE}
    assert service.retry_failed_lookups(run.id) == 0  # nothing left to retry


def test_retry_keeps_previous_results_when_server_is_unreachable(setup, tmp_path):
    calls, failing = [], {"CVE-2026-54874"}
    meta = SecurityMetadata(setup, fetcher=flaky_fetcher(calls, failing))
    run = run_analysis(setup, meta, ScriptedSSH())
    before = summarize(run.servers[0]).cve_status

    failing.clear()
    ssh = ScriptedSSH(failures={GOOD_IP: (255, "ssh: connect to host port 22: Connection refused")})
    service = AnalysisService(setup, meta, runner=ssh, starter=sync)
    assert service.retry_failed_lookups(run.id) == 1

    run = setup.get_analysis_run(run.id)
    good = run.servers[0]
    assert good.status == "complete" and summarize(good).cve_status == before
    assert run.failed_lookups == ["CVE-2026-54874"]  # still failed: nothing was re-resolved


def test_retry_is_refused_while_analysis_runs(setup, tmp_path):
    calls, failing = [], {"CVE-2026-54874"}
    meta = SecurityMetadata(setup, fetcher=flaky_fetcher(calls, failing))
    run = run_analysis(setup, meta, ScriptedSSH())
    service = AnalysisService(setup, meta, runner=ScriptedSSH(), starter=sync)
    service._running = True
    assert service.retry_failed_lookups(run.id) is None
    assert setup.get_analysis_run(run.id).failed_lookups == ["CVE-2026-54874"]


def spy_start_run(meta):
    """Record the start_run() arguments of ``meta``."""
    runs, original = [], meta.start_run

    def start_run(force_refresh=False, cves=None):
        runs.append((force_refresh, None if cves is None else sorted(cves)))
        original(force_refresh, cves)

    meta.start_run = start_run
    return runs


def test_retry_failed_lookups_force_refreshes_the_failed_cves(setup):
    calls, failing = [], {"CVE-2026-54874"}
    meta = SecurityMetadata(setup, fetcher=flaky_fetcher(calls, failing))
    run = run_analysis(setup, meta, ScriptedSSH())
    runs = spy_start_run(meta)
    failing.clear()
    AnalysisService(setup, meta, runner=ScriptedSSH(), starter=sync).retry_failed_lookups(run.id)
    assert runs == [(True, ["CVE-2026-54874"])]


def test_reanalyze_server_force_refreshes_all_its_cves(setup):
    calls = []
    meta = SecurityMetadata(setup, fetcher=flaky_fetcher(calls, set()))
    run = run_analysis(setup, meta, ScriptedSSH(failures=AUTH_FAILURE))
    good, bad = run.servers
    assert run.status == "completed_with_errors"

    calls.clear()
    runs = spy_start_run(meta)
    ssh = ScriptedSSH()
    service = AnalysisService(setup, meta, runner=ssh, starter=sync)
    assert service.reanalyze_server(run.id, good.id)
    assert runs == [(True, None)]
    # Memo and SQLite cache are fresh, yet every CVE of the server is fetched again.
    assert sorted(calls) == sorted(API.format(cve) for cve in REAL_REPORT[GOOD])
    assert [args[-2] for args in ssh.calls] == [f"ubuntu@{GOOD_IP}"]  # only this server

    # The failed server can be re-analyzed too (its SSH now works): the run recovers.
    assert service.reanalyze_server(run.id, bad.id)
    run = setup.get_analysis_run(run.id)
    assert [s.status for s in run.servers] == ["complete", "complete"]
    assert run.servers[1].error is None
    assert run.status == "completed" and run.progress_message is None
    assert run.lookup_tally.label == "3 ok / 0 cached / 0 failed"


def test_reanalyze_keeps_previous_results_when_server_is_unreachable(setup, metadata):
    run = run_analysis(setup, metadata, ScriptedSSH())
    good = run.servers[0]
    before = summarize(good).cve_status
    refused = ScriptedSSH(failures={GOOD_IP: (255, "ssh: connect to host port 22: refused")})
    assert AnalysisService(setup, metadata, runner=refused, starter=sync).reanalyze_server(
        run.id, good.id
    )
    good = setup.get_server_analysis(good.id)
    assert good.status == "complete" and summarize(good).cve_status == before
    assert "Re-analysis at" in good.warnings[-1] and "refused" in good.warnings[-1]


def test_reanalyze_refused_while_running_or_for_foreign_server(setup, metadata):
    run = run_analysis(setup, metadata, ScriptedSSH())
    other = run_analysis(setup, metadata, ScriptedSSH())
    service = AnalysisService(setup, metadata, runner=ScriptedSSH(), starter=sync)
    assert not service.reanalyze_server(run.id, other.servers[0].id)
    service._running = True
    assert not service.reanalyze_server(run.id, run.servers[0].id)
    assert service.retry_cves(run.id, {"CVE-2026-63076"}) is None


def test_retry_investigate_cves_force_refreshes_only_those_cves(setup):
    calls, failing = [], {"CVE-2026-54874"}
    meta = SecurityMetadata(setup, fetcher=flaky_fetcher(calls, failing))
    run = run_analysis(setup, meta, ScriptedSSH())
    good = setup.get_server_analysis(run.servers[0].id)
    cves = investigate_cves(good)
    assert cves == {"CVE-2026-54874"}  # METADATA_UNAVAILABLE -> Investigate bucket

    failing.clear()
    calls.clear()
    runs = spy_start_run(meta)
    ssh = ScriptedSSH()
    service = AnalysisService(setup, meta, runner=ssh, starter=sync)
    assert service.retry_cves(run.id, cves, {good.id}) == 1
    assert runs == [(True, ["CVE-2026-54874"])]
    assert calls == [API.format("CVE-2026-54874")]  # the other CVEs come from the cache
    assert [args[-2] for args in ssh.calls] == [f"ubuntu@{GOOD_IP}"]
    good = setup.get_server_analysis(good.id)
    assert summarize(good).cve_status["CVE-2026-54874"] == cr.PATCH_AVAILABLE
    assert investigate_cves(good) == set()


def test_plan_failure_keeps_required_updates_visible(setup, metadata, fake_apt):
    fake_apt.plan = "@@EC2P simulate\nE: Unable to correct problems\n@@EC2P simulate-rc\n100\n@@EC2P uris\n@@EC2P uris-rc\n100\n@@EC2P end\n"  # noqa: E501
    good = run_analysis(setup, metadata, ScriptedSSH()).servers[0]
    assert good.status == "complete"
    assert good.plan and all(p.status == "unresolved" and p.deb_filename is None for p in good.plan)
    assert all("Unable to resolve package download plan" in p.reason for p in good.plan)
    assert summarize(good).cve_status["CVE-2026-63076"] == cr.PATCH_AVAILABLE


def test_candidate_query_failure_marks_errors(setup, metadata, fake_apt):
    fake_apt.policy_error = "E: The package cache file is corrupted"
    good = run_analysis(setup, metadata, ScriptedSSH()).servers[0]
    statuses = {f.status for f in good.findings if f.source_package == "openssl"}
    assert statuses == {cr.ANALYSIS_ERROR}
    assert all("package cache file is corrupted" in f.detail for f in good.findings
               if f.source_package == "openssl")  # fmt: skip
    assert good.plan == []


def test_all_status_types_reconcile(setup, metadata):
    report = {GOOD: ALL_CVES + ["CVE-2026-99999"], BAD: ["CVE-2026-63076"]}
    good = run_analysis(setup, metadata, ScriptedSSH(), report=report).servers[0]
    summary = summarize(good)
    assert summary.reported == len(ALL_CVES) + 1 == sum(summary.by_status.values())
    for status in (
        cr.PATCH_AVAILABLE, cr.ALREADY_FIXED, cr.PACKAGE_NOT_INSTALLED, cr.NO_FIX_PUBLISHED,
        cr.PRO_OR_ESM_REQUIRED, cr.FIX_NOT_IN_CONFIGURED_REPOS, cr.UNKNOWN, cr.PENDING_OR_DEFERRED,
    ):  # fmt: skip
        assert summary.by_status.get(status), status


def test_candidate_below_fix_is_fix_not_in_repos_without_update_hint(setup, metadata):
    report = {GOOD: ALL_CVES, BAD: ["CVE-2026-63076"]}
    good = run_analysis(setup, metadata, ScriptedSSH(), report=report).servers[0]
    libxml2 = next(f for f in good.findings if f.source_package == "libxml2")
    assert libxml2.status == cr.FIX_NOT_IN_CONFIGURED_REPOS
    assert "apt-get update" not in libxml2.detail
    assert not any("apt-get update" in w or "sudo" in w for w in good.warnings)
    # The report shows the age of the workstation's private lists.
    assert good.apt_updated_at and good.apt_age_hours is not None and good.apt_age_hours < 1


def test_private_apt_update_failure_is_reported_not_faked(setup, metadata, fake_apt):
    fake_apt.update_error = (
        "E: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease"
    )
    good = run_analysis(setup, metadata, ScriptedSSH()).servers[0]
    assert good.status == "complete"
    openssl = [f for f in good.findings if f.source_package == "openssl"]
    assert openssl and {f.status for f in openssl} == {cr.ANALYSIS_ERROR}
    assert all("apt-get update of the private noble/amd64 APT lists failed" in f.detail
               for f in openssl)  # fmt: skip
    assert all(f.apt_candidate is None for f in good.findings) and good.plan == []
    assert any(w.startswith("Local APT resolution failed:") for w in good.warnings)
    # No candidate query ran against the missing lists; the next server reuses the failure.
    assert all(apt_operands(c)[-1] == "update" for c in fake_apt.calls)
    assert len(fake_apt.updates) == 1


def test_display_name_never_matches_report(db, pem_file, metadata):
    db.create_server("app-01", GOOD_IP, str(pem_file), tags=[("display_name", "ip-10-0-0-245")])
    db.save_report("r.json", {"app-01": ["CVE-2026-63076"]}, "VALID")
    run = run_analysis(db, metadata, ScriptedSSH(), report={"app-01": ["CVE-2026-63076"]})
    assert [s.server_name for s in run.servers] == ["app-01"]


def test_only_one_analysis_at_a_time(setup, metadata):
    pending = []
    setup.save_report("r.json", REAL_REPORT, "VALID")
    service = AnalysisService(setup, metadata, runner=ScriptedSSH(), starter=pending.append)
    first = service.start(setup.get_latest_report())
    assert first is not None and service.is_running
    assert service.start(setup.get_latest_report()) is None
    pending[0]()
    assert not service.is_running
    assert setup.get_analysis_run(first).status == "completed"


# --- persistence ----------------------------------------------------------------------


def test_results_survive_restart(setup, metadata, db_path):
    run = run_analysis(setup, metadata, ScriptedSSH())
    reopened = Database(db_path)
    again = reopened.get_analysis_run(run.id)
    good = again.servers[0]
    assert good.status == "complete" and len(good.findings) == len(run.servers[0].findings)
    libssl = next(p for p in good.plan if p.binary_package == "libssl3t64")
    assert libssl.cves == ["CVE-2026-63075", "CVE-2026-63076"]
    assert libssl.uri.endswith("/libssl3t64_3.0.13-0ubuntu3.6_amd64.deb")
    assert libssl.checksum.startswith("SHA256:") and libssl.size == 1940000
    assert good.apt_arguments[:2] == ["install", "-qq"]
    assert "libssl3t64:amd64=3.0.13-0ubuntu3.6" in good.apt_arguments


def test_new_run_does_not_overwrite_previous(setup, metadata):
    first = run_analysis(setup, metadata, ScriptedSSH())
    second = run_analysis(setup, metadata, ScriptedSSH(failures=AUTH_FAILURE))
    assert second.id != first.id
    assert setup.get_latest_analysis_run().id == second.id
    old = setup.get_analysis_run(first.id)
    assert old.status == "completed" and old.servers[1].status == "complete"
    assert [r.id for r in setup.list_analysis_runs()] == [second.id, first.id]


def test_snapshot_not_changed_by_later_edits(setup, metadata, pem_file):
    run = run_analysis(setup, metadata, ScriptedSSH())
    server = setup.get_server_by_name(GOOD)
    setup.update_server(server.id, GOOD, "10.9.9.9", str(pem_file), tags=[("display_name", "New")])
    setup.save_report("other.json", {GOOD: ["CVE-2026-10005"]}, "VALID")
    good = setup.get_analysis_run(run.id).servers[0]
    assert (good.ip_address, good.display_name) == (GOOD_IP, "Billing API")
    assert setup.get_analysis_run(run.id).report == REAL_REPORT
    # Deleting the server keeps the historical result.
    setup.delete_server(server.id)
    kept = setup.get_analysis_run(run.id).servers[0]
    assert kept.server_id is None and kept.server_name == GOOD and kept.findings


def test_analysis_run_crud(db):
    db.save_report("r.json", {"a": ["CVE-2026-1"]}, "VALID")
    run_id = db.create_analysis_run(db.get_latest_report(), [("a", None, None)])
    run = db.get_analysis_run(run_id)
    assert run.status == "running" and run.servers[0].status == "waiting"
    db.update_analysis_run(run_id, status="completed", metadata_stale=True)
    assert db.get_analysis_run(run_id).metadata_stale is True
    with pytest.raises(ValueError):
        db.update_analysis_run(run_id, report_content="x")
    with pytest.raises(ValueError):
        db.update_server_analysis(run.servers[0].id, server_name="x")
    assert db.get_analysis_run(999) is None and db.get_server_analysis(999) is None


def test_interrupted_runs_marked_on_startup(db, db_path):
    db.save_report("r.json", {"a": ["CVE-2026-1"]}, "VALID")
    run_id = db.create_analysis_run(db.get_latest_report(), [("a", None, None)])
    create_app(db_path=db_path)
    run = Database(db_path).get_analysis_run(run_id)
    assert run.status == "interrupted"
    assert run.servers[0].status == "failed" and "interrupted" in run.servers[0].error


def test_phase2_migration_keeps_existing_data(db_path):
    from ec2patcher.database import _MIGRATIONS

    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as conn:
        conn.executescript(_MIGRATIONS[1])
        conn.executescript(_MIGRATIONS[2])
        conn.execute("PRAGMA user_version = 2")
        conn.execute(
            "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
            "VALUES ('a', '10.0.0.1', '/k.pem', 'then', 'then')"
        )
    conn.close()
    db = Database(db_path)
    assert db.get_server_by_name("a") is not None
    assert db.list_analysis_runs() == []


def test_lookup_tally_migration(db_path, pem_file):
    from ec2patcher.database import _MIGRATIONS

    db_path.parent.mkdir(parents=True)
    with sqlite3.connect(db_path) as conn:
        for version in range(1, 7):
            conn.executescript(_MIGRATIONS[version])
        conn.execute("PRAGMA user_version = 6")
    conn.close()
    db = Database(db_path)
    db.create_server(GOOD, GOOD_IP, str(pem_file))
    db.save_report("r.json", {GOOD: ["CVE-2026-63076"]}, "VALID")
    server = db.get_server_by_name(GOOD)
    run_id = db.create_analysis_run(db.get_latest_report(), [(GOOD, server, None)])
    run = db.get_analysis_run(run_id)
    assert run.metadata_lookups == {}
    assert run.lookup_tally.state == "Not recorded"
    db.update_analysis_run(run_id, metadata_lookups={"CVE-2026-63076": "cached"})
    assert db.get_analysis_run(run_id).lookup_tally.label == "0 ok / 1 cached / 0 failed"


# --- web / UI -------------------------------------------------------------------------


@pytest.fixture
def web(db_path, tmp_path):
    def factory(ssh=None, fetcher=None):
        meta = SecurityMetadata(db_path, fetcher=fetcher or online_fetcher())
        app = create_app(
            db_path=db_path, ssh_runner=ssh or ScriptedSSH(failures=AUTH_FAILURE),
            metadata=meta, analysis_starter=sync, shutdown_handler=lambda: None,
        )  # fmt: skip
        return TestClient(app, base_url="http://127.0.0.1")

    return factory


def add_servers(client, pem):
    save(client, GOOD, GOOD_IP, pem, tags=[("display_name", "Billing API")])
    save(client, BAD, BAD_IP, pem)


def test_analyze_button_only_after_valid_report(web, pem_file):
    with web() as c:
        page = c.get("/reports").text
        assert "Pre-Patch Analysis" in page and "Upload a valid report to enable analysis." in page
        assert 'action="/reports/analyze"' not in page
        assert "Canonical security data is queried online per CVE" in page
        assert "Upload Report" in page and "Upload &amp; Validate" not in page
        assert ">Validate</button>" not in page
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        page = c.get("/reports").text
        assert 'action="/reports/analyze"' in page and "Analyze Report" in page


def test_upload_does_not_start_analysis_or_contact_remote_services(web, pem_file, db_path):
    ssh = ScriptedSSH()
    c = web(ssh=ssh)
    metadata = c.app.state.analyzer.metadata
    fetch = metadata.fetcher
    fetch_calls = []

    def tracked_fetch(*args):
        fetch_calls.append(args)
        return fetch(*args)

    metadata.fetcher = tracked_fetch
    add_servers(c, pem_file)
    assert upload(c, {GOOD: ["CVE-2026-63076"]}).status_code == 200
    db = Database(db_path)
    assert db.get_latest_report() is not None
    assert db.list_analysis_runs() == []
    assert fetch_calls == [] and ssh.calls == []
    assert c.post("/reports/analyze", follow_redirects=False).status_code == 303
    assert len(db.list_analysis_runs()) == 1
    assert fetch_calls and ssh.calls
    assert all(call[0].startswith("https://ubuntu.com/security/cves/CVE-") for call in fetch_calls)


@pytest.mark.parametrize("included", [(GOOD,), (GOOD, BAD)])
def test_report_subset_only_analyzes_named_inventory_servers(web, pem_file, db_path, included):
    omitted = "inventory-only"
    c = web(ssh=ScriptedSSH())
    add_servers(c, pem_file)
    save(c, omitted, "192.0.2.216", pem_file)
    report = {name: ["CVE-2026-63076"] for name in included}
    assert upload(c, report).status_code == 200
    db = Database(db_path)
    assert db.get_latest_report().servers == report
    assert db.list_analysis_runs() == []
    assert c.post("/reports/analyze", follow_redirects=False).status_code == 303
    run = db.get_latest_analysis_run()
    assert [server.server_name for server in run.servers] == list(included)
    assert db.get_server_by_name(omitted) is not None


def test_settings_cache_and_database_controls_are_independent(web, pem_file, db_path):
    c = web()
    add_servers(c, pem_file)
    assert upload(c, {GOOD: ["CVE-2026-63076"]}).status_code == 200
    db = Database(db_path)
    page = c.get("/settings").text
    assert 'action="/settings/clear-cache"' in page
    assert 'action="/settings/reset-database"' in page
    assert c.post("/settings/clear-cache", follow_redirects=True).status_code == 200
    assert db.get_latest_report() is not None and db.count_servers() == 2

    denied = c.post("/settings/reset-database", data={"confirm_text": "wrong"})
    assert denied.status_code == 400 and db.count_servers() == 2
    c.app.state.analyzer._running = True
    try:
        busy = c.post("/settings/reset-database", data={"confirm_text": "RESET"})
        assert busy.status_code == 409 and db.count_servers() == 2
    finally:
        c.app.state.analyzer._running = False
    done = c.post("/settings/reset-database", data={"confirm_text": "RESET"}, follow_redirects=True)
    assert done.status_code == 200 and "Database reset" in done.text
    assert str(db_path) in done.text
    assert db.count_servers() == 0 and db.get_latest_report() is None


def test_status_panel_tallies_and_retry_button(web, pem_file, db_path):
    calls, failing = [], {"CVE-2026-54874"}
    with web(ssh=ScriptedSSH(), fetcher=flaky_fetcher(calls, failing)) as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        page = c.get(run_url).text
        assert "Degraded per-CVE lookup" in page
        assert "2 ok / 0 cached / 1 failed" in page
        assert f'action="{run_url}/retry-lookups"' in page
        assert "Retry failed lookups (1)" in page

        failing.clear()
        calls.clear()
        r = c.post(f"{run_url}/retry-lookups", follow_redirects=True)
        assert r.status_code == 200
        assert "Retrying 1 failed Canonical lookup(s)." in r.text
        assert calls == [API.format("CVE-2026-54874")]
        assert "Online per-CVE lookup" in r.text and "3 ok / 0 cached / 0 failed" in r.text
        assert "retry-lookups" not in r.text  # nothing left to retry: no button

        r = c.post(f"{run_url}/retry-lookups", follow_redirects=True)
        assert "There are no failed Canonical lookups to retry." in r.text
        assert c.post("/analysis/999/retry-lookups").status_code == 404


def test_server_report_reanalyze_and_retry_investigate_buttons(web, pem_file, db_path):
    calls, failing = [], {"CVE-2026-54874"}
    with web(ssh=ScriptedSSH(), fetcher=flaky_fetcher(calls, failing)) as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run = Database(db_path).get_latest_analysis_run()
        good, bad = (s.id for s in run.servers)
        page = c.get(f"{run_url}/servers/{good}").text
        assert f'action="{run_url}/servers/{good}/reanalyze"' in page
        assert f'action="{run_url}/servers/{good}/retry-investigate"' in page
        assert "Retry these CVEs (1)" in page

        failing.clear()
        calls.clear()
        r = c.post(f"{run_url}/servers/{good}/retry-investigate", follow_redirects=True)
        assert r.status_code == 200
        assert "Retrying 1 CVE(s) from the Investigate bucket." in r.text
        assert calls == [API.format("CVE-2026-54874")]
        assert "retry-investigate" not in r.text  # Investigate bucket is empty now
        r = c.post(f"{run_url}/servers/{good}/retry-investigate", follow_redirects=True)
        assert "There are no CVEs in the Investigate bucket to retry." in r.text

        calls.clear()  # every CVE is cached and memoized; Re-analyze fetches them anyway
        r = c.post(f"{run_url}/servers/{good}/reanalyze", follow_redirects=True)
        assert r.status_code == 200 and "Re-analyzing this server" in r.text
        assert sorted(calls) == sorted(API.format(cve) for cve in REAL_REPORT[GOOD])

        assert c.post(f"/analysis/999/servers/{good}/reanalyze").status_code == 404
        assert c.post(f"{run_url}/servers/999/retry-investigate").status_code == 404
        c.app.state.analyzer._running = True
        try:
            assert c.post(f"{run_url}/servers/{bad}/reanalyze").status_code == 409
        finally:
            c.app.state.analyzer._running = False


def test_analyze_without_report(web):
    with web() as c:
        r = c.post("/reports/analyze")
        assert r.status_code == 400 and "Upload a valid report first." in r.text


def test_analysis_progress_and_reports(web, pem_file):
    with web() as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        r = c.post("/reports/analyze", follow_redirects=False)
        assert r.status_code == 303
        run_url = r.headers["location"]
        page = c.get(run_url).text
        assert "COMPLETED WITH ERRORS" in page
        assert "&#10003;" in page and "&#10005;" in page  # complete + failed markers
        assert "Complete" in page and "Failed" in page
        assert "Permission denied (publickey)" in page
        assert "Billing API" in page
        assert '<meta http-equiv="refresh"' not in page  # finished runs do not auto-refresh
        counters = re.findall(r'class="bucket-count[^"]*">([^<]+)</span>', page)
        assert counters == ["Action required: 3", "Investigate: 0", "No action: 0"], counters
        assert "unresolved / no fix" not in page
        assert "Reboot: <strong>YES EXPECTED</strong>" in page

        links = re.findall(r'href="(/analysis/\d+/servers/\d+)"', page)
        assert len(links) == 2
        report = c.get(links[0]).text
        # Header
        assert "Pre-Patch Report: ip-10-0-0-245" in report
        assert "<dt>Server Name</dt><dd>ip-10-0-0-245</dd>" in report
        assert "<dt>Display Name</dt><dd>Billing API</dd>" in report
        assert "<dt>Remote Hostname</dt><dd>ip-10-0-0-245</dd>" in report
        assert "<dt>Ubuntu</dt><dd>Ubuntu 24.04.3 LTS</dd>" in report
        assert "<dt>Codename</dt><dd>noble</dd>" in report
        assert "<dt>Running Kernel</dt><dd>6.8.0-1021-aws</dd>" in report
        assert "Online per-CVE lookup" in report
        assert "Final reboot requirement will be verified after installation in Phase 3." in report
        assert "YES EXPECTED" in report
        # Summary + tables
        assert (
            '<span class="summary-value">3</span><span class="summary-label">Reported CVEs</span>'
            in report
        )
        assert (
            '<span class="summary-value">6</span><span class="summary-label">.deb files required</span>'  # noqa: E501
            in report
        )
        assert "CVE Findings" in report and "Package / .deb Plan" in report
        assert "libssl3t64_3.0.13-0ubuntu3.6_amd64.deb" in report
        assert "linux-image-6.8.0-1024-aws_6.8.0-1024.26_amd64.deb" in report
        assert "Reboot expected (new kernel)" in report
        # Sources without an installed package remain visible as individual rows.
        assert "linux-gcp" in report
        assert "Package not installed" in report
        assert "Repository Candidate" in report
        # Findings are bucketed by status via the view helper; no-action rows are collapsed.
        assert re.search(r"Action required: [1-9]\d*</span>", report)
        assert '<details class="report-details bucket bucket-no_action">' in report
        assert report.index("linux-gcp") > report.index("bucket-no_action")
        assert "NOT CURRENT" not in report  # fixture APT lists are ~17h old
        assert "Repository Candidate" in report
        analysis_id = c.app.state.db.get_latest_analysis_run().servers[0].id
        for finding in c.app.state.db.get_server_analysis(analysis_id).findings:
            if finding.apt_candidate and "; " in finding.apt_candidate:
                assert finding.apt_candidate not in report
        assert "Technical details" in report and "--print-uris" in report
        assert "http://security.ubuntu.com/ubuntu/pool/main/o/openssl/" in report
        # Failed server report is explicit.
        failed = c.get(links[1]).text
        assert "ANALYSIS FAILED" in failed and "Permission denied (publickey)" in failed
        assert "Display Name" not in failed  # no display_name tag -> row hidden
        assert "CVE-2026-63076" in failed


def test_reports_survive_restart_and_history(web, pem_file):
    with web() as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        first = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        second = c.post("/reports/analyze", follow_redirects=False).headers["location"]
    assert first != second
    with web(fetcher=failing_fetcher()) as c:  # restart, offline
        page = c.get("/reports").text
        assert f'href="{first}"' in page and f'href="{second}"' in page
        assert "Latest" in page
        assert "COMPLETED WITH ERRORS" in c.get(first).text
        link = re.findall(r'href="(/analysis/\d+/servers/\d+)"', c.get(first).text)[0]
        old = c.get(link).text
        assert "historical report" in old and "libssl3t64_3.0.13-0ubuntu3.6_amd64.deb" in old


def test_running_analysis_page_auto_refreshes(web, pem_file, db_path):
    with web() as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        db = Database(db_path)
        report = db.get_latest_report()
        run_id = db.create_analysis_run(
            report, [(GOOD, db.get_server_by_name(GOOD), None), (BAD, None, None)]
        )
        first, second = db.get_analysis_run(run_id).servers
        db.update_analysis_run(run_id, progress_message="Analyzing ip-10-0-0-245 (1 of 2)")
        db.update_server_analysis(first.id, status="analyzing")
        page = c.get(f"/analysis/{run_id}").text
    assert '<meta http-equiv="refresh" content="3">' in page
    assert "RUNNING" in page and "Analyzing ip-10-0-0-245 (1 of 2)" in page
    assert "&#9679;" in page and "&#9675;" in page  # analyzing + waiting markers
    assert "Analyzing" in page and "Waiting" in page
    # An app restart turns the orphaned run into an explicit "interrupted" state.
    with web() as c:
        page = c.get(f"/analysis/{run_id}").text
    assert "INTERRUPTED" in page and "Analysis was interrupted" in page
    assert '<meta http-equiv="refresh"' not in page


def test_unknown_analysis_pages_404(web):
    with web() as c:
        assert c.get("/analysis/999").status_code == 404
        assert c.get("/analysis/1/servers/1").status_code == 404


def test_server_report_escapes_html(web, pem_file, db_path):
    with web() as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        c.post("/reports/analyze")
    db = Database(db_path)
    run = db.get_latest_analysis_run()
    db.update_server_analysis(run.servers[1].id, error="<script>alert(1)</script>")
    with web() as c:
        page = c.get(f"/analysis/{run.id}/servers/{run.servers[1].id}").text
    assert "<script>alert(1)</script>" not in page and "&lt;script&gt;" in page


def test_analyze_rejects_cross_site_post(web, pem_file, db_path):
    with web() as c:
        add_servers(c, pem_file)
        upload(c, REAL_REPORT)
        r = c.post("/reports/analyze", headers={"Origin": "http://evil.example"})
        assert r.status_code == 403
    assert Database(db_path).list_analysis_runs() == []


def test_phase1_ssh_test_still_uses_original_command(client, fake_ssh, pem_file):
    save(client, "app-prod-01", "10.10.20.15", pem_file, action="test")
    assert fake_ssh.calls[0][0][-1].startswith('echo "EC2P_HOSTNAME=$(hostname)"')


def test_report_json_snapshot_is_stored(setup, metadata, db_path):
    run = run_analysis(setup, metadata, ScriptedSSH())
    with sqlite3.connect(db_path) as conn:
        content = conn.execute(
            "SELECT report_content FROM analysis_runs WHERE id = ?", (run.id,)
        ).fetchone()[0]
    assert json.loads(content) == REAL_REPORT


def test_group_findings_collapses_not_installed_rows(setup, metadata):
    from ec2patcher.services.analysis_service import group_findings

    good = run_analysis(setup, metadata, ScriptedSSH()).servers[0]
    groups = {g.cve: g for g in group_findings(good)}
    assert list(groups) == REAL_REPORT[GOOD]  # report order
    kernel = groups["CVE-2026-54874"]
    assert kernel.status == cr.PATCH_AVAILABLE
    assert [f.source_package for f in kernel.rows] == ["linux-aws", "linux-signed-aws"]
    assert sorted(f.source_package for f in kernel.not_installed) == [
        "linux", "linux-azure", "linux-gcp",
    ]  # fmt: skip
    assert len(groups["CVE-2026-63076"].rows) == 1 and not groups["CVE-2026-63076"].not_installed


def test_starter_failure_does_not_block_future_runs(setup, metadata):
    setup.save_report("r.json", REAL_REPORT, "VALID")

    def broken(fn):
        raise RuntimeError("no threads")

    service = AnalysisService(setup, metadata, runner=ScriptedSSH(), starter=broken)
    with pytest.raises(RuntimeError):
        service.start(setup.get_latest_report())
    assert not service.is_running
    assert setup.get_latest_analysis_run().status == "failed"
