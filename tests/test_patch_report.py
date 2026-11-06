"""Paste import flow, patch report table (migration 17, flows, filters, summary) and its export."""

import io
import json
import sqlite3
from datetime import datetime

import pytest
from openpyxl import load_workbook
from phase2_fixtures import ScriptedSSH, make_metadata
from phase3_fixtures import FakeFetcher, FakeUbuntu, findings, make_analysis

from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import PatchReportRow
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import excel_export, patch_report, patch_service
from ec2patcher.services import patch_state as ps
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.patch_service import PatchService
from ec2patcher.services.security_list import match_servers, parse_security_list

C1, C2, C3 = "CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"
HOST = "ip-10-0-0-1"
FQDN = "ip-10-0-0-1.us-east-1.compute.internal"
USN1, USN2 = "USN-0000-1", "USN-0000-2"
TITLE = f"Ubuntu Security Notification for example-package Vulnerabilities ({USN1})"
OTHER = f"Ubuntu Security Notification for other-package Vulnerabilities ({USN2})"
PASTE = (
    f"| {C1}, {C2} | {FQDN} | 1 | {TITLE} |\n"
    f"| {C3} | ip-10-0-0-2 | 2 | {OTHER} |\n"
    f"| {C1} | ip-10-0-0-9 | 3 | {TITLE} |\n"
)


def sync(fn):
    fn()


@pytest.fixture
def saved(client, db_path, pem_file):
    """Two servers: one matched by name, one by private IP; ip-10-0-0-9 stays unknown."""
    db = Database(db_path)
    db.create_server(HOST, "10.0.0.1", str(pem_file), tags=[("env", "test"), ("owner", "team-a")])
    db.create_server("app-02", "10.0.0.2", str(pem_file))
    return db


def rows_of(db, **filters):
    return {(r.server_name, r.cve): r for r in db.list_patch_report(**filters)}


def seed(db, server, cve, **fields):
    row = PatchReportRow(server, cve, **fields)
    db.merge_patch_report(server, lambda current: [row])


# --- preview ------------------------------------------------------------------------------


def test_import_page_is_linked_from_reports(client):
    assert 'href="/reports/import"' in client.get("/reports").text
    assert "<textarea" in client.get("/reports/import").text


def test_preview_shows_matches_and_stores_nothing(client, saved):
    response = client.post("/reports/import", data={"raw_text": PASTE, "action": "preview"})
    assert response.status_code == 200
    html = response.text
    assert FQDN in html and HOST in html and "app-02" in html
    assert "by name" in html and "by private IP" in html
    assert "unknown" in html and "ip-10-0-0-9" in html
    assert USN1 in html and USN2 in html
    assert saved.get_latest_report() is None and saved.list_patch_report() == []
    assert 'value="confirm"' in html


def test_preview_keeps_the_pasted_text(client, saved):
    response = client.post("/reports/import", data={"raw_text": PASTE})
    assert "<textarea" in response.text
    assert f"{C1}, {C2}" in response.text


def test_pasted_markup_is_escaped(client, saved):
    title = "Ubuntu Security Notification for <b>x Vulnerabilities"
    text = f"{C1} {HOST} <script>alert(1)</script> {title}"
    html = client.post("/reports/import", data={"raw_text": text}).text
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html


def test_preview_reports_runs_without_a_host_and_invalid_ids(client, saved):
    text = f"{C2} {TITLE}\nCVE-2000-1 {C1} {HOST} {TITLE}"
    html = client.post("/reports/import", data={"raw_text": text}).text
    assert 'id="import-no-host"' in html and C2 in html
    assert 'id="import-invalid"' in html and "CVE-2000-1" in html


def test_nothing_parsable_is_an_error(client, saved):
    response = client.post("/reports/import", data={"raw_text": "nothing useful"})
    assert response.status_code == 422 and "No record" in response.text


def test_too_long_a_paste_is_refused(client, saved, monkeypatch):
    from ec2patcher.services import security_list

    monkeypatch.setattr(security_list, "MAX_PASTE_CHARS", 10)
    response = client.post("/reports/import", data={"raw_text": PASTE})
    assert response.status_code == 422 and "too long" in response.text


# --- confirm: report JSON and round trip -----------------------------------------------------


def test_confirm_loads_the_report_in_the_apps_format(client, saved):
    response = client.post("/reports/import", data={"raw_text": PASTE, "action": "confirm"})
    assert response.status_code == 200 and 'id="import-loaded"' in response.text
    report = saved.get_latest_report()
    assert report.filename.startswith("security-list-") and report.filename.endswith(".json")
    assert report.status == "VALID"
    assert report.servers == {HOST: [C1, C2], "app-02": [C3]}
    assert 'href="/reports/latest/download"' in response.text


def test_confirm_does_not_log_the_pasted_text(client, saved, caplog):
    with caplog.at_level("INFO"):
        client.post("/reports/import", data={"raw_text": PASTE, "action": "confirm"})
    assert "Security list imported" in caplog.text
    assert USN1 not in caplog.text and C1 not in caplog.text


def test_download_round_trips_through_upload(client, saved):
    client.post("/reports/import", data={"raw_text": PASTE, "action": "confirm"})
    loaded = saved.get_latest_report()
    download = client.get("/reports/latest/download")
    assert download.status_code == 200
    assert download.headers["content-type"].startswith("application/json")
    assert f'filename="{loaded.filename}"' in download.headers["content-disposition"]
    assert json.loads(download.content) == {HOST: [C1, C2], "app-02": [C3]}

    uploaded = client.post(
        "/reports/upload",
        files={"report_file": ("again.json", download.content, "application/json")},
    )
    assert uploaded.status_code == 200 and "VALIDATION FAILED" not in uploaded.text
    again = saved.get_latest_report()
    assert again.filename == "again.json" and again.servers == loaded.servers
    assert client.get("/reports/latest/download").content == download.content


def test_download_without_a_report(client):
    assert client.get("/reports/latest/download").status_code == 404


def test_confirm_with_only_unknown_hosts_loads_nothing(client, saved):
    previous = {HOST: [C1]}
    saved.save_report("previous.json", previous, "VALID")
    text = f"{C1} ip-10-0-0-9 {TITLE}"
    response = client.post("/reports/import", data={"raw_text": text, "action": "confirm"})
    assert response.status_code == 422 and "nothing was loaded" in response.text
    assert saved.get_latest_report().servers == previous
    assert saved.list_patch_report() == []


def test_confirm_records_report_rows(client, saved):
    client.post("/reports/import", data={"raw_text": PASTE, "action": "confirm"})
    rows = rows_of(saved)
    assert set(rows) == {(HOST, C1), (HOST, C2), ("app-02", C3)}  # no row for the unknown host
    row = rows[(HOST, C1)]
    assert (row.hostname, row.usn, row.package, row.title, row.status) == (
        FQDN, USN1, "example-package", TITLE, "pending",
    )  # fmt: skip
    assert row.imported_at and row.patched_at is None and row.run_id is None
    assert row.priority is None
    assert rows[("app-02", C3)].hostname == "ip-10-0-0-2"


def test_import_again_keeps_status_and_merges_usns(client, saved):
    client.post("/reports/import", data={"raw_text": f"{C1} {HOST} {TITLE}", "action": "confirm"})
    row = rows_of(saved)[(HOST, C1)]
    row.status, row.patched_at, row.run_id = "patched", "2000-01-01T00:00:00+00:00", 7
    saved.merge_patch_report(HOST, lambda current: [row])
    client.post("/reports/import", data={"raw_text": f"{C1} {HOST} {OTHER}", "action": "confirm"})
    after = rows_of(saved)[(HOST, C1)]
    assert (after.status, after.patched_at, after.run_id) == (
        "patched", "2000-01-01T00:00:00+00:00", 7,
    )  # fmt: skip
    assert after.usn == f"{USN1}, {USN2}" and after.package == "other-package"


def test_one_row_per_server_and_cve_across_usns_of_one_paste(client, saved):
    text = f"{C1} {HOST} {TITLE}\n{C1} {HOST} {OTHER}"
    client.post("/reports/import", data={"raw_text": text, "action": "confirm"})
    rows = saved.list_patch_report()
    assert len(rows) == 1 and rows[0].usn == f"{USN1}, {USN2}"


# --- analysis flow -------------------------------------------------------------------------


def imported(db, cves=(C1,), server=HOST):
    parsed = parse_security_list(f"{', '.join(cves)} {server} {TITLE}")
    patch_report.record_import(db, match_servers(parsed.records, db.list_servers()))


def analyze(db, server_name, finding_list, reported=(C1,), **fields):
    db.save_report("r.json", {server_name: list(reported)}, "VALID")
    server = db.get_server_by_name(server_name)
    run_id = db.create_analysis_run(db.get_latest_report(), [(server.name, server, None)])
    analysis = db.get_analysis_run(run_id).servers[0]
    db.save_server_results(
        analysis.id, finding_list, [], status="complete", remote_hostname=server_name, **fields
    )
    patch_report.record_analysis(db, analysis.id)
    return analysis


def finding(status, cve=C1, source="example-package", installed="1.0", **kwargs):
    return cr.Finding(cve, source, status, "detail", installed, "2.0", **kwargs)


def test_analysis_keeps_what_only_the_paste_knows(client, saved):
    imported(saved)
    analysis = analyze(saved, HOST, [finding(cr.PATCH_AVAILABLE, priority="high")])
    row = rows_of(saved)[(HOST, C1)]
    assert row.status == "pending" and row.run_id == analysis.run_id
    assert row.usn == USN1 and row.title == TITLE and row.hostname == HOST
    assert row.priority == "high" and row.version_before == "1.0"
    assert row.imported_at and row.error is None


def test_priority_is_left_empty_when_no_run_supplied_it(client, saved):
    imported(saved)
    analyze(saved, HOST, [finding(cr.PATCH_AVAILABLE)])
    assert rows_of(saved)[(HOST, C1)].priority is None


def test_analysis_of_an_uploaded_report_adds_rows(client, saved):
    analyze(saved, HOST, [finding(cr.PATCH_AVAILABLE)], reported=(C1, C2))
    rows = rows_of(saved)
    assert rows[(HOST, C1)].version_before == "1.0" and rows[(HOST, C1)].imported_at is None
    assert rows[(HOST, C2)].status == "pending"  # reported, no finding: not analyzed


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (cr.NOT_AFFECTED, "not-affected"),
        (cr.PACKAGE_NOT_INSTALLED, "not-affected"),
        (cr.ALREADY_FIXED, "patched"),
        (cr.PATCH_AVAILABLE, "pending"),
        (cr.NO_FIX_PUBLISHED, "pending"),
        (cr.PRO_OR_ESM_REQUIRED, "pending"),
        (cr.UNKNOWN, "pending"),
        (cr.METADATA_UNAVAILABLE, "pending"),
    ],
)
def test_analysis_status_mapping(client, saved, status, expected):
    imported(saved)
    analyze(saved, HOST, [finding(status)])
    assert rows_of(saved)[(HOST, C1)].status == expected


def test_a_fix_found_in_place_has_no_patched_time(client, saved):
    imported(saved)
    analyze(saved, HOST, [finding(cr.ALREADY_FIXED, installed="2.1")])
    row = rows_of(saved)[(HOST, C1)]
    assert row.status == "patched" and row.patched_at is None and row.version_after == "2.1"


def test_any_open_finding_keeps_the_cve_open(client, saved):
    imported(saved)
    analyze(saved, HOST, [finding(cr.NOT_AFFECTED, source="a"), finding(cr.PATCH_AVAILABLE)])
    assert rows_of(saved)[(HOST, C1)].status == "pending"


def test_metadata_problems_are_recorded_as_error_text(client, saved):
    imported(saved)
    analyze(saved, HOST, [finding(cr.METADATA_UNAVAILABLE)])
    assert rows_of(saved)[(HOST, C1)].error == "detail"


def test_reanalysis_keeps_a_patch_on_record(client, saved):
    patched_at = "2000-01-02T00:00:00+00:00"
    seed(saved, HOST, C1, status="patched", patched_at=patched_at, version_before="1.0",
         version_after="2.0", run_id=1)  # fmt: skip
    analyze(saved, HOST, [finding(cr.ALREADY_FIXED, installed="2.0")])
    row = rows_of(saved)[(HOST, C1)]
    assert (row.status, row.patched_at, row.version_before, row.version_after) == (
        "patched", patched_at, "1.0", "2.0",
    )  # fmt: skip


def test_reanalysis_settles_reboot_required_only_when_the_server_says_so(client, saved):
    seed(saved, HOST, C1, status="reboot-required", patched_at="2000-01-02T00:00:00+00:00")
    analyze(saved, HOST, [finding(cr.ALREADY_FIXED)], current_reboot_required=True)
    assert rows_of(saved)[(HOST, C1)].status == "reboot-required"
    analyze(saved, HOST, [finding(cr.ALREADY_FIXED)], current_reboot_required=False)
    assert rows_of(saved)[(HOST, C1)].status == "patched"


def test_reanalysis_that_finds_the_cve_open_again_reopens_a_patched_row(client, saved):
    seed(saved, HOST, C1, status="patched", patched_at="2000-01-02T00:00:00+00:00")
    analyze(saved, HOST, [finding(cr.PATCH_AVAILABLE)])
    row = rows_of(saved)[(HOST, C1)]
    assert row.status == "pending" and row.patched_at is None and row.version_after is None


def test_failed_stays_failed_until_the_cve_is_found_fixed(client, saved):
    seed(saved, HOST, C1, status="failed", error="PATCH FAILED: example")
    analyze(saved, HOST, [finding(cr.PATCH_AVAILABLE)])
    assert rows_of(saved)[(HOST, C1)].status == "failed"
    analyze(saved, HOST, [finding(cr.ALREADY_FIXED)])
    row = rows_of(saved)[(HOST, C1)]
    assert row.status == "patched" and row.error is None and row.patched_at is None


def test_follow_up_on_an_older_run_does_not_overrule_a_newer_one(client, saved):
    older = analyze(saved, HOST, [finding(cr.PATCH_AVAILABLE)])
    newer = analyze(saved, HOST, [finding(cr.ALREADY_FIXED)])
    patch_report.record_analysis(saved, older.id)
    row = rows_of(saved)[(HOST, C1)]
    assert row.status == "patched" and row.run_id == newer.run_id


def test_real_analysis_run_updates_the_report(saved, tmp_path):
    """Through AnalysisService, with an unreachable server: the row says why."""
    imported(saved)
    saved.save_report("r.json", {HOST: [C1]}, "VALID")
    ssh = ScriptedSSH(failures={"10.0.0.1": (255, "ubuntu@10.0.0.1: Permission denied.")})
    service = AnalysisService(saved, make_metadata(tmp_path), runner=ssh, starter=sync)
    run_id = service.start(saved.get_latest_report())
    row = rows_of(saved)[(HOST, C1)]
    assert row.status == "pending" and row.run_id == run_id and "Permission denied" in row.error


def test_report_failure_never_breaks_the_flow(client, saved, caplog):
    def broken(*args):
        raise sqlite3.OperationalError("database is locked")

    patch_report.safely(broken, saved, 1)
    assert "Could not update the patch report" in caplog.text


# --- patch flow ---------------------------------------------------------------------------


class Patching:
    SERVER_NAME = "ip-10-0-0-3"

    def __init__(self, db, pem, tmp_path):
        self.db = db
        self.server = db.create_server(self.SERVER_NAME, "192.0.2.245", str(pem))
        self.fake = FakeUbuntu()
        db.set_setting(patch_service.STAGING_SETTING, f"{tmp_path}/staging/${{server_name}}")
        self.service = PatchService(db, runner=self.fake, starter=sync, fetcher=FakeFetcher())
        self.cves = sorted({f.cve for f in findings() if f.status == cr.PATCH_AVAILABLE})

    def patch(self, skip_reboot=True):
        analysis = make_analysis(self.db, self.server)
        patch_report.record_analysis(self.db, analysis.id)
        execution_id = self.service.approve(analysis.id, skip_reboot=skip_reboot)
        return self.db.get_execution(execution_id)

    def rows(self):
        rows = self.db.list_patch_report(server=self.SERVER_NAME)
        return {r.cve: r for r in rows}


@pytest.fixture
def patching(db, pem_file, tmp_path):
    return Patching(db, pem_file, tmp_path)


def test_verified_patch_marks_its_cves_patched(patching):
    patching.service.sleep = lambda seconds: None
    execution = patching.patch(skip_reboot=False)
    assert execution.state == ps.SUCCESS
    rows = patching.rows()
    for cve in patching.cves:
        row = rows[cve]
        assert row.status == "patched", cve
        assert row.patched_at == execution.install_finished_at
        assert row.run_id == execution.analysis_run_id
        assert row.version_before and row.version_after and row.error is None


def test_versions_before_and_after_come_from_the_execution(patching):
    execution = patching.patch()
    result = next(c for c in execution.cves if c.source_package == "openssl")
    row = patching.rows()[result.cve]
    assert row.version_before == "3.0.13-0ubuntu3.4"
    assert row.version_after == result.resulting_version


def test_cves_the_patch_did_not_address_are_untouched(patching):
    patching.patch()
    open_finding = next(f for f in findings() if f.status == cr.NO_FIX_PUBLISHED)
    assert patching.rows()[open_finding.cve].status == "pending"


def test_skip_reboot_with_a_pending_reboot_is_reboot_required(patching):
    execution = patching.patch(skip_reboot=True)
    assert execution.reboot_required_after is True  # the fake installs a new kernel
    # (The image package requests it; a skipped reboot leaves it pending.)
    statuses = {r.status for c, r in patching.rows().items() if c in patching.cves}
    assert statuses == {"reboot-required"}


def test_reboot_done_settles_as_patched(patching):
    patching.service.sleep = lambda seconds: None
    execution = patching.patch(skip_reboot=False)
    assert execution.reboot_status == ps.REBOOT_DONE
    statuses = {r.status for c, r in patching.rows().items() if c in patching.cves}
    assert statuses == {"patched"}


def test_reboot_failure_is_noted_and_stays_reboot_required(patching):
    patching.fake.reboot_mode = "refused"
    execution = patching.patch(skip_reboot=False)
    assert execution.reboot_status == ps.REBOOT_FAILED
    row = patching.rows()[patching.cves[0]]
    assert row.status == "reboot-required" and row.patched_at and row.error


def test_failure_before_install_marks_failed_with_the_reason(patching):
    patching.fake.sudo = False
    execution = patching.patch()
    assert execution.state == ps.FAILED
    rows = patching.rows()
    for cve in patching.cves:
        assert rows[cve].status == "failed" and rows[cve].patched_at is None
        assert "Passwordless sudo" in rows[cve].error
        assert rows[cve].run_id == execution.analysis_run_id


def test_failed_install_keeps_the_resulting_version_for_review(patching):
    patching.fake.install_mode = "fail"
    patching.patch()
    rows = patching.rows()
    assert all(rows[cve].status == "failed" for cve in patching.cves)
    assert all("PATCH FAILED" in rows[cve].error for cve in patching.cves)


def test_already_patched_server_counts_as_patched(patching):
    patching.fake.preinstall()
    execution = patching.patch(skip_reboot=False)
    assert execution.state == ps.ALREADY_PATCHED
    row = patching.rows()[patching.cves[0]]
    assert row.status == "patched" and row.patched_at == execution.finished_at
    assert row.version_after


def test_rejection_changes_nothing(patching):
    analysis = make_analysis(patching.db, patching.server)
    patch_report.record_analysis(patching.db, analysis.id)
    patching.service.reject(analysis.id)
    assert {r.status for r in patching.rows().values()} == {"pending"}


def test_interrupted_execution_shows_as_failed(patching):
    analysis = make_analysis(patching.db, patching.server)
    patch_report.record_analysis(patching.db, analysis.id)
    held = PatchService(
        patching.db, runner=patching.fake, starter=lambda fn: None, fetcher=FakeFetcher()
    )
    execution_id = held.approve(analysis.id, skip_reboot=True)
    assert patching.db.mark_interrupted_executions() == 1
    assert patching.db.get_execution(execution_id).state == ps.INTERRUPTED
    rows = patching.rows()
    for cve in patching.cves:
        assert rows[cve].status == "failed" and "PATCH INTERRUPTED" in rows[cve].error
    open_finding = next(f for f in findings() if f.status == cr.NO_FIX_PUBLISHED)
    assert rows[open_finding.cve].status == "pending"


def test_a_broken_report_does_not_fail_the_patch(patching, monkeypatch):
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("database is locked")

    analysis = make_analysis(patching.db, patching.server)
    monkeypatch.setattr(patching.db, "merge_patch_report", broken)
    execution_id = patching.service.approve(analysis.id, skip_reboot=True)
    assert patching.db.get_execution(execution_id).state == ps.SUCCESS


# --- server lifecycle --------------------------------------------------------------------


def test_rows_follow_a_rename(client, saved, pem_file):
    imported(saved)
    server = saved.get_server_by_name(HOST)
    saved.update_server(server.id, "renamed", "10.0.0.1", str(pem_file))
    assert set(rows_of(saved)) == {("renamed", C1)}


def test_rows_outlive_a_deleted_server(client, saved):
    imported(saved)
    saved.delete_server(saved.get_server_by_name(HOST).id)
    row = rows_of(saved)[(HOST, C1)]
    assert row.tags == [] and row.usn == USN1


def test_a_server_may_still_be_edited_and_deleted_with_rows(client, saved, pem_file):
    imported(saved)
    server = saved.get_server_by_name(HOST)
    form = {"name": HOST, "ip_address": "10.0.0.7", "pem_path": str(pem_file)}
    assert client.post(f"/servers/{server.id}/edit", data=form).status_code == 200
    assert saved.get_server(server.id).ip_address == "10.0.0.7"
    assert saved.clear_servers() == 2


# --- page, filters, summary ----------------------------------------------------------------


@pytest.fixture
def report_rows(client, saved):
    seed(saved, HOST, C1, status="pending", usn=USN1, imported_at="2000-01-10T12:00:00+00:00")
    seed(saved, HOST, C2, status="patched", usn=f"{USN1}, {USN2}", package="example-package",
         imported_at="2000-01-10T12:00:00+00:00", patched_at="2000-01-20T12:00:00+00:00",
         run_id=3)  # fmt: skip
    seed(saved, HOST, C3, status="failed", usn=USN2, error="PATCH FAILED: example",
         imported_at="2000-01-15T12:00:00+00:00")  # fmt: skip
    seed(saved, "app-02", C1, status="not-affected", usn="USN-0000-11",
         imported_at="2000-01-15T12:00:00+00:00")  # fmt: skip
    seed(saved, "app-02", C3, status="reboot-required", imported_at="2000-01-25T12:00:00+00:00",
         patched_at="2000-01-26T12:00:00+00:00")  # fmt: skip
    return saved


def keys(db, **filters):
    return sorted((r.server_name, r.cve) for r in db.list_patch_report(**filters))


def test_filter_by_server_status_cve(report_rows):
    assert keys(report_rows, server=HOST) == [(HOST, C1), (HOST, C2), (HOST, C3)]
    assert keys(report_rows, server=HOST.upper()) == [(HOST, C1), (HOST, C2), (HOST, C3)]
    assert keys(report_rows, status="failed") == [(HOST, C3)]
    assert keys(report_rows, cve=C1.lower()) == [("app-02", C1), (HOST, C1)]
    assert keys(report_rows, server="app-02", cve=C1) == [("app-02", C1)]


def test_filter_by_usn_matches_whole_entries(report_rows):
    assert keys(report_rows, usn=USN1) == [(HOST, C1), (HOST, C2)]
    assert keys(report_rows, usn=USN2.lower()) == [(HOST, C2), (HOST, C3)]
    assert keys(report_rows, usn="USN-0000-11") == [("app-02", C1)]
    assert keys(report_rows, usn="USN-0000") == []


def local_date(stamp):
    return datetime.fromisoformat(stamp).astimezone().date().isoformat()


def test_filter_by_date_uses_the_imported_or_patched_day(report_rows):
    imported_day = local_date("2000-01-10T12:00:00+00:00")
    patched_day = local_date("2000-01-20T12:00:00+00:00")
    assert keys(report_rows, date_from=imported_day, date_to=imported_day) == [
        (HOST, C1), (HOST, C2),
    ]  # fmt: skip
    assert keys(report_rows, date_from=patched_day, date_to=patched_day) == [(HOST, C2)]
    span = {"date_from": local_date("2000-01-15T12:00:00+00:00"), "date_to": patched_day}
    assert keys(report_rows, **span) == [("app-02", C1), (HOST, C2), (HOST, C3)]
    assert keys(report_rows, date_from=local_date("2000-01-26T12:00:00+00:00")) == [("app-02", C3)]
    assert keys(report_rows, date_to=imported_day) == [(HOST, C1), (HOST, C2)]


def test_rows_without_import_or_patch_date_use_their_last_update(client, saved):
    seed(saved, HOST, C1)
    today = datetime.now().astimezone().date().isoformat()
    assert keys(saved, date_from=today, date_to=today) == [(HOST, C1)]
    assert keys(saved, date_to="2000-01-01") == []


def test_page_applies_filters_server_side(client, report_rows):
    html = client.get("/patch-report", params={"status": "failed"}).text
    details = html.split('id="report-details"')[1]
    assert C3 in details and C1 not in details
    assert "PATCH FAILED: example" in details
    assert "1 of 5 rows" in html
    assert '<option value="failed" selected>' in html


def test_page_shows_columns_tags_and_navigation(client, report_rows):
    html = client.get("/patch-report", params={"server": HOST}).text
    assert 'href="/patch-report"' in html and 'aria-current="page"' in html
    assert "env=test" in html and "owner=team-a" in html
    assert '<a href="/analysis/3">#3</a>' in html
    assert "example-package" in html


def test_page_date_param_is_an_exact_day(client, report_rows):
    day = local_date("2000-01-25T12:00:00+00:00")
    assert "1 of 5 rows" in client.get("/patch-report", params={"date": day}).text


def test_bad_filters_are_reported_and_left_out(client, report_rows):
    response = client.get("/patch-report", params={"date": "yesterday", "status": "nope"})
    assert response.status_code == 422
    assert "Date must be a date" in response.text and "Unknown status" in response.text
    assert "5 of 5 rows" in response.text


def test_empty_report_page(client):
    html = client.get("/patch-report").text
    assert "Nothing to report yet" in html


def test_summary_counts_per_server(report_rows):
    summaries = patch_report.summarize(report_rows.list_patch_report())
    by_server = {s.server: s for s in summaries}
    assert by_server[HOST].total == 3
    assert by_server[HOST].counts == {
        "pending": 1, "patched": 1, "failed": 1, "not-affected": 0, "reboot-required": 0,
    }  # fmt: skip
    assert by_server["app-02"].total == 2
    assert by_server["app-02"].counts["not-affected"] == 1
    assert by_server["app-02"].counts["reboot-required"] == 1


def test_summary_on_the_page_follows_the_filters(client, report_rows):
    html = client.get("/patch-report", params={"status": "failed"}).text
    summary = html.split('id="report-summary"')[1].split('id="report-details"')[0]
    assert f'data-summary="{HOST}"' in summary and 'data-summary="app-02"' not in summary
    assert '<td class="num" data-count="failed">1</td>' in summary


def test_export_link_carries_the_filters(client, report_rows):
    html = client.get("/patch-report", params={"status": "failed", "server": HOST}).text
    assert f"/patch-report/export.xlsx?server={HOST}&amp;status=failed" in html


# --- xlsx ----------------------------------------------------------------------------------


def workbook(client, **params):
    response = client.get("/patch-report/export.xlsx", params=params)
    assert response.status_code == 200
    assert response.headers["content-type"] == excel_export.MEDIA_TYPE
    assert 'filename="ec2patcher_patch_report_' in response.headers["content-disposition"]
    return load_workbook(io.BytesIO(response.content))


def sheet_rows(ws):
    rows = [list(r) for r in ws.iter_rows(values_only=True)]
    return rows[0], rows[1:]


def test_export_has_both_sheets_with_filter_and_frozen_header(client, report_rows):
    wb = workbook(client)
    assert wb.sheetnames == ["Details", "Summary"]
    for ws, used in ((wb["Details"], "A1:S6"), (wb["Summary"], "A1:G3")):
        assert ws.freeze_panes == "A2"
        assert ws.auto_filter.ref == used
        assert all(cell.font.bold for cell in ws[1])


def test_export_details_match_the_page_columns(client, report_rows):
    header, rows = sheet_rows(workbook(client)["Details"])
    assert header == [
        "Hostname", "Server", "Tags", "CVE", "USN", "Package", "Title", "Ubuntu Priority",
        "Status", "Version Before", "Version After", "Imported At", "Patched At", "Run ID", "Error",
        "Source", "KEV", "EPSS", "Failure Reason",
    ]  # fmt: skip
    assert len(rows) == 5
    row = dict(zip(header, next(r for r in rows if r[3] == C2 and r[1] == HOST), strict=True))
    assert row["Status"] == "patched" and row["Run ID"] == 3
    assert row["USN"] == f"{USN1}, {USN2}" and row["Tags"] == "env=test, owner=team-a"
    assert row["Imported At"] and row["Patched At"]


def test_export_honours_the_filters(client, report_rows):
    wb = workbook(client, status="failed")
    _, details = sheet_rows(wb["Details"])
    assert [(r[1], r[3]) for r in details] == [(HOST, C3)]
    assert wb["Details"].auto_filter.ref == "A1:S2"
    header, summary = sheet_rows(wb["Summary"])
    assert summary == [[HOST, 1, 0, 0, 1, 0, 0]]
    assert header[:2] == ["Server", "Total"]


def test_export_summary_counts(client, report_rows):
    header, summary = sheet_rows(workbook(client)["Summary"])
    row = dict(zip(header, next(r for r in summary if r[0] == "app-02"), strict=True))
    assert row["Total"] == 2 and row["Not-affected"] == 1 and row["Reboot-required"] == 1


def test_export_with_no_rows_still_opens(client):
    wb = workbook(client)
    assert sheet_rows(wb["Details"])[1] == [] and wb["Details"].auto_filter.ref == "A1:S1"
    assert wb["Summary"].freeze_panes == "A2"


def test_export_refuses_a_filter_it_cannot_apply(client, report_rows):
    response = client.get("/patch-report/export.xlsx", params={"date": "yesterday"})
    assert response.status_code == 422


def test_text_cannot_become_a_formula_in_the_export(client, saved):
    seed(saved, HOST, C1, error="=HYPERLINK(1)", title="=1+1")
    ws = workbook(client)["Details"]
    assert all(cell.data_type != "f" for row in ws.iter_rows() for cell in row)


# --- migration 17 --------------------------------------------------------------------------


def legacy(db_path, version):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    for v in range(1, version + 1):
        conn.executescript(_MIGRATIONS[v])
    conn.execute(f"PRAGMA user_version = {version}")
    conn.execute(
        "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
        "VALUES ('keep', '10.0.0.1', '/k.pem', 't', 't')"
    )
    conn.execute(
        "INSERT INTO reports (filename, content, uploaded_at, status) "
        "VALUES ('r.json', '{\"keep\": []}', 't', 'VALID')"
    )
    conn.commit()
    return conn


def version_of(db_path):
    with sqlite3.connect(db_path) as conn:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
    conn.close()
    return version


def test_fresh_database_has_the_table(db_path):
    db = Database(db_path)
    assert version_of(db_path) == SCHEMA_VERSION == 19
    db.create_server("keep", "10.0.0.1", "/k.pem")
    seed(db, "keep", C1)
    assert [r.cve for r in db.list_patch_report()] == [C1]


@pytest.mark.parametrize("version", [1, 16])
def test_upgrade_keeps_data_and_adds_the_table(db_path, version):
    legacy(db_path, version).close()
    db = Database(db_path)
    assert version_of(db_path) == SCHEMA_VERSION
    assert db.get_server_by_name("keep").ip_address == "10.0.0.1"
    assert db.get_latest_report().servers == {"keep": []}
    assert db.list_patch_report() == []
    seed(db, "keep", C1, status="patched")
    assert Database(db_path).list_patch_report()[0].status == "patched"


def test_v17_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "patch_report" in _MIGRATIONS[17]
    assert all("patch_report" not in _MIGRATIONS[v] for v in range(1, 17))


def test_status_is_constrained_and_rows_are_unique(db_path):
    db = Database(db_path)
    seed(db, "keep", C1)
    seed(db, "KEEP", C1, status="patched")  # the same row: names are not case-sensitive
    assert [r.status for r in db.list_patch_report()] == ["patched"]
    with pytest.raises(sqlite3.IntegrityError):
        seed(db, "keep", C2, status="nonsense")


def test_reset_clears_the_report(client, saved):
    seed(saved, HOST, C1)
    assert (
        client.post("/settings/reset-database", data={"confirm_text": "RESET"}).status_code == 200
    )
    assert saved.list_patch_report() == []
