"""Phase 2.1: vulnerability severity and per-server Excel export (read-only).

Phase 2.2 changed the meaning of Severity: it now comes from NVD CVSS (nvd_fixtures), while
Canonical's priority is still captured and stored separately as "Ubuntu Priority". The
fixtures below give every CVE an NVD rating that differs from its Canonical priority.
"""

import copy
import io
import re
import sqlite3
from datetime import datetime

import pytest
from fastapi.testclient import TestClient
from nvd_fixtures import REPORT_CVES, FakeNvd
from nvd_fixtures import make_client as make_nvd_client
from openpyxl import load_workbook
from phase2_fixtures import (
    DOCS,
    FIXED_NOTE,
    REAL_REPORT,
    ScriptedSSH,
    facts_output,
    failing_fetcher,
    online_fetcher,
    parse_fixture_document,
    statement,
    vex_doc,
)
from test_analysis import AUTH_FAILURE, BAD, GOOD, add_servers, sync
from test_web import upload

from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.formatting import format_size
from ec2patcher.models import AnalysisRun, ServerAnalysis
from ec2patcher.services import analysis_service, local_apt, nvd, ssh_service
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import excel_export as xl
from ec2patcher.services.security_metadata import (
    SecurityMetadata,
    VexEntry,
)
from ec2patcher.services.server_state import parse_facts
from ec2patcher.services.severity import normalize_severity

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def priority_note(word: str) -> str:
    return f"Ubuntu Security Team classified this CVE as of {word} priority."


# --- severity normalization ------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Critical", "Critical"),
        ("critical", "Critical"),
        ("High", "High"),
        ("HIGH", "High"),
        ("Medium", "Medium"),
        (" low ", "Low"),
        ("Untriaged", "Unknown"),
        ("Negligible", "Unknown"),
        ("None", "Unknown"),
        ("unknown", "Unknown"),
        ("", "Unknown"),
        (None, "Unknown"),
        ("Critical-ish", "Unknown"),
        (42, "Unknown"),
        (["High"], "Unknown"),
    ],
)
def test_normalize_severity(raw, expected):
    assert normalize_severity(raw) == expected


@pytest.mark.parametrize(
    ("word", "expected"),
    [
        ("critical", "Critical"),
        ("high", "High"),
        ("medium", "Medium"),
        ("low", "Low"),
        ("untriaged", "Unknown"),
        ("negligible", "Unknown"),
    ],
)
def test_priority_from_real_canonical_note_no_longer_drives_severity(word, expected):
    """Production path: Canonical note -> PRIORITY_RE -> VexEntry.priority -> Finding.

    Phase 2.2: the priority is still captured (and normalizes as before, shown as "Ubuntu
    Priority"), but a finding's Severity comes only from NVD CVSS - Unknown without it."""
    entry = VexEntry(
        source="openssl", version="3.0.13-0ubuntu3.6", distro="noble", status="fixed",
        note=f"{FIXED_NOTE} {priority_note(word)}",
    )  # fmt: skip
    assert entry.priority == word.capitalize()
    facts = parse_facts(facts_output())
    installed = [p for p in facts.packages if p.source == "openssl"]
    finding = cr.resolve_source("CVE-2026-1", "openssl", [entry], installed, facts)
    assert finding.priority == word.capitalize()
    assert normalize_severity(finding.priority) == expected
    assert finding.severity == "Unknown"
    finding.cvss = nvd.CvssResult(status=nvd.OK, severity="Low", score=2.0, version="3.1")
    assert finding.severity == "Low"


def test_missing_priority_is_unknown():
    record = parse_fixture_document(DOCS[0])  # openssl statements carry no priority note
    facts = parse_facts(facts_output())
    (finding,) = cr.resolve_cve("CVE-2026-63076", record, facts)
    assert finding.priority is None and finding.severity == "Unknown"


# --- end-to-end with severities ----------------------------------------------------------


def severity_docs():
    """The Phase 2 fixture documents, with real-format priority notes on the report CVEs."""
    docs = copy.deepcopy(DOCS)
    by_cve = {d["statements"][0]["vulnerability"]["name"]: d for d in docs}
    for cve, word in [
        ("CVE-2026-63076", "critical"),
        ("CVE-2026-54874", "high"),
        ("CVE-2026-63075", "low"),
    ]:
        for stmt in by_cve[cve]["statements"]:
            stmt["status_notes"] = f"{stmt.get('status_notes', '')} {priority_note(word)}".strip()
    by_cve["CVE-2026-10004"]["statements"][0]["status_notes"] = priority_note("untriaged")
    return docs


@pytest.fixture
def web(db_path, tmp_path):
    def factory(ssh=None, fetcher=None, nvd_transport=None):
        meta = SecurityMetadata(db_path, fetcher=fetcher or online_fetcher(severity_docs()))
        nvd_client = make_nvd_client(tmp_path, nvd_transport or FakeNvd(REPORT_CVES))
        app = create_app(
            db_path=db_path, ssh_runner=ssh or ScriptedSSH(failures=AUTH_FAILURE),
            metadata=meta, analysis_starter=sync, shutdown_handler=lambda: None,
            nvd_client=nvd_client,
        )  # fmt: skip
        return TestClient(app, base_url="http://127.0.0.1")

    return factory


REPORT = {GOOD: [*REAL_REPORT[GOOD], "CVE-2026-10004", "CVE-2026-10005"], BAD: ["CVE-2026-63076"]}


@pytest.fixture
def analyzed(web, pem_file, db_path):
    """One completed run: GOOD analyzed (display_name tag), BAD failed. Returns the run."""
    with web() as c:
        add_servers(c, pem_file)
        upload(c, REPORT)
        c.post("/reports/analyze")
    return Database(db_path).get_latest_analysis_run(details=True)


def test_severity_persisted_with_findings(analyzed):
    """Canonical priority is still stored raw; Severity is the stored NVD CVSS rating."""
    good = analyzed.servers[0]
    by_key = {(f.cve, f.source_package): f for f in good.findings}
    assert by_key[("CVE-2026-63076", "openssl")].priority == "Critical"
    assert by_key[("CVE-2026-63076", "openssl")].severity == "High"  # NVD 7.5
    assert by_key[("CVE-2026-54874", "linux-aws")].priority == "High"
    assert by_key[("CVE-2026-54874", "linux-aws")].severity == "Critical"  # CNA v4.0 9.3
    assert by_key[("CVE-2026-63075", "openssl")].priority == "Low"
    assert by_key[("CVE-2026-63075", "openssl")].severity == "Medium"
    assert by_key[("CVE-2026-63075", "curl")].severity == "Medium"
    assert by_key[("CVE-2026-10004", "bash")].priority == "Untriaged"
    assert by_key[("CVE-2026-10004", "bash")].severity == "Low"
    assert by_key[("CVE-2026-10005", "nginx")].priority is None
    assert by_key[("CVE-2026-10005", "nginx")].severity == "Unknown"  # not in NVD
    assert SCHEMA_VERSION == 9


def test_severity_column_rendered(web, analyzed):
    good = analyzed.servers[0]
    with web() as c:
        page = c.get(f"/analysis/{analyzed.id}/servers/{good.id}").text
    assert "<th>CVE</th><th>Severity</th><th>CVSS</th><th>Ubuntu Source Package</th>" in page
    critical = '<span class="badge badge-critical">Critical</span>'
    assert f'{critical}<div class="muted small">Ubuntu Priority: High</div>' in page
    high = '<span class="badge badge-danger">High</span>'
    assert f'{high}<div class="muted small">Ubuntu Priority: Critical</div>' in page
    medium = '<span class="badge badge-warning">Medium</span>'
    assert f'{medium}<div class="muted small">Ubuntu Priority: Low</div>' in page
    low = '<span class="badge badge-low">Low</span>'
    assert f'{low}<div class="muted small">Ubuntu Priority: Untriaged</div>' in page
    assert '<span class="badge badge-neutral">Unknown</span>' in page  # nginx: not in NVD
    assert "CVE not found in NVD" in page


def test_severity_survives_restart_and_metadata_change(web, analyzed, tmp_path):
    good = analyzed.servers[0]
    changed = FakeNvd({})  # NVD now knows none of the CVEs
    with web(fetcher=online_fetcher(), nvd_transport=changed) as c:
        page = c.get(f"/analysis/{analyzed.id}/servers/{good.id}").text
    assert ">Critical</span>" in page and ">High</span>" in page
    assert "Ubuntu Priority: Critical" in page
    with web(fetcher=failing_fetcher(), nvd_transport=changed) as c:
        r = c.get(f"/analysis/{analyzed.id}/servers/{good.id}/export.xlsx")
    rows = list(load_workbook(io.BytesIO(r.content))["CVE Findings"].values)
    assert ("CVE-2026-63076", "High") in {(row[0], row[1]) for row in rows}
    assert changed.calls == []


def test_export_button_per_server(web, analyzed):
    with web() as c:
        for s in analyzed.servers:
            page = c.get(f"/analysis/{analyzed.id}/servers/{s.id}").text
            href = f"/analysis/{analyzed.id}/servers/{s.id}/export.xlsx"
            assert f'<a href="{href}" class="btn btn-primary" download>Export to Excel</a>' in page
            assert page.count("export.xlsx") == 1


# --- workbook contents --------------------------------------------------------------------


def export(web, run_id, analysis_id):
    with web() as c:
        r = c.get(f"/analysis/{run_id}/servers/{analysis_id}/export.xlsx")
    assert r.status_code == 200
    return r, load_workbook(io.BytesIO(r.content))


def summary_values(wb) -> dict:
    ws = wb["Summary"]
    assert ws["A1"].value == "EC2Patcher Pre-Patch Report"
    return {row[0]: row[1] for row in ws.iter_rows(min_row=5, values_only=True) if row[0]}


def table(wb, name) -> tuple[list, list[dict]]:
    rows = list(wb[name].values)
    return list(rows[0]), [dict(zip(rows[0], r, strict=True)) for r in rows[1:]]


def test_export_response(web, analyzed):
    good = analyzed.servers[0]
    r, wb = export(web, analyzed.id, good.id)
    assert r.headers["content-type"] == XLSX
    date = datetime.fromisoformat(good.completed_at).astimezone().strftime("%Y-%m-%d")
    assert r.headers["content-disposition"] == (
        f'attachment; filename="ec2patcher_ip-10-0-0-245_{date}.xlsx"'
    )
    assert wb.sheetnames == ["Summary", "CVE Findings", "Package Plan"]
    assert "Billing API" not in r.headers["content-disposition"]


def test_export_summary_matches_stored_snapshot(web, analyzed):
    good = analyzed.servers[0]
    _, wb = export(web, analyzed.id, good.id)
    s = summary_values(wb)
    summary = analysis_service.summarize(good)
    assert s["Server Name"] == GOOD
    assert s["Display Name"] == "Billing API"
    assert s["IP"] == "192.0.2.245"
    assert s["Remote Hostname"] == "ip-10-0-0-245"
    assert s["Ubuntu"] == "Ubuntu 24.04.3 LTS"
    assert s["Ubuntu Version"] == "24.04"
    assert s["Codename"] == "noble"
    assert s["Architecture"] == "amd64"
    assert s["Running Kernel"] == "6.8.0-1021-aws"
    assert s["Canonical Security Metadata"].startswith("Online per-CVE lookup")
    assert s["Canonical Metadata Stale"] == "NO"
    assert s["APT Metadata"].startswith("Workstation private lists updated ")
    assert "hours before analysis" in s["APT Metadata"]
    assert s["Current Reboot Required"] == "NO"
    assert s["Expected Reboot After Planned Patch"] == "YES EXPECTED"
    assert s["Reported CVEs"] == 5 == summary.reported
    assert s["Patch available"] == summary.count(cr.PATCH_AVAILABLE) == 3
    assert s["Already fixed"] == summary.count(cr.ALREADY_FIXED)
    assert s["Not affected"] == summary.count(cr.NOT_AFFECTED)
    assert s["Package not installed"] == summary.count(cr.PACKAGE_NOT_INSTALLED) == 1
    assert s["No published fix / deferred"] == 1  # bash CVE-2026-10004
    assert s["Needs investigation / errors"] == 0
    assert s["Binary packages to update"] == summary.packages == 6
    assert s[".deb files required"] == summary.debs == 6
    assert s["Estimated download size"] == format_size(summary.download_bytes)
    assert s["Estimated download size (bytes)"] == summary.download_bytes


def test_export_cve_findings_match_stored_rows(web, analyzed):
    good = analyzed.servers[0]
    _, wb = export(web, analyzed.id, good.id)
    headers, rows = table(wb, "CVE Findings")
    assert headers[:15] == [
        "CVE", "Severity", "CVSS Score", "CVSS Version", "Severity Source", "CVSS Vector",
        "Ubuntu Priority", "Ubuntu Source Package", "Installed Version", "Canonical Status",
        "Fixed Version", "APT Candidate", "Fix Pocket", "Status", "Related Binary Package(s)",
    ]  # fmt: skip
    assert len(rows) == len(good.findings)  # nothing collapsed or dropped
    got = {(r["CVE"], r["Ubuntu Source Package"]): r for r in rows}
    for f in good.findings:
        r = got[(f.cve, f.source_package)]
        assert r["Severity"] == f.severity
        assert (r["Ubuntu Priority"] or "") == (f.priority or "")
        assert r["Installed Version"] == f.installed_version
        assert r["Canonical Status"] == f.canonical_status
        assert r["Fixed Version"] == f.fixed_version
        assert (r["APT Candidate"] or "") == (f.apt_candidate or "")
        assert r["Status"] == cr.STATUS_LABELS[f.status]
        assert (r["Related Binary Package(s)"] or "") == ", ".join(f.binary_packages)
    openssl = got[("CVE-2026-63076", "openssl")]
    assert openssl["Severity"] == "High" and openssl["Status"] == "Patch available"
    assert openssl["Ubuntu Priority"] == "Critical"
    assert openssl["Installed Version"] == "3.0.13-0ubuntu3.4"
    assert openssl["Fixed Version"] == "3.0.13-0ubuntu3.6"
    assert openssl["Related Binary Package(s)"] == "libssl3t64:amd64, openssl"
    assert got[("CVE-2026-54874", "linux-gcp")]["Status"] == "Package not installed"
    assert got[("CVE-2026-10005", "nginx")]["Severity"] == "Unknown"
    # Report order is kept.
    assert [r["CVE"] for r in rows][0] == "CVE-2026-63076"


def test_export_package_plan_matches_stored_rows(web, analyzed):
    good = analyzed.servers[0]
    _, wb = export(web, analyzed.id, good.id)
    _, rows = table(wb, "Package Plan")
    assert len(rows) == len(good.plan) == 6
    got = {r["Binary Package"]: r for r in rows}
    for p in good.plan:
        r = got[p.binary_package]
        assert r["Target Version"] == p.target_version
        assert r[".deb Filename"] == p.deb_filename
        assert r["Download URI"] == p.uri
        assert r["Size (bytes)"] == p.size
        assert r["Size"] == format_size(p.size)
        assert r["Checksum"] == p.checksum
        assert r["Related CVEs"] == (", ".join(p.cves) or "required dependency")
    ssl = got["libssl3t64"]
    assert ssl[".deb Filename"] == "libssl3t64_3.0.13-0ubuntu3.6_amd64.deb"
    assert ssl["Download URI"].startswith("http://security.ubuntu.com/ubuntu/pool/main/o/openssl/")
    assert ssl["Checksum"] == "SHA256:" + "ab" * 32
    assert ssl["Current Version"] == "3.0.13-0ubuntu3.4"
    assert "CVE-2026-63076" in ssl["Related CVEs"] and "CVE-2026-63075" in ssl["Related CVEs"]
    image = got["linux-image-6.8.0-1024-aws"]
    assert image["Reboot Impact"] == "Reboot expected (new kernel)"
    assert image["Dependency"] == "Yes" and image["Current Version"] == "not installed"


def test_export_presentation(web, analyzed):
    _, wb = export(web, analyzed.id, analyzed.servers[0].id)
    for name in ("CVE Findings", "Package Plan"):
        ws = wb[name]
        assert ws.freeze_panes == "A2"
        assert ws.auto_filter.ref and ws.auto_filter.ref.startswith("A1:")
        assert all(cell.font.bold for cell in ws[1])
        assert ws.column_dimensions["A"].width > 10
        assert all(c.data_type != "f" for row in ws.iter_rows() for c in row)


def test_export_failed_server_lists_every_reported_cve(web, analyzed):
    bad = analyzed.servers[1]
    _, wb = export(web, analyzed.id, bad.id)
    s = summary_values(wb)
    assert s["Server Name"] == BAD and "Display Name" not in s
    assert s["Analysis Status"] == "failed" and "Permission denied" in s["Analysis Error"]
    assert s["Needs investigation / errors"] == 1
    _, rows = table(wb, "CVE Findings")
    assert [(r["CVE"], r["Severity"], r["Status"]) for r in rows] == [
        ("CVE-2026-63076", "Unknown", "Not analyzed")
    ]
    _, plan = table(wb, "Package Plan")
    assert plan == []


# --- route validation -------------------------------------------------------------------


def test_export_404s(web, analyzed, pem_file):
    good = analyzed.servers[0]
    with web() as c:
        assert c.get(f"/analysis/999/servers/{good.id}/export.xlsx").status_code == 404
        assert c.get(f"/analysis/{analyzed.id}/servers/999/export.xlsx").status_code == 404
        assert c.get(f"/analysis/{analyzed.id}/servers/abc/export.xlsx").status_code == 422
        c.post("/reports/analyze")  # second run
        runs = c.app.state.db.list_analysis_runs()
        newer = runs[0]
        other = newer.servers[0].id
        # Server report of run 2 requested through run 1 -> 404 (page and export).
        assert c.get(f"/analysis/{analyzed.id}/servers/{other}/export.xlsx").status_code == 404
        assert c.get(f"/analysis/{analyzed.id}/servers/{other}").status_code == 404
        assert c.get(f"/analysis/{newer.id}/servers/{other}/export.xlsx").status_code == 200
        r = c.get(f"/analysis/{analyzed.id}/servers/..%2F..%2Fetc%2Fpasswd/export.xlsx")
        assert r.status_code in (404, 422)


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("ip-10-0-0-245", "ip-10-0-0-245"),
        ("../../etc/passwd", "etc_passwd"),
        ('web "prod"/01;rm -rf', "web_prod_01_rm_-rf"),
        ("Café Server", "Caf_Server"),
        ("...", "server"),
    ],
)
def test_export_filename_sanitized(name, expected):
    run = AnalysisRun(
        id=1, report_id=1, report_filename="r.json", report_uploaded_at="t", report={},
        started_at="2026-09-27T12:00:00+00:00", completed_at=None, status="completed",
        progress_message=None, metadata_source=None, metadata_updated_at=None,
        metadata_checked_at=None, metadata_stale=False, metadata_warning=None, error=None,
    )  # fmt: skip
    analysis = ServerAnalysis(
        id=1, run_id=1, position=0, server_id=None, server_name=name, ip_address=None,
        display_name="Display <b>", reported_cves=[], status="failed",
    )  # fmt: skip
    filename = xl.export_filename(run, analysis)
    date = datetime.fromisoformat(run.started_at).astimezone().strftime("%Y-%m-%d")
    assert filename == f"ec2patcher_{expected}_{date}.xlsx"
    assert re.fullmatch(r"[A-Za-z0-9._-]+", filename)
    xl.build_workbook(run, analysis)  # an empty/failed analysis still exports


def test_export_does_not_touch_ssh_metadata_apt_or_state(web, analyzed, db_path, monkeypatch):
    good = analyzed.servers[0]
    calls = []

    def forbidden(name):
        def fail(*args, **kwargs):
            calls.append(name)
            raise AssertionError(f"{name} must not be called during export")

        return fail

    monkeypatch.setattr(ssh_service, "run_remote", forbidden("ssh run_remote"))
    monkeypatch.setattr(ssh_service, "check_connection", forbidden("ssh check_connection"))
    for method in ("prepare", "candidates", "plan"):
        monkeypatch.setattr(local_apt.LocalApt, method, forbidden(f"local apt {method}"))
    for method in ("ensure_fresh", "lookup", "refresh"):
        if hasattr(SecurityMetadata, method):
            monkeypatch.setattr(SecurityMetadata, method, forbidden(f"metadata.{method}"))
    monkeypatch.setattr(analysis_service.AnalysisService, "start", forbidden("analysis start"))
    monkeypatch.setattr(analysis_service.AnalysisService, "run", forbidden("analysis run"))
    for method in ("lookup", "fetch"):
        monkeypatch.setattr(nvd.NvdClient, method, forbidden(f"nvd.{method}"))

    def dump():
        with sqlite3.connect(db_path) as conn:
            return list(conn.iterdump())

    before = dump()
    ssh = ScriptedSSH()
    fetches = []
    nvd_transport = FakeNvd(REPORT_CVES)
    with web(ssh=ssh, fetcher=lambda *a: fetches.append(a), nvd_transport=nvd_transport) as c:
        r = c.get(f"/analysis/{analyzed.id}/servers/{good.id}/export.xlsx")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    assert calls == [] and ssh.calls == [] and fetches == [] and nvd_transport.calls == []
    assert dump() == before  # no analysis/state change of any kind


# --- schema / historical data ------------------------------------------------------------


def test_existing_v3_database_migrates_to_v6_without_data_loss(db_path, web):
    """A Phase 2 (v3) database, including findings stored before Phase 2.1, stays readable.

    Phase 2.2 adds schema v4 (NVD CVSS columns). Old findings keep their Canonical priority
    but have no CVSS snapshot, so their Severity is Unknown - they are never re-fetched."""
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    for version in (1, 2, 3):
        conn.executescript(_MIGRATIONS[version])
    conn.execute("PRAGMA user_version = 3")
    conn.execute(
        "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
        "VALUES ('old-server', '10.0.0.9', '/k.pem', 'then', 'then')"
    )
    conn.execute(
        "INSERT INTO analysis_runs (report_filename, report_uploaded_at, report_content, "
        "started_at, completed_at, status) VALUES ('old.json', 't', "
        '\'{"old-server": ["CVE-2025-1", "CVE-2025-2"]}\', '
        "'2026-01-02T03:04:05+00:00', '2026-01-02T03:05:00+00:00', 'completed')"
    )
    conn.execute(
        "INSERT INTO server_analyses (run_id, position, server_id, server_name, ip_address, "
        "reported_cves, status, completed_at) VALUES (1, 0, 1, 'old-server', '10.0.0.9', "
        "'[\"CVE-2025-1\", \"CVE-2025-2\"]', 'complete', '2026-01-02T03:05:00+00:00')"
    )
    conn.execute(
        "INSERT INTO cve_findings (server_analysis_id, cve, source_package, installed_version, "
        "status, binary_packages, priority) VALUES "
        "(1, 'CVE-2025-1', 'zlib', '1:1.3', 'NOT_AFFECTED', '[\"zlib1g\"]', NULL), "
        "(1, 'CVE-2025-2', 'bash', '5.2', 'ALREADY_FIXED', '[\"bash\"]', 'High')"
    )
    conn.commit()
    conn.close()

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION
    analysis = db.get_server_analysis(1)
    assert [(f.cve, f.priority, f.severity, f.cvss_score) for f in analysis.findings] == [
        ("CVE-2025-1", None, "Unknown", None),
        ("CVE-2025-2", "High", "Unknown", None),
    ]
    assert db.get_server_by_name("old-server") is not None
    with web(fetcher=failing_fetcher()) as c:
        page = c.get("/analysis/1/servers/1").text
        assert '<span class="badge badge-neutral">Unknown</span>' in page
        assert "Ubuntu Priority: High" in page and "Export to Excel" in page
        assert ">High</span>" not in page and "not captured" in page
        assert 'href="/analysis/1"' in c.get("/reports").text  # history intact
        assert "old-server" in c.get("/analysis/1").text
        r = c.get("/analysis/1/servers/1/export.xlsx")
    assert r.status_code == 200
    assert 'filename="ec2patcher_old-server_' in r.headers["content-disposition"]
    wb = load_workbook(io.BytesIO(r.content))
    _, rows = table(wb, "CVE Findings")
    assert [(r["CVE"], r["Severity"], r["Ubuntu Priority"]) for r in rows] == [
        ("CVE-2025-1", "Unknown", None),
        ("CVE-2025-2", "Unknown", "High"),
    ]
    # Reopening keeps everything.
    assert Database(db_path).get_server_analysis(1).findings[1].priority == "High"


def test_workbook_never_contains_formulas_or_illegal_chars():
    run = AnalysisRun(
        id=1, report_id=None, report_filename="=HYPERLINK(\"x\")", report_uploaded_at="t",
        report={}, started_at="2026-09-27T12:00:00+00:00", completed_at=None,
        status="completed", progress_message=None, metadata_source=None,
        metadata_updated_at=None, metadata_checked_at=None, metadata_stale=False,
        metadata_warning=None, error=None,
    )  # fmt: skip
    analysis = ServerAnalysis(
        id=1, run_id=1, position=0, server_id=None, server_name="s", ip_address=None,
        display_name=None, reported_cves=["=1+1"], status="failed", error="bad\x07output",
    )  # fmt: skip
    wb = load_workbook(io.BytesIO(xl.build_workbook(run, analysis)))
    s = summary_values(wb)
    assert s["Report File"] == '=HYPERLINK("x")'
    assert s["Analysis Error"] == "badoutput"
    assert wb["CVE Findings"]["A2"].value == "=1+1"
    assert wb["CVE Findings"]["A2"].data_type == "s"


def test_vex_statement_helper_still_builds_priority_notes():
    """Guard for the fixture used above: priority notes flow through parse_vex_document."""
    doc = vex_doc(
        "CVE-2026-9",
        statement("CVE-2026-9", "affected", [("bash", "5.2", "noble")],
                  status_notes=priority_note("critical")),
    )  # fmt: skip
    assert parse_fixture_document(doc).entries[0].priority == "Critical"
