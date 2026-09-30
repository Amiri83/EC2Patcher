"""Presentation grouping for stored remediation findings."""

from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ec2patcher.formatting import format_size, format_timestamp
from ec2patcher.models import CveFindingRow, LookupTally, ServerAnalysis
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import nvd
from ec2patcher.services.analysis_service import (
    ACTION_REQUIRED,
    BUCKETS,
    INVESTIGATE,
    NO_ACTION,
    bucket_for_status,
    bucket_groups,
    remediation_groups,
    summarize,
)
from ec2patcher.services.patch_service import Eligibility
from ec2patcher.services.severity import SEVERITIES, SEVERITY_CLASSES


def finding(index, *, fixed="1:5.10-0ubuntu1.10", status=cr.PATCH_AVAILABLE, **changes):
    values = dict(
        id=index,
        cve=f"CVE-2026-{index:05d}",
        source_package="sample-source",
        installed_version="1:5.10-0ubuntu1.8",
        fixed_version=fixed,
        status=status,
        detail="A fix is available.",
        binary_packages=["sample-bin", "sample-dev"],
        pocket="noble-security",
        priority="high",
        apt_candidate="sample-bin: 1:5.10-0ubuntu1.9; sample-dev: 1:5.10-0ubuntu1.10",
        cvss_severity="High",
        cvss_score=8.1,
        cvss_version="3.1",
    )
    values.update(changes)
    return CveFindingRow(**values)


def test_nine_cves_one_remediation_with_clean_debian_max_candidate():
    rows = [finding(i) for i in range(1, 10)]
    rows[0].installed_version = "1:5.10-0ubuntu1.7"
    rows[1].cvss_score = 9.8
    rows[1].cvss_severity = "Critical"
    rows[2].binary_packages = ["sample-bin"]
    groups = remediation_groups(rows)
    assert len(groups) == 1
    group = groups[0]
    assert group.source == "sample-source"
    assert group.cves == sorted({row.cve for row in rows})
    assert group.cve_count == 9
    assert (group.severity, group.cvss_score) == ("Critical", 9.8)
    assert group.ubuntu_priority == "high"
    assert group.installed_version == "1:5.10-0ubuntu1.7"
    assert group.fixed_version == "1:5.10-0ubuntu1.10"
    assert group.candidate_version == "1:5.10-0ubuntu1.10"
    assert group.status == cr.PATCH_AVAILABLE
    assert group.binary_packages == ["sample-bin", "sample-dev"]
    assert group.pockets == ["noble-security"]
    assert group.rows == rows


def test_different_fixes_separate_and_missing_keys_stay_individual():
    rows = [
        finding(1, fixed="1.2"),
        finding(2, fixed="1.10"),
        finding(3, fixed=None, status=cr.UNKNOWN),
        finding(4, source_package=None, status=cr.METADATA_UNAVAILABLE),
        finding(5, fixed=None, status=cr.PACKAGE_NOT_INSTALLED, binary_packages=[]),
    ]
    groups = remediation_groups(rows)
    assert len(groups) == 5
    assert {group.fixed_version for group in groups[:2]} == {"1.2", "1.10"}
    assert [group.cves for group in groups[2:]] == [[row.cve] for row in rows[2:]]


def test_group_status_is_stored_status_without_reclassification():
    for status in (cr.PATCH_AVAILABLE, cr.FIX_NOT_IN_CONFIGURED_REPOS, cr.ALREADY_FIXED):
        rows = [finding(1, status=status), finding(2, status=status)]
        assert remediation_groups(rows)[0].status == status
    rows = [finding(1, status=cr.UNKNOWN), finding(2, status=cr.PATCH_AVAILABLE)]
    groups = remediation_groups(rows)
    assert {(g.status, g.cve_count) for g in groups} == {(cr.UNKNOWN, 1), (cr.PATCH_AVAILABLE, 1)}
    assert [r.status for r in rows] == [cr.UNKNOWN, cr.PATCH_AVAILABLE]


def test_perl_group_counts_only_cves_with_the_same_outcome():
    """Regression: a perl row showed '9 CVEs' because rows sharing (source, fix) but with a
    different outcome were merged in, inflating the count and raising the severity."""
    actionable = [
        finding(i, source_package="perl", cvss_severity="Medium", cvss_score=5.5)
        for i in range(1, 5)
    ]
    other = [
        finding(5, source_package="perl", status=cr.ALREADY_FIXED, cvss_score=9.8,
                cvss_severity="Critical"),
        finding(6, source_package="perl", status=cr.NOT_AFFECTED, cvss_score=9.1,
                cvss_severity="Critical"),
        finding(7, source_package="perl", status=cr.PACKAGE_NOT_INSTALLED, cvss_score=8.8),
        finding(8, source_package="perl", status=cr.UNKNOWN, cvss_score=7.5),
        finding(9, source_package="libdbi-perl", cvss_score=9.9, cvss_severity="Critical"),
    ]  # fmt: skip
    groups = remediation_groups(actionable + other)
    perl = next(g for g in groups if g.source == "perl" and g.status == cr.PATCH_AVAILABLE)
    assert perl.cve_count == 4
    assert perl.cves == sorted(r.cve for r in actionable)
    assert (perl.severity, perl.cvss_score) == ("Medium", 5.5)
    assert sum(g.cve_count for g in groups) == 9
    assert all(len({r.status for r in g.rows}) == 1 for g in groups)
    assert all(len({r.source_package for r in g.rows}) == 1 for g in groups)
    # statuses are presentation input only - never rewritten
    assert [r.status for r in other][:4] == [
        cr.ALREADY_FIXED, cr.NOT_AFFECTED, cr.PACKAGE_NOT_INSTALLED, cr.UNKNOWN,
    ]  # fmt: skip


# --- report buckets ---------------------------------------------------------------------


def test_every_status_has_exactly_one_bucket():
    assigned = [s for _, _, statuses in BUCKETS for s in statuses]
    assert sorted(assigned) == sorted(cr.STATUS_LABELS)
    assert bucket_for_status("SOMETHING_NEW") == INVESTIGATE
    assert bucket_for_status(None) == INVESTIGATE
    assert bucket_for_status("NOT_ANALYZED") == INVESTIGATE
    assert bucket_for_status("PATCH_REQUIRED") == ACTION_REQUIRED  # legacy name


def test_bucket_groups_splits_by_status_and_keeps_empty_buckets():
    rows = [
        finding(1),
        finding(2, status=cr.FIX_NOT_IN_CONFIGURED_REPOS, fixed="2"),
        finding(3, status=cr.PRO_OR_ESM_REQUIRED, fixed="3"),
        *(finding(10 + i, fixed=None, status=cr.PACKAGE_NOT_INSTALLED) for i in range(5)),
    ]
    buckets = bucket_groups(remediation_groups(rows))
    assert [b.key for b in buckets] == [ACTION_REQUIRED, INVESTIGATE, NO_ACTION]
    assert [(b.count, b.cve_count) for b in buckets] == [(3, 3), (0, 0), (5, 5)]
    assert [r.status for r in rows[:3]] == [
        cr.PATCH_AVAILABLE, cr.FIX_NOT_IN_CONFIGURED_REPOS, cr.PRO_OR_ESM_REQUIRED,
    ]  # fmt: skip

    empty = bucket_groups([])
    assert [(b.count, b.cve_count, b.groups) for b in empty] == [(0, 0, [])] * 3


def test_report_html_buckets_with_counts_and_collapsed_no_action():
    rows = [
        finding(1, source_package="perl"),
        finding(2, source_package="perl", status=cr.METADATA_UNAVAILABLE, fixed=None),
        *(
            finding(10 + i, source_package=f"perl-mod{i}", fixed=None,
                    status=cr.PACKAGE_NOT_INSTALLED)
            for i in range(5)
        ),
    ]  # fmt: skip
    html = render_report(rows)
    assert "Action required: 1</span>" in html
    assert "Investigate: 1</span>" in html
    assert "No action: 5</span>" in html
    action = html.index('<h3 class="bucket bucket-action">')
    investigate = html.index('<h3 class="bucket bucket-investigate">')
    no_action = html.index('<details class="report-details bucket bucket-no_action">')
    assert action < investigate < no_action
    assert html.index("<strong>perl</strong>") < investigate
    assert html.index("<strong>perl-mod0</strong>") > no_action
    closed = html[no_action : html.index("</details>", html.index("perl-mod4"))]
    assert "<details class" in closed and " open" not in closed.split(">", 1)[0]


def test_report_html_empty_buckets_render():
    html = render_report([finding(1, status=cr.ALREADY_FIXED)])
    assert "Action required: 0</span>" in html and "Investigate: 0</span>" in html
    assert html.count("None.") == 2


def test_only_installed_binaries_appear_in_group():
    rows = [
        finding(1, binary_packages=["sample-bin"]),
        finding(2, binary_packages=["sample-dev"]),
    ]
    assert remediation_groups(rows)[0].binary_packages == ["sample-bin", "sample-dev"]
    assert "uninstalled-bin" not in remediation_groups(rows)[0].binary_packages


def server_analysis(rows):
    return ServerAnalysis(
        id=1,
        run_id=1,
        position=1,
        server_id=1,
        server_name="host",
        ip_address="127.0.0.1",
        display_name=None,
        reported_cves=list(dict.fromkeys(row.cve for row in rows)),
        status="complete",
        findings=rows,
    )


def template_env():
    template_dir = Path(__file__).resolve().parents[1] / "src/ec2patcher/templates"
    env = Environment(loader=FileSystemLoader(template_dir), autoescape=select_autoescape())
    env.filters.update(timestamp=format_timestamp, filesize=format_size)
    env.globals.update(
        url_for=lambda *_args, **_kwargs: "/static/file",
        status_labels=cr.STATUS_LABELS,
        status_classes={},
        reboot_help=cr.REBOOT_HELP,
        severity_classes=SEVERITY_CLASSES,
        severities=SEVERITIES,
        nvd_status_labels=nvd.STATUS_LABELS,
    )
    return env


def render_report(rows, **context):
    run = SimpleNamespace(
        id=1,
        started_at="2026-01-01T00:00:00+00:00",
        metadata_updated_at=None,
        metadata_stale=False,
        metadata_source=None,
        lookup_tally=LookupTally(),
    )
    analysis = server_analysis(rows)
    template = template_env().get_template("server_report.html")
    return template.render(
        analysis=analysis,
        run=run,
        summary=summarize(analysis),
        remediation_groups=remediation_groups(rows),
        finding_buckets=bucket_groups(remediation_groups(rows)),
        is_latest=True,
        patch=Eligibility(allowed=False),
        version="test",
        active="reports",
        **context,
    )


def test_report_html_shows_single_candidate_without_raw_apt_dump():
    rows = [finding(1), finding(2)]
    html = render_report(rows)
    assert html.count("<strong>sample-source</strong>") == 1
    assert "2 CVEs" in html and "Affected CVEs" in html
    assert "<code>1:5.10-0ubuntu1.10</code>" in html
    assert rows[0].apt_candidate not in html


def test_group_row_shows_highest_cve_severity_not_first_row():
    rows = [
        finding(1, cvss_severity="Medium", cvss_score=5.3),
        finding(2, cvss_severity="Critical", cvss_score=9.8),
        finding(3, cvss_severity="High", cvss_score=7.5),
        finding(4, cvss_severity="Critical", cvss_score=9.8),
    ]
    group = remediation_groups(rows)[0]
    assert group.highest_row is rows[1]
    assert (group.severity, group.cvss_score) == ("Critical", 9.8)
    assert group.cvss_label == rows[1].cvss_label != rows[0].cvss_label
    assert group.highest_row.severity == group.severity

    html = render_report(rows)
    main_cells = html.split("</details>", 1)[1].split("<strong>sample-source</strong>", 1)[0]
    assert f">{group.severity}</span>" in main_cells
    assert '<td class="cvss">' in main_cells
    assert f">{group.cvss_label}</span>" in main_cells
    assert "Medium" not in main_cells
    assert rows[0].cvss_label not in main_cells


def perl_server_findings(open_status, detail):
    """Perl fixture: one CVE needing action or investigation, five needing none (each spread
    over several source packages, as Canonical reports perl and its split-out modules)."""
    rows = [
        finding(1, source_package="perl", status=open_status, detail=detail),
        finding(101, cve="CVE-2026-00001", source_package="libperl-x", fixed=None,
                status=cr.PACKAGE_NOT_INSTALLED),
    ]  # fmt: skip
    closed = [cr.ALREADY_FIXED, cr.NOT_AFFECTED, cr.PACKAGE_NOT_INSTALLED, cr.ALREADY_FIXED,
              cr.NOT_AFFECTED]  # fmt: skip
    for i, status in enumerate(closed, start=2):
        rows.append(finding(i, source_package="perl", status=status))
        rows.append(finding(100 + i, cve=f"CVE-2026-{i:05d}", source_package="perl-modules",
                            fixed=None, status=cr.PACKAGE_NOT_INSTALLED))  # fmt: skip
    return rows


def render_run_page(rows):
    analysis = server_analysis(rows)
    run = SimpleNamespace(
        id=1, is_running=False, status="complete", report_filename="perl.json",
        report_uploaded_at=None, started_at=None, completed_at=None, metadata_updated_at=None,
        metadata_stale=False, progress_message=None, metadata_warning=None, error=None,
        servers=[analysis], lookup_tally=LookupTally(), failed_lookups=[],
    )  # fmt: skip
    template = template_env().get_template("analysis_run.html")
    return template.render(
        run=run, summaries={analysis.id: summarize(analysis)}, version="test", active="reports"
    )


def test_perl_summary_counters_use_report_buckets():
    for status, bucket in ((cr.PATCH_AVAILABLE, ACTION_REQUIRED), (cr.UNKNOWN, INVESTIGATE)):
        summary = summarize(server_analysis(perl_server_findings(status, "")))
        assert summary.by_bucket == {bucket: 1, NO_ACTION: 5} | {
            k: 0 for k in (ACTION_REQUIRED, INVESTIGATE) if k != bucket
        }
        assert [t for _, t, _ in summary.buckets] == ["Action required", "Investigate", "No action"]
        assert sum(summary.by_bucket.values()) == summary.reported == 6

    rows = perl_server_findings(cr.ANALYSIS_ERROR, "APT candidate check failed: boom")
    summary = summarize(server_analysis(rows))
    assert summary.by_bucket == {ACTION_REQUIRED: 0, INVESTIGATE: 1, NO_ACTION: 5}

    page = render_run_page(rows)
    meta = page[page.index('<div class="server-meta">') :]
    assert "Action required: 0</span>" in meta
    assert "Investigate: 1</span>" in meta
    assert "No action: 5</span>" in meta
    assert "unresolved" not in meta

    report = render_report(rows)
    assert "Investigate: 1 CVE</span>" in report and "No action: 5 CVEs</span>" in report


def test_reports_never_suggest_updating_apt_on_the_server():
    """APT is resolved on the workstation with fresh private lists: no server-side hint."""
    rows = perl_server_findings(cr.FIX_NOT_IN_CONFIGURED_REPOS, "")
    for html in (render_report(rows), render_run_page(rows)):
        assert "apt-get update" not in html and "sudo" not in html
        assert "NOT CURRENT" not in html and "stale-apt-hint" not in html
