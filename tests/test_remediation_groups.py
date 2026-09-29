"""Presentation grouping for stored remediation findings."""

from pathlib import Path
from types import SimpleNamespace

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ec2patcher.formatting import format_size, format_timestamp
from ec2patcher.models import CveFindingRow, ServerAnalysis
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import nvd
from ec2patcher.services.analysis_service import remediation_groups, summarize
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


def test_group_status_uses_existing_rollup_without_reclassification():
    for status in (cr.PATCH_AVAILABLE, cr.FIX_NOT_IN_CONFIGURED_REPOS, cr.ALREADY_FIXED):
        rows = [finding(1, status=status), finding(2, status=status)]
        assert remediation_groups(rows)[0].status == status
    rows = [finding(1, status=cr.UNKNOWN), finding(2, status=cr.PATCH_AVAILABLE)]
    assert remediation_groups(rows)[0].status == cr.PATCH_AVAILABLE


def test_only_installed_binaries_appear_in_group():
    rows = [
        finding(1, binary_packages=["sample-bin"]),
        finding(2, binary_packages=["sample-dev"]),
    ]
    assert remediation_groups(rows)[0].binary_packages == ["sample-bin", "sample-dev"]
    assert "uninstalled-bin" not in remediation_groups(rows)[0].binary_packages


def render_report(rows):
    analysis = ServerAnalysis(
        id=1,
        run_id=1,
        position=1,
        server_id=1,
        server_name="host",
        ip_address="127.0.0.1",
        display_name=None,
        reported_cves=[row.cve for row in rows],
        status="complete",
        findings=rows,
    )
    run = SimpleNamespace(
        id=1,
        started_at="2026-01-01T00:00:00+00:00",
        metadata_updated_at=None,
        metadata_stale=False,
        metadata_source=None,
    )
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
    return env.get_template("server_report.html").render(
        analysis=analysis,
        run=run,
        summary=summarize(analysis),
        remediation_groups=remediation_groups(rows),
        is_latest=True,
        version="test",
        active="reports",
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
