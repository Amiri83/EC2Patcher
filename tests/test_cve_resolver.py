"""CVE -> source package -> installed binaries -> fixed version -> APT candidate -> plan."""

from phase2_fixtures import (
    DOCS,
    KERNEL_FIXED,
    NOBLE_PACKAGES,
    PLAN_OUTPUT,
    candidates_output,
    facts_output,
    parse_fixture_document,
    statement,
    vex_doc,
)

from ec2patcher.services import apt_planner
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services.server_state import parse_facts

RECORDS = {r.cve: r for r in (parse_fixture_document(d) for d in DOCS)}


def facts(**kwargs):
    return parse_facts(facts_output(**kwargs))


def resolve(cve, f=None):
    return {x.source: x for x in cr.resolve_cve(cve, RECORDS.get(cve), f or facts())}


def single(cve, **kwargs):
    findings = cr.resolve_cve(cve, RECORDS.get(cve), facts(**kwargs))
    assert len(findings) == 1
    return findings[0]


# --- statuses ---------------------------------------------------------------------------


def test_patch_required():
    f = single("CVE-2026-63076")
    assert (f.source, f.status) == ("openssl", cr.FIX_NOT_IN_CONFIGURED_REPOS)
    assert (f.installed_version, f.fixed_version) == ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6")
    assert f.binaries == ["libssl3t64:amd64", "openssl"]
    assert f.pocket == "noble"


def test_already_fixed():
    f = single("CVE-2026-10006")
    assert (f.status, f.installed_version, f.fixed_version) == (
        cr.ALREADY_FIXED, "5.2.21-2ubuntu4", "5.2.21-2ubuntu3",
    )  # fmt: skip


def test_package_not_installed():
    f = single("CVE-2026-10005")
    assert (f.source, f.status) == ("nginx", cr.PACKAGE_NOT_INSTALLED)
    assert f.installed_version is None  # the 'rc' nginx-common row does not count


def test_not_affected():
    assert resolve("CVE-2026-63075")["curl"].status == cr.NOT_AFFECTED


def test_fix_not_available():
    f = single("CVE-2026-10004")
    assert f.status == cr.NO_FIX_PUBLISHED and f.fixed_version is None
    assert f.priority == "Medium"


def test_under_investigation():
    assert single("CVE-2026-10001").status == cr.NO_FIX_PUBLISHED


def test_ignored_no_fix_planned():
    f = single("CVE-2026-10002")
    assert f.status == cr.PENDING_OR_DEFERRED and "ignored" in f.detail


def test_fix_requires_pro():
    f = single("CVE-2026-10003")
    assert f.status == cr.PRO_OR_ESM_REQUIRED
    assert (f.fixed_version, f.pocket) == ("7:6.1.1-3ubuntu5+esm2", "esm-apps/noble")


def test_pro_fix_already_installed():
    esm = "7:6.1.1-3ubuntu5+esm2"
    pkgs = [
        p if p[2] != "ffmpeg" else (p[0], esm, "ffmpeg", esm, "amd64", "ii ")
        for p in NOBLE_PACKAGES
    ]
    assert single("CVE-2026-10003", packages=pkgs).status == cr.ALREADY_FIXED


def test_cve_not_in_metadata():
    f = single("CVE-2026-99999")
    assert f.status == cr.UNKNOWN and f.source is None
    assert "not found in Canonical" in f.detail


def test_installed_source_tracked_only_for_other_release():
    f = single("CVE-2026-10007")
    assert (f.source, f.status) == ("sudo", cr.UNKNOWN)
    assert "no statement for noble" in f.detail


def test_release_matching_uses_server_codename():
    jammy_release = (
        'ID=ubuntu\nVERSION_ID="22.04"\nVERSION_CODENAME=jammy\nPRETTY_NAME="Ubuntu 22.04.5 LTS"'
    )
    pkgs = [("openssl", "3.0.2-0ubuntu1.15", "openssl", "3.0.2-0ubuntu1.15", "amd64", "ii ")]
    f = cr.resolve_cve(
        "CVE-2026-63076", RECORDS["CVE-2026-63076"], facts(os_release=jammy_release, packages=pkgs)
    )
    assert [(x.fixed_version, x.status) for x in f] == [
        ("3.0.2-0ubuntu1.20", cr.FIX_NOT_IN_CONFIGURED_REPOS)
    ]
    focal_release = 'ID=ubuntu\nVERSION_ID="20.04"\nVERSION_CODENAME=focal'
    pkgs = [("openssl", "1.1.1f-1ubuntu2.20", "openssl", "1.1.1f-1ubuntu2.20", "amd64", "ii ")]
    f = cr.resolve_cve(
        "CVE-2026-63076", RECORDS["CVE-2026-63076"], facts(os_release=focal_release, packages=pkgs)
    )
    assert [x.status for x in f] == [cr.NOT_AFFECTED]  # esm-infra/focal statement applies


def test_multiple_source_packages_for_one_cve():
    findings = resolve("CVE-2026-54874")
    assert findings["linux-aws"].status == cr.FIX_NOT_IN_CONFIGURED_REPOS
    assert findings["linux-signed-aws"].status == cr.FIX_NOT_IN_CONFIGURED_REPOS
    assert findings["linux"].status == cr.PACKAGE_NOT_INSTALLED
    assert findings["linux-azure"].status == cr.PACKAGE_NOT_INSTALLED
    assert findings["linux-aws"].is_kernel
    statuses = cr.cve_statuses(list(findings.values()))
    assert statuses == {"CVE-2026-54874": cr.FIX_NOT_IN_CONFIGURED_REPOS}


def test_one_bad_cve_does_not_break_others():
    def lookup(cve):
        if cve == "CVE-2026-63075":
            raise RuntimeError("boom")
        return RECORDS.get(cve)

    findings = cr.resolve_all(["CVE-2026-63075", "CVE-2026-63076"], lookup, facts())
    assert findings[0].status == cr.METADATA_UNAVAILABLE and "boom" in findings[0].detail
    assert findings[1].status == cr.FIX_NOT_IN_CONFIGURED_REPOS


def test_rollup_prefers_actionable_status():
    assert cr.rollup_status([cr.PACKAGE_NOT_INSTALLED, cr.PATCH_AVAILABLE]) == cr.PATCH_AVAILABLE
    assert cr.rollup_status([cr.NOT_AFFECTED, cr.UNKNOWN]) == cr.UNKNOWN


# --- kernels ------------------------------------------------------------------------------


def test_fixed_kernel_installed_but_not_running():
    extra = [
        (
            "linux-image-6.8.0-1024-aws",
            KERNEL_FIXED,
            "linux-signed-aws",
            KERNEL_FIXED,
            "amd64",
            "ii ",
        ),
        ("linux-modules-6.8.0-1024-aws", KERNEL_FIXED, "linux-aws", KERNEL_FIXED, "amd64", "ii "),
    ]
    findings = resolve("CVE-2026-54874", facts(packages=NOBLE_PACKAGES + extra))
    f = findings["linux-aws"]
    assert f.status == cr.ALREADY_FIXED
    assert f.installed_version == "6.8.0-1021.23"  # the running kernel
    assert "reboot into the new kernel is still pending" in f.detail.lower()


def test_running_newest_kernel_is_fixed():
    pkgs = [p for p in NOBLE_PACKAGES if "linux" not in p[0]] + [
        ("linux-modules-6.8.0-1024-aws", KERNEL_FIXED, "linux-aws", KERNEL_FIXED, "amd64", "ii "),
    ]
    f = resolve("CVE-2026-54874", facts(packages=pkgs, kernel="6.8.0-1024-aws"))["linux-aws"]
    assert f.status == cr.ALREADY_FIXED and f.installed_version == KERNEL_FIXED


def test_kernel_meta_version_mapping():
    assert cr.kernel_meta_version("6.8.0-1024.26") == "6.8.0.1024.26"
    assert cr.kernel_meta_version("6.8.0-1024.26~22.04.1") == "6.8.0.1024.26~22.04.1"


# --- candidates + plan --------------------------------------------------------------------


def analyzed(cves=("CVE-2026-63076", "CVE-2026-63075", "CVE-2026-54874")):
    f = facts()
    findings = cr.resolve_all(list(cves), RECORDS.get, f)
    names = cr.candidate_query_packages(findings, f)
    candidates = apt_planner.parse_candidates(candidates_output(names), names)
    requests = cr.apply_candidates(findings, candidates, f)
    return f, findings, names, candidates, requests


def test_candidate_query_uses_binaries_and_kernel_meta_packages():
    _, _, names, _, requests = analyzed()
    assert names == ["libssl3t64:amd64", "linux-aws", "linux-image-aws", "openssl"]
    assert requests == [
        ("libssl3t64:amd64", "3.0.13-0ubuntu3.6"),
        ("linux-aws", "6.8.0.1024.26"),
        ("linux-image-aws", "6.8.0.1024.26"),
        ("openssl", "3.0.13-0ubuntu3.6"),
    ]


def test_candidate_older_than_fix():
    _, findings, _, _, requests = analyzed(("CVE-2026-10008",))
    f = findings[0]
    assert f.status == cr.FIX_NOT_IN_CONFIGURED_REPOS
    assert (
        "APT candidate 2.9.14+dfsg-1.3ubuntu3.4 is older than 2.9.14+dfsg-1.3ubuntu3.5" in f.detail
    )
    assert requests == []


def test_no_candidate_at_all():
    f = facts()
    findings = cr.resolve_all(["CVE-2026-63076"], RECORDS.get, f)
    requests = cr.apply_candidates(findings, {}, f)
    assert findings[0].status == cr.FIX_NOT_IN_CONFIGURED_REPOS and requests == []
    assert "no installation candidate" in findings[0].detail


def test_candidate_older_than_fix_is_a_genuine_missing_fix():
    """Candidates come from freshly updated private lists: no 'run apt-get update' hint."""
    _, findings, _, _, requests = analyzed(("CVE-2026-10008",))
    f = findings[0]
    assert f.status == cr.FIX_NOT_IN_CONFIGURED_REPOS and requests == []
    assert "noble, noble-updates, noble-security" in f.detail and "amd64" in f.detail
    assert "apt-get update" not in f.detail and "sudo" not in f.detail


def test_missing_kernel_meta_package_is_not_in_repos():
    f = facts()
    kernel = cr.Finding("CVE-1", "linux-aws", cr.FIX_NOT_IN_CONFIGURED_REPOS,
                        fixed_version="6.8.0-1024.26", is_kernel=True)  # fmt: skip
    f.packages = [p for p in f.packages if not p.source.startswith("linux-meta")]
    assert cr.apply_candidates([kernel], {}, f) == []
    assert kernel.status == cr.FIX_NOT_IN_CONFIGURED_REPOS


def test_pro_fix_without_pro_candidate_stays_pro():
    _, findings, _, _, requests = analyzed(("CVE-2026-10003",))
    assert findings[0].status == cr.PRO_OR_ESM_REQUIRED and requests == []
    assert "Ubuntu archive has no suitable candidate" in findings[0].detail


def test_pro_fix_also_offered_by_the_archive_is_patchable():
    f = facts()
    findings = cr.resolve_all(["CVE-2026-10003"], RECORDS.get, f)
    cand = apt_planner.Candidate(
        "libavcodec60:amd64", "7:6.1.1-3ubuntu5", "7:6.1.1-3ubuntu5+esm2", "ffmpeg",
        "7:6.1.1-3ubuntu5+esm2",
    )  # fmt: skip
    requests = cr.apply_candidates(findings, {"libavcodec60:amd64": cand}, f)
    assert findings[0].status == cr.PATCH_AVAILABLE and "Ubuntu archive" in findings[0].detail
    assert requests == [("libavcodec60:amd64", "7:6.1.1-3ubuntu5+esm2")]


def test_deduplicated_package_plan():
    f, findings, _, candidates, requests = analyzed()
    download = apt_planner.parse_plan(PLAN_OUTPUT, requests)
    plan = {p.package: p for p in cr.build_plan(findings, download, candidates, f)}
    # Two CVEs fixed by the same openssl update -> one entry per binary, both CVEs linked.
    assert plan["openssl"].cves == ["CVE-2026-63075", "CVE-2026-63076"]
    assert plan["libssl3t64"].cves == ["CVE-2026-63075", "CVE-2026-63076"]
    assert plan["libssl3t64"].deb_filename == "libssl3t64_3.0.13-0ubuntu3.6_amd64.deb"
    assert plan["libssl3t64"].source == "openssl"
    assert len([p for p in plan.values() if p.deb_filename]) == len(plan) == 6
    # New kernel packages are dependencies of the meta package and carry the kernel CVE.
    image = plan["linux-image-6.8.0-1024-aws"]
    assert image.is_dependency and image.current_version is None
    assert image.cves == ["CVE-2026-54874"]
    assert not plan["linux-aws"].is_dependency


def test_reboot_classification():
    f, findings, _, candidates, requests = analyzed()
    plan = cr.build_plan(findings, apt_planner.parse_plan(PLAN_OUTPUT, requests), candidates, f)
    by = {p.package: p for p in plan}
    assert by["linux-image-6.8.0-1024-aws"].reboot_impact == "Reboot expected (new kernel)"
    assert by["libssl3t64"].reboot_impact.startswith("Reboot expected (package requests")
    assert by["openssl"].reboot_impact == "No reboot expected"
    reboot, reason = cr.expected_reboot(plan)
    assert reboot and "linux-image-6.8.0-1024-aws" in reason


def test_userland_only_plan_has_no_expected_reboot():
    entry = cr.PlanEntry("curl", "amd64", "1", "2", reboot_impact="No reboot expected")
    assert cr.expected_reboot([entry]) == (
        False,
        "No planned package is known to require a reboot.",
    )
    assert cr.expected_reboot([])[0] is False
    assert cr.reboot_impact("curl", False) is None
    assert cr.reboot_impact("linux-modules-6.8.0-1024-aws", False) == "Reboot expected (new kernel)"
    assert cr.reboot_impact("linux-headers-6.8.0-1024-aws", False) is None


def test_multiple_binaries_one_source_share_versions():
    doc = vex_doc(
        "CVE-2026-7", statement("CVE-2026-7", "fixed", [("curl", "8.5.0-2ubuntu10.7", "noble")])
    )
    findings = cr.resolve_cve("CVE-2026-7", parse_fixture_document(doc), facts())
    assert findings[0].binaries == ["curl", "libcurl4t64:amd64"]
    assert findings[0].status == cr.FIX_NOT_IN_CONFIGURED_REPOS


def test_cve_only_tracked_for_unsupported_releases_is_not_reported_safe():
    doc = vex_doc("CVE-2016-1", statement("CVE-2016-1", "fixed", [("foo", "1.0-1", "xenial")]))
    findings = cr.resolve_cve("CVE-2016-1", parse_fixture_document(doc), facts())
    assert [(f.source, f.status) for f in findings] == [(None, cr.UNKNOWN)]


def test_cve_tracked_for_other_supported_release_only_is_not_installed():
    """Regression (perl report): Canonical tracks the source for jammy only (e.g. DNE for
    noble) and it is not installed here. The PACKAGE_NOT_INSTALLED fallback used to be
    unreachable, so this became UNKNOWN and the CVE landed in the Investigate bucket."""
    doc = vex_doc("CVE-2026-8", statement("CVE-2026-8", "fixed", [("foo", "1.0-1", "jammy")]))
    findings = cr.resolve_cve("CVE-2026-8", parse_fixture_document(doc), facts())
    assert [(f.source, f.status) for f in findings] == [(None, cr.PACKAGE_NOT_INSTALLED)]
    assert "(foo)" in findings[0].detail


def test_installed_source_tracked_for_other_release_only_stays_unknown():
    doc = vex_doc(
        "CVE-2026-9",
        statement("CVE-2026-9", "fixed", [("sudo", "1.0-1", "jammy"), ("foo", "1.0-1", "jammy")]),
    )
    findings = cr.resolve_cve("CVE-2026-9", parse_fixture_document(doc), facts())
    assert [(f.source, f.status) for f in findings] == [("sudo", cr.UNKNOWN)]  # sudo installed
