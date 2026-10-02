"""Amazon Linux 2023: read-only facts (rpm -qa, releasever, needs-restarting -r), CVE
resolution against Amazon's advisories (updateinfo of the server's releasever and of latest)
and the analysis-only flow (no plan, no patching)."""

import subprocess

import pytest
from amazon_fixtures import (
    AL2023_OS_RELEASE,
    AL2023_PACKAGES,
    KERNEL_RUNNING,
    NEEDS_RESTARTING_YES,
    RELEASEVER,
    FakeCdn,
    advisory,
    al_facts_output,
    pkg,
    ubuntu_facts_on_amazon,
)
from phase2_fixtures import facts_output, make_metadata

from ec2patcher.services import (
    amazon_state,
    amazon_updateinfo,
    analysis_service,
    cve_resolver,
    os_adapters,
    server_state,
)
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services.amazon_updateinfo import UpdateInfo, UpdateInfoSource
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.os_adapters.amazon_linux import (
    PATCHING_UNSUPPORTED,
    resolve_cve,
)
from ec2patcher.services.patch_service import PatchService, check_plan
from ec2patcher.services.server_state import RemoteOutputError

AMAZON_IP, UBUNTU_IP = "10.0.0.12", "10.0.0.11"
NO_ADVISORY_CVE = "CVE-2021-34527"  # PrintNightmare: a Windows CVE, no ALAS

REPORT_CVES = [
    "CVE-2024-0001",  # openssl: fix in the server's releasever -> patch available
    "CVE-2025-0006",  # curl: fix only in a newer release -> needs a newer releasever
    "CVE-2024-0002",  # vim: two advisories, installed = newest fix -> already fixed
    "CVE-2024-0004",  # nginx: not installed
    "CVE-2024-0005",  # kernel: fixed kernel installed but not running -> already fixed
    NO_ADVISORY_CVE,  # no advisory
]


def sync(fn):
    fn()


def facts(**kwargs) -> amazon_state.AmazonFacts:
    return amazon_state.parse_facts(al_facts_output(**kwargs))


def infos(cdn=None, tmp_path=None):
    src = UpdateInfoSource(transport=cdn or FakeCdn(), cache_db=tmp_path / "c.db")
    return src.lookup(RELEASEVER, "x86_64"), src.lookup("latest", "x86_64")


class AmazonSSH:
    """Fake ssh: the detection (Ubuntu) facts command and the Amazon Linux facts command, per
    target IP. Anything else - in particular dnf / yum / sudo - fails the test."""

    def __init__(self, amazon=None, ubuntu=None):
        self.amazon = amazon if amazon is not None else al_facts_output()
        self.ubuntu = ubuntu or facts_output()
        self.calls: list[list[str]] = []
        self.fail_second: tuple[int, str] | None = None

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        target, command = args[-2], args[-1]
        ip = target.split("@", 1)[1]
        if command == server_state.FACTS_COMMAND:
            out = ubuntu_facts_on_amazon() if ip == AMAZON_IP else self.ubuntu
            return subprocess.CompletedProcess(args, 0, out, "")
        if command == amazon_state.FACTS_COMMAND and ip == AMAZON_IP:
            if self.fail_second:
                return subprocess.CompletedProcess(
                    args, self.fail_second[0], "", self.fail_second[1]
                )
            return subprocess.CompletedProcess(args, 0, self.amazon, "")
        raise AssertionError(f"unexpected remote command: {command}")


@pytest.fixture
def fleet(db, pem_file):
    db.create_server("web-amazon", AMAZON_IP, str(pem_file), ssh_user="ec2-user")
    db.create_server("web-ubuntu", UBUNTU_IP, str(pem_file))
    return db


def analyze(db, ssh=None, cdn=None, servers=("web-amazon",), cves=None):
    cves = REPORT_CVES if cves is None else cves
    db.save_report("report.json", {name: cves for name in servers}, "VALID")
    service = AnalysisService(
        db, make_metadata(None), runner=ssh or AmazonSSH(), starter=sync,
        advisories=UpdateInfoSource(db, transport=cdn or FakeCdn()),
    )  # fmt: skip
    run_id = service.start(db.get_latest_report())
    return service, db.get_analysis_run(run_id)


def by_cve(analysis):
    return {f.cve: f for f in analysis.findings}


# --- facts -------------------------------------------------------------------------------


def test_facts_command_is_constant_and_read_only():
    command = amazon_state.FACTS_COMMAND
    assert command.startswith("echo '@@EC2P hostname'; hostname; echo '@@EC2P os-release'")
    assert "rpm -qa --qf '%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{ARCH}\\n'" in command
    assert "cat /etc/amazon-linux-release" in command and "needs-restarting -r" in command
    for forbidden in ("sudo", "dnf ", "yum", "install", "upgrade", "makecache", "curl", "wget"):
        assert forbidden not in command
    assert os_adapters.AMAZON_LINUX.facts_command == command


def test_parse_facts():
    f = facts()
    assert (f.os_id, f.version_id, f.releasever, f.codename) == (
        "amzn", "2023", RELEASEVER, RELEASEVER,
    )  # fmt: skip
    assert f.system_release == RELEASEVER and f.releasever_source == "/etc/amazon-linux-release"
    assert (f.architecture, f.kernel, f.hostname) == ("x86_64", KERNEL_RUNNING, "ip-10-0-0-12")
    assert f.pretty_name == "Amazon Linux 2023.6.20241010" and f.release_label == f.pretty_name
    assert f.reboot_required is False and f.reboot_required_pkgs == [] and f.warnings == []
    index = {(p.name, p.version) for p in f.packages}
    assert ("bash", "5.2.15-1.amzn2023.0.2") in index  # (none) epoch omitted
    assert ("openssl", "1:3.0.8-1.amzn2023.0.14") in index
    assert ("kernel", "6.1.112-122.189.amzn2023") in index
    assert ("kernel", "6.1.115-126.197.amzn2023") in index
    assert not any(p.name == "gpg-pubkey" for p in f.packages)
    vim_data = next(p for p in f.packages if p.name == "vim-data")
    assert vim_data.architecture == "noarch" and vim_data.source == "vim-data"


def test_parse_rpm_inventory_counts_malformed_rows():
    rows = ["bash (none):5.2-1 x86_64", "broken row", "x 1:bad version x86_64", "y 1.0 x86_64",
            "bad/name 1.0-1 x86_64", "", "gpg-pubkey (none):a-b (none)"]  # fmt: skip
    packages, malformed = amazon_state.parse_rpm_inventory(rows)
    assert [p.name for p in packages] == ["bash"] and malformed == 4


def test_malformed_rows_are_a_warning():
    rows = [*AL2023_PACKAGES, ("x", "garbage", "x86_64", "extra")]
    assert facts(packages=rows).warnings == ["1 package inventory row(s) could not be parsed."]


@pytest.mark.parametrize(
    "output",
    [
        "garbage\n",
        al_facts_output().replace("@@EC2P end\n", ""),
        al_facts_output(packages=[]),
        al_facts_output(kernel=""),
        al_facts_output().replace("@@EC2P rpm-rc\n0", "@@EC2P rpm-rc\n1"),
    ],
)
def test_unusable_output_is_an_error(output):
    with pytest.raises(RemoteOutputError):
        amazon_state.parse_facts(output)


def test_reboot_required_from_needs_restarting():
    f = facts(reboot=NEEDS_RESTARTING_YES, reboot_rc="1")
    assert f.reboot_required is True and f.reboot_required_pkgs == ["kernel", "openssl-libs"]


@pytest.mark.parametrize(
    ("lines", "rc", "warning"),
    [
        ([], "unavailable", "needs-restarting is not installed"),
        (["Error: something"], "1", "needs-restarting -r failed (exit status 1): Error: something"),
        ([], "2", "needs-restarting -r failed (exit status 2): no output"),
        (["Reboot should not be necessary."], "1", "exit status 1"),
    ],
)
def test_reboot_state_unknown(lines, rc, warning):
    f = facts(reboot=lines, reboot_rc=rc)
    assert f.reboot_required is None and f.reboot_required_pkgs == []
    assert len(f.warnings) == 1 and warning in f.warnings[0]


def test_releasever_from_dnf_vars_or_fallbacks():
    latest = facts(dnf_releasever="latest")
    assert latest.releasever == "latest" and latest.system_release == RELEASEVER
    assert latest.releasever_source == "/etc/dnf/vars/releasever"
    pinned = facts(dnf_releasever="2023.5.20240624")
    assert pinned.releasever == "2023.5.20240624"
    assert facts(dnf_releasever="garbage $(reboot)").releasever == RELEASEVER  # ignored
    # No release file: PRETTY_NAME, then the system-release package.
    assert facts(release_file=None).releasever == RELEASEVER
    plain = AL2023_OS_RELEASE.replace("Amazon Linux 2023.6.20241010", "Amazon Linux 2023")
    assert facts(release_file=None, os_release=plain).releasever == "2023.6.20241010"
    rows = [p for p in AL2023_PACKAGES if p[0] != "system-release"]
    unknown = facts(release_file="Amazon Linux release 2023 (Amazon Linux)", os_release=plain,
                    packages=rows)  # fmt: skip
    assert unknown.releasever == "" and "releasever" in amazon_state.check_supported(unknown)


def test_check_supported():
    assert amazon_state.check_supported(facts()) is None
    assert amazon_state.check_supported(facts(arch="aarch64")) is None
    assert "architecture: i686" in amazon_state.check_supported(facts(arch="i686"))
    al2 = AL2023_OS_RELEASE.replace('VERSION_ID="2023"', 'VERSION_ID="2"')
    assert amazon_state.check_supported(facts(os_release=al2)).startswith("Unsupported")


def test_adapter_detection():
    al = os_adapters.AMAZON_LINUX
    assert al.matches({"ID": "amzn", "VERSION_ID": "2023"})
    assert not al.matches({"ID": "amzn", "VERSION_ID": "2"})
    assert not al.matches({"ID": "fedora", "VERSION_ID": "2023"})
    detected = os_adapters.os_release_from_output(ubuntu_facts_on_amazon())
    assert os_adapters.detect(detected) is al
    assert al.supports_patching is False and al.patching_unsupported == PATCHING_UNSUPPORTED
    assert os_adapters.UBUNTU.supports_patching is True
    assert al.blocker(facts()) is None and not al.is_blocker("anything")
    assert os_adapters.get("amzn") is al


def test_adapter_version_helpers_use_rpm_rules():
    al = os_adapters.AMAZON_LINUX
    assert al.compare_versions("1:1.0-1", "2.0-1") > 0
    assert al.at_or_above_target("1.10-1", "1.9-1") and not al.at_or_above_target(None, "1")
    assert al.same_version("0:1.0-1", "1.0-1") and not al.same_version("1.0-1", None)
    assert al.at_or_above_target("bad version", "bad version")
    assert al.is_kernel_package("kernel") and al.is_kernel_package("kernel6.12")
    assert not al.is_kernel_package("kernel-headers")
    assert sorted(["1.10-1", "1.9-1"], key=al.version_key) == ["1.9-1", "1.10-1"]
    assert al.plan_row_problems(object(), "x86_64") == [PATCHING_UNSUPPORTED]
    for call in (
        lambda: al.install_command("/tmp/x", ["a.rpm"]),
        lambda: al.simulate_command("/tmp/x", []),
        lambda: al.reboot_check_command,
    ):
        with pytest.raises(NotImplementedError, match="Patching not supported yet"):
            call()  # fmt: skip


# --- resolution --------------------------------------------------------------------------


def test_resolution_buckets(tmp_path):
    current, latest = infos(tmp_path=tmp_path)
    f = facts()
    results = {cve: resolve_cve(cve, f, current, latest) for cve in REPORT_CVES}
    assert all(len(v) == 1 for v in results.values())
    found = {cve: v[0] for cve, v in results.items()}

    openssl = found["CVE-2024-0001"]
    assert openssl.status == cr.PATCH_AVAILABLE and openssl.source == "openssl"
    assert openssl.installed_version == "1:3.0.8-1.amzn2023.0.14"
    assert openssl.fixed_version == "1:3.0.8-1.amzn2023.0.16"
    assert openssl.binaries == ["openssl", "openssl-libs"]  # src / aarch64 builds ignored
    assert openssl.pocket == "ALAS2023-2024-700" and openssl.priority == "important"
    assert RELEASEVER in openssl.detail

    curl = found["CVE-2025-0006"]
    assert curl.status == cr.FIX_NOT_IN_CONFIGURED_REPOS and curl.source == "curl"
    assert curl.fixed_version == "8.11.1-4.amzn2023.0.1"
    assert "The fix needs a newer releasever" in curl.detail and RELEASEVER in curl.detail

    vim = found["CVE-2024-0002"]
    assert vim.status == cr.ALREADY_FIXED and vim.source == "vim"
    assert vim.fixed_version == "2:9.0.2153-1.amzn2023.0.1"  # the newer of two advisories
    assert vim.pocket == "ALAS2023-2024-650" and vim.binaries == ["vim-data", "vim-minimal"]
    assert vim.priority == "medium"  # highest severity of the advisories involved

    nginx = found["CVE-2024-0004"]
    assert nginx.status == cr.PACKAGE_NOT_INSTALLED and nginx.source == "nginx"
    assert nginx.fixed_version == "1:1.24.0-1.amzn2023.0.4" and nginx.installed_version is None
    assert "none of these packages is installed" in nginx.detail

    kernel = found["CVE-2024-0005"]
    assert kernel.status == cr.ALREADY_FIXED and kernel.is_kernel
    assert kernel.installed_version == "6.1.112-122.189.amzn2023"  # the running kernel
    assert "reboot into the new kernel is still pending" in kernel.detail

    none = found[NO_ADVISORY_CVE]
    assert none.status == cr.NO_ADVISORY and none.source is None
    assert f"https://explore.alas.aws.amazon.com/{NO_ADVISORY_CVE}.html" in none.detail
    assert "or the latest release" in none.detail


def test_running_kernel_with_the_fix_is_fixed_and_without_any_fix_is_vulnerable(tmp_path):
    current, latest = infos(tmp_path=tmp_path)
    running_new = facts(kernel="6.1.115-126.197.amzn2023.x86_64")
    (k,) = resolve_cve("CVE-2024-0005", running_new, current, latest)
    assert k.status == cr.ALREADY_FIXED and "pending" not in k.detail
    only_old = [p for p in AL2023_PACKAGES if p[1] != "(none):6.1.115-126.197.amzn2023"]
    (k,) = resolve_cve("CVE-2024-0005", facts(packages=only_old), current, latest)
    assert k.status == cr.PATCH_AVAILABLE and k.fixed_version == "6.1.115-126.197.amzn2023"


def test_server_on_latest_has_every_published_fix_available(tmp_path):
    cdn = FakeCdn()
    src = UpdateInfoSource(transport=cdn, cache_db=tmp_path / "c.db")
    f = facts(dnf_releasever="latest")
    latest = src.lookup("latest", "x86_64")
    (curl,) = resolve_cve("CVE-2025-0006", f, latest, None)
    assert curl.status == cr.PATCH_AVAILABLE and "(latest)" in curl.detail
    (none,) = resolve_cve(NO_ADVISORY_CVE, f, latest, None)
    assert none.status == cr.NO_ADVISORY and "or the latest release" not in none.detail


def test_re_issued_fix_in_a_newer_release(tmp_path):
    """Fixed in the server's release, but a newer release re-fixed the CVE at a higher
    version the server does not have: the remaining fix needs a newer releasever."""
    refix = advisory("ALAS2023-2025-950", ["CVE-2024-0002"], [
        pkg("vim-minimal", "9.1.0", "1.amzn2023", epoch="2", src="vim-9.1.0-1.amzn2023.src.rpm"),
    ])  # fmt: skip
    from amazon_fixtures import CURRENT_ADVISORIES, NEWER_ADVISORIES

    cdn = FakeCdn({RELEASEVER: CURRENT_ADVISORIES, "latest": [*NEWER_ADVISORIES, refix]})
    current, latest = infos(cdn, tmp_path)
    (vim,) = resolve_cve("CVE-2024-0002", facts(), current, latest)
    assert vim.status == cr.FIX_NOT_IN_CONFIGURED_REPOS
    assert vim.fixed_version == "2:9.1.0-1.amzn2023" and vim.pocket == "ALAS2023-2025-950"


def test_one_cve_in_two_sources_gives_one_finding_each(tmp_path):
    both = advisory("ALAS2023-2024-800", ["CVE-2024-0009"], [
        pkg("bash", "5.2.15", "1.amzn2023.0.3"),
        pkg("python3", "3.9.16", "1.amzn2023.0.9"),
    ])  # fmt: skip
    cdn = FakeCdn({RELEASEVER: [both], "latest": [both]})
    current, latest = infos(cdn, tmp_path)
    findings = resolve_cve("CVE-2024-0009", facts(), current, latest)
    assert [(x.source, x.status) for x in findings] == [
        ("bash", cr.PATCH_AVAILABLE), ("python3", cr.ALREADY_FIXED),
    ]  # fmt: skip
    assert cve_resolver.rollup_status([x.status for x in findings]) == cr.PATCH_AVAILABLE


def test_advisories_unavailable(tmp_path):
    failed = UpdateInfo(f"{RELEASEVER}/x86_64", amazon_updateinfo.FAILED, error="down")
    f = facts()
    (x,) = resolve_cve("CVE-2024-0001", f, failed, failed)
    assert x.status == cr.METADATA_UNAVAILABLE
    _, latest = infos(tmp_path=tmp_path)
    # Only latest known: a missing fix cannot be placed in a release.
    (curl,) = resolve_cve("CVE-2025-0006", f, failed, latest)
    assert curl.status == cr.METADATA_UNAVAILABLE and "unknown" in curl.detail
    (vim,) = resolve_cve("CVE-2024-0002", f, failed, latest)
    assert vim.status == cr.ALREADY_FIXED  # at or above every published fix
    (none,) = resolve_cve(NO_ADVISORY_CVE, f, failed, latest)
    assert none.status == cr.NO_ADVISORY and "were unavailable" in none.detail
    current, _ = infos(tmp_path=tmp_path)
    (none,) = resolve_cve(NO_ADVISORY_CVE, f, current, failed)
    assert none.status == cr.NO_ADVISORY and "newer releases could not be checked" in none.detail


def test_other_architecture_only_advisory(tmp_path):
    arm = advisory("ALAS2023-2024-801", ["CVE-2024-0010"], [
        pkg("bash", "5.2.15", "1.amzn2023.0.3", arch="aarch64"),
    ])  # fmt: skip
    cdn = FakeCdn({RELEASEVER: [arm], "latest": [arm]})
    current, latest = infos(cdn, tmp_path)
    (x,) = resolve_cve("CVE-2024-0010", facts(), current, latest)
    assert x.status == cr.PACKAGE_NOT_INSTALLED and "no x86_64 package" in x.detail


# --- analysis (read-only, fake ssh + fake CDN) -------------------------------------------


def test_analysis_end_to_end(fleet):
    ssh = AmazonSSH()
    cdn = FakeCdn()
    _, run = analyze(fleet, ssh, cdn)
    (amazon,) = run.servers
    assert amazon.status == "complete", amazon.error
    assert run.status == "completed"
    assert (amazon.os_id, amazon.os_version_id, amazon.os_codename) == ("amzn", "2023", RELEASEVER)
    assert amazon.architecture == "x86_64" and amazon.running_kernel == KERNEL_RUNNING
    assert amazon.current_reboot_required is False and amazon.remote_hostname == "ip-10-0-0-12"
    assert amazon.plan == [] and amazon.apt_arguments == []
    assert amazon.expected_reboot is None and amazon.expected_reboot_reason == PATCHING_UNSUPPORTED
    statuses = {cve: f.status for cve, f in by_cve(amazon).items()}
    assert statuses == {
        "CVE-2024-0001": cr.PATCH_AVAILABLE,
        "CVE-2025-0006": cr.FIX_NOT_IN_CONFIGURED_REPOS,
        "CVE-2024-0002": cr.ALREADY_FIXED,
        "CVE-2024-0004": cr.PACKAGE_NOT_INSTALLED,
        "CVE-2024-0005": cr.ALREADY_FIXED,
        NO_ADVISORY_CVE: cr.NO_ADVISORY,
    }
    summary = analysis_service.summarize(amazon)
    assert summary.by_bucket == {"action": 2, "investigate": 1, "no_action": 3}
    # Read-only: the detection command, then the Amazon Linux facts command, as ec2-user.
    assert [args[-1] for args in ssh.calls] == [
        server_state.FACTS_COMMAND, amazon_state.FACTS_COMMAND,
    ]  # fmt: skip
    assert all(args[-2] == f"ec2-user@{AMAZON_IP}" for args in ssh.calls)
    # The repositories were fetched once each (server's releasever + latest) on the workstation.
    assert cdn.downloads == 2


def test_mixed_fleet_ubuntu_is_unchanged(fleet):
    ssh = AmazonSSH()
    _, run = analyze(fleet, ssh, servers=("web-amazon", "web-ubuntu"), cves=["CVE-2026-63076"])
    amazon, ubuntu = run.servers
    assert ubuntu.status == "complete" and ubuntu.os_id == "ubuntu" and ubuntu.findings
    assert amazon.status == "complete" and amazon.os_id == "amzn"
    ubuntu_calls = [a[-1] for a in ssh.calls if a[-2].endswith(UBUNTU_IP)]
    assert ubuntu_calls == [server_state.FACTS_COMMAND]  # one command, exactly as before


def test_second_command_failure_is_a_server_failure(fleet):
    ssh = AmazonSSH()
    ssh.fail_second = (255, "ssh: connect to host 10.0.0.12 port 22: Connection timed out")
    _, run = analyze(fleet, ssh)
    assert run.servers[0].status == "failed" and "timed out" in run.servers[0].error.lower()


def test_malformed_amazon_output_is_a_failure(fleet):
    _, run = analyze(fleet, AmazonSSH(amazon="garbage\n"))
    assert run.servers[0].status == "failed"
    assert run.servers[0].error.startswith("Malformed remote output")


def test_unsupported_architecture_fails_clearly(fleet):
    _, run = analyze(fleet, AmazonSSH(amazon=al_facts_output(arch="i686")))
    assert run.servers[0].status == "failed"
    assert "Unsupported Amazon Linux 2023 architecture: i686" in run.servers[0].error


def test_cdn_unreachable_marks_cves_unavailable_with_warnings(fleet):
    _, run = analyze(fleet, cdn=FakeCdn(fail=OSError("Network is unreachable")))
    (amazon,) = run.servers
    assert amazon.status == "complete"
    assert {f.status for f in amazon.findings} == {cr.METADATA_UNAVAILABLE}
    assert any("advisories of release" in w and "unavailable" in w for w in amazon.warnings)
    assert analysis_service.summarize(amazon).by_bucket["investigate"] == len(REPORT_CVES)


def test_latest_unavailable_is_a_warning(fleet):
    cdn = FakeCdn()
    cdn.files = {k: v for k, v in cdn.files.items() if "/latest/" not in k}
    _, run = analyze(fleet, cdn=cdn)
    (amazon,) = run.servers
    assert "Fixes that need a newer releasever could not be detected." in amazon.warnings
    assert by_cve(amazon)["CVE-2025-0006"].status == cr.NO_ADVISORY
    assert by_cve(amazon)["CVE-2024-0001"].status == cr.PATCH_AVAILABLE


def test_stale_cache_is_used_with_a_warning(fleet):
    from datetime import timedelta

    cdn = FakeCdn()
    analyze(fleet, cdn=cdn)
    src = UpdateInfoSource(fleet, transport=FakeCdn(fail=TimeoutError("timed out")))
    src.now = lambda: amazon_updateinfo._now() + timedelta(days=31)
    service = AnalysisService(fleet, make_metadata(None), runner=AmazonSSH(), starter=sync,
                              advisories=src)  # fmt: skip
    run_id = service.start(fleet.get_latest_report())
    (amazon,) = fleet.get_analysis_run(run_id).servers
    assert by_cve(amazon)["CVE-2024-0001"].status == cr.PATCH_AVAILABLE
    assert any("could not be refreshed" in w and "timed out" in w for w in amazon.warnings)


def test_reanalyze_force_refreshes_advisories(fleet):
    cdn = FakeCdn()
    service, run = analyze(fleet, cdn=cdn)
    assert cdn.downloads == 2
    assert service.reanalyze_server(run.id, run.servers[0].id)
    assert cdn.downloads == 4
    again = fleet.get_server_analysis(run.servers[0].id)
    assert again.status == "complete" and again.error is None


def test_needs_restarting_result_is_stored(fleet):
    out = al_facts_output(reboot=NEEDS_RESTARTING_YES, reboot_rc="1")
    _, run = analyze(fleet, AmazonSSH(amazon=out))
    (amazon,) = run.servers
    assert amazon.current_reboot_required is True
    assert amazon.reboot_required_packages == ["kernel", "openssl-libs"]
    _, run = analyze(fleet, AmazonSSH(amazon=al_facts_output(reboot_rc="unavailable")))
    assert run.servers[0].current_reboot_required is None
    assert any("needs-restarting is not installed" in w for w in run.servers[0].warnings)


# --- no planning / patching yet ----------------------------------------------------------


def test_patching_is_refused(fleet):
    _, run = analyze(fleet)
    amazon = fleet.get_server_analysis(run.servers[0].id)
    assert check_plan(amazon) == [PATCHING_UNSUPPORTED]
    service = PatchService(fleet, runner=AmazonSSH(), starter=sync)
    check = service.eligibility(amazon)
    assert not check.allowed and PATCHING_UNSUPPORTED in check.reasons
    from ec2patcher.services.patch_service import PatchNotAllowedError

    with pytest.raises(PatchNotAllowedError):
        service.approve(amazon.id)
    assert fleet.get_execution_for_analysis(amazon.id) is None
    assert sum(c.allowed for _, c in service.queue_preview(fleet.get_analysis_run(run.id))) == 0


def test_web_report_hides_the_patch_button(fleet, make_client):
    _, run = analyze(fleet, servers=("web-amazon", "web-ubuntu"))
    amazon, ubuntu = run.servers
    with make_client() as client:
        report = client.get(f"/analysis/{run.id}/servers/{amazon.id}").text
        assert PATCHING_UNSUPPORTED in report
        assert "Approve &amp; Patch" not in report and "/reject" not in report
        assert "ANALYSIS COMPLETE" in report and "<dt>Releasever</dt>" in report
        assert "Source RPM" in report and "Amazon Fixed Version (Advisory)" in report
        assert "ALAS2023-2024-700" in report and "1:3.0.8-1.amzn2023.0.16" in report
        assert "needs a newer releasever" in report
        assert "No Amazon Linux advisory" in report and "ALAS Severity: important" in report
        assert "Package planning is not supported yet" in report
        assert "Canonical Security Metadata" not in report
        page = client.get(f"/analysis/{run.id}").text
        assert "Patching not supported yet" in page
        # Ubuntu's report keeps its labels and the patch decision.
        other = client.get(f"/analysis/{run.id}/servers/{ubuntu.id}").text
        assert "Approve &amp; Patch" in other and "<dt>Codename</dt>" in other
        assert "Ubuntu Source Package" in other and PATCHING_UNSUPPORTED not in other
        assert client.get(f"/analysis/{run.id}/servers/{amazon.id}/approve").status_code == 409
        response = client.post(
            f"/analysis/{run.id}/servers/{amazon.id}/approve", data={"confirm": "yes"}
        )
        assert response.status_code == 409 and fleet.get_execution_for_analysis(amazon.id) is None
        export = client.get(f"/analysis/{run.id}/servers/{amazon.id}/export.xlsx")
        assert export.status_code == 200


def test_remediation_groups_accept_rpm_versions():
    from ec2patcher.models import CveFindingRow

    rows = [
        CveFindingRow(id=i, cve=f"CVE-2024-000{i}", source_package="foo",
                      installed_version=v, fixed_version="1.0_1-1", status=cr.ALREADY_FIXED,
                      detail="", binary_packages=["foo"], pocket=None, priority=None)
        for i, v in enumerate(["1.0_1-1", "1.0_0-9"])
    ]  # fmt: skip
    (group,) = analysis_service.remediation_groups(rows)
    assert group.installed_version == "1.0_0-9"  # not a Debian version: rpm order
