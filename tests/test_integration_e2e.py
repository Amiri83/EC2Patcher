"""End-to-end integration tests against the local test targets (scripts/test-targets).

Deselected by default; run with ``pytest -m integration`` after ``scripts/test-targets/up.sh``.
Unlike test_integration_targets these need the internet:

* Amazon Linux 2023: the AL2023 advisories (cdn.amazonlinux.com) are fetched on the
  workstation; the container's dnf is used once to downgrade a package (test setup) so that a
  fix of the container's own releasever is pending. The report is generated from REAL CVEs of
  the real advisories for packages installed in the container, and every expected bucket is
  derived independently with the container's own librpm (python3 ``rpm.labelCompare``).
* Ubuntu 24.04: the container's apt installs the release-pocket version of a small package
  (test setup) so an update is pending; the report is generated from the REAL CVEs of the
  pending versions' changelog. Then the full pipeline runs: analyze (Canonical + workstation
  APT) -> approve -> download -> scp -> install -> verify -> cleanup, without a reboot.

Requirements: both containers with passwordless sudo for the login user (ubuntu /
ec2-user); AL2023 container with python3-rpm and dnf-utils (needs-restarting); the
workstation with apt-get and /usr/share/keyrings/ubuntu-archive-keyring.gpg (local_apt).
"""

import json
import re
import shlex
import subprocess
from datetime import timedelta
from functools import cmp_to_key

import pytest
from phase2_fixtures import make_metadata
from test_integration_targets import (  # noqa: F401 - test_target_ssh is an autouse fixture
    AMAZON,
    HOST,
    KEY,
    UBUNTU,
    port_runner,
    test_target_ssh,
)

from ec2patcher.services import (
    amazon_state,
    amazon_updateinfo,
    analysis_service,
    debversion,
    local_apt,
    os_adapters,
    patch_service,
    rpmversion,
    ssh_service,
)
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import patch_state as ps
from ec2patcher.services.amazon_updateinfo import UpdateInfoSource
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.security_metadata import SecurityMetadata

pytestmark = pytest.mark.integration

# Captured at import time, before conftest's autouse fixtures replace them with offline fakes.
REAL_UPDATEINFO_GET = amazon_updateinfo.http_get
REAL_APT_RUNNER = local_apt.default_runner

NO_ADVISORY_CVE = "CVE-2021-34527"  # PrintNightmare (Windows print spooler): no ALAS exists
KERNEL_RE = re.compile(r"^kernel(?:\d+\.\d+)?$")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b")


def sync(fn):
    fn()


def sh(target, command: str, timeout: int = 900, check: bool = True):
    user, port = target
    result = ssh_service.run_remote(
        HOST, KEY, command, timeout=timeout, user=user, port=port,
        accept_returncodes=(0,) if check else tuple(range(256)),
    )  # fmt: skip
    if check:
        assert result.ok, f"{command!r} failed: {result.error}\n{result.stdout}\n{result.stderr}"
    return result


# --- Amazon Linux 2023 ------------------------------------------------------------------

RPM_ORACLE = r"""
import sys, rpm
def evr(s):
    e, _, vr = s.rpartition(":")
    v, sep, r = vr.rpartition("-")
    if not sep:
        v, r = vr, ""
    return (e or "0", v, r)
for line in sys.stdin:
    if line.strip():
        a, b = line.split()
        print(rpm.labelCompare(evr(a), evr(b)))
"""

# Downgraded first when no installed package is older than a fix of its own releasever:
# leaf packages that nothing on the container depends on at an exact version.
DOWNGRADE_PREFERENCE = (
    "less", "vim-minimal", "tar", "gzip", "bzip2", "zip", "unzip", "findutils", "file",
    "diffutils", "sqlite-libs", "expat", "libxml2", "xz", "jq",
)  # fmt: skip
NEVER_DOWNGRADE = re.compile(
    r"^(glibc|rpm|dnf|python3|libdnf|librepo|libsolv|openssh|openssl|systemd|libcurl|curl|"
    r"sudo|bash|coreutils|pam|krb5|shadow|setup|filesystem|system-release|amazon-linux)"
)


def rpm_compare(pairs) -> dict[tuple[str, str], int]:
    """cmp(installed, fixed) for each pair, by the container's librpm (independent oracle)."""
    pairs = sorted(set(pairs))
    if not pairs:
        return {}
    user, port = AMAZON
    args = ssh_service.build_ssh_command(
        HOST, KEY, "python3 -c " + shlex.quote(RPM_ORACLE), user=user, port=port
    )
    proc = subprocess.run(  # noqa: S603
        args, input="".join(f"{a} {b}\n" for a, b in pairs), capture_output=True, text=True,
        timeout=300, check=False,
    )  # fmt: skip
    assert proc.returncode == 0, f"rpm oracle (python3-rpm) failed: {proc.stderr}"
    values = [int(v) for v in proc.stdout.split()]
    assert len(values) == len(pairs)
    return dict(zip(pairs, values, strict=True))


def amazon_facts() -> amazon_state.AmazonFacts:
    return os_adapters.AMAZON_LINUX.parse_facts(sh(AMAZON, amazon_state.FACTS_COMMAND).stdout)


def expected_statuses(facts, current, latest) -> dict[str, str]:
    """Expected roll-up status of every (non-kernel) CVE of the advisories, computed from the
    raw advisories and the container's librpm - not with the adapter's resolver."""
    installed: dict[tuple[str, str], list[str]] = {}
    for p in facts.packages:
        installed.setdefault((p.name, p.architecture), []).append(p.version)

    def matches(advisory):
        return [(pkg, v) for pkg in advisory.packages
                for v in installed.get((pkg.name, pkg.arch), [])]  # fmt: skip

    advisories = [*current.advisories, *(latest.advisories if latest else [])]
    cmp = rpm_compare((v, pkg.evr) for a in advisories for pkg, v in matches(a))
    expected = {}
    for cve in sorted({c for a in advisories for c in a.cves}):
        here = current.for_cve(cve)
        later = latest.for_cve(cve) if latest else []
        if any(KERNEL_RE.match(p.name) for a in here + later for p in a.packages):
            continue  # running-kernel rules: not reproducible in a container
        if any(cmp[(v, p.evr)] < 0 for a in here for p, v in matches(a)):
            expected[cve] = cr.PATCH_AVAILABLE
        elif any(cmp[(v, p.evr)] < 0 for a in later for p, v in matches(a)):
            expected[cve] = cr.FIX_NOT_IN_CONFIGURED_REPOS
        elif any(matches(a) for a in here + later):
            expected[cve] = cr.ALREADY_FIXED
        else:
            expected[cve] = cr.PACKAGE_NOT_INSTALLED
    return expected


def available_builds(names) -> dict[tuple[str, str], list[str]]:
    """{(name, arch): [evr, ...]} of every build of ``names`` in the container's repos."""
    qf = "%{name} %{epoch}:%{version}-%{release} %{arch}\\n"
    result = sh(
        AMAZON,
        f"sudo -n dnf -q repoquery --showduplicates --qf {shlex.quote(qf)} "
        + " ".join(shlex.quote(n) for n in names),
        check=False,
    )  # fmt: skip
    packages, _ = amazon_state.parse_rpm_inventory(result.stdout.splitlines())
    builds: dict[tuple[str, str], list[str]] = {}
    for p in packages:
        builds.setdefault((p.name, p.architecture), []).append(p.version)
    return builds


def ensure_pending_fix(facts, current, latest):
    """Test setup: downgrade one installed package (container dnf, sudo) to a build older than
    a fix of the container's own releasever, so that fix is pending. A plain ``dnf downgrade``
    only steps back one build, which is usually still at or above every advisory's fixed
    version, so an explicit older build is chosen. Returns the new facts."""
    installed = {(p.name, p.architecture): p.version for p in facts.packages}
    fixed: dict[tuple[str, str], set[str]] = {}
    for a in current.advisories:
        if any(KERNEL_RE.match(p.name) for p in a.packages):
            continue
        for pkg in a.packages:
            if (pkg.name, pkg.arch) in installed:
                fixed.setdefault((pkg.name, pkg.arch), set()).add(pkg.evr)
    names = sorted({name for name, _ in fixed})
    order = [n for n in DOWNGRADE_PREFERENCE if n in names]
    order += [n for n in names if n not in order and not NEVER_DOWNGRADE.match(n)]
    order = order[:20]
    builds = available_builds(order)
    # Older than the installed build and than at least one fixed version of that package.
    pairs = [(b, x) for key, evrs in builds.items() if key in fixed
             for b in evrs for x in (installed[key], *fixed[key])]  # fmt: skip
    cmp = rpm_compare(pairs)
    attempts = []
    for name in order:
        for (pkg, arch), evrs in builds.items():
            if pkg != name or (pkg, arch) not in fixed:
                continue
            older = [b for b in evrs if cmp[(b, installed[(pkg, arch)])] < 0
                     and any(cmp[(b, x)] < 0 for x in fixed[(pkg, arch)])]  # fmt: skip
            if not older:
                attempts.append(f"{pkg}.{arch}: no build older than a fix")
                continue
            # The newest such build: the smallest downgrade that still leaves a fix pending.
            target = max(older, key=cmp_to_key(
                lambda a, b: rpmversion.compare_evr(rpmversion.parse_evr(a),
                                                    rpmversion.parse_evr(b))))  # fmt: skip
            epoch, version, release = rpmversion.parse_evr(target)
            nevra = f"{pkg}-{epoch}:{version}-{release}.{arch}"
            result = sh(AMAZON, f"sudo -n dnf -y -q downgrade {shlex.quote(nevra)}", check=False)
            attempts.append(f"{nevra}: exit {result.returncode}")
            if result.returncode != 0:
                continue
            facts = amazon_facts()
            if cr.PATCH_AVAILABLE in expected_statuses(facts, current, latest).values():
                return facts
    pytest.fail("Could not create a pending fix on the AL2023 target: " + "; ".join(attempts))


def test_integration_al2023_analysis_buckets(db, tmp_path):
    user, port = AMAZON
    facts = amazon_facts()
    assert facts.releasever, facts
    arch = facts.architecture
    source = UpdateInfoSource(db, transport=REAL_UPDATEINFO_GET)

    def indexes():
        source.start_run()
        current = source.lookup(facts.releasever, arch)
        latest = None
        if facts.releasever != amazon_updateinfo.LATEST:
            latest = source.lookup(amazon_updateinfo.LATEST, arch)
            assert latest.available, latest.error
        assert current.available, current.error
        assert current.advisories, "the AL2023 updateinfo has no CVE advisories"
        return current, latest

    current, latest = indexes()
    expected = expected_statuses(facts, current, latest)
    if cr.PATCH_AVAILABLE not in expected.values():
        facts = ensure_pending_fix(facts, current, latest)
        expected = expected_statuses(facts, current, latest)

    picked: dict[str, list[str]] = {}
    for cve, status in expected.items():
        limit = 2 if status == cr.PACKAGE_NOT_INSTALLED else 3
        if len(picked.setdefault(status, [])) < limit:
            picked[status].append(cve)
    for required in (cr.PATCH_AVAILABLE, cr.ALREADY_FIXED, cr.PACKAGE_NOT_INSTALLED):
        assert picked.get(required), f"no {required} CVE for this container: {picked}"
    assert not current.for_cve(NO_ADVISORY_CVE)
    assert not (latest and latest.for_cve(NO_ADVISORY_CVE))
    expected[NO_ADVISORY_CVE] = cr.NO_ADVISORY
    report_cves = [cve for cves in picked.values() for cve in cves] + [NO_ADVISORY_CVE]
    (tmp_path / "it-al2023.json").write_text(json.dumps({"it-al2023": report_cves}, indent=2))

    rpmdb_before = sh(AMAZON, "rpm -qa | sort | sha256sum").stdout
    db.create_server("it-al2023", HOST, KEY, ssh_user=user)
    db.save_report("it-al2023.json", {"it-al2023": report_cves}, "VALID")
    service = AnalysisService(
        db, make_metadata(tmp_path), runner=port_runner(port), starter=sync,
        advisories=UpdateInfoSource(db, transport=REAL_UPDATEINFO_GET),
    )  # fmt: skip
    run_id = service.start(db.get_latest_report())
    analysis = db.get_analysis_run(run_id).servers[0]

    assert analysis.status == "complete", analysis.error
    assert analysis.os_id == "amzn" and analysis.os_codename == facts.releasever
    assert analysis.plan == []
    findings: dict[str, list] = {}
    for f in analysis.findings:
        findings.setdefault(f.cve, []).append(f)
    actual = {cve: cr.rollup_status([f.status for f in rows]) for cve, rows in findings.items()}
    assert actual == {cve: expected[cve] for cve in report_cves}, analysis.warnings
    for cve in picked.get(cr.FIX_NOT_IN_CONFIGURED_REPOS, []):
        assert any(cr.NEWER_RELEASEVER_REQUIRED in f.detail for f in findings[cve])
    for cve in picked[cr.PATCH_AVAILABLE]:
        assert any(f.fixed_version and f.pocket.startswith("ALAS2023-") for f in findings[cve])
    buckets = analysis_service.summarize(analysis).by_bucket
    assert buckets == {
        "action": len(picked[cr.PATCH_AVAILABLE])
        + len(picked.get(cr.FIX_NOT_IN_CONFIGURED_REPOS, [])),
        "investigate": 1,  # the CVE without an advisory
        "no_action": len(picked[cr.ALREADY_FIXED]) + len(picked[cr.PACKAGE_NOT_INSTALLED]),
    }
    assert patch_service.check_plan(analysis) == [os_adapters.AMAZON_LINUX.patching_unsupported]
    # Read-only: the analysis changed nothing in the rpm database.
    assert sh(AMAZON, "rpm -qa | sort | sha256sum").stdout == rpmdb_before


# --- Ubuntu 24.04: analyze -> approve -> download -> scp -> install -> verify -> cleanup ----

UBUNTU_SERVER = "it-ubuntu-patch"
# Small packages without reverse dependencies on the target, tried in this order.
UBUNTU_CANDIDATES = ("less", "vim-tiny", "nano", "bzip2", "xz-utils", "zstd", "file")
APT = "sudo -n env DEBIAN_FRONTEND=noninteractive apt-get -q -y -o Dpkg::Use-Pty=0"
_MADISON_RE = re.compile(r"^\s*(\S+)\s*\|\s*(\S+)\s*\|\s*(\S+)\s+(\S+)\s+\S+\s+Packages")
_CHANGELOG_HEADER_RE = re.compile(r"^(\S+) \(([^)]+)\) ")


def installed_version(package: str) -> str | None:
    result = sh(UBUNTU, f"dpkg-query -W -f='${{Status}} ${{Version}}' {shlex.quote(package)}",
                check=False)  # fmt: skip
    status, _, version = result.stdout.strip().rpartition(" ")
    return version if result.returncode == 0 and status == "install ok installed" else None


def changelog_cves(package: str, older: str, newer: str) -> list[str]:
    """CVEs named in the changelog entries after ``older`` up to ``newer`` (real data from
    changelogs.ubuntu.com, through the container's apt)."""
    text = sh(UBUNTU, f"apt-get changelog -q {shlex.quote(package)}", timeout=300).stdout
    cves: list[str] = []
    version = None
    for line in text.splitlines():
        header = _CHANGELOG_HEADER_RE.match(line)
        if header:
            version = header.group(2)
            continue
        if version is None or not debversion.is_valid_version(version):
            continue
        cmp_old = debversion.compare_versions(version, older)
        if cmp_old > 0 and debversion.compare_versions(version, newer) <= 0:
            cves.extend(c for c in CVE_RE.findall(line) if c not in cves)
    return cves


def prepare_pending_updates(limit: int = 2) -> dict[str, dict]:
    """Test setup (container apt, sudo): install the release-pocket version of small packages
    whose newer -updates / -security version fixes CVEs. Returns {package: {old, new, cves}}."""
    sh(UBUNTU, f"{APT} update", timeout=600)
    chosen: dict[str, dict] = {}
    for package in UBUNTU_CANDIDATES:
        rows = [m.groups() for m in map(_MADISON_RE.match, sh(
            UBUNTU, f"apt-cache madison {shlex.quote(package)}", check=False).stdout.splitlines())
            if m and m.group(1) == package]  # fmt: skip
        release = [v for _, v, _, pocket in rows if pocket.split("/")[0] == "noble"]
        if not rows or not release:
            continue
        newest = max((v for _, v, _, _ in rows), key=debversion.version_key)
        old = min(release, key=debversion.version_key)
        if debversion.compare_versions(old, newest) >= 0:
            continue  # no update published since the release
        cves = changelog_cves(package, old, newest)[:4]
        if not cves:
            continue
        result = sh(
            UBUNTU,
            f"{APT} install --allow-downgrades --no-install-recommends "
            f"{shlex.quote(f'{package}={old}')}",
            check=False, timeout=600,
        )  # fmt: skip
        if result.returncode != 0 or installed_version(package) != old:
            continue
        chosen[package] = {"old": old, "new": newest, "cves": cves}
        if len(chosen) >= limit:
            break
    assert chosen, "no package with a pending CVE fix could be prepared on the Ubuntu target"
    return chosen


def test_integration_ubuntu_patch_end_to_end(db, tmp_path):
    user, port = UBUNTU
    pending = prepare_pending_updates()
    report_cves = list(dict.fromkeys(c for info in pending.values() for c in info["cves"]))
    (tmp_path / "it-ubuntu.json").write_text(json.dumps({UBUNTU_SERVER: report_cves}, indent=2))
    sh(UBUNTU, f"rm -rf -- /tmp/{UBUNTU_SERVER}", check=False)  # leftovers of an aborted run

    db.create_server(UBUNTU_SERVER, HOST, KEY, ssh_user=user)
    db.save_report("it-ubuntu.json", {UBUNTU_SERVER: report_cves}, "VALID")
    apt = local_apt.LocalApt(tmp_path / "apt", timedelta(hours=6), runner=REAL_APT_RUNNER)
    analyzer = AnalysisService(
        db, SecurityMetadata(db), runner=port_runner(port), starter=sync, apt=apt
    )
    run_id = analyzer.start(db.get_latest_report())
    analysis = db.get_analysis_run(run_id).servers[0]
    assert analysis.status == "complete", analysis.error
    assert analysis.os_id == "ubuntu" and analysis.os_codename == "noble"
    statuses = analysis_service.summarize(analysis).cve_status
    assert cr.PATCH_AVAILABLE in statuses.values(), (statuses, analysis.warnings)
    planned = {p.binary_package: p for p in analysis.plan}
    for package, info in pending.items():
        assert package in planned, (package, analysis.plan)
        assert planned[package].current_version == info["old"]
        assert debversion.compare_versions(planned[package].target_version, info["old"]) > 0
    assert patch_service.check_plan(analysis) == []

    db.set_setting(patch_service.STAGING_SETTING, f"{tmp_path}/staging/${{server_name}}")
    patcher = patch_service.PatchService(db, runner=port_runner(port), starter=sync)
    assert patcher.eligibility(analysis).allowed
    before = {p.binary_package: installed_version(p.binary_package) for p in analysis.plan}
    execution = db.get_execution(patcher.approve(analysis.id, skip_reboot=True))

    assert execution.state == ps.SUCCESS, (execution.error_title, execution.error_summary)
    assert execution.cleanup_status == "DELETED"
    assert execution.reboot_status in (ps.REBOOT_SKIPPED, ps.REBOOT_NOT_REQUIRED)
    for pkg in execution.packages:
        assert pkg.after_version == pkg.target_version, pkg
        after = installed_version(pkg.binary_package)
        assert after == pkg.target_version and after != before.get(pkg.binary_package)
    for package, info in pending.items():
        assert debversion.compare_versions(installed_version(package), info["old"]) > 0
    # Staging directories are gone on both sides.
    assert execution.local_staging_path and execution.remote_staging_path
    assert not (tmp_path / "staging" / UBUNTU_SERVER).exists()
    remote = shlex.quote(execution.remote_staging_path)
    check = sh(UBUNTU, f"if [ -e {remote} ]; then echo present; else echo absent; fi")
    assert check.stdout.strip().splitlines()[-1] == "absent"

    # A new analysis finds the patched CVEs fixed.
    db.save_report("it-ubuntu-after.json", {UBUNTU_SERVER: report_cves}, "VALID")
    rerun = db.get_analysis_run(analyzer.start(db.get_latest_report())).servers[0]
    assert rerun.status == "complete", rerun.error
    after_status = analysis_service.summarize(rerun).cve_status
    for cve, status in statuses.items():
        if status == cr.PATCH_AVAILABLE:
            assert after_status[cve] == cr.ALREADY_FIXED, (cve, rerun.findings)
