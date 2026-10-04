"""The perl report end to end: per-server action buckets and the local APT verdict.

Every server reports one perl CVE with a published fix (installed 5.38.2-3.2ubuntu0.3, fixed
in 5.38.2-3.2ubuntu0.4) and five perl-module CVEs whose source packages are not installed.
Four of those are tracked by Canonical for other releases only (noble: DNE). Their
PACKAGE_NOT_INSTALLED fallback used to be unreachable, so they became UNKNOWN and the per-server
summary counted them as "Investigate" instead of "No action".
"""

import json
import re

import pytest
from fastapi.testclient import TestClient
from phase2_fixtures import FIXTURES, NOBLE_PACKAGES, ScriptedSSH, _policy, facts_output

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services.analysis_service import (
    ACTION_REQUIRED,
    INVESTIGATE,
    NO_ACTION,
    bucket_groups,
    remediation_groups,
    summarize,
)
from ec2patcher.services.report_service import validate_report
from ec2patcher.services.security_metadata import SecurityMetadata

REPORT_FILE = FIXTURES / "perl_vulnerability_findings.json"
METADATA = json.loads((FIXTURES / "perl_canonical_metadata.json").read_text())
SERVERS = {"ip-10-0-0-3": "192.0.2.245", "ip-10-0-0-2": "192.0.2.215"}
PERL_CVE = "CVE-2026-40001"
INSTALLED, FIXED = "5.38.2-3.2ubuntu0.3", "5.38.2-3.2ubuntu0.4"
SECURITY = "http://security.ubuntu.com/ubuntu noble-security/main"

PERL_BINARIES = [
    ("perl", "amd64"), ("perl-base", "amd64"), ("perl-modules-5.38", "all"),
    ("libperl5.38t64:amd64", "amd64"),
]  # fmt: skip
PERL_PACKAGES = [(name, INSTALLED, "perl", INSTALLED, arch, "ii ") for name, arch in PERL_BINARIES]


def fetch(url):
    cve = url.rsplit("/", 1)[1].removesuffix(".json")
    if cve not in METADATA:
        from urllib.error import HTTPError

        raise HTTPError(url, 404, "Not Found", None, None)
    return METADATA[cve]


def perl_candidates(candidate):
    def answer(names):
        policy, show = [], []
        for name in names:
            base = name.split(":")[0]
            policy.append(_policy(base, INSTALLED, candidate, SECURITY))
            arch = "all" if base == "perl-modules-5.38" else "amd64"
            show.append(f"Package: {base}\nSource: perl\nArchitecture: {arch}\n"
                        f"Version: {candidate}\n")  # fmt: skip
        return ("@@EC2P policy\n" + "".join(policy) + "@@EC2P show\n" + "\n".join(show)
                + "@@EC2P reboot-hooks\n@@EC2P end\n")  # fmt: skip

    return answer


def perl_plan():
    inst, uris = [], []
    for name, arch in PERL_BINARIES:
        base = name.split(":")[0]
        inst.append(f"Inst {base} [{INSTALLED}] ({FIXED} Ubuntu:24.04/noble-security [{arch}])")
        filename = f"{base}_{FIXED}_{arch}.deb"
        uris.append(f"'http://security.ubuntu.com/ubuntu/pool/main/p/perl/{filename}' "
                    f"{filename} 100000 SHA256:{'cd' * 32}")  # fmt: skip
    return "\n".join(["@@EC2P simulate", *inst, "@@EC2P simulate-rc", "0", "@@EC2P uris",
                      *uris, "@@EC2P uris-rc", "0", "@@EC2P end"]) + "\n"  # fmt: skip


@pytest.fixture
def perl_web(db_path, pem_file, fake_apt):
    fake_apt.candidates = perl_candidates(FIXED)
    fake_apt.plan = perl_plan()
    ssh = ScriptedSSH(facts=facts_output(packages=NOBLE_PACKAGES + PERL_PACKAGES))
    app = create_app(
        db_path=db_path, ssh_runner=ssh, metadata=SecurityMetadata(fetcher=fetch),
        analysis_starter=lambda fn: fn(), shutdown_handler=lambda: None,
    )  # fmt: skip
    db = Database(db_path)
    for name, ip in SERVERS.items():
        db.create_server(name, ip, str(pem_file))
    validation = validate_report(REPORT_FILE.read_bytes(), REPORT_FILE.name, set(SERVERS))
    assert validation.valid, validation.errors
    db.save_report(validation.filename, validation.servers, "VALID")
    return TestClient(app, base_url="http://127.0.0.1"), db, ssh


def test_perl_report_buckets_per_server(perl_web, fake_apt):
    client, db, ssh = perl_web
    response = client.post("/reports/analyze", follow_redirects=False)
    assert response.status_code == 303
    run = db.get_latest_analysis_run(details=True)
    assert [s.server_name for s in run.servers] == list(SERVERS)

    page = client.get(response.headers["location"]).text
    for analysis in run.servers:
        assert analysis.status == "complete", analysis.error
        summary = summarize(analysis)
        assert summary.reported == 6
        assert summary.by_bucket == {ACTION_REQUIRED: 1, INVESTIGATE: 0, NO_ACTION: 5}
        assert summary.cve_status[PERL_CVE] == cr.PATCH_AVAILABLE
        others = {c: s for c, s in summary.cve_status.items() if c != PERL_CVE}
        assert set(others.values()) == {cr.PACKAGE_NOT_INSTALLED}, others

        # The perl remediation: installed ...0.3 -> archive candidate ...0.4, Action required.
        buckets = {b.key: b for b in bucket_groups(remediation_groups(analysis.findings))}
        [perl] = buckets[ACTION_REQUIRED].groups
        assert (perl.source, perl.installed_version, perl.fixed_version) == ("perl", INSTALLED,
                                                                            FIXED)  # fmt: skip
        assert perl.candidate_version == FIXED and perl.status == cr.PATCH_AVAILABLE
        assert buckets[INVESTIGATE].groups == []
        assert buckets[NO_ACTION].cve_count == 5
        assert sorted(p.binary_package for p in analysis.plan) == sorted(
            n.split(":")[0] for n, _ in PERL_BINARIES
        )

        # The rendered per-server summary on the run page.
        item = page[page.index(f"<strong>{analysis.server_name}</strong>") :]
        counters = re.findall(r'class="bucket-count[^"]*">([^<]+)</span>', item)[:3]
        assert counters == ["Action required: 1", "Investigate: 0", "No action: 5"], counters
        report = client.get(f"/analysis/{run.id}/servers/{analysis.id}").text
        assert "Action required: 1 CVE</span>" in report and "No action: 5 CVEs</span>" in report
        assert "apt-get update" not in report and "sudo" not in report

    # Servers stayed read-only: one facts command each, never an APT query.
    assert len(ssh.calls) == len(SERVERS)
    assert not any("apt" in args[-1].replace("/var/lib/dpkg", "") for args in ssh.calls)
    assert len(fake_apt.updates) == 1  # one private noble/amd64 update shared by both servers


def test_perl_candidate_below_fix_is_fix_not_in_repos(perl_web, fake_apt):
    client, db, _ = perl_web
    fake_apt.candidates = perl_candidates(INSTALLED)  # the archive still offers ...0.3
    client.post("/reports/analyze")
    for analysis in db.get_latest_analysis_run(details=True).servers:
        summary = summarize(analysis)
        assert summary.cve_status[PERL_CVE] == cr.FIX_NOT_IN_CONFIGURED_REPOS
        assert summary.by_bucket == {ACTION_REQUIRED: 1, INVESTIGATE: 0, NO_ACTION: 5}
        assert analysis.plan == []
