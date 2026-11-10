"""Opt-in fallbacks when Canonical's data is blocked or incomplete (Settings -> APT
Repositories), the version of a fix pending publication, the OVAL download retry, and the
install command. Off by default; never auto-approved. Nothing here reaches the network."""

import bz2
import io
import shlex
from datetime import timedelta
from urllib.error import HTTPError

import pytest
import test_cve_sources as sources_tests
from fastapi.testclient import TestClient
from phase2_fixtures import facts_output
from phase3_fixtures import IP, SERVER, FakeFetcher, FakeUbuntu, findings, make_analysis

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import (
    analysis_service,
    apt_repos,
    cve_resolver,
    local_apt,
    oval_feed,
    patch_remote,
    patch_service,
)
from ec2patcher.services.os_adapters import AnalysisContext
from ec2patcher.services.os_adapters.ubuntu import UbuntuAdapter
from ec2patcher.services.security_metadata import (
    CveRecord,
    SecurityMetadata,
    parse_cve_document,
    status_entry,
)
from ec2patcher.services.server_state import parse_facts

CVE = "CVE-2000-0001"
FIXED = "3.0.13-0ubuntu3.6"  # the fixtures' APT candidate of openssl / libssl3t64


def facts():
    return parse_facts(facts_output())


def pending_record(version=FIXED, source="openssl"):
    record = CveRecord(cve=CVE, origin="oval")
    record.entries.append(status_entry(source, version, "noble", "pending", "Medium"))
    return record


def unreachable(cve):
    raise OSError("network access is disabled in tests")


def assess(tmp_path, lookup, related=lambda cve: [], unconfirmed=False, pending=False):
    ctx = AnalysisContext(
        metadata=SecurityMetadata(fetcher=lambda url: {}),
        packages=local_apt.LocalApt(tmp_path / "apt", timedelta(hours=1)),
        progress=lambda message: None,
        record=lambda **fields: None,
        lookup=lookup,
        allow_unconfirmed_candidates=unconfirmed,
        allow_pending_candidates=pending,
        related_sources=related,
    )
    return UbuntuAdapter().assess(facts(), [CVE], ctx)


# --- 3. the version of a fix pending publication is kept -----------------------------------------

NOTE = "(note: '3.0.13-0ubuntu3.6')"
PENDING_COMMENTS = (
    f"openssl package in noble is affected. A fix is pending publication {NOTE}.",
    "example-package package in noble is affected. A fix is pending publication.",
)
CRITERIA = "".join(
    f'<criterion test_ref="t{n}" comment="{comment}"/>'
    for n, comment in enumerate(PENDING_COMMENTS, start=1)
)
PENDING_OVAL = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<oval_definitions xmlns="http://oval.mitre.org/XMLSchema/oval-definitions-5"><definitions>'
    '<definition class="vulnerability" id="oval:com.ubuntu.noble:def:1" version="1">'
    "<metadata><title>CVE-2000-0001 on Ubuntu 24.04 LTS (noble) - medium</title>"
    '<reference source="CVE" ref_id="CVE-2000-0001"/></metadata>'
    f"<criteria>{CRITERIA}</criteria></definition></definitions></oval_definitions>"
).encode()


def test_oval_keeps_the_version_of_a_pending_fix_in_the_feed_table(db):
    """Reported: the pending version was dropped by the OVAL parser, so it never reached the
    table and the resolver could not compare it with the mirror's candidate."""
    entries = {e.package: e for e in oval_feed.parse_oval(io.BytesIO(PENDING_OVAL))}
    assert (entries["openssl"].status, entries["openssl"].fixed_version) == ("pending", FIXED)
    assert entries["example-package"].fixed_version is None  # no version named
    fetcher = sources_tests.oval_fetcher(bz2.compress(PENDING_OVAL))
    feed = oval_feed.OvalFeed(db, fetcher=fetcher, now=sources_tests.Clock())
    assert feed.ensure("noble").usable
    rows = {r["package"]: r for r in db.oval_rows(CVE, "noble", feed.feed_name("noble"))}
    assert (rows["openssl"]["status"], rows["openssl"]["fixed_version"]) == ("pending", FIXED)
    (entry,) = [e for e in feed.lookup(CVE, "noble").entries if e.source == "openssl"]
    assert (entry.version, entry.justification) == (FIXED, "pending")


def test_security_metadata_keeps_the_version_of_a_pending_fix_on_the_finding():
    """Reported: a 'pending' CVE carrying a version lost it on the way to the finding."""
    status = {"release_codename": "noble", "status": "pending", "description": FIXED}
    doc = {"id": CVE, "packages": [{"name": "openssl", "statuses": [status]}]}
    record = parse_cve_document(doc, CVE)
    (entry,) = record.for_release("noble")
    assert (entry.version, entry.justification) == (FIXED, "pending")
    (finding,) = [f for f in cve_resolver.resolve_cve(CVE, record, facts()) if f.source]
    assert finding.status == cve_resolver.PENDING_OR_DEFERRED  # by default nothing else changes
    assert finding.fixed_version == FIXED and finding.pocket == "noble"


def test_deferred_or_unversioned_pending_statements_carry_no_version():
    record = CveRecord(cve=CVE)
    record.entries += [
        status_entry("openssl", "2000-01-01", "noble", "deferred", None),
        status_entry("curl", "", "noble", "pending", None),
    ]
    for finding in cve_resolver.resolve_cve(CVE, record, facts()):
        assert finding.status == cve_resolver.PENDING_OR_DEFERRED
        assert finding.fixed_version is None


# --- 3. FIX_AVAILABLE_PENDING_PUBLICATION (opt-in) ------------------------------------------------


def test_pending_fix_reached_by_the_candidate_is_planned_when_allowed(tmp_path, fake_apt):
    result = assess(tmp_path, lambda cve: pending_record(), pending=True)
    (finding,) = [f for f in result.findings if f.source == "openssl"]
    assert finding.status == cve_resolver.FIX_AVAILABLE_PENDING_PUBLICATION
    assert "needs an explicit confirmation" in finding.detail
    assert "libssl3t64:amd64: 3.0.13-0ubuntu3.6" in finding.apt_candidate
    planned = {p.package: p for p in result.plan}
    assert planned["openssl"].target_version == FIXED and CVE in planned["openssl"].cves
    assert any("not confirmed" in w for w in result.warnings)


def test_pending_fix_stays_pending_by_default(tmp_path, fake_apt):
    result = assess(tmp_path, lambda cve: pending_record())
    (finding,) = [f for f in result.findings if f.source == "openssl"]
    assert finding.status == cve_resolver.PENDING_OR_DEFERRED
    assert result.plan == [] and fake_apt.calls == []  # not even an APT query


def test_pending_fix_newer_than_the_candidate_stays_pending(tmp_path, fake_apt):
    result = assess(tmp_path, lambda cve: pending_record("3.0.13-0ubuntu3.7"), pending=True)
    (finding,) = [f for f in result.findings if f.source == "openssl"]
    assert finding.status == cve_resolver.PENDING_OR_DEFERRED
    assert "older than the pending version 3.0.13-0ubuntu3.7" in finding.detail
    assert result.plan == []


def test_kernel_pending_fixes_keep_the_kernel_logic():
    kernel = cve_resolver.Finding(
        CVE, "linux-aws", cve_resolver.PENDING_OR_DEFERRED, "pending",
        installed_version="6.8.0-1021.23", fixed_version="6.8.0-1024.26",
        binaries=["linux-modules-6.8.0-1021-aws"], is_kernel=True,
    )  # fmt: skip
    assert not cve_resolver.needs_unconfirmed_check(kernel, True, True)
    assert cve_resolver.apply_unconfirmed([kernel], {}, facts(), True, True) == []
    assert kernel.status == cve_resolver.PENDING_OR_DEFERRED


# --- 2. CANDIDATE_WITHOUT_METADATA (opt-in) ------------------------------------------------------


def test_unavailable_metadata_with_a_newer_candidate_is_planned_when_allowed(tmp_path, fake_apt):
    related = []

    def sources(cve):
        related.append(cve)
        return ["openssl", "not-installed"]

    result = assess(tmp_path, unreachable, related=sources, unconfirmed=True)
    assert related == [CVE]
    (finding,) = result.findings
    assert (finding.source, finding.status) == ("openssl", cve_resolver.CANDIDATE_WITHOUT_METADATA)
    assert finding.installed_version == "3.0.13-0ubuntu3.4"
    assert finding.failure_reason  # why the metadata is missing stays visible
    assert "not confirmed" in finding.detail
    planned = {p.package: p for p in result.plan}
    assert {"openssl", "libssl3t64"} <= set(planned) and CVE in planned["openssl"].cves


def test_unavailable_metadata_stays_unresolved_by_default(tmp_path, fake_apt):
    result = assess(tmp_path, unreachable, related=lambda cve: ["openssl"])
    (finding,) = result.findings
    assert (finding.source, finding.status) == (None, cve_resolver.METADATA_UNAVAILABLE)
    assert result.plan == [] and fake_apt.calls == []


def test_no_newer_candidate_leaves_the_cve_unresolved(tmp_path, fake_apt):
    # ffmpeg: the fixtures' candidate equals the installed version.
    result = assess(tmp_path, unreachable, related=lambda cve: ["ffmpeg"], unconfirmed=True)
    (finding,) = result.findings
    assert (finding.source, finding.status) == ("ffmpeg", cve_resolver.METADATA_UNAVAILABLE)
    assert "offer no newer version of ffmpeg" in finding.detail
    assert result.plan == []


def test_a_cve_linked_to_no_installed_package_is_left_alone(tmp_path, fake_apt):
    result = assess(tmp_path, unreachable, related=lambda cve: ["not-installed"], unconfirmed=True)
    (finding,) = result.findings
    assert (finding.source, finding.status) == (None, cve_resolver.METADATA_UNAVAILABLE)


def test_the_analysis_reads_the_fallback_settings(db, tmp_path):
    apt_repos.save(db, apt_repos.AptRepos(allow_pending_candidates=True))
    service = analysis_service.AnalysisService(db, SecurityMetadata(db, fetcher=lambda url: {}))
    repos = service.repos()
    assert repos.allow_pending_candidates and not repos.allow_unconfirmed_candidates


# --- never approved without the explicit confirmation ---------------------------------------------


@pytest.fixture
def web(db_path):
    app = create_app(
        db_path=db_path, ssh_runner=FakeUbuntu(), analysis_starter=lambda fn: fn(),
        patch_starter=lambda fn: fn(), patch_fetcher=FakeFetcher(),
        shutdown_handler=lambda: None,
    )  # fmt: skip
    with TestClient(app, base_url="http://127.0.0.1") as client:
        yield client


def unconfirmed_analysis(db, pem, status=cve_resolver.CANDIDATE_WITHOUT_METADATA):
    server = db.create_server(SERVER, IP, str(pem))
    db.set_setting(patch_service.STAGING_SETTING, f"{pem.parent}/stage/${{server_name}}")
    rows = findings()
    rows[0].status = status  # CVE-2026-63076 (openssl): covered by the plan's openssl rows
    analysis = make_analysis(db, server, finding_list=rows)
    done_at = sources_tests.START.isoformat()
    db.update_analysis_run(analysis.run_id, status="completed", completed_at=done_at)
    return analysis


@pytest.mark.parametrize("status", sorted(cve_resolver.UNCONFIRMED_STATUSES))
def test_approve_needs_the_unconfirmed_count(web, db_path, pem_file, status):
    db = Database(db_path)
    analysis = unconfirmed_analysis(db, pem_file, status)
    url = f"/analysis/{analysis.run_id}/servers/{analysis.id}"
    confirm = web.get(f"{url}/approve").text
    assert '<input type="checkbox" name="acknowledged_unconfirmed" value="1" required>' in confirm
    assert "Not confirmed by Canonical" in confirm
    refused = web.post(f"{url}/approve", data={"confirm": "yes", "skip_reboot": "1"})
    assert refused.status_code == 409 and "not confirmed as fixed" in refused.text
    assert db.get_execution_for_analysis(analysis.id) is None
    with pytest.raises(patch_service.PatchNotAllowedError):
        web.app.state.patcher.approve(analysis.id)  # the service refuses too, not just the page
    done = web.post(
        f"{url}/approve",
        data={"confirm": "yes", "acknowledged_unconfirmed": "1", "skip_reboot": "1"},
        follow_redirects=False,
    )
    assert done.status_code == 303 and done.headers["location"].startswith("/patch/")


def test_patch_all_needs_the_unconfirmed_total(web, db_path, pem_file):
    db = Database(db_path)
    analysis = unconfirmed_analysis(db, pem_file)
    url = f"/analysis/{analysis.run_id}/patch-all"
    confirm = web.get(url).text
    assert 'name="acknowledged_unconfirmed" value="1" required' in confirm
    data = {"confirm": "yes", "skip_reboot": "1", "analysis_id": [str(analysis.id)]}
    refused = web.post(url, data=data)
    assert refused.status_code == 409 and "not confirmed as fixed" in refused.text
    assert db.latest_queue_id(analysis.run_id) is None
    done = web.post(url, data={**data, "acknowledged_unconfirmed": "1"}, follow_redirects=False)
    assert done.status_code == 303 and "/patch-all/" in done.headers["location"]


def test_a_plan_without_unconfirmed_upgrades_needs_no_extra_confirm(web, db_path, pem_file):
    db = Database(db_path)
    analysis = make_analysis(db, db.create_server(SERVER, IP, str(pem_file)))
    url = f"/analysis/{analysis.run_id}/servers/{analysis.id}/approve"
    assert 'name="acknowledged_unconfirmed"' not in web.get(url).text
    assert patch_service.unconfirmed_cves(analysis) == []


def test_unconfirmed_findings_are_action_items_in_the_report():
    for status in cve_resolver.UNCONFIRMED_STATUSES:
        assert analysis_service.bucket_for_status(status) == analysis_service.ACTION_REQUIRED
        assert status in cve_resolver.STATUS_LABELS
    statuses = [cve_resolver.CANDIDATE_WITHOUT_METADATA, cve_resolver.METADATA_UNAVAILABLE]
    assert cve_resolver.rollup_status(statuses) == cve_resolver.CANDIDATE_WITHOUT_METADATA


# --- 2. OVAL download: retried twice with backoff ------------------------------------------------


class Flaky:
    """Fails ``failures`` times with ``error``, then serves the feed."""

    def __init__(self, failures, error=None):
        self.failures, self.calls = failures, 0
        self.error = error or OSError("Connection reset by peer")

    def __call__(self, url, out, max_bytes, timeout):
        self.calls += 1
        if self.calls <= self.failures:
            out.write(b"partial")
            raise self.error
        out.write(bz2.compress(sources_tests.OVAL_XML))


def flaky_feed(db, fetcher, monkeypatch, sleeps):
    monkeypatch.setattr(oval_feed, "RETRY_BACKOFF_SECONDS", 2.0)
    return oval_feed.OvalFeed(db, fetcher=fetcher, now=sources_tests.Clock(), sleep=sleeps.append)


def test_oval_download_is_retried_twice_with_backoff(db, monkeypatch):
    sleeps, fetcher = [], Flaky(2)
    state = flaky_feed(db, fetcher, monkeypatch, sleeps).ensure("noble")
    assert state.usable and "downloaded" in state.message
    assert fetcher.calls == 3 and sleeps == [2.0, 4.0]


def test_oval_gives_up_after_the_retries(db, monkeypatch):
    sleeps, fetcher = [], Flaky(5)
    state = flaky_feed(db, fetcher, monkeypatch, sleeps).ensure("noble")
    assert not state.usable and "Connection reset by peer" in state.problem
    assert fetcher.calls == 3 and sleeps == [2.0, 4.0]


@pytest.mark.parametrize("code", [403, 404])
def test_a_definite_http_answer_is_not_retried(db, monkeypatch, code):
    sleeps = []
    fetcher = Flaky(5, HTTPError("https://example.invalid", code, "No", None, None))
    flaky_feed(db, fetcher, monkeypatch, sleeps).ensure("noble")
    assert fetcher.calls == 1 and sleeps == []


def test_a_retried_server_error_succeeds(db, monkeypatch):
    sleeps = []
    fetcher = Flaky(1, HTTPError("https://example.invalid", 503, "Busy", None, None))
    assert flaky_feed(db, fetcher, monkeypatch, sleeps).ensure("noble").usable
    assert fetcher.calls == 2 and sleeps == [2.0]


# --- 4. the install command ----------------------------------------------------------------------


def test_install_uses_absolute_deb_paths_and_never_no_download():
    remote = "/tmp/ip-10-0-0-1"
    debs = ["example-package_1.0-1ubuntu0.1_amd64.deb", "libexample1_1.0-1ubuntu0.1_amd64.deb"]
    for build in (patch_remote.install_command, patch_remote.simulate_command):
        tokens = shlex.split(build(remote, debs))
        end = next(i for i, token in enumerate(tokens) if token.startswith("2>&1"))
        argv = tokens[tokens.index("sudo") : end]
        assert argv[:2] == ["sudo", "-n"] and "apt-get" in argv
        assert "--no-download" not in argv and not any("no-download" in a for a in argv)
        operands = argv[argv.index("--") + 1 :]
        assert operands == [f"{remote}/{name}" for name in debs]
        assert all(o.startswith("/") and o.endswith(".deb") for o in operands)
        assert not any(a in argv for a in ("upgrade", "dist-upgrade", "full-upgrade"))
