"""Phase 3 patch execution: approval, revalidation, download, transfer, simulation, install,
verification, cleanup and history. Every remote interaction goes to FakeUbuntu (no network,
no real server); local staging lives under pytest's tmp_path."""

import os
import subprocess
from pathlib import Path

import pytest
from phase3_fixtures import (
    IMAGE,
    IP,
    PLAN,
    SERVER,
    FakeFetcher,
    FakeUbuntu,
    deb_name,
    make_analysis,
    plan_entries,
    plan_uri,
)

from ec2patcher.database import Database
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import nvd, patch_service, staging
from ec2patcher.services import patch_state as ps
from ec2patcher.services.patch_service import PatchNotAllowedError, PatchService

OPENSSL_DEB = deb_name("openssl", "3.0.13-0ubuntu3.6")
REMOTE = f"/tmp/{SERVER}"


def sync(fn):
    fn()


class Harness:
    def __init__(self, db, pem, tmp_path):
        self.db = db
        self.tmp = tmp_path
        self.server = db.create_server(SERVER, IP, str(pem), tags=[("display_name", "Billing API")])
        self.fake = FakeUbuntu()
        self.fetcher = FakeFetcher()
        original = self.fetcher.__call__

        def fetch(url, out, max_bytes, timeout):
            self.fake.calls.append(("fetch", url))
            return original(url, out, max_bytes, timeout)

        self.fetch = fetch
        self.template = f"{tmp_path}/staging/${{server_name}}"
        db.set_setting(patch_service.STAGING_SETTING, self.template)
        self.local = tmp_path / "staging" / SERVER
        self.service = PatchService(db, runner=self.fake, starter=sync, fetcher=fetch)

    def analysis(self, **kwargs):
        return make_analysis(self.db, self.server, **kwargs)

    def approve(self, analysis=None):
        analysis = analysis or self.analysis()
        return self.db.get_execution(self.service.approve(analysis.id))

    @property
    def remote_commands(self) -> list[str]:
        return [c for op, c in self.fake.calls if op not in ("scp", "fetch")]


@pytest.fixture
def h(db, pem_file, tmp_path):
    return Harness(db, pem_file, tmp_path)


def by_name(execution):
    return {p.binary_package: p for p in execution.packages}


# --- happy path ------------------------------------------------------------------------


def test_successful_patch_end_to_end(h):
    analysis = h.analysis()
    assert h.service.eligibility(analysis).allowed
    ex = h.approve(analysis)
    assert ex.state == ps.SUCCESS and ex.decision == ps.APPROVED
    assert ex.error_title is None and ex.failure_stage is None
    ops = h.fake.ops
    # Order: revalidate -> sudo -> downloads -> remote staging -> scp -> verify -> sudo ->
    # simulate -> install -> verify state -> cleanup.
    assert ops[:2] == ["hostname", "sudo"]
    fetches = [i for i, op in enumerate(ops) if op == "fetch"]
    assert len(fetches) == 6 and max(fetches) < ops.index("stage")
    assert ops[ops.index("stage") :] == [
        "stage", "mark", *["scp"] * 6, "stat", "sudo", "simulate", "install", "post", "cleanup",
    ]  # fmt: skip
    # Versions: before / target / after all recorded and verified.
    pkgs = by_name(ex)
    assert (pkgs["openssl"].before_version, pkgs["openssl"].target_version) == (
        "3.0.13-0ubuntu3.4",
        "3.0.13-0ubuntu3.6",
    )
    assert pkgs["openssl"].after_version == "3.0.13-0ubuntu3.6"
    assert pkgs[IMAGE].before_version is None and pkgs[IMAGE].after_version == "6.8.0-1024.26"
    assert all(p.verification_result == "VERIFIED" for p in ex.packages)
    assert all(p.download_result == "DOWNLOADED" for p in ex.packages)
    assert all(p.checksum_result == "VERIFIED" for p in ex.packages)
    assert all(p.transfer_result == "VERIFIED" for p in ex.packages)
    assert all(p.install_result == "INSTALLED" for p in ex.packages)
    assert h.fake.installed("openssl") == "3.0.13-0ubuntu3.6"
    # CVEs verified against Canonical fixed versions (no NVD).
    cves = {(c.cve, c.source_package): c for c in ex.cves}
    assert len(cves) == 4 and all(c.result == "VERIFIED" for c in ex.cves)
    kernel = cves[("CVE-2026-54874", "linux-signed-aws")]
    assert kernel.resulting_version == "6.8.0-1024.26" and "reboot" in kernel.detail
    # Reboot is detected, never performed.
    assert ex.reboot_required_after is True and ex.reboot_required_packages == [IMAGE]
    assert ex.audit_ok is True and ex.install_exit_status == 0
    # Cleanup after success: local and remote staging gone.
    assert ex.cleanup_status == "DELETED"
    assert not h.local.exists() and REMOTE not in h.fake.dirs
    assert ex.local_staging_path == str(h.local) and ex.remote_staging_path == REMOTE
    assert ex.started_at and ex.finished_at and ex.install_started_at and ex.install_finished_at
    # The analysis (BEFORE snapshot) is unchanged.
    again = h.db.get_server_analysis(analysis.id)
    assert [p.current_version for p in again.plan] == [p.current_version for p in analysis.plan]
    assert again.status == "complete"


def test_remote_commands_are_limited_and_explicit(h):
    h.approve()
    joined = "\n".join(h.remote_commands)
    for forbidden in (
        "upgrade", "dist-upgrade", "full-upgrade", "autoremove", "reboot ", "shutdown",
        "systemctl", "service ", "--allow-downgrades", "rm -rf", "*.deb", "curl ", "wget ",
    ):  # fmt: skip
        assert forbidden not in joined, forbidden
    install = next(c for op, c in h.fake.calls if op == "install")
    plain = install.replace("'", "")
    assert "sudo -n env DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get install -y" in (
        plain
    )
    assert "--no-remove" in plain and "--no-download" not in plain
    assert "-o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/dev/null" in plain
    expected = sorted(f"{REMOTE}/{deb_name(p[0], p[3])}" for p in PLAN)
    assert plain.split(" -- ")[1].split(" 2>&1")[0].split() == expected
    simulate = next(c for op, c in h.fake.calls if op == "simulate").replace("'", "")
    assert "apt-get -s -o Dir::Etc::SourceList=/dev/null -o Dir::Etc::SourceParts=/dev/null" in (
        simulate
    )
    assert simulate.split(" -- ")[1].split(" 2>&1")[0].split() == expected
    for op, args in h.fake.calls:
        if op == "scp":
            assert args[:4] == ["scp", "-q", "-i", str(h.server.pem_path)]
            assert "BatchMode=yes" in args and args[-1] == f"ubuntu@{IP}:{REMOTE}/"
            assert args[-3] == "--" and args[-2].startswith(str(h.local) + "/")


def test_no_nvd_or_unexpected_subprocess_during_patch(h, monkeypatch):
    analysis = h.analysis()

    def forbidden(*args, **kwargs):
        raise AssertionError("unexpected external call")

    monkeypatch.setattr(nvd, "http_get", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    assert h.approve(analysis).state == ps.SUCCESS


def test_shared_deb_downloaded_once(h):
    ex = h.approve()
    urls = h.fetcher.calls
    assert len(urls) == len(set(urls)) == 6
    assert sorted(urls) == sorted(plan_uri(p[0], p[3], p[6]) for p in PLAN)
    # openssl .deb fixes two CVEs but was fetched and copied once.
    assert sum(1 for c in ex.cves if c.source_package == "openssl") == 2
    assert sum(1 for op, a in h.fake.calls if op == "scp" and a[-2].endswith(OPENSSL_DEB)) == 1


# --- approval / rejection --------------------------------------------------------------


def test_reject_does_nothing_remote_or_local(h):
    analysis = h.analysis()
    execution_id = h.service.reject(analysis.id)
    ex = h.db.get_execution(execution_id)
    assert ex.state == ps.REJECTED and ex.decision == ps.REJECTED
    assert ex.packages == [] and ex.cves == [] and ex.cleanup_status is None
    assert h.fake.calls == [] and h.fetcher.calls == []
    assert not (h.tmp / "staging").exists()
    assert h.db.get_server_analysis(analysis.id).status == "complete"  # report still viewable
    with pytest.raises(PatchNotAllowedError):
        h.service.approve(analysis.id)
    with pytest.raises(PatchNotAllowedError):
        h.service.reject(analysis.id)
    assert h.fake.calls == []


def test_duplicate_approval_and_patch_twice_blocked(h):
    analysis = h.analysis()
    assert h.approve(analysis).state == ps.SUCCESS
    calls = len(h.fake.calls)
    with pytest.raises(PatchNotAllowedError, match="already recorded"):
        h.service.approve(analysis.id)
    assert len(h.fake.calls) == calls
    assert not h.service.eligibility(analysis).allowed


def test_superseded_report_cannot_be_patched(h):
    old = h.analysis()
    h.analysis()  # newer analysis of the same server
    check = h.service.eligibility(old)
    assert not check.allowed and patch_service.NEWER_ANALYSIS in check.reasons
    with pytest.raises(PatchNotAllowedError, match="A newer analysis exists"):
        h.service.approve(old.id)
    assert h.fake.calls == []


def test_only_one_active_execution(h, db, pem_file):
    started = []
    h.service.starter = started.append  # approved but not yet running
    first = h.analysis()
    other = db.create_server("ip-10-0-0-215", "192.0.2.215", str(pem_file))
    second = make_analysis(db, other)
    h.service.approve(first.id)
    with pytest.raises(PatchNotAllowedError, match="Another patch execution"):
        h.service.approve(second.id)
    # Even a second service instance (e.g. after a double submit) sees the DB lock.
    other_service = PatchService(db, runner=h.fake, starter=sync, fetcher=h.fetch)
    with pytest.raises(PatchNotAllowedError, match="Another patch execution"):
        other_service.approve(second.id)
    started[0]()
    assert h.db.get_execution_for_analysis(first.id).state == ps.SUCCESS
    assert other_service.approve(second.id)


def test_analysis_running_blocks_approval(h):
    h.service.analysis_running = lambda: True
    analysis = h.analysis()
    with pytest.raises(PatchNotAllowedError, match="analysis is currently running"):
        h.service.approve(analysis.id)


def test_server_ip_changed_blocks(h, db):
    analysis = h.analysis()
    db.update_server(h.server.id, SERVER, "192.0.2.99", h.server.pem_path)
    assert not h.service.eligibility(analysis).allowed
    with pytest.raises(PatchNotAllowedError, match="IP address changed"):
        h.service.approve(analysis.id)


def _plan(**changes):
    entries = plan_entries()
    for key, value in changes.items():
        setattr(entries[1], key, value)  # the openssl entry
    return entries


@pytest.mark.parametrize(
    ("kwargs", "reason"),
    [
        ({"plan": _plan(status="unresolved", deb_filename=None)}, "unresolved"),
        ({"plan": _plan(uri=None)}, "download URI"),
        ({"plan": _plan(uri="file:///var/cache/x.deb")}, "download URI"),
        ({"plan": _plan(checksum=None)}, "SHA256 checksum is unavailable"),
        ({"plan": _plan(checksum="MD5Sum:0123")}, "SHA256 checksum is unavailable"),
        ({"plan": _plan(architecture="arm64")}, "architecture"),
        ({"plan": _plan(target_version="not a version")}, "target version is unresolved"),
        ({"plan": _plan(deb_filename="openssl_9.9_amd64.deb")}, "inconsistent"),
        # A row already at target is excluded, not a blocker (see test_stale_state.py).
        ({"plan": []}, "no package updates"),
        ({"plan": [e for e in plan_entries() if "CVE-2026-54874" not in e.cves]},
         "CVE-2026-54874: patch required but there is no exact package plan"),
        ({"status": "failed"}, "analysis of this server failed"),
        ({"remote_hostname": None}, "Incomplete SSH analysis"),
    ],
)  # fmt: skip
def test_incomplete_plans_are_blocked(h, kwargs, reason):
    analysis = h.analysis(**kwargs)
    check = h.service.eligibility(analysis)
    assert not check.allowed
    assert any(reason in r for r in check.reasons), check.reasons
    with pytest.raises(PatchNotAllowedError):
        h.service.approve(analysis.id)
    assert h.fake.calls == [] and h.fetcher.calls == []


def test_analysis_error_finding_blocks(h):
    findings = [
        *plan_findings(),
        cr.Finding("CVE-2026-1", "zlib", cr.ANALYSIS_ERROR, "mapping failed"),
    ]
    check = h.service.eligibility(h.analysis(finding_list=findings))
    assert not check.allowed and any("package mapping failed" in r for r in check.reasons)


def test_metadata_unavailable_finding_blocks(h):
    findings = [
        *plan_findings(),
        cr.Finding("CVE-2026-7", None, cr.METADATA_UNAVAILABLE, "Canonical unreachable"),
    ]
    analysis = h.analysis(finding_list=findings)
    check = h.service.eligibility(analysis)
    assert not check.allowed
    assert any(
        "1 CVE(s) not checked / Canonical metadata unavailable: CVE-2026-7" in r
        for r in check.reasons
    ), check.reasons
    assert check.not_checked_warning.startswith("1 CVE not checked")
    with pytest.raises(PatchNotAllowedError, match="metadata unavailable"):
        h.service.approve(analysis.id)
    assert h.fake.calls == [] and h.fetcher.calls == []


def plan_findings():
    from phase3_fixtures import findings

    return findings()


def test_legitimate_statuses_do_not_block(h):
    findings = [
        *plan_findings(),
        cr.Finding("CVE-2026-2", "vim", cr.PENDING_OR_DEFERRED, "no fix planned"),
        cr.Finding("CVE-2026-3", "sudo", cr.UNKNOWN, "under investigation"),
        cr.Finding("CVE-2026-4", "zlib", cr.ALREADY_FIXED, "fixed", "1", "1"),
        cr.Finding("CVE-2026-5", "zz", cr.PACKAGE_NOT_INSTALLED, "-"),
        cr.Finding("CVE-2026-6", "libxml2", cr.FIX_NOT_IN_CONFIGURED_REPOS, "stale lists"),
    ]
    check = h.service.eligibility(h.analysis(finding_list=findings))
    assert check.allowed, check.reasons
    assert any("CVE-2026-6" in n for n in check.unpatched_notes)


# --- revalidation ------------------------------------------------------------------------


def assert_aborted_before_download(h, ex, title=patch_service.SERVER_CHANGED):
    assert ex.state == ps.FAILED and ex.failure_stage == ps.REVALIDATING
    assert ex.error_title == title
    assert h.fetcher.calls == []
    assert not (h.tmp / "staging").exists()
    assert not {"stage", "scp", "simulate", "install"} & set(h.fake.ops)
    assert ex.cleanup_status == "NOT_NEEDED"


def test_revalidation_same_state_continues(h):
    assert h.approve().state == ps.SUCCESS


def test_revalidation_package_version_changed_aborts(h):
    h.fake.packages[("openssl", "amd64")][0] = "3.0.13-0ubuntu3.5"
    ex = h.approve()
    assert_aborted_before_download(h, ex)
    assert patch_service.DRIFT_MESSAGE in ex.error_summary and "openssl" in ex.error_summary


def test_revalidation_new_dependency_installed_at_other_version_aborts(h):
    # At the exact target version it would be dropped (see test_patch_resilience.py); any
    # other version is drift.
    h.fake.packages[(IMAGE, "amd64")] = [
        "6.8.0-1023.25",
        "linux-signed-aws",
        "6.8.0-1023.25",
        "ii ",
    ]
    assert_aborted_before_download(h, h.approve())


def test_revalidation_release_changed_aborts(h):
    h.fake.os_release = h.fake.os_release.replace('VERSION_ID="24.04"', 'VERSION_ID="26.04"')
    ex = h.approve()
    assert_aborted_before_download(h, ex)
    assert "VERSION_ID changed: 24.04 -> 26.04" in ex.error_summary


def test_revalidation_arch_and_hostname_changed_abort(h):
    h.fake.arch = "arm64"
    h.fake.hostname = "other"
    ex = h.approve()
    assert_aborted_before_download(h, ex)
    assert "Architecture changed: amd64 -> arm64" in ex.error_summary


def test_revalidation_unreachable_aborts(h):
    h.fake.unreachable = True
    ex = h.approve()
    assert_aborted_before_download(h, ex, title=patch_service.PATCH_FAILED)
    assert "timed out" in ex.error_summary.lower()


def test_sudo_unavailable_aborts_before_download(h):
    h.fake.sudo = False
    ex = h.approve()
    assert_aborted_before_download(h, ex, title=patch_service.PATCH_FAILED)
    assert "Passwordless sudo" in ex.error_summary


# --- download ----------------------------------------------------------------------------


def assert_download_failure(h, ex, filename):
    assert ex.state == ps.FAILED and ex.failure_stage in (ps.DOWNLOADING, ps.VERIFYING_DOWNLOADS)
    assert ex.error_package == filename
    assert not {"stage", "mark", "scp", "simulate", "install"} & set(h.fake.ops)
    assert not (h.local / filename).exists()
    assert ex.cleanup_status == "PRESERVED" and str(h.local) in ex.cleanup_detail
    assert h.local.exists()  # preserved for troubleshooting


def test_checksum_mismatch_stops(h):
    url = plan_uri("openssl", "3.0.13-0ubuntu3.6", "o/openssl")
    data = h.fetcher.data[url]
    h.fetcher.override[url] = data[:-1] + b"Z"  # same size, different content
    ex = h.approve()
    assert_download_failure(h, ex, OPENSSL_DEB)
    assert "SHA256 checksum mismatch" in ex.error_summary and OPENSSL_DEB in ex.error_summary
    assert (h.local / f"{OPENSSL_DEB}.part").exists()


def test_size_mismatch_stops(h):
    url = plan_uri("openssl", "3.0.13-0ubuntu3.6", "o/openssl")
    h.fetcher.override[url] = h.fetcher.data[url][:100]
    ex = h.approve()
    assert_download_failure(h, ex, OPENSSL_DEB)
    assert "size mismatch" in ex.error_summary


def test_oversized_response_stops(h):
    url = plan_uri("openssl", "3.0.13-0ubuntu3.6", "o/openssl")
    h.fetcher.override[url] = h.fetcher.data[url] + b"extra"
    ex = h.approve()
    assert_download_failure(h, ex, OPENSSL_DEB)


@pytest.mark.parametrize(
    ("exc", "text"),
    [(OSError("HTTP Error 503: Service Unavailable"), "503"), (TimeoutError(), "timed out")],
)
def test_http_failure_and_timeout(h, exc, text):
    url = plan_uri("openssl", "3.0.13-0ubuntu3.6", "o/openssl")
    h.fetcher.fail[url] = exc
    ex = h.approve()
    assert_download_failure(h, ex, OPENSSL_DEB)
    assert text in ex.error_summary


def test_failed_last_download_means_no_remote_modification(h):
    last = sorted(plan_uri(p[0], p[3], p[6]) for p in PLAN)
    # downloads run in file-name order; fail the last one
    names = sorted(deb_name(p[0], p[3]) for p in PLAN)
    url = next(u for u in last if u.endswith(names[-1]))
    h.fetcher.fail[url] = OSError("connection reset")
    ex = h.approve()
    assert ex.state == ps.FAILED and len(h.fetcher.calls) == 6
    assert h.fake.ops == ["hostname", "sudo", *["fetch"] * 6]


# --- local staging safety ------------------------------------------------------------------


def test_unmanaged_local_files_abort_without_deleting(h):
    h.local.mkdir(parents=True)
    (h.local / "notes.txt").write_text("mine")
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.DOWNLOADING
    assert "not empty and contains unmanaged files" in ex.error_summary
    assert (h.local / "notes.txt").read_text() == "mine"
    assert h.fetcher.calls == [] and "stage" not in h.fake.ops


def test_earlier_failed_run_files_are_kept(h):
    h.local.mkdir(parents=True)
    (h.local / staging.MARKER).write_text("{}")
    old = h.local / "zlib1g_1%3a1.3_amd64.deb"
    old.write_bytes(b"old")
    ex = h.approve()
    assert ex.state == ps.SUCCESS_WITH_CLEANUP_WARNING
    assert old.read_bytes() == b"old" and (h.local / staging.MARKER).exists()
    assert "kept" in ex.cleanup_detail and not (h.local / OPENSSL_DEB).exists()


def test_symlinked_local_staging_is_refused(h):
    (h.tmp / "staging").mkdir()
    (h.tmp / "elsewhere").mkdir()
    h.local.symlink_to(h.tmp / "elsewhere")
    ex = h.approve()
    assert ex.state == ps.FAILED and "symbolic link" in ex.error_summary


def test_setting_change_does_not_change_old_execution(h, db):
    ex = h.approve()
    db.set_setting(patch_service.STAGING_SETTING, "/srv/other/${server_name}")
    assert db.get_execution(ex.id).local_staging_path == str(h.local)


# --- transfer --------------------------------------------------------------------------


def test_transfer_failure_blocks_install(h):
    h.fake.scp_fail = True
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.TRANSFERRING
    assert not {"simulate", "install"} & set(h.fake.ops)
    # A failed copy is retried once, then both staging directories are cleaned up.
    assert h.fake.ops.count("scp") == patch_service.SCP_ATTEMPTS
    assert ex.cleanup_status == "DELETED"
    assert not (h.local / OPENSSL_DEB).exists() and REMOTE not in h.fake.dirs


def test_remote_checksum_mismatch_blocks_install(h):
    h.fake.corrupt_transfer = True
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.VERIFYING_TRANSFER
    assert "checksum mismatch" in ex.error_summary
    assert not {"simulate", "install"} & set(h.fake.ops)
    assert h.fake.dirs[REMOTE]  # remote files preserved


def test_unrelated_remote_content_blocks(h):
    h.fake.dirs[REMOTE] = {"backup.tar": b"precious"}
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.TRANSFERRING
    assert "unmanaged files" in ex.error_summary
    assert h.fake.dirs[REMOTE] == {"backup.tar": b"precious"}
    assert "scp" not in h.fake.ops and "cleanup" not in h.fake.ops


@pytest.mark.parametrize(("attr", "text"), [("symlinks", "symbolic link"), ("foreign", "owned")])
def test_unsafe_remote_directory_blocks(h, attr, text):
    getattr(h.fake, attr).add(REMOTE)
    ex = h.approve()
    assert ex.state == ps.FAILED and text in ex.error_summary and "scp" not in h.fake.ops


def test_remote_leftovers_from_earlier_run_are_accepted(h):
    h.fake.dirs[REMOTE] = {staging.MARKER: b"", OPENSSL_DEB: b"stale partial copy"}
    ex = h.approve()
    assert ex.state == ps.SUCCESS and REMOTE not in h.fake.dirs


# --- simulation --------------------------------------------------------------------------


def assert_simulation_blocked(h, ex, text):
    assert ex.state == ps.FAILED and ex.failure_stage == ps.SIMULATING_INSTALL
    assert text in ex.error_summary, ex.error_summary
    assert "install" not in h.fake.ops
    assert h.fake.installed("openssl") == "3.0.13-0ubuntu3.4"  # nothing changed
    assert ex.cleanup_status == "PRESERVED" and h.fake.dirs[REMOTE] and h.local.exists()


def test_simulation_unexpected_removal_blocks(h):
    h.fake.sim_extra = ["Remv cloud-init [24.1]"]
    assert_simulation_blocked(h, h.approve(), "would remove package(s): cloud-init")


def test_simulation_extra_package_blocks(h):
    h.fake.sim_extra = ["Inst libfoo1 (1.0 local-deb [amd64])"]
    assert_simulation_blocked(h, h.approve(), "Unexpected package in simulation: libfoo1")


def test_simulation_downgrade_blocks(h):
    h.fake.sim_old_override = {"openssl": "3.0.13-0ubuntu3.9"}
    assert_simulation_blocked(h, h.approve(), "DOWNGRADED")


def test_simulation_package_from_repository_blocks(h):
    h.fake.sim_origin = {"openssl": "Ubuntu:24.04/noble-security"}
    assert_simulation_blocked(h, h.approve(), "would not install it from the staged .deb")


@pytest.mark.parametrize(
    "error",
    [
        "E: Unmet dependencies. Try 'apt --fix-broken install' with no packages",
        "E: Package architecture (arm64) does not match system (amd64)",
    ],
)
def test_simulation_apt_errors_block(h, error):
    h.fake.sim_rc = 100
    h.fake.sim_extra = [error]
    assert_simulation_blocked(h, h.approve(), error)


# --- install -----------------------------------------------------------------------------


def test_apt_failure_is_partial_state_and_preserves_files(h):
    h.fake.install_mode = "fail"
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.INSTALLING
    assert ex.error_title == patch_service.PARTIAL_STATE and ex.partial_state_possible
    assert "exit 100" in ex.error_summary and "No automatic retry or rollback" in ex.error_summary
    assert ex.install_exit_status == 100
    assert h.fake.ops.count("install") == 1  # never retried
    assert ex.cleanup_status == "PRESERVED" and h.local.exists() and h.fake.dirs[REMOTE]
    # Actual resulting state recorded (first .deb applied, others not).
    pkgs = by_name(ex)
    assert all(p.install_result == "FAILED" for p in ex.packages)
    assert pkgs["libssl3t64"].after_version == "3.0.13-0ubuntu3.6"  # applied before the error
    assert pkgs["openssl"].after_version == "3.0.13-0ubuntu3.4"
    assert pkgs[IMAGE].after_version is None
    assert pkgs["openssl"].verification_result == "FAILED"


def test_disconnect_then_verified_state_succeeds_with_note(h):
    h.fake.install_mode = "disconnect"
    ex = h.approve()
    assert ex.state == ps.SUCCESS
    assert any("Connection lost" in n for n in ex.notes)
    assert all(p.install_result == "INSTALLED (verified after reconnect)" for p in ex.packages)
    assert h.fake.ops.count("install") == 1


def test_disconnect_without_changes_is_failed_partial(h):
    h.fake.install_mode = "disconnect-none"
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.partial_state_possible
    assert "connection was lost" in ex.error_summary.lower()
    assert ex.cleanup_status == "PRESERVED"


def test_disconnect_and_reconnect_failure_is_unknown(h):
    h.fake.install_mode = "disconnect"
    h.fake.post_fail = True
    ex = h.approve()
    assert ex.state == ps.UNKNOWN and ex.error_title == patch_service.STATE_UNKNOWN
    assert h.fake.ops.count("post") == 1  # exactly one controlled reconnect
    assert ex.cleanup_status == "PRESERVED"


def test_timeout_with_busy_package_manager_is_unknown(h):
    h.fake.install_mode = "timeout"
    h.fake.busy = True
    ex = h.approve()
    assert ex.state == ps.UNKNOWN and "still running" in ex.error_summary


def test_install_ok_but_state_unverifiable_is_unknown(h):
    h.fake.post_fail_after_install = True
    ex = h.approve()
    assert ex.state == ps.UNKNOWN and ex.failure_stage == ps.INSTALLING


# --- post-install verification ------------------------------------------------------------


def test_newer_than_target_is_verified(h):
    h.fake.install_versions = {"openssl": "3.0.13-0ubuntu3.10"}  # Debian: 3.10 > 3.6
    ex = h.approve()
    assert ex.state == ps.SUCCESS
    assert by_name(ex)["openssl"].after_version == "3.0.13-0ubuntu3.10"
    assert "newer" in by_name(ex)["openssl"].detail


def test_still_below_target_fails(h):
    h.fake.install_versions = {"openssl": "3.0.13-0ubuntu3.5"}
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.failure_stage == ps.VERIFYING_INSTALL
    assert by_name(ex)["openssl"].verification_result == "FAILED"
    assert ex.cleanup_status == "PRESERVED" and h.local.exists()


def test_missing_package_after_install_fails(h):
    h.fake.skip = {IMAGE}
    ex = h.approve()
    assert ex.state == ps.FAILED and by_name(ex)[IMAGE].after_version is None
    assert "not installed after the patch" in ex.error_summary


def test_cve_below_canonical_fixed_version_fails(h):
    for name, row in h.fake.debs.items():
        if row[0] == "openssl":
            h.fake.debs[name] = (*row[:4], "3.0.13-0ubuntu3.4")  # source version too low
    ex = h.approve()
    assert ex.state == ps.FAILED
    failed = [c for c in ex.cves if c.result == "FAILED"]
    assert {c.cve for c in failed} == {"CVE-2026-63075", "CVE-2026-63076"}


def test_dpkg_audit_problem_fails(h):
    h.fake.audit = ["The following packages are only half configured:", " openssl"]
    ex = h.approve()
    assert ex.state == ps.FAILED and ex.audit_ok is False
    assert "dpkg --audit" in ex.error_summary and ex.cleanup_status == "PRESERVED"


def test_no_reboot_required(h):
    plan = [e for e in plan_entries() if e.package in ("openssl", "libssl3t64")]
    findings = [f for f in plan_findings() if not f.is_kernel]
    ex = h.approve(h.analysis(plan=plan, finding_list=findings, expected_reboot=False))
    assert ex.state == ps.SUCCESS and ex.reboot_required_after is False
    assert ex.reboot_required_packages == []


# --- cleanup ----------------------------------------------------------------------------


def test_cleanup_failure_after_success_is_warning(h):
    h.fake.cleanup_fail = True
    ex = h.approve()
    assert ex.state == ps.SUCCESS_WITH_CLEANUP_WARNING and ex.cleanup_status == "WARNING"
    assert REMOTE in ex.cleanup_detail
    assert all(p.verification_result == "VERIFIED" for p in ex.packages)


@pytest.mark.parametrize("path", ["/", "/tmp", "/home", "/root", "~", "/var/tmp"])
def test_cleanup_refuses_system_paths(path):
    target = Path(os.path.expanduser(path))
    warning = staging.cleanup_local(target, ["openssl_1_amd64.deb"])
    assert warning and "Refusing" in warning
    assert target.exists()


def test_cleanup_keeps_unrelated_files(tmp_path):
    d = tmp_path / "stage" / SERVER
    d.mkdir(parents=True)
    (d / OPENSSL_DEB).write_bytes(b"x")
    (d / staging.MARKER).write_text("{}")
    (d / "unrelated.txt").write_text("keep")
    warning = staging.cleanup_local(d, [OPENSSL_DEB])
    assert "kept" in warning
    assert not (d / OPENSSL_DEB).exists() and (d / "unrelated.txt").exists()
    assert (d / staging.MARKER).exists()
    (d / "unrelated.txt").unlink()
    assert staging.cleanup_local(d, [OPENSSL_DEB]) is None and not d.exists()
    assert (tmp_path / "stage").exists()  # never the parent


# --- history / persistence ---------------------------------------------------------------


def test_history_persisted_and_never_overwritten(h, db_path):
    first = h.approve()
    second_analysis = h.analysis()  # a new analysis after patching
    h.service.reject(second_analysis.id)
    reopened = Database(db_path)
    executions = reopened.list_executions()
    assert [e.state for e in executions] == [ps.REJECTED, ps.SUCCESS]
    old = reopened.get_execution(first.id)
    assert old.server_name == SERVER and old.display_name == "Billing API"
    assert old.ip_address == IP and old.expected_reboot is True
    assert old.reboot_required_after is True and len(old.packages) == 6 and len(old.cves) == 4
    assert old.analysis_run_id == first.analysis_run_id and old.cleanup_status == "DELETED"
    assert executions[0].packages == []  # rejection: lightweight record only


def test_failure_details_persist(h, db_path):
    h.fake.install_mode = "fail"
    ex = h.approve()
    stored = Database(db_path).get_execution(ex.id)
    assert stored.error_summary == ex.error_summary and stored.failure_stage == ps.INSTALLING
    assert "E: Sub-process" in stored.install_output


# --- state machine -----------------------------------------------------------------------


def test_state_machine_rules():
    assert ps.is_allowed(ps.PENDING_REVIEW, ps.APPROVED)
    assert ps.is_allowed(ps.PENDING_REVIEW, ps.REJECTED)
    assert ps.is_allowed(ps.SIMULATING_INSTALL, ps.INSTALLING)
    for current, target in [
        (ps.REJECTED, ps.INSTALLING),
        (ps.SUCCESS, ps.INSTALLING),
        (ps.PENDING_REVIEW, ps.INSTALLING),
        (ps.APPROVED, ps.INSTALLING),
        (ps.DOWNLOADING, ps.INSTALLING),
        (ps.FAILED, ps.APPROVED),
        (ps.UNKNOWN, ps.SUCCESS),
        (ps.INSTALLING, ps.SUCCESS),
        (ps.REVALIDATING, ps.UNKNOWN),
    ]:
        assert not ps.is_allowed(current, target)
        with pytest.raises(ps.InvalidTransitionError):
            ps.check_transition(current, target)
    assert {ps.REJECTED, ps.SUCCESS, ps.FAILED, ps.UNKNOWN} <= ps.TERMINAL


def test_database_enforces_transitions(h):
    analysis = h.analysis()
    rejected = h.db.get_execution(h.service.reject(analysis.id))
    with pytest.raises(ps.InvalidTransitionError):
        h.db.transition_execution(rejected.id, ps.REJECTED, ps.INSTALLING)
    success = h.approve(h.analysis())
    with pytest.raises(ps.InvalidTransitionError):
        h.db.transition_execution(success.id, ps.SUCCESS, ps.INSTALLING)
    # Compare-and-set: a stale "current" state is refused even for a legal edge.
    with pytest.raises(ps.InvalidTransitionError):
        h.db.transition_execution(success.id, ps.SIMULATING_INSTALL, ps.INSTALLING)
    with pytest.raises(ps.InvalidTransitionError):
        h.db.create_patch_decision(h.analysis(), ps.INSTALLING)


@pytest.mark.parametrize(
    ("state", "expected"),
    [
        (ps.DOWNLOADING, ps.INTERRUPTED),
        (ps.INSTALLING, ps.UNKNOWN),
        (ps.VERIFYING_INSTALL, ps.UNKNOWN),
        (ps.CLEANING_UP, ps.SUCCESS_WITH_CLEANUP_WARNING),
    ],
)
def test_interrupted_executions_on_startup(h, db_path, state, expected):
    h.service.starter = lambda fn: None
    execution_id = h.service.approve(h.analysis().id)
    with h.db.connect() as conn:
        conn.execute("UPDATE patch_executions SET state = ? WHERE id = ?", (state, execution_id))
    reopened = Database(db_path)
    assert reopened.mark_interrupted_executions() == 1
    assert reopened.get_execution(execution_id).state == expected
    assert reopened.active_execution_id() is None


def test_progress_steps(h):
    h.fake.corrupt_transfer = True
    failed = h.approve()
    statuses = [s.status for s in patch_service.progress_steps(failed)]
    assert statuses[:5] == ["done", "done", "done", "done", "failed"]
    assert statuses[5:] == ["pending"] * 5
    h.fake.corrupt_transfer = False
    h.fake.dirs.clear()
    ex = h.approve(h.analysis())  # nothing was installed, so a new analysis can proceed
    steps = patch_service.progress_steps(ex)
    assert [s.status for s in steps] == ["done"] * 10
    assert steps[1].label == "Downloaded 6/6" and steps[3].label == "Transferred 6/6"
