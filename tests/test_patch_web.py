"""Phase 3: staging settings/paths, downloader + SCP units, and the web UI (report decision
area, confirmation, progress/result pages, history and settings)."""

import io
import os
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from phase2_fixtures import make_metadata
from phase3_fixtures import (
    IP,
    PLAN,
    SERVER,
    FakeFetcher,
    FakeUbuntu,
    analysis_plan_output,
    deb_content,
    deb_name,
    make_analysis,
    plan_uri,
    sha,
)
from test_tags import save
from test_web import upload

from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import (
    cve_resolver,
    downloader,
    nvd,
    patch_remote,
    patch_service,
    ssh_service,
    staging,
)
from ec2patcher.services import patch_state as ps


def sync(fn):
    fn()


# --- staging path setting -----------------------------------------------------------------


def test_default_template_is_tmp_server_name():
    assert staging.DEFAULT_LOCAL_TEMPLATE == "/tmp/${server_name}"
    assert staging.resolve_local(staging.DEFAULT_LOCAL_TEMPLATE, SERVER) == Path(f"/tmp/{SERVER}")
    assert staging.remote_dir(SERVER) == f"/tmp/{SERVER}"


def test_setting_persists_and_resets(db, db_path):
    service = patch_service.PatchService(db)
    assert service.staging_template() == "/tmp/${server_name}"
    db.set_setting(patch_service.STAGING_SETTING, "~/patches/${server_name}")
    assert patch_service.PatchService(Database(db_path)).staging_template() == (
        "~/patches/${server_name}"
    )
    db.delete_setting(patch_service.STAGING_SETTING)
    assert service.staging_template() == "/tmp/${server_name}"


def test_home_expansion():
    resolved = staging.resolve_local("~/patches/${server_name}", SERVER)
    assert resolved == Path(os.path.expanduser("~")) / "patches" / SERVER
    assert staging.check_template("~/patches/${server_name}") is None


@pytest.mark.parametrize(
    ("template", "message"),
    [
        ("/tmp", "must contain ${server_name}"),
        ("/", "must contain ${server_name}"),
        ("", "required"),
        ("patches/${server_name}", "absolute path"),
        ("${server_name}", "absolute path"),
        ("../../${server_name}", "traversal"),
        ("/tmp/../${server_name}", "traversal"),
        ("/tmp/x/../../${server_name}", "traversal"),
        ("/${server_name}", "per-server subdirectory"),
        ("~root/${server_name}", "'~user'"),
        ("/tmp/$HOME/${server_name}", "Only the ${server_name} placeholder"),
        ("/tmp/${server_name}\n/x", "invalid characters"),
    ],
)
def test_invalid_templates_rejected(template, message):
    error = staging.check_template(template)
    assert error and message in error, error


@pytest.mark.parametrize(
    "template",
    ["/tmp/${server_name}", "/var/tmp/ec2patcher/${server_name}", "/srv/p/x-${server_name}"],
)
def test_valid_templates(template):
    assert staging.check_template(template) is None


@pytest.mark.parametrize("name", ["../etc", "a/b", "", "..", ".", "x\x00y", "-rf", "a b"])
def test_unsafe_server_names_rejected(name):
    with pytest.raises(staging.StagingError):
        staging.safe_component(name)
    with pytest.raises(staging.StagingError):
        staging.remote_dir(name)


def test_real_server_names_stay_readable():
    for name in ("ip-10-143-76-245", "app_prod.01"):
        assert staging.safe_component(name) == name
        assert staging.resolve_local("/tmp/${server_name}", name) == Path(f"/tmp/{name}")


def test_prepare_local_never_deletes(tmp_path):
    d = tmp_path / "s" / SERVER
    result = staging.prepare_local(d, SERVER, 1)
    assert result.created and oct(d.stat().st_mode & 0o777) == "0o700"
    assert (d / staging.MARKER).exists()
    (d / "foreign.bin").write_text("x")
    with pytest.raises(staging.StagingError, match="unmanaged files"):
        staging.prepare_local(d, SERVER, 2)
    assert (d / "foreign.bin").exists()
    with pytest.raises(staging.StagingError):
        staging.prepare_local(Path("/tmp"), SERVER, 3)


# --- downloader ---------------------------------------------------------------------------


def test_download_is_atomic(tmp_path):
    data = b"deb-data" * 100
    seen = {}

    def fetcher(url, out, max_bytes, timeout):
        out.write(data)
        seen["final_during_download"] = (tmp_path / "a_1_amd64.deb").exists()
        seen["part_during_download"] = (tmp_path / "a_1_amd64.deb.part").exists()

    path = downloader.download(
        "http://archive/pool/a_1_amd64.deb", tmp_path, "a_1_amd64.deb", len(data), sha(data),
        fetcher,
    )  # fmt: skip
    assert seen == {"final_during_download": False, "part_during_download": True}
    assert path.read_bytes() == data and not (tmp_path / "a_1_amd64.deb.part").exists()


def test_download_rejects_wrong_uri(tmp_path):
    with pytest.raises(downloader.DownloadError, match="does not point at"):
        downloader.download("http://a/pool/b_1_amd64.deb", tmp_path, "a_1_amd64.deb", 1, "0" * 64)
    with pytest.raises(downloader.DownloadError, match="Unsupported"):
        downloader.download("ftp://a/a_1_amd64.deb", tmp_path, "a_1_amd64.deb", 1, "0" * 64)


def test_urllib_fetcher_limits_size(monkeypatch):
    class Response(io.BytesIO):
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    monkeypatch.setattr(
        downloader.urllib.request, "urlopen", lambda req, timeout: Response(b"x" * 20)
    )
    out = io.BytesIO()
    with pytest.raises(downloader.DownloadError, match="more than the expected 10"):
        downloader.urllib_fetcher("http://archive/x.deb", out, 10, 5)
    with pytest.raises(downloader.DownloadError):
        downloader.urllib_fetcher("file:///etc/passwd", out, 10, 5)


def test_parse_sha256():
    assert downloader.parse_sha256("SHA256:" + "AB" * 32) == "ab" * 32
    assert downloader.parse_sha256("MD5Sum:" + "ab" * 16) is None
    assert downloader.parse_sha256(None) is None


# --- scp / remote commands ------------------------------------------------------------------


def test_scp_command_is_safe_argument_list(pem_file):
    calls = []

    def runner(args, **kwargs):
        calls.append((args, kwargs))
        import subprocess

        return subprocess.CompletedProcess(args, 0, "", "")

    result = ssh_service.run_scp(IP, str(pem_file), ["/x/a_1_amd64.deb"], "/tmp/srv", runner=runner)
    assert result.ok
    args, kwargs = calls[0]
    assert args[:4] == ["scp", "-q", "-i", str(pem_file)]
    assert args[-3:] == ["--", "/x/a_1_amd64.deb", f"ubuntu@{IP}:/tmp/srv/"]
    assert "shell" not in kwargs and kwargs["stdin"] is not None
    assert ssh_service.build_scp_command("::1", str(pem_file), ["f"], "/tmp/s")[-1] == (
        "ubuntu@[::1]:/tmp/s/"
    )
    assert not ssh_service.run_scp("not-an-ip", str(pem_file), ["f"], "/tmp/s", runner=runner).ok
    assert len(calls) == 1


def test_scp_failure_reported(pem_file):
    import subprocess

    def runner(args, **kwargs):
        return subprocess.CompletedProcess(args, 1, "", "scp: Connection closed")

    result = ssh_service.run_scp(IP, str(pem_file), ["f"], "/tmp/s", runner=runner)
    assert not result.ok and "Connection closed" in result.error


def test_remote_command_builders_validate_inputs():
    with pytest.raises(ValueError):
        patch_remote.install_command("/tmp/../etc", ["a_1_amd64.deb"])
    with pytest.raises(ValueError):
        patch_remote.install_command("/var/x", ["a_1_amd64.deb"])
    with pytest.raises(ValueError):
        patch_remote.install_command("/tmp/s", ["a;reboot_1_amd64.deb"])
    with pytest.raises(ValueError):
        patch_remote.install_command("/tmp/s", [])
    with pytest.raises(ValueError):
        patch_remote.post_install_command(["$(reboot)"])
    command = patch_remote.install_command("/tmp/s", ["a_1%3a2_amd64.deb"])
    assert "/tmp/s/a_1%3a2_amd64.deb" in command and "*" not in command


def test_simulation_never_accepts_incomplete_output():
    result = patch_remote.parse_apt("@@EC2P simulate\nInst a (1 x [amd64])\n", "simulate")
    check = patch_remote.check_simulation(result, {("a", "amd64"): (None, "1")})
    assert not check.ok and "did not complete" in check.problems[0]


# --- web UI -------------------------------------------------------------------------------


@pytest.fixture
def web(db_path, tmp_path, fake_apt):
    # Analysis resolves the plan with the workstation's private APT state, so the plan whose
    # URIs/sizes/checksums match FakeFetcher's content must come from the local APT backend.
    fake_apt.plan = analysis_plan_output()
    state = {"fake": FakeUbuntu(plan_output=analysis_plan_output()), "fetcher": FakeFetcher()}

    def factory():
        meta = make_metadata(tmp_path)
        app = create_app(
            db_path=db_path, ssh_runner=state["fake"], metadata=meta, analysis_starter=sync,
            patch_starter=sync, patch_fetcher=state["fetcher"], shutdown_handler=lambda: None,
        )  # fmt: skip
        return TestClient(app, base_url="http://127.0.0.1")

    factory.state = state
    return factory


def set_staging(c, tmp_path):
    r = c.post("/settings/staging", data={"template": f"{tmp_path}/stage/${{server_name}}"})
    assert r.status_code == 200 and "Settings saved." in r.text


def analyze(c, pem, tmp_path):
    save(c, SERVER, IP, pem, tags=[("display_name", "Billing API")])
    set_staging(c, tmp_path)
    upload(c, {SERVER: ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"]})
    run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
    return re.findall(r'href="(/analysis/\d+/servers/\d+)"', c.get(run_url).text)[0]


def test_full_web_flow_real_analysis_then_patch(web, pem_file, tmp_path, monkeypatch):
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        page = c.get(report_url).text
        assert "Patch Decision" in page and "PENDING REVIEW" in page
        assert f"{tmp_path}/stage/{SERVER}" in page and f"/tmp/{SERVER}" in page
        assert f'href="{report_url}/approve"' in page and "Reject" in page

        confirm = c.get(f"{report_url}/approve").text
        assert "This action will modify installed packages on this server." in confirm
        assert (
            "Billing API" in confirm and IP in confirm and "Approve &amp; Start Patching" in confirm
        )
        assert f"{tmp_path}/stage/{SERVER}" in confirm and f"/tmp/{SERVER}" in confirm
        assert web.state["fake"].ops.count("install") == 0  # confirmation page does nothing

        # Without the confirmation field nothing happens.
        r = c.post(f"{report_url}/approve", follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].endswith("/approve")
        assert "fetch" not in web.state["fake"].ops and web.state["fetcher"].calls == []

        def no_nvd(*args, **kwargs):
            raise AssertionError("NVD must not be called during patch execution")

        monkeypatch.setattr(nvd, "http_get", no_nvd)
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"}, follow_redirects=False)
        assert r.status_code == 303 and r.headers["location"].startswith("/patch/")
        result = c.get(r.headers["location"]).text
        assert "PATCH SUCCESSFUL" in result and "SUCCESS" in result
        assert "Downloaded 6/6" in result and "Transferred 6/6" in result
        assert result.count("&#10003;") == 10
        assert "VERIFIED" in result and "4 of 4 CVE check(s) verified" in result
        assert "Reboot Required After Patch" in result and "<strong>YES</strong>" in result
        assert "EC2Patcher does not reboot servers" in result
        assert "Local and remote staging deleted" in result
        assert '<meta http-equiv="refresh"' not in result

        # Report now shows the decision; approving again is refused.
        page = c.get(report_url).text
        assert "PATCH SUCCESSFUL" in page and "View Patch Execution" in page
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"})
        assert r.status_code == 409 and "already recorded" in r.text
        assert web.state["fake"].ops.count("install") == 1

        history = c.get("/history").text
        assert SERVER in history and "Billing API" in history and "6/6" in history
        assert "4/4 verified" in history

        # A fresh analysis sees the patched versions (Phase 2 remains read-only).
        monkeypatch.undo()
        upload(c, {SERVER: ["CVE-2026-63076"]})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run_page = c.get(run_url).text
        assert "Action required: 0</span>" in run_page and "0 packages to update" in run_page
        assert c.get(report_url).status_code == 200


def test_reject_via_web(web, pem_file, tmp_path):
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        calls_before = len(web.state["fake"].calls)
        r = c.post(f"{report_url}/reject", data={"confirm": "yes"})
        assert r.status_code == 200
        assert "Patching was rejected for this report. No action was taken." in r.text
        assert "REJECTED" in r.text and "No packages were downloaded" in r.text
        assert len(web.state["fake"].calls) == calls_before
        assert web.state["fetcher"].calls == [] and not (tmp_path / "stage").exists()
        assert c.get(f"{report_url}/approve").status_code == 409
        history = c.get("/history").text
        assert "Rejected" in history and SERVER in history


def test_superseded_report_blocked_in_web(web, pem_file, tmp_path):
    with web() as c:
        old_url = analyze(c, pem_file, tmp_path)
        c.post("/reports/analyze")
        page = c.get(old_url).text
        assert patch_service.NEWER_ANALYSIS in page
        assert '<button type="button" class="btn btn-primary" disabled>' in page
        r = c.post(f"{old_url}/approve", data={"confirm": "yes"})
        assert r.status_code == 409 and "A newer analysis exists" in r.text
        assert "install" not in web.state["fake"].ops and web.state["fetcher"].calls == []


def test_failed_analysis_cannot_be_approved(web, pem_file, tmp_path, db_path):
    with web() as c:
        save(c, SERVER, IP, pem_file)
        db = Database(db_path)
        analysis = make_analysis(db, db.get_server_by_name(SERVER), status="failed")
        url = f"/analysis/{analysis.run_id}/servers/{analysis.id}"
        page = c.get(url).text
        assert "The analysis of this server failed." in page
        assert f'href="{url}/approve"' not in page
        assert c.post(f"{url}/approve", data={"confirm": "yes"}).status_code == 409


def test_metadata_unavailable_report_is_not_clean(web, pem_file, tmp_path, db_path):
    with web() as c:
        save(c, SERVER, IP, pem_file)
        db = Database(db_path)
        finding = cve_resolver.Finding(
            "CVE-2026-63076", None, cve_resolver.METADATA_UNAVAILABLE, "Canonical unreachable"
        )
        analysis = make_analysis(db, db.get_server_by_name(SERVER), plan=[], finding_list=[finding])
        url = f"/analysis/{analysis.run_id}/servers/{analysis.id}"
        page = c.get(url).text
        assert "1 CVE not checked (metadata/key status unavailable)" in page
        assert "this report does not mean the server is clean" in page
        assert "No package updates are planned for this server for the CVEs that were checked" in (
            page
        )
        assert "1 CVE(s) not checked / Canonical metadata unavailable: CVE-2026-63076" in page
        assert f'href="{url}/approve"' not in page
        assert c.post(f"{url}/approve", data={"confirm": "yes"}).status_code == 409


def test_failure_page_shows_preserved_paths(web, pem_file, tmp_path):
    web.state["fake"].install_mode = "fail"
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"})
        page = r.text
        assert "PATCH FAILED — PARTIAL STATE POSSIBLE" in page
        assert "Temporary files preserved for troubleshooting." in page
        assert f"{tmp_path}/stage/{SERVER}" in page and f"/tmp/{SERVER}" in page
        assert "Run a new analysis before retrying." in page
        assert "exit 100" in page and "&#10005;" in page


def test_revalidation_abort_page(web, pem_file, tmp_path):
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        web.state["fake"].packages[("openssl", "amd64")][0] = "3.0.13-0ubuntu3.5"
        page = c.post(f"{report_url}/approve", data={"confirm": "yes"}).text
        assert "PATCH ABORTED — SERVER STATE CHANGED" in page
        assert "Package state changed since this report was analyzed." in page
        assert web.state["fetcher"].calls == []


def test_running_execution_page_refreshes(web, pem_file, tmp_path, db_path):
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        c.app.state.patcher.starter = lambda fn: None  # approved, not yet started
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"}, follow_redirects=False)
        page = c.get(r.headers["location"]).text
        assert '<meta http-equiv="refresh" content="3">' in page
        assert "Preflight revalidation" in page and "APPROVED" in page
        other = c.post(f"{report_url}/approve", data={"confirm": "yes"})
        assert other.status_code == 409


def test_reset_database_refused_while_patch_running(web, pem_file, tmp_path, db_path):
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        c.app.state.patcher.starter = lambda fn: None  # approved, not yet started
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"}, follow_redirects=False)
        assert r.status_code == 303
        db = Database(db_path)
        execution_id = db.active_execution_id()
        assert execution_id is not None and c.app.state.patcher.is_running
        assert not c.app.state.analyzer.is_running
        busy = c.post("/settings/reset-database", data={"confirm_text": "RESET"})
        assert busy.status_code == 409
        assert "Database cannot be reset during patching." in busy.text
        assert db.count_servers() == 1 and db.get_latest_report() is not None
        assert db.active_execution_id() == execution_id
        assert db.get_execution(execution_id).state == ps.APPROVED


def test_approve_rejects_cross_site_post(web, pem_file, tmp_path):
    with web() as c:
        report_url = analyze(c, pem_file, tmp_path)
        r = c.post(
            f"{report_url}/approve", data={"confirm": "yes"},
            headers={"origin": "http://evil.example"},
        )  # fmt: skip
        assert r.status_code == 403
        assert "install" not in web.state["fake"].ops


def test_settings_page_save_reset_and_validation(web, pem_file):
    with web() as c:
        page = c.get("/settings").text
        assert "Local Patch Download Directory" in page
        assert 'value="/tmp/${server_name}"' in page and "/tmp/ip-10-0-0-1" in page
        save(c, SERVER, IP, pem_file)
        assert f"/tmp/{SERVER}" in c.get("/settings").text
        r = c.post("/settings/staging", data={"template": "/tmp"})
        assert r.status_code == 422 and "must contain ${server_name}" in r.text
        r = c.post("/settings/staging", data={"template": "/srv/patches/${server_name}"})
        assert "Settings saved." in r.text and f"/srv/patches/{SERVER}" in r.text
        r = c.post("/settings/staging", data={"action": "reset"})
        assert "Settings reset to default." in r.text and 'value="/tmp/${server_name}"' in r.text
        assert c.get("/settings?server=../../etc").status_code == 200


def test_unknown_execution_404(web):
    with web() as c:
        assert c.get("/patch/999").status_code == 404


def test_history_empty_state(web):
    with web() as c:
        assert "No patch operations have been performed yet." in c.get("/history").text


def test_shared_fixture_consistency():
    # Guard: fixture checksums match fixture contents.
    for package, _, _, target, _, _, pool, _, _ in PLAN:
        name = deb_name(package, target)
        assert plan_uri(package, target, pool).endswith(name)
        assert len(sha(deb_content(name))) == 64
    assert ps.SUCCESS in ps.TERMINAL
