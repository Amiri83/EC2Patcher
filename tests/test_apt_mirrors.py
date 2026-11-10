"""Corporate networks: APT mirrors (Settings -> APT Repositories), proxies, and the mirror each
lookup used in the report and the Excel exports. Nothing here reaches the network."""

import io
import json
import sqlite3
import urllib.request
from datetime import timedelta

import pytest
import test_cve_sources as sources_tests
from openpyxl import load_workbook
from phase2_fixtures import ScriptedSSH, candidates_output, facts_output, make_metadata

from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.services import (
    apt_planner,
    apt_repos,
    changelog_source,
    cve_resolver,
    cve_sources,
    downloader,
    enrichment,
    excel_export,
    local_apt,
    source_http,
)
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.apt_repos import AptRepos
from ec2patcher.services.security_metadata import CveRecord, SecurityMetadata
from ec2patcher.services.server_state import parse_facts

MIRROR = "https://nexus.example.internal/repository/ubuntu"
SECURITY = "https://nexus.example.internal/repository/ubuntu-security"
PORTS = "https://nexus.example.internal/repository/ubuntu-ports"
PER_RELEASE = "https://nexus.example.internal/repository/ubuntu-${codename}"
KEYRING = "/etc/apt/keyrings/example-archive.gpg"
COMPONENTS = "main restricted universe multiverse"
ARCHIVE = "https://archive.example.internal"
SERVER = "ip-10-0-0-1"

# The sources.list of the code before mirrors existed, verbatim: the defaults must not change it.
TODAY_NOBLE_AMD64 = (
    "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
    "http://archive.ubuntu.com/ubuntu noble main restricted universe multiverse\n"
    "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
    "http://archive.ubuntu.com/ubuntu noble-updates main restricted universe multiverse\n"
    "deb [arch=amd64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
    "http://security.ubuntu.com/ubuntu noble-security main restricted universe multiverse\n"
)
TODAY_JAMMY_ARM64 = (
    "deb [arch=arm64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
    "http://ports.ubuntu.com/ubuntu-ports jammy main restricted universe multiverse\n"
    "deb [arch=arm64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
    "http://ports.ubuntu.com/ubuntu-ports jammy-updates main restricted universe multiverse\n"
    "deb [arch=arm64 signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
    "http://ports.ubuntu.com/ubuntu-ports jammy-security main restricted universe multiverse\n"
)


def mirrors(**extra) -> AptRepos:
    return AptRepos(archive_mirror=MIRROR, security_mirror=SECURITY, ports_mirror=PORTS, **extra)


def facts():
    return parse_facts(facts_output())


# --- defaults: byte-identical to the code without mirrors --------------------------------------


def test_nothing_configured_gives_todays_urls_paths_and_commands(db, tmp_path, fake_apt):
    assert apt_repos.load(db) == apt_repos.DEFAULT and apt_repos.DEFAULT.is_default
    assert apt_repos.preview(apt_repos.load(db), "noble", "amd64") == TODAY_NOBLE_AMD64
    assert apt_repos.preview(apt_repos.load(db), "jammy", "arm64") == TODAY_JAMMY_ARM64
    assert local_apt.sources_list("noble", "amd64") == TODAY_NOBLE_AMD64
    # A LocalApt reading the (empty) settings runs exactly what one without settings runs.
    runs = {}
    for name, repos in (("plain", None), ("settings", apt_repos.provider(db))):
        root = tmp_path / name
        apt = local_apt.LocalApt(root, timedelta(hours=1), repos=repos)
        state = apt.prepare("noble", "amd64")
        sources = (root / "noble-amd64" / "etc" / "sources.list").read_text()
        calls = [[a.replace(str(root), "ROOT") for a in call] for call in fake_apt.calls]
        runs[name] = (sources, calls, state.mirrors)
        fake_apt.calls.clear()
    assert runs["plain"] == runs["settings"]
    assert runs["settings"][0] == TODAY_NOBLE_AMD64
    # The changelog fallback and its probe ask Canonical's hosts, as before.
    fetcher = sources_tests.changelog_fetcher()
    source = changelog_source.ChangelogSource(fetcher=fetcher, repos=apt_repos.provider(db))
    source.find("CVE-2000-0006", "noble", "amd64", ["example-source"])
    assert fetcher.calls == [
        "http://security.ubuntu.com/ubuntu/dists/noble-security/main/binary-amd64/Packages.gz",
        "http://security.ubuntu.com/ubuntu/dists/noble-security/universe/binary-amd64/Packages.gz",
        f"http://security.ubuntu.com/ubuntu/{sources_tests.POOL}/example-binary_1.2-3_amd64.deb",
    ]
    assert source.mirror("noble", "arm64") == "http://ports.ubuntu.com/ubuntu-ports"
    urls = []
    resolver = probing_resolver(db, urls, apt_repos.provider(db))
    resolver.start_run()
    assert sorted(urls) == sorted(url for _, url in cve_sources.PROBE_TARGETS)
    assert "http://security.ubuntu.com/ubuntu/dists/noble-security/Release" in urls


def test_default_settings_save_nothing_and_reset_restores_them(db):
    repos, errors = apt_repos.validate_form({})
    assert errors == {} and repos == apt_repos.DEFAULT
    apt_repos.save(db, mirrors(mirror_changelog=True))
    assert apt_repos.load(db).archive_mirror == MIRROR
    apt_repos.reset(db)
    assert db.get_setting(apt_repos.SETTING) is None and apt_repos.load(db) == apt_repos.DEFAULT


# --- validation ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        MIRROR,
        f"{MIRROR}/",  # the trailing slash is dropped
        PER_RELEASE,
        "http://10.0.0.1:8081/repository/ubuntu",
        "https://nexus.example.internal:8443/repository/${codename}/ubuntu",
    ],
)
def test_valid_mirror_urls(url):
    repos, errors = apt_repos.validate_form({"archive_mirror": url})
    assert errors == {} and repos.archive_mirror == url.rstrip("/")


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("ftp://nexus.example.internal/ubuntu", "Only http:// and https://"),
        ("file:///srv/ubuntu", "Only http:// and https://"),
        ("nexus.example.internal/ubuntu", "Only http:// and https://"),
        ("https://user:secret@nexus.example.internal/ubuntu", "must not contain credentials"),
        ("https://token@nexus.example.internal/ubuntu", "must not contain credentials"),
        (f"{MIRROR}?token=1", "query string"),
        (f"{MIRROR}#top", "fragment"),
        (f"{MIRROR} extra", "spaces or quotes"),
        (f"{MIRROR}\tx", "spaces or quotes"),
        (f'{MIRROR}"', "spaces or quotes"),
        (f"{MIRROR}'", "spaces or quotes"),
        ("https://nexus.example.internal/${release}/ubuntu", "Only the ${codename} placeholder"),
        ("https://nexus.example.internal/${CODENAME}", "Only the ${codename} placeholder"),
        ("https://nexus.example.internal/$HOME", "Only the ${codename} placeholder"),
        ("https://nexus.example.internal/${codename", "Only the ${codename} placeholder"),
        ("https:///ubuntu", "needs a host name"),
        ("https://nexus.example.internal:99999/ubuntu", "invalid port"),
        ("https://nexus.example.internal/" + "a" * 600, "longer than"),
    ],
)
def test_invalid_mirror_urls_are_rejected_with_a_clear_message(url, message):
    for field in apt_repos.URL_FIELDS:
        repos, errors = apt_repos.validate_form({field: url})
        assert repos is None and message in errors[field], (field, errors)


@pytest.mark.parametrize(
    ("path", "ok"),
    [
        (KEYRING, True),
        ("/usr/share/keyrings/ubuntu-archive-keyring.gpg", True),
        ("keyrings/example.gpg", False),
        ("/etc/apt/../shadow", False),
        ("/etc/apt/key ring.gpg", False),
        ("/etc/apt/keyring.gpg]", False),
        ('/etc/apt/"keyring".gpg', False),
    ],
)
def test_keyring_path_validation(path, ok):
    repos, errors = apt_repos.validate_form({"keyring": path})
    assert (repos is not None) is ok and (("keyring" in errors) is not ok)
    if ok:
        assert repos.keyring == path


def test_a_saved_value_that_no_longer_validates_never_reaches_sources_list(db, caplog):
    saved = {"archive_mirror": "https://user:pw@nexus.example.internal/x", "keyring": KEYRING}
    db.set_setting(apt_repos.SETTING, json.dumps(saved))
    repos = apt_repos.load(db)
    assert repos.archive_mirror == local_apt.ARCHIVE_MIRROR and repos.keyring == KEYRING
    assert "user:pw" not in caplog.text  # the URL is never logged with its credentials
    db.set_setting(apt_repos.SETTING, "not json")
    assert apt_repos.load(db) == apt_repos.DEFAULT


# --- the mirrors at work ---------------------------------------------------------------------


def test_local_apt_reads_the_configured_mirrors_and_keyring(db, tmp_path, fake_apt):
    repos = AptRepos(archive_mirror=PER_RELEASE, security_mirror=SECURITY, keyring=KEYRING)
    apt_repos.save(db, repos)
    apt = local_apt.LocalApt(tmp_path / "apt", timedelta(hours=1), repos=apt_repos.provider(db))
    state = apt.prepare("noble", "amd64")
    sources = (state.root / "etc" / "sources.list").read_text()
    archive = "https://nexus.example.internal/repository/ubuntu-noble"

    def line(mirror, suite):
        return f"deb [arch=amd64 signed-by={KEYRING}] {mirror} {suite} {COMPONENTS}\n"

    suites = [(archive, "noble"), (archive, "noble-updates"), (SECURITY, "noble-security")]
    assert sources == "".join(line(m, s) for m, s in suites)
    assert state.mirrors == (archive, archive, SECURITY)
    assert len(fake_apt.updates) == 1
    # Other mirrors: the lists no longer match their sources and are updated again.
    apt_repos.save(db, mirrors())
    apt.start_run()
    arm = apt.prepare("noble", "arm64")
    assert f"{PORTS} noble-security" in (arm.root / "etc" / "sources.list").read_text()
    apt.prepare("noble", "amd64")
    assert len(fake_apt.updates) == 3


def test_changelog_uses_the_mirror_only_when_asked(db):
    apt_repos.save(db, mirrors())
    fetcher = sources_tests.changelog_fetcher()
    source = changelog_source.ChangelogSource(fetcher=fetcher, repos=apt_repos.provider(db))
    source.find("CVE-2000-0006", "noble", "amd64", ["example-source"])
    assert all(url.startswith("http://security.ubuntu.com/ubuntu/") for url in fetcher.calls)
    apt_repos.save(db, mirrors(mirror_changelog=True))
    source.start_run()  # settings are read once per run
    fetcher.calls.clear()
    assert source.find("CVE-2000-0006", "noble", "amd64", ["example-source"]) == (
        {"example-source": "1.2-2"},
        [],
    )
    assert fetcher.calls == [
        f"{SECURITY}/dists/noble-security/main/binary-amd64/Packages.gz",
        f"{SECURITY}/dists/noble-security/universe/binary-amd64/Packages.gz",
        f"{SECURITY}/{sources_tests.POOL}/example-binary_1.2-3_amd64.deb",
    ]
    assert source.mirror("noble", "arm64") == PORTS


def probing_resolver(db, urls, repos):
    def prober(url, timeout):
        urls.append(url)
        return None

    return cve_sources.SourceResolver(
        db,
        SecurityMetadata(db, fetcher=lambda url: {}),
        priority=enrichment.Enrichment(db, fetcher=lambda url: {}),
        prober=prober,
        repos=repos,
    )


def test_the_changelog_probe_asks_the_mirror_and_records_it(db):
    apt_repos.save(db, mirrors(mirror_changelog=True))
    urls = []
    resolver = probing_resolver(db, urls, apt_repos.provider(db))
    results = {r.source: r for r in resolver.start_run()}
    assert f"{SECURITY}/dists/noble-security/Release" in urls
    assert "http://security.ubuntu.com/ubuntu/dists/noble-security/Release" not in urls
    assert results["changelog"].endpoint == "nexus.example.internal"


def test_a_changelog_answer_names_the_mirror_on_the_findings(db):
    apt_repos.save(db, mirrors(mirror_changelog=True))
    changelog = changelog_source.ChangelogSource(
        fetcher=sources_tests.FileFetcher({}), repos=apt_repos.provider(db)
    )
    changelog.find = lambda cve, codename, arch, sources: ({"curl": "8.5.0-2ubuntu10.7"}, [])
    resolver = sources_tests.chain(
        db, sources_tests.FakeSource(packages=["curl"]), sources_tests.FakeSource(), changelog
    )
    (finding,) = cve_resolver.resolve_all(
        ["CVE-2000-0001"], lambda cve: resolver.lookup(cve, facts()), facts()
    )
    assert finding.resolution_source == "changelog"
    assert finding.mirror == f"changelog: {SECURITY}"


def test_apt_candidates_name_the_mirror_that_offered_them():
    cand = apt_planner.Candidate(
        "openssl", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6",
        origins=[f"{SECURITY} noble-security/main amd64 Packages"],
    )  # fmt: skip
    finding = cve_resolver.Finding(
        "CVE-2000-0001", "openssl", cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS,
        installed_version="3.0.13-0ubuntu3.4", fixed_version="3.0.13-0ubuntu3.6",
        binaries=["openssl"],
    )  # fmt: skip
    cve_resolver.apply_candidates([finding], {"openssl": cand}, facts())
    assert finding.status == cve_resolver.PATCH_AVAILABLE
    assert finding.mirror == f"apt: {SECURITY} noble-security"


def nexus_candidates(names):
    return candidates_output(names).replace("http://security.ubuntu.com/ubuntu", SECURITY)


def test_analysis_report_and_exports_show_the_mirror_of_each_lookup(db, pem_file, fake_apt):
    apt_repos.save(db, mirrors())
    fake_apt.candidates = nexus_candidates
    db.create_server(SERVER, "192.0.2.1", str(pem_file))
    db.save_report("report.json", {SERVER: ["CVE-2026-63076"]}, "VALID")
    service = AnalysisService(
        db, make_metadata(None), runner=ScriptedSSH(), starter=lambda fn: fn()
    )
    run = db.get_analysis_run(service.start(db.get_latest_report()))
    sources = (service.apt.state_dir("noble", "amd64") / "etc" / "sources.list").read_text()
    assert f"{MIRROR} noble-updates" in sources and f"{SECURITY} noble-security" in sources
    analysis = run.servers[0]
    openssl = next(f for f in analysis.findings if f.source_package == "openssl")
    assert openssl.status == cve_resolver.PATCH_AVAILABLE
    assert openssl.mirror == f"apt: {SECURITY} noble-security"
    (row,) = db.list_patch_report()
    assert row.mirror == f"apt: {SECURITY} noble-security"
    wb = load_workbook(io.BytesIO(excel_export.build_workbook(run, analysis)))
    rows = list(wb["CVE Findings"].values)
    exported = [dict(zip(rows[0], r, strict=True)) for r in rows[1:]]
    assert rows[0][-1] == "Mirror"
    assert any(r["Mirror"] == f"apt: {SECURITY} noble-security" for r in exported)
    wb = load_workbook(io.BytesIO(excel_export.build_patch_report_workbook([row], [])))
    details = list(wb["Details"].values)
    assert dict(zip(details[0], details[1], strict=True))["Mirror"] == row.mirror


# --- Settings -> APT Repositories ------------------------------------------------------------


def test_settings_card_shows_defaults_and_a_preview(client):
    page = client.get("/settings").text
    assert "<h2>APT Repositories</h2>" in page
    assert f'placeholder="{local_apt.ARCHIVE_MIRROR}"' in page
    assert "The Ubuntu defaults are in use." in page
    assert "http://archive.ubuntu.com/ubuntu noble-updates main" in page  # the preview
    arm = client.get("/settings", params={"apt_release": "jammy", "apt_arch": "arm64"}).text
    assert "http://ports.ubuntu.com/ubuntu-ports jammy-security main" in arm
    assert 'name="allow_unconfirmed_candidates" value="1">' in page  # off by default
    assert 'name="allow_pending_candidates" value="1">' in page


def test_save_validates_redirects_and_is_used_by_the_preview(client, db_path):
    form = {
        "action": "save", "archive_mirror": f"{MIRROR}/", "security_mirror": SECURITY,
        "ports_mirror": "", "keyring": "", "mirror_changelog": "1",
    }  # fmt: skip
    saved = client.post("/settings/apt-repos", data=form, follow_redirects=False)
    assert saved.status_code == 303 and "notice=apt_repos_saved" in saved.headers["location"]
    repos = apt_repos.load(Database(db_path))
    assert (repos.archive_mirror, repos.security_mirror, repos.ports_mirror) == (
        MIRROR, SECURITY, local_apt.PORTS_MIRROR,
    )  # fmt: skip
    assert repos.mirror_changelog and not repos.allow_unconfirmed_candidates
    page = client.get("/settings").text
    assert "APT repositories saved." in page and f"{MIRROR} noble-updates" in page
    assert f'value="{MIRROR}"' in page and "The Ubuntu defaults are in use." not in page


def test_invalid_values_are_refused_like_the_other_settings(client, db_path):
    form = {"action": "save", "archive_mirror": "https://user:pw@nexus.example.internal/x"}
    refused = client.post("/settings/apt-repos", data=form)
    assert refused.status_code == 422
    assert "must not contain credentials" in refused.text and "has-error" in refused.text
    assert "user:pw" not in refused.text  # a typed password is never echoed back
    assert apt_repos.load(Database(db_path)) == apt_repos.DEFAULT


def test_reset_to_defaults(client, db_path):
    apt_repos.save(Database(db_path), mirrors())
    reset = client.post("/settings/apt-repos", data={"action": "reset"}, follow_redirects=False)
    assert reset.status_code == 303 and "notice=apt_repos_reset" in reset.headers["location"]
    assert apt_repos.load(Database(db_path)) == apt_repos.DEFAULT


def test_live_preview_of_typed_values(client):
    ok = client.get(
        "/settings/apt-repos/preview",
        params={"archive_mirror": PER_RELEASE, "apt_release": "jammy", "apt_arch": "amd64"},
    )
    assert ok.status_code == 200 and ok.json()["errors"] == {}
    assert "ubuntu-jammy jammy-updates main" in ok.json()["preview"]
    bad = client.get("/settings/apt-repos/preview", params={"ports_mirror": f"{PORTS}?x=1"})
    assert bad.status_code == 422 and "query string" in bad.json()["errors"]["ports_mirror"]


def test_test_button_fetches_inrelease_per_pocket_without_saving(client, db_path, monkeypatch):
    asked = []

    def fetch(url, out, max_bytes, timeout):
        asked.append(url)
        if "-security/" in url:
            raise OSError("Connection refused")
        out.write(b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA512\n\nOrigin: Ubuntu\n")

    monkeypatch.setattr(source_http, "fetch_to_file", fetch)
    form = {"action": "test", "archive_mirror": MIRROR, "security_mirror": SECURITY}
    page = client.post("/settings/apt-repos", data=form)
    assert page.status_code == 200
    assert asked == [
        f"{MIRROR}/dists/noble/InRelease",
        f"{MIRROR}/dists/noble-updates/InRelease",
        f"{SECURITY}/dists/noble-security/InRelease",
    ]
    assert "Connection refused" in page.text and page.text.count("OK (") == 2
    assert apt_repos.load(Database(db_path)) == apt_repos.DEFAULT  # nothing saved


def test_a_non_inrelease_answer_fails_the_test():
    def fetch(url, out, max_bytes, timeout):
        out.write(b"<html>login</html>")

    (first, *_) = apt_repos.check_pockets(mirrors(), "noble", "amd64", fetch)
    assert not first.ok and "not an InRelease" in first.detail


# --- proxies -----------------------------------------------------------------------------------


@pytest.fixture
def proxy_env(monkeypatch):
    for name in ("http_proxy", "https_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_proxies_follow_the_environment_with_no_proxy(proxy_env):
    proxy_env.setenv("HTTPS_PROXY", "http://proxy.example.internal:3128")
    proxy_env.setenv("HTTP_PROXY", "http://proxy.example.internal:3129")
    proxy_env.setenv("NO_PROXY", "nexus.example.internal,.corp.example.internal")
    assert downloader.proxies_for("https://archive.example.internal/a.deb") == {
        "https": "http://proxy.example.internal:3128"
    }
    assert downloader.proxies_for("http://archive.example.internal/a.deb") == {
        "http": "http://proxy.example.internal:3129"
    }
    assert downloader.proxies_for(f"{MIRROR}/pool/a.deb") == {}
    assert downloader.proxies_for("https://apt.corp.example.internal:8443/a.deb") == {}
    proxy_env.delenv("HTTPS_PROXY")
    assert downloader.proxies_for("https://archive.example.internal/a.deb") == {}


def test_urllib_fetcher_honours_the_proxy_of_the_current_environment(proxy_env, monkeypatch):
    """Reported: .deb downloads ignored HTTPS_PROXY / NO_PROXY set after the first request
    (urlopen keeps the global opener of its first call)."""
    opened = []

    class Response(io.BytesIO):
        pass

    class Opener:
        def __init__(self, proxies):
            self.proxies = proxies

        def open(self, request, timeout):
            opened.append((request.full_url, self.proxies))
            return Response(b"data")

    def build_opener(*handlers):
        (proxy,) = [h for h in handlers if isinstance(h, urllib.request.ProxyHandler)]
        return Opener(dict(proxy.proxies))

    def no_global_opener(*args, **kwargs):
        raise AssertionError("urlopen's cached opener must not be used")

    monkeypatch.setattr(urllib.request, "build_opener", build_opener)
    monkeypatch.setattr(urllib.request, "urlopen", no_global_opener)
    proxy_env.setenv("HTTPS_PROXY", "http://proxy.example.internal:3128")
    proxy_env.setenv("NO_PROXY", "nexus.example.internal")
    out = io.BytesIO()
    downloader.urllib_fetcher(f"{ARCHIVE}/a_1_amd64.deb", out, 10, 5)
    downloader.urllib_fetcher(f"{MIRROR}/pool/a_1_amd64.deb", io.BytesIO(), 10, 5)
    proxy_env.setenv("HTTPS_PROXY", "http://other-proxy.example.internal:8080")
    downloader.urllib_fetcher(f"{ARCHIVE}/b_1_amd64.deb", io.BytesIO(), 10, 5)
    assert out.getvalue() == b"data"
    assert opened == [
        (f"{ARCHIVE}/a_1_amd64.deb", {"https": "http://proxy.example.internal:3128"}),
        (f"{MIRROR}/pool/a_1_amd64.deb", {}),
        (f"{ARCHIVE}/b_1_amd64.deb", {"https": "http://other-proxy.example.internal:8080"}),
    ]


# --- migration 20 ------------------------------------------------------------------------------


def columns(db_path, table):
    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    conn.close()
    return {row[1] for row in rows}


def test_fresh_database_reaches_v20_with_the_mirror_columns(db_path):
    Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 20
    conn.close()
    assert "mirror" in columns(db_path, "cve_findings")
    assert "mirror" in columns(db_path, "patch_report")


@pytest.mark.parametrize("version", [1, 19])
def test_upgrade_to_v20_keeps_existing_data(db_path, version):
    conn = sources_tests.legacy(db_path, version)
    if version == 19:
        conn.execute(
            "INSERT INTO patch_report (server_name, cve, status, source, updated_at) "
            "VALUES ('keep', 'CVE-2000-0001', 'patched', 'oval', 't')"
        )
    conn.commit()
    conn.close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 20
    check.close()
    assert db.get_server_by_name("keep").ip_address == "10.0.0.1"
    assert "mirror" in columns(db_path, "cve_findings")
    if version == 19:
        (row,) = db.list_patch_report()
        assert (row.status, row.source, row.mirror) == ("patched", "oval", None)


def test_v20_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "mirror" in _MIGRATIONS[20]
    assert all("ADD COLUMN mirror" not in _MIGRATIONS[v] for v in range(1, 20))


def test_findings_and_report_rows_keep_their_mirror(db, pem_file):
    from phase3_fixtures import make_analysis

    server = db.create_server(SERVER, "192.0.2.1", str(pem_file))
    finding = cve_resolver.Finding("CVE-2000-0001", "openssl", cve_resolver.ALREADY_FIXED, "ok")
    finding.mirror = f"changelog: {SECURITY}"
    analysis = make_analysis(db, server, plan=[], finding_list=[finding])
    assert analysis.findings[0].mirror == f"changelog: {SECURITY}"
    record = CveRecord(cve="CVE-2000-0001")
    assert record.mirror is None  # only the changelog source sets it
