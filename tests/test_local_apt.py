"""Workstation-side APT resolution against a private per-release state (no sudo, no server)."""

import subprocess
from datetime import datetime, timedelta, timezone

import pytest
from phase2_fixtures import (
    FakeApt,
    ScriptedSSH,
    apt_operands,
    apt_options,
    facts_output,
    make_metadata,
)

from ec2patcher import config
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services import local_apt
from ec2patcher.services.analysis_service import AnalysisService
from ec2patcher.services.server_state import parse_facts

T0 = datetime(2026, 9, 29, 12, 0, tzinfo=timezone.utc)


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def backend():
    return FakeApt()


@pytest.fixture
def apt(tmp_path, backend, clock):
    return local_apt.LocalApt(tmp_path / "apt", timedelta(hours=6), runner=backend, clock=clock)


def facts(**kwargs):
    return parse_facts(facts_output(**kwargs))


# --- private state ------------------------------------------------------------------------


def test_private_state_layout_and_sources_match_the_server(apt, tmp_path, backend):
    state = apt.prepare("noble", "amd64")
    root = tmp_path / "apt" / "noble-amd64"
    assert state.root == root and state.updated_at == T0
    for sub in ("etc/sources.list.d", "etc/preferences.d", "etc/trusted.gpg.d",
                "state/lists/partial", "cache/archives/partial", "status"):  # fmt: skip
        assert (root / sub).is_dir(), sub
    assert list((root / "etc" / "sources.list.d").iterdir()) == []
    sources = (root / "etc" / "sources.list").read_text().splitlines()
    assert sources == [
        f"deb [arch=amd64 signed-by={local_apt.KEYRING}] {mirror} {suite} "
        "main restricted universe multiverse"
        for mirror, suite in (
            ("http://archive.ubuntu.com/ubuntu", "noble"),
            ("http://archive.ubuntu.com/ubuntu", "noble-updates"),
            ("http://security.ubuntu.com/ubuntu", "noble-security"),
        )
    ]
    assert "proposed" not in "".join(sources) and "backports" not in "".join(sources)
    assert (root / "state" / local_apt.STAMP_NAME).exists()
    assert {
        p.name.split("_dists_")[1].split("_")[0]
        for p in (root / "state" / "lists").glob("*_Packages")
    } == {  # fmt: skip
        "noble",
        "noble-updates",
        "noble-security",
    }


def test_arm64_uses_ports_and_its_own_state(apt, tmp_path):
    state = apt.prepare("jammy", "arm64")
    assert state.root == tmp_path / "apt" / "jammy-arm64"
    sources = (state.root / "etc" / "sources.list").read_text()
    assert sources.count("http://ports.ubuntu.com/ubuntu-ports") == 3
    assert "[arch=arm64 " in sources and "archive.ubuntu.com" not in sources


def test_update_runs_on_the_private_dir_only_with_o_flags(apt, tmp_path, backend):
    apt.prepare("noble", "amd64")
    [update] = backend.updates
    root = tmp_path / "apt" / "noble-amd64"
    assert update[0] == "apt-get" and apt_operands(update) == ["-q", "update"]
    assert "sudo" not in update
    opts = apt_options(update)
    assert opts["Dir::State"] == str(root / "state")
    assert opts["Dir::Cache"] == str(root / "cache")
    assert opts["Dir::Etc::sourcelist"] == str(root / "etc" / "sources.list")
    assert opts["Dir::Etc::sourceparts"] == str(root / "etc" / "sources.list.d")
    assert opts["Dir::State::status"] == str(root / "status" / "empty")
    assert (opts["APT::Architecture"], opts["APT::Architectures"]) == ("amd64", "amd64")
    # Every path-valued setting stays inside the private state: never /etc/apt or /var/lib/apt.
    paths = [v for k, v in opts.items() if k.startswith("Dir::") and v]
    assert paths and all(v.startswith(str(root)) for v in paths), paths
    # The workstation's apt.conf / apt.conf.d (and their APT::Update hooks) are never read.
    [env] = backend.envs
    assert env["APT_CONFIG"] == str(root / "etc" / "apt.conf") and env["LC_ALL"] == "C"
    conf = (root / "etc" / "apt.conf").read_text()
    assert f'Dir::Etc::parts "{root / "etc" / "apt.conf.d"}";' in conf
    assert f'Dir::Etc::main "{root / "etc" / "apt.conf.main"}";' in conf
    assert list((root / "etc" / "apt.conf.d").iterdir()) == []


def test_relative_state_root_is_made_absolute(backend, monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    apt = local_apt.LocalApt("rel-apt", timedelta(hours=1), runner=backend)
    assert apt.root == tmp_path / "rel-apt"  # apt would resolve relative Dir:: against /
    apt.prepare("noble", "amd64")
    assert apt_options(backend.calls[0])["Dir::State"].startswith(str(tmp_path))


def test_update_cadence_follows_max_age(apt, backend, clock):
    apt.prepare("noble", "amd64")
    apt.prepare("noble", "amd64")  # same run: never twice
    assert len(backend.updates) == 1
    apt.start_run()
    clock.now = T0 + timedelta(hours=5)
    assert apt.prepare("noble", "amd64").updated_at == T0  # still fresh: reused
    assert len(backend.updates) == 1
    apt.start_run()
    clock.now = T0 + timedelta(hours=7)
    assert apt.prepare("noble", "amd64").updated_at == clock.now  # too old: refreshed
    assert len(backend.updates) == 2


def test_zero_max_age_updates_every_run(tmp_path, backend, clock):
    apt = local_apt.LocalApt(tmp_path / "apt", timedelta(0), runner=backend, clock=clock)
    for _ in range(3):
        apt.start_run()
        apt.prepare("noble", "amd64")
    assert len(backend.updates) == 3


def test_lists_missing_or_sources_changed_force_an_update(apt, backend, tmp_path):
    root = apt.prepare("noble", "amd64").root
    apt.start_run()
    for path in (root / "state" / "lists").glob("*noble-security*"):
        path.unlink()
    apt.prepare("noble", "amd64")
    assert len(backend.updates) == 2
    # A tampered sources.list is rewritten before use (the lists still match the stamp).
    apt.start_run()
    (root / "etc" / "sources.list").write_text("deb http://example.invalid/ubuntu noble main\n")
    apt.prepare("noble", "amd64")
    assert "example.invalid" not in (root / "etc" / "sources.list").read_text()
    assert len(backend.updates) == 2
    # Different sources (here: keyring) invalidate the stamp and refresh the lists.
    apt.start_run()
    apt.keyring = "/usr/share/keyrings/other.gpg"
    apt.prepare("noble", "amd64")
    assert len(backend.updates) == 3


def test_failed_update_raises_and_never_fakes_candidates(apt, backend, tmp_path):
    backend.update_error = (
        "E: Failed to fetch http://archive.ubuntu.com/ubuntu/dists/noble/InRelease"
    )
    with pytest.raises(local_apt.AptResolutionError, match="Failed to fetch"):
        apt.prepare("noble", "amd64")
    with pytest.raises(local_apt.AptResolutionError):  # remembered for this run
        apt.prepare("noble", "amd64")
    assert len(backend.updates) == 1
    assert not (tmp_path / "apt" / "noble-amd64" / "state" / local_apt.STAMP_NAME).exists()
    backend.update_error = None
    apt.start_run()  # the next run retries
    assert apt.prepare("noble", "amd64").updated_at == T0


def test_update_without_indexes_is_a_failure(apt, backend, monkeypatch):
    def no_lists(args, **kwargs):
        backend.calls.append(args)
        return subprocess.CompletedProcess(args, 0, "", "")

    apt.runner = no_lists
    with pytest.raises(local_apt.AptResolutionError, match="no package index for noble"):
        apt.prepare("noble", "amd64")


def test_missing_apt_binary_is_reported(apt):
    def missing(*args, **kwargs):
        raise FileNotFoundError("apt-get")

    apt.runner = missing
    with pytest.raises(local_apt.AptResolutionError, match="'apt-get' was not found"):
        apt.prepare("noble", "amd64")


@pytest.mark.parametrize("codename, arch", [("xenial", "amd64"), ("noble", "amd64 x"),
                                            ("noble", "../x")])  # fmt: skip
def test_unexpected_release_or_architecture_refused(apt, backend, codename, arch):
    with pytest.raises(local_apt.AptResolutionError):
        apt.prepare(codename, arch)
    assert backend.calls == []


# --- queries --------------------------------------------------------------------------------


def test_candidates_use_a_status_file_rebuilt_from_dpkg_query(apt, backend):
    f = facts()
    state = apt.prepare("noble", "amd64")
    cands = apt.candidates(state, f, ["libssl3t64:amd64", "openssl"])
    assert cands["openssl"].candidate == "3.0.13-0ubuntu3.6"
    assert cands["libssl3t64:amd64"].requests_reboot  # from the server's reboot-hooks facts
    policy, show = [c for c in backend.calls if c[0] == "apt-cache"]
    assert apt_operands(policy) == ["policy", "--", "libssl3t64:amd64", "openssl"]
    assert apt_operands(show)[:2] == ["show", "--no-all-versions"]
    status = backend.statuses[0]
    assert "Package: libssl3t64\nStatus: install ok installed\nArchitecture: amd64\n" in status
    assert "Package: linux-image-6.8.0-1021-aws" in status and "nginx-common" not in status
    assert list((state.root / "status").glob("*.status")) == []  # temporary, removed again


def test_plan_runs_simulation_and_print_uris_only(apt, backend):
    state = apt.prepare("noble", "amd64")
    requests = [("libssl3t64:amd64", "3.0.13-0ubuntu3.6"), ("openssl", "3.0.13-0ubuntu3.6")]
    plan = apt.plan(state, facts(), requests)
    assert plan.ok and {d.package for d in plan.packages} >= {"libssl3t64", "openssl"}
    runs = [c for c in backend.calls if c[0] == "apt-get"][1:]
    assert [apt_operands(r)[:2] for r in runs] == [["-s", "install"], ["--print-uris", "install"]]
    for args in runs:
        assert apt_options(args)["Dir::Cache::archives"] == "/nonexistent/ec2patcher-no-download/"
    assert plan.apt_arguments[:2] == ["install", "-qq"]


def test_plan_refuses_unsafe_requests_without_running_apt(apt, backend):
    state = apt.prepare("noble", "amd64")
    before = len(backend.calls)
    plan = apt.plan(state, facts(), [("bash; rm -rf /", "1.0")])
    assert not plan.ok and "Refusing" in plan.error and len(backend.calls) == before


# --- analysis ---------------------------------------------------------------------------------


@pytest.fixture
def one_server(db, pem_file):
    db.create_server("ip-10-0-0-245", "192.0.2.245", str(pem_file))
    return db


def analyze(db, tmp_path, backend, cves):
    db.save_report("r.json", {"ip-10-0-0-245": cves}, "VALID")
    ssh = ScriptedSSH()
    apt = local_apt.LocalApt(tmp_path / "private-apt", timedelta(hours=6), runner=backend)
    service = AnalysisService(db, make_metadata(tmp_path), runner=ssh, starter=lambda fn: fn(),
                              apt=apt)  # fmt: skip
    run = db.get_analysis_run(service.start(db.get_latest_report()))
    return run.servers[0], ssh


def test_candidate_at_or_above_fix_is_action_required(one_server, tmp_path, backend):
    good, ssh = analyze(one_server, tmp_path, backend, ["CVE-2026-63076"])
    [openssl] = [f for f in good.findings if f.source_package == "openssl"]
    assert openssl.status == cr.PATCH_AVAILABLE  # candidate 3.0.13-0ubuntu3.6 == fix
    assert any(p.binary_package == "libssl3t64" and p.deb_filename for p in good.plan)
    assert backend.updates and all(
        apt_options(c)["Dir::State"] == str(tmp_path / "private-apt" / "noble-amd64" / "state")
        for c in backend.calls
    )
    assert [args[-1].count("apt") for args in ssh.calls] == [0]  # facts only, no apt at all


def test_candidate_below_fix_is_fix_not_in_configured_repos(one_server, tmp_path, backend):
    good, ssh = analyze(one_server, tmp_path, backend, ["CVE-2026-10008"])
    [libxml2] = good.findings
    assert libxml2.status == cr.FIX_NOT_IN_CONFIGURED_REPOS  # candidate ...3.4 < fix ...3.5
    assert "noble, noble-updates, noble-security" in libxml2.detail
    assert good.plan == [] and len(ssh.calls) == 1


def test_no_candidate_check_needed_means_no_apt_at_all(one_server, tmp_path, backend):
    good, _ = analyze(one_server, tmp_path, backend, ["CVE-2026-10005"])  # not installed
    assert good.findings[0].status == cr.PACKAGE_NOT_INSTALLED
    assert backend.calls == [] and good.apt_updated_at is None


# --- configuration ------------------------------------------------------------------------------


def test_config_defaults_and_overrides(tmp_path, monkeypatch):
    data = tmp_path / "data"
    assert config.get_apt_state_dir(data) == data / "apt"
    assert config.get_apt_max_age() == timedelta(hours=config.DEFAULT_APT_MAX_AGE_HOURS)
    monkeypatch.setenv(config.APT_STATE_DIR_ENV, str(tmp_path / "elsewhere"))
    monkeypatch.setenv(config.APT_MAX_AGE_ENV, "0.5")
    assert config.get_apt_state_dir(data) == tmp_path / "elsewhere"
    assert config.get_apt_max_age() == timedelta(minutes=30)
    assert config.get_apt_state_dir(data, str(tmp_path / "cli")) == tmp_path / "cli"
    assert config.get_apt_max_age(0) == timedelta(0)
    for bad in ("-1", "nan", "soon"):
        monkeypatch.setenv(config.APT_MAX_AGE_ENV, bad)
        with pytest.raises(ValueError):
            config.get_apt_max_age()


def test_app_puts_the_private_state_under_the_data_dir(make_client, db_path):
    with make_client() as client:
        apt = client.app.state.analyzer.apt
        assert apt.root == db_path.parent / "apt" and apt.max_age == timedelta(hours=6)
        page = client.get("/settings").text
        assert str(db_path.parent / "apt") in page and "6 hours" in page


def test_default_runner_is_never_the_real_apt_in_tests():
    assert isinstance(local_apt.default_runner, FakeApt)
