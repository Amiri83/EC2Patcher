"""APT candidate parsing and the exact .deb plan (simulation + --print-uris, no download)."""

import pytest
from phase2_fixtures import FIXTURES, PLAN_OUTPUT

from ec2patcher.services import apt_planner as ap

REAL_CANDIDATES = (FIXTURES / "apt_candidates_real.txt").read_text()
REAL_PLAN = (FIXTURES / "apt_plan_real.txt").read_text()
REAL_REQUESTS = [("bluez", "5.85-4ubuntu0.2"), ("libbluetooth3:amd64", "5.85-4ubuntu0.2")]


def test_parse_real_candidates():
    names = ["bluez", "libbluetooth3:amd64", "libc6:amd64", "dbus", "nosuchpkgzz"]
    cands = ap.parse_candidates(REAL_CANDIDATES, names)
    bluez = cands["bluez"]
    assert (bluez.installed, bluez.candidate) == ("5.85-4", "5.85-4ubuntu0.2")
    assert (bluez.source, bluez.source_version) == ("bluez", "5.85-4ubuntu0.2")
    assert bluez.origins == [
        "http://archive.ubuntu.com/ubuntu resolute-updates/main amd64 Packages"
    ]
    lib = cands["libbluetooth3:amd64"]
    assert (lib.source, lib.candidate) == ("bluez", "5.85-4ubuntu0.2")
    # Reboot hooks read from the installed maintainer scripts.
    assert cands["libc6:amd64"].requests_reboot and cands["dbus"].requests_reboot
    assert not bluez.requests_reboot
    # Unknown package: no candidate at all.
    assert cands["nosuchpkgzz"].candidate is None


def test_candidate_source_version_in_parentheses():
    out = (
        "@@EC2P policy\nlinux-image-6.8.0-1024-aws:\n  Installed: (none)\n  Candidate: 6.8.0-1024.26\n"  # noqa: E501
        "@@EC2P show\nPackage: linux-image-6.8.0-1024-aws\nSource: linux-signed-aws (6.8.0-1024.26)\n"  # noqa: E501
        "Version: 6.8.0-1024.26\n\n@@EC2P reboot-hooks\n@@EC2P end\n"
    )
    cand = ap.parse_candidates(out, ["linux-image-6.8.0-1024-aws"])["linux-image-6.8.0-1024-aws"]
    assert cand.installed is None
    assert (cand.source, cand.source_version) == ("linux-signed-aws", "6.8.0-1024.26")


def test_candidate_output_incomplete():
    with pytest.raises(ValueError):
        ap.parse_candidates("@@EC2P policy\n", ["x"])


def test_parse_real_plan_output():
    plan = ap.parse_plan(REAL_PLAN, REAL_REQUESTS)
    assert plan.ok and plan.error is None and plan.removals == []
    by_name = {d.package: d for d in plan.packages}
    # bluez-cups / bluez-obexd are pulled in as required co-upgrades (dependencies).
    assert sorted(by_name) == ["bluez", "bluez-cups", "bluez-obexd", "libbluetooth3"]
    bluez = by_name["bluez"]
    assert (bluez.current_version, bluez.target_version, bluez.architecture) == (
        "5.85-4", "5.85-4ubuntu0.2", "amd64",
    )  # fmt: skip
    assert bluez.deb_filename == "bluez_5.85-4ubuntu0.2_amd64.deb"
    assert bluez.uri == (
        "http://archive.ubuntu.com/ubuntu/pool/main/b/bluez/bluez_5.85-4ubuntu0.2_amd64.deb"
    )
    assert bluez.size == 1550492
    assert bluez.checksum.startswith("SHA256:3d10739644e4")
    assert bluez.release == "Ubuntu:26.04/resolute-updates"


def test_plan_with_new_kernel_dependencies():
    requests = [("linux-aws", "6.8.0.1024.26")]
    plan = ap.parse_plan(PLAN_OUTPUT, requests)
    new = [d for d in plan.packages if d.current_version is None]
    assert {d.package for d in new} == {
        "linux-image-6.8.0-1024-aws",
        "linux-modules-6.8.0-1024-aws",
    }
    assert all(d.deb_filename and d.size for d in plan.packages)


def test_epoch_filename_encoding():
    assert ap.expected_deb_filename("vim", "2:9.1.0016-1ubuntu7.9", "amd64") == (
        "vim_2%3a9.1.0016-1ubuntu7.9_amd64.deb"
    )
    assert ap.expected_deb_filename("libc6:amd64", "2.39-0ubuntu8.6", "amd64") == (
        "libc6_2.39-0ubuntu8.6_amd64.deb"
    )
    out = (
        "@@EC2P simulate\nInst vim [2:9.1.0016-1ubuntu7.8] (2:9.1.0016-1ubuntu7.9 Ubuntu:24.04/"
        "noble-security [amd64])\n@@EC2P simulate-rc\n0\n@@EC2P uris\n'http://security.ubuntu.com/"
        "ubuntu/pool/main/v/vim/vim_2%3a9.1.0016-1ubuntu7.9_amd64.deb' "
        "vim_2%3a9.1.0016-1ubuntu7.9_amd64.deb 1826000 SHA256:aa\n@@EC2P uris-rc\n0\n@@EC2P end\n"
    )
    plan = ap.parse_plan(out, [("vim", "2:9.1.0016-1ubuntu7.9")])
    assert plan.packages[0].deb_filename == "vim_2%3a9.1.0016-1ubuntu7.9_amd64.deb"


def test_epoch_is_absent_from_real_pool_uris():
    """Captured from a real apt 2.7 --print-uris run: the pool file has no epoch."""
    out = (
        "@@EC2P simulate\nInst zlib1g [1:1.3.dfsg-3.1ubuntu2] (1:1.3.dfsg-3.1ubuntu2.2 "
        "Ubuntu:24.04/noble-updates [amd64])\n@@EC2P simulate-rc\n0\n@@EC2P uris\n"
        "'http://archive.ubuntu.com/ubuntu/pool/main/z/zlib/"
        "zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb' "
        "zlib1g_1%3a1.3.dfsg-3.1ubuntu2.2_amd64.deb 64306 SHA256:ab\n@@EC2P uris-rc\n0\n"
        "@@EC2P end\n"
    )
    [deb] = ap.parse_plan(out, [("zlib1g", "1:1.3.dfsg-3.1ubuntu2.2")]).packages
    assert deb.error is None and deb.deb_filename == "zlib1g_1%3a1.3.dfsg-3.1ubuntu2.2_amd64.deb"
    assert deb.uri.endswith("/zlib1g_1.3.dfsg-3.1ubuntu2.2_amd64.deb")
    # A different package's pool file is still rejected.
    bad = out.replace("pool/main/z/zlib/zlib1g_1.3", "pool/main/z/zlib/evil_1.3")
    [deb] = ap.parse_plan(bad, [("zlib1g", "1:1.3.dfsg-3.1ubuntu2.2")]).packages
    assert deb.deb_filename is None and "Unexpected URI" in deb.error


def test_missing_uri_is_not_invented():
    out = REAL_PLAN.replace(
        "'http://archive.ubuntu.com/ubuntu/pool/main/b/bluez/bluez-cups_5.85-4ubuntu0.2_amd64.deb' "
        "bluez-cups_5.85-4ubuntu0.2_amd64.deb 27846 "
        "SHA256:9204262033d802191aecee9f47c3d970c7147ea846bbd22f609c0793ce51ab7a\n",
        "",
    )
    plan = ap.parse_plan(out, REAL_REQUESTS)
    cups = next(d for d in plan.packages if d.package == "bluez-cups")
    assert cups.deb_filename is None and cups.uri is None and cups.size is None
    assert "did not print a download URI" in cups.error


def test_mismatched_uri_rejected():
    out = REAL_PLAN.replace(
        "'http://archive.ubuntu.com/ubuntu/pool/main/b/bluez/bluez_5.85-4ubuntu0.2_amd64.deb'",
        "'http://archive.ubuntu.com/ubuntu/pool/main/b/bluez/evil.deb'",
    )
    bluez = next(d for d in ap.parse_plan(out, REAL_REQUESTS).packages if d.package == "bluez")
    assert bluez.deb_filename is None and "Unexpected URI" in bluez.error


def test_unavailable_version_fails_plan():
    out = (
        "@@EC2P simulate\nE: Version '9.9' for 'bluez' was not found\n@@EC2P simulate-rc\n100\n"
        "@@EC2P uris\nE: Version '9.9' for 'bluez' was not found\n@@EC2P uris-rc\n100\n@@EC2P end\n"
    )
    plan = ap.parse_plan(out, [("bluez", "9.9")])
    assert not plan.ok
    assert "Version '9.9' for 'bluez' was not found" in plan.error


def test_print_uris_failure_marks_every_package_unresolved():
    out = REAL_PLAN.replace("@@EC2P uris-rc\n0", "@@EC2P uris-rc\n100")
    plan = ap.parse_plan(out, REAL_REQUESTS)
    assert plan.ok
    assert all(d.deb_filename is None and "exit status 100" in d.error for d in plan.packages)


@pytest.mark.parametrize("output", ["", "@@EC2P simulate\nInst x\n", "garbage"])
def test_malformed_plan_output(output):
    plan = ap.parse_plan(output, REAL_REQUESTS)
    assert not plan.ok and plan.error


def test_simulation_removals_reported():
    out = REAL_PLAN.replace("Conf bluez ", "Remv bluez-legacy [1.0]\nConf bluez ")
    assert ap.parse_plan(out, REAL_REQUESTS).removals == ["bluez-legacy"]


def test_plan_commands_are_read_only_argument_lists():
    simulate, uris = ap.plan_commands(REAL_REQUESTS)
    assert simulate[:2] == ["-s", "install"] and uris[:2] == ["--print-uris", "install"]
    assert simulate[2:] == uris[2:] == ap.plan_arguments(REAL_REQUESTS)
    args = ap.plan_arguments(REAL_REQUESTS)
    assert "Dir::Cache::archives=/nonexistent/ec2patcher-no-download/" in args
    assert "Acquire::ForceHash=SHA256" in args and "--only-upgrade" in args
    assert args[-3:] == ["--", "bluez=5.85-4ubuntu0.2", "libbluetooth3:amd64=5.85-4ubuntu0.2"]
    for forbidden in ("sudo", "download", "dpkg", "-y", "--yes"):
        assert forbidden not in simulate + uris


def test_transcript_round_trips_through_the_parsers():
    text = ap.transcript([
        ("simulate", REAL_PLAN.split("@@EC2P simulate\n", 1)[1].split("@@EC2P simulate-rc")[0]),
        ("simulate-rc", "0"),
        ("uris", REAL_PLAN.split("@@EC2P uris\n", 1)[1].split("@@EC2P uris-rc")[0]),
        ("uris-rc", "0"),
    ])  # fmt: skip
    assert text.endswith("@@EC2P end\n")
    assert ap.parse_plan(text, REAL_REQUESTS) == ap.parse_plan(REAL_PLAN, REAL_REQUESTS)


@pytest.mark.parametrize(
    "requests",
    [
        [("bluez; rm -rf /", "1.0")],
        [("bluez", "1.0$(id)")],
        [("Bluez", "1.0")],
        [("bluez", "")],
        [("-o", "1.0")],
    ],
)
def test_unsafe_arguments_refused(requests):
    with pytest.raises(ap.UnsafeArgumentError):
        ap.plan_commands(requests)


def test_candidate_arguments_refuse_unsafe_names():
    with pytest.raises(ap.UnsafeArgumentError):
        ap.candidate_arguments(["ok", "bad name"])
    with pytest.raises(ap.UnsafeArgumentError):
        ap.candidate_arguments(["-o"])
    policy, show = ap.candidate_arguments(["libssl3t64:amd64"])
    assert policy == ["policy", "--", "libssl3t64:amd64"]
    assert show == ["show", "--no-all-versions", "--", "libssl3t64:amd64"]
