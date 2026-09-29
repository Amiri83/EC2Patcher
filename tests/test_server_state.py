"""Remote facts parsing: release, architecture, kernel, reboot state and package inventory."""

import pytest
from phase2_fixtures import NOBLE_OS_RELEASE, NOBLE_PACKAGES, facts_output

from ec2patcher.services import server_state as st


def test_parse_noble_facts():
    facts = st.parse_facts(facts_output())
    assert facts.hostname == "ip-10-143-76-245"
    assert (facts.version_id, facts.codename, facts.os_id) == ("24.04", "noble", "ubuntu")
    assert facts.pretty_name == "Ubuntu 24.04.3 LTS"
    assert facts.architecture == "amd64"
    assert facts.kernel == "6.8.0-1021-aws"
    assert facts.reboot_required is False and facts.reboot_required_pkgs == []
    assert facts.reboot_hooks == {"libssl3t64:amd64"}
    assert facts.warnings == []
    assert st.check_supported(facts) is None


@pytest.mark.parametrize(
    "version_id, codename",
    [("20.04", "focal"), ("22.04", "jammy"), ("24.04", "noble"), ("26.04", "resolute")],
)
def test_supported_releases(version_id, codename):
    os_release = NOBLE_OS_RELEASE.replace("24.04", version_id).replace("noble", codename)
    facts = st.parse_facts(facts_output(os_release=os_release))
    assert (facts.version_id, facts.codename) == (version_id, codename)
    assert st.check_supported(facts) is None


def test_unsupported_release_and_os():
    old = NOBLE_OS_RELEASE.replace("24.04", "16.04").replace("noble", "xenial")
    assert "Unsupported Ubuntu release: 16.04" in st.check_supported(
        st.parse_facts(facts_output(os_release=old))
    )
    debian = (
        'PRETTY_NAME="Debian GNU/Linux 12"\nID=debian\nVERSION_ID="12"\nVERSION_CODENAME=bookworm'
    )
    assert "Unsupported operating system" in st.check_supported(
        st.parse_facts(facts_output(os_release=debian))
    )
    mismatch = NOBLE_OS_RELEASE.replace("VERSION_CODENAME=noble", "VERSION_CODENAME=jammy")
    assert "expected 'noble'" in st.check_supported(
        st.parse_facts(facts_output(os_release=mismatch))
    )


def test_reboot_required_detected():
    out = facts_output(reboot="yes", reboot_pkgs=["linux-base", "libc6", "linux-base"])
    facts = st.parse_facts(out)
    assert facts.reboot_required is True
    assert facts.reboot_required_pkgs == ["libc6", "linux-base"]


def test_binary_to_source_mapping():
    facts = st.parse_facts(facts_output())
    by_source = facts.by_source()
    # Several binaries from one source package.
    assert sorted(p.name for p in by_source["openssl"]) == ["libssl3t64:amd64", "openssl"]
    assert sorted(p.name for p in by_source["curl"]) == ["curl", "libcurl4t64:amd64"]
    # Binary name differs from source; epoch preserved.
    assert by_source["ffmpeg"][0].name == "libavcodec60:amd64"
    assert by_source["vim"][0].source_version == "2:9.1.0016-1ubuntu7.8"
    # The kernel image comes from linux-signed-aws, the modules from linux-aws.
    assert by_source["linux-signed-aws"][0].name == "linux-image-6.8.0-1021-aws"
    # Removed-but-configured ("rc") packages are not installed.
    assert "nginx" not in by_source
    # Lookup by arch-qualified or plain name.
    names = facts.by_name()
    assert names["libssl3t64"].name == "libssl3t64:amd64"


def test_source_version_differs_from_binary_version():
    rows = [("libfoo1:amd64", "1.2-3build1", "foo", "1.2-3", "amd64", "ii ")]
    packages, malformed = st.parse_dpkg_inventory(["\t".join(r) for r in rows])
    assert malformed == 0
    assert (packages[0].version, packages[0].source_version) == ("1.2-3build1", "1.2-3")


def test_empty_source_fields_fall_back_to_binary():
    packages, _ = st.parse_dpkg_inventory(["mypkg\t1.0-1\t\t\tall\tii "])
    assert (packages[0].source, packages[0].source_version) == ("mypkg", "1.0-1")


def test_malformed_inventory_rows_counted():
    rows = ["\t".join(NOBLE_PACKAGES[0]), "garbage line", "bad name!\t1.0\tx\t1.0\tamd64\tii "]
    packages, malformed = st.parse_dpkg_inventory(rows)
    assert len(packages) == 1 and malformed == 2
    facts = st.parse_facts(
        facts_output(packages=[NOBLE_PACKAGES[0]]).replace("@@EC2P end", "junk\n@@EC2P end")
    )
    assert "1 package inventory row(s) could not be parsed." in facts.warnings


def test_relationship_columns_are_kept_for_local_apt_resolution():
    depends = "perl-base (= 5.38.2-3.2ubuntu0.3), libperl5.38t64 (= 5.38.2-3.2ubuntu0.3)"
    row = "\t".join([
        "perl", "5.38.2-3.2ubuntu0.3", "perl", "5.38.2-3.2ubuntu0.3", "amd64", "ii ",
        "allowed", "", "", depends, "", "", "",
    ])  # fmt: skip
    packages, malformed = st.parse_dpkg_inventory([row])
    assert malformed == 0
    assert packages[0].relations == {"Multi-Arch": "allowed", "Depends": depends}
    assert st.parse_dpkg_inventory(["\t".join(["x"] * 9)]) == ([], 1)  # partial columns


def test_no_server_side_apt_state_is_collected():
    """The server's own APT lists are irrelevant: resolution happens on the workstation."""
    cmd = st.FACTS_COMMAND
    assert "/var/lib/apt" not in cmd and "apt-cache" not in cmd and "apt-get" not in cmd
    assert "${Depends}" in cmd and "notify-reboot-required" in cmd


@pytest.mark.parametrize(
    "output, message",
    [
        ("", "incomplete"),
        ("Welcome\n@@EC2P hostname\nx\n", "incomplete"),
        (facts_output(packages=[]), "package list"),
        (facts_output(kernel=""), "architecture or running kernel"),
        (facts_output(reboot="maybe"), "reboot-required"),
    ],
)
def test_malformed_remote_output(output, message):
    with pytest.raises(st.RemoteOutputError, match=message):
        st.parse_facts(output)


def test_facts_command_is_constant_and_read_only():
    cmd = st.FACTS_COMMAND
    for forbidden in ("sudo", "apt-get", "install", "dpkg -i", "reboot ", "rm ", "scp"):
        assert forbidden not in cmd
