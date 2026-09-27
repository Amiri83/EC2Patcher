"""Debian version comparison (dpkg semantics, not string comparison)."""

import shutil
import subprocess

import pytest

from ec2patcher.services.debversion import (
    InvalidVersionError,
    compare_versions,
    is_valid_version,
    parse_version,
)


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("1.0", "1.0", 0),
        ("1.10", "1.9", 1),  # numeric, not lexical
        ("1.9", "1.10", -1),
        ("1.0.1", "1.0", 1),
        ("1.00", "1.0", 0),  # leading zeros are insignificant
        ("1.0a", "1.0", 1),
        ("1.0+b1", "1.0", 1),
        ("1.0.0", "1.0+b1", 1),  # non-letters compare by ASCII: '+' (43) < '.' (46)
    ],
)
def test_upstream_ordering(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("3.0.13-0ubuntu3.6", "3.0.13-0ubuntu3.4", 1),
        ("3.0.13-0ubuntu3.10", "3.0.13-0ubuntu3.9", 1),
        ("2.43-2ubuntu2.10", "2.43-2ubuntu2.4", 1),
        ("1.2.2-2ubuntu0.22.04.2", "1.2.2-2ubuntu0.22.04.10", -1),
        ("1.0-1ubuntu1", "1.0-1", 1),
        ("1.0-1ubuntu0.1", "1.0-1", 1),
        ("1.0-1", "1.0", 1),
        ("3.0.2-0ubuntu1.18+esm1", "3.0.2-0ubuntu1.18", 1),  # Ubuntu Pro rebuild is newer
        ("6.8.0-1024.26", "6.8.0-1021.23", 1),  # kernel ABI
        ("1.2.3-4-5", "1.2.3-4", 1),  # last hyphen separates the revision
    ],
)
def test_ubuntu_revisions(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("1:0.9", "1.0", 1),  # epoch dominates
        ("0:1.0", "1.0", 0),  # explicit zero epoch equals none
        ("2:1.0", "1:9.9", 1),
        ("1:8.9p1-3ubuntu0.17", "1:8.9p1-3ubuntu0.10", 1),
        ("7:6.1.1-3ubuntu5+esm2", "7:6.1.1-3ubuntu5", 1),
        ("2:9.1.0016-1ubuntu7.8", "9.9.9", 1),
    ],
)
def test_epochs(a, b, expected):
    assert compare_versions(a, b) == expected


@pytest.mark.parametrize(
    "a, b, expected",
    [
        ("1.0~rc1", "1.0", -1),  # tilde sorts before the empty string
        ("1.0~rc1", "1.0~rc2", -1),
        ("1.0~~", "1.0~", -1),
        ("1.0~", "1.0", -1),
        ("0.4.0-4ubuntu0.1~esm1", "0.4.0-4ubuntu0.1", -1),
        ("1.0~rc1-1", "1.0-0", -1),
        ("5.85-4ubuntu0.2", "5.85-4", 1),
    ],
)
def test_tilde_pre_releases(a, b, expected):
    assert compare_versions(a, b) == expected


def test_comparison_is_antisymmetric():
    assert compare_versions("1.10", "1.9") == -compare_versions("1.9", "1.10")


@pytest.mark.parametrize("bad", ["", "a1.0", "1.0-", ":1.0", "x:1.0", "1.0 2", "1.0_1"])
def test_invalid_versions(bad):
    assert not is_valid_version(bad)
    with pytest.raises(InvalidVersionError):
        compare_versions(bad, "1.0")


def test_parse_version_parts():
    assert parse_version("1:2.3-4ubuntu1") == (1, "2.3", "4ubuntu1")
    assert parse_version("2.3") == (0, "2.3", "")


@pytest.mark.skipif(shutil.which("dpkg") is None, reason="dpkg not available")
def test_agrees_with_dpkg():
    versions = [
        "1.0", "1.0-1", "1:0.9", "1.10", "1.9", "1.0~rc1", "1.0+b1", "1.0a", "2.43-2ubuntu2.4",
        "2.43-2ubuntu2.10", "0.4.0-4ubuntu0.1~esm1", "6.8.0.1024.26", "6.8.0-1024.26",
    ]  # fmt: skip
    for a in versions:
        for b in versions:
            ours = compare_versions(a, b)
            op = {-1: "lt", 0: "eq", 1: "gt"}[ours]
            assert subprocess.run(["dpkg", "--compare-versions", a, op, b]).returncode == 0, (a, b)
