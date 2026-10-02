"""rpmvercmp port: rpm's own test vectors (tests/rpmvercmp.at) plus EVR parsing / comparison."""

import pytest

from ec2patcher.services import rpmversion
from ec2patcher.services.rpmversion import (
    InvalidVersionError,
    compare_evr,
    compare_versions,
    format_evr,
    parse_evr,
    rpmvercmp,
    version_key,
)

# (a, b, expected rpmvercmp(a, b)) from rpm's tests/rpmvercmp.at
RPM_VECTORS = [
    ("1.0", "1.0", 0), ("1.0", "2.0", -1), ("2.0", "1.0", 1),
    ("2.0.1", "2.0.1", 0), ("2.0", "2.0.1", -1), ("2.0.1", "2.0", 1),
    ("2.0.1a", "2.0.1a", 0), ("2.0.1a", "2.0.1", 1), ("2.0.1", "2.0.1a", -1),
    ("5.5p1", "5.5p1", 0), ("5.5p1", "5.5p2", -1), ("5.5p2", "5.5p1", 1),
    ("5.5p10", "5.5p10", 0), ("5.5p1", "5.5p10", -1), ("5.5p10", "5.5p1", 1),
    ("10xyz", "10.1xyz", -1), ("10.1xyz", "10xyz", 1),
    ("xyz10", "xyz10", 0), ("xyz10", "xyz10.1", -1), ("xyz10.1", "xyz10", 1),
    ("xyz.4", "xyz.4", 0), ("xyz.4", "8", -1), ("8", "xyz.4", 1),
    ("xyz.4", "2", -1), ("2", "xyz.4", 1),
    ("5.5p2", "5.6p1", -1), ("5.6p1", "5.5p2", 1),
    ("5.6p1", "6.5p1", -1), ("6.5p1", "5.6p1", 1),
    ("6.0.rc1", "6.0", 1), ("6.0", "6.0.rc1", -1),
    ("10b2", "10a1", 1), ("10a2", "10b2", -1),
    ("1.0aa", "1.0aa", 0), ("1.0a", "1.0aa", -1), ("1.0aa", "1.0a", 1),
    ("10.0001", "10.0001", 0), ("10.0001", "10.1", 0), ("10.1", "10.0001", 0),
    ("10.0001", "10.0039", -1), ("10.0039", "10.0001", 1),
    ("4.999.9", "5.0", -1), ("5.0", "4.999.9", 1),
    ("20101121", "20101121", 0), ("20101121", "20101122", -1), ("20101122", "20101121", 1),
    ("2_0", "2_0", 0), ("2.0", "2_0", 0), ("2_0", "2.0", 0),
    ("a", "a", 0), ("a+", "a+", 0), ("a+", "a_", 0), ("a_", "a+", 0),
    ("+a", "+a", 0), ("+a", "_a", 0), ("_a", "+a", 0),
    ("+_", "+_", 0), ("_+", "+_", 0), ("_+", "_+", 0), ("+", "_", 0), ("_", "+", 0),
    ("1.0~rc1", "1.0~rc1", 0), ("1.0~rc1", "1.0", -1), ("1.0", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc2", -1), ("1.0~rc2", "1.0~rc1", 1),
    ("1.0~rc1~git123", "1.0~rc1~git123", 0), ("1.0~rc1~git123", "1.0~rc1", -1),
    ("1.0~rc1", "1.0~rc1~git123", 1),
    ("1.0^", "1.0^", 0), ("1.0^", "1.0", 1), ("1.0", "1.0^", -1),
    ("1.0^git1", "1.0^git1", 0), ("1.0^git1", "1.0", 1), ("1.0", "1.0^git1", -1),
    ("1.0^git1", "1.0^git2", -1), ("1.0^git2", "1.0^git1", 1),
    ("1.0^git1", "1.01", -1), ("1.01", "1.0^git1", 1),
    ("1.0^20160101", "1.0^20160101", 0), ("1.0^20160101", "1.0.1", -1),
    ("1.0.1", "1.0^20160101", 1),
    ("1.0^20160101^git1", "1.0^20160101^git1", 0),
    ("1.0^20160102", "1.0^20160101^git1", 1), ("1.0^20160101^git1", "1.0^20160102", -1),
    ("1.0~rc1^git1", "1.0~rc1^git1", 0), ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1", "1.0~rc1^git1", -1),
    ("1.0^git1~pre", "1.0^git1~pre", 0), ("1.0^git1", "1.0^git1~pre", 1),
    ("1.0^git1~pre", "1.0^git1", -1),
]  # fmt: skip


@pytest.mark.parametrize(("a", "b", "expected"), RPM_VECTORS)
def test_rpmvercmp_matches_rpm(a, b, expected):
    assert rpmvercmp(a, b) == expected


@pytest.mark.parametrize(
    ("a", "b", "expected"),
    [
        ("1.0", "1.0.0", -1),  # more segments wins
        ("1", "a", 1),  # numeric segment newer than alphabetic
        ("a", "1", -1),
        ("1.10", "1.9", 1),  # numeric, not lexical
        ("0001", "1", 0),  # leading zeros ignored
        ("1.0é", "1.0", 0),  # non-ASCII characters are separators, like in C rpm
        ("", "", 0),
        ("", "1", -1),
        ("1", "", 1),
        ("~", "", -1),
        ("^", "", 1),
    ],
)
def test_rpmvercmp_edge_cases(a, b, expected):
    assert rpmvercmp(a, b) == expected


def test_parse_evr():
    assert parse_evr("1:3.0.8-1.amzn2023.0.14") == (1, "3.0.8", "1.amzn2023.0.14")
    assert parse_evr("(none):5.2.15-1.amzn2023.0.2") == (0, "5.2.15", "1.amzn2023.0.2")
    assert parse_evr("0:1.0-1") == (0, "1.0", "1")
    assert parse_evr("5.2.15-1.amzn2023.0.2") == (0, "5.2.15", "1.amzn2023.0.2")
    assert parse_evr("1.0") == (0, "1.0", "")
    assert parse_evr("1.0~rc1^git2-3") == (0, "1.0~rc1^git2", "3")
    for bad in ("", " ", "1:", ":1.0-1", "x:1.0-1", "1.0 -1", "1.0-", "1:2:3-4"):
        with pytest.raises(InvalidVersionError):
            parse_evr(bad)
    assert rpmversion.is_valid_evr("2:9.0.2153-1.amzn2023.0.1")
    assert not rpmversion.is_valid_evr("not a version")


def test_format_evr_omits_a_zero_epoch():
    assert format_evr("0", "1.0", "1.amzn2023") == "1.0-1.amzn2023"
    assert format_evr(None, "1.0", "1") == "1.0-1"
    assert format_evr("(none)", "1.0", "1") == "1.0-1"
    assert format_evr(2, "9.0", "1") == "2:9.0-1"
    assert format_evr("1", "3.0.8", "") == "1:3.0.8"


def test_compare_evr_epoch_version_release():
    assert compare_evr((1, "1.0", "1"), (0, "9.9", "9")) > 0  # epoch dominates
    assert compare_evr((0, "1.0", "2"), (0, "1.0", "10")) < 0  # release compared numerically
    assert compare_evr((0, "1.1", "1"), (0, "1.0", "99")) > 0  # version before release
    assert compare_evr((0, "1.0", ""), (0, "1.0", "5")) == 0  # missing release matches any
    assert compare_versions("1:3.0.8-1.amzn2023.0.14", "1:3.0.8-1.amzn2023.0.16") < 0
    assert compare_versions("3.0.8-1.amzn2023.0.16", "1:3.0.8-1.amzn2023.0.14") < 0
    assert compare_versions("0:1.0-1", "1.0-1") == 0
    assert compare_versions("(none):1.0-1", "0:1.0-1") == 0
    assert compare_versions("6.1.115-126.197.amzn2023", "6.1.112-122.189.amzn2023") > 0
    assert compare_versions("8.5.0-1.amzn2023.0.4", "8.11.1-4.amzn2023.0.1") < 0


def test_version_key_sorts_and_rejects_invalid_versions():
    versions = ["1.10-1", "1:0.1-1", "1.9-1", "1.9-1~rc", "1.9^post-1", "1.9-1.1"]
    assert sorted(versions, key=version_key) == [
        "1.9-1~rc", "1.9-1", "1.9-1.1", "1.9^post-1", "1.10-1", "1:0.1-1",
    ]  # fmt: skip
    with pytest.raises(InvalidVersionError):
        version_key("bad version")
