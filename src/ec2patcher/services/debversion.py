"""Debian package version comparison (same semantics as ``dpkg --compare-versions``).

A version is ``[epoch:]upstream_version[-debian_revision]``. Plain string comparison is
wrong for these (``1.10`` > ``1.9``, ``~`` sorts before everything, epochs dominate), so
this module implements the algorithm from Debian Policy section 5.6.12 / dpkg's verrevcmp.
"""

import functools
import re

_VALID_RE = re.compile(r"^(?:\d+:)?[0-9][A-Za-z0-9.+~:-]*$")


class InvalidVersionError(ValueError):
    """Raised for strings that are not valid Debian versions."""


def parse_version(version: str) -> tuple[int, str, str]:
    """Split a version into (epoch, upstream, revision)."""
    value = (version or "").strip()
    if not value or not _VALID_RE.match(value):
        raise InvalidVersionError(f"Invalid Debian version: {version!r}")
    epoch = 0
    if ":" in value:
        epoch_text, value = value.split(":", 1)
        epoch = int(epoch_text)
    upstream, sep, revision = value.rpartition("-")
    if not sep:
        upstream, revision = value, ""
    if not upstream or (sep and not revision):
        raise InvalidVersionError(f"Invalid Debian version: {version!r}")
    return epoch, upstream, revision


def is_valid_version(version: str) -> bool:
    try:
        parse_version(version)
    except InvalidVersionError:
        return False
    return True


def _order(char: str) -> int:
    # '~' sorts before everything (even the end of the string), letters before non-letters.
    if char == "~":
        return -1
    if char.isdigit():
        return 0
    if char.isalpha():
        return ord(char)
    return ord(char) + 256


def _compare_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = (a[i] > b[j]) - (a[i] < b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def compare_versions(a: str, b: str) -> int:
    """Return -1, 0 or 1 like dpkg --compare-versions. Raises InvalidVersionError."""
    a_epoch, a_up, a_rev = parse_version(a)
    b_epoch, b_up, b_rev = parse_version(b)
    if a_epoch != b_epoch:
        return -1 if a_epoch < b_epoch else 1
    return _compare_part(a_up, b_up) or _compare_part(a_rev, b_rev)


def version_key(version: str):
    """Sort key usable with sorted()/max()."""
    return functools.cmp_to_key(compare_versions)(version)
