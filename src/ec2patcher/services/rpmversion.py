"""RPM package version comparison (same semantics as rpm's ``rpmvercmp`` / ``labelCompare``).

An EVR is ``[epoch:]version-release``. Epochs compare numerically (missing = 0), then version
and release with ``rpmvercmp``: strings are split into alternating digit / letter segments
(every other ASCII character separates them); numeric segments compare as integers and are
newer than alphabetic ones; ``~`` sorts before everything (pre-releases) and ``^`` after the
base version but before any further segment (post-release snapshots). Port of rpm's
``rpmio/rpmvercmp.c`` (rpm >= 4.15, the version shipped with Amazon Linux 2023).
"""

import functools
import re


class InvalidVersionError(ValueError):
    """Raised for strings that are not valid RPM EVRs."""


# version / release: no whitespace, ':' or '-' (rpm forbids '-' in both); epoch digits only.
_EVR_RE = re.compile(r"^(?:(\d+|\(none\)):)?([^\s:-]+)(?:-([^\s:-]+))?$")


def _alpha(char: str) -> bool:
    return ("a" <= char <= "z") or ("A" <= char <= "Z")


def _digit(char: str) -> bool:
    return "0" <= char <= "9"


def _alnum(char: str) -> bool:
    return _alpha(char) or _digit(char)


def rpmvercmp(a: str, b: str) -> int:
    """-1, 0 or 1 like rpm's rpmvercmp for one version or release string."""
    if a == b:
        return 0
    i = j = 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not _alnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not _alnum(b[j]) and b[j] not in "~^":
            j += 1
        # '~' sorts before everything, even the end of the string.
        if (i < la and a[i] == "~") or (j < lb and b[j] == "~"):
            if i >= la or a[i] != "~":
                return 1
            if j >= lb or b[j] != "~":
                return -1
            i, j = i + 1, j + 1
            continue
        # '^' sorts after the end of the string but before any other segment.
        if (i < la and a[i] == "^") or (j < lb and b[j] == "^"):
            if i >= la:
                return -1
            if j >= lb:
                return 1
            if a[i] != "^":
                return 1
            if b[j] != "^":
                return -1
            i, j = i + 1, j + 1
            continue
        if not (i < la and j < lb):
            break
        start_a, start_b = i, j
        numeric = _digit(a[i])
        kind = _digit if numeric else _alpha
        while i < la and kind(a[i]):
            i += 1
        while j < lb and kind(b[j]):
            j += 1
        seg_a, seg_b = a[start_a:i], b[start_b:j]
        if not seg_b:
            # Different segment types: a numeric segment is always newer.
            return 1 if numeric else -1
        if numeric:
            seg_a, seg_b = seg_a.lstrip("0"), seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def parse_evr(evr: str) -> tuple[int, str, str]:
    """Split ``[epoch:]version[-release]`` into (epoch, version, release). An epoch of
    ``(none)`` (rpm's query format for an unset epoch) is 0; the release may be empty."""
    value = (evr or "").strip()
    match = _EVR_RE.match(value)
    if not match:
        raise InvalidVersionError(f"Invalid RPM version: {evr!r}")
    epoch, version, release = match.groups()
    return (int(epoch) if epoch and epoch.isdigit() else 0), version, release or ""


def is_valid_evr(evr: str) -> bool:
    try:
        parse_evr(evr)
    except InvalidVersionError:
        return False
    return True


def format_evr(epoch: int | str | None, version: str, release: str) -> str:
    """``version-release``, prefixed with ``epoch:`` only for a non-zero epoch."""
    epoch_text = str(epoch or "").strip()
    prefix = f"{epoch_text}:" if epoch_text.isdigit() and int(epoch_text) else ""
    return f"{prefix}{version}-{release}" if release else f"{prefix}{version}"


def compare_evr(a: tuple[int, str, str], b: tuple[int, str, str]) -> int:
    """rpm's labelCompare: epoch, then version, then release (an empty release on either
    side matches any release, as in rpm dependency comparisons)."""
    if a[0] != b[0]:
        return 1 if a[0] > b[0] else -1
    result = rpmvercmp(a[1], b[1])
    if result or not a[2] or not b[2]:
        return result
    return rpmvercmp(a[2], b[2])


def compare_versions(a: str, b: str) -> int:
    """<0, 0 or >0 like cmp(a, b) for two EVR strings."""
    return compare_evr(parse_evr(a), parse_evr(b))


def version_key(version: str):
    """Sort key for EVR strings (raises InvalidVersionError for invalid ones)."""
    parse_evr(version)
    return _KEY(version)


_KEY = functools.cmp_to_key(compare_versions)
