"""Parse a security list pasted as raw text (a chat table or plain lines) into records.

Each record is a run of CVE IDs, then a host (``ip-a-b-c-d[.<region>.compute.internal]``), then a
title like "Ubuntu Security Notification for <pkg> Vulnerabilities (USN-NNNN-N)". Line breaks and
column separators carry no meaning: the whole text is scanned and a new record starts at each CVE
run, so wrapped lines rejoin and extra columns are ignored.

Pure text handling: nothing here touches the web layer, the database or a network.
"""

import ipaddress
import re
from dataclasses import dataclass, field

from ec2patcher.services.report_service import CVE_RE

MAX_PASTE_CHARS = 2_000_000

# Removed, or made a plain hyphen, before scanning: invisible to the person pasting.
_INVISIBLE = dict.fromkeys(map(ord, "­​‌‍⁠﻿"))
_HYPHENS = dict.fromkeys(map(ord, "‐‑"), "-")
_CHARACTER_FIXES = {**_INVISIBLE, **_HYPHENS}

_SEPARATORS = "|·•∙‣◦▪*`"
_SEPARATOR_RE = re.compile(f"[{re.escape(_SEPARATORS)}]")
_LINE_BREAK = rf"[ \t]*\r?\n[\s{re.escape(_SEPARATORS)}]*"
# A token wrapped right after one of its own hyphens: CVE-2000-<newline>0001.
_WRAPPED_HYPHEN_RE = re.compile(rf"(?<=\w)-{_LINE_BREAK}(?=\w)")
# A host wrapped between the labels of its suffix: ip-10-0-0-1.us-east-1.<newline>compute.internal.
_WRAPPED_SUFFIX_RE = re.compile(
    rf"(?<=\w)\.{_LINE_BREAK}(?=(?:[\w-]+\.)*internal\b)", re.IGNORECASE
)

_CVE_TOKEN_RE = re.compile(r"(?<![\w-])CVE-\d{4}-\d+(?![\w-])", re.IGNORECASE)
_BETWEEN_CVES_RE = re.compile(rf"[\s,;{re.escape(_SEPARATORS)}]*")
_HOST_RE = re.compile(
    r"(?<![\w.-])ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})"
    r"(?:\.(?:[a-z]{2}(?:-[a-z]+)+-\d+\.compute|ec2)\.internal)?"
    r"(?![\w-])(?!\.\w)",
    re.IGNORECASE,
)
_USN_RE = re.compile(r"(?<![\w-])USN-\d+-\d+(?![\w-])", re.IGNORECASE)
_TITLE_START = r"Ubuntu Security Notification for (?P<package>\S.{0,120}?)"
_TITLE_RES = (
    re.compile(
        rf"{_TITLE_START} (?:Vulnerabilit(?:y|ies)|Regressions?)\b(?: ?\( ?USN-\d+-\d+[^)]*\))?",
        re.IGNORECASE,
    ),
    re.compile(rf"{_TITLE_START} ?\( ?USN-\d+-\d+[^)]*\)", re.IGNORECASE),
)


@dataclass(frozen=True)
class SecurityRecord:
    host: str  # lower case, as pasted (with its suffix, if any)
    private_ip: str
    cves: tuple[str, ...]
    usns: tuple[str, ...] = ()
    package: str = ""
    title: str = ""


@dataclass
class ParsedList:
    records: list[SecurityRecord] = field(default_factory=list)
    # CVE runs dropped because the text names no host for them: never guessed.
    without_host: list[tuple[str, ...]] = field(default_factory=list)
    # CVE-shaped tokens the report format rejects (fewer than 4 digits at the end).
    invalid_cves: list[str] = field(default_factory=list)


def parse_security_list(text: str) -> ParsedList:
    """Every record found in ``text``, deduplicated on (host, CVE, USN)."""
    text = (text or "").translate(_CHARACTER_FIXES)
    text = _WRAPPED_HYPHEN_RE.sub("-", text)
    text = _WRAPPED_SUFFIX_RE.sub(".", text)
    parsed = ParsedList()
    seen: set[tuple[str, str, str]] = set()
    for tokens, segment in _cve_runs(text):
        cves = []
        for token in tokens:
            cve = token.upper()
            if not CVE_RE.match(cve):
                parsed.invalid_cves.append(cve)
            elif cve not in cves:
                cves.append(cve)
        if cves:
            _add_record(parsed, tuple(cves), _clean(segment), seen)
    parsed.invalid_cves = list(dict.fromkeys(parsed.invalid_cves))
    return parsed


def _cve_runs(text: str) -> list[tuple[list[str], str]]:
    """(the CVE tokens of a run, the text up to the next run), for every run."""
    matches = list(_CVE_TOKEN_RE.finditer(text))
    runs: list[tuple[list[str], str]] = []
    start = 0
    while start < len(matches):
        end = start
        while end + 1 < len(matches) and _BETWEEN_CVES_RE.fullmatch(
            text, matches[end].end(), matches[end + 1].start()
        ):
            end += 1
        stop = matches[end + 1].start() if end + 1 < len(matches) else len(text)
        tokens = [m.group(0) for m in matches[start : end + 1]]
        runs.append((tokens, text[matches[end].end() : stop]))
        start = end + 1
    return runs


def _clean(segment: str) -> str:
    return " ".join(_SEPARATOR_RE.sub(" ", segment).split())


def _add_record(
    parsed: ParsedList, cves: tuple[str, ...], segment: str, seen: set[tuple[str, str, str]]
) -> None:
    host = _find_host(segment)
    if host is None:
        parsed.without_host.append(cves)
        return
    name, private_ip = host
    usns = tuple(dict.fromkeys(u.upper() for u in _USN_RE.findall(segment)))
    title = next((m for m in (r.search(segment) for r in _TITLE_RES) if m), None)
    new_cves = []
    for cve in cves:
        keys = {(name, cve, usn) for usn in usns or ("",)}
        if not keys <= seen:
            new_cves.append(cve)
        seen |= keys
    if new_cves:
        parsed.records.append(
            SecurityRecord(
                host=name,
                private_ip=private_ip,
                cves=tuple(new_cves),
                usns=usns,
                package=title.group("package").strip() if title else "",
                title=title.group(0).strip() if title else "",
            )
        )


def _find_host(segment: str) -> tuple[str, str] | None:
    for match in _HOST_RE.finditer(segment):
        try:
            address = ipaddress.IPv4Address(".".join(str(int(g)) for g in match.groups()))
        except ValueError:  # an octet above 255: not an address
            continue
        return match.group(0).lower(), str(address)
    return None


# --- matching to saved servers -----------------------------------------------------------


@dataclass(frozen=True)
class MatchedRecord:
    record: SecurityRecord
    server_name: str | None = None  # None: unknown (or ambiguous) host
    matched_by: str | None = None  # "name" | "private IP"
    candidates: tuple[str, ...] = ()  # the servers sharing the private IP, when ambiguous


def match_servers(records: list[SecurityRecord], servers: list) -> list[MatchedRecord]:
    """Match each record's host to a saved server by name, else by private IP. Several servers
    with that IP (separate VPCs can reuse one) are not guessed between."""
    by_name = {s.name.casefold(): s.name for s in servers}
    by_ip: dict[str, list[str]] = {}
    for server in servers:
        by_ip.setdefault(server.ip_address, []).append(server.name)
    matched = []
    for record in records:
        short = record.host.split(".", 1)[0]
        name = by_name.get(record.host) or by_name.get(short)
        same_ip = by_ip.get(record.private_ip, [])
        if name:
            matched.append(MatchedRecord(record, name, "name"))
        elif len(same_ip) == 1:
            matched.append(MatchedRecord(record, same_ip[0], "private IP"))
        else:
            matched.append(MatchedRecord(record, candidates=tuple(same_ip)))
    return matched


def build_report(matched: list[MatchedRecord]) -> dict[str, list[str]]:
    """The app's CVE list format (server name -> CVE IDs); hosts without a server are left out,
    as the report format only accepts configured servers."""
    servers: dict[str, list[str]] = {}
    for item in matched:
        if item.server_name is None:
            continue
        cves = servers.setdefault(item.server_name, [])
        cves.extend(cve for cve in item.record.cves if cve not in cves)
    return servers
