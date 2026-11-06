"""Parser and server matching of pasted security lists. Generic fixtures only."""

from types import SimpleNamespace

from ec2patcher.services.security_list import (
    build_report,
    match_servers,
    parse_security_list,
)

C1, C2, C3 = "CVE-2000-0001", "CVE-2000-0002", "CVE-2000-0003"
HOST = "ip-10-0-0-1"
FQDN = "ip-10-0-0-1.us-east-1.compute.internal"
TITLE = "Ubuntu Security Notification for example-package Vulnerabilities (USN-0000-1)"


def only(text):
    records = parse_security_list(text).records
    assert len(records) == 1
    return records[0]


def server(name, ip="192.0.2.1"):
    return SimpleNamespace(name=name, ip_address=ip)


def test_one_plain_record():
    record = only(f"{C1}, {C2} {FQDN} {TITLE}")
    assert record.host == FQDN and record.private_ip == "10.0.0.1"
    assert record.cves == (C1, C2)
    assert record.usns == ("USN-0000-1",)
    assert record.package == "example-package"
    assert record.title == TITLE


def test_single_cve_record():
    assert only(f"{C1} {HOST} {TITLE}").cves == (C1,)


def test_wrapped_lines_rejoin_into_one_record():
    text = (
        f"{C1},\n{C2},\n   {C3}\n{FQDN}\nUbuntu Security\nNotification for\n"
        "example-package\nVulnerabilities\n(USN-0000-1)\n"
    )
    record = only(text)
    assert record.cves == (C1, C2, C3) and record.host == FQDN
    assert record.title == TITLE and record.package == "example-package"


def test_tokens_wrapped_at_their_own_hyphens_and_dots_rejoin():
    text = (
        "CVE-2000-\n0001, CVE-\n2000-0002 ip-10-0-\n0-1.us-east-1.\ncompute.internal "
        "Ubuntu Security Notification for example-\npackage Vulnerabilities (USN-0000-\n1)"
    )
    record = only(text)
    assert record.cves == (C1, C2) and record.host == FQDN
    assert record.package == "example-package" and record.usns == ("USN-0000-1",)


def test_new_record_starts_at_each_cve_run():
    other = "Ubuntu Security Notification for other-package Vulnerabilities (USN-0000-2)"
    records = parse_security_list(f"{C1}, {C2} {HOST} {TITLE} {C3} ip-10-0-0-2 {other}").records
    assert [(r.host, r.cves, r.package) for r in records] == [
        (HOST, (C1, C2), "example-package"),
        ("ip-10-0-0-2", (C3,), "other-package"),
    ]


def test_missing_usn_still_parses():
    title = "Ubuntu Security Notification for example-package Vulnerabilities"
    record = only(f"{C1} {HOST} {title}")
    assert record.usns == () and record.package == "example-package" and record.title == title


def test_no_title_at_all_still_reports_what_it_found():
    record = only(f"{C1} {HOST} something else entirely")
    assert (record.host, record.cves, record.package, record.title) == (HOST, (C1,), "", "")


def test_usn_without_vulnerabilities_word():
    title = "Ubuntu Security Notification for example-package (USN-0000-1)"
    record = only(f"{C1} {HOST} {title}")
    assert record.package == "example-package" and record.title == title


def test_singular_and_multi_word_titles():
    title = "Ubuntu Security Notification for Linux kernel (AWS) Vulnerability (USN-0000-1)"
    record = only(f"{C1} {HOST} {title}")
    assert record.package == "Linux kernel (AWS)" and record.title == title


def test_junk_columns_are_ignored():
    text = (
        f"id 42 high open {C1}, {C2} 12 days {HOST} 443/tcp Critical {TITLE} "
        "owner: team-a, due 2000-01-31, see ticket ABC-1"
    )
    record = only(text)
    assert record.cves == (C1, C2) and record.host == HOST and record.title == TITLE


def test_markdown_table_paste():
    text = (
        "| CVE | Host | QID | Title |\n"
        "|---|---|---|---|\n"
        f"| {C1}, {C2} | {FQDN} | 12345 | {TITLE} |\n"
        f"| {C3} | ip-10-0-0-2 | 12346 | Ubuntu Security Notification for other-package "
        "Vulnerabilities (USN-0000-2) |\n"
    )
    records = parse_security_list(text).records
    assert [(r.host, r.cves) for r in records] == [(FQDN, (C1, C2)), ("ip-10-0-0-2", (C3,))]
    assert records[0].title == TITLE and records[1].usns == ("USN-0000-2",)


def test_table_row_wrapped_inside_cells():
    text = (
        f"| {C1},       | {HOST} | Ubuntu Security Notification for |\n"
        f"| {C2}        |        | example-package Vulnerabilities (USN-0000-1) |\n"
    )
    records = parse_security_list(text).records
    # The two CVEs do not touch (the host sits between them), so this reads as two records, and
    # the second has no host of its own: dropped rather than guessed.
    assert [r.cves for r in records] == [(C1,)]
    assert parse_security_list(text).without_host == [(C2,)]


def test_separators_between_host_and_title():
    for separator in ("|", "·", "•", " ", " | ", " · ", "  ", "**"):
        record = only(f"{C1}{separator}{HOST}{separator}{TITLE}")
        assert record.host == HOST and record.title == TITLE, repr(separator)


def test_nbsp_inside_the_title_and_invisible_characters():
    title = TITLE.replace(" ", " ")
    record = only(f"﻿{C1},​{C2} {HOST} {title}")
    assert record.cves == (C1, C2) and record.title == TITLE


def test_non_breaking_hyphens_are_plain_hyphens():
    assert only(f"CVE‑2000‑0001 ip‑10‑0‑0‑1 {TITLE}").host == HOST


def test_case_is_normalized():
    record = only(f"cve-2000-0001 {FQDN.upper()} {TITLE.lower()}")
    assert record.cves == (C1,) and record.host == FQDN and record.usns == ("USN-0000-1",)


def test_duplicates_are_removed():
    line = f"{C1}, {C2} {HOST} {TITLE}"
    assert only(f"{line}\n{line}\n{line}").cves == (C1, C2)
    assert only(f"{C1}, {C1}, {C2} {HOST} {TITLE}").cves == (C1, C2)


def test_partial_overlap_keeps_only_the_new_cve():
    records = parse_security_list(f"{C1}, {C2} {HOST} {TITLE}\n{C2}, {C3} {HOST} {TITLE}").records
    assert [r.cves for r in records] == [(C1, C2), (C3,)]


def test_same_cve_under_another_host_or_usn_is_not_a_duplicate():
    other_usn = TITLE.replace("USN-0000-1", "USN-0000-2")
    text = f"{C1} {HOST} {TITLE}\n{C1} ip-10-0-0-2 {TITLE}\n{C1} {HOST} {other_usn}"
    assert len(parse_security_list(text).records) == 3


def test_record_without_a_host_is_dropped_not_guessed():
    parsed = parse_security_list(f"{C1} {TITLE}\n{C2} {HOST} {TITLE}")
    assert [r.cves for r in parsed.records] == [(C2,)]
    assert parsed.without_host == [(C1,)]


def test_host_before_the_first_cve_belongs_to_nothing():
    parsed = parse_security_list(f"{HOST} {C1} {TITLE}")
    assert parsed.records == [] and parsed.without_host == [(C1,)]


def test_other_host_shapes_are_not_hosts():
    for host in ("ip-10-0-0", "ip-300-0-0-1", "myip-10-0-0-1", "ip-10-0-0-1.example.com"):
        assert parse_security_list(f"{C1} {host} {TITLE}").records == [], host


def test_us_east_1_style_suffix_is_a_host():
    assert only(f"{C1} ip-10-0-0-1.ec2.internal {TITLE}").host == "ip-10-0-0-1.ec2.internal"


def test_cve_the_report_format_rejects_is_reported_not_kept():
    parsed = parse_security_list(f"CVE-2000-1, {C1} {HOST} {TITLE}")
    assert parsed.records[0].cves == (C1,)
    assert parsed.invalid_cves == ["CVE-2000-1"]


def test_nothing_usable():
    for text in ("", "   \n ", "no records here", f"{HOST} {TITLE}"):
        parsed = parse_security_list(text)
        assert parsed.records == [] and parsed.without_host == []


# --- matching ------------------------------------------------------------------------------


def test_matches_by_name_short_or_full_and_by_private_ip():
    records = parse_security_list(
        f"{C1} {FQDN} {TITLE}\n{C1} ip-10-0-0-2 {TITLE}\n{C1} ip-10-0-0-3 {TITLE}\n"
        f"{C1} ip-10-0-0-4 {TITLE}"
    ).records
    servers = [
        server(HOST),  # the short name of the pasted full host
        server("ip-10-0-0-2.us-east-1.compute.internal", "10.9.9.9"),  # not this one: short pasted
        server("app-01", "10.0.0.3"),
    ]
    matched = match_servers(records, servers)
    assert [(m.server_name, m.matched_by) for m in matched] == [
        (HOST, "name"), (None, None), ("app-01", "private IP"), (None, None),
    ]  # fmt: skip


def test_full_host_matches_a_server_named_with_it():
    records = parse_security_list(f"{C1} {FQDN} {TITLE}").records
    assert match_servers(records, [server(FQDN)])[0].server_name == FQDN


def test_name_match_is_case_insensitive_and_returns_the_saved_spelling():
    records = parse_security_list(f"{C1} {HOST} {TITLE}").records
    assert match_servers(records, [server("IP-10-0-0-1")])[0].server_name == "IP-10-0-0-1"


def test_two_servers_with_the_private_ip_are_not_guessed_between():
    records = parse_security_list(f"{C1} {HOST} {TITLE}").records
    item = match_servers(records, [server("a", "10.0.0.1"), server("b", "10.0.0.1")])[0]
    assert item.server_name is None and item.candidates == ("a", "b")


def test_build_report_merges_records_of_a_server_and_leaves_out_unknown_hosts():
    records = parse_security_list(
        f"{C1}, {C2} {HOST} {TITLE}\n{C2}, {C3} {FQDN} {TITLE}\n{C1} ip-10-0-0-9 {TITLE}"
    ).records
    report = build_report(match_servers(records, [server("app-01", "10.0.0.1")]))
    assert report == {"app-01": [C1, C2, C3]}
