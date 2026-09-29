"""Canonical VEX parsing, local index, refresh and stale-data handling."""

import json
import sqlite3
from datetime import timedelta

import pytest
from phase2_fixtures import (
    DOCS,
    FIXTURES,
    archive_fetcher,
    failing_fetcher,
    make_metadata,
    make_vex_archive,
    statement,
    vex_doc,
)

from ec2patcher.services.security_metadata import (
    SecurityMetadata,
    classify_distro,
    parse_purl,
    parse_vex_document,
)


def entries_by(record, codename):
    return {(e.source, e.status): e for e in record.for_release(codename)}


# --- parsing --------------------------------------------------------------------------


def test_parse_real_canonical_document():
    doc = json.loads((FIXTURES / "vex_real_CVE-2024-6387.json").read_text())
    record = parse_vex_document(doc)
    assert record.cve == "CVE-2024-6387"
    assert record.timestamp == "2026-09-24T15:43:45.985077Z"
    noble = entries_by(record, "noble")
    assert noble[("openssh", "fixed")].version == "1:9.6p1-3ubuntu13.19"
    assert noble[("openssh-ssh1", "not_affected")].justification == "vulnerable_code_not_present"
    jammy = entries_by(record, "jammy")
    assert jammy[("openssh", "fixed")].version == "1:8.9p1-3ubuntu0.17"
    # Only arch=source products are kept - binary products are mapped via dpkg on the server.
    assert all(e.source in ("openssh", "openssh-ssh1") for e in record.entries)
    # esm-infra/focal is an Ubuntu Pro pocket for focal; fips pockets are ignored.
    focal = record.for_release("focal")
    assert {(e.source, e.distro, e.is_pro) for e in focal} == {
        ("openssh", "esm-infra/focal", True),
        ("openssh-ssh1", "focal", False),
    }
    assert not any(e.distro.startswith("fips") for e in record.entries)


def test_parse_statuses():
    doc = vex_doc(
        "CVE-2026-1",
        statement("CVE-2026-1", "fixed", [("a", "1.0-1ubuntu1", "noble")]),
        statement("CVE-2026-1", "affected", [("b", "2.0-1", "noble")], status_notes="x"),
        statement("CVE-2026-1", "not_affected", [("c", "1", "noble")], justification="j"),
        statement("CVE-2026-1", "under_investigation", [("d", "1", "noble")]),
        statement("CVE-2026-1", "fixed", [("e", "1+esm1", "esm-apps/noble")]),
    )
    record = parse_vex_document(doc)
    statuses = {(e.source, e.status, e.is_pro) for e in record.for_release("noble")}
    assert statuses == {
        ("a", "fixed", False),
        ("b", "affected", False),
        ("c", "not_affected", False),
        ("d", "under_investigation", False),
        ("e", "fixed", True),
    }


def test_parse_multiple_packages_per_cve():
    record = parse_vex_document(DOCS[1])  # kernel CVE, several source packages
    assert {e.source for e in record.for_release("noble")} == {
        "linux-aws", "linux-signed-aws", "linux", "linux-gcp", "linux-azure",
    }  # fmt: skip


def test_parse_wrapped_metadata_layout():
    doc = vex_doc(
        "CVE-2026-2", statement("CVE-2026-2", "fixed", [("a", "1", "noble")]), wrapped=True
    )
    record = parse_vex_document(doc)
    assert record.cve == "CVE-2026-2" and record.timestamp == "2026-09-20T10:00:00Z"


def test_parse_priority_and_unsupported_releases():
    doc = vex_doc(
        "CVE-2026-3",
        statement(
            "CVE-2026-3", "affected", [("a", "1", "noble"), ("a", "1", "xenial")],
            status_notes="Ubuntu Security Team classified this CVE as of High priority.",
        ),
    )  # fmt: skip
    record = parse_vex_document(doc)
    assert [e.distro for e in record.entries] == ["noble"]  # xenial is not a supported release
    assert record.entries[0].priority == "High"


def test_parse_garbage_documents():
    assert parse_vex_document({}) is None
    assert parse_vex_document({"statements": []}) is None
    assert parse_vex_document({"statements": [{"vulnerability": {"name": "USN-1"}}]}) is None


def test_parse_purl_with_epoch_and_encoding():
    assert parse_purl("pkg:deb/ubuntu/vim@2%3A9.1-1?arch=source&distro=noble") == (
        "vim", "2:9.1-1", {"arch": "source", "distro": "noble"},
    )  # fmt: skip
    assert parse_purl("pkg:npm/foo@1") is None


@pytest.mark.parametrize(
    "distro, expected",
    [
        ("focal", ("focal", False)),
        ("jammy", ("jammy", False)),
        ("noble", ("noble", False)),
        ("resolute", ("resolute", False)),
        ("esm-infra/focal", ("focal", True)),
        ("esm-apps/jammy", ("jammy", True)),
        ("esm-infra-legacy/bionic", ("bionic", True)),
        ("fips-updates/jammy", None),
        ("realtime/noble", None),
        ("xenial", None),
        ("trusty/esm", None),
    ],
)
def test_classify_distro(distro, expected):
    assert classify_distro(distro) == expected


# --- index + refresh --------------------------------------------------------------------


def test_build_index_and_lookup(tmp_path):
    meta = make_metadata(tmp_path)
    assert not meta.status().available
    status = meta.ensure_fresh()
    assert status.available and not status.stale and status.warning is None
    assert status.cve_count == len(DOCS)
    assert status.last_modified == "Fri, 25 Sep 2026 18:09:55 GMT"
    record = meta.lookup("cve-2026-63076")
    assert record.cve == "CVE-2026-63076"
    assert entries_by(record, "noble")[("openssl", "fixed")].version == "3.0.13-0ubuntu3.6"
    assert meta.lookup("CVE-2026-99999") is None
    # The index is small and holds no raw documents.
    with sqlite3.connect(meta.index_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0] == len(DOCS)


def test_cache_reused_without_download(tmp_path):
    archive = make_vex_archive(tmp_path / "a.tar.xz")
    calls = []
    meta = SecurityMetadata(tmp_path / "c", fetcher=archive_fetcher(archive, calls))
    meta.ensure_fresh()
    meta.ensure_fresh()
    assert len(calls) == 1  # fresh cache -> no second download
    # A new instance (== app restart) reads the same cache.
    again = SecurityMetadata(tmp_path / "c", fetcher=failing_fetcher())
    assert again.lookup("CVE-2026-63076") is not None


def test_clear_removes_cache_and_next_lookup_refreshes(tmp_path):
    archive = make_vex_archive(tmp_path / "fixture.tar.xz")
    calls = []
    meta = SecurityMetadata(tmp_path / "cache", fetcher=archive_fetcher(archive, calls))
    assert meta.ensure_fresh().available
    part = meta.archive_path.with_suffix(".part")
    part.write_bytes(b"partial")
    meta._last_error = "old error"

    assert meta.clear()
    assert not any(path.exists() for path in (meta.index_path, meta.archive_path, part))
    assert meta._last_error is None
    assert not meta.status().available and meta.needs_refresh()
    assert not meta.clear()
    assert meta.ensure_fresh().available
    assert len(calls) == 2
    assert meta.lookup("CVE-2026-63076") is not None


def test_refresh_uses_conditional_request_and_handles_not_modified(tmp_path):
    archive = make_vex_archive(tmp_path / "a.tar.xz")
    calls = []
    meta = SecurityMetadata(tmp_path / "c", fetcher=archive_fetcher(archive, calls))
    meta.refresh()
    meta.fetcher = lambda url, dest, headers: calls.append(headers)  # returns None == 304
    meta.refresh()
    assert calls[1] == {
        "If-None-Match": '"abc"',
        "If-Modified-Since": "Fri, 25 Sep 2026 18:09:55 GMT",
    }
    assert meta.status().available and not meta.status().stale


def test_download_failure_with_cache_is_stale_but_usable(tmp_path):
    archive = make_vex_archive(tmp_path / "a.tar.xz")
    meta = SecurityMetadata(tmp_path / "c", fetcher=archive_fetcher(archive), max_age=timedelta(0))
    meta.refresh()
    meta.fetcher = failing_fetcher()
    status = meta.ensure_fresh()
    assert status.available and status.stale
    assert "STALE DATA" in status.warning and "Temporary failure" in status.warning
    assert meta.lookup("CVE-2026-63076") is not None


def test_no_metadata_at_all_fails_cleanly(tmp_path):
    meta = SecurityMetadata(tmp_path / "c", fetcher=failing_fetcher())
    status = meta.ensure_fresh()
    assert not status.available
    assert "Temporary failure" in status.error
    assert not (tmp_path / "c" / "vex-all.part").exists()


def test_corrupt_archive_keeps_previous_index(tmp_path):
    archive = make_vex_archive(tmp_path / "a.tar.xz")
    meta = SecurityMetadata(tmp_path / "c", fetcher=archive_fetcher(archive), max_age=timedelta(0))
    meta.refresh()
    bad = tmp_path / "bad.tar.xz"
    bad.write_bytes(b"not an xz archive")
    meta.fetcher = archive_fetcher(bad)
    meta.refresh()
    status = meta.status()
    assert status.available and status.stale and "corrupt" in status.warning
    assert meta.lookup("CVE-2026-63076") is not None


def test_archive_without_cves_is_rejected(tmp_path):
    archive = make_vex_archive(tmp_path / "a.tar.xz", docs=[])
    meta = SecurityMetadata(tmp_path / "c", fetcher=archive_fetcher(archive))
    status = meta.ensure_fresh()
    assert not status.available and "did not contain any CVE" in status.error
