"""Canonical Security JSON API mapping and online lookup behavior."""

from pathlib import Path
from urllib.error import HTTPError

import pytest
from phase2_fixtures import online_fetcher

from ec2patcher.services.security_metadata import SecurityMetadata, classify_distro


@pytest.mark.parametrize(
    "distro, expected",
    [
        ("focal", ("focal", False)),
        ("noble", ("noble", False)),
        ("esm-infra/focal", ("focal", True)),
        ("esm-apps/jammy", ("jammy", True)),
        ("esm-infra-legacy/bionic", ("bionic", True)),
        ("fips-updates/jammy", None),
        ("upstream", None),
        ("xenial", None),
    ],
)
def test_classify_distro(distro, expected):
    assert classify_distro(distro) == expected


def test_direct_canonical_lookup_maps_source_status_and_pocket():
    calls = []
    body = {
        "id": "CVE-2024-6387",
        "priority": "high",
        "packages": [
            {
                "name": "openssh",
                "statuses": [
                    {
                        "release_codename": "noble",
                        "status": "released",
                        "pocket": "security",
                        "description": "1:9.6p1-3ubuntu13.3",
                    },
                    {
                        "release_codename": "focal",
                        "status": "not-affected",
                        "pocket": None,
                        "description": "",
                    },
                    {
                        "release_codename": "noble",
                        "status": "released",
                        "pocket": "esm-infra",
                        "description": "1:9.6p1-3ubuntu13.4",
                    },
                    {
                        "release_codename": "upstream",
                        "status": "released",
                        "pocket": None,
                        "description": "1.0",
                    },
                ],
            }
        ],
    }

    def fetch(url):
        calls.append(url)
        return body

    meta = SecurityMetadata(fetcher=fetch)
    assert meta.ensure_fresh().available
    assert calls == []  # status checks never fetch
    record = meta.lookup("cve-2024-6387")
    assert calls == ["https://ubuntu.com/security/cves/CVE-2024-6387.json"]
    noble = record.for_release("noble")
    assert (noble[0].source, noble[0].status, noble[0].version, noble[0].distro) == (
        "openssh",
        "fixed",
        "1:9.6p1-3ubuntu13.3",
        "noble",
    )
    assert noble[0].priority == "High"
    assert (record.for_release("focal")[0].status, record.for_release("focal")[0].note) == (
        "not_affected",
        "not-affected; Ubuntu Security Team classified this CVE as of high priority.",
    )
    assert noble[1].is_pro and noble[1].distro == "esm-infra/noble"
    assert len(record.entries) == 3
    assert meta.lookup("CVE-2024-6387") is record
    assert len(calls) == 1
    assert meta.clear()
    assert meta.lookup("CVE-2024-6387") is not record
    assert len(calls) == 2
    assert meta.clear()  # memo has one entry again


def test_404_is_memoized_and_clear_requeries():
    calls = []

    def fetch(url):
        calls.append(url)
        raise HTTPError(url, 404, "Not Found", None, None)

    meta = SecurityMetadata(fetcher=fetch)
    assert meta.lookup("CVE-2026-99999") is None
    assert meta.lookup("CVE-2026-99999") is None
    assert len(calls) == 1
    assert meta.clear()
    assert meta.lookup("CVE-2026-99999") is None
    assert len(calls) == 2


def test_network_and_parse_failures_raise_without_memo():
    calls = []

    def fetch(url):
        calls.append(url)
        raise OSError("offline")

    meta = SecurityMetadata(fetcher=fetch)
    with pytest.raises(OSError, match="offline"):
        meta.lookup("CVE-2024-6387")
    with pytest.raises(OSError, match="offline"):
        meta.lookup("CVE-2024-6387")
    assert len(calls) == 2
    meta.fetcher = lambda url: {"id": "CVE-2024-6387"}
    with pytest.raises(ValueError, match="packages list"):
        meta.lookup("CVE-2024-6387")


def test_no_bulk_index_reference_in_service():
    source = (
        Path(__file__).parents[1] / "src/ec2patcher/services/security_metadata.py"
    ).read_text()
    assert "security-metadata.canonical.com/vex/vex-all" not in source
    assert "build_index" not in source
    assert "tarfile" not in source
    assert "sqlite3" not in source


def test_fixture_lookup_is_online_per_cve():
    calls = []
    meta = SecurityMetadata(fetcher=online_fetcher(calls=calls))
    record = meta.lookup("CVE-2026-63076")
    assert record.for_release("noble")[0].version == "3.0.13-0ubuntu3.6"
    assert calls == ["https://ubuntu.com/security/cves/CVE-2026-63076.json"]
