"""NVD CVE API 2.0 fixtures (structure as returned by services.nvd.nist.gov) and a fake
transport. Unit tests never touch the live API."""

import json
import urllib.parse
from pathlib import Path

from ec2patcher.services import nvd


def cvss(version, score, severity, source="nvd@nist.gov", kind="Primary", vector=True):
    """One metric entry of cvssMetricV40 / V31 / V30 (v2 keeps baseSeverity outside)."""
    data = {"version": version, "baseScore": score}
    if vector:
        prefix = "CVSS:4.0/AV:N/AC:L/AT:N" if version == "4.0" else f"CVSS:{version}/AV:N/AC:L"
        data["vectorString"] = prefix
    if severity is not None:
        data["baseSeverity"] = severity
    return {"source": source, "type": kind, "cvssData": data}


def v2(score, severity, source="nvd@nist.gov"):
    return {
        "source": source,
        "type": "Primary",
        "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                     "baseScore": score},
        "baseSeverity": severity,
    }  # fmt: skip


def cve_obj(cve_id, **metrics):
    return {
        "id": cve_id,
        "sourceIdentifier": "cve@mitre.org",
        "published": "2026-05-01T10:15:00.000",
        "lastModified": "2026-09-01T12:17:13.423",
        "vulnStatus": "Analyzed",
        "descriptions": [{"lang": "en", "value": "fixture"}],
        "metrics": metrics,
    }


def response(*cves) -> bytes:
    return json.dumps(
        {
            "resultsPerPage": len(cves),
            "startIndex": 0,
            "totalResults": len(cves),
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-09-27T16:26:02.045",
            "vulnerabilities": [{"cve": c} for c in cves],
        }
    ).encode()


# The Phase 2 fixture CVEs. NVD's rating deliberately differs from Canonical's priority.
REPORT_CVES = {
    # Canonical priority: critical -> NVD High (CNA listed first, like the real API does)
    "CVE-2026-63076": cve_obj(
        "CVE-2026-63076",
        cvssMetricV31=[
            cvss("3.1", 9.8, "CRITICAL", source="openssl-security@openssl.org", kind="Secondary"),
            cvss("3.1", 7.5, "HIGH"),
        ],
    ),
    # Canonical priority: high -> only a Primary CNA v4.0 assessment: Critical
    "CVE-2026-54874": cve_obj(
        "CVE-2026-54874",
        cvssMetricV40=[cvss("4.0", 9.3, "CRITICAL", source="security@kernel.org")],
    ),
    # Canonical priority: low -> NVD Medium
    "CVE-2026-63075": cve_obj("CVE-2026-63075", cvssMetricV31=[cvss("3.1", 5.9, "MEDIUM")]),
    # Canonical priority: untriaged -> NVD Low
    "CVE-2026-10004": cve_obj("CVE-2026-10004", cvssMetricV31=[cvss("3.1", 3.3, "LOW")]),
    # CVE-2026-10005 is unknown to NVD -> Unknown
}


class FakeNvd:
    """Transport stand-in: serves ``cves`` by cveId, or a scripted list of replies."""

    def __init__(self, cves=None, replies=None):
        self.cves = dict(cves or {})
        self.replies = list(replies or [])
        self.calls: list[tuple[str, dict]] = []

    def requested(self) -> list[str]:
        return [
            urllib.parse.parse_qs(urllib.parse.urlsplit(u).query)["cveId"][0] for u, _ in self.calls
        ]

    def __call__(self, url, headers, timeout):
        self.calls.append((url, dict(headers)))
        if self.replies:
            reply = self.replies.pop(0)
            if isinstance(reply, BaseException):
                raise reply
            return reply
        cve_id = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["cveId"][0]
        cve = self.cves.get(cve_id)
        return 200, {}, response(cve) if cve else response()


def make_client(tmp_path: Path, transport, **kwargs) -> nvd.NvdClient:
    kwargs.setdefault("sleep", lambda seconds: None)
    return nvd.NvdClient(cache_db=nvd_cache_db(tmp_path), transport=transport, **kwargs)


def nvd_cache_db(tmp_path: Path) -> Path:
    """The SQLite database holding the ``nvd_cache`` table of ``make_client(tmp_path, ...)``."""
    return tmp_path / "nvd-cache.db"
