"""User-facing vulnerability severity labels.

Since Phase 2.2 the Severity shown in reports is the CVSS rating selected from NVD
(``nvd.py``) and persisted with each finding at analysis time (``cvss_severity``), so
historical reports never change when NVD does. Canonical's priority is still stored
separately and shown as "Ubuntu Priority"; it no longer drives Severity. Nothing is guessed:
anything other than the four known levels (missing CVSS, 0.0, unexpected text, ...) is Unknown.
"""

CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
UNKNOWN = "Unknown"

SEVERITIES = (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)
_KNOWN = {s.casefold(): s for s in (CRITICAL, HIGH, MEDIUM, LOW)}

SEVERITY_CLASSES = {
    CRITICAL: "badge-critical",
    HIGH: "badge-danger",
    MEDIUM: "badge-warning",
    LOW: "badge-low",
    UNKNOWN: "badge-neutral",
}


def normalize_severity(value: object) -> str:
    """Map a stored rating to Critical / High / Medium / Low / Unknown."""
    if not isinstance(value, str):
        return UNKNOWN
    return _KNOWN.get(value.strip().casefold(), UNKNOWN)


def cvss_label(score: float | None, version: str | None) -> str:
    """Compact CVSS cell, e.g. "9.8 (v3.1)"; "—" when no score was captured."""
    if score is None:
        return "—"
    return f"{score:.1f} (v{version})" if version else f"{score:.1f}"
