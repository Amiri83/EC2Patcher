"""User-facing vulnerability severity derived from Canonical's CVE priority.

The raw value is the word Canonical publishes in its OpenVEX notes ("... classified this CVE
as of <priority> priority", see ``security_metadata.PRIORITY_RE``) and is persisted with each
finding at analysis time. Severity is a pure function of that stored snapshot, so historical
reports never change when the metadata does. Nothing is guessed: anything other than the four
known levels (untriaged, negligible, missing, unexpected text, ...) is shown as Unknown.
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
    LOW: "badge-neutral",
    UNKNOWN: "badge-neutral",
}


def normalize_severity(priority: object) -> str:
    """Map a raw Canonical priority to Critical / High / Medium / Low / Unknown."""
    if not isinstance(priority, str):
        return UNKNOWN
    return _KNOWN.get(priority.strip().casefold(), UNKNOWN)
