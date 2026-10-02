"""OS adapters and OS detection from /etc/os-release.

Ubuntu is the only implementation. Analysis collects facts with one read-only ssh command:
the default adapter's ``facts_command``, whose output starts with the OS-independent hostname
and os-release sections. The OS is detected from that section before anything else is parsed;
a server whose os-release names an OS without an adapter is reported as "OS not supported
yet" instead of failing on output it cannot understand. (An adapter whose facts differ from
Ubuntu's will need that command to branch on the OS in the remote shell.)
"""

from ec2patcher.services import server_state
from ec2patcher.services.os_adapters.base import AnalysisContext, Assessment, OsAdapter
from ec2patcher.services.os_adapters.ubuntu import UbuntuAdapter

__all__ = [
    "ADAPTERS",
    "DEFAULT",
    "UNSUPPORTED_PREFIX",
    "UNSUPPORTED_STATUS",
    "AnalysisContext",
    "Assessment",
    "OsAdapter",
    "UbuntuAdapter",
    "describe",
    "detect",
    "for_analysis",
    "get",
    "is_blocker",
    "os_release_from_output",
    "unsupported_message",
]

UBUNTU = UbuntuAdapter()
ADAPTERS: tuple[OsAdapter, ...] = (UBUNTU,)
# Collects the facts used for detection, and parses output without a usable os-release.
DEFAULT: OsAdapter = UBUNTU

UNSUPPORTED_PREFIX = "OS not supported yet"
# Server analysis status for an OS without an adapter (not a failure; nothing to patch).
UNSUPPORTED_STATUS = "unsupported"


def os_release_from_output(stdout: str) -> dict[str, str]:
    """/etc/os-release fields from the ``os-release`` section of a facts command output."""
    sections = server_state.split_sections(stdout or "")
    return server_state.parse_os_release(sections.get("os-release", []))


def detect(os_release: dict[str, str]) -> OsAdapter | None:
    """The adapter for this OS; None if os-release names an OS without one.

    Output without an os-release ID is left to the default adapter, whose parser reports
    what is wrong with it."""
    if not os_release.get("ID"):
        return DEFAULT
    return next((a for a in ADAPTERS if a.matches(os_release)), None)


def describe(os_release: dict[str, str]) -> str:
    """'<name> <version>' from os-release, e.g. 'Amazon Linux 2023'."""
    name = os_release.get("NAME") or os_release.get("ID") or "unknown"
    version = os_release.get("VERSION_ID", "")
    if not version and os_release.get("PRETTY_NAME"):
        return os_release["PRETTY_NAME"]
    return f"{name} {version}".strip()


def unsupported_message(os_release: dict[str, str]) -> str:
    return f"{UNSUPPORTED_PREFIX}: {describe(os_release)}"


def get(os_id: str | None) -> OsAdapter | None:
    """The adapter stored with an analysis; None (no os_id) means Ubuntu, the only OS that
    could be analyzed before the adapter was recorded."""
    os_id = os_id or UBUNTU.os_id
    return next((a for a in ADAPTERS if a.os_id == os_id), None)


def for_analysis(analysis) -> OsAdapter | None:
    return get(getattr(analysis, "os_id", None))


def is_blocker(error: str) -> bool:
    return any(a.is_blocker(error) for a in ADAPTERS)
