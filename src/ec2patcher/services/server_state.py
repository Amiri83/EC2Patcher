"""Read-only collection of a server's Ubuntu release, kernel and installed package state.

One constant remote command (no user input) prints clearly marked sections that are parsed
here. Nothing on the server is modified and no privilege escalation (sudo) is used.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from ec2patcher.services import debversion

MARK = "@@EC2P "

# dpkg-query fields: binary name (arch-qualified for Multi-Arch: same), binary version,
# source package name and source version (dpkg derives both from the Source: field),
# architecture and the abbreviated status (e.g. "ii ").
DPKG_FORMAT = (
    r"${binary:Package}\t${Version}\t${source:Package}\t${source:Version}"
    r"\t${Architecture}\t${db:Status-Abbrev}\n"
)

FACTS_COMMAND = (
    f"echo '{MARK}hostname'; hostname; "
    f"echo '{MARK}os-release'; cat /etc/os-release; "
    f"echo '{MARK}arch'; dpkg --print-architecture; "
    f"echo '{MARK}kernel'; uname -r; "
    f"echo '{MARK}reboot'; "
    "if [ -e /run/reboot-required ] || [ -e /var/run/reboot-required ]; then echo yes; "
    "cat /run/reboot-required.pkgs 2>/dev/null || cat /var/run/reboot-required.pkgs 2>/dev/null; "
    "else echo no; fi; "
    f"echo '{MARK}apt-update-stamp'; "
    "stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null; "
    f"echo '{MARK}apt-lists-mtime'; stat -c %Y /var/lib/apt/lists 2>/dev/null; "
    f"echo '{MARK}now'; date +%s; "
    f"echo '{MARK}dpkg'; dpkg-query -W -f='{DPKG_FORMAT}'; "
    f"echo '{MARK}end'"
)

# Ubuntu releases the analyzer understands (VERSION_ID -> codename). LTS releases on EC2.
SUPPORTED_RELEASES = {
    "18.04": "bionic",
    "20.04": "focal",
    "22.04": "jammy",
    "24.04": "noble",
    "26.04": "resolute",
}

APT_STALE_AFTER_HOURS = 48

_PKG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?$")


class RemoteOutputError(ValueError):
    """The remote command output could not be understood."""


@dataclass
class InstalledPackage:
    name: str  # binary package, arch-qualified when dpkg does so (e.g. "libc6:amd64")
    version: str
    source: str
    source_version: str
    architecture: str

    @property
    def base_name(self) -> str:
        return self.name.split(":", 1)[0]


@dataclass
class ServerFacts:
    hostname: str
    os_id: str
    version_id: str
    codename: str
    pretty_name: str
    architecture: str
    kernel: str
    reboot_required: bool
    reboot_required_pkgs: list[str] = field(default_factory=list)
    apt_updated_at: str | None = None  # ISO UTC
    apt_updated_source: str | None = None
    apt_age_hours: float | None = None
    packages: list[InstalledPackage] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def release_label(self) -> str:
        return self.pretty_name or f"Ubuntu {self.version_id}"

    def by_source(self) -> dict[str, list[InstalledPackage]]:
        grouped: dict[str, list[InstalledPackage]] = {}
        for pkg in self.packages:
            grouped.setdefault(pkg.source, []).append(pkg)
        return grouped

    def by_name(self) -> dict[str, InstalledPackage]:
        index = {}
        for pkg in self.packages:
            index[pkg.name] = pkg
            index.setdefault(pkg.base_name, pkg)
        return index


def split_sections(stdout: str) -> dict[str, list[str]]:
    """Split marked output into {section: lines}. Text before the first marker (MOTD) is dropped."""
    sections: dict[str, list[str]] = {}
    current: list[str] | None = None
    for line in stdout.splitlines():
        if line.startswith(MARK):
            current = sections.setdefault(line[len(MARK) :].strip(), [])
        elif current is not None:
            current.append(line)
    return sections


def parse_os_release(lines: list[str]) -> dict[str, str]:
    data = {}
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if sep and key:
            data[key] = value.strip().strip('"').strip("'")
    return data


def parse_dpkg_inventory(lines: list[str]) -> tuple[list[InstalledPackage], int]:
    """Parse dpkg-query rows. Only fully installed packages ('ii') are returned.

    Returns (packages, number_of_malformed_rows).
    """
    packages: list[InstalledPackage] = []
    malformed = 0
    for line in lines:
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 6:
            malformed += 1
            continue
        name, version, source, source_version, arch, status = (p.strip() for p in parts)
        if not status.startswith("ii"):
            continue  # removed-but-configured ("rc"), half-installed, etc.
        if (
            not _PKG_NAME_RE.match(name)
            or not debversion.is_valid_version(version)
            or not debversion.is_valid_version(source_version or version)
        ):
            malformed += 1
            continue
        packages.append(
            InstalledPackage(
                name=name,
                version=version,
                source=source or name.split(":", 1)[0],
                source_version=source_version or version,
                architecture=arch,
            )
        )
    return packages, malformed


def _epoch_to_iso(value: int) -> str:
    return datetime.fromtimestamp(value, timezone.utc).replace(microsecond=0).isoformat()


def _first_int(lines: list[str] | None) -> int | None:
    for line in lines or []:
        if line.strip().isdigit():
            return int(line.strip())
    return None


def parse_facts(stdout: str) -> ServerFacts:
    """Parse FACTS_COMMAND output. Raises RemoteOutputError for unusable output."""
    sections = split_sections(stdout)
    if "end" not in sections or "dpkg" not in sections:
        raise RemoteOutputError("Remote output was incomplete (end marker missing).")
    osr = parse_os_release(sections.get("os-release", []))
    arch = next((ln.strip() for ln in sections.get("arch", []) if ln.strip()), "")
    kernel = next((ln.strip() for ln in sections.get("kernel", []) if ln.strip()), "")
    hostname = next((ln.strip() for ln in sections.get("hostname", []) if ln.strip()), "")
    reboot_lines = [ln.strip() for ln in sections.get("reboot", []) if ln.strip()]
    if not reboot_lines or reboot_lines[0] not in ("yes", "no"):
        raise RemoteOutputError("Could not determine the reboot-required state.")
    if not arch or not kernel:
        raise RemoteOutputError("Could not determine architecture or running kernel.")
    packages, malformed = parse_dpkg_inventory(sections["dpkg"])
    if not packages:
        raise RemoteOutputError("The installed package list (dpkg-query) was empty.")

    facts = ServerFacts(
        hostname=hostname or "unknown",
        os_id=osr.get("ID", ""),
        version_id=osr.get("VERSION_ID", ""),
        codename=osr.get("VERSION_CODENAME") or osr.get("UBUNTU_CODENAME", ""),
        pretty_name=osr.get("PRETTY_NAME", ""),
        architecture=arch,
        kernel=kernel,
        reboot_required=reboot_lines[0] == "yes",
        reboot_required_pkgs=sorted(set(reboot_lines[1:])),
        packages=packages,
    )
    if malformed:
        facts.warnings.append(f"{malformed} package inventory row(s) could not be parsed.")

    now = _first_int(sections.get("now"))
    stamp = _first_int(sections.get("apt-update-stamp"))
    source = "last successful apt update (update-success-stamp)"
    if stamp is None:
        stamp = _first_int(sections.get("apt-lists-mtime"))
        source = "APT package list directory modification time"
    if stamp is not None:
        facts.apt_updated_at = _epoch_to_iso(stamp)
        facts.apt_updated_source = source
        if now is not None:
            facts.apt_age_hours = max(0.0, (now - stamp) / 3600)
            if facts.apt_age_hours > APT_STALE_AFTER_HOURS:
                facts.warnings.append(
                    f"APT package lists were last updated {facts.apt_age_hours / 24:.1f} days "
                    "ago; newer fixes may not be visible to APT on this server."
                )
    else:
        facts.warnings.append("The age of the APT package lists could not be determined.")
    return facts


def apt_lists_fresh(age_hours: float | None) -> bool:
    """True only when the APT package lists are known to be recent enough to trust a
    "fixed version not offered by APT" verdict. An unknown age is never assumed fresh."""
    return age_hours is not None and age_hours <= APT_STALE_AFTER_HOURS


def check_supported(facts: ServerFacts) -> str | None:
    """Return an error message if the server's OS is not a supported Ubuntu release."""
    if facts.os_id != "ubuntu":
        return f"Unsupported operating system: {facts.pretty_name or facts.os_id or 'unknown'}."
    expected = SUPPORTED_RELEASES.get(facts.version_id)
    if expected is None:
        return f"Unsupported Ubuntu release: {facts.version_id or 'unknown'}."
    if facts.codename != expected:
        return (
            f"Ubuntu {facts.version_id} reported codename '{facts.codename}', "
            f"expected '{expected}'."
        )
    return None
