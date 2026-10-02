"""Read-only collection of an Amazon Linux 2023 server's release, kernel, reboot state and
installed rpm packages.

One constant remote command (no user input, no sudo) prints marked sections like the Ubuntu
facts command (``server_state.MARK``). It starts with the same hostname / os-release sections
so the OS detection works on its output too. The release lock (``releasever``) comes from
``/etc/dnf/vars/releasever`` when set (e.g. ``latest``), else from
``/etc/amazon-linux-release``. ``needs-restarting -r`` only reads the rpm database and the
boot time. Advisories are fetched on the workstation (see amazon_updateinfo).
"""

import re
from dataclasses import dataclass

from ec2patcher.services import rpmversion
from ec2patcher.services.server_state import (
    MARK,
    InstalledPackage,
    RemoteOutputError,
    ServerFacts,
    parse_os_release,
    split_sections,
)

RPM_QUERY_FORMAT = r"%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} %{ARCH}\n"

FACTS_COMMAND = (
    f"echo '{MARK}hostname'; hostname; "
    f"echo '{MARK}os-release'; cat /etc/os-release; "
    f"echo '{MARK}amazon-linux-release'; cat /etc/amazon-linux-release 2>/dev/null; "
    f"echo '{MARK}dnf-releasever'; cat /etc/dnf/vars/releasever 2>/dev/null; "
    f"echo '{MARK}arch'; uname -m; "
    f"echo '{MARK}kernel'; uname -r; "
    f"echo '{MARK}reboot'; "
    "if command -v needs-restarting >/dev/null 2>&1; then needs-restarting -r 2>&1; rc=$?; "
    "else rc=unavailable; fi; "
    f"echo '{MARK}reboot-rc'; echo $rc; "
    f"echo '{MARK}rpm'; rpm -qa --qf '{RPM_QUERY_FORMAT}'; rc=$?; "
    f"echo '{MARK}rpm-rc'; echo $rc; "
    f"echo '{MARK}end'"
)

SUPPORTED_VERSION_ID = "2023"
ARCHITECTURES = ("x86_64", "aarch64")
LATEST = "latest"
_RELEASEVER_RE = re.compile(r"\b(2023\.\d+\.\d{8})\b")
_RPM_NAME_RE = re.compile(r"^[A-Za-z0-9_.+-]+$")
_ARCH_RE = re.compile(r"^[A-Za-z0-9_]+$")
# needs-restarting -r lists the updated core packages as "  * <name>".
_REBOOT_ITEM_RE = re.compile(r"^\s*\*\s*(\S+)")
NEEDS_RESTARTING_MISSING = (
    "needs-restarting is not installed on the server (dnf-utils), so whether it needs a "
    "reboot is unknown."
)


@dataclass
class AmazonFacts(ServerFacts):
    """``codename`` holds the effective releasever (what the analysis is pinned to);
    ``system_release`` the installed release from /etc/amazon-linux-release."""

    system_release: str = ""
    releasever_source: str = ""  # where the releasever came from

    @property
    def release_label(self) -> str:
        return self.pretty_name or f"Amazon Linux {self.version_id}"

    @property
    def releasever(self) -> str:
        return self.codename


def parse_rpm_inventory(lines: list[str]) -> tuple[list[InstalledPackage], int]:
    """Parse ``rpm -qa`` rows ``name epoch:version-release arch``.

    Returns (packages, number_of_malformed_rows). gpg-pubkey pseudo packages (arch
    ``(none)``) are skipped. Versions are stored as ``[epoch:]version-release`` (epoch only
    when non-zero); rpm names its packages itself, so source = binary name."""
    packages: list[InstalledPackage] = []
    malformed = 0
    for line in lines:
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 3:
            malformed += 1
            continue
        name, evr, arch = parts
        if arch == "(none)" or name == "gpg-pubkey":
            continue
        try:
            epoch, version, release = rpmversion.parse_evr(evr)
        except rpmversion.InvalidVersionError:
            malformed += 1
            continue
        if not _RPM_NAME_RE.match(name) or not _ARCH_RE.match(arch) or not release:
            malformed += 1
            continue
        normalized = rpmversion.format_evr(epoch, version, release)
        packages.append(
            InstalledPackage(
                name=name, version=normalized, source=name, source_version=normalized,
                architecture=arch,
            )
        )  # fmt: skip
    return packages, malformed


def parse_reboot(lines: list[str], rc: str) -> tuple[bool | None, list[str], str | None]:
    """(reboot required or None if unknown, updated core packages, warning) from the output
    and exit status of ``needs-restarting -r``: 1 = reboot required, 0 = not required."""
    text = "\n".join(lines)
    if rc == "unavailable":
        return None, [], NEEDS_RESTARTING_MISSING
    if rc == "1" and "Reboot is required" in text:
        items = sorted({m.group(1) for ln in lines if (m := _REBOOT_ITEM_RE.match(ln))})
        return True, items, None
    if rc == "0" and ("Reboot should not be necessary" in text or "No core libraries" in text):
        return False, [], None
    detail = " ".join(ln.strip() for ln in lines if ln.strip())[:300] or "no output"
    return None, [], f"needs-restarting -r failed (exit status {rc or '?'}): {detail}"


def _first(sections: dict[str, list[str]], name: str) -> str:
    return next((ln.strip() for ln in sections.get(name, []) if ln.strip()), "")


def resolve_releasever(
    dnf_var: str, release_file: str, os_release: dict[str, str], packages
) -> tuple[str, str, str]:
    """(effective releasever, installed release, source of the releasever).

    dnf uses /etc/dnf/vars/releasever when it exists (``latest`` or a pinned version);
    otherwise the installed release (system-release) is the lock."""
    installed = ""
    for text in (
        release_file,
        os_release.get("PRETTY_NAME", ""),
        os_release.get("VERSION", ""),
        next((p.version for p in packages if p.name == "system-release"), ""),
    ):
        match = _RELEASEVER_RE.search(text or "")
        if match:
            installed = match.group(1)
            break
    var = dnf_var.strip()
    if var == LATEST or _RELEASEVER_RE.fullmatch(var):
        return var, installed, "/etc/dnf/vars/releasever"
    return installed, installed, "/etc/amazon-linux-release" if installed else ""


def parse_facts(stdout: str) -> AmazonFacts:
    """Parse FACTS_COMMAND output. Raises RemoteOutputError for unusable output."""
    sections = split_sections(stdout)
    if "end" not in sections or "rpm" not in sections:
        raise RemoteOutputError("Remote output was incomplete (end marker missing).")
    osr = parse_os_release(sections.get("os-release", []))
    arch, kernel = _first(sections, "arch"), _first(sections, "kernel")
    if not arch or not kernel:
        raise RemoteOutputError("Could not determine architecture or running kernel.")
    if _first(sections, "rpm-rc") not in ("", "0"):
        raise RemoteOutputError(f"rpm -qa failed (exit status {_first(sections, 'rpm-rc')}).")
    packages, malformed = parse_rpm_inventory(sections["rpm"])
    if not packages:
        raise RemoteOutputError("The installed package list (rpm -qa) was empty.")
    reboot, reboot_pkgs, reboot_warning = parse_reboot(
        sections.get("reboot", []), _first(sections, "reboot-rc")
    )
    releasever, installed, source = resolve_releasever(
        _first(sections, "dnf-releasever"), _first(sections, "amazon-linux-release"), osr, packages
    )
    facts = AmazonFacts(
        hostname=_first(sections, "hostname") or "unknown",
        os_id=osr.get("ID", ""),
        version_id=osr.get("VERSION_ID", ""),
        codename=releasever,
        pretty_name=osr.get("PRETTY_NAME", ""),
        architecture=arch,
        kernel=kernel,
        reboot_required=reboot,  # None = unknown
        reboot_required_pkgs=reboot_pkgs,
        packages=packages,
        system_release=installed,
        releasever_source=source,
    )
    if reboot_warning:
        facts.warnings.append(reboot_warning)
    if malformed:
        facts.warnings.append(f"{malformed} package inventory row(s) could not be parsed.")
    return facts


def check_supported(facts: AmazonFacts) -> str | None:
    """Error message if the server is not an Amazon Linux 2023 release this tool can analyze."""
    if facts.os_id != "amzn" or facts.version_id != SUPPORTED_VERSION_ID:
        return f"Unsupported operating system: {facts.pretty_name or facts.os_id or 'unknown'}."
    if facts.architecture not in ARCHITECTURES:
        return f"Unsupported Amazon Linux 2023 architecture: {facts.architecture}."
    if not facts.releasever:
        return (
            "Could not determine the Amazon Linux 2023 release version (releasever) from "
            "/etc/dnf/vars/releasever or /etc/amazon-linux-release."
        )
    return None
