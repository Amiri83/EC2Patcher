"""Remote commands used by Phase 3 patch execution, and parsers for their output.

Every command is built from validated values only (staging directory ``/tmp/<server>``,
APT archive file names, package names) and each value is additionally shell-quoted. Each
command prints ``@@EC2P`` marked sections and ends with ``@@EC2P end`` so an incomplete
output (lost connection) is never mistaken for a result.

The only commands that change the server are: creating/cleaning the staging directory, the
single ``apt-get install`` of the explicit, verified local .deb files and, after a verified
patch, ``sudo reboot`` when /run/reboot-required exists and the operator did not skip it.
There is no ``apt-get upgrade``/``dist-upgrade``, no remote download (APT runs without any
remote sources) and no removal (``--no-remove``).
"""

import re
import shlex
from dataclasses import dataclass, field

from ec2patcher.services import debversion
from ec2patcher.services.apt_planner import PKG_NAME_RE, parse_simulation
from ec2patcher.services.server_state import MARK, split_sections
from ec2patcher.services.staging import MARKER, check_deb_filename

REMOTE_DIR_RE = re.compile(r"^/tmp/[A-Za-z0-9][A-Za-z0-9._-]*$")

# dpkg field layout identical to the Phase 2 inventory (server_state.DPKG_FORMAT).
QUERY_FORMAT = (
    r"${binary:Package}\t${Version}\t${source:Package}\t${source:Version}"
    r"\t${Architecture}\t${db:Status-Abbrev}\n"
)

# apt-get options shared by the simulation and the real install.
# No remote sources at all: APT can only use the explicit local .deb files plus what is
# already installed, so it can never download anything or pull in an unapproved update; a
# missing dependency becomes a hard error. (``--no-download`` is NOT usable: verified on
# Ubuntu 24.04 that it also stops APT from reading local .deb files.) The package cache files
# are disabled so this reduced view is never written to /var/cache/apt.
APT_SAFETY_OPTIONS = [
    "-o", "Dir::Etc::SourceList=/dev/null",
    "-o", "Dir::Etc::SourceParts=/dev/null",
    "-o", "Dir::Cache::pkgcache=",
    "-o", "Dir::Cache::srcpkgcache=",
    "--no-remove",  # abort instead of removing any package
    "--no-install-recommends",
    "-o", "Dpkg::Options::=--force-confdef",  # keep modified config files, never prompt
    "-o", "Dpkg::Options::=--force-confold",
]  # fmt: skip
# DEBIAN_FRONTEND: never wait for terminal input. NEEDRESTART_MODE=l: needrestart (Ubuntu
# 22.04+) only lists services instead of restarting them; EC2Patcher restarts nothing.
APT_ENV = ["env", "DEBIAN_FRONTEND=noninteractive", "NEEDRESTART_MODE=l"]


def _q(value: str) -> str:
    return shlex.quote(value)


def _check_dir(remote_dir: str) -> str:
    if not REMOTE_DIR_RE.match(remote_dir or "") or ".." in remote_dir:
        raise ValueError(f"Unexpected remote staging directory: {remote_dir!r}")
    return remote_dir


def _deb_paths(remote_dir: str, filenames: list[str]) -> list[str]:
    _check_dir(remote_dir)
    if not filenames:
        raise ValueError("No .deb files given.")
    return [f"{remote_dir}/{check_deb_filename(name)}" for name in filenames]


def _package_names(names: list[str]) -> list[str]:
    for name in names:
        if not PKG_NAME_RE.match(name or ""):
            raise ValueError(f"Refusing unexpected package name: {name!r}")
    return names


# --- sudo -----------------------------------------------------------------------------

SUDO_CHECK_COMMAND = (
    f"echo '{MARK}sudo'; if sudo -n true 2>/dev/null; then echo ok; else echo denied; fi; "
    f"echo '{MARK}end'"
)


def parse_sudo(stdout: str) -> bool:
    sections = split_sections(stdout)
    return "end" in sections and [ln.strip() for ln in sections.get("sudo", [])][:1] == ["ok"]


# --- staging directory ----------------------------------------------------------------


def stage_command(remote_dir: str) -> str:
    """Inspect ``/tmp/<server>``; create it (mode 700) only if it does not exist."""
    d = _q(_check_dir(remote_dir))
    return (
        f"echo '{MARK}stage'; "
        f"if [ -L {d} ]; then echo symlink; "
        f"elif [ -e {d} ] && [ ! -d {d} ]; then echo notdir; "
        f'elif [ -d {d} ]; then if [ "$(stat -c %u -- {d})" != "$(id -u)" ]; '
        f"then echo foreign-owner; else echo exists; echo '{MARK}entries'; ls -A1 -- {d}; fi; "
        f"elif mkdir -m 700 -- {d}; then echo created; else echo mkdir-failed; fi; "
        f"echo '{MARK}end'"
    )


def mark_command(remote_dir: str) -> str:
    d = _check_dir(remote_dir)
    return f"echo '{MARK}mark'; touch -- {_q(f'{d}/{MARKER}')} && echo ok; echo '{MARK}end'"


@dataclass
class StageResult:
    status: str  # created | exists | symlink | notdir | foreign-owner | mkdir-failed | invalid
    entries: list[str] = field(default_factory=list)


def parse_stage(stdout: str) -> StageResult:
    sections = split_sections(stdout)
    if "end" not in sections:
        return StageResult("invalid")
    status = next((ln.strip() for ln in sections.get("stage", []) if ln.strip()), "invalid")
    entries = [ln.strip() for ln in sections.get("entries", []) if ln.strip()]
    return StageResult(status, entries)


# --- transfer verification ------------------------------------------------------------


def verify_transfer_command(remote_dir: str, filenames: list[str]) -> str:
    paths = " ".join(_q(p) for p in _deb_paths(remote_dir, filenames))
    return (
        f"echo '{MARK}stat'; stat -c '%F|%s|%n' -- {paths} 2>&1; "
        f"echo '{MARK}sha256'; sha256sum -- {paths} 2>&1; "
        f"echo '{MARK}end'"
    )


@dataclass
class RemoteFile:
    kind: str | None = None
    size: int | None = None
    sha256: str | None = None


def parse_verify_transfer(stdout: str, remote_dir: str) -> dict[str, RemoteFile] | None:
    sections = split_sections(stdout)
    if "end" not in sections:
        return None
    files: dict[str, RemoteFile] = {}
    prefix = f"{remote_dir}/"
    for line in sections.get("stat", []):
        parts = line.strip().split("|", 2)
        if len(parts) == 3 and parts[1].isdigit() and parts[2].startswith(prefix):
            files.setdefault(parts[2][len(prefix) :], RemoteFile()).kind = parts[0]
            files[parts[2][len(prefix) :]].size = int(parts[1])
    for line in sections.get("sha256", []):
        m = re.match(r"^([0-9a-f]{64})\s+\*?(\S+)$", line.strip())
        if m and m.group(2).startswith(prefix):
            files.setdefault(m.group(2)[len(prefix) :], RemoteFile()).sha256 = m.group(1)
    return files


# --- simulation and install ----------------------------------------------------------


def simulate_command(remote_dir: str, filenames: list[str]) -> str:
    """``apt-get -s`` (simulation, no changes) of exactly the staged .debs."""
    args = ["sudo", "-n", *APT_ENV, "apt-get", "-s", *APT_SAFETY_OPTIONS, "install", "--"]
    args += _deb_paths(remote_dir, filenames)
    return (
        f"echo '{MARK}simulate'; {' '.join(_q(a) for a in args)} 2>&1; rc=$?; "
        f"echo '{MARK}rc'; echo $rc; echo '{MARK}end'"
    )


def install_command(remote_dir: str, filenames: list[str]) -> str:
    """The one package-changing command: install exactly the staged, verified .debs."""
    args = ["sudo", "-n", *APT_ENV, "apt-get", "install", "-y", *APT_SAFETY_OPTIONS]
    args += ["-o", "DPkg::Lock::Timeout=120", "--", *_deb_paths(remote_dir, filenames)]
    return (
        f"echo '{MARK}install'; {' '.join(_q(a) for a in args)} 2>&1 </dev/null; rc=$?; "
        f"echo '{MARK}rc'; echo $rc; echo '{MARK}end'"
    )


@dataclass
class AptResult:
    complete: bool  # end marker seen: apt finished and its exit status is known
    returncode: int | None
    output: list[str]


def parse_apt(stdout: str, section: str) -> AptResult:
    sections = split_sections(stdout)
    rc = next(
        (int(ln.strip()) for ln in sections.get("rc", []) if ln.strip().lstrip("-").isdigit()),
        None,
    )
    complete = "end" in sections and rc is not None
    return AptResult(complete, rc, sections.get(section, []))


@dataclass
class SimulationCheck:
    ok: bool
    problems: list[str]
    installs: list[tuple[str, str, str | None, str]]  # (package, arch, old, new)


def check_simulation(result: AptResult, expected: dict[tuple[str, str], tuple]) -> SimulationCheck:
    """Accept the simulation only if it installs exactly the approved package set.

    ``expected`` maps (package, arch) -> (before_version or None, target_version).
    """
    problems: list[str] = []
    if not result.complete:
        return SimulationCheck(False, ["The install simulation did not complete."], [])
    errors = [ln.strip() for ln in result.output if ln.strip().startswith("E:")]
    if result.returncode != 0:
        detail = "; ".join(errors[:5]) or f"exit status {result.returncode}"
        return SimulationCheck(False, [f"APT simulation failed: {detail}"], [])
    problems += [f"APT: {e}" for e in errors]
    installs, removals = parse_simulation(result.output)
    if removals:
        problems.append("APT would remove package(s): " + ", ".join(removals))
    seen: set[tuple[str, str]] = set()
    rows = []
    for deb in installs:
        name = deb.package.split(":", 1)[0]
        key = (name, deb.architecture)
        rows.append((name, deb.architecture, deb.current_version, deb.target_version))
        seen.add(key)
        if key not in expected:
            problems.append(
                f"Unexpected package in simulation: {name} ({deb.architecture}) "
                f"{deb.target_version}"
            )
            continue
        if deb.release.strip() != "local-deb":
            problems.append(
                f"{name}: simulation would not install it from the staged .deb file "
                f"(origin: {deb.release or 'unknown'})"
            )
        before, target = expected[key]
        if deb.target_version != target:
            problems.append(f"{name}: simulation installs {deb.target_version}, approved {target}")
        if (deb.current_version or None) != (before or None):
            problems.append(
                f"{name}: installed version is {deb.current_version or 'not installed'}, "
                f"analysis recorded {before or 'not installed'}"
            )
        try:
            if deb.current_version and (
                debversion.compare_versions(deb.target_version, deb.current_version) < 0
            ):
                problems.append(
                    f"{name}: would be DOWNGRADED {deb.current_version} -> {deb.target_version}"
                )
        except debversion.InvalidVersionError:
            problems.append(f"{name}: unparsable version in simulation output")
    for key in sorted(set(expected) - seen):
        problems.append(f"Approved package {key[0]} ({key[1]}) is missing from the simulation.")
    return SimulationCheck(not problems, problems, rows)


# --- post-install state ---------------------------------------------------------------


def post_install_command(packages: list[str]) -> str:
    """Read-only: package versions, dpkg health, reboot-required, package manager still busy."""
    names = " ".join(_q(n) for n in _package_names(sorted(set(packages))))
    return (
        f"echo '{MARK}dpkg'; dpkg-query -W -f='{QUERY_FORMAT}' -- {names} 2>/dev/null; "
        f"echo '{MARK}audit'; dpkg --audit 2>&1; echo '{MARK}audit-rc'; echo $?; "
        f"echo '{MARK}reboot'; if [ -e /run/reboot-required ]; then echo yes; "
        "cat /run/reboot-required.pkgs 2>/dev/null; else echo no; fi; "
        f"echo '{MARK}busy'; if pgrep -x dpkg >/dev/null || pgrep -x apt-get >/dev/null; "
        "then echo yes; else echo no; fi; "
        f"echo '{MARK}end'"
    )


@dataclass
class PackageState:
    name: str
    version: str
    source: str
    source_version: str
    architecture: str
    status: str

    @property
    def installed(self) -> bool:
        return self.status.startswith("ii")


@dataclass
class PostInstallState:
    packages: dict[tuple[str, str], PackageState]
    audit_ok: bool
    audit_output: list[str]
    reboot_required: bool
    reboot_packages: list[str]
    busy: bool


def parse_post_install(stdout: str) -> PostInstallState | None:
    """None if the output is incomplete (e.g. the connection dropped)."""
    sections = split_sections(stdout)
    needed = ("dpkg", "audit", "audit-rc", "reboot", "busy", "end")
    if any(s not in sections for s in needed):
        return None
    packages = {}
    for line in sections["dpkg"]:
        parts = [p.strip() for p in line.split("\t")]
        if len(parts) != 6:
            continue
        name, version, source, source_version, arch, status = parts
        base = name.split(":", 1)[0]
        packages[(base, arch)] = PackageState(
            base, version, source or base, source_version or version, arch, status
        )
    audit = [ln for ln in sections["audit"] if ln.strip()]
    audit_rc = next((ln.strip() for ln in sections["audit-rc"] if ln.strip()), "")
    reboot = [ln.strip() for ln in sections["reboot"] if ln.strip()]
    busy = [ln.strip() for ln in sections["busy"] if ln.strip()]
    if not reboot or reboot[0] not in ("yes", "no") or not busy:
        return None
    return PostInstallState(
        packages=packages,
        audit_ok=audit_rc == "0" and not audit,
        audit_output=audit,
        reboot_required=reboot[0] == "yes",
        reboot_packages=sorted(set(reboot[1:])),
        busy=busy[0] == "yes",
    )


# --- reboot ---------------------------------------------------------------------------

# Read-only: is a reboot pending right now, and which boot is this (to prove a reboot later).
REBOOT_CHECK_COMMAND = (
    f"echo '{MARK}reboot-check'; if [ -e /run/reboot-required ]; then echo yes; else echo no; "
    f"fi; echo '{MARK}boot-id'; cat /proc/sys/kernel/random/boot_id; echo '{MARK}end'"
)

# The session usually drops while the server goes down, so a missing end marker is expected;
# only a completed output with a non-zero exit status proves the reboot was refused.
REBOOT_COMMAND = (
    f"echo '{MARK}reboot-now'; sudo -n reboot 2>&1 </dev/null; rc=$?; "
    f"echo '{MARK}rc'; echo $rc; echo '{MARK}end'"
)

# Read-only, after reconnecting: boot id (must differ from before), uptime and kernel.
BOOT_STATE_COMMAND = (
    f"echo '{MARK}boot-state'; cat /proc/sys/kernel/random/boot_id; "
    f"echo '{MARK}uptime'; uptime -p; echo '{MARK}kernel'; uname -r; echo '{MARK}end'"
)


@dataclass
class RebootCheck:
    required: bool
    boot_id: str


def _first(sections: dict[str, list[str]], name: str) -> str:
    return next((ln.strip() for ln in sections.get(name, []) if ln.strip()), "")


def parse_reboot_check(stdout: str) -> RebootCheck | None:
    sections = split_sections(stdout)
    flag, boot_id = _first(sections, "reboot-check"), _first(sections, "boot-id")
    if "end" not in sections or flag not in ("yes", "no") or not boot_id:
        return None
    return RebootCheck(flag == "yes", boot_id)


def parse_reboot_refused(stdout: str) -> str | None:
    """The reason if ``sudo reboot`` provably failed; None if it was (probably) issued."""
    result = parse_apt(stdout, "reboot-now")
    if not result.complete or result.returncode == 0:
        return None
    detail = "; ".join(ln.strip() for ln in result.output if ln.strip())[:300]
    return f"sudo reboot failed (exit {result.returncode})" + (f": {detail}" if detail else ".")


@dataclass
class BootState:
    boot_id: str
    uptime: str
    kernel: str


def parse_boot_state(stdout: str) -> BootState | None:
    sections = split_sections(stdout)
    boot_id = _first(sections, "boot-state")
    if "end" not in sections or not boot_id:
        return None
    return BootState(boot_id, _first(sections, "uptime"), _first(sections, "kernel"))


# --- cleanup --------------------------------------------------------------------------


def cleanup_command(remote_dir: str, filenames: list[str]) -> str:
    """Remove exactly the staged files and the marker, then rmdir (fails if not empty)."""
    d = _check_dir(remote_dir)
    files = " ".join(_q(p) for p in [*_deb_paths(d, filenames), f"{d}/{MARKER}"])
    return (
        f"echo '{MARK}cleanup'; if [ -L {_q(d)} ]; then echo symlink; "
        f"else rm -f -- {files} 2>/dev/null; rmdir -- {_q(d)} 2>/dev/null; "
        f"if [ -e {_q(d)} ]; then echo kept; ls -A1 -- {_q(d)} 2>/dev/null | head -n 5; "
        "else echo removed; fi; fi; "
        f"echo '{MARK}end'"
    )


def parse_cleanup(stdout: str) -> tuple[bool, str]:
    sections = split_sections(stdout)
    lines = [ln.strip() for ln in sections.get("cleanup", []) if ln.strip()]
    if "end" not in sections or not lines:
        return False, "Remote cleanup output was incomplete."
    if lines[0] == "removed":
        return True, ""
    if lines[0] == "symlink":
        return False, "Remote staging path is a symbolic link; nothing was deleted."
    rest = [ln for ln in lines if ln not in ("kept",)]
    return False, "Remote staging directory was kept" + (
        f" (contains: {', '.join(rest[:5])})." if rest else "."
    )
