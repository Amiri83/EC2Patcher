"""Read-only APT queries: candidate versions and the exact .deb download plan.

The queries run on the workstation against a private APT state (see local_apt); nothing
here installs, downloads or changes anything:

* ``apt-cache policy`` / ``apt-cache show`` only read the package lists.
* ``apt-get -s`` is a simulation (no root needed, no lock, no changes).
* ``apt-get --print-uris`` prints the URI, file name, size and checksum of every .deb the
  install *would* fetch, and exits without downloading. ``Dir::Cache::archives`` points at a
  non-existent directory so already-cached .debs are listed too (apt otherwise omits them),
  and ``Acquire::ForceHash=SHA256`` makes apt print SHA256 instead of MD5.

Package names and versions are validated against strict patterns and passed as separate
arguments (never through a shell). The outputs are combined into one marked transcript
(``transcript``) that the parsers below understand.
"""

import re
from dataclasses import dataclass, field
from urllib.parse import unquote, urlsplit

from ec2patcher.services import debversion
from ec2patcher.services.server_state import MARK, split_sections

PKG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]*(?::[a-z0-9-]+)?$")
VERSION_RE = re.compile(r"^(?:\d+:)?[0-9][A-Za-z0-9.+~:-]*$")

NONEXISTENT_ARCHIVE_DIR = "/nonexistent/ec2patcher-no-download/"
APT_PLAN_OPTIONS = [
    "-qq",
    "--only-upgrade",
    "--no-install-recommends",
    "-o", "Acquire::ForceHash=SHA256",
    "-o", f"Dir::Cache::archives={NONEXISTENT_ARCHIVE_DIR}",
]  # fmt: skip


class UnsafeArgumentError(ValueError):
    pass


def _check_name(name: str) -> str:
    if not PKG_NAME_RE.match(name or ""):
        raise UnsafeArgumentError(f"Refusing unexpected package name: {name!r}")
    return name


def _check_version(version: str) -> str:
    if not VERSION_RE.match(version or "") or not debversion.is_valid_version(version):
        raise UnsafeArgumentError(f"Refusing unexpected version: {version!r}")
    return version


def transcript(sections: list[tuple[str, str]]) -> str:
    """Join command outputs into the marked format parsed here (an ``end`` marker is added)."""
    lines = []
    for name, text in sections:
        lines.append(f"{MARK}{name}")
        lines.extend(text.splitlines())
    lines.append(f"{MARK}end")
    return "\n".join(lines) + "\n"


# --- candidate lookup ----------------------------------------------------------------


@dataclass
class Candidate:
    package: str
    installed: str | None
    candidate: str | None
    source: str | None = None
    source_version: str | None = None
    origins: list[str] = field(default_factory=list)  # repository lines for the candidate
    requests_reboot: bool = False  # installed postinst calls notify-reboot-required


def candidate_arguments(packages: list[str]) -> tuple[list[str], list[str]]:
    """``apt-cache`` arguments (after the options) for the policy and show queries."""
    names = [_check_name(p) for p in packages]
    return ["policy", "--", *names], ["show", "--no-all-versions", "--", *names]


def parse_policy(lines: list[str]) -> dict[str, dict]:
    """Parse ``apt-cache policy`` into {package: {installed, candidate, origins}}."""
    result: dict[str, dict] = {}
    current: dict | None = None
    in_table = False
    candidate_row = False
    for raw in lines:
        if not raw.strip():
            continue
        if not raw.startswith(" ") and raw.rstrip().endswith(":"):
            name = raw.strip()[:-1]
            current = result.setdefault(name, {"installed": None, "candidate": None, "origins": []})
            in_table = candidate_row = False
            continue
        if current is None:
            continue
        text = raw.strip()
        if text.startswith("Installed:"):
            value = text.split(":", 1)[1].strip()
            current["installed"] = None if value == "(none)" else value
        elif text.startswith("Candidate:"):
            value = text.split(":", 1)[1].strip()
            current["candidate"] = None if value == "(none)" else value
        elif text.startswith("Version table:"):
            in_table = True
        elif in_table:
            parts = text.replace("***", "").split()
            if len(parts) == 2 and parts[1].lstrip("-").isdigit():
                candidate_row = parts[0] == current["candidate"]
            elif candidate_row and len(parts) >= 3 and parts[0].lstrip("-").isdigit():
                current["origins"].append(" ".join(parts[1:]))
    return result


def parse_control_records(lines: list[str]) -> list[dict[str, str]]:
    """Parse RFC822-style records (``apt-cache show``); continuation lines are joined."""
    records: list[dict[str, str]] = []
    record: dict[str, str] = {}
    last_key = None
    for line in lines + [""]:
        if not line.strip():
            if record:
                records.append(record)
            record, last_key = {}, None
            continue
        if line[0] in " \t" and last_key:
            record[last_key] += " " + line.strip()
            continue
        key, sep, value = line.partition(":")
        if sep:
            last_key = key.strip()
            record[last_key] = value.strip()
    return records


def parse_candidates(stdout: str, packages: list[str]) -> dict[str, Candidate]:
    sections = split_sections(stdout)
    if "end" not in sections:
        raise ValueError("APT candidate query output was incomplete.")
    policy = parse_policy(sections.get("policy", []))
    shown: dict[str, dict[str, str]] = {}
    for record in parse_control_records(sections.get("show", [])):
        if "Package" in record:
            shown[record["Package"]] = record
            if record.get("Architecture"):
                shown[f"{record['Package']}:{record['Architecture']}"] = record
    hooks = {
        line.strip().rsplit("/", 1)[-1].removesuffix(".postinst")
        for line in sections.get("reboot-hooks", [])
        if line.strip()
    }
    result: dict[str, Candidate] = {}
    for name in packages:
        base = name.split(":", 1)[0]
        info = policy.get(name) or policy.get(base) or {}
        cand = Candidate(
            package=name,
            installed=info.get("installed"),
            candidate=info.get("candidate"),
            origins=info.get("origins", []),
            requests_reboot=name in hooks or base in hooks,
        )
        record = shown.get(name) or shown.get(base)
        if record and cand.candidate and record.get("Version") == cand.candidate:
            src = record.get("Source", "").strip()
            m = re.match(r"^(\S+)(?:\s+\((\S+)\))?$", src)
            if m:
                cand.source = m.group(1)
                cand.source_version = m.group(2) or cand.candidate
            else:
                cand.source, cand.source_version = base, cand.candidate
        result[name] = cand
    return result


# --- download plan -------------------------------------------------------------------


@dataclass
class PlannedDeb:
    package: str
    architecture: str
    current_version: str | None  # None -> newly installed dependency
    target_version: str
    release: str = ""
    deb_filename: str | None = None
    uri: str | None = None
    size: int | None = None
    checksum: str | None = None
    error: str | None = None


@dataclass
class DownloadPlan:
    ok: bool
    packages: list[PlannedDeb] = field(default_factory=list)
    removals: list[str] = field(default_factory=list)
    apt_arguments: list[str] = field(default_factory=list)
    error: str | None = None
    messages: list[str] = field(default_factory=list)


def plan_arguments(requests: list[tuple[str, str]]) -> list[str]:
    """``apt-get install`` arguments (after the subcommand) pinning each package version."""
    specs = [f"{_check_name(n)}={_check_version(v)}" for n, v in requests]
    return [*APT_PLAN_OPTIONS, "--", *specs]


def plan_commands(requests: list[tuple[str, str]]) -> tuple[list[str], list[str]]:
    """``apt-get`` arguments (after the options): simulation, then --print-uris. Neither
    installs or downloads anything."""
    args = plan_arguments(requests)
    return ["-s", "install", *args], ["--print-uris", "install", *args]


_INST_RE = re.compile(r"^Inst (\S+) (?:\[(\S+)\] )?\((\S+) (.*?)\s*\[([^\]]+)\]\)")
_REMV_RE = re.compile(r"^Remv (\S+)")
_URI_RE = re.compile(r"^'([^']+)' (\S+) (\d+) (\S+)\s*$")


def parse_simulation(lines: list[str]) -> tuple[list[PlannedDeb], list[str]]:
    installs, removals = [], []
    for line in lines:
        m = _INST_RE.match(line.strip())
        if m:
            name, old, new, release, arch = m.groups()
            installs.append(PlannedDeb(name, arch, old, new, release.strip()))
            continue
        r = _REMV_RE.match(line.strip())
        if r:
            removals.append(r.group(1))
    return installs, removals


def parse_uris(lines: list[str]) -> dict[str, dict]:
    """Parse ``--print-uris`` lines keyed by destination file name."""
    entries = {}
    for line in lines:
        m = _URI_RE.match(line.strip())
        if not m:
            continue
        uri, filename, size, checksum = m.groups()
        entries[filename] = {"uri": uri, "filename": filename, "size": int(size), "hash": checksum}
    return entries


def expected_deb_filename(package: str, version: str, arch: str) -> str:
    """APT's archive file name: <name>_<version>_<arch>.deb with ':' encoded as %3a."""
    return f"{package.split(':', 1)[0]}_{version.replace(':', '%3a')}_{arch}.deb"


def uri_basename_matches(uri: str, filename: str) -> bool:
    """True if the URI's file name is ``filename``.

    Ubuntu pool file names omit the epoch (pool/.../libaudit1_3.1.2-2_amd64.deb) while APT's
    archive file name keeps it (libaudit1_1%3a3.1.2-2_amd64.deb), so both forms are accepted.
    """
    basename = unquote(urlsplit(uri).path.rsplit("/", 1)[-1])
    name = unquote(filename)
    package, _, rest = name.partition("_")
    version = rest.split("_", 1)[0]
    without_epoch = f"{package}_{rest.split(':', 1)[1]}" if ":" in version else name
    return basename in (name, without_epoch)


def _uri_matches(uri: str, filename: str) -> bool:
    parts = urlsplit(uri)
    if parts.scheme not in ("http", "https", "file", "mirror+http", "mirror+https"):
        return False
    return uri_basename_matches(uri, filename)


def _rc(sections: dict[str, list[str]], key: str) -> int | None:
    for line in sections.get(key, []):
        if line.strip().lstrip("-").isdigit():
            return int(line.strip())
    return None


def _errors(lines: list[str]) -> list[str]:
    return [ln.strip() for ln in lines if ln.strip().startswith(("E:", "W:"))]


def parse_plan(stdout: str, requests: list[tuple[str, str]]) -> DownloadPlan:
    """Combine the simulation (what changes) with --print-uris (where each .deb comes from)."""
    plan = DownloadPlan(ok=False, apt_arguments=["install", *plan_arguments(requests)])
    sections = split_sections(stdout)
    if "end" not in sections:
        plan.error = "APT planning output was incomplete."
        return plan
    sim_rc, uri_rc = _rc(sections, "simulate-rc"), _rc(sections, "uris-rc")
    sim_lines, uri_lines = sections.get("simulate", []), sections.get("uris", [])
    plan.messages = _errors(sim_lines) + [m for m in _errors(uri_lines) if m not in sim_lines]
    if sim_rc != 0:
        detail = "; ".join(_errors(sim_lines)) or f"exit status {sim_rc}"
        plan.error = f"APT could not plan the upgrade: {detail}"
        return plan
    installs, plan.removals = parse_simulation(sim_lines)
    if not installs:
        plan.error = "APT simulation did not list any package to upgrade."
        return plan
    uris = parse_uris(uri_lines) if uri_rc == 0 else {}
    uri_problem = None
    if uri_rc != 0:
        uri_problem = "; ".join(_errors(uri_lines)) or f"apt --print-uris exit status {uri_rc}"
    for deb in installs:
        expected = expected_deb_filename(deb.package, deb.target_version, deb.architecture)
        entry = uris.get(expected)
        if entry is None:
            deb.error = uri_problem or "APT did not print a download URI for this package."
        elif not _uri_matches(entry["uri"], expected):
            deb.error = f"Unexpected URI for {expected}: {entry['uri'][:200]}"
        else:
            deb.deb_filename = expected
            deb.uri = entry["uri"]
            deb.size = entry["size"]
            deb.checksum = entry["hash"]
    plan.packages = installs
    plan.ok = True
    return plan
