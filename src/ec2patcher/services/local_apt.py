"""Workstation-side APT resolution against a private, per-release APT state.

Servers are read-only inputs for patch planning: they only report their Ubuntu release,
architecture and installed packages (dpkg-query). APT candidates and the exact .deb plan are
resolved here, on the workstation, with apt-get / apt-cache pointed at a private state
directory per Ubuntu release and architecture:

    <state root>/<codename>-<arch>/         e.g. ~/.local/share/ec2patcher/apt/noble-amd64/
        etc/apt.conf              passed as $APT_CONFIG: points Dir::Etc::parts / main at the
                                  empty etc/apt.conf.d, so the workstation's apt.conf(.d) -
                                  including APT::Update hooks - is never read or run
        etc/sources.list          Ubuntu archive pockets <codename>, <codename>-updates and
                                  <codename>-security only (never -proposed / -backports),
                                  restricted to [arch=<arch>] and the Ubuntu archive keyring
        etc/sources.list.d/       empty: the workstation's own sources are never read
        etc/preferences.d/        empty: no workstation pinning
        etc/trusted.gpg.d/        empty
        state/lists/              package lists written by the private ``apt-get update``
        state/ec2patcher-updated  stamp of the last successful update (+ sources hash)
        cache/                    apt's cache directory (no .deb is ever downloaded)
        status/                   temporary dpkg status files built from a server's dpkg-query

Every invocation passes ``-o Dir::State=... -o Dir::Cache=... -o Dir::Etc::sourcelist=...``
(and the other Dir::Etc overrides below) plus the private $APT_CONFIG, so the system APT
state (/var/lib/apt, /etc/apt configuration, sources, pinning and hooks) is never used or
modified. Nothing runs with sudo; commands are argument
lists without a shell. The private lists are refreshed with ``apt-get update`` when they are
older than the configured maximum age (at most once per analysis run and release). A failed
update is reported as an error; candidates are never guessed.
"""

import contextlib
import hashlib
import json
import logging
import os
import re
import subprocess  # noqa: S404 - apt-get / apt-cache run as argument lists, never via a shell
import tempfile
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ec2patcher.services import apt_planner
from ec2patcher.services.server_state import SUPPORTED_RELEASES, InstalledPackage, ServerFacts

logger = logging.getLogger(__name__)

ARCHIVE_MIRROR = "http://archive.ubuntu.com/ubuntu"
SECURITY_MIRROR = "http://security.ubuntu.com/ubuntu"
PORTS_MIRROR = "http://ports.ubuntu.com/ubuntu-ports"
ARCHIVE_ARCHITECTURES = ("amd64", "i386")  # everything else is served from ubuntu-ports
COMPONENTS = ("main", "restricted", "universe", "multiverse")
KEYRING = "/usr/share/keyrings/ubuntu-archive-keyring.gpg"
STAMP_NAME = "ec2patcher-updated"
UPDATE_TIMEOUT_SECONDS = 600
QUERY_TIMEOUT_SECONDS = 180
ARCH_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

Runner = Callable[..., subprocess.CompletedProcess]
# Looked up when a LocalApt is created, so tests can substitute a fake apt backend.
default_runner: Runner = subprocess.run


class AptResolutionError(RuntimeError):
    """The private APT state could not be prepared or queried."""


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def pockets(codename: str) -> list[str]:
    return [codename, f"{codename}-updates", f"{codename}-security"]


def sources_list(codename: str, architecture: str, keyring: str = KEYRING) -> str:
    """One-line sources for the release pocket, -updates and -security of one architecture."""
    options = f"[arch={architecture} signed-by={keyring}]"
    if architecture in ARCHIVE_ARCHITECTURES:
        mirrors = [ARCHIVE_MIRROR, ARCHIVE_MIRROR, SECURITY_MIRROR]
    else:
        mirrors = [PORTS_MIRROR] * 3
    components = " ".join(COMPONENTS)
    return "".join(
        f"deb {options} {mirror} {suite} {components}\n"
        for mirror, suite in zip(mirrors, pockets(codename), strict=True)
    )


def status_record(pkg: InstalledPackage) -> str:
    """dpkg status stanza reproducing one installed package of the server."""
    lines = [
        f"Package: {pkg.base_name}",
        "Status: install ok installed",
        f"Architecture: {pkg.architecture}",
        f"Version: {pkg.version}",
    ]
    if pkg.source_version != pkg.version:
        lines.append(f"Source: {pkg.source} ({pkg.source_version})")
    elif pkg.source != pkg.base_name:
        lines.append(f"Source: {pkg.source}")
    lines += [f"{key}: {value}" for key, value in pkg.relations.items()]
    return "\n".join(lines) + "\n"


@dataclass
class AptState:
    """A prepared private APT state (package lists present and within the maximum age)."""

    codename: str
    architecture: str
    root: Path
    updated_at: datetime

    @property
    def label(self) -> str:
        return f"{self.architecture}: {', '.join(pockets(self.codename))}"


class LocalApt:
    def __init__(
        self,
        root: Path,
        max_age: timedelta,
        runner: Runner | None = None,
        clock: Callable[[], datetime] = _now,
        keyring: str = KEYRING,
    ):
        self.root = Path(root).expanduser().absolute()  # apt resolves relative Dir:: against /
        self.max_age = max_age
        self.runner = runner or default_runner
        self.clock = clock
        self.keyring = keyring
        self._lock = threading.Lock()
        self._prepared: dict[tuple[str, str], AptState | AptResolutionError] = {}

    def start_run(self) -> None:
        """Forget which states were prepared, so a new analysis run re-checks their age."""
        with self._lock:
            self._prepared.clear()

    # --- private state -----------------------------------------------------------------

    def state_dir(self, codename: str, architecture: str) -> Path:
        return self.root / f"{codename}-{architecture}"

    def options(self, root: Path, architecture: str, status: Path) -> list[str]:
        etc = root / "etc"
        settings = {
            "Dir::State": root / "state",
            "Dir::State::status": status,
            "Dir::Cache": root / "cache",
            "Dir::Cache::pkgcache": "",  # build the cache in memory: status differs per server
            "Dir::Cache::srcpkgcache": "",
            "Dir::Etc::sourcelist": etc / "sources.list",
            "Dir::Etc::sourceparts": etc / "sources.list.d",
            "Dir::Etc::preferences": etc / "preferences",
            "Dir::Etc::preferencesparts": etc / "preferences.d",
            "Dir::Etc::trusted": etc / "trusted.gpg",
            "Dir::Etc::trustedparts": etc / "trusted.gpg.d",
            "APT::Architecture": architecture,
            "APT::Architectures": architecture,
            "Acquire::Languages": "none",
        }
        args: list[str] = []
        for key, value in settings.items():
            args += ["-o", f"{key}={value}"]
        return args

    def prepare(self, codename: str, architecture: str) -> AptState:
        """Private state for a release/architecture, running ``apt-get update`` when the
        lists are missing, older than the maximum age or built from other sources.

        Raises AptResolutionError; a failure is remembered for the rest of the run."""
        key = (codename, architecture)
        with self._lock:
            known = self._prepared.get(key)
            if isinstance(known, AptResolutionError):
                raise known
            if known is not None:
                return known
            try:
                state = self._prepare(codename, architecture)
            except AptResolutionError as exc:
                self._prepared[key] = exc
                raise
            self._prepared[key] = state
            return state

    def _prepare(self, codename: str, architecture: str) -> AptState:
        if codename not in SUPPORTED_RELEASES.values():
            raise AptResolutionError(f"Unsupported Ubuntu release for APT resolution: {codename!r}")
        if not ARCH_RE.match(architecture or ""):
            raise AptResolutionError(f"Unexpected architecture: {architecture!r}")
        root = self.state_dir(codename, architecture)
        for sub in (
            "etc/apt.conf.d", "etc/sources.list.d", "etc/preferences.d", "etc/trusted.gpg.d",
            "state/lists/partial", "cache/archives/partial", "status",
        ):  # fmt: skip
            (root / sub).mkdir(parents=True, exist_ok=True)
        (root / "etc" / "apt.conf").write_text(
            "// EC2Patcher private APT state: never read the workstation's APT configuration.\n"
            f'Dir::Etc::main "{root / "etc" / "apt.conf.main"}";\n'
            f'Dir::Etc::parts "{root / "etc" / "apt.conf.d"}";\n'
        )
        sources = sources_list(codename, architecture, self.keyring)
        sources_file = root / "etc" / "sources.list"
        if not sources_file.exists() or sources_file.read_text() != sources:
            sources_file.write_text(sources)
        digest = hashlib.sha256(sources.encode()).hexdigest()

        updated_at = self._stamp(root, codename, digest)
        now = self.clock()
        if updated_at is not None and self.max_age and now - updated_at <= self.max_age:
            return AptState(codename, architecture, root, updated_at)

        self._update(root, codename, architecture)
        stamp = {"updated_at": now.isoformat(), "sources": digest}
        (root / "state" / STAMP_NAME).write_text(json.dumps(stamp))
        return AptState(codename, architecture, root, now)

    def _stamp(self, root: Path, codename: str, digest: str) -> datetime | None:
        """Time of the last successful update of these exact sources, if the lists exist."""
        try:
            stamp = json.loads((root / "state" / STAMP_NAME).read_text())
            updated_at = datetime.fromisoformat(stamp["updated_at"])
        except (OSError, ValueError, KeyError, TypeError):
            return None
        if stamp.get("sources") != digest or self._missing_lists(root, codename):
            return None
        return updated_at

    @staticmethod
    def _missing_lists(root: Path, codename: str) -> list[str]:
        """Pockets without a Packages index in the private lists directory."""
        names = [p.name for p in (root / "state" / "lists").glob("*_Packages*")]
        return [s for s in pockets(codename) if not any(f"_dists_{s}_" in n for n in names)]

    def _update(self, root: Path, codename: str, architecture: str) -> None:
        empty_status = root / "status" / "empty"
        empty_status.touch()
        logger.info("Updating private APT lists for %s/%s in %s", codename, architecture, root)
        proc = self._run("apt-get", root, architecture, empty_status, ["-q", "update"],
                         UPDATE_TIMEOUT_SECONDS)  # fmt: skip
        output = f"{proc.stdout or ''}\n{proc.stderr or ''}"
        problems = [
            ln.strip() for ln in output.splitlines()
            if ln.strip().startswith(("E:", "Err:", "W: Failed to fetch", "W: GPG error"))
        ]  # fmt: skip
        missing = [] if problems or proc.returncode else self._missing_lists(root, codename)
        if proc.returncode or problems or missing:
            detail = "; ".join(problems[:5]) or (
                f"no package index for {', '.join(missing)}"
                if missing
                else f"exit status {proc.returncode}"
            )
            raise AptResolutionError(
                f"apt-get update of the private {codename}/{architecture} APT lists failed: "
                f"{detail[:600]}"
            )

    def _run(self, binary, root, architecture, status, args, timeout):
        command = [binary, *self.options(root, architecture, status), *args]
        env = {
            **os.environ, "LC_ALL": "C", "LANG": "C", "LANGUAGE": "",
            "APT_CONFIG": str(root / "etc" / "apt.conf"),
        }  # fmt: skip
        try:
            return self.runner(
                command, capture_output=True, text=True, timeout=timeout,
                stdin=subprocess.DEVNULL, check=False, env=env,
            )  # fmt: skip
        except subprocess.TimeoutExpired as exc:
            raise AptResolutionError(f"{binary} did not finish within {timeout}s.") from exc
        except FileNotFoundError as exc:
            raise AptResolutionError(
                f"'{binary}' was not found on this workstation; APT is required to resolve "
                "package candidates and plans locally."
            ) from exc
        except OSError as exc:
            raise AptResolutionError(f"Could not run {binary}: {exc.strerror or exc}") from exc

    @contextlib.contextmanager
    def _server_status(self, state: AptState, facts: ServerFacts) -> Iterator[Path]:
        """Temporary dpkg status file reproducing the server's installed packages."""
        with tempfile.NamedTemporaryFile(
            "w", dir=state.root / "status", suffix=".status", delete=False
        ) as handle:
            handle.write("\n".join(status_record(p) for p in facts.packages))
        path = Path(handle.name)
        try:
            yield path
        finally:
            path.unlink(missing_ok=True)

    # --- queries -----------------------------------------------------------------------

    def candidates(
        self, state: AptState, facts: ServerFacts, packages: list[str]
    ) -> dict[str, apt_planner.Candidate]:
        """APT candidates for the server's packages. Raises AptResolutionError / ValueError."""
        policy_args, show_args = apt_planner.candidate_arguments(packages)
        arch = state.architecture
        with self._server_status(state, facts) as status:
            policy = self._run("apt-cache", state.root, arch, status, policy_args,
                               QUERY_TIMEOUT_SECONDS)  # fmt: skip
            if policy.returncode != 0:
                detail = [ln for ln in (policy.stderr or "").splitlines() if ln.strip()]
                raise AptResolutionError(
                    f"apt-cache policy failed (exit {policy.returncode})"
                    + (f": {detail[-1][:300]}" if detail else "")
                )
            # Unknown names make apt-cache show exit non-zero; policy already reports them.
            show = self._run("apt-cache", state.root, arch, status, show_args,
                             QUERY_TIMEOUT_SECONDS)  # fmt: skip
        hooks = "\n".join(f"/var/lib/dpkg/info/{n}.postinst" for n in sorted(facts.reboot_hooks))
        text = apt_planner.transcript([
            ("policy", f"{policy.stdout or ''}{policy.stderr or ''}"),
            ("show", show.stdout or ""),
            ("reboot-hooks", hooks),
        ])  # fmt: skip
        return apt_planner.parse_candidates(text, packages)

    def plan(
        self, state: AptState, facts: ServerFacts, requests: list[tuple[str, str]]
    ) -> apt_planner.DownloadPlan:
        """Exact .deb plan (simulation + --print-uris) for the server's pinned upgrades."""
        try:
            simulate, uris = apt_planner.plan_commands(requests)
        except apt_planner.UnsafeArgumentError as exc:
            return apt_planner.DownloadPlan(ok=False, error=str(exc))
        arch = state.architecture
        try:
            with self._server_status(state, facts) as status:
                sim = self._run("apt-get", state.root, arch, status, simulate,
                                QUERY_TIMEOUT_SECONDS)  # fmt: skip
                uri = self._run("apt-get", state.root, arch, status, uris, QUERY_TIMEOUT_SECONDS)
        except AptResolutionError as exc:
            return apt_planner.DownloadPlan(
                ok=False,
                apt_arguments=["install", *apt_planner.plan_arguments(requests)],
                error=str(exc),
            )
        text = apt_planner.transcript([
            ("simulate", f"{sim.stdout or ''}{sim.stderr or ''}"),
            ("simulate-rc", str(sim.returncode)),
            ("uris", f"{uri.stdout or ''}{uri.stderr or ''}"),
            ("uris-rc", str(uri.returncode)),
        ])  # fmt: skip
        return apt_planner.parse_plan(text, requests)
