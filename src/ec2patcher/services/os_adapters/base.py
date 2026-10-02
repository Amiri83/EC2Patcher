"""The OsAdapter interface: everything that depends on the server's operating system.

An adapter owns the OS-specific parts of the read-only analysis (facts command and package
inventory, supported releases, vulnerability metadata and package planning) and of patch
execution (plan rules, version semantics, install simulation, install, post-install state
and the reboot-required check). OS-independent steps (ssh/scp, staging directories, file
verification, the reboot itself and boot polling) stay in the services.

Contract for ``facts_command``: its output starts with the ``hostname`` and ``os-release``
sections (``server_state.MARK``), so the OS can be detected from it before the adapter
parses the rest (see ``os_adapters.detect``).
"""

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field

from ec2patcher.services.server_state import ServerFacts


@dataclass
class AnalysisContext:
    """What an adapter may use while assessing one server (all read-only on the server)."""

    metadata: object  # vulnerability metadata source (SecurityMetadata for Ubuntu)
    packages: object  # workstation package resolver (LocalApt for Ubuntu)
    progress: Callable[[str], None]
    record: Callable[..., None]  # update fields of the server's analysis row
    lookup: Callable[[str], object] | None = None  # replaces the metadata lookup (retries)


@dataclass
class Assessment:
    """Findings and the package plan of one server, ready to be stored."""

    findings: list
    plan: list
    apt_arguments: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


class OsAdapter(ABC):
    os_id: str  # /etc/os-release ID handled by this adapter (stored with each analysis)
    name: str  # human-readable OS family, e.g. "Ubuntu"

    # --- detection and facts (read-only) ---------------------------------------------

    @abstractmethod
    def matches(self, os_release: dict[str, str]) -> bool:
        """True if this adapter handles the OS described by /etc/os-release."""

    @property
    @abstractmethod
    def facts_command(self) -> str:
        """Constant, read-only remote command collecting the server facts."""

    @abstractmethod
    def parse_facts(self, stdout: str) -> ServerFacts:
        """Parse ``facts_command`` output; raises server_state.RemoteOutputError."""

    @abstractmethod
    def check_supported(self, facts: ServerFacts) -> str | None:
        """Error message if this release of the OS is not supported."""

    @abstractmethod
    def blocker(self, facts: ServerFacts) -> str | None:
        """Error message if the package manager state blocks any plan."""

    @abstractmethod
    def is_blocker(self, error: str) -> bool:
        """True if ``error`` came from ``blocker`` (previous results become invalid)."""

    @abstractmethod
    def assess(
        self, facts: ServerFacts, reported_cves: list[str], ctx: AnalysisContext
    ) -> Assessment:
        """Resolve the reported CVEs against vulnerability metadata and plan the updates."""

    @abstractmethod
    def expected_reboot(self, plan: list) -> tuple[bool, str | None]:
        """Whether installing ``plan`` is expected to need a reboot, and why."""

    # --- patch execution -------------------------------------------------------------

    @abstractmethod
    def release_fields(self, analysis) -> list[tuple[str, str | None]]:
        """(label, value) of the release facts a plan depends on (all must be known)."""

    @abstractmethod
    def os_drift(self, facts: ServerFacts, analysis) -> list[str]:
        """Differences between the live server and the analysis that forbid patching."""

    @abstractmethod
    def plan_row_problems(self, row, architecture: str | None) -> list[str]:
        """Reasons why one 'planned' package row must not be installed."""

    @abstractmethod
    def compare_versions(self, a: str, b: str) -> int:
        """<0, 0 or >0 like cmp(a, b) under the OS package version rules."""

    @abstractmethod
    def version_key(self, version: str):
        """Sort key for package versions."""

    @abstractmethod
    def at_or_above_target(self, current: str | None, target: str | None) -> bool: ...

    @abstractmethod
    def same_version(self, a: str | None, b: str | None) -> bool: ...

    @abstractmethod
    def is_kernel_package(self, name: str) -> bool:
        """A package whose fix only takes effect after a reboot."""

    @abstractmethod
    def simulate_command(self, remote_dir: str, filenames: list[str]) -> str: ...

    @abstractmethod
    def check_simulation(self, stdout: str, expected: dict) -> tuple[list[str], object]:
        """(output lines to store, check with ``ok`` and ``problems``)."""

    @abstractmethod
    def install_command(self, remote_dir: str, filenames: list[str]) -> str: ...

    @abstractmethod
    def parse_install(self, stdout: str):
        """Install outcome with ``complete``, ``returncode`` and ``output``."""

    @abstractmethod
    def post_install_command(self, packages: list[str]) -> str: ...

    @abstractmethod
    def parse_post_install(self, stdout: str):
        """Post-install state (versions, health, reboot-required) or None if incomplete."""

    @property
    @abstractmethod
    def reboot_check_command(self) -> str: ...

    @abstractmethod
    def parse_reboot_check(self, stdout: str):
        """Reboot-required flag plus the current boot id, or None if incomplete."""
