"""Plain data objects shared between the database layer and the web layer."""

from dataclasses import dataclass, field

from ec2patcher.services.severity import cvss_label, normalize_severity


@dataclass
class Tag:
    """User-defined key/value metadata attached to a server (inventory only)."""

    id: int
    server_id: int
    key: str
    value: str


@dataclass
class Server:
    id: int
    name: str
    ip_address: str
    pem_path: str
    created_at: str
    updated_at: str
    tags: list[Tag] = field(default_factory=list)  # ordered by key (case-insensitive), then id


@dataclass
class StoredReport:
    id: int
    filename: str
    servers: dict[str, list[str]]
    uploaded_at: str
    status: str

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def cve_count(self) -> int:
        return sum(len(cves) for cves in self.servers.values())


# --- Phase 2: pre-patch analysis (read-only snapshots) ---------------------------------


@dataclass
class CveFindingRow:
    id: int
    cve: str
    source_package: str | None
    installed_version: str | None
    fixed_version: str | None
    status: str
    detail: str | None
    binary_packages: list[str]
    pocket: str | None
    priority: str | None  # raw Canonical priority captured at analysis time
    apt_candidate: str | None = None
    canonical_status: str | None = None
    # NVD CVSS snapshot captured at analysis time (Phase 2.2); all None for older findings.
    cvss_severity: str | None = None
    cvss_score: float | None = None
    cvss_version: str | None = None
    cvss_vector: str | None = None
    cvss_source: str | None = None
    cvss_source_type: str | None = None
    nvd_last_modified: str | None = None
    nvd_status: str | None = None
    nvd_note: str | None = None

    @property
    def severity(self) -> str:
        """Primary Severity: the stored NVD CVSS rating (not Canonical's priority)."""
        return normalize_severity(self.cvss_severity)

    @property
    def cvss_label(self) -> str:
        return cvss_label(self.cvss_score, self.cvss_version)


@dataclass
class PackagePlanRow:
    id: int
    binary_package: str
    architecture: str
    source_package: str | None
    current_version: str | None
    target_version: str
    deb_filename: str | None
    uri: str | None
    size: int | None
    checksum: str | None
    is_dependency: bool
    reboot_impact: str | None
    requests_reboot: bool
    status: str
    reason: str | None
    cves: list[str] = field(default_factory=list)


@dataclass
class ServerAnalysis:
    id: int
    run_id: int
    position: int
    server_id: int | None
    server_name: str
    ip_address: str | None
    display_name: str | None
    reported_cves: list[str]
    status: str  # waiting | analyzing | complete | failed
    error: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    remote_hostname: str | None = None
    os_pretty_name: str | None = None
    os_version_id: str | None = None
    os_codename: str | None = None
    architecture: str | None = None
    running_kernel: str | None = None
    apt_updated_at: str | None = None
    apt_age_hours: float | None = None
    current_reboot_required: bool | None = None
    reboot_required_packages: list[str] = field(default_factory=list)
    expected_reboot: bool | None = None
    expected_reboot_reason: str | None = None
    apt_arguments: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[CveFindingRow] = field(default_factory=list)
    plan: list[PackagePlanRow] = field(default_factory=list)


# --- Phase 3: patch decisions and executions (separate from the analysis snapshot) ------


@dataclass
class PatchPackageResult:
    id: int
    binary_package: str
    architecture: str
    before_version: str | None
    target_version: str
    after_version: str | None
    deb_filename: str
    size: int | None
    checksum: str | None
    is_dependency: bool
    download_result: str | None
    checksum_result: str | None
    transfer_result: str | None
    install_result: str | None
    verification_result: str | None
    detail: str | None


@dataclass
class PatchCveResult:
    id: int
    cve: str
    source_package: str | None
    fixed_version: str | None
    resulting_version: str | None
    result: str
    detail: str | None


@dataclass
class PatchExecution:
    id: int
    analysis_run_id: int
    server_analysis_id: int
    server_id: int | None
    server_name: str
    display_name: str | None
    ip_address: str | None
    decision: str  # APPROVED | REJECTED
    decided_at: str
    state: str
    failure_stage: str | None
    started_at: str | None
    finished_at: str | None
    updated_at: str
    local_staging_path: str | None
    remote_staging_path: str | None
    local_staging_created: bool
    remote_staging_created: bool
    expected_reboot: bool | None
    expected_reboot_reason: str | None
    reboot_required_after: bool | None
    reboot_required_packages: list[str]
    error_title: str | None
    error_summary: str | None
    error_package: str | None
    partial_state_possible: bool
    cleanup_status: str | None
    cleanup_detail: str | None
    install_started_at: str | None
    install_finished_at: str | None
    install_exit_status: int | None
    install_output: str | None
    simulation_output: str | None
    audit_ok: bool | None
    audit_output: str | None
    notes: list[str] = field(default_factory=list)
    # Post-patch reboot; all None for executions recorded before reboot support.
    skip_reboot: bool | None = None
    reboot_status: str | None = None  # see patch_state.REBOOT_*
    reboot_detail: str | None = None
    reboot_requested_at: str | None = None
    reboot_finished_at: str | None = None
    post_reboot_uptime: str | None = None
    post_reboot_kernel: str | None = None
    queue_id: int | None = None  # set when started by "Patch All"
    # One entry per scp attempt: {filename, attempt, ok, exit_code, stderr, error}.
    transfer_attempts: list[dict] = field(default_factory=list)
    packages: list[PatchPackageResult] = field(default_factory=list)
    cves: list[PatchCveResult] = field(default_factory=list)

    @property
    def cves_verified(self) -> int:
        return sum(1 for c in self.cves if c.result == "VERIFIED")


@dataclass
class PatchQueueItem:
    id: int
    position: int
    server_analysis_id: int
    server_name: str
    display_name: str | None
    status: str  # see patch_state.ITEM_*
    execution_id: int | None
    detail: str | None


@dataclass
class PatchQueue:
    """A "Patch All" run: the servers of one analysis run, patched one at a time."""

    id: int
    analysis_run_id: int
    created_at: str
    finished_at: str | None
    state: str  # see patch_state.QUEUE_*
    skip_reboot: bool
    stop_reason: str | None
    items: list[PatchQueueItem] = field(default_factory=list)

    @property
    def is_running(self) -> bool:
        return self.state == "RUNNING"


@dataclass
class AnalysisRun:
    id: int
    report_id: int | None
    report_filename: str
    report_uploaded_at: str
    report: dict[str, list[str]]
    started_at: str
    completed_at: str | None
    status: str  # running | completed | completed_with_errors | failed | interrupted
    progress_message: str | None
    metadata_source: str | None
    metadata_updated_at: str | None
    metadata_checked_at: str | None
    metadata_stale: bool
    metadata_warning: str | None
    error: str | None
    servers: list[ServerAnalysis] = field(default_factory=list)
    # Canonical lookup outcome per unique CVE of the run: ok / cached / failed.
    metadata_lookups: dict[str, str] = field(default_factory=dict)

    @property
    def is_running(self) -> bool:
        return self.status == "running"

    @property
    def lookup_tally(self) -> "LookupTally":
        return LookupTally.from_outcomes(self.metadata_lookups)

    @property
    def failed_lookups(self) -> list[str]:
        return sorted(cve for cve, outcome in self.metadata_lookups.items() if outcome == "failed")


@dataclass
class LookupTally:
    ok: int = 0
    cached: int = 0
    failed: int = 0

    @classmethod
    def from_outcomes(cls, outcomes: dict[str, str]) -> "LookupTally":
        values = list(outcomes.values())
        return cls(values.count("ok"), values.count("cached"), values.count("failed"))

    @property
    def total(self) -> int:
        return self.ok + self.cached + self.failed

    @property
    def label(self) -> str:
        return f"{self.ok} ok / {self.cached} cached / {self.failed} failed"

    @property
    def state(self) -> str:
        """Online / Degraded / Unavailable, for the status panel headline."""
        if not self.total:
            return "Not recorded"
        if self.failed == self.total:
            return "Unavailable"
        if self.failed or self.cached:
            return "Degraded"
        return "Online"
