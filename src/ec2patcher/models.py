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

    @property
    def is_running(self) -> bool:
        return self.status == "running"
