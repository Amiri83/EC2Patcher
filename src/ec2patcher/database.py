"""SQLite persistence for the server inventory, server tags and the latest accepted CVE report.

The schema is created/migrated automatically on first use (tracked with PRAGMA user_version).
Only the PEM *path* is stored; private key contents are never read or persisted.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ec2patcher.models import (
    AnalysisRun,
    CveFindingRow,
    PackagePlanRow,
    PatchCveResult,
    PatchExecution,
    PatchPackageResult,
    PatchQueue,
    PatchQueueItem,
    Server,
    ServerAnalysis,
    StoredReport,
    Tag,
)
from ec2patcher.services import patch_state

SCHEMA_VERSION = 9

# Raw Canonical CVE JSON per CVE; document NULL = Canonical confirmed 404 (unknown CVE).
# Failed lookups are never stored. Part of v7; IF NOT EXISTS so it is also (re)created in
# databases that reached v7 before the table was added to that migration.
_CVE_METADATA_CACHE = """
    CREATE TABLE IF NOT EXISTS cve_metadata_cache (
        cve         TEXT PRIMARY KEY,
        document    TEXT,
        fetched_at  TEXT NOT NULL
    );
"""

_MIGRATIONS = {
    1: """
        CREATE TABLE servers (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
            ip_address  TEXT NOT NULL,
            pem_path    TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
        CREATE TABLE reports (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            filename     TEXT NOT NULL,
            content      TEXT NOT NULL,
            uploaded_at  TEXT NOT NULL,
            status       TEXT NOT NULL
        );
    """,
    # Phase 1.5: user-defined key/value tags per server. Keys are unique per server
    # (case-insensitive, like server names). Tags are removed with their server.
    2: """
        CREATE TABLE server_tags (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            server_id   INTEGER NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
            key         TEXT NOT NULL COLLATE NOCASE,
            value       TEXT NOT NULL,
            created_at  TEXT NOT NULL,
            updated_at  TEXT NOT NULL,
            UNIQUE(server_id, key)
        );
        CREATE INDEX idx_server_tags_server_id ON server_tags(server_id);
    """,
    # Phase 2: pre-patch analysis results. Each run is an immutable snapshot: the report,
    # server name/IP/display name and remote facts are copied, so later edits to servers,
    # tags or reports never change a historical result. Deleting a server keeps its results.
    3: """
        CREATE TABLE analysis_runs (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id             INTEGER,
            report_filename       TEXT NOT NULL,
            report_uploaded_at    TEXT NOT NULL,
            report_content        TEXT NOT NULL,
            started_at            TEXT NOT NULL,
            completed_at          TEXT,
            status                TEXT NOT NULL,
            progress_message      TEXT,
            metadata_source       TEXT,
            metadata_updated_at   TEXT,
            metadata_checked_at   TEXT,
            metadata_stale        INTEGER NOT NULL DEFAULT 0,
            metadata_warning      TEXT,
            error                 TEXT
        );
        CREATE TABLE server_analyses (
            id                        INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id                    INTEGER NOT NULL
                                      REFERENCES analysis_runs(id) ON DELETE CASCADE,
            position                  INTEGER NOT NULL,
            server_id                 INTEGER REFERENCES servers(id) ON DELETE SET NULL,
            server_name               TEXT NOT NULL,
            ip_address                TEXT,
            display_name              TEXT,
            reported_cves             TEXT NOT NULL,
            status                    TEXT NOT NULL,
            error                     TEXT,
            started_at                TEXT,
            completed_at              TEXT,
            remote_hostname           TEXT,
            os_pretty_name            TEXT,
            os_version_id             TEXT,
            os_codename               TEXT,
            architecture              TEXT,
            running_kernel            TEXT,
            apt_updated_at            TEXT,
            apt_age_hours             REAL,
            current_reboot_required   INTEGER,
            reboot_required_packages  TEXT,
            expected_reboot           INTEGER,
            expected_reboot_reason    TEXT,
            apt_arguments             TEXT,
            warnings                  TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX idx_server_analyses_run ON server_analyses(run_id);
        CREATE TABLE cve_findings (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            server_analysis_id  INTEGER NOT NULL REFERENCES server_analyses(id) ON DELETE CASCADE,
            cve                 TEXT NOT NULL,
            source_package      TEXT,
            installed_version   TEXT,
            fixed_version       TEXT,
            status              TEXT NOT NULL,
            detail              TEXT,
            binary_packages     TEXT NOT NULL DEFAULT '[]',
            pocket              TEXT,
            priority            TEXT
        );
        CREATE INDEX idx_cve_findings_server ON cve_findings(server_analysis_id);
        CREATE TABLE package_plans (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            server_analysis_id  INTEGER NOT NULL REFERENCES server_analyses(id) ON DELETE CASCADE,
            binary_package      TEXT NOT NULL,
            architecture        TEXT NOT NULL,
            source_package      TEXT,
            current_version     TEXT,
            target_version      TEXT NOT NULL,
            deb_filename        TEXT,
            uri                 TEXT,
            size                INTEGER,
            checksum            TEXT,
            is_dependency       INTEGER NOT NULL DEFAULT 0,
            reboot_impact       TEXT,
            requests_reboot     INTEGER NOT NULL DEFAULT 0,
            status              TEXT NOT NULL,
            reason              TEXT,
            UNIQUE(server_analysis_id, binary_package, architecture)
        );
        CREATE TABLE package_plan_cves (
            package_plan_id  INTEGER NOT NULL REFERENCES package_plans(id) ON DELETE CASCADE,
            cve              TEXT NOT NULL,
            PRIMARY KEY (package_plan_id, cve)
        );
    """,
    # Phase 2.2: NVD CVSS snapshot per finding, captured at analysis time. Existing rows keep
    # NULLs (shown as Unknown severity); Canonical's priority column is unchanged.
    4: """
        ALTER TABLE cve_findings ADD COLUMN cvss_severity TEXT;
        ALTER TABLE cve_findings ADD COLUMN cvss_score REAL;
        ALTER TABLE cve_findings ADD COLUMN cvss_version TEXT;
        ALTER TABLE cve_findings ADD COLUMN cvss_vector TEXT;
        ALTER TABLE cve_findings ADD COLUMN cvss_source TEXT;
        ALTER TABLE cve_findings ADD COLUMN cvss_source_type TEXT;
        ALTER TABLE cve_findings ADD COLUMN nvd_last_modified TEXT;
        ALTER TABLE cve_findings ADD COLUMN nvd_status TEXT;
        ALTER TABLE cve_findings ADD COLUMN nvd_note TEXT;
    """,
    # Phase 3: settings and patch decisions/executions. An execution is a separate record
    # linked to (never modifying) the analysis snapshot; at most one decision per analysis.
    # Analysis ids are plain columns (no FK) so history is never lost with other data.
    5: """
        CREATE TABLE settings (
            key         TEXT PRIMARY KEY,
            value       TEXT NOT NULL,
            updated_at  TEXT NOT NULL
        );
        CREATE TABLE patch_executions (
            id                        INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_run_id           INTEGER NOT NULL,
            server_analysis_id        INTEGER NOT NULL UNIQUE,
            server_id                 INTEGER REFERENCES servers(id) ON DELETE SET NULL,
            server_name               TEXT NOT NULL,
            display_name              TEXT,
            ip_address                TEXT,
            decision                  TEXT NOT NULL,
            decided_at                TEXT NOT NULL,
            state                     TEXT NOT NULL,
            failure_stage             TEXT,
            started_at                TEXT,
            finished_at               TEXT,
            updated_at                TEXT NOT NULL,
            local_staging_path        TEXT,
            remote_staging_path       TEXT,
            local_staging_created     INTEGER NOT NULL DEFAULT 0,
            remote_staging_created    INTEGER NOT NULL DEFAULT 0,
            expected_reboot           INTEGER,
            expected_reboot_reason    TEXT,
            reboot_required_after     INTEGER,
            reboot_required_packages  TEXT NOT NULL DEFAULT '[]',
            error_title               TEXT,
            error_summary             TEXT,
            error_package             TEXT,
            partial_state_possible    INTEGER NOT NULL DEFAULT 0,
            cleanup_status            TEXT,
            cleanup_detail            TEXT,
            install_started_at        TEXT,
            install_finished_at       TEXT,
            install_exit_status       INTEGER,
            install_output            TEXT,
            simulation_output         TEXT,
            audit_ok                  INTEGER,
            audit_output              TEXT,
            notes                     TEXT NOT NULL DEFAULT '[]'
        );
        CREATE INDEX idx_patch_executions_state ON patch_executions(state);
        CREATE TABLE patch_execution_packages (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id         INTEGER NOT NULL
                                 REFERENCES patch_executions(id) ON DELETE CASCADE,
            binary_package       TEXT NOT NULL,
            architecture         TEXT NOT NULL,
            before_version       TEXT,
            target_version       TEXT NOT NULL,
            after_version        TEXT,
            deb_filename         TEXT NOT NULL,
            size                 INTEGER,
            checksum             TEXT,
            is_dependency        INTEGER NOT NULL DEFAULT 0,
            download_result      TEXT,
            checksum_result      TEXT,
            transfer_result      TEXT,
            install_result       TEXT,
            verification_result  TEXT,
            detail               TEXT
        );
        CREATE INDEX idx_patch_packages_execution ON patch_execution_packages(execution_id);
        CREATE TABLE patch_execution_cves (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            execution_id       INTEGER NOT NULL REFERENCES patch_executions(id) ON DELETE CASCADE,
            cve                TEXT NOT NULL,
            source_package     TEXT,
            fixed_version      TEXT,
            resulting_version  TEXT,
            result             TEXT NOT NULL,
            detail             TEXT
        );
        CREATE INDEX idx_patch_cves_execution ON patch_execution_cves(execution_id);
    """,
    6: """
        ALTER TABLE cve_findings ADD COLUMN apt_candidate TEXT;
        ALTER TABLE cve_findings ADD COLUMN canonical_status TEXT;
    """,
    # Canonical lookup outcome per unique CVE of a run ({"CVE-...": "ok|cached|failed"}),
    # tallied in the status panel and used to retry only the failed lookups; plus the
    # Canonical CVE document cache (see _CVE_METADATA_CACHE).
    7: """
        ALTER TABLE analysis_runs ADD COLUMN metadata_lookups TEXT NOT NULL DEFAULT '{}';
    """
    + _CVE_METADATA_CACHE,
    # Post-patch reboot (operator may skip it) and "Patch All" queues. A queue patches the
    # eligible servers of one analysis run one at a time and stops at the first failure;
    # every server of the run gets an item (SKIPPED / NOT_RUN included) for the history.
    8: """
        ALTER TABLE patch_executions ADD COLUMN skip_reboot INTEGER;
        ALTER TABLE patch_executions ADD COLUMN reboot_status TEXT;
        ALTER TABLE patch_executions ADD COLUMN reboot_detail TEXT;
        ALTER TABLE patch_executions ADD COLUMN reboot_requested_at TEXT;
        ALTER TABLE patch_executions ADD COLUMN reboot_finished_at TEXT;
        ALTER TABLE patch_executions ADD COLUMN post_reboot_uptime TEXT;
        ALTER TABLE patch_executions ADD COLUMN post_reboot_kernel TEXT;
        ALTER TABLE patch_executions ADD COLUMN queue_id INTEGER;
        CREATE TABLE patch_queues (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_run_id  INTEGER NOT NULL,
            created_at       TEXT NOT NULL,
            finished_at      TEXT,
            state            TEXT NOT NULL,
            skip_reboot      INTEGER NOT NULL DEFAULT 0,
            stop_reason      TEXT
        );
        CREATE TABLE patch_queue_items (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_id            INTEGER NOT NULL REFERENCES patch_queues(id) ON DELETE CASCADE,
            position            INTEGER NOT NULL,
            server_analysis_id  INTEGER NOT NULL,
            server_name         TEXT NOT NULL,
            display_name        TEXT,
            status              TEXT NOT NULL,
            execution_id        INTEGER,
            detail              TEXT
        );
        CREATE INDEX idx_patch_queue_items_queue ON patch_queue_items(queue_id);
    """,
    # Every scp attempt (exit code + stderr) of an execution, shown on its page.
    9: """
        ALTER TABLE patch_executions ADD COLUMN transfer_attempts TEXT NOT NULL DEFAULT '[]';
    """,
}


class DuplicateServerNameError(Exception):
    """Raised when a server name violates the UNIQUE constraint."""


class DuplicateTagKeyError(Exception):
    """Raised when the same tag key is given twice for one server."""


class DecisionExistsError(Exception):
    """The analysis was already approved or rejected (args[0]: existing execution id)."""


class ExecutionActiveError(Exception):
    """Another patch execution is still running (args[0]: its execution id)."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _row_to_tag(row: sqlite3.Row) -> Tag:
    return Tag(id=row["id"], server_id=row["server_id"], key=row["key"], value=row["value"])


def _row_to_server(row: sqlite3.Row) -> Server:
    return Server(
        id=row["id"],
        name=row["name"],
        ip_address=row["ip_address"],
        pem_path=row["pem_path"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


_RUN_COLUMNS = {
    "completed_at", "status", "progress_message", "metadata_source", "metadata_updated_at",
    "metadata_checked_at", "metadata_stale", "metadata_warning", "error", "metadata_lookups",
}  # fmt: skip
_SERVER_ANALYSIS_COLUMNS = {
    "status", "error", "started_at", "completed_at", "remote_hostname", "os_pretty_name",
    "os_version_id", "os_codename", "architecture", "running_kernel", "apt_updated_at",
    "apt_age_hours", "current_reboot_required", "reboot_required_packages", "expected_reboot",
    "expected_reboot_reason", "apt_arguments", "warnings",
}  # fmt: skip


def _bool_or_none(value) -> bool | None:
    return None if value is None else bool(value)


def _row_to_run(row: sqlite3.Row) -> AnalysisRun:
    return AnalysisRun(
        id=row["id"],
        report_id=row["report_id"],
        report_filename=row["report_filename"],
        report_uploaded_at=row["report_uploaded_at"],
        report=json.loads(row["report_content"]),
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        status=row["status"],
        progress_message=row["progress_message"],
        metadata_source=row["metadata_source"],
        metadata_updated_at=row["metadata_updated_at"],
        metadata_checked_at=row["metadata_checked_at"],
        metadata_stale=bool(row["metadata_stale"]),
        metadata_warning=row["metadata_warning"],
        error=row["error"],
        metadata_lookups=json.loads(row["metadata_lookups"] or "{}"),
    )


def _row_to_server_analysis(row: sqlite3.Row) -> ServerAnalysis:
    return ServerAnalysis(
        id=row["id"],
        run_id=row["run_id"],
        position=row["position"],
        server_id=row["server_id"],
        server_name=row["server_name"],
        ip_address=row["ip_address"],
        display_name=row["display_name"],
        reported_cves=json.loads(row["reported_cves"]),
        status=row["status"],
        error=row["error"],
        started_at=row["started_at"],
        completed_at=row["completed_at"],
        remote_hostname=row["remote_hostname"],
        os_pretty_name=row["os_pretty_name"],
        os_version_id=row["os_version_id"],
        os_codename=row["os_codename"],
        architecture=row["architecture"],
        running_kernel=row["running_kernel"],
        apt_updated_at=row["apt_updated_at"],
        apt_age_hours=row["apt_age_hours"],
        current_reboot_required=_bool_or_none(row["current_reboot_required"]),
        reboot_required_packages=json.loads(row["reboot_required_packages"] or "[]"),
        expected_reboot=_bool_or_none(row["expected_reboot"]),
        expected_reboot_reason=row["expected_reboot_reason"],
        apt_arguments=json.loads(row["apt_arguments"] or "[]"),
        warnings=json.loads(row["warnings"] or "[]"),
    )


def _row_to_finding(row: sqlite3.Row) -> CveFindingRow:
    from ec2patcher.services.cve_resolver import current_status

    return CveFindingRow(
        id=row["id"],
        cve=row["cve"],
        source_package=row["source_package"],
        installed_version=row["installed_version"],
        fixed_version=row["fixed_version"],
        status=current_status(row["status"]),
        detail=row["detail"],
        binary_packages=json.loads(row["binary_packages"] or "[]"),
        pocket=row["pocket"],
        priority=row["priority"],
        apt_candidate=row["apt_candidate"],
        canonical_status=row["canonical_status"],
        cvss_severity=row["cvss_severity"],
        cvss_score=row["cvss_score"],
        cvss_version=row["cvss_version"],
        cvss_vector=row["cvss_vector"],
        cvss_source=row["cvss_source"],
        cvss_source_type=row["cvss_source_type"],
        nvd_last_modified=row["nvd_last_modified"],
        nvd_status=row["nvd_status"],
        nvd_note=row["nvd_note"],
    )


def _row_to_plan(row: sqlite3.Row) -> PackagePlanRow:
    return PackagePlanRow(
        id=row["id"],
        binary_package=row["binary_package"],
        architecture=row["architecture"],
        source_package=row["source_package"],
        current_version=row["current_version"],
        target_version=row["target_version"],
        deb_filename=row["deb_filename"],
        uri=row["uri"],
        size=row["size"],
        checksum=row["checksum"],
        is_dependency=bool(row["is_dependency"]),
        reboot_impact=row["reboot_impact"],
        requests_reboot=bool(row["requests_reboot"]),
        status=row["status"],
        reason=row["reason"],
    )


_EXECUTION_COLUMNS = {
    "failure_stage", "started_at", "finished_at", "updated_at", "local_staging_path",
    "remote_staging_path", "local_staging_created", "remote_staging_created",
    "reboot_required_after", "reboot_required_packages", "error_title", "error_summary",
    "error_package", "partial_state_possible", "cleanup_status", "cleanup_detail",
    "install_started_at", "install_finished_at", "install_exit_status", "install_output",
    "simulation_output", "audit_ok", "audit_output", "notes", "reboot_status", "reboot_detail",
    "reboot_requested_at", "reboot_finished_at", "post_reboot_uptime", "post_reboot_kernel",
    "transfer_attempts",
}  # fmt: skip
_QUEUE_COLUMNS = {"finished_at", "state", "stop_reason"}
_QUEUE_ITEM_COLUMNS = {"status", "execution_id", "detail"}
_EXECUTION_PACKAGE_COLUMNS = {
    "after_version", "download_result", "checksum_result", "transfer_result", "install_result",
    "verification_result", "detail",
}  # fmt: skip


def _row_to_execution(row: sqlite3.Row) -> PatchExecution:
    return PatchExecution(
        id=row["id"],
        analysis_run_id=row["analysis_run_id"],
        server_analysis_id=row["server_analysis_id"],
        server_id=row["server_id"],
        server_name=row["server_name"],
        display_name=row["display_name"],
        ip_address=row["ip_address"],
        decision=row["decision"],
        decided_at=row["decided_at"],
        state=row["state"],
        failure_stage=row["failure_stage"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        updated_at=row["updated_at"],
        local_staging_path=row["local_staging_path"],
        remote_staging_path=row["remote_staging_path"],
        local_staging_created=bool(row["local_staging_created"]),
        remote_staging_created=bool(row["remote_staging_created"]),
        expected_reboot=_bool_or_none(row["expected_reboot"]),
        expected_reboot_reason=row["expected_reboot_reason"],
        reboot_required_after=_bool_or_none(row["reboot_required_after"]),
        reboot_required_packages=json.loads(row["reboot_required_packages"] or "[]"),
        error_title=row["error_title"],
        error_summary=row["error_summary"],
        error_package=row["error_package"],
        partial_state_possible=bool(row["partial_state_possible"]),
        cleanup_status=row["cleanup_status"],
        cleanup_detail=row["cleanup_detail"],
        install_started_at=row["install_started_at"],
        install_finished_at=row["install_finished_at"],
        install_exit_status=row["install_exit_status"],
        install_output=row["install_output"],
        simulation_output=row["simulation_output"],
        audit_ok=_bool_or_none(row["audit_ok"]),
        audit_output=row["audit_output"],
        notes=json.loads(row["notes"] or "[]"),
        skip_reboot=_bool_or_none(row["skip_reboot"]),
        reboot_status=row["reboot_status"],
        reboot_detail=row["reboot_detail"],
        reboot_requested_at=row["reboot_requested_at"],
        reboot_finished_at=row["reboot_finished_at"],
        post_reboot_uptime=row["post_reboot_uptime"],
        post_reboot_kernel=row["post_reboot_kernel"],
        queue_id=row["queue_id"],
        transfer_attempts=json.loads(row["transfer_attempts"] or "[]"),
    )


def _row_to_queue_item(row: sqlite3.Row) -> PatchQueueItem:
    return PatchQueueItem(
        id=row["id"],
        position=row["position"],
        server_analysis_id=row["server_analysis_id"],
        server_name=row["server_name"],
        display_name=row["display_name"],
        status=row["status"],
        execution_id=row["execution_id"],
        detail=row["detail"],
    )


def _row_to_execution_package(row: sqlite3.Row) -> PatchPackageResult:
    return PatchPackageResult(
        id=row["id"],
        binary_package=row["binary_package"],
        architecture=row["architecture"],
        before_version=row["before_version"],
        target_version=row["target_version"],
        after_version=row["after_version"],
        deb_filename=row["deb_filename"],
        size=row["size"],
        checksum=row["checksum"],
        is_dependency=bool(row["is_dependency"]),
        download_result=row["download_result"],
        checksum_result=row["checksum_result"],
        transfer_result=row["transfer_result"],
        install_result=row["install_result"],
        verification_result=row["verification_result"],
        detail=row["detail"],
    )


def _row_to_execution_cve(row: sqlite3.Row) -> PatchCveResult:
    return PatchCveResult(
        id=row["id"],
        cve=row["cve"],
        source_package=row["source_package"],
        fixed_version=row["fixed_version"],
        resulting_version=row["resulting_version"],
        result=row["result"],
        detail=row["detail"],
    )


def _check_duplicate_keys(tags: list[tuple[str, str]]) -> None:
    seen: set[str] = set()
    for key, _ in tags:
        folded = key.casefold()
        if folded in seen:
            raise DuplicateTagKeyError(key)
        seen.add(folded)


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")  # per-connection; needed for ON DELETE CASCADE
        try:
            with conn:  # commits on success, rolls back on exception
                yield conn
        finally:
            conn.close()

    def _migrate(self) -> None:
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            for target in range(version + 1, SCHEMA_VERSION + 1):
                conn.executescript(_MIGRATIONS[target])
                conn.execute(f"PRAGMA user_version = {int(target)}")
            # Also covers databases that reached v7 before the cache table was part of it.
            conn.executescript(_CVE_METADATA_CACHE)

    def reset(self) -> bool:
        """Remove all stored data and recreate the current schema."""
        for path in (
            self.path,
            *(
                self.path.with_name(self.path.name + suffix)
                for suffix in ("-journal", "-wal", "-shm")
            ),
        ):
            path.unlink(missing_ok=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
        if version != SCHEMA_VERSION:
            raise RuntimeError(
                f"Database reset failed: schema version {version}, expected {SCHEMA_VERSION}"
            )
        return True

    # --- servers -----------------------------------------------------------

    def list_servers(self) -> list[Server]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM servers ORDER BY name COLLATE NOCASE").fetchall()
            tag_rows = conn.execute(
                "SELECT * FROM server_tags ORDER BY key COLLATE NOCASE, id"
            ).fetchall()
        servers = [_row_to_server(r) for r in rows]
        by_id = {s.id: s for s in servers}
        for tag_row in tag_rows:
            server = by_id.get(tag_row["server_id"])
            if server is not None:
                server.tags.append(_row_to_tag(tag_row))
        return servers

    def count_servers(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]

    def get_server(self, server_id: int) -> Server | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
            if row is None:
                return None
            server = _row_to_server(row)
            server.tags = self._list_tags(conn, server_id)
        return server

    def get_server_by_name(self, name: str) -> Server | None:
        """Case-insensitive lookup (names are unique regardless of case)."""
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM servers WHERE name = ?", (name,)).fetchone()
        return _row_to_server(row) if row else None

    def server_names(self) -> set[str]:
        with self.connect() as conn:
            return {r[0] for r in conn.execute("SELECT name FROM servers")}

    def create_server(
        self,
        name: str,
        ip_address: str,
        pem_path: str,
        tags: list[tuple[str, str]] | None = None,
    ) -> Server:
        """Insert a server (and optionally its tags) in one transaction."""
        _check_duplicate_keys(tags or [])
        now = _now()
        try:
            with self.connect() as conn:
                cur = conn.execute(
                    "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (name, ip_address, pem_path, now, now),
                )
                server_id = cur.lastrowid
                if tags:
                    self._replace_tags(conn, server_id, tags)
        except sqlite3.IntegrityError as exc:
            raise DuplicateServerNameError(name) from exc
        return self.get_server(server_id)

    def update_server(
        self,
        server_id: int,
        name: str,
        ip_address: str,
        pem_path: str,
        tags: list[tuple[str, str]] | None = None,
    ) -> bool:
        """Update a server. If ``tags`` is given, it replaces the server's full tag set."""
        if tags is not None:
            _check_duplicate_keys(tags)
        try:
            with self.connect() as conn:
                cur = conn.execute(
                    "UPDATE servers SET name = ?, ip_address = ?, pem_path = ?, updated_at = ? "
                    "WHERE id = ?",
                    (name, ip_address, pem_path, _now(), server_id),
                )
                if cur.rowcount == 1 and tags is not None:
                    self._replace_tags(conn, server_id, tags)
        except sqlite3.IntegrityError as exc:
            raise DuplicateServerNameError(name) from exc
        return cur.rowcount == 1

    def delete_server(self, server_id: int) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return cur.rowcount == 1

    def clear_servers(self) -> int:
        """Remove the whole server inventory and all server tags.

        Other data (e.g. the latest report) is kept. Returns the number of servers removed.
        """
        with self.connect() as conn:
            conn.execute("DELETE FROM server_tags")
            cur = conn.execute("DELETE FROM servers")
        return cur.rowcount

    # --- server tags -------------------------------------------------------

    def list_tags(self, server_id: int) -> list[Tag]:
        """Tags of one server, ordered by key (case-insensitive), then id."""
        with self.connect() as conn:
            return self._list_tags(conn, server_id)

    def tag_pairs(self, server_id: int) -> list[tuple[str, str]]:
        """Ordered (key, value) pairs for display."""
        return [(t.key, t.value) for t in self.list_tags(server_id)]

    def set_tags(self, server_id: int, tags: list[tuple[str, str]]) -> None:
        """Atomically replace the server's tag set with exactly ``tags``."""
        _check_duplicate_keys(tags)
        with self.connect() as conn:
            self._replace_tags(conn, server_id, tags)

    @staticmethod
    def _list_tags(conn: sqlite3.Connection, server_id: int) -> list[Tag]:
        rows = conn.execute(
            "SELECT * FROM server_tags WHERE server_id = ? ORDER BY key COLLATE NOCASE, id",
            (server_id,),
        ).fetchall()
        return [_row_to_tag(r) for r in rows]

    @staticmethod
    def _replace_tags(
        conn: sqlite3.Connection, server_id: int, tags: list[tuple[str, str]]
    ) -> None:
        """Delete tags not in ``tags``, update changed ones, insert new ones (same transaction)."""
        now = _now()
        keys = [key for key, _ in tags]
        placeholders = ",".join("?" * len(keys))
        where_not_kept = f" AND key NOT IN ({placeholders})" if keys else ""
        conn.execute(
            f"DELETE FROM server_tags WHERE server_id = ?{where_not_kept}",  # noqa: S608
            (server_id, *keys),
        )
        for key, value in tags:
            conn.execute(
                "INSERT INTO server_tags (server_id, key, value, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(server_id, key) DO UPDATE SET "
                "key = excluded.key, value = excluded.value, updated_at = excluded.updated_at "
                "WHERE server_tags.key IS NOT excluded.key COLLATE BINARY "
                "OR server_tags.value IS NOT excluded.value",
                (server_id, key, value, now, now),
            )

    # --- reports -----------------------------------------------------------

    def save_report(self, filename: str, servers: dict[str, list[str]], status: str) -> None:
        """Store the latest accepted report, replacing any previous one."""
        content = json.dumps(servers, indent=2)
        with self.connect() as conn:
            conn.execute("DELETE FROM reports")
            conn.execute(
                "INSERT INTO reports (filename, content, uploaded_at, status) VALUES (?, ?, ?, ?)",
                (filename, content, _now(), status),
            )

    # --- analysis runs (Phase 2) ----------------------------------------------

    def create_analysis_run(
        self, report: StoredReport, servers: list[tuple[str, Server | None, str | None]]
    ) -> int:
        """Create a run plus one 'waiting' row per report server.

        ``servers`` holds (report server name, matched Server or None, display_name tag).
        """
        now = _now()
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO analysis_runs (report_id, report_filename, report_uploaded_at, "
                "report_content, started_at, status) VALUES (?, ?, ?, ?, ?, 'running')",
                (report.id, report.filename, report.uploaded_at, json.dumps(report.servers), now),
            )
            run_id = cur.lastrowid
            for position, (name, server, display_name) in enumerate(servers):
                conn.execute(
                    "INSERT INTO server_analyses (run_id, position, server_id, server_name, "
                    "ip_address, display_name, reported_cves, status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, 'waiting')",
                    (
                        run_id, position, server.id if server else None, name,
                        server.ip_address if server else None, display_name,
                        json.dumps(report.servers.get(name, [])),
                    ),
                )  # fmt: skip
        return run_id

    def update_analysis_run(self, run_id: int, **fields) -> None:
        self._update("analysis_runs", _RUN_COLUMNS, run_id, fields)

    def update_server_analysis(self, analysis_id: int, **fields) -> None:
        self._update("server_analyses", _SERVER_ANALYSIS_COLUMNS, analysis_id, fields)

    def _update(self, table: str, allowed: set[str], row_id: int, fields: dict) -> None:
        with self.connect() as conn:
            self._apply_update(conn, table, allowed, row_id, fields)

    @staticmethod
    def _apply_update(conn, table: str, allowed: set[str], row_id: int, fields: dict) -> None:
        if not fields:
            return
        unknown = set(fields) - allowed
        if unknown:
            raise ValueError(f"Unknown column(s) for {table}: {sorted(unknown)}")
        values = [
            json.dumps(v) if isinstance(v, list | dict) else (int(v) if isinstance(v, bool) else v)
            for v in fields.values()
        ]
        assignments = ", ".join(f"{column} = ?" for column in fields)
        conn.execute(
            f"UPDATE {table} SET {assignments} WHERE id = ?",  # noqa: S608 - whitelisted columns
            (*values, row_id),
        )

    def save_server_results(self, analysis_id: int, findings: list, plan: list, **fields) -> None:
        """Store findings + package plan and final server fields in one transaction."""
        with self.connect() as conn:
            conn.execute("DELETE FROM cve_findings WHERE server_analysis_id = ?", (analysis_id,))
            conn.execute("DELETE FROM package_plans WHERE server_analysis_id = ?", (analysis_id,))
            for f in findings:
                c = f.cvss
                conn.execute(
                    "INSERT INTO cve_findings (server_analysis_id, cve, source_package, "
                    "installed_version, fixed_version, status, detail, binary_packages, pocket, "
                    "priority, apt_candidate, canonical_status, cvss_severity, cvss_score, "
                    "cvss_version, cvss_vector, cvss_source, cvss_source_type, "
                    "nvd_last_modified, nvd_status, nvd_note) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        analysis_id, f.cve, f.source, f.installed_version, f.fixed_version,
                        f.status, f.detail, json.dumps(f.binaries), f.pocket, f.priority,
                        f.apt_candidate, f.canonical_status,
                        *(
                            (c.severity, c.score, c.version, c.vector, c.source, c.source_type,
                             c.last_modified, c.status, c.note)
                            if c else (None,) * 9
                        ),
                    ),
                )  # fmt: skip
            for p in plan:
                cur = conn.execute(
                    "INSERT INTO package_plans (server_analysis_id, binary_package, architecture, "
                    "source_package, current_version, target_version, deb_filename, uri, size, "
                    "checksum, is_dependency, reboot_impact, requests_reboot, status, reason) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        analysis_id, p.package, p.architecture, p.source, p.current_version,
                        p.target_version, p.deb_filename, p.uri, p.size, p.checksum,
                        int(p.is_dependency), p.reboot_impact, int(p.requests_reboot),
                        p.status, p.reason,
                    ),
                )  # fmt: skip
                conn.executemany(
                    "INSERT OR IGNORE INTO package_plan_cves (package_plan_id, cve) VALUES (?, ?)",
                    [(cur.lastrowid, cve) for cve in p.cves],
                )
            self._apply_update(
                conn, "server_analyses", _SERVER_ANALYSIS_COLUMNS, analysis_id, fields
            )

    def mark_interrupted_runs(self) -> int:
        """Runs still 'running' at startup were cut short by a restart; say so explicitly."""
        now = _now()
        with self.connect() as conn:
            conn.execute(
                "UPDATE server_analyses SET status = 'failed', completed_at = ?, "
                "error = 'Analysis was interrupted (application stopped).' "
                "WHERE status IN ('waiting', 'analyzing') AND run_id IN "
                "(SELECT id FROM analysis_runs WHERE status = 'running')",
                (now,),
            )
            cur = conn.execute(
                "UPDATE analysis_runs SET status = 'interrupted', completed_at = ?, "
                "progress_message = NULL, error = 'The application stopped during the analysis.' "
                "WHERE status = 'running'",
                (now,),
            )
        return cur.rowcount

    def list_analysis_runs(self, limit: int = 20) -> list[AnalysisRun]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM analysis_runs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            runs = [_row_to_run(r) for r in rows]
            for run in runs:
                run.servers = self._server_analyses(conn, run.id, details=False)
        return runs

    def get_analysis_run(self, run_id: int, details: bool = True) -> AnalysisRun | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM analysis_runs WHERE id = ?", (run_id,)).fetchone()
            if row is None:
                return None
            run = _row_to_run(row)
            run.servers = self._server_analyses(conn, run_id, details=details)
        return run

    def get_latest_analysis_run(self, details: bool = False) -> AnalysisRun | None:
        with self.connect() as conn:
            row = conn.execute("SELECT id FROM analysis_runs ORDER BY id DESC LIMIT 1").fetchone()
        return self.get_analysis_run(row["id"], details=details) if row else None

    def get_server_analysis(self, analysis_id: int) -> ServerAnalysis | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM server_analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
            if row is None:
                return None
            analysis = _row_to_server_analysis(row)
            self._load_details(conn, [analysis])
        return analysis

    def _server_analyses(self, conn, run_id: int, details: bool) -> list[ServerAnalysis]:
        rows = conn.execute(
            "SELECT * FROM server_analyses WHERE run_id = ? ORDER BY position", (run_id,)
        ).fetchall()
        analyses = [_row_to_server_analysis(r) for r in rows]
        if details:
            self._load_details(conn, analyses)
        else:
            for analysis in analyses:
                analysis.findings = [
                    _row_to_finding(r)
                    for r in conn.execute(
                        "SELECT * FROM cve_findings WHERE server_analysis_id = ? ORDER BY id",
                        (analysis.id,),
                    )
                ]
        return analyses

    @staticmethod
    def _load_details(conn, analyses: list[ServerAnalysis]) -> None:
        for analysis in analyses:
            analysis.findings = [
                _row_to_finding(r)
                for r in conn.execute(
                    "SELECT * FROM cve_findings WHERE server_analysis_id = ? ORDER BY id",
                    (analysis.id,),
                )
            ]
            plans = [
                _row_to_plan(r)
                for r in conn.execute(
                    "SELECT * FROM package_plans WHERE server_analysis_id = ? "
                    "ORDER BY is_dependency, binary_package",
                    (analysis.id,),
                )
            ]
            for plan in plans:
                plan.cves = [
                    r[0]
                    for r in conn.execute(
                        "SELECT cve FROM package_plan_cves WHERE package_plan_id = ? ORDER BY cve",
                        (plan.id,),
                    )
                ]
            analysis.plan = plans

    # --- Canonical CVE metadata cache ---------------------------------------------

    def get_cve_metadata(self, cve: str) -> tuple[str | None, str] | None:
        """(document JSON or None for a confirmed 404, fetched_at), or None if not cached."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT document, fetched_at FROM cve_metadata_cache WHERE cve = ?", (cve,)
            ).fetchone()
        return (row["document"], row["fetched_at"]) if row else None

    def put_cve_metadata(self, cve: str, document: str | None, fetched_at: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO cve_metadata_cache (cve, document, fetched_at) VALUES (?, ?, ?) "
                "ON CONFLICT(cve) DO UPDATE SET "
                "document = excluded.document, fetched_at = excluded.fetched_at",
                (cve, document, fetched_at),
            )

    def clear_cve_metadata(self) -> int:
        with self.connect() as conn:
            return conn.execute("DELETE FROM cve_metadata_cache").rowcount

    def get_latest_report(self) -> StoredReport | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM reports ORDER BY id DESC LIMIT 1").fetchone()
        if row is None:
            return None
        return StoredReport(
            id=row["id"],
            filename=row["filename"],
            servers=json.loads(row["content"]),
            uploaded_at=row["uploaded_at"],
            status=row["status"],
        )

    def latest_analysis_for_server(self, server_name: str) -> ServerAnalysis | None:
        """The server's analysis from the most recent run that includes it (by name)."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM server_analyses WHERE server_name = ? COLLATE NOCASE "
                "ORDER BY run_id DESC LIMIT 1",
                (server_name,),
            ).fetchone()
        return self.get_server_analysis(row["id"]) if row else None

    def newer_analysis_exists(self, analysis: ServerAnalysis) -> bool:
        """True if a later analysis run includes the same server (by canonical name)."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM server_analyses WHERE server_name = ? COLLATE NOCASE "
                "AND run_id > ? LIMIT 1",
                (analysis.server_name, analysis.run_id),
            ).fetchone()
        return row is not None

    # --- settings (Phase 3) ---------------------------------------------------

    def get_setting(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None

    def set_setting(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value = excluded.value, "
                "updated_at = excluded.updated_at",
                (key, value, _now()),
            )

    def delete_setting(self, key: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM settings WHERE key = ?", (key,))

    # --- patch executions (Phase 3) -----------------------------------------------

    def create_patch_decision(
        self,
        analysis: ServerAnalysis,
        decision: str,
        local_staging_path: str | None = None,
        remote_staging_path: str | None = None,
        packages: list[dict] | None = None,
        skip_reboot: bool | None = None,
        queue_id: int | None = None,
    ) -> int:
        """Record APPROVED or REJECTED for one analysis, atomically.

        Raises DecisionExistsError if the analysis already has a decision and
        ExecutionActiveError if approving while another execution is active.
        """
        patch_state.check_transition(patch_state.PENDING_REVIEW, decision)
        now = _now()
        reboot_status = None
        if decision == patch_state.APPROVED:  # the reboot step only exists for an approval
            reboot_status = (
                patch_state.REBOOT_SKIPPED if skip_reboot else patch_state.REBOOT_PENDING
            )
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")  # serialise concurrent approvals
            existing = conn.execute(
                "SELECT id FROM patch_executions WHERE server_analysis_id = ?", (analysis.id,)
            ).fetchone()
            if existing:
                raise DecisionExistsError(existing["id"])
            if decision == patch_state.APPROVED:
                active = self._active_execution_id(conn)
                if active is not None:
                    raise ExecutionActiveError(active)
            cur = conn.execute(
                "INSERT INTO patch_executions (analysis_run_id, server_analysis_id, server_id, "
                "server_name, display_name, ip_address, decision, decided_at, state, updated_at, "
                "local_staging_path, remote_staging_path, expected_reboot, "
                "expected_reboot_reason, cleanup_status, skip_reboot, reboot_status, queue_id) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    analysis.run_id, analysis.id, analysis.server_id, analysis.server_name,
                    analysis.display_name, analysis.ip_address, decision, now, decision, now,
                    local_staging_path, remote_staging_path,
                    None if analysis.expected_reboot is None else int(analysis.expected_reboot),
                    analysis.expected_reboot_reason,
                    "NOT_STARTED" if decision == patch_state.APPROVED else None,
                    None if skip_reboot is None else int(skip_reboot), reboot_status, queue_id,
                ),
            )  # fmt: skip
            execution_id = cur.lastrowid
            for p in packages or []:
                conn.execute(
                    "INSERT INTO patch_execution_packages (execution_id, binary_package, "
                    "architecture, before_version, target_version, deb_filename, size, checksum, "
                    "is_dependency) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        execution_id, p["binary_package"], p["architecture"],
                        p["before_version"], p["target_version"], p["deb_filename"], p["size"],
                        p["checksum"], int(p["is_dependency"]),
                    ),
                )  # fmt: skip
        return execution_id

    @staticmethod
    def _active_execution_id(conn) -> int | None:
        """An execution still in the pipeline, or patched and still in its reboot step."""
        active = tuple(sorted(patch_state.ACTIVE))
        successful = tuple(sorted(patch_state.SUCCESSFUL))
        rebooting = tuple(sorted(patch_state.REBOOT_ACTIVE))
        row = conn.execute(
            f"SELECT id FROM patch_executions WHERE state IN ({','.join('?' * len(active))}) "  # noqa: S608
            f"OR (state IN ({','.join('?' * len(successful))}) "
            f"AND reboot_status IN ({','.join('?' * len(rebooting))})) ORDER BY id LIMIT 1",
            (*active, *successful, *rebooting),
        ).fetchone()
        return row["id"] if row else None

    def active_execution_id(self) -> int | None:
        with self.connect() as conn:
            return self._active_execution_id(conn)

    def transition_execution(self, execution_id: int, current: str, target: str, **fields) -> None:
        """Compare-and-set state change; only transitions allowed by patch_state succeed."""
        patch_state.check_transition(current, target)
        fields = {**fields, "updated_at": _now()}
        with self.connect() as conn:
            values, assignments = self._execution_assignments(fields)
            cur = conn.execute(
                f"UPDATE patch_executions SET state = ?, {assignments} "  # noqa: S608
                "WHERE id = ? AND state = ?",
                (target, *values, execution_id, current),
            )
            if cur.rowcount != 1:
                raise patch_state.InvalidTransitionError(
                    f"Execution {execution_id} is not in state {current}; cannot move to {target}."
                )

    def update_execution(self, execution_id: int, **fields) -> None:
        fields = {**fields, "updated_at": _now()}
        with self.connect() as conn:
            values, assignments = self._execution_assignments(fields)
            conn.execute(
                f"UPDATE patch_executions SET {assignments} WHERE id = ?",  # noqa: S608
                (*values, execution_id),
            )

    @staticmethod
    def _execution_assignments(fields: dict) -> tuple[list, str]:
        unknown = set(fields) - _EXECUTION_COLUMNS
        if unknown:
            raise ValueError(f"Unknown column(s) for patch_executions: {sorted(unknown)}")
        values = [
            json.dumps(v) if isinstance(v, list) else (int(v) if isinstance(v, bool) else v)
            for v in fields.values()
        ]
        return values, ", ".join(f"{column} = ?" for column in fields)

    def update_execution_package(self, package_id: int, **fields) -> None:
        self._update("patch_execution_packages", _EXECUTION_PACKAGE_COLUMNS, package_id, fields)

    def replace_execution_cves(self, execution_id: int, rows: list[dict]) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM patch_execution_cves WHERE execution_id = ?", (execution_id,))
            conn.executemany(
                "INSERT INTO patch_execution_cves (execution_id, cve, source_package, "
                "fixed_version, resulting_version, result, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [
                    (
                        execution_id, r["cve"], r["source_package"], r["fixed_version"],
                        r["resulting_version"], r["result"], r["detail"],
                    )
                    for r in rows
                ],
            )  # fmt: skip

    def get_execution(self, execution_id: int) -> PatchExecution | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM patch_executions WHERE id = ?", (execution_id,)
            ).fetchone()
            if row is None:
                return None
            execution = _row_to_execution(row)
            self._load_execution_details(conn, execution)
        return execution

    def get_execution_for_analysis(self, analysis_id: int) -> PatchExecution | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM patch_executions WHERE server_analysis_id = ?", (analysis_id,)
            ).fetchone()
        return self.get_execution(row["id"]) if row else None

    def list_executions(self, limit: int = 200) -> list[PatchExecution]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM patch_executions ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            executions = [_row_to_execution(r) for r in rows]
            for execution in executions:
                self._load_execution_details(conn, execution)
        return executions

    @staticmethod
    def _load_execution_details(conn, execution: PatchExecution) -> None:
        execution.packages = [
            _row_to_execution_package(r)
            for r in conn.execute(
                "SELECT * FROM patch_execution_packages WHERE execution_id = ? "
                "ORDER BY is_dependency, binary_package",
                (execution.id,),
            )
        ]
        execution.cves = [
            _row_to_execution_cve(r)
            for r in conn.execute(
                "SELECT * FROM patch_execution_cves WHERE execution_id = ? ORDER BY cve, id",
                (execution.id,),
            )
        ]

    def mark_interrupted_executions(self) -> int:
        """Executions still active at startup were cut short by a restart.

        Before installing nothing on the server's packages changed -> FAILED. Once the
        install may have started the outcome is not provable -> UNKNOWN. Staging files are
        preserved either way. Returns the number of executions updated.
        """
        now = _now()
        count = 0
        with self.connect() as conn:
            rows = conn.execute(
                f"SELECT id, state, reboot_status FROM patch_executions WHERE state IN "  # noqa: S608
                f"({','.join('?' * len(patch_state.ACTIVE))})",
                tuple(sorted(patch_state.ACTIVE)),
            ).fetchall()
            for row in rows:
                state = row["state"]
                if state == patch_state.CLEANING_UP:
                    target, title = patch_state.SUCCESS_WITH_CLEANUP_WARNING, None
                    fields = {
                        "cleanup_status": "WARNING",
                        "cleanup_detail": "The application stopped during cleanup; "
                        "staging directories may still exist.",
                    }
                elif state in patch_state.POST_INSTALL:
                    target, title = patch_state.UNKNOWN, "EXECUTION STATE UNKNOWN"
                    fields = {"partial_state_possible": 1, "cleanup_status": "PRESERVED"}
                else:
                    target, title = patch_state.FAILED, "PATCH FAILED"
                    fields = {"cleanup_status": "PRESERVED"}
                if title:
                    fields.update(
                        error_title=title,
                        failure_stage=state,
                        error_summary="The application stopped while the patch was running "
                        f"(stage: {patch_state.LABELS[state]}). Run a new analysis before "
                        "retrying.",
                    )
                if row["reboot_status"] == patch_state.REBOOT_PENDING:
                    fields["reboot_status"] = patch_state.REBOOT_NOT_RUN
                values, assignments = self._execution_assignments(
                    {**fields, "finished_at": now, "updated_at": now}
                )
                conn.execute(
                    f"UPDATE patch_executions SET state = ?, {assignments} "  # noqa: S608
                    "WHERE id = ? AND state = ?",
                    (target, *values, row["id"], state),
                )
                count += 1
            # Patched, but the app stopped before/while rebooting: the reboot is not proven.
            successful = tuple(sorted(patch_state.SUCCESSFUL))
            rebooting = tuple(sorted(patch_state.REBOOT_ACTIVE))
            cur = conn.execute(
                "UPDATE patch_executions SET reboot_status = ?, reboot_detail = ?, "  # noqa: S608
                "reboot_finished_at = ?, updated_at = ? "
                f"WHERE state IN ({','.join('?' * len(successful))}) "
                f"AND reboot_status IN ({','.join('?' * len(rebooting))})",
                (
                    patch_state.REBOOT_FAILED,
                    "The application stopped during the reboot step. Check the server manually.",
                    now, now, *successful, *rebooting,
                ),
            )  # fmt: skip
            count += cur.rowcount
        return count

    # --- "Patch All" queues ----------------------------------------------------------

    def create_patch_queue(self, run_id: int, skip_reboot: bool, items: list[dict]) -> int:
        """items: {server_analysis_id, server_name, display_name, status, detail} in order."""
        with self.connect() as conn:
            cur = conn.execute(
                "INSERT INTO patch_queues (analysis_run_id, created_at, state, skip_reboot) "
                "VALUES (?, ?, ?, ?)",
                (run_id, _now(), patch_state.QUEUE_RUNNING, int(skip_reboot)),
            )
            queue_id = cur.lastrowid
            for position, item in enumerate(items):
                conn.execute(
                    "INSERT INTO patch_queue_items (queue_id, position, server_analysis_id, "
                    "server_name, display_name, status, detail) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        queue_id, position, item["server_analysis_id"], item["server_name"],
                        item["display_name"], item["status"], item.get("detail"),
                    ),
                )  # fmt: skip
        return queue_id

    def update_patch_queue(self, queue_id: int, **fields) -> None:
        self._update("patch_queues", _QUEUE_COLUMNS, queue_id, fields)

    def update_queue_item(self, item_id: int, **fields) -> None:
        self._update("patch_queue_items", _QUEUE_ITEM_COLUMNS, item_id, fields)

    def get_patch_queue(self, queue_id: int) -> PatchQueue | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM patch_queues WHERE id = ?", (queue_id,)).fetchone()
            if row is None:
                return None
            items = conn.execute(
                "SELECT * FROM patch_queue_items WHERE queue_id = ? ORDER BY position",
                (queue_id,),
            ).fetchall()
        return PatchQueue(
            id=row["id"],
            analysis_run_id=row["analysis_run_id"],
            created_at=row["created_at"],
            finished_at=row["finished_at"],
            state=row["state"],
            skip_reboot=bool(row["skip_reboot"]),
            stop_reason=row["stop_reason"],
            items=[_row_to_queue_item(r) for r in items],
        )

    def latest_queue_id(self, run_id: int) -> int | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT id FROM patch_queues WHERE analysis_run_id = ? ORDER BY id DESC LIMIT 1",
                (run_id,),
            ).fetchone()
        return row["id"] if row else None

    def mark_interrupted_queues(self) -> int:
        """Queues still RUNNING at startup were cut short by a restart."""
        now = _now()
        with self.connect() as conn:
            ids = [
                r["id"]
                for r in conn.execute(
                    "SELECT id FROM patch_queues WHERE state = ?", (patch_state.QUEUE_RUNNING,)
                )
            ]
            for queue_id in ids:
                conn.execute(
                    "UPDATE patch_queue_items SET status = ?, detail = ? "
                    "WHERE queue_id = ? AND status = ?",
                    (
                        patch_state.ITEM_FAILED, "The application stopped while patching.",
                        queue_id, patch_state.ITEM_RUNNING,
                    ),
                )  # fmt: skip
                conn.execute(
                    "UPDATE patch_queue_items SET status = ? WHERE queue_id = ? AND status = ?",
                    (patch_state.ITEM_NOT_RUN, queue_id, patch_state.ITEM_PENDING),
                )
                conn.execute(
                    "UPDATE patch_queues SET state = ?, finished_at = ?, stop_reason = ? "
                    "WHERE id = ?",
                    (
                        patch_state.QUEUE_STOPPED, now,
                        "The application stopped while the queue was running.", queue_id,
                    ),
                )  # fmt: skip
        return len(ids)
