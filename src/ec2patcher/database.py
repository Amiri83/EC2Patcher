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
    Server,
    ServerAnalysis,
    StoredReport,
    Tag,
)

SCHEMA_VERSION = 4

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
}


class DuplicateServerNameError(Exception):
    """Raised when a server name violates the UNIQUE constraint."""


class DuplicateTagKeyError(Exception):
    """Raised when the same tag key is given twice for one server."""


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
    "metadata_checked_at", "metadata_stale", "metadata_warning", "error",
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
    return CveFindingRow(
        id=row["id"],
        cve=row["cve"],
        source_package=row["source_package"],
        installed_version=row["installed_version"],
        fixed_version=row["fixed_version"],
        status=row["status"],
        detail=row["detail"],
        binary_packages=json.loads(row["binary_packages"] or "[]"),
        pocket=row["pocket"],
        priority=row["priority"],
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
            json.dumps(v) if isinstance(v, list) else (int(v) if isinstance(v, bool) else v)
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
                    "priority, cvss_severity, cvss_score, cvss_version, cvss_vector, cvss_source, "
                    "cvss_source_type, nvd_last_modified, nvd_status, nvd_note) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        analysis_id, f.cve, f.source, f.installed_version, f.fixed_version,
                        f.status, f.detail, json.dumps(f.binaries), f.pocket, f.priority,
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
