"""SQLite persistence for the server inventory and the latest accepted CVE report.

The schema is created/migrated automatically on first use (tracked with PRAGMA user_version).
Only the PEM *path* is stored; private key contents are never read or persisted.
"""

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from ec2patcher.models import Server, StoredReport

SCHEMA_VERSION = 1

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
}


class DuplicateServerNameError(Exception):
    """Raised when a server name violates the UNIQUE constraint."""


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _row_to_server(row: sqlite3.Row) -> Server:
    return Server(
        id=row["id"],
        name=row["name"],
        ip_address=row["ip_address"],
        pem_path=row["pem_path"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


class Database:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
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
        return [_row_to_server(r) for r in rows]

    def count_servers(self) -> int:
        with self.connect() as conn:
            return conn.execute("SELECT COUNT(*) FROM servers").fetchone()[0]

    def get_server(self, server_id: int) -> Server | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()
        return _row_to_server(row) if row else None

    def get_server_by_name(self, name: str) -> Server | None:
        """Case-insensitive lookup (names are unique regardless of case)."""
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM servers WHERE name = ?", (name,)).fetchone()
        return _row_to_server(row) if row else None

    def server_names(self) -> set[str]:
        with self.connect() as conn:
            return {r[0] for r in conn.execute("SELECT name FROM servers")}

    def create_server(self, name: str, ip_address: str, pem_path: str) -> Server:
        now = _now()
        try:
            with self.connect() as conn:
                cur = conn.execute(
                    "INSERT INTO servers (name, ip_address, pem_path, created_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (name, ip_address, pem_path, now, now),
                )
                server_id = cur.lastrowid
        except sqlite3.IntegrityError as exc:
            raise DuplicateServerNameError(name) from exc
        return self.get_server(server_id)

    def update_server(self, server_id: int, name: str, ip_address: str, pem_path: str) -> bool:
        try:
            with self.connect() as conn:
                cur = conn.execute(
                    "UPDATE servers SET name = ?, ip_address = ?, pem_path = ?, updated_at = ? "
                    "WHERE id = ?",
                    (name, ip_address, pem_path, _now(), server_id),
                )
        except sqlite3.IntegrityError as exc:
            raise DuplicateServerNameError(name) from exc
        return cur.rowcount == 1

    def delete_server(self, server_id: int) -> bool:
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return cur.rowcount == 1

    def clear_servers(self) -> int:
        """Remove the whole server inventory. Other data (e.g. the latest report) is kept."""
        with self.connect() as conn:
            cur = conn.execute("DELETE FROM servers")
        return cur.rowcount

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
