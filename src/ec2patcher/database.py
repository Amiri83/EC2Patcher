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

from ec2patcher.models import Server, StoredReport, Tag

SCHEMA_VERSION = 2

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
