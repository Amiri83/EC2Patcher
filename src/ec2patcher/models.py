"""Plain data objects shared between the database layer and the web layer."""

from dataclasses import dataclass


@dataclass
class Server:
    id: int
    name: str
    ip_address: str
    pem_path: str
    created_at: str
    updated_at: str


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
