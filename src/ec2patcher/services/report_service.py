"""Structural validation of the security team's CVE JSON report.

Phase 1 only checks the structure and CVE identifier format. No CVE analysis is done.

Expected format:
    {"app-prod-01": ["CVE-2026-12345", "CVE-2026-67890"], "database-prod-01": ["CVE-2026-22222"]}
"""

import json
import os
import re
from dataclasses import dataclass, field

MAX_REPORT_BYTES = 1024 * 1024  # 1 MiB is far more than any realistic report
MAX_ERRORS_SHOWN = 50
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


@dataclass
class ReportValidation:
    filename: str
    servers: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    @property
    def server_count(self) -> int:
        return len(self.servers)

    @property
    def cve_count(self) -> int:
        return sum(len(cves) for cves in self.servers.values())


class _DuplicateKeyError(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise _DuplicateKeyError(key)
        seen[key] = value
    return seen


def safe_filename(filename: str | None) -> str:
    name = os.path.basename((filename or "").replace("\\", "/")).strip()
    return name[:255] or "report.json"


def normalize_cve(value: str) -> str:
    return value.strip().upper()


def validate_report(raw: bytes, filename: str | None, known_servers: set[str]) -> ReportValidation:
    result = ReportValidation(filename=safe_filename(filename))

    if not result.filename.lower().endswith(".json"):
        result.errors.append("Only .json files are accepted.")
        return result
    if len(raw) > MAX_REPORT_BYTES:
        result.errors.append(f"File is too large (limit is {MAX_REPORT_BYTES // 1024} KiB).")
        return result
    if not raw.strip():
        result.errors.append("The file is empty.")
        return result

    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        result.errors.append("The file is not valid UTF-8 text.")
        return result

    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKeyError as exc:
        result.errors.append(f"Duplicate key in report: '{exc.args[0]}'.")
        return result
    except json.JSONDecodeError as exc:
        result.errors.append(f"Malformed JSON: {exc.msg} (line {exc.lineno}, column {exc.colno}).")
        return result
    except RecursionError:
        result.errors.append("Malformed JSON: nesting is too deep.")
        return result

    if not isinstance(data, dict):
        result.errors.append(
            "The report must be a JSON object mapping server names to lists of CVEs, "
            'e.g. {"app-prod-01": ["CVE-2026-12345"]}.'
        )
        return result
    if not data:
        result.errors.append("The report does not contain any servers.")
        return result

    servers: dict[str, list[str]] = {}
    for server_name, cves in data.items():
        if server_name not in known_servers:
            result.errors.append(
                f"Unknown server: {server_name}. This server is not configured in EC2Patcher."
            )
            continue
        if not isinstance(cves, list):
            result.errors.append(
                f"Server '{server_name}': CVE entries must be a JSON array, got {_json_type(cves)}."
            )
            continue
        normalized: list[str] = []
        for item in cves:
            if not isinstance(item, str):
                result.errors.append(
                    f"Server '{server_name}': CVE entries must be strings, got {_json_type(item)}."
                )
                continue
            cve = normalize_cve(item)
            if not CVE_RE.match(cve):
                result.errors.append(
                    f"Server '{server_name}': invalid CVE identifier '{item[:80]}'. "
                    "Expected format like CVE-2026-12345."
                )
                continue
            if cve not in normalized:
                normalized.append(cve)
        servers[server_name] = normalized

    if len(result.errors) > MAX_ERRORS_SHOWN:
        extra = len(result.errors) - MAX_ERRORS_SHOWN
        result.errors = result.errors[:MAX_ERRORS_SHOWN] + [f"... and {extra} more error(s)."]
    if result.valid:
        result.servers = servers
    return result


def _json_type(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, dict):
        return "an object"
    if isinstance(value, list):
        return "an array"
    return type(value).__name__
