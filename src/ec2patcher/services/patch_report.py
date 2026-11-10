"""The patch report: one row per server x CVE, fed by the existing flows.

The paste import creates the rows and supplies what only the pasted list knows (host, USN, title);
analyses and patch executions supply the status, versions, timestamps, run ID and errors. A row an
import never created is added by the first analysis of that server and CVE.

The report never decides anything about patching, and a failure to update it never affects the
analysis or patch it reports on (``safely``).
"""

import logging
from collections import Counter
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from functools import partial
from urllib.parse import urlencode

from ec2patcher.database import Database
from ec2patcher.models import (
    REPORT_FAILED,
    REPORT_NOT_AFFECTED,
    REPORT_PATCHED,
    REPORT_PENDING,
    REPORT_REBOOT_REQUIRED,
    REPORT_STATUSES,
    PatchReportRow,
    ServerAnalysis,
)
from ec2patcher.services import cve_resolver, usn_notices
from ec2patcher.services import patch_state as ps
from ec2patcher.services.security_list import MatchedRecord

logger = logging.getLogger(__name__)

MAX_ERROR_CHARS = 2000
NO_LONGER_AFFECTED = frozenset({cve_resolver.NOT_AFFECTED, cve_resolver.PACKAGE_NOT_INSTALLED})
FIX_IN_PLACE = NO_LONGER_AFFECTED | {cve_resolver.ALREADY_FIXED}
# Findings a verified patch counts as fixed (both have a version the install is checked against).
PATCHED_BY_PLAN = frozenset(
    {cve_resolver.PATCH_AVAILABLE, cve_resolver.FIX_AVAILABLE_PENDING_PUBLICATION}
)
LOOKUP_PROBLEMS = frozenset({cve_resolver.ANALYSIS_ERROR, cve_resolver.METADATA_UNAVAILABLE})
_DONE_REBOOTS = frozenset({ps.REBOOT_DONE, ps.REBOOT_NOT_REQUIRED})

BADGES = {
    REPORT_PENDING: "badge-warning",
    REPORT_PATCHED: "badge-success",
    REPORT_FAILED: "badge-danger",
    REPORT_NOT_AFFECTED: "badge-neutral",
    REPORT_REBOOT_REQUIRED: "badge-warning",
}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _join(values: Iterable[str | None]) -> str | None:
    return ", ".join(dict.fromkeys(v for v in values if v)) or None


def _short(text: str | None) -> str | None:
    return text[:MAX_ERROR_CHARS] if text else None


def safely(update: Callable[..., None], *args) -> None:
    """Run one report update on behalf of a flow that must carry on whatever happens to it."""
    try:
        update(*args)
    except Exception:
        logger.exception("Could not update the patch report (%s)", update.__name__)


# --- paste import ------------------------------------------------------------------------


def record_import(db: Database, matched: list[MatchedRecord]) -> int:
    """Add or refresh the rows of the records matched to a server; status, versions and run stay
    as earlier runs left them. Returns the number of server x CVE rows the import names."""
    by_server: dict[str, list] = {}
    for item in matched:
        if item.server_name is not None:
            by_server.setdefault(item.server_name, []).append(item.record)
    now = _now()
    for server_name, records in by_server.items():
        db.merge_patch_report(server_name, partial(_merge_records, server_name, records, now))
    return sum(len({cve for r in records for cve in r.cves}) for records in by_server.values())


def _merge_records(
    server_name: str, records: list, now: str, current: dict[str, PatchReportRow]
) -> list[PatchReportRow]:
    rows: dict[str, PatchReportRow] = {}
    for record in records:
        for cve in record.cves:
            row = rows.get(cve) or current.get(cve) or PatchReportRow(server_name, cve)
            usns = [u.strip() for u in (row.usn or "").split(",")]
            row.server_name = server_name
            row.hostname = record.host
            row.usn = _join([*usns, *record.usns])
            row.package = record.package or row.package
            row.title = record.title or row.title
            row.imported_at = now
            rows[cve] = row
    return list(rows.values())


# --- analysis ----------------------------------------------------------------------------


def record_analysis(db: Database, analysis_id: int) -> None:
    """Bring the rows of one server up to date with a finished analysis of it."""
    analysis = db.get_server_analysis(analysis_id)
    if analysis is None:
        return
    findings: dict[str, list] = {}
    for finding in analysis.findings:
        findings.setdefault(finding.cve, []).append(finding)
    cves = list(dict.fromkeys([*analysis.reported_cves, *findings]))
    # Read before the report's transaction starts. Only Ubuntu has USNs.
    usns = {}
    if analysis.os_id in (None, "ubuntu") and analysis.status == "complete":
        usns = {cve: usn_notices.best_usn(db, cve, analysis.os_codename) for cve in cves}

    def merge(current: dict[str, PatchReportRow]) -> list[PatchReportRow]:
        rows = []
        for cve in cves:
            row = current.get(cve) or PatchReportRow(analysis.server_name, cve)
            if row.run_id and row.run_id > analysis.run_id:
                continue  # a follow-up on an older run does not overrule a newer one
            row.server_name = analysis.server_name
            row.hostname = row.hostname or analysis.remote_hostname
            row.run_id = analysis.run_id
            if analysis.status == "complete":
                usn = usns.get(cve)
                if usn is not None:  # what a pasted list says about the row stays
                    row.usn = row.usn or usn.id
                    row.title = row.title or usn.title
                _apply_findings(row, findings.get(cve, []), analysis)
            else:  # the server could not be analyzed: what is known of the CVE has not changed
                row.error = _short(analysis.error)
            rows.append(row)
        return rows

    db.merge_patch_report(analysis.server_name, merge)


def _apply_findings(row: PatchReportRow, findings: list, analysis: ServerAnalysis) -> None:
    statuses = {f.status for f in findings}
    installed = _join(f.installed_version for f in findings)
    row.priority = _join(f.priority for f in findings) or row.priority
    row.package = row.package or _join(f.source_package for f in findings)
    row.source = _join(f.resolution_source for f in findings)
    row.failure_reason = _short(_join(f.failure_reason for f in findings))
    row.mirror = _short(_join(getattr(f, "mirror", None) for f in findings))
    known_kev = [f.kev for f in findings if f.kev is not None]
    row.kev = any(known_kev) if known_kev else row.kev
    row.epss = max((f.epss for f in findings if f.epss is not None), default=row.epss)
    row.error = None
    if statuses and statuses <= NO_LONGER_AFFECTED:
        row.status, row.version_after = REPORT_NOT_AFFECTED, None
    elif statuses and statuses <= FIX_IN_PLACE:
        reboot_pending = (
            row.status == REPORT_REBOOT_REQUIRED and analysis.current_reboot_required is not False
        )
        row.status = REPORT_REBOOT_REQUIRED if reboot_pending else REPORT_PATCHED
        # patched_at is only ever the time EC2Patcher patched: a fix found in place has none.
        row.version_after = row.version_after or installed
    else:
        row.version_before = installed or row.version_before
        row.error = _short(_join(f.detail for f in findings if f.status in LOOKUP_PROBLEMS))
        if row.status == REPORT_FAILED:  # still open: the failed patch stays on record
            return
        row.status, row.version_after, row.patched_at = REPORT_PENDING, None, None


# --- patch executions --------------------------------------------------------------------


def record_execution(db: Database, execution_id: int) -> None:
    """Record the outcome of a patch execution for the CVEs it was approved to fix. Called again
    after the reboot step, which may settle a reboot-required row."""
    execution = db.get_execution(execution_id)
    if execution is None or execution.decision != ps.APPROVED:
        return
    if execution.state == ps.CANCELLED:
        return  # stopped before the install: the rows stay as they were
    verified = execution.state in ps.DONE or execution.state == ps.CLEANING_UP
    if execution.state in ps.ACTIVE and not verified:
        return
    analysis = db.get_server_analysis(execution.server_analysis_id)
    findings = [
        f for f in (analysis.findings if analysis else [])
        if f.status in PATCHED_BY_PLAN
    ]  # fmt: skip
    results: dict[str, list] = {}
    for result in execution.cves:
        results.setdefault(result.cve, []).append(result)
    needs_reboot = bool(execution.reboot_required_after) and (
        execution.reboot_status not in _DONE_REBOOTS
    )
    patched_at = execution.install_finished_at or execution.finished_at or _now()
    failure = f"{execution.error_title or execution.state}: {execution.error_summary or ''}"

    def after_version(cve: str) -> str | None:
        version = _join(r.resulting_version for r in results.get(cve, []))
        if version or analysis is None:
            return version
        planned = {(p.binary_package, p.architecture) for p in analysis.plan if cve in p.cves}
        return _join(
            p.after_version
            for p in execution.packages
            if (p.binary_package, p.architecture) in planned
        )

    def merge(current: dict[str, PatchReportRow]) -> list[PatchReportRow]:
        rows = []
        for cve in dict.fromkeys([*(f.cve for f in findings), *results]):
            row = current.get(cve) or PatchReportRow(execution.server_name, cve)
            row.server_name = execution.server_name
            row.hostname = row.hostname or (analysis.remote_hostname if analysis else None)
            row.run_id = execution.analysis_run_id
            row.package = row.package or _join(f.source_package for f in findings if f.cve == cve)
            row.version_before = (
                _join(f.installed_version for f in findings if f.cve == cve) or row.version_before
            )
            row.version_after = after_version(cve)
            if verified:
                row.status = REPORT_REBOOT_REQUIRED if needs_reboot else REPORT_PATCHED
                row.patched_at = patched_at
                row.error = None
                if execution.reboot_status == ps.REBOOT_FAILED:
                    row.error = _short(execution.reboot_detail)
            else:
                details = _join(r.detail for r in results.get(cve, []) if r.result != "VERIFIED")
                row.status, row.patched_at = REPORT_FAILED, None
                row.error = _short(f"{failure} ({details})" if details else failure)
            rows.append(row)
        return rows

    db.merge_patch_report(execution.server_name, merge)


# --- page and export ---------------------------------------------------------------------


@dataclass(frozen=True)
class ReportFilters:
    server: str = ""
    status: str = ""
    usn: str = ""
    cve: str = ""
    date: str = ""
    date_from: str = ""
    date_to: str = ""

    def query(self) -> dict[str, str | None]:
        """The arguments of ``Database.list_patch_report``; an exact date is a one-day span."""
        return {
            "server": self.server or None,
            "status": self.status or None,
            "usn": self.usn or None,
            "cve": self.cve or None,
            "date_from": self.date or self.date_from or None,
            "date_to": self.date or self.date_to or None,
        }

    def query_string(self) -> str:
        """These filters as URL parameters, for the export link."""
        return urlencode({k: v for k, v in vars(self).items() if v})


def parse_filters(params: Mapping[str, str]) -> tuple[ReportFilters, list[str]]:
    """Filters from query parameters, and what is wrong with them. A filter that cannot be
    applied is left out and reported, never silently treated as "no match"."""
    values = {k: params.get(k, "").strip()[:128] for k in vars(ReportFilters())}
    errors = []
    if values["status"] and values["status"] not in REPORT_STATUSES:
        errors.append(f"Unknown status '{values['status']}'.")
        values["status"] = ""
    for key, label in (("date", "Date"), ("date_from", "From"), ("date_to", "To")):
        try:
            if values[key]:
                date.fromisoformat(values[key])
        except ValueError:
            errors.append(f"{label} must be a date like 2000-01-31.")
            values[key] = ""
    return ReportFilters(**values), errors


@dataclass(frozen=True)
class ServerSummary:
    server: str
    total: int
    counts: dict[str, int]


def summarize(rows: list[PatchReportRow]) -> list[ServerSummary]:
    """Counts per server and status of ``rows``, in row order."""
    tally: dict[str, Counter] = {}
    for row in rows:
        tally.setdefault(row.server_name, Counter())[row.status] += 1
    return [
        ServerSummary(name, sum(counts.values()), {s: counts[s] for s in REPORT_STATUSES})
        for name, counts in tally.items()
    ]
