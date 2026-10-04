"""FastAPI application: routes and page rendering."""

import logging
import os
import signal
import subprocess  # noqa: S404 - default runner handed to the ssh service
from collections.abc import Callable
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ec2patcher import __version__, config, logging_setup, models
from ec2patcher.config import DB_FILENAME, get_apt_max_age, get_apt_state_dir, get_data_dir
from ec2patcher.database import Database, DuplicateServerNameError, DuplicateTagKeyError
from ec2patcher.formatting import format_size, format_timestamp
from ec2patcher.models import AUTH_METHODS, AUTH_PASSWORD, AUTH_PEM, DEFAULT_SSH_USER
from ec2patcher.services import (
    analysis_service,
    cache_settings,
    cve_resolver,
    downloader,
    excel_export,
    local_apt,
    nvd,
    os_adapters,
    patch_service,
    report_service,
    secret_store,
    ssh_service,
    staging,
)
from ec2patcher.services import patch_state as ps
from ec2patcher.services.secret_store import SecretError
from ec2patcher.services.security_metadata import SecurityMetadata
from ec2patcher.services.severity import SEVERITIES, SEVERITY_CLASSES
from ec2patcher.validation import (
    check_nvd_api_key,
    check_ssh_password,
    tag_rows,
    validate_server_input,
)

logger = logging.getLogger(__name__)

PACKAGE_DIR = Path(__file__).parent
CLEAR_CONFIRMATION_TEXT = "DELETE SERVERS"
DEFAULT_ALLOWED_HOSTS = ["127.0.0.1", "localhost", "::1", "[::1]"]

NOTICES = {
    "created": "Server '{name}' was added.",
    "updated": "Server '{name}' was updated.",
    "deleted": "Server '{name}' was deleted.",
    "cleared": "All configured servers were removed ({count} deleted).",
    "not_found": "That server no longer exists.",
    "cache_cleared": (
        "Security lookup memory and cache cleared. The next analysis will query Canonical and "
        "NVD again."
    ),
    "cache_clean": "Security lookup memory and cache are already clear.",
    "lookups_retrying": "Retrying {count} failed Canonical lookup(s).",
    "no_failed_lookups": "There are no failed Canonical lookups to retry.",
    "reanalyzing": "Re-analyzing this server; all of its CVEs are fetched from Canonical again.",
    "cves_retrying": "Retrying {count} CVE(s) from the Investigate bucket.",
    "nothing_to_investigate": "There are no CVEs in the Investigate bucket to retry.",
    "database_reset": "Database reset. All stored data was removed.",
    "saved": "Settings saved.",
    "reset": "Settings reset to default.",
    "rejected": "Patching was rejected for this report. No action was taken.",
    "nvd_key_saved": "NVD API key saved (encrypted). It is used instead of NVD_API_KEY.",
    "nvd_key_saved_valid": (
        "NVD API key saved (encrypted). It is used instead of NVD_API_KEY. NVD accepted it."
    ),
    "nvd_key_saved_rejected": (
        "NVD API key saved (encrypted), but NVD rejected it. Check the key and save it again."
    ),
    "nvd_key_saved_unknown": (
        "NVD API key saved (encrypted). NVD could not be reached, so the key is not checked yet."
        " Reason: {reason}."
    ),
    "nvd_key_valid": "NVD accepted the API key.",
    "nvd_key_rejected": "NVD rejected the API key. Check the key in Settings or NVD_API_KEY.",
    "nvd_key_unknown": (
        "NVD could not be reached, so the API key could not be checked. Reason: {reason}."
    ),
    "nvd_key_missing": "There is no NVD API key to test.",
    "nvd_key_cleared": "NVD API key removed from Settings.",
    "log_dir_saved": "Log directory saved. The application now logs to the new location.",
    "log_dir_reset": "Log directory reset to default.",
    "cache_ttl_saved": (
        "Cache TTLs saved. No entries were deleted; expired ones are refreshed on their next "
        "lookup."
    ),
    "cache_ttl_reset": "Cache TTLs reset to default. No entries were deleted.",
}


def _default_shutdown() -> None:
    # Used when the app is not started through ec2patcher.main (e.g. plain uvicorn):
    # SIGINT triggers uvicorn's normal graceful shutdown.
    os.kill(os.getpid(), signal.SIGINT)


STATUS_CLASSES = {
    cve_resolver.PATCH_AVAILABLE: "badge-danger",
    cve_resolver.ANALYSIS_ERROR: "badge-danger",
    cve_resolver.FIX_NOT_IN_CONFIGURED_REPOS: "badge-warning",
    cve_resolver.PRO_OR_ESM_REQUIRED: "badge-warning",
    cve_resolver.NO_FIX_PUBLISHED: "badge-warning",
    cve_resolver.PENDING_OR_DEFERRED: "badge-warning",
    cve_resolver.UNKNOWN: "badge-warning",
    cve_resolver.METADATA_UNAVAILABLE: "badge-warning",
    cve_resolver.NO_ADVISORY: "badge-warning",
    cve_resolver.ALREADY_FIXED: "badge-success",
    cve_resolver.NOT_AFFECTED: "badge-success",
    cve_resolver.PACKAGE_NOT_INSTALLED: "badge-success",
}


def create_app(
    db_path: Path | None = None,
    shutdown_handler: Callable[[], None] | None = None,
    ssh_runner: ssh_service.Runner | None = None,
    allowed_hosts: list[str] | None = None,
    metadata: SecurityMetadata | None = None,
    analysis_starter: analysis_service.Starter | None = None,
    nvd_client: nvd.NvdClient | None = None,
    apt: local_apt.LocalApt | None = None,
    apt_state_dir: str | None = None,
    apt_max_age_hours: float | None = None,
    patch_starter: patch_service.Starter | None = None,
    patch_fetcher: downloader.Fetcher | None = None,
    file_logging: bool = False,
    secret_key_path: Path | None = None,
    startup_key_check: bool = False,
    key_check_starter: analysis_service.Starter | None = None,
) -> FastAPI:
    """``file_logging``: log to the rotating file of the configured log directory (the CLI
    enables it). ``secret_key_path``: Fernet key file of the stored secrets (default: in the
    config directory). ``startup_key_check``: at start, check a configured NVD API key again
    in the background (``key_check_starter``) when its last check is unknown or older than
    24 h (the CLI enables it)."""
    db = Database(db_path or get_data_dir() / DB_FILENAME)
    # Server passwords and the NVD API key, encrypted in the database.
    credentials = secret_store.SecretStore(db, secret_store.SecretBox(secret_key_path))

    def log_dir() -> Path:
        return logging_setup.log_dir_for(db.get_setting(logging_setup.LOG_DIR_SETTING))

    def apply_log_dir() -> None:
        if not file_logging:
            return
        for directory in dict.fromkeys([log_dir(), config.get_default_log_dir()]):
            try:
                logging_setup.configure_file_logging(directory)
                return
            except OSError as exc:
                logger.warning("Cannot log to %s: %s", directory, exc)

    apply_log_dir()
    interrupted = db.mark_interrupted_runs()
    if interrupted:
        logger.warning("Marked %d unfinished analysis run(s) as interrupted", interrupted)
    metadata = metadata or SecurityMetadata(
        db,
        timeout=config.get_canonical_timeout(),
        max_age=config.get_canonical_cache_ttl(),
        breaker_threshold=config.get_canonical_breaker_threshold(),
    )
    apt = apt or local_apt.LocalApt(
        get_apt_state_dir(db.path.parent, apt_state_dir), get_apt_max_age(apt_max_age_hours)
    )
    analyzer = analysis_service.AnalysisService(
        db,
        metadata,
        runner=ssh_runner or subprocess.run,
        starter=analysis_starter or analysis_service.thread_starter,
        nvd_client=nvd_client,
        apt=apt,
        credentials=credentials,
    )

    def apply_nvd_key(startup: bool = False) -> None:
        """Use the NVD API key saved in Settings (it overrides NVD_API_KEY)."""
        if startup and not credentials.has_nvd_key():
            return  # keep the client's own key (NVD_API_KEY)
        try:
            key = credentials.nvd_key()
        except SecretError as exc:
            logger.error("The NVD API key saved in Settings cannot be used: %s", exc)
            analyzer.nvd.use_settings_key(None, unreadable=True)
            return
        analyzer.nvd.use_settings_key(key)

    apply_nvd_key(startup=True)
    # Cache TTLs saved in Settings (the clients' own TTLs are the defaults).
    ttls = cache_settings.CacheTtls(db, metadata, analyzer.nvd, analyzer.advisories)

    def recheck_nvd_key() -> str | None:
        """Check the NVD API key again if its last check is unknown or older than 24 h;
        the result (or None when no check was due) is persisted like a Test key."""
        if not analyzer.nvd.key_check_due():
            return None
        result = analyzer.nvd.check_key()
        logger.info("NVD API key re-checked at start: %s", result)
        return result

    def recheck_nvd_key_safely() -> None:
        try:
            recheck_nvd_key()
        except Exception:
            logger.exception("NVD API key check at start failed")

    interrupted = db.mark_interrupted_executions()
    if interrupted:
        logger.warning("Marked %d unfinished patch execution(s) as interrupted", interrupted)
    interrupted = db.mark_interrupted_queues()
    if interrupted:
        logger.warning("Marked %d unfinished Patch All queue(s) as stopped", interrupted)
    patcher = patch_service.PatchService(
        db,
        runner=ssh_runner or subprocess.run,
        starter=patch_starter or patch_service.thread_starter,
        fetcher=patch_fetcher,
        analysis_running=lambda: analyzer.is_running,
        credentials=credentials,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("EC2Patcher %s started (database: %s)", __version__, db.path)
        if startup_key_check:
            (key_check_starter or analysis_service.thread_starter)(recheck_nvd_key_safely)
        yield
        logger.info("EC2Patcher stopped")

    app = FastAPI(
        title="EC2 Patcher", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None
    )
    app.state.db = db
    app.state.shutdown_handler = shutdown_handler or _default_shutdown
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=allowed_hosts or DEFAULT_ALLOWED_HOSTS)
    app.mount("/static", StaticFiles(directory=PACKAGE_DIR / "static"), name="static")
    templates = Jinja2Templates(directory=PACKAGE_DIR / "templates")
    templates.env.filters["timestamp"] = format_timestamp
    templates.env.filters["filesize"] = format_size
    templates.env.globals["status_labels"] = cve_resolver.STATUS_LABELS
    templates.env.globals["status_classes"] = STATUS_CLASSES
    templates.env.globals["reboot_help"] = cve_resolver.REBOOT_HELP
    templates.env.globals["severity_classes"] = SEVERITY_CLASSES
    templates.env.globals["severities"] = SEVERITIES
    templates.env.globals["apt_state_dir"] = apt.root
    templates.env.globals["apt_max_age_hours"] = apt.max_age.total_seconds() / 3600
    templates.env.globals["nvd_status_labels"] = nvd.STATUS_LABELS
    templates.env.globals["nvd_key_status"] = lambda: analyzer.nvd.key_status
    templates.env.globals["nvd_key_source"] = lambda: analyzer.nvd.key_source
    templates.env.globals["nvd_key_checked_at"] = lambda: analyzer.nvd.key_checked_at
    templates.env.globals["nvd_key_reason"] = lambda: analyzer.nvd.key_reason
    templates.env.globals["cache_badges"] = lambda: cache_settings.badges(db, ttls)
    templates.env.globals["cache_labels"] = {
        models.CACHE_NVD: "NVD", models.CACHE_CANONICAL: "Canonical",
        models.CACHE_AMAZON: "Amazon updateinfo",
    }  # fmt: skip
    templates.env.globals["patch_labels"] = ps.LABELS
    templates.env.globals["patch_badges"] = ps.BADGES
    templates.env.globals["reboot_labels"] = ps.REBOOT_LABELS
    templates.env.globals["reboot_badges"] = ps.REBOOT_BADGES
    templates.env.globals["queue_item_badges"] = ps.ITEM_BADGES
    templates.env.globals["default_staging_template"] = staging.DEFAULT_LOCAL_TEMPLATE
    templates.env.globals["auth_methods"] = AUTH_METHODS
    app.state.analyzer = analyzer
    app.state.patcher = patcher
    app.state.credentials = credentials
    app.state.cache_ttls = ttls
    app.state.recheck_nvd_key = recheck_nvd_key

    def run_ssh_test(
        name: str, ip: str, pem: str, user: str, password: str | None = None
    ) -> ssh_service.SSHTestResult:
        kwargs = {"user": user, "password": password}
        if ssh_runner is not None:
            kwargs["runner"] = ssh_runner
        return ssh_service.check_connection(name, ip, pem, **kwargs)

    def render(request: Request, template: str, active: str, status_code: int = 200, **ctx):
        ctx.setdefault("notice", None)
        ctx.setdefault("error", None)
        return templates.TemplateResponse(
            request, template, {"active": active, "version": __version__, **ctx},
            status_code=status_code,
        )  # fmt: skip

    def redirect(path: str, **params) -> RedirectResponse:
        url = f"{path}?{urlencode(params)}" if params else path
        return RedirectResponse(url, status_code=303)

    def notice_from_query(request: Request) -> str | None:
        template = NOTICES.get(request.query_params.get("notice", ""))
        if template is None:
            return None
        return template.format(
            name=request.query_params.get("name", "")[:64],
            count=request.query_params.get("count", "0")[:6],
            # from the persisted key check, never from the URL
            reason=analyzer.nvd.key_reason or "no details recorded",
        )

    # --- basic CSRF protection for a localhost app without authentication ---

    @app.middleware("http")
    async def reject_cross_site_posts(request: Request, call_next):
        if request.method == "POST":
            origin = request.headers.get("origin")
            host = request.headers.get("host", "")
            cross_site = request.headers.get("sec-fetch-site") == "cross-site"
            if cross_site or (origin and origin != "null" and urlsplit(origin).netloc != host):
                logger.warning(
                    "Rejected cross-site POST to %s (origin=%s)", request.url.path, origin
                )
                return Response("Cross-site request rejected.", status_code=403)
        return await call_next(request)

    # --- error pages ---------------------------------------------------------

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request: Request, exc: StarletteHTTPException):
        message = "Page not found." if exc.status_code == 404 else str(exc.detail)
        return render(request, "error.html", "", status_code=exc.status_code, message=message)

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        logger.exception("Unexpected error handling %s %s", request.method, request.url.path)
        return render(
            request, "error.html", "", status_code=500,
            message="An unexpected error occurred. Details were written to the application log.",
        )  # fmt: skip

    # --- dashboard -----------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def dashboard(request: Request):
        return render(
            request, "dashboard.html", "dashboard",
            server_count=db.count_servers(), report=db.get_latest_report(), db_path=db.path,
        )  # fmt: skip

    # --- servers -------------------------------------------------------------

    def servers_page(request: Request, status_code: int = 200, **ctx):
        ctx.setdefault("notice", notice_from_query(request))
        servers = db.list_servers()
        return render(
            request, "servers.html", "servers", status_code=status_code,
            servers=servers, confirm_text=CLEAR_CONFIRMATION_TEXT, **ctx,
        )  # fmt: skip

    @app.get("/servers", response_class=HTMLResponse)
    def list_servers(request: Request):
        return servers_page(request)

    def stored_password(server_id: int | None) -> tuple[str | None, str | None]:
        """(password, error) of a saved server: (None, None) when none is stored."""
        if server_id is None:
            return None, None
        try:
            return credentials.server_password(server_id), None
        except SecretError as exc:
            return None, str(exc)

    def server_form(request: Request, server_id: int | None, form: dict, status_code=200, **ctx):
        # The password field is always rendered empty; only "a password is stored" is shown.
        server = db.get_server(server_id) if server_id is not None else None
        has_stored = server is not None and server.has_password
        return render(
            request, "server_form.html", "servers", status_code=status_code,
            server_id=server_id, form=form, errors=ctx.pop("errors", {}),
            has_stored_password=has_stored,
            stored_password_error=stored_password(server_id)[1] if has_stored else None, **ctx,
        )  # fmt: skip

    def handle_server_form(
        request: Request,
        server_id: int | None,
        action: str,
        name: str,
        ip: str,
        pem: str,
        tag_keys: list[str] | None,
        tag_values: list[str] | None,
        ssh_user: str,
        auth_method: str = AUTH_PEM,
        ssh_password: str = "",
    ):
        form = {
            "name": name, "ip_address": ip, "pem_path": pem, "ssh_user": ssh_user,
            "auth_method": auth_method,
        }  # fmt: skip
        form["tags"] = tag_rows(tag_keys, tag_values)
        use_password = auth_method == AUTH_PASSWORD
        if action == "test":  # never saves anything
            password, error = None, None
            if use_password and ssh_password:
                password, error = ssh_password, check_ssh_password(ssh_password)
            elif use_password:
                password, error = stored_password(server_id)
                if password is None and error is None:
                    error = "Enter the SSH password to test the connection."
            if error:
                result = ssh_service.SSHTestResult(
                    False, name.strip() or "(unsaved)", ip.strip(), error=error
                )
            else:
                result = run_ssh_test(
                    name.strip() or "(unsaved)", ip.strip(), pem, ssh_user.strip(), password
                )
            return server_form(request, server_id, form, ssh_result=result)

        data = validate_server_input(
            db, name, ip, pem, exclude_id=server_id, tag_keys=tag_keys, tag_values=tag_values,
            ssh_user=ssh_user, auth_method=auth_method,
        )  # fmt: skip
        existing = db.get_server(server_id) if server_id is not None else None
        if data.auth_method == AUTH_PASSWORD:
            # An empty field keeps the stored password; a new server needs one.
            error = check_ssh_password(ssh_password)
            if not ssh_password and existing is not None and existing.has_password:
                error = None
            if error:
                data.errors["ssh_password"] = error
        if not data.is_valid:
            return server_form(request, server_id, form, status_code=422, errors=data.errors)
        encrypted = None
        if data.auth_method == AUTH_PASSWORD and ssh_password:
            try:
                encrypted = credentials.encrypt(ssh_password)
            except SecretError as exc:
                logger.error("Cannot store the SSH password of %s: %s", data.name, exc)
                errors = {"ssh_password": str(exc)}
                return server_form(request, server_id, form, status_code=422, errors=errors)
        try:
            if server_id is None:
                db.create_server(
                    data.name, data.ip_address, data.pem_path, tags=data.tags,
                    ssh_user=data.ssh_user, auth_method=data.auth_method,
                    password_encrypted=encrypted,
                )  # fmt: skip
                logger.info(
                    "Server created: %s (%s@%s, %s login), %d tag(s)",
                    data.name, data.ssh_user, data.ip_address, data.auth_method, len(data.tags),
                )  # fmt: skip
                return redirect("/servers", notice="created", name=data.name)
            if not db.update_server(
                server_id, data.name, data.ip_address, data.pem_path, tags=data.tags,
                ssh_user=data.ssh_user, auth_method=data.auth_method,
            ):  # fmt: skip
                return redirect("/servers", notice="not_found")
            if data.auth_method != AUTH_PASSWORD and existing.has_password:
                credentials.clear_server_password(server_id)  # key login: drop the password
                logger.info("Stored SSH password removed: server=%s", data.name)
            elif encrypted is not None:
                db.set_server_password(server_id, encrypted)
                logger.info("Stored SSH password replaced (encrypted): server=%s", data.name)
            logger.info(
                "Server edited: id=%s %s (%s), %d tag(s)",
                server_id, data.name, data.ip_address, len(data.tags),
            )  # fmt: skip
            return redirect("/servers", notice="updated", name=data.name)
        except DuplicateServerNameError:
            errors = {"name": f"A server named '{data.name}' already exists. Names must be unique."}
            return server_form(request, server_id, form, status_code=422, errors=errors)
        except DuplicateTagKeyError as exc:
            errors = {"tags": f"Duplicate tag key: {exc.args[0]}"}
            return server_form(request, server_id, form, status_code=422, errors=errors)

    @app.get("/servers/new", response_class=HTMLResponse)
    def new_server(request: Request):
        form = {
            "name": "", "ip_address": "", "pem_path": "", "ssh_user": DEFAULT_SSH_USER,
            "auth_method": AUTH_PEM,
        }  # fmt: skip
        return server_form(request, None, {**form, "tags": []})

    @app.post("/servers/new", response_class=HTMLResponse)
    def create_server(
        request: Request,
        action: str = Form("save"),
        name: str = Form(""),
        ip_address: str = Form(""),
        pem_path: str = Form(""),
        ssh_user: str = Form(DEFAULT_SSH_USER),
        tag_key: list[str] | None = Form(None),  # noqa: B008
        tag_value: list[str] | None = Form(None),  # noqa: B008
        auth_method: str = Form(AUTH_PEM),
        ssh_password: str = Form(""),
    ):
        return handle_server_form(
            request, None, action, name, ip_address, pem_path, tag_key, tag_value, ssh_user,
            auth_method, ssh_password,
        )  # fmt: skip

    @app.get("/servers/{server_id}/edit", response_class=HTMLResponse)
    def edit_server(request: Request, server_id: int):
        server = db.get_server(server_id)
        if server is None:
            return redirect("/servers", notice="not_found")
        form = {
            "name": server.name,
            "ip_address": server.ip_address,
            "pem_path": server.pem_path,
            "ssh_user": server.ssh_user,
            "auth_method": server.auth_method,
            "tags": [{"key": t.key, "value": t.value} for t in server.tags],
        }
        return server_form(request, server_id, form)

    @app.post("/servers/{server_id}/edit", response_class=HTMLResponse)
    def update_server(
        request: Request,
        server_id: int,
        action: str = Form("save"),
        name: str = Form(""),
        ip_address: str = Form(""),
        pem_path: str = Form(""),
        ssh_user: str | None = Form(None),  # absent: keep the server's current user
        tag_key: list[str] | None = Form(None),  # noqa: B008
        tag_value: list[str] | None = Form(None),  # noqa: B008
        auth_method: str | None = Form(None),  # absent: keep the server's login method
        ssh_password: str = Form(""),
    ):
        server = db.get_server(server_id)
        if server is None:
            return redirect("/servers", notice="not_found")
        user = server.ssh_user if ssh_user is None else ssh_user
        method = server.auth_method if auth_method is None else auth_method
        return handle_server_form(
            request, server_id, action, name, ip_address, pem_path, tag_key, tag_value, user,
            method, ssh_password,
        )  # fmt: skip

    @app.post("/servers/{server_id}/delete")
    def delete_server(server_id: int):
        server = db.get_server(server_id)
        if server is None or not db.delete_server(server_id):
            return redirect("/servers", notice="not_found")
        logger.info("Server deleted: id=%s %s", server_id, server.name)
        return redirect("/servers", notice="deleted", name=server.name)

    @app.post("/servers/{server_id}/test", response_class=HTMLResponse)
    def test_saved_server(request: Request, server_id: int):
        server = db.get_server(server_id)
        if server is None:
            return redirect("/servers", notice="not_found")
        password, error = ssh_service.server_password(server, credentials)
        if error:
            result = ssh_service.SSHTestResult(False, server.name, server.ip_address, error=error)
        else:
            result = run_ssh_test(
                server.name, server.ip_address, server.pem_path, server.ssh_user, password
            )
        return servers_page(request, ssh_result=result, tested_id=server_id)

    @app.post("/servers/clear", response_class=HTMLResponse)
    def clear_servers(request: Request, confirm_text: str = Form("")):
        if confirm_text.strip() != CLEAR_CONFIRMATION_TEXT:
            error = f"Servers were NOT cleared. Type {CLEAR_CONFIRMATION_TEXT} exactly to confirm."
            return servers_page(request, status_code=400, error=error)
        count = db.clear_servers()  # their stored passwords go with them
        logger.info("All servers cleared (%d removed)", count)
        return redirect("/servers", notice="cleared", count=count)

    # --- reports -------------------------------------------------------------

    def reports_page(request: Request, status_code: int = 200, **ctx):
        analyzer.reconcile()  # "running" means a live worker, never a leftover status flag
        report = db.get_latest_report()
        missing = []
        if report is not None:
            names = db.server_names()
            missing = [name for name in report.servers if name not in names]
        return render(
            request, "reports.html", "reports", status_code=status_code,
            report=report, missing_servers=missing,
            max_kib=report_service.MAX_REPORT_BYTES // 1024,
            runs=db.list_analysis_runs(limit=10), analysis_running=analyzer.is_running,
            metadata_status=metadata.status(), **ctx,
        )  # fmt: skip

    @app.get("/reports", response_class=HTMLResponse)
    def reports(request: Request):
        return reports_page(request)

    @app.post("/reports/upload", response_class=HTMLResponse)
    async def upload_report(request: Request, report_file: UploadFile | None = File(None)):  # noqa: B008
        if report_file is None or not report_file.filename:
            return reports_page(request, status_code=400, upload_error="Please choose a JSON file.")
        raw = await report_file.read(report_service.MAX_REPORT_BYTES + 1)
        filename = report_service.safe_filename(report_file.filename)
        logger.info("Report uploaded: %s (%d bytes)", filename, len(raw))
        result = report_service.validate_report(raw, filename, db.server_names())
        if not result.valid:
            logger.warning("Report validation failed: %s: %s", filename, "; ".join(result.errors))
            return reports_page(request, status_code=422, validation=result)
        db.save_report(result.filename, result.servers, status="VALID")
        logger.info(
            "Report validation succeeded: %s (%d servers, %d CVEs)",
            result.filename, result.server_count, result.cve_count,
        )  # fmt: skip
        return reports_page(request, validation=result)

    # --- analysis (Phase 2, read-only) -----------------------------------------

    @app.post("/reports/analyze", response_class=HTMLResponse)
    def analyze_report(request: Request):
        report = db.get_latest_report()
        if report is None:
            return reports_page(request, status_code=400, error="Upload a valid report first.")
        if analyzer.is_running:
            latest = db.get_latest_analysis_run()
            if latest is not None and latest.is_running:
                return redirect(f"/analysis/{latest.id}")
            return reports_page(request, status_code=409, error="An analysis is already running.")
        run_id = analyzer.start(report)
        if run_id is None:
            return reports_page(request, status_code=409, error="An analysis is already running.")
        return redirect(f"/analysis/{run_id}")

    @app.get("/analysis/{run_id}", response_class=HTMLResponse)
    def analysis_run(request: Request, run_id: int):
        analyzer.reconcile()
        patcher.reconcile()
        run = db.get_analysis_run(run_id, details=True)
        if run is None:
            raise StarletteHTTPException(404)
        summaries = {s.id: analysis_service.summarize(s) for s in run.servers}
        eligible_count = 0
        if not run.is_running:  # same read-only preview as the Patch All confirmation page
            eligible_count = sum(c.allowed for _, c in patcher.queue_preview(run))
        return render(
            request, "analysis_run.html", "reports", run=run, summaries=summaries,
            notice=notice_from_query(request), patch_running=patcher.is_running,
            latest_queue_id=db.latest_queue_id(run_id), eligible_count=eligible_count,
        )  # fmt: skip

    @app.post("/analysis/{run_id}/retry-lookups", response_class=HTMLResponse)
    def retry_failed_lookups(request: Request, run_id: int):
        """Re-run only the Canonical lookups that failed in this run."""
        if db.get_analysis_run(run_id, details=False) is None:
            raise StarletteHTTPException(404)
        count = analyzer.retry_failed_lookups(run_id)
        if count is None:
            return reports_page(request, status_code=409, error="An analysis is already running.")
        if not count:
            return redirect(f"/analysis/{run_id}", notice="no_failed_lookups")
        return redirect(f"/analysis/{run_id}", notice="lookups_retrying", count=count)

    def stored_server_report(run_id: int, analysis_id: int):
        run = db.get_analysis_run(run_id, details=False)
        analysis = db.get_server_analysis(analysis_id)
        if run is None or analysis is None or analysis.run_id != run_id:
            raise StarletteHTTPException(404)
        return run, analysis

    @app.post("/analysis/{run_id}/servers/{analysis_id}/reanalyze", response_class=HTMLResponse)
    def reanalyze_server(request: Request, run_id: int, analysis_id: int):
        """Re-analyze one server, fetching all of its CVEs from ubuntu.com again."""
        stored_server_report(run_id, analysis_id)
        if not analyzer.reanalyze_server(run_id, analysis_id):
            return reports_page(request, status_code=409, error="An analysis is already running.")
        return redirect(f"/analysis/{run_id}/servers/{analysis_id}", notice="reanalyzing")

    @app.post(
        "/analysis/{run_id}/servers/{analysis_id}/retry-investigate", response_class=HTMLResponse
    )
    def retry_investigate_cves(request: Request, run_id: int, analysis_id: int):
        """Fetch the CVEs of the server's Investigate bucket again and re-analyze it."""
        _, analysis = stored_server_report(run_id, analysis_id)
        cves = analysis_service.investigate_cves(analysis)  # from the stored report only
        count = analyzer.retry_cves(
            run_id, cves, {analysis_id}, message=f"Retrying CVEs of {analysis.server_name}"
        )
        if count is None:
            return reports_page(request, status_code=409, error="An analysis is already running.")
        page = f"/analysis/{run_id}/servers/{analysis_id}"
        if not count:
            return redirect(page, notice="nothing_to_investigate")
        return redirect(page, notice="cves_retrying", count=count)

    def server_report_page(
        request: Request, run_id: int, analysis_id: int, status_code: int = 200, **ctx
    ):
        analyzer.reconcile()
        run, analysis = stored_server_report(run_id, analysis_id)
        latest = db.get_latest_analysis_run()
        groups = analysis_service.remediation_groups(analysis.findings)
        ctx.setdefault("notice", notice_from_query(request))
        adapter = os_adapters.for_analysis(analysis)
        unsupported = None  # analysis-only OS: no patch decision is offered
        if adapter is not None and not adapter.supports_patching:
            unsupported = adapter.patching_unsupported
        return render(
            request, "server_report.html", "reports", status_code=status_code, run=run,
            analysis=analysis, summary=analysis_service.summarize(analysis),
            finding_groups=analysis_service.group_findings(analysis),
            remediation_groups=groups,
            finding_buckets=analysis_service.bucket_groups(groups),
            is_latest=latest is not None and latest.id == run_id,
            patch=patcher.eligibility(analysis), patching_unsupported=unsupported, **ctx,
        )  # fmt: skip

    @app.get("/analysis/{run_id}/servers/{analysis_id}", response_class=HTMLResponse)
    def server_report(request: Request, run_id: int, analysis_id: int):
        return server_report_page(request, run_id, analysis_id)

    # --- patch execution (Phase 3) ---------------------------------------------------

    @app.get("/analysis/{run_id}/servers/{analysis_id}/approve", response_class=HTMLResponse)
    def confirm_patch(request: Request, run_id: int, analysis_id: int):
        run, analysis = stored_server_report(run_id, analysis_id)
        check = patcher.eligibility(analysis)
        if not check.allowed:
            return server_report_page(
                request, run_id, analysis_id, status_code=409,
                error="Patching is not available for this report: " + " ".join(check.reasons),
            )  # fmt: skip
        return render(
            request, "patch_confirm.html", "reports", run=run, analysis=analysis, patch=check
        )

    @app.post("/analysis/{run_id}/servers/{analysis_id}/approve", response_class=HTMLResponse)
    def approve_patch(
        request: Request,
        run_id: int,
        analysis_id: int,
        confirm: str = Form(""),
        skip_reboot: str = Form(""),
    ):
        stored_server_report(run_id, analysis_id)
        if confirm != "yes":
            return redirect(f"/analysis/{run_id}/servers/{analysis_id}/approve")
        try:
            # An unchecked "Skip reboot" box is absent from the form: reboot if required.
            execution_id = patcher.approve(analysis_id, skip_reboot=bool(skip_reboot))
        except patch_service.PatchNotAllowedError as exc:
            logger.warning("Patch approval refused for analysis %s: %s", analysis_id, exc)
            return server_report_page(
                request, run_id, analysis_id, status_code=409,
                error=f"Patching was not started. {exc}",
            )  # fmt: skip
        return redirect(f"/patch/{execution_id}")

    @app.post("/analysis/{run_id}/servers/{analysis_id}/reject", response_class=HTMLResponse)
    def reject_patch(request: Request, run_id: int, analysis_id: int, confirm: str = Form("")):
        stored_server_report(run_id, analysis_id)
        if confirm != "yes":
            return redirect(f"/analysis/{run_id}/servers/{analysis_id}")
        try:
            patcher.reject(analysis_id)
        except patch_service.PatchNotAllowedError as exc:
            return server_report_page(request, run_id, analysis_id, status_code=409, error=str(exc))
        return redirect(f"/analysis/{run_id}/servers/{analysis_id}", notice="rejected")

    @app.get("/patch/{execution_id}", response_class=HTMLResponse)
    def patch_execution(request: Request, execution_id: int):
        patcher.reconcile()
        execution = db.get_execution(execution_id)
        if execution is None:
            raise StarletteHTTPException(404)
        return render(
            request, "patch_execution.html", "history", execution=execution,
            steps=patch_service.progress_steps(execution),
            is_active=ps.in_progress(execution.state, execution.reboot_status),
        )  # fmt: skip

    # --- "Patch All": the eligible servers of one run, one at a time --------------------

    def patch_all_run(run_id: int):
        run = db.get_analysis_run(run_id, details=True)
        if run is None:
            raise StarletteHTTPException(404)
        return run

    def patch_all_page(request: Request, run_id: int, skip_reboot: bool, status_code=200, **ctx):
        run = patch_all_run(run_id)
        preview = patcher.queue_preview(run)
        return render(
            request, "patch_all_confirm.html", "reports", status_code=status_code, run=run,
            eligible=[(a, c) for a, c in preview if c.allowed],
            skipped=[(a, c) for a, c in preview if not c.allowed],
            skip_reboot=skip_reboot, **ctx,
        )  # fmt: skip

    @app.get("/analysis/{run_id}/patch-all", response_class=HTMLResponse)
    def confirm_patch_all(request: Request, run_id: int):
        skip_reboot = bool(request.query_params.get("skip_reboot"))
        if patcher.is_running:
            return patch_all_page(
                request, run_id, skip_reboot, status_code=409,
                error="Another patch execution is running. Wait for it to finish.",
            )  # fmt: skip
        return patch_all_page(request, run_id, skip_reboot)

    @app.post("/analysis/{run_id}/patch-all", response_class=HTMLResponse)
    def start_patch_all(
        request: Request,
        run_id: int,
        confirm: str = Form(""),
        skip_reboot: str = Form(""),
        analysis_id: list[int] | None = Form(None),  # noqa: B008
    ):
        patch_all_run(run_id)
        if confirm != "yes":
            return redirect(f"/analysis/{run_id}/patch-all")
        try:
            queue_id = patcher.start_queue(run_id, analysis_id or [], bool(skip_reboot))
        except patch_service.PatchNotAllowedError as exc:
            logger.warning("Patch All refused for analysis run %s: %s", run_id, exc)
            return patch_all_page(
                request, run_id, bool(skip_reboot), status_code=409,
                error=f"Patch All was not started. {exc}",
            )  # fmt: skip
        return redirect(f"/patch-all/{queue_id}")

    @app.get("/patch-all/{queue_id}", response_class=HTMLResponse)
    def patch_all_queue(request: Request, queue_id: int):
        patcher.reconcile()
        queue = db.get_patch_queue(queue_id)
        if queue is None:
            raise StarletteHTTPException(404)
        executions = {
            i.execution_id: db.get_execution(i.execution_id) for i in queue.items if i.execution_id
        }
        return render(request, "patch_all.html", "history", queue=queue, executions=executions)

    @app.get("/analysis/{run_id}/servers/{analysis_id}/export.xlsx")
    def export_server_report(run_id: int, analysis_id: int):
        # Built from the stored snapshot only: no ssh, metadata, APT or downloads.
        run, analysis = stored_server_report(run_id, analysis_id)
        filename = excel_export.export_filename(run, analysis)
        content = excel_export.build_workbook(run, analysis)
        logger.info("Excel export of analysis %s/%s (%s)", run_id, analysis_id, filename)
        return Response(
            content,
            media_type=excel_export.MEDIA_TYPE,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # --- history / settings --------------------------------------------------

    @app.get("/history", response_class=HTMLResponse)
    def history(request: Request):
        patcher.reconcile()
        return render(request, "history.html", "history", executions=db.list_executions())

    def settings_page(request: Request, status_code: int = 200, **ctx):
        template = ctx.pop("template", None) or patcher.staging_template()
        names = sorted(db.server_names(), key=str.casefold)
        preview_name = ctx.pop("preview_name", None) or (names[0] if names else "ip-10-0-0-1")
        log_dir_value = ctx.pop("log_dir_value", None) or str(log_dir())
        preview, preview_error = None, None
        try:
            preview = staging.resolve_local(template, preview_name)
        except staging.StagingError as exc:
            preview_error = str(exc)
        return render(
            request, "settings.html", "settings", status_code=status_code, db_path=db.path,
            staging_template=template, saved_template=patcher.staging_template(), preview=preview,
            preview_error=preview_error, preview_name=preview_name, server_names=names,
            remote_example=f"{staging.REMOTE_BASE}/{preview_name}",
            metadata_status=metadata.status(), log_dir_value=log_dir_value,
            default_log_dir=config.get_default_log_dir(),
            active_log_file=logging_setup.active_log_file(),
            log_file=logging_setup.log_file_in(log_dir()),
            log_max_mb=logging_setup.LOG_MAX_BYTES // (1024 * 1024),
            log_backups=logging_setup.LOG_BACKUP_COUNT, nvd_key=nvd_key_view(),
            secret_key_path=credentials.box.key_path,
            cache_ttl_values=ctx.pop("cache_ttl_values", None) or ttls.form_values(),
            cache_ttl_errors=ctx.pop("cache_ttl_errors", {}),
            cache_ttl_labels=cache_settings.LABELS, cache_ttl_saved=bool(ttls.saved()), **ctx,
        )  # fmt: skip

    def nvd_key_view() -> dict:
        """What Settings shows of the NVD API key: only the last 4 characters of a saved key,
        nothing of NVD_API_KEY."""
        view = {
            "saved": credentials.has_nvd_key(), "masked": None, "error": None,
            "env_set": bool(os.environ.get(nvd.API_KEY_ENV)), "testable": analyzer.nvd.has_key,
        }  # fmt: skip
        if view["saved"]:
            try:
                view["masked"] = secret_store.mask(credentials.nvd_key())
            except SecretError as exc:
                view["error"] = str(exc)
        return view

    @app.post("/settings/nvd-key", response_class=HTMLResponse)
    def save_nvd_key(request: Request, action: str = Form("save"), nvd_api_key: str = Form("")):
        if action == "clear":
            credentials.clear_nvd_key()
            apply_nvd_key()
            analyzer.nvd.forget_key_check()  # it was about the removed key
            logger.info("NVD API key removed from Settings")
            return redirect("/settings", notice="nvd_key_cleared")
        if action == "test":  # one keyed request now, with the key in use
            if not analyzer.nvd.has_key:
                return redirect("/settings", notice="nvd_key_missing")
            return redirect("/settings", notice=f"nvd_key_{analyzer.nvd.check_key()}")
        key = nvd_api_key.strip()
        error = check_nvd_api_key(key)
        if error is None:
            try:
                credentials.set_nvd_key(key)
            except SecretError as exc:
                error = str(exc)
        if error:  # the typed key is never echoed back
            return settings_page(request, status_code=422, nvd_key_error=error)
        apply_nvd_key()
        logger.info("NVD API key saved in Settings (encrypted)")
        if not analyzer.nvd.has_key:  # cannot happen unless the key cannot be read back
            return redirect("/settings", notice="nvd_key_saved")
        return redirect("/settings", notice=f"nvd_key_saved_{analyzer.nvd.check_key()}")

    @app.get("/settings", response_class=HTMLResponse)
    def settings(request: Request):
        preview_name = request.query_params.get("server", "")
        if staging.safe_name_error(preview_name):
            preview_name = None
        return settings_page(request, notice=notice_from_query(request), preview_name=preview_name)

    @app.post("/settings/cache-ttl", response_class=HTMLResponse)
    async def save_cache_ttl(request: Request):
        form = await request.form()
        if form.get("action") == "reset":
            ttls.reset()
            return redirect("/settings", notice="cache_ttl_reset")
        values = {key: str(form.get(key, ""))[:32] for key in cache_settings.FIELDS}
        hours, errors = cache_settings.validate_form(values)
        if errors:
            return settings_page(
                request, status_code=422, cache_ttl_values=values, cache_ttl_errors=errors
            )
        ttls.save(hours)  # entries are kept; expired ones refresh on their next lookup
        return redirect("/settings", notice="cache_ttl_saved")

    @app.post("/settings/clear-cache")
    def clear_security_cache():
        removed = metadata.clear()
        removed = analyzer.nvd.clear() or removed
        removed = analyzer.advisories.clear() or removed
        return redirect("/settings", notice="cache_cleared" if removed else "cache_clean")

    @app.post("/settings/reset-database", response_class=HTMLResponse)
    def reset_database(request: Request, confirm_text: str = Form("")):
        if analyzer.is_running:
            return settings_page(
                request, status_code=409, error="Database cannot be reset during analysis."
            )
        if patcher.is_running:
            return settings_page(
                request, status_code=409, error="Database cannot be reset during patching."
            )
        if confirm_text != "RESET":
            return settings_page(request, status_code=400, error="Type RESET exactly to confirm.")
        db.reset()
        apply_log_dir()  # the saved log directory was removed with the settings
        apply_nvd_key()  # so was a saved NVD API key: back to NVD_API_KEY
        ttls.apply_saved()  # and the cache TTLs: back to the defaults
        return redirect("/settings", notice="database_reset")

    @app.post("/settings/staging", response_class=HTMLResponse)
    def save_staging(request: Request, action: str = Form("save"), template: str = Form("")):
        if action == "reset":
            db.delete_setting(patch_service.STAGING_SETTING)
            logger.info("Local patch download directory reset to default")
            return redirect("/settings", notice="reset")
        error = staging.check_template(template)
        if error:
            return settings_page(request, status_code=422, template=template, template_error=error)
        db.set_setting(patch_service.STAGING_SETTING, template.strip())
        logger.info("Local patch download directory set to %s", template.strip())
        return redirect("/settings", notice="saved")

    @app.post("/settings/log-dir", response_class=HTMLResponse)
    def save_log_dir(request: Request, action: str = Form("save"), log_dir_path: str = Form("")):
        if action == "reset":
            db.delete_setting(logging_setup.LOG_DIR_SETTING)
            apply_log_dir()
            logger.info("Log directory reset to default (%s)", log_dir())
            return redirect("/settings", notice="log_dir_reset")
        directory, error = logging_setup.check_log_dir(log_dir_path)
        if error:
            return settings_page(
                request, status_code=422, log_dir_value=log_dir_path, log_dir_error=error
            )
        db.set_setting(logging_setup.LOG_DIR_SETTING, str(directory))
        apply_log_dir()
        logger.info("Log directory set to %s", directory)
        return redirect("/settings", notice="log_dir_saved")

    # --- shutdown ------------------------------------------------------------

    @app.get("/shutdown", response_class=HTMLResponse)
    def shutdown_confirm(request: Request):
        return render(request, "shutdown_confirm.html", "shutdown")

    @app.post("/shutdown", response_class=HTMLResponse)
    def shutdown(request: Request, confirm: str = Form("")):
        if confirm != "yes":
            return redirect("/shutdown")
        logger.info("Shutdown requested from the GUI")
        return templates.TemplateResponse(
            request, "shutdown_done.html", {},
            background=BackgroundTask(app.state.shutdown_handler),
        )  # fmt: skip

    return app
