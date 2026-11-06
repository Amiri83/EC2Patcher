"""FastAPI application: routes and page rendering."""

import logging
import os
import re
import signal
import subprocess  # noqa: S404 - default runner handed to the ssh service
import threading
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.datastructures import FormData
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ec2patcher import __version__, config, logging_setup, models
from ec2patcher.config import DB_FILENAME, get_apt_max_age, get_apt_state_dir, get_data_dir
from ec2patcher.database import Database, DuplicateServerNameError, DuplicateTagKeyError
from ec2patcher.formatting import format_size, format_timestamp
from ec2patcher.models import AUTH_METHODS, AUTH_PASSWORD, AUTH_PEM, DEFAULT_SSH_USER
from ec2patcher.services import (
    analysis_service,
    aws_config,
    cache_settings,
    cve_resolver,
    downloader,
    excel_export,
    local_apt,
    nvd,
    os_adapters,
    patch_report,
    patch_service,
    report_service,
    run_events,
    secret_store,
    security_list,
    ssh_service,
    ssm_plugin,
    ssm_service,
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
    "step_timeout_saved": "Step timeout saved. It applies from the next step of a run.",
    "step_timeout_reset": "Step timeout reset to default.",
    "connection_saved": (
        "Connection defaults saved. Servers with their own connection type keep it."
    ),
    "connection_applied": (
        "Connection defaults saved. Every server now follows them ({count} per-server connection "
        "setting(s) cleared; manual instance IDs are kept)."
    ),
    "ssm_plugin_installed": "Session Manager plugin {name} installed; its signature was verified.",
    "ssm_plugin_unsigned": (
        "Session Manager plugin {name} installed. Its signature was not checked because gpg is not "
        "installed on this machine; the package name, architecture and format were."
    ),
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


def _form_count(value: str) -> int:
    """A count from a form field; anything else counts as nothing confirmed."""
    text = value.strip()
    return int(text) if text.isdigit() and len(text) < 10 else 0


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
    templates.env.globals["connection_types"] = models.CONNECTION_TYPES
    templates.env.globals["connection_defaults"] = lambda: ssm_service.load_defaults(db)
    templates.env.globals["connection_view"] = lambda s: ssm_service.connection_view(db, s)
    templates.env.globals["aws_profiles"] = aws_config.read_profiles
    templates.env.globals["aws_regions"] = aws_config.COMMERCIAL_REGIONS
    templates.env.globals["aws_dropdown_view"] = aws_config.dropdown
    templates.env.globals["report_statuses"] = models.REPORT_STATUSES
    templates.env.globals["report_status_badges"] = patch_report.BADGES
    app.state.analyzer = analyzer
    app.state.patcher = patcher
    app.state.credentials = credentials
    app.state.cache_ttls = ttls
    app.state.recheck_nvd_key = recheck_nvd_key

    def run_connection_test(
        server: models.Server, password: str | None = None
    ) -> ssh_service.SSHTestResult:
        """Test ``server`` over its transport. An explicit test looks a cached instance ID up
        again, so it also repairs the mapping of a replaced instance."""
        runner = ssh_runner or subprocess.run
        transport = ssm_service.TransportResolver(db, runner).for_server(server, force_refresh=True)
        if transport.error:
            return ssh_service.SSHTestResult(
                False, server.name, server.ip_address, error=transport.error,
                transport=transport.label,
            )  # fmt: skip
        result = ssh_service.check_connection(
            server.name, server.ip_address, server.pem_path, runner=runner, user=server.ssh_user,
            password=password, ssm=transport.target,
        )  # fmt: skip
        result.transport = transport.label
        return result

    plugin_install_lock = threading.Lock()

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

    def rejected_cross_site(request: Request) -> Response | None:
        """The rejection of a request from another site, or None."""
        origin = request.headers.get("origin")
        host = request.headers.get("host", "")
        cross_site = request.headers.get("sec-fetch-site") == "cross-site"
        if cross_site or (origin and origin != "null" and urlsplit(origin).netloc != host):
            logger.warning(
                "Rejected cross-site %s to %s (origin=%s)",
                request.method, request.url.path, origin,
            )  # fmt: skip
            return Response("Cross-site request rejected.", status_code=403)
        return None

    @app.middleware("http")
    async def reject_cross_site_posts(request: Request, call_next):
        if request.method == "POST" and (rejected := rejected_cross_site(request)):
            return rejected
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

    def server_form(
        request: Request,
        server_id: int | None,
        form: dict,
        status_code=200,
        clone_source: models.Server | None = None,
        **ctx,
    ):
        # The password field is always rendered empty; only "a password is stored" is shown.
        server = db.get_server(server_id) if server_id is not None else None
        kept_from = server or clone_source
        has_stored = kept_from is not None and kept_from.has_password
        connection = ssm_service.connection_view(db, server) if server else None
        return render(
            request, "server_form.html", "servers", status_code=status_code,
            server_id=server_id, form=form, errors=ctx.pop("errors", {}),
            has_stored_password=has_stored, connection=connection, clone_source=clone_source,
            stored_password_error=stored_password(kept_from.id)[1] if has_stored else None, **ctx,
        )  # fmt: skip

    def clone_source_of(raw: str) -> models.Server | None:
        """The server a ``clone`` value names, if any (the id of the row, nothing else of it)."""
        return db.get_server(int(raw)) if raw.isdecimal() and len(raw) < 19 else None

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
        transport: dict[str, str] | None = None,
        others: dict[str, str] | None = None,
        clone_source: models.Server | None = None,
    ):
        def show(status_code: int = 200, **ctx):
            return server_form(request, server_id, form, status_code, clone_source, **ctx)

        transport, other_chosen = aws_config.resolve_choices(transport or {}, others or {})
        form = {
            "name": name, "ip_address": ip, "pem_path": pem, "ssh_user": ssh_user,
            "auth_method": auth_method, **transport, "other_chosen": other_chosen,
        }  # fmt: skip
        form["tags"] = tag_rows(tag_keys, tag_values)
        # Direct SSH hides the SSM fields and does not use them: an empty Other is no error there.
        kind = transport.get("connection_type", "").strip()
        over_ssm = (kind or ssm_service.load_defaults(db).connection_type) == models.CONNECTION_SSM
        other_errors = aws_config.other_errors(transport, other_chosen) if over_ssm else {}
        use_password = auth_method == AUTH_PASSWORD
        if action == "test":  # never saves anything
            password, error = None, None
            if use_password and ssh_password:
                password, error = ssh_password, check_ssh_password(ssh_password)
            elif use_password:
                password, error = stored_password(clone_source.id if clone_source else server_id)
                if password is None and error is None:
                    error = "Enter the SSH password to test the connection."
            error = error or next(iter(other_errors.values()), None)
            if error:
                result = ssh_service.SSHTestResult(
                    False, name.strip() or "(unsaved)", ip.strip(), error=error
                )
            else:
                # What the form says right now, without saving it.
                probe = models.Server(
                    id=server_id or 0, name=name.strip() or "(unsaved)", ip_address=ip.strip(),
                    pem_path=pem, created_at="", updated_at="", ssh_user=ssh_user.strip(),
                    **{key: value.strip() or None for key, value in transport.items()},
                )  # fmt: skip
                result = run_connection_test(probe, password)
            return show(ssh_result=result, errors=other_errors)

        data = validate_server_input(
            db, name, ip, pem, exclude_id=server_id, tag_keys=tag_keys, tag_values=tag_values,
            ssh_user=ssh_user, auth_method=auth_method, **transport,
        )  # fmt: skip
        existing = db.get_server(server_id) if server_id is not None else None
        if data.auth_method == AUTH_PASSWORD:
            # An empty field keeps the stored password; a new server needs one.
            error = check_ssh_password(ssh_password)
            if not ssh_password and existing is not None and existing.has_password:
                error = None
            if not ssh_password and clone_source is not None and clone_source.has_password:
                error = stored_password(clone_source.id)[1]  # a credential that cannot be used
            if error:
                data.errors["ssh_password"] = error
        if clone_source is not None and over_ssm and not data.instance_id_override:
            # A clone is another machine: it must not resolve to, or reuse, the source's instance.
            data.errors["instance_id_override"] = (
                "Instance ID is required for a cloned server: enter the ID of the new instance."
            )
        data.errors.update(other_errors)
        if not data.is_valid:
            return show(status_code=422, errors=data.errors)
        encrypted = None
        if data.auth_method == AUTH_PASSWORD and ssh_password:
            try:
                encrypted = credentials.encrypt(ssh_password)
            except SecretError as exc:
                logger.error("Cannot store the SSH password of %s: %s", data.name, exc)
                return show(status_code=422, errors={"ssh_password": str(exc)})
        elif data.auth_method == AUTH_PASSWORD and clone_source is not None:
            # The ciphertext as stored, for the new row; it is never decrypted here.
            encrypted = db.get_server_password(clone_source.id)
        try:
            if server_id is None:
                db.create_server(
                    data.name, data.ip_address, data.pem_path, tags=data.tags,
                    ssh_user=data.ssh_user, auth_method=data.auth_method,
                    password_encrypted=encrypted, transport=data.transport,
                )  # fmt: skip
                logger.info(
                    "Server created: %s (%s@%s, %s login), %d tag(s)",
                    data.name, data.ssh_user, data.ip_address, data.auth_method, len(data.tags),
                )  # fmt: skip
                if clone_source is not None:
                    logger.info("Server %s cloned from %s", data.name, clone_source.name)
                return redirect("/servers", notice="created", name=data.name)
            if not db.update_server(
                server_id, data.name, data.ip_address, data.pem_path, tags=data.tags,
                ssh_user=data.ssh_user, auth_method=data.auth_method, transport=data.transport,
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
            return show(status_code=422, errors=errors)
        except DuplicateTagKeyError as exc:
            return show(status_code=422, errors={"tags": f"Duplicate tag key: {exc.args[0]}"})

    @app.get("/servers/new", response_class=HTMLResponse)
    def new_server(request: Request):
        form = {
            "name": "", "ip_address": "", "pem_path": "", "ssh_user": DEFAULT_SSH_USER,
            "auth_method": AUTH_PEM, "connection_type": "", "instance_id_override": "",
            "aws_profile": "", "aws_region": "",
        }  # fmt: skip
        clone = request.query_params.get("clone")
        if clone is None:
            return server_form(request, None, {**form, "tags": []})
        source = clone_source_of(clone)
        if source is None:
            return redirect("/servers", notice="not_found")
        # Name, IP, PEM file and instance ID identify the source: they stay empty.
        form.update(
            ssh_user=source.ssh_user, auth_method=source.auth_method,
            connection_type=source.connection_type or "", aws_profile=source.aws_profile or "",
            aws_region=source.aws_region or "",
        )  # fmt: skip
        tags = [{"key": t.key, "value": t.value} for t in source.tags]
        return server_form(request, None, {**form, "tags": tags}, clone_source=source)

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
        connection_type: str = Form(""),
        instance_id_override: str = Form(""),
        aws_profile: str = Form(""),
        aws_region: str = Form(""),
        aws_profile_other: str = Form(""),
        aws_region_other: str = Form(""),
        clone_from: str = Form(""),
    ):
        source = clone_source_of(clone_from) if clone_from else None
        if clone_from and source is None:
            return redirect("/servers", notice="not_found")
        transport = {
            "connection_type": connection_type, "instance_id_override": instance_id_override,
            "aws_profile": aws_profile, "aws_region": aws_region,
        }  # fmt: skip
        others = {"aws_profile": aws_profile_other, "aws_region": aws_region_other}
        return handle_server_form(
            request, None, action, name, ip_address, pem_path, tag_key, tag_value, ssh_user,
            auth_method, ssh_password, transport, others, clone_source=source,
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
            "connection_type": server.connection_type or "",
            "instance_id_override": server.instance_id_override or "",
            "aws_profile": server.aws_profile or "",
            "aws_region": server.aws_region or "",
            "tags": [{"key": t.key, "value": t.value} for t in server.tags],
        }
        return server_form(request, server_id, form)

    async def submitted_form(request: Request) -> FormData:
        """The raw form: unlike Form(None), it tells an empty field from a missing one."""
        return await request.form()

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
        submitted: FormData = Depends(submitted_form),  # noqa: B008
    ):
        server = db.get_server(server_id)
        if server is None:
            return redirect("/servers", notice="not_found")
        user = server.ssh_user if ssh_user is None else ssh_user
        method = server.auth_method if auth_method is None else auth_method
        # A field left out keeps its value; an empty one clears it (back to the default).
        transport = {
            key: str(submitted.get(key, getattr(server, key) or ""))
            for key in ("connection_type", "instance_id_override", "aws_profile", "aws_region")
        }
        others = {key: str(submitted.get(f"{key}_other", "")) for key in aws_config.CHOICE_FIELDS}
        return handle_server_form(
            request, server_id, action, name, ip_address, pem_path, tag_key, tag_value, user,
            method, ssh_password, transport, others,
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
            result = run_connection_test(server, password)
        return servers_page(request, ssh_result=result, tested_id=server_id)

    @app.post("/servers/{server_id}/resolve-instance", response_class=HTMLResponse)
    def resolve_server_instance(request: Request, server_id: int):
        """Look the instance ID up now and cache it, as on first use. Only runs the aws CLI."""
        server = db.get_server(server_id)
        if server is None:
            return redirect("/servers", notice="not_found")
        runner = ssh_runner or subprocess.run
        transport = ssm_service.TransportResolver(db, runner).for_server(server, force_refresh=True)
        result = {"ok": transport.error is None, "error": transport.error}
        return servers_page(request, instance_result=result, tested_id=server_id)

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

    @app.get("/reports/latest/download")
    def download_latest_report():
        report = db.get_latest_report()
        if report is None:
            raise StarletteHTTPException(404)
        filename = report_service.safe_filename(report.filename).replace('"', "_")
        return Response(
            report_service.dump_report(report.servers),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    # --- paste import of a security list -----------------------------------------

    def import_page(request: Request, status_code: int = 200, **ctx):
        ctx.setdefault("raw_text", "")
        ctx.setdefault("parsed", None)
        ctx.setdefault("matched", [])
        ctx.setdefault("loaded", None)
        return render(request, "report_import.html", "reports", status_code=status_code, **ctx)

    @app.get("/reports/import", response_class=HTMLResponse)
    def report_import(request: Request):
        return import_page(request)

    @app.post("/reports/import", response_class=HTMLResponse)
    def import_security_list(
        request: Request, action: str = Form("preview"), raw_text: str = Form("")
    ):
        """Stateless: the pasted text is parsed again on Confirm, and its contents never logged."""
        if len(raw_text) > security_list.MAX_PASTE_CHARS:
            error = f"The pasted text is too long (limit {security_list.MAX_PASTE_CHARS} chars)."
            return import_page(request, status_code=422, error=error)
        parsed = security_list.parse_security_list(raw_text)
        matched = security_list.match_servers(parsed.records, db.list_servers())
        page = {"raw_text": raw_text, "parsed": parsed, "matched": matched}
        if not parsed.records:
            error = "No record with a CVE and a host (ip-a-b-c-d) was found in the pasted text."
            return import_page(request, status_code=422, error=error, **page)
        if action != "confirm":
            return import_page(request, **page)
        servers = security_list.build_report(matched)
        if not servers:
            error = "No host matches a saved server, so nothing was loaded. Add the servers first."
            return import_page(request, status_code=422, error=error, **page)
        name = f"security-list-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        result = report_service.validate_report(
            report_service.dump_report(servers), name, db.server_names()
        )
        if not result.valid:
            error = "The generated report was not accepted: " + "; ".join(result.errors)
            return import_page(request, status_code=422, error=error, **page)
        db.save_report(result.filename, result.servers, status="VALID")
        rows = patch_report.record_import(db, matched)
        logger.info(
            "Security list imported: %s (%d records, %d servers, %d CVEs, %d unknown hosts)",
            result.filename, len(parsed.records), result.server_count, result.cve_count,
            sum(m.server_name is None for m in matched),
        )  # fmt: skip
        return import_page(request, loaded=result, report_rows=rows, **page)

    # --- patch report --------------------------------------------------------------

    @app.get("/patch-report", response_class=HTMLResponse)
    def patch_report_page(request: Request):
        patcher.reconcile()  # a patch cut short shows as failed, not pending
        filters, problems = patch_report.parse_filters(request.query_params)
        rows = db.list_patch_report(**filters.query())
        everything = db.list_patch_report()
        usns = {u.strip() for r in everything for u in (r.usn or "").split(",") if u.strip()}
        return render(
            request, "patch_report.html", "patch-report", status_code=422 if problems else 200,
            error=" ".join(problems) or None, rows=rows, filters=filters,
            summaries=patch_report.summarize(rows), total=len(everything),
            server_options=list(dict.fromkeys(r.server_name for r in everything)),
            usn_options=sorted(usns), cve_options=sorted({r.cve for r in everything}),
            export_query=filters.query_string(),
        )  # fmt: skip

    @app.get("/patch-report/export.xlsx")
    def export_patch_report(request: Request):
        # Not with a filter left out: the file would claim more than was asked for.
        filters, problems = patch_report.parse_filters(request.query_params)
        if problems:
            raise StarletteHTTPException(422, " ".join(problems))
        rows = db.list_patch_report(**filters.query())
        filename = excel_export.patch_report_filename()
        logger.info("Patch report export: %s (%d rows)", filename, len(rows))
        return Response(
            excel_export.build_patch_report_workbook(rows, patch_report.summarize(rows)),
            media_type=excel_export.MEDIA_TYPE,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

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

    # --- live progress of a run --------------------------------------------------------

    def reconcile_run(ref: run_events.RunRef) -> None:
        """A run whose worker died must read as finished, and cannot be cancelled any more."""
        (analyzer if ref.kind == run_events.KIND_ANALYSIS else patcher).reconcile()

    unknown_run = {"error": "Unknown run."}

    @app.get("/runs/{run_ref}/events")
    def run_progress_events(request: Request, run_ref: str):
        """The step events after the id ``after``, and the state of the run. Server names say
        something about the user, so other sites must not read them."""
        if rejected := rejected_cross_site(request):
            return rejected
        ref = run_events.parse_ref(run_ref)
        if ref is None:
            return JSONResponse(unknown_run, status_code=404)
        after = request.query_params.get("after", "0")
        if not re.fullmatch(r"\d{1,18}", after):
            error = {"error": "after must be a non-negative whole number."}
            return JSONResponse(error, status_code=422)
        reconcile_run(ref)
        payload = run_events.events_payload(db, ref, int(after))
        if payload is None:
            return JSONResponse(unknown_run, status_code=404)
        return JSONResponse(
            {**payload, "now": datetime.now(timezone.utc).isoformat(timespec="milliseconds")}
        )

    @app.post("/runs/{run_ref}/cancel")
    def cancel_run(run_ref: str):
        """Stop a run after its current step. A finished run, or a second request, is a no-op."""
        ref = run_events.parse_ref(run_ref)
        if ref is None:
            return JSONResponse({**unknown_run, "accepted": False}, status_code=404)
        reconcile_run(ref)
        answer = run_events.request_cancel(db, ref)
        if answer is None:
            return JSONResponse({**unknown_run, "accepted": False}, status_code=404)
        return JSONResponse(answer)

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
        acknowledged_unresolved: str = Form(""),
    ):
        stored_server_report(run_id, analysis_id)
        if confirm != "yes":
            return redirect(f"/analysis/{run_id}/servers/{analysis_id}/approve")
        try:
            # An unchecked "Skip reboot" box is absent from the form: reboot if required.
            execution_id = patcher.approve(
                analysis_id,
                skip_reboot=bool(skip_reboot),
                acknowledged_unresolved=_form_count(acknowledged_unresolved),
            )
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
        acknowledged_unresolved: str = Form(""),
    ):
        patch_all_run(run_id)
        if confirm != "yes":
            return redirect(f"/analysis/{run_id}/patch-all")
        try:
            queue_id = patcher.start_queue(
                run_id,
                analysis_id or [],
                bool(skip_reboot),
                acknowledged_unresolved=_form_count(acknowledged_unresolved),
            )
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
        defaults = ssm_service.load_defaults(db)
        # With no region saved, the default profile's own region is the default selection.
        profile_region = "" if defaults.region else aws_config.region_of(defaults.profile)
        connection_form = ctx.pop("connection_form", None) or {
            "connection_type": defaults.connection_type,
            "aws_profile": defaults.profile or "",
            "aws_region": defaults.region or profile_region,
            "region_from_profile": bool(profile_region),
        }
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
            cache_ttl_labels=cache_settings.LABELS, cache_ttl_saved=bool(ttls.saved()),
            connection_form=connection_form,
            connection_errors=ctx.pop("connection_errors", {}),
            ssm_plugin_location=ssm_plugin.find_plugin(),
            ssm_plugin_dir=config.get_plugin_bin_dir(), ssm_status=ctx.pop("ssm_status", None),
            step_timeout_value=ctx.pop("step_timeout_value", None)
            or cache_settings.step_timeout(db),
            step_timeout_error=ctx.pop("step_timeout_error", None),
            step_timeout_default=cache_settings.DEFAULT_STEP_TIMEOUT_SECONDS,
            step_timeout_min=cache_settings.MIN_STEP_TIMEOUT_SECONDS,
            step_timeout_max=cache_settings.MAX_STEP_TIMEOUT_SECONDS,
            **ctx,
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

    @app.post("/settings/connection", response_class=HTMLResponse)
    def save_connection_defaults(
        request: Request,
        action: str = Form("save"),
        connection_type: str = Form(""),
        aws_profile: str = Form(""),
        aws_region: str = Form(""),
        aws_profile_other: str = Form(""),
        aws_region_other: str = Form(""),
    ):
        choices, other_chosen = aws_config.resolve_choices(
            {"aws_profile": aws_profile, "aws_region": aws_region},
            {"aws_profile": aws_profile_other, "aws_region": aws_region_other},
        )
        form = {
            "connection_type": connection_type.strip(),
            "aws_profile": choices["aws_profile"].strip(),
            "aws_region": choices["aws_region"].strip(),
        }
        errors = {
            **ssm_service.check_defaults(*form.values()),
            **aws_config.other_errors(choices, other_chosen),
        }
        if errors:
            shown = {**form, "other_chosen": other_chosen}
            return settings_page(
                request, status_code=422, connection_form=shown, connection_errors=errors
            )
        ssm_service.save_defaults(db, *form.values())
        logger.info(
            "Default connection set to %s (profile=%s region=%s)",
            models.CONNECTION_TYPES[form["connection_type"]],
            form["aws_profile"] or "-", form["aws_region"] or "-",
        )  # fmt: skip
        if action != "apply_all":
            return redirect("/settings", notice="connection_saved")
        count = db.clear_server_connection_settings()
        logger.info("All servers follow the default connection (%d cleared)", count)
        return redirect("/settings", notice="connection_applied", count=count)

    @app.get("/settings/aws-options")
    def aws_options(request: Request):
        """The profiles of the AWS CLI config and the region list, for the connection forms.
        Profile names say something about the user, so other sites must not read them."""
        return rejected_cross_site(request) or JSONResponse(aws_config.options())

    @app.get("/settings/ssm-status", response_class=HTMLResponse)
    def ssm_status_fragment(request: Request):
        """The Settings badge, loaded apart from the page: it runs the aws CLI (read-only)."""
        status = ssm_service.check_status(db, ssh_runner or subprocess.run)
        return templates.TemplateResponse(request, "_ssm_status.html", {"ssm_status": status})

    @app.post("/settings/ssm-plugin/install", response_class=HTMLResponse)
    def install_ssm_plugin(request: Request):
        if not plugin_install_lock.acquire(blocking=False):
            error = "The Session Manager plugin is already being installed."
            return settings_page(request, status_code=409, error=error)
        try:
            result = ssm_plugin.install(runner=ssh_runner or subprocess.run)
        except ssm_plugin.PluginInstallError as exc:
            logger.warning("Session Manager plugin not installed: %s", exc)
            return settings_page(request, status_code=502, error=str(exc))
        finally:
            plugin_install_lock.release()
        notice = "ssm_plugin_installed" if result.signature_checked else "ssm_plugin_unsigned"
        return redirect("/settings", notice=notice, name=result.version)

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
        status = None
        if request.query_params.get("ssm_check"):  # the Check now link, also without JavaScript
            status = ssm_service.check_status(db, ssh_runner or subprocess.run)
        return settings_page(
            request, notice=notice_from_query(request), preview_name=preview_name, ssm_status=status
        )

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

    @app.post("/settings/step-timeout", response_class=HTMLResponse)
    def save_step_timeout(
        request: Request, action: str = Form("save"), step_timeout: str = Form("")
    ):
        if action == "reset":
            db.delete_setting(cache_settings.STEP_TIMEOUT_SETTING)
            logger.info("Step timeout reset to default")
            return redirect("/settings", notice="step_timeout_reset")
        seconds, error = cache_settings.parse_step_timeout(step_timeout)
        if error:
            return settings_page(
                request, status_code=422, step_timeout_value=step_timeout[:32],
                step_timeout_error=error,
            )  # fmt: skip
        db.set_setting(cache_settings.STEP_TIMEOUT_SETTING, str(seconds))
        logger.info("Step timeout set to %d s", seconds)
        return redirect("/settings", notice="step_timeout_saved")

    @app.post("/settings/clear-cache")
    def clear_security_cache():
        removed = metadata.clear()
        removed = analyzer.nvd.clear() or removed
        removed = analyzer.advisories.clear() or removed
        removed = analyzer.sources.clear() or removed
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
