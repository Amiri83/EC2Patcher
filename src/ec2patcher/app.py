"""FastAPI application: routes and page rendering."""

import logging
import os
import signal
from collections.abc import Callable
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode, urlsplit

from fastapi import FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.background import BackgroundTask
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.trustedhost import TrustedHostMiddleware

from ec2patcher import __version__
from ec2patcher.config import DB_FILENAME, get_data_dir
from ec2patcher.database import Database, DuplicateServerNameError
from ec2patcher.services import report_service, ssh_service
from ec2patcher.validation import validate_server_input

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
}


def _default_shutdown() -> None:
    # Used when the app is not started through ec2patcher.main (e.g. plain uvicorn):
    # SIGINT triggers uvicorn's normal graceful shutdown.
    os.kill(os.getpid(), signal.SIGINT)


def format_timestamp(value: str) -> str:
    """Render a stored UTC ISO timestamp in local time, e.g. '2026-09-26 23:25 MDT'."""
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    except (TypeError, ValueError):
        return value


def create_app(
    db_path: Path | None = None,
    shutdown_handler: Callable[[], None] | None = None,
    ssh_runner: ssh_service.Runner | None = None,
    allowed_hosts: list[str] | None = None,
) -> FastAPI:
    db = Database(db_path or get_data_dir() / DB_FILENAME)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("EC2Patcher %s started (database: %s)", __version__, db.path)
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

    def run_ssh_test(name: str, ip: str, pem: str) -> ssh_service.SSHTestResult:
        if ssh_runner is not None:
            return ssh_service.check_connection(name, ip, pem, runner=ssh_runner)
        return ssh_service.check_connection(name, ip, pem)

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
        return render(
            request, "servers.html", "servers", status_code=status_code,
            servers=db.list_servers(), confirm_text=CLEAR_CONFIRMATION_TEXT, **ctx,
        )  # fmt: skip

    @app.get("/servers", response_class=HTMLResponse)
    def list_servers(request: Request):
        return servers_page(request)

    def server_form(request: Request, server_id: int | None, form: dict, status_code=200, **ctx):
        return render(
            request, "server_form.html", "servers", status_code=status_code,
            server_id=server_id, form=form, errors=ctx.pop("errors", {}), **ctx,
        )  # fmt: skip

    def handle_server_form(
        request: Request, server_id: int | None, action: str, name: str, ip: str, pem: str
    ):
        form = {"name": name, "ip_address": ip, "pem_path": pem}
        if action == "test":
            result = run_ssh_test(name.strip() or "(unsaved)", ip.strip(), pem)
            return server_form(request, server_id, form, ssh_result=result)

        data = validate_server_input(db, name, ip, pem, exclude_id=server_id)
        if not data.is_valid:
            return server_form(request, server_id, form, status_code=422, errors=data.errors)
        try:
            if server_id is None:
                db.create_server(data.name, data.ip_address, data.pem_path)
                logger.info("Server created: %s (%s)", data.name, data.ip_address)
                return redirect("/servers", notice="created", name=data.name)
            if not db.update_server(server_id, data.name, data.ip_address, data.pem_path):
                return redirect("/servers", notice="not_found")
            logger.info("Server edited: id=%s %s (%s)", server_id, data.name, data.ip_address)
            return redirect("/servers", notice="updated", name=data.name)
        except DuplicateServerNameError:
            errors = {"name": f"A server named '{data.name}' already exists. Names must be unique."}
            return server_form(request, server_id, form, status_code=422, errors=errors)

    @app.get("/servers/new", response_class=HTMLResponse)
    def new_server(request: Request):
        return server_form(request, None, {"name": "", "ip_address": "", "pem_path": ""})

    @app.post("/servers/new", response_class=HTMLResponse)
    def create_server(
        request: Request,
        action: str = Form("save"),
        name: str = Form(""),
        ip_address: str = Form(""),
        pem_path: str = Form(""),
    ):
        return handle_server_form(request, None, action, name, ip_address, pem_path)

    @app.get("/servers/{server_id}/edit", response_class=HTMLResponse)
    def edit_server(request: Request, server_id: int):
        server = db.get_server(server_id)
        if server is None:
            return redirect("/servers", notice="not_found")
        form = {"name": server.name, "ip_address": server.ip_address, "pem_path": server.pem_path}
        return server_form(request, server_id, form)

    @app.post("/servers/{server_id}/edit", response_class=HTMLResponse)
    def update_server(
        request: Request,
        server_id: int,
        action: str = Form("save"),
        name: str = Form(""),
        ip_address: str = Form(""),
        pem_path: str = Form(""),
    ):
        if db.get_server(server_id) is None:
            return redirect("/servers", notice="not_found")
        return handle_server_form(request, server_id, action, name, ip_address, pem_path)

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
        result = run_ssh_test(server.name, server.ip_address, server.pem_path)
        return servers_page(request, ssh_result=result, tested_id=server_id)

    @app.post("/servers/clear", response_class=HTMLResponse)
    def clear_servers(request: Request, confirm_text: str = Form("")):
        if confirm_text.strip() != CLEAR_CONFIRMATION_TEXT:
            error = f"Servers were NOT cleared. Type {CLEAR_CONFIRMATION_TEXT} exactly to confirm."
            return servers_page(request, status_code=400, error=error)
        count = db.clear_servers()
        logger.info("All servers cleared (%d removed)", count)
        return redirect("/servers", notice="cleared", count=count)

    # --- reports -------------------------------------------------------------

    def reports_page(request: Request, status_code: int = 200, **ctx):
        report = db.get_latest_report()
        missing = []
        if report is not None:
            names = db.server_names()
            missing = [name for name in report.servers if name not in names]
        return render(
            request, "reports.html", "reports", status_code=status_code,
            report=report, missing_servers=missing,
            max_kib=report_service.MAX_REPORT_BYTES // 1024, **ctx,
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

    # --- history / settings --------------------------------------------------

    @app.get("/history", response_class=HTMLResponse)
    def history(request: Request):
        return render(request, "history.html", "history")

    @app.get("/settings", response_class=HTMLResponse)
    def settings(request: Request):
        return render(request, "settings.html", "settings", db_path=db.path)

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
