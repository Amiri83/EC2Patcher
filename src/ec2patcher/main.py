"""Command line entry point: `ec2patcher` or `python -m ec2patcher`."""

import argparse
import logging
import os
import sys
import threading
import webbrowser

import uvicorn

from ec2patcher import __version__
from ec2patcher.app import DEFAULT_ALLOWED_HOSTS, create_app
from ec2patcher.config import DB_FILENAME, DEFAULT_HOST, DEFAULT_PORT, LOG_FILENAME, get_data_dir


def setup_logging(log_path) -> None:
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    for handler in (logging.StreamHandler(sys.stderr), logging.FileHandler(log_path)):
        handler.setFormatter(fmt)
        root.addHandler(handler)


def _can_open_browser() -> bool:
    if sys.platform.startswith("linux"):
        return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return True


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ec2patcher", description="EC2 Patcher GUI")
    parser.add_argument(
        "--host", default=DEFAULT_HOST, help=f"bind address (default {DEFAULT_HOST})"
    )
    parser.add_argument(
        "--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})"
    )
    parser.add_argument(
        "--data-dir", help="data directory (default: per-user data dir, or $EC2PATCHER_DATA_DIR)"
    )
    parser.add_argument("--no-browser", action="store_true", help="do not open a web browser")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)

    data_dir = get_data_dir(args.data_dir)
    setup_logging(data_dir / LOG_FILENAME)

    server: uvicorn.Server | None = None

    def request_shutdown() -> None:
        if server is not None:
            server.should_exit = True

    allowed_hosts = list(dict.fromkeys([*DEFAULT_ALLOWED_HOSTS, args.host]))
    if args.host in ("0.0.0.0", "::"):  # noqa: S104 - explicit user choice
        allowed_hosts = ["*"]
    app = create_app(
        db_path=data_dir / DB_FILENAME,
        shutdown_handler=request_shutdown,
        allowed_hosts=allowed_hosts,
    )
    config = uvicorn.Config(
        app, host=args.host, port=args.port, log_config=None, log_level="info", access_log=False
    )
    server = uvicorn.Server(config)

    url_host = f"[{args.host}]" if ":" in args.host else args.host
    url = f"http://{url_host}:{args.port}/"
    print(f"EC2 Patcher {__version__} - open {url} (data: {data_dir})", flush=True)
    if not args.no_browser and _can_open_browser():
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()

    server.run()


if __name__ == "__main__":
    main()
