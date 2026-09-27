"""Display formatting shared by the HTML pages and the Excel export."""

from datetime import datetime


def format_timestamp(value: str) -> str:
    """Render a stored UTC ISO timestamp in local time, e.g. '2026-09-26 23:25 MDT'."""
    try:
        return datetime.fromisoformat(value).astimezone().strftime("%Y-%m-%d %H:%M %Z")
    except (TypeError, ValueError):
        return value


def format_size(value: int | None) -> str:
    if value is None:
        return "-"
    size = float(value)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if size < 1024 or unit == "GiB":
            return f"{int(size)} B" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return str(value)
