# EC2 Patcher

A small, local, single-user web GUI for recurring security patching of Ubuntu EC2 servers.

**Current scope: Phase 1.5.** This covers the application shell, the server inventory
(with user-defined server tags), SSH connectivity testing, and uploading/validating the
security team's CVE report.
CVE analysis, package downloads and patching are **not** implemented yet; they come in later phases.

## Features (Phase 1 + 1.5)

- **Dashboard**: number of configured servers, the latest accepted report, and application status.
- **Servers**: add, edit, delete and SSH-test servers. **Clear All Servers** requires typing
  `DELETE SERVERS` first.
  - Each server has a unique **name**, an **IP address** and a **PEM file path**.
  - Names may contain letters, digits, `.`, `_` and `-`, and are unique regardless of case.
    Later phases use the name to match reports and to name per-server directories.
  - Only the PEM *path* is stored. Key contents are never read, stored or logged. `~` is expanded.
    The PEM file must exist and be readable when you save or test a server.
  - The SSH user is always `ubuntu`, and only key-based auth is used.
- **Server tags** (Phase 1.5): optional free-form key/value labels per server, e.g.
  `display_name = Billing API`, `env = prod`.
  - Add, edit and remove tag rows on the Add/Edit Server form (**+ Add Tag** / **Remove**).
    Saving stores exactly the rows shown; removed rows are deleted.
  - Keys and values are trimmed. A key is required (max 64 chars); the value may be empty
    (max 256 chars). Rows with a blank key *and* value are ignored. Up to 50 tags per server.
  - Keys are unique per server, regardless of case (`Duplicate tag key: env`). Different
    servers can use the same key.
  - The Servers page shows the first two tags, sorted by key, then **+N more**. Hover over it
    to see all tags.
  - Deleting a server or using **Clear All Servers** also removes its tags.
  - Tags are inventory metadata only. CVE reports are always matched by the server **name**.
- **SSH test**: runs `ssh -i <pem> ubuntu@<ip>` with `BatchMode=yes` and `ConnectTimeout=10`,
  plus a 30 s overall limit. It shows the hostname, OS release and architecture, or a short error
  such as *Permission denied (publickey)* or *Connection timed out*. The system OpenSSH client
  runs it with an argument list, never through a shell. New host keys are accepted on first
  connect (`StrictHostKeyChecking=accept-new`); a changed host key is reported as an error.
- **Reports**: upload a CVE JSON report (`.json`, max 1 MiB). Validation is structural only. The
  latest accepted report is kept in SQLite; a failed upload does not replace it.
- **History / Settings**: placeholders for later phases.
- **Shutdown App**: stops the local server after you confirm. No data is removed.

### CVE report format

```json
{
  "app-prod-01": ["CVE-2026-12345", "CVE-2026-67890"],
  "database-prod-01": ["CVE-2026-22222"]
}
```

Each key must exactly match the name of a configured server; an unknown server rejects the
whole report. Each value must be a JSON array of strings that look like `CVE-YYYY-NNNN...`.
Case doesn't matter on input. IDs are normalized to uppercase and de-duplicated.

## Requirements

- Python 3.10+
- OpenSSH client (`ssh`) on `PATH` (only for SSH tests)

## Install

```bash
cd /data/projects/EC2Patcher
python3 -m venv .venv            # or: uv venv .venv
.venv/bin/pip install -e ".[dev]"
```

## Run

```bash
.venv/bin/ec2patcher             # or: .venv/bin/python -m ec2patcher
```

Then open <http://127.0.0.1:8080/>. If a desktop session is available, a browser opens automatically.

Options:

| Option | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address (localhost only by default; there is no authentication) |
| `--port` | `8080` | Port |
| `--data-dir` | per-user data dir | Where the database and log live (also `$EC2PATCHER_DATA_DIR`) |
| `--no-browser` | off | Do not open a browser |

Stop the app with **Shutdown App** in the sidebar, or with Ctrl+C.

## Data location

| File | Default path (Linux) |
|---|---|
| SQLite database | `~/.local/share/ec2patcher/ec2patcher.db` |
| Log file | `~/.local/share/ec2patcher/ec2patcher.log` |

Other platforms use the equivalent [platformdirs](https://pypi.org/project/platformdirs/)
user data directory. The schema is created and migrated automatically on startup. A database
created by Phase 1 is upgraded in place: the `server_tags` table is added, and existing servers
and reports are kept.

## Test and lint

```bash
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

The tests mock `ssh`, so they never need a real EC2 server.

## Project layout

```
src/ec2patcher/
  main.py            CLI entry point (argparse + uvicorn, shutdown hook)
  app.py             FastAPI app and all routes
  config.py          data directory / defaults
  database.py        SQLite schema, migrations, server + tag + report storage
  models.py          Server / Tag / StoredReport dataclasses
  validation.py      server name / IP / PEM path / tag validation
  services/
    ssh_service.py     SSH connectivity test (subprocess, no shell)
    report_service.py  CVE report structural validation
  templates/         Jinja2 templates
  static/            CSS + a small amount of vanilla JS
tests/               pytest suite
```

## Security notes

- The app binds to `127.0.0.1` by default and rejects requests whose `Host` header isn't local.
  It also rejects cross-site POSTs, which guards against CSRF and DNS-rebinding attacks from
  websites open in your browser.
- The app never reads PEM contents. Subprocesses never use `shell=True`.
- Unexpected errors show a generic message in the GUI; details go to the log.
