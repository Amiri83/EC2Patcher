# EC2 Patcher

A small, local, single-user web GUI for recurring security patching of Ubuntu EC2 servers.

**Current scope: Phase 2.1.** This covers the application shell, the server inventory
(with user-defined server tags), SSH connectivity testing, uploading/validating the
security team's CVE report, and a **read-only pre-patch analysis** that produces a per-server
report (with CVE severity and Excel export) and an exact package / .deb plan.
Package downloads, installation, reboots and patch approval are **not** implemented yet;
they come in Phase 3.

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

## Pre-patch analysis (Phase 2)

On the **Reports** page, click **Analyze Report**. The analysis runs in the background and the
page shows each server as *Waiting*, *Analyzing*, *Complete* or *Failed* (with the reason).
Servers are analyzed one after another; one failing server never affects the others. When it
finishes, **View Report** opens the per-server pre-patch report.

**Read-only.** For each server in the latest report, EC2Patcher runs three fixed commands over
the same SSH connection settings as the SSH test (`ubuntu@<ip>` with the configured PEM), as the
unprivileged `ubuntu` user, **without sudo**:

1. Facts: hostname, `/etc/os-release`, `dpkg --print-architecture`, `uname -r`,
   `/run/reboot-required(.pkgs)`, APT list age, and `dpkg-query` (binary package, version,
   **source package**, source version).
2. APT candidates: `apt-cache policy` / `apt-cache show` for the affected binary packages, and
   whether their installed maintainer scripts request a reboot.
3. APT plan: `apt-get -s install ...` (simulation) and `apt-get --print-uris install ...` for
   the exact candidate versions. `--print-uris` prints the URI, `.deb` file name, size and
   SHA256 of every package the upgrade needs **without downloading anything**.

Nothing is downloaded, copied, installed, removed or restarted. There is no SCP and no reboot.

### How a CVE is decided

Ubuntu tracks vulnerabilities per **source** package; APT installs **binary** packages. For
each reported CVE and the server's Ubuntu release:

1. Canonical's statement(s) for the release name the affected source package(s) and, when
   fixed, the fixed version (Ubuntu Pro / ESM pockets such as `esm-infra/focal` are recognised).
2. `dpkg-query` maps installed binary packages to their source package and source version
   (no substring matching).
3. Versions are compared with Debian semantics (epochs, revisions, `~`), identical to
   `dpkg --compare-versions`.
4. If a patch is required, the server's APT candidate must be at least the fixed version;
   otherwise the finding says *Fix known - suitable APT candidate not available* and why.
5. The APT simulation + `--print-uris` produce the exact .deb plan. Packages fixing several
   CVEs appear once, linked to every CVE they fix.

Statuses: *Patch required*, *Already fixed*, *Not affected*, *Package not installed*,
*Fix not available*, *Fix requires Ubuntu Pro / ESM*, *Fix known - suitable APT candidate not
available*, *Under investigation / needs evaluation*, *Ignored / no fix planned*,
*Analysis error*. Anything that cannot be decided is shown as such, never as safe. A CVE that
Canonical does not know is *needs evaluation*.

**Kernels:** kernel CVEs are checked against the *running* kernel. The upgrade path is the
installed kernel meta package (e.g. `linux-aws`), which pulls in the new ABI packages
(`linux-image-<abi>-aws`, ...). If a fixed kernel is already installed but not running, the
finding is *Already fixed* with a *reboot pending* note.

**Reboot:** *Current reboot required* reads `/run/reboot-required`. *Expected reboot after
planned patch* is YES when the plan contains a new kernel image/modules, or a package whose
maintainer scripts request a reboot (e.g. `libc6`, `dbus`). The final requirement is verified
after installation in Phase 3.

### Canonical security metadata

Source: Canonical's official Ubuntu OpenVEX data,
<https://security-metadata.canonical.com/vex/vex-all.tar.xz> (NVD, ubuntu.com web pages and
the Ubuntu Security API are not used). The ~70 MB archive (~26 GB uncompressed) is streamed
once and reduced to a small local index; analyses then query it locally.

- Cache: `~/.cache/ec2patcher/security-metadata/` (override with `$EC2PATCHER_CACHE_DIR`),
  about 160 MB (archive + index).
- The first analysis downloads and indexes the data; this takes several minutes. Later
  analyses refresh it at most once a day, using a conditional request (no download if
  unchanged).
- If a refresh fails but a cache exists, the cached data is used and the report shows a
  **STALE DATA** warning with the cache time. With no usable data, the analysis fails; nothing
  is guessed.

### Results

Every analysis is stored as a new run in SQLite (older runs are kept and remain viewable from
the Reports page). A run keeps a snapshot of the report, the server name, IP and `display_name`
tag, and all remote facts, so later edits don't change historical results. Report keys are
always matched against the canonical server **name**; `display_name` is shown but never used
for matching. If the app is stopped during an analysis, the run is marked *interrupted*.

**Severity (Phase 2.1).** Each CVE finding shows a Severity taken from Canonical's own priority
("... classified this CVE as of *high* priority") as stored at analysis time: Critical, High,
Medium or Low. Anything else (untriaged, negligible, missing, older runs without a priority)
is shown as **Unknown**; nothing is guessed.

**Export to Excel (Phase 2.1).** Each server report page has an *Export to Excel* button that
downloads `ec2patcher_<server name>_<analysis date>.xlsx` with three sheets: *Summary*,
*CVE Findings* (every stored finding) and *Package Plan*. The workbook is built on demand from
the stored snapshot only; exporting never runs ssh, APT or metadata downloads.

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
- OpenSSH client (`ssh`) on `PATH` (for SSH tests and analysis)
- Internet access to `security-metadata.canonical.com` for the security metadata (the cached
  copy is used when offline)

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
| Canonical metadata cache | `~/.cache/ec2patcher/security-metadata/` |

Other platforms use the equivalent [platformdirs](https://pypi.org/project/platformdirs/)
user data directory. The schema is created and migrated automatically on startup. A database
created by an earlier phase is upgraded in place (Phase 1.5 adds `server_tags`, Phase 2 adds the
analysis tables); existing servers, tags and reports are kept.

## Test and lint

```bash
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

The tests mock `ssh` and use fixture Canonical VEX data and captured APT output, so they never
need a real EC2 server, a real PEM, internet access or package installs.

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
    ssh_service.py        SSH connectivity test + read-only remote commands (no shell)
    report_service.py     CVE report structural validation
    security_metadata.py  Canonical VEX download, local index, stale-data handling
    server_state.py       remote facts + dpkg inventory (binary -> source mapping)
    debversion.py         Debian version comparison (dpkg semantics)
    cve_resolver.py       CVE status, APT candidate check, package plan, reboot expectation
    apt_planner.py        apt-cache / apt-get -s / --print-uris commands and parsers
    analysis_service.py   background analysis runs, persistence
  templates/         Jinja2 templates
  static/            CSS + a small amount of vanilla JS
tests/               pytest suite
```

## Security notes

- The app binds to `127.0.0.1` by default and rejects requests whose `Host` header isn't local.
  It also rejects cross-site POSTs, which guards against CSRF and DNS-rebinding attacks from
  websites open in your browser.
- The app never reads PEM contents. Subprocesses never use `shell=True`.
- Analysis commands are fixed strings; package names and versions are validated against strict
  patterns and shell-quoted. No `sudo`, no downloads, no installs.
- Unexpected errors show a generic message in the GUI; details go to the log.
