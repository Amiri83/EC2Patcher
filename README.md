# EC2 Patcher

A small, local, single-user web GUI for recurring security patching of Ubuntu EC2 servers.

**Current scope: Phase 3.** This covers the application shell, the server inventory
(with user-defined server tags), SSH connectivity testing, uploading/validating the
security team's CVE report, a **read-only pre-patch analysis** that produces a per-server
report (with NVD CVSS severity and Excel export) and an exact package / .deb plan, and
**per-server patch execution** of an approved plan with verification and patch history, and
**Patch All** (the eligible servers of one analysis, sequentially). After a verified patch a
server is rebooted only if `/run/reboot-required` exists on it and *Skip reboot* is unchecked.
EC2Patcher never runs `apt upgrade` / `dist-upgrade`.

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

**Read-only.** For each server in the latest report, EC2Patcher runs **one** fixed command over
the same SSH connection settings as the SSH test (`ubuntu@<ip>` with the configured PEM), as the
unprivileged `ubuntu` user, **without sudo**. It collects the facts: hostname,
`/etc/os-release`, `dpkg --print-architecture`, `uname -r`, `/run/reboot-required(.pkgs)`,
which installed maintainer scripts request a reboot, and `dpkg-query` (binary package, version,
**source package**, source version, architecture and dependency fields).

The server is never asked for APT candidates or plans. Those are resolved **on the
workstation** against a private APT state per Ubuntu release and architecture
(`<data dir>/apt/<codename>-<arch>/`, e.g. `noble-amd64`). Its `sources.list` holds only the
Ubuntu archive pockets `<codename>`, `<codename>-updates` and `<codename>-security` (never
`-proposed` / `-backports`) for the server's architecture. Every `apt-get` / `apt-cache` call
passes `-o Dir::State=…`, `-o Dir::Cache=…`, `-o Dir::Etc::sourcelist=…` (plus the other
`Dir::Etc` overrides), so the workstation's own APT configuration and state are never used or
changed, and no `sudo` is needed:

1. `apt-get update` on the private state, only when its lists are older than the configured
   maximum age (default 6 hours, at most once per analysis run and release). If the update
   fails, the affected findings are reported as *Analysis error*. Candidates are never guessed.
2. APT candidates: `apt-cache policy` / `apt-cache show` for the affected binary packages,
   evaluated against a dpkg status file rebuilt from the server's `dpkg-query` output.
3. APT plan: `apt-get -s install ...` (simulation) and `apt-get --print-uris install ...` for
   the exact candidate versions. `--print-uris` prints the URI, `.deb` file name, size and
   SHA256 of every package the upgrade needs **without downloading anything**.

Because the lists are always current, a candidate older than Canonical's fix means the fix is
genuinely not published in those pockets (*Fixed version not in configured repositories*).
Fixes published only in Ubuntu Pro / ESM stay *Ubuntu Pro / ESM required*, since the private
state has no Pro credentials.

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
4. If a patch is required, the archive's APT candidate must be at least the fixed version;
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

Source: Canonical's Security JSON API at
`https://ubuntu.com/security/cves/<CVE>.json`. During analysis, EC2Patcher queries
Canonical once per reported CVE and maps source-package release statuses to its findings.
Repeated CVEs are memoized in process memory; the Settings button clears that memo.
There is no persistent Canonical metadata cache or bulk dataset download. If an online
lookup fails, that CVE is marked **Canonical metadata unavailable** and analysis continues.

### Results

Every analysis is stored as a new run in SQLite (older runs are kept and remain viewable from
the Reports page). A run keeps a snapshot of the report, the server name, IP and `display_name`
tag, and all remote facts, so later edits don't change historical results. Report keys are
always matched against the canonical server **name**; `display_name` is shown but never used
for matching. If the app is stopped during an analysis, the run is marked *interrupted*.

**Severity (Phase 2.2).** Each CVE finding shows a **Severity** (Critical / High / Medium /
Low / Unknown) and a compact **CVSS** value (e.g. `8.8 (v3.1)`) taken from the official
[NVD CVE API 2.0](https://nvd.nist.gov/developers/vulnerabilities) during the analysis and
stored with the finding. NVD is *only* used for severity: whether a CVE affects a server, the
fixed version, the status and the package plan still come exclusively from Canonical.
Canonical's own priority is still stored and shown as **Ubuntu Priority**.

- CVSS selection (deterministic): the NVD/NIST assessment (`nvd@nist.gov`) if present, else
  the CNA's *Primary* assessment, else any other; within each group CVSS v4.0 > v3.1 > v3.0
  (ties by source name). CVSS v2 is only a last-resort fallback (never rated Critical).
- The rating follows the numeric base score (0.1-3.9 Low, 4.0-6.9 Medium, 7.0-8.9 High,
  9.0-10.0 Critical); a missing or inconsistent NVD `baseSeverity` is recorded, and a score of
  0.0 (None) is shown as Unknown, never Low.
- Each unique CVE is queried once per analysis, sequentially, 6 s apart (NVD's public limit of
  5 requests / 30 s; 0.6 s with an API key). Set `NVD_API_KEY` to use a key; it is sent in the
  `apiKey` request header and never stored, logged or exported.
- Responses are cached per CVE in `~/.cache/ec2patcher/nvd/` for 24 hours. If NVD cannot be
  reached, older cached data is used and marked *stale cache*; without a cache the severity is
  **Unknown** ("NVD lookup failed"). NVD problems never change a finding's patch status.
- Analyses made before Phase 2.2 keep their stored data and show Severity **Unknown**; they
  are never re-fetched.

**Export to Excel (Phase 2.1).** Each server report page has an *Export to Excel* button that
downloads `ec2patcher_<server name>_<analysis date>.xlsx` with three sheets: *Summary*,
*CVE Findings* (every stored finding, including CVSS Score / Version / Vector, Severity Source
and Ubuntu Priority) and *Package Plan*. The workbook is built on demand from the stored
snapshot only; exporting never runs ssh, APT, NVD or metadata downloads.

## Patch execution (Phase 3)

Each server report has a **Patch Decision** area with **Reject** and **Approve & Patch**
(one server at a time; see *Patch All* below for a whole analysis). Rejecting only records
the decision.
Approving (after a confirmation page) runs this pipeline; every step must pass:

1. **Revalidate**: reconnect and compare hostname, Ubuntu version/codename, architecture and
   the installed version of every planned package with the analysis. Any drift aborts with
   *PATCH ABORTED — SERVER STATE CHANGED* before anything is downloaded. A package that is
   already installed at its target version is not drift: it is dropped from the plan (and its
   CVEs are still verified after the install). If every package is already at its target the
   execution ends as **ALREADY PATCHED** without touching the server. `sudo -n true` must
   work (no password prompt, ever).
2. **Download** each approved `.deb` once from its recorded URI into the local staging
   directory as `<file>.part`; it is renamed only after size and SHA256 match the plan.
3. **Transfer** with `scp` to `/tmp/<server name>` on the server and verify size + `sha256sum`.
   A failed copy is retried once; the exit code and stderr of every attempt are shown on the
   execution page. If the retry fails too, local and remote staging are cleaned up.
4. **Simulate** `apt-get -s install <explicit .deb paths>`; the simulation must install exactly
   the approved packages/versions from the staged files, with no removal or downgrade.
5. **Install** `sudo -n apt-get install -y <explicit .deb paths>`. APT runs with **no remote
   sources** (`Dir::Etc::SourceList=/dev/null`, `Dir::Etc::SourceParts=/dev/null`), so it
   cannot download anything or pull in other updates, plus `--no-remove`,
   `DEBIAN_FRONTEND=noninteractive` and `NEEDRESTART_MODE=l`.
6. **Verify** installed versions (Debian version comparison), `dpkg --audit`, each CVE against
   Canonical's fixed version, and `/run/reboot-required`.
7. **Clean up** local and remote staging (only after success and after history is saved).
8. **Reboot** (only after a verified patch): if `/run/reboot-required` exists on the server
   *now* and **Skip reboot** (a checkbox on the confirmation page, unchecked by default) was not
   checked, run `sudo -n reboot`, wait up to 10 minutes for SSH to answer with a new boot id,
   and record the post-reboot uptime and kernel. The reboot status (*Skipped*, *Not required*,
   *Rebooting*, *Rebooted*, *REBOOT FAILED*, *Not run* after a failed patch) is stored in the
   history; the patch result itself is not changed by the reboot.

On any other failure the staging files are kept and their paths shown; a new analysis is required
before trying again. A failed or interrupted install is never retried or rolled back; if the
connection drops, the server is inspected once more and the result is either proven or
recorded as *EXECUTION STATE UNKNOWN*. Each approved report can be executed once, and only
if it is the latest analysis for that server.

**Local Patch Download Directory** (Settings) defaults to `/tmp/${server_name}`. The template
must contain `${server_name}` and resolve to an absolute path (`~` is expanded); system
directories, `/tmp` itself and `..` are refused. Existing directories are only reused when
empty or when they hold EC2Patcher's own files; cleanup deletes only the files it staged.

### Patch All

The analysis run page has a **Patch All** button with a **Skip reboot** checkbox (unchecked by
default). It opens one confirmation page listing the eligible servers in queue order and the
servers that are **SKIPPED** with their reasons (unresolved plan, Canonical metadata
unavailable, nothing to install, …). A server that was analyzed again after this run is
patched from its **latest** analysis (linked on the confirmation page). After confirming, the servers are patched
**one at a time** with the per-server pipeline above (including the reboot step). The queue
**stops at the first failure** (a failed/unknown patch or a failed reboot); the remaining
servers are shown as **NOT RUN**. A cleanup warning does not stop the queue.

**History** lists every decision and execution with before/target/after versions, CVE
verification, reboot state and reboot result, cleanup result and errors.

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
- APT (`apt-get`, `apt-cache`) and the Ubuntu archive keyring
  (`/usr/share/keyrings/ubuntu-archive-keyring.gpg`) on the workstation, plus internet access
  to `archive.ubuntu.com` / `security.ubuntu.com` (or `ports.ubuntu.com` for arm64), for local
  APT resolution
- Internet access to `ubuntu.com` for per-CVE Canonical security metadata and to
  `services.nvd.nist.gov` for CVSS severity (optional: without it severities are Unknown)

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
| `--apt-state-dir` | `<data dir>/apt` | Private APT state for local resolution (also `$EC2PATCHER_APT_STATE_DIR`) |
| `--apt-max-age-hours` | `6` | Refresh the private APT lists when older than this; `0` = every run (also `$EC2PATCHER_APT_MAX_AGE_HOURS`) |
| `--no-browser` | off | Do not open a browser |

Stop the app with **Shutdown App** in the sidebar, or with Ctrl+C.

## Data location

| File | Default path (Linux) |
|---|---|
| SQLite database | `~/.local/share/ec2patcher/ec2patcher.db` |
| Log file | `~/.local/share/ec2patcher/ec2patcher.log` |
| NVD CVSS cache | `~/.cache/ec2patcher/nvd/` |
| Private APT state | `~/.local/share/ec2patcher/apt/<codename>-<arch>/` |

Other platforms use the equivalent [platformdirs](https://pypi.org/project/platformdirs/)
user data directory. The schema is created and migrated automatically on startup. A database
created by an earlier phase is upgraded in place (Phase 1.5 adds `server_tags`, Phase 2 adds the
analysis tables, Phase 2.2 adds the CVSS columns, Phase 3 adds settings and patch history, then
reboot results and Patch All queues);
existing servers, tags and reports are kept.

## Test and lint

```bash
.venv/bin/pytest
.venv/bin/ruff check . && .venv/bin/ruff format --check .
```

The tests mock `ssh`, `scp`, package downloads, NVD and the local `apt-get` / `apt-cache`
backend, and use fixture Canonical VEX data, NVD API responses and captured APT output, so they
never need a real EC2 server, a real PEM, internet access or package installs. Patch execution
runs against a scripted fake server.

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
    security_metadata.py  Canonical Security JSON API lookups and in-process memo
    server_state.py       remote facts + dpkg inventory (binary -> source mapping)
    debversion.py         Debian version comparison (dpkg semantics)
    cve_resolver.py       CVE status, APT candidate check, package plan, reboot expectation
    nvd.py                NVD CVE API 2.0 client + cache, CVSS selection (severity only)
    apt_planner.py        apt-cache / apt-get -s / --print-uris arguments and parsers
    local_apt.py          private per-release APT state on the workstation (update, queries)
    analysis_service.py   background analysis runs, persistence
    patch_service.py      Phase 3 approval/rejection, eligibility, execution pipeline
    patch_state.py        execution states and allowed transitions
    patch_remote.py       patch-time remote commands (staging, simulate, install, verify)
    downloader.py         approved .deb download + size/SHA256 verification
    staging.py            local/remote staging path rules and safe cleanup
  templates/         Jinja2 templates
  static/            CSS + a small amount of vanilla JS
tests/               pytest suite
```

## Security notes

- The app binds to `127.0.0.1` by default and rejects requests whose `Host` header isn't local.
  It also rejects cross-site POSTs, which guards against CSRF and DNS-rebinding attacks from
  websites open in your browser.
- The app never reads PEM contents. Subprocesses never use `shell=True`.
- The remote analysis command is a fixed string. Local APT commands are argument lists; package
  names and versions are validated against strict patterns. Analysis uses no `sudo`, no
  downloads, no installs.
- Patch commands only use validated `/tmp/<server>` paths and APT archive file names, and
  `sudo -n` (non-interactive). Only one patch execution (or Patch All queue) runs at a
  time. `sudo -n reboot` only when `/run/reboot-required` exists and Skip reboot is unchecked;
  no `apt upgrade`/`dist-upgrade`, no rollback. PEM paths and key material are never logged.
- Unexpected errors show a generic message in the GUI; details go to the log.
