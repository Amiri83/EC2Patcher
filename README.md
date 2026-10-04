# EC2 Patcher

A small, local, single-user web GUI (FastAPI + Jinja2 + SQLite) for recurring security
patching of Ubuntu EC2 servers. You keep an inventory of servers, upload the security team's
CVE report, get a **read-only** per-server analysis with an exact package / `.deb` plan, and
then patch an approved plan on one server or on all eligible servers of an analysis
(**Patch All**), with an optional reboot afterwards.

EC2Patcher never runs `apt upgrade` / `apt dist-upgrade`: it installs only the exact `.deb`
files of a plan you approved.

## Workflow at a glance

1. **Servers**: add each server (name, IP, PEM path, optional tags) and run the SSH test.
2. **Reports**: pick or drop the CVE report JSON; it is uploaded and validated automatically.
3. **Analyze Report**: read-only analysis of every server in the report.
4. Review each **server report** (Severity, CVSS, Ubuntu priority, package plan, reboot
   expectation); export it to Excel if needed. **Re-analyze** or **Retry** where needed.
5. **Approve & Patch** one server, or **Patch All** for the whole analysis. Optionally tick
   **Skip reboot**.
6. **History** keeps every decision, execution, verification and reboot result.

## Target server requirements

- Ubuntu, reachable over SSH as the server's **SSH user** (per server, default `ubuntu`) with
  a PEM key (default; the PEM *path* is stored, its contents are never read, stored or logged)
  or with username + password (see below). Other operating systems are detected and listed as
  *OS not supported yet*.
- **Passwordless sudo** for that user for patching: every privileged command uses `sudo -n`,
  and patching aborts if `sudo -n true` fails. Analysis needs no sudo at all.
- `dpkg`, `apt-get`, `sha256sum` and write access to `/tmp` (the standard Ubuntu image has
  them).

## Features

### Servers and tags

- Add, edit, delete and SSH-test servers. **Clear All Servers** requires typing
  `DELETE SERVERS`.
- Names may contain letters, digits, `.`, `_` and `-` and are unique regardless of case. CVE
  reports are always matched by **name**.
- Optional key/value **tags** per server (e.g. `display_name = Billing API`, `env = prod`):
  up to 50 per server, keys unique per server (case-insensitive). `display_name` is shown in
  reports but never used for matching.
- Each server has an **SSH user** (default `ubuntu`, e.g. `ec2-user` on Amazon Linux) used for
  every ssh/scp to it. It must be a plain POSIX user name (`[a-z_][a-z0-9_.-]*`, max 32).
- **SSH test** runs `ssh -i <pem> <user>@<ip>` with `BatchMode=yes`, `ConnectTimeout=10` and a
  30 s overall limit, and shows hostname, OS release and architecture or a short error. New host
  keys are accepted on first connect (`accept-new`); a changed host key is an error.
- **Login type** per server (dropdown on the server form): **PEM key** (default) or
  **username + password**. The password is **stored per server, encrypted** (Fernet, see
  [Secrets at rest](#secrets-at-rest)); it is never shown, logged or exported, and the form
  field is always empty: when editing, leave it empty to keep the stored password. Switching a
  server to PEM, deleting it, Clear All Servers or Reset Database removes its password.
  Password login runs `sshpass -e ssh|scp ...`; the password reaches sshpass only through the
  `SSHPASS` environment variable of the child process, never the command line. Install
  `sshpass` on the workstation (`sudo apt install sshpass`); without it the connection fails
  with a clear message. Analysis or patching of a password server without a usable stored
  password is refused with a clear message. `sudo` on the server must still be passwordless
  (`sudo -n`).

### Report upload

On **Reports**, choosing or dropping a `.json` file uploads it immediately (no extra click; a
plain *Upload Report* button is shown without JavaScript). Max 1 MiB; structural validation
only. The latest accepted report is kept; a failed upload does not replace it.

```json
{
  "app-prod-01": ["CVE-2026-12345", "CVE-2026-67890"],
  "database-prod-01": ["CVE-2026-22222"]
}
```

Each key must be a configured server name (an unknown server rejects the whole report); each
value is an array of `CVE-YYYY-NNNN…` strings (case-insensitive, normalized and de-duplicated).

### Analysis (read-only)

**Analyze Report** starts a background run; the run page refreshes itself and shows each
server as *Waiting*, *Analyzing*, *Complete*, *Failed* (with the reason) or *Not supported*.
Servers are analyzed one after another; one failure never affects the others.

- **On the server**: one fixed read-only command as the server's SSH user, **without sudo**:
  hostname, `/etc/os-release`, architecture, running kernel, `/run/reboot-required(.pkgs)`,
  `dpkg-query` (binary → source package and versions) and `dpkg --audit`. Nothing is
  downloaded, copied, installed or restarted.
- **OS detection**: the OS is taken from `/etc/os-release`; everything OS-specific (inventory,
  Canonical lookups, APT planning, install, reboot check) sits behind an `OsAdapter`
  (`services/os_adapters/`). Ubuntu is the only adapter: any other OS is shown as
  `OS not supported yet: <name> <version>` (not a failure, never patchable).
- **On the workstation**: APT candidates and the `.deb` plan are resolved against a private
  APT state per release and architecture (`<data dir>/apt/<codename>-<arch>/`, pockets
  `<codename>`, `-updates`, `-security`). Every `apt-get` / `apt-cache` call overrides
  `Dir::State`, `Dir::Cache` and `Dir::Etc`, so the workstation's own APT is never used or
  changed. `apt-get -s` and `--print-uris` give exact versions, URIs, sizes and SHA256 without
  downloading anything.
- **Canonical** (`https://ubuntu.com/security/cves/<CVE>.json`) decides applicability, fixed
  version and status, per source package and Ubuntu release, with Debian version comparison.
  Kernel CVEs are checked against the *running* kernel.
- **NVD** (CVE API 2.0) supplies only the CVSS **Severity** (Critical/High/Medium/Low/Unknown)
  and score; it never changes a finding's status or plan. Canonical's priority is shown as
  **Ubuntu Priority**.
- A server with unconfigured/half-installed packages (`dpkg --audit`) gets a blocker
  ("run sudo dpkg --configure -a") instead of a plan. Packages already at or above their
  target version are never planned (shown as an "already at target" warning).
- Findings are grouped into **Action required**, **Investigate** and **No action**. Anything
  that cannot be decided is shown as such, never as safe.
- Every run is stored as a snapshot (report, server facts, findings, plan); older runs stay
  viewable. **Export to Excel** builds an `.xlsx` (Summary, CVE Findings, Package Plan) from
  that snapshot only, without any network or SSH access.

**Re-analyze and Retry**

- **Retry failed lookups** (run page): re-runs only the Canonical lookups that failed in that
  run.
- **Retry these CVEs** (server report, Investigate bucket): fetches those CVEs again and
  re-analyzes the server.
- **Re-analyze** (server report): analyzes the server again, fetching all of its CVEs from
  Canonical again.

### Patching one server

Each server report has **Reject** and **Approve & Patch** (after a confirmation page with a
**Skip reboot** checkbox, unchecked by default). Only the latest analysis of a server can be
executed, and each approved analysis only once. The pipeline stops at the first failing step:

1. **Revalidate** hostname, release, architecture and installed versions against the analysis
   (drift → *PATCH ABORTED — SERVER STATE CHANGED*); check `sudo -n true`. Packages already
   at target are dropped; if nothing is left the result is **ALREADY PATCHED**.
2. **Download** each approved `.deb` from its recorded URI; keep it only if size and SHA256
   match the plan.
3. **Transfer** with `scp` to `/tmp/<server name>` and verify size + `sha256sum` (one retry).
4. **Simulate** `apt-get -s install <explicit .deb paths>`: must install exactly the approved
   packages/versions, with no removal or downgrade.
5. **Install** `sudo -n apt-get install -y <explicit .deb paths>` with no remote APT sources,
   `--no-remove`, `DEBIAN_FRONTEND=noninteractive`, `NEEDRESTART_MODE=l`.
6. **Verify** installed versions, `dpkg --audit`, each CVE against Canonical's fixed version,
   and `/run/reboot-required`.
7. **Clean up** local and remote staging.
8. **Reboot**, only after a verified patch, only if `/run/reboot-required` exists and **Skip
   reboot** is unchecked: `sudo -n reboot`, wait up to 10 minutes for a new boot id, record
   uptime and kernel. The reboot result is recorded separately from the patch result.

A failed or interrupted install is never retried or rolled back; if the connection drops the
server is inspected once more and the result is proven or recorded as *EXECUTION STATE
UNKNOWN*. A new analysis is required before trying again.

### Patch All

The analysis run page has **Patch All** with a **Skip reboot** checkbox. The confirmation page
lists the eligible servers in order and the **SKIPPED** ones with their reasons. A server
analyzed again after this run is patched from its latest analysis. Servers are patched **one
at a time** with the pipeline above; the queue **stops at the first failure** and the rest are
shown as **NOT RUN**. Only one patch execution or queue runs at a time.

### Settings

- **Local Patch Download Directory**: template, default `/tmp/${server_name}`; must contain
  `${server_name}` and resolve to a safe absolute path.
- **Logging**: the **Log directory** (default: the per-user log directory from platformdirs, or
  `$EC2PATCHER_LOG_DIR`) and the current log file path. The directory is created if needed and
  must be writable, or it is not saved. Logs rotate at 5 MB, keeping 5 old files.
- **Security Data**: Canonical and NVD cache details. **Clear Security Cache** empties the
  in-memory lookup state and both caches (Canonical `cve_metadata_cache`, NVD `nvd_cache`), so
  the next analysis queries Canonical and NVD again.
- **Reset Database**: type `RESET` to remove all stored data (refused while an analysis or
  patch is running).

### Caching and NVD API key

Both caches live in the application SQLite database; failed lookups are never cached and a
cache error never fails a lookup.

- **Canonical** (`cve_metadata_cache`): reused for 24 h (1 h while a release is under
  investigation); older entries are refreshed and used as a marked fallback when ubuntu.com is
  unreachable.
- **NVD** (`nvd_cache`): raw CVSS metrics per CVE, reused for **30 days**; older entries are
  refreshed and used as a *stale cache* fallback when NVD is unreachable. Without any data the
  severity is **Unknown**. (The old on-disk NVD cache under `~/.cache/ec2patcher/nvd/` is no
  longer read or written and can be deleted.)

NVD requests are spaced 6 s apart (public limit). With an API key they are spaced 0.6 s apart.
Enter the key on **Settings → NVD API Key** (stored encrypted; shown only as its last 4
characters, with **Replace** / **Clear**), or provide it through the environment — never in a
file in this repository:

```bash
export NVD_API_KEY=...   # your own key; it is sent only in the apiKey request header
```
Request a free key at https://nvd.nist.gov/developers/request-an-api-key.

A key saved in Settings **overrides** `NVD_API_KEY`; Clear falls back to the environment. The
key is never logged, exported or shown in full. The Pre-Patch Analysis pages show only its state
and source: *NVD API key: not set*, *set (not used yet)*, *in use* (green, after a successful
keyed request in this app session) or *NVD API key rejected* (red, NVD answered HTTP 403), each
followed by *from Settings* or *from NVD_API_KEY env var*. If the saved key cannot be decrypted
the badge is red and asks to enter it again in Settings (no key is sent until then).

### Secrets at rest

Server passwords and the Settings NVD API key are encrypted with Fernet (`cryptography`). The
key file is `~/.config/ec2patcher/secret.key` (or `$EC2PATCHER_CONFIG_DIR/secret.key`), created
with mode `0600` on first use and never stored in the database or the repository. If it is
missing or does not match, nothing fails silently: the Servers / Settings pages, Test SSH,
analysis and patching show a clear error asking you to enter the secret again (it is then
encrypted with the current key). Back up the key file together with the database if you move
them to another machine.

## Requirements (workstation)

- Python 3.10+
- OpenSSH client (`ssh`, `scp`) on `PATH`
- APT (`apt-get`, `apt-cache`) and `/usr/share/keyrings/ubuntu-archive-keyring.gpg`
- Internet access to the Ubuntu archive (`archive.ubuntu.com` / `security.ubuntu.com`, or
  `ports.ubuntu.com` for arm64), `ubuntu.com` and `services.nvd.nist.gov` (optional: without it
  severities are Unknown). `HTTPS_PROXY` / `NO_PROXY` are honoured.

## Install

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"     # or without [dev] if you don't run tests
```

## Run

```bash
.venv/bin/ec2patcher                  # or: .venv/bin/python -m ec2patcher
```

Open <http://127.0.0.1:8080/> (a browser opens automatically when a desktop session is
available). Stop with **Shutdown App** in the sidebar or Ctrl+C.

| Option | Default | Description |
|---|---|---|
| `--host` | `127.0.0.1` | Bind address (no authentication: keep it local) |
| `--port` | `8080` | Port |
| `--data-dir` | per-user data dir | Database and log location (also `$EC2PATCHER_DATA_DIR`) |
| `--apt-state-dir` | `<data dir>/apt` | Private APT state (also `$EC2PATCHER_APT_STATE_DIR`) |
| `--apt-max-age-hours` | `6` | Refresh the private APT lists when older; `0` = every run (also `$EC2PATCHER_APT_MAX_AGE_HOURS`) |
| `--no-browser` | off | Do not open a browser |

Other environment variables: `NVD_API_KEY` (a key saved in Settings overrides it),
`EC2PATCHER_CONFIG_DIR` (location of the secret key file), `EC2PATCHER_LOG_DIR` (default log directory),
`EC2PATCHER_CANONICAL_TIMEOUT_SECONDS` (20),
`EC2PATCHER_CANONICAL_CACHE_TTL_HOURS` (24), `EC2PATCHER_CANONICAL_BREAKER_THRESHOLD` (3).

## Data location (Linux defaults)

| What | Path |
|---|---|
| SQLite database (incl. Canonical and NVD caches) | `~/.local/share/ec2patcher/ec2patcher.db` |
| Secret key file (encrypts stored passwords / NVD key; mode 0600) | `~/.config/ec2patcher/secret.key` |
| Log file (rotating, 5 × 5 MB; directory configurable in Settings) | `~/.local/state/ec2patcher/log/ec2patcher.log` |
| Private APT state | `~/.local/share/ec2patcher/apt/<codename>-<arch>/` |

The schema is created and migrated automatically on startup (`PRAGMA user_version`); existing
data is kept. Run one EC2Patcher process per database.

## Test and lint

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

The tests mock `ssh`, `scp`, downloads, Canonical, NVD and the local APT backend; they never
need a real server, PEM key, internet access or package installs.

### Integration tests (local containers, no AWS)

`scripts/test-targets/` holds two SSH targets with key-only auth on localhost: Ubuntu 24.04
(user `ubuntu`, port 2201) and Amazon Linux 2023 (user `ec2-user`, port 2202). The key pair is
generated at runtime into `scripts/test-targets/.keys/` (git-ignored). Docker runs via `sudo`
(set `DOCKER=docker` to change that).

```bash
sh scripts/test-targets/up.sh                 # build + start, generate the key on first use
.venv/bin/python -m pytest -q -m integration  # deselected by default
sh scripts/test-targets/down.sh
```

Overrides: `EC2P_IT_HOST`, `EC2P_IT_UBUNTU_PORT`, `EC2P_IT_AMAZON_PORT`, `EC2P_IT_KEY`.

## Security notes

- Binds to `127.0.0.1` by default; requests with a non-local `Host` header and cross-site POSTs
  are rejected (CSRF / DNS rebinding).
- Subprocesses never use `shell=True`; the remote analysis command is fixed; package names,
  versions and paths are validated against strict patterns.
- Analysis uses no sudo and changes nothing. Patching uses `sudo -n` only for the sudo check,
  the `apt-get` simulation/install of the explicit `.deb` files and the optional reboot.
- PEM contents are never read; the NVD API key and SSH passwords are stored only encrypted
  (key file outside the database, mode 0600) and never appear in HTML, logs, exports, error
  messages or command lines (passwords reach sshpass via `SSHPASS` only). Unexpected errors
  show a generic message in the GUI; details go to the log.
