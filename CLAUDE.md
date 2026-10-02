# CLAUDE.md

Local single-user GUI that analyzes Ubuntu EC2 servers for CVE fixes and patches them over SSH.
See README.md for features and behaviour.

## Stack

Python 3.10+, FastAPI + Jinja2 templates (server-rendered, minimal vanilla JS), SQLite
(stdlib `sqlite3`), uvicorn, openpyxl, cryptography (Fernet). System `ssh`/`scp` and local `apt-get`/`apt-cache`
via argument-list subprocesses. Lint/format: ruff (line length 100).

## Layout

- `src/ec2patcher/app.py` – all routes; `main.py` – CLI; `config.py` – paths/env vars
- `src/ec2patcher/database.py` – schema, `_MIGRATIONS`, `SCHEMA_VERSION`, all queries
- `src/ec2patcher/services/` – `analysis_service` (runs), `cve_resolver` (statuses/plan),
  `security_metadata` (Canonical), `nvd` (CVSS), `local_apt`/`apt_planner` (workstation APT),
  `patch_service`/`patch_remote`/`downloader`/`staging` (patching), `ssh_service`,
  `secret_store` (encrypted secrets, Fernet key file in the config dir)
- `src/ec2patcher/templates/`, `static/` – UI
- `tests/` – pytest; fixtures in `conftest.py`, `*_fixtures.py`, `tests/fixtures/`

## Commands (all must pass before handing back)

```bash
.venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q
.venv/bin/ruff check .
.venv/bin/ruff format --check .
```

Tests must never touch the network, real servers or the real APT/data dirs (conftest fakes
them); keep it that way.

## Migration rules

- Schema changes go in a **new** `_MIGRATIONS[n]` with `SCHEMA_VERSION = n`. One meaning per
  version number: never edit, reuse or renumber an existing migration (other branches and
  deployed databases already depend on them). If a branch collides, take the next free number.
- Every migration needs tests for a **fresh DB** (reaches the current version with the new
  schema) and the **full upgrade path** (previous version → new, and v1 → current) with
  existing data kept. Update hard-coded `SCHEMA_VERSION == n` assertions.

## Safety rules

- Analysis is **read-only**: no sudo, no downloads/installs/restarts on servers.
- Patching executes **only an approved plan** (explicit `.deb` files, verified size/SHA256),
  with `sudo -n` only. Never `apt upgrade` / `apt dist-upgrade` / `apt full-upgrade`, never
  remote APT sources during install, never rollback or automatic retry of an install.
- No `shell=True`; validate anything that reaches a command line.
- Reboot only after a verified patch, only if `/run/reboot-required`, never if Skip reboot.

## Secrets

Never commit secrets: no API keys (NVD_API_KEY comes from the env var or the encrypted
Settings value, never a file in the repo), PEM keys, the Fernet `secret.key`, hostnames/IPs of
real servers or real reports. Use placeholders in docs and fake values in tests.
Stored secrets (server passwords, NVD key) are Fernet-encrypted via
`services/secret_store`; they must never reach HTML, logs, argv, exports or error messages
(passwords go to sshpass via `SSHPASS` only).

## Workflow

One-way development: code is written here and tested at work against real servers; there is
no direct access to those systems. Fixes from work come back as handoff docs (symptoms, logs,
expected behaviour) — reproduce them as tests first, then fix. Don't commit or push unless
asked; git is handled separately.
