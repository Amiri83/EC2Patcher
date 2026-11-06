# EC2 Patcher

A small, local, single-user web GUI (FastAPI + Jinja2 + SQLite) for recurring security
patching of EC2 servers. You keep an inventory of servers, upload the security team's CVE
report, get a **read-only** per-server analysis, and then patch an approved plan on one server
or on all eligible servers of an analysis (**Patch All**), with an optional reboot afterwards.

- **Ubuntu**: analysis (Canonical security data) with an exact package / `.deb` plan, and
  patching of the approved plan.
- **Amazon Linux 2023**: read-only analysis (Amazon's ALAS advisories); patching is not
  supported yet.
- The OS is **detected automatically** from `/etc/os-release`; any other OS is listed as
  *OS not supported yet*.

```bash
pipx install ec2patcher
ec2patcher
```

EC2Patcher never runs `apt upgrade` / `apt dist-upgrade`: it installs only the exact `.deb`
files of a plan you approved.

## Workflow at a glance

1. **Servers**: add each server (name, IP, SSH user, login type: PEM key or password,
   optional tags) and run the SSH test.
2. **Reports**: pick or drop the CVE report JSON; it is uploaded and validated automatically.
3. **Analyze Report**: read-only analysis of every server in the report.
4. Review each **server report** (Severity, CVSS, Ubuntu priority, package plan, reboot
   expectation); export it to Excel if needed. **Re-analyze** or **Retry** where needed.
5. **Approve & Patch** one server, or **Patch All** for the whole analysis. Optionally tick
   **Skip reboot**.
6. **History** keeps every decision, execution, verification and reboot result.

## Target server requirements

- Ubuntu (analysis + patching) or Amazon Linux 2023 (analysis only), reachable over SSH as
  the server's **SSH user** (per server, default `ubuntu`; `ec2-user` on Amazon Linux) with a
  PEM key (default; the PEM *path* is stored, its contents are never read, stored or logged)
  or with username + password (see below). Other operating systems (including end-of-life
  Amazon Linux 2) are detected and listed as *OS not supported yet* / *OS not supported*.
- **Passwordless sudo** for that user for patching: every privileged command uses `sudo -n`,
  and patching aborts if `sudo -n true` fails. Analysis needs no sudo at all.
- Ubuntu: `dpkg`, `apt-get`, `sha256sum` and write access to `/tmp` (the standard Ubuntu image
  has them). Amazon Linux 2023: `rpm` (read-only queries; `needs-restarting` from
  `dnf-utils` is optional and used only for the reboot status).

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
- **Test connection** runs `ssh -i <pem> <user>@<ip>` with `BatchMode=yes`, `ConnectTimeout=10`
  and a 30 s overall limit, and shows the transport, hostname, OS release, architecture and
  `uname`, or a short error. New host
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
- **Connection type** per server: **SSH (direct)** or **SSH over SSM**, see
  [Connection types](#connection-types).
- **Clone** (button on each server) opens the Add form pre-filled with the source's SSH user, login
  type, connection type, AWS profile, region and all tags. Name, IP and PEM file are empty and
  required; so is the instance ID when the clone connects over SSM (PEM applies to key login only,
  and direct SSH has no instance ID). A stored password stays usable by the clone without being
  shown: leave the field empty to give the new server its own encrypted copy, or type another.
  Saving creates a new server; the source is not changed.

### Connection types

Direct SSH is the default. Choose **SSH over SSM** where only AWS Systems Manager is reachable.
Only the transport changes: analysis, patching, verification and cleanup use the same ssh and
scp commands and the same PEM or password login, plus this option:

```text
-o ProxyCommand=aws ssm start-session --target <instance-id> --document-name AWS-StartSSHSession
   --parameters portNumber=<port> --profile <profile> --region <region>
```

**Prerequisites on the workstation**

- AWS CLI v2 (`aws`) on `PATH`.
- The Session Manager plugin (`session-manager-plugin`) on `PATH` or managed by the app, see
  [below](#session-manager-plugin).
- A working profile. For SSO, sign in first: `aws sso login --profile example`.
- On the server: `sshd` running, the SSM agent connected, and your login still valid. SSM only
  carries the connection; ssh still authenticates with the server's PEM key or password.

**Settings**

- **Settings → Connection** holds the default connection type, AWS profile and region. AWS
  credentials stay in the AWS CLI configuration; EC2 Patcher only stores the profile name.
- A server follows the default until it gets its own connection type on the server form, where
  the profile and region can also be overridden.
- **Save** changes the servers that follow the default. **Apply to all servers** also clears the
  connection type, AWS profile and region set on individual servers. Manual instance IDs are
  kept, because each one identifies a single server.
- **AWS profile** is a dropdown on both forms, read from the AWS CLI config (`~/.aws/config`, or
  `AWS_CONFIG_FILE`) and never written to: `[default]` is `default`, `[profile x]` is `x`, and
  other sections such as `[sso-session y]` are ignored. A missing or broken file leaves the list
  empty and says why.
- **AWS region** is a dropdown of the commercial AWS regions (a fixed list; no AWS call). Choosing
  a profile selects its region from the config, if it has one, unless you already picked a
  region. In Settings, a default profile with a region preselects it when no region is saved.
- **Other…**, the last option of both, reveals a text input for a manual value. A manual region
  must look like `us-east-1` (`^[a-z]{2}(-[a-z]+)+-\d$`). Other… left empty is refused instead of
  saved as something else, and a saved value that is not in the list shows under Other…
- On the server form the empty choice means the default from Settings.
- `GET /settings/aws-options` returns both lists as JSON, with a `reason` when the config cannot
  be used.

#### Session Manager plugin

The app looks for `session-manager-plugin` in `<data dir>/bin` (by default
`~/.local/share/ec2patcher/bin`) first and then on `PATH`. The aws CLI, directly and as the
ProxyCommand of ssh and scp, runs with that directory first on its `PATH`.

If the plugin is missing, **Settings → Connection → Install SSM plugin** installs it without sudo
and changes nothing outside the data directory:

1. It downloads the official Ubuntu package for this machine's architecture from AWS
   (`https://s3.amazonaws.com/session-manager-downloads/plugin/latest/ubuntu_64bit/session-manager-plugin.deb`,
   or `ubuntu_arm64`).
2. AWS publishes no checksum, so it verifies the detached GPG signature (`.deb.sig`) against the
   signing key in the AWS documentation, using a throwaway keyring. A bad or missing signature
   stops the install. If `gpg` is not installed, this step is skipped and the result says so.
3. It checks that the file is a `dpkg-deb`-readable package named `session-manager-plugin` for
   the right architecture.
4. It unpacks the package with `dpkg-deb -x` into a temporary directory (no maintainer scripts run
   and no dpkg state changes), and copies only the program to `<data dir>/bin` once it has run
   `--version` successfully.

A failed install leaves an existing plugin in place and reports why: no network, download failed,
not a `.deb`, `dpkg-deb` missing, bad signature or wrong architecture. A plugin installed this way
can be refreshed with **Update SSM plugin**; a plugin found on `PATH` is left to you.

**Status badge**

**Settings → Connection** shows the plugin version and where it was found, the AWS CLI version and
whether the default profile works: **Profile OK**, or **SSO expired** with the
`aws sso login --profile example` command to run. The checks load after the page, and **Check
now** runs them again.

**Instance ID**

- For a server named `ip-a-b-c-d` (with or without a domain), EC2 Patcher looks up the instance
  with `aws ec2 describe-instances`, filtered on `private-ip-address` = `a.b.c.d`. Any other
  name uses the server's IPv4 address.
- The result is cached in SQLite per private IP, profile and region. When SSM reports that the
  instance is not connected, the cached ID is dropped and looked up again next time. **Test
  connection** always looks it up again.
- The **Instance ID** field on the server form is a manual override and always wins. Use it when
  the lookup finds no instance or several, each of which is reported on that server.
- The Servers page shows each SSM server's instance ID and whether it was resolved or set
  manually. **Resolve instance ID** looks it up now; a failed lookup shows a short reason there.
  The server form also shows the resolved ID.

**Preflight and errors**

- Before connecting, each analysis run and patch execution checks that `aws` and
  `session-manager-plugin` are installed, that `aws sts get-caller-identity` works for the
  profile and region, and that the instance ID is known. Each failure has its own message (missing
  CLI, missing plugin, expired SSO, unknown profile, bad region, instance not found). An analysis
  run checks each profile and region once. Direct SSH servers skip all of this.
- An expired SSO session is reported as ``run `aws sso login --profile example` ``, not as a raw
  ssh error, including when it expires during a run. A failed preflight only fails the servers
  that use SSM; nothing is downloaded or changed on them.
- When a connection fails because SSM reports the instance as not connected, EC2 Patcher finds out
  why with read-only calls using the same profile and region (`aws sts get-caller-identity`,
  `aws ec2 describe-instances`, `aws ssm describe-instance-information`; 10 s each):
  - not found: `Instance i-0123456789abcdef0 not found in profile example / region us-east-1.
    Wrong account or region?`
  - stopped: says the instance is stopped (other states, such as terminated, are named too)
  - running but not in SSM: the SSM agent / instance role message

  Expired credentials skip the EC2 and SSM calls and show the `aws sso login` hint. If a lookup
  itself fails (denied, no network), the message gives the reason from AWS. Successful connections
  and direct SSH never run these calls.

**Testing and logs**

- **Test connection** on the Servers page and the server form runs `uname` (plus hostname, OS
  and architecture) over the chosen transport. The form tests the values typed, without saving.
- The transport of each server is written to the log and shown on the analysis run, the server
  report and the patch execution, for example
  `SSH over SSM (i-0123456789abcdef0, profile example, region us-east-1)`.

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

### Paste import of a security list

**Reports → Paste it as it is** takes the list as raw text, exactly as received: a chat table
(`|`, `·`, bullets, non-breaking spaces) or plain lines, wrapped anywhere. Each record is
comma-separated CVE IDs, then a host (`ip-10-0-0-1` or `ip-10-0-0-1.us-east-1.compute.internal`),
then a title like `Ubuntu Security Notification for example-package Vulnerabilities (USN-0000-1)`.
A new record starts at each run of CVE IDs; other columns and text are ignored, and a missing USN or
title is fine. Records are de-duplicated on host, CVE and USN.

**Preview** lists each record with its host, the saved server it matches (by name, else private
IP), the CVE count and USNs. A host with no saved server, or a private IP several servers share, is
flagged *unknown*; CVEs with no host in the text are dropped and listed. Nothing is stored yet.

**Confirm and Load** generates the report JSON above from the matched records, makes it the latest
report (**Download JSON** gives the same file, which can be uploaded again) and adds the rows to the
patch report. Unknown hosts are left out: add the server and paste the list again.

### Patch report

**Patch Report** (`/patch-report`) has one row per server and CVE: hostname, server and tags, CVE,
USN, package, title, Ubuntu priority (only if an analysis supplied one), status, package version
before and after, imported at, patched at, run ID, error, and the source, KEV, EPSS and failure reason
of the [CVE resolver](#cve-resolver). Status is one of:

| Status | Meaning |
| --- | --- |
| `pending` | Listed or found still open. |
| `patched` | Verified by a patch (with *Patched at*), or found already fixed by an analysis (without). |
| `failed` | The patch did not finish or was not verified; see Error. Stays until a patch succeeds or an analysis finds the CVE fixed. |
| `not-affected` | Canonical says not affected, or the package is not installed. |
| `reboot-required` | Patched, but the server still needs a reboot. |

Rows come from the paste import and are kept up to date by every analysis and patch execution; an
analysis of an uploaded report adds rows too (without USN or imported date). They outlive a deleted
server and follow a renamed one. Filters (server, status, USN, CVE, exact date or date range, on the
imported or patched day) are URL parameters and apply to the per-server summary and the export.

**Export .xlsx** downloads the filtered rows: a `Details` sheet with the same columns and a `Summary`
sheet with the counts per server, both with an autofilter and a frozen header.

### Analysis (read-only)

**Analyze Report** starts a background run; the run page refreshes itself and shows each
server as *Waiting*, *Analyzing*, *Complete*, *Failed* (with the reason) or *Not supported*.
Servers are analyzed one after another; one failure never affects the others.

- **On the server**: one fixed read-only command as the server's SSH user, **without sudo**:
  hostname, `/etc/os-release`, architecture, running kernel, `/run/reboot-required(.pkgs)`,
  `dpkg-query` (binary → source package and versions) and `dpkg --audit`. Nothing is
  downloaded, copied, installed or restarted.
- **OS detection**: the OS is taken from `/etc/os-release`; everything OS-specific (inventory,
  security data lookups, planning, install, reboot check) sits behind an `OsAdapter`
  (`services/os_adapters/`). Adapters: **Ubuntu** (analysis + patching) and **Amazon Linux
  2023** (analysis only). For Amazon Linux a second fixed read-only command collects the `rpm`
  inventory and the dnf releasever. Any other OS is shown as
  `OS not supported yet: <name> <version>` (not a failure, never patchable).
- **On the workstation**: APT candidates and the `.deb` plan are resolved against a private
  APT state per release and architecture (`<data dir>/apt/<codename>-<arch>/`, pockets
  `<codename>`, `-updates`, `-security`). Every `apt-get` / `apt-cache` call overrides
  `Dir::State`, `Dir::Cache` and `Dir::Etc`, so the workstation's own APT is never used or
  changed. `apt-get -s` and `--print-uris` give exact versions, URIs, sizes and SHA256 without
  downloading anything.
- **Canonical's data** decides applicability, fixed version and status, per source package and
  Ubuntu release, with Debian version comparison. It comes from the first source of the
  [resolver](#cve-resolver) that answers. Kernel CVEs are checked against the *running* kernel.
- **Amazon Linux 2023**: the repository `updateinfo.xml` (ALAS advisories) of the server's
  releasever and of the latest release is fetched on the workstation (via
  `cdn.amazonlinux.com` mirror lists) and compared with the installed rpm versions (EVR
  comparison). Statuses: patch available, fix only in a newer releasever, already fixed,
  package not installed, or no advisory (investigate). No plan is built and the server is
  never patchable (*Patching not supported yet for Amazon Linux 2023*).
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

#### CVE resolver

Needs no configuration. Each Ubuntu CVE is resolved by the first source that answers, in this order:

| # | Source (as shown in reports) | What it is |
| --- | --- | --- |
| 1 | `oval` | Canonical's OVAL feed (`security-metadata.canonical.com/oval/com.ubuntu.<codename>.cve.oval.xml.bz2`), one file per release found on the run's servers, stored in SQLite, refreshed after 24 h. A corrupt or truncated download is discarded and the previous copy stays in use. CVEs are then answered locally, without a request per CVE. |
| 2 | `notices` | USNs from `ubuntu.com/security/notices.json`: paged, stored, refreshed after 24 h. The first download may span several runs (each gives it up to 2 minutes). Also supplies the USN and title of the report: a CVE in several USNs keeps them all, and the report shows the one for the server's release, then the latest, then the highest number. |
| 3 | `changelog` | `changelog.Debian.gz` of the package's candidate `.deb` on `security.ubuntu.com` (`ports.ubuntu.com` for arm64). The oldest entry mentioning the CVE is the fix version. Bounded per run, one read per package, and only for packages already linked to the CVE (pasted list, other releases, USNs). |
| 4 | `cve-json` | The per-CVE `ubuntu.com/security/cves/<CVE>.json`, as a last resort, with a 5 s timeout. |

When a run starts, every source (and NVD, KEV, EPSS) is probed in parallel with one small request.
The progress panel shows one line per source; a blocked one is skipped for that run, with its reason
recorded, while data already stored from it is still used. Circuit breakers are per source and
endpoint, half-open with a doubling backoff and held in memory: a blocked `ubuntu.com` never disables
`security.ubuntu.com`, NVD, KEV or EPSS.

**Unresolved CVEs** are summed up as `Unresolved: N (reason: count, ...)`, each reason naming the
source that failed. They do not block the resolved plan: patching one server or Patch All asks for an
explicit confirmation of how many CVEs stay unresolved. An analysis error (a required package mapping
failed) still blocks.

**Priority only, never the status**: CISA's KEV catalogue (one file, cached 24 h) and FIRST's EPSS
scores (batches of 50 CVEs, cached 24 h) join the NVD CVSS severity. They are best-effort and get at
most 20 s per server; a failure only leaves the value empty.

**Columns**: `Source`, `KEV` (yes/no) and `EPSS` (the score) are on the findings of the server report
and the patch report; those two and the `.xlsx` sheets (`CVE Findings`, `Details`) also give the
`Failure Reason` of unresolved CVEs.

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

### Live progress, cancel and the step timeout

Analysis runs and patch runs write each step to the `run_events` table as they go. **Show
progress** on the run page opens a drawer (it also opens by itself when a run starts) with:

- the step list per server (spinner, check or cross, elapsed time, the current step in bold), and
  a progress bar per server and overall (servers and CVEs done / total);
- for a failed step, the real error text and a hint by cause (SSM, expired AWS SSO session with
  its `aws sso login --profile <profile>`, SSH login); never a traceback or a secret;
- a log tail that follows the run, with **Pause**;
- **Hide**, or Escape: the run keeps going and a small badge with the done / total count reopens
  the drawer. The open and paused state survives a page refresh while the run is going;
- **Cancel**, after a confirmation.

Analysis steps: resolve instance ID, SSM check, open SSH/SCP, detect OS/release, list installed
packages, map CVEs to packages, Canonical/NVD/Amazon lookups (each CVE as `CVE-2000-0001 (3 of
12)`, then the cache hits, misses and API calls), compute fix versions, then done or failed. Patch
runs share the first two and then follow the pipeline above. Without JavaScript the pages keep
their automatic refresh and show no drawer.

**Events endpoint**: `GET /runs/<run>/events?after=<last id>` answers JSON: `events` (`id`, `ts`,
`server`, `phase`, `phase_label`, `message`, `level`, `duration_ms`, `hint`), `next` (pass it as
`after`), `more`, `status`, `done`, `cancelled`, `cancel_requested`, `started_at`, `finished_at`,
`servers`, `servers_done`, `servers_total`, `cves_done`, `cves_total` and `phases`. `<run>` is an
analysis run (`12`), a single patch execution (`patch-12`) or a Patch All queue (`queue-3`); a
patch execution of a queue reports to its queue. An unknown run answers 404 with a JSON error and
a bad `after` (not a whole number, or negative) answers 422.

**Cancel**: `POST /runs/<run>/cancel` records the request in the database, so it survives a
restart; the run stops after its current step and ends as `cancelled`, not failed. Finished servers
keep their results and the others are marked cancelled. Cancelling a finished run, or twice, is a
no-op that says so. Patching is stricter, as it is never left half done: a cancel is honoured only
before the install starts, and after that the install is finished and verified, then the server is
**not rebooted** and no further server of a queue is patched. A cancelled execution keeps its
staging files and needs a new analysis, like a failed one.

**Step timeout**: Settings > Run progress, in seconds, 10 to 3600, default 300. In an analysis a
blocking call that takes longer (the SSM checks, opening SSH and listing packages, one CVE lookup,
one APT resolution) shows an error naming the step and the timeout, fails that server, and the run
moves to the next server. Each CVE lookup has its own limit, so a long CVE list is not cut off
while it makes progress. Commands keep any shorter limit of their own (the 90 s of the facts
command). When patching the timeout only shortens the commands before the install; scp, the install,
its verification and the reboot keep their own limits, and Patch All still stops at the first
failed server.

### Settings

- **Run progress**: the per-step timeout (see
  [Live progress, cancel and the step timeout](#live-progress-cancel-and-the-step-timeout)).
- **Caches** (top of the page): one badge per cache (*NVD cache: <N> CVEs, oldest <age>, TTL
  <ttl>*, same for Canonical and Amazon updateinfo; blue when the latest analysis answered
  lookups from it, gray when unused or empty), the **Cache TTL** of each cache and **Clear
  Security Cache**, which empties the caches (`nvd_cache`, `cve_metadata_cache`,
  `amazon_updateinfo_cache`), the stored OVAL, USN, KEV and EPSS data and the in-memory lookup state. TTLs are entered as hours (`24h`)
  or days (`30d`), between 1 hour and 365 days, and stored in the database. Changing a TTL
  deletes nothing; expired entries are refreshed on their next lookup. The same badges appear
  next to the NVD API key badge on the Pre-Patch Analysis pages and link to this section.
- **Connection**: default connection type, AWS profile and region (see
  [Connection types](#connection-types)).
- **Local Patch Download Directory**: template, default `/tmp/${server_name}`; must contain
  `${server_name}` and resolve to a safe absolute path.
- **Logging**: the **Log directory** (default: the per-user log directory from platformdirs, or
  `$EC2PATCHER_LOG_DIR`) and the current log file path. The directory is created if needed and
  must be writable, or it is not saved. Logs rotate at 5 MB, keeping 5 old files.
- **Security Data**: Canonical request settings (timeout, pacing, retries, proxy).
- **Reset Database**: type `RESET` to remove all stored data (refused while an analysis or
  patch is running).

### Caching and NVD API key

All caches live in the application SQLite database; failed lookups are never cached and a
cache error never fails a lookup. The TTLs below are the defaults (**Settings → Caches**; a
saved Canonical TTL also overrides `EC2PATCHER_CANONICAL_CACHE_TTL_HOURS`). Each analysis run
records, per cache, how many lookups came from the cache and how many were live (*NVD: x from
cache / y live*, shown on the run page and the server report; re-analyses and retries add to
it).

- **Canonical** (`cve_metadata_cache`): reused for 24 h (1 h while a release is under
  investigation); older entries are refreshed and used as a marked fallback when ubuntu.com is
  unreachable.
- **OVAL, USN notices, KEV, EPSS** (`oval_cve_packages`, `usn_notices`, `kev_cves`, `epss_scores`,
  state in `source_feeds`): reused for 24 h, a fixed TTL; **Clear Security Cache** empties them too.
  See [CVE resolver](#cve-resolver).
- **Amazon updateinfo** (`amazon_updateinfo_cache`): per repository, reused for 24 h.
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
key is never logged, exported or shown in full. Saving a key, and the **Test key** button, send
one keyed request to NVD right away (cached CVSS lookups send none). The result and its time are
kept in the settings table (never the key itself) and updated by every keyed lookup, so they
survive restarts. The Pre-Patch Analysis pages show only the state and source: *NVD API key: not
set*, *unknown* (not checked yet, or NVD could not be reached), *valid (checked <time>)* (green,
HTTP 200) or *NVD API key rejected* (red, HTTP 403, or HTTP 404 with NVD's invalid-apiKey
message), each followed by *from Settings (DB)* or *from NVD_API_KEY env var* whenever a key is
configured. For *unknown* the reason (HTTP status or network error, or *not checked yet*) is in
the badge tooltip and the Settings notice; HTTP 429 / 5xx is retried once (after Retry-After)
before a check ends as unknown. At start the app checks the key again in the background if its
last check is unknown or older than 24 h. A rejected key never
marks a CVE as unknown to NVD and is never cached. If the saved key cannot be decrypted the badge
is red and asks to enter it again in Settings (no key is sent until then).

### Secrets at rest

Server passwords and the Settings NVD API key are encrypted with Fernet (`cryptography`). The
key file is `~/.config/ec2patcher/secret.key` (or `$EC2PATCHER_CONFIG_DIR/secret.key`), created
with mode `0600` on first use and never stored in the database or the repository. If it is
missing or does not match, nothing fails silently: the Servers / Settings pages, Test connection,
analysis and patching show a clear error asking you to enter the secret again (it is then
encrypted with the current key). Back up the key file together with the database if you move
them to another machine.

## Requirements (workstation)

- Python 3.10+
- OpenSSH client (`ssh`, `scp`) on `PATH`
- APT (`apt-get`, `apt-cache`) and `/usr/share/keyrings/ubuntu-archive-keyring.gpg`
- `sshpass` only for servers with password login (`sudo apt install sshpass`)
- AWS CLI v2 and `session-manager-plugin` only for servers using
  [SSH over SSM](#connection-types)
- Internet access to the Ubuntu archive (`archive.ubuntu.com` / `security.ubuntu.com`, or
  `ports.ubuntu.com` for arm64), `security-metadata.canonical.com`, `ubuntu.com`,
  `cdn.amazonlinux.com` (Amazon Linux servers), and optionally `services.nvd.nist.gov`, `www.cisa.gov`
  and `api.first.org` (without them severity, KEV and EPSS stay empty). A blocked source is skipped,
  see [CVE resolver](#cve-resolver). `HTTPS_PROXY` / `NO_PROXY` are honoured.

## Install

With [pipx](https://pipx.pypa.io/) (recommended; installs the `ec2patcher` command in its own
virtual environment):

```bash
pipx install ec2patcher                                           # from PyPI
pipx install git+https://github.com/Amiri83/EC2Patcher.git        # latest main from GitHub
pipx upgrade ec2patcher                                           # later updates
```

From a checkout, for development:

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"     # or without [dev] if you don't run tests
```

## Run

```bash
ec2patcher                            # from a checkout: .venv/bin/ec2patcher or .venv/bin/python -m ec2patcher
ec2patcher --version
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
| `--version` | | Print the version and exit |

Other environment variables: `NVD_API_KEY` (a key saved in Settings overrides it),
`EC2PATCHER_CONFIG_DIR` (location of the secret key file), `EC2PATCHER_LOG_DIR` (default log directory),
`EC2PATCHER_CANONICAL_TIMEOUT_SECONDS` (5),
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

GitHub Actions (`.github/workflows/tests.yml`) runs ruff, the test suite (without integration
tests) and a package build check on every pull request.

## Release

The version lives only in `pyproject.toml` (`ec2patcher --version` reads the installed
metadata). To release:

1. Bump `version` in `pyproject.toml` and merge it to `main`.
2. Check locally: `.venv/bin/python -m build && .venv/bin/twine check dist/*`.
3. Push a tag `v<version>` (e.g. `v1.0.0`). `.github/workflows/publish.yml` checks that the
   tag matches the version, runs the tests, builds the sdist + wheel and publishes them to
   PyPI with **Trusted Publishing** (OIDC, environment `pypi`): no API token is stored in the
   repository or in GitHub secrets. The trusted publisher must be configured once on PyPI for
   this repository and workflow.

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
- The Fernet key file lives in the config directory, never in the package, the database or
  this repository; the built wheel and sdist contain no secrets, keys or server data.

## License

MIT, see [LICENSE](https://github.com/Amiri83/EC2Patcher/blob/main/LICENSE).
