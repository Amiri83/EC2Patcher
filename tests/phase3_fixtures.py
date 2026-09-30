"""Phase 3 test doubles: a stateful fake Ubuntu server (ssh + scp) and a fake HTTP fetcher.

Nothing here touches a real server, the network or the real /tmp of a remote machine: remote
directories live in a dict, local staging goes to pytest's tmp_path.
"""

import hashlib
import re
import subprocess

from phase2_fixtures import NOBLE_OS_RELEASE, candidates_output, facts_output

from ec2patcher.models import Server
from ec2patcher.services import cve_resolver as cr
from ec2patcher.services.downloader import DownloadError
from ec2patcher.services.staging import MARKER

SERVER = "ip-10-143-76-245"
IP = "10.143.76.245"
SEC = "http://security.ubuntu.com/ubuntu/pool/main"
KERNEL_FIXED = "6.8.0-1024.26"
IMAGE = "linux-image-6.8.0-1024-aws"
MODULES = "linux-modules-6.8.0-1024-aws"

# (package, arch, before, target, installed source, source version, pool, cves, dependency)
PLAN = [
    ("libssl3t64", "amd64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6", "openssl",
     "3.0.13-0ubuntu3.6", "o/openssl", ["CVE-2026-63075", "CVE-2026-63076"], False),
    ("openssl", "amd64", "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6", "openssl",
     "3.0.13-0ubuntu3.6", "o/openssl", ["CVE-2026-63075", "CVE-2026-63076"], False),
    ("linux-aws", "amd64", "6.8.0.1021.23", "6.8.0.1024.26", "linux-meta-aws",
     "6.8.0.1024.26", "l/linux-meta-aws", ["CVE-2026-54874"], False),
    ("linux-image-aws", "amd64", "6.8.0.1021.23", "6.8.0.1024.26", "linux-meta-aws",
     "6.8.0.1024.26", "l/linux-meta-aws", ["CVE-2026-54874"], False),
    (IMAGE, "amd64", None, KERNEL_FIXED, "linux-signed-aws", KERNEL_FIXED,
     "l/linux-signed-aws", ["CVE-2026-54874"], True),
    (MODULES, "amd64", None, KERNEL_FIXED, "linux-aws", KERNEL_FIXED, "l/linux-aws",
     ["CVE-2026-54874"], True),
]  # fmt: skip

INITIAL_PACKAGES = [
    ("bash", "5.2.21-2ubuntu4", "bash", "5.2.21-2ubuntu4", "amd64", "ii "),
    ("curl", "8.5.0-2ubuntu10.6", "curl", "8.5.0-2ubuntu10.6", "amd64", "ii "),
    ("openssl", "3.0.13-0ubuntu3.4", "openssl", "3.0.13-0ubuntu3.4", "amd64", "ii "),
    ("libssl3t64:amd64", "3.0.13-0ubuntu3.4", "openssl", "3.0.13-0ubuntu3.4", "amd64", "ii "),
    ("linux-image-6.8.0-1021-aws", "6.8.0-1021.23", "linux-signed-aws", "6.8.0-1021.23", "amd64", "ii "),  # noqa: E501
    ("linux-modules-6.8.0-1021-aws", "6.8.0-1021.23", "linux-aws", "6.8.0-1021.23", "amd64", "ii "),  # noqa: E501
    ("linux-aws", "6.8.0.1021.23", "linux-meta-aws", "6.8.0.1021.23", "amd64", "ii "),
    ("linux-image-aws", "6.8.0.1021.23", "linux-meta-aws", "6.8.0.1021.23", "amd64", "ii "),
]  # fmt: skip


def deb_name(package, version, arch="amd64"):
    return f"{package}_{version.replace(':', '%3a')}_{arch}.deb"


def deb_content(filename: str) -> bytes:
    return (f"!<arch>\nfake debian package {filename}\n" * 40).encode()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def plan_uri(package, target, pool):
    return f"{SEC}/{pool}/{deb_name(package, target)}"


def deb_index():
    """filename -> (package, arch, version, source, source_version)."""
    return {deb_name(p, t): (p, a, t, src, sv) for p, a, _, t, src, sv, _, _, _ in PLAN}


def contents():
    return {
        plan_uri(p, t, pool): deb_content(deb_name(p, t)) for p, _, _, t, _, _, pool, _, _ in PLAN
    }


def plan_entries(plan=PLAN):
    entries = []
    for package, arch, before, target, src, _, pool, cves, dep in plan:
        filename = deb_name(package, target, arch)
        data = deb_content(filename)
        entries.append(
            cr.PlanEntry(
                package=package, architecture=arch, current_version=before,
                target_version=target, source=src if before else None, deb_filename=filename,
                uri=plan_uri(package, target, pool), size=len(data),
                checksum=f"SHA256:{sha(data)}", is_dependency=dep,
                reboot_impact="Reboot expected (new kernel)" if package == IMAGE else
                "No reboot expected",
                requests_reboot=package == IMAGE, cves=list(cves),
            )
        )  # fmt: skip
    return entries


def findings():
    return [
        cr.Finding("CVE-2026-63076", "openssl", cr.PATCH_AVAILABLE, "old",
                   "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6",
                   binaries=["libssl3t64:amd64", "openssl"]),
        cr.Finding("CVE-2026-63075", "openssl", cr.PATCH_AVAILABLE, "old",
                   "3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.5",
                   binaries=["libssl3t64:amd64", "openssl"]),
        cr.Finding("CVE-2026-63075", "curl", cr.NOT_AFFECTED, "not affected"),
        cr.Finding("CVE-2026-54874", "linux-aws", cr.PATCH_AVAILABLE, "old", "6.8.0-1021.23",
                   KERNEL_FIXED, binaries=["linux-modules-6.8.0-1021-aws"], is_kernel=True),
        cr.Finding("CVE-2026-54874", "linux-signed-aws", cr.PATCH_AVAILABLE, "old",
                   "6.8.0-1021.23", KERNEL_FIXED, binaries=["linux-image-6.8.0-1021-aws"],
                   is_kernel=True),
        cr.Finding("CVE-2026-10004", "bash", cr.NO_FIX_PUBLISHED, "no fix yet",
                   "5.2.21-2ubuntu4"),
    ]  # fmt: skip


def make_analysis(db, server: Server, plan=None, finding_list=None, display="Billing API", **extra):
    """Store a complete analysis snapshot for ``server`` directly (no ssh)."""
    db.save_report("report.json", {server.name: ["CVE-2026-63076"]}, "VALID")
    report = db.get_latest_report()
    run_id = db.create_analysis_run(report, [(server.name, server, display)])
    analysis = db.get_analysis_run(run_id).servers[0]
    _save_results(db, analysis.id, plan, finding_list, **extra)
    return db.get_server_analysis(analysis.id)


def make_run(db, servers: list[Server], overrides: dict | None = None):
    """One analysis run over several servers (queue order = list order), stored directly.

    ``overrides``: server name -> make_analysis-style keyword arguments (plan, finding_list,
    status, ...) for that server.
    """
    overrides = overrides or {}
    db.save_report("report.json", {s.name: ["CVE-2026-63076"] for s in servers}, "VALID")
    run_id = db.create_analysis_run(db.get_latest_report(), [(s.name, s, None) for s in servers])
    for analysis in db.get_analysis_run(run_id).servers:
        _save_results(db, analysis.id, **overrides.get(analysis.server_name, {}))
    db.update_analysis_run(run_id, status="completed", completed_at="2026-09-27T10:05:00+00:00")
    return db.get_analysis_run(run_id, details=True)


def _save_results(db, analysis_id, plan=None, finding_list=None, **extra):
    fields = {
        "status": "complete",
        "completed_at": "2026-09-27T10:00:00+00:00",
        "remote_hostname": SERVER,
        "os_pretty_name": "Ubuntu 24.04.3 LTS",
        "os_version_id": "24.04",
        "os_codename": "noble",
        "architecture": "amd64",
        "running_kernel": "6.8.0-1021-aws",
        "expected_reboot": True,
        "expected_reboot_reason": f"{IMAGE}: Reboot expected (new kernel)",
        **extra,
    }
    db.save_server_results(
        analysis_id,
        findings() if finding_list is None else finding_list,
        plan_entries() if plan is None else plan,
        **fields,
    )


class FakeFetcher:
    def __init__(self, data=None):
        self.data = contents() if data is None else data
        self.calls: list[str] = []
        self.fail: dict[str, BaseException] = {}
        self.override: dict[str, bytes] = {}

    def __call__(self, url, out, max_bytes, timeout):
        self.calls.append(url)
        if url in self.fail:
            raise self.fail[url]
        data = self.override.get(url, self.data.get(url))
        if data is None:
            raise OSError("HTTP Error 404: Not Found")
        if len(data) > max_bytes:
            out.write(data[:max_bytes])
            raise DownloadError(f"Server sent more than the expected {max_bytes} bytes.")
        out.write(data)


def _done(args, stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess(args, rc, stdout, stderr)


class FakeUbuntu:
    """A scripted Ubuntu 24.04 server. Package state changes only through 'apt-get install'."""

    def __init__(self, packages=None, plan_output=None):
        self.packages = {}
        for row in packages or INITIAL_PACKAGES:
            name, version, source, sv, arch, status = row
            self.packages[(name.split(":")[0], arch)] = [version, source, sv, status]
        self.hostname = SERVER
        self.os_release = NOBLE_OS_RELEASE
        self.arch = "amd64"
        self.dirs: dict[str, dict[str, bytes]] = {}
        self.foreign: set[str] = set()
        self.symlinks: set[str] = set()
        self.sudo = True
        self.reboot_required = False
        self.reboot_pkgs: list[str] = []
        self.debs = deb_index()
        self.plan_output = plan_output
        self.calls: list[tuple[str, object]] = []  # (op, args)
        # behaviour knobs
        self.unreachable = False
        self.scp_fail = False
        self.scp_failures = 0  # the next N scp calls die mid-copy (truncated remote file)
        self.corrupt_transfer = False
        self.sim_rc = 0
        self.sim_extra: list[str] = []
        self.sim_old_override: dict[str, str] = {}
        self.sim_origin: dict[str, str] = {}  # package -> origin printed by apt
        self.install_mode = "ok"  # ok | fail | disconnect | disconnect-none | timeout
        self.post_fail = False
        self.post_fail_after_install = False
        self.audit: list[str] = []
        self.busy = False
        self.install_versions: dict[str, str] = {}  # package -> version actually installed
        self.cleanup_fail = False
        self.skip: set[str] = set()  # packages apt 'installs' without effect
        # reboot: ok | refused (sudo denied) | never-returns (SSH stays down) | ignored
        # (command accepted but the server keeps running on the same boot)
        self.reboot_mode = "ok"
        self.down_polls = 2  # SSH attempts that fail while the server restarts
        self.boot_id = "boot-1"
        self.kernel = "6.8.0-1021-aws"
        self.uptime = "up 3 weeks, 2 days"
        self._down = 0

    # --- helpers -------------------------------------------------------------------------

    @property
    def ops(self) -> list[str]:
        return [op for op, _ in self.calls]

    def facts(self) -> str:
        rows = []
        for (name, arch), (version, source, sv, status) in sorted(self.packages.items()):
            full = f"{name}:{arch}" if name.startswith("lib") else name
            rows.append((full, version, source, sv, arch, status))
        return facts_output(packages=rows, os_release=self.os_release, arch=self.arch)

    def installed(self, name, arch="amd64"):
        row = self.packages.get((name, arch))
        return row[0] if row else None

    def preinstall(self, names=None):
        """Install PLAN packages (all, or ``names``) at their target version out of band."""
        for package, arch, _, target, source, sv, _, _, _ in PLAN:
            if names is None or package in names:
                self.packages[(package, arch)] = [target, source, sv, "ii "]

    # --- dispatch ------------------------------------------------------------------------

    def __call__(self, args, **kwargs):
        if args[0] == "scp":
            return self._scp(args)
        assert args[0] == "ssh" and "shell" not in kwargs
        command = args[-1]
        m = re.match(r"echo '@@EC2P (\S+)'", command)
        op = m.group(1) if m else "?"
        if op == "simulate" and "--print-uris" in command:
            op = "plan"
        if op == "dpkg":
            op = "post"
        self.calls.append((op, command))
        if self._down:  # rebooting
            self._down -= 1
            return _done(args, rc=255, stderr="ssh: connect to host port 22: Connection refused")
        if self.unreachable:
            return _done(
                args, rc=255, stderr="ssh: connect to host 10.143.76.245 port 22: timed out"
            )
        handler = getattr(self, f"_op_{op.replace('-', '_')}", None)
        if handler is None:
            raise AssertionError(f"unexpected remote command: {command}")
        return handler(args, command)

    def _dir(self, command):
        return re.search(r"/tmp/[A-Za-z0-9._-]+", command).group(0)

    def _files(self, command):
        return re.findall(r"/tmp/[A-Za-z0-9._-]+/([^\s'/]+\.deb)", command)

    def _op_hostname(self, args, command):
        return _done(args, self.facts())

    def _op_policy(self, args, command):
        names = [
            n.strip("'") for n in command.split("apt-cache policy -- ")[1].split(" 2>&1")[0].split()
        ]
        return _done(args, candidates_output(names))

    def _op_plan(self, args, command):
        return _done(args, self.plan_output)

    def _op_sudo(self, args, command):
        return _done(args, f"@@EC2P sudo\n{'ok' if self.sudo else 'denied'}\n@@EC2P end\n")

    def _op_stage(self, args, command):
        d = self._dir(command)
        if d in self.symlinks:
            status = "symlink"
        elif d in self.foreign:
            status = "foreign-owner"
        elif d in self.dirs:
            entries = "\n".join(sorted(self.dirs[d]))
            status = f"exists\n@@EC2P entries\n{entries}" if entries else "exists\n@@EC2P entries"
        else:
            self.dirs[d] = {}
            status = "created"
        return _done(args, f"@@EC2P stage\n{status}\n@@EC2P end\n")

    def _op_mark(self, args, command):
        self.dirs[self._dir(command)][MARKER] = b""
        return _done(args, "@@EC2P mark\nok\n@@EC2P end\n")

    def _scp(self, args):
        self.calls.append(("scp", args))
        if self.scp_fail or self.unreachable:
            return _done(args, rc=1, stderr="scp: Connection closed")
        split = args.index("--")
        files, dest = args[split + 1 : -1], args[-1]
        d = dest.split(":", 1)[1].rstrip("/")
        if self.scp_failures:
            self.scp_failures -= 1
            for path in files:
                with open(path, "rb") as fh:
                    self.dirs[d][path.rsplit("/", 1)[1]] = fh.read()[:10]
            stderr = "client_loop: send disconnect: Broken pipe\nlost connection"
            return _done(args, rc=1, stderr=stderr)
        for path in files:
            with open(path, "rb") as fh:
                data = fh.read()
            if self.corrupt_transfer:
                data = data[:-1] + b"X"
            self.dirs[d][path.rsplit("/", 1)[1]] = data
        return _done(args)

    def _op_stat(self, args, command):
        d = self._dir(command)
        stat_lines, sha_lines = [], []
        for name in self._files(command):
            data = self.dirs.get(d, {}).get(name)
            if data is None:
                stat_lines.append(f"stat: cannot statx '{d}/{name}': No such file or directory")
                continue
            stat_lines.append(f"regular file|{len(data)}|{d}/{name}")
            sha_lines.append(f"{sha(data)}  {d}/{name}")
        out = ["@@EC2P stat", *stat_lines, "@@EC2P sha256", *sha_lines, "@@EC2P end"]
        return _done(args, "\n".join(out) + "\n")

    def _op_simulate(self, args, command):
        plain = command.replace("'", "")
        assert "sudo -n" in plain and " -s " in plain and "SourceList=/dev/null" in plain
        lines = ["NOTE: This is only a simulation!"]
        for name in self._files(command):
            package, arch, version, _, _ = self.debs[name]
            old = self.sim_old_override.get(package, self.installed(package, arch))
            old_part = f"[{old}] " if old else ""
            lines.append(
                f"Inst {package} {old_part}({version} {self.sim_origin.get(package, 'local-deb')} "
                f"[{arch}])"
            )
        lines += self.sim_extra
        out = ["@@EC2P simulate", *lines, "@@EC2P rc", str(self.sim_rc), "@@EC2P end"]
        return _done(args, "\n".join(out) + "\n")

    def _apply(self, names):
        for name in names:
            package, arch, version, source, sv = self.debs[name]
            if package in self.skip:
                continue
            version = self.install_versions.get(package, version)
            self.packages[(package, arch)] = [version, source, sv, "ii "]
            if package.startswith("linux-image-6"):
                self.reboot_required = True
                self.reboot_pkgs = [package]

    def _op_install(self, args, command):
        names = self._files(command)
        if self.install_mode == "ok":
            self._apply(names)
            out = ["@@EC2P install", "Setting up openssl ...", "@@EC2P rc", "0", "@@EC2P end"]
        elif self.install_mode == "fail":
            self._apply(names[:1])
            out = [
                "@@EC2P install",
                "dpkg: error processing package openssl (--configure):",
                "E: Sub-process /usr/bin/dpkg returned an error code (1)",
                "@@EC2P rc",
                "100",
                "@@EC2P end",
            ]
        elif self.install_mode in ("disconnect", "disconnect-none"):
            if self.install_mode == "disconnect":
                self._apply(names)
            return _done(
                args, "@@EC2P install\nUnpacking ...\n", 255,
                "Connection to 10.143.76.245 closed by remote host.",
            )  # fmt: skip
        elif self.install_mode == "timeout":
            raise subprocess.TimeoutExpired(args, 1800)
        if self.post_fail_after_install:
            self.post_fail = True
        return _done(args, "\n".join(out) + "\n")

    def _op_post(self, args, command):
        if self.post_fail:
            return _done(args, rc=255, stderr="ssh: connect to host port 22: Connection refused")
        names = re.search(r"-- (.*?) 2>/dev/null", command).group(1).replace("'", "").split()
        rows = []
        for (name, arch), (version, source, sv, status) in sorted(self.packages.items()):
            if name in names:
                rows.append("\t".join([name, version, source, sv, arch, status]))
        reboot = ["yes", *self.reboot_pkgs] if self.reboot_required else ["no"]
        out = [
            "@@EC2P dpkg", *rows, "@@EC2P audit", *self.audit,
            "@@EC2P audit-rc", "0", "@@EC2P reboot", *reboot,
            "@@EC2P busy", "yes" if self.busy else "no", "@@EC2P end",
        ]  # fmt: skip
        return _done(args, "\n".join(out) + "\n")

    @property
    def reboots(self) -> int:
        return self.ops.count("reboot-now")

    def _op_reboot_check(self, args, command):
        flag = "yes" if self.reboot_required else "no"
        out = f"@@EC2P reboot-check\n{flag}\n@@EC2P boot-id\n{self.boot_id}\n@@EC2P end\n"
        return _done(args, out)

    def _op_reboot_now(self, args, command):
        assert "sudo -n reboot" in command
        if self.reboot_mode == "refused":
            out = "@@EC2P reboot-now\nsudo: a password is required\n@@EC2P rc\n1\n@@EC2P end\n"
            return _done(args, out)
        if self.reboot_mode == "ok":
            self.boot_id = f"boot-{self.reboots + 1}"
            self.reboot_required, self.reboot_pkgs = False, []
            if (IMAGE, "amd64") in self.packages:
                self.kernel = "6.8.0-1024-aws"
            self.uptime = "up 1 minute"
            self._down = self.down_polls
        elif self.reboot_mode == "never-returns":
            self._down = 10**9
        return _done(args, "@@EC2P reboot-now\n", 255, "Connection to 10.143.76.245 closed.")

    def _op_boot_state(self, args, command):
        out = (
            f"@@EC2P boot-state\n{self.boot_id}\n@@EC2P uptime\n{self.uptime}\n"
            f"@@EC2P kernel\n{self.kernel}\n@@EC2P end\n"
        )
        return _done(args, out)

    def _op_cleanup(self, args, command):
        if self.cleanup_fail:
            return _done(args, rc=255, stderr="Connection closed by remote host")
        d = self._dir(command)
        files = self.dirs.get(d)
        if files is not None:
            for name in [*self._files(command), MARKER]:
                files.pop(name, None)
            if files:
                entries = "\n".join(sorted(files))
                return _done(args, f"@@EC2P cleanup\nkept\n{entries}\n@@EC2P end\n")
            del self.dirs[d]
        return _done(args, "@@EC2P cleanup\nremoved\n@@EC2P end\n")


class FakeClock:
    """Monotonic clock + sleep for the reboot wait: sleeping only advances fake time."""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


class Fleet:
    """Several FakeUbuntu servers behind one ssh/scp runner, routed by ``ubuntu@<ip>``.

    ``log`` records (ip, op) across all servers in call order.
    """

    def __init__(self, ips):
        self.servers = {ip: FakeUbuntu() for ip in ips}
        self.log: list[tuple[str, str]] = []

    def __getitem__(self, ip) -> FakeUbuntu:
        return self.servers[ip]

    def __call__(self, args, **kwargs):
        target = next(a for a in args if a.startswith("ubuntu@"))
        ip = target.split("@", 1)[1].split(":", 1)[0]
        fake = self.servers[ip]
        before = len(fake.calls)
        result = fake(args, **kwargs)
        self.log += [(ip, op) for op, _ in fake.calls[before:]]
        return result

    def ips_in_order(self) -> list[str]:
        """Servers in the order they were first contacted."""
        return list(dict.fromkeys(ip for ip, _ in self.log))


def analysis_plan_output() -> str:
    """Phase 2 'apt-get -s / --print-uris' output matching PLAN with real checksums."""
    inst, uris = [], []
    for package, arch, before, target, _, _, pool, _, _ in PLAN:
        old = f"[{before}] " if before else ""
        inst.append(f"Inst {package} {old}({target} Ubuntu:24.04/noble-security [{arch}])")
        name = deb_name(package, target)
        data = deb_content(name)
        uris.append(f"'{plan_uri(package, target, pool)}' {name} {len(data)} SHA256:{sha(data)}")
    return "\n".join(
        ["@@EC2P simulate", *inst, "@@EC2P simulate-rc", "0", "@@EC2P uris", *uris,
         "@@EC2P uris-rc", "0", "@@EC2P end"]
    ) + "\n"  # fmt: skip
