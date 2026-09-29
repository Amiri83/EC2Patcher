"""Shared Phase 2 test data: Canonical VEX documents, remote server output and APT output.

The VEX documents follow the exact structure of Canonical's OpenVEX files (see
fixtures/vex_real_CVE-2024-6387.json, a trimmed real document). The server is modelled on an
Ubuntu 24.04 (noble) EC2 instance running an AWS kernel. APT output formats were captured
from real apt 3.x runs (fixtures/apt_*_real.txt).
"""

import subprocess
from pathlib import Path

from ec2patcher.services.security_metadata import SecurityMetadata, parse_cve_document

FIXTURES = Path(__file__).parent / "fixtures"

FIXED_NOTE = (
    "This package (for the given release) was vulnerable, but an update has been uploaded "
    "and published."
)
NOT_FIX_NOTE = (
    "This package (for the given release) is vulnerable to the CVE, the problem is understood, "
    "but the Ubuntu Security Team decided to not fix it. "
)
MEDIUM_NOTE = "Ubuntu Security Team classified this CVE as of Medium priority."


def statement(cve, status, sources, binaries=(), **extra):
    """sources/binaries: iterables of (name, version, distro[, arch])."""
    products = [{"@id": f"pkg:deb/ubuntu/{n}@{v}?arch=source&distro={d}"} for n, v, d in sources]
    products += [{"@id": f"pkg:deb/ubuntu/{n}@{v}?arch={a}&distro={d}"} for n, v, d, a in binaries]
    stmt = {
        "vulnerability": {
            "@id": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "name": cve,
            "description": f"Test description for {cve}.",
            "aliases": [f"https://ubuntu.com/security/{cve}"],
        },
        "timestamp": "2026-09-01T00:00:00Z",
        "products": products,
        "status": status,
    }
    if status == "fixed":
        stmt["status_notes"] = FIXED_NOTE
    stmt.update(extra)
    return stmt


def vex_doc(cve, *statements, wrapped=False):
    header = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": f"https://github.com/canonical/ubuntu-security-notices/blob/main/vex/cve/2026/{cve}",
        "author": "Canonical Ltd.",
        "timestamp": "2026-09-20T10:00:00Z",
        "version": 3,
    }
    if wrapped:  # a handful of real documents use this layout
        return {"metadata": header, "statements": list(statements)}
    return {**header, "statements": list(statements)}


# The user's real report shape.
REAL_REPORT = {
    "ip-10-0-0-245": ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"],
    "ip-10-0-0-215": ["CVE-2026-63076"],
}

KERNEL_FIXED = "6.8.0-1024.26"

DOCS = [
    # openssl fixed in noble + jammy; the fixture server runs an older noble openssl.
    vex_doc(
        "CVE-2026-63076",
        statement(
            "CVE-2026-63076",
            "fixed",
            [("openssl", "3.0.13-0ubuntu3.6", "noble"), ("openssl", "3.0.2-0ubuntu1.20", "jammy")],
            [("libssl3t64", "3.0.13-0ubuntu3.6", "noble", "amd64")],
        ),
        statement(
            "CVE-2026-63076",
            "not_affected",
            [("openssl", "1.1.1f-1ubuntu2.24", "esm-infra/focal")],
            justification="vulnerable_code_not_present",
        ),
    ),
    # Kernel CVE: AWS kernel fixed in noble; other flavours listed too.
    vex_doc(
        "CVE-2026-54874",
        statement(
            "CVE-2026-54874",
            "fixed",
            [
                ("linux-aws", KERNEL_FIXED, "noble"),
                ("linux-signed-aws", KERNEL_FIXED, "noble"),
                ("linux", "6.8.0-85.85", "noble"),
                ("linux-gcp", "6.8.0-1040.42", "noble"),
            ],
        ),
        statement(
            "CVE-2026-54874",
            "affected",
            [("linux-azure", "6.8.0-1030.35", "noble")],
            status_notes=MEDIUM_NOTE,
        ),
    ),
    # Second openssl CVE (dedup: one package update fixes both) + curl not affected.
    vex_doc(
        "CVE-2026-63075",
        statement("CVE-2026-63075", "fixed", [("openssl", "3.0.13-0ubuntu3.5", "noble")]),
        statement(
            "CVE-2026-63075",
            "not_affected",
            [("curl", "8.5.0-2ubuntu10.6", "noble")],
            justification="vulnerable_code_not_present",
            impact_statement="This package (for the given release), while related...",
        ),
    ),
    vex_doc(
        "CVE-2026-10001",
        statement(
            "CVE-2026-10001",
            "under_investigation",
            [("sudo", "1.9.15p5-3ubuntu5", "noble")],
            status_notes=MEDIUM_NOTE,
        ),
    ),  # fmt: skip
    vex_doc(
        "CVE-2026-10002",
        statement(
            "CVE-2026-10002",
            "affected",
            [("vim", "2:9.1.0016-1ubuntu7.8", "noble")],
            action_statement=NOT_FIX_NOTE,
        ),
    ),  # fmt: skip
    vex_doc(
        "CVE-2026-10003",
        statement(
            "CVE-2026-10003", "fixed", [("ffmpeg", "7:6.1.1-3ubuntu5+esm2", "esm-apps/noble")]
        ),
        statement(
            "CVE-2026-10003",
            "affected",
            [("ffmpeg", "7:6.1.1-3ubuntu5", "noble")],
            action_statement="This package (for the given release) is no longer supported. "
            "Please upgrade your system.",
        ),
    ),  # fmt: skip
    vex_doc(
        "CVE-2026-10004",
        statement(
            "CVE-2026-10004",
            "affected",
            [("bash", "5.2.21-2ubuntu4", "noble")],
            status_notes=MEDIUM_NOTE,
        ),
    ),  # fmt: skip
    vex_doc(
        "CVE-2026-10005",
        statement("CVE-2026-10005", "fixed", [("nginx", "1.24.0-2ubuntu7.5", "noble")]),
    ),
    vex_doc(
        "CVE-2026-10006",
        statement("CVE-2026-10006", "fixed", [("bash", "5.2.21-2ubuntu3", "noble")]),
        wrapped=True,
    ),
    vex_doc(  # sudo tracked for jammy only; installed on the noble server -> needs evaluation
        "CVE-2026-10007",
        statement("CVE-2026-10007", "fixed", [("sudo", "1.9.9-1ubuntu2.5", "jammy")]),
    ),
    vex_doc(  # fixed version known, but the server's APT candidate is older
        "CVE-2026-10008",
        statement("CVE-2026-10008", "fixed", [("libxml2", "2.9.14+dfsg-1.3ubuntu3.5", "noble")]),
    ),
]

ALL_CVES = [d["statements"][0]["vulnerability"]["name"] for d in DOCS]


def as_api_document(doc):
    """Turn historical statement fixtures into Canonical Security JSON API replies."""
    statements = doc["statements"]
    cve = statements[0]["vulnerability"]["name"]
    packages = {}
    for statement in statements:
        old_status = statement["status"]
        note = " ".join(str(statement.get(k) or "") for k in ("status_notes", "action_statement"))
        priority = ""
        if "classified this CVE as of " in note:
            priority = note.split("classified this CVE as of ", 1)[1].split(" priority", 1)[0]
        status = {
            "fixed": "released",
            "not_affected": "not-affected",
            "under_investigation": "needs-triage",
            "affected": "needed",
        }[old_status]
        if "decided to not fix" in note or "no longer supported" in note:
            status = "ignored"
        for product in statement["products"]:
            purl = product["@id"]
            if "arch=source" not in purl:
                continue
            source = purl.split("/ubuntu/", 1)[1].split("@", 1)[0]
            version = purl.split("@", 1)[1].split("?", 1)[0]
            distro = purl.split("distro=", 1)[1]
            if "/" in distro:
                pocket, codename = distro.split("/", 1)
            else:
                pocket, codename = None, distro
            packages.setdefault(source, []).append(
                {
                    "release_codename": codename,
                    "status": status,
                    "pocket": pocket,
                    "description": version,
                    "priority": priority,
                }
            )
    return {
        "id": cve,
        "description": statements[0]["vulnerability"].get("description", ""),
        "packages": [
            {"name": source, "statuses": statuses} for source, statuses in packages.items()
        ],
    }


def parse_fixture_document(doc):
    api = as_api_document(doc)
    return parse_cve_document(api, api["id"])


def online_fetcher(docs=None, calls=None):
    replies = {api["id"]: api for api in map(as_api_document, DOCS if docs is None else docs)}

    def fetch(url):
        cve = url.rsplit("/", 1)[1].removesuffix(".json")
        if calls is not None:
            calls.append(url)
        if cve not in replies:
            from urllib.error import HTTPError

            raise HTTPError(url, 404, "Not Found", None, None)
        return replies[cve]

    return fetch


def failing_fetcher(message="Network error: [Errno -3] Temporary failure in name resolution"):
    def fetch(url):
        raise OSError(message)

    return fetch


def make_metadata(tmp_path: Path, docs=None) -> SecurityMetadata:
    return SecurityMetadata(fetcher=online_fetcher(docs))


# --- remote server output -----------------------------------------------------------

NOBLE_OS_RELEASE = """PRETTY_NAME="Ubuntu 24.04.3 LTS"
NAME="Ubuntu"
VERSION_ID="24.04"
VERSION="24.04.3 LTS (Noble Numbat)"
VERSION_CODENAME=noble
ID=ubuntu
ID_LIKE=debian
UBUNTU_CODENAME=noble"""

RUNNING_KERNEL = "6.8.0-1021-aws"

# binary, version, source, source version, arch, status
NOBLE_PACKAGES = [
    ("bash", "5.2.21-2ubuntu4", "bash", "5.2.21-2ubuntu4", "amd64", "ii "),
    ("curl", "8.5.0-2ubuntu10.6", "curl", "8.5.0-2ubuntu10.6", "amd64", "ii "),
    ("libcurl4t64:amd64", "8.5.0-2ubuntu10.6", "curl", "8.5.0-2ubuntu10.6", "amd64", "ii "),
    ("openssl", "3.0.13-0ubuntu3.4", "openssl", "3.0.13-0ubuntu3.4", "amd64", "ii "),
    ("libssl3t64:amd64", "3.0.13-0ubuntu3.4", "openssl", "3.0.13-0ubuntu3.4", "amd64", "ii "),
    ("sudo", "1.9.15p5-3ubuntu5", "sudo", "1.9.15p5-3ubuntu5", "amd64", "ii "),
    ("vim", "2:9.1.0016-1ubuntu7.8", "vim", "2:9.1.0016-1ubuntu7.8", "amd64", "ii "),
    ("libxml2:amd64", "2.9.14+dfsg-1.3ubuntu3.3", "libxml2", "2.9.14+dfsg-1.3ubuntu3.3", "amd64", "ii "),  # noqa: E501
    ("libavcodec60:amd64", "7:6.1.1-3ubuntu5", "ffmpeg", "7:6.1.1-3ubuntu5", "amd64", "ii "),
    (f"linux-image-{RUNNING_KERNEL}", "6.8.0-1021.23", "linux-signed-aws", "6.8.0-1021.23", "amd64", "ii "),  # noqa: E501
    (f"linux-modules-{RUNNING_KERNEL}", "6.8.0-1021.23", "linux-aws", "6.8.0-1021.23", "amd64", "ii "),  # noqa: E501
    ("linux-aws", "6.8.0.1021.23", "linux-meta-aws", "6.8.0.1021.23", "amd64", "ii "),
    ("linux-image-aws", "6.8.0.1021.23", "linux-meta-aws", "6.8.0.1021.23", "amd64", "ii "),
    ("nginx-common", "1.24.0-2ubuntu7.1", "nginx", "1.24.0-2ubuntu7.1", "all", "rc "),  # removed
]  # fmt: skip


def facts_output(
    packages=None,
    os_release=NOBLE_OS_RELEASE,
    arch="amd64",
    kernel=RUNNING_KERNEL,
    reboot="no",
    reboot_pkgs=(),
    apt_stamp=1790400000,
    now=1790460000,
    motd=True,
) -> str:
    packages = NOBLE_PACKAGES if packages is None else packages
    lines = []
    if motd:
        lines += ["Welcome to Ubuntu 24.04.3 LTS (GNU/Linux 6.8.0-1021-aws x86_64)", ""]
    lines += ["@@EC2P hostname", "ip-10-0-0-245", "@@EC2P os-release", os_release]
    lines += ["@@EC2P arch", arch, "@@EC2P kernel", kernel, "@@EC2P reboot", reboot, *reboot_pkgs]
    lines += ["@@EC2P apt-update-stamp"] + ([str(apt_stamp)] if apt_stamp else [])
    lines += ["@@EC2P apt-lists-mtime", str(apt_stamp or 1790000000), "@@EC2P now", str(now)]
    lines += ["@@EC2P dpkg"] + ["\t".join(p) for p in packages] + ["@@EC2P end"]
    return "\n".join(lines) + "\n"


def _policy(name, installed, candidate, origin):
    return (
        f"{name}:\n  Installed: {installed}\n  Candidate: {candidate}\n  Version table:\n"
        f"     {candidate} 500\n        500 {origin} amd64 Packages\n"
        f" *** {installed} 100\n        100 /var/lib/dpkg/status\n"
    )


SECURITY = "http://security.ubuntu.com/ubuntu noble-security/main"
UPDATES = "http://us-east-1.ec2.archive.ubuntu.com/ubuntu noble-updates/main"

# name -> (installed, candidate, source header for apt-cache show)
CANDIDATES = {
    "libssl3t64:amd64": ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6", "openssl", SECURITY),
    "openssl": ("3.0.13-0ubuntu3.4", "3.0.13-0ubuntu3.6", None, SECURITY),
    "linux-aws": ("6.8.0.1021.23", "6.8.0.1024.26", "linux-meta-aws", SECURITY),
    "linux-image-aws": ("6.8.0.1021.23", "6.8.0.1024.26", "linux-meta-aws", SECURITY),
    # libxml2: APT lists are stale, candidate is older than the fix.
    "libxml2:amd64": ("2.9.14+dfsg-1.3ubuntu3.3", "2.9.14+dfsg-1.3ubuntu3.4", None, UPDATES),
    # ffmpeg: no Ubuntu Pro on this server, candidate == installed
    "libavcodec60:amd64": ("7:6.1.1-3ubuntu5", "7:6.1.1-3ubuntu5", "ffmpeg", UPDATES),
}


def candidates_output(names) -> str:
    policy, show = [], []
    for name in names:
        if name not in CANDIDATES:
            continue
        installed, candidate, source, origin = CANDIDATES[name]
        policy.append(_policy(name.split(":")[0], installed, candidate, origin))
        record = [f"Package: {name.split(':')[0]}", "Architecture: amd64", f"Version: {candidate}"]
        if source:
            record.insert(1, f"Source: {source}")
        show.append("\n".join(record) + "\n")
    return (
        "@@EC2P policy\n" + "".join(policy) + "@@EC2P show\n" + "\n".join(show)
        + "@@EC2P reboot-hooks\n/var/lib/dpkg/info/libssl3t64:amd64.postinst\n@@EC2P end\n"
    )  # fmt: skip


NEW_IMAGE = "linux-image-6.8.0-1024-aws"
NEW_MODULES = "linux-modules-6.8.0-1024-aws"


def _deb_line(name, version, size, section="main", pool="o/openssl"):
    filename = f"{name}_{version.replace(':', '%3a')}_amd64.deb"
    uri = f"http://security.ubuntu.com/ubuntu/pool/{section}/{pool}/{filename}"
    return f"'{uri}' {filename} {size} SHA256:{'ab' * 32}"


PLAN_OUTPUT = (
    "\n".join(
        [
            "@@EC2P simulate",
            "NOTE: This is only a simulation!",
            "      apt-get needs root privileges for real execution.",
            "Inst libssl3t64 [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])",  # noqa: E501
            "Inst openssl [3.0.13-0ubuntu3.4] (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])",  # noqa: E501
            f"Inst {NEW_MODULES} (6.8.0-1024.26 Ubuntu:24.04/noble-security [amd64])",
            f"Inst {NEW_IMAGE} (6.8.0-1024.26 Ubuntu:24.04/noble-security [amd64])",
            "Inst linux-image-aws [6.8.0.1021.23] (6.8.0.1024.26 Ubuntu:24.04/noble-security [amd64])",  # noqa: E501
            "Inst linux-aws [6.8.0.1021.23] (6.8.0.1024.26 Ubuntu:24.04/noble-security [amd64])",
            "Conf libssl3t64 (3.0.13-0ubuntu3.6 Ubuntu:24.04/noble-security [amd64])",
            "@@EC2P simulate-rc",
            "0",
            "@@EC2P uris",
            _deb_line("libssl3t64", "3.0.13-0ubuntu3.6", 1940000),
            _deb_line("openssl", "3.0.13-0ubuntu3.6", 1003000),
            _deb_line(NEW_MODULES, "6.8.0-1024.26", 30500000, pool="l/linux-aws"),
            _deb_line(NEW_IMAGE, "6.8.0-1024.26", 14600000, pool="l/linux-signed-aws"),
            _deb_line("linux-image-aws", "6.8.0.1024.26", 2400, pool="l/linux-meta-aws"),
            _deb_line("linux-aws", "6.8.0.1024.26", 1700, pool="l/linux-meta-aws"),
            "@@EC2P uris-rc",
            "0",
            "@@EC2P end",
        ]
    )
    + "\n"
)


class ScriptedSSH:
    """Fake ssh runner answering by remote command type and target IP."""

    def __init__(self, facts=None, candidates=None, plan=None, failures=None):
        self.facts = facts or facts_output()
        self.candidates = candidates  # callable(names) -> str, or None for default
        self.plan = PLAN_OUTPUT if plan is None else plan
        self.failures = failures or {}  # ip -> (returncode, stderr) or exception
        self.calls: list[list[str]] = []

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        target, command = args[-2], args[-1]
        ip = target.split("@", 1)[1]
        failure = self.failures.get(ip)
        if isinstance(failure, BaseException):
            raise failure
        if failure:
            return subprocess.CompletedProcess(args, failure[0], "", failure[1])
        if "@@EC2P dpkg" in command:
            out = self.facts
        elif "apt-cache policy" in command:
            names = [
                n.strip("'")
                for n in command.split("apt-cache policy -- ")[1].split(" 2>&1")[0].split()
            ]
            out = (self.candidates or candidates_output)(names)
        elif "--print-uris" in command:
            out = self.plan
        else:
            raise AssertionError(f"unexpected remote command: {command}")
        return subprocess.CompletedProcess(args, 0, out, "")
