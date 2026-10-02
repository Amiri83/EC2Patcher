"""Shared Amazon Linux 2023 test data: facts command output and repository metadata.

The XML follows the structure of the real AL2023 ``repodata/repomd.xml`` and
``updateinfo.xml`` (createrepo / updateinfo schema); advisory ids, CVEs and versions are
made up. The fake CDN answers the mirror list -> repomd.xml -> updateinfo chain per
releasever without any network access.
"""

import gzip
from xml.sax.saxutils import quoteattr

from ec2patcher.services import amazon_updateinfo

RELEASEVER = "2023.6.20241010"
NEWER = "2023.7.20250512"  # what "latest" points at in these fixtures
KERNEL_RUNNING = "6.1.112-122.189.amzn2023.x86_64"

AL2023_OS_RELEASE = """NAME="Amazon Linux"
VERSION="2023"
ID="amzn"
ID_LIKE="fedora"
VERSION_ID="2023"
PLATFORM_ID="platform:al2023"
PRETTY_NAME="Amazon Linux 2023.6.20241010"
ANSI_COLOR="0;33"
CPE_NAME="cpe:2.3:o:amazon:amazon_linux:2023"
HOME_URL="https://aws.amazon.com/linux/amazon-linux-2023/"
SUPPORT_END="2029-06-30\""""

# name, epoch:version-release (rpm --qf output, epoch "(none)" when unset), arch
AL2023_PACKAGES = [
    ("bash", "(none):5.2.15-1.amzn2023.0.2", "x86_64"),
    ("openssl", "1:3.0.8-1.amzn2023.0.14", "x86_64"),
    ("openssl-libs", "1:3.0.8-1.amzn2023.0.14", "x86_64"),
    ("curl-minimal", "(none):8.5.0-1.amzn2023.0.4", "x86_64"),
    ("libcurl-minimal", "(none):8.5.0-1.amzn2023.0.4", "x86_64"),
    ("vim-minimal", "2:9.0.2153-1.amzn2023.0.1", "x86_64"),
    ("vim-data", "2:9.0.2153-1.amzn2023.0.1", "noarch"),
    ("python3", "(none):3.9.16-1.amzn2023.0.9", "x86_64"),
    ("kernel", "(none):6.1.112-122.189.amzn2023", "x86_64"),
    ("kernel", "(none):6.1.115-126.197.amzn2023", "x86_64"),
    ("system-release", "(none):2023.6.20241010-0.amzn2023", "noarch"),
    ("gpg-pubkey", "(none):d832c631-6515c85e", "(none)"),
]

NEEDS_RESTARTING_NO = [
    "No core libraries or services have been updated since boot-up.",
    "Reboot should not be necessary.",
]
NEEDS_RESTARTING_YES = [
    "Core libraries or services have been updated since boot-up:",
    "  * kernel",
    "  * openssl-libs",
    "",
    "Reboot is required to fully utilize these updates.",
    "More information: https://access.redhat.com/solutions/27943",
]


def al_facts_output(
    packages=None,
    os_release=AL2023_OS_RELEASE,
    release_file=f"Amazon Linux release {RELEASEVER} (Amazon Linux)",
    dnf_releasever=None,
    arch="x86_64",
    kernel=KERNEL_RUNNING,
    reboot=None,
    reboot_rc="0",
    hostname="ip-10-0-0-12",
) -> str:
    """What amazon_state.FACTS_COMMAND prints (``reboot_rc='unavailable'``: no
    needs-restarting)."""
    packages = AL2023_PACKAGES if packages is None else packages
    reboot = NEEDS_RESTARTING_NO if reboot is None else reboot
    lines = ["   ,     #_", "   ~\\_  ####_        Amazon Linux 2023", ""]  # MOTD
    lines += ["@@EC2P hostname", hostname, "@@EC2P os-release", os_release]
    lines += ["@@EC2P amazon-linux-release", *([release_file] if release_file else [])]
    lines += ["@@EC2P dnf-releasever", *([dnf_releasever] if dnf_releasever else [])]
    lines += ["@@EC2P arch", arch, "@@EC2P kernel", kernel]
    lines += ["@@EC2P reboot", *([] if reboot_rc == "unavailable" else reboot)]
    lines += ["@@EC2P reboot-rc", reboot_rc]
    lines += ["@@EC2P rpm", *(" ".join(p) for p in packages), "@@EC2P rpm-rc", "0"]
    return "\n".join([*lines, "@@EC2P end"]) + "\n"


def ubuntu_facts_on_amazon(os_release=AL2023_OS_RELEASE) -> str:
    """What the (Ubuntu) detection facts command prints on Amazon Linux: no dpkg."""
    lines = ["@@EC2P hostname", "ip-10-0-0-12", "@@EC2P os-release", os_release, "@@EC2P arch"]
    lines += ["@@EC2P kernel", KERNEL_RUNNING, "@@EC2P reboot", "no", "@@EC2P reboot-hooks"]
    lines += ["@@EC2P dpkg", "@@EC2P audit", "@@EC2P audit-rc", "127", "@@EC2P end"]
    return "\n".join(lines) + "\n"


# --- repository metadata ------------------------------------------------------------------


def pkg(name, version, release, epoch="0", arch="x86_64", src=None):
    """One <package> of an advisory; ``src`` defaults to '<name>-<version>-<release>'."""
    return {
        "name": name, "epoch": epoch, "version": version, "release": release, "arch": arch,
        "src": src if src is not None else f"{name}-{version}-{release}.src.rpm",
    }  # fmt: skip


def advisory(adv_id, cves, packages, severity="important", issued="2024-10-01 00:00"):
    return {"id": adv_id, "cves": cves, "packages": packages, "severity": severity,
            "issued": issued}  # fmt: skip


def updateinfo_xml(advisories) -> bytes:
    out = ['<?xml version="1.0" encoding="UTF-8"?>', "<updates>"]
    for a in advisories:
        out.append(
            '<update author="amazon" from="alas@amazon.com" status="final" type="security" '
            'version="2.0">'
        )
        out.append(f"<id>{a['id']}</id><title>Amazon Linux 2023 - {a['id']}</title>")
        out.append(f'<issued date="{a["issued"]}"/><updated date="{a["issued"]}"/>')
        out.append(f"<severity>{a['severity']}</severity><description>Package updates."
                   "</description>")  # fmt: skip
        out.append("<references>")
        for cve in a["cves"]:
            href = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"
            out.append(f'<reference href="{href}" id="{cve}" title="{cve}" type="cve"/>')
        out.append(
            f'<reference href="https://alas.aws.amazon.com/AL2023/{a["id"]}.html" '
            f'id="{a["id"]}" title="{a["id"]}" type="self"/>'
        )
        out.append('</references><pkglist><collection short="amazon-linux-2023">')
        out.append("<name>amazon-linux-2023</name>")
        for p in a["packages"]:
            attrs = " ".join(f"{k}={quoteattr(v)}" for k, v in p.items() if v is not None)
            filename = f"Packages/{p['name']}-{p['version']}-{p['release']}.{p['arch']}.rpm"
            out.append(f"<package {attrs}><filename>{filename}</filename>"
                       f'<sum type="sha256">{"ab" * 32}</sum></package>')  # fmt: skip
        out.append("</collection></pkglist></update>")
    out.append("</updates>")
    return "\n".join(out).encode()


def repomd_xml(href="repodata/0123abcd-updateinfo.xml.gz") -> bytes:
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<repomd xmlns="http://linux.duke.edu/metadata/repo" '
        'xmlns:rpm="http://linux.duke.edu/metadata/rpm">\n'
        "  <revision>1728518400</revision>\n"
        '  <data type="primary"><location href="repodata/aa-primary.xml.gz"/></data>\n'
        f'  <data type="updateinfo"><checksum type="sha256">{"cd" * 32}</checksum>'
        f'<location href="{href}"/><timestamp>1728518400</timestamp></data>\n'
        '  <data type="updateinfo_zck"><location href="repodata/x-updateinfo.xml.zck"/></data>\n'
        "</repomd>\n"
    ).encode()


# The fixture world: OpenSSL fixed in the server's release (patch available), curl fixed only
# in a newer release, vim already fixed, nginx not installed, a kernel fix installed but not
# running, and CVE-2024-0002 referenced by two advisories (the newer one wins).
CURRENT_ADVISORIES = [
    advisory("ALAS2023-2024-700", ["CVE-2024-0001"], [
        pkg("openssl", "3.0.8", "1.amzn2023.0.16", epoch="1", src="openssl-3.0.8-1.amzn2023.0.16.src.rpm"),  # noqa: E501
        pkg("openssl-libs", "3.0.8", "1.amzn2023.0.16", epoch="1", src="openssl-3.0.8-1.amzn2023.0.16.src.rpm"),  # noqa: E501
        pkg("openssl-libs", "3.0.8", "1.amzn2023.0.16", epoch="1", arch="aarch64", src="openssl-3.0.8-1.amzn2023.0.16.src.rpm"),  # noqa: E501
        pkg("openssl", "3.0.8", "1.amzn2023.0.16", epoch="1", arch="src", src=""),
    ], severity="important"),
    advisory("ALAS2023-2024-500", ["CVE-2024-0002"], [
        pkg("vim-minimal", "9.0.2120", "1.amzn2023", epoch="2", src="vim-9.0.2120-1.amzn2023.src.rpm"),  # noqa: E501
        pkg("vim-data", "9.0.2120", "1.amzn2023", epoch="2", arch="noarch", src="vim-9.0.2120-1.amzn2023.src.rpm"),  # noqa: E501
    ], severity="medium"),
    advisory("ALAS2023-2024-650", ["CVE-2024-0002", "CVE-2024-0003"], [
        pkg("vim-minimal", "9.0.2153", "1.amzn2023.0.1", epoch="2", src="vim-9.0.2153-1.amzn2023.0.1.src.rpm"),  # noqa: E501
        pkg("vim-data", "9.0.2153", "1.amzn2023.0.1", epoch="2", arch="noarch", src="vim-9.0.2153-1.amzn2023.0.1.src.rpm"),  # noqa: E501
    ], severity="low"),
    advisory("ALAS2023-2024-610", ["CVE-2024-0004"], [
        pkg("nginx", "1.24.0", "1.amzn2023.0.4", epoch="1"),
        pkg("nginx-core", "1.24.0", "1.amzn2023.0.4", epoch="1", src="nginx-1.24.0-1.amzn2023.0.4.src.rpm"),  # noqa: E501
    ], severity="critical"),
    advisory("ALAS2023-2024-690", ["CVE-2024-0005"], [
        pkg("kernel", "6.1.115", "126.197.amzn2023"),
    ]),
]  # fmt: skip
NEWER_ADVISORIES = [
    *CURRENT_ADVISORIES,
    advisory("ALAS2023-2025-900", ["CVE-2025-0006"], [
        pkg("curl-minimal", "8.11.1", "4.amzn2023.0.1", src="curl-8.11.1-4.amzn2023.0.1.src.rpm"),  # noqa: E501
        pkg("libcurl-minimal", "8.11.1", "4.amzn2023.0.1", src="curl-8.11.1-4.amzn2023.0.1.src.rpm"),  # noqa: E501
    ], severity="medium"),
]  # fmt: skip

BASE_URL = "https://cdn.amazonlinux.com/al2023/core/guids/{guid}/x86_64/"


class FakeCdn:
    """Transport for UpdateInfoSource: releasever -> advisories (gzip-compressed
    updateinfo). ``fail``: exception raised for every request."""

    def __init__(self, repos=None, fail=None, compress=gzip.compress):
        if repos is None:
            repos = {RELEASEVER: CURRENT_ADVISORIES, "latest": NEWER_ADVISORIES}
        self.repos, self.fail, self.compress = repos, fail, compress
        self.calls: list[str] = []
        self.files: dict[str, bytes] = {}
        for index, (releasever, advisories) in enumerate(self.repos.items()):
            mirror = amazon_updateinfo.MIRROR_LIST_URL.format(releasever=releasever, arch="x86_64")
            base = BASE_URL.format(guid=f"{index:064x}")
            self.files[mirror] = f"{base}\n".encode()
            self.files[base + "repodata/repomd.xml"] = repomd_xml()
            self.files[base + "repodata/0123abcd-updateinfo.xml.gz"] = self.compress(
                updateinfo_xml(advisories)
            )

    def __call__(self, url, timeout):
        self.calls.append(url)
        if self.fail is not None:
            raise self.fail
        if url not in self.files:
            raise amazon_updateinfo.UpdateInfoError(f"HTTP 404 for {url}")
        return self.files[url]

    @property
    def downloads(self) -> int:
        return sum(1 for url in self.calls if url.endswith(".xml.gz"))
