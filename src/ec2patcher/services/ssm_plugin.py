"""The session-manager-plugin managed by the app: detection, PATH and installation.

The aws CLI starts ``session-manager-plugin`` through PATH. It is used from PATH or from
``<data dir>/bin``, where Settings can install it: without sudo and without touching the system.
The official Ubuntu package is downloaded, verified, unpacked (not installed: dpkg-deb -x runs no
maintainer scripts and changes no dpkg state) in a temporary directory, and only its binary is
kept. A failed install leaves an existing binary and the data directory as they were.

AWS publishes no checksum of the package, but a detached GPG signature. It is checked against
the signing key AWS documents, in a throwaway keyring. Without gpg on this machine the package
checks below still apply and the result says that the signature was not checked.
"""

import logging
import os
import platform
import shutil
import subprocess  # noqa: S404 - runs dpkg-deb, gpg and the plugin as argument lists
import tempfile
import urllib.error
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ec2patcher import config
from ec2patcher.services import downloader

logger = logging.getLogger(__name__)

Runner = Callable[..., subprocess.CompletedProcess]

PLUGIN_BINARY = "session-manager-plugin"
DOWNLOAD_BASE = "https://s3.amazonaws.com/session-manager-downloads/plugin/latest"
# platform.machine() -> (directory of the download URL, Debian architecture)
PACKAGES = {
    "x86_64": ("ubuntu_64bit", "amd64"),
    "amd64": ("ubuntu_64bit", "amd64"),
    "aarch64": ("ubuntu_arm64", "arm64"),
    "arm64": ("ubuntu_arm64", "arm64"),
}
DEB_MAGIC = b"!<arch>\n"
# Sanity bounds only: an error page is far smaller, a runaway download is stopped.
MIN_DEB_BYTES = 256 * 1024
MAX_DEB_BYTES = 256 * 1024 * 1024
MAX_SIGNATURE_BYTES = 64 * 1024
DOWNLOAD_TIMEOUT_SECONDS = 60  # per socket operation
TOOL_TIMEOUT_SECONDS = 60

# The public signing key and fingerprint published in the AWS Systems Manager user guide,
# "Verify the signature of the Session Manager plugin".
SIGNER_FINGERPRINT = "7959637124CE093AD501D47A2C4D4AFF6F6757EE"
SIGNER_PUBLIC_KEY = """\
-----BEGIN PGP PUBLIC KEY BLOCK-----

mFIEZ5ERQxMIKoZIzj0DAQcCAwQjuZy+IjFoYg57sLTGhF3aZLBaGpzB+gY6j7Ix
P7NqbpXyjVj8a+dy79gSd64OEaMxUb7vw/jug+CfRXwVGRMNtIBBV1MgU1NNIFNl
c3Npb24gTWFuYWdlciA8c2Vzc2lvbi1tYW5hZ2VyLXBsdWdpbi1zaWduZXJAYW1h
em9uLmNvbT4gKEFXUyBTeXN0ZW1zIE1hbmFnZXIgU2Vzc2lvbiBNYW5hZ2VyIFBs
dWdpbiBMaW51eCBTaWduZXIgS2V5KYkBAAQQEwgAqAUCZ5ERQ4EcQVdTIFNTTSBT
ZXNzaW9uIE1hbmFnZXIgPHNlc3Npb24tbWFuYWdlci1wbHVnaW4tc2lnbmVyQGFt
YXpvbi5jb20+IChBV1MgU3lzdGVtcyBNYW5hZ2VyIFNlc3Npb24gTWFuYWdlciBQ
bHVnaW4gTGludXggU2lnbmVyIEtleSkWIQR5WWNxJM4JOtUB1HosTUr/b2dX7gIe
AwIbAwIVCAAKCRAsTUr/b2dX7rO1AQCa1kig3lQ78W/QHGU76uHx3XAyv0tfpE9U
oQBCIwFLSgEA3PDHt3lZ+s6m9JLGJsy+Cp5ZFzpiF6RgluR/2gA861M=
=2DQm
-----END PGP PUBLIC KEY BLOCK-----
"""

DPKG_MISSING = (
    "The 'dpkg-deb' command was not found. It is needed to unpack the Session Manager plugin "
    "package (it is part of dpkg on Ubuntu)."
)
NOT_A_DEB = (
    "The download is not a valid Session Manager plugin .deb package, so nothing was installed."
)

default_fetcher: downloader.Fetcher = downloader.urllib_fetcher


class PluginInstallError(Exception):
    """The plugin could not be installed. The message is user-facing."""


@dataclass(frozen=True)
class PluginLocation:
    path: Path
    managed: bool  # in the app-managed directory (else found on PATH)


@dataclass(frozen=True)
class InstallResult:
    path: Path
    version: str
    signature_checked: bool


def managed_binary() -> Path:
    return config.get_plugin_bin_dir() / PLUGIN_BINARY


def find_plugin() -> PluginLocation | None:
    """The plugin the aws CLI will use, the app-managed one first. Only looks at the disk."""
    managed = managed_binary()
    if managed.is_file() and os.access(managed, os.X_OK):
        return PluginLocation(managed, True)
    found = shutil.which(PLUGIN_BINARY)
    return PluginLocation(Path(found), False) if found else None


def aws_env() -> dict[str, str]:
    """Environment of the aws CLI, directly or as the ProxyCommand of ssh and scp: the
    app-managed directory comes first on PATH."""
    path = os.pathsep.join(
        part for part in (str(config.get_plugin_bin_dir()), os.environ.get("PATH")) if part
    )
    return {**os.environ, "AWS_PAGER": "", "PATH": path}


def download_url(subdir: str, suffix: str = "") -> str:
    return f"{DOWNLOAD_BASE}/{subdir}/{PLUGIN_BINARY}.deb{suffix}"


def _download(url: str, target: Path, max_bytes: int, what: str, fetcher) -> None:
    try:
        with open(target, "wb") as out:
            fetcher(url, out, max_bytes, DOWNLOAD_TIMEOUT_SECONDS)
    except downloader.DownloadError as exc:
        raise PluginInstallError(f"The {what} download failed: {exc}") from None
    except urllib.error.HTTPError as exc:
        raise PluginInstallError(
            f"The {what} download failed: AWS answered HTTP {exc.code}."
        ) from None
    except urllib.error.URLError as exc:
        raise PluginInstallError(
            f"The {what} download failed: AWS could not be reached ({exc.reason}). Check the "
            "network and HTTPS_PROXY."
        ) from None
    except TimeoutError:
        raise PluginInstallError(
            f"The {what} download timed out. Check the network and HTTPS_PROXY."
        ) from None
    except OSError as exc:
        raise PluginInstallError(f"The {what} download failed: {exc.strerror or exc}") from None


def _check_package_file(deb: Path) -> None:
    size = deb.stat().st_size
    with open(deb, "rb") as fh:
        magic = fh.read(len(DEB_MAGIC))
    if magic != DEB_MAGIC or size < MIN_DEB_BYTES:
        raise PluginInstallError(NOT_A_DEB)


def _run_tool(command: list[str], runner: Runner, action: str, **kwargs):
    """Raises FileNotFoundError when the tool is missing, for the caller to word."""
    try:
        return runner(
            command, capture_output=True, text=True, timeout=TOOL_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL, check=False, **kwargs,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        raise PluginInstallError(
            f"{action} did not finish within {TOOL_TIMEOUT_SECONDS}s."
        ) from None
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PluginInstallError(f"{action} could not be run: {exc.strerror or exc}") from None


def _dpkg_deb(arguments: list[str], runner: Runner, action: str):
    try:
        return _run_tool(["dpkg-deb", *arguments], runner, action)
    except FileNotFoundError:
        raise PluginInstallError(DPKG_MISSING) from None


def _verify_signature(deb: Path, signature: Path, work: Path, runner: Runner) -> None:
    """Only a good signature by the pinned key passes. The caller made sure gpg exists."""
    home = work / "gnupg"
    home.mkdir(mode=0o700)
    key = work / "signer.asc"
    key.write_text(SIGNER_PUBLIC_KEY, encoding="ascii")
    gpg = ["gpg", "--homedir", str(home), "--batch", "--no-tty", "--no-autostart"]
    failed = "The signature of the Session Manager plugin package could not be verified"
    try:
        imported = _run_tool([*gpg, "--import", str(key)], runner, "Importing the signing key")
        if imported.returncode != 0:
            raise PluginInstallError(f"{failed}: gpg could not import the AWS signing key.")
        checked = _run_tool(
            [*gpg, "--status-fd", "1", "--verify", str(signature), str(deb)],
            runner, "Verifying the signature",
        )  # fmt: skip
    except FileNotFoundError:
        raise PluginInstallError(f"{failed}: gpg is not available.") from None
    valid = [
        line.split()[2]
        for line in (checked.stdout or "").splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) > 2
    ]
    if checked.returncode != 0 or valid != [SIGNER_FINGERPRINT]:
        raise PluginInstallError(f"{failed}: it is not signed by the AWS key. Nothing installed.")


def _gpg_available(runner: Runner) -> bool:
    try:
        return _run_tool(["gpg", "--version"], runner, "gpg").returncode == 0
    except (FileNotFoundError, PluginInstallError):
        return False


def _check_package_fields(deb: Path, architecture: str, runner: Runner) -> None:
    proc = _dpkg_deb(["-f", str(deb), "Package", "Architecture"], runner, "Reading the package")
    if proc.returncode != 0:
        raise PluginInstallError(NOT_A_DEB)
    fields = dict(
        (key.strip(), value.strip())
        for key, sep, value in (line.partition(":") for line in (proc.stdout or "").splitlines())
        if sep
    )
    if fields.get("Package") != PLUGIN_BINARY:
        raise PluginInstallError(NOT_A_DEB)
    if fields.get("Architecture") != architecture:
        raise PluginInstallError(
            f"The downloaded package is for {fields.get('Architecture') or 'an unknown'} "
            f"architecture, this machine needs {architecture}. Nothing was installed."
        )


def _binary_in(tree: Path) -> Path:
    """The plugin in an unpacked package. Links are not followed: they could point anywhere."""
    found = [
        path for path in sorted(tree.rglob(PLUGIN_BINARY))
        if path.is_file() and not path.is_symlink()
    ]  # fmt: skip
    if not found:
        raise PluginInstallError(
            f"The package has no {PLUGIN_BINARY} program, so nothing was installed."
        )
    return found[0]


def version_of(binary: Path | str, runner: Runner) -> str | None:
    """``<binary> --version`` (first line), or None when it does not run."""
    try:
        proc = _run_tool([str(binary), "--version"], runner, "The Session Manager plugin")
    except (FileNotFoundError, PluginInstallError):
        return None
    lines = (proc.stdout or "").strip().splitlines()
    return lines[0][:64] if proc.returncode == 0 and lines else None


def _keep_binary(source: Path, runner: Runner) -> tuple[Path, str]:
    """Copy the binary to the app directory; an existing one is replaced only by a working one."""
    target = managed_binary()
    target.parent.mkdir(parents=True, exist_ok=True)
    staged = target.with_name(f".{PLUGIN_BINARY}.new")
    try:
        shutil.copyfile(source, staged)
        staged.chmod(0o755)
        version = version_of(staged, runner)
        if version is None:
            raise PluginInstallError(
                f"The {PLUGIN_BINARY} from the package does not run on this machine, so nothing "
                "was installed."
            )
        os.replace(staged, target)
    finally:
        staged.unlink(missing_ok=True)
    return target, version


def install(
    runner: Runner = subprocess.run,
    fetcher: downloader.Fetcher | None = None,
    machine: str | None = None,
) -> InstallResult:
    """Download, verify and unpack the official package. Raises :class:`PluginInstallError`."""
    machine = machine if machine is not None else platform.machine()
    package = PACKAGES.get(machine.lower())
    if package is None:
        raise PluginInstallError(f"AWS publishes no Ubuntu Session Manager plugin for {machine!r}.")
    subdir, architecture = package
    fetch = fetcher or default_fetcher
    if _dpkg_deb(["--version"], runner, "dpkg-deb").returncode != 0:  # before a long download
        raise PluginInstallError(DPKG_MISSING)
    try:
        with tempfile.TemporaryDirectory(prefix=".ssm-plugin-", dir=config.get_data_dir()) as tmp:
            work = Path(tmp)
            deb = work / f"{PLUGIN_BINARY}.deb"
            _download(download_url(subdir), deb, MAX_DEB_BYTES, "plugin package", fetch)
            _check_package_file(deb)
            signature_checked = _gpg_available(runner)
            if signature_checked:
                signature = work / f"{PLUGIN_BINARY}.deb.sig"
                url = download_url(subdir, ".sig")
                _download(url, signature, MAX_SIGNATURE_BYTES, "plugin signature", fetch)
                _verify_signature(deb, signature, work, runner)
            else:
                logger.warning("gpg not found: Session Manager plugin signature not checked")
            _check_package_fields(deb, architecture, runner)
            tree = work / "unpacked"
            tree.mkdir()
            proc = _dpkg_deb(["-x", str(deb), str(tree)], runner, "Unpacking the package")
            if proc.returncode != 0:
                raise PluginInstallError(NOT_A_DEB)
            target, version = _keep_binary(_binary_in(tree), runner)
    except OSError as exc:
        raise PluginInstallError(
            f"The Session Manager plugin could not be installed: {exc.strerror or exc}"
        ) from None
    logger.info(
        "Session Manager plugin %s installed in %s (signature %s)",
        version, target, "verified" if signature_checked else "not checked: no gpg",
    )  # fmt: skip
    return InstallResult(target, version, signature_checked)
