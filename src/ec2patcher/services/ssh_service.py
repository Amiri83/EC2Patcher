"""SSH connectivity test using the system OpenSSH client.

The command is always built as an argument list and run without a shell, so user
supplied values (IP address, PEM path) are never interpreted by a shell.
"""

import logging
import subprocess  # noqa: S404 - required to drive the system ssh client safely
from collections.abc import Callable
from dataclasses import dataclass

from ec2patcher.models import DEFAULT_SSH_USER
from ec2patcher.validation import (
    check_ip_address,
    check_pem_path,
    check_ssh_user,
    expand_pem_path,
)

logger = logging.getLogger(__name__)

SSH_USER = DEFAULT_SSH_USER  # default login user; each server can configure its own
SSH_BINARY = "ssh"
CONNECT_TIMEOUT_SECONDS = 10
# Hard upper bound for the whole ssh process (connect + run remote command).
PROCESS_TIMEOUT_SECONDS = 30

# Constant remote command (no user input). Prefixed markers make parsing robust
# against login banners or MOTD text printed to stdout.
REMOTE_COMMAND = (
    'echo "EC2P_HOSTNAME=$(hostname)"; '
    ". /etc/os-release 2>/dev/null; "
    'echo "EC2P_OS=${PRETTY_NAME:-unknown}"; '
    'echo "EC2P_ARCH=$(dpkg --print-architecture 2>/dev/null || uname -m)"'
)

Runner = Callable[..., subprocess.CompletedProcess]


@dataclass
class SSHTestResult:
    success: bool
    server_name: str
    ip_address: str
    hostname: str | None = None
    os_release: str | None = None
    architecture: str | None = None
    error: str | None = None


@dataclass
class RemoteResult:
    """Outcome of running one fixed, read-only command on a server over ssh."""

    ok: bool
    stdout: str = ""
    stderr: str = ""
    returncode: int | None = None
    error: str | None = None  # user-friendly message when ok is False


def _checked_user(user: str) -> str:
    error = check_ssh_user(user)
    if error:
        raise ValueError(error)
    return user


def _port_options(flag: str, port: int | None) -> list[str]:
    """``-p``/``-P <port>``; no option (ssh default 22) when ``port`` is None."""
    if port is None:
        return []
    if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
        raise ValueError(f"Invalid SSH port: {port!r}")
    return [flag, str(port)]


def _check_target(ip_address: str, pem_path: str, user: str) -> tuple[str | None, str | None]:
    """(normalized_ip, error) after validating IP, PEM path and SSH user."""
    normalized_ip, ip_error = check_ip_address(ip_address)
    if ip_error:
        return None, ip_error
    return normalized_ip, check_pem_path(pem_path) or check_ssh_user(user)


def build_ssh_command(
    ip_address: str,
    pem_path: str,
    remote_command: str = REMOTE_COMMAND,
    user: str = SSH_USER,
    port: int | None = None,
) -> list[str]:
    """Build the ssh argument list. PEM path '~' is expanded here.

    ``remote_command`` is passed as a single argument and interpreted by the remote login
    shell, so callers must only pass constant text or values quoted with shlex.quote().
    """
    return [
        SSH_BINARY,
        "-i", str(expand_pem_path(pem_path)),
        *SSH_OPTIONS,
        *_port_options("-p", port),
        "--",
        f"{_checked_user(user)}@{ip_address}",
        remote_command,
    ]  # fmt: skip


SCP_BINARY = "scp"
SSH_OPTIONS = [
    "-o", "BatchMode=yes",
    "-o", "IdentitiesOnly=yes",
    "-o", "PasswordAuthentication=no",
    "-o", f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}",
    "-o", "StrictHostKeyChecking=accept-new",
]  # fmt: skip


def build_scp_command(
    ip_address: str,
    pem_path: str,
    local_files: list[str],
    remote_dir: str,
    user: str = SSH_USER,
    port: int | None = None,
) -> list[str]:
    """``scp -i <pem> <options> -- <files...> <user>@<ip>:<remote_dir>/`` as an argument list.

    Callers validate ``remote_dir`` and the file names (no shell metacharacters).
    """
    host = f"[{ip_address}]" if ":" in ip_address else ip_address
    return [
        SCP_BINARY, "-q", "-i", str(expand_pem_path(pem_path)), *SSH_OPTIONS,
        *_port_options("-P", port),
        "--", *local_files, f"{_checked_user(user)}@{host}:{remote_dir.rstrip('/')}/",
    ]  # fmt: skip


def run_scp(
    ip_address: str,
    pem_path: str,
    local_files: list[str],
    remote_dir: str,
    runner: Runner = subprocess.run,
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    user: str = SSH_USER,
    port: int | None = None,
) -> RemoteResult:
    """Copy local files to ``<user>@<ip>:<remote_dir>/`` (no shell, same ssh options)."""
    normalized_ip, error = _check_target(ip_address, pem_path, user)
    if error:
        return RemoteResult(ok=False, error=error)
    command = build_scp_command(normalized_ip, pem_path, local_files, remote_dir, user, port)
    try:
        proc = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return RemoteResult(ok=False, error=f"The file transfer did not finish within {timeout}s.")
    except FileNotFoundError:
        return RemoteResult(ok=False, error="The 'scp' command was not found.")
    except OSError as exc:
        logger.exception("Could not start scp process")
        return RemoteResult(ok=False, error=f"Could not run scp: {exc.strerror or exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if proc.returncode != 0:
        return RemoteResult(False, stdout, stderr, proc.returncode, describe_ssh_error(stderr))
    return RemoteResult(True, stdout, stderr, proc.returncode)


def parse_remote_info(stdout: str) -> dict[str, str]:
    info: dict[str, str] = {}
    keys = {"EC2P_HOSTNAME": "hostname", "EC2P_OS": "os_release", "EC2P_ARCH": "architecture"}
    for line in stdout.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in keys and value.strip():
            info[keys[key]] = value.strip()
    return info


def describe_ssh_error(stderr: str) -> str:
    """Translate ssh stderr into a short, user-friendly message."""
    text = stderr or ""
    lower = text.lower()
    if "remote host identification has changed" in lower:
        return (
            "Host key verification failed: the server's host key has changed. "
            "Remove the old entry from ~/.ssh/known_hosts if this is expected."
        )
    if "unprotected private key file" in lower or "bad permissions" in lower:
        return "PEM file permissions are too open. Run: chmod 400 <pem-file>"
    if "permission denied" in lower:
        return "Permission denied (publickey). Check the PEM file matches this server."
    if "timed out" in lower:
        return "Connection timed out. Check the IP address, network access and security group."
    if "connection refused" in lower:
        return "Connection refused. SSH may not be running on the server."
    if "no route to host" in lower:
        return "No route to host. Check the IP address and network access."
    if "host key verification failed" in lower:
        return "Host key verification failed."
    if "invalid format" in lower or "load key" in lower:
        return "The PEM file could not be loaded as a private key (invalid format)."
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    if lines:
        return f"SSH connection failed: {lines[-1][:300]}"
    return "SSH connection failed for an unknown reason."


def run_remote(
    ip_address: str,
    pem_path: str,
    remote_command: str,
    runner: Runner = subprocess.run,
    timeout: int = PROCESS_TIMEOUT_SECONDS,
    accept_returncodes: tuple[int, ...] = (0,),
    user: str = SSH_USER,
    port: int | None = None,
) -> RemoteResult:
    """Run a command as ``<user>@<ip>`` with the same safe ssh options as the SSH test.

    The IP, PEM path and user are validated first. ssh itself exits 255 on connection/auth
    errors.
    """
    normalized_ip, error = _check_target(ip_address, pem_path, user)
    if error:
        return RemoteResult(ok=False, error=error)
    command = build_ssh_command(normalized_ip, pem_path, remote_command, user, port)
    try:
        proc = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return RemoteResult(ok=False, error=f"The remote command did not finish within {timeout}s.")
    except FileNotFoundError:
        return RemoteResult(ok=False, error="The 'ssh' command was not found.")
    except OSError as exc:
        logger.exception("Could not start ssh process")
        return RemoteResult(ok=False, error=f"Could not run ssh: {exc.strerror or exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if proc.returncode == 255:
        return RemoteResult(False, stdout, stderr, 255, describe_ssh_error(stderr))
    if proc.returncode not in accept_returncodes:
        detail = [ln.strip() for ln in stderr.splitlines() if ln.strip()]
        message = f"Remote command failed (exit {proc.returncode})"
        if detail:
            message += f": {detail[-1][:300]}"
        return RemoteResult(False, stdout, stderr, proc.returncode, message)
    return RemoteResult(True, stdout, stderr, proc.returncode)


def check_connection(
    server_name: str,
    ip_address: str,
    pem_path: str,
    runner: Runner = subprocess.run,
    user: str = SSH_USER,
    port: int | None = None,
) -> SSHTestResult:
    """Attempt `ssh -i <pem> <user>@<ip>` and collect hostname / OS / architecture."""
    result = SSHTestResult(success=False, server_name=server_name, ip_address=ip_address)

    normalized_ip, error = _check_target(ip_address, pem_path, user)
    if error:
        result.error = error
        return result

    logger.info("SSH test attempted: server=%s ip=%s user=%s", server_name, normalized_ip, user)
    command = build_ssh_command(normalized_ip, pem_path, user=user, port=port)
    try:
        proc = runner(
            command,
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            check=False,
        )
    except subprocess.TimeoutExpired:
        result.error = "Connection timed out. The server did not respond in time."
    except FileNotFoundError:
        result.error = "The 'ssh' command was not found. Install the OpenSSH client."
    except OSError as exc:
        logger.exception("SSH test could not start ssh process")
        result.error = f"Could not run ssh: {exc.strerror or exc}"
    else:
        if proc.returncode == 0:
            info = parse_remote_info(proc.stdout or "")
            result.success = True
            result.hostname = info.get("hostname", "unknown")
            result.os_release = info.get("os_release", "unknown")
            result.architecture = info.get("architecture", "unknown")
        else:
            logger.warning(
                "SSH test stderr for %s (exit %s): %s",
                server_name, proc.returncode, (proc.stderr or "").strip()[:1000],
            )  # fmt: skip
            result.error = describe_ssh_error(proc.stderr or "")

    if result.success:
        logger.info(
            "SSH test succeeded: server=%s ip=%s hostname=%s",
            server_name, normalized_ip, result.hostname,
        )  # fmt: skip
    else:
        logger.warning(
            "SSH test failed: server=%s ip=%s error=%s", server_name, normalized_ip, result.error
        )
    return result
