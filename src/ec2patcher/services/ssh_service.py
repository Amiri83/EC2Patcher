"""SSH connectivity test using the system OpenSSH client.

The command is always built as an argument list and run without a shell, so user
supplied values (IP address, PEM path) are never interpreted by a shell.

Servers log in with a PEM key (default) or with username + password. A password is stored
per server, encrypted (services.secret_store), decrypted only to connect and reaches ssh/scp
through ``sshpass -e``, which reads it from the ``SSHPASS`` environment variable of the
child process - never from the command line, a plain-text file or a log.
"""

import logging
import os
import subprocess  # noqa: S404 - required to drive the system ssh client safely
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ec2patcher.models import AUTH_PASSWORD, DEFAULT_SSH_USER
from ec2patcher.services.secret_store import SecretError
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

SSHPASS_BINARY = "sshpass"
SSHPASS_ENV = "SSHPASS"
# sshpass's own exit codes (otherwise it passes through the exit code of ssh/scp).
SSHPASS_WRONG_PASSWORD = 5
SSHPASS_HOST_KEY_UNKNOWN = 6
SSHPASS_MISSING = (
    "The 'sshpass' command was not found. Install it (e.g. sudo apt install sshpass) to "
    "use password login, or switch this server to a PEM key."
)
PASSWORD_MISSING = (  # an error message, not a password
    "No SSH password is stored for this server. Edit the server on the Servers page, "  # noqa: S105
    "enter its password and save, then try again."
)


class PasswordSource(Protocol):
    def server_password(self, server_id: int) -> str | None: ...


def server_password(server, credentials: PasswordSource) -> tuple[str | None, str | None]:
    """(password, error) for one configured server: (None, None) for PEM key login,
    (None, PASSWORD_MISSING) for password login without a stored password, and (None, the
    user-facing reason) when the stored password cannot be decrypted. Never raises."""
    if getattr(server, "auth_method", None) != AUTH_PASSWORD:
        return None, None
    try:
        password = credentials.server_password(server.id)
    except SecretError as exc:
        logger.error("Stored SSH password of %s cannot be used: %s", server.name, exc)
        return None, str(exc)
    return (password, None) if password else (None, PASSWORD_MISSING)


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


def _check_target(
    ip_address: str, pem_path: str, user: str, password: str | None = None
) -> tuple[str | None, str | None]:
    """(normalized_ip, error) after validating IP, PEM path (key login only) and SSH user."""
    normalized_ip, ip_error = check_ip_address(ip_address)
    if ip_error:
        return None, ip_error
    if password is not None:
        if not password:
            return normalized_ip, "SSH password is required."
        return normalized_ip, check_ssh_user(user)
    return normalized_ip, check_pem_path(pem_path) or check_ssh_user(user)


def _auth_prefix(binary: str, pem_path: str, password: str | None) -> list[str]:
    """``[sshpass -e] <binary> <identity/auth options>``. The password itself is never part of
    the argument list (sshpass -e reads it from $SSHPASS)."""
    if password is None:
        return [binary, "-i", str(expand_pem_path(pem_path)), *SSH_OPTIONS]
    return [SSHPASS_BINARY, "-e", binary, *PASSWORD_SSH_OPTIONS]


def _run_kwargs(password: str | None) -> dict:
    """Extra subprocess arguments: the SSHPASS environment for password login."""
    if password is None:
        return {}
    return {"env": {**os.environ, SSHPASS_ENV: password}}


def _sshpass_error(returncode: int, password: str | None) -> str | None:
    if password is None:
        return None
    if returncode == SSHPASS_WRONG_PASSWORD:
        return "Permission denied: the SSH password was rejected. Check the user and password."
    if returncode == SSHPASS_HOST_KEY_UNKNOWN:
        return "Host key verification failed (unknown host key)."
    return None


def build_ssh_command(
    ip_address: str,
    pem_path: str,
    remote_command: str = REMOTE_COMMAND,
    user: str = SSH_USER,
    port: int | None = None,
    password: str | None = None,
) -> list[str]:
    """Build the ssh argument list. PEM path '~' is expanded here.

    ``remote_command`` is passed as a single argument and interpreted by the remote login
    shell, so callers must only pass constant text or values quoted with shlex.quote().
    With a ``password`` the command runs through ``sshpass -e`` (password not on argv).
    """
    return [
        *_auth_prefix(SSH_BINARY, pem_path, password),
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
# Password login (through sshpass): no keys or agent, exactly one password prompt.
PASSWORD_SSH_OPTIONS = [
    "-o", "PubkeyAuthentication=no",
    "-o", "PreferredAuthentications=password,keyboard-interactive",
    "-o", "NumberOfPasswordPrompts=1",
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
    password: str | None = None,
) -> list[str]:
    """``scp -i <pem> <options> -- <files...> <user>@<ip>:<remote_dir>/`` as an argument list
    (``sshpass -e scp ...`` with a ``password``).

    Callers validate ``remote_dir`` and the file names (no shell metacharacters).
    """
    host = f"[{ip_address}]" if ":" in ip_address else ip_address
    prefix = _auth_prefix(SCP_BINARY, pem_path, password)
    split = prefix.index(SCP_BINARY) + 1
    return [
        *prefix[:split], "-q", *prefix[split:],
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
    password: str | None = None,
) -> RemoteResult:
    """Copy local files to ``<user>@<ip>:<remote_dir>/`` (no shell, same ssh options)."""
    normalized_ip, error = _check_target(ip_address, pem_path, user, password)
    if error:
        return RemoteResult(ok=False, error=error)
    command = build_scp_command(
        normalized_ip, pem_path, local_files, remote_dir, user, port, password
    )
    try:
        proc = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
            **_run_kwargs(password),
        )
    except subprocess.TimeoutExpired:
        return RemoteResult(ok=False, error=f"The file transfer did not finish within {timeout}s.")
    except FileNotFoundError:
        missing = SSHPASS_MISSING if password is not None else "The 'scp' command was not found."
        return RemoteResult(ok=False, error=missing)
    except OSError as exc:
        logger.exception("Could not start scp process")
        return RemoteResult(ok=False, error=f"Could not run scp: {exc.strerror or exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if proc.returncode != 0:
        message = _sshpass_error(proc.returncode, password) or describe_ssh_error(
            stderr, password is not None
        )
        return RemoteResult(False, stdout, stderr, proc.returncode, message)
    return RemoteResult(True, stdout, stderr, proc.returncode)


def parse_remote_info(stdout: str) -> dict[str, str]:
    info: dict[str, str] = {}
    keys = {"EC2P_HOSTNAME": "hostname", "EC2P_OS": "os_release", "EC2P_ARCH": "architecture"}
    for line in stdout.splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key in keys and value.strip():
            info[keys[key]] = value.strip()
    return info


def describe_ssh_error(stderr: str, password_login: bool = False) -> str:
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
        if password_login:
            return "Permission denied. Check the SSH user and password of this server."
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
    password: str | None = None,
) -> RemoteResult:
    """Run a command as ``<user>@<ip>`` with the same safe ssh options as the SSH test.

    The IP, PEM path (key login) and user are validated first. ssh itself exits 255 on
    connection/auth errors; sshpass exits 5 on a rejected password.
    """
    normalized_ip, error = _check_target(ip_address, pem_path, user, password)
    if error:
        return RemoteResult(ok=False, error=error)
    command = build_ssh_command(normalized_ip, pem_path, remote_command, user, port, password)
    try:
        proc = runner(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
            check=False,
            **_run_kwargs(password),
        )
    except subprocess.TimeoutExpired:
        return RemoteResult(ok=False, error=f"The remote command did not finish within {timeout}s.")
    except FileNotFoundError:
        missing = SSHPASS_MISSING if password is not None else "The 'ssh' command was not found."
        return RemoteResult(ok=False, error=missing)
    except OSError as exc:
        logger.exception("Could not start ssh process")
        return RemoteResult(ok=False, error=f"Could not run ssh: {exc.strerror or exc}")
    stdout, stderr = proc.stdout or "", proc.stderr or ""
    if proc.returncode == 255:
        message = describe_ssh_error(stderr, password is not None)
        return RemoteResult(False, stdout, stderr, 255, message)
    sshpass_error = _sshpass_error(proc.returncode, password)
    if sshpass_error and proc.returncode not in accept_returncodes:
        return RemoteResult(False, stdout, stderr, proc.returncode, sshpass_error)
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
    password: str | None = None,
) -> SSHTestResult:
    """Attempt `ssh -i <pem> <user>@<ip>` (or password login through sshpass) and collect
    hostname / OS / architecture."""
    result = SSHTestResult(success=False, server_name=server_name, ip_address=ip_address)

    normalized_ip, error = _check_target(ip_address, pem_path, user, password)
    if error:
        result.error = error
        return result

    logger.info(
        "SSH test attempted: server=%s ip=%s user=%s login=%s",
        server_name, normalized_ip, user, "key" if password is None else "password",
    )  # fmt: skip
    command = build_ssh_command(normalized_ip, pem_path, user=user, port=port, password=password)
    try:
        proc = runner(
            command,
            capture_output=True,
            text=True,
            timeout=PROCESS_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            check=False,
            **_run_kwargs(password),
        )
    except subprocess.TimeoutExpired:
        result.error = "Connection timed out. The server did not respond in time."
    except FileNotFoundError:
        result.error = (
            "The 'ssh' command was not found. Install the OpenSSH client."
            if password is None
            else SSHPASS_MISSING
        )
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
            result.error = _sshpass_error(proc.returncode, password) or describe_ssh_error(
                proc.stderr or "", password is not None
            )

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
