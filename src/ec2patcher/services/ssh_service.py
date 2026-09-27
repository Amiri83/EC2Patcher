"""SSH connectivity test using the system OpenSSH client.

The command is always built as an argument list and run without a shell, so user
supplied values (IP address, PEM path) are never interpreted by a shell.
"""

import logging
import subprocess  # noqa: S404 - required to drive the system ssh client safely
from collections.abc import Callable
from dataclasses import dataclass

from ec2patcher.validation import check_ip_address, check_pem_path, expand_pem_path

logger = logging.getLogger(__name__)

SSH_USER = "ubuntu"
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


def build_ssh_command(ip_address: str, pem_path: str) -> list[str]:
    """Build the ssh argument list. PEM path '~' is expanded here."""
    return [
        SSH_BINARY,
        "-i", str(expand_pem_path(pem_path)),
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "PasswordAuthentication=no",
        "-o", f"ConnectTimeout={CONNECT_TIMEOUT_SECONDS}",
        "-o", "StrictHostKeyChecking=accept-new",
        "--",
        f"{SSH_USER}@{ip_address}",
        REMOTE_COMMAND,
    ]  # fmt: skip


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


def check_connection(
    server_name: str, ip_address: str, pem_path: str, runner: Runner = subprocess.run
) -> SSHTestResult:
    """Attempt `ssh -i <pem> ubuntu@<ip>` and collect hostname / OS / architecture."""
    result = SSHTestResult(success=False, server_name=server_name, ip_address=ip_address)

    normalized_ip, ip_error = check_ip_address(ip_address)
    if ip_error:
        result.error = ip_error
        return result
    pem_error = check_pem_path(pem_path)
    if pem_error:
        result.error = pem_error
        return result

    logger.info("SSH test attempted: server=%s ip=%s", server_name, normalized_ip)
    command = build_ssh_command(normalized_ip, pem_path)
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
