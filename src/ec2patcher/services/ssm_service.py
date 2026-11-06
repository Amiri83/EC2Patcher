"""SSH over AWS Systems Manager: settings, preflight and instance ID resolution.

Only the transport changes: ssh and scp stay the same programs with the same options and login
method, and reach the server through ``aws ssm start-session`` as their ProxyCommand. The aws
CLI is used (not an SDK) because the ProxyCommand needs it anyway, so one profile configuration
and one ``aws sso login`` cover everything.

aws runs as an argument list without a shell, but ssh hands the ProxyCommand to a shell after
expanding its % tokens. Every value in it is therefore checked against an allowlist first.

Credentials stay in the aws CLI's own configuration: nothing here reads, stores or logs one.
"""

import ipaddress
import json
import logging
import re
import subprocess  # noqa: S404 - runs the aws CLI as an argument list
from collections.abc import Callable
from dataclasses import dataclass, field

from ec2patcher.models import CONNECTION_SSH, CONNECTION_SSM, CONNECTION_TYPES
from ec2patcher.services import ssm_plugin
from ec2patcher.validation import check_aws_profile, check_aws_region, check_instance_id

logger = logging.getLogger(__name__)

Runner = Callable[..., subprocess.CompletedProcess]

AWS_BINARY = "aws"
PLUGIN_BINARY = ssm_plugin.PLUGIN_BINARY
SSM_DOCUMENT = "AWS-StartSSHSession"
DEFAULT_SSH_PORT = 22  # what ssh connects to when no port is configured
AWS_TIMEOUT_SECONDS = 30
CREDENTIALS_CHECK = "The AWS credentials check"

DEFAULT_CONNECTION_SETTING = "default_connection_type"
DEFAULT_PROFILE_SETTING = "default_aws_profile"
DEFAULT_REGION_SETTING = "default_aws_region"

AWS_MISSING = (
    "The 'aws' command was not found. Install AWS CLI v2 on this machine to use SSH over SSM."
)
PLUGIN_MISSING = (
    "The 'session-manager-plugin' command was not found. Use Install SSM plugin in Settings "
    "(no sudo needed) to use SSH over SSM."
)

_HOST_IP_RE = re.compile(r"ip-(\d{1,3})-(\d{1,3})-(\d{1,3})-(\d{1,3})(\..*)?", re.IGNORECASE)
_SSO_EXPIRED_RE = re.compile(
    "token has expired and refresh failed|error when retrieving token from sso|"
    "sso session associated with this profile|error loading sso token|"
    "unauthorizedssotoken|ssotokenloaderror|aws sso login",
    re.IGNORECASE,
)
# Specific to AWS: over ssh this text sits next to server output, e.g. a login banner saying
# "if you are not authorized, disconnect".
_EXPIRED_MARKERS = ("expiredtoken", "requestexpired", "token included in the request is expired")
_REJECTED_MARKERS = ("invalidclienttokenid", "unrecognizedclient", "signaturedoesnotmatch")
_DENIED_MARKERS = ("accessdenied", "unauthorizedoperation", "is not authorized to perform")
_ARN_RE = re.compile(r"arn:aws[a-z-]*:\S+")
_SESSION_NOISE_RE = re.compile(r"\s*(starting|exiting) session with sessionid\b", re.IGNORECASE)


class SsmError(Exception):
    """SSH over SSM cannot be used right now. The message is user-facing."""


@dataclass(frozen=True)
class SsmTarget:
    instance_id: str
    profile: str
    region: str


def target_error(target: SsmTarget) -> str | None:
    """Why ``target`` must not reach a command line, or None."""
    return (
        check_instance_id(target.instance_id)
        or check_aws_profile(target.profile)
        or check_aws_region(target.region)
    )


def build_proxy_command(target: SsmTarget, port: int | None = None) -> str:
    """The ProxyCommand of ssh/scp. ``port`` is the port given to ssh/scp themselves (None:
    their default, 22), so both sides always agree."""
    error = target_error(target)
    if error:
        raise ValueError(error)
    number = DEFAULT_SSH_PORT if port is None else port
    if not isinstance(number, int) or isinstance(number, bool) or not 0 < number < 65536:
        raise ValueError(f"Invalid SSH port: {port!r}")
    return (
        f"{AWS_BINARY} ssm start-session --target {target.instance_id} "
        f"--document-name {SSM_DOCUMENT} --parameters portNumber={number} "
        f"--profile {target.profile} --region {target.region}"
    )


def transport_label(target: SsmTarget | None) -> str:
    if target is None:
        return CONNECTION_TYPES[CONNECTION_SSH]
    return (
        f"{CONNECTION_TYPES[CONNECTION_SSM]} ({target.instance_id}, profile {target.profile}, "
        f"region {target.region})"
    )


# --- AWS error messages ---------------------------------------------------------------


def is_sso_expired(stderr: str) -> bool:
    return bool(_SSO_EXPIRED_RE.search(stderr or ""))


def describe_aws_error(stderr: str, profile: str) -> str | None:
    """A clear message for a recognized failure of the aws CLI or the SSM session, or None."""
    text = stderr or ""
    lower = text.lower()
    login = f"aws sso login --profile {profile}"
    if is_sso_expired(text):
        return f"The AWS SSO session of profile {profile} has expired: run `{login}`."
    if any(s in lower for s in _EXPIRED_MARKERS):
        return (
            f"The AWS credentials of profile {profile} have expired. For an SSO profile run "
            f"`{login}`; otherwise refresh the credentials."
        )
    if "config profile" in lower and "could not be found" in lower:
        return f"AWS profile {profile} was not found in the AWS CLI configuration."
    if "unable to locate credentials" in lower or "nocredentials" in lower:
        return f"The AWS CLI found no credentials for profile {profile}."
    if any(s in lower for s in _REJECTED_MARKERS):
        return f"AWS rejected the credentials of profile {profile}."
    if "targetnotconnected" in lower or "invalidinstanceid" in lower:
        return (
            "The instance is not connected to Systems Manager (stopped, SSM agent not running, "
            "or no instance role). If it was replaced, try again: a cached instance ID is looked "
            "up anew. Also check the instance ID set on this server, if any."
        )
    if any(s in lower for s in _DENIED_MARKERS):
        return f"Profile {profile} is not allowed to do this in AWS (access denied)."
    if "sessionmanagerplugin is not found" in lower:
        return PLUGIN_MISSING
    if re.search(r"\baws: (command )?not found", lower):
        return AWS_MISSING
    if "provided region_name" in lower or "invalid endpoint" in lower:
        return "The AWS region is not valid. Check the region in Settings or on this server."
    if "could not connect to the endpoint url" in lower or "connect timeout on endpoint" in lower:
        return (
            "AWS could not be reached from this machine. Check the network, HTTPS_PROXY and the "
            "AWS region."
        )
    return None


def clean_session_stderr(stderr: str) -> str:
    """ssh stderr over SSM without the session plugin's start/exit lines (they would hide the
    real last line) and with ARNs removed (they carry the account ID and the role)."""
    kept = [line for line in stderr.splitlines() if not _SESSION_NOISE_RE.match(line)]
    return _ARN_RE.sub("<arn>", "\n".join(kept))


def _failure(stderr: str, profile: str, action: str) -> str:
    known = describe_aws_error(stderr, profile)
    if known:
        return known
    lines = [line.strip() for line in clean_session_stderr(stderr).splitlines() if line.strip()]
    return f"{action} failed: {lines[-1][:300]}" if lines else f"{action} failed."


# --- running the aws CLI ---------------------------------------------------------------


def _run(command: list[str], runner: Runner, missing: str, action: str):
    """Run one local command. Raises :class:`SsmError` when it cannot be run at all."""
    try:
        return runner(
            command,
            capture_output=True,
            text=True,
            timeout=AWS_TIMEOUT_SECONDS,
            stdin=subprocess.DEVNULL,
            check=False,
            env=ssm_plugin.aws_env(),  # finds the app-managed plugin too
        )
    except FileNotFoundError:
        raise SsmError(missing) from None
    except subprocess.TimeoutExpired:
        raise SsmError(f"{action} did not finish within {AWS_TIMEOUT_SECONDS}s.") from None
    except OSError as exc:
        raise SsmError(f"{action} could not be run: {exc.strerror or exc}") from None


def preflight(profile: str, region: str, runner: Runner = subprocess.run) -> None:
    """The aws CLI and the plugin are installed and the profile works. Raises
    :class:`SsmError`. The identity sts answers with is neither kept nor logged."""
    for binary, missing in ((AWS_BINARY, AWS_MISSING), (PLUGIN_BINARY, PLUGIN_MISSING)):
        proc = _run([binary, "--version"], runner, missing, f"'{binary} --version'")
        if proc.returncode != 0:
            raise SsmError(f"'{binary} --version' failed (exit {proc.returncode}).")
    proc = _caller_identity(profile, region, runner)
    if proc.returncode != 0:
        raise SsmError(_failure(proc.stderr or "", profile, CREDENTIALS_CHECK))


def _caller_identity(profile: str, region: str, runner: Runner):
    return _run(
        [AWS_BINARY, "sts", "get-caller-identity", "--profile", profile, "--region", region],
        runner, AWS_MISSING, CREDENTIALS_CHECK,
    )  # fmt: skip


def private_ip_for(name: str, ip_address: str) -> str | None:
    """The private IPv4 of a server: from an ``ip-a-b-c-d`` name (optionally followed by a
    domain), else its configured IP address."""
    match = _HOST_IP_RE.fullmatch(name or "")
    candidates = [".".join(match.groups()[:4])] if match else []
    for candidate in [*candidates, ip_address]:
        try:
            return str(ipaddress.IPv4Address((candidate or "").strip()))
        except ValueError:
            continue
    return None


def resolve_instance_id(
    private_ip: str, profile: str, region: str, runner: Runner = subprocess.run
) -> str:
    """The one instance with this private IP. Raises :class:`SsmError` otherwise."""
    action = f"Looking up the instance with private IP {private_ip}"
    proc = _run(
        [
            AWS_BINARY, "ec2", "describe-instances",
            "--filters", f"Name=private-ip-address,Values={private_ip}",
            "--query", "Reservations[].Instances[].InstanceId",
            "--output", "json", "--profile", profile, "--region", region,
        ],
        runner, AWS_MISSING, action,
    )  # fmt: skip
    if proc.returncode != 0:
        raise SsmError(_failure(proc.stderr or "", profile, action))
    try:
        found = json.loads(proc.stdout or "")
    except ValueError:
        found = None
    if not isinstance(found, list) or any(check_instance_id(str(i)) for i in found):
        raise SsmError(f"{action} failed: the AWS CLI returned an unexpected answer.")
    instances = list(dict.fromkeys(found))
    where = f"(profile {profile}, region {region})"
    if not instances:
        raise SsmError(
            f"No EC2 instance has the private IP {private_ip} {where}. Check the profile and "
            "region, or set the instance ID on this server."
        )
    if len(instances) > 1:
        raise SsmError(
            f"Several EC2 instances have the private IP {private_ip} {where}: "
            f"{', '.join(instances)}. Set the instance ID on this server."
        )
    return instances[0]


# --- settings --------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectionDefaults:
    connection_type: str = CONNECTION_SSH
    profile: str | None = None
    region: str | None = None


def load_defaults(db) -> ConnectionDefaults:
    stored = db.get_setting(DEFAULT_CONNECTION_SETTING)
    return ConnectionDefaults(
        stored if stored in CONNECTION_TYPES else CONNECTION_SSH,
        db.get_setting(DEFAULT_PROFILE_SETTING) or None,
        db.get_setting(DEFAULT_REGION_SETTING) or None,
    )


def save_defaults(db, connection_type: str, profile: str, region: str) -> None:
    db.set_setting(DEFAULT_CONNECTION_SETTING, connection_type)
    for key, value in ((DEFAULT_PROFILE_SETTING, profile), (DEFAULT_REGION_SETTING, region)):
        if value:
            db.set_setting(key, value)
        else:
            db.delete_setting(key)


def check_defaults(connection_type: str, profile: str, region: str) -> dict[str, str]:
    """Errors of the Settings form per field."""
    errors = {}
    if connection_type not in CONNECTION_TYPES:
        errors["connection_type"] = "Choose SSH (direct) or SSH over SSM."
    if profile and (error := check_aws_profile(profile)):
        errors["aws_profile"] = error
    if region and (error := check_aws_region(region)):
        errors["aws_region"] = error
    if connection_type == CONNECTION_SSM:
        if not profile:
            errors["aws_profile"] = "SSH over SSM as the default needs a default AWS profile."
        if not region:
            errors["aws_region"] = "SSH over SSM as the default needs a default AWS region."
    return errors


def effective_type(server, defaults: ConnectionDefaults) -> str:
    chosen = server.connection_type
    return chosen if chosen in CONNECTION_TYPES else defaults.connection_type


def _aws_settings(server, defaults: ConnectionDefaults) -> tuple[str | None, str | None]:
    return server.aws_profile or defaults.profile, server.aws_region or defaults.region


def _config_error(server, defaults: ConnectionDefaults) -> str | None:
    profile, region = _aws_settings(server, defaults)
    missing = [n for n, v in (("AWS profile", profile), ("AWS region", region)) if not v]
    if missing:
        return (
            f"SSH over SSM needs an {' and an '.join(missing)}. Set the defaults in Settings or "
            "set them on this server."
        )
    if server.instance_id_override and (error := check_instance_id(server.instance_id_override)):
        return error
    return check_aws_profile(profile) or check_aws_region(region)


def config_error(db, server) -> str | None:
    """Why this server's connection settings cannot work. Runs nothing, so pages can call it."""
    defaults = load_defaults(db)
    if effective_type(server, defaults) != CONNECTION_SSM:
        return None
    return _config_error(server, defaults)


def connection_view(db, server) -> dict:
    """What the server pages show of a connection. Runs nothing."""
    defaults = load_defaults(db)
    kind = effective_type(server, defaults)
    view = {
        "type": kind,
        "label": CONNECTION_TYPES[kind],
        "from_default": server.connection_type not in CONNECTION_TYPES,
        "instance_id": None,
        "instance_source": None,
        "profile": None,
        "region": None,
    }
    if kind != CONNECTION_SSM:
        return view
    view["profile"], view["region"] = _aws_settings(server, defaults)
    if server.instance_id_override:
        view["instance_id"], view["instance_source"] = server.instance_id_override, "set manually"
        return view
    ip = private_ip_for(server.name, server.ip_address)
    if ip and view["profile"] and view["region"]:
        cached = db.get_instance_mapping(ip, view["profile"], view["region"])
        if cached:
            view["instance_id"], view["instance_source"] = cached, "resolved"
    return view


# --- status shown in Settings -------------------------------------------------------------


PROFILE_OK = "ok"
PROFILE_SSO_EXPIRED = "sso_expired"
PROFILE_FAILED = "failed"
PROFILE_NOT_CHECKED = "not_checked"


@dataclass(frozen=True)
class ToolStatus:
    found: bool
    version: str | None = None
    path: str | None = None
    managed: bool = False  # the plugin in the app-managed directory


@dataclass(frozen=True)
class ProfileStatus:
    state: str
    message: str
    profile: str | None = None
    region: str | None = None
    hint: str | None = None  # the command that repairs it


@dataclass(frozen=True)
class SsmStatus:
    plugin: ToolStatus
    aws: ToolStatus
    profile: ProfileStatus


def _plugin_status(runner: Runner) -> ToolStatus:
    location = ssm_plugin.find_plugin()
    if location is None:
        return ToolStatus(False)
    version = ssm_plugin.version_of(location.path, runner)
    return ToolStatus(version is not None, version, str(location.path), location.managed)


def _aws_status(runner: Runner) -> ToolStatus:
    try:
        proc = _run([AWS_BINARY, "--version"], runner, AWS_MISSING, "'aws --version'")
    except SsmError:
        return ToolStatus(False)
    if proc.returncode != 0:
        return ToolStatus(False)
    # aws-cli/2.x.y Python/... : only the first word is the CLI's version.
    words = f"{proc.stdout or ''} {proc.stderr or ''}".split()
    return ToolStatus(True, words[0][:64] if words else None)


def _profile_status(defaults: ConnectionDefaults, aws_found: bool, runner: Runner) -> ProfileStatus:
    profile, region = defaults.profile, defaults.region
    if not profile or not region:
        message = "Set the default AWS profile and region above to check them."
        return ProfileStatus(PROFILE_NOT_CHECKED, message, profile, region)
    if not aws_found:
        return ProfileStatus(PROFILE_NOT_CHECKED, "Needs the AWS CLI.", profile, region)
    try:
        proc = _caller_identity(profile, region, runner)
    except SsmError as exc:
        return ProfileStatus(PROFILE_FAILED, str(exc), profile, region)
    if proc.returncode == 0:  # the identity it answers with is neither kept nor shown
        return ProfileStatus(PROFILE_OK, "Profile OK", profile, region)
    stderr = proc.stderr or ""
    if is_sso_expired(stderr):
        login = f"aws sso login --profile {profile}"
        return ProfileStatus(PROFILE_SSO_EXPIRED, "SSO expired", profile, region, login)
    message = _failure(stderr, profile, CREDENTIALS_CHECK)
    return ProfileStatus(PROFILE_FAILED, message, profile, region)


def check_status(db, runner: Runner = subprocess.run) -> SsmStatus:
    """The plugin, the aws CLI and the default profile. This runs them, so pages load it apart."""
    aws = _aws_status(runner)
    profile = _profile_status(load_defaults(db), aws.found, runner)
    return SsmStatus(_plugin_status(runner), aws, profile)


# --- one server's transport ------------------------------------------------------------


@dataclass(frozen=True)
class Transport:
    """How to reach one server: ``target`` is None for direct SSH. With ``error`` the server
    cannot be reached over the chosen transport and nothing may be attempted."""

    label: str
    target: SsmTarget | None = None
    error: str | None = None


@dataclass
class TransportResolver:
    db: object
    runner: Runner = subprocess.run
    _preflights: dict[tuple[str, str], str | None] = field(default_factory=dict)

    def start_run(self) -> None:
        """The preflight runs once per run for each profile and region."""
        self._preflights = {}

    def _preflight_error(self, profile: str, region: str) -> str | None:
        key = (profile, region)
        if key not in self._preflights:
            try:
                preflight(profile, region, self.runner)
                self._preflights[key] = None
            except SsmError as exc:
                logger.warning("SSM preflight failed: %s", exc)
                self._preflights[key] = str(exc)
        return self._preflights[key]

    def for_server(self, server, force_refresh: bool = False) -> Transport:
        """Never raises for an AWS problem: it is reported in ``Transport.error``.
        ``force_refresh``: look a cached instance ID up again."""
        defaults = load_defaults(self.db)
        if effective_type(server, defaults) != CONNECTION_SSM:
            return Transport(CONNECTION_TYPES[CONNECTION_SSH])
        base = CONNECTION_TYPES[CONNECTION_SSM]
        error = _config_error(server, defaults)
        if error:
            return Transport(base, error=error)
        profile, region = _aws_settings(server, defaults)
        unresolved = f"{base} (profile {profile}, region {region})"
        error = self._preflight_error(profile, region)
        if error:
            return Transport(unresolved, error=error)
        try:
            instance_id = self._instance_id(server, profile, region, force_refresh)
        except SsmError as exc:
            logger.warning("SSM target of %s: %s", server.name, exc)
            return Transport(unresolved, error=str(exc))
        target = SsmTarget(instance_id, profile, region)
        return Transport(transport_label(target), target)

    def _instance_id(self, server, profile: str, region: str, force_refresh: bool) -> str:
        if server.instance_id_override:
            return server.instance_id_override
        private_ip = private_ip_for(server.name, server.ip_address)
        if private_ip is None:
            raise SsmError(
                f"Cannot tell the private IP of {server.name}: its name is not ip-a-b-c-d and its "
                "IP address is not IPv4. Set the instance ID on this server."
            )
        if not force_refresh:
            cached = self.db.get_instance_mapping(private_ip, profile, region)
            if cached and not check_instance_id(cached):
                return cached
        instance_id = resolve_instance_id(private_ip, profile, region, self.runner)
        self.db.save_instance_mapping(private_ip, profile, region, instance_id)
        logger.info("Resolved %s (%s) to %s", server.name, private_ip, instance_id)
        return instance_id

    def note_failure(self, target: SsmTarget | None, stderr: str) -> None:
        """Forget a cached instance ID SSM no longer knows, so that a replaced instance is
        found again (a manual override is not cached and stays as it is)."""
        lower = (stderr or "").lower()
        if target and ("targetnotconnected" in lower or "invalidinstanceid" in lower):
            self.db.delete_instance_mapping(target.instance_id)
