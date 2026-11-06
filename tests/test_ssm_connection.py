"""SSH over SSM: ProxyCommand building, instance ID resolution, preflight, expired SSO detection,
the connection settings and schema v16. subprocess is always faked: no aws, ssh or network."""

import logging
import re
import sqlite3
import subprocess

import pytest
from conftest import SUCCESS_STDOUT, FakeSSH
from fastapi.testclient import TestClient
from phase2_fixtures import make_metadata
from phase3_fixtures import IP, SERVER, FakeFetcher, FakeUbuntu, analysis_plan_output
from test_patch_execution import Harness
from test_patch_web import set_staging
from test_ssh_user import _legacy_db, columns
from test_web import upload

from ec2patcher.app import create_app
from ec2patcher.database import _MIGRATIONS, SCHEMA_VERSION, Database
from ec2patcher.models import CONNECTION_SSH, CONNECTION_SSM, CONNECTION_TYPES
from ec2patcher.services import patch_state as ps
from ec2patcher.services import ssh_service, ssm_service
from ec2patcher.services.patch_service import PatchService
from ec2patcher.services.ssm_service import SsmError, SsmTarget, TransportResolver

INSTANCE = "i-0123456789abcdef0"
OTHER_INSTANCE = "i-0fedcba9876543210"
PROFILE = "example"
REGION = "us-east-1"
HOST = "ip-10-0-0-1"
HOST_IP = "10.0.0.1"
TARGET = SsmTarget(INSTANCE, PROFILE, REGION)
SSO_EXPIRED = "Error when retrieving token from sso: Token has expired and refresh failed\n"
SSO_MESSAGE = f"run `aws sso login --profile {PROFILE}`"
RAW_SSH_ERROR = "kex_exchange_identification: Connection closed by remote host\n"
ACCOUNT = "123456789012"
TEST_STDOUT = SUCCESS_STDOUT + "EC2P_UNAME=Linux 6.8.0-1021-aws x86_64\n"


def proxy(port=22, instance=INSTANCE):
    return (
        f"ProxyCommand=aws ssm start-session --target {instance} --document-name "
        f"AWS-StartSSHSession --parameters portNumber={port} --profile {PROFILE} "
        f"--region {REGION}"
    )


def done(args, stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess(args, rc, stdout, stderr)


class FakeAws:
    """Answers the aws CLI and the plugin; ssh and scp go to ``inner``."""

    def __init__(self, inner=None, instances=(INSTANCE,), sts=None, ec2=None, missing=()):
        self.inner = inner or FakeSSH(stdout=TEST_STDOUT)
        self.instances = list(instances)
        self.sts, self.ec2 = sts, ec2  # (exit code, stderr) of a failing call
        self.missing = missing
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []

    def __call__(self, args, **kwargs):
        assert "shell" not in kwargs
        self.calls.append(list(args))
        if args[0] in self.missing:
            raise FileNotFoundError(args[0])
        if args[1:] == ["--version"]:
            return done(args, "version 1\n")
        if args[:2] == ["aws", "sts"]:
            self.envs.append(kwargs.get("env", {}))
            if self.sts:
                return done(args, rc=self.sts[0], stderr=self.sts[1])
            return done(args, f'{{"Account": "{ACCOUNT}"}}')
        if args[:2] == ["aws", "ec2"]:
            if self.ec2:
                return done(args, rc=self.ec2[0], stderr=self.ec2[1])
            return done(args, str(self.instances).replace("'", '"'))
        assert args[0] != "aws", args
        return self.inner(args, **kwargs)

    def count(self, *prefix):
        return sum(1 for call in self.calls if call[: len(prefix)] == list(prefix))

    @property
    def remote_calls(self):
        return [c for c in self.calls if "ssh" in c[:3] or "scp" in c[:3]]


def sync(fn):
    fn()


def ssm_server(db, pem="/k.pem", name=HOST, ip=HOST_IP, **transport):
    return db.create_server(
        name, ip, pem, transport={"connection_type": CONNECTION_SSM, **transport}
    )


@pytest.fixture
def defaults(db):
    ssm_service.save_defaults(db, CONNECTION_SSH, PROFILE, REGION)
    return db


# --- ProxyCommand ------------------------------------------------------------------------


def test_proxy_command_is_exactly_the_session_command():
    assert "ProxyCommand=" + ssm_service.build_proxy_command(TARGET) == proxy()


def test_ssh_command_is_the_direct_command_plus_the_proxy_option(pem_file):
    direct = ssh_service.build_ssh_command(HOST_IP, str(pem_file), "uname")
    over_ssm = ssh_service.build_ssh_command(HOST_IP, str(pem_file), "uname", ssm=TARGET)
    split = direct.index("--")
    assert over_ssm == [*direct[:split], "-o", proxy(), *direct[split:]]
    assert not any("ProxyCommand" in a for a in direct)


def test_scp_command_is_the_direct_command_plus_the_same_proxy_option(pem_file):
    args = (HOST_IP, str(pem_file), ["/x/a.deb"], "/tmp/s")
    direct = ssh_service.build_scp_command(*args)
    over_ssm = ssh_service.build_scp_command(*args, ssm=TARGET)
    split = direct.index("--")
    assert over_ssm == [*direct[:split], "-o", proxy(), *direct[split:]]
    assert not any("ProxyCommand" in a for a in direct)


def test_the_session_uses_the_port_of_the_direct_transport(pem_file):
    ssh = ssh_service.build_ssh_command(HOST_IP, str(pem_file), "uname", port=2222, ssm=TARGET)
    scp = ssh_service.build_scp_command(
        HOST_IP, str(pem_file), ["/x/a"], "/tmp/s", port=2222, ssm=TARGET
    )
    assert ssh[ssh.index("-p") + 1] == "2222" and proxy(2222) in ssh
    assert scp[scp.index("-P") + 1] == "2222" and proxy(2222) in scp


def test_password_login_works_over_ssm():
    password = "fake-test-password"  # noqa: S105
    ssh = ssh_service.build_ssh_command(HOST_IP, "", "uname", password=password, ssm=TARGET)
    scp = ssh_service.build_scp_command(HOST_IP, "", ["/x/a"], "/t", password=password, ssm=TARGET)
    for args, binary in ((ssh, "ssh"), (scp, "scp")):
        assert args[:3] == ["sshpass", "-e", binary] and proxy() in args
        assert all(password not in a for a in args)
    fake = FakeSSH(stdout=TEST_STDOUT)
    assert ssh_service.run_remote(HOST_IP, "", "uname", fake, password=password, ssm=TARGET).ok
    assert fake.calls[0][1]["env"]["SSHPASS"] == password


@pytest.mark.parametrize(
    "target",
    [
        SsmTarget("i-123; touch /tmp/x", PROFILE, REGION),
        SsmTarget("$(id)", PROFILE, REGION),
        SsmTarget(INSTANCE, "a b", REGION),
        SsmTarget(INSTANCE, "a;id", REGION),
        SsmTarget(INSTANCE, "$(id)", REGION),
        SsmTarget(INSTANCE, "`id`", REGION),
        SsmTarget(INSTANCE, "%h", REGION),
        SsmTarget(INSTANCE, "--debug", REGION),
        SsmTarget(INSTANCE, "a\nb", REGION),
        SsmTarget(INSTANCE, PROFILE, "us-east-1|id"),
        SsmTarget(INSTANCE, PROFILE, "us-east-1\n"),
    ],
)
def test_values_unsafe_for_the_proxy_shell_never_reach_a_command(target, pem_file):
    with pytest.raises(ValueError):
        ssm_service.build_proxy_command(target)
    fake = FakeSSH()
    assert not ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake, ssm=target).ok
    assert not ssh_service.run_scp(HOST_IP, str(pem_file), ["/x"], "/t", fake, ssm=target).ok
    assert not ssh_service.check_connection("s", HOST_IP, str(pem_file), fake, ssm=target).success
    assert fake.calls == []


@pytest.mark.parametrize("port", [0, 65536, True, "22; id"])
def test_invalid_port_never_reaches_the_proxy_command(port):
    with pytest.raises(ValueError):
        ssm_service.build_proxy_command(TARGET, port)


@pytest.mark.parametrize("profile", ["example", "Team_A-prod", "a.b@c+d=e,f:g/h"])
def test_usual_profile_names_are_accepted(profile):
    assert f"--profile {profile} " in ssm_service.build_proxy_command(
        SsmTarget(INSTANCE, profile, REGION)
    )


# --- ip-a-b-c-d -> instance ID -----------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "ip", "expected"),
    [
        ("ip-10-0-0-1", "192.0.2.10", "10.0.0.1"),  # the name wins
        ("IP-10-0-0-1", "192.0.2.10", "10.0.0.1"),
        ("ip-10-0-0-1.ec2.internal", "192.0.2.10", "10.0.0.1"),
        ("app-prod-01", "192.0.2.10", "192.0.2.10"),
        ("ip-999-0-0-1", "192.0.2.10", "192.0.2.10"),  # not an address
        ("ip-10-0-0", "192.0.2.10", "192.0.2.10"),
        ("app-prod-01", "2001:db8::1", None),
        ("app-prod-01", "", None),
    ],
)
def test_private_ip_of_a_server(name, ip, expected):
    assert ssm_service.private_ip_for(name, ip) == expected


def test_resolution_filters_on_the_private_ip_with_the_profile_and_region():
    fake = FakeAws()
    assert ssm_service.resolve_instance_id(HOST_IP, PROFILE, REGION, fake) == INSTANCE
    args = fake.calls[0]
    assert args[:3] == ["aws", "ec2", "describe-instances"]
    assert args[args.index("--filters") + 1] == f"Name=private-ip-address,Values={HOST_IP}"
    assert args[args.index("--profile") + 1] == PROFILE
    assert args[args.index("--region") + 1] == REGION


def test_resolution_without_a_match_is_a_clear_message():
    with pytest.raises(SsmError, match=f"No EC2 instance has the private IP {HOST_IP}"):
        ssm_service.resolve_instance_id(HOST_IP, PROFILE, REGION, FakeAws(instances=()))


def test_resolution_with_several_matches_names_them():
    fake = FakeAws(instances=(INSTANCE, OTHER_INSTANCE))
    with pytest.raises(SsmError) as exc:
        ssm_service.resolve_instance_id(HOST_IP, PROFILE, REGION, fake)
    assert "Several EC2 instances" in str(exc.value)
    assert INSTANCE in str(exc.value) and OTHER_INSTANCE in str(exc.value)


@pytest.mark.parametrize("stdout", ["not json", '{"a": 1}', '["i-bad; id"]', "[1]", ""])
def test_resolution_rejects_an_unexpected_answer(stdout):
    def runner(args, **kwargs):
        return done(args, stdout)

    with pytest.raises(SsmError, match="unexpected answer"):
        ssm_service.resolve_instance_id(HOST_IP, PROFILE, REGION, runner)


def test_resolved_instance_is_cached_in_sqlite(defaults, db_path):
    server = ssm_server(defaults)
    fake = FakeAws()
    assert TransportResolver(defaults, fake).for_server(server).target == TARGET
    assert fake.count("aws", "ec2") == 1
    # A new process: from the database, without another lookup.
    resolver = TransportResolver(Database(db_path), fake)
    assert resolver.for_server(server).target == TARGET
    assert fake.count("aws", "ec2") == 1
    assert defaults.get_instance_mapping(HOST_IP, PROFILE, REGION) == INSTANCE


def test_cache_is_per_profile_and_region(defaults):
    fake = FakeAws()
    TransportResolver(defaults, fake).for_server(ssm_server(defaults))
    other = ssm_server(defaults, name="other", aws_region="eu-west-1", ip=HOST_IP)
    fake.instances = [OTHER_INSTANCE]
    target = TransportResolver(defaults, fake).for_server(other).target
    assert target == SsmTarget(OTHER_INSTANCE, PROFILE, "eu-west-1")
    assert fake.count("aws", "ec2") == 2


def test_force_refresh_looks_the_instance_up_again(defaults):
    server = ssm_server(defaults)
    fake = FakeAws()
    TransportResolver(defaults, fake).for_server(server)
    fake.instances = [OTHER_INSTANCE]
    resolver = TransportResolver(defaults, fake)
    assert resolver.for_server(server).target.instance_id == INSTANCE
    assert resolver.for_server(server, force_refresh=True).target.instance_id == OTHER_INSTANCE
    assert defaults.get_instance_mapping(HOST_IP, PROFILE, REGION) == OTHER_INSTANCE


def test_manual_override_always_wins(defaults):
    defaults.save_instance_mapping(HOST_IP, PROFILE, REGION, INSTANCE)
    server = ssm_server(defaults, instance_id_override=OTHER_INSTANCE)
    fake = FakeAws(instances=(INSTANCE, "i-0aaaaaaaaaaaaaaaa"))  # would be ambiguous
    transport = TransportResolver(defaults, fake).for_server(server, force_refresh=True)
    assert transport.error is None and transport.target.instance_id == OTHER_INSTANCE
    assert fake.count("aws", "ec2") == 0
    assert fake.count("aws", "sts") == 1  # the profile must still work


@pytest.mark.parametrize(
    ("fake", "expected"),
    [
        (FakeAws(instances=()), "No EC2 instance"),
        (FakeAws(instances=(INSTANCE, OTHER_INSTANCE)), "Several EC2 instances"),
        (FakeAws(ec2=(255, SSO_EXPIRED)), SSO_MESSAGE),
        (FakeAws(ec2=(253, "Unable to locate credentials.")), "no credentials"),
        (FakeAws(ec2=(254, "An error occurred (UnauthorizedOperation)")), "access denied"),
    ],
)
def test_resolution_failures_are_per_server_messages_not_exceptions(defaults, fake, expected):
    transport = TransportResolver(defaults, fake).for_server(ssm_server(defaults))
    assert expected in transport.error and transport.target is None
    assert defaults.get_instance_mapping(HOST_IP, PROFILE, REGION) is None


def test_server_without_a_usable_ip_asks_for_the_instance_id(defaults):
    server = ssm_server(defaults, name="app-01", ip="2001:db8::1")
    transport = TransportResolver(defaults, FakeAws()).for_server(server)
    assert "Set the instance ID" in transport.error


def test_replaced_instance_is_looked_up_again_after_ssm_rejects_it(defaults):
    server = ssm_server(defaults)
    fake = FakeAws()
    resolver = TransportResolver(defaults, fake)
    target = resolver.for_server(server).target
    resolver.note_failure(target, "Connection reset")  # unrelated: the mapping stays
    assert defaults.get_instance_mapping(HOST_IP, PROFILE, REGION) == INSTANCE
    resolver.note_failure(target, "An error occurred (TargetNotConnected) when calling ...")
    assert defaults.get_instance_mapping(HOST_IP, PROFILE, REGION) is None
    fake.instances = [OTHER_INSTANCE]
    assert resolver.for_server(server).target.instance_id == OTHER_INSTANCE


# --- preflight and expired SSO sessions ----------------------------------------------------


def test_preflight_checks_cli_plugin_and_profile():
    fake = FakeAws()
    ssm_service.preflight(PROFILE, REGION, fake)
    assert fake.calls == [
        ["aws", "--version"],
        ["session-manager-plugin", "--version"],
        ["aws", "sts", "get-caller-identity", "--profile", PROFILE, "--region", REGION],
    ]


def test_preflight_reports_a_missing_cli():
    with pytest.raises(SsmError, match="'aws' command was not found"):
        ssm_service.preflight(PROFILE, REGION, FakeAws(missing=("aws",)))


def test_preflight_reports_a_missing_plugin():
    with pytest.raises(SsmError, match="session-manager-plugin"):
        ssm_service.preflight(PROFILE, REGION, FakeAws(missing=("session-manager-plugin",)))


def test_preflight_reports_a_timeout():
    def runner(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 30)

    with pytest.raises(SsmError, match="did not finish"):
        ssm_service.preflight(PROFILE, REGION, runner)


@pytest.mark.parametrize(
    "stderr",
    [
        SSO_EXPIRED,
        "The SSO session associated with this profile has expired or is otherwise invalid. "
        "To refresh this SSO session run aws sso login with the corresponding profile.",
        "Error loading SSO Token: Token for example does not exist",
        "botocore.exceptions.UnauthorizedSSOTokenError: ...",
    ],
)
def test_preflight_detects_an_expired_sso_session(stderr):
    with pytest.raises(SsmError) as exc:
        ssm_service.preflight(PROFILE, REGION, FakeAws(sts=(255, stderr)))
    assert SSO_MESSAGE in str(exc.value)


@pytest.mark.parametrize(
    ("stderr", "expected"),
    [
        ("An error occurred (ExpiredToken) when calling ...", "have expired"),
        ("The config profile (example) could not be found", "was not found"),
        ("Unable to locate credentials.", "no credentials"),
        ("An error occurred (InvalidClientTokenId) when calling ...", "rejected"),
        ("Could not connect to the endpoint URL: ...", "could not be reached"),
    ],
)
def test_preflight_explains_other_profile_problems(stderr, expected):
    with pytest.raises(SsmError, match=expected):
        ssm_service.preflight(PROFILE, REGION, FakeAws(sts=(255, stderr)))


def test_unknown_aws_failure_shows_its_last_line_without_arns():
    stderr = f"User arn:aws:iam::{ACCOUNT}:user/someone hit something odd\n"
    with pytest.raises(SsmError) as exc:
        ssm_service.preflight(PROFILE, REGION, FakeAws(sts=(1, stderr)))
    assert "hit something odd" in str(exc.value) and ACCOUNT not in str(exc.value)


def test_expired_sso_during_ssh_is_not_a_raw_ssh_error(pem_file):
    fake = FakeSSH(returncode=255, stderr=SSO_EXPIRED + RAW_SSH_ERROR)
    result = ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake, ssm=TARGET)
    assert not result.ok and SSO_MESSAGE in result.error and "kex_exchange" not in result.error


def test_expired_sso_during_scp_is_not_a_raw_ssh_error(pem_file):
    fake = FakeSSH(returncode=1, stderr=SSO_EXPIRED + RAW_SSH_ERROR)
    result = ssh_service.run_scp(HOST_IP, str(pem_file), ["/x"], "/t", fake, ssm=TARGET)
    assert not result.ok and SSO_MESSAGE in result.error


def test_expired_sso_during_the_connection_test_is_not_a_raw_ssh_error(pem_file):
    fake = FakeSSH(returncode=255, stderr=SSO_EXPIRED + RAW_SSH_ERROR)
    result = ssh_service.check_connection("s", HOST_IP, str(pem_file), fake, ssm=TARGET)
    assert not result.success and SSO_MESSAGE in result.error


def test_direct_ssh_never_reads_stderr_as_an_aws_error(pem_file):
    fake = FakeSSH(returncode=255, stderr="Token has expired and refresh failed\n")
    result = ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake)
    assert result.error.startswith("SSH connection failed:")


def test_session_plugin_lines_do_not_hide_the_remote_error(pem_file):
    stderr = (
        "Starting session with SessionId: abc\nreal problem\nExiting session with sessionId: abc\n"
    )
    fake = FakeSSH(returncode=3, stderr=stderr)
    result = ssh_service.run_remote(HOST_IP, str(pem_file), "false", fake, ssm=TARGET)
    assert result.error == "Remote command failed (exit 3): real problem"
    assert "SessionId" not in result.stderr


def test_login_banner_is_not_mistaken_for_an_aws_error(pem_file):
    stderr = "If you are not authorized, disconnect now.\nPermission denied (publickey).\n"
    fake = FakeSSH(returncode=255, stderr=stderr)
    result = ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake, ssm=TARGET)
    assert result.error == "Permission denied (publickey). Check the PEM file matches this server."


def test_ssm_rejections_over_ssh_are_explained(pem_file):
    stderr = "An error occurred (TargetNotConnected) when calling the StartSession operation\n"
    fake = FakeSSH(returncode=255, stderr=stderr + RAW_SSH_ERROR)
    result = ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake, ssm=TARGET)
    assert "not connected to Systems Manager" in result.error


def test_preflight_runs_once_per_run_for_each_profile(defaults):
    fake = FakeAws()
    resolver = TransportResolver(defaults, fake)
    first = ssm_server(defaults)
    second = ssm_server(defaults, name="ip-10-0-0-2", ip="10.0.0.2")
    third = ssm_server(defaults, name="third", aws_profile="other")
    for server in (first, second, third):
        resolver.for_server(server)
    assert fake.count("aws", "sts") == 2  # example once, other once
    resolver.start_run()
    resolver.for_server(first)
    assert fake.count("aws", "sts") == 3


def test_failed_preflight_is_reported_for_every_server_of_the_run(defaults):
    fake = FakeAws(sts=(255, SSO_EXPIRED))
    resolver = TransportResolver(defaults, fake)
    errors = [
        resolver.for_server(ssm_server(defaults)).error,
        resolver.for_server(ssm_server(defaults, name="ip-10-0-0-2", ip="10.0.0.2")).error,
    ]
    assert all(SSO_MESSAGE in error for error in errors)
    assert fake.count("aws", "sts") == 1 and fake.count("aws", "ec2") == 0


def test_direct_servers_run_nothing_in_aws(db):
    fake = FakeAws()
    server = db.create_server("direct", HOST_IP, "/k.pem")
    transport = TransportResolver(db, fake).for_server(server)
    assert transport.label == "SSH (direct)" and transport.target is None and not transport.error
    assert fake.calls == []


@pytest.mark.parametrize(
    ("settings", "missing"),
    [
        ((None, None), "AWS profile and an AWS region"),
        ((PROFILE, None), "AWS region"),
        ((None, REGION), "AWS profile"),
    ],
)
def test_missing_profile_or_region_is_a_clear_message(db, settings, missing):
    ssm_service.save_defaults(db, CONNECTION_SSH, settings[0] or "", settings[1] or "")
    server = ssm_server(db)
    assert missing in ssm_service.config_error(db, server)
    fake = FakeAws()
    assert missing in TransportResolver(db, fake).for_server(server).error
    assert fake.calls == []


# --- connection type: per server, default in Settings --------------------------------------


def test_server_follows_the_default_until_it_has_its_own_type(defaults):
    plain = defaults.create_server("plain", HOST_IP, "/k.pem")
    chosen = defaults.create_server(
        "chosen", HOST_IP, "/k.pem", transport={"connection_type": CONNECTION_SSH}
    )
    fake = FakeAws()
    resolver = TransportResolver(defaults, fake)
    assert resolver.for_server(plain).target is None
    ssm_service.save_defaults(defaults, CONNECTION_SSM, PROFILE, REGION)
    assert resolver.for_server(plain).target == TARGET
    assert resolver.for_server(chosen).target is None


def test_server_profile_and_region_override_the_defaults(defaults):
    server = ssm_server(defaults, aws_profile="other", aws_region="eu-west-1")
    target = TransportResolver(defaults, FakeAws()).for_server(server).target
    assert (target.profile, target.region) == ("other", "eu-west-1")


def test_labels_are_the_required_ones():
    assert CONNECTION_TYPES == {"ssh": "SSH (direct)", "ssm": "SSH over SSM"}
    assert ssm_service.transport_label(None) == "SSH (direct)"
    assert ssm_service.transport_label(TARGET).startswith("SSH over SSM (" + INSTANCE)


def form_data(pem, **extra):
    return {
        "name": HOST,
        "ip_address": HOST_IP,
        "pem_path": str(pem),
        "ssh_user": "ubuntu",
        **extra,
    }


def test_settings_page_saves_the_defaults(client, db_path):
    page = client.get("/settings").text
    assert "Default connection type" in page and "SSH over SSM" in page
    r = client.post(
        "/settings/connection",
        data={"connection_type": "ssm", "aws_profile": PROFILE, "aws_region": REGION},
    )
    assert r.status_code == 200 and "Connection defaults saved" in r.text
    assert ssm_service.load_defaults(Database(db_path)) == ssm_service.ConnectionDefaults(
        CONNECTION_SSM, PROFILE, REGION
    )
    assert f'value="{PROFILE}"' in client.get("/settings").text


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        ({"connection_type": "ssm", "aws_region": REGION}, "needs a default AWS profile"),
        ({"connection_type": "ssm", "aws_profile": PROFILE}, "needs a default AWS region"),
        ({"connection_type": "ssh", "aws_profile": "a;id"}, "AWS profile may only contain"),
        ({"connection_type": "ssh", "aws_region": "nowhere"}, "must look like us-east-1"),
        ({"connection_type": "ftp"}, "Choose SSH (direct) or SSH over SSM"),
    ],
)
def test_settings_page_rejects_bad_defaults(client, db_path, data, expected):
    r = client.post("/settings/connection", data=data)
    assert r.status_code == 422 and expected in r.text
    assert ssm_service.load_defaults(Database(db_path)).connection_type == CONNECTION_SSH


def test_switch_all_servers_clears_the_per_server_types(client, db_path):
    db = Database(db_path)
    db.create_server("a", HOST_IP, "/k.pem", transport={"connection_type": CONNECTION_SSH})
    db.create_server("b", "10.0.0.2", "/k.pem", transport={"connection_type": CONNECTION_SSM})
    db.create_server("c", "10.0.0.3", "/k.pem")
    data = {"connection_type": "ssm", "aws_profile": PROFILE, "aws_region": REGION}
    r = client.post("/settings/connection", data={**data, "action": "apply_all"})
    assert "Every server now follows them (2 per-server" in r.text
    assert all(s.connection_type is None for s in db.list_servers())
    defaults = ssm_service.load_defaults(db)
    assert {ssm_service.effective_type(s, defaults) for s in db.list_servers()} == {CONNECTION_SSM}


def test_plain_save_keeps_the_per_server_types(client, db_path):
    db = Database(db_path)
    db.create_server("a", HOST_IP, "/k.pem", transport={"connection_type": CONNECTION_SSH})
    client.post("/settings/connection", data={"connection_type": "ssm", "aws_profile": PROFILE,
                                              "aws_region": REGION})  # fmt: skip
    assert db.get_server_by_name("a").connection_type == CONNECTION_SSH


def test_server_form_saves_the_connection_fields(client, db_path, pem_file):
    fields = {
        "connection_type": "ssm", "instance_id_override": INSTANCE, "aws_profile": PROFILE,
        "aws_region": REGION,
    }  # fmt: skip
    r = client.post("/servers/new", data=form_data(pem_file, **fields))
    assert r.status_code == 200
    server = Database(db_path).get_server_by_name(HOST)
    assert server.connection_type == CONNECTION_SSM and server.instance_id_override == INSTANCE
    assert (server.aws_profile, server.aws_region) == (PROFILE, REGION)
    assert "SSH over SSM" in r.text and INSTANCE in r.text and "set manually" in r.text
    assert f'value="{INSTANCE}"' in client.get(f"/servers/{server.id}/edit").text


def test_new_server_follows_the_default_and_keeps_pem_and_user(client, db_path, pem_file):
    client.post("/servers/new", data=form_data(pem_file))
    server = Database(db_path).get_server_by_name(HOST)
    assert server.connection_type is None and server.pem_path == str(pem_file)
    assert "SSH (direct)" in client.get("/servers").text


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("connection_type", "telnet", "Choose SSH (direct) or SSH over SSM"),
        ("instance_id_override", "i-1; id", "Instance ID must look like"),
        ("aws_profile", "a b", "AWS profile may only contain"),
        ("aws_region", "us east", "must look like us-east-1"),
    ],
)
def test_server_form_rejects_bad_connection_fields(
    client, db_path, pem_file, field, value, expected
):
    r = client.post("/servers/new", data=form_data(pem_file, **{field: value}))
    assert r.status_code == 422 and expected in r.text
    assert Database(db_path).count_servers() == 0


def test_editing_without_the_connection_fields_keeps_them_and_empty_clears(
    client, db_path, pem_file
):
    db = Database(db_path)
    server = db.create_server(
        HOST, HOST_IP, str(pem_file),
        transport={"connection_type": CONNECTION_SSM, "instance_id_override": INSTANCE},
    )  # fmt: skip
    client.post(f"/servers/{server.id}/edit", data=form_data(pem_file))
    kept = db.get_server(server.id)
    assert kept.connection_type == CONNECTION_SSM and kept.instance_id_override == INSTANCE
    client.post(
        f"/servers/{server.id}/edit",
        data=form_data(pem_file, connection_type="", instance_id_override=""),
    )
    cleared = db.get_server(server.id)
    assert cleared.connection_type is None and cleared.instance_id_override is None


# --- Test connection -----------------------------------------------------------------------


def saved_ssm_server(db_path, pem_file):
    db = Database(db_path)
    ssm_service.save_defaults(db, CONNECTION_SSH, PROFILE, REGION)
    return ssm_server(db, str(pem_file))


def test_test_connection_runs_uname_over_ssm(make_client, db_path, pem_file):
    server = saved_ssm_server(db_path, pem_file)
    fake = FakeAws()
    with make_client(fake) as c:
        page = c.post(f"/servers/{server.id}/test").text
    assert "SSH CONNECTION SUCCESSFUL" in page and "Linux 6.8.0-1021-aws x86_64" in page
    assert f"SSH over SSM ({INSTANCE}, profile {PROFILE}, region {REGION})" in page
    args = fake.remote_calls[-1]
    assert proxy() in args and "uname" in args[-1]


def test_test_connection_shows_the_direct_transport(make_client, db_path, pem_file):
    server = Database(db_path).create_server(HOST, HOST_IP, str(pem_file))
    fake = FakeAws()
    with make_client(fake) as c:
        page = c.post(f"/servers/{server.id}/test").text
    assert "Test connection" in page and "SSH (direct)" in page
    assert "uname" in fake.calls[0][-1] and not any("ProxyCommand" in a for a in fake.calls[0])
    assert fake.count("aws") == 0


def test_test_connection_reports_an_expired_sso_session(make_client, db_path, pem_file):
    server = saved_ssm_server(db_path, pem_file)
    fake = FakeAws(sts=(255, SSO_EXPIRED))
    with make_client(fake) as c:
        page = c.post(f"/servers/{server.id}/test").text
    assert "SSH CONNECTION FAILED" in page and SSO_MESSAGE in page
    assert fake.remote_calls == []


def test_test_connection_repairs_a_stale_cached_instance(make_client, db_path, pem_file):
    server = saved_ssm_server(db_path, pem_file)
    Database(db_path).save_instance_mapping(HOST_IP, PROFILE, REGION, OTHER_INSTANCE)
    fake = FakeAws()
    with make_client(fake) as c:
        c.post(f"/servers/{server.id}/test")
    assert proxy() in fake.remote_calls[-1]
    assert Database(db_path).get_instance_mapping(HOST_IP, PROFILE, REGION) == INSTANCE


def test_form_test_uses_the_typed_connection_without_saving(make_client, db_path, pem_file):
    fake = FakeAws()
    data = form_data(
        pem_file, action="test", connection_type="ssm", instance_id_override=INSTANCE,
        aws_profile=PROFILE, aws_region=REGION,
    )  # fmt: skip
    with make_client(fake) as c:
        page = c.post("/servers/new", data=data).text
    assert "SSH CONNECTION SUCCESSFUL" in page and proxy() in fake.remote_calls[-1]
    assert Database(db_path).count_servers() == 0


def test_form_test_refuses_an_unsafe_typed_value(make_client, db_path, pem_file):
    fake = FakeAws()
    data = form_data(
        pem_file, action="test", connection_type="ssm", instance_id_override=INSTANCE,
        aws_profile="$(id)", aws_region=REGION,
    )  # fmt: skip
    with make_client(fake) as c:
        page = c.post("/servers/new", data=data).text
    assert "AWS profile may only contain" in page and fake.calls == []


# --- analysis and patching keep working, over either transport ------------------------------


def make_ssm_app(db_path, tmp_path, fake_apt, aws):
    fake_apt.plan = analysis_plan_output()
    return create_app(
        db_path=db_path, ssh_runner=aws, metadata=make_metadata(tmp_path), analysis_starter=sync,
        patch_starter=sync, patch_fetcher=FakeFetcher(), shutdown_handler=lambda: None,
    )  # fmt: skip


def test_analysis_and_patching_over_ssm_end_to_end(db_path, tmp_path, fake_apt, pem_file, caplog):
    caplog.set_level(logging.INFO)
    ubuntu = FakeUbuntu(plan_output=analysis_plan_output())
    aws = FakeAws(inner=ubuntu)
    app = make_ssm_app(db_path, tmp_path, fake_apt, aws)
    with TestClient(app, base_url="http://127.0.0.1") as c:
        c.post(
            "/settings/connection",
            data={"connection_type": "ssm", "aws_profile": PROFILE, "aws_region": REGION},
        )
        Database(db_path).create_server(SERVER, IP, str(pem_file))
        set_staging(c, tmp_path)
        upload(c, {SERVER: ["CVE-2026-63076", "CVE-2026-54874", "CVE-2026-63075"]})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        run_page = c.get(run_url).text
        report_url = re.findall(r'href="(/analysis/\d+/servers/\d+)"', run_page)[0]
        label = f"SSH over SSM ({INSTANCE}, profile {PROFILE}, region {REGION})"
        assert label in run_page and label in c.get(report_url).text
        r = c.post(f"{report_url}/approve", data={"confirm": "yes"}, follow_redirects=False)
        result = c.get(r.headers["location"]).text
    assert "PATCH SUCCESSFUL" in result and label in result
    assert ubuntu.ops.count("install") == 1
    # Every ssh and scp of analysis and patching carried the ProxyCommand.
    assert {c[0] for c in aws.remote_calls} == {"ssh", "scp"}
    assert all(proxy() in call for call in aws.remote_calls)
    logs = caplog.text
    assert f"Analysis of {SERVER}: transport: {label}" in logs
    assert re.search(rf"Patch execution \d+: transport: {re.escape(label)}", logs)


def test_failed_preflight_fails_only_the_ssm_servers_of_a_run(
    db_path, tmp_path, fake_apt, pem_file
):
    ubuntu = FakeUbuntu(plan_output=analysis_plan_output())
    aws = FakeAws(inner=ubuntu, sts=(255, SSO_EXPIRED))
    app = make_ssm_app(db_path, tmp_path, fake_apt, aws)
    db = Database(db_path)
    ssm_service.save_defaults(db, CONNECTION_SSH, PROFILE, REGION)
    db.create_server(SERVER, IP, str(pem_file))
    ssm_server(db, str(pem_file))
    ssm_server(db, str(pem_file), name="ip-10-0-0-2", ip="10.0.0.2")
    with TestClient(app, base_url="http://127.0.0.1") as c:
        cves = ["CVE-2026-63076"]
        upload(c, {SERVER: cves, HOST: cves, "ip-10-0-0-2": cves})
        run_url = c.post("/reports/analyze", follow_redirects=False).headers["location"]
        page = c.get(run_url).text
    run = db.get_latest_analysis_run()
    by_name = {s.server_name: s for s in db.get_analysis_run(run.id, details=False).servers}
    assert by_name[SERVER].status == "complete" and by_name[SERVER].transport == "SSH (direct)"
    for name in (HOST, "ip-10-0-0-2"):
        assert by_name[name].status == "failed" and SSO_MESSAGE in by_name[name].error
    assert SSO_MESSAGE in page
    assert aws.count("aws", "sts") == 1  # once per run
    assert all("ProxyCommand" not in " ".join(call) for call in aws.remote_calls)


class SsmHarness(Harness):
    """The patch harness with the server switched to SSH over SSM."""

    def __init__(self, db, pem, tmp_path, **aws):
        super().__init__(db, pem, tmp_path)
        ssm_service.save_defaults(db, CONNECTION_SSM, PROFILE, REGION)
        self.aws = FakeAws(inner=self.fake, **aws)
        self.service = PatchService(db, runner=self.aws, starter=sync, fetcher=self.fetch)


def test_patch_is_refused_at_approval_without_a_profile(db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path)
    db.delete_setting(ssm_service.DEFAULT_PROFILE_SETTING)
    check = h.service.eligibility(h.analysis())
    assert not check.allowed and any("AWS profile" in reason for reason in check.reasons)
    assert h.aws.calls == []  # rendering a page never runs the aws CLI


def test_eligibility_never_runs_the_aws_cli(db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path, sts=(255, SSO_EXPIRED))
    assert h.service.eligibility(h.analysis()).allowed
    assert h.aws.calls == []


def test_expired_sso_stops_a_patch_before_anything_happens(db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path, sts=(255, SSO_EXPIRED))
    ex = h.approve()
    assert ex.state == ps.FAILED and SSO_MESSAGE in ex.error_summary
    assert ex.transport == f"SSH over SSM (profile {PROFILE}, region {REGION})"
    assert h.aws.remote_calls == [] and h.fake.calls == []  # no ssh, no download


def test_patch_preflight_runs_per_execution(db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path)
    h.approve()
    assert h.aws.count("aws", "sts") == 1
    h.service.transports.start_run()
    h.service.transports.for_server(h.server)
    assert h.aws.count("aws", "sts") == 2


def test_patch_over_ssm_uses_the_proxy_for_every_connection(db, pem_file, tmp_path):
    h = SsmHarness(db, pem_file, tmp_path)
    ex = h.approve()
    assert ex.state == ps.SUCCESS and ex.transport.startswith("SSH over SSM (" + INSTANCE)
    assert {call[0] for call in h.aws.remote_calls} == {"ssh", "scp"}
    assert all(proxy() in call for call in h.aws.remote_calls)
    assert h.fake.ops.count("install") == 1


def test_patch_over_direct_ssh_is_unchanged(h_direct):
    ex = h_direct.approve()
    assert ex.state == ps.SUCCESS and ex.transport == "SSH (direct)"
    assert h_direct.fake.ops.count("install") == 1


@pytest.fixture
def h_direct(db, pem_file, tmp_path):
    return Harness(db, pem_file, tmp_path)


def test_no_credential_or_identity_is_kept_or_logged(db, caplog):
    caplog.set_level(logging.DEBUG)
    ssm_service.save_defaults(db, CONNECTION_SSH, PROFILE, REGION)
    aws = FakeAws()
    TransportResolver(db, aws).for_server(ssm_server(db))
    assert ACCOUNT not in caplog.text
    with db.connect() as conn:
        dump = "\n".join(line for line in conn.iterdump())
    assert ACCOUNT not in dump
    assert "SSHPASS" not in aws.envs[0]


# --- schema v16 ----------------------------------------------------------------------------


def test_fresh_database_is_v16_with_the_connection_schema(db_path):
    db = Database(db_path)
    with sqlite3.connect(db_path) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 19
    conn.close()
    server_columns = columns(db_path, "servers")
    for name in ("connection_type", "instance_id_override", "aws_profile", "aws_region"):
        assert server_columns[name] == ("TEXT", 0, None)
    assert columns(db_path, "server_analyses")["transport"] == ("TEXT", 0, None)
    assert columns(db_path, "patch_executions")["transport"] == ("TEXT", 0, None)
    assert set(columns(db_path, "ssm_instance_cache")) == {
        "private_ip", "profile", "region", "instance_id", "resolved_at",
    }  # fmt: skip
    server = db.create_server("a", HOST_IP, "/k.pem")
    assert server.connection_type is None and server.instance_id_override is None
    db.save_instance_mapping(HOST_IP, PROFILE, REGION, INSTANCE)
    db.save_instance_mapping(HOST_IP, PROFILE, REGION, OTHER_INSTANCE)  # replaces
    assert db.get_instance_mapping(HOST_IP, PROFILE, REGION) == OTHER_INSTANCE
    assert db.delete_instance_mapping(OTHER_INSTANCE) == 1


def test_v15_database_upgrades_to_v16_keeping_data(db_path):
    conn = _legacy_db(db_path, 15)
    conn.execute("UPDATE servers SET ssh_user = 'ec2-user', auth_method = 'password', "
                 "password_encrypted = 'token'")  # fmt: skip
    conn.execute(
        "INSERT INTO analysis_runs (report_filename, report_uploaded_at, report_content, "
        "started_at, status) VALUES ('r.json', 't', '{}', 't', 'completed')"
    )
    conn.execute(
        "INSERT INTO server_analyses (run_id, position, server_name, reported_cves, status) "
        "VALUES (1, 0, 'keep', '[]', 'complete')"
    )
    conn.execute("INSERT INTO settings (key, value, updated_at) VALUES ('kept', 'yes', 't')")
    conn.commit()
    conn.close()
    assert "connection_type" not in columns(db_path, "servers")

    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 19
    check.close()
    server = db.get_server_by_name("keep")
    assert (server.ip_address, server.pem_path, server.ssh_user) == (
        "10.0.0.1", "/k.pem", "ec2-user",
    )  # fmt: skip
    assert server.uses_password and db.get_server_password(server.id) == "token"
    assert server.connection_type is None  # existing servers stay on direct SSH by default
    assert ssm_service.load_defaults(db).connection_type == CONNECTION_SSH
    assert db.get_setting("kept") == "yes"
    assert db.get_latest_report().filename == "r.json"
    assert db.get_analysis_run(1, details=False).servers[0].transport is None
    assert Database(db_path).get_server_by_name("keep").connection_type is None


def test_full_upgrade_path_from_v1_reaches_v16(db_path):
    _legacy_db(db_path, 1).close()
    db = Database(db_path)
    with sqlite3.connect(db_path) as check:
        assert check.execute("PRAGMA user_version").fetchone()[0] == SCHEMA_VERSION == 19
    check.close()
    server = db.get_server_by_name("keep")
    assert server.connection_type is None and server.ssh_user == "ubuntu"
    assert db.get_latest_report().servers == {"keep": []}
    db.save_instance_mapping(HOST_IP, PROFILE, REGION, INSTANCE)


def test_v16_is_a_new_migration_number():
    assert sorted(_MIGRATIONS) == list(range(1, SCHEMA_VERSION + 1))
    assert "connection_type" in _MIGRATIONS[16]
    assert all("connection_type" not in _MIGRATIONS[v] for v in range(1, 16))


# --- the connection test command --------------------------------------------------------------


def test_remote_command_collects_uname():
    assert "uname -srm" in ssh_service.REMOTE_COMMAND
    info = ssh_service.parse_remote_info(TEST_STDOUT)
    assert info["uname"] == "Linux 6.8.0-1021-aws x86_64"
    assert info["hostname"] == "ip-10-10-20-15"
