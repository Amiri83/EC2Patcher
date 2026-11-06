"""Why an SSM session could not start, the AWS profile and region dropdowns and their endpoint.
subprocess is always faked and the AWS CLI config is a temporary file: no aws, ssh or ~/.aws."""

import json
import subprocess

import pytest
from conftest import FakeSSH

from ec2patcher import config
from ec2patcher.database import Database
from ec2patcher.models import CONNECTION_SSM
from ec2patcher.services import aws_config, ssh_service, ssm_service
from ec2patcher.services.aws_config import OTHER_CHOICE
from ec2patcher.services.ssm_service import NOT_CONNECTED, SsmTarget
from ec2patcher.validation import check_aws_region

INSTANCE = "i-0123456789abcdef0"
PROFILE = "my-profile"
REGION = "us-east-1"
HOST = "ip-10-0-0-1"
HOST_IP = "10.0.0.1"
TARGET = SsmTarget(INSTANCE, PROFILE, REGION)
NOT_CONNECTED_STDERR = (
    "An error occurred (TargetNotConnected) when calling the StartSession operation: "
    f"{INSTANCE} is not connected.\n"
)
SSO_EXPIRED = "Error when retrieving token from sso: Token has expired and refresh failed\n"
EXPIRED_TOKEN = "An error occurred (ExpiredToken): The security token is expired\n"
NOT_FOUND_STDERR = (
    "An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances "
    f"operation: The instance ID '{INSTANCE}' does not exist\n"
)
DENIED = (
    "An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation: "
    "User: arn:aws:iam::123456789012:user/example is not authorized to perform this\n"
)
CONFIG = f"""\
[default]
region = eu-west-1

[profile {PROFILE}]
region = {REGION}
sso_session = my-sso

[profile no-region]
output = json

[sso-session my-sso]
sso_region = us-east-2
sso_start_url = https://example.invalid/start

[services example]
s3 =
  endpoint_url = https://example.invalid

[plain-section]
region = us-west-2

[profile has space]
region = us-west-1
"""


def done(args, stdout="", rc=0, stderr=""):
    return subprocess.CompletedProcess(args, rc, stdout, stderr)


class FakeCli:
    """ssh fails as not connected; the aws CLI answers per service with (exit, stdout, stderr)."""

    def __init__(self, ssh_stderr=NOT_CONNECTED_STDERR, sts=None, ec2=None, ssm=None, raises=None):
        self.ssh_stderr = ssh_stderr
        self.answers = {
            "sts": sts or (0, "{}", ""),
            "ec2": ec2 or (0, '["running"]', ""),
            "ssm": ssm or (0, "[]", ""),
        }
        self.raises = raises or {}
        self.calls: list[list[str]] = []
        self.timeouts: list[int] = []

    def __call__(self, args, **kwargs):
        assert "shell" not in kwargs
        if args[1:] == ["--version"]:  # the preflight
            return done(args, "version 1\n")
        self.calls.append(list(args))
        if args[0] != "aws":
            return done(args, rc=255, stderr=self.ssh_stderr)
        self.timeouts.append(kwargs["timeout"])
        service = args[1]
        if service in self.raises:
            raise self.raises[service]
        rc, stdout, stderr = self.answers[service]
        return done(args, stdout, rc, stderr)

    def services(self):
        return [call[1] for call in self.calls if call[0] == "aws"]


def explain(fake, stderr=NOT_CONNECTED_STDERR):
    return ssm_service.explain_failure(TARGET, stderr, fake)


# --- why a session could not start ---------------------------------------------------------


def test_instance_not_found_answers_with_the_profile_and_region():
    fake = FakeCli(ec2=(254, "", NOT_FOUND_STDERR))
    assert explain(fake) == (
        f"Instance {INSTANCE} not found in profile {PROFILE} / region {REGION}. "
        "Wrong account or region?"
    )
    assert fake.services() == ["sts", "ec2"]


def test_an_empty_answer_is_not_found_too():
    message = explain(FakeCli(ec2=(0, "[]", "")))
    assert f"Instance {INSTANCE} not found in profile {PROFILE} / region {REGION}." in message


def test_the_lookup_uses_the_profile_and_region_of_the_target():
    fake = FakeCli()
    explain(fake)
    ec2 = next(call for call in fake.calls if call[1] == "ec2")
    assert ec2[:4] == ["aws", "ec2", "describe-instances", "--instance-ids"] and INSTANCE in ec2
    ssm = next(call for call in fake.calls if call[1] == "ssm")
    assert ssm[2] == "describe-instance-information"
    assert f"Key=InstanceIds,Values={INSTANCE}" in ssm
    for call in (ec2, ssm):
        assert call[call.index("--profile") + 1] == PROFILE
        assert call[call.index("--region") + 1] == REGION


def test_stopped_instance_says_stopped_without_asking_ssm():
    fake = FakeCli(ec2=(0, '["stopped"]', ""))
    message = explain(fake)
    assert f"Instance {INSTANCE} is stopped" in message
    assert PROFILE in message and REGION in message
    assert fake.services() == ["sts", "ec2"]


def test_terminated_instance_is_named_and_not_told_to_start():
    message = explain(FakeCli(ec2=(0, '["terminated"]', "")))
    assert "is terminated" in message and "Start it" not in message


def test_running_instance_missing_from_ssm_keeps_the_agent_and_role_message():
    fake = FakeCli(ssm=(0, "[]", ""))
    assert explain(fake) == NOT_CONNECTED
    assert "SSM agent not running" in NOT_CONNECTED and "no instance role" in NOT_CONNECTED
    assert fake.services() == ["sts", "ec2", "ssm"]


def test_running_instance_with_a_lost_connection_keeps_the_agent_and_role_message():
    assert explain(FakeCli(ssm=(0, '["ConnectionLost"]', ""))) == NOT_CONNECTED


def test_running_instance_online_in_ssm_is_not_blamed_on_the_agent():
    message = explain(FakeCli(ssm=(0, '["Online"]', "")))
    assert "online in Systems Manager" in message and "Try again" in message


@pytest.mark.parametrize("stderr", [SSO_EXPIRED, NOT_CONNECTED_STDERR + SSO_EXPIRED])
def test_expired_sso_in_the_failure_skips_every_lookup(stderr):
    fake = FakeCli()
    assert f"run `aws sso login --profile {PROFILE}`" in explain(fake, stderr)
    assert fake.calls == []


def test_expired_credentials_in_the_failure_skip_every_lookup():
    fake = FakeCli()
    assert "credentials of profile" in explain(fake, NOT_CONNECTED_STDERR + EXPIRED_TOKEN)
    assert fake.calls == []


@pytest.mark.parametrize("stderr", [SSO_EXPIRED, EXPIRED_TOKEN])
def test_credentials_found_expired_never_ask_ec2(stderr):
    fake = FakeCli(sts=(255, "", stderr))
    assert f"aws sso login --profile {PROFILE}" in explain(fake)
    assert fake.services() == ["sts"]


def test_credentials_expiring_at_the_lookup_get_the_hint():
    fake = FakeCli(ec2=(255, "", SSO_EXPIRED))
    assert f"run `aws sso login --profile {PROFILE}`" in explain(fake)
    assert fake.services() == ["sts", "ec2"]


def test_a_denied_lookup_gives_the_aws_message_without_the_arn():
    message = explain(FakeCli(ec2=(254, "", DENIED)))
    assert "looking up why failed" in message and "UnauthorizedOperation" in message
    assert "arn:aws" not in message and "123456789012" not in message


def test_a_denied_ssm_lookup_gives_a_reason_too():
    message = explain(FakeCli(ssm=(254, "", DENIED)))
    assert "looking up why failed" in message and "UnauthorizedOperation" in message


@pytest.mark.parametrize(
    "error",
    [
        subprocess.TimeoutExpired("aws", 10),
        FileNotFoundError("aws"),
        OSError("no such thing"),
    ],
)
@pytest.mark.parametrize("service", ["sts", "ec2", "ssm"])
def test_a_lookup_that_cannot_run_is_a_short_reason(service, error):
    message = explain(FakeCli(raises={service: error}))
    assert message.startswith(f"Instance {INSTANCE} is not connected")
    assert "Traceback" not in message


@pytest.mark.parametrize("stdout", ["not json", "{}", '["melting"]', ""])
def test_an_unexpected_ec2_answer_is_a_short_reason(stdout):
    assert "unexpected answer" in explain(FakeCli(ec2=(0, stdout, "")))


def test_every_lookup_has_the_short_timeout():
    fake = FakeCli()
    explain(fake)
    assert fake.timeouts == [ssm_service.AWS_LOOKUP_TIMEOUT_SECONDS] * 3
    assert ssm_service.AWS_LOOKUP_TIMEOUT_SECONDS < ssm_service.AWS_TIMEOUT_SECONDS


def test_other_failures_are_described_without_a_lookup():
    fake = FakeCli()
    assert "access denied" in explain(fake, "AccessDeniedException: no\n")
    assert explain(fake, "Permission denied (publickey).\n") is None
    assert fake.calls == []


def test_all_three_connection_paths_explain_not_connected(pem_file):
    fake = FakeCli(ec2=(254, "", NOT_FOUND_STDERR))
    wrong_account = "Wrong account or region?"
    pem = str(pem_file)
    remote = ssh_service.run_remote(HOST_IP, pem, "uname", fake, ssm=TARGET)
    assert not remote.ok and wrong_account in remote.error
    assert "TargetNotConnected" in remote.stderr  # what note_failure reads stays as it was
    scp = ssh_service.run_scp(HOST_IP, pem, ["/x"], "/t", fake, ssm=TARGET)
    assert not scp.ok and wrong_account in scp.error
    test = ssh_service.check_connection("s", HOST_IP, pem, fake, ssm=TARGET)
    assert not test.success and wrong_account in test.error


def test_a_successful_connection_looks_nothing_up(pem_file):
    fake = FakeSSH(stdout="EC2P_HOSTNAME=h\n")
    assert ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake, ssm=TARGET).ok
    assert len(fake.calls) == 1


def test_direct_ssh_looks_nothing_up(pem_file):
    fake = FakeSSH(returncode=255, stderr=NOT_CONNECTED_STDERR)
    result = ssh_service.run_remote(HOST_IP, str(pem_file), "uname", fake)
    assert result.error.startswith("SSH connection failed:")
    assert len(fake.calls) == 1


# --- the AWS CLI config --------------------------------------------------------------------


@pytest.fixture
def aws_file(tmp_path):
    path = tmp_path / "aws-config"
    path.write_text(CONFIG)
    return path


def test_default_and_profile_sections_are_profiles_and_others_are_ignored(aws_file):
    found = aws_config.read_profiles(aws_file)
    assert found.profiles == ("default", PROFILE, "no-region")
    assert found.reason is None


def test_the_profile_region_is_extracted_when_present(aws_file):
    found = aws_config.read_profiles(aws_file)
    assert found.regions == {"default": "eu-west-1", PROFILE: REGION}
    assert aws_config.region_of(PROFILE, aws_file) == REGION
    assert aws_config.region_of("no-region", aws_file) == ""
    assert aws_config.region_of(None, aws_file) == ""


def test_an_invalid_region_in_the_config_is_not_offered(tmp_path):
    path = tmp_path / "c"
    path.write_text(f"[profile {PROFILE}]\nregion = $(id)\n")
    found = aws_config.read_profiles(path)
    assert found.profiles == (PROFILE,) and found.regions == {}


def test_repeated_sections_and_a_percent_sign_do_not_break_the_file(tmp_path):
    path = tmp_path / "c"
    path.write_text(f"[default]\noutput = %x\n[default]\noutput = json\n[profile {PROFILE}]\n")
    assert aws_config.read_profiles(path).profiles == ("default", PROFILE)


def test_a_missing_file_is_empty_with_a_reason(tmp_path):
    found = aws_config.read_profiles(tmp_path / "nothing")
    assert found.profiles == () and "No AWS config file" in found.reason


@pytest.mark.parametrize(
    "content", ["no section header = secret-value\n", "[default]\njunk line\n"]
)
def test_a_malformed_file_is_empty_with_a_reason_that_quotes_nothing(tmp_path, content):
    path = tmp_path / "c"
    path.write_text(content)
    found = aws_config.read_profiles(path)
    assert found.profiles == () and "not valid" in found.reason
    assert "secret-value" not in found.reason and "junk" not in found.reason


def test_a_binary_file_is_empty_with_a_reason(tmp_path):
    path = tmp_path / "c"
    path.write_bytes(b"\xff\xfe\x00bad")
    found = aws_config.read_profiles(path)
    assert found.profiles == () and "not valid" in found.reason


def test_an_unreadable_file_is_empty_with_a_reason(tmp_path):
    found = aws_config.read_profiles(tmp_path)  # a directory cannot be read as a file
    assert found.profiles == () and "could not be read" in found.reason


def test_reading_never_changes_the_file(aws_file):
    before = (aws_file.read_bytes(), aws_file.stat().st_mtime_ns)
    aws_config.read_profiles(aws_file)
    assert (aws_file.read_bytes(), aws_file.stat().st_mtime_ns) == before


def test_the_config_path_follows_the_aws_cli(monkeypatch, tmp_path):
    assert str(config.get_aws_config_path()).startswith(str(tmp_path))
    monkeypatch.delenv(config.AWS_CONFIG_FILE_ENV)
    assert str(config.get_aws_config_path()).endswith("/.aws/config")


# --- regions -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "region", ["us-east-1", "ap-southeast-7", "eu-central-2", "us-gov-west-1", "me-south-1"]
)
def test_region_format_accepts(region):
    assert check_aws_region(region) is None


@pytest.mark.parametrize(
    "region",
    [
        "", "us", "us-east", "us-east-", "useast1", "US-EAST-1", "us-east-1a", "us-east-11",
        "u-east-1", "use-east-1", "us_east_1", "us east 1", "us-east-1\n", "us-east-1;id", "us-1",
        "us-east-١",
    ],
)  # fmt: skip
def test_region_format_rejects(region):
    assert check_aws_region(region) == "AWS region must look like us-east-1."


def test_the_region_list_is_commercial_and_valid():
    regions = aws_config.COMMERCIAL_REGIONS
    assert len(regions) == len(set(regions)) and REGION in regions
    assert not [r for r in regions if check_aws_region(r)]
    assert not [r for r in regions if r.startswith(("cn-", "us-gov-", "us-iso"))]


# --- what the dropdown shows ---------------------------------------------------------------


def test_a_listed_value_is_selected():
    view = aws_config.dropdown(PROFILE, ("default", PROFILE))
    assert (view.selected, view.other_value) == (PROFILE, "")


def test_a_value_not_listed_shows_as_other_with_the_value():
    view = aws_config.dropdown("saved-before", ("default",))
    assert (view.selected, view.other_value) == (OTHER_CHOICE, "saved-before")


def test_an_empty_value_is_the_empty_choice_unless_other_was_chosen():
    assert aws_config.dropdown("", ("default",)).selected == ""
    assert aws_config.dropdown(None, ("default",)).selected == ""
    assert aws_config.dropdown("", ("default",), other_chosen=True).selected == OTHER_CHOICE


def test_the_other_marker_can_never_be_saved_as_a_value():
    assert ssm_service.check_aws_profile(OTHER_CHOICE) and check_aws_region(OTHER_CHOICE)


# --- the endpoint --------------------------------------------------------------------------


def write_config(text=CONFIG):
    path = config.get_aws_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_endpoint_returns_profiles_and_regions(client):
    write_config()
    response = client.get("/settings/aws-options")
    assert response.status_code == 200 and response.headers["content-type"] == "application/json"
    data = response.json()
    assert data["profiles"] == ["default", PROFILE, "no-region"]
    assert data["regions"] == list(aws_config.COMMERCIAL_REGIONS)
    assert data["profile_regions"][PROFILE] == REGION
    assert data["reason"] is None


def test_endpoint_sends_nothing_of_the_config_but_names_and_regions(client):
    write_config(CONFIG + "\n[profile leaky]\naws_secret_access_key = fake-secret-value\n")
    body = client.get("/settings/aws-options").text
    assert "fake-secret-value" not in body and "example.invalid" not in body
    assert "my-sso" not in body


@pytest.mark.parametrize("content", [None, "broken line\n"])
def test_endpoint_never_raises_on_a_broken_config(client, content):
    if content:
        write_config(content)
    response = client.get("/settings/aws-options")
    assert response.status_code == 200
    data = response.json()
    assert data["profiles"] == [] and data["reason"]
    assert data["regions"] == list(aws_config.COMMERCIAL_REGIONS)


@pytest.mark.parametrize(
    "headers",
    [{"origin": "https://evil.example"}, {"sec-fetch-site": "cross-site"}],
)
def test_endpoint_rejects_other_sites(client, headers):
    write_config()
    response = client.get("/settings/aws-options", headers=headers)
    assert response.status_code == 403 and PROFILE not in response.text


def test_endpoint_rejects_a_foreign_host(client):
    response = client.get("/settings/aws-options", headers={"host": "evil.example"})
    assert response.status_code == 400


def test_endpoint_allows_the_same_origin(client):
    response = client.get("/settings/aws-options", headers={"origin": "http://127.0.0.1"})
    assert response.status_code == 200


# --- the forms -----------------------------------------------------------------------------


def form_data(pem_file, **extra):
    return {
        "name": HOST, "ip_address": HOST_IP, "pem_path": str(pem_file), "ssh_user": "ubuntu",
        "connection_type": CONNECTION_SSM, **extra,
    }  # fmt: skip


def option(value, selected=False):
    return f'<option value="{value}"{" selected" if selected else ""}>'


def test_forms_list_profiles_regions_and_other(client):
    write_config()
    for url in ("/servers/new", "/settings"):
        page = client.get(url).text
        for value in ("default", PROFILE, "no-region", REGION, "sa-east-1"):
            assert option(value) in page, (url, value)
        assert f"{option(OTHER_CHOICE)}Other…</option>" in page
        assert "my-sso" not in page and "plain-section" not in page


def test_server_form_shows_the_default_from_settings_as_the_empty_choice(client):
    page = client.get("/servers/new").text
    assert f"{option('', selected=True)}Default from Settings</option>" in page


def test_server_form_empty_choices_save_as_default(client, db_path, pem_file):
    write_config()
    data = form_data(pem_file, aws_profile="", aws_region="")
    assert client.post("/servers/new", data=data).status_code == 200
    server = Database(db_path).get_server_by_name(HOST)
    assert (server.aws_profile, server.aws_region) == (None, None)


def test_server_form_listed_choices_round_trip(client, db_path, pem_file):
    write_config()
    client.post("/servers/new", data=form_data(pem_file, aws_profile=PROFILE, aws_region=REGION))
    server = Database(db_path).get_server_by_name(HOST)
    assert (server.aws_profile, server.aws_region) == (PROFILE, REGION)
    page = client.get(f"/servers/{server.id}/edit").text
    assert option(PROFILE, selected=True) in page and option(REGION, selected=True) in page


def test_server_form_manual_values_round_trip_as_other(client, db_path, pem_file):
    write_config()
    data = form_data(
        pem_file, aws_profile=OTHER_CHOICE, aws_profile_other=" typed-profile ",
        aws_region=OTHER_CHOICE, aws_region_other="xx-newplace-1",
    )  # fmt: skip
    assert client.post("/servers/new", data=data).status_code == 200
    server = Database(db_path).get_server_by_name(HOST)
    assert (server.aws_profile, server.aws_region) == ("typed-profile", "xx-newplace-1")
    page = client.get(f"/servers/{server.id}/edit").text
    assert option(OTHER_CHOICE, selected=True) in page
    assert 'value="typed-profile"' in page and 'value="xx-newplace-1"' in page


def test_a_saved_value_gone_from_the_config_shows_as_other(client, db_path, pem_file):
    write_config()
    client.post("/servers/new", data=form_data(pem_file, aws_profile=PROFILE))
    write_config("[default]\n")
    server = Database(db_path).get_server_by_name(HOST)
    page = client.get(f"/servers/{server.id}/edit").text
    assert option(OTHER_CHOICE, selected=True) in page and f'value="{PROFILE}"' in page


def test_editing_can_change_other_back_to_the_default(client, db_path, pem_file):
    write_config()
    client.post("/servers/new", data=form_data(pem_file, aws_profile="typed-profile"))
    server = Database(db_path).get_server_by_name(HOST)
    # the Other input still holds the old text, but the select says Default from Settings
    data = form_data(pem_file, aws_profile="", aws_profile_other="typed-profile")
    client.post(f"/servers/{server.id}/edit", data=data)
    assert Database(db_path).get_server_by_name(HOST).aws_profile is None


@pytest.mark.parametrize(
    ("field", "expected"),
    [("aws_profile", "AWS profile name for Other"), ("aws_region", "AWS region for Other")],
)
def test_other_without_text_saves_nothing_over_ssm(client, db_path, pem_file, field, expected):
    r = client.post("/servers/new", data=form_data(pem_file, **{field: OTHER_CHOICE}))
    assert r.status_code == 422 and expected in r.text
    assert option(OTHER_CHOICE, selected=True) in r.text
    assert Database(db_path).count_servers() == 0


def test_other_without_text_keeps_the_saved_value_when_editing(client, db_path, pem_file):
    client.post("/servers/new", data=form_data(pem_file, aws_profile=PROFILE))
    server = Database(db_path).get_server_by_name(HOST)
    r = client.post(
        f"/servers/{server.id}/edit", data=form_data(pem_file, aws_profile=OTHER_CHOICE)
    )
    assert r.status_code == 422
    assert Database(db_path).get_server_by_name(HOST).aws_profile == PROFILE


def test_other_without_text_does_not_block_direct_ssh(client, db_path, pem_file):
    data = form_data(pem_file, connection_type="ssh", aws_profile=OTHER_CHOICE)
    assert client.post("/servers/new", data=data).status_code == 200
    assert Database(db_path).get_server_by_name(HOST).aws_profile is None


def test_a_bad_manual_region_is_refused_and_stays_in_the_form(client, db_path, pem_file):
    data = form_data(pem_file, aws_region=OTHER_CHOICE, aws_region_other="us-east-11")
    r = client.post("/servers/new", data=data)
    assert r.status_code == 422 and "must look like us-east-1" in r.text
    assert 'value="us-east-11"' in r.text and option(OTHER_CHOICE, selected=True) in r.text
    assert Database(db_path).count_servers() == 0


def test_test_connection_with_an_empty_other_runs_nothing(make_client, pem_file):
    fake = FakeSSH()
    with make_client(fake) as client:
        data = form_data(pem_file, action="test", aws_profile=OTHER_CHOICE)
        r = client.post("/servers/new", data=data)
    assert "AWS profile name for Other" in r.text and fake.calls == []


def test_test_connection_uses_the_typed_other_values(make_client, pem_file):
    fake = FakeCli(ssh_stderr=NOT_CONNECTED_STDERR, ec2=(254, "", NOT_FOUND_STDERR))
    with make_client(fake) as client:
        data = form_data(
            pem_file, action="test", aws_profile=OTHER_CHOICE, aws_profile_other="typed-profile",
            aws_region=OTHER_CHOICE, aws_region_other="eu-west-3",
            instance_id_override=INSTANCE,
        )  # fmt: skip
        r = client.post("/servers/new", data=data)
    assert "not found in profile typed-profile / region eu-west-3" in r.text


def test_settings_manual_values_round_trip(client, db_path):
    write_config()
    data = {
        "connection_type": "ssm", "aws_profile": OTHER_CHOICE, "aws_profile_other": "typed-profile",
        "aws_region": OTHER_CHOICE, "aws_region_other": "xx-newplace-1",
    }  # fmt: skip
    assert client.post("/settings/connection", data=data).status_code == 200
    defaults = ssm_service.load_defaults(Database(db_path))
    assert (defaults.profile, defaults.region) == ("typed-profile", "xx-newplace-1")
    page = client.get("/settings").text
    assert 'value="typed-profile"' in page and 'value="xx-newplace-1"' in page
    assert option(OTHER_CHOICE, selected=True) in page


def test_settings_other_without_text_saves_nothing(client, db_path):
    data = {"connection_type": "ssh", "aws_profile": PROFILE, "aws_region": REGION}
    client.post("/settings/connection", data=data)
    r = client.post("/settings/connection", data={**data, "aws_region": OTHER_CHOICE})
    assert r.status_code == 422 and "AWS region for Other" in r.text
    assert ssm_service.load_defaults(Database(db_path)).region == REGION


def test_settings_preselects_the_region_of_the_default_profile(client, db_path):
    write_config()
    data = {"connection_type": "ssh", "aws_profile": PROFILE, "aws_region": ""}
    client.post("/settings/connection", data=data)
    assert ssm_service.load_defaults(Database(db_path)).region is None
    page = client.get("/settings").text
    assert option(REGION, selected=True) in page and "data-from-profile" in page


def test_settings_keeps_a_saved_region_over_the_profile_region(client):
    write_config()
    data = {"connection_type": "ssh", "aws_profile": PROFILE, "aws_region": "eu-west-3"}
    client.post("/settings/connection", data=data)
    page = client.get("/settings").text
    assert option("eu-west-3", selected=True) in page
    assert option(REGION, selected=True) not in page and "data-from-profile" not in page


def test_a_saved_server_without_a_region_is_not_given_the_profile_region(client, db_path, pem_file):
    write_config()
    client.post("/servers/new", data=form_data(pem_file, aws_profile=PROFILE))
    server = Database(db_path).get_server_by_name(HOST)
    page = client.get(f"/servers/{server.id}/edit").text
    assert option(REGION, selected=True) not in page


def test_a_broken_config_still_renders_the_forms_with_the_reason(client):
    write_config("broken line\n")
    for url in ("/servers/new", "/settings"):
        response = client.get(url)
        assert response.status_code == 200 and "is not valid and was ignored" in response.text
        assert f"{option(OTHER_CHOICE)}Other…</option>" in response.text


def test_the_options_payload_is_json_serializable(tmp_path):
    json.dumps(aws_config.options(tmp_path / "nothing"))
