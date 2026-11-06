"""Clone server: the Add form pre-filled from a saved server. Generic fixtures only."""

import re
from dataclasses import asdict

import pytest

from ec2patcher.database import Database
from ec2patcher.models import AUTH_PASSWORD, CONNECTION_SSH, CONNECTION_SSM
from ec2patcher.services import secret_store

INSTANCE = "i-0fedcba9876543210"  # not the form's placeholder
NEW_INSTANCE = "i-0aaaabbbbccccdddd"
SECRET = "pa55-word-never-shown"  # noqa: S105 - a fake test value
TAGS = [("display_name", "Example API"), ("env", "test"), ("owner", "team-a"), ("zone", "a")]


@pytest.fixture
def db_handle(client, db_path):
    return Database(db_path)


@pytest.fixture
def source(db_handle, pem_file):
    """A server over SSM with every field set."""
    return db_handle.create_server(
        "ip-10-0-0-1", "10.0.0.1", str(pem_file), tags=TAGS, ssh_user="ec2-user",
        transport={
            "connection_type": CONNECTION_SSM, "instance_id_override": INSTANCE,
            "aws_profile": "my-profile", "aws_region": "us-east-1",
        },
    )  # fmt: skip


@pytest.fixture
def password_source(db_handle, client):
    token = client.app.state.credentials.encrypt(SECRET)
    return db_handle.create_server(
        "ip-10-0-0-2", "10.0.0.2", "", auth_method=AUTH_PASSWORD, password_encrypted=token,
        ssh_user="ec2-user", transport={"connection_type": CONNECTION_SSH},
    )  # fmt: skip


def field_value(html, name):
    match = re.search(rf'<input[^>]*name="{name}"[^>]*value="([^"]*)"', html, re.DOTALL)
    assert match, name
    return match.group(1)


def selected(html, select_id):
    block = re.search(rf'<select[^>]*id="{select_id}".*?</select>', html, re.DOTALL).group(0)
    return re.search(r'<option value="([^"]*)" selected', block).group(1)


def clone_form(source, pem_file, **changes):
    return {
        "clone_from": str(source.id),
        "name": "ip-10-0-0-5",
        "ip_address": "10.0.0.5",
        "pem_path": str(pem_file),
        "ssh_user": source.ssh_user,
        "auth_method": source.auth_method,
        "connection_type": source.connection_type or "",
        "instance_id_override": NEW_INSTANCE,
        "aws_profile": source.aws_profile or "",
        "aws_region": source.aws_region or "",
        "tag_key": [t.key for t in source.tags],
        "tag_value": [t.value for t in source.tags],
        "action": "save",
        **changes,
    }


# --- the form ------------------------------------------------------------------------------


def test_every_server_in_the_list_has_a_clone_button(client, db_handle, source, pem_file):
    other = db_handle.create_server("ip-10-0-0-9", "10.0.0.9", str(pem_file))
    html = client.get("/servers").text
    for server in (source, other):
        assert f'href="/servers/new?clone={server.id}"' in html


def test_form_copies_settings_and_clears_identity(client, source):
    response = client.get(f"/servers/new?clone={source.id}")
    assert response.status_code == 200
    html = response.text
    assert "Add Server" in html and 'action="/servers/new"' in html
    assert f'name="clone_from" value="{source.id}"' in html
    assert field_value(html, "ssh_user") == "ec2-user"
    assert selected(html, "connection_type") == CONNECTION_SSM
    assert selected(html, "auth_method") == "pem"
    assert 'value="my-profile"' in html and 'value="us-east-1"' in html
    for key, value in TAGS:  # all of them, not just the first
        assert f'value="{key}"' in html and f'value="{value}"' in html
    for name in ("name", "ip_address", "pem_path", "instance_id_override"):
        assert field_value(html, name) == "", name


def test_form_shows_nothing_identifying_the_source_except_its_name(client, source):
    html = client.get(f"/servers/new?clone={source.id}").text
    assert source.ip_address not in html
    assert source.pem_path not in html
    assert INSTANCE not in html


def test_stored_password_is_shown_by_reference_only(client, password_source):
    response = client.get(f"/servers/new?clone={password_source.id}")
    html = response.text
    assert f"Stored credential of {password_source.name}" in html
    assert 'name="ssh_password" value=""' in html
    assert SECRET not in html
    token = client.app.state.db.get_server_password(password_source.id)
    assert token not in html


def test_no_stored_password_claims_nothing(client, source):
    assert "Stored credential" not in client.get(f"/servers/new?clone={source.id}").text


@pytest.mark.parametrize("value", ["999", "abc", "-1", "1" * 40, ""])
def test_clone_of_an_unknown_server_goes_back_to_the_list(client, value):
    response = client.get(f"/servers/new?clone={value}", follow_redirects=False)
    assert response.status_code == 303 and "notice=not_found" in response.headers["location"]


def test_plain_add_form_is_unchanged(client):
    html = client.get("/servers/new").text
    assert "clone_from" not in html and "Cloning" not in html


# --- saving --------------------------------------------------------------------------------


def test_save_creates_a_new_server_with_copied_fields(client, db_handle, source, pem_file):
    response = client.post(
        "/servers/new", data=clone_form(source, pem_file), follow_redirects=False
    )
    assert response.status_code == 303
    clone = db_handle.get_server_by_name("ip-10-0-0-5")
    clone = db_handle.get_server(clone.id)
    assert clone.id != source.id
    assert (clone.ip_address, clone.instance_id_override) == ("10.0.0.5", NEW_INSTANCE)
    assert clone.ssh_user == "ec2-user" and clone.auth_method == "pem"
    assert (clone.connection_type, clone.aws_profile, clone.aws_region) == (
        CONNECTION_SSM, "my-profile", "us-east-1",
    )  # fmt: skip
    assert [(t.key, t.value) for t in clone.tags] == TAGS


def test_save_leaves_the_source_unchanged(client, db_handle, source, pem_file):
    before = asdict(db_handle.get_server(source.id))
    client.post(
        "/servers/new",
        data=clone_form(
            source, pem_file, ssh_user="ubuntu", aws_profile="*other*",
            aws_profile_other="other-profile", tag_key=["only"], tag_value=["this"],
        ),
    )  # fmt: skip
    clone = db_handle.get_server_by_name("ip-10-0-0-5")
    assert db_handle.get_server(clone.id).aws_profile == "other-profile"
    assert [t.key for t in db_handle.get_server(clone.id).tags] == ["only"]
    assert asdict(db_handle.get_server(source.id)) == before
    assert db_handle.count_servers() == 2


def test_clone_tags_are_rows_of_its_own(client, db_handle, source, pem_file):
    client.post("/servers/new", data=clone_form(source, pem_file))
    clone = db_handle.get_server_by_name("ip-10-0-0-5")
    db_handle.delete_server(clone.id)
    assert len(db_handle.get_server(source.id).tags) == len(TAGS)


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("name", "Server name is required"),
        ("ip_address", "IP address is required"),
        ("pem_path", "PEM file path is required"),
        ("instance_id_override", "Instance ID is required"),
    ],
)
def test_cleared_fields_are_required(client, db_handle, source, pem_file, field, message):
    response = client.post("/servers/new", data=clone_form(source, pem_file, **{field: ""}))
    assert response.status_code == 422
    assert message in response.text
    assert db_handle.count_servers() == 1
    # Still a clone, with what was typed: nothing of the source came back into the empty field.
    assert f'name="clone_from" value="{source.id}"' in response.text
    assert field_value(response.text, field) == ""


def test_source_values_are_not_a_default_for_empty_fields(client, db_handle, source, pem_file):
    empty = {"name": "", "ip_address": "", "pem_path": "", "instance_id_override": ""}
    response = client.post("/servers/new", data=clone_form(source, pem_file, **empty))
    assert response.status_code == 422
    for message in ("Server name is required", "IP address is required", "PEM file path is"):
        assert message in response.text
    assert "Instance ID is required" in response.text


def test_instance_id_only_required_over_ssm(client, db_handle, source, pem_file):
    form = clone_form(source, pem_file, connection_type=CONNECTION_SSH, instance_id_override="")
    assert client.post("/servers/new", data=form, follow_redirects=False).status_code == 303
    assert db_handle.get_server_by_name("ip-10-0-0-5").connection_type == CONNECTION_SSH


def test_instance_id_required_when_the_default_connection_is_ssm(
    client, db_handle, source, pem_file
):
    from ec2patcher.services import ssm_service

    ssm_service.save_defaults(db_handle, CONNECTION_SSM, "my-profile", "us-east-1")
    form = clone_form(source, pem_file, connection_type="", instance_id_override="")
    response = client.post("/servers/new", data=form)
    assert response.status_code == 422 and "Instance ID is required" in response.text


def test_an_invalid_instance_id_is_refused(client, db_handle, source, pem_file):
    form = clone_form(source, pem_file, instance_id_override="not-an-instance")
    response = client.post("/servers/new", data=form)
    assert response.status_code == 422 and "Instance ID must look like" in response.text


def test_duplicate_name_keeps_the_clone_form(client, source, pem_file):
    response = client.post("/servers/new", data=clone_form(source, pem_file, name=source.name))
    assert response.status_code == 422 and "already exists" in response.text
    assert f'name="clone_from" value="{source.id}"' in response.text


def test_source_deleted_meanwhile(client, db_handle, source, pem_file):
    form = clone_form(source, pem_file)
    db_handle.delete_server(source.id)
    response = client.post("/servers/new", data=form, follow_redirects=False)
    assert "notice=not_found" in response.headers["location"]
    assert db_handle.count_servers() == 0


def test_clone_from_is_not_a_way_to_edit(client, db_handle, source, pem_file):
    """Whatever is posted, the id only selects what to copy from."""
    before = asdict(db_handle.get_server(source.id))
    client.post("/servers/new", data=clone_form(source, pem_file, name="ip-10-0-0-6"))
    assert asdict(db_handle.get_server(source.id)) == before


# --- stored credentials --------------------------------------------------------------------


def password_form(source, **changes):
    return clone_form(source, "", **{"pem_path": "", "instance_id_override": "", **changes})


def test_kept_password_works_for_the_clone(client, db_handle, password_source):
    response = client.post("/servers/new", data=password_form(password_source))
    assert response.status_code in (200, 303)
    clone = db_handle.get_server_by_name("ip-10-0-0-5")
    assert clone.has_password and clone.uses_password
    assert client.app.state.credentials.server_password(clone.id) == SECRET
    assert clone.pem_path == ""


def test_typed_password_replaces_only_the_clones(client, db_handle, password_source):
    client.post("/servers/new", data=password_form(password_source, ssh_password="another-one"))
    clone = db_handle.get_server_by_name("ip-10-0-0-5")
    credentials = client.app.state.credentials
    assert credentials.server_password(clone.id) == "another-one"
    assert credentials.server_password(password_source.id) == SECRET


def test_deleting_the_source_leaves_the_clones_password(client, db_handle, password_source):
    client.post("/servers/new", data=password_form(password_source))
    db_handle.delete_server(password_source.id)
    clone = db_handle.get_server_by_name("ip-10-0-0-5")
    assert client.app.state.credentials.server_password(clone.id) == SECRET


def test_switching_a_clone_to_pem_does_not_copy_the_password(
    client, db_handle, password_source, pem_file
):
    form = password_form(password_source, auth_method="pem", pem_path=str(pem_file))
    assert client.post("/servers/new", data=form, follow_redirects=False).status_code == 303
    assert not db_handle.get_server_by_name("ip-10-0-0-5").has_password
    assert db_handle.get_server(password_source.id).has_password


def test_password_source_without_a_password_needs_one(client, db_handle):
    source = db_handle.create_server(
        "ip-10-0-0-3", "10.0.0.3", "", auth_method=AUTH_PASSWORD,
        transport={"connection_type": CONNECTION_SSH},
    )  # fmt: skip
    response = client.post("/servers/new", data=password_form(source))
    assert response.status_code == 422 and "Enter the SSH password" in response.text


def test_unreadable_credential_is_not_copied(client, db_handle, password_source, tmp_path):
    other = secret_store.SecretBox(tmp_path / "other.key")
    db_handle.set_server_password(password_source.id, other.encrypt(SECRET))
    response = client.post("/servers/new", data=password_form(password_source))
    assert response.status_code == 422
    assert db_handle.count_servers() == 1
    assert SECRET not in response.text


def test_test_connection_uses_the_stored_credential_and_saves_nothing(
    client, db_handle, fake_ssh, password_source
):
    form = password_form(password_source, action="test", ip_address="10.0.0.5")
    response = client.post("/servers/new", data=form)
    assert response.status_code == 200
    assert "Enter the SSH password" not in response.text
    assert db_handle.count_servers() == 1
    assert fake_ssh.calls, "the connection was tried"
    args, kwargs = fake_ssh.calls[-1]
    assert not any(SECRET in str(a) for a in args)
    assert SECRET not in response.text
    assert kwargs["env"]["SSHPASS"] == SECRET
