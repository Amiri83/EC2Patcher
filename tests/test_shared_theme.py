"""DadsOps shared theme (linked on every page, served as a static file) and the shared
environment defaults: AWS_PROFILE / AWS_REGION and DADSOPS_LOG_DIR."""

import logging
import re
from pathlib import Path

import pytest

from ec2patcher import config, logging_setup
from ec2patcher.app import create_app
from ec2patcher.database import Database
from ec2patcher.services import ssm_service

THEME_HREF = "/static/theme/dadsops-theme.css"
APP_CSS_HREF = "/static/style.css"
THEME_SOURCE = Path(__file__).resolve().parents[1] / "src/ec2patcher/static/theme/dadsops-theme.css"
PAGES = (
    "/", "/servers", "/servers/new", "/reports", "/analysis/latest", "/patch-report",
    "/history", "/settings", "/shutdown", "/does-not-exist",
)  # fmt: skip
NAV = ("Dashboard", "Servers", "Reports", "Analysis", "Patch Report", "History", "Settings")
PROFILE, REGION = "example", "eu-west-1"


def stylesheets(page: str) -> list[str]:
    return re.findall(r'<link rel="stylesheet" href="https?://[^/"]+([^"]+)">', page)


# --- theme -----------------------------------------------------------------------------------


@pytest.mark.parametrize("url", PAGES)
def test_every_page_links_the_theme_before_the_app_stylesheet(client, url):
    page = client.get(url).text
    links = stylesheets(page)
    assert THEME_HREF in links and APP_CSS_HREF in links, (url, links)
    assert links.index(THEME_HREF) < links.index(APP_CSS_HREF), (url, links)


@pytest.mark.parametrize("url", PAGES)
def test_every_page_has_the_theme_top_menu(client, url):
    page = client.get(url).text
    assert 'class="sidebar"' not in page and "nav-link" not in page
    header = page.split('<header class="shell-header">', 1)[1].split("</header>", 1)[0]
    labels = re.findall(r"<a href=\"[^\"]+\"[^>]*>([^<]+)</a>", header)
    assert labels == ["EC2 Patcher", *NAV, "Shutdown App"], (url, labels)
    assert 'class="tagline">v' in header
    assert '<main class="page">' in page


def test_theme_file_is_served(client):
    r = client.get(THEME_HREF)
    assert r.status_code == 200 and r.text.strip()
    assert r.headers["content-type"].startswith("text/css")
    assert r.content == THEME_SOURCE.read_bytes()
    assert r.text.startswith("/* DadsOps shared theme v")


def test_shutdown_menu_item_is_highlighted_on_its_page(client):
    page = client.get("/shutdown").text
    assert 'class="nav-shutdown active"' in page
    assert page.count('aria-current="page"') == 1


# --- AWS_PROFILE / AWS_REGION ----------------------------------------------------------------


def set_aws_env(monkeypatch):
    monkeypatch.setenv(config.AWS_PROFILE_ENV, PROFILE)
    monkeypatch.setenv(config.AWS_REGION_ENV, REGION)


def test_defaults_follow_the_aws_environment(monkeypatch, db):
    set_aws_env(monkeypatch)
    defaults = ssm_service.load_defaults(db)
    assert (defaults.profile, defaults.region) == (PROFILE, REGION)
    assert (defaults.profile_source, defaults.region_source) == ("AWS_PROFILE", "AWS_REGION")
    assert defaults.saved_profile is None and defaults.saved_region is None


def test_defaults_without_the_aws_environment_are_unchanged(db):
    assert ssm_service.load_defaults(db) == ssm_service.ConnectionDefaults()
    ssm_service.save_defaults(db, "ssm", "saved-profile", "us-west-2")
    defaults = ssm_service.load_defaults(db)
    assert (defaults.profile, defaults.region) == ("saved-profile", "us-west-2")
    assert defaults.profile_source == defaults.region_source == ssm_service.SOURCE_SETTINGS


def test_saved_settings_win_over_the_aws_environment(monkeypatch, db):
    set_aws_env(monkeypatch)
    ssm_service.save_defaults(db, "ssh", "saved-profile", "us-west-2")
    defaults = ssm_service.load_defaults(db)
    assert (defaults.profile, defaults.region) == ("saved-profile", "us-west-2")


def test_invalid_aws_environment_values_are_ignored(monkeypatch, db):
    monkeypatch.setenv(config.AWS_PROFILE_ENV, "bad profile;")
    monkeypatch.setenv(config.AWS_REGION_ENV, "nowhere")
    defaults = ssm_service.load_defaults(db)
    assert defaults.profile is None and defaults.region is None


def test_server_form_shows_the_environment_default(monkeypatch, client):
    set_aws_env(monkeypatch)
    page = client.get("/servers/new").text
    assert '<option value="" selected>Default from AWS_PROFILE</option>' in page
    assert '<option value="" selected>Default from AWS_REGION</option>' in page
    assert f"Default from AWS_PROFILE (<code>{PROFILE}</code>)" in page
    assert f"Default from AWS_REGION (<code>{REGION}</code>)" in page


def test_server_form_without_the_environment_is_unchanged(client):
    page = client.get("/servers/new").text
    assert '<option value="" selected>Default from Settings</option>' in page
    assert "AWS_PROFILE" not in page and "AWS_REGION" not in page


def test_settings_show_the_environment_default_without_storing_it(monkeypatch, client, db_path):
    set_aws_env(monkeypatch)
    page = client.get("/settings").text
    assert f'<option value="" selected>From AWS_PROFILE: {PROFILE}</option>' in page
    assert f'<option value="" selected>From AWS_REGION: {REGION}</option>' in page
    assert f"the default is <code>{PROFILE}</code> from <code>AWS_PROFILE</code>" in page
    # Saving the form as shown (empty choices, even SSH over SSM) keeps the env out of the DB.
    data = {"action": "save", "connection_type": "ssm", "aws_profile": "", "aws_region": ""}
    r = client.post("/settings/connection", data=data, follow_redirects=False)
    assert r.status_code == 303
    db = Database(db_path)
    assert db.get_setting(ssm_service.DEFAULT_PROFILE_SETTING) is None
    assert db.get_setting(ssm_service.DEFAULT_REGION_SETTING) is None
    assert ssm_service.load_defaults(db).profile == PROFILE


def test_settings_without_the_environment_are_unchanged(client):
    page = client.get("/settings").text
    assert '<option value="" selected>None</option>' in page
    assert "AWS_PROFILE" not in page and "AWS_REGION" not in page
    data = {"action": "save", "connection_type": "ssm", "aws_profile": "", "aws_region": ""}
    r = client.post("/settings/connection", data=data)
    assert r.status_code == 422 and "needs a default AWS profile" in r.text


def test_saved_setting_wins_on_the_settings_page(monkeypatch, client, db_path):
    set_aws_env(monkeypatch)
    ssm_service.save_defaults(Database(db_path), "ssh", "saved-profile", "us-west-2")
    page = client.get("/settings").text
    assert 'value="saved-profile"' in page  # not in the (absent) AWS CLI config: Other…
    assert '<option value="us-west-2" selected>' in page
    assert "From AWS_PROFILE" not in page and "From AWS_REGION" not in page


# --- DADSOPS_LOG_DIR -------------------------------------------------------------------------


@pytest.fixture
def restore_root_handlers():
    root = logging.getLogger()
    before = list(root.handlers)
    yield
    logging_setup.stop_file_logging()
    for handler in list(root.handlers):
        if handler not in before:
            root.removeHandler(handler)


def test_default_log_dir_follows_dadsops_log_dir(monkeypatch, tmp_path):
    monkeypatch.delenv(config.LOG_DIR_ENV)
    monkeypatch.setenv(config.SHARED_LOG_DIR_ENV, str(tmp_path / "shared-logs"))
    assert config.get_default_log_dir() == tmp_path / "shared-logs"
    assert config.default_log_dir_source()[1] == "DADSOPS_LOG_DIR"


def test_default_log_dir_without_dadsops_log_dir_is_unchanged(monkeypatch, tmp_path):
    assert config.get_default_log_dir() == tmp_path / "logs"  # EC2PATCHER_LOG_DIR (conftest)
    monkeypatch.delenv(config.LOG_DIR_ENV)
    monkeypatch.setattr(config, "user_log_dir", lambda app, appauthor: f"/x/{app}/log")
    assert str(config.get_default_log_dir()) == "/x/ec2patcher/log"
    assert config.default_log_dir_source()[1] is None


def test_app_specific_log_dir_wins_over_dadsops_log_dir(monkeypatch, tmp_path):
    monkeypatch.setenv(config.SHARED_LOG_DIR_ENV, str(tmp_path / "shared-logs"))
    assert config.get_default_log_dir() == tmp_path / "logs"


def test_app_logs_to_dadsops_log_dir(monkeypatch, tmp_path, db_path, restore_root_handlers):
    monkeypatch.delenv(config.LOG_DIR_ENV)
    monkeypatch.setenv(config.SHARED_LOG_DIR_ENV, str(tmp_path / "shared-logs"))
    create_app(db_path=db_path, shutdown_handler=lambda: None, file_logging=True)
    assert logging_setup.active_log_file() == tmp_path / "shared-logs" / config.LOG_FILENAME
    assert Database(db_path).get_setting(logging_setup.LOG_DIR_SETTING) is None


def test_saved_log_dir_wins_over_dadsops_log_dir(
    monkeypatch, tmp_path, db_path, restore_root_handlers
):
    monkeypatch.delenv(config.LOG_DIR_ENV)
    monkeypatch.setenv(config.SHARED_LOG_DIR_ENV, str(tmp_path / "shared-logs"))
    Database(db_path).set_setting(logging_setup.LOG_DIR_SETTING, str(tmp_path / "chosen"))
    create_app(db_path=db_path, shutdown_handler=lambda: None, file_logging=True)
    assert logging_setup.active_log_file() == tmp_path / "chosen" / config.LOG_FILENAME


def test_settings_show_the_log_dir_source(monkeypatch, tmp_path, client):
    assert "DADSOPS_LOG_DIR" not in client.get("/settings").text
    monkeypatch.delenv(config.LOG_DIR_ENV)
    monkeypatch.setenv(config.SHARED_LOG_DIR_ENV, str(tmp_path / "shared-logs"))
    page = client.get("/settings").text
    assert f"Default: <code>{tmp_path / 'shared-logs'}</code>" in page
    assert "(from <code>DADSOPS_LOG_DIR</code>)" in page
