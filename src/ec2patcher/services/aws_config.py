"""AWS profile and region choices of the connection forms.

The AWS CLI config is only read, and only for profile names and their regions: credentials are not
looked at, and a parser message is never passed on because it can quote a line of the file.
"""

import configparser
from dataclasses import dataclass, field
from pathlib import Path

from ec2patcher import config
from ec2patcher.validation import check_aws_profile, check_aws_region

# Not valid in a profile name or a region, so it cannot be mistaken for one.
OTHER_CHOICE = "*other*"
CHOICE_FIELDS = ("aws_profile", "aws_region")
_OTHER_EMPTY = {
    "aws_profile": "Type the AWS profile name for Other…, or choose one from the list.",
    "aws_region": "Type the AWS region for Other…, or choose one from the list.",
}
_DEFAULT_PROFILE = "default"
_PROFILE_PREFIX = "profile"

COMMERCIAL_REGIONS = (
    "us-east-1", "us-east-2", "us-west-1", "us-west-2",
    "af-south-1",
    "ap-east-1", "ap-east-2",
    "ap-south-1", "ap-south-2",
    "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
    "ap-southeast-1", "ap-southeast-2", "ap-southeast-3", "ap-southeast-4", "ap-southeast-5",
    "ap-southeast-6", "ap-southeast-7",
    "ca-central-1", "ca-west-1",
    "eu-central-1", "eu-central-2",
    "eu-north-1",
    "eu-south-1", "eu-south-2",
    "eu-west-1", "eu-west-2", "eu-west-3",
    "il-central-1",
    "me-central-1", "me-south-1",
    "mx-central-1",
    "sa-east-1",
)  # fmt: skip


@dataclass(frozen=True)
class AwsProfiles:
    profiles: tuple[str, ...] = ()
    regions: dict[str, str] = field(default_factory=dict)  # only profiles that have a region
    reason: str | None = None  # why there are no profiles


@dataclass(frozen=True)
class Dropdown:
    options: tuple[str, ...]
    selected: str  # "" for the empty choice, else one of options or OTHER_CHOICE
    other_value: str = ""
    other_marker: str = OTHER_CHOICE


def _profile_name(section: str) -> str | None:
    """``[default]`` and ``[profile x]`` name a profile; any other section does not. A name that
    could not be saved or reach a command line is not offered."""
    words = section.split(None, 1)
    if section.strip() == _DEFAULT_PROFILE:
        name = _DEFAULT_PROFILE
    elif len(words) == 2 and words[0] == _PROFILE_PREFIX:
        name = words[1].strip()
    else:
        return None
    return None if check_aws_profile(name) else name


def read_profiles(path: Path | None = None) -> AwsProfiles:
    """The profiles of the AWS CLI config, ``default`` first. Never raises: a file that is missing,
    unreadable or malformed yields no profiles and a reason."""
    shown = str(path) if path is not None else config.DEFAULT_AWS_CONFIG_FILE
    try:
        source = path if path is not None else config.get_aws_config_path()
        shown = str(source)
        # default_section="": a [DEFAULT] section means nothing to the AWS CLI.
        parser = configparser.RawConfigParser(strict=False, default_section="")
        parser.read_string(Path(source).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return AwsProfiles(reason=f"No AWS config file at {shown}.")
    except (configparser.Error, ValueError):  # ValueError: not UTF-8, or a NUL in the path
        return AwsProfiles(reason=f"The AWS config file {shown} is not valid and was ignored.")
    except (OSError, RuntimeError):  # RuntimeError: the home directory is unknown
        return AwsProfiles(reason=f"The AWS config file {shown} could not be read.")
    regions: dict[str, str] = {}
    names: set[str] = set()
    for section in parser.sections():
        name = _profile_name(section)
        if name is None:
            continue
        names.add(name)
        region = parser.get(section, "region", fallback="").strip()
        if not check_aws_region(region):
            regions[name] = region
    ordered = sorted(names, key=lambda n: (n != _DEFAULT_PROFILE, n.casefold(), n))
    return AwsProfiles(tuple(ordered), regions)


def region_of(profile: str | None, path: Path | None = None) -> str:
    """The profile's own region from the config, or an empty string."""
    return read_profiles(path).regions.get(profile or "", "")


def options(path: Path | None = None) -> dict:
    """What the options endpoint answers. Never raises."""
    found = read_profiles(path)
    return {
        "profiles": list(found.profiles),
        "regions": list(COMMERCIAL_REGIONS),
        "profile_regions": found.regions,
        "reason": found.reason,
    }


def dropdown(value: str | None, choices, other_chosen: bool = False) -> Dropdown:
    """What a form shows for ``value``: a listed value is selected, any other one (a saved value
    no longer in the config, a manual entry) appears under Other…"""
    current = (value or "").strip()
    listed = tuple(choices)
    if current in listed:
        return Dropdown(listed, current)
    if current or other_chosen:
        return Dropdown(listed, OTHER_CHOICE, current)
    return Dropdown(listed, "")


def resolve_choices(
    fields: dict[str, str], others: dict[str, str]
) -> tuple[dict[str, str], list[str]]:
    """``fields`` with Other… replaced by the text typed for it, and the fields where Other… was
    chosen. Fields not using Other… are left as they are."""
    resolved = dict(fields)
    chosen = []
    for key in CHOICE_FIELDS:
        if resolved.get(key, "").strip() == OTHER_CHOICE:
            resolved[key] = others.get(key, "").strip()
            chosen.append(key)
    return resolved, chosen


def other_errors(fields: dict[str, str], other_chosen: list[str]) -> dict[str, str]:
    """Other… without a value is a mistake, not a request for the default: nothing is saved."""
    return {key: _OTHER_EMPTY[key] for key in other_chosen if not fields.get(key)}
