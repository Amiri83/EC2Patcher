"""Free-space pre-flight before the install: Installed-Size against /, /boot and /usr/src."""

from ec2patcher.services import patch_remote

REMOTE = "/tmp/ip-10-0-0-1"
IMAGE = "linux-image-6.8.0-1024-aws_6.8.0-1024.26_amd64.deb"
HEADERS = "linux-headers-6.8.0-1024-aws_6.8.0-1024.26_amd64.deb"
MODULES = "linux-modules-6.8.0-1024-aws_6.8.0-1024.26_amd64.deb"
OPENSSL = "openssl_3.0.13-0ubuntu3.6_amd64.deb"
MIB = 1024  # KiB


def output(installed: dict[str, int | str], df: dict[str, tuple[str, int]]) -> str:
    lines = ["@@EC2P installed-size"]
    lines += [f"{REMOTE}/{name}\t{size}" for name, size in installed.items()]
    lines.append("@@EC2P df")
    for path, (mount, free) in df.items():
        lines.append(f"{path}\t/dev/nvme0n1p1 8000000 4000000 {free} 51% {mount}")
    return "\n".join([*lines, "@@EC2P end"]) + "\n"


SEPARATE_BOOT = {"/": ("/", 4000 * MIB), "/boot": ("/boot", 150 * MIB), "/usr/src": ("/", 0)}


def test_command_is_read_only_and_quotes_every_path():
    command = patch_remote.space_check_command(REMOTE, [OPENSSL, IMAGE])
    assert "sudo" not in command and "rm " not in command and "autoremove" not in command
    assert f"{REMOTE}/{OPENSSL}" in command and "dpkg-deb -f" in command
    assert "df -Pk --" in command and "/usr/src" in command


def test_parse_reads_sizes_and_filesystems():
    check = patch_remote.parse_space(output({OPENSSL: 1500, IMAGE: ""}, SEPARATE_BOOT), REMOTE)
    assert check.installed_kb == {OPENSSL: 1500}  # an unreadable size is left out
    assert check.filesystems["/boot"] == ("/boot", 150 * MIB)
    assert check.filesystems["/usr/src"][0] == "/"


def test_incomplete_or_rootless_output_is_unusable():
    full = output({OPENSSL: 1500}, SEPARATE_BOOT)
    assert patch_remote.parse_space(full.replace("@@EC2P end\n", ""), REMOTE) is None
    assert patch_remote.parse_space(output({OPENSSL: 1500}, {}), REMOTE) is None


def test_packages_that_fit_give_no_problem():
    check = patch_remote.parse_space(output({OPENSSL: 1500}, SEPARATE_BOOT), REMOTE)
    assert patch_remote.space_problems(check, {OPENSSL: 1_000_000}) == []


def test_kernel_image_needs_room_for_its_initrd_on_boot():
    installed = {IMAGE: 15 * MIB, MODULES: 120 * MIB, HEADERS: 80 * MIB}
    check = patch_remote.parse_space(output(installed, SEPARATE_BOOT), REMOTE)
    problems = patch_remote.space_problems(check, dict.fromkeys(installed, 1))
    # /boot: 15 MiB image + 128 MiB initrd + margin > 150 MiB; / has room for the rest.
    assert len(problems) == 2
    assert problems[0].startswith("/boot (filesystem /boot): 150.0 MiB free")
    assert problems[1] == patch_remote.AUTOREMOVE_HINT
    assert "apt-get autoremove --purge" in problems[1]


def test_paths_on_one_filesystem_add_up():
    installed = {IMAGE: 15 * MIB, MODULES: 120 * MIB, HEADERS: 80 * MIB}
    one = {path: ("/", 300 * MIB) for path in patch_remote.SPACE_PATHS}
    check = patch_remote.parse_space(output(installed, one), REMOTE)
    problem, _hint = patch_remote.space_problems(check, dict.fromkeys(installed, 1))
    assert problem.startswith("/, /boot, /usr/src (filesystem /): 300.0 MiB free")


def test_unknown_installed_size_is_estimated_from_the_deb():
    df = {"/": ("/", 100 * MIB)}  # /boot and /usr/src not reported: they count towards /
    check = patch_remote.parse_space(output({}, df), REMOTE)
    assert patch_remote.space_problems(check, {OPENSSL: 1024 * 1024}) == []  # 4 MiB + margin
    assert patch_remote.space_problems(check, {OPENSSL: 20 * 1024 * 1024})  # 80 MiB + margin
