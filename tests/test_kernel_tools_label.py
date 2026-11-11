"""Kernel userspace packages (tools, headers) are labelled so they are not read as kernels."""

import pytest

from ec2patcher.services import cve_resolver as cr


@pytest.mark.parametrize(
    "package",
    ["linux-tools-common", "linux-tools-6.8.0-149", "linux-cloud-tools-common:amd64",
     "linux-headers-6.8.0-149-generic"],
)  # fmt: skip
def test_kernel_userspace_packages_say_tools_only(package):
    assert cr.reboot_impact(package, False) is None  # still no reboot requested
    assert cr.no_reboot_label(package) == cr.KERNEL_TOOLS_NO_REBOOT


@pytest.mark.parametrize("package", ["openssl", "linux-libc-dev", "libssl3:amd64", "linux-base"])
def test_other_packages_keep_the_plain_label(package):
    assert cr.no_reboot_label(package) == cr.NO_REBOOT


def test_a_new_kernel_image_still_expects_a_reboot():
    assert cr.reboot_impact("linux-image-6.8.0-149-generic", False).startswith("Reboot expected")
