"""The reason shown for a failed apt-get install names the real cause, not only apt's summary."""

from ec2patcher.services.patch_service import install_error_lines

OUTPUT = """\
Selecting previously unselected package linux-image-1.0.0-2-flavour.
Setting up linux-image-1.0.0-2-flavour (1.0.0-2.2) ...
update-initramfs: Generating /boot/initrd.img-1.0.0-2-flavour
gzip: stdout: No space left on device
E: mkinitramfs failure gzip 1
update-initramfs: failed for /boot/initrd.img-1.0.0-2-flavour with 1.
run-parts: /etc/kernel/postinst.d/initramfs-tools exited with return code 1
dpkg: error processing package linux-image-1.0.0-2-flavour (--configure):
 installed linux-image-1.0.0-2-flavour package post-installation script subprocess \
returned error exit status 1
Errors were encountered while processing:
 linux-image-1.0.0-2-flavour
E: Sub-process /usr/bin/dpkg returned an error code (1)
""".splitlines()


def test_cause_lines_come_first_and_apt_summary_last():
    lines = install_error_lines(OUTPUT)
    assert lines[0] == "gzip: stdout: No space left on device"
    assert any(ln.startswith("dpkg: error processing package") for ln in lines)
    assert lines[-1].startswith("E: ") and len(lines) <= 6


def test_plain_apt_error_still_reported():
    assert install_error_lines(["E: Unable to locate package x"]) == [
        "E: Unable to locate package x"
    ]
