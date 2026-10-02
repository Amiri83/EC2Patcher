# Amazon Linux 2023 SSH test target: login user "ec2-user", key-only auth, passwordless sudo
# (as on EC2). The public key is mounted at runtime; no key material is baked into the image.
# dnf-utils provides needs-restarting (reboot check of the analysis); python3-rpm is the
# integration tests' independent version-comparison oracle (rpm.labelCompare).
FROM amazonlinux:2023

RUN dnf install -y openssh-server sudo shadow-utils hostname procps-ng dnf-utils python3-rpm \
    && dnf clean all \
    && rm -rf /var/cache/dnf

# '*' = no password, but not "locked" for sshd.
RUN useradd -m -s /bin/bash ec2-user \
    && usermod -p '*' ec2-user \
    && echo 'ec2-user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ec2-user \
    && chmod 440 /etc/sudoers.d/90-ec2-user \
    && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' \
        /etc/pam.d/sshd \
    && rm -f /etc/ssh/ssh_host_*

COPY sshd-test-target.conf /etc/ssh/sshd_config.d/00-test-target.conf
COPY entrypoint.sh /usr/local/bin/test-target-entrypoint
RUN chmod 755 /usr/local/bin/test-target-entrypoint

ENV TARGET_USER=ec2-user
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/test-target-entrypoint"]
