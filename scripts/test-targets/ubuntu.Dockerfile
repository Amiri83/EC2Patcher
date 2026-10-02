# Ubuntu 24.04 SSH test target: login user "ubuntu", key-only auth, passwordless sudo (as on
# EC2). The public key is mounted at runtime; no key material is baked into the image.
FROM ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        openssh-server sudo \
    && rm -rf /var/lib/apt/lists/*

# The image already ships the "ubuntu" user. '*' = no password, but not "locked" for sshd.
RUN id ubuntu >/dev/null 2>&1 || useradd -m -s /bin/bash ubuntu; \
    usermod -p '*' -s /bin/bash ubuntu \
    && echo 'ubuntu ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/90-ubuntu \
    && chmod 440 /etc/sudoers.d/90-ubuntu \
    && sed -i 's/^session\s\+required\s\+pam_loginuid.so/session optional pam_loginuid.so/' \
        /etc/pam.d/sshd \
    && rm -f /etc/ssh/ssh_host_*

COPY sshd-test-target.conf /etc/ssh/sshd_config.d/00-test-target.conf
COPY entrypoint.sh /usr/local/bin/test-target-entrypoint
RUN chmod 755 /usr/local/bin/test-target-entrypoint

ENV TARGET_USER=ubuntu
EXPOSE 22
ENTRYPOINT ["/usr/local/bin/test-target-entrypoint"]
