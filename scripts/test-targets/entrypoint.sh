#!/bin/sh
# Test target entrypoint: install the runtime-generated public key for $TARGET_USER, create
# fresh host keys and run sshd in the foreground (key-only auth, see sshd-test-target.conf).
set -eu

: "${TARGET_USER:?TARGET_USER must be set}"
home="/home/${TARGET_USER}"
key=/keys/authorized_keys

if [ ! -s "$key" ]; then
    echo "No public key mounted at $key (run scripts/test-targets/up.sh)." >&2
    exit 1
fi

install -d -m 700 -o "$TARGET_USER" -g "$TARGET_USER" "$home/.ssh"
install -m 600 -o "$TARGET_USER" -g "$TARGET_USER" "$key" "$home/.ssh/authorized_keys"
ssh-keygen -A >/dev/null
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e
