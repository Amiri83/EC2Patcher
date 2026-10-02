#!/bin/sh
# Start the local SSH test targets (Ubuntu 24.04 + Amazon Linux 2023) for
# `pytest -m integration`. Generates the test key pair on first use (never committed).
# Docker runs through sudo unless DOCKER is set, e.g. DOCKER=docker ./up.sh
set -eu

cd "$(dirname "$0")"
DOCKER="${DOCKER:-sudo docker}"
UBUNTU_PORT="${EC2P_IT_UBUNTU_PORT:-2201}"
AMAZON_PORT="${EC2P_IT_AMAZON_PORT:-2202}"
export EC2P_IT_UBUNTU_PORT="$UBUNTU_PORT" EC2P_IT_AMAZON_PORT="$AMAZON_PORT"

if [ ! -f .keys/id_ed25519 ]; then
    mkdir -p .keys
    chmod 700 .keys
    ssh-keygen -q -t ed25519 -N "" -C "ec2patcher-test-targets" -f .keys/id_ed25519
fi
chmod 600 .keys/id_ed25519

$DOCKER compose -f compose.yaml up -d --build

# Wait until both sshd answer (host key exchange only, no login).
for port in "$UBUNTU_PORT" "$AMAZON_PORT"; do
    tries=0
    until ssh-keyscan -T 2 -p "$port" 127.0.0.1 >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then
            echo "sshd on 127.0.0.1:$port did not come up" >&2
            $DOCKER compose -f compose.yaml logs --tail 50 >&2
            exit 1
        fi
        sleep 1
    done
done

echo "Test targets ready: ubuntu@127.0.0.1:$UBUNTU_PORT, ec2-user@127.0.0.1:$AMAZON_PORT"
echo "Key: $(pwd)/.keys/id_ed25519"
