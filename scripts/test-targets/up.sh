#!/bin/sh
# Start the local SSH test targets (Ubuntu 24.04 + Amazon Linux 2023) for
# `pytest -m integration`. Generates the test key pair on first use (never committed).
# Docker runs through sudo unless DOCKER is set, e.g. DOCKER=docker ./up.sh
# Without the `docker compose` plugin, falls back to plain `docker build` + `docker run`
# with the same images, hostnames, ports and key mount as compose.yaml.
set -eu

cd "$(dirname "$0")"
DOCKER="${DOCKER:-sudo docker}"
UBUNTU_PORT="${EC2P_IT_UBUNTU_PORT:-2201}"
AMAZON_PORT="${EC2P_IT_AMAZON_PORT:-2202}"
export EC2P_IT_UBUNTU_PORT="$UBUNTU_PORT" EC2P_IT_AMAZON_PORT="$AMAZON_PORT"

UBUNTU_IMAGE="ec2patcher-test-target-ubuntu:24.04"
UBUNTU_NAME="ec2p-test-ubuntu"
AMAZON_IMAGE="ec2patcher-test-target-amazonlinux:2023"
AMAZON_NAME="ec2p-test-amazonlinux"

if [ ! -f .keys/id_ed25519 ]; then
    mkdir -p .keys
    chmod 700 .keys
    ssh-keygen -q -t ed25519 -N "" -C "ec2patcher-test-targets" -f .keys/id_ed25519
fi
chmod 600 .keys/id_ed25519

# start_target <image> <dockerfile> <name> <port>
start_target() {
    $DOCKER build -t "$1" -f "$2" .
    $DOCKER rm -f "$3" >/dev/null 2>&1 || true
    $DOCKER run -d --name "$3" --hostname "$3" -p "127.0.0.1:$4:22" \
        -v "$PWD/.keys/id_ed25519.pub:/keys/authorized_keys:ro" "$1"
}

if $DOCKER compose version >/dev/null 2>&1; then
    USE_COMPOSE=1
    $DOCKER compose -f compose.yaml up -d --build
else
    USE_COMPOSE=0
    echo "docker compose not available, using docker build + docker run" >&2
    start_target "$UBUNTU_IMAGE" ubuntu.Dockerfile "$UBUNTU_NAME" "$UBUNTU_PORT"
    start_target "$AMAZON_IMAGE" amazonlinux.Dockerfile "$AMAZON_NAME" "$AMAZON_PORT"
fi

show_logs() {
    if [ "$USE_COMPOSE" -eq 1 ]; then
        $DOCKER compose -f compose.yaml logs --tail 50 >&2
    else
        for name in "$UBUNTU_NAME" "$AMAZON_NAME"; do
            echo "--- $name ---" >&2
            $DOCKER logs --tail 50 "$name" >&2 || true
        done
    fi
}

# Wait until both sshd answer (host key exchange only, no login).
for port in "$UBUNTU_PORT" "$AMAZON_PORT"; do
    tries=0
    until ssh-keyscan -T 2 -p "$port" 127.0.0.1 >/dev/null 2>&1; do
        tries=$((tries + 1))
        if [ "$tries" -ge 30 ]; then
            echo "sshd on 127.0.0.1:$port did not come up" >&2
            show_logs
            exit 1
        fi
        sleep 1
    done
done

echo "Test targets ready: ubuntu@127.0.0.1:$UBUNTU_PORT, ec2-user@127.0.0.1:$AMAZON_PORT"
echo "Key: $(pwd)/.keys/id_ed25519"
