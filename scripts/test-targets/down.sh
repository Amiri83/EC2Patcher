#!/bin/sh
# Stop and remove the local SSH test targets. The key pair in .keys/ is kept for the next run
# (delete the directory to rotate it).
set -eu

cd "$(dirname "$0")"
DOCKER="${DOCKER:-sudo docker}"
$DOCKER compose -f compose.yaml down --remove-orphans
