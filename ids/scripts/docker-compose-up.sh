#!/bin/sh

# Docker Compose Up Script for Honeypot IDS System
# Starts all services defined in docker-compose.yml

set -e

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$SCRIPT_DIR/.."

echo "Starting Honeypot IDS System..."
echo "================================"

# Check if docker compose is available
if ! docker compose version >/dev/null 2>&1; then
    echo "Error: docker compose is not installed or not available"
    exit 1
fi

# Check if docker-compose.yml exists
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: docker-compose.yml not found in current directory"
    exit 1
fi

# Deliberately plain `docker compose up`, no --profile: vector
# (profiles: [elk]) is meant to stay opt-in here -- it always tries to
# connect out to VECTOR_HOST (vector/vector.yaml has no ELK_ENABLED gate
# of its own; that env var isn't referenced there at all), so blanket-
# starting it for everyone running this script would mean real outbound
# connection attempts nobody asked for. Use
# `docker compose --profile elk up` (or the dashboard's Services page)
# to include it. docker-purge.sh/docker-compose-down.sh, by contrast, DO
# use --profile '*' -- tearing down must always cover everything that
# might be running, regardless of which profile started it.
# Remove host iptables rules orphaned by a previous teardown before starting.
# Docker does not reliably drop its raw-table anti-spoof rules when a network
# is removed; the leftover `! -i <dead-bridge>` DROP then blackholes the reused
# container IP on this `up` (e.g. production_db_seed can't reach
# production_database). Non-fatal -- see scripts/prune_orphan_iptables.sh.
sh "$SCRIPT_DIR/prune_orphan_iptables.sh" || true

echo "Starting services with docker compose..."
docker compose up --build

echo ""
echo "Services stopped."