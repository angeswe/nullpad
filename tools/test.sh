#!/usr/bin/env bash
# Run integration tests and clean up orphaned Redis containers.
#
# testcontainers-rs uses a static OnceCell that never drops, so Redis
# containers leak on every test run. This script prunes them afterward.

set -euo pipefail

cleanup() {
    local containers
    containers=$(docker ps -aq --filter "label=nullpad-test=integration" 2>/dev/null || true)
    if [ -n "$containers" ]; then
        echo "Cleaning up test Redis containers..."
        docker rm -f $containers >/dev/null 2>&1 || true
    fi
}

trap cleanup EXIT

cargo test --test integration -- --test-threads=1 "$@"
