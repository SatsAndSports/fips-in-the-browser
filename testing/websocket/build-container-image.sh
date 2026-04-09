#!/usr/bin/env bash
set -euo pipefail

# Build the FIPS container image with the websocket feature enabled.
#
# Usage:
#   ./testing/websocket/build-container-image.sh [docker|podman]

RUNTIME="${1:-docker}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TESTING_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROJECT_ROOT="$(cd "$TESTING_DIR/.." && pwd)"
DOCKER_DIR="$TESTING_DIR/docker"

if ! command -v "$RUNTIME" >/dev/null 2>&1; then
    echo "Error: runtime '$RUNTIME' not found in PATH" >&2
    exit 1
fi

echo "Building FIPS release binary with websocket feature..."
cargo build --release --features websocket --manifest-path "$PROJECT_ROOT/Cargo.toml"

echo "Copying binaries into testing/docker/..."
cp "$PROJECT_ROOT/target/release/fips" "$DOCKER_DIR/fips"
cp "$PROJECT_ROOT/target/release/fipsctl" "$DOCKER_DIR/fipsctl"
if [ -f "$PROJECT_ROOT/target/release/fipstop" ]; then
    cp "$PROJECT_ROOT/target/release/fipstop" "$DOCKER_DIR/fipstop"
    chmod +x "$DOCKER_DIR/fipstop"
fi
chmod +x "$DOCKER_DIR/fips" "$DOCKER_DIR/fipsctl"

echo "Building image fips-test:latest with $RUNTIME..."
"$RUNTIME" build -t fips-test:latest "$DOCKER_DIR"

echo "Done. Image available as fips-test:latest"
