#!/usr/bin/env bash
#
# Two-node WebTransport transport test.
#
# Node A runs a WebTransport server on 127.0.0.1:4433.
# Node B connects as a client and peers over QUIC datagrams.
#
# Usage:
#   cargo build --features webtransport
#   bash testing/webtransport/run.sh
#
# What to look for in the output:
#   - "WebTransport server started"           (Node A)
#   - "WebTransport client connected"         (Node B)
#   - "WebTransport session accepted"         (Node A)
#   - "peer promoted to active"              (both)
#   - "TreeAnnounce" exchanges               (both)

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
FIPS="${DIR}/../../target/debug/fips"
TMPDIR="/tmp/fips-wt-test"

if [ ! -x "$FIPS" ]; then
    echo "Binary not found at $FIPS"
    echo "Run: cargo build --features webtransport"
    exit 1
fi

mkdir -p "$TMPDIR"

# Clean up stale state from previous runs
rm -f "$TMPDIR/control-a.sock" "$TMPDIR/control-b.sock"

cleanup() {
    echo ""
    echo "Stopping nodes..."
    kill "$PID_A" "$PID_B" 2>/dev/null
    wait "$PID_A" "$PID_B" 2>/dev/null
    echo "Done."
}
trap cleanup EXIT

echo "=== Starting Node A (WebTransport server) ==="
RUST_LOG=info,fips=debug "$FIPS" --config "$DIR/node-a.yaml" 2>&1 | sed 's/^/[A] /' &
PID_A=$!

# Give Node A time to generate cert and bind the port
sleep 2

echo ""
echo "=== Starting Node B (WebTransport client) ==="
RUST_LOG=info,fips=debug "$FIPS" --config "$DIR/node-b.yaml" 2>&1 | sed 's/^/[B] /' &
PID_B=$!

echo ""
echo "Both nodes running. Press Ctrl+C to stop."
echo ""

wait
