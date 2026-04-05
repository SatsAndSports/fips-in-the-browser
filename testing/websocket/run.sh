#!/usr/bin/env bash
#
# WebSocket transport browser test.
#
# Starts a FIPS node with a WebSocket server on ws://localhost:8080.
# Open the browser client to connect and complete a Noise IK handshake.
#
# Usage:
#   cargo build --features websocket
#   bash testing/websocket/run.sh
#
# Then:
#   cd browser && wasm-pack build --target web
#   python3 -m http.server 8080 --directory browser  # from repo root, different port!
#   # Or: cd browser && python3 -m http.server 9000
#   # Open http://localhost:9000/www/

set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
FIPS="${DIR}/../../target/debug/fips"
TMPDIR="/tmp/fips-ws-test"

if [ ! -x "$FIPS" ]; then
    echo "Binary not found at $FIPS"
    echo "Run: cargo build --features websocket"
    exit 1
fi

mkdir -p "$TMPDIR"
rm -f "$TMPDIR/control-a.sock"

echo "=== FIPS Node (WebSocket server on ws://localhost:8080) ==="
echo ""
echo "  npub: npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m"
echo ""
echo "  To connect from the browser:"
echo "    1. cd browser && wasm-pack build --target web"
echo "    2. cd browser && python3 -m http.server 9000"
echo "    3. Open http://localhost:9000/www/"
echo "    4. Enter ws://localhost:8080 and the npub above"
echo ""

RUST_LOG=info,fips=debug "$FIPS" --config "$DIR/node-a.yaml"
