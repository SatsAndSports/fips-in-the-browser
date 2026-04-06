# WebSocket Transport

A FIPS transport that uses WebSocket binary messages for packet delivery.
Behind the `websocket` cargo feature flag, using
[tokio-tungstenite](https://crates.io/crates/tokio-tungstenite).

Each WebSocket binary message carries one FMP packet. No TLS — FIPS handles
authentication and encryption at the Noise layer; WebSocket is just the
byte pipe.

## Building

```bash
cargo build --features websocket
```

The `websocket` feature is not included in the default build. When
disabled, all WebSocket code is compiled out.

## Configuration

Add a `websocket` section under `transports` in the node config:

```yaml
transports:
  websocket:
    bind_addr: "127.0.0.1:8080"
```

### Options

| Field | Default | Description |
|-------|---------|-------------|
| `bind_addr` | *(none)* | Server listen address (`host:port`). When set, the transport accepts incoming WebSocket connections (HTTP Upgrade). When absent, the transport operates in client-only mode. A transport with `bind_addr` set can do both: accept inbound and initiate outbound connections. |
| `accept_connections` | `true` | Whether to accept incoming WebSocket connections. |

### Peer addresses

Reference the transport in peer config with type `"websocket"`:

```yaml
peers:
  - npub: "npub1..."
    addresses:
      - transport: "websocket"
        addr: "192.168.1.1:8080"
```

### Client-only mode

A node with `websocket: {}` (no `bind_addr`) starts the transport
without binding a port. It can still make outbound connections to peers
that have a `websocket` address configured.

## Transport properties

| Property | Value |
|----------|-------|
| Connection-oriented | Yes (TCP + WebSocket handshake) |
| Reliable | Yes (TCP provides reliable, ordered delivery) |
| Encrypted | No at WebSocket layer (FIPS Noise IK handles encryption) |
| MTU | Effectively unlimited (TCP stream, no datagram size limit) |

## Browser client

The `browser/` directory at the repository root contains a FIPS node
that runs in the browser via WebAssembly. It uses the same Noise IK
handshake and FMP wire format as native FIPS nodes, with WebSocket as
the transport layer.

### Building the browser client

```bash
cd browser
wasm-pack build --target web
```

This produces a `pkg/` directory with the WASM binary and JS bindings.

### Running

**Terminal 1 — FIPS node with WebSocket server:**

```bash
cargo build --features websocket
bash testing/websocket/run.sh
```

**Terminal 2 — Serve the browser client:**

```bash
cd browser
python3 -m http.server 9000
```

**Browser:**

1. Open `http://localhost:9000/www/`
2. Enter `ws://localhost:8080` as the WebSocket URL
3. Enter the node's npub (printed by `run.sh`)
4. Click "Connect + Handshake"

### What happens

1. The browser loads the WASM module (156 KB) containing the FIPS
   protocol stack (Noise IK, FMP framing, ChaCha20-Poly1305)
2. A random FIPS identity (secp256k1 keypair) is generated in the browser
3. The browser connects to the FIPS node via WebSocket
4. A Noise IK handshake is performed — the browser uses k256 (pure Rust
   secp256k1) and the server uses the secp256k1 FFI crate. The ECDH
   produces identical shared secrets (both compute SHA-256 of the
   x-coordinate of the shared elliptic curve point)
5. After the handshake, both sides derive matching ChaCha20-Poly1305
   cipher keys
6. The FIPS node promotes the browser as an active peer and begins
   sending protocol messages (TreeAnnounce, FilterAnnounce, MMP reports)

### Browser WASM architecture

```
Browser
├── JS:   WebSocket API (send/recv binary messages)
├── WASM: fips protocol core
│         ├── Identity (k256 keypairs, NodeAddr, npub/nsec)
│         ├── Noise IK (handshake state machine)
│         ├── CipherState (ChaCha20-Poly1305 + replay window)
│         └── FMP wire format (build/parse all frame types)
└── HTML: UI (connect, send messages, protocol log)
```

The WASM code is a standalone crate (`browser/`) that adapts the
cryptographic primitives from the native fips codebase for
`wasm32-unknown-unknown`. The key difference is the use of `k256`
(pure Rust) instead of the `secp256k1` FFI crate — both produce
byte-identical ECDH results.

### Current limitations

The browser client currently implements Phase 1 only:

- Noise IK handshake (mutual authentication)
- Encrypted data frame exchange

It does **not** yet respond to:

- TreeAnnounce (tree protocol)
- FilterAnnounce (bloom filter routing)
- MMP SenderReports (link quality metrics)

Because of this, the FIPS node will remove the browser peer after 30
seconds (link dead timeout) due to missing MMP responses. Phase 2 will
add these responses to keep the link alive indefinitely.
