# WebTransport Transport

A FIPS transport that uses unreliable QUIC datagrams via WebTransport
(HTTP/3). Behind the `webtransport` cargo feature flag, using the
[wtransport](https://crates.io/crates/wtransport) crate.

## Building

```bash
cargo build --features webtransport
```

The `webtransport` feature is not included in the default build. When
disabled, all WebTransport code is compiled out and there is zero impact
on the binary.

## Configuration

Add a `webtransport` section under `transports` in the node config:

```yaml
transports:
  webtransport:
    bind_addr: "0.0.0.0:4433"
    cert_file: "/etc/fips/wt-cert.pem"
    key_file: "/etc/fips/wt-key.pem"
    mtu: 1200
    accept_connections: true
```

### Options

| Field | Default | Description |
|-------|---------|-------------|
| `bind_addr` | *(none)* | Server listen address (`host:port`). When set, the transport accepts incoming WebTransport sessions. When absent, the transport operates in client-only mode. A transport with `bind_addr` set can do both: accept inbound and initiate outbound connections. |
| `cert_file` | `/etc/fips/wt-cert.pem` | Path to the TLS certificate PEM file. If the file doesn't exist on first startup, a self-signed certificate is generated and saved here. |
| `key_file` | `/etc/fips/wt-key.pem` | Path to the TLS private key PEM file. Generated alongside the certificate if absent. |
| `mtu` | `1200` | Maximum datagram payload size in bytes. QUIC datagrams are bounded by path MTU; 1200 is a conservative default. |
| `accept_connections` | `true` | Whether to accept incoming WebTransport sessions. |

### Peer addresses

Reference the transport in peer config with type `"webtransport"`:

```yaml
peers:
  - npub: "npub1..."
    addresses:
      - transport: "webtransport"
        addr: "192.168.1.1:4433"
```

### Client-only mode

A node with `webtransport: {}` (no `bind_addr`) starts the transport
without binding a port. It can still make outbound connections to peers
that have a `webtransport` address configured:

```yaml
transports:
  webtransport: {}

peers:
  - npub: "npub1..."
    addresses:
      - transport: "webtransport"
        addr: "10.0.0.1:4433"
```

## Transport properties

| Property | Value |
|----------|-------|
| Connection-oriented | Yes (QUIC session establishment) |
| Reliable | No (datagrams are unreliable, unordered) |
| Encrypted | Yes (TLS 1.3 via QUIC, plus FIPS Noise IK) |

This is a unique combination in FIPS — TCP and Tor are connection-oriented
but reliable, UDP and Ethernet are unreliable but connectionless.
WebTransport needs a connection (for the QUIC/TLS handshake) but data
delivery is unreliable.

### TLS and authentication

TLS is mandatory for QUIC/HTTP3. The server loads (or generates) a
persistent certificate. The client skips TLS certificate validation
(`dangerous-configuration` feature in `rustls`) because FIPS authenticates
peers at the Noise IK layer — TLS is just mandatory ceremony for QUIC
compliance.

For future browser clients, the certificate hash can be used with the
browser's `serverCertificateHashes` option (see the standalone demo
below).

### Datagram size limits

QUIC datagrams are bounded by path MTU, typically around 1200 bytes.
There is no fragmentation or reassembly — if a datagram doesn't fit in
one QUIC packet, the send fails.

## Two-node test

A localhost test with two FIPS nodes peering over WebTransport. No
Docker, no `sudo`, no TUN.

```bash
cargo build --features webtransport
bash testing/webtransport/run.sh
```

**Node A** runs a WebTransport server on `127.0.0.1:4433`. **Node B**
connects as a client and initiates a Noise IK handshake. Log lines are
prefixed `[A]` and `[B]`.

### What to look for

```
[A] WebTransport server started ... bind_addr=127.0.0.1:4433
[B] WebTransport transport started (client-only)
[B] WebTransport client connected
[A] WebTransport session accepted
[B] Sent Noise handshake message 1 ... bytes=114
[A] Sent msg2 response ... bytes=69
[A] Inbound peer promoted to active peer=npub1tdwa...
[B] Peer promoted to active peer=npub1sjlh...
[A] Mesh size estimate estimated_mesh_size=2
[B] Mesh size estimate estimated_mesh_size=2
```

The full sequence — QUIC connect, Noise handshake, tree convergence,
bloom filter exchange — completes in about 1 second on localhost.

### Test node identities

| Node | nsec (hex) | npub |
|------|-----------|------|
| A | `010203...1f20` | `npub1sjlh2c3x9w7kjsqg2ay080n2lff2uvt325vpan33ke34rn8l5jcqawh57m` |
| B | `b10203...1fb0` | `npub1tdwa4vjrjl33pcjdpf2t4p027nl86xrx24g4d3avg4vwvayr3g8qhd84le` |

These are the same test keys used by the chain topology in
`testing/static/configs/topologies/chain.yaml`.

## Standalone demo

The `demo/` subdirectory contains a minimal WebTransport echo server and
browser client, independent of FIPS. Useful for learning and testing the
WebTransport protocol in isolation.

### Running the demo

```bash
cd testing/webtransport/demo
cargo run
```

The server generates a self-signed certificate, prints its SHA-256 hash,
and listens on `https://localhost:4433`.

Open `demo/static/index.html` in Chrome (or any Chromium-based browser).
Paste the certificate hash from the terminal into the hash field, or
append it to the URL as a fragment:

```
file:///path/to/static/index.html#aa:bb:cc:dd:...
```

The page auto-fills the hash from the fragment and auto-connects. Type
messages to send them as unreliable QUIC datagrams — the server echoes
each one back with a UTC timestamp.

### Browser support

| Browser | WebTransport | `serverCertificateHashes` |
|---------|:------------:|:-------------------------:|
| Chrome / Edge | Yes | Yes |
| Opera | Yes | Yes |
| Firefox | Behind flag | No |
| Safari | No | No |

### Self-signed certificate constraints

Chrome requires certificates used with `serverCertificateHashes` to:

- Use ECDSA with P-256
- Have a validity period of at most 14 days
- Be identified by their SHA-256 hash

The `wtransport` crate's `Identity::self_signed()` satisfies all of these.
The certificate hash changes on every server restart (new keypair). The
demo passes it via the URL fragment to avoid manual copy-paste. The FIPS
transport persists certificates to disk so the hash stays stable across
restarts.
