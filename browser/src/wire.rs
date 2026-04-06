//! FMP wire format (link-layer packet framing).
//!
//! Pure byte layout, no crypto deps. Adapted from fips `src/node/wire.rs`.
//!
//! ## Common Prefix (4 bytes, all packets)
//! ```text
//! [ver(4bit)+phase(4bit)] [flags:1] [payload_len:2 LE]
//! ```
//!
//! ## Packet Types
//! | Phase | Type            | Total wire size |
//! |-------|-----------------|-----------------|
//! | 0x1   | Noise IK msg1   | 114 bytes       |
//! | 0x2   | Noise IK msg2   | 69 bytes        |
//! | 0x0   | Encrypted frame | 32+ bytes       |

use crate::noise::{HANDSHAKE_MSG1_SIZE, HANDSHAKE_MSG2_SIZE};

// ============================================================================
// Protocol constants
// ============================================================================

/// FMP protocol version.
pub const FMP_VERSION: u8 = 0;

pub const PHASE_ESTABLISHED: u8 = 0x0;
pub const PHASE_MSG1: u8 = 0x1;
pub const PHASE_MSG2: u8 = 0x2;

/// Common prefix size (all packets).
pub const COMMON_PREFIX_SIZE: usize = 4;

/// Established frame header: prefix(4) + receiver_idx(4) + counter(8) = 16.
pub const ESTABLISHED_HEADER_SIZE: usize = 16;

/// Msg1 wire: prefix(4) + sender_idx(4) + noise_msg1(106) = 114.
pub const MSG1_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + HANDSHAKE_MSG1_SIZE;

/// Msg2 wire: prefix(4) + sender_idx(4) + receiver_idx(4) + noise_msg2(57) = 69.
pub const MSG2_WIRE_SIZE: usize = COMMON_PREFIX_SIZE + 4 + 4 + HANDSHAKE_MSG2_SIZE;

/// Minimum encrypted frame: header(16) + tag(16) = 32.
pub const ENCRYPTED_MIN_SIZE: usize = ESTABLISHED_HEADER_SIZE + 16;

/// Inner header size (timestamp + message type).
pub const INNER_HEADER_SIZE: usize = 5;

// ============================================================================
// Link-layer message type constants
// ============================================================================

/// SessionDatagram — encapsulated session-layer payload for multi-hop forwarding.
pub const MSG_TYPE_SESSION_DATAGRAM: u8 = 0x00;
/// MMP SenderReport.
pub const MSG_TYPE_SENDER_REPORT: u8 = 0x01;
/// MMP ReceiverReport.
pub const MSG_TYPE_RECEIVER_REPORT: u8 = 0x02;
/// TreeAnnounce — spanning tree declaration.
pub const MSG_TYPE_TREE_ANNOUNCE: u8 = 0x10;
/// FilterAnnounce — bloom filter routing update.
pub const MSG_TYPE_FILTER_ANNOUNCE: u8 = 0x20;
/// Disconnect — orderly link closure.
pub const MSG_TYPE_DISCONNECT: u8 = 0x50;
/// Heartbeat — liveness keepalive (empty payload).
pub const MSG_TYPE_HEARTBEAT: u8 = 0x51;

// ============================================================================
// Time helpers
// ============================================================================

/// Get current time in milliseconds since epoch.
pub fn current_time_ms() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// Get current Unix timestamp in seconds.
pub fn current_unix_secs() -> u64 {
    current_time_ms() / 1000
}

/// Get a session-relative timestamp in milliseconds (wrapping u32).
pub fn current_timestamp_ms() -> u32 {
    (current_time_ms() & 0xFFFFFFFF) as u32
}

// ============================================================================
// Parsing
// ============================================================================

/// Parsed common prefix.
pub struct CommonPrefix {
    pub phase: u8,
}

impl CommonPrefix {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
            return None;
        }
        Some(Self {
            phase: data[0] & 0x0F,
        })
    }
}

/// Parsed msg2 header.
pub struct Msg2Header {
    pub sender_idx: u32,
    pub noise_payload: Vec<u8>,
}

impl Msg2Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < MSG2_WIRE_SIZE {
            return None;
        }
        let prefix = CommonPrefix::parse(data)?;
        if prefix.phase != PHASE_MSG2 {
            return None;
        }
        let sender_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        // Skip receiver_idx at [8..12] — we don't need it (it's our own index).
        let noise_payload = data[12..MSG2_WIRE_SIZE].to_vec();
        Some(Self {
            sender_idx,
            noise_payload,
        })
    }
}

/// Parsed encrypted frame header.
pub struct EncryptedHeader {
    pub counter: u64,
    pub header_bytes: [u8; ESTABLISHED_HEADER_SIZE],
}

impl EncryptedHeader {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ENCRYPTED_MIN_SIZE {
            return None;
        }
        let version = data[0] >> 4;
        let phase = data[0] & 0x0F;
        if version != FMP_VERSION || phase != PHASE_ESTABLISHED {
            return None;
        }
        let counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let mut header_bytes = [0u8; ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..ESTABLISHED_HEADER_SIZE]);
        Some(Self {
            counter,
            header_bytes,
        })
    }

    pub fn ciphertext<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        &data[ESTABLISHED_HEADER_SIZE..]
    }
}

// ============================================================================
// Building
// ============================================================================

/// Build a msg1 wire packet.
///
/// Wire format: [prefix:4][sender_idx:4 LE][noise_msg1:106] = 114 bytes.
pub fn build_msg1(sender_idx: u32, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);
    let payload_len = (4 + noise_msg1.len()) as u16;
    let mut pkt = Vec::with_capacity(MSG1_WIRE_SIZE);
    pkt.push((FMP_VERSION << 4) | PHASE_MSG1);
    pkt.push(0x00);
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    pkt.extend_from_slice(&sender_idx.to_le_bytes());
    pkt.extend_from_slice(noise_msg1);
    debug_assert_eq!(pkt.len(), MSG1_WIRE_SIZE);
    pkt
}

/// Build the 16-byte FMP header for an established frame.
///
/// Used as both the wire header and the AEAD AAD. `payload_len` is the
/// inner plaintext length (before the AEAD tag is appended).
pub fn build_established_header(
    flags: u8,
    payload_len: u16,
    receiver_idx: u32,
    counter: u64,
) -> [u8; ESTABLISHED_HEADER_SIZE] {
    let mut hdr = [0u8; ESTABLISHED_HEADER_SIZE];
    hdr[0] = (FMP_VERSION << 4) | PHASE_ESTABLISHED;
    hdr[1] = flags;
    hdr[2..4].copy_from_slice(&payload_len.to_le_bytes());
    hdr[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    hdr[8..16].copy_from_slice(&counter.to_le_bytes());
    hdr
}

/// Parse inner header from decrypted plaintext.
///
/// Returns (timestamp, msg_type, payload_slice).
pub fn parse_inner(data: &[u8]) -> Option<(u32, u8, &[u8])> {
    if data.len() < INNER_HEADER_SIZE {
        return None;
    }
    let timestamp = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    let msg_type = data[4];
    Some((timestamp, msg_type, &data[INNER_HEADER_SIZE..]))
}

// ============================================================================
// FSP (FIPS Session Protocol) constants and helpers
// ============================================================================

/// FSP header size (ver_phase + flags + payload_len + counter).
pub const FSP_HEADER_SIZE: usize = 12;

/// FSP inner header size (timestamp + msg_type + inner_flags).
pub const FSP_INNER_HEADER_SIZE: usize = 6;

/// FSP phases.
pub const FSP_PHASE_ESTABLISHED: u8 = 0x0;
pub const FSP_PHASE_SETUP: u8 = 0x1;
pub const FSP_PHASE_ACK: u8 = 0x2;
pub const FSP_PHASE_MSG3: u8 = 0x3;

/// FSP session message types (inside AEAD envelope).
pub const FSP_MSG_TYPE_DATA: u8 = 0x10;

/// FSP port for chat messages.
pub const FSP_PORT_CHAT: u16 = 1;

/// FSP port for IPv6 shim (Phase 3 IPv6).
#[allow(dead_code)]
pub const FSP_PORT_IPV6_SHIM: u16 = 256;

/// AEAD tag size.
pub const AEAD_TAG_SIZE: usize = 16;

// ============================================================================
// SessionDatagram (link-layer envelope for session payloads)
// ============================================================================

/// SessionDatagram header size: ttl(1) + path_mtu(2) + src_addr(16) + dest_addr(16) = 35.
pub const SESSION_DATAGRAM_HEADER_SIZE: usize = 35;

/// Build a SessionDatagram payload (after msg_type 0x00).
///
/// Wire: [ttl:1][path_mtu:2 LE][src_addr:16][dest_addr:16][fsp_payload...]
/// The msg_type byte (0x00) is prepended by the caller.
pub fn build_session_datagram_body(
    ttl: u8,
    path_mtu: u16,
    src_addr: &[u8; 16],
    dest_addr: &[u8; 16],
    fsp_payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(SESSION_DATAGRAM_HEADER_SIZE + fsp_payload.len());
    body.push(ttl);
    body.extend_from_slice(&path_mtu.to_le_bytes());
    body.extend_from_slice(src_addr);
    body.extend_from_slice(dest_addr);
    body.extend_from_slice(fsp_payload);
    body
}

/// Parse a SessionDatagram body (after msg_type 0x00 has been stripped).
///
/// Returns (ttl, path_mtu, src_addr, dest_addr, fsp_payload).
pub fn parse_session_datagram_body(data: &[u8]) -> Option<(u8, u16, [u8; 16], [u8; 16], &[u8])> {
    if data.len() < SESSION_DATAGRAM_HEADER_SIZE {
        return None;
    }
    let ttl = data[0];
    let path_mtu = u16::from_le_bytes([data[1], data[2]]);
    let mut src_addr = [0u8; 16];
    src_addr.copy_from_slice(&data[3..19]);
    let mut dest_addr = [0u8; 16];
    dest_addr.copy_from_slice(&data[19..35]);
    let fsp_payload = &data[35..];
    Some((ttl, path_mtu, src_addr, dest_addr, fsp_payload))
}

// ============================================================================
// Coordinate encoding (compact, address-only)
// ============================================================================

/// Encode coordinates as [count:2 LE][addr:16 * count].
pub fn encode_coords(coords: &[[u8; 16]]) -> Vec<u8> {
    let count = coords.len() as u16;
    let mut out = Vec::with_capacity(2 + coords.len() * 16);
    out.extend_from_slice(&count.to_le_bytes());
    for addr in coords {
        out.extend_from_slice(addr);
    }
    out
}

// ============================================================================
// SessionSetup / SessionAck / SessionMsg3 builders
// ============================================================================

/// Build a SessionSetup (FSP phase 0x1) payload.
///
/// Wire: [0x01][0x00][payload_len:2 LE][flags:1][src_coords][dest_coords][hs_len:2 LE][hs_payload]
pub fn build_session_setup(
    src_coords: &[[u8; 16]],
    dest_coords: &[[u8; 16]],
    handshake_payload: &[u8],
) -> Vec<u8> {
    let src_enc = encode_coords(src_coords);
    let dest_enc = encode_coords(dest_coords);
    let hs_len = handshake_payload.len() as u16;
    let body_len = 1 + src_enc.len() + dest_enc.len() + 2 + handshake_payload.len();

    let mut out = Vec::with_capacity(4 + body_len);
    // FSP prefix
    out.push((0 << 4) | FSP_PHASE_SETUP); // ver=0, phase=1
    out.push(0x00); // flags
    out.extend_from_slice(&(body_len as u16).to_le_bytes());
    // Body
    out.push(0x00); // session_flags
    out.extend_from_slice(&src_enc);
    out.extend_from_slice(&dest_enc);
    out.extend_from_slice(&hs_len.to_le_bytes());
    out.extend_from_slice(handshake_payload);
    out
}

/// Build a SessionAck (FSP phase 0x2) payload.
///
/// Wire: [0x02][0x00][payload_len:2 LE][flags:1][src_coords][dest_coords][hs_len:2 LE][hs_payload]
pub fn build_session_ack(
    src_coords: &[[u8; 16]],
    dest_coords: &[[u8; 16]],
    handshake_payload: &[u8],
) -> Vec<u8> {
    let src_enc = encode_coords(src_coords);
    let dest_enc = encode_coords(dest_coords);
    let hs_len = handshake_payload.len() as u16;
    let body_len = 1 + src_enc.len() + dest_enc.len() + 2 + handshake_payload.len();

    let mut out = Vec::with_capacity(4 + body_len);
    out.push((0 << 4) | FSP_PHASE_ACK);
    out.push(0x00);
    out.extend_from_slice(&(body_len as u16).to_le_bytes());
    out.push(0x00); // flags
    out.extend_from_slice(&src_enc);
    out.extend_from_slice(&dest_enc);
    out.extend_from_slice(&hs_len.to_le_bytes());
    out.extend_from_slice(handshake_payload);
    out
}

/// Build a SessionMsg3 (FSP phase 0x3) payload.
///
/// Wire: [0x03][0x00][payload_len:2 LE][flags:1][hs_len:2 LE][hs_payload]
/// Note: no coordinates in msg3.
pub fn build_session_msg3(handshake_payload: &[u8]) -> Vec<u8> {
    let hs_len = handshake_payload.len() as u16;
    let body_len = 1 + 2 + handshake_payload.len();

    let mut out = Vec::with_capacity(4 + body_len);
    out.push((0 << 4) | FSP_PHASE_MSG3);
    out.push(0x00);
    out.extend_from_slice(&(body_len as u16).to_le_bytes());
    out.push(0x00); // flags
    out.extend_from_slice(&hs_len.to_le_bytes());
    out.extend_from_slice(handshake_payload);
    out
}

/// Parse a SessionSetup body (after the 4-byte FSP prefix).
///
/// Returns (src_coords, dest_coords, handshake_payload).
pub fn parse_session_setup_body(data: &[u8]) -> Option<(Vec<[u8; 16]>, Vec<[u8; 16]>, Vec<u8>)> {
    if data.len() < 1 {
        return None;
    }
    let mut pos = 1; // skip session_flags

    let (src_coords, new_pos) = parse_coords(data, pos)?;
    pos = new_pos;
    let (dest_coords, new_pos) = parse_coords(data, pos)?;
    pos = new_pos;

    if pos + 2 > data.len() {
        return None;
    }
    let hs_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;
    if pos + hs_len > data.len() {
        return None;
    }
    let hs_payload = data[pos..pos + hs_len].to_vec();
    Some((src_coords, dest_coords, hs_payload))
}

/// Parse a SessionAck body (same layout as SessionSetup).
pub fn parse_session_ack_body(data: &[u8]) -> Option<(Vec<[u8; 16]>, Vec<[u8; 16]>, Vec<u8>)> {
    parse_session_setup_body(data) // Same wire layout
}

/// Parse a SessionMsg3 body (after the 4-byte FSP prefix).
///
/// Returns handshake_payload.
pub fn parse_session_msg3_body(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 3 {
        return None;
    }
    let pos = 1; // skip flags
    let hs_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    let start = pos + 2;
    if start + hs_len > data.len() {
        return None;
    }
    Some(data[start..start + hs_len].to_vec())
}

/// Parse coordinate array at a given offset.
/// Returns (coords, new_position).
pub fn parse_coords(data: &[u8], pos: usize) -> Option<(Vec<[u8; 16]>, usize)> {
    if pos + 2 > data.len() {
        return None;
    }
    let count = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    let mut p = pos + 2;
    let mut coords = Vec::with_capacity(count);
    for _ in 0..count {
        if p + 16 > data.len() {
            return None;
        }
        let mut addr = [0u8; 16];
        addr.copy_from_slice(&data[p..p + 16]);
        coords.push(addr);
        p += 16;
    }
    Some((coords, p))
}

/// Build FSP established header (12 bytes, used as AEAD AAD).
pub fn build_fsp_header(flags: u8, payload_len: u16, counter: u64) -> [u8; FSP_HEADER_SIZE] {
    let mut hdr = [0u8; FSP_HEADER_SIZE];
    hdr[0] = (0 << 4) | FSP_PHASE_ESTABLISHED;
    hdr[1] = flags;
    hdr[2..4].copy_from_slice(&payload_len.to_le_bytes());
    hdr[4..12].copy_from_slice(&counter.to_le_bytes());
    hdr
}

/// Build FSP inner header (6 bytes): [timestamp:4 LE][msg_type:1][inner_flags:1].
pub fn build_fsp_inner(
    timestamp: u32,
    msg_type: u8,
    inner_flags: u8,
) -> [u8; FSP_INNER_HEADER_SIZE] {
    let mut hdr = [0u8; FSP_INNER_HEADER_SIZE];
    hdr[0..4].copy_from_slice(&timestamp.to_le_bytes());
    hdr[4] = msg_type;
    hdr[5] = inner_flags;
    hdr
}

/// Parse FSP encrypted header (12 bytes).
/// Returns (flags, payload_len, counter, header_bytes).
pub fn parse_fsp_header(data: &[u8]) -> Option<(u8, u16, u64, [u8; FSP_HEADER_SIZE])> {
    if data.len() < FSP_HEADER_SIZE + AEAD_TAG_SIZE {
        return None;
    }
    let flags = data[1];
    let payload_len = u16::from_le_bytes([data[2], data[3]]);
    let counter = u64::from_le_bytes([
        data[4], data[5], data[6], data[7], data[8], data[9], data[10], data[11],
    ]);
    let mut hdr = [0u8; FSP_HEADER_SIZE];
    hdr.copy_from_slice(&data[..FSP_HEADER_SIZE]);
    Some((flags, payload_len, counter, hdr))
}
