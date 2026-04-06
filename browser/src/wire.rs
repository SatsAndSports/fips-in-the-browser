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
