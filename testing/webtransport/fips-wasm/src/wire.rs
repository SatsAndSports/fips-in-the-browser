//! FMP wire format (link-layer packet framing).
//!
//! Adapted from fips `src/node/wire.rs`. Pure byte layout, no crypto deps.
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

// Flag bits (byte 1 of common prefix, phase 0x0 only).
pub const FLAG_KEY_EPOCH: u8 = 0x01;

// ============================================================================
// Parsing
// ============================================================================

/// Parsed common prefix.
pub struct CommonPrefix {
    pub version: u8,
    pub phase: u8,
    pub flags: u8,
    pub payload_len: u16,
}

impl CommonPrefix {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < COMMON_PREFIX_SIZE {
            return None;
        }
        Some(Self {
            version: data[0] >> 4,
            phase: data[0] & 0x0F,
            flags: data[1],
            payload_len: u16::from_le_bytes([data[2], data[3]]),
        })
    }
}

/// Parsed msg1 header.
pub struct Msg1Header {
    pub sender_idx: u32,
    pub noise_payload: Vec<u8>,
}

impl Msg1Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < MSG1_WIRE_SIZE {
            return None;
        }
        let prefix = CommonPrefix::parse(data)?;
        if prefix.version != FMP_VERSION || prefix.phase != PHASE_MSG1 {
            return None;
        }
        let sender_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let noise_payload = data[8..MSG1_WIRE_SIZE].to_vec();
        Some(Self {
            sender_idx,
            noise_payload,
        })
    }
}

/// Parsed msg2 header.
pub struct Msg2Header {
    pub sender_idx: u32,
    pub receiver_idx: u32,
    pub noise_payload: Vec<u8>,
}

impl Msg2Header {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < MSG2_WIRE_SIZE {
            return None;
        }
        let prefix = CommonPrefix::parse(data)?;
        if prefix.version != FMP_VERSION || prefix.phase != PHASE_MSG2 {
            return None;
        }
        let sender_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let receiver_idx = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
        let noise_payload = data[12..MSG2_WIRE_SIZE].to_vec();
        Some(Self {
            sender_idx,
            receiver_idx,
            noise_payload,
        })
    }
}

/// Parsed encrypted frame header.
pub struct EncryptedHeader {
    pub flags: u8,
    pub payload_len: u16,
    pub receiver_idx: u32,
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
        let flags = data[1];
        let payload_len = u16::from_le_bytes([data[2], data[3]]);
        let receiver_idx = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        let counter = u64::from_le_bytes([
            data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15],
        ]);
        let mut header_bytes = [0u8; ESTABLISHED_HEADER_SIZE];
        header_bytes.copy_from_slice(&data[..ESTABLISHED_HEADER_SIZE]);
        Some(Self {
            flags,
            payload_len,
            receiver_idx,
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

fn ver_phase_byte(version: u8, phase: u8) -> u8 {
    (version << 4) | (phase & 0x0F)
}

/// Build a msg1 wire packet.
///
/// Wire format: [prefix:4][sender_idx:4 LE][noise_msg1:106] = 114 bytes.
pub fn build_msg1(sender_idx: u32, noise_msg1: &[u8]) -> Vec<u8> {
    debug_assert_eq!(noise_msg1.len(), HANDSHAKE_MSG1_SIZE);
    let payload_len = (4 + noise_msg1.len()) as u16; // sender_idx + noise
    let mut pkt = Vec::with_capacity(MSG1_WIRE_SIZE);
    pkt.push(ver_phase_byte(FMP_VERSION, PHASE_MSG1));
    pkt.push(0x00); // flags
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    pkt.extend_from_slice(&sender_idx.to_le_bytes());
    pkt.extend_from_slice(noise_msg1);
    debug_assert_eq!(pkt.len(), MSG1_WIRE_SIZE);
    pkt
}

/// Build an encrypted frame wire packet.
///
/// Wire format: [header:16][ciphertext+tag].
/// The 16-byte header is used as AEAD AAD.
pub fn build_encrypted_frame(
    flags: u8,
    receiver_idx: u32,
    counter: u64,
    ciphertext: &[u8],
) -> Vec<u8> {
    let payload_len = ciphertext.len().saturating_sub(16) as u16; // exclude tag
    let mut pkt = Vec::with_capacity(ESTABLISHED_HEADER_SIZE + ciphertext.len());
    pkt.push(ver_phase_byte(FMP_VERSION, PHASE_ESTABLISHED));
    pkt.push(flags);
    pkt.extend_from_slice(&payload_len.to_le_bytes());
    pkt.extend_from_slice(&receiver_idx.to_le_bytes());
    pkt.extend_from_slice(&counter.to_le_bytes());
    pkt.extend_from_slice(ciphertext);
    pkt
}

/// Build inner header (prepended to plaintext before AEAD encryption).
///
/// [timestamp:4 LE][msg_type:1][payload...]
pub fn build_inner(timestamp: u32, msg_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::with_capacity(INNER_HEADER_SIZE + payload.len());
    inner.extend_from_slice(&timestamp.to_le_bytes());
    inner.push(msg_type);
    inner.extend_from_slice(payload);
    inner
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
