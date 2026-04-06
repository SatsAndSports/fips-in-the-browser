//! Bloom filter and FilterAnnounce builder.
//!
//! Implements the FIPS v1 bloom filter: 8192 bits (1024 bytes), k=5 hash
//! functions, SHA-256 double hashing.

use crate::wire;
use sha2::{Digest, Sha256};

/// Number of hash functions (v1).
const HASH_COUNT: u8 = 5;

/// Size class for v1 filters (512 << 1 = 1024 bytes).
const SIZE_CLASS: u8 = 1;

/// Filter size in bytes (v1).
const FILTER_BYTES: usize = 1024;

/// Filter size in bits (v1).
const FILTER_BITS: usize = FILTER_BYTES * 8; // 8192

/// A v1 FIPS bloom filter (8192 bits, k=5, SHA-256 double hashing).
pub struct BloomFilter {
    bits: [u8; FILTER_BYTES],
}

impl BloomFilter {
    /// Create a new empty bloom filter.
    pub fn new() -> Self {
        Self {
            bits: [0u8; FILTER_BYTES],
        }
    }

    /// Insert a NodeAddr (16 bytes) into the filter.
    ///
    /// Sets k=5 bits using double hashing:
    ///   h(data, k) = (h1 + k * h2) % 8192
    /// where h1, h2 are derived from SHA-256(data).
    pub fn insert(&mut self, data: &[u8; 16]) {
        let hash: [u8; 32] = Sha256::digest(data).into();
        let h1 = u64::from_le_bytes(hash[0..8].try_into().unwrap());
        let h2 = u64::from_le_bytes(hash[8..16].try_into().unwrap());

        for k in 0..HASH_COUNT as u64 {
            let combined = h1.wrapping_add(k.wrapping_mul(h2));
            let bit_index = (combined % FILTER_BITS as u64) as usize;
            let byte_index = bit_index / 8;
            let bit_offset = bit_index % 8;
            self.bits[byte_index] |= 1 << bit_offset;
        }
    }

    /// Get the raw filter bytes.
    pub fn as_bytes(&self) -> &[u8; FILTER_BYTES] {
        &self.bits
    }
}

/// Build a FilterAnnounce payload.
///
/// Returns the payload bytes (starting with msg_type 0x20) to be wrapped
/// in an FMP encrypted frame.
///
/// Wire format:
///   [msg_type:1][sequence:8 LE][hash_count:1][size_class:1][filter_bits:1024]
///   Total: 1035 bytes.
pub fn build_filter_announce(filter: &BloomFilter, sequence: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1035);
    payload.push(wire::MSG_TYPE_FILTER_ANNOUNCE);
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.push(HASH_COUNT);
    payload.push(SIZE_CLASS);
    payload.extend_from_slice(filter.as_bytes());
    debug_assert_eq!(payload.len(), 1035);
    payload
}

/// Build a FilterAnnounce containing just a single NodeAddr.
///
/// Convenience function: creates a filter, inserts the address, and
/// builds the announce payload.
pub fn build_self_filter_announce(node_addr: &[u8; 16], sequence: u64) -> Vec<u8> {
    let mut filter = BloomFilter::new();
    filter.insert(node_addr);
    build_filter_announce(&filter, sequence)
}
