//! TreeAnnounce builder for a browser leaf/root node.
//!
//! Builds a TreeAnnounce declaring this node as its own root (depth 0,
//! parent = self). The declaration is signed with BIP-340 Schnorr.

use crate::wire;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

/// TreeAnnounce version.
const VERSION_1: u8 = 0x01;

/// CoordEntry wire size.
const COORD_ENTRY_SIZE: usize = 32;

/// Build a TreeAnnounce for a root node (no parent, depth 0).
///
/// The node declares itself as its own root with a single ancestry entry.
/// The declaration is signed with BIP-340 Schnorr.
///
/// Returns the payload bytes (starting with msg_type 0x10) to be wrapped
/// in an FMP encrypted frame.
pub fn build_tree_announce(
    node_addr: &[u8; 16],
    secret_key: &k256::SecretKey,
    sequence: u64,
) -> Result<Vec<u8>, String> {
    // Timestamp: current Unix seconds (WASM-compatible via js_sys or manual)
    let timestamp = wire::current_unix_secs();

    // For a root node: parent == self
    let parent = node_addr;

    // Build the signing bytes: node_addr(16) || parent_id(16) || sequence(8 LE) || timestamp(8 LE)
    let mut signing_bytes = Vec::with_capacity(48);
    signing_bytes.extend_from_slice(node_addr);
    signing_bytes.extend_from_slice(parent);
    signing_bytes.extend_from_slice(&sequence.to_le_bytes());
    signing_bytes.extend_from_slice(&timestamp.to_le_bytes());

    // SHA-256 hash of signing bytes
    let signing_hash: [u8; 32] = Sha256::digest(&signing_bytes).into();

    // BIP-340 Schnorr sign the hash
    let signing_key = SigningKey::from(secret_key.clone());
    let signature = signing_key
        .sign_prehash(&signing_hash)
        .map_err(|e| format!("Schnorr sign failed: {e}"))?;
    let sig_bytes = signature.to_bytes();

    // Build ancestry: single entry (self)
    // CoordEntry: node_addr(16) || sequence(8 LE) || timestamp(8 LE) = 32 bytes
    let ancestry_count: u16 = 1;

    // Assemble the TreeAnnounce payload
    let total_size = 1 + 1 + 8 + 8 + 16 + 2 + (COORD_ENTRY_SIZE * ancestry_count as usize) + 64;
    let mut payload = Vec::with_capacity(total_size);

    // msg_type
    payload.push(wire::MSG_TYPE_TREE_ANNOUNCE);
    // version
    payload.push(VERSION_1);
    // sequence
    payload.extend_from_slice(&sequence.to_le_bytes());
    // timestamp
    payload.extend_from_slice(&timestamp.to_le_bytes());
    // parent (== self for root)
    payload.extend_from_slice(parent);
    // ancestry_count
    payload.extend_from_slice(&ancestry_count.to_le_bytes());
    // ancestry[0]: self
    payload.extend_from_slice(node_addr); // node_addr (16)
    payload.extend_from_slice(&sequence.to_le_bytes()); // sequence (8)
    payload.extend_from_slice(&timestamp.to_le_bytes()); // timestamp (8)
                                                         // signature (64 bytes)
    payload.extend_from_slice(&sig_bytes);

    debug_assert_eq!(payload.len(), total_size);
    Ok(payload)
}
