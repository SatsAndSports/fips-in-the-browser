//! TreeAnnounce builder and parser for a browser node.
//!
//! Supports two modes:
//! - **Root**: `parent = self`, single ancestry entry (used at startup before
//!   the gateway's TreeAnnounce arrives).
//! - **Leaf**: `parent = gateway`, ancestry = `[self, ...gateway_ancestry]`
//!   (used after receiving the gateway's TreeAnnounce).
//!
//! Declarations are signed with BIP-340 Schnorr.

use crate::wire;
use k256::ecdsa::signature::hazmat::PrehashSigner;
use k256::schnorr::SigningKey;
use sha2::{Digest, Sha256};

/// TreeAnnounce version.
const VERSION_1: u8 = 0x01;

/// CoordEntry wire size: node_addr(16) + sequence(8) + timestamp(8).
const COORD_ENTRY_SIZE: usize = 32;

/// A single ancestry entry from a parsed TreeAnnounce.
#[derive(Clone, Debug)]
pub struct AncestryEntry {
    pub node_addr: [u8; 16],
    pub sequence: u64,
    pub timestamp: u64,
}

/// Parsed TreeAnnounce (without signature verification — the gateway is
/// already authenticated via Noise IK).
pub struct ParsedTreeAnnounce {
    #[allow(dead_code)]
    pub parent: [u8; 16],
    pub ancestry: Vec<AncestryEntry>,
}

/// Parse a TreeAnnounce payload (after msg_type byte has been stripped).
///
/// We skip signature verification because the link peer is already
/// authenticated via Noise IK handshake.
pub fn parse_tree_announce(payload: &[u8]) -> Result<ParsedTreeAnnounce, String> {
    // Minimum: version(1) + seq(8) + ts(8) + parent(16) + count(2) + sig(64) = 99
    if payload.len() < 99 {
        return Err(format!(
            "TreeAnnounce too short: {} < 99",
            payload.len()
        ));
    }

    let mut pos = 0;

    // version
    let version = payload[pos];
    pos += 1;
    if version != VERSION_1 {
        return Err(format!("unsupported TreeAnnounce version: {version}"));
    }

    // sequence (8 LE) — skip, we don't need it
    pos += 8;
    // timestamp (8 LE) — skip
    pos += 8;

    // parent (16)
    let mut parent = [0u8; 16];
    parent.copy_from_slice(&payload[pos..pos + 16]);
    pos += 16;

    // ancestry_count (2 LE)
    let ancestry_count =
        u16::from_le_bytes([payload[pos], payload[pos + 1]]) as usize;
    pos += 2;

    // Check remaining length: entries + signature
    let needed = ancestry_count * COORD_ENTRY_SIZE + 64;
    if payload.len() - pos < needed {
        return Err(format!(
            "TreeAnnounce truncated: need {} more bytes, have {}",
            needed,
            payload.len() - pos
        ));
    }

    // Parse ancestry entries
    let mut ancestry = Vec::with_capacity(ancestry_count);
    for _ in 0..ancestry_count {
        let mut node_addr = [0u8; 16];
        node_addr.copy_from_slice(&payload[pos..pos + 16]);
        pos += 16;
        let sequence = u64::from_le_bytes(
            payload[pos..pos + 8].try_into().unwrap(),
        );
        pos += 8;
        let timestamp = u64::from_le_bytes(
            payload[pos..pos + 8].try_into().unwrap(),
        );
        pos += 8;
        ancestry.push(AncestryEntry {
            node_addr,
            sequence,
            timestamp,
        });
    }
    // Skip signature (64 bytes) — not verified

    Ok(ParsedTreeAnnounce { parent, ancestry })
}

/// Build a TreeAnnounce for a root node (parent = self, depth 0).
pub fn build_tree_announce(
    node_addr: &[u8; 16],
    secret_key: &k256::SecretKey,
    sequence: u64,
) -> Result<Vec<u8>, String> {
    build_tree_announce_inner(node_addr, secret_key, sequence, node_addr, &[])
}

/// Build a TreeAnnounce as a leaf of a parent node.
///
/// The ancestry will be `[self, ...parent_ancestry]`, and the declaration
/// is signed with our own key. This tells the gateway (and the rest of the
/// mesh) that we share the same spanning tree root.
pub fn build_tree_announce_as_leaf(
    node_addr: &[u8; 16],
    secret_key: &k256::SecretKey,
    sequence: u64,
    parent_addr: &[u8; 16],
    parent_ancestry: &[AncestryEntry],
) -> Result<Vec<u8>, String> {
    build_tree_announce_inner(node_addr, secret_key, sequence, parent_addr, parent_ancestry)
}

/// Shared builder for both root and leaf TreeAnnounce.
fn build_tree_announce_inner(
    node_addr: &[u8; 16],
    secret_key: &k256::SecretKey,
    sequence: u64,
    parent: &[u8; 16],
    parent_ancestry: &[AncestryEntry],
) -> Result<Vec<u8>, String> {
    let timestamp = wire::current_unix_secs();

    // Build the signing bytes: node_addr(16) || parent_id(16) || sequence(8 LE) || timestamp(8 LE)
    let mut signing_bytes = Vec::with_capacity(48);
    signing_bytes.extend_from_slice(node_addr);
    signing_bytes.extend_from_slice(parent);
    signing_bytes.extend_from_slice(&sequence.to_le_bytes());
    signing_bytes.extend_from_slice(&timestamp.to_le_bytes());

    // SHA-256 hash → BIP-340 Schnorr signature
    let signing_hash: [u8; 32] = Sha256::digest(&signing_bytes).into();
    let signing_key = SigningKey::from(secret_key.clone());
    let signature = signing_key
        .sign_prehash(&signing_hash)
        .map_err(|e| format!("Schnorr sign failed: {e}"))?;
    let sig_bytes = signature.to_bytes();

    // ancestry: [self_entry, ...parent_ancestry]
    let ancestry_count: u16 = 1 + parent_ancestry.len() as u16;

    let total_size =
        1 + 1 + 8 + 8 + 16 + 2 + (COORD_ENTRY_SIZE * ancestry_count as usize) + 64;
    let mut payload = Vec::with_capacity(total_size);

    // msg_type
    payload.push(wire::MSG_TYPE_TREE_ANNOUNCE);
    // version
    payload.push(VERSION_1);
    // sequence
    payload.extend_from_slice(&sequence.to_le_bytes());
    // timestamp
    payload.extend_from_slice(&timestamp.to_le_bytes());
    // parent
    payload.extend_from_slice(parent);
    // ancestry_count
    payload.extend_from_slice(&ancestry_count.to_le_bytes());
    // ancestry[0]: self
    payload.extend_from_slice(node_addr);
    payload.extend_from_slice(&sequence.to_le_bytes());
    payload.extend_from_slice(&timestamp.to_le_bytes());
    // ancestry[1..]: parent's ancestry
    for entry in parent_ancestry {
        payload.extend_from_slice(&entry.node_addr);
        payload.extend_from_slice(&entry.sequence.to_le_bytes());
        payload.extend_from_slice(&entry.timestamp.to_le_bytes());
    }
    // signature
    payload.extend_from_slice(&sig_bytes);

    debug_assert_eq!(payload.len(), total_size);
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Identity;

    #[test]
    fn build_root_announce() {
        let id = Identity::generate();
        let payload = build_tree_announce(id.node_addr(), id.secret_key(), 1).unwrap();
        // msg_type(1) + version(1) + seq(8) + ts(8) + parent(16) + count(2) + 1*entry(32) + sig(64) = 132
        assert_eq!(payload.len(), 132);
        assert_eq!(payload[0], wire::MSG_TYPE_TREE_ANNOUNCE);
    }

    #[test]
    fn build_leaf_announce() {
        let id = Identity::generate();
        let gateway_id = Identity::generate();

        let parent_ancestry = vec![AncestryEntry {
            node_addr: *gateway_id.node_addr(),
            sequence: 5,
            timestamp: 1000,
        }];

        let payload = build_tree_announce_as_leaf(
            id.node_addr(),
            id.secret_key(),
            2,
            gateway_id.node_addr(),
            &parent_ancestry,
        )
        .unwrap();

        // 1 + 1 + 8 + 8 + 16 + 2 + 2*32 + 64 = 164
        assert_eq!(payload.len(), 164);
        assert_eq!(payload[0], wire::MSG_TYPE_TREE_ANNOUNCE);

        // Parse it back
        let parsed = parse_tree_announce(&payload[1..]).unwrap();
        assert_eq!(parsed.parent, *gateway_id.node_addr());
        assert_eq!(parsed.ancestry.len(), 2);
        assert_eq!(parsed.ancestry[0].node_addr, *id.node_addr());
        assert_eq!(parsed.ancestry[1].node_addr, *gateway_id.node_addr());
        assert_eq!(parsed.ancestry[1].sequence, 5);
        assert_eq!(parsed.ancestry[1].timestamp, 1000);
    }

    #[test]
    fn parse_round_trip() {
        let id = Identity::generate();
        let payload = build_tree_announce(id.node_addr(), id.secret_key(), 3).unwrap();
        let parsed = parse_tree_announce(&payload[1..]).unwrap();
        assert_eq!(parsed.parent, *id.node_addr()); // root: parent == self
        assert_eq!(parsed.ancestry.len(), 1);
        assert_eq!(parsed.ancestry[0].node_addr, *id.node_addr());
    }

    #[test]
    fn parse_rejects_short() {
        assert!(parse_tree_announce(&[0u8; 50]).is_err());
    }

    #[test]
    fn parse_rejects_bad_version() {
        let mut data = vec![0xFFu8]; // bad version
        data.extend_from_slice(&[0u8; 98]); // pad to minimum
        assert!(parse_tree_announce(&data).is_err());
    }
}
