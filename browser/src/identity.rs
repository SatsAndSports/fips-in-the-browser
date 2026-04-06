//! FIPS identity using k256 (pure-Rust secp256k1).
//!
//! Adapted from fips `src/identity/` — uses k256 instead of the secp256k1
//! FFI crate for WASM compatibility. Produces byte-identical results for
//! NodeAddr derivation and npub/nsec encoding.

use bech32::{Bech32, Hrp};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Human-readable part for npub (NIP-19).
const NPUB_HRP: Hrp = Hrp::parse_unchecked("npub");

/// Human-readable part for nsec (NIP-19).
const NSEC_HRP: Hrp = Hrp::parse_unchecked("nsec");

/// A FIPS node identity: keypair + derived identifiers.
pub struct Identity {
    /// secp256k1 secret key.
    secret: SecretKey,
    /// Corresponding public key.
    public: PublicKey,
    /// 16-byte node address (first 16 bytes of SHA-256(x-only pubkey)).
    node_addr: [u8; 16],
}

impl Identity {
    /// Create a new random identity.
    pub fn generate() -> Self {
        let secret = SecretKey::random(&mut rand_core::OsRng);
        Self::from_secret(secret)
    }

    /// Create from an existing secret key.
    pub fn from_secret(secret: SecretKey) -> Self {
        let public = secret.public_key();
        let node_addr = derive_node_addr(&public);
        Self {
            secret,
            public,
            node_addr,
        }
    }

    /// Create from a secret key encoded as nsec (bech32) or hex string.
    pub fn from_secret_str(s: &str) -> Result<Self, String> {
        let bytes = decode_secret(s)?;
        let secret =
            SecretKey::from_slice(&bytes).map_err(|e| format!("invalid secret key: {e}"))?;
        Ok(Self::from_secret(secret))
    }

    /// Get the secret key.
    pub fn secret_key(&self) -> &SecretKey {
        &self.secret
    }

    /// Get the 32-byte x-only public key (no parity prefix).
    pub fn pubkey_x_only(&self) -> [u8; 32] {
        let encoded = self.public.to_encoded_point(true);
        let mut x = [0u8; 32];
        x.copy_from_slice(encoded.x().unwrap());
        x
    }

    /// Get the 16-byte node address.
    pub fn node_addr(&self) -> &[u8; 16] {
        &self.node_addr
    }

    /// Get the node address as a hex string.
    pub fn node_addr_hex(&self) -> String {
        hex::encode(self.node_addr)
    }

    /// Encode as bech32 npub string (NIP-19).
    pub fn npub(&self) -> String {
        encode_npub(&self.pubkey_x_only())
    }
}

// ============================================================================
// NodeAddr derivation
// ============================================================================

/// Derive a 16-byte NodeAddr from a public key.
///
/// NodeAddr = first 16 bytes of SHA-256(x-only pubkey).
/// Matches fips `NodeAddr::from_pubkey()` exactly.
fn derive_node_addr(pubkey: &PublicKey) -> [u8; 16] {
    let encoded = pubkey.to_encoded_point(true);
    let x_bytes = encoded.x().unwrap(); // 32-byte x-coordinate, big-endian
    let hash = Sha256::digest(x_bytes);
    let mut addr = [0u8; 16];
    addr.copy_from_slice(&hash[..16]);
    addr
}

// ============================================================================
// PublicKey helpers
// ============================================================================

/// Parse a 33-byte compressed public key (SEC1 format).
pub fn pubkey_from_bytes(bytes: &[u8]) -> Result<PublicKey, String> {
    PublicKey::from_sec1_bytes(bytes).map_err(|e| format!("invalid public key: {e}"))
}

/// Construct a full public key from a 32-byte x-only key (assume even parity).
///
/// This matches fips `XOnlyPublicKey.public_key(Parity::Even)`.
pub fn pubkey_from_x_only(x_bytes: &[u8; 32]) -> Result<PublicKey, String> {
    let mut compressed = [0u8; 33];
    compressed[0] = 0x02; // even parity
    compressed[1..33].copy_from_slice(x_bytes);
    PublicKey::from_sec1_bytes(&compressed).map_err(|e| format!("invalid x-only key: {e}"))
}

/// Serialize a public key as 33-byte compressed SEC1.
pub fn pubkey_to_bytes(pubkey: &PublicKey) -> [u8; 33] {
    let encoded = pubkey.to_encoded_point(true);
    let mut bytes = [0u8; 33];
    bytes.copy_from_slice(encoded.as_bytes());
    bytes
}

/// Normalize a compressed public key to even parity for Noise pre-message hashing.
///
/// Both sides of the handshake must mix identical bytes into the hash chain.
/// Since the initiator may only have the x-only key (from an npub) and assumes
/// even parity, the responder normalizes to even parity too.
pub fn normalize_for_premessage(pubkey: &PublicKey) -> [u8; 33] {
    let mut bytes = pubkey_to_bytes(pubkey);
    bytes[0] = 0x02; // Force even parity
    bytes
}

// ============================================================================
// Bech32 encoding (npub / nsec)
// ============================================================================

/// Encode a 32-byte x-only public key as bech32 npub.
pub fn encode_npub(x_only: &[u8; 32]) -> String {
    bech32::encode::<Bech32>(NPUB_HRP, x_only).expect("npub encoding cannot fail")
}

/// Decode an npub string to a 32-byte x-only public key.
pub fn decode_npub(npub: &str) -> Result<[u8; 32], String> {
    let (hrp, data) = bech32::decode(npub).map_err(|e| format!("bech32 decode: {e}"))?;
    if hrp != NPUB_HRP {
        return Err(format!("expected npub prefix, got {hrp}"));
    }
    if data.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", data.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data);
    Ok(key)
}

/// Decode a secret key from nsec (bech32) or hex format. Returns raw 32 bytes.
fn decode_secret(s: &str) -> Result<[u8; 32], String> {
    if s.starts_with("nsec1") {
        let (hrp, data) = bech32::decode(s).map_err(|e| format!("bech32 decode: {e}"))?;
        if hrp != NSEC_HRP {
            return Err(format!("expected nsec prefix, got {hrp}"));
        }
        if data.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", data.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        Ok(key)
    } else {
        let bytes = hex::decode(s).map_err(|e| format!("hex decode: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }
}
