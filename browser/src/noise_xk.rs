//! Noise XK handshake (3-message, session layer).
//!
//! Pattern:
//!   pre-message: <- s  (initiator knows responder's static key)
//!   msg1: -> e, es                    (33 bytes)
//!   msg2: <- e, ee + encrypted epoch  (57 bytes)
//!   msg3: -> s, se + encrypted epoch  (73 bytes)
//!
//! Protocol name: Noise_XK_secp256k1_ChaChaPoly_SHA256
//!
//! After msg3, both sides call split() to derive transport ciphers.
//! Initiator sends with k1, receives with k2 (same convention as IK).

use crate::cipher::CipherState;
use crate::identity::{normalize_for_premessage, pubkey_from_bytes, pubkey_to_bytes};
use crate::noise::SymmetricState;
use k256::{PublicKey, SecretKey};

/// Protocol name (hashed since > 32 bytes).
const PROTOCOL_NAME_XK: &[u8] = b"Noise_XK_secp256k1_ChaChaPoly_SHA256";

const PUBKEY_SIZE: usize = 33;
const TAG_SIZE: usize = 16;
const EPOCH_SIZE: usize = 8;
const EPOCH_ENCRYPTED_SIZE: usize = EPOCH_SIZE + TAG_SIZE; // 24

/// XK msg1: ephemeral only (33 bytes).
pub const XK_MSG1_SIZE: usize = PUBKEY_SIZE;
/// XK msg2: ephemeral + encrypted epoch (57 bytes).
pub const XK_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE;
/// XK msg3: encrypted static + encrypted epoch (73 bytes).
pub const XK_MSG3_SIZE: usize = PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// ECDH: SHA-256(x-coordinate of shared point). Same as noise.rs.
fn ecdh(our_secret: &SecretKey, their_public: &PublicKey) -> [u8; 32] {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use sha2::{Digest, Sha256};

    let their_affine = their_public.as_affine();
    let our_scalar = our_secret.to_nonzero_scalar();
    let shared_point = (*their_affine * *our_scalar).to_affine();
    let encoded = shared_point.to_encoded_point(false);
    let x_bytes = encoded.x().expect("shared point is not identity");
    Sha256::digest(x_bytes).into()
}

fn generate_ephemeral() -> (SecretKey, PublicKey) {
    let secret = SecretKey::random(&mut rand_core::OsRng);
    let public = secret.public_key();
    (secret, public)
}

// ============================================================================
// Handshake state
// ============================================================================

#[derive(Clone, Copy, PartialEq, Eq)]
enum XkRole {
    Initiator,
    Responder,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum XkProgress {
    Initial,
    Msg1Done,
    Msg2Done,
    Complete,
}

/// Noise XK handshake state (both initiator and responder).
pub struct HandshakeXK {
    role: XkRole,
    progress: XkProgress,
    symmetric: SymmetricState,
    static_secret: SecretKey,
    static_public: PublicKey,
    ephemeral_secret: Option<SecretKey>,
    ephemeral_public: Option<PublicKey>,
    remote_static: Option<PublicKey>,
    remote_ephemeral: Option<PublicKey>,
    local_epoch: [u8; 8],
    remote_epoch: Option<[u8; 8]>,
}

impl HandshakeXK {
    /// Create as initiator (browser connecting to a remote node).
    ///
    /// The initiator knows the responder's static key before msg1.
    pub fn new_initiator(
        static_secret: SecretKey,
        remote_static: PublicKey,
        local_epoch: [u8; 8],
    ) -> Self {
        let static_public = static_secret.public_key();
        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME_XK);

        // Pre-message: <- s (hash responder's static, normalized to even parity)
        let normalized = normalize_for_premessage(&remote_static);
        symmetric.mix_hash(&normalized);

        Self {
            role: XkRole::Initiator,
            progress: XkProgress::Initial,
            symmetric,
            static_secret,
            static_public,
            ephemeral_secret: None,
            ephemeral_public: None,
            remote_static: Some(remote_static),
            remote_ephemeral: None,
            local_epoch,
            remote_epoch: None,
        }
    }

    /// Create as responder (browser receiving a SessionSetup from a remote node).
    ///
    /// The responder knows its own static key. The initiator's identity is
    /// revealed in msg3.
    pub fn new_responder(static_secret: SecretKey, local_epoch: [u8; 8]) -> Self {
        let static_public = static_secret.public_key();
        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME_XK);

        // Pre-message: <- s (hash OUR static, normalized to even parity)
        // Both sides hash the responder's static — and WE are the responder.
        let normalized = normalize_for_premessage(&static_public);
        symmetric.mix_hash(&normalized);

        Self {
            role: XkRole::Responder,
            progress: XkProgress::Initial,
            symmetric,
            static_secret,
            static_public,
            ephemeral_secret: None,
            ephemeral_public: None,
            remote_static: None,
            remote_ephemeral: None,
            local_epoch,
            remote_epoch: None,
        }
    }

    // ========================================================================
    // Initiator side
    // ========================================================================

    /// Write XK msg1 (initiator → responder): -> e, es
    ///
    /// Returns 33 bytes (ephemeral public key only).
    pub fn write_msg1(&mut self) -> Result<Vec<u8>, String> {
        if self.role != XkRole::Initiator || self.progress != XkProgress::Initial {
            return Err("wrong state for write_msg1".into());
        }

        let rs = self.remote_static.as_ref().unwrap();

        // -> e: generate ephemeral, send pubkey, mix into hash
        let (e_sec, e_pub) = generate_ephemeral();
        let e_pub_bytes = pubkey_to_bytes(&e_pub);
        self.symmetric.mix_hash(&e_pub_bytes);

        // -> es: DH(ephemeral, responder_static)
        let es = ecdh(&e_sec, rs);
        self.symmetric.mix_key(&es);

        self.ephemeral_secret = Some(e_sec);
        self.ephemeral_public = Some(e_pub);
        self.progress = XkProgress::Msg1Done;

        let mut message = Vec::with_capacity(XK_MSG1_SIZE);
        message.extend_from_slice(&e_pub_bytes);
        debug_assert_eq!(message.len(), XK_MSG1_SIZE);
        Ok(message)
    }

    /// Read XK msg2 (initiator receives from responder): <- e, ee + epoch
    ///
    /// Processes 57 bytes.
    pub fn read_msg2(&mut self, message: &[u8]) -> Result<(), String> {
        if self.role != XkRole::Initiator || self.progress != XkProgress::Msg1Done {
            return Err("wrong state for read_msg2".into());
        }
        if message.len() != XK_MSG2_SIZE {
            return Err(format!(
                "xk msg2 wrong size: expected {}, got {}",
                XK_MSG2_SIZE,
                message.len()
            ));
        }

        // <- e: parse responder ephemeral, mix into hash
        let re = pubkey_from_bytes(&message[..PUBKEY_SIZE])?;
        self.symmetric.mix_hash(&message[..PUBKEY_SIZE]);

        // <- ee: DH(our_ephemeral, their_ephemeral)
        let e_sec = self.ephemeral_secret.as_ref().unwrap();
        let ee = ecdh(e_sec, &re);
        self.symmetric.mix_key(&ee);

        // Decrypt responder's epoch
        let epoch_ct = &message[PUBKEY_SIZE..];
        let epoch_pt = self.symmetric.decrypt_and_hash(epoch_ct)?;
        if epoch_pt.len() != EPOCH_SIZE {
            return Err("bad epoch size in msg2".into());
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&epoch_pt);
        self.remote_epoch = Some(epoch);

        self.remote_ephemeral = Some(re);
        self.progress = XkProgress::Msg2Done;
        Ok(())
    }

    /// Write XK msg3 (initiator → responder): -> s, se + epoch
    ///
    /// Returns 73 bytes. After this, the handshake is complete.
    pub fn write_msg3(&mut self) -> Result<Vec<u8>, String> {
        if self.role != XkRole::Initiator || self.progress != XkProgress::Msg2Done {
            return Err("wrong state for write_msg3".into());
        }

        let re = self.remote_ephemeral.as_ref().unwrap();

        // -> s: encrypt our static public key
        let s_bytes = pubkey_to_bytes(&self.static_public);
        let encrypted_static = self.symmetric.encrypt_and_hash(&s_bytes)?;

        // -> se: DH(our_static, their_ephemeral)
        let se = ecdh(&self.static_secret, re);
        self.symmetric.mix_key(&se);

        // Encrypt our epoch
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&self.local_epoch)?;

        let mut message = Vec::with_capacity(XK_MSG3_SIZE);
        message.extend_from_slice(&encrypted_static);
        message.extend_from_slice(&encrypted_epoch);
        debug_assert_eq!(message.len(), XK_MSG3_SIZE);

        self.progress = XkProgress::Complete;
        Ok(message)
    }

    // ========================================================================
    // Responder side
    // ========================================================================

    /// Read XK msg1 (responder receives from initiator): -> e, es
    ///
    /// Processes 33 bytes.
    pub fn read_msg1(&mut self, message: &[u8]) -> Result<(), String> {
        if self.role != XkRole::Responder || self.progress != XkProgress::Initial {
            return Err("wrong state for read_msg1".into());
        }
        if message.len() != XK_MSG1_SIZE {
            return Err(format!(
                "xk msg1 wrong size: expected {}, got {}",
                XK_MSG1_SIZE,
                message.len()
            ));
        }

        // -> e: parse initiator ephemeral, mix into hash
        let re = pubkey_from_bytes(&message[..PUBKEY_SIZE])?;
        self.symmetric.mix_hash(&message[..PUBKEY_SIZE]);

        // -> es: DH(our_static, their_ephemeral)
        // Responder uses static secret, initiator used ephemeral with our static pub.
        // DH symmetry: DH(s_resp, e_init) == DH(e_init, s_resp)
        let es = ecdh(&self.static_secret, &re);
        self.symmetric.mix_key(&es);

        self.remote_ephemeral = Some(re);
        self.progress = XkProgress::Msg1Done;
        Ok(())
    }

    /// Write XK msg2 (responder → initiator): <- e, ee + epoch
    ///
    /// Returns 57 bytes.
    pub fn write_msg2(&mut self) -> Result<Vec<u8>, String> {
        if self.role != XkRole::Responder || self.progress != XkProgress::Msg1Done {
            return Err("wrong state for write_msg2".into());
        }

        let re = self.remote_ephemeral.as_ref().unwrap();

        // <- e: generate ephemeral, send pubkey, mix into hash
        let (e_sec, e_pub) = generate_ephemeral();
        let e_pub_bytes = pubkey_to_bytes(&e_pub);
        self.symmetric.mix_hash(&e_pub_bytes);

        // <- ee: DH(our_ephemeral, their_ephemeral)
        let ee = ecdh(&e_sec, re);
        self.symmetric.mix_key(&ee);

        // Encrypt our epoch
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&self.local_epoch)?;

        self.ephemeral_secret = Some(e_sec);
        self.ephemeral_public = Some(e_pub);
        self.progress = XkProgress::Msg2Done;

        let mut message = Vec::with_capacity(XK_MSG2_SIZE);
        message.extend_from_slice(&e_pub_bytes);
        message.extend_from_slice(&encrypted_epoch);
        debug_assert_eq!(message.len(), XK_MSG2_SIZE);
        Ok(message)
    }

    /// Read XK msg3 (responder receives from initiator): -> s, se + epoch
    ///
    /// Processes 73 bytes. After this, the responder knows the initiator's identity.
    pub fn read_msg3(&mut self, message: &[u8]) -> Result<(), String> {
        if self.role != XkRole::Responder || self.progress != XkProgress::Msg2Done {
            return Err("wrong state for read_msg3".into());
        }
        if message.len() != XK_MSG3_SIZE {
            return Err(format!(
                "xk msg3 wrong size: expected {}, got {}",
                XK_MSG3_SIZE,
                message.len()
            ));
        }

        // -> s: decrypt initiator's static public key
        let encrypted_static = &message[..PUBKEY_SIZE + TAG_SIZE];
        let s_bytes = self.symmetric.decrypt_and_hash(encrypted_static)?;
        let remote_pub = pubkey_from_bytes(&s_bytes)?;
        self.remote_static = Some(remote_pub);

        // -> se: DH(our_ephemeral, their_static)
        let e_sec = self.ephemeral_secret.as_ref().unwrap();
        let se = ecdh(e_sec, &remote_pub);
        self.symmetric.mix_key(&se);

        // Decrypt initiator's epoch
        let epoch_ct = &message[PUBKEY_SIZE + TAG_SIZE..];
        let epoch_pt = self.symmetric.decrypt_and_hash(epoch_ct)?;
        if epoch_pt.len() != EPOCH_SIZE {
            return Err("bad epoch size in msg3".into());
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&epoch_pt);
        self.remote_epoch = Some(epoch);

        self.progress = XkProgress::Complete;
        Ok(())
    }

    // ========================================================================
    // Completion
    // ========================================================================

    /// Complete the handshake and return transport ciphers.
    ///
    /// Returns (send_cipher, recv_cipher, remote_static_pubkey).
    /// Initiator sends with c1, receives with c2. Responder vice versa.
    pub fn into_transport(self) -> Result<(CipherState, CipherState, PublicKey), String> {
        if self.progress != XkProgress::Complete {
            return Err("handshake not complete".into());
        }
        let (c1, c2) = self.symmetric.split();
        let remote = self.remote_static.ok_or("no remote static key")?;

        let (send, recv) = match self.role {
            XkRole::Initiator => (c1, c2),
            XkRole::Responder => (c2, c1),
        };

        Ok((send, recv, remote))
    }
}
