//! Noise IK handshake using k256 (pure-Rust secp256k1).
//!
//! Adapted from fips `src/noise/handshake.rs`. Uses k256 for ECDH instead
//! of the secp256k1 FFI crate. The ECDH output is byte-identical: both
//! produce SHA-256(x-coordinate of shared point), big-endian.
//!
//! Protocol: Noise_IK_secp256k1_ChaChaPoly_SHA256

use crate::cipher::CipherState;
use crate::identity::{normalize_for_premessage, pubkey_from_bytes, pubkey_to_bytes};
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Protocol name (must match fips exactly for handshake compatibility).
const PROTOCOL_NAME_IK: &[u8] = b"Noise_IK_secp256k1_ChaChaPoly_SHA256";

/// Compressed public key size.
const PUBKEY_SIZE: usize = 33;

/// AEAD tag size.
const TAG_SIZE: usize = 16;

/// Startup epoch size.
const EPOCH_SIZE: usize = 8;

/// Encrypted epoch size (epoch + tag).
const EPOCH_ENCRYPTED_SIZE: usize = EPOCH_SIZE + TAG_SIZE;

/// IK msg1: ephemeral(33) + encrypted_static(33+16) + encrypted_epoch(8+16) = 106.
pub const HANDSHAKE_MSG1_SIZE: usize = PUBKEY_SIZE + PUBKEY_SIZE + TAG_SIZE + EPOCH_ENCRYPTED_SIZE;

/// IK msg2: ephemeral(33) + encrypted_epoch(8+16) = 57.
pub const HANDSHAKE_MSG2_SIZE: usize = PUBKEY_SIZE + EPOCH_ENCRYPTED_SIZE;

// ============================================================================
// SymmetricState
// ============================================================================

struct SymmetricState {
    ck: [u8; 32],
    h: [u8; 32],
    cipher: CipherState,
}

impl SymmetricState {
    fn initialize(protocol_name: &[u8]) -> Self {
        let h = if protocol_name.len() <= 32 {
            let mut h = [0u8; 32];
            h[..protocol_name.len()].copy_from_slice(protocol_name);
            h
        } else {
            let hash: [u8; 32] = Sha256::digest(protocol_name).into();
            hash
        };
        Self {
            ck: h,
            h,
            cipher: CipherState::empty(),
        }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        let mut hasher = Sha256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    fn mix_key(&mut self, ikm: &[u8]) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), ikm);
        let mut output = [0u8; 64];
        hk.expand(&[], &mut output)
            .expect("64 bytes is valid output length");
        self.ck.copy_from_slice(&output[..32]);
        let mut key = [0u8; 32];
        key.copy_from_slice(&output[32..64]);
        self.cipher.initialize_key(key);
    }

    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let ct = self.cipher.encrypt(plaintext)?;
        self.mix_hash(&ct);
        Ok(ct)
    }

    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        let pt = self.cipher.decrypt(ciphertext)?;
        self.mix_hash(ciphertext);
        Ok(pt)
    }

    fn split(&self) -> (CipherState, CipherState) {
        let hk = Hkdf::<Sha256>::new(Some(&self.ck), &[]);
        let mut output = [0u8; 64];
        hk.expand(&[], &mut output)
            .expect("64 bytes is valid output length");
        let mut k1 = [0u8; 32];
        let mut k2 = [0u8; 32];
        k1.copy_from_slice(&output[..32]);
        k2.copy_from_slice(&output[32..64]);
        (CipherState::new(k1), CipherState::new(k2))
    }

    fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }
}

// ============================================================================
// ECDH
// ============================================================================

/// Perform ECDH and return SHA-256(x-coordinate of shared point).
///
/// Uses x-only hashing (SHA-256 of just the x-coordinate) to produce a
/// parity-independent shared secret. This matches fips's `ecdh()` function
/// byte-for-byte: both `secp256k1::ecdh::shared_secret_point` and k256's
/// scalar multiplication produce the same big-endian x-coordinate.
fn ecdh(our_secret: &SecretKey, their_public: &PublicKey) -> [u8; 32] {
    // Compute the shared point: their_public * our_secret
    let their_affine = their_public.as_affine();
    let our_scalar = our_secret.to_nonzero_scalar();
    let shared_point = (*their_affine * *our_scalar).to_affine();

    // Extract x-coordinate (32 bytes, big-endian)
    let encoded = shared_point.to_encoded_point(false); // uncompressed
    let x_bytes = encoded.x().expect("shared point is not identity");

    // SHA-256(x-coordinate) — matches fips exactly
    let hash: [u8; 32] = Sha256::digest(x_bytes).into();
    hash
}

/// Generate an ephemeral keypair.
fn generate_ephemeral() -> (SecretKey, PublicKey) {
    let secret = SecretKey::random(&mut rand_core::OsRng);
    let public = secret.public_key();
    (secret, public)
}

// ============================================================================
// HandshakeState (IK pattern, initiator only for Phase 1)
// ============================================================================

/// Handshake role.
#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum Role {
    Initiator,
    Responder, // Needed for Phase 3 (Noise XK sessions)
}

/// Handshake progress.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Progress {
    Initial,
    Message1Done,
    Complete,
}

/// Noise IK handshake state.
///
/// The browser is always the **initiator** (it connects to the fips node).
pub struct HandshakeState {
    role: Role,
    progress: Progress,
    symmetric: SymmetricState,
    /// Our static keypair.
    static_secret: SecretKey,
    static_public: PublicKey,
    /// Our ephemeral keypair.
    ephemeral_secret: Option<SecretKey>,
    ephemeral_public: Option<PublicKey>,
    /// Remote static public key (known before handshake for initiator).
    remote_static: Option<PublicKey>,
    /// Remote ephemeral public key (learned during handshake).
    remote_ephemeral: Option<PublicKey>,
    /// Our startup epoch.
    local_epoch: [u8; 8],
    /// Remote peer's startup epoch.
    remote_epoch: Option<[u8; 8]>,
}

impl HandshakeState {
    /// Create an IK handshake as initiator (browser connecting to fips node).
    pub fn new_initiator(
        static_secret: SecretKey,
        remote_static: PublicKey,
        local_epoch: [u8; 8],
    ) -> Self {
        let static_public = static_secret.public_key();
        let mut symmetric = SymmetricState::initialize(PROTOCOL_NAME_IK);

        // Pre-message: <- s (mix responder's static, normalized to even parity)
        let normalized = normalize_for_premessage(&remote_static);
        symmetric.mix_hash(&normalized);

        Self {
            role: Role::Initiator,
            progress: Progress::Initial,
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

    /// Write IK message 1 (initiator → responder).
    ///
    /// Returns 106 bytes: ephemeral(33) + encrypted_static(49) + encrypted_epoch(24).
    pub fn write_message_1(&mut self) -> Result<Vec<u8>, String> {
        if self.role != Role::Initiator || self.progress != Progress::Initial {
            return Err("wrong state for write_message_1".to_string());
        }

        let remote_static = self.remote_static.as_ref().unwrap();

        // Generate ephemeral
        let (e_sec, e_pub) = generate_ephemeral();
        let e_pub_bytes = pubkey_to_bytes(&e_pub);

        let mut message = Vec::with_capacity(HANDSHAKE_MSG1_SIZE);

        // -> e: send ephemeral, mix into hash
        message.extend_from_slice(&e_pub_bytes);
        self.symmetric.mix_hash(&e_pub_bytes);

        // -> es: DH(e, rs), mix into key
        let es = ecdh(&e_sec, remote_static);
        self.symmetric.mix_key(&es);

        // -> s: encrypt our static and send
        let our_static = pubkey_to_bytes(&self.static_public);
        let encrypted_static = self.symmetric.encrypt_and_hash(&our_static)?;
        message.extend_from_slice(&encrypted_static);

        // -> ss: DH(s, rs), mix into key
        let ss = ecdh(&self.static_secret, remote_static);
        self.symmetric.mix_key(&ss);

        // -> epoch: encrypt startup epoch
        let encrypted_epoch = self.symmetric.encrypt_and_hash(&self.local_epoch)?;
        message.extend_from_slice(&encrypted_epoch);

        self.ephemeral_secret = Some(e_sec);
        self.ephemeral_public = Some(e_pub);
        self.progress = Progress::Message1Done;

        debug_assert_eq!(message.len(), HANDSHAKE_MSG1_SIZE);
        Ok(message)
    }

    /// Read IK message 2 (responder → initiator).
    ///
    /// Processes 57 bytes: ephemeral(33) + encrypted_epoch(24).
    /// After this, the handshake is complete.
    pub fn read_message_2(&mut self, message: &[u8]) -> Result<(), String> {
        if self.role != Role::Initiator || self.progress != Progress::Message1Done {
            return Err("wrong state for read_message_2".to_string());
        }
        if message.len() != HANDSHAKE_MSG2_SIZE {
            return Err(format!(
                "msg2 wrong size: expected {}, got {}",
                HANDSHAKE_MSG2_SIZE,
                message.len()
            ));
        }

        // <- e: parse remote ephemeral, mix into hash
        let re = pubkey_from_bytes(&message[..PUBKEY_SIZE])?;
        self.remote_ephemeral = Some(re);
        self.symmetric.mix_hash(&message[..PUBKEY_SIZE]);

        let e_sec = self.ephemeral_secret.as_ref().unwrap();

        // <- ee: DH(e, re), mix into key
        let ee = ecdh(e_sec, &re);
        self.symmetric.mix_key(&ee);

        // <- se: DH(e, rs), mix into key
        // DH symmetry: DH(e_init, s_resp) == DH(s_resp, e_init) because
        // scalar multiplication on the curve is commutative: a*B = b*A.
        let rs = self.remote_static.as_ref().unwrap();
        let se = ecdh(e_sec, rs);
        self.symmetric.mix_key(&se);

        // <- epoch: decrypt responder's epoch
        let encrypted_epoch = &message[PUBKEY_SIZE..];
        let decrypted_epoch = self.symmetric.decrypt_and_hash(encrypted_epoch)?;
        if decrypted_epoch.len() != EPOCH_SIZE {
            return Err("bad epoch size".to_string());
        }
        let mut epoch = [0u8; 8];
        epoch.copy_from_slice(&decrypted_epoch);
        self.remote_epoch = Some(epoch);

        self.progress = Progress::Complete;
        Ok(())
    }

    /// Complete the handshake and return cipher states for transport.
    ///
    /// Returns (send_cipher, recv_cipher, handshake_hash, remote_static).
    pub fn into_transport(self) -> Result<(CipherState, CipherState, [u8; 32], PublicKey), String> {
        if self.progress != Progress::Complete {
            return Err("handshake not complete".to_string());
        }
        let (c1, c2) = self.symmetric.split();
        let hash = self.symmetric.handshake_hash();
        let remote = self.remote_static.unwrap();

        // Initiator sends with c1, receives with c2
        let (send, recv) = match self.role {
            Role::Initiator => (c1, c2),
            Role::Responder => (c2, c1),
        };

        Ok((send, recv, hash, remote))
    }
}
