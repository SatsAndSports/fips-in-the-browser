//! Symmetric cipher state for Noise protocol.
//!
//! Direct port from fips `src/noise/mod.rs` CipherState — same
//! ChaCha20-Poly1305 crate, same nonce layout, byte-identical output.

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};

/// AEAD tag size.
pub const TAG_SIZE: usize = 16;

/// Symmetric cipher state for post-handshake encryption.
#[derive(Clone)]
pub struct CipherState {
    key: [u8; 32],
    pub(crate) nonce: u64,
    has_key: bool,
}

impl CipherState {
    /// Create with a key.
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key,
            nonce: 0,
            has_key: true,
        }
    }

    /// Create empty (no key yet — used during handshake init).
    pub fn empty() -> Self {
        Self {
            key: [0u8; 32],
            nonce: 0,
            has_key: false,
        }
    }

    /// Set the key (called during handshake `mix_key`).
    pub fn initialize_key(&mut self, key: [u8; 32]) {
        self.key = key;
        self.nonce = 0;
        self.has_key = true;
    }

    /// Encrypt plaintext, returning ciphertext + 16-byte tag.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        if !self.has_key {
            return Ok(plaintext.to_vec());
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| "bad key".to_string())?;
        let nonce = self.next_nonce()?;
        cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| "encryption failed".to_string())
    }

    /// Decrypt ciphertext (with appended tag).
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if !self.has_key {
            return Ok(ciphertext.to_vec());
        }
        if ciphertext.len() < TAG_SIZE {
            return Err("ciphertext too short".to_string());
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| "bad key".to_string())?;
        let nonce = self.next_nonce()?;
        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| "decryption failed".to_string())
    }

    /// Encrypt with Additional Authenticated Data.
    pub fn encrypt_with_aad(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
        if !self.has_key {
            return Ok(plaintext.to_vec());
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| "bad key".to_string())?;
        let nonce = self.next_nonce()?;
        cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| "encryption failed".to_string())
    }

    /// Decrypt with explicit counter and AAD (transport phase).
    pub fn decrypt_with_counter_and_aad(
        &self,
        ciphertext: &[u8],
        counter: u64,
        aad: &[u8],
    ) -> Result<Vec<u8>, String> {
        if !self.has_key {
            return Ok(ciphertext.to_vec());
        }
        if ciphertext.len() < TAG_SIZE {
            return Err("ciphertext too short".to_string());
        }
        let cipher =
            ChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| "bad key".to_string())?;
        let nonce = Self::counter_to_nonce(counter);
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| "decryption failed".to_string())
    }

    fn counter_to_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&counter.to_le_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }

    fn next_nonce(&mut self) -> Result<Nonce, String> {
        if self.nonce == u64::MAX {
            return Err("nonce overflow".to_string());
        }
        let n = self.nonce;
        self.nonce += 1;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&n.to_le_bytes());
        Ok(*Nonce::from_slice(&nonce_bytes))
    }

    pub fn nonce(&self) -> u64 {
        self.nonce
    }
}
