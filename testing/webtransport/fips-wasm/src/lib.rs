//! FIPS protocol implementation for WebAssembly.
//!
//! Provides a `FipsNode` that can complete a Noise IK handshake with a native
//! fips node over WebTransport datagrams, then exchange encrypted data.

mod cipher;
mod identity;
mod noise;
mod replay;
mod wire;

use cipher::CipherState;
use identity::Identity;
use noise::HandshakeState;
use replay::ReplayWindow;
use serde::Serialize;
use wasm_bindgen::prelude::*;

// ============================================================================
// State machine
// ============================================================================

/// Current link state.
enum LinkState {
    /// Handshake in progress.
    Handshaking {
        hs: HandshakeState,
        /// Our sender index (chosen randomly, sent in msg1 header).
        our_idx: u32,
    },
    /// Handshake complete, transport phase.
    Established {
        send_cipher: CipherState,
        recv_cipher: CipherState,
        replay: ReplayWindow,
        /// Our sender index (the remote peer uses this as receiver_idx).
        our_idx: u32,
        /// Remote peer's sender index (we use this as receiver_idx when sending).
        remote_idx: u32,
    },
}

// ============================================================================
// JS-facing result types
// ============================================================================

#[derive(Serialize)]
struct ProcessResult {
    /// What kind of packet was received.
    msg_type: String,
    /// Bytes to send back (if any). Serialized as JS Uint8Array.
    #[serde(skip_serializing_if = "Option::is_none")]
    respond: Option<Vec<u8>>,
    /// Decrypted payload (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<Vec<u8>>,
    /// Additional info for the UI.
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<String>,
}

// ============================================================================
// FipsNode
// ============================================================================

/// A FIPS node running in the browser via WASM.
///
/// Lifecycle:
/// 1. `new()` or `from_nsec()` — create node with a keypair.
/// 2. `initiate_handshake(remote_npub)` — returns msg1 wire bytes to send.
/// 3. Feed incoming datagrams to `process_incoming()`.
/// 4. After handshake completes, use `send_data()` for outgoing data.
#[wasm_bindgen]
pub struct FipsNode {
    identity: Identity,
    link: Option<LinkState>,
}

#[wasm_bindgen]
impl FipsNode {
    /// Create a new node with a random keypair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            identity: Identity::generate(),
            link: None,
        }
    }

    /// Create from an existing nsec (bech32) or hex secret key.
    pub fn from_nsec(nsec: &str) -> Result<FipsNode, JsValue> {
        let identity = Identity::from_secret_str(nsec).map_err(|e| JsValue::from_str(&e))?;
        Ok(Self {
            identity,
            link: None,
        })
    }

    /// Get this node's npub string.
    pub fn npub(&self) -> String {
        self.identity.npub()
    }

    /// Get this node's hex node address.
    pub fn node_addr_hex(&self) -> String {
        self.identity.node_addr_hex()
    }

    /// Initiate a Noise IK handshake with a remote peer.
    ///
    /// `remote_npub` is the peer's npub string (bech32).
    /// Returns the full FMP msg1 wire packet (114 bytes) to send as a datagram.
    pub fn initiate_handshake(&mut self, remote_npub: &str) -> Result<Vec<u8>, JsValue> {
        // Decode remote npub → x-only → full public key (assume even parity)
        let x_only = identity::decode_npub(remote_npub).map_err(|e| JsValue::from_str(&e))?;
        let remote_pub =
            identity::pubkey_from_x_only(&x_only).map_err(|e| JsValue::from_str(&e))?;

        // Generate random epoch and sender index
        let mut epoch = [0u8; 8];
        getrandom::getrandom(&mut epoch).map_err(|e| JsValue::from_str(&format!("{e}")))?;

        let mut idx_bytes = [0u8; 4];
        getrandom::getrandom(&mut idx_bytes).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let our_idx = u32::from_le_bytes(idx_bytes);

        // Create handshake state and build msg1
        let mut hs =
            HandshakeState::new_initiator(self.identity.secret_key().clone(), remote_pub, epoch);
        let noise_msg1 = hs.write_message_1().map_err(|e| JsValue::from_str(&e))?;

        // Wrap in FMP wire format
        let wire_msg1 = wire::build_msg1(our_idx, &noise_msg1);

        self.link = Some(LinkState::Handshaking { hs, our_idx });

        Ok(wire_msg1)
    }

    /// Process an incoming FMP datagram.
    ///
    /// Returns a JS object with:
    /// - `msg_type`: "msg2", "data", "unknown"
    /// - `respond`: bytes to send back (if any)
    /// - `payload`: decrypted payload (if any)
    /// - `info`: human-readable status
    pub fn process_incoming(&mut self, data: &[u8]) -> Result<JsValue, JsValue> {
        let prefix =
            wire::CommonPrefix::parse(data).ok_or_else(|| JsValue::from_str("packet too short"))?;

        let result = match prefix.phase {
            wire::PHASE_MSG2 => self.handle_msg2(data)?,
            wire::PHASE_ESTABLISHED => self.handle_encrypted(data)?,
            other => ProcessResult {
                msg_type: format!("unknown_phase_{other}"),
                respond: None,
                payload: None,
                info: Some(format!("Unknown FMP phase: {other:#x}")),
            },
        };

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&format!("{e}")))
    }

    /// Encrypt and send data as an FMP encrypted frame.
    ///
    /// Returns the full wire packet to send as a datagram.
    pub fn send_data(&mut self, payload: &[u8]) -> Result<Vec<u8>, JsValue> {
        let link = self
            .link
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active link"))?;

        match link {
            LinkState::Established {
                send_cipher,
                remote_idx,
                ..
            } => {
                // Build inner: [timestamp:4][msg_type:1][payload]
                // msg_type 0x00 = link-layer data
                let inner = wire::build_inner(0, 0x00, payload);

                // The counter for the AEAD nonce
                let counter = send_cipher.nonce();

                // payload_len = inner plaintext length (matches what the
                // server puts in the header and uses as AAD for decryption)
                let payload_len = inner.len() as u16;

                // Build the 16-byte header — used as both AAD and wire header
                let header_bytes = build_header_bytes(0, payload_len, *remote_idx, counter);

                // Encrypt with AAD
                let ciphertext = send_cipher
                    .encrypt_with_aad(&inner, &header_bytes)
                    .map_err(|e| JsValue::from_str(&e))?;

                // Assemble wire packet: header(16) + ciphertext+tag
                let mut pkt = Vec::with_capacity(16 + ciphertext.len());
                pkt.extend_from_slice(&header_bytes);
                pkt.extend_from_slice(&ciphertext);
                Ok(pkt)
            }
            LinkState::Handshaking { .. } => Err(JsValue::from_str("handshake not complete")),
        }
    }

    /// Check if the link is established (handshake complete).
    pub fn is_established(&self) -> bool {
        matches!(self.link, Some(LinkState::Established { .. }))
    }
}

// ============================================================================
// Internal handlers
// ============================================================================

impl FipsNode {
    fn handle_msg2(&mut self, data: &[u8]) -> Result<ProcessResult, JsValue> {
        let msg2 = wire::Msg2Header::parse(data)
            .ok_or_else(|| JsValue::from_str("invalid msg2 packet"))?;

        // Extract handshake state
        let link = self
            .link
            .take()
            .ok_or_else(|| JsValue::from_str("no handshake in progress"))?;

        match link {
            LinkState::Handshaking { mut hs, our_idx } => {
                // Process Noise msg2
                hs.read_message_2(&msg2.noise_payload)
                    .map_err(|e| JsValue::from_str(&e))?;

                // Complete handshake → transport phase
                let (send_cipher, recv_cipher, _hash, _remote_pub) =
                    hs.into_transport().map_err(|e| JsValue::from_str(&e))?;

                self.link = Some(LinkState::Established {
                    send_cipher,
                    recv_cipher,
                    replay: ReplayWindow::new(),
                    our_idx,
                    remote_idx: msg2.sender_idx,
                });

                Ok(ProcessResult {
                    msg_type: "msg2".to_string(),
                    respond: None,
                    payload: None,
                    info: Some("Noise IK handshake complete! Link established.".to_string()),
                })
            }
            other => {
                // Put it back
                self.link = Some(other);
                Err(JsValue::from_str(
                    "received msg2 but not in handshaking state",
                ))
            }
        }
    }

    fn handle_encrypted(&mut self, data: &[u8]) -> Result<ProcessResult, JsValue> {
        let link = self
            .link
            .as_mut()
            .ok_or_else(|| JsValue::from_str("no active link"))?;

        match link {
            LinkState::Established {
                recv_cipher,
                replay,
                ..
            } => {
                let header = wire::EncryptedHeader::parse(data)
                    .ok_or_else(|| JsValue::from_str("invalid encrypted frame"))?;

                // Replay check
                if !replay.check(header.counter) {
                    return Ok(ProcessResult {
                        msg_type: "replay".to_string(),
                        respond: None,
                        payload: None,
                        info: Some(format!("Replay detected: counter {}", header.counter)),
                    });
                }

                // Decrypt with AAD (header bytes)
                let ciphertext = header.ciphertext(data);
                let plaintext = recv_cipher
                    .decrypt_with_counter_and_aad(ciphertext, header.counter, &header.header_bytes)
                    .map_err(|e| JsValue::from_str(&e))?;

                // Accept into replay window after successful decryption
                replay.accept(header.counter);

                // Parse inner header
                if let Some((timestamp, msg_type, payload)) = wire::parse_inner(&plaintext) {
                    Ok(ProcessResult {
                        msg_type: format!("data_{msg_type:#04x}"),
                        respond: None,
                        payload: Some(payload.to_vec()),
                        info: Some(format!(
                            "Encrypted frame: counter={}, timestamp={}, msg_type={:#04x}, {} bytes",
                            header.counter,
                            timestamp,
                            msg_type,
                            payload.len()
                        )),
                    })
                } else {
                    Ok(ProcessResult {
                        msg_type: "data_short".to_string(),
                        respond: None,
                        payload: Some(plaintext),
                        info: Some("Encrypted frame (inner header too short)".to_string()),
                    })
                }
            }
            LinkState::Handshaking { .. } => Err(JsValue::from_str(
                "received encrypted frame but handshake not complete",
            )),
        }
    }
}

/// Build the 16-byte header bytes for AEAD AAD.
///
/// `payload_len` is the length of the inner plaintext (before AEAD tag).
/// This MUST match what appears on the wire, since the receiver uses the
/// wire header bytes as AAD for decryption.
fn build_header_bytes(flags: u8, payload_len: u16, receiver_idx: u32, counter: u64) -> [u8; 16] {
    let mut hdr = [0u8; 16];
    hdr[0] = (wire::FMP_VERSION << 4) | wire::PHASE_ESTABLISHED;
    hdr[1] = flags;
    hdr[2..4].copy_from_slice(&payload_len.to_le_bytes());
    hdr[4..8].copy_from_slice(&receiver_idx.to_le_bytes());
    hdr[8..16].copy_from_slice(&counter.to_le_bytes());
    hdr
}
