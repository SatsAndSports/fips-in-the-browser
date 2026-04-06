//! FIPS protocol implementation for WebAssembly.
//!
//! Provides a `FipsNode` that can complete a Noise IK handshake with a native
//! fips node over WebSocket, then participate as a leaf node in the mesh —
//! exchanging TreeAnnounce, FilterAnnounce, and MMP reports to keep the link
//! alive.

mod bloom;
mod cipher;
mod identity;
mod mmp;
mod noise;
mod replay;
mod tree;
mod wire;

use cipher::CipherState;
use identity::Identity;
use mmp::ReceiverState;
use noise::HandshakeState;
use replay::ReplayWindow;
use serde::Serialize;
use wasm_bindgen::prelude::*;
use wire::current_time_ms;

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
        #[allow(dead_code)]
        our_idx: u32,
        /// Remote peer's sender index (we use this as receiver_idx when sending).
        remote_idx: u32,
        /// MMP receiver state (tracks incoming frame metadata).
        receiver_state: ReceiverState,
        /// Next TreeAnnounce sequence number.
        tree_seq: u64,
        /// Next FilterAnnounce sequence number.
        filter_seq: u64,
    },
}

// ============================================================================
// JS-facing result types
// ============================================================================

#[derive(Serialize)]
struct ProcessResult {
    /// What kind of packet was received.
    msg_type: String,
    /// Multiple messages to send back (each is a complete FMP wire packet).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    responses: Vec<Vec<u8>>,
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
/// 3. Feed incoming messages to `process_incoming()`.
/// 4. Send all `responses` from the result back over the WebSocket.
/// 5. After handshake completes, use `send_data()` for outgoing data.
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
    /// Returns the full FMP msg1 wire packet (114 bytes) to send.
    pub fn initiate_handshake(&mut self, remote_npub: &str) -> Result<Vec<u8>, JsValue> {
        let x_only = identity::decode_npub(remote_npub).map_err(|e| JsValue::from_str(&e))?;
        let remote_pub =
            identity::pubkey_from_x_only(&x_only).map_err(|e| JsValue::from_str(&e))?;

        let mut epoch = [0u8; 8];
        getrandom::getrandom(&mut epoch).map_err(|e| JsValue::from_str(&format!("{e}")))?;

        let mut idx_bytes = [0u8; 4];
        getrandom::getrandom(&mut idx_bytes).map_err(|e| JsValue::from_str(&format!("{e}")))?;
        let our_idx = u32::from_le_bytes(idx_bytes);

        let mut hs =
            HandshakeState::new_initiator(self.identity.secret_key().clone(), remote_pub, epoch);
        let noise_msg1 = hs.write_message_1().map_err(|e| JsValue::from_str(&e))?;

        let wire_msg1 = wire::build_msg1(our_idx, &noise_msg1);

        self.link = Some(LinkState::Handshaking { hs, our_idx });

        Ok(wire_msg1)
    }

    /// Process an incoming FMP message (from WebSocket binary frame).
    ///
    /// Returns a JS object with:
    /// - `msg_type`: "msg2", "tree_announce", "filter_announce", "sender_report", etc.
    /// - `responses`: array of FMP wire packets to send back
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
                responses: vec![],
                payload: None,
                info: Some(format!("Unknown FMP phase: {other:#x}")),
            },
        };

        serde_wasm_bindgen::to_value(&result).map_err(|e| JsValue::from_str(&format!("{e}")))
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
    /// Build an encrypted FMP frame carrying a link-layer message.
    ///
    /// `inner_payload` starts with the msg_type byte (e.g., 0x10 for TreeAnnounce).
    fn build_encrypted_message(&mut self, inner_payload: &[u8]) -> Result<Vec<u8>, String> {
        let link = self
            .link
            .as_mut()
            .ok_or_else(|| "no active link".to_string())?;

        match link {
            LinkState::Established {
                send_cipher,
                remote_idx,
                ..
            } => {
                // Build inner: [timestamp:4 LE][msg_type + payload...]
                // The msg_type is already the first byte of inner_payload.
                let timestamp = wire::current_timestamp_ms();
                let mut inner = Vec::with_capacity(4 + inner_payload.len());
                inner.extend_from_slice(&timestamp.to_le_bytes());
                inner.extend_from_slice(inner_payload);

                let counter = send_cipher.nonce();
                let payload_len = inner.len() as u16;
                let header_bytes =
                    wire::build_established_header(0, payload_len, *remote_idx, counter);
                let ciphertext = send_cipher
                    .encrypt_with_aad(&inner, &header_bytes)
                    .map_err(|e| format!("encrypt failed: {e}"))?;

                let mut pkt = Vec::with_capacity(16 + ciphertext.len());
                pkt.extend_from_slice(&header_bytes);
                pkt.extend_from_slice(&ciphertext);
                Ok(pkt)
            }
            _ => Err("not in established state".to_string()),
        }
    }

    fn handle_msg2(&mut self, data: &[u8]) -> Result<ProcessResult, JsValue> {
        let msg2 = wire::Msg2Header::parse(data)
            .ok_or_else(|| JsValue::from_str("invalid msg2 packet"))?;

        let link = self
            .link
            .take()
            .ok_or_else(|| JsValue::from_str("no handshake in progress"))?;

        match link {
            LinkState::Handshaking { mut hs, our_idx } => {
                hs.read_message_2(&msg2.noise_payload)
                    .map_err(|e| JsValue::from_str(&e))?;

                let (send_cipher, recv_cipher, _hash, _remote_pub) =
                    hs.into_transport().map_err(|e| JsValue::from_str(&e))?;

                self.link = Some(LinkState::Established {
                    send_cipher,
                    recv_cipher,
                    replay: ReplayWindow::new(),
                    our_idx,
                    remote_idx: msg2.sender_idx,
                    receiver_state: ReceiverState::new(),
                    tree_seq: 1,
                    filter_seq: 1,
                });

                // Build TreeAnnounce + FilterAnnounce to send immediately
                let mut responses = Vec::new();

                // TreeAnnounce (as root node, parent = self)
                match self.build_tree_announce_message() {
                    Ok(pkt) => responses.push(pkt),
                    Err(e) => {
                        return Ok(ProcessResult {
                            msg_type: "msg2".to_string(),
                            responses: vec![],
                            payload: None,
                            info: Some(format!("Handshake OK, but TreeAnnounce failed: {e}")),
                        });
                    }
                }

                // FilterAnnounce (bloom filter with our own address)
                match self.build_filter_announce_message() {
                    Ok(pkt) => responses.push(pkt),
                    Err(e) => {
                        return Ok(ProcessResult {
                            msg_type: "msg2".to_string(),
                            responses: responses,
                            payload: None,
                            info: Some(format!("Handshake OK, but FilterAnnounce failed: {e}")),
                        });
                    }
                }

                Ok(ProcessResult {
                    msg_type: "msg2".to_string(),
                    responses,
                    payload: None,
                    info: Some(format!(
                        "Noise IK handshake complete! Link established. Sent TreeAnnounce + FilterAnnounce."
                    )),
                })
            }
            other => {
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
                receiver_state,
                ..
            } => {
                let header = wire::EncryptedHeader::parse(data)
                    .ok_or_else(|| JsValue::from_str("invalid encrypted frame"))?;

                if !replay.check(header.counter) {
                    return Ok(ProcessResult {
                        msg_type: "replay".to_string(),
                        responses: vec![],
                        payload: None,
                        info: Some(format!("Replay detected: counter {}", header.counter)),
                    });
                }

                let ciphertext = header.ciphertext(data);
                let plaintext = recv_cipher
                    .decrypt_with_counter_and_aad(ciphertext, header.counter, &header.header_bytes)
                    .map_err(|e| JsValue::from_str(&e))?;

                replay.accept(header.counter);

                // Parse inner header: [timestamp:4 LE][msg_type:1][payload...]
                let (timestamp, msg_type, payload) = match wire::parse_inner(&plaintext) {
                    Some(v) => v,
                    None => {
                        return Ok(ProcessResult {
                            msg_type: "data_short".to_string(),
                            responses: vec![],
                            payload: Some(plaintext),
                            info: Some("Encrypted frame (inner header too short)".to_string()),
                        });
                    }
                };

                // Record frame in MMP receiver state (for ReceiverReports)
                let now_ms = current_time_ms();
                receiver_state.record_frame(header.counter, timestamp, data.len(), now_ms);

                // Dispatch by link-layer msg_type
                self.dispatch_link_message(timestamp, msg_type, payload, now_ms)
            }
            LinkState::Handshaking { .. } => Err(JsValue::from_str(
                "received encrypted frame but handshake not complete",
            )),
        }
    }

    /// Dispatch a decrypted link-layer message by msg_type.
    fn dispatch_link_message(
        &mut self,
        _timestamp: u32,
        msg_type: u8,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<ProcessResult, JsValue> {
        match msg_type {
            wire::MSG_TYPE_TREE_ANNOUNCE => Ok(ProcessResult {
                msg_type: "tree_announce".to_string(),
                responses: vec![],
                payload: None,
                info: Some(format!("TreeAnnounce received ({} bytes)", payload.len())),
            }),

            wire::MSG_TYPE_FILTER_ANNOUNCE => Ok(ProcessResult {
                msg_type: "filter_announce".to_string(),
                responses: vec![],
                payload: None,
                info: Some(format!("FilterAnnounce received ({} bytes)", payload.len())),
            }),

            wire::MSG_TYPE_SENDER_REPORT => {
                let mut responses = Vec::new();
                match self.build_receiver_report(now_ms) {
                    Ok(pkt) => responses.push(pkt),
                    Err(e) => {
                        return Ok(ProcessResult {
                            msg_type: "sender_report".to_string(),
                            responses: vec![],
                            payload: None,
                            info: Some(format!(
                                "SenderReport received, ReceiverReport failed: {e}"
                            )),
                        });
                    }
                }
                Ok(ProcessResult {
                    msg_type: "sender_report".to_string(),
                    responses,
                    payload: None,
                    info: Some("SenderReport received, sent ReceiverReport".to_string()),
                })
            }

            wire::MSG_TYPE_RECEIVER_REPORT => Ok(ProcessResult {
                msg_type: "receiver_report".to_string(),
                responses: vec![],
                payload: None,
                info: None,
            }),

            wire::MSG_TYPE_SESSION_DATAGRAM => Ok(ProcessResult {
                msg_type: "session_datagram".to_string(),
                responses: vec![],
                payload: Some(payload.to_vec()),
                info: Some(format!(
                    "SessionDatagram ({} bytes, Phase 3 needed)",
                    payload.len()
                )),
            }),

            wire::MSG_TYPE_HEARTBEAT => Ok(ProcessResult {
                msg_type: "heartbeat".to_string(),
                responses: vec![],
                payload: None,
                info: None,
            }),

            wire::MSG_TYPE_DISCONNECT => Ok(ProcessResult {
                msg_type: "disconnect".to_string(),
                responses: vec![],
                payload: None,
                info: Some("Disconnect received".to_string()),
            }),

            other => Ok(ProcessResult {
                msg_type: format!("link_msg_{other:#04x}"),
                responses: vec![],
                payload: Some(payload.to_vec()),
                info: Some(format!("Unknown link message type: {other:#04x}")),
            }),
        }
    }

    // ========================================================================
    // Message builders
    // ========================================================================

    /// Build an encrypted TreeAnnounce message.
    fn build_tree_announce_message(&mut self) -> Result<Vec<u8>, String> {
        let seq = match &self.link {
            Some(LinkState::Established { tree_seq, .. }) => *tree_seq,
            _ => return Err("not established".to_string()),
        };

        let node_addr = *self.identity.node_addr();
        let secret = self.identity.secret_key().clone();
        let tree_payload = tree::build_tree_announce(&node_addr, &secret, seq)?;

        // Increment sequence
        if let Some(LinkState::Established { tree_seq, .. }) = &mut self.link {
            *tree_seq += 1;
        }

        self.build_encrypted_message(&tree_payload)
    }

    /// Build an encrypted FilterAnnounce message.
    fn build_filter_announce_message(&mut self) -> Result<Vec<u8>, String> {
        let seq = match &self.link {
            Some(LinkState::Established { filter_seq, .. }) => *filter_seq,
            _ => return Err("not established".to_string()),
        };

        let node_addr = *self.identity.node_addr();
        let filter_payload = bloom::build_self_filter_announce(&node_addr, seq);

        // Increment sequence
        if let Some(LinkState::Established { filter_seq, .. }) = &mut self.link {
            *filter_seq += 1;
        }

        self.build_encrypted_message(&filter_payload)
    }

    /// Build an encrypted ReceiverReport message.
    fn build_receiver_report(&mut self, now_ms: u64) -> Result<Vec<u8>, String> {
        let report_payload = match &mut self.link {
            Some(LinkState::Established { receiver_state, .. }) => {
                receiver_state.build_report(now_ms)
            }
            _ => return Err("not established".to_string()),
        };

        self.build_encrypted_message(&report_payload)
    }
}
