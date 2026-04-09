//! FIPS protocol implementation for WebAssembly.
//!
//! Provides a `FipsNode` that can complete a Noise IK handshake with a native
//! fips node over WebSocket, then participate as a leaf node in the mesh —
//! exchanging TreeAnnounce, FilterAnnounce, and MMP reports to keep the link
//! alive.

mod bloom;
mod cipher;
mod dns;
mod identity;
mod ipv6;
mod mmp;
mod noise;
mod noise_xk;
mod replay;
mod session;
mod tree;
mod wire;

use cipher::CipherState;
use identity::Identity;
use mmp::ReceiverState;
use noise::HandshakeState;
use replay::ReplayWindow;
use serde::Serialize;
use session::SessionEventKind;
use session::SessionManager;
use std::collections::HashMap;
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
    /// Session peer npub when a session becomes established.
    #[serde(skip_serializing_if = "Option::is_none")]
    session_peer_npub: Option<String>,
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
    sessions: SessionManager,
    /// Random epoch for session handshakes.
    session_epoch: [u8; 8],
    next_ping_seq: u16,
    pending_pings: HashMap<u16, u64>,
    raw_ipv6_passthrough: bool,
}

#[wasm_bindgen]
impl FipsNode {
    /// Create a new node with a random keypair.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let identity = Identity::generate();
        let node_addr = *identity.node_addr();
        let mut epoch = [0u8; 8];
        let _ = getrandom::getrandom(&mut epoch);
        Self {
            sessions: SessionManager::new(node_addr),
            session_epoch: epoch,
            next_ping_seq: 1,
            pending_pings: HashMap::new(),
            raw_ipv6_passthrough: false,
            identity,
            link: None,
        }
    }

    /// Create from an existing nsec (bech32) or hex secret key.
    pub fn from_nsec(nsec: &str) -> Result<FipsNode, JsValue> {
        let identity = Identity::from_secret_str(nsec).map_err(|e| JsValue::from_str(&e))?;
        let node_addr = *identity.node_addr();
        let mut epoch = [0u8; 8];
        let _ = getrandom::getrandom(&mut epoch);
        Ok(Self {
            sessions: SessionManager::new(node_addr),
            session_epoch: epoch,
            next_ping_seq: 1,
            pending_pings: HashMap::new(),
            raw_ipv6_passthrough: false,
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

    /// Resolve a direct `<npub>.fips` name locally.
    pub fn resolve_fips_name(&self, name: &str) -> Result<JsValue, JsValue> {
        let resolved = dns::resolve_fips_query(name).map_err(|e| JsValue::from_str(&e))?;
        serde_wasm_bindgen::to_value(&resolved).map_err(|e| JsValue::from_str(&format!("{e}")))
    }

    /// Enable or disable raw IPv6 passthrough mode.
    ///
    /// When enabled, incoming port-256 IPv6 shim packets are surfaced back to JS
    /// as raw IPv6 packets instead of being handled internally for ICMPv6 ping.
    pub fn set_ipv6_passthrough(&mut self, enabled: bool) {
        self.raw_ipv6_passthrough = enabled;
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
                session_peer_npub: None,
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

    /// Initiate an end-to-end session with a remote node (Noise XK).
    ///
    /// `dest_npub` is the remote node's npub string.
    /// Returns FMP wire packets to send over the WebSocket.
    pub fn connect_session(&mut self, dest_npub: &str) -> Result<Vec<u8>, JsValue> {
        if self.is_session_established(dest_npub) {
            return Err(JsValue::from_str(
                "session already established for this destination",
            ));
        }

        let x_only = identity::decode_npub(dest_npub).map_err(|e| JsValue::from_str(&e))?;
        let dest_pub = identity::pubkey_from_x_only(&x_only).map_err(|e| JsValue::from_str(&e))?;

        // Derive dest NodeAddr from x-only pubkey
        let dest_addr = identity::node_addr_from_x_only(&x_only);
        if dest_addr == *self.identity.node_addr() {
            return Err(JsValue::from_str("cannot start a session to self"));
        }

        // Initiate session (builds Noise XK msg1 + SessionSetup)
        let fsp_payload = self
            .sessions
            .initiate(
                dest_addr,
                &dest_pub,
                self.session_epoch,
                self.identity.secret_key(),
            )
            .map_err(|e| JsValue::from_str(&e))?;

        // Wrap in SessionDatagram (link msg_type 0x00 envelope)
        let datagram_inner = self.sessions.wrap_in_datagram(&dest_addr, &fsp_payload);

        // Link-encrypt and return wire packet
        self.build_encrypted_message(&datagram_inner)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Send a chat message through an established session.
    ///
    /// Returns FMP wire packets to send over the WebSocket.
    pub fn send_message(&mut self, dest_npub: &str, text: &str) -> Result<Vec<u8>, JsValue> {
        let x_only = identity::decode_npub(dest_npub).map_err(|e| JsValue::from_str(&e))?;
        let dest_addr = identity::node_addr_from_x_only(&x_only);
        if dest_addr == *self.identity.node_addr() {
            return Err(JsValue::from_str("cannot send a session message to self"));
        }

        // Encrypt at session layer (FSP)
        let fsp_payload = self
            .sessions
            .send_data(
                &dest_addr,
                wire::FSP_PORT_CHAT,
                wire::FSP_PORT_CHAT,
                text.as_bytes(),
            )
            .map_err(|e| JsValue::from_str(&e))?;

        // Wrap in SessionDatagram
        let datagram_inner = self.sessions.wrap_in_datagram(&dest_addr, &fsp_payload);

        // Link-encrypt
        self.build_encrypted_message(&datagram_inner)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Send an ICMPv6 Echo Request through an established session.
    pub fn send_ping(&mut self, dest_npub: &str) -> Result<Vec<u8>, JsValue> {
        let x_only = identity::decode_npub(dest_npub).map_err(|e| JsValue::from_str(&e))?;
        let dest_addr = identity::node_addr_from_x_only(&x_only);
        if dest_addr == *self.identity.node_addr() {
            return Err(JsValue::from_str(
                "cannot send an IPv6 ping to self through a session",
            ));
        }

        let src_ipv6 = ipv6::ipv6_from_node_addr(self.identity.node_addr());
        let dst_ipv6 = ipv6::ipv6_from_node_addr(&dest_addr);

        let seq = self.next_ping_seq;
        self.next_ping_seq = self.next_ping_seq.wrapping_add(1);
        self.pending_pings.insert(seq, current_time_ms());

        let ipv6_packet = ipv6::build_icmpv6_echo_request(src_ipv6, dst_ipv6, seq);
        let compressed = ipv6::compress_ipv6(&ipv6_packet)
            .ok_or_else(|| JsValue::from_str("IPv6 shim compression failed"))?;

        let fsp_payload = self
            .sessions
            .send_data(
                &dest_addr,
                wire::FSP_PORT_IPV6_SHIM,
                wire::FSP_PORT_IPV6_SHIM,
                &compressed,
            )
            .map_err(|e| JsValue::from_str(&e))?;

        let datagram_inner = self.sessions.wrap_in_datagram(&dest_addr, &fsp_payload);
        self.build_encrypted_message(&datagram_inner)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Send a raw IPv6 packet through an established session on port 256.
    pub fn send_ipv6(&mut self, dest_npub: &str, packet: &[u8]) -> Result<Vec<u8>, JsValue> {
        let x_only = identity::decode_npub(dest_npub).map_err(|e| JsValue::from_str(&e))?;
        let dest_addr = identity::node_addr_from_x_only(&x_only);
        if dest_addr == *self.identity.node_addr() {
            return Err(JsValue::from_str(
                "cannot send raw IPv6 to self through a session",
            ));
        }

        let compressed = ipv6::compress_ipv6(packet)
            .ok_or_else(|| JsValue::from_str("IPv6 shim compression failed"))?;

        let fsp_payload = self
            .sessions
            .send_data(
                &dest_addr,
                wire::FSP_PORT_IPV6_SHIM,
                wire::FSP_PORT_IPV6_SHIM,
                &compressed,
            )
            .map_err(|e| JsValue::from_str(&e))?;

        let datagram_inner = self.sessions.wrap_in_datagram(&dest_addr, &fsp_payload);
        self.build_encrypted_message(&datagram_inner)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Send an empty data packet to port 0 as a session-layer keepalive.
    pub fn send_keepalive(&mut self, dest_npub: &str) -> Result<Vec<u8>, JsValue> {
        let x_only = identity::decode_npub(dest_npub).map_err(|e| JsValue::from_str(&e))?;
        let dest_addr = identity::node_addr_from_x_only(&x_only);

        // Send empty data packet to port 0. Server will touch() session activity
        // upon successful decryption, even if port 0 is unknown.
        let fsp_payload = self
            .sessions
            .send_data(&dest_addr, 0, 0, &[])
            .map_err(|e| JsValue::from_str(&e))?;

        let datagram_inner = self.sessions.wrap_in_datagram(&dest_addr, &fsp_payload);
        self.build_encrypted_message(&datagram_inner)
            .map_err(|e| JsValue::from_str(&e))
    }

    /// Check if a session is established with a given npub.
    pub fn is_session_established(&self, dest_npub: &str) -> bool {
        if let Ok(x_only) = identity::decode_npub(dest_npub) {
            let dest_addr = identity::node_addr_from_x_only(&x_only);
            self.sessions.is_established(&dest_addr)
        } else {
            false
        }
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
                            session_peer_npub: None,
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
                            session_peer_npub: None,
                            payload: None,
                            info: Some(format!("Handshake OK, but FilterAnnounce failed: {e}")),
                        });
                    }
                }

                Ok(ProcessResult {
                    msg_type: "msg2".to_string(),
                    responses,
                    session_peer_npub: None,
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
                        session_peer_npub: None,
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
                            session_peer_npub: None,
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
                session_peer_npub: None,
                payload: None,
                info: Some(format!("TreeAnnounce received ({} bytes)", payload.len())),
            }),

            wire::MSG_TYPE_FILTER_ANNOUNCE => Ok(ProcessResult {
                msg_type: "filter_announce".to_string(),
                responses: vec![],
                session_peer_npub: None,
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
                            session_peer_npub: None,
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
                    session_peer_npub: None,
                    payload: None,
                    info: Some("SenderReport received, sent ReceiverReport".to_string()),
                })
            }

            wire::MSG_TYPE_RECEIVER_REPORT => Ok(ProcessResult {
                msg_type: "receiver_report".to_string(),
                responses: vec![],
                session_peer_npub: None,
                payload: None,
                info: None,
            }),

            wire::MSG_TYPE_SESSION_DATAGRAM => self.handle_session_datagram(payload),

            wire::MSG_TYPE_HEARTBEAT => Ok(ProcessResult {
                msg_type: "heartbeat".to_string(),
                responses: vec![],
                session_peer_npub: None,
                payload: None,
                info: None,
            }),

            wire::MSG_TYPE_DISCONNECT => Ok(ProcessResult {
                msg_type: "disconnect".to_string(),
                responses: vec![],
                session_peer_npub: None,
                payload: None,
                info: Some("Disconnect received".to_string()),
            }),

            other => Ok(ProcessResult {
                msg_type: format!("link_msg_{other:#04x}"),
                responses: vec![],
                session_peer_npub: None,
                payload: Some(payload.to_vec()),
                info: Some(format!("Unknown link message type: {other:#04x}")),
            }),
        }
    }

    // ========================================================================
    // SessionDatagram handler
    // ========================================================================

    fn handle_session_datagram(&mut self, payload: &[u8]) -> Result<ProcessResult, JsValue> {
        // Parse SessionDatagram envelope (after msg_type 0x00)
        let (ttl, _path_mtu, src_addr, dest_addr, fsp_payload) =
            wire::parse_session_datagram_body(payload)
                .ok_or_else(|| JsValue::from_str("invalid SessionDatagram (too short)"))?;

        let our_addr = *self.identity.node_addr();

        // Check if this is addressed to us
        if dest_addr != our_addr {
            return Ok(ProcessResult {
                msg_type: "session_datagram_forward".to_string(),
                responses: vec![],
                session_peer_npub: None,
                payload: None,
                info: Some(format!(
                    "SessionDatagram not for us (dest={}, ttl={})",
                    hex::encode(dest_addr),
                    ttl
                )),
            });
        }

        // Process through SessionManager
        let event = self
            .sessions
            .process_incoming(
                src_addr,
                fsp_payload,
                self.session_epoch,
                self.identity.secret_key(),
            )
            .map_err(|e| JsValue::from_str(&e))?;

        // Build link-layer responses (wrap FSP responses in SessionDatagrams + link-encrypt)
        let mut responses = Vec::new();
        for fsp_resp in &event.fsp_responses {
            let datagram_inner = self.sessions.wrap_in_datagram(&src_addr, fsp_resp);
            match self.build_encrypted_message(&datagram_inner) {
                Ok(pkt) => responses.push(pkt),
                Err(e) => {
                    return Ok(ProcessResult {
                        msg_type: "session_error".to_string(),
                        responses: vec![],
                        session_peer_npub: None,
                        payload: None,
                        info: Some(format!("Failed to encrypt session response: {e}")),
                    });
                }
            }
        }

        // Build result
        let mut result = ProcessResult {
            msg_type: "session".to_string(),
            responses,
            session_peer_npub: event.remote_npub,
            payload: None,
            info: Some(event.info),
        };

        // Handle session-layer MMP reports
        if matches!(event.kind, SessionEventKind::SenderReport) {
            let now_ms = current_time_ms();
            match self
                .sessions
                .build_session_receiver_report(&src_addr, now_ms)
            {
                Ok(fsp_resp) => {
                    let datagram_inner = self.sessions.wrap_in_datagram(&src_addr, &fsp_resp);
                    if let Ok(pkt) = self.build_encrypted_message(&datagram_inner) {
                        result.responses.push(pkt);
                    }
                }
                Err(_) => {}
            }
            result.msg_type = "session_sender_report".to_string();
        } else if matches!(event.kind, SessionEventKind::ReceiverReport) {
            result.msg_type = "session_receiver_report".to_string();
        }

        // If there's application data, include it
        if let Some((port, data)) = event.payload {
            if port == wire::FSP_PORT_CHAT {
                let text = String::from_utf8_lossy(&data).to_string();
                result.msg_type = "session_chat".to_string();
                result.payload = Some(data);
                result.info = Some(format!(
                    "Chat from {}: {}",
                    hex::encode(&event.from[..4]),
                    text
                ));
            } else if port == wire::FSP_PORT_IPV6_SHIM {
                let src_ipv6 = ipv6::ipv6_from_node_addr(&event.from);
                let dst_ipv6 = ipv6::ipv6_from_node_addr(self.identity.node_addr());
                if let Some(packet) = ipv6::decompress_ipv6(&data, src_ipv6, dst_ipv6) {
                    if self.raw_ipv6_passthrough {
                        result.msg_type = "session_ipv6".to_string();
                        result.payload = Some(packet);
                        result.info = Some(format!(
                            "IPv6 shim packet from {}",
                            ipv6::format_ipv6(&src_ipv6)
                        ));
                    } else if let Some((_ident, seq)) = ipv6::parse_icmpv6_echo_reply(&packet) {
                        let now_ms = current_time_ms();
                        let rtt_ms = self
                            .pending_pings
                            .remove(&seq)
                            .map(|sent| now_ms.saturating_sub(sent));
                        result.msg_type = "ping_reply".to_string();
                        result.payload = Some(packet);
                        result.info = Some(match rtt_ms {
                            Some(rtt) => format!(
                                "ICMPv6 Echo Reply from {} seq={} rtt={}ms",
                                ipv6::format_ipv6(&src_ipv6),
                                seq,
                                rtt
                            ),
                            None => format!(
                                "ICMPv6 Echo Reply from {} seq={}",
                                ipv6::format_ipv6(&src_ipv6),
                                seq
                            ),
                        });
                    } else if let Some((_ident, seq)) = ipv6::parse_icmpv6_echo_request(&packet) {
                        if let Some(reply_ipv6) = ipv6::build_icmpv6_echo_reply(&packet) {
                            if let Some(reply_compressed) = ipv6::compress_ipv6(&reply_ipv6) {
                                if let Ok(fsp_payload) = self.sessions.send_data(
                                    &event.from,
                                    wire::FSP_PORT_IPV6_SHIM,
                                    wire::FSP_PORT_IPV6_SHIM,
                                    &reply_compressed,
                                ) {
                                    let datagram_inner =
                                        self.sessions.wrap_in_datagram(&event.from, &fsp_payload);
                                    if let Ok(pkt) = self.build_encrypted_message(&datagram_inner) {
                                        result.responses.push(pkt);
                                    }
                                }
                            }
                        }

                        result.msg_type = "ping_request".to_string();
                        result.payload = Some(packet);
                        result.info = Some(format!(
                            "ICMPv6 Echo Request from {} seq={}, sent Echo Reply",
                            ipv6::format_ipv6(&src_ipv6),
                            seq
                        ));
                    } else {
                        result.msg_type = "session_ipv6".to_string();
                        result.payload = Some(packet);
                        result.info = Some(format!(
                            "IPv6 shim packet from {}",
                            ipv6::format_ipv6(&src_ipv6)
                        ));
                    }
                } else {
                    result.msg_type = "session_ipv6_bad".to_string();
                    result.payload = Some(data);
                    result.info = Some("Failed to decompress IPv6 shim packet".to_string());
                }
            } else {
                result.msg_type = format!("session_port_{port}");
                result.payload = Some(data);
            }
        }

        Ok(result)
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
