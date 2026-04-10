//! Session manager — Noise XK sessions with FSP encryption.
//!
//! Manages end-to-end encrypted sessions between this browser node and
//! remote FIPS nodes. Each session goes through a 3-message Noise XK
//! handshake (routed via SessionDatagram through the mesh), then uses
//! ChaCha20-Poly1305 for data encryption.

use crate::cipher::CipherState;
use crate::identity;
use crate::mmp::ReceiverState;
use crate::noise_xk::HandshakeXK;
use crate::replay::ReplayWindow;
use crate::wire;
use serde::Serialize;
use std::collections::HashMap;

/// Session info for UI display.
#[derive(Serialize)]
pub struct SessionInfo {
    pub node_addr: [u8; 16],
    pub status: String,
    /// Seconds since last activity.
    pub idle_secs: u64,
    /// Seconds since session was created.
    pub age_secs: u64,
}

/// Default TTL for SessionDatagrams.
const DEFAULT_TTL: u8 = 64;

/// Default path MTU for SessionDatagrams.
const DEFAULT_PATH_MTU: u16 = u16::MAX;

/// A session in one of its lifecycle states.
enum SessionPhase {
    /// Initiator: sent msg1, waiting for msg2 (SessionAck).
    Initiating(HandshakeXK),
    /// Responder: sent msg2, waiting for msg3 (SessionMsg3).
    AwaitingMsg3(HandshakeXK),
    /// Handshake complete, data can flow.
    Established {
        send_cipher: CipherState,
        recv_cipher: CipherState,
        replay: ReplayWindow,
        /// MMP receiver state for session-layer metrics.
        receiver_state: ReceiverState,
    },
}

/// Session entry with lifecycle phase and activity tracking.
struct SessionEntry {
    phase: SessionPhase,
    created_at: u64,
    last_activity: u64,
}

impl SessionEntry {
    fn new(phase: SessionPhase) -> Self {
        let now = wire::current_time_ms();
        Self {
            phase,
            created_at: now,
            last_activity: now,
        }
    }

    fn touch(&mut self) {
        self.last_activity = wire::current_time_ms();
    }

    fn is_established(&self) -> bool {
        matches!(self.phase, SessionPhase::Established { .. })
    }

    fn idle_ms(&self) -> u64 {
        wire::current_time_ms().saturating_sub(self.last_activity)
    }
}

/// Manages all active sessions, keyed by remote NodeAddr.
pub struct SessionManager {
    sessions: HashMap<[u8; 16], SessionEntry>,
    /// Our own coordinates (root, depth 0 — just our own NodeAddr).
    our_coords: Vec<[u8; 16]>,
    /// Our NodeAddr.
    our_addr: [u8; 16],
}

/// Result of processing an incoming SessionDatagram.
pub enum SessionEventKind {
    Setup,
    Ack,
    Msg3,
    SenderReport,
    ReceiverReport,
    Data,
    Other,
    Replay,
}

pub struct SessionEvent {
    /// FMP wire packets to send back (already link-encrypted by the caller).
    pub fsp_responses: Vec<Vec<u8>>,
    /// Human-readable description for the UI.
    pub info: String,
    /// The peer's npub when a session becomes established.
    pub remote_npub: Option<String>,
    /// Decrypted application payload (if any).
    pub payload: Option<(u16, Vec<u8>)>, // (dst_port, data)
    /// The source NodeAddr (who sent this).
    pub from: [u8; 16],
    /// What kind of session event occurred.
    pub kind: SessionEventKind,
}

impl SessionManager {
    pub fn new(our_addr: [u8; 16]) -> Self {
        Self {
            sessions: HashMap::new(),
            our_coords: vec![our_addr],
            our_addr,
        }
    }

    /// Update our coordinates (ancestry path from self to root).
    ///
    /// Called when we receive the gateway's TreeAnnounce and adopt it as
    /// parent. Future SessionSetup/Ack packets will include these coords.
    pub fn update_coords(&mut self, coords: Vec<[u8; 16]>) {
        self.our_coords = coords;
    }

    /// Check if a session with the given dest is established.
    pub fn is_established(&self, dest: &[u8; 16]) -> bool {
        self.sessions.get(dest).map_or(false, |e| e.is_established())
    }

    /// Return all established session destination addresses.
    pub fn established_destinations(&self) -> Vec<[u8; 16]> {
        self.sessions
            .iter()
            .filter_map(|(addr, entry)| {
                if entry.is_established() { Some(*addr) } else { None }
            })
            .collect()
    }

    /// Return a snapshot of all sessions with their state for UI display.
    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        self.sessions
            .iter()
            .map(|(addr, entry)| {
                let status = match &entry.phase {
                    SessionPhase::Initiating(_) => "initiating",
                    SessionPhase::AwaitingMsg3(_) => "awaiting_msg3",
                    SessionPhase::Established { .. } => "established",
                };
                let now = wire::current_time_ms();
                SessionInfo {
                    node_addr: *addr,
                    status: status.to_string(),
                    idle_secs: now.saturating_sub(entry.last_activity) / 1000,
                    age_secs: now.saturating_sub(entry.created_at) / 1000,
                }
            })
            .collect()
    }

    /// Remove sessions that have been idle longer than the given threshold.
    /// Returns the number of sessions pruned.
    pub fn prune_idle(&mut self, max_idle_ms: u64) -> usize {
        let before = self.sessions.len();
        self.sessions.retain(|_, entry| entry.idle_ms() < max_idle_ms);
        before - self.sessions.len()
    }

    // ========================================================================
    // Initiate a session (we are the initiator)
    // ========================================================================

    /// Initiate a Noise XK session with a remote node.
    ///
    /// Returns the FSP SessionSetup payload (to be wrapped in a SessionDatagram
    /// by the caller, then link-encrypted and sent).
    pub fn initiate(
        &mut self,
        dest_addr: [u8; 16],
        dest_pubkey: &k256::PublicKey,
        local_epoch: [u8; 8],
        our_secret: &k256::SecretKey,
    ) -> Result<Vec<u8>, String> {
        if let Some(entry) = self.sessions.get(&dest_addr) {
            return Err(if entry.is_established() {
                "session already established for this destination".into()
            } else {
                "session handshake already in progress for this destination".into()
            });
        }

        let mut hs = HandshakeXK::new_initiator(our_secret.clone(), *dest_pubkey, local_epoch);
        let msg1 = hs.write_msg1()?;

        // Build SessionSetup (FSP phase 0x1) with coordinates
        let dest_coords: &[[u8; 16]] = &[dest_addr]; // placeholder
        let setup = wire::build_session_setup(&self.our_coords, dest_coords, &msg1);

        self.sessions
            .insert(dest_addr, SessionEntry::new(SessionPhase::Initiating(hs)));

        Ok(setup)
    }

    // ========================================================================
    // Process incoming FSP payload (from a SessionDatagram addressed to us)
    // ========================================================================

    /// Process an incoming FSP payload from a SessionDatagram.
    ///
    /// `src_addr` is the source NodeAddr from the SessionDatagram envelope.
    /// `fsp_payload` is the raw FSP bytes (starting with the 4-byte FSP prefix).
    ///
    /// Returns a SessionEvent with any response FSP payloads and decoded data.
    pub fn process_incoming(
        &mut self,
        src_addr: [u8; 16],
        fsp_payload: &[u8],
        local_epoch: [u8; 8],
        our_secret: &k256::SecretKey,
    ) -> Result<SessionEvent, String> {
        if fsp_payload.len() < 4 {
            return Err("FSP payload too short".into());
        }

        let phase = fsp_payload[0] & 0x0F;
        let body = &fsp_payload[4..]; // skip 4-byte FSP prefix

        match phase {
            wire::FSP_PHASE_SETUP => self.handle_setup(src_addr, body, local_epoch, our_secret),
            wire::FSP_PHASE_ACK => self.handle_ack(src_addr, body),
            wire::FSP_PHASE_MSG3 => self.handle_msg3(src_addr, body),
            wire::FSP_PHASE_ESTABLISHED => self.handle_established_data(src_addr, fsp_payload),
            other => Err(format!("unknown FSP phase: {other:#x}")),
        }
    }

    // ========================================================================
    // Handshake handlers
    // ========================================================================

    /// Handle incoming SessionSetup (we are the responder).
    fn handle_setup(
        &mut self,
        src_addr: [u8; 16],
        body: &[u8],
        local_epoch: [u8; 8],
        our_secret: &k256::SecretKey,
    ) -> Result<SessionEvent, String> {
        let (_src_coords, _dest_coords, hs_payload) =
            wire::parse_session_setup_body(body).ok_or("invalid SessionSetup body")?;

        // Create responder handshake state
        let mut hs = HandshakeXK::new_responder(our_secret.clone(), local_epoch);
        hs.read_msg1(&hs_payload)?;
        let msg2 = hs.write_msg2()?;

        // Build SessionAck (FSP phase 0x2)
        let src_coords_for_ack = &self.our_coords;
        let dest_coords_for_ack: &[[u8; 16]] = &[src_addr]; // initiator's addr
        let ack = wire::build_session_ack(src_coords_for_ack, dest_coords_for_ack, &msg2);

        // Store as AwaitingMsg3
        self.sessions
            .insert(src_addr, SessionEntry::new(SessionPhase::AwaitingMsg3(hs)));

        Ok(SessionEvent {
            fsp_responses: vec![ack],
            info: format!("SessionSetup received, sent SessionAck (XK msg2)"),
            remote_npub: None,
            payload: None,
            from: src_addr,
            kind: SessionEventKind::Setup,
        })
    }

    /// Handle incoming SessionAck (we are the initiator, receiving msg2).
    fn handle_ack(&mut self, src_addr: [u8; 16], body: &[u8]) -> Result<SessionEvent, String> {
        let (_src_coords, _dest_coords, hs_payload) =
            wire::parse_session_ack_body(body).ok_or("invalid SessionAck body")?;

        let entry = self
            .sessions
            .remove(&src_addr)
            .ok_or("no session for this source (unexpected SessionAck)")?;

        match entry.phase {
            SessionPhase::Initiating(mut hs) => {
                hs.read_msg2(&hs_payload)?;
                let msg3 = hs.write_msg3()?;

                // Build SessionMsg3 (FSP phase 0x3)
                let msg3_fsp = wire::build_session_msg3(&msg3);

                // Complete handshake → established
                let (send_cipher, recv_cipher, remote_pub) = hs.into_transport()?;
                let remote_npub = identity::pubkey_to_npub(&remote_pub);

                self.sessions.insert(
                    src_addr,
                    SessionEntry::new(SessionPhase::Established {
                        send_cipher,
                        recv_cipher,
                        replay: ReplayWindow::new(),
                        receiver_state: ReceiverState::new(),
                    }),
                );

                Ok(SessionEvent {
                    fsp_responses: vec![msg3_fsp],
                    info: format!("SessionAck received, sent msg3. Session ESTABLISHED!"),
                    remote_npub: Some(remote_npub),
                    payload: None,
                    from: src_addr,
                    kind: SessionEventKind::Ack,
                })
            }
            other_phase => {
                self.sessions.insert(src_addr, SessionEntry { phase: other_phase, ..entry });
                Err("received SessionAck but not in Initiating state".into())
            }
        }
    }

    /// Handle incoming SessionMsg3 (we are the responder, receiving msg3).
    fn handle_msg3(&mut self, src_addr: [u8; 16], body: &[u8]) -> Result<SessionEvent, String> {
        let hs_payload = wire::parse_session_msg3_body(body).ok_or("invalid SessionMsg3 body")?;

        let entry = self
            .sessions
            .remove(&src_addr)
            .ok_or("no session for this source (unexpected SessionMsg3)")?;

        match entry.phase {
            SessionPhase::AwaitingMsg3(mut hs) => {
                hs.read_msg3(&hs_payload)?;
                let (send_cipher, recv_cipher, remote_pub) = hs.into_transport()?;
                let remote_npub = identity::pubkey_to_npub(&remote_pub);

                self.sessions.insert(
                    src_addr,
                    SessionEntry::new(SessionPhase::Established {
                        send_cipher,
                        recv_cipher,
                        replay: ReplayWindow::new(),
                        receiver_state: ReceiverState::new(),
                    }),
                );

                Ok(SessionEvent {
                    fsp_responses: vec![],
                    info: format!("SessionMsg3 received. Session ESTABLISHED!"),
                    remote_npub: Some(remote_npub),
                    payload: None,
                    from: src_addr,
                    kind: SessionEventKind::Msg3,
                })
            }
            other_phase => {
                self.sessions.insert(src_addr, SessionEntry { phase: other_phase, ..entry });
                Err("received SessionMsg3 but not in AwaitingMsg3 state".into())
            }
        }
    }

    // ========================================================================
    // Established session data
    // ========================================================================

    /// Handle incoming encrypted session data (FSP phase 0x0).
    fn handle_established_data(
        &mut self,
        src_addr: [u8; 16],
        fsp_payload: &[u8],
    ) -> Result<SessionEvent, String> {
        let (flags, _payload_len, counter, header_bytes) =
            wire::parse_fsp_header(fsp_payload).ok_or("invalid FSP header")?;

        // Skip coords if CP flag is set
        let mut data_offset = wire::FSP_HEADER_SIZE;
        if flags & 0x01 != 0 {
            // CP flag: skip cleartext coords
            let (_coords, new_pos) =
                wire::parse_coords(fsp_payload, data_offset).ok_or("invalid src coords in CP")?;
            data_offset = new_pos;
            let (_coords, new_pos) =
                wire::parse_coords(fsp_payload, data_offset).ok_or("invalid dest coords in CP")?;
            data_offset = new_pos;
        }

        let ciphertext = &fsp_payload[data_offset..];

        let entry = self
            .sessions
            .get_mut(&src_addr)
            .ok_or("no established session for this source")?;

        entry.touch();

        match &mut entry.phase {
            SessionPhase::Established {
                recv_cipher,
                replay,
                receiver_state,
                ..
            } => {
                if !replay.check(counter) {
                    return Ok(SessionEvent {
                        fsp_responses: vec![],
                        info: format!("Session replay detected: counter {counter}"),
                        remote_npub: None,
                        payload: None,
                        from: src_addr,
                        kind: SessionEventKind::Replay,
                    });
                }

                let plaintext = recv_cipher
                    .decrypt_with_counter_and_aad(ciphertext, counter, &header_bytes)
                    .map_err(|e| format!("session decrypt failed: {e}"))?;

                replay.accept(counter);

                // Parse FSP inner header: [timestamp:4][msg_type:1][inner_flags:1]
                if plaintext.len() < wire::FSP_INNER_HEADER_SIZE {
                    return Err("FSP inner header too short".into());
                }
                let timestamp =
                    u32::from_le_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
                let msg_type = plaintext[4];

                // Record frame in MMP receiver state
                receiver_state.record_frame(
                    counter,
                    timestamp,
                    fsp_payload.len(),
                    wire::current_time_ms(),
                );

                if msg_type == wire::FSP_MSG_TYPE_DATA {
                    // DataPacket: [inner_header:6][src_port:2][dst_port:2][payload...]
                    if plaintext.len() < wire::FSP_INNER_HEADER_SIZE + 4 {
                        return Err("DataPacket too short for port header".into());
                    }
                    let src_port = u16::from_le_bytes([
                        plaintext[wire::FSP_INNER_HEADER_SIZE],
                        plaintext[wire::FSP_INNER_HEADER_SIZE + 1],
                    ]);
                    let dst_port = u16::from_le_bytes([
                        plaintext[wire::FSP_INNER_HEADER_SIZE + 2],
                        plaintext[wire::FSP_INNER_HEADER_SIZE + 3],
                    ]);
                    let data = plaintext[wire::FSP_INNER_HEADER_SIZE + 4..].to_vec();

                    Ok(SessionEvent {
                        fsp_responses: vec![],
                        info: format!(
                            "Session data: src_port={src_port} dst_port={dst_port} {} bytes",
                            data.len()
                        ),
                        remote_npub: None,
                        payload: Some((dst_port, data)),
                        from: src_addr,
                        kind: SessionEventKind::Data,
                    })
                } else if msg_type == wire::MSG_TYPE_SENDER_REPORT {
                    Ok(SessionEvent {
                        fsp_responses: vec![],
                        info: "Session SenderReport received".to_string(),
                        remote_npub: None,
                        payload: None,
                        from: src_addr,
                        kind: SessionEventKind::SenderReport,
                    })
                } else if msg_type == wire::MSG_TYPE_RECEIVER_REPORT {
                    Ok(SessionEvent {
                        fsp_responses: vec![],
                        info: "Session ReceiverReport received".to_string(),
                        remote_npub: None,
                        payload: None,
                        from: src_addr,
                        kind: SessionEventKind::ReceiverReport,
                    })
                } else {
                    // Other FSP message types (MMP ReceiverReport, coords warmup, etc.) — log
                    Ok(SessionEvent {
                        fsp_responses: vec![],
                        info: format!(
                            "Session msg_type {msg_type:#04x} ({} bytes)",
                            plaintext.len()
                        ),
                        remote_npub: None,
                        payload: None,
                        from: src_addr,
                        kind: SessionEventKind::Other,
                    })
                }
            }
            _ => Err("session not in Established state for data".into()),
        }
    }

    // ========================================================================
    // Send data through an established session
    // ========================================================================

    /// Encrypt and build an FSP data payload for an established session.
    ///
    /// Returns the FSP wire bytes (header + ciphertext) to be wrapped in a
    /// SessionDatagram by the caller.
    pub fn send_data(
        &mut self,
        dest_addr: &[u8; 16],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or("no established session for this destination")?;

        entry.touch();

        match &mut entry.phase {
            SessionPhase::Established { send_cipher, .. } => {
                let timestamp = wire::current_timestamp_ms();
                let inner_header = wire::build_fsp_inner(timestamp, wire::FSP_MSG_TYPE_DATA, 0);

                // Build inner plaintext: [fsp_inner:6][src_port:2][dst_port:2][payload]
                let mut inner = Vec::with_capacity(wire::FSP_INNER_HEADER_SIZE + 4 + payload.len());
                inner.extend_from_slice(&inner_header);
                inner.extend_from_slice(&src_port.to_le_bytes());
                inner.extend_from_slice(&dst_port.to_le_bytes());
                inner.extend_from_slice(payload);

                // Build FSP header (12 bytes, used as AEAD AAD)
                let counter = send_cipher.nonce();
                let payload_len = inner.len() as u16;
                let header = wire::build_fsp_header(0, payload_len, counter);

                // Encrypt
                let ciphertext = send_cipher.encrypt_with_aad(&inner, &header)?;

                // Assemble: header(12) + ciphertext+tag
                let mut out = Vec::with_capacity(wire::FSP_HEADER_SIZE + ciphertext.len());
                out.extend_from_slice(&header);
                out.extend_from_slice(&ciphertext);
                Ok(out)
            }
            _ => Err("session not established".into()),
        }
    }

    /// Build an encrypted FSP message for an established session.
    ///
    /// `inner_payload` starts with the msg_type byte (e.g., 0x12 for ReceiverReport).
    pub fn build_encrypted_session_message(
        &mut self,
        dest_addr: &[u8; 16],
        inner_payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or("no established session for this destination")?;

        match &mut entry.phase {
            SessionPhase::Established { send_cipher, .. } => {
                let timestamp = wire::current_timestamp_ms();
                // Build inner: [timestamp:4 LE][msg_type + payload...]
                let mut inner = Vec::with_capacity(4 + inner_payload.len());
                inner.extend_from_slice(&timestamp.to_le_bytes());
                inner.extend_from_slice(inner_payload);

                let counter = send_cipher.nonce();
                let payload_len = inner.len() as u16;
                let header = wire::build_fsp_header(0, payload_len, counter);

                // Encrypt
                let ciphertext = send_cipher.encrypt_with_aad(&inner, &header)?;

                // Assemble: header(12) + ciphertext+tag
                let mut out = Vec::with_capacity(wire::FSP_HEADER_SIZE + ciphertext.len());
                out.extend_from_slice(&header);
                out.extend_from_slice(&ciphertext);
                Ok(out)
            }
            _ => Err("session not established".into()),
        }
    }

    /// Build an encrypted session-layer ReceiverReport.
    pub fn build_session_receiver_report(
        &mut self,
        dest_addr: &[u8; 16],
        now_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let entry = self
            .sessions
            .get_mut(dest_addr)
            .ok_or("no session for this destination")?;

        let report_payload = match &mut entry.phase {
            SessionPhase::Established { receiver_state, .. } => receiver_state.build_report(now_ms),
            _ => return Err("session not established".into()),
        };

        self.build_encrypted_session_message(dest_addr, &report_payload)
    }

    /// Wrap an FSP payload in a SessionDatagram (link-layer msg_type 0x00 envelope).
    ///
    /// Returns the full link-layer inner payload (msg_type byte + datagram body).
    pub fn wrap_in_datagram(&self, dest_addr: &[u8; 16], fsp_payload: &[u8]) -> Vec<u8> {
        let body = wire::build_session_datagram_body(
            DEFAULT_TTL,
            DEFAULT_PATH_MTU,
            &self.our_addr,
            dest_addr,
            fsp_payload,
        );
        // Prepend msg_type 0x00 (SessionDatagram)
        let mut out = Vec::with_capacity(1 + body.len());
        out.push(wire::MSG_TYPE_SESSION_DATAGRAM);
        out.extend_from_slice(&body);
        out
    }
}
