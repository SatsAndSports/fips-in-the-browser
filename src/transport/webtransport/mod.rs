//! WebTransport Transport Implementation
//!
//! Provides WebTransport-based transport for FIPS peer communication,
//! using unreliable QUIC datagrams as the packet delivery mechanism.
//!
//! Supports both server mode (accepting incoming WebTransport sessions)
//! and client mode (connecting to a remote WebTransport server). TLS is
//! mandatory (QUIC/HTTP3 requirement) but FIPS authentication happens at
//! the Noise layer, so client mode skips TLS certificate validation.

pub mod stats;

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::WebTransportConfig;
use stats::WebTransportStats;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{debug, info};
use wtransport::config::QuicTransportConfig;
use wtransport::tls::Sha256DigestFmt;
use wtransport::{Connection, Endpoint, Identity, ServerConfig};

/// Default initial MTU (UDP payload size) for QUIC connections.
///
/// 1452 bytes fits standard 1500-byte Ethernet with IPv6 + UDP headers
/// (1500 - 40 - 8 = 1452). This is also quinn's default PMTU discovery
/// upper bound. After subtracting QUIC/H3/WebTransport overhead (~23 bytes),
/// this gives ~1429 bytes of datagram payload — enough for a full IPv6
/// minimum-MTU packet (1280) wrapped in FMP framing (37 bytes overhead).
const DEFAULT_INITIAL_MTU: u16 = 1452;

/// Minimum MTU floor for QUIC (RFC 9000 minimum).
const DEFAULT_MIN_MTU: u16 = 1200;

/// FMP overhead: encrypted header (16) + AEAD tag (16) + inner header (5).
const FMP_OVERHEAD: usize = 37;

/// WebTransport transport for FIPS.
///
/// Uses QUIC/HTTP3 WebTransport sessions with unreliable datagrams for
/// packet delivery. Connection-oriented (QUIC session establishment) but
/// unreliable (datagrams may be lost or reordered).
///
/// Server mode: listens for incoming WebTransport sessions on a configured
/// address. Each accepted session spawns a datagram receive loop.
///
/// Client mode: connects to remote WebTransport servers via `connect_async()`.
/// Used when a peer address has `transport: "webtransport"`.
pub struct WebTransportTransport {
    /// Unique transport identifier.
    transport_id: TransportId,
    /// Optional instance name (for named instances in config).
    name: Option<String>,
    /// Configuration.
    config: WebTransportConfig,
    /// Current state.
    state: TransportState,
    /// Channel for delivering received packets to Node.
    packet_tx: PacketTx,
    /// Server accept loop task handle.
    accept_task: Option<JoinHandle<()>>,
    /// Active sessions keyed by remote address string.
    sessions: Arc<Mutex<HashMap<TransportAddr, SessionEntry>>>,
    /// Pending client connections (background tasks).
    connecting: Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>,
    /// Transport statistics.
    stats: Arc<WebTransportStats>,
}

/// An established WebTransport session.
struct SessionEntry {
    /// The WebTransport connection.
    connection: Connection,
    /// Datagram receive loop task handle.
    recv_task: JoinHandle<()>,
    /// Maximum WebTransport datagram payload (from QUIC PMTU discovery).
    /// This is the value from `connection.max_datagram_size()` at session
    /// establishment time.
    max_datagram_size: Option<usize>,
}

/// A pending client connection attempt.
struct ConnectingEntry {
    task: JoinHandle<Result<(Connection, TransportAddr), TransportError>>,
}

impl WebTransportTransport {
    /// Create a new WebTransport transport.
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: WebTransportConfig,
        packet_tx: PacketTx,
    ) -> Self {
        Self {
            transport_id,
            name,
            config,
            state: TransportState::Configured,
            packet_tx,
            accept_task: None,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            connecting: Arc::new(Mutex::new(HashMap::new())),
            stats: Arc::new(WebTransportStats::new()),
        }
    }

    /// Get the instance name (if configured as a named instance).
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the transport statistics.
    pub fn stats(&self) -> &Arc<WebTransportStats> {
        &self.stats
    }

    /// Whether to accept incoming connections. Default: true.
    pub fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }

    // ========================================================================
    // Async lifecycle
    // ========================================================================

    /// Start the transport asynchronously.
    ///
    /// If `bind_addr` is configured, loads or generates a TLS certificate,
    /// starts the WebTransport server endpoint, and spawns the session
    /// accept loop. If `bind_addr` is absent, the transport starts in
    /// client-only mode (outbound connections via `connect_async()` only).
    ///
    /// A transport with `bind_addr` set can do both: accept inbound
    /// sessions and initiate outbound client connections.
    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        if let Some(bind_str) = self.config.bind_addr() {
            // Server mode: listen for incoming WebTransport sessions.
            let identity = load_or_generate_identity(&self.config).await?;

            // Log certificate hash (useful for browser clients and debugging)
            if let Some(cert) = identity.certificate_chain().as_slice().first() {
                let hash = cert.hash();
                info!(
                    hash = %hash.fmt(Sha256DigestFmt::DottedHex),
                    "WebTransport certificate loaded"
                );
            }

            let bind_addr: std::net::SocketAddr = bind_str.parse().map_err(|e| {
                TransportError::StartFailed(format!("invalid bind address: {e}"))
            })?;

            // Configure quinn's QUIC transport with PMTU discovery and
            // a higher initial MTU so IPv6 packets fit from the start.
            let quic_transport = build_quic_transport_config();

            let server_config = ServerConfig::builder()
                .with_bind_address(bind_addr)
                .with_custom_transport(identity, quic_transport)
                .keep_alive_interval(Some(Duration::from_secs(3)))
                .build();

            let server = Endpoint::server(server_config).map_err(|e| {
                TransportError::StartFailed(format!("endpoint creation failed: {e}"))
            })?;

            info!(
                transport_id = %self.transport_id,
                bind_addr = %bind_addr,
                config_mtu = self.config.mtu(),
                initial_mtu = DEFAULT_INITIAL_MTU,
                min_mtu = DEFAULT_MIN_MTU,
                pmtu_discovery = "enabled",
                "WebTransport server started"
            );

            // Spawn accept loop
            let transport_id = self.transport_id;
            let packet_tx = self.packet_tx.clone();
            let sessions = self.sessions.clone();
            let stats = self.stats.clone();

            let accept_task = tokio::spawn(async move {
                accept_loop(server, transport_id, packet_tx, sessions, stats).await;
            });

            self.accept_task = Some(accept_task);
        } else {
            // Client-only mode: no server listener, outbound connections only.
            info!(
                transport_id = %self.transport_id,
                mtu = self.config.mtu(),
                "WebTransport transport started (client-only)"
            );
        }

        self.state = TransportState::Up;
        Ok(())
    }

    /// Stop the transport asynchronously.
    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Abort accept loop
        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }

        // Close all sessions
        {
            let mut sessions = self.sessions.lock().await;
            for (addr, entry) in sessions.drain() {
                entry.recv_task.abort();
                debug!(remote_addr = %addr, "WebTransport session closed (shutdown)");
            }
        }

        // Cancel pending connects
        {
            let mut connecting = self.connecting.lock().await;
            for (_, entry) in connecting.drain() {
                entry.task.abort();
            }
        }

        self.state = TransportState::Down;
        info!(transport_id = %self.transport_id, "WebTransport transport stopped");
        Ok(())
    }

    /// Send a datagram to a remote address asynchronously.
    pub async fn send_async(
        &self,
        addr: &TransportAddr,
        data: &[u8],
    ) -> Result<usize, TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        let sessions = self.sessions.lock().await;
        let entry = sessions.get(addr).ok_or_else(|| {
            TransportError::SendFailed(format!("no WebTransport session for {addr}"))
        })?;

        match entry.connection.send_datagram(data) {
            Ok(()) => {
                self.stats.record_send(data.len());
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed(format!(
                    "datagram send failed: {e}"
                )))
            }
        }
    }

    /// Initiate a non-blocking client connection to a remote WebTransport server.
    ///
    /// Spawns a background task that performs the QUIC/HTTP3 handshake.
    /// Poll `connection_state_sync()` to check when the connection is ready.
    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        // Already established?
        {
            let sessions = self.sessions.lock().await;
            if sessions.contains_key(addr) {
                return Ok(());
            }
        }

        // Already connecting?
        {
            let connecting = self.connecting.lock().await;
            if connecting.contains_key(addr) {
                return Ok(());
            }
        }

        let addr_string = addr
            .as_str()
            .ok_or_else(|| TransportError::InvalidAddress("not valid UTF-8".into()))?
            .to_string();

        let transport_id = self.transport_id;
        let remote_addr = addr.clone();

        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            "Initiating background WebTransport connect"
        );

        let task = tokio::spawn(async move {
            // Build a client config that skips TLS cert validation.
            // FIPS handles authentication via Noise IK — TLS is just
            // mandatory ceremony for QUIC/HTTP3 compliance.
            let mut client_config = wtransport::ClientConfig::builder()
                .with_bind_default()
                .with_no_cert_validation()
                .build();

            // Override the QUIC transport config with our PMTU-aware settings.
            // (with_no_cert_validation and with_custom_transport are mutually
            // exclusive builder states, so we mutate after build instead.)
            let quic_transport = build_quic_transport_config();
            client_config
                .quic_config_mut()
                .transport_config(Arc::new(quic_transport));

            let client = Endpoint::client(client_config).map_err(|e| {
                TransportError::StartFailed(format!("client endpoint creation failed: {e}"))
            })?;

            let url = format!("https://{}", addr_string);

            debug!(
                transport_id = %transport_id,
                url = %url,
                "WebTransport client connecting"
            );

            let connection = match tokio::time::timeout(
                Duration::from_secs(10),
                client.connect(&url),
            )
            .await
            {
                Ok(Ok(conn)) => conn,
                Ok(Err(e)) => {
                    debug!(
                        transport_id = %transport_id,
                        url = %url,
                        error = %e,
                        "WebTransport connect failed"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(_) => {
                    debug!(
                        transport_id = %transport_id,
                        url = %url,
                        "WebTransport connect timed out"
                    );
                    return Err(TransportError::Timeout);
                }
            };

            info!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "WebTransport client connected"
            );

            Ok((connection, remote_addr))
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });
        Ok(())
    }

    /// Query the state of a connection to a remote address.
    ///
    /// If a background connect task has completed, promotes it to the
    /// established sessions map (spawning a datagram receive loop).
    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        // Check established sessions first
        if let Ok(sessions) = self.sessions.try_lock() {
            if sessions.contains_key(addr) {
                return ConnectionState::Connected;
            }
        } else {
            return ConnectionState::Connecting;
        }

        // Check connecting pool
        let mut connecting = match self.connecting.try_lock() {
            Ok(c) => c,
            Err(_) => return ConnectionState::Connecting,
        };

        let entry = match connecting.get_mut(addr) {
            Some(e) => e,
            None => return ConnectionState::None,
        };

        if !entry.task.is_finished() {
            return ConnectionState::Connecting;
        }

        // Task finished — extract result
        let entry = connecting.remove(addr).unwrap();
        let result = futures::executor::block_on(entry.task);

        match result {
            Ok(Ok((connection, remote_addr))) => {
                // Query the QUIC-negotiated datagram capacity.
                let max_datagram_size = connection.max_datagram_size();
                let fmp_payload = max_datagram_size.map(|s| s.saturating_sub(FMP_OVERHEAD));

                info!(
                    transport_id = %self.transport_id,
                    remote_addr = %remote_addr,
                    max_datagram_size = ?max_datagram_size,
                    fmp_max_payload = ?fmp_payload,
                    ipv6_fits = fmp_payload.map_or(false, |p| p >= 1280),
                    "WebTransport client session established"
                );

                // Spawn datagram receive loop and promote to sessions
                let recv_task = spawn_datagram_rx(
                    connection.clone(),
                    self.transport_id,
                    remote_addr.clone(),
                    self.packet_tx.clone(),
                    self.stats.clone(),
                );

                self.stats.record_session_connected();

                if let Ok(mut sessions) = self.sessions.try_lock() {
                    sessions.insert(
                        addr.clone(),
                        SessionEntry {
                            connection,
                            recv_task,
                            max_datagram_size,
                        },
                    );
                }

                ConnectionState::Connected
            }
            Ok(Err(e)) => ConnectionState::Failed(e.to_string()),
            Err(e) => ConnectionState::Failed(format!("connect task panicked: {e}")),
        }
    }

    /// Close a specific session.
    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.remove(addr) {
            entry.recv_task.abort();
            self.stats.record_session_closed();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "WebTransport session closed"
            );
        }
    }
}

// ============================================================================
// Transport trait (sync shims — real work is in async methods)
// ============================================================================

impl Transport for WebTransportTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::WEBTRANSPORT
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn link_mtu(&self, addr: &TransportAddr) -> u16 {
        // Try to get the actual QUIC datagram capacity for this session.
        // Falls back to the config MTU if the session isn't found or locked.
        if let Ok(sessions) = self.sessions.try_lock() {
            if let Some(entry) = sessions.get(addr) {
                // Prefer the live value from the connection (tracks PMTU changes).
                if let Some(live_size) = entry.connection.max_datagram_size() {
                    return live_size.min(u16::MAX as usize) as u16;
                }
                // Fall back to the value captured at session establishment.
                if let Some(stored_size) = entry.max_datagram_size {
                    return stored_size.min(u16::MAX as usize) as u16;
                }
            }
        }
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for WebTransport transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for WebTransport transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for WebTransport transport".into(),
        ))
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }
}

// ============================================================================
// Server accept loop
// ============================================================================

/// Accept incoming WebTransport sessions and spawn datagram receive loops.
async fn accept_loop(
    server: Endpoint<wtransport::endpoint::endpoint_side::Server>,
    transport_id: TransportId,
    packet_tx: PacketTx,
    sessions: Arc<Mutex<HashMap<TransportAddr, SessionEntry>>>,
    stats: Arc<WebTransportStats>,
) {
    debug!(transport_id = %transport_id, "WebTransport accept loop starting");

    loop {
        let incoming_session = server.accept().await;

        let packet_tx = packet_tx.clone();
        let sessions = sessions.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            match handle_incoming_session(incoming_session, transport_id, packet_tx, sessions, stats)
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    debug!(
                        transport_id = %transport_id,
                        error = %e,
                        "Incoming WebTransport session failed"
                    );
                }
            }
        });
    }
}

/// Handle a single incoming WebTransport session.
async fn handle_incoming_session(
    incoming: wtransport::endpoint::IncomingSession,
    transport_id: TransportId,
    packet_tx: PacketTx,
    sessions: Arc<Mutex<HashMap<TransportAddr, SessionEntry>>>,
    stats: Arc<WebTransportStats>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let session_request = incoming.await?;

    info!(
        transport_id = %transport_id,
        authority = %session_request.authority(),
        path = %session_request.path(),
        "WebTransport session request"
    );

    let connection = session_request.accept().await?;

    // Use the session's stable ID as the transport address so that
    // outbound sends can be routed back to the right QUIC connection.
    let remote_addr = TransportAddr::from_string(&format!("wt-session-{}", connection.session_id()));

    // Query the QUIC-negotiated datagram capacity.
    let max_datagram_size = connection.max_datagram_size();
    let fmp_payload = max_datagram_size.map(|s| s.saturating_sub(FMP_OVERHEAD));

    info!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        max_datagram_size = ?max_datagram_size,
        fmp_max_payload = ?fmp_payload,
        ipv6_fits = fmp_payload.map_or(false, |p| p >= 1280),
        "WebTransport session accepted"
    );

    stats.record_session_accepted();

    let recv_task = spawn_datagram_rx(
        connection.clone(),
        transport_id,
        remote_addr.clone(),
        packet_tx,
        stats.clone(),
    );

    let mut sessions_guard = sessions.lock().await;
    sessions_guard.insert(
        remote_addr,
        SessionEntry {
            connection,
            recv_task,
            max_datagram_size,
        },
    );

    Ok(())
}

// ============================================================================
// Datagram receive loop
// ============================================================================

/// Spawn a datagram receive loop for a single WebTransport session.
///
/// Reads datagrams from the connection and feeds them as `ReceivedPacket`
/// into the Node's packet channel.
fn spawn_datagram_rx(
    connection: Connection,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    stats: Arc<WebTransportStats>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match connection.receive_datagram().await {
                Ok(datagram) => {
                    let data = datagram.to_vec();
                    stats.record_recv(data.len());

                    let packet =
                        ReceivedPacket::new(transport_id, remote_addr.clone(), data);

                    if packet_tx.send(packet).await.is_err() {
                        // Node shut down — stop receiving
                        break;
                    }
                }
                Err(e) => {
                    stats.record_recv_error();
                    debug!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        error = %e,
                        "WebTransport datagram receive error (session closing)"
                    );
                    break;
                }
            }
        }

        stats.record_session_closed();
        debug!(
            transport_id = %transport_id,
            remote_addr = %remote_addr,
            "WebTransport datagram receive loop ended"
        );
    })
}

// ============================================================================
// QUIC transport configuration
// ============================================================================

/// Build a quinn TransportConfig with PMTU discovery and a higher initial MTU.
///
/// The default quinn initial_mtu of 1200 only gives ~1177 bytes of WebTransport
/// datagram payload — not enough for a full IPv6 minimum-MTU packet (1280 bytes)
/// wrapped in FMP framing (37 bytes overhead = 1317 total).
///
/// By starting at 1452 (standard Ethernet minus IPv6+UDP headers), we get
/// ~1429 bytes of payload from the very first packet. PMTU discovery still
/// runs and will back off if the path can't support it.
fn build_quic_transport_config() -> QuicTransportConfig {
    let mut config = QuicTransportConfig::default();
    config.initial_mtu(DEFAULT_INITIAL_MTU);
    config.min_mtu(DEFAULT_MIN_MTU);
    // PMTU discovery is enabled by default in quinn; ensure it stays on.
    config.mtu_discovery_config(Some(Default::default()));
    config
}

// ============================================================================
// TLS identity management
// ============================================================================

/// Load a TLS identity from PEM files, or generate and persist a self-signed one.
async fn load_or_generate_identity(
    config: &WebTransportConfig,
) -> Result<Identity, TransportError> {
    let cert_path: &str = config.cert_file();
    let key_path: &str = config.key_file();

    // Try loading existing cert + key
    let cert_exists: bool = tokio::fs::metadata(cert_path).await.is_ok();
    let key_exists: bool = tokio::fs::metadata(key_path).await.is_ok();

    if cert_exists && key_exists {
        let identity: Identity = Identity::load_pemfiles(cert_path, key_path)
            .await
            .map_err(|e| {
                TransportError::StartFailed(format!("failed to load TLS identity: {e}"))
            })?;

        info!(cert = cert_path, key = key_path, "Loaded existing TLS identity");
        return Ok(identity);
    }

    // Generate self-signed (valid 14 days, ECDSA P-256)
    info!(
        cert = cert_path,
        key = key_path,
        "Generating self-signed TLS certificate"
    );

    let identity: Identity = Identity::self_signed(["localhost", "127.0.0.1", "::1"])
        .map_err(|e| TransportError::StartFailed(format!("cert generation failed: {e}")))?;

    // Persist to disk for reuse across restarts
    if let Some(parent) = std::path::Path::new(cert_path).parent() {
        let _: () = tokio::fs::create_dir_all(parent).await.map_err(|e| {
            TransportError::StartFailed(format!("failed to create cert directory: {e}"))
        })?;
    }

    let _: () = identity
        .certificate_chain()
        .store_pemfile(cert_path)
        .await
        .map_err(|e| {
            TransportError::StartFailed(format!("failed to write cert file: {e}"))
        })?;

    let _: () = identity
        .private_key()
        .store_secret_pemfile(key_path)
        .await
        .map_err(|e| {
            TransportError::StartFailed(format!("failed to write key file: {e}"))
        })?;

    info!("Self-signed TLS certificate persisted to disk");
    Ok(identity)
}
