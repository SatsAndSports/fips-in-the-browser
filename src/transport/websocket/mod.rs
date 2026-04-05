//! WebSocket Transport Implementation
//!
//! Provides WebSocket-based transport for FIPS peer communication. Each
//! WebSocket binary message carries one FMP packet. No TLS — FIPS handles
//! authentication and encryption at the Noise layer.
//!
//! Supports server mode (accepting incoming WebSocket connections via HTTP
//! Upgrade) and client mode (connecting to a remote WebSocket server).

pub mod stats;

use super::{
    ConnectionState, DiscoveredPeer, PacketTx, ReceivedPacket, Transport, TransportAddr,
    TransportError, TransportId, TransportState, TransportType,
};
use crate::config::WebSocketConfig;
use futures::{SinkExt, StreamExt};
use stats::WebSocketStats;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message;
use tracing::{debug, info};

/// WebSocket transport for FIPS.
///
/// Uses WebSocket binary messages for packet delivery. Connection-oriented
/// and reliable (TCP underneath). Each binary message = one FMP packet.
///
/// Server mode: listens for incoming WebSocket connections on a configured
/// address. Each accepted connection performs an HTTP Upgrade handshake,
/// then spawns a message receive loop.
///
/// Client mode: connects to remote WebSocket servers via `connect_async()`.
pub struct WebSocketTransport {
    transport_id: TransportId,
    name: Option<String>,
    config: WebSocketConfig,
    state: TransportState,
    packet_tx: PacketTx,
    accept_task: Option<JoinHandle<()>>,
    sessions: Arc<Mutex<HashMap<TransportAddr, SessionEntry>>>,
    connecting: Arc<Mutex<HashMap<TransportAddr, ConnectingEntry>>>,
    stats: Arc<WebSocketStats>,
}

/// An established WebSocket session.
///
/// The write half is behind a Mutex so `send_async` can be called
/// concurrently with the receive loop.
struct SessionEntry {
    /// Write half of the WebSocket stream.
    writer: Arc<Mutex<WriterHandle>>,
    /// Receive loop task handle.
    recv_task: JoinHandle<()>,
}

/// Enum wrapping the two possible write-half types (server vs client).
enum WriterHandle {
    /// Server-accepted connection (plain TCP).
    Server(futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
        Message,
    >),
    /// Client-initiated connection (may be TLS-wrapped).
    Client(futures::stream::SplitSink<
        tokio_tungstenite::WebSocketStream<
            tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
        >,
        Message,
    >),
}

impl WriterHandle {
    async fn send(&mut self, msg: Message) -> Result<(), tokio_tungstenite::tungstenite::Error> {
        match self {
            WriterHandle::Server(w) => w.send(msg).await,
            WriterHandle::Client(w) => w.send(msg).await,
        }
    }
}

/// Type alias for the read half of a server-accepted WebSocket stream.
type ServerSplitStream = futures::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
>;

/// Type alias for the read half of a client-initiated WebSocket stream.
type ClientSplitStream = futures::stream::SplitStream<
    tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
>;

/// A pending client connection attempt.
struct ConnectingEntry {
    task: JoinHandle<Result<ConnectResult, TransportError>>,
}

struct ConnectResult {
    writer: Arc<Mutex<WriterHandle>>,
    reader: ClientSplitStream,
    remote_addr: TransportAddr,
}

impl WebSocketTransport {
    pub fn new(
        transport_id: TransportId,
        name: Option<String>,
        config: WebSocketConfig,
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
            stats: Arc::new(WebSocketStats::new()),
        }
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn stats(&self) -> &Arc<WebSocketStats> {
        &self.stats
    }

    // ========================================================================
    // Async lifecycle
    // ========================================================================

    pub async fn start_async(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Starting;

        if let Some(bind_str) = self.config.bind_addr() {
            let bind_addr: std::net::SocketAddr = bind_str.parse().map_err(|e| {
                TransportError::StartFailed(format!("invalid bind address: {e}"))
            })?;

            let listener = TcpListener::bind(bind_addr).await.map_err(|e| {
                TransportError::StartFailed(format!("bind failed: {e}"))
            })?;

            info!(
                transport_id = %self.transport_id,
                bind_addr = %bind_addr,
                "WebSocket server started"
            );

            let transport_id = self.transport_id;
            let packet_tx = self.packet_tx.clone();
            let sessions = self.sessions.clone();
            let stats = self.stats.clone();

            let accept_task = tokio::spawn(async move {
                accept_loop(listener, transport_id, packet_tx, sessions, stats).await;
            });

            self.accept_task = Some(accept_task);
        } else {
            info!(
                transport_id = %self.transport_id,
                "WebSocket transport started (client-only)"
            );
        }

        self.state = TransportState::Up;
        Ok(())
    }

    pub async fn stop_async(&mut self) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        if let Some(task) = self.accept_task.take() {
            task.abort();
            let _ = task.await;
        }

        {
            let mut sessions = self.sessions.lock().await;
            for (addr, entry) in sessions.drain() {
                entry.recv_task.abort();
                debug!(remote_addr = %addr, "WebSocket session closed (shutdown)");
            }
        }

        {
            let mut connecting = self.connecting.lock().await;
            for (_, entry) in connecting.drain() {
                entry.task.abort();
            }
        }

        self.state = TransportState::Down;
        info!(transport_id = %self.transport_id, "WebSocket transport stopped");
        Ok(())
    }

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
            TransportError::SendFailed(format!("no WebSocket session for {addr}"))
        })?;

        let mut handle = entry.writer.lock().await;
        match handle.send(Message::Binary(data.to_vec().into())).await {
            Ok(()) => {
                self.stats.record_send(data.len());
                Ok(data.len())
            }
            Err(e) => {
                self.stats.record_send_error();
                Err(TransportError::SendFailed(format!(
                    "WebSocket send failed: {e}"
                )))
            }
        }
    }

    pub async fn connect_async(&self, addr: &TransportAddr) -> Result<(), TransportError> {
        if !self.state.is_operational() {
            return Err(TransportError::NotStarted);
        }

        {
            let sessions = self.sessions.lock().await;
            if sessions.contains_key(addr) {
                return Ok(());
            }
        }

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
            "Initiating WebSocket connect"
        );

        let task = tokio::spawn(async move {
            let url = format!("ws://{}", addr_string);

            let ws_stream = match tokio::time::timeout(
                Duration::from_secs(10),
                tokio_tungstenite::connect_async(&url),
            )
            .await
            {
                Ok(Ok((stream, _response))) => stream,
                Ok(Err(e)) => {
                    debug!(
                        transport_id = %transport_id,
                        url = %url,
                        error = %e,
                        "WebSocket connect failed"
                    );
                    return Err(TransportError::ConnectionRefused);
                }
                Err(_) => {
                    debug!(
                        transport_id = %transport_id,
                        url = %url,
                        "WebSocket connect timed out"
                    );
                    return Err(TransportError::Timeout);
                }
            };

            info!(
                transport_id = %transport_id,
                remote_addr = %remote_addr,
                "WebSocket client connected"
            );

            let (write, read) = ws_stream.split();
            let writer = Arc::new(Mutex::new(WriterHandle::Client(write)));

            Ok(ConnectResult {
                writer,
                reader: read,
                remote_addr,
            })
        });

        let mut connecting = self.connecting.lock().await;
        connecting.insert(addr.clone(), ConnectingEntry { task });
        Ok(())
    }

    pub fn connection_state_sync(&self, addr: &TransportAddr) -> ConnectionState {
        if let Ok(sessions) = self.sessions.try_lock() {
            if sessions.contains_key(addr) {
                return ConnectionState::Connected;
            }
        } else {
            return ConnectionState::Connecting;
        }

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

        let entry = connecting.remove(addr).unwrap();
        let result = futures::executor::block_on(entry.task);

        match result {
            Ok(Ok(connect_result)) => {
                let recv_task = spawn_client_ws_rx(
                    connect_result.reader,
                    self.transport_id,
                    connect_result.remote_addr.clone(),
                    self.packet_tx.clone(),
                    self.stats.clone(),
                );

                self.stats.record_session_connected();

                info!(
                    transport_id = %self.transport_id,
                    remote_addr = %connect_result.remote_addr,
                    "WebSocket client session established"
                );

                if let Ok(mut sessions) = self.sessions.try_lock() {
                    sessions.insert(
                        addr.clone(),
                        SessionEntry {
                            writer: connect_result.writer,
                            recv_task,
                        },
                    );
                }

                ConnectionState::Connected
            }
            Ok(Err(e)) => ConnectionState::Failed(e.to_string()),
            Err(e) => ConnectionState::Failed(format!("connect task panicked: {e}")),
        }
    }

    pub async fn close_connection_async(&self, addr: &TransportAddr) {
        let mut sessions = self.sessions.lock().await;
        if let Some(entry) = sessions.remove(addr) {
            entry.recv_task.abort();
            self.stats.record_session_closed();
            debug!(
                transport_id = %self.transport_id,
                remote_addr = %addr,
                "WebSocket session closed"
            );
        }
    }
}

// ============================================================================
// Transport trait
// ============================================================================

impl Transport for WebSocketTransport {
    fn transport_id(&self) -> TransportId {
        self.transport_id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::WEBSOCKET
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        // WebSocket has no practical MTU limit (TCP underneath).
        // Use 65535 (max u16) since FMP packets are always well below this.
        u16::MAX
    }

    fn start(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use start_async() for WebSocket transport".into(),
        ))
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use stop_async() for WebSocket transport".into(),
        ))
    }

    fn send(&self, _addr: &TransportAddr, _data: &[u8]) -> Result<(), TransportError> {
        Err(TransportError::NotSupported(
            "use send_async() for WebSocket transport".into(),
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

async fn accept_loop(
    listener: TcpListener,
    transport_id: TransportId,
    packet_tx: PacketTx,
    sessions: Arc<Mutex<HashMap<TransportAddr, SessionEntry>>>,
    stats: Arc<WebSocketStats>,
) {
    debug!(transport_id = %transport_id, "WebSocket accept loop starting");

    loop {
        let (tcp_stream, peer_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!(
                    transport_id = %transport_id,
                    error = %e,
                    "TCP accept failed"
                );
                continue;
            }
        };

        let packet_tx = packet_tx.clone();
        let sessions = sessions.clone();
        let stats = stats.clone();

        tokio::spawn(async move {
            match tokio_tungstenite::accept_async(tcp_stream).await {
                Ok(ws_stream) => {
                    let remote_addr = TransportAddr::from_string(&format!("ws-{}", peer_addr));

                    info!(
                        transport_id = %transport_id,
                        remote_addr = %remote_addr,
                        "WebSocket session accepted"
                    );

                    stats.record_session_accepted();

                    let (write, read) = ws_stream.split();
                    let writer = Arc::new(Mutex::new(WriterHandle::Server(write)));

                    let recv_task = spawn_server_ws_rx(
                        read,
                        transport_id,
                        remote_addr.clone(),
                        packet_tx,
                        stats,
                    );

                    let mut sessions_guard = sessions.lock().await;
                    sessions_guard.insert(
                        remote_addr,
                        SessionEntry { writer, recv_task },
                    );
                }
                Err(e) => {
                    debug!(
                        transport_id = %transport_id,
                        peer_addr = %peer_addr,
                        error = %e,
                        "WebSocket HTTP Upgrade failed"
                    );
                }
            }
        });
    }
}

// ============================================================================
// Message receive loop
// ============================================================================

/// Spawn receive loop for a server-accepted WebSocket connection.
fn spawn_server_ws_rx(
    reader: ServerSplitStream,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    stats: Arc<WebSocketStats>,
) -> JoinHandle<()> {
    tokio::spawn(ws_rx_loop(reader, transport_id, remote_addr, packet_tx, stats))
}

/// Spawn receive loop for a client-initiated WebSocket connection.
fn spawn_client_ws_rx(
    reader: ClientSplitStream,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    stats: Arc<WebSocketStats>,
) -> JoinHandle<()> {
    tokio::spawn(ws_rx_loop(reader, transport_id, remote_addr, packet_tx, stats))
}

/// Generic WebSocket receive loop. Works with any stream that yields Messages.
async fn ws_rx_loop<S>(
    mut reader: S,
    transport_id: TransportId,
    remote_addr: TransportAddr,
    packet_tx: PacketTx,
    stats: Arc<WebSocketStats>,
)
where
    S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
{
    loop {
        match reader.next().await {
            Some(Ok(Message::Binary(data))) => {
                let data_vec = data.to_vec();
                stats.record_recv(data_vec.len());

                let packet = ReceivedPacket::new(
                    transport_id,
                    remote_addr.clone(),
                    data_vec,
                );

                if packet_tx.send(packet).await.is_err() {
                    break;
                }
            }
            Some(Ok(Message::Close(_))) => {
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    "WebSocket close received"
                );
                break;
            }
            Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => {
                // Tungstenite handles ping/pong automatically
            }
            Some(Ok(_)) => {
                // Text or other message types — ignore
            }
            Some(Err(e)) => {
                stats.record_recv_error();
                debug!(
                    transport_id = %transport_id,
                    remote_addr = %remote_addr,
                    error = %e,
                    "WebSocket receive error"
                );
                break;
            }
            None => {
                break;
            }
        }
    }

    stats.record_session_closed();
    debug!(
        transport_id = %transport_id,
        remote_addr = %remote_addr,
        "WebSocket receive loop ended"
    );
}
