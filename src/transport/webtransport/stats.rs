//! WebTransport transport statistics.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a WebTransport transport instance.
///
/// Uses atomic counters for lock-free updates from the receive loops
/// and send path concurrently.
pub struct WebTransportStats {
    pub datagrams_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub datagrams_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub sessions_accepted: AtomicU64,
    pub sessions_connected: AtomicU64,
    pub sessions_closed: AtomicU64,
}

impl WebTransportStats {
    /// Create a new stats instance with all counters at zero.
    pub fn new() -> Self {
        Self {
            datagrams_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            datagrams_recv: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            sessions_accepted: AtomicU64::new(0),
            sessions_connected: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
        }
    }

    /// Record a successful datagram send.
    pub fn record_send(&self, bytes: usize) {
        self.datagrams_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a successful datagram receive.
    pub fn record_recv(&self, bytes: usize) {
        self.datagrams_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a send error.
    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a receive error.
    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new accepted session (server side).
    pub fn record_session_accepted(&self) {
        self.sessions_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a new outbound session (client side).
    pub fn record_session_connected(&self) {
        self.sessions_connected.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a closed session.
    pub fn record_session_closed(&self) {
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
    }

    /// Take a snapshot of all counters.
    pub fn snapshot(&self) -> WebTransportStatsSnapshot {
        WebTransportStatsSnapshot {
            datagrams_sent: self.datagrams_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            datagrams_recv: self.datagrams_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            sessions_accepted: self.sessions_accepted.load(Ordering::Relaxed),
            sessions_connected: self.sessions_connected.load(Ordering::Relaxed),
            sessions_closed: self.sessions_closed.load(Ordering::Relaxed),
        }
    }
}

impl Default for WebTransportStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Point-in-time snapshot of WebTransport stats (non-atomic, copyable).
#[derive(Clone, Debug, Default, Serialize)]
pub struct WebTransportStatsSnapshot {
    pub datagrams_sent: u64,
    pub bytes_sent: u64,
    pub datagrams_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub sessions_accepted: u64,
    pub sessions_connected: u64,
    pub sessions_closed: u64,
}
