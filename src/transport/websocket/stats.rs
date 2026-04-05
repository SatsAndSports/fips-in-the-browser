//! WebSocket transport statistics.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Statistics for a WebSocket transport instance.
pub struct WebSocketStats {
    pub messages_sent: AtomicU64,
    pub bytes_sent: AtomicU64,
    pub messages_recv: AtomicU64,
    pub bytes_recv: AtomicU64,
    pub send_errors: AtomicU64,
    pub recv_errors: AtomicU64,
    pub sessions_accepted: AtomicU64,
    pub sessions_connected: AtomicU64,
    pub sessions_closed: AtomicU64,
}

impl WebSocketStats {
    pub fn new() -> Self {
        Self {
            messages_sent: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            messages_recv: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            send_errors: AtomicU64::new(0),
            recv_errors: AtomicU64::new(0),
            sessions_accepted: AtomicU64::new(0),
            sessions_connected: AtomicU64::new(0),
            sessions_closed: AtomicU64::new(0),
        }
    }

    pub fn record_send(&self, bytes: usize) {
        self.messages_sent.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_recv(&self, bytes: usize) {
        self.messages_recv.fetch_add(1, Ordering::Relaxed);
        self.bytes_recv.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    pub fn record_send_error(&self) {
        self.send_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_recv_error(&self) {
        self.recv_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_accepted(&self) {
        self.sessions_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_connected(&self) {
        self.sessions_connected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_closed(&self) {
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> WebSocketStatsSnapshot {
        WebSocketStatsSnapshot {
            messages_sent: self.messages_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            messages_recv: self.messages_recv.load(Ordering::Relaxed),
            bytes_recv: self.bytes_recv.load(Ordering::Relaxed),
            send_errors: self.send_errors.load(Ordering::Relaxed),
            recv_errors: self.recv_errors.load(Ordering::Relaxed),
            sessions_accepted: self.sessions_accepted.load(Ordering::Relaxed),
            sessions_connected: self.sessions_connected.load(Ordering::Relaxed),
            sessions_closed: self.sessions_closed.load(Ordering::Relaxed),
        }
    }
}

impl Default for WebSocketStats {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct WebSocketStatsSnapshot {
    pub messages_sent: u64,
    pub bytes_sent: u64,
    pub messages_recv: u64,
    pub bytes_recv: u64,
    pub send_errors: u64,
    pub recv_errors: u64,
    pub sessions_accepted: u64,
    pub sessions_connected: u64,
    pub sessions_closed: u64,
}
