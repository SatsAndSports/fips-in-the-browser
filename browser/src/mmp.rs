//! MMP (Mesh Metric Protocol) receiver state and ReceiverReport builder.
//!
//! Tracks metadata from received encrypted frames and builds
//! ReceiverReports (msg_type 0x02) that the peer uses for RTT/loss metrics.

use crate::wire;

/// ReceiverReport body size (after msg_type byte).
const RECEIVER_REPORT_BODY_SIZE: usize = 67;

/// Receiver-side MMP state.
///
/// Tracks metadata from received encrypted frames for building
/// ReceiverReports. Updated on every incoming decrypted frame.
pub struct ReceiverState {
    /// Highest AEAD counter ever received.
    highest_counter: u64,
    /// Lifetime packets received.
    cumulative_packets: u64,
    /// Lifetime bytes received.
    cumulative_bytes: u64,
    /// Packets received since last report.
    interval_packets: u32,
    /// Bytes received since last report.
    interval_bytes: u32,
    /// Sender timestamp from the last received frame (session-relative ms).
    last_sender_timestamp: u32,
    /// Time (ms since epoch) when we last received a frame.
    last_recv_time_ms: u64,
}

impl ReceiverState {
    /// Create a new receiver state.
    pub fn new() -> Self {
        Self {
            highest_counter: 0,
            cumulative_packets: 0,
            cumulative_bytes: 0,
            interval_packets: 0,
            interval_bytes: 0,
            last_sender_timestamp: 0,
            last_recv_time_ms: 0,
        }
    }

    /// Record a received encrypted frame.
    ///
    /// Called for every successfully decrypted FMP frame.
    ///
    /// - `counter`: the AEAD counter from the FMP outer header
    /// - `sender_timestamp`: the 4-byte timestamp from the FMP inner header
    /// - `size`: total wire size of the frame
    /// - `now_ms`: current time in ms (from Date.now() or similar)
    pub fn record_frame(&mut self, counter: u64, sender_timestamp: u32, size: usize, now_ms: u64) {
        if counter > self.highest_counter {
            self.highest_counter = counter;
        }
        self.cumulative_packets += 1;
        self.cumulative_bytes += size as u64;
        self.interval_packets += 1;
        self.interval_bytes = self.interval_bytes.saturating_add(size as u32);
        self.last_sender_timestamp = sender_timestamp;
        self.last_recv_time_ms = now_ms;
    }

    /// Build a ReceiverReport payload.
    ///
    /// Returns the payload bytes (starting with msg_type 0x02) to be
    /// wrapped in an FMP encrypted frame.
    ///
    /// `now_ms` is the current time in milliseconds.
    pub fn build_report(&mut self, now_ms: u64) -> Vec<u8> {
        let dwell_time_ms = if self.last_recv_time_ms > 0 {
            (now_ms.saturating_sub(self.last_recv_time_ms)) as u16
        } else {
            0u16
        };

        let mut payload = Vec::with_capacity(1 + RECEIVER_REPORT_BODY_SIZE);

        // msg_type
        payload.push(wire::MSG_TYPE_RECEIVER_REPORT);
        // reserved (3 bytes)
        payload.extend_from_slice(&[0u8; 3]);
        // highest_counter (u64 LE)
        payload.extend_from_slice(&self.highest_counter.to_le_bytes());
        // cumulative_packets_recv (u64 LE)
        payload.extend_from_slice(&self.cumulative_packets.to_le_bytes());
        // cumulative_bytes_recv (u64 LE)
        payload.extend_from_slice(&self.cumulative_bytes.to_le_bytes());
        // timestamp_echo (u32 LE) — CRITICAL for RTT computation
        payload.extend_from_slice(&self.last_sender_timestamp.to_le_bytes());
        // dwell_time (u16 LE) — CRITICAL for RTT computation
        payload.extend_from_slice(&dwell_time_ms.to_le_bytes());
        // max_burst_loss (u16 LE)
        payload.extend_from_slice(&0u16.to_le_bytes());
        // mean_burst_loss (u16 LE)
        payload.extend_from_slice(&0u16.to_le_bytes());
        // reserved (u16 LE)
        payload.extend_from_slice(&0u16.to_le_bytes());
        // jitter (u32 LE)
        payload.extend_from_slice(&0u32.to_le_bytes());
        // ecn_ce_count (u32 LE)
        payload.extend_from_slice(&0u32.to_le_bytes());
        // owd_trend (i32 LE)
        payload.extend_from_slice(&0i32.to_le_bytes());
        // burst_loss_count (u32 LE)
        payload.extend_from_slice(&0u32.to_le_bytes());
        // cumulative_reorder_count (u32 LE)
        payload.extend_from_slice(&0u32.to_le_bytes());
        // interval_packets_recv (u32 LE)
        payload.extend_from_slice(&self.interval_packets.to_le_bytes());
        // interval_bytes_recv (u32 LE)
        payload.extend_from_slice(&self.interval_bytes.to_le_bytes());

        debug_assert_eq!(payload.len(), 1 + RECEIVER_REPORT_BODY_SIZE);

        // Reset interval counters after building report
        self.interval_packets = 0;
        self.interval_bytes = 0;

        payload
    }
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self::new()
    }
}
