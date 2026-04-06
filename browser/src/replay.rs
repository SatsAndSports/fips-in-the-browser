//! Sliding-window replay protection.
//!
//! Direct port from fips `src/noise/replay.rs` — no crypto dependencies,
//! pure bitmap logic. WireGuard/RFC 6479 style.

/// Replay window size in packets.
pub const REPLAY_WINDOW_SIZE: usize = 2048;

/// Sliding window for replay protection.
///
/// Tracks which packet counters have been received within a window of
/// `REPLAY_WINDOW_SIZE`. Packets with counters below the window or already
/// seen within the window are rejected.
#[derive(Clone)]
pub struct ReplayWindow {
    /// Highest counter value seen.
    highest: u64,
    /// Bitmap tracking which counters in the window have been seen.
    bitmap: [u64; REPLAY_WINDOW_SIZE / 64],
}

impl ReplayWindow {
    /// Create a new replay window.
    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: [0; REPLAY_WINDOW_SIZE / 64],
        }
    }

    /// Check if a counter is valid (not replayed, not too old).
    ///
    /// Returns true if the counter is acceptable. Does NOT update state —
    /// call `accept` after successful decryption.
    pub fn check(&self, counter: u64) -> bool {
        if counter > self.highest {
            return true;
        }
        let diff = self.highest - counter;
        if diff as usize >= REPLAY_WINDOW_SIZE {
            return false;
        }
        let word_idx = (diff as usize) / 64;
        let bit_idx = (diff as usize) % 64;
        (self.bitmap[word_idx] & (1u64 << bit_idx)) == 0
    }

    /// Accept a counter into the window.
    ///
    /// Call only after successful AEAD decryption.
    pub fn accept(&mut self, counter: u64) {
        if counter > self.highest {
            let shift = counter - self.highest;
            if shift as usize >= REPLAY_WINDOW_SIZE {
                self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            } else {
                self.shift_bitmap(shift as usize);
            }
            self.highest = counter;
            self.bitmap[0] |= 1;
        } else {
            let diff = self.highest - counter;
            let word_idx = (diff as usize) / 64;
            let bit_idx = (diff as usize) % 64;
            self.bitmap[word_idx] |= 1u64 << bit_idx;
        }
    }

    fn shift_bitmap(&mut self, shift: usize) {
        if shift >= REPLAY_WINDOW_SIZE {
            self.bitmap = [0; REPLAY_WINDOW_SIZE / 64];
            return;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        if word_shift > 0 {
            for i in (word_shift..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmap[i] = 0;
            }
        }
        if bit_shift > 0 {
            let mut carry = 0u64;
            for i in 0..self.bitmap.len() {
                let new_carry = self.bitmap[i] >> (64 - bit_shift);
                self.bitmap[i] = (self.bitmap[i] << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}
