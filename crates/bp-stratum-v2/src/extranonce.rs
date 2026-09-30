// SPDX-License-Identifier: AGPL-3.0-or-later

//! Pool-side extranonce-prefix allocation for SV2 channels.
//!
//! The allocator itself lives in [`bp_common::extranonce`], shared with SV1.
//! What is SV2's own is the key: SV1 holds one prefix per connection, SV2
//! one per channel, and a wire `channel_id` is only unique within its
//! connection (every connection's first channel is id 1).

pub use bp_common::extranonce::{SharedExtranonceAllocator, SV2_WORKER_ID};

/// One connection's view of the SV2 allocator: the pool-wide instance plus
/// a number that sets this connection's channel keys apart from every other
/// live connection's.
///
/// That number comes from the allocator's own counter, not from the random
/// `session_id`, because two connections can draw the same session id and
/// must still get distinct prefixes. It is truncated to
/// 32 bits to leave the low half of the key for the channel id, so it
/// repeats after 2^32 connections — a collision then needs a connection
/// that stayed open across all of them.
///
/// Deliberately not `Clone`: a copy would carry the same connection number.
#[derive(Debug)]
pub struct ConnectionExtranonce {
    shared: SharedExtranonceAllocator,
    connection: u32,
}

impl ConnectionExtranonce {
    /// Claim a connection number on `shared`. Call once per connection.
    pub fn new(shared: SharedExtranonceAllocator) -> Self {
        let connection = shared.next_key() as u32;
        Self { shared, connection }
    }

    /// The prefix for `channel_id`; the same one again for a repeated id.
    /// Empty, and logged, when the partition is exhausted.
    pub fn allocate(&self, channel_id: u32) -> Vec<u8> {
        match self.shared.allocate(self.key(channel_id)) {
            Ok(prefix) => prefix.to_vec(),
            Err(err) => {
                tracing::warn!(
                    channel_id,
                    "sv2: {err}; opening the channel with an empty (non-unique) \
                     extranonce prefix"
                );
                Vec::new()
            }
        }
    }

    /// Return `channel_id`'s prefix. A no-op for an id holding none.
    pub fn release(&self, channel_id: u32) {
        self.shared.release(self.key(channel_id));
    }

    fn key(&self, channel_id: u32) -> u64 {
        (u64::from(self.connection) << 32) | u64::from(channel_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Channel 1 on two connections gets two prefixes; the same channel id
    /// again gets its own prefix back; a release frees it.
    #[test]
    fn channel_keys_are_per_connection() {
        let shared = SharedExtranonceAllocator::new_default_on_worker(SV2_WORKER_ID);
        let a = ConnectionExtranonce::new(shared.clone());
        let b = ConnectionExtranonce::new(shared.clone());

        let p_a = a.allocate(1);
        let p_b = b.allocate(1);
        assert_eq!(p_a.len(), 4, "precondition: a real prefix was allocated");
        assert_ne!(
            p_a, p_b,
            "channel 1 on two connections must not share a prefix"
        );
        assert_eq!(p_a, a.allocate(1), "a repeated channel id keeps its prefix");
        assert_eq!(shared.allocated_count(), 2);

        a.release(1);
        assert_eq!(shared.allocated_count(), 1, "release frees the prefix");
        a.release(1);
        assert_eq!(shared.allocated_count(), 1, "a second release is a no-op");
    }
}
