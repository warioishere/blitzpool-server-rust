// SPDX-License-Identifier: AGPL-3.0-or-later

//! The front process's boot time, a Redis STRING (epoch millis, no TTL).
//! `/api/info` reports it as the pool's uptime, so restarting a satellite
//! (api, payout, notify) leaves the uptime alone and only a front restart
//! resets it.

use chrono::{DateTime, Utc};
use redis::{aio::ConnectionManager, AsyncCommands, RedisError};

pub const CORE_STARTED_AT_KEY: &str = "pool:core:started_at";

/// Overwrites any prior value; no expiry.
pub async fn write_core_started_at(
    conn: &mut ConnectionManager,
    at: DateTime<Utc>,
) -> Result<(), RedisError> {
    let _: () = conn.set(CORE_STARTED_AT_KEY, at.timestamp_millis()).await?;
    Ok(())
}

/// `Ok(None)` when missing or not epoch millis.
pub async fn read_core_started_at(
    conn: &mut ConnectionManager,
) -> Result<Option<DateTime<Utc>>, RedisError> {
    let raw: Option<String> = conn.get(CORE_STARTED_AT_KEY).await?;
    Ok(raw
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(DateTime::from_timestamp_millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn started_at_round_trips_and_garbage_reads_as_none() {
        let Some(mut conn) =
            bp_test_support::connect_redis_in_range_or_skip(bp_test_support::redis_db::API, 1)
                .await
        else {
            return;
        };
        assert_eq!(read_core_started_at(&mut conn).await.unwrap(), None);

        let at = DateTime::from_timestamp_millis(1_790_000_000_123).unwrap();
        write_core_started_at(&mut conn, at).await.unwrap();
        assert_eq!(read_core_started_at(&mut conn).await.unwrap(), Some(at));

        let _: () = conn.set(CORE_STARTED_AT_KEY, "not-a-number").await.unwrap();
        assert_eq!(read_core_started_at(&mut conn).await.unwrap(), None);
    }
}
