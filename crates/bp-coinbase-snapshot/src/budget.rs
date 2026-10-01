// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable live coinbase weight budget, a Redis STRING with no TTL. It must
//! survive a restart, or a reboot drops to the config floor and the autoscaler
//! re-climbs from scratch. Missing or unparseable reads as `None` (config seed).

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

/// Redis key of the PPLNS live budget. The autoscaler writes it; the API
/// reads it to report the ceiling the running coinbase actually has.
pub const PPLNS_COINBASE_BUDGET_KEY: &str = "pplns:coinbase_budget";

/// Persist the live budget. Overwrites any prior value; no expiry.
pub async fn write_coinbase_budget(
    conn: &mut ConnectionManager,
    key: &str,
    budget: u32,
) -> Result<(), RedisError> {
    let _: () = conn.set(key, budget).await?;
    Ok(())
}

/// Read the persisted live budget. `Ok(None)` when missing or not a `u32`,
/// so the caller seeds from config rather than failing.
pub async fn read_coinbase_budget(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<u32>, RedisError> {
    let raw: Option<String> = match conn.get(key).await {
        Ok(v) => v,
        Err(e) if is_wrongtype(&e) => {
            warn!(key, error = %e, "coinbase budget: wrong-typed key, treating as missing");
            return Ok(None);
        }
        Err(e) => return Err(e),
    };
    match raw {
        Some(s) => match s.trim().parse::<u32>() {
            Ok(v) => Ok(Some(v)),
            Err(_) => {
                warn!(key, value = %s, "coinbase budget: unparseable value, treating as missing");
                Ok(None)
            }
        },
        None => Ok(None),
    }
}

fn is_wrongtype(e: &RedisError) -> bool {
    matches!(
        e.kind(),
        redis::ErrorKind::TypeError | redis::ErrorKind::ResponseError
    ) && e.to_string().to_ascii_uppercase().contains("WRONGTYPE")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Local dev Redis, or `None` (test skips) when unreachable.
    async fn conn() -> Option<ConnectionManager> {
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:16379".into());
        let client = redis::Client::open(url).ok()?;
        // `ConnectionManager::new` hangs on an unreachable host instead of
        // erroring.
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            ConnectionManager::new(client),
        )
        .await
        .ok()?
        .ok()
    }

    #[tokio::test]
    #[allow(clippy::print_stderr)]
    async fn round_trips_and_overwrites() {
        let Some(mut c) = conn().await else {
            eprintln!("skipping: no local Redis");
            return;
        };
        let key = "test:coinbase_budget:roundtrip";
        let _: () = c.del(key).await.unwrap();

        // Missing → None.
        assert_eq!(read_coinbase_budget(&mut c, key).await.unwrap(), None);

        // Write then read back.
        write_coinbase_budget(&mut c, key, 123_456).await.unwrap();
        assert_eq!(
            read_coinbase_budget(&mut c, key).await.unwrap(),
            Some(123_456)
        );

        // Overwrite wins.
        write_coinbase_budget(&mut c, key, 200_000).await.unwrap();
        assert_eq!(
            read_coinbase_budget(&mut c, key).await.unwrap(),
            Some(200_000)
        );

        let _: () = c.del(key).await.unwrap();
    }

    #[tokio::test]
    #[allow(clippy::print_stderr)]
    async fn no_ttl_set_on_value() {
        let Some(mut c) = conn().await else {
            eprintln!("skipping: no local Redis");
            return;
        };
        let key = "test:coinbase_budget:nottl";
        write_coinbase_budget(&mut c, key, 77_000).await.unwrap();
        // TTL -1 = key exists with no expiry (must persist across restarts).
        let ttl: i64 = c.ttl(key).await.unwrap();
        assert_eq!(ttl, -1, "live budget must not expire");
        let _: () = c.del(key).await.unwrap();
    }
}
