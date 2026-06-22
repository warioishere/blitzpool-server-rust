// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable persistence of the live coinbase weight budget.
//!
//! The coinbase-budget autoscaler steps `coinbase_weight_budget` up/down at
//! runtime. That live value MUST survive a restart — otherwise a reboot resets
//! to the TOML floor and the autoscaler re-climbs from scratch (and bitcoin-
//! core's reservation snaps back down), which is itself a form of hopping.
//!
//! Stored as a plain Redis STRING (`SET key <u32>`), **no TTL** — it persists
//! until the next change overwrites it. A missing or unparseable value reads
//! back as `None` so the boot path falls back to the configured seed.

use redis::{aio::ConnectionManager, AsyncCommands, RedisError};
use tracing::warn;

/// Persist the live budget. Overwrites any prior value; no expiry.
pub async fn write_coinbase_budget(
    conn: &mut ConnectionManager,
    key: &str,
    budget: u32,
) -> Result<(), RedisError> {
    let _: () = conn.set(key, budget).await?;
    Ok(())
}

/// Read the persisted live budget. `Ok(None)` when the key is missing (first
/// boot) or holds a non-`u32` payload (legacy / corrupt — logged, treated as
/// missing so the caller seeds from config rather than crashing).
pub async fn read_coinbase_budget(
    conn: &mut ConnectionManager,
    key: &str,
) -> Result<Option<u32>, RedisError> {
    // Fetch as an optional string so a missing key isn't an error and a
    // wrong-typed key can be downgraded to "missing" with a warning.
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

/// `WRONGTYPE` guard — a key that exists under a non-STRING type (e.g. a stale
/// Hash) is reported as missing rather than crashing the read.
fn is_wrongtype(e: &RedisError) -> bool {
    matches!(
        e.kind(),
        redis::ErrorKind::TypeError | redis::ErrorKind::ResponseError
    ) && e.to_string().to_ascii_uppercase().contains("WRONGTYPE")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Connect to the local dev Redis (docker `blitzpool-rust-redis`). Skips
    /// the test body with a clear message if Redis isn't reachable, so the
    /// suite stays green on machines without the container.
    async fn conn() -> Option<ConnectionManager> {
        // Default to the docker dev Redis port (`:16379`), mirroring the
        // PG tests' `:15433` convention. Override via `REDIS_URL`.
        let url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:16379".into());
        let client = redis::Client::open(url).ok()?;
        // `ConnectionManager::new` retries internally and HANGS when the host
        // is unreachable (e.g. Redis on a non-default port) rather than
        // erroring — which would wedge the whole `cargo test` run. Bound it so
        // the test skips cleanly when Redis isn't reachable.
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
