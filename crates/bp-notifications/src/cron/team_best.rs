// SPDX-License-Identifier: AGPL-3.0-or-later

//! Team best cron: tells a Team's members when the Team's best share rises.
//! The best starts over only at the Team's own block, when
//! `resetRoundOnBlock` is set; a lower best after that is recorded without a
//! notice, as the per-address best-diff cron does. The baseline is stored in
//! `team_best_tracker`, only for Teams that have followers, so a best that
//! rose while this process was down is announced when it comes back; a Team
//! without a stored baseline is only recorded.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bp_common::AddressId;
use bp_db::{
    delete_team_best_trackers_except, find_group, find_team_best_ntfy_recipients,
    find_team_best_telegram_recipients, find_team_best_trackers, upsert_team_best_tracker,
};
use bp_group_solo_engine::round::GroupRoundStore;
use sqlx::PgPool;
use tokio::sync::watch;
use tracing::warn;
use uuid::Uuid;

use super::classify;
use crate::dispatcher::{NotificationDispatcher, TeamBestNotice};
use crate::format::Language;

const TARGET: &str = "bp_notifications::cron::team_best";

const TICK: Duration = Duration::from_secs(60);

/// Who follows one Team's best.
#[derive(Default)]
struct Followers {
    /// Chat and forum topic.
    telegram_chats: Vec<(i64, Option<i64>)>,
    ntfy_topics: Vec<(AddressId, Language)>,
}

pub fn spawn_team_best_cron(
    startup_offset: Duration,
    pool: PgPool,
    round: GroupRoundStore,
    dispatcher: Arc<NotificationDispatcher>,
) -> watch::Sender<bool> {
    super::spawn_periodic("team_best", TICK, startup_offset, move || {
        let (pool, round, dispatcher) = (pool.clone(), round.clone(), dispatcher.clone());
        async move {
            if let Err(e) = run_once(&pool, &round, &dispatcher).await {
                warn!(target: TARGET, error = %e, "tick failed");
            }
        }
    })
}

async fn run_once(
    pool: &PgPool,
    round: &GroupRoundStore,
    dispatcher: &NotificationDispatcher,
) -> Result<(), String> {
    let mut teams: BTreeMap<Uuid, Followers> = BTreeMap::new();
    for r in find_team_best_telegram_recipients(pool)
        .await
        .map_err(|e| format!("telegram recipients: {e}"))?
    {
        teams
            .entry(r.group_id)
            .or_default()
            .telegram_chats
            .push((r.telegram_chat_id, r.message_thread_id));
    }
    for r in find_team_best_ntfy_recipients(pool)
        .await
        .map_err(|e| format!("ntfy recipients: {e}"))?
    {
        teams
            .entry(r.group_id)
            .or_default()
            .ntfy_topics
            .push((r.address, Language::parse(&r.language)));
    }
    let followed: Vec<Uuid> = teams.keys().copied().collect();
    let mut with_best = Vec::new();
    for (group_id, followers) in teams {
        match round.read_best_share(&group_id.to_string()).await {
            Ok(Some(best)) => with_best.push((group_id, followers, best)),
            Ok(None) => {}
            Err(e) => warn!(target: TARGET, %group_id, error = %e, "team best read failed"),
        }
    }
    let current: Vec<(Uuid, f64)> = with_best
        .iter()
        .map(|(g, _, best)| (*g, best.difficulty))
        .collect();
    let rose = rises(pool, &followed, &current).await?;
    for (group_id, followers, best) in with_best {
        if !rose.contains(&group_id) {
            continue;
        }
        let group = match find_group(pool, group_id).await {
            Ok(Some(g)) => g,
            Ok(None) => continue,
            Err(e) => {
                // Not recorded, so the next tick tries again.
                warn!(target: TARGET, %group_id, error = %e, "group read failed");
                continue;
            }
        };
        // Recorded before the notice, and the notice skipped when that
        // fails, so a failing write cannot announce the same best every tick.
        if !record(pool, group_id, best.difficulty).await {
            continue;
        }
        let notice = TeamBestNotice {
            best_resets_on_block: group.reset_round_on_block,
            group_name: group.name,
            difficulty: best.difficulty,
            finder: best.address,
        };
        dispatcher
            .notify_team_best(&notice, &followers.telegram_chats, &followers.ntfy_topics)
            .await;
    }
    Ok(())
}

/// The followed Teams whose current best rose past their stored baseline,
/// to announce; the caller records each best once it is sure to announce it.
/// Every other change is recorded here without a notice, and the baselines
/// of Teams nobody follows are dropped: a Team followed again starts from
/// scratch, so a best reached meanwhile is not announced as new.
async fn rises(
    pool: &PgPool,
    followed: &[Uuid],
    current: &[(Uuid, f64)],
) -> Result<HashSet<Uuid>, String> {
    delete_team_best_trackers_except(pool, followed)
        .await
        .map_err(|e| format!("tracker cleanup: {e}"))?;
    let tracked: HashMap<Uuid, f64> = find_team_best_trackers(pool)
        .await
        .map_err(|e| format!("trackers read: {e}"))?
        .into_iter()
        .collect();
    let mut rose = HashSet::new();
    for &(group_id, best) in current {
        let action = classify(best, tracked.get(&group_id).copied());
        if action.notify {
            rose.insert(group_id);
        } else if action.upsert {
            record(pool, group_id, best).await;
        }
    }
    Ok(rose)
}

/// Stores `best` as the Team's baseline; `false` when the write failed.
async fn record(pool: &PgPool, group_id: Uuid, best: f64) -> bool {
    match upsert_team_best_tracker(pool, group_id, best, bp_common::now_ms()).await {
        Ok(()) => true,
        Err(e) => {
            warn!(target: TARGET, %group_id, error = %e, "team best tracker write failed");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn baseline(pool: &PgPool, group_id: Uuid) -> Option<f64> {
        find_team_best_trackers(pool)
            .await
            .expect("trackers read")
            .into_iter()
            .find(|(g, _)| *g == group_id)
            .map(|(_, best)| best)
    }

    /// One test, because `rises` drops the baseline of every Team it is not
    /// given: two tests in parallel would drop each other's rows.
    #[tokio::test]
    async fn the_stored_baseline_decides_what_is_announced() {
        let Some(pool) = bp_test_support::connect_pg_or_skip().await else {
            return;
        };
        let (rose, fresh, lower, equal, dropped) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        for (g, best) in [
            (rose, 100.0),
            (lower, 100.0),
            (equal, 100.0),
            (dropped, 100.0),
        ] {
            upsert_team_best_tracker(&pool, g, best, 1)
                .await
                .expect("seed baseline");
        }

        let followed = [rose, fresh, lower, equal];
        let current = [(rose, 150.0), (fresh, 150.0), (lower, 50.0), (equal, 100.0)];
        let announced = rises(&pool, &followed, &current).await.expect("rises");

        // A best above the stored baseline is announced even though this
        // process never saw the lower one: the baseline outlives a restart.
        assert_eq!(announced, HashSet::from([rose]));
        assert_eq!(
            baseline(&pool, rose).await,
            Some(100.0),
            "an announced best is recorded by the caller"
        );
        // No baseline yet: recorded, not announced.
        assert_eq!(baseline(&pool, fresh).await, Some(150.0));
        // A lower best moves the baseline down silently; an equal one stays.
        assert_eq!(baseline(&pool, lower).await, Some(50.0));
        assert_eq!(baseline(&pool, equal).await, Some(100.0));
        // A Team nobody follows any more loses its baseline.
        assert_eq!(baseline(&pool, dropped).await, None);

        delete_team_best_trackers_except(&pool, &[])
            .await
            .expect("cleanup");
    }
}
