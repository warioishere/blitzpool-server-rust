// SPDX-License-Identifier: AGPL-3.0-or-later

//! Team round-best cron: tells a Team's members when the best share of the
//! Team's current round rises. The round is the group-solo engine's (see
//! [`bp_group_solo_engine::reader::round_reset`]); a lower best after it
//! starts over is recorded without a notice, as the per-address best-diff
//! cron does. The best last seen is kept in memory, only for Teams that have
//! followers; a Team seen for the first time is only recorded.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::time::Duration;

use bp_common::AddressId;
use bp_db::{find_group, find_team_best_ntfy_recipients, find_team_best_telegram_recipients};
use bp_group_solo_engine::reader::round_reset;
use bp_group_solo_engine::round::GroupRoundStore;
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::MissedTickBehavior;
use tracing::{info, warn};
use uuid::Uuid;

use crate::dispatcher::{NotificationDispatcher, TeamBestNotice};
use crate::format::Language;

const TARGET: &str = "bp_notifications::cron::team_best";

#[derive(Debug, Clone)]
pub struct TeamBestCronConfig {
    pub tick_interval: Duration,
    /// Phase offset applied to the first tick so this cron doesn't
    /// align with other periodic jobs of the same period.
    pub startup_offset: Duration,
}

impl Default for TeamBestCronConfig {
    fn default() -> Self {
        Self {
            tick_interval: Duration::from_secs(60),
            startup_offset: Duration::ZERO,
        }
    }
}

/// Who follows one Team's round best.
#[derive(Default)]
struct Followers {
    telegram_chats: Vec<i64>,
    ntfy_topics: Vec<(AddressId, Language)>,
}

pub fn spawn_team_best_cron(
    config: TeamBestCronConfig,
    pool: PgPool,
    round: GroupRoundStore,
    dispatcher: Arc<NotificationDispatcher>,
) -> watch::Sender<bool> {
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let start = tokio::time::Instant::now() + config.tick_interval + config.startup_offset;
        let mut ticker = tokio::time::interval_at(start, config.tick_interval);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
        info!(target: TARGET, "cron started");
        let mut seen: HashMap<Uuid, f64> = HashMap::new();
        loop {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { break; }
                }
                _ = ticker.tick() => {
                    if let Err(e) = run_once(&pool, &round, &dispatcher, &mut seen).await {
                        warn!(target: TARGET, error = %e, "tick failed");
                    }
                }
            }
        }
        info!(target: TARGET, "cron stopped");
    });
    shutdown_tx
}

async fn run_once(
    pool: &PgPool,
    round: &GroupRoundStore,
    dispatcher: &NotificationDispatcher,
    seen: &mut HashMap<Uuid, f64>,
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
            .push(r.telegram_chat_id);
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
    // A Team nobody follows any more starts from scratch when it is
    // followed again, so a best reached meanwhile is not announced as new.
    seen.retain(|group_id, _| teams.contains_key(group_id));
    for (group_id, followers) in teams {
        let best = match round.read_best_share(&group_id.to_string()).await {
            Ok(Some(best)) => best,
            Ok(None) => continue,
            Err(e) => {
                warn!(target: TARGET, %group_id, error = %e, "round best read failed");
                continue;
            }
        };
        match seen.get(&group_id) {
            Some(last) if best.difficulty > *last => {}
            Some(last) if best.difficulty == *last => continue,
            // First sight, or lower after the round started over.
            _ => {
                seen.insert(group_id, best.difficulty);
                continue;
            }
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
        seen.insert(group_id, best.difficulty);
        let notice = TeamBestNotice {
            reset: round_reset(&group),
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
