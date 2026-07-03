// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-style bot commands.
//!
//! Two layers:
//!
//! - Stateless commands (no engine reader needed):
//!   [`build_pool_hashrate`], [`build_current_difficulty`],
//!   [`build_next_difficulty`], [`build_stats`], [`build_group_history`].
//! - Engine-reader commands: [`build_pplns_status`],
//!   [`build_pplns_top`], [`build_group_status`], [`build_group_members`],
//!   [`build_show_workers`]. These take the optional engine handles
//!   from [`crate::command::CommandHandler`] and fall back to a
//!   "not configured" reply when the corresponding engine wasn't
//!   wired in at startup.

use std::sync::Arc;
use std::time::Duration;

use bp_common::AddressId;
use bp_db::{
    find_address_settings, find_clients_by_address, find_group, find_group_member_by_address,
    find_pplns_group_members_for_group, find_recent_group_block_history, sum_active_pool_hashrate,
    sum_hashrate_for_addresses, PplnsGroupBlockHistoryRow,
};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_pplns_engine::engine::PplnsEngine;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use tracing::warn;

use crate::format::{format_number_suffix, Language};

const MEMPOOL_CURRENT_DIFF: &str = "https://mempool.space/api/v1/mining/hashrate/3d";
const MEMPOOL_NEXT_ADJUST: &str = "https://mempool.space/api/v1/difficulty-adjustment";

// ── Small shared client builder so the listener can pass one Client
// down to all read commands (keeps connection pool reuse). For tests
// we always inline a default 5s-timeout client.

fn default_http_client() -> Client {
    Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("default reqwest Client build")
}

// ── /poolhashrate ────────────────────────────────────────────────────

pub(super) async fn build_pool_hashrate(pool: &PgPool, lang: Language) -> String {
    let now_ms = chrono::Utc::now().timestamp_millis();
    match sum_active_pool_hashrate(pool, now_ms, bp_db::HASHRATE_DECAY_WINDOW_MS).await {
        Ok(total) => format_pool_hashrate(lang, total),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "pool_hashrate");
            match lang {
                Language::De => "Konnte die Pool-Hashrate nicht abrufen.".to_string(),
                Language::En => "Could not fetch pool hashrate.".to_string(),
            }
        }
    }
}

fn format_pool_hashrate(lang: Language, total_h_per_s: f64) -> String {
    let th = total_h_per_s / 1e12;
    match lang {
        Language::De => format!("Aktuelle Pool-Hashrate: {th:.2} TH/s"),
        Language::En => format!("Current pool hashrate: {th:.2} TH/s"),
    }
}

// ── /difficulty ──────────────────────────────────────────────────────

pub(super) async fn build_current_difficulty(lang: Language) -> String {
    let client = default_http_client();
    match fetch_current_difficulty(&client).await {
        Ok(diff) => format_current_difficulty(lang, diff),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "current_difficulty");
            match lang {
                Language::De => "Konnte die Difficulty nicht abrufen.".to_string(),
                Language::En => "Could not fetch difficulty.".to_string(),
            }
        }
    }
}

async fn fetch_current_difficulty(client: &Client) -> Result<f64, String> {
    #[derive(Deserialize)]
    struct CurrentDifficulty {
        #[serde(rename = "currentDifficulty")]
        current_difficulty: f64,
    }
    let resp = client
        .get(MEMPOOL_CURRENT_DIFF)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status().as_u16()));
    }
    let body: CurrentDifficulty = resp.json().await.map_err(|e| format!("body: {e}"))?;
    Ok(body.current_difficulty)
}

fn format_current_difficulty(lang: Language, raw: f64) -> String {
    let t = raw / 1e12;
    match lang {
        Language::De => format!("Aktuelle Difficulty: {t:.2} T"),
        Language::En => format!("Current difficulty: {t:.2} T"),
    }
}

// ── /next_difficulty ─────────────────────────────────────────────────

pub(super) async fn build_next_difficulty(lang: Language) -> String {
    let client = default_http_client();
    match fetch_next_adjustment(&client).await {
        Ok(adj) => format_next_adjustment(lang, &adj),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "next_difficulty");
            match lang {
                Language::De => {
                    "Konnte die nächste Difficulty-Anpassung nicht abrufen.".to_string()
                }
                Language::En => "Could not fetch next difficulty adjustment.".to_string(),
            }
        }
    }
}

#[derive(Debug, Deserialize)]
struct NextDifficultyAdjustment {
    #[serde(rename = "progressPercent")]
    pub progress_percent: f64,
    #[serde(rename = "difficultyChange")]
    pub difficulty_change: f64,
    /// Epoch-ms timestamp for the estimated retarget; mempool.space
    /// returns it as a number (not ISO string).
    #[serde(rename = "estimatedRetargetDate")]
    pub estimated_retarget_date_ms: i64,
}

async fn fetch_next_adjustment(client: &Client) -> Result<NextDifficultyAdjustment, String> {
    let resp = client
        .get(MEMPOOL_NEXT_ADJUST)
        .send()
        .await
        .map_err(|e| format!("request: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("status {}", resp.status().as_u16()));
    }
    resp.json().await.map_err(|e| format!("body: {e}"))
}

fn format_next_adjustment(lang: Language, adj: &NextDifficultyAdjustment) -> String {
    let change_text = if adj.difficulty_change >= 0.0 {
        format!("\u{1f4c8} +{:.2}%", adj.difficulty_change)
    } else {
        format!("\u{1f4c9} {:.2}%", adj.difficulty_change)
    };
    let dt = DateTime::<Utc>::from_timestamp_millis(adj.estimated_retarget_date_ms)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
    // dd.MM.yyyy HH:mm UTC — seconds dropped for tighter bot output;
    // the UTC suffix makes the timezone unambiguous.
    let when = dt.format("%d.%m.%Y, %H:%M UTC").to_string();
    let progress = format!("{:.2}", adj.progress_percent);
    match lang {
        Language::De => format!(
            "\u{1f4ca} Nächste Difficulty-Anpassung:\n\n\
            • Fortschritt: {progress}%\n\
            • Geschätzt: {when}\n\
            • Erwartete Änderung: {change_text}"
        ),
        Language::En => format!(
            "\u{1f4ca} Next difficulty adjustment:\n\n\
            • Progress: {progress}%\n\
            • Estimated: {when}\n\
            • Expected change: {change_text}"
        ),
    }
}

// ── /stats <address> ─────────────────────────────────────────────────

pub(crate) async fn build_stats(pool: &PgPool, lang: Language, address: &AddressId) -> String {
    let workers = match find_clients_by_address(pool, address).await {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "stats: clients lookup");
            return db_error_text(lang);
        }
    };
    if workers.is_empty() {
        return match lang {
            Language::De => format!(
                "Keine aktiven Worker für {addr} gefunden.",
                addr = format_address_short(address.as_str())
            ),
            Language::En => format!(
                "No active workers found for {addr}.",
                addr = format_address_short(address.as_str())
            ),
        };
    }
    let total_hashrate: f64 = workers.iter().map(|w| w.hash_rate).sum();
    let total_th = total_hashrate / 1e12;
    let now_ms = Utc::now().timestamp_millis();
    // Freshness from the first worker row's `updatedAt` — single-worker
    // assumption that the first row represents the address.
    let last_seen_seconds = ((now_ms - workers[0].updated_at).max(0) / 1000) as i64;

    let settings = match find_address_settings(pool, address).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "stats: address_settings");
            return db_error_text(lang);
        }
    };
    let total_shares = settings.as_ref().map(|r| r.shares).unwrap_or(0.0);
    let best_diff_raw = settings.as_ref().map(|r| r.best_difficulty).unwrap_or(0.0);
    let best_g = best_diff_raw / 1e9;

    match lang {
        Language::De => format!(
            "\u{1f4c8} Stats für deine Adresse:\n\
            - Aktuelle Hashrate: {total_th:.2} TH/s\n\
            - Gesamt-Shares: {shares}\n\
            - Letzter Share: vor {last_seen_seconds} Sekunden\n\
            - Beste Difficulty: {best_g:.2} G",
            shares = format_number_suffix(total_shares),
        ),
        Language::En => format!(
            "\u{1f4c8} Stats for your address:\n\
            - Current hashrate: {total_th:.2} TH/s\n\
            - Total shares: {shares}\n\
            - Last share: {last_seen_seconds} seconds ago\n\
            - Best difficulty: {best_g:.2} G",
            shares = format_number_suffix(total_shares),
        ),
    }
}

// ── /group_history <address> ─────────────────────────────────────────

pub(super) async fn build_group_history(
    pool: &PgPool,
    lang: Language,
    address: &AddressId,
) -> String {
    let member = match find_group_member_by_address(pool, address).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_history: member");
            return db_error_text(lang);
        }
    };
    let Some(member) = member else {
        return not_in_group_text(lang, address.as_str());
    };
    let group = match find_group(pool, member.group_id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return match lang {
                Language::De => "Gruppe nicht mehr verfügbar.".to_string(),
                Language::En => "Group is no longer available.".to_string(),
            }
        }
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_history: group");
            return db_error_text(lang);
        }
    };
    let history = match find_recent_group_block_history(pool, member.group_id, 50).await {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_history: history");
            return db_error_text(lang);
        }
    };
    let mine: Vec<&PplnsGroupBlockHistoryRow> = history
        .iter()
        .filter(|h| h.address == address.clone())
        .take(10)
        .collect();
    if mine.is_empty() {
        return match lang {
            Language::De => format!(
                "Keine Auszahlungen für {addr} in \"{name}\".",
                addr = format_address_short(address.as_str()),
                name = group.name,
            ),
            Language::En => format!(
                "No payouts for {addr} in \"{name}\".",
                addr = format_address_short(address.as_str()),
                name = group.name,
            ),
        };
    }
    let mut lines: Vec<String> = Vec::with_capacity(mine.len());
    for entry in &mine {
        let when = DateTime::<Utc>::from_timestamp_millis(entry.created_at)
            .map(|dt| match lang {
                Language::De => dt.format("%d.%m.%y, %H:%M UTC").to_string(),
                Language::En => dt.format("%-m/%-d/%y, %H:%M UTC").to_string(),
            })
            .unwrap_or_else(|| "—".to_string());
        let sats: i64 = entry.paid_sats.into();
        let amount = format_sats(sats);
        lines.push(format!(
            "Block {height} — {when} — {amount} sats",
            height = entry.block_height,
        ));
    }
    match lang {
        Language::De => format!(
            "Letzte Auszahlungen für {addr} in \"{name}\":\n{body}",
            addr = format_address_short(address.as_str()),
            name = group.name,
            body = lines.join("\n"),
        ),
        Language::En => format!(
            "Recent payouts for {addr} in \"{name}\":\n{body}",
            addr = format_address_short(address.as_str()),
            name = group.name,
            body = lines.join("\n"),
        ),
    }
}

// ── Local helpers ────────────────────────────────────────────────────

pub(super) fn format_address_short(address: &str) -> String {
    if address.len() <= 9 {
        return address.to_string();
    }
    let head: String = address.chars().take(4).collect();
    let tail: String = address
        .chars()
        .rev()
        .take(5)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect();
    format!("{head}...{tail}")
}

fn format_sats(sats: i64) -> String {
    // en-US thousand separators ("12,345").
    let abs = sats.unsigned_abs();
    let mut s = format!("{abs}");
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    let mut count = 0;
    while let Some(c) = s.pop() {
        if count > 0 && count % 3 == 0 {
            out.push(',');
        }
        out.push(c);
        count += 1;
    }
    let joined: String = out.chars().rev().collect();
    if sats < 0 {
        format!("-{joined}")
    } else {
        joined
    }
}

fn db_error_text(lang: Language) -> String {
    match lang {
        Language::De => "Datenbank-Fehler, bitte später noch einmal versuchen.".to_string(),
        Language::En => "Database error, please try again later.".to_string(),
    }
}

fn not_in_group_text(lang: Language, address: &str) -> String {
    let short = format_address_short(address);
    match lang {
        Language::De => format!("{short} ist in keiner Gruppe."),
        Language::En => format!("{short} is not in any group."),
    }
}

fn group_unavailable_text(lang: Language) -> String {
    match lang {
        Language::De => "Gruppe nicht mehr verfügbar.".to_string(),
        Language::En => "Group is no longer available.".to_string(),
    }
}

fn engine_error_text(lang: Language) -> String {
    match lang {
        Language::De => "Engine-Fehler, bitte später noch einmal versuchen.".to_string(),
        Language::En => "Engine error, please try again later.".to_string(),
    }
}

fn format_hashrate_th(hash_rate: f64) -> String {
    let th = hash_rate / 1e12;
    format!("{th:.2} TH/s")
}

// ── /pplns_status <address> ──────────────────────────────────────────

pub(super) async fn build_pplns_status(
    pool: &PgPool,
    pplns: &Arc<PplnsEngine>,
    lang: Language,
    address: &AddressId,
) -> String {
    let reader = pplns.reader();

    let (status, window, distribution, my_hash) = tokio::join!(
        reader.address_status(address.as_str()),
        reader.window_stats(),
        reader.current_distribution(),
        sum_hashrate_for_addresses(pool, std::slice::from_ref(address)),
    );

    let status = match status {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "pplns_status: address_status");
            return engine_error_text(lang);
        }
    };
    let window = match window {
        Ok(w) => w,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "pplns_status: window");
            return engine_error_text(lang);
        }
    };
    let distribution = match distribution {
        Ok(d) => d,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "pplns_status: distribution");
            return engine_error_text(lang);
        }
    };
    let my_hashrate = my_hash.unwrap_or_else(|e| {
        warn!(target: "bp_notifications::command::read", error = %e, "pplns_status: own hashrate");
        0.0
    });

    let pplns_addresses: Vec<AddressId> = distribution
        .iter()
        .filter_map(|d| AddressId::new(d.address.clone()).ok())
        .collect();
    let total_pplns_hashrate = if pplns_addresses.is_empty() {
        0.0
    } else {
        sum_hashrate_for_addresses(pool, &pplns_addresses)
            .await
            .unwrap_or_else(|e| {
                warn!(target: "bp_notifications::command::read", error = %e, "pplns_status: pool hashrate");
                0.0
            })
    };

    let trimmed = format_address_short(address.as_str());
    let (percent, my_shares, balance, total_paid) = match status {
        Some(s) => (
            s.current_window_percent,
            s.current_window_shares,
            s.balance_sats,
            s.total_paid_sats,
        ),
        None => (0.0, 0.0, 0, 0),
    };
    let total_shares = window.total_shares;
    let miner_count = window.miner_count;

    let ledger_de = match balance.cmp(&0) {
        std::cmp::Ordering::Greater => format!("{} sats (Pool schuldet dir)", format_sats(balance)),
        std::cmp::Ordering::Less => format!(
            "{} sats (du schuldest dem Pool — wird mit nächster Auszahlung verrechnet)",
            format_sats(balance)
        ),
        std::cmp::Ordering::Equal => "0 sats".to_string(),
    };
    let ledger_en = match balance.cmp(&0) {
        std::cmp::Ordering::Greater => format!("{} sats (pool owes you)", format_sats(balance)),
        std::cmp::Ordering::Less => format!(
            "{} sats (you owe the pool — settled at the next payout)",
            format_sats(balance)
        ),
        std::cmp::Ordering::Equal => "0 sats".to_string(),
    };

    match lang {
        Language::De => format!(
            "PPLNS Status — {trimmed}\n\
            Window-Anteil: {percent:.2}%\n\
            Deine Hashrate: {my_h}\n\
            PPLNS-Hashrate (gesamt): {pool_h}\n\
            Deine Shares: {my_sh}\n\
            Pool-Shares (Window): {total_sh}\n\
            Aktive Miner im Window: {miner_count}\n\
            Saldo: {ledger}\n\
            Lifetime ausbezahlt: {paid} sats",
            my_h = format_hashrate_th(my_hashrate),
            pool_h = format_hashrate_th(total_pplns_hashrate),
            my_sh = format_number_suffix(my_shares),
            total_sh = format_number_suffix(total_shares),
            ledger = ledger_de,
            paid = format_sats(total_paid),
        ),
        Language::En => format!(
            "PPLNS status — {trimmed}\n\
            Window share: {percent:.2}%\n\
            Your hashrate: {my_h}\n\
            PPLNS hashrate (total): {pool_h}\n\
            Your shares: {my_sh}\n\
            Pool shares (window): {total_sh}\n\
            Active miners in window: {miner_count}\n\
            Ledger: {ledger}\n\
            Lifetime paid: {paid} sats",
            my_h = format_hashrate_th(my_hashrate),
            pool_h = format_hashrate_th(total_pplns_hashrate),
            my_sh = format_number_suffix(my_shares),
            total_sh = format_number_suffix(total_shares),
            ledger = ledger_en,
            paid = format_sats(total_paid),
        ),
    }
}

// ── /pplns_top ───────────────────────────────────────────────────────

pub(super) async fn build_pplns_top(pplns: &Arc<PplnsEngine>, lang: Language) -> String {
    let distribution = match pplns.reader().current_distribution().await {
        Ok(d) => d,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "pplns_top");
            return engine_error_text(lang);
        }
    };
    if distribution.is_empty() {
        return match lang {
            Language::De => "Keine Shares im aktuellen PPLNS-Window.".to_string(),
            Language::En => "No shares in the current PPLNS window.".to_string(),
        };
    }
    let total = distribution.len();
    let top = &distribution[..distribution.len().min(10)];
    let mut lines: Vec<String> = Vec::with_capacity(top.len());
    for (idx, entry) in top.iter().enumerate() {
        lines.push(format!(
            "{idx:>2}. {addr}   {pct:.2}%",
            idx = idx + 1,
            addr = format_address_short(&entry.address),
            pct = entry.percent,
        ));
    }
    let body = lines.join("\n");
    match lang {
        Language::De => format!("Top 10 PPLNS-Miner (von {total} aktiven):\n{body}"),
        Language::En => format!("Top 10 PPLNS miners (out of {total} active):\n{body}"),
    }
}

// ── /group_status <address> ──────────────────────────────────────────

pub(super) async fn build_group_status(
    pool: &PgPool,
    group_solo: &Arc<GroupSoloEngine>,
    lang: Language,
    address: &AddressId,
) -> String {
    let member = match find_group_member_by_address(pool, address).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_status: member lookup");
            return db_error_text(lang);
        }
    };
    let Some(member) = member else {
        return not_in_group_text(lang, address.as_str());
    };
    let group_id = member.group_id;

    let reader = group_solo.reader();
    let (group_res, members_res, round_res, best_res) = tokio::join!(
        find_group(pool, group_id),
        find_pplns_group_members_for_group(pool, group_id),
        reader.round_stats(group_id),
        reader.best_difficulty(group_id),
    );

    let group = match group_res {
        Ok(Some(g)) => g,
        Ok(None) => return group_unavailable_text(lang),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_status: group");
            return db_error_text(lang);
        }
    };
    let members = match members_res {
        Ok(m) => m,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_status: members");
            return db_error_text(lang);
        }
    };
    let round = match round_res {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_status: round");
            return engine_error_text(lang);
        }
    };
    let best = match best_res {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_status: best");
            return engine_error_text(lang);
        }
    };

    let member_addresses: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
    let group_hashrate = if member_addresses.is_empty() {
        0.0
    } else {
        sum_hashrate_for_addresses(pool, &member_addresses)
            .await
            .unwrap_or(0.0)
    };

    let my_shares = round
        .per_address
        .get(address.as_str())
        .copied()
        .unwrap_or(0.0);
    let my_percent = if round.total_shares > 0.0 {
        (my_shares / round.total_shares) * 100.0
    } else {
        0.0
    };
    let total_shares = round.total_shares;
    let total_rejected = round.total_rejected;
    let active_count = round.per_address.len();

    let best_diff_str = match best {
        Some(b) if b.difficulty > 0.0 => format!(
            "{} ({})",
            format_number_suffix(b.difficulty),
            format_address_short(&b.address)
        ),
        _ => "—".to_string(),
    };

    match lang {
        Language::De => format!(
            "Gruppe: {name}\n\
            Aktive Miner (Round): {active_count}\n\
            Gruppen-Hashrate: {group_h}\n\
            Dein Anteil: {pct:.2}% ({my_sh})\n\
            Round-Shares gesamt: {total_sh}\n\
            Round-Rejected: {rej_sh}\n\
            Beste Round-Difficulty: {best_diff_str}",
            name = group.name,
            group_h = format_hashrate_th(group_hashrate),
            pct = my_percent,
            my_sh = format_number_suffix(my_shares),
            total_sh = format_number_suffix(total_shares),
            rej_sh = format_number_suffix(total_rejected),
        ),
        Language::En => format!(
            "Group: {name}\n\
            Active miners (round): {active_count}\n\
            Group hashrate: {group_h}\n\
            Your share: {pct:.2}% ({my_sh})\n\
            Round shares total: {total_sh}\n\
            Round rejected: {rej_sh}\n\
            Best round difficulty: {best_diff_str}",
            name = group.name,
            group_h = format_hashrate_th(group_hashrate),
            pct = my_percent,
            my_sh = format_number_suffix(my_shares),
            total_sh = format_number_suffix(total_shares),
            rej_sh = format_number_suffix(total_rejected),
        ),
    }
}

// ── /group_members <address> ─────────────────────────────────────────

pub(super) async fn build_group_members(
    pool: &PgPool,
    group_solo: &Arc<GroupSoloEngine>,
    lang: Language,
    address: &AddressId,
) -> String {
    let member = match find_group_member_by_address(pool, address).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_members: member");
            return db_error_text(lang);
        }
    };
    let Some(member) = member else {
        return not_in_group_text(lang, address.as_str());
    };
    let group_id = member.group_id;

    let reader = group_solo.reader();
    let (group_res, members_res, round_res) = tokio::join!(
        find_group(pool, group_id),
        find_pplns_group_members_for_group(pool, group_id),
        reader.round_stats(group_id),
    );
    let group = match group_res {
        Ok(Some(g)) => g,
        Ok(None) => return group_unavailable_text(lang),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_members: group");
            return db_error_text(lang);
        }
    };
    let mut members = match members_res {
        Ok(m) => m,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_members: members");
            return db_error_text(lang);
        }
    };
    let round = match round_res {
        Ok(r) => r,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_members: round");
            return engine_error_text(lang);
        }
    };

    // Compute percent per member from round.per_address share-counts.
    let percent_for = |addr: &str| -> Option<f64> {
        round.per_address.get(addr).map(|s| {
            if round.total_shares > 0.0 {
                (s / round.total_shares) * 100.0
            } else {
                0.0
            }
        })
    };
    // Descending sort by share percent; missing entries sort last.
    members.sort_by(|a, b| {
        let pa = percent_for(a.address.as_str()).unwrap_or(-1.0);
        let pb = percent_for(b.address.as_str()).unwrap_or(-1.0);
        pb.partial_cmp(&pa).unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut lines_de: Vec<String> = Vec::with_capacity(members.len());
    let mut lines_en: Vec<String> = Vec::with_capacity(members.len());
    for m in &members {
        let pct_str = match percent_for(m.address.as_str()) {
            Some(p) => format!("{p:.2}%"),
            None => "—".to_string(),
        };
        let trimmed = format_address_short(m.address.as_str());
        let me = m.address == address.clone();
        lines_de.push(format!(
            "{trimmed}   {pct_str}{marker}",
            marker = if me { " (du)" } else { "" }
        ));
        lines_en.push(format!(
            "{trimmed}   {pct_str}{marker}",
            marker = if me { " (you)" } else { "" }
        ));
    }
    let count = members.len();
    match lang {
        Language::De => format!(
            "Mitglieder von \"{name}\" ({count}):\n{body}",
            name = group.name,
            body = lines_de.join("\n"),
        ),
        Language::En => format!(
            "Members of \"{name}\" ({count}):\n{body}",
            name = group.name,
            body = lines_en.join("\n"),
        ),
    }
}

// ── /show_workers <address> ──────────────────────────────────────────

pub(crate) async fn build_show_workers(
    pool: &PgPool,
    lang: Language,
    address: &AddressId,
) -> String {
    let workers = match find_clients_by_address(pool, address).await {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "show_workers: clients");
            return db_error_text(lang);
        }
    };
    if workers.is_empty() {
        return match lang {
            Language::De => format!(
                "Keine aktiven Worker für {addr} gefunden.",
                addr = format_address_short(address.as_str())
            ),
            Language::En => format!(
                "No active workers found for {addr}.",
                addr = format_address_short(address.as_str())
            ),
        };
    }
    let settings = match find_address_settings(pool, address).await {
        Ok(s) => s,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "show_workers: address_settings");
            return db_error_text(lang);
        }
    };
    let total_hashrate: f64 = workers.iter().map(|w| w.hash_rate).sum();
    let total_shares = settings.as_ref().map(|s| s.shares).unwrap_or(0.0);
    let best_diff_total = settings.as_ref().map(|s| s.best_difficulty);
    let best_diff_str = best_diff_total
        .map(format_number_suffix)
        .unwrap_or_else(|| "–".to_string());
    let workers_count = workers.len();
    let hashrate_str = format_number_suffix(total_hashrate);
    let shares_str = format_number_suffix(total_shares);

    let summary_de = [
        "\u{1f477} Worker-Übersicht".to_string(),
        format!("Gesamtanzahl: {workers_count}"),
        format!("Gesamt-Hashrate: {hashrate_str}H/s"),
        format!("Gesamt-Shares: {shares_str}"),
        format!("Beste Difficulty: {best_diff_str}"),
    ]
    .join("\n");
    let summary_en = [
        "\u{1f477} Workers overview".to_string(),
        format!("Total workers: {workers_count}"),
        format!("Total hashrate: {hashrate_str}H/s"),
        format!("Total shares: {shares_str}"),
        format!("Best difficulty: {best_diff_str}"),
    ]
    .join("\n");

    let mut worker_de: Vec<String> = Vec::with_capacity(workers.len());
    let mut worker_en: Vec<String> = Vec::with_capacity(workers.len());
    for (idx, w) in workers.iter().enumerate() {
        let name = if w.client_name.is_empty() {
            format!("Worker {n}", n = idx + 1)
        } else {
            w.client_name.clone()
        };
        let hr = format_number_suffix(w.hash_rate);
        let cur = w
            .current_difficulty
            .map(|d| format!("{d}"))
            .unwrap_or_else(|| "–".to_string());
        let best = format_number_suffix(w.best_difficulty as f64);
        worker_de.push(format!(
            "• {name}\nHashrate: {hr}H/s\nAktuelle Difficulty: {cur}\nBeste Difficulty: {best}"
        ));
        worker_en.push(format!(
            "• {name}\nHashrate: {hr}H/s\nCurrent difficulty: {cur}\nBest difficulty: {best}"
        ));
    }
    match lang {
        Language::De => {
            if worker_de.is_empty() {
                summary_de
            } else {
                format!("{summary_de}\n\n{}", worker_de.join("\n"))
            }
        }
        Language::En => {
            if worker_en.is_empty() {
                summary_en
            } else {
                format!("{summary_en}\n\n{}", worker_en.join("\n"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_pool_hashrate_two_decimals_th() {
        assert_eq!(
            format_pool_hashrate(Language::De, 12_500_000_000_000.0),
            "Aktuelle Pool-Hashrate: 12.50 TH/s"
        );
        assert_eq!(
            format_pool_hashrate(Language::En, 1_000_000_000_000.0),
            "Current pool hashrate: 1.00 TH/s"
        );
    }

    #[test]
    fn format_pool_hashrate_zero() {
        assert_eq!(
            format_pool_hashrate(Language::De, 0.0),
            "Aktuelle Pool-Hashrate: 0.00 TH/s"
        );
    }

    #[test]
    fn format_current_difficulty_t_unit() {
        assert_eq!(
            format_current_difficulty(Language::De, 158_000_000_000_000.0),
            "Aktuelle Difficulty: 158.00 T"
        );
        assert_eq!(
            format_current_difficulty(Language::En, 50_000_000_000_000.0),
            "Current difficulty: 50.00 T"
        );
    }

    #[test]
    fn format_next_adjustment_positive_change() {
        let adj = NextDifficultyAdjustment {
            progress_percent: 42.5,
            difficulty_change: 3.21,
            estimated_retarget_date_ms: 1_780_000_000_000, // 2026-06-04T11:06:40 UTC roughly
        };
        let out = format_next_adjustment(Language::De, &adj);
        assert!(out.contains("\u{1f4ca}"));
        assert!(out.contains("Fortschritt: 42.50%"));
        assert!(out.contains("\u{1f4c8} +3.21%"));
        assert!(out.contains("UTC"));
    }

    #[test]
    fn format_next_adjustment_negative_change() {
        let adj = NextDifficultyAdjustment {
            progress_percent: 12.0,
            difficulty_change: -2.0,
            estimated_retarget_date_ms: 1_780_000_000_000,
        };
        let out = format_next_adjustment(Language::En, &adj);
        assert!(out.contains("Progress: 12.00%"));
        assert!(out.contains("\u{1f4c9} -2.00%"));
        assert!(out.contains("Expected change"));
    }

    #[test]
    fn format_address_short_keeps_first_4_last_5() {
        assert_eq!(
            format_address_short("bc1q1234567890abcdefxyz"),
            "bc1q...efxyz"
        );
    }

    #[test]
    fn format_sats_en_us_separators() {
        assert_eq!(format_sats(0), "0");
        assert_eq!(format_sats(1), "1");
        assert_eq!(format_sats(1_234), "1,234");
        assert_eq!(format_sats(12_345), "12,345");
        assert_eq!(format_sats(123_456), "123,456");
        assert_eq!(format_sats(1_234_567), "1,234,567");
        assert_eq!(format_sats(-1_234), "-1,234");
    }

    #[test]
    fn format_hashrate_th_two_decimals() {
        assert_eq!(format_hashrate_th(0.0), "0.00 TH/s");
        assert_eq!(format_hashrate_th(1.0e12), "1.00 TH/s");
        assert_eq!(format_hashrate_th(12_500_000_000_000.0), "12.50 TH/s");
    }

    #[test]
    fn group_unavailable_text_per_language() {
        assert_eq!(
            group_unavailable_text(Language::De),
            "Gruppe nicht mehr verfügbar."
        );
        assert_eq!(
            group_unavailable_text(Language::En),
            "Group is no longer available."
        );
    }

    #[test]
    fn engine_error_text_per_language() {
        assert!(engine_error_text(Language::De).contains("Engine-Fehler"));
        assert!(engine_error_text(Language::En).contains("Engine error"));
    }
}
