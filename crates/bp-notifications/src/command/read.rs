// SPDX-License-Identifier: AGPL-3.0-or-later

//! Read-style bot commands. The engine-backed ones ([`build_pplns_status`],
//! [`build_group_status`], ...) take optional engine handles and answer
//! "not configured" when that engine was not wired in at startup.

use std::sync::Arc;
use std::time::Duration;

use bp_blockparty::BlockpartyStatus;
use bp_client_live::{hashrate_for_addresses, pool_hashrate};
use bp_common::{short_address, AddressId};
use bp_db::{
    find_address_settings, find_address_settings_for_addresses, find_blockparty_group,
    find_blockparty_member_by_address, find_clients_by_address, find_group,
    find_group_member_by_address, find_pplns_group_members_for_group,
    find_recent_group_block_history, list_blockparty_block_history,
    list_blockparty_members_for_group, PplnsGroupBlockHistoryRow,
};
use bp_group_solo_engine::engine::GroupSoloEngine;
use bp_pplns_engine::engine::PplnsEngine;
use chrono::{DateTime, Utc};
use redis::aio::ConnectionManager;
use reqwest::Client;
use serde::Deserialize;
use sqlx::PgPool;
use tracing::warn;

use crate::format::html::{addr, bold, esc, row, title, title_for};
use crate::format::{format_number_suffix, format_sats, Language};

const MEMPOOL_CURRENT_DIFF: &str = "https://mempool.space/api/v1/mining/hashrate/3d";
const MEMPOOL_NEXT_ADJUST: &str = "https://mempool.space/api/v1/difficulty-adjustment";

// ── HTTP client for the mempool.space-backed read commands (5 s timeout).

fn default_http_client() -> Client {
    bp_http::client_builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("default reqwest Client build")
}

// ── /poolhashrate ────────────────────────────────────────────────────

pub(super) async fn build_pool_hashrate(
    redis: Option<&ConnectionManager>,
    lang: Language,
) -> String {
    match pool_hashrate(redis).await {
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
    let th = format_hashrate_th(total_h_per_s);
    match lang {
        Language::De => format!("{}\n{}", title(None, "Pool-Hashrate"), row("Aktuell", &th)),
        Language::En => format!("{}\n{}", title(None, "Pool hashrate"), row("Current", &th)),
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
    let t = format!("{:.2} T", raw / 1e12);
    match lang {
        Language::De => format!(
            "{}\n{}",
            title(None, "Netzwerk-Difficulty"),
            row("Aktuell", &t)
        ),
        Language::En => format!(
            "{}\n{}",
            title(None, "Network difficulty"),
            row("Current", &t)
        ),
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
        format!("+{:.2} %", adj.difficulty_change)
    } else {
        format!("{:.2} %", adj.difficulty_change)
    };
    let dt = DateTime::<Utc>::from_timestamp_millis(adj.estimated_retarget_date_ms)
        .unwrap_or_else(|| DateTime::<Utc>::from_timestamp(0, 0).unwrap());
    // dd.MM.yyyy HH:mm UTC — seconds dropped for tighter bot output;
    // the UTC suffix makes the timezone unambiguous.
    let when = dt.format("%d.%m.%Y, %H:%M UTC").to_string();
    let progress = format!("{:.2} %", adj.progress_percent);
    match lang {
        Language::De => [
            title(None, "Nächste Difficulty-Anpassung"),
            row("Fortschritt", &progress),
            row("Geschätzt", &when),
            row("Erwartete Änderung", &change_text),
        ]
        .join("\n"),
        Language::En => [
            title(None, "Next difficulty adjustment"),
            row("Progress", &progress),
            row("Estimated", &when),
            row("Expected change", &change_text),
        ]
        .join("\n"),
    }
}

/// Live fields for a worker list, positionally aligned. Redis trouble
/// degrades to zeros rather than an error reply, since the durable half of
/// the message is still worth sending.
async fn live_fields_for_workers(
    redis: Option<&ConnectionManager>,
    workers: &[bp_db::ClientRow],
) -> Vec<Option<bp_client_live::LiveFields>> {
    match bp_client_live::live_fields_for_sessions(redis, workers).await {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "live fields lookup");
            vec![None; workers.len()]
        }
    }
}

// ── /stats <address> ─────────────────────────────────────────────────

pub(crate) async fn build_stats(
    pool: &PgPool,
    redis: Option<&ConnectionManager>,
    lang: Language,
    address: &AddressId,
) -> String {
    let workers = match find_clients_by_address(pool, address).await {
        Ok(v) => v,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "stats: clients lookup");
            return db_error_text(lang);
        }
    };
    if workers.is_empty() {
        return no_workers_text(lang, address);
    }
    let live = live_fields_for_workers(redis, &workers).await;
    let total_hashrate: f64 = live.iter().flatten().map(|lf| lf.hash_rate).sum();
    let total_th = format_hashrate_th(total_hashrate);
    let now_ms = Utc::now().timestamp_millis();
    // Freshness = the freshest accepted share across the address's live
    // hashes; a session without one falls back to its start.
    let freshest = live
        .iter()
        .flatten()
        .filter_map(|lf| lf.updated_at_ms)
        .max()
        .or_else(|| workers.iter().map(|w| w.start_time).max())
        .unwrap_or(now_ms);
    let last_seen_seconds = ((now_ms - freshest).max(0) / 1000) as i64;

    let settings = match find_address_settings(pool, address).await {
        Ok(opt) => opt,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "stats: address_settings");
            return db_error_text(lang);
        }
    };
    let total_shares = settings.as_ref().map(|r| r.shares).unwrap_or(0.0);
    let best_diff_raw = settings.as_ref().map(|r| r.best_difficulty).unwrap_or(0.0);
    let short = short_address(address.as_str());
    let shares = format_number_suffix(total_shares);
    let best = format_number_suffix(best_diff_raw);

    match lang {
        Language::De => [
            title_for(None, "Stats", &short),
            row("Hashrate", &total_th),
            row("Shares", &shares),
            row("Letzter Share", &format!("vor {last_seen_seconds} s")),
            row("Beste Difficulty", &best),
        ]
        .join("\n"),
        Language::En => [
            title_for(None, "Stats", &short),
            row("Hashrate", &total_th),
            row("Shares", &shares),
            row("Last share", &format!("{last_seen_seconds} s ago")),
            row("Best difficulty", &best),
        ]
        .join("\n"),
    }
}

// ── /team_history <address> ─────────────────────────────────────────

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
                Language::De => "Team nicht mehr verfügbar.".to_string(),
                Language::En => "Team is no longer available.".to_string(),
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
    let short = short_address(address.as_str());
    if mine.is_empty() {
        return match lang {
            Language::De => format!(
                "Keine Auszahlungen für {} im Team {}.",
                addr(&short),
                bold(&group.name)
            ),
            Language::En => format!(
                "No payouts for {} in the Team {}.",
                addr(&short),
                bold(&group.name)
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
            "Block {} · {} · {}",
            bold(&entry.block_height.to_string()),
            esc(&when),
            bold(&format!("{amount} sats")),
        ));
    }
    let head = match lang {
        Language::De => format!(
            "{}\nTeam {}",
            title_for(None, "Letzte Auszahlungen", &short),
            bold(&group.name)
        ),
        Language::En => format!(
            "{}\nTeam {}",
            title_for(None, "Recent payouts", &short),
            bold(&group.name)
        ),
    };
    format!("{head}\n\n{}", lines.join("\n"))
}

// ── Local helpers ─────────────────────────────────────────────────────────────────────

fn db_error_text(lang: Language) -> String {
    match lang {
        Language::De => "Datenbank-Fehler, bitte später noch einmal versuchen.".to_string(),
        Language::En => "Database error, please try again later.".to_string(),
    }
}

fn not_in_group_text(lang: Language, address: &str) -> String {
    let short = addr(&short_address(address));
    match lang {
        Language::De => format!("{short} ist in keinem Team."),
        Language::En => format!("{short} is not in any Team."),
    }
}

fn group_unavailable_text(lang: Language) -> String {
    match lang {
        Language::De => "Team nicht mehr verfügbar.".to_string(),
        Language::En => "Team is no longer available.".to_string(),
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
    redis: Option<&ConnectionManager>,
    pplns: &Arc<PplnsEngine>,
    lang: Language,
    address: &AddressId,
) -> String {
    let reader = pplns.reader();

    let (status, window, distribution, my_hash) = tokio::join!(
        reader.address_status(address.as_str()),
        reader.window_stats(),
        reader.current_distribution(),
        hashrate_for_addresses(redis, std::slice::from_ref(address)),
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
        hashrate_for_addresses(redis, &pplns_addresses)
            .await
            .unwrap_or_else(|e| {
                warn!(target: "bp_notifications::command::read", error = %e, "pplns_status: pool hashrate");
                0.0
            })
    };

    let trimmed = short_address(address.as_str());
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

    let sats = |v: i64| format!("{} sats", format_sats(v));
    let ledger_note = match (lang, balance.cmp(&0)) {
        (Language::De, std::cmp::Ordering::Greater) => " (Pool schuldet dir)",
        (Language::De, std::cmp::Ordering::Less) => {
            " (du schuldest dem Pool, wird mit der nächsten Auszahlung verrechnet)"
        }
        (Language::En, std::cmp::Ordering::Greater) => " (pool owes you)",
        (Language::En, std::cmp::Ordering::Less) => {
            " (you owe the pool, settled at the next payout)"
        }
        (_, std::cmp::Ordering::Equal) => "",
    };
    let my_h = format_hashrate_th(my_hashrate);
    let pool_h = format_hashrate_th(total_pplns_hashrate);
    let my_sh = format_number_suffix(my_shares);
    let total_sh = format_number_suffix(total_shares);
    let pct = format!("{percent:.2} %");
    let miners = miner_count.to_string();

    match lang {
        Language::De => [
            title_for(None, "PPLNS", &trimmed),
            row("Window-Anteil", &pct),
            row("Deine Hashrate", &my_h),
            row("PPLNS-Hashrate gesamt", &pool_h),
            row("Deine Shares", &my_sh),
            row("Shares im Window", &total_sh),
            row("Aktive Miner im Window", &miners),
            format!("{}{ledger_note}", row("Saldo", &sats(balance))),
            row("Insgesamt ausbezahlt", &sats(total_paid)),
        ]
        .join("\n"),
        Language::En => [
            title_for(None, "PPLNS", &trimmed),
            row("Window share", &pct),
            row("Your hashrate", &my_h),
            row("PPLNS hashrate total", &pool_h),
            row("Your shares", &my_sh),
            row("Shares in the window", &total_sh),
            row("Active miners in the window", &miners),
            format!("{}{ledger_note}", row("Balance", &sats(balance))),
            row("Paid in total", &sats(total_paid)),
        ]
        .join("\n"),
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
            "{}. {} {}",
            idx + 1,
            addr(&short_address(&entry.address)),
            bold(&format!("{:.2} %", entry.percent)),
        ));
    }
    let body = lines.join("\n");
    match lang {
        Language::De => format!(
            "{} (von {total} aktiven)\n\n{body}",
            title(None, "Top 10 im PPLNS-Window")
        ),
        Language::En => format!(
            "{} (out of {total} active)\n\n{body}",
            title(None, "Top 10 in the PPLNS window")
        ),
    }
}

// ── /team_status <address> ──────────────────────────────────────────

pub(super) async fn build_group_status(
    pool: &PgPool,
    redis: Option<&ConnectionManager>,
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
    let (group_res, members_res, round_res) = tokio::join!(
        find_group(pool, group_id),
        find_pplns_group_members_for_group(pool, group_id),
        reader.round_stats(group_id),
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

    let member_addresses: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
    let group_hashrate = if member_addresses.is_empty() {
        0.0
    } else {
        hashrate_for_addresses(redis, &member_addresses)
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

    // The highest all-time best among the members, as the dashboard shows
    // it for the Team.
    let member_strings: Vec<String> = member_addresses
        .iter()
        .map(|a| a.as_str().to_string())
        .collect();
    let best = match find_address_settings_for_addresses(pool, &member_strings).await {
        Ok(rows) => rows
            .into_iter()
            .filter(|r| r.best_difficulty > 0.0)
            .max_by(|a, b| a.best_difficulty.total_cmp(&b.best_difficulty)),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "group_status: member bests");
            return db_error_text(lang);
        }
    };
    let best_line = |label: &str| match &best {
        Some(b) => format!(
            "{} ({})",
            row(label, &format_number_suffix(b.best_difficulty)),
            addr(&short_address(b.address.as_str()))
        ),
        None => row(label, "—"),
    };

    let short = short_address(address.as_str());
    let head = |word: &str| format!("{} {}", bold(word), bold(&group.name));
    let group_h = format_hashrate_th(group_hashrate);
    let share = format!("{my_percent:.2} %");
    let my_sh = format_number_suffix(my_shares);
    let total_sh = format_number_suffix(total_shares);
    let rej_sh = format_number_suffix(total_rejected);
    let active = active_count.to_string();
    match lang {
        Language::De => [
            head("Team"),
            format!("Adresse: {}", addr(&short)),
            String::new(),
            row("Aktive Miner in der Runde", &active),
            row("Team-Hashrate", &group_h),
            format!("{} ({my_sh} Shares)", row("Dein Anteil", &share)),
            row("Shares in der Runde", &total_sh),
            row("Abgelehnt in der Runde", &rej_sh),
            best_line("Beste Difficulty im Team"),
        ]
        .join("\n"),
        Language::En => [
            head("Team"),
            format!("Address: {}", addr(&short)),
            String::new(),
            row("Active miners this round", &active),
            row("Team hashrate", &group_h),
            format!("{} ({my_sh} shares)", row("Your share", &share)),
            row("Shares this round", &total_sh),
            row("Rejected this round", &rej_sh),
            best_line("Best difficulty in the Team"),
        ]
        .join("\n"),
    }
}

// ── /blockparty_status <address> ────────────────────────────────────

pub(super) async fn build_blockparty_status(
    pool: &PgPool,
    redis: Option<&ConnectionManager>,
    lang: Language,
    address: &AddressId,
) -> String {
    let short = short_address(address.as_str());
    let not_in_party = || match lang {
        Language::De => format!("{} ist in keiner Blockparty.", addr(&short)),
        Language::En => format!("{} is not in any Blockparty.", addr(&short)),
    };
    let member = match find_blockparty_member_by_address(pool, address).await {
        Ok(Some(m)) => m,
        Ok(None) => return not_in_party(),
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "blockparty_status: member");
            return db_error_text(lang);
        }
    };
    let (group_res, members_res, history_res) = tokio::join!(
        find_blockparty_group(pool, member.group_id),
        list_blockparty_members_for_group(pool, member.group_id),
        list_blockparty_block_history(pool, member.group_id),
    );
    let (group, members, history) = match (group_res, members_res, history_res) {
        (Ok(Some(g)), Ok(m), Ok(h)) => (g, m, h),
        (Ok(None), _, _) => return not_in_party(),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
            warn!(target: "bp_notifications::command::read", error = %e, "blockparty_status: group");
            return db_error_text(lang);
        }
    };
    let status = match group.status.parse::<BlockpartyStatus>() {
        Ok(BlockpartyStatus::Dissolved) => return not_in_party(),
        Ok(status) => blockparty_status_name(lang, status),
        Err(_) => group.status.clone(),
    };
    let addresses: Vec<AddressId> = members.iter().map(|m| m.address.clone()).collect();
    let hashrate = hashrate_for_addresses(redis, &addresses)
        .await
        .unwrap_or(0.0);
    let pct = f64::from(member.percent_bp) / 100.0;
    let confirmed = match (lang, member.confirmed_at.is_some()) {
        (Language::De, true) => "bestätigt",
        (Language::De, false) => "noch nicht bestätigt",
        (Language::En, true) => "confirmed",
        (Language::En, false) => "not confirmed yet",
    };
    let last_block = history.first().map(|block| {
        let mine: i64 = block
            .splits
            .iter()
            .filter(|s| s.address == address.as_str())
            .map(|s| s.sats)
            .sum();
        (block.block_height, format_sats(mine))
    });
    let head = format!(
        "{} {} ({})",
        bold("Blockparty"),
        bold(&group.name),
        esc(&status)
    );
    let share = format!("{pct:.2} %");
    let count = members.len().to_string();
    let hashrate = format_hashrate_th(hashrate);
    let found = history.len().to_string();
    let mut lines = match lang {
        Language::De => vec![
            head,
            format!("Adresse: {}", addr(&short)),
            String::new(),
            format!("{} ({confirmed})", row("Dein Anteil", &share)),
            row("Mitglieder", &count),
            row("Hashrate", &hashrate),
            row("Gefundene Blöcke", &found),
        ],
        Language::En => vec![
            head,
            format!("Address: {}", addr(&short)),
            String::new(),
            format!("{} ({confirmed})", row("Your share", &share)),
            row("Members", &count),
            row("Hashrate", &hashrate),
            row("Blocks found", &found),
        ],
    };
    if let Some((height, sats)) = last_block {
        lines.push(match lang {
            Language::De => format!(
                "Letzter Block: {}, für dich {}",
                bold(&height.to_string()),
                bold(&format!("{sats} sats"))
            ),
            Language::En => format!(
                "Last block: {}, {} for you",
                bold(&height.to_string()),
                bold(&format!("{sats} sats"))
            ),
        });
    }
    lines.join("\n")
}

fn blockparty_status_name(lang: Language, status: BlockpartyStatus) -> String {
    let name = match (lang, status) {
        (Language::De, BlockpartyStatus::Draft) => "Entwurf",
        (Language::De, BlockpartyStatus::Confirming) => "wartet auf Bestätigung",
        (Language::De, BlockpartyStatus::Ready) => "bereit",
        (Language::De, BlockpartyStatus::Active) => "aktiv",
        (Language::De, BlockpartyStatus::Dissolved) => "aufgelöst",
        (Language::En, BlockpartyStatus::Draft) => "draft",
        (Language::En, BlockpartyStatus::Confirming) => "waiting for confirmation",
        (Language::En, BlockpartyStatus::Ready) => "ready",
        (Language::En, BlockpartyStatus::Active) => "active",
        (Language::En, BlockpartyStatus::Dissolved) => "dissolved",
    };
    name.to_string()
}

// ── /team_members <address> ─────────────────────────────────────────

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
        let trimmed = addr(&short_address(m.address.as_str()));
        let pct = bold(&pct_str);
        let me = m.address == address.clone();
        lines_de.push(format!(
            "{trimmed} {pct}{marker}",
            marker = if me { " (du)" } else { "" }
        ));
        lines_en.push(format!(
            "{trimmed} {pct}{marker}",
            marker = if me { " (you)" } else { "" }
        ));
    }
    let count = members.len();
    match lang {
        Language::De => format!(
            "{} {} ({count})\nAnteil an der Runde\n\n{}",
            bold("Mitglieder von"),
            bold(&group.name),
            lines_de.join("\n"),
        ),
        Language::En => format!(
            "{} {} ({count})\nShare of the round\n\n{}",
            bold("Members of"),
            bold(&group.name),
            lines_en.join("\n"),
        ),
    }
}

// ── /show_workers <address> ──────────────────────────────────────────

pub(crate) async fn build_show_workers(
    pool: &PgPool,
    redis: Option<&ConnectionManager>,
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
        return no_workers_text(lang, address);
    }
    let settings = match find_address_settings(pool, address).await {
        Ok(s) => s,
        Err(e) => {
            warn!(target: "bp_notifications::command::read", error = %e, "show_workers: address_settings");
            return db_error_text(lang);
        }
    };
    let live = live_fields_for_workers(redis, &workers).await;
    let total_hashrate: f64 = live.iter().flatten().map(|lf| lf.hash_rate).sum();
    let total_shares = settings.as_ref().map(|s| s.shares).unwrap_or(0.0);
    let best_diff_str = settings
        .as_ref()
        .map(|s| format_number_suffix(s.best_difficulty))
        .unwrap_or_else(|| "–".to_string());
    let count = workers.len().to_string();
    let hashrate = format_hashrate_th(total_hashrate);
    let shares = format_number_suffix(total_shares);
    let short = short_address(address.as_str());

    let mut blocks = vec![match lang {
        Language::De => [
            title_for(None, "Worker", &short),
            row("Anzahl", &count),
            row("Hashrate", &hashrate),
            row("Shares", &shares),
            row("Beste Difficulty", &best_diff_str),
        ]
        .join("\n"),
        Language::En => [
            title_for(None, "Workers", &short),
            row("Count", &count),
            row("Hashrate", &hashrate),
            row("Shares", &shares),
            row("Best difficulty", &best_diff_str),
        ]
        .join("\n"),
    }];
    for (idx, (w, lf)) in workers.iter().zip(&live).enumerate() {
        let name = if w.client_name.is_empty() {
            format!("Worker {n}", n = idx + 1)
        } else {
            w.client_name.clone()
        };
        let lf = lf.clone().unwrap_or_default();
        let hr = format_hashrate_th(lf.hash_rate);
        let cur = lf
            .current_difficulty
            .map(|d| format!("{d}"))
            .unwrap_or_else(|| "–".to_string());
        let best = format_number_suffix(w.best_difficulty);
        blocks.push(match lang {
            Language::De => [
                bold(&name),
                row("Hashrate", &hr),
                row("Aktuelle Difficulty", &cur),
                row("Beste Difficulty", &best),
            ]
            .join("\n"),
            Language::En => [
                bold(&name),
                row("Hashrate", &hr),
                row("Current difficulty", &cur),
                row("Best difficulty", &best),
            ]
            .join("\n"),
        });
    }
    blocks.join("\n\n")
}

fn no_workers_text(lang: Language, address: &AddressId) -> String {
    let short = addr(&short_address(address.as_str()));
    match lang {
        Language::De => format!("Keine aktiven Worker für {short}."),
        Language::En => format!("No active workers for {short}."),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::html::{is_valid_telegram_html, to_plain};

    /// The plain text of a reply, after checking Telegram takes its HTML.
    fn plain(html: &str) -> String {
        assert!(is_valid_telegram_html(html), "{html}");
        to_plain(html)
    }

    #[test]
    fn format_pool_hashrate_two_decimals_th() {
        assert_eq!(
            plain(&format_pool_hashrate(Language::De, 12_500_000_000_000.0)),
            "Pool-Hashrate\nAktuell: 12.50 TH/s"
        );
        assert_eq!(
            plain(&format_pool_hashrate(Language::En, 1_000_000_000_000.0)),
            "Pool hashrate\nCurrent: 1.00 TH/s"
        );
    }

    #[test]
    fn format_pool_hashrate_zero() {
        assert_eq!(
            plain(&format_pool_hashrate(Language::De, 0.0)),
            "Pool-Hashrate\nAktuell: 0.00 TH/s"
        );
    }

    #[test]
    fn format_current_difficulty_t_unit() {
        assert_eq!(
            plain(&format_current_difficulty(
                Language::De,
                158_000_000_000_000.0
            )),
            "Netzwerk-Difficulty\nAktuell: 158.00 T"
        );
        assert_eq!(
            plain(&format_current_difficulty(
                Language::En,
                50_000_000_000_000.0
            )),
            "Network difficulty\nCurrent: 50.00 T"
        );
    }

    #[test]
    fn format_next_adjustment_positive_change() {
        let adj = NextDifficultyAdjustment {
            progress_percent: 42.5,
            difficulty_change: 3.21,
            estimated_retarget_date_ms: 1_780_000_000_000,
        };
        let out = plain(&format_next_adjustment(Language::De, &adj));
        assert!(out.contains("Fortschritt: 42.50 %"), "{out}");
        assert!(out.contains("Erwartete Änderung: +3.21 %"), "{out}");
        assert!(out.contains("UTC"), "{out}");
    }

    #[test]
    fn format_next_adjustment_negative_change() {
        let adj = NextDifficultyAdjustment {
            progress_percent: 12.0,
            difficulty_change: -2.0,
            estimated_retarget_date_ms: 1_780_000_000_000,
        };
        let out = plain(&format_next_adjustment(Language::En, &adj));
        assert!(out.contains("Progress: 12.00 %"), "{out}");
        assert!(out.contains("Expected change: -2.00 %"), "{out}");
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
            "Team nicht mehr verfügbar."
        );
        assert_eq!(
            group_unavailable_text(Language::En),
            "Team is no longer available."
        );
    }

    #[test]
    fn engine_error_text_per_language() {
        assert!(engine_error_text(Language::De).contains("Engine-Fehler"));
        assert!(engine_error_text(Language::En).contains("Engine error"));
    }
}
