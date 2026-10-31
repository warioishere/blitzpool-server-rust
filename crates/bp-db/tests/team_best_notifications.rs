// SPDX-License-Identifier: AGPL-3.0-or-later

#![allow(clippy::print_stderr)]
#![allow(clippy::needless_return)]

//! Who follows a Team's round best.

use bp_common::AddressId;
use bp_db::{
    find_team_best_ntfy_recipients, find_team_best_telegram_recipients,
    find_telegram_subscriptions_by_chat, insert_pplns_group, insert_pplns_group_member,
    update_ntfy_sub_team_best_flag, update_pplns_group_dissolved,
    update_telegram_sub_team_best_flag, upsert_ntfy_subscription, upsert_telegram_subscription,
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const DEFAULT_URL: &str = "postgres://postgres:postgres@localhost:15433/public_pool";
const NAME_PREFIX: &str = "bp-test-teambest-";
/// Chats: both members of the Team, one member with the switch off, an
/// address in no Team, a member of the Team that is dissolved.
const CHAT_BOTH: i64 = 990_000_881;
const CHAT_OFF: i64 = 990_000_882;
const CHAT_OUTSIDER: i64 = 990_000_883;
const CHAT_DISSOLVED: i64 = 990_000_884;
const MEMBER_A: &str = "bc1q_teambest_member_a";
const MEMBER_B: &str = "bc1q_teambest_member_b";
const OUTSIDER: &str = "bc1q_teambest_outsider";
const DISSOLVED_MEMBER: &str = "bc1q_teambest_dissolved";

async fn connect_or_skip() -> Option<PgPool> {
    let url = std::env::var("BP_PG_URL").unwrap_or_else(|_| DEFAULT_URL.to_string());
    match tokio::time::timeout(
        std::time::Duration::from_secs(2),
        PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(std::time::Duration::from_secs(2))
            .connect(&url),
    )
    .await
    {
        Ok(Ok(p)) => Some(p),
        Ok(Err(e)) => {
            eprintln!("PG connect failed for {url}: {e} — skipping integration test");
            return None;
        }
        Err(_) => {
            eprintln!("PG connect timed out — skipping");
            return None;
        }
    }
}

async fn cleanup(pool: &PgPool) {
    let addresses = vec![MEMBER_A, MEMBER_B, OUTSIDER, DISSOLVED_MEMBER];

    sqlx::query(r#"DELETE FROM telegram_subscriptions_entity WHERE "telegramChatId" = ANY($1)"#)
        .bind(vec![CHAT_BOTH, CHAT_OFF, CHAT_OUTSIDER, CHAT_DISSOLVED])
        .execute(pool)
        .await
        .expect("cleanup telegram");
    sqlx::query("DELETE FROM ntfy_subscriptions_entity WHERE address = ANY($1)")
        .bind(&addresses)
        .execute(pool)
        .await
        .expect("cleanup ntfy");
    sqlx::query("DELETE FROM pplns_group_member WHERE address = ANY($1)")
        .bind(&addresses)
        .execute(pool)
        .await
        .expect("cleanup members");
    sqlx::query("DELETE FROM pplns_group WHERE name LIKE $1")
        .bind(format!("{NAME_PREFIX}%"))
        .execute(pool)
        .await
        .expect("cleanup groups");
}

fn addr(a: &str) -> AddressId {
    AddressId::new(a).unwrap()
}

async fn team(pool: &PgPool, members: &[&str]) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().timestamp_millis();
    insert_pplns_group(
        pool,
        id,
        &format!("{NAME_PREFIX}{id}"),
        &addr(members[0]),
        "hash",
        true,
        false,
        "prop",
        now,
    )
    .await
    .expect("group");
    for (i, m) in members.iter().enumerate() {
        let role = if i == 0 { "creator" } else { "member" };
        insert_pplns_group_member(pool, id, &addr(m), role, now)
            .await
            .expect("member");
    }
    id
}

async fn telegram_recipients(pool: &PgPool, groups: &[Uuid]) -> Vec<(Uuid, i64)> {
    let mut out: Vec<(Uuid, i64)> = find_team_best_telegram_recipients(pool)
        .await
        .expect("telegram recipients")
        .into_iter()
        .filter(|r| groups.contains(&r.group_id))
        .map(|r| (r.group_id, r.telegram_chat_id))
        .collect();
    out.sort();
    out
}

async fn ntfy_recipients(pool: &PgPool, groups: &[Uuid]) -> Vec<(Uuid, String)> {
    find_team_best_ntfy_recipients(pool)
        .await
        .expect("ntfy recipients")
        .into_iter()
        .filter(|r| groups.contains(&r.group_id))
        .map(|r| (r.group_id, r.address.as_str().to_string()))
        .collect()
}

#[tokio::test]
async fn a_teams_round_best_goes_to_each_following_chat_once() {
    let Some(pool) = connect_or_skip().await else {
        return;
    };
    cleanup(&pool).await;
    let active = team(&pool, &[MEMBER_A, MEMBER_B]).await;
    let dissolved = team(&pool, &[DISSOLVED_MEMBER]).await;
    let groups = [active, dissolved];

    for (chat, addresses) in [
        (CHAT_BOTH, vec![MEMBER_A, MEMBER_B]),
        (CHAT_OFF, vec![MEMBER_A]),
        (CHAT_OUTSIDER, vec![OUTSIDER]),
        (CHAT_DISSOLVED, vec![DISSOLVED_MEMBER]),
    ] {
        for a in addresses {
            upsert_telegram_subscription(&pool, chat, &addr(a))
                .await
                .expect("subscribe");
        }
    }
    // A new subscription starts with the switch on.
    let subs = find_telegram_subscriptions_by_chat(&pool, CHAT_BOTH)
        .await
        .expect("subs");
    assert_eq!(subs.len(), 2);
    assert!(subs.iter().all(|s| s.team_best_notifications_enabled));

    for a in [MEMBER_B, OUTSIDER, DISSOLVED_MEMBER] {
        upsert_ntfy_subscription(&pool, &addr(a))
            .await
            .expect("ntfy");
    }

    // Negative control: before the switch goes off and the Team dissolves,
    // CHAT_OFF and the dissolved Team's chat and topic follow too.
    assert_eq!(
        telegram_recipients(&pool, &groups).await.len(),
        3,
        "both member chats and the dissolved Team's chat, before any filter"
    );
    assert_eq!(ntfy_recipients(&pool, &groups).await.len(), 2);
    update_telegram_sub_team_best_flag(&pool, CHAT_OFF, &addr(MEMBER_A), false)
        .await
        .expect("switch off");
    // The write touches that switch alone.
    let off = &find_telegram_subscriptions_by_chat(&pool, CHAT_OFF)
        .await
        .expect("subs")[0];
    assert!(!off.team_best_notifications_enabled);
    assert!(off.best_diff_notifications_enabled && off.block_notifications_enabled);
    let now = chrono::Utc::now().timestamp_millis();
    update_pplns_group_dissolved(&pool, dissolved, now)
        .await
        .expect("dissolve");
    // Two members in one chat: one row. The switched-off chat, the address
    // in no Team and the dissolved Team: none.
    assert_eq!(
        telegram_recipients(&pool, &groups).await,
        vec![(active, CHAT_BOTH)]
    );

    // The address in no Team and the dissolved Team's topic: none.
    assert_eq!(
        ntfy_recipients(&pool, &groups).await,
        vec![(active, MEMBER_B.to_string())]
    );
    update_ntfy_sub_team_best_flag(&pool, &addr(MEMBER_B), false)
        .await
        .expect("ntfy off");
    assert!(ntfy_recipients(&pool, &groups).await.is_empty());

    cleanup(&pool).await;
}
