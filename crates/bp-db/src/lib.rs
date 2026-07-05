// SPDX-License-Identifier: AGPL-3.0-or-later

//! `sqlx`-based data layer against the existing Blitzpool Postgres schema
//! (see `db/schema.sql` for the canonical DDL).
//!
//! # Scope
//!
//! - Strongly-typed `Row` structs for every domain table — what comes back
//!   from a `SELECT *` materialises into Rust types that round-trip
//!   `Sats` ↔ BIGINT, `AddressId` ↔ VARCHAR, `MiningMode` ↔ kebab-case
//!   VARCHAR automatically.
//! - `Db` connection-pool wrapper + `DbError`.
//! - Module split by domain (see below) — no orchestration, no business
//!   logic, no caching.
//!
//! # API surface choice
//!
//! Each table module exposes a `find_<table>_by_pk(...)` async function —
//! this is universal (every consumer needs to look a row up by its key),
//! so it lands in the data layer up-front.
//!
//! **Anything beyond find_by_pk** (filtered, batched, time-windowed,
//! with-soft-delete, RETURNING-id INSERT, conditional UPSERT, …) has
//! multiple plausible signatures whose right shape only becomes clear at
//! the consumer site. Those are added 2-at-a-time as call sites
//! emerge (Design-Prinzip 9: extract abstractions on demand, never
//! speculatively). See `DEFERRED.md` for the running list.
//!
//! # SQL verification status
//!
//! Write queries and point-read queries use the compile-time `sqlx::query!`
//! / `sqlx::query_as!` macros backed by the `.sqlx` offline cache. A small
//! number of aggregate read queries (e.g. `find_user_agents`,
//! `find_found_blocks`) still use the runtime `query_as` form where the
//! projection is derived — those are type-checked at the `FromRow` boundary.

mod address;
mod block;
mod blockparty;
mod client;
mod email;
mod external;
mod group;
mod notification;
mod pool;
mod pool_stats;
mod pplns;
mod redis_backup;
mod stats_writes;

pub use pool::{Db, DbConfig, DbError};

pub use redis_backup::{
    fetch_redis_backup, insert_redis_backup, latest_redis_backup_captured_at,
    list_redis_backup_snapshots, prune_redis_backups_before, RedisBackupRow, RedisBackupSnapshot,
};

pub use address::{
    find_address_settings, find_best_difficulty_tracker,
    find_best_difficulty_trackers_for_addresses, find_high_scores,
    reset_address_settings_best_difficulty, upsert_best_difficulty_trackers, AddressSettingsRow,
    BestDifficultyTrackerRow, HighScoreRow,
};
pub use block::{
    delete_old_rpc_blocks, find_block, find_found_blocks, find_rpc_block, insert_found_block,
    BlocksRow, FoundBlockRow, RpcBlockRow,
};
pub use blockparty::{
    delete_blockparty_member, find_blockparty_group, find_blockparty_group_by_admin_address,
    find_blockparty_group_by_name, find_blockparty_invitation_by_token,
    find_blockparty_invitation_pending_for_group_address, find_blockparty_member_by_address,
    find_blockparty_member_in_group, insert_blockparty_block_history, insert_blockparty_group,
    insert_blockparty_invitation, insert_blockparty_member, list_all_blockparty_members,
    list_blockparty_block_history, list_blockparty_groups, list_blockparty_groups_non_dissolved,
    list_blockparty_invitations_for_group, list_blockparty_members_for_group,
    reset_blockparty_member_confirmations_non_admin, reset_blockparty_member_onboarding,
    update_blockparty_group_dissolved, update_blockparty_group_last_share_and_status,
    update_blockparty_group_rental_hint, update_blockparty_group_status,
    update_blockparty_invitation_status, update_blockparty_member_confirmed,
    update_blockparty_member_percent_bp, BlockpartyBlockHistoryRow, BlockpartyGroupRow,
    BlockpartyInvitationRow, BlockpartyMemberRow, BlockpartySplitSnapshot,
};
pub use client::{
    bulk_set_client_hashrate, bulk_touch_clients_for_share, delete_client_for_session,
    delete_old_client_difficulty_statistics, delete_old_client_rejected_statistics,
    delete_old_client_statistics, delete_old_clients, delete_old_pool_mode_hashrate, find_client,
    find_client_difficulty_statistics, find_client_recent_first_seen,
    find_client_rejected_statistics, find_client_rejected_statistics_since_for_address,
    find_client_statistics, find_client_statistics_since, find_client_statistics_since_for_address,
    find_clients_by_address, find_pool_worker_rows_since, find_user_agents, find_worker_shares,
    kill_dead_clients, sum_active_pool_hashrate, sum_hashrate_for_addresses, touch_client_for_share,
    update_sv2_user_agent_by_address, upsert_address_best_difficulty, upsert_client,
    upsert_client_difficulty_statistic, ClientDifficultyStatisticsRow, ClientRejectedStatisticsRow,
    ClientRow, ClientStatisticsRow, ClientUpsert, PoolWorkerRow, UserAgentAggRow, WorkerSharesRow,
};
pub use email::{
    delete_email_verification_by_token, delete_email_verifications_for_address,
    delete_expired_email_verifications, find_address_email, find_email_verification,
    insert_email_verification, upsert_address_email_verified, AddressEmailRow,
    EmailVerificationRow,
};
pub use external::{
    find_external_share, find_external_share_top_difficulties, insert_external_share,
    ExternalShareTopDifficulty, ExternalSharesRow,
};
pub use group::{
    add_pplns_group_balance_pending, bulk_insert_pplns_group_block_history,
    bulk_upsert_pplns_group_balances, count_pplns_group_join_requests_pending_for_address,
    count_pplns_group_members_for_group, delete_pplns_group_balance,
    delete_pplns_group_balances_for_group, delete_pplns_group_block_history_for_group,
    delete_pplns_group_invitation_by_token, delete_pplns_group_member,
    delete_pplns_group_members_for_group, expire_pending_pplns_group_invitations,
    expire_pending_pplns_group_join_requests, find_all_pplns_group_balances_for_group,
    find_all_pplns_group_member_addresses, find_all_pplns_group_members, find_group,
    find_group_balance, find_group_block_history, find_group_invitation, find_group_join_request,
    find_group_member, find_group_member_by_address, find_pplns_group_active_open_invite_for_group,
    find_pplns_group_balances_dormant, find_pplns_group_balances_for_group,
    find_pplns_group_by_name_not_dissolved, find_pplns_group_creator_member,
    find_pplns_group_invitation_pending_directed,
    find_pplns_group_invitations_pending_for_address_directed,
    find_pplns_group_invitations_pending_for_group_directed,
    find_pplns_group_join_request_most_recent_rejected,
    find_pplns_group_join_request_pending_in_group, find_pplns_group_member_in_group,
    find_pplns_group_members_for_group, find_recent_group_block_history, insert_pplns_group,
    insert_pplns_group_invitation, insert_pplns_group_join_request, insert_pplns_group_member,
    list_active_pplns_group_flags, list_active_pplns_groups,
    list_pplns_group_join_requests_for_group, list_pplns_group_join_requests_pending_for_address,
    revoke_pending_open_invites_for_group, update_pplns_group_active,
    update_pplns_group_balance_pending_sats, update_pplns_group_creator_and_admin_token,
    update_pplns_group_dissolved, update_pplns_group_invitation_status_by_token,
    update_pplns_group_join_request_decision, update_pplns_group_last_reset_at,
    update_pplns_group_member_role, update_pplns_group_round_reset_config, GroupBalanceUpsert,
    GroupPayoutHistoryInsert, PatchField, PplnsGroupBalanceRow, PplnsGroupBlockHistoryRow,
    PplnsGroupInvitationRow, PplnsGroupJoinRequestRow, PplnsGroupMemberRow, PplnsGroupRow,
    RoundResetConfigPatch,
};
pub use notification::{
    delete_ntfy_subscription_by_address, delete_push_subscription_by_endpoint,
    delete_push_subscription_by_endpoint_and_type, delete_push_subscriptions_by_address,
    delete_push_subscriptions_by_address_and_type, delete_stale_push_subscriptions,
    delete_telegram_subscription_by_chat_address, find_addresses_for_ntfy_listener,
    find_addresses_with_push_subscription, find_ntfy_subscription,
    find_ntfy_subscription_by_address, find_ntfy_subscriptions_with_hourly_enabled,
    find_push_subscription, find_push_subscriptions_by_address, find_telegram_subscription,
    find_telegram_subscriptions_by_address, find_telegram_subscriptions_by_chat,
    find_telegram_subscriptions_with_hourly_enabled, promote_telegram_default_if_none,
    set_telegram_default_subscription, set_telegram_hourly_flags, update_ntfy_sub_best_diff_flag,
    update_ntfy_sub_device_flag, update_ntfy_sub_hourly_flags, update_ntfy_sub_language,
    update_push_subscription_last_notification, update_push_subscription_preferences,
    update_telegram_sub_best_diff_flag, update_telegram_sub_device_flag,
    update_telegram_sub_hourly_flags, upsert_ntfy_subscription, upsert_push_subscription,
    upsert_telegram_subscription, NtfySubscriptionRow, PushSubscriptionRow,
    TelegramSubscriptionRow,
};
pub use pool_stats::{
    find_network_difficulty_tracker, find_pool_mode_hashrate, find_pool_mode_hashrate_since,
    find_pool_rejected_statistics, find_pool_rejected_statistics_since, find_pool_share_statistics,
    find_pool_share_statistics_since, upsert_network_difficulty_tracker,
    NetworkDifficultyTrackerRow, PoolModeHashrateRow, PoolRejectedStatisticsRow,
    PoolShareStatisticsRow,
};
pub use pplns::{
    aggregate_pplns_balances, bulk_insert_pplns_payout_history,
    bulk_update_pplns_last_accepted_share_at, bulk_upsert_pplns_balances, delete_pplns_balance,
    find_pplns_balance, find_pplns_balances_abandoned, find_pplns_balances_for_addresses,
    find_pplns_balances_with_open_balance, find_pplns_payout_history, update_pplns_balance_sats,
    BalanceUpsert, PayoutHistoryInsert, PplnsBalanceAggregate, PplnsBalanceRow,
    PplnsPayoutHistoryRow, TouchUpdate,
};
pub use stats_writes::{
    bulk_update_address_settings_shares, bulk_upsert_client_rejected_statistics_entity,
    bulk_upsert_client_statistics_entity, bulk_upsert_pool_mode_hashrate,
    bulk_upsert_pool_rejected_statistics, bulk_upsert_pool_share_statistics,
    bulk_upsert_worker_shares_entity, count_worker_shares,
    seed_worker_shares_from_client_statistics, AddressSharesUpdate, ClientRejectedStatsUpsert,
    ClientStatsUpsert, PoolModeHashrateUpsert, PoolRejectedStatsUpsert, PoolShareStatsUpsert,
    WorkerSharesUpsert,
};
