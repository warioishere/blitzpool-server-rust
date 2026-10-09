// SPDX-License-Identifier: AGPL-3.0-or-later

//! `sqlx` data layer over the Blitzpool Postgres schema, which
//! `crates/bp-db/migrations/` builds from an empty database. Typed rows and
//! queries only, split by domain: no orchestration, business logic or caching.
//! Queries are added when a call site needs them, never speculatively.

mod address;
mod address_ownership;
mod block;
mod blockparty;
mod client;
mod custom_extranonce;
mod email;
mod group;
mod notification;
mod pool;
mod pool_stats;
mod pplns;
mod redis_backup;
mod stats_writes;
mod text;

pub use pool::{with_boot_policy, Db, DbConfig, DbError};
pub use text::pg_text;

pub use redis_backup::{
    fetch_redis_backup, insert_redis_backup, latest_redis_backup_captured_at,
    list_redis_backup_snapshots, prune_redis_backups_before, RedisBackupRow, RedisBackupSnapshot,
};

pub use address::{
    find_address_settings, find_address_settings_for_addresses, find_best_difficulty_tracker,
    find_best_difficulty_trackers_for_addresses, find_high_scores,
    reset_address_settings_best_difficulty, upsert_best_difficulty_trackers, AddressSettingsRow,
    BestDifficultyTrackerRow, HighScoreRow,
};
pub use address_ownership::{
    addresses_with_ownership_proof, delete_ownership_challenge, find_address_ownership,
    find_ownership_challenge, is_address_ownership_verified, is_address_verified,
    upsert_address_ownership_verified, upsert_ownership_challenge, AddressOwnershipRow,
    OwnershipChallengeRow,
};
pub use block::{
    find_found_blocks, found_block_miner_at_height, insert_found_block, payout_recorded_at_height,
    FoundBlockRow,
};
pub use blockparty::{
    delete_blockparty_join_link, delete_blockparty_member, delete_blockparty_members_for_group,
    find_blockparty_group, find_blockparty_group_by_admin_address, find_blockparty_group_by_name,
    find_blockparty_join_link_by_token, find_blockparty_join_link_for_group,
    find_blockparty_member_by_address, find_blockparty_member_in_group,
    insert_blockparty_block_history, insert_blockparty_group, insert_blockparty_member,
    list_all_blockparty_members, list_blockparty_block_history,
    list_blockparty_groups_non_dissolved, list_blockparty_members_for_group,
    set_blockparty_confirmation_requested, update_blockparty_group_dissolved,
    update_blockparty_group_last_share_and_status, update_blockparty_group_rental_hint,
    update_blockparty_group_status, update_blockparty_member_confirmed,
    upsert_blockparty_join_link, BlockpartyBlockHistoryRow, BlockpartyGroupRow,
    BlockpartyJoinLinkRow, BlockpartyMemberRow, BlockpartySplitSnapshot,
};
pub use client::{
    bulk_upsert_clients, delete_client_for_session, delete_old_client_statistics,
    delete_old_clients, delete_old_pool_mode_hashrate, delete_old_pool_rejected_statistics,
    device_first_seen, device_watch_seed, find_active_session_keys,
    find_active_sessions_for_addresses, find_client, find_client_statistics_since_for_addresses,
    find_clients_by_address, find_max_difficulty_since_for_addresses,
    find_pool_worker_counts_since, find_recently_deleted_sessions, find_stale_active_sessions,
    find_worker_shares_for_address, raise_client_best_difficulties, revive_sessions,
    soft_delete_sessions, update_sv2_user_agent_by_address, upsert_client, ClientRow,
    ClientStatisticsRow, ClientUpsert, DeletedSessionRow, DeviceFirstSeenRow, PoolWorkerCounts,
    WorkerSharesRow,
};
pub use custom_extranonce::{
    all_custom_extranonces, delete_extranonce_challenge, find_custom_extranonces_for_address,
    find_extranonce_challenge, find_extranonce_token, upsert_custom_extranonces_batch,
    upsert_extranonce_challenge, upsert_extranonce_token, CustomExtranonceRow,
    ExtranonceChallengeRow, ExtranonceTokenRow,
};
pub use email::{
    delete_email_verification_by_token, delete_email_verifications_for_address,
    delete_expired_email_verifications, find_address_email, find_email_verification,
    insert_email_verification, upsert_address_email_verified, AddressEmailRow,
    EmailVerificationRow,
};
pub use group::{
    bulk_insert_pplns_group_block_history, count_pplns_group_join_requests_pending_for_address,
    count_pplns_group_members_for_group, delete_pplns_group_block_history_for_group,
    delete_pplns_group_member, delete_pplns_group_members_for_group,
    expire_pending_pplns_group_invitations, expire_pending_pplns_group_join_requests,
    find_all_pplns_group_member_addresses, find_group, find_group_invitation,
    find_group_member_by_address, find_pplns_group_active_open_invite_for_group,
    find_pplns_group_by_name_not_dissolved, find_pplns_group_creator_member,
    find_pplns_group_join_request_most_recent_rejected,
    find_pplns_group_join_request_pending_in_group, find_pplns_group_member_in_group,
    find_pplns_group_members_for_group, find_recent_group_block_history, insert_pplns_group,
    insert_pplns_group_invitation, insert_pplns_group_join_request, insert_pplns_group_member,
    list_active_pplns_group_flags, list_active_pplns_groups,
    list_pplns_group_join_requests_for_group, list_pplns_group_join_requests_pending_for_address,
    revoke_pending_open_invites_for_group, update_pplns_group_active,
    update_pplns_group_creator_and_admin_token, update_pplns_group_dissolved,
    update_pplns_group_invitation_status_by_token, update_pplns_group_join_request_decision,
    update_pplns_group_last_reset_at, update_pplns_group_member_role,
    update_pplns_group_round_reset_config, GroupPayoutHistoryInsert, PatchField,
    PplnsGroupBlockHistoryRow, PplnsGroupInvitationRow, PplnsGroupJoinRequestRow,
    PplnsGroupMemberRow, PplnsGroupRow, RoundResetConfigPatch,
};
pub use notification::{
    delete_ntfy_subscription_by_address, delete_push_subscription_by_endpoint,
    delete_push_subscription_by_endpoint_and_type, delete_push_subscriptions_by_address,
    delete_push_subscriptions_by_address_and_type, delete_stale_push_subscriptions,
    delete_telegram_subscription_by_chat_address, find_addresses_for_ntfy_listener,
    find_addresses_with_push_subscription, find_best_difficulty_scan_addresses,
    find_device_notification_addresses, find_ntfy_subscription_by_address,
    find_ntfy_subscriptions_with_hourly_enabled, find_push_subscriptions_by_address,
    find_telegram_subscriptions_by_address, find_telegram_subscriptions_by_chat,
    find_telegram_subscriptions_with_hourly_enabled, promote_telegram_default_if_none,
    set_telegram_default_subscription, set_telegram_hourly_flags, update_ntfy_sub_best_diff_flag,
    update_ntfy_sub_device_flag, update_ntfy_sub_hourly_flags, update_ntfy_sub_language,
    update_push_subscription_last_notification, update_push_subscription_preferences,
    update_telegram_sub_best_diff_flag, update_telegram_sub_device_flag, upsert_ntfy_subscription,
    upsert_push_subscription, upsert_telegram_subscription, NtfySubscriptionRow,
    PushSubscriptionRow, TelegramSubscriptionRow,
};
pub use pool_stats::{
    find_network_difficulty_tracker, find_pool_mode_hashrate_since,
    find_pool_rejected_statistics_since, find_pool_share_statistics_since,
    upsert_network_difficulty_tracker, NetworkDifficultyTrackerRow, PoolModeHashrateRow,
    PoolRejectedStatisticsRow, PoolShareStatisticsRow,
};
pub use pplns::{
    aggregate_pplns_balances, bulk_insert_pplns_payout_history,
    bulk_update_pplns_last_accepted_share_at, bulk_upsert_pplns_balances, find_pplns_balance,
    find_pplns_balances_for_addresses_locked, find_pplns_balances_with_open_balance,
    pplns_booked_value_rows_at_height, take_pplns_settlement_lock,
    update_pplns_balance_sats_if_unchanged, BalanceUpsert, PayoutHistoryInsert,
    PplnsBalanceAggregate, PplnsBalanceRow, TouchUpdate, PPLNS_SETTLEMENT_LOCK,
};
pub use stats_writes::{
    bulk_upsert_address_settings, bulk_upsert_client_statistics_entity,
    bulk_upsert_pool_mode_hashrate, bulk_upsert_pool_rejected_statistics,
    bulk_upsert_pool_share_statistics, bulk_upsert_worker_shares_entity, AddressSettingsUpsert,
    ClientStatsUpsert, PoolModeHashrateUpsert, PoolRejectedStatsUpsert, PoolShareStatsUpsert,
    WorkerSharesUpsert,
};
