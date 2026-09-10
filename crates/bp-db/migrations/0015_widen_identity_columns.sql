-- Widen every identity column from `character varying(62)` to `(90)`.
--
-- **This is a pre-existing break and has nothing to do with xpubs.** It is
-- Phase 5 of the payout-identity plan and deliberately NOT part of that
-- feature's diff: a reviewer looking at a payout-identity change cannot also be
-- evaluating a 32-column width migration.
--
-- Measured: a **regtest P2TR address (`bcrt1p…`) is 64 characters** against a
-- 62-character cap, in these columns and in `bp_common`'s
-- `validate_address_shape`. Mainnet `bc1p…` is 62 and fits exactly, with zero
-- spare, which is why this has never surfaced — 62 was chosen as exactly the
-- mainnet taproot width. `grep -rln 'bcrt1p' crates bin tests` returns zero
-- hits, so nothing in the repo pays or tests a taproot payout on regtest today;
-- the break is real and latent, and it surfaces as `TooLong(64)` at the moment
-- someone tries.
--
-- **Why 90 and not 64.** 90 is BIP-173's maximum length for a bech32 string, so
-- this is the last time the number has to move: the widest address any witness
-- version can produce is a 40-byte program on regtest — `bcrt` + `1` + 64 data
-- + 6 checksum = 75 characters — and no base58 address exceeds 35. Widening to
-- 64 would fix today's taproot case and leave the next witness version to
-- rediscover this migration. The cap is not address validation (it never was);
-- it is a shape bound on what these columns must hold, and 90 is that bound.
-- It still rejects the things the cap is relied on to reject: a bare extended
-- key is 111 characters and an output descriptor is ~130.
--
-- **Not widened: `miner_identity.descriptor`.** It is already `text`, and
-- deliberately so — the identity shape applies to the ledger key, never to the
-- descriptor.
--
-- **Cost and locking.** Increasing a `varchar` length limit is a catalog-only
-- change in PostgreSQL (the old type is binary-coercible to the new one), so
-- none of these tables and none of their indexes are rewritten — including
-- `worker_shares_entity` and `client_statistics_entity`, the two large ones.
-- Each statement takes a brief ACCESS EXCLUSIVE lock on its own table; there is
-- no long-running scan to wait behind. sqlx runs the whole file in one
-- transaction, so all 32 land or none do.
--
-- **Rollback story.** Reverting is `TYPE character varying(62)`, which is NOT
-- free: narrowing scans the table and fails outright if any row has grown past
-- 62. So the rollback is only safe while no address longer than 62 has been
-- written — i.e. before a taproot payout is enabled on regtest, which is the
-- only thing this migration unblocks. After that, reverting means finding those
-- rows first:
--
--   SELECT 'pplns_balance', address FROM pplns_balance WHERE length(address) > 62
--   UNION ALL SELECT 'miner_identity', "payoutId" FROM miner_identity WHERE length("payoutId") > 62;
--
-- Re-running this file is a harmless no-op (a widen to the width it already
-- has), and sqlx's `_sqlx_migrations` table means it runs once anyway.
--
-- The Rust half of this change is `bp_common::MAX_ADDRESS_LEN`. The two must
-- agree: the Rust cap is what keeps a too-long value from ever reaching a
-- column, and the column width is what makes the cap's number load-bearing.
ALTER TABLE address_settings_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE best_difficulty_tracker_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE blocks_entity ALTER COLUMN "minerAddress" TYPE character varying(90);
ALTER TABLE client_difficulty_statistics_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE client_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE client_rejected_statistics_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE client_statistics_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE external_shares_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE ntfy_subscriptions_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_address_email ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_balance ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_email_verification ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_ownership_challenge ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_address_ownership ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_group ALTER COLUMN "creatorAddress" TYPE character varying(90);
ALTER TABLE pplns_group_balance ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_group_block_history ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_group_invitation ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_group_join_request ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_group_member ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_payout_history ALTER COLUMN address TYPE character varying(90);
ALTER TABLE push_subscription_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE telegram_subscriptions_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE worker_shares_entity ALTER COLUMN address TYPE character varying(90);
ALTER TABLE blockparty_group ALTER COLUMN "adminAddress" TYPE character varying(90);
ALTER TABLE blockparty_member ALTER COLUMN address TYPE character varying(90);
ALTER TABLE blockparty_invitation ALTER COLUMN address TYPE character varying(90);
ALTER TABLE miner_identity ALTER COLUMN "payoutId" TYPE character varying(90);
ALTER TABLE miner_identity ALTER COLUMN address TYPE character varying(90);

-- The three tables `0012_add_custom_extranonce.sql` added. They were written
-- with the same `character varying(62)` the rest of the schema had, so they
-- carry the identical latent break — a 64-character regtest `bcrt1p…` cannot be
-- stored. They are widened here rather than in 0012 because this migration is
-- the one place the identity width is decided; `identity_column_width.rs` asks
-- `information_schema` rather than a name list precisely so a table added
-- between the two shows up as a failing test instead of a silent gap, and that
-- is how these three were found.
ALTER TABLE pplns_extranonce_challenge ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_extranonce_token ALTER COLUMN address TYPE character varying(90);
ALTER TABLE pplns_custom_extranonce ALTER COLUMN address TYPE character varying(90);
