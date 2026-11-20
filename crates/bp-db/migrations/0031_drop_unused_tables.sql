-- Drops five tables no query reads or writes: `blockparty_invitation`,
-- `external_shares_entity`, `pplns_group_balance` (Group-Solo keeps no
-- ledger), `rpc_block_entity` and `migrations` (the TS pool's own migration
-- log). No other table references them; their sequences go with them.
--
-- IF EXISTS: a database need not have all five. A binary one release older
-- never touches any of them, so it starts and runs against this schema.

DROP TABLE IF EXISTS blockparty_invitation;
DROP TABLE IF EXISTS external_shares_entity;
DROP TABLE IF EXISTS pplns_group_balance;
DROP TABLE IF EXISTS rpc_block_entity;
DROP TABLE IF EXISTS migrations;
