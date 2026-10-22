-- A Team's or Blockparty's own coinbase tag, set by its admin and written
-- after the pool identifier into the coinbase of every block the group mines:
-- at most 25 printable ASCII characters (`bp_common::CoinbaseTag`), NULL for
-- none.
--
-- Nullable columns without a default: catalog-only in PostgreSQL, and a binary
-- one release older neither reads nor writes them.

ALTER TABLE pplns_group ADD COLUMN IF NOT EXISTS "coinbaseTag" varchar(25);
ALTER TABLE blockparty_group ADD COLUMN IF NOT EXISTS "coinbaseTag" varchar(25);

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'CHK_pplns_group_coinbase_tag') THEN
    ALTER TABLE pplns_group ADD CONSTRAINT "CHK_pplns_group_coinbase_tag"
      CHECK ("coinbaseTag" ~ '^[ -~]{1,25}$');
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'CHK_blockparty_group_coinbase_tag') THEN
    ALTER TABLE blockparty_group ADD CONSTRAINT "CHK_blockparty_group_coinbase_tag"
      CHECK ("coinbaseTag" ~ '^[ -~]{1,25}$');
  END IF;
END $$;
