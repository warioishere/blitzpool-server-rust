-- The schema a fresh database starts from: every table, sequence, index and
-- constraint as they stand after 0016_blockparty_dissolve_frees_addresses.sql.
--
-- The migrations after the TS pool only ALTER a schema that pool had already
-- built, so an empty database used to fail at migration 0001 and needed
-- db/schema.sql loaded by hand first. This file replaces that step: the pool
-- now builds its own schema at boot.
--
-- It only acts on a database that has NONE of these tables. Any existing
-- database (prod, the test server, one seeded from the old schema.sql) takes
-- the no-op branch: no statement runs, no table is locked. There it is only
-- recorded as applied. 0001-0016 then run over a fresh schema as they always
-- have; each is written to be a no-op against a table that already has what
-- it adds.
--
-- Generated with pg_dump --schema-only from a database built by the old
-- schema.sql plus 0001-0016, so a fresh database gets the same tables as prod,
-- including four no query reads any more (`blockparty_invitation`,
-- `external_shares_entity`, `pplns_group_balance` and the TS pool's
-- `migrations`). Left out: the pg_stat_statements and uuid-ossp extensions.
-- The first needs a superuser and is an ops choice; nothing uses the second.
--
-- sqlx checksums applied migrations: once this has run anywhere, it must
-- never be edited. A later schema change is a new migration.

DO $baseline$
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_tables
        WHERE schemaname = 'public'
          AND tablename IN (
              'address_settings_entity',
              'best_difficulty_tracker_entity',
              'blockparty_block_history',
              'blockparty_group',
              'blockparty_invitation',
              'blockparty_join_link',
              'blockparty_member',
              'blocks_entity',
              'client_difficulty_statistics_entity',
              'client_entity',
              'client_rejected_statistics_entity',
              'client_statistics_entity',
              'external_shares_entity',
              'migrations',
              'network_difficulty_tracker_entity',
              'ntfy_subscriptions_entity',
              'pool_mode_hashrate',
              'pool_rejected_statistics_entity',
              'pool_share_statistics_entity',
              'pplns_address_email',
              'pplns_address_ownership',
              'pplns_balance',
              'pplns_custom_extranonce',
              'pplns_email_verification',
              'pplns_extranonce_challenge',
              'pplns_extranonce_token',
              'pplns_group',
              'pplns_group_balance',
              'pplns_group_block_history',
              'pplns_group_invitation',
              'pplns_group_join_request',
              'pplns_group_member',
              'pplns_ownership_challenge',
              'pplns_payout_history',
              'push_subscription_entity',
              'redis_state_backup',
              'rpc_block_entity',
              'telegram_subscriptions_entity',
              'worker_shares_entity'
          )
    ) THEN
        RAISE NOTICE 'baseline: existing schema found, nothing to create';
        RETURN;
    END IF;

    CREATE TABLE public.address_settings_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        address character varying(62) NOT NULL,
        shares double precision DEFAULT '0'::double precision NOT NULL,
        "bestDifficulty" double precision DEFAULT '0'::real NOT NULL,
        "miscCoinbaseScriptData" character varying,
        "bestDifficultyUserAgent" character varying,
        "allTimeBestDifficulty" double precision DEFAULT 0 NOT NULL,
        "allTimeBestDifficultyUserAgent" character varying,
        "allTimeBestDifficultyAt" bigint
    );
    CREATE TABLE public.best_difficulty_tracker_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        address character varying(62) NOT NULL,
        "bestDifficulty" double precision NOT NULL,
        "lastCheckedAt" bigint NOT NULL
    );
    CREATE TABLE public.blockparty_block_history (
        id bigint NOT NULL,
        "groupId" uuid NOT NULL,
        "blockHeight" integer NOT NULL,
        "blockHash" character varying(64) NOT NULL,
        "foundAt" bigint NOT NULL,
        "coinbaseValueSats" bigint NOT NULL,
        "poolFeeSats" bigint NOT NULL,
        splits jsonb NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL
    );
    CREATE SEQUENCE public.blockparty_block_history_id_seq
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.blockparty_block_history_id_seq OWNED BY public.blockparty_block_history.id;
    CREATE TABLE public.blockparty_group (
        id uuid DEFAULT gen_random_uuid() NOT NULL,
        name character varying(64) NOT NULL,
        "adminAddress" character varying(62) NOT NULL,
        "adminTokenHash" character varying(64) NOT NULL,
        status character varying(16) DEFAULT 'draft'::character varying NOT NULL,
        "lastShareAt" bigint,
        "rentalProviderHint" character varying(64),
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "dissolvedAt" bigint,
        "confirmationRequestedAt" bigint
    );
    CREATE TABLE public.blockparty_invitation (
        token character varying(64) NOT NULL,
        "groupId" uuid NOT NULL,
        address character varying(62) NOT NULL,
        email character varying(320) NOT NULL,
        status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "expiresAt" bigint NOT NULL,
        "respondedAt" bigint
    );
    CREATE TABLE public.blockparty_join_link (
        "groupId" uuid NOT NULL,
        token character varying(64) NOT NULL,
        "expiresAt" bigint NOT NULL,
        "createdAt" bigint NOT NULL
    );
    CREATE TABLE public.blockparty_member (
        id bigint NOT NULL,
        "groupId" uuid NOT NULL,
        address character varying(62) NOT NULL,
        email character varying(320) NOT NULL,
        "percentBp" integer NOT NULL,
        role character varying(16) DEFAULT 'member'::character varying NOT NULL,
        "confirmedAt" bigint,
        "memberTokenHash" character varying(64),
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL
    );
    CREATE SEQUENCE public.blockparty_member_id_seq
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.blockparty_member_id_seq OWNED BY public.blockparty_member.id;
    CREATE TABLE public.blocks_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        height bigint NOT NULL,
        "minerAddress" character varying(62) NOT NULL,
        worker character varying NOT NULL,
        "sessionId" character varying(8) NOT NULL,
        "blockData" character varying NOT NULL
    );
    CREATE SEQUENCE public.blocks_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.blocks_entity_id_seq OWNED BY public.blocks_entity.id;
    CREATE TABLE public.client_difficulty_statistics_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        "clientName" character varying(64),
        "slotTime" bigint NOT NULL,
        "maxDifficulty" real DEFAULT '0'::real NOT NULL
    );
    CREATE SEQUENCE public.client_difficulty_statistics_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.client_difficulty_statistics_entity_id_seq OWNED BY public.client_difficulty_statistics_entity.id;
    CREATE TABLE public.client_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        address character varying(62) NOT NULL,
        "clientName" character varying(64) NOT NULL,
        "sessionId" character varying(8) NOT NULL,
        "userAgent" character varying(128),
        "startTime" bigint NOT NULL,
        "firstSeen" bigint
    );
    CREATE TABLE public.client_rejected_statistics_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        "time" bigint NOT NULL,
        reason character varying NOT NULL,
        count real DEFAULT '0'::real NOT NULL,
        shares real DEFAULT '0'::real NOT NULL
    );
    CREATE SEQUENCE public.client_rejected_statistics_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.client_rejected_statistics_entity_id_seq OWNED BY public.client_rejected_statistics_entity.id;
    CREATE TABLE public.client_statistics_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        "clientName" character varying NOT NULL,
        "sessionId" character varying(8) NOT NULL,
        "time" bigint NOT NULL,
        shares real NOT NULL,
        "acceptedCount" integer DEFAULT 0 NOT NULL,
        "rejectedCount" integer DEFAULT 0 NOT NULL,
        "rejectedJobNotFoundCount" integer DEFAULT 0 NOT NULL,
        "rejectedJobNotFoundDiff1" real DEFAULT '0'::real NOT NULL,
        "rejectedDuplicateShareCount" integer DEFAULT 0 NOT NULL,
        "rejectedDuplicateShareDiff1" real DEFAULT '0'::real NOT NULL,
        "rejectedLowDifficultyShareCount" integer DEFAULT 0 CONSTRAINT "client_statistics_entity_rejectedLowDifficultyShareCou_not_null" NOT NULL,
        "rejectedLowDifficultyShareDiff1" real DEFAULT '0'::real CONSTRAINT "client_statistics_entity_rejectedLowDifficultyShareDif_not_null" NOT NULL,
        "rejectedVersionRollingCount" integer DEFAULT 0 NOT NULL,
        "rejectedVersionRollingDiff1" real DEFAULT '0'::real NOT NULL,
        "rejectedStaleCount" integer DEFAULT 0 NOT NULL,
        "rejectedStaleDiff1" real DEFAULT '0'::real NOT NULL
    )
    WITH (fillfactor='80');
    CREATE SEQUENCE public.client_statistics_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.client_statistics_entity_id_seq OWNED BY public.client_statistics_entity.id;
    CREATE TABLE public.external_shares_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        "clientName" character varying NOT NULL,
        "time" bigint NOT NULL,
        difficulty real NOT NULL,
        "userAgent" character varying(128),
        "externalPoolName" character varying(128),
        header character varying NOT NULL
    );
    CREATE SEQUENCE public.external_shares_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.external_shares_entity_id_seq OWNED BY public.external_shares_entity.id;
    CREATE TABLE public.migrations (
        id integer NOT NULL,
        "timestamp" bigint NOT NULL,
        name character varying NOT NULL
    );
    CREATE SEQUENCE public.migrations_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.migrations_id_seq OWNED BY public.migrations.id;
    CREATE TABLE public.network_difficulty_tracker_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer DEFAULT 1 NOT NULL,
        "currentDifficulty" double precision NOT NULL,
        "previousDifficulty" double precision,
        "lastCheckedAt" bigint NOT NULL,
        "lastChangedAt" bigint,
        CONSTRAINT "CHK_network_difficulty_tracker_singleton" CHECK ((id = 1))
    );
    CREATE TABLE public.ntfy_subscriptions_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        language character varying DEFAULT 'de'::character varying NOT NULL,
        "bestDiffNotificationsEnabled" boolean DEFAULT true NOT NULL,
        "deviceNotificationsEnabled" boolean DEFAULT false NOT NULL,
        "hourlyStatsEnabled" boolean DEFAULT false NOT NULL,
        "hourlyWorkersEnabled" boolean DEFAULT false NOT NULL
    );
    CREATE SEQUENCE public.ntfy_subscriptions_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.ntfy_subscriptions_entity_id_seq OWNED BY public.ntfy_subscriptions_entity.id;
    CREATE TABLE public.pool_mode_hashrate (
        id integer NOT NULL,
        mode character varying(16) NOT NULL,
        "time" bigint NOT NULL,
        diff real DEFAULT 0 NOT NULL
    );
    CREATE SEQUENCE public.pool_mode_hashrate_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.pool_mode_hashrate_id_seq OWNED BY public.pool_mode_hashrate.id;
    CREATE TABLE public.pool_rejected_statistics_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        "time" bigint NOT NULL,
        reason character varying NOT NULL,
        count real DEFAULT '0'::real NOT NULL
    );
    CREATE SEQUENCE public.pool_rejected_statistics_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.pool_rejected_statistics_entity_id_seq OWNED BY public.pool_rejected_statistics_entity.id;
    CREATE TABLE public.pool_share_statistics_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        "time" bigint NOT NULL,
        accepted real DEFAULT '0'::real NOT NULL,
        rejected real DEFAULT '0'::real NOT NULL
    );
    CREATE SEQUENCE public.pool_share_statistics_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.pool_share_statistics_entity_id_seq OWNED BY public.pool_share_statistics_entity.id;
    CREATE TABLE public.pplns_address_email (
        address character varying(62) NOT NULL,
        email character varying(320) NOT NULL,
        "verifiedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL
    );
    CREATE TABLE public.pplns_address_ownership (
        address character varying(62) NOT NULL,
        method character varying(16) NOT NULL,
        "scriptType" character varying(16) NOT NULL,
        "verifiedAt" bigint NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL
    );
    CREATE TABLE public.pplns_balance (
        address character varying(62) NOT NULL,
        "balanceSats" bigint DEFAULT 0 CONSTRAINT "pplns_balance_pendingSats_not_null" NOT NULL,
        "totalPaidSats" bigint DEFAULT 0 NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "lastAcceptedShareAt" bigint
    );
    CREATE TABLE public.pplns_custom_extranonce (
        address character varying(62) NOT NULL,
        worker character varying NOT NULL,
        prefix bigint NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        CONSTRAINT pplns_custom_extranonce_prefix_u32 CHECK (((prefix >= 0) AND (prefix <= '4294967295'::bigint))),
        CONSTRAINT pplns_custom_extranonce_prefix_unreserved CHECK ((prefix >= 33554432))
    );
    CREATE TABLE public.pplns_email_verification (
        token character varying(64) NOT NULL,
        address character varying(62) NOT NULL,
        email character varying(320) NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "expiresAt" bigint NOT NULL
    );
    CREATE TABLE public.pplns_extranonce_challenge (
        address character varying(62) NOT NULL,
        message text NOT NULL,
        "createdAt" bigint NOT NULL,
        "expiresAt" bigint NOT NULL
    );
    CREATE TABLE public.pplns_extranonce_token (
        address character varying(62) NOT NULL,
        "tokenHash" character varying(64) NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL
    );
    CREATE TABLE public.pplns_group (
        id uuid NOT NULL,
        name character varying(64) NOT NULL,
        "creatorAddress" character varying(62) NOT NULL,
        "adminTokenHash" character varying(255) NOT NULL,
        active boolean DEFAULT false NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "dissolvedAt" bigint,
        "roundResetIntervalDays" integer,
        "roundResetHourLocal" integer,
        "roundResetTimezone" character varying(64),
        "lastRoundResetAt" bigint,
        "finderBonusSats" bigint,
        "finderBonusPpm" integer,
        "roundResetPreset" character varying(16),
        "isPublic" boolean DEFAULT false NOT NULL,
        "resetRoundOnBlock" boolean DEFAULT false NOT NULL,
        "maxMembers" integer,
        "payoutMode" character varying(16) DEFAULT 'prop'::character varying NOT NULL
    );
    CREATE TABLE public.pplns_group_balance (
        address character varying(62) NOT NULL,
        "groupId" uuid NOT NULL,
        "pendingSats" bigint DEFAULT 0 NOT NULL,
        "totalPaidSats" bigint DEFAULT 0 NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "lastAcceptedShareAt" bigint
    );
    CREATE TABLE public.pplns_group_block_history (
        id integer NOT NULL,
        "groupId" uuid NOT NULL,
        "blockHeight" integer NOT NULL,
        address character varying(62) NOT NULL,
        "paidSats" bigint DEFAULT 0 NOT NULL,
        percent real DEFAULT 0 NOT NULL,
        "sharesInRound" bigint DEFAULT 0 NOT NULL,
        "totalSharesInRound" bigint DEFAULT 0 NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "rowType" character varying(16) DEFAULT 'coinbase'::character varying NOT NULL
    );
    CREATE SEQUENCE public.pplns_group_block_history_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.pplns_group_block_history_id_seq OWNED BY public.pplns_group_block_history.id;
    CREATE TABLE public.pplns_group_invitation (
        token character varying(64) NOT NULL,
        "groupId" uuid NOT NULL,
        address character varying(62),
        email character varying(320),
        status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "expiresAt" bigint NOT NULL,
        "respondedAt" bigint,
        "inviteType" character varying(16) DEFAULT 'directed'::character varying NOT NULL,
        "approvalRequired" boolean DEFAULT false NOT NULL
    );
    CREATE TABLE public.pplns_group_join_request (
        id uuid DEFAULT gen_random_uuid() NOT NULL,
        "groupId" uuid NOT NULL,
        address character varying(62) NOT NULL,
        email character varying(320) NOT NULL,
        message text,
        status character varying(16) DEFAULT 'pending'::character varying NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "decidedAt" bigint,
        "decidedByAdminTokenHash" character varying(255)
    );
    CREATE TABLE public.pplns_group_member (
        id integer NOT NULL,
        "groupId" uuid NOT NULL,
        address character varying(62) NOT NULL,
        role character varying(16) DEFAULT 'member'::character varying NOT NULL,
        "joinedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL
    );
    CREATE SEQUENCE public.pplns_group_member_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.pplns_group_member_id_seq OWNED BY public.pplns_group_member.id;
    CREATE TABLE public.pplns_ownership_challenge (
        address character varying(62) NOT NULL,
        message text NOT NULL,
        "createdAt" bigint NOT NULL,
        "expiresAt" bigint NOT NULL
    );
    CREATE TABLE public.pplns_payout_history (
        id integer NOT NULL,
        "blockHeight" integer NOT NULL,
        address character varying(62) NOT NULL,
        "paidSats" bigint DEFAULT 0 NOT NULL,
        percent real DEFAULT 0 NOT NULL,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "rowType" character varying(16) DEFAULT 'coinbase'::character varying NOT NULL
    );
    CREATE SEQUENCE public.pplns_payout_history_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.pplns_payout_history_id_seq OWNED BY public.pplns_payout_history.id;
    CREATE TABLE public.push_subscription_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        endpoint text NOT NULL,
        platform character varying DEFAULT 'unknown'::character varying NOT NULL,
        "lastNotificationAt" bigint,
        "bestDiffNotificationsEnabled" boolean DEFAULT true NOT NULL,
        "deviceNotificationsEnabled" boolean DEFAULT true NOT NULL,
        "blockNotificationsEnabled" boolean DEFAULT true NOT NULL,
        "subscriptionType" character varying(20) DEFAULT 'unified_push'::character varying NOT NULL,
        "networkDiffNotificationsEnabled" boolean DEFAULT true CONSTRAINT "push_subscription_entity_networkDiffNotificationsEnabl_not_null" NOT NULL
    );
    CREATE SEQUENCE public.push_subscription_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.push_subscription_entity_id_seq OWNED BY public.push_subscription_entity.id;
    CREATE TABLE public.redis_state_backup (
        id bigint NOT NULL,
        captured_at bigint NOT NULL,
        scope text NOT NULL,
        redis_key text NOT NULL,
        dump bytea NOT NULL
    );
    CREATE SEQUENCE public.redis_state_backup_id_seq
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.redis_state_backup_id_seq OWNED BY public.redis_state_backup.id;
    CREATE TABLE public.rpc_block_entity (
        "blockHeight" bigint NOT NULL,
        "lockedBy" character varying,
        data character varying
    );
    CREATE TABLE public.telegram_subscriptions_entity (
        "deletedAt" bigint,
        "createdAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        "updatedAt" bigint DEFAULT ((EXTRACT(epoch FROM now()) * (1000)::numeric))::bigint NOT NULL,
        id integer NOT NULL,
        address character varying(62) NOT NULL,
        "telegramChatId" bigint NOT NULL,
        "bestDiffNotificationsEnabled" boolean DEFAULT true CONSTRAINT "telegram_subscriptions_enti_bestDiffNotificationsEnabl_not_null" NOT NULL,
        "isDefault" boolean DEFAULT false NOT NULL,
        "deviceNotificationsEnabled" boolean DEFAULT false CONSTRAINT "telegram_subscriptions_enti_deviceNotificationsEnabled_not_null" NOT NULL,
        "hourlyStatsEnabled" boolean DEFAULT false NOT NULL,
        "hourlyWorkersEnabled" boolean DEFAULT false NOT NULL
    );
    CREATE SEQUENCE public.telegram_subscriptions_entity_id_seq
        AS integer
        START WITH 1
        INCREMENT BY 1
        NO MINVALUE
        NO MAXVALUE
        CACHE 1;
    ALTER SEQUENCE public.telegram_subscriptions_entity_id_seq OWNED BY public.telegram_subscriptions_entity.id;
    CREATE TABLE public.worker_shares_entity (
        address character varying(62) NOT NULL,
        "clientName" character varying NOT NULL,
        shares double precision DEFAULT 0 NOT NULL,
        "rejectedShares" double precision DEFAULT 0 NOT NULL
    );
    ALTER TABLE ONLY public.blockparty_block_history ALTER COLUMN id SET DEFAULT nextval('public.blockparty_block_history_id_seq'::regclass);
    ALTER TABLE ONLY public.blockparty_member ALTER COLUMN id SET DEFAULT nextval('public.blockparty_member_id_seq'::regclass);
    ALTER TABLE ONLY public.blocks_entity ALTER COLUMN id SET DEFAULT nextval('public.blocks_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.client_difficulty_statistics_entity ALTER COLUMN id SET DEFAULT nextval('public.client_difficulty_statistics_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.client_rejected_statistics_entity ALTER COLUMN id SET DEFAULT nextval('public.client_rejected_statistics_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.client_statistics_entity ALTER COLUMN id SET DEFAULT nextval('public.client_statistics_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.external_shares_entity ALTER COLUMN id SET DEFAULT nextval('public.external_shares_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.migrations ALTER COLUMN id SET DEFAULT nextval('public.migrations_id_seq'::regclass);
    ALTER TABLE ONLY public.ntfy_subscriptions_entity ALTER COLUMN id SET DEFAULT nextval('public.ntfy_subscriptions_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.pool_mode_hashrate ALTER COLUMN id SET DEFAULT nextval('public.pool_mode_hashrate_id_seq'::regclass);
    ALTER TABLE ONLY public.pool_rejected_statistics_entity ALTER COLUMN id SET DEFAULT nextval('public.pool_rejected_statistics_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.pool_share_statistics_entity ALTER COLUMN id SET DEFAULT nextval('public.pool_share_statistics_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.pplns_group_block_history ALTER COLUMN id SET DEFAULT nextval('public.pplns_group_block_history_id_seq'::regclass);
    ALTER TABLE ONLY public.pplns_group_member ALTER COLUMN id SET DEFAULT nextval('public.pplns_group_member_id_seq'::regclass);
    ALTER TABLE ONLY public.pplns_payout_history ALTER COLUMN id SET DEFAULT nextval('public.pplns_payout_history_id_seq'::regclass);
    ALTER TABLE ONLY public.push_subscription_entity ALTER COLUMN id SET DEFAULT nextval('public.push_subscription_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.redis_state_backup ALTER COLUMN id SET DEFAULT nextval('public.redis_state_backup_id_seq'::regclass);
    ALTER TABLE ONLY public.telegram_subscriptions_entity ALTER COLUMN id SET DEFAULT nextval('public.telegram_subscriptions_entity_id_seq'::regclass);
    ALTER TABLE ONLY public.rpc_block_entity
        ADD CONSTRAINT "PK_1d879c7524320d41601c8916262" PRIMARY KEY ("blockHeight");
    ALTER TABLE ONLY public.pplns_group_invitation
        ADD CONSTRAINT "PK_26e45de736c1d14a1221ca3edf7" PRIMARY KEY (token);
    ALTER TABLE ONLY public.pplns_email_verification
        ADD CONSTRAINT "PK_337f46c4efd12c7456755f7c590" PRIMARY KEY (token);
    ALTER TABLE ONLY public.client_rejected_statistics_entity
        ADD CONSTRAINT "PK_33d6282ff85d90fb12e3e5b0948" PRIMARY KEY (id);
    ALTER TABLE ONLY public.external_shares_entity
        ADD CONSTRAINT "PK_36fdb7a4e3e93e017bc4bfa3047" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pplns_group_join_request
        ADD CONSTRAINT "PK_5a12a8aead09017d102151c5950" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pplns_group_block_history
        ADD CONSTRAINT "PK_5b374c8b7669122851b388abaf1" PRIMARY KEY (id);
    ALTER TABLE ONLY public.blocks_entity
        ADD CONSTRAINT "PK_6b5cb3b7439f2c66cdb0156f703" PRIMARY KEY (id);
    ALTER TABLE ONLY public.client_entity
        ADD CONSTRAINT "PK_72591a7d9edf0ec824243c68aeb" PRIMARY KEY (address, "clientName", "sessionId");
    ALTER TABLE ONLY public.pplns_address_email
        ADD CONSTRAINT "PK_77f690e5335dffd0f71910e4371" PRIMARY KEY (address);
    ALTER TABLE ONLY public.pplns_balance
        ADD CONSTRAINT "PK_8912cce874fb31e21ef246ec341" PRIMARY KEY (address);
    ALTER TABLE ONLY public.migrations
        ADD CONSTRAINT "PK_8c82d7f526340ab734260ea46be" PRIMARY KEY (id);
    ALTER TABLE ONLY public.telegram_subscriptions_entity
        ADD CONSTRAINT "PK_93b0925f78fa753929f313021c7" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pool_mode_hashrate
        ADD CONSTRAINT "PK_94820f4c644a91339eb0cb55ea6" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pplns_group_member
        ADD CONSTRAINT "PK_a3e186953fc37330b393dddda4d" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pool_rejected_statistics_entity
        ADD CONSTRAINT "PK_a775609a3adb8274bc383466563" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pplns_payout_history
        ADD CONSTRAINT "PK_b009d8dc7d8ea328c17d07dcbc7" PRIMARY KEY (id);
    ALTER TABLE ONLY public.client_statistics_entity
        ADD CONSTRAINT "PK_b62c23f526570c9284b894e9c11" PRIMARY KEY (id);
    ALTER TABLE ONLY public.best_difficulty_tracker_entity
        ADD CONSTRAINT "PK_best_difficulty_tracker_entity" PRIMARY KEY (address);
    ALTER TABLE ONLY public.blockparty_block_history
        ADD CONSTRAINT "PK_blockparty_block_history" PRIMARY KEY (id);
    ALTER TABLE ONLY public.blockparty_group
        ADD CONSTRAINT "PK_blockparty_group" PRIMARY KEY (id);
    ALTER TABLE ONLY public.blockparty_invitation
        ADD CONSTRAINT "PK_blockparty_invitation" PRIMARY KEY (token);
    ALTER TABLE ONLY public.blockparty_member
        ADD CONSTRAINT "PK_blockparty_member" PRIMARY KEY (id);
    ALTER TABLE ONLY public.client_difficulty_statistics_entity
        ADD CONSTRAINT "PK_client_difficulty_statistics_entity_id" PRIMARY KEY (id);
    ALTER TABLE ONLY public.address_settings_entity
        ADD CONSTRAINT "PK_d20f2ff951af47908573162bafe" PRIMARY KEY (address);
    ALTER TABLE ONLY public.pplns_group
        ADD CONSTRAINT "PK_d4aefa7018d4003a573e05886fa" PRIMARY KEY (id);
    ALTER TABLE ONLY public.pplns_group_balance
        ADD CONSTRAINT "PK_dc0ff3a355d647a179bf5b1f133" PRIMARY KEY (address, "groupId");
    ALTER TABLE ONLY public.pool_share_statistics_entity
        ADD CONSTRAINT "PK_f962c8caee66b1dc18949f19284" PRIMARY KEY (id);
    ALTER TABLE ONLY public.network_difficulty_tracker_entity
        ADD CONSTRAINT "PK_network_difficulty_tracker_entity" PRIMARY KEY (id);
    ALTER TABLE ONLY public.ntfy_subscriptions_entity
        ADD CONSTRAINT "PK_ntfy_subscriptions_entity" PRIMARY KEY (id);
    ALTER TABLE ONLY public.push_subscription_entity
        ADD CONSTRAINT "PK_push_subscription_entity" PRIMARY KEY (id);
    ALTER TABLE ONLY public.worker_shares_entity
        ADD CONSTRAINT "PK_worker_shares_entity" PRIMARY KEY (address, "clientName");
    ALTER TABLE ONLY public.pool_share_statistics_entity
        ADD CONSTRAINT "UQ_1e8bf1f7a6775ce455ae3fd5a08" UNIQUE ("time");
    ALTER TABLE ONLY public.pplns_group
        ADD CONSTRAINT "UQ_20b3f49abe5220514c53dc0c6fa" UNIQUE (name);
    ALTER TABLE ONLY public.pplns_group_member
        ADD CONSTRAINT "UQ_4f2fe5281883e1bc9593362ce92" UNIQUE (address);
    ALTER TABLE ONLY public.client_rejected_statistics_entity
        ADD CONSTRAINT "UQ_8b864b9a747bbf963241e46a99a" UNIQUE (address, "time", reason);
    ALTER TABLE ONLY public.pool_rejected_statistics_entity
        ADD CONSTRAINT "UQ_95efa6065f98aac8076bfe2cb05" UNIQUE ("time", reason);
    ALTER TABLE ONLY public.blockparty_block_history
        ADD CONSTRAINT "UQ_blockparty_block_history_group_hash" UNIQUE ("groupId", "blockHash");
    ALTER TABLE ONLY public.blockparty_group
        ADD CONSTRAINT "UQ_blockparty_group_name" UNIQUE (name);
    ALTER TABLE ONLY public.blockparty_member
        ADD CONSTRAINT "UQ_blockparty_member_address" UNIQUE (address);
    ALTER TABLE ONLY public.blockparty_member
        ADD CONSTRAINT "UQ_blockparty_member_group_address" UNIQUE ("groupId", address);
    ALTER TABLE ONLY public.client_statistics_entity
        ADD CONSTRAINT "UQ_client_statistics_composite" UNIQUE (address, "clientName", "sessionId", "time");
    ALTER TABLE ONLY public.ntfy_subscriptions_entity
        ADD CONSTRAINT "UQ_ntfy_subscriptions_address" UNIQUE (address);
    ALTER TABLE ONLY public.pool_mode_hashrate
        ADD CONSTRAINT "UQ_pool_mode_hashrate_mode_time" UNIQUE (mode, "time");
    ALTER TABLE ONLY public.push_subscription_entity
        ADD CONSTRAINT "UQ_push_subscription_address_endpoint_type" UNIQUE (address, endpoint, "subscriptionType");
    ALTER TABLE ONLY public.blockparty_join_link
        ADD CONSTRAINT blockparty_join_link_pkey PRIMARY KEY ("groupId");
    ALTER TABLE ONLY public.blockparty_join_link
        ADD CONSTRAINT blockparty_join_link_token_key UNIQUE (token);
    ALTER TABLE ONLY public.pplns_address_ownership
        ADD CONSTRAINT pplns_address_ownership_pkey PRIMARY KEY (address);
    ALTER TABLE ONLY public.pplns_custom_extranonce
        ADD CONSTRAINT pplns_custom_extranonce_address_prefix_key UNIQUE (address, prefix) DEFERRABLE;
    ALTER TABLE ONLY public.pplns_custom_extranonce
        ADD CONSTRAINT pplns_custom_extranonce_pkey PRIMARY KEY (address, worker);
    ALTER TABLE ONLY public.pplns_extranonce_challenge
        ADD CONSTRAINT pplns_extranonce_challenge_pkey PRIMARY KEY (address);
    ALTER TABLE ONLY public.pplns_extranonce_token
        ADD CONSTRAINT pplns_extranonce_token_pkey PRIMARY KEY (address);
    ALTER TABLE ONLY public.pplns_ownership_challenge
        ADD CONSTRAINT pplns_ownership_challenge_pkey PRIMARY KEY (address);
    ALTER TABLE ONLY public.redis_state_backup
        ADD CONSTRAINT redis_state_backup_pkey PRIMARY KEY (id);
    CREATE INDEX "IDX_07dddd1062211639f25291ea47" ON public.pplns_group_member USING btree ("groupId");
    CREATE INDEX "IDX_37ff12a362264511bb753ca364" ON public.pplns_group_balance USING btree ("groupId");
    CREATE INDEX "IDX_7a5a07e449b2e9e6c62bf76d70" ON public.pplns_group_invitation USING btree (address);
    CREATE INDEX "IDX_7d081302c6f984f26f81caa5cc" ON public.client_statistics_entity USING btree ("time");
    CREATE INDEX "IDX_as_bestdifficulty_desc" ON public.address_settings_entity USING btree ("bestDifficulty" DESC);
    CREATE INDEX "IDX_b0d3d46f8123933e60c836eaa8" ON public.pplns_group_block_history USING btree ("groupId");
    CREATE INDEX "IDX_blockparty_block_history_group" ON public.blockparty_block_history USING btree ("groupId");
    CREATE INDEX "IDX_blockparty_block_history_height" ON public.blockparty_block_history USING btree ("blockHeight");
    CREATE INDEX "IDX_blockparty_group_status" ON public.blockparty_group USING btree (status);
    CREATE INDEX "IDX_blockparty_invitation_address" ON public.blockparty_invitation USING btree (address);
    CREATE INDEX "IDX_blockparty_invitation_group" ON public.blockparty_invitation USING btree ("groupId");
    CREATE INDEX "IDX_blockparty_member_group" ON public.blockparty_member USING btree ("groupId");
    CREATE INDEX "IDX_c2011ee3f6a7e1066a1a4b18cc" ON public.pplns_email_verification USING btree (address);
    CREATE INDEX "IDX_cds_address_slottime" ON public.client_difficulty_statistics_entity USING btree (address, "slotTime");
    CREATE INDEX "IDX_client_active" ON public.client_entity USING btree (address, "clientName") WHERE ("deletedAt" IS NULL);
    CREATE INDEX "IDX_client_deleted" ON public.client_entity USING btree ("deletedAt") WHERE ("deletedAt" IS NOT NULL);
    CREATE UNIQUE INDEX "IDX_client_difficulty_statistics_unique" ON public.client_difficulty_statistics_entity USING btree (address, "clientName", "slotTime");
    CREATE INDEX "IDX_client_session" ON public.client_entity USING btree ("sessionId") WHERE ("deletedAt" IS NULL);
    CREATE INDEX "IDX_cs_address_time" ON public.client_statistics_entity USING btree (address, "time");
    CREATE INDEX "IDX_cs_real_time_cov" ON public.client_statistics_entity USING btree ("time", address, "clientName") WHERE ((("sessionId")::text <> 'AGG'::text) AND ((address)::text <> 'POOL'::text));
    CREATE INDEX "IDX_e03795301e82c3fd4c0d50f114" ON public.telegram_subscriptions_entity USING btree (address);
    CREATE INDEX "IDX_e15b2d6740ce54f1e231cb0444" ON public.external_shares_entity USING btree (address, "time");
    CREATE INDEX "IDX_e826071cc6839da924a21f8941" ON public.pplns_group_block_history USING btree ("blockHeight");
    CREATE INDEX "IDX_f665b7cf018106f856223ce13e" ON public.pplns_payout_history USING btree ("blockHeight");
    CREATE INDEX "IDX_f7b4fb9f4c89562fb125dc7e56" ON public.pplns_payout_history USING btree (address);
    CREATE INDEX "IDX_fd67b3160c7475d88e1ae5b780" ON public.pplns_group_invitation USING btree ("groupId");
    CREATE INDEX "IDX_ntfy_subscriptions_address" ON public.ntfy_subscriptions_entity USING btree (address);
    CREATE INDEX "IDX_pool_mode_hashrate_mode" ON public.pool_mode_hashrate USING btree (mode);
    CREATE INDEX "IDX_pool_mode_hashrate_time" ON public.pool_mode_hashrate USING btree ("time");
    CREATE INDEX "IDX_pplns_email_verification_expiresAt" ON public.pplns_email_verification USING btree ("expiresAt");
    CREATE INDEX "IDX_pplns_extranonce_challenge_expiresAt" ON public.pplns_extranonce_challenge USING btree ("expiresAt");
    CREATE INDEX "IDX_pplns_group_invitation_expiresAt" ON public.pplns_group_invitation USING btree ("expiresAt");
    CREATE INDEX "IDX_pplns_join_request_address_status" ON public.pplns_group_join_request USING btree (address, status);
    CREATE INDEX "IDX_pplns_join_request_group_status" ON public.pplns_group_join_request USING btree ("groupId", status);
    CREATE INDEX "IDX_pplns_ownership_challenge_expiresAt" ON public.pplns_ownership_challenge USING btree ("expiresAt");
    CREATE INDEX "IDX_ps_address_subtype" ON public.push_subscription_entity USING btree (address, "subscriptionType");
    CREATE INDEX "IDX_ps_network_diff_notifications" ON public.push_subscription_entity USING btree ("subscriptionType") WHERE ("networkDiffNotificationsEnabled" = true);
    CREATE INDEX "IDX_push_subscription_address" ON public.push_subscription_entity USING btree (address);
    CREATE INDEX "IDX_push_subscription_type" ON public.push_subscription_entity USING btree ("subscriptionType");
    CREATE INDEX "IDX_ts_chatid" ON public.telegram_subscriptions_entity USING btree ("telegramChatId");
    CREATE INDEX "IDX_worker_shares_address" ON public.worker_shares_entity USING btree (address);
    CREATE UNIQUE INDEX "UQ_blockparty_group_admin_address_live" ON public.blockparty_group USING btree ("adminAddress") WHERE ((status)::text <> 'dissolved'::text);
    CREATE UNIQUE INDEX "UQ_blockparty_invitation_group_address_pending" ON public.blockparty_invitation USING btree ("groupId", address) WHERE ((status)::text = 'pending'::text);
    CREATE UNIQUE INDEX "UQ_pplns_group_block_history_group_block_address" ON public.pplns_group_block_history USING btree ("groupId", "blockHeight", address);
    CREATE UNIQUE INDEX "UQ_pplns_join_request_group_address_pending" ON public.pplns_group_join_request USING btree ("groupId", address) WHERE ((status)::text = 'pending'::text);
    CREATE UNIQUE INDEX "UQ_pplns_payout_history_block_address" ON public.pplns_payout_history USING btree ("blockHeight", address);
    CREATE INDEX redis_state_backup_captured_at_idx ON public.redis_state_backup USING btree (captured_at DESC);
    ALTER TABLE ONLY public.pplns_group_member
        ADD CONSTRAINT "FK_07dddd1062211639f25291ea478" FOREIGN KEY ("groupId") REFERENCES public.pplns_group(id) ON DELETE CASCADE;
    ALTER TABLE ONLY public.pplns_group_balance
        ADD CONSTRAINT "FK_37ff12a362264511bb753ca3640" FOREIGN KEY ("groupId") REFERENCES public.pplns_group(id) ON DELETE CASCADE;
    ALTER TABLE ONLY public.pplns_group_block_history
        ADD CONSTRAINT "FK_b0d3d46f8123933e60c836eaa80" FOREIGN KEY ("groupId") REFERENCES public.pplns_group(id) ON DELETE CASCADE;
    ALTER TABLE ONLY public.blockparty_block_history
        ADD CONSTRAINT "FK_blockparty_block_history_group" FOREIGN KEY ("groupId") REFERENCES public.blockparty_group(id) ON DELETE CASCADE;
    ALTER TABLE ONLY public.blockparty_invitation
        ADD CONSTRAINT "FK_blockparty_invitation_group" FOREIGN KEY ("groupId") REFERENCES public.blockparty_group(id) ON DELETE CASCADE;
    ALTER TABLE ONLY public.blockparty_member
        ADD CONSTRAINT "FK_blockparty_member_group" FOREIGN KEY ("groupId") REFERENCES public.blockparty_group(id) ON DELETE CASCADE;
    ALTER TABLE ONLY public.pplns_group_invitation
        ADD CONSTRAINT "FK_fd67b3160c7475d88e1ae5b7804" FOREIGN KEY ("groupId") REFERENCES public.pplns_group(id) ON DELETE CASCADE;
END
$baseline$;
