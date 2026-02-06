-- Initial schema for zcash_client_sqlx (PostgreSQL)
-- This schema supports multi-wallet storage with wallet_id in wallet-specific tables.
-- Blockchain-derived data (blocks, commitment trees, nullifier maps) is stored globally
-- since it is identical across all wallets, reducing storage significantly.

-- Enable pgcrypto extension for UUID generation
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ============================================================================
-- Wallets table (multi-wallet support)
-- ============================================================================

CREATE TABLE wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT,
    network TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_wallets_created ON wallets (created_at);

-- ============================================================================
-- Accounts table
-- ============================================================================

CREATE TABLE accounts (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    uuid UUID NOT NULL DEFAULT gen_random_uuid(),
    name TEXT,
    account_kind INTEGER NOT NULL DEFAULT 0,
    key_source TEXT,
    hd_seed_fingerprint BYTEA,
    hd_account_index BIGINT,
    ufvk TEXT,
    uivk TEXT NOT NULL,
    orchard_fvk_item_cache BYTEA,
    sapling_fvk_item_cache BYTEA,
    p2pkh_fvk_item_cache BYTEA,
    birthday_height BIGINT NOT NULL,
    birthday_sapling_tree_size BIGINT,
    birthday_orchard_tree_size BIGINT,
    recover_until_height BIGINT,
    has_spend_key BOOLEAN NOT NULL DEFAULT TRUE,
    zcashd_legacy_address_index INTEGER NOT NULL DEFAULT -1,
    deleted_at TIMESTAMPTZ,
    UNIQUE (wallet_id, uuid),
    CONSTRAINT chk_account_kind CHECK (
        (account_kind = 0 AND hd_seed_fingerprint IS NOT NULL AND hd_account_index IS NOT NULL AND ufvk IS NOT NULL)
        OR
        (account_kind = 1 AND (hd_seed_fingerprint IS NULL) = (hd_account_index IS NULL))
    )
);

CREATE INDEX idx_accounts_wallet_id ON accounts (wallet_id);
CREATE UNIQUE INDEX idx_accounts_ufvk ON accounts (wallet_id, ufvk) WHERE ufvk IS NOT NULL;
CREATE UNIQUE INDEX idx_accounts_uivk ON accounts (wallet_id, uivk);
CREATE UNIQUE INDEX idx_accounts_hd_derivation ON accounts (wallet_id, hd_seed_fingerprint, hd_account_index, zcashd_legacy_address_index)
    WHERE hd_seed_fingerprint IS NOT NULL;

-- ============================================================================
-- Addresses table
-- ============================================================================

CREATE TABLE addresses (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    key_scope INTEGER NOT NULL,
    diversifier_index_be BYTEA,
    address TEXT NOT NULL,
    transparent_child_index INTEGER,
    cached_transparent_receiver_address TEXT,
    exposed_at_height BIGINT,
    receiver_flags INTEGER NOT NULL,
    transparent_receiver_next_check_time BIGINT,
    imported_transparent_receiver_pubkey BYTEA,
    UNIQUE (wallet_id, account_id, key_scope, diversifier_index_be)
);

CREATE INDEX idx_addresses_wallet ON addresses (wallet_id);
CREATE INDEX idx_addresses_account_id ON addresses (account_id);
CREATE INDEX idx_addresses_diversifier ON addresses (diversifier_index_be);
CREATE INDEX idx_addresses_t_indices ON addresses (transparent_child_index);
CREATE UNIQUE INDEX idx_addresses_imported_pubkey ON addresses (wallet_id, imported_transparent_receiver_pubkey) WHERE imported_transparent_receiver_pubkey IS NOT NULL;

-- ============================================================================
-- Blocks table (GLOBAL - shared across all wallets)
-- Block data is identical for all wallets syncing to the same chain.
-- NOTE: Unlike SQLite, we don't include the legacy `sapling_tree` column
-- since this is a fresh PostgreSQL implementation with no migration concerns.
-- ============================================================================

CREATE TABLE blocks (
    height BIGINT PRIMARY KEY,
    hash BYTEA NOT NULL,
    time BIGINT NOT NULL,
    sapling_commitment_tree_size BIGINT,
    orchard_commitment_tree_size BIGINT,
    sapling_output_count BIGINT,
    orchard_action_count BIGINT
);

-- ============================================================================
-- Transactions table
-- ============================================================================

CREATE TABLE transactions (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    txid BYTEA NOT NULL,
    created TIMESTAMPTZ,
    block_height BIGINT,
    mined_height BIGINT,
    tx_index INTEGER,
    expiry_height BIGINT,
    raw BYTEA,
    fee BIGINT,
    target_height BIGINT,
    min_observed_height BIGINT NOT NULL,
    confirmed_unmined_at_height BIGINT,
    trust_status INTEGER DEFAULT 0,
    UNIQUE (wallet_id, txid),
    CONSTRAINT chk_height_consistency CHECK (
        block_height IS NULL OR mined_height = block_height
    ),
    CONSTRAINT chk_unmined_consistency CHECK (
        mined_height IS NULL OR confirmed_unmined_at_height IS NULL
    )
);

CREATE INDEX idx_transactions_wallet_id ON transactions (wallet_id);
CREATE INDEX idx_transactions_block ON transactions (wallet_id, block_height);
CREATE INDEX idx_transactions_mined ON transactions (wallet_id, mined_height);

-- ============================================================================
-- Sapling received notes
-- ============================================================================

CREATE TABLE sapling_received_notes (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    tx_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    output_index INTEGER NOT NULL,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    diversifier BYTEA NOT NULL,
    value BIGINT NOT NULL,
    rcm BYTEA NOT NULL,
    nf BYTEA,
    is_change BOOLEAN NOT NULL DEFAULT FALSE,
    memo BYTEA,
    commitment_tree_position BIGINT,
    recipient_key_scope BIGINT,
    address_id BIGINT REFERENCES addresses(id) ON DELETE SET NULL,
    UNIQUE (wallet_id, tx_id, output_index)
);

CREATE INDEX idx_sapling_received_notes_account ON sapling_received_notes (account_id);
CREATE INDEX idx_sapling_received_notes_tx ON sapling_received_notes (tx_id);
CREATE UNIQUE INDEX idx_sapling_received_notes_nf ON sapling_received_notes (wallet_id, nf) WHERE nf IS NOT NULL;

-- ============================================================================
-- Orchard received notes
-- ============================================================================

CREATE TABLE orchard_received_notes (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    tx_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    action_index INTEGER NOT NULL,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    diversifier BYTEA NOT NULL,
    value BIGINT NOT NULL,
    rho BYTEA NOT NULL,
    rseed BYTEA NOT NULL,
    nf BYTEA,
    is_change BOOLEAN NOT NULL DEFAULT FALSE,
    memo BYTEA,
    commitment_tree_position BIGINT,
    recipient_key_scope BIGINT,
    address_id BIGINT REFERENCES addresses(id) ON DELETE SET NULL,
    UNIQUE (wallet_id, tx_id, action_index)
);

CREATE INDEX idx_orchard_received_notes_account ON orchard_received_notes (account_id);
CREATE INDEX idx_orchard_received_notes_tx ON orchard_received_notes (tx_id);
CREATE UNIQUE INDEX idx_orchard_received_notes_nf ON orchard_received_notes (wallet_id, nf) WHERE nf IS NOT NULL;

-- ============================================================================
-- Transparent received outputs (UTXOs)
-- ============================================================================

CREATE TABLE transparent_received_outputs (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    tx_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    output_index INTEGER NOT NULL,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address_id BIGINT NOT NULL REFERENCES addresses(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    script BYTEA NOT NULL,
    value_zat BIGINT NOT NULL,
    max_observed_unspent_height BIGINT,
    UNIQUE (wallet_id, tx_id, output_index)
);

CREATE INDEX idx_transparent_outputs_account ON transparent_received_outputs (account_id);
CREATE INDEX idx_transparent_outputs_tx ON transparent_received_outputs (tx_id);
CREATE INDEX idx_transparent_outputs_address ON transparent_received_outputs (address);

-- ============================================================================
-- Sent notes (outputs we sent)
-- ============================================================================

CREATE TABLE sent_notes (
    id BIGSERIAL PRIMARY KEY,
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    tx_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    output_pool INTEGER NOT NULL,
    output_index INTEGER NOT NULL,
    from_account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    to_address TEXT,
    to_account_id BIGINT REFERENCES accounts(id) ON DELETE SET NULL,
    value BIGINT NOT NULL,
    memo BYTEA,
    UNIQUE (wallet_id, tx_id, output_pool, output_index)
);

CREATE INDEX idx_sent_notes_from_account ON sent_notes (from_account_id);
CREATE INDEX idx_sent_notes_to_account ON sent_notes (to_account_id) WHERE to_account_id IS NOT NULL;
CREATE INDEX idx_sent_notes_tx ON sent_notes (tx_id);

-- ============================================================================
-- Sapling received note spends (tracks which transactions spent which notes)
-- ============================================================================

CREATE TABLE sapling_received_note_spends (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    sapling_received_note_id BIGINT NOT NULL REFERENCES sapling_received_notes(id) ON DELETE CASCADE,
    transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    PRIMARY KEY (wallet_id, sapling_received_note_id, transaction_id)
);

CREATE INDEX idx_sapling_spends_note ON sapling_received_note_spends (sapling_received_note_id);
CREATE INDEX idx_sapling_spends_tx ON sapling_received_note_spends (transaction_id);

-- ============================================================================
-- Orchard received note spends (tracks which transactions spent which notes)
-- ============================================================================

CREATE TABLE orchard_received_note_spends (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    orchard_received_note_id BIGINT NOT NULL REFERENCES orchard_received_notes(id) ON DELETE CASCADE,
    transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    PRIMARY KEY (wallet_id, orchard_received_note_id, transaction_id)
);

CREATE INDEX idx_orchard_spends_note ON orchard_received_note_spends (orchard_received_note_id);
CREATE INDEX idx_orchard_spends_tx ON orchard_received_note_spends (transaction_id);

-- ============================================================================
-- Transparent received output spends (tracks which transactions spent which UTXOs)
-- ============================================================================

CREATE TABLE transparent_received_output_spends (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    transparent_received_output_id BIGINT NOT NULL REFERENCES transparent_received_outputs(id) ON DELETE CASCADE,
    transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    PRIMARY KEY (wallet_id, transparent_received_output_id, transaction_id)
);

CREATE INDEX idx_transparent_spends_output ON transparent_received_output_spends (transparent_received_output_id);
CREATE INDEX idx_transparent_spends_tx ON transparent_received_output_spends (transaction_id);

-- ============================================================================
-- Ephemeral addresses (ZIP 320)
-- ============================================================================

CREATE TABLE ephemeral_addresses (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    address_index INTEGER NOT NULL,
    address TEXT,
    used_in_tx BIGINT REFERENCES transactions(id) ON DELETE SET NULL,
    seen_in_tx BIGINT REFERENCES transactions(id) ON DELETE SET NULL,
    PRIMARY KEY (wallet_id, account_id, address_index)
);

CREATE UNIQUE INDEX idx_ephemeral_addresses_address ON ephemeral_addresses (wallet_id, address) WHERE address IS NOT NULL;

-- ============================================================================
-- Sapling note commitment tree shards (GLOBAL - shared across all wallets)
-- The commitment tree represents on-chain state, identical for all wallets.
-- ============================================================================

CREATE TABLE sapling_tree_shards (
    shard_index BIGINT PRIMARY KEY,
    subtree_end_height BIGINT,
    root_hash BYTEA,
    shard_data BYTEA
);

CREATE UNIQUE INDEX idx_sapling_shards_root ON sapling_tree_shards (root_hash) WHERE root_hash IS NOT NULL;

CREATE TABLE sapling_tree_cap (
    cap_id INTEGER PRIMARY KEY DEFAULT 0,
    cap_data BYTEA NOT NULL
);

CREATE TABLE sapling_tree_checkpoints (
    checkpoint_id BIGINT PRIMARY KEY,
    position BIGINT
);

CREATE TABLE sapling_tree_checkpoint_marks (
    checkpoint_id BIGINT NOT NULL REFERENCES sapling_tree_checkpoints(checkpoint_id) ON DELETE CASCADE,
    mark_position BIGINT NOT NULL,
    PRIMARY KEY (checkpoint_id, mark_position)
);

-- ============================================================================
-- Orchard note commitment tree shards (GLOBAL - shared across all wallets)
-- The commitment tree represents on-chain state, identical for all wallets.
-- ============================================================================

CREATE TABLE orchard_tree_shards (
    shard_index BIGINT PRIMARY KEY,
    subtree_end_height BIGINT,
    root_hash BYTEA,
    shard_data BYTEA
);

CREATE UNIQUE INDEX idx_orchard_shards_root ON orchard_tree_shards (root_hash) WHERE root_hash IS NOT NULL;

CREATE TABLE orchard_tree_cap (
    cap_id INTEGER PRIMARY KEY DEFAULT 0,
    cap_data BYTEA NOT NULL
);

CREATE TABLE orchard_tree_checkpoints (
    checkpoint_id BIGINT PRIMARY KEY,
    position BIGINT
);

CREATE TABLE orchard_tree_checkpoint_marks (
    checkpoint_id BIGINT NOT NULL REFERENCES orchard_tree_checkpoints(checkpoint_id) ON DELETE CASCADE,
    mark_position BIGINT NOT NULL,
    PRIMARY KEY (checkpoint_id, mark_position)
);

-- ============================================================================
-- Scan queue for tracking what needs to be scanned
-- ============================================================================

CREATE TABLE scan_queue (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    block_range_start BIGINT NOT NULL,
    block_range_end BIGINT NOT NULL,
    priority BIGINT NOT NULL,
    PRIMARY KEY (wallet_id, block_range_start),
    UNIQUE (wallet_id, block_range_end),
    CONSTRAINT chk_range_valid CHECK (block_range_start < block_range_end)
);

CREATE INDEX idx_scan_queue_priority ON scan_queue (wallet_id, priority DESC);

-- ============================================================================
-- Nullifier map for spend detection (GLOBAL - shared across all wallets)
-- Nullifiers are revealed when anyone spends a note on-chain.
-- All wallets observing the same blocks see the same nullifiers.
-- ============================================================================

CREATE TABLE sapling_nullifier_map (
    spend_pool INTEGER NOT NULL,
    nf BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    tx_index INTEGER NOT NULL
);

CREATE INDEX idx_sapling_nfmap_height ON sapling_nullifier_map (block_height);

CREATE TABLE orchard_nullifier_map (
    spend_pool INTEGER NOT NULL,
    nf BYTEA PRIMARY KEY,
    block_height BIGINT NOT NULL,
    tx_index INTEGER NOT NULL
);

CREATE INDEX idx_orchard_nfmap_height ON orchard_nullifier_map (block_height);

-- ============================================================================
-- Transaction data requests queue
-- ============================================================================

CREATE TABLE tx_retrieval_queue (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    txid BYTEA NOT NULL,
    query_type INTEGER NOT NULL,
    dependent_transaction_id BIGINT REFERENCES transactions(id) ON DELETE CASCADE,
    PRIMARY KEY (wallet_id, txid)
);

CREATE INDEX idx_tx_retrieval_dependent ON tx_retrieval_queue (dependent_transaction_id);

-- ============================================================================
-- Transparent spend search queue
-- ============================================================================

CREATE TABLE transparent_spend_search_queue (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    address TEXT NOT NULL,
    transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    output_index INTEGER NOT NULL,
    PRIMARY KEY (wallet_id, transaction_id, output_index)
);

CREATE INDEX idx_transparent_search_tx ON transparent_spend_search_queue (transaction_id);

-- ============================================================================
-- Transparent spend map
-- ============================================================================

CREATE TABLE transparent_spend_map (
    wallet_id UUID NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    spending_transaction_id BIGINT NOT NULL REFERENCES transactions(id) ON DELETE CASCADE,
    prevout_txid BYTEA NOT NULL,
    prevout_output_index INTEGER NOT NULL,
    PRIMARY KEY (wallet_id, spending_transaction_id, prevout_txid, prevout_output_index)
);

CREATE INDEX idx_transparent_spend_map_tx ON transparent_spend_map (spending_transaction_id);

-- ============================================================================
-- Views for transaction listing and reporting
-- ============================================================================

-- Union of all received outputs across pools, with sent_note linkage
CREATE VIEW v_received_outputs AS
    SELECT
        sapling_received_notes.id AS id_within_pool_table,
        sapling_received_notes.tx_id AS transaction_id,
        sapling_received_notes.wallet_id,
        2 AS pool,
        sapling_received_notes.output_index,
        sapling_received_notes.account_id,
        sapling_received_notes.value,
        sapling_received_notes.is_change,
        sapling_received_notes.memo,
        sent_notes.id AS sent_note_id,
        sapling_received_notes.address_id
    FROM sapling_received_notes
    LEFT JOIN sent_notes
        ON sent_notes.tx_id = sapling_received_notes.tx_id
        AND sent_notes.output_pool = 2
        AND sent_notes.output_index = sapling_received_notes.output_index
UNION ALL
    SELECT
        orchard_received_notes.id AS id_within_pool_table,
        orchard_received_notes.tx_id AS transaction_id,
        orchard_received_notes.wallet_id,
        3 AS pool,
        orchard_received_notes.action_index AS output_index,
        orchard_received_notes.account_id,
        orchard_received_notes.value,
        orchard_received_notes.is_change,
        orchard_received_notes.memo,
        sent_notes.id AS sent_note_id,
        orchard_received_notes.address_id
    FROM orchard_received_notes
    LEFT JOIN sent_notes
        ON sent_notes.tx_id = orchard_received_notes.tx_id
        AND sent_notes.output_pool = 3
        AND sent_notes.output_index = orchard_received_notes.action_index
UNION ALL
    SELECT
        u.id AS id_within_pool_table,
        u.tx_id AS transaction_id,
        u.wallet_id,
        0 AS pool,
        u.output_index,
        u.account_id,
        u.value_zat AS value,
        FALSE AS is_change,
        NULL AS memo,
        sent_notes.id AS sent_note_id,
        u.address_id
    FROM transparent_received_outputs u
    LEFT JOIN sent_notes
        ON sent_notes.tx_id = u.tx_id
        AND sent_notes.output_pool = 0
        AND sent_notes.output_index = u.output_index;

-- Union of all received output spends across pools
CREATE VIEW v_received_output_spends AS
    SELECT
        2 AS pool,
        s.sapling_received_note_id AS received_output_id,
        s.transaction_id,
        rn.account_id
    FROM sapling_received_note_spends s
    JOIN sapling_received_notes rn ON rn.id = s.sapling_received_note_id
UNION ALL
    SELECT
        3 AS pool,
        s.orchard_received_note_id AS received_output_id,
        s.transaction_id,
        rn.account_id
    FROM orchard_received_note_spends s
    JOIN orchard_received_notes rn ON rn.id = s.orchard_received_note_id
UNION ALL
    SELECT
        0 AS pool,
        s.transparent_received_output_id AS received_output_id,
        s.transaction_id,
        rn.account_id
    FROM transparent_received_output_spends s
    JOIN transparent_received_outputs rn ON rn.id = s.transparent_received_output_id;

-- Summarized transaction view per account
CREATE VIEW v_transactions AS
WITH
notes AS (
    -- Outputs received in this transaction
    SELECT ro.account_id              AS account_id,
           ro.wallet_id               AS wallet_id,
           transactions.mined_height  AS mined_height,
           transactions.txid          AS txid,
           ro.pool                    AS pool,
           id_within_pool_table,
           ro.value                   AS value,
           ro.value                   AS received_value,
           0::bigint                  AS spent_value,
           0                          AS spent_note_count,
           CASE WHEN ro.is_change THEN 1 ELSE 0 END AS change_note_count,
           CASE WHEN ro.is_change THEN 0 ELSE 1 END AS received_count,
           CASE
             WHEN (ro.memo IS NULL OR ro.memo = E'\\xF6'::bytea)
               THEN 0 ELSE 1
           END AS memo_present,
           CASE WHEN ro.pool = 0 THEN 1 ELSE 0 END AS does_not_match_shielding
    FROM v_received_outputs ro
    JOIN transactions ON transactions.id = ro.transaction_id
UNION ALL
    -- Outputs spent in this transaction
    SELECT ro.account_id              AS account_id,
           ro.wallet_id               AS wallet_id,
           transactions.mined_height  AS mined_height,
           transactions.txid          AS txid,
           ro.pool                    AS pool,
           id_within_pool_table,
           -ro.value                  AS value,
           0::bigint                  AS received_value,
           ro.value                   AS spent_value,
           1                          AS spent_note_count,
           0                          AS change_note_count,
           0                          AS received_count,
           0                          AS memo_present,
           CASE WHEN ro.pool != 0 THEN 1 ELSE 0 END AS does_not_match_shielding
    FROM v_received_outputs ro
    JOIN v_received_output_spends ros
         ON ros.pool = ro.pool
         AND ros.received_output_id = ro.id_within_pool_table
    JOIN transactions ON transactions.id = ros.transaction_id
),
sent_note_counts AS (
    SELECT sent_notes.from_account_id     AS account_id,
           transactions.txid              AS txid,
           COUNT(DISTINCT sent_notes.id)  AS sent_notes,
           SUM(
             CASE
               WHEN (sent_notes.memo IS NULL OR sent_notes.memo = E'\\xF6'::bytea OR ro.transaction_id IS NOT NULL)
                 THEN 0 ELSE 1
             END
           ) AS memo_count
    FROM sent_notes
    JOIN transactions ON transactions.id = sent_notes.tx_id
    LEFT JOIN v_received_outputs ro ON sent_notes.id = ro.sent_note_id
    WHERE COALESCE(ro.is_change, FALSE) = FALSE
    GROUP BY sent_notes.from_account_id, transactions.txid
),
blocks_max_height AS (
    SELECT MAX(blocks.height) AS max_height FROM blocks
)
SELECT accounts.uuid                AS account_uuid,
       notes.wallet_id              AS wallet_id,
       notes.mined_height           AS mined_height,
       notes.txid                   AS txid,
       transactions.tx_index        AS tx_index,
       transactions.expiry_height   AS expiry_height,
       transactions.raw             AS raw,
       SUM(notes.value)             AS account_balance_delta,
       SUM(notes.spent_value)       AS total_spent,
       SUM(notes.received_value)    AS total_received,
       transactions.fee             AS fee_paid,
       (SUM(notes.change_note_count) > 0)  AS has_change,
       MAX(COALESCE(sent_note_counts.sent_notes, 0))  AS sent_note_count,
       SUM(notes.received_count)         AS received_note_count,
       SUM(notes.memo_present) + MAX(COALESCE(sent_note_counts.memo_count, 0)) AS memo_count,
       blocks.time                       AS block_time,
       (
            notes.mined_height IS NULL
            AND transactions.expiry_height > 0
            AND transactions.expiry_height <= blocks_max_height.max_height
       ) AS expired_unmined,
       SUM(notes.spent_note_count) AS spent_note_count
FROM notes
LEFT JOIN accounts ON accounts.id = notes.account_id
LEFT JOIN transactions
     ON notes.txid = transactions.txid AND notes.wallet_id = transactions.wallet_id
CROSS JOIN blocks_max_height
LEFT JOIN blocks ON blocks.height = notes.mined_height
LEFT JOIN sent_note_counts
     ON sent_note_counts.account_id = notes.account_id
     AND sent_note_counts.txid = notes.txid
GROUP BY notes.wallet_id, notes.account_id, notes.txid,
         accounts.uuid, transactions.tx_index, transactions.expiry_height,
         transactions.raw, transactions.fee, blocks.time, notes.mined_height,
         blocks_max_height.max_height;

-- Detailed transaction outputs view
CREATE VIEW v_tx_outputs AS
WITH unioned AS (
    SELECT t.id                         AS transaction_id,
           t.wallet_id                  AS wallet_id,
           t.txid                       AS txid,
           t.mined_height               AS mined_height,
           COALESCE(t.trust_status, 0)  AS trust_status,
           ro.pool                      AS output_pool,
           ro.output_index              AS output_index,
           from_account.uuid            AS from_account_uuid,
           to_account.uuid              AS to_account_uuid,
           a.address                    AS to_address,
           a.diversifier_index_be       AS diversifier_index_be,
           ro.value                     AS value,
           ro.is_change                 AS is_change,
           ro.memo                      AS memo,
           a.key_scope                  AS recipient_key_scope
    FROM v_received_outputs ro
    JOIN transactions t ON t.id = ro.transaction_id
    LEFT JOIN addresses a ON a.id = ro.address_id
    LEFT JOIN sent_notes ON sent_notes.id = ro.sent_note_id
    LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
    LEFT JOIN accounts to_account ON to_account.id = ro.account_id
UNION ALL
    SELECT t.id                         AS transaction_id,
           t.wallet_id                  AS wallet_id,
           t.txid                       AS txid,
           t.mined_height               AS mined_height,
           COALESCE(t.trust_status, 0)  AS trust_status,
           sent_notes.output_pool       AS output_pool,
           sent_notes.output_index      AS output_index,
           from_account.uuid            AS from_account_uuid,
           NULL::uuid                   AS to_account_uuid,
           sent_notes.to_address        AS to_address,
           NULL::bytea                  AS diversifier_index_be,
           sent_notes.value             AS value,
           FALSE                        AS is_change,
           sent_notes.memo              AS memo,
           NULL::integer                AS recipient_key_scope
    FROM sent_notes
    JOIN transactions t ON t.id = sent_notes.tx_id
    LEFT JOIN v_received_outputs ro ON ro.sent_note_id = sent_notes.id
    LEFT JOIN accounts from_account ON from_account.id = sent_notes.from_account_id
    WHERE ro.sent_note_id IS NULL
)
SELECT
    transaction_id,
    wallet_id,
    (array_agg(txid))[1]                   AS txid,
    MAX(mined_height)                      AS tx_mined_height,
    MIN(trust_status)                      AS tx_trust_status,
    output_pool,
    output_index,
    (array_agg(from_account_uuid))[1]      AS from_account_uuid,
    (array_agg(to_account_uuid))[1]        AS to_account_uuid,
    MAX(to_address)                        AS to_address,
    MAX(value)                             AS value,
    BOOL_OR(is_change)                     AS is_change,
    (array_agg(memo))[1]                   AS memo,
    MAX(recipient_key_scope)               AS recipient_key_scope
FROM unioned
GROUP BY transaction_id, wallet_id, output_pool, output_index;
