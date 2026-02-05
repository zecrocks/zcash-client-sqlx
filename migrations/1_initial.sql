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
    priority INTEGER NOT NULL,
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
