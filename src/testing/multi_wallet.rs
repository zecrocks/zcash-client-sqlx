//! Multi-wallet test infrastructure for PostgreSQL backend.
//!
//! This module provides testing utilities for scenarios involving multiple wallets
//! sharing the same PostgreSQL database. Unlike `TestDbFactory` which creates a new
//! database per wallet, `MultiWalletTestEnv` creates ONE database with MULTIPLE wallets.
#![allow(dead_code, unused_variables, unused_imports, clippy::comparison_chain)]
//!
//! ## Block Generation
//!
//! This module provides block generation capabilities for testing note detection,
//! balance tracking, and reorg handling across multiple wallets. Use the
//! `generate_next_block_*` methods to create blocks with shielded outputs.

use std::collections::BTreeMap;

use rand::{CryptoRng, RngCore, SeedableRng};
use rand_chacha::ChaChaRng;
use secrecy::{Secret, SecretVec};
use tokio::runtime::Runtime;

use sapling::zip32::DiversifiableFullViewingKey;
use zcash_client_backend::{
    data_api::{
        AccountBirthday, WalletRead, WalletWrite,
        chain::{ChainState, ScanSummary, scan_cached_blocks},
        testing::{AddressType, TestCache, TestFvk},
        wallet::ConfirmationsPolicy,
    },
    proto::compact_formats::{ChainMetadata, CompactBlock, CompactTx},
};

#[cfg(feature = "orchard")]
use ::orchard::keys::FullViewingKey as OrchardFullViewingKey;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_primitives::block::BlockHash;
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    local_consensus::LocalNetwork,
    value::Zatoshis,
};

#[cfg(feature = "orchard")]
use orchard::tree::MerkleHashOrchard;

use crate::{
    AccountUuid, Pool, SqlxClientError, WalletDb, WalletId,
    init::init_wallet_db,
    pool::{PoolConfig, create_pool},
    wallet::create_wallet,
};

use super::{
    BlockCacheWithSource, MemoryBlockSource,
    db::{get_or_start_container, unique_db_name},
};

// ============================================================================
// Local cached block tracking
// ============================================================================

/// Local version of CachedBlock that tracks chain state for block generation.
///
/// Since `zcash_client_backend::data_api::testing::CachedBlock` doesn't expose
/// `chain_state` or `roll_forward`, we maintain our own tracking.
#[derive(Clone)]
struct LocalCachedBlock {
    chain_state: ChainState,
    sapling_end_size: u32,
    orchard_end_size: u32,
}

impl LocalCachedBlock {
    /// Create a block representing the state before any shielded activity.
    fn none(block_height: BlockHeight) -> Self {
        Self {
            chain_state: ChainState::empty(block_height, BlockHash([0; 32])),
            sapling_end_size: 0,
            orchard_end_size: 0,
        }
    }

    fn height(&self) -> BlockHeight {
        self.chain_state.block_height()
    }

    fn chain_state(&self) -> &ChainState {
        &self.chain_state
    }

    fn sapling_end_size(&self) -> u32 {
        self.sapling_end_size
    }

    fn orchard_end_size(&self) -> u32 {
        self.orchard_end_size
    }

    /// Roll forward the cached block state based on a new compact block.
    fn roll_forward(&self, cb: &CompactBlock) -> Self {
        assert_eq!(self.chain_state.block_height() + 1, cb.height());

        // Build new Sapling tree state
        let sapling_final_tree = cb.vtx.iter().flat_map(|tx| tx.outputs.iter()).fold(
            self.chain_state.final_sapling_tree().clone(),
            |mut acc, c_out| {
                if let Ok(cmu) = c_out.cmu() {
                    acc.append(::sapling::Node::from_cmu(&cmu));
                }
                acc
            },
        );
        let sapling_end_size = sapling_final_tree.tree_size() as u32;

        #[cfg(feature = "orchard")]
        let orchard_final_tree = cb.vtx.iter().flat_map(|tx| tx.actions.iter()).fold(
            self.chain_state.final_orchard_tree().clone(),
            |mut acc, c_act| {
                if let Ok(cmx) = c_act.cmx() {
                    acc.append(MerkleHashOrchard::from_cmx(&cmx));
                }
                acc
            },
        );
        #[cfg(feature = "orchard")]
        let orchard_end_size = orchard_final_tree.tree_size() as u32;

        #[cfg(not(feature = "orchard"))]
        let orchard_end_size = cb.vtx.iter().fold(self.orchard_end_size, |sz, tx| {
            sz + (tx.actions.len() as u32)
        });

        Self {
            chain_state: ChainState::new(
                cb.height(),
                cb.hash(),
                sapling_final_tree,
                #[cfg(feature = "orchard")]
                orchard_final_tree,
            ),
            sapling_end_size,
            orchard_end_size,
        }
    }
}

// ============================================================================
// Helper functions for block generation
// ============================================================================

/// Create a fake CompactTx with a random txid.
fn fake_compact_tx<R: RngCore + CryptoRng>(rng: &mut R) -> CompactTx {
    let mut ctx = CompactTx::default();
    let mut txid = vec![0; 32];
    rng.fill_bytes(&mut txid);
    ctx.txid = txid;
    ctx
}

/// Create a fake CompactBlock from a CompactTx.
fn fake_compact_block_from_compact_tx(
    ctx: CompactTx,
    height: BlockHeight,
    prev_hash: BlockHash,
    initial_sapling_tree_size: u32,
    initial_orchard_tree_size: u32,
) -> CompactBlock {
    let mut hash = [0u8; 32];
    // Use height as a simple deterministic hash for tests
    hash[0..4].copy_from_slice(&u32::from(height).to_le_bytes());

    let sapling_outputs_count: u32 = ctx.outputs.len() as u32;
    let orchard_actions_count: u32 = ctx.actions.len() as u32;

    CompactBlock {
        hash: hash.to_vec(),
        height: height.into(),
        prev_hash: prev_hash.0.to_vec(),
        vtx: vec![ctx],
        chain_metadata: Some(ChainMetadata {
            sapling_commitment_tree_size: initial_sapling_tree_size + sapling_outputs_count,
            orchard_commitment_tree_size: initial_orchard_tree_size + orchard_actions_count,
        }),
        ..Default::default()
    }
}

/// Creates a LocalNetwork configured for testing with all upgrades at height 1.
fn test_network() -> LocalNetwork {
    let height = Some(BlockHeight::from_u32(1));
    LocalNetwork {
        overwinter: height,
        sapling: height,
        blossom: height,
        heartwood: height,
        canopy: height,
        nu5: height,
        nu6: height,
        nu6_1: None, // Not yet activated in tests
    }
}

/// A test account stored in a wallet.
#[allow(dead_code)]
pub struct TestAccount {
    pub account_uuid: AccountUuid,
    pub usk: UnifiedSpendingKey,
    pub birthday: AccountBirthday,
    pub seed: SecretVec<u8>,
}

/// Multi-wallet test environment for PostgreSQL.
///
/// This environment manages multiple `WalletDb` instances sharing the same database,
/// allowing testing of multi-wallet scenarios like:
/// - Wallet isolation
/// - Shared blockchain data (blocks, commitment trees)
/// - Concurrent operations
/// - Reorgs affecting multiple wallets
/// - Note detection isolation
/// - Balance tracking across wallets
pub struct MultiWalletTestEnv {
    pool: Pool,
    wallets: Vec<WalletDb<LocalNetwork>>,
    accounts: Vec<Option<TestAccount>>,
    network: LocalNetwork,
    runtime: Runtime,
    db_name: String,
    admin_pool: Pool,
    #[allow(dead_code)]
    container_url: String,

    // Block generation infrastructure
    cache: BlockCacheWithSource,
    cached_blocks: BTreeMap<BlockHeight, LocalCachedBlock>,
    latest_block_height: Option<BlockHeight>,
    rng: ChaChaRng,
}

impl MultiWalletTestEnv {
    /// Creates a new multi-wallet test environment with the specified number of wallets.
    ///
    /// All wallets share the same database.
    pub fn new(wallet_count: usize) -> Result<Self, SqlxClientError> {
        let network = test_network();

        let runtime = Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;

        let container_url = runtime.block_on(async {
            let container = get_or_start_container().await;
            let host = container.get_host().await.unwrap();
            let port = container.get_host_port_ipv4(5432).await.unwrap();
            format!("postgres://postgres:postgres@{}:{}", host, port)
        });

        let db_name = unique_db_name();

        // Create database using a separate connection
        runtime.block_on(async {
            let admin_url = format!("{}/postgres", container_url);
            let admin_pool = create_pool(
                &admin_url,
                &PoolConfig {
                    max_connections: 2,
                    min_connections: 1,
                    acquire_timeout_secs: 30,
                    max_lifetime_secs: None,
                    idle_timeout_secs: None,
                },
            )
            .await?;

            sqlx_core::query::query(&format!("CREATE DATABASE \"{}\"", db_name))
                .execute(&admin_pool)
                .await?;

            Ok::<_, SqlxClientError>(())
        })?;

        // Now create pools in the test runtime
        let (pool, admin_pool, wallets) = runtime.block_on(async {
            let admin_url = format!("{}/postgres", container_url);
            let admin_pool = create_pool(
                &admin_url,
                &PoolConfig {
                    max_connections: 2,
                    min_connections: 1,
                    acquire_timeout_secs: 30,
                    max_lifetime_secs: None,
                    idle_timeout_secs: None,
                },
            )
            .await?;

            let db_url = format!("{}/{}", container_url, db_name);
            let pool = create_pool(
                &db_url,
                &PoolConfig {
                    max_connections: 10,
                    min_connections: 1,
                    acquire_timeout_secs: 30,
                    max_lifetime_secs: None,
                    idle_timeout_secs: None,
                },
            )
            .await?;

            // Initialize the database schema
            init_wallet_db(&pool).await?;

            // Create wallets
            let handle = tokio::runtime::Handle::current();
            let mut wallets = Vec::with_capacity(wallet_count);

            for i in 0..wallet_count {
                let wallet_id =
                    create_wallet(&pool, &network, Some(&format!("wallet_{}", i))).await?;
                let wallet_db = WalletDb::for_wallet_with_handle(
                    pool.clone(),
                    wallet_id,
                    network,
                    handle.clone(),
                );
                wallets.push(wallet_db);
            }

            Ok::<_, SqlxClientError>((pool, admin_pool, wallets))
        })?;

        let mut accounts = Vec::with_capacity(wallet_count);
        for _ in 0..wallet_count {
            accounts.push(None);
        }

        Ok(Self {
            pool,
            wallets,
            accounts,
            network,
            runtime,
            db_name,
            admin_pool,
            container_url,
            cache: BlockCacheWithSource::new(),
            cached_blocks: BTreeMap::new(),
            latest_block_height: None,
            rng: ChaChaRng::from_seed([0u8; 32]),
        })
    }

    /// Returns a reference to the wallet at the given index.
    pub fn wallet(&self, idx: usize) -> &WalletDb<LocalNetwork> {
        &self.wallets[idx]
    }

    /// Returns a mutable reference to the wallet at the given index.
    #[allow(dead_code)]
    pub fn wallet_mut(&mut self, idx: usize) -> &mut WalletDb<LocalNetwork> {
        &mut self.wallets[idx]
    }

    /// Returns the number of wallets in this environment.
    pub fn wallet_count(&self) -> usize {
        self.wallets.len()
    }

    /// Returns the network parameters.
    pub fn network(&self) -> &LocalNetwork {
        &self.network
    }

    /// Returns a reference to the shared connection pool.
    #[allow(dead_code)]
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Returns a reference to the test account for the specified wallet, if one exists.
    #[allow(dead_code)]
    pub fn test_account(&self, wallet_idx: usize) -> Option<&TestAccount> {
        self.accounts[wallet_idx].as_ref()
    }

    /// Returns the Sapling activation height.
    pub fn sapling_activation_height(&self) -> BlockHeight {
        self.network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling)
            .expect("Sapling activation height should be set")
    }

    /// Creates an account in the specified wallet.
    ///
    /// The account will have a unique seed based on the wallet index.
    pub fn create_account(
        &mut self,
        wallet_idx: usize,
        birthday: AccountBirthday,
    ) -> Result<&TestAccount, SqlxClientError> {
        // Create a unique seed for this wallet's account
        let seed = Secret::new(vec![wallet_idx as u8; 32]);

        let wallet = &mut self.wallets[wallet_idx];
        let (account_uuid, usk) = wallet.create_account("", &seed, &birthday, None)?;

        self.accounts[wallet_idx] = Some(TestAccount {
            account_uuid,
            usk,
            birthday,
            seed,
        });

        Ok(self.accounts[wallet_idx].as_ref().unwrap())
    }

    /// Scans cached blocks for the specified wallet.
    ///
    /// Uses the provided block source and chain state.
    #[allow(dead_code)]
    pub fn scan_for_wallet<BS>(
        &mut self,
        wallet_idx: usize,
        block_source: &BS,
        from_height: BlockHeight,
        prior_chain_state: &ChainState,
        limit: usize,
    ) -> Result<ScanSummary, SqlxClientError>
    where
        BS: zcash_client_backend::data_api::chain::BlockSource<Error = SqlxClientError>,
    {
        let wallet = &mut self.wallets[wallet_idx];

        scan_cached_blocks(
            &self.network,
            block_source,
            wallet,
            from_height,
            prior_chain_state,
            limit,
        )
        .map_err(|e| match e {
            zcash_client_backend::data_api::chain::error::Error::Wallet(e) => e,
            zcash_client_backend::data_api::chain::error::Error::BlockSource(e) => e,
            zcash_client_backend::data_api::chain::error::Error::Scan(e) => {
                SqlxClientError::Encoding(format!("Scan error: {:?}", e))
            }
        })
    }

    /// Truncates all wallets to the specified height (simulates a reorg).
    pub fn truncate_all_to_height(&mut self, height: BlockHeight) -> Result<(), SqlxClientError> {
        use zcash_client_backend::data_api::WalletWrite;

        for wallet in &mut self.wallets {
            wallet.truncate_to_height(height)?;
        }
        Ok(())
    }

    /// Returns the wallet ID for the specified wallet index.
    pub fn wallet_id(&self, idx: usize) -> WalletId {
        self.wallets[idx].wallet_id()
    }

    // ========================================================================
    // Block Generation Infrastructure
    // ========================================================================

    /// Returns a reference to the block source for scanning.
    pub fn block_source(&self) -> &MemoryBlockSource {
        self.cache.block_source()
    }

    /// Returns the latest cached block, or a "pre-sapling" block if none exists.
    ///
    /// The initial block is at `sapling_activation_height()`, so the first generated
    /// block will be at `sapling_activation_height() + 1`.
    fn latest_cached_block(&self) -> LocalCachedBlock {
        self.cached_blocks
            .values()
            .last()
            .cloned()
            .unwrap_or_else(|| LocalCachedBlock::none(self.sapling_activation_height()))
    }

    /// Returns the chain state at the start of scanning (before any blocks).
    ///
    /// This is the state at `sapling_activation_height()`, which means the first
    /// scannable block is at `sapling_activation_height() + 1`.
    pub fn initial_chain_state(&self) -> ChainState {
        ChainState::empty(self.sapling_activation_height(), BlockHash([0; 32]))
    }

    /// Returns the height of the first generated block.
    pub fn first_block_height(&self) -> BlockHeight {
        self.sapling_activation_height() + 1
    }

    /// Generate a block with a Sapling output to the specified wallet's account.
    ///
    /// Returns (height, nullifier).
    pub fn generate_next_block_for_wallet(
        &mut self,
        wallet_idx: usize,
        value: Zatoshis,
    ) -> (BlockHeight, sapling::Nullifier) {
        let (height, nfs) = self.generate_next_block_multi(&[(wallet_idx, value)]);
        (height, nfs[0])
    }

    /// Generate a block with outputs to multiple wallets.
    ///
    /// Each tuple is (wallet_idx, value).
    /// Returns (height, Vec<nullifiers>).
    pub fn generate_next_block_multi(
        &mut self,
        outputs: &[(usize, Zatoshis)],
    ) -> (BlockHeight, Vec<sapling::Nullifier>) {
        let prior = self.latest_cached_block();
        let height = prior.height() + 1;

        // Collect the DFVKs and values we need
        let wallet_outputs: Vec<(DiversifiableFullViewingKey, Zatoshis)> = outputs
            .iter()
            .map(|(wallet_idx, value)| {
                let account = self.accounts[*wallet_idx]
                    .as_ref()
                    .expect("account must exist for wallet");
                let dfvk = account.usk.sapling().to_diversifiable_full_viewing_key();
                (dfvk, *value)
            })
            .collect();

        // Generate the compact block with outputs
        let mut ctx = fake_compact_tx(&mut self.rng);
        let mut nfs = vec![];

        for (dfvk, value) in &wallet_outputs {
            let initial_sapling_tree_size = prior.sapling_end_size() + ctx.outputs.len() as u32;
            let nf = dfvk.add_output(
                &mut ctx,
                &self.network,
                height,
                None, // No sender OVK needed for test outputs
                AddressType::DefaultExternal,
                *value,
                initial_sapling_tree_size,
                &mut self.rng,
            );
            nfs.push(nf);
        }

        let cb = fake_compact_block_from_compact_tx(
            ctx,
            height,
            prior.chain_state().block_hash(),
            prior.sapling_end_size(),
            prior.orchard_end_size(),
        );

        // Roll forward cached block state
        let new_cached_block = prior.roll_forward(&cb);
        self.cached_blocks.insert(height, new_cached_block);

        // Insert into block cache
        self.cache.insert(&cb);
        self.latest_block_height = Some(height);

        (height, nfs)
    }

    /// Generate an empty block (advances chain without adding notes).
    pub fn generate_empty_block(&mut self) -> BlockHeight {
        let prior = self.latest_cached_block();
        let height = prior.height() + 1;

        let cb = self.create_empty_compact_block(height, prior.chain_state().block_hash());

        let new_cached_block = prior.roll_forward(&cb);
        self.cached_blocks.insert(height, new_cached_block);
        self.cache.insert(&cb);
        self.latest_block_height = Some(height);

        height
    }

    /// Generate a block with an Orchard output to the specified wallet's account.
    ///
    /// Returns (height, nullifier).
    #[cfg(feature = "orchard")]
    pub fn generate_next_block_for_orchard(
        &mut self,
        wallet_idx: usize,
        value: Zatoshis,
    ) -> (BlockHeight, ::orchard::note::Nullifier) {
        let (height, nfs) = self.generate_next_block_orchard_multi(&[(wallet_idx, value)]);
        (height, nfs[0])
    }

    /// Generate a block with Orchard outputs to multiple wallets.
    ///
    /// Each tuple is (wallet_idx, value).
    /// Returns (height, Vec<nullifiers>).
    #[cfg(feature = "orchard")]
    pub fn generate_next_block_orchard_multi(
        &mut self,
        outputs: &[(usize, Zatoshis)],
    ) -> (BlockHeight, Vec<::orchard::note::Nullifier>) {
        let prior = self.latest_cached_block();
        let height = prior.height() + 1;

        // Collect the Orchard FVKs and values we need
        let wallet_outputs: Vec<(OrchardFullViewingKey, Zatoshis)> = outputs
            .iter()
            .map(|(wallet_idx, value)| {
                let account = self.accounts[*wallet_idx]
                    .as_ref()
                    .expect("account must exist for wallet");
                let fvk = OrchardFullViewingKey::from(account.usk.orchard());
                (fvk, *value)
            })
            .collect();

        // Generate the compact block with Orchard outputs
        let mut ctx = fake_compact_tx(&mut self.rng);
        let mut nfs = vec![];

        for (fvk, value) in &wallet_outputs {
            // Position is not used for Orchard nullifier computation
            let nf = fvk.add_output(
                &mut ctx,
                &self.network,
                height,
                None, // No sender OVK needed for test outputs
                AddressType::DefaultExternal,
                *value,
                0, // Position ignored for Orchard
                &mut self.rng,
            );
            nfs.push(nf);
        }

        let cb = fake_compact_block_from_compact_tx(
            ctx,
            height,
            prior.chain_state().block_hash(),
            prior.sapling_end_size(),
            prior.orchard_end_size(),
        );

        // Roll forward cached block state
        let new_cached_block = prior.roll_forward(&cb);
        self.cached_blocks.insert(height, new_cached_block);

        // Insert into block cache
        self.cache.insert(&cb);
        self.latest_block_height = Some(height);

        (height, nfs)
    }

    /// Scan cached blocks for a specific wallet.
    ///
    /// Scans from `from_height` up to `limit` blocks.
    /// Note: `from_height` must be the height of the first block to scan, and
    /// `prior_chain_state` must be the state at `from_height - 1`.
    pub fn scan_cached_blocks(
        &mut self,
        wallet_idx: usize,
        from_height: BlockHeight,
        limit: usize,
    ) -> Result<ScanSummary, SqlxClientError> {
        // Get the chain state at from_height - 1
        // scan_cached_blocks requires: from_height == prior_chain_state.block_height() + 1
        let prior_chain_state = if from_height == self.sapling_activation_height() + 1 {
            // Special case: scanning from the first block after sapling activation
            self.initial_chain_state()
        } else if from_height > self.sapling_activation_height() + 1 {
            self.cached_blocks
                .get(&(from_height - 1))
                .map(|cb| cb.chain_state().clone())
                .unwrap_or_else(|| self.initial_chain_state())
        } else {
            // from_height is at or before sapling activation, use initial state
            self.initial_chain_state()
        };

        let wallet = &mut self.wallets[wallet_idx];
        let block_source = self.cache.block_source();

        scan_cached_blocks(
            &self.network,
            block_source,
            wallet,
            from_height,
            &prior_chain_state,
            limit,
        )
        .map_err(|e| match e {
            zcash_client_backend::data_api::chain::error::Error::Wallet(e) => e,
            zcash_client_backend::data_api::chain::error::Error::BlockSource(e) => e,
            zcash_client_backend::data_api::chain::error::Error::Scan(e) => {
                SqlxClientError::Encoding(format!("Scan error: {:?}", e))
            }
        })
    }

    /// Get total balance for a wallet's account.
    ///
    /// Returns `Zatoshis::ZERO` if the wallet has no account or no summary available.
    pub fn get_total_balance(&self, wallet_idx: usize) -> Zatoshis {
        let wallet = &self.wallets[wallet_idx];
        let account = match &self.accounts[wallet_idx] {
            Some(a) => a,
            None => return Zatoshis::ZERO,
        };

        wallet
            .get_wallet_summary(ConfirmationsPolicy::default())
            .ok()
            .flatten()
            .and_then(|summary| {
                summary
                    .account_balances()
                    .get(&account.account_uuid)
                    .map(|bal| bal.total())
            })
            .unwrap_or(Zatoshis::ZERO)
    }

    /// Get spendable balance for a wallet's account with the given minimum confirmations.
    ///
    /// Returns `Zatoshis::ZERO` if the wallet has no account or no summary available.
    #[allow(dead_code)]
    pub fn get_spendable_balance(&self, wallet_idx: usize, min_confirmations: u32) -> Zatoshis {
        use std::num::NonZeroU32;

        let wallet = &self.wallets[wallet_idx];
        let account = match &self.accounts[wallet_idx] {
            Some(a) => a,
            None => return Zatoshis::ZERO,
        };

        // Use NonZeroU32 for the confirmations policy, defaulting to 1 if 0 is provided
        let confirmations = NonZeroU32::new(min_confirmations.max(1)).unwrap();
        let policy = ConfirmationsPolicy::new_symmetrical(
            confirmations,
            #[cfg(feature = "transparent-inputs")]
            false,
        );

        wallet
            .get_wallet_summary(policy)
            .ok()
            .flatten()
            .and_then(|summary| {
                summary
                    .account_balances()
                    .get(&account.account_uuid)
                    .map(|bal| bal.spendable_value())
            })
            .unwrap_or(Zatoshis::ZERO)
    }

    /// Truncate chain and wallet state to the given height (reorg simulation).
    ///
    /// This truncates both the block cache and all wallet states.
    pub fn truncate_to_height(&mut self, height: BlockHeight) {
        // Truncate cached blocks
        self.cached_blocks.retain(|h, _| *h <= height);
        self.cache.truncate_to_height(height);

        // Update latest_block_height
        self.latest_block_height = self.cached_blocks.keys().last().copied();

        // Truncate all wallets
        let _ = self.truncate_all_to_height(height);
    }

    // ========================================================================
    // Private helpers for block generation
    // ========================================================================

    /// Create an empty compact block.
    fn create_empty_compact_block(
        &mut self,
        height: BlockHeight,
        prev_hash: BlockHash,
    ) -> CompactBlock {
        let mut hash = [0u8; 32];
        self.rng.fill_bytes(&mut hash);

        CompactBlock {
            hash: hash.to_vec(),
            height: height.into(),
            prev_hash: prev_hash.0.to_vec(),
            vtx: vec![],
            chain_metadata: Some(ChainMetadata {
                sapling_commitment_tree_size: self.latest_cached_block().sapling_end_size(),
                orchard_commitment_tree_size: self.latest_cached_block().orchard_end_size(),
            }),
            ..Default::default()
        }
    }
}

impl Drop for MultiWalletTestEnv {
    fn drop(&mut self) {
        // Clean up the test database
        let db_name = self.db_name.clone();
        let admin_pool = self.admin_pool.clone();

        let result = tokio::runtime::Handle::try_current();
        match result {
            Ok(handle) => {
                handle.spawn(async move {
                    let _ = sqlx_core::query::query(&format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                        db_name
                    ))
                    .execute(&admin_pool)
                    .await;

                    let _ = sqlx_core::query::query(&format!(
                        "DROP DATABASE IF EXISTS \"{}\"",
                        db_name
                    ))
                    .execute(&admin_pool)
                    .await;
                });
            }
            Err(_) => {
                if let Ok(rt) = Runtime::new() {
                    rt.block_on(async {
                        let _ = sqlx_core::query::query(&format!(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                            db_name
                        ))
                        .execute(&admin_pool)
                        .await;

                        let _ = sqlx_core::query::query(&format!(
                            "DROP DATABASE IF EXISTS \"{}\"",
                            db_name
                        ))
                        .execute(&admin_pool)
                        .await;
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::WalletRead;
    use zcash_primitives::block::BlockHash;

    /// Helper to create a birthday at Sapling activation.
    fn birthday_at_sapling_activation(network: &LocalNetwork) -> AccountBirthday {
        let height = network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling)
            .expect("Sapling activation height should be set");

        AccountBirthday::from_parts(ChainState::empty(height, BlockHash([0; 32])), None)
    }

    #[test]
    fn test_multiple_wallets_coexist() {
        // Create an environment with 3 wallets
        let mut env = MultiWalletTestEnv::new(3).expect("Failed to create multi-wallet env");

        // Verify we have 3 wallets with distinct IDs
        assert_eq!(env.wallet_count(), 3);

        let wallet_id_0 = env.wallet_id(0);
        let wallet_id_1 = env.wallet_id(1);
        let wallet_id_2 = env.wallet_id(2);

        assert_ne!(wallet_id_0, wallet_id_1);
        assert_ne!(wallet_id_1, wallet_id_2);
        assert_ne!(wallet_id_0, wallet_id_2);

        // Create accounts in each wallet
        let birthday = birthday_at_sapling_activation(env.network());

        env.create_account(0, birthday.clone())
            .expect("Failed to create account in wallet 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account in wallet 1");
        env.create_account(2, birthday.clone())
            .expect("Failed to create account in wallet 2");

        // Verify each wallet has exactly one account
        let accounts_0: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        let accounts_1: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        let accounts_2: Vec<_> = env
            .wallet(2)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();

        assert_eq!(accounts_0.len(), 1);
        assert_eq!(accounts_1.len(), 1);
        assert_eq!(accounts_2.len(), 1);

        // Verify account UUIDs are different
        assert_ne!(accounts_0[0], accounts_1[0]);
        assert_ne!(accounts_1[0], accounts_2[0]);
    }

    #[test]
    fn test_wallet_data_isolation() {
        // Create an environment with 2 wallets
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone())
            .expect("Failed to create account in wallet 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account in wallet 1");

        // Verify each wallet only sees its own account via API
        let accounts_0: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        let accounts_1: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();

        assert_eq!(accounts_0.len(), 1);
        assert_eq!(accounts_1.len(), 1);
        assert_ne!(accounts_0[0], accounts_1[0]);

        // Wallet 0 should not see wallet 1's account via API
        let account_from_0 = env.wallet(0).get_account(accounts_1[0]);
        assert!(account_from_0.is_ok(), "Query should succeed");
        assert!(
            account_from_0.unwrap().is_none(),
            "Wallet 0 should not see wallet 1's account"
        );

        // Wallet 1 should not see wallet 0's account via API
        let account_from_1 = env.wallet(1).get_account(accounts_0[0]);
        assert!(account_from_1.is_ok(), "Query should succeed");
        assert!(
            account_from_1.unwrap().is_none(),
            "Wallet 1 should not see wallet 0's account"
        );

        // Generate notes and scan to create more wallet-scoped data
        let value = Zatoshis::from_u64(50000).unwrap();
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(1, value);
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        let pool = env.wallet(0).pool();
        let wallet0_id = env.wallet_id(0);
        let wallet1_id = env.wallet_id(1);

        // DATABASE-LEVEL VERIFICATION: Check that accounts are wallet-scoped
        // Note: accounts.id is BIGSERIAL (i64), not UUID
        let accounts_for_w0: Vec<(i64,)> = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT id FROM accounts WHERE wallet_id = $1")
                    .bind(wallet0_id.expose_uuid())
                    .fetch_all(pool)
                    .await
            })
            .expect("Query failed");
        assert_eq!(
            accounts_for_w0.len(),
            1,
            "Wallet 0 should have 1 account in DB"
        );

        // DATABASE-LEVEL VERIFICATION: Check that notes are wallet-scoped
        let notes_for_w0: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                )
                .bind(wallet0_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(notes_for_w0.0, 1, "Wallet 0 should have 1 note in DB");

        let notes_for_w1: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                )
                .bind(wallet1_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(notes_for_w1.0, 1, "Wallet 1 should have 1 note in DB");

        // DATABASE-LEVEL VERIFICATION: Check that transactions are wallet-scoped
        let txs_for_w0: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM transactions WHERE wallet_id = $1",
                )
                .bind(wallet0_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert!(
            txs_for_w0.0 >= 1,
            "Wallet 0 should have at least 1 transaction in DB"
        );

        let txs_for_w1: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM transactions WHERE wallet_id = $1",
                )
                .bind(wallet1_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert!(
            txs_for_w1.0 >= 1,
            "Wallet 1 should have at least 1 transaction in DB"
        );

        // Verify transactions don't overlap
        let w0_txids: Vec<(Vec<u8>,)> = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT txid FROM transactions WHERE wallet_id = $1")
                    .bind(wallet0_id.expose_uuid())
                    .fetch_all(pool)
                    .await
            })
            .expect("Query failed");

        let w1_txids: Vec<(Vec<u8>,)> = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT txid FROM transactions WHERE wallet_id = $1")
                    .bind(wallet1_id.expose_uuid())
                    .fetch_all(pool)
                    .await
            })
            .expect("Query failed");

        // Each wallet sees transactions relevant to its notes
        // They may have overlap if they scanned the same block, but each has its own records
        assert!(
            !w0_txids.is_empty(),
            "Wallet 0 should have transaction records"
        );
        assert!(
            !w1_txids.is_empty(),
            "Wallet 1 should have transaction records"
        );
    }

    #[test]
    fn test_wallets_share_database() {
        // Create an environment with 2 wallets - they should share the same DB
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let wallet_id_0 = env.wallet_id(0);
        let wallet_id_1 = env.wallet_id(1);
        assert_ne!(wallet_id_0, wallet_id_1, "Wallet IDs should be different");

        // Clone the pool so we can use it after mutating env
        let pool = env.wallet(0).pool().clone();

        // Query wallets table directly to verify BOTH wallets exist in same DB
        let wallet_count: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT COUNT(*) FROM wallets")
                    .fetch_one(&pool)
                    .await
            })
            .expect("Query failed");
        assert_eq!(
            wallet_count.0, 2,
            "Should have exactly 2 wallets in shared database"
        );

        // Verify both wallet IDs exist in the same wallets table
        let wallet_exists_0: (bool,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT EXISTS(SELECT 1 FROM wallets WHERE id = $1)")
                    .bind(wallet_id_0.expose_uuid())
                    .fetch_one(&pool)
                    .await
            })
            .expect("Query failed");
        assert!(wallet_exists_0.0, "Wallet 0 should exist in database");

        let wallet_exists_1: (bool,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT EXISTS(SELECT 1 FROM wallets WHERE id = $1)")
                    .bind(wallet_id_1.expose_uuid())
                    .fetch_one(&pool)
                    .await
            })
            .expect("Query failed");
        assert!(wallet_exists_1.0, "Wallet 1 should exist in database");

        // Verify accounts table contains accounts from both wallets
        let account_count: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT COUNT(*) FROM accounts")
                    .fetch_one(&pool)
                    .await
            })
            .expect("Query failed");
        assert_eq!(
            account_count.0, 2,
            "Should have 2 accounts total in shared database"
        );

        // Generate a note for wallet 0 and scan
        let value = Zatoshis::from_u64(50000).unwrap();
        let (h, _) = env.generate_next_block_for_wallet(0, value);
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan");

        // Verify the note is stored in the shared database
        let total_notes: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as("SELECT COUNT(*) FROM sapling_received_notes")
                    .fetch_one(&pool)
                    .await
            })
            .expect("Query failed");
        assert!(
            total_notes.0 >= 1,
            "Note should be stored in shared database"
        );

        // But verify it's scoped to wallet 0
        let wallet0_notes: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                )
                .bind(wallet_id_0.expose_uuid())
                .fetch_one(&pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(wallet0_notes.0, 1, "Wallet 0 should have 1 note");

        let wallet1_notes: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                )
                .bind(wallet_id_1.expose_uuid())
                .fetch_one(&pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(wallet1_notes.0, 0, "Wallet 1 should have 0 notes");
    }

    #[test]
    fn test_truncate_affects_global_tables() {
        // Create an environment with 2 wallets
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone())
            .expect("Failed to create account in wallet 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account in wallet 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate blocks with notes for both wallets
        let (h1, _) = env.generate_next_block_for_wallet(0, value); // height 2
        let (h2, _) = env.generate_next_block_for_wallet(1, value); // height 3
        let (h3, _) = env.generate_next_block_for_wallet(0, value); // height 4

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Verify initial state
        let tip_0_before = env.wallet(0).chain_height().expect("chain_height");
        let tip_1_before = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(tip_0_before, Some(h3), "Wallet 0 should be at h3");
        assert_eq!(tip_1_before, Some(h3), "Wallet 1 should be at h3");

        // Verify balances before truncate
        assert_eq!(
            env.get_total_balance(0),
            (value + value).unwrap(),
            "Wallet 0 has 2 notes"
        );
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 has 1 note");

        // Verify notes exist in database before truncate
        // Notes are linked to transactions, and transactions have mined_height
        let pool = env.wallet(0).pool().clone();
        let note_count_before: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes n
                 JOIN transactions t ON n.tx_id = t.id
                 WHERE t.mined_height IS NOT NULL",
                )
                .fetch_one(&pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(
            note_count_before.0, 3,
            "Should have 3 mined notes before truncate"
        );

        // Truncate to height 2 (h1) - keeps first block only
        env.truncate_to_height(h1);

        // Verify chain heights after truncate
        let tip_0_after = env.wallet(0).chain_height().expect("chain_height");
        let tip_1_after = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(
            tip_0_after,
            Some(h1),
            "Wallet 0 should be at h1 after truncate"
        );
        assert_eq!(
            tip_1_after,
            Some(h1),
            "Wallet 1 should be at h1 after truncate"
        );

        // Verify notes above truncation height become pending (mined_height = NULL in their tx)
        let mined_note_count_after: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes n
                 JOIN transactions t ON n.tx_id = t.id
                 WHERE t.mined_height IS NOT NULL",
                )
                .fetch_one(&pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(
            mined_note_count_after.0, 1,
            "Should have 1 mined note after truncate (wallet 0's first note at h1)"
        );

        // Verify pending notes exist (notes whose transactions have NULL mined_height)
        let pending_note_count: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes n
                 JOIN transactions t ON n.tx_id = t.id
                 WHERE t.mined_height IS NULL",
                )
                .fetch_one(&pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(
            pending_note_count.0, 2,
            "Should have 2 pending notes after truncate"
        );

        // Verify spendable balances
        assert_eq!(
            env.get_spendable_balance(0, 1),
            value,
            "Wallet 0 should have 1 spendable note (at h1)"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "Wallet 1 should have 0 spendable notes (note at h2 is now pending)"
        );
    }

    // ========================================================================
    // Note Detection and Balance Tests
    // ========================================================================

    /// Verify notes sent to wallet A are NOT visible to wallet B.
    /// Includes database-level verification of note isolation.
    #[test]
    fn test_note_detection_isolation() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate block with note to wallet 0
        let (h, nf0) = env.generate_next_block_for_wallet(0, value);

        // Both wallets scan the same block
        env.scan_cached_blocks(0, h, 10).expect("scan wallet 0");
        env.scan_cached_blocks(1, h, 10).expect("scan wallet 1");

        // API-level verification: Only wallet 0 should see the note
        assert_eq!(
            env.get_total_balance(0),
            value,
            "Wallet 0 should have the note"
        );
        assert_eq!(
            env.get_total_balance(1),
            Zatoshis::ZERO,
            "Wallet 1 should NOT see wallet 0's note"
        );

        // Verify heights are consistent
        let tip_0 = env.wallet(0).chain_height().expect("chain_height");
        let tip_1 = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(tip_0, Some(h), "Wallet 0 should be at height {}", h);
        assert_eq!(tip_1, Some(h), "Wallet 1 should be at height {}", h);

        // DATABASE-LEVEL VERIFICATION
        let pool = env.wallet(0).pool();
        let wallet0_id = env.wallet_id(0);
        let wallet1_id = env.wallet_id(1);

        // Verify note exists only for wallet 0
        let w0_notes: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                )
                .bind(wallet0_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(w0_notes.0, 1, "Wallet 0 should have exactly 1 note in DB");

        let w1_notes: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                )
                .bind(wallet1_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(w1_notes.0, 0, "Wallet 1 should have 0 notes in DB");

        // Verify the nullifier is stored correctly and scoped to wallet 0
        let nf_bytes = nf0.0.to_vec();
        let nf_exists_w0: (bool,) = env.wallet(0).block_on(async {
            sqlx_core::query_as::query_as(
                "SELECT EXISTS(SELECT 1 FROM sapling_received_notes WHERE wallet_id = $1 AND nf = $2)"
            )
            .bind(wallet0_id.expose_uuid())
            .bind(&nf_bytes)
            .fetch_one(pool)
            .await
        }).expect("Query failed");
        assert!(nf_exists_w0.0, "Nullifier should exist for wallet 0");

        let nf_exists_w1: (bool,) = env.wallet(0).block_on(async {
            sqlx_core::query_as::query_as(
                "SELECT EXISTS(SELECT 1 FROM sapling_received_notes WHERE wallet_id = $1 AND nf = $2)"
            )
            .bind(wallet1_id.expose_uuid())
            .bind(&nf_bytes)
            .fetch_one(pool)
            .await
        }).expect("Query failed");
        assert!(!nf_exists_w1.0, "Nullifier should NOT exist for wallet 1");

        // Verify the note's value is correct at DB level
        let note_value: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT value FROM sapling_received_notes WHERE wallet_id = $1 AND nf = $2",
                )
                .bind(wallet0_id.expose_uuid())
                .bind(&nf_bytes)
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(
            note_value.0 as u64,
            u64::from(value),
            "Note value should match in DB"
        );
    }

    /// Both wallets receive notes in the same block.
    #[test]
    fn test_multiple_wallets_receive_in_same_block() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value_0 = Zatoshis::from_u64(50000).unwrap();
        let value_1 = Zatoshis::from_u64(75000).unwrap();

        // Generate block with outputs to both wallets
        let (h, _nfs) = env.generate_next_block_multi(&[(0, value_0), (1, value_1)]);

        // Both wallets scan
        let from_height = env.first_block_height();
        env.scan_cached_blocks(0, from_height, 10)
            .expect("scan wallet 0");
        env.scan_cached_blocks(1, from_height, 10)
            .expect("scan wallet 1");

        // Each wallet sees only its own note
        assert_eq!(env.get_total_balance(0), value_0, "Wallet 0 balance");
        assert_eq!(env.get_total_balance(1), value_1, "Wallet 1 balance");

        // Heights should be the same
        let tip_0 = env.wallet(0).chain_height().expect("chain_height");
        let tip_1 = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(tip_0, tip_1);
        assert_eq!(tip_0, Some(h));
    }

    /// Wallet B scans later than wallet A, still finds its notes.
    #[test]
    fn test_wallet_scans_at_different_times() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value_0 = Zatoshis::from_u64(30000).unwrap();
        let value_1 = Zatoshis::from_u64(40000).unwrap();

        // Generate multiple blocks
        let _h1 = env.generate_next_block_for_wallet(0, value_0);
        let _h2 = env.generate_next_block_for_wallet(1, value_1);
        let _h3 = env.generate_empty_block();

        let from_height = env.first_block_height();

        // Wallet 0 scans first
        env.scan_cached_blocks(0, from_height, 10)
            .expect("scan wallet 0");
        assert_eq!(
            env.get_total_balance(0),
            value_0,
            "Wallet 0 balance after scan"
        );

        // Wallet 1 hasn't scanned yet - should have zero balance
        assert_eq!(
            env.get_total_balance(1),
            Zatoshis::ZERO,
            "Wallet 1 before scan"
        );

        // Wallet 1 scans later (same blocks)
        env.scan_cached_blocks(1, from_height, 10)
            .expect("scan wallet 1");
        assert_eq!(
            env.get_total_balance(1),
            value_1,
            "Wallet 1 balance after scan"
        );

        // Wallet 0's balance should be unchanged
        assert_eq!(
            env.get_total_balance(0),
            value_0,
            "Wallet 0 balance unchanged"
        );
    }

    /// Accumulate multiple notes in a single wallet across multiple blocks.
    #[test]
    fn test_balance_accumulation() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value1 = Zatoshis::from_u64(10000).unwrap();
        let value2 = Zatoshis::from_u64(20000).unwrap();
        let value3 = Zatoshis::from_u64(30000).unwrap();

        // Generate multiple blocks with notes to wallet 0
        env.generate_next_block_for_wallet(0, value1);
        env.generate_next_block_for_wallet(0, value2);
        env.generate_next_block_for_wallet(0, value3);

        // Generate one note to wallet 1
        let wallet1_value = Zatoshis::from_u64(50000).unwrap();
        env.generate_next_block_for_wallet(1, wallet1_value);

        let from_height = env.first_block_height();

        // Scan both wallets
        env.scan_cached_blocks(0, from_height, 10)
            .expect("scan wallet 0");
        env.scan_cached_blocks(1, from_height, 10)
            .expect("scan wallet 1");

        // Wallet 0 should have sum of all three notes
        let expected_0 = (value1 + value2).unwrap();
        let expected_0 = (expected_0 + value3).unwrap();
        assert_eq!(
            env.get_total_balance(0),
            expected_0,
            "Wallet 0 accumulated balance"
        );

        // Wallet 1 should have only its note
        assert_eq!(env.get_total_balance(1), wallet1_value, "Wallet 1 balance");
    }

    // ========================================================================
    // Reorg Tests with Notes
    // ========================================================================

    /// Reorg removes notes from all affected wallets.
    #[test]
    fn test_reorg_invalidates_notes_for_all_wallets() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        let birthday_height = env.sapling_activation_height();
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate blocks with notes at heights 2 and 3 (sapling = 1)
        let (h1, _) = env.generate_next_block_for_wallet(0, value); // height 2
        let (h2, _) = env.generate_next_block_for_wallet(1, value); // height 3

        // Scan all
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Both have balance
        assert_eq!(env.get_total_balance(0), value, "Wallet 0 has balance");
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 has balance");

        // Reorg to height 1 (before both notes)
        env.truncate_to_height(env.sapling_activation_height());

        // Both wallets should show zero balance after reorg
        assert_eq!(
            env.get_total_balance(0),
            Zatoshis::ZERO,
            "Wallet 0 balance after reorg"
        );
        assert_eq!(
            env.get_total_balance(1),
            Zatoshis::ZERO,
            "Wallet 1 balance after reorg"
        );
    }

    /// Reorg at height between two notes affects only one wallet.
    /// Note: This test verifies that partial reorgs work correctly. Wallet 0's
    /// note at a lower height should survive while wallet 1's note at a higher
    /// height should be invalidated.
    #[test]
    fn test_reorg_partial_invalidation() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Wallet 0 receives at height 2
        let (h1, _) = env.generate_next_block_for_wallet(0, value);
        // Add some empty blocks
        env.generate_empty_block(); // height 3
        env.generate_empty_block(); // height 4
        // Wallet 1 receives at height 5
        let (_h2, _) = env.generate_next_block_for_wallet(1, value);

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Both have balance
        assert_eq!(env.get_total_balance(0), value, "Wallet 0 initial balance");
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 initial balance");

        // Reorg to height 3 (after wallet 0's note at height 2, before wallet 1's note at height 5)
        let reorg_height = h1 + 1; // height 3
        env.truncate_to_height(reorg_height);

        // After truncation, notes above the reorg height have mined_height = NULL.
        // They become pending (might come back on rescan) but are not spendable.
        // Wallet 0's note at height 2 is still mined and spendable.
        assert_eq!(
            env.get_spendable_balance(0, 1),
            value,
            "Wallet 0 note survives"
        );
        // Wallet 1's note at height 5 is now pending (not spendable).
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "Wallet 1 note not spendable"
        );

        // TOTAL BALANCE verification: Wallet 0's total equals spendable (no pending)
        assert_eq!(
            env.get_total_balance(0),
            value,
            "Wallet 0 total balance should equal spendable (no pending notes)"
        );
        // Wallet 1's total should still include the pending note
        assert_eq!(
            env.get_total_balance(1),
            value,
            "Wallet 1 total balance should include pending note"
        );

        // DATABASE verification: Check mined_height state
        // Notes are linked to transactions; check transaction's mined_height
        let pool = env.wallet(0).pool();
        let wallet1_id = env.wallet_id(1);
        let pending_notes: (i64,) = env
            .wallet(0)
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes n
                 JOIN transactions t ON n.tx_id = t.id
                 WHERE n.wallet_id = $1 AND t.mined_height IS NULL",
                )
                .bind(wallet1_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(
            pending_notes.0, 1,
            "Wallet 1 should have 1 pending note in DB after reorg"
        );
    }

    /// After reorg, new chain has different notes for wallets.
    /// Note: This test verifies that after a reorg, rescanning a completely
    /// new chain works correctly. This requires full commitment tree handling.
    #[test]
    fn test_rescan_after_reorg_finds_new_notes() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate chain A with note to wallet 0
        env.generate_next_block_for_wallet(0, value);

        // Scan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        assert_eq!(
            env.get_total_balance(0),
            value,
            "Wallet 0 has balance on chain A"
        );
        assert_eq!(
            env.get_total_balance(1),
            Zatoshis::ZERO,
            "Wallet 1 has no balance on chain A"
        );

        // Reorg back to birthday
        env.truncate_to_height(env.sapling_activation_height());

        // Generate chain B with note to wallet 1 instead
        env.generate_next_block_for_wallet(1, value);

        // Rescan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("rescan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("rescan 1");

        // After rescan of new chain:
        // - Wallet 0's old note from chain A stays in DB as pending (might come back)
        // - Wallet 1's new note from chain B is mined and spendable
        // Verify spendable balances reflect the currently active chain.
        assert_eq!(
            env.get_spendable_balance(0, 1),
            Zatoshis::ZERO,
            "Wallet 0 has no spendable balance on chain B"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            value,
            "Wallet 1 has spendable balance on chain B"
        );
    }

    /// Multiple truncates should work correctly.
    /// This test verifies complex reorg scenarios with multiple truncations at different heights.
    #[test]
    fn test_multiple_reorgs() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(25000).unwrap();
        let h0 = env.sapling_activation_height();

        // ==================== Chain A ====================
        // Build initial chain: h2, h3, h4, h5 with alternating wallet notes
        let (h2, _) = env.generate_next_block_for_wallet(0, value); // h2
        let (h3, _) = env.generate_next_block_for_wallet(1, value); // h3
        let (h4, _) = env.generate_next_block_for_wallet(0, value); // h4
        let (h5, _) = env.generate_next_block_for_wallet(1, value); // h5

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Initial state: wallet 0 has 2 notes (h2, h4), wallet 1 has 2 notes (h3, h5)
        assert_eq!(
            env.get_total_balance(0),
            (value + value).unwrap(),
            "W0 initial"
        );
        assert_eq!(
            env.get_total_balance(1),
            (value + value).unwrap(),
            "W1 initial"
        );

        // ==================== First Reorg to h3 ====================
        // Truncate to h3, losing h4 and h5
        env.truncate_to_height(h3);

        // Wallet 0: h2 mined, h4 pending
        // Wallet 1: h3 mined, h5 pending
        assert_eq!(env.get_spendable_balance(0, 1), value, "W0 after reorg 1");
        assert_eq!(env.get_spendable_balance(1, 1), value, "W1 after reorg 1");
        // Total includes pending
        assert_eq!(
            env.get_total_balance(0),
            (value + value).unwrap(),
            "W0 total after reorg 1"
        );
        assert_eq!(
            env.get_total_balance(1),
            (value + value).unwrap(),
            "W1 total after reorg 1"
        );

        // ==================== Build Chain B from h3 ====================
        // Generate new blocks on chain B
        let (h4b, _) = env.generate_next_block_for_wallet(1, value); // h4 - wallet 1 this time
        let (h5b, _) = env.generate_next_block_for_wallet(0, value); // h5 - wallet 0 this time

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0 chain B");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1 chain B");

        // After chain B:
        // Wallet 0: h2 mined, h5b mined (old h4 still pending)
        // Wallet 1: h3 mined, h4b mined (old h5 still pending)
        assert_eq!(
            env.get_spendable_balance(0, 1),
            (value + value).unwrap(),
            "W0 spendable after chain B"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            (value + value).unwrap(),
            "W1 spendable after chain B"
        );

        // ==================== Second Reorg to h2 ====================
        // Truncate to h2, losing h3, h4b, h5b
        env.truncate_to_height(h2);

        // Wallet 0: only h2 mined
        // Wallet 1: no mined notes (h3 was above h2)
        assert_eq!(env.get_spendable_balance(0, 1), value, "W0 after reorg 2");
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "W1 after reorg 2"
        );

        // ==================== Build Chain C from h2 ====================
        // Generate completely different chain
        let (h3c, _) = env.generate_next_block_for_wallet(0, value); // h3 - wallet 0
        let (h4c, _) = env.generate_next_block_for_wallet(0, value); // h4 - wallet 0

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0 chain C");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1 chain C");

        // Final state after chain C:
        // Wallet 0: h2, h3c, h4c mined = 3 spendable notes
        // Wallet 1: no mined notes on chain C
        let expected_w0 = ((value + value).unwrap() + value).unwrap();
        assert_eq!(
            env.get_spendable_balance(0, 1),
            expected_w0,
            "W0 final after chain C"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "W1 final after chain C (all notes pending)"
        );

        // Wallet 1 should still have total balance from pending notes
        assert!(
            env.get_total_balance(1) > Zatoshis::ZERO,
            "W1 should have pending notes in total balance"
        );
    }

    // ========================================================================
    // Mark Note Spent Tests
    // ========================================================================

    /// Test that mark_sapling_note_spent correctly marks a note as spent
    /// and verify cross-wallet isolation (marking doesn't affect other wallet's notes).
    #[test]
    fn test_mark_sapling_note_spent_basic() {
        use crate::wallet::notes::sapling::mark_sapling_note_spent;

        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate notes for both wallets
        let (_height0, nf0) = env.generate_next_block_for_wallet(0, value);
        let (_height1, _nf1) = env.generate_next_block_for_wallet(1, value);

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan wallet 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan wallet 1");

        // Verify both wallets have their notes
        assert_eq!(env.get_total_balance(0), value, "Wallet 0 initial balance");
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 initial balance");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Create a fake spending transaction for wallet 0
        let tx_ref = wallet.block_on(async {
            let fake_txid = [1u8; 32];
            sqlx_core::query::query(
                "INSERT INTO transactions (wallet_id, txid, min_observed_height) VALUES ($1, $2, $3)"
            )
            .bind(wallet_id.expose_uuid())
            .bind(&fake_txid[..])
            .bind(100i64)
            .execute(pool)
            .await?;

            let row: (i64,) = sqlx_core::query_as::query_as(
                "SELECT id FROM transactions WHERE wallet_id = $1 AND txid = $2"
            )
            .bind(wallet_id.expose_uuid())
            .bind(&fake_txid[..])
            .fetch_one(pool)
            .await?;

            Ok::<_, crate::SqlxClientError>(crate::types::TxRef(row.0))
        }).expect("Failed to create transaction");

        // Mark wallet 0's note as spent
        let marked = wallet
            .block_on(mark_sapling_note_spent(pool, wallet_id, tx_ref, &nf0))
            .expect("mark_sapling_note_spent failed");

        assert!(marked, "Should have marked a note as spent");

        // Marking again should return false (already marked)
        let marked_again = wallet
            .block_on(mark_sapling_note_spent(pool, wallet_id, tx_ref, &nf0))
            .expect("mark_sapling_note_spent failed");
        assert!(!marked_again, "Second mark should affect no rows");

        // CRITICAL: Verify wallet 1's note is NOT affected
        assert_eq!(
            env.get_total_balance(1),
            value,
            "Wallet 1's note should NOT be affected by wallet 0's spend"
        );

        // Verify wallet 1's note count is still 1 at database level
        // Spending is tracked in sapling_received_note_spends table
        let wallet1 = env.wallet(1);
        let wallet1_id = wallet1.wallet_id();
        let unspent_count: (i64,) = wallet1
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT COUNT(*) FROM sapling_received_notes n
                 LEFT JOIN sapling_received_note_spends s ON n.id = s.sapling_received_note_id
                 WHERE n.wallet_id = $1 AND s.sapling_received_note_id IS NULL",
                )
                .bind(wallet1_id.expose_uuid())
                .fetch_one(pool)
                .await
            })
            .expect("Query failed");
        assert_eq!(
            unspent_count.0, 1,
            "Wallet 1 should still have 1 unspent note in DB"
        );
    }

    /// Test mark_sapling_note_spent returns false for unknown nullifier
    /// and verify that using wrong wallet's nullifier doesn't affect other wallets.
    #[test]
    fn test_mark_sapling_note_spent_unknown_nullifier() {
        use crate::wallet::notes::sapling::mark_sapling_note_spent;

        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Wallet 0 gets a note, wallet 1 gets a note
        let (_h0, _nf0) = env.generate_next_block_for_wallet(0, value);
        let (_h1, nf1) = env.generate_next_block_for_wallet(1, value);

        // Scan both
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Create a fake spending transaction for wallet 0
        let tx_ref = wallet.block_on(async {
            let fake_txid = [2u8; 32];
            sqlx_core::query::query(
                "INSERT INTO transactions (wallet_id, txid, min_observed_height) VALUES ($1, $2, $3)"
            )
            .bind(wallet_id.expose_uuid())
            .bind(&fake_txid[..])
            .bind(100i64)
            .execute(pool)
            .await?;

            let row: (i64,) = sqlx_core::query_as::query_as(
                "SELECT id FROM transactions WHERE wallet_id = $1 AND txid = $2"
            )
            .bind(wallet_id.expose_uuid())
            .bind(&fake_txid[..])
            .fetch_one(pool)
            .await?;

            Ok::<_, crate::SqlxClientError>(crate::types::TxRef(row.0))
        }).expect("Failed to create transaction");

        // Try to mark a completely fake nullifier
        let fake_nf = ::sapling::Nullifier([99u8; 32]);
        let marked = wallet
            .block_on(mark_sapling_note_spent(pool, wallet_id, tx_ref, &fake_nf))
            .expect("mark_sapling_note_spent failed");
        assert!(!marked, "Should not mark any note for unknown nullifier");

        // CRITICAL: Try to mark wallet 1's nullifier using wallet 0's context
        // This should NOT affect wallet 1's note due to wallet_id scoping
        let marked_wrong_wallet = wallet
            .block_on(mark_sapling_note_spent(pool, wallet_id, tx_ref, &nf1))
            .expect("mark_sapling_note_spent failed");
        assert!(
            !marked_wrong_wallet,
            "Should not mark wallet 1's note via wallet 0's context"
        );

        // Verify wallet 1's balance is still intact
        assert_eq!(
            env.get_total_balance(1),
            value,
            "Wallet 1's balance should be unaffected"
        );

        // Verify wallet 0's balance is also intact (no note was marked)
        assert_eq!(
            env.get_total_balance(0),
            value,
            "Wallet 0's balance should be unaffected"
        );
    }

    // ========================================================================
    // Chain Tip and Height Tests
    // ========================================================================

    /// Test get_chain_tip returns correct height for each wallet.
    /// The chain tip tracks the highest scanned block height per wallet.
    #[test]
    fn test_get_chain_tip() {
        use crate::wallet::common::get_chain_tip;

        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        // Initially no blocks scanned for either wallet
        {
            let wallet0 = env.wallet(0);
            let tip0 = wallet0
                .block_on(get_chain_tip(wallet0.pool(), wallet0.wallet_id()))
                .expect("get_chain_tip failed");
            assert!(
                tip0.is_none(),
                "Wallet 0 should have no tip before scanning"
            );

            let wallet1 = env.wallet(1);
            let tip1 = wallet1
                .block_on(get_chain_tip(wallet1.pool(), wallet1.wallet_id()))
                .expect("get_chain_tip failed");
            assert!(
                tip1.is_none(),
                "Wallet 1 should have no tip before scanning"
            );
        }

        // Generate multiple blocks
        let value = Zatoshis::from_u64(50000).unwrap();
        let (h1, _) = env.generate_next_block_for_wallet(0, value);
        let (h2, _) = env.generate_next_block_for_wallet(1, value);
        let (h3, _) = env.generate_next_block_for_wallet(0, value);

        // Wallet 0 scans all 3 blocks
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan wallet 0");

        // Verify wallet 0's tip is at h3 after scanning
        {
            let wallet0 = env.wallet(0);
            let tip0 = wallet0
                .block_on(get_chain_tip(wallet0.pool(), wallet0.wallet_id()))
                .expect("get_chain_tip failed");
            assert_eq!(tip0, Some(h3), "Wallet 0 should be at height h3");
        }

        // Wallet 1 scans all blocks too
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan wallet 1");

        // Verify wallet 1's tip is also at h3 now
        {
            let wallet1 = env.wallet(1);
            let tip1 = wallet1
                .block_on(get_chain_tip(wallet1.pool(), wallet1.wallet_id()))
                .expect("get_chain_tip failed");
            assert_eq!(
                tip1,
                Some(h3),
                "Wallet 1 should be at height h3 after full scan"
            );
        }

        // Balances should reflect what each wallet scanned
        // Wallet 0 has notes at h1 and h3
        assert_eq!(
            env.get_total_balance(0),
            (value + value).unwrap(),
            "Wallet 0 has 2 notes"
        );
        // Wallet 1 has note at h2
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 has 1 note");

        // Chain tips should be consistent
        let tip0 = env.wallet(0).chain_height().expect("chain_height");
        let tip1 = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(
            tip0, tip1,
            "Both wallets should have same chain tip after full scan"
        );
    }

    // ========================================================================
    // Count Unspent Notes Tests
    // ========================================================================

    /// Test count_unspent_notes returns correct counts per wallet (isolation test).
    #[test]
    fn test_count_unspent_notes() {
        use crate::wallet::common::count_unspent_notes;
        use zcash_protocol::ShieldedProtocol;

        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Wallet 0 gets 3 notes
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(0, value);

        // Wallet 1 gets 2 notes
        env.generate_next_block_for_wallet(1, value);
        let (height, _) = env.generate_next_block_for_wallet(1, value);

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        let wallet0 = env.wallet(0);
        let wallet0_id = wallet0.wallet_id();
        let pool = wallet0.pool();
        let account0_uuid = env.test_account(0).unwrap().account_uuid;

        // Count wallet 0's notes
        let result0 = wallet0
            .block_on(count_unspent_notes(
                pool,
                wallet0_id,
                account0_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[],
            ))
            .expect("count_unspent_notes for wallet 0 failed");
        assert_eq!(
            result0.unwrap().note_count(),
            3,
            "Wallet 0 should have 3 unspent notes"
        );

        // Count wallet 1's notes
        let wallet1 = env.wallet(1);
        let wallet1_id = wallet1.wallet_id();
        let account1_uuid = env.test_account(1).unwrap().account_uuid;

        let result1 = wallet1
            .block_on(count_unspent_notes(
                pool,
                wallet1_id,
                account1_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[],
            ))
            .expect("count_unspent_notes for wallet 1 failed");
        assert_eq!(
            result1.unwrap().note_count(),
            2,
            "Wallet 1 should have 2 unspent notes"
        );

        // CRITICAL: Verify wallet 0's account doesn't see wallet 1's notes
        // Using wallet 0's wallet_id with wallet 1's account_uuid should return None or 0 notes
        let cross_result = wallet0
            .block_on(count_unspent_notes(
                pool,
                wallet0_id,
                account1_uuid, // Wrong account for this wallet
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[],
            ))
            .expect("cross-wallet count should not error");
        // The account doesn't belong to wallet 0, so either None or 0 notes is acceptable
        let cross_count = cross_result.map(|m| m.note_count()).unwrap_or(0);
        assert_eq!(
            cross_count, 0,
            "Using wallet 0's context with wallet 1's account should find no notes"
        );
    }

    /// Test count_unspent_notes respects exclude list by querying actual note IDs.
    #[test]
    fn test_count_unspent_notes_with_exclude() {
        use crate::wallet::common::count_unspent_notes;
        use zcash_protocol::ShieldedProtocol;

        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate 3 notes for wallet 0
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(0, value);

        // Generate 1 note for wallet 1 (for isolation testing)
        let (height, _) = env.generate_next_block_for_wallet(1, value);

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();
        let account_uuid = env.test_account(0).unwrap().account_uuid;

        // Query actual note IDs from the database for wallet 0
        // Spending is tracked in sapling_received_note_spends table
        let note_ids: Vec<(i64,)> = wallet
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT n.id FROM sapling_received_notes n
                 LEFT JOIN sapling_received_note_spends s ON n.id = s.sapling_received_note_id
                 WHERE n.wallet_id = $1 AND s.sapling_received_note_id IS NULL
                 ORDER BY n.id",
                )
                .bind(wallet_id.expose_uuid())
                .fetch_all(pool)
                .await
            })
            .expect("Failed to query note IDs");

        assert_eq!(note_ids.len(), 3, "Should have 3 note IDs to work with");

        // Count without exclusions
        let result_all = wallet
            .block_on(count_unspent_notes(
                pool,
                wallet_id,
                account_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[],
            ))
            .expect("count_unspent_notes failed");
        assert_eq!(
            result_all.unwrap().note_count(),
            3,
            "Should have 3 notes initially"
        );

        // Exclude the first note
        let result_exclude_one = wallet
            .block_on(count_unspent_notes(
                pool,
                wallet_id,
                account_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[note_ids[0].0],
            ))
            .expect("count_unspent_notes failed");
        assert_eq!(
            result_exclude_one.unwrap().note_count(),
            2,
            "Should have 2 notes after excluding 1"
        );

        // Exclude two notes
        let result_exclude_two = wallet
            .block_on(count_unspent_notes(
                pool,
                wallet_id,
                account_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[note_ids[0].0, note_ids[1].0],
            ))
            .expect("count_unspent_notes failed");
        assert_eq!(
            result_exclude_two.unwrap().note_count(),
            1,
            "Should have 1 note after excluding 2"
        );

        // Exclude all notes
        let result_exclude_all = wallet
            .block_on(count_unspent_notes(
                pool,
                wallet_id,
                account_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[note_ids[0].0, note_ids[1].0, note_ids[2].0],
            ))
            .expect("count_unspent_notes failed");
        // When all notes are excluded, either None or count=0 is acceptable
        let count = result_exclude_all.map(|m| m.note_count()).unwrap_or(0);
        assert_eq!(count, 0, "Should have 0 notes after excluding all");

        // Excluding non-existent ID has no effect
        let result_fake_exclude = wallet
            .block_on(count_unspent_notes(
                pool,
                wallet_id,
                account_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[999999],
            ))
            .expect("count_unspent_notes failed");
        assert_eq!(
            result_fake_exclude.unwrap().note_count(),
            3,
            "Excluding non-existent ID should not affect count"
        );

        // CRITICAL: Excluding wallet 1's note ID should NOT affect wallet 0's count
        let wallet1 = env.wallet(1);
        let wallet1_id = wallet1.wallet_id();
        let wallet1_note_ids: Vec<(i64,)> = wallet1
            .block_on(async {
                sqlx_core::query_as::query_as(
                    "SELECT n.id FROM sapling_received_notes n
                 LEFT JOIN sapling_received_note_spends s ON n.id = s.sapling_received_note_id
                 WHERE n.wallet_id = $1 AND s.sapling_received_note_id IS NULL",
                )
                .bind(wallet1_id.expose_uuid())
                .fetch_all(pool)
                .await
            })
            .expect("Failed to query wallet 1 note IDs");

        assert_eq!(wallet1_note_ids.len(), 1, "Wallet 1 should have 1 note");

        // Try to exclude wallet 1's note from wallet 0's count
        let result_cross_exclude = wallet
            .block_on(count_unspent_notes(
                pool,
                wallet_id,
                account_uuid,
                ShieldedProtocol::Sapling,
                0,
                height + 10,
                &[wallet1_note_ids[0].0],
            ))
            .expect("count_unspent_notes failed");
        assert_eq!(
            result_cross_exclude.unwrap().note_count(),
            3,
            "Excluding wallet 1's note ID should NOT affect wallet 0's count"
        );
    }

    // ========================================================================
    // Wallet Summary and Balance Tests
    // ========================================================================

    /// Test that wallet summary accounts for multiple notes correctly
    /// and that summaries are isolated per wallet.
    #[test]
    fn test_wallet_summary_multiple_notes() {
        use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let v1 = Zatoshis::from_u64(10000).unwrap();
        let v2 = Zatoshis::from_u64(20000).unwrap();
        let v3 = Zatoshis::from_u64(30000).unwrap();

        // Wallet 0 gets v1, v2, v3
        env.generate_next_block_for_wallet(0, v1);
        env.generate_next_block_for_wallet(0, v2);
        env.generate_next_block_for_wallet(0, v3);

        // Wallet 1 gets different amounts
        let w1_v1 = Zatoshis::from_u64(15000).unwrap();
        let w1_v2 = Zatoshis::from_u64(25000).unwrap();
        env.generate_next_block_for_wallet(1, w1_v1);
        env.generate_next_block_for_wallet(1, w1_v2);

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Check wallet 0's summary
        let wallet0 = env.wallet(0);
        let account0_uuid = env.test_account(0).unwrap().account_uuid;
        let summary0 = wallet0
            .get_wallet_summary(ConfirmationsPolicy::default())
            .expect("get_wallet_summary failed")
            .expect("Should have summary");

        let balance0 = summary0
            .account_balances()
            .get(&account0_uuid)
            .expect("Account 0 should have balance");

        let expected0 = ((v1 + v2).unwrap() + v3).unwrap();
        assert_eq!(
            balance0.total(),
            expected0,
            "Wallet 0 total should match sum"
        );

        // Check wallet 1's summary
        let wallet1 = env.wallet(1);
        let account1_uuid = env.test_account(1).unwrap().account_uuid;
        let summary1 = wallet1
            .get_wallet_summary(ConfirmationsPolicy::default())
            .expect("get_wallet_summary failed")
            .expect("Should have summary");

        let balance1 = summary1
            .account_balances()
            .get(&account1_uuid)
            .expect("Account 1 should have balance");

        let expected1 = (w1_v1 + w1_v2).unwrap();
        assert_eq!(
            balance1.total(),
            expected1,
            "Wallet 1 total should match sum"
        );

        // CRITICAL: Wallet 0's summary should NOT include wallet 1's account
        assert!(
            !summary0.account_balances().contains_key(&account1_uuid),
            "Wallet 0's summary should NOT contain wallet 1's account"
        );

        // CRITICAL: Wallet 1's summary should NOT include wallet 0's account
        assert!(
            !summary1.account_balances().contains_key(&account0_uuid),
            "Wallet 1's summary should NOT contain wallet 0's account"
        );
    }

    /// Test spendable balance respects confirmations independently per wallet.
    #[test]
    fn test_spendable_balance_confirmations() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");
        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Both wallets get notes in the first block
        env.generate_next_block_multi(&[(0, value), (1, value)]);

        // Scan first block only for both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 1)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 1)
            .expect("scan 1");

        // With 1 confirmation requirement and only 1 block, balance should be zero
        let spendable_0_before = env.get_spendable_balance(0, 1);
        let spendable_1_before = env.get_spendable_balance(1, 1);

        // But total balance should show the notes exist
        assert_eq!(
            env.get_total_balance(0),
            value,
            "Wallet 0 has total balance"
        );
        assert_eq!(
            env.get_total_balance(1),
            value,
            "Wallet 1 has total balance"
        );

        // Generate more blocks for confirmations
        env.generate_empty_block();
        env.generate_empty_block();

        // Only wallet 0 scans the new blocks
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0 full");

        // Wallet 0 should now have spendable balance
        let spendable_0_after = env.get_spendable_balance(0, 1);
        assert_eq!(
            spendable_0_after, value,
            "Wallet 0 should be spendable with confirmations"
        );

        // Wallet 1 has NOT scanned the new blocks, so its state depends on implementation
        // Let's scan wallet 1 too and verify both are spendable
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1 full");

        let spendable_1_after = env.get_spendable_balance(1, 1);
        assert_eq!(
            spendable_1_after, value,
            "Wallet 1 should be spendable with confirmations"
        );

        // Verify isolation: each wallet's spendable balance is independent
        assert_eq!(env.get_spendable_balance(0, 1), value);
        assert_eq!(env.get_spendable_balance(1, 1), value);
    }

    // ========================================================================
    // Orchard Multi-Wallet Tests
    // ========================================================================

    #[cfg(feature = "orchard")]
    mod orchard_multi_wallet_tests {
        use super::*;

        /// Both wallets receive Orchard notes in the same block.
        #[test]
        fn test_multiple_wallets_receive_orchard_in_same_block() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday.clone()).expect("account 1");

            let value_0 = Zatoshis::from_u64(50000).unwrap();
            let value_1 = Zatoshis::from_u64(75000).unwrap();

            // Generate block with Orchard outputs to both wallets
            let (h, _nfs) = env.generate_next_block_orchard_multi(&[(0, value_0), (1, value_1)]);

            // Both wallets scan
            let from_height = env.first_block_height();
            env.scan_cached_blocks(0, from_height, 10)
                .expect("scan wallet 0");
            env.scan_cached_blocks(1, from_height, 10)
                .expect("scan wallet 1");

            // Each wallet sees only its own note
            assert_eq!(
                env.get_total_balance(0),
                value_0,
                "Wallet 0 Orchard balance"
            );
            assert_eq!(
                env.get_total_balance(1),
                value_1,
                "Wallet 1 Orchard balance"
            );

            // Heights should be the same
            let tip_0 = env.wallet(0).chain_height().expect("chain_height");
            let tip_1 = env.wallet(1).chain_height().expect("chain_height");
            assert_eq!(tip_0, tip_1);
            assert_eq!(tip_0, Some(h));
        }

        /// Verify Orchard notes sent to wallet A are NOT visible to wallet B.
        #[test]
        fn test_orchard_note_detection_isolation() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday.clone()).expect("account 1");

            let value = Zatoshis::from_u64(50000).unwrap();

            // Generate block with Orchard note to wallet 0
            let (h, _nf) = env.generate_next_block_for_orchard(0, value);

            // Both wallets scan the same block
            env.scan_cached_blocks(0, h, 10).expect("scan wallet 0");
            env.scan_cached_blocks(1, h, 10).expect("scan wallet 1");

            // Only wallet 0 should see the note
            assert_eq!(
                env.get_total_balance(0),
                value,
                "Wallet 0 should have the Orchard note"
            );
            assert_eq!(
                env.get_total_balance(1),
                Zatoshis::ZERO,
                "Wallet 1 should NOT see wallet 0's Orchard note"
            );
        }

        /// Accumulate multiple Orchard notes in a single wallet across multiple blocks.
        #[test]
        fn test_orchard_balance_accumulation() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday.clone()).expect("account 1");

            let value1 = Zatoshis::from_u64(10000).unwrap();
            let value2 = Zatoshis::from_u64(20000).unwrap();
            let value3 = Zatoshis::from_u64(30000).unwrap();

            // Generate multiple blocks with Orchard notes to wallet 0
            env.generate_next_block_for_orchard(0, value1);
            env.generate_next_block_for_orchard(0, value2);
            env.generate_next_block_for_orchard(0, value3);

            // Generate one Orchard note to wallet 1
            let wallet1_value = Zatoshis::from_u64(50000).unwrap();
            env.generate_next_block_for_orchard(1, wallet1_value);

            let from_height = env.first_block_height();

            // Scan both wallets
            env.scan_cached_blocks(0, from_height, 10)
                .expect("scan wallet 0");
            env.scan_cached_blocks(1, from_height, 10)
                .expect("scan wallet 1");

            // Wallet 0 should have sum of all three notes
            let expected_0 = (value1 + value2).unwrap();
            let expected_0 = (expected_0 + value3).unwrap();
            assert_eq!(
                env.get_total_balance(0),
                expected_0,
                "Wallet 0 accumulated Orchard balance"
            );

            // Wallet 1 should have only its note
            assert_eq!(
                env.get_total_balance(1),
                wallet1_value,
                "Wallet 1 Orchard balance"
            );
        }

        /// Reorg removes Orchard notes from all affected wallets.
        #[test]
        fn test_reorg_invalidates_orchard_notes_for_all_wallets() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday.clone()).expect("account 1");

            let value = Zatoshis::from_u64(50000).unwrap();

            // Generate blocks with Orchard notes
            let (_h1, _) = env.generate_next_block_for_orchard(0, value);
            let (_h2, _) = env.generate_next_block_for_orchard(1, value);

            // Scan all
            env.scan_cached_blocks(0, env.first_block_height(), 10)
                .expect("scan 0");
            env.scan_cached_blocks(1, env.first_block_height(), 10)
                .expect("scan 1");

            // Both have balance
            assert_eq!(
                env.get_total_balance(0),
                value,
                "Wallet 0 has Orchard balance"
            );
            assert_eq!(
                env.get_total_balance(1),
                value,
                "Wallet 1 has Orchard balance"
            );

            // Reorg to before both notes
            env.truncate_to_height(env.sapling_activation_height());

            // Both wallets should show zero balance after reorg
            assert_eq!(
                env.get_total_balance(0),
                Zatoshis::ZERO,
                "Wallet 0 Orchard balance after reorg"
            );
            assert_eq!(
                env.get_total_balance(1),
                Zatoshis::ZERO,
                "Wallet 1 Orchard balance after reorg"
            );
        }

        /// Orchard partial reorg: reorg at height between two notes affects only one wallet.
        /// Equivalent to test_reorg_partial_invalidation for Orchard.
        #[test]
        fn test_orchard_reorg_partial_invalidation() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday.clone()).expect("account 1");

            let value = Zatoshis::from_u64(50000).unwrap();

            // Wallet 0 receives Orchard note at height 2
            let (h1, _) = env.generate_next_block_for_orchard(0, value);
            // Add some empty blocks
            env.generate_empty_block(); // height 3
            env.generate_empty_block(); // height 4
            // Wallet 1 receives Orchard note at height 5
            let (_h2, _) = env.generate_next_block_for_orchard(1, value);

            // Scan both wallets
            env.scan_cached_blocks(0, env.first_block_height(), 10)
                .expect("scan 0");
            env.scan_cached_blocks(1, env.first_block_height(), 10)
                .expect("scan 1");

            // Both have balance
            assert_eq!(
                env.get_total_balance(0),
                value,
                "Wallet 0 initial Orchard balance"
            );
            assert_eq!(
                env.get_total_balance(1),
                value,
                "Wallet 1 initial Orchard balance"
            );

            // Reorg to height 3 (after wallet 0's note at h1=2, before wallet 1's note at h2=5)
            let reorg_height = h1 + 1; // height 3
            env.truncate_to_height(reorg_height);

            // Wallet 0's Orchard note at h1=2 should survive and be spendable
            assert_eq!(
                env.get_spendable_balance(0, 1),
                value,
                "Wallet 0 Orchard note survives partial reorg"
            );
            // Wallet 1's Orchard note at h2=5 is now pending (not spendable)
            assert_eq!(
                env.get_spendable_balance(1, 1),
                Zatoshis::ZERO,
                "Wallet 1 Orchard note not spendable after partial reorg"
            );

            // TOTAL BALANCE verification
            assert_eq!(
                env.get_total_balance(0),
                value,
                "Wallet 0 total equals spendable (no pending Orchard notes)"
            );
            assert_eq!(
                env.get_total_balance(1),
                value,
                "Wallet 1 total includes pending Orchard note"
            );

            // DATABASE verification: Check Orchard note state
            // Notes are linked to transactions; check transaction's mined_height
            let pool = env.wallet(0).pool();
            let wallet1_id = env.wallet_id(1);
            let pending_orchard_notes: (i64,) = env
                .wallet(0)
                .block_on(async {
                    sqlx_core::query_as::query_as(
                        "SELECT COUNT(*) FROM orchard_received_notes n
                     JOIN transactions t ON n.tx_id = t.id
                     WHERE n.wallet_id = $1 AND t.mined_height IS NULL",
                    )
                    .bind(wallet1_id.expose_uuid())
                    .fetch_one(pool)
                    .await
                })
                .expect("Query failed");
            assert_eq!(
                pending_orchard_notes.0, 1,
                "Wallet 1 should have 1 pending Orchard note in DB after reorg"
            );
        }

        /// Test mixing Sapling and Orchard notes across multiple wallets.
        /// Verifies that mixed pool notes are properly isolated per wallet.
        #[test]
        fn test_mixed_sapling_and_orchard_notes() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday).expect("account 1");

            let sapling_value_0 = Zatoshis::from_u64(30000).unwrap();
            let orchard_value_0 = Zatoshis::from_u64(50000).unwrap();
            let sapling_value_1 = Zatoshis::from_u64(25000).unwrap();
            let orchard_value_1 = Zatoshis::from_u64(75000).unwrap();

            // Wallet 0 gets Sapling then Orchard notes
            env.generate_next_block_for_wallet(0, sapling_value_0); // Sapling
            env.generate_next_block_for_orchard(0, orchard_value_0); // Orchard

            // Wallet 1 gets Orchard then Sapling notes (different order)
            env.generate_next_block_for_orchard(1, orchard_value_1); // Orchard
            env.generate_next_block_for_wallet(1, sapling_value_1); // Sapling

            env.scan_cached_blocks(0, env.first_block_height(), 10)
                .expect("scan 0");
            env.scan_cached_blocks(1, env.first_block_height(), 10)
                .expect("scan 1");

            // Wallet 0 total should be sum of its Sapling + Orchard
            let expected_0 = (sapling_value_0 + orchard_value_0).unwrap();
            assert_eq!(
                env.get_total_balance(0),
                expected_0,
                "Wallet 0 total should include both Sapling and Orchard"
            );

            // Wallet 1 total should be sum of its Sapling + Orchard
            let expected_1 = (sapling_value_1 + orchard_value_1).unwrap();
            assert_eq!(
                env.get_total_balance(1),
                expected_1,
                "Wallet 1 total should include both Sapling and Orchard"
            );

            // DATABASE verification: Check note counts per wallet
            let pool = env.wallet(0).pool();
            let wallet0_id = env.wallet_id(0);
            let wallet1_id = env.wallet_id(1);

            // Wallet 0: 1 Sapling, 1 Orchard
            let w0_sapling: (i64,) = env
                .wallet(0)
                .block_on(async {
                    sqlx_core::query_as::query_as(
                        "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                    )
                    .bind(wallet0_id.expose_uuid())
                    .fetch_one(pool)
                    .await
                })
                .expect("Query failed");
            assert_eq!(w0_sapling.0, 1, "Wallet 0 should have 1 Sapling note");

            let w0_orchard: (i64,) = env
                .wallet(0)
                .block_on(async {
                    sqlx_core::query_as::query_as(
                        "SELECT COUNT(*) FROM orchard_received_notes WHERE wallet_id = $1",
                    )
                    .bind(wallet0_id.expose_uuid())
                    .fetch_one(pool)
                    .await
                })
                .expect("Query failed");
            assert_eq!(w0_orchard.0, 1, "Wallet 0 should have 1 Orchard note");

            // Wallet 1: 1 Sapling, 1 Orchard
            let w1_sapling: (i64,) = env
                .wallet(0)
                .block_on(async {
                    sqlx_core::query_as::query_as(
                        "SELECT COUNT(*) FROM sapling_received_notes WHERE wallet_id = $1",
                    )
                    .bind(wallet1_id.expose_uuid())
                    .fetch_one(pool)
                    .await
                })
                .expect("Query failed");
            assert_eq!(w1_sapling.0, 1, "Wallet 1 should have 1 Sapling note");

            let w1_orchard: (i64,) = env
                .wallet(0)
                .block_on(async {
                    sqlx_core::query_as::query_as(
                        "SELECT COUNT(*) FROM orchard_received_notes WHERE wallet_id = $1",
                    )
                    .bind(wallet1_id.expose_uuid())
                    .fetch_one(pool)
                    .await
                })
                .expect("Query failed");
            assert_eq!(w1_orchard.0, 1, "Wallet 1 should have 1 Orchard note");
        }

        /// Test that after reorg, rescanning a new chain with different Orchard notes works.
        #[test]
        fn test_orchard_rescan_after_reorg_finds_new_notes() {
            let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

            let birthday = birthday_at_sapling_activation(env.network());
            env.create_account(0, birthday.clone()).expect("account 0");
            env.create_account(1, birthday.clone()).expect("account 1");

            let value = Zatoshis::from_u64(50000).unwrap();

            // Generate chain A with Orchard note to wallet 0
            env.generate_next_block_for_orchard(0, value);

            // Scan
            env.scan_cached_blocks(0, env.first_block_height(), 10)
                .expect("scan 0");
            env.scan_cached_blocks(1, env.first_block_height(), 10)
                .expect("scan 1");

            assert_eq!(
                env.get_total_balance(0),
                value,
                "Wallet 0 has Orchard balance on chain A"
            );
            assert_eq!(
                env.get_total_balance(1),
                Zatoshis::ZERO,
                "Wallet 1 has no balance on chain A"
            );

            // Reorg back to birthday
            env.truncate_to_height(env.sapling_activation_height());

            // Generate chain B with Orchard note to wallet 1 instead
            env.generate_next_block_for_orchard(1, value);

            // Rescan
            env.scan_cached_blocks(0, env.first_block_height(), 10)
                .expect("rescan 0");
            env.scan_cached_blocks(1, env.first_block_height(), 10)
                .expect("rescan 1");

            // After rescan of new chain:
            // - Wallet 0's old note from chain A is pending (not spendable)
            // - Wallet 1's new note from chain B is mined and spendable
            assert_eq!(
                env.get_spendable_balance(0, 1),
                Zatoshis::ZERO,
                "Wallet 0 has no spendable Orchard balance on chain B"
            );
            assert_eq!(
                env.get_spendable_balance(1, 1),
                value,
                "Wallet 1 has spendable Orchard balance on chain B"
            );
        }
    }
}
