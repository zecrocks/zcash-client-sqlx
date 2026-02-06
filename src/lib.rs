//! *A PostgreSQL-backed Zcash light client with native multi-wallet support.*
//!
//! `zcash_client_sqlx` provides a complete PostgreSQL implementation of the
//! [`WalletRead`], [`WalletWrite`], and [`WalletCommitmentTrees`] traits from the
//! [`zcash_client_backend`] crate. In combination with [`zcash_client_backend`], it provides
//! a full implementation of a database-backed client for the Zcash network.
//!
//! # Design
//!
//! This crate differs from `zcash_client_sqlite` in several important ways:
//!
//! - **PostgreSQL backend**: Uses PostgreSQL for better scalability and concurrent access
//! - **Native multi-wallet support**: A single database can hold multiple independent wallets,
//!   each identified by a unique [`WalletId`]
//! - **Async-first**: Built on sqlx with internal `block_on` for sync trait compatibility
//!
//! ## Feature flags
#![doc = document_features::document_features!()]
//!
//! [`WalletRead`]: zcash_client_backend::data_api::WalletRead
//! [`WalletWrite`]: zcash_client_backend::data_api::WalletWrite
//! [`WalletCommitmentTrees`]: zcash_client_backend::data_api::WalletCommitmentTrees

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(docsrs, doc(auto_cfg))]
// Catch documentation errors caused by code changes.
#![deny(rustdoc::broken_intra_doc_links)]

use std::{collections::HashMap, fmt::Debug, num::NonZeroU32};

use incrementalmerkletree::{Marking, Position, Retention};
use secrecy::SecretVec;
use shardtree::{ShardTree, error::ShardTreeError, store::ShardStore};
use tokio::runtime::{Handle, Runtime};
use zip32::DiversifierIndex;

use zcash_client_backend::{
    data_api::{
        self, Account as AccountTrait, AccountBirthday, AccountMeta, AccountPurpose, AccountSource,
        AddressInfo, BlockMetadata, DecryptedTransaction, InputSource, NoteFilter, NullifierQuery,
        ReceivedNotes, ReceivedTransactionOutput, SAPLING_SHARD_HEIGHT, ScannedBlock,
        SeedRelevance, SentTransaction, TargetValue, TransactionDataRequest, WalletCommitmentTrees,
        WalletRead, WalletSummary, WalletWrite, Zip32Derivation,
        chain::ChainState,
        scanning::ScanRange,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{
        UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedIncomingViewingKey, UnifiedSpendingKey,
    },
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{BlockHeight, Parameters},
    memo::Memo,
};

pub use crate::{
    error::SqlxClientError,
    types::{AccountUuid, ReceivedNoteId, UtxoId, WalletId},
};

#[cfg(feature = "postgres")]
pub use crate::pool::{Pool, create_pool, create_pool_default};

#[cfg(feature = "postgres")]
pub use crate::wallet::{
    TransactionOutputRow, TransactionRow, get_transaction_outputs, get_transactions,
};

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

#[cfg(feature = "transparent-inputs")]
use {
    std::time::SystemTime,
    transparent::{address::TransparentAddress, bundle::OutPoint, keys::TransparentKeyScope},
    zcash_client_backend::{
        data_api::{Balance, TransactionsInvolvingAddress, WalletUtxo},
        wallet::TransparentAddressMetadata,
    },
};

#[cfg(any(test, feature = "test-dependencies"))]
use zcash_client_backend::data_api::{OutputOfSentTx, WalletTest, testing::TransactionSummary};

pub mod error;
pub mod init;
pub mod pool;
pub mod types;
pub mod wallet;

#[cfg(all(feature = "test-dependencies", feature = "postgres"))]
pub(crate) mod testing;

#[cfg(feature = "transparent-inputs")]
pub use types::GapLimits;

/// The maximum number of blocks the wallet is allowed to rewind. This is
/// consistent with the bound in zcashd, and allows block data deeper than
/// this delta from the chain tip to be pruned.
#[allow(dead_code)]
pub(crate) const PRUNING_DEPTH: u32 = 100;

/// The number of blocks to verify ahead when the chain tip is updated.
#[allow(dead_code)]
pub(crate) const VERIFY_LOOKAHEAD: u32 = 10;

pub(crate) const SAPLING_TABLES_PREFIX: &str = "sapling";

#[cfg(feature = "orchard")]
pub(crate) const ORCHARD_TABLES_PREFIX: &str = "orchard";

/// The viewing key that an [`Account`] has available to it.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub(crate) enum ViewingKey {
    /// A full viewing key.
    ///
    /// This is available to derived accounts, as well as accounts directly imported as
    /// full viewing keys.
    Full(Box<UnifiedFullViewingKey>),

    /// An incoming viewing key.
    ///
    /// Accounts that have this kind of viewing key cannot be used in wallet contexts,
    /// because they are unable to maintain an accurate balance.
    Incoming(Box<UnifiedIncomingViewingKey>),
}

impl ViewingKey {
    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        match self {
            ViewingKey::Full(ufvk) => Some(ufvk),
            ViewingKey::Incoming(_) => None,
        }
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        match self {
            ViewingKey::Full(ufvk) => ufvk.as_ref().to_unified_incoming_viewing_key(),
            ViewingKey::Incoming(uivk) => uivk.as_ref().clone(),
        }
    }
}

/// An account stored in a `zcash_client_sqlx` database.
#[derive(Debug, Clone)]
pub struct Account {
    id: types::AccountRef,
    uuid: AccountUuid,
    name: Option<String>,
    kind: AccountSource,
    viewing_key: ViewingKey,
    birthday: BlockHeight,
}

impl Account {
    /// Returns the default Unified Address for the account, along with the diversifier index that
    /// generated it.
    ///
    /// The diversifier index may be non-zero if the Unified Address includes a Sapling
    /// receiver, and there was no valid Sapling receiver at diversifier index zero.
    #[allow(dead_code)]
    pub(crate) fn default_address(
        &self,
        request: UnifiedAddressRequest,
    ) -> Result<(UnifiedAddress, DiversifierIndex), zcash_keys::keys::AddressGenerationError> {
        self.uivk().default_address(request)
    }

    #[allow(dead_code)]
    pub(crate) fn internal_id(&self) -> types::AccountRef {
        self.id
    }

    #[allow(dead_code)]
    pub(crate) fn birthday(&self) -> BlockHeight {
        self.birthday
    }
}

impl AccountTrait for Account {
    type AccountId = AccountUuid;

    fn id(&self) -> AccountUuid {
        self.uuid
    }

    fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    fn source(&self) -> &AccountSource {
        &self.kind
    }

    fn ufvk(&self) -> Option<&UnifiedFullViewingKey> {
        self.viewing_key.ufvk()
    }

    fn uivk(&self) -> UnifiedIncomingViewingKey {
        self.viewing_key.uivk()
    }
}

/// Information about a wallet stored in the database.
#[derive(Debug, Clone)]
pub struct WalletInfo {
    /// The unique identifier for the wallet.
    pub id: WalletId,
    /// The human-readable name of the wallet, if set.
    pub name: Option<String>,
    /// The network this wallet is configured for (e.g., "mainnet", "testnet").
    pub network: String,
    /// When the wallet was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A wrapper around a sqlx connection pool that provides access to wallet data.
///
/// This is the main entry point for interacting with wallet data stored in PostgreSQL or MySQL.
/// Each `WalletDb` instance is bound to a specific wallet identified by [`WalletId`], providing
/// isolation between multiple wallets stored in the same database.
#[cfg(feature = "postgres")]
pub struct WalletDb<P: Parameters> {
    pool: Pool,
    wallet_id: WalletId,
    params: P,
    runtime: RuntimeHandle,
    #[cfg(feature = "transparent-inputs")]
    gap_limits: GapLimits,
}

/// A handle to a Tokio runtime, either owned or borrowed.
enum RuntimeHandle {
    /// An owned runtime that will be dropped when the WalletDb is dropped.
    Owned(Runtime),
    /// A borrowed handle to an existing runtime.
    Handle(Handle),
}

impl RuntimeHandle {
    fn handle(&self) -> &Handle {
        match self {
            RuntimeHandle::Owned(rt) => rt.handle(),
            RuntimeHandle::Handle(h) => h,
        }
    }
}

#[cfg(feature = "postgres")]
impl<P: Parameters> WalletDb<P> {
    /// Creates a new `WalletDb` instance for a specific wallet.
    ///
    /// This function opens a connection to the specified wallet in the database.
    /// The wallet must already exist; use [`create_wallet`] to create a new wallet.
    ///
    /// # Arguments
    /// * `pool` - The database connection pool
    /// * `wallet_id` - The unique identifier of the wallet to open
    /// * `params` - The consensus parameters for the network
    ///
    /// # Errors
    /// Returns an error if the wallet does not exist or if there's a database error.
    pub fn for_wallet(pool: Pool, wallet_id: WalletId, params: P) -> Result<Self, SqlxClientError> {
        let runtime = Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;

        Ok(Self {
            pool,
            wallet_id,
            params,
            runtime: RuntimeHandle::Owned(runtime),
            #[cfg(feature = "transparent-inputs")]
            gap_limits: GapLimits::default(),
        })
    }

    /// Creates a new `WalletDb` instance using an existing Tokio runtime handle.
    ///
    /// This is useful when integrating with applications that already have a Tokio runtime.
    pub fn for_wallet_with_handle(
        pool: Pool,
        wallet_id: WalletId,
        params: P,
        handle: Handle,
    ) -> Self {
        Self {
            pool,
            wallet_id,
            params,
            runtime: RuntimeHandle::Handle(handle),
            #[cfg(feature = "transparent-inputs")]
            gap_limits: GapLimits::default(),
        }
    }

    /// Creates a new `WalletDb` instance from a PostgreSQL connection URL (blocking version).
    ///
    /// This is a convenience function that creates a connection pool from the URL and
    /// then creates a `WalletDb` instance for the specified wallet.
    ///
    /// # Arguments
    /// * `url` - The PostgreSQL connection URL (e.g., `postgresql://user:pass@host:port/db`)
    /// * `wallet_id` - The unique identifier of the wallet to open
    /// * `params` - The consensus parameters for the network
    ///
    /// # Errors
    /// Returns an error if the connection pool cannot be created or if there's a database error.
    ///
    /// # Example
    /// ```no_run
    /// use zcash_client_sqlx::{WalletDb, WalletId};
    /// use zcash_protocol::consensus::Network;
    /// use uuid::Uuid;
    ///
    /// let wallet_id = WalletId::from_uuid(Uuid::nil());
    /// let db = WalletDb::for_url(
    ///     "postgresql://user:pass@localhost:5432/mydb",
    ///     wallet_id,
    ///     Network::TestNetwork,
    /// )?;
    /// # Ok::<(), zcash_client_sqlx::error::SqlxClientError>(())
    /// ```
    pub fn for_url(url: &str, wallet_id: WalletId, params: P) -> Result<Self, SqlxClientError> {
        let runtime = Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;
        let pool = runtime.block_on(pool::create_pool_default(url))?;
        Self::for_wallet(pool, wallet_id, params)
    }

    /// Creates a new `WalletDb` instance from a PostgreSQL connection URL (async version).
    ///
    /// This is a convenience function that creates a connection pool from the URL and
    /// then creates a `WalletDb` instance for the specified wallet.
    ///
    /// # Arguments
    /// * `url` - The PostgreSQL connection URL (e.g., `postgresql://user:pass@host:port/db`)
    /// * `wallet_id` - The unique identifier of the wallet to open
    /// * `params` - The consensus parameters for the network
    ///
    /// # Errors
    /// Returns an error if the connection pool cannot be created or if there's a database error.
    ///
    /// # Example
    /// ```no_run
    /// use zcash_client_sqlx::{WalletDb, WalletId};
    /// use zcash_protocol::consensus::Network;
    /// use uuid::Uuid;
    ///
    /// # async fn example() -> Result<(), zcash_client_sqlx::error::SqlxClientError> {
    /// let wallet_id = WalletId::from_uuid(Uuid::nil());
    /// let db = WalletDb::for_url_async(
    ///     "postgresql://user:pass@localhost:5432/mydb",
    ///     wallet_id,
    ///     Network::TestNetwork,
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn for_url_async(
        url: &str,
        wallet_id: WalletId,
        params: P,
    ) -> Result<Self, SqlxClientError> {
        let pool = pool::create_pool_default(url).await?;
        Self::for_wallet(pool, wallet_id, params)
    }

    /// Sets the gap limits for transparent address management.
    #[cfg(feature = "transparent-inputs")]
    pub fn with_gap_limits(mut self, gap_limits: GapLimits) -> Self {
        self.gap_limits = gap_limits;
        self
    }

    /// Returns the wallet ID this instance is bound to.
    pub fn wallet_id(&self) -> WalletId {
        self.wallet_id
    }

    /// Returns a reference to the consensus parameters.
    pub fn params(&self) -> &P {
        &self.params
    }

    /// Returns a reference to the connection pool.
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// Executes a future on the runtime.
    pub(crate) fn block_on<F: std::future::Future>(&self, future: F) -> F::Output {
        match &self.runtime {
            RuntimeHandle::Owned(rt) => rt.block_on(future),
            RuntimeHandle::Handle(handle) => {
                // When using an external handle, we may be called from within an async
                // context. Use block_in_place to avoid panicking.
                tokio::task::block_in_place(|| handle.block_on(future))
            }
        }
    }
}

// Static functions for wallet management
#[cfg(feature = "postgres")]
impl<P: Parameters> WalletDb<P> {
    /// Creates a new wallet in the database.
    ///
    /// # Arguments
    /// * `pool` - The database connection pool
    /// * `params` - The consensus parameters for the network
    /// * `name` - An optional human-readable name for the wallet
    ///
    /// # Returns
    /// The unique identifier for the newly created wallet.
    pub async fn create_wallet_async(
        pool: &Pool,
        params: &P,
        name: Option<&str>,
    ) -> Result<WalletId, SqlxClientError> {
        wallet::create_wallet(pool, params, name).await
    }

    /// Lists all wallets in the database.
    pub async fn list_wallets_async(pool: &Pool) -> Result<Vec<WalletInfo>, SqlxClientError> {
        wallet::list_wallets(pool).await
    }

    /// Deletes a wallet and all associated data from the database.
    ///
    /// **WARNING**: This is a destructive operation that cannot be undone.
    pub async fn delete_wallet_async(
        pool: &Pool,
        wallet_id: WalletId,
    ) -> Result<(), SqlxClientError> {
        wallet::delete_wallet(pool, wallet_id).await
    }
}

// Synchronous versions of wallet management functions
#[cfg(feature = "postgres")]
impl<P: Parameters> WalletDb<P> {
    /// Creates a new wallet in the database (blocking version).
    pub fn create_wallet(
        pool: &Pool,
        params: &P,
        name: Option<&str>,
    ) -> Result<WalletId, SqlxClientError> {
        let runtime = Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;
        runtime.block_on(Self::create_wallet_async(pool, params, name))
    }

    /// Lists all wallets in the database (blocking version).
    pub fn list_wallets(pool: &Pool) -> Result<Vec<WalletInfo>, SqlxClientError> {
        let runtime = Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;
        runtime.block_on(Self::list_wallets_async(pool))
    }

    /// Deletes a wallet and all associated data (blocking version).
    pub fn delete_wallet(pool: &Pool, wallet_id: WalletId) -> Result<(), SqlxClientError> {
        let runtime = Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;
        runtime.block_on(Self::delete_wallet_async(pool, wallet_id))
    }
}

// Implement Debug manually to avoid exposing internal state
#[cfg(feature = "postgres")]
impl<P: Parameters + Debug> Debug for WalletDb<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalletDb")
            .field("wallet_id", &self.wallet_id)
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

#[cfg(feature = "postgres")]
impl<P: Parameters> InputSource for WalletDb<P> {
    type Error = SqlxClientError;
    type AccountId = AccountUuid;
    type NoteRef = ReceivedNoteId;

    fn get_spendable_note(
        &self,
        txid: &TxId,
        protocol: ShieldedProtocol,
        index: u32,
        target_height: TargetHeight,
    ) -> Result<Option<ReceivedNote<Self::NoteRef, Note>>, Self::Error> {
        self.block_on(wallet::get_spendable_note(
            &self.pool,
            &self.params,
            self.wallet_id,
            txid,
            protocol,
            index,
            target_height,
        ))
    }

    fn select_spendable_notes(
        &self,
        account: Self::AccountId,
        target_value: TargetValue,
        sources: &[ShieldedProtocol],
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[Self::NoteRef],
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.block_on(wallet::select_spendable_notes(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            target_value,
            sources,
            target_height,
            confirmations_policy,
            exclude,
        ))
    }

    fn select_unspent_notes(
        &self,
        account: Self::AccountId,
        sources: &[ShieldedProtocol],
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<ReceivedNotes<Self::NoteRef>, Self::Error> {
        self.block_on(wallet::select_unspent_notes(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            sources,
            target_height,
            exclude,
        ))
    }

    fn get_account_metadata(
        &self,
        account: Self::AccountId,
        selector: &NoteFilter,
        target_height: TargetHeight,
        exclude: &[Self::NoteRef],
    ) -> Result<AccountMeta, Self::Error> {
        self.block_on(wallet::get_account_metadata(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            selector,
            target_height,
            exclude,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_unspent_transparent_output(
        &self,
        outpoint: &OutPoint,
        target_height: TargetHeight,
    ) -> Result<Option<WalletUtxo>, Self::Error> {
        self.block_on(wallet::transparent::get_unspent_transparent_output(
            &self.pool,
            &self.params,
            self.wallet_id,
            outpoint,
            target_height,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_spendable_transparent_outputs(
        &self,
        address: &TransparentAddress,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<WalletUtxo>, Self::Error> {
        self.block_on(wallet::transparent::get_spendable_transparent_outputs(
            &self.pool,
            &self.params,
            self.wallet_id,
            address,
            target_height,
            confirmations_policy,
        ))
    }
}

#[cfg(feature = "postgres")]
impl<P: Parameters> WalletRead for WalletDb<P> {
    type Error = SqlxClientError;
    type AccountId = AccountUuid;
    type Account = Account;

    fn get_account_ids(&self) -> Result<Vec<Self::AccountId>, Self::Error> {
        self.block_on(wallet::get_account_ids(&self.pool, self.wallet_id))
    }

    fn get_account(
        &self,
        account_id: Self::AccountId,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.block_on(wallet::get_account(
            &self.pool,
            &self.params,
            self.wallet_id,
            account_id,
        ))
    }

    fn get_derived_account(
        &self,
        derivation: &Zip32Derivation,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.block_on(wallet::get_derived_account(
            &self.pool,
            &self.params,
            self.wallet_id,
            derivation,
        ))
    }

    fn validate_seed(
        &self,
        account_id: Self::AccountId,
        seed: &SecretVec<u8>,
    ) -> Result<bool, Self::Error> {
        self.block_on(wallet::validate_seed(
            &self.pool,
            &self.params,
            self.wallet_id,
            account_id,
            seed,
        ))
    }

    fn seed_relevance_to_derived_accounts(
        &self,
        seed: &SecretVec<u8>,
    ) -> Result<SeedRelevance<Self::AccountId>, Self::Error> {
        self.block_on(wallet::seed_relevance_to_derived_accounts(
            &self.pool,
            &self.params,
            self.wallet_id,
            seed,
        ))
    }

    fn get_account_for_ufvk(
        &self,
        ufvk: &UnifiedFullViewingKey,
    ) -> Result<Option<Self::Account>, Self::Error> {
        self.block_on(wallet::get_account_for_ufvk(
            &self.pool,
            &self.params,
            self.wallet_id,
            ufvk,
        ))
    }

    fn list_addresses(&self, account: Self::AccountId) -> Result<Vec<AddressInfo>, Self::Error> {
        self.block_on(wallet::list_addresses(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
        ))
    }

    fn get_last_generated_address_matching(
        &self,
        account: Self::AccountId,
        address_filter: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.block_on(wallet::get_last_generated_address_matching(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            address_filter,
        ))
        .map(|res| res.map(|(addr, _)| addr))
    }

    fn get_account_birthday(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.block_on(wallet::get_account_birthday(
            &self.pool,
            self.wallet_id,
            account,
        ))
    }

    fn get_wallet_birthday(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.block_on(wallet::get_wallet_birthday(&self.pool, self.wallet_id))
    }

    fn get_wallet_summary(
        &self,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Option<WalletSummary<Self::AccountId>>, Self::Error> {
        self.block_on(wallet::get_wallet_summary(
            &self.pool,
            &self.params,
            self.wallet_id,
            confirmations_policy,
        ))
    }

    fn chain_height(&self) -> Result<Option<BlockHeight>, Self::Error> {
        self.block_on(wallet::chain_height(&self.pool, self.wallet_id))
    }

    fn get_block_hash(&self, block_height: BlockHeight) -> Result<Option<BlockHash>, Self::Error> {
        self.block_on(wallet::get_block_hash(
            &self.pool,
            self.wallet_id,
            block_height,
        ))
    }

    fn block_metadata(&self, height: BlockHeight) -> Result<Option<BlockMetadata>, Self::Error> {
        self.block_on(wallet::block_metadata(&self.pool, self.wallet_id, height))
    }

    fn block_fully_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        self.block_on(wallet::block_fully_scanned(&self.pool, self.wallet_id))
    }

    fn get_max_height_hash(&self) -> Result<Option<(BlockHeight, BlockHash)>, Self::Error> {
        self.block_on(wallet::get_max_height_hash(&self.pool, self.wallet_id))
    }

    fn block_max_scanned(&self) -> Result<Option<BlockMetadata>, Self::Error> {
        self.block_on(wallet::block_max_scanned(&self.pool, self.wallet_id))
    }

    fn suggest_scan_ranges(&self) -> Result<Vec<ScanRange>, Self::Error> {
        self.block_on(wallet::suggest_scan_ranges(&self.pool, self.wallet_id))
    }

    fn get_target_and_anchor_heights(
        &self,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<(TargetHeight, BlockHeight)>, Self::Error> {
        self.block_on(wallet::get_target_and_anchor_heights(
            &self.pool,
            self.wallet_id,
            min_confirmations,
        ))
    }

    fn get_tx_height(&self, txid: TxId) -> Result<Option<BlockHeight>, Self::Error> {
        self.block_on(wallet::get_tx_height(&self.pool, self.wallet_id, txid))
    }

    fn get_unified_full_viewing_keys(
        &self,
    ) -> Result<HashMap<Self::AccountId, UnifiedFullViewingKey>, Self::Error> {
        self.block_on(wallet::get_unified_full_viewing_keys(
            &self.pool,
            &self.params,
            self.wallet_id,
        ))
    }

    fn get_memo(&self, note_id: NoteId) -> Result<Option<Memo>, Self::Error> {
        self.block_on(wallet::get_memo(&self.pool, self.wallet_id, note_id))
    }

    fn get_transaction(&self, txid: TxId) -> Result<Option<Transaction>, Self::Error> {
        self.block_on(wallet::get_transaction(&self.pool, self.wallet_id, txid))
    }

    fn get_sapling_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, sapling::Nullifier)>, Self::Error> {
        self.block_on(wallet::get_sapling_nullifiers(
            &self.pool,
            self.wallet_id,
            query,
        ))
    }

    #[cfg(feature = "orchard")]
    fn get_orchard_nullifiers(
        &self,
        query: NullifierQuery,
    ) -> Result<Vec<(Self::AccountId, orchard::note::Nullifier)>, Self::Error> {
        self.block_on(wallet::get_orchard_nullifiers(
            &self.pool,
            self.wallet_id,
            query,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_receivers(
        &self,
        account: Self::AccountId,
        include_change: bool,
        include_standalone: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.block_on(wallet::transparent::get_transparent_receivers(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            include_change,
            include_standalone,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_ephemeral_transparent_receivers(
        &self,
        account: Self::AccountId,
        exposure_depth: u32,
        exclude_used: bool,
    ) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, Self::Error> {
        self.block_on(wallet::transparent::get_ephemeral_transparent_receivers(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            exposure_depth,
            exclude_used,
            &self.gap_limits,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_balances(
        &self,
        account: Self::AccountId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<HashMap<TransparentAddress, (TransparentKeyScope, Balance)>, Self::Error> {
        self.block_on(wallet::transparent::get_transparent_balances(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            target_height,
            confirmations_policy,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_address_metadata(
        &self,
        account: Self::AccountId,
        address: &TransparentAddress,
    ) -> Result<Option<TransparentAddressMetadata>, Self::Error> {
        self.block_on(wallet::transparent::get_transparent_address_metadata(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            address,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn utxo_query_height(&self, account: Self::AccountId) -> Result<BlockHeight, Self::Error> {
        self.block_on(wallet::transparent::utxo_query_height(
            &self.pool,
            self.wallet_id,
            account,
            &self.gap_limits,
        ))
    }

    fn transaction_data_requests(&self) -> Result<Vec<TransactionDataRequest>, Self::Error> {
        self.block_on(wallet::transaction_data_requests(
            &self.pool,
            self.wallet_id,
        ))
    }

    fn get_received_outputs(
        &self,
        txid: TxId,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Vec<ReceivedTransactionOutput>, Self::Error> {
        self.block_on(wallet::get_received_outputs(
            &self.pool,
            self.wallet_id,
            txid,
            target_height,
            confirmations_policy,
        ))
    }
}

#[cfg(feature = "postgres")]
impl<P: Parameters> WalletWrite for WalletDb<P> {
    type UtxoRef = UtxoId;

    fn create_account(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::AccountId, UnifiedSpendingKey), Self::Error> {
        let (account_id, usk) = self.block_on(wallet::create_account(
            &self.pool,
            &self.params,
            self.wallet_id,
            account_name,
            seed,
            birthday,
            key_source,
        ))?;

        // Generate gap addresses for transparent key scopes
        #[cfg(feature = "transparent-inputs")]
        {
            use transparent::keys::TransparentKeyScope;
            let ufvk = usk.to_unified_full_viewing_key();
            let account_ref = self.block_on(wallet::get_account_ref(
                &self.pool,
                self.wallet_id,
                account_id,
            ))?;
            for key_scope in [
                TransparentKeyScope::EXTERNAL,
                TransparentKeyScope::INTERNAL,
                TransparentKeyScope::EPHEMERAL,
            ] {
                self.block_on(wallet::transparent::generate_gap_addresses(
                    &self.pool,
                    &self.params,
                    self.wallet_id,
                    account_ref.0,
                    &ufvk,
                    key_scope,
                    &self.gap_limits,
                ))?;
            }
        }

        Ok((account_id, usk))
    }

    fn import_account_hd(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        account_index: zip32::AccountId,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Self::Error> {
        let (account, usk) = self.block_on(wallet::import_account_hd(
            &self.pool,
            &self.params,
            self.wallet_id,
            account_name,
            seed,
            account_index,
            birthday,
            key_source,
        ))?;

        // Generate gap addresses for transparent key scopes
        #[cfg(feature = "transparent-inputs")]
        {
            use transparent::keys::TransparentKeyScope;
            use zcash_client_backend::data_api::Account as _;
            let ufvk = account.ufvk().cloned();
            if let Some(ufvk) = ufvk {
                for key_scope in [
                    TransparentKeyScope::EXTERNAL,
                    TransparentKeyScope::INTERNAL,
                    TransparentKeyScope::EPHEMERAL,
                ] {
                    self.block_on(wallet::transparent::generate_gap_addresses(
                        &self.pool,
                        &self.params,
                        self.wallet_id,
                        account.internal_id().0,
                        &ufvk,
                        key_scope,
                        &self.gap_limits,
                    ))?;
                }
            }
        }

        Ok((account, usk))
    }

    fn import_account_ufvk(
        &mut self,
        account_name: &str,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<Self::Account, Self::Error> {
        let account = self.block_on(wallet::import_account_ufvk(
            &self.pool,
            &self.params,
            self.wallet_id,
            account_name,
            unified_key,
            birthday,
            purpose,
            key_source,
        ))?;

        // Generate gap addresses for transparent key scopes
        #[cfg(feature = "transparent-inputs")]
        {
            use transparent::keys::TransparentKeyScope;
            for key_scope in [
                TransparentKeyScope::EXTERNAL,
                TransparentKeyScope::INTERNAL,
                TransparentKeyScope::EPHEMERAL,
            ] {
                self.block_on(wallet::transparent::generate_gap_addresses(
                    &self.pool,
                    &self.params,
                    self.wallet_id,
                    account.internal_id().0,
                    unified_key,
                    key_scope,
                    &self.gap_limits,
                ))?;
            }
        }

        Ok(account)
    }

    fn delete_account(&mut self, account: Self::AccountId) -> Result<(), Self::Error> {
        self.block_on(wallet::delete_account(&self.pool, self.wallet_id, account))
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_pubkey(
        &mut self,
        account: Self::AccountId,
        pubkey: secp256k1::PublicKey,
    ) -> Result<(), Self::Error> {
        self.block_on(wallet::transparent::import_standalone_transparent_pubkey(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            pubkey,
        ))
    }

    fn get_next_available_address(
        &mut self,
        account: Self::AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Self::Error> {
        self.block_on(wallet::get_next_available_address(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            request,
        ))
    }

    fn get_address_for_index(
        &mut self,
        account: Self::AccountId,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Self::Error> {
        self.block_on(wallet::get_address_for_index(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            diversifier_index,
            request,
        ))
    }

    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Self::Error> {
        self.block_on(wallet::update_chain_tip(
            &self.pool,
            &self.params,
            self.wallet_id,
            tip_height,
        ))
    }

    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<Self::AccountId>>,
    ) -> Result<(), Self::Error> {
        // First, do the database operations and collect commitment data
        let result = self.block_on(wallet::put_blocks(
            &self.pool,
            &self.params,
            self.wallet_id,
            from_state,
            blocks,
        ))?;

        // If blocks were processed, update the commitment trees
        if let Some(put_blocks_result) = result {
            // Extract data from result - use Option to allow take() in closure
            let sapling_start_position = put_blocks_result.sapling_start_position;
            let mut sapling_commitments = Some(put_blocks_result.sapling_commitments);
            #[cfg(feature = "orchard")]
            let orchard_start_position = put_blocks_result.orchard_start_position;
            #[cfg(feature = "orchard")]
            let mut orchard_commitments = Some(put_blocks_result.orchard_commitments);

            // Update Sapling commitment tree
            self.with_sapling_tree_mut::<_, _, Self::Error>(|sapling_tree| {
                // Insert the frontier from the chain state with checkpoint retention
                // This allows us to truncate back to this point
                sapling_tree.insert_frontier(
                    from_state.final_sapling_tree().clone(),
                    Retention::Checkpoint {
                        id: from_state.block_height(),
                        marking: Marking::Reference,
                    },
                )?;

                // Insert commitments from the scanned blocks
                if let Some(commitments) = sapling_commitments.take() {
                    sapling_tree.batch_insert(sapling_start_position, commitments.into_iter())?;
                }

                Ok(())
            })?;

            // Update Orchard commitment tree
            #[cfg(feature = "orchard")]
            self.with_orchard_tree_mut::<_, _, Self::Error>(|orchard_tree| {
                // Insert the frontier from the chain state with checkpoint retention
                orchard_tree.insert_frontier(
                    from_state.final_orchard_tree().clone(),
                    Retention::Checkpoint {
                        id: from_state.block_height(),
                        marking: Marking::Reference,
                    },
                )?;

                // Insert commitments from the scanned blocks
                if let Some(commitments) = orchard_commitments.take() {
                    orchard_tree.batch_insert(orchard_start_position, commitments.into_iter())?;
                }

                Ok(())
            })?;

            // Ensure checkpoint synchronization between Sapling and Orchard trees.
            // When both protocols are enabled, we need to ensure that both trees have
            // checkpoints at the same heights so that anchor selection works correctly.
            // This matches the SQLite implementation's `ensure_checkpoints` logic.
            #[cfg(feature = "orchard")]
            {
                use shardtree::store::Checkpoint;
                use std::collections::BTreeMap;

                // Collect ALL checkpoint heights and positions from both trees
                // We use Option<Position> to distinguish between tree_empty (None) and
                // at_position (Some) checkpoints
                let mut sapling_checkpoints: BTreeMap<BlockHeight, Option<Position>> =
                    BTreeMap::new();
                let mut orchard_checkpoints: BTreeMap<BlockHeight, Option<Position>> =
                    BTreeMap::new();

                // Get all Sapling checkpoints (including tree_empty ones)
                self.with_sapling_tree_mut::<_, _, Self::Error>(|sapling_tree| {
                    let count = sapling_tree
                        .store()
                        .checkpoint_count()
                        .map_err(ShardTreeError::Storage)?;
                    sapling_tree
                        .store_mut()
                        .with_checkpoints(count, |height, checkpoint| {
                            sapling_checkpoints.insert(*height, checkpoint.position());
                            Ok(())
                        })
                        .map_err(ShardTreeError::Storage)?;
                    Ok(())
                })?;

                // Get all Orchard checkpoints (including tree_empty ones)
                self.with_orchard_tree_mut::<_, _, Self::Error>(|orchard_tree| {
                    let count = orchard_tree
                        .store()
                        .checkpoint_count()
                        .map_err(ShardTreeError::Storage)?;
                    orchard_tree
                        .store_mut()
                        .with_checkpoints(count, |height, checkpoint| {
                            orchard_checkpoints.insert(*height, checkpoint.position());
                            Ok(())
                        })
                        .map_err(ShardTreeError::Storage)?;
                    Ok(())
                })?;

                // For each Orchard checkpoint height, ensure Sapling has a checkpoint
                // This matches SQLite's ensure_checkpoints logic
                let missing_sapling: Vec<(BlockHeight, Checkpoint)> = orchard_checkpoints
                    .keys()
                    .filter_map(|orchard_height| {
                        // Skip if Sapling already has this checkpoint at this exact height
                        if sapling_checkpoints.contains_key(orchard_height) {
                            return None;
                        }
                        // Find the closest Sapling checkpoint at or below this height
                        let checkpoint = sapling_checkpoints
                            .range::<BlockHeight, _>(..=*orchard_height)
                            .last()
                            .and_then(|(_, pos_opt)| pos_opt.map(Checkpoint::at_position))
                            .unwrap_or_else(|| {
                                from_state
                                    .final_sapling_tree()
                                    .value()
                                    .map_or_else(Checkpoint::tree_empty, |t| {
                                        Checkpoint::at_position(t.position())
                                    })
                            });
                        Some((*orchard_height, checkpoint))
                    })
                    .collect();

                // For each Sapling checkpoint height, ensure Orchard has a checkpoint
                let missing_orchard: Vec<(BlockHeight, Checkpoint)> = sapling_checkpoints
                    .keys()
                    .filter_map(|sapling_height| {
                        // Skip if Orchard already has this checkpoint at this exact height
                        if orchard_checkpoints.contains_key(sapling_height) {
                            return None;
                        }
                        // Find the closest Orchard checkpoint at or below this height
                        let checkpoint = orchard_checkpoints
                            .range::<BlockHeight, _>(..=*sapling_height)
                            .last()
                            .and_then(|(_, pos_opt)| pos_opt.map(Checkpoint::at_position))
                            .unwrap_or_else(|| {
                                from_state
                                    .final_orchard_tree()
                                    .value()
                                    .map_or_else(Checkpoint::tree_empty, |t| {
                                        Checkpoint::at_position(t.position())
                                    })
                            });
                        Some((*sapling_height, checkpoint))
                    })
                    .collect();

                // Add missing Sapling checkpoints
                if !missing_sapling.is_empty() {
                    self.with_sapling_tree_mut::<_, _, Self::Error>(|sapling_tree| {
                        let min_checkpoint = sapling_tree
                            .store()
                            .min_checkpoint_id()
                            .map_err(ShardTreeError::Storage)?;
                        for (height, checkpoint) in &missing_sapling {
                            // Only add checkpoints above the minimum retained checkpoint
                            if min_checkpoint.is_none_or(|min| *height > min) {
                                sapling_tree
                                    .store_mut()
                                    .add_checkpoint(*height, checkpoint.clone())
                                    .map_err(ShardTreeError::Storage)?;
                            }
                        }
                        Ok(())
                    })?;
                }

                // Add missing Orchard checkpoints
                if !missing_orchard.is_empty() {
                    self.with_orchard_tree_mut::<_, _, Self::Error>(|orchard_tree| {
                        let min_checkpoint = orchard_tree
                            .store()
                            .min_checkpoint_id()
                            .map_err(ShardTreeError::Storage)?;
                        for (height, checkpoint) in &missing_orchard {
                            // Only add checkpoints above the minimum retained checkpoint
                            if min_checkpoint.is_none_or(|min| *height > min) {
                                orchard_tree
                                    .store_mut()
                                    .add_checkpoint(*height, checkpoint.clone())
                                    .map_err(ShardTreeError::Storage)?;
                            }
                        }
                        Ok(())
                    })?;
                }
            }
        }

        Ok(())
    }

    fn put_received_transparent_utxo(
        &mut self,
        output: &WalletTransparentOutput,
    ) -> Result<Self::UtxoRef, Self::Error> {
        self.block_on(wallet::put_received_transparent_utxo(
            &self.pool,
            &self.params,
            self.wallet_id,
            output,
        ))
    }

    fn store_decrypted_tx(
        &mut self,
        received_tx: DecryptedTransaction<Self::AccountId>,
    ) -> Result<(), Self::Error> {
        self.block_on(wallet::store_decrypted_tx(
            &self.pool,
            &self.params,
            self.wallet_id,
            received_tx,
        ))
    }

    fn set_tx_trust(&mut self, txid: TxId, trusted: bool) -> Result<(), Self::Error> {
        self.block_on(wallet::set_tx_trust(
            &self.pool,
            self.wallet_id,
            txid,
            trusted,
        ))
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<Self::AccountId>],
    ) -> Result<(), Self::Error> {
        self.block_on(wallet::store_transactions_to_be_sent(
            &self.pool,
            &self.params,
            self.wallet_id,
            transactions,
        ))
    }

    fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Self::Error> {
        // First truncate the database state
        let truncation_height = self.block_on(wallet::truncate_to_height(
            &self.pool,
            self.wallet_id,
            max_height,
        ))?;

        // Then truncate the commitment trees to the checkpoint at the truncation height
        self.with_sapling_tree_mut(|tree| {
            tree.truncate_to_checkpoint(&truncation_height)?;
            Ok::<_, ShardTreeError<SqlxClientError>>(())
        })?;

        #[cfg(feature = "orchard")]
        self.with_orchard_tree_mut(|tree| {
            tree.truncate_to_checkpoint(&truncation_height)?;
            Ok::<_, ShardTreeError<SqlxClientError>>(())
        })?;

        Ok(truncation_height)
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        account_id: Self::AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Self::Error> {
        self.block_on(wallet::transparent::reserve_next_n_ephemeral_addresses(
            &self.pool,
            &self.params,
            self.wallet_id,
            account_id,
            n,
            &self.gap_limits,
        ))
    }

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: data_api::TransactionStatus,
    ) -> Result<(), Self::Error> {
        self.block_on(wallet::set_transaction_status(
            &self.pool,
            &self.params,
            self.wallet_id,
            #[cfg(feature = "transparent-inputs")]
            &self.gap_limits,
            txid,
            status,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn schedule_next_check(
        &mut self,
        address: &TransparentAddress,
        offset_seconds: u32,
    ) -> Result<Option<SystemTime>, Self::Error> {
        self.block_on(wallet::transparent::schedule_next_check(
            &self.pool,
            &self.params,
            self.wallet_id,
            address,
            offset_seconds,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn notify_address_checked(
        &mut self,
        request: TransactionsInvolvingAddress,
        as_of_height: BlockHeight,
    ) -> Result<(), Self::Error> {
        self.block_on(wallet::transparent::notify_address_checked(
            &self.pool,
            self.wallet_id,
            request,
            as_of_height,
        ))
    }
}

// WalletCommitmentTrees implementation
#[cfg(feature = "postgres")]
impl<P: Parameters> WalletCommitmentTrees for WalletDb<P> {
    type Error = SqlxClientError;
    type SaplingShardStore<'a> =
        wallet::commitment_tree::SqlxShardStore<'a, sapling::Node, SAPLING_SHARD_HEIGHT>;

    fn with_sapling_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::SaplingShardStore<'a>,
                { sapling::NOTE_COMMITMENT_TREE_DEPTH },
                SAPLING_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        // commitment tree tables are global (shared across all wallets)
        let store = wallet::commitment_tree::SqlxShardStore::new(
            &self.pool,
            SAPLING_TABLES_PREFIX,
            self.runtime.handle().clone(),
        );
        let mut tree = ShardTree::new(store, 100);
        callback(&mut tree)
    }

    fn put_sapling_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[zcash_client_backend::data_api::chain::CommitmentTreeRoot<sapling::Node>],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        // commitment tree tables are global (shared across all wallets)
        self.block_on(wallet::commitment_tree::put_sapling_subtree_roots::<
            { sapling::NOTE_COMMITMENT_TREE_DEPTH },
            SAPLING_SHARD_HEIGHT,
        >(&self.pool, start_index, roots))
    }

    #[cfg(feature = "orchard")]
    type OrchardShardStore<'a> = wallet::commitment_tree::SqlxShardStore<
        'a,
        orchard::tree::MerkleHashOrchard,
        ORCHARD_SHARD_HEIGHT,
    >;

    #[cfg(feature = "orchard")]
    fn with_orchard_tree_mut<F, A, E>(&mut self, mut callback: F) -> Result<A, E>
    where
        for<'a> F: FnMut(
            &'a mut ShardTree<
                Self::OrchardShardStore<'a>,
                { ORCHARD_SHARD_HEIGHT * 2 },
                ORCHARD_SHARD_HEIGHT,
            >,
        ) -> Result<A, E>,
        E: From<ShardTreeError<Self::Error>>,
    {
        // commitment tree tables are global (shared across all wallets)
        let store = wallet::commitment_tree::SqlxShardStore::new(
            &self.pool,
            ORCHARD_TABLES_PREFIX,
            self.runtime.handle().clone(),
        );
        let mut tree = ShardTree::new(store, 100);
        callback(&mut tree)
    }

    #[cfg(feature = "orchard")]
    fn put_orchard_subtree_roots(
        &mut self,
        start_index: u64,
        roots: &[zcash_client_backend::data_api::chain::CommitmentTreeRoot<
            orchard::tree::MerkleHashOrchard,
        >],
    ) -> Result<(), ShardTreeError<Self::Error>> {
        self.block_on(wallet::commitment_tree::put_orchard_subtree_roots::<
            { ORCHARD_SHARD_HEIGHT * 2 },
            ORCHARD_SHARD_HEIGHT,
        >(&self.pool, start_index, roots))
    }
}

#[cfg(all(any(test, feature = "test-dependencies"), feature = "postgres"))]
impl<P: Parameters> WalletTest for WalletDb<P> {
    fn get_tx_history(&self) -> Result<Vec<TransactionSummary<AccountUuid>>, SqlxClientError> {
        self.block_on(wallet::testing::get_tx_history(
            &self.pool,
            &self.params,
            self.wallet_id,
        ))
    }

    fn get_sent_note_ids(
        &self,
        txid: &TxId,
        protocol: ShieldedProtocol,
    ) -> Result<Vec<NoteId>, SqlxClientError> {
        self.block_on(wallet::testing::get_sent_note_ids(
            &self.pool,
            self.wallet_id,
            txid,
            protocol,
        ))
    }

    fn get_sent_outputs(&self, txid: &TxId) -> Result<Vec<OutputOfSentTx>, SqlxClientError> {
        self.block_on(wallet::testing::get_sent_outputs(
            &self.pool,
            &self.params,
            self.wallet_id,
            txid,
        ))
    }

    fn get_checkpoint_history(
        &self,
        protocol: &ShieldedProtocol,
    ) -> Result<Vec<(BlockHeight, Option<incrementalmerkletree::Position>)>, SqlxClientError> {
        self.block_on(wallet::testing::get_checkpoint_history(
            &self.pool,
            self.wallet_id,
            protocol,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_transparent_output(
        &self,
        outpoint: &OutPoint,
        spendable_as_of: Option<TargetHeight>,
    ) -> Result<Option<WalletTransparentOutput>, SqlxClientError> {
        self.block_on(wallet::testing::get_transparent_output(
            &self.pool,
            &self.params,
            self.wallet_id,
            outpoint,
            spendable_as_of,
        ))
    }

    fn get_notes(
        &self,
        protocol: ShieldedProtocol,
    ) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqlxClientError> {
        self.block_on(wallet::testing::get_notes(
            &self.pool,
            &self.params,
            self.wallet_id,
            protocol,
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    fn get_known_ephemeral_addresses(
        &self,
        account: AccountUuid,
        index_range: Option<std::ops::Range<transparent::keys::NonHardenedChildIndex>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqlxClientError> {
        self.block_on(wallet::testing::get_known_ephemeral_addresses(
            &self.pool,
            &self.params,
            self.wallet_id,
            account,
            index_range,
            &self.gap_limits,
        ))
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "postgres", feature = "test-dependencies"))]
mod tests {
    use zcash_client_backend::data_api::testing::sapling::SaplingPoolTester;

    #[cfg(feature = "orchard")]
    use zcash_client_backend::data_api::testing::orchard::OrchardPoolTester;

    use crate::testing;

    // =========================================================================
    // Sapling pool tests
    // =========================================================================

    #[test]
    fn sapling_send_single_step_proposed_transfer() {
        testing::pool::send_single_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_spend_max_spendable_single_step_proposed_transfer() {
        testing::pool::spend_max_spendable_single_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_spend_everything_single_step_proposed_transfer() {
        testing::pool::spend_everything_single_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_fails_to_send_max_to_transparent_with_memo() {
        testing::pool::fails_to_send_max_to_transparent_with_memo::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_send_max_proposal_fails_when_unconfirmed_funds_present() {
        testing::pool::send_max_proposal_fails_when_unconfirmed_funds_present::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_spend_everything_multi_step_single_note_proposed_transfer() {
        testing::pool::spend_everything_multi_step_single_note_proposed_transfer::<SaplingPoolTester>(
        )
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_spend_everything_multi_step_with_marginal_notes_proposed_transfer() {
        testing::pool::spend_everything_multi_step_with_marginal_notes_proposed_transfer::<
            SaplingPoolTester,
        >()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_spend_everything_multi_step_many_notes_proposed_transfer() {
        testing::pool::spend_everything_multi_step_many_notes_proposed_transfer::<SaplingPoolTester>(
        )
    }

    #[test]
    fn sapling_send_with_multiple_change_outputs() {
        testing::pool::send_with_multiple_change_outputs::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_send_multi_step_proposed_transfer() {
        testing::pool::send_multi_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_spend_all_funds_single_step_proposed_transfer() {
        testing::pool::spend_all_funds_single_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_spend_all_funds_multi_step_proposed_transfer() {
        testing::pool::spend_all_funds_multi_step_proposed_transfer::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_proposal_fails_if_not_all_ephemeral_outputs_consumed() {
        testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_create_to_address_fails_on_incorrect_usk() {
        testing::pool::create_to_address_fails_on_incorrect_usk::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_proposal_fails_with_no_blocks() {
        testing::pool::proposal_fails_with_no_blocks::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_spend_fails_on_unverified_notes() {
        testing::pool::spend_fails_on_unverified_notes::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_spend_fails_on_locked_notes() {
        testing::pool::spend_fails_on_locked_notes::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_ovk_policy_prevents_recovery_from_chain() {
        testing::pool::ovk_policy_prevents_recovery_from_chain::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_spend_succeeds_to_t_addr_zero_change() {
        testing::pool::spend_succeeds_to_t_addr_zero_change::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_change_note_spends_succeed() {
        testing::pool::change_note_spends_succeed::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_account_deletion() {
        testing::pool::account_deletion::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_external_address_change_spends_detected_in_restore_from_seed() {
        testing::pool::external_address_change_spends_detected_in_restore_from_seed::<
            SaplingPoolTester,
        >()
    }

    #[test]
    #[ignore] // FIXME: #1316 This requires support for dust outputs.
    fn sapling_zip317_spend() {
        testing::pool::zip317_spend::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "transparent-inputs")]
    fn sapling_shield_transparent() {
        testing::pool::shield_transparent::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_birthday_in_anchor_shard() {
        testing::pool::birthday_in_anchor_shard::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_checkpoint_gaps() {
        testing::pool::checkpoint_gaps::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_scan_cached_blocks_detects_spends_out_of_order() {
        testing::pool::scan_cached_blocks_detects_spends_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_metadata_queries_exclude_unwanted_notes() {
        testing::pool::metadata_queries_exclude_unwanted_notes::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_valid_chain_states() {
        testing::pool::valid_chain_states::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_data_db_truncation() {
        testing::pool::data_db_truncation::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_reorg_to_checkpoint() {
        testing::pool::reorg_to_checkpoint::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_scan_cached_blocks_allows_blocks_out_of_order() {
        testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_scan_cached_blocks_finds_received_notes() {
        testing::pool::scan_cached_blocks_finds_received_notes::<SaplingPoolTester>()
    }

    #[test]
    fn sapling_scan_cached_blocks_finds_change_notes() {
        testing::pool::scan_cached_blocks_finds_change_notes::<SaplingPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn sapling_pool_crossing_required() {
        testing::pool::pool_crossing_required::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn sapling_fully_funded_fully_private() {
        testing::pool::fully_funded_fully_private::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(all(feature = "orchard", feature = "transparent-inputs"))]
    fn sapling_fully_funded_send_to_t() {
        testing::pool::fully_funded_send_to_t::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn sapling_multi_pool_checkpoint() {
        testing::pool::multi_pool_checkpoint::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[test]
    #[cfg(feature = "orchard")]
    fn sapling_multi_pool_checkpoints_with_pruning() {
        testing::pool::multi_pool_checkpoints_with_pruning::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[cfg(feature = "pczt-tests")]
    #[test]
    fn sapling_pczt_single_step_sapling_only() {
        testing::pool::pczt_single_step::<SaplingPoolTester, SaplingPoolTester>()
    }

    #[cfg(all(feature = "orchard", feature = "pczt-tests"))]
    #[test]
    fn sapling_pczt_single_step_sapling_to_orchard() {
        testing::pool::pczt_single_step::<SaplingPoolTester, OrchardPoolTester>()
    }

    #[cfg(feature = "transparent-inputs")]
    #[test]
    fn sapling_wallet_recovery_compute_fees() {
        testing::pool::wallet_recovery_computes_fees::<SaplingPoolTester>();
    }

    #[test]
    fn sapling_zip315_can_spend_inputs_by_confirmations_policy() {
        testing::pool::can_spend_inputs_by_confirmations_policy::<SaplingPoolTester>();
    }

    #[test]
    fn sapling_receive_two_notes_with_same_value() {
        testing::pool::receive_two_notes_with_same_value::<SaplingPoolTester>();
    }

    // =========================================================================
    // Orchard pool tests
    // =========================================================================

    #[cfg(feature = "orchard")]
    mod orchard_tests {
        use super::*;

        #[test]
        fn orchard_send_single_step_proposed_transfer() {
            testing::pool::send_single_step_proposed_transfer::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_spend_max_spendable_single_step_proposed_transfer() {
            testing::pool::spend_max_spendable_single_step_proposed_transfer::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_spend_everything_single_step_proposed_transfer() {
            testing::pool::spend_everything_single_step_proposed_transfer::<OrchardPoolTester>()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_fails_to_send_max_to_transparent_with_memo() {
            testing::pool::fails_to_send_max_to_transparent_with_memo::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_send_max_proposal_fails_when_unconfirmed_funds_present() {
            testing::pool::send_max_proposal_fails_when_unconfirmed_funds_present::<OrchardPoolTester>(
            )
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_spend_everything_multi_step_single_note_proposed_transfer() {
            testing::pool::spend_everything_multi_step_single_note_proposed_transfer::<
                OrchardPoolTester,
            >()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_spend_everything_multi_step_with_marginal_notes_proposed_transfer() {
            testing::pool::spend_everything_multi_step_with_marginal_notes_proposed_transfer::<
                OrchardPoolTester,
            >()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_spend_everything_multi_step_many_notes_proposed_transfer() {
            testing::pool::spend_everything_multi_step_many_notes_proposed_transfer::<
                OrchardPoolTester,
            >()
        }

        #[test]
        fn orchard_send_with_multiple_change_outputs() {
            testing::pool::send_with_multiple_change_outputs::<OrchardPoolTester>()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_send_multi_step_proposed_transfer() {
            testing::pool::send_multi_step_proposed_transfer::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_spend_all_funds_single_step_proposed_transfer() {
            testing::pool::spend_all_funds_single_step_proposed_transfer::<OrchardPoolTester>()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_spend_all_funds_multi_step_proposed_transfer() {
            testing::pool::spend_all_funds_multi_step_proposed_transfer::<OrchardPoolTester>()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_proposal_fails_if_not_all_ephemeral_outputs_consumed() {
            testing::pool::proposal_fails_if_not_all_ephemeral_outputs_consumed::<OrchardPoolTester>(
            )
        }

        #[test]
        fn orchard_create_to_address_fails_on_incorrect_usk() {
            testing::pool::create_to_address_fails_on_incorrect_usk::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_proposal_fails_with_no_blocks() {
            testing::pool::proposal_fails_with_no_blocks::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_spend_fails_on_unverified_notes() {
            testing::pool::spend_fails_on_unverified_notes::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_spend_fails_on_locked_notes() {
            testing::pool::spend_fails_on_locked_notes::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_ovk_policy_prevents_recovery_from_chain() {
            testing::pool::ovk_policy_prevents_recovery_from_chain::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_spend_succeeds_to_t_addr_zero_change() {
            testing::pool::spend_succeeds_to_t_addr_zero_change::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_change_note_spends_succeed() {
            testing::pool::change_note_spends_succeed::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_account_deletion() {
            testing::pool::account_deletion::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_external_address_change_spends_detected_in_restore_from_seed() {
            testing::pool::external_address_change_spends_detected_in_restore_from_seed::<
                OrchardPoolTester,
            >()
        }

        #[test]
        #[ignore] // FIXME: #1316 This requires support for dust outputs.
        fn orchard_zip317_spend() {
            testing::pool::zip317_spend::<OrchardPoolTester>()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_shield_transparent() {
            testing::pool::shield_transparent::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_birthday_in_anchor_shard() {
            testing::pool::birthday_in_anchor_shard::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_checkpoint_gaps() {
            testing::pool::checkpoint_gaps::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_scan_cached_blocks_detects_spends_out_of_order() {
            testing::pool::scan_cached_blocks_detects_spends_out_of_order::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_metadata_queries_exclude_unwanted_notes() {
            testing::pool::metadata_queries_exclude_unwanted_notes::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_valid_chain_states() {
            testing::pool::valid_chain_states::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_data_db_truncation() {
            testing::pool::data_db_truncation::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_reorg_to_checkpoint() {
            testing::pool::reorg_to_checkpoint::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_scan_cached_blocks_allows_blocks_out_of_order() {
            testing::pool::scan_cached_blocks_allows_blocks_out_of_order::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_scan_cached_blocks_finds_received_notes() {
            testing::pool::scan_cached_blocks_finds_received_notes::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_scan_cached_blocks_finds_change_notes() {
            testing::pool::scan_cached_blocks_finds_change_notes::<OrchardPoolTester>()
        }

        #[test]
        fn orchard_pool_crossing_required() {
            testing::pool::pool_crossing_required::<OrchardPoolTester, SaplingPoolTester>()
        }

        #[test]
        fn orchard_fully_funded_fully_private() {
            testing::pool::fully_funded_fully_private::<OrchardPoolTester, SaplingPoolTester>()
        }

        #[test]
        #[cfg(feature = "transparent-inputs")]
        fn orchard_fully_funded_send_to_t() {
            testing::pool::fully_funded_send_to_t::<OrchardPoolTester, SaplingPoolTester>()
        }

        #[test]
        fn orchard_multi_pool_checkpoint() {
            testing::pool::multi_pool_checkpoint::<OrchardPoolTester, SaplingPoolTester>()
        }

        #[test]
        fn orchard_multi_pool_checkpoints_with_pruning() {
            testing::pool::multi_pool_checkpoints_with_pruning::<OrchardPoolTester, SaplingPoolTester>(
            )
        }

        #[cfg(feature = "pczt-tests")]
        #[test]
        fn orchard_pczt_single_step_orchard_only() {
            testing::pool::pczt_single_step::<OrchardPoolTester, OrchardPoolTester>()
        }

        #[cfg(feature = "pczt-tests")]
        #[test]
        fn orchard_pczt_single_step_orchard_to_sapling() {
            testing::pool::pczt_single_step::<OrchardPoolTester, SaplingPoolTester>()
        }

        #[cfg(feature = "transparent-inputs")]
        #[test]
        fn orchard_wallet_recovery_compute_fees() {
            testing::pool::wallet_recovery_computes_fees::<OrchardPoolTester>();
        }

        #[test]
        fn orchard_zip315_can_spend_inputs_by_confirmations_policy() {
            testing::pool::can_spend_inputs_by_confirmations_policy::<OrchardPoolTester>();
        }

        #[test]
        fn orchard_receive_two_notes_with_same_value() {
            testing::pool::receive_two_notes_with_same_value::<OrchardPoolTester>();
        }
    }
}
