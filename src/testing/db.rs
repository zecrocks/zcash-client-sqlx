//! Test database setup using testcontainers for PostgreSQL.
#![allow(dead_code, unused_variables, unused_imports)]

use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::Range;
use std::sync::OnceLock;

use ambassador::Delegate;
use secrecy::SecretVec;
use shardtree::{ShardTree, error::ShardTreeError};
use tokio::runtime::Runtime;
use zip32::DiversifierIndex;

use testcontainers::{ContainerAsync, runners::AsyncRunner};
use testcontainers_modules::postgres::Postgres;

use zcash_client_backend::{
    data_api::{
        AccountBirthday,
        AccountMeta,
        AccountPurpose,
        AddressInfo,
        BlockMetadata,
        DecryptedTransaction,
        InputSource,
        NoteFilter,
        NullifierQuery,
        OutputOfSentTx,
        ReceivedNotes,
        ReceivedTransactionOutput,
        SAPLING_SHARD_HEIGHT,
        ScannedBlock,
        SeedRelevance,
        SentTransaction,
        TargetValue,
        TransactionDataRequest,
        TransactionStatus,
        WalletCommitmentTrees,
        WalletRead,
        WalletSummary,
        WalletTest,
        WalletWrite,
        Zip32Derivation,
        // Import the ambassador delegation macros
        ambassador_impl_InputSource,
        ambassador_impl_WalletCommitmentTrees,
        ambassador_impl_WalletRead,
        ambassador_impl_WalletTest,
        ambassador_impl_WalletWrite,
        chain::{ChainState, CommitmentTreeRoot},
        scanning::ScanRange,
        testing::{self, DataStoreFactory, Reset, TestState},
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
};

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_primitives::{
    block::BlockHash,
    transaction::{Transaction, TxId},
};
use zcash_protocol::{
    ShieldedProtocol, consensus::BlockHeight, local_consensus::LocalNetwork, memo::Memo,
};

use crate::{
    AccountUuid, Pool, SqlxClientError, WalletDb,
    init::init_wallet_db,
    pool::{PoolConfig, create_pool},
    wallet::create_wallet,
};

#[cfg(feature = "transparent-inputs")]
use {
    crate::GapLimits,
    std::time::SystemTime,
    transparent::{
        address::TransparentAddress,
        bundle::OutPoint,
        keys::{NonHardenedChildIndex, TransparentKeyScope},
    },
    zcash_client_backend::{
        data_api::{Balance, TransactionsInvolvingAddress, WalletUtxo},
        wallet::TransparentAddressMetadata,
    },
};

/// Global PostgreSQL container shared across all tests.
///
/// Using `OnceLock` ensures the container is started only once and reused
/// across all tests, significantly improving test performance.
static POSTGRES_CONTAINER: OnceLock<ContainerAsync<Postgres>> = OnceLock::new();

/// Get or start the shared PostgreSQL container.
pub(super) async fn get_or_start_container() -> &'static ContainerAsync<Postgres> {
    // If already initialized, return it
    if let Some(container) = POSTGRES_CONTAINER.get() {
        return container;
    }

    // Start a new container
    let container = Postgres::default()
        .start()
        .await
        .expect("Failed to start PostgreSQL container");

    // Try to set it; if another thread beat us, use theirs
    match POSTGRES_CONTAINER.set(container) {
        Ok(()) => POSTGRES_CONTAINER.get().unwrap(),
        Err(_) => POSTGRES_CONTAINER.get().unwrap(),
    }
}

/// Generate a unique database name for test isolation.
pub(super) fn unique_db_name() -> String {
    format!("test_db_{}", uuid::Uuid::new_v4().simple())
}

/// A wrapper around `WalletDb` that provides test-specific functionality.
///
/// This struct uses ambassador to delegate trait implementations to the
/// underlying `WalletDb`, making it a drop-in replacement for tests.
#[allow(clippy::duplicated_attributes, reason = "False positive")]
#[derive(Delegate)]
#[delegate(InputSource, target = "wallet_db")]
#[delegate(WalletRead, target = "wallet_db")]
#[delegate(WalletTest, target = "wallet_db")]
#[delegate(WalletWrite, target = "wallet_db")]
#[delegate(WalletCommitmentTrees, target = "wallet_db")]
pub struct TestDb {
    wallet_db: WalletDb<LocalNetwork>,
    pool: Pool,
    db_name: String,
    admin_pool: Pool,
    /// Keep the runtime alive so the WalletDb's handle remains valid
    #[allow(dead_code)]
    runtime: Runtime,
}

impl TestDb {
    /// Returns a reference to the underlying `WalletDb`.
    pub(crate) fn db(&self) -> &WalletDb<LocalNetwork> {
        &self.wallet_db
    }

    /// Returns a mutable reference to the underlying `WalletDb`.
    pub(crate) fn db_mut(&mut self) -> &mut WalletDb<LocalNetwork> {
        &mut self.wallet_db
    }

    /// Returns a reference to the connection pool.
    pub(crate) fn pool(&self) -> &Pool {
        &self.pool
    }
}

impl Drop for TestDb {
    fn drop(&mut self) {
        // Clean up the test database when the TestDb is dropped.
        // We need to run this in a blocking context since Drop is synchronous.
        let db_name = self.db_name.clone();
        let admin_pool = self.admin_pool.clone();

        // Try to get the current runtime handle, or create a new one
        let result = tokio::runtime::Handle::try_current();
        match result {
            Ok(handle) => {
                // We're in an async context, spawn a task
                handle.spawn(async move {
                    // Close connections to the database first
                    let _ = sqlx_core::query::query(&format!(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                        db_name
                    ))
                    .execute(&admin_pool)
                    .await;

                    // Drop the database
                    let _ = sqlx_core::query::query(&format!(
                        "DROP DATABASE IF EXISTS \"{}\"",
                        db_name
                    ))
                    .execute(&admin_pool)
                    .await;
                });
            }
            Err(_) => {
                // We're not in an async context, create a temporary runtime
                if let Ok(rt) = Runtime::new() {
                    rt.block_on(async {
                        // Close connections to the database first
                        let _ = sqlx_core::query::query(&format!(
                            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{}'",
                            db_name
                        ))
                        .execute(&admin_pool)
                        .await;

                        // Drop the database
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

/// Factory for creating test databases.
///
/// This factory manages the connection to the shared PostgreSQL container
/// and creates isolated databases for each test.
pub struct TestDbFactory {
    container_url: String,
    runtime: Runtime,
}

impl TestDbFactory {
    /// Creates a new `TestDbFactory` connected to the shared PostgreSQL container.
    ///
    /// This function will start the container if it hasn't been started yet.
    pub fn new() -> Self {
        let runtime = Runtime::new().expect("Failed to create Tokio runtime");

        let container_url = runtime.block_on(async {
            let container = get_or_start_container().await;
            let host = container.get_host().await.unwrap();
            let port = container.get_host_port_ipv4(5432).await.unwrap();
            format!("postgres://postgres:postgres@{}:{}", host, port)
        });

        Self {
            container_url,
            runtime,
        }
    }
}

impl Default for TestDbFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl DataStoreFactory for TestDbFactory {
    type Error = SqlxClientError;
    type AccountId = AccountUuid;
    type Account = crate::Account;
    type DsError = SqlxClientError;
    type DataStore = TestDb;

    fn new_data_store(
        &self,
        network: LocalNetwork,
        #[cfg(feature = "transparent-inputs")] gap_limits: Option<
            zcash_client_backend::wallet::transparent::GapLimits,
        >,
    ) -> Result<Self::DataStore, Self::Error> {
        // Create a new runtime for this TestDb instance that will be used for ALL database operations.
        // This is critical: sqlx pools are tied to the tokio runtime they're created in.
        let test_runtime =
            Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;

        // First, use the factory's runtime to create the database (admin operations only)
        let db_name = unique_db_name();
        self.runtime.block_on(async {
            // Connect to the default 'postgres' database for admin operations
            let admin_url = format!("{}/postgres", self.container_url);
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

            // Create the unique test database
            sqlx_core::query::query(&format!("CREATE DATABASE \"{}\"", db_name))
                .execute(&admin_pool)
                .await?;

            Ok::<_, SqlxClientError>(())
        })?;

        // Now use the TEST runtime for everything else - pools must be created in the same
        // runtime they'll be used in
        let container_url = self.container_url.clone();
        let (wallet_db, pool, admin_pool) = test_runtime.block_on(async {
            // Connect to the admin database (in test runtime for cleanup later)
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

            // Connect to the test database
            let db_url = format!("{}/{}", container_url, db_name);
            let pool = create_pool(
                &db_url,
                &PoolConfig {
                    max_connections: 5,
                    min_connections: 1,
                    acquire_timeout_secs: 30,
                    max_lifetime_secs: None,
                    idle_timeout_secs: None,
                },
            )
            .await?;

            // Run migrations to set up the schema
            init_wallet_db(&pool).await?;

            // Create a wallet for testing
            let wallet_id = create_wallet(&pool, &network, Some("test")).await?;

            // Create the WalletDb instance using this runtime's handle
            let handle = tokio::runtime::Handle::current();
            #[allow(unused_mut)]
            let mut wallet_db =
                WalletDb::for_wallet_with_handle(pool.clone(), wallet_id, network, handle);

            #[cfg(feature = "transparent-inputs")]
            if let Some(limits) = gap_limits {
                wallet_db = wallet_db.with_gap_limits(GapLimits::from(limits));
            }

            Ok::<_, SqlxClientError>((wallet_db, pool, admin_pool))
        })?;

        Ok(TestDb {
            wallet_db,
            pool,
            db_name,
            admin_pool,
            runtime: test_runtime,
        })
    }
}

impl Reset for TestDb {
    type Handle = ();

    fn reset<C>(st: &mut TestState<C, Self, LocalNetwork>) {
        let network = *st.network();

        #[cfg(feature = "transparent-inputs")]
        let gap_limits = {
            // Get gap limits from current wallet if available
            None // Use default for now
        };

        let old_db = std::mem::replace(
            st.wallet_mut(),
            TestDbFactory::new()
                .new_data_store(
                    network,
                    #[cfg(feature = "transparent-inputs")]
                    gap_limits,
                )
                .expect("Failed to create new test database"),
        );

        // The old_db will be dropped here, cleaning up the database
        drop(old_db);
    }
}

#[cfg(feature = "transparent-inputs")]
impl From<zcash_client_backend::wallet::transparent::GapLimits> for GapLimits {
    fn from(limits: zcash_client_backend::wallet::transparent::GapLimits) -> Self {
        GapLimits {
            external: limits.external(),
            internal: limits.internal(),
            ephemeral: limits.ephemeral(),
        }
    }
}
