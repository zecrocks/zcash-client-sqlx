//! Database initialization and migrations.
//!
//! This module uses SQLx's built-in migration system. Migrations are stored in
//! `migrations/` at the crate root and are embedded into the binary at compile time.

#[cfg(feature = "postgres")]
use sqlx_postgres::PgPool;

use crate::SqlxClientError;

/// Initializes the wallet database by running all pending migrations.
///
/// This function should be called before using the database. It will create
/// all necessary tables if they don't exist, or update them if migrations
/// are pending.
///
/// Migrations are automatically tracked in the `_sqlx_migrations` table,
/// which SQLx manages internally.
///
/// # Arguments
/// * `pool` - The database connection pool
#[cfg(feature = "postgres")]
pub async fn init_wallet_db(pool: &PgPool) -> Result<(), SqlxClientError> {
    sqlx_core::migrate::Migrator::new(std::path::Path::new("./migrations"))
        .await?
        .run(pool)
        .await?;
    Ok(())
}

/// Synchronous version of `init_wallet_db`.
#[cfg(feature = "postgres")]
pub fn init_wallet_db_sync(pool: &PgPool) -> Result<(), SqlxClientError> {
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;
    runtime.block_on(init_wallet_db(pool))
}
