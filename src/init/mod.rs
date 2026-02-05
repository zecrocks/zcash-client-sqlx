//! Database initialization and migrations.
//!
//! This module uses SQLx's built-in migration system. Migrations are embedded
//! into the binary at compile time using `include_str!`.

use std::borrow::Cow;

#[cfg(feature = "postgres")]
use sqlx_postgres::PgPool;

use sqlx_core::migrate::{Migration, MigrationType, Migrator};

use crate::SqlxClientError;

const INITIAL_SQL: &str = include_str!("../../migrations/1_initial.sql");

fn embedded_migrator() -> Migrator {
    Migrator {
        migrations: Cow::Owned(vec![Migration::new(
            1,
            Cow::Borrowed("initial"),
            MigrationType::Simple,
            Cow::Borrowed(INITIAL_SQL),
            false,
        )]),
        ignore_missing: false,
        locking: true,
        no_tx: false,
    }
}

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
    embedded_migrator().run(pool).await?;
    Ok(())
}

/// Synchronous version of `init_wallet_db`.
#[cfg(feature = "postgres")]
pub fn init_wallet_db_sync(pool: &PgPool) -> Result<(), SqlxClientError> {
    let runtime =
        tokio::runtime::Runtime::new().map_err(|e| SqlxClientError::TokioRuntime(e.to_string()))?;
    runtime.block_on(init_wallet_db(pool))
}
