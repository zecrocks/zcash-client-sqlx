//! Connection pool setup and management for the sqlx wallet backend.

use crate::error::SqlxClientError;

/// Configuration options for database connection pools.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of connections in the pool.
    pub max_connections: u32,
    /// Minimum number of connections to keep idle in the pool.
    pub min_connections: u32,
    /// Maximum time to wait for a connection from the pool.
    pub acquire_timeout_secs: u64,
    /// Maximum lifetime of a connection in seconds.
    pub max_lifetime_secs: Option<u64>,
    /// Time after which an idle connection will be closed.
    pub idle_timeout_secs: Option<u64>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_connections: 10,
            min_connections: 1,
            acquire_timeout_secs: 30,
            max_lifetime_secs: Some(1800), // 30 minutes
            idle_timeout_secs: Some(600),  // 10 minutes
        }
    }
}

// PostgreSQL pool type and creation
#[cfg(feature = "postgres")]
pub use sqlx_postgres::PgPool as Pool;

#[cfg(feature = "postgres")]
pub use sqlx_postgres::PgPoolOptions as PoolOptions;

/// Creates a connection pool for the specified database URL.
///
/// # Arguments
/// * `database_url` - The database connection URL (e.g., `postgres://user:pass@localhost/dbname`)
/// * `config` - Pool configuration options
///
/// # Supported URL schemes
/// * `postgres://` or `postgresql://` - PostgreSQL (requires `postgres` feature)
#[cfg(feature = "postgres")]
pub async fn create_pool(database_url: &str, config: &PoolConfig) -> Result<Pool, SqlxClientError> {
    let mut options = PoolOptions::new()
        .max_connections(config.max_connections)
        .min_connections(config.min_connections)
        .acquire_timeout(std::time::Duration::from_secs(config.acquire_timeout_secs));

    if let Some(lifetime) = config.max_lifetime_secs {
        options = options.max_lifetime(std::time::Duration::from_secs(lifetime));
    }

    if let Some(idle) = config.idle_timeout_secs {
        options = options.idle_timeout(std::time::Duration::from_secs(idle));
    }

    options
        .connect(database_url)
        .await
        .map_err(SqlxClientError::from)
}

/// Creates a connection pool with default configuration.
///
/// This is a convenience function equivalent to calling `create_pool(url, &PoolConfig::default())`.
#[cfg(feature = "postgres")]
pub async fn create_pool_default(database_url: &str) -> Result<Pool, SqlxClientError> {
    create_pool(database_url, &PoolConfig::default()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_default() {
        let config = PoolConfig::default();
        assert_eq!(config.max_connections, 10);
        assert_eq!(config.min_connections, 1);
        assert_eq!(config.acquire_timeout_secs, 30);
    }
}
