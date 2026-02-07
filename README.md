# zcash_client_sqlx

A PostgreSQL-backed Zcash light client with native multi-wallet support.

`zcash_client_sqlx` provides a complete PostgreSQL implementation of the `WalletRead`, `WalletWrite`, and `WalletCommitmentTrees` traits from the `zcash_client_backend` crate.

## Prerequisites

- **Rust** 1.85.1 or later
- **Docker** (required for integration tests that use testcontainers)
- **PostgreSQL 16** client libraries (for compilation)

## Building

```bash
cargo build
```

## Running Tests

### Quick tests (no database required)

```bash
cargo test
```

This runs the unit tests and doc-tests. No external services needed.

### Full integration test suite

```bash
cargo test --all-features
```

**Requires Docker**: The integration tests use [testcontainers](https://docs.rs/testcontainers) to automatically spin up a PostgreSQL 16 container. Make sure Docker is running before executing these tests.

## Live Network Sync Tests

To test against the live Zcash network, [use zcash-devtool-sqlx from the sibling repository](https://github.com/zecrocks/zcash-devtool-sqlx). This validates that `zcash_client_sqlx` produces correct results when syncing real blockchain data.

### Setup

```bash
cd ../zcash-devtool
cargo build --features postgres --release
```

### Initialize wallets

Initialize both SQLite (reference) and PostgreSQL wallets with the same viewing key:

```bash
# SQLite wallet (reference baseline)
./target/release/zcash-devtool wallet \
  init-fvk \
  --name "SyncTest" \
  --fvk "<UNIFIED_FULL_VIEWING_KEY>" \
  --birthday <BLOCK_HEIGHT> \
  --server zecrocks --connection direct

# PostgreSQL wallet
./target/release/zcash-devtool wallet \
  --database "postgres://localhost/zcash_sync_test" \
  init-fvk \
  --name "SyncTest" \
  --fvk "<UNIFIED_FULL_VIEWING_KEY>" \
  --birthday <BLOCK_HEIGHT> \
  --server zecrocks --connection direct
```

### Sync

Run the syncs **sequentially** (they share a filesystem block cache):

```bash
# Sync SQLite first
./target/release/zcash-devtool wallet \
  sync --server zecrocks --connection direct

# Then sync PostgreSQL
./target/release/zcash-devtool wallet \
  --database "postgres://localhost/zcash_sync_test" \
  sync --server zecrocks --connection direct
```

### Compare results

```bash
# Export transaction listings
./target/release/zcash-devtool wallet list-tx > /tmp/sqlite_list_tx.txt
./target/release/zcash-devtool wallet \
  --database "postgres://localhost/zcash_sync_test" \
  list-tx > /tmp/postgres_list_tx.txt

# Normalize UUIDs (they differ between databases) and compare
sed -i '' 's/<SQLITE_ACCOUNT_UUID>/ACCOUNT/g' /tmp/sqlite_list_tx.txt
sed -i '' 's/<PG_ACCOUNT_UUID>/ACCOUNT/g' /tmp/postgres_list_tx.txt
diff /tmp/sqlite_list_tx.txt /tmp/postgres_list_tx.txt
```

Expected differences are limited to:
- **Transaction ordering** within the same block height (no tiebreaker in the sort)
- **Output index ordering** within the same transaction
- These are known view-level differences, not data correctness issues

The transaction ID sets should be identical between both backends.

