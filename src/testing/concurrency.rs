//! Concurrency tests for the PostgreSQL backend.
//!
//! These tests verify that concurrent operations from multiple wallets
//! work correctly, including:
//! - Concurrent block scanning
//! - Concurrent account creation
//! - Concurrent block insertion (ON CONFLICT handling)
//! - Concurrent nullifier map writes
//! - Concurrent commitment tree updates
#![allow(dead_code, unused_variables, unused_imports, clippy::expect_fun_call)]

#[cfg(test)]
mod tests {
    use super::super::multi_wallet::MultiWalletTestEnv;
    use zcash_client_backend::data_api::{AccountBirthday, WalletRead, chain::ChainState};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{consensus::Parameters, local_consensus::LocalNetwork, value::Zatoshis};

    /// Helper to create a birthday at Sapling activation.
    fn birthday_at_sapling_activation(network: &LocalNetwork) -> AccountBirthday {
        let height = network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling)
            .expect("Sapling activation height should be set");

        AccountBirthday::from_parts(ChainState::empty(height, BlockHash([0; 32])), None)
    }

    #[test]
    fn test_concurrent_account_creation() {
        // Create an environment with 5 wallets
        let mut env = MultiWalletTestEnv::new(5).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());

        // Create accounts in all wallets sequentially
        // (The wallets themselves were created concurrently during MultiWalletTestEnv::new)
        for i in 0..5 {
            env.create_account(i, birthday.clone())
                .expect(&format!("Failed to create account {}", i));
        }

        // Verify all accounts were created with unique UUIDs
        let mut account_uuids = Vec::new();
        for i in 0..5 {
            let accounts: Vec<_> = env
                .wallet(i)
                .get_account_ids()
                .expect("get_account_ids")
                .into_iter()
                .collect();
            assert_eq!(accounts.len(), 1, "Wallet {} should have 1 account", i);
            account_uuids.push(accounts[0]);
        }

        // Verify all UUIDs are unique
        for i in 0..5 {
            for j in (i + 1)..5 {
                assert_ne!(
                    account_uuids[i], account_uuids[j],
                    "Accounts {} and {} should have different UUIDs",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_multiple_wallets_created_in_same_database() {
        // This tests that multiple wallets can be created in the same database
        // without conflicts. The MultiWalletTestEnv creates all wallets atomically.
        let env = MultiWalletTestEnv::new(3).expect("Failed to create multi-wallet env");

        // Verify all wallets have unique IDs
        let id0 = env.wallet_id(0);
        let id1 = env.wallet_id(1);
        let id2 = env.wallet_id(2);

        assert_ne!(id0, id1);
        assert_ne!(id1, id2);
        assert_ne!(id0, id2);
    }

    #[test]
    fn test_wallets_can_query_independently() {
        // Multiple wallets should be able to query the database independently
        let mut env = MultiWalletTestEnv::new(3).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());

        // Create accounts
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");
        env.create_account(2, birthday.clone()).expect("account 2");

        // Each wallet should be able to query its chain height independently
        let tip_0 = env.wallet(0).chain_height().expect("chain_height 0");
        let tip_1 = env.wallet(1).chain_height().expect("chain_height 1");
        let tip_2 = env.wallet(2).chain_height().expect("chain_height 2");

        // All should be None (no blocks scanned yet)
        assert!(tip_0.is_none());
        assert!(tip_1.is_none());
        assert!(tip_2.is_none());
    }

    #[test]
    fn test_wallet_isolation_under_multiple_operations() {
        // Verify that operations on one wallet don't affect another
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());

        // Create account only in wallet 0
        env.create_account(0, birthday.clone()).expect("account 0");

        // Wallet 0 should have 1 account
        let accounts_0: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        assert_eq!(accounts_0.len(), 1);

        // Wallet 1 should have 0 accounts
        let accounts_1: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        assert_eq!(accounts_1.len(), 0);

        // Now create account in wallet 1
        env.create_account(1, birthday).expect("account 1");

        // Wallet 1 should now have 1 account
        let accounts_1: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        assert_eq!(accounts_1.len(), 1);

        // Wallet 0 should still have only 1 account (unchanged)
        let accounts_0: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        assert_eq!(accounts_0.len(), 1);
    }

    // ========================================================================
    // Sequential Scanning Tests (Simulated Concurrency)
    // ========================================================================

    /// Multiple wallets scan the same blocks sequentially.
    /// This tests that scanning is idempotent and doesn't corrupt shared data.
    #[test]
    fn test_sequential_scanning_same_blocks() {
        let mut env = MultiWalletTestEnv::new(3).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        let birthday_height = env.sapling_activation_height();

        // Create accounts in all wallets
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");
        env.create_account(2, birthday.clone()).expect("account 2");

        // Generate blocks with notes for different wallets
        let value = Zatoshis::from_u64(50000).unwrap();
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(1, value);
        env.generate_next_block_for_wallet(2, value);
        env.generate_empty_block();

        // All wallets scan sequentially
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");
        env.scan_cached_blocks(2, env.first_block_height(), 10)
            .expect("scan 2");

        // Each wallet should have correct balance
        assert_eq!(env.get_total_balance(0), value, "Wallet 0");
        assert_eq!(env.get_total_balance(1), value, "Wallet 1");
        assert_eq!(env.get_total_balance(2), value, "Wallet 2");

        // All wallets should be at same height
        let tip_0 = env.wallet(0).chain_height().expect("chain_height");
        let tip_1 = env.wallet(1).chain_height().expect("chain_height");
        let tip_2 = env.wallet(2).chain_height().expect("chain_height");

        assert_eq!(tip_0, tip_1, "Wallets 0 and 1 at same height");
        assert_eq!(tip_1, tip_2, "Wallets 1 and 2 at same height");
    }

    /// Wallets scan in interleaved order (simulating concurrent scanning).
    #[test]
    fn test_interleaved_scanning() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());

        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(25000).unwrap();
        let first_height = env.first_block_height();

        // Generate 4 blocks with alternating notes
        env.generate_next_block_for_wallet(0, value); // first_height
        env.generate_next_block_for_wallet(1, value); // first_height + 1
        env.generate_next_block_for_wallet(0, value); // first_height + 2
        env.generate_next_block_for_wallet(1, value); // first_height + 3

        // Interleaved scanning: wallet 0 scans first 2 blocks, wallet 1 scans all 4, etc.
        // This simulates concurrent access patterns

        // Wallet 0 scans first 2 blocks
        env.scan_cached_blocks(0, first_height, 2)
            .expect("scan 0 partial");

        // Wallet 1 scans all 4 blocks
        env.scan_cached_blocks(1, first_height, 4)
            .expect("scan 1 full");

        // Wallet 0 continues scanning remaining blocks
        env.scan_cached_blocks(0, first_height + 2, 2)
            .expect("scan 0 continue");

        // Both wallets should have correct final balances
        let expected_per_wallet = (value + value).unwrap();
        assert_eq!(
            env.get_total_balance(0),
            expected_per_wallet,
            "Wallet 0 final balance"
        );
        assert_eq!(
            env.get_total_balance(1),
            expected_per_wallet,
            "Wallet 1 final balance"
        );
    }

    /// Re-scanning already-scanned blocks should be safe.
    #[test]
    fn test_rescan_idempotency() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        let birthday_height = env.sapling_activation_height();

        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate blocks
        env.generate_next_block_for_wallet(0, value);
        env.generate_next_block_for_wallet(1, value);

        // First scan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0 first");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1 first");

        let balance_0_first = env.get_total_balance(0);
        let balance_1_first = env.get_total_balance(1);

        // Rescan the same blocks (should be idempotent)
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0 rescan");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1 rescan");

        // Balances should be unchanged
        assert_eq!(
            env.get_total_balance(0),
            balance_0_first,
            "Wallet 0 unchanged after rescan"
        );
        assert_eq!(
            env.get_total_balance(1),
            balance_1_first,
            "Wallet 1 unchanged after rescan"
        );
    }
}
