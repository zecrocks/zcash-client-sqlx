//! Tests for spending account detection functionality.
//!
//! These tests exercise the `detect_spending_accounts()` functions for
//! Sapling, Orchard, and Transparent pools.

use zcash_client_backend::data_api::AccountBirthday;
use zcash_primitives::block::BlockHash;
use zcash_protocol::value::Zatoshis;

#[allow(unused_imports)]
use super::multi_wallet::MultiWalletTestEnv;

/// Helper to create a birthday at Sapling activation height.
fn birthday_at_sapling_activation(env: &MultiWalletTestEnv) -> AccountBirthday {
    use zcash_client_backend::data_api::chain::ChainState;

    let height = env.sapling_activation_height();
    AccountBirthday::from_parts(ChainState::empty(height, BlockHash([0; 32])), None)
}

/// Test that detect_spending_accounts returns the correct account when a Sapling note is spent.
#[test]
fn test_detect_sapling_spending_accounts_single_account() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    let value = Zatoshis::from_u64(50000).unwrap();
    let (_height, nullifier) = env.generate_next_block_for_wallet(0, value);

    // Scan the block
    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("Failed to scan blocks");

    // Now detect spending accounts for this nullifier
    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    let result = wallet
        .block_on(sapling::detect_spending_accounts(
            pool,
            wallet_id,
            [nullifier].iter(),
        ))
        .expect("detect_spending_accounts failed");

    // Should find the account that owns this note
    let account = env.test_account(0).expect("Account should exist");
    assert!(
        result.contains(&account.account_uuid),
        "Should detect the owning account as spending"
    );
    assert_eq!(result.len(), 1, "Should only detect one account");
}

/// Test that detect_spending_accounts returns empty set for unknown nullifiers.
#[test]
fn test_detect_sapling_spending_accounts_unknown_nullifier() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    let value = Zatoshis::from_u64(50000).unwrap();
    env.generate_next_block_for_wallet(0, value);
    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("Failed to scan blocks");

    // Create a random nullifier that doesn't exist in the wallet
    let fake_nullifier = ::sapling::Nullifier([0u8; 32]);

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    let result = wallet
        .block_on(sapling::detect_spending_accounts(
            pool,
            wallet_id,
            [fake_nullifier].iter(),
        ))
        .expect("detect_spending_accounts failed");

    assert!(
        result.is_empty(),
        "Should not detect any accounts for unknown nullifier"
    );
}

/// Test detect_spending_accounts with multiple accounts in same wallet.
/// When one account's nullifier is queried, only that account should be detected.
#[test]
fn test_detect_sapling_spending_accounts_multi_account_isolation() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);

    // Create first account in the wallet
    env.create_account(0, birthday.clone())
        .expect("Failed to create account");
    let account1_uuid = env.test_account(0).unwrap().account_uuid;

    // Generate note for account 1
    let value = Zatoshis::from_u64(50000).unwrap();
    let (_height, nf1) = env.generate_next_block_for_wallet(0, value);

    // Scan
    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("Failed to scan blocks");

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    // Query for nf1 - should only return account1
    let result = wallet
        .block_on(sapling::detect_spending_accounts(
            pool,
            wallet_id,
            [nf1].iter(),
        ))
        .expect("detect_spending_accounts failed");

    assert_eq!(result.len(), 1, "Should detect exactly one account");
    assert!(result.contains(&account1_uuid), "Should detect account 1");
}

/// Test detect_spending_accounts returns empty for empty nullifier iterator.
#[test]
fn test_detect_sapling_spending_accounts_empty_iterator() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    let empty: Vec<::sapling::Nullifier> = vec![];
    let result = wallet
        .block_on(sapling::detect_spending_accounts(
            pool,
            wallet_id,
            empty.iter(),
        ))
        .expect("detect_spending_accounts failed");

    assert!(result.is_empty(), "Should return empty set for empty input");
}

/// Test detect_spending_accounts works across multiple wallets.
/// Each wallet should only detect accounts within its own wallet.
#[test]
fn test_detect_sapling_spending_accounts_cross_wallet_isolation() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(2).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);

    env.create_account(0, birthday.clone())
        .expect("Failed to create account 0");
    env.create_account(1, birthday.clone())
        .expect("Failed to create account 1");

    let value = Zatoshis::from_u64(50000).unwrap();

    // Generate note for wallet 0
    let (_h1, nf0) = env.generate_next_block_for_wallet(0, value);
    // Generate note for wallet 1
    let (_h2, nf1) = env.generate_next_block_for_wallet(1, value);

    // Scan both wallets
    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("scan 0");
    env.scan_cached_blocks(1, env.first_block_height(), 10)
        .expect("scan 1");

    let account0_uuid = env.test_account(0).unwrap().account_uuid;
    let account1_uuid = env.test_account(1).unwrap().account_uuid;

    // Wallet 0 queries for nf0 - should find account 0
    {
        let wallet = env.wallet(0);
        let result = wallet
            .block_on(sapling::detect_spending_accounts(
                wallet.pool(),
                wallet.wallet_id(),
                [nf0].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert_eq!(result.len(), 1);
        assert!(result.contains(&account0_uuid));
    }

    // Wallet 0 queries for nf1 (wallet 1's nullifier) - should NOT find anything
    {
        let wallet = env.wallet(0);
        let result = wallet
            .block_on(sapling::detect_spending_accounts(
                wallet.pool(),
                wallet.wallet_id(),
                [nf1].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert!(
            result.is_empty(),
            "Wallet 0 should not see wallet 1's nullifiers"
        );
    }

    // Wallet 1 queries for nf1 - should find account 1
    {
        let wallet = env.wallet(1);
        let result = wallet
            .block_on(sapling::detect_spending_accounts(
                wallet.pool(),
                wallet.wallet_id(),
                [nf1].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert_eq!(result.len(), 1);
        assert!(result.contains(&account1_uuid));
    }
}

#[cfg(feature = "orchard")]
mod orchard_tests {
    use super::*;
    use crate::wallet::notes::orchard;

    /// Test detect_spending_accounts returns empty for empty nullifier iterator (Orchard).
    #[test]
    fn test_detect_orchard_spending_accounts_empty_iterator() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        let empty: Vec<::orchard::note::Nullifier> = vec![];
        let result = wallet
            .block_on(orchard::detect_spending_accounts(
                pool,
                wallet_id,
                empty.iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert!(result.is_empty(), "Should return empty set for empty input");
    }

    /// Test that detect_spending_accounts returns the correct account when an Orchard note is spent.
    #[test]
    fn test_detect_orchard_spending_accounts_single_account() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let value = Zatoshis::from_u64(50000).unwrap();
        let (_height, nullifier) = env.generate_next_block_for_orchard(0, value);

        // Scan the block
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        // Now detect spending accounts for this nullifier
        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        let result = wallet
            .block_on(orchard::detect_spending_accounts(
                pool,
                wallet_id,
                [nullifier].iter(),
            ))
            .expect("detect_spending_accounts failed");

        // Should find the account that owns this note
        let account = env.test_account(0).expect("Account should exist");
        assert!(
            result.contains(&account.account_uuid),
            "Should detect the owning account as spending"
        );
        assert_eq!(result.len(), 1, "Should only detect one account");
    }

    /// Test that detect_spending_accounts returns empty set for unknown Orchard nullifiers.
    #[test]
    fn test_detect_orchard_spending_accounts_unknown_nullifier() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let value = Zatoshis::from_u64(50000).unwrap();
        env.generate_next_block_for_orchard(0, value);
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        // Create a random Orchard nullifier that doesn't exist in the wallet
        let fake_nullifier = ::orchard::note::Nullifier::from_bytes(&[0u8; 32])
            .into_option()
            .expect("Valid nullifier bytes");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        let result = wallet
            .block_on(orchard::detect_spending_accounts(
                pool,
                wallet_id,
                [fake_nullifier].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert!(
            result.is_empty(),
            "Should not detect any accounts for unknown nullifier"
        );
    }

    /// Test detect_spending_accounts with multiple Orchard notes in same wallet.
    #[test]
    fn test_detect_orchard_spending_accounts_multi_note() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);

        env.create_account(0, birthday.clone())
            .expect("Failed to create account");
        let account_uuid = env.test_account(0).unwrap().account_uuid;

        // Generate multiple Orchard notes
        let value = Zatoshis::from_u64(50000).unwrap();
        let (_h1, nf1) = env.generate_next_block_for_orchard(0, value);
        let (_h2, nf2) = env.generate_next_block_for_orchard(0, value);

        // Scan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Query for nf1 - should return the account
        let result1 = wallet
            .block_on(orchard::detect_spending_accounts(
                pool,
                wallet_id,
                [nf1].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert_eq!(
            result1.len(),
            1,
            "Should detect exactly one account for nf1"
        );
        assert!(result1.contains(&account_uuid), "Should detect the account");

        // Query for nf2 - should return the same account
        let result2 = wallet
            .block_on(orchard::detect_spending_accounts(
                pool,
                wallet_id,
                [nf2].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert_eq!(
            result2.len(),
            1,
            "Should detect exactly one account for nf2"
        );
        assert!(result2.contains(&account_uuid), "Should detect the account");

        // Query for both - should still return just one account (same account)
        let result_both = wallet
            .block_on(orchard::detect_spending_accounts(
                pool,
                wallet_id,
                [nf1, nf2].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert_eq!(
            result_both.len(),
            1,
            "Should detect exactly one account for both nullifiers"
        );
        assert!(
            result_both.contains(&account_uuid),
            "Should detect the account"
        );
    }

    /// Test detect_spending_accounts works across multiple wallets with Orchard notes.
    #[test]
    fn test_detect_orchard_spending_accounts_cross_wallet_isolation() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);

        env.create_account(0, birthday.clone())
            .expect("Failed to create account 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Generate Orchard note for wallet 0
        let (_h1, nf0) = env.generate_next_block_for_orchard(0, value);
        // Generate Orchard note for wallet 1
        let (_h2, nf1) = env.generate_next_block_for_orchard(1, value);

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        let account0_uuid = env.test_account(0).unwrap().account_uuid;
        let account1_uuid = env.test_account(1).unwrap().account_uuid;

        // Wallet 0 queries for nf0 - should find account 0
        {
            let wallet = env.wallet(0);
            let result = wallet
                .block_on(orchard::detect_spending_accounts(
                    wallet.pool(),
                    wallet.wallet_id(),
                    [nf0].iter(),
                ))
                .expect("detect_spending_accounts failed");

            assert_eq!(result.len(), 1);
            assert!(result.contains(&account0_uuid));
        }

        // Wallet 0 queries for nf1 (wallet 1's nullifier) - should NOT find anything
        {
            let wallet = env.wallet(0);
            let result = wallet
                .block_on(orchard::detect_spending_accounts(
                    wallet.pool(),
                    wallet.wallet_id(),
                    [nf1].iter(),
                ))
                .expect("detect_spending_accounts failed");

            assert!(
                result.is_empty(),
                "Wallet 0 should not see wallet 1's Orchard nullifiers"
            );
        }

        // Wallet 1 queries for nf1 - should find account 1
        {
            let wallet = env.wallet(1);
            let result = wallet
                .block_on(orchard::detect_spending_accounts(
                    wallet.pool(),
                    wallet.wallet_id(),
                    [nf1].iter(),
                ))
                .expect("detect_spending_accounts failed");

            assert_eq!(result.len(), 1);
            assert!(result.contains(&account1_uuid));
        }
    }
}

#[cfg(feature = "transparent-inputs")]
mod transparent_tests {
    use super::*;
    use crate::wallet::transparent;
    use ::transparent::bundle::OutPoint;

    /// Test detect_spending_accounts returns empty for empty outpoint iterator.
    #[test]
    fn test_detect_transparent_spending_accounts_empty_iterator() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        let empty: Vec<OutPoint> = vec![];
        let result = wallet
            .block_on(transparent::detect_spending_accounts(
                pool,
                wallet_id,
                empty.iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert!(result.is_empty(), "Should return empty set for empty input");
    }

    /// Test detect_spending_accounts returns empty for unknown outpoints.
    #[test]
    fn test_detect_transparent_spending_accounts_unknown_outpoint() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Create a fake outpoint that doesn't exist
        let fake_outpoint = OutPoint::new([0u8; 32], 0);

        let result = wallet
            .block_on(transparent::detect_spending_accounts(
                pool,
                wallet_id,
                [fake_outpoint].iter(),
            ))
            .expect("detect_spending_accounts failed");

        assert!(
            result.is_empty(),
            "Should not detect any accounts for unknown outpoint"
        );
    }
}
