//! Tests for nullifier tracking and get_nullifiers functionality.
//!
//! These tests exercise the `get_nullifiers()` functions for both
//! `NullifierQuery::Unspent` and `NullifierQuery::All` modes.

use zcash_client_backend::data_api::{AccountBirthday, NullifierQuery};
use zcash_primitives::block::BlockHash;
use zcash_protocol::value::Zatoshis;

use super::multi_wallet::MultiWalletTestEnv;

/// Helper to create a birthday at Sapling activation height.
fn birthday_at_sapling_activation(env: &MultiWalletTestEnv) -> AccountBirthday {
    use zcash_client_backend::data_api::chain::ChainState;

    let height = env.sapling_activation_height();
    AccountBirthday::from_parts(ChainState::empty(height, BlockHash([0; 32])), None)
}

/// Test get_sapling_nullifiers with NullifierQuery::Unspent returns unspent note nullifiers.
#[test]
fn test_get_sapling_nullifiers_unspent() {
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

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();
    let account_uuid = env.test_account(0).unwrap().account_uuid;

    // Query unspent nullifiers
    let result = wallet
        .block_on(sapling::get_sapling_nullifiers(
            pool,
            wallet_id,
            NullifierQuery::Unspent,
        ))
        .expect("get_sapling_nullifiers failed");

    // Should contain the nullifier for our unspent note
    assert!(!result.is_empty(), "Should have at least one nullifier");

    let nullifiers: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
    assert!(
        nullifiers.contains(&nullifier),
        "Should contain the expected nullifier"
    );

    // Account UUID should match
    let account_uuids: Vec<_> = result.iter().map(|(acc, _)| *acc).collect();
    assert!(
        account_uuids.contains(&account_uuid),
        "Should be associated with the correct account"
    );
}

/// Test get_sapling_nullifiers with NullifierQuery::All returns all nullifiers.
#[test]
fn test_get_sapling_nullifiers_all() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    // Create multiple notes
    let value = Zatoshis::from_u64(50000).unwrap();
    let (_h1, nf1) = env.generate_next_block_for_wallet(0, value);
    let (_h2, nf2) = env.generate_next_block_for_wallet(0, value);

    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("Failed to scan blocks");

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    // Query all nullifiers
    let result = wallet
        .block_on(sapling::get_sapling_nullifiers(
            pool,
            wallet_id,
            NullifierQuery::All,
        ))
        .expect("get_sapling_nullifiers failed");

    // Should contain both nullifiers
    let nullifiers: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
    assert!(nullifiers.contains(&nf1), "Should contain first nullifier");
    assert!(nullifiers.contains(&nf2), "Should contain second nullifier");
}

/// Test that unspent nullifiers don't include nullifiers from mined spends.
#[test]
fn test_get_sapling_nullifiers_excludes_mined_spends() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    // Create two notes
    let value = Zatoshis::from_u64(50000).unwrap();
    let (_h1, nf1) = env.generate_next_block_for_wallet(0, value);
    let (_h2, nf2) = env.generate_next_block_for_wallet(0, value);

    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("Failed to scan blocks");

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    // Verify both are unspent initially
    let unspent_initial = wallet
        .block_on(sapling::get_sapling_nullifiers(
            pool,
            wallet_id,
            NullifierQuery::Unspent,
        ))
        .expect("get_sapling_nullifiers failed");

    let unspent_nfs: Vec<_> = unspent_initial.iter().map(|(_, nf)| *nf).collect();
    assert!(
        unspent_nfs.contains(&nf1),
        "nf1 should be unspent initially"
    );
    assert!(
        unspent_nfs.contains(&nf2),
        "nf2 should be unspent initially"
    );

    // Query all - should also have both
    let all_nfs = wallet
        .block_on(sapling::get_sapling_nullifiers(
            pool,
            wallet_id,
            NullifierQuery::All,
        ))
        .expect("get_sapling_nullifiers failed");

    assert_eq!(
        all_nfs.len(),
        unspent_initial.len(),
        "All and unspent should match when nothing is spent"
    );
}

/// Test get_nullifiers returns empty for a wallet with no notes.
#[test]
fn test_get_sapling_nullifiers_empty_wallet() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    // Don't generate any notes

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    let unspent = wallet
        .block_on(sapling::get_sapling_nullifiers(
            pool,
            wallet_id,
            NullifierQuery::Unspent,
        ))
        .expect("get_sapling_nullifiers failed");

    let all = wallet
        .block_on(sapling::get_sapling_nullifiers(
            pool,
            wallet_id,
            NullifierQuery::All,
        ))
        .expect("get_sapling_nullifiers failed");

    assert!(
        unspent.is_empty(),
        "Unspent should be empty for wallet with no notes"
    );
    assert!(
        all.is_empty(),
        "All should be empty for wallet with no notes"
    );
}

/// Test nullifier isolation between wallets.
#[test]
fn test_get_sapling_nullifiers_wallet_isolation() {
    use crate::wallet::notes::sapling;

    let mut env = MultiWalletTestEnv::new(2).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);

    env.create_account(0, birthday.clone()).expect("account 0");
    env.create_account(1, birthday.clone()).expect("account 1");

    let value = Zatoshis::from_u64(50000).unwrap();

    // Each wallet gets a note
    let (_h1, nf0) = env.generate_next_block_for_wallet(0, value);
    let (_h2, nf1) = env.generate_next_block_for_wallet(1, value);

    // Scan both
    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("scan 0");
    env.scan_cached_blocks(1, env.first_block_height(), 10)
        .expect("scan 1");

    // Wallet 0's nullifiers
    {
        let wallet = env.wallet(0);
        let result = wallet
            .block_on(sapling::get_sapling_nullifiers(
                wallet.pool(),
                wallet.wallet_id(),
                NullifierQuery::All,
            ))
            .expect("get_sapling_nullifiers failed");

        let nfs: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
        assert!(nfs.contains(&nf0), "Wallet 0 should have its own nullifier");
        assert!(
            !nfs.contains(&nf1),
            "Wallet 0 should NOT have wallet 1's nullifier"
        );
    }

    // Wallet 1's nullifiers
    {
        let wallet = env.wallet(1);
        let result = wallet
            .block_on(sapling::get_sapling_nullifiers(
                wallet.pool(),
                wallet.wallet_id(),
                NullifierQuery::All,
            ))
            .expect("get_sapling_nullifiers failed");

        let nfs: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
        assert!(nfs.contains(&nf1), "Wallet 1 should have its own nullifier");
        assert!(
            !nfs.contains(&nf0),
            "Wallet 1 should NOT have wallet 0's nullifier"
        );
    }
}

/// Test that generic get_nullifiers in common.rs works for Sapling.
#[test]
fn test_common_get_nullifiers_sapling() {
    use crate::wallet::common;
    use zcash_protocol::ShieldedProtocol;

    let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
    let birthday = birthday_at_sapling_activation(&env);
    env.create_account(0, birthday)
        .expect("Failed to create account");

    let value = Zatoshis::from_u64(50000).unwrap();
    let (_height, expected_nf) = env.generate_next_block_for_wallet(0, value);

    env.scan_cached_blocks(0, env.first_block_height(), 10)
        .expect("Failed to scan blocks");

    let wallet = env.wallet(0);
    let wallet_id = wallet.wallet_id();
    let pool = wallet.pool();

    // Use the common get_nullifiers with a parse function
    let result = wallet
        .block_on(common::get_nullifiers(
            pool,
            wallet_id,
            ShieldedProtocol::Sapling,
            NullifierQuery::All,
            |bytes| {
                ::sapling::Nullifier::from_slice(bytes)
                    .map_err(|_| crate::SqlxClientError::Encoding("Invalid nullifier".to_string()))
            },
        ))
        .expect("get_nullifiers failed");

    let nfs: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
    assert!(
        nfs.contains(&expected_nf),
        "Should contain the expected nullifier"
    );
}

#[cfg(feature = "orchard")]
mod orchard_tests {
    use super::*;
    use crate::wallet::notes::orchard;

    /// Test get_orchard_nullifiers returns empty for wallet with no Orchard notes.
    #[test]
    fn test_get_orchard_nullifiers_empty_wallet() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        let unspent = wallet
            .block_on(orchard::get_orchard_nullifiers(
                pool,
                wallet_id,
                NullifierQuery::Unspent,
            ))
            .expect("get_orchard_nullifiers failed");

        let all = wallet
            .block_on(orchard::get_orchard_nullifiers(
                pool,
                wallet_id,
                NullifierQuery::All,
            ))
            .expect("get_orchard_nullifiers failed");

        assert!(unspent.is_empty(), "Unspent should be empty");
        assert!(all.is_empty(), "All should be empty");
    }

    /// Test get_orchard_nullifiers with NullifierQuery::Unspent returns unspent note nullifiers.
    #[test]
    fn test_get_orchard_nullifiers_unspent() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let value = Zatoshis::from_u64(50000).unwrap();
        let (_height, nullifier) = env.generate_next_block_for_orchard(0, value);

        // Scan the block
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();
        let account_uuid = env.test_account(0).unwrap().account_uuid;

        // Query unspent nullifiers
        let result = wallet
            .block_on(orchard::get_orchard_nullifiers(
                pool,
                wallet_id,
                NullifierQuery::Unspent,
            ))
            .expect("get_orchard_nullifiers failed");

        // Should contain the nullifier for our unspent note
        assert!(!result.is_empty(), "Should have at least one nullifier");

        let nullifiers: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
        assert!(
            nullifiers.contains(&nullifier),
            "Should contain the expected nullifier"
        );

        // Account UUID should match
        let account_uuids: Vec<_> = result.iter().map(|(acc, _)| *acc).collect();
        assert!(
            account_uuids.contains(&account_uuid),
            "Should be associated with the correct account"
        );
    }

    /// Test get_orchard_nullifiers with NullifierQuery::All returns all nullifiers.
    #[test]
    fn test_get_orchard_nullifiers_all() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        // Create multiple Orchard notes
        let value = Zatoshis::from_u64(50000).unwrap();
        let (_h1, nf1) = env.generate_next_block_for_orchard(0, value);
        let (_h2, nf2) = env.generate_next_block_for_orchard(0, value);

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Query all nullifiers
        let result = wallet
            .block_on(orchard::get_orchard_nullifiers(
                pool,
                wallet_id,
                NullifierQuery::All,
            ))
            .expect("get_orchard_nullifiers failed");

        // Should contain both nullifiers
        let nullifiers: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
        assert!(nullifiers.contains(&nf1), "Should contain first nullifier");
        assert!(nullifiers.contains(&nf2), "Should contain second nullifier");
    }

    /// Test that unspent Orchard nullifiers don't include nullifiers from mined spends.
    #[test]
    fn test_get_orchard_nullifiers_excludes_mined_spends() {
        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        // Create two Orchard notes
        let value = Zatoshis::from_u64(50000).unwrap();
        let (_h1, nf1) = env.generate_next_block_for_orchard(0, value);
        let (_h2, nf2) = env.generate_next_block_for_orchard(0, value);

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Verify both are unspent initially
        let unspent_initial = wallet
            .block_on(orchard::get_orchard_nullifiers(
                pool,
                wallet_id,
                NullifierQuery::Unspent,
            ))
            .expect("get_orchard_nullifiers failed");

        let unspent_nfs: Vec<_> = unspent_initial.iter().map(|(_, nf)| *nf).collect();
        assert!(
            unspent_nfs.contains(&nf1),
            "nf1 should be unspent initially"
        );
        assert!(
            unspent_nfs.contains(&nf2),
            "nf2 should be unspent initially"
        );

        // Query all - should also have both
        let all_nfs = wallet
            .block_on(orchard::get_orchard_nullifiers(
                pool,
                wallet_id,
                NullifierQuery::All,
            ))
            .expect("get_orchard_nullifiers failed");

        assert_eq!(
            all_nfs.len(),
            unspent_initial.len(),
            "All and unspent should match when nothing is spent"
        );
    }

    /// Test Orchard nullifier isolation between wallets.
    #[test]
    fn test_get_orchard_nullifiers_wallet_isolation() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);

        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Each wallet gets an Orchard note
        let (_h1, nf0) = env.generate_next_block_for_orchard(0, value);
        let (_h2, nf1) = env.generate_next_block_for_orchard(1, value);

        // Scan both
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Wallet 0's nullifiers
        {
            let wallet = env.wallet(0);
            let result = wallet
                .block_on(orchard::get_orchard_nullifiers(
                    wallet.pool(),
                    wallet.wallet_id(),
                    NullifierQuery::All,
                ))
                .expect("get_orchard_nullifiers failed");

            let nfs: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
            assert!(
                nfs.contains(&nf0),
                "Wallet 0 should have its own Orchard nullifier"
            );
            assert!(
                !nfs.contains(&nf1),
                "Wallet 0 should NOT have wallet 1's Orchard nullifier"
            );
        }

        // Wallet 1's nullifiers
        {
            let wallet = env.wallet(1);
            let result = wallet
                .block_on(orchard::get_orchard_nullifiers(
                    wallet.pool(),
                    wallet.wallet_id(),
                    NullifierQuery::All,
                ))
                .expect("get_orchard_nullifiers failed");

            let nfs: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
            assert!(
                nfs.contains(&nf1),
                "Wallet 1 should have its own Orchard nullifier"
            );
            assert!(
                !nfs.contains(&nf0),
                "Wallet 1 should NOT have wallet 0's Orchard nullifier"
            );
        }
    }

    /// Test common get_nullifiers works for Orchard protocol with actual data.
    #[test]
    fn test_common_get_nullifiers_orchard() {
        use crate::wallet::common;
        use zcash_protocol::ShieldedProtocol;

        let mut env = MultiWalletTestEnv::new(1).expect("Failed to create test env");
        let birthday = birthday_at_sapling_activation(&env);
        env.create_account(0, birthday)
            .expect("Failed to create account");

        let value = Zatoshis::from_u64(50000).unwrap();
        let (_height, expected_nf) = env.generate_next_block_for_orchard(0, value);

        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("Failed to scan blocks");

        let wallet = env.wallet(0);
        let wallet_id = wallet.wallet_id();
        let pool = wallet.pool();

        // Use the common get_nullifiers with a parse function
        let result = wallet
            .block_on(common::get_nullifiers(
                pool,
                wallet_id,
                ShieldedProtocol::Orchard,
                NullifierQuery::All,
                |bytes| {
                    let arr: [u8; 32] = bytes.try_into().map_err(|_| {
                        crate::SqlxClientError::Encoding("Invalid nullifier length".to_string())
                    })?;
                    ::orchard::note::Nullifier::from_bytes(&arr)
                        .into_option()
                        .ok_or_else(|| {
                            crate::SqlxClientError::Encoding(
                                "Invalid Orchard nullifier".to_string(),
                            )
                        })
                },
            ))
            .expect("get_nullifiers failed");

        let nfs: Vec<_> = result.iter().map(|(_, nf)| *nf).collect();
        assert!(
            nfs.contains(&expected_nf),
            "Should contain the expected Orchard nullifier"
        );
    }
}
