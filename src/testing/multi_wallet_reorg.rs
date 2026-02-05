//! Multi-wallet reorg tests for the PostgreSQL backend.
//!
//! These tests verify correct behavior when a chain reorganization occurs
//! while multiple wallets exist in the same database. Key scenarios include:
//! - Both wallets at the same height when reorg occurs
#![allow(dead_code, unused_variables, unused_imports)]
//! - Wallets at different heights when reorg occurs
//! - Reorg height above/below wallet scan heights
//! - Nullifier map cleanup across all wallets
//! - Checkpoint integrity after reorg

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
    fn test_truncate_with_multiple_wallets() {
        // Setup: Create environment with 2 wallets
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone())
            .expect("Failed to create account 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account 1");

        // Truncate should work with multiple wallets
        let result = env.truncate_all_to_height(env.sapling_activation_height());
        assert!(result.is_ok(), "Truncate should succeed");

        // Both wallets should still be accessible
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

        // Both should still have their accounts
        assert_eq!(accounts_0.len(), 1);
        assert_eq!(accounts_1.len(), 1);
    }

    #[test]
    fn test_truncate_preserves_wallet_isolation() {
        // Verify that truncate operations maintain wallet isolation
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone())
            .expect("Failed to create account 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account 1");

        // Get the account IDs before truncate
        let accounts_0_before: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        let accounts_1_before: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();

        // Truncate
        env.truncate_all_to_height(env.sapling_activation_height())
            .expect("Truncate should succeed");

        // Get the account IDs after truncate
        let accounts_0_after: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        let accounts_1_after: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();

        // Accounts should be unchanged
        assert_eq!(accounts_0_before, accounts_0_after);
        assert_eq!(accounts_1_before, accounts_1_after);

        // Wallet 0's account should still not be visible to wallet 1
        let account_from_1 = env.wallet(1).get_account(accounts_0_after[0]);
        assert!(account_from_1.is_ok());
        assert!(account_from_1.unwrap().is_none());
    }

    #[test]
    fn test_global_chain_state_after_truncate() {
        // Both wallets should see the same chain state after truncate
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone())
            .expect("Failed to create account 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account 1");

        // Both wallets should have the same chain height (None initially)
        let tip_0_before = env.wallet(0).chain_height().expect("chain_height");
        let tip_1_before = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(tip_0_before, tip_1_before);

        // Truncate
        env.truncate_all_to_height(env.sapling_activation_height())
            .expect("Truncate should succeed");

        // Both should still have the same chain height
        let tip_0_after = env.wallet(0).chain_height().expect("chain_height");
        let tip_1_after = env.wallet(1).chain_height().expect("chain_height");
        assert_eq!(tip_0_after, tip_1_after);
    }

    #[test]
    fn test_multiple_truncates() {
        // Multiple truncate operations at different heights should work correctly
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone())
            .expect("Failed to create account 0");
        env.create_account(1, birthday.clone())
            .expect("Failed to create account 1");

        let value = Zatoshis::from_u64(25000).unwrap();

        // Build a chain with notes at different heights
        let (h2, _) = env.generate_next_block_for_wallet(0, value); // h2
        let (h3, _) = env.generate_next_block_for_wallet(1, value); // h3
        let (h4, _) = env.generate_next_block_for_wallet(0, value); // h4
        let (h5, _) = env.generate_next_block_for_wallet(1, value); // h5
        let (h6, _) = env.generate_next_block_for_wallet(0, value); // h6

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        // Initial state: W0 has 3 notes (h2,h4,h6), W1 has 2 notes (h3,h5)
        let expected_0 = ((value + value).unwrap() + value).unwrap();
        let expected_1 = (value + value).unwrap();
        assert_eq!(env.get_total_balance(0), expected_0, "W0 initial");
        assert_eq!(env.get_total_balance(1), expected_1, "W1 initial");

        // First truncate to h5 - W0 loses h6, W1 unchanged
        env.truncate_to_height(h5);
        assert_eq!(
            env.get_spendable_balance(0, 1),
            (value + value).unwrap(),
            "W0 after truncate to h5"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            (value + value).unwrap(),
            "W1 after truncate to h5"
        );

        // Add new blocks after first truncate
        let (h6b, _) = env.generate_next_block_for_wallet(1, value); // h6 - now for W1
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0 after reorg");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1 after reorg");

        // State: W0 has 2 mined + 1 pending, W1 has 3 mined
        assert_eq!(
            env.get_spendable_balance(0, 1),
            (value + value).unwrap(),
            "W0 spendable after chain extension"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            ((value + value).unwrap() + value).unwrap(),
            "W1 spendable after chain extension"
        );

        // Second truncate to h3 - W0 loses h4, W1 loses h5 and h6b
        env.truncate_to_height(h3);
        assert_eq!(
            env.get_spendable_balance(0, 1),
            value,
            "W0 after second truncate"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            value,
            "W1 after second truncate"
        );

        // Third truncate to h2 - W1 loses its only mined note
        env.truncate_to_height(h2);
        assert_eq!(
            env.get_spendable_balance(0, 1),
            value,
            "W0 after third truncate"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "W1 after third truncate (all pending)"
        );

        // W1 should still have total balance from pending notes
        assert!(
            env.get_total_balance(1) > Zatoshis::ZERO,
            "W1 should have pending notes in total balance"
        );

        // Wallets should still work correctly
        let accounts_0: Vec<_> = env
            .wallet(0)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        assert_eq!(accounts_0.len(), 1);
        let accounts_1: Vec<_> = env
            .wallet(1)
            .get_account_ids()
            .expect("get_account_ids")
            .into_iter()
            .collect();
        assert_eq!(accounts_1.len(), 1);
    }

    // ========================================================================
    // Advanced Reorg Tests with Notes
    // ========================================================================

    /// Complex reorg scenario with multiple wallets at different scan heights.
    #[test]
    fn test_reorg_with_wallets_at_different_heights() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(10000).unwrap();

        // Build chain: wallet 0 has notes at heights 2, 4, 6
        // wallet 1 has notes at heights 3, 5
        env.generate_next_block_for_wallet(0, value); // h2
        env.generate_next_block_for_wallet(1, value); // h3
        env.generate_next_block_for_wallet(0, value); // h4
        env.generate_next_block_for_wallet(1, value); // h5
        env.generate_next_block_for_wallet(0, value); // h6

        // Wallet 0 scans to height 6
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");

        // Wallet 1 only scans to height 4
        env.scan_cached_blocks(1, env.first_block_height(), 3)
            .expect("scan 1 partial");

        // Wallet 0 should have 3 notes (30000)
        let expected_0 = ((value + value).unwrap() + value).unwrap();
        assert_eq!(
            env.get_total_balance(0),
            expected_0,
            "Wallet 0 before reorg"
        );

        // Wallet 1 should have 1 note (from h3, within scan range)
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 before reorg");

        // Reorg to height 5 (wallet 0 loses note at h6, wallet 1's scan range unaffected)
        env.truncate_to_height(env.first_block_height() + 3); // height 5

        // After truncation, notes above height 5 become pending (not spendable).
        // Wallet 0 should have 2 spendable notes (h2, h4), note at h6 is pending.
        let expected_0_after = (value + value).unwrap();
        assert_eq!(
            env.get_spendable_balance(0, 1),
            expected_0_after,
            "Wallet 0 spendable after reorg"
        );

        // TOTAL BALANCE verification: Wallet 0's total should include the pending note
        assert_eq!(
            env.get_total_balance(0),
            expected_0,
            "Wallet 0 total balance should include pending note at h6"
        );

        // Wallet 1's note at h3 should still be spendable
        assert_eq!(
            env.get_spendable_balance(1, 1),
            value,
            "Wallet 1 spendable unchanged"
        );

        // Wallet 1's total should equal spendable (no pending notes for wallet 1)
        assert_eq!(env.get_total_balance(1), value, "Wallet 1 total unchanged");
    }

    /// Reorg followed by new blocks with different notes.
    #[test]
    fn test_reorg_and_rescan_different_chain() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value_small = Zatoshis::from_u64(10000).unwrap();
        let value_large = Zatoshis::from_u64(90000).unwrap();

        // Original chain: wallet 0 gets small value
        env.generate_next_block_for_wallet(0, value_small);
        env.generate_empty_block();

        // Scan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        assert_eq!(env.get_total_balance(0), value_small, "Wallet 0 on chain A");
        assert_eq!(
            env.get_total_balance(1),
            Zatoshis::ZERO,
            "Wallet 1 on chain A"
        );

        // Reorg
        env.truncate_to_height(env.sapling_activation_height());

        // New chain: wallet 1 gets large value, wallet 0 gets nothing
        env.generate_next_block_for_wallet(1, value_large);
        env.generate_empty_block();

        // Rescan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("rescan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("rescan 1");

        // Spendable balances should reflect new chain.
        // Wallet 0's old note stays pending but is not spendable.
        assert_eq!(
            env.get_spendable_balance(0, 1),
            Zatoshis::ZERO,
            "Wallet 0 spendable on chain B"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            value_large,
            "Wallet 1 spendable on chain B"
        );

        // TOTAL BALANCE verification: Wallet 0's total should include pending note from chain A
        assert_eq!(
            env.get_total_balance(0),
            value_small,
            "Wallet 0 total should include pending note from chain A"
        );
        // Wallet 1's total equals spendable (new note from chain B)
        assert_eq!(
            env.get_total_balance(1),
            value_large,
            "Wallet 1 total on chain B"
        );
    }

    /// Deep reorg affecting many blocks.
    #[test]
    fn test_deep_reorg() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        // Use value > MARGINAL_FEE (5000) to avoid being classified as dust/uneconomic
        let value = Zatoshis::from_u64(10000).unwrap();

        // Build a longer chain (10 blocks)
        for i in 0..10 {
            if i % 2 == 0 {
                env.generate_next_block_for_wallet(0, value);
            } else {
                env.generate_next_block_for_wallet(1, value);
            }
        }

        // Scan both wallets
        env.scan_cached_blocks(0, env.first_block_height(), 20)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 20)
            .expect("scan 1");

        // Each wallet should have 5 notes
        let expected =
            (((((value + value).unwrap() + value).unwrap() + value).unwrap()) + value).unwrap();
        assert_eq!(
            env.get_total_balance(0),
            expected,
            "Wallet 0 before deep reorg"
        );
        assert_eq!(
            env.get_total_balance(1),
            expected,
            "Wallet 1 before deep reorg"
        );

        // Deep reorg back to first_block_height (keeps only block at h2)
        // Truncate is inclusive: truncate_to_height(h) keeps blocks up to and including h
        env.truncate_to_height(env.first_block_height());

        // After deep reorg, notes above first_block_height become pending (not spendable).
        // - Wallet 0 should have 1 spendable note (at h2 = first_block_height)
        // - Wallet 1 should have 0 spendable notes (first note was at h3, now pending)
        assert_eq!(
            env.get_spendable_balance(0, 1),
            value,
            "Wallet 0 spendable after deep reorg"
        );
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "Wallet 1 spendable after deep reorg"
        );
    }

    /// Reorg to exactly the height of a note.
    #[test]
    fn test_reorg_at_note_height() {
        let mut env = MultiWalletTestEnv::new(2).expect("Failed to create multi-wallet env");

        let birthday = birthday_at_sapling_activation(env.network());
        env.create_account(0, birthday.clone()).expect("account 0");
        env.create_account(1, birthday.clone()).expect("account 1");

        let value = Zatoshis::from_u64(50000).unwrap();

        // Wallet 0 note at height 2
        let (h2, _) = env.generate_next_block_for_wallet(0, value);
        // Wallet 1 note at height 3
        let (_h3, _) = env.generate_next_block_for_wallet(1, value);

        // Scan
        env.scan_cached_blocks(0, env.first_block_height(), 10)
            .expect("scan 0");
        env.scan_cached_blocks(1, env.first_block_height(), 10)
            .expect("scan 1");

        assert_eq!(env.get_total_balance(0), value);
        assert_eq!(env.get_total_balance(1), value);

        // Reorg to exactly height 2 (where wallet 0's note is)
        // The note at h2 stays mined and spendable, h3 becomes pending.
        env.truncate_to_height(h2);

        // Wallet 0's note at the reorg height survives and is spendable
        assert_eq!(
            env.get_spendable_balance(0, 1),
            value,
            "Wallet 0 note at reorg height survives"
        );
        // Wallet 1's note above the reorg height is now pending (not spendable)
        assert_eq!(
            env.get_spendable_balance(1, 1),
            Zatoshis::ZERO,
            "Wallet 1 note above reorg is not spendable"
        );

        // TOTAL BALANCE verification
        assert_eq!(
            env.get_total_balance(0),
            value,
            "Wallet 0 total equals spendable (no pending)"
        );
        assert_eq!(
            env.get_total_balance(1),
            value,
            "Wallet 1 total includes pending note"
        );
    }
}
