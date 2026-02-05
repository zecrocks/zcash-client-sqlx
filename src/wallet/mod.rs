//! Wallet operations for the sqlx-backed wallet implementation.

use std::collections::HashMap;
use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use incrementalmerkletree::{Position, Retention};
use secrecy::SecretVec;
use uuid::Uuid;
use zip32::DiversifierIndex;

use zcash_client_backend::{
    data_api::{
        AccountBirthday, AccountMeta, AccountPurpose, AddressInfo, BlockMetadata,
        DecryptedTransaction, NoteFilter, NullifierQuery, ReceivedNotes, ReceivedTransactionOutput,
        ScannedBlock, SeedRelevance, SentTransaction, TargetValue, TransactionDataRequest,
        TransactionStatus, WalletSummary, Zip32Derivation,
        chain::ChainState,
        scanning::ScanRange,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
};
use zcash_keys::{
    address::UnifiedAddress,
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
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

#[cfg(feature = "transparent-inputs")]
use crate::GapLimits;
use crate::types::AccountRef;
use crate::{Account, AccountUuid, ReceivedNoteId, SqlxClientError, UtxoId, WalletId, WalletInfo};

#[cfg(feature = "orchard")]
use orchard;

#[cfg(feature = "postgres")]
use crate::pool::Pool;

pub mod commitment_tree;
pub mod common;
pub mod notes;
pub mod scanning;

#[cfg(feature = "transparent-inputs")]
pub mod transparent;

#[cfg(any(test, feature = "test-dependencies"))]
pub mod testing;

// ============================================================================
// Put blocks result types
// ============================================================================

/// Data collected during `put_blocks` that's needed for commitment tree updates.
#[cfg(feature = "postgres")]
pub struct PutBlocksResult {
    /// The height of the first block processed.
    pub start_height: BlockHeight,
    /// The height of the last block processed (if any).
    pub last_scanned_height: Option<BlockHeight>,
    /// Sapling note commitments with their retention flags.
    pub sapling_commitments: Vec<(sapling::Node, Retention<BlockHeight>)>,
    /// Starting position for Sapling commitments.
    pub sapling_start_position: Position,
    /// Orchard note commitments with their retention flags.
    #[cfg(feature = "orchard")]
    pub orchard_commitments: Vec<(orchard::tree::MerkleHashOrchard, Retention<BlockHeight>)>,
    /// Starting position for Orchard commitments.
    #[cfg(feature = "orchard")]
    pub orchard_start_position: Position,
    /// Note positions for scan completion tracking.
    pub note_positions: Vec<(ShieldedProtocol, Position)>,
}

/// Raw note balance data from database query.
///
/// This struct provides named fields instead of positional tuple access,
/// improving code clarity and reducing the risk of field order mistakes.
#[cfg(feature = "postgres")]
struct NoteBalanceRow {
    value: i64,
    is_change: bool,
    recipient_key_scope: Option<i64>,
    mined_height: Option<i64>,
    tx_trusted: bool,
}

#[cfg(feature = "postgres")]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for NoteBalanceRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            value: row.try_get("value")?,
            is_change: row.try_get("is_change")?,
            recipient_key_scope: row.try_get("recipient_key_scope")?,
            mined_height: row.try_get("mined_height")?,
            tx_trusted: row.try_get("tx_trusted")?,
        })
    }
}

/// Raw received output data from database query.
#[cfg(feature = "postgres")]
struct ReceivedOutputRow {
    output_index: i32,
    value: i64,
    recipient_key_scope: Option<i64>,
    mined_height: Option<i64>,
    tx_trusted: bool,
}

#[cfg(feature = "postgres")]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for ReceivedOutputRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            output_index: row.try_get("output_index")?,
            value: row.try_get("value")?,
            recipient_key_scope: row.try_get("recipient_key_scope")?,
            mined_height: row.try_get("mined_height")?,
            tx_trusted: row.try_get("tx_trusted")?,
        })
    }
}

/// Raw spending transaction data from database query.
#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
struct SpendingTxRow {
    tx_id: i64,
    raw: Vec<u8>,
    mined_height: Option<i64>,
    #[allow(dead_code)] // Present in query result, may be used in future
    expiry_height: Option<i64>,
}

#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for SpendingTxRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            tx_id: row.try_get("id")?,
            raw: row.try_get("raw")?,
            mined_height: row.try_get("mined_height")?,
            expiry_height: row.try_get("expiry_height")?,
        })
    }
}

/// Raw account row from database query.
#[cfg(feature = "postgres")]
struct AccountRow {
    id: i64,
    name: Option<String>,
    uuid: Uuid,
    account_kind: i32,
    hd_seed_fingerprint: Option<Vec<u8>>,
    hd_account_index: Option<i64>,
    key_source: Option<String>,
    ufvk: Option<String>,
    uivk: Option<String>,
    has_spend_key: bool,
    birthday_height: i64,
}

#[cfg(feature = "postgres")]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for AccountRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            id: row.try_get("id")?,
            name: row.try_get("name")?,
            uuid: row.try_get("uuid")?,
            account_kind: row.try_get("account_kind")?,
            hd_seed_fingerprint: row.try_get("hd_seed_fingerprint")?,
            hd_account_index: row.try_get("hd_account_index")?,
            key_source: row.try_get("key_source")?,
            ufvk: row.try_get("ufvk")?,
            uivk: row.try_get("uivk")?,
            has_spend_key: row.try_get("has_spend_key")?,
            birthday_height: row.try_get("birthday_height")?,
        })
    }
}

// ============================================================================
// Wallet management
// ============================================================================

/// Creates a new wallet in the database.
#[cfg(feature = "postgres")]
pub async fn create_wallet<P: Parameters>(
    pool: &Pool,
    params: &P,
    name: Option<&str>,
) -> Result<WalletId, SqlxClientError> {
    let wallet_id = WalletId::new();
    let network = format!("{:?}", params.network_type());

    sqlx_core::query::query(
        "INSERT INTO wallets (id, name, network, created_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(wallet_id.expose_uuid())
    .bind(name)
    .bind(&network)
    .bind(Utc::now())
    .execute(pool)
    .await?;

    Ok(wallet_id)
}

/// Lists all wallets in the database.
#[cfg(feature = "postgres")]
pub async fn list_wallets(pool: &Pool) -> Result<Vec<WalletInfo>, SqlxClientError> {
    let rows: Vec<(Uuid, Option<String>, String, DateTime<Utc>)> = sqlx_core::query_as::query_as(
        "SELECT id, name, network, created_at FROM wallets ORDER BY created_at",
    )
    .fetch_all(pool)
    .await?;

    let result = rows
        .into_iter()
        .map(|(id, name, network, created_at)| WalletInfo {
            id: WalletId::from_uuid(id),
            name,
            network,
            created_at,
        })
        .collect();

    Ok(result)
}

/// Deletes a wallet and all associated data.
#[cfg(feature = "postgres")]
pub async fn delete_wallet(pool: &Pool, wallet_id: WalletId) -> Result<(), SqlxClientError> {
    let result = sqlx_core::query::query("DELETE FROM wallets WHERE id = $1")
        .bind(wallet_id.expose_uuid())
        .execute(pool)
        .await?;

    if result.rows_affected() == 0 {
        return Err(SqlxClientError::WalletNotFound(wallet_id));
    }

    Ok(())
}

// ============================================================================
// InputSource implementation helpers
// ============================================================================

#[cfg(feature = "postgres")]
pub async fn get_spendable_note<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    txid: &TxId,
    protocol: ShieldedProtocol,
    index: u32,
    target_height: TargetHeight,
) -> Result<Option<ReceivedNote<ReceivedNoteId, Note>>, SqlxClientError> {
    // Pass target_height directly to match SQLite's implementation
    // (spent notes exclusion uses target_height, not anchor_height)
    match protocol {
        ShieldedProtocol::Sapling => {
            let note = notes::sapling::get_spendable_sapling_note(
                pool,
                params,
                wallet_id,
                txid,
                index,
                target_height,
            )
            .await?;
            Ok(note.map(|n| n.map_note(Note::Sapling)))
        }
        #[cfg(feature = "orchard")]
        ShieldedProtocol::Orchard => {
            let note = notes::orchard::get_spendable_orchard_note(
                pool,
                params,
                wallet_id,
                txid,
                index,
                target_height,
            )
            .await?;
            Ok(note.map(|n| n.map_note(Note::Orchard)))
        }
        #[cfg(not(feature = "orchard"))]
        ShieldedProtocol::Orchard => Ok(None),
    }
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
pub async fn select_spendable_notes<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    target_value: TargetValue,
    sources: &[ShieldedProtocol],
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
    exclude: &[ReceivedNoteId],
) -> Result<ReceivedNotes<ReceivedNoteId>, SqlxClientError> {
    use zcash_client_backend::data_api::MaxSpendMode;

    // TODO: When put_blocks properly creates tree checkpoints, use get_anchor_height instead.
    // For now, use compute_anchor_height which does simple arithmetic.
    // This means we rely on the individual note selection functions to check spendability.
    let anchor_height = common::compute_anchor_height(target_height, confirmations_policy);

    // Split exclude list by protocol
    let exclude_sapling: Vec<i64> = exclude
        .iter()
        .filter(|id| id.protocol() == ShieldedProtocol::Sapling)
        .map(|id| id.1)
        .collect();

    #[cfg(feature = "orchard")]
    let exclude_orchard: Vec<i64> = exclude
        .iter()
        .filter(|id| id.protocol() == ShieldedProtocol::Orchard)
        .map(|id| id.1)
        .collect();

    // Handle AllFunds(Everything) mode: error if there are any unspent notes not yet spendable
    // This matches SQLite's NoteRequest::UnspentOrError behavior.
    if let TargetValue::AllFunds(MaxSpendMode::Everything) = target_value {
        // Get all unspent notes (without anchor height filter)
        let all_unspent_sapling = if sources.contains(&ShieldedProtocol::Sapling) {
            notes::sapling::select_unspent_sapling_notes(
                pool,
                params,
                wallet_id,
                account,
                target_height,
                anchor_height, // ignored in select_unspent
                &exclude_sapling,
            )
            .await?
        } else {
            vec![]
        };

        // Get spendable notes (with anchor height filter)
        let spendable_sapling = if sources.contains(&ShieldedProtocol::Sapling) {
            notes::sapling::select_spendable_sapling_notes(
                pool,
                params,
                wallet_id,
                account,
                u64::MAX,
                target_height,
                anchor_height,
                confirmations_policy,
                &exclude_sapling,
            )
            .await?
        } else {
            vec![]
        };

        // If there are unspent notes that aren't spendable, error
        if all_unspent_sapling.len() != spendable_sapling.len() {
            return Err(SqlxClientError::IneligibleNotes);
        }

        #[cfg(feature = "orchard")]
        {
            let all_unspent_orchard = if sources.contains(&ShieldedProtocol::Orchard) {
                notes::orchard::select_unspent_orchard_notes(
                    pool,
                    params,
                    wallet_id,
                    account,
                    target_height,
                    anchor_height,
                    &exclude_orchard,
                )
                .await?
            } else {
                vec![]
            };

            let spendable_orchard = if sources.contains(&ShieldedProtocol::Orchard) {
                notes::orchard::select_spendable_orchard_notes(
                    pool,
                    params,
                    wallet_id,
                    account,
                    u64::MAX,
                    target_height,
                    anchor_height,
                    confirmations_policy,
                    &exclude_orchard,
                )
                .await?
            } else {
                vec![]
            };

            if all_unspent_orchard.len() != spendable_orchard.len() {
                return Err(SqlxClientError::IneligibleNotes);
            }

            return Ok(ReceivedNotes::new(spendable_sapling, spendable_orchard));
        }

        #[cfg(not(feature = "orchard"))]
        return Ok(ReceivedNotes::new(spendable_sapling));
    }

    // For AtLeast and AllFunds(MaxSpendable), use normal spendable note selection
    let target_zats = match target_value {
        TargetValue::AtLeast(z) => u64::from(z),
        TargetValue::AllFunds(_) => u64::MAX, // MaxSpendable: select all spendable funds
    };

    // Select Sapling notes if requested
    // Pass both target_height (for spent notes clause) and anchor_height (for note confirmation)
    let sapling_notes = if sources.contains(&ShieldedProtocol::Sapling) {
        notes::sapling::select_spendable_sapling_notes(
            pool,
            params,
            wallet_id,
            account,
            target_zats,
            target_height,
            anchor_height,
            confirmations_policy,
            &exclude_sapling,
        )
        .await?
    } else {
        vec![]
    };

    // Select Orchard notes if requested
    #[cfg(feature = "orchard")]
    let orchard_notes = if sources.contains(&ShieldedProtocol::Orchard) {
        notes::orchard::select_spendable_orchard_notes(
            pool,
            params,
            wallet_id,
            account,
            target_zats,
            target_height,
            anchor_height,
            confirmations_policy,
            &exclude_orchard,
        )
        .await?
    } else {
        vec![]
    };

    #[cfg(feature = "orchard")]
    return Ok(ReceivedNotes::new(sapling_notes, orchard_notes));
    #[cfg(not(feature = "orchard"))]
    Ok(ReceivedNotes::new(sapling_notes))
}

#[cfg(feature = "postgres")]
pub async fn select_unspent_notes<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    sources: &[ShieldedProtocol],
    target_height: TargetHeight,
    exclude: &[ReceivedNoteId],
) -> Result<ReceivedNotes<ReceivedNoteId>, SqlxClientError> {
    use common::compute_anchor_height;
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;

    // Use default confirmations policy for computing anchor
    let anchor_height = compute_anchor_height(target_height, ConfirmationsPolicy::default());

    // Split exclude list by protocol
    let exclude_sapling: Vec<i64> = exclude
        .iter()
        .filter(|id| id.protocol() == ShieldedProtocol::Sapling)
        .map(|id| id.1)
        .collect();

    #[cfg(feature = "orchard")]
    let exclude_orchard: Vec<i64> = exclude
        .iter()
        .filter(|id| id.protocol() == ShieldedProtocol::Orchard)
        .map(|id| id.1)
        .collect();

    // Select Sapling notes if requested
    // Pass both target_height (for spent notes clause) and anchor_height (for note confirmation)
    let sapling_notes = if sources.contains(&ShieldedProtocol::Sapling) {
        notes::sapling::select_unspent_sapling_notes(
            pool,
            params,
            wallet_id,
            account,
            target_height,
            anchor_height,
            &exclude_sapling,
        )
        .await?
    } else {
        vec![]
    };

    // Select Orchard notes if requested
    #[cfg(feature = "orchard")]
    let orchard_notes = if sources.contains(&ShieldedProtocol::Orchard) {
        notes::orchard::select_unspent_orchard_notes(
            pool,
            params,
            wallet_id,
            account,
            target_height,
            anchor_height,
            &exclude_orchard,
        )
        .await?
    } else {
        vec![]
    };

    #[cfg(feature = "orchard")]
    return Ok(ReceivedNotes::new(sapling_notes, orchard_notes));
    #[cfg(not(feature = "orchard"))]
    Ok(ReceivedNotes::new(sapling_notes))
}

#[cfg(feature = "postgres")]
pub async fn get_account_metadata<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    selector: &NoteFilter,
    target_height: TargetHeight,
    exclude: &[ReceivedNoteId],
) -> Result<AccountMeta, SqlxClientError> {
    // Convert TargetHeight to BlockHeight for use in queries
    let target_height_block: BlockHeight = target_height.into();

    // Determine the minimum note value based on the NoteFilter
    let min_value =
        match compute_min_value_for_filter(pool, wallet_id, account, selector, target_height_block)
            .await?
        {
            Some(v) => u64::from(v) as i64,
            None => {
                // Cannot evaluate filter, return empty metadata
                return Ok(AccountMeta::new(None, None));
            }
        };

    // Split exclude list by protocol
    let exclude_sapling: Vec<i64> = exclude
        .iter()
        .filter(|id| id.protocol() == ShieldedProtocol::Sapling)
        .map(|id| id.1)
        .collect();

    #[cfg(feature = "orchard")]
    let exclude_orchard: Vec<i64> = exclude
        .iter()
        .filter(|id| id.protocol() == ShieldedProtocol::Orchard)
        .map(|id| id.1)
        .collect();

    common::get_account_metadata_impl(
        pool,
        wallet_id,
        account,
        min_value,
        target_height_block,
        &exclude_sapling,
        #[cfg(feature = "orchard")]
        &exclude_orchard,
    )
    .await
}

/// Computes the minimum note value based on the NoteFilter.
/// Returns None if the filter cannot be evaluated (e.g., no prior sends for percentile filter).
#[cfg(feature = "postgres")]
async fn compute_min_value_for_filter(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
    filter: &NoteFilter,
    target_height: BlockHeight,
) -> Result<Option<zcash_protocol::value::Zatoshis>, SqlxClientError> {
    use zcash_protocol::value::Zatoshis;

    match filter {
        NoteFilter::ExceedsMinValue(v) => Ok(Some(*v)),
        NoteFilter::ExceedsPriorSendPercentile(percentile) => {
            // Query the percentile of previously sent note values using NTILE bucketing
            // to match SQLite's approach.
            let n = percentile.value();

            // First, get the bucket maxima using NTILE(10)
            let query = r#"
                WITH bucketed AS (
                    SELECT s.value, NTILE(10) OVER (ORDER BY s.value) AS bucket_index
                    FROM sent_notes s
                    INNER JOIN accounts a ON a.id = s.from_account_id
                    INNER JOIN transactions t ON t.id = s.tx_id
                    WHERE s.wallet_id = $1
                      AND a.uuid = $2
                      AND t.mined_height IS NOT NULL
                      AND (s.to_account_id IS NULL OR s.from_account_id != s.to_account_id)
                )
                SELECT MAX(value)::BIGINT as value
                FROM bucketed
                GROUP BY bucket_index
                ORDER BY bucket_index
            "#;

            let rows: Vec<(i64,)> = sqlx_core::query_as::query_as(query)
                .bind(wallet_id.expose_uuid())
                .bind(account.expose_uuid())
                .fetch_all(pool)
                .await?;

            if rows.is_empty() {
                return Ok(None); // No prior sends
            }

            // Pick a bucket index by scaling the requested percentile to the number of buckets
            // i = (bucket_count * percentile / 100) - 1, clamped to valid range
            let bucket_count = rows.len();
            let i = (bucket_count * usize::from(n) / 100).saturating_sub(1);
            let threshold = rows.get(i).map(|(v,)| *v).unwrap_or(0);

            Ok(Some(
                Zatoshis::from_nonnegative_i64(threshold)
                    .map_err(|_| SqlxClientError::CorruptedOutput)?,
            ))
        }
        NoteFilter::ExceedsBalancePercentage(percentage) => {
            // Compute total balance and return the percentage threshold
            let n = percentage.value();
            let target_height_i64 = common::height_to_i64(target_height);

            // Query total balance across shielded pools
            // Matches SQLite's logic: exclude notes where the spending tx is "unexpired"
            // (i.e., might still get mined)
            let query = r#"
                SELECT COALESCE(SUM(rn.value), 0)::BIGINT
                FROM sapling_received_notes rn
                INNER JOIN accounts a ON a.id = rn.account_id
                INNER JOIN transactions t ON t.id = rn.tx_id
                WHERE rn.wallet_id = $1
                  AND a.uuid = $2
                  AND a.deleted_at IS NULL
                  AND a.ufvk IS NOT NULL
                  AND t.mined_height IS NOT NULL
                  AND rn.id NOT IN (
                      SELECT rns.sapling_received_note_id
                      FROM sapling_received_note_spends rns
                      INNER JOIN transactions stx ON stx.id = rns.transaction_id
                      WHERE stx.mined_height < $3
                         OR stx.expiry_height = 0
                         OR stx.expiry_height >= $3
                         OR (stx.expiry_height IS NULL
                             AND stx.min_observed_height + 40 >= $3)
                  )
            "#;

            let sapling_balance: (i64,) = sqlx_core::query_as::query_as(query)
                .bind(wallet_id.expose_uuid())
                .bind(account.expose_uuid())
                .bind(target_height_i64)
                .fetch_one(pool)
                .await?;

            #[cfg(feature = "orchard")]
            let orchard_balance = {
                let orchard_query = r#"
                    SELECT COALESCE(SUM(rn.value), 0)::BIGINT
                    FROM orchard_received_notes rn
                    INNER JOIN accounts a ON a.id = rn.account_id
                    INNER JOIN transactions t ON t.id = rn.tx_id
                    WHERE rn.wallet_id = $1
                      AND a.uuid = $2
                      AND a.deleted_at IS NULL
                      AND a.ufvk IS NOT NULL
                      AND t.mined_height IS NOT NULL
                      AND rn.id NOT IN (
                          SELECT rns.orchard_received_note_id
                          FROM orchard_received_note_spends rns
                          INNER JOIN transactions stx ON stx.id = rns.transaction_id
                          WHERE stx.mined_height < $3
                             OR stx.expiry_height = 0
                             OR stx.expiry_height >= $3
                             OR (stx.expiry_height IS NULL
                                 AND stx.min_observed_height + 40 >= $3)
                      )
                "#;
                let result: (i64,) = sqlx_core::query_as::query_as(orchard_query)
                    .bind(wallet_id.expose_uuid())
                    .bind(account.expose_uuid())
                    .bind(target_height_i64)
                    .fetch_one(pool)
                    .await?;
                result.0
            };

            #[cfg(not(feature = "orchard"))]
            let orchard_balance: i64 = 0;

            let total_balance = sapling_balance.0 + orchard_balance;
            if total_balance == 0 {
                return Ok(None);
            }

            let threshold = (total_balance as f64 * n as f64 / 100.0) as i64;
            Ok(Some(
                Zatoshis::from_nonnegative_i64(threshold)
                    .map_err(|_| SqlxClientError::CorruptedOutput)?,
            ))
        }
        NoteFilter::Combine(left, right) => {
            // Both conditions must be evaluable; take the max of the two
            let left_val = Box::pin(compute_min_value_for_filter(
                pool,
                wallet_id,
                account,
                left,
                target_height,
            ))
            .await?;
            let right_val = Box::pin(compute_min_value_for_filter(
                pool,
                wallet_id,
                account,
                right,
                target_height,
            ))
            .await?;

            match (left_val, right_val) {
                (Some(l), Some(r)) => Ok(Some(std::cmp::max(l, r))),
                (Some(v), None) | (None, Some(v)) => Ok(Some(v)),
                (None, None) => Ok(None),
            }
        }
        NoteFilter::Attempt {
            condition,
            fallback,
        } => {
            // Try the condition first, fall back if it cannot be evaluated
            match Box::pin(compute_min_value_for_filter(
                pool,
                wallet_id,
                account,
                condition,
                target_height,
            ))
            .await?
            {
                Some(v) => Ok(Some(v)),
                None => {
                    Box::pin(compute_min_value_for_filter(
                        pool,
                        wallet_id,
                        account,
                        fallback,
                        target_height,
                    ))
                    .await
                }
            }
        }
    }
}

// ============================================================================
// WalletRead implementation helpers
// ============================================================================

#[cfg(feature = "postgres")]
pub async fn get_account_ids(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Vec<AccountUuid>, SqlxClientError> {
    let rows: Vec<(Uuid,)> = sqlx_core::query_as::query_as(
        "SELECT uuid FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL ORDER BY id",
    )
    .bind(wallet_id.expose_uuid())
    .fetch_all(pool)
    .await?;

    let result = rows
        .into_iter()
        .map(|(uuid,)| AccountUuid::from_uuid(uuid))
        .collect();

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn get_account<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: AccountUuid,
) -> Result<Option<Account>, SqlxClientError> {
    let query = r#"
        SELECT id, name, uuid, account_kind,
               hd_seed_fingerprint, hd_account_index, key_source,
               ufvk, uivk, has_spend_key, birthday_height
        FROM accounts
        WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL
    "#;

    let row: Option<AccountRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account_id.expose_uuid())
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => parse_account_row(params, row),
        None => Ok(None),
    }
}

/// Parses an account row from the database into an Account struct.
#[cfg(feature = "postgres")]
fn parse_account_row<P: Parameters>(
    params: &P,
    row: AccountRow,
) -> Result<Option<Account>, SqlxClientError> {
    use crate::{ViewingKey, types::AccountRef};
    use zcash_client_backend::data_api::{AccountPurpose, AccountSource, Zip32Derivation};
    use zcash_keys::keys::{UnifiedFullViewingKey, UnifiedIncomingViewingKey};
    use zip32::fingerprint::SeedFingerprint;

    let account_uuid = AccountUuid::from_uuid(row.uuid);
    let account_ref = AccountRef(row.id);

    // Parse derivation info if available
    let derivation = match (row.hd_seed_fingerprint, row.hd_account_index) {
        (Some(fp), Some(idx)) => {
            let fp_array: [u8; 32] = fp.try_into().map_err(|_| {
                SqlxClientError::Encoding("Invalid seed fingerprint length".to_string())
            })?;
            let account_id = zip32::AccountId::try_from(idx as u32)
                .map_err(|_| SqlxClientError::Encoding("Invalid account index".to_string()))?;
            Some(Zip32Derivation::new(
                SeedFingerprint::from_bytes(fp_array),
                account_id,
            ))
        }
        _ => None,
    };

    // Parse account source (kind)
    let kind = match (row.account_kind, derivation) {
        (0, Some(derivation)) => AccountSource::Derived {
            derivation,
            key_source: row.key_source,
        },
        (1, derivation) => AccountSource::Imported {
            purpose: if row.has_spend_key {
                AccountPurpose::Spending { derivation }
            } else {
                AccountPurpose::ViewOnly
            },
            key_source: row.key_source,
        },
        (0, None) => {
            return Err(SqlxClientError::Encoding(
                "Derived account missing derivation info".to_string(),
            ));
        }
        _ => {
            return Err(SqlxClientError::Encoding(format!(
                "Unrecognized account_kind: {}",
                row.account_kind
            )));
        }
    };

    // Parse viewing key
    let viewing_key = if let Some(ufvk_str) = row.ufvk {
        ViewingKey::Full(Box::new(
            UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                SqlxClientError::Encoding(format!(
                    "Could not decode UFVK for account {}: {}",
                    account_uuid, e
                ))
            })?,
        ))
    } else if let Some(uivk_str) = row.uivk {
        ViewingKey::Incoming(Box::new(
            UnifiedIncomingViewingKey::decode(params, &uivk_str).map_err(|e| {
                SqlxClientError::Encoding(format!(
                    "Could not decode UIVK for account {}: {}",
                    account_uuid, e
                ))
            })?,
        ))
    } else {
        return Err(SqlxClientError::Encoding(format!(
            "Account {} has no viewing key",
            account_uuid
        )));
    };

    let birthday = BlockHeight::from_u32(row.birthday_height as u32);

    Ok(Some(Account {
        id: account_ref,
        uuid: account_uuid,
        name: row.name,
        kind,
        viewing_key,
        birthday,
    }))
}

/// Gets the internal account reference (database ID) for an account UUID.
#[cfg(feature = "postgres")]
pub(crate) async fn get_account_ref(
    pool: &Pool,
    wallet_id: WalletId,
    account_id: AccountUuid,
) -> Result<AccountRef, SqlxClientError> {
    let row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account_id.expose_uuid())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((id,)) => Ok(AccountRef(id)),
        None => Err(SqlxClientError::AccountNotFound(account_id)),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_derived_account<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    derivation: &Zip32Derivation,
) -> Result<Option<Account>, SqlxClientError> {
    let query = r#"
        SELECT id, name, uuid, account_kind,
               hd_seed_fingerprint, hd_account_index, key_source,
               ufvk, uivk, has_spend_key, birthday_height
        FROM accounts
        WHERE wallet_id = $1
          AND hd_seed_fingerprint = $2
          AND hd_account_index = $3
          AND deleted_at IS NULL
    "#;

    let row: Option<AccountRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(derivation.seed_fingerprint().to_bytes().to_vec())
        .bind(u32::from(derivation.account_index()) as i64)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => parse_account_row(params, row),
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn validate_seed<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: AccountUuid,
    seed: &SecretVec<u8>,
) -> Result<bool, SqlxClientError> {
    use secrecy::ExposeSecret;
    use zcash_client_backend::data_api::Account as AccountTrait;
    use zip32::fingerprint::SeedFingerprint;

    // Get the account
    let account = match get_account(pool, params, wallet_id, account_id).await? {
        Some(a) => a,
        None => return Ok(false),
    };

    // Check if this is a derived account
    let derivation = match account.source().key_derivation() {
        Some(d) => d,
        None => return Ok(false), // Imported accounts can't be validated against a seed
    };

    // Compute the seed fingerprint
    let seed_fingerprint = match SeedFingerprint::from_seed(seed.expose_secret()) {
        Some(fp) => fp,
        None => return Ok(false),
    };

    // Check if the fingerprints match
    if seed_fingerprint != *derivation.seed_fingerprint() {
        return Ok(false);
    }

    // Derive the UFVK from the seed and compare
    let usk = match UnifiedSpendingKey::from_seed(
        params,
        seed.expose_secret(),
        derivation.account_index(),
    ) {
        Ok(k) => k,
        Err(_) => return Ok(false),
    };

    // Compare the UFVKs
    match account.ufvk() {
        Some(account_ufvk) => {
            let derived_ufvk = usk.to_unified_full_viewing_key();
            Ok(derived_ufvk.encode(params) == account_ufvk.encode(params))
        }
        None => Ok(false),
    }
}

#[cfg(feature = "postgres")]
pub async fn seed_relevance_to_derived_accounts<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    seed: &SecretVec<u8>,
) -> Result<SeedRelevance<AccountUuid>, SqlxClientError> {
    use secrecy::ExposeSecret;
    use zip32::fingerprint::SeedFingerprint;

    // Compute the seed fingerprint
    let seed_fingerprint = match SeedFingerprint::from_seed(seed.expose_secret()) {
        Some(fp) => fp,
        None => return Err(SqlxClientError::Encoding("Invalid seed".to_string())),
    };

    // Query for accounts derived from this seed
    let query = r#"
        SELECT uuid, hd_account_index, ufvk
        FROM accounts
        WHERE wallet_id = $1
          AND hd_seed_fingerprint = $2
          AND account_kind = 0
          AND deleted_at IS NULL
        ORDER BY hd_account_index
    "#;

    let rows: Vec<(Uuid, i64, Option<String>)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(seed_fingerprint.to_bytes().to_vec())
        .fetch_all(pool)
        .await?;

    if rows.is_empty() {
        // Check if there are any accounts at all
        let count: (i64,) = sqlx_core::query_as::query_as(
            "SELECT COUNT(*) FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL",
        )
        .bind(wallet_id.expose_uuid())
        .fetch_one(pool)
        .await?;

        if count.0 == 0 {
            return Ok(SeedRelevance::NoAccounts);
        } else {
            // There are accounts but none match this seed
            return Ok(SeedRelevance::NotRelevant);
        }
    }

    // Verify each account's UFVK matches what we'd derive from this seed
    let mut relevant_accounts = Vec::new();
    for (uuid, account_index, ufvk_str) in rows {
        let account_id = zip32::AccountId::try_from(account_index as u32)
            .map_err(|_| SqlxClientError::Encoding("Invalid account index".to_string()))?;

        // Derive the expected UFVK
        let usk = UnifiedSpendingKey::from_seed(params, seed.expose_secret(), account_id)
            .map_err(SqlxClientError::KeyDerivationError)?;
        let derived_ufvk = usk.to_unified_full_viewing_key();

        // Compare with stored UFVK
        if let Some(stored_ufvk) = ufvk_str {
            if derived_ufvk.encode(params) == stored_ufvk {
                relevant_accounts.push(AccountUuid::from_uuid(uuid));
            } else {
                // UFVK mismatch - seed doesn't match
                return Ok(SeedRelevance::NotRelevant);
            }
        }
    }

    match nonempty::NonEmpty::from_vec(relevant_accounts) {
        Some(account_ids) => Ok(SeedRelevance::Relevant { account_ids }),
        None => Ok(SeedRelevance::NotRelevant),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_account_for_ufvk<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    ufvk: &UnifiedFullViewingKey,
) -> Result<Option<Account>, SqlxClientError> {
    // Compare the encoded UFVK string
    let ufvk_encoded = ufvk.encode(params);

    let query = r#"
        SELECT id, name, uuid, account_kind,
               hd_seed_fingerprint, hd_account_index, key_source,
               ufvk, uivk, has_spend_key, birthday_height
        FROM accounts
        WHERE wallet_id = $1 AND ufvk = $2 AND deleted_at IS NULL
    "#;

    let row: Option<AccountRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(&ufvk_encoded)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => parse_account_row(params, row),
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn list_addresses<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
) -> Result<Vec<AddressInfo>, SqlxClientError> {
    use zcash_client_backend::data_api::AddressSource;
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_keys::address::{Address, UnifiedAddress};

    let query = r#"
        SELECT diversifier_index_be, address, used_in_tx, cached_transparent_receiver_address
        FROM addresses
        WHERE wallet_id = $1
          AND account_id IN (
              SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL
          )
        ORDER BY diversifier_index_be
    "#;

    type AddressRow = (Vec<u8>, String, Option<i64>, Option<String>);

    let rows: Vec<AddressRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (diversifier_index_be, address_str, _used_in_tx, _transparent) in rows {
        // Parse diversifier index from big-endian bytes
        let di_bytes: [u8; 11] = diversifier_index_be
            .try_into()
            .map_err(|_| SqlxClientError::Encoding("Invalid diversifier index".to_string()))?;
        let diversifier_index = DiversifierIndex::from(di_bytes);

        // Parse the unified address
        let ua = UnifiedAddress::decode(params, &address_str)
            .map_err(|e| SqlxClientError::Encoding(format!("Could not decode address: {}", e)))?;

        let address = Address::Unified(ua);
        let source = AddressSource::Derived {
            diversifier_index,
            #[cfg(feature = "transparent-inputs")]
            transparent_key_scope: None,
        };

        if let Some(info) = AddressInfo::from_parts(address, source) {
            result.push(info);
        }
    }

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn get_last_generated_address_matching<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    address_filter: UnifiedAddressRequest,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqlxClientError> {
    use zcash_client_backend::data_api::Account as AccountTrait;
    use zcash_client_backend::encoding::AddressCodec;

    // Get the account first to access its UIVK
    let account_data = match get_account(pool, params, wallet_id, account).await? {
        Some(a) => a,
        None => return Err(SqlxClientError::AccountUnknown),
    };

    // Compute receiver requirements for filtering
    let requirements = account_data
        .uivk()
        .receiver_requirements(address_filter)
        .map_err(|_| {
            SqlxClientError::Encoding(
                "Could not generate UnifiedAddressRequest for UIVK".to_string(),
            )
        })?;
    let require_flags = common::ReceiverFlags::required(requirements).bits();
    let omit_flags = common::ReceiverFlags::omitted(requirements).bits();

    // This returns the most recently exposed external-scope address (the address that was exposed
    // at the greatest block height, using the largest diversifier index to break ties)
    // that conforms to the specified requirements.
    let query = r#"
        SELECT address, diversifier_index_be
        FROM addresses
        WHERE wallet_id = $1
          AND account_id IN (
              SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL
          )
          AND key_scope = $3
          AND (receiver_flags & $4) = $4
          AND (receiver_flags & $5) = 0
          AND exposed_at_height IS NOT NULL
        ORDER BY exposed_at_height DESC, diversifier_index_be DESC
        LIMIT 1
    "#;

    let row: Option<(String, Option<Vec<u8>>)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(0i32) // key_scope = External
        .bind(require_flags)
        .bind(omit_flags)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((address_str, di_vec)) => {
            let diversifier_index = di_vec
                .and_then(|v| {
                    let bytes: [u8; 11] = v.try_into().ok()?;
                    Some(DiversifierIndex::from(bytes))
                })
                .ok_or(SqlxClientError::CorruptedDiversifierIndex)?;

            let ua = UnifiedAddress::decode(params, &address_str).map_err(|e| {
                SqlxClientError::Encoding(format!("Could not decode address: {}", e))
            })?;

            Ok(Some((ua, diversifier_index)))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_account_birthday(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
) -> Result<BlockHeight, SqlxClientError> {
    let row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT birthday_height FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL"
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((height,)) => Ok(BlockHeight::from_u32(height as u32)),
        None => Err(SqlxClientError::AccountNotFound(account)),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_wallet_birthday(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(
        "SELECT MIN(birthday_height) FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(h,)| h.map(|h| BlockHeight::from_u32(h as u32))))
}

#[cfg(feature = "postgres")]
pub async fn get_wallet_summary<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<Option<WalletSummary<AccountUuid>>, SqlxClientError> {
    use common::i64_to_height;
    use zcash_client_backend::data_api::{AccountBalance, Progress, Ratio};
    use zcash_protocol::ShieldedProtocol;

    // Get chain tip height
    let chain_tip_row: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    let chain_tip_height = match chain_tip_row {
        Some((Some(h),)) => i64_to_height(h)?,
        _ => return Ok(None), // No blocks scanned yet
    };

    // Get wallet birthday (minimum birthday of all accounts)
    let birthday_row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(
        "SELECT MIN(birthday_height) FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let birthday_height = match birthday_row {
        Some((Some(h),)) => i64_to_height(h)?,
        _ => return Ok(None), // No accounts
    };

    // Get fully scanned height (minimum height where we've scanned all blocks)
    // For simplicity, use chain tip as fully scanned if scan queue is empty or complete
    let fully_scanned_height = chain_tip_height;

    // Get target height for calculating anchor
    let target_height = TargetHeight::from(chain_tip_height + 1);

    // Get all accounts
    let account_rows: Vec<(Uuid,)> = sqlx_core::query_as::query_as(
        "SELECT uuid FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .fetch_all(pool)
    .await?;

    let mut account_balances = HashMap::new();

    for (account_uuid,) in account_rows {
        let account_id = AccountUuid::from_uuid(account_uuid);

        // Calculate Sapling balance
        let sapling_balance = get_pool_balance(
            pool,
            wallet_id,
            account_id,
            "sapling_received_notes",
            "sapling_received_note_spends",
            "sapling_received_note_id",
            ShieldedProtocol::Sapling,
            target_height,
            confirmations_policy,
        )
        .await?;

        // Calculate Orchard balance
        #[cfg(feature = "orchard")]
        let orchard_balance = get_pool_balance(
            pool,
            wallet_id,
            account_id,
            "orchard_received_notes",
            "orchard_received_note_spends",
            "orchard_received_note_id",
            ShieldedProtocol::Orchard,
            target_height,
            confirmations_policy,
        )
        .await?;

        #[cfg(not(feature = "orchard"))]
        let orchard_balance = zcash_client_backend::data_api::Balance::ZERO;

        let mut balance = AccountBalance::ZERO;
        balance.with_sapling_balance_mut::<_, SqlxClientError>(|bal| {
            *bal = sapling_balance;
            Ok(())
        })?;
        balance.with_orchard_balance_mut::<_, SqlxClientError>(|bal| {
            *bal = orchard_balance;
            Ok(())
        })?;

        account_balances.insert(account_id, balance);
    }

    // Add transparent balances
    #[cfg(feature = "transparent-inputs")]
    transparent::add_transparent_account_balances(
        pool,
        wallet_id,
        target_height,
        confirmations_policy,
        &mut account_balances,
    )
    .await?;

    // Calculate progress - for simplicity, report 100% if we have blocks scanned
    let birthday_u32 = u32::from(birthday_height);
    let blocks_scanned = u64::from(chain_tip_height.saturating_sub(birthday_u32)) + 1;
    let total_blocks = blocks_scanned; // Simplified: assume we've scanned all we need

    // Check if any accounts have a recover-until height
    let has_recovery: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT COUNT(*) FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL AND recover_until_height IS NOT NULL"
    )
    .bind(wallet_id.expose_uuid())
    .fetch_optional(pool)
    .await?;

    // If no accounts have recover_until_height, recovery ratio is 0/0
    // (indicating no recovery phase needed)
    let recovery_progress = if has_recovery.map(|r| r.0).unwrap_or(0) == 0 {
        Some(Ratio::new(0, 0))
    } else {
        // TODO: Calculate actual recovery progress if needed
        Some(Ratio::new(0, 0))
    };

    let progress = Progress::new(
        Ratio::new(blocks_scanned, total_blocks.max(1)),
        recovery_progress,
    );

    // Get next subtree indices from commitment tree shards (global tables)
    let next_sapling_subtree_index = get_next_subtree_index(pool, "sapling").await?;

    #[cfg(feature = "orchard")]
    let next_orchard_subtree_index = get_next_subtree_index(pool, "orchard").await?;

    let summary = WalletSummary::new(
        account_balances,
        chain_tip_height,
        fully_scanned_height,
        progress,
        next_sapling_subtree_index,
        #[cfg(feature = "orchard")]
        next_orchard_subtree_index,
    );

    Ok(Some(summary))
}

/// Helper to calculate pool balance for an account.
/// Matches SQLite's `with_pool_balances` by using `confirmations_until_spendable()` per-note.
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn get_pool_balance(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
    notes_table: &str,
    spends_table: &str,
    spend_note_id_col: &str,
    protocol: zcash_protocol::ShieldedProtocol,
    target_height: zcash_client_backend::data_api::wallet::TargetHeight,
    confirmations_policy: zcash_client_backend::data_api::wallet::ConfirmationsPolicy,
) -> Result<zcash_client_backend::data_api::Balance, SqlxClientError> {
    use crate::wallet::common::MARGINAL_FEE;
    use crate::wallet::common::i64_to_optional_height;
    use zcash_client_backend::data_api::Balance;
    use zcash_protocol::{PoolType, value::Zatoshis};

    let target_height_i64 = common::height_to_i64(target_height.into());
    let trusted_height = target_height.saturating_sub(u32::from(confirmations_policy.trusted()));
    let _trusted_height_i64 = common::height_to_i64(trusted_height);

    // Query for all unspent notes with their details
    // Matches SQLite's with_pool_balances query structure
    let notes_query = format!(
        r#"
        SELECT
            rn.value,
            rn.is_change,
            rn.recipient_key_scope,
            t.mined_height,
            COALESCE(t.trust_status, 0) > 0 AS tx_trusted
        FROM {} rn
        INNER JOIN accounts a ON a.id = rn.account_id
        INNER JOIN transactions t ON t.id = rn.tx_id
        WHERE rn.wallet_id = $1
          AND a.uuid = $2
          AND a.deleted_at IS NULL
          AND a.ufvk IS NOT NULL
          -- Transaction is unexpired (matches SQLite's tx_unexpired_condition)
          AND (
              t.mined_height < $3  -- the transaction is mined below target height
              OR t.expiry_height = 0  -- the tx will not expire
              OR t.expiry_height >= $3  -- the tx is unexpired
              OR (t.expiry_height IS NULL AND t.min_observed_height + 40 >= $3)  -- unknown expiry but recently observed
          )
          -- Note is unspent (matches SQLite's spent_notes_clause)
          AND rn.id NOT IN (
              SELECT rns.{}
              FROM {} rns
              INNER JOIN transactions stx ON stx.id = rns.transaction_id
              WHERE rns.wallet_id = $1
                AND (stx.mined_height < $3
                   OR stx.expiry_height = 0
                   OR stx.expiry_height >= $3
                   OR (stx.expiry_height IS NULL AND stx.min_observed_height + 40 >= $3))
          )
        "#,
        notes_table, spend_note_id_col, spends_table
    );

    let note_rows: Vec<NoteBalanceRow> = sqlx_core::query_as::query_as(&notes_query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(target_height_i64)
        .fetch_all(pool)
        .await?;

    let marginal_fee = Zatoshis::from_u64(MARGINAL_FEE as u64).unwrap();
    let mut balance = Balance::ZERO;

    for row in note_rows {
        let value = Zatoshis::from_nonnegative_i64(row.value)
            .map_err(|_| SqlxClientError::CorruptedOutput)?;

        let received_height = i64_to_optional_height(row.mined_height)?;

        // Decode key scope - use the notes table value directly for balance calculation
        // (unlike get_received_outputs which uses addresses table via v_tx_outputs)
        let key_scope = row.recipient_key_scope.and_then(|s| match s {
            0 => Some(zip32::Scope::External),
            1 => Some(zip32::Scope::Internal),
            _ => None,
        });

        // A note is spendable if confirmations_until_spendable returns 0
        // Note: We simplify by not tracking shielding input heights for now
        let is_spendable = confirmations_policy.confirmations_until_spendable(
            target_height,
            PoolType::Shielded(protocol),
            key_scope,
            received_height,
            row.tx_trusted,
            None,  // max_shielding_input_height
            false, // tx_shielding_inputs_trusted
        ) == 0;

        // Change is pending confirmation if mined after trusted_height
        let is_pending_change = row.is_change && received_height.is_none_or(|h| h > trusted_height);

        // Categorize the value (matches SQLite's logic)
        if value <= marginal_fee {
            balance.add_uneconomic_value(value)?;
        } else if is_spendable {
            balance.add_spendable_value(value)?;
        } else if is_pending_change {
            balance.add_pending_change_value(value)?;
        } else {
            balance.add_pending_spendable_value(value)?;
        }
    }

    Ok(balance)
}

/// Helper to get next subtree index for a protocol's commitment tree.
#[cfg(feature = "postgres")]
async fn get_next_subtree_index(pool: &Pool, table_prefix: &str) -> Result<u64, SqlxClientError> {
    // Global table - commitment tree shards are shared across all wallets
    let query = format!(
        "SELECT COALESCE(MAX(shard_index), -1) FROM {}_tree_shards",
        table_prefix
    );

    let row: (i64,) = sqlx_core::query_as::query_as(&query)
        .fetch_one(pool)
        .await?;

    // Return the second-to-last shard index (the last complete one)
    // or 0 if no shards exist
    Ok(if row.0 > 0 { (row.0 - 1) as u64 } else { 0 })
}

#[cfg(feature = "postgres")]
pub async fn chain_height(
    pool: &Pool,
    _wallet_id: WalletId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let row: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    Ok(row.and_then(|(h,)| h.map(|h| BlockHeight::from_u32(h as u32))))
}

#[cfg(feature = "postgres")]
pub async fn get_block_hash(
    pool: &Pool,
    _wallet_id: WalletId,
    block_height: BlockHeight,
) -> Result<Option<BlockHash>, SqlxClientError> {
    // blocks table is global - all wallets share the same blockchain data
    let row: Option<(Vec<u8>,)> =
        sqlx_core::query_as::query_as("SELECT hash FROM blocks WHERE height = $1")
            .bind(u32::from(block_height) as i64)
            .fetch_optional(pool)
            .await?;

    match row {
        Some((hash,)) => {
            let hash_array: [u8; 32] = hash
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid block hash length".to_string()))?;
            Ok(Some(BlockHash(hash_array)))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn block_metadata(
    pool: &Pool,
    _wallet_id: WalletId,
    height: BlockHeight,
) -> Result<Option<BlockMetadata>, SqlxClientError> {
    // blocks table is global - all wallets share the same blockchain data
    #[cfg(feature = "orchard")]
    let query = r#"
        SELECT hash, sapling_commitment_tree_size, orchard_commitment_tree_size
        FROM blocks
        WHERE height = $1
    "#;

    #[cfg(not(feature = "orchard"))]
    let query = r#"
        SELECT hash, sapling_commitment_tree_size
        FROM blocks
        WHERE height = $1
    "#;

    #[cfg(feature = "orchard")]
    type RowType = (Vec<u8>, Option<i64>, Option<i64>);

    #[cfg(not(feature = "orchard"))]
    type RowType = (Vec<u8>, Option<i64>);

    let row: Option<RowType> = sqlx_core::query_as::query_as(query)
        .bind(u32::from(height) as i64)
        .fetch_optional(pool)
        .await?;

    match row {
        #[cfg(feature = "orchard")]
        Some((hash, sapling_size, orchard_size)) => {
            let hash_array: [u8; 32] = hash
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid block hash length".to_string()))?;
            Ok(Some(BlockMetadata::from_parts(
                height,
                BlockHash(hash_array),
                sapling_size.map(|s| s as u32),
                orchard_size.map(|s| s as u32),
            )))
        }
        #[cfg(not(feature = "orchard"))]
        Some((hash, sapling_size)) => {
            let hash_array: [u8; 32] = hash
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid block hash length".to_string()))?;
            Ok(Some(BlockMetadata::from_parts(
                height,
                BlockHash(hash_array),
                sapling_size.map(|s| s as u32),
            )))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn block_fully_scanned(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Option<BlockMetadata>, SqlxClientError> {
    // Find the maximum height where scanning is complete
    // This queries for the highest block where there are no gaps in the scan queue
    // For now, return the max scanned block if the scan queue has no pending ranges

    let has_pending: (i64,) = sqlx_core::query_as::query_as(
        "SELECT COUNT(*) FROM scan_queue WHERE wallet_id = $1 AND priority > 0",
    )
    .bind(wallet_id.expose_uuid())
    .fetch_one(pool)
    .await?;

    if has_pending.0 > 0 {
        // There are still ranges to scan, so nothing is fully scanned yet
        // In practice, we should return the highest contiguous scanned block
        // For now, return None to indicate scanning is not complete
        return Ok(None);
    }

    // If no pending scan ranges, return the max scanned block
    block_max_scanned(pool, wallet_id).await
}

#[cfg(feature = "postgres")]
pub async fn get_max_height_hash(
    pool: &Pool,
    _wallet_id: WalletId,
) -> Result<Option<(BlockHeight, BlockHash)>, SqlxClientError> {
    // blocks table is global - all wallets share the same blockchain data
    let row: Option<(i64, Vec<u8>)> = sqlx_core::query_as::query_as(
        "SELECT height, hash FROM blocks ORDER BY height DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;

    match row {
        Some((height, hash)) => {
            let hash_array: [u8; 32] = hash
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid block hash length".to_string()))?;
            Ok(Some((
                BlockHeight::from_u32(height as u32),
                BlockHash(hash_array),
            )))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn block_max_scanned(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Option<BlockMetadata>, SqlxClientError> {
    // Get the maximum height in the blocks table
    let row: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    match row {
        Some((Some(height),)) => {
            let height = BlockHeight::from_u32(height as u32);
            block_metadata(pool, wallet_id, height).await
        }
        _ => Ok(None),
    }
}

/// Retrieves scan ranges from the scan queue ordered by priority.
///
/// Returns all scan ranges with priority >= ScanPriority::Historic (includes Scanned).
/// Ranges are returned ordered by priority DESC, then block_range_end DESC.
#[cfg(feature = "postgres")]
pub async fn suggest_scan_ranges(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Vec<ScanRange>, SqlxClientError> {
    use zcash_client_backend::data_api::scanning::ScanPriority;

    // Use the scanning module with correct priority codes
    // Default to Historic to include most scan ranges (matches typical usage)
    scanning::suggest_scan_ranges(pool, wallet_id, ScanPriority::Historic).await
}

#[cfg(feature = "postgres")]
pub async fn get_target_and_anchor_heights(
    pool: &Pool,
    wallet_id: WalletId,
    min_confirmations: NonZeroU32,
) -> Result<Option<(TargetHeight, BlockHeight)>, SqlxClientError> {
    use zcash_protocol::ShieldedProtocol;

    // Get the chain tip height
    let chain_tip = match chain_height(pool, wallet_id).await? {
        Some(h) => h,
        None => return Ok(None), // No blocks scanned yet
    };

    // Target height is chain_tip + 1 (the mempool height, the block we're building for)
    let target_height = TargetHeight::from(chain_tip + 1);

    // Get the anchor height by finding the max checkpoint that satisfies confirmations.
    // This matches SQLite's approach which queries the checkpoint table.
    let sapling_anchor = common::get_max_checkpointed_height(
        pool,
        wallet_id,
        ShieldedProtocol::Sapling,
        target_height,
        min_confirmations,
    )
    .await?;

    #[cfg(feature = "orchard")]
    let orchard_anchor = common::get_max_checkpointed_height(
        pool,
        wallet_id,
        ShieldedProtocol::Orchard,
        target_height,
        min_confirmations,
    )
    .await?;

    #[cfg(not(feature = "orchard"))]
    let orchard_anchor: Option<BlockHeight> = None;

    // Return the minimum of the two anchors, or whichever one exists
    let anchor_height = sapling_anchor
        .zip(orchard_anchor)
        .map(|(s, o)| std::cmp::min(s, o))
        .or(sapling_anchor)
        .or(orchard_anchor);

    Ok(anchor_height.map(|h| (target_height, h)))
}

#[cfg(feature = "postgres")]
pub async fn get_tx_height(
    pool: &Pool,
    wallet_id: WalletId,
    txid: TxId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(
        "SELECT mined_height FROM transactions WHERE wallet_id = $1 AND txid = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(txid.as_ref())
    .fetch_optional(pool)
    .await?;

    Ok(row.and_then(|(h,)| h.map(|h| BlockHeight::from_u32(h as u32))))
}

#[cfg(feature = "postgres")]
pub async fn get_unified_full_viewing_keys<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
) -> Result<HashMap<AccountUuid, UnifiedFullViewingKey>, SqlxClientError> {
    let query = r#"
        SELECT uuid, ufvk
        FROM accounts
        WHERE wallet_id = $1 AND ufvk IS NOT NULL AND deleted_at IS NULL
    "#;

    let rows: Vec<(Uuid, String)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = HashMap::new();
    for (uuid, ufvk_str) in rows {
        let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
            .map_err(|e| SqlxClientError::Encoding(format!("Could not decode UFVK: {}", e)))?;
        result.insert(AccountUuid::from_uuid(uuid), ufvk);
    }

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn get_memo(
    pool: &Pool,
    wallet_id: WalletId,
    note_id: NoteId,
) -> Result<Option<Memo>, SqlxClientError> {
    use zcash_protocol::memo::MemoBytes;

    // First, try to get memo from sent_notes
    let pool_code: i32 = match note_id.protocol() {
        ShieldedProtocol::Sapling => 2,
        ShieldedProtocol::Orchard => 3,
    };

    let sent_query = r#"
        SELECT sn.memo
        FROM sent_notes sn
        INNER JOIN transactions t ON t.id = sn.tx_id
        WHERE sn.wallet_id = $1
          AND t.txid = $2
          AND sn.output_pool = $3
          AND sn.output_index = $4
    "#;

    let sent_row: Option<(Option<Vec<u8>>,)> = sqlx_core::query_as::query_as(sent_query)
        .bind(wallet_id.expose_uuid())
        .bind(note_id.txid().as_ref())
        .bind(pool_code)
        .bind(note_id.output_index() as i32)
        .fetch_optional(pool)
        .await?;

    if let Some((Some(memo_bytes),)) = sent_row {
        let memo = MemoBytes::from_bytes(&memo_bytes)
            .and_then(Memo::try_from)
            .map_err(|_| SqlxClientError::Encoding("Invalid memo".to_string()))?;
        return Ok(Some(memo));
    }

    // Fall back to received notes
    let (table, output_col) = match note_id.protocol() {
        ShieldedProtocol::Sapling => ("sapling_received_notes", "output_index"),
        ShieldedProtocol::Orchard => ("orchard_received_notes", "action_index"),
    };

    let query = format!(
        r#"
        SELECT rn.memo
        FROM {} rn
        INNER JOIN transactions t ON t.id = rn.tx_id
        WHERE rn.wallet_id = $1
          AND t.txid = $2
          AND rn.{} = $3
        "#,
        table, output_col
    );

    let row: Option<(Option<Vec<u8>>,)> = sqlx_core::query_as::query_as(&query)
        .bind(wallet_id.expose_uuid())
        .bind(note_id.txid().as_ref())
        .bind(note_id.output_index() as i32)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((Some(memo_bytes),)) => {
            let memo = MemoBytes::from_bytes(&memo_bytes)
                .and_then(Memo::try_from)
                .map_err(|_| SqlxClientError::Encoding("Invalid memo".to_string()))?;
            Ok(Some(memo))
        }
        Some((None,)) | None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_transaction(
    pool: &Pool,
    wallet_id: WalletId,
    txid: TxId,
) -> Result<Option<Transaction>, SqlxClientError> {
    let row: Option<(Vec<u8>,)> = sqlx_core::query_as::query_as(
        "SELECT raw FROM transactions WHERE wallet_id = $1 AND txid = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(txid.as_ref())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((raw,)) => {
            let tx = Transaction::read(&raw[..], zcash_protocol::consensus::BranchId::Nu5)
                .map_err(|e| SqlxClientError::Encoding(e.to_string()))?;
            Ok(Some(tx))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_sapling_nullifiers(
    pool: &Pool,
    wallet_id: WalletId,
    query: NullifierQuery,
) -> Result<Vec<(AccountUuid, sapling::Nullifier)>, SqlxClientError> {
    let sql = match query {
        NullifierQuery::Unspent => {
            r#"
                SELECT a.uuid, rn.nf
                FROM sapling_received_notes rn
                INNER JOIN accounts a ON a.id = rn.account_id
                WHERE rn.wallet_id = $1
                  AND rn.nf IS NOT NULL
                  AND a.deleted_at IS NULL
                  AND rn.id NOT IN (
                      SELECT rns.sapling_received_note_id
                      FROM sapling_received_note_spends rns
                      INNER JOIN transactions t ON t.id = rns.transaction_id
                      WHERE t.mined_height IS NOT NULL
                  )
            "#
        }
        NullifierQuery::All => {
            r#"
                SELECT a.uuid, rn.nf
                FROM sapling_received_notes rn
                INNER JOIN accounts a ON a.id = rn.account_id
                WHERE rn.wallet_id = $1
                  AND rn.nf IS NOT NULL
                  AND a.deleted_at IS NULL
            "#
        }
    };

    let rows: Vec<(Uuid, Vec<u8>)> = sqlx_core::query_as::query_as(sql)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (uuid, nf_bytes) in rows {
        let nf_array: [u8; 32] = nf_bytes
            .try_into()
            .map_err(|_| SqlxClientError::Encoding("Invalid nullifier length".to_string()))?;
        result.push((AccountUuid::from_uuid(uuid), sapling::Nullifier(nf_array)));
    }

    Ok(result)
}

#[cfg(all(feature = "orchard", feature = "postgres"))]
pub async fn get_orchard_nullifiers(
    pool: &Pool,
    wallet_id: WalletId,
    query: NullifierQuery,
) -> Result<Vec<(AccountUuid, orchard::note::Nullifier)>, SqlxClientError> {
    let sql = match query {
        NullifierQuery::Unspent => {
            r#"
                SELECT a.uuid, rn.nf
                FROM orchard_received_notes rn
                INNER JOIN accounts a ON a.id = rn.account_id
                WHERE rn.wallet_id = $1
                  AND rn.nf IS NOT NULL
                  AND a.deleted_at IS NULL
                  AND rn.id NOT IN (
                      SELECT rns.orchard_received_note_id
                      FROM orchard_received_note_spends rns
                      INNER JOIN transactions t ON t.id = rns.transaction_id
                      WHERE t.mined_height IS NOT NULL
                  )
            "#
        }
        NullifierQuery::All => {
            r#"
                SELECT a.uuid, rn.nf
                FROM orchard_received_notes rn
                INNER JOIN accounts a ON a.id = rn.account_id
                WHERE rn.wallet_id = $1
                  AND rn.nf IS NOT NULL
                  AND a.deleted_at IS NULL
            "#
        }
    };

    let rows: Vec<(Uuid, Vec<u8>)> = sqlx_core::query_as::query_as(sql)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (uuid, nf_bytes) in rows {
        let nf_array: [u8; 32] = nf_bytes
            .try_into()
            .map_err(|_| SqlxClientError::Encoding("Invalid nullifier length".to_string()))?;
        let nf = orchard::note::Nullifier::from_bytes(&nf_array)
            .into_option()
            .ok_or_else(|| SqlxClientError::Encoding("Invalid Orchard nullifier".to_string()))?;
        result.push((AccountUuid::from_uuid(uuid), nf));
    }

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn transaction_data_requests(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Vec<TransactionDataRequest>, SqlxClientError> {
    // Query for transaction data requests from:
    // 1. Explicit entries in tx_retrieval_queue
    // 2. Transactions without mined_height that need status updates

    // Default expiry delta (40 blocks) + pruning depth (100 blocks)
    const CERTAINTY_DEPTH: i64 = 140;

    let query = r#"
        SELECT txid, query_type FROM tx_retrieval_queue WHERE wallet_id = $1
        UNION
        SELECT txid, 0 as query_type
        FROM transactions
        WHERE wallet_id = $1
          AND mined_height IS NULL
          AND (
            -- we have no confirmation of expiry
            confirmed_unmined_at_height IS NULL
            -- a nonzero expiry height is known, and we have confirmation that the transaction was
            -- not unmined as of a height greater than or equal to that expiry height
            OR (
                expiry_height > 0
                AND confirmed_unmined_at_height < expiry_height
            )
            -- the expiry height is unknown and the default expiry height for it is not yet in the
            -- stable block range according to the pruning depth
            OR (
                expiry_height IS NULL
                AND confirmed_unmined_at_height < min_observed_height + $2
            )
          )
    "#;

    let rows: Vec<(Vec<u8>, i32)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(CERTAINTY_DEPTH)
        .fetch_all(pool)
        .await?;

    let mut result = Vec::new();
    for (txid_bytes, query_type) in rows {
        let txid_array: [u8; 32] = txid_bytes
            .try_into()
            .map_err(|_| SqlxClientError::Encoding("Invalid txid length".to_string()))?;
        let txid = TxId::from_bytes(txid_array);

        let request = match query_type {
            0 => TransactionDataRequest::GetStatus(txid),
            1 => TransactionDataRequest::Enhancement(txid),
            _ => {
                return Err(SqlxClientError::Encoding(
                    "Unrecognized transaction data request type".to_string(),
                ));
            }
        };
        result.push(request);
    }

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn get_received_outputs(
    pool: &Pool,
    wallet_id: WalletId,
    txid: TxId,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<Vec<ReceivedTransactionOutput>, SqlxClientError> {
    use common::i64_to_optional_height;
    use zcash_protocol::{PoolType, value::Zatoshis};

    let mut result = Vec::new();

    // Query Sapling received notes
    let sapling_query = r#"
        SELECT
            rn.output_index,
            rn.value,
            rn.recipient_key_scope,
            t.mined_height,
            COALESCE(t.trust_status, 0) > 0 AS tx_trusted
        FROM sapling_received_notes rn
        INNER JOIN transactions t ON t.id = rn.tx_id
        WHERE rn.wallet_id = $1 AND t.txid = $2
        ORDER BY rn.output_index
    "#;

    let sapling_rows: Vec<ReceivedOutputRow> = sqlx_core::query_as::query_as(sapling_query)
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .fetch_all(pool)
        .await?;

    for row in sapling_rows {
        let value = Zatoshis::from_nonnegative_i64(row.value)
            .map_err(|_| SqlxClientError::CorruptedOutput)?;
        let mined_height = i64_to_optional_height(row.mined_height)?;
        // Match SQLite's behavior: internal notes don't have address entries, so the
        // v_tx_outputs view returns NULL for recipient_key_scope. We emulate this by
        // returning None for Internal scope. Only External scope addresses are tracked.
        let key_scope = row.recipient_key_scope.and_then(|s| match s {
            0 => Some(zip32::Scope::External),
            _ => None, // Internal scope or unknown → None (like SQLite's LEFT JOIN to addresses)
        });

        let confirmations_until_spendable = confirmations_policy.confirmations_until_spendable(
            target_height,
            PoolType::SAPLING,
            key_scope,
            mined_height,
            row.tx_trusted,
            None,  // max_shielding_input_height (simplified)
            false, // tx_shielding_inputs_trusted (simplified)
        );

        result.push(ReceivedTransactionOutput::from_parts(
            PoolType::SAPLING,
            row.output_index as usize,
            value,
            confirmations_until_spendable,
        ));
    }

    // Query Orchard received notes
    #[cfg(feature = "orchard")]
    {
        let orchard_query = r#"
            SELECT
                rn.action_index AS output_index,
                rn.value,
                rn.recipient_key_scope,
                t.mined_height,
                COALESCE(t.trust_status, 0) > 0 AS tx_trusted
            FROM orchard_received_notes rn
            INNER JOIN transactions t ON t.id = rn.tx_id
            WHERE rn.wallet_id = $1 AND t.txid = $2
            ORDER BY rn.action_index
        "#;

        let orchard_rows: Vec<ReceivedOutputRow> = sqlx_core::query_as::query_as(orchard_query)
            .bind(wallet_id.expose_uuid())
            .bind(txid.as_ref())
            .fetch_all(pool)
            .await?;

        for row in orchard_rows {
            let value = Zatoshis::from_nonnegative_i64(row.value)
                .map_err(|_| SqlxClientError::CorruptedOutput)?;
            let mined_height = i64_to_optional_height(row.mined_height)?;
            // Match SQLite's behavior: internal notes don't have address entries, so the
            // v_tx_outputs view returns NULL for recipient_key_scope. We emulate this by
            // returning None for Internal scope. Only External scope addresses are tracked.
            let key_scope = row.recipient_key_scope.and_then(|s| match s {
                0 => Some(zip32::Scope::External),
                _ => None, // Internal scope or unknown → None (like SQLite's LEFT JOIN to addresses)
            });

            let confirmations_until_spendable = confirmations_policy.confirmations_until_spendable(
                target_height,
                PoolType::ORCHARD,
                key_scope,
                mined_height,
                row.tx_trusted,
                None,  // max_shielding_input_height (simplified)
                false, // tx_shielding_inputs_trusted (simplified)
            );

            result.push(ReceivedTransactionOutput::from_parts(
                PoolType::ORCHARD,
                row.output_index as usize,
                value,
                confirmations_until_spendable,
            ));
        }
    }

    Ok(result)
}

// ============================================================================
// WalletWrite implementation helpers
// ============================================================================

#[cfg(feature = "postgres")]
pub async fn create_account<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_name: &str,
    seed: &SecretVec<u8>,
    birthday: &AccountBirthday,
    key_source: Option<&str>,
) -> Result<(AccountUuid, UnifiedSpendingKey), SqlxClientError> {
    use secrecy::ExposeSecret;
    use zcash_client_backend::data_api::AccountSource;
    use zip32::fingerprint::SeedFingerprint;

    // Find the next available account index
    let next_index = get_next_account_index(pool, wallet_id, seed).await?;

    // Derive the spending key for this account
    let usk = UnifiedSpendingKey::from_seed(params, seed.expose_secret(), next_index)
        .map_err(SqlxClientError::KeyDerivationError)?;

    // Create the account source
    let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
        .ok_or_else(|| SqlxClientError::Encoding("Invalid seed".to_string()))?;
    let derivation = Zip32Derivation::new(seed_fingerprint, next_index);
    let kind = AccountSource::Derived {
        derivation: derivation.clone(),
        key_source: key_source.map(|s| s.to_string()),
    };

    // Add the account
    let account = add_account(
        pool,
        params,
        wallet_id,
        account_name,
        &kind,
        &usk.to_unified_full_viewing_key(),
        birthday,
    )
    .await?;

    Ok((account.uuid, usk))
}

/// Gets the next available account index for the given seed
#[cfg(feature = "postgres")]
async fn get_next_account_index(
    pool: &Pool,
    wallet_id: WalletId,
    seed: &SecretVec<u8>,
) -> Result<zip32::AccountId, SqlxClientError> {
    use secrecy::ExposeSecret;
    use zip32::fingerprint::SeedFingerprint;

    let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
        .ok_or_else(|| SqlxClientError::Encoding("Invalid seed".to_string()))?;

    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(
        r#"
        SELECT MAX(hd_account_index)
        FROM accounts
        WHERE wallet_id = $1
          AND hd_seed_fingerprint = $2
          AND deleted_at IS NULL
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(seed_fingerprint.to_bytes().to_vec())
    .fetch_optional(pool)
    .await?;

    let next_index = match row {
        Some((Some(max_idx),)) => (max_idx + 1) as u32,
        _ => 0,
    };

    zip32::AccountId::try_from(next_index)
        .map_err(|_| SqlxClientError::Encoding("Account index overflow".to_string()))
}

/// Adds an account to the database
#[cfg(feature = "postgres")]
async fn add_account<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_name: &str,
    kind: &zcash_client_backend::data_api::AccountSource,
    ufvk: &UnifiedFullViewingKey,
    birthday: &AccountBirthday,
) -> Result<Account, SqlxClientError> {
    use crate::{ViewingKey, types::AccountRef};
    use zcash_client_backend::data_api::{AccountPurpose, AccountSource};

    let account_uuid = AccountUuid::from_uuid(Uuid::new_v4());

    let (derivation, spending_key_available, key_source_str) = match kind {
        AccountSource::Derived {
            derivation,
            key_source,
        } => (Some(derivation), true, key_source.clone()),
        AccountSource::Imported {
            purpose: AccountPurpose::Spending { derivation },
            key_source,
        } => (derivation.as_ref(), true, key_source.clone()),
        AccountSource::Imported {
            purpose: AccountPurpose::ViewOnly,
            key_source,
        } => (None, false, key_source.clone()),
    };

    // Account kind codes: 0 = derived, 1 = imported
    let account_kind: i32 = match kind {
        AccountSource::Derived { .. } => 0,
        AccountSource::Imported { .. } => 1,
    };

    let ufvk_encoded = ufvk.encode(params);
    let uivk_encoded = ufvk.to_unified_incoming_viewing_key().encode(params);

    let birthday_height = u32::from(birthday.height()) as i64;
    let birthday_sapling_tree_size = birthday.sapling_frontier().tree_size() as i64;

    #[cfg(feature = "orchard")]
    let birthday_orchard_tree_size = Some(birthday.orchard_frontier().tree_size() as i64);
    #[cfg(not(feature = "orchard"))]
    let birthday_orchard_tree_size: Option<i64> = None;

    let recover_until_height = birthday.recover_until().map(|h| u32::from(h) as i64);

    let query = r#"
        INSERT INTO accounts (
            wallet_id, name, uuid, account_kind,
            hd_seed_fingerprint, hd_account_index, key_source,
            ufvk, uivk,
            birthday_height, birthday_sapling_tree_size, birthday_orchard_tree_size,
            recover_until_height, has_spend_key
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account_name)
        .bind(account_uuid.expose_uuid())
        .bind(account_kind)
        .bind(derivation.map(|d| d.seed_fingerprint().to_bytes().to_vec()))
        .bind(derivation.map(|d| u32::from(d.account_index()) as i64))
        .bind(key_source_str)
        .bind(&ufvk_encoded)
        .bind(&uivk_encoded)
        .bind(birthday_height)
        .bind(birthday_sapling_tree_size)
        .bind(birthday_orchard_tree_size)
        .bind(recover_until_height)
        .bind(spending_key_available)
        .fetch_one(pool)
        .await?;

    let account_ref = AccountRef(row.0);

    let account = Account {
        id: account_ref,
        uuid: account_uuid,
        name: Some(account_name.to_string()),
        kind: kind.clone(),
        viewing_key: ViewingKey::Full(Box::new(ufvk.clone())),
        birthday: birthday.height(),
    };

    // Always derive the default Unified Address for the account. If the account's viewing
    // key has fewer components than the wallet supports (most likely due to this being an
    // imported viewing key), derive an address containing the common subset of receivers.
    let (address, d_idx) = account
        .default_address(UnifiedAddressRequest::AllAvailableKeys)
        .map_err(|e| SqlxClientError::Encoding(format!("Address generation error: {}", e)))?;
    upsert_address(
        pool,
        params,
        wallet_id,
        account_ref,
        d_idx,
        &address,
        Some(birthday.height()),
    )
    .await?;

    Ok(account)
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
pub async fn import_account_hd<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_name: &str,
    seed: &SecretVec<u8>,
    account_index: zip32::AccountId,
    birthday: &AccountBirthday,
    key_source: Option<&str>,
) -> Result<(Account, UnifiedSpendingKey), SqlxClientError> {
    use secrecy::ExposeSecret;
    use zcash_client_backend::data_api::AccountSource;
    use zip32::fingerprint::SeedFingerprint;

    // Derive the spending key for the specified account index
    let usk = UnifiedSpendingKey::from_seed(params, seed.expose_secret(), account_index)
        .map_err(SqlxClientError::KeyDerivationError)?;

    // Create the account source
    let seed_fingerprint = SeedFingerprint::from_seed(seed.expose_secret())
        .ok_or_else(|| SqlxClientError::Encoding("Invalid seed".to_string()))?;
    let derivation = Zip32Derivation::new(seed_fingerprint, account_index);
    let kind = AccountSource::Derived {
        derivation,
        key_source: key_source.map(|s| s.to_string()),
    };

    // Check for existing account with same derivation
    if let Some(existing) = get_derived_account(
        pool,
        params,
        wallet_id,
        &Zip32Derivation::new(seed_fingerprint, account_index),
    )
    .await?
    {
        return Err(SqlxClientError::AccountCollision(existing.uuid));
    }

    // Add the account
    let account = add_account(
        pool,
        params,
        wallet_id,
        account_name,
        &kind,
        &usk.to_unified_full_viewing_key(),
        birthday,
    )
    .await?;

    Ok((account, usk))
}

#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
pub async fn import_account_ufvk<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_name: &str,
    unified_key: &UnifiedFullViewingKey,
    birthday: &AccountBirthday,
    purpose: AccountPurpose,
    key_source: Option<&str>,
) -> Result<Account, SqlxClientError> {
    use zcash_client_backend::data_api::AccountSource;

    // Check for existing account with same UFVK
    if let Some(existing) = get_account_for_ufvk(pool, params, wallet_id, unified_key).await? {
        return Err(SqlxClientError::AccountCollision(existing.uuid));
    }

    // Create the account source
    let kind = AccountSource::Imported {
        purpose,
        key_source: key_source.map(|s| s.to_string()),
    };

    // Add the account
    add_account(
        pool,
        params,
        wallet_id,
        account_name,
        &kind,
        unified_key,
        birthday,
    )
    .await
}

#[cfg(feature = "postgres")]
pub async fn delete_account(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
) -> Result<(), SqlxClientError> {
    // Check if account exists
    let account_exists: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    if account_exists.is_none() {
        return Err(SqlxClientError::AccountNotFound(account));
    }

    // Update sent_notes: set to_address for notes sent to this account
    // This preserves the address info before we delete account references
    sqlx_core::query::query(
        r#"
        UPDATE sent_notes sn
        SET to_address = (
            SELECT COALESCE(addr.address, addr.cached_transparent_receiver_address)
            FROM sapling_received_notes rn
            JOIN addresses addr ON addr.account_id = rn.account_id
                AND addr.diversifier_index_be = rn.diversifier
            WHERE rn.tx_id = sn.tx_id AND rn.output_index = sn.output_index
            LIMIT 1
        ),
        to_account_id = NULL
        WHERE sn.wallet_id = $1
          AND sn.to_account_id IN (
              SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2
          )
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .execute(pool)
    .await?;

    // Delete transactions that are solely linked to this account
    // Keep transactions that involve other accounts
    sqlx_core::query::query(
        r#"
        WITH account_transactions AS (
            -- Transactions where this account received notes
            SELECT rn.tx_id AS transaction_id
            FROM sapling_received_notes rn
            JOIN accounts a ON a.id = rn.account_id
            WHERE rn.wallet_id = $1 AND a.uuid = $2
            UNION
            SELECT rn.tx_id AS transaction_id
            FROM orchard_received_notes rn
            JOIN accounts a ON a.id = rn.account_id
            WHERE rn.wallet_id = $1 AND a.uuid = $2
            UNION
            -- Transactions where this account spent notes
            SELECT rns.transaction_id
            FROM sapling_received_note_spends rns
            JOIN sapling_received_notes rn ON rn.id = rns.sapling_received_note_id
            JOIN accounts a ON a.id = rn.account_id
            WHERE rns.wallet_id = $1 AND a.uuid = $2
            UNION
            SELECT rns.transaction_id
            FROM orchard_received_note_spends rns
            JOIN orchard_received_notes rn ON rn.id = rns.orchard_received_note_id
            JOIN accounts a ON a.id = rn.account_id
            WHERE rns.wallet_id = $1 AND a.uuid = $2
        ),
        other_account_transactions AS (
            -- Transactions involving other accounts
            SELECT rn.tx_id AS transaction_id
            FROM sapling_received_notes rn
            JOIN accounts a ON a.id = rn.account_id
            WHERE rn.wallet_id = $1 AND a.uuid != $2 AND a.deleted_at IS NULL
            UNION
            SELECT rn.tx_id AS transaction_id
            FROM orchard_received_notes rn
            JOIN accounts a ON a.id = rn.account_id
            WHERE rn.wallet_id = $1 AND a.uuid != $2 AND a.deleted_at IS NULL
            UNION
            SELECT rns.transaction_id
            FROM sapling_received_note_spends rns
            JOIN sapling_received_notes rn ON rn.id = rns.sapling_received_note_id
            JOIN accounts a ON a.id = rn.account_id
            WHERE rns.wallet_id = $1 AND a.uuid != $2 AND a.deleted_at IS NULL
            UNION
            SELECT rns.transaction_id
            FROM orchard_received_note_spends rns
            JOIN orchard_received_notes rn ON rn.id = rns.orchard_received_note_id
            JOIN accounts a ON a.id = rn.account_id
            WHERE rns.wallet_id = $1 AND a.uuid != $2 AND a.deleted_at IS NULL
        )
        DELETE FROM transactions
        WHERE wallet_id = $1
          AND id IN (
              SELECT transaction_id FROM account_transactions
              EXCEPT
              SELECT transaction_id FROM other_account_transactions
          )
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .execute(pool)
    .await?;

    // Delete the account itself (hard delete, not soft delete)
    // CASCADE will clean up related records like addresses, received_notes, etc.
    sqlx_core::query::query("DELETE FROM accounts WHERE wallet_id = $1 AND uuid = $2")
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn get_next_available_address<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    request: UnifiedAddressRequest,
) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, SqlxClientError> {
    use zcash_client_backend::data_api::Account as AccountTrait;

    // Get the account to access its UIVK
    let account_data = match get_account(pool, params, wallet_id, account).await? {
        Some(a) => a,
        None => return Ok(None),
    };

    // Get the maximum diversifier index used so far
    let query = r#"
        SELECT MAX(diversifier_index_be)
        FROM addresses
        WHERE wallet_id = $1
          AND account_id IN (
              SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL
          )
    "#;

    let row: Option<(Option<Vec<u8>>,)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .fetch_optional(pool)
        .await?;

    let next_diversifier = match row {
        Some((Some(max_di_bytes),)) => {
            // Parse the max diversifier index and increment
            let di_bytes: [u8; 11] = max_di_bytes
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid diversifier index".to_string()))?;
            let mut next_di = DiversifierIndex::from(di_bytes);
            next_di
                .increment()
                .map_err(|_| SqlxClientError::Encoding("Diversifier index overflow".to_string()))?;
            next_di
        }
        _ => DiversifierIndex::default(),
    };

    // Generate the address at the next diversifier index
    let uivk = account_data.uivk();
    let ua = uivk
        .address(next_diversifier, request)
        .map_err(|e| SqlxClientError::Encoding(format!("Address generation error: {}", e)))?;

    // Store the new address in the database
    let ua_encoded = ua.encode(params);
    let di_bytes = next_diversifier.as_bytes();

    // Compute receiver flags from the unified address
    let receiver_flags = common::ReceiverFlags::from(&ua).bits();

    // Extract transparent receiver info if available
    #[cfg(feature = "transparent-inputs")]
    let (transparent_child_index, cached_taddr) = {
        use ::transparent::keys::NonHardenedChildIndex;
        use zcash_client_backend::encoding::AddressCodec;

        let idx = NonHardenedChildIndex::try_from(next_diversifier)
            .ok()
            .map(|i| i.index() as i32);

        let taddr = ua.transparent().map(|t| t.encode(params));

        (idx, taddr)
    };

    #[cfg(not(feature = "transparent-inputs"))]
    let (transparent_child_index, cached_taddr): (Option<i32>, Option<String>) = (None, None);

    let insert_query = r#"
        INSERT INTO addresses (
            wallet_id, account_id, diversifier_index_be, address,
            key_scope, receiver_flags, transparent_child_index, cached_transparent_receiver_address
        )
        SELECT $1, id, $3, $4, $5, $6, $7, $8
        FROM accounts
        WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL
    "#;

    sqlx_core::query::query(insert_query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(di_bytes.to_vec())
        .bind(&ua_encoded)
        .bind(0i32) // key_scope = External
        .bind(receiver_flags)
        .bind(transparent_child_index)
        .bind(cached_taddr)
        .execute(pool)
        .await?;

    Ok(Some((ua, next_diversifier)))
}

#[cfg(feature = "postgres")]
pub async fn get_address_for_index<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    diversifier_index: DiversifierIndex,
    request: UnifiedAddressRequest,
) -> Result<Option<UnifiedAddress>, SqlxClientError> {
    use zcash_client_backend::data_api::Account as AccountTrait;

    // Get the account to access its UIVK
    let account_data = match get_account(pool, params, wallet_id, account).await? {
        Some(a) => a,
        None => return Ok(None),
    };

    // Check if we already have this address stored
    let di_bytes = diversifier_index.as_bytes();
    let query = r#"
        SELECT address
        FROM addresses
        WHERE wallet_id = $1
          AND diversifier_index_be = $2
          AND account_id IN (
              SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $3 AND deleted_at IS NULL
          )
    "#;

    let row: Option<(String,)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(di_bytes.to_vec())
        .bind(account.expose_uuid())
        .fetch_optional(pool)
        .await?;

    if let Some((existing_address,)) = row {
        // Parse and return the existing address
        use zcash_client_backend::encoding::AddressCodec;
        let ua = UnifiedAddress::decode(params, &existing_address)
            .map_err(|e| SqlxClientError::Encoding(format!("Could not decode address: {}", e)))?;
        return Ok(Some(ua));
    }

    // Generate the address at the requested diversifier index
    let uivk = account_data.uivk();
    let ua = uivk
        .address(diversifier_index, request)
        .map_err(|e| SqlxClientError::Encoding(format!("Address generation error: {}", e)))?;

    // Store the new address in the database
    let ua_encoded = ua.encode(params);

    // Compute receiver flags from the unified address
    let receiver_flags = common::ReceiverFlags::from(&ua).bits();

    // Extract transparent receiver info if available
    #[cfg(feature = "transparent-inputs")]
    let (transparent_child_index, cached_taddr) = {
        use ::transparent::keys::NonHardenedChildIndex;
        use zcash_client_backend::encoding::AddressCodec;

        let idx = NonHardenedChildIndex::try_from(diversifier_index)
            .ok()
            .map(|i| i.index() as i32);

        let taddr = ua.transparent().map(|t| t.encode(params));

        (idx, taddr)
    };

    #[cfg(not(feature = "transparent-inputs"))]
    let (transparent_child_index, cached_taddr): (Option<i32>, Option<String>) = (None, None);

    let insert_query = r#"
        INSERT INTO addresses (
            wallet_id, account_id, diversifier_index_be, address,
            key_scope, receiver_flags, transparent_child_index, cached_transparent_receiver_address
        )
        SELECT $1, id, $3, $4, $5, $6, $7, $8
        FROM accounts
        WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL
        ON CONFLICT (wallet_id, account_id, key_scope, diversifier_index_be) DO NOTHING
    "#;

    sqlx_core::query::query(insert_query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(di_bytes.to_vec())
        .bind(&ua_encoded)
        .bind(0i32) // key_scope = External
        .bind(receiver_flags)
        .bind(transparent_child_index)
        .bind(cached_taddr)
        .execute(pool)
        .await?;

    Ok(Some(ua))
}

/// A reference to an address in the addresses table.
#[derive(Debug, Clone, Copy)]
pub struct AddressRef(pub i64);

/// Inserts or updates an address in the addresses table.
///
/// This is used when creating accounts to ensure the default address is stored
/// with an `exposed_at_height` so that `get_last_generated_address_matching` can find it.
///
/// Returns the address ID of the inserted/updated address.
#[cfg(feature = "postgres")]
pub(crate) async fn upsert_address<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: crate::types::AccountRef,
    diversifier_index: DiversifierIndex,
    address: &UnifiedAddress,
    exposed_at_height: Option<BlockHeight>,
) -> Result<AddressRef, SqlxClientError> {
    use zcash_client_backend::encoding::AddressCodec;

    let di_bytes = diversifier_index.as_bytes();
    let ua_encoded = address.encode(params);
    let receiver_flags = common::ReceiverFlags::from(address).bits();

    // Extract transparent receiver info if available
    #[cfg(feature = "transparent-inputs")]
    let (transparent_child_index, cached_taddr) = {
        use ::transparent::keys::NonHardenedChildIndex;

        let idx = NonHardenedChildIndex::try_from(diversifier_index)
            .ok()
            .map(|i| i.index() as i32);

        let taddr = address.transparent().map(|t| t.encode(params));

        (idx, taddr)
    };

    #[cfg(not(feature = "transparent-inputs"))]
    let (transparent_child_index, cached_taddr): (Option<i32>, Option<String>) = (None, None);

    let exposed_height = exposed_at_height.map(|h| u32::from(h) as i64);

    // Use ON CONFLICT to update exposed_at_height if the address already exists
    // Return the ID of the upserted row
    let query = r#"
        INSERT INTO addresses (
            wallet_id, account_id, diversifier_index_be, address,
            key_scope, receiver_flags, transparent_child_index,
            cached_transparent_receiver_address, exposed_at_height
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (wallet_id, account_id, key_scope, diversifier_index_be) DO UPDATE
        SET exposed_at_height = COALESCE(
            LEAST(addresses.exposed_at_height, EXCLUDED.exposed_at_height),
            addresses.exposed_at_height,
            EXCLUDED.exposed_at_height
        ),
        address = CASE
            WHEN addresses.exposed_at_height IS NULL THEN EXCLUDED.address
            ELSE addresses.address
        END,
        receiver_flags = CASE
            WHEN addresses.exposed_at_height IS NULL THEN EXCLUDED.receiver_flags
            ELSE addresses.receiver_flags
        END
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account_id.0)
        .bind(di_bytes.to_vec())
        .bind(&ua_encoded)
        .bind(0i32) // key_scope = External
        .bind(receiver_flags)
        .bind(transparent_child_index)
        .bind(cached_taddr)
        .bind(exposed_height)
        .fetch_one(pool)
        .await?;

    Ok(AddressRef(row.0))
}

/// Updates the scan queue with new ranges based on the chain tip.
///
/// This function analyzes the current chain state and creates appropriate
/// scan ranges with correct priorities based on:
/// - Wallet birthday
/// - Maximum scanned height
/// - Shard boundaries
/// - Chain tip
#[cfg(feature = "postgres")]
pub async fn update_chain_tip<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    tip_height: BlockHeight,
) -> Result<(), SqlxClientError> {
    // Use the scanning module implementation which matches SQLite
    scanning::update_chain_tip(pool, params, wallet_id, tip_height).await
}

#[cfg(feature = "postgres")]
pub async fn put_blocks<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    from_state: &ChainState,
    blocks: Vec<ScannedBlock<AccountUuid>>,
) -> Result<Option<PutBlocksResult>, SqlxClientError> {
    use common::height_to_i64;

    if blocks.is_empty() {
        return Ok(None);
    }

    // Validate block sequence
    let initial_block = blocks.first().unwrap();
    if from_state.block_height() + 1 != initial_block.height() {
        return Err(SqlxClientError::BlockHeightDiscontinuity {
            expected: from_state.block_height() + 1,
            found: initial_block.height(),
        });
    }

    // Calculate starting positions for commitments
    let sapling_start_position = Position::from(
        u64::from(initial_block.sapling().final_tree_size())
            - u64::try_from(initial_block.sapling().commitments().len()).unwrap(),
    );
    #[cfg(feature = "orchard")]
    let orchard_start_position = Position::from(
        u64::from(initial_block.orchard().final_tree_size())
            - u64::try_from(initial_block.orchard().commitments().len()).unwrap(),
    );

    let start_height = initial_block.height();
    let mut last_height: Option<BlockHeight> = None;
    let mut sapling_commitments = vec![];
    #[cfg(feature = "orchard")]
    let mut orchard_commitments = vec![];
    let mut note_positions = vec![];

    for block in blocks.into_iter() {
        // Check block sequence continuity
        if let Some(prev) = last_height {
            if block.height() != prev + 1 {
                return Err(SqlxClientError::BlockHeightDiscontinuity {
                    expected: prev + 1,
                    found: block.height(),
                });
            }
        }

        let height = block.height();
        let height_i64 = height_to_i64(height);
        let hash = block.block_hash();
        let block_time = block.block_time() as i64;
        let sapling_tree_size = block.sapling().final_tree_size() as i64;
        let sapling_output_count = block.sapling().commitments().len() as i64;

        #[cfg(feature = "orchard")]
        let orchard_tree_size = block.orchard().final_tree_size() as i64;
        #[cfg(feature = "orchard")]
        let orchard_action_count = block.orchard().commitments().len() as i64;

        // Check for block hash conflict (reorg detection)
        // Global blocks table - all wallets share the same blockchain data
        let existing_hash: Option<(Vec<u8>,)> =
            sqlx_core::query_as::query_as("SELECT hash FROM blocks WHERE height = $1")
                .bind(height_i64)
                .fetch_optional(pool)
                .await?;

        if let Some((stored_hash,)) = existing_hash {
            if stored_hash != hash.0.to_vec() {
                return Err(SqlxClientError::BlockConflict(height));
            }
        }

        // Insert block metadata (global table, no wallet_id)
        #[cfg(feature = "orchard")]
        let block_query = r#"
            INSERT INTO blocks (height, hash, time, sapling_commitment_tree_size,
                               sapling_output_count, orchard_commitment_tree_size, orchard_action_count)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (height) DO NOTHING
        "#;

        #[cfg(not(feature = "orchard"))]
        let block_query = r#"
            INSERT INTO blocks (height, hash, time, sapling_commitment_tree_size, sapling_output_count)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (height) DO NOTHING
        "#;

        #[cfg(feature = "orchard")]
        sqlx_core::query::query(block_query)
            .bind(height_i64)
            .bind(hash.0.to_vec())
            .bind(block_time)
            .bind(sapling_tree_size)
            .bind(sapling_output_count)
            .bind(orchard_tree_size)
            .bind(orchard_action_count)
            .execute(pool)
            .await?;

        #[cfg(not(feature = "orchard"))]
        sqlx_core::query::query(block_query)
            .bind(height_i64)
            .bind(hash.0.to_vec())
            .bind(block_time)
            .bind(sapling_tree_size)
            .bind(sapling_output_count)
            .execute(pool)
            .await?;

        // Insert ALL nullifiers from this block into the nullifier_map for out-of-order scanning.
        // This is done before processing wallet transactions so that when we insert received notes,
        // we can check if their nullifiers were already spent in a later block we scanned first.
        // (Global table, no wallet_id)
        for (_txid, tx_index, nullifiers) in block.sapling().nullifier_map() {
            for nf in nullifiers {
                let nf_map_query = r#"
                    INSERT INTO sapling_nullifier_map (spend_pool, nf, block_height, tx_index)
                    VALUES (2, $1, $2, $3)
                    ON CONFLICT (nf) DO NOTHING
                "#;
                sqlx_core::query::query(nf_map_query)
                    .bind(nf.0.to_vec())
                    .bind(height_i64)
                    .bind(i32::from(u16::from(*tx_index)))
                    .execute(pool)
                    .await?;
            }
        }

        #[cfg(feature = "orchard")]
        for (_txid, tx_index, nullifiers) in block.orchard().nullifier_map() {
            for nf in nullifiers {
                let nf_map_query = r#"
                    INSERT INTO orchard_nullifier_map (spend_pool, nf, block_height, tx_index)
                    VALUES (3, $1, $2, $3)
                    ON CONFLICT (nf) DO NOTHING
                "#;
                sqlx_core::query::query(nf_map_query)
                    .bind(nf.to_bytes().to_vec())
                    .bind(height_i64)
                    .bind(i32::from(u16::from(*tx_index)))
                    .execute(pool)
                    .await?;
            }
        }

        // Process transactions in this block
        for tx in block.transactions() {
            let txid = tx.txid();

            // Insert or update transaction metadata
            let tx_query = r#"
                INSERT INTO transactions (wallet_id, txid, mined_height, tx_index, min_observed_height)
                VALUES ($1, $2, $3, $4, $3)
                ON CONFLICT (wallet_id, txid) DO UPDATE SET
                    mined_height = EXCLUDED.mined_height,
                    tx_index = EXCLUDED.tx_index,
                    min_observed_height = LEAST(transactions.min_observed_height, EXCLUDED.min_observed_height)
                RETURNING id
            "#;

            let tx_ref: (i64,) = sqlx_core::query_as::query_as(tx_query)
                .bind(wallet_id.expose_uuid())
                .bind(txid.as_ref())
                .bind(height_i64)
                .bind(tx.block_index() as i64)
                .fetch_one(pool)
                .await?;

            let tx_id = tx_ref.0;

            // Process Sapling spends (mark notes as spent)
            for spend in tx.sapling_spends() {
                let nf = spend.nf();
                // Mark the note as spent if it exists in our wallet
                let mark_spent_query = r#"
                    INSERT INTO sapling_received_note_spends (wallet_id, sapling_received_note_id, transaction_id)
                    SELECT $1, rn.id, $2
                    FROM sapling_received_notes rn
                    WHERE rn.wallet_id = $1 AND rn.nf = $3
                    ON CONFLICT (wallet_id, sapling_received_note_id, transaction_id) DO NOTHING
                "#;
                sqlx_core::query::query(mark_spent_query)
                    .bind(wallet_id.expose_uuid())
                    .bind(tx_id)
                    .bind(nf.0.to_vec())
                    .execute(pool)
                    .await?;
            }

            #[cfg(feature = "orchard")]
            for spend in tx.orchard_spends() {
                let nf = spend.nf();
                // Mark the note as spent if it exists in our wallet
                let mark_spent_query = r#"
                    INSERT INTO orchard_received_note_spends (wallet_id, orchard_received_note_id, transaction_id)
                    SELECT $1, rn.id, $2
                    FROM orchard_received_notes rn
                    WHERE rn.wallet_id = $1 AND rn.nf = $3
                    ON CONFLICT (wallet_id, orchard_received_note_id, transaction_id) DO NOTHING
                "#;
                sqlx_core::query::query(mark_spent_query)
                    .bind(wallet_id.expose_uuid())
                    .bind(tx_id)
                    .bind(nf.to_bytes().to_vec())
                    .execute(pool)
                    .await?;
            }

            // Process Sapling outputs (received notes)
            for output in tx.sapling_outputs() {
                // Check if this note was spent in a block we already scanned (out-of-order)
                // nullifier_map is global, but transactions are per-wallet
                let spent_in = if let Some(nf) = output.nf() {
                    let query_nf_map = r#"
                        SELECT t.id
                        FROM sapling_nullifier_map nm
                        JOIN transactions t ON t.wallet_id = $1
                            AND t.mined_height = nm.block_height
                            AND t.tx_index = nm.tx_index
                        WHERE nm.nf = $2
                    "#;
                    let result: Option<(i64,)> = sqlx_core::query_as::query_as(query_nf_map)
                        .bind(wallet_id.expose_uuid())
                        .bind(nf.0.to_vec())
                        .fetch_optional(pool)
                        .await?;
                    result.map(|(id,)| id)
                } else {
                    None
                };

                put_sapling_received_note(
                    pool,
                    params,
                    wallet_id,
                    tx_id,
                    output,
                    Some(height),
                    spent_in,
                )
                .await?;
            }

            #[cfg(feature = "orchard")]
            for output in tx.orchard_outputs() {
                // Check if this note was spent in a block we already scanned (out-of-order)
                // nullifier_map is global, but transactions are per-wallet
                let spent_in = if let Some(nf) = output.nf() {
                    let query_nf_map = r#"
                        SELECT t.id
                        FROM orchard_nullifier_map nm
                        JOIN transactions t ON t.wallet_id = $1
                            AND t.mined_height = nm.block_height
                            AND t.tx_index = nm.tx_index
                        WHERE nm.nf = $2
                    "#;
                    let result: Option<(i64,)> = sqlx_core::query_as::query_as(query_nf_map)
                        .bind(wallet_id.expose_uuid())
                        .bind(nf.to_bytes().to_vec())
                        .fetch_optional(pool)
                        .await?;
                    result.map(|(id,)| id)
                } else {
                    None
                };

                put_orchard_received_note(
                    pool,
                    params,
                    wallet_id,
                    tx_id,
                    output,
                    Some(height),
                    spent_in,
                )
                .await?;
            }

            // Collect note positions for scan completion tracking
            for output in tx.sapling_outputs() {
                note_positions.push((
                    ShieldedProtocol::Sapling,
                    output.note_commitment_tree_position(),
                ));
            }
            #[cfg(feature = "orchard")]
            for output in tx.orchard_outputs() {
                note_positions.push((
                    ShieldedProtocol::Orchard,
                    output.note_commitment_tree_position(),
                ));
            }
        }

        // Collect commitments from this block for tree updates
        let block_commitments = block.into_commitments();
        for (commitment, retention) in block_commitments.sapling {
            sapling_commitments.push((commitment, retention));
        }
        #[cfg(feature = "orchard")]
        for (commitment, retention) in block_commitments.orchard {
            orchard_commitments.push((commitment, retention));
        }

        last_height = Some(height);
    }

    // Update scan queue to mark this range as scanned
    // This is more complex than a simple DELETE because we need to handle partial overlaps:
    // - If we scanned [A, B] and queue has [X, Y]:
    //   - If A <= X and B >= Y-1: delete the entry (fully covered)
    //   - If A > X and B >= Y-1: shrink to [X, A)
    //   - If A <= X and B < Y-1: shrink to [B+1, Y)
    //   - If A > X and B < Y-1: split into [X, A) and [B+1, Y)
    if let Some(end_height) = last_height {
        let scanned_start = height_to_i64(start_height);
        let scanned_end = height_to_i64(end_height) + 1; // exclusive

        // First, get all overlapping scan_queue entries
        let overlapping: Vec<(i64, i64, i32)> = sqlx_core::query_as::query_as(
            r#"
            SELECT block_range_start, block_range_end, priority
            FROM scan_queue
            WHERE wallet_id = $1
              AND block_range_start < $3
              AND block_range_end > $2
            "#,
        )
        .bind(wallet_id.expose_uuid())
        .bind(scanned_start)
        .bind(scanned_end)
        .fetch_all(pool)
        .await?;

        // Delete all overlapping entries
        sqlx_core::query::query(
            r#"
            DELETE FROM scan_queue
            WHERE wallet_id = $1
              AND block_range_start < $3
              AND block_range_end > $2
            "#,
        )
        .bind(wallet_id.expose_uuid())
        .bind(scanned_start)
        .bind(scanned_end)
        .execute(pool)
        .await?;

        // Re-insert partial ranges that weren't scanned
        for (queue_start, queue_end, priority) in overlapping {
            // If there's an unscanned range before what we scanned
            if queue_start < scanned_start {
                sqlx_core::query::query(
                    r#"
                    INSERT INTO scan_queue (wallet_id, block_range_start, block_range_end, priority)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (wallet_id, block_range_start, block_range_end)
                    DO UPDATE SET priority = GREATEST(scan_queue.priority, $4)
                    "#,
                )
                .bind(wallet_id.expose_uuid())
                .bind(queue_start)
                .bind(scanned_start)
                .bind(priority)
                .execute(pool)
                .await?;
            }

            // If there's an unscanned range after what we scanned
            if queue_end > scanned_end {
                sqlx_core::query::query(
                    r#"
                    INSERT INTO scan_queue (wallet_id, block_range_start, block_range_end, priority)
                    VALUES ($1, $2, $3, $4)
                    ON CONFLICT (wallet_id, block_range_start, block_range_end)
                    DO UPDATE SET priority = GREATEST(scan_queue.priority, $4)
                    "#,
                )
                .bind(wallet_id.expose_uuid())
                .bind(scanned_end)
                .bind(queue_end)
                .bind(priority)
                .execute(pool)
                .await?;
            }
        }
    }

    Ok(Some(PutBlocksResult {
        start_height,
        last_scanned_height: last_height,
        sapling_commitments,
        sapling_start_position,
        #[cfg(feature = "orchard")]
        orchard_commitments,
        #[cfg(feature = "orchard")]
        orchard_start_position,
        note_positions,
    }))
}

/// Inserts a received Sapling note into the database.
#[cfg(feature = "postgres")]
async fn put_sapling_received_note<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    tx_id: i64,
    output: &zcash_client_backend::wallet::WalletSaplingOutput<AccountUuid>,
    mined_height: Option<BlockHeight>,
    spent_in: Option<i64>,
) -> Result<(), SqlxClientError> {
    use group::ff::PrimeField;
    use zcash_keys::keys::UnifiedAddressRequest;

    // Get the account's internal ID
    let account_query =
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL";
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(account_query)
        .bind(wallet_id.expose_uuid())
        .bind(output.account_id().expose_uuid())
        .fetch_optional(pool)
        .await?;

    let account_id = match account_row {
        Some((id,)) => id,
        None => return Ok(()), // Unknown account, skip
    };

    // Ensure address exists for non-change notes
    let address_id = if output.recipient_key_scope() != Some(zip32::Scope::Internal) {
        // Get the UIVK to derive the address
        let uivk_row: Option<(String,)> =
            sqlx_core::query_as::query_as("SELECT uivk FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(pool)
                .await?;

        if let Some((uivk_str,)) = uivk_row {
            if let Ok(uivk) = zcash_keys::keys::UnifiedIncomingViewingKey::decode(params, &uivk_str)
            {
                if let Some(sapling_ivk) = uivk.sapling() {
                    let to = output.note().recipient();
                    if let Some(di) = sapling_ivk.decrypt_diversifier(&to) {
                        if let Ok(ua) = uivk.address(di, UnifiedAddressRequest::ALLOW_ALL) {
                            let addr_ref = upsert_address(
                                pool,
                                params,
                                wallet_id,
                                crate::types::AccountRef(account_id),
                                di,
                                &ua,
                                mined_height,
                            )
                            .await
                            .ok();
                            addr_ref.map(|a| a.0)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let note = output.note();
    let recipient = note.recipient();
    let diversifier = recipient.diversifier();
    let diversifier_bytes = diversifier.0.to_vec();
    let value = note.value().inner() as i64;
    let rcm = note.rcm().to_repr();
    let rcm_bytes = rcm.as_slice().to_vec();
    let nf = output.nf().map(|nf| nf.0.to_vec());
    let is_change = output.is_change();
    let position = output.note_commitment_tree_position();
    let position_i64 = u64::from(position) as i64;
    let scope = output.recipient_key_scope().map(|s| match s {
        zip32::Scope::External => 0i64,
        zip32::Scope::Internal => 1i64,
    });

    let query = r#"
        INSERT INTO sapling_received_notes (
            wallet_id, tx_id, output_index, account_id, address_id,
            diversifier, value, rcm, memo, nf, is_change,
            commitment_tree_position, recipient_key_scope
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (wallet_id, tx_id, output_index) DO UPDATE SET
            account_id = EXCLUDED.account_id,
            address_id = COALESCE(EXCLUDED.address_id, sapling_received_notes.address_id),
            diversifier = EXCLUDED.diversifier,
            value = EXCLUDED.value,
            rcm = EXCLUDED.rcm,
            nf = COALESCE(EXCLUDED.nf, sapling_received_notes.nf),
            is_change = GREATEST(EXCLUDED.is_change::int, sapling_received_notes.is_change::int)::bool,
            commitment_tree_position = COALESCE(EXCLUDED.commitment_tree_position, sapling_received_notes.commitment_tree_position),
            recipient_key_scope = COALESCE(EXCLUDED.recipient_key_scope, sapling_received_notes.recipient_key_scope)
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_id)
        .bind(output.index() as i32)
        .bind(account_id)
        .bind(address_id)
        .bind(diversifier_bytes)
        .bind(value)
        .bind(rcm_bytes)
        .bind(None::<Vec<u8>>) // memo - would need to be extracted from tx
        .bind(nf)
        .bind(is_change)
        .bind(position_i64)
        .bind(scope)
        .fetch_one(pool)
        .await?;

    let received_note_id = row.0;

    // If this note was already spent in a block we scanned out of order, record the spend
    if let Some(spending_tx_id) = spent_in {
        let spend_query = r#"
            INSERT INTO sapling_received_note_spends (wallet_id, sapling_received_note_id, transaction_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (wallet_id, sapling_received_note_id, transaction_id) DO NOTHING
        "#;
        sqlx_core::query::query(spend_query)
            .bind(wallet_id.expose_uuid())
            .bind(received_note_id)
            .bind(spending_tx_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

/// Inserts a received Orchard note into the database.
#[cfg(all(feature = "orchard", feature = "postgres"))]
async fn put_orchard_received_note<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    tx_id: i64,
    output: &zcash_client_backend::wallet::WalletOrchardOutput<AccountUuid>,
    mined_height: Option<BlockHeight>,
    spent_in: Option<i64>,
) -> Result<(), SqlxClientError> {
    use zcash_keys::keys::UnifiedAddressRequest;

    // Get the account's internal ID
    let account_query =
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL";
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(account_query)
        .bind(wallet_id.expose_uuid())
        .bind(output.account_id().expose_uuid())
        .fetch_optional(pool)
        .await?;

    let account_id = match account_row {
        Some((id,)) => id,
        None => return Ok(()), // Unknown account, skip
    };

    // Ensure address exists for non-change notes
    let address_id = if output.recipient_key_scope() != Some(orchard::keys::Scope::Internal) {
        // Get the UIVK to derive the address
        let uivk_row: Option<(String,)> =
            sqlx_core::query_as::query_as("SELECT uivk FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(pool)
                .await?;

        if let Some((uivk_str,)) = uivk_row {
            if let Ok(uivk) = zcash_keys::keys::UnifiedIncomingViewingKey::decode(params, &uivk_str)
            {
                if let Some(orchard_ivk) = uivk.orchard() {
                    let to = output.note().recipient();
                    // Note: Orchard IVK diversifier_index takes an Address, not a Diversifier
                    if let Some(di) = orchard_ivk.diversifier_index(&to) {
                        if let Ok(ua) = uivk.address(di, UnifiedAddressRequest::ALLOW_ALL) {
                            let addr_ref = upsert_address(
                                pool,
                                params,
                                wallet_id,
                                crate::types::AccountRef(account_id),
                                di,
                                &ua,
                                mined_height,
                            )
                            .await
                            .ok();
                            addr_ref.map(|a| a.0)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    let note = output.note();
    let recipient = note.recipient();
    let diversifier = recipient.diversifier();
    // Orchard diversifier is stored as 11 bytes - use as_array() to get the bytes
    let diversifier_bytes = diversifier.as_array().to_vec();
    let value = note.value().inner() as i64;
    let rho = note.rho().to_bytes();
    let rho_bytes = rho.to_vec();
    let rseed = *note.rseed().as_bytes();
    let rseed_bytes = rseed.to_vec();
    let nf = output.nf().map(|nf| nf.to_bytes().to_vec());
    let is_change = output.is_change();
    let position = output.note_commitment_tree_position();
    let position_i64 = u64::from(position) as i64;
    let scope = output.recipient_key_scope().map(|s| match s {
        orchard::keys::Scope::External => 0i64,
        orchard::keys::Scope::Internal => 1i64,
    });

    let query = r#"
        INSERT INTO orchard_received_notes (
            wallet_id, tx_id, action_index, account_id, address_id,
            diversifier, value, rho, rseed, memo, nf, is_change,
            commitment_tree_position, recipient_key_scope
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        ON CONFLICT (wallet_id, tx_id, action_index) DO UPDATE SET
            account_id = EXCLUDED.account_id,
            address_id = COALESCE(EXCLUDED.address_id, orchard_received_notes.address_id),
            diversifier = EXCLUDED.diversifier,
            value = EXCLUDED.value,
            rho = EXCLUDED.rho,
            rseed = EXCLUDED.rseed,
            nf = COALESCE(EXCLUDED.nf, orchard_received_notes.nf),
            is_change = GREATEST(EXCLUDED.is_change::int, orchard_received_notes.is_change::int)::bool,
            commitment_tree_position = COALESCE(EXCLUDED.commitment_tree_position, orchard_received_notes.commitment_tree_position),
            recipient_key_scope = EXCLUDED.recipient_key_scope
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_id)
        .bind(output.index() as i32)
        .bind(account_id)
        .bind(address_id)
        .bind(diversifier_bytes)
        .bind(value)
        .bind(rho_bytes)
        .bind(rseed_bytes)
        .bind(None::<Vec<u8>>) // memo
        .bind(nf)
        .bind(is_change)
        .bind(position_i64)
        .bind(scope)
        .fetch_one(pool)
        .await?;

    let received_note_id = row.0;

    // If this note was already spent in a block we scanned out of order, record the spend
    if let Some(spending_tx_id) = spent_in {
        let spend_query = r#"
            INSERT INTO orchard_received_note_spends (wallet_id, orchard_received_note_id, transaction_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (wallet_id, orchard_received_note_id, transaction_id) DO NOTHING
        "#;
        sqlx_core::query::query(spend_query)
            .bind(wallet_id.expose_uuid())
            .bind(received_note_id)
            .bind(spending_tx_id)
            .execute(pool)
            .await?;
    }

    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn put_received_transparent_utxo<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    output: &WalletTransparentOutput,
) -> Result<UtxoId, SqlxClientError> {
    use common::height_to_i64;
    use zcash_client_backend::encoding::AddressCodec;

    let addr_str = output.recipient_address().encode(params);

    // Look up the address to find the account and verify we own this address
    let address_info: Option<(i64, i64)> = sqlx_core::query_as::query_as(
        "SELECT account_id, id FROM addresses
         WHERE wallet_id = $1 AND cached_transparent_receiver_address = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(&addr_str)
    .fetch_optional(pool)
    .await?;

    let (account_id, address_id) = address_info.ok_or_else(|| {
        SqlxClientError::Encoding(format!("Address not recognized: {}", addr_str))
    })?;

    let output_height = output.mined_height().map(height_to_i64);

    // Get the chain tip height for observation_height
    let chain_tip: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    let observation_height = match chain_tip {
        Some((Some(h),)) => h,
        _ => output_height.unwrap_or(0),
    };

    // Get or create transaction record
    let txid_bytes = output.outpoint().hash().to_vec();
    let tx_id: i64 = sqlx_core::query_scalar::query_scalar(
        r#"
        INSERT INTO transactions (wallet_id, txid, mined_height, min_observed_height)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (wallet_id, txid) DO UPDATE
        SET mined_height = COALESCE(transactions.mined_height, EXCLUDED.mined_height),
            min_observed_height = LEAST(transactions.min_observed_height, EXCLUDED.min_observed_height)
        RETURNING id
        "#
    )
    .bind(wallet_id.expose_uuid())
    .bind(&txid_bytes)
    .bind(output_height)
    .bind(output_height.map_or(observation_height, |h| std::cmp::min(h, observation_height)))
    .fetch_one(pool)
    .await?;

    // Insert or update the transparent received output
    let value_zat = output.value().into_u64() as i64;
    let script_bytes = output.txout().script_pubkey().0.0.clone();
    let output_index = output.outpoint().n() as i32;

    let utxo_id: i64 = sqlx_core::query_scalar::query_scalar(
        r#"
        INSERT INTO transparent_received_outputs (
            wallet_id, tx_id, account_id, address_id, output_index, address, script, value_zat,
            max_observed_unspent_height
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (wallet_id, tx_id, output_index) DO UPDATE
        SET max_observed_unspent_height = GREATEST(
            transparent_received_outputs.max_observed_unspent_height,
            EXCLUDED.max_observed_unspent_height
        )
        RETURNING id
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(tx_id)
    .bind(account_id)
    .bind(address_id)
    .bind(output_index)
    .bind(&addr_str)
    .bind(&script_bytes)
    .bind(value_zat)
    .bind(observation_height) // max_observed_unspent_height
    .fetch_one(pool)
    .await?;

    Ok(UtxoId(utxo_id))
}

/// Determines the fee paid by a transaction by looking up transparent input values.
#[cfg(feature = "postgres")]
async fn determine_fee(
    pool: &Pool,
    wallet_id: WalletId,
    tx: &zcash_primitives::transaction::Transaction,
) -> Result<Option<zcash_protocol::value::Zatoshis>, SqlxClientError> {
    use zcash_protocol::value::Zatoshis;

    // Use the transaction's fee_paid method with a closure that looks up transparent inputs
    let transparent_bundle = tx.transparent_bundle();

    // Collect the outpoints we need to look up
    let outpoints: Vec<_> = transparent_bundle
        .map(|b| b.vin.iter().map(|input| input.prevout()).collect())
        .unwrap_or_default();

    // Look up each transparent input value
    let mut input_values = Vec::new();
    for outpoint in &outpoints {
        let txid_bytes = outpoint.hash().to_vec();
        let output_index = outpoint.n() as i32;

        let value_row: Option<(i64,)> = sqlx_core::query_as::query_as(
            r#"
            SELECT value_zat
            FROM transparent_received_outputs tro
            JOIN transactions t ON t.id = tro.tx_id
            WHERE t.wallet_id = $1 AND t.txid = $2 AND tro.output_index = $3
            "#,
        )
        .bind(wallet_id.expose_uuid())
        .bind(&txid_bytes)
        .bind(output_index)
        .fetch_optional(pool)
        .await?;

        match value_row {
            Some((value,)) => {
                input_values.push(Zatoshis::from_nonnegative_i64(value).map_err(|_| {
                    SqlxClientError::Encoding(format!("Invalid UTXO value: {}", value))
                })?);
            }
            None => {
                // Can't compute fee without all input values
                return Ok(None);
            }
        }
    }

    // Now compute the fee using the transaction's method
    tx.fee_paid(|outpoint| {
        // Find the value for this outpoint in our collected values
        let idx = outpoints.iter().position(|o| *o == outpoint);
        match idx {
            Some(i) => Ok(Some(input_values[i])),
            None => Ok(None),
        }
    })
}

#[cfg(feature = "postgres")]
pub async fn store_decrypted_tx<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    received_tx: DecryptedTransaction<'_, AccountUuid>,
) -> Result<(), SqlxClientError> {
    use common::height_to_i64;
    use zcash_client_backend::TransferType;

    let tx = received_tx.tx();
    let txid = tx.txid();
    let mined_height = received_tx.mined_height();

    // If there are no decrypted outputs, nothing to store
    if !received_tx.has_decrypted_outputs() {
        return Ok(());
    }

    // Get a height for min_observed_height. Use mined_height if available,
    // otherwise use the chain tip.
    let observed_height = match mined_height {
        Some(h) => height_to_i64(h),
        None => {
            // Get chain tip as fallback
            let tip_row: Option<(Option<i64>,)> =
                sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
                    .fetch_optional(pool)
                    .await?;
            match tip_row {
                Some((Some(h),)) => h,
                _ => return Err(SqlxClientError::ChainHeightUnavailable),
            }
        }
    };

    // Compute the fee by looking up transparent input values
    let fee = determine_fee(pool, wallet_id, tx).await?;
    let fee_i64 = fee.map(|z| z.into_u64() as i64);

    // Detect coinbase transactions - they have tx_index = 0
    let tx_index = tx
        .transparent_bundle()
        .and_then(|bundle| bundle.is_coinbase().then_some(0i64));

    // Insert or update the transaction record
    let tx_query = r#"
        INSERT INTO transactions (wallet_id, txid, mined_height, tx_index, min_observed_height, fee)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (wallet_id, txid) DO UPDATE SET
            mined_height = COALESCE(EXCLUDED.mined_height, transactions.mined_height),
            tx_index = COALESCE(EXCLUDED.tx_index, transactions.tx_index),
            min_observed_height = LEAST(transactions.min_observed_height, EXCLUDED.min_observed_height),
            fee = COALESCE(EXCLUDED.fee, transactions.fee)
        RETURNING id
    "#;

    let mined_height_i64 = mined_height.map(height_to_i64);
    let tx_ref: (i64,) = sqlx_core::query_as::query_as(tx_query)
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .bind(mined_height_i64)
        .bind(tx_index)
        .bind(observed_height)
        .bind(fee_i64)
        .fetch_one(pool)
        .await?;

    let tx_id = tx_ref.0;

    // Process Sapling outputs
    for output in received_tx.sapling_outputs() {
        match output.transfer_type() {
            TransferType::Incoming | TransferType::WalletInternal => {
                // Store received note
                put_decrypted_sapling_note(pool, params, wallet_id, tx_id, output, mined_height)
                    .await?;
            }
            TransferType::Outgoing => {
                // Outgoing notes are tracked in sent_notes table
                use zcash_keys::address::Receiver;

                let receiver = Receiver::Sapling(output.note().recipient());
                let recipient_address =
                    select_receiving_address(pool, params, wallet_id, *output.account(), &receiver)
                        .await?
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|| {
                            receiver.to_zcash_address(params.network_type()).to_string()
                        });

                put_sent_output(
                    pool,
                    wallet_id,
                    *output.account(),
                    tx_id,
                    output.index(),
                    &recipient_address,
                    common::pool_code::SAPLING,
                    output.note_value().into_u64() as i64,
                    Some(output.memo().as_slice()),
                )
                .await?;
            }
        }
    }

    // Process Orchard outputs
    #[cfg(feature = "orchard")]
    for output in received_tx.orchard_outputs() {
        match output.transfer_type() {
            TransferType::Incoming | TransferType::WalletInternal => {
                // Store received note
                put_decrypted_orchard_note(pool, params, wallet_id, tx_id, output, mined_height)
                    .await?;
            }
            TransferType::Outgoing => {
                // Outgoing notes are tracked in sent_notes table
                use zcash_keys::address::Receiver;

                let receiver = Receiver::Orchard(output.note().recipient());
                let recipient_address =
                    select_receiving_address(pool, params, wallet_id, *output.account(), &receiver)
                        .await?
                        .map(|addr| addr.to_string())
                        .unwrap_or_else(|| {
                            receiver.to_zcash_address(params.network_type()).to_string()
                        });

                put_sent_output(
                    pool,
                    wallet_id,
                    *output.account(),
                    tx_id,
                    output.index(),
                    &recipient_address,
                    common::pool_code::ORCHARD,
                    output.note().value().inner() as i64,
                    Some(output.memo().as_slice()),
                )
                .await?;
            }
        }
    }

    // Queue transparent inputs for enhancement
    // This allows the wallet to request full transaction data for inputs
    #[cfg(feature = "transparent-inputs")]
    if let Some(bundle) = tx.transparent_bundle() {
        if !bundle.is_coinbase() {
            for txin in bundle.vin.iter() {
                let prevout_txid = txin.prevout().txid();
                queue_tx_retrieval(pool, wallet_id, prevout_txid, Some(tx_id)).await?;
            }
        }
    }

    // For each transaction that spends a transparent output of this transaction and does not
    // already have a known fee value, update the fee if we can now compute it.
    #[cfg(feature = "transparent-inputs")]
    {
        use zcash_protocol::consensus::BranchId;

        // Find transactions that spend transparent outputs of the current transaction
        let spending_txs: Vec<SpendingTxRow> = sqlx_core::query_as::query_as(
            r#"
            SELECT DISTINCT t.id, t.raw, t.mined_height, t.expiry_height
            FROM transactions t
            JOIN transparent_received_output_spends ts ON ts.transaction_id = t.id
            JOIN transparent_received_outputs tro ON tro.id = ts.transparent_received_output_id
            WHERE tro.tx_id = $1
              AND tro.wallet_id = $2
              AND t.wallet_id = $2
              AND t.fee IS NULL
              AND t.raw IS NOT NULL
            "#,
        )
        .bind(tx_id)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

        for row in spending_txs {
            // Parse the transaction
            let branch_id = row
                .mined_height
                .and_then(|h| common::i64_to_height(h).ok())
                .map(|h| BranchId::for_height(params, h))
                .unwrap_or(BranchId::Nu5);

            let spending_tx =
                match zcash_primitives::transaction::Transaction::read(&row.raw[..], branch_id) {
                    Ok(tx) => tx,
                    Err(_) => continue, // Skip if we can't parse it
                };

            // Try to compute the fee
            if let Some(new_fee) = determine_fee(pool, wallet_id, &spending_tx).await? {
                sqlx_core::query::query("UPDATE transactions SET fee = $1 WHERE id = $2")
                    .bind(new_fee.into_u64() as i64)
                    .bind(row.tx_id)
                    .execute(pool)
                    .await?;
            }
        }
    }

    Ok(())
}

/// Queues a transaction for retrieval (status or enhancement).
/// If the transaction already has raw data, it queues for status; otherwise for enhancement.
#[cfg(all(feature = "postgres", feature = "transparent-inputs"))]
async fn queue_tx_retrieval(
    pool: &Pool,
    wallet_id: WalletId,
    txid: &TxId,
    dependent_tx_id: Option<i64>,
) -> Result<(), SqlxClientError> {
    // Check if we already have the raw transaction data
    let has_raw: Option<(bool,)> = sqlx_core::query_as::query_as(
        "SELECT raw IS NOT NULL FROM transactions WHERE wallet_id = $1 AND txid = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(txid.as_ref())
    .fetch_optional(pool)
    .await?;

    // Determine query type: 0 = Status, 1 = Enhancement
    let query_type: i32 = match has_raw {
        Some((true,)) => 0, // Has raw data, just need status
        _ => 1,             // Need enhancement (full tx data)
    };

    // Insert into queue, update if exists
    // Note: column is 'dependent_transaction_id' in init/mod.rs
    let query = r#"
        INSERT INTO tx_retrieval_queue (wallet_id, txid, query_type, dependent_transaction_id)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (wallet_id, txid) DO UPDATE SET
            query_type = LEAST(EXCLUDED.query_type, tx_retrieval_queue.query_type),
            dependent_transaction_id = COALESCE(EXCLUDED.dependent_transaction_id, tx_retrieval_queue.dependent_transaction_id)
    "#;

    sqlx_core::query::query(query)
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .bind(query_type)
        .bind(dependent_tx_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Inserts a decrypted Sapling note into the database.
/// This is used for notes from DecryptedTransaction which may not have tree positions.
#[cfg(feature = "postgres")]
async fn put_decrypted_sapling_note<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
    tx_id: i64,
    output: &zcash_client_backend::DecryptedOutput<sapling::Note, AccountUuid>,
    _mined_height: Option<BlockHeight>,
) -> Result<(), SqlxClientError> {
    use group::ff::PrimeField;
    use zcash_client_backend::TransferType;

    // Get the account's internal ID
    let account_query =
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL";
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(account_query)
        .bind(wallet_id.expose_uuid())
        .bind(output.account().expose_uuid())
        .fetch_optional(pool)
        .await?;

    let account_id = match account_row {
        Some((id,)) => id,
        None => return Ok(()), // Unknown account, skip
    };

    let note = output.note();
    let recipient = note.recipient();
    let diversifier = recipient.diversifier();
    let diversifier_bytes = diversifier.0.to_vec();
    let value = note.value().inner() as i64;
    let rcm = note.rcm().to_repr();
    let rcm_bytes = rcm.as_slice().to_vec();
    let is_change = output.transfer_type() == TransferType::WalletInternal;
    let memo_bytes = output.memo().as_slice().to_vec();

    // DecryptedOutput doesn't have nullifier or tree position
    let scope = match output.transfer_type() {
        TransferType::WalletInternal => Some(1i64), // Internal scope
        TransferType::Incoming => Some(0i64),       // External scope
        TransferType::Outgoing => None,
    };

    let query = r#"
        INSERT INTO sapling_received_notes (
            wallet_id, tx_id, output_index, account_id,
            diversifier, value, rcm, memo, nf, is_change,
            commitment_tree_position, recipient_key_scope
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (wallet_id, tx_id, output_index) DO UPDATE SET
            account_id = EXCLUDED.account_id,
            diversifier = EXCLUDED.diversifier,
            value = EXCLUDED.value,
            rcm = EXCLUDED.rcm,
            memo = COALESCE(EXCLUDED.memo, sapling_received_notes.memo),
            nf = COALESCE(EXCLUDED.nf, sapling_received_notes.nf),
            is_change = GREATEST(EXCLUDED.is_change::int, sapling_received_notes.is_change::int)::bool,
            commitment_tree_position = COALESCE(EXCLUDED.commitment_tree_position, sapling_received_notes.commitment_tree_position),
            recipient_key_scope = COALESCE(EXCLUDED.recipient_key_scope, sapling_received_notes.recipient_key_scope)
    "#;

    sqlx_core::query::query(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_id)
        .bind(output.index() as i32)
        .bind(account_id)
        .bind(diversifier_bytes)
        .bind(value)
        .bind(rcm_bytes)
        .bind(Some(memo_bytes))
        .bind(None::<Vec<u8>>) // nf - not available from DecryptedOutput
        .bind(is_change)
        .bind(None::<i64>) // commitment_tree_position - not available from DecryptedOutput
        .bind(scope)
        .execute(pool)
        .await?;

    Ok(())
}

/// Inserts a decrypted Orchard note into the database.
/// This is used for notes from DecryptedTransaction which may not have tree positions.
#[cfg(all(feature = "postgres", feature = "orchard"))]
async fn put_decrypted_orchard_note<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
    tx_id: i64,
    output: &zcash_client_backend::DecryptedOutput<orchard::note::Note, AccountUuid>,
    _mined_height: Option<BlockHeight>,
) -> Result<(), SqlxClientError> {
    use zcash_client_backend::TransferType;

    // Get the account's internal ID
    let account_query =
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL";
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(account_query)
        .bind(wallet_id.expose_uuid())
        .bind(output.account().expose_uuid())
        .fetch_optional(pool)
        .await?;

    let account_id = match account_row {
        Some((id,)) => id,
        None => return Ok(()), // Unknown account, skip
    };

    let note = output.note();
    let recipient = note.recipient();
    let diversifier = recipient.diversifier();
    let diversifier_bytes = diversifier.as_array().to_vec();
    let value = note.value().inner() as i64;
    let rho = note.rho().to_bytes();
    let rho_bytes = rho.to_vec();
    let rseed = *note.rseed().as_bytes();
    let rseed_bytes = rseed.to_vec();
    let is_change = output.transfer_type() == TransferType::WalletInternal;
    let memo_bytes = output.memo().as_slice().to_vec();

    // DecryptedOutput doesn't have nullifier or tree position
    let scope = match output.transfer_type() {
        TransferType::WalletInternal => Some(1i64), // Internal scope
        TransferType::Incoming => Some(0i64),       // External scope
        TransferType::Outgoing => None,
    };

    let query = r#"
        INSERT INTO orchard_received_notes (
            wallet_id, tx_id, action_index, account_id,
            diversifier, value, rho, rseed, memo, nf, is_change,
            commitment_tree_position, recipient_key_scope
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
        ON CONFLICT (wallet_id, tx_id, action_index) DO UPDATE SET
            account_id = EXCLUDED.account_id,
            diversifier = EXCLUDED.diversifier,
            value = EXCLUDED.value,
            rho = EXCLUDED.rho,
            rseed = EXCLUDED.rseed,
            memo = COALESCE(EXCLUDED.memo, orchard_received_notes.memo),
            nf = COALESCE(EXCLUDED.nf, orchard_received_notes.nf),
            is_change = GREATEST(EXCLUDED.is_change::int, orchard_received_notes.is_change::int)::bool,
            commitment_tree_position = COALESCE(EXCLUDED.commitment_tree_position, orchard_received_notes.commitment_tree_position),
            recipient_key_scope = COALESCE(EXCLUDED.recipient_key_scope, orchard_received_notes.recipient_key_scope)
    "#;

    sqlx_core::query::query(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_id)
        .bind(output.index() as i32)
        .bind(account_id)
        .bind(diversifier_bytes)
        .bind(value)
        .bind(rho_bytes)
        .bind(rseed_bytes)
        .bind(Some(memo_bytes))
        .bind(None::<Vec<u8>>) // nf - not available from DecryptedOutput
        .bind(is_change)
        .bind(None::<i64>) // commitment_tree_position - not available from DecryptedOutput
        .bind(scope)
        .execute(pool)
        .await?;

    Ok(())
}

/// Looks up a known receiving address that corresponds to the given receiver.
/// Returns `None` if no matching address is found in the wallet.
#[cfg(feature = "postgres")]
async fn select_receiving_address<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    receiver: &zcash_keys::address::Receiver,
) -> Result<Option<zcash_address::ZcashAddress>, SqlxClientError> {
    use zcash_keys::address::Receiver;

    match receiver {
        #[cfg(feature = "transparent-inputs")]
        Receiver::Transparent(taddr) => {
            use zcash_keys::address::Address;

            let taddr_str = Address::Transparent(*taddr).encode(params);
            let row: Option<(String,)> = sqlx_core::query_as::query_as(
                "SELECT address FROM addresses WHERE wallet_id = $1 AND cached_transparent_receiver_address = $2"
            )
            .bind(wallet_id.expose_uuid())
            .bind(&taddr_str)
            .fetch_optional(pool)
            .await?;

            if let Some((addr_str,)) = row {
                let parsed = addr_str
                    .parse::<zcash_address::ZcashAddress>()
                    .map_err(|e| SqlxClientError::Encoding(format!("Invalid address: {}", e)))?;
                Ok(Some(parsed))
            } else {
                Ok(None)
            }
        }
        receiver => {
            // For Sapling/Orchard receivers, check if any external address for this account
            // corresponds to this receiver
            let rows: Vec<(String,)> = sqlx_core::query_as::query_as(
                r#"
                SELECT address FROM addresses
                JOIN accounts ON accounts.id = addresses.account_id
                WHERE addresses.wallet_id = $1
                  AND accounts.uuid = $2
                  AND key_scope = 0
                "#,
            )
            .bind(wallet_id.expose_uuid())
            .bind(account.expose_uuid())
            .fetch_all(pool)
            .await?;

            for (addr_str,) in rows {
                let decoded = addr_str
                    .parse::<zcash_address::ZcashAddress>()
                    .map_err(|e| SqlxClientError::Encoding(format!("Invalid address: {}", e)))?;
                if receiver.corresponds(&decoded) {
                    return Ok(Some(decoded));
                }
            }

            Ok(None)
        }
    }
}

/// Stores a sent output in the sent_notes table.
/// This is used to track outputs sent to external recipients or internal change.
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
async fn put_sent_output(
    pool: &Pool,
    wallet_id: WalletId,
    from_account: AccountUuid,
    tx_id: i64,
    output_index: usize,
    recipient_address: &str,
    pool_code: i32,
    value: i64,
    memo: Option<&[u8]>,
) -> Result<(), SqlxClientError> {
    // Get from_account's internal ID
    let from_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(from_account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let from_account_id = match from_row {
        Some((id,)) => id,
        None => return Ok(()), // Unknown account, skip
    };

    let query = r#"
        INSERT INTO sent_notes (wallet_id, tx_id, output_pool, output_index,
            from_account_id, to_address, to_account_id, value, memo)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (wallet_id, tx_id, output_pool, output_index) DO UPDATE SET
            from_account_id = EXCLUDED.from_account_id,
            to_address = COALESCE(EXCLUDED.to_address, sent_notes.to_address),
            to_account_id = COALESCE(EXCLUDED.to_account_id, sent_notes.to_account_id),
            value = EXCLUDED.value,
            memo = COALESCE(EXCLUDED.memo, sent_notes.memo)
    "#;

    sqlx_core::query::query(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_id)
        .bind(pool_code)
        .bind(output_index as i32)
        .bind(from_account_id)
        .bind(Some(recipient_address))
        .bind(None::<i64>) // to_account_id - external recipient
        .bind(value)
        .bind(memo)
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn set_tx_trust(
    pool: &Pool,
    wallet_id: WalletId,
    txid: TxId,
    trusted: bool,
) -> Result<(), SqlxClientError> {
    // trust_status: 0 = untrusted, 1 = trusted (matches SQLite's trust_status column)
    let trust_status: i32 = if trusted { 1 } else { 0 };
    sqlx_core::query::query(
        "UPDATE transactions SET trust_status = $1 WHERE wallet_id = $2 AND txid = $3",
    )
    .bind(trust_status)
    .bind(wallet_id.expose_uuid())
    .bind(txid.as_ref())
    .execute(pool)
    .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn store_transactions_to_be_sent<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    transactions: &[SentTransaction<'_, AccountUuid>],
) -> Result<(), SqlxClientError> {
    use common::height_to_i64;
    use zcash_client_backend::{
        DecryptedOutput, TransferType,
        encoding::AddressCodec,
        wallet::{Note, Recipient},
    };
    use zcash_protocol::memo::MemoBytes;

    for sent_tx in transactions {
        let tx = sent_tx.tx();
        let txid = tx.txid();
        let target_height = sent_tx.target_height();
        let target_height_i64 = height_to_i64(target_height.into());
        let fee = sent_tx.fee_amount().into_u64() as i64;
        let expiry_height = i64::from(u32::from(tx.expiry_height()));

        // Serialize the transaction
        let mut raw_tx = vec![];
        tx.write(&mut raw_tx).map_err(|e| {
            SqlxClientError::Encoding(format!("Failed to serialize transaction: {}", e))
        })?;

        // Insert or update transaction record
        let tx_query = r#"
            INSERT INTO transactions (wallet_id, txid, fee, created, expiry_height, raw, target_height, min_observed_height)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
            ON CONFLICT (wallet_id, txid) DO UPDATE SET
                fee = COALESCE(EXCLUDED.fee, transactions.fee),
                created = COALESCE(EXCLUDED.created, transactions.created),
                expiry_height = COALESCE(EXCLUDED.expiry_height, transactions.expiry_height),
                raw = COALESCE(EXCLUDED.raw, transactions.raw),
                target_height = COALESCE(EXCLUDED.target_height, transactions.target_height),
                min_observed_height = LEAST(transactions.min_observed_height, EXCLUDED.min_observed_height)
            RETURNING id
        "#;

        // Convert time::OffsetDateTime to chrono::DateTime<Utc>
        let created = sent_tx.created();
        let created_at =
            chrono::DateTime::from_timestamp(created.unix_timestamp(), created.nanosecond())
                .unwrap_or_else(chrono::Utc::now);
        let tx_ref: (i64,) = sqlx_core::query_as::query_as(tx_query)
            .bind(wallet_id.expose_uuid())
            .bind(txid.as_ref())
            .bind(fee)
            .bind(created_at)
            .bind(expiry_height)
            .bind(&raw_tx)
            .bind(target_height_i64)
            .fetch_one(pool)
            .await?;

        let tx_id = tx_ref.0;

        // Mark Sapling notes as spent by nullifiers
        if let Some(bundle) = tx.sapling_bundle() {
            for spend in bundle.shielded_spends() {
                let nf = spend.nullifier().0.to_vec();
                let mark_spent_query = r#"
                    INSERT INTO sapling_received_note_spends (wallet_id, sapling_received_note_id, transaction_id)
                    SELECT $1, rn.id, $2
                    FROM sapling_received_notes rn
                    WHERE rn.wallet_id = $1 AND rn.nf = $3
                    ON CONFLICT (wallet_id, sapling_received_note_id, transaction_id) DO NOTHING
                "#;
                sqlx_core::query::query(mark_spent_query)
                    .bind(wallet_id.expose_uuid())
                    .bind(tx_id)
                    .bind(&nf)
                    .execute(pool)
                    .await?;
            }
        }

        // Mark Orchard notes as spent by nullifiers
        #[cfg(feature = "orchard")]
        if let Some(bundle) = tx.orchard_bundle() {
            for action in bundle.actions() {
                let nf = action.nullifier().to_bytes().to_vec();
                let mark_spent_query = r#"
                    INSERT INTO orchard_received_note_spends (wallet_id, orchard_received_note_id, transaction_id)
                    SELECT $1, rn.id, $2
                    FROM orchard_received_notes rn
                    WHERE rn.wallet_id = $1 AND rn.nf = $3
                    ON CONFLICT (wallet_id, orchard_received_note_id, transaction_id) DO NOTHING
                "#;
                sqlx_core::query::query(mark_spent_query)
                    .bind(wallet_id.expose_uuid())
                    .bind(tx_id)
                    .bind(&nf)
                    .execute(pool)
                    .await?;
            }
        }

        // Mark transparent UTXOs as spent
        #[cfg(feature = "transparent-inputs")]
        for utxo_outpoint in sent_tx.utxos_spent() {
            transparent::mark_transparent_utxo_spent(pool, wallet_id, tx_id, utxo_outpoint).await?;
        }

        // Store sent outputs
        for output in sent_tx.outputs() {
            // Get from account internal ID
            let from_account = sent_tx.account_id();
            let from_account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
                "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
            )
            .bind(wallet_id.expose_uuid())
            .bind(from_account.expose_uuid())
            .fetch_optional(pool)
            .await?;

            let from_account_id = match from_account_row {
                Some((id,)) => id,
                None => continue, // Unknown account, skip
            };

            let output_index = output.output_index() as i32;
            let value = output.value().into_u64() as i64;
            let memo = output.memo().map(|m| m.as_slice().to_vec());

            // Determine recipient information
            let (to_address, to_account_id, output_pool): (Option<String>, Option<i64>, i32) =
                match output.recipient() {
                    Recipient::External {
                        recipient_address,
                        output_pool,
                    } => {
                        let pool_code = match output_pool {
                            zcash_protocol::PoolType::Transparent => 0,
                            zcash_protocol::PoolType::Shielded(ShieldedProtocol::Sapling) => 2,
                            zcash_protocol::PoolType::Shielded(ShieldedProtocol::Orchard) => 3,
                        };

                        // For transparent outputs, check if the address belongs to the wallet
                        // and record the transparent output if so (for gap limit management)
                        #[cfg(feature = "transparent-inputs")]
                        if output_pool == &zcash_protocol::PoolType::Transparent {
                            use ::transparent::address::TransparentAddress;
                            use ::transparent::keys::NonHardenedChildIndex;
                            use zcash_client_backend::encoding::AddressCodec;
                            use zcash_script::script::Evaluable;

                            // Parse the recipient address as a transparent address
                            let addr_str = recipient_address.encode();
                            if let Ok(taddr) = TransparentAddress::decode(params, &addr_str) {
                                if let Ok(Some((_, account_id, _))) =
                                    transparent::find_account_for_transparent_address(
                                        pool, params, wallet_id, &taddr,
                                    )
                                    .await
                                {
                                    // This is a transparent output to a wallet address
                                    // Record it in transparent_received_outputs
                                    let script_bytes = taddr.script().to_bytes();
                                    let taddr_encoded = taddr.encode(params);

                                    // First try to find the address_id from the addresses table
                                    let address_row: Option<(i64,)> =
                                        sqlx_core::query_as::query_as(
                                            r#"
                                        SELECT id FROM addresses
                                        WHERE wallet_id = $1
                                          AND cached_transparent_receiver_address = $2
                                        "#,
                                        )
                                        .bind(wallet_id.expose_uuid())
                                        .bind(&taddr_encoded)
                                        .fetch_optional(pool)
                                        .await?;

                                    let address_id = match address_row {
                                        Some((id,)) => id,
                                        None => {
                                            // The address isn't in the addresses table (legacy transparent
                                            // address derived from UIVK). We need to insert it.
                                            // Use index 0 for the legacy address, with EXTERNAL key scope.
                                            let di_bytes = NonHardenedChildIndex::ZERO
                                                .index()
                                                .to_be_bytes()
                                                .to_vec();
                                            let inserted_id: (i64,) = sqlx_core::query_as::query_as(
                                                r#"
                                                INSERT INTO addresses (
                                                    wallet_id, account_id, key_scope, address,
                                                    transparent_child_index, cached_transparent_receiver_address,
                                                    receiver_flags, diversifier_index_be
                                                )
                                                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                                                ON CONFLICT (wallet_id, account_id, key_scope, diversifier_index_be)
                                                DO UPDATE SET cached_transparent_receiver_address = EXCLUDED.cached_transparent_receiver_address
                                                RETURNING id
                                                "#,
                                            )
                                            .bind(wallet_id.expose_uuid())
                                            .bind(account_id)
                                            .bind(0i32) // External key scope
                                            .bind(&taddr_encoded) // Use transparent address as the address column
                                            .bind(0i32) // Index 0 for legacy address
                                            .bind(&taddr_encoded)
                                            .bind(1i32) // P2PKH receiver flag
                                            .bind(di_bytes)
                                            .fetch_one(pool)
                                            .await?;
                                            inserted_id.0
                                        }
                                    };

                                    // Insert the transparent received output
                                    sqlx_core::query::query(
                                        r#"
                                        INSERT INTO transparent_received_outputs
                                            (wallet_id, tx_id, output_index, account_id, address_id, address, script, value_zat)
                                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                                        ON CONFLICT (wallet_id, tx_id, output_index) DO UPDATE
                                            SET account_id = EXCLUDED.account_id,
                                                address_id = EXCLUDED.address_id,
                                                address = EXCLUDED.address,
                                                script = EXCLUDED.script,
                                                value_zat = EXCLUDED.value_zat
                                        "#,
                                    )
                                    .bind(wallet_id.expose_uuid())
                                    .bind(tx_id)
                                    .bind(output.output_index() as i32)
                                    .bind(account_id)
                                    .bind(address_id)
                                    .bind(&taddr_encoded)
                                    .bind(script_bytes)
                                    .bind(output.value().into_u64() as i64)
                                    .execute(pool)
                                    .await?;
                                }
                            }
                        }

                        (Some(recipient_address.encode()), None, pool_code)
                    }
                    Recipient::InternalAccount {
                        receiving_account,
                        note,
                        ..
                    } => {
                        // Get receiving account's internal ID
                        let to_row: Option<(i64,)> = sqlx_core::query_as::query_as(
                            "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL"
                        )
                        .bind(wallet_id.expose_uuid())
                        .bind(receiving_account.expose_uuid())
                        .fetch_optional(pool)
                        .await?;

                        let pool_code = match note.as_ref() {
                            Note::Sapling(_) => 2,
                            #[cfg(feature = "orchard")]
                            Note::Orchard(_) => 3,
                        };

                        // Store the received note for internal transfers
                        match note.as_ref() {
                            Note::Sapling(sapling_note) => {
                                put_decrypted_sapling_note(
                                    pool,
                                    params,
                                    wallet_id,
                                    tx_id,
                                    &DecryptedOutput::new(
                                        output.output_index(),
                                        sapling_note.clone(),
                                        *receiving_account,
                                        memo.as_ref()
                                            .map(|m| {
                                                MemoBytes::from_bytes(m)
                                                    .unwrap_or_else(|_| MemoBytes::empty())
                                            })
                                            .unwrap_or_else(MemoBytes::empty),
                                        TransferType::WalletInternal,
                                    ),
                                    Some(target_height.into()),
                                )
                                .await?;
                            }
                            #[cfg(feature = "orchard")]
                            Note::Orchard(orchard_note) => {
                                put_decrypted_orchard_note(
                                    pool,
                                    params,
                                    wallet_id,
                                    tx_id,
                                    &DecryptedOutput::new(
                                        output.output_index(),
                                        *orchard_note,
                                        *receiving_account,
                                        memo.as_ref()
                                            .map(|m| {
                                                MemoBytes::from_bytes(m)
                                                    .unwrap_or_else(|_| MemoBytes::empty())
                                            })
                                            .unwrap_or_else(MemoBytes::empty),
                                        TransferType::WalletInternal,
                                    ),
                                    Some(target_height.into()),
                                )
                                .await?;
                            }
                        }

                        (None, to_row.map(|(id,)| id), pool_code)
                    }
                    #[cfg(feature = "transparent-inputs")]
                    Recipient::EphemeralTransparent {
                        receiving_account,
                        ephemeral_address,
                        outpoint,
                    } => {
                        // Insert a transparent_received_output entry for the ephemeral address.
                        // This marks the ephemeral address as "used".
                        transparent::put_transparent_output_for_ephemeral(
                            pool,
                            params,
                            wallet_id,
                            ephemeral_address,
                            outpoint,
                            output.value(),
                            target_height.into(),
                        )
                        .await?;

                        // Get receiving account's internal ID for to_account_id
                        let to_row: Option<(i64,)> = sqlx_core::query_as::query_as(
                            "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL"
                        )
                        .bind(wallet_id.expose_uuid())
                        .bind(receiving_account.expose_uuid())
                        .fetch_optional(pool)
                        .await?;

                        // Transparent pool code is 0
                        (
                            Some(ephemeral_address.encode(params)),
                            to_row.map(|(id,)| id),
                            0,
                        )
                    }
                };

            // Insert sent note record
            let sent_query = r#"
                INSERT INTO sent_notes (wallet_id, tx_id, output_pool, output_index,
                    from_account_id, to_address, to_account_id, value, memo)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (wallet_id, tx_id, output_pool, output_index) DO UPDATE SET
                    from_account_id = EXCLUDED.from_account_id,
                    to_address = EXCLUDED.to_address,
                    to_account_id = EXCLUDED.to_account_id,
                    value = EXCLUDED.value,
                    memo = COALESCE(EXCLUDED.memo, sent_notes.memo)
            "#;

            sqlx_core::query::query(sent_query)
                .bind(wallet_id.expose_uuid())
                .bind(tx_id)
                .bind(output_pool)
                .bind(output_index)
                .bind(from_account_id)
                .bind(to_address)
                .bind(to_account_id)
                .bind(value)
                .bind(memo)
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

#[cfg(feature = "postgres")]
pub async fn truncate_to_height(
    pool: &Pool,
    wallet_id: WalletId,
    max_height: BlockHeight,
) -> Result<BlockHeight, SqlxClientError> {
    use crate::wallet::common::height_to_i64;

    let max_height_i64 = height_to_i64(max_height);

    // Delete blocks above the truncation height (global table)
    // This affects all wallets since blockchain data is shared
    sqlx_core::query::query("DELETE FROM blocks WHERE height > $1")
        .bind(max_height_i64)
        .execute(pool)
        .await?;

    // Un-mine transactions that were mined above the truncation height (wallet-specific)
    sqlx_core::query::query(
        "UPDATE transactions SET mined_height = NULL WHERE wallet_id = $1 AND mined_height > $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(max_height_i64)
    .execute(pool)
    .await?;

    // Delete Sapling note spends from unmined transactions
    sqlx_core::query::query(
        r#"
        DELETE FROM sapling_received_note_spends
        WHERE wallet_id = $1
          AND transaction_id IN (
              SELECT id FROM transactions
              WHERE wallet_id = $1 AND mined_height IS NULL
          )
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .execute(pool)
    .await?;

    // Delete Orchard note spends from unmined transactions
    #[cfg(feature = "orchard")]
    sqlx_core::query::query(
        r#"
        DELETE FROM orchard_received_note_spends
        WHERE wallet_id = $1
          AND transaction_id IN (
              SELECT id FROM transactions
              WHERE wallet_id = $1 AND mined_height IS NULL
          )
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .execute(pool)
    .await?;

    // Delete transparent output spends from unmined transactions
    #[cfg(feature = "transparent-inputs")]
    sqlx_core::query::query(
        r#"
        DELETE FROM transparent_received_output_spends
        WHERE wallet_id = $1
          AND transaction_id IN (
              SELECT id FROM transactions
              WHERE wallet_id = $1 AND mined_height IS NULL
          )
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .execute(pool)
    .await?;

    // Update scan queue - remove any ranges that are entirely above the truncation height
    sqlx_core::query::query(
        "DELETE FROM scan_queue WHERE wallet_id = $1 AND block_range_start > $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(max_height_i64)
    .execute(pool)
    .await?;

    // Truncate scan queue ranges that span the truncation height
    sqlx_core::query::query(
        r#"
        UPDATE scan_queue
        SET block_range_end = $2 + 1
        WHERE wallet_id = $1
          AND block_range_start <= $2
          AND block_range_end > $2 + 1
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(max_height_i64)
    .execute(pool)
    .await?;

    // Delete Sapling tree checkpoints above the truncation height (global table)
    sqlx_core::query::query("DELETE FROM sapling_tree_checkpoints WHERE checkpoint_id > $1")
        .bind(max_height_i64)
        .execute(pool)
        .await?;

    // Delete Orchard tree checkpoints above the truncation height (global table)
    #[cfg(feature = "orchard")]
    sqlx_core::query::query("DELETE FROM orchard_tree_checkpoints WHERE checkpoint_id > $1")
        .bind(max_height_i64)
        .execute(pool)
        .await?;

    // Delete Sapling nullifier map entries above the truncation height (global table)
    sqlx_core::query::query("DELETE FROM sapling_nullifier_map WHERE block_height > $1")
        .bind(max_height_i64)
        .execute(pool)
        .await?;

    // Delete Orchard nullifier map entries above the truncation height (global table)
    #[cfg(feature = "orchard")]
    sqlx_core::query::query("DELETE FROM orchard_nullifier_map WHERE block_height > $1")
        .bind(max_height_i64)
        .execute(pool)
        .await?;

    // Return the actual height we truncated to (the max height in blocks table, or the requested height)
    // blocks table is now global
    let actual_height: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    match actual_height {
        Some((Some(h),)) => Ok(BlockHeight::from_u32(h as u32)),
        _ => Ok(max_height),
    }
}

#[cfg(feature = "postgres")]
pub async fn set_transaction_status<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    #[cfg(feature = "transparent-inputs")] gap_limits: &GapLimits,
    txid: TxId,
    status: TransactionStatus,
) -> Result<(), SqlxClientError> {
    use crate::wallet::common::height_to_i64;

    match status {
        TransactionStatus::Mined(height) => {
            // Mark transaction as mined at the given height
            sqlx_core::query::query(
                "UPDATE transactions SET mined_height = $1 WHERE wallet_id = $2 AND txid = $3",
            )
            .bind(height_to_i64(height))
            .bind(wallet_id.expose_uuid())
            .bind(txid.as_ref())
            .execute(pool)
            .await?;

            // Update gap limits for any transparent addresses used in this transaction
            #[cfg(feature = "transparent-inputs")]
            transparent::update_gap_limits(pool, params, wallet_id, gap_limits, txid, height)
                .await?;
        }
        TransactionStatus::NotInMainChain => {
            // Transaction was unmined (reorg) - clear the mined_height
            sqlx_core::query::query(
                "UPDATE transactions SET mined_height = NULL WHERE wallet_id = $1 AND txid = $2",
            )
            .bind(wallet_id.expose_uuid())
            .bind(txid.as_ref())
            .execute(pool)
            .await?;
        }
        TransactionStatus::TxidNotRecognized => {
            // Transaction is not recognized - update confirmed_unmined_at_height
            let chain_tip_row: Option<(Option<i64>,)> =
                sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
                    .fetch_optional(pool)
                    .await?;

            if let Some((Some(chain_tip),)) = chain_tip_row {
                sqlx_core::query::query(
                    "UPDATE transactions
                     SET confirmed_unmined_at_height = $1
                     WHERE wallet_id = $2 AND txid = $3 AND mined_height IS NULL",
                )
                .bind(chain_tip)
                .bind(wallet_id.expose_uuid())
                .bind(txid.as_ref())
                .execute(pool)
                .await?;
            }
        }
    }

    // Suppress unused parameter warning when transparent-inputs is disabled
    let _ = params;

    // Delete from tx_retrieval_queue for all status cases
    sqlx_core::query::query("DELETE FROM tx_retrieval_queue WHERE wallet_id = $1 AND txid = $2")
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .execute(pool)
        .await?;

    Ok(())
}
