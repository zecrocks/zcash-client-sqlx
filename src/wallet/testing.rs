//! Test utilities for the sqlx wallet backend.

use std::ops::Range;

use incrementalmerkletree::Position;
use transparent::keys::NonHardenedChildIndex;

use zcash_client_backend::{
    data_api::{OutputOfSentTx, testing::TransactionSummary},
    wallet::{Note, NoteId, ReceivedNote, WalletTransparentOutput},
};
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{BlockHeight, Parameters},
    value::{ZatBalance, Zatoshis},
};

#[cfg(feature = "transparent-inputs")]
use {
    transparent::address::TransparentAddress,
    transparent::bundle::OutPoint,
    zcash_client_backend::{data_api::wallet::TargetHeight, wallet::TransparentAddressMetadata},
};

#[cfg(feature = "postgres")]
use crate::pool::Pool;

#[cfg(feature = "transparent-inputs")]
use crate::GapLimits;
use crate::wallet::common::TableConstants;
use crate::{AccountUuid, ReceivedNoteId, SqlxClientError, WalletId};
use zcash_primitives::transaction::TxId;

/// Raw transaction history from database query.
///
/// This struct provides named fields instead of positional tuple access,
/// improving code clarity and reducing the risk of field order mistakes.
#[cfg(feature = "postgres")]
struct TransactionHistoryRow {
    account_uuid: uuid::Uuid,
    txid_bytes: Vec<u8>,
    expiry_height: Option<i64>,
    mined_height: Option<i64>,
    account_balance_delta: i64,
    total_spent: i64,
    total_received: i64,
    fee_paid: Option<i64>,
    spent_note_count: i64,
    has_change: bool,
    sent_note_count: i64,
    received_note_count: i64,
    memo_count: i64,
    expired_unmined: bool,
    is_shielding: bool,
}

#[cfg(feature = "postgres")]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for TransactionHistoryRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            account_uuid: row.try_get("account_uuid")?,
            txid_bytes: row.try_get("txid")?,
            expiry_height: row.try_get("expiry_height")?,
            mined_height: row.try_get("mined_height")?,
            account_balance_delta: row.try_get("account_balance_delta")?,
            total_spent: row.try_get("total_spent")?,
            total_received: row.try_get("total_received")?,
            fee_paid: row.try_get("fee_paid")?,
            spent_note_count: row.try_get("spent_note_count")?,
            has_change: row.try_get("has_change")?,
            sent_note_count: row.try_get("sent_note_count")?,
            received_note_count: row.try_get("received_note_count")?,
            memo_count: row.try_get("memo_count")?,
            expired_unmined: row.try_get("expired_unmined")?,
            is_shielding: row.try_get("is_shielding")?,
        })
    }
}

/// Raw sent output from database query.
#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
struct SentOutputRow {
    value: i64,
    to_address: Option<String>,
    ephemeral_address: Option<String>,
    address_index: Option<i32>,
}

#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for SentOutputRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            value: row.try_get("value")?,
            to_address: row.try_get("to_address")?,
            ephemeral_address: row.try_get("cached_transparent_receiver_address")?,
            address_index: row.try_get("transparent_child_index")?,
        })
    }
}

/// Raw ephemeral address from database query.
#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
struct EphemeralAddressRow {
    address: Option<String>,
    child_index: Option<i32>,
    exposed_at_height: Option<i64>,
    #[allow(dead_code)] // Present in query result, may be used in future
    next_check_time: Option<i64>,
}

#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for EphemeralAddressRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            address: row.try_get("cached_transparent_receiver_address")?,
            child_index: row.try_get("transparent_child_index")?,
            exposed_at_height: row.try_get("exposed_at_height")?,
            next_check_time: row.try_get("transparent_receiver_next_check_time")?,
        })
    }
}

#[cfg(feature = "postgres")]
pub async fn get_tx_history<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
) -> Result<Vec<TransactionSummary<AccountUuid>>, SqlxClientError> {
    // Query transaction data with aggregated note counts
    // This mirrors the SQLite v_transactions view logic:
    // - account_balance_delta = notes_received_in_tx - notes_spent_in_tx
    // - Only include account/transaction pairs where the account is actually involved
    // - Includes Sapling, Orchard, and transparent outputs
    let query = r#"
        WITH notes AS (
            -- Sapling notes received in transactions
            SELECT srn.account_id,
                   srn.tx_id AS transaction_id,
                   srn.value AS value,
                   srn.value AS received_value,
                   0::BIGINT AS spent_value,
                   0::BIGINT AS spent_note_count,
                   CASE WHEN srn.is_change THEN 1 ELSE 0 END AS change_note_count,
                   CASE WHEN srn.is_change THEN 0 ELSE 1 END AS received_count,
                   0::BIGINT AS does_not_match_shielding
            FROM sapling_received_notes srn
            WHERE srn.wallet_id = $1
            UNION ALL
            -- Sapling notes spent in transactions
            -- Spending shielded notes means it's NOT a shielding transaction
            SELECT srn.account_id,
                   srns.transaction_id AS transaction_id,
                   -srn.value AS value,
                   0::BIGINT AS received_value,
                   srn.value AS spent_value,
                   1::BIGINT AS spent_note_count,
                   0::BIGINT AS change_note_count,
                   0::BIGINT AS received_count,
                   1::BIGINT AS does_not_match_shielding
            FROM sapling_received_notes srn
            INNER JOIN sapling_received_note_spends srns ON srns.sapling_received_note_id = srn.id
            WHERE srn.wallet_id = $1
            UNION ALL
            -- Orchard notes received in transactions
            SELECT orn.account_id,
                   orn.tx_id AS transaction_id,
                   orn.value AS value,
                   orn.value AS received_value,
                   0::BIGINT AS spent_value,
                   0::BIGINT AS spent_note_count,
                   CASE WHEN orn.is_change THEN 1 ELSE 0 END AS change_note_count,
                   CASE WHEN orn.is_change THEN 0 ELSE 1 END AS received_count,
                   0::BIGINT AS does_not_match_shielding
            FROM orchard_received_notes orn
            WHERE orn.wallet_id = $1
            UNION ALL
            -- Orchard notes spent in transactions
            -- Spending shielded notes means it's NOT a shielding transaction
            SELECT orn.account_id,
                   orns.transaction_id AS transaction_id,
                   -orn.value AS value,
                   0::BIGINT AS received_value,
                   orn.value AS spent_value,
                   1::BIGINT AS spent_note_count,
                   0::BIGINT AS change_note_count,
                   0::BIGINT AS received_count,
                   1::BIGINT AS does_not_match_shielding
            FROM orchard_received_notes orn
            INNER JOIN orchard_received_note_spends orns ON orns.orchard_received_note_id = orn.id
            WHERE orn.wallet_id = $1
            UNION ALL
            -- Transparent outputs received
            SELECT tro.account_id,
                   tro.tx_id AS transaction_id,
                   tro.value_zat AS value,
                   tro.value_zat AS received_value,
                   0::BIGINT AS spent_value,
                   0::BIGINT AS spent_note_count,
                   0::BIGINT AS change_note_count,
                   1::BIGINT AS received_count,
                   0::BIGINT AS does_not_match_shielding
            FROM transparent_received_outputs tro
            WHERE tro.wallet_id = $1
            UNION ALL
            -- Transparent outputs spent in transactions
            -- Spending transparent is consistent with shielding
            SELECT tro.account_id,
                   tros.transaction_id AS transaction_id,
                   -tro.value_zat AS value,
                   0::BIGINT AS received_value,
                   tro.value_zat AS spent_value,
                   1::BIGINT AS spent_note_count,
                   0::BIGINT AS change_note_count,
                   0::BIGINT AS received_count,
                   0::BIGINT AS does_not_match_shielding
            FROM transparent_received_outputs tro
            INNER JOIN transparent_received_output_spends tros ON tros.transparent_received_output_id = tro.id
            WHERE tro.wallet_id = $1
        ),
        sent_note_counts AS (
            -- Count sent notes to external recipients only (to_account_id IS NULL)
            -- Internal sends (including shielding change) are not counted
            SELECT sn.from_account_id AS account_id,
                   sn.tx_id AS transaction_id,
                   COUNT(DISTINCT sn.id) AS sent_notes,
                   SUM(CASE WHEN sn.memo IS NOT NULL THEN 1 ELSE 0 END) AS memo_count
            FROM sent_notes sn
            WHERE sn.wallet_id = $1 AND sn.to_account_id IS NULL
            GROUP BY sn.from_account_id, sn.tx_id
        ),
        blocks_max_height AS (
            SELECT COALESCE(MAX(height), 0) AS max_height FROM blocks
        )
        SELECT
            a.uuid as account_uuid,
            t.txid,
            t.expiry_height,
            t.mined_height,
            SUM(notes.value)::BIGINT as account_balance_delta,
            SUM(notes.spent_value)::BIGINT as total_spent,
            SUM(notes.received_value)::BIGINT as total_received,
            t.fee as fee_paid,
            SUM(notes.spent_note_count)::BIGINT as spent_note_count,
            SUM(notes.change_note_count) > 0 as has_change,
            COALESCE(MAX(snc.sent_notes), 0)::BIGINT as sent_note_count,
            SUM(notes.received_count)::BIGINT as received_note_count,
            COALESCE(MAX(snc.memo_count), 0)::BIGINT as memo_count,
            (t.mined_height IS NULL AND t.expiry_height IS NOT NULL
             AND t.expiry_height <= (SELECT max_height FROM blocks_max_height)) as expired_unmined,
            (
                -- All spent outputs are transparent (consistent with shielding)
                SUM(notes.does_not_match_shielding) = 0
                -- At least one spent output
                AND SUM(notes.spent_note_count) > 0
                -- At least one received/change note
                AND (SUM(notes.received_count) + SUM(notes.change_note_count)) > 0
                -- No external sends
                AND COALESCE(MAX(snc.sent_notes), 0) = 0
            ) as is_shielding
        FROM notes
        INNER JOIN accounts a ON a.id = notes.account_id
        INNER JOIN transactions t ON t.id = notes.transaction_id
        LEFT JOIN sent_note_counts snc ON snc.account_id = notes.account_id AND snc.transaction_id = notes.transaction_id
        WHERE a.wallet_id = $1
          AND a.deleted_at IS NULL
        GROUP BY a.uuid, t.id, t.txid, t.expiry_height, t.mined_height, t.fee
        ORDER BY t.mined_height DESC NULLS LAST, t.tx_index DESC NULLS LAST
    "#;

    let rows: Vec<TransactionHistoryRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut results = Vec::new();
    for row in rows {
        let txid_bytes: [u8; 32] = row
            .txid_bytes
            .try_into()
            .map_err(|_| SqlxClientError::CorruptedOutput)?;

        results.push(TransactionSummary::from_parts(
            AccountUuid::from_uuid(row.account_uuid),
            TxId::from_bytes(txid_bytes),
            row.expiry_height.map(|h| BlockHeight::from_u32(h as u32)),
            row.mined_height.map(|h| BlockHeight::from_u32(h as u32)),
            ZatBalance::from_i64(row.account_balance_delta)?,
            Zatoshis::from_nonnegative_i64(row.total_spent)?,
            Zatoshis::from_nonnegative_i64(row.total_received)?,
            row.fee_paid
                .map(Zatoshis::from_nonnegative_i64)
                .transpose()?,
            row.spent_note_count as usize,
            row.has_change,
            row.sent_note_count as usize,
            row.received_note_count as usize,
            row.memo_count as usize,
            row.expired_unmined,
            row.is_shielding,
        ));
    }

    Ok(results)
}

#[cfg(feature = "postgres")]
pub async fn get_sent_note_ids(
    pool: &Pool,
    wallet_id: WalletId,
    txid: &TxId,
    protocol: ShieldedProtocol,
) -> Result<Vec<NoteId>, SqlxClientError> {
    let query = r#"
        SELECT sn.output_index
        FROM sent_notes sn
        INNER JOIN transactions t ON t.id = sn.tx_id
        WHERE t.wallet_id = $1 AND t.txid = $2 AND sn.output_pool = $3
        ORDER BY sn.output_index
    "#;

    let pool_code = match protocol {
        ShieldedProtocol::Sapling => 2i32,
        ShieldedProtocol::Orchard => 3i32,
    };

    let rows: Vec<(i32,)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .bind(pool_code)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(idx,)| NoteId::new(*txid, protocol, idx as u16))
        .collect())
}

#[cfg(feature = "postgres")]
pub async fn get_sent_outputs<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    txid: &TxId,
) -> Result<Vec<OutputOfSentTx>, SqlxClientError> {
    use zcash_keys::address::Address;

    #[cfg(feature = "transparent-inputs")]
    {
        use crate::wallet::transparent::KeyScope;

        // Query sent notes for this transaction, joining with transparent_received_outputs
        // and addresses to get ephemeral address info (matching SQLite pattern)
        let query = r#"
            SELECT sn.value, sn.to_address,
                   a.cached_transparent_receiver_address, a.transparent_child_index
            FROM sent_notes sn
            INNER JOIN transactions t ON t.id = sn.tx_id
            LEFT JOIN transparent_received_outputs tro ON tro.tx_id = t.id
            LEFT JOIN addresses a ON a.id = tro.address_id AND a.key_scope = $3
            WHERE t.wallet_id = $1 AND t.txid = $2
            ORDER BY sn.value
        "#;

        let ephemeral_scope = KeyScope::Ephemeral.encode();

        let rows: Vec<SentOutputRow> = sqlx_core::query_as::query_as(query)
            .bind(wallet_id.expose_uuid())
            .bind(txid.as_ref())
            .bind(ephemeral_scope)
            .fetch_all(pool)
            .await?;

        let mut results = Vec::new();
        for row in rows {
            let value = Zatoshis::from_nonnegative_i64(row.value)
                .map_err(|_| SqlxClientError::CorruptedOutput)?;

            // Decode the external recipient address (to_address)
            let external_recipient = row
                .to_address
                .map(|s| {
                    Address::decode(params, &s)
                        .ok_or_else(|| SqlxClientError::Encoding(format!("invalid address: {s}")))
                })
                .transpose()?;

            // Handle ephemeral address info
            use transparent::keys::NonHardenedChildIndex;

            let ephemeral = row
                .ephemeral_address
                .zip(row.address_index)
                .map(|(addr_str, idx)| {
                    let addr = Address::decode(params, &addr_str).ok_or_else(|| {
                        SqlxClientError::Encoding(format!(
                            "invalid transparent address: {addr_str}"
                        ))
                    })?;
                    let i = NonHardenedChildIndex::from_index(idx as u32).ok_or_else(|| {
                        SqlxClientError::Encoding(format!(
                            "invalid non-hardened child index: {idx}"
                        ))
                    })?;
                    Ok::<_, SqlxClientError>((addr, i))
                })
                .transpose()?;

            results.push(OutputOfSentTx::from_parts(
                value,
                external_recipient,
                ephemeral,
            ));
        }

        Ok(results)
    }

    #[cfg(not(feature = "transparent-inputs"))]
    {
        // Simpler query without ephemeral address tracking
        let query = r#"
            SELECT sn.value, sn.to_address
            FROM sent_notes sn
            INNER JOIN transactions t ON t.id = sn.tx_id
            WHERE t.wallet_id = $1 AND t.txid = $2
            ORDER BY sn.value
        "#;

        let rows: Vec<(i64, Option<String>)> = sqlx_core::query_as::query_as(query)
            .bind(wallet_id.expose_uuid())
            .bind(txid.as_ref())
            .fetch_all(pool)
            .await?;

        let mut results = Vec::new();
        for (value, to_address) in rows {
            let value = Zatoshis::from_nonnegative_i64(value)
                .map_err(|_| SqlxClientError::CorruptedOutput)?;

            let external_recipient = to_address
                .map(|s| {
                    Address::decode(params, &s)
                        .ok_or_else(|| SqlxClientError::Encoding(format!("invalid address: {s}")))
                })
                .transpose()?;

            results.push(OutputOfSentTx::from_parts(value, external_recipient));
        }

        Ok(results)
    }
}

#[cfg(feature = "postgres")]
pub async fn get_checkpoint_history(
    pool: &Pool,
    _wallet_id: WalletId,
    protocol: &ShieldedProtocol,
) -> Result<Vec<(BlockHeight, Option<Position>)>, SqlxClientError> {
    let tables = TableConstants::for_protocol(*protocol);

    // Global table - tree checkpoints are shared across all wallets
    let query = format!(
        "SELECT checkpoint_id, position FROM {} ORDER BY checkpoint_id",
        tables.tree_checkpoints
    );

    let rows: Vec<(i64, Option<i64>)> = sqlx_core::query_as::query_as(&query)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(id, pos)| {
            (
                BlockHeight::from_u32(id as u32),
                pos.map(|p| Position::from(p as u64)),
            )
        })
        .collect())
}

#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
pub async fn get_transparent_output<P: Parameters>(
    _pool: &Pool,
    _params: &P,
    _wallet_id: WalletId,
    _outpoint: &OutPoint,
    _spendable_as_of: Option<TargetHeight>,
) -> Result<Option<WalletTransparentOutput>, SqlxClientError> {
    // This requires constructing a TxOut from stored data, which is complex.
    // Return None for now - can be implemented when full transparent support is needed.
    Ok(None)
}

#[cfg(feature = "postgres")]
pub async fn get_notes<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    protocol: ShieldedProtocol,
) -> Result<Vec<ReceivedNote<ReceivedNoteId, Note>>, SqlxClientError> {
    use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
    use zcash_client_backend::data_api::wallet::TargetHeight;

    // Get target and anchor heights with minimal confirmations (1) - matches SQLite
    let chain_tip = crate::wallet::common::get_chain_tip(pool, wallet_id)
        .await?
        .ok_or(SqlxClientError::ChainHeightUnavailable)?;
    let target_height = TargetHeight::from(chain_tip + 1);
    // Use minimal confirmations (1) for get_notes, like SQLite does
    let _anchor_height =
        crate::wallet::common::compute_anchor_height(target_height, ConfirmationsPolicy::MIN);

    let tables = TableConstants::for_protocol(protocol);
    let output_index_col = tables.output_index_col;

    // Query all received notes that have the required fields for spendability
    let query = format!(
        "SELECT t.txid, rn.{}::BIGINT
         FROM {} rn
         INNER JOIN transactions t ON t.id = rn.tx_id
         WHERE rn.wallet_id = $1
         AND t.mined_height IS NOT NULL
         AND rn.recipient_key_scope IS NOT NULL
         AND rn.nf IS NOT NULL
         AND rn.commitment_tree_position IS NOT NULL",
        output_index_col, tables.received_notes
    );

    let rows: Vec<(Vec<u8>, i64)> = sqlx_core::query_as::query_as(&query)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = Vec::new();
    for (txid_bytes, output_index) in rows {
        let txid_arr: [u8; 32] = txid_bytes
            .try_into()
            .map_err(|_| SqlxClientError::CorruptedOutput)?;
        let txid = TxId::from_bytes(txid_arr);

        // Get the spendable note using existing function
        if let Some(note) = crate::wallet::get_spendable_note(
            pool,
            params,
            wallet_id,
            &txid,
            protocol,
            output_index as u32,
            target_height,
        )
        .await?
        {
            result.push(note);
        }
    }

    Ok(result)
}

#[cfg(all(feature = "transparent-inputs", feature = "postgres"))]
pub async fn get_known_ephemeral_addresses<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    index_range: Option<Range<NonHardenedChildIndex>>,
    gap_limits: &GapLimits,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqlxClientError> {
    use crate::wallet::transparent::KeyScope;
    use transparent::keys::TransparentKeyScope;
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_client_backend::wallet::{Exposure, GapMetadata};

    // Get account internal ID
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let internal_account_id = match account_row {
        Some((id,)) => id,
        None => return Ok(Vec::new()), // Account not found
    };

    // Get gap start
    let gap_start = crate::wallet::transparent::find_gap_start_internal(
        pool,
        wallet_id,
        internal_account_id,
        TransparentKeyScope::EPHEMERAL,
        gap_limits.ephemeral,
    )
    .await?;

    let key_scope_code = KeyScope::Ephemeral.encode();
    let start_index = index_range
        .as_ref()
        .map_or(0i32, |r| r.start.index() as i32);
    let end_index = index_range
        .as_ref()
        .map_or(i32::MAX, |r| r.end.index() as i32);

    // Query the addresses table for ephemeral addresses (key_scope = 2)
    let query = r#"
        SELECT
            cached_transparent_receiver_address,
            transparent_child_index,
            exposed_at_height,
            transparent_receiver_next_check_time
        FROM addresses
        WHERE wallet_id = $1
          AND account_id = $2
          AND transparent_child_index >= $3
          AND transparent_child_index < $4
          AND key_scope = $5
        ORDER BY transparent_child_index
    "#;

    let rows: Vec<EphemeralAddressRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(internal_account_id)
        .bind(start_index)
        .bind(end_index)
        .bind(key_scope_code)
        .fetch_all(pool)
        .await?;

    let mut results = Vec::new();
    for row in rows {
        let addr_str = match row.address {
            Some(s) => s,
            None => continue, // Skip if no address
        };
        let child_index = match row.child_index {
            Some(idx) => idx,
            None => continue, // Skip if no child index
        };

        let address = TransparentAddress::decode(params, &addr_str)
            .map_err(|_| SqlxClientError::Encoding("Invalid ephemeral address".to_string()))?;

        let address_index = NonHardenedChildIndex::from_index(child_index as u32)
            .ok_or(SqlxClientError::CorruptedOutput)?;

        // Calculate gap metadata
        let gap_metadata = gap_start.map_or(GapMetadata::DerivationUnknown, |start| {
            if let Some(gap_position) = address_index.index().checked_sub(start.index()) {
                GapMetadata::InGap {
                    gap_position,
                    gap_limit: gap_limits.ephemeral,
                }
            } else {
                GapMetadata::GapRecoverable {
                    gap_limit: gap_limits.ephemeral,
                }
            }
        });

        let exposure = row
            .exposed_at_height
            .map_or(Exposure::Unknown, |h| Exposure::Exposed {
                at_height: BlockHeight::from_u32(h as u32),
                gap_metadata,
            });

        let metadata = TransparentAddressMetadata::derived(
            TransparentKeyScope::EPHEMERAL,
            address_index,
            exposure,
            None, // TODO: Convert next_check_time
        );
        results.push((address, metadata));
    }

    Ok(results)
}
