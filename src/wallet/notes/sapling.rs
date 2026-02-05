//! Sapling note storage and retrieval operations.

use std::collections::HashSet;

use group::ff::PrimeField;
use incrementalmerkletree::Position;

use sapling::{Diversifier, Nullifier, Rseed};
use zcash_client_backend::data_api::NullifierQuery;
use zcash_client_backend::wallet::ReceivedNote;
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::{
    ShieldedProtocol, TxId,
    consensus::{self, BlockHeight},
    memo::MemoBytes,
};
use zip32::Scope;

#[cfg(feature = "postgres")]
use crate::pool::Pool;

use crate::types::{AccountRef, TxRef};
use crate::{AccountUuid, ReceivedNoteId, SqlxClientError, WalletId};

/// Parses a Sapling note from database row data.
///
/// Returns `Ok(None)` if the note cannot be spent (missing UFVK or key scope).
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
pub fn parse_sapling_note<P: consensus::Parameters>(
    params: &P,
    note_id: i64,
    txid_bytes: &[u8],
    output_index: i32,
    diversifier_bytes: &[u8],
    value: i64,
    rcm_bytes: &[u8],
    commitment_tree_position: i64,
    ufvk_str: Option<&str>,
    recipient_key_scope: Option<i64>,
    mined_height: Option<i64>,
    max_shielding_input_height: Option<i64>,
) -> Result<Option<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqlxClientError> {
    use crate::wallet::common::i64_to_optional_height;

    // Both UFVK and key scope are required to reconstruct a spendable note
    let (ufvk_str, scope_code) = match (ufvk_str, recipient_key_scope) {
        (Some(u), Some(s)) => (u, s),
        _ => return Ok(None),
    };

    // Parse the note ID
    let note_id = ReceivedNoteId::new(ShieldedProtocol::Sapling, note_id);

    // Parse txid
    let txid_array: [u8; 32] = txid_bytes
        .try_into()
        .map_err(|_| SqlxClientError::Encoding("Invalid txid length".to_string()))?;
    let txid = TxId::from_bytes(txid_array);

    // Parse diversifier
    let diversifier = {
        if diversifier_bytes.len() != 11 {
            return Err(SqlxClientError::Encoding(
                "Invalid diversifier length".to_string(),
            ));
        }
        let mut tmp = [0u8; 11];
        tmp.copy_from_slice(diversifier_bytes);
        Diversifier(tmp)
    };

    // Parse note value
    let note_value: u64 = value
        .try_into()
        .map_err(|_| SqlxClientError::Encoding("Note values must be nonnegative".to_string()))?;

    // Parse rcm (random commitment trapdoor)
    let rseed = {
        let rcm = jubjub::Fr::from_repr(
            rcm_bytes
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid rcm length".to_string()))?,
        );
        if rcm.is_none().into() {
            return Err(SqlxClientError::Encoding("Invalid rcm value".to_string()));
        }
        // We store rcm directly, so pretend this is pre-ZIP 212
        Rseed::BeforeZip212(rcm.unwrap())
    };

    // Parse commitment tree position
    let position = Position::from(commitment_tree_position as u64);

    // Parse key scope
    let spending_key_scope = match scope_code {
        0 => Scope::External,
        1 => Scope::Internal,
        _ => {
            return Err(SqlxClientError::Encoding(format!(
                "Invalid key scope code {}",
                scope_code
            )));
        }
    };

    // Decode the UFVK and reconstruct the note recipient
    let ufvk = UnifiedFullViewingKey::decode(params, ufvk_str)
        .map_err(|e| SqlxClientError::Encoding(format!("Could not decode UFVK: {}", e)))?;

    let recipient = match spending_key_scope {
        Scope::Internal => ufvk
            .sapling()
            .and_then(|dfvk| dfvk.diversified_change_address(diversifier)),
        Scope::External => ufvk
            .sapling()
            .and_then(|dfvk| dfvk.diversified_address(diversifier)),
    }
    .ok_or_else(|| SqlxClientError::Encoding("Diversifier invalid".to_string()))?;

    // Construct the Sapling note
    let note = sapling::Note::from_parts(
        recipient,
        sapling::value::NoteValue::from_raw(note_value),
        rseed,
    );

    // Parse heights
    let mined_height = i64_to_optional_height(mined_height)?;
    let max_shielding_input_height = i64_to_optional_height(max_shielding_input_height)?;

    Ok(Some(ReceivedNote::from_parts(
        note_id,
        txid,
        output_index as u16,
        note,
        spending_key_scope,
        position,
        mined_height,
        max_shielding_input_height,
    )))
}

/// Retrieves a specific spendable Sapling note by transaction ID and output index.
///
/// Matches SQLite's `get_spendable_note` implementation - uses target_height to filter
/// out notes that have been spent by unexpired transactions.
#[cfg(feature = "postgres")]
pub async fn get_spendable_sapling_note<P: consensus::Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    txid: &TxId,
    output_index: u32,
    target_height: zcash_client_backend::data_api::wallet::TargetHeight,
) -> Result<Option<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqlxClientError> {
    use crate::wallet::common::height_to_i64;

    let target_height_i64 = height_to_i64(target_height.into());

    // Query for the specific note, ensuring it's unspent and spendable.
    // Matches SQLite's get_spendable_note query structure:
    // - No mined_height <= anchor filter (SQLite doesn't have this)
    // - Uses tx_unexpired_condition logic for spent notes exclusion
    let query = r#"
        SELECT
            rn.id,
            t.txid,
            rn.output_index,
            rn.diversifier,
            rn.value,
            rn.rcm,
            rn.commitment_tree_position,
            a.ufvk,
            rn.recipient_key_scope,
            t.mined_height,
            MAX(tt.mined_height) AS max_shielding_input_height
        FROM sapling_received_notes rn
        INNER JOIN accounts a ON a.id = rn.account_id
        INNER JOIN transactions t ON t.id = rn.tx_id
        LEFT OUTER JOIN transparent_received_output_spends ros
            ON ros.transaction_id = t.id
        LEFT OUTER JOIN transparent_received_outputs tro
            ON tro.id = ros.transparent_received_output_id
            AND tro.account_id = a.id
        LEFT OUTER JOIN transactions tt
            ON tt.id = tro.tx_id
        WHERE rn.wallet_id = $1
          AND t.txid = $2
          AND rn.output_index = $3
          AND t.mined_height IS NOT NULL
          AND a.ufvk IS NOT NULL
          AND rn.recipient_key_scope IS NOT NULL
          AND rn.nf IS NOT NULL
          AND rn.commitment_tree_position IS NOT NULL
          AND rn.id NOT IN (
              SELECT rns.sapling_received_note_id
              FROM sapling_received_note_spends rns
              INNER JOIN transactions stx ON stx.id = rns.transaction_id
              WHERE stx.mined_height < $4
                 OR stx.expiry_height = 0
                 OR stx.expiry_height >= $4
                 OR (stx.expiry_height IS NULL
                     AND stx.min_observed_height + 40 >= $4)
          )
        GROUP BY rn.id, t.txid, rn.output_index, rn.diversifier, rn.value, rn.rcm,
                 rn.commitment_tree_position, a.ufvk, rn.recipient_key_scope, t.mined_height
    "#;

    type NoteRow = (
        i64,            // id
        Vec<u8>,        // txid
        i32,            // output_index
        Vec<u8>,        // diversifier
        i64,            // value
        Vec<u8>,        // rcm
        i64,            // commitment_tree_position
        Option<String>, // ufvk
        Option<i64>,    // recipient_key_scope
        Option<i64>,    // mined_height
        Option<i64>,    // max_shielding_input_height
    );

    let row: Option<NoteRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .bind(output_index as i32)
        .bind(target_height_i64)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((
            note_id,
            txid_bytes,
            output_index,
            diversifier,
            value,
            rcm,
            position,
            ufvk,
            scope,
            mined_height,
            max_shielding,
        )) => parse_sapling_note(
            params,
            note_id,
            &txid_bytes,
            output_index,
            &diversifier,
            value,
            &rcm,
            position,
            ufvk.as_deref(),
            scope,
            mined_height,
            max_shielding,
        ),
        None => Ok(None),
    }
}

/// Selects spendable Sapling notes to meet a target value.
///
/// Notes are selected greedily from oldest to newest until the target is met.
/// Returns an empty vec if no notes are available or if unscanned ranges exist
/// that might contain relevant notes.
///
/// This function takes both `target_height` and `anchor_height`:
/// - `target_height` is used for the spent notes exclusion clause (tx_unexpired_condition)
/// - `anchor_height` is used to filter notes that are sufficiently confirmed
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
pub async fn select_spendable_sapling_notes<P: consensus::Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    target_value: u64,
    target_height: zcash_client_backend::data_api::wallet::TargetHeight,
    anchor_height: BlockHeight,
    confirmations_policy: zcash_client_backend::data_api::wallet::ConfirmationsPolicy,
    exclude: &[i64],
) -> Result<Vec<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqlxClientError> {
    use crate::wallet::common::{MARGINAL_FEE, height_to_i64, i64_to_optional_height};
    use zcash_protocol::{PoolType, ShieldedProtocol};

    let target_height_i64 = height_to_i64(target_height.into());
    let anchor_height_i64 = height_to_i64(anchor_height);

    // Check if there are unscanned ranges below the anchor that would affect spendability.
    // This is a simplified version of SQLite's unscanned_tip_exists check.
    //
    // A note is spendable if all blocks from birthday to the note's mined_height are scanned.
    // The main query already filters notes by `mined_height <= anchor_height`, so we only need
    // to check that there's no gap between the wallet birthday and the first scanned block.
    //
    // Note: We intentionally don't check for gaps AFTER the first scanned block. Notes at
    // lower heights can still be spent even if later blocks haven't been scanned yet.
    // The mined_height <= anchor_height filter handles ensuring notes are confirmed enough.
    let unscanned_check = r#"
        WITH wallet_birthday AS (
            SELECT MIN(birthday_height) AS height
            FROM accounts
            WHERE wallet_id = $1 AND deleted_at IS NULL
        ),
        scanned_blocks AS (
            SELECT MIN(height) AS first_scanned
            FROM blocks
        )
        SELECT
            -- Check if we have explicit unscanned ranges in scan_queue at or before anchor
            EXISTS (
                SELECT 1 FROM scan_queue sq
                WHERE sq.wallet_id = $1
                  AND sq.priority > 0
                  AND sq.block_range_start <= $2
            )
            OR
            -- Check if there are gaps between birthday and first scanned block
            (
                SELECT CASE
                    WHEN wb.height IS NULL THEN FALSE  -- no accounts, no birthday constraint
                    WHEN sb.first_scanned IS NULL THEN TRUE  -- no blocks scanned at all
                    WHEN sb.first_scanned > wb.height THEN TRUE  -- gap before first scanned block
                    ELSE FALSE
                END
                FROM wallet_birthday wb, scanned_blocks sb
            )
            AS has_unscanned
    "#;

    // Check for unscanned ranges before selecting spendable notes.
    // This is similar to SQLite's unscanned_tip_exists but uses a simpler approach
    // by checking for gaps in the blocks table rather than using shard scan state views.
    let has_unscanned: (bool,) = sqlx_core::query_as::query_as(unscanned_check)
        .bind(wallet_id.expose_uuid())
        .bind(anchor_height_i64)
        .fetch_one(pool)
        .await?;

    if has_unscanned.0 {
        // Cannot safely select notes if there are unscanned ranges
        return Ok(vec![]);
    }

    // Select notes using a running sum window function
    // This efficiently selects the minimum set of notes needed to meet the target
    // Uses anchor_height ($4) for note confirmation filter
    // Uses target_height ($7) for spent notes exclusion (tx_unexpired_condition)
    //
    // For AllFunds mode (target_value = u64::MAX), we select ALL eligible notes without
    // the running_sum filter. We use a boolean flag ($6) instead of the target value
    // to avoid i64 overflow issues with u64::MAX.
    let select_all = target_value == u64::MAX;
    let query = r#"
        WITH eligible AS (
            SELECT
                rn.id,
                t.txid,
                rn.output_index,
                rn.diversifier,
                rn.value,
                rn.rcm,
                rn.commitment_tree_position,
                a.ufvk,
                rn.recipient_key_scope,
                t.mined_height,
                COALESCE(t.trust_status, 0) > 0 AS tx_trusted,
                (SUM(rn.value) OVER (ORDER BY t.mined_height, rn.id ROWS UNBOUNDED PRECEDING))::BIGINT AS running_sum,
                        MAX(tt.mined_height) AS max_shielding_input_height,
                COALESCE(MIN(CASE WHEN tt.trust_status IS NOT NULL THEN CASE WHEN tt.trust_status > 0 THEN 1 ELSE 0 END ELSE NULL END), 1) > 0 AS min_shielding_input_trusted
            FROM sapling_received_notes rn
            INNER JOIN accounts a ON a.id = rn.account_id
            INNER JOIN transactions t ON t.id = rn.tx_id
            LEFT OUTER JOIN transparent_received_output_spends ros
                ON ros.transaction_id = t.id
            LEFT OUTER JOIN transparent_received_outputs tro
                ON tro.id = ros.transparent_received_output_id
                AND tro.account_id = a.id
            LEFT OUTER JOIN transactions tt
                ON tt.id = tro.tx_id
            WHERE rn.wallet_id = $1
              AND a.uuid = $2
              AND rn.value > $3
              AND a.ufvk IS NOT NULL
              AND rn.recipient_key_scope IS NOT NULL
              AND rn.nf IS NOT NULL
              AND rn.commitment_tree_position IS NOT NULL
              AND t.mined_height IS NOT NULL
              AND t.mined_height <= $4
              AND rn.id NOT IN (SELECT unnest($5::BIGINT[]))
              AND rn.id NOT IN (
                  SELECT rns.sapling_received_note_id
                  FROM sapling_received_note_spends rns
                  INNER JOIN transactions stx ON stx.id = rns.transaction_id
                  WHERE stx.mined_height < $8
                     OR stx.expiry_height = 0
                     OR stx.expiry_height >= $8
                     OR (stx.expiry_height IS NULL
                         AND stx.min_observed_height + 40 >= $8)
              )
            GROUP BY rn.id, t.txid, rn.output_index, rn.diversifier, rn.value, rn.rcm,
                     rn.commitment_tree_position, a.ufvk, rn.recipient_key_scope, t.mined_height,
                     t.trust_status
        )
        SELECT id, txid, output_index, diversifier, value, rcm, commitment_tree_position,
               ufvk, recipient_key_scope, mined_height, tx_trusted, max_shielding_input_height,
               min_shielding_input_trusted
        FROM eligible
        WHERE $6 OR running_sum - value < $7
        ORDER BY mined_height, id
    "#;

    type NoteRow = (
        i64,            // id
        Vec<u8>,        // txid
        i32,            // output_index
        Vec<u8>,        // diversifier
        i64,            // value
        Vec<u8>,        // rcm
        i64,            // commitment_tree_position
        Option<String>, // ufvk
        Option<i64>,    // recipient_key_scope
        Option<i64>,    // mined_height
        bool,           // tx_trusted
        Option<i64>,    // max_shielding_input_height
        bool,           // min_shielding_input_trusted
    );

    let rows: Vec<NoteRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid()) // $1
        .bind(account.expose_uuid()) // $2
        .bind(MARGINAL_FEE) // $3
        .bind(anchor_height_i64) // $4 - for note confirmation
        .bind(exclude) // $5
        .bind(select_all) // $6 - true to select all, false to use running_sum
        .bind(target_value as i64) // $7 - target value (only used when $6 is false)
        .bind(target_height_i64) // $8 - for spent notes exclusion
        .fetch_all(pool)
        .await?;

    let mut notes = Vec::with_capacity(rows.len());
    for (
        note_id,
        txid_bytes,
        output_index,
        diversifier,
        value,
        rcm,
        position,
        ufvk,
        scope,
        mined_height_raw,
        tx_trusted,
        max_shielding,
        min_shielding_trusted,
    ) in rows
    {
        // Per-note confirmation check (matches SQLite's confirmations_until_spendable filtering)
        let mined_height = i64_to_optional_height(mined_height_raw)?;
        let key_scope = scope.and_then(|s| match s {
            0 => Some(zip32::Scope::External),
            1 => Some(zip32::Scope::Internal),
            _ => None,
        });
        let max_shielding_height = i64_to_optional_height(max_shielding)?;

        let has_confirmations = confirmations_policy.confirmations_until_spendable(
            target_height,
            PoolType::Shielded(ShieldedProtocol::Sapling),
            key_scope,
            mined_height,
            tx_trusted,
            max_shielding_height,
            min_shielding_trusted,
        ) == 0;

        if !has_confirmations {
            // Note doesn't have enough confirmations to be spendable
            continue;
        }

        if let Some(note) = parse_sapling_note(
            params,
            note_id,
            &txid_bytes,
            output_index,
            &diversifier,
            value,
            &rcm,
            position,
            ufvk.as_deref(),
            scope,
            mined_height_raw,
            max_shielding,
        )? {
            notes.push(note);
        }
    }

    Ok(notes)
}

/// Selects all unspent Sapling notes for an account.
///
/// This is used for operations that need all notes, regardless of confirmation status.
/// Unlike `select_spendable_sapling_notes`, this does NOT filter by anchor height.
///
/// - `target_height` is used for the spent notes exclusion clause (tx_unexpired_condition)
/// - `anchor_height` is accepted for API compatibility but NOT used for filtering
#[cfg(feature = "postgres")]
pub async fn select_unspent_sapling_notes<P: consensus::Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    target_height: zcash_client_backend::data_api::wallet::TargetHeight,
    _anchor_height: BlockHeight, // Not used for unspent queries
    exclude: &[i64],
) -> Result<Vec<ReceivedNote<ReceivedNoteId, sapling::Note>>, SqlxClientError> {
    use crate::wallet::common::{MARGINAL_FEE, height_to_i64};

    let target_height_i64 = height_to_i64(target_height.into());

    // Query for ALL unspent notes matching SQLite's NoteRequest::Unspent behavior.
    // Unlike spendable notes, we don't filter by anchor height here.
    // - target_height ($4) is used for spent notes exclusion (tx_unexpired_condition)
    let query = r#"
        SELECT
            rn.id,
            t.txid,
            rn.output_index,
            rn.diversifier,
            rn.value,
            rn.rcm,
            rn.commitment_tree_position,
            a.ufvk,
            rn.recipient_key_scope,
            t.mined_height,
            MAX(tt.mined_height) AS max_shielding_input_height
        FROM sapling_received_notes rn
        INNER JOIN accounts a ON a.id = rn.account_id
        INNER JOIN transactions t ON t.id = rn.tx_id
        LEFT OUTER JOIN transparent_received_output_spends ros
            ON ros.transaction_id = t.id
        LEFT OUTER JOIN transparent_received_outputs tro
            ON tro.id = ros.transparent_received_output_id
            AND tro.account_id = a.id
        LEFT OUTER JOIN transactions tt
            ON tt.id = tro.tx_id
        WHERE rn.wallet_id = $1
          AND a.uuid = $2
          AND rn.value > $3
          AND a.ufvk IS NOT NULL
          AND rn.recipient_key_scope IS NOT NULL
          AND rn.nf IS NOT NULL
          AND rn.commitment_tree_position IS NOT NULL
          AND t.mined_height IS NOT NULL
          AND rn.id NOT IN (SELECT unnest($4::BIGINT[]))
          AND rn.id NOT IN (
              SELECT rns.sapling_received_note_id
              FROM sapling_received_note_spends rns
              INNER JOIN transactions stx ON stx.id = rns.transaction_id
              WHERE stx.mined_height < $5
                 OR stx.expiry_height = 0
                 OR stx.expiry_height >= $5
                 OR (stx.expiry_height IS NULL
                     AND stx.min_observed_height + 40 >= $5)
          )
        GROUP BY rn.id, t.txid, rn.output_index, rn.diversifier, rn.value, rn.rcm,
                 rn.commitment_tree_position, a.ufvk, rn.recipient_key_scope, t.mined_height
        ORDER BY t.mined_height, rn.id
    "#;

    type NoteRow = (
        i64,            // id
        Vec<u8>,        // txid
        i32,            // output_index
        Vec<u8>,        // diversifier
        i64,            // value
        Vec<u8>,        // rcm
        i64,            // commitment_tree_position
        Option<String>, // ufvk
        Option<i64>,    // recipient_key_scope
        Option<i64>,    // mined_height
        Option<i64>,    // max_shielding_input_height
    );

    let rows: Vec<NoteRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid()) // $1
        .bind(account.expose_uuid()) // $2
        .bind(MARGINAL_FEE) // $3
        .bind(exclude) // $4
        .bind(target_height_i64) // $5 - for spent notes exclusion
        .fetch_all(pool)
        .await?;

    let mut notes = Vec::with_capacity(rows.len());
    for (
        note_id,
        txid_bytes,
        output_index,
        diversifier,
        value,
        rcm,
        position,
        ufvk,
        scope,
        mined_height,
        max_shielding,
    ) in rows
    {
        if let Some(note) = parse_sapling_note(
            params,
            note_id,
            &txid_bytes,
            output_index,
            &diversifier,
            value,
            &rcm,
            position,
            ufvk.as_deref(),
            scope,
            mined_height,
            max_shielding,
        )? {
            notes.push(note);
        }
    }

    Ok(notes)
}

/// Retrieves the set of nullifiers for "potentially spendable" Sapling notes that the
/// wallet is tracking.
///
/// "Potentially spendable" means:
/// - The transaction in which the note was created has been observed as mined.
/// - No transaction in which the note's nullifier appears has been observed as mined.
#[cfg(feature = "postgres")]
pub async fn get_sapling_nullifiers(
    pool: &Pool,
    wallet_id: WalletId,
    query: NullifierQuery,
) -> Result<Vec<(AccountUuid, Nullifier)>, SqlxClientError> {
    // Query nullifiers based on the query type
    let sql = match query {
        NullifierQuery::Unspent => {
            // Get nullifiers for notes that are:
            // - Created in a mined transaction
            // - Not spent in any mined transaction, OR not spent in a non-expiring transaction
            r#"
            SELECT a.uuid, rn.nf
            FROM sapling_received_notes rn
            JOIN accounts a ON a.id = rn.account_id
            JOIN transactions tx ON tx.id = rn.tx_id
            WHERE rn.wallet_id = $1
              AND rn.nf IS NOT NULL
              AND tx.mined_height IS NOT NULL
              AND rn.id NOT IN (
                SELECT rns.sapling_received_note_id
                FROM sapling_received_note_spends rns
                JOIN transactions stx ON stx.id = rns.transaction_id
                WHERE stx.mined_height IS NOT NULL  -- the spending tx is mined
                   OR stx.expiry_height = 0         -- the spending tx will not expire
              )
            "#
        }
        NullifierQuery::All => {
            r#"
            SELECT a.uuid, rn.nf
            FROM sapling_received_notes rn
            JOIN accounts a ON a.id = rn.account_id
            WHERE rn.wallet_id = $1
              AND rn.nf IS NOT NULL
            "#
        }
    };

    let rows: Vec<(uuid::Uuid, Vec<u8>)> = sqlx_core::query_as::query_as(sql)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (account_uuid, nf_bytes) in rows {
        let nf = Nullifier::from_slice(&nf_bytes).map_err(|_| {
            SqlxClientError::Encoding("unable to parse Sapling nullifier".to_string())
        })?;
        result.push((AccountUuid::from_uuid(account_uuid), nf));
    }

    Ok(result)
}

/// Detects which accounts are affected by the given Sapling nullifiers being spent.
///
/// Returns the set of account UUIDs that have notes matching the provided nullifiers.
#[cfg(feature = "postgres")]
pub async fn detect_spending_accounts<'a>(
    pool: &Pool,
    wallet_id: WalletId,
    nfs: impl Iterator<Item = &'a Nullifier>,
) -> Result<HashSet<AccountUuid>, SqlxClientError> {
    let nf_bytes: Vec<Vec<u8>> = nfs.map(|nf| nf.to_vec()).collect();

    if nf_bytes.is_empty() {
        return Ok(HashSet::new());
    }

    // Query for accounts that own notes with the given nullifiers
    let query = r#"
        SELECT DISTINCT a.uuid
        FROM sapling_received_notes rn
        JOIN accounts a ON a.id = rn.account_id
        WHERE rn.wallet_id = $1
          AND rn.nf = ANY($2)
    "#;

    let rows: Vec<(uuid::Uuid,)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(&nf_bytes)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(uuid,)| AccountUuid::from_uuid(uuid))
        .collect())
}

/// Marks a given nullifier as having been revealed in the construction
/// of the specified transaction.
///
/// Marking a note spent in this fashion does NOT imply that the
/// spending transaction has been mined.
///
/// Returns `true` if a note was found and marked as spent, `false` otherwise.
#[cfg(feature = "postgres")]
#[allow(dead_code)] // Used in tests
pub(crate) async fn mark_sapling_note_spent(
    pool: &Pool,
    wallet_id: WalletId,
    tx_ref: TxRef,
    nf: &Nullifier,
) -> Result<bool, SqlxClientError> {
    // Insert into sapling_received_note_spends, selecting the note ID based on the nullifier
    let query = r#"
        INSERT INTO sapling_received_note_spends (wallet_id, sapling_received_note_id, transaction_id)
        SELECT $1, id, $2
        FROM sapling_received_notes
        WHERE wallet_id = $1 AND nf = $3
        ON CONFLICT (wallet_id, sapling_received_note_id, transaction_id) DO NOTHING
    "#;

    let result = sqlx_core::query::query(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_ref.0)
        .bind(&nf.0[..])
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// This trait provides a generalization over shielded output representations.
pub trait ReceivedSaplingOutput {
    type AccountId;

    fn index(&self) -> usize;
    fn account_id(&self) -> Self::AccountId;
    fn note(&self) -> &sapling::Note;
    fn memo(&self) -> Option<&MemoBytes>;
    fn is_change(&self) -> bool;
    fn nullifier(&self) -> Option<&Nullifier>;
    fn note_commitment_tree_position(&self) -> Option<Position>;
    fn recipient_key_scope(&self) -> Option<Scope>;
}

impl<AccountId: Copy> ReceivedSaplingOutput
    for zcash_client_backend::wallet::WalletSaplingOutput<AccountId>
{
    type AccountId = AccountId;

    fn index(&self) -> usize {
        zcash_client_backend::wallet::WalletSaplingOutput::index(self)
    }
    fn account_id(&self) -> Self::AccountId {
        *zcash_client_backend::wallet::WalletSaplingOutput::account_id(self)
    }
    fn note(&self) -> &sapling::Note {
        zcash_client_backend::wallet::WalletSaplingOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        None
    }
    fn is_change(&self) -> bool {
        zcash_client_backend::wallet::WalletSaplingOutput::is_change(self)
    }
    fn nullifier(&self) -> Option<&Nullifier> {
        self.nf()
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        Some(zcash_client_backend::wallet::WalletSaplingOutput::note_commitment_tree_position(self))
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        zcash_client_backend::wallet::WalletSaplingOutput::recipient_key_scope(self)
    }
}

impl<AccountId: Copy> ReceivedSaplingOutput
    for zcash_client_backend::DecryptedOutput<sapling::Note, AccountId>
{
    type AccountId = AccountId;

    fn index(&self) -> usize {
        zcash_client_backend::DecryptedOutput::index(self)
    }
    fn account_id(&self) -> Self::AccountId {
        *self.account()
    }
    fn note(&self) -> &sapling::Note {
        zcash_client_backend::DecryptedOutput::note(self)
    }
    fn memo(&self) -> Option<&MemoBytes> {
        Some(self.memo())
    }
    fn is_change(&self) -> bool {
        self.transfer_type() == zcash_client_backend::TransferType::WalletInternal
    }
    fn nullifier(&self) -> Option<&Nullifier> {
        None
    }
    fn note_commitment_tree_position(&self) -> Option<Position> {
        None
    }
    fn recipient_key_scope(&self) -> Option<Scope> {
        if self.transfer_type() == zcash_client_backend::TransferType::WalletInternal {
            Some(Scope::Internal)
        } else {
            Some(Scope::External)
        }
    }
}

/// Ensures that an address record exists for a received output.
///
/// For external (non-change) outputs, this derives the unified address from the
/// diversifier and upserts it into the addresses table, returning the address ID.
/// For internal (change) outputs, returns None since we don't need to track those addresses.
#[cfg(feature = "postgres")]
#[allow(dead_code)] // Used internally during note storage
pub(crate) async fn ensure_address<T, P>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: AccountRef,
    output: &T,
    exposure_height: Option<BlockHeight>,
) -> Result<Option<crate::wallet::AddressRef>, SqlxClientError>
where
    T: ReceivedSaplingOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
{
    use zcash_keys::keys::UnifiedAddressRequest;

    // Only ensure address for external outputs (not change)
    if output.recipient_key_scope() != Some(Scope::Internal) {
        // Get the account's UIVK to derive the address
        let account_row: Option<(String,)> =
            sqlx_core::query_as::query_as("SELECT uivk FROM accounts WHERE id = $1")
                .bind(account_id.0)
                .fetch_optional(pool)
                .await?;

        let uivk_str = match account_row {
            Some((uivk,)) => uivk,
            None => return Ok(None), // Account not found, skip address tracking
        };

        // Parse the UIVK
        let uivk = zcash_keys::keys::UnifiedIncomingViewingKey::decode(params, &uivk_str)
            .map_err(|e| SqlxClientError::Encoding(format!("Could not decode UIVK: {}", e)))?;

        // Get the Sapling IVK to decrypt the diversifier index
        let sapling_ivk = match uivk.sapling() {
            Some(ivk) => ivk,
            None => return Ok(None), // No Sapling capability
        };

        // Decrypt the diversifier index from the note's recipient address
        let to = output.note().recipient();
        let diversifier_index = sapling_ivk.decrypt_diversifier(&to).ok_or_else(|| {
            SqlxClientError::Encoding(
                "Could not decrypt diversifier from note recipient".to_string(),
            )
        })?;

        // Derive the full unified address at this diversifier index
        let ua = uivk
            .address(diversifier_index, UnifiedAddressRequest::ALLOW_ALL)
            .map_err(|e| SqlxClientError::Encoding(format!("Address derivation error: {}", e)))?;

        // Upsert the address and return its ID
        let address_ref = crate::wallet::upsert_address(
            pool,
            params,
            wallet_id,
            account_id,
            diversifier_index,
            &ua,
            exposure_height,
        )
        .await?;

        Ok(Some(address_ref))
    } else {
        Ok(None)
    }
}

/// Records the specified shielded output as having been received.
///
/// This implementation relies on the facts that:
/// - A transaction will not contain more than 2^63 shielded outputs.
/// - A note value will never exceed 2^63 zatoshis.
///
/// Returns the internal account reference of the account that received the output.
#[cfg(feature = "postgres")]
#[allow(dead_code)] // Used internally during block scanning
pub(crate) async fn put_received_note<T, P>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    output: &T,
    tx_ref: TxRef,
    target_or_mined_height: Option<BlockHeight>,
    spent_in: Option<TxRef>,
) -> Result<AccountRef, SqlxClientError>
where
    T: ReceivedSaplingOutput<AccountId = AccountUuid>,
    P: consensus::Parameters,
{
    // Look up the internal account ID
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(output.account_id().expose_uuid())
    .fetch_optional(pool)
    .await?;

    let account_id = match account_row {
        Some((id,)) => AccountRef(id),
        None => return Err(SqlxClientError::AccountNotFound(output.account_id())),
    };

    // Ensure address record exists for external outputs
    let address_id = ensure_address(
        pool,
        params,
        wallet_id,
        account_id,
        output,
        target_or_mined_height,
    )
    .await?;

    let rcm = output.note().rcm().to_repr();
    let to = output.note().recipient();
    let diversifier = to.diversifier();

    // Convert memo to bytes if present
    let memo_bytes: Option<Vec<u8>> = output.memo().map(|m| m.as_slice().to_vec());

    // Key scope encoding: External = 0, Internal = 1
    let key_scope_code: Option<i64> = output.recipient_key_scope().map(|s| match s {
        Scope::External => 0i64,
        Scope::Internal => 1i64,
    });

    // Insert or update the received note
    let query = r#"
        INSERT INTO sapling_received_notes (
            wallet_id, tx_id, output_index, account_id, address_id,
            diversifier, value, rcm, memo, nf,
            is_change, commitment_tree_position,
            recipient_key_scope
        )
        VALUES (
            $1, $2, $3, $4, $5,
            $6, $7, $8, $9, $10,
            $11, $12,
            $13
        )
        ON CONFLICT (wallet_id, tx_id, output_index) DO UPDATE
        SET account_id = EXCLUDED.account_id,
            address_id = COALESCE(EXCLUDED.address_id, sapling_received_notes.address_id),
            diversifier = EXCLUDED.diversifier,
            value = EXCLUDED.value,
            rcm = EXCLUDED.rcm,
            nf = COALESCE(EXCLUDED.nf, sapling_received_notes.nf),
            memo = COALESCE(EXCLUDED.memo, sapling_received_notes.memo),
            is_change = sapling_received_notes.is_change OR EXCLUDED.is_change,
            commitment_tree_position = COALESCE(EXCLUDED.commitment_tree_position, sapling_received_notes.commitment_tree_position),
            recipient_key_scope = EXCLUDED.recipient_key_scope
        RETURNING id
    "#;

    let received_note_id: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_ref.0)
        .bind(output.index() as i32)
        .bind(account_id.0)
        .bind(address_id.map(|a| a.0))
        .bind(&diversifier.0[..])
        .bind(output.note().value().inner() as i64)
        .bind(&rcm[..])
        .bind(memo_bytes)
        .bind(output.nullifier().map(|nf| nf.0.to_vec()))
        .bind(output.is_change())
        .bind(
            output
                .note_commitment_tree_position()
                .map(|p| u64::from(p) as i64),
        )
        .bind(key_scope_code)
        .fetch_one(pool)
        .await?;

    // If spent_in is provided, also record the spend
    if let Some(spent_in) = spent_in {
        let spend_query = r#"
            INSERT INTO sapling_received_note_spends (wallet_id, sapling_received_note_id, transaction_id)
            VALUES ($1, $2, $3)
            ON CONFLICT (wallet_id, sapling_received_note_id, transaction_id) DO NOTHING
        "#;

        sqlx_core::query::query(spend_query)
            .bind(wallet_id.expose_uuid())
            .bind(received_note_id.0)
            .bind(spent_in.0)
            .execute(pool)
            .await?;
    }

    Ok(account_id)
}
