//! Common utilities for wallet operations.

use bitflags::bitflags;
use zcash_client_backend::data_api::{
    AccountMeta, PoolMeta,
    wallet::{ConfirmationsPolicy, TargetHeight},
};
use zcash_keys::address::UnifiedAddress;
use zcash_keys::keys::ReceiverRequirement;
use zcash_protocol::{ShieldedProtocol, consensus::BlockHeight, value::Zatoshis};

#[cfg(feature = "transparent-inputs")]
use transparent::address::TransparentAddress;

#[cfg(feature = "postgres")]
use crate::pool::Pool;

use crate::{AccountUuid, SqlxClientError, WalletId};

bitflags! {
    /// Flags indicating which receiver types are present in an address.
    pub(crate) struct ReceiverFlags: i64 {
        /// The address did not contain any recognized receiver types.
        const UNKNOWN = 0b00000000;
        /// The associated address can receive transparent p2pkh outputs.
        const P2PKH = 0b00000001;
        /// The associated address can receive transparent p2sh outputs.
        const P2SH = 0b00000010;
        /// The associated address can receive Sapling outputs.
        const SAPLING = 0b00000100;
        /// The associated address can receive Orchard outputs.
        const ORCHARD = 0b00001000;
    }
}

impl ReceiverFlags {
    /// Returns the flags for receivers that are required by the given requirements.
    pub(crate) fn required(request: zcash_keys::keys::ReceiverRequirements) -> Self {
        let mut flags = ReceiverFlags::UNKNOWN;
        if matches!(request.orchard(), ReceiverRequirement::Require) {
            flags |= ReceiverFlags::ORCHARD;
        }
        if matches!(request.sapling(), ReceiverRequirement::Require) {
            flags |= ReceiverFlags::SAPLING;
        }
        if matches!(request.p2pkh(), ReceiverRequirement::Require) {
            flags |= ReceiverFlags::P2PKH;
        }
        flags
    }

    /// Returns the flags for receivers that should be omitted per the given requirements.
    pub(crate) fn omitted(request: zcash_keys::keys::ReceiverRequirements) -> Self {
        let mut flags = ReceiverFlags::UNKNOWN;
        if matches!(request.orchard(), ReceiverRequirement::Omit) {
            flags |= ReceiverFlags::ORCHARD;
        }
        if matches!(request.sapling(), ReceiverRequirement::Omit) {
            flags |= ReceiverFlags::SAPLING;
        }
        if matches!(request.p2pkh(), ReceiverRequirement::Omit) {
            flags |= ReceiverFlags::P2PKH;
        }
        flags
    }
}

/// Computes the [`ReceiverFlags`] describing the types of outputs that the provided
/// unified address can receive.
impl From<&UnifiedAddress> for ReceiverFlags {
    fn from(value: &UnifiedAddress) -> Self {
        #[cfg(feature = "transparent-inputs")]
        use TransparentAddress::{PublicKeyHash, ScriptHash};

        let mut flags = ReceiverFlags::UNKNOWN;
        #[cfg(feature = "transparent-inputs")]
        match value.transparent() {
            Some(PublicKeyHash(_)) => {
                flags |= ReceiverFlags::P2PKH;
            }
            Some(ScriptHash(_)) => {
                flags |= ReceiverFlags::P2SH;
            }
            _ => {}
        }
        #[cfg(not(feature = "transparent-inputs"))]
        let _ = value.transparent();

        if value.has_sapling() {
            flags |= ReceiverFlags::SAPLING;
        }
        if value.has_orchard() {
            flags |= ReceiverFlags::ORCHARD;
        }
        flags
    }
}

/// Converts a block height to a database integer value.
pub fn height_to_i64(height: BlockHeight) -> i64 {
    u32::from(height) as i64
}

/// Converts a database integer value to a block height.
pub fn i64_to_height(height: i64) -> Result<BlockHeight, SqlxClientError> {
    if height < 0 {
        return Err(SqlxClientError::CorruptedBlockHeight(height));
    }
    Ok(BlockHeight::from_u32(height as u32))
}

/// Converts an optional database integer to an optional block height.
pub fn i64_to_optional_height(height: Option<i64>) -> Result<Option<BlockHeight>, SqlxClientError> {
    height.map(i64_to_height).transpose()
}

/// Table name constants for different protocols.
pub struct TableConstants {
    pub received_notes: &'static str,
    pub received_note_spends: &'static str,
    pub tree_shards: &'static str,
    pub tree_cap: &'static str,
    pub tree_checkpoints: &'static str,
    pub tree_checkpoint_marks: &'static str,
    pub output_index_col: &'static str,
}

impl TableConstants {
    pub const SAPLING: Self = Self {
        received_notes: "sapling_received_notes",
        received_note_spends: "sapling_received_note_spends",
        tree_shards: "sapling_tree_shards",
        tree_cap: "sapling_tree_cap",
        tree_checkpoints: "sapling_tree_checkpoints",
        tree_checkpoint_marks: "sapling_tree_checkpoint_marks",
        output_index_col: "output_index",
    };

    #[cfg(feature = "orchard")]
    pub const ORCHARD: Self = Self {
        received_notes: "orchard_received_notes",
        received_note_spends: "orchard_received_note_spends",
        tree_shards: "orchard_tree_shards",
        tree_cap: "orchard_tree_cap",
        tree_checkpoints: "orchard_tree_checkpoints",
        tree_checkpoint_marks: "orchard_tree_checkpoint_marks",
        output_index_col: "action_index",
    };

    /// Returns the table constants for a given protocol.
    pub fn for_protocol(protocol: ShieldedProtocol) -> Self {
        match protocol {
            ShieldedProtocol::Sapling => Self::SAPLING,
            #[cfg(feature = "orchard")]
            ShieldedProtocol::Orchard => Self::ORCHARD,
            #[cfg(not(feature = "orchard"))]
            ShieldedProtocol::Orchard => {
                panic!("Orchard protocol not supported without orchard feature")
            }
        }
    }
}

/// Pool type codes used in the database.
pub mod pool_code {
    /// Transparent pool code (matches SQLite implementation).
    pub const TRANSPARENT: i32 = 0;
    /// Sapling pool code (matches SQLite implementation).
    pub const SAPLING: i32 = 2;
    /// Orchard pool code (matches SQLite implementation).
    pub const ORCHARD: i32 = 3;
}

/// Computes the anchor height based on target height and confirmations policy.
///
/// The anchor height is the maximum height at which notes can be considered spendable.
/// For n confirmations, a note is spendable if mined_height <= target_height - n.
/// This matches SQLite's `get_anchor_height` which uses `trusted()` confirmations.
///
/// Note: The actual spendability of individual notes is determined by
/// `confirmations_until_spendable()` which considers the note's key scope and trust status.
/// The anchor height is a conservative estimate for commitment tree purposes.
pub fn compute_anchor_height(
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> BlockHeight {
    // Get the effective height from the target
    let effective_height: BlockHeight = target_height.into();

    // Use trusted confirmations to match SQLite's behavior
    // (get_wallet_summary line 2040 uses confirmations_policy.trusted())
    let min_confirmations = confirmations_policy.trusted().get();

    // Calculate anchor height = target - confirmations
    // A note at height H is spendable when H <= anchor_height
    effective_height.saturating_sub(min_confirmations)
}

/// Gets the max checkpointed height for a protocol that satisfies the confirmations requirement.
///
/// This queries the tree checkpoints table to find the highest checkpoint at or below
/// the max allowed checkpoint height. Returns None if no valid checkpoint exists.
///
/// Matches SQLite's `get_max_checkpointed_height` implementation.
#[cfg(feature = "postgres")]
pub async fn get_max_checkpointed_height(
    pool: &crate::pool::Pool,
    _wallet_id: WalletId,
    protocol: ShieldedProtocol,
    target_height: TargetHeight,
    min_confirmations: std::num::NonZeroU32,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let tables = TableConstants::for_protocol(protocol);

    // max_checkpoint_height = target_height - min_confirmations
    let effective_height: BlockHeight = target_height.into();
    let max_checkpoint_height = effective_height.saturating_sub(min_confirmations.get());
    let max_checkpoint_height_i64 = height_to_i64(max_checkpoint_height);

    // Global table - tree checkpoints are shared across all wallets
    let query = format!(
        "SELECT checkpoint_id
         FROM {}
         WHERE checkpoint_id <= $1
         ORDER BY checkpoint_id DESC
         LIMIT 1",
        tables.tree_checkpoints
    );

    let row: Option<(i64,)> = sqlx_core::query_as::query_as(&query)
        .bind(max_checkpoint_height_i64)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((h,)) => Ok(Some(i64_to_height(h)?)),
        None => Ok(None),
    }
}

/// Gets the anchor height for spendable notes.
///
/// Returns the minimum valid anchor height across all enabled shielded protocols.
/// Returns None if no valid checkpoint exists for the confirmations requirement.
///
/// Matches SQLite's `get_anchor_height` implementation.
#[cfg(feature = "postgres")]
pub async fn get_anchor_height(
    pool: &crate::pool::Pool,
    wallet_id: WalletId,
    target_height: TargetHeight,
    min_confirmations: std::num::NonZeroU32,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let sapling_anchor = get_max_checkpointed_height(
        pool,
        wallet_id,
        ShieldedProtocol::Sapling,
        target_height,
        min_confirmations,
    )
    .await?;

    #[cfg(feature = "orchard")]
    let orchard_anchor = get_max_checkpointed_height(
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
    Ok(sapling_anchor
        .zip(orchard_anchor)
        .map(|(s, o)| std::cmp::min(s, o))
        .or(sapling_anchor)
        .or(orchard_anchor))
}

/// Gets the chain tip height (global - same for all wallets).
#[cfg(feature = "postgres")]
pub async fn get_chain_tip(
    pool: &Pool,
    _wallet_id: WalletId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    // blocks table is global - all wallets share the same blockchain data
    let row: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    match row {
        Some((Some(h),)) => Ok(Some(i64_to_height(h)?)),
        _ => Ok(None),
    }
}

/// Counts unspent notes and their total value for a specific protocol.
/// Matches SQLite's `unspent_notes_meta` implementation.
#[cfg(feature = "postgres")]
pub async fn count_unspent_notes(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
    protocol: ShieldedProtocol,
    min_value: i64,
    target_height: BlockHeight,
    exclude: &[i64],
) -> Result<Option<PoolMeta>, SqlxClientError> {
    let tables = TableConstants::for_protocol(protocol);
    let target_height_i64 = height_to_i64(target_height);

    // Build the query dynamically based on the protocol
    // The column name for the spent note ID varies by protocol
    let spent_note_id_col = match protocol {
        ShieldedProtocol::Sapling => "sapling_received_note_id",
        ShieldedProtocol::Orchard => "orchard_received_note_id",
    };

    // This query matches SQLite's unspent_notes_meta:
    // - No anchor height filter on receiving transaction (just mined_height IS NOT NULL)
    // - No nullifier check (nf IS NOT NULL is not required)
    // - Spent notes exclusion uses tx_unexpired_condition logic with target_height
    let query = format!(
        r#"
        SELECT COUNT(*)::BIGINT as note_count, COALESCE(SUM(rn.value), 0)::BIGINT as total_value
        FROM {} rn
        INNER JOIN accounts a ON a.id = rn.account_id
        INNER JOIN transactions t ON t.id = rn.tx_id
        WHERE rn.wallet_id = $1
          AND a.uuid = $2
          AND a.ufvk IS NOT NULL
          AND rn.value >= $3
          AND t.mined_height IS NOT NULL
          AND rn.id NOT IN (SELECT unnest($4::BIGINT[]))
          AND rn.id NOT IN (
              SELECT rns.{}
              FROM {} rns
              INNER JOIN transactions stx ON stx.id = rns.transaction_id
              WHERE stx.mined_height < $5
                 OR stx.expiry_height = 0
                 OR stx.expiry_height >= $5
                 OR (stx.expiry_height IS NULL
                     AND stx.min_observed_height + 40 >= $5)
          )
        "#,
        tables.received_notes, spent_note_id_col, tables.received_note_spends,
    );

    let row: (i64, i64) = sqlx_core::query_as::query_as(&query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(min_value)
        .bind(exclude)
        .bind(target_height_i64)
        .fetch_one(pool)
        .await?;

    // Return Some even when count is 0, as the change strategy needs accurate counts.
    // None should only be returned if the query cannot be evaluated (e.g., filter issue).
    let value =
        Zatoshis::from_nonnegative_i64(row.1).map_err(|_| SqlxClientError::CorruptedOutput)?;

    Ok(Some(PoolMeta::new(row.0 as usize, value)))
}

/// Gets account metadata (unspent note counts and values) for all pools.
#[cfg(feature = "postgres")]
pub async fn get_account_metadata_impl(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
    min_value: i64,
    target_height: BlockHeight,
    exclude_sapling: &[i64],
    #[cfg(feature = "orchard")] exclude_orchard: &[i64],
) -> Result<AccountMeta, SqlxClientError> {
    let sapling_meta = count_unspent_notes(
        pool,
        wallet_id,
        account,
        ShieldedProtocol::Sapling,
        min_value,
        target_height,
        exclude_sapling,
    )
    .await?;

    #[cfg(feature = "orchard")]
    let orchard_meta = count_unspent_notes(
        pool,
        wallet_id,
        account,
        ShieldedProtocol::Orchard,
        min_value,
        target_height,
        exclude_orchard,
    )
    .await?;

    #[cfg(feature = "orchard")]
    return Ok(AccountMeta::new(sapling_meta, orchard_meta));

    #[cfg(not(feature = "orchard"))]
    Ok(AccountMeta::new(sapling_meta, None))
}

/// The marginal fee per action (5000 zatoshis = 0.00005 ZEC).
/// Notes with value less than this are considered dust and excluded from selection.
pub const MARGINAL_FEE: i64 = 5000;

/// Gets nullifiers from the database for notes matching the given query type.
///
/// This function supports both unspent-only and all-nullifiers queries, which is used
/// for different scanning strategies.
///
/// Matches SQLite's `get_nullifiers` implementation in common.rs.
#[cfg(feature = "postgres")]
pub async fn get_nullifiers<N, F: Fn(&[u8]) -> Result<N, SqlxClientError>>(
    pool: &Pool,
    wallet_id: WalletId,
    protocol: ShieldedProtocol,
    query: zcash_client_backend::data_api::NullifierQuery,
    parse_nf: F,
) -> Result<Vec<(AccountUuid, N)>, SqlxClientError> {
    use zcash_client_backend::data_api::NullifierQuery;

    let tables = TableConstants::for_protocol(protocol);
    let spent_note_id_col = match protocol {
        ShieldedProtocol::Sapling => "sapling_received_note_id",
        ShieldedProtocol::Orchard => "orchard_received_note_id",
    };

    let sql = match query {
        NullifierQuery::Unspent => {
            // Only retrieve nullifiers for notes that:
            // 1. Have a nullifier set
            // 2. Are mined (in a block)
            // 3. Are not spent by a mined tx or a tx that won't expire
            format!(
                r#"
                SELECT a.uuid, rn.nf
                FROM {} rn
                JOIN accounts a ON a.id = rn.account_id
                JOIN transactions tx ON tx.id = rn.tx_id
                WHERE rn.wallet_id = $1
                  AND rn.nf IS NOT NULL
                  AND tx.mined_height IS NOT NULL
                  AND rn.id NOT IN (
                      SELECT rns.{}
                      FROM {} rns
                      JOIN transactions stx ON stx.id = rns.transaction_id
                      WHERE stx.mined_height IS NOT NULL  -- the spending tx is mined
                         OR stx.expiry_height = 0  -- the spending tx will not expire
                  )
                "#,
                tables.received_notes, spent_note_id_col, tables.received_note_spends
            )
        }
        NullifierQuery::All => {
            // Retrieve all nullifiers for this wallet
            format!(
                r#"
                SELECT a.uuid, rn.nf
                FROM {} rn
                JOIN accounts a ON a.id = rn.account_id
                WHERE rn.wallet_id = $1
                  AND rn.nf IS NOT NULL
                "#,
                tables.received_notes
            )
        }
    };

    let rows: Vec<(uuid::Uuid, Vec<u8>)> = sqlx_core::query_as::query_as(&sql)
        .bind(wallet_id.expose_uuid())
        .fetch_all(pool)
        .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (account_uuid, nf_bytes) in rows {
        let nf = parse_nf(&nf_bytes)?;
        result.push((AccountUuid::from_uuid(account_uuid), nf));
    }

    Ok(result)
}
