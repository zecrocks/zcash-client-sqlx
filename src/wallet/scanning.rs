//! Scanning-related functions for the sqlx-backed wallet implementation.
//!
//! This module provides scan queue management and related utilities,
//! matching the SQLite implementation in `zcash_client_sqlite/src/wallet/scanning.rs`.

use std::cmp::{max, min};
use std::ops::Range;

use tracing::debug;

use zcash_client_backend::data_api::{
    SAPLING_SHARD_HEIGHT,
    scanning::{ScanPriority, ScanRange, spanning_tree::SpanningTree},
};
use zcash_protocol::{
    ShieldedProtocol,
    consensus::{self, BlockHeight, NetworkUpgrade},
};

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;

#[cfg(feature = "postgres")]
use crate::pool::Pool;

use super::common::{TableConstants, height_to_i64, i64_to_height};
use crate::{SqlxClientError, WalletId};

/// The default number of blocks to retain when pruning.
/// This matches the SQLite PRUNING_DEPTH constant.
pub const PRUNING_DEPTH: u32 = 100;

/// The number of blocks to look ahead when verifying chain connectivity.
/// This matches the SQLite VERIFY_LOOKAHEAD constant.
pub const VERIFY_LOOKAHEAD: u32 = 10;

/// Converts a ScanPriority to its database integer representation.
///
/// Priority codes match the SQLite implementation:
/// - 0: Ignored
/// - 10: Scanned
/// - 20: Historic
/// - 30: OpenAdjacent
/// - 40: FoundNote
/// - 50: ChainTip
/// - 60: Verify
pub fn priority_code(priority: &ScanPriority) -> i64 {
    use ScanPriority::*;
    match priority {
        Ignored => 0,
        Scanned => 10,
        Historic => 20,
        OpenAdjacent => 30,
        FoundNote => 40,
        ChainTip => 50,
        Verify => 60,
    }
}

/// Parses a database integer value back to a ScanPriority.
///
/// Returns None if the code is not recognized.
pub fn parse_priority_code(code: i64) -> Option<ScanPriority> {
    use ScanPriority::*;
    match code {
        0 => Some(Ignored),
        10 => Some(Scanned),
        20 => Some(Historic),
        30 => Some(OpenAdjacent),
        40 => Some(FoundNote),
        50 => Some(ChainTip),
        60 => Some(Verify),
        _ => None,
    }
}

/// Retrieves scan ranges from the scan queue ordered by priority.
///
/// # Arguments
/// * `pool` - Database connection pool
/// * `wallet_id` - The wallet to query scan ranges for
/// * `min_priority` - Only return ranges with priority >= this value
///
/// Ranges are returned ordered by priority DESC, then block_range_end DESC
/// (matching SQLite's behavior).
#[cfg(feature = "postgres")]
pub async fn suggest_scan_ranges(
    pool: &Pool,
    wallet_id: WalletId,
    min_priority: ScanPriority,
) -> Result<Vec<ScanRange>, SqlxClientError> {
    let min_priority_code = priority_code(&min_priority);

    let query = r#"
        SELECT block_range_start, block_range_end, priority
        FROM scan_queue
        WHERE wallet_id = $1 AND priority >= $2
        ORDER BY priority DESC, block_range_end DESC
    "#;

    let rows: Vec<(i64, i64, i64)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(min_priority_code)
        .fetch_all(pool)
        .await?;

    let mut result = Vec::with_capacity(rows.len());
    for (start, end, priority) in rows {
        let range = Range {
            start: i64_to_height(start)?,
            end: i64_to_height(end)?,
        };
        let scan_priority = parse_priority_code(priority).ok_or_else(|| {
            SqlxClientError::CorruptedData(format!("scan priority not recognized: {priority}"))
        })?;
        result.push(ScanRange::from_parts(range, scan_priority));
    }

    Ok(result)
}

/// Inserts multiple scan queue entries.
#[cfg(feature = "postgres")]
pub async fn insert_queue_entries<'a>(
    pool: &Pool,
    wallet_id: WalletId,
    entries: impl Iterator<Item = &'a ScanRange>,
) -> Result<(), SqlxClientError> {
    for entry in entries {
        if !entry.is_empty() {
            let query = r#"
                INSERT INTO scan_queue (wallet_id, block_range_start, block_range_end, priority)
                VALUES ($1, $2, $3, $4)
            "#;

            sqlx_core::query::query(query)
                .bind(wallet_id.expose_uuid())
                .bind(height_to_i64(entry.block_range().start))
                .bind(height_to_i64(entry.block_range().end))
                .bind(priority_code(&entry.priority()))
                .execute(pool)
                .await?;
        }
    }

    Ok(())
}

/// Replaces scan queue entries overlapping with the given range.
///
/// This function queries existing ranges that overlap or are adjacent to `query_range`,
/// builds a spanning tree to coalesce them with the new entries, and then atomically
/// deletes the old entries and inserts the new coalesced ranges.
///
/// This matches the SQLite `replace_queue_entries` implementation.
#[cfg(feature = "postgres")]
pub async fn replace_queue_entries(
    pool: &Pool,
    wallet_id: WalletId,
    query_range: &Range<BlockHeight>,
    entries: impl Iterator<Item = ScanRange>,
    force_rescans: bool,
) -> Result<(), SqlxClientError> {
    // Query overlapping/adjacent ranges
    let overlap_query = r#"
        SELECT block_range_start, block_range_end, priority
        FROM scan_queue
        WHERE wallet_id = $1
          AND NOT (block_range_start > $3 OR $2 > block_range_end)
        ORDER BY block_range_end
    "#;

    let rows: Vec<(i64, i64, i64)> = sqlx_core::query_as::query_as(overlap_query)
        .bind(wallet_id.expose_uuid())
        .bind(height_to_i64(query_range.start))
        .bind(height_to_i64(query_range.end))
        .fetch_all(pool)
        .await?;

    // Build the spanning tree from existing ranges
    let mut to_create: Option<SpanningTree> = None;
    let mut to_delete_ends: Vec<i64> = vec![];

    for (start, end, priority_val) in rows {
        let entry = ScanRange::from_parts(
            Range {
                start: i64_to_height(start)?,
                end: i64_to_height(end)?,
            },
            parse_priority_code(priority_val).ok_or_else(|| {
                SqlxClientError::CorruptedData(format!(
                    "scan priority not recognized: {priority_val}"
                ))
            })?,
        );
        to_delete_ends.push(end);
        to_create = if let Some(cur) = to_create {
            Some(cur.insert(entry, force_rescans))
        } else {
            Some(SpanningTree::Leaf(entry))
        };
    }

    // Insert new entries into the spanning tree
    for entry in entries {
        to_create = if let Some(cur) = to_create {
            Some(cur.insert(entry, force_rescans))
        } else {
            Some(SpanningTree::Leaf(entry))
        };
    }

    // Apply the changes
    if let Some(tree) = to_create {
        // Delete old entries
        if !to_delete_ends.is_empty() {
            let delete_query = r#"
                DELETE FROM scan_queue
                WHERE wallet_id = $1 AND block_range_end = ANY($2)
            "#;

            sqlx_core::query::query(delete_query)
                .bind(wallet_id.expose_uuid())
                .bind(&to_delete_ends)
                .execute(pool)
                .await?;
        }

        // Insert new coalesced entries
        let scan_ranges = tree.into_vec();
        insert_queue_entries(pool, wallet_id, scan_ranges.iter()).await?;
    }

    Ok(())
}

/// Gets the maximum subtree end height for a given protocol.
#[cfg(feature = "postgres")]
async fn tip_shard_end_height(
    pool: &Pool,
    protocol: ShieldedProtocol,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let tables = TableConstants::for_protocol(protocol);
    let query = format!("SELECT MAX(subtree_end_height) FROM {}", tables.tree_shards);

    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(&query)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((Some(h),)) => Ok(Some(i64_to_height(h)?)),
        _ => Ok(None),
    }
}

/// Gets the wallet birthday (minimum account birthday height).
#[cfg(feature = "postgres")]
async fn get_wallet_birthday(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(
        "SELECT MIN(birthday_height) FROM accounts WHERE wallet_id = $1 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .fetch_optional(pool)
    .await?;

    match row {
        Some((Some(h),)) => Ok(Some(i64_to_height(h)?)),
        _ => Ok(None),
    }
}

/// Gets the per-wallet max scanned height from the wallets table.
/// Unlike `block_height_extrema` which reads the global `blocks` table,
/// this returns the max height scanned by a specific wallet, which is
/// critical for multi-wallet correctness.
#[cfg(feature = "postgres")]
async fn wallet_max_scanned_height(
    pool: &Pool,
    wallet_id: WalletId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let row: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT max_scanned_height FROM wallets WHERE id = $1")
            .bind(wallet_id.expose_uuid())
            .fetch_optional(pool)
            .await?;

    match row {
        Some((Some(h),)) => Ok(Some(i64_to_height(h)?)),
        _ => Ok(None),
    }
}

/// Updates the scan queue with new ranges based on the chain tip.
///
/// This function analyzes the current chain state and creates appropriate
/// scan ranges with correct priorities based on:
/// - Wallet birthday
/// - Maximum scanned height
/// - Shard boundaries
/// - Chain tip
///
/// This matches the SQLite `update_chain_tip` implementation.
#[cfg(feature = "postgres")]
pub async fn update_chain_tip<P: consensus::Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    new_tip: BlockHeight,
) -> Result<(), SqlxClientError> {
    // If the caller provided a chain tip that is before Sapling activation, do nothing.
    let sapling_activation = match params.activation_height(NetworkUpgrade::Sapling) {
        Some(h) if h <= new_tip => h,
        _ => return Ok(()),
    };

    // Read the previous max scanned height for THIS wallet (not global blocks table).
    // In multi-wallet PostgreSQL, the blocks table is shared across wallets, so we
    // track per-wallet scan progress in wallets.max_scanned_height.
    let max_scanned = wallet_max_scanned_height(pool, wallet_id).await?;

    // Read the wallet birthday (if known).
    let wallet_birthday = get_wallet_birthday(pool, wallet_id).await?;

    // If the chain tip is below the prior max scanned height, then the caller has caught
    // the chain in the middle of a reorg. Do nothing.
    match max_scanned {
        Some(h) if new_tip < h => return Ok(()),
        _ => (),
    };

    // `ScanRange` uses an exclusive upper bound.
    let chain_end = new_tip + 1;

    // Read the maximum height from each of the shards tables.
    let sapling_shard_tip = tip_shard_end_height(pool, ShieldedProtocol::Sapling).await?;

    #[cfg(feature = "orchard")]
    let orchard_shard_tip = tip_shard_end_height(pool, ShieldedProtocol::Orchard).await?;

    #[cfg(feature = "orchard")]
    let min_shard_tip = match (sapling_shard_tip, orchard_shard_tip) {
        (None, None) => None,
        (None, Some(o)) => Some(o),
        (Some(s), None) => Some(s),
        (Some(s), Some(o)) => Some(std::cmp::min(s, o)),
    };
    #[cfg(not(feature = "orchard"))]
    let min_shard_tip = sapling_shard_tip;

    // Create a scanning range for the fragment of the last shard leading up to new tip.
    let tip_shard_entry = min_shard_tip.filter(|h| h < &chain_end).map(|h| {
        let min_to_scan = wallet_birthday.filter(|b| b > &h).unwrap_or(h);
        ScanRange::from_parts(min_to_scan..chain_end, ScanPriority::ChainTip)
    });

    // Create scan ranges to either validate potentially invalid blocks at the wallet's
    // view of the chain tip, or connect the prior tip to the new tip.
    let tip_entry = max_scanned.map_or_else(
        || {
            // No blocks have been scanned
            wallet_birthday.map_or_else(
                // No wallet birthday - ignore all blocks up to the chain tip
                || ScanRange::from_parts(sapling_activation..chain_end, ScanPriority::Ignored),
                // Has wallet birthday - mark as Historic for recovery
                |wallet_birthday| {
                    ScanRange::from_parts(wallet_birthday..chain_end, ScanPriority::Historic)
                },
            )
        },
        |max_scanned| {
            let min_unscanned = max_scanned + 1;

            if tip_shard_entry.is_none() {
                // No shard metadata - linear scanning with Historic priority
                ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::Historic)
            } else {
                // Determine the stable height
                let stable_height = new_tip.saturating_sub(PRUNING_DEPTH);

                if max_scanned > stable_height {
                    // Steady-state case - wallet is close to chain tip
                    ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::ChainTip)
                } else {
                    // Max scanned is stable - verify connectivity
                    ScanRange::from_parts(
                        min_unscanned..min(stable_height + 1, min_unscanned + VERIFY_LOOKAHEAD),
                        ScanPriority::Verify,
                    )
                }
            }
        },
    );

    if let Some(entry) = &tip_shard_entry {
        debug!("{} will update latest shard", entry);
    }
    debug!("{} will connect prior scanned state to new tip", tip_entry);

    let query_range = match tip_shard_entry.as_ref() {
        Some(se) => Range {
            start: min(se.block_range().start, tip_entry.block_range().start),
            end: max(se.block_range().end, tip_entry.block_range().end),
        },
        None => tip_entry.block_range().clone(),
    };

    // Persist the updated scan queue entries
    replace_queue_entries(
        pool,
        wallet_id,
        &query_range,
        tip_shard_entry.into_iter().chain(Some(tip_entry)),
        false,
    )
    .await?;

    Ok(())
}

/// Marks a range as scanned and updates the scan queue accordingly.
///
/// This function is called after `scan_cached_blocks` to update the scan queue
/// with the scanned range and any extended ranges needed for note spendability.
#[cfg(feature = "postgres")]
pub async fn scan_complete<P: consensus::Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    range: Range<BlockHeight>,
    wallet_note_positions: &[(ShieldedProtocol, incrementalmerkletree::Position)],
) -> Result<(), SqlxClientError> {
    use incrementalmerkletree::Address;
    use std::collections::BTreeSet;

    // Read the wallet birthday
    let wallet_birthday = get_wallet_birthday(pool, wallet_id).await?;

    // Determine the range of block heights for which we will be updating the scan queue.
    let extended_range = {
        let mut required_sapling_subtrees = BTreeSet::new();
        #[cfg(feature = "orchard")]
        let mut required_orchard_subtrees = BTreeSet::new();

        for (protocol, position) in wallet_note_positions {
            match protocol {
                ShieldedProtocol::Sapling => {
                    required_sapling_subtrees.insert(
                        Address::above_position(SAPLING_SHARD_HEIGHT.into(), *position).index(),
                    );
                }
                ShieldedProtocol::Orchard => {
                    #[cfg(feature = "orchard")]
                    required_orchard_subtrees.insert(
                        Address::above_position(ORCHARD_SHARD_HEIGHT.into(), *position).index(),
                    );
                }
            }
        }

        let extended_range = extend_range(
            pool,
            &range,
            required_sapling_subtrees,
            ShieldedProtocol::Sapling,
            params.activation_height(NetworkUpgrade::Sapling),
            wallet_birthday,
        )
        .await?;

        #[cfg(feature = "orchard")]
        let extended_range = extend_range(
            pool,
            extended_range.as_ref().unwrap_or(&range),
            required_orchard_subtrees,
            ShieldedProtocol::Orchard,
            params.activation_height(NetworkUpgrade::Nu5),
            wallet_birthday,
        )
        .await?
        .or(extended_range);

        #[allow(clippy::let_and_return)]
        extended_range
    };

    let query_range = extended_range.clone().unwrap_or_else(|| range.clone());

    let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);

    // Create extended ranges if needed
    let extended_before = extended_range
        .as_ref()
        .map(|extended| ScanRange::from_parts(extended.start..range.start, ScanPriority::FoundNote))
        .filter(|range| !range.is_empty());
    let extended_after = extended_range
        .map(|extended| ScanRange::from_parts(range.end..extended.end, ScanPriority::FoundNote))
        .filter(|range| !range.is_empty());

    let replacement = Some(scanned)
        .into_iter()
        .chain(extended_before)
        .chain(extended_after);

    replace_queue_entries(pool, wallet_id, &query_range, replacement, false).await?;

    Ok(())
}

/// Extends a scan range to include subtree boundaries.
#[cfg(feature = "postgres")]
async fn extend_range(
    pool: &Pool,
    range: &Range<BlockHeight>,
    required_subtree_indices: std::collections::BTreeSet<u64>,
    protocol: ShieldedProtocol,
    fallback_start_height: Option<BlockHeight>,
    birthday_height: Option<BlockHeight>,
) -> Result<Option<Range<BlockHeight>>, SqlxClientError> {
    let tables = TableConstants::for_protocol(protocol);

    let subtree_index_bounds = required_subtree_indices
        .iter()
        .min()
        .zip(required_subtree_indices.iter().max());

    // Helper function to get shard end height
    async fn get_shard_end(
        pool: &Pool,
        table: &str,
        index: u64,
    ) -> Result<Option<BlockHeight>, SqlxClientError> {
        let query = format!(
            "SELECT subtree_end_height FROM {} WHERE shard_index = $1",
            table
        );
        let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(&query)
            .bind(index as i64)
            .fetch_optional(pool)
            .await?;

        match row {
            Some((Some(h),)) => Ok(Some(i64_to_height(h)?)),
            _ => Ok(None),
        }
    }

    if let Some((min_idx, max_idx)) = subtree_index_bounds {
        let range_min = if *min_idx > 0 {
            get_shard_end(pool, tables.tree_shards, *min_idx - 1).await?
        } else {
            fallback_start_height
        };

        // Bound the minimum to the wallet birthday
        let range_min = range_min.map(|h| birthday_height.map_or(h, |b| std::cmp::max(b, h)));

        // Get the block height for the end of the current shard
        let range_max = get_shard_end(pool, tables.tree_shards, *max_idx)
            .await?
            .map(|end| end + 1);

        Ok(Some(Range {
            start: range.start.min(range_min.unwrap_or(range.start)),
            end: range.end.max(range_max.unwrap_or(range.end)),
        }))
    } else {
        Ok(None)
    }
}
