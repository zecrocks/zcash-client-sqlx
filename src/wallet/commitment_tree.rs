//! Commitment tree storage for the sqlx-backed wallet implementation.

use std::{
    collections::BTreeSet,
    io::{self, Cursor},
    marker::PhantomData,
    ops::Range,
    sync::Arc,
};

use incrementalmerkletree::{Address, Hashable, Level, Position};
use shardtree::{
    LocatedPrunableTree, LocatedTree, PrunableTree, RetentionFlags,
    error::ShardTreeError,
    store::{Checkpoint, ShardStore, TreeState},
};
use tokio::runtime::Handle;
use zcash_client_backend::{
    data_api::{SAPLING_SHARD_HEIGHT, chain::CommitmentTreeRoot},
    serialization::shardtree::{read_shard, write_shard},
};

#[cfg(feature = "orchard")]
use zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT;
use zcash_primitives::merkle_tree::HashSer;
use zcash_protocol::consensus::BlockHeight;

#[cfg(feature = "postgres")]
use crate::pool::Pool;

use crate::SqlxClientError;

/// A [`ShardStore`] implementation backed by sqlx.
///
/// Note: The commitment tree tables are global (shared across all wallets) since
/// the commitment tree represents on-chain state that is identical for all wallets.
pub struct SqlxShardStore<'a, H, const SHARD_HEIGHT: u8> {
    #[cfg(feature = "postgres")]
    pool: &'a Pool,
    #[cfg(not(feature = "postgres"))]
    pool: &'a (),
    table_prefix: &'static str,
    handle: Handle,
    _phantom: PhantomData<H>,
}

impl<'a, H, const SHARD_HEIGHT: u8> SqlxShardStore<'a, H, SHARD_HEIGHT> {
    const SHARD_ROOT_LEVEL: Level = Level::new(SHARD_HEIGHT);

    #[cfg(feature = "postgres")]
    pub(crate) fn new(pool: &'a Pool, table_prefix: &'static str, handle: Handle) -> Self {
        Self {
            pool,
            table_prefix,
            handle,
            _phantom: PhantomData,
        }
    }
}

// ============================================================================
// Async helper functions for database operations
// ============================================================================

#[cfg(feature = "postgres")]
async fn get_shard_async<H: HashSer>(
    pool: &Pool,
    table_prefix: &'static str,
    shard_root_addr: Address,
) -> Result<Option<LocatedPrunableTree<H>>, SqlxClientError> {
    let query = format!(
        "SELECT shard_data, root_hash FROM {}_tree_shards WHERE shard_index = $1",
        table_prefix
    );

    let row: Option<(Vec<u8>, Option<Vec<u8>>)> = sqlx_core::query_as::query_as(&query)
        .bind(shard_root_addr.index() as i64)
        .fetch_optional(pool)
        .await?;

    match row {
        None => Ok(None),
        Some((shard_data, root_hash)) => {
            let shard_tree =
                read_shard(&mut Cursor::new(shard_data)).map_err(SqlxClientError::Io)?;
            let located_tree = LocatedPrunableTree::from_parts(shard_root_addr, shard_tree)
                .map_err(|e| {
                    SqlxClientError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Tree contained invalid data at address {:?}", e),
                    ))
                })?;
            if let Some(root_hash_data) = root_hash {
                let root_hash =
                    H::read(Cursor::new(root_hash_data)).map_err(SqlxClientError::Io)?;
                Ok(Some(
                    located_tree.reannotate_root(Some(Arc::new(root_hash))),
                ))
            } else {
                Ok(Some(located_tree))
            }
        }
    }
}

#[cfg(feature = "postgres")]
async fn last_shard_async<H: HashSer>(
    pool: &Pool,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Option<LocatedPrunableTree<H>>, SqlxClientError> {
    let query = format!(
        "SELECT shard_index, shard_data FROM {}_tree_shards ORDER BY shard_index DESC LIMIT 1",
        table_prefix
    );

    let row: Option<(i64, Vec<u8>)> = sqlx_core::query_as::query_as(&query)
        .fetch_optional(pool)
        .await?;

    match row {
        None => Ok(None),
        Some((shard_index, shard_data)) => {
            let shard_root = Address::from_parts(shard_root_level, shard_index as u64);
            let shard_tree =
                read_shard(&mut Cursor::new(shard_data)).map_err(SqlxClientError::Io)?;
            let located_tree =
                LocatedPrunableTree::from_parts(shard_root, shard_tree).map_err(|e| {
                    SqlxClientError::Io(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("Tree contained invalid data at address {:?}", e),
                    ))
                })?;
            Ok(Some(located_tree))
        }
    }
}

#[cfg(feature = "postgres")]
async fn check_shard_discontinuity(
    pool: &Pool,
    table_prefix: &'static str,
    proposed_insertion_range: Range<u64>,
) -> Result<(), SqlxClientError> {
    let query = format!(
        "SELECT MIN(shard_index), MAX(shard_index) FROM {}_tree_shards",
        table_prefix
    );

    let row: (Option<i64>, Option<i64>) = sqlx_core::query_as::query_as(&query)
        .fetch_one(pool)
        .await?;

    if let (Some(stored_min), Some(stored_max)) = row {
        let stored_min = stored_min as u64;
        let stored_max = stored_max as u64;
        let (cur_start, cur_end) = (stored_min, stored_max + 1);
        let (ins_start, ins_end) = (proposed_insertion_range.start, proposed_insertion_range.end);
        if cur_start > ins_end || ins_start > cur_end {
            return Err(SqlxClientError::SubtreeDiscontinuity {
                attempted_insertion_range: proposed_insertion_range,
                existing_range: cur_start..cur_end,
            });
        }
    }

    Ok(())
}

#[cfg(feature = "postgres")]
async fn put_shard_async<H: HashSer>(
    pool: &Pool,
    table_prefix: &'static str,
    subtree: LocatedPrunableTree<H>,
) -> Result<(), SqlxClientError> {
    let subtree_root_hash = subtree
        .root()
        .annotation()
        .and_then(|ann| {
            ann.as_ref().map(|rc| {
                let mut root_hash = vec![];
                rc.write(&mut root_hash)?;
                Ok(root_hash)
            })
        })
        .transpose()
        .map_err(SqlxClientError::Io)?;

    let mut subtree_data = vec![];
    write_shard(&mut subtree_data, subtree.root()).map_err(SqlxClientError::Io)?;

    let shard_index = subtree.root_addr().index() as i64;

    check_shard_discontinuity(
        pool,
        table_prefix,
        shard_index as u64..(shard_index as u64) + 1,
    )
    .await?;

    let query = format!(
        r#"
        INSERT INTO {}_tree_shards (shard_index, root_hash, shard_data)
        VALUES ($1, $2, $3)
        ON CONFLICT (shard_index) DO UPDATE
        SET root_hash = EXCLUDED.root_hash, shard_data = EXCLUDED.shard_data
        "#,
        table_prefix
    );

    sqlx_core::query::query(&query)
        .bind(shard_index)
        .bind(subtree_root_hash)
        .bind(subtree_data)
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
async fn get_shard_roots_async(
    pool: &Pool,
    table_prefix: &'static str,
    shard_root_level: Level,
) -> Result<Vec<Address>, SqlxClientError> {
    let query = format!(
        "SELECT shard_index FROM {}_tree_shards ORDER BY shard_index",
        table_prefix
    );

    let rows: Vec<(i64,)> = sqlx_core::query_as::query_as(&query)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(idx,)| Address::from_parts(shard_root_level, idx as u64))
        .collect())
}

#[cfg(feature = "postgres")]
async fn truncate_shards_async(
    pool: &Pool,
    table_prefix: &'static str,
    shard_index: u64,
) -> Result<(), SqlxClientError> {
    let query = format!(
        "DELETE FROM {}_tree_shards WHERE shard_index >= $1",
        table_prefix
    );

    sqlx_core::query::query(&query)
        .bind(shard_index as i64)
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
async fn get_cap_async<H: HashSer>(
    pool: &Pool,
    table_prefix: &'static str,
) -> Result<PrunableTree<H>, SqlxClientError> {
    let query = format!(
        "SELECT cap_data FROM {}_tree_cap WHERE cap_id = 0",
        table_prefix
    );

    let row: Option<(Vec<u8>,)> = sqlx_core::query_as::query_as(&query)
        .fetch_optional(pool)
        .await?;

    match row {
        None => Ok(PrunableTree::empty()),
        Some((cap_data,)) => read_shard(&mut Cursor::new(cap_data)).map_err(SqlxClientError::Io),
    }
}

#[cfg(feature = "postgres")]
async fn put_cap_async<H: HashSer>(
    pool: &Pool,
    table_prefix: &'static str,
    cap: PrunableTree<H>,
) -> Result<(), SqlxClientError> {
    let mut cap_data = vec![];
    write_shard(&mut cap_data, &cap).map_err(SqlxClientError::Io)?;

    let query = format!(
        r#"
        INSERT INTO {}_tree_cap (cap_id, cap_data)
        VALUES (0, $1)
        ON CONFLICT (cap_id) DO UPDATE
        SET cap_data = EXCLUDED.cap_data
        "#,
        table_prefix
    );

    sqlx_core::query::query(&query)
        .bind(cap_data)
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
async fn min_checkpoint_id_async(
    pool: &Pool,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let query = format!(
        "SELECT MIN(checkpoint_id) FROM {}_tree_checkpoints",
        table_prefix
    );

    let row: (Option<i64>,) = sqlx_core::query_as::query_as(&query)
        .fetch_one(pool)
        .await?;

    Ok(row.0.map(|h| BlockHeight::from_u32(h as u32)))
}

#[cfg(feature = "postgres")]
async fn max_checkpoint_id_async(
    pool: &Pool,
    table_prefix: &'static str,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    let query = format!(
        "SELECT MAX(checkpoint_id) FROM {}_tree_checkpoints",
        table_prefix
    );

    let row: (Option<i64>,) = sqlx_core::query_as::query_as(&query)
        .fetch_one(pool)
        .await?;

    Ok(row.0.map(|h| BlockHeight::from_u32(h as u32)))
}

#[cfg(feature = "postgres")]
async fn get_marks_removed_async(
    pool: &Pool,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<BTreeSet<Position>, SqlxClientError> {
    let query = format!(
        "SELECT mark_position FROM {}_tree_checkpoint_marks WHERE checkpoint_id = $1",
        table_prefix
    );

    let rows: Vec<(i64,)> = sqlx_core::query_as::query_as(&query)
        .bind(u32::from(checkpoint_id) as i64)
        .fetch_all(pool)
        .await?;

    Ok(rows
        .into_iter()
        .map(|(pos,)| Position::from(pos as u64))
        .collect())
}

#[cfg(feature = "postgres")]
async fn add_checkpoint_async(
    pool: &Pool,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
    checkpoint: Checkpoint,
) -> Result<(), SqlxClientError> {
    // Check if checkpoint exists
    let check_query = format!(
        "SELECT position FROM {}_tree_checkpoints WHERE checkpoint_id = $1",
        table_prefix
    );

    let existing: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(&check_query)
        .bind(u32::from(checkpoint_id) as i64)
        .fetch_optional(pool)
        .await?;

    match existing {
        Some((pos_opt,)) => {
            let extant_tree_state = pos_opt.map_or(TreeState::Empty, |p| {
                TreeState::AtPosition(Position::from(p as u64))
            });
            if extant_tree_state != checkpoint.tree_state() {
                return Err(SqlxClientError::CheckpointConflict(checkpoint_id));
            }
            // Check marks_removed match
            let marks_removed = get_marks_removed_async(pool, table_prefix, checkpoint_id).await?;
            if &marks_removed != checkpoint.marks_removed() {
                return Err(SqlxClientError::CheckpointConflict(checkpoint_id));
            }
            Ok(())
        }
        None => {
            // Insert new checkpoint
            let position = checkpoint.position().map(|p| u64::from(p) as i64);

            let insert_query = format!(
                "INSERT INTO {}_tree_checkpoints (checkpoint_id, position) VALUES ($1, $2)",
                table_prefix
            );

            sqlx_core::query::query(&insert_query)
                .bind(u32::from(checkpoint_id) as i64)
                .bind(position)
                .execute(pool)
                .await?;

            // Insert marks removed
            let insert_marks_query = format!(
                "INSERT INTO {}_tree_checkpoint_marks (checkpoint_id, mark_position) VALUES ($1, $2)",
                table_prefix
            );

            for pos in checkpoint.marks_removed() {
                sqlx_core::query::query(&insert_marks_query)
                    .bind(u32::from(checkpoint_id) as i64)
                    .bind(u64::from(*pos) as i64)
                    .execute(pool)
                    .await?;
            }

            Ok(())
        }
    }
}

#[cfg(feature = "postgres")]
async fn checkpoint_count_async(
    pool: &Pool,
    table_prefix: &'static str,
) -> Result<usize, SqlxClientError> {
    let query = format!("SELECT COUNT(*) FROM {}_tree_checkpoints", table_prefix);

    let row: (i64,) = sqlx_core::query_as::query_as(&query)
        .fetch_one(pool)
        .await?;

    Ok(row.0 as usize)
}

#[cfg(feature = "postgres")]
async fn get_checkpoint_async(
    pool: &Pool,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<Option<Checkpoint>, SqlxClientError> {
    let query = format!(
        "SELECT position FROM {}_tree_checkpoints WHERE checkpoint_id = $1",
        table_prefix
    );

    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(&query)
        .bind(u32::from(checkpoint_id) as i64)
        .fetch_optional(pool)
        .await?;

    match row {
        None => Ok(None),
        Some((pos_opt,)) => {
            let tree_state = pos_opt.map_or(TreeState::Empty, |p| {
                TreeState::AtPosition(Position::from(p as u64))
            });
            let marks_removed = get_marks_removed_async(pool, table_prefix, checkpoint_id).await?;
            Ok(Some(Checkpoint::from_parts(tree_state, marks_removed)))
        }
    }
}

#[cfg(feature = "postgres")]
async fn get_checkpoint_at_depth_async(
    pool: &Pool,
    table_prefix: &'static str,
    checkpoint_depth: usize,
) -> Result<Option<(BlockHeight, Checkpoint)>, SqlxClientError> {
    let query = format!(
        "SELECT checkpoint_id, position FROM {}_tree_checkpoints ORDER BY checkpoint_id DESC LIMIT 1 OFFSET $1",
        table_prefix
    );

    let row: Option<(i64, Option<i64>)> = sqlx_core::query_as::query_as(&query)
        .bind(checkpoint_depth as i64)
        .fetch_optional(pool)
        .await?;

    match row {
        None => Ok(None),
        Some((checkpoint_id, pos_opt)) => {
            let checkpoint_height = BlockHeight::from_u32(checkpoint_id as u32);
            let tree_state = pos_opt.map_or(TreeState::Empty, |p| {
                TreeState::AtPosition(Position::from(p as u64))
            });
            let marks_removed =
                get_marks_removed_async(pool, table_prefix, checkpoint_height).await?;
            Ok(Some((
                checkpoint_height,
                Checkpoint::from_parts(tree_state, marks_removed),
            )))
        }
    }
}

#[cfg(feature = "postgres")]
async fn remove_checkpoint_async(
    pool: &Pool,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), SqlxClientError> {
    // Delete marks first (FK constraint), then checkpoint
    let delete_marks_query = format!(
        "DELETE FROM {}_tree_checkpoint_marks WHERE checkpoint_id = $1",
        table_prefix
    );

    sqlx_core::query::query(&delete_marks_query)
        .bind(u32::from(checkpoint_id) as i64)
        .execute(pool)
        .await?;

    let delete_query = format!(
        "DELETE FROM {}_tree_checkpoints WHERE checkpoint_id = $1",
        table_prefix
    );

    sqlx_core::query::query(&delete_query)
        .bind(u32::from(checkpoint_id) as i64)
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
async fn truncate_checkpoints_retaining_async(
    pool: &Pool,
    table_prefix: &'static str,
    checkpoint_id: BlockHeight,
) -> Result<(), SqlxClientError> {
    // Delete marks for checkpoints > checkpoint_id
    let delete_marks_query = format!(
        "DELETE FROM {}_tree_checkpoint_marks WHERE checkpoint_id > $1",
        table_prefix
    );

    sqlx_core::query::query(&delete_marks_query)
        .bind(u32::from(checkpoint_id) as i64)
        .execute(pool)
        .await?;

    // Delete checkpoints > checkpoint_id
    let delete_query = format!(
        "DELETE FROM {}_tree_checkpoints WHERE checkpoint_id > $1",
        table_prefix
    );

    sqlx_core::query::query(&delete_query)
        .bind(u32::from(checkpoint_id) as i64)
        .execute(pool)
        .await?;

    // Delete marks for the retained checkpoint
    let delete_retained_marks_query = format!(
        "DELETE FROM {}_tree_checkpoint_marks WHERE checkpoint_id = $1",
        table_prefix
    );

    sqlx_core::query::query(&delete_retained_marks_query)
        .bind(u32::from(checkpoint_id) as i64)
        .execute(pool)
        .await?;

    Ok(())
}

#[cfg(feature = "postgres")]
async fn with_checkpoints_async<F, E>(
    pool: &Pool,
    table_prefix: &'static str,
    limit: usize,
    mut callback: F,
) -> Result<(), E>
where
    F: FnMut(&BlockHeight, &Checkpoint) -> Result<(), E>,
    E: From<SqlxClientError>,
{
    let query = format!(
        "SELECT checkpoint_id, position FROM {}_tree_checkpoints ORDER BY position LIMIT $1",
        table_prefix
    );

    let rows: Vec<(i64, Option<i64>)> = sqlx_core::query_as::query_as(&query)
        .bind(limit as i64)
        .fetch_all(pool)
        .await
        .map_err(|e| E::from(SqlxClientError::from(e)))?;

    for (checkpoint_id, pos_opt) in rows {
        let checkpoint_height = BlockHeight::from_u32(checkpoint_id as u32);
        let tree_state = pos_opt.map_or(TreeState::Empty, |p| {
            TreeState::AtPosition(Position::from(p as u64))
        });
        let marks_removed = get_marks_removed_async(pool, table_prefix, checkpoint_height)
            .await
            .map_err(E::from)?;
        callback(
            &checkpoint_height,
            &Checkpoint::from_parts(tree_state, marks_removed),
        )?;
    }

    Ok(())
}

// ============================================================================
// ShardStore implementations for Sapling
// ============================================================================

#[cfg(feature = "postgres")]
impl ShardStore for SqlxShardStore<'_, sapling::Node, { SAPLING_SHARD_HEIGHT }> {
    type H = sapling::Node;
    type CheckpointId = BlockHeight;
    type Error = SqlxClientError;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        self.handle
            .block_on(get_shard_async(self.pool, self.table_prefix, shard_root))
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        self.handle.block_on(last_shard_async(
            self.pool,
            self.table_prefix,
            Self::SHARD_ROOT_LEVEL,
        ))
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        self.handle
            .block_on(put_shard_async(self.pool, self.table_prefix, subtree))
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        self.handle.block_on(get_shard_roots_async(
            self.pool,
            self.table_prefix,
            Self::SHARD_ROOT_LEVEL,
        ))
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Self::Error> {
        self.handle.block_on(truncate_shards_async(
            self.pool,
            self.table_prefix,
            shard_index,
        ))
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        self.handle
            .block_on(get_cap_async(self.pool, self.table_prefix))
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        self.handle
            .block_on(put_cap_async(self.pool, self.table_prefix, cap))
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        self.handle
            .block_on(min_checkpoint_id_async(self.pool, self.table_prefix))
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        self.handle
            .block_on(max_checkpoint_id_async(self.pool, self.table_prefix))
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        self.handle.block_on(add_checkpoint_async(
            self.pool,
            self.table_prefix,
            checkpoint_id,
            checkpoint,
        ))
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        self.handle
            .block_on(checkpoint_count_async(self.pool, self.table_prefix))
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        self.handle.block_on(get_checkpoint_at_depth_async(
            self.pool,
            self.table_prefix,
            checkpoint_depth,
        ))
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        self.handle.block_on(get_checkpoint_async(
            self.pool,
            self.table_prefix,
            *checkpoint_id,
        ))
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        self.handle.block_on(with_checkpoints_async(
            self.pool,
            self.table_prefix,
            limit,
            callback,
        ))
    }

    fn for_each_checkpoint<F>(&self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        self.handle.block_on(with_checkpoints_async(
            self.pool,
            self.table_prefix,
            limit,
            callback,
        ))
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        self.handle.block_on(async {
            if let Some(mut checkpoint) =
                get_checkpoint_async(self.pool, self.table_prefix, *checkpoint_id).await?
            {
                update(&mut checkpoint)?;
                remove_checkpoint_async(self.pool, self.table_prefix, *checkpoint_id).await?;
                add_checkpoint_async(self.pool, self.table_prefix, *checkpoint_id, checkpoint)
                    .await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        self.handle.block_on(remove_checkpoint_async(
            self.pool,
            self.table_prefix,
            *checkpoint_id,
        ))
    }

    fn truncate_checkpoints_retaining(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        self.handle.block_on(truncate_checkpoints_retaining_async(
            self.pool,
            self.table_prefix,
            *checkpoint_id,
        ))
    }
}

// ============================================================================
// ShardStore implementations for Orchard
// ============================================================================

#[cfg(all(feature = "orchard", feature = "postgres"))]
impl ShardStore for SqlxShardStore<'_, orchard::tree::MerkleHashOrchard, { ORCHARD_SHARD_HEIGHT }> {
    type H = orchard::tree::MerkleHashOrchard;
    type CheckpointId = BlockHeight;
    type Error = SqlxClientError;

    fn get_shard(
        &self,
        shard_root: Address,
    ) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        self.handle
            .block_on(get_shard_async(self.pool, self.table_prefix, shard_root))
    }

    fn last_shard(&self) -> Result<Option<LocatedPrunableTree<Self::H>>, Self::Error> {
        self.handle.block_on(last_shard_async(
            self.pool,
            self.table_prefix,
            Self::SHARD_ROOT_LEVEL,
        ))
    }

    fn put_shard(&mut self, subtree: LocatedPrunableTree<Self::H>) -> Result<(), Self::Error> {
        self.handle
            .block_on(put_shard_async(self.pool, self.table_prefix, subtree))
    }

    fn get_shard_roots(&self) -> Result<Vec<Address>, Self::Error> {
        self.handle.block_on(get_shard_roots_async(
            self.pool,
            self.table_prefix,
            Self::SHARD_ROOT_LEVEL,
        ))
    }

    fn truncate_shards(&mut self, shard_index: u64) -> Result<(), Self::Error> {
        self.handle.block_on(truncate_shards_async(
            self.pool,
            self.table_prefix,
            shard_index,
        ))
    }

    fn get_cap(&self) -> Result<PrunableTree<Self::H>, Self::Error> {
        self.handle
            .block_on(get_cap_async(self.pool, self.table_prefix))
    }

    fn put_cap(&mut self, cap: PrunableTree<Self::H>) -> Result<(), Self::Error> {
        self.handle
            .block_on(put_cap_async(self.pool, self.table_prefix, cap))
    }

    fn min_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        self.handle
            .block_on(min_checkpoint_id_async(self.pool, self.table_prefix))
    }

    fn max_checkpoint_id(&self) -> Result<Option<Self::CheckpointId>, Self::Error> {
        self.handle
            .block_on(max_checkpoint_id_async(self.pool, self.table_prefix))
    }

    fn add_checkpoint(
        &mut self,
        checkpoint_id: Self::CheckpointId,
        checkpoint: Checkpoint,
    ) -> Result<(), Self::Error> {
        self.handle.block_on(add_checkpoint_async(
            self.pool,
            self.table_prefix,
            checkpoint_id,
            checkpoint,
        ))
    }

    fn checkpoint_count(&self) -> Result<usize, Self::Error> {
        self.handle
            .block_on(checkpoint_count_async(self.pool, self.table_prefix))
    }

    fn get_checkpoint_at_depth(
        &self,
        checkpoint_depth: usize,
    ) -> Result<Option<(Self::CheckpointId, Checkpoint)>, Self::Error> {
        self.handle.block_on(get_checkpoint_at_depth_async(
            self.pool,
            self.table_prefix,
            checkpoint_depth,
        ))
    }

    fn get_checkpoint(
        &self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<Option<Checkpoint>, Self::Error> {
        self.handle.block_on(get_checkpoint_async(
            self.pool,
            self.table_prefix,
            *checkpoint_id,
        ))
    }

    fn with_checkpoints<F>(&mut self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        self.handle.block_on(with_checkpoints_async(
            self.pool,
            self.table_prefix,
            limit,
            callback,
        ))
    }

    fn for_each_checkpoint<F>(&self, limit: usize, callback: F) -> Result<(), Self::Error>
    where
        F: FnMut(&Self::CheckpointId, &Checkpoint) -> Result<(), Self::Error>,
    {
        self.handle.block_on(with_checkpoints_async(
            self.pool,
            self.table_prefix,
            limit,
            callback,
        ))
    }

    fn update_checkpoint_with<F>(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
        update: F,
    ) -> Result<bool, Self::Error>
    where
        F: Fn(&mut Checkpoint) -> Result<(), Self::Error>,
    {
        self.handle.block_on(async {
            if let Some(mut checkpoint) =
                get_checkpoint_async(self.pool, self.table_prefix, *checkpoint_id).await?
            {
                update(&mut checkpoint)?;
                remove_checkpoint_async(self.pool, self.table_prefix, *checkpoint_id).await?;
                add_checkpoint_async(self.pool, self.table_prefix, *checkpoint_id, checkpoint)
                    .await?;
                Ok(true)
            } else {
                Ok(false)
            }
        })
    }

    fn remove_checkpoint(&mut self, checkpoint_id: &Self::CheckpointId) -> Result<(), Self::Error> {
        self.handle.block_on(remove_checkpoint_async(
            self.pool,
            self.table_prefix,
            *checkpoint_id,
        ))
    }

    fn truncate_checkpoints_retaining(
        &mut self,
        checkpoint_id: &Self::CheckpointId,
    ) -> Result<(), Self::Error> {
        self.handle.block_on(truncate_checkpoints_retaining_async(
            self.pool,
            self.table_prefix,
            *checkpoint_id,
        ))
    }
}

// ============================================================================
// Subtree root insertion functions
// ============================================================================

/// Put Sapling subtree roots into the database.
#[cfg(feature = "postgres")]
pub async fn put_sapling_subtree_roots<const DEPTH: u8, const SHARD_HEIGHT: u8>(
    pool: &Pool,
    start_index: u64,
    roots: &[CommitmentTreeRoot<sapling::Node>],
) -> Result<(), ShardTreeError<SqlxClientError>> {
    put_subtree_roots::<sapling::Node, DEPTH, SHARD_HEIGHT>(pool, "sapling", start_index, roots)
        .await
}

/// Put Orchard subtree roots into the database.
#[cfg(all(feature = "orchard", feature = "postgres"))]
pub async fn put_orchard_subtree_roots<const DEPTH: u8, const SHARD_HEIGHT: u8>(
    pool: &Pool,
    start_index: u64,
    roots: &[CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>],
) -> Result<(), ShardTreeError<SqlxClientError>> {
    put_subtree_roots::<orchard::tree::MerkleHashOrchard, DEPTH, SHARD_HEIGHT>(
        pool,
        "orchard",
        start_index,
        roots,
    )
    .await
}

#[cfg(feature = "postgres")]
async fn put_subtree_roots<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    pool: &Pool,
    table_prefix: &'static str,
    start_index: u64,
    roots: &[CommitmentTreeRoot<H>],
) -> Result<(), ShardTreeError<SqlxClientError>>
where
    H: Hashable + HashSer + Clone + Eq,
{
    use incrementalmerkletree::Retention;

    if roots.is_empty() {
        return Ok(());
    }

    // LevelShifter for batch insertion into cap
    #[derive(Clone, Debug, PartialEq, Eq)]
    struct LevelShifter<H, const SHARD_HEIGHT: u8>(H);

    impl<H: Hashable, const SHARD_HEIGHT: u8> Hashable for LevelShifter<H, SHARD_HEIGHT> {
        fn empty_leaf() -> Self {
            Self(H::empty_root(SHARD_HEIGHT.into()))
        }

        fn combine(level: Level, a: &Self, b: &Self) -> Self {
            Self(H::combine(level + SHARD_HEIGHT, &a.0, &b.0))
        }

        fn empty_root(level: Level) -> Self
        where
            Self: Sized,
        {
            Self(H::empty_root(level + SHARD_HEIGHT))
        }
    }

    impl<H: HashSer, const SHARD_HEIGHT: u8> HashSer for LevelShifter<H, SHARD_HEIGHT> {
        fn read<R: io::Read>(reader: R) -> io::Result<Self>
        where
            Self: Sized,
        {
            H::read(reader).map(Self)
        }

        fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
            self.0.write(writer)
        }
    }

    let cap: PrunableTree<LevelShifter<H, SHARD_HEIGHT>> = get_cap_async(pool, table_prefix)
        .await
        .map_err(ShardTreeError::Storage)?;

    let cap = LocatedTree::from_parts(Address::from_parts((DEPTH - SHARD_HEIGHT).into(), 0), cap)
        .map_err(|e| {
        ShardTreeError::Storage(SqlxClientError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Note commitment tree cap was invalid at address {:?}", e),
        )))
    })?;

    let cap_result = cap
        .batch_insert::<(), _>(
            Position::from(start_index),
            roots
                .iter()
                .map(|r| (LevelShifter(r.root_hash().clone()), Retention::Reference)),
        )
        .map_err(ShardTreeError::Insert)?
        .expect("slice of inserted roots was verified to be nonempty");

    put_cap_async(pool, table_prefix, cap_result.subtree.take_root())
        .await
        .map_err(ShardTreeError::Storage)?;

    check_shard_discontinuity(
        pool,
        table_prefix,
        start_index..start_index + (roots.len() as u64),
    )
    .await
    .map_err(ShardTreeError::Storage)?;

    // Insert shard roots
    let query = format!(
        r#"
        INSERT INTO {}_tree_shards (shard_index, subtree_end_height, root_hash, shard_data)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (shard_index) DO UPDATE
        SET subtree_end_height = EXCLUDED.subtree_end_height, root_hash = EXCLUDED.root_hash
        "#,
        table_prefix
    );

    for (root, i) in roots.iter().zip(0u64..) {
        let mut shard_data: Vec<u8> = vec![];
        let tree = PrunableTree::leaf((root.root_hash().clone(), RetentionFlags::EPHEMERAL));
        write_shard(&mut shard_data, &tree)
            .map_err(|e| ShardTreeError::Storage(SqlxClientError::Io(e)))?;

        let mut root_hash_data: Vec<u8> = vec![];
        root.root_hash()
            .write(&mut root_hash_data)
            .map_err(|e| ShardTreeError::Storage(SqlxClientError::Io(e)))?;

        sqlx_core::query::query(&query)
            .bind((start_index + i) as i64)
            .bind(u32::from(root.subtree_end_height()) as i64)
            .bind(root_hash_data)
            .bind(shard_data)
            .execute(pool)
            .await
            .map_err(|e| ShardTreeError::Storage(SqlxClientError::from(e)))?;
    }

    Ok(())
}
