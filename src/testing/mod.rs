//! Test utilities for the sqlx wallet backend with PostgreSQL.
//!
//! This module provides test infrastructure for running integration tests against
//! a real PostgreSQL database using testcontainers.

// Allow dead code and unused variables in test utilities - these are helpers that may not all be used in every test run
#![allow(dead_code, unused_variables, unused_imports)]

use prost::Message;
use zcash_client_backend::{
    data_api::testing::{CacheInsertionResult, NoteCommitments, TestCache},
    proto::compact_formats::CompactBlock,
};
use zcash_protocol::{TxId, consensus::BlockHeight};

use crate::SqlxClientError;

pub(crate) mod concurrency;
pub(crate) mod db;
pub(crate) mod multi_wallet;
pub(crate) mod multi_wallet_reorg;
pub(crate) mod pool;

// New integration test modules
#[cfg(test)]
mod nullifiers;
#[cfg(test)]
mod spending_detection;
#[cfg(all(test, feature = "transparent-inputs"))]
mod transparent_tests;

/// In-memory block cache for testing.
///
/// Unlike the SQLite implementation which uses a database-backed cache,
/// this implementation stores blocks in memory for simplicity in tests.
pub(crate) struct BlockCache {
    blocks: Vec<CompactBlock>,
}

impl BlockCache {
    pub(crate) fn new() -> Self {
        BlockCache { blocks: Vec::new() }
    }
}

/// Result of inserting a block into the cache.
pub struct BlockCacheInsertionResult {
    txids: Vec<TxId>,
    note_commitments: NoteCommitments,
}

impl BlockCacheInsertionResult {
    pub fn note_commitments(&self) -> &NoteCommitments {
        &self.note_commitments
    }
}

impl CacheInsertionResult for BlockCacheInsertionResult {
    fn txids(&self) -> &[TxId] {
        &self.txids[..]
    }
}

/// A simple in-memory block source for testing.
pub struct MemoryBlockSource {
    blocks: Vec<(BlockHeight, Vec<u8>)>,
}

impl MemoryBlockSource {
    pub(crate) fn new() -> Self {
        MemoryBlockSource { blocks: Vec::new() }
    }

    pub(crate) fn insert(&mut self, height: BlockHeight, data: Vec<u8>) {
        // Insert in sorted order by height
        let pos = self
            .blocks
            .binary_search_by_key(&height, |(h, _)| *h)
            .unwrap_or_else(|e| e);
        self.blocks.insert(pos, (height, data));
    }

    pub(crate) fn truncate_to_height(&mut self, height: BlockHeight) {
        self.blocks.retain(|(h, _)| *h <= height);
    }
}

impl zcash_client_backend::data_api::chain::BlockSource for MemoryBlockSource {
    type Error = SqlxClientError;

    fn with_blocks<F, DbErrT>(
        &self,
        from_height: Option<BlockHeight>,
        limit: Option<usize>,
        mut with_row: F,
    ) -> Result<(), zcash_client_backend::data_api::chain::error::Error<DbErrT, Self::Error>>
    where
        F: FnMut(
            CompactBlock,
        ) -> Result<
            (),
            zcash_client_backend::data_api::chain::error::Error<DbErrT, Self::Error>,
        >,
    {
        let start = from_height.map_or(0, |h| {
            self.blocks
                .binary_search_by_key(&h, |(bh, _)| *bh)
                .unwrap_or_else(|e| e)
        });

        let iter = self.blocks[start..].iter();
        let iter: Box<dyn Iterator<Item = _>> = if let Some(limit) = limit {
            Box::new(iter.take(limit))
        } else {
            Box::new(iter)
        };

        for (_, data) in iter {
            let block = CompactBlock::decode(&data[..]).map_err(|e| {
                zcash_client_backend::data_api::chain::error::Error::BlockSource(
                    SqlxClientError::Encoding(e.to_string()),
                )
            })?;
            with_row(block)?;
        }

        Ok(())
    }
}

impl TestCache for BlockCache {
    type BsError = SqlxClientError;
    type BlockSource = MemoryBlockSource;
    type InsertResult = BlockCacheInsertionResult;

    fn block_source(&self) -> &Self::BlockSource {
        // We need to return a reference, but we're building a new source.
        // This is a workaround - we'll use a different approach.
        unimplemented!("Use BlockCacheWithSource instead")
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        let note_commitments = NoteCommitments::from_compact_block(cb);
        self.blocks.push(cb.clone());

        BlockCacheInsertionResult {
            txids: cb.vtx.iter().map(|tx| tx.txid()).collect(),
            note_commitments,
        }
    }

    fn truncate_to_height(&mut self, height: BlockHeight) {
        self.blocks.retain(|b| b.height() <= height);
    }
}

/// Block cache with embedded source for testing.
///
/// This struct owns both the cache and the block source, allowing
/// proper lifetime management.
pub(crate) struct BlockCacheWithSource {
    source: MemoryBlockSource,
}

impl BlockCacheWithSource {
    pub(crate) fn new() -> Self {
        BlockCacheWithSource {
            source: MemoryBlockSource::new(),
        }
    }

    pub(crate) fn source_mut(&mut self) -> &mut MemoryBlockSource {
        &mut self.source
    }
}

impl TestCache for BlockCacheWithSource {
    type BsError = SqlxClientError;
    type BlockSource = MemoryBlockSource;
    type InsertResult = BlockCacheInsertionResult;

    fn block_source(&self) -> &Self::BlockSource {
        &self.source
    }

    fn insert(&mut self, cb: &CompactBlock) -> Self::InsertResult {
        let note_commitments = NoteCommitments::from_compact_block(cb);
        let cb_bytes = cb.encode_to_vec();
        self.source.insert(cb.height(), cb_bytes);

        BlockCacheInsertionResult {
            txids: cb.vtx.iter().map(|tx| tx.txid()).collect(),
            note_commitments,
        }
    }

    fn truncate_to_height(&mut self, height: BlockHeight) {
        self.source.truncate_to_height(height);
    }
}
