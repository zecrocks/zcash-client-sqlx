//! Error types for the sqlx-backed wallet implementation.

use std::{fmt, ops::Range};

use shardtree::error::ShardTreeError;
use zcash_address::ConversionError;
use zcash_keys::keys::DerivationError;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::BlockHeight;

use crate::types::{AccountUuid, WalletId};

#[cfg(feature = "transparent-inputs")]
use ::transparent::keys::TransparentKeyScope;

/// Errors that can occur when working with the sqlx wallet backend.
#[derive(Debug)]
pub enum SqlxClientError {
    /// An error occurred executing a SQL query.
    DbError(sqlx_core::Error),

    /// An error occurred running database migrations.
    MigrationError(Box<sqlx_core::migrate::MigrateError>),

    /// An error occurred during IO.
    Io(std::io::Error),

    /// An error occurred while decoding a protobuf message.
    Protobuf(prost::DecodeError),

    /// The requested wallet was not found.
    WalletNotFound(WalletId),

    /// The account for the given identifier was not found.
    AccountNotFound(AccountUuid),

    /// The account corresponding to the given UUID has been previously removed from the wallet
    /// database.
    AccountDeleted(AccountUuid),

    /// An error occurred deriving a key.
    KeyDerivationError(DerivationError),

    /// An error occurred while processing an account birthday.
    AccountBirthday(String),

    /// An error occurred parsing a Zcash address.
    AddressParse(ConversionError<&'static str>),

    /// Illegal attempt to reinitialize an already-initialized wallet database.
    DatabaseAlreadyInitialized,

    /// A requested account does not exist in the database.
    AccountUnknown,

    /// A caller attempted to initialize the accounts table without providing a birthday for the
    /// account.
    AccountMissingBirthday,

    /// An account collision occurred: the hash of the full viewing key components matches an
    /// existing account.
    AccountCollision(AccountUuid),

    /// An error occurred parsing a network type.
    NetworkMismatch {
        /// The expected network type.
        expected: String,
        /// The actual network type found in the database.
        actual: String,
    },

    /// An error occurred encoding or decoding data.
    Encoding(String),

    /// The seed does not match the derived accounts in the wallet.
    SeedMismatch,

    /// An error occurred while processing a commitment tree operation.
    CommitmentTree(Box<ShardTreeError<SqlxClientError>>),

    /// A note selection error occurred.
    NoteSelection(String),

    /// The wallet contains no accounts.
    NoAccounts,

    /// Chain height information was unavailable, indicating that no blocks have been scanned.
    ChainHeightUnavailable,

    /// The transaction has expired.
    TransactionExpired(TxId),

    /// An error occurred attempting to spend funds that would leave the balance below the
    /// minimum fee requirement.
    InsufficientFunds {
        /// The balance available for spending.
        available: u64,
        /// The balance required.
        required: u64,
    },

    /// A corrupted block height value was detected.
    CorruptedBlockHeight(i64),

    /// A corrupted data error with a descriptive message.
    CorruptedData(String),

    /// A corrupted diversifier index was detected.
    CorruptedDiversifierIndex,

    /// A corrupted nullifier was detected.
    CorruptedNullifier,

    /// A corrupted transaction output was detected.
    CorruptedOutput,

    /// A block height outside the expected range was encountered.
    BlockHeightDiscontinuity {
        /// Expected block height.
        expected: BlockHeight,
        /// Actual block height.
        found: BlockHeight,
    },

    /// A range or account ID was requested, but no scan queue was available.
    ScanQueueEmpty,

    /// A requested rewind would violate invariants of the database.
    RequestedRewindInvalid {
        /// The height to which the rewind was requested.
        requested: BlockHeight,
        /// The height to which it is possible to rewind.
        safe_rewind: BlockHeight,
    },

    /// An error occurred with the underlying Tokio runtime.
    TokioRuntime(String),

    /// A gap limit would be violated by a transparent address operation.
    #[cfg(feature = "transparent-inputs")]
    AddressGapLimitExceeded {
        /// The key scope at which the gap limit would be exceeded.
        key_scope: TransparentKeyScope,
        /// The maximum allowed address index.
        max_address_index: u32,
    },

    /// An ephemeral address would be reused.
    #[cfg(feature = "transparent-inputs")]
    EphemeralAddressReuse,

    /// The database returned an unexpected number of rows.
    UnexpectedRowCount {
        /// The expected number of rows.
        expected: usize,
        /// The actual number of rows.
        actual: usize,
    },

    /// An error during balance calculation.
    BalanceError(zcash_protocol::value::BalanceError),

    /// An error occurred parsing memo bytes.
    MemoDecoding(zcash_protocol::memo::Error),

    /// Attempted to perform an operation that is only valid for spending accounts
    /// on a view-only account.
    ViewOnlyAccount(AccountUuid),

    /// Attempted to insert subtree roots that would create a discontinuity in the tree.
    SubtreeDiscontinuity {
        /// The range of indices that was attempted to be inserted.
        attempted_insertion_range: Range<u64>,
        /// The range of indices already existing in the database.
        existing_range: Range<u64>,
    },

    /// Attempted to add a checkpoint at a height where a conflicting checkpoint exists.
    CheckpointConflict(BlockHeight),

    /// An attempt was made to spend funds that include notes that are not yet spendable,
    /// when the spending mode required all funds to be available.
    IneligibleNotes,

    /// A block hash mismatch was detected at the given height, indicating a chain reorg.
    BlockConflict(BlockHeight),
}

impl fmt::Display for SqlxClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SqlxClientError::DbError(e) => write!(f, "Database error: {}", e),
            SqlxClientError::MigrationError(e) => write!(f, "Migration error: {}", e),
            SqlxClientError::Io(e) => write!(f, "IO error: {}", e),
            SqlxClientError::Protobuf(e) => write!(f, "Protobuf decode error: {}", e),
            SqlxClientError::WalletNotFound(id) => write!(f, "Wallet not found: {:?}", id),
            SqlxClientError::AccountNotFound(id) => write!(f, "Account not found: {:?}", id),
            SqlxClientError::AccountDeleted(id) => write!(f, "Account was deleted: {:?}", id),
            SqlxClientError::KeyDerivationError(e) => write!(f, "Key derivation error: {:?}", e),
            SqlxClientError::AccountBirthday(e) => write!(f, "Account birthday error: {}", e),
            SqlxClientError::AddressParse(e) => write!(f, "Address parse error: {:?}", e),
            SqlxClientError::DatabaseAlreadyInitialized => {
                write!(f, "Database already initialized")
            }
            SqlxClientError::AccountUnknown => write!(f, "Account unknown"),
            SqlxClientError::AccountMissingBirthday => write!(f, "Account missing birthday"),
            SqlxClientError::AccountCollision(id) => {
                write!(f, "Account collision with existing account {:?}", id)
            }
            SqlxClientError::NetworkMismatch { expected, actual } => {
                write!(f, "Network mismatch: expected {}, got {}", expected, actual)
            }
            SqlxClientError::Encoding(msg) => write!(f, "Encoding error: {}", msg),
            SqlxClientError::SeedMismatch => write!(f, "Seed does not match derived accounts"),
            SqlxClientError::CommitmentTree(e) => write!(f, "Commitment tree error: {:?}", e),
            SqlxClientError::NoteSelection(msg) => write!(f, "Note selection error: {}", msg),
            SqlxClientError::NoAccounts => write!(f, "Wallet contains no accounts"),
            SqlxClientError::ChainHeightUnavailable => write!(f, "Chain height unavailable"),
            SqlxClientError::TransactionExpired(txid) => {
                write!(f, "Transaction {:?} has expired", txid)
            }
            SqlxClientError::InsufficientFunds {
                available,
                required,
            } => write!(
                f,
                "Insufficient funds: available {}, required {}",
                available, required
            ),
            SqlxClientError::CorruptedBlockHeight(h) => {
                write!(f, "Corrupted block height: {}", h)
            }
            SqlxClientError::CorruptedData(msg) => {
                write!(f, "Corrupted data: {}", msg)
            }
            SqlxClientError::CorruptedDiversifierIndex => {
                write!(f, "Corrupted diversifier index")
            }
            SqlxClientError::CorruptedNullifier => write!(f, "Corrupted nullifier"),
            SqlxClientError::CorruptedOutput => write!(f, "Corrupted output"),
            SqlxClientError::BlockHeightDiscontinuity { expected, found } => {
                write!(
                    f,
                    "Block height discontinuity: expected {:?}, found {:?}",
                    expected, found
                )
            }
            SqlxClientError::ScanQueueEmpty => write!(f, "Scan queue is empty"),
            SqlxClientError::RequestedRewindInvalid {
                requested,
                safe_rewind,
            } => {
                write!(
                    f,
                    "Requested rewind to {:?} is invalid; safe rewind height is {:?}",
                    requested, safe_rewind
                )
            }
            SqlxClientError::TokioRuntime(msg) => write!(f, "Tokio runtime error: {}", msg),
            #[cfg(feature = "transparent-inputs")]
            SqlxClientError::AddressGapLimitExceeded {
                key_scope,
                max_address_index,
            } => {
                write!(
                    f,
                    "Address gap limit exceeded for scope {:?}: max index {}",
                    key_scope, max_address_index
                )
            }
            #[cfg(feature = "transparent-inputs")]
            SqlxClientError::EphemeralAddressReuse => {
                write!(f, "Ephemeral address would be reused")
            }
            SqlxClientError::UnexpectedRowCount { expected, actual } => {
                write!(
                    f,
                    "Unexpected row count: expected {}, got {}",
                    expected, actual
                )
            }
            SqlxClientError::BalanceError(e) => write!(f, "Balance error: {:?}", e),
            SqlxClientError::MemoDecoding(e) => write!(f, "Memo decoding error: {}", e),
            SqlxClientError::ViewOnlyAccount(id) => {
                write!(f, "Account {:?} is view-only", id)
            }
            SqlxClientError::SubtreeDiscontinuity {
                attempted_insertion_range,
                existing_range,
            } => {
                write!(
                    f,
                    "Attempted to write subtree roots with indices {:?} which is discontinuous with existing subtree range {:?}",
                    attempted_insertion_range, existing_range
                )
            }
            SqlxClientError::CheckpointConflict(height) => {
                write!(f, "Checkpoint conflict at block height {:?}", height)
            }
            SqlxClientError::IneligibleNotes => {
                write!(f, "Some notes are not yet spendable")
            }
            SqlxClientError::BlockConflict(height) => {
                write!(
                    f,
                    "A block hash mismatch was detected at height {:?}, indicating a chain reorg",
                    height
                )
            }
        }
    }
}

impl std::error::Error for SqlxClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SqlxClientError::DbError(e) => Some(e),
            SqlxClientError::MigrationError(e) => Some(e.as_ref()),
            SqlxClientError::Io(e) => Some(e),
            SqlxClientError::Protobuf(e) => Some(e),
            _ => None,
        }
    }
}

impl From<sqlx_core::Error> for SqlxClientError {
    fn from(e: sqlx_core::Error) -> Self {
        SqlxClientError::DbError(e)
    }
}

impl From<sqlx_core::migrate::MigrateError> for SqlxClientError {
    fn from(e: sqlx_core::migrate::MigrateError) -> Self {
        SqlxClientError::MigrationError(Box::new(e))
    }
}

impl From<std::io::Error> for SqlxClientError {
    fn from(e: std::io::Error) -> Self {
        SqlxClientError::Io(e)
    }
}

impl From<prost::DecodeError> for SqlxClientError {
    fn from(e: prost::DecodeError) -> Self {
        SqlxClientError::Protobuf(e)
    }
}

impl From<DerivationError> for SqlxClientError {
    fn from(e: DerivationError) -> Self {
        SqlxClientError::KeyDerivationError(e)
    }
}

impl From<zcash_client_backend::data_api::BirthdayError> for SqlxClientError {
    fn from(e: zcash_client_backend::data_api::BirthdayError) -> Self {
        use zcash_client_backend::data_api::BirthdayError;
        let msg = match e {
            BirthdayError::HeightInvalid(e) => format!("height invalid: {}", e),
            BirthdayError::Decode(e) => format!("decode error: {}", e),
        };
        SqlxClientError::AccountBirthday(msg)
    }
}

impl From<ConversionError<&'static str>> for SqlxClientError {
    fn from(e: ConversionError<&'static str>) -> Self {
        SqlxClientError::AddressParse(e)
    }
}

impl From<ShardTreeError<SqlxClientError>> for SqlxClientError {
    fn from(e: ShardTreeError<SqlxClientError>) -> Self {
        SqlxClientError::CommitmentTree(Box::new(e))
    }
}

impl From<zcash_protocol::value::BalanceError> for SqlxClientError {
    fn from(e: zcash_protocol::value::BalanceError) -> Self {
        SqlxClientError::BalanceError(e)
    }
}

impl From<zcash_protocol::memo::Error> for SqlxClientError {
    fn from(e: zcash_protocol::memo::Error) -> Self {
        SqlxClientError::MemoDecoding(e)
    }
}
