//! Core types for the sqlx-backed wallet implementation.

use std::fmt;

use subtle::ConditionallySelectable;
use uuid::Uuid;
use zcash_protocol::ShieldedProtocol;

/// A unique identifier for a wallet in the database.
///
/// In the sqlx implementation, multiple wallets can be stored in the same database,
/// each identified by a unique `WalletId`. This enables multi-wallet support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletId(Uuid);

impl WalletId {
    /// Creates a new random wallet ID.
    pub fn new() -> Self {
        WalletId(Uuid::new_v4())
    }

    /// Creates a `WalletId` from a raw UUID.
    ///
    /// The resulting identifier is not guaranteed to correspond to any wallet stored in
    /// the database.
    pub fn from_uuid(uuid: Uuid) -> Self {
        WalletId(uuid)
    }

    /// Returns the underlying UUID.
    pub fn expose_uuid(&self) -> Uuid {
        self.0
    }
}

impl Default for WalletId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for WalletId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for WalletId {
    fn from(uuid: Uuid) -> Self {
        WalletId(uuid)
    }
}

/// Unique identifier for a specific account tracked by a wallet.
///
/// Account identifiers are "one-way stable": a given identifier always points to a
/// specific viewing key within a specific wallet instance, but the same viewing key
/// may have multiple account identifiers over time. In particular, this crate upholds
/// the following properties:
///
/// - When an account starts being tracked within a wallet instance (via APIs like
///   [`WalletWrite::create_account`], [`WalletWrite::import_account_hd`], or
///   [`WalletWrite::import_account_ufvk`]), a new `AccountUuid` is generated.
/// - If an `AccountUuid` is present within a wallet, it always points to the same
///   account.
///
/// What this means is that account identifiers are not stable across "wallet recreation
/// events". Examples of these include:
/// - Restoring a wallet from a backed-up seed.
/// - Importing the same viewing key into two different wallet instances.
///
/// [`WalletWrite::create_account`]: zcash_client_backend::data_api::WalletWrite::create_account
/// [`WalletWrite::import_account_hd`]: zcash_client_backend::data_api::WalletWrite::import_account_hd
/// [`WalletWrite::import_account_ufvk`]: zcash_client_backend::data_api::WalletWrite::import_account_ufvk
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AccountUuid(#[cfg_attr(feature = "serde", serde(with = "uuid::serde::compact"))] Uuid);

impl ConditionallySelectable for AccountUuid {
    fn conditional_select(a: &Self, b: &Self, choice: subtle::Choice) -> Self {
        AccountUuid(Uuid::from_u128(
            ConditionallySelectable::conditional_select(&a.0.as_u128(), &b.0.as_u128(), choice),
        ))
    }
}

impl AccountUuid {
    /// Constructs an `AccountUuid` from a bare [`Uuid`] value.
    ///
    /// The resulting identifier is not guaranteed to correspond to any account stored in
    /// a wallet.
    pub fn from_uuid(value: Uuid) -> Self {
        AccountUuid(value)
    }

    /// Exposes the opaque account identifier from its typesafe wrapper.
    pub fn expose_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for AccountUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<Uuid> for AccountUuid {
    fn from(uuid: Uuid) -> Self {
        AccountUuid(uuid)
    }
}

/// A typesafe wrapper for the primary key identifier for a row in the `accounts` table.
///
/// This is an ephemeral value for efficiently and generically working with accounts in a
/// database. To reference accounts in external contexts, use [`AccountUuid`].
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Default, PartialOrd, Ord)]
pub(crate) struct AccountRef(pub(crate) i64);

impl From<i64> for AccountRef {
    fn from(id: i64) -> Self {
        AccountRef(id)
    }
}

/// An opaque type for received note identifiers.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReceivedNoteId(pub(crate) ShieldedProtocol, pub(crate) i64);

impl ReceivedNoteId {
    /// Creates a new received note ID.
    pub fn new(protocol: ShieldedProtocol, id: i64) -> Self {
        ReceivedNoteId(protocol, id)
    }

    /// Returns the protocol this note belongs to.
    pub fn protocol(&self) -> ShieldedProtocol {
        self.0
    }

    /// Returns the internal database ID.
    #[allow(dead_code)]
    pub(crate) fn internal_id(&self) -> i64 {
        self.1
    }
}

impl fmt::Display for ReceivedNoteId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReceivedNoteId(protocol, id) => write!(f, "Received {:?} Note: {}", protocol, id),
        }
    }
}

/// A newtype wrapper for database primary key values for the utxos table.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct UtxoId(pub i64);

impl From<i64> for UtxoId {
    fn from(id: i64) -> Self {
        UtxoId(id)
    }
}

impl fmt::Display for UtxoId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UTXO:{}", self.0)
    }
}

/// A newtype wrapper for database primary key values for the transactions table.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct TxRef(pub(crate) i64);

impl From<i64> for TxRef {
    fn from(id: i64) -> Self {
        TxRef(id)
    }
}

/// A newtype wrapper for database primary key values for the addresses table.
#[allow(dead_code)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub(crate) struct AddressRef(pub(crate) i64);

impl From<i64> for AddressRef {
    fn from(id: i64) -> Self {
        AddressRef(id)
    }
}

/// A data structure that can be used to configure custom gap limits for use in transparent address
/// rotation.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg(feature = "transparent-inputs")]
pub struct GapLimits {
    pub(crate) external: u32,
    pub(crate) internal: u32,
    pub(crate) ephemeral: u32,
}

#[cfg(feature = "transparent-inputs")]
impl GapLimits {
    /// The recommended gap limits for use with this crate.
    pub const DEFAULT: Self = Self {
        external: 20,
        internal: 20,
        ephemeral: 20,
    };

    /// Constructs a new `GapLimits` value from its constituent parts.
    ///
    /// The gap limits recommended for use with this crate are supplied by the [`Default`]
    /// implementation for this type.
    #[cfg(any(test, feature = "test-dependencies", feature = "unstable"))]
    pub fn from_parts(external: u32, internal: u32, ephemeral: u32) -> Self {
        Self {
            external,
            internal,
            ephemeral,
        }
    }

    /// Returns the gap limit for external (receiving) addresses.
    pub fn external(&self) -> u32 {
        self.external
    }

    /// Returns the gap limit for internal (change) addresses.
    pub fn internal(&self) -> u32 {
        self.internal
    }

    /// Returns the gap limit for ephemeral addresses.
    pub fn ephemeral(&self) -> u32 {
        self.ephemeral
    }
}

#[cfg(feature = "transparent-inputs")]
impl Default for GapLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}
