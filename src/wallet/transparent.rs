//! Transparent address and UTXO operations.

use std::collections::{HashMap, HashSet};
use std::ops::DerefMut;
use std::time::{Duration, SystemTime};

use rand::RngCore;
use rand_distr::Distribution;
use transparent::{
    address::TransparentAddress,
    bundle::OutPoint,
    keys::{IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope},
};
use zcash_client_backend::encoding::AddressCodec;
use zcash_client_backend::wallet::{Exposure, GapMetadata};
use zcash_client_backend::{
    data_api::{
        Balance, TransactionsInvolvingAddress, WalletUtxo,
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::TransparentAddressMetadata,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::TxId;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_script::script::Evaluable;

#[cfg(feature = "postgres")]
use crate::pool::Pool;

use crate::{AccountUuid, GapLimits, SqlxClientError, WalletId};

/// Key scope encoding for database storage.
/// Matches SQLite's encoding in wallet/encoding.rs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KeyScope {
    /// External scope (ZIP32)
    External,
    /// Internal scope (ZIP32)
    Internal,
    /// Ephemeral transparent addresses
    Ephemeral,
    /// Foreign (imported) addresses
    Foreign,
}

impl KeyScope {
    pub const EXTERNAL: KeyScope = KeyScope::External;
    pub const INTERNAL: KeyScope = KeyScope::Internal;

    pub fn encode(&self) -> i64 {
        match self {
            KeyScope::External => 0i64,
            KeyScope::Internal => 1i64,
            KeyScope::Ephemeral => 2i64,
            KeyScope::Foreign => -1i64,
        }
    }

    pub fn decode(code: i64) -> Result<Self, SqlxClientError> {
        match code {
            0i64 => Ok(KeyScope::External),
            1i64 => Ok(KeyScope::Internal),
            2i64 => Ok(KeyScope::Ephemeral),
            -1i64 => Ok(KeyScope::Foreign),
            other => Err(SqlxClientError::Encoding(format!(
                "Invalid key scope code: {other}"
            ))),
        }
    }
}

impl From<TransparentKeyScope> for KeyScope {
    fn from(value: TransparentKeyScope) -> Self {
        match value {
            TransparentKeyScope::EXTERNAL => KeyScope::External,
            TransparentKeyScope::INTERNAL => KeyScope::Internal,
            TransparentKeyScope::EPHEMERAL => KeyScope::Ephemeral,
            _ => KeyScope::Foreign,
        }
    }
}

impl From<KeyScope> for Option<TransparentKeyScope> {
    fn from(value: KeyScope) -> Self {
        match value {
            KeyScope::External => Some(TransparentKeyScope::EXTERNAL),
            KeyScope::Internal => Some(TransparentKeyScope::INTERNAL),
            KeyScope::Ephemeral => Some(TransparentKeyScope::EPHEMERAL),
            KeyScope::Foreign => None,
        }
    }
}

/// Raw transparent output from database query.
///
/// This struct provides named fields instead of positional tuple access,
/// improving code clarity and reducing the risk of field order mistakes.
#[cfg(feature = "postgres")]
pub(crate) struct TransparentOutputRow {
    pub txid_bytes: Vec<u8>,
    pub output_index: i32,
    pub script_bytes: Vec<u8>,
    pub value_zat: i64,
    pub key_scope_code: i32,
    pub received_height: Option<i64>,
}

#[cfg(feature = "postgres")]
impl<'r> sqlx_core::from_row::FromRow<'r, sqlx_postgres::PgRow> for TransparentOutputRow {
    fn from_row(row: &'r sqlx_postgres::PgRow) -> Result<Self, sqlx_core::Error> {
        use sqlx_core::row::Row;
        Ok(Self {
            txid_bytes: row.try_get("txid")?,
            output_index: row.try_get("output_index")?,
            script_bytes: row.try_get("script")?,
            value_zat: row.try_get("value_zat")?,
            key_scope_code: row.try_get("key_scope")?,
            received_height: row.try_get("received_height")?,
        })
    }
}

/// Detects which accounts are affected by the given transparent outpoints being spent.
///
/// Returns the set of account UUIDs that have outputs matching the provided outpoints.
#[cfg(feature = "postgres")]
pub async fn detect_spending_accounts<'a>(
    pool: &Pool,
    wallet_id: WalletId,
    spent: impl Iterator<Item = &'a OutPoint>,
) -> Result<HashSet<AccountUuid>, SqlxClientError> {
    let mut acc = HashSet::new();

    for prevout in spent {
        // Query for accounts that have outputs at this outpoint
        let query = r#"
            SELECT accounts.uuid
            FROM transparent_received_outputs o
            JOIN accounts ON accounts.id = o.account_id
            JOIN transactions t ON t.id = o.tx_id
            WHERE o.wallet_id = $1
              AND t.txid = $2
              AND o.output_index = $3
        "#;

        let rows: Vec<(uuid::Uuid,)> = sqlx_core::query_as::query_as(query)
            .bind(wallet_id.expose_uuid())
            .bind(prevout.hash())
            .bind(prevout.n() as i32)
            .fetch_all(pool)
            .await?;

        for (account_uuid,) in rows {
            acc.insert(AccountUuid::from_uuid(account_uuid));
        }
    }

    Ok(acc)
}

/// Get information about a transparent output controlled by the wallet.
///
/// # Parameters
/// - `outpoint`: The identifier for the output to be retrieved.
/// - `spendable_as_of`: The target height of a transaction under construction that will spend the
///   returned output. If this is `None`, no spendability checks are performed.
#[cfg(feature = "postgres")]
pub async fn get_wallet_transparent_output<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
    outpoint: &OutPoint,
    spendable_as_of: Option<TargetHeight>,
) -> Result<Option<WalletUtxo>, SqlxClientError> {
    use ::transparent::address::Script;
    use ::transparent::bundle::TxOut;
    use zcash_client_backend::wallet::WalletTransparentOutput;
    use zcash_protocol::value::Zatoshis;
    use zcash_script::script;

    const DEFAULT_TX_EXPIRY_DELTA: i64 = 40;

    let target_height_i64: Option<i64> =
        spendable_as_of.map(|h| u32::from(BlockHeight::from(h)) as i64);

    // Query the output with optional spendability checks
    let query = r#"
        SELECT t.txid, u.output_index, u.script,
               u.value_zat, addresses.key_scope,
               t.mined_height AS received_height
        FROM transparent_received_outputs u
        JOIN transactions t ON t.id = u.tx_id
        JOIN accounts ON accounts.id = u.account_id
        JOIN addresses ON addresses.id = u.address_id
        WHERE u.wallet_id = $1
          AND t.txid = $2
          AND u.output_index = $3
          AND (
              -- If no spendability check, return the output regardless
              $4 IS NULL
              OR (
                  -- the transaction is unexpired
                  (t.mined_height < $4
                   OR t.expiry_height = 0
                   OR t.expiry_height >= $4
                   OR (t.expiry_height IS NULL AND t.min_observed_height + $5 >= $4))
                  -- and the output is unspent
                  AND u.id NOT IN (
                      SELECT txo_spends.transparent_received_output_id
                      FROM transparent_received_output_spends txo_spends
                      JOIN transactions stx ON stx.id = txo_spends.transaction_id
                      WHERE stx.mined_height < $4
                         OR stx.expiry_height = 0
                         OR stx.expiry_height >= $4
                         OR (stx.expiry_height IS NULL AND stx.min_observed_height + $5 >= $4)
                  )
                  -- exclude likely-spent wallet-internal ephemeral outputs
                  AND (
                      addresses.key_scope != 2
                      OR NOT EXISTS (
                          SELECT 1 FROM sent_notes sn
                          JOIN transactions snt ON snt.id = sn.tx_id
                          WHERE snt.wallet_id = u.wallet_id
                            AND sn.to_address = u.address
                            AND sn.from_account_id = accounts.id
                      )
                      OR u.max_observed_unspent_height IS NOT NULL
                  )
              )
          )
    "#;

    let row: Option<TransparentOutputRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(outpoint.hash())
        .bind(outpoint.n() as i32)
        .bind(target_height_i64)
        .bind(DEFAULT_TX_EXPIRY_DELTA)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => {
            let mut txid_arr = [0u8; 32];
            if row.txid_bytes.len() == 32 {
                txid_arr.copy_from_slice(&row.txid_bytes);
            } else {
                return Err(SqlxClientError::Encoding(format!(
                    "Invalid txid length: {}",
                    row.txid_bytes.len()
                )));
            }

            let outpoint = OutPoint::new(txid_arr, row.output_index as u32);
            let script_pubkey = Script(script::Code(row.script_bytes));
            let value = Zatoshis::from_nonnegative_i64(row.value_zat)
                .map_err(|_| SqlxClientError::CorruptedOutput)?;
            let height = row.received_height.map(|h| BlockHeight::from_u32(h as u32));

            let output = WalletTransparentOutput::from_parts(
                outpoint,
                TxOut::new(value, script_pubkey),
                height,
            )
            .ok_or(SqlxClientError::CorruptedOutput)?;

            let key_scope_opt: Option<TransparentKeyScope> =
                KeyScope::decode(row.key_scope_code as i64)?.into();
            Ok(Some(WalletUtxo::new(output, key_scope_opt)))
        }
        None => Ok(None),
    }
}

/// Returns information about a transparent output if it exists and is unspent.
///
/// If `target_height` is provided, the function returns the output only if it is spendable
/// at that height. If `target_height` is `None`, it returns the output regardless of
/// spendability status.
#[cfg(feature = "postgres")]
pub async fn get_unspent_transparent_output<P: Parameters>(
    pool: &Pool,
    _params: &P,
    wallet_id: WalletId,
    outpoint: &OutPoint,
    target_height: TargetHeight,
) -> Result<Option<WalletUtxo>, SqlxClientError> {
    use ::transparent::address::Script;
    use ::transparent::bundle::TxOut;
    use zcash_client_backend::wallet::WalletTransparentOutput;
    use zcash_protocol::value::Zatoshis;

    const DEFAULT_TX_EXPIRY_DELTA: i64 = 40;

    let target_height_i64: i64 = u32::from(BlockHeight::from(target_height)) as i64;

    // Query for the specific transparent output by outpoint (txid + output_index)
    // This follows the SQLite `get_wallet_transparent_output` pattern
    let query = r#"
        SELECT t.txid, u.output_index, u.script,
               u.value_zat, addresses.key_scope,
               t.mined_height AS received_height
        FROM transparent_received_outputs u
        JOIN transactions t ON t.id = u.tx_id
        JOIN accounts ON accounts.id = u.account_id
        JOIN addresses ON addresses.id = u.address_id
        WHERE u.wallet_id = $1
          AND t.txid = $2
          AND u.output_index = $3
          -- the transaction is unexpired
          AND (
              t.mined_height IS NOT NULL AND t.mined_height < $4
              OR t.expiry_height = 0
              OR t.expiry_height >= $4
              OR (t.expiry_height IS NULL AND t.min_observed_height + $5 >= $4)
          )
          -- and the output is unspent
          AND u.id NOT IN (
              SELECT txo_spends.transparent_received_output_id
              FROM transparent_received_output_spends txo_spends
              JOIN transactions stx ON stx.id = txo_spends.transaction_id
              WHERE stx.mined_height IS NOT NULL AND stx.mined_height < $4
                 OR stx.expiry_height = 0
                 OR stx.expiry_height >= $4
                 OR (stx.expiry_height IS NULL AND stx.min_observed_height + $5 >= $4)
          )
          -- exclude likely-spent wallet-internal ephemeral outputs
          AND (
              addresses.key_scope != 2
              OR t.id NOT IN (
                  SELECT transaction_id FROM sapling_received_note_spends
                  WHERE wallet_id = u.wallet_id
                  UNION SELECT transaction_id FROM orchard_received_note_spends
                  WHERE wallet_id = u.wallet_id
                  UNION SELECT transaction_id FROM transparent_received_output_spends
                  WHERE wallet_id = u.wallet_id
              )
              OR u.max_observed_unspent_height > t.expiry_height
          )
    "#;

    let txid_bytes: &[u8] = outpoint.hash().as_ref();
    let row: Option<TransparentOutputRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(txid_bytes)
        .bind(outpoint.n() as i32)
        .bind(target_height_i64)
        .bind(DEFAULT_TX_EXPIRY_DELTA)
        .fetch_optional(pool)
        .await?;

    match row {
        Some(row) => {
            use zcash_script::script;

            // Convert txid bytes to array
            let txid_arr: [u8; 32] = row
                .txid_bytes
                .as_slice()
                .try_into()
                .map_err(|_| SqlxClientError::Encoding("Invalid txid length".to_string()))?;

            // Build the outpoint
            let outpoint = OutPoint::new(txid_arr, row.output_index as u32);

            // Build the script
            let script_pubkey = Script(script::Code(row.script_bytes));

            // Create the TxOut
            let value = Zatoshis::from_u64(row.value_zat as u64)
                .map_err(|_| SqlxClientError::Encoding("Invalid value".to_string()))?;

            // Get the height if available
            let height = row.received_height.map(|h| BlockHeight::from_u32(h as u32));

            // Create the WalletTransparentOutput
            let transparent_output = WalletTransparentOutput::from_parts(
                outpoint,
                TxOut::new(value, script_pubkey),
                height,
            )
            .ok_or_else(|| SqlxClientError::Encoding("Invalid transparent output".to_string()))?;

            // Decode key_scope to TransparentKeyScope
            let transparent_key_scope = match row.key_scope_code {
                0 => Some(TransparentKeyScope::EXTERNAL),  // External
                1 => Some(TransparentKeyScope::INTERNAL),  // Internal
                2 => Some(TransparentKeyScope::EPHEMERAL), // Ephemeral
                _ => None,                                 // Unknown
            };

            Ok(Some(WalletUtxo::new(
                transparent_output,
                transparent_key_scope,
            )))
        }
        None => Ok(None),
    }
}

#[cfg(feature = "postgres")]
pub async fn get_spendable_transparent_outputs<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    address: &TransparentAddress,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<Vec<WalletUtxo>, SqlxClientError> {
    use ::transparent::address::Script;
    use ::transparent::bundle::{OutPoint, TxOut};
    use zcash_client_backend::encoding::AddressCodec;
    use zcash_client_backend::wallet::WalletTransparentOutput;
    use zcash_protocol::value::Zatoshis;
    use zcash_script::script;

    const DEFAULT_TX_EXPIRY_DELTA: i64 = 40;
    const MARGINAL_FEE: i64 = 5000;

    let addr_str = address.encode(params);

    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations: i64 = if confirmations_policy.allow_zero_conf_shielding() {
        0
    } else {
        i64::from(u32::from(confirmations_policy.untrusted()))
    };

    let target_height_i64: i64 = u32::from(BlockHeight::from(target_height)) as i64;

    // Query for spendable transparent outputs at this address
    // This follows the SQLite pattern:
    // - Filter by address
    // - Filter by minimum value (MARGINAL_FEE)
    // - Transaction must be mined with enough confirmations, or unexpired with zero-conf
    // - Output must not be spent
    // - Exclude wallet-internal ephemeral outputs (key_scope = 2)
    let query = r#"
        SELECT t.txid, u.output_index, u.script,
               u.value_zat, addresses.key_scope,
               t.mined_height AS received_height
        FROM transparent_received_outputs u
        JOIN transactions t ON t.id = u.tx_id
        JOIN accounts ON accounts.id = u.account_id
        JOIN addresses ON addresses.id = u.address_id
        WHERE u.wallet_id = $1
          AND u.address = $2
          AND u.value_zat >= $6
          -- the transaction is mined with enough confirmations, or unmined but unexpired for zero-conf
          AND (
              -- tx is mined with enough confirmations (or 0 confirmations for zero-conf shielding)
              (t.mined_height IS NOT NULL AND t.mined_height < $3
               AND ($4 = 0 OR $3 - t.mined_height >= $4))
              -- or outputs may be spent with zero confirmations and the transaction is unexpired
              OR ($4 = 0 AND (t.expiry_height = 0 OR t.expiry_height IS NULL OR t.expiry_height >= $3))
          )
          -- and the output is unspent (not in spent UTXOs)
          AND u.id NOT IN (
              SELECT txo_spends.transparent_received_output_id
              FROM transparent_received_output_spends txo_spends
              JOIN transactions stx ON stx.id = txo_spends.transaction_id
              WHERE stx.mined_height IS NOT NULL AND stx.mined_height < $3
                 OR stx.expiry_height = 0
                 OR stx.expiry_height >= $3
                 OR (stx.expiry_height IS NULL AND stx.min_observed_height + $5 >= $3)
          )
          -- exclude likely-spent wallet-internal ephemeral outputs
          AND (
              -- If not ephemeral, include it
              addresses.key_scope != 2
              -- If ephemeral but received from external, include if confirmed unspent after expiry
              OR (
                  NOT EXISTS (
                      SELECT 1 FROM sent_notes sn
                      JOIN transactions snt ON snt.id = sn.tx_id
                      WHERE snt.wallet_id = u.wallet_id
                        AND sn.to_address = u.address
                        AND sn.from_account_id = accounts.id
                  )
                  OR u.max_observed_unspent_height IS NOT NULL
              )
          )
          -- exclude immature coinbase outputs (require 100 confirmations)
          AND NOT (
              -- the output is a coinbase output (tx_index = 0)
              COALESCE(t.tx_index, 1) = 0
              -- the coinbase output is immature (< 100 confirmations)
              AND $3 - t.mined_height < 100
          )
    "#;

    let rows: Vec<TransparentOutputRow> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(&addr_str)
        .bind(target_height_i64)
        .bind(min_confirmations)
        .bind(DEFAULT_TX_EXPIRY_DELTA)
        .bind(MARGINAL_FEE)
        .fetch_all(pool)
        .await?;

    let mut utxos = Vec::new();
    for row in rows {
        let mut txid_arr = [0u8; 32];
        if row.txid_bytes.len() == 32 {
            txid_arr.copy_from_slice(&row.txid_bytes);
        } else {
            return Err(SqlxClientError::Encoding(format!(
                "Invalid txid length: {}",
                row.txid_bytes.len()
            )));
        }

        let outpoint = OutPoint::new(txid_arr, row.output_index as u32);
        let script_pubkey = Script(script::Code(row.script_bytes));
        let value = Zatoshis::from_nonnegative_i64(row.value_zat)
            .map_err(|_| SqlxClientError::CorruptedOutput)?;
        let height = row.received_height.map(|h| BlockHeight::from_u32(h as u32));

        let output =
            WalletTransparentOutput::from_parts(outpoint, TxOut::new(value, script_pubkey), height)
                .ok_or(SqlxClientError::CorruptedOutput)?;

        let key_scope_opt: Option<TransparentKeyScope> =
            KeyScope::decode(row.key_scope_code as i64)?.into();
        utxos.push(WalletUtxo::new(output, key_scope_opt));
    }

    Ok(utxos)
}

/// Returns the transparent receivers associated with an account, with their metadata.
///
/// This retrieves all transparent addresses for the given account that match the specified
/// scope filters.
#[cfg(feature = "postgres")]
pub async fn get_transparent_receivers<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    include_change: bool,
    include_standalone: bool,
) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, SqlxClientError> {
    // Build the list of scopes to include
    let mut scopes = vec![KeyScope::External];
    if include_change {
        scopes.push(KeyScope::Internal);
    }
    if include_standalone {
        scopes.push(KeyScope::Foreign);
    }

    // Get the account's internal ID
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let internal_account_id = match account_row {
        Some((id,)) => id,
        None => return Err(SqlxClientError::AccountNotFound(account)),
    };

    // Build the scope values for the SQL query
    let scope_values: Vec<i64> = scopes.iter().map(|s| s.encode()).collect();

    // Query for addresses with the specified scopes
    let query = r#"
        SELECT
            cached_transparent_receiver_address,
            key_scope,
            transparent_child_index,
            exposed_at_height
        FROM addresses
        WHERE wallet_id = $1
          AND account_id = $2
          AND cached_transparent_receiver_address IS NOT NULL
          AND key_scope = ANY($3)
    "#;

    let rows: Vec<(String, i64, Option<i32>, Option<i64>)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(internal_account_id)
        .bind(&scope_values)
        .fetch_all(pool)
        .await?;

    let mut ret: HashMap<TransparentAddress, TransparentAddressMetadata> = HashMap::new();

    for (addr_str, key_scope_code, transparent_child_index_opt, exposed_at_height_opt) in rows {
        let key_scope = KeyScope::decode(key_scope_code)?;

        let taddr = TransparentAddress::decode(params, &addr_str).map_err(|_| {
            SqlxClientError::Encoding("Not a valid Zcash transparent address".to_string())
        })?;

        let address_index_opt = transparent_child_index_opt
            .and_then(|idx| NonHardenedChildIndex::from_index(idx as u32));

        // Calculate exposure
        let exposure = exposed_at_height_opt.map_or(Exposure::Unknown, |h| Exposure::Exposed {
            at_height: BlockHeight::from_u32(h as u32),
            gap_metadata: GapMetadata::DerivationUnknown,
        });

        // Build metadata based on key scope
        let metadata = match key_scope {
            KeyScope::Foreign => {
                // For foreign addresses, we would need the pubkey
                // For now, skip foreign addresses as they require special handling
                continue;
            }
            derived => {
                let scope_opt = <Option<TransparentKeyScope>>::from(derived);
                let (t_scope, address_index) = match scope_opt.zip(address_index_opt) {
                    Some(pair) => pair,
                    None => continue, // Skip addresses without proper derivation metadata
                };

                TransparentAddressMetadata::derived(
                    t_scope,
                    address_index,
                    exposure,
                    None, // next_check_time - not implemented yet
                )
            }
        };

        ret.insert(taddr, metadata);
    }

    Ok(ret)
}

#[cfg(feature = "postgres")]
pub async fn get_ephemeral_transparent_receivers<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    exposure_depth: u32,
    exclude_used: bool,
    gap_limits: &GapLimits,
) -> Result<HashMap<TransparentAddress, TransparentAddressMetadata>, SqlxClientError> {
    use zcash_client_backend::wallet::GapMetadata;

    // Get the mempool height (chain tip + 1)
    let mempool_height = match crate::wallet::common::get_chain_tip(pool, wallet_id).await? {
        Some(tip) => tip + 1,
        None => return Ok(HashMap::new()), // No chain tip, no addresses
    };

    // Calculate min exposure height
    let min_exposure_height = mempool_height.saturating_sub(exposure_depth);
    let min_exposure_height_i64 = u32::from(min_exposure_height) as i64;

    // Get the account's internal ID
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let internal_account_id = match account_row {
        Some((id,)) => id,
        None => return Ok(HashMap::new()), // Account not found
    };

    // Get the gap start for ephemeral addresses
    let gap_start = find_gap_start(
        pool,
        wallet_id,
        internal_account_id,
        TransparentKeyScope::EPHEMERAL,
        gap_limits.ephemeral,
    )
    .await?
    .unwrap_or(NonHardenedChildIndex::ZERO);

    let key_scope_code = KeyScope::Ephemeral.encode();
    let gap_limit = gap_limits.ephemeral;

    // Build the query - filter by exposure depth and optionally exclude used addresses
    let query = if exclude_used {
        r#"
            SELECT
                a.cached_transparent_receiver_address,
                a.transparent_child_index,
                a.exposed_at_height
            FROM addresses a
            WHERE a.wallet_id = $1
              AND a.account_id = $2
              AND a.key_scope = $3
              AND a.cached_transparent_receiver_address IS NOT NULL
              AND a.exposed_at_height IS NOT NULL
              AND a.exposed_at_height >= $4
              AND NOT EXISTS(
                  SELECT 1 FROM transparent_received_outputs tro
                  WHERE tro.address_id = a.id
              )
            ORDER BY a.transparent_child_index
        "#
    } else {
        r#"
            SELECT
                a.cached_transparent_receiver_address,
                a.transparent_child_index,
                a.exposed_at_height
            FROM addresses a
            WHERE a.wallet_id = $1
              AND a.account_id = $2
              AND a.key_scope = $3
              AND a.cached_transparent_receiver_address IS NOT NULL
              AND a.exposed_at_height IS NOT NULL
              AND a.exposed_at_height >= $4
            ORDER BY a.transparent_child_index
        "#
    };

    let rows: Vec<(String, Option<i32>, Option<i64>)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(internal_account_id)
        .bind(key_scope_code)
        .bind(min_exposure_height_i64)
        .fetch_all(pool)
        .await?;

    let mut result = HashMap::new();

    for (addr_str, child_index_opt, exposed_at_height_opt) in rows {
        let taddr = TransparentAddress::decode(params, &addr_str)
            .map_err(|_| SqlxClientError::Encoding("Invalid transparent address".to_string()))?;

        let child_index =
            child_index_opt.and_then(|idx| NonHardenedChildIndex::from_index(idx as u32));

        // Calculate gap metadata
        let gap_metadata = child_index.map_or(GapMetadata::DerivationUnknown, |idx| {
            if let Some(gap_position) = idx.index().checked_sub(gap_start.index()) {
                GapMetadata::InGap {
                    gap_position,
                    gap_limit,
                }
            } else {
                GapMetadata::GapRecoverable { gap_limit }
            }
        });

        // Build exposure
        let exposure = exposed_at_height_opt.map_or(Exposure::Unknown, |h| Exposure::Exposed {
            at_height: BlockHeight::from_u32(h as u32),
            gap_metadata,
        });

        let metadata = TransparentAddressMetadata::derived(
            TransparentKeyScope::EPHEMERAL,
            child_index.unwrap_or(NonHardenedChildIndex::ZERO),
            exposure,
            None, // next_check_time
        );

        result.insert(taddr, metadata);
    }

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn get_transparent_balances<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    target_height: TargetHeight,
    confirmations_policy: ConfirmationsPolicy,
) -> Result<HashMap<TransparentAddress, (TransparentKeyScope, Balance)>, SqlxClientError> {
    use zcash_protocol::value::Zatoshis;

    const DEFAULT_TX_EXPIRY_DELTA: i64 = 40;
    const MARGINAL_FEE: i64 = 5000;

    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations: i64 = if confirmations_policy.allow_zero_conf_shielding() {
        0
    } else {
        i64::from(u32::from(confirmations_policy.untrusted()))
    };

    let target_height_i64: i64 = u32::from(BlockHeight::from(target_height)) as i64;

    let mut result = HashMap::new();

    // Query spendable balances
    // This query matches SQLite's get_transparent_balances - uses address_id for the join
    let query = r#"
        SELECT u.address, u.value_zat, addresses.key_scope
        FROM transparent_received_outputs u
        JOIN accounts ON accounts.id = u.account_id
        JOIN transactions t ON t.id = u.tx_id
        JOIN addresses ON addresses.id = u.address_id
        WHERE u.wallet_id = $1
          AND accounts.uuid = $2
          AND u.value_zat > 0
          -- the transaction is mined with enough confirmations, or unmined but unexpired for zero-conf
          AND (
              -- tx is mined with enough confirmations (or 0 confirmations for zero-conf shielding)
              (t.mined_height IS NOT NULL AND ($4 = 0 OR $3 - t.mined_height >= $4))
              -- or tx is unmined but unexpired (for zero-conf shielding only)
              OR ($4 = 0 AND t.mined_height IS NULL
                  AND (t.expiry_height = 0 OR t.expiry_height >= $3
                       OR (t.expiry_height IS NULL AND t.min_observed_height + $5 >= $3)))
          )
          -- and the output is unspent (not in spent UTXOs)
          AND u.id NOT IN (
              SELECT txo_spends.transparent_received_output_id
              FROM transparent_received_output_spends txo_spends
              JOIN transactions stx ON stx.id = txo_spends.transaction_id
              WHERE stx.mined_height < $3
                 OR stx.expiry_height = 0
                 OR stx.expiry_height >= $3
                 OR (stx.expiry_height IS NULL AND stx.min_observed_height + $5 >= $3)
          )
          -- exclude ephemeral addresses (key_scope = 2)
          AND addresses.key_scope != 2
          -- exclude immature coinbase outputs (require 100 confirmations)
          AND NOT (
              -- the output is a coinbase output (tx_index = 0)
              COALESCE(t.tx_index, 1) = 0
              -- the coinbase output is immature (< 100 confirmations)
              AND $3 - t.mined_height < 100
          )
    "#;

    let rows: Vec<(String, i64, i64)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(target_height_i64)
        .bind(min_confirmations)
        .bind(DEFAULT_TX_EXPIRY_DELTA)
        .fetch_all(pool)
        .await?;

    for (addr_str, value_zat, key_scope_code) in rows {
        let taddr = TransparentAddress::decode(params, &addr_str).map_err(|e| {
            SqlxClientError::Encoding(format!("Invalid transparent address: {}", e))
        })?;
        let value = Zatoshis::from_nonnegative_i64(value_zat)
            .map_err(|_| SqlxClientError::CorruptedOutput)?;
        let key_scope_opt: Option<TransparentKeyScope> = KeyScope::decode(key_scope_code)?.into();
        let key_scope = key_scope_opt.ok_or_else(|| {
            SqlxClientError::Encoding(format!(
                "Invalid key scope code for transparent received output: {}",
                key_scope_code
            ))
        })?;

        let entry = result.entry(taddr).or_insert((key_scope, Balance::ZERO));
        if value < Zatoshis::const_from_u64(MARGINAL_FEE as u64) {
            entry.1.add_uneconomic_value(value)?;
        } else {
            entry.1.add_spendable_value(value)?;
        }
    }

    // Pending spendable balance for transparent UTXOs is only relevant for min_confirmations > 0;
    // with min_confirmations == 0, zero-conf spends are allowed and therefore the value will
    // appear in the spendable balance and we don't want to double-count it.
    if min_confirmations > 0 {
        let pending_query = r#"
            SELECT u.address, u.value_zat, addresses.key_scope
            FROM transparent_received_outputs u
            JOIN accounts ON accounts.id = u.account_id
            JOIN transactions t ON t.id = u.tx_id
            JOIN addresses ON addresses.id = u.address_id
            WHERE u.wallet_id = $1
              AND accounts.uuid = $2
              AND u.value_zat > 0
              -- the transaction that created the output is mined with not enough confirmations
              -- or unmined but definitely not expired
              AND (
                  -- mined with insufficient confirmations
                  (t.mined_height IS NOT NULL AND $3 - t.mined_height < $4)
                  -- or unmined but unexpired
                  OR (t.mined_height IS NULL
                      AND (t.expiry_height = 0 OR t.expiry_height >= $3
                           OR (t.expiry_height IS NULL AND t.min_observed_height + $5 >= $3)))
              )
              -- and the output is unspent
              AND u.id NOT IN (
                  SELECT txo_spends.transparent_received_output_id
                  FROM transparent_received_output_spends txo_spends
                  JOIN transactions stx ON stx.id = txo_spends.transaction_id
                  WHERE stx.mined_height < $3
                     OR stx.expiry_height = 0
                     OR stx.expiry_height >= $3
                     OR (stx.expiry_height IS NULL AND stx.min_observed_height + $5 >= $3)
              )
              -- exclude ephemeral addresses
              AND addresses.key_scope != 2
        "#;

        let pending_rows: Vec<(String, i64, i64)> = sqlx_core::query_as::query_as(pending_query)
            .bind(wallet_id.expose_uuid())
            .bind(account.expose_uuid())
            .bind(target_height_i64)
            .bind(min_confirmations)
            .bind(DEFAULT_TX_EXPIRY_DELTA)
            .fetch_all(pool)
            .await?;

        for (addr_str, value_zat, key_scope_code) in pending_rows {
            let taddr = TransparentAddress::decode(params, &addr_str).map_err(|e| {
                SqlxClientError::Encoding(format!("Invalid transparent address: {}", e))
            })?;
            let value = Zatoshis::from_nonnegative_i64(value_zat)
                .map_err(|_| SqlxClientError::CorruptedOutput)?;
            let key_scope_opt: Option<TransparentKeyScope> =
                KeyScope::decode(key_scope_code)?.into();
            let key_scope = key_scope_opt.ok_or_else(|| {
                SqlxClientError::Encoding(format!(
                    "Invalid key scope code for transparent received output: {}",
                    key_scope_code
                ))
            })?;

            let entry = result.entry(taddr).or_insert((key_scope, Balance::ZERO));
            entry.1.add_pending_spendable_value(value)?;
        }
    }

    Ok(result)
}

#[cfg(feature = "postgres")]
pub async fn get_transparent_address_metadata<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account: AccountUuid,
    address: &TransparentAddress,
) -> Result<Option<TransparentAddressMetadata>, SqlxClientError> {
    let address_str = address.encode(params);

    // Query the address metadata
    let query = r#"
        SELECT
            a.key_scope,
            a.transparent_child_index,
            a.exposed_at_height
        FROM addresses a
        JOIN accounts acc ON a.account_id = acc.id
        WHERE a.wallet_id = $1
          AND acc.uuid = $2
          AND a.cached_transparent_receiver_address = $3
    "#;

    let row: Option<(i32, Option<i32>, Option<i64>)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account.expose_uuid())
        .bind(&address_str)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((scope_code, child_index, _exposed_at_height)) => {
            let key_scope = KeyScope::decode(scope_code as i64)?;

            // Convert key_scope to TransparentKeyScope and get the child index
            if let Some(t_key_scope) = <Option<TransparentKeyScope>>::from(key_scope) {
                if let Some(child_idx) =
                    child_index.and_then(|i| NonHardenedChildIndex::from_index(i as u32))
                {
                    let metadata = TransparentAddressMetadata::derived(
                        t_key_scope,
                        child_idx,
                        Exposure::Unknown,
                        None,
                    );
                    return Ok(Some(metadata));
                }
            }

            Ok(None)
        }
        None => Ok(None),
    }
}

/// Returns the height to start querying for UTXOs from.
///
/// This is the minimum of the external and internal gap start heights, or the account
/// birthday height if no addresses have been used yet.
#[cfg(feature = "postgres")]
pub async fn utxo_query_height(
    pool: &Pool,
    wallet_id: WalletId,
    account: AccountUuid,
    gap_limits: &GapLimits,
) -> Result<BlockHeight, SqlxClientError> {
    // Get the account ID first
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let account_id = match account_row {
        Some((id,)) => id,
        None => return Err(SqlxClientError::AccountUnknown),
    };

    // Query for the minimum mined height of addresses that are at or after gap_start - gap_limit - 1
    // for each key scope.
    let get_height = |key_scope: TransparentKeyScope, gap_limit: u32| async move {
        let key_scope_code = KeyScope::from(key_scope).encode();

        // First find the gap start for this scope
        let gap_start = find_gap_start(pool, wallet_id, account_id, key_scope, gap_limit).await?;

        if let Some(gap_start_idx) = gap_start {
            let threshold_idx = gap_start_idx.index().saturating_sub(gap_limit + 1) as i32;

            // Query the minimum mined height for addresses at or after the threshold
            let query = r#"
                SELECT MIN(au.mined_height)::INTEGER
                FROM (
                    SELECT t.mined_height, a.transparent_child_index
                    FROM transparent_received_outputs tro
                    JOIN addresses a ON a.id = tro.address_id
                    JOIN transactions t ON t.id = tro.tx_id
                    WHERE a.wallet_id = $1
                      AND a.account_id = $2
                      AND a.key_scope = $3
                      AND a.transparent_child_index >= $4
                      AND t.mined_height IS NOT NULL
                    UNION ALL
                    SELECT t.mined_height, a.transparent_child_index
                    FROM transparent_received_output_spends tros
                    JOIN transparent_received_outputs tro ON tro.id = tros.transparent_received_output_id
                    JOIN addresses a ON a.id = tro.address_id
                    JOIN transactions t ON t.id = tros.transaction_id
                    WHERE a.wallet_id = $1
                      AND a.account_id = $2
                      AND a.key_scope = $3
                      AND a.transparent_child_index >= $4
                      AND t.mined_height IS NOT NULL
                ) au
            "#;

            let row: Option<(Option<i32>,)> = sqlx_core::query_as::query_as(query)
                .bind(wallet_id.expose_uuid())
                .bind(account_id)
                .bind(key_scope_code)
                .bind(threshold_idx)
                .fetch_optional(pool)
                .await?;

            Ok::<Option<BlockHeight>, SqlxClientError>(
                row.and_then(|(h,)| h)
                    .map(|h| BlockHeight::from_u32(h as u32)),
            )
        } else {
            Ok(None)
        }
    };

    let h_external = get_height(TransparentKeyScope::EXTERNAL, gap_limits.external()).await?;
    let h_internal = get_height(TransparentKeyScope::INTERNAL, gap_limits.internal()).await?;

    match (h_external, h_internal) {
        (Some(ext), Some(int)) => Ok(std::cmp::min(ext, int)),
        (Some(h), None) | (None, Some(h)) => Ok(h),
        (None, None) => {
            // Fall back to account birthday height
            account_birthday(pool, wallet_id, account_id).await
        }
    }
}

/// Gets the birthday height for an account.
#[cfg(feature = "postgres")]
async fn account_birthday(
    pool: &Pool,
    wallet_id: WalletId,
    account_id: i64,
) -> Result<BlockHeight, SqlxClientError> {
    let row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT birthday_height FROM accounts WHERE wallet_id = $1 AND id = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    match row {
        Some((h,)) => Ok(BlockHeight::from_u32(h as u32)),
        None => Err(SqlxClientError::AccountUnknown),
    }
}

/// Gets the current chain tip height (global - same for all wallets).
#[cfg(feature = "postgres")]
async fn get_chain_tip(
    pool: &Pool,
    _wallet_id: WalletId,
) -> Result<Option<BlockHeight>, SqlxClientError> {
    // blocks table is global - all wallets share the same blockchain data
    let row: Option<(Option<i64>,)> =
        sqlx_core::query_as::query_as("SELECT MAX(height) FROM blocks")
            .fetch_optional(pool)
            .await?;

    match row {
        Some((Some(h),)) if h >= 0 => Ok(Some(BlockHeight::from_u32(h as u32))),
        _ => Ok(None),
    }
}

/// Find the start of the gap for a given key scope.
/// Returns the first index where we can start allocating addresses from the gap.
#[cfg(feature = "postgres")]
async fn find_gap_start(
    pool: &Pool,
    wallet_id: WalletId,
    account_id: i64,
    key_scope: TransparentKeyScope,
    _gap_limit: u32,
) -> Result<Option<NonHardenedChildIndex>, SqlxClientError> {
    let key_scope_code = KeyScope::from(key_scope).encode();

    // This query finds the first gap of at least gap_limit unused addresses.
    // It looks at addresses that have been used (have transparent_received_outputs)
    // and finds the first gap after them.
    //
    // For now, use a simpler approach: find the maximum used index and start from there + 1,
    // or start from 0 if no addresses have been used.
    let query = r#"
        SELECT COALESCE(MAX(a.transparent_child_index) + 1, 0)::INTEGER as gap_start
        FROM addresses a
        LEFT JOIN transparent_received_outputs tro ON tro.address_id = a.id
        WHERE a.wallet_id = $1
          AND a.account_id = $2
          AND a.key_scope = $3
          AND a.transparent_child_index IS NOT NULL
          AND (a.exposed_at_height IS NOT NULL OR tro.id IS NOT NULL)
    "#;

    let row: Option<(i32,)> = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account_id)
        .bind(key_scope_code)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((gap_start,)) => Ok(NonHardenedChildIndex::from_index(gap_start as u32)),
        None => Ok(Some(NonHardenedChildIndex::ZERO)),
    }
}

/// Public version of find_gap_start for use in testing.
#[cfg(all(feature = "postgres", any(test, feature = "test-dependencies")))]
pub async fn find_gap_start_internal(
    pool: &Pool,
    wallet_id: WalletId,
    account_id: i64,
    key_scope: TransparentKeyScope,
    gap_limit: u32,
) -> Result<Option<NonHardenedChildIndex>, SqlxClientError> {
    find_gap_start(pool, wallet_id, account_id, key_scope, gap_limit).await
}

/// Generate addresses for a range of transparent child indices.
#[cfg(feature = "postgres")]
#[allow(clippy::too_many_arguments)]
pub async fn generate_address_range<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: i64,
    ufvk: &UnifiedFullViewingKey,
    key_scope: TransparentKeyScope,
    start: NonHardenedChildIndex,
    end: NonHardenedChildIndex,
) -> Result<(), SqlxClientError> {
    // Check if the account has a transparent key
    let transparent_key = match ufvk.transparent() {
        Some(k) => k,
        None => return Ok(()), // No transparent key, nothing to generate
    };

    let key_scope_code = KeyScope::from(key_scope).encode();

    // Generate addresses for the range
    let mut current = start;
    while current.index() < end.index() {
        // Derive the transparent address based on key scope
        let transparent_address = match key_scope {
            TransparentKeyScope::EXTERNAL => transparent_key
                .derive_external_ivk()
                .map_err(|e| SqlxClientError::Encoding(format!("Key derivation error: {:?}", e)))?
                .derive_address(current)
                .map_err(|e| {
                    SqlxClientError::Encoding(format!("Address derivation error: {:?}", e))
                })?,
            TransparentKeyScope::INTERNAL => transparent_key
                .derive_internal_ivk()
                .map_err(|e| SqlxClientError::Encoding(format!("Key derivation error: {:?}", e)))?
                .derive_address(current)
                .map_err(|e| {
                    SqlxClientError::Encoding(format!("Address derivation error: {:?}", e))
                })?,
            TransparentKeyScope::EPHEMERAL => transparent_key
                .derive_ephemeral_ivk()
                .map_err(|e| SqlxClientError::Encoding(format!("Key derivation error: {:?}", e)))?
                .derive_ephemeral_address(current)
                .map_err(|e| {
                    SqlxClientError::Encoding(format!("Address derivation error: {:?}", e))
                })?,
            _ => {
                return Err(SqlxClientError::Encoding(
                    "Unsupported transparent key scope".to_string(),
                ));
            }
        };

        let address_encoded = transparent_address.encode(params);

        // Insert or ignore if already exists
        // For transparent-only addresses, we store the transparent address in both columns
        let insert_query = r#"
            INSERT INTO addresses (
                wallet_id, account_id, key_scope, address,
                transparent_child_index, cached_transparent_receiver_address,
                receiver_flags, diversifier_index_be
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (wallet_id, account_id, key_scope, diversifier_index_be) DO NOTHING
        "#;

        // Use the transparent_child_index as diversifier_index_be for transparent addresses
        let di_bytes = current.index().to_be_bytes().to_vec();

        sqlx_core::query::query(insert_query)
            .bind(wallet_id.expose_uuid())
            .bind(account_id)
            .bind(key_scope_code)
            .bind(&address_encoded) // Store transparent address as the main address
            .bind(current.index() as i32)
            .bind(&address_encoded) // Also store in cached_transparent_receiver_address
            .bind(1i32) // P2PKH receiver flag
            .bind(di_bytes)
            .execute(pool)
            .await
            .ok(); // Ignore conflicts

        current = match NonHardenedChildIndex::from_index(current.index() + 1) {
            Some(idx) => idx,
            None => break, // Overflow, stop
        };
    }

    Ok(())
}

/// Generate gap addresses for a given key scope.
/// This pre-generates addresses up to the gap limit.
#[cfg(feature = "postgres")]
pub async fn generate_gap_addresses<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: i64,
    ufvk: &UnifiedFullViewingKey,
    key_scope: TransparentKeyScope,
    gap_limits: &GapLimits,
) -> Result<(), SqlxClientError> {
    let gap_limit = match key_scope {
        TransparentKeyScope::EXTERNAL => gap_limits.external,
        TransparentKeyScope::INTERNAL => gap_limits.internal,
        TransparentKeyScope::EPHEMERAL => gap_limits.ephemeral,
        _ => {
            return Err(SqlxClientError::Encoding(
                "Unsupported transparent key scope".to_string(),
            ));
        }
    };

    if let Some(gap_start) =
        find_gap_start(pool, wallet_id, account_id, key_scope, gap_limit).await?
    {
        let gap_end = gap_start.saturating_add(gap_limit);
        generate_address_range(
            pool, params, wallet_id, account_id, ufvk, key_scope, gap_start, gap_end,
        )
        .await?;
    }

    Ok(())
}

/// Reserve the next n ephemeral addresses for use in a transaction.
#[cfg(feature = "postgres")]
pub async fn reserve_next_n_ephemeral_addresses<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    account_id: AccountUuid,
    n: usize,
    gap_limits: &GapLimits,
) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, SqlxClientError> {
    if n == 0 {
        return Ok(vec![]);
    }

    // Get the account's internal ID
    let account_row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM accounts WHERE wallet_id = $1 AND uuid = $2 AND deleted_at IS NULL",
    )
    .bind(wallet_id.expose_uuid())
    .bind(account_id.expose_uuid())
    .fetch_optional(pool)
    .await?;

    let internal_account_id = match account_row {
        Some((id,)) => id,
        None => return Err(SqlxClientError::AccountNotFound(account_id)),
    };

    // Get the account's UFVK to potentially generate more addresses
    let ufvk_row: Option<(String,)> =
        sqlx_core::query_as::query_as("SELECT ufvk FROM accounts WHERE id = $1")
            .bind(internal_account_id)
            .fetch_optional(pool)
            .await?;

    let ufvk_str = match ufvk_row {
        Some((s,)) => s,
        None => return Err(SqlxClientError::AccountNotFound(account_id)),
    };

    let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str)
        .map_err(|e| SqlxClientError::Encoding(format!("Failed to decode UFVK: {:?}", e)))?;

    // Ensure we have enough addresses generated
    generate_gap_addresses(
        pool,
        params,
        wallet_id,
        internal_account_id,
        &ufvk,
        TransparentKeyScope::EPHEMERAL,
        gap_limits,
    )
    .await?;

    let key_scope_code = KeyScope::Ephemeral.encode();

    // Find the gap start
    let gap_start = find_gap_start(
        pool,
        wallet_id,
        internal_account_id,
        TransparentKeyScope::EPHEMERAL,
        gap_limits.ephemeral,
    )
    .await?
    .unwrap_or(NonHardenedChildIndex::ZERO);

    let gap_end = gap_start.index() + gap_limits.ephemeral;

    // Select addresses to reserve (not yet exposed)
    let select_query = r#"
        SELECT id, transparent_child_index, cached_transparent_receiver_address
        FROM addresses
        WHERE wallet_id = $1
          AND account_id = $2
          AND key_scope = $3
          AND transparent_child_index >= $4
          AND transparent_child_index < $5
          AND exposed_at_height IS NULL
        ORDER BY transparent_child_index
        LIMIT $6
    "#;

    let rows: Vec<(i64, i32, Option<String>)> = sqlx_core::query_as::query_as(select_query)
        .bind(wallet_id.expose_uuid())
        .bind(internal_account_id)
        .bind(key_scope_code)
        .bind(gap_start.index() as i32)
        .bind(gap_end as i32)
        .bind(n as i64)
        .fetch_all(pool)
        .await?;

    if rows.len() < n {
        return Err(SqlxClientError::AddressGapLimitExceeded {
            key_scope: TransparentKeyScope::EPHEMERAL,
            max_address_index: gap_end,
        });
    }

    // Check that the maximum index being reserved doesn't exceed the safe limit.
    // The maximum safe index is (gap_limit * 2) - 1, because we need to ensure
    // that recovery by gap limit exploration will find all allocated addresses.
    let max_safe_index = gap_limits.ephemeral * 2;
    if let Some((_, max_child_index, _)) = rows.last() {
        let max_index = *max_child_index as u32;
        if max_index >= max_safe_index {
            return Err(SqlxClientError::AddressGapLimitExceeded {
                key_scope: TransparentKeyScope::EPHEMERAL,
                max_address_index: max_safe_index,
            });
        }
    }

    // Get the current chain tip height for marking exposure
    let chain_tip = get_chain_tip(pool, wallet_id)
        .await?
        .ok_or(SqlxClientError::ChainHeightUnavailable)?;
    let chain_tip_i64 = u32::from(chain_tip) as i64;

    // Update the addresses to mark them as exposed
    let address_ids: Vec<i64> = rows.iter().map(|(id, _, _)| *id).collect();
    for id in &address_ids {
        sqlx_core::query::query("UPDATE addresses SET exposed_at_height = $1 WHERE id = $2")
            .bind(chain_tip_i64)
            .bind(id)
            .execute(pool)
            .await?;
    }

    // Regenerate addresses to maintain the gap after marking some as exposed
    generate_gap_addresses(
        pool,
        params,
        wallet_id,
        internal_account_id,
        &ufvk,
        TransparentKeyScope::EPHEMERAL,
        gap_limits,
    )
    .await?;

    // Build the result with proper exposure metadata
    let mut results = Vec::with_capacity(n);
    for (gap_position, (_, child_index, addr_str)) in rows.into_iter().enumerate() {
        let addr_str = addr_str.ok_or(SqlxClientError::CorruptedOutput)?;
        let transparent_address = TransparentAddress::decode(params, &addr_str)
            .map_err(|_| SqlxClientError::Encoding("Invalid transparent address".to_string()))?;

        let child_idx = NonHardenedChildIndex::from_index(child_index as u32)
            .ok_or(SqlxClientError::CorruptedOutput)?;

        // Reserved addresses are exposed at the chain tip height with InGap metadata
        let exposure = Exposure::Exposed {
            at_height: chain_tip,
            gap_metadata: zcash_client_backend::wallet::GapMetadata::InGap {
                gap_position: gap_position as u32,
                gap_limit: gap_limits.ephemeral,
            },
        };

        let metadata = TransparentAddressMetadata::derived(
            TransparentKeyScope::EPHEMERAL,
            child_idx,
            exposure,
            None,
        );

        results.push((transparent_address, metadata));
    }

    Ok(results)
}

/// An enumeration of the types of errors that can occur when scheduling an event to happen at a
/// specific time.
#[derive(Debug, Clone)]
pub enum SchedulingError {
    /// An error occurred in sampling a time offset using an exponential distribution.
    Distribution(rand_distr::ExpError),
    /// The system attempted to generate an invalid timestamp.
    Time(std::time::SystemTimeError),
    /// A generated duration was out of the range of valid integer values for durations.
    OutOfRange(std::num::TryFromIntError),
}

impl std::fmt::Display for SchedulingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            SchedulingError::Distribution(e) => {
                write!(f, "Failure in sampling scheduling time: {e}")
            }
            SchedulingError::Time(t) => write!(f, "Invalid system time: {t}"),
            SchedulingError::OutOfRange(t) => write!(f, "Not a valid timestamp or duration: {t}"),
        }
    }
}

impl std::error::Error for SchedulingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self {
            SchedulingError::Distribution(_) => None,
            SchedulingError::Time(t) => Some(t),
            SchedulingError::OutOfRange(i) => Some(i),
        }
    }
}

impl From<rand_distr::ExpError> for SchedulingError {
    fn from(value: rand_distr::ExpError) -> Self {
        SchedulingError::Distribution(value)
    }
}

impl From<std::time::SystemTimeError> for SchedulingError {
    fn from(value: std::time::SystemTimeError) -> Self {
        SchedulingError::Time(value)
    }
}

impl From<std::num::TryFromIntError> for SchedulingError {
    fn from(value: std::num::TryFromIntError) -> Self {
        SchedulingError::OutOfRange(value)
    }
}

impl From<SchedulingError> for SqlxClientError {
    fn from(value: SchedulingError) -> Self {
        SqlxClientError::Encoding(value.to_string())
    }
}

/// Sample a random timestamp from an exponential distribution such that the expected value of the
/// generated timestamp is `check_interval_seconds` after the provided `from_event` time.
pub fn next_check_time<R: RngCore, D: DerefMut<Target = R>>(
    mut rng: D,
    from_event: SystemTime,
    check_interval_seconds: u32,
) -> Result<SystemTime, SchedulingError> {
    // A λ parameter of 1/check_interval_seconds will result in a distribution with an expected
    // value of `check_interval_seconds`.
    let dist = rand_distr::Exp::new(1.0 / f64::from(check_interval_seconds))?;
    let event_delay = dist.sample(rng.deref_mut()).round() as u64;

    Ok(from_event + Duration::new(event_delay, 0))
}

/// Schedule the next check time for a transparent address.
#[cfg(feature = "postgres")]
pub async fn schedule_next_check<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    address: &TransparentAddress,
    offset_seconds: u32,
) -> Result<Option<SystemTime>, SqlxClientError> {
    use rand::thread_rng;
    let addr_str = address.encode(params);
    let now = SystemTime::now();
    let mut rng = thread_rng();
    let next_check = next_check_time(&mut rng, now, offset_seconds)?;

    let current_epoch = epoch_seconds(now)?;
    let next_check_epoch = epoch_seconds(next_check)?;

    // Update the next check time if it's earlier than the existing one or if the existing
    // one has passed
    let query = r#"
        UPDATE addresses
        SET transparent_receiver_next_check_time = CASE
            WHEN transparent_receiver_next_check_time < $1 THEN $2
            WHEN $2 <= COALESCE(transparent_receiver_next_check_time, $2) THEN $2
            ELSE COALESCE(transparent_receiver_next_check_time, $2)
        END
        WHERE wallet_id = $3
          AND cached_transparent_receiver_address = $4
        RETURNING transparent_receiver_next_check_time
    "#;

    let row: Option<(Option<i64>,)> = sqlx_core::query_as::query_as(query)
        .bind(current_epoch)
        .bind(next_check_epoch)
        .bind(wallet_id.expose_uuid())
        .bind(&addr_str)
        .fetch_optional(pool)
        .await?;

    match row {
        Some((Some(ts),)) => decode_epoch_seconds(ts).map(Some),
        _ => Ok(None),
    }
}

/// Convert a SystemTime to epoch seconds.
fn epoch_seconds(time: SystemTime) -> Result<i64, SqlxClientError> {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .map_err(|e| SqlxClientError::Encoding(format!("Invalid system time: {e}")))
}

/// Convert epoch seconds to a SystemTime.
fn decode_epoch_seconds(secs: i64) -> Result<SystemTime, SqlxClientError> {
    if secs >= 0 {
        Ok(SystemTime::UNIX_EPOCH + Duration::from_secs(secs as u64))
    } else {
        Err(SqlxClientError::Encoding(format!(
            "Negative epoch seconds: {secs}"
        )))
    }
}

/// Updates the max_observed_unspent_height for unspent transparent outputs at the given address.
#[cfg(feature = "postgres")]
pub async fn update_observed_unspent_heights<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    address: TransparentAddress,
    checked_at: BlockHeight,
) -> Result<(), SqlxClientError> {
    let chain_tip = get_chain_tip(pool, wallet_id).await?;
    let chain_tip_height = chain_tip.ok_or(SqlxClientError::ChainHeightUnavailable)?;
    let checked_at = std::cmp::min(checked_at, chain_tip_height);
    let checked_at_i64 = u32::from(checked_at) as i64;

    let addr_str = address.encode(params);

    // Update max_observed_unspent_height for all unspent outputs at this address
    let query = r#"
        UPDATE transparent_received_outputs AS tro
        SET max_observed_unspent_height = CASE
            WHEN max_observed_unspent_height IS NULL THEN $1
            WHEN max_observed_unspent_height < $1 THEN $1
            ELSE max_observed_unspent_height
        END
        WHERE wallet_id = $2
          AND address = $3
          AND tro.id NOT IN (
              SELECT transparent_received_output_id
              FROM transparent_received_output_spends
          )
    "#;

    sqlx_core::query::query(query)
        .bind(checked_at_i64)
        .bind(wallet_id.expose_uuid())
        .bind(&addr_str)
        .execute(pool)
        .await?;

    Ok(())
}

/// Adds the given received UTXO to the datastore.
#[cfg(feature = "postgres")]
pub async fn put_received_transparent_utxo<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    gap_limits: &GapLimits,
    output: &zcash_client_backend::wallet::WalletTransparentOutput,
) -> Result<crate::UtxoId, SqlxClientError> {
    let observed_height = get_chain_tip(pool, wallet_id)
        .await?
        .ok_or(SqlxClientError::ChainHeightUnavailable)?;

    put_transparent_output(
        pool,
        params,
        wallet_id,
        gap_limits,
        output,
        observed_height,
        true,
    )
    .await
}

/// Internal function to store a transparent output.
#[cfg(feature = "postgres")]
async fn put_transparent_output<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    gap_limits: &GapLimits,
    output: &zcash_client_backend::wallet::WalletTransparentOutput,
    observed_height: BlockHeight,
    _is_external: bool,
) -> Result<crate::UtxoId, SqlxClientError> {
    let outpoint = output.outpoint();
    let txout = output.txout();
    let height = output.mined_height();

    // Get the address from the script
    let address = txout
        .recipient_address()
        .ok_or_else(|| SqlxClientError::Encoding("Invalid script for UTXO".to_string()))?;

    let addr_str = address.encode(params);

    // Find the account for this address
    let account_info =
        find_account_for_transparent_address(pool, params, wallet_id, &address).await?;

    let (_account_uuid, account_id, key_scope) = match account_info {
        Some(info) => info,
        None => return Err(SqlxClientError::AccountUnknown),
    };

    // Get or create the address entry
    let address_id = get_or_create_address_id(pool, wallet_id, account_id, &addr_str).await?;

    // Get or create the transaction entry
    let tx_id = get_or_create_transaction(pool, wallet_id, *outpoint.hash(), height).await?;

    let value_zat = u64::from(txout.value()) as i64;
    let script_bytes = txout.script_pubkey().0.0.clone();
    let output_index = outpoint.n() as i32;
    let observed_height_i64 = u32::from(observed_height) as i64;

    // Insert or update the transparent received output
    let query = r#"
        INSERT INTO transparent_received_outputs
            (wallet_id, tx_id, output_index, account_id, address_id, address, script, value_zat, max_observed_unspent_height)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (wallet_id, tx_id, output_index)
        DO UPDATE SET
            max_observed_unspent_height = GREATEST(
                transparent_received_outputs.max_observed_unspent_height,
                EXCLUDED.max_observed_unspent_height
            )
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(tx_id)
        .bind(output_index)
        .bind(account_id)
        .bind(address_id)
        .bind(&addr_str)
        .bind(&script_bytes)
        .bind(value_zat)
        .bind(observed_height_i64)
        .fetch_one(pool)
        .await?;

    // Update gap limits if needed
    if let Some(t_key_scope) = <Option<TransparentKeyScope>>::from(key_scope) {
        let ufvk_row: Option<(String,)> =
            sqlx_core::query_as::query_as("SELECT ufvk FROM accounts WHERE id = $1")
                .bind(account_id)
                .fetch_optional(pool)
                .await?;

        if let Some((ufvk_str,)) = ufvk_row {
            let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                SqlxClientError::Encoding(format!("Failed to decode UFVK: {:?}", e))
            })?;

            generate_gap_addresses(
                pool,
                params,
                wallet_id,
                account_id,
                &ufvk,
                t_key_scope,
                gap_limits,
            )
            .await?;
        }
    }

    Ok(crate::UtxoId(row.0))
}

/// Get or create an address ID for a transparent address.
#[cfg(feature = "postgres")]
async fn get_or_create_address_id(
    pool: &Pool,
    wallet_id: WalletId,
    account_id: i64,
    addr_str: &str,
) -> Result<i64, SqlxClientError> {
    // Try to get existing address
    let row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM addresses WHERE wallet_id = $1 AND cached_transparent_receiver_address = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(addr_str)
    .fetch_optional(pool)
    .await?;

    if let Some((id,)) = row {
        return Ok(id);
    }

    // Create a new address entry (for foreign/imported addresses)
    let query = r#"
        INSERT INTO addresses (wallet_id, account_id, key_scope, cached_transparent_receiver_address)
        VALUES ($1, $2, $3, $4)
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(account_id)
        .bind(KeyScope::Foreign.encode())
        .bind(addr_str)
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// Get or create a transaction entry for a txid.
#[cfg(feature = "postgres")]
async fn get_or_create_transaction(
    pool: &Pool,
    wallet_id: WalletId,
    txid_bytes: [u8; 32],
    mined_height: Option<BlockHeight>,
) -> Result<i64, SqlxClientError> {
    // Try to get existing transaction
    let row: Option<(i64,)> = sqlx_core::query_as::query_as(
        "SELECT id FROM transactions WHERE wallet_id = $1 AND txid = $2",
    )
    .bind(wallet_id.expose_uuid())
    .bind(&txid_bytes[..])
    .fetch_optional(pool)
    .await?;

    if let Some((id,)) = row {
        return Ok(id);
    }

    // Create a new transaction entry
    let mined_height_i64 = mined_height.map(|h| u32::from(h) as i64);

    let query = r#"
        INSERT INTO transactions (wallet_id, txid, mined_height)
        VALUES ($1, $2, $3)
        RETURNING id
    "#;

    let row: (i64,) = sqlx_core::query_as::query_as(query)
        .bind(wallet_id.expose_uuid())
        .bind(&txid_bytes[..])
        .bind(mined_height_i64)
        .fetch_one(pool)
        .await?;

    Ok(row.0)
}

/// Returns the vector of [`TransactionDataRequest`]s that represents the information needed by the
/// wallet backend in order to be able to present a complete view of wallet history and memo data.
#[cfg(feature = "postgres")]
pub async fn transaction_data_requests<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    chain_tip_height: BlockHeight,
) -> Result<Vec<zcash_client_backend::data_api::TransactionDataRequest>, SqlxClientError> {
    use zcash_client_backend::data_api::{
        OutputStatusFilter, TransactionDataRequest, TransactionStatusFilter,
    };

    const DEFAULT_TX_EXPIRY_DELTA: u32 = 40;

    let chain_tip_i64 = u32::from(chain_tip_height) as i64;

    // Create transaction data requests that can find spends of our received UTXOs
    let spend_requests_query = r#"
        SELECT
            ssq.address,
            COALESCE(tro.max_observed_unspent_height + 1, t.mined_height)::INTEGER AS block_range_start
        FROM transparent_spend_search_queue ssq
        JOIN transactions t ON t.id = ssq.transaction_id
        JOIN transparent_received_outputs tro ON tro.tx_id = t.id
        JOIN addresses ON addresses.id = tro.address_id
        LEFT OUTER JOIN transparent_received_output_spends tros
            ON tros.transparent_received_output_id = tro.id
        WHERE ssq.wallet_id = $1
          AND tros.transaction_id IS NULL
          AND addresses.key_scope != $2
          AND (
              tro.max_observed_unspent_height IS NULL
              OR tro.max_observed_unspent_height < $3
          )
          AND (
              block_range_start IS NOT NULL
              OR t.expiry_height > $3
          )
    "#;

    let spend_rows: Vec<(String, Option<i32>)> =
        sqlx_core::query_as::query_as(spend_requests_query)
            .bind(wallet_id.expose_uuid())
            .bind(KeyScope::Ephemeral.encode())
            .bind(chain_tip_i64)
            .fetch_all(pool)
            .await?;

    let mut requests = Vec::new();

    for (addr_str, block_range_start) in spend_rows {
        let address = TransparentAddress::decode(params, &addr_str)
            .map_err(|_| SqlxClientError::Encoding(format!("Invalid address: {addr_str}")))?;

        // If the transaction that creates this UTXO is unmined, default to chain tip
        let block_range_start = block_range_start
            .map(|h| BlockHeight::from_u32(h as u32))
            .unwrap_or(chain_tip_height);

        let max_end_height = block_range_start + DEFAULT_TX_EXPIRY_DELTA + 1;

        requests.push(TransactionDataRequest::transactions_involving_address(
            address,
            block_range_start,
            Some(std::cmp::min(chain_tip_height + 1, max_end_height)),
            None,
            TransactionStatusFilter::Mined,
            OutputStatusFilter::All,
        ));
    }

    // Query for ephemeral addresses that need checking
    let ephemeral_query = r#"
        SELECT
            cached_transparent_receiver_address,
            MIN(COALESCE(tro.max_observed_unspent_height + 1, t.mined_height))::INTEGER,
            transparent_receiver_next_check_time
        FROM addresses
        LEFT OUTER JOIN transparent_received_outputs tro ON tro.address_id = addresses.id
        LEFT OUTER JOIN transactions t ON t.id = tro.tx_id
        WHERE addresses.wallet_id = $1
          AND addresses.key_scope = $2
          -- ensure that there is not a pending transaction
          AND NOT EXISTS (
              SELECT 1
              FROM transparent_received_outputs tro2
              JOIN transactions t2 ON t2.id = tro2.tx_id
              WHERE tro2.address_id = addresses.id
                AND t2.expiry_height > $3
          )
        GROUP BY addresses.id
    "#;

    let ephemeral_rows: Vec<(Option<String>, Option<i32>, Option<i64>)> =
        sqlx_core::query_as::query_as(ephemeral_query)
            .bind(wallet_id.expose_uuid())
            .bind(KeyScope::Ephemeral.encode())
            .bind(chain_tip_i64)
            .fetch_all(pool)
            .await?;

    for (addr_str, block_range_start, next_check_time) in ephemeral_rows {
        let addr_str = match addr_str {
            Some(s) => s,
            None => continue,
        };

        let address = TransparentAddress::decode(params, &addr_str)
            .map_err(|_| SqlxClientError::Encoding(format!("Invalid address: {addr_str}")))?;

        let block_range_start = BlockHeight::from_u32(block_range_start.unwrap_or(0) as u32);

        let request_at = next_check_time.map(decode_epoch_seconds).transpose()?;

        requests.push(TransactionDataRequest::transactions_involving_address(
            address,
            block_range_start,
            None,
            request_at,
            TransactionStatusFilter::All,
            OutputStatusFilter::Unspent,
        ));
    }

    Ok(requests)
}

#[cfg(feature = "postgres")]
pub async fn notify_address_checked(
    _pool: &Pool,
    _wallet_id: WalletId,
    _request: TransactionsInvolvingAddress,
    _as_of_height: BlockHeight,
) -> Result<(), SqlxClientError> {
    // TODO: Implement
    Ok(())
}

/// Updates gap addresses when a transaction is mined, ensuring we always have
/// enough addresses to meet the gap limit after addresses are used.
#[cfg(feature = "postgres")]
pub async fn update_gap_limits<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    gap_limits: &GapLimits,
    txid: TxId,
    observation_height: BlockHeight,
) -> Result<(), SqlxClientError> {
    // Query for addresses used in this transaction via transparent_received_outputs
    // and transparent_received_output_spends
    let scopes_query = r#"
        SELECT tro.address_id, a.account_id, a.key_scope
        FROM transparent_received_outputs tro
        JOIN addresses a ON a.id = tro.address_id
        JOIN transactions t ON t.id = tro.tx_id
        WHERE t.wallet_id = $1 AND t.txid = $2
        UNION
        SELECT tro.address_id, a.account_id, a.key_scope
        FROM transparent_received_output_spends tros
        JOIN transparent_received_outputs tro ON tro.id = tros.transparent_received_output_id
        JOIN addresses a ON a.id = tro.address_id
        JOIN transactions t ON t.id = tros.transaction_id
        WHERE t.wallet_id = $1 AND t.txid = $2
    "#;

    let rows: Vec<(i64, i64, i32)> = sqlx_core::query_as::query_as(scopes_query)
        .bind(wallet_id.expose_uuid())
        .bind(txid.as_ref())
        .fetch_all(pool)
        .await?;

    let height_i64 = u32::from(observation_height) as i64;

    for (addr_id, account_id, key_scope_code) in rows {
        // Update the exposure height for the address, in case the transaction was mined at a lower
        // height than the existing exposure height due to a reorg.
        sqlx_core::query::query(
            "UPDATE addresses
             SET exposed_at_height = LEAST(
                COALESCE(exposed_at_height, $1),
                $1
             )
             WHERE id = $2",
        )
        .bind(height_i64)
        .bind(addr_id)
        .execute(pool)
        .await?;

        let key_scope = KeyScope::decode(key_scope_code as i64)?;
        if let Some(t_key_scope) = <Option<TransparentKeyScope>>::from(key_scope) {
            // Get account UFVK for address generation
            let ufvk_row: Option<(String,)> =
                sqlx_core::query_as::query_as("SELECT ufvk FROM accounts WHERE id = $1")
                    .bind(account_id)
                    .fetch_optional(pool)
                    .await?;

            if let Some((ufvk_str,)) = ufvk_row {
                let ufvk = UnifiedFullViewingKey::decode(params, &ufvk_str).map_err(|e| {
                    SqlxClientError::Encoding(format!("Failed to decode UFVK: {:?}", e))
                })?;

                generate_gap_addresses(
                    pool,
                    params,
                    wallet_id,
                    account_id,
                    &ufvk,
                    t_key_scope,
                    gap_limits,
                )
                .await?;
            }
        }
    }

    Ok(())
}

/// Find the account and key scope for a transparent address.
/// Returns None if the address doesn't belong to any account in the wallet.
#[cfg(feature = "postgres")]
pub async fn find_account_for_transparent_address<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    address: &TransparentAddress,
) -> Result<Option<(AccountUuid, i64, KeyScope)>, SqlxClientError> {
    use zcash_keys::keys::UnifiedIncomingViewingKey;

    let address_str = address.encode(params);

    // Check if the address is in our addresses table
    let row: Option<(uuid::Uuid, i64, i32)> = sqlx_core::query_as::query_as(
        r#"
        SELECT accounts.uuid, addresses.account_id, addresses.key_scope
        FROM addresses
        JOIN accounts ON accounts.id = addresses.account_id
        WHERE addresses.wallet_id = $1
          AND addresses.cached_transparent_receiver_address = $2
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(&address_str)
    .fetch_optional(pool)
    .await?;

    if let Some((account_uuid, account_id, key_scope_code)) = row {
        let key_scope = KeyScope::decode(key_scope_code as i64)?;
        return Ok(Some((
            AccountUuid::from_uuid(account_uuid),
            account_id,
            key_scope,
        )));
    }

    // Fallback: If the UTXO is received at the legacy transparent address (at BIP 44 address
    // index 0 within its particular account), there may be no entry in the addresses table
    // that can be used to tie the address to a particular account. In this case, we
    // look up the legacy address for each account in the wallet, and check whether it
    // matches the address for the received UTXO.
    let accounts: Vec<(uuid::Uuid, i64, String)> = sqlx_core::query_as::query_as(
        r#"
        SELECT uuid, id, uivk
        FROM accounts
        WHERE wallet_id = $1 AND deleted_at IS NULL AND uivk IS NOT NULL
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .fetch_all(pool)
    .await?;

    for (account_uuid, account_id, uivk_str) in accounts {
        // Decode the UIVK and derive the legacy transparent address
        if let Ok(uivk) = UnifiedIncomingViewingKey::decode(params, &uivk_str) {
            if let Some(transparent_ivk) = uivk.transparent() {
                let (legacy_addr, _) = transparent_ivk.default_address();
                if legacy_addr == *address {
                    return Ok(Some((
                        AccountUuid::from_uuid(account_uuid),
                        account_id,
                        KeyScope::External,
                    )));
                }
            }
        }
    }

    Ok(None)
}

#[cfg(all(feature = "transparent-key-import", feature = "postgres"))]
pub async fn import_standalone_transparent_pubkey<P: Parameters>(
    _pool: &Pool,
    _params: &P,
    _wallet_id: WalletId,
    _account: AccountUuid,
    _pubkey: secp256k1::PublicKey,
) -> Result<(), SqlxClientError> {
    // TODO: Implement
    Ok(())
}

/// Marks the given UTXO as having been spent.
///
/// Returns `true` if the UTXO was known to the wallet.
#[cfg(feature = "postgres")]
pub async fn mark_transparent_utxo_spent(
    pool: &Pool,
    wallet_id: WalletId,
    spent_in_tx: i64,
    outpoint: &OutPoint,
) -> Result<bool, SqlxClientError> {
    // Insert into transparent_received_output_spends, selecting the output ID
    // based on matching the transaction txid and output index.
    let query = r#"
        INSERT INTO transparent_received_output_spends (wallet_id, transparent_received_output_id, transaction_id)
        SELECT $1, txo.id, $2
        FROM transparent_received_outputs txo
        JOIN transactions t ON t.id = txo.tx_id
        WHERE t.wallet_id = $1 AND t.txid = $3 AND txo.output_index = $4
        ON CONFLICT (wallet_id, transparent_received_output_id, transaction_id) DO NOTHING
    "#;

    let result = sqlx_core::query::query(query)
        .bind(wallet_id.expose_uuid())
        .bind(spent_in_tx)
        .bind(outpoint.hash())
        .bind(outpoint.n() as i32)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Add a transparent output for an ephemeral address to the database.
/// This marks the ephemeral address as "used" for the purposes of get_ephemeral_transparent_receivers.
#[cfg(feature = "postgres")]
pub async fn put_transparent_output_for_ephemeral<P: Parameters>(
    pool: &Pool,
    params: &P,
    wallet_id: WalletId,
    ephemeral_address: &TransparentAddress,
    outpoint: &OutPoint,
    value: zcash_protocol::value::Zatoshis,
    target_height: BlockHeight,
) -> Result<(), SqlxClientError> {
    let addr_str = ephemeral_address.encode(params);

    // Find the address_id from the addresses table
    let address_row: Option<(i64, i64)> = sqlx_core::query_as::query_as(
        r#"
        SELECT id, account_id
        FROM addresses
        WHERE wallet_id = $1
          AND cached_transparent_receiver_address = $2
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(&addr_str)
    .fetch_optional(pool)
    .await?;

    let (address_id, account_id) = match address_row {
        Some((aid, acc_id)) => (aid, acc_id),
        None => {
            return Err(SqlxClientError::Encoding(format!(
                "Ephemeral address {} not found in addresses table",
                addr_str
            )));
        }
    };

    // Insert or get the transaction
    let txid_bytes = outpoint.hash();
    let target_height_i64 = u32::from(target_height) as i64;

    let tx_id: i64 = sqlx_core::query_scalar::query_scalar(
        r#"
        INSERT INTO transactions (wallet_id, txid, min_observed_height)
        VALUES ($1, $2, $3)
        ON CONFLICT (wallet_id, txid) DO UPDATE
            SET min_observed_height = LEAST(transactions.min_observed_height, EXCLUDED.min_observed_height)
        RETURNING id
        "#,
    )
    .bind(wallet_id.expose_uuid())
    .bind(txid_bytes)
    .bind(target_height_i64)
    .fetch_one(pool)
    .await?;

    // Insert the transparent received output
    let output_index = outpoint.n() as i32;
    let value_zat = value.into_u64() as i64;
    let script_bytes = ephemeral_address.script().to_bytes();

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
    .bind(output_index)
    .bind(account_id)
    .bind(address_id)
    .bind(&addr_str)
    .bind(script_bytes)
    .bind(value_zat)
    .execute(pool)
    .await?;

    Ok(())
}

/// Adds transparent UTXO balances to the account balance map.
///
/// This function queries all unspent transparent outputs and categorizes them
/// into spendable and pending balances based on confirmations.
#[cfg(feature = "postgres")]
pub async fn add_transparent_account_balances(
    pool: &Pool,
    wallet_id: WalletId,
    target_height: zcash_client_backend::data_api::wallet::TargetHeight,
    confirmations_policy: zcash_client_backend::data_api::wallet::ConfirmationsPolicy,
    account_balances: &mut std::collections::HashMap<
        AccountUuid,
        zcash_client_backend::data_api::AccountBalance,
    >,
) -> Result<(), SqlxClientError> {
    use uuid::Uuid;
    use zcash_client_backend::data_api::AccountBalance;
    use zcash_primitives::transaction::fees::zip317;
    use zcash_protocol::value::Zatoshis;

    let target_height_i64 = u32::from(target_height) as i64;

    // We treat all transparent UTXOs as untrusted; however, if zero-conf shielding
    // is enabled, we set the minimum number of confirmations to zero.
    let min_confirmations: i64 = if confirmations_policy.allow_zero_conf_shielding() {
        0
    } else {
        u32::from(confirmations_policy.untrusted()) as i64
    };

    // Query for spendable transparent UTXOs:
    // - Transaction is mined with enough confirmations OR
    // - min_confirmations is 0 and transaction is unexpired
    // - UTXO is not spent
    // - Exclude wallet-internal ephemeral outputs that are likely spent
    let spendable_query = r#"
        SELECT acct.uuid, COALESCE(SUM(u.value_zat), 0)::BIGINT
        FROM transparent_received_outputs u
        JOIN accounts acct ON acct.id = u.account_id AND acct.wallet_id = $1
        JOIN transactions t ON t.id = u.tx_id AND t.wallet_id = $1
        JOIN addresses addr ON addr.id = u.address_id AND addr.wallet_id = $1
        WHERE u.wallet_id = $1
          AND (
            -- tx is mined and has at least min_confirmations
            (t.mined_height IS NOT NULL AND t.mined_height < $2 AND $2 - t.mined_height >= $3)
            -- or outputs may be spent with zero confirmations and the transaction is unexpired
            OR ($3 = 0 AND (t.expiry_height IS NULL OR t.expiry_height = 0 OR t.expiry_height >= $2))
          )
          -- the received txo is unspent
          AND u.id NOT IN (
            SELECT tros.transparent_received_output_id
            FROM transparent_received_output_spends tros
            JOIN transactions stx ON stx.id = tros.transaction_id AND stx.wallet_id = $1
            WHERE stx.mined_height IS NOT NULL
               OR (stx.expiry_height IS NULL OR stx.expiry_height = 0 OR stx.expiry_height >= $2)
          )
          -- exclude likely-spent wallet-internal ephemeral outputs
          AND (
            addr.key_scope != 2  -- not ephemeral
            OR t.id NOT IN (
              SELECT ros.transaction_id
              FROM (
                SELECT sn.transaction_id, n.account_id FROM sapling_received_note_spends sn
                JOIN sapling_received_notes n ON n.id = sn.sapling_received_note_id
                WHERE n.wallet_id = $1
                UNION ALL
                SELECT os.transaction_id, n.account_id FROM orchard_received_note_spends os
                JOIN orchard_received_notes n ON n.id = os.orchard_received_note_id
                WHERE n.wallet_id = $1
                UNION ALL
                SELECT trs.transaction_id, tro.account_id FROM transparent_received_output_spends trs
                JOIN transparent_received_outputs tro ON tro.id = trs.transparent_received_output_id
                WHERE tro.wallet_id = $1
              ) ros
              WHERE ros.account_id = acct.id
            )
            OR (u.max_observed_unspent_height IS NOT NULL AND t.expiry_height IS NOT NULL
                AND u.max_observed_unspent_height > t.expiry_height)
          )
          AND acct.deleted_at IS NULL
        GROUP BY acct.uuid
    "#;

    let rows: Vec<(Uuid, i64)> = sqlx_core::query_as::query_as(spendable_query)
        .bind(wallet_id.expose_uuid())
        .bind(target_height_i64)
        .bind(min_confirmations)
        .fetch_all(pool)
        .await?;

    for (account_uuid, raw_value) in rows {
        let account = AccountUuid::from_uuid(account_uuid);
        let value = Zatoshis::from_nonnegative_i64(raw_value)
            .map_err(|_| SqlxClientError::Encoding(format!("Negative UTXO value {raw_value:?}")))?;

        account_balances
            .entry(account)
            .or_insert(AccountBalance::ZERO)
            .with_unshielded_balance_mut(|bal| {
                if value >= zip317::MARGINAL_FEE {
                    bal.add_spendable_value(value)
                } else {
                    bal.add_uneconomic_value(value)
                }
            })?;
    }

    // Pending spendable balance for transparent UTXOs is only relevant for min_confirmations > 0;
    // with min_confirmations == 0, zero-conf spends are allowed and therefore the value will
    // appear in the spendable balance and we don't want to double-count it.
    if min_confirmations > 0 {
        let pending_query = r#"
            SELECT acct.uuid, COALESCE(SUM(u.value_zat), 0)::BIGINT
            FROM transparent_received_outputs u
            JOIN accounts acct ON acct.id = u.account_id AND acct.wallet_id = $1
            JOIN transactions t ON t.id = u.tx_id AND t.wallet_id = $1
            JOIN addresses addr ON addr.id = u.address_id AND addr.wallet_id = $1
            WHERE u.wallet_id = $1
              AND (
                -- the transaction that created the output is mined with not enough confirmations
                (t.mined_height IS NOT NULL AND t.mined_height < $2 AND $2 - t.mined_height < $3)
                -- or the tx is unmined but definitely not expired
                OR (t.mined_height IS NULL AND (t.expiry_height IS NULL OR t.expiry_height = 0 OR t.expiry_height >= $2))
              )
              -- the received txo is unspent
              AND u.id NOT IN (
                SELECT tros.transparent_received_output_id
                FROM transparent_received_output_spends tros
                JOIN transactions stx ON stx.id = tros.transaction_id AND stx.wallet_id = $1
                WHERE stx.mined_height IS NOT NULL
                   OR (stx.expiry_height IS NULL OR stx.expiry_height = 0 OR stx.expiry_height >= $2)
              )
              -- exclude likely-spent wallet-internal ephemeral outputs
              AND (
                addr.key_scope != 2  -- not ephemeral
                OR t.id NOT IN (
                  SELECT ros.transaction_id
                  FROM (
                    SELECT sn.transaction_id, n.account_id FROM sapling_received_note_spends sn
                    JOIN sapling_received_notes n ON n.id = sn.sapling_received_note_id
                    WHERE n.wallet_id = $1
                    UNION ALL
                    SELECT os.transaction_id, n.account_id FROM orchard_received_note_spends os
                    JOIN orchard_received_notes n ON n.id = os.orchard_received_note_id
                    WHERE n.wallet_id = $1
                    UNION ALL
                    SELECT trs.transaction_id, tro.account_id FROM transparent_received_output_spends trs
                    JOIN transparent_received_outputs tro ON tro.id = trs.transparent_received_output_id
                    WHERE tro.wallet_id = $1
                  ) ros
                  WHERE ros.account_id = acct.id
                )
                OR (u.max_observed_unspent_height IS NOT NULL AND t.expiry_height IS NOT NULL
                    AND u.max_observed_unspent_height > t.expiry_height)
              )
              AND acct.deleted_at IS NULL
            GROUP BY acct.uuid
        "#;

        let rows: Vec<(Uuid, i64)> = sqlx_core::query_as::query_as(pending_query)
            .bind(wallet_id.expose_uuid())
            .bind(target_height_i64)
            .bind(min_confirmations)
            .fetch_all(pool)
            .await?;

        for (account_uuid, raw_value) in rows {
            let account = AccountUuid::from_uuid(account_uuid);
            let value = Zatoshis::from_nonnegative_i64(raw_value).map_err(|_| {
                SqlxClientError::Encoding(format!("Negative UTXO value {raw_value:?}"))
            })?;

            account_balances
                .entry(account)
                .or_insert(AccountBalance::ZERO)
                .with_unshielded_balance_mut(|bal| {
                    if value >= zip317::MARGINAL_FEE {
                        bal.add_pending_spendable_value(value)
                    } else {
                        bal.add_uneconomic_value(value)
                    }
                })?;
        }
    }

    Ok(())
}
