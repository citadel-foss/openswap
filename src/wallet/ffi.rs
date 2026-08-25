//! FFI-compatible types for the Taker module.
//!
//! This module provides Foreign Function Interface (FFI) compatible data structures
//! for exposing swap functionality and reporting to other languages.

use crate::{
    security::{load_sensitive_struct, KeyMaterial, SerdeJson},
    utill::{get_taker_dir, parse_checked_address, MIN_FEE_RATE},
    wallet::{infer_address_type, AddressType, Destination, Wallet, WalletBackup, WalletError},
};
use bitcoin::{Amount, OutPoint, Txid};
use bitcoind::bitcoincore_rpc::json::ListTransactionResult;

use super::blockchain::{BackendConfig, Blockchain};
use std::path::{Path, PathBuf};

pub use super::report::{
    MakerFeeInfo, MakerReport, RecoveryReport, SwapRole, SwapStatus, TakerReport,
};

/// Restores a wallet from a JSON backup file for GUI/FFI applications.
///
/// This is a non-interactive restore method designed for programmatic use via FFI bindings.
/// Unlike `restore_wallet`, this function accepts a path to a JSON backup file.
/// Only encrypted backups are accepted; decryption uses [`load_sensitive_struct`].
///
/// # Behavior
///
/// 1. Reads and parses the JSON backup file into a [`WalletBackup`] structure
/// 2. If encrypted, decrypts using the provided password and preserves encryption material
/// 3. Constructs the wallet path: `{data_dir_or_default}/wallets/{wallet_file_name_or_default}`
/// 4. Calls [`Wallet::restore`] to reconstruct the wallet with all UTXOs and metadata
///
/// # Parameters
///
/// - `data_dir`: Target directory, defaults to `~/.openswap/taker`
/// - `wallet_file_name`: Restored wallet filename, defaults to name from backup if empty
/// - `backup_file_path`: Path to the JSON file containing the wallet backup.
///   Only encrypted backups are accepted.
/// - `password`: Required. Decrypts the encrypted backup and becomes the
///   passphrase of the restored (always encrypted) wallet.
pub fn restore_wallet_gui_app(
    data_dir: Option<PathBuf>,
    wallet_file_name: Option<String>,
    backend: BackendConfig,
    backup_file_path: PathBuf,
    password: Option<String>,
) {
    let password = password.filter(|p| !p.is_empty());
    let Some(password) = password else {
        log::error!(
            "Wallet restore failed: a passphrase is required; \
             cleartext wallet files are not supported"
        );
        return;
    };
    let (backup, encryption_material) = match load_sensitive_struct::<WalletBackup, SerdeJson>(
        &backup_file_path,
        Some(password.clone()),
    ) {
        Ok((backup, Some(material))) => (backup, material),
        Ok((_, None)) => {
            unreachable!("a supplied passphrase either decrypts or errors")
        }
        Err(err) => {
            log::error!("Wallet backup load failed: {err}");
            return;
        }
    };
    let restored_wallet_path = match data_dir.clone().map(Ok).unwrap_or_else(get_taker_dir) {
        // A nameless path resolves to the backup's filename inside `Wallet::restore`.
        Ok(dir) => match wallet_file_name {
            Some(name) => dir.join("wallets").join(name),
            None => dir.join("wallets"),
        },
        Err(e) => {
            log::error!("Wallet restore failed: {e}");
            return;
        }
    };

    if let Err(e) = Wallet::restore(
        &backup,
        &restored_wallet_path,
        &backend,
        encryption_material,
    ) {
        log::error!("Wallet restore failed: {e:?}");
    } else {
        println!("Wallet restore succeeded!");
    }
}

impl Wallet {
    /// Creates a wallet backup for GUI/FFI applications.
    ///
    /// This is a ffi-only wrapper around [`Wallet::backup`] that derives the
    /// encryption material from the provided password. Backups contain the
    /// master key and are always encrypted; a missing or empty password is
    /// an error.
    ///
    /// # Parameters
    ///
    /// - `destination_path`: Destination file path for the backup (`.json`)
    /// - `password`: Required password used to encrypt the backup
    ///
    /// # Example
    ///
    /// ```ignore
    /// wallet.backup_wallet_gui_app("/path/to/backup".to_string(), Some("my_password".to_string()))?;
    pub fn backup_wallet_gui_app(
        &self,
        destination_path: String,
        password: Option<String>,
    ) -> Result<(), WalletError> {
        let Some(password) = password.filter(|p| !p.is_empty()) else {
            return Err(WalletError::General(
                "a passphrase is required for wallet backups; \
                 cleartext backups are not supported"
                    .to_string(),
            ));
        };
        let km = KeyMaterial::new_from_password(Some(password))
            .expect("a non-empty passphrase always yields key material");
        let backup_path = Path::new(&destination_path);
        self.backup(backup_path, km)?;

        Ok(())
    }

    /// Checks whether wallet is encrypted or not.
    pub fn is_wallet_encrypted(wallet_path: &Path) -> Result<bool, WalletError> {
        if !wallet_path.exists() {
            return Ok(false); // No wallet = not encrypted
        }

        let content = std::fs::read(wallet_path).map_err(WalletError::IO)?;

        // Try to deserialize as EncryptedData using CBOR
        // If it succeeds, the wallet is encrypted
        // If it fails, the wallet is plaintext
        match serde_cbor::from_slice::<crate::security::EncryptedData>(&content) {
            Ok(_) => Ok(true),   // Successfully parsed as EncryptedData = encrypted
            Err(_) => Ok(false), // Failed to parse as EncryptedData = plaintext
        }
    }

    /// Returns a list of recent Incoming Transactions (bydefault last 10)
    pub fn get_transactions(
        &self,
        count: Option<usize>,
        skip: Option<usize>,
    ) -> Result<Vec<ListTransactionResult>, WalletError> {
        self.blockchain
            .list_transactions(None, count, skip, Some(true))
    }

    /// Sends specified Amount of Satoshis to an External Address
    pub fn send_to_address(
        &mut self,
        amount: u64,
        address: String,
        fee_rate: Option<f64>,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
    ) -> Result<Txid, WalletError> {
        let amount = Amount::from_sat(amount);

        let addr = parse_checked_address(&address, self.store.network).map_err(|e| {
            log::debug!(
                "Address validation failed for network {:?}: {:?}",
                self.store.network,
                e
            );
            WalletError::General("Invalid address for the current wallet network".to_string())
        })?;

        let coins_to_spend = self.coin_select(
            amount,
            fee_rate.unwrap_or(MIN_FEE_RATE),
            infer_address_type(&addr.script_pubkey()),
            manually_selected_outpoints,
            None,
        )?;

        let outputs = vec![(addr, amount)];
        let destination = Destination::Multi {
            outputs,
            op_return_data: None,
            change_address_type: AddressType::P2TR,
        };

        let tx = self.spend_from_wallet(
            fee_rate.unwrap_or(MIN_FEE_RATE),
            destination,
            &coins_to_spend,
        )?;

        let txid = self.send_tx(&tx)?;
        self.sync_and_save(&crate::utill::NO_SHUTDOWN)?;

        Ok(txid)
    }
}
