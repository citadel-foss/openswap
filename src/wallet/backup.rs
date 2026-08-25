use std::{env, ffi::OsStr, fs, io::Write, path::PathBuf};

use crate::{
    security::{encrypt_struct, load_sensitive_struct, KeyMaterial, SecurityError, SerdeJson},
    utill::prompt_password,
    wallet::{Blockchain, Wallet, WalletError},
};

use super::{
    blockchain::{AnyBlockchain, BackendConfig},
    storage::WalletStore,
};
use bip39::Mnemonic;
use bitcoin::{bip32::Xpriv, Network};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Represents a wallet backup, containing all the necessary information to
/// restore a wallet instance.
///
/// This struct captures the essential elements of a wallet's state, including
/// its network, master key, creation time, and file name. It is serializable
/// and can be persisted to disk or transferred for backup purposes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletBackup {
    /// Network the wallet operates on.
    pub(crate) network: Network, //Can be asked to the user, but is nice to save
    /// The master key for the wallet.
    pub(super) master_key: Xpriv,

    pub(super) wallet_birthday: Option<u64>, //Avoid scanning from genesis block
    /// The file name associated with the wallet store.
    pub file_name: String, //Can be asked to user, or stored for convenience
}
impl From<&Wallet> for WalletBackup {
    fn from(wallet: &Wallet) -> Self {
        WalletBackup {
            network: (wallet.store.network),
            master_key: wallet
                .with_master_key(|master_key| Ok(*master_key))
                .expect("in-memory master key unsealing failed"),
            wallet_birthday: (wallet.store.wallet_birthday),
            file_name: (wallet.store.file_name.clone()),
        }
    }
}
impl Wallet {
    /// Creates a backup of the wallet and writes it to the given path.
    ///
    /// The backup is saved as a `.json` file, encrypted with the provided
    /// key material. Backups are always encrypted: they contain the master
    /// key, so a cleartext-on-disk form is not supported by design.
    pub fn backup(&self, path: &Path, backup_enc_material: KeyMaterial) -> Result<(), WalletError> {
        let mut backup_path = path.join("");
        backup_path.set_extension("json");

        log::info!("Backing up to {backup_path:?}");

        let backup = WalletBackup::from(self);

        let encrypted = encrypt_struct(backup, &backup_enc_material)
            .map_err(|e| WalletError::General(format!("wallet backup encryption failed: {e:?}")))?;
        let backup_file_content = serde_json::to_string_pretty(&encrypted)?;
        // Atomic replace: never truncate an existing backup before the new
        // one is durable on disk.
        let parent = backup_path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(backup_file_content.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(&backup_path)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        fs::File::open(parent)?.sync_all()?;

        Ok(())
    }

    /// Restores a `Wallet` from this backup to a specified path.
    ///
    /// Initializes a new wallet instance using the data from the backup and syncs
    /// it with the blockchain using the provided backend configuration.
    ///
    /// # Returns
    ///
    /// A fully initialized and synced `Wallet` instance.
    ///
    /// # Behavior
    ///
    /// If `wallet_path` does not contain a file name, `wallet_backup.file_name` will be used.
    /// The method initializes the wallet store, connects to the blockchain backend,
    /// syncs wallet data, and saves the state to disk.
    pub fn restore(
        wallet_backup: &WalletBackup,
        wallet_path: &Path,
        backend_config: &BackendConfig,
        restored_enc_material: KeyMaterial,
    ) -> Result<Wallet, WalletError> {
        if wallet_path.exists() {
            return Err(WalletError::General(format!(
                "a wallet already exists at {wallet_path:?}; refusing to overwrite it"
            )));
        }

        let wallet_file_name = wallet_path
            .file_name()
            .unwrap_or(OsStr::new(&wallet_backup.file_name)) // If no name filename for the restored one is provided use the previous one
            .to_str()
            .ok_or_else(|| {
                WalletError::General(
                    "restored wallet path has no valid UTF-8 file name".to_string(),
                )
            })?
            .to_string();

        // For the Core backend, rebind the node wallet name to the restored
        // wallet's filename. Electrum has no server-side wallet, so nothing to do.
        let mut backend_config_test = backend_config.clone();
        if let BackendConfig::CoreRpc(cfg) = &mut backend_config_test {
            cfg.wallet_name = wallet_file_name.clone();
        }

        let blockchain = AnyBlockchain::from_config(&backend_config_test)?;

        // Refuse to restore against a backend on a different chain.
        let chain = blockchain.get_blockchain_info()?.chain;
        if chain != wallet_backup.network {
            return Err(WalletError::General(format!(
                "backend chain `{chain}` does not match backup network `{}`",
                wallet_backup.network
            )));
        }

        // Initialise wallet
        let store = WalletStore::init(
            wallet_file_name,
            wallet_path,
            wallet_backup.network,
            wallet_backup.master_key,
            wallet_backup.wallet_birthday,
            &restored_enc_material,
        )?;

        let mut tmp_wallet = Wallet {
            blockchain,
            wallet_file_path: wallet_path.to_path_buf(),
            store,
            store_enc_material: restored_enc_material,
            new_mnemonic: None,
            locked_utxos: std::collections::HashSet::new(),
            // Flag to use the RESTORE_ADDRESS_GAP instead of normal gap while restoring.
            restore_scan: true,
        };
        tmp_wallet.seal_master_key()?;
        tmp_wallet.sync_and_save(&crate::utill::NO_SHUTDOWN)?;
        tmp_wallet.restore_scan = false;

        Ok(tmp_wallet)
    }

    /// Restores a `Wallet` from its BIP39 seed phrase, via [`Wallet::restore`].
    ///
    /// `wallet_birthday` is a floor on the Bitcoin Core rescan — `None` scans from
    /// genesis, and the effective start may be up to 2h of blocks later. Electrum
    /// ignores it and never rescans.
    ///
    /// Recovers exactly what a [`WalletBackup`] file does: HD funds, including
    /// already-swept swap coins — though those lose the label that keeps them out of
    /// the regular coin pool. Live swap keys are per-swap `OsRng` and unrecoverable
    /// from any seed.
    pub fn restore_from_mnemonic(
        phrase: &str,
        wallet_path: &Path,
        backend_config: &BackendConfig,
        wallet_birthday: Option<u64>,
        restored_enc_material: KeyMaterial,
    ) -> Result<Wallet, WalletError> {
        let network = AnyBlockchain::from_config(backend_config)?
            .get_blockchain_info()?
            .chain;

        let file_name = wallet_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();

        let mnemonic = Mnemonic::parse(phrase)?;
        let backup = WalletBackup {
            network,
            master_key: Wallet::master_key_from_mnemonic(&mnemonic, network)?,
            wallet_birthday,
            file_name,
        };

        Wallet::restore(&backup, wallet_path, backend_config, restored_enc_material)
    }

    /// Interactively restores a wallet from a backup file.
    ///
    /// This method loads a wallet backup from the given file path, prompts for decryption
    /// if necessary, and then restores the wallet to a new location. During restoration,
    /// the user is also prompted to provide a new encryption passphrase for the restored wallet.
    ///
    /// # Behavior
    ///
    /// - **Only encrypted backups are accepted**; a cleartext backup is an error.
    /// - **Prompts for decryption passphrase** if the backup file is encrypted.
    /// - Loads and decrypts the backup content.
    /// - **Prompts for a new encryption passphrase** for the restored wallet.
    /// - Initializes the wallet with the decrypted data and new encryption.
    /// - Syncs the wallet with the blockchain.
    /// - Saves the restored wallet to disk.
    pub fn restore_interactive(
        backup_file_path: &PathBuf,
        backend: &BackendConfig,
        restored_path: &Path,
    ) -> Result<(), WalletError> {
        log::info!(
            "Initiating wallet restore, from backup: {backup_file_path:?} to wallet {:?}",
            restored_path.file_name()
        );

        let backup = match load_sensitive_struct::<WalletBackup, SerdeJson>(backup_file_path, None)
        {
            // Cleartext (legacy) backups are not supported.
            Ok((_, None)) => {
                return Err(WalletError::General(format!(
                    "wallet backup {backup_file_path:?} is unencrypted; \
                     cleartext backups are not supported"
                )))
            }
            Ok((backup, Some(_))) => backup,
            Err(SecurityError::PasswordRequired) => {
                let password = prompt_password("Enter encryption passphrase: ".to_string())
                    .map_err(|e| WalletError::General(format!("failed to read passphrase: {e}")))?;
                load_sensitive_struct::<WalletBackup, SerdeJson>(backup_file_path, Some(password))
                    .map_err(|e| WalletError::General(format!("wallet backup load failed: {e}")))?
                    .0
            }
            Err(err) => {
                return Err(WalletError::General(format!(
                    "wallet backup load failed: {err}"
                )))
            }
        };
        let restore_enc_material = KeyMaterial::new_interactive(Some(
            "Enter restored wallet encryption passphrase: ".to_string(),
        ))
        .map_err(|e| WalletError::General(format!("encryption passphrase prompt failed: {e}")))?
        .ok_or_else(|| {
            WalletError::General(
                "wallet restore failed: a passphrase is required; \
                 cleartext wallet files are not supported"
                    .to_string(),
            )
        })?;

        Wallet::restore(&backup, restored_path, backend, restore_enc_material)?;
        println!("Wallet restore succeeded!");
        Ok(())
    }
    /// Interactively creates a wallet backup.
    ///
    /// This is a user-friendly version of the [`Wallet::backup`] method, which:
    /// - Uses the current working directory as the backup location.
    /// - Prompts the user for the encryption passphrase (backups contain the
    ///   master key, so they are always encrypted).
    ///
    /// # Behavior
    ///
    /// - Names the backup file as `{wallet_name}-backup.json`.
    /// - Writes the backup to the current working directory.
    pub fn backup_interactive(wallet: &Self) -> Result<(), WalletError> {
        log::info!("Initiating wallet backup!");
        let backup_name = format!("{}-backup", wallet.get_name());
        log::info!(
            "Backing up wallet: {} to {}",
            wallet.get_name(),
            backup_name
        );

        let working_directory: PathBuf = env::current_dir()
            .map_err(|e| WalletError::General(format!("failed to get current directory: {e}")))?;

        let backup_enc_material = KeyMaterial::new_interactive(None)
            .map_err(|e| WalletError::General(format!("encryption passphrase prompt failed: {e}")))?
            .ok_or_else(|| {
                WalletError::General(
                    "wallet backup failed: a passphrase is required; \
                     cleartext backups are not supported"
                        .to_string(),
                )
            })?;

        let backup_path = working_directory.join(backup_name);
        wallet.backup(&backup_path, backup_enc_material)?;
        log::info!("Wallet backup succeeded: {backup_path:?}");
        Ok(())
    }
}
