use std::{env, ffi::OsStr, fs, io::Write, path::PathBuf};

use crate::{
    security::{encrypt_struct, load_sensitive_struct, KeyMaterial, SecurityError, SerdeJson},
    utill::prompt_password,
    wallet::{Blockchain, Wallet, WalletError},
};

use super::{
    api::{ADDRESS_IMPORT_COUNT, MAX_WATCH_WINDOW, RESTORE_ADDRESS_GAP},
    blockchain::{AnyBlockchain, BackendConfig},
    storage::WalletStore,
};
use bip39::Mnemonic;
use bitcoin::{bip32::Xpriv, Network};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

/// The way back from a wallet file that cannot be used.
pub const RESTORE_FROM_MNEMONIC_HINT: &str =
    "restore the wallet from its seed phrase with `restore --mnemonic`";

/// How far a restore searches. Saved in the wallet file until the first scan
/// finishes, so a restore cut short resumes with the same options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RestoreOptions {
    /// First block the Core rescan reads; `None` keeps the backup's, else genesis.
    /// Not saved here: it becomes the wallet's own birthday.
    #[serde(skip)]
    pub birthday: Option<u64>,
    /// Unused addresses in a row that end the search on each keychain.
    pub address_gap: u32,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            birthday: None,
            address_gap: RESTORE_ADDRESS_GAP,
        }
    }
}

/// Open swaps a restore loses: their keys are random per swap and live only
/// in the wallet file, never in a seed phrase or backup.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OpenSwapsSummary {
    /// Incoming swap coins not swept yet.
    pub incoming: usize,
    /// Outgoing swap coins whose preimage we never learned.
    pub outgoing: usize,
    /// Swaps holding wallet coins for their funding.
    pub swap_locks: usize,
    /// Taker and maker Lightning swaps in progress.
    pub lightning: usize,
}

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

    /// Restores a `Wallet` from this backup to a specified path, with the
    /// default [`RestoreOptions`]. See [`Wallet::restore_with`].
    pub fn restore(
        wallet_backup: &WalletBackup,
        wallet_path: &Path,
        backend_config: &BackendConfig,
        restored_enc_material: KeyMaterial,
    ) -> Result<Wallet, WalletError> {
        Self::restore_with(
            wallet_backup,
            wallet_path,
            backend_config,
            restored_enc_material,
            RestoreOptions::default(),
        )
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
    /// If `wallet_path` is a directory or has no file name, the wallet is
    /// restored inside it under `wallet_backup.file_name`. The method
    /// initializes the wallet store, connects to the blockchain backend,
    /// syncs wallet data, and saves the state to disk.
    pub fn restore_with(
        wallet_backup: &WalletBackup,
        wallet_path: &Path,
        backend_config: &BackendConfig,
        restored_enc_material: KeyMaterial,
        options: RestoreOptions,
    ) -> Result<Wallet, WalletError> {
        if !(ADDRESS_IMPORT_COUNT..=MAX_WATCH_WINDOW).contains(&options.address_gap) {
            return Err(WalletError::General(format!(
                "address gap {} is outside {ADDRESS_IMPORT_COUNT}..={MAX_WATCH_WINDOW}",
                options.address_gap
            )));
        }

        // Directories and nameless paths restore under the backup's filename.
        // That name is untrusted input: accept exactly one normal component,
        // or `../x` escapes the directory and an absolute path replaces it.
        let wallet_path = if wallet_path.file_name().is_none() || wallet_path.is_dir() {
            let mut components = Path::new(&wallet_backup.file_name).components();
            match (components.next(), components.next()) {
                (Some(std::path::Component::Normal(_)), None) => {
                    wallet_path.join(&wallet_backup.file_name)
                }
                _ => {
                    return Err(WalletError::General(format!(
                        "backup file name {:?} is not a plain file name",
                        wallet_backup.file_name
                    )))
                }
            }
        } else {
            wallet_path.to_path_buf()
        };
        let wallet_path = wallet_path.as_path();

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

        // A requested birthday above the tip is a typo or a node still syncing.
        // A backup's own birthday keeps the old behaviour: rescan from genesis.
        if let Some(birthday) = options.birthday {
            let tip = blockchain.get_block_count()?;
            if birthday > tip {
                return Err(WalletError::General(format!(
                    "birthday {birthday} is above the chain tip {tip}"
                )));
            }
        }
        let wallet_birthday = options.birthday.or(wallet_backup.wallet_birthday);

        // Initialise wallet
        let store = WalletStore::init(
            wallet_file_name,
            wallet_path,
            wallet_backup.network,
            wallet_backup.master_key,
            wallet_birthday,
            Some(options),
            &restored_enc_material,
        )?;

        let mut tmp_wallet = Wallet {
            blockchain,
            wallet_file_path: wallet_path.to_path_buf(),
            store,
            store_enc_material: restored_enc_material,
            new_mnemonic: None,
            locked_utxos: std::collections::HashSet::new(),
        };
        tmp_wallet.seal_master_key()?;
        tmp_wallet.sync_and_save(&crate::utill::NO_SHUTDOWN)?;

        Ok(tmp_wallet)
    }

    /// Restores a `Wallet` from its BIP39 seed phrase, via [`Wallet::restore_with`].
    ///
    /// `options.birthday` is a floor on the Bitcoin Core rescan — `None` scans from
    /// genesis, and the effective start may be up to 2h of blocks later. Electrum
    /// ignores it and never rescans.
    ///
    /// Recovers exactly what a [`WalletBackup`] file does: HD funds, fidelity bonds
    /// and already-swept swap coins — though swap coins lose the label that keeps
    /// them out of the regular coin pool. Bonds are found by their OP_RETURN, up to
    /// the first index without one. Live swap keys are per-swap `OsRng` and
    /// unrecoverable from any seed.
    pub fn restore_from_mnemonic(
        phrase: Zeroizing<String>,
        wallet_path: &Path,
        backend_config: &BackendConfig,
        options: RestoreOptions,
        restored_enc_material: KeyMaterial,
    ) -> Result<Wallet, WalletError> {
        // A phrase carries no wallet name, so the path must name the file.
        let file_name = match wallet_path.file_name().and_then(|name| name.to_str()) {
            Some(name) if !wallet_path.is_dir() => name.to_string(),
            _ => {
                return Err(WalletError::General(format!(
                    "{wallet_path:?} is not a wallet file path"
                )))
            }
        };
        let mnemonic = Mnemonic::parse(phrase.as_str())?;

        let network = AnyBlockchain::from_config(backend_config)?
            .get_blockchain_info()?
            .chain;
        let backup = WalletBackup {
            network,
            master_key: Wallet::master_key_from_mnemonic(&mnemonic, network)?,
            wallet_birthday: None,
            file_name,
        };

        Wallet::restore_with(
            &backup,
            wallet_path,
            backend_config,
            restored_enc_material,
            options,
        )
    }

    /// Checks a seed phrase's words and checksum before anything else is asked.
    pub fn validate_mnemonic(phrase: &str) -> Result<(), WalletError> {
        Mnemonic::parse(phrase)?;
        Ok(())
    }

    /// Counts the open swaps a restore would lose, for backup and restore warnings.
    pub fn open_swaps_summary(&self) -> OpenSwapsSummary {
        let (incoming, outgoing) = self.find_unfinished_swapcoins();
        OpenSwapsSummary {
            incoming: incoming.len(),
            outgoing: outgoing.len(),
            swap_locks: self.store.swap_locks.len(),
            lightning: self.store.ln_pending_swaps.len() + self.store.ln_maker_swaps.len(),
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{
        api::test_support::test_wallet,
        storage::{
            LnMakerDirection, LnMakerPhase, LnMakerSwapRecord, LnPendingSwap, SwapReservation,
        },
        swapcoin::IncomingSwapCoin,
        CoreRpcConfig,
    };
    use bip39::rand::{thread_rng, Rng};
    use bitcoin::{
        absolute::LockTime,
        hashes::{sha256, Hash},
        secp256k1::SecretKey,
        transaction::Version,
        Amount, PublicKey, ScriptBuf, Transaction,
    };
    use bitcoind::tempfile::tempdir;
    use std::collections::HashSet;

    fn dummy_backup(file_name: &str) -> WalletBackup {
        let seed: [u8; 16] = thread_rng().gen();
        WalletBackup {
            network: Network::Regtest,
            master_key: Xpriv::new_master(Network::Regtest, &seed).unwrap(),
            wallet_birthday: None,
            file_name: file_name.to_string(),
        }
    }

    /// Each kind of open swap lands in its own count; a fresh wallet has none.
    #[test]
    fn open_swaps_summary_counts_each_kind() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet"));
        assert_eq!(wallet.open_swaps_summary(), OpenSwapsSummary::default());

        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let pubkey = PublicKey::new(wallet.get_fidelity_keypair(0).unwrap().public_key());
        let contract_tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: Vec::new(),
            output: Vec::new(),
        };
        let store = &mut wallet.store;
        store.incoming_swapcoins.insert(
            "incoming".to_string(),
            IncomingSwapCoin::new_legacy(
                key,
                pubkey,
                contract_tx,
                ScriptBuf::new(),
                key,
                Amount::ZERO,
                1,
            ),
        );
        store.swap_locks.insert(
            "lock".to_string(),
            SwapReservation {
                outpoints: HashSet::new(),
                reserved_at: 0,
            },
        );
        store.ln_pending_swaps.insert(
            "taker-ln".to_string(),
            LnPendingSwap {
                is_swap_in: true,
                preimage: None,
                redeemscript: ScriptBuf::new(),
                locktime: 0,
                privkey: key,
                outpoint: None,
                value: None,
            },
        );
        store.ln_maker_swaps.insert(
            "maker-ln".to_string(),
            LnMakerSwapRecord {
                direction: LnMakerDirection::SwapIn,
                phase: LnMakerPhase::InAccepted,
                payment_hash: sha256::Hash::all_zeros(),
                amount: Amount::ZERO,
                fee: Amount::ZERO,
                locktime: 0,
                min_confirmations: 1,
                redeemscript: ScriptBuf::new(),
                privkey: key,
                invoice: String::new(),
                preimage: None,
                refund_txid: None,
                accepted_height: None,
                payout_script: None,
                funding_outpoint: None,
                funding_value: None,
                funding_height: None,
            },
        );
        assert_eq!(
            wallet.open_swaps_summary(),
            OpenSwapsSummary {
                incoming: 1,
                outgoing: 0,
                swap_locks: 1,
                lightning: 2,
            }
        );
    }

    /// A backup whose `file_name` traverses or is absolute must be rejected
    /// before the restore touches the backend.
    #[test]
    fn restore_rejects_traversal_in_backup_file_name() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("wallets");
        std::fs::create_dir_all(&target).unwrap();
        let backend = BackendConfig::CoreRpc(CoreRpcConfig::default());
        for bad in ["../escape", "/tmp/absolute", "nested/name"] {
            let err = Wallet::restore(
                &dummy_backup(bad),
                &target,
                &backend,
                KeyMaterial::new_ephemeral(),
            )
            .expect_err("a traversal name must be rejected");
            assert!(
                err.to_string().contains("not a plain file name"),
                "{}: {}",
                bad,
                err
            );
        }
    }

    /// A directory path or an out-of-range gap must fail before the backend
    /// is touched (none runs here).
    #[test]
    fn restore_rejects_bad_options_before_touching_the_backend() {
        let dir = tempdir().unwrap();
        let backend = BackendConfig::CoreRpc(CoreRpcConfig::default());
        let phrase = Zeroizing::new(
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
                .to_string(),
        );
        let err = Wallet::restore_from_mnemonic(
            phrase,
            dir.path(),
            &backend,
            RestoreOptions::default(),
            KeyMaterial::new_ephemeral(),
        )
        .expect_err("a directory is not a wallet file");
        assert!(
            err.to_string().contains("not a wallet file path"),
            "{}",
            err
        );

        for address_gap in [ADDRESS_IMPORT_COUNT - 1, MAX_WATCH_WINDOW + 1] {
            let err = Wallet::restore_with(
                &dummy_backup("wallet"),
                &dir.path().join("wallet"),
                &backend,
                KeyMaterial::new_ephemeral(),
                RestoreOptions {
                    address_gap,
                    ..Default::default()
                },
            )
            .expect_err("the gap is out of range");
            assert!(
                err.to_string().contains("is outside"),
                "{}: {}",
                address_gap,
                err
            );
        }
    }
}
