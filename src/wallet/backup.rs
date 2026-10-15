use std::{collections::HashSet, env, ffi::OsStr, fs, io::Write, path::PathBuf};

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
use bitcoin::{absolute::LockTime, bip32::Xpriv, Network, ScriptBuf};
use bitcoind::bitcoincore_rpc::json::GetBlockchainInfoResult;
use serde::{Deserialize, Serialize};
use std::{path::Path, str::FromStr};
use zeroize::Zeroizing;

/// The way back from a wallet file that cannot be used.
pub const RESTORE_FROM_MNEMONIC_HINT: &str =
    "restore the wallet from its seed phrase with `restore --mnemonic`";

/// Shown before every restore, since no seed or backup holds open swap keys.
pub const RESTORE_OPEN_SWAPS_WARNING: &str =
    "A restore cannot recover swaps still in progress (including Lightning swaps): \
     their keys are not in a seed phrase or backup. Finish or refund them on the old wallet first.";

/// How far a restore searches. Saved in the wallet file until the first scan
/// finishes, so a restore cut short resumes with the same options.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct RestoreOptions {
    /// First block the Core rescan reads; `None` keeps the backup's, else genesis.
    /// Not saved here: it becomes the wallet's own birthday.
    #[serde(skip)]
    pub birthday: Option<u64>,
    /// Unused addresses in a row that end the search on each keychain.
    pub address_gap: u32,
    /// Unused bond indexes in a row that end the bond search.
    pub bond_gap: u32,
    /// Bonds made without an OP_RETURN announcement, which only these find.
    pub bond_hints: Vec<BondHint>,
}

impl Default for RestoreOptions {
    fn default() -> Self {
        Self {
            birthday: None,
            address_gap: RESTORE_ADDRESS_GAP,
            bond_gap: 20,
            bond_hints: Vec::new(),
        }
    }
}

/// A bond the user remembers. Used only if one of our own sends pays it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BondHint {
    /// The bond key's index in the fidelity derivation path.
    pub index: u32,
    /// The bond's locktime.
    pub locktime: LockTime,
}

/// Parses the CLI form `INDEX:LOCKTIME`.
impl FromStr for BondHint {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let (index, locktime) = s.split_once(':').ok_or("expected INDEX:LOCKTIME")?;
        let index: u32 = index.parse().map_err(|e| format!("bad index: {e}"))?;
        // Bond keys are normal (unhardened) children: the index must be below 2^31.
        if index >= 1 << 31 {
            return Err(format!("bad index: {index} is not below 2^31"));
        }
        Ok(BondHint {
            index,
            locktime: LockTime::from_consensus(
                locktime.parse().map_err(|e| format!("bad locktime: {e}"))?,
            ),
        })
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

    // Added after v0.2.3: older backups read them as empty, and older
    // readers skip them.
    /// Every bond the wallet held. The restore treats each as a [`BondHint`],
    /// so a record the chain no longer backs is dropped, not trusted.
    #[serde(default)]
    pub(super) fidelity_bonds: Vec<BondHint>,
    /// Swept swap coin scripts, kept out of the regular coin pool.
    #[serde(default)]
    pub(super) swept_incoming_swapcoins: HashSet<ScriptBuf>,
    /// Receive addresses handed out, including ones never funded.
    #[serde(default)]
    pub(super) external_index: u32,
    /// Change addresses handed out, including ones never funded.
    #[serde(default)]
    pub(super) internal_index: u32,
    /// Gaps of a restore still in progress, so restoring this backup scans
    /// at least as wide as the unfinished one would have.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) pending_gaps: Option<(u32, u32)>,
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
            fidelity_bonds: wallet
                .store
                .fidelity_bond
                .iter()
                .map(|bond| BondHint {
                    index: bond.bond_index,
                    locktime: bond.lock_time,
                })
                // A restore still in progress may not have found these yet.
                .chain(
                    wallet
                        .store
                        .pending_restore
                        .iter()
                        .flat_map(|o| o.bond_hints.clone()),
                )
                .collect(),
            swept_incoming_swapcoins: wallet.store.swept_incoming_swapcoins.clone(),
            external_index: wallet.store.external_index,
            internal_index: wallet.store.internal_index,
            pending_gaps: wallet
                .store
                .pending_restore
                .as_ref()
                .map(|o| (o.address_gap, o.bond_gap)),
        }
    }
}
impl Wallet {
    /// Backup and restore need the live chain backend; there is no offline backup.
    pub(crate) fn require_backend(
        blockchain: &AnyBlockchain,
    ) -> Result<GetBlockchainInfoResult, WalletError> {
        blockchain.get_blockchain_info().map_err(|e| {
            WalletError::General(format!(
                "backup and restore need a reachable Bitcoin Core or Electrum backend: {e}"
            ))
        })
    }

    /// Creates a backup of the wallet and writes it to the given path.
    ///
    /// The backup is saved as a `.json` file, encrypted with the provided
    /// key material. Backups are always encrypted: they contain the master
    /// key, so a cleartext-on-disk form is not supported by design.
    pub fn backup(&self, path: &Path, backup_enc_material: KeyMaterial) -> Result<(), WalletError> {
        Self::require_backend(&self.blockchain)?;
        self.write_backup(path, backup_enc_material)
    }

    /// The file-only part of [`Wallet::backup`], for tests with no backend.
    pub(crate) fn write_backup(
        &self,
        path: &Path,
        backup_enc_material: KeyMaterial,
    ) -> Result<(), WalletError> {
        let mut backup_path = path.join("");
        backup_path.set_extension("json");

        log::info!("Backing up to {backup_path:?}");

        let backup = WalletBackup::from(self);

        let encrypted = encrypt_struct(backup, &backup_enc_material)
            .map_err(|e| WalletError::General(format!("wallet backup encryption failed: {e:?}")))?;
        let backup_file_content = serde_json::to_string_pretty(&encrypted)?;
        // Atomic replace: never truncate an existing backup before the new
        // one is durable on disk.
        // A bare file name has an empty parent; use the current directory.
        let parent = backup_path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        tmp.write_all(backup_file_content.as_bytes())?;
        tmp.as_file().sync_all()?;
        tmp.persist(&backup_path)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        // Make the rename durable. Windows can't open a directory as a file.
        #[cfg(not(windows))]
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
        mut options: RestoreOptions,
    ) -> Result<Wallet, WalletError> {
        options.bond_hints.extend(&wallet_backup.fidelity_bonds);
        if let Some((address_gap, bond_gap)) = wallet_backup.pending_gaps {
            options.address_gap = options.address_gap.max(address_gap);
            options.bond_gap = options.bond_gap.max(bond_gap);
        }
        for (name, gap, min) in [
            ("address", options.address_gap, ADDRESS_IMPORT_COUNT),
            ("bond", options.bond_gap, 1),
        ] {
            if !(min..=MAX_WATCH_WINDOW).contains(&gap) {
                return Err(WalletError::General(format!(
                    "{name} gap {gap} is outside {min}..={MAX_WATCH_WINDOW}"
                )));
            }
        }
        // The watch window starts at the highest handed-out index, so a gap
        // inside the range can still push its end past the cap.
        let window = wallet_backup
            .external_index
            .max(wallet_backup.internal_index)
            .saturating_add(options.address_gap - 1);
        if window > MAX_WATCH_WINDOW {
            return Err(WalletError::WatchWindowCap {
                window,
                cap: MAX_WATCH_WINDOW,
            });
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
        let chain = Self::require_backend(&blockchain)?.chain;
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
        // Counters and swept tags go into the first write, so a restore cut
        // short resumes with them rather than with defaults.
        let store = WalletStore::init_with(
            wallet_file_name,
            wallet_path,
            wallet_backup.network,
            wallet_backup.master_key,
            wallet_birthday,
            Some(options),
            &restored_enc_material,
            |store| {
                store.swept_incoming_swapcoins = wallet_backup.swept_incoming_swapcoins.clone();
                store.external_index = wallet_backup.external_index;
                store.internal_index = wallet_backup.internal_index;
            },
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
    /// Recovers HD funds, fidelity bonds and already-swept swap coins — though swap
    /// coins lose the label a [`WalletBackup`] file keeps, which holds them out of
    /// the regular coin pool. Bonds are found by their OP_RETURN or a
    /// [`BondHint`], until `options.bond_gap` indexes in a row find none. Live swap
    /// keys are per-swap `OsRng` and unrecoverable from any seed.
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
        let mut mnemonic = Mnemonic::parse(phrase.as_str())?;

        let network = Self::require_backend(&AnyBlockchain::from_config(backend_config)?)?.chain;
        let master_key = Wallet::master_key_from_mnemonic(&mnemonic, network);
        // Wipe the words as soon as the key exists, not after the chain scan.
        zeroize::Zeroize::zeroize(&mut mnemonic);
        drop(phrase);
        let master_key = master_key?;
        let backup = WalletBackup {
            network,
            master_key,
            wallet_birthday: None,
            file_name,
            fidelity_bonds: Vec::new(),
            swept_incoming_swapcoins: HashSet::new(),
            external_index: 0,
            internal_index: 0,
            pending_gaps: None,
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
        options: RestoreOptions,
    ) -> Result<(), WalletError> {
        println!("{RESTORE_OPEN_SWAPS_WARNING}");
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

        let hints = options.bond_hints.clone();
        let wallet = Wallet::restore_with(
            &backup,
            restored_path,
            backend,
            restore_enc_material,
            options,
        )?;
        println!("Wallet restore succeeded!");
        wallet.print_restored_bonds(&hints);
        Ok(())
    }

    /// Interactively restores a wallet from a seed phrase read at a hidden
    /// prompt, so it never appears in argv or shell history.
    pub fn restore_from_mnemonic_interactive(
        restored_path: &Path,
        backend: &BackendConfig,
        options: RestoreOptions,
    ) -> Result<(), WalletError> {
        println!("{RESTORE_OPEN_SWAPS_WARNING}");
        let phrase = Zeroizing::new(
            prompt_password("Enter seed phrase: ".to_string())
                .map_err(|e| WalletError::General(format!("failed to read seed phrase: {e}")))?,
        );
        Wallet::validate_mnemonic(&phrase)?;
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

        let hints = options.bond_hints.clone();
        let wallet = Wallet::restore_from_mnemonic(
            phrase,
            restored_path,
            backend,
            options,
            restore_enc_material,
        )?;
        println!("Wallet restore succeeded!");
        wallet.print_restored_bonds(&hints);
        Ok(())
    }

    /// A hint that finds nothing must not pass silently: the user may have
    /// mistyped it, and that bond's money is still out there.
    fn print_restored_bonds(&self, hints: &[BondHint]) {
        let bonds = &self.store.fidelity_bond;
        let indexes: Vec<u32> = bonds.iter().map(|bond| bond.bond_index).collect();
        println!("Fidelity bonds recovered at indexes: {indexes:?}");
        for hint in hints {
            if !bonds
                .iter()
                .any(|bond| bond.bond_index == hint.index && bond.lock_time == hint.locktime)
            {
                println!(
                    "Bond hint {}:{} matched no bond",
                    hint.index,
                    hint.locktime.to_consensus_u32()
                );
            }
        }
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
    /// - Writes the backup to the current working directory, or to `output`.
    pub fn backup_interactive(wallet: &Self, output: Option<PathBuf>) -> Result<(), WalletError> {
        log::info!("Initiating wallet backup!");
        let open = wallet.open_swaps_summary();
        if open != OpenSwapsSummary::default() {
            println!(
                "Warning: {} incoming and {} outgoing swap coins, {} swap fundings and {} \
                 Lightning swaps are still open. {RESTORE_OPEN_SWAPS_WARNING}",
                open.incoming, open.outgoing, open.swap_locks, open.lightning
            );
        }
        let backup_name = format!("{}-backup", wallet.get_name());
        log::info!(
            "Backing up wallet: {} to {}",
            wallet.get_name(),
            backup_name
        );

        let backup_enc_material = KeyMaterial::new_interactive(None)
            .map_err(|e| WalletError::General(format!("encryption passphrase prompt failed: {e}")))?
            .ok_or_else(|| {
                WalletError::General(
                    "wallet backup failed: a passphrase is required; \
                     cleartext backups are not supported"
                        .to_string(),
                )
            })?;

        let backup_path = match output {
            Some(path) => path,
            None => env::current_dir()
                .map_err(|e| WalletError::General(format!("failed to get current directory: {e}")))?
                .join(backup_name),
        }
        // `backup` swaps any extension for `.json`; log the file it really writes.
        .with_extension("json");
        wallet.backup(&backup_path, backup_enc_material)?;
        log::info!("Wallet backup succeeded: {backup_path:?}");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{
        api::{test_support::test_wallet, KeychainKind},
        storage::{
            LnMakerDirection, LnMakerPhase, LnMakerSwapRecord, LnPendingSwap, SwapReservation,
        },
        swapcoin::IncomingSwapCoin,
        CoreRpcConfig, FidelityBond,
    };
    use bip39::rand::{thread_rng, Rng};
    use bitcoin::{
        hashes::{sha256, Hash},
        secp256k1::SecretKey,
        transaction::Version,
        Amount, OutPoint, PublicKey, Transaction,
    };
    use bitcoind::tempfile::tempdir;
    use std::collections::BTreeMap;

    fn dummy_backup(file_name: &str) -> WalletBackup {
        let seed: [u8; 16] = thread_rng().gen();
        WalletBackup {
            network: Network::Regtest,
            master_key: Xpriv::new_master(Network::Regtest, &seed).unwrap(),
            wallet_birthday: None,
            file_name: file_name.to_string(),
            fidelity_bonds: Vec::new(),
            swept_incoming_swapcoins: HashSet::new(),
            external_index: 0,
            internal_index: 0,
            pending_gaps: None,
        }
    }

    /// The backup as v0.2.3 and v1 write and read it.
    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct BackupV1 {
        network: Network,
        master_key: Xpriv,
        wallet_birthday: Option<u64>,
        file_name: String,
    }

    /// A v2 backup file keeps bonds, swept tags and counters; v1 readers still
    /// open it, and a v1 file opens with those fields empty.
    #[test]
    fn backup_v2_keeps_new_fields_and_reads_v1_both_ways() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet"));
        let locktime = LockTime::from_height(900).unwrap();
        wallet.store.fidelity_bond.push(FidelityBond {
            outpoint: OutPoint::null(),
            amount: Amount::from_sat(50_000),
            lock_time: locktime,
            pubkey: PublicKey::new(wallet.get_fidelity_keypair(3).unwrap().public_key()),
            conf_height: Some(100),
            is_spent: false,
            bond_index: 3,
            tx: None,
        });
        let pending = BondHint { index: 7, locktime };
        wallet.store.pending_restore = Some(RestoreOptions {
            address_gap: 500,
            bond_gap: 40,
            bond_hints: vec![pending],
            ..Default::default()
        });
        let swept = HashSet::from([ScriptBuf::from_bytes(vec![0x51])]);
        wallet.store.swept_incoming_swapcoins = swept.clone();
        wallet.store.external_index = 30;
        wallet.store.internal_index = 7;

        let password = Some("backup password".to_string());
        let km = KeyMaterial::new_from_password(password.clone()).unwrap();
        let v2_path = dir.path().join("v2.json");
        wallet.write_backup(&v2_path, km.clone()).unwrap();
        let (v2, _) =
            load_sensitive_struct::<WalletBackup, SerdeJson>(&v2_path, password.clone()).unwrap();
        assert_eq!(
            v2.fidelity_bonds,
            [BondHint { index: 3, locktime }, pending]
        );
        assert_eq!(v2.swept_incoming_swapcoins, swept);
        assert_eq!((v2.external_index, v2.internal_index), (30, 7));
        assert_eq!(v2.pending_gaps, Some((500, 40)));

        let (v1, _) =
            load_sensitive_struct::<BackupV1, SerdeJson>(&v2_path, password.clone()).unwrap();
        let expected = BackupV1 {
            network: v2.network,
            master_key: v2.master_key,
            wallet_birthday: v2.wallet_birthday,
            file_name: v2.file_name,
        };
        assert_eq!(v1, expected);

        let v1_path = dir.path().join("v1.json");
        let encrypted = encrypt_struct(expected, &km).unwrap();
        fs::write(&v1_path, serde_json::to_string_pretty(&encrypted).unwrap()).unwrap();
        let (read, _) =
            load_sensitive_struct::<WalletBackup, SerdeJson>(&v1_path, password).unwrap();
        assert_eq!(read.master_key, v1.master_key);
        assert!(read.fidelity_bonds.is_empty() && read.swept_incoming_swapcoins.is_empty());
        assert_eq!((read.external_index, read.internal_index), (0, 0));
        assert_eq!(read.pending_gaps, None);
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

        for (address_gap, bond_gap) in [
            (ADDRESS_IMPORT_COUNT - 1, 20),
            (MAX_WATCH_WINDOW + 1, 20),
            (100, 0),
        ] {
            let err = Wallet::restore_with(
                &dummy_backup("wallet"),
                &dir.path().join("wallet"),
                &backend,
                KeyMaterial::new_ephemeral(),
                RestoreOptions {
                    address_gap,
                    bond_gap,
                    ..Default::default()
                },
            )
            .expect_err("the gap is out of range");
            assert!(
                err.to_string().contains("is outside"),
                "{} {}: {}",
                address_gap,
                bond_gap,
                err
            );
        }

        // The window ends at `highest index + gap - 1`: index 2 puts it one past
        // the cap, index 1 sits on it and passes (then fails at the backend).
        let path = dir.path().join("windowed");
        let mut backup = dummy_backup("wallet");
        for (external_index, window) in [(2, Some(MAX_WATCH_WINDOW + 1)), (1, None)] {
            backup.external_index = external_index;
            let err = Wallet::restore_with(
                &backup,
                &path,
                &backend,
                KeyMaterial::new_ephemeral(),
                RestoreOptions {
                    address_gap: MAX_WATCH_WINDOW,
                    ..Default::default()
                },
            )
            .expect_err("no backend runs here");
            match (window, err) {
                (Some(window), WalletError::WatchWindowCap { window: got, cap }) => {
                    assert_eq!((got, cap), (window, MAX_WATCH_WINDOW));
                    assert!(!path.exists(), "the file must not be created");
                }
                (None, err) => assert!(!matches!(err, WalletError::WatchWindowCap { .. })),
                (Some(_), err) => panic!("expected the window cap, got {}", err),
            }
        }
    }

    /// With no node behind it, the backup refuses with the backend error.
    #[test]
    fn backup_needs_a_reachable_backend() {
        let dir = tempdir().unwrap();
        let wallet = test_wallet(&dir.path().join("wallet"));
        let km = KeyMaterial::new_from_password(Some("pw".to_string())).unwrap();
        let err = wallet
            .backup(&dir.path().join("b.json"), km)
            .expect_err("no backend runs here");
        assert!(
            err.to_string()
                .contains("reachable Bitcoin Core or Electrum"),
            "{}",
            err
        );
        assert!(!dir.path().join("b.json").exists());
    }

    /// A counter near `u32::MAX` must report the cap, not overflow the window.
    #[test]
    fn max_watch_index_overflow_is_the_window_cap() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet"));
        wallet.store.external_index = u32::MAX;
        assert!(matches!(
            wallet.max_watch_index(KeychainKind::External),
            Err(WalletError::WatchWindowCap {
                window: u32::MAX,
                cap: MAX_WATCH_WINDOW
            })
        ));
    }

    /// The checkpoint lives in the wallet file: hints must survive it, and a
    /// checkpoint saved without the bond fields reads them as the defaults.
    #[test]
    fn restore_options_survive_the_wallet_file_format() {
        let options = RestoreOptions {
            address_gap: 200,
            bond_gap: 5,
            bond_hints: vec![BondHint {
                index: 3,
                locktime: LockTime::from_height(900).unwrap(),
            }],
            ..Default::default()
        };
        let bytes = serde_cbor::to_vec(&options).unwrap();
        assert_eq!(
            serde_cbor::from_slice::<RestoreOptions>(&bytes).unwrap(),
            options
        );

        let bytes = serde_cbor::to_vec(&BTreeMap::from([("address_gap", 200)])).unwrap();
        assert_eq!(
            serde_cbor::from_slice::<RestoreOptions>(&bytes).unwrap(),
            RestoreOptions {
                address_gap: 200,
                ..Default::default()
            }
        );
    }
}
