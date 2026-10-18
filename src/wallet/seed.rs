//! The wallet's seed phrase. It is sealed in the wallet file when the wallet
//! is created or restored, under its own key from the wallet password, and
//! opened only with that password.

use bip39::Mnemonic;
use bitcoin::{bip32::Xpriv, Network};
use std::{collections::HashSet, path::Path};
use zeroize::Zeroizing;

use crate::security::{SealedSecret, SecurityError};

use super::{
    api::Wallet,
    backup::parse_mnemonic,
    blockchain::{AnyBlockchain, BackendConfig, CoreRpcConfig},
    error::WalletError,
    seed_cli::{WalletInUse, IN_USE_MESSAGE},
    storage::{SecretEntropy, SecretXpriv, WalletStore},
};

/// Shown when a wallet is created. The words themselves are never printed.
pub(super) const SEED_NOT_BACKED_UP: &str =
    "Seed phrase not backed up yet; run `show-seed` and write it down";

/// Shown while a wallet has no stored phrase and no confirmed backup.
pub(super) const SEED_NOT_STORED: &str = "No seed phrase stored and none confirmed as backed up; \
     run `attach-seed` with your original phrase, or keep an encrypted backup";

/// A BIP39 seed phrase, wiped on drop. No `Clone`, `Debug`, `Display` or
/// `Serialize`; [`SecretMnemonic::words`] is the only reader.
///
/// Copies made outside Rust (GUI widgets, managed strings, the clipboard)
/// can't be wiped by this library. Dispose of them as soon as the user has
/// written the seed down.
pub struct SecretMnemonic(Mnemonic);

impl SecretMnemonic {
    /// Callers must not log or persist the result.
    pub fn words(&self) -> Zeroizing<String> {
        // Sized up front: a growing string frees unwiped copies of the words.
        let size = self.0.words().map(|word| word.len() + 1).sum();
        let mut phrase = Zeroizing::new(String::with_capacity(size));
        for word in self.0.words() {
            if !phrase.is_empty() {
                phrase.push(' ');
            }
            phrase.push_str(word);
        }
        phrase
    }
}

/// Refuses `mnemonic` unless it derives exactly `master_key`, key and chain
/// code. Otherwise a bug or an edited file could hand out the wrong seed.
fn require_same_key(
    mnemonic: &Mnemonic,
    master_key: &Xpriv,
    network: Network,
) -> Result<(), WalletError> {
    let derived = SecretXpriv(Wallet::master_key_from_mnemonic(mnemonic, network)?);
    if derived.0.private_key == master_key.private_key
        && derived.0.chain_code == master_key.chain_code
    {
        Ok(())
    } else {
        Err(WalletError::MnemonicMismatch)
    }
}

/// Seals `mnemonic` under a key derived from `password`, once the words that
/// will be read back from it are known to derive exactly `master_key`.
pub(super) fn seal_mnemonic(
    mnemonic: &Mnemonic,
    master_key: &Xpriv,
    network: Network,
    password: &str,
) -> Result<SealedSecret, WalletError> {
    seal_entropy(
        &SecretEntropy::from_mnemonic(mnemonic)?,
        master_key,
        network,
        password,
    )
}

/// Like [`seal_mnemonic`], for a phrase already held as entropy.
pub(super) fn seal_entropy(
    entropy: &SecretEntropy,
    master_key: &Xpriv,
    network: Network,
    password: &str,
) -> Result<SealedSecret, WalletError> {
    require_same_key(&entropy.to_mnemonic()?, master_key, network)?;
    SealedSecret::seal(entropy, password)
        .map_err(|e| WalletError::General(format!("seed phrase sealing failed: {e:?}")))
}

impl Wallet {
    /// Opens an existing wallet file with no backend, for the offline seed
    /// commands. It never syncs, and writes only the one-time upgrade of an
    /// older file, under the exclusive lock; the backend it holds is inert
    /// and must not be used.
    pub fn open_offline(path: &Path, password: Zeroizing<String>) -> Result<Self, WalletError> {
        if !path.exists() {
            return Err(WalletError::General(format!(
                "no wallet file at {path:?}; a wallet must exist to read its seed"
            )));
        }
        if password.is_empty() {
            return Err(WalletError::WrongPassword);
        }
        let wrong_password = |e| match e {
            WalletError::Security(SecurityError::Decryption) => WalletError::WrongPassword,
            e => e,
        };
        let loaded = match WalletStore::read_without_upgrade(path, Some(password.to_string()))
            .map_err(wrong_password)?
        {
            Some(loaded) => loaded,
            // The upgrade rewrites the file, so no running process may hold it.
            None => {
                let Some(_owner) = WalletInUse::exclusive_if_idle(path)? else {
                    return Err(WalletError::General(IN_USE_MESSAGE.to_string()));
                };
                WalletStore::read_from_disk(path, Some(password.to_string()))
                    .map_err(wrong_password)?
            }
        };
        let (mut store, store_enc_material) = loaded;
        store.master_key.seal(&store_enc_material)?;
        // Building the client opens no connection, and nothing here calls it.
        let blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default()))?;
        Ok(Self {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        })
    }

    /// The wallet's seed phrase, for the user to write down. Local only:
    /// never send it over RPC or the network.
    ///
    /// Needs the current wallet password on every call. The phrase is
    /// decrypted just in time and nothing seed-related is cached. The result
    /// doesn't borrow the wallet, so release any wallet lock before showing it.
    pub fn get_wallet_mnemonic(
        &self,
        password: Zeroizing<String>,
    ) -> Result<SecretMnemonic, WalletError> {
        if password.is_empty() {
            return Err(WalletError::WrongPassword);
        }
        let sealed = self
            .store
            .sealed_mnemonic
            .as_ref()
            .ok_or(WalletError::MnemonicUnavailable)?;
        let entropy: SecretEntropy = sealed.open(&password).map_err(|e| match e {
            SecurityError::Decryption => WalletError::WrongPassword,
            e => e.into(),
        })?;
        drop(password);
        let mnemonic = entropy.to_mnemonic()?;
        drop(entropy);
        self.with_master_key(|master_key| {
            require_same_key(&mnemonic, master_key, self.store.network)
        })?;
        Ok(SecretMnemonic(mnemonic))
    }

    /// Stores the user's original phrase in a wallet that has none, such as
    /// one created before phrases were stored. Accepted only if it derives
    /// exactly this wallet's master key. A stored phrase is never replaced.
    pub fn attach_wallet_mnemonic(
        &mut self,
        password: Zeroizing<String>,
        phrase: Zeroizing<String>,
    ) -> Result<(), WalletError> {
        if self.store.sealed_mnemonic.is_some() {
            return Err(WalletError::MnemonicAlreadyStored);
        }
        self.require_file_password(&password)?;
        let mnemonic = parse_mnemonic(&phrase)?;
        drop(phrase);
        let sealed = self.with_master_key(|master_key| {
            seal_mnemonic(&mnemonic, master_key, self.store.network, &password)
        })?;
        drop(mnemonic);
        drop(password);
        self.store.sealed_mnemonic = Some(sealed);
        // Memory must match the file, or a later save would store it unasked.
        if let Err(e) = self.save_to_disk() {
            self.store.sealed_mnemonic = None;
            return Err(e);
        }
        Ok(())
    }

    /// Records that the user has written the seed phrase down. The caller
    /// shows the phrase and checks a few re-typed words first.
    pub fn confirm_seed_backup(&mut self, password: Zeroizing<String>) -> Result<(), WalletError> {
        drop(self.get_wallet_mnemonic(password)?);
        let backed_up = std::mem::replace(&mut self.store.seed_backed_up, true);
        if let Err(e) = self.save_to_disk() {
            self.store.seed_backed_up = backed_up;
            return Err(e);
        }
        Ok(())
    }

    /// Logs the not-backed-up warning, if it applies. Called on every load.
    pub(super) fn warn_if_seed_not_backed_up(&self) {
        if self.store.seed_backed_up {
            return;
        }
        if self.store.sealed_mnemonic.is_some() {
            log::warn!("{SEED_NOT_BACKED_UP}");
        } else {
            log::warn!("{SEED_NOT_STORED}");
        }
    }

    /// Whether the user has confirmed writing the seed phrase down.
    pub fn seed_backed_up(&self) -> bool {
        self.store.seed_backed_up
    }

    /// The password check every master-key export passes. Returns the stored
    /// seed entropy, if any, for the export to carry.
    pub(super) fn unlock_export(
        &self,
        password: Zeroizing<String>,
    ) -> Result<Option<SecretEntropy>, WalletError> {
        if self.store.sealed_mnemonic.is_none() {
            self.require_file_password(&password)?;
            return Ok(None);
        }
        let mnemonic = self.get_wallet_mnemonic(password)?;
        SecretEntropy::from_mnemonic(&mnemonic.0).map(Some)
    }

    /// For wallets with no sealed phrase to check `password` against: checks
    /// it against the file key instead.
    fn require_file_password(&self, password: &str) -> Result<(), WalletError> {
        if password.is_empty() || !self.store_enc_material.matches_password(password) {
            return Err(WalletError::WrongPassword);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::{api::test_support::test_wallet_with_key, storage::WalletStore};
    use bitcoind::tempfile::tempdir;
    use std::path::Path;

    const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                          abandon abandon abandon abandon abandon about";

    fn password(text: &str) -> Zeroizing<String> {
        Zeroizing::new(text.to_string())
    }

    /// A wallet keyed from `phrase` that stores no phrase, like one created
    /// before phrases were stored. Its password is `test-password`.
    fn legacy_wallet(path: &Path, phrase: &str) -> Wallet {
        let mnemonic = Mnemonic::parse(phrase).unwrap();
        let key = Wallet::master_key_from_mnemonic(&mnemonic, Network::Regtest).unwrap();
        test_wallet_with_key(path, key)
    }

    #[test]
    fn words_are_sized_once() {
        let words = SecretMnemonic(Mnemonic::parse(PHRASE).unwrap()).words();
        assert_eq!(words.as_str(), PHRASE);
        // One byte over the phrase, so the buffer never had to grow.
        assert_eq!(words.capacity(), PHRASE.len() + 1);
    }

    #[test]
    fn attach_stores_only_the_matching_phrase_once() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let mut wallet = legacy_wallet(&path, PHRASE);
        assert!(matches!(
            wallet.get_wallet_mnemonic(password("test-password")),
            Err(WalletError::MnemonicUnavailable)
        ));

        for wrong in ["", "wrong-password"] {
            let err = wallet
                .attach_wallet_mnemonic(password(wrong), password(PHRASE))
                .unwrap_err();
            assert!(matches!(err, WalletError::WrongPassword), "{}", err);
        }
        let other = Mnemonic::generate(24).unwrap().to_string();
        let err = wallet
            .attach_wallet_mnemonic(password("test-password"), Zeroizing::new(other))
            .unwrap_err();
        assert!(matches!(err, WalletError::MnemonicMismatch), "{}", err);
        assert!(wallet.store.sealed_mnemonic.is_none());

        wallet
            .attach_wallet_mnemonic(password("test-password"), password(PHRASE))
            .unwrap();
        let err = wallet
            .attach_wallet_mnemonic(password("test-password"), password(PHRASE))
            .unwrap_err();
        assert!(matches!(err, WalletError::MnemonicAlreadyStored), "{}", err);

        // Saved to disk, and read back only with the password.
        let (saved, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        wallet.store = saved;
        for wrong in ["", "wrong-password"] {
            assert!(matches!(
                wallet.get_wallet_mnemonic(password(wrong)),
                Err(WalletError::WrongPassword)
            ));
        }
        let words = wallet
            .get_wallet_mnemonic(password("test-password"))
            .unwrap()
            .words();
        assert_eq!(words.as_str(), PHRASE);
        assert!(!format!("{wallet:?}").contains("abandon"));
    }

    /// A stored phrase that doesn't derive the wallet's key is never handed out.
    #[test]
    fn mismatched_stored_phrase_is_refused_on_read() {
        let dir = tempdir().unwrap();
        let mut wallet = legacy_wallet(&dir.path().join("wallet"), PHRASE);
        let entropy = SecretEntropy::from_mnemonic(&Mnemonic::generate(12).unwrap()).unwrap();
        wallet.store.sealed_mnemonic = Some(SealedSecret::seal(&entropy, "test-password").unwrap());
        assert!(matches!(
            wallet.get_wallet_mnemonic(password("test-password")),
            Err(WalletError::MnemonicMismatch)
        ));
        assert!(matches!(
            wallet.confirm_seed_backup(password("test-password")),
            Err(WalletError::MnemonicMismatch)
        ));
        assert!(!wallet.seed_backed_up());
    }

    #[test]
    fn seal_checks_the_key_for_every_phrase_length() {
        for words in [12, 15, 18, 21, 24] {
            let mnemonic = Mnemonic::generate(words).unwrap();
            let key = Wallet::master_key_from_mnemonic(&mnemonic, Network::Regtest).unwrap();
            let sealed = seal_mnemonic(&mnemonic, &key, Network::Regtest, "pw").unwrap();
            let entropy: SecretEntropy = sealed.open("pw").unwrap();
            assert_eq!(entropy.to_mnemonic().unwrap(), mnemonic);

            let other = Mnemonic::generate(words).unwrap();
            assert!(matches!(
                seal_mnemonic(&other, &key, Network::Regtest, "pw"),
                Err(WalletError::MnemonicMismatch)
            ));
        }
    }

    #[test]
    fn confirm_needs_the_password_and_a_stored_phrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let mut wallet = legacy_wallet(&path, PHRASE);
        assert!(matches!(
            wallet.confirm_seed_backup(password("test-password")),
            Err(WalletError::MnemonicUnavailable)
        ));
        wallet
            .attach_wallet_mnemonic(password("test-password"), password(PHRASE))
            .unwrap();
        for wrong in ["", "wrong-password"] {
            assert!(matches!(
                wallet.confirm_seed_backup(password(wrong)),
                Err(WalletError::WrongPassword)
            ));
        }
        assert!(!wallet.seed_backed_up());

        wallet
            .confirm_seed_backup(password("test-password"))
            .unwrap();
        assert!(wallet.seed_backed_up());
        let (saved, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        assert!(saved.seed_backed_up);
    }

    #[test]
    fn offline_open_reads_the_seed_without_writing() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let mut wallet = legacy_wallet(&path, PHRASE);
        wallet
            .attach_wallet_mnemonic(password("test-password"), password(PHRASE))
            .unwrap();
        let before = std::fs::read(&path).unwrap();

        for wrong in ["", "wrong-password"] {
            let err = Wallet::open_offline(&path, password(wrong)).err().unwrap();
            assert!(matches!(err, WalletError::WrongPassword), "{}", err);
        }
        let offline = Wallet::open_offline(&path, password("test-password")).unwrap();
        let words = offline
            .get_wallet_mnemonic(password("test-password"))
            .unwrap()
            .words();
        assert_eq!(words.as_str(), PHRASE);
        assert!(!offline.seed_backed_up());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[test]
    fn offline_open_needs_an_existing_wallet_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("missing");
        assert!(Wallet::open_offline(&path, password("test-password")).is_err());
        assert!(!path.exists());
    }

    #[test]
    fn pre_port_v2_seed_remains_password_gated_after_rewrite() {
        for backed_up in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("wallet");
            let mut original = legacy_wallet(&path, PHRASE);
            original
                .attach_wallet_mnemonic(password("test-password"), password(PHRASE))
                .unwrap();
            original.store.seed_backed_up = backed_up;
            let seed_bytes = serde_cbor::to_vec(&original.store.sealed_mnemonic).unwrap();
            let master_bytes = serde_cbor::to_vec(&original.store.master_key).unwrap();
            // Use #1165's writer to exercise migration on the first open.
            let old = crate::security::encrypt_struct_v2(
                &original.store,
                &original.store_enc_material,
                Vec::new(),
            )
            .unwrap();
            let source = serde_cbor::to_vec(&old).unwrap();
            std::fs::write(&path, &source).unwrap();
            drop(original);

            let mut offline = Wallet::open_offline(&path, password("test-password")).unwrap();
            assert_eq!(
                std::fs::read(path.with_file_name("wallet.v2pre")).unwrap(),
                source
            );
            assert!(!path.with_file_name("wallet.v023").exists());
            let migrated: crate::security::EncryptedDataV2 =
                serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(migrated.requires, [crate::security::WALLET_STORE_FORMAT]);
            assert_eq!(offline.seed_backed_up(), backed_up);
            assert_eq!(
                offline
                    .get_wallet_mnemonic(password("test-password"))
                    .unwrap()
                    .words()
                    .as_str(),
                PHRASE
            );
            let before_confirmation = std::fs::read(&path).unwrap();
            for wrong in ["", "wrong-password"] {
                assert!(matches!(
                    offline.get_wallet_mnemonic(password(wrong)),
                    Err(WalletError::WrongPassword)
                ));
                assert!(matches!(
                    offline.confirm_seed_backup(password(wrong)),
                    Err(WalletError::WrongPassword)
                ));
                assert_eq!(std::fs::read(&path).unwrap(), before_confirmation);
                assert_eq!(offline.seed_backed_up(), backed_up);
            }
            // Match the seed CLI's write path: a fresh read under its guard.
            drop(offline);
            let _owner = WalletInUse::exclusive_if_idle(&path).unwrap().unwrap();
            let mut offline = Wallet::open_offline(&path, password("test-password")).unwrap();
            offline
                .confirm_seed_backup(password("test-password"))
                .unwrap();
            drop(offline);

            let reopened = Wallet::open_offline(&path, password("test-password")).unwrap();
            assert!(reopened.seed_backed_up());
            assert_eq!(
                serde_cbor::to_vec(&reopened.store.sealed_mnemonic).unwrap(),
                seed_bytes
            );
            assert_eq!(
                serde_cbor::to_vec(&reopened.store.master_key).unwrap(),
                master_bytes
            );
            assert_eq!(
                reopened
                    .get_wallet_mnemonic(password("test-password"))
                    .unwrap()
                    .words()
                    .as_str(),
                PHRASE
            );
            for wrong in ["", "wrong-password"] {
                assert!(matches!(
                    reopened.get_wallet_mnemonic(password(wrong)),
                    Err(WalletError::WrongPassword)
                ));
            }
        }
    }

    #[test]
    fn migrated_v1_wallet_can_attach_and_reopen_its_seed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let original = legacy_wallet(&path, PHRASE);
        // v0.2.3 / pre-seed stores did not serialize either seed field.
        let serde_cbor::Value::Map(mut old) = serde_cbor::value::to_value(&original.store).unwrap()
        else {
            panic!("store is not a map")
        };
        old.remove(&serde_cbor::Value::Text("sealed_mnemonic".into()));
        old.remove(&serde_cbor::Value::Text("seed_backed_up".into()));
        let v1 = crate::security::encrypt_struct(
            serde_cbor::Value::Map(old),
            &original.store_enc_material,
        )
        .unwrap();
        let source = serde_cbor::to_vec(&v1).unwrap();
        std::fs::write(&path, &source).unwrap();
        drop(original);

        let (store, _) = WalletStore::read_from_disk(&path, Some("test-password".into())).unwrap();
        assert!(store.sealed_mnemonic.is_none());
        assert!(!store.seed_backed_up);
        assert_eq!(
            std::fs::read(path.with_file_name("wallet.v023")).unwrap(),
            source
        );
        let mut migrated = Wallet::open_offline(&path, password("test-password")).unwrap();
        assert!(matches!(
            migrated.get_wallet_mnemonic(password("test-password")),
            Err(WalletError::MnemonicUnavailable)
        ));
        migrated
            .attach_wallet_mnemonic(password("test-password"), password(PHRASE))
            .unwrap();
        drop(migrated);

        let reopened = Wallet::open_offline(&path, password("test-password")).unwrap();
        assert_eq!(
            reopened
                .get_wallet_mnemonic(password("test-password"))
                .unwrap()
                .words()
                .as_str(),
            PHRASE
        );
        assert!(matches!(
            reopened.get_wallet_mnemonic(password("wrong-password")),
            Err(WalletError::WrongPassword)
        ));
        assert_eq!(
            std::fs::read(path.with_file_name("wallet.v023")).unwrap(),
            source
        );
    }

    #[test]
    fn offline_legacy_read_does_not_write_while_an_owner_runs() {
        for v2 in [false, true] {
            let dir = tempdir().unwrap();
            let path = dir.path().join("wallet");
            let original = legacy_wallet(&path, PHRASE);
            let source = if v2 {
                serde_cbor::to_vec(
                    &crate::security::encrypt_struct_v2(
                        &original.store,
                        &original.store_enc_material,
                        Vec::new(),
                    )
                    .unwrap(),
                )
                .unwrap()
            } else {
                serde_cbor::to_vec(
                    &crate::security::encrypt_struct(&original.store, &original.store_enc_material)
                        .unwrap(),
                )
                .unwrap()
            };
            std::fs::write(&path, &source).unwrap();
            drop(original);
            let report_path = dir.path().join("wallet_swap_report.json");
            let report =
                include_bytes!("../../tests/fixtures/compat/v0.2.3/closed_swap_report.json");
            std::fs::write(&report_path, report).unwrap();

            // Both seed commands use this read before obtaining their exclusive
            // guard. Neither an owner nor another seed writer may be bypassed.
            for exclusive in [false, true] {
                let owner = if exclusive {
                    WalletInUse::exclusive_if_idle(&path).unwrap().unwrap()
                } else {
                    WalletInUse::shared(&path).unwrap()
                };
                let err = Wallet::open_offline(&path, password("test-password")).unwrap_err();
                assert!(
                    matches!(err, WalletError::General(ref message) if message == IN_USE_MESSAGE)
                );
                assert!(
                    std::fs::read(&path).unwrap() == source,
                    "an offline seed read rewrote the live owner's wallet"
                );
                assert_eq!(std::fs::read(&report_path).unwrap(), report);
                assert!(!path.with_file_name("wallet.v023").exists());
                assert!(!path.with_file_name("wallet.v2pre").exists());
                assert!(!report_path
                    .with_file_name("wallet_swap_report.json.v023")
                    .exists());
                assert!(!report_path
                    .with_file_name("wallet_swap_report.json.v2pre")
                    .exists());
                drop(owner);
            }
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
        }
    }

    #[test]
    fn offline_upgrade_refusals_release_lock_and_preserve_inputs() {
        let closed = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet");
        let open = include_bytes!("../../tests/fixtures/compat/v0.2.3/open.wallet");
        let report = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed_swap_report.json");
        for v2 in [false, true] {
            for refusal in ["password", "open swap", "report", "archive"] {
                let dir = tempdir().unwrap();
                let path = dir.path().join("wallet");
                let report_path = dir.path().join("wallet_swap_report.json");
                let suffix = if v2 { ".v2pre" } else { ".v023" };
                let archive = dir.path().join(format!("wallet{suffix}"));
                let source: &[u8] = if refusal == "open swap" { open } else { closed };
                let report_bytes: &[u8] = if refusal == "report" {
                    b"bad json"
                } else {
                    report
                };
                let source = if v2 {
                    let (store, material) = crate::security::decrypt_with_password::<WalletStore>(
                        serde_cbor::from_slice(source).unwrap(),
                        "compat-v023".into(),
                        &[],
                    )
                    .unwrap();
                    serde_cbor::to_vec(
                        &crate::security::encrypt_struct_v2(&store, &material, Vec::new()).unwrap(),
                    )
                    .unwrap()
                } else {
                    source.to_vec()
                };
                std::fs::write(&path, &source).unwrap();
                std::fs::write(&report_path, report_bytes).unwrap();
                if refusal == "archive" {
                    std::fs::create_dir(&archive).unwrap();
                }
                let supplied = if refusal == "password" {
                    "wrong"
                } else {
                    "compat-v023"
                };
                let err = Wallet::open_offline(&path, password(supplied)).unwrap_err();
                if refusal == "password" {
                    assert!(matches!(err, WalletError::WrongPassword));
                }
                assert!(std::fs::read(&path).unwrap() == source, "{}", refusal);
                assert_eq!(std::fs::read(&report_path).unwrap(), report_bytes);
                assert!(!report_path
                    .with_file_name(format!("wallet_swap_report.json{suffix}"))
                    .exists());
                if refusal != "archive" {
                    assert!(!archive.exists());
                }
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
            }
        }
    }

    #[test]
    fn offline_open_upgrades_an_old_wallet_when_no_process_runs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let original = legacy_wallet(&path, PHRASE);
        let v1 =
            crate::security::encrypt_struct(&original.store, &original.store_enc_material).unwrap();
        let source = serde_cbor::to_vec(&v1).unwrap();
        std::fs::write(&path, &source).unwrap();
        drop(original);

        let wallet = Wallet::open_offline(&path, password("test-password")).unwrap();
        assert!(matches!(
            wallet.get_wallet_mnemonic(password("test-password")),
            Err(WalletError::MnemonicUnavailable)
        ));
        assert_eq!(
            std::fs::read(path.with_file_name("wallet.v023")).unwrap(),
            source
        );
        assert_ne!(std::fs::read(&path).unwrap(), source);
        // The lock taken for the upgrade is released again.
        assert!(
            super::super::seed_cli::WalletInUse::exclusive_if_idle(&path)
                .unwrap()
                .is_some()
        );
    }
}
