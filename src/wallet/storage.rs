//! The Wallet Storage Interface.
//!
//! Wallet data is written to disk as AES-256-GCM-encrypted CBOR; there is no
//! cleartext-on-disk wallet format by design (legacy cleartext files are
//! still readable, for one-time migration by `Wallet::load`). The master key
//! is additionally sealed individually, see [`MasterKey`].

use crate::{
    security::{
        decrypt_struct, encrypt_struct, load_sensitive_struct, EncryptedData, KeyMaterial,
        SerdeCbor,
    },
    wallet::UTXOSpendInfo,
};

use super::{error::WalletError, fidelity::FidelityBond};

use bitcoin::{bip32::Xpriv, Network, OutPoint, ScriptBuf};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};

use super::swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin};

use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry;

/// Address type supported by the wallet for HD address generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum AddressType {
    /// BIP-84 Native SegWit (P2WPKH)
    #[default]
    P2WPKH,
    /// BIP-86 Taproot key-path only (P2TR)
    P2TR,
}

/// The wallet's BIP32 master key.
///
/// The key is kept *sealed* — AES-256-GCM-encrypted under the wallet's
/// passphrase-derived key — both in memory and on disk (the sealed blob is
/// what gets serialized; there is no cleartext-on-disk form by design). It
/// is only decrypted transiently when a signature or key derivation
/// requires it, which shrinks the window in which the plaintext key is
/// exposed to memory-scraping malware from the whole process lifetime to
/// the duration of a single signing operation.
///
/// Note: the sealing key itself must remain in memory for a hot wallet to
/// sign autonomously, so this defends against passive memory disclosure
/// (core dumps, swap, cold reads), not against a live attacker reading the
/// process's memory. Erasure is best-effort (`Xpriv` is `Copy`; a panic
/// inside the closure skips the wipe; the chain code is never erased).
/// See `docs/wallet-security.md` for the full threat model.
pub(crate) enum MasterKey {
    /// Plaintext key. Transient: only present while a legacy (pre-encryption)
    /// wallet file is being migrated and resealed, or in tests. Must never
    /// reach disk — see [`MasterKey`]'s `Serialize` impl.
    Plaintext(Xpriv),
    /// Sealed (encrypted) key blob. This is the only serializable state.
    Sealed(EncryptedData),
}

impl MasterKey {
    /// Seals a plaintext key in place, erasing the plaintext copy. No-op if
    /// the key is already sealed.
    pub(crate) fn seal(&mut self, key: &KeyMaterial) -> Result<(), WalletError> {
        if let Self::Plaintext(xpriv) = self {
            let data = encrypt_struct(xpriv, key)
                .map_err(|e| WalletError::General(format!("master key sealing failed: {e:?}")))?;
            let mut old = std::mem::replace(self, Self::Sealed(data));
            if let Self::Plaintext(old_xpriv) = &mut old {
                old_xpriv.private_key.non_secure_erase();
            }
        }
        Ok(())
    }

    /// Unseals the key (if sealed), runs `f` with the plaintext, then erases
    /// the plaintext copy. The plaintext key must not escape the closure;
    /// derive whatever is needed inside it.
    pub(crate) fn with_unlocked<T>(
        &self,
        key: &KeyMaterial,
        f: impl FnOnce(&Xpriv) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        match self {
            Self::Plaintext(xpriv) => f(xpriv),
            Self::Sealed(data) => {
                let mut xpriv: Xpriv = decrypt_struct(data.clone(), key)?;
                let result = f(&xpriv);
                xpriv.private_key.non_secure_erase();
                result
            }
        }
    }

    /// Returns the plaintext key, unsealing first if necessary.
    ///
    /// Only used where the surrounding interface cannot propagate errors
    /// (`PartialEq`); prefer [`MasterKey::with_unlocked`].
    pub(crate) fn plaintext_with(&self, key: &KeyMaterial) -> Option<Xpriv> {
        match self {
            Self::Plaintext(xpriv) => Some(*xpriv),
            Self::Sealed(data) => decrypt_struct(data.clone(), key).ok(),
        }
    }
}

/// Byte-wise equality of the stored representation: two loads of the same
/// wallet file compare equal. To compare master keys across different
/// passphrases or sealings, decrypt both via [`MasterKey::plaintext_with`]
/// (as `Wallet`'s `PartialEq` does).
impl PartialEq for MasterKey {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Plaintext(a), Self::Plaintext(b)) => a == b,
            (Self::Sealed(a), Self::Sealed(b)) => a == b,
            _ => false,
        }
    }
}

/// Redacted: never print key material, sealed or not.
impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Plaintext(_) => f.write_str("MasterKey(<plaintext>)"),
            Self::Sealed(_) => f.write_str("MasterKey(<sealed>)"),
        }
    }
}

/// Only the sealed blob is serializable: a plaintext master key must never
/// be written to disk, so attempting to serialize one is a hard error.
/// Serializing the sealed form never decrypts anything, which keeps
/// plaintext out of the (frequent) wallet-state save path entirely.
impl Serialize for MasterKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Sealed(data) => data.serialize(serializer),
            Self::Plaintext(_) => Err(serde::ser::Error::custom(
                "plaintext master key must never be serialized",
            )),
        }
    }
}

/// On-disk representation: new wallet files store the sealed blob; legacy
/// files store a plain [`Xpriv`], which deserializes into the transient
/// [`MasterKey::Plaintext`] state for migration (`Wallet::load` reseals and
/// rewrites the file encrypted right after loading).
impl<'de> Deserialize<'de> for MasterKey {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum MasterKeyWire {
            Sealed(EncryptedData),
            Legacy(Xpriv),
        }
        Ok(match MasterKeyWire::deserialize(deserializer)? {
            MasterKeyWire::Sealed(data) => Self::Sealed(data),
            MasterKeyWire::Legacy(xpriv) => Self::Plaintext(xpriv),
        })
    }
}

/// Represents the internal data store for a Bitcoin wallet.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub(crate) struct WalletStore {
    /// The file name associated with the wallet store.
    pub(crate) file_name: String,
    /// Network the wallet operates on.
    pub(crate) network: Network,
    /// The master key for the wallet. Sealed (encrypted) in memory; only
    /// unsealed transiently for signing, see [`MasterKey`].
    pub(super) master_key: MasterKey,
    /// The external index for the wallet.
    pub(super) external_index: u32,
    /// The internal index for the wallet.
    #[serde(default)]
    pub(super) internal_index: u32,
    /// The maximum size for an offer in the wallet.
    pub(crate) offer_maxsize: u64,
    /// Map of swap_id to incoming swapcoins.
    pub(super) incoming_swapcoins: HashMap<String, IncomingSwapCoin>,
    /// Map of swap_id to outgoing swapcoins.
    pub(super) outgoing_swapcoins: HashMap<String, OutgoingSwapCoin>,
    /// Map of swap_id to watch-only swapcoins.
    #[serde(default)]
    pub(super) watchonly_swapcoins: HashMap<String, Vec<WatchOnlySwapCoin>>,
    /// Map of prevout to contract redeemscript.
    pub(super) prevout_to_contract_map: HashMap<OutPoint, ScriptBuf>,
    /// Set of swept incoming swap coin scriptpubkeys to prevent mixing with regular UTXOs
    pub(crate) swept_incoming_swapcoins: HashSet<ScriptBuf>,
    /// List of all fidelity bonds.
    pub(crate) fidelity_bond: Vec<FidelityBond>,
    pub(super) last_synced_height: Option<u64>,

    pub(super) wallet_birthday: Option<u64>,

    /// Maps transaction outpoints to their associated UTXO and spend information.
    #[serde(default)] // Ensures deserialization works if `utxo_cache` is missing
    pub(super) utxo_cache: HashMap<OutPoint, (ListUnspentResultEntry, UTXOSpendInfo)>,
}

impl WalletStore {
    /// Initialize a store at a path (if path already exists, it will overwrite it).
    ///
    /// The master key is sealed with `store_enc_material` before the first
    /// write, so the plaintext key never reaches disk.
    pub(crate) fn init(
        file_name: String,
        path: &Path,
        network: Network,
        master_key: Xpriv,
        wallet_birthday: Option<u64>,
        store_enc_material: &KeyMaterial,
    ) -> Result<Self, WalletError> {
        let mut store = Self {
            file_name,
            network,
            master_key: MasterKey::Plaintext(master_key),
            external_index: 0,
            internal_index: 0,
            offer_maxsize: 0,
            incoming_swapcoins: HashMap::new(),
            outgoing_swapcoins: HashMap::new(),
            watchonly_swapcoins: HashMap::new(),
            prevout_to_contract_map: HashMap::new(),
            swept_incoming_swapcoins: HashSet::new(),
            fidelity_bond: Vec::new(),
            last_synced_height: None,
            wallet_birthday,
            utxo_cache: HashMap::new(),
        };
        store.master_key.seal(store_enc_material)?;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        // Exclusive create: fails with `AlreadyExists` instead of truncating a
        // wallet that appeared since the caller checked the path.
        File::create_new(path)?;

        store.write_to_disk(path, store_enc_material)?;

        Ok(store)
    }

    /// Load existing file, updates it, writes it back (errors if path doesn't exist).
    ///
    /// The wallet file is always encrypted: there is no cleartext-on-disk
    /// form by design. The write is atomic — a tempfile in the same
    /// directory, fsynced and renamed over the target — so a crash mid-save
    /// cannot truncate the only copy of the wallet.
    pub(crate) fn write_to_disk(
        &self,
        path: &Path,
        store_enc_material: &KeyMaterial,
    ) -> Result<(), WalletError> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let encrypted = encrypt_struct(self, store_enc_material)
            .map_err(|e| WalletError::General(format!("wallet store encryption failed: {e:?}")))?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        let mut writer = BufWriter::new(&mut tmp);
        serde_cbor::to_writer(&mut writer, &encrypted)?;
        // `Drop for BufWriter` discards flush errors, so flush explicitly:
        // a swallowed error would rename a truncated wallet over the good one.
        writer.flush()?;
        drop(writer);
        tmp.as_file().sync_all()?;
        tmp.persist(path)
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        // Without this the rename itself may not survive a crash.
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    /// Reads from a path (errors if path doesn't exist).
    /// If `password` is provided, attempts to decrypt the file using the
    /// provided key. Returns the deserialized `WalletStore` and the derived
    /// encryption material (`None` for a plaintext file).
    /// An encrypted file read without a password yields
    /// [`crate::security::SecurityError::PasswordRequired`].
    pub(crate) fn read_from_disk(
        backup_file_path: &Path,
        password: Option<String>,
    ) -> Result<(Self, Option<KeyMaterial>), WalletError> {
        load_sensitive_struct::<Self, SerdeCbor>(backup_file_path, password).map_err(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityError;
    use bip39::rand::{thread_rng, Rng};
    use bitcoind::tempfile::tempdir;

    #[test]
    fn test_write_and_read_wallet_to_disk() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_wallet.cbor");

        let master_key = {
            let seed: [u8; 16] = thread_rng().gen();
            Xpriv::new_master(Network::Bitcoin, &seed).unwrap()
        };
        let password = "wallet password".to_string();
        let encryption_material = KeyMaterial::new_from_password(Some(password.clone())).unwrap();

        let original_wallet_store = WalletStore::init(
            "test_wallet".to_string(),
            &file_path,
            Network::Bitcoin,
            master_key,
            None,
            &encryption_material,
        )
        .unwrap();

        original_wallet_store
            .write_to_disk(&file_path, &encryption_material)
            .unwrap();

        let (read_wallet, material) =
            WalletStore::read_from_disk(&file_path, Some(password)).unwrap();
        assert!(material.is_some());
        assert_eq!(original_wallet_store, read_wallet);
    }

    #[test]
    fn sealed_master_key_roundtrips() {
        let seed: [u8; 16] = thread_rng().gen();
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let material = KeyMaterial::new_ephemeral();

        let mut key = MasterKey::Plaintext(xpriv);
        key.seal(&material).unwrap();
        assert!(matches!(key, MasterKey::Sealed(_)));

        // Unsealing yields the original key.
        let unsealed = key.with_unlocked(&material, |k| Ok(*k)).unwrap();
        assert_eq!(unsealed, xpriv);

        // The sealed blob survives a serde roundtrip and still unseals.
        let bytes = serde_cbor::to_vec(&key).unwrap();
        let read_back: MasterKey = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(key, read_back);
        assert_eq!(
            read_back.with_unlocked(&material, |k| Ok(*k)).unwrap(),
            xpriv
        );

        // A legacy plaintext representation still deserializes (into the
        // transient migration state)...
        let legacy: MasterKey =
            serde_cbor::from_slice(&serde_cbor::to_vec(&xpriv).unwrap()).unwrap();
        assert_eq!(legacy, MasterKey::Plaintext(xpriv));

        // ...but serializing a plaintext key is a hard error: cleartext must
        // never reach disk.
        assert!(serde_cbor::to_vec(&legacy).is_err());

        // Debug output never contains key material.
        assert_eq!(format!("{key:?}"), "MasterKey(<sealed>)");
        assert_eq!(format!("{legacy:?}"), "MasterKey(<plaintext>)");
    }

    #[test]
    fn sealed_master_key_survives_encrypted_store_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("sealed_wallet.cbor");
        let seed: [u8; 16] = thread_rng().gen();
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let password = "wallet password".to_string();
        let encryption_material = KeyMaterial::new_from_password(Some(password.clone())).unwrap();

        // init seals the master key before the first write.
        let store = WalletStore::init(
            "sealed_wallet".to_string(),
            &file_path,
            Network::Bitcoin,
            xpriv,
            None,
            &encryption_material,
        )
        .unwrap();
        assert!(matches!(store.master_key, MasterKey::Sealed(_)));
        store
            .write_to_disk(&file_path, &encryption_material)
            .unwrap();

        let (read_store, _) = WalletStore::read_from_disk(&file_path, Some(password)).unwrap();
        assert_eq!(store, read_store);
        let unsealed = read_store
            .master_key
            .with_unlocked(&encryption_material, |k| Ok(*k))
            .unwrap();
        assert_eq!(unsealed, xpriv);
    }

    #[test]
    fn reads_encrypted_wallet_when_password_is_supplied() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_wallet.cbor");
        let seed: [u8; 16] = thread_rng().gen();
        let master_key = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let password = "wallet password".to_string();
        let encryption_material = KeyMaterial::new_from_password(Some(password.clone())).unwrap();

        let original_wallet_store = WalletStore::init(
            "test_wallet".to_string(),
            &file_path,
            Network::Bitcoin,
            master_key,
            None,
            &encryption_material,
        )
        .unwrap();

        let error = WalletStore::read_from_disk(&file_path, Some("wrong password".to_string()))
            .expect_err("a wrong password must fail authentication");
        assert!(error.to_string().contains("decryption failed"));

        let (read_wallet, read_encryption_material) =
            WalletStore::read_from_disk(&file_path, Some(password)).unwrap();
        assert_eq!(original_wallet_store, read_wallet);
        assert!(read_encryption_material.is_some());
    }

    #[test]
    fn encrypted_wallet_without_password_says_password_required() {
        let temp_dir = tempdir().unwrap();
        let file_path = temp_dir.path().join("test_wallet.cbor");
        let seed: [u8; 16] = thread_rng().gen();
        let master_key = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        let encryption_material =
            KeyMaterial::new_from_password(Some("wallet password".to_string())).unwrap();

        WalletStore::init(
            "test_wallet".to_string(),
            &file_path,
            Network::Bitcoin,
            master_key,
            None,
            &encryption_material,
        )
        .unwrap();

        // No passphrase at all must surface PasswordRequired, not a
        // misleading decryption failure from an empty passphrase.
        let error = WalletStore::read_from_disk(&file_path, None)
            .expect_err("an encrypted file without a password must be rejected");
        assert!(matches!(
            error,
            WalletError::Security(SecurityError::PasswordRequired)
        ));
    }
}
