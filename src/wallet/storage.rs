//! The Wallet Storage Interface.
//!
//! Wallet data is written to disk as AES-256-GCM-encrypted CBOR in the version
//! 2 container; there is no cleartext-on-disk wallet format by design. Version
//! 1 files still load, and the next save writes them as version 2. The master
//! key and the seed phrase are each sealed again, see [`MasterKey`] and
//! [`WalletStore::sealed_mnemonic`].

use crate::{
    security::{
        decrypt_struct, encrypt_struct, encrypt_struct_v2, load_sensitive_struct, EncryptedData,
        KeyMaterial, SealedSecret, SerdeCbor,
    },
    wallet::UTXOSpendInfo,
};

use super::{backup::RestoreOptions, error::WalletError, fidelity::FidelityBond};

use bip39::Mnemonic;
use bitcoin::{bip32::Xpriv, Network, OutPoint, ScriptBuf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{HashMap, HashSet},
    fmt::Write as _,
    fs::File,
    io::{BufWriter, Write},
    path::Path,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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

/// The wallet's BIP32 master key stays sealed in memory and on disk.
/// Plaintext is erased after signing or legacy wallet migration.
pub(crate) enum MasterKey {
    /// Plaintext key. Transient: only present while a legacy (pre-encryption)
    /// wallet file is being migrated and resealed, or in tests. Must never
    /// reach disk — see [`MasterKey`]'s `Serialize` impl.
    Plaintext(Xpriv),
    /// Sealed (encrypted) key blob. This is the only serializable state.
    Sealed(EncryptedData),
}

fn erase_xpriv(key: &mut Xpriv) {
    key.private_key.non_secure_erase();
    let chain_code: &mut [u8; 32] = key.chain_code.as_mut();
    chain_code.zeroize();
}

impl Drop for MasterKey {
    fn drop(&mut self) {
        if let Self::Plaintext(key) = self {
            erase_xpriv(key);
        }
    }
}

/// Wipes a copied private key and chain code on return or unwind.
pub(crate) struct SecretXpriv(pub(crate) Xpriv);

impl Drop for SecretXpriv {
    fn drop(&mut self) {
        erase_xpriv(&mut self.0);
    }
}

// Same text as `Xpriv`'s own impl, which goes through serde's growing and
// unwiped `to_string`. Base58 of the 82-byte key is at most 112 characters.
impl Serialize for SecretXpriv {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = Zeroizing::new(String::with_capacity(112));
        write!(text, "{}", self.0).expect("writing to a String cannot fail");
        serializer.serialize_str(&text)
    }
}

impl<'de> Deserialize<'de> for SecretXpriv {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Xpriv::deserialize(deserializer).map(Self)
    }
}

/// BIP39 entropy lengths in bytes, for 12, 15, 18, 21 and 24 words.
const ENTROPY_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];

/// How stored entropy turns back into the wallet's keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum SeedPolicy {
    /// English words and an empty BIP39 passphrase.
    Bip39EnglishEmptyPassphrase,
}

/// The seed phrase as BIP39 entropy, wiped on drop. All fields have a fixed
/// size, so serde never grows a buffer and frees an unwiped copy.
#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub(crate) struct SecretEntropy {
    #[zeroize(skip)]
    policy: SeedPolicy,
    len: u8,
    bytes: [u8; 32],
}

impl SecretEntropy {
    pub(crate) fn from_mnemonic(mnemonic: &Mnemonic) -> Result<Self, WalletError> {
        let (array, len) = mnemonic.to_entropy_array();
        let array = Zeroizing::new(array);
        if !ENTROPY_LENGTHS.contains(&len) {
            return Err(WalletError::General(format!(
                "seed entropy must be 16 to 32 bytes in steps of 4, not {len}"
            )));
        }
        let mut entropy = Self {
            policy: SeedPolicy::Bip39EnglishEmptyPassphrase,
            len: len as u8,
            bytes: [0; 32],
        };
        entropy.bytes[..len].copy_from_slice(&array[..len]);
        Ok(entropy)
    }

    /// Rebuilds the canonical English words.
    pub(crate) fn to_mnemonic(&self) -> Result<Mnemonic, WalletError> {
        let SeedPolicy::Bip39EnglishEmptyPassphrase = self.policy;
        let len = usize::from(self.len);
        if !ENTROPY_LENGTHS.contains(&len) {
            return Err(WalletError::General(format!(
                "stored seed entropy has invalid length {len}"
            )));
        }
        Ok(Mnemonic::from_entropy(&self.bytes[..len])?)
    }
}

impl MasterKey {
    /// Seals a plaintext key in place, erasing the plaintext copy. No-op if
    /// the key is already sealed.
    pub(crate) fn seal(&mut self, key: &KeyMaterial) -> Result<(), WalletError> {
        if let Self::Plaintext(xpriv) = self {
            let data = encrypt_struct(SecretXpriv(*xpriv), key)
                .map_err(|e| WalletError::General(format!("master key sealing failed: {e:?}")))?;
            *self = Self::Sealed(data);
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
                let xpriv = SecretXpriv(decrypt_struct(data.clone(), key)?);
                f(&xpriv.0)
            }
        }
    }
}

/// Byte-wise equality of the stored representation: two loads of the same
/// wallet file compare equal.
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
/// [`MasterKey::Plaintext`] state. `Wallet::load` reseals it in memory only;
/// the file keeps the plain key until the next save.
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

/// Inputs one swap holds out of coin selection, and when it took them.
/// Persisted so a restart inside the grace still honours the reservation:
/// a funding broadcast can still arrive for a swap the process forgot.
#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub(crate) struct SwapReservation {
    pub(crate) outpoints: HashSet<OutPoint>,
    pub(crate) reserved_at: u64,
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

    /// Set until a restore's first scan finishes, so a restart resumes that
    /// scan with the options the user chose.
    #[serde(default)]
    pub(super) pending_restore: Option<RestoreOptions>,

    /// Maps transaction outpoints to their associated UTXO and spend information.
    #[serde(default)] // Ensures deserialization works if `utxo_cache` is missing
    pub(super) utxo_cache: HashMap<OutPoint, (ListUnspentResultEntry, UTXOSpendInfo)>,
    /// Outpoints promised to one in-flight swap, keyed by swap id. Unlike
    /// `locked_utxos` (a property of the coin), these live and die with the
    /// swap, so one swap's release must never free another's inputs.
    #[serde(default)]
    pub(crate) swap_locks: HashMap<String, SwapReservation>,

    /// Pending Lightning submarine swaps by swap_id (hex payment hash).
    /// Everything needed to claim or refund the on-chain HTLC after a crash.
    #[serde(default)]
    pub(crate) ln_pending_swaps: HashMap<String, LnPendingSwap>,

    /// Maker-side Lightning swaps in progress, by swap_id. Restored into the
    /// maker's live swap map on startup so a restart mid-swap can still
    /// sweep or refund.
    #[serde(default)]
    pub(crate) ln_maker_swaps: HashMap<String, LnMakerSwapRecord>,

    /// The seed phrase as [`SecretEntropy`], sealed under its own key from the
    /// wallet password. Load, save, sync and signing never open it.
    #[serde(default)]
    pub(super) sealed_mnemonic: Option<SealedSecret>,
    /// Set once the user has confirmed writing the seed phrase down.
    #[serde(default)]
    pub(super) seed_backed_up: bool,
}

/// Which side of a Lightning swap the maker is serving.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LnMakerDirection {
    /// Taker pays on-chain, maker pays over Lightning.
    SwapIn,
    /// Taker pays over Lightning, maker pays on-chain.
    SwapOut,
}

/// How far a maker-side Lightning swap has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LnMakerPhase {
    /// Swap-in accepted; awaiting the taker's HTLC funding announcement.
    InAccepted,
    /// Swap-in invoice paid; awaiting the settlement that reveals the
    /// preimage, then an on-chain sweep.
    InPaid,
    /// Swap-in sweep broadcast, awaiting confirmation. The record is kept
    /// until then so the sweep can be rebuilt and rebroadcast: a spend that
    /// is only in the mempool can still be evicted or reorged away.
    InSwept,
    /// Swap-out accepted (hold invoice created); awaiting payment.
    OutAccepted,
    /// Swap-out HTLC funded on-chain; awaiting the taker's claim.
    OutFunded,
}

/// Maker-side recovery record for a Lightning submarine swap.
///
/// Written before the maker commits anything of value — before paying an
/// invoice, before funding an HTLC — so a maker that restarts mid-swap can
/// still reach the money. Without it a restarted swap-in maker cannot sweep
/// the HTLC it already paid for, and a restarted swap-out maker cannot
/// refund the HTLC it already funded.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct LnMakerSwapRecord {
    /// Direction of the swap.
    pub direction: LnMakerDirection,
    /// Current phase.
    pub phase: LnMakerPhase,
    /// Lightning payment hash (the swap id in hex).
    pub payment_hash: bitcoin::hashes::sha256::Hash,
    /// Swap amount (what the taker receives).
    pub amount: bitcoin::Amount,
    /// Maker fee on top of `amount`.
    pub fee: bitcoin::Amount,
    /// Relative locktime (blocks, CSV) of the refund branch.
    pub locktime: u16,
    /// Confirmations required on the HTLC funding output.
    pub min_confirmations: u32,
    /// The HTLC witness script.
    pub redeemscript: ScriptBuf,
    /// The maker's branch key: hashlock (swap-in) or timelock (swap-out).
    pub privkey: bitcoin::secp256k1::SecretKey,
    /// The invoice: the taker's hold invoice (swap-in) or ours (swap-out).
    pub invoice: String,
    /// The swap preimage, once the maker has learned it. Kept so a sweep
    /// can be rebuilt after a restart or an evicted broadcast.
    #[serde(default)]
    pub preimage: Option<[u8; 32]>,
    /// Txid of the refund this maker broadcast, once it has. Lets a
    /// confirmed spend of the HTLC be attributed: only if *this*
    /// transaction confirmed was the refund ours.
    #[serde(default)]
    pub refund_txid: Option<bitcoin::Txid>,
    /// Chain tip when this swap was accepted. A swap-in's funding deadline
    /// is measured in blocks from here, since the taker must wait for the
    /// confirmations the maker demanded before it can announce.
    #[serde(default)]
    pub accepted_height: Option<u32>,
    /// Where this swap's sweep or refund pays out. Fixed on first use so a
    /// rebuild produces the same transaction instead of one that conflicts
    /// with what is already in the mempool — and so retrying does not
    /// consume a fresh address every tick.
    #[serde(default)]
    pub payout_script: Option<ScriptBuf>,
    /// The HTLC funding outpoint, once known.
    pub funding_outpoint: Option<OutPoint>,
    /// The HTLC funding value, once known.
    pub funding_value: Option<bitcoin::Amount>,
    /// Refund timing. Swap-in: the block that confirmed the funding, where the
    /// taker's CSV refund window starts. Swap-out: the chain tip when the
    /// maker broadcast its funding.
    pub funding_height: Option<u32>,
}

/// Redacted like [`LnPendingSwap`]: `Wallet` formats its store.
impl std::fmt::Debug for LnMakerSwapRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LnMakerSwapRecord")
            .field("direction", &self.direction)
            .field("phase", &self.phase)
            .field("payment_hash", &self.payment_hash)
            .field("amount", &self.amount)
            .field("fee", &self.fee)
            .field("locktime", &self.locktime)
            .field("min_confirmations", &self.min_confirmations)
            .field("preimage", &self.preimage.map(|_| "<redacted>"))
            .field("refund_txid", &self.refund_txid)
            .field("accepted_height", &self.accepted_height)
            .field("funding_outpoint", &self.funding_outpoint)
            .field("funding_value", &self.funding_value)
            .field("funding_height", &self.funding_height)
            .finish_non_exhaustive()
    }
}

/// Taker-side recovery record for a Lightning submarine swap.
///
/// Persisted (encrypted with the rest of the store) before any value is
/// committed, so a crashed taker can always claim (preimage present) or
/// refund (timelock branch) the on-chain HTLC.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct LnPendingSwap {
    /// Whether this is a swap-in (`true`: we funded, refund branch is ours)
    /// or a swap-out (`false`: we claim via hashlock with the preimage).
    pub is_swap_in: bool,
    /// The swap preimage; only for swap-outs (we generated it).
    pub preimage: Option<[u8; 32]>,
    /// The HTLC witness script.
    pub redeemscript: ScriptBuf,
    /// Relative locktime (blocks, CSV) of the refund branch.
    pub locktime: u16,
    /// Our branch key: timelock (swap-in) or hashlock (swap-out).
    pub privkey: bitcoin::secp256k1::SecretKey,
    /// The HTLC funding outpoint, once known.
    pub outpoint: Option<OutPoint>,
    /// The HTLC funding value, once known.
    pub value: Option<bitcoin::Amount>,
}

/// Redacted: the preimage is the secret the whole swap turns on, and
/// `Wallet` formats its store.
impl std::fmt::Debug for LnPendingSwap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LnPendingSwap")
            .field("is_swap_in", &self.is_swap_in)
            .field("preimage", &self.preimage.map(|_| "<redacted>"))
            .field("locktime", &self.locktime)
            .field("outpoint", &self.outpoint)
            .field("value", &self.value)
            .finish_non_exhaustive()
    }
}

impl WalletStore {
    /// Initialize a store at a path (if path already exists, it will overwrite it).
    ///
    /// The master key is sealed with `store_enc_material` before the first
    /// write, so the plaintext key never reaches disk. Wallets with no seed
    /// phrase exist only in tests now.
    #[cfg(test)]
    pub(crate) fn init(
        file_name: String,
        path: &Path,
        network: Network,
        master_key: Xpriv,
        wallet_birthday: Option<u64>,
        pending_restore: Option<RestoreOptions>,
        store_enc_material: &KeyMaterial,
    ) -> Result<Self, WalletError> {
        let master_key = SecretXpriv(master_key);
        Self::init_with(
            file_name,
            path,
            network,
            master_key.0,
            wallet_birthday,
            pending_restore,
            store_enc_material,
            |_| {},
        )
    }

    /// Initialize a store at a path that must not exist yet. `prepare` fills
    /// in extra state before the first durable write, so no partial store
    /// ever reaches disk. The master key is sealed before that write.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn init_with(
        file_name: String,
        path: &Path,
        network: Network,
        master_key: Xpriv,
        wallet_birthday: Option<u64>,
        pending_restore: Option<RestoreOptions>,
        store_enc_material: &KeyMaterial,
        prepare: impl FnOnce(&mut Self),
    ) -> Result<Self, WalletError> {
        let master_key = SecretXpriv(master_key);
        let mut store = Self {
            file_name,
            network,
            master_key: MasterKey::Plaintext(master_key.0),
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
            pending_restore,
            utxo_cache: HashMap::new(),
            swap_locks: HashMap::new(),
            ln_pending_swaps: HashMap::new(),
            ln_maker_swaps: HashMap::new(),
            sealed_mnemonic: None,
            seed_backed_up: false,
        };
        drop(master_key);
        prepare(&mut store);
        store.master_key.seal(store_enc_material)?;

        // No-clobber: fails with `AlreadyExists` instead of replacing a wallet
        // that appeared since the caller checked the path, and never leaves
        // an empty or partial file there if the write fails.
        store.write_file(path, store_enc_material, true)?;

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
        self.write_file(path, store_enc_material, false)
    }

    fn write_file(
        &self,
        path: &Path,
        store_enc_material: &KeyMaterial,
        no_clobber: bool,
    ) -> Result<(), WalletError> {
        // Always version 2, which upgrades a version 1 file on its first save.
        let encrypted = encrypt_struct_v2(self, store_enc_material)
            .map_err(|e| WalletError::General(format!("wallet store encryption failed: {e:?}")))?;
        write_atomic(path, no_clobber, |writer| {
            serde_cbor::to_writer(writer, &encrypted)?;
            Ok(())
        })
    }

    /// Reads a version 1 or 2 file from a path (errors if path doesn't exist).
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

/// Writes `path` through a fsynced tempfile in the same directory, then
/// renames it into place (refusing an existing file when `no_clobber`).
/// A failure at any step leaves `path` as it was.
fn write_atomic(
    path: &Path,
    no_clobber: bool,
    write: impl FnOnce(&mut BufWriter<&mut tempfile::NamedTempFile>) -> Result<(), WalletError>,
) -> Result<(), WalletError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
    let mut writer = BufWriter::new(&mut tmp);
    write(&mut writer)?;
    // `Drop for BufWriter` discards flush errors, so flush explicitly:
    // a swallowed error would rename a truncated wallet over the good one.
    writer.flush()?;
    drop(writer);
    tmp.as_file().sync_all()?;
    if no_clobber {
        tmp.persist_noclobber(path)
    } else {
        tmp.persist(path)
    }
    .map_err(|e| e.error)?;
    // Without this the rename itself may not survive a crash.
    #[cfg(not(windows))]
    File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{is_encrypted_cbor, SecurityError};
    use bip39::rand::{thread_rng, Rng};
    use bitcoin::{
        hashes::{sha256, Hash},
        secp256k1::SecretKey,
        Amount,
    };
    use bitcoind::tempfile::tempdir;

    #[test]
    fn failed_first_write_leaves_no_wallet_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let failed = write_atomic(&path, true, |_| Err(WalletError::General("cut".into())));
        assert!(failed.is_err());
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            0,
            "neither the wallet nor a tempfile may remain"
        );

        // So a retry writes it, and a second no-clobber write refuses to replace it.
        write_atomic(&path, true, |w| Ok(w.write_all(b"first")?)).unwrap();
        assert!(write_atomic(&path, true, |w| Ok(w.write_all(b"second")?)).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"first");
    }

    fn test_store(path: &Path, material: &KeyMaterial) -> WalletStore {
        let seed: [u8; 16] = thread_rng().gen();
        let xpriv = Xpriv::new_master(Network::Bitcoin, &seed).unwrap();
        WalletStore::init(
            "test_wallet".to_string(),
            path,
            Network::Bitcoin,
            xpriv,
            None,
            None,
            material,
        )
        .unwrap()
    }

    #[test]
    fn secret_entropy_roundtrips_every_phrase_length() {
        for words in [12, 15, 18, 21, 24] {
            let mnemonic = Mnemonic::generate(words).unwrap();
            let entropy = SecretEntropy::from_mnemonic(&mnemonic).unwrap();
            assert_eq!(usize::from(entropy.len), words * 4 / 3);

            let sealed = SealedSecret::seal(&entropy, "wallet password").unwrap();
            let opened: SecretEntropy = sealed.open("wallet password").unwrap();
            assert_eq!(opened.to_mnemonic().unwrap(), mnemonic);
        }

        // A hand-edited length is refused instead of read past the entropy.
        for len in [0, 17, 33] {
            let edited = SecretEntropy {
                policy: SeedPolicy::Bip39EnglishEmptyPassphrase,
                len,
                bytes: [7; 32],
            };
            assert!(edited.to_mnemonic().is_err());
        }
    }

    #[test]
    fn sealed_mnemonic_survives_save_and_load_unopened() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let password = "wallet password";
        let material = KeyMaterial::new_from_password(Some(password.to_string())).unwrap();
        let mut store = test_store(&path, &material);
        assert!(store.sealed_mnemonic.is_none());
        assert!(!store.seed_backed_up);

        let mnemonic = Mnemonic::generate(24).unwrap();
        let entropy = SecretEntropy::from_mnemonic(&mnemonic).unwrap();
        store.sealed_mnemonic = Some(SealedSecret::seal(&entropy, password).unwrap());
        store.seed_backed_up = true;
        store.write_to_disk(&path, &material).unwrap();

        let (read, _) = WalletStore::read_from_disk(&path, Some(password.to_string())).unwrap();
        assert_eq!(read, store);
        assert!(read.seed_backed_up);
        let opened: SecretEntropy = read
            .sealed_mnemonic
            .as_ref()
            .unwrap()
            .open(password)
            .unwrap();
        assert_eq!(opened.to_mnemonic().unwrap(), mnemonic);

        // `Wallet`'s Debug prints the store; no word or entropy may show.
        let debug = format!("{read:?}");
        assert!(debug.contains("sealed_mnemonic: Some(SealedSecret(<sealed>))"));
        assert!(!debug.contains(&mnemonic.to_string()));
    }

    #[test]
    fn maker_swap_debug_redacts_the_preimage() {
        let preimage = [0xab; 32];
        let record = LnMakerSwapRecord {
            direction: LnMakerDirection::SwapIn,
            phase: LnMakerPhase::InPaid,
            payment_hash: sha256::Hash::hash(&preimage),
            amount: Amount::from_sat(50_000),
            fee: Amount::from_sat(500),
            locktime: 144,
            min_confirmations: 1,
            redeemscript: ScriptBuf::new(),
            privkey: SecretKey::from_slice(&[1; 32]).unwrap(),
            invoice: String::new(),
            preimage: Some(preimage),
            refund_txid: None,
            accepted_height: None,
            payout_script: None,
            funding_outpoint: None,
            funding_value: None,
            funding_height: None,
        };
        let debug = format!("{record:?}");
        assert!(debug.contains("preimage: Some(\"<redacted>\")"));
        assert!(!debug.contains("171"), "a preimage byte leaked: {}", debug);
    }

    #[test]
    fn version_1_file_loads_and_next_save_writes_version_2() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let password = "wallet password";
        let material = KeyMaterial::new_from_password(Some(password.to_string())).unwrap();
        let store = test_store(&path, &material);

        // An older build's file: no seed fields, the version 1 container.
        let serde_cbor::Value::Map(mut old) = serde_cbor::value::to_value(&store).unwrap() else {
            panic!("store is not a map")
        };
        for field in ["sealed_mnemonic", "seed_backed_up"] {
            old.remove(&serde_cbor::Value::Text(field.to_string()));
        }
        let v1 = encrypt_struct(serde_cbor::Value::Map(old), &material).unwrap();
        std::fs::write(&path, serde_cbor::to_vec(&v1).unwrap()).unwrap();
        let v1_bytes = std::fs::read(&path).unwrap();

        let (read, read_material) =
            WalletStore::read_from_disk(&path, Some(password.to_string())).unwrap();
        assert_eq!(read, store);
        assert_eq!(std::fs::read(&path).unwrap(), v1_bytes, "load never writes");

        read.write_to_disk(&path, &read_material.unwrap()).unwrap();
        let v2_bytes = std::fs::read(&path).unwrap();
        assert!(serde_cbor::from_slice::<EncryptedData>(&v2_bytes).is_err());
        assert!(is_encrypted_cbor(&v2_bytes));
        let (upgraded, _) = WalletStore::read_from_disk(&path, Some(password.to_string())).unwrap();
        assert_eq!(upgraded, store);
    }

    /// An older build reads a version 1 file, a new build upgrades it on its
    /// first write, and from then on the older build refuses the file at parse
    /// time, so it never saves over the sealed phrase.
    #[test]
    fn old_new_old_sequence_never_loses_the_sealed_phrase() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let password = "wallet password";
        let material = KeyMaterial::new_from_password(Some(password.to_string())).unwrap();
        let mut store = test_store(&path, &material);
        let mnemonic = bip39::Mnemonic::generate(12).unwrap();
        let entropy = SecretEntropy::from_mnemonic(&mnemonic).unwrap();
        store.sealed_mnemonic = Some(SealedSecret::seal(&entropy, password).unwrap());

        let v1 = encrypt_struct(&store, &material).unwrap();
        std::fs::write(&path, serde_cbor::to_vec(&v1).unwrap()).unwrap();
        assert!(serde_cbor::from_slice::<EncryptedData>(&std::fs::read(&path).unwrap()).is_ok());

        let (read, read_material) =
            WalletStore::read_from_disk(&path, Some(password.to_string())).unwrap();
        read.write_to_disk(&path, &read_material.unwrap()).unwrap();
        let v2_bytes = std::fs::read(&path).unwrap();
        // The old build's refusal is modelled by its v1 parser, not a real run.
        assert!(serde_cbor::from_slice::<EncryptedData>(&v2_bytes).is_err());

        let (again, _) = WalletStore::read_from_disk(&path, Some(password.to_string())).unwrap();
        assert_eq!(again.sealed_mnemonic, store.sealed_mnemonic);
        assert_eq!(std::fs::read(&path).unwrap(), v2_bytes);
    }

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

        // The wiped encoding writes the same bytes, so older sealed keys still open.
        assert_eq!(
            serde_cbor::to_vec(&SecretXpriv(xpriv)).unwrap(),
            serde_cbor::to_vec(&xpriv).unwrap()
        );

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
