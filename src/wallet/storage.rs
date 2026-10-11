//! The Wallet Storage Interface.
//!
//! Wallet data is written to disk as AES-256-GCM-encrypted CBOR; there is no
//! cleartext-on-disk wallet format by design (legacy cleartext files are
//! still readable, for one-time migration by `Wallet::load`). The master key
//! is additionally sealed individually, see [`MasterKey`].

use crate::{
    protocol::features::{check_requires, supported},
    security::{
        decrypt_struct, decrypt_with_password, encrypt_struct, requires_aad, EncryptedData,
        KeyMaterial, SecurityError, FORMAT_NAMES,
    },
    utill::deserialize_from_cbor,
    wallet::UTXOSpendInfo,
};

use super::{error::WalletError, fidelity::FidelityBond};

use bitcoin::{bip32::Xpriv, Network, OutPoint, ScriptBuf};
use serde::{Deserialize, Deserializer, Serialize};
use serde_cbor::{value::from_value, Value};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
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
            let data = encrypt_struct(xpriv, key, &[])
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
                let mut xpriv: Xpriv = decrypt_struct(data.clone(), key, &[])?;
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
            Self::Sealed(data) => decrypt_struct(data.clone(), key, &[]).ok(),
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

/// Cleartext envelope around the encrypted store. `requires` is read before
/// anything is decrypted and is bound to the ciphertext as AES-GCM associated
/// data, so stripping a name makes decryption fail. No other fields: any future
/// cleartext field must be gated by a name in `requires`.
#[derive(Serialize, Deserialize)]
pub(super) struct WalletFile {
    requires: Vec<String>,
    encrypted: EncryptedData,
}

/// Feature names a stored record needs its reader to understand. Each impl
/// destructures every field and matches every variant, so a new one forces a
/// decision: a build that can't serve a name refuses the whole wallet.
pub(crate) trait Requires {
    /// Adds the names this record needs to `out`.
    fn requires(&self, out: &mut BTreeSet<&'static str>);
}

/// Keeps each cache entry this build can decode and drops the rest: a UTXO
/// type it can't spend, or one a dependency bump reshaped. The next sync
/// rebuilds them; until then the balance only reads low.
fn decodable_cache_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<HashMap<OutPoint, (ListUnspentResultEntry, UTXOSpendInfo)>, D::Error> {
    let raw = BTreeMap::<Value, Value>::deserialize(deserializer)?;
    Ok(raw
        .into_iter()
        .filter_map(|(outpoint, entry)| Some((from_value(outpoint).ok()?, from_value(entry).ok()?)))
        .collect())
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

    /// Maps transaction outpoints to their associated UTXO and spend information.
    #[serde(default, deserialize_with = "decodable_cache_entries")]
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

    /// Fields a newer build wrote that this one doesn't know, written back
    /// unchanged. Never rebuild the store through a conversion that drops them.
    #[serde(flatten)]
    pub(crate) extra: BTreeMap<String, Value>,
}

impl Requires for WalletStore {
    fn requires(&self, out: &mut BTreeSet<&'static str>) {
        let Self {
            file_name: _,
            network: _,
            master_key: _,
            external_index: _,
            internal_index: _,
            offer_maxsize: _,
            incoming_swapcoins,
            outgoing_swapcoins,
            watchonly_swapcoins,
            prevout_to_contract_map: _,
            swept_incoming_swapcoins: _,
            fidelity_bond,
            last_synced_height: _,
            wallet_birthday: _,
            // An entry this build can't read is dropped on load, never refused.
            utxo_cache: _,
            swap_locks,
            ln_pending_swaps,
            ln_maker_swaps,
            // Kept for a newer build; this one needs nothing from them.
            extra: _,
        } = self;
        incoming_swapcoins.values().for_each(|c| c.requires(out));
        outgoing_swapcoins.values().for_each(|c| c.requires(out));
        watchonly_swapcoins
            .values()
            .flatten()
            .for_each(|c| c.requires(out));
        fidelity_bond.iter().for_each(|b| b.requires(out));
        swap_locks.values().for_each(|r| r.requires(out));
        ln_pending_swaps.values().for_each(|s| s.requires(out));
        ln_maker_swaps.values().for_each(|s| s.requires(out));
    }
}

impl Requires for SwapReservation {
    fn requires(&self, _out: &mut BTreeSet<&'static str>) {
        let Self {
            outpoints: _,
            reserved_at: _,
        } = self;
    }
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// Block height when the funding was first seen (refund timing).
    pub funding_height: Option<u32>,
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

impl Requires for LnMakerSwapRecord {
    fn requires(&self, out: &mut BTreeSet<&'static str>) {
        let Self {
            direction,
            phase,
            payment_hash: _,
            amount: _,
            fee: _,
            locktime: _,
            min_confirmations: _,
            redeemscript: _,
            privkey: _,
            invoice: _,
            preimage: _,
            refund_txid: _,
            accepted_height: _,
            payout_script: _,
            funding_outpoint: _,
            funding_value: _,
            funding_height: _,
        } = self;
        out.insert(match direction {
            LnMakerDirection::SwapIn => "ln-swap-in",
            LnMakerDirection::SwapOut => "ln-swap-out",
        });
        match phase {
            LnMakerPhase::InAccepted
            | LnMakerPhase::InPaid
            | LnMakerPhase::InSwept
            | LnMakerPhase::OutAccepted
            | LnMakerPhase::OutFunded => {}
        }
    }
}

impl Requires for LnPendingSwap {
    fn requires(&self, out: &mut BTreeSet<&'static str>) {
        let Self {
            is_swap_in,
            preimage: _,
            redeemscript: _,
            locktime: _,
            privkey: _,
            outpoint: _,
            value: _,
        } = self;
        out.insert(if *is_swap_in {
            "ln-swap-in"
        } else {
            "ln-swap-out"
        });
    }
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
            swap_locks: HashMap::new(),
            ln_pending_swaps: HashMap::new(),
            ln_maker_swaps: HashMap::new(),
            extra: BTreeMap::new(),
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

        let mut names: BTreeSet<&'static str> = FORMAT_NAMES.iter().copied().collect();
        self.requires(&mut names);
        let requires: Vec<String> = names.into_iter().map(String::from).collect();
        let encrypted = encrypt_struct(self, store_enc_material, &requires_aad(&requires))
            .map_err(|e| WalletError::General(format!("wallet store encryption failed: {e:?}")))?;

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
        let mut writer = BufWriter::new(&mut tmp);
        serde_cbor::to_writer(
            &mut writer,
            &WalletFile {
                requires,
                encrypted,
            },
        )?;
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

    /// Reads and decrypts the wallet at `path`, returning the store and the
    /// key material derived from `password`.
    ///
    /// A name in `requires` this build can't serve gives
    /// [`WalletError::NeedsUpgrade`] before anything is decrypted. A bare
    /// v0.2.3 file gives [`WalletError::OldFormat`]. No password gives
    /// [`SecurityError::PasswordRequired`]. The file is never written here.
    pub(crate) fn read_from_disk(
        path: &Path,
        password: Option<String>,
    ) -> Result<(Self, KeyMaterial), WalletError> {
        let content = std::fs::read(path)?;
        let file = match deserialize_from_cbor::<WalletFile>(&content) {
            Ok(file) => file,
            Err(_) if deserialize_from_cbor::<EncryptedData>(&content).is_ok() => {
                return Err(WalletError::OldFormat)
            }
            Err(e) => return Err(e.into()),
        };
        check_requires(&file.requires, &supported()).map_err(WalletError::NeedsUpgrade)?;
        let password = password
            .filter(|p| !p.is_empty())
            .ok_or(SecurityError::PasswordRequired)?;
        Ok(decrypt_with_password(
            file.encrypted,
            password,
            &requires_aad(&file.requires),
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::SecurityError;
    use bip39::rand::{thread_rng, Rng};
    use bitcoin::{hashes::Hash, Amount, Txid};
    use bitcoind::tempfile::tempdir;
    use serde_cbor::value::to_value;

    const PASSWORD: &str = "wallet password";

    fn stored_wallet(dir: &Path) -> (std::path::PathBuf, WalletStore, KeyMaterial) {
        let path = dir.join("wallet.cbor");
        let xpriv = Xpriv::new_master(Network::Regtest, &thread_rng().gen::<[u8; 16]>()).unwrap();
        let material = KeyMaterial::new_from_password(Some(PASSWORD.to_string())).unwrap();
        let store =
            WalletStore::init("w".into(), &path, Network::Regtest, xpriv, None, &material).unwrap();
        (path, store, material)
    }

    fn cache_entry(vout: u32) -> (OutPoint, (ListUnspentResultEntry, UTXOSpendInfo)) {
        let outpoint = OutPoint::new(Txid::all_zeros(), vout);
        let entry = ListUnspentResultEntry {
            txid: outpoint.txid,
            vout,
            address: None,
            label: None,
            redeem_script: None,
            witness_script: None,
            script_pub_key: ScriptBuf::new(),
            amount: Amount::from_sat(1_000),
            confirmations: 1,
            spendable: true,
            solvable: true,
            descriptor: None,
            safe: true,
        };
        let info = UTXOSpendInfo::SeedCoin {
            path: "m/84'/1'/0'/0/0".to_string(),
            input_value: Amount::from_sat(1_000),
            address_type: AddressType::P2WPKH,
        };
        (outpoint, (entry, info))
    }

    #[test]
    fn requires_aad_is_sorted_unique_names_joined_by_newline() {
        assert_eq!(requires_aad::<&str>(&[]), b"");
        assert_eq!(requires_aad(&["taproot"]), b"taproot");
        assert_eq!(requires_aad(&["b", "a-v2", "b"]), b"a-v2\nb");
    }

    #[test]
    fn unknown_fields_survive_and_unreadable_cache_entries_drop() {
        let dir = tempdir().unwrap();
        let (_, mut store, _) = stored_wallet(dir.path());
        let (outpoint, entry) = cache_entry(0);
        store.utxo_cache.insert(outpoint, entry);
        store
            .prevout_to_contract_map
            .insert(outpoint, ScriptBuf::new());

        let Value::Map(mut fields) = to_value(&store).unwrap() else {
            panic!("a store encodes as a map");
        };
        fields.insert(Value::Text("future_field".into()), Value::Integer(7));
        let Some(Value::Map(cache)) = fields.get_mut(&Value::Text("utxo_cache".into())) else {
            panic!("the cache encodes as a map");
        };
        let future_entry = Value::Array(vec![Value::Null, Value::Text("FutureSpendInfo".into())]);
        cache.insert(to_value(cache_entry(1).0).unwrap(), future_entry);

        let bytes = serde_cbor::to_vec(&Value::Map(fields)).unwrap();
        let read: WalletStore = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(read.utxo_cache, store.utxo_cache);
        assert_eq!(read.prevout_to_contract_map, store.prevout_to_contract_map);
        assert_eq!(read.extra.get("future_field"), Some(&Value::Integer(7)));

        let rewritten: WalletStore =
            serde_cbor::from_slice(&serde_cbor::to_vec(&read).unwrap()).unwrap();
        assert_eq!(rewritten, read);
    }

    #[test]
    fn unserved_names_refuse_untouched_and_stripped_names_fail_decryption() {
        let dir = tempdir().unwrap();
        let (path, store, material) = stored_wallet(dir.path());

        let write = |requires: &[&str], aad: &[&str]| {
            let file = WalletFile {
                requires: requires.iter().map(|n| n.to_string()).collect(),
                encrypted: encrypt_struct(&store, &material, &requires_aad(aad)).unwrap(),
            };
            let bytes = serde_cbor::to_vec(&file).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            bytes
        };

        let bytes = write(&["future-v1"], &["future-v1"]);
        let error = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap_err();
        assert!(matches!(error, WalletError::NeedsUpgrade(names) if names == ["future-v1"]));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);

        write(&[], &["legacy"]);
        let error = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap_err();
        assert!(matches!(
            error,
            WalletError::Security(SecurityError::Decryption)
        ));

        let bare = encrypt_struct(&store, &material, &[]).unwrap();
        std::fs::write(&path, serde_cbor::to_vec(&bare).unwrap()).unwrap();
        let error = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap_err();
        assert!(matches!(error, WalletError::OldFormat));
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
            &encryption_material,
        )
        .unwrap();

        original_wallet_store
            .write_to_disk(&file_path, &encryption_material)
            .unwrap();

        let (read_wallet, _material) =
            WalletStore::read_from_disk(&file_path, Some(password)).unwrap();
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

        let (read_wallet, _read_encryption_material) =
            WalletStore::read_from_disk(&file_path, Some(password)).unwrap();
        assert_eq!(original_wallet_store, read_wallet);
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
