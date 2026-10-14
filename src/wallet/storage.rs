//! The Wallet Storage Interface.
//!
//! Wallet data is written to disk as AES-256-GCM-encrypted CBOR; there is no
//! cleartext-on-disk wallet format by design (legacy cleartext files are
//! still readable, for one-time migration by `Wallet::load`). The master key
//! is additionally sealed individually, see [`MasterKey`].

use crate::{
    protocol::features::{check_requires, supported},
    security::{
        decrypt_struct, decrypt_with_password, encrypt_struct, encrypt_struct_with_aad,
        requires_aad, EncryptedData, KeyMaterial, SecurityError, FORMAT_NAMES,
    },
    utill::deserialize_from_cbor,
    wallet::UTXOSpendInfo,
};

use super::{error::WalletError, fidelity::FidelityBond, report::SwapReportFile};

use bitcoin::{bip32::Xpriv, Network, OutPoint, ScriptBuf};
use serde::{Deserialize, Deserializer, Serialize};
use serde_cbor::{value::from_value, Value};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fs::File,
    io::{BufWriter, ErrorKind, Write},
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

    /// Swap reports by kind, as raw values so a report this build can't read
    /// survives a save. Typed views are decoded on read.
    #[serde(default)]
    pub(crate) reports: BTreeMap<String, Vec<Value>>,

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
            // Only informational; an older build that drops one loses no funds.
            reports: _,
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
    /// Refund timing. Swap-in: the block that confirmed the funding, where the
    /// taker's CSV refund window starts. Swap-out: the chain tip when the
    /// maker broadcast its funding.
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
            reports: BTreeMap::new(),
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
        let encrypted = encrypt_struct_with_aad(self, store_enc_material, &requires_aad(&requires))
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
    /// Unsupported requirements refuse before decryption. A closed legacy
    /// wallet is archived and upgraded before returning; an open one is untouched.
    pub(crate) fn read_from_disk(
        path: &Path,
        password: Option<String>,
    ) -> Result<(Self, KeyMaterial), WalletError> {
        let content = std::fs::read(path)?;
        if let Ok(file) = deserialize_from_cbor::<WalletFile>(&content) {
            check_requires(&file.requires, &supported()).map_err(WalletError::NeedsUpgrade)?;
            let password = password
                .filter(|p| !p.is_empty())
                .ok_or(SecurityError::PasswordRequired)?;
            return Ok(decrypt_with_password(
                file.encrypted,
                password,
                &requires_aad(&file.requires),
            )?);
        }
        let encrypted = deserialize_from_cbor::<EncryptedData>(&content);
        let plaintext = if encrypted.is_err() {
            Some(deserialize_from_cbor::<Self>(&content)?)
        } else {
            None
        };
        let password = password
            .filter(|p| !p.is_empty())
            .ok_or(SecurityError::PasswordRequired)?;
        let (mut store, material) = if let Some(store) = plaintext {
            (
                store,
                KeyMaterial::new_from_password(Some(password))
                    .ok_or(SecurityError::PasswordRequired)?,
            )
        } else {
            decrypt_with_password(encrypted?, password, &[])?
        };
        let refuse = |reason: String| {
            WalletError::General(format!(
            "Cannot upgrade {}: {reason}. Stop every v0.2.3 process using this data directory; an old process can overwrite new swap keys and lose funds. Start v0.2.3 once and finish all swaps before retrying.",
            path.display()
        ))
        };
        if !store.incoming_swapcoins.is_empty()
            || !store.outgoing_swapcoins.is_empty()
            || store
                .watchonly_swapcoins
                .values()
                .any(|coins| !coins.is_empty())
            || !store.swap_locks.is_empty()
            || !store.ln_pending_swaps.is_empty()
            || !store.ln_maker_swaps.is_empty()
        {
            return Err(refuse("the wallet has open swaps".into()));
        }
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let data_dir = if parent.file_name().is_some_and(|name| name == "wallets") {
            parent.parent().unwrap_or(parent)
        } else {
            parent
        };
        for (name, maker) in [
            ("maker_swap_tracker.cbor", true),
            ("swap_tracker.cbor", false),
        ] {
            let tracker = data_dir.join(name);
            match std::fs::read(&tracker) {
                Ok(bytes) if legacy_tracker_is_open(&bytes, maker) => {
                    return Err(refuse(format!(
                        "{} is unreadable or incomplete",
                        tracker.display()
                    )));
                }
                Err(e) if e.kind() != ErrorKind::NotFound => {
                    return Err(refuse(format!("cannot read {}: {e}", tracker.display())));
                }
                _ => {}
            }
        }
        let report_path = parent.join(format!(
            "{}_swap_report.json",
            path.file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| refuse("the wallet filename is invalid".into()))?
        ));
        let report_bytes = match std::fs::read(&report_path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == ErrorKind::NotFound => None,
            Err(e) => {
                return Err(refuse(format!(
                    "cannot read {}: {e}",
                    report_path.display()
                )))
            }
        };
        if let Some(bytes) = &report_bytes {
            let report: SwapReportFile = serde_json::from_slice(bytes)
                .map_err(|e| refuse(format!("{} is unreadable: {e}", report_path.display())))?;
            for (kind, entries) in report.into_values()? {
                store
                    .reports
                    .entry(kind.into())
                    .or_default()
                    .extend(entries);
            }
        }
        store.master_key.seal(&material)?;
        log::warn!("Upgrading {}. Every v0.2.3 process must be stopped: an old process can overwrite new swap keys and lose funds.", path.display());
        archive_legacy_file(path, &content)?;
        if let Some(bytes) = &report_bytes {
            archive_legacy_file(&report_path, bytes)?;
        }
        // Both archives must survive a crash before the live wallet is replaced.
        // Windows cannot open a directory as a file, so the sync is Unix only.
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        store.write_to_disk(path, &material)?;
        // The entries are committed now, and a later load never imports the
        // file again, so a failed delete only leaves a stale copy behind.
        if report_bytes.is_some() {
            if let Err(e) = std::fs::remove_file(&report_path) {
                log::warn!("Could not delete {}: {e}", report_path.display());
            }
        }
        log::warn!("Upgraded {}. After every wallet in this data directory is upgraded, manually delete maker_swap_tracker.cbor and swap_tracker.cbor. Keep the private .v023 archives for rollback.", path.display());
        Ok((store, material))
    }
}

fn legacy_tracker_is_open(bytes: &[u8], maker: bool) -> bool {
    let Ok(Value::Map(fields)) = serde_cbor::from_slice::<Value>(bytes) else {
        return true;
    };
    let Some(Value::Map(swaps)) = fields.get(&Value::Text("swaps".into())) else {
        return true;
    };
    swaps.values().any(|record| {
        let Value::Map(record) = record else {
            return true;
        };
        let phase = record.get(&Value::Text("phase".into()));
        let Some(Value::Map(recovery)) = record.get(&Value::Text("recovery".into())) else {
            return true;
        };
        let Some(Value::Text(recovery_phase)) = recovery.get(&Value::Text("phase".into())) else {
            return true;
        };
        let recognized_recovery = if maker {
            matches!(
                recovery_phase.as_str(),
                "NotStarted"
                    | "Monitoring"
                    | "HashlockRecovered"
                    | "TimelockWaiting"
                    | "TimelockRecovered"
                    | "CleanedUp"
            )
        } else {
            matches!(
                recovery_phase.as_str(),
                "NotStarted"
                    | "PreimageStamped"
                    | "SwapcoinsPersisted"
                    | "IncomingRecovered"
                    | "OutgoingRecovered"
                    | "CleanedUp"
            )
        };
        if !recognized_recovery {
            return true;
        }
        let cleaned = recovery_phase == "CleanedUp";
        if maker {
            !matches!(phase, Some(Value::Text(p)) if p == "Completed" || p == "Recovered")
                || !cleaned
        } else {
            !matches!(phase, Some(Value::Text(p)) if p == "Completed" || (p == "Failed" && cleaned))
        }
    })
}

fn archive_legacy_file(path: &Path, bytes: &[u8]) -> Result<(), WalletError> {
    let mut name = path.as_os_str().to_os_string();
    name.push(".v023");
    let archive = Path::new(&name);
    match std::fs::read(archive) {
        Ok(existing) if existing == bytes => {
            #[cfg(unix)]
            std::fs::set_permissions(archive, std::fs::Permissions::from_mode(0o600))?;
            File::open(archive)?.sync_all()?;
            return Ok(());
        }
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
    temporary
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(archive).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
pub(crate) mod compat_support {
    use super::*;
    use crate::{
        compat_fixtures::{check, write},
        protocol::ProtocolVersion,
        wallet::{compat_reports, deniability::DeniabilityProof, swapcoin::PaymentTarget},
    };
    use bitcoin::{
        absolute::LockTime,
        hashes::{sha256, Hash},
        secp256k1::{Message, Scalar, Secp256k1, SecretKey},
        Amount, CompressedPublicKey, PublicKey, Txid,
    };
    use serde_cbor::value::to_value;

    pub(crate) fn compat_store() -> WalletStore {
        let dir = tempfile::tempdir().unwrap();
        let key = KeyMaterial::new_from_password(Some("fixture-password".into())).unwrap();
        let mut store = WalletStore::init(
            "fixture.wallet".into(),
            &dir.path().join("fixture.wallet"),
            Network::Regtest,
            Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap(),
            Some(101),
            &key,
        )
        .unwrap();
        let (old, _) = decrypt_with_password::<WalletStore>(
            serde_cbor::from_slice(include_bytes!(
                "../../tests/fixtures/compat/v0.2.3/open.wallet"
            ))
            .unwrap(),
            "compat-v023".into(),
            &[],
        )
        .unwrap();
        let incoming = old.incoming_swapcoins.into_values().next().unwrap();
        let tx = incoming.contract_tx.clone();
        let script = incoming.contract_redeemscript.clone().unwrap();
        let mine = incoming.my_privkey.unwrap();
        let other = incoming.other_pubkey.unwrap();
        let secp = Secp256k1::new();
        let pubkey = PublicKey::new(mine.public_key(&secp));
        let point = OutPoint::new(tx.compute_txid(), 0);
        let signature = bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&Message::from_digest([7; 32]), &mine),
        );
        store.external_index = 7;
        store.internal_index = 11;
        store.offer_maxsize = 123_456;
        store.wallet_birthday = Some(101);
        store.last_synced_height = Some(202);
        store.prevout_to_contract_map.insert(point, script.clone());
        store.swept_incoming_swapcoins.insert(script.clone());
        store.fidelity_bond.push(FidelityBond {
            outpoint: point,
            amount: Amount::from_sat(100_000),
            lock_time: LockTime::from_height(900_000).unwrap(),
            pubkey,
            conf_height: Some(800_000),
            is_spent: true,
            bond_index: 7,
            tx: Some(tx.clone()),
            extra: BTreeMap::new(),
        });
        store.swap_locks.insert(
            "fixture-swap".into(),
            SwapReservation {
                outpoints: HashSet::from([point]),
                reserved_at: 123,
            },
        );
        store.reports = IntoIterator::into_iter(compat_reports().into_values().unwrap())
            .map(|(name, values)| (name.into(), values))
            .collect();
        for protocol in [ProtocolVersion::Legacy, ProtocolVersion::Taproot] {
            let name = format!("{protocol:?}");
            let mut incoming = incoming.clone();
            incoming.protocol = protocol;
            incoming.other_privkey = Some(SecretKey::from_slice(&[2; 32]).unwrap());
            incoming.contract_txid = Some(tx.compute_txid());
            incoming.hash_preimage = Some([4; 32]);
            incoming.swap_id = Some(name.clone());
            incoming.hashlock_script = Some(script.clone());
            incoming.timelock_script = Some(script.clone());
            incoming.others_contract_sig = Some(signature);
            incoming.tap_tweak = Some(Scalar::ONE);
            incoming.internal_key = Some(pubkey.inner.x_only_public_key().0);
            incoming.spending_tx = Some(tx.clone());
            incoming.payment_target = Some(PaymentTarget {
                script_pubkey: script.clone(),
                amount: Amount::from_sat(90_000),
            });
            incoming.negotiated_feerate = 3;
            if protocol == ProtocolVersion::Taproot {
                let proof = DeniabilityProof::from_incoming_swapcoin(
                    &incoming,
                    super::super::SwapRole::Taker,
                    Some(point),
                )
                .unwrap();
                store
                    .reports
                    .get_mut("deniability_proofs")
                    .unwrap()
                    .push(to_value(proof).unwrap());
            }
            let mut outgoing = OutgoingSwapCoin::new_legacy(
                mine,
                other,
                tx.clone(),
                script.clone(),
                mine,
                Amount::from_sat(100_000),
                3,
            );
            outgoing.protocol = protocol;
            outgoing.other_privkey = incoming.other_privkey;
            outgoing.funding_tx = Some(tx.clone());
            outgoing.hash_preimage = Some([4; 32]);
            outgoing.swap_id = Some(name.clone());
            outgoing.hashlock_script = Some(script.clone());
            outgoing.timelock_script = Some(script.clone());
            outgoing.others_contract_sig = Some(signature);
            outgoing.tap_tweak = Some(Scalar::ONE);
            outgoing.internal_key = incoming.internal_key;
            outgoing.recovery_address = Some(
                bitcoin::Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Regtest)
                    .as_unchecked()
                    .clone(),
            );
            outgoing.committed = true;
            outgoing.incoming_claimed = true;
            let mut watchonly = WatchOnlySwapCoin::new_legacy(
                pubkey,
                other,
                tx.clone(),
                script.clone(),
                Amount::from_sat(100_000),
            );
            watchonly.protocol = protocol;
            watchonly.hashlock_script = Some(script.clone());
            watchonly.timelock_script = Some(script.clone());
            store.incoming_swapcoins.insert(name.clone(), incoming);
            store.outgoing_swapcoins.insert(name.clone(), outgoing);
            store.watchonly_swapcoins.insert(name, vec![watchonly]);
        }
        for (index, info) in [
            UTXOSpendInfo::SeedCoin {
                path: "m/84'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2WPKH,
            },
            UTXOSpendInfo::SeedCoin {
                path: "m/86'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2TR,
            },
            UTXOSpendInfo::IncomingSwapCoin {
                multisig_redeemscript: script.clone(),
            },
            UTXOSpendInfo::OutgoingSwapCoin {
                multisig_redeemscript: script.clone(),
            },
            UTXOSpendInfo::TimelockContract {
                swapcoin_multisig_redeemscript: script.clone(),
                input_value: Amount::from_sat(100_000),
            },
            UTXOSpendInfo::HashlockContract {
                swapcoin_multisig_redeemscript: script.clone(),
                input_value: Amount::from_sat(100_000),
            },
            UTXOSpendInfo::FidelityBondCoin {
                index: 7,
                input_value: Amount::from_sat(100_000),
            },
            UTXOSpendInfo::SweptCoin {
                path: "m/84'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2WPKH,
            },
            UTXOSpendInfo::SweptCoin {
                path: "m/86'/1'/0'/0/7".into(),
                input_value: Amount::from_sat(100_000),
                address_type: AddressType::P2TR,
            },
        ]
        .iter()
        .enumerate()
        {
            let point = OutPoint::new(Txid::from_byte_array([5; 32]), index as u32);
            let entry = ListUnspentResultEntry {
                txid: point.txid,
                vout: point.vout,
                address: Some(
                    bitcoin::Address::p2wpkh(&CompressedPublicKey(pubkey.inner), Network::Regtest)
                        .as_unchecked()
                        .clone(),
                ),
                label: Some("fixture".into()),
                redeem_script: Some(script.clone()),
                witness_script: Some(script.clone()),
                script_pub_key: script.clone(),
                amount: Amount::from_sat(100_000),
                confirmations: 7,
                spendable: true,
                solvable: true,
                descriptor: Some("fixture-descriptor".into()),
                safe: true,
            };
            store.utxo_cache.insert(point, (entry, info.clone()));
        }
        for is_swap_in in [true, false] {
            store.ln_pending_swaps.insert(
                format!("pending-{is_swap_in}"),
                LnPendingSwap {
                    is_swap_in,
                    preimage: Some([4; 32]),
                    redeemscript: script.clone(),
                    locktime: 20,
                    privkey: mine,
                    outpoint: Some(point),
                    value: Some(Amount::from_sat(100_000)),
                },
            );
        }
        for (direction, phase) in [
            (LnMakerDirection::SwapIn, LnMakerPhase::InAccepted),
            (LnMakerDirection::SwapIn, LnMakerPhase::InPaid),
            (LnMakerDirection::SwapIn, LnMakerPhase::InSwept),
            (LnMakerDirection::SwapOut, LnMakerPhase::OutAccepted),
            (LnMakerDirection::SwapOut, LnMakerPhase::OutFunded),
        ] {
            store.ln_maker_swaps.insert(
                format!("{phase:?}"),
                LnMakerSwapRecord {
                    direction,
                    phase,
                    payment_hash: sha256::Hash::hash(&[4; 32]),
                    amount: Amount::from_sat(100_000),
                    fee: Amount::from_sat(1_000),
                    locktime: 20,
                    min_confirmations: 3,
                    redeemscript: script.clone(),
                    privkey: mine,
                    invoice: "fixture-invoice".into(),
                    preimage: Some([4; 32]),
                    refund_txid: Some(point.txid),
                    accepted_height: Some(123),
                    payout_script: Some(script.clone()),
                    funding_outpoint: Some(point),
                    funding_value: Some(Amount::from_sat(101_000)),
                    funding_height: Some(125),
                },
            );
        }
        store
    }

    pub(crate) fn compat_assert_empty_extra(store: &WalletStore) {
        assert!(
            store.extra.is_empty(),
            "a stored wallet field was renamed or removed: {:?}",
            store.extra.keys()
        );
        for bond in &store.fidelity_bond {
            assert!(
                bond.extra.is_empty(),
                "a stored bond field was renamed or removed: {:?}",
                bond.extra.keys()
            );
        }
    }

    pub(crate) fn generate_storage(release: &Path) {
        let store = compat_store();
        write(release, "wallet-store", &store);
        for (name, coin) in &store.incoming_swapcoins {
            write(release, &format!("coin-incoming-{name}"), coin);
        }
        for (name, coin) in &store.outgoing_swapcoins {
            write(release, &format!("coin-outgoing-{name}"), coin);
        }
        for (name, coins) in &store.watchonly_swapcoins {
            write(release, &format!("coin-watchonly-{name}"), &coins[0]);
        }
        for (name, swap) in &store.ln_maker_swaps {
            write(release, &format!("storage-ln-maker-{name}"), swap);
        }
        for (name, swap) in &store.ln_pending_swaps {
            write(release, &format!("storage-ln-{name}"), swap);
        }
        for (point, cache) in &store.utxo_cache {
            write(release, &format!("storage-cache-{}", point.vout), cache);
        }
        write(
            release,
            "storage-reservation",
            &store.swap_locks["fixture-swap"],
        );
        write(release, "bond-fidelity", &store.fidelity_bond[0]);
        generate_envelope(release, &store);
    }

    #[test]
    fn compat_fixtures_wallet_index_rename_cannot_hide_in_extra() {
        let original = to_value(compat_store()).unwrap();
        let Value::Map(mut fields) = original.clone() else {
            panic!()
        };
        let index = fields
            .remove(&Value::Text("internal_index".into()))
            .unwrap();
        fields.insert(Value::Text("renamed_index".into()), index);
        let renamed: WalletStore =
            serde_cbor::from_slice(&serde_cbor::to_vec(&Value::Map(fields)).unwrap()).unwrap();
        assert!(std::panic::catch_unwind(|| compat_assert_empty_extra(&renamed)).is_err());
        assert!(
            std::panic::catch_unwind(|| crate::compat_fixtures::assert_subset(
                &original,
                &to_value(&renamed).unwrap()
            ))
            .is_err()
        );
    }

    #[test]
    fn compat_fixtures_nested_bond_rename_cannot_hide_in_extra() {
        let Value::Map(mut fields) = to_value(compat_store()).unwrap() else {
            panic!()
        };
        let Value::Array(bonds) = fields
            .get_mut(&Value::Text("fidelity_bond".into()))
            .unwrap()
        else {
            panic!()
        };
        let Value::Map(bond) = &mut bonds[0] else {
            panic!()
        };
        let index = bond.remove(&Value::Text("bond_index".into())).unwrap();
        bond.insert(Value::Text("renamed_bond_index".into()), index);
        // A flattened old key must never make a renamed required field seem compatible.
        assert!(serde_cbor::from_slice::<WalletStore>(
            &serde_cbor::to_vec(&Value::Map(fields)).unwrap()
        )
        .is_err());
    }

    pub(crate) fn generate_envelope(release: &Path, store: &WalletStore) {
        let MasterKey::Sealed(sealed) = &store.master_key else {
            panic!()
        };
        let (mut master, key) =
            decrypt_with_password::<Xpriv>(sealed.clone(), "fixture-password".into(), &[]).unwrap();
        master.private_key.non_secure_erase();
        let mut names = BTreeSet::new();
        store.requires(&mut names);
        let requires: Vec<_> = names.into_iter().map(String::from).collect();
        let encrypted = encrypt_struct_with_aad(store, &key, &requires_aad(&requires)).unwrap();
        write(
            release,
            "wallet-file",
            &WalletFile {
                requires,
                encrypted,
            },
        );
    }

    pub(crate) fn check_envelope(release: &Path) {
        let file: WalletFile = check(release, "wallet-file");
        let (store, key) = decrypt_with_password::<WalletStore>(
            file.encrypted,
            "fixture-password".into(),
            &requires_aad(&file.requires),
        )
        .unwrap();
        compat_assert_empty_extra(&store);
        assert_eq!(
            store.master_key.plaintext_with(&key),
            Some(Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap())
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        security::SecurityError,
        wallet::{
            deniability::{verify_proof_for_test, DeniabilityProof},
            report::{RecoveryReport, SwapRole},
            Wallet,
        },
    };
    use bip39::rand::{thread_rng, Rng};
    use bitcoin::{
        absolute::LockTime,
        hashes::{sha256, Hash},
        secp256k1::{Secp256k1, SecretKey},
        Amount, PublicKey, Txid,
    };
    use bitcoind::tempfile::tempdir;
    use serde_cbor::value::to_value;
    #[cfg(unix)]
    use std::os::unix::fs::MetadataExt;

    const PASSWORD: &str = "wallet password";
    const V023_PASSWORD: &str = "compat-v023";
    const V023_CLOSED: &[u8] = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet");
    const V023_NEWER: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/closed-newer.wallet");
    const V023_OPEN: &[u8] = include_bytes!("../../tests/fixtures/compat/v0.2.3/open.wallet");
    const V023_REPORT: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/closed_swap_report.json");
    const V023_SIBLING: &[u8] = include_bytes!("../../tests/fixtures/compat/v0.2.3/sibling.wallet");
    const V023_MAKER_DONE: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/maker-completed.cbor");
    const V023_MAKER_OPEN: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/maker-incomplete.cbor");
    const V023_TAKER_DONE: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/taker-completed.cbor");
    const V023_TAKER_OPEN: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/taker-incomplete.cbor");
    const V023_BAD_REPORT: &[u8] =
        include_bytes!("../../tests/fixtures/compat/v0.2.3/bad_swap_report.json");

    fn install_v023_wallet(dir: &Path) -> std::path::PathBuf {
        let wallets = dir.join("wallets");
        std::fs::create_dir(&wallets).unwrap();
        let path = wallets.join("closed.wallet");
        std::fs::write(&path, V023_CLOSED).unwrap();
        std::fs::write(wallets.join("closed_swap_report.json"), V023_REPORT).unwrap();
        path
    }

    #[test]
    fn compat_v023_upgrade_preserves_verified_proofs_and_manual_tracker_files() {
        let dir = tempdir().unwrap();
        let path = install_v023_wallet(dir.path());
        let wallets = path.parent().unwrap();
        let maker = dir.path().join("maker_swap_tracker.cbor");
        let taker = dir.path().join("swap_tracker.cbor");
        std::fs::write(&maker, V023_MAKER_DONE).unwrap();
        std::fs::write(&taker, V023_TAKER_DONE).unwrap();
        let sibling = wallets.join("sibling.wallet");
        let sibling_report = wallets.join("sibling_swap_report.json");
        std::fs::write(&sibling, V023_SIBLING).unwrap();
        std::fs::write(&sibling_report, V023_BAD_REPORT).unwrap();
        let expected: SwapReportFile = serde_json::from_slice(V023_REPORT).unwrap();
        let chain_spk: ScriptBuf = serde_cbor::from_slice(include_bytes!(
            "../../tests/fixtures/compat/v0.2.3/proof-chain-script.cbor"
        ))
        .unwrap();
        verify_proof_for_test(&expected.deniability_proofs[0], &chain_spk).unwrap();
        let (store, material) =
            WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).unwrap();
        assert_eq!(store.external_index, 7);
        assert_eq!(store.internal_index, 9);
        assert_eq!(store.wallet_birthday, Some(100));
        assert_eq!(store.last_synced_height, Some(200));
        assert_eq!(
            store.master_key.plaintext_with(&material),
            Some(Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap())
        );
        let proof: DeniabilityProof =
            from_value(store.reports["deniability_proofs"][0].clone()).unwrap();
        assert_eq!(proof, expected.deniability_proofs[0]);
        verify_proof_for_test(&proof, &chain_spk).unwrap();
        assert!(verify_proof_for_test(&proof, &ScriptBuf::new()).is_err());
        for (archive, original) in [
            (wallets.join("closed.wallet.v023"), V023_CLOSED),
            (wallets.join("closed_swap_report.json.v023"), V023_REPORT),
        ] {
            assert_eq!(std::fs::read(&archive).unwrap(), original);
            #[cfg(unix)]
            assert_eq!(
                std::fs::metadata(archive).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert!(!wallets.join("closed_swap_report.json").exists());
        assert_eq!(std::fs::read(&sibling).unwrap(), V023_SIBLING);
        assert_eq!(std::fs::read(&sibling_report).unwrap(), V023_BAD_REPORT);
        assert_eq!(std::fs::read(&maker).unwrap(), V023_MAKER_DONE);
        assert_eq!(std::fs::read(&taker).unwrap(), V023_TAKER_DONE);
        let committed = std::fs::read(&path).unwrap();
        let (again, _) = WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).unwrap();
        assert_eq!(again, store);
        assert_eq!(std::fs::read(&path).unwrap(), committed);
    }

    #[test]
    fn compat_v023_open_coins_trackers_and_bad_reports_refuse_untouched() {
        for failure in [
            "incoming coin",
            "maker tracker",
            "taker tracker",
            "bad tracker",
            "bad report",
            "future proof",
        ] {
            let dir = tempdir().unwrap();
            let path = install_v023_wallet(dir.path());
            let report_path = path.parent().unwrap().join("closed_swap_report.json");
            let maker = dir.path().join("maker_swap_tracker.cbor");
            let taker = dir.path().join("swap_tracker.cbor");
            std::fs::write(&maker, V023_MAKER_DONE).unwrap();
            std::fs::write(&taker, V023_TAKER_DONE).unwrap();
            match failure {
                "incoming coin" => std::fs::write(&path, V023_OPEN).unwrap(),
                "maker tracker" => std::fs::write(&maker, V023_MAKER_OPEN).unwrap(),
                "taker tracker" => std::fs::write(&taker, V023_TAKER_OPEN).unwrap(),
                "bad tracker" => std::fs::write(&maker, b"broken").unwrap(),
                "bad report" => std::fs::write(&report_path, V023_BAD_REPORT).unwrap(),
                "future proof" => {
                    let mut report: serde_json::Value =
                        serde_json::from_slice(V023_REPORT).unwrap();
                    report["deniability_proofs"][0]["proof"] =
                        serde_json::json!({"FutureProof": [1, 2, 3]});
                    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
                }
                _ => unreachable!(),
            }
            let snapshots: Vec<_> = [&path, &report_path, &maker, &taker]
                .iter()
                .map(|&file| (file, std::fs::read(file).unwrap()))
                .collect();
            let error = WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into()))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("Stop every v0.2.3 process"),
                "{}: {}",
                failure,
                error
            );
            assert!(error.contains("lose funds"));
            assert!(error.contains("Start v0.2.3 once"));
            if matches!(failure, "bad report" | "future proof") {
                assert!(error.contains(&report_path.display().to_string()));
            }
            for (file, bytes) in snapshots {
                assert_eq!(std::fs::read(file).unwrap(), bytes, "{}", failure);
            }
            assert_eq!(
                std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                2
            );
        }
    }

    #[test]
    fn compat_v023_archive_failure_retries_with_an_identical_private_archive() {
        let dir = tempdir().unwrap();
        let path = install_v023_wallet(dir.path());
        let parent = path.parent().unwrap();
        let archive = parent.join("closed.wallet.v023");
        let report_archive = parent.join("closed_swap_report.json.v023");
        // Fail the second archive after the first has completed, before commit.
        std::fs::create_dir(&report_archive).unwrap();
        assert!(WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), V023_CLOSED);
        assert_eq!(std::fs::read(&archive).unwrap(), V023_CLOSED);
        assert_eq!(
            std::fs::read(parent.join("closed_swap_report.json")).unwrap(),
            V023_REPORT
        );
        #[cfg(unix)]
        let original_inode = std::fs::metadata(&archive).unwrap().ino();
        #[cfg(unix)]
        std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::remove_dir(&report_archive).unwrap();
        let (store, _) = WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).unwrap();
        assert_eq!(store.reports["deniability_proofs"].len(), 1);
        assert_eq!(std::fs::read(&archive).unwrap(), V023_CLOSED);
        assert_eq!(std::fs::read(&report_archive).unwrap(), V023_REPORT);
        #[cfg(unix)]
        {
            assert_eq!(std::fs::metadata(&archive).unwrap().ino(), original_inode);
            assert_eq!(
                std::fs::metadata(&archive).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn compat_v023_retry_archives_a_changed_live_wallet() {
        let dir = tempdir().unwrap();
        let path = install_v023_wallet(dir.path());
        let parent = path.parent().unwrap();
        let archive = parent.join("closed.wallet.v023");
        let report_archive = parent.join("closed_swap_report.json.v023");
        std::fs::create_dir(&report_archive).unwrap();
        assert!(WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).is_err());
        assert_eq!(std::fs::read(&archive).unwrap(), V023_CLOSED);
        std::fs::write(&path, V023_NEWER).unwrap();
        std::fs::remove_dir(&report_archive).unwrap();
        // A crash's unfinished temporary copy must never be mistaken for an archive.
        let unfinished = parent.join(".tmp-v023-interrupted-copy");
        std::fs::write(&unfinished, &V023_NEWER[..30]).unwrap();
        let (store, _) = WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).unwrap();
        assert_eq!(store.external_index, 11);
        assert_eq!(std::fs::read(&archive).unwrap(), V023_NEWER);
        assert_eq!(std::fs::read(&report_archive).unwrap(), V023_REPORT);
        assert_eq!(std::fs::read(&unfinished).unwrap(), &V023_NEWER[..30]);
    }

    #[test]
    fn compat_v023_password_refusals_preserve_every_input() {
        let dir = tempdir().unwrap();
        let path = install_v023_wallet(dir.path());
        for password in [None, Some(String::new()), Some("wrong-password".into())] {
            let error = WalletStore::read_from_disk(&path, password).unwrap_err();
            assert!(matches!(
                error,
                WalletError::Security(SecurityError::PasswordRequired | SecurityError::Decryption)
            ));
            assert_eq!(std::fs::read(&path).unwrap(), V023_CLOSED);
            assert_eq!(
                std::fs::read(path.parent().unwrap().join("closed_swap_report.json")).unwrap(),
                V023_REPORT
            );
            assert_eq!(
                std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                2
            );
        }
    }

    #[test]
    fn compat_v023_malformed_tracker_predicates_refuse_untouched() {
        let mut accepted = Vec::new();
        // The tag rejects these malformed phase and recovery fields.
        for (name, bytes) in [
            (
                "maker_swap_tracker.cbor",
                include_bytes!("../../tests/fixtures/compat/v0.2.3/maker-malformed.cbor")
                    .as_slice(),
            ),
            (
                "swap_tracker.cbor",
                include_bytes!("../../tests/fixtures/compat/v0.2.3/taker-malformed.cbor")
                    .as_slice(),
            ),
        ] {
            let dir = tempdir().unwrap();
            let path = install_v023_wallet(dir.path());
            let tracker = dir.path().join(name);
            std::fs::write(&tracker, bytes).unwrap();
            if WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).is_ok() {
                accepted.push(name);
                continue;
            }
            assert_eq!(std::fs::read(&path).unwrap(), V023_CLOSED);
            assert_eq!(std::fs::read(&tracker).unwrap(), bytes);
            assert_eq!(
                std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
                2
            );
        }
        assert!(
            accepted.is_empty(),
            "malformed v0.2.3 tracker predicates accepted: {:?}",
            accepted
        );
    }

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
    fn compat_wallet_requirements_precede_password_and_decryption() {
        let dir = tempdir().unwrap();
        let (path, _, material) = stored_wallet(dir.path());
        for name in ["future-v1", "legacy-v1", "ln-swap-in"] {
            let file = WalletFile {
                requires: vec![name.into()],
                encrypted: serde_json::from_value(serde_json::json!({
                    "nonce": material.nonce,
                    "pbkdf2_salt": material.pbkdf2_salt,
                    "encrypted_payload": [0],
                }))
                .unwrap(),
            };
            let bytes = serde_cbor::to_vec(&file).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(Wallet::is_wallet_encrypted(&path).unwrap());
            for password in [None, Some(String::new()), Some("wrong".into())] {
                let error = WalletStore::read_from_disk(&path, password).unwrap_err();
                if name == "ln-swap-in" && cfg!(feature = "lightning") {
                    assert!(!matches!(error, WalletError::NeedsUpgrade(_)));
                } else {
                    assert!(matches!(error, WalletError::NeedsUpgrade(names) if names == [name]));
                }
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
            }
        }
    }

    #[test]
    fn compat_wallet_headers_authenticate_and_bare_files_upgrade() {
        let dir = tempdir().unwrap();
        let (path, store, material) = stored_wallet(dir.path());
        let encrypted = encrypt_struct_with_aad(&store, &material, b"legacy\ntaproot").unwrap();
        let file = WalletFile {
            requires: vec!["taproot".into(), "legacy".into(), "taproot".into()],
            encrypted: encrypted.clone(),
        };
        std::fs::write(&path, serde_cbor::to_vec(&file).unwrap()).unwrap();
        assert_eq!(
            WalletStore::read_from_disk(&path, Some(PASSWORD.into()))
                .unwrap()
                .0,
            store
        );
        for requires in [vec![], vec!["legacy".into()], vec!["taproot".into()]] {
            let file = WalletFile {
                requires,
                encrypted: encrypted.clone(),
            };
            let bytes = serde_cbor::to_vec(&file).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(matches!(
                WalletStore::read_from_disk(&path, Some(PASSWORD.into())),
                Err(WalletError::Security(SecurityError::Decryption))
            ));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        let bare = serde_cbor::to_vec(&encrypt_struct(&store, &material).unwrap()).unwrap();
        std::fs::write(&path, &bare).unwrap();
        assert!(Wallet::is_wallet_encrypted(&path).unwrap());
        assert!(matches!(
            WalletStore::read_from_disk(&path, None),
            Err(WalletError::Security(SecurityError::PasswordRequired))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), bare);
        let (read, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(read, store);
        assert_eq!(
            std::fs::read(path.with_file_name("wallet.cbor.v023")).unwrap(),
            bare
        );
        std::fs::write(&path, b"garbage").unwrap();
        assert!(!Wallet::is_wallet_encrypted(&path).unwrap());
    }

    #[test]
    fn compat_wallet_and_bond_extra_survive_encrypted_rewrites() {
        let dir = tempdir().unwrap();
        let (path, mut store, material) = stored_wallet(dir.path());
        let future = Value::Map(BTreeMap::from([(
            Value::Text("nested".into()),
            Value::Array(vec![Value::Bytes(vec![7, 8]), Value::Bool(true)]),
        )]));
        store.extra.insert("future_store".into(), future.clone());
        store.external_index = 17;
        store.internal_index = 23;
        store.utxo_cache.extend([cache_entry(0), cache_entry(1)]);
        store.fidelity_bond.push(FidelityBond {
            outpoint: cache_entry(0).0,
            amount: Amount::from_sat(123_456),
            lock_time: LockTime::from_height(800_000).unwrap(),
            pubkey: PublicKey::new(
                SecretKey::from_slice(&[7; 32])
                    .unwrap()
                    .public_key(&Secp256k1::new()),
            ),
            conf_height: Some(799_000),
            is_spent: false,
            bond_index: 3,
            tx: None,
            extra: BTreeMap::from([("future_bond".into(), future)]),
        });
        for _ in 0..2 {
            store.write_to_disk(&path, &material).unwrap();
            let (read, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            assert_eq!(read, store);
            assert_eq!(
                read.master_key.plaintext_with(&material),
                store.master_key.plaintext_with(&material)
            );
            store = read;
        }
    }

    #[test]
    fn compat_cache_future_spend_info_drops_only_its_entry() {
        let dir = tempdir().unwrap();
        let (_, mut store, _) = stored_wallet(dir.path());
        store.utxo_cache.extend([cache_entry(0), cache_entry(1)]);
        store
            .prevout_to_contract_map
            .insert(cache_entry(0).0, ScriptBuf::from_bytes(vec![0x51]));
        let mut value = to_value(&store).unwrap();
        let Value::Map(fields) = &mut value else {
            panic!()
        };
        let Value::Map(cache) = fields.get_mut(&Value::Text("utxo_cache".into())).unwrap() else {
            panic!()
        };
        let mut future = to_value(cache_entry(2).1).unwrap();
        let Value::Array(pair) = &mut future else {
            panic!()
        };
        pair[1] = Value::Map(BTreeMap::from([(
            Value::Text("FutureSpendInfo".into()),
            Value::Map(BTreeMap::new()),
        )]));
        cache.insert(to_value(cache_entry(2).0).unwrap(), future);
        cache.insert(
            Value::Text("future-outpoint".into()),
            to_value(cache_entry(3).1).unwrap(),
        );
        let decoded: WalletStore =
            serde_cbor::from_slice(&serde_cbor::to_vec(&value).unwrap()).unwrap();
        assert_eq!(decoded.utxo_cache, store.utxo_cache);
        assert_eq!(
            decoded.prevout_to_contract_map,
            store.prevout_to_contract_map
        );
        assert_eq!(decoded, store);
    }

    #[test]
    fn compat_lightning_records_derive_requirements_in_every_build() {
        let dir = tempdir().unwrap();
        let (path, mut store, material) = stored_wallet(dir.path());
        for (direction, phases, name) in [
            (
                LnMakerDirection::SwapIn,
                vec![
                    LnMakerPhase::InAccepted,
                    LnMakerPhase::InPaid,
                    LnMakerPhase::InSwept,
                ],
                "ln-swap-in",
            ),
            (
                LnMakerDirection::SwapOut,
                vec![LnMakerPhase::OutAccepted, LnMakerPhase::OutFunded],
                "ln-swap-out",
            ),
        ] {
            for phase in phases {
                store.ln_pending_swaps.clear();
                store.ln_maker_swaps.clear();
                let record = LnMakerSwapRecord {
                    direction,
                    phase,
                    payment_hash: sha256::Hash::hash(b"compat-payment"),
                    amount: Amount::from_sat(50_000),
                    fee: Amount::from_sat(500),
                    locktime: 60,
                    min_confirmations: 2,
                    redeemscript: ScriptBuf::from_bytes(vec![0x51]),
                    privkey: SecretKey::from_slice(&[9; 32]).unwrap(),
                    invoice: "invoice".into(),
                    preimage: Some([8; 32]),
                    refund_txid: Some(Txid::all_zeros()),
                    accepted_height: Some(42),
                    payout_script: Some(ScriptBuf::from_bytes(vec![0x52])),
                    funding_outpoint: Some(cache_entry(0).0),
                    funding_value: Some(Amount::from_sat(50_000)),
                    funding_height: Some(43),
                };
                let mut names = BTreeSet::new();
                record.requires(&mut names);
                assert_eq!(names, BTreeSet::from([name]));
                store.ln_maker_swaps.insert("maker".into(), record);
                let pending = LnPendingSwap {
                    is_swap_in: direction == LnMakerDirection::SwapIn,
                    preimage: Some([8; 32]),
                    redeemscript: ScriptBuf::from_bytes(vec![0x51]),
                    locktime: 60,
                    privkey: SecretKey::from_slice(&[9; 32]).unwrap(),
                    outpoint: Some(cache_entry(0).0),
                    value: Some(Amount::from_sat(50_000)),
                };
                let mut pending_names = BTreeSet::new();
                pending.requires(&mut pending_names);
                assert_eq!(pending_names, names);
                store.ln_pending_swaps.insert("taker".into(), pending);
                store.write_to_disk(&path, &material).unwrap();
                let bytes = std::fs::read(&path).unwrap();
                let file: WalletFile = serde_cbor::from_slice(&bytes).unwrap();
                assert_eq!(file.requires, [name]);
                let read = WalletStore::read_from_disk(&path, Some(PASSWORD.into()));
                if cfg!(feature = "lightning") {
                    assert_eq!(read.unwrap().0, store);
                } else {
                    assert!(
                        matches!(read, Err(WalletError::NeedsUpgrade(names)) if names == [name])
                    );
                }
                assert_eq!(std::fs::read(&path).unwrap(), bytes);
            }
        }
        store.ln_pending_swaps.get_mut("taker").unwrap().is_swap_in = true;
        store.write_to_disk(&path, &material).unwrap();
        let union: WalletFile = serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(union.requires, ["ln-swap-in", "ln-swap-out"]);
        store.ln_pending_swaps.clear();
        store.ln_maker_swaps.clear();
        store.write_to_disk(&path, &material).unwrap();
        let file: WalletFile = serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert!(file.requires.is_empty());
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
                encrypted: encrypt_struct_with_aad(&store, &material, &requires_aad(aad)).unwrap(),
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

        let bare = encrypt_struct(&store, &material).unwrap();
        std::fs::write(&path, serde_cbor::to_vec(&bare).unwrap()).unwrap();
        let (read, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(read, store);
    }

    #[test]
    fn legacy_upgrade_archives_exact_inputs_and_seals_the_master_key() {
        for cleartext in [false, true] {
            let dir = tempdir().unwrap();
            let wallets = dir.path().join("wallets");
            std::fs::create_dir(&wallets).unwrap();
            let (path, store, material) = stored_wallet(&wallets);
            let xpriv = store.master_key.plaintext_with(&material).unwrap();
            let mut legacy = to_value(&store).unwrap();
            let Value::Map(fields) = &mut legacy else {
                panic!()
            };
            fields.insert(Value::Text("master_key".into()), to_value(xpriv).unwrap());
            let bytes = if cleartext {
                serde_cbor::to_vec(&legacy).unwrap()
            } else {
                serde_cbor::to_vec(&encrypt_struct(&legacy, &material).unwrap()).unwrap()
            };
            std::fs::write(&path, &bytes).unwrap();
            let sibling = wallets.join("sibling.wallet");
            std::fs::write(&sibling, &bytes).unwrap();
            let report_path = wallets.join("wallet_swap_report.json");
            let report = SwapReportFile {
                recovery: vec![RecoveryReport {
                    swap_id: "closed-swap".into(),
                    role: SwapRole::Taker,
                    node: None,
                    recovery_type: "timelock".into(),
                    recovery_txids: vec!["txid".into()],
                    network: "regtest".into(),
                    timestamp: 10,
                }],
                ..Default::default()
            };
            let report_bytes = serde_json::to_vec(&report).unwrap();
            std::fs::write(&report_path, &report_bytes).unwrap();
            let archive = wallets.join("wallet.cbor.v023");
            std::fs::write(&archive, b"older wallet").unwrap();
            #[cfg(unix)]
            std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o644)).unwrap();
            let (read, key) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            assert!(matches!(read.master_key, MasterKey::Sealed(_)));
            assert_eq!(read.master_key.plaintext_with(&key), Some(xpriv));
            assert_eq!(
                read.reports["recovery"],
                vec![to_value(&report.recovery[0]).unwrap()]
            );
            assert_eq!(std::fs::read(&archive).unwrap(), bytes);
            let report_archive = wallets.join("wallet_swap_report.json.v023");
            assert_eq!(std::fs::read(&report_archive).unwrap(), report_bytes);
            assert_eq!(std::fs::read(&sibling).unwrap(), bytes);
            assert!(!report_path.exists());
            #[cfg(unix)]
            for file in [&archive, &report_archive] {
                assert_eq!(
                    std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
            let migrated = std::fs::read(&path).unwrap();
            assert!(serde_cbor::from_slice::<WalletFile>(&migrated).is_ok());
            // A report created beside a restored envelope is never imported or deleted.
            std::fs::write(&report_path, &report_bytes).unwrap();
            let (second, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            assert_eq!(second, read);
            assert_eq!(std::fs::read(&path).unwrap(), migrated);
            assert_eq!(std::fs::read(&report_path).unwrap(), report_bytes);
        }
    }

    #[test]
    fn legacy_upgrade_refuses_before_creating_archives() {
        for reason in [
            "open wallet",
            "incomplete tracker",
            "bad tracker",
            "bad report",
        ] {
            let dir = tempdir().unwrap();
            let wallets = if reason == "incomplete tracker" {
                dir.path().to_path_buf()
            } else {
                dir.path().join("wallets")
            };
            std::fs::create_dir_all(&wallets).unwrap();
            let (path, mut store, material) = stored_wallet(&wallets);
            if reason == "open wallet" {
                store
                    .swap_locks
                    .insert("open".into(), SwapReservation::default());
            }
            let bytes = serde_cbor::to_vec(&encrypt_struct(&store, &material).unwrap()).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            let tracker_path = dir.path().join("swap_tracker.cbor");
            let tracker = if reason == "bad tracker" {
                b"broken".to_vec()
            } else if reason == "incomplete tracker" {
                serde_cbor::to_vec(&serde_json::json!({"swaps":{"s":{"phase":"FundsBroadcast","recovery":{"phase":"CleanedUp"}}}})).unwrap()
            } else {
                serde_cbor::to_vec(&serde_json::json!({"swaps":{}})).unwrap()
            };
            std::fs::write(&tracker_path, &tracker).unwrap();
            let report_path = wallets.join("wallet_swap_report.json");
            let report_bytes = if reason == "bad report" {
                b"broken".to_vec()
            } else {
                serde_json::to_vec(&SwapReportFile::default()).unwrap()
            };
            std::fs::write(&report_path, &report_bytes).unwrap();
            let error = WalletStore::read_from_disk(&path, Some(PASSWORD.into()))
                .unwrap_err()
                .to_string();
            assert!(error.contains("Start v0.2.3 once"), "{}", error);
            assert!(error.contains("Stop every v0.2.3 process"));
            assert!(error.contains("lose funds"));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
            assert_eq!(std::fs::read(&tracker_path).unwrap(), tracker);
            assert_eq!(std::fs::read(&report_path).unwrap(), report_bytes);
            assert_eq!(
                std::fs::read_dir(&wallets).unwrap().count(),
                if wallets == dir.path() { 3 } else { 2 }
            );
        }
    }

    #[test]
    fn legacy_tracker_predicates_match_v023() {
        for (phase, cleanup, maker_open, taker_open) in [
            ("Completed", "NotStarted", true, false),
            ("Completed", "CleanedUp", false, false),
            ("Recovered", "CleanedUp", false, true),
            ("Failed", "CleanedUp", true, false),
            ("Failed", "NotStarted", true, true),
            ("FuturePhase", "CleanedUp", true, true),
            ("Completed", "FutureRecovery", true, true),
        ] {
            let bytes = serde_cbor::to_vec(
                &serde_json::json!({"swaps":{"s":{"phase":phase,"recovery":{"phase":cleanup}}}}),
            )
            .unwrap();
            assert_eq!(legacy_tracker_is_open(&bytes, true), maker_open);
            assert_eq!(legacy_tracker_is_open(&bytes, false), taker_open);
        }
        assert!(legacy_tracker_is_open(b"broken", false));
        assert!(legacy_tracker_is_open(
            &serde_cbor::to_vec(&serde_json::json!({"swaps":[]})).unwrap(),
            true
        ));
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
