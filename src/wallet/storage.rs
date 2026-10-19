//! The Wallet Storage Interface.
//!
//! Wallet data is written to disk as AES-256-GCM-encrypted CBOR inside the
//! version 2 container. Unmarked version 2, bare version 1 and legacy
//! cleartext files are read only for one-time migration. The master key and the seed
//! phrase are each sealed again, see [`MasterKey`] and
//! [`WalletStore::sealed_mnemonic`].

use crate::{
    security::{
        decrypt_struct, decrypt_with_password, encrypt_struct, encrypt_struct_v2,
        is_versioned_container, load_sensitive_struct_from_slice, EncryptedData, EncryptedDataV2,
        KeyMaterial, SealedSecret, SecurityError, SerdeCbor, FORMAT_NAMES, WALLET_STORE_FORMAT,
    },
    utill::deserialize_from_cbor,
    wallet::UTXOSpendInfo,
};

use super::{
    backup::RestoreOptions, error::WalletError, fidelity::FidelityBond, report::SwapReportFile,
};

use bip39::Mnemonic;
use bitcoin::{bip32::Xpriv, Network, OutPoint, ScriptBuf};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_cbor::{value::from_value, Value};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt::Write as _,
    fs::File,
    io::{BufWriter, ErrorKind, Write},
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
/// [`MasterKey::Plaintext`] state. Migration reseals it before atomically
/// replacing the live file; only the private archive keeps the original bytes.
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

/// Inputs one swap holds out of coin selection, and when it took them or
/// last tried to send its funding: the unbroadcast grace counts from there.
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

    /// The seed phrase as [`SecretEntropy`], sealed under its own key from the
    /// wallet password. Load, save, sync and signing never open it.
    #[serde(default)]
    pub(super) sealed_mnemonic: Option<SealedSecret>,
    /// Set once the user has confirmed writing the seed phrase down.
    #[serde(default)]
    pub(super) seed_backed_up: bool,

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
            // An older build that drops it rescans with its default gaps.
            pending_restore: _,
            // An entry this build can't read is dropped on load, never refused.
            utxo_cache: _,
            swap_locks,
            ln_pending_swaps,
            ln_maker_swaps,
            // The V2 container guards these; no separate seed feature name.
            sealed_mnemonic: _,
            seed_backed_up: _,
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
            reports: BTreeMap::new(),
            extra: BTreeMap::new(),
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
        let mut names: BTreeSet<&'static str> = FORMAT_NAMES.iter().copied().collect();
        self.requires(&mut names);
        let requires: Vec<String> = names.into_iter().map(String::from).collect();
        let file = encrypt_struct_v2(self, store_enc_material, requires)
            .map_err(|e| WalletError::General(format!("wallet store encryption failed: {e:?}")))?;
        write_atomic(path, no_clobber, |writer| {
            serde_cbor::to_writer(writer, &file)?;
            Ok(())
        })
    }

    /// Reads and decrypts the wallet at `path`, returning the store and the
    /// key material derived from `password`.
    ///
    /// Unsupported requirements refuse before decryption. A version 2
    /// container with the format marker loads as is. A closed older wallet
    /// is archived and upgraded before returning; an open one is untouched.
    /// Callers must hold the wallet lock throughout any upgrade.
    pub(crate) fn read_from_disk(
        path: &Path,
        password: Option<String>,
    ) -> Result<(Self, KeyMaterial), WalletError> {
        Self::read_file(path, password, true)?.ok_or_else(|| {
            WalletError::General(format!("{} needs a one-time upgrade", path.display()))
        })
    }

    /// Like [`Self::read_from_disk`], but never writes: `None` for an older
    /// file (including unmarked V2), whose one-time upgrade rewrites it.
    pub(crate) fn read_without_upgrade(
        path: &Path,
        password: Option<String>,
    ) -> Result<Option<(Self, KeyMaterial)>, WalletError> {
        Self::read_file(path, password, false)
    }

    fn read_file(
        path: &Path,
        password: Option<String>,
        upgrade: bool,
    ) -> Result<Option<(Self, KeyMaterial)>, WalletError> {
        // Wiped on every return: a legacy file may be plaintext.
        let mut password = password.map(Zeroizing::new);
        let content = Zeroizing::new(std::fs::read(path)?);
        let versioned = if is_versioned_container(&content) {
            let password = password.as_mut().map(|p| std::mem::take(&mut **p));
            let (store, material) =
                load_sensitive_struct_from_slice::<Self, SerdeCbor>(&content, path, password)?;
            // The loader has checked version, requirements and authentication.
            let header: EncryptedDataV2 = deserialize_from_cbor(&content)?;
            let loaded = (store, material.ok_or(SecurityError::PasswordRequired)?);
            if header
                .requires
                .iter()
                .any(|name| name == WALLET_STORE_FORMAT)
            {
                return Ok(Some(loaded));
            }
            Some(loaded)
        } else {
            None
        };
        let mut take_password = || -> Result<String, WalletError> {
            match password.as_mut() {
                Some(p) if !p.is_empty() => Ok(std::mem::take(&mut **p)),
                _ => Err(SecurityError::PasswordRequired.into()),
            }
        };
        if !upgrade {
            return Ok(None);
        }
        let suffix = if versioned.is_some() {
            ".v2pre"
        } else {
            ".v023"
        };
        let (mut store, material) = if let Some(loaded) = versioned {
            loaded
        } else {
            match deserialize_from_cbor::<EncryptedData>(&content) {
                Ok(encrypted) => decrypt_with_password(encrypted, take_password()?, &[])?,
                Err(_) => (
                    deserialize_from_cbor::<Self>(&content)?,
                    KeyMaterial::new_from_password(Some(take_password()?))
                        .ok_or(SecurityError::PasswordRequired)?,
                ),
            }
        };
        let refuse = |reason: String| {
            WalletError::General(format!(
            "Cannot upgrade {}: {reason}. Stop every older openswap process using this data directory; an old process can overwrite new swap keys and lose funds. Start the older openswap build once and finish all swaps before retrying.",
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
        log::warn!("Upgrading {}. Every older openswap process must be stopped: an old process can overwrite new swap keys and lose funds.", path.display());
        archive_legacy_file(path, &content, suffix)?;
        if let Some(bytes) = &report_bytes {
            archive_legacy_file(&report_path, bytes, suffix)?;
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
        log::warn!("Upgraded {}. After every wallet in this data directory is upgraded, manually delete maker_swap_tracker.cbor and swap_tracker.cbor. Keep the private {suffix} archives for rollback.", path.display());
        Ok(Some((store, material)))
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

fn archive_legacy_file(path: &Path, bytes: &[u8], suffix: &str) -> Result<(), WalletError> {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    let archive = Path::new(&name);
    match std::fs::read(archive).map(Zeroizing::new) {
        Ok(existing) if existing.as_slice() == bytes => {
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
        security::load_sensitive_struct,
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
            None,
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
        generate_container(release, &store);
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

    pub(crate) fn generate_container(release: &Path, store: &WalletStore) {
        let MasterKey::Sealed(sealed) = &store.master_key else {
            panic!()
        };
        let (mut master, key) =
            decrypt_with_password::<Xpriv>(sealed.clone(), "fixture-password".into(), &[]).unwrap();
        master.private_key.non_secure_erase();
        let mut names: BTreeSet<_> = FORMAT_NAMES.iter().copied().collect();
        store.requires(&mut names);
        let requires: Vec<_> = names.into_iter().map(String::from).collect();
        let file = encrypt_struct_v2(store, &key, requires).unwrap();
        write(release, "wallet-file", &file);
    }

    pub(crate) fn check_container(release: &Path) {
        let file: crate::security::EncryptedDataV2 = check(release, "wallet-file");
        assert_eq!(
            file.requires,
            [
                "ln-swap-in",
                "ln-swap-out",
                crate::security::WALLET_STORE_FORMAT
            ]
        );
        let loaded = load_sensitive_struct::<WalletStore, SerdeCbor>(
            &release.join("wallet-file.cbor"),
            Some("fixture-password".into()),
        );
        if !cfg!(feature = "lightning") {
            assert!(
                matches!(loaded, Err(SecurityError::NeedsUpgrade(names)) if names == ["ln-swap-in", "ln-swap-out"])
            );
            return;
        }
        let (store, key) = loaded.unwrap();
        let key = key.unwrap();
        compat_assert_empty_extra(&store);
        assert_eq!(
            store.master_key.with_unlocked(&key, |k| Ok(*k)).ok(),
            Some(Xpriv::new_master(Network::Regtest, &[42; 32]).unwrap())
        );
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
    use crate::{
        security::{load_sensitive_struct, EncryptedDataV2, SecurityError, WALLET_STORE_FORMAT},
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
    fn compat_v023_migration_is_refused_by_pre_port_v2_reader() {
        use aes_gcm::{
            aead::{Aead, Payload},
            Aes256Gcm, KeyInit,
        };

        // Model #1165's header gate and decryptor independently of the new
        // requirement registry and V2 loader. Confirm the model can decrypt
        // an unmarked V2 control before testing its downgrade refusal.
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct PrePortV2 {
            version: u32,
            requires: Vec<String>,
            nonce: [u8; 12],
            pbkdf2_salt: [u8; 16],
            ciphertext: Vec<u8>,
        }
        let old_read = |bytes: &[u8]| -> Result<Value, &'static str> {
            let file: PrePortV2 = serde_cbor::from_slice(bytes).map_err(|_| "invalid container")?;
            if file.version != 2 || !file.requires.is_empty() {
                return Err("unsupported header");
            }
            let key = KeyMaterial::existing(V023_PASSWORD.into(), file.nonce, file.pbkdf2_salt);
            let aad = serde_cbor::to_vec(&(file.version, file.requires)).unwrap();
            let plain = Zeroizing::new(
                Aes256Gcm::new_from_slice(&key.key)
                    .unwrap()
                    .decrypt(
                        &file.nonce.into(),
                        Payload {
                            msg: &file.ciphertext,
                            aad: &aad,
                        },
                    )
                    .map_err(|_| "decryption failed")?,
            );
            serde_cbor::from_slice(&plain).map_err(|_| "invalid payload")
        };

        let dir = tempdir().unwrap();
        let path = install_v023_wallet(dir.path());
        let (store, key) = WalletStore::read_from_disk(&path, Some(V023_PASSWORD.into())).unwrap();
        let unmarked = encrypt_struct_v2(&store, &key, Vec::new()).unwrap();
        let control = old_read(&serde_cbor::to_vec(&unmarked).unwrap()).unwrap();
        assert_eq!(control, to_value(&store).unwrap());
        assert!(!store.reports.is_empty());
        assert!(store.sealed_mnemonic.is_none());
        assert!(!store.seed_backed_up);

        let bytes = std::fs::read(&path).unwrap();
        let header: PrePortV2 = serde_cbor::from_slice(&bytes).unwrap();
        assert_eq!(header.version, 2);
        assert_eq!(header.requires, [WALLET_STORE_FORMAT]);
        assert_eq!(old_read(&bytes), Err("unsupported header"));
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert_eq!(
            std::fs::read(path.with_file_name("closed.wallet.v023")).unwrap(),
            V023_CLOSED
        );
        assert_eq!(
            std::fs::read(path.with_file_name("closed_swap_report.json.v023")).unwrap(),
            V023_REPORT
        );
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
            store.master_key.with_unlocked(&material, |k| Ok(*k)).ok(),
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
                error.contains("Stop every older openswap process"),
                "{}: {}",
                failure,
                error
            );
            assert!(error.contains("lose funds"));
            assert!(error.contains("Start the older openswap build once"));
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
        let store = WalletStore::init(
            "w".into(),
            &path,
            Network::Regtest,
            xpriv,
            None,
            None,
            &material,
        )
        .unwrap();
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
            let file: EncryptedDataV2 = serde_json::from_value(serde_json::json!({
                "version": 2,
                "requires": [name],
                "nonce": material.nonce,
                "pbkdf2_salt": material.pbkdf2_salt,
                "ciphertext": [0],
            }))
            .unwrap();
            let bytes = serde_cbor::to_vec(&file).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            assert!(Wallet::is_wallet_encrypted(&path).unwrap());
            for password in [None, Some(String::new()), Some("wrong".into())] {
                for result in [
                    WalletStore::read_from_disk(&path, password.clone()).map(|_| ()),
                    WalletStore::read_without_upgrade(&path, password).map(|_| ()),
                ] {
                    let error = result.unwrap_err();
                    if name == "ln-swap-in" && cfg!(feature = "lightning") {
                        assert!(!matches!(error, WalletError::NeedsUpgrade(_)));
                    } else {
                        assert!(
                            matches!(error, WalletError::NeedsUpgrade(names) if names == [name])
                        );
                    }
                    assert_eq!(std::fs::read(&path).unwrap(), bytes);
                }
            }
        }
    }

    #[test]
    fn compat_wallet_headers_authenticate_and_bare_files_upgrade() {
        let dir = tempdir().unwrap();
        let (path, store, material) = stored_wallet(dir.path());
        let file = encrypt_struct_v2(
            &store,
            &material,
            vec!["taproot".into(), "legacy".into(), "taproot".into()],
        )
        .unwrap();
        std::fs::write(&path, serde_cbor::to_vec(&file).unwrap()).unwrap();
        assert_eq!(
            WalletStore::read_from_disk(&path, Some(PASSWORD.into()))
                .unwrap()
                .0,
            store
        );
        // V2 authenticates the exact sequence, including order and duplicates.
        for requires in [
            vec![],
            vec!["legacy".into()],
            vec!["taproot".into()],
            vec!["legacy".into(), "taproot".into()],
            vec!["legacy".into(), "taproot".into(), "taproot".into()],
        ] {
            let mut file = file.clone();
            file.requires = requires;
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
                read.master_key.with_unlocked(&material, |k| Ok(*k)).ok(),
                store.master_key.with_unlocked(&material, |k| Ok(*k)).ok()
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
                let file: EncryptedDataV2 = serde_cbor::from_slice(&bytes).unwrap();
                assert_eq!(file.requires, [name, WALLET_STORE_FORMAT]);
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
        let union: EncryptedDataV2 =
            serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(
            union.requires,
            ["ln-swap-in", "ln-swap-out", WALLET_STORE_FORMAT]
        );
        store.ln_pending_swaps.clear();
        store.ln_maker_swaps.clear();
        store.write_to_disk(&path, &material).unwrap();
        let file: EncryptedDataV2 = serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(file.requires, [WALLET_STORE_FORMAT]);
    }

    #[test]
    fn wallet_saves_v2_with_format_marker_and_refuses_pre_port_readers() {
        let dir = tempdir().unwrap();
        let (path, store, material) = stored_wallet(dir.path());
        let first = std::fs::read(&path).unwrap();
        let file: EncryptedDataV2 = serde_cbor::from_slice(&first).unwrap();
        assert_eq!(file.requires, [WALLET_STORE_FORMAT]);
        assert!(crate::protocol::features::supported().contains(&WALLET_STORE_FORMAT));
        assert!(serde_cbor::from_slice::<EncryptedData>(&first).is_err());
        // #1165's reader rejects every nonempty requires list.
        assert!(!file.requires.is_empty());
        let (loaded, _) =
            load_sensitive_struct::<WalletStore, SerdeCbor>(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(loaded, store);
        store.write_to_disk(&path, &material).unwrap();
        let second: EncryptedDataV2 =
            serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(second.requires, file.requires);
        assert_ne!(second, file, "each save must rotate the nonce");
        // Removing the downgrade guard cannot make a saved wallet readable.
        let mut stripped = second;
        stripped.requires.clear();
        let bytes = serde_cbor::to_vec(&stripped).unwrap();
        std::fs::write(&path, &bytes).unwrap();
        for result in [
            WalletStore::read_from_disk(&path, Some(PASSWORD.into())).map(|_| ()),
            WalletStore::read_without_upgrade(&path, Some(PASSWORD.into())).map(|_| ()),
        ] {
            assert!(matches!(
                result,
                Err(WalletError::Security(SecurityError::Decryption))
            ));
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
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
            let mut file = encrypt_struct_v2(
                &store,
                &material,
                aad.iter().map(|n| n.to_string()).collect(),
            )
            .unwrap();
            file.requires = requires.iter().map(|n| n.to_string()).collect();
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
            let xpriv = store
                .master_key
                .with_unlocked(&material, |k| Ok(*k))
                .ok()
                .unwrap();
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
            assert_eq!(
                read.master_key.with_unlocked(&key, |k| Ok(*k)).ok(),
                Some(xpriv)
            );
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
            assert!(serde_cbor::from_slice::<EncryptedDataV2>(&migrated).is_ok());
            // A report created beside a restored container is never imported or deleted.
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
            assert!(
                error.contains("Start the older openswap build once"),
                "{}",
                error
            );
            assert!(error.contains("Stop every older openswap process"));
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
    fn pre_port_v2_preserves_opaque_seed_and_forward_fields_on_save() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let material = KeyMaterial::new_from_password(Some(PASSWORD.into())).unwrap();
        let mut store = test_store(&path, &material);
        let entropy = SecretEntropy::from_mnemonic(&Mnemonic::generate(12).unwrap()).unwrap();
        // Deliberately cannot be opened with the outer file's password. Load
        // and save must copy the sealed blob without trying to decrypt it.
        store.sealed_mnemonic = Some(SealedSecret::seal(&entropy, "other password").unwrap());
        store.seed_backed_up = true;
        store.pending_restore = Some(RestoreOptions {
            address_gap: 321,
            bond_gap: 37,
            ..Default::default()
        });
        store
            .extra
            .insert("future_field".into(), Value::Bytes(vec![1, 2, 3]));
        store
            .reports
            .insert("future_report".into(), vec![Value::Bool(true)]);
        let seed_bytes = serde_cbor::to_vec(&store.sealed_mnemonic).unwrap();
        let master_bytes = serde_cbor::to_vec(&store.master_key).unwrap();
        let old = crate::security::encrypt_struct_v2(&store, &material, Vec::new()).unwrap();
        let source = serde_cbor::to_vec(&old).unwrap();
        std::fs::write(&path, &source).unwrap();
        assert!(Wallet::is_wallet_encrypted(&path).unwrap());

        // Both entry points password-gate unmarked V2 before any migration.
        for nonmutating in [false, true] {
            for password in [None, Some(""), Some("wrong password")] {
                let supplied = password.map(String::from);
                let err = if nonmutating {
                    WalletStore::read_without_upgrade(&path, supplied).unwrap_err()
                } else {
                    WalletStore::read_from_disk(&path, supplied).unwrap_err()
                };
                match password {
                    None | Some("") => assert!(matches!(
                        err,
                        WalletError::Security(SecurityError::PasswordRequired)
                    )),
                    _ => assert!(matches!(
                        err,
                        WalletError::Security(SecurityError::Decryption)
                    )),
                }
                assert_eq!(std::fs::read(&path).unwrap(), source);
                assert!(!path.with_file_name("wallet.v023").exists());
                assert!(!path.with_file_name("wallet.v2pre").exists());
            }
        }
        assert!(
            WalletStore::read_without_upgrade(&path, Some(PASSWORD.into()))
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(&path).unwrap(), source);

        let (read, key) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(read, store);
        assert_eq!(
            std::fs::read(path.with_file_name("wallet.v2pre")).unwrap(),
            source
        );
        assert!(!path.with_file_name("wallet.v023").exists());
        let migrated = std::fs::read(&path).unwrap();
        assert_ne!(migrated, source);
        read.write_to_disk(&path, &key).unwrap();
        // Migration writes the format marker: the current reader accepts it,
        // while #1165's blanket nonempty-requires refusal guards downgrades.
        let saved = std::fs::read(&path).unwrap();
        let saved_container: EncryptedDataV2 = serde_cbor::from_slice(&saved).unwrap();
        assert_eq!(saved_container.requires, [WALLET_STORE_FORMAT]);
        let (saved_store, _) =
            load_sensitive_struct::<WalletStore, SerdeCbor>(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(saved_store, store);
        assert_eq!(std::fs::read(&path).unwrap(), saved);
        let (rewritten, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(rewritten, store);
        assert_eq!(
            serde_cbor::to_vec(&rewritten.sealed_mnemonic).unwrap(),
            seed_bytes
        );
        assert_eq!(
            serde_cbor::to_vec(&rewritten.master_key).unwrap(),
            master_bytes
        );
        assert!(rewritten.seed_backed_up);
        assert!(matches!(
            rewritten
                .sealed_mnemonic
                .unwrap()
                .open::<SecretEntropy>(PASSWORD),
            Err(SecurityError::Decryption)
        ));
    }

    #[test]
    fn pre_port_v2_report_import_retries_private_archives_before_commit() {
        for changed in [false, true] {
            let dir = tempdir().unwrap();
            let (path, mut store, material) = stored_wallet(dir.path());
            store
                .reports
                .insert("future".into(), vec![Value::Bool(true)]);
            let mut source =
                serde_cbor::to_vec(&encrypt_struct_v2(&store, &material, Vec::new()).unwrap())
                    .unwrap();
            std::fs::write(&path, &source).unwrap();
            let report = dir.path().join("wallet_swap_report.json");
            let archive = dir.path().join("wallet.cbor.v2pre");
            let report_archive = dir.path().join("wallet_swap_report.json.v2pre");
            std::fs::write(&report, V023_REPORT).unwrap();
            // Interrupt after the wallet archive, before the report archive.
            std::fs::create_dir(&report_archive).unwrap();
            assert!(WalletStore::read_from_disk(&path, Some(PASSWORD.into())).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), source);
            assert_eq!(std::fs::read(&archive).unwrap(), source);
            assert_eq!(std::fs::read(&report).unwrap(), V023_REPORT);
            #[cfg(unix)]
            let inode = std::fs::metadata(&archive).unwrap().ino();
            #[cfg(unix)]
            std::fs::set_permissions(&archive, std::fs::Permissions::from_mode(0o644)).unwrap();
            if changed {
                store.external_index += 1;
                source =
                    serde_cbor::to_vec(&encrypt_struct_v2(&store, &material, Vec::new()).unwrap())
                        .unwrap();
                std::fs::write(&path, &source).unwrap();
            }
            std::fs::remove_dir(&report_archive).unwrap();
            let (migrated, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            assert_eq!(migrated.external_index, store.external_index);
            assert_eq!(migrated.reports["future"], store.reports["future"]);
            assert_eq!(migrated.reports["deniability_proofs"].len(), 1);
            let proof: DeniabilityProof =
                from_value(migrated.reports["deniability_proofs"][0].clone()).unwrap();
            let script: ScriptBuf = serde_cbor::from_slice(include_bytes!(
                "../../tests/fixtures/compat/v0.2.3/proof-chain-script.cbor"
            ))
            .unwrap();
            verify_proof_for_test(&proof, &script).unwrap();
            assert_eq!(std::fs::read(&archive).unwrap(), source);
            assert_eq!(std::fs::read(&report_archive).unwrap(), V023_REPORT);
            assert!(!report.exists());
            assert!(!dir.path().join("wallet.cbor.v023").exists());
            #[cfg(unix)]
            {
                if !changed {
                    assert_eq!(std::fs::metadata(&archive).unwrap().ino(), inode);
                }
                for file in [&archive, &report_archive] {
                    assert_eq!(
                        std::fs::metadata(file).unwrap().permissions().mode() & 0o777,
                        0o600
                    );
                }
            }
            let committed = std::fs::read(&path).unwrap();
            let header: EncryptedDataV2 = serde_cbor::from_slice(&committed).unwrap();
            assert!(header
                .requires
                .iter()
                .any(|name| name == WALLET_STORE_FORMAT));
            let (again, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            assert_eq!(again, migrated);
            assert_eq!(std::fs::read(&path).unwrap(), committed);
        }
    }

    #[test]
    fn pre_port_v2_marker_controls_migration_and_report_import_once() {
        let dir = tempdir().unwrap();
        let (path, mut store, material) = stored_wallet(dir.path());
        let _owner = crate::wallet::seed_cli::WalletInUse::owner(&path).unwrap();
        let existing = Value::Map(BTreeMap::from([(
            Value::Text("future-proof".into()),
            Value::Bytes(vec![1, 2, 3]),
        )]));
        store
            .reports
            .insert("deniability_proofs".into(), vec![existing.clone()]);
        // Migration depends on the marker's absence, not on an empty header.
        let source = serde_cbor::to_vec(
            &encrypt_struct_v2(&store, &material, vec!["legacy".into()]).unwrap(),
        )
        .unwrap();
        std::fs::write(&path, &source).unwrap();
        let report = dir.path().join("wallet_swap_report.json");
        std::fs::write(&report, V023_REPORT).unwrap();
        assert!(
            WalletStore::read_without_upgrade(&path, Some(PASSWORD.into()))
                .unwrap()
                .is_none()
        );
        assert_eq!(std::fs::read(&path).unwrap(), source);
        let (mut migrated, key) =
            WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        let expected: SwapReportFile = serde_json::from_slice(V023_REPORT).unwrap();
        assert_eq!(
            migrated.reports["deniability_proofs"],
            vec![existing, to_value(&expected.deniability_proofs[0]).unwrap(),]
        );
        assert_eq!(
            std::fs::read(dir.path().join("wallet.cbor.v2pre")).unwrap(),
            source
        );
        assert_eq!(
            std::fs::read(dir.path().join("wallet_swap_report.json.v2pre")).unwrap(),
            V023_REPORT
        );
        assert!(!dir.path().join("wallet.cbor.v023").exists());
        assert!(!report.exists());
        let header: EncryptedDataV2 =
            serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(header.requires, [WALLET_STORE_FORMAT]);

        // Model a report left behind after commit and subsequently damaged.
        // A current wallet may have new open swaps and obsolete trackers;
        // reopening must neither rerun migration nor import/delete the report.
        std::fs::write(&report, b"stale report").unwrap();
        let tracker = dir.path().join("maker_swap_tracker.cbor");
        std::fs::write(&tracker, V023_MAKER_OPEN).unwrap();
        migrated
            .swap_locks
            .insert("new-swap".into(), SwapReservation::default());
        migrated.write_to_disk(&path, &key).unwrap();
        let committed = std::fs::read(&path).unwrap();
        let (again, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(again, migrated);
        assert_eq!(std::fs::read(&path).unwrap(), committed);
        assert_eq!(std::fs::read(&report).unwrap(), b"stale report");
        assert_eq!(std::fs::read(&tracker).unwrap(), V023_MAKER_OPEN);
        assert_eq!(
            std::fs::read(dir.path().join("wallet.cbor.v2pre")).unwrap(),
            source
        );
        assert_eq!(
            std::fs::read(dir.path().join("wallet_swap_report.json.v2pre")).unwrap(),
            V023_REPORT
        );
    }

    #[test]
    fn pre_port_v2_refuses_open_swaps_trackers_and_reports_untouched() {
        for failure in [
            "incoming",
            "outgoing",
            "watchonly",
            "reservation",
            "ln pending",
            "ln maker",
            "maker tracker",
            "taker tracker",
            "unreadable tracker",
            "unreadable report",
            "bad report",
        ] {
            let dir = tempdir().unwrap();
            let (path, mut store, material) = stored_wallet(dir.path());
            let mut open = compat_support::compat_store();
            let report = dir.path().join("wallet_swap_report.json");
            let tracker = dir.path().join("maker_swap_tracker.cbor");
            std::fs::write(&report, V023_REPORT).unwrap();
            match failure {
                "incoming" => {
                    store.incoming_swapcoins = std::mem::take(&mut open.incoming_swapcoins)
                }
                "outgoing" => {
                    store.outgoing_swapcoins = std::mem::take(&mut open.outgoing_swapcoins)
                }
                "watchonly" => {
                    store.watchonly_swapcoins = std::mem::take(&mut open.watchonly_swapcoins)
                }
                "reservation" => store.swap_locks = std::mem::take(&mut open.swap_locks),
                "ln pending" => store.ln_pending_swaps = std::mem::take(&mut open.ln_pending_swaps),
                "ln maker" => store.ln_maker_swaps = std::mem::take(&mut open.ln_maker_swaps),
                "maker tracker" => std::fs::write(&tracker, V023_MAKER_OPEN).unwrap(),
                "taker tracker" => {
                    std::fs::write(dir.path().join("swap_tracker.cbor"), V023_TAKER_OPEN).unwrap()
                }
                "unreadable tracker" => std::fs::create_dir(&tracker).unwrap(),
                "unreadable report" => {
                    std::fs::remove_file(&report).unwrap();
                    std::fs::create_dir(&report).unwrap();
                }
                "bad report" => std::fs::write(&report, V023_BAD_REPORT).unwrap(),
                _ => unreachable!(),
            }
            let source =
                serde_cbor::to_vec(&encrypt_struct_v2(&store, &material, Vec::new()).unwrap())
                    .unwrap();
            std::fs::write(&path, &source).unwrap();
            let snapshots: Vec<_> = std::fs::read_dir(dir.path())
                .unwrap()
                .map(|entry| {
                    let path = entry.unwrap().path();
                    let bytes = if path.is_file() {
                        Some(std::fs::read(&path).unwrap())
                    } else {
                        None
                    };
                    (path, bytes)
                })
                .collect();
            let error = WalletStore::read_from_disk(&path, Some(PASSWORD.into()))
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("Stop every older openswap process"),
                "{}: {}",
                failure,
                error
            );
            assert!(error.contains("lose funds"));
            assert_eq!(
                std::fs::read_dir(dir.path()).unwrap().count(),
                snapshots.len()
            );
            for (file, bytes) in snapshots {
                if let Some(bytes) = bytes {
                    assert_eq!(std::fs::read(file).unwrap(), bytes, "{failure}");
                } else {
                    assert!(file.is_dir());
                }
            }
        }
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
    fn version_1_file_migrates_on_load() {
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
        let mut archive = path.clone().into_os_string();
        archive.push(".v023");
        assert_eq!(std::fs::read(&archive).unwrap(), v1_bytes);

        read.write_to_disk(&path, &read_material).unwrap();
        let v2_bytes = std::fs::read(&path).unwrap();
        assert!(serde_cbor::from_slice::<EncryptedData>(&v2_bytes).is_err());
        assert!(serde_cbor::from_slice::<EncryptedDataV2>(&v2_bytes).is_ok());
        let (upgraded, _) = WalletStore::read_from_disk(&path, Some(password.to_string())).unwrap();
        assert_eq!(upgraded, store);
    }

    /// An older build reads a version 1 file, a new build upgrades it on its
    /// first load, and from then on the older build refuses the file at parse
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
        read.write_to_disk(&path, &read_material).unwrap();
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

        let (read_wallet, _material) =
            WalletStore::read_from_disk(&file_path, Some(password)).unwrap();
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
