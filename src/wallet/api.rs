//! The Wallet API.
//!
//! Currently, wallet synchronization is exclusively performed through RPC for makers.
//! In the future, takers might adopt alternative synchronization methods, such as lightweight wallet solutions.

use std::{
    cmp::max,
    fmt::Display,
    path::PathBuf,
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use std::collections::{HashMap, HashSet};

use crate::security::{KeyMaterial, SecurityError};

use bip39::Mnemonic;
#[cfg(not(feature = "integration-test"))]
use bitcoin::hashes::{sha512, Hash};
use bitcoin::{
    address::NetworkUnchecked,
    bip32::{ChainCode, ChildNumber, DerivationPath, Xpriv, Xpub},
    block::Header,
    key::TapTweak,
    secp256k1,
    secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey},
    sighash::{EcdsaSighashType, Prevouts, SighashCache, TapSighashType},
    Address, Amount, Network, OutPoint, PublicKey, Script, ScriptBuf, Transaction, TxOut, Txid,
    Weight, WitnessProgram, WitnessVersion,
};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::{ListUnspentResultEntry, ScanningDetails};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::Path;
use zeroize::Zeroizing;

use crate::{
    lock_debug,
    protocol::{contract::create_multisig_redeemscript, ProtocolVersion},
    utill::{
        capped_fee, compute_checksum, fee_at_rate_sats, generate_keypair,
        get_hd_path_from_descriptor, now_secs, redeemscript_to_scriptpubkey, HEART_BEAT_INTERVAL,
        LEGACY_CONTRACT_SPEND_VSIZE, MIN_RELAY_FEE_RATE, TAPROOT_KEYPATH_VSIZE,
        TX_BROADCAST_TIMEOUT, TX_CONFIRMATION_TIMEOUT,
    },
};

use rust_coinselect::{
    selectcoin::select_coin,
    types::{CoinSelectionOpt, ExcessStrategy, OutputGroup, SelectionError},
    utils::calculate_fee,
};

use super::{
    backup::RestoreOptions,
    blockchain::{AnyBlockchain, BackendConfig, Blockchain, HdOrigin},
    deniability::verify_swap_proof,
    error::WalletError,
    report::{RecoveryReport, SwapRole},
    seed::{seal_mnemonic, SEED_NOT_BACKED_UP},
    seed_cli::{WalletInUse, IN_USE_MESSAGE},
    storage::{AddressType, SecretXpriv, SwapReservation, WalletStore},
    swapcoin::{contract_timelock, WatchOnlySwapCoin},
};

// these subroutines are coded so that as much as possible they keep all their
// data in the bitcoin core wallet
// for example which privkey corresponds to a scriptpubkey is stored in hd paths

/// Address gap limit of 20 from [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#address-gap-limit):
/// the rolling watch/import window always extends this many unused addresses
/// beyond the last used one per keychain (see [`Wallet::max_watch_index`]).
pub(crate) const ADDRESS_IMPORT_COUNT: u32 = 20;
/// Default gap used while syncing a wallet restored from backup. A seed phrase
/// carries no hand-out counters, so index gaps left by aborted multi-tx
/// funding (see [`Wallet::get_next_internal_addresses`]) must be bridged by
/// scanning alone; a run of unused indices longer than the gap would otherwise
/// end discovery early and strand funds past it. Only costs restore-time
/// queries — syncs after the first completed scan stay at [`ADDRESS_IMPORT_COUNT`].
pub(crate) const RESTORE_ADDRESS_GAP: u32 = 100;
/// Hard caps on the rolling-gap sync loop: a server inventing UTXOs at ever
/// higher indices must not keep the loop or the watch window growing forever.
const MAX_SYNC_PASSES: u32 = 100;
pub(crate) const MAX_WATCH_WINDOW: u32 = 100_000;
/// [`Wallet::judge_unseen_incoming`]'s answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnseenIncoming {
    /// A mined replacement pays the same contract: move the coin onto it.
    Follow,
    /// Its coins went elsewhere for good: nothing is ever swept from it.
    Drop,
    /// Not decided yet.
    Wait,
}

/// What [`Wallet::retire_replaced_versions`] did with a swap's leftover versions.
#[derive(Debug, Default)]
pub(crate) struct Retirement {
    /// Contract outputs of the outgoing versions dropped, to unwatch.
    pub(crate) removed: Vec<(OutPoint, ScriptBuf)>,
    /// Versions still kept: not yet beaten deep enough.
    pub(crate) remaining: usize,
    /// One kept version's own funding is mined: a reorg made it the hop, and
    /// the swap needs recovering from it.
    pub(crate) revived: bool,
}

/// A funding version that a fee bump replaced, or that replaced another, is
/// dropped only once the spend that beat it is this many blocks deep: a reorg
/// that undoes a shallower one can still confirm the dropped version.
pub(crate) const REPLACED_VERSION_DISCARD_DEPTH: u64 = 6;

/// [`REPLACED_VERSION_DISCARD_DEPTH`], which a test can raise through
/// `OPENSWAP_REPLACED_VERSION_DISCARD_DEPTH` to keep a swap's replaced
/// versions around long enough to reorg one back in.
pub(crate) fn replaced_version_discard_depth() -> u64 {
    #[cfg(feature = "integration-test")]
    if let Some(depth) = std::env::var("OPENSWAP_REPLACED_VERSION_DISCARD_DEPTH")
        .ok()
        .and_then(|depth| depth.parse().ok())
    {
        return depth;
    }
    REPLACED_VERSION_DISCARD_DEPTH
}
/// script-path: sig+preimage+script+control_block (~154)
const TAPROOT_SCRIPTPATH_VSIZE: u64 = 155;
/// ≈141 + 1 (growing block-height)
const LEGACY_TIMELOCK_VSIZE: u64 = 142;
/// ≈138 + 2 (growing block-height)
const TAPROOT_TIMELOCK_VSIZE: u64 = 140;

/// Represents a Bitcoin wallet with associated functionality and data.
pub struct Wallet {
    pub(crate) blockchain: AnyBlockchain,
    pub(crate) wallet_file_path: PathBuf,
    pub(crate) store: WalletStore,
    /// Encryption material derived from the user’s passphrase. Wallet files
    /// are always encrypted; this key encrypts the store on disk and seals
    /// the master key in memory. The original passphrase is never stored —
    /// only the derived key is kept in memory.
    pub(crate) store_enc_material: KeyMaterial,
    /// Wallet-side set of outpoints excluded from coin selection.
    pub(crate) locked_utxos: HashSet<OutPoint>,
    /// Shared for library wallets, exclusive for daemons, held for the
    /// wallet's lifetime. `None` only offline.
    pub(crate) _in_use: Option<WalletInUse>,
}

/// Manual impl: `AnyBlockchain` (and the encryption material) carry no useful
/// or safe-to-print state, so only the file path and store are shown.
impl std::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wallet")
            .field("wallet_file_path", &self.wallet_file_path)
            .field("store", &self.store)
            .finish_non_exhaustive()
    }
}

/// Compares two wallets for cryptographic equivalence.
///
/// This comparison checks fields relevant to the cryptographic and functional
/// state of the wallet, intentionally excluding fields that are:
/// - related to file metadata (like `file_name`),
/// - transient or runtime-only (e.g., swap coins, sync height),
/// - dynamic (e.g., `prevout_to_contract_map`).
///
/// The fields checked include:
/// - `network`
/// - `master_key`
/// - `external_index`
/// - `offer_maxsize`
/// - `fidelity_bond`
/// - `wallet_birthday`
/// - `utxo_cache`
///
/// This allows comparing whether two wallets represent the same core cryptographic
/// identity and logic state, regardless of runtime or file system differences.
impl PartialEq for Wallet {
    fn eq(&self, other: &Self) -> bool {
        //self.store == other.store
        //avoided filename
        self.store.network == other.store.network &&
        // Compare the unsealed keys inside their wipe-on-return scopes.
        self.with_master_key(|a| other.with_master_key(|b| Ok(a == b)))
            .unwrap_or(false) &&
        self.store.external_index == other.store.external_index &&
        self.store.internal_index == other.store.internal_index &&
        self.store.offer_maxsize == other.store.offer_maxsize &&
        //avoided incoming_swapcoins
        //avoided outgoing_swapcoins
        //avoided prevout_to_contract_map
        self.store.fidelity_bond == other.store.fidelity_bond &&
        //avoided last_synced_height
        self.store.wallet_birthday == other.store.wallet_birthday &&
        self.store.utxo_cache == other.store.utxo_cache
    }
}

/// Specify the keychain derivation path from [`Wallet::get_derivation_path`]
/// Each kind represents an unhardened index value. Starting with External = 0.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub(crate) enum KeychainKind {
    External = 0isize,
    Internal,
}

impl KeychainKind {
    fn index_num(&self) -> u32 {
        match self {
            Self::External => 0,
            Self::Internal => 1,
        }
    }
}

/// Enum representing additional data needed to spend a UTXO, in addition to `ListUnspentResultEntry`.
// data needed to find information  in addition to ListUnspentResultEntry
// about a UTXO required to spend it
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum UTXOSpendInfo {
    /// Seed Coin (regular wallet UTXO from HD derivation)
    SeedCoin {
        /// HD derivation path for the private key
        path: String,
        /// UTXO value in satoshis
        input_value: Amount,
        /// Address type (P2WPKH or P2TR)
        #[serde(default)]
        address_type: AddressType,
    },
    /// Coins that we have received in a swap
    IncomingSwapCoin {
        /// Multisig redeem script for spending (2-OF-2 MSIG)
        multisig_redeemscript: ScriptBuf,
    },
    /// Coins that we have sent in a swap
    OutgoingSwapCoin {
        /// Multisig redeem script for spending (2-OF-2 MSIG)
        multisig_redeemscript: ScriptBuf,
    },
    /// Timelock contract UTXO (can be claimed after locktime expiry)
    TimelockContract {
        /// Original swap multisig redeem script
        swapcoin_multisig_redeemscript: ScriptBuf,
        /// UTXO value in satoshis
        input_value: Amount,
    },
    /// Hashlock contract UTXO (requires hash preimage to spend)
    HashlockContract {
        /// Original swap multisig redeem script
        swapcoin_multisig_redeemscript: ScriptBuf,
        /// UTXO value in satoshis
        input_value: Amount,
    },
    /// Fidelity Bond Coin (time-locked)
    FidelityBondCoin {
        /// Bond index in wallet's fidelity bond list
        index: u32,
        /// UTXO value in satoshis
        input_value: Amount,
    },
    /// Swept incoming swap coin (recovered to regular wallet address at the end of the Swap)
    SweptCoin {
        /// HD derivation path for the swept address
        path: String,
        /// UTXO value in satoshis
        input_value: Amount,
        /// Address type (P2WPKH or P2TR)
        #[serde(default)]
        address_type: AddressType,
    },
}

impl UTXOSpendInfo {
    /// Estimates Witness Size for different types of UTXOs in the context of OpenSwap
    pub fn estimate_witness_size(&self) -> usize {
        const P2WPKH_WITNESS_SIZE: usize = 107; // 1 + 72 (sig) + 33 (pubkey) + 1 (count)
        const P2TR_WITNESS_SIZE: usize = 66; // 1 (witness items) + 1 (Signature length) + 64 (Schnorr sig)
        const P2WSH_MULTISIG_2OF2_WITNESS_SIZE: usize = 218; //1 + 1 + 72 + 72 + 72
        const FIDELITY_BOND_WITNESS_SIZE: usize = 115; // 1 (count) + 1 (sig len) + 71 (sig) + 1 (script len) + 40 (script) = ~114
        match self {
            Self::SeedCoin { address_type, .. } | Self::SweptCoin { address_type, .. } => {
                match address_type {
                    AddressType::P2WPKH => P2WPKH_WITNESS_SIZE,
                    AddressType::P2TR => P2TR_WITNESS_SIZE,
                }
            }
            Self::IncomingSwapCoin { .. } | Self::OutgoingSwapCoin { .. } => {
                P2WSH_MULTISIG_2OF2_WITNESS_SIZE
            }
            Self::TimelockContract { .. } => 179,
            Self::HashlockContract { .. } => 211,
            Self::FidelityBondCoin { .. } => FIDELITY_BOND_WITNESS_SIZE,
        }
    }
}

/// Spend path of a swap transaction, for protocol-aware vsize estimation.
#[derive(Debug, Clone, Copy)]
pub(crate) enum SpendKind {
    /// Incoming swapcoin spend; `cooperative` = key-path/2-of-2 vs hashlock path.
    ContractSpend { cooperative: bool },
    /// Timelock recovery of an outgoing swapcoin.
    Timelock,
}

/// Per-swapcoin fee budget a PaySwap taker reserves on the final hop, priced
/// at the negotiated feerate and sized for the most expensive settlement
/// path: legacy publishes the contract tx and spends via hashlock; taproot is
/// the script-path spend. Cheaper paths pay the surplus as extra miner fee —
/// a change output back to the taker would link it to the settlement.
/// On the common cooperative path the taker
/// loses the worst-vs-cheap vsize gap per swapcoin: 43 vB for taproot
/// (key-path, 43 sats at the relay floor) and 150 vB for legacy
/// (2-of-2 spend, 150 sats).
pub(crate) fn payment_settlement_budget_sats(
    protocol: crate::protocol::ProtocolVersion,
    feerate: f64,
) -> Option<u64> {
    match protocol {
        crate::protocol::ProtocolVersion::Legacy => {
            fee_at_rate_sats(crate::protocol::contract::CONTRACT_TX_VSIZE, feerate).and_then(
                |contract_fee| {
                    fee_at_rate_sats(LEGACY_CONTRACT_SPEND_VSIZE, feerate)
                        .and_then(|spend_fee| contract_fee.checked_add(spend_fee))
                },
            )
        }
        crate::protocol::ProtocolVersion::Taproot => {
            fee_at_rate_sats(TAPROOT_SCRIPTPATH_VSIZE, feerate)
        }
    }
}

/// Smallest P2TR output value that is not dust: P2TR is the wallet's
/// highest-dust script and its change type.
pub(crate) fn p2tr_min_non_dust_sats() -> u64 {
    let p2tr = ScriptBuf::new_witness_program(
        &WitnessProgram::new(WitnessVersion::V1, &[0; 32]).expect("a 32-byte v1 program is valid"),
    );
    p2tr.minimal_non_dust().to_sat()
}

/// Smallest contract worth creating: it pays the costliest spend path at `feerate`
/// and still leaves a P2TR output, the wallet's highest-dust script, above dust.
pub fn min_contract_value_sats(protocol: ProtocolVersion, feerate: f64) -> Option<u64> {
    payment_settlement_budget_sats(protocol, feerate)?.checked_add(p2tr_min_non_dust_sats())
}

/// Returns the estimated vsize (virtual bytes) for cooperative keypath, preimage (hashlock),
/// and timelock recovery spend transactions only.
pub(crate) fn contract_and_timelock_vsize(
    protocol: crate::protocol::ProtocolVersion,
    kind: SpendKind,
) -> u64 {
    use crate::protocol::ProtocolVersion::{Legacy, Taproot};
    use SpendKind::{ContractSpend, Timelock};

    match (protocol, kind) {
        (Legacy, ContractSpend { .. }) => LEGACY_CONTRACT_SPEND_VSIZE,
        (Taproot, ContractSpend { cooperative: true }) => TAPROOT_KEYPATH_VSIZE,
        (Taproot, ContractSpend { cooperative: false }) => TAPROOT_SCRIPTPATH_VSIZE,
        (Legacy, Timelock) => LEGACY_TIMELOCK_VSIZE,
        (Taproot, Timelock) => TAPROOT_TIMELOCK_VSIZE,
    }
}

impl Display for UTXOSpendInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            UTXOSpendInfo::SeedCoin { .. } => {
                write!(f, "regular")
            }
            UTXOSpendInfo::SweptCoin { .. } => write!(f, "swept-incoming-swap"),
            UTXOSpendInfo::FidelityBondCoin { .. } => write!(f, "fidelity-bond"),
            UTXOSpendInfo::HashlockContract { .. } => write!(f, "hashlock-contract"),
            UTXOSpendInfo::TimelockContract { .. } => write!(f, "timelock-contract"),
            UTXOSpendInfo::IncomingSwapCoin { .. } => write!(f, "incoming-swap"),
            UTXOSpendInfo::OutgoingSwapCoin { .. } => write!(f, "outgoing-swap"),
        }
    }
}

pub(crate) fn infer_address_type(script_pubkey: &Script) -> AddressType {
    if script_pubkey.is_p2wpkh() {
        AddressType::P2WPKH
    } else {
        // P2TR and P2WSH both have 34-byte scriptpubkeys; default non-P2WPKH to P2TR.
        AddressType::P2TR
    }
}

/// Results of sweep/recovery operations with per-contract detail.
#[derive(Debug, Default, Clone)]
pub struct RecoveryOutcome {
    /// (contract_txid, spending_txid) for contracts we successfully spent.
    pub resolved: Vec<(Txid, Txid)>,
    /// Contract txids that were discarded (never broadcast, or their funding is gone).
    pub discarded: Vec<Txid>,
}

/// A spend sent by a recovery pass: (swapcoin key, contract txid, spending txid).
type SentSpend = (String, Txid, Txid);

/// What one [`Wallet::settle_unsent_funding`] pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct UnsentPass {
    /// Unsent funding still holds reserved inputs, waiting out the grace.
    pub(crate) waiting: bool,
    /// This pass gave reserved inputs back to the wallet.
    pub(crate) released: bool,
    /// Every outgoing coin was dead, so the swap was dropped.
    pub(crate) finished: bool,
}

/// Chain state of one swapcoin's contract output on a recovery pass.
#[derive(Debug, PartialEq, Eq)]
enum ContractChainState {
    /// The output is on-chain or was just broadcast; recovery can proceed.
    OnChain,
    /// The output is gone for good; the swapcoin can be dropped.
    Discarded,
    /// Our own timelock recovery already confirmed; record it as resolved.
    RecoveredByTimelock(Txid),
    /// Our own timelock recovery is out but unconfirmed; it can be replaced at
    /// a higher fee.
    RecoveryPending(Transaction),
    /// Nothing decided this pass; the next recovery run retries.
    NotYet,
}

/// True when `replacement_fee` beats `pending_fee` by what a node asks of a
/// replacement: `increment_rate` sat/vB over the replacement's own size.
fn outbids(
    pending_fee: Amount,
    replacement_fee: Amount,
    replacement_vsize: u64,
    increment_rate: f64,
) -> bool {
    fee_at_rate_sats(replacement_vsize, increment_rate)
        .and_then(|increment| pending_fee.checked_add(Amount::from_sat(increment)))
        .is_some_and(|needed| replacement_fee >= needed)
}

fn recovery_address_or_else<F>(
    stored: Option<Address<NetworkUnchecked>>,
    create: F,
) -> Result<(Address<NetworkUnchecked>, bool), WalletError>
where
    F: FnOnce() -> Result<Address<NetworkUnchecked>, WalletError>,
{
    match stored {
        Some(address) => Ok((address, false)),
        None => Ok((create()?, true)),
    }
}

impl RecoveryOutcome {
    /// Returns true if no contracts were resolved or discarded.
    pub fn is_empty(&self) -> bool {
        self.resolved.is_empty() && self.discarded.is_empty()
    }

    /// Total number of contracts handled (resolved + discarded).
    pub fn len(&self) -> usize {
        self.resolved.len() + self.discarded.len()
    }
}

/// Represents total wallet balances of different categories.
#[derive(Serialize, Deserialize, Debug)]
pub struct Balances {
    /// All single signature regular wallet coins (seed balance).
    pub regular: Amount,
    /// All 2of2 multisig coins received in swaps.
    pub swap: Amount,
    /// All live contract transaction balance locked in timelocks.
    pub contract: Amount,
    /// All coins locked in fidelity bonds.
    pub fidelity: Amount,
    /// Spendable amount in wallet (regular + swap balance).
    pub spendable: Amount,
}

impl Wallet {
    /// Initialize the wallet at a given path.
    ///
    /// The path should include the full path for a wallet file.
    /// If the wallet file doesn't exist it will create a new wallet file.
    /// `password` encrypts the file and seals the new seed phrase in it; read
    /// the phrase back with [`Wallet::get_wallet_mnemonic`].
    pub fn init(
        path: &Path,
        blockchain: AnyBlockchain,
        password: Zeroizing<String>,
    ) -> Result<Self, WalletError> {
        Self::init_with_lock(path, blockchain, password, WalletInUse::shared(path)?)
    }

    fn init_with_lock(
        path: &Path,
        blockchain: AnyBlockchain,
        password: Zeroizing<String>,
        in_use: WalletInUse,
    ) -> Result<Self, WalletError> {
        if password.is_empty() {
            return Err(WalletError::General(
                "a passphrase is required to create a wallet; \
                 cleartext wallet files are not supported"
                    .to_string(),
            ));
        }
        let network = blockchain.get_blockchain_info()?.chain;
        // Refuse old Core before a seed is generated or a wallet file is
        // written, whichever caller creates the wallet.
        if let AnyBlockchain::CoreRPC(core) = &blockchain {
            core.require_v22()?;
        }

        // Initialise wallet
        let file_name = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| {
                WalletError::General("wallet path has no valid UTF-8 file name".to_string())
            })?
            .to_string();

        // Network and key derivation come first: none of it runs while the phrase exists.
        let wallet_birthday = blockchain.get_block_count()?;
        let store_enc_material = KeyMaterial::new_from_password(Some(password.to_string()))
            .expect("a passphrase always yields key material");
        let mnemonic = Mnemonic::generate(12)?;
        let master_key = SecretXpriv(Self::master_key_from_mnemonic(&mnemonic, network)?);
        let sealed_mnemonic = seal_mnemonic(&mnemonic, &master_key.0, network, &password)?;
        drop(mnemonic);
        drop(password);
        // WalletStore::init seals the master key before the first write, so
        // the plaintext key never reaches disk. The phrase is in that write.
        let store = WalletStore::init_with(
            file_name,
            path,
            network,
            master_key.0,
            Some(wallet_birthday),
            None,
            &store_enc_material,
            |store| store.sealed_mnemonic = Some(sealed_mnemonic),
        )?;
        drop(master_key);
        log::info!(
            "Wallet birth_height = {wallet_birthday}, last_synced_height = {:?}",
            store.last_synced_height
        );
        log::warn!("{SEED_NOT_BACKED_UP}");
        Ok(Self {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material,
            locked_utxos: HashSet::new(),
            _in_use: Some(in_use),
        })
    }

    /// BIP39 seed to BIP32 master key, without the optional BIP39 passphrase
    pub(super) fn master_key_from_mnemonic(
        mnemonic: &Mnemonic,
        network: Network,
    ) -> Result<Xpriv, WalletError> {
        let seed = zeroize::Zeroizing::new(mnemonic.to_seed(""));
        Ok(Xpriv::new_master(network, seed.as_slice())?)
    }

    /// Get the wallet name
    pub fn get_name(&self) -> &str {
        &self.store.file_name
    }

    /// Verify the deniability proof for a specific swap stored in this wallet.
    pub fn verify_deniability(&self, swap_id: &str) -> Result<bool, std::io::Error> {
        verify_swap_proof(
            self.swap_reports().deniability_proofs,
            &self.blockchain,
            swap_id,
        )
    }

    /// Load wallet data from file and connect to a blockchain backend.
    /// In case of core rpc, core wallet name, and wallet_id field in the file should match.
    ///
    /// Wallet files are always written encrypted. Older files, including
    /// legacy plaintext, migrate under the supplied lock before backend setup.
    /// Opening an encrypted file requires the passphrase it was written with.
    pub(crate) fn load(
        path: &Path,
        blockchain: AnyBlockchain,
        password: Option<String>,
    ) -> Result<Self, WalletError> {
        let password = password.map(Zeroizing::new);
        let in_use = Self::shared_after_migration(path, password.as_ref())?;
        Self::load_with_lock(path, blockchain, password, in_use)
    }

    /// Takes the shared lock for a library load. An older file rewrites on
    /// first read, which no running process may overlap, so it migrates
    /// first under the exclusive lock, as `open_offline` does.
    fn shared_after_migration(
        path: &Path,
        password: Option<&Zeroizing<String>>,
    ) -> Result<WalletInUse, WalletError> {
        // Each reader takes its own copy and wipes it.
        let password = || password.filter(|p| !p.is_empty()).map(|p| p.to_string());
        if path.exists()
            && matches!(
                WalletStore::read_without_upgrade(path, password()),
                Ok(None)
            )
        {
            let Some(_owner) = WalletInUse::exclusive_if_idle(path)? else {
                return Err(WalletError::General(IN_USE_MESSAGE.to_string()));
            };
            match WalletStore::read_from_disk(path, password()) {
                // No passphrase: nothing was written, and the load reports it.
                Err(WalletError::Security(SecurityError::PasswordRequired)) => {}
                other => {
                    other?;
                }
            }
        }
        WalletInUse::shared(path)
    }

    fn load_with_lock(
        path: &Path,
        blockchain: AnyBlockchain,
        mut password: Option<Zeroizing<String>>,
        in_use: WalletInUse,
    ) -> Result<Self, WalletError> {
        if password.as_ref().is_some_and(|p| p.is_empty()) {
            password = None;
        }

        // The supplied guard is already held before reading or migrating.
        let (mut store, store_enc_material) =
            Self::read_store(path, password.as_mut().map(|p| std::mem::take(&mut **p)))?;
        // An older file may hold the key in plaintext; seal it before any backend call.
        store.master_key.seal(&store_enc_material)?;
        if let AnyBlockchain::CoreRPC(core) = &blockchain {
            if core.wallet_name() != store.file_name {
                return Err(WalletError::General(format!(
                    "Wallet name of database file and core mismatch, expected {}, found {}",
                    core.wallet_name(),
                    store.file_name
                )));
            }
        }
        let network = blockchain.get_blockchain_info()?.chain;

        // Check if the backend node is running on correct network. Or else hard error.
        if store.network != network {
            log::error!(
                "Wallet file is created for {}, backend is running on {}",
                store.network,
                network
            );
            return Err(WalletError::General("Wrong Bitcoin Network".to_string()));
        }
        log::debug!(
            "Loaded wallet file {} | External Index = {} | Incoming = {} | Outgoing = {}",
            store.file_name,
            store.external_index,
            store.incoming_swapcoins.len(),
            store.outgoing_swapcoins.len()
        );
        // The first restore writes the encrypted file before its scan. A file
        // without a saved tip must finish that scan before it is usable.
        if store.last_synced_height.is_none() {
            store
                .pending_restore
                .get_or_insert_with(RestoreOptions::default);
        }
        let wallet = Self {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material,
            locked_utxos: HashSet::new(),
            _in_use: Some(in_use),
        };
        wallet.warn_if_seed_not_backed_up();
        Ok(wallet)
    }

    /// Reads and decrypts the wallet file at `path`, refusing a missing
    /// passphrase. Does not touch the backend.
    fn read_store(
        path: &Path,
        password: Option<String>,
    ) -> Result<(WalletStore, KeyMaterial), WalletError> {
        match WalletStore::read_from_disk(path, password) {
            Ok(loaded) => Ok(loaded),
            // Encrypted file, no passphrase supplied. Report how to supply
            // one instead of failing decryption with an empty passphrase.
            Err(WalletError::Security(SecurityError::PasswordRequired)) => {
                Err(WalletError::General(format!(
                    "wallet file {path:?} is encrypted; \
                     provide the wallet passphrase via --password-file or -p"
                )))
            }
            Err(e) => Err(e),
        }
    }

    /// Loads an existing wallet from the given path or initializes a new one if none exists.
    ///
    /// Wallet files are always encrypted, so a passphrase is required both to
    /// open an existing wallet and to create a new one.
    pub(crate) fn load_or_init(
        path: &Path,
        blockchain: AnyBlockchain,
        password: Option<String>,
    ) -> Result<Wallet, WalletError> {
        let password = password.map(Zeroizing::new);
        let in_use = Self::shared_after_migration(path, password.as_ref())?;
        Self::load_or_init_with_lock(path, blockchain, password, in_use)
    }

    /// Consumes an already-held guard, so daemon startup reads, migrates and
    /// creates wallets under its one owner lock without taking a second fd.
    pub(crate) fn load_or_init_with_lock(
        path: &Path,
        blockchain: AnyBlockchain,
        password: Option<Zeroizing<String>>,
        in_use: WalletInUse,
    ) -> Result<Wallet, WalletError> {
        let wallet = if path.exists() {
            // wallet already exists, load the wallet. Refuse old Core first,
            // as `Wallet::init` does for a new wallet, so callers that start
            // without syncing get the minimum-version error up front.
            if let AnyBlockchain::CoreRPC(core) = &blockchain {
                core.require_v22()?;
            }
            let mut wallet = Self::load_with_lock(path, blockchain, password, in_use)?;
            if wallet.store.pending_restore.is_some() {
                log::warn!("Wallet at {path:?} has an unfinished first scan; resuming it");
                wallet.sync_and_save(&crate::utill::NO_SHUTDOWN)?;
            }
            log::info!("Wallet file at {path:?} successfully loaded.");
            wallet
        } else {
            // wallet doesn't exists at the given path, create a new one
            let wallet =
                Self::init_with_lock(path, blockchain, password.unwrap_or_default(), in_use)?;

            log::info!("New Wallet created at : {path:?}");
            wallet
        };

        Ok(wallet)
    }

    /// Creates a missing wallet for the CLI and saves its first tip. The seed
    /// phrase is sealed in the file; only a notice to back it up is logged.
    pub fn init_interactive(
        path: &Path,
        backend: &BackendConfig,
        password: Option<String>,
    ) -> Result<(), WalletError> {
        let mut password = password.map(Zeroizing::new);
        if path.exists() {
            // Check a given passphrase now, not on the next start. An older
            // file upgrades on that read, so only under the exclusive lock.
            if let Some(p) = password.as_ref().filter(|p| !p.is_empty()) {
                let check = || -> Result<(), WalletError> {
                    if WalletStore::read_without_upgrade(path, Some(p.to_string()))?.is_none() {
                        let Some(_owner) = WalletInUse::exclusive_if_idle(path)? else {
                            return Err(WalletError::General(IN_USE_MESSAGE.to_string()));
                        };
                        WalletStore::read_from_disk(path, Some(p.to_string()))?;
                    }
                    Ok(())
                };
                check().map_err(|e| {
                    WalletError::General(format!(
                        "wallet {path:?} already exists and could not be opened \
                         with the given passphrase: {e}"
                    ))
                })?;
            }
            return Ok(());
        }
        // `Wallet::init` refuses old Core before a wallet file and seed are written.
        let mut wallet = Self::load_or_init(
            path,
            AnyBlockchain::from_config(backend)?,
            password.as_mut().map(|p| std::mem::take(&mut **p)),
        )?;
        // Save a tip, or the next load resumes this wallet as an unfinished restore.
        wallet.sync_and_save(&crate::utill::NO_SHUTDOWN)
    }

    /// Persist wallet data to disk, creating missing parent directories and file as needed.
    pub(crate) fn save_to_disk(&self) -> Result<(), WalletError> {
        self.store
            .write_to_disk(&self.wallet_file_path, &self.store_enc_material)
    }

    /// Runs `f` with the plaintext master key, unsealing the in-memory key
    /// first and erasing the plaintext copy afterwards. The plaintext key
    /// must not escape the closure; derive whatever is needed inside it.
    pub(crate) fn with_master_key<T>(
        &self,
        f: impl FnOnce(&Xpriv) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        self.store
            .master_key
            .with_unlocked(&self.store_enc_material, f)
    }

    /// Runs `f` with the account-level Xpriv for `address_type`
    /// (`m/purpose'/coin_type'/0'`), erasing the account key afterwards.
    /// Prefer this over [`Wallet::with_master_key`] whenever an account key
    /// suffices — it shortens the master key's exposure and wipes the
    /// derived key too.
    pub(crate) fn with_account_key<T>(
        &self,
        address_type: AddressType,
        f: impl FnOnce(&Xpriv) -> Result<T, WalletError>,
    ) -> Result<T, WalletError> {
        let secp = crate::utill::global_secp();
        self.with_master_key(|master_key| {
            let account = SecretXpriv(master_key.derive_priv(
                secp,
                &Self::get_derivation_path(address_type, self.store.network),
            )?);
            f(&account.0)
        })
    }

    /// Adds a incoming swap coin to the wallet.
    pub(crate) fn add_incoming_swapcoin(&mut self, coin: &super::swapcoin::IncomingSwapCoin) {
        // Use contract txid as key to ensure each swapcoin has a unique entry,
        // even when multiple incoming swapcoins share the same swap_id.
        let key = coin.contract_tx.compute_txid().to_string();
        self.store
            .incoming_swapcoins
            .insert(key.clone(), coin.clone());
        log::info!(
            "Added incoming swapcoin to wallet store: {} (total: {})",
            key,
            self.store.incoming_swapcoins.len()
        );
    }

    /// Adds a outgoing swap coin to the wallet.
    pub(crate) fn add_outgoing_swapcoin(&mut self, coin: &super::swapcoin::OutgoingSwapCoin) {
        // Use contract txid as key to ensure each swapcoin has a unique entry,
        // even when multiple outgoing swapcoins share the same swap_id.
        let key = coin.contract_tx.compute_txid().to_string();
        let mut coin = coin.clone();
        // Both flags only ever go to `true`: a stale copy re-inserted must not
        // make a committed coin look unsent or forget a claimed incoming.
        if let Some(stored) = self.store.outgoing_swapcoins.get(&key) {
            coin.committed |= stored.committed;
            coin.incoming_claimed |= stored.incoming_claimed;
        }
        self.store.outgoing_swapcoins.insert(key.clone(), coin);
        log::info!(
            "Added outgoing swapcoin to wallet store: {} (total: {})",
            key,
            self.store.outgoing_swapcoins.len()
        );
    }

    /// Restarts the swap's unbroadcast grace and saves it, just before a
    /// funding send: a send that may still be in flight after a crash must get
    /// the whole grace, however long the sends before it took.
    pub(crate) fn restart_funding_grace(&mut self, swap_id: &str) -> Result<(), WalletError> {
        if let Some(locks) = self.store.swap_locks.get_mut(swap_id) {
            locks.reserved_at = now_secs();
            self.save_to_disk()?;
        }
        Ok(())
    }

    /// Saves a funding batch's swapcoins in one write: a crash must not leave
    /// half a batch. A failed save leaves none of it.
    pub(crate) fn save_funding_batch(
        &mut self,
        incoming: &[super::swapcoin::IncomingSwapCoin],
        outgoing: &[super::swapcoin::OutgoingSwapCoin],
    ) -> Result<(), WalletError> {
        let key = |tx: &Transaction| tx.compute_txid().to_string();
        let previous_incoming: Vec<_> = incoming
            .iter()
            .map(|coin| key(&coin.contract_tx))
            .map(|k| (k.clone(), self.store.incoming_swapcoins.get(&k).cloned()))
            .collect();
        let previous_outgoing: Vec<_> = outgoing
            .iter()
            .map(|coin| key(&coin.contract_tx))
            .map(|k| (k.clone(), self.store.outgoing_swapcoins.get(&k).cloned()))
            .collect();
        incoming
            .iter()
            .for_each(|coin| self.add_incoming_swapcoin(coin));
        outgoing
            .iter()
            .for_each(|coin| self.add_outgoing_swapcoin(coin));
        let saved = self.save_to_disk();
        if saved.is_err() {
            for (k, coin) in previous_incoming {
                match coin {
                    Some(coin) => self.store.incoming_swapcoins.insert(k, coin),
                    None => self.store.incoming_swapcoins.remove(&k),
                };
            }
            for (k, coin) in previous_outgoing {
                match coin {
                    Some(coin) => self.store.outgoing_swapcoins.insert(k, coin),
                    None => self.store.outgoing_swapcoins.remove(&k),
                };
            }
        }
        saved
    }

    /// Finds a incoming swap coin by swap_id.
    #[allow(dead_code)]
    pub(crate) fn find_incoming_swapcoin(
        &self,
        contract_txid: &str,
    ) -> Option<&super::swapcoin::IncomingSwapCoin> {
        self.store.incoming_swapcoins.get(contract_txid)
    }

    /// Finds a incoming swap coin by contract txid (mutable).
    pub(crate) fn find_incoming_swapcoin_mut(
        &mut self,
        contract_txid: &str,
    ) -> Option<&mut super::swapcoin::IncomingSwapCoin> {
        self.store.incoming_swapcoins.get_mut(contract_txid)
    }

    /// Finds a outgoing swap coin by multisig redeemscript.
    pub(crate) fn find_outgoing_swapcoin_by_multisig(
        &self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Option<&super::swapcoin::OutgoingSwapCoin> {
        for swapcoin in self.store.outgoing_swapcoins.values() {
            // Only check Legacy swapcoins which have my_pubkey and other_pubkey
            if swapcoin.protocol == crate::protocol::ProtocolVersion::Legacy {
                if let (Some(my_pubkey), Some(other_pubkey)) =
                    (swapcoin.my_pubkey, swapcoin.other_pubkey)
                {
                    let computed_script = create_multisig_redeemscript(&my_pubkey, &other_pubkey);
                    if &computed_script == multisig_redeemscript {
                        return Some(swapcoin);
                    }
                }
            }
        }
        None
    }

    /// Finds a incoming swap coin by multisig redeemscript.
    pub(crate) fn find_incoming_swapcoin_by_multisig(
        &self,
        multisig_redeemscript: &ScriptBuf,
    ) -> Option<&super::swapcoin::IncomingSwapCoin> {
        for swapcoin in self.store.incoming_swapcoins.values() {
            if swapcoin.protocol == crate::protocol::ProtocolVersion::Legacy {
                if let (Some(my_pubkey), Some(other_pubkey)) =
                    (swapcoin.my_pubkey, swapcoin.other_pubkey)
                {
                    let computed_script = create_multisig_redeemscript(&my_pubkey, &other_pubkey);
                    if &computed_script == multisig_redeemscript {
                        return Some(swapcoin);
                    }
                }
            }
        }
        None
    }

    /// Removes a incoming swap coin by contract txid.
    pub(crate) fn remove_incoming_swapcoin(
        &mut self,
        contract_txid: &str,
    ) -> Option<super::swapcoin::IncomingSwapCoin> {
        let removed = self.store.incoming_swapcoins.remove(contract_txid);
        if removed.is_some() {
            log::info!(
                "Removed incoming swapcoin from wallet store: {} (remaining: {})",
                contract_txid,
                self.store.incoming_swapcoins.len()
            );
        }
        removed
    }

    /// Adds watch-only swapcoins for a given swap.
    pub(crate) fn add_watchonly_swapcoins(
        &mut self,
        swap_id: &str,
        coins: Vec<super::swapcoin::WatchOnlySwapCoin>,
    ) {
        let count = coins.len();
        self.store
            .watchonly_swapcoins
            .entry(swap_id.to_string())
            .or_default()
            .extend(coins);
        log::info!("Added {} watch-only swapcoins for swap {}", count, swap_id);
    }

    /// True when this wallet talks to an Electrum server rather than Bitcoin Core.
    pub fn is_electrum(&self) -> bool {
        self.blockchain.is_electrum()
    }

    /// Gets the count of incoming swap coins.
    pub fn get_incoming_swapcoins_count(&self) -> usize {
        self.store.incoming_swapcoins.len()
    }

    /// Contract outpoint, timelock and saved refund address of each outgoing
    /// swapcoin, so an integration test can follow a refund on chain.
    #[cfg(feature = "integration-test")]
    pub fn outgoing_refund_targets(
        &self,
    ) -> Vec<(OutPoint, Option<u32>, Option<Address<NetworkUnchecked>>)> {
        self.store
            .outgoing_swapcoins
            .values()
            .map(|coin| {
                (
                    OutPoint::new(
                        coin.contract_tx.compute_txid(),
                        coin.get_contract_output_vout(),
                    ),
                    coin.get_timelock(),
                    coin.recovery_address.clone(),
                )
            })
            .collect()
    }

    /// Gets the count of outgoing swap coins.
    pub fn get_outgoing_swapcoins_count(&self) -> usize {
        self.store.outgoing_swapcoins.len()
    }

    /// Outgoing swap coins of `swap_id` recorded as funded: one per accepted
    /// or seen funding send, plus the taker's first coin, committed before its send.
    #[cfg(feature = "integration-test")]
    pub fn committed_outgoing_swapcoins_count(&self, swap_id: &str) -> usize {
        self.store
            .outgoing_swapcoins
            .values()
            .filter(|coin| coin.swap_id.as_deref() == Some(swap_id) && coin.committed)
            .count()
    }

    /// Returns persisted outgoing contract outpoints, optionally restricted to
    /// the supplied swaps.
    pub(crate) fn outgoing_contract_outpoints(
        &self,
        swap_scope: Option<&HashSet<String>>,
    ) -> Vec<(OutPoint, ScriptBuf)> {
        self.store
            .outgoing_swapcoins
            .values()
            .filter(|sc| {
                swap_scope.is_none_or(|ids| {
                    sc.swap_id
                        .as_ref()
                        .is_some_and(|swap_id| ids.contains(swap_id))
                })
            })
            .map(|sc| {
                let vout = sc.get_contract_output_vout();
                (
                    OutPoint {
                        txid: sc.contract_tx.compute_txid(),
                        vout,
                    },
                    sc.contract_tx.output[vout as usize].script_pubkey.clone(),
                )
            })
            .collect()
    }

    /// Returns persisted incoming contract outpoints, optionally restricted to
    /// the supplied swaps.
    pub(crate) fn incoming_contract_outpoints(
        &self,
        swap_scope: Option<&HashSet<String>>,
    ) -> Vec<(OutPoint, ScriptBuf)> {
        self.store
            .incoming_swapcoins
            .values()
            .filter(|sc| {
                swap_scope.is_none_or(|ids| {
                    sc.swap_id
                        .as_ref()
                        .is_some_and(|swap_id| ids.contains(swap_id))
                })
            })
            .map(|sc| {
                let vout = sc.get_contract_output_vout();
                (
                    OutPoint {
                        txid: sc.contract_tx.compute_txid(),
                        vout,
                    },
                    sc.contract_tx.output[vout as usize].script_pubkey.clone(),
                )
            })
            .collect()
    }

    /// Returns contract outpoints and their scriptPubKeys for all persisted
    /// watchonly swapcoins.
    pub(crate) fn watchonly_contract_outpoints(&self) -> Vec<(OutPoint, ScriptBuf)> {
        self.store
            .watchonly_swapcoins
            .values()
            .flatten()
            .filter_map(|sc| {
                let outpoint = sc.contract_outpoint();
                let output = sc.contract_tx.output.get(outpoint.vout as usize)?;
                Some((outpoint, output.script_pubkey.clone()))
            })
            .collect()
    }

    /// Remove a outgoing swapcoin by contract txid.
    pub(crate) fn remove_outgoing_swapcoin(
        &mut self,
        contract_txid: &str,
    ) -> Option<super::swapcoin::OutgoingSwapCoin> {
        let coin = self.store.outgoing_swapcoins.remove(contract_txid);
        if coin.is_some() {
            log::info!(
                "Removed outgoing swapcoin: {} (remaining: {})",
                contract_txid,
                self.store.outgoing_swapcoins.len()
            );
        }
        coin
    }

    /// Returns contract_txid keys of outgoing swapcoins matching a swap_id.
    pub(crate) fn outgoing_keys_for_swap(&self, swap_id: &str) -> Vec<String> {
        self.store
            .outgoing_swapcoins
            .iter()
            .filter(|(_, sc)| sc.swap_id.as_deref() == Some(swap_id))
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// The mined replacement of a Taproot incoming contract whose funding a fee
    /// bump replaced: a confirmed tx spending exactly the same coins and paying
    /// the same contract script once. Its keys and scripts are the contract's,
    /// so the coin is ours to claim there just as it was in the original.
    fn confirmed_taproot_replacement(
        chain: &AnyBlockchain,
        coin: &super::swapcoin::IncomingSwapCoin,
    ) -> Result<Option<Transaction>, WalletError> {
        if coin.protocol != ProtocolVersion::Taproot {
            return Ok(None);
        }
        let contract_txid = coin.contract_tx.compute_txid();
        if chain.tx_block_height(&contract_txid)?.is_some() {
            return Ok(None);
        }
        let Some(contract_output) = coin
            .contract_tx
            .output
            .get(coin.get_contract_output_vout() as usize)
        else {
            return Ok(None);
        };
        let Some(outpoint) = coin.contract_tx.input.first().map(|i| i.previous_output) else {
            return Ok(None);
        };
        let parent = match chain.get_raw_transaction(&outpoint.txid, None) {
            Ok(parent) if parent.compute_txid() == outpoint.txid => parent,
            Ok(_) => return Ok(None),
            Err(_) if chain.is_tx_unknown(&outpoint.txid)? => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(prevout) = parent.output.get(outpoint.vout as usize) else {
            return Ok(None);
        };
        let Some(spender) =
            chain.confirmed_spending_transaction(&outpoint, &prevout.script_pubkey)?
        else {
            return Ok(None);
        };
        let same_coins = spender.input.len() == coin.contract_tx.input.len()
            && coin.contract_tx.input.iter().all(|input| {
                spender
                    .input
                    .iter()
                    .any(|other| other.previous_output == input.previous_output)
            });
        let paying = spender
            .output
            .iter()
            .filter(|output| output.script_pubkey == contract_output.script_pubkey)
            .count();
        if spender.compute_txid() == contract_txid || !same_coins || paying != 1 {
            return Ok(None);
        }
        Ok(Some(spender))
    }

    /// What recovery does with an incoming coin whose contract output it cannot
    /// find: follow a mined Taproot replacement paying the same contract, drop
    /// one whose coins went elsewhere for good, else wait.
    fn judge_unseen_incoming(
        chain: &AnyBlockchain,
        coin: &super::swapcoin::IncomingSwapCoin,
    ) -> Result<UnseenIncoming, WalletError> {
        if coin.protocol != ProtocolVersion::Taproot
            || chain
                .tx_block_height(&coin.contract_tx.compute_txid())?
                .is_some()
        {
            return Ok(UnseenIncoming::Wait);
        }
        if !coin.replaced && Self::confirmed_taproot_replacement(chain, coin)?.is_some() {
            return Ok(UnseenIncoming::Follow);
        }
        if Self::replaced_by_confirmed_spend(
            chain,
            &coin.contract_tx,
            replaced_version_discard_depth(),
        )? {
            return Ok(UnseenIncoming::Drop);
        }
        Ok(UnseenIncoming::Wait)
    }

    /// Point each Taproot incoming swapcoin of `swap_id` at the mined version
    /// when a funding fee bump replaced its own, after a reorg or behind our
    /// back. Returns each moved coin's old contract txid and the coin now.
    pub(crate) fn follow_replaced_incoming(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        swap_id: &str,
    ) -> Result<Vec<(Txid, super::swapcoin::IncomingSwapCoin)>, WalletError> {
        let coins: Vec<_> = lock_debug!(wallet.read())
            .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?
            .store
            .incoming_swapcoins
            .values()
            .filter(|coin| {
                // A flagged copy stands for one version only; retirement
                // drops it once another version is mined deep.
                coin.protocol == ProtocolVersion::Taproot
                    && coin.swap_id.as_deref() == Some(swap_id)
                    && coin.spending_tx.is_none()
                    && !coin.replaced
            })
            .cloned()
            .collect();
        let mut moved = Vec::new();
        for coin in coins {
            let Some(replacement) = Self::confirmed_taproot_replacement(chain, &coin)? else {
                continue;
            };
            let script =
                &coin.contract_tx.output[coin.get_contract_output_vout() as usize].script_pubkey;
            let Some(amount) = replacement
                .output
                .iter()
                .find(|output| output.script_pubkey == *script)
                .map(|output| output.value)
            else {
                continue;
            };
            let old = coin.contract_tx.compute_txid();
            let mut followed = coin;
            followed.contract_txid = followed.contract_txid.map(|_| replacement.compute_txid());
            followed.contract_tx = replacement;
            followed.funding_amount = amount;
            moved.push((old, followed));
        }
        if !moved.is_empty() {
            let mut w = lock_debug!(wallet.write())
                .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;
            for (old, followed) in &moved {
                w.remove_incoming_swapcoin(&old.to_string());
                w.add_incoming_swapcoin(followed);
                log::warn!(
                    "Incoming contract {} of swap {} was replaced by {} worth {}; following it",
                    old,
                    swap_id,
                    followed.contract_tx.compute_txid(),
                    followed.funding_amount
                );
            }
            w.save_to_disk()?;
        }
        Ok(moved)
    }

    /// Whether `swap_id` has an outgoing coin whose funding is not known sent.
    pub(crate) fn has_unsent_funding(&self, swap_id: &str) -> bool {
        self.store
            .outgoing_swapcoins
            .values()
            .any(|coin| coin.swap_id.as_deref() == Some(swap_id) && !coin.committed)
    }

    /// Flag the swapcoins whose contract tx is one of `contract_txids` as
    /// funding versions a fee bump replaced, and save. Retirement acts only
    /// on these, and only these can come back revived.
    pub(crate) fn mark_replaced_versions(
        &mut self,
        contract_txids: &[Txid],
    ) -> Result<(), WalletError> {
        for txid in contract_txids {
            let key = txid.to_string();
            if let Some(coin) = self.store.outgoing_swapcoins.get_mut(&key) {
                coin.replaced = true;
            }
            if let Some(coin) = self.store.incoming_swapcoins.get_mut(&key) {
                coin.replaced = true;
            }
        }
        self.save_to_disk()
    }

    /// Drop the watch-only coins of `swap_id`, not saving.
    pub(crate) fn remove_watchonly_swapcoins(&mut self, swap_id: &str) {
        self.store.watchonly_swapcoins.remove(swap_id);
    }

    /// Keep retry state in memory when cleanup cannot be saved.
    pub(crate) fn remove_swap_coins_and_save(
        &mut self,
        swap_id: &str,
        remove_incoming: bool,
        remove_outgoing: bool,
    ) -> Result<(), WalletError> {
        let incoming: Vec<_> = if remove_incoming {
            self.incoming_keys_for_swap(swap_id)
                .into_iter()
                .filter_map(|key| {
                    self.store
                        .incoming_swapcoins
                        .remove(&key)
                        .map(|coin| (key, coin))
                })
                .collect()
        } else {
            Vec::new()
        };
        let outgoing: Vec<_> = if remove_outgoing {
            self.outgoing_keys_for_swap(swap_id)
                .into_iter()
                .filter_map(|key| {
                    self.store
                        .outgoing_swapcoins
                        .remove(&key)
                        .map(|coin| (key, coin))
                })
                .collect()
        } else {
            Vec::new()
        };
        let watchonly = if remove_outgoing {
            self.store.watchonly_swapcoins.remove(swap_id)
        } else {
            None
        };
        let reservation = self.store.swap_locks.remove(swap_id);
        if let Err(error) = self.save_to_disk() {
            self.store.incoming_swapcoins.extend(incoming);
            self.store.outgoing_swapcoins.extend(outgoing);
            if let Some(coins) = watchonly {
                self.store
                    .watchonly_swapcoins
                    .insert(swap_id.to_owned(), coins);
            }
            if let Some(reservation) = reservation {
                self.store
                    .swap_locks
                    .insert(swap_id.to_owned(), reservation);
            }
            return Err(error);
        }
        let mut remaining = self.store.outgoing_swapcoins.len() + outgoing.len();
        for (key, _) in &outgoing {
            remaining -= 1;
            log::info!(
                "Removed outgoing swapcoin: {} (remaining: {})",
                key,
                remaining
            );
        }
        Ok(())
    }

    /// Whether a confirmed transaction other than `tx` spends one of its
    /// inputs, deep enough that `tx` can never confirm.
    fn inputs_spent_elsewhere(
        chain: &AnyBlockchain,
        tx: &Transaction,
    ) -> Result<bool, WalletError> {
        // Only a spend buried deep: a fee bump's other versions spend these
        // very inputs, and a reorg that undoes a shallow one can still
        // confirm `tx`.
        Self::replaced_by_confirmed_spend(chain, tx, replaced_version_discard_depth())
    }

    /// On-chain swaps with stored recovery or watch-only coins.
    pub(crate) fn onchain_swap_ids(&self) -> HashSet<String> {
        self.store
            .incoming_swapcoins
            .values()
            .filter_map(|coin| coin.swap_id.clone())
            .chain(
                self.store
                    .outgoing_swapcoins
                    .values()
                    .filter_map(|coin| coin.swap_id.clone()),
            )
            .chain(self.store.watchonly_swapcoins.keys().cloned())
            .collect()
    }

    /// All persisted swaps that still own reservations.
    pub(crate) fn swap_ids(&self) -> HashSet<String> {
        let mut ids = self.onchain_swap_ids();
        ids.extend(self.store.ln_pending_swaps.keys().cloned());
        ids.extend(self.store.ln_maker_swaps.keys().cloned());
        ids
    }

    /// The confirmed tx spending `outpoint` and how many blocks deep it is.
    /// `None` when no confirmed spend is found, or the parent is unknown.
    fn confirmed_spend_depth(
        chain: &AnyBlockchain,
        outpoint: &OutPoint,
    ) -> Result<Option<(Txid, u64)>, WalletError> {
        let parent = match chain.get_raw_transaction(&outpoint.txid, None) {
            Ok(parent) if parent.compute_txid() == outpoint.txid => parent,
            Ok(_) => return Ok(None),
            // As in `check_funding_inputs_state`: only a genuinely absent
            // parent has nothing to check.
            Err(_) if chain.is_tx_unknown(&outpoint.txid)? => return Ok(None),
            Err(e) => return Err(e),
        };
        let Some(output) = parent.output.get(outpoint.vout as usize) else {
            return Ok(None);
        };
        let Some(spender) =
            chain.confirmed_spending_transaction(outpoint, &output.script_pubkey)?
        else {
            return Ok(None);
        };
        let spender_txid = spender.compute_txid();
        let Some(height) = chain.tx_block_height(&spender_txid)? else {
            return Ok(None);
        };
        let depth = chain.get_block_count()?.saturating_sub(height) + 1;
        Ok(Some((spender_txid, depth)))
    }

    /// Whether another tx than `tx` spent one of its inputs and is at least
    /// `min_depth` blocks deep: a replacement of it won for good, so `tx`
    /// never lands. A confirmed spend by `tx` itself, say mined since the
    /// caller last looked, is not one; nor is a shallower one, which a reorg
    /// can still undo.
    pub(crate) fn replaced_by_confirmed_spend(
        chain: &AnyBlockchain,
        tx: &Transaction,
        min_depth: u64,
    ) -> Result<bool, WalletError> {
        let txid = tx.compute_txid();
        for input in &tx.input {
            if Self::confirmed_spend_depth(chain, &input.previous_output)?
                .is_some_and(|(spender, depth)| spender != txid && depth >= min_depth)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// One pass over the funding versions a fee bump left behind for
    /// `swap_id` once the swap settled on another, the coins flagged
    /// `replaced`: each is dropped once the spend that beat it is
    /// [`REPLACED_VERSION_DISCARD_DEPTH`] deep, and kept before that, since a
    /// reorg can still confirm it and its refund needs the coin. Reads the
    /// chain with no wallet lock held.
    pub(crate) fn retire_replaced_versions(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        swap_id: &str,
    ) -> Result<Retirement, WalletError> {
        let (outgoing, incoming) = {
            let wallet = lock_debug!(wallet.read())
                .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;
            let of_swap = |id: &Option<String>| id.as_deref() == Some(swap_id);
            let outgoing: Vec<(String, Option<Transaction>, OutPoint, ScriptBuf)> = wallet
                .store
                .outgoing_swapcoins
                .iter()
                .filter(|(_, coin)| of_swap(&coin.swap_id) && coin.replaced)
                .map(|(key, coin)| {
                    let funding = match coin.protocol {
                        ProtocolVersion::Taproot => Some(coin.contract_tx.clone()),
                        ProtocolVersion::Legacy => coin.funding_tx.clone(),
                    };
                    let vout = coin.get_contract_output_vout();
                    let script = coin
                        .contract_tx
                        .output
                        .get(vout as usize)
                        .map(|output| output.script_pubkey.clone())
                        .unwrap_or_default();
                    (
                        key.clone(),
                        funding,
                        OutPoint::new(coin.contract_tx.compute_txid(), vout),
                        script,
                    )
                })
                .collect();
            // A Taproot incoming coin's contract tx is the maker's funding; a
            // Legacy copy carries the funding of the version it stands for.
            let incoming: Vec<(String, Option<Transaction>)> = wallet
                .store
                .incoming_swapcoins
                .iter()
                .filter(|(_, coin)| of_swap(&coin.swap_id) && coin.replaced)
                .map(|(key, coin)| {
                    let funding = match coin.protocol {
                        ProtocolVersion::Taproot => Some(coin.contract_tx.clone()),
                        ProtocolVersion::Legacy => coin.replaced_funding_tx.clone(),
                    };
                    (key.clone(), funding)
                })
                .collect();
            (outgoing, incoming)
        };

        // `Some(true)`: beaten deep, retire it. `Some(false)`: its own
        // funding is mined. `None`: keep it for now.
        let judge = |funding: Option<&Transaction>| -> Result<Option<bool>, WalletError> {
            let Some(funding) = funding else {
                return Ok(None);
            };
            if Self::replaced_by_confirmed_spend(chain, funding, replaced_version_discard_depth())?
            {
                return Ok(Some(true));
            }
            Ok(chain
                .tx_block_height(&funding.compute_txid())?
                .map(|_| false))
        };
        let mut retirement = Retirement::default();
        let mut retire_outgoing = Vec::new();
        let mut retire_incoming = Vec::new();
        for (key, funding, outpoint, script) in &outgoing {
            match judge(funding.as_ref())? {
                Some(true) => {
                    retire_outgoing.push(key.clone());
                    retirement.removed.push((*outpoint, script.clone()));
                }
                verdict => {
                    retirement.revived |= verdict == Some(false);
                    retirement.remaining += 1;
                }
            }
        }
        for (key, funding) in &incoming {
            match judge(funding.as_ref())? {
                Some(true) => retire_incoming.push(key.clone()),
                verdict => {
                    retirement.revived |= verdict == Some(false);
                    retirement.remaining += 1;
                }
            }
        }
        if retire_outgoing.is_empty() && retire_incoming.is_empty() {
            return Ok(retirement);
        }
        let mut wallet = lock_debug!(wallet.write())
            .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;
        for key in &retire_outgoing {
            wallet.remove_outgoing_swapcoin(key);
        }
        for key in &retire_incoming {
            wallet.remove_incoming_swapcoin(key);
        }
        wallet.save_to_disk()?;
        log::info!(
            "Retired {} funding version(s) of swap {} that another version beat for good",
            retire_outgoing.len() + retire_incoming.len(),
            swap_id
        );
        Ok(retirement)
    }

    /// Returns contract_txid keys of incoming swapcoins matching a swap_id.
    pub(crate) fn incoming_keys_for_swap(&self, swap_id: &str) -> Vec<String> {
        self.store
            .incoming_swapcoins
            .iter()
            .filter(|(_, sc)| sc.swap_id.as_deref() == Some(swap_id))
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Ensure a swapcoin's contract tx is on-chain, broadcasting it when needed.
    ///
    /// Every answer comes from a chain query, never from parsing backend error
    /// strings; a transport failure reaches the caller instead of reading as
    /// "output spent".
    fn ensure_contract_on_chain(
        chain: &AnyBlockchain,
        swap_id: &str,
        swapcoin: &super::swapcoin::OutgoingSwapCoin,
    ) -> Result<ContractChainState, WalletError> {
        // An uncommitted coin's funding never went out, or its send failed.
        // Recovery never sends it, but a failed send can still propagate:
        // funding the backend has seen is treated as sent.
        if !swapcoin.committed && !Self::funding_seen(chain, swapcoin)? {
            return Self::unsent_funding_state(chain, swap_id, swapcoin);
        }
        let contract_txid = swapcoin.contract_tx.compute_txid();
        let contract_vout = swapcoin.get_contract_output_vout();
        if chain
            .get_tx_out(&contract_txid, contract_vout, Some(false))?
            .is_some()
        {
            // Core's confirmed view keeps an output that a mempool tx spends.
            // Electrum's drops it, and reaches the same lookup below.
            if chain
                .get_tx_out(&contract_txid, contract_vout, Some(true))?
                .is_none()
            {
                return Ok(match Self::pending_own_recovery(chain, swapcoin)? {
                    Some(pending) => ContractChainState::RecoveryPending(pending),
                    // The other side's claim is in the mempool. A refund would
                    // conflict with it, and would give up our incoming claim
                    // for a swap that is settling by hashlock.
                    None => ContractChainState::NotYet,
                });
            }
            return Ok(ContractChainState::OnChain);
        }
        if chain.tx_block_height(&contract_txid)?.is_some() {
            let outpoint = OutPoint::new(contract_txid, contract_vout);
            let script = &swapcoin.contract_tx.output[contract_vout as usize].script_pubkey;
            // Look only at the mined spender: Electrum history can list an
            // unconfirmed conflict, such as a replaced recovery, ahead of it.
            match chain.confirmed_spending_transaction(&outpoint, script)? {
                // Our own timelock recovery whose bookkeeping was lost to a
                // crash or a failed confirmation wait.
                Some(recovery) if swapcoin.is_own_timelock_spend(&recovery) => {
                    let recovery_txid = recovery.compute_txid();
                    log::info!(
                        "Contract output for {} already spent by our confirmed timelock recovery {} — recording as resolved",
                        swap_id,
                        recovery_txid
                    );
                    return Ok(ContractChainState::RecoveredByTimelock(recovery_txid));
                }
                // The other side claimed it, and that spend may carry the preimage
                // we still need. Keep the coin until the swap settles.
                Some(_) => {
                    log::info!(
                        "Contract output for {} claimed by a confirmed tx — keeping swapcoin",
                        swap_id
                    );
                }
                None => {
                    if let Some(pending) = Self::pending_own_recovery(chain, swapcoin)? {
                        return Ok(ContractChainState::RecoveryPending(pending));
                    }
                }
            }
            return Ok(ContractChainState::NotYet);
        }
        let funding = if swapcoin.protocol == ProtocolVersion::Taproot {
            Some(&swapcoin.contract_tx)
        } else {
            swapcoin.funding_tx.as_ref()
        };
        // An absent committed funding tx may still confirm from another node.
        // Only a confirmed conflicting spend proves it cannot return: of a
        // funding input, or of the funding output a legacy contract spends.
        let funding_dead = match funding {
            Some(funding) => {
                chain.tx_block_height(&funding.compute_txid())?.is_none()
                    && Self::inputs_spent_elsewhere(chain, funding)?
            }
            None => false,
        };
        if funding_dead
            || (swapcoin.protocol == ProtocolVersion::Legacy
                && Self::inputs_spent_elsewhere(chain, &swapcoin.contract_tx)?)
        {
            log::info!(
                "Funding for {} was confirmed spent elsewhere, discarding swapcoin",
                swap_id
            );
            return Ok(ContractChainState::Discarded);
        }
        let signed_contract = match swapcoin.create_signed_contract_tx() {
            Ok(tx) => tx,
            Err(e) => {
                log::warn!(
                    "Failed to sign contract tx for {}: {:?} — keeping committed coin",
                    swap_id,
                    e
                );
                return Ok(ContractChainState::NotYet);
            }
        };
        // Eviction, or a crash before the batch's first send, leaves committed
        // legacy funding unknown, and its contract can't go out without it.
        // An uncommitted coin's funding is known by now. Only sent once
        // the contract is signed, so the funds can always come back.
        if let Some(funding) = funding.filter(|_| swapcoin.protocol == ProtocolVersion::Legacy) {
            if chain.is_tx_unknown(&funding.compute_txid())? {
                if let Err(e) = chain.send_raw_transaction(funding) {
                    log::warn!("Failed to resend funding tx for {}: {:?}", swap_id, e);
                }
            }
        }
        if let Err(e) = chain.send_raw_transaction(&signed_contract) {
            if chain
                .get_tx_out(&contract_txid, contract_vout, Some(true))?
                .is_some()
            {
                return Ok(ContractChainState::OnChain);
            }
            log::warn!(
                "Failed to broadcast contract tx for {}: {:?} — retrying next cycle",
                swap_id,
                e
            );
            return Ok(ContractChainState::NotYet);
        }
        Ok(ContractChainState::OnChain)
    }

    /// Whether the backend knows this coin's funding (mempool or chain): the
    /// contract tx itself, or for Legacy the funding tx its contract spends.
    fn funding_seen(
        chain: &AnyBlockchain,
        swapcoin: &super::swapcoin::OutgoingSwapCoin,
    ) -> Result<bool, WalletError> {
        if !chain.is_tx_unknown(&swapcoin.contract_tx.compute_txid())? {
            return Ok(true);
        }
        if swapcoin.protocol == ProtocolVersion::Legacy {
            if let Some(input) = swapcoin.contract_tx.input.first() {
                return Ok(!chain.is_tx_unknown(&input.previous_output.txid)?);
            }
        }
        Ok(false)
    }

    /// An uncommitted coin whose funding the backend has not seen. No peer
    /// holds that funding signed: Legacy hands it out without witnesses, and
    /// Taproot sends its contract data after the batch. So, as for master's
    /// unshared funding, the coin is dropped once its funding is dead, or
    /// while every input it spends is unspent: then only we could send it,
    /// and we never will. An input spent by a tx the backend cannot name
    /// keeps the coin, unsent, until that resolves.
    fn unsent_funding_state(
        chain: &AnyBlockchain,
        swap_id: &str,
        swapcoin: &super::swapcoin::OutgoingSwapCoin,
    ) -> Result<ContractChainState, WalletError> {
        if let Some(funding) = Self::own_funding(swapcoin) {
            if Self::inputs_spent_elsewhere(chain, funding)? {
                log::info!(
                    "Unsent funding for {} was confirmed spent elsewhere, discarding swapcoin",
                    swap_id
                );
                return Ok(ContractChainState::Discarded);
            }
            for input in &funding.input {
                let prev = input.previous_output;
                if chain
                    .get_tx_out(&prev.txid, prev.vout, Some(true))?
                    .is_none()
                {
                    log::info!(
                        "Unsent funding for {} has an input spent by an unknown tx, keeping swapcoin",
                        swap_id
                    );
                    return Ok(ContractChainState::NotYet);
                }
            }
        }
        log::info!(
            "Funding for {} was never broadcast and its inputs are unspent, discarding swapcoin",
            swap_id
        );
        Ok(ContractChainState::Discarded)
    }

    /// The tx our own wallet sends for this coin: Legacy's funding tx, or
    /// Taproot's contract tx, which is its funding.
    fn own_funding(swapcoin: &super::swapcoin::OutgoingSwapCoin) -> Option<&Transaction> {
        match swapcoin.protocol {
            ProtocolVersion::Taproot => Some(&swapcoin.contract_tx),
            ProtocolVersion::Legacy => swapcoin.funding_tx.as_ref(),
        }
    }

    /// One maker pass over the uncommitted outgoing coins of `swap_id`: their
    /// funding was never sent, or its send failed. Seen funding is recorded as
    /// sent. Funding whose input a named tx spent in a block can never confirm,
    /// so its coin is dropped, and the whole swap once no outgoing coin is
    /// left. Any other coin is kept and watched; past the grace its inputs go
    /// back to the wallet. Nothing is ever broadcast here.
    pub(crate) fn settle_unsent_funding(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        swap_id: &str,
        grace_over: bool,
    ) -> Result<UnsentPass, WalletError> {
        let unsent: Vec<(String, super::swapcoin::OutgoingSwapCoin)> = lock_debug!(wallet.read())
            .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?
            .store
            .outgoing_swapcoins
            .iter()
            .filter(|(_, coin)| coin.swap_id.as_deref() == Some(swap_id) && !coin.committed)
            .map(|(key, coin)| (key.clone(), coin.clone()))
            .collect();
        // A failed query is no proof of absence: it frees nothing this pass,
        // but what the other queries proved is still saved, so a seen funding
        // evicted later is never taken for unsent.
        let mut seen = Vec::new();
        let mut dead = Vec::new();
        let mut unknown = Vec::new();
        let mut failure = None;
        for (key, coin) in unsent {
            let funding = Self::own_funding(&coin);
            let inputs: Vec<OutPoint> = funding
                .map(|tx| tx.input.iter().map(|input| input.previous_output).collect())
                .unwrap_or_default();
            let dead_funding =
                || funding.map_or(Ok(false), |tx| Self::inputs_spent_elsewhere(chain, tx));
            match Self::funding_seen(chain, &coin) {
                Ok(true) => seen.push(key),
                Ok(false) => match dead_funding() {
                    Ok(true) => dead.push((key, inputs)),
                    Ok(false) => unknown.extend(inputs),
                    Err(e) => failure = Some(e),
                },
                Err(e) => failure = Some(e),
            }
        }

        let mut w = lock_debug!(wallet.write())
            .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;
        let mut pass = UnsentPass::default();
        if !dead.is_empty() && w.outgoing_keys_for_swap(swap_id).len() == dead.len() {
            log::info!(
                "Funding for {} was confirmed spent elsewhere, dropping the kept swap",
                swap_id
            );
            w.remove_swap_coins_and_save(swap_id, true, true)?;
            pass.finished = true;
            return Ok(pass);
        }
        let previous_outgoing = w.store.outgoing_swapcoins.clone();
        let previous_locks = w
            .store
            .swap_locks
            .get(swap_id)
            .map(|locks| (locks.outpoints.clone(), locks.reserved_at));
        for key in &seen {
            if let Some(coin) = w.store.outgoing_swapcoins.get_mut(key) {
                log::info!(
                    "Funding of {} for {} was seen; recording it as sent",
                    key,
                    swap_id
                );
                coin.committed = true;
            }
        }
        for (key, inputs) in &dead {
            log::info!(
                "Funding of {} for {} was confirmed spent elsewhere, dropping its swapcoin",
                key,
                swap_id
            );
            w.store.outgoing_swapcoins.remove(key);
            w.release_swap_locks(swap_id, Some(inputs));
        }
        let holding = w
            .store
            .swap_locks
            .get(swap_id)
            .is_some_and(|locks| unknown.iter().any(|input| locks.outpoints.contains(input)));
        if holding && grace_over && failure.is_none() {
            pass.released = w.release_swap_locks(swap_id, Some(&unknown));
        } else {
            pass.waiting = holding;
        }
        if !seen.is_empty() || !dead.is_empty() || pass.released {
            if let Err(e) = w.save_to_disk() {
                w.store.outgoing_swapcoins = previous_outgoing;
                match previous_locks {
                    Some((outpoints, reserved_at)) => {
                        w.store.swap_locks.insert(
                            swap_id.to_owned(),
                            SwapReservation {
                                outpoints,
                                reserved_at,
                            },
                        );
                    }
                    None => {
                        w.store.swap_locks.remove(swap_id);
                    }
                }
                return Err(e);
            }
        }
        match failure {
            Some(e) => Err(e),
            None => Ok(pass),
        }
    }

    /// Our own timelock recovery spending the contract output from the mempool.
    ///
    /// Read from the backend on every pass rather than stored with the coin: a
    /// stored txid goes stale once the tx is evicted or replaced.
    fn pending_own_recovery(
        chain: &AnyBlockchain,
        swapcoin: &super::swapcoin::OutgoingSwapCoin,
    ) -> Result<Option<Transaction>, WalletError> {
        let outpoint = OutPoint::new(
            swapcoin.contract_tx.compute_txid(),
            swapcoin.get_contract_output_vout(),
        );
        let Some(output) = swapcoin.contract_tx.output.get(outpoint.vout as usize) else {
            return Ok(None);
        };
        Ok(chain
            .spending_transaction(&outpoint, &output.script_pubkey, None)?
            .filter(|tx| swapcoin.is_own_timelock_spend(tx)))
    }

    /// Attempt to recover timelocked outgoing swapcoins.
    ///
    /// The caller supplies the backend connection: the confirmation wait runs
    /// on it with no wallet guard held, so a slow tx cannot wedge the wallet.
    /// Without `swap_scope` every eligible outgoing swapcoin is considered.
    /// The callback is ignored and kept so callers still compile; each coin's
    /// saved `committed` flag now decides.
    pub fn recover_timelocked_swapcoins(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        swap_scope: Option<&HashSet<String>>,
        _funding_shared_with_peer: &dyn Fn(Option<&str>) -> bool,
    ) -> Result<RecoveryOutcome, WalletError> {
        let (refunds, discarded) = Self::broadcast_timelock_recoveries(
            wallet,
            chain,
            shutdown,
            swap_scope,
            &|_| false,
            &|_| false,
            &mut false,
            true,
        )?;
        Ok(Self::finish_recoveries(
            wallet,
            chain,
            shutdown,
            Vec::new(),
            refunds,
            discarded,
            Some(SwapRole::Maker),
        )?
        .1)
    }

    /// Broadcasts every ready timelock refund without waiting on any of them.
    /// Returns the refunds sent and the outgoing swapcoins to discard.
    ///
    /// Feerates come from our own backend: the peer that abandoned the swap
    /// does not get to price our refund.
    ///
    /// `claimed_by_hashlock` names swaps whose incoming coin we claimed. Their
    /// outgoing coins are the first maker's to claim with the preimage, so they
    /// are refunded only once that can provably never happen. `claim_proven`
    /// is the part of those with real evidence of a claim; only such a swap
    /// keeps its preimage when it is refunded.
    ///
    /// `synced` skips the wallet sync when the pass already ran one, and is set
    /// once this call syncs.
    ///
    /// `keep_unsent` leaves an unsent coin to [`Self::settle_unsent_funding`]:
    /// the maker keeps its keys in case that funding still confirms.
    #[allow(clippy::too_many_arguments)]
    fn broadcast_timelock_recoveries(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        swap_scope: Option<&HashSet<String>>,
        claimed_by_hashlock: &dyn Fn(&str) -> bool,
        claim_proven: &dyn Fn(&str) -> bool,
        synced: &mut bool,
        keep_unsent: bool,
    ) -> Result<(Vec<SentSpend>, Vec<String>), WalletError> {
        // Snapshot everything the recovery needs, then drop the guard before any backend call.
        let candidates = {
            let mut w = lock_debug!(wallet.write())
                .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;

            let candidates: Vec<_> = w
                .store
                .outgoing_swapcoins
                .iter()
                .filter(|(_, sc)| sc.my_privkey.is_some())
                .filter(|(_, sc)| {
                    swap_scope.is_none_or(|ids| {
                        sc.swap_id
                            .as_ref()
                            .is_some_and(|swap_id| ids.contains(swap_id))
                    })
                })
                .filter_map(|(swap_id, sc)| {
                    sc.get_timelock()
                        .map(|timelock| (swap_id.clone(), sc.clone(), timelock))
                })
                .collect();

            if candidates.is_empty() {
                return Ok((Vec::new(), Vec::new()));
            }

            if !*synced {
                w.sync_and_save(shutdown)?;
                *synced = true;
            }

            candidates
        };

        let current_height = chain.get_block_count()? as u32;

        log::info!(
            "recover_timelocked: {} outgoing swapcoins in store at height {}",
            candidates.len(),
            current_height
        );

        let mut to_recover = Vec::new();

        for (swap_id, swapcoin, timelock) in candidates {
            if !swapcoin.committed {
                to_recover.push((swap_id, swapcoin, timelock));
            } else if swapcoin.protocol == crate::protocol::ProtocolVersion::Taproot {
                // Taproot uses CLTV (absolute height).
                if current_height >= timelock {
                    log::info!(
                        "Outgoing swapcoin {} ready for timelock recovery (current: {}, CLTV: {})",
                        swap_id,
                        current_height,
                        timelock
                    );
                    to_recover.push((swap_id, swapcoin, timelock));
                } else {
                    log::debug!(
                        "Outgoing swapcoin {} not yet ready (current: {}, CLTV: {})",
                        swap_id,
                        current_height,
                        timelock
                    );
                }
            } else {
                // Legacy uses CSV (relative to contract tx confirmation).
                // Can't filter by height alone — the confirmation count
                // check below is the real gate.
                log::debug!(
                    "Outgoing swapcoin {} queued for timelock recovery (CSV: {} blocks)",
                    swap_id,
                    timelock
                );
                to_recover.push((swap_id, swapcoin, timelock));
            }
        }

        let mut discarded = Vec::new();
        let mut refunds = Vec::new();
        let mut fee_rates = None;

        for (swap_id, mut swapcoin, timelock) in to_recover {
            // One failing coin must not hold back the other coins' refunds.
            if let Err(e) = (|| -> Result<(), WalletError> {
                // Funding the backend has seen was sent. Commit the coin for
                // good, so a later eviction cannot make it look unsent.
                let commit_seen = |swapcoin: &mut super::swapcoin::OutgoingSwapCoin| {
                    let mut w = lock_debug!(wallet.write())
                        .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;
                    if let Some(stored) = w.store.outgoing_swapcoins.get_mut(&swap_id) {
                        stored.committed = true;
                    }
                    w.save_to_disk()?;
                    swapcoin.committed = true;
                    Ok::<_, WalletError>(())
                };
                // One classification per pass: an uncommitted coin whose funding
                // the backend has not seen goes straight to the unsent-funding
                // rules (never sent, kept while an input is spent by an unknown
                // tx). Seen funding is recorded as sent before any further work,
                // so the probe inside ensure_contract_on_chain is never reached
                // for an uncommitted coin.
                let state = if swapcoin.committed {
                    Self::ensure_contract_on_chain(chain, &swap_id, &swapcoin)?
                } else if Self::funding_seen(chain, &swapcoin)? {
                    commit_seen(&mut swapcoin)?;
                    Self::ensure_contract_on_chain(chain, &swap_id, &swapcoin)?
                } else if keep_unsent {
                    ContractChainState::NotYet
                } else {
                    Self::unsent_funding_state(chain, &swap_id, &swapcoin)?
                };
                let contract_txid = swapcoin.contract_tx.compute_txid();
                let contract_vout = swapcoin.get_contract_output_vout();
                match state {
                    // An uncommitted coin skipped the CLTV gate above.
                    ContractChainState::OnChain
                        if swapcoin.protocol == ProtocolVersion::Taproot
                            && current_height < timelock =>
                    {
                        return Ok(());
                    }
                    ContractChainState::OnChain => {}
                    ContractChainState::Discarded => {
                        discarded.push(swap_id.clone());
                        return Ok(());
                    }
                    // Already mined, so the shared wait returns at once and records it.
                    ContractChainState::RecoveredByTimelock(recovery_txid) => {
                        refunds.push((swap_id.clone(), contract_txid, recovery_txid));
                        return Ok(());
                    }
                    // Replaces our stuck refund once current rates beat it by the relay
                    // step. Pays the saved recovery address, never one read off the
                    // backend's tx. An unreplaced refund is recorded once mined.
                    ContractChainState::RecoveryPending(pending) => {
                        let Some(address) = swapcoin.recovery_address.as_ref() else {
                            log::debug!(
                                "Not fee-bumping refund {} for swap {}: no stored recovery address",
                                pending.compute_txid(),
                                swap_id
                            );
                            return Ok(());
                        };
                        let Some(contract_output) =
                            swapcoin.contract_tx.output.get(contract_vout as usize)
                        else {
                            return Ok(());
                        };
                        let fee_of = |tx: &Transaction| {
                            tx.output
                                .iter()
                                .try_fold(Amount::ZERO, |sum, output| sum.checked_add(output.value))
                                .and_then(|paid| contract_output.value.checked_sub(paid))
                        };
                        let fee_rates = fee_rates.get_or_insert_with(|| chain.recovery_feerates());
                        let replacement = Self::create_timelock_recovery_tx(
                            &swapcoin,
                            fee_rates,
                            address.clone().assume_checked(),
                        )?;
                        let (Some(pending_fee), Some(fee)) =
                            (fee_of(&pending), fee_of(&replacement))
                        else {
                            return Ok(());
                        };
                        let increment = chain.replacement_increment_rate();
                        if outbids(pending_fee, fee, replacement.vsize() as u64, increment) {
                            match chain.send_raw_transaction(&replacement) {
                                Ok(txid) => {
                                    log::info!(
                                        "Replaced timelock recovery tx {} with {} at a higher fee",
                                        pending.compute_txid(),
                                        txid
                                    );
                                    refunds.push((swap_id.clone(), contract_txid, txid));
                                }
                                Err(e) => log::warn!(
                                    "Failed to replace timelock recovery tx {}: {:?}",
                                    pending.compute_txid(),
                                    e
                                ),
                            }
                        }
                        return Ok(());
                    }
                    ContractChainState::NotYet => return Ok(()),
                }

                // Verify the contract UTXO is confirmed and the timelock is satisfied.
                //
                // Legacy uses BIP68 CSV (relative): the recovery tx sets
                // Sequence::from_height(timelock), requiring `timelock` confirmations.
                //
                // Taproot uses BIP65 CLTV (absolute): the recovery tx sets
                // nLockTime to the absolute height. We just need the UTXO to be
                // confirmed (at least 1 confirmation).
                let required_confirmations =
                    if swapcoin.protocol == crate::protocol::ProtocolVersion::Taproot {
                        1 // CLTV only needs the UTXO to exist; the height check is above
                    } else {
                        timelock // CSV needs this many confirmations
                    };
                match chain.get_tx_out(&contract_txid, contract_vout, Some(false)) {
                    Ok(Some(utxo_info)) if utxo_info.confirmations >= required_confirmations => {
                        log::info!(
                            "Contract tx {} has {} confirmations (need {}), proceeding with recovery",
                            contract_txid,
                            utxo_info.confirmations,
                            required_confirmations
                        );
                    }
                    Ok(Some(utxo_info)) => {
                        log::info!(
                            "Contract tx {} has {} confirmations, need {} — waiting",
                            contract_txid,
                            utxo_info.confirmations,
                            required_confirmations
                        );
                        return Ok(());
                    }
                    Ok(None) => {
                        log::info!(
                            "Contract tx {} not yet confirmed, skipping recovery attempt",
                            contract_txid
                        );
                        return Ok(());
                    }
                    Err(e) => return Err(e),
                }

                // The first maker learns the preimage only from a spend of its own
                // outgoing: the first hops, all at the one locktime we gave it.
                // Once each went back by timelock, our outgoing is left dangling.
                let claimed = swapcoin.swap_id.as_deref().is_some_and(claimed_by_hashlock);
                let proven = swapcoin.swap_id.as_deref().is_some_and(claim_proven);
                if let Some(swap_id) = swapcoin.swap_id.as_deref().filter(|_| claimed) {
                    let hops = lock_debug!(wallet.read())
                        .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?
                        .store
                        .watchonly_swapcoins
                        .get(swap_id)
                        .cloned()
                        .unwrap_or_default();
                    let timelock = |hop: &WatchOnlySwapCoin| {
                        contract_timelock(
                            hop.protocol,
                            Some(&hop.contract_redeemscript),
                            hop.timelock_script.as_deref(),
                        )
                    };
                    let first_maker_lock = hops.first().and_then(timelock);
                    // A fee-bumped hop is kept in every version, and only one
                    // of them ever exists: a contract is refunded once any of
                    // its versions is. Versions share every script and key.
                    let mut refunded: Vec<(&WatchOnlySwapCoin, bool)> = Vec::new();
                    for hop in hops.iter().filter(|hop| timelock(hop) == first_maker_lock) {
                        let outpoint = hop.contract_outpoint();
                        let spent = match hop.contract_tx.output.get(outpoint.vout as usize) {
                            Some(output) => chain
                                .confirmed_spending_transaction(&outpoint, &output.script_pubkey)?
                                .is_some_and(|tx| hop.is_timelock_spend(&tx)),
                            None => false,
                        };
                        match refunded
                            .iter_mut()
                            .find(|(seen, _)| seen.is_version_of(hop))
                        {
                            Some((_, any)) => *any |= spent,
                            None => refunded.push((hop, spent)),
                        }
                    }
                    let dangling = first_maker_lock.is_some()
                        && !refunded.is_empty()
                        && refunded.iter().all(|(_, spent)| *spent);
                    if !dangling {
                        log::debug!(
                            "Holding refund of {} for the first maker's hashlock claim",
                            contract_txid
                        );
                        return Ok(());
                    }
                    log::info!(
                        "First maker refunded its outgoing by timelock; outgoing {} of swap {} is dangling past its timelock, refunding it",
                        contract_txid,
                        swap_id
                    );
                }

                // A retry must pay the same destination. Persist it before
                // broadcasting so a failed wait cannot burn another index.
                let recovery_address = {
                    let mut w = lock_debug!(wallet.write())
                        .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;
                    let stored = w
                        .store
                        .outgoing_swapcoins
                        .get(&swap_id)
                        .and_then(|coin| coin.recovery_address.clone());
                    let (address, created) = recovery_address_or_else(stored, || {
                        Ok(w.get_next_internal_addresses(1, AddressType::P2TR)?[0]
                            .clone()
                            .into_unchecked())
                    })?;
                    // Checked before any write: a refund that cannot go out must
                    // not give up the claim below.
                    let checked =
                        address
                            .clone()
                            .require_network(w.store.network)
                            .map_err(|e| {
                                WalletError::General(format!(
                                    "invalid recovery address network: {e}"
                                ))
                            })?;
                    if created {
                        w.store
                            .outgoing_swapcoins
                            .get_mut(&swap_id)
                            .ok_or_else(|| {
                                WalletError::General(format!(
                                    "outgoing swapcoin {} disappeared during recovery",
                                    swap_id
                                ))
                            })?
                            .recovery_address = Some(address.clone());
                    }
                    // This refund settles an unclaimed swap: a hashlock sweep of
                    // its incoming after it would take both sides. Give up that
                    // claim before it goes out. A maker never refunds a known preimage.
                    // A sweep we already built proves a claim too.
                    let unclaimed = swapcoin.swap_id.as_ref().filter(|id| {
                        !proven
                            && !w.store.incoming_swapcoins.values().any(|coin| {
                                coin.swap_id.as_ref() == Some(*id) && coin.spending_tx.is_some()
                            })
                    });
                    let mut changed = created;
                    if let Some(id) = unclaimed {
                        for coin in w.store.incoming_swapcoins.values_mut() {
                            if coin.swap_id.as_ref() == Some(id) {
                                changed |= coin.hash_preimage.take().is_some();
                            }
                        }
                    }
                    if changed {
                        w.save_to_disk()?;
                    }
                    checked
                };

                // Read once, at the first ready coin: no refund in this pass waits
                // on another, so every one is built within seconds.
                let fee_rates = fee_rates.get_or_insert_with(|| chain.recovery_feerates());
                match Self::create_timelock_recovery_tx(&swapcoin, fee_rates, recovery_address) {
                    Ok(recovery_tx) => match chain.send_raw_transaction(&recovery_tx) {
                        Ok(txid) => refunds.push((swap_id.clone(), contract_txid, txid)),
                        Err(e) => {
                            log::warn!("Failed to broadcast recovery tx for {}: {:?}", swap_id, e);
                        }
                    },
                    Err(e) => {
                        log::warn!("Failed to create recovery tx for {}: {:?}", swap_id, e);
                    }
                }
                Ok(())
            })() {
                log::warn!("Timelock recovery for {} failed: {:?}", swap_id, e);
            }
        }

        Ok((refunds, discarded))
    }

    /// Waits once for every broadcast sweep and refund, then drops each coin
    /// whose spend was mined. The next pass records any spend mined later.
    /// Returns the (incoming, outgoing) outcomes.
    fn finish_recoveries(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        sweeps: Vec<SentSpend>,
        refunds: Vec<SentSpend>,
        discarded: Vec<String>,
        report_role: Option<SwapRole>,
    ) -> Result<(RecoveryOutcome, RecoveryOutcome), WalletError> {
        let txids: Vec<Txid> = sweeps
            .iter()
            .chain(&refunds)
            .map(|(_, _, txid)| *txid)
            .collect();
        let confirmed =
            wait_for_tx_confirmation(chain, &txids, 1, TX_BROADCAST_TIMEOUT, Some(shutdown), None);
        // A failed batch wait says nothing about each tx, so ask for each one
        // before taking the guard. A sibling that did confirm is still recorded.
        let mined = |(_, _, txid): &SentSpend| {
            confirmed.is_ok() || matches!(chain.tx_block_height(txid), Ok(Some(_)))
        };
        let sweeps: Vec<_> = sweeps.into_iter().filter(mined).collect();
        let refunds: Vec<_> = refunds.into_iter().filter(mined).collect();

        let mut w = lock_debug!(wallet.write())
            .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;

        let previous_incoming = w.store.incoming_swapcoins.clone();
        let previous_outgoing = w.store.outgoing_swapcoins.clone();
        let previous_reports = w.store.reports.clone();
        let mut reports: HashMap<(String, bool), Vec<String>> = HashMap::new();
        let mut incoming = RecoveryOutcome::default();
        for (key, contract_txid, txid) in sweeps {
            log::info!("Sweep transaction {} confirmed", txid);
            if let Some(coin) = w.remove_incoming_swapcoin(&key) {
                if let Some(id) = coin.swap_id {
                    for outgoing in w.store.outgoing_swapcoins.values_mut() {
                        if outgoing.swap_id.as_ref() == Some(&id) {
                            outgoing.incoming_claimed = true;
                        }
                    }
                    if coin.other_privkey.is_none() {
                        reports
                            .entry((id, true))
                            .or_default()
                            .push(txid.to_string());
                    }
                }
                incoming.resolved.push((contract_txid, txid));
            }
        }
        let mut outgoing = RecoveryOutcome::default();
        for (key, contract_txid, txid) in refunds {
            log::info!("Timelock recovery tx {} confirmed", txid);
            if let Some(coin) = w.remove_outgoing_swapcoin(&key) {
                reports
                    .entry((coin.swap_id.unwrap_or(key), false))
                    .or_default()
                    .push(txid.to_string());
                outgoing.resolved.push((contract_txid, txid));
            }
        }
        for id in &discarded {
            if let Some(sc) = w.store.outgoing_swapcoins.remove(id) {
                outgoing.discarded.push(sc.contract_tx.compute_txid());
            }
        }
        if !incoming.is_empty() || !outgoing.is_empty() {
            let saved = (|| -> Result<(), WalletError> {
                if let Some(role) = report_role {
                    for ((swap_id, hashlock), recovery_txids) in reports {
                        RecoveryReport {
                            swap_id,
                            role,
                            node: if role == SwapRole::Maker {
                                w.wallet_file_path
                                    .parent()
                                    .and_then(Path::parent)
                                    .and_then(Path::file_name)
                                    .and_then(|n| n.to_str())
                                    .map(str::to_owned)
                            } else {
                                None
                            },
                            recovery_type: if hashlock { "hashlock" } else { "timelock" }.into(),
                            recovery_txids,
                            network: w.store.network.to_string(),
                            timestamp: now_secs(),
                        }
                        .store_in_wallet(&mut w)?;
                    }
                }
                w.save_to_disk()
            })();
            if let Err(e) = saved {
                w.store.incoming_swapcoins = previous_incoming;
                w.store.outgoing_swapcoins = previous_outgoing;
                w.store.reports = previous_reports;
                return Err(e);
            }
            #[cfg(debug_assertions)]
            log::debug!(
                "[RECOVERY_STATE] Wallet: {} | Swept: {} | Refunded: {} | Discarded: {} | IncomingRemaining: {} | OutgoingRemaining: {}",
                w.store.file_name,
                incoming.resolved.len(),
                outgoing.resolved.len(),
                outgoing.discarded.len(),
                w.store.incoming_swapcoins.len(),
                w.store.outgoing_swapcoins.len()
            );
        }

        // Callers drop the outcome on `Err`, so a partial success must return
        // `Ok`. Unresolved coins stay in the wallet for the next pass.
        match confirmed {
            Err(e) if incoming.is_empty() && outgoing.is_empty() => Err(e),
            _ => Ok((incoming, outgoing)),
        }
    }

    /// One recovery pass over both sides. Every ready sweep and timelock refund
    /// is broadcast before a single wait, so a slow sweep cannot hold back a
    /// refund while its race is open. Returns the (incoming, outgoing) outcomes.
    ///
    /// A swap settles one way: a swap whose incoming coin we claim, now or in an
    /// earlier pass, gets no refund unless it provably dangles.
    ///
    /// Both callbacks are ignored and kept so callers still compile; the saved
    /// `committed` and `incoming_claimed` flags now decide.
    pub fn recover_swapcoins(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        contract_txids: &HashSet<Txid>,
        swap_ids: &HashSet<String>,
        _funding_shared_with_peer: &dyn Fn(Option<&str>) -> bool,
        _incoming_claimed: &dyn Fn(&str) -> bool,
    ) -> Result<(RecoveryOutcome, RecoveryOutcome), WalletError> {
        // Both steps want a synced wallet; the pass syncs it once.
        let mut synced = false;
        // A failed sweep step must still let the refunds go out, but with no
        // word on which coins are claimable, each refund must prove it dangles.
        let (sweeps, claiming, sweep_failed) = match Self::broadcast_incoming_sweeps(
            wallet,
            chain,
            shutdown,
            Some(contract_txids),
            &mut synced,
        ) {
            Ok((sweeps, claiming)) => (sweeps, claiming, false),
            Err(e) => {
                log::warn!("Incoming sweep failed: {:?}", e);
                (Vec::new(), HashSet::new(), true)
            }
        };
        let claimed: HashSet<String> = lock_debug!(wallet.read())
            .map_err(|_| WalletError::General("wallet lock poisoned".into()))?
            .store
            .outgoing_swapcoins
            .values()
            .filter(|coin| coin.incoming_claimed)
            .filter_map(|coin| coin.swap_id.clone())
            .collect();
        let (refunds, discarded) = Self::broadcast_timelock_recoveries(
            wallet,
            chain,
            shutdown,
            Some(swap_ids),
            &|swap_id| sweep_failed || claiming.contains(swap_id) || claimed.contains(swap_id),
            // A failed sweep step holds every refund, but proves no claim.
            &|swap_id| claiming.contains(swap_id) || claimed.contains(swap_id),
            &mut synced,
            false,
        )?;
        Self::finish_recoveries(
            wallet,
            chain,
            shutdown,
            sweeps,
            refunds,
            discarded,
            Some(SwapRole::Taker),
        )
    }

    /// Create a recovery transaction for a timelocked outgoing swapcoin.
    fn create_timelock_recovery_tx(
        swapcoin: &super::swapcoin::OutgoingSwapCoin,
        fee_rates: &[f64],
        recovery_address: Address,
    ) -> Result<bitcoin::Transaction, WalletError> {
        use bitcoin::{locktime::absolute::LockTime, transaction::Version, Sequence, TxIn, TxOut};

        let timelock = swapcoin.get_timelock().ok_or_else(|| {
            WalletError::General("Could not extract timelock from swapcoin".to_string())
        })?;
        let contract_txid = swapcoin.contract_tx.compute_txid();
        let contract_vout = swapcoin.get_contract_output_vout();

        let contract_output = swapcoin
            .contract_tx
            .output
            .get(contract_vout as usize)
            .ok_or_else(|| WalletError::General("No output in contract tx".to_string()))?;

        let vsize = contract_and_timelock_vsize(swapcoin.protocol, SpendKind::Timelock);

        let script_pubkey = recovery_address.script_pubkey();
        let fee = capped_fee(fee_rates, vsize, contract_output.value, &script_pubkey)
            .ok_or_else(|| WalletError::General("No feerate leaves a relayable output".into()))?;

        // Legacy (CSV): nSequence encodes relative locktime, nLockTime = 0.
        // Taproot (CLTV): nLockTime = absolute height. Both nSequence forms
        // signal RBF, so an underpriced recovery can be replaced.
        let (lock_time, sequence) =
            if swapcoin.protocol == crate::protocol::ProtocolVersion::Taproot {
                (
                    LockTime::from_height(timelock).unwrap_or(LockTime::ZERO),
                    Sequence::ENABLE_RBF_NO_LOCKTIME,
                )
            } else {
                (LockTime::ZERO, Sequence::from_height(timelock as u16))
            };

        let recovery_tx = bitcoin::Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: contract_txid,
                    vout: contract_vout,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: contract_output.value - fee,
                script_pubkey,
            }],
        };

        swapcoin.sign_timelock_recovery(recovery_tx)
    }

    /// Calculates the total balances of different categories in the wallet.
    /// Includes regular, swap, contract, fidelity, and spendable (regular + swap) utxos.
    /// Optionally takes in a list of UTXOs to reduce rpc call. If None is provided, the full list is fetched from core rpc.
    pub fn get_balances(&self) -> Result<Balances, WalletError> {
        let regular = self
            .list_descriptor_utxo_spend_info()
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount);
        // Contract balance: outgoing swapcoins whose contract TX is still unspent on-chain.
        // These are OUR funds locked in a contract, recoverable via timelock.
        // This is already covered by list_live_timelock_contract_spend_info() which
        // checks outgoing_swapcoins in check_and_derive_live_contract_spend_info().
        let contract = self
            .list_live_timelock_contract_spend_info()
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount);

        let swap = self
            .list_swept_incoming_swap_utxos()
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount);
        let fidelity = self
            .list_fidelity_spend_info()
            .iter()
            .fold(Amount::ZERO, |sum, (utxo, _)| sum + utxo.amount);
        let spendable = regular + swap;

        Ok(Balances {
            regular,
            swap,
            contract,
            fidelity,
            spendable,
        })
    }

    /// Ensures a funding prevout is bound to the expected cached contract.
    ///
    /// Proof-of-funding verification must fail closed when the binding is absent:
    /// the maker only caches it after approving the sender contract transaction.
    pub(crate) fn ensure_prevout_matches_cached_contract(
        &self,
        prevout: &OutPoint,
        contract_scriptpubkey: &Script,
    ) -> Result<(), WalletError> {
        match self.store.prevout_to_contract_map.get(prevout) {
            Some(cached_contract) if cached_contract == contract_scriptpubkey => Ok(()),
            Some(_) => Err(WalletError::General(
                "Provided contract does not match the cached sender contract".to_string(),
            )),
            None => Err(WalletError::General(format!(
                "No cached sender contract for funding prevout {prevout}"
            ))),
        }
    }

    /// Stores an entry into [`WalletStore`]'s prevout-to-contract map.
    /// Refuses to rebind a prevout that already has a different contract — that
    /// refusal stops a taker re-binding a prevout the maker already signed for.
    pub(crate) fn cache_prevout_to_contract(
        &mut self,
        bindings: &[(OutPoint, ScriptBuf)],
    ) -> Result<(), WalletError> {
        for (prevout, contract) in bindings {
            if self
                .store
                .prevout_to_contract_map
                .get(prevout)
                .is_some_and(|cached_contract| cached_contract != contract)
            {
                return Err(WalletError::General(format!(
                    "Refusing to rebind funding prevout {prevout} to a different contract"
                )));
            }
        }

        self.store
            .prevout_to_contract_map
            .extend(bindings.iter().cloned());
        self.save_to_disk()
    }

    //pub(crate) fn get_recovery_phrase_from_file()

    /// Account-level derivation path: `m / purpose' / coin_type' / account'`.
    ///
    /// `purpose` 84' (P2WPKH) or 86' (P2TR); `coin_type` 0' mainnet, 1' test networks
    /// (BIP-44 registered types); `account` always 0'. Callers append `/change/address_index`.
    fn get_derivation_path(address_type: AddressType, network: Network) -> DerivationPath {
        let purpose = match address_type {
            AddressType::P2WPKH => 84,
            AddressType::P2TR => 86,
        };
        let coin_type = match network {
            Network::Bitcoin => 0,
            _ => 1,
        };
        DerivationPath::from(vec![
            ChildNumber::Hardened { index: purpose },
            ChildNumber::Hardened { index: coin_type },
            ChildNumber::Hardened { index: 0 },
        ])
    }

    /// Wallet descriptors are derivable. Currently only supports two KeychainKind. Internal and External.
    fn get_wallet_descriptors(
        &self,
        address_type: AddressType,
    ) -> Result<HashMap<KeychainKind, String>, WalletError> {
        let secp = Secp256k1::new();
        let wallet_xpub =
            self.with_account_key(address_type, |account| Ok(Xpub::from_priv(&secp, account)))?;

        // Get descriptors for external and internal keychain. Other chains are not supported yet.
        [KeychainKind::External, KeychainKind::Internal]
            .iter()
            .map(|keychain| {
                let descriptor_without_checksum = match address_type {
                    AddressType::P2WPKH => {
                        format!("wpkh({}/{}/*)", wallet_xpub, keychain.index_num())
                    }
                    AddressType::P2TR => {
                        format!("tr({}/{}/*)", wallet_xpub, keychain.index_num())
                    }
                };
                let decriptor = format!(
                    "{}#{}",
                    descriptor_without_checksum,
                    compute_checksum(&descriptor_without_checksum)?
                );
                Ok((*keychain, decriptor))
            })
            .collect()
    }

    /// Returns the wallet descriptors whose imported range stops short of the
    /// rolling gap-limit window ([`Wallet::max_watch_index`]).
    pub(super) fn get_unimported_wallet_desc(
        &self,
        address_type: AddressType,
    ) -> Result<Vec<String>, WalletError> {
        let mut unimported = Vec::new();
        for (keychain, descriptor) in self.get_wallet_descriptors(address_type)? {
            // Core may have grown the range past ours, and a re-import must
            // cover it, so only import when the window has outgrown it.
            let last_index = self.max_watch_index(keychain)?;
            if !self
                .blockchain
                .imported_range_covers(&descriptor, last_index)?
            {
                unimported.push(descriptor);
            }
        }

        Ok(unimported)
    }

    /// Gets the external index from the wallet.
    pub fn get_external_index(&self) -> &u32 {
        &self.store.external_index
    }

    /// Core wallet label is the master Xpub(crate) fingerint.
    pub(crate) fn get_core_wallet_label(&self) -> String {
        let secp = Secp256k1::new();
        let m_xpub = self
            .with_master_key(|master_key| Ok(Xpub::from_priv(&secp, master_key)))
            .expect("in-memory master key unsealing failed");
        m_xpub.fingerprint().to_string()
    }

    /// Locks the fidelity and live_contract utxos which are not considered for spending from the wallet.
    pub fn lock_unspendable_utxos(&mut self) -> Result<(), WalletError> {
        self.locked_utxos.clear();

        let all_unspents = self.blockchain.list_unspent(Some(0), Some(9999999))?;
        let mut utxos_to_lock = Vec::new();
        for u in all_unspents {
            if self
                .check_and_derive_descriptor_utxo_or_swap_coin(&u)?
                .is_none()
            {
                utxos_to_lock.push(OutPoint {
                    txid: u.txid,
                    vout: u.vout,
                });
            }
        }
        self.lock_utxos(&utxos_to_lock);
        Ok(())
    }

    /// Add `outpoints` to the wallet-side lock set so [`Wallet::coin_select`]
    /// skips them. See [`Wallet::locked_utxos`].
    pub(crate) fn lock_utxos(&mut self, outpoints: &[OutPoint]) {
        self.locked_utxos.extend(outpoints.iter().copied());
    }

    /// Outpoints currently held in the wallet-side lock set (see
    /// [`Wallet::locked_utxos`]).
    pub(crate) fn list_lock_unspent(&self) -> Vec<OutPoint> {
        self.locked_utxos.iter().copied().collect()
    }

    /// Reserve `outpoints` for the swap `swap_key`; they stay out of coin
    /// selection until released. The reservation is persisted, so a restart
    /// still honours it.
    pub(crate) fn reserve_swap_locks(&mut self, swap_key: &str, outpoints: &[OutPoint]) {
        let entry = self
            .store
            .swap_locks
            .entry(swap_key.to_string())
            .or_default();
        if entry.outpoints.is_empty() {
            entry.reserved_at = now_secs();
        }
        entry.outpoints.extend(outpoints.iter().copied());
    }

    /// Reserve `inputs` for `swap_key` only if planning could pick each one: a
    /// wallet coin neither locked nor held by a swap. Otherwise reserve nothing.
    pub(crate) fn claim_swap_inputs(&mut self, swap_key: &str, inputs: &[OutPoint]) -> bool {
        let plannable: HashSet<OutPoint> = self
            .plannable_pools()
            .concat()
            .into_iter()
            .map(|(outpoint, _)| outpoint)
            .collect();
        if !inputs.iter().all(|outpoint| plannable.contains(outpoint)) {
            return false;
        }
        self.reserve_swap_locks(swap_key, inputs);
        true
    }

    /// [`Self::claim_swap_inputs`], except that inputs `swap_key` already holds
    /// pass as they are: rebuilding a swap's funding must not lose to its own
    /// claim.
    pub(crate) fn claim_or_hold_swap_inputs(
        &mut self,
        swap_key: &str,
        inputs: &[OutPoint],
    ) -> bool {
        let held = self
            .store
            .swap_locks
            .get(swap_key)
            .is_some_and(|locks| inputs.iter().all(|input| locks.outpoints.contains(input)));
        held || self.claim_swap_inputs(swap_key, inputs)
    }

    /// `Some(inputs)` frees the inputs of a funding transaction the backend
    /// accepted, and drops them from the cache so no claim reads them as free
    /// before the next sync; `None` drops the whole swap's reservation. Never
    /// release after an ambiguous broadcast failure: the tx may still land.
    pub(crate) fn release_swap_locks(
        &mut self,
        swap_key: &str,
        inputs: Option<&[OutPoint]>,
    ) -> bool {
        let Some(inputs) = inputs else {
            return self.store.swap_locks.remove(swap_key).is_some();
        };
        for input in inputs {
            self.store.utxo_cache.remove(input);
        }
        let Some(locks) = self.store.swap_locks.get_mut(swap_key) else {
            return false;
        };
        // Not `any`: it short-circuits, leaving the rest of the batch reserved.
        let mut freed = false;
        for input in inputs {
            freed |= locks.outpoints.remove(input);
        }
        if locks.outpoints.is_empty() {
            self.store.swap_locks.remove(swap_key);
        }
        freed
    }

    /// True while a swap's reservation holds `outpoint`. Coins are reserved only
    /// at funding, so a reservation lasts until its swap ends or fails.
    pub(crate) fn is_swap_reserved(&self, outpoint: &OutPoint) -> bool {
        self.store
            .swap_locks
            .values()
            .any(|locks| locks.outpoints.contains(outpoint))
    }

    /// Test-only: the funding tx of every outgoing swapcoin that has one:
    /// a Taproot coin's contract tx, a Legacy coin's stored funding tx.
    #[cfg(feature = "integration-test")]
    pub fn outgoing_funding_txs_for_test(&self) -> Vec<Transaction> {
        self.store
            .outgoing_swapcoins
            .values()
            .filter_map(|coin| match coin.protocol {
                ProtocolVersion::Taproot => Some(coin.contract_tx.clone()),
                ProtocolVersion::Legacy => coin.funding_tx.clone(),
            })
            .collect()
    }

    /// Test-only: for each incoming swapcoin flagged as a replaced version,
    /// whether it holds the other party's private key.
    #[cfg(feature = "integration-test")]
    pub fn replaced_incoming_keyed_for_test(&self) -> Vec<bool> {
        self.store
            .incoming_swapcoins
            .values()
            .filter(|coin| coin.replaced)
            .map(|coin| coin.other_privkey.is_some())
            .collect()
    }

    /// Test-only: reserve `outpoints` for `swap_key` and persist it, as
    /// another swap's claim would be.
    #[cfg(feature = "integration-test")]
    pub fn reserve_swap_locks_for_test(
        &mut self,
        swap_key: &str,
        outpoints: &[OutPoint],
    ) -> Result<(), WalletError> {
        self.reserve_swap_locks(swap_key, outpoints);
        self.save_to_disk()
    }

    /// Outpoints currently held out of coin selection by a reservation.
    #[cfg(feature = "integration-test")]
    pub(crate) fn reserved_inputs(&self) -> usize {
        self.store
            .swap_locks
            .values()
            .map(|l| l.outpoints.len())
            .sum()
    }

    /// Checks if a UTXO belongs to fidelity bonds, and then returns corresponding UTXOSpendInfo
    fn check_if_fidelity(&self, utxo: &ListUnspentResultEntry) -> Option<UTXOSpendInfo> {
        self.store.fidelity_bond.iter().find_map(|bond| {
            if bond.script_pub_key() == utxo.script_pub_key && bond.amount == utxo.amount {
                Some(UTXOSpendInfo::FidelityBondCoin {
                    index: bond.bond_index,
                    input_value: bond.amount,
                })
            } else {
                None
            }
        })
    }

    /// Check if a UTXO is a swept incoming swap coin based on ScriptPubkey
    fn check_if_swept_incoming_swapcoin(
        &self,
        utxo: &ListUnspentResultEntry,
    ) -> Option<UTXOSpendInfo> {
        if !self
            .store
            .swept_incoming_swapcoins
            .contains(&utxo.script_pub_key)
        {
            return None;
        }
        // Bitcoin Core path: HD origin lives in the descriptor string.
        if let Some(descriptor) = &utxo.descriptor {
            if let Some((_, addr_type, index)) = get_hd_path_from_descriptor(descriptor) {
                let address_type = if descriptor.starts_with("tr(") {
                    AddressType::P2TR
                } else {
                    AddressType::P2WPKH
                };
                return Some(UTXOSpendInfo::SweptCoin {
                    input_value: utxo.amount,
                    path: format!("m/{addr_type}/{index}"),
                    address_type,
                });
            }
        }
        // Electrum Path: HD Origin is stored internally for each script pubkey.
        if let Some(hd) = self.blockchain.hd_origin_for_script(&utxo.script_pub_key) {
            let address_type = if hd.is_taproot {
                AddressType::P2TR
            } else {
                AddressType::P2WPKH
            };
            return Some(UTXOSpendInfo::SweptCoin {
                input_value: utxo.amount,
                path: format!("m/{}/{}", hd.keychain_idx, hd.index),
                address_type,
            });
        }
        None
    }

    /// Checks if a UTXO belongs to live contracts, and then returns corresponding UTXOSpendInfo
    /// ### Note
    /// This is a costly search and should be used with care.
    fn check_and_derive_live_contract_spend_info(
        &self,
        utxo: &ListUnspentResultEntry,
    ) -> Option<UTXOSpendInfo> {
        // Check outgoing swapcoins for timelock contracts
        for outgoing in self.store.outgoing_swapcoins.values() {
            let contract_txid = outgoing.contract_tx.compute_txid();
            let vout = outgoing.get_contract_output_vout();
            if utxo.txid == contract_txid && utxo.vout == vout {
                return Some(UTXOSpendInfo::TimelockContract {
                    swapcoin_multisig_redeemscript: outgoing
                        .contract_redeemscript
                        .clone()
                        .unwrap_or_default(),
                    input_value: utxo.amount,
                });
            }
        }

        // Check incoming swapcoins for hashlock contracts
        for incoming in self.store.incoming_swapcoins.values() {
            let contract_txid = incoming.contract_tx.compute_txid();
            let vout = incoming.get_contract_output_vout();
            if utxo.txid == contract_txid && utxo.vout == vout && incoming.is_preimage_known() {
                return Some(UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript: incoming
                        .contract_redeemscript
                        .clone()
                        .unwrap_or_default(),
                    input_value: utxo.amount,
                });
            }
        }

        None
    }

    /// Checks if a UTXO belongs to descriptor or swap coin, and then returns corresponding UTXOSpendInfo
    /// ### Note
    /// This is a costly search and should be used with care.
    fn check_and_derive_descriptor_utxo_or_swap_coin(
        &self,
        utxo: &ListUnspentResultEntry,
    ) -> Result<Option<UTXOSpendInfo>, WalletError> {
        // First check if it's a swept incoming swap coin (V1)
        if let Some(swept_info) = self.check_if_swept_incoming_swapcoin(utxo) {
            return Ok(Some(swept_info));
        }

        // Electrum surfaces HD origin out-of-band rather than via the descriptor
        // string (which is empty for Electrum UTXOs).
        if let Some(hd) = self.blockchain.hd_origin_for_script(&utxo.script_pub_key) {
            let address_type = if hd.is_taproot {
                AddressType::P2TR
            } else {
                AddressType::P2WPKH
            };
            let secp = crate::utill::global_secp();
            let account_fingerprint = self.with_account_key(address_type, |account| {
                Ok(account.fingerprint(secp).to_string())
            })?;
            if hd.fingerprint == account_fingerprint {
                return Ok(Some(UTXOSpendInfo::SeedCoin {
                    path: format!("m/{}/{}", hd.keychain_idx, hd.index),
                    input_value: utxo.amount,
                    address_type,
                }));
            }
        }

        // Bitcoin Core populates `witness_script` via importdescriptors; Electrum
        // doesn't. Fall back to deriving the redeem script from our swap-coin
        // records and matching by scriptPubKey.
        if utxo.witness_script.is_none() {
            let spk = utxo.script_pub_key.as_script();
            let legacy = crate::protocol::ProtocolVersion::Legacy;
            let match_rs = |my: Option<PublicKey>, other: Option<PublicKey>| -> Option<ScriptBuf> {
                let rs = create_multisig_redeemscript(&my?, &other?);
                (ScriptBuf::new_p2wsh(&rs.wscript_hash()).as_script() == spk).then_some(rs)
            };
            for sc in self.store.incoming_swapcoins.values() {
                if sc.protocol == legacy && sc.other_privkey.is_some() {
                    if let Some(rs) = match_rs(sc.my_pubkey, sc.other_pubkey) {
                        return Ok(Some(UTXOSpendInfo::IncomingSwapCoin {
                            multisig_redeemscript: rs,
                        }));
                    }
                }
            }
            for sc in self.store.outgoing_swapcoins.values() {
                if sc.protocol == legacy && sc.hash_preimage.is_some() {
                    if let Some(rs) = match_rs(sc.my_pubkey, sc.other_pubkey) {
                        return Ok(Some(UTXOSpendInfo::OutgoingSwapCoin {
                            multisig_redeemscript: rs,
                        }));
                    }
                }
            }
        }

        // Existing logic for other UTXO types
        if let Some(descriptor) = &utxo.descriptor {
            // Descriptor logic here
            if let Some(ret) = get_hd_path_from_descriptor(descriptor) {
                //utxo is in a hd wallet
                let (fingerprint, addr_type, index) = ret;

                let address_type = if descriptor.starts_with("tr(") {
                    AddressType::P2TR
                } else {
                    AddressType::P2WPKH
                };

                let secp = Secp256k1::new();
                let account_fingerprint = self.with_account_key(address_type, |account| {
                    Ok(account.fingerprint(&secp).to_string())
                })?;
                if fingerprint == account_fingerprint {
                    return Ok(Some(UTXOSpendInfo::SeedCoin {
                        path: format!("m/{addr_type}/{index}"),
                        input_value: utxo.amount,
                        address_type,
                    }));
                }
            } else {
                //utxo might be one of our swapcoins
                let default_script = ScriptBuf::default();
                let witness_script = utxo.witness_script.as_ref().unwrap_or(&default_script);

                if self
                    .find_incoming_swapcoin_by_multisig(witness_script)
                    .is_some_and(|sc| sc.other_privkey.is_some())
                {
                    return Ok(Some(UTXOSpendInfo::IncomingSwapCoin {
                        multisig_redeemscript: utxo
                            .witness_script
                            .as_ref()
                            .expect("witness script expected")
                            .clone(),
                    }));
                }

                if self
                    .find_outgoing_swapcoin_by_multisig(witness_script)
                    .is_some_and(|sc| sc.hash_preimage.is_some())
                {
                    return Ok(Some(UTXOSpendInfo::OutgoingSwapCoin {
                        multisig_redeemscript: utxo
                            .witness_script
                            .as_ref()
                            .expect("witness script expected")
                            .clone(),
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Returns a list of all UTXOs tracked by the wallet. Including fidelity, live_contracts and swap coins.
    pub fn list_all_utxo(&self) -> Vec<ListUnspentResultEntry> {
        self.list_all_utxo_spend_info()
            .iter()
            .map(|(utxo, _)| utxo.clone())
            .collect()
    }

    /// Returns a list all utxos with their spend info tracked by the wallet.
    /// Optionally takes in an Utxo list to reduce RPC calls. If None is given, the
    /// full list of utxo is fetched from core rpc.
    pub fn list_all_utxo_spend_info(&self) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let processed_utxos = self
            .store
            .utxo_cache
            .values()
            .map(|(utxo, spend_info)| (utxo.clone(), spend_info.clone()))
            .collect();
        processed_utxos
    }

    /// Lists live contract UTXOs along with their Spend info.
    pub fn list_live_contract_spend_info(&self) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| {
                matches!(x.1, UTXOSpendInfo::HashlockContract { .. })
                    || matches!(x.1, UTXOSpendInfo::TimelockContract { .. })
            })
            .cloned()
            .collect();
        filtered_utxos
    }

    /// Lists live timelock contract UTXOs along with their Spend info.
    pub fn list_live_timelock_contract_spend_info(
        &self,
    ) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::TimelockContract { .. }))
            .cloned()
            .collect();
        filtered_utxos
    }
    /// Lists all live hashlock contract UTXOs along with their Spend info.
    pub fn list_live_hashlock_contract_spend_info(
        &self,
    ) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::HashlockContract { .. }))
            .cloned()
            .collect();
        filtered_utxos
    }

    /// Lists fidelity UTXOs along with their Spend info.
    pub fn list_fidelity_spend_info(&self) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::FidelityBondCoin { .. }))
            .cloned()
            .collect();
        filtered_utxos
    }

    /// Lists descriptor UTXOs along with their Spend info.
    pub fn list_descriptor_utxo_spend_info(&self) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::SeedCoin { .. }))
            .cloned()
            .collect();
        filtered_utxos
    }

    /// Lists swap coin UTXOs along with their Spend info.
    pub fn list_swap_coin_utxo_spend_info(&self) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| {
                matches!(
                    x.1,
                    UTXOSpendInfo::IncomingSwapCoin { .. } | UTXOSpendInfo::OutgoingSwapCoin { .. }
                )
            })
            .cloned()
            .collect();
        filtered_utxos
    }

    /// Lists all incoming swapcoin UTXOs along with their Spend info.
    pub fn list_incoming_swap_coin_utxo_spend_info(
        &self,
    ) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|x| matches!(x.1, UTXOSpendInfo::IncomingSwapCoin { .. }))
            .cloned()
            .collect();
        filtered_utxos
    }
    /// Lists all swept incoming swapcoin UTXOs along with their Spend info.
    pub fn list_swept_incoming_swap_utxos(&self) -> Vec<(ListUnspentResultEntry, UTXOSpendInfo)> {
        let all_valid_utxo = self.list_all_utxo_spend_info();
        let filtered_utxos: Vec<_> = all_valid_utxo
            .iter()
            .filter(|(_, spend_info)| matches!(spend_info, UTXOSpendInfo::SweptCoin { .. }))
            .cloned()
            .collect();
        filtered_utxos
    }

    /// Finds unfinished swapcoins.
    /// Incoming swapcoins remain unfinished until they are swept and removed.
    /// Outgoing swapcoins remain unfinished until their cleanup is saved.
    pub(crate) fn find_unfinished_swapcoins(
        &self,
    ) -> (
        Vec<super::swapcoin::IncomingSwapCoin>,
        Vec<super::swapcoin::OutgoingSwapCoin>,
    ) {
        let unfinished_incomings: Vec<_> =
            self.store.incoming_swapcoins.values().cloned().collect();
        let unfinished_outgoings: Vec<_> =
            self.store.outgoing_swapcoins.values().cloned().collect();
        if !unfinished_incomings.is_empty() || !unfinished_outgoings.is_empty() {
            log::info!(
                "Unfinished swaps - Incoming: {}, Outgoing: {}",
                unfinished_incomings.len(),
                unfinished_outgoings.len()
            );
        }
        (unfinished_incomings, unfinished_outgoings)
    }

    /// Finds the next unused index in the HD keychain.
    ///
    /// It will only return an unused address; i.e., an address that doesn't have a transaction associated with it.
    pub(super) fn find_hd_next_index(&self, keychain: KeychainKind) -> Result<u32, WalletError> {
        let mut max_index: i32 = -1;

        let mut utxos = self.list_descriptor_utxo_spend_info();
        let mut swap_coin_utxo = self.list_swap_coin_utxo_spend_info();
        utxos.append(&mut swap_coin_utxo);

        let target = keychain.index_num();
        for (utxo, _) in utxos {
            // The HD path comes from the UTXO's descriptor string on Bitcoin Core;
            // Electrum attaches no descriptor, so fall back to the backend's
            // script -> HdOrigin map populated by `watch_wallet_scripts`.
            let (kc_idx, index) = if let Some(d) = &utxo.descriptor {
                match get_hd_path_from_descriptor(d) {
                    Some((_, kc, i)) => (kc, i),
                    None => continue,
                }
            } else if let Some(hd) = self.blockchain.hd_origin_for_script(&utxo.script_pub_key) {
                (hd.keychain_idx, hd.index as i32)
            } else {
                continue;
            };
            if kc_idx == target {
                max_index = std::cmp::max(max_index, index);
            }
        }
        let mut next = (max_index + 1) as u32;

        // A seed carries no hand-out counters, and an emptied address leaves no
        // UTXO to find, so the loop above stops at the first spent-out run. Script
        // history still remembers those addresses, so probe forward on it.
        if let Some(restore) = &self.store.pending_restore {
            let secp = crate::utill::global_secp();
            let mut accounts = Vec::with_capacity(2);
            for address_type in [AddressType::P2WPKH, AddressType::P2TR] {
                // Public derivation suffices for history probing, so only the
                // account xpub leaves the key closure — no secret material is
                // held for the duration of the scan.
                accounts.push((
                    address_type,
                    self.with_account_key(address_type, |account| {
                        Ok(Xpub::from_priv(secp, account))
                    })?,
                ));
            }

            let mut probe = next;
            let mut empty_run = 0;
            // The window cap is only checked after this returns, so stop probing
            // at it too - otherwise a server claiming history everywhere loops on.
            while empty_run < restore.address_gap && probe <= MAX_WATCH_WINDOW {
                let mut has_history = false;
                for (address_type, account) in &accounts {
                    let script = derive_child_script(account, *address_type, keychain, probe)?;
                    if self
                        .blockchain
                        .script_has_history(&script, self.store.network)?
                    {
                        has_history = true;
                        break;
                    }
                }
                if has_history {
                    next = probe + 1;
                    empty_run = 0;
                } else {
                    empty_run += 1;
                }
                probe += 1;
            }
            // Cut off by the cap, not by a full empty run: funds past it would be missed.
            if empty_run < restore.address_gap {
                return Err(WalletError::WatchWindowCap {
                    window: next.saturating_add(restore.address_gap) - 1,
                    cap: MAX_WATCH_WINDOW,
                });
            }
        }
        Ok(next)
    }

    /// Highest HD index (inclusive) to watch/import on a keychain. The returned
    /// index leaves [`ADDRESS_IMPORT_COUNT`] unused addresses beyond the last
    /// used one: `used` below is the *next* never-used index, so the window ends
    /// at `used + gap - 1`.
    pub(crate) fn max_watch_index(&self, keychain: KeychainKind) -> Result<u32, WalletError> {
        let handed_out = match keychain {
            KeychainKind::External => self.store.external_index,
            KeychainKind::Internal => self.store.internal_index,
        };
        // Take the max because each side misses addresses the other knows:
        // the UTXO scan can't see addresses that are handed out but not yet
        // funded, and the store counters can't see on-chain funds past them.
        let used = self.find_hd_next_index(keychain)?.max(handed_out);
        let gap = self
            .store
            .pending_restore
            .as_ref()
            .map_or(ADDRESS_IMPORT_COUNT, |restore| restore.address_gap);
        used.checked_add(gap - 1)
            .ok_or(WalletError::WatchWindowCap {
                window: u32::MAX,
                cap: MAX_WATCH_WINDOW,
            })
    }

    /// Gets the next external address from the HD keychain. Saves the wallet to disk
    pub fn get_next_external_address(
        &mut self,
        address_type: AddressType,
    ) -> Result<Address, WalletError> {
        let descriptors = self.get_wallet_descriptors(address_type)?;
        let receive_branch_descriptor = descriptors
            .get(&KeychainKind::External)
            .expect("external keychain expected");
        let receive_address = self.blockchain.derive_addresses(
            receive_branch_descriptor,
            Some([self.store.external_index, self.store.external_index]),
        )?[0]
            .clone();
        self.store.external_index += 1;
        self.save_to_disk()?;
        Ok(receive_address.assume_checked())
    }

    /// Gets the next internal addresses from the HD keychain. Index saved to disk
    pub fn get_next_internal_addresses(
        &mut self,
        count: u32,
        address_type: AddressType,
    ) -> Result<Vec<Address>, WalletError> {
        // Return early. If count = 0 the calculation below will overflow.
        if count == 0 {
            return Ok(Vec::new());
        }
        let start = self.store.internal_index;
        let descriptors = self.get_wallet_descriptors(address_type)?;
        let change_branch_descriptor = descriptors
            .get(&KeychainKind::Internal)
            .expect("Internal Keychain expected");
        let addresses = self
            .blockchain
            .derive_addresses(change_branch_descriptor, Some([start, start + count - 1]))?;

        // Deliberate: the counter advances at hand-out time (multi-tx funding
        // needs a batch up front), so aborted attempts leave unused index gaps.
        // The rolling watch window follows the counter, so funds stay visible;
        self.store.internal_index += count;
        self.save_to_disk()?;

        Ok(addresses
            .into_iter()
            .map(|addrs| addrs.assume_checked())
            .collect())
    }

    /// Refreshes the offer maximum size cache based on the current wallet's unspent transaction outputs (UTXOs).
    pub(crate) fn refresh_offer_maxsize_cache(&mut self) -> Result<(), WalletError> {
        let Balances { swap, regular, .. } = self.get_balances()?;
        self.store.offer_maxsize = max(swap, regular).to_sat();
        Ok(())
    }

    //expose a deterministically-derived 64-byte Ed25519-V3 Tor key
    // built from the wallet's master_key
    #[cfg(not(feature = "integration-test"))]
    pub(crate) fn derive_tor_key(&self) -> [u8; 64] {
        // Hash the 32-byte secp256k1 private key bytes RFC 8032 per 5.1.5,
        // then clamp into a valid Ed25519 expanded key.
        let mut tor_key = self
            .with_master_key(|mk| {
                Ok(*sha512::Hash::hash(&mk.private_key.secret_bytes()).as_byte_array())
            })
            .expect("in-memory master key unsealing failed");
        tor_key[0] &= 248;
        tor_key[31] &= 127;
        tor_key[31] |= 64;
        tor_key
    }

    /// Gets a tweakable key pair from the master key of the wallet.
    pub(crate) fn get_tweakable_keypair(
        &self,
    ) -> Result<(SecretKey, PublicKey, ChainCode), WalletError> {
        let secp = Secp256k1::new();
        self.with_master_key(|mk| {
            let mut child = mk.derive_priv(&secp, &[ChildNumber::from_hardened_idx(175)?])?;
            let public_key = PublicKey {
                compressed: true,
                inner: child.private_key.public_key(&secp),
            };
            // The returned SecretKey is caller-owned by design; erase the
            // intermediate extended key it was copied out of.
            let result = (child.private_key, public_key, child.chain_code);
            child.private_key.non_secure_erase();
            Ok(result)
        })
    }

    /// Refreshes the UTXO cache by adding only new UTXOs while preserving existing ones.
    pub(crate) fn update_utxo_cache(
        &mut self,
        utxos: Vec<ListUnspentResultEntry>,
    ) -> Result<(), WalletError> {
        let mut new_entries = Vec::new();
        let existing_outpoints: std::collections::HashSet<OutPoint> = utxos
            .iter()
            .map(|utxo| OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            })
            .collect();

        // Identify UTXOs to be removed (present in store but missing in utxos parameter passed)
        let mut to_remove = Vec::new();
        for existing_outpoint in self.store.utxo_cache.keys().cloned().collect::<Vec<_>>() {
            if !existing_outpoints.contains(&existing_outpoint) {
                to_remove.push(existing_outpoint);
            }
        }

        // Remove UTXOs that no longer exist in the received utxos list
        for outpoint in &to_remove {
            self.store.utxo_cache.remove(outpoint);
        }

        // Refresh backend metadata for cached UTXOs without rebuilding their
        // derived spend info. Confirmations and other list-unspent fields can
        // change while the outpoint remains the same.
        for utxo in utxos {
            let outpoint = OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            };

            if let Some((cached_utxo, _)) = self.store.utxo_cache.get_mut(&outpoint) {
                let mut utxo = utxo;
                utxo.amount = cached_utxo.amount;
                utxo.script_pub_key = cached_utxo.script_pub_key.clone();
                *cached_utxo = utxo;
                continue;
            }

            // Process UTXOs to pair each with it's spend info using the wallet's private methods.
            let spend_info = match self
                .check_if_fidelity(&utxo)
                .or_else(|| self.check_and_derive_live_contract_spend_info(&utxo))
            {
                Some(info) => Some(info),
                None => self.check_and_derive_descriptor_utxo_or_swap_coin(&utxo)?,
            };

            // If we found valid spend info, store it in the cache
            if let Some(info) = spend_info {
                new_entries.push((outpoint, (utxo, info)));
            }
        }

        // Insert only new entries into the cache
        #[cfg(debug_assertions)]
        if !new_entries.is_empty() || !to_remove.is_empty() {
            log::debug!(
                "[UTXO_STATE] Source: wallet::api::update_utxo_cache | Wallet: {} | Added: {} | Removed: {} | CachedUtxos: {} -> {} | IncomingSwapcoins: {} | OutgoingSwapcoins: {}",
                self.store.file_name,
                new_entries.len(),
                to_remove.len(),
                self.store.utxo_cache.len() + to_remove.len(),
                self.store.utxo_cache.len() + new_entries.len(),
                self.store.incoming_swapcoins.len(),
                self.store.outgoing_swapcoins.len()
            );
        }
        for (outpoint, entry) in new_entries {
            self.store.utxo_cache.insert(outpoint, entry);
        }
        Ok(())
    }

    /// Signs a transaction corresponding to the provided UTXO spend information.
    pub(crate) fn sign_transaction(
        &self,
        tx: &mut Transaction,
        inputs_info: impl Iterator<Item = UTXOSpendInfo>,
    ) -> Result<(), WalletError> {
        let secp = Secp256k1::new();
        let tx_clone = tx.clone();

        let inputs_info: Vec<UTXOSpendInfo> = inputs_info.collect();

        // Build all prevouts for taproot sighash computation (BIP-341 requires all prevouts)
        let prevouts: Vec<TxOut> = inputs_info
            .iter()
            .map(|info| -> Result<TxOut, WalletError> {
                Ok(match info {
                    UTXOSpendInfo::SeedCoin {
                        path,
                        input_value,
                        address_type,
                    }
                    | UTXOSpendInfo::SweptCoin {
                        path,
                        input_value,
                        address_type,
                        ..
                    } => {
                        // Prevouts only need the script_pubkey: derive it
                        // from the account xpub so no secret material is
                        // involved in this pass at all.
                        let account_xpub = self.with_account_key(*address_type, |account| {
                            Ok(Xpub::from_priv(&secp, account))
                        })?;
                        let child_pubkey = account_xpub
                            .derive_pub(&secp, &DerivationPath::from_str(path)?)?
                            .public_key;

                        let script_pubkey = match address_type {
                            AddressType::P2WPKH => {
                                let pubkey = PublicKey {
                                    compressed: true,
                                    inner: child_pubkey,
                                };
                                ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash()?)
                            }
                            AddressType::P2TR => {
                                let x_only_pubkey = XOnlyPublicKey::from(child_pubkey);
                                ScriptBuf::new_p2tr(&secp, x_only_pubkey, None)
                            }
                        };
                        TxOut {
                            script_pubkey,
                            value: *input_value,
                        }
                    }
                    UTXOSpendInfo::FidelityBondCoin { index, input_value } => {
                        let redeemscript = self.get_fidelity_reedemscript(*index)?;
                        TxOut {
                            script_pubkey: redeemscript.to_p2wsh(),
                            value: *input_value,
                        }
                    }
                    _ => TxOut {
                        script_pubkey: ScriptBuf::new(),
                        value: Amount::ZERO,
                    },
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if tx.input.len() != inputs_info.len() {
            return Err(WalletError::General(format!(
                "Mismatched signer/input counts: tx has {} inputs but signer metadata has {} entries",
                tx.input.len(),
                inputs_info.len()
            )));
        }

        for (ix, (input, input_info)) in tx.input.iter_mut().zip(inputs_info).enumerate() {
            match input_info {
                UTXOSpendInfo::OutgoingSwapCoin { .. } => {
                    return Err(WalletError::General(
                        "Can't sign for outgoing swapcoins".to_string(),
                    ))
                }
                UTXOSpendInfo::IncomingSwapCoin {
                    multisig_redeemscript,
                } => {
                    let sc = self
                        .find_incoming_swapcoin_by_multisig(&multisig_redeemscript)
                        .ok_or_else(|| {
                            WalletError::General(
                                "incoming swapcoin not found in wallet store".to_string(),
                            )
                        })?;
                    let spend_tx = sc.sign_spend_transaction(
                        sc.funding_amount,
                        &tx.output[0].script_pubkey,
                        1.0,
                    )?;
                    input.witness = spend_tx.input[0].witness.clone();
                }
                UTXOSpendInfo::SeedCoin {
                    path,
                    input_value,
                    address_type,
                }
                | UTXOSpendInfo::SweptCoin {
                    path,
                    input_value,
                    address_type,
                    ..
                } => {
                    // Wiped on drop, so an early `?` below cannot skip it.
                    let child = self.with_account_key(address_type, |account| {
                        Ok(SecretXpriv(
                            account.derive_priv(&secp, &DerivationPath::from_str(&path)?)?,
                        ))
                    })?;
                    let privkey = &child.0.private_key;

                    match address_type {
                        AddressType::P2WPKH => {
                            // P2WPKH signing (existing logic)
                            let pubkey = PublicKey {
                                compressed: true,
                                inner: privkey.public_key(&secp),
                            };
                            let scriptcode = ScriptBuf::new_p2wpkh(&pubkey.wpubkey_hash()?);
                            let sighash = SighashCache::new(&tx_clone).p2wpkh_signature_hash(
                                ix,
                                &scriptcode,
                                input_value,
                                EcdsaSighashType::All,
                            )?;
                            //use low-R value signatures for privacy
                            //https://en.bitcoin.it/wiki/Privacy#Wallet_fingerprinting
                            let signature = secp.sign_ecdsa_low_r(
                                &secp256k1::Message::from_digest_slice(&sighash[..])?,
                                privkey,
                            );
                            let mut sig_serialised = signature.serialize_der().to_vec();
                            sig_serialised.push(EcdsaSighashType::All as u8);
                            input.witness.push(sig_serialised);
                            input.witness.push(pubkey.to_bytes());
                        }
                        AddressType::P2TR => {
                            // Calculate taproot key-spend sighash using all prevouts
                            let sighash = SighashCache::new(&tx_clone)
                                .taproot_key_spend_signature_hash(
                                    ix,
                                    &Prevouts::All(&prevouts),
                                    TapSighashType::Default,
                                )?;

                            // Nothing between building and erasing the key pairs can fail.
                            let mut keypair = Keypair::from_secret_key(&secp, privkey);
                            let mut tweaked = keypair.tap_tweak(&secp, None).to_keypair();
                            let msg = secp256k1::Message::from(sighash);
                            let signature = secp.sign_schnorr(&msg, &tweaked);

                            input.witness.push(signature.as_ref());
                            keypair.non_secure_erase();
                            tweaked.non_secure_erase();
                        }
                    }
                }
                UTXOSpendInfo::TimelockContract {
                    swapcoin_multisig_redeemscript,
                    ..
                } => {
                    let sc = self
                        .find_outgoing_swapcoin_by_multisig(&swapcoin_multisig_redeemscript)
                        .ok_or_else(|| {
                            WalletError::General(
                                "outgoing swapcoin not found in wallet store".to_string(),
                            )
                        })?;
                    let signed_tx = sc.sign_timelock_recovery(tx_clone.clone())?;
                    input.witness = signed_tx.input[0].witness.clone();
                }
                UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript,
                    ..
                } => {
                    let sc = self
                        .find_incoming_swapcoin_by_multisig(&swapcoin_multisig_redeemscript)
                        .ok_or_else(|| {
                            WalletError::General(
                                "incoming swapcoin not found in wallet store".to_string(),
                            )
                        })?;
                    let spend_tx = sc.sign_spend_transaction(
                        sc.funding_amount,
                        &tx.output[0].script_pubkey,
                        1.0,
                    )?;
                    input.witness = spend_tx.input[0].witness.clone();
                }
                UTXOSpendInfo::FidelityBondCoin { index, input_value } => {
                    let redeemscript = self.get_fidelity_reedemscript(index)?;
                    let sighash = SighashCache::new(&tx_clone).p2wsh_signature_hash(
                        ix,
                        &redeemscript,
                        input_value,
                        EcdsaSighashType::All,
                    )?;
                    let msg = secp256k1::Message::from_digest_slice(&sighash[..])?;
                    let sig = self.with_fidelity_keypair(index, |keypair| {
                        Ok(secp.sign_ecdsa_low_r(&msg, &keypair.secret_key()))
                    })?;

                    let mut sig_serialised = sig.serialize_der().to_vec();
                    sig_serialised.push(EcdsaSighashType::All as u8);
                    input.witness.push(sig_serialised);
                    input.witness.push(redeemscript.as_bytes());
                }
            }
        }
        Ok(())
    }

    /// Performs coin selection to choose UTXOs that sum to a target amount.
    ///
    /// Uses the rust-coinselect library to implement Bitcoin Core's coin selection algorithm.
    /// The algorithm tries to minimize the number of inputs while accounting for:
    /// - Transaction fees and weight
    /// - Long-term UTXO pool management
    /// - Change output costs
    /// - Privacy considerations
    ///
    /// Always prefers to spend reused addresses first to preserve privacy.
    /// Selects more UTXOs if total reused addresses amount isn't adequate.
    ///
    /// Seperates regular and swap UTXOs, and always chooses regular UTXOs first.
    /// Mixing regular and swap UTXOs is not allowed.
    ///
    /// # Arguments
    /// * `amount` - The target amount to select coins for
    /// * `feerate` - Fee rate in sats/vbyte
    ///
    /// # Returns
    /// * `Ok(Vec<(ListUnspentResultEntry, UTXOSpendInfo)>)` - Selected UTXOs and their spend info
    /// * `Err(WalletError)` - If coin selection fails or there are insufficient funds
    ///
    /// # Note
    /// Only considers spendable UTXOs (regular coins and swap coins), filtering out:
    /// - Fidelity bond UTXOs
    /// - Locked UTXOs
    /// - Unconfirmed UTXOs
    pub fn coin_select(
        &self,
        amount: Amount,
        feerate: f64,
        output_address_type: AddressType,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
        excluded_outpoints: Option<Vec<OutPoint>>,
    ) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
        // `target + fee` below is plain u64 arithmetic, so an amount near the
        // top of the range wraps in release and panics in debug, leaving the
        // wallet lock poisoned for every later call.
        if amount > Amount::MAX_MONEY {
            return Err(WalletError::General(
                "Amount is above the 21M BTC cap".to_string(),
            ));
        }

        const LONG_TERM_FEERATE: f32 = 10.0;
        // (version 4 + input varint 1 + output varint 1 + locktime 4) * 4 + marker 1 + flag 1 = 42 WU
        const BASE_TXN_ONLY_WEIGHT: u64 = 42;
        // Non-witness data (multiplied by 4):
        // - Previous txid (32 bytes) * 4     = 128 WU
        // - Prev vout (4 bytes) * 4          = 16 WU
        // - Script length (1 byte) * 4       = 4 WU
        // - Empty scriptsig (0 bytes) * 4    = 0 WU
        // - nSequence (4 bytes) * 4          = 16 WU
        // Subtotal non-witness:              = 164 WU
        const INPUT_BASE_WEIGHT: u64 = (32 + 4 + 4 + 1) * 4;
        let output_script_pubkey_size: u64 = match output_address_type {
            // OP_0 (1 byte) + OP_PUSH_20 (1 byte) + 20-byte pubkey hash = 22
            AddressType::P2WPKH => 22,
            // OP_1 (1 byte) +  OP_PUSH_32 (1 byte) + 32-byte x-only pubkey = 34
            AddressType::P2TR => 34,
        };
        let target_output_weight = (Amount::SIZE as u64 + 1 + output_script_pubkey_size) * 4;
        // Change always goes to a P2TR address for now.
        // TODO : Have a combined policy for change to choose it's type depending on the wallet state.
        let change_output_weight = (Amount::SIZE as u64 + 1 + 34u64) * 4;

        // 1. Drop locked, swap-reserved, and explicitly excluded UTXOs.
        let locked_utxos = self.list_lock_unspent();
        let excluded: std::collections::HashSet<OutPoint> =
            excluded_outpoints.unwrap_or_default().into_iter().collect();
        let filter_locked = |utxos: Vec<(ListUnspentResultEntry, UTXOSpendInfo)>| {
            utxos
                .into_iter()
                .filter(|(utxo, _)| {
                    let outpoint = OutPoint::new(utxo.txid, utxo.vout);
                    !locked_utxos.contains(&outpoint)
                        && !excluded.contains(&outpoint)
                        && !self.is_swap_reserved(&outpoint)
                })
                .collect::<Vec<_>>()
        };

        // 2. Segregate spendable UTXOs into two pools: regular and swap.
        let available_regular_utxos = filter_locked(self.list_descriptor_utxo_spend_info());
        let available_swap_utxos = filter_locked(self.list_swept_incoming_swap_utxos());

        // Assert that no non-spendable UTXOs are included after filtering
        debug_assert!(
        available_regular_utxos.iter().chain(available_swap_utxos.iter()).all(|(_, spend_info)| !matches!(
            spend_info,
            UTXOSpendInfo::FidelityBondCoin { .. }
                | UTXOSpendInfo::OutgoingSwapCoin { .. }
                | UTXOSpendInfo::TimelockContract { .. }
                | UTXOSpendInfo::HashlockContract { .. }
        )),
        "Fidelity, Outgoing Swapcoins, Hashlock and Timelock coins are not included in coin selection"
    );

        let target = amount.to_sat();
        let target_feerate_wu = feerate as f32 / 4.0;

        let input_weight = |utxo_data: &(ListUnspentResultEntry, UTXOSpendInfo)| -> u64 {
            let (_, spend_info) = utxo_data;
            INPUT_BASE_WEIGHT + spend_info.estimate_witness_size() as u64
        };

        // 3. Validate manual selection: all outpoints must exist and stay within one pool.
        let manually_selected_outpoints =
            manually_selected_outpoints.filter(|outpoints| !outpoints.is_empty());

        let (manual_utxo_type, manual_outpoints) = if let Some(ref manual_outpoints) =
            manually_selected_outpoints
        {
            let requested_outpoints: HashSet<_> = manual_outpoints.iter().copied().collect();

            let matched_manual_regular_utxos = available_regular_utxos
                .iter()
                .filter(|(utxo, _)| {
                    requested_outpoints.contains(&OutPoint::new(utxo.txid, utxo.vout))
                })
                .collect::<Vec<_>>();
            let matched_manual_swap_utxos = available_swap_utxos
                .iter()
                .filter(|(utxo, _)| {
                    requested_outpoints.contains(&OutPoint::new(utxo.txid, utxo.vout))
                })
                .collect::<Vec<_>>();

            let matched_manual_count =
                matched_manual_regular_utxos.len() + matched_manual_swap_utxos.len();
            if matched_manual_count != requested_outpoints.len() {
                return Err(WalletError::General(
                    "Some manually selected UTXOs are unavailable, locked, or excluded".to_string(),
                ));
            }

            if !matched_manual_regular_utxos.is_empty() && !matched_manual_swap_utxos.is_empty() {
                return Err(WalletError::General(
                    "Cannot mix regular and swap UTXOs in manual selection".to_string(),
                ));
            }

            let utxo_type = if !matched_manual_regular_utxos.is_empty() {
                "regular"
            } else {
                "swap"
            };

            (Some(utxo_type), requested_outpoints)
        } else {
            (None, HashSet::new())
        };

        let change_weight = Weight::from_wu(change_output_weight);
        let cost_of_change = {
            let creation_cost = calculate_fee(change_weight.to_vbytes_ceil(), feerate as f32);
            let future_spending_cost =
                calculate_fee((INPUT_BASE_WEIGHT + 66).div_ceil(4), LONG_TERM_FEERATE);
            creation_cost + future_spending_cost
        };

        let tx_weight_with_selected_inputs =
            |selected_weight: u64| BASE_TXN_ONLY_WEIGHT + selected_weight + target_output_weight;
        let required_total = |selected_weight: u64| {
            target
                + calculate_fee(
                    tx_weight_with_selected_inputs(selected_weight),
                    target_feerate_wu,
                )
        };
        // 4. Try each pool in order: manual pins one pool, else regular first then swap.
        let utxo_types_to_try = if manual_utxo_type == Some("regular") {
            vec![("regular", &available_regular_utxos)]
        } else if manual_utxo_type == Some("swap") {
            vec![("swap", &available_swap_utxos)]
        } else {
            vec![
                ("regular", &available_regular_utxos),
                ("swap", &available_swap_utxos),
            ]
        };

        let mut insufficient_funds = None;
        let mut other_selection_error = None;
        for (utxo_type, unspents) in utxo_types_to_try {
            // 5. Force-include manually selected UTXOs; the rest are free candidates.
            let (forced_utxos, candidate_utxos): (Vec<&_>, Vec<&_>) =
                unspents.iter().partition(|(utxo, _)| {
                    let outpoint = OutPoint::new(utxo.txid, utxo.vout);
                    manual_outpoints.contains(&outpoint)
                });

            let unspents = candidate_utxos.into_iter().cloned().collect::<Vec<_>>();

            // 6. Group candidates by address so reused addresses are spent together.
            let mut address_groups: HashMap<String, Vec<(ListUnspentResultEntry, UTXOSpendInfo)>> =
                HashMap::new();
            for (utxo, spend_info) in unspents {
                let address_str = utxo
                    .address
                    .as_ref()
                    .map(|addr| addr.clone().assume_checked().to_string())
                    .unwrap_or_else(|| format!("script_{}", utxo.script_pub_key));
                address_groups
                    .entry(address_str)
                    .or_default()
                    .push((utxo.clone(), spend_info.clone()));
            }

            // 6. Split reused addresses (>1 UTXO) from singletons, both sorted ascending by value.
            let (mut grouped_addresses, mut single_addresses): (Vec<_>, Vec<_>) = address_groups
                .into_values()
                .partition(|group| group.len() > 1);

            grouped_addresses
                .sort_by_key(|group| group.iter().map(|(u, _)| u.amount.to_sat()).sum::<u64>());

            single_addresses
                .sort_by_key(|group| group.iter().map(|(u, _)| u.amount.to_sat()).sum::<u64>());

            let (selected_utxos, selected_total, selected_weight) = {
                let mut result_utxos = forced_utxos.into_iter().cloned().collect::<Vec<_>>();
                let mut result_total = result_utxos
                    .iter()
                    .map(|(utxo, _)| utxo.amount.to_sat())
                    .sum::<u64>();
                let mut result_weight = result_utxos.iter().map(&input_weight).sum::<u64>();

                let required_for_selected = required_total(result_weight);
                if result_total >= required_for_selected {
                    log::info!(
                        "Manual selection: Selected {} {} UTXOs (total: {} sats, target+fee: {} sats)",
                        result_utxos.len(),
                        utxo_type,
                        result_total,
                        required_for_selected
                    );
                    return Ok(result_utxos);
                }

                for group in grouped_addresses {
                    let group_total: u64 = group.iter().map(|(u, _)| u.amount.to_sat()).sum();
                    let group_weight: u64 = group.iter().map(&input_weight).sum();

                    result_total += group_total;
                    result_weight += group_weight;
                    result_utxos.extend(group);

                    let required_for_selected = required_total(result_weight);
                    if result_total >= required_for_selected {
                        log::info!(
                    "Address grouping: Selected {} {} UTXOs (total: {} sats, target+fee: {} sats)",
                    result_utxos.len(),
                    utxo_type,
                    result_total,
                    required_for_selected
                );
                        #[cfg(debug_assertions)]
                        log::debug!(
                            "[COIN_SELECTION] Source: wallet::api::coin_select | Wallet: {} | Type: {} | Inputs: {} | Selected: {} | TargetWithFee: {} | Strategy: grouped",
                            self.store.file_name,
                            utxo_type,
                            result_utxos.len(),
                            result_total,
                            required_for_selected
                        );
                        return Ok(result_utxos);
                    }
                }
                (result_utxos, result_total, result_weight)
            };

            // 7. Run rust-coinselect over the remaining single-address UTXOs.
            let single_output_groups = single_addresses
                .iter()
                .map(|single_address_utxos| {
                    let total_value: u64 = single_address_utxos
                        .iter()
                        .map(|(utxo, _)| utxo.amount.to_sat())
                        .sum();
                    let total_weight: u64 = single_address_utxos.iter().map(&input_weight).sum();

                    OutputGroup {
                        value: total_value,
                        weight: total_weight,
                        input_count: single_address_utxos.len(),
                        creation_sequence: None,
                    }
                })
                .collect::<Vec<_>>();

            let base_weight = tx_weight_with_selected_inputs(selected_weight);

            let remaining_target = target.saturating_sub(selected_total).max(1);

            let coin_selection_option = CoinSelectionOpt {
                target_value: remaining_target,
                target_feerate: target_feerate_wu, //sats per wu
                long_term_feerate: Some(LONG_TERM_FEERATE),
                min_absolute_fee: 0,
                base_weight,
                change_weight: change_weight.to_wu(),
                change_cost: cost_of_change,
                min_change_value: 330, // P2TR dust threshold (since P2WPKH's 294)
                excess_strategy: ExcessStrategy::ToChange,
            };

            match select_coin(&single_output_groups, &coin_selection_option) {
                Ok(results) => {
                    let (_, result) = results.into_iter().next().unwrap();
                    let _fee = result.fee;
                    let additional_utxos: Vec<_> = result
                        .selected_inputs
                        .iter()
                        .flat_map(|&group_index| single_addresses[group_index].clone())
                        .collect();

                    let mut final_selection = selected_utxos;
                    final_selection.extend(additional_utxos);

                    log::info!("Selected {} {utxo_type} UTXOs", final_selection.len());
                    #[cfg(debug_assertions)]
                    log::debug!(
                        "[COIN_SELECTION] Source: wallet::api::coin_select | Wallet: {} | Type: {} | Inputs: {} | Selected: {} | TargetWithFee: {} | Strategy: coinselect",
                        self.store.file_name,
                        utxo_type,
                        final_selection.len(),
                        final_selection
                            .iter()
                            .map(|(utxo, _)| utxo.amount.to_sat())
                            .sum::<u64>(),
                        required_total(
                            selected_weight
                                + result
                                    .selected_inputs
                                    .iter()
                                    .map(|&group_index| single_output_groups[group_index].weight)
                                    .sum::<u64>(),
                        )
                    );
                    return Ok(final_selection);
                }
                Err(e) => {
                    if let SelectionError::InsufficientFunds {
                        available,
                        required,
                    } = e
                    {
                        // coinselect sees (target - selected_total) as its target and
                        // base_weight already includes manual+grouped input weights.
                        // Add selected_total back to restore both to wallet-level figures.
                        let available = available + selected_total;
                        let required = required + selected_total;
                        // Each pool (regular, swap) may report insufficient funds. Keep the
                        // one with the smallest deficit (required - available) so the final
                        // error reflects the pool closest to covering the target, rather than
                        // whichever pool happened to be tried last.
                        let deficit = required.saturating_sub(available);
                        let is_better = insufficient_funds
                            .map(|(prev_avail, prev_req): (u64, u64)| {
                                deficit < prev_req.saturating_sub(prev_avail)
                            })
                            .unwrap_or(true);
                        if is_better {
                            insufficient_funds = Some((available, required));
                        }
                        log::warn!(
                            "Coin selection with {utxo_type} UTXOs failed: insufficient funds (available={available}, required={required})"
                        );
                    } else {
                        log::warn!("Coin selection with {utxo_type} UTXOs failed: {e:?}");
                        other_selection_error = Some(e);
                    }
                }
            }
        }
        // 8. All pools exhausted: report the pool that came closest to covering the target.
        if let Some((available, required)) = insufficient_funds {
            Err(WalletError::InsufficientFund {
                available,
                required,
            })
        } else if let Some(e) = other_selection_error {
            Err(WalletError::Selection(e))
        } else {
            Err(WalletError::General(
                "coin selection failed without returning an error".to_string(),
            ))
        }
    }

    pub(crate) fn create_and_import_swap_address(
        &mut self,
        other_pubkey: &PublicKey,
    ) -> Result<(Address, SecretKey), WalletError> {
        let (my_pubkey, my_privkey) = generate_keypair();

        // create_multisig_reedemscript already follows BIP67 lexicographic ordering.
        // So this reedemscript is equavalent to `sortedmulti` descriptor.
        // This is revalidated again for Core backend only.
        let redeem_script = create_multisig_redeemscript(&my_pubkey, other_pubkey);
        let network = self.store.network;
        let address = Address::p2wsh(&redeem_script, network);

        let descriptor_without_checksum = format!("wsh(sortedmulti(2,{my_pubkey},{other_pubkey}))");
        let descriptor = format!(
            "{descriptor_without_checksum}#{}",
            compute_checksum(&descriptor_without_checksum)?
        );

        // Check for equvalence from Core backend
        // Electrum cannot do this.
        if !self.blockchain.is_electrum() {
            let derived = self
                .blockchain
                .derive_addresses(&descriptor, None)?
                .first()
                .map(|a| a.clone().assume_checked())
                .ok_or_else(|| {
                    WalletError::General(format!(
                        "deriveaddresses returned no address for {descriptor}"
                    ))
                })?;
            if derived != address {
                return Err(WalletError::General(format!(
                    "descriptor {descriptor} derives {derived}, expected {address}"
                )));
            }
        }
        // Import into Core
        self.import_descriptors(std::slice::from_ref(&descriptor), None, None)?;
        // Import into Electrum
        self.blockchain.watch_script(&address.script_pubkey(), None);

        Ok((address, my_privkey))
    }

    pub(crate) fn descriptors_to_import(&self) -> Result<Vec<String>, WalletError> {
        let mut descriptors_to_import = Vec::new();

        // Import both P2WPKH and P2TR descriptors to support both address types
        descriptors_to_import.extend(self.get_unimported_wallet_desc(AddressType::P2WPKH)?);
        descriptors_to_import.extend(self.get_unimported_wallet_desc(AddressType::P2TR)?);

        // Import swapcoin descriptors (Legacy only — multisig + contract redeemscripts)
        for sc in self.store.incoming_swapcoins.values() {
            if let (Some(my_pubkey), Some(other_pubkey)) = (sc.my_pubkey, sc.other_pubkey) {
                let descriptor_without_checksum =
                    format!("wsh(sortedmulti(2,{},{}))", other_pubkey, my_pubkey);
                descriptors_to_import.push(format!(
                    "{}#{}",
                    descriptor_without_checksum,
                    compute_checksum(&descriptor_without_checksum)?
                ));
            }
            if let Some(ref redeemscript) = sc.contract_redeemscript {
                let contract_spk = redeemscript_to_scriptpubkey(redeemscript)?;
                let descriptor_without_checksum = format!("raw({contract_spk:x})");
                descriptors_to_import.push(format!(
                    "{}#{}",
                    descriptor_without_checksum,
                    compute_checksum(&descriptor_without_checksum)?
                ));
            }
        }

        for sc in self.store.outgoing_swapcoins.values() {
            if let (Some(my_pubkey), Some(other_pubkey)) = (sc.my_pubkey, sc.other_pubkey) {
                let descriptor_without_checksum =
                    format!("wsh(sortedmulti(2,{},{}))", other_pubkey, my_pubkey);
                descriptors_to_import.push(format!(
                    "{}#{}",
                    descriptor_without_checksum,
                    compute_checksum(&descriptor_without_checksum)?
                ));
            }
            if let Some(ref redeemscript) = sc.contract_redeemscript {
                let contract_spk = redeemscript_to_scriptpubkey(redeemscript)?;
                let descriptor_without_checksum = format!("raw({contract_spk:x})");
                descriptors_to_import.push(format!(
                    "{}#{}",
                    descriptor_without_checksum,
                    compute_checksum(&descriptor_without_checksum)?
                ));
            }
        }

        descriptors_to_import.extend(
            self.store
                .fidelity_bond
                .iter()
                .map(|bond| {
                    let descriptor_without_checksum = format!("raw({:x})", bond.script_pub_key());
                    Ok(format!(
                        "{}#{}",
                        descriptor_without_checksum,
                        compute_checksum(&descriptor_without_checksum)?
                    ))
                })
                .collect::<Result<Vec<String>, WalletError>>()?,
        );
        Ok(descriptors_to_import)
    }

    /// Uses internal RPC client to broadcast a transaction
    pub fn send_tx(&self, tx: &Transaction) -> Result<Txid, WalletError> {
        self.blockchain.send_raw_transaction(tx)
    }
    /// Sweeps all completed incoming swap coins.
    /// Sweep incoming swapcoins whose claim is ready (cooperative key or hashlock preimage).
    ///
    /// The taker always claims what it can. A claimed incoming coin settles its
    /// swap: `recover_swapcoins` then refunds its outgoing only if it dangles.
    ///
    /// The caller supplies the backend connection: the confirmation wait runs
    /// on it with no wallet guard held, so a slow tx cannot wedge the wallet.
    /// `contract_txids` scopes normal settlement to one swap; `None` is reserved
    /// for startup and background recovery across the whole wallet.
    pub fn sweep_incoming_swapcoins(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        contract_txids: Option<&HashSet<Txid>>,
    ) -> Result<RecoveryOutcome, WalletError> {
        let (sweeps, _) =
            Self::broadcast_incoming_sweeps(wallet, chain, shutdown, contract_txids, &mut false)?;
        Ok(Self::finish_recoveries(
            wallet,
            chain,
            shutdown,
            sweeps,
            Vec::new(),
            Vec::new(),
            None,
        )?
        .0)
    }

    /// Recovery sweeps record their report with the coin removal.
    pub(crate) fn sweep_incoming_swapcoins_for_role(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        contract_txids: Option<&HashSet<Txid>>,
        role: SwapRole,
    ) -> Result<RecoveryOutcome, WalletError> {
        let (sweeps, _) =
            Self::broadcast_incoming_sweeps(wallet, chain, shutdown, contract_txids, &mut false)?;
        Ok(Self::finish_recoveries(
            wallet,
            chain,
            shutdown,
            sweeps,
            Vec::new(),
            Vec::new(),
            Some(role),
        )?
        .0)
    }

    /// Broadcasts every ready incoming sweep without waiting on any of them, and
    /// returns the sweeps sent. A contract still in the mempool waits for a later pass.
    /// Also returns the swaps being claimed: those whose incoming contract is on
    /// chain, whether or not their sweep went out in this pass.
    /// A PaySwap coin pays the receiver an exact amount, so its fee is whatever
    /// the input leaves over; every other coin sweeps at its negotiated feerate.
    /// `synced` works as in [`Self::broadcast_timelock_recoveries`].
    fn broadcast_incoming_sweeps(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        contract_txids: Option<&HashSet<Txid>>,
        synced: &mut bool,
    ) -> Result<(Vec<SentSpend>, HashSet<String>), WalletError> {
        let mut sweeps = Vec::new();
        let mut claiming = HashSet::new();

        // Snapshot everything the sweep needs, then drop the guard before any backend call.
        let completed_swapcoins = {
            let mut w = lock_debug!(wallet.write())
                .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?;

            let completed_swapcoins: Vec<_> = w
                .store
                .incoming_swapcoins
                .iter()
                .filter(|(_, swapcoin)| {
                    (swapcoin.other_privkey.is_some() || swapcoin.hash_preimage.is_some())
                        && contract_txids.is_none_or(|txids| {
                            txids.contains(&swapcoin.contract_tx.compute_txid())
                        })
                })
                .map(|(swap_id, swapcoin)| (swap_id.clone(), swapcoin.clone()))
                .collect();

            if completed_swapcoins.is_empty() {
                log::info!("No completed incoming swap coins to sweep");
                return Ok((sweeps, claiming));
            }

            if !*synced {
                w.sync_and_save(shutdown)?;
                *synced = true;
            }

            completed_swapcoins
        };

        log::info!(
            "Sweeping {} completed incoming swap coins",
            completed_swapcoins.len()
        );
        for (swap_id, swapcoin) in completed_swapcoins.into_iter() {
            // One failing coin must not hold back the other coins' sweeps.
            if let Err(e) = (|| -> Result<(), WalletError> {
                let contract_txid = swapcoin.contract_tx.compute_txid();
                if let Some(spend_tx) = &swapcoin.spending_tx {
                    // A sweep we built before may already be out. If the backend
                    // does not know it, the contract output checks below decide.
                    let txid = spend_tx.compute_txid();
                    match chain.is_tx_unknown(&txid) {
                        // Our hashlock sweep put the preimage out. Only the sender's
                        // confirmed timelock refund proves that claim is over.
                        Ok(true) if swapcoin.other_privkey.is_none() => {
                            let outpoint =
                                OutPoint::new(contract_txid, swapcoin.get_contract_output_vout());
                            let refunded =
                                match swapcoin.contract_tx.output.get(outpoint.vout as usize) {
                                    Some(output) => chain
                                        .confirmed_spending_transaction(
                                            &outpoint,
                                            &output.script_pubkey,
                                        )
                                        .inspect_err(|_| claiming.extend(swapcoin.swap_id.clone()))?
                                        .is_some_and(|tx| swapcoin.is_timelock_spend(&tx)),
                                    None => false,
                                };
                            if !refunded {
                                claiming.extend(swapcoin.swap_id.clone());
                            }
                        }
                        Ok(true) => {}
                        Ok(false) => {
                            claiming.extend(swapcoin.swap_id.clone());
                            sweeps.push((swap_id.clone(), contract_txid, txid));
                            return Ok(());
                        }
                        Err(e) => {
                            claiming.extend(swapcoin.swap_id.clone());
                            return Err(e);
                        }
                    }
                }
                // Determine which UTXO to spend based on protocol and spending path.
                let (utxo_txid, utxo_vout, input_value) = match swapcoin.protocol {
                    crate::protocol::ProtocolVersion::Legacy => {
                        if swapcoin.other_privkey.is_some() {
                            // Legacy cooperative: spend from funding output
                            let funding_outpoint = match swapcoin.contract_tx.input.first() {
                                Some(input) => input.previous_output,
                                None => {
                                    log::warn!(
                                        "Contract tx has no input for swap {} - skipping sweep",
                                        swap_id
                                    );
                                    return Ok(());
                                }
                            };
                            (
                                funding_outpoint.txid,
                                funding_outpoint.vout,
                                swapcoin.funding_amount,
                            )
                        } else {
                            // Legacy hashlock: spend from contract output
                            let contract_txid = swapcoin.contract_tx.compute_txid();
                            let contract_output = match swapcoin.contract_tx.output.first() {
                                Some(output) => output,
                                None => {
                                    log::warn!(
                                        "No output found in contract tx for swap {} - skipping sweep",
                                        swap_id
                                    );
                                    return Ok(());
                                }
                            };
                            (contract_txid, 0, contract_output.value)
                        }
                    }
                    crate::protocol::ProtocolVersion::Taproot => {
                        // Taproot: contract_tx IS the funding tx, spend from its P2TR output.
                        // Find the correct output index by matching the funding amount.
                        let contract_txid = swapcoin.contract_tx.compute_txid();
                        let vout = swapcoin
                            .contract_tx
                            .output
                            .iter()
                            .position(|o| o.value == swapcoin.funding_amount)
                            .unwrap_or(0) as u32;
                        (contract_txid, vout, swapcoin.funding_amount)
                    }
                };

                // Verify the UTXO actually exists on chain before attempting to spend.
                // First check confirmed UTXOs, then fall back to mempool.
                // A failed lookup says nothing about the contract, so the coin
                // holds its swap's refund until a later pass can tell.
                let utxo_confirmed = match chain.get_tx_out(&utxo_txid, utxo_vout, Some(false)) {
                    Ok(utxo) => utxo.is_some(),
                    Err(e) => {
                        claiming.extend(swapcoin.swap_id.clone());
                        return Err(e);
                    }
                };

                if !utxo_confirmed {
                    // UTXO not yet confirmed. Check if it's at least in the mempool.
                    let in_mempool = match chain.get_tx_out(&utxo_txid, utxo_vout, None) {
                        Ok(utxo) => utxo.is_some(),
                        Err(e) => {
                            claiming.extend(swapcoin.swap_id.clone());
                            return Err(e);
                        }
                    };

                    if in_mempool {
                        // Waiting here would hold back every other sweep and refund
                        // in the pass. A later pass sweeps it once it confirms.
                        claiming.extend(swapcoin.swap_id.clone());
                        log::info!(
                            "Incoming contract tx {}:{} is in mempool for {} — sweeping on a later pass",
                            utxo_txid,
                            utxo_vout,
                            swap_id
                        );
                        return Ok(());
                    } else if swapcoin.other_privkey.is_none()
                        && swapcoin.others_contract_sig.is_some()
                    {
                        log::info!(
                            "Contract output not on-chain for {} — broadcasting signed contract tx",
                            swap_id
                        );
                        match swapcoin.create_signed_contract_tx() {
                            Ok(signed_contract_tx) => {
                                match chain.send_raw_transaction(&signed_contract_tx) {
                                    Ok(txid) => {
                                        log::info!(
                                            "Broadcast incoming contract tx {} for {}",
                                            txid,
                                            swap_id
                                        );
                                        // Our contract is out, so we will sweep it: hold the refund.
                                        claiming.extend(swapcoin.swap_id.clone());
                                    }
                                    // An error does not prove a rejection: the
                                    // re-check below tells whether it landed.
                                    Err(e) => {
                                        log::warn!(
                                            "Failed to broadcast incoming contract tx for {}: {:?}",
                                            swap_id,
                                            e
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                log::warn!(
                                    "Failed to create signed incoming contract tx for {}: {:?}",
                                    swap_id,
                                    e
                                );
                                return Ok(());
                            }
                        }

                        // Re-check UTXO availability (including mempool) after broadcast
                        let utxo_available =
                            match chain.get_tx_out(&utxo_txid, utxo_vout, Some(true)) {
                                Ok(utxo) => utxo.is_some(),
                                Err(e) => {
                                    claiming.extend(swapcoin.swap_id.clone());
                                    return Err(e);
                                }
                            };
                        if !utxo_available {
                            log::info!(
                                "Contract output still not available for {} after broadcast — will retry later",
                                swap_id
                            );
                            return Ok(());
                        }
                    } else {
                        // A fee bump replaced this contract. A replacement paying
                        // the same contract is ours to claim: follow it, and
                        // the next pass sweeps it. One beaten for good by any
                        // other spend is never swept.
                        let verdict = Self::judge_unseen_incoming(chain, &swapcoin)?;
                        if verdict == UnseenIncoming::Follow {
                            if let Some(id) = swapcoin.swap_id.as_deref() {
                                Self::follow_replaced_incoming(wallet, chain, id)?;
                            }
                            return Ok(());
                        }
                        if verdict == UnseenIncoming::Drop {
                            log::info!(
                                "Incoming contract {} for {} was replaced and its inputs are confirmed spent — dropping it",
                                utxo_txid,
                                swap_id
                            );
                            let mut w = lock_debug!(wallet.write()).map_err(|_| {
                                WalletError::General("wallet lock poisoned".to_string())
                            })?;
                            w.remove_incoming_swapcoin(&swap_id);
                            w.save_to_disk()?;
                            return Ok(());
                        }
                        log::info!(
                            "Skipping sweep for {} - UTXO not available on chain",
                            swap_id
                        );
                        return Ok(());
                    }
                }

                // The contract is on chain, so this coin is ours to claim even if
                // its sweep fails to go out below.
                claiming.extend(swapcoin.swap_id.clone());

                // A PaySwap coin settles to the receiver's own script — nothing is
                // allocated or tracked in this wallet. Otherwise, allocate the
                // internal address only for a coin actually being swept; a coin
                // skipped every pass would otherwise burn an index each time and
                // grow the watch window forever. Take the guard just for this, so
                // nothing below waits with it held.
                let (internal_address, spend_result) = match (
                    &swapcoin.spending_tx,
                    &swapcoin.payment_target,
                ) {
                    (Some(tx), _) => (None, Ok(tx.clone())),
                    (None, Some(target)) => {
                        log::info!(
                            "Settling incoming swap coin {} (utxo: {}:{}) to payment receiver, exact output {}",
                            swap_id,
                            utxo_txid,
                            utxo_vout,
                            target.amount
                        );
                        let spend = swapcoin.sign_spend_transaction_with_output_value(
                            input_value,
                            target.amount,
                            &target.script_pubkey,
                        );
                        (None, spend)
                    }
                    (None, None) => {
                        let address = {
                            let mut w = lock_debug!(wallet.write()).map_err(|_| {
                                WalletError::General("wallet lock poisoned".to_string())
                            })?;
                            let addr =
                                w.get_next_internal_addresses(1, AddressType::P2TR)?[0].clone();
                            // Mark the sweep target before broadcast, not after confirmation: a
                            // sync inside the confirmation window must not see it as a seed coin.
                            w.store
                                .swept_incoming_swapcoins
                                .insert(addr.script_pubkey());
                            addr
                        };
                        log::info!(
                            "Sweeping incoming swap coin {} (utxo: {}:{}) to internal address {}",
                            swap_id,
                            utxo_txid,
                            utxo_vout,
                            address
                        );
                        let spend = swapcoin.sign_spend_transaction(
                            input_value,
                            &address.script_pubkey(),
                            // A stored rate below the relay floor can never relay;
                            // recover at the floor instead of retrying it forever.
                            (swapcoin.negotiated_feerate as f64).max(MIN_RELAY_FEE_RATE),
                        );
                        (Some(address), spend)
                    }
                };

                // Sweep never happened; unmark the address.
                let unmark_on_failure = |addr: &Option<Address>| -> Result<(), WalletError> {
                    if let Some(addr) = addr {
                        lock_debug!(wallet.write())
                            .map_err(|_| WalletError::General("wallet lock poisoned".to_string()))?
                            .store
                            .swept_incoming_swapcoins
                            .remove(&addr.script_pubkey());
                    }
                    Ok(())
                };

                match spend_result {
                    Ok(spend_tx) => {
                        {
                            let mut w = lock_debug!(wallet.write()).map_err(|_| {
                                WalletError::General("wallet lock poisoned".to_string())
                            })?;
                            let stored =
                                w.find_incoming_swapcoin_mut(&swap_id).ok_or_else(|| {
                                    WalletError::General(format!(
                                        "incoming swapcoin {swap_id} disappeared during sweep"
                                    ))
                                })?;
                            stored.spending_tx = Some(spend_tx.clone());
                            w.save_to_disk()?;
                        }
                        match chain.send_raw_transaction(&spend_tx) {
                            Ok(txid) => sweeps.push((swap_id.clone(), contract_txid, txid)),
                            Err(e) => {
                                log::warn!(
                                    "Failed to broadcast sweep tx for swapcoin {}: {:?}",
                                    swap_id,
                                    e
                                );
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!(
                            "Failed to create spend tx for swapcoin {}: {:?}",
                            swap_id,
                            e
                        );
                        unmark_on_failure(&internal_address)?;
                    }
                }
                Ok(())
            })() {
                log::warn!("Incoming sweep for {} failed: {:?}", swap_id, e);
            }
        }

        // The sweeps are already out: a failed save must not hide them from the wait.
        match lock_debug!(wallet.write()) {
            Ok(w) => {
                if let Err(e) = w.save_to_disk() {
                    log::warn!("Failed to persist incoming sweep state: {:?}", e);
                }
            }
            Err(_) => log::warn!("Failed to persist incoming sweep state: wallet lock poisoned"),
        }
        Ok((sweeps, claiming))
    }

    /// Runs the crate's shared bounded wait on this wallet's own backend connection.
    /// Note the connection is shared, so the caller must not hold a wallet guard.
    pub fn wait_for_tx_confirmation(
        &self,
        txids: &[Txid],
        required_confirms: u32,
        shutdown: Option<&std::sync::atomic::AtomicBool>,
        abort_check: Option<&dyn Fn() -> bool>,
    ) -> Result<u32, WalletError> {
        wait_for_tx_confirmation(
            &self.blockchain,
            txids,
            required_confirms,
            TX_BROADCAST_TIMEOUT,
            shutdown,
            abort_check,
        )
    }

    /// Resolve the previous-output scripts for every input in a transaction.
    ///
    /// Parent transactions are cached for the duration of this call so inputs
    /// spending multiple outputs from one parent require only one backend
    /// lookup.
    pub fn resolve_input_scripts(
        &self,
        tx: &Transaction,
    ) -> Result<Vec<(OutPoint, ScriptBuf)>, WalletError> {
        let mut parent_transactions = HashMap::new();
        let mut resolved = Vec::with_capacity(tx.input.len());

        for input in &tx.input {
            let outpoint = input.previous_output;
            let parent = if let Some(parent) = parent_transactions.get(&outpoint.txid) {
                parent
            } else {
                let parent = self.blockchain.get_raw_transaction(&outpoint.txid, None)?;
                parent_transactions.insert(outpoint.txid, parent);
                parent_transactions
                    .get(&outpoint.txid)
                    .expect("inserted parent transaction")
            };

            let output = parent.output.get(outpoint.vout as usize).ok_or_else(|| {
                WalletError::General(format!(
                    "Input {outpoint} references missing output {}",
                    outpoint.vout
                ))
            })?;

            resolved.push((outpoint, output.script_pubkey.clone()));
        }

        Ok(resolved)
    }
}

/// Wait for the given txs to reach `required_confirms`, returning the highest block
/// height any of them was mined at. Returns 0 if `required_confirms` is 0 or `txids`
/// is empty.
///
/// Bounded three ways: a tx that never reaches our mempool fails after
/// `arrival_timeout`; a seen tx that vanishes gets one window of the same
/// length to reappear (it never re-arms, so a flapping tx still trips it); and the
/// whole wait fails after [`TX_CONFIRMATION_TIMEOUT`]. A `shutdown` flag or an
/// `abort_check` closure interrupts the wait between polls.
///
/// `arrival_timeout` is [`TX_BROADCAST_TIMEOUT`] for a tx already broadcast, which
/// only covers relay lag. Waiting on a maker to broadcast at all needs longer.
pub(crate) fn wait_for_tx_confirmation(
    blockchain: &AnyBlockchain,
    txids: &[Txid],
    required_confirms: u32,
    arrival_timeout: Duration,
    shutdown: Option<&std::sync::atomic::AtomicBool>,
    abort_check: Option<&dyn Fn() -> bool>,
) -> Result<u32, WalletError> {
    let slots: Vec<Vec<Txid>> = txids.iter().map(|txid| vec![*txid]).collect();
    match wait_for_slots_confirmation(
        blockchain,
        &slots,
        &SlotWait {
            required_confirms,
            arrival_timeout,
            started: Instant::now(),
            interrupt_at_height: None,
        },
        &mut SlotTrack::new(slots.len()),
        shutdown,
        abort_check,
    )? {
        SlotWaitOutcome::Confirmed { height, .. } => Ok(height),
        SlotWaitOutcome::HeightReached(_) => Err(WalletError::General(
            "confirmation wait returned at a height it was never given".to_string(),
        )),
    }
}

/// The bounds of a [`wait_for_slots_confirmation`].
pub(crate) struct SlotWait {
    /// Confirmations each slot needs.
    pub(crate) required_confirms: u32,
    /// How long a slot may go unseen, or vanish, before the wait fails.
    pub(crate) arrival_timeout: Duration,
    /// When the wait began. A resumed wait passes its first start, so
    /// [`TX_CONFIRMATION_TIMEOUT`] bounds all of it.
    pub(crate) started: Instant,
    /// Return [`SlotWaitOutcome::HeightReached`] once the tip reaches this
    /// height and some slot is still unconfirmed.
    pub(crate) interrupt_at_height: Option<u64>,
}

/// What a [`wait_for_slots_confirmation`] has seen of its slots, kept by the
/// caller across the waits an interrupt height splits it into: which slots
/// were never seen and since when, and when a seen slot vanished.
pub(crate) struct SlotTrack {
    arrival_started: Instant,
    unseen: HashSet<usize>,
    vanished_at: HashMap<usize, Instant>,
}

impl SlotTrack {
    /// Nothing seen yet of `slots` slots; the arrival deadline runs from now.
    pub(crate) fn new(slots: usize) -> Self {
        Self {
            arrival_started: Instant::now(),
            unseen: (0..slots).collect(),
            vanished_at: HashMap::new(),
        }
    }
}

/// How a [`wait_for_slots_confirmation`] ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SlotWaitOutcome {
    /// Every slot confirmed. `winners[i]` is the member of slot `i` that did;
    /// `height` is the highest block any of them was mined at.
    Confirmed { height: u32, winners: Vec<Txid> },
    /// The tip reached the interrupt height first.
    HeightReached(u64),
}

/// Wait until one member of every slot reaches the required confirmations.
///
/// A slot is the set of transactions spending the same coins, such as a
/// funding tx and its fee-bumped replacements: only one of them can confirm,
/// and any one confirming settles the slot. The slot counts as seen while any
/// member is, and as vanished only when every member is gone, since a replaced
/// tx leaves the mempool as its replacement enters it. Otherwise bounded as
/// [`wait_for_tx_confirmation`] is. `track` carries what the wait has seen,
/// so a wait resumed after [`SlotWaitOutcome::HeightReached`] keeps the
/// arrival deadline and eviction windows it started with.
pub(crate) fn wait_for_slots_confirmation(
    blockchain: &AnyBlockchain,
    slots: &[Vec<Txid>],
    wait: &SlotWait,
    track: &mut SlotTrack,
    shutdown: Option<&std::sync::atomic::AtomicBool>,
    abort_check: Option<&dyn Fn() -> bool>,
) -> Result<SlotWaitOutcome, WalletError> {
    let required_confirms = wait.required_confirms;
    let arrival_timeout = wait.arrival_timeout;
    if required_confirms == 0 || slots.is_empty() {
        return Ok(SlotWaitOutcome::Confirmed {
            height: 0,
            winners: slots
                .iter()
                .filter_map(|slot| slot.first().copied())
                .collect(),
        });
    }

    log::info!(
        "Waiting for {} confirmation(s) on {} transaction(s)...",
        required_confirms,
        slots.len()
    );

    const SYNC_INTERVAL_SECS: u64 = 10;
    /// Longest gap between reads of seen txs while the tip stands still, so an
    /// eviction from the mempool is still noticed.
    const MEMPOOL_RECHECK: Duration = Duration::from_secs(60);

    let SlotTrack {
        arrival_started: started,
        unseen,
        vanished_at,
    } = track;
    let started = *started;
    let mut last_tip = None;
    let mut last_read: Option<Instant> = None;

    loop {
        if shutdown.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
            return Err(WalletError::Interrupted("Shutdown requested"));
        }
        if abort_check.is_some_and(|f| f()) {
            return Err(WalletError::Interrupted("Abort requested"));
        }
        if wait.started.elapsed() > TX_CONFIRMATION_TIMEOUT {
            log::error!(
                "Tx(s) did not confirm within {}s",
                TX_CONFIRMATION_TIMEOUT.as_secs()
            );
            return Err(WalletError::TxConfirmationTimeout(
                "Tx did not confirm before the confirmation deadline".to_string(),
            ));
        }

        // Confirmations only move with a block, so a seen tx is read again on a
        // new tip, or after `MEMPOOL_RECHECK` to catch an eviction. The tip is
        // one request; reading each tx costs several on Electrum.
        let tip = blockchain.get_block_count().ok();
        let due = !unseen.is_empty()
            || !vanished_at.is_empty()
            || tip.is_none()
            || tip != last_tip
            || last_read.is_none_or(|at| at.elapsed() >= MEMPOOL_RECHECK);
        if !due {
            pause_between_polls(SYNC_INTERVAL_SECS, shutdown, abort_check)?;
            continue;
        }
        last_tip = tip;
        last_read = Some(Instant::now());

        let mut all_confirmed = true;
        let mut max_confirm_height: u32 = 0;
        let mut winners = Vec::with_capacity(slots.len());

        for (slot_index, slot) in slots.iter().enumerate() {
            let mut seen = None;
            let mut winner = None;
            for txid in slot {
                let Ok(tx_info) = blockchain.get_raw_transaction_info(txid, None) else {
                    log::debug!("Tx {txid} is not visible to the backend");
                    continue;
                };
                seen.get_or_insert(*txid);
                let confirms: u32 = tx_info.confirmations.unwrap_or(0);
                if confirms < required_confirms {
                    log::debug!(
                        "Tx {} has {} confirmations (need {})",
                        txid,
                        confirms,
                        required_confirms
                    );
                    continue;
                }
                // QA: Ask the backend for the mined height directly;
                // tip-height arithmetic can race with a newly mined block.
                let confirm_height = blockchain.tx_block_height(txid)?.ok_or_else(|| {
                    WalletError::General(format!(
                        "Confirmed transaction {txid} has no block height"
                    ))
                })? as u32;
                max_confirm_height = max_confirm_height.max(confirm_height);
                winner = Some(*txid);
                break;
            }
            // First sighting gets a line: the eviction window anchors to it,
            // and tests time a replacement off it.
            if let Some(txid) = seen {
                if unseen.remove(&slot_index) && winner.is_none() {
                    log::info!(
                        "Tx {txid} seen in mempool, waiting for {required_confirms} confirmation(s)"
                    );
                }
            }
            if seen.is_none()
                && !unseen.contains(&slot_index)
                // A seen slot that vanishes (mempool eviction) gets one window
                // to reappear. Re-sighting never clears the window, so a slot
                // flapping in and out of the mempool still trips the bound.
                && vanished_at
                    .entry(slot_index)
                    .or_insert_with(Instant::now)
                    .elapsed()
                    > arrival_timeout
            {
                return Err(WalletError::TxConfirmationTimeout(
                    "Tx vanished from our mempool and did not reappear".to_string(),
                ));
            }
            match winner {
                Some(txid) => winners.push(txid),
                None => all_confirmed = false,
            }
        }

        if !unseen.is_empty() && started.elapsed() > arrival_timeout {
            log::error!(
                "{} tx(s) never reached our mempool within {}s",
                unseen.len(),
                arrival_timeout.as_secs()
            );

            // Never seeing a tx is not the same as the backend telling us it has
            // none. Only a definite answer for every missing tx names a withheld
            // broadcast; an error means we could not ask.
            let mut missing: Vec<Txid> = unseen
                .iter()
                .flat_map(|slot_index| slots[*slot_index].iter().copied())
                .collect();
            missing.sort();
            let mut confirmed_absent = true;
            for txid in &missing {
                match blockchain.is_tx_unknown(txid) {
                    Ok(true) => {}
                    Ok(false) => {
                        log::warn!("Tx {txid} is known to the backend after all");
                        confirmed_absent = false;
                        break;
                    }
                    Err(e) => {
                        log::warn!("Cannot confirm {txid} is absent: {e:?}");
                        confirmed_absent = false;
                        break;
                    }
                }
            }

            if confirmed_absent {
                return Err(WalletError::TxNeverBroadcast(missing));
            }
            return Err(WalletError::TxConfirmationTimeout(
                "Tx did not reach our mempool before the broadcast timeout".to_string(),
            ));
        }

        if all_confirmed {
            log::info!(
                "All transactions confirmed (latest at height {})",
                max_confirm_height
            );
            return Ok(SlotWaitOutcome::Confirmed {
                height: max_confirm_height,
                winners,
            });
        }

        if let (Some(tip), Some(at)) = (tip, wait.interrupt_at_height) {
            if tip >= at {
                return Ok(SlotWaitOutcome::HeightReached(tip));
            }
        }

        log::info!("Next sync in {} secs", SYNC_INTERVAL_SECS);
        pause_between_polls(SYNC_INTERVAL_SECS, shutdown, abort_check)?;
    }
}

/// Sleep `secs` in 1-second increments so shutdown and abort are seen.
fn pause_between_polls(
    secs: u64,
    shutdown: Option<&std::sync::atomic::AtomicBool>,
    abort_check: Option<&dyn Fn() -> bool>,
) -> Result<(), WalletError> {
    for _ in 0..secs {
        if shutdown.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
            return Err(WalletError::Interrupted("Shutdown requested"));
        }
        if abort_check.is_some_and(|f| f()) {
            return Err(WalletError::Interrupted("Abort requested"));
        }
        thread::sleep(Duration::from_secs(1));
    }
    Ok(())
}

/// True when `tx` is the transaction `utxo` names (txid recomputed, not
/// trusted) and really pays the reported script and value at `utxo.vout`.
fn utxo_matches_tx(tx: &Transaction, utxo: &ListUnspentResultEntry) -> bool {
    tx.compute_txid() == utxo.txid
        && tx
            .output
            .get(utxo.vout as usize)
            .is_some_and(|out| out.script_pubkey == utxo.script_pub_key && out.value == utxo.amount)
}

/// scriptPubKey at `(keychain, index)` under an already-derived account key.
/// Taking the account keeps the expensive hardened derivation out of index
/// loops, and using the account *xpub* means watch/probe paths never hold
/// any secret material.
fn derive_child_script(
    account: &Xpub,
    address_type: AddressType,
    keychain: KeychainKind,
    index: u32,
) -> Result<ScriptBuf, WalletError> {
    let secp = crate::utill::global_secp();
    let child = account.derive_pub(
        secp,
        &DerivationPath::from(vec![
            ChildNumber::from_normal_idx(keychain.index_num())?,
            ChildNumber::from_normal_idx(index)?,
        ]),
    )?;
    Ok(match address_type {
        AddressType::P2WPKH => {
            let pk = PublicKey {
                compressed: true,
                inner: child.public_key,
            };
            ScriptBuf::new_p2wpkh(
                &pk.wpubkey_hash()
                    .expect("compressed key always has wpubkey hash"),
            )
        }
        AddressType::P2TR => {
            let xonly = XOnlyPublicKey::from(child.public_key);
            ScriptBuf::new_p2tr(secp, xonly, None)
        }
    })
}

/// Wallet synchronization APIs.
impl Wallet {
    /// Register every wallet-owned scriptPubKey with the backend: HD-derived
    /// receive/change addresses (up to the rolling gap-limit window, see
    /// [`Wallet::max_watch_index`]), fidelity bonds, and persisted swapcoin SPKs.
    /// No-op on Bitcoin Core (server-side wallet tracks these); on Electrum this
    /// populates the local watch set so `list_unspent` returns the right UTXOs.
    pub(crate) fn watch_wallet_scripts(&self) -> Result<(), WalletError> {
        let secp = crate::utill::global_secp();

        // Add the descriptor utxos to the watch list.
        for address_type in [AddressType::P2WPKH, AddressType::P2TR] {
            // Watching only needs public derivation: take the account xpub
            // out of the key closure and hold no secret material for the
            // duration of the watch loop. Every (keychain, index) below it is
            // then a cheap public child derive.
            let account =
                self.with_account_key(address_type, |account| Ok(Xpub::from_priv(secp, account)))?;
            let fingerprint = account.fingerprint().to_string();
            let is_taproot = matches!(address_type, AddressType::P2TR);
            for keychain in [KeychainKind::External, KeychainKind::Internal] {
                for index in 0..=self.max_watch_index(keychain)? {
                    let script = derive_child_script(&account, address_type, keychain, index)?;
                    self.blockchain.watch_script(
                        &script,
                        Some(HdOrigin {
                            fingerprint: fingerprint.clone(),
                            keychain_idx: keychain.index_num(),
                            index,
                            is_taproot,
                        }),
                    );
                }
            }
        }

        // Watch fidelity bonds
        for bond in self.store.fidelity_bond.iter() {
            self.blockchain.watch_script(&bond.script_pub_key(), None);
        }

        // Add the incoming and outgoing swapcoins into watch list.
        // Any malformed script will error here.
        for (my_pubkey, other_pubkey, contract_redeemscript, contract_output_spk) in self
            .store
            .incoming_swapcoins
            .values()
            .map(|sc| {
                (
                    sc.my_pubkey,
                    sc.other_pubkey,
                    sc.contract_redeemscript(),
                    sc.contract_tx
                        .output
                        .get(sc.get_contract_output_vout() as usize)
                        .map(|out| &out.script_pubkey),
                )
            })
            .chain(self.store.outgoing_swapcoins.values().map(|sc| {
                (
                    sc.my_pubkey,
                    sc.other_pubkey,
                    sc.contract_redeemscript(),
                    sc.contract_tx
                        .output
                        .get(sc.get_contract_output_vout() as usize)
                        .map(|out| &out.script_pubkey),
                )
            }))
        {
            if let (Some(mine), Some(other)) = (my_pubkey, other_pubkey) {
                let multisig_redeem = create_multisig_redeemscript(&mine, &other);
                let multisig_spk = ScriptBuf::new_p2wsh(&multisig_redeem.wscript_hash());
                self.blockchain.watch_script(&multisig_spk, None);
            }
            if let Some(redeem) = contract_redeemscript {
                let contract_spk = redeemscript_to_scriptpubkey(redeem)?;
                self.blockchain.watch_script(&contract_spk, None);
            }
            // Taproot swapcoins carry no redeemscript or multisig keys; the
            // contract output's own script is the only watchable handle.
            // For legacy this duplicates the redeemscript-derived script.
            if let Some(spk) = contract_output_spk {
                self.blockchain.watch_script(spk, None);
            }
        }

        Ok(())
    }

    /// Sync the wallet, then persist to disk. The shutdown flag stops scans,
    /// backend retries, and the outer retry loop.
    pub fn sync_and_save(
        &mut self,
        shutdown: &std::sync::atomic::AtomicBool,
    ) -> Result<(), WalletError> {
        log::info!("Sync Started for {:?}", self.store.file_name);
        self.sync_no_fail(shutdown)?;
        // A seed carries no bond records. Rebuild them, then rescan from the
        // birthday so Core finds their coins.
        if self.store.pending_restore.is_some() && self.recover_fidelity_bonds()? {
            self.store.last_synced_height = None;
            self.sync_no_fail(shutdown)?;
        }
        self.store.pending_restore = None;
        self.save_to_disk()?;
        log::info!("Synced & Saved {:?}", self.store.file_name);
        Ok(())
    }

    /// Get all utxos tracked by the backend.
    ///
    /// Returns the full unspent set; coin locking is applied wallet-side at
    /// selection time (see [`Wallet::coin_select`]), not by filtering here.
    fn get_all_utxo_from_blockchain(&self) -> Result<Vec<ListUnspentResultEntry>, WalletError> {
        let all_utxos = self.blockchain.list_unspent(Some(0), Some(9999999))?;
        Ok(all_utxos)
    }

    /// Every UTXO the backend reports must be backed by a real transaction
    /// paying that script and value. Bad data here is permanent —
    /// `post_sync_updates` persists the advanced keychain indices — so a lie
    /// fails the sync before the cache or any index can move.
    fn corroborate_utxos(
        &self,
        utxos: &[ListUnspentResultEntry],
        shutdown: &std::sync::atomic::AtomicBool,
    ) -> Result<(), WalletError> {
        for utxo in utxos {
            Self::check_shutdown(shutdown)?;
            let outpoint = OutPoint {
                txid: utxo.txid,
                vout: utxo.vout,
            };
            // Already corroborated when it first entered the cache.
            if self.store.utxo_cache.contains_key(&outpoint) {
                continue;
            }
            let tx = self.blockchain.get_raw_transaction(&utxo.txid, None)?;
            if !utxo_matches_tx(&tx, utxo) {
                return Err(WalletError::General(format!(
                    "Backend reported UTXO {outpoint} that its transaction does not pay"
                )));
            }
        }
        Ok(())
    }

    fn check_watch_window(window: (u32, u32)) -> Result<(), WalletError> {
        match window.0.max(window.1) {
            window if window > MAX_WATCH_WINDOW => Err(WalletError::WatchWindowCap {
                window,
                cap: MAX_WATCH_WINDOW,
            }),
            _ => Ok(()),
        }
    }

    /// Rolling gap limit, shared by both sync paths: a wider watch window can
    /// reveal UTXOs at higher indices, which widens the window again (e.g.
    /// after a seed restore) — repeat `pass` until the window stops moving.
    fn sync_with_rolling_gap_limit(
        &mut self,
        shutdown: &std::sync::atomic::AtomicBool,
        mut pass: impl FnMut(&mut Self) -> Result<(), WalletError>,
    ) -> Result<(), WalletError> {
        let mut prev_window = (
            self.max_watch_index(KeychainKind::External)?,
            self.max_watch_index(KeychainKind::Internal)?,
        );
        // A resumed restore never passed `restore_prepared`'s check; a plain wallet
        // keeps syncing as it did before the cap existed.
        if self.store.pending_restore.is_some() {
            Self::check_watch_window(prev_window)?;
        }
        for _ in 0..MAX_SYNC_PASSES {
            Self::check_shutdown(shutdown)?;
            pass(self)?;
            Self::check_shutdown(shutdown)?;
            let utxos = self.get_all_utxo_from_blockchain()?;
            self.corroborate_utxos(&utxos, shutdown)?;
            Self::check_shutdown(shutdown)?;
            self.update_utxo_cache(utxos)?;
            let window = (
                self.max_watch_index(KeychainKind::External)?,
                self.max_watch_index(KeychainKind::Internal)?,
            );
            if window == prev_window {
                return Ok(());
            }
            Self::check_watch_window(window)?;
            prev_window = window;
        }
        Err(WalletError::General(format!(
            "Wallet sync did not settle within {MAX_SYNC_PASSES} passes"
        )))
    }

    /// Bitcoin Core's importdescriptors + scan vs Electrum's scripthash-history walk.
    fn sync(&mut self, shutdown: &std::sync::atomic::AtomicBool) -> Result<(), WalletError> {
        Self::check_shutdown(shutdown)?;
        if self.blockchain.is_electrum() {
            return self.sync_no_rescan(shutdown);
        }
        // Create or load the watch-only Bitcoin Core wallet.
        self.blockchain
            .prepare_backend_wallet(&self.store.file_name)?;

        let mut descriptors_to_import = self.descriptors_to_import()?;

        if descriptors_to_import.is_empty() && self.store.pending_restore.is_none() {
            // Nothing new to import, but the chain may have moved: refresh state.
            Self::check_shutdown(shutdown)?;
            self.update_utxo_cache(self.get_all_utxo_from_blockchain()?)?;
            return self.post_sync_updates(shutdown);
        }

        // Sometimes in tests multiple wallet scans can occur at the same time, resulting in error.
        let mut last_synced_height = self
            .store
            .last_synced_height
            .unwrap_or(0)
            .max(self.store.wallet_birthday.unwrap_or(0));
        let node_synced = self.blockchain.get_block_count()?;

        // If the chain is shorter than the wallet's last synced height (e.g. node
        // restarted with a fresh chain or a reorg), reset to rescan from the start.
        if last_synced_height > node_synced {
            log::warn!(
                "Wallet last_synced_height ({}) exceeds chain height ({}), resetting to 0",
                last_synced_height,
                node_synced
            );
            last_synced_height = 0;
            self.store.last_synced_height = Some(0);
        }

        log::info!("Re-scanning Blockchain from:{last_synced_height} to:{node_synced}");
        // A resumed restore may have imported its full descriptor range before
        // the process died. Recheck those already-imported scripts from the
        // birthday instead of mistaking an empty import list for a full scan.
        if self.store.pending_restore.is_some() && descriptors_to_import.is_empty() {
            Self::check_shutdown(shutdown)?;
            self.blockchain.rescan_wallet_from(last_synced_height)?;
            // The rescan can reveal a UTXO near the old range boundary, so
            // import the newly required range before testing for convergence.
            descriptors_to_import = self.descriptors_to_import()?;
        }

        let Header { time, .. } = self.blockchain.header_at_height(last_synced_height)?;

        // The import timestamp stays anchored to the pre-sync height so a
        // widened range is scanned over the same blocks on later passes.
        self.sync_with_rolling_gap_limit(shutdown, |w| {
            Self::check_shutdown(shutdown)?;
            if !descriptors_to_import.is_empty() {
                w.import_descriptors(&descriptors_to_import, Some(time), None)?;
            }

            // Returns when the scanning is completed.
            loop {
                Self::check_shutdown(shutdown)?;
                match w.blockchain.wallet_scanning_status()? {
                    Some(ScanningDetails::Scanning { duration, .. }) => {
                        // Todo: Show scan progress
                        log::info!("Scanning for {}s", duration);
                        Self::wait_for_shutdown(shutdown, HEART_BEAT_INTERVAL)?;
                        continue;
                    }
                    Some(ScanningDetails::NotScanning(_)) => {
                        log::info!("Scanning completed");
                        break;
                    }
                    None => {
                        log::info!("No scan is in progress or Scanning completed");
                        break;
                    }
                }
            }
            descriptors_to_import = w.descriptors_to_import()?;
            Ok(())
        })?;
        self.post_sync_updates(shutdown)
    }

    /// Electrum-style sync: register every wallet-owned script client-side, then
    /// list UTXOs via per-scripthash queries.
    fn sync_no_rescan(
        &mut self,
        shutdown: &std::sync::atomic::AtomicBool,
    ) -> Result<(), WalletError> {
        self.sync_with_rolling_gap_limit(shutdown, |w| {
            Self::check_shutdown(shutdown)?;
            w.watch_wallet_scripts()
        })?;
        self.post_sync_updates(shutdown)
    }

    /// Shared tail of both sync paths: record the synced tip, advance the
    /// keychain indices, and recompute the offer-max cache. Both callers
    /// refresh the UTXO cache inside their gap-limit loops before calling this.
    fn post_sync_updates(
        &mut self,
        shutdown: &std::sync::atomic::AtomicBool,
    ) -> Result<(), WalletError> {
        Self::check_shutdown(shutdown)?;
        self.store.last_synced_height = Some(self.blockchain.get_block_count()?);
        // Monotonic: on-chain discovery may advance the indices but never
        // rewind them below addresses already handed out (they may be funded
        // later). Internal only lags after a seed restore; advancing it there
        // avoids reusing old change addresses.
        let max_external_index = self.find_hd_next_index(KeychainKind::External)?;
        self.store.external_index = max_external_index.max(self.store.external_index);
        Self::check_shutdown(shutdown)?;
        let max_internal_index = self.find_hd_next_index(KeychainKind::Internal)?;
        self.store.internal_index = max_internal_index.max(self.store.internal_index);
        self.refresh_offer_maxsize_cache()
    }

    /// Retry sync until it succeeds; handles transient backend errors.
    /// The shutdown flag breaks the loop so teardown can join the caller's
    /// thread instead of retrying against a dead backend forever.
    fn sync_no_fail(
        &mut self,
        shutdown: &std::sync::atomic::AtomicBool,
    ) -> Result<(), WalletError> {
        loop {
            Self::check_shutdown(shutdown)?;
            match self.sync(shutdown) {
                Ok(()) => return Ok(()),
                Err(e) if Self::sync_error_is_final(&e) => return Err(e),
                Err(e) => log::error!("Blockchain sync failed. Retrying. | {e:?}"),
            }
            Self::wait_for_shutdown(shutdown, HEART_BEAT_INTERVAL)?;
        }
    }

    /// Errors a retry cannot fix: shutdown, a watch window past the cap
    /// (fixed by the wallet's counters and gap), or a too-old Bitcoin Core.
    fn sync_error_is_final(e: &WalletError) -> bool {
        matches!(
            e,
            WalletError::Interrupted(_)
                | WalletError::WatchWindowCap { .. }
                | WalletError::CoreTooOld
        )
    }

    /// Returns a typed interruption so shutdown never enters the outer retry path.
    fn check_shutdown(shutdown: &std::sync::atomic::AtomicBool) -> Result<(), WalletError> {
        if shutdown.load(std::sync::atomic::Ordering::Relaxed) {
            Err(WalletError::Interrupted("Shutdown requested"))
        } else {
            Ok(())
        }
    }

    /// Splits retry waits so cancellation is observed within one second.
    fn wait_for_shutdown(
        shutdown: &std::sync::atomic::AtomicBool,
        duration: Duration,
    ) -> Result<(), WalletError> {
        let mut remaining = duration;
        while !remaining.is_zero() {
            Self::check_shutdown(shutdown)?;
            let slice = remaining.min(Duration::from_secs(1));
            thread::sleep(slice);
            remaining -= slice;
        }
        Self::check_shutdown(shutdown)
    }

    /// Build descriptor import requests and hand them to the backend. Does not
    /// check whether the descriptors were already imported. Scans blocks from a
    /// given timestamp. No-op on Electrum (which pre-registers scripts instead).
    pub(crate) fn import_descriptors(
        &self,
        descriptors_to_import: &[String],
        time: Option<u32>,
        address_label: Option<String>,
    ) -> Result<(), WalletError> {
        let address_label = address_label.unwrap_or(self.get_core_wallet_label());

        // Offset by +2h because importdescriptors applies a default -2h to the timestamp.
        let time_stamp = time.map(|t| json!(t + 7200)).unwrap_or(json!("now"));

        // Ranged (HD) descriptors are imported up to the rolling gap-limit
        // window; a single range covering both keychains keeps the import flat.
        let max_index = self
            .max_watch_index(KeychainKind::External)?
            .max(self.max_watch_index(KeychainKind::Internal)?);

        let import_requests: Vec<Value> = descriptors_to_import
            .iter()
            .map(|desc| {
                if desc.contains("/*") {
                    json!({
                        "timestamp": time_stamp,
                        "desc": desc,
                        "range": max_index
                    })
                } else {
                    json!({
                        "timestamp": time_stamp,
                        "desc": desc,
                        "label": address_label
                    })
                }
            })
            .collect();
        self.blockchain.import_descriptors(&import_requests)
    }
}

#[cfg(test)]
mod utxo_corroboration_tests {
    use super::*;
    use bitcoin::{absolute::LockTime, hashes::Hash, transaction::Version};
    use bitcoind::tempfile::tempdir;

    fn entry_for(
        tx: &Transaction,
        vout: u32,
        spk: ScriptBuf,
        amount: Amount,
    ) -> ListUnspentResultEntry {
        ListUnspentResultEntry {
            txid: tx.compute_txid(),
            vout,
            address: None,
            label: None,
            redeem_script: None,
            witness_script: None,
            script_pub_key: spk,
            amount,
            confirmations: 1,
            spendable: true,
            solvable: true,
            descriptor: None,
            safe: true,
        }
    }

    #[test]
    fn fabricated_utxo_fails_corroboration() {
        let spk = ScriptBuf::from_bytes(vec![0x51]);
        let value = Amount::from_sat(1000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value,
                script_pubkey: spk.clone(),
            }],
        };

        // Honest report passes.
        assert!(utxo_matches_tx(&tx, &entry_for(&tx, 0, spk.clone(), value)));
        // Wrong value.
        assert!(!utxo_matches_tx(
            &tx,
            &entry_for(&tx, 0, spk.clone(), Amount::from_sat(2000))
        ));
        // Wrong script.
        assert!(!utxo_matches_tx(
            &tx,
            &entry_for(&tx, 0, ScriptBuf::from_bytes(vec![0x52]), value)
        ));
        // Non-existent output index.
        assert!(!utxo_matches_tx(
            &tx,
            &entry_for(&tx, 1, spk.clone(), value)
        ));
        // Txid that does not hash to the fetched transaction.
        let mut lying = entry_for(&tx, 0, spk, value);
        lying.txid = Txid::all_zeros();
        assert!(!utxo_matches_tx(&tx, &lying));
    }

    #[test]
    fn cached_utxo_refresh_preserves_transaction_value_and_script() {
        let dir = tempdir().unwrap();
        let mut wallet = super::test_support::test_wallet(&dir.path().join("cache-test-wallet"));
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let amount = Amount::from_sat(1_000);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: amount,
                script_pubkey: script.clone(),
            }],
        };
        let original = entry_for(&tx, 0, script.clone(), amount);
        let outpoint = OutPoint::new(original.txid, original.vout);
        wallet.store.utxo_cache.insert(
            outpoint,
            (
                original.clone(),
                UTXOSpendInfo::SeedCoin {
                    path: "m/0/0".into(),
                    input_value: amount,
                    address_type: AddressType::P2WPKH,
                },
            ),
        );
        let mut refreshed = original;
        refreshed.amount = Amount::from_sat(2_000);
        refreshed.script_pub_key = ScriptBuf::from_bytes(vec![0x52]);
        refreshed.confirmations = 6;

        wallet.update_utxo_cache(vec![refreshed]).unwrap();

        let (cached, _) = &wallet.store.utxo_cache[&outpoint];
        assert_eq!(cached.amount, amount);
        assert_eq!(cached.script_pub_key, script);
        assert_eq!(cached.confirmations, 6);
    }
}

/// Fixtures shared by unit tests that never reach the backend.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::wallet::blockchain::{BackendConfig, CoreRpcConfig};

    /// Regtest wallet with an empty UTXO cache, so coin selection fails
    /// locally instead of calling out to a node.
    pub(crate) fn test_wallet(path: &Path) -> Wallet {
        test_wallet_with_key(
            path,
            Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap(),
        )
    }

    /// Like [`test_wallet`], with `master_key` and no stored seed phrase.
    pub(crate) fn test_wallet_with_key(path: &Path, master_key: Xpriv) -> Wallet {
        let enc_material =
            KeyMaterial::new_from_password(Some("test-password".to_string())).unwrap();
        let store = WalletStore::init(
            "prevout-contract-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
            None,
            None,
            &enc_material,
        )
        .unwrap();

        let blockchain =
            AnyBlockchain::from_config(&BackendConfig::CoreRpc(CoreRpcConfig::default())).unwrap();

        Wallet {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        }
    }
}

#[cfg(test)]
mod coin_select_cap_tests {
    use super::{test_support::test_wallet, *};
    use crate::utill::MIN_RELAY_FEE_RATE;
    use bitcoind::tempfile::tempdir;

    #[test]
    fn coin_select_rejects_amounts_above_the_cap() {
        let dir = tempdir().unwrap();
        let wallet = test_wallet(&dir.path().join("cap-test-wallet"));

        // `target + fee` inside coin_select is plain u64 arithmetic.
        for amount in [
            Amount::from_sat(u64::MAX),
            Amount::MAX_MONEY + Amount::ONE_SAT,
        ] {
            let err = wallet
                .coin_select(amount, MIN_RELAY_FEE_RATE, AddressType::P2WPKH, None, None)
                .unwrap_err();
            assert!(
                format!("{:?}", err).contains("21M"),
                "{} sats must trip the cap: {:?}",
                amount.to_sat(),
                err
            );
        }

        // The cap itself is spendable as far as this check is concerned, so a
        // `>=` here would be wrong; it fails later for want of funds.
        let err = wallet
            .coin_select(
                Amount::MAX_MONEY,
                MIN_RELAY_FEE_RATE,
                AddressType::P2WPKH,
                None,
                None,
            )
            .unwrap_err();
        assert!(
            matches!(err, WalletError::InsufficientFund { .. }),
            "the cap itself must reach coin selection, not the guard: {:?}",
            err
        );
    }
}

#[cfg(test)]
mod swap_reservation_tests {
    use super::{test_support::test_wallet, *};
    use bitcoin::hashes::Hash;
    use bitcoind::tempfile::tempdir;

    fn outpoint(n: u8) -> OutPoint {
        OutPoint::new(Txid::from_slice(&[n; 32]).unwrap(), 0)
    }

    #[test]
    fn a_reservation_survives_a_wallet_reload() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet.cbor");
        let reserved = outpoint(1);

        {
            let mut wallet = test_wallet(&path);
            wallet.reserve_swap_locks("swap-1", &[reserved]);
            assert!(wallet.is_swap_reserved(&reserved));
            wallet.save_to_disk().unwrap();
        }

        // A restarted maker must still refuse these inputs to another swap:
        // the funding it planned them for can still reach the network.
        let (store, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        let locks = store
            .swap_locks
            .get("swap-1")
            .expect("the reservation must outlive the process that took it");
        assert!(locks.outpoints.contains(&reserved));
        assert!(!locks.outpoints.contains(&outpoint(2)));
        assert!(locks.reserved_at > 0, "the lock time must be persisted too");
    }

    #[test]
    fn only_a_spendable_coin_no_swap_holds_can_be_claimed() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet.cbor"));
        let coin = outpoint(3);
        let amount = Amount::from_sat(50_000);
        wallet.store.utxo_cache.insert(
            coin,
            (
                ListUnspentResultEntry {
                    txid: coin.txid,
                    vout: coin.vout,
                    address: None,
                    label: None,
                    redeem_script: None,
                    witness_script: None,
                    script_pub_key: ScriptBuf::from_bytes(vec![0x51]),
                    amount,
                    confirmations: 1,
                    spendable: true,
                    solvable: true,
                    descriptor: None,
                    safe: true,
                },
                UTXOSpendInfo::SeedCoin {
                    path: "m/0/0".into(),
                    input_value: amount,
                    address_type: AddressType::P2WPKH,
                },
            ),
        );

        assert!(
            !wallet.claim_swap_inputs("swap-a", &[outpoint(4)]),
            "not a wallet coin"
        );
        assert_eq!(wallet.plannable_balance(), amount);
        assert!(wallet.claim_swap_inputs("swap-a", &[coin]));
        assert_eq!(
            wallet.plannable_balance(),
            Amount::ZERO,
            "a claimed coin is not available to plan"
        );
        assert!(
            !wallet.claim_swap_inputs("swap-b", &[coin]),
            "held by another swap"
        );
        assert!(!wallet.store.swap_locks.contains_key("swap-b"));

        assert!(
            wallet.claim_or_hold_swap_inputs("swap-a", &[coin]),
            "a swap's own claim does not block it"
        );
        assert!(
            !wallet.claim_or_hold_swap_inputs("swap-b", &[coin]),
            "another swap's claim does"
        );
        assert!(
            !wallet.claim_or_hold_swap_inputs("swap-a", &[coin, outpoint(4)]),
            "a claim that does not cover every input is not held"
        );
        assert!(
            !wallet.store.swap_locks["swap-a"]
                .outpoints
                .contains(&outpoint(4)),
            "a refused claim reserves nothing"
        );
        assert!(!wallet.store.swap_locks.contains_key("swap-b"));
    }
}

#[cfg(test)]
mod prevout_contract_tests {
    use super::{test_support::test_wallet, *};
    use bitcoind::tempfile::tempdir;

    #[test]
    fn proof_of_funding_rejects_missing_cached_contract() {
        let temp_dir = tempdir().unwrap();
        let wallet = test_wallet(&temp_dir.path().join("wallet.cbor"));

        let error = wallet
            .ensure_prevout_matches_cached_contract(
                &OutPoint::null(),
                ScriptBuf::from_bytes(vec![0x51]).as_script(),
            )
            .unwrap_err();

        assert!(matches!(
            error,
            WalletError::General(message) if message.contains("No cached sender contract")
        ));
    }

    #[test]
    fn cached_contract_matches_only_the_approved_script() {
        let temp_dir = tempdir().unwrap();
        let mut wallet = test_wallet(&temp_dir.path().join("wallet.cbor"));
        let prevout = OutPoint::null();
        let approved_contract = ScriptBuf::from_bytes(vec![0x51]);
        let different_contract = ScriptBuf::from_bytes(vec![0x52]);

        wallet
            .cache_prevout_to_contract(&[(prevout, approved_contract.clone())])
            .unwrap();

        wallet
            .ensure_prevout_matches_cached_contract(&prevout, approved_contract.as_script())
            .unwrap();
        assert!(wallet
            .ensure_prevout_matches_cached_contract(&prevout, different_contract.as_script())
            .is_err());
    }

    #[test]
    fn cached_contract_is_idempotent_immutable_and_persistent() {
        let temp_dir = tempdir().unwrap();
        let wallet_path = temp_dir.path().join("wallet.cbor");
        let mut wallet = test_wallet(&wallet_path);
        let prevout = OutPoint::null();
        let new_prevout = OutPoint {
            txid: prevout.txid,
            vout: 1,
        };
        let approved_contract = ScriptBuf::from_bytes(vec![0x51]);

        wallet
            .cache_prevout_to_contract(&[(prevout, approved_contract.clone())])
            .unwrap();
        wallet
            .cache_prevout_to_contract(&[(prevout, approved_contract.clone())])
            .unwrap();
        assert!(wallet
            .cache_prevout_to_contract(&[
                (new_prevout, ScriptBuf::from_bytes(vec![0x53])),
                (prevout, ScriptBuf::from_bytes(vec![0x52])),
            ])
            .is_err());
        assert!(!wallet
            .store
            .prevout_to_contract_map
            .contains_key(&new_prevout));

        let (reloaded_store, _) =
            WalletStore::read_from_disk(&wallet_path, Some("test-password".to_string())).unwrap();
        assert_eq!(
            reloaded_store.prevout_to_contract_map.get(&prevout),
            Some(&approved_contract)
        );
    }
}

#[cfg(test)]
mod restore_history_probe_tests {
    use super::*;
    use crate::{
        security::{load_sensitive_struct, SerdeJson},
        wallet::{
            blockchain::Electrum, ffi::restore_wallet_from_backup_gui_app, storage::SecretEntropy,
            BackendConfig, WalletBackup,
        },
    };
    use bitcoin::{
        consensus::encode::serialize_hex,
        hashes::{sha256, Hash},
    };
    use bitcoind::tempfile::tempdir;
    use std::{
        collections::HashSet as StdHashSet,
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
    };
    use zeroize::Zeroizing;

    const MASTER_SEED: [u8; 32] = [42; 32];

    fn scripthash_hex(script: &Script) -> String {
        let mut hash = sha256::Hash::hash(script.as_bytes()).to_byte_array();
        hash.reverse();
        hash.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The smallest Electrum server that `Electrum::new` and a history probe need:
    /// a handshake, plus a scripted `get_history` answer per scripthash.
    fn start_stub(with_history: StdHashSet<String>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);
        // Restore lists the history's transactions, so the stub must serve one.
        let history_tx = genesis.txdata[0].clone();
        let history_txid = history_tx.compute_txid().to_string();
        let history_tx_hex = serialize_hex(&history_tx);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                // Each probe is one tiny request/reply, so Nagle would add its
                // delay to every single one of them.
                let _ = stream.set_nodelay(true);
                let (hash, header) = (genesis_hash.clone(), header_hex.clone());
                let (txid, tx_hex) = (history_txid.clone(), history_tx_hex.clone());
                let known = with_history.clone();
                thread::spawn(move || {
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let req: Value = match serde_json::from_str(&line) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = req["id"].clone();
                        let result = match req["method"].as_str().unwrap_or_default() {
                            "server.features" => json!({
                                "server_version": "stub",
                                "genesis_hash": hash,
                                "protocol_min": "1.4",
                                "protocol_max": "1.4",
                                "hash_function": "sha256",
                                "pruning": Value::Null,
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"height": 0, "hex": header})
                            }
                            "blockchain.scripthash.get_history" => {
                                let sh = req["params"][0].as_str().unwrap_or_default();
                                if known.contains(sh) {
                                    json!([{"height": 1, "tx_hash": txid}])
                                } else {
                                    json!([])
                                }
                            }
                            "blockchain.scripthash.listunspent" => json!([]),
                            "blockchain.transaction.get" => json!(tx_hex),
                            _ => json!(Value::Null),
                        };
                        let resp = json!({"jsonrpc": "2.0", "id": id, "result": result});
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });

        url
    }

    fn account_for(seed: &[u8], address_type: AddressType) -> Xpub {
        let secp = crate::utill::global_secp();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, seed).unwrap();
        let account = master
            .derive_priv(
                secp,
                &Wallet::get_derivation_path(address_type, bitcoin::Network::Regtest),
            )
            .unwrap();
        Xpub::from_priv(secp, &account)
    }

    fn electrum_config(url: String) -> crate::wallet::ElectrumConfig {
        crate::wallet::ElectrumConfig {
            url,
            ..Default::default()
        }
    }

    fn stub_wallet(path: &Path, url: String) -> Wallet {
        let master_key = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        let enc_material = KeyMaterial::new_ephemeral();
        let store = WalletStore::init(
            "restore-probe-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
            None,
            Some(RestoreOptions::default()),
            &enc_material,
        )
        .unwrap();
        let electrum = Electrum::new(&electrum_config(url)).expect("connect to stub");

        Wallet {
            blockchain: AnyBlockchain::Electrum(electrum),
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        }
    }

    /// A restored wallet holds no UTXOs and no hand-out counters, so only script
    /// history can reveal index 60. The gap between it and index 0 is far wider
    /// than the regular 20, and the two indices use different address types.
    #[test]
    fn restore_probe_bridges_a_long_run_of_emptied_addresses() {
        let temp_dir = tempdir().unwrap();
        let external = KeychainKind::External;
        let funded = |address_type, index| {
            let account = account_for(&MASTER_SEED, address_type);
            let script =
                derive_child_script(&account, address_type, external, index).expect("derive");
            scripthash_hex(&script)
        };
        let with_history = StdHashSet::from([
            funded(AddressType::P2WPKH, 0),
            funded(AddressType::P2TR, 60),
        ]);

        let url = start_stub(with_history);
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), url);

        assert_eq!(
            wallet.find_hd_next_index(external).unwrap(),
            61,
            "history probing must reach the P2TR-only index past the hole"
        );

        // The hole is 59 unused addresses: a gap of 60 bridges it, 59 does not.
        for (address_gap, expected) in [(60, 61), (59, 1)] {
            wallet.store.pending_restore = Some(RestoreOptions {
                address_gap,
                ..Default::default()
            });
            let next = wallet.find_hd_next_index(external).unwrap();
            assert_eq!(next, expected, "gap {address_gap}");
        }

        // Without the restore flag the probe is off and the empty UTXO set decides.
        wallet.store.pending_restore = None;
        assert_eq!(wallet.find_hd_next_index(external).unwrap(), 0);
    }

    /// The probe stops at the cap. A full empty run ending exactly on it passes;
    /// one address short, it reports the cap instead of missing coins past it.
    /// A cached coin starts the probe near the cap, so the run stays short.
    #[test]
    fn restore_probe_reports_a_window_cut_off_by_the_cap() {
        let temp_dir = tempdir().unwrap();
        let external = KeychainKind::External;
        let gap = ADDRESS_IMPORT_COUNT;
        for (next, expected) in [
            (MAX_WATCH_WINDOW - gap + 1, Ok(MAX_WATCH_WINDOW - gap + 1)),
            (MAX_WATCH_WINDOW - gap + 2, Err(MAX_WATCH_WINDOW + 1)),
        ] {
            let url = start_stub(StdHashSet::new());
            let mut wallet = stub_wallet(&temp_dir.path().join(format!("w{next}")), url);
            wallet.store.pending_restore = Some(RestoreOptions {
                address_gap: gap,
                ..Default::default()
            });
            let coin = ListUnspentResultEntry {
                txid: bitcoin::Txid::all_zeros(),
                vout: 0,
                address: None,
                label: None,
                redeem_script: None,
                witness_script: None,
                script_pub_key: ScriptBuf::new(),
                amount: Amount::from_sat(1_000),
                confirmations: 1,
                spendable: true,
                solvable: true,
                descriptor: Some(format!("wpkh([00000000/0/{}])", next - 1)),
                safe: true,
            };
            let spend = UTXOSpendInfo::SeedCoin {
                path: format!("m/0/{}", next - 1),
                input_value: coin.amount,
                address_type: AddressType::P2WPKH,
            };
            wallet
                .store
                .utxo_cache
                .insert(OutPoint::new(coin.txid, 0), (coin, spend));
            match (wallet.find_hd_next_index(external), expected) {
                (Ok(got), Ok(want)) => assert_eq!(got, want),
                (Err(WalletError::WatchWindowCap { window, cap }), Err(want)) => {
                    assert_eq!((window, cap), (want, MAX_WATCH_WINDOW))
                }
                (got, want) => panic!("next {}: got {:?}, want {:?}", next, got, want),
            }
        }
    }

    /// A restore resumed from a file never passed the start check, so the
    /// first sync pass must reject a window already past the cap.
    #[test]
    fn resumed_restore_checks_the_window_before_syncing() {
        let temp_dir = tempdir().unwrap();
        let url = start_stub(StdHashSet::new());
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), url);
        wallet.store.external_index = MAX_WATCH_WINDOW - 50;
        assert!(matches!(
            wallet.sync_no_rescan(&crate::utill::NO_SHUTDOWN),
            Err(WalletError::WatchWindowCap { window, .. }) if window == MAX_WATCH_WINDOW + 49
        ));
    }

    /// A window past the cap or a too-old Core is final: `sync_no_fail` must
    /// not retry it forever.
    #[test]
    fn window_cap_and_old_core_are_not_retried() {
        let cap = WalletError::WatchWindowCap {
            window: MAX_WATCH_WINDOW + 1,
            cap: MAX_WATCH_WINDOW,
        };
        assert!(Wallet::sync_error_is_final(&cap));
        assert!(Wallet::sync_error_is_final(&WalletError::CoreTooOld));
        assert!(!Wallet::sync_error_is_final(&WalletError::General(
            "rpc down".into()
        )));
    }

    /// A file from an older restore has no saved options and resumes at the
    /// default gap of 100, which misses index 150; the saved gap of 200 finds it.
    #[test]
    fn interrupted_restore_finishes_before_wallet_is_loaded() {
        let script = derive_child_script(
            &account_for(&MASTER_SEED, AddressType::P2TR),
            AddressType::P2TR,
            KeychainKind::External,
            150,
        )
        .unwrap();
        let wider = RestoreOptions {
            address_gap: 200,
            ..Default::default()
        };
        for (pending_restore, expected) in [(None, 0), (Some(wider), 151)] {
            let temp_dir = tempdir().unwrap();
            let path = temp_dir.path().join("restore-probe-test");
            let url = start_stub(StdHashSet::from([scripthash_hex(&script)]));
            let password = "restore-test-password".to_string();
            let material = KeyMaterial::new_from_password(Some(password.clone())).unwrap();
            let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
            // This is the on-disk state after restore created the file but before
            // its first scan saved a height.
            WalletStore::init(
                path.file_name().unwrap().to_str().unwrap().to_string(),
                &path,
                bitcoin::Network::Regtest,
                master,
                None,
                pending_restore,
                &material,
            )
            .unwrap();

            let backend = AnyBlockchain::Electrum(Electrum::new(&electrum_config(url)).unwrap());
            let wallet = Wallet::load_or_init(&path, backend, Some(password.clone())).unwrap();
            assert_eq!(wallet.store.external_index, expected);

            let (saved, _) = WalletStore::read_from_disk(&path, Some(password)).unwrap();
            assert_eq!(saved.external_index, expected);
            assert!(saved.last_synced_height.is_some());
            assert!(saved.pending_restore.is_none());
        }
    }

    /// `init-wallet` on an existing wallet must reject a wrong passphrase
    /// instead of exiting 0, without needing a backend.
    #[test]
    fn init_interactive_checks_the_passphrase_of_an_existing_wallet() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("init-existing");
        let material = KeyMaterial::new_from_password(Some("right".to_string())).unwrap();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        WalletStore::init(
            "init-existing".to_string(),
            &path,
            bitcoin::Network::Regtest,
            master,
            None,
            None,
            &material,
        )
        .unwrap();
        // Unreachable, so a backend call would fail the right-passphrase case.
        let backend = BackendConfig::Electrum(electrum_config("tcp://127.0.0.1:1".to_string()));

        Wallet::init_interactive(&path, &backend, Some("right".to_string())).unwrap();
        let err = Wallet::init_interactive(&path, &backend, Some("wrong".to_string()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"), "{}", err);
    }

    /// The passphrase check of `init-wallet` upgrades an older file only
    /// when no process holds the wallet, and never on a wrong passphrase.
    #[test]
    fn init_interactive_upgrades_an_older_wallet_only_when_idle() {
        let temp_dir = tempdir().unwrap();
        let backend = BackendConfig::Electrum(electrum_config("tcp://127.0.0.1:1".to_string()));

        let v023 = temp_dir.path().join("closed.wallet");
        let v023_source = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet");
        std::fs::write(&v023, v023_source).unwrap();

        let unmarked = temp_dir.path().join("unmarked");
        let material = KeyMaterial::new_from_password(Some("right".to_string())).unwrap();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        WalletStore::init(
            "unmarked".to_string(),
            &unmarked,
            bitcoin::Network::Regtest,
            master,
            None,
            None,
            &material,
        )
        .unwrap();
        let (store, material) =
            WalletStore::read_from_disk(&unmarked, Some("right".to_string())).unwrap();
        let unmarked_source = serde_cbor::to_vec(
            &crate::security::encrypt_struct_v2(&store, &material, Vec::new()).unwrap(),
        )
        .unwrap();
        std::fs::write(&unmarked, &unmarked_source).unwrap();

        for (path, source, password, suffix) in [
            (&v023, &v023_source[..], "compat-v023", ".v023"),
            (&unmarked, &unmarked_source[..], "right", ".v2pre"),
        ] {
            let mut archive = path.as_os_str().to_os_string();
            archive.push(suffix);
            let archive = std::path::PathBuf::from(archive);

            let holder = WalletInUse::shared(path).unwrap();
            let err = Wallet::init_interactive(path, &backend, Some(password.to_string()))
                .unwrap_err()
                .to_string();
            assert!(err.contains(IN_USE_MESSAGE), "{}", err);
            assert_eq!(std::fs::read(path).unwrap(), source);
            assert!(!archive.exists());
            drop(holder);

            let err = Wallet::init_interactive(path, &backend, Some("wrong".to_string()))
                .unwrap_err()
                .to_string();
            assert!(err.contains("already exists"), "{}", err);
            assert_eq!(std::fs::read(path).unwrap(), source);
            assert!(!archive.exists());

            Wallet::init_interactive(path, &backend, Some(password.to_string())).unwrap();
            assert_eq!(std::fs::read(&archive).unwrap(), source);
            assert!(
                WalletStore::read_without_upgrade(path, Some(password.to_string()))
                    .unwrap()
                    .is_some()
            );
        }
    }

    /// The phrase alone must give the key and, with a wide enough gap, the
    /// coins at index 150 that the default gap of 100 cannot reach.
    #[test]
    fn restore_from_mnemonic_uses_the_phrase_key_and_gap() {
        const PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                              abandon abandon abandon abandon abandon about";
        let mnemonic = Mnemonic::parse(PHRASE).unwrap();
        let script = derive_child_script(
            &account_for(&mnemonic.to_seed(""), AddressType::P2TR),
            AddressType::P2TR,
            KeychainKind::External,
            150,
        )
        .unwrap();
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("mnemonic-wallet");
        let backend = BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::from([
            scripthash_hex(&script),
        ]))));

        // The stub's tip is the genesis block, height 0.
        let err = Wallet::restore_from_mnemonic(
            Zeroizing::new(PHRASE.to_string()),
            &path,
            &backend,
            RestoreOptions {
                birthday: Some(1),
                ..Default::default()
            },
            Zeroizing::new("test-password".to_string()),
        )
        .expect_err("a birthday above the tip is rejected");
        assert!(err.to_string().contains("above the chain tip"), "{}", err);
        assert!(!path.exists());

        let wallet = Wallet::restore_from_mnemonic(
            Zeroizing::new(PHRASE.to_string()),
            &path,
            &backend,
            RestoreOptions {
                address_gap: 200,
                ..Default::default()
            },
            Zeroizing::new("test-password".to_string()),
        )
        .unwrap();
        assert_eq!(wallet.store.external_index, 151);
        assert_eq!(
            wallet.with_master_key(|key| Ok(*key)).unwrap(),
            Wallet::master_key_from_mnemonic(&mnemonic, bitcoin::Network::Regtest).unwrap()
        );
    }

    /// A new wallet's phrase is in its first write: a restart reads it back,
    /// even if nothing after `Wallet::init` ever ran.
    #[test]
    fn new_wallet_seals_its_phrase_in_the_first_write() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("new-wallet");
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let password = || Zeroizing::new("test-password".to_string());

        let err = Wallet::init(&path, backend(), Zeroizing::default()).unwrap_err();
        assert!(
            err.to_string().contains("passphrase is required"),
            "{}",
            err
        );
        assert!(!path.exists());

        let created = Wallet::init(&path, backend(), password()).unwrap();
        let first_words = created.get_wallet_mnemonic(password()).unwrap().words();
        assert_eq!(first_words.split(' ').count(), 12);
        drop(created);

        let (saved, _) =
            WalletStore::read_from_disk(&path, Some("test-password".to_string())).unwrap();
        assert!(saved.sealed_mnemonic.is_some());
        assert!(!saved.seed_backed_up);

        let loaded =
            Wallet::load_or_init(&path, backend(), Some("test-password".to_string())).unwrap();
        let words = loaded.get_wallet_mnemonic(password()).unwrap().words();
        assert_eq!(words, first_words);
        let mnemonic = Mnemonic::parse(words.as_str()).unwrap();
        assert_eq!(
            loaded.with_master_key(|key| Ok(*key)).unwrap(),
            Wallet::master_key_from_mnemonic(&mnemonic, bitcoin::Network::Regtest).unwrap()
        );
        assert!(!loaded.seed_backed_up());
    }

    /// A library load never migrates an older file while another process
    /// holds the wallet; it migrates once the wallet is idle.
    #[test]
    fn library_load_migrates_only_when_no_process_holds_the_wallet() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("closed.wallet");
        let original = include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet");
        std::fs::write(&path, original).unwrap();
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let password = || Some("compat-v023".to_string());

        let holder = WalletInUse::shared(&path).unwrap();
        for error in [
            Wallet::load(&path, backend(), password()).err().unwrap(),
            Wallet::load_or_init(&path, backend(), password())
                .err()
                .unwrap(),
        ] {
            assert!(matches!(error, WalletError::General(ref message)
                if message == crate::wallet::seed_cli::IN_USE_MESSAGE));
        }
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(!path.with_file_name("closed.wallet.v023").exists());
        drop(holder);

        Wallet::load(&path, backend(), password()).unwrap();
        assert_eq!(
            std::fs::read(path.with_file_name("closed.wallet.v023")).unwrap(),
            original
        );
    }

    /// Every library owner holds the wallet lock while it lives, so the seed
    /// commands refuse to write under it. The offline reader holds nothing.
    #[test]
    fn live_library_wallet_blocks_seed_command_writes() {
        use crate::wallet::seed_cli::WalletInUse;

        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("wallet");
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let password = || Zeroizing::new("test-password".to_string());
        let idle = || WalletInUse::exclusive_if_idle(&path).unwrap().is_some();

        let created = Wallet::init(&path, backend(), password()).unwrap();
        assert!(!idle());
        drop(created);
        assert!(idle());

        let loaded =
            Wallet::load_or_init(&path, backend(), Some("test-password".to_string())).unwrap();
        assert!(!idle());
        let offline = Wallet::open_offline(&path, password()).unwrap();
        drop(loaded);
        assert!(idle());
        drop(offline);

        let phrase = Mnemonic::generate(12).unwrap().to_string();
        let restored_path = temp_dir.path().join("restored");
        let restored = Wallet::restore_from_mnemonic(
            Zeroizing::new(phrase),
            &restored_path,
            &BackendConfig::Electrum(electrum_config(url.clone())),
            RestoreOptions::default(),
            password(),
        )
        .unwrap();
        assert!(WalletInUse::exclusive_if_idle(&restored_path)
            .unwrap()
            .is_none());
        drop(restored);
        assert!(WalletInUse::exclusive_if_idle(&restored_path)
            .unwrap()
            .is_some());
    }

    /// Use a subprocess with a deadline: a second flock on the owner's fd
    /// path would hang forever, rather than fail an ordinary assertion.
    #[test]
    fn owner_process_creates_and_loads_wallet_without_self_deadlock() {
        use std::{
            fs::{OpenOptions, TryLockError},
            process::{Child, Command},
            sync::mpsc,
            time::{Duration, Instant},
        };

        const CHILD_ENV: &str = "OPENSWAP_OWNER_WALLET_CHILD";
        if let Some(path) = std::env::var_os(CHILD_ENV) {
            let path = PathBuf::from(path);
            let url = start_stub(StdHashSet::new());
            let password = || Zeroizing::new("test-password".to_string());
            let mut first_words = None;
            for _ in 0..2 {
                let owner = WalletInUse::owner(&path).unwrap();
                let blockchain =
                    AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
                // The same entry point used by maker and taker, with a real
                // exclusive owner even in integration-test builds.
                let mut wallet =
                    Wallet::load_or_init_with_lock(&path, blockchain, Some(password()), owner)
                        .unwrap();
                let words = wallet.get_wallet_mnemonic(password()).unwrap().words();
                assert_eq!(first_words.get_or_insert_with(|| words.clone()), &words);
                // show-seed's confirmation and attach-seed share this gate.
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
                let mut sentinel = path.as_os_str().to_os_string();
                sentinel.push(".lock");
                let reader = OpenOptions::new().write(true).open(sentinel).unwrap();
                assert!(matches!(
                    reader.try_lock_shared(),
                    Err(TryLockError::WouldBlock)
                ));
                // A save replaces the wallet inode; ownership must survive it.
                wallet.store.last_synced_height = Some(0);
                wallet.save_to_disk().unwrap();
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
                drop(wallet);
                assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
            }

            // An ordinary library load must wait before reading the file;
            // otherwise its later save could erase this owner's final state.
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let mut owner_wallet = Wallet::load_or_init_with_lock(
                &path,
                blockchain,
                Some(password()),
                WalletInUse::owner(&path).unwrap(),
            )
            .unwrap();
            let (started_tx, started_rx) = mpsc::channel();
            let (loaded_tx, loaded_rx) = mpsc::channel();
            let reader_path = path.clone();
            let reader_url = url.clone();
            let reader = std::thread::spawn(move || {
                let blockchain =
                    AnyBlockchain::Electrum(Electrum::new(&electrum_config(reader_url)).unwrap());
                started_tx.send(()).unwrap();
                loaded_tx
                    .send(Wallet::load(
                        &reader_path,
                        blockchain,
                        Some("test-password".into()),
                    ))
                    .unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            assert!(matches!(
                loaded_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            owner_wallet.store.external_index = 37;
            owner_wallet.save_to_disk().unwrap();
            drop(owner_wallet);
            let loaded = loaded_rx
                .recv_timeout(Duration::from_secs(5))
                .unwrap()
                .unwrap();
            assert_eq!(loaded.store.external_index, 37);
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
            drop(loaded);
            reader.join().unwrap();
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());

            // An unmarked, seed-bearing V2 file must also migrate while
            // consuming the daemon's one owner guard, without a second flock.
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let mut original = Wallet::load_or_init_with_lock(
                &path,
                blockchain,
                Some(password()),
                WalletInUse::owner(&path).unwrap(),
            )
            .unwrap();
            original.store.seed_backed_up = true;
            let seed_bytes = serde_cbor::to_vec(&original.store.sealed_mnemonic).unwrap();
            let master_bytes = serde_cbor::to_vec(&original.store.master_key).unwrap();
            let unmarked = crate::security::encrypt_struct_v2(
                &original.store,
                &original.store_enc_material,
                Vec::new(),
            )
            .unwrap();
            let source = serde_cbor::to_vec(&unmarked).unwrap();
            std::fs::write(&path, &source).unwrap();
            let error = Wallet::open_offline(&path, password()).unwrap_err();
            assert!(matches!(error, WalletError::General(ref message)
                if message == crate::wallet::seed_cli::IN_USE_MESSAGE));
            assert_eq!(std::fs::read(&path).unwrap(), source);
            assert!(!path.with_file_name("wallet.v2pre").exists());
            drop(original);
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let migrated = Wallet::load_or_init_with_lock(
                &path,
                blockchain,
                Some(password()),
                WalletInUse::owner(&path).unwrap(),
            )
            .unwrap();
            assert_eq!(
                std::fs::read(path.with_file_name("wallet.v2pre")).unwrap(),
                source
            );
            assert_eq!(
                serde_cbor::to_vec(&migrated.store.sealed_mnemonic).unwrap(),
                seed_bytes
            );
            assert_eq!(
                serde_cbor::to_vec(&migrated.store.master_key).unwrap(),
                master_bytes
            );
            assert!(migrated.seed_backed_up());
            assert_eq!(
                migrated.get_wallet_mnemonic(password()).unwrap().words(),
                first_words.unwrap()
            );
            let header: crate::security::EncryptedDataV2 =
                serde_cbor::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            assert_eq!(header.requires, [crate::security::WALLET_STORE_FORMAT]);
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_none());
            drop(migrated);
            assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());

            // The legacy migration branch must consume the same owner guard,
            // rather than acquiring another handle while rewriting the file.
            for (name, original, closed) in [
                (
                    "closed.wallet",
                    include_bytes!("../../tests/fixtures/compat/v0.2.3/closed.wallet").as_slice(),
                    true,
                ),
                (
                    "open.wallet",
                    include_bytes!("../../tests/fixtures/compat/v0.2.3/open.wallet").as_slice(),
                    false,
                ),
            ] {
                let legacy = path.with_file_name(name);
                std::fs::write(&legacy, original).unwrap();
                let blockchain =
                    AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
                let result = Wallet::load_or_init_with_lock(
                    &legacy,
                    blockchain,
                    Some(Zeroizing::new("compat-v023".to_string())),
                    WalletInUse::owner(&legacy).unwrap(),
                );
                let archive = path.with_file_name(format!("{name}.v023"));
                if closed {
                    let wallet = result.unwrap();
                    assert_eq!(std::fs::read(&archive).unwrap(), original);
                    assert!(WalletInUse::exclusive_if_idle(&legacy).unwrap().is_none());
                    assert!(matches!(
                        wallet.get_wallet_mnemonic(Zeroizing::new("compat-v023".to_string())),
                        Err(WalletError::MnemonicUnavailable)
                    ));
                    drop(wallet);
                } else {
                    assert!(result.unwrap_err().to_string().contains("open swaps"));
                    assert_eq!(std::fs::read(&legacy).unwrap(), original);
                    assert!(!archive.exists());
                }
                assert!(WalletInUse::exclusive_if_idle(&legacy).unwrap().is_some());
            }
            return;
        }

        struct ChildProcess(Child);
        impl Drop for ChildProcess {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let dir = tempdir().unwrap();
        let mut child = ChildProcess(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "wallet::api::restore_history_probe_tests::owner_process_creates_and_loads_wallet_without_self_deadlock",
                    "--nocapture",
                ])
                .env(CHILD_ENV, dir.path().join("wallet"))
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success(), "owner process failed: {}", status);
                break;
            }
            assert!(Instant::now() < deadline, "owner wallet startup deadlocked");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn failed_wallet_load_or_creation_releases_owner_lock() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("wallet");
        let url = start_stub(StdHashSet::new());
        let backend =
            || AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
        let open = |password| {
            Wallet::load_or_init_with_lock(
                &path,
                backend(),
                Some(Zeroizing::new(password)),
                WalletInUse::owner(&path).unwrap(),
            )
        };
        assert!(open(String::new()).is_err());
        assert!(!path.exists());
        assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
        drop(open("test-password".to_string()).unwrap());
        let original = std::fs::read(&path).unwrap();
        assert!(matches!(
            open("wrong-password".to_string()),
            Err(WalletError::Security(SecurityError::Decryption))
        ));
        assert_eq!(std::fs::read(&path).unwrap(), original);
        assert!(WalletInUse::exclusive_if_idle(&path).unwrap().is_some());
    }

    /// A malformed blocklist aborts `Taker::init` immediately after the
    /// wallet's first write. Its seed must survive that failed startup.
    #[test]
    fn seed_is_readable_after_taker_init_fails() {
        use crate::{
            blocklist::{blocklist_path, BlocklistError},
            taker::{error::TakerError, Taker, TakerInitConfig},
        };

        let temp_dir = tempdir().unwrap();
        let data_dir = temp_dir.path().join("taker");
        let path = data_dir.join("wallets").join("new-wallet");
        let url = start_stub(StdHashSet::new());
        let password = || Zeroizing::new("test-password".to_string());
        std::fs::write(blocklist_path(&data_dir), "{not valid json").unwrap();
        assert!(!path.exists());

        let err = Taker::init(TakerInitConfig {
            data_dir: Some(data_dir),
            wallet_name: "new-wallet".to_string(),
            backend: BackendConfig::Electrum(electrum_config(url)),
            password: Some("test-password".to_string()),
            check_blocklist: Some(true),
            ..Default::default()
        })
        .err()
        .expect("the blocklist must abort startup after the wallet was created");
        assert!(matches!(err, TakerError::Blocklist(BlocklistError::IO(_))));

        let first_write = std::fs::read(&path).unwrap();
        let offline = Wallet::open_offline(&path, password()).unwrap();
        let words = offline.get_wallet_mnemonic(password()).unwrap().words();
        assert_eq!(words.split(' ').count(), 12);
        let mnemonic = Mnemonic::parse(words.as_str()).unwrap();
        assert_eq!(
            offline.with_master_key(|key| Ok(*key)).unwrap(),
            Wallet::master_key_from_mnemonic(&mnemonic, bitcoin::Network::Regtest).unwrap()
        );
        assert!(!offline.seed_backed_up());
        assert_eq!(std::fs::read(&path).unwrap(), first_write);
    }

    /// Restore stores the phrase it was given, whatever its length.
    #[test]
    fn restore_from_mnemonic_seals_the_phrase() {
        let url = start_stub(StdHashSet::new());
        let backend = BackendConfig::Electrum(electrum_config(url.clone()));
        for words in [12, 24] {
            let temp_dir = tempdir().unwrap();
            let path = temp_dir.path().join("restored");
            let phrase = Mnemonic::generate(words).unwrap().to_string();
            let password = || Zeroizing::new("test-password".to_string());
            let err = Wallet::restore_from_mnemonic(
                Zeroizing::new(phrase.clone()),
                &path,
                &backend,
                RestoreOptions::default(),
                Zeroizing::default(),
            )
            .unwrap_err();
            assert!(
                err.to_string().contains("passphrase is required"),
                "{}",
                err
            );
            assert!(!path.exists());

            Wallet::restore_from_mnemonic(
                Zeroizing::new(phrase.clone()),
                &path,
                &backend,
                RestoreOptions::default(),
                password(),
            )
            .unwrap();
            let blockchain =
                AnyBlockchain::Electrum(Electrum::new(&electrum_config(url.clone())).unwrap());
            let loaded =
                Wallet::load_or_init(&path, blockchain, Some("test-password".to_string())).unwrap();
            let read = loaded.get_wallet_mnemonic(password()).unwrap().words();
            assert_eq!(read.as_str(), phrase);
        }
    }

    /// A nameless backup restore into a fresh data dir lands under `wallets/`,
    /// instead of taking `wallets` itself as the wallet file.
    #[test]
    fn backup_restore_into_a_fresh_data_dir() {
        let temp_dir = tempdir().unwrap();
        let wallet = test_support::test_wallet(&temp_dir.path().join("source"));
        let password = "backup password".to_string();
        let backup = temp_dir.path().join("backup.json");
        let km = KeyMaterial::new_from_password(Some(password.clone())).unwrap();
        wallet
            .write_backup(&backup, Zeroizing::new("test-password".to_string()), km)
            .unwrap();

        let data_dir = temp_dir.path().join("fresh");
        restore_wallet_from_backup_gui_app(
            Some(data_dir.clone()),
            None,
            BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::new()))),
            backup,
            Some(password),
            RestoreOptions::default(),
        )
        .unwrap();
        assert!(data_dir
            .join("wallets")
            .join(&wallet.store.file_name)
            .is_file());
    }

    #[test]
    fn v023_and_pre_port_backups_restore_to_marked_v2() {
        use crate::security::{EncryptedData, EncryptedDataV2, WALLET_STORE_FORMAT};

        let dir = tempdir().unwrap();
        let backend = BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::new())));
        let v023: WalletBackup = serde_cbor::from_slice(include_bytes!(
            "../../tests/fixtures/compat/v0.2.3/backup-wallet.cbor"
        ))
        .unwrap();
        let source = Wallet::init(
            &dir.path().join("source"),
            AnyBlockchain::from_config(&backend).unwrap(),
            Zeroizing::new("source-password".into()),
        )
        .unwrap();
        let words = source
            .get_wallet_mnemonic(Zeroizing::new("source-password".into()))
            .unwrap()
            .words();
        let pre_port =
            WalletBackup::new(&source, Zeroizing::new("source-password".into())).unwrap();
        // #1165's backup predates `requires`; preserve its seed payload.
        let serde_cbor::Value::Map(mut payload) = serde_cbor::value::to_value(&pre_port).unwrap()
        else {
            panic!("backup is a map")
        };
        payload.remove(&serde_cbor::Value::Text("requires".into()));
        let pre_port: WalletBackup =
            serde_cbor::value::from_value(serde_cbor::Value::Map(payload)).unwrap();

        for (name, backup, has_seed) in [("v023", v023, false), ("pre-port", pre_port, true)] {
            assert!(backup.requires.is_empty());
            let path = dir.path().join(name);
            let restored = Wallet::restore_with(
                &backup,
                &path,
                &backend,
                Zeroizing::new("restored-password".into()),
                RestoreOptions::default(),
            )
            .unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let container: EncryptedDataV2 = serde_cbor::from_slice(&bytes).unwrap();
            assert_eq!(container.requires, [WALLET_STORE_FORMAT]);
            assert!(serde_cbor::from_slice::<EncryptedData>(&bytes).is_err());
            let seed = restored.get_wallet_mnemonic(Zeroizing::new("restored-password".into()));
            if has_seed {
                assert_eq!(seed.unwrap().words(), words);
            } else {
                assert!(matches!(seed, Err(WalletError::MnemonicUnavailable)));
            }
        }
    }

    /// A backup takes the phrase only past the current wallet password, and a
    /// restore seals it again under the new wallet's own password. A backup
    /// without one restores with none; one whose phrase doesn't derive its
    /// key is refused before any file is written.
    #[test]
    fn backup_carries_the_phrase_to_the_restored_wallet() {
        let temp_dir = tempdir().unwrap();
        let backend = BackendConfig::Electrum(electrum_config(start_stub(StdHashSet::new())));
        let password = |text: &str| Zeroizing::new(text.to_string());
        let wallet = Wallet::init(
            &temp_dir.path().join("source"),
            AnyBlockchain::from_config(&backend).unwrap(),
            password("test-password"),
        )
        .unwrap();
        let phrase = wallet
            .get_wallet_mnemonic(password("test-password"))
            .unwrap()
            .words();

        let backup_file = temp_dir.path().join("backup.json");
        let backup_gui = |wallet_password: Option<&str>| {
            wallet.backup_wallet_gui_app(
                backup_file.display().to_string(),
                Some("backup password".to_string()),
                wallet_password.map(str::to_string),
            )
        };
        for wrong in [None, Some(""), Some("wrong-password")] {
            let err = backup_gui(wrong).unwrap_err();
            assert!(matches!(err, WalletError::WrongPassword), "{}", err);
        }
        assert!(!backup_file.exists());
        backup_gui(Some("test-password")).unwrap();
        let (mut backup, _) = load_sensitive_struct::<WalletBackup, SerdeJson>(
            &backup_file,
            Some("backup password".to_string()),
        )
        .unwrap();

        let restore = |backup: &WalletBackup, name: &str| {
            Wallet::restore_with(
                backup,
                &temp_dir.path().join(name),
                &backend,
                password("new-password"),
                RestoreOptions::default(),
            )
        };
        let restored = restore(&backup, "restored").unwrap();
        let read = restored.get_wallet_mnemonic(password("new-password"));
        assert_eq!(read.unwrap().words(), phrase);
        assert!(matches!(
            restored.get_wallet_mnemonic(password("test-password")),
            Err(WalletError::WrongPassword)
        ));
        let (saved, _) = WalletStore::read_from_disk(
            &temp_dir.path().join("restored"),
            Some("new-password".to_string()),
        )
        .unwrap();
        assert_eq!(saved.sealed_mnemonic, restored.store.sealed_mnemonic);
        assert_ne!(saved.sealed_mnemonic, wallet.store.sealed_mnemonic);

        let other = Mnemonic::generate(12).unwrap();
        backup.mnemonic = Some(SecretEntropy::from_mnemonic(&other).unwrap());
        let err = restore(&backup, "mismatched").unwrap_err();
        assert!(matches!(err, WalletError::MnemonicMismatch), "{}", err);
        assert!(!temp_dir.path().join("mismatched").exists());

        backup.mnemonic = None;
        let old = restore(&backup, "old").unwrap();
        assert!(matches!(
            old.get_wallet_mnemonic(password("new-password")),
            Err(WalletError::MnemonicUnavailable)
        ));
    }

    /// Proves a stopped sync returns before making its first backend request.
    #[test]
    fn sync_does_not_enter_the_backend_after_shutdown() {
        let temp_dir = tempdir().unwrap();
        let url = start_stub(StdHashSet::new());
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), url);
        let shutdown = std::sync::atomic::AtomicBool::new(true);

        assert!(matches!(
            wallet.sync_and_save(&shutdown),
            Err(WalletError::Interrupted("Shutdown requested"))
        ));
    }
}

/// A recovery pass that finds our own timelock recovery already confirmed must
/// record it as resolved with its txid, drop the swapcoin, persist that, and
/// leave nothing for the next pass. Run against stubbed backends.
#[cfg(test)]
mod timelock_reconcile_tests {
    use super::*;
    use crate::{
        protocol::contract::{create_contract_redeemscript, Hash160},
        wallet::{blockchain::Electrum, swapcoin::OutgoingSwapCoin, test_wallet},
    };
    use bitcoin::{
        consensus::encode::serialize_hex, hashes::Hash, locktime::absolute::LockTime, BlockHash,
        TxIn,
    };
    use bitcoind::tempfile::tempdir;
    use serde_cbor::{value::to_value as to_cbor_value, Value as CborValue};
    use std::{
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
        sync::{atomic::AtomicBool, Arc, RwLock},
    };

    const CONTRACT_HEIGHT: i64 = 5;
    const RECOVERY_HEIGHT: i64 = 6;
    const TIP: i64 = 10;
    pub(super) const PASSWORD: &str = "test-password";

    pub(super) fn key(byte: u8) -> SecretKey {
        SecretKey::from_slice(&[byte; 32]).unwrap()
    }

    pub(super) fn pubkey(byte: u8) -> PublicKey {
        PublicKey::new(bitcoin::secp256k1::PublicKey::from_secret_key(
            crate::utill::global_secp(),
            &key(byte),
        ))
    }

    pub(super) fn tx(
        previous_output: OutPoint,
        value: u64,
        script_pubkey: ScriptBuf,
    ) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey,
            }],
        }
    }

    /// A Legacy outgoing swapcoin with a confirmed contract, and our own signed
    /// timelock recovery of it.
    fn legacy_coin_and_recovery() -> (OutgoingSwapCoin, Transaction) {
        let (coin, recovery, _) = legacy_coin_and_recoveries();
        (coin, recovery)
    }

    /// Also returns a second, differently priced recovery: one it replaced.
    fn legacy_coin_and_recoveries() -> (OutgoingSwapCoin, Transaction, Transaction) {
        let redeemscript =
            create_contract_redeemscript(&pubkey(2), &pubkey(3), &Hash160::all_zeros(), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut coin = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(3),
            Amount::from_sat(50_000),
            1,
        );
        coin.committed = true;
        let recovery_spk = ScriptBuf::new_p2wpkh(&pubkey(5).wpubkey_hash().unwrap());
        let recovery_at = |value| {
            let unsigned = tx(
                OutPoint::new(coin.contract_tx.compute_txid(), 0),
                value,
                recovery_spk.clone(),
            );
            coin.sign_timelock_recovery(unsigned).unwrap()
        };
        let (recovery, replaced) = (recovery_at(49_000), recovery_at(49_500));
        (coin, recovery, replaced)
    }

    pub(super) fn scripthash(script: &Script) -> String {
        use bitcoin::hex::DisplayHex;
        use electrum_client::ToElectrumScriptHash;
        script.to_electrum_scripthash().to_lower_hex_string()
    }

    /// Electrum server knowing the contract (mined at `CONTRACT_HEIGHT`) and
    /// our recovery spending it (mined at `RECOVERY_HEIGHT`). Every other
    /// script is empty and every other txid unknown.
    fn start_electrum_stub(contract: Transaction, recovery: Transaction) -> String {
        start_electrum_stub_with(contract, recovery, None)
    }

    /// As [`start_electrum_stub`], with `stale` (never mined, also spending the
    /// contract) listed in the contract's history ahead of `recovery`.
    fn start_electrum_stub_with(
        contract: Transaction,
        recovery: Transaction,
        stale: Option<Transaction>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);
        let entry = |tx: &Transaction, height: i64| json!({"tx_hash": tx.compute_txid().to_string(), "height": height});
        let mut contract_history = vec![entry(&contract, CONTRACT_HEIGHT)];
        let mut recovery_history = Vec::new();
        let mut txs = HashMap::from([
            (
                contract.compute_txid().to_string(),
                serialize_hex(&contract),
            ),
            (
                recovery.compute_txid().to_string(),
                serialize_hex(&recovery),
            ),
        ]);
        if let Some(stale) = &stale {
            contract_history.push(entry(stale, 0));
            recovery_history.push(entry(stale, 0));
            txs.insert(stale.compute_txid().to_string(), serialize_hex(stale));
        }
        contract_history.push(entry(&recovery, RECOVERY_HEIGHT));
        recovery_history.push(entry(&recovery, RECOVERY_HEIGHT));
        let history = HashMap::from([
            (
                scripthash(&contract.output[0].script_pubkey),
                Value::Array(contract_history),
            ),
            (
                scripthash(&recovery.output[0].script_pubkey),
                Value::Array(recovery_history),
            ),
        ]);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let (genesis_hash, header_hex) = (genesis_hash.clone(), header_hex.clone());
                let (history, txs) = (history.clone(), txs.clone());
                thread::spawn(move || {
                    let answer = |req: &Value| -> Value {
                        let param = req["params"][0].as_str().unwrap_or_default();
                        let result = match req["method"].as_str().unwrap_or_default() {
                            "server.features" => json!({
                                "server_version": "stub",
                                "genesis_hash": genesis_hash,
                                "protocol_min": "1.4",
                                "protocol_max": "1.4",
                                "hash_function": "sha256",
                                "pruning": Value::Null,
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"height": TIP, "hex": header_hex})
                            }
                            "blockchain.block.header" => json!(header_hex),
                            "blockchain.scripthash.get_history" => {
                                history.get(param).cloned().unwrap_or(json!([]))
                            }
                            "blockchain.scripthash.listunspent" => json!([]),
                            "blockchain.transaction.get" => match txs.get(param) {
                                Some(hex) => json!(hex),
                                None => {
                                    return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                        "code": 2,
                                        "message": "No such mempool or blockchain transaction",
                                    }})
                                }
                            },
                            _ => Value::Null,
                        };
                        json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
                    };
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let Ok(req) = serde_json::from_str::<Value>(&line) else {
                            return;
                        };
                        let resp = match req.as_array() {
                            Some(batch) => Value::Array(batch.iter().map(answer).collect()),
                            None => answer(&req),
                        };
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    pub(super) fn electrum(url: &str) -> AnyBlockchain {
        AnyBlockchain::Electrum(
            Electrum::new(&crate::wallet::ElectrumConfig {
                url: url.to_string(),
                ..Default::default()
            })
            .expect("connect to stub"),
        )
    }

    pub(super) fn stub_wallet(path: &Path, blockchain: AnyBlockchain) -> Wallet {
        let master_key = Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap();
        let enc_material = KeyMaterial::new_from_password(Some(PASSWORD.to_string())).unwrap();
        let store = WalletStore::init(
            "timelock-reconcile-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
            None,
            None,
            &enc_material,
        )
        .unwrap();
        Wallet {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            locked_utxos: HashSet::new(),
            _in_use: None,
        }
    }

    /// Fails the pass instead of hanging if the stub cannot satisfy a sync:
    /// `sync_no_fail` retries forever until shutdown.
    pub(super) fn shutdown_after(secs: u64) -> Arc<AtomicBool> {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = shutdown.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(secs));
            flag.store(true, std::sync::atomic::Ordering::Relaxed);
        });
        shutdown
    }

    /// Runs two recovery passes over a wallet holding `coin` and checks the
    /// first records `recovery` as resolved, persists the removal, and the
    /// second finds nothing.
    fn assert_reconciles(
        wallet: Wallet,
        chain: &AnyBlockchain,
        coin: &OutgoingSwapCoin,
        recovery: &Transaction,
    ) {
        let wallet_path = wallet.wallet_file_path.clone();
        let wallet = RwLock::new(wallet);
        let shutdown = shutdown_after(60);
        let contract_txid = coin.contract_tx.compute_txid();

        let first =
            Wallet::recover_timelocked_swapcoins(&wallet, chain, &shutdown, None, &|_| true)
                .unwrap();
        assert_eq!(
            first.resolved,
            vec![(contract_txid, recovery.compute_txid())]
        );
        assert!(first.discarded.is_empty());
        assert!(wallet.read().unwrap().store.outgoing_swapcoins.is_empty());

        let (reloaded, _) =
            WalletStore::read_from_disk(&wallet_path, Some(PASSWORD.to_string())).unwrap();
        assert!(reloaded.outgoing_swapcoins.is_empty());

        let second =
            Wallet::recover_timelocked_swapcoins(&wallet, chain, &shutdown, None, &|_| true)
                .unwrap();
        assert!(second.is_empty());
    }

    #[test]
    fn compat_coin_flags_default_to_safe_values_and_preserve_fresh_values() {
        let (reference, _) = legacy_coin_and_recovery();
        let legacy = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            reference.contract_tx.clone(),
            reference.contract_redeemscript.clone().unwrap(),
            key(3),
            Amount::from_sat(50_000),
            1,
        );
        let taproot = OutgoingSwapCoin::new_taproot(
            key(3),
            ScriptBuf::new(),
            ScriptBuf::new(),
            reference.contract_tx,
            Amount::from_sat(50_000),
            1,
        );
        for coin in [legacy, taproot] {
            assert!(!coin.committed && !coin.incoming_claimed);
            let current: OutgoingSwapCoin =
                serde_cbor::from_slice(&serde_cbor::to_vec(&coin).unwrap()).unwrap();
            assert_eq!(current, coin);
            for omitted in [
                vec!["committed"],
                vec!["incoming_claimed"],
                vec!["committed", "incoming_claimed"],
            ] {
                let mut old = to_cbor_value(&coin).unwrap();
                let CborValue::Map(fields) = &mut old else {
                    panic!("coin must serialize as a map")
                };
                for field in &omitted {
                    fields.remove(&CborValue::Text((*field).into()));
                }
                let decoded: OutgoingSwapCoin =
                    serde_cbor::from_slice(&serde_cbor::to_vec(&old).unwrap()).unwrap();
                assert_eq!(decoded.committed, omitted.contains(&"committed"));
                assert_eq!(
                    decoded.incoming_claimed,
                    omitted.contains(&"incoming_claimed")
                );
                assert_eq!(decoded.contract_tx, coin.contract_tx);
            }
        }
    }

    #[test]
    fn compat_coin_flags_stay_monotonic_after_stale_reinsert_and_reload() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.cbor");
        let mut wallet = test_wallet(&path);
        let (mut original, _) = legacy_coin_and_recovery();
        original.swap_id = Some("swap".into());
        original.committed = false;
        original.incoming_claimed = false;
        wallet.add_outgoing_swapcoin(&original);
        for ((committed, incoming_claimed), expected) in [
            ((true, false), (true, false)),
            ((false, true), (true, true)),
            ((false, false), (true, true)),
        ] {
            let mut update = original.clone();
            update.committed = committed;
            update.incoming_claimed = incoming_claimed;
            wallet.add_outgoing_swapcoin(&update);
            wallet.save_to_disk().unwrap();
            let (store, material) =
                WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            let coin = &store.outgoing_swapcoins[&original.contract_tx.compute_txid().to_string()];
            assert_eq!((coin.committed, coin.incoming_claimed), expected);
            wallet.store = store;
            wallet.store_enc_material = material;
        }
        let saved =
            &wallet.store.outgoing_swapcoins[&original.contract_tx.compute_txid().to_string()];
        assert!(saved.committed && saved.incoming_claimed);
    }

    #[test]
    fn cleanup_save_failure_preserves_coins_and_monotonic_flags() {
        let (mut coin, recovery) = legacy_coin_and_recovery();
        coin.swap_id = Some("swap".into());
        let mut stale = coin.clone();
        stale.committed = false;
        coin.incoming_claimed = true;
        coin.hash_preimage = Some([7; 32]);
        let url = start_electrum_stub(coin.contract_tx.clone(), recovery);
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.cbor");
        let mut wallet = stub_wallet(&path, electrum(&url));
        wallet.add_outgoing_swapcoin(&coin);
        wallet.add_outgoing_swapcoin(&stale);
        let (_, outgoing) = wallet.find_unfinished_swapcoins();
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing[0].committed && outgoing[0].incoming_claimed);
        wallet.save_to_disk().unwrap();

        // A directory at the destination forces the atomic replacement to fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(wallet
            .remove_swap_coins_and_save("swap", true, true)
            .is_err());
        let (_, outgoing) = wallet.find_unfinished_swapcoins();
        assert_eq!(outgoing.len(), 1);
        assert!(outgoing[0].committed && outgoing[0].incoming_claimed);
    }

    #[test]
    fn electrum_records_our_confirmed_recovery_as_resolved() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_electrum_stub(coin.contract_tx.clone(), recovery.clone());
        let temp_dir = tempdir().unwrap();
        let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), electrum(&url));
        wallet.add_outgoing_swapcoin(&coin);
        wallet.save_to_disk().unwrap();

        assert_reconciles(wallet, &electrum(&url), &coin, &recovery);
    }

    /// Electrum can list a replaced, never-mined recovery ahead of the one that
    /// confirmed. Classification must skip it and record the mined recovery.
    #[test]
    fn electrum_skips_an_unconfirmed_spend_listed_first() {
        let (coin, recovery, replaced) = legacy_coin_and_recoveries();
        let url =
            start_electrum_stub_with(coin.contract_tx.clone(), recovery.clone(), Some(replaced));
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// The next hop's claim of our contract can carry the preimage the maker
    /// still needs for its incoming, so the coin stays until the swap settles.
    #[test]
    fn electrum_keeps_a_contract_the_other_side_claimed() {
        let (coin, _) = legacy_coin_and_recovery();
        let claim = tx(
            OutPoint::new(coin.contract_tx.compute_txid(), 0),
            49_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let url = start_electrum_stub(coin.contract_tx.clone(), claim);
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// A Taproot outgoing swapcoin whose contract output commits to both
    /// leaves, and our own signed timelock recovery of it.
    pub(super) fn taproot_coin_and_recovery() -> (OutgoingSwapCoin, Transaction) {
        use crate::protocol::contract2::{create_hashlock_script, create_timelock_script};
        use bitcoin::{key::Keypair, secp256k1::Scalar, taproot::TaprootBuilder, XOnlyPublicKey};

        let secp = crate::utill::global_secp();
        let xonly = |byte| -> XOnlyPublicKey {
            Keypair::from_secret_key(secp, &key(byte))
                .x_only_public_key()
                .0
        };
        let hashlock_script = create_hashlock_script(&[7; 32], &xonly(2));
        let timelock_script =
            create_timelock_script(LockTime::from_height(500).unwrap(), &xonly(3));
        let merkle_root = TaprootBuilder::new()
            .add_leaf(1, hashlock_script.clone())
            .unwrap()
            .add_leaf(1, timelock_script.clone())
            .unwrap()
            .finalize(secp, xonly(5))
            .unwrap()
            .merkle_root();
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            50_000,
            ScriptBuf::new_p2tr(secp, xonly(5), merkle_root),
        );
        let mut coin = OutgoingSwapCoin::new_taproot(
            key(3),
            hashlock_script,
            timelock_script,
            contract_tx,
            Amount::from_sat(50_000),
            1,
        );
        coin.committed = true;
        coin.internal_key = Some(xonly(5));
        coin.tap_tweak = Some(Scalar::ZERO);
        let unsigned = tx(
            OutPoint::new(coin.contract_tx.compute_txid(), 0),
            49_000,
            ScriptBuf::new_p2wpkh(&pubkey(5).wpubkey_hash().unwrap()),
        );
        let recovery = coin.sign_timelock_recovery(unsigned).unwrap();
        (coin, recovery)
    }

    #[test]
    fn electrum_classifies_our_confirmed_taproot_recovery_as_recovered() {
        let (coin, recovery) = taproot_coin_and_recovery();
        let url = start_electrum_stub(coin.contract_tx.clone(), recovery.clone());
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// Hand-rolled Bitcoin Core JSON-RPC over HTTP: the contract is mined at
    /// `CONTRACT_HEIGHT`, our recovery at `RECOVERY_HEIGHT`, and the contract
    /// output is spent. Only the calls classification makes are answered.
    fn start_core_stub(contract: Transaction, recovery: Transaction) -> String {
        start_core_stub_with(contract, recovery, true)
    }

    /// As [`start_core_stub`]. With `recovery_mined` unset the recovery sits in
    /// the mempool: the confirmed view still holds the contract output.
    fn start_core_stub_with(
        contract: Transaction,
        recovery: Transaction,
        recovery_mined: bool,
    ) -> String {
        start_core_stub_full(contract, recovery, recovery_mined, RECOVERY_HEIGHT)
    }

    /// As [`start_core_stub`], with the recovery mined at `recovery_height`.
    fn start_core_stub_at(
        contract: Transaction,
        recovery: Transaction,
        recovery_height: i64,
    ) -> String {
        start_core_stub_full(contract, recovery, true, recovery_height)
    }

    fn start_core_stub_full(
        contract: Transaction,
        recovery: Transaction,
        recovery_mined: bool,
        recovery_height: i64,
    ) -> String {
        use std::io::Read;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().unwrap().to_string();
        let header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        let block_hash = |height: i64| BlockHash::from_byte_array([height as u8; 32]);
        let mut mined =
            HashMap::from([(contract.compute_txid(), (contract.clone(), CONTRACT_HEIGHT))]);
        if recovery_mined {
            mined.insert(recovery.compute_txid(), (recovery.clone(), recovery_height));
        }
        let mined = Arc::new(mined);

        let answer = move |method: &str, params: &Value| -> Result<Value, Value> {
            let unknown =
                || json!({"code": -5, "message": "No such mempool or blockchain transaction"});
            Ok(match method {
                "getblockcount" => json!(TIP),
                "getblockhash" => json!(block_hash(params[0].as_i64().unwrap())),
                "getblockheader" => {
                    let hash = params[0].as_str().unwrap();
                    let height = (0..=TIP)
                        .find(|h| block_hash(*h).to_string() == hash)
                        .ok_or_else(unknown)?;
                    json!({
                        "hash": hash, "confirmations": TIP - height + 1, "height": height,
                        "version": 1, "merkleroot": header.merkle_root, "time": 0,
                        "mediantime": 0, "nonce": 0, "bits": "207fffff", "difficulty": 1.0,
                        "chainwork": "00", "nTx": 1,
                    })
                }
                "getblock" => {
                    let hash = params[0].as_str().unwrap();
                    let txdata = mined
                        .values()
                        .filter(|(_, h)| block_hash(*h).to_string() == hash)
                        .map(|(tx, _)| tx.clone())
                        .collect();
                    json!(serialize_hex(&bitcoin::Block { header, txdata }))
                }
                "getrawtransaction" => {
                    let txid: Txid = params[0].as_str().unwrap().parse().unwrap();
                    if !recovery_mined && txid == recovery.compute_txid() {
                        return Ok(json!(serialize_hex(&recovery)));
                    }
                    let (tx, height) = mined.get(&txid).ok_or_else(unknown)?;
                    if !params[1].as_bool().unwrap_or(false) {
                        json!(serialize_hex(tx))
                    } else {
                        let vin: Vec<Value> = tx
                            .input
                            .iter()
                            .map(|i| {
                                json!({
                                    "txid": i.previous_output.txid,
                                    "vout": i.previous_output.vout,
                                    "scriptSig": {"asm": "", "hex": ""},
                                    "sequence": i.sequence.0,
                                })
                            })
                            .collect();
                        let vout: Vec<Value> = tx
                            .output
                            .iter()
                            .enumerate()
                            .map(|(n, o)| {
                                json!({
                                    "value": o.value.to_btc(),
                                    "n": n,
                                    "scriptPubKey": {
                                        "asm": "",
                                        "hex": o.script_pubkey.to_hex_string(),
                                        "type": null,
                                    },
                                })
                            })
                            .collect();
                        json!({
                            "hex": serialize_hex(tx), "txid": txid, "hash": tx.compute_wtxid(),
                            "size": tx.total_size(), "vsize": tx.vsize(), "version": 2,
                            "locktime": 0, "blockhash": block_hash(*height),
                            "confirmations": TIP - height + 1, "vin": vin, "vout": vout,
                        })
                    }
                }
                // A mempool spend leaves the output in the confirmed view only.
                "gettxout" if !recovery_mined && params[2] == json!(false) => json!({
                    "bestblock": block_hash(TIP),
                    "confirmations": TIP - CONTRACT_HEIGHT + 1,
                    "value": contract.output[0].value.to_btc(),
                    "scriptPubKey": {
                        "asm": "",
                        "hex": contract.output[0].script_pubkey.to_hex_string(),
                        "type": null,
                    },
                    "coinbase": false,
                }),
                "gettxout" => Value::Null,
                "getmempoolinfo" => json!({
                    "loaded": true, "size": 1, "bytes": 1, "usage": 1, "maxmempool": 1,
                    "mempoolminfee": 0.00001, "minrelaytxfee": 0.00001,
                    "incrementalrelayfee": 0.00005,
                }),
                "gettxspendingprevout" => {
                    let spender = (!recovery_mined).then(|| recovery.compute_txid());
                    json!([{
                        "txid": params[0][0]["txid"], "vout": params[0][0]["vout"],
                        "spendingtxid": spender,
                    }])
                }
                other => panic!("core stub: unexpected call {}", other),
            })
        };
        let answer = Arc::new(answer);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let answer = answer.clone();
                thread::spawn(move || {
                    let mut out = stream.try_clone().expect("clone stub stream");
                    let mut reader = BufReader::new(stream);
                    loop {
                        let mut body_len = 0;
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            if line.trim().is_empty() {
                                break;
                            }
                            if let Some(n) = line.to_lowercase().strip_prefix("content-length:") {
                                body_len = n.trim().parse().unwrap();
                            }
                        }
                        let mut body = vec![0; body_len];
                        if reader.read_exact(&mut body).is_err() {
                            return;
                        }
                        let req: Value = serde_json::from_slice(&body).unwrap();
                        let (result, error) =
                            match answer(req["method"].as_str().unwrap(), &req["params"]) {
                                Ok(result) => (result, Value::Null),
                                Err(error) => (Value::Null, error),
                            };
                        let reply = json!({
                            "jsonrpc": "2.0", "id": req["id"], "result": result, "error": error,
                        })
                        .to_string();
                        let written = write!(
                            out,
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                            reply.len()
                        );
                        if written.and_then(|_| out.flush()).is_err() {
                            return;
                        }
                    }
                });
            }
        });
        addr
    }

    fn core(url: String) -> AnyBlockchain {
        AnyBlockchain::CoreRPC(
            crate::wallet::CoreRPC::new(&crate::wallet::CoreRpcConfig {
                url,
                ..Default::default()
            })
            .unwrap(),
        )
    }

    /// A Taproot contract tx whose fee-bump replacement confirmed is kept
    /// while that replacement is shallow: a reorg can still confirm it.
    #[test]
    fn core_keeps_a_replaced_taproot_contract_until_its_replacement_is_deep() {
        let (mut coin, _) = taproot_coin_and_recovery();
        let parent = tx(
            OutPoint::new(Txid::from_byte_array([8; 32]), 0),
            60_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let contract_spk = coin.contract_tx.output[0].script_pubkey.clone();
        let version = |value| {
            tx(
                OutPoint::new(parent.compute_txid(), 0),
                value,
                contract_spk.clone(),
            )
        };
        coin.contract_tx = version(50_000);
        let replacement = version(49_000);
        let url = start_core_stub(parent, replacement);
        let chain = core(url);
        // The stub mines the replacement 5 blocks deep.
        let depth = (TIP - RECOVERY_HEIGHT + 1) as u64;
        assert!(depth < REPLACED_VERSION_DISCARD_DEPTH);
        let state = Wallet::ensure_contract_on_chain(&chain, "swap", &coin).unwrap();
        assert_ne!(state, ContractChainState::Discarded);
        // At the depth the discard waits for, the same spend replaces it.
        assert!(Wallet::replaced_by_confirmed_spend(&chain, &coin.contract_tx, depth).unwrap());
        assert!(
            !Wallet::replaced_by_confirmed_spend(&chain, &coin.contract_tx, depth + 1).unwrap()
        );
    }

    /// A contract mined after the caller saw it unconfirmed spends its own
    /// inputs: that confirmed spend is the contract landing, not a
    /// replacement, so it must never read as one.
    #[test]
    fn a_contract_spending_its_own_inputs_is_not_replaced() {
        let (mut coin, _) = taproot_coin_and_recovery();
        let parent = tx(
            OutPoint::new(Txid::from_byte_array([8; 32]), 0),
            60_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        coin.contract_tx = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            coin.contract_tx.output[0].script_pubkey.clone(),
        );
        let url = start_core_stub(parent, coin.contract_tx.clone());
        assert!(!Wallet::replaced_by_confirmed_spend(&core(url), &coin.contract_tx, 1).unwrap());
    }

    /// A completed swap's leftover funding version, and a fresh wallet that
    /// holds it, as a bump leaves behind once the swap settles on another.
    fn leftover_version(dir: &Path) -> (RwLock<Wallet>, OutgoingSwapCoin, Transaction) {
        let (mut coin, _) = taproot_coin_and_recovery();
        let parent = tx(
            OutPoint::new(Txid::from_byte_array([8; 32]), 0),
            60_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let contract_spk = coin.contract_tx.output[0].script_pubkey.clone();
        coin.contract_tx = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            contract_spk,
        );
        coin.swap_id = Some("swap".to_string());
        coin.replaced = true;
        let mut wallet = super::test_support::test_wallet(&dir.join("wallet"));
        wallet.add_outgoing_swapcoin(&coin);
        (RwLock::new(wallet), coin, parent)
    }

    /// The version that beat a leftover one is mined, but shallow: a reorg
    /// can still confirm the leftover, so it is kept.
    #[test]
    fn a_leftover_version_is_kept_while_its_winner_is_shallow() {
        let dir = tempdir().unwrap();
        let (wallet, coin, parent) = leftover_version(dir.path());
        let winner = tx(
            OutPoint::new(parent.compute_txid(), 0),
            49_000,
            coin.contract_tx.output[0].script_pubkey.clone(),
        );
        let chain = core(start_core_stub(parent, winner));
        let retirement = Wallet::retire_replaced_versions(&wallet, &chain, "swap").unwrap();
        assert!(retirement.removed.is_empty());
        assert_eq!(retirement.remaining, 1);
        assert!(!retirement.revived);
        assert_eq!(
            wallet.read().unwrap().outgoing_keys_for_swap("swap").len(),
            1
        );
    }

    /// Once the version that beat a leftover one is buried deep enough, no
    /// reorg can bring the leftover back: it is dropped, for good, and its
    /// contract output handed back to unwatch.
    #[test]
    fn a_leftover_version_is_retired_once_its_winner_is_deep() {
        let dir = tempdir().unwrap();
        let (wallet, coin, parent) = leftover_version(dir.path());
        let winner = tx(
            OutPoint::new(parent.compute_txid(), 0),
            49_000,
            coin.contract_tx.output[0].script_pubkey.clone(),
        );
        let depth = REPLACED_VERSION_DISCARD_DEPTH as i64;
        let chain = core(start_core_stub_at(parent, winner, TIP - depth + 1));
        let retirement = Wallet::retire_replaced_versions(&wallet, &chain, "swap").unwrap();
        assert_eq!(retirement.remaining, 0);
        assert!(!retirement.revived);
        assert_eq!(
            retirement.removed,
            vec![(
                OutPoint::new(coin.contract_tx.compute_txid(), 0),
                coin.contract_tx.output[0].script_pubkey.clone(),
            )]
        );
        assert!(wallet
            .read()
            .unwrap()
            .outgoing_keys_for_swap("swap")
            .is_empty());
        // The removal is on disk, not only in memory.
        let wallet_path = wallet.read().unwrap().wallet_file_path.clone();
        let (reloaded, _) =
            WalletStore::read_from_disk(&wallet_path, Some(PASSWORD.to_string())).unwrap();
        assert!(reloaded.outgoing_swapcoins.is_empty());
    }

    /// An incoming Taproot coin whose contract output recovery cannot find.
    /// A mined replacement paying the same contract is followed, never
    /// dropped: the coins are still ours to claim there. A flagged copy
    /// stands for its own version only, so it is dropped once beaten deep;
    /// so is any coin whose coins went elsewhere. A shallow spend waits.
    #[test]
    fn recovery_follows_a_replacement_paying_the_same_contract() {
        let (outgoing, _) = taproot_coin_and_recovery();
        let parent = tx(
            OutPoint::new(Txid::from_byte_array([8; 32]), 0),
            60_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let contract_spk = outgoing.contract_tx.output[0].script_pubkey.clone();
        let spending = |value, script: &ScriptBuf| {
            tx(
                OutPoint::new(parent.compute_txid(), 0),
                value,
                script.clone(),
            )
        };
        let coin = |replaced| {
            let mut coin = crate::wallet::swapcoin::IncomingSwapCoin::new_taproot(
                key(3),
                outgoing.hashlock_script.clone().unwrap(),
                outgoing.timelock_script.clone().unwrap(),
                spending(50_000, &contract_spk),
                Amount::from_sat(50_000),
                1,
            );
            coin.replaced = replaced;
            coin
        };
        let elsewhere = ScriptBuf::new_p2wpkh(&pubkey(7).wpubkey_hash().unwrap());
        let deep = TIP - REPLACED_VERSION_DISCARD_DEPTH as i64 + 1;
        for (replaced, winner_script, height, expected) in [
            (false, &contract_spk, deep, UnseenIncoming::Follow),
            (true, &contract_spk, deep, UnseenIncoming::Drop),
            (false, &elsewhere, deep, UnseenIncoming::Drop),
            (false, &elsewhere, deep + 1, UnseenIncoming::Wait),
        ] {
            let chain = core(start_core_stub_at(
                parent.clone(),
                spending(49_000, winner_script),
                height,
            ));
            assert_eq!(
                Wallet::judge_unseen_incoming(&chain, &coin(replaced)).unwrap(),
                expected,
                "replaced={} height={}",
                replaced,
                height
            );
        }
    }

    /// Only a flagged version comes back revived: an ordinary swap's coin
    /// whose funding is mined is no leftover, and retirement leaves it alone.
    #[test]
    fn an_unflagged_coin_is_never_retired_or_revived() {
        let dir = tempdir().unwrap();
        let (wallet, coin, _) = leftover_version(dir.path());
        wallet
            .write()
            .unwrap()
            .store
            .outgoing_swapcoins
            .values_mut()
            .for_each(|coin| coin.replaced = false);
        let unrelated = tx(
            OutPoint::new(Txid::from_byte_array([4; 32]), 0),
            1_000,
            ScriptBuf::new(),
        );
        let chain = core(start_core_stub(coin.contract_tx.clone(), unrelated));
        let retirement = Wallet::retire_replaced_versions(&wallet, &chain, "swap").unwrap();
        assert!(!retirement.revived);
        assert_eq!(retirement.remaining, 0);
        assert!(retirement.removed.is_empty());
        assert_eq!(
            wallet.read().unwrap().outgoing_keys_for_swap("swap").len(),
            1
        );
    }

    /// A reorg mined the leftover version itself: the swap needs recovering
    /// from it, and the coin stays for that.
    #[test]
    fn a_mined_leftover_version_is_reported_revived() {
        let dir = tempdir().unwrap();
        let (wallet, coin, _) = leftover_version(dir.path());
        let unrelated = tx(
            OutPoint::new(Txid::from_byte_array([4; 32]), 0),
            1_000,
            ScriptBuf::new(),
        );
        let chain = core(start_core_stub(coin.contract_tx.clone(), unrelated));
        let retirement = Wallet::retire_replaced_versions(&wallet, &chain, "swap").unwrap();
        assert!(retirement.revived);
        assert_eq!(retirement.remaining, 1);
        assert_eq!(
            wallet.read().unwrap().outgoing_keys_for_swap("swap").len(),
            1
        );
    }

    /// A slot settles on whichever of its versions is mined, and the wait
    /// reports each slot's winner.
    #[test]
    fn a_slot_confirms_on_whichever_version_is_mined() {
        let (coin, recovery) = taproot_coin_and_recovery();
        let url = start_core_stub(coin.contract_tx.clone(), recovery.clone());
        let replaced = tx(
            OutPoint::new(Txid::from_byte_array([3; 32]), 0),
            1_000,
            ScriptBuf::new(),
        );
        let outcome = wait_for_slots_confirmation(
            &core(url),
            &[
                vec![replaced.compute_txid(), recovery.compute_txid()],
                vec![coin.contract_tx.compute_txid()],
            ],
            &SlotWait {
                required_confirms: 1,
                arrival_timeout: Duration::from_secs(30),
                started: Instant::now(),
                interrupt_at_height: None,
            },
            &mut SlotTrack::new(2),
            None,
            None,
        )
        .unwrap();
        assert_eq!(
            outcome,
            SlotWaitOutcome::Confirmed {
                height: RECOVERY_HEIGHT as u32,
                winners: vec![recovery.compute_txid(), coin.contract_tx.compute_txid()],
            }
        );
    }

    /// While a slot is unconfirmed, the wait hands control back at the
    /// height the caller set, so a bump can be decided there.
    #[test]
    fn an_unconfirmed_wait_returns_at_its_interrupt_height() {
        let (coin, recovery) = taproot_coin_and_recovery();
        let url = start_core_stub(coin.contract_tx.clone(), recovery);
        let stuck = tx(
            OutPoint::new(Txid::from_byte_array([3; 32]), 0),
            1_000,
            ScriptBuf::new(),
        );
        let outcome = wait_for_slots_confirmation(
            &core(url),
            &[vec![stuck.compute_txid()]],
            &SlotWait {
                required_confirms: 1,
                arrival_timeout: Duration::from_secs(30),
                started: Instant::now(),
                interrupt_at_height: Some(TIP as u64),
            },
            &mut SlotTrack::new(1),
            None,
            None,
        )
        .unwrap();
        assert_eq!(outcome, SlotWaitOutcome::HeightReached(TIP as u64));
    }

    /// A wait split by height interrupts is one wait: a tx never seen across
    /// all of them still runs out the arrival deadline set when it began.
    #[test]
    fn interrupted_waits_keep_the_first_arrival_deadline() {
        let (coin, recovery) = taproot_coin_and_recovery();
        let url = start_core_stub(coin.contract_tx.clone(), recovery);
        let chain = core(url);
        let never_sent = tx(
            OutPoint::new(Txid::from_byte_array([3; 32]), 0),
            1_000,
            ScriptBuf::new(),
        );
        let slots = [vec![never_sent.compute_txid()]];
        let wait = SlotWait {
            required_confirms: 1,
            arrival_timeout: Duration::from_millis(500),
            started: Instant::now(),
            interrupt_at_height: Some(TIP as u64),
        };
        let mut track = SlotTrack::new(slots.len());
        assert_eq!(
            wait_for_slots_confirmation(&chain, &slots, &wait, &mut track, None, None).unwrap(),
            SlotWaitOutcome::HeightReached(TIP as u64)
        );
        thread::sleep(Duration::from_millis(600));
        // Each resumed wait alone is younger than the deadline; together
        // they are not.
        let resumed = wait_for_slots_confirmation(&chain, &slots, &wait, &mut track, None, None);
        assert!(
            matches!(
                resumed,
                Err(WalletError::TxNeverBroadcast(_) | WalletError::TxConfirmationTimeout(_))
            ),
            "a resumed wait must keep the first arrival deadline, got {:?}",
            resumed
        );
    }

    #[test]
    fn core_classifies_our_confirmed_recovery_as_recovered() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_core_stub(coin.contract_tx.clone(), recovery.clone());
        let state = Wallet::ensure_contract_on_chain(&core(url), "swap", &coin).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// Core still lists a contract output that our unconfirmed recovery spends,
    /// so the mempool has to be asked before the coin reads as untouched.
    #[test]
    fn core_classifies_our_unconfirmed_recovery_as_pending() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_core_stub_with(coin.contract_tx.clone(), recovery.clone(), false);
        let state = Wallet::ensure_contract_on_chain(&core(url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::RecoveryPending(recovery));
    }

    /// The next hop's unconfirmed claim leaves the output in Core's confirmed
    /// view too. Reading that as untouched would send a conflicting refund.
    #[test]
    fn core_waits_on_an_unconfirmed_claim_by_the_other_side() {
        let (coin, _) = legacy_coin_and_recovery();
        let claim = tx(
            OutPoint::new(coin.contract_tx.compute_txid(), 0),
            49_000,
            ScriptBuf::new_p2wpkh(&pubkey(6).wpubkey_hash().unwrap()),
        );
        let url = start_core_stub_with(coin.contract_tx.clone(), claim, false);
        let state = Wallet::ensure_contract_on_chain(&core(url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// A replacement must add the node's own increment, which an operator can
    /// set above the relay floor. Electrum cannot report one.
    #[test]
    fn replacement_increment_comes_from_the_backend() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let core_url = start_core_stub(coin.contract_tx.clone(), recovery.clone());
        assert_eq!(core(core_url).replacement_increment_rate(), 5.0);
        let electrum_url = start_electrum_stub(coin.contract_tx, recovery);
        assert_eq!(
            electrum(&electrum_url).replacement_increment_rate(),
            MIN_RELAY_FEE_RATE
        );
    }
}

/// Recovery against the mempool: an incoming contract still there is swept on
/// a later pass, and our own stuck refund is replaced once fees outbid it.
#[cfg(test)]
mod mempool_deferral_tests {
    use super::{
        timelock_reconcile_tests::{
            electrum, key, pubkey, scripthash, shutdown_after, stub_wallet,
            taproot_coin_and_recovery, tx, PASSWORD,
        },
        *,
    };
    use crate::{
        protocol::contract::{create_contract_redeemscript, Hash160},
        wallet::{
            blockchain::SCRIPT_CACHE_TTL,
            swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
        },
    };
    use bitcoin::{
        consensus::encode::{deserialize_hex, serialize_hex},
        hashes::Hash,
        Witness,
    };
    use bitcoind::tempfile::tempdir;
    use std::{
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
        sync::{Arc, Mutex, RwLock},
    };

    /// Past the 500-block CLTV of the Taproot fixture.
    const TIP: i64 = 600;
    /// Leaves the outgoing contract's 20-block CSV matured at `TIP`.
    const OUTGOING_HEIGHT: i64 = 50;
    const SWAP: &str = "swap";

    /// What the stub server knows. A height of `0` is the mempool.
    struct StubChain {
        txs: HashMap<Txid, (Transaction, i64)>,
        broadcast: Vec<Txid>,
        reject_broadcast: bool,
        /// Lookups of these txs fail as a down backend would, never as "unknown".
        fail_lookups: HashSet<Txid>,
        /// Every fee estimate, in sat/vB.
        feerate: f64,
    }

    impl StubChain {
        fn with(txs: &[(&Transaction, i64)]) -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(StubChain {
                txs: txs
                    .iter()
                    .map(|(tx, height)| (tx.compute_txid(), ((*tx).clone(), *height)))
                    .collect(),
                broadcast: Vec::new(),
                reject_broadcast: false,
                fail_lookups: HashSet::new(),
                feerate: 1.0,
            }))
        }

        fn script_of(&self, outpoint: &OutPoint) -> Option<&ScriptBuf> {
            self.txs
                .get(&outpoint.txid)
                .and_then(|(tx, _)| tx.output.get(outpoint.vout as usize))
                .map(|output| &output.script_pubkey)
        }

        fn is_spent(&self, outpoint: &OutPoint) -> bool {
            self.txs
                .values()
                .any(|(tx, _)| tx.input.iter().any(|i| i.previous_output == *outpoint))
        }

        /// Every tx paying to or spending from the script.
        fn history(&self, scripthash_hex: &str) -> Value {
            let matches = |script: &ScriptBuf| scripthash(script) == scripthash_hex;
            self.txs
                .iter()
                .filter(|(_, (tx, _))| {
                    tx.output.iter().any(|o| matches(&o.script_pubkey))
                        || tx
                            .input
                            .iter()
                            .any(|i| self.script_of(&i.previous_output).is_some_and(matches))
                })
                .map(|(txid, (_, height))| json!({"tx_hash": txid.to_string(), "height": height}))
                .collect()
        }

        fn unspent(&self, scripthash_hex: &str) -> Value {
            let mut entries = Vec::new();
            for (txid, (tx, height)) in &self.txs {
                for (vout, output) in tx.output.iter().enumerate() {
                    let outpoint = OutPoint::new(*txid, vout as u32);
                    if scripthash(&output.script_pubkey) == scripthash_hex
                        && !self.is_spent(&outpoint)
                    {
                        entries.push(json!({
                            "tx_hash": txid.to_string(), "tx_pos": vout, "height": height,
                            "value": output.value.to_sat(),
                        }));
                    }
                }
            }
            Value::Array(entries)
        }
    }

    /// Electrum server over `chain`. A broadcast tx is mined at `TIP` at once,
    /// so a pass's confirmation wait returns on its first poll.
    fn start_electrum_stub(chain: Arc<Mutex<StubChain>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let (genesis_hash, header_hex) = (genesis_hash.clone(), header_hex.clone());
                let chain = chain.clone();
                thread::spawn(move || {
                    let answer = |req: &Value| -> Value {
                        let param = req["params"][0].as_str().unwrap_or_default();
                        let mut chain = chain.lock().unwrap();
                        let result = match req["method"].as_str().unwrap_or_default() {
                            "server.features" => json!({
                                "server_version": "stub",
                                "genesis_hash": genesis_hash,
                                "protocol_min": "1.4",
                                "protocol_max": "1.4",
                                "hash_function": "sha256",
                                "pruning": Value::Null,
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"height": TIP, "hex": header_hex})
                            }
                            "blockchain.block.header" => json!(header_hex),
                            "blockchain.estimatefee" => json!(chain.feerate / 100_000.0),
                            "blockchain.scripthash.get_history" => chain.history(param),
                            "blockchain.scripthash.listunspent" => chain.unspent(param),
                            "blockchain.transaction.get"
                                if param
                                    .parse::<Txid>()
                                    .is_ok_and(|txid| chain.fail_lookups.contains(&txid)) =>
                            {
                                return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                    "code": -32603, "message": "backend unavailable",
                                }});
                            }
                            "blockchain.transaction.get" => {
                                match param.parse::<Txid>().ok().and_then(|t| chain.txs.get(&t)) {
                                    Some((tx, _)) => json!(serialize_hex(tx)),
                                    None => {
                                        return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                            "code": 2,
                                            "message": "No such mempool or blockchain transaction",
                                        }})
                                    }
                                }
                            }
                            "blockchain.transaction.broadcast" => {
                                if chain.reject_broadcast {
                                    return json!({"jsonrpc": "2.0", "id": req["id"], "error": {
                                        "code": -26, "message": "transaction temporarily rejected",
                                    }});
                                }
                                let tx: Transaction = deserialize_hex(param).unwrap();
                                let txid = tx.compute_txid();
                                chain.txs.insert(txid, (tx, TIP));
                                chain.broadcast.push(txid);
                                json!(txid.to_string())
                            }
                            _ => Value::Null,
                        };
                        json!({"jsonrpc": "2.0", "id": req["id"], "result": result})
                    };
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let Ok(req) = serde_json::from_str::<Value>(&line) else {
                            return;
                        };
                        let resp = match req.as_array() {
                            Some(batch) => Value::Array(batch.iter().map(answer).collect()),
                            None => answer(&req),
                        };
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });
        url
    }

    /// Our Legacy incoming coin, claimable by hashlock: we hold the preimage.
    fn incoming_coin() -> IncomingSwapCoin {
        let preimage = [7; 32];
        let redeemscript =
            create_contract_redeemscript(&pubkey(2), &pubkey(3), &Hash160::hash(&preimage), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([8; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut coin = IncomingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(2),
            Amount::from_sat(50_000),
            1,
        );
        coin.hash_preimage = Some(preimage);
        coin.swap_id = Some(SWAP.to_string());
        coin
    }

    /// Our Legacy outgoing coin of the same swap.
    fn outgoing_coin() -> OutgoingSwapCoin {
        let redeemscript =
            create_contract_redeemscript(&pubkey(5), &pubkey(6), &Hash160::all_zeros(), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut coin = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(6),
            Amount::from_sat(50_000),
            1,
        );
        coin.swap_id = Some(SWAP.to_string());
        coin.committed = true;
        coin
    }

    fn wallet_with(
        path: &Path,
        url: &str,
        incoming: &IncomingSwapCoin,
        outgoing: Option<&OutgoingSwapCoin>,
    ) -> RwLock<Wallet> {
        let mut wallet = stub_wallet(path, electrum(url));
        wallet.add_incoming_swapcoin(incoming);
        if let Some(outgoing) = outgoing {
            wallet.add_outgoing_swapcoin(outgoing);
        }
        wallet.save_to_disk().unwrap();
        RwLock::new(wallet)
    }

    /// The first pass meets the contract in the mempool: it holds the swap as
    /// claimed and broadcasts nothing. Once the contract is mined, the next
    /// pass sweeps it.
    #[test]
    fn mempool_contract_is_swept_on_a_later_pass() {
        let incoming = incoming_coin();
        let contract_txid = incoming.contract_tx.compute_txid();
        let chain = StubChain::with(&[(&incoming.contract_tx, 0)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = wallet_with(&temp_dir.path().join("wallet.cbor"), &url, &incoming, None);
        let backend = electrum(&url);
        let shutdown = shutdown_after(60);

        let (sweeps, claiming) =
            Wallet::broadcast_incoming_sweeps(&wallet, &backend, &shutdown, None, &mut false)
                .unwrap();
        assert!(sweeps.is_empty());
        assert_eq!(claiming, HashSet::from([SWAP.to_string()]));
        assert!(chain.lock().unwrap().broadcast.is_empty());

        chain.lock().unwrap().txs.get_mut(&contract_txid).unwrap().1 = TIP;
        // Passes run a block apart, long after the backend stops reusing its
        // answers about the contract.
        thread::sleep(SCRIPT_CACHE_TTL);
        let outcome = Wallet::sweep_incoming_swapcoins(&wallet, &backend, &shutdown, None).unwrap();
        let chain = chain.lock().unwrap();
        let [sweep] = chain.broadcast[..] else {
            panic!("expected one sweep, got {:?}", chain.broadcast);
        };
        assert_eq!(
            chain.txs[&sweep].0.input[0].previous_output,
            OutPoint::new(contract_txid, 0)
        );
        assert_eq!(outcome.resolved, vec![(contract_txid, sweep)]);
        assert!(wallet.read().unwrap().store.incoming_swapcoins.is_empty());
    }

    /// Txs one recovery pass broadcasts for a swap whose outgoing timelock has
    /// matured, with the incoming contract at `incoming_height` (`None`: never
    /// broadcast).
    fn broadcast_by_recovery(incoming_height: Option<i64>) -> Vec<Transaction> {
        let (incoming, outgoing) = (incoming_coin(), outgoing_coin());
        let chain = StubChain::with(&[(&outgoing.contract_tx, OUTGOING_HEIGHT)]);
        if let Some(height) = incoming_height {
            let contract = &incoming.contract_tx;
            chain
                .lock()
                .unwrap()
                .txs
                .insert(contract.compute_txid(), (contract.clone(), height));
        }
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = wallet_with(
            &temp_dir.path().join("wallet.cbor"),
            &url,
            &incoming,
            Some(&outgoing),
        );

        Wallet::recover_swapcoins(
            &wallet,
            &electrum(&url),
            &shutdown_after(60),
            &HashSet::from([incoming.contract_tx.compute_txid()]),
            &HashSet::from([SWAP.to_string()]),
            &|_| true,
            &|_| false,
        )
        .unwrap();
        let chain = chain.lock().unwrap();
        chain
            .broadcast
            .iter()
            .map(|txid| chain.txs[txid].0.clone())
            .collect()
    }

    #[test]
    fn compat_committed_taproot_survives_absence_until_confirmation() {
        let parent = tx(
            OutPoint::null(),
            100_000,
            ScriptBuf::new_p2wpkh(&pubkey(9).wpubkey_hash().unwrap()),
        );
        let contract = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new_p2tr(
                crate::utill::global_secp(),
                pubkey(7).inner.x_only_public_key().0,
                None,
            ),
        );
        let mut coin = OutgoingSwapCoin::new_taproot(
            key(6),
            ScriptBuf::new(),
            ScriptBuf::new(),
            contract.clone(),
            Amount::from_sat(50_000),
            1,
        );
        coin.committed = false;
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        // A split whose send failed is dropped, never sent by recovery.
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::Discarded
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());
        coin.committed = true;
        chain.lock().unwrap().reject_broadcast = true;
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::NotYet
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());
        chain.lock().unwrap().reject_broadcast = false;
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        {
            let chain = chain.lock().unwrap();
            let txid = contract.compute_txid();
            assert_eq!(chain.broadcast, vec![txid]);
            assert_eq!(chain.txs[&txid].0, contract);
        }
        // A failed send that reached the network anyway is still reclaimed:
        // funding the backend knows outweighs the missing flag.
        coin.committed = false;
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        let txid = contract.compute_txid();
        assert!(chain
            .lock()
            .unwrap()
            .broadcast
            .iter()
            .all(|sent| *sent == txid));
    }

    #[test]
    fn committed_legacy_resends_unknown_funding_before_its_contract() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::new());
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding.clone());
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::NotYet
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());

        let digest = secp256k1::Message::from_digest([1; 32]);
        coin.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            crate::utill::global_secp().sign_ecdsa(&digest, &key(3)),
        ));
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        assert_eq!(
            chain.lock().unwrap().broadcast,
            vec![funding.compute_txid(), coin.contract_tx.compute_txid()]
        );
    }

    #[test]
    fn uncommitted_legacy_is_dropped_unless_its_funding_is_seen() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::new());
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.committed = false;
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding.clone());
        let digest = secp256k1::Message::from_digest([1; 32]);
        coin.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            crate::utill::global_secp().sign_ecdsa(&digest, &key(3)),
        ));
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        // A split whose send failed: recovery sends neither its funding nor
        // its contract, and drops it.
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::Discarded
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());

        // The failed send reached the mempool anyway: the split is kept and
        // its contract goes out so the timelock can reclaim it.
        chain
            .lock()
            .unwrap()
            .txs
            .insert(funding.compute_txid(), (funding.clone(), 0));
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::OnChain
        );
        assert_eq!(
            chain.lock().unwrap().broadcast,
            vec![coin.contract_tx.compute_txid()]
        );
    }

    #[test]
    fn uncommitted_split_is_kept_until_its_funding_is_dead() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::new());
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            40_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.committed = false;
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding);
        let chain = StubChain::with(&[(&parent, 50), (&conflict, 0)]);
        let url = start_electrum_stub(chain.clone());
        let backend = electrum(&url);
        // An unconfirmed spend of its input may still be evicted, and the
        // funding could then confirm: keep the coin, and send nothing.
        assert_eq!(
            Wallet::ensure_contract_on_chain(&backend, SWAP, &coin).unwrap(),
            ContractChainState::NotYet
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());

        // Once that spend confirms, the funding can never confirm.
        chain
            .lock()
            .unwrap()
            .txs
            .insert(conflict.compute_txid(), (conflict.clone(), 50));
        assert_eq!(
            Wallet::ensure_contract_on_chain(&electrum(&url), SWAP, &coin).unwrap(),
            ContractChainState::Discarded
        );
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    /// A mined parent, our unsent Legacy funding spending it, and the coin
    /// whose contract spends that funding. `seed` keeps each coin distinct.
    fn unsent_coin(seed: u8) -> (Transaction, Transaction, OutgoingSwapCoin) {
        let parent = tx(
            OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
            100_000,
            ScriptBuf::new(),
        );
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::new(),
        );
        let mut coin = outgoing_coin();
        coin.committed = false;
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        coin.funding_tx = Some(funding.clone());
        (parent, funding, coin)
    }

    /// The swap's incoming coin and `outgoing`, each unsent coin's funding
    /// inputs reserved for the swap.
    fn unsent_wallet(path: &Path, url: &str, outgoing: &[&OutgoingSwapCoin]) -> RwLock<Wallet> {
        let mut wallet = stub_wallet(path, electrum(url));
        wallet.add_incoming_swapcoin(&incoming_coin());
        for coin in outgoing {
            wallet.add_outgoing_swapcoin(coin);
            if let Some(funding) = coin.funding_tx.as_ref().filter(|_| !coin.committed) {
                let inputs: Vec<_> = funding.input.iter().map(|i| i.previous_output).collect();
                wallet.reserve_swap_locks(SWAP, &inputs);
            }
        }
        wallet.save_to_disk().unwrap();
        RwLock::new(wallet)
    }

    /// Fresh connection per pass: passes run a block apart, past any cache.
    fn settle(wallet: &RwLock<Wallet>, url: &str, grace_over: bool) -> UnsentPass {
        Wallet::settle_unsent_funding(wallet, &electrum(url), SWAP, grace_over).unwrap()
    }

    fn coin_counts(wallet: &RwLock<Wallet>) -> (usize, usize, usize) {
        let w = wallet.read().unwrap();
        (
            w.get_incoming_swapcoins_count(),
            w.get_outgoing_swapcoins_count(),
            w.store.swap_locks.values().map(|l| l.outpoints.len()).sum(),
        )
    }

    #[test]
    fn unsent_funding_waits_out_the_grace_then_frees_only_its_inputs() {
        let (parent, _, coin) = unsent_coin(1);
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);

        let waiting = UnsentPass {
            waiting: true,
            ..UnsentPass::default()
        };
        assert_eq!(settle(&wallet, &url, false), waiting);
        assert_eq!(coin_counts(&wallet), (1, 1, 1));

        let released = UnsentPass {
            released: true,
            ..UnsentPass::default()
        };
        assert_eq!(settle(&wallet, &url, true), released);
        // Keys and contract data stay: the funding could still confirm.
        assert_eq!(coin_counts(&wallet), (1, 1, 0));
        assert_eq!(settle(&wallet, &url, true), UnsentPass::default());
        assert_eq!(coin_counts(&wallet), (1, 1, 0));

        // The maker's refund pass neither sends nor drops the kept coin.
        Wallet::recover_timelocked_swapcoins(
            &wallet,
            &electrum(&url),
            &shutdown_after(60),
            None,
            &|_| false,
        )
        .unwrap();
        assert_eq!(coin_counts(&wallet), (1, 1, 0));
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    #[test]
    fn unsent_funding_seen_after_release_is_recorded_as_sent() {
        let (parent, funding, coin) = unsent_coin(2);
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);
        assert!(settle(&wallet, &url, true).released);

        chain
            .lock()
            .unwrap()
            .txs
            .insert(funding.compute_txid(), (funding.clone(), 0));
        assert_eq!(settle(&wallet, &url, true), UnsentPass::default());
        let key = coin.contract_tx.compute_txid().to_string();
        assert!(wallet.read().unwrap().store.outgoing_swapcoins[&key].committed);
        assert!(!wallet.read().unwrap().has_unsent_funding(SWAP));
        // Recording it sends nothing: the refund pass takes it from here.
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    #[test]
    fn unsent_funding_is_dropped_only_once_its_input_spend_confirms() {
        let (parent, _, coin) = unsent_coin(3);
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            40_000,
            ScriptBuf::new(),
        );
        let chain = StubChain::with(&[(&parent, 50), (&conflict, 0)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);

        // A mempool spend may still be evicted: keep everything.
        assert!(!settle(&wallet, &url, true).finished);
        assert_eq!(coin_counts(&wallet), (1, 1, 0));

        chain
            .lock()
            .unwrap()
            .txs
            .insert(conflict.compute_txid(), (conflict.clone(), 50));
        let finished = UnsentPass {
            finished: true,
            ..UnsentPass::default()
        };
        assert_eq!(settle(&wallet, &url, true), finished);
        assert_eq!(coin_counts(&wallet), (0, 0, 0));
        assert!(chain.lock().unwrap().broadcast.is_empty());
    }

    #[test]
    fn dead_unsent_split_leaves_the_rest_of_the_swap() {
        let (parent, _, unsent) = unsent_coin(4);
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            40_000,
            ScriptBuf::new(),
        );
        let (_, _, mut sent) = unsent_coin(5);
        sent.committed = true;
        let chain = StubChain::with(&[(&parent, 50), (&conflict, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(
            &temp_dir.path().join("wallet.cbor"),
            &url,
            &[&unsent, &sent],
        );

        assert_eq!(settle(&wallet, &url, false), UnsentPass::default());
        assert_eq!(coin_counts(&wallet), (1, 1, 0));
        let key = sent.contract_tx.compute_txid().to_string();
        assert!(wallet
            .read()
            .unwrap()
            .store
            .outgoing_swapcoins
            .contains_key(&key));
    }

    #[test]
    fn failed_lookup_keeps_unsent_funding_reserved() {
        let (parent, _, coin) = unsent_coin(6);
        let chain = StubChain::with(&[(&parent, 50)]);
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(&temp_dir.path().join("wallet.cbor"), &url, &[&coin]);

        chain
            .lock()
            .unwrap()
            .fail_lookups
            .insert(coin.contract_tx.compute_txid());
        assert!(Wallet::settle_unsent_funding(&wallet, &electrum(&url), SWAP, true).is_err());
        assert_eq!(coin_counts(&wallet), (1, 1, 1));
    }

    /// One coin's failed lookup must not cost another coin's proof that its
    /// funding was seen: once that funding is evicted it would read as unsent.
    #[test]
    fn seen_funding_is_saved_even_when_another_lookup_fails() {
        let (parent_a, funding_a, seen) = unsent_coin(7);
        let (parent_b, _, failing) = unsent_coin(8);
        let chain = StubChain::with(&[(&parent_a, 50), (&parent_b, 50), (&funding_a, 0)]);
        chain
            .lock()
            .unwrap()
            .fail_lookups
            .insert(failing.contract_tx.compute_txid());
        let url = start_electrum_stub(chain.clone());
        let temp_dir = tempdir().unwrap();
        let wallet = unsent_wallet(
            &temp_dir.path().join("wallet.cbor"),
            &url,
            &[&seen, &failing],
        );

        assert!(Wallet::settle_unsent_funding(&wallet, &electrum(&url), SWAP, true).is_err());
        let key = seen.contract_tx.compute_txid().to_string();
        assert!(wallet.read().unwrap().store.outgoing_swapcoins[&key].committed);
        // Nothing is freed while a lookup fails.
        assert_eq!(coin_counts(&wallet), (1, 2, 2));

        // The seen funding is evicted and the backend recovers: the failing
        // coin's inputs are freed, the committed one's stay reserved.
        {
            let mut chain = chain.lock().unwrap();
            chain.txs.remove(&funding_a.compute_txid());
            chain.fail_lookups.clear();
        }
        assert!(settle(&wallet, &url, true).released);
        assert_eq!(coin_counts(&wallet), (1, 2, 1));
        let held = OutPoint::new(parent_a.compute_txid(), 0);
        assert!(wallet.read().unwrap().store.swap_locks[SWAP]
            .outpoints
            .contains(&held));
    }

    /// The batch is saved whole before its sends: a failed save leaves none
    /// of it, so a later save cannot persist half a batch.
    #[test]
    fn funding_batch_saves_whole_or_not_at_all() {
        let (parent, _, coin) = unsent_coin(9);
        let url = start_electrum_stub(StubChain::with(&[(&parent, 50)]));
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("wallet.cbor");
        let mut wallet = stub_wallet(&path, electrum(&url));
        wallet.save_to_disk().unwrap();
        let incoming = incoming_coin();

        // A directory at the destination forces the atomic replacement to fail.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(wallet
            .save_funding_batch(std::slice::from_ref(&incoming), std::slice::from_ref(&coin))
            .is_err());
        assert_eq!(wallet.get_incoming_swapcoins_count(), 0);
        assert_eq!(wallet.get_outgoing_swapcoins_count(), 0);

        std::fs::remove_dir(&path).unwrap();
        wallet
            .save_funding_batch(std::slice::from_ref(&incoming), &[coin])
            .unwrap();
        let (store, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
        assert_eq!(store.incoming_swapcoins.len(), 1);
        assert_eq!(store.outgoing_swapcoins.len(), 1);
    }

    /// Each funding send restarts the grace on disk: slow earlier sends, or
    /// a claim made long before, must not let a restart free the inputs of a
    /// send that may still be in flight.
    #[test]
    fn each_send_attempt_persists_a_fresh_grace_origin() {
        let (parent, _, _) = unsent_coin(10);
        let url = start_electrum_stub(StubChain::with(&[(&parent, 50)]));
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("wallet.cbor");
        let mut wallet = stub_wallet(&path, electrum(&url));
        wallet.reserve_swap_locks(SWAP, &[OutPoint::new(parent.compute_txid(), 0)]);
        wallet.store.swap_locks.get_mut(SWAP).unwrap().reserved_at = 1;
        wallet.save_to_disk().unwrap();
        let saved_at = || {
            let (store, _) = WalletStore::read_from_disk(&path, Some(PASSWORD.into())).unwrap();
            store.swap_locks[SWAP].reserved_at
        };

        let before = now_secs();
        wallet.restart_funding_grace(SWAP).unwrap();
        let first = saved_at();
        assert!(first >= before, "the first send restarts the grace on disk");

        // Origins are whole seconds; wait for the next one.
        thread::sleep(Duration::from_millis(1_100));
        wallet.restart_funding_grace(SWAP).unwrap();
        assert!(
            saved_at() > first,
            "each later send moves the origin forward"
        );
    }

    #[test]
    fn compat_incoming_claim_report_and_removal_save_together() {
        for role in [SwapRole::Maker, SwapRole::Taker] {
            let incoming = incoming_coin();
            let outgoing = outgoing_coin();
            let chain = StubChain::with(&[
                (&incoming.contract_tx, 50),
                (&outgoing.contract_tx, OUTGOING_HEIGHT),
            ]);
            let url = start_electrum_stub(chain.clone());
            let directory = tempdir().unwrap();
            let path = directory.path().join("wallet.cbor");
            let wallet = wallet_with(&path, &url, &incoming, Some(&outgoing));
            let mut other = outgoing.clone();
            other.swap_id = Some("other".into());
            other.contract_tx.output[0].value = Amount::from_sat(49_999);
            wallet.write().unwrap().add_outgoing_swapcoin(&other);
            let swept = Wallet::sweep_incoming_swapcoins_for_role(
                &wallet,
                &electrum(&url),
                &shutdown_after(60),
                None,
                role,
            )
            .unwrap();
            assert_eq!(swept.resolved.len(), 1);
            let (saved, _) =
                WalletStore::read_from_disk(&path, Some("test-password".into())).unwrap();
            assert!(saved.incoming_swapcoins.is_empty());
            assert!(
                saved.outgoing_swapcoins[&outgoing.contract_tx.compute_txid().to_string()]
                    .incoming_claimed
            );
            assert!(
                !saved.outgoing_swapcoins[&other.contract_tx.compute_txid().to_string()]
                    .incoming_claimed
            );
            let mut snapshot = wallet.write().unwrap();
            snapshot.store = saved;
            let reports = snapshot.swap_reports();
            assert_eq!(reports.recovery.len(), 1);
            let report = &reports.recovery[0];
            assert_eq!(report.swap_id, SWAP);
            assert_eq!(report.role, role);
            assert_eq!(report.recovery_type, "hashlock");
            assert_eq!(report.recovery_txids, vec![swept.resolved[0].1.to_string()]);
        }
    }

    #[test]
    fn compat_failed_recovery_save_rolls_back_then_retries() {
        let incoming = incoming_coin();
        let outgoing = outgoing_coin();
        let chain = StubChain::with(&[(&incoming.contract_tx, 50)]);
        let url = start_electrum_stub(chain);
        let directory = tempdir().unwrap();
        let path = directory.path().join("wallet.cbor");
        let wallet = wallet_with(&path, &url, &incoming, Some(&outgoing));
        let backend = electrum(&url);
        let shutdown = shutdown_after(60);
        let (sweeps, _) =
            Wallet::broadcast_incoming_sweeps(&wallet, &backend, &shutdown, None, &mut false)
                .unwrap();
        assert_eq!(sweeps.len(), 1);
        let before = {
            let wallet = wallet.read().unwrap();
            (
                wallet.store.incoming_swapcoins.clone(),
                wallet.store.outgoing_swapcoins.clone(),
                wallet.store.reports.clone(),
            )
        };
        let original_bytes = std::fs::read(&path).unwrap();
        let saved_path = path.with_extension("saved");
        std::fs::rename(&path, &saved_path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(Wallet::finish_recoveries(
            &wallet,
            &backend,
            &shutdown,
            sweeps.clone(),
            Vec::new(),
            Vec::new(),
            Some(SwapRole::Taker)
        )
        .is_err());
        {
            let wallet = wallet.read().unwrap();
            assert_eq!(wallet.store.incoming_swapcoins, before.0);
            assert_eq!(wallet.store.outgoing_swapcoins, before.1);
            assert_eq!(wallet.store.reports, before.2);
        }
        assert_eq!(std::fs::read(&saved_path).unwrap(), original_bytes);
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&saved_path, &path).unwrap();
        let recovered = Wallet::finish_recoveries(
            &wallet,
            &backend,
            &shutdown,
            sweeps,
            Vec::new(),
            Vec::new(),
            Some(SwapRole::Taker),
        )
        .unwrap();
        assert_eq!(recovered.0.resolved.len(), 1);
        let (saved, _) = WalletStore::read_from_disk(&path, Some("test-password".into())).unwrap();
        assert!(saved.incoming_swapcoins.is_empty());
        assert!(saved
            .outgoing_swapcoins
            .values()
            .all(|coin| coin.incoming_claimed));
        let mut wallet = wallet.write().unwrap();
        wallet.store = saved;
        assert_eq!(wallet.swap_reports().recovery.len(), 1);
    }

    /// The taker side: its incoming contract is still in the mempool when its
    /// outgoing timelock matures. It will sweep that coin, so a refund now
    /// would settle the swap both ways; the refund waits.
    #[test]
    fn mempool_incoming_holds_the_matured_refund() {
        assert!(broadcast_by_recovery(Some(0)).is_empty());

        // With no incoming contract anywhere, the same pass refunds, so the
        // hold above comes from the mempool contract.
        let refunds = broadcast_by_recovery(None);
        let outgoing_contract = OutPoint::new(outgoing_coin().contract_tx.compute_txid(), 0);
        assert_eq!(refunds.len(), 1);
        assert_eq!(refunds[0].input[0].previous_output, outgoing_contract);
    }

    /// Where our refunds go: the address saved with the coin.
    fn recovery_address() -> Address {
        let script = ScriptBuf::new_p2wpkh(&pubkey(7).wpubkey_hash().unwrap());
        Address::from_script(&script, bitcoin::Network::Regtest).unwrap()
    }

    fn with_recovery_address(mut coin: OutgoingSwapCoin) -> OutgoingSwapCoin {
        coin.recovery_address = Some(recovery_address().into_unchecked());
        coin
    }

    fn legacy_coin() -> OutgoingSwapCoin {
        with_recovery_address(outgoing_coin())
    }

    fn taproot_coin() -> OutgoingSwapCoin {
        let mut coin = taproot_coin_and_recovery().0;
        // Recovery only considers a coin holding its own key.
        coin.my_privkey = Some(key(1));
        with_recovery_address(coin)
    }

    /// Our recovery of `coin`, priced at 1 sat/vB.
    fn pending_recovery(coin: &OutgoingSwapCoin) -> Transaction {
        Wallet::create_timelock_recovery_tx(coin, &[1.0], recovery_address()).unwrap()
    }

    /// The first maker's Legacy hop and its confirmed timelock refund.
    fn refunded_first_maker_hop() -> (WatchOnlySwapCoin, Transaction) {
        let redeemscript =
            create_contract_redeemscript(&pubkey(2), &pubkey(3), &Hash160::all_zeros(), &20);
        let contract_tx = tx(
            OutPoint::new(Txid::from_byte_array([6; 32]), 0),
            50_000,
            redeemscript.to_p2wsh(),
        );
        let mut refund = tx(
            OutPoint::new(contract_tx.compute_txid(), 0),
            49_000,
            recovery_address().script_pubkey(),
        );
        refund.input[0].witness =
            Witness::from_slice(&[vec![1; 72], Vec::new(), redeemscript.to_bytes()]);
        let hop = WatchOnlySwapCoin::new_legacy(
            pubkey(3),
            pubkey(2),
            contract_tx,
            redeemscript,
            Amount::from_sat(50_000),
        );
        (hop, refund)
    }

    /// One refund pass over `coin`, with `pending` spending its contract from
    /// the mempool and every fee estimate at `feerate`.
    struct Pass {
        coin: OutgoingSwapCoin,
        pending: Transaction,
        feerate: f64,
        /// The swap's incoming coin is being claimed by hashlock.
        claimed: bool,
        /// The first maker took its own outgoing back by timelock.
        first_maker_refunded: bool,
    }

    impl Pass {
        fn over(coin: OutgoingSwapCoin, feerate: f64) -> Self {
            Pass {
                pending: pending_recovery(&coin),
                coin,
                feerate,
                claimed: false,
                first_maker_refunded: false,
            }
        }

        /// Returns the refunds the pass sent and the txs it broadcast.
        fn run(self) -> (Vec<SentSpend>, Vec<Transaction>) {
            let chain = StubChain::with(&[
                (&self.coin.contract_tx, OUTGOING_HEIGHT),
                (&self.pending, 0),
            ]);
            chain.lock().unwrap().feerate = self.feerate;
            let url = start_electrum_stub(chain.clone());
            let temp_dir = tempdir().unwrap();
            let mut wallet = stub_wallet(&temp_dir.path().join("wallet.cbor"), electrum(&url));
            wallet.add_outgoing_swapcoin(&self.coin);
            if self.first_maker_refunded {
                let (hop, refund) = refunded_first_maker_hop();
                let mut chain = chain.lock().unwrap();
                for tx in [&hop.contract_tx, &refund] {
                    chain
                        .txs
                        .insert(tx.compute_txid(), (tx.clone(), OUTGOING_HEIGHT));
                }
                wallet
                    .store
                    .watchonly_swapcoins
                    .insert(SWAP.to_string(), vec![hop]);
            }
            wallet.save_to_disk().unwrap();

            let claimed = self.claimed;
            let (refunds, discarded) = Wallet::broadcast_timelock_recoveries(
                &RwLock::new(wallet),
                &electrum(&url),
                &shutdown_after(60),
                None,
                &|swap_id| claimed && swap_id == SWAP,
                &|_| false,
                &mut false,
                false,
            )
            .unwrap();
            assert!(discarded.is_empty());
            let chain = chain.lock().unwrap();
            let broadcast = chain
                .broadcast
                .iter()
                .map(|txid| chain.txs[txid].0.clone())
                .collect();
            (refunds, broadcast)
        }
    }

    /// Checks `pass` sent exactly one replacement of its pending tx: ours, to
    /// the stored address, at a higher fee.
    fn assert_replaces(pass: Pass) {
        let (coin, pending) = (pass.coin.clone(), pass.pending.clone());
        let contract_txid = coin.contract_tx.compute_txid();
        let (refunds, broadcast) = pass.run();
        let [replacement] = &broadcast[..] else {
            panic!("expected one replacement, got {:?}", broadcast);
        };
        assert_eq!(
            refunds,
            vec![(
                contract_txid.to_string(),
                contract_txid,
                replacement.compute_txid()
            )]
        );
        assert!(coin.is_own_timelock_spend(replacement));
        assert_eq!(replacement.output.len(), 1);
        assert_eq!(
            replacement.output[0].script_pubkey,
            recovery_address().script_pubkey()
        );
        assert!(replacement.output[0].value < pending.output[0].value);
        // The fee is priced on the size estimate, so the signed tx must fit it.
        assert!(
            replacement.vsize() as u64
                <= contract_and_timelock_vsize(coin.protocol, SpendKind::Timelock)
        );
    }

    /// Electrum hides a mempool-spent output, which used to read as "nothing
    /// to do". Our own recovery spending it must be told apart from that.
    #[test]
    fn electrum_classifies_our_unconfirmed_recovery_as_pending() {
        for coin in [legacy_coin(), taproot_coin()] {
            let pending = pending_recovery(&coin);
            let chain = StubChain::with(&[(&coin.contract_tx, OUTGOING_HEIGHT), (&pending, 0)]);
            let url = start_electrum_stub(chain);
            let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
            assert_eq!(state, ContractChainState::RecoveryPending(pending));
        }
    }

    /// The other side's unconfirmed claim is not ours to replace.
    #[test]
    fn electrum_leaves_an_unconfirmed_claim_by_the_other_side() {
        let coin = legacy_coin();
        let mut claim = pending_recovery(&coin);
        // A hashlock claim carries the preimage where a refund leaves it empty.
        claim.input[0].witness = Witness::from_slice(&[
            vec![1; 72],
            vec![2; 32],
            coin.contract_redeemscript.clone().unwrap().into_bytes(),
        ]);
        let chain = StubChain::with(&[(&coin.contract_tx, OUTGOING_HEIGHT), (&claim, 0)]);
        let url = start_electrum_stub(chain);
        let state = Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// Legacy refunds lock by CSV `nSequence`, Taproot ones by `nLockTime`, and
    /// each has its own size estimate behind the fee.
    #[test]
    fn stuck_recovery_is_replaced_when_fees_rise() {
        assert_replaces(Pass::over(legacy_coin(), 10.0));
        assert_replaces(Pass::over(taproot_coin(), 10.0));
    }

    /// A backend can hand us any unconfirmed tx shaped like our refund. Its
    /// output must never choose where the replacement pays.
    #[test]
    fn forged_pending_tx_cannot_redirect_the_refund() {
        let mut pass = Pass::over(legacy_coin(), 10.0);
        pass.pending.output[0].script_pubkey =
            ScriptBuf::new_p2wpkh(&pubkey(9).wpubkey_hash().unwrap());
        pass.pending.input[0].witness = Witness::from_slice(&[
            vec![0x30; 72],
            Vec::new(),
            pass.coin
                .contract_redeemscript
                .clone()
                .unwrap()
                .into_bytes(),
        ]);
        assert!(pass.coin.is_own_timelock_spend(&pass.pending));
        assert_replaces(pass);
    }

    /// A coin with no stored address never sent a refund of ours.
    #[test]
    fn pending_tx_is_not_replaced_without_a_stored_address() {
        let mut pass = Pass::over(legacy_coin(), 10.0);
        pass.coin.recovery_address = None;
        assert_eq!(pass.run(), (Vec::new(), Vec::new()));
    }

    #[test]
    fn stuck_recovery_stays_when_a_replacement_is_not_due() {
        // The market has not moved.
        assert_eq!(
            Pass::over(legacy_coin(), 1.0).run(),
            (Vec::new(), Vec::new())
        );
        // It moved by less than the 1 sat/vB a replacement must add.
        assert_eq!(
            Pass::over(legacy_coin(), 1.5).run(),
            (Vec::new(), Vec::new())
        );
    }

    /// We refund a claimed swap once its outgoing dangles, and the first maker
    /// can still claim that outgoing by hashlock. A stuck refund there races
    /// the claim, so it is bumped like any other.
    #[test]
    fn stuck_refund_of_a_claimed_swap_is_replaced() {
        assert_replaces(Pass {
            claimed: true,
            first_maker_refunded: true,
            ..Pass::over(legacy_coin(), 10.0)
        });
    }

    /// The replacement must add `increment_rate` sat/vB over its own size.
    #[test]
    fn outbids_needs_the_full_increment() {
        let fee = Amount::from_sat;
        assert!(outbids(fee(100), fee(250), 150, 1.0));
        assert!(!outbids(fee(100), fee(249), 150, 1.0));
        // A node with a higher increment rejects what the default accepts.
        assert!(!outbids(fee(100), fee(250), 150, 5.0));
        assert!(outbids(fee(100), fee(850), 150, 5.0));
    }
}

#[cfg(test)]
mod recovery_address_tests {
    use super::*;

    fn address() -> Address<NetworkUnchecked> {
        let secp = Secp256k1::new();
        let keypair = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[1u8; 32]).unwrap());
        Address::p2tr(&secp, keypair.x_only_public_key().0, None, Network::Regtest).into_unchecked()
    }

    #[test]
    fn retry_reuses_the_stored_recovery_address() {
        let stored = address();
        let (selected, created) = recovery_address_or_else(Some(stored.clone()), || {
            panic!("a retry must not allocate another address")
        })
        .unwrap();

        assert_eq!(selected, stored);
        assert!(!created);
    }

    #[test]
    fn first_recovery_creates_an_address() {
        let expected = address();
        let (selected, created) = recovery_address_or_else(None, || Ok(expected.clone())).unwrap();

        assert_eq!(selected, expected);
        assert!(created);
    }
}

#[cfg(test)]
mod legacy_recovery_tests {
    use super::{timelock_reconcile_tests::tx, *};
    use crate::wallet::{
        blockchain::{CoreRPC, CoreRpcConfig, Electrum},
        swapcoin::OutgoingSwapCoin,
    };
    use bitcoin::{
        consensus::encode::serialize_hex, hashes::Hash, secp256k1::SecretKey, Amount, OutPoint,
        PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };
    use serde_json::{json, Value};
    use std::{
        io::{BufRead, BufReader, Read, Write as IoWrite},
        net::TcpListener,
    };

    fn start_electrum_recovery_stub(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        aliases: Vec<(Txid, Transaction)>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let url = format!("tcp://{}", listener.local_addr().unwrap());
        let genesis = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_hash = genesis.block_hash().to_string();
        let header_hex = serialize_hex(&genesis.header);

        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let (hash, header) = (genesis_hash.clone(), header_hex.clone());
                let txs = known_txs.clone();
                let aliases = aliases.clone();
                std::thread::spawn(move || {
                    let mut out = stream.try_clone().expect("clone stub stream");
                    for line in BufReader::new(stream).lines() {
                        let Ok(line) = line else { return };
                        let req: serde_json::Value = match serde_json::from_str(&line) {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        let id = req["id"].clone();
                        let method = req["method"].as_str().unwrap_or_default();
                        let resp = match method {
                            "server.features" => json!({
                                "jsonrpc": "2.0",
                                "id": id,
                                "result": {
                                    "server_version": "stub",
                                    "genesis_hash": hash,
                                    "protocol_min": "1.4",
                                    "protocol_max": "1.4",
                                    "hash_function": "sha256",
                                    "pruning": serde_json::Value::Null,
                                }
                            }),
                            "blockchain.headers.subscribe" => {
                                json!({"jsonrpc": "2.0", "id": id, "result": {"height": 100, "hex": header}})
                            }
                            "blockchain.block.header" => {
                                json!({"jsonrpc": "2.0", "id": id, "result": header})
                            }
                            "blockchain.scripthash.listunspent" => {
                                let mut unspent = Vec::new();
                                for (tx, height, is_unspent) in &txs {
                                    let is_spent_by_known = txs.iter().any(|(t, _, _)| {
                                        t.input.iter().any(|i| {
                                            i.previous_output.txid == tx.compute_txid()
                                                && i.previous_output.vout == 0
                                        })
                                    });
                                    if *is_unspent && !is_spent_by_known {
                                        let h = height.map(|h| h as i64).unwrap_or(0);
                                        unspent.push(json!({
                                            "height": h,
                                            "tx_hash": tx.compute_txid().to_string(),
                                            "tx_pos": 0,
                                            "value": tx.output[0].value.to_sat(),
                                        }));
                                    }
                                }
                                json!({"jsonrpc": "2.0", "id": id, "result": unspent})
                            }
                            "blockchain.scripthash.get_history" => {
                                let mut history = Vec::new();
                                for (tx, height, _) in &txs {
                                    let h = height.map(|h| h as i64).unwrap_or(0);
                                    history.push(json!({
                                        "height": h,
                                        "tx_hash": tx.compute_txid().to_string(),
                                    }));
                                }
                                json!({"jsonrpc": "2.0", "id": id, "result": history})
                            }
                            "blockchain.transaction.get" => {
                                let txid_requested = req["params"][0].as_str().unwrap_or_default();
                                if let Some((tx, _, _)) = txs.iter().find(|(tx, _, _)| {
                                    tx.compute_txid().to_string() == txid_requested
                                }) {
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": serialize_hex(tx)
                                    })
                                } else if let Some((_, tx)) =
                                    aliases.iter().find(|(alias_txid, _)| {
                                        alias_txid.to_string() == txid_requested
                                    })
                                {
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "result": serialize_hex(tx)
                                    })
                                } else {
                                    json!({
                                        "jsonrpc": "2.0",
                                        "id": id,
                                        "error": {
                                            "code": 1,
                                            "message": "No such mempool or blockchain transaction"
                                        }
                                    })
                                }
                            }
                            _ => {
                                json!({"jsonrpc": "2.0", "id": id, "result": serde_json::Value::Null})
                            }
                        };
                        if writeln!(out, "{resp}").is_err() {
                            return;
                        }
                    }
                });
            }
        });

        url
    }

    fn start_core_recovery_stub(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        aliases: Vec<(Txid, Transaction)>,
    ) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind core stub");
        let addr = listener.local_addr().unwrap();
        let url = format!("{}:{}", addr.ip(), addr.port());

        std::thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(mut stream) = incoming else { continue };
                let _ = stream.set_nodelay(true);
                let txs = known_txs.clone();
                let aliases = aliases.clone();
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().expect("clone core stream"));
                    loop {
                        let mut content_length = 0;
                        let mut line = String::new();
                        loop {
                            line.clear();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                return;
                            }
                            let trimmed = line.trim();
                            if trimmed.is_empty() {
                                break;
                            }
                            if let Some((k, v)) = trimmed.split_once(':') {
                                if k.trim().eq_ignore_ascii_case("content-length") {
                                    content_length = v.trim().parse::<usize>().unwrap_or(0);
                                }
                            }
                        }

                        if content_length == 0 {
                            return;
                        }

                        let mut body_buf = vec![0u8; content_length];
                        if reader.read_exact(&mut body_buf).is_err() {
                            return;
                        }

                        let Ok(req): Result<serde_json::Value, _> =
                            serde_json::from_slice(&body_buf)
                        else {
                            return;
                        };
                        let id = req["id"].clone();
                        let method = req["method"].as_str().unwrap_or_default();
                        let params = &req["params"];

                        let (status_code, resp_body) = match method {
                            "gettxspendingprevout" => {
                                let requested = &params[0][0];
                                let spending = txs
                                    .iter()
                                    .find(|(tx, height, _)| {
                                        height.is_none()
                                            && tx.input.iter().any(|input| {
                                                input.previous_output.txid.to_string()
                                                    == requested["txid"]
                                                        .as_str()
                                                        .unwrap_or_default()
                                                    && u64::from(input.previous_output.vout)
                                                        == requested["vout"].as_u64().unwrap_or(0)
                                            })
                                    })
                                    .map(|(tx, _, _)| tx.compute_txid());
                                (
                                    200,
                                    json!({"id": id, "result": [{"txid": requested["txid"], "vout": requested["vout"], "spendingtxid": spending}], "error": null}),
                                )
                            }
                            // The same tip the Electrum stub reports, so a
                            // mined tx is equally deep on both backends.
                            "getblockcount" => {
                                let height = txs
                                    .iter()
                                    .filter_map(|(_, height, _)| *height)
                                    .max()
                                    .unwrap_or(0)
                                    .max(100);
                                (200, json!({"id": id, "result": height, "error": null}))
                            }
                            "getblockhash" => (
                                200,
                                json!({"id": id, "result": format!("{:064x}", params[0].as_u64().unwrap()), "error": null}),
                            ),
                            "getblock" => {
                                let height =
                                    u64::from_str_radix(params[0].as_str().unwrap(), 16).unwrap();
                                let block = bitcoin::Block {
                                    header: bitcoin::constants::genesis_block(
                                        bitcoin::Network::Regtest,
                                    )
                                    .header,
                                    txdata: txs
                                        .iter()
                                        .filter(|(_, h, _)| *h == Some(height))
                                        .map(|(tx, _, _)| tx.clone())
                                        .collect(),
                                };
                                (
                                    200,
                                    json!({"id": id, "result": serialize_hex(&block), "error": null}),
                                )
                            }
                            "getrawtransaction" => {
                                let txid_req = params[0].as_str().unwrap_or_default();
                                let verbose = params
                                    .get(1)
                                    .map(|v| {
                                        v.as_bool().unwrap_or(false)
                                            || v.as_i64().unwrap_or(0) != 0
                                            || v.as_u64().unwrap_or(0) != 0
                                    })
                                    .unwrap_or(false);
                                if let Some((tx, height, _)) = txs
                                    .iter()
                                    .find(|(t, _, _)| t.compute_txid().to_string() == txid_req)
                                {
                                    if verbose {
                                        let blockhash = height.map(|h| format!("{:064x}", h));
                                        let vin: Vec<Value> = tx
                                            .input
                                            .iter()
                                            .map(|i| {
                                                json!({
                                                    "txid": i.previous_output.txid.to_string(),
                                                    "vout": i.previous_output.vout,
                                                    "scriptSig": {"asm": "", "hex": serialize_hex(&i.script_sig)},
                                                    "sequence": i.sequence.0,
                                                })
                                            })
                                            .collect();
                                        let vout: Vec<Value> = tx
                                            .output
                                            .iter()
                                            .enumerate()
                                            .map(|(n, o)| {
                                                json!({
                                                    "value": o.value.to_btc(),
                                                    "n": n,
                                                    "scriptPubKey": {
                                                        "asm": "",
                                                        "hex": serialize_hex(&o.script_pubkey),
                                                        "type": null,
                                                    }
                                                })
                                            })
                                            .collect();
                                        let result = json!({
                                            "in_active_chain": null,
                                            "hex": serialize_hex(tx),
                                            "txid": txid_req,
                                            "hash": tx.compute_wtxid().to_string(),
                                            "size": tx.total_size(),
                                            "vsize": tx.vsize(),
                                            "version": tx.version.0 as u32,
                                            "locktime": tx.lock_time.to_consensus_u32(),
                                            "vin": vin,
                                            "vout": vout,
                                            "blockhash": blockhash,
                                            "confirmations": if height.is_some() { 1 } else { 0 },
                                            "time": 100,
                                            "blocktime": 100,
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": serialize_hex(tx), "error": Value::Null}),
                                        )
                                    }
                                } else if let Some((_, tx)) = aliases
                                    .iter()
                                    .find(|(alias_txid, _)| alias_txid.to_string() == txid_req)
                                {
                                    if verbose {
                                        let vin: Vec<Value> = tx
                                            .input
                                            .iter()
                                            .map(|i| {
                                                json!({
                                                    "txid": i.previous_output.txid.to_string(),
                                                    "vout": i.previous_output.vout,
                                                    "scriptSig": {"asm": "", "hex": serialize_hex(&i.script_sig)},
                                                    "sequence": i.sequence.0,
                                                })
                                            })
                                            .collect();
                                        let vout: Vec<Value> = tx
                                            .output
                                            .iter()
                                            .enumerate()
                                            .map(|(n, o)| {
                                                json!({
                                                    "value": o.value.to_btc(),
                                                    "n": n,
                                                    "scriptPubKey": {
                                                        "asm": "",
                                                        "hex": serialize_hex(&o.script_pubkey),
                                                        "type": null,
                                                    }
                                                })
                                            })
                                            .collect();
                                        let result = json!({
                                            "in_active_chain": null,
                                            "hex": serialize_hex(tx),
                                            "txid": txid_req,
                                            "hash": tx.compute_wtxid().to_string(),
                                            "size": tx.total_size(),
                                            "vsize": tx.vsize(),
                                            "version": tx.version.0 as u32,
                                            "locktime": tx.lock_time.to_consensus_u32(),
                                            "vin": vin,
                                            "vout": vout,
                                            "blockhash": Value::Null,
                                            "confirmations": 0,
                                            "time": 100,
                                            "blocktime": 100,
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": serialize_hex(tx), "error": Value::Null}),
                                        )
                                    }
                                } else {
                                    (
                                        500,
                                        json!({
                                            "jsonrpc": "1.0",
                                            "id": id,
                                            "result": Value::Null,
                                            "error": {
                                                "code": -5,
                                                "message": "No such mempool or blockchain transaction"
                                            }
                                        }),
                                    )
                                }
                            }
                            "getblockheader" => {
                                let hash_req = params[0].as_str().unwrap_or_default();
                                let height =
                                    u64::from_str_radix(hash_req.trim_start_matches('0'), 16)
                                        .unwrap_or(1);
                                let result = json!({
                                    "hash": hash_req,
                                    "confirmations": 1,
                                    "height": height as usize,
                                    "version": 1,
                                    "versionHex": "00000001",
                                    "merkleroot": "0000000000000000000000000000000000000000000000000000000000000000",
                                    "time": 100,
                                    "mediantime": 100,
                                    "nonce": 0,
                                    "bits": "1d00ffff",
                                    "difficulty": 1.0,
                                    "chainwork": "0000000000000000000000000000000000000000000000000000000000000001",
                                    "nTx": 1,
                                    "previousblockhash": Value::Null,
                                    "nextblockhash": Value::Null,
                                });
                                (
                                    200,
                                    json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                )
                            }
                            "getmempoolentry" => {
                                let txid_req = params[0].as_str().unwrap_or_default();
                                if let Some((tx, height, _)) = txs
                                    .iter()
                                    .find(|(t, _, _)| t.compute_txid().to_string() == txid_req)
                                {
                                    if height.is_none() {
                                        let result = json!({
                                            "vsize": tx.vsize(),
                                            "weight": tx.weight().to_wu() as usize,
                                            "time": 100,
                                            "height": 0,
                                            "descendantcount": 1,
                                            "descendantsize": 100,
                                            "ancestorcount": 1,
                                            "ancestorsize": 100,
                                            "wtxid": tx.compute_wtxid().to_string(),
                                            "fees": {
                                                "base": 0.00001,
                                                "modified": 0.00001,
                                                "ancestor": 0.00001,
                                                "descendant": 0.00001
                                            },
                                            "depends": [],
                                            "spentby": [],
                                            "bip125-replaceable": true,
                                            "unbroadcast": false
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            500,
                                            json!({
                                                "jsonrpc": "1.0",
                                                "id": id,
                                                "result": Value::Null,
                                                "error": {
                                                    "code": -5,
                                                    "message": "Transaction not in mempool"
                                                }
                                            }),
                                        )
                                    }
                                } else {
                                    (
                                        500,
                                        json!({
                                            "jsonrpc": "1.0",
                                            "id": id,
                                            "result": Value::Null,
                                            "error": {
                                                "code": -5,
                                                "message": "Transaction not in mempool"
                                            }
                                        }),
                                    )
                                }
                            }
                            "gettxout" => {
                                let txid_req = params[0].as_str().unwrap_or_default();
                                let vout_req = params[1].as_u64().unwrap_or(0) as u32;
                                let include_mempool = params[2].as_bool().unwrap_or(true);
                                if let Some((tx, height, is_unspent)) = txs
                                    .iter()
                                    .find(|(t, _, _)| t.compute_txid().to_string() == txid_req)
                                {
                                    let is_confirmed_spent = txs.iter().any(|(t, h, _)| {
                                        h.is_some()
                                            && t.input.iter().any(|i| {
                                                i.previous_output.txid == tx.compute_txid()
                                                    && i.previous_output.vout == vout_req
                                            })
                                    });
                                    let is_mempool_spent = txs.iter().any(|(t, h, _)| {
                                        h.is_none()
                                            && t.input.iter().any(|i| {
                                                i.previous_output.txid == tx.compute_txid()
                                                    && i.previous_output.vout == vout_req
                                            })
                                    });
                                    let is_spent = if include_mempool {
                                        is_confirmed_spent || is_mempool_spent
                                    } else {
                                        is_confirmed_spent
                                    };
                                    if *is_unspent
                                        && !is_spent
                                        && (height.is_some() || include_mempool)
                                    {
                                        let result = json!({
                                            "bestblock": "0000000000000000000000000000000000000000000000000000000000000000",
                                            "confirmations": if height.is_some() { 1 } else { 0 },
                                            "value": tx.output[vout_req as usize].value.to_btc(),
                                            "scriptPubKey": {
                                                "asm": "",
                                                "hex": serialize_hex(&tx.output[vout_req as usize].script_pubkey),
                                                "type": null,
                                            },
                                            "coinbase": false
                                        });
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": result, "error": Value::Null}),
                                        )
                                    } else {
                                        (
                                            200,
                                            json!({"jsonrpc": "1.0", "id": id, "result": Value::Null, "error": Value::Null}),
                                        )
                                    }
                                } else {
                                    (
                                        200,
                                        json!({"jsonrpc": "1.0", "id": id, "result": Value::Null, "error": Value::Null}),
                                    )
                                }
                            }
                            _ => (
                                200,
                                json!({"jsonrpc": "1.0", "id": id, "result": Value::Null, "error": Value::Null}),
                            ),
                        };

                        let resp_str = resp_body.to_string();
                        let status_text = if status_code == 200 {
                            "200 OK"
                        } else {
                            "500 Internal Server Error"
                        };
                        let http_resp = format!(
                            "HTTP/1.1 {status_text}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n{resp_str}",
                            resp_str.len()
                        );
                        if stream.write_all(http_resp.as_bytes()).is_err() {
                            return;
                        }
                    }
                });
            }
        });

        url
    }

    fn for_both_backends_with_aliases<F: Fn(AnyBlockchain)>(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        aliases: Vec<(Txid, Transaction)>,
        test_fn: F,
    ) {
        let electrum_url = start_electrum_recovery_stub(known_txs.clone(), aliases.clone());
        let electrum = Electrum::new(&crate::wallet::ElectrumConfig {
            url: electrum_url,
            ..Default::default()
        })
        .expect("connect to electrum stub");
        test_fn(AnyBlockchain::Electrum(electrum));

        let core_url = start_core_recovery_stub(known_txs, aliases);
        let core = CoreRPC::new(&CoreRpcConfig {
            url: core_url,
            ..Default::default()
        })
        .expect("connect to core stub");
        test_fn(AnyBlockchain::CoreRPC(core));
    }

    fn for_both_backends<F: Fn(AnyBlockchain)>(
        known_txs: Vec<(Transaction, Option<u64>, bool)>,
        test_fn: F,
    ) {
        for_both_backends_with_aliases(known_txs, vec![], test_fn);
    }

    fn make_legacy_outgoing_swapcoin(funding_tx: Option<Transaction>) -> OutgoingSwapCoin {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([10u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = funding_tx;
        sc.others_contract_sig = None;
        sc
    }

    #[test]
    fn compat_funding_inputs_distinguish_confirmed_conflicts_from_own_funding() {
        let parent = tx(OutPoint::null(), 100_000, ScriptBuf::from_bytes(vec![0x51]));
        let funding = tx(
            OutPoint::new(parent.compute_txid(), 0),
            50_000,
            ScriptBuf::from_bytes(vec![0x52]),
        );
        let conflict = tx(
            OutPoint::new(parent.compute_txid(), 0),
            49_000,
            ScriptBuf::from_bytes(vec![0x53]),
        );
        let mut coin = make_legacy_outgoing_swapcoin(Some(funding.clone()));
        coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
        for (spender, height, expected) in [
            (&funding, Some(11), ContractChainState::NotYet),
            (&funding, None, ContractChainState::NotYet),
            (&conflict, None, ContractChainState::NotYet),
            (&conflict, Some(11), ContractChainState::Discarded),
        ] {
            for_both_backends(
                vec![
                    (parent.clone(), Some(10), false),
                    (spender.clone(), height, true),
                ],
                |chain| {
                    assert_eq!(
                        Wallet::ensure_contract_on_chain(&chain, "committed", &coin).unwrap(),
                        expected
                    );
                },
            );
        }
    }

    #[test]
    fn compat_legacy_contract_funding_output_requires_a_confirmed_conflict() {
        let funding = tx(OutPoint::null(), 100_000, ScriptBuf::from_bytes(vec![0x51]));
        let conflict = tx(
            OutPoint::new(funding.compute_txid(), 0),
            49_000,
            ScriptBuf::from_bytes(vec![0x53]),
        );
        for stored_funding in [None, Some(funding.clone())] {
            let mut coin = make_legacy_outgoing_swapcoin(stored_funding);
            coin.contract_tx.input[0].previous_output = OutPoint::new(funding.compute_txid(), 0);
            for (height, expected) in [
                (None, ContractChainState::NotYet),
                (Some(11), ContractChainState::Discarded),
            ] {
                for_both_backends(
                    vec![
                        (funding.clone(), Some(10), false),
                        (conflict.clone(), height, true),
                    ],
                    |chain| {
                        assert_eq!(
                            Wallet::ensure_contract_on_chain(&chain, "committed", &coin).unwrap(),
                            expected
                        );
                    },
                );
            }
        }
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_spent_wallet_inputs_is_discarded() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        for_both_backends(
            vec![(parent_tx, Some(10), false), (spending_tx, Some(11), true)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-spent", &sc).unwrap();
                assert_eq!(res, ContractChainState::Discarded);
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_spent_parent_is_discarded() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends(
            vec![(parent_tx, Some(10), false), (spending_tx, Some(11), true)],
            |blockchain| {
                let res =
                    Wallet::ensure_contract_on_chain(&blockchain, "swap-no-funding-spent", &sc)
                        .unwrap();
                assert_eq!(res, ContractChainState::Discarded);
            },
        );
    }

    #[test]
    fn test_ensure_contract_uncommitted_legacy_is_discarded() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        sc.committed = false;
        for_both_backends(vec![(parent_tx, Some(10), true)], |blockchain| {
            let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-unspent", &sc).unwrap();
            assert_eq!(res, ContractChainState::Discarded);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_unspent_wallet_inputs_and_shared_funding_is_not_yet(
    ) {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        for_both_backends(vec![(parent_tx, Some(10), true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-unspent-shared", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    /// A coin the maker signed may have had its funding broadcast, and an
    /// evicted funding tx can still confirm elsewhere. Unknown funding with
    /// unspent inputs is no proof otherwise, so it must be kept even when the
    /// contract still cannot be signed for another reason.
    #[test]
    fn test_ensure_contract_maker_signed_legacy_with_unknown_funding_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let mut sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let msg = bitcoin::secp256k1::Message::from_digest([1u8; 32]);
        sc.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&msg, &SecretKey::from_slice(&[3u8; 32]).unwrap()),
        ));
        // Signing still fails, so the coin takes the unsignable path.
        sc.other_pubkey = None;
        for_both_backends(vec![(parent_tx, Some(10), true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-maker-signed", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    /// A shared funding whose input a rival spends only in the mempool can
    /// still confirm: the rival may be evicted, and the peer holds the signed
    /// funding. Electrum's confirmed view hides that input all the same, so
    /// only a proven deep confirmed spend may discard the coin.
    #[test]
    fn test_ensure_contract_signed_legacy_with_mempool_spent_funding_input_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let spend_parent = |value| Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let funding_tx = spend_parent(50_000);
        let rival = spend_parent(90_000);

        let mut sc = make_legacy_outgoing_swapcoin(Some(funding_tx.clone()));
        sc.contract_tx.input[0].previous_output = OutPoint::new(funding_tx.compute_txid(), 0);
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let msg = bitcoin::secp256k1::Message::from_digest([1u8; 32]);
        sc.others_contract_sig = Some(bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&msg, &SecretKey::from_slice(&[3u8; 32]).unwrap()),
        ));
        for_both_backends(
            vec![(parent_tx, Some(10), true), (rival, None, true)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-mempool-rival", &sc)
                    .unwrap();
                assert_eq!(res, ContractChainState::NotYet);
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_no_onchain_input_is_not_yet() {
        let sc = make_legacy_outgoing_swapcoin(None);
        for_both_backends(vec![], |blockchain| {
            let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-no-input", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_funding_tx_in_mempool_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let parent_txid = parent_tx.compute_txid();

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx.clone()));
        for_both_backends(
            vec![(parent_tx, Some(10), true), (funding_tx, None, true)],
            |blockchain| {
                let res =
                    Wallet::ensure_contract_on_chain(&blockchain, "swap-mempool-funding", &sc)
                        .unwrap();
                assert_eq!(res, ContractChainState::NotYet);
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_parent_in_mempool_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends(vec![(parent_tx, None, true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-mempool-parent", &sc).unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_mismatched_parent_tx_is_not_yet() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let mismatched_txid = Txid::from_byte_array([99u8; 32]);

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let funding_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(mismatched_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let sc = make_legacy_outgoing_swapcoin(Some(funding_tx));
        for_both_backends_with_aliases(
            vec![
                (parent_tx.clone(), Some(10), false),
                (spending_tx, Some(11), true),
            ],
            vec![(mismatched_txid, parent_tx)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(&blockchain, "swap-mismatched", &sc);
                // Electrum validates the returned txid and rejects the
                // mismatch; that failure must reach the caller, not read as
                // "nothing to check, keep waiting". Core's stub has no such
                // guard and returns the wrong transaction transparently, so
                // the mismatch there is caught downstream by the plain txid
                // comparison instead, and normal NotYet still applies.
                if matches!(blockchain, AnyBlockchain::Electrum(_)) {
                    res.unwrap_err();
                } else {
                    assert_eq!(res.unwrap(), ContractChainState::NotYet);
                }
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_mismatched_parent_tx_is_not_yet()
    {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let mismatched_txid = Txid::from_byte_array([99u8; 32]);

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(parent_tx.compute_txid(), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let dummy_contract_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(mismatched_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new(),
            }],
        };

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_privkey = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let other_privkey = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let other_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_privkey),
        };
        let timelock_privkey = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let mut sc = OutgoingSwapCoin::new_legacy(
            my_privkey,
            other_pubkey,
            dummy_contract_tx,
            ScriptBuf::new(),
            timelock_privkey,
            Amount::from_sat(50_000),
            1,
        );
        sc.committed = true;
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends_with_aliases(
            vec![
                (parent_tx.clone(), Some(10), false),
                (spending_tx, Some(11), true),
            ],
            vec![(mismatched_txid, parent_tx)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(
                    &blockchain,
                    "swap-no-funding-mismatched",
                    &sc,
                );
                // Same split as the funded-mismatch case: Electrum's
                // txid-validating fetch rejects the wrong transaction and
                // that must propagate, while Core's stub returns it
                // transparently and the plain txid comparison downstream
                // catches the mismatch, leaving NotYet.
                if matches!(blockchain, AnyBlockchain::Electrum(_)) {
                    res.unwrap_err();
                } else {
                    assert_eq!(res.unwrap(), ContractChainState::NotYet);
                }
            },
        );
    }

    #[test]
    fn test_electrum_tx_block_height_rejects_mismatched_txid() {
        let parent_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x20, 0x01]),
            }],
        };
        let mismatched_txid = Txid::from_byte_array([99u8; 32]);

        for_both_backends_with_aliases(
            vec![(parent_tx.clone(), Some(10), true)],
            vec![(mismatched_txid, parent_tx)],
            |blockchain| {
                if let AnyBlockchain::Electrum(ref electrum) = blockchain {
                    let res = electrum.tx_block_height(&mismatched_txid);
                    assert!(
                        res.is_err(),
                        "Electrum::tx_block_height must reject txid mismatch"
                    );
                }
            },
        );
    }
}
