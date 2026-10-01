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
use zeroize::Zeroize;

use crate::{
    lock_debug,
    protocol::{contract::create_multisig_redeemscript, ProtocolVersion},
    utill::{
        capped_fee, compute_checksum, fee_at_rate_sats, generate_keypair,
        get_hd_path_from_descriptor, now_secs, redeemscript_to_scriptpubkey, HEART_BEAT_INTERVAL,
        LEGACY_CONTRACT_SPEND_VSIZE, MIN_RELAY_FEE_RATE, TAPROOT_KEYPATH_VSIZE,
        TX_BROADCAST_TIMEOUT, TX_CONFIRMATION_TIMEOUT, UNFUNDED_SWAP_LIFETIME,
    },
};

use rust_coinselect::{
    selectcoin::select_coin,
    types::{CoinSelectionOpt, ExcessStrategy, OutputGroup, SelectionError},
    utils::calculate_fee,
};

use super::{
    blockchain::{AnyBlockchain, Blockchain, HdOrigin},
    error::WalletError,
    storage::{AddressType, WalletStore},
    swapcoin::{contract_timelock, WatchOnlySwapCoin},
};

// these subroutines are coded so that as much as possible they keep all their
// data in the bitcoin core wallet
// for example which privkey corresponds to a scriptpubkey is stored in hd paths

/// Address gap limit of 20 from [BIP-44](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#address-gap-limit):
/// the rolling watch/import window always extends this many unused addresses
/// beyond the last used one per keychain (see [`Wallet::max_watch_index`]).
pub(crate) const ADDRESS_IMPORT_COUNT: u32 = 20;
/// Wider gap used while syncing a wallet restored from backup. The backup
/// carries no hand-out counters, so index gaps left by aborted multi-tx
/// funding (see [`Wallet::get_next_internal_addresses`]) must be bridged by
/// scanning alone; a run of unused indices longer than the gap would otherwise
/// end discovery early and strand funds past it. Only costs restore-time
/// queries — syncs after the first completed scan stay at [`ADDRESS_IMPORT_COUNT`].
pub(crate) const RESTORE_ADDRESS_GAP: u32 = 100;
/// Hard caps on the rolling-gap sync loop: a server inventing UTXOs at ever
/// higher indices must not keep the loop or the watch window growing forever.
const MAX_SYNC_PASSES: u32 = 100;
const MAX_WATCH_WINDOW: u32 = 100_000;
/// script-path: sig+preimage+script+control_block (~154)
const TAPROOT_SCRIPTPATH_VSIZE: u64 = 155;
/// ≈141 + 1 (growing block-height)
const LEGACY_TIMELOCK_VSIZE: u64 = 142;
/// ≈138 + 2 (growing block-height)
const TAPROOT_TIMELOCK_VSIZE: u64 = 140;

/// A BIP39 seed phrase for one-time display.No `Debug`/`Display`;
/// [`SecretMnemonic::words`] is the only reader.
pub struct SecretMnemonic(Mnemonic);

impl SecretMnemonic {
    /// Callers must not log or persist the result.
    pub fn words(&self) -> String {
        self.0.to_string()
    }
}

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
    /// Transient: seed phrase of a wallet created by
    /// [`Wallet::init`]. Read once via [`Wallet::take_new_mnemonic`].
    pub(super) new_mnemonic: Option<SecretMnemonic>,
    /// Wallet-side set of outpoints excluded from coin selection.
    pub(crate) locked_utxos: HashSet<OutPoint>,
    /// Transient (never persisted): widens the gap-limit window to
    /// [`RESTORE_ADDRESS_GAP`] during restore or when reopening a wallet whose
    /// first scan never saved a height.
    pub(crate) restore_scan: bool,
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
        // Compare master keys by plaintext (each unsealed with its own
        // passphrase), not by sealed bytes, so wallets sealed under
        // different passphrases/nonces still compare equal. Both sides must
        // unseal: `plaintext_with` maps a decryption failure to `None`, and
        // `None == None` would report a false match.
        matches!(
            (
                self.store.master_key.plaintext_with(&self.store_enc_material),
                other
                    .store
                    .master_key
                    .plaintext_with(&other.store_enc_material),
            ),
            (Some(a), Some(b)) if a == b
        ) &&
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

/// Smallest contract worth creating: it pays the costliest spend path at `feerate`
/// and still leaves a P2TR output, the wallet's highest-dust script, above dust.
pub fn min_contract_value_sats(protocol: ProtocolVersion, feerate: f64) -> Option<u64> {
    let p2tr =
        ScriptBuf::new_witness_program(&WitnessProgram::new(WitnessVersion::V1, &[0; 32]).ok()?);
    payment_settlement_budget_sats(protocol, feerate)?.checked_add(p2tr.minimal_non_dust().to_sat())
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

/// Chain state of one swapcoin's contract output on a recovery pass.
#[derive(Debug, PartialEq, Eq)]
enum ContractChainState {
    /// The output is on-chain or was just broadcast; recovery can proceed.
    OnChain,
    /// The output is gone for good; the swapcoin can be dropped.
    Discarded,
    /// Our own timelock recovery already confirmed; record it as resolved.
    RecoveredByTimelock(Txid),
    /// Nothing decided this pass; the next recovery run retries.
    NotYet,
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
    pub fn init(
        path: &Path,
        blockchain: AnyBlockchain,
        store_enc_material: KeyMaterial,
    ) -> Result<Self, WalletError> {
        let network = blockchain.get_blockchain_info()?.chain;

        // Generate Master key
        let mnemonic = Mnemonic::generate(12)?;
        let master_key = Self::master_key_from_mnemonic(&mnemonic, network)?;

        // Initialise wallet
        let file_name = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| {
                WalletError::General("wallet path has no valid UTF-8 file name".to_string())
            })?
            .to_string();

        let wallet_birthday = blockchain.get_block_count()?;
        // WalletStore::init seals the master key before the first write, so
        // the plaintext key never reaches disk.
        let store = WalletStore::init(
            file_name,
            path,
            network,
            master_key,
            Some(wallet_birthday),
            &store_enc_material,
        )?;
        log::info!(
            "Wallet birth_height = {wallet_birthday}, last_synced_height = {:?}",
            store.last_synced_height
        );
        Ok(Self {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material,
            new_mnemonic: Some(SecretMnemonic(mnemonic)),
            locked_utxos: HashSet::new(),
            restore_scan: false,
        })
    }

    /// BIP39 seed to BIP32 master key, without the optional BIP39 passphrase
    pub(super) fn master_key_from_mnemonic(
        mnemonic: &Mnemonic,
        network: Network,
    ) -> Result<Xpriv, WalletError> {
        Ok(Xpriv::new_master(network, &mnemonic.to_seed(""))?)
    }

    /// `Some` at most once; always `None` for loaded or restored wallets.
    pub fn take_new_mnemonic(&mut self) -> Option<SecretMnemonic> {
        self.new_mnemonic.take()
    }

    /// Get the wallet name
    pub fn get_name(&self) -> &str {
        &self.store.file_name
    }

    /// Verify the deniability proof for a specific swap in this wallet's report file.
    pub fn verify_deniability(&self, swap_id: &str) -> Result<bool, std::io::Error> {
        let stem = self
            .wallet_file_path
            .file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| std::io::Error::other("wallet path has no valid file stem"))?;
        let report_path = self
            .wallet_file_path
            .parent()
            .ok_or_else(|| std::io::Error::other("wallet path has no parent directory"))?
            .join(format!("{stem}_swap_report.json"));
        crate::wallet::deniability::verify_deniability(&report_path, &self.blockchain, swap_id)
    }

    /// Load wallet data from file and connect to a blockchain backend.
    /// In case of core rpc, core wallet name, and wallet_id field in the file should match.
    ///
    /// Wallet files are always encrypted; an unencrypted file is rejected.
    /// Opening one requires the passphrase it was written with.
    pub(crate) fn load(
        path: &Path,
        blockchain: AnyBlockchain,
        password: Option<String>,
    ) -> Result<Self, WalletError> {
        let password = password.filter(|p| !p.is_empty());

        let (store, store_enc_material) = match WalletStore::read_from_disk(path, password.clone())
        {
            Ok((store, Some(material))) => (store, material),
            // Cleartext wallet files are not supported at all.
            Ok((_, None)) => {
                return Err(WalletError::General(format!(
                    "wallet file {path:?} is unencrypted; \
                         cleartext wallet files are not supported"
                )))
            }
            // Encrypted file, no passphrase supplied. Report how to supply
            // one instead of failing decryption with an empty passphrase.
            Err(WalletError::Security(SecurityError::PasswordRequired)) => {
                return Err(WalletError::General(format!(
                    "wallet file {path:?} is encrypted; \
                         provide the wallet passphrase via -p/--password"
                )))
            }
            Err(e) => return Err(e),
        };
        // Wipe the cleartext passphrase; only the derived key material is kept.
        if let Some(mut p) = password {
            p.zeroize();
        }

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
        let restore_scan = store.last_synced_height.is_none();
        let mut wallet = Self {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material,
            new_mnemonic: None,
            locked_utxos: HashSet::new(),
            restore_scan,
        };
        wallet.seal_master_key()?;
        Ok(wallet)
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
        let wallet = if path.exists() {
            // wallet already exists, load the wallet
            let mut wallet = Wallet::load(path, blockchain, password)?;
            if wallet.restore_scan {
                log::warn!("Wallet at {path:?} has an unfinished first scan; resuming it");
                wallet.sync_and_save(&crate::utill::NO_SHUTDOWN)?;
            }
            log::info!("Wallet file at {path:?} successfully loaded.");
            wallet
        } else {
            // wallet doesn't exists at the given path, create a new one
            let Some(password) = password.filter(|p| !p.is_empty()) else {
                return Err(WalletError::General(
                    "a passphrase is required to create a wallet; \
                     cleartext wallet files are not supported"
                        .to_string(),
                ));
            };
            let store_enc_material = KeyMaterial::new_from_password(Some(password))
                .expect("a non-empty passphrase always yields key material");

            let wallet = Wallet::init(path, blockchain, store_enc_material)?;

            log::info!("New Wallet created at : {path:?}");
            wallet
        };

        Ok(wallet)
    }

    /// Persist wallet data to disk, creating missing parent directories and file as needed.
    pub(crate) fn save_to_disk(&self) -> Result<(), WalletError> {
        self.store
            .write_to_disk(&self.wallet_file_path, &self.store_enc_material)
    }

    /// Seals the master key in memory under the wallet's encryption material
    /// and erases the plaintext copy. Called once at wallet construction
    /// (load/restore; `WalletStore::init` seals before its first write);
    /// afterwards the plaintext key only exists transiently inside
    /// [`Wallet::with_master_key`].
    pub(crate) fn seal_master_key(&mut self) -> Result<(), WalletError> {
        self.store.master_key.seal(&self.store_enc_material)
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
            let mut account = master_key.derive_priv(
                secp,
                &Self::get_derivation_path(address_type, self.store.network),
            )?;
            let result = f(&account);
            account.private_key.non_secure_erase();
            result
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
        self.store
            .outgoing_swapcoins
            .insert(key.clone(), coin.clone());
        log::info!(
            "Added outgoing swapcoin to wallet store: {} (total: {})",
            key,
            self.store.outgoing_swapcoins.len()
        );
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

    /// Removes watch-only swapcoins for a given swap.
    pub(crate) fn remove_watchonly_swapcoins(
        &mut self,
        swap_id: &str,
    ) -> Option<Vec<super::swapcoin::WatchOnlySwapCoin>> {
        self.store.watchonly_swapcoins.remove(swap_id)
    }

    /// True when this wallet talks to an Electrum server rather than Bitcoin Core.
    pub fn is_electrum(&self) -> bool {
        self.blockchain.is_electrum()
    }

    /// Gets the count of incoming swap coins.
    pub fn get_incoming_swapcoins_count(&self) -> usize {
        self.store.incoming_swapcoins.len()
    }

    /// Gets the count of outgoing swap coins.
    pub fn get_outgoing_swapcoins_count(&self) -> usize {
        self.store.outgoing_swapcoins.len()
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
    pub(crate) fn remove_outgoing_swapcoin(&mut self, contract_txid: &str) {
        if self
            .store
            .outgoing_swapcoins
            .remove(contract_txid)
            .is_some()
        {
            log::info!(
                "Removed outgoing swapcoin: {} (remaining: {})",
                contract_txid,
                self.store.outgoing_swapcoins.len()
            );
        }
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

    fn check_funding_inputs_state(
        chain: &AnyBlockchain,
        tx: &Transaction,
    ) -> Result<(bool, bool), WalletError> {
        let mut any_confirmed_spent = false;
        let mut all_unspent = !tx.input.is_empty();

        for input in &tx.input {
            let outpoint = input.previous_output;
            let unspent = matches!(
                chain.get_tx_out(&outpoint.txid, outpoint.vout, Some(true)),
                Ok(Some(_))
            );
            if !unspent {
                all_unspent = false;
            }
            match chain.get_raw_transaction(&outpoint.txid, None) {
                Ok(parent_tx) => {
                    if parent_tx.compute_txid() == outpoint.txid {
                        if let Some(output) = parent_tx.output.get(outpoint.vout as usize) {
                            if chain.is_confirmed_spend(&outpoint, &output.script_pubkey)? {
                                any_confirmed_spent = true;
                                break;
                            }
                        }
                    }
                }
                // A genuinely absent parent has nothing to check. Any other
                // failure — transport, protocol, a txid-mismatch guard — must
                // reach the caller, not read as "input not confirmed spent".
                Err(_) if chain.is_tx_unknown(&outpoint.txid)? => {}
                Err(e) => return Err(e),
            }
        }

        Ok((any_confirmed_spent, all_unspent))
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
        funding_shared_with_peer: &dyn Fn(Option<&str>) -> bool,
    ) -> Result<ContractChainState, WalletError> {
        let contract_txid = swapcoin.contract_tx.compute_txid();
        let contract_vout = swapcoin.get_contract_output_vout();

        if chain
            .get_tx_out(&contract_txid, contract_vout, Some(false))?
            .is_some()
        {
            return Ok(ContractChainState::OnChain);
        }

        // The confirmed view has no such output: it was spent, or the
        // contract tx was never broadcast.
        if chain.tx_block_height(&contract_txid)?.is_some() {
            // Classify only a confirmed spend. On Electrum a mempool-spent
            // output looks identical here, and such a spend can be evicted;
            // the backend answers from the script's history instead.
            let outpoint = OutPoint::new(contract_txid, contract_vout);
            let script = &swapcoin.contract_tx.output[contract_vout as usize].script_pubkey;
            if chain.is_confirmed_spend(&outpoint, script)? {
                // The spend may be our own timelock recovery whose bookkeeping
                // was lost to a crash or a failed confirmation wait. Look only at
                // the mined spender: Electrum history can list an unconfirmed
                // conflict, such as a replaced recovery, ahead of it.
                if let Some(recovery) = chain
                    .confirmed_spending_transaction(&outpoint, script)?
                    .filter(|tx| swapcoin.is_own_timelock_spend(tx))
                {
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
                log::info!(
                    "Contract output for {} claimed by a confirmed tx — keeping swapcoin",
                    swap_id
                );
            }
            return Ok(ContractChainState::NotYet);
        }

        // The contract tx is not on-chain. For Taproot it IS the funding tx:
        // if its wallet input is still unspent, the tx was never broadcast
        // and the funds never left.
        let input_outpoint = swapcoin.contract_tx.input[0].previous_output;
        if swapcoin.protocol == crate::protocol::ProtocolVersion::Taproot {
            let input_unspent = chain
                .get_tx_out(&input_outpoint.txid, input_outpoint.vout, Some(true))?
                .is_some();
            if input_unspent {
                log::info!(
                    "Contract tx for {} was never broadcast — wallet UTXOs still unspent, discarding swapcoin",
                    swap_id
                );
                return Ok(ContractChainState::Discarded);
            }
        }

        // Legacy: the contract tx is pre-signed insurance that may never have
        // been broadcast. Push it so the timelock output exists.
        let signed_contract_tx = match swapcoin.create_signed_contract_tx() {
            Ok(tx) => tx,
            Err(e) => {
                // If the contract tx cannot be signed (e.g. missing maker's signature),
                // check if the swapcoin can be safely discarded:
                // 1. Funding transaction inputs were confirmed spent elsewhere, so funding
                //    can never confirm.
                // 2. Funding transaction is unknown to the mempool/chain, all its wallet
                //    inputs are still unspent, it was never shared with the peer, and
                //    the maker never signed our contract.
                //
                // An unknown tx with unspent inputs alone does not prove it was never
                // broadcast: an evicted tx can still confirm from another node's
                // mempool. The missing maker signature does. The taker persists that
                // signature before broadcasting funding (`exchange_legacy`), so a coin
                // the maker never signed was never broadcast by us, and unshared
                // means no peer holds the signed funding tx either.
                let maker_never_signed = swapcoin.others_contract_sig.is_none();
                if let Some(ref funding_tx) = swapcoin.funding_tx {
                    let funding_txid = funding_tx.compute_txid();
                    let funding_confirmed = chain.tx_block_height(&funding_txid)?.is_some();

                    if !funding_confirmed {
                        let (any_confirmed_spent, all_unspent) =
                            Self::check_funding_inputs_state(chain, funding_tx)?;

                        if any_confirmed_spent {
                            log::info!(
                                "Contract tx for {} cannot be signed and funding tx inputs were spent — discarding swapcoin",
                                swap_id
                            );
                            return Ok(ContractChainState::Discarded);
                        }

                        let funding_unknown = chain.is_tx_unknown(&funding_txid)?;
                        if maker_never_signed
                            && funding_unknown
                            && all_unspent
                            && !funding_shared_with_peer(swapcoin.swap_id.as_deref())
                        {
                            log::info!(
                                "Contract tx for {} was never signed by the maker, funding tx is unknown, wallet inputs are unspent, and funding was never shared — discarding swapcoin",
                                swap_id
                            );
                            return Ok(ContractChainState::Discarded);
                        }
                    }
                } else if let Some(input) = swapcoin.contract_tx.input.first() {
                    let input_outpoint = input.previous_output;
                    let parent_tx = match chain.get_raw_transaction(&input_outpoint.txid, None) {
                        Ok(tx) => Some(tx),
                        // A genuinely absent parent has nothing to check here.
                        // Any other failure — transport, protocol, a
                        // txid-mismatch guard — must reach the caller, not
                        // read as "nothing learned about this input".
                        Err(_) if chain.is_tx_unknown(&input_outpoint.txid)? => None,
                        Err(e) => return Err(e),
                    };
                    if let Some(parent_tx) = parent_tx {
                        if parent_tx.compute_txid() == input_outpoint.txid {
                            if let Some(output) = parent_tx.output.get(input_outpoint.vout as usize)
                            {
                                if chain
                                    .is_confirmed_spend(&input_outpoint, &output.script_pubkey)?
                                {
                                    log::info!(
                                        "Contract tx for {} cannot be signed and input outpoint was confirmed spent — discarding swapcoin",
                                        swap_id,
                                    );
                                    return Ok(ContractChainState::Discarded);
                                }
                            }

                            let parent_confirmed =
                                chain.tx_block_height(&input_outpoint.txid)?.is_some();
                            if !parent_confirmed {
                                let (any_confirmed_spent, all_unspent) =
                                    Self::check_funding_inputs_state(chain, &parent_tx)?;

                                if any_confirmed_spent {
                                    log::info!(
                                        "Contract tx for {} cannot be signed and parent tx inputs were spent — discarding swapcoin",
                                        swap_id
                                    );
                                    return Ok(ContractChainState::Discarded);
                                }

                                let parent_unknown = chain.is_tx_unknown(&input_outpoint.txid)?;
                                if maker_never_signed
                                    && parent_unknown
                                    && all_unspent
                                    && !funding_shared_with_peer(swapcoin.swap_id.as_deref())
                                {
                                    log::info!(
                                        "Contract tx for {} was never signed by the maker, parent tx is unknown, wallet inputs are unspent, and funding was never shared — discarding swapcoin",
                                        swap_id
                                    );
                                    return Ok(ContractChainState::Discarded);
                                }
                            }
                        }
                    }
                }

                log::warn!(
                    "Failed to sign contract tx for {}: {:?} — skipping recovery",
                    swap_id,
                    e
                );
                return Ok(ContractChainState::NotYet);
            }
        };
        if let Err(e) = chain.send_raw_transaction(&signed_contract_tx) {
            // Derive the real state from the chain instead of parsing the
            // error: the output showing up (mempool counts) means the tx was
            // already on its way; the input being gone means it never confirms.
            if chain
                .get_tx_out(&contract_txid, contract_vout, Some(true))?
                .is_some()
            {
                return Ok(ContractChainState::OnChain);
            }
            let input_gone = chain
                .get_tx_out(&input_outpoint.txid, input_outpoint.vout, Some(true))?
                .is_none();
            if input_gone {
                // If this coin's funding never left us, nothing can put it
                // on-chain and the insurance is dead weight. A coin with no
                // swap id predates the field, so it counts as shared.
                if !funding_shared_with_peer(swapcoin.swap_id.as_deref()) {
                    return Ok(ContractChainState::Discarded);
                }
                // The peer holds the funding fully signed and can broadcast it
                // at any time. Discard only once it is permanently invalid:
                // every input confirmed spent elsewhere (confirmed view — a
                // mempool spend can still be evicted). No stored funding tx
                // means we cannot prove that, so keep.
                let Some(funding_tx) = &swapcoin.funding_tx else {
                    return Ok(ContractChainState::NotYet);
                };
                for input in &funding_tx.input {
                    let prev = input.previous_output;
                    if chain
                        .get_tx_out(&prev.txid, prev.vout, Some(false))?
                        .is_some()
                    {
                        return Ok(ContractChainState::NotYet);
                    }
                }
                return Ok(ContractChainState::Discarded);
            }
            log::warn!(
                "Failed to broadcast contract tx for {}: {:?} — retrying next cycle",
                swap_id,
                e
            );
            return Ok(ContractChainState::NotYet);
        }
        log::info!(
            "Contract tx {} broadcast successfully",
            signed_contract_tx.compute_txid()
        );
        Ok(ContractChainState::OnChain)
    }

    /// Attempt to recover timelocked outgoing swapcoins.
    ///
    /// The caller supplies the backend connection: the confirmation wait runs
    /// on it with no wallet guard held, so a slow tx cannot wedge the wallet.
    /// Without `swap_scope` every eligible outgoing swapcoin is considered.
    pub fn recover_timelocked_swapcoins(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        swap_scope: Option<&HashSet<String>>,
        funding_shared_with_peer: &dyn Fn(Option<&str>) -> bool,
    ) -> Result<RecoveryOutcome, WalletError> {
        let (refunds, discarded) = Self::broadcast_timelock_recoveries(
            wallet,
            chain,
            shutdown,
            swap_scope,
            funding_shared_with_peer,
            &|_| false,
            &|_| false,
        )?;
        Ok(Self::finish_recoveries(wallet, chain, shutdown, Vec::new(), refunds, discarded)?.1)
    }

    /// Broadcasts every ready timelock refund without waiting on any of them.
    /// Returns the refunds sent and the outgoing swapcoins to discard.
    ///
    /// Feerates come from our own backend: the peer that abandoned the swap
    /// does not get to price our refund.
    ///
    /// `funding_shared_with_peer` answers per coin whether the peer may hold
    /// its funding txs. Unshared funding can never land on-chain, so its
    /// swapcoin is discardable; shared funding is kept until its inputs are
    /// confirmed spent elsewhere.
    ///
    /// `claimed_by_hashlock` names swaps whose incoming coin we claimed. Their
    /// outgoing coins are the first maker's to claim with the preimage, so they
    /// are refunded only once that can provably never happen. `claim_proven`
    /// is the part of those with real evidence of a claim; only such a swap
    /// keeps its preimage when it is refunded.
    fn broadcast_timelock_recoveries(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        swap_scope: Option<&HashSet<String>>,
        funding_shared_with_peer: &dyn Fn(Option<&str>) -> bool,
        claimed_by_hashlock: &dyn Fn(&str) -> bool,
        claim_proven: &dyn Fn(&str) -> bool,
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

            w.sync_and_save(shutdown)?;

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
            if swapcoin.protocol == crate::protocol::ProtocolVersion::Taproot {
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

        for (swap_id, swapcoin, timelock) in to_recover {
            // One failing coin must not hold back the other coins' refunds.
            if let Err(e) = (|| -> Result<(), WalletError> {
                let contract_txid = swapcoin.contract_tx.compute_txid();
                let contract_vout = swapcoin.get_contract_output_vout();
                match Self::ensure_contract_on_chain(
                    chain,
                    &swap_id,
                    &swapcoin,
                    funding_shared_with_peer,
                )? {
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
                    let mut dangling = first_maker_lock.is_some();
                    for hop in hops.iter().filter(|hop| timelock(hop) == first_maker_lock) {
                        let outpoint = hop.contract_outpoint();
                        dangling = match hop.contract_tx.output.get(outpoint.vout as usize) {
                            Some(output) => chain
                                .confirmed_spending_transaction(&outpoint, &output.script_pubkey)?
                                .is_some_and(|tx| hop.is_timelock_spend(&tx)),
                            None => false,
                        };
                        if !dangling {
                            break;
                        }
                    }
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

        let mut incoming = RecoveryOutcome::default();
        for (swap_id, contract_txid, txid) in sweeps {
            log::info!("Sweep transaction {} confirmed", txid);
            w.remove_incoming_swapcoin(&swap_id);
            incoming.resolved.push((contract_txid, txid));
        }

        let mut outgoing = RecoveryOutcome::default();
        for (swap_id, contract_txid, txid) in refunds {
            log::info!("Timelock recovery tx {} confirmed", txid);
            w.remove_outgoing_swapcoin(&swap_id);
            outgoing.resolved.push((contract_txid, txid));
        }
        for id in &discarded {
            if let Some(sc) = w.store.outgoing_swapcoins.get(id) {
                outgoing.discarded.push(sc.contract_tx.compute_txid());
            }
            w.store.outgoing_swapcoins.remove(id);
        }

        if !incoming.is_empty() || !outgoing.is_empty() {
            // The spends are mined and the coins are gone from memory: a failed
            // save must not drop the outcome the caller records.
            if let Err(e) = w.save_to_disk() {
                log::warn!("Failed to persist recovery outcome: {:?}", e);
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
    /// earlier pass (`incoming_claimed`), gets no refund unless it provably dangles.
    pub fn recover_swapcoins(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        contract_txids: &HashSet<Txid>,
        swap_ids: &HashSet<String>,
        funding_shared_with_peer: &dyn Fn(Option<&str>) -> bool,
        incoming_claimed: &dyn Fn(&str) -> bool,
    ) -> Result<(RecoveryOutcome, RecoveryOutcome), WalletError> {
        // A failed sweep step must still let the refunds go out, but with no
        // word on which coins are claimable, each refund must prove it dangles.
        let (sweeps, claiming, sweep_failed) =
            match Self::broadcast_incoming_sweeps(wallet, chain, shutdown, Some(contract_txids)) {
                Ok((sweeps, claiming)) => (sweeps, claiming, false),
                Err(e) => {
                    log::warn!("Incoming sweep failed: {:?}", e);
                    (Vec::new(), HashSet::new(), true)
                }
            };
        let (refunds, discarded) = Self::broadcast_timelock_recoveries(
            wallet,
            chain,
            shutdown,
            Some(swap_ids),
            funding_shared_with_peer,
            &|swap_id| sweep_failed || claiming.contains(swap_id) || incoming_claimed(swap_id),
            // A failed sweep step holds every refund, but proves no claim.
            &|swap_id| claiming.contains(swap_id) || incoming_claimed(swap_id),
        )?;
        Self::finish_recoveries(wallet, chain, shutdown, sweeps, refunds, discarded)
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

    /// Checks if the addresses derived from the wallet descriptor is imported upto the
    /// rolling gap-limit window ([`Wallet::max_watch_index`]).
    /// Returns the list of descriptors not imported yet.
    pub(super) fn get_unimported_wallet_desc(
        &self,
        address_type: AddressType,
    ) -> Result<Vec<String>, WalletError> {
        let mut unimported = Vec::new();
        for (keychain, descriptor) in self.get_wallet_descriptors(address_type)? {
            let first_addr = self
                .blockchain
                .derive_addresses(&descriptor, Some([0, 0]))?[0]
                .clone();

            let last_index = self.max_watch_index(keychain)?;
            let last_addr = self
                .blockchain
                .derive_addresses(&descriptor, Some([last_index, last_index]))?[0]
                .clone();

            let first_addr_imported = self
                .blockchain
                .get_address_info(&first_addr.assume_checked())?
                .is_watchonly
                .unwrap_or(false);
            let last_addr_imported = self
                .blockchain
                .get_address_info(&last_addr.assume_checked())?
                .is_watchonly
                .unwrap_or(false);

            if !first_addr_imported || !last_addr_imported {
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
    /// selection until released, or until the reservation ages out. The
    /// reservation is persisted, so a restart still honours it.
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

    /// `Some(inputs)` frees one funding transaction's inputs once its outcome is
    /// proved; `None` drops the whole swap's reservation. Never release after an
    /// ambiguous broadcast failure: the transaction may still reach the mempool.
    pub(crate) fn release_swap_locks(
        &mut self,
        swap_key: &str,
        inputs: Option<&[OutPoint]>,
    ) -> bool {
        let Some(inputs) = inputs else {
            return self.store.swap_locks.remove(swap_key).is_some();
        };
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

    /// True while an unexpired reservation holds `outpoint`. A committed swap's
    /// reservation outlives the taker's connection on purpose: funding can still
    /// arrive, and reusing its inputs invites a conflicting transaction.
    pub(crate) fn is_swap_reserved(&self, outpoint: &OutPoint) -> bool {
        let now = now_secs();
        self.store.swap_locks.values().any(|locks| {
            locks.outpoints.contains(outpoint)
                && now.saturating_sub(locks.reserved_at) < UNFUNDED_SWAP_LIFETIME.as_secs()
        })
    }

    /// Outpoints still held out of coin selection by a live reservation.
    #[cfg(feature = "integration-test")]
    pub(crate) fn live_reserved_inputs(&self) -> usize {
        let now = now_secs();
        self.store
            .swap_locks
            .values()
            .filter(|l| now.saturating_sub(l.reserved_at) < UNFUNDED_SWAP_LIFETIME.as_secs())
            .map(|l| l.outpoints.len())
            .sum()
    }

    /// Drop reservations past the grace, so an abandoned swap stops holding
    /// liquidity. Returns true when anything was released.
    pub(crate) fn expire_swap_locks(&mut self) -> bool {
        let now = now_secs();
        let before = self.store.swap_locks.len();
        self.store
            .swap_locks
            .retain(|_, l| now.saturating_sub(l.reserved_at) < UNFUNDED_SWAP_LIFETIME.as_secs());
        self.store.swap_locks.len() != before
    }

    /// When this swap's inputs were reserved, if the reservation still exists.
    /// Restart recovery reads it to age the unbroadcast grace from the event,
    /// not from the restart.
    pub(crate) fn reservation_created_at(&self, swap_id: &str) -> Option<u64> {
        self.store.swap_locks.get(swap_id).map(|l| l.reserved_at)
    }

    /// Checks if a UTXO belongs to fidelity bonds, and then returns corresponding UTXOSpendInfo
    fn check_if_fidelity(&self, utxo: &ListUnspentResultEntry) -> Option<UTXOSpendInfo> {
        self.store
            .fidelity_bond
            .iter()
            .enumerate()
            .find_map(|(i, bond)| {
                if bond.script_pub_key() == utxo.script_pub_key && bond.amount == utxo.amount {
                    Some(UTXOSpendInfo::FidelityBondCoin {
                        index: i as u32,
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
    /// Outgoing unfinished: `hash_preimage` is None.
    pub(crate) fn find_unfinished_swapcoins(
        &self,
    ) -> (
        Vec<super::swapcoin::IncomingSwapCoin>,
        Vec<super::swapcoin::OutgoingSwapCoin>,
    ) {
        let unfinished_incomings: Vec<_> =
            self.store.incoming_swapcoins.values().cloned().collect();
        let unfinished_outgoings: Vec<_> = self
            .store
            .outgoing_swapcoins
            .values()
            .filter(|oc| oc.hash_preimage.is_none())
            .cloned()
            .collect();
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

        // A backup carries no hand-out counters, and an emptied address leaves no
        // UTXO to find, so the loop above stops at the first spent-out run. Script
        // history still remembers those addresses, so probe forward on it.
        if self.restore_scan && self.blockchain.is_electrum() {
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
            while empty_run < RESTORE_ADDRESS_GAP && probe <= MAX_WATCH_WINDOW {
                let mut has_history = false;
                for (address_type, account) in &accounts {
                    let script = derive_child_script(account, *address_type, keychain, probe)?;
                    if self.blockchain.script_has_history(&script)? {
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
        let gap = if self.restore_scan {
            RESTORE_ADDRESS_GAP
        } else {
            ADDRESS_IMPORT_COUNT
        };
        Ok(used + gap - 1)
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
                    let mut privkey = self.with_account_key(address_type, |account| {
                        Ok(account
                            .derive_priv(&secp, &DerivationPath::from_str(&path)?)?
                            .private_key)
                    })?;

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
                                &privkey,
                            );
                            let mut sig_serialised = signature.serialize_der().to_vec();
                            sig_serialised.push(EcdsaSighashType::All as u8);
                            input.witness.push(sig_serialised);
                            input.witness.push(pubkey.to_bytes());
                        }
                        AddressType::P2TR => {
                            let mut keypair = Keypair::from_secret_key(&secp, &privkey);

                            // Calculate taproot key-spend sighash using all prevouts
                            let sighash = SighashCache::new(&tx_clone)
                                .taproot_key_spend_signature_hash(
                                    ix,
                                    &Prevouts::All(&prevouts),
                                    TapSighashType::Default,
                                )?;

                            let tweaked_keypair = keypair.tap_tweak(&secp, None);
                            let msg = secp256k1::Message::from(sighash);
                            let signature = secp.sign_schnorr(&msg, &tweaked_keypair.to_keypair());

                            input.witness.push(signature.as_ref());
                            keypair.non_secure_erase();
                        }
                    }
                    privkey.non_secure_erase();
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
                    let privkey = self.get_fidelity_keypair(index)?.secret_key();
                    let redeemscript = self.get_fidelity_reedemscript(index)?;
                    let sighash = SighashCache::new(&tx_clone).p2wsh_signature_hash(
                        ix,
                        &redeemscript,
                        input_value,
                        EcdsaSighashType::All,
                    )?;
                    let sig = secp.sign_ecdsa_low_r(
                        &secp256k1::Message::from_digest_slice(&sighash[..])?,
                        &privkey,
                    );

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
        let (sweeps, _) = Self::broadcast_incoming_sweeps(wallet, chain, shutdown, contract_txids)?;
        Ok(Self::finish_recoveries(wallet, chain, shutdown, sweeps, Vec::new(), Vec::new())?.0)
    }

    /// Broadcasts every ready incoming sweep without waiting on any of them, and
    /// returns the sweeps sent. A contract still in the mempool waits for a later pass.
    /// Also returns the swaps being claimed: those whose incoming contract is on
    /// chain, whether or not their sweep went out in this pass.
    /// A PaySwap coin pays the receiver an exact amount, so its fee is whatever
    /// the input leaves over; every other coin sweeps at its negotiated feerate.
    fn broadcast_incoming_sweeps(
        wallet: &std::sync::RwLock<Wallet>,
        chain: &AnyBlockchain,
        shutdown: &std::sync::atomic::AtomicBool,
        contract_txids: Option<&HashSet<Txid>>,
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

            w.sync_and_save(shutdown)?;

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
    if required_confirms == 0 || txids.is_empty() {
        return Ok(0);
    }

    log::info!(
        "Waiting for {} confirmation(s) on {} transaction(s)...",
        required_confirms,
        txids.len()
    );

    const SYNC_INTERVAL_SECS: u64 = 10;

    let started = Instant::now();
    let mut unseen: HashSet<Txid> = txids.iter().copied().collect();
    let mut vanished_at: HashMap<Txid, Instant> = HashMap::new();

    loop {
        if shutdown.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
            return Err(WalletError::Interrupted("Shutdown requested"));
        }
        if abort_check.is_some_and(|f| f()) {
            return Err(WalletError::Interrupted("Abort requested"));
        }
        if started.elapsed() > TX_CONFIRMATION_TIMEOUT {
            log::error!(
                "Tx(s) did not confirm within {}s",
                TX_CONFIRMATION_TIMEOUT.as_secs()
            );
            return Err(WalletError::TxConfirmationTimeout(
                "Tx did not confirm before the confirmation deadline".to_string(),
            ));
        }

        let mut all_confirmed = true;
        let mut max_confirm_height: u32 = 0;

        for txid in txids {
            match blockchain.get_raw_transaction_info(txid, None) {
                Ok(tx_info) => {
                    let confirms: u32 = tx_info.confirmations.unwrap_or(0);
                    // First sighting gets a line: the eviction window anchors
                    // to it, and tests time a replacement off it.
                    if unseen.remove(txid) && confirms < required_confirms {
                        log::info!(
                            "Tx {txid} seen in mempool, waiting for {required_confirms} confirmation(s)"
                        );
                    }
                    if confirms < required_confirms {
                        log::debug!(
                            "Tx {} has {} confirmations (need {})",
                            txid,
                            confirms,
                            required_confirms
                        );
                        all_confirmed = false;
                    } else {
                        // QA: Ask the backend for the mined height directly;
                        // tip-height arithmetic can race with a newly mined block.
                        let confirm_height = blockchain.tx_block_height(txid)?.ok_or_else(|| {
                            WalletError::General(format!(
                                "Confirmed transaction {txid} has no block height"
                            ))
                        })? as u32;
                        max_confirm_height = max_confirm_height.max(confirm_height);
                    }
                }
                Err(e) => {
                    log::debug!("Error getting tx info for {}: {:?}", txid, e);
                    // A seen tx that vanishes (mempool eviction) gets one window to
                    // reappear. Re-sighting never clears the window, so a tx
                    // flapping in and out of the mempool still trips the bound.
                    if !unseen.contains(txid)
                        && vanished_at
                            .entry(*txid)
                            .or_insert_with(Instant::now)
                            .elapsed()
                            > arrival_timeout
                    {
                        return Err(WalletError::TxConfirmationTimeout(
                            "Tx vanished from our mempool and did not reappear".to_string(),
                        ));
                    }
                    all_confirmed = false;
                }
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
            let mut missing: Vec<Txid> = unseen.iter().copied().collect();
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
            return Ok(max_confirm_height);
        }

        log::info!("Next sync in {} secs", SYNC_INTERVAL_SECS);

        // Sleep in 1-second increments so we can check shutdown/abort.
        for _ in 0..SYNC_INTERVAL_SECS {
            if shutdown.is_some_and(|s| s.load(std::sync::atomic::Ordering::Relaxed)) {
                return Err(WalletError::Interrupted("Shutdown requested"));
            }
            if abort_check.is_some_and(|f| f()) {
                return Err(WalletError::Interrupted("Abort requested"));
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
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
        self.save_to_disk()?;
        self.restore_scan = false;
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
            if window.0.max(window.1) > MAX_WATCH_WINDOW {
                return Err(WalletError::General(format!(
                    "Watch window {window:?} exceeds cap {MAX_WATCH_WINDOW}"
                )));
            }
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

        if descriptors_to_import.is_empty() && !self.restore_scan {
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
        if self.restore_scan && descriptors_to_import.is_empty() {
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
                Err(WalletError::Interrupted(reason)) => {
                    return Err(WalletError::Interrupted(reason));
                }
                Err(e) => log::error!("Blockchain sync failed. Retrying. | {e:?}"),
            }
            Self::wait_for_shutdown(shutdown, HEART_BEAT_INTERVAL)?;
        }
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
        let master_key = Xpriv::new_master(bitcoin::Network::Regtest, &[42; 32]).unwrap();
        let enc_material =
            KeyMaterial::new_from_password(Some("test-password".to_string())).unwrap();
        let store = WalletStore::init(
            "prevout-contract-test".to_string(),
            path,
            bitcoin::Network::Regtest,
            master_key,
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
            new_mnemonic: None,
            locked_utxos: HashSet::new(),
            restore_scan: false,
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
    fn a_reservation_stops_holding_inputs_once_it_ages_out() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet.cbor"));
        let reserved = outpoint(3);
        wallet.reserve_swap_locks("swap-2", &[reserved]);

        // Backdate past the grace: an abandoned swap must stop holding liquidity.
        wallet
            .store
            .swap_locks
            .get_mut("swap-2")
            .unwrap()
            .reserved_at -= UNFUNDED_SWAP_LIFETIME.as_secs() + 1;

        assert!(!wallet.is_swap_reserved(&reserved));
        assert!(wallet.expire_swap_locks());
        assert!(wallet.store.swap_locks.is_empty());
        assert!(!wallet.expire_swap_locks(), "expiry must be idempotent");
    }
}

#[cfg(test)]
mod prevout_contract_tests {
    use super::{test_support::test_wallet, *};
    use bitcoind::tempfile::tempdir;

    #[test]
    fn new_mnemonic_is_yielded_once_then_dropped() {
        const TEST_PHRASE: &str = "abandon abandon abandon abandon abandon abandon \
                                   abandon abandon abandon abandon abandon about";

        let temp_dir = tempdir().unwrap();
        let mut wallet = test_wallet(&temp_dir.path().join("wallet.cbor"));
        wallet.new_mnemonic = Some(SecretMnemonic(Mnemonic::parse(TEST_PHRASE).unwrap()));

        assert_eq!(
            wallet.take_new_mnemonic().map(|m| m.words()).as_deref(),
            Some(TEST_PHRASE)
        );
        assert!(
            wallet.take_new_mnemonic().is_none(),
            "the phrase must be dropped from the wallet after the first take"
        );
    }

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
    use crate::wallet::blockchain::Electrum;
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

        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(stream) = incoming else { continue };
                // Each probe is one tiny request/reply, so Nagle would add its
                // delay to every single one of them.
                let _ = stream.set_nodelay(true);
                let (hash, header) = (genesis_hash.clone(), header_hex.clone());
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
                                    json!([{"height": 1, "tx_hash": Txid::all_zeros().to_string()}])
                                } else {
                                    json!([])
                                }
                            }
                            "blockchain.scripthash.listunspent" => json!([]),
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

    fn account_for(address_type: AddressType) -> Xpub {
        let secp = crate::utill::global_secp();
        let master = Xpriv::new_master(bitcoin::Network::Regtest, &MASTER_SEED).unwrap();
        let account = master
            .derive_priv(
                secp,
                &Wallet::get_derivation_path(address_type, bitcoin::Network::Regtest),
            )
            .unwrap();
        Xpub::from_priv(secp, &account)
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
            &enc_material,
        )
        .unwrap();
        let electrum = Electrum::new(&crate::wallet::ElectrumConfig {
            url,
            ..Default::default()
        })
        .expect("connect to stub");

        Wallet {
            blockchain: AnyBlockchain::Electrum(electrum),
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            new_mnemonic: None,
            locked_utxos: HashSet::new(),
            restore_scan: true,
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
            let account = account_for(address_type);
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

        // Without the restore flag the probe is off and the empty UTXO set decides.
        wallet.restore_scan = false;
        assert_eq!(wallet.find_hd_next_index(external).unwrap(), 0);
    }

    #[test]
    fn interrupted_restore_finishes_before_wallet_is_loaded() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("restore-probe-test");
        let script = derive_child_script(
            &account_for(AddressType::P2TR),
            AddressType::P2TR,
            KeychainKind::External,
            60,
        )
        .unwrap();
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
            &material,
        )
        .unwrap();

        let backend = AnyBlockchain::Electrum(
            Electrum::new(&crate::wallet::ElectrumConfig {
                url,
                ..Default::default()
            })
            .unwrap(),
        );
        let wallet = Wallet::load_or_init(&path, backend, Some(password.clone())).unwrap();
        assert_eq!(wallet.store.external_index, 61);
        assert!(!wallet.restore_scan);

        let (saved, _) = WalletStore::read_from_disk(&path, Some(password)).unwrap();
        assert_eq!(saved.external_index, 61);
        assert!(saved.last_synced_height.is_some());
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
        wallet::{blockchain::Electrum, swapcoin::OutgoingSwapCoin},
    };
    use bitcoin::{
        consensus::encode::serialize_hex, hashes::Hash, locktime::absolute::LockTime, BlockHash,
        TxIn,
    };
    use bitcoind::tempfile::tempdir;
    use std::{
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
        sync::{atomic::AtomicBool, Arc, RwLock},
    };

    const CONTRACT_HEIGHT: i64 = 5;
    const RECOVERY_HEIGHT: i64 = 6;
    const TIP: i64 = 10;
    const PASSWORD: &str = "test-password";

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
        let coin = OutgoingSwapCoin::new_legacy(
            key(1),
            pubkey(4),
            contract_tx,
            redeemscript,
            key(3),
            Amount::from_sat(50_000),
            1,
        );
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
            &enc_material,
        )
        .unwrap();
        Wallet {
            blockchain,
            wallet_file_path: path.to_path_buf(),
            store,
            store_enc_material: enc_material,
            new_mnemonic: None,
            locked_utxos: HashSet::new(),
            restore_scan: false,
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
        let state =
            Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin, &|_| true).unwrap();
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
        let state =
            Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin, &|_| true).unwrap();
        assert_eq!(state, ContractChainState::NotYet);
    }

    /// A Taproot outgoing swapcoin whose contract output commits to both
    /// leaves, and our own signed timelock recovery of it.
    fn taproot_coin_and_recovery() -> (OutgoingSwapCoin, Transaction) {
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
        let state =
            Wallet::ensure_contract_on_chain(&electrum(&url), "swap", &coin, &|_| true).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }

    /// Hand-rolled Bitcoin Core JSON-RPC over HTTP: the contract is mined at
    /// `CONTRACT_HEIGHT`, our recovery at `RECOVERY_HEIGHT`, and the contract
    /// output is spent. Only the calls classification makes are answered.
    fn start_core_stub(contract: Transaction, recovery: Transaction) -> String {
        use std::io::Read;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub");
        let addr = listener.local_addr().unwrap().to_string();
        let header = bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header;
        let block_hash = |height: i64| BlockHash::from_byte_array([height as u8; 32]);
        let mined = Arc::new(HashMap::from([
            (contract.compute_txid(), (contract.clone(), CONTRACT_HEIGHT)),
            (recovery.compute_txid(), (recovery.clone(), RECOVERY_HEIGHT)),
        ]));

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
                // The contract output is spent, and not from the mempool.
                "gettxout" => Value::Null,
                "gettxspendingprevout" => {
                    json!([{"txid": params[0][0]["txid"], "vout": params[0][0]["vout"]}])
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

    #[test]
    fn core_classifies_our_confirmed_recovery_as_recovered() {
        let (coin, recovery) = legacy_coin_and_recovery();
        let url = start_core_stub(coin.contract_tx.clone(), recovery.clone());
        let core = AnyBlockchain::CoreRPC(
            crate::wallet::CoreRPC::new(&crate::wallet::CoreRpcConfig {
                url,
                ..Default::default()
            })
            .unwrap(),
        );
        let state = Wallet::ensure_contract_on_chain(&core, "swap", &coin, &|_| true).unwrap();
        assert_eq!(
            state,
            ContractChainState::RecoveredByTimelock(recovery.compute_txid())
        );
    }
}

/// An incoming contract still in the mempool is swept on a later pass, and its
/// swap's refund waits meanwhile.
#[cfg(test)]
mod mempool_deferral_tests {
    use super::{
        timelock_reconcile_tests::{
            electrum, key, pubkey, scripthash, shutdown_after, stub_wallet, tx,
        },
        *,
    };
    use crate::{
        protocol::contract::{create_contract_redeemscript, Hash160},
        wallet::swapcoin::{IncomingSwapCoin, OutgoingSwapCoin},
    };
    use bitcoin::{
        consensus::encode::{deserialize_hex, serialize_hex},
        hashes::Hash,
    };
    use bitcoind::tempfile::tempdir;
    use std::{
        io::{BufRead, BufReader, Write as IoWrite},
        net::TcpListener,
        sync::{Arc, Mutex, RwLock},
    };

    const TIP: i64 = 100;
    /// Leaves the outgoing contract's 20-block CSV matured at `TIP`.
    const OUTGOING_HEIGHT: i64 = 50;
    const SWAP: &str = "swap";

    /// What the stub server knows. A height of `0` is the mempool.
    #[derive(Default)]
    struct StubChain {
        txs: HashMap<Txid, (Transaction, i64)>,
        broadcast: Vec<Txid>,
    }

    impl StubChain {
        fn with(txs: &[(&Transaction, i64)]) -> Arc<Mutex<Self>> {
            Arc::new(Mutex::new(StubChain {
                txs: txs
                    .iter()
                    .map(|(tx, height)| (tx.compute_txid(), ((*tx).clone(), *height)))
                    .collect(),
                broadcast: Vec::new(),
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
                            "blockchain.estimatefee" => json!(0.00001),
                            "blockchain.scripthash.get_history" => chain.history(param),
                            "blockchain.scripthash.listunspent" => chain.unspent(param),
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
            Wallet::broadcast_incoming_sweeps(&wallet, &backend, &shutdown, None).unwrap();
        assert!(sweeps.is_empty());
        assert_eq!(claiming, HashSet::from([SWAP.to_string()]));
        assert!(chain.lock().unwrap().broadcast.is_empty());

        chain.lock().unwrap().txs.get_mut(&contract_txid).unwrap().1 = TIP;
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
    use super::*;
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
        sc.funding_tx = funding_tx;
        sc.others_contract_sig = None;
        sc
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
                let res =
                    Wallet::ensure_contract_on_chain(&blockchain, "swap-spent", &sc, &|_| false)
                        .unwrap();
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
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends(
            vec![(parent_tx, Some(10), false), (spending_tx, Some(11), true)],
            |blockchain| {
                let res = Wallet::ensure_contract_on_chain(
                    &blockchain,
                    "swap-no-funding-spent",
                    &sc,
                    &|_| false,
                )
                .unwrap();
                assert_eq!(res, ContractChainState::Discarded);
            },
        );
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_unspent_wallet_inputs_and_unshared_funding_is_discarded(
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
                Wallet::ensure_contract_on_chain(&blockchain, "swap-unspent", &sc, &|_| false)
                    .unwrap();
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
                Wallet::ensure_contract_on_chain(&blockchain, "swap-unspent-shared", &sc, &|_| {
                    true
                })
                .unwrap();
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
                Wallet::ensure_contract_on_chain(&blockchain, "swap-maker-signed", &sc, &|_| false)
                    .unwrap();
            assert_eq!(res, ContractChainState::NotYet);
        });
    }

    #[test]
    fn test_ensure_contract_unsigned_legacy_with_no_funding_tx_and_no_onchain_input_is_not_yet() {
        let sc = make_legacy_outgoing_swapcoin(None);
        for_both_backends(vec![], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-no-input", &sc, &|_| false)
                    .unwrap();
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
                let res = Wallet::ensure_contract_on_chain(
                    &blockchain,
                    "swap-mempool-funding",
                    &sc,
                    &|_| false,
                )
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
        sc.funding_tx = None;
        sc.others_contract_sig = None;

        for_both_backends(vec![(parent_tx, None, true)], |blockchain| {
            let res =
                Wallet::ensure_contract_on_chain(&blockchain, "swap-mempool-parent", &sc, &|_| {
                    false
                })
                .unwrap();
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
                let res =
                    Wallet::ensure_contract_on_chain(&blockchain, "swap-mismatched", &sc, &|_| {
                        false
                    });
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
                    &|_| false,
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
