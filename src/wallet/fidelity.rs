use crate::{
    protocol::common_messages::FidelityProof,
    utill::redeemscript_to_scriptpubkey,
    wallet::{infer_address_type, AddressType, Blockchain, Wallet},
    watch_tower::utils::{extract_op_return_data, parse_fidelity_op_return},
};
use bitcoin::{
    absolute::{Height, LockTime, Time},
    bip32::{ChildNumber, DerivationPath},
    consensus::encode::{serialize, VarInt},
    hashes::{sha256d, Hash},
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV},
    script::{Builder, Instruction},
    secp256k1::{Keypair, Message, Secp256k1},
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Transaction, Txid,
};
use bitcoind::bitcoincore_rpc::json::GetTransactionResultDetailCategory;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    convert::TryFrom,
    str::FromStr,
    time::{SystemTime, UNIX_EPOCH},
};

use super::{Destination, WalletError};

// To (strongly) disincentivize Sybil behavior, the value assessment of the bond
// is based on the (time value of the bond)^x here x is the bond_value_exponent,
// where x > 1.
const BOND_VALUE_EXPONENT: f64 = 1.3;

// Interest rate used when calculating the value of fidelity bonds created
// by locking bitcoins in timelocked addresses
// See also:
// https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#determining-interest-rate-r
// Set as a real number, i.e. 1 = 100% and 0.01 = 1%
const BOND_VALUE_INTEREST_RATE: f64 = 0.015;

/// Constant representing the derivation path for fidelity addresses.
const FIDELITY_DERIVATION_PATH: &str = "m/175'/2";
// Fidelity Bond relative timelock in number of blocks ( 1 block ~= 10mins)
// Must be between 12,960 (≈3 months) and 25,920 (≈6 months)
#[cfg(not(feature = "integration-test"))]
pub const MIN_FIDELITY_TIMELOCK: u32 = 12_960; // 3 months
#[cfg(not(feature = "integration-test"))]
pub const MAX_FIDELITY_TIMELOCK: u32 = 25_920; // 6 months

// Shorter for tests
#[cfg(feature = "integration-test")]
pub const MIN_FIDELITY_TIMELOCK: u32 = 800;
#[cfg(feature = "integration-test")]
pub const MAX_FIDELITY_TIMELOCK: u32 = 6_000;

/// Smallest bond amount in satoshis that a maker may lock, and that discovery
/// will announce. This is the raw locked amount, not the time-weighted value
/// `calculate_fidelity_value` computes; it exists to keep cheap bonds from
/// spamming taker registries. Makers and takers must agree on it: a maker
/// below this floor funds a valid bond that no taker ever discovers.
pub const MIN_FIDELITY_BOND_AMOUNT_SATS: u64 = 10_000;

/// Error structure defining possible fidelity related errors
#[derive(Debug)]
pub enum FidelityError {
    WrongScriptType,
    BondDoesNotExist,
    BondAlreadyRedeemed,
    BondLocktimeExpired,
    InvalidCertHash,
    /// The certificate is not signed by the bond key.
    InvalidCertSignature,
    General(String),
    InvalidBondLocktime,
    BondUncomfirmed,
    /// The bond key does not derive from the offer's tweak point, so the proof
    /// belongs to someone else.
    BondPubkeyMismatch,
    /// The signed bond amount is not what the chain output locks.
    BondAmountMismatch {
        claimed: Amount,
        actual: Amount,
    },
    /// The bond's funding transaction was evicted from the network and the
    /// wallet holds no stored raw transaction to rebroadcast, so the bond
    /// can never be recovered by this maker.
    BondTransactionMissing {
        index: u32,
    },
    /// The configured bond amount is below `MIN_FIDELITY_BOND_AMOUNT_SATS`, so
    /// the bond would fund but never be discovered by any taker.
    BondAmountTooLow {
        configured: u64,
        minimum: u64,
    },
}

impl std::fmt::Display for FidelityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FidelityError::WrongScriptType => write!(f, "Wrong script type for fidelity bond"),
            FidelityError::BondDoesNotExist => write!(f, "Fidelity bond does not exist"),
            FidelityError::BondAlreadyRedeemed => {
                write!(f, "Fidelity bond has already been redeemed")
            }
            FidelityError::BondLocktimeExpired => write!(f, "Fidelity bond locktime has expired"),
            FidelityError::InvalidCertHash => write!(f, "Invalid fidelity certificate hash"),
            FidelityError::InvalidCertSignature => {
                write!(f, "Fidelity certificate is not signed by the bond key")
            }
            FidelityError::InvalidBondLocktime => {
                write!(f, "Fidelity bond locktime is outside the acceptable range")
            }
            FidelityError::BondUncomfirmed => write!(f, "Fidelity bond transaction is unconfirmed"),
            FidelityError::BondPubkeyMismatch => {
                write!(f, "Fidelity bond does not correspond to the provided tweak point")
            }
            FidelityError::BondAmountMismatch { claimed, actual } => {
                write!(f, "Bond amount mismatch: claimed {claimed}, actual {actual}")
            }
            FidelityError::BondTransactionMissing { index } => write!(
                f,
                "fidelity bond at index {index} was evicted and has no stored transaction to rebroadcast"
            ),
            FidelityError::BondAmountTooLow {
                configured,
                minimum,
            } => write!(
                f,
                "Fidelity bond amount {configured} sats is below the minimum of {minimum} sats; \
                 takers would never discover it"
            ),
            FidelityError::General(msg) => write!(f, "{}", msg),
        }
    }
}

impl std::error::Error for FidelityError {}

// ------- Fidelity Helper Scripts -------------
#[allow(rustdoc::invalid_html_tags)]
/// Create a Fidelity Timelocked redeemscript.
/// Redeem script used
/// Old script: <locktime> <OP_CLTV> <OP_DROP> <pubkey> <OP_CHECKSIG>
/// The new script drops the extra byte <OP_DROP>
/// New script: <pubkey> <OP_CHECKSIGVERIFY> <locktime> <OP_CLTV>
fn fidelity_redeemscript(lock_time: &LockTime, pubkey: &PublicKey) -> ScriptBuf {
    Builder::new()
        .push_key(pubkey)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_lock_time(*lock_time)
        .push_opcode(OP_CLTV)
        .into_script()
}

/// Verifies a fidelity bond by checking timelock validity,
/// certificate integrity, redeem script existence, and ECDSA signature correctness.
pub(crate) fn verify_fidelity_checks(
    proof: &FidelityProof,
    addr: &str,
    tx: Transaction,
    current_height: u64,
    confirmation_height: u32,
    tweakable_point: &PublicKey,
    tweak_chain_code: &bitcoin::bip32::ChainCode,
) -> Result<(), WalletError> {
    // Every height here is the one our own backend reported, so the maker's
    // claimed `conf_height` is never read and never needs checking.

    // Ensure fidelity bond timelock lies within allowed range
    let bond_height = proof
        .bond
        .lock_time
        .to_consensus_u32()
        .checked_sub(confirmation_height)
        .ok_or(FidelityError::InvalidBondLocktime)?;
    if !(MIN_FIDELITY_TIMELOCK..=MAX_FIDELITY_TIMELOCK).contains(&bond_height) {
        log::warn!(
            "Invalid fidelity bond timelock: {} blocks. Accepted range is [{}-{}] blocks.",
            bond_height,
            MIN_FIDELITY_TIMELOCK,
            MAX_FIDELITY_TIMELOCK
        );
        return Err(FidelityError::InvalidBondLocktime.into());
    }

    // Check if bond lock time has expired
    let lock_time = LockTime::from_height(current_height as u32)?;
    if lock_time > proof.bond.lock_time {
        return Err(FidelityError::BondLocktimeExpired.into());
    }

    // Verify certificate hash
    let expected_cert_hash = proof.bond.generate_cert_hash(addr, tweakable_point);
    if proof.cert_hash != expected_cert_hash {
        return Err(FidelityError::InvalidCertHash.into());
    }

    // Verify fidelity pubkey derivation from tweak key.
    // Only public_key and chain_code are used in BIP32 derivation;
    // network, depth, parent_fingerprint, child_number are metadata only.
    let offer_xpub = bitcoin::bip32::Xpub {
        network: bitcoin::NetworkKind::Main,
        depth: 1,
        parent_fingerprint: Default::default(),
        child_number: ChildNumber::Hardened { index: 0 },
        public_key: tweakable_point.inner,
        chain_code: *tweak_chain_code,
    };
    let secp = Secp256k1::new();
    let derived = offer_xpub.derive_pub(
        &secp,
        &[
            ChildNumber::Normal { index: 2 },
            ChildNumber::Normal {
                index: proof.bond.bond_index,
            },
        ],
    )?;
    if derived.public_key != proof.bond.pubkey.inner {
        return Err(FidelityError::BondPubkeyMismatch.into());
    }

    // Validate redeem script and corresponding output scriptPubKey
    let fidelity_redeem_script = fidelity_redeemscript(&proof.bond.lock_time, &proof.bond.pubkey);
    let derived_script_pubkey = redeemscript_to_scriptpubkey(&fidelity_redeem_script)?;
    let tx_out = tx
        .tx_out(proof.bond.outpoint.vout as usize)
        .map_err(|_| FidelityError::BondDoesNotExist)?;

    if tx_out.script_pubkey != derived_script_pubkey {
        return Err(WalletError::Fidelity(FidelityError::BondDoesNotExist));
    }
    // QA: A maker could advertise a larger bond amount than the output actually
    // locks, inflating its fidelity value and offer ranking. Bind the signed
    // proof amount to the real chain output before accepting the bond.
    if tx_out.value != proof.bond.amount {
        return Err(FidelityError::BondAmountMismatch {
            claimed: proof.bond.amount,
            actual: tx_out.value,
        }
        .into());
    }

    // Verify ECDSA signature
    let cert_message = Message::from_digest_slice(proof.cert_hash.as_byte_array())?;
    secp.verify_ecdsa(&cert_message, &proof.cert_sig, &proof.bond.pubkey.inner)
        .map_err(|_| FidelityError::InvalidCertSignature)?;

    Ok(())
}

#[allow(unused)]
/// Reads the locktime from a fidelity redeemscript.
fn read_locktime_from_fidelity_script(redeemscript: &ScriptBuf) -> Result<LockTime, FidelityError> {
    if let Some(Ok(Instruction::PushBytes(locktime_bytes))) = redeemscript.instructions().nth(2) {
        let mut u4slice: [u8; 4] = [0; 4];
        u4slice[..locktime_bytes.len()].copy_from_slice(locktime_bytes.as_bytes());
        Ok(LockTime::from_consensus(u32::from_le_bytes(u4slice)))
    } else {
        Err(FidelityError::WrongScriptType)
    }
}

#[allow(unused)]
/// Reads the public key from a fidelity redeemscript.
fn read_pubkey_from_fidelity_script(redeemscript: &ScriptBuf) -> Result<PublicKey, FidelityError> {
    if let Some(Ok(Instruction::PushBytes(pubkey_bytes))) = redeemscript.instructions().next() {
        Ok(PublicKey::from_slice(pubkey_bytes.as_bytes())
            .map_err(|e| FidelityError::General(e.to_string()))?)
    } else {
        Err(FidelityError::WrongScriptType)
    }
}

/// Calculates the theoretical fidelity bond value. Refer [The OG Fidelity Bond Paper by Chris Belcher.]<https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#financial-mathematics-of-joinmarket-fidelity-bonds>
fn calculate_fidelity_value(
    value: Amount,          // Bond amount in sats
    locktime: u64,          // Bond locktime timestamp
    confirmation_time: u64, // Confirmation timestamp
    current_time: u64,      // Current timestamp
) -> Amount {
    let sec_in_a_year: f64 = 60.0 * 60.0 * 24.0 * 365.2425; // Gregorian calender year length

    let interest_rate = BOND_VALUE_INTEREST_RATE;
    let lock_period_yr = ((locktime - confirmation_time) as f64) / sec_in_a_year;
    let locktime_yr = (locktime as f64) / sec_in_a_year;
    let currenttime_yr = (current_time as f64) / sec_in_a_year;

    let exp_rt_m1 = f64::exp_m1(interest_rate * lock_period_yr);
    let exp_rtl_m1 = f64::exp_m1(interest_rate * f64::max(0.0, currenttime_yr - locktime_yr));

    let timevalue = f64::max(0.0, f64::min(1.0, exp_rt_m1) - f64::min(1.0, exp_rtl_m1));

    Amount::from_sat(((value.to_sat() as f64) * timevalue).powf(BOND_VALUE_EXPONENT) as u64)
}

/// Structure describing a Fidelity Bond.
/// Fidelity Bonds are described here : <https://github.com/JoinMarket-Org/joinmarket-clientserver/blob/master/docs/fidelity-bonds.md>
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, PartialOrd, Hash)]
pub struct FidelityBond {
    pub(crate) outpoint: OutPoint,
    /// Fidelity Amount
    pub amount: Amount,
    /// Fidelity Locktime
    pub lock_time: LockTime,
    pub(crate) pubkey: PublicKey,
    // Height at which the bond was confirmed.
    pub(crate) conf_height: Option<u32>,
    /// Whether this bond is spent or not.
    pub(crate) is_spent: bool,
    /// The child index used in the HD derivation path `m/175'/2/<bond_index>`.
    /// Note: Fidelity bonds must only be appended to the store; they should never be removed or reordered.
    pub bond_index: u32,
    /// The raw bond transaction, kept only until confirmation so an evicted
    /// broadcast can be re-sent as-is. Rebroadcasting the identical bytes
    /// reproduces the same txid, so no replacement spending different coins
    /// can ever confirm alongside the original and double-lock funds.
    #[serde(default)]
    pub(crate) tx: Option<Transaction>,
}

impl FidelityBond {
    /// The UTXO outpoint backing this bond.
    pub fn outpoint(&self) -> OutPoint {
        self.outpoint
    }

    /// Whether the fidelity bond is spent or not
    pub fn is_spent(&self) -> bool {
        self.is_spent
    }
    /// get the reedemscript for this bond
    pub(crate) fn redeem_script(&self) -> ScriptBuf {
        fidelity_redeemscript(&self.lock_time, &self.pubkey)
    }

    /// Get the script_pubkey for this bond.
    pub(crate) fn script_pub_key(&self) -> ScriptBuf {
        redeemscript_to_scriptpubkey(&self.redeem_script()).expect("This can never panic as fidelity redeemscript template is hardcoded in a private function.")
    }

    /// Generate the bond's certificate hash.
    pub(crate) fn generate_cert_hash(
        &self,
        addr: &str,
        tweakable_point: &PublicKey,
    ) -> sha256d::Hash {
        let cert_msg_str = format!(
            "fidelity-bond-cert|{}|{}|{}|{}|{}|{}",
            self.outpoint, self.pubkey, self.lock_time, self.amount, addr, tweakable_point
        );
        let cert_msg = cert_msg_str.as_bytes();
        let mut btc_signed_msg = Vec::<u8>::new();
        btc_signed_msg.extend("\x18Bitcoin Signed Message:\n".as_bytes());
        btc_signed_msg.extend(serialize(&VarInt(cert_msg.len() as u64)));
        btc_signed_msg.extend(cert_msg);

        sha256d::Hash::hash(&btc_signed_msg)
    }

    /// Ensure this bond's funding transaction is visible to the network,
    /// returning its txid.
    ///
    /// If the original broadcast is still in the mempool or already confirmed,
    /// its txid is returned unchanged. Otherwise the transaction was evicted
    /// (e.g. while the maker was offline) and waiting for it would never
    /// succeed: the raw transaction stored at creation is rebroadcast, which
    /// reproduces the same txid, so the bond keeps its original outpoint and
    /// no replacement spending different coins can double-lock funds.
    pub fn ensure_broadcast(&self, chain: &impl Blockchain) -> Result<Txid, WalletError> {
        // Only a proven "unknown transaction" answer means eviction; any
        // other backend failure surfaces as an error instead of triggering
        // a spurious rebroadcast.
        if !chain.is_tx_unknown(&self.outpoint.txid)? {
            return Ok(self.outpoint.txid);
        }

        log::warn!(
            "Fidelity bond tx {} is not visible to the backend (evicted from mempool?); rebroadcasting",
            self.outpoint.txid
        );

        let tx = self
            .tx
            .as_ref()
            .ok_or(FidelityError::BondTransactionMissing {
                index: self.bond_index,
            })?;
        // The stored tx is this bond's, so its txid is known: the backend's
        // answer is never trusted to name what we wait on.
        chain.send_raw_transaction(tx)?;
        Ok(self.outpoint.txid)
    }
}

// Wallet APIs related to fidelity bonds.
impl Wallet {
    /// Get a reference to the fidelity bond store
    pub fn get_fidelity_bonds(&self) -> &Vec<FidelityBond> {
        &self.store.fidelity_bond
    }

    /// Display the fidelity bonds
    pub fn display_fidelity_bonds(&self) -> Result<String, WalletError> {
        // Only a live bond needs a valuation, so the tip is fetched on the
        // first one that does. An empty or all-spent list makes no chain call.
        let mut tip = None;
        let serialized = self
            .store
            .fidelity_bond
            .iter()
            .map(|bond| -> Result<serde_json::Value, WalletError> {
                let mut bond_info = serde_json::json!({
                        "index": bond.bond_index,
                        "outpoint": bond.outpoint.to_string(),
                        "amount": bond.amount.to_sat(),
                        "status": if bond.is_spent {"Redeemed"} else {"Live"}
                });

                if !bond.is_spent {
                    let (tip_height, tip_time) = match tip {
                        Some(t) => t,
                        None => {
                            let t = self.chain_tip()?;
                            tip = Some(t);
                            t
                        }
                    };
                    let bond_value = self.calculate_bond_value(bond, tip_height, tip_time)?;
                    bond_info["bond_value"] = serde_json::json!(bond_value);
                }

                Ok(bond_info)
            })
            .collect::<Result<Vec<serde_json::Value>, _>>()?;

        serde_json::to_string_pretty(&serialized).map_err(|e| WalletError::General(e.to_string()))
    }

    /// Whether a confirmed, unspent bond is still locked at the tip. Read from
    /// the bond records, so a failed valuation never reads as no live bond.
    pub(crate) fn has_live_fidelity_bond(&self) -> Result<bool, WalletError> {
        let mut confirmed = self
            .store
            .fidelity_bond
            .iter()
            .filter(|bond| !bond.is_spent && bond.conf_height.is_some())
            .peekable();
        if confirmed.peek().is_none() {
            return Ok(false);
        }
        let (tip_height, tip_time) = self.chain_tip()?;
        let out_of_range = |what| WalletError::General(format!("tip {what} is out of range"));
        let height =
            Height::from_consensus(u32::try_from(tip_height).map_err(|_| out_of_range("height"))?)?;
        let time =
            Time::from_consensus(u32::try_from(tip_time).map_err(|_| out_of_range("time"))?)?;
        Ok(confirmed.any(|bond| !bond.lock_time.is_satisfied_by(height, time)))
    }

    /// Get the highest value fidelity bond. Returns None, if no bond exists.
    pub fn get_highest_fidelity_index(&self) -> Result<Option<u32>, WalletError> {
        // No live bond means no valuation and no chain calls.
        if self.store.fidelity_bond.iter().all(|b| b.is_spent) {
            return Ok(None);
        }
        let (tip_height, tip_time) = self.chain_tip()?;
        Ok(self
            .store
            .fidelity_bond
            .iter()
            .filter_map(|bond| {
                let i = bond.bond_index;
                if !bond.is_spent {
                    match self.calculate_bond_value(bond, tip_height, tip_time) {
                        Ok(v) => {
                            log::info!("Fidelity Bond found | Index: {i} | Bond Value : {v}");
                            Some((i, v))
                        }
                        Err(e) => {
                            log::error!("Fidelity valuation failed for index {i}:  {e:?} ");
                            None
                        }
                    }
                } else {
                    None
                }
            })
            .max_by(|a, b| a.1.cmp(&b.1))
            .map(|(i, _)| i))
    }

    /// Get the [`Keypair`] for the fidelity bond at given index.
    pub(crate) fn get_fidelity_keypair(&self, index: u32) -> Result<Keypair, WalletError> {
        let secp = Secp256k1::new();

        let derivation_path = DerivationPath::from_str(FIDELITY_DERIVATION_PATH)?;

        let child_derivation_path = derivation_path.child(ChildNumber::Normal { index });

        self.with_master_key(|mk| {
            Ok(mk
                .derive_priv(&secp, &child_derivation_path)?
                .to_keypair(&secp))
        })
    }

    /// Derives the fidelity redeemscript from bond values at a given index.
    pub(crate) fn get_fidelity_reedemscript(&self, index: u32) -> Result<ScriptBuf, WalletError> {
        Ok(self.fidelity_bond(index)?.redeem_script())
    }

    /// The bond whose key derives at `index`. A restore can skip indexes,
    /// so a bond's place in the list is not its index.
    pub(crate) fn fidelity_bond(&self, index: u32) -> Result<&FidelityBond, WalletError> {
        self.store
            .fidelity_bond
            .iter()
            .find(|bond| bond.bond_index == index)
            .ok_or_else(|| FidelityError::BondDoesNotExist.into())
    }

    /// [`Self::fidelity_bond`], writable.
    pub(crate) fn fidelity_bond_mut(
        &mut self,
        index: u32,
    ) -> Result<&mut FidelityBond, WalletError> {
        self.store
            .fidelity_bond
            .iter_mut()
            .find(|bond| bond.bond_index == index)
            .ok_or_else(|| FidelityError::BondDoesNotExist.into())
    }

    /// Get the next fidelity bond address. If no fidelity bond is created
    /// returned address will be derived from index 0, of the [`FIDELITY_DERIVATION_PATH`]
    pub(crate) fn get_next_fidelity_address(
        &self,
        locktime: LockTime,
    ) -> Result<(u32, Address, PublicKey), WalletError> {
        let next_index = self
            .store
            .fidelity_bond
            .iter()
            .map(|bond| bond.bond_index + 1)
            .max()
            .unwrap_or(0);

        let fidelity_pubkey = PublicKey {
            compressed: true,
            inner: self.get_fidelity_keypair(next_index)?.public_key(),
        };

        Ok((
            next_index,
            Address::p2wsh(
                fidelity_redeemscript(&locktime, &fidelity_pubkey).as_script(),
                self.store.network,
            ),
            fidelity_pubkey,
        ))
    }

    /// Current tip height and its header time. Fetched once by callers so a
    /// scan over many bonds uses the value fetched once.
    pub fn chain_tip(&self) -> Result<(u64, u64), WalletError> {
        let height = self.blockchain.get_block_count()?;
        let time = self.blockchain.header_at_height(height)?.time as u64;
        Ok((height, time))
    }

    /// Calculate the theoretical fidelity bond value.
    /// Bond value calculation is described in the document below.
    /// <https://gist.github.com/chris-belcher/87ebbcbb639686057a389acb9ab3e25b#financial-mathematics-of-joinmarket-fidelity-bonds>
    pub fn calculate_bond_value(
        &self,
        bond: &FidelityBond,
        tip_height: u64,
        tip_time: u64,
    ) -> Result<Amount, WalletError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("This can't error")
            .as_secs();

        let conf_height = bond.conf_height.ok_or(FidelityError::BondDoesNotExist)? as u64;
        let confirmation_time = self.blockchain.header_at_height(conf_height)?.time as u64;

        let locktime = match bond.lock_time {
            LockTime::Blocks(blocks) => {
                // Estimated locktime from block height = [current-time + (maturity-height - block-count) * 10 * 60] sec
                let height_diff =
                    if let Some(x) = blocks.to_consensus_u32().checked_sub(tip_height as u32) {
                        x as u64
                    } else {
                        return Err(FidelityError::BondLocktimeExpired.into());
                    };

                tip_time + (height_diff * 10 * 60)
            }
            LockTime::Seconds(sec) => sec.to_consensus_u32() as u64,
        };

        let bond_value =
            calculate_fidelity_value(bond.amount, locktime, confirmation_time, current_time);

        Ok(bond_value)
    }

    /// Create a new fidelity bond with given amount and absolute height based locktime.
    /// This function creates the fidelity transaction, signs and broadcast it.
    /// Upon confirmation it stores the fidelity information in the wallet data.
    /// Create and broadcast the fidelity bond transaction. Returns `(index, txid)`
    /// so the caller can wait for confirmation without holding the wallet lock.
    pub fn create_fidelity(
        &mut self,
        amount: Amount,
        locktime: LockTime,
        maker_address: Option<&str>,
        feerate: f64,
        change_address_type: AddressType,
    ) -> Result<(u32, Txid), WalletError> {
        let (index, fidelity_addr, fidelity_pubkey) = self.get_next_fidelity_address(locktime)?;

        let coins = self.coin_select(
            amount,
            feerate,
            infer_address_type(&fidelity_addr.script_pubkey()),
            None,
            None,
        )?;
        let outputs = vec![(fidelity_addr, amount)];

        let op_return_data = match maker_address {
            Some(onion) => Some(self.encode_fidelity_op_return(onion, locktime)?),
            None => None,
        };

        let destination = Destination::Multi {
            outputs,
            op_return_data,
            change_address_type,
        };

        let tx = self.spend_coins(&coins, destination, feerate)?;

        let txid = self.send_tx(&tx)?;

        // Register this bond even if it is in mempool and not yet confirmed to avoid the edge case when the Maker server
        // unexpectedly shutdown while it was waiting for the fidelity transaction confirmation.
        // Otherwise the wallet wouldn't know about this bond in this case and would attempt to create a new bond again.
        {
            let bond = FidelityBond {
                outpoint: OutPoint::new(txid, 0),
                amount,
                lock_time: locktime,
                pubkey: fidelity_pubkey,
                // `conf_height` is None because it can't be known before confirmation.
                conf_height: None,
                is_spent: false,
                bond_index: index,
                tx: Some(tx),
            };
            self.store.fidelity_bond.push(bond);
            self.save_to_disk()?;
        }

        Ok((index, txid))
    }

    /// Update the confirmation height of a fidelity bond after it confirms.
    /// Also drops the stored raw transaction, which is only kept as a
    /// rebroadcast fallback until confirmation, and saves the wallet file.
    pub fn update_fidelity_bond_conf_details(
        &mut self,
        index: u32,
        conf_height: u32,
    ) -> Result<(), WalletError> {
        let bond = self.fidelity_bond_mut(index)?;
        bond.conf_height = Some(conf_height);
        bond.tx = None;

        // Persist immediately: without this a stop before the next save
        // replays the rebroadcast-and-wait cycle on the next start.
        self.save_to_disk()?;

        Ok(())
    }

    /// Redeems all expired fidelity bonds in the wallet ,if found any.
    pub fn redeem_expired_fidelity_bonds(
        &mut self,
        feerate: f64,
        destination_address_type: AddressType,
    ) -> Result<(), WalletError> {
        let curr_height = self.blockchain.get_block_count()? as u32;

        let expired_bond_indices = self
            .store
            .fidelity_bond
            .iter()
            .filter(|bond| !bond.is_spent && curr_height > bond.lock_time.to_consensus_u32())
            .map(|bond| bond.bond_index)
            .collect::<Vec<_>>();

        expired_bond_indices.into_iter().try_for_each(|i| {
            log::info!("Fidelity Bond at index: {i:?} expired | Redeeming it.");
            self.redeem_fidelity(i, feerate, destination_address_type)
                .map(|_| ())
        })
    }

    /// Generate a [`FidelityProof`] for bond at a given index and a specific onion address.
    pub(crate) fn generate_fidelity_proof(
        &self,
        index: u32,
        maker_addr: &str,
    ) -> Result<FidelityProof, WalletError> {
        // Generate a fidelity bond proof from the fidelity data.
        let bond = self.fidelity_bond(index)?;
        if bond.is_spent {
            return Err(FidelityError::BondAlreadyRedeemed.into());
        }

        let fidelity_privkey = self.get_fidelity_keypair(index)?.secret_key();
        let (_, tweakable_point, _) = self.get_tweakable_keypair()?;

        let cert_hash = bond.generate_cert_hash(maker_addr, &tweakable_point);

        let secp = Secp256k1::new();
        let cert_sig = secp.sign_ecdsa_low_r(
            &Message::from_digest_slice(cert_hash.as_byte_array())?,
            &fidelity_privkey,
        );

        let mut bond = bond.clone();
        // The stored raw transaction is a local rebroadcast fallback, not part
        // of the proof; keep it off the wire.
        bond.tx = None;

        Ok(FidelityProof {
            bond,
            cert_hash,
            cert_sig,
        })
    }

    pub(crate) fn encode_fidelity_op_return(
        &self,
        onion: &str,
        locktime: LockTime,
    ) -> Result<Box<[u8]>, WalletError> {
        let locktime_height = match locktime {
            LockTime::Blocks(h) => h.to_consensus_u32(),
            LockTime::Seconds(_) => {
                return Err(WalletError::General(
                    "fidelity locktime must be height-based".to_string(),
                ))
            }
        };

        let onion = onion.strip_suffix(".onion").unwrap_or(onion);
        let payload = format!("{onion}#{locktime_height}");
        Ok(payload.into_bytes().into_boxed_slice())
    }

    /// Rebuilds bond records from the wallet's own sends: the OP_RETURN, a hint or
    /// a backup's record gives the locktime, the seed gives the key per index.
    pub(crate) fn recover_fidelity_bonds(&mut self) -> Result<bool, WalletError> {
        // Only our own send can fund a bond; anyone can pay us a lookalike.
        let txids: HashSet<Txid> = self
            .blockchain
            .list_transactions(None, Some(i32::MAX as usize), None, Some(true))?
            .into_iter()
            .filter(|entry| {
                matches!(
                    entry.detail.category,
                    GetTransactionResultDetailCategory::Send
                )
            })
            .map(|entry| entry.info.txid)
            .collect();
        let txs = txids
            .iter()
            .map(|txid| self.blockchain.get_raw_transaction(txid, None))
            .collect::<Result<Vec<_>, _>>()?;

        let bonds = self.find_bonds(&txs)?;
        let found = !bonds.is_empty();
        for mut bond in bonds {
            bond.is_spent = self
                .blockchain
                .is_confirmed_spend(&bond.outpoint, &bond.script_pub_key())?;
            // Left unconfirmed with its tx, so maker startup fills in the height.
            self.store.fidelity_bond.push(bond);
        }
        Ok(found)
    }

    /// The bonds `txs` pay that the store lacks, in index order: each restore
    /// hint at its own index, then every announced locktime at each index,
    /// until `bond_gap` indexes in a row past the last bond find nothing.
    fn find_bonds(&self, txs: &[Transaction]) -> Result<Vec<FidelityBond>, WalletError> {
        let Some(options) = &self.store.pending_restore else {
            return Ok(Vec::new());
        };
        let mut taken: HashSet<u32> = self
            .store
            .fidelity_bond
            .iter()
            .map(|bond| bond.bond_index)
            .collect();
        let mut bonds = Vec::new();
        for hint in &options.bond_hints {
            if taken.contains(&hint.index) {
                continue;
            }
            // The CLI refuses these; skip one saved by an older build or the API.
            if hint.index >= 1 << 31 {
                log::warn!("Skipping bond hint {hint:?}: index is not below 2^31");
                continue;
            }
            match self.find_bond(hint.index, &[hint.locktime], txs)? {
                Some(bond) => {
                    taken.insert(hint.index);
                    bonds.push(bond);
                }
                None => log::warn!("Bond hint {hint:?} matches none of the wallet's sends"),
            }
        }

        let announced: Vec<LockTime> = txs
            .iter()
            .filter_map(|tx| {
                let data = extract_op_return_data(tx.output.get(1)?.script_pubkey.as_bytes())?;
                LockTime::from_height(parse_fidelity_op_return(data)?.expires_at_height).ok()
            })
            .collect();
        // Scan from 0, and past each known bond, until `bond_gap` indexes in a
        // row find nothing. A high bond only opens a gap-sized window past
        // itself; the keys between it and the low run are never derived.
        let mut starts: Vec<u32> = std::iter::once(0)
            .chain(taken.iter().map(|index| index.saturating_add(1)))
            .collect();
        starts.sort_unstable();
        let mut scanned_to = 0;
        for start in starts {
            let mut end = start.saturating_add(options.bond_gap);
            let mut index = start.max(scanned_to);
            while index < end {
                if !taken.contains(&index) {
                    if let Some(bond) = self.find_bond(index, &announced, txs)? {
                        end = end.max(index.saturating_add(1).saturating_add(options.bond_gap));
                        taken.insert(index);
                        bonds.push(bond);
                    }
                }
                index += 1;
            }
            scanned_to = scanned_to.max(end);
        }
        bonds.sort_by_key(|bond| bond.bond_index);
        Ok(bonds)
    }

    /// The first output in `txs` paying the bond at `index` with one of `lock_times`.
    fn find_bond(
        &self,
        index: u32,
        lock_times: &[LockTime],
        txs: &[Transaction],
    ) -> Result<Option<FidelityBond>, WalletError> {
        let pubkey = PublicKey {
            compressed: true,
            inner: self.get_fidelity_keypair(index)?.public_key(),
        };
        Ok(lock_times.iter().find_map(|lock_time| {
            let script = fidelity_redeemscript(lock_time, &pubkey).to_p2wsh();
            txs.iter().find_map(|tx| {
                let vout = tx
                    .output
                    .iter()
                    .position(|out| out.script_pubkey == script)?;
                Some(FidelityBond {
                    outpoint: OutPoint::new(tx.compute_txid(), vout as u32),
                    amount: tx.output[vout].value,
                    lock_time: *lock_time,
                    pubkey,
                    conf_height: None,
                    is_spent: false,
                    bond_index: index,
                    tx: Some(tx.clone()),
                })
            })
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::wallet::{api::test_support::test_wallet, BondHint, RestoreOptions};
    use bitcoin::{bip32::Xpriv, secp256k1::SecretKey, transaction::Version, NetworkKind, TxOut};
    use bitcoind::tempfile::tempdir;

    /// A proof that passes every other check, built the way a maker builds one:
    /// the bond key is derived from the tweak point at [2, bond_index].
    fn valid_proof(
        addr: &str,
        conf_height: u32,
    ) -> (
        FidelityProof,
        Transaction,
        PublicKey,
        bitcoin::bip32::ChainCode,
    ) {
        let secp = Secp256k1::new();
        let chain_code = bitcoin::bip32::ChainCode::from([7u8; 32]);
        let tweak_secret = SecretKey::from_slice(&[3u8; 32]).expect("valid secret key");
        let tweakable_point = PublicKey::new(tweak_secret.public_key(&secp));

        let xpriv = Xpriv {
            network: NetworkKind::Main,
            depth: 1,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::Hardened { index: 0 },
            private_key: tweak_secret,
            chain_code,
        };
        let bond_xpriv = xpriv
            .derive_priv(
                &secp,
                &[
                    ChildNumber::Normal { index: 2 },
                    ChildNumber::Normal { index: 0 },
                ],
            )
            .expect("derivable path");
        let bond_pubkey = PublicKey::new(bond_xpriv.private_key.public_key(&secp));

        let lock_time = LockTime::from_height(conf_height + MIN_FIDELITY_TIMELOCK)
            .expect("height based locktime");
        let amount = Amount::from_sat(100_000);
        let script_pubkey =
            redeemscript_to_scriptpubkey(&fidelity_redeemscript(&lock_time, &bond_pubkey))
                .expect("derivable scriptpubkey");
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut {
                value: amount,
                script_pubkey,
            }],
        };

        let bond = FidelityBond {
            outpoint: OutPoint {
                txid: tx.compute_txid(),
                vout: 0,
            },
            amount,
            lock_time,
            pubkey: bond_pubkey,
            conf_height: Some(conf_height),
            is_spent: false,
            bond_index: 0,
            tx: None,
        };

        let cert_hash = bond.generate_cert_hash(addr, &tweakable_point);
        let msg = Message::from_digest_slice(cert_hash.as_byte_array()).expect("32 byte digest");
        let cert_sig = secp.sign_ecdsa(&msg, &bond_xpriv.private_key);

        (
            FidelityProof {
                bond,
                cert_hash,
                cert_sig,
            },
            tx,
            tweakable_point,
            chain_code,
        )
    }

    #[test]
    fn a_stale_advertised_confirmation_height_still_verifies() {
        let addr = "test.onion:6102";
        let conf_height = 1_000u32;
        let (mut proof, tx, tweakable_point, chain_code) = valid_proof(addr, conf_height);
        let current_height = u64::from(conf_height) + 1;

        verify_fidelity_checks(
            &proof,
            addr,
            tx.clone(),
            current_height,
            conf_height,
            &tweakable_point,
            &chain_code,
        )
        .expect("a proof agreeing with our chain must verify");

        // A reorg remined the bond and the maker has not caught up yet. Our own
        // height is the one that counts, so this proves nothing against it.
        proof.bond.conf_height = Some(conf_height - 1);
        verify_fidelity_checks(
            &proof,
            addr,
            tx,
            current_height,
            conf_height,
            &tweakable_point,
            &chain_code,
        )
        .expect("a stale advertised height must not fail the proof");
    }

    #[test]
    fn a_forged_proof_is_named_as_forgery() {
        let addr = "test.onion:6103";
        let conf_height = 1_000u32;
        let (proof, tx, tweakable_point, chain_code) = valid_proof(addr, conf_height);
        let verify = |proof: &FidelityProof| {
            verify_fidelity_checks(
                proof,
                addr,
                tx.clone(),
                u64::from(conf_height) + 1,
                conf_height,
                &tweakable_point,
                &chain_code,
            )
        };

        // A signed outpoint naming an output the transaction does not have.
        let mut missing_output = proof.clone();
        missing_output.bond.outpoint.vout = 1;
        missing_output.cert_hash = missing_output
            .bond
            .generate_cert_hash(addr, &tweakable_point);
        assert!(matches!(
            verify(&missing_output),
            Err(WalletError::Fidelity(FidelityError::BondDoesNotExist))
        ));

        let secp = Secp256k1::new();
        let msg = Message::from_digest_slice(proof.cert_hash.as_byte_array()).unwrap();
        let mut wrong_signer = proof;
        wrong_signer.cert_sig = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&[9u8; 32]).unwrap());
        assert!(matches!(
            verify(&wrong_signer),
            Err(WalletError::Fidelity(FidelityError::InvalidCertSignature))
        ));
    }

    #[test]
    fn test_fidelity_bond_value_function_behavior() {
        const EPSILON: f64 = 0.000001;
        const YEAR: f64 = 60.0 * 60.0 * 24.0 * 365.2425;

        //the function should be flat anywhere before the locktime ends
        let values = (0..4)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    (6.0 * YEAR) as u64,
                    0,
                    y * (YEAR as u64),
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_diff = (0..values.len() - 1)
            .map(|i| values[i + 1] - values[i])
            .collect::<Vec<f64>>();
        for v in &value_diff {
            assert!(v.abs() < EPSILON);
        }

        //after locktime, the value should go down
        let values = (0..5)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    (6.0 * YEAR) as u64,
                    0,
                    (6 + y) * (YEAR as u64),
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_diff = (0..values.len() - 1)
            .map(|i| values[i + 1] - values[i])
            .collect::<Vec<f64>>();
        for v in &value_diff {
            assert!(*v < 0.0);
        }

        //value of a bond goes up as the locktime goes up
        let values = (0..5)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    ((y as f64) * YEAR) as u64,
                    0,
                    0,
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_ratio = (0..values.len() - 1)
            .map(|i| values[i] / values[i + 1])
            .collect::<Vec<f64>>();
        let value_ratio_diff = (0..value_ratio.len() - 1)
            .map(|i| value_ratio[i] - value_ratio[i + 1])
            .collect::<Vec<f64>>();
        for v in &value_ratio_diff {
            assert!(*v < 0.0);
        }

        //value of a bond locked into the far future is constant, clamped at the value of burned coins
        let values = (0..5)
            .map(|y| {
                calculate_fidelity_value(
                    Amount::from_sat(100000000),
                    (((200 + y) as f64) * YEAR) as u64,
                    0,
                    0,
                )
                .to_sat() as f64
            })
            .collect::<Vec<f64>>();
        let value_diff = (0..values.len() - 1)
            .map(|i| values[i] - values[i + 1])
            .collect::<Vec<f64>>();
        for v in &value_diff {
            assert!(v.abs() < EPSILON);
        }
    }

    #[test]
    fn test_fidelity_bond_values() {
        let value = Amount::from_btc(1.0).unwrap();
        let confirmation_time = 50_000;
        let current_time = 60_000;

        // Following is a (locktime, fidelity_value) tuple series to show how fidelity_value increases with locktimes
        let test_vectors = [
            (55000, 0), // Value is zero for expired timelocks
            (60000, 3020),
            (65000, 5117),
            (70000, 7437),
            (75000, 9940),
            (80000, 12599),
            (85000, 15395),
            (90000, 18313),
            (95000, 21344),
            (100000, 24477),
            (105000, 27706),
            (110000, 31024),
            (115000, 34426),
            (120000, 37908),
            (125000, 41465),
            (130000, 45094),
            (135000, 48792),
            (140000, 52556),
            (145000, 56383),
        ]
        .map(|(lt, val)| (lt as u64, Amount::from_sat(val)));

        for (locktime, fidelity_value) in test_vectors {
            assert_eq!(
                fidelity_value,
                calculate_fidelity_value(value, locktime, confirmation_time, current_time)
            );
        }
    }

    #[cfg(not(feature = "integration-test"))]
    const MAKER_ADDRESS: &str = "aeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaeaqcaibaea37ead.onion";
    #[cfg(feature = "integration-test")]
    const MAKER_ADDRESS: &str = "127.0.0.1:6102";

    /// A transaction paying the bond at `index`, announced as a maker does or bare.
    fn bond_tx(wallet: &Wallet, index: u32, lock_time: LockTime, announce: bool) -> Transaction {
        let pubkey = PublicKey::new(wallet.get_fidelity_keypair(index).unwrap().public_key());
        let mut output = vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: fidelity_redeemscript(&lock_time, &pubkey).to_p2wsh(),
        }];
        if announce {
            let data = wallet
                .encode_fidelity_op_return(MAKER_ADDRESS, lock_time)
                .unwrap();
            let mut script = vec![0x6a, data.len() as u8];
            script.extend_from_slice(&data);
            output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: script.into(),
            });
        }
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    /// Bonds at 1 and 4 leave 0, 2 and 3 empty: a gap of 3 crosses both holes,
    /// a gap of 2 stops before 4. Bare bond 9 needs a hint with its locktime,
    /// and then counts as used, so the gap reaches 12. Every lookup must then
    /// go by index, never by place in the list.
    #[test]
    fn restore_finds_bonds_past_missing_indexes_and_by_hint() {
        let dir = tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("wallet"));
        let lock_time = |height| LockTime::from_height(height).unwrap();
        let txs = [
            bond_tx(&wallet, 1, lock_time(1000), true),
            bond_tx(&wallet, 4, lock_time(1001), true),
            bond_tx(&wallet, 9, lock_time(1002), false),
            bond_tx(&wallet, 12, lock_time(1003), true),
        ];
        let hint = BondHint {
            index: 9,
            locktime: lock_time(1002),
        };
        let wrong_locktime = BondHint {
            locktime: lock_time(1004),
            ..hint
        };
        for (bond_gap, bond_hints, expected) in [
            (3, vec![], vec![1, 4]),
            (2, vec![], vec![1]),
            (3, vec![wrong_locktime], vec![1, 4]),
            (3, vec![wrong_locktime, hint], vec![1, 4, 9, 12]),
            (
                3,
                vec![
                    BondHint {
                        index: 1 << 31,
                        ..hint
                    },
                    hint,
                ],
                vec![1, 4, 9, 12],
            ),
        ] {
            wallet.store.pending_restore = Some(RestoreOptions {
                bond_gap,
                bond_hints,
                ..Default::default()
            });
            let found: Vec<u32> = wallet
                .find_bonds(&txs)
                .unwrap()
                .iter()
                .map(|bond| bond.bond_index)
                .collect();
            assert_eq!(found, expected, "gap {bond_gap}");
        }
        // A matched hint far out scans only a window past itself: deriving
        // every key up to 2^30 would never finish.
        let far = 1 << 30;
        let mut far_txs = txs.to_vec();
        far_txs.push(bond_tx(&wallet, far, lock_time(1005), false));
        far_txs.push(bond_tx(&wallet, far + 2, lock_time(1006), true));
        wallet.store.pending_restore = Some(RestoreOptions {
            bond_gap: 3,
            bond_hints: vec![BondHint {
                index: far,
                locktime: lock_time(1005),
            }],
            ..Default::default()
        });
        let found: Vec<u32> = wallet
            .find_bonds(&far_txs)
            .unwrap()
            .iter()
            .map(|bond| bond.bond_index)
            .collect();
        assert_eq!(found, vec![1, 4, far, far + 2]);
        wallet.store.pending_restore = Some(RestoreOptions {
            bond_gap: 3,
            bond_hints: vec![hint],
            ..Default::default()
        });

        wallet.store.fidelity_bond = wallet.find_bonds(&txs).unwrap();
        assert!(
            wallet.find_bonds(&txs).unwrap().is_empty(),
            "a resumed restore must not add a bond twice"
        );
        assert_eq!(
            wallet.fidelity_bond(9).unwrap().outpoint,
            OutPoint::new(txs[2].compute_txid(), 0)
        );

        // Signing takes the key and the script by index, so they must agree.
        for index in [1, 4, 9, 12] {
            let script = wallet.get_fidelity_reedemscript(index).unwrap();
            let key = wallet.get_fidelity_keypair(index).unwrap().public_key();
            assert_eq!(
                read_pubkey_from_fidelity_script(&script).unwrap().inner,
                key
            );
        }
        assert!(wallet.fidelity_bond(0).is_err());
        let (next, _, _) = wallet.get_next_fidelity_address(lock_time(1000)).unwrap();
        assert_eq!(next, 13, "a new bond must not reuse a recovered key");
    }
}

#[test]
fn test_fidleity_redeemscripts() {
    let test_data = [
        (
            (
                "03ffe2b8b46eb21eadc3b535e9f57054213a1775b035faba6c5b3368b3a0ab5a5c",
                15000,
            ),
            "2103ffe2b8b46eb21eadc3b535e9f57054213a1775b035faba6c5b3368b3a0ab5a5cad02983ab1",
        ),
        (
            (
                "031499764842691088897cff51efd85347dd3215912cbb8fb9b121b1da3b15bec8",
                30000,
            ),
            "21031499764842691088897cff51efd85347dd3215912cbb8fb9b121b1da3b15bec8ad023075b1",
        ),
        (
            (
                "022714334f189db14fabd3dd893bbb913b8c3ddff245f7094cdc0b24c2fabb3570",
                45000,
            ),
            "21022714334f189db14fabd3dd893bbb913b8c3ddff245f7094cdc0b24c2fabb3570ad03c8af00b1",
        ),
        (
            (
                "02145a1d2bd118edcb3fe85495192d44e1d09f75ab4f0fe98269f61ff672860dae",
                60000,
            ),
            "2102145a1d2bd118edcb3fe85495192d44e1d09f75ab4f0fe98269f61ff672860daead0360ea00b1",
        ),
    ]
    .map(|((pk, lt), script)| {
        (
            (
                PublicKey::from_str(pk).unwrap(),
                LockTime::from_height(lt).unwrap(),
            ),
            ScriptBuf::from_hex(script).unwrap(),
        )
    });

    for ((pk, lt), script) in test_data {
        assert_eq!(script, fidelity_redeemscript(&lt, &pk));
        assert_eq!(pk, read_pubkey_from_fidelity_script(&script).unwrap());
        assert_eq!(lt, read_locktime_from_fidelity_script(&script).unwrap());
    }
}
