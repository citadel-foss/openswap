use crate::{
    protocol::common_messages::FidelityProof,
    utill::{redeemscript_to_scriptpubkey, MIN_FEE_RATE},
    wallet::{infer_address_type, AddressType, Blockchain, Wallet},
};
use bitcoin::{
    absolute::LockTime,
    bip32::{ChildNumber, DerivationPath},
    consensus::encode::{serialize, VarInt},
    hashes::{sha256d, Hash},
    opcodes::all::{OP_CHECKSIGVERIFY, OP_CLTV},
    script::{Builder, Instruction},
    secp256k1::{Keypair, Message, Secp256k1},
    Address, Amount, OutPoint, PublicKey, ScriptBuf, Transaction, Txid,
};
use serde::{Deserialize, Serialize};
use std::{
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

/// Error structure defining possible fidelity related errors
#[derive(Debug)]
pub enum FidelityError {
    WrongScriptType,
    BondDoesNotExist,
    BondAlreadyRedeemed,
    BondLocktimeExpired,
    InvalidCertHash,
    InvalidConfirmationHeight {
        claimed: Option<u32>,
        actual: u32,
    },
    General(String),
    InvalidBondLocktime,
    BondUncomfirmed,
    /// The bond's funding transaction was evicted from the network and the
    /// wallet holds no stored raw transaction to rebroadcast, so the bond
    /// can never be recovered by this maker.
    BondTransactionMissing {
        index: u32,
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
            FidelityError::InvalidConfirmationHeight { claimed, actual } => {
                write!(
                    f,
                    "Fidelity bond confirmation height {claimed:?} does not match chain height {actual}"
                )
            }
            FidelityError::InvalidBondLocktime => {
                write!(f, "Fidelity bond locktime is outside the acceptable range")
            }
            FidelityError::BondUncomfirmed => write!(f, "Fidelity bond transaction is unconfirmed"),
            FidelityError::BondTransactionMissing { index } => write!(
                f,
                "fidelity bond at index {index} was evicted and has no stored transaction to rebroadcast"
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
    // QA: conf_height is maker-supplied and affects the accepted lock period,
    // so bind it to the bond output's actual confirmation height.
    if proof.bond.conf_height != Some(confirmation_height) {
        return Err(FidelityError::InvalidConfirmationHeight {
            claimed: proof.bond.conf_height,
            actual: confirmation_height,
        }
        .into());
    }

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
        return Err(WalletError::General(
            "Fidelity bond does not correspond to the provided tweak point".to_string(),
        ));
    }

    // Validate redeem script and corresponding output scriptPubKey
    let fidelity_redeem_script = fidelity_redeemscript(&proof.bond.lock_time, &proof.bond.pubkey);
    let derived_script_pubkey = redeemscript_to_scriptpubkey(&fidelity_redeem_script)?;
    let tx_out = tx
        .tx_out(proof.bond.outpoint.vout as usize)
        .map_err(|_| WalletError::General("Outputs index error".to_string()))?;

    if tx_out.script_pubkey != derived_script_pubkey {
        return Err(WalletError::Fidelity(FidelityError::BondDoesNotExist));
    }
    // QA: A maker could advertise a larger bond amount than the output actually
    // locks, inflating its fidelity value and offer ranking. Bind the signed
    // proof amount to the real chain output before accepting the bond.
    if tx_out.value != proof.bond.amount {
        return Err(WalletError::Fidelity(FidelityError::General(format!(
            "Bond amount mismatch: expected {}, actual {}",
            proof.bond.amount, tx_out.value
        ))));
    }

    // Verify ECDSA signature
    let cert_message = Message::from_digest_slice(proof.cert_hash.as_byte_array())?;
    secp.verify_ecdsa(&cert_message, &proof.cert_sig, &proof.bond.pubkey.inner)?;

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
            .enumerate()
            .map(|(index, bond)| -> Result<serde_json::Value, WalletError> {
                let mut bond_info = serde_json::json!({
                        "index": index,
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
            .enumerate()
            .filter_map(|(i, bond)| {
                if !bond.is_spent {
                    match self.calculate_bond_value(bond, tip_height, tip_time) {
                        Ok(v) => {
                            log::info!("Fidelity Bond found | Index: {i} | Bond Value : {v}");
                            Some((i as u32, v))
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
        let bond = self
            .store
            .fidelity_bond
            .get(index as usize)
            .ok_or(FidelityError::BondDoesNotExist)?;
        Ok(bond.redeem_script())
    }

    /// Get the next fidelity bond address. If no fidelity bond is created
    /// returned address will be derived from index 0, of the [`FIDELITY_DERIVATION_PATH`]
    pub(crate) fn get_next_fidelity_address(
        &self,
        locktime: LockTime,
    ) -> Result<(u32, Address, PublicKey), WalletError> {
        // Check what was the last fidelity address index.
        // Derive a fidelity address
        let next_index = self.store.fidelity_bond.len() as u32;

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

    /// Ensure the funding transaction of the bond at `index` is visible to the
    /// network, returning its txid.
    ///
    /// If the original broadcast is still in the mempool or already confirmed,
    /// its txid is returned unchanged. Otherwise the transaction was evicted
    /// (e.g. while the maker was offline) and waiting for it would never
    /// succeed: the raw transaction stored at creation is rebroadcast, which
    /// reproduces the same txid, so the bond keeps its original outpoint and
    /// no replacement spending different coins can double-lock funds.
    pub fn ensure_fidelity_bond_broadcast(&self, index: u32) -> Result<Txid, WalletError> {
        let bond = self
            .store
            .fidelity_bond
            .get(index as usize)
            .ok_or(FidelityError::BondDoesNotExist)?;

        // Only a proven "unknown transaction" answer means eviction; any
        // other backend failure surfaces as an error instead of triggering
        // a spurious rebroadcast.
        if !self.blockchain.is_tx_unknown(&bond.outpoint.txid)? {
            return Ok(bond.outpoint.txid);
        }

        log::warn!(
            "Fidelity bond tx {} is not visible to the backend (evicted from mempool?); rebroadcasting",
            bond.outpoint.txid
        );

        let tx = bond
            .tx
            .as_ref()
            .ok_or(FidelityError::BondTransactionMissing { index })?;
        let txid = self.send_tx(tx)?;
        debug_assert_eq!(txid, bond.outpoint.txid);

        Ok(txid)
    }

    /// Update the confirmation height of a fidelity bond after it confirms.
    /// Also drops the stored raw transaction, which is only kept as a
    /// rebroadcast fallback until confirmation, and saves the wallet file.
    pub fn update_fidelity_bond_conf_details(
        &mut self,
        index: u32,
        conf_height: u32,
    ) -> Result<(), WalletError> {
        let bond = self
            .store
            .fidelity_bond
            .get_mut(index as usize)
            .ok_or(FidelityError::BondDoesNotExist)?;

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
        destination_address_type: AddressType,
    ) -> Result<(), WalletError> {
        let curr_height = self.blockchain.get_block_count()? as u32;

        let expired_bond_indices = self
            .store
            .fidelity_bond
            .iter()
            .enumerate()
            .filter_map(|(i, bond)| {
                if !bond.is_spent && curr_height > bond.lock_time.to_consensus_u32() {
                    Some(i as u32)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        expired_bond_indices.into_iter().try_for_each(|i| {
            log::info!("Fidelity Bond at index: {i:?} expired | Redeeming it.");
            self.redeem_fidelity(i, MIN_FEE_RATE, destination_address_type)
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
        let bond = self
            .store
            .fidelity_bond
            .get(index as usize)
            .ok_or(FidelityError::BondDoesNotExist)?;
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

    fn encode_fidelity_op_return(
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
}

#[cfg(test)]
mod test {
    use super::*;

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
