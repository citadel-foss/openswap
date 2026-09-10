//! SwapCoin structures for both Legacy (ECDSA) and Taproot (MuSig2) protocols.

use bitcoin::{
    address::NetworkUnchecked,
    hashes::Hash,
    secp256k1::{Keypair, Scalar, SecretKey, XOnlyPublicKey},
    sighash::SighashCache,
    taproot::Signature as TaprootSignature,
    Address, Amount, PublicKey, ScriptBuf, Transaction, Txid, Witness,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::convert::TryInto;

use crate::protocol::{
    common_messages::ProtocolVersion,
    contract2::calculate_contract_sighash,
    musig_interface::{
        aggregate_partial_signatures_compat, generate_new_nonce_pair_compat,
        generate_partial_signature_compat, get_aggregated_nonce_compat,
    },
};

use super::{contract_and_timelock_vsize, SpendKind, WalletError};

mod option_scalar_serde {
    use super::*;

    pub fn serialize<S>(scalar: &Option<Scalar>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match scalar {
            Some(s) => serializer.serialize_some(&s.to_be_bytes()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Scalar>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<u8>> = Deserialize::deserialize(deserializer)?;
        opt.map(|bytes| {
            let bytes_array: [u8; 32] = bytes
                .try_into()
                .map_err(|_| serde::de::Error::custom("Invalid scalar byte length"))?;
            Scalar::from_be_bytes(bytes_array)
                .map_err(|e| serde::de::Error::custom(format!("Invalid scalar: {:?}", e)))
        })
        .transpose()
    }
}

/// Feerate stored on swapcoins persisted before the field existed.
fn default_negotiated_feerate() -> u64 {
    crate::utill::MIN_RELAY_FEE_RATE as u64
}

/// Exact settlement destination for a PaySwap incoming swapcoin.
///
/// When set, every claim path pays exactly `amount` to `script_pubkey` and
/// spends the remaining input value as miner fee — the output never absorbs
/// a fee.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentTarget {
    /// The receiver's locking script.
    pub script_pubkey: ScriptBuf,
    /// Exact amount the settlement output must carry.
    pub amount: Amount,
}

/// Incoming swap coin for both protocol versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IncomingSwapCoin {
    /// Protocol version for this swap coin.
    pub protocol: ProtocolVersion,

    // ---- Common fields ----
    /// Our private key for this swap.
    pub my_privkey: Option<SecretKey>,
    /// Our derived public key.
    pub my_pubkey: Option<PublicKey>,
    /// Counterparty's public key.
    pub other_pubkey: Option<PublicKey>,
    /// Counterparty's private key (received during handover).
    pub other_privkey: Option<SecretKey>,
    /// The contract transaction.
    pub contract_tx: Transaction,
    /// Contract transaction ID.
    pub contract_txid: Option<Txid>,
    /// Private key for hashlock spending.
    pub hashlock_privkey: SecretKey,
    /// The funding amount.
    pub funding_amount: Amount,
    /// The hash preimage (revealed during settlement).
    pub hash_preimage: Option<[u8; 32]>,
    /// Unique swap identifier.
    pub swap_id: Option<String>,
    /// Contract redeemscript (Legacy only) - the HTLC script.
    pub contract_redeemscript: Option<ScriptBuf>,
    /// Multisig redeemscript (Legacy only) - 2-of-2 multisig for cooperative spend.
    #[serde(default)]
    pub multisig_redeemscript: Option<ScriptBuf>,
    /// Hashlock script (Taproot only).
    pub hashlock_script: Option<ScriptBuf>,
    /// Timelock script (Taproot only).
    pub timelock_script: Option<ScriptBuf>,
    /// Other party's contract signature (Legacy only).
    pub others_contract_sig: Option<bitcoin::ecdsa::Signature>,
    /// Taproot tap tweak.
    #[serde(with = "option_scalar_serde")]
    pub tap_tweak: Option<Scalar>,
    /// Taproot internal key.
    pub internal_key: Option<XOnlyPublicKey>,
    /// Spending transaction (Taproot only, for preimage extraction).
    pub spending_tx: Option<Transaction>,
    /// PaySwap settlement destination; `None` sweeps to a wallet-internal address.
    pub payment_target: Option<PaymentTarget>,
    /// Negotiated swap feerate (sats/vB). Settlement sweeps pay this rate:
    /// the peer was charged for it, so sweeping cheaper pockets the
    /// difference and can leave the sweep underpriced.
    #[serde(default = "default_negotiated_feerate")]
    pub negotiated_feerate: u64,
}

impl IncomingSwapCoin {
    pub fn new_legacy(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: ScriptBuf,
        hashlock_privkey: SecretKey,
        funding_amount: Amount,
        negotiated_feerate: u64,
    ) -> Self {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &my_privkey),
        };

        let multisig_redeemscript =
            crate::protocol::contract::create_multisig_redeemscript(&my_pubkey, &other_pubkey);

        IncomingSwapCoin {
            protocol: ProtocolVersion::Legacy,
            my_privkey: Some(my_privkey),
            my_pubkey: Some(my_pubkey),
            other_pubkey: Some(other_pubkey),
            other_privkey: None,
            contract_tx,
            contract_txid: None,
            hashlock_privkey,
            funding_amount,
            hash_preimage: None,
            swap_id: None,
            contract_redeemscript: Some(contract_redeemscript),
            multisig_redeemscript: Some(multisig_redeemscript),
            hashlock_script: None,
            timelock_script: None,
            others_contract_sig: None,
            tap_tweak: None,
            internal_key: None,
            spending_tx: None,
            payment_target: None,
            negotiated_feerate,
        }
    }

    /// Create a new Taproot (MuSig2) incoming swap coin.
    pub fn new_taproot(
        hashlock_privkey: SecretKey,
        hashlock_script: ScriptBuf,
        timelock_script: ScriptBuf,
        contract_tx: Transaction,
        funding_amount: Amount,
        negotiated_feerate: u64,
    ) -> Self {
        IncomingSwapCoin {
            protocol: ProtocolVersion::Taproot,
            my_privkey: None,
            my_pubkey: None,
            other_pubkey: None,
            other_privkey: None,
            contract_tx,
            contract_txid: None,
            hashlock_privkey,
            funding_amount,
            hash_preimage: None,
            swap_id: None,
            contract_redeemscript: None,
            multisig_redeemscript: None,
            hashlock_script: Some(hashlock_script),
            timelock_script: Some(timelock_script),
            others_contract_sig: None,
            tap_tweak: None,
            internal_key: None,
            spending_tx: None,
            payment_target: None,
            negotiated_feerate,
        }
    }

    /// Returns our private key.
    pub fn privkey(&self) -> Result<SecretKey, WalletError> {
        self.my_privkey.ok_or_else(|| {
            WalletError::General("Incoming swapcoin's privkey does not exist".to_string())
        })
    }

    /// Returns our public key.
    pub fn pubkey(&self) -> Result<PublicKey, WalletError> {
        self.my_pubkey.ok_or_else(|| {
            WalletError::General("Incoming swapcoin's pubkey does not exist".to_string())
        })
    }

    /// Returns the counterparty's public key.
    pub fn other_pubkey(&self) -> Result<PublicKey, WalletError> {
        self.other_pubkey.ok_or_else(|| {
            WalletError::General("Incoming swapcoin's other pubkey does not exist".to_string())
        })
    }

    /// Returns the contract txid.
    pub fn contract_txid(&self) -> Result<Txid, WalletError> {
        self.contract_txid
            .or_else(|| Some(self.contract_tx.compute_txid()))
            .ok_or_else(|| {
                WalletError::General("Incoming swapcoin's contract txid does not exist".to_string())
            })
    }

    /// Returns the hashlock script (Taproot).
    pub fn hashlock_script(&self) -> Option<&ScriptBuf> {
        self.hashlock_script.as_ref()
    }

    /// Returns the timelock script (Taproot).
    pub fn timelock_script(&self) -> Option<&ScriptBuf> {
        self.timelock_script.as_ref()
    }

    /// Returns the contract redeemscript (Legacy).
    pub fn contract_redeemscript(&self) -> Option<&ScriptBuf> {
        self.contract_redeemscript.as_ref()
    }

    /// Returns the tap tweak (Taproot).
    pub fn tap_tweak(&self) -> Result<Scalar, WalletError> {
        self.tap_tweak.ok_or_else(|| {
            WalletError::General("Incoming swapcoin's tap tweak does not exist".to_string())
        })
    }

    /// Returns the internal key (Taproot).
    pub fn internal_key(&self) -> Result<XOnlyPublicKey, WalletError> {
        self.internal_key.ok_or_else(|| {
            WalletError::General("Incoming swapcoin's internal key does not exist".to_string())
        })
    }

    /// Returns whether the preimage is known.
    pub fn is_preimage_known(&self) -> bool {
        self.hash_preimage.is_some()
    }

    /// Sets the preimage.
    pub fn set_preimage(&mut self, preimage: [u8; 32]) {
        self.hash_preimage = Some(preimage);
    }

    /// Sets the other party's private key.
    pub fn set_other_privkey(&mut self, privkey: SecretKey) {
        self.other_privkey = Some(privkey);
    }

    /// Sets the Taproot parameters.
    pub fn set_taproot_params(
        &mut self,
        my_privkey: SecretKey,
        my_pubkey: PublicKey,
        other_pubkey: PublicKey,
        internal_key: XOnlyPublicKey,
        tap_tweak: Scalar,
    ) {
        self.my_privkey = Some(my_privkey);
        self.my_pubkey = Some(my_pubkey);
        self.other_pubkey = Some(other_pubkey);
        self.internal_key = Some(internal_key);
        self.tap_tweak = Some(tap_tweak);
    }

    /// Create a fully signed contract transaction for broadcast.
    ///
    /// For Legacy, the contract tx spends the P2WSH multisig funding output.
    /// It needs both our signature and the maker's signature applied to the witness.
    pub fn create_signed_contract_tx(&self) -> Result<Transaction, WalletError> {
        let mut signed_tx = self.contract_tx.clone();

        match self.protocol {
            ProtocolVersion::Legacy => {
                let my_privkey = self.my_privkey.ok_or_else(|| {
                    WalletError::General("Missing my_privkey for contract tx signing".to_string())
                })?;
                let my_pubkey = self.my_pubkey.ok_or_else(|| {
                    WalletError::General("Missing my_pubkey for contract tx signing".to_string())
                })?;
                let other_pubkey = self.other_pubkey.ok_or_else(|| {
                    WalletError::General("Missing other_pubkey for contract tx signing".to_string())
                })?;
                let others_sig = self.others_contract_sig.ok_or_else(|| {
                    WalletError::General(
                        "Missing others_contract_sig for contract tx signing".to_string(),
                    )
                })?;

                let multisig_redeemscript = crate::protocol::contract::create_multisig_redeemscript(
                    &my_pubkey,
                    &other_pubkey,
                );

                let my_sig = crate::protocol::contract::sign_contract_tx(
                    &signed_tx,
                    &multisig_redeemscript,
                    self.funding_amount,
                    &my_privkey,
                )
                .map_err(|e| {
                    WalletError::General(format!("Failed to sign contract tx: {:?}", e))
                })?;

                if let Some(input) = signed_tx.input.get_mut(0) {
                    crate::protocol::contract::apply_two_signatures_to_2of2_multisig_spend(
                        &my_pubkey,
                        &other_pubkey,
                        &my_sig,
                        &others_sig,
                        input,
                        &multisig_redeemscript,
                    );
                }
            }
            ProtocolVersion::Taproot => {
                // Taproot contract txs don't need multisig witness signing
            }
        }

        Ok(signed_tx)
    }

    /// Creates and signs a spend transaction for this incoming swap coin.
    pub fn sign_spend_transaction(
        &self,
        input_value: Amount,
        output_script: &ScriptBuf,
        feerate: f64,
    ) -> Result<Transaction, WalletError> {
        let vsize = contract_and_timelock_vsize(
            self.protocol,
            SpendKind::ContractSpend {
                cooperative: self.other_privkey.is_some(),
            },
        );

        let fee = Amount::from_sat((feerate * vsize as f64) as u64);
        let output_value = input_value
            .checked_sub(fee)
            .ok_or_else(|| WalletError::General("Fee exceeds input value".to_string()))?;

        self.sign_spend_transaction_with_output_value(input_value, output_value, output_script)
    }

    /// Like [`Self::sign_spend_transaction`], but pins the output to an exact
    /// value; the input surplus is paid as miner fee. Used for PaySwap settlements.
    pub(crate) fn sign_spend_transaction_with_output_value(
        &self,
        input_value: Amount,
        output_value: Amount,
        output_script: &ScriptBuf,
    ) -> Result<Transaction, WalletError> {
        use bitcoin::{
            absolute::LockTime,
            transaction::{Transaction as BtcTransaction, TxIn, TxOut, Version},
            OutPoint, Sequence, Witness,
        };

        if output_value >= input_value {
            return Err(WalletError::General(format!(
                "Spend output {output_value} leaves no fee from input {input_value}"
            )));
        }

        // Determine which outpoint to spend from based on protocol version:
        let previous_output = match self.protocol {
            crate::protocol::ProtocolVersion::Legacy => {
                if self.other_privkey.is_some() {
                    self.contract_tx
                        .input
                        .first()
                        .map(|input| input.previous_output)
                        .ok_or_else(|| {
                            WalletError::General(
                                "Contract tx has no input (funding outpoint)".to_string(),
                            )
                        })?
                } else {
                    let contract_txid = self.contract_tx.compute_txid();
                    OutPoint {
                        txid: contract_txid,
                        vout: 0,
                    }
                }
            }
            crate::protocol::ProtocolVersion::Taproot => {
                let contract_txid = self.contract_tx.compute_txid();
                let vout = self
                    .contract_tx
                    .output
                    .iter()
                    .position(|o| o.value == self.funding_amount)
                    .unwrap_or(0) as u32;
                OutPoint {
                    txid: contract_txid,
                    vout,
                }
            }
        };

        // For hashlock spend via contract redeemscript, the CSV opcode with
        // value 0 requires nSequence bit 31 to be clear (BIP68-enabled).
        // Sequence::ZERO satisfies this. For cooperative spend (2-of-2 multisig),
        // Sequence::ENABLE_RBF_NO_LOCKTIME is fine since there's no CSV check.
        let sequence = if self.other_privkey.is_some() {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        } else {
            Sequence::ZERO
        };

        let tx_input = TxIn {
            previous_output,
            script_sig: bitcoin::ScriptBuf::new(),
            sequence,
            witness: Witness::default(),
        };

        let tx_output = TxOut {
            value: output_value,
            script_pubkey: output_script.clone(),
        };

        let mut spend_tx = BtcTransaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![tx_input],
            output: vec![tx_output],
        };

        match self.protocol {
            crate::protocol::ProtocolVersion::Legacy => {
                self.sign_legacy_spend(&mut spend_tx)?;
            }
            crate::protocol::ProtocolVersion::Taproot => {
                self.sign_taproot_spend(&mut spend_tx)?;
            }
        }

        Ok(spend_tx)
    }

    /// Signs a legacy (ECDSA) spend transaction.
    fn sign_legacy_spend(&self, spend_tx: &mut Transaction) -> Result<(), WalletError> {
        use crate::protocol::contract::apply_two_signatures_to_2of2_multisig_spend;
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};

        if let Some(other_privkey) = &self.other_privkey {
            log::info!("Signing legacy cooperative spend (2-of-2 multisig)");

            let my_privkey = self.my_privkey.as_ref().ok_or_else(|| {
                WalletError::General("Missing my_privkey for cooperative spend".to_string())
            })?;
            let my_pubkey = self.my_pubkey.as_ref().ok_or_else(|| {
                WalletError::General("Missing my_pubkey for cooperative spend".to_string())
            })?;
            let other_pubkey = self.other_pubkey.as_ref().ok_or_else(|| {
                WalletError::General("Missing other_pubkey for cooperative spend".to_string())
            })?;
            let multisig_redeemscript = self.multisig_redeemscript.as_ref().ok_or_else(|| {
                WalletError::General(
                    "Missing multisig_redeemscript for cooperative spend".to_string(),
                )
            })?;

            let secp = bitcoin::secp256k1::Secp256k1::new();

            let sighash = bitcoin::secp256k1::Message::from_digest_slice(
                &SighashCache::new(&*spend_tx)
                    .p2wsh_signature_hash(
                        0,
                        multisig_redeemscript,
                        self.funding_amount,
                        EcdsaSighashType::All,
                    )
                    .map_err(|e| WalletError::General(format!("Sighash error: {:?}", e)))?[..],
            )
            .map_err(|e| WalletError::General(format!("Message creation error: {:?}", e)))?;

            let sig_mine = bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa_low_r(&sighash, my_privkey),
                sighash_type: EcdsaSighashType::All,
            };

            let sig_other = bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa_low_r(&sighash, other_privkey),
                sighash_type: EcdsaSighashType::All,
            };

            if let Some(input) = spend_tx.input.get_mut(0) {
                apply_two_signatures_to_2of2_multisig_spend(
                    my_pubkey,
                    other_pubkey,
                    &sig_mine,
                    &sig_other,
                    input,
                    multisig_redeemscript,
                );
            }

            Ok(())
        } else if let Some(preimage) = &self.hash_preimage {
            log::info!("Signing legacy hashlock spend with preimage");

            let contract_redeemscript = self.contract_redeemscript.as_ref().ok_or_else(|| {
                WalletError::General("Missing contract_redeemscript for hashlock spend".to_string())
            })?;

            // For hashlock spend, the sighash must use the contract output value
            // (not funding_amount), because the UTXO being spent is the contract
            // output which has value = funding_amount - contract_tx_fee.
            let contract_output_value = self
                .contract_tx
                .output
                .first()
                .ok_or_else(|| {
                    WalletError::General("Contract tx has no output for hashlock spend".to_string())
                })?
                .value;

            let secp = bitcoin::secp256k1::Secp256k1::new();
            let sighash = bitcoin::secp256k1::Message::from_digest_slice(
                &SighashCache::new(&*spend_tx)
                    .p2wsh_signature_hash(
                        0,
                        contract_redeemscript,
                        contract_output_value,
                        EcdsaSighashType::All,
                    )
                    .map_err(|e| WalletError::General(format!("Sighash error: {:?}", e)))?[..],
            )
            .map_err(|e| WalletError::General(format!("Message creation error: {:?}", e)))?;

            let sig = bitcoin::ecdsa::Signature {
                signature: secp.sign_ecdsa_low_r(&sighash, &self.hashlock_privkey),
                sighash_type: EcdsaSighashType::All,
            };

            if let Some(input) = spend_tx.input.get_mut(0) {
                input.witness.push(sig.to_vec());
                input.witness.push(preimage);
                input.witness.push(contract_redeemscript.to_bytes());
            }

            Ok(())
        } else {
            Err(WalletError::General(
                "Cannot spend: need either other_privkey or preimage".to_string(),
            ))
        }
    }

    /// Get the vout of the contract output in the contract_tx.
    pub fn get_contract_output_vout(&self) -> u32 {
        if self.protocol == ProtocolVersion::Taproot && self.contract_tx.output.len() > 1 {
            for (i, output) in self.contract_tx.output.iter().enumerate() {
                if output.value == self.funding_amount {
                    return i as u32;
                }
            }
        }
        0
    }

    /// Signs a Taproot (MuSig2) spend transaction using cooperative key-path spend.
    fn sign_taproot_spend(&self, spend_tx: &mut Transaction) -> Result<(), WalletError> {
        if self.other_privkey.is_none() {
            if let Some(preimage) = &self.hash_preimage {
                log::info!("Signing taproot hashlock spend with preimage");

                let hashlock_script = self.hashlock_script.as_ref().ok_or_else(|| {
                    WalletError::General(
                        "Missing hashlock_script for taproot hashlock spend".to_string(),
                    )
                })?;
                let timelock_script = self.timelock_script.as_ref().ok_or_else(|| {
                    WalletError::General(
                        "Missing timelock_script for taproot hashlock spend".to_string(),
                    )
                })?;
                let internal_key = self.internal_key.ok_or_else(|| {
                    WalletError::General(
                        "Missing internal_key for taproot hashlock spend".to_string(),
                    )
                })?;

                let secp = bitcoin::secp256k1::Secp256k1::new();

                // Recreate taproot spend info to get control block
                let (_, taproot_spendinfo) = crate::protocol::contract2::create_taproot_script(
                    hashlock_script.clone(),
                    timelock_script.clone(),
                    internal_key,
                )?;

                let control_block = taproot_spendinfo
                    .control_block(&(
                        hashlock_script.clone(),
                        bitcoin::taproot::LeafVersion::TapScript,
                    ))
                    .ok_or_else(|| {
                        WalletError::General(
                            "Failed to get control block for hashlock script".to_string(),
                        )
                    })?;

                // Sighash for script-path spend
                let contract_vout = self.get_contract_output_vout() as usize;
                let contract_output = bitcoin::TxOut {
                    value: self.funding_amount,
                    script_pubkey: self.contract_tx.output[contract_vout].script_pubkey.clone(),
                };
                let prevouts = vec![contract_output];
                let prevouts_all = bitcoin::sighash::Prevouts::All(&prevouts);

                let mut sighasher = SighashCache::new(&mut *spend_tx);
                let leaf_hash = bitcoin::taproot::TapLeafHash::from_script(
                    hashlock_script,
                    bitcoin::taproot::LeafVersion::TapScript,
                );
                let sighash = sighasher
                    .taproot_script_spend_signature_hash(
                        0,
                        &prevouts_all,
                        leaf_hash,
                        bitcoin::TapSighashType::All,
                    )
                    .map_err(|e| WalletError::General(format!("Sighash error: {:?}", e)))?;

                let msg = bitcoin::secp256k1::Message::from(sighash);
                // Use hashlock_privkey for signing — it matches the pubkey in the hashlock script.
                // For maker: hashlock_privkey = tweakable_privkey + received_nonce
                // For taker: hashlock_privkey = my_privkey (set during swapcoin creation)
                let keypair = Keypair::from_secret_key(&secp, &self.hashlock_privkey);
                let signature = secp.sign_schnorr(&msg, &keypair);
                let tap_sig = bitcoin::taproot::Signature {
                    signature,
                    sighash_type: bitcoin::TapSighashType::All,
                };

                // Build witness: [sig] [preimage] [hashlock_script] [control_block]
                let mut witness = Witness::new();
                witness.push(tap_sig.to_vec());
                witness.push(preimage);
                witness.push(hashlock_script.as_bytes());
                witness.push(control_block.serialize());

                *sighasher.witness_mut(0).unwrap() = witness;

                return Ok(());
            }
            return Err(WalletError::General(
                "Cannot spend: need other_privkey for cooperative spend or preimage for hashlock"
                    .to_string(),
            ));
        }

        log::info!("Signing taproot cooperative spend (key-path)");

        let secp = bitcoin::secp256k1::Secp256k1::new();

        let my_privkey = self
            .my_privkey
            .ok_or_else(|| WalletError::General("Missing my_privkey".to_string()))?;
        let my_keypair = Keypair::from_secret_key(&secp, &my_privkey);

        let other_privkey = self
            .other_privkey
            .ok_or_else(|| WalletError::General("Missing other_privkey".to_string()))?;
        let other_keypair = Keypair::from_secret_key(&secp, &other_privkey);

        let tap_tweak = self
            .tap_tweak
            .ok_or_else(|| WalletError::General("Missing tap_tweak".to_string()))?;
        let internal_key = self
            .internal_key
            .ok_or_else(|| WalletError::General("Missing internal_key".to_string()))?;
        let hashlock_script = self
            .hashlock_script
            .as_ref()
            .ok_or_else(|| WalletError::General("Missing hashlock_script".to_string()))?;
        let timelock_script = self
            .timelock_script
            .as_ref()
            .ok_or_else(|| WalletError::General("Missing timelock_script".to_string()))?;

        let (my_sec_nonce, my_pub_nonce) = generate_new_nonce_pair_compat(my_keypair.public_key())
            .map_err(|e| {
                WalletError::General(format!("Failed to generate my nonce pair: {:?}", e))
            })?;
        let (other_sec_nonce, other_pub_nonce) =
            generate_new_nonce_pair_compat(other_keypair.public_key()).map_err(|e| {
                WalletError::General(format!("Failed to generate other nonce pair: {:?}", e))
            })?;

        let message = calculate_contract_sighash(
            spend_tx,
            self.funding_amount,
            hashlock_script,
            timelock_script,
            internal_key,
        )
        .map_err(|e| WalletError::General(format!("Failed to calculate sighash: {:?}", e)))?;

        // Order public keys deterministically
        let mut ordered_pubkeys = [my_keypair.public_key(), other_keypair.public_key()];
        ordered_pubkeys.sort_by_key(|a| a.serialize());

        let nonce_refs = if ordered_pubkeys[0] == my_keypair.public_key() {
            vec![&my_pub_nonce, &other_pub_nonce]
        } else {
            vec![&other_pub_nonce, &my_pub_nonce]
        };
        let aggregated_nonce = get_aggregated_nonce_compat(&nonce_refs);

        let my_partial_sig = generate_partial_signature_compat(
            message,
            &aggregated_nonce,
            my_sec_nonce,
            my_keypair,
            tap_tweak,
            ordered_pubkeys[0],
            ordered_pubkeys[1],
        )
        .map_err(|e| WalletError::General(format!("Failed to generate my partial sig: {:?}", e)))?;

        let other_partial_sig = generate_partial_signature_compat(
            message,
            &aggregated_nonce,
            other_sec_nonce,
            other_keypair,
            tap_tweak,
            ordered_pubkeys[0],
            ordered_pubkeys[1],
        )
        .map_err(|e| {
            WalletError::General(format!("Failed to generate other partial sig: {:?}", e))
        })?;

        // Aggregate partial signatures in correct order
        let partial_sigs = if ordered_pubkeys[0] == my_keypair.public_key() {
            vec![&my_partial_sig, &other_partial_sig]
        } else {
            vec![&other_partial_sig, &my_partial_sig]
        };

        let aggregated_sig = aggregate_partial_signatures_compat(
            message,
            aggregated_nonce,
            tap_tweak,
            partial_sigs,
            ordered_pubkeys[0],
            ordered_pubkeys[1],
        )
        .map_err(|e| WalletError::General(format!("Failed to aggregate signatures: {:?}", e)))?;

        let final_signature =
            TaprootSignature::from_slice(aggregated_sig.assume_valid().as_byte_array())
                .map_err(|e| WalletError::General(format!("Invalid taproot signature: {:?}", e)))?;

        let mut sighasher = SighashCache::new(spend_tx);
        *sighasher
            .witness_mut(0)
            .ok_or_else(|| WalletError::General("Failed to access witness".to_string()))? =
            Witness::p2tr_key_spend(&final_signature);

        log::info!("Successfully signed taproot cooperative spend");
        Ok(())
    }
}

/// Outgoing swap coin for both protocol versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutgoingSwapCoin {
    /// Protocol version for this swap coin.
    pub protocol: ProtocolVersion,

    /// Our private key for this swap.
    pub my_privkey: Option<SecretKey>,
    /// Our derived public key.
    pub my_pubkey: Option<PublicKey>,
    /// Counterparty's public key.
    pub other_pubkey: Option<PublicKey>,
    /// Counterparty's private key (received during handover).
    pub other_privkey: Option<SecretKey>,
    /// The funding transaction (sends to multisig).
    pub funding_tx: Option<Transaction>,
    /// The contract transaction (spends from funding).
    pub contract_tx: Transaction,
    /// Private key for timelock spending.
    pub timelock_privkey: SecretKey,
    /// The funding amount.
    pub funding_amount: Amount,
    /// The hash preimage (received during settlement).
    pub hash_preimage: Option<[u8; 32]>,
    /// Unique swap identifier.
    pub swap_id: Option<String>,

    /// Contract redeemscript (Legacy only).
    pub contract_redeemscript: Option<ScriptBuf>,
    /// Hashlock script (Taproot only).
    pub hashlock_script: Option<ScriptBuf>,
    /// Timelock script (Taproot only).
    pub timelock_script: Option<ScriptBuf>,
    /// Other party's contract signature (Legacy only).
    pub others_contract_sig: Option<bitcoin::ecdsa::Signature>,
    /// Taproot tap tweak.
    #[serde(with = "option_scalar_serde")]
    pub tap_tweak: Option<Scalar>,
    /// Taproot internal key.
    pub internal_key: Option<XOnlyPublicKey>,
    /// Destination reused by every timelock recovery retry.
    #[serde(default)]
    pub recovery_address: Option<Address<NetworkUnchecked>>,
    /// Negotiated swap feerate (sats/vB) at creation.
    #[serde(default = "default_negotiated_feerate")]
    pub negotiated_feerate: u64,
}

impl OutgoingSwapCoin {
    /// Create a new Legacy (ECDSA) outgoing swap coin.
    pub fn new_legacy(
        my_privkey: SecretKey,
        other_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: ScriptBuf,
        timelock_privkey: SecretKey,
        funding_amount: Amount,
        negotiated_feerate: u64,
    ) -> Self {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let my_pubkey = PublicKey {
            compressed: true,
            inner: bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &my_privkey),
        };

        OutgoingSwapCoin {
            protocol: ProtocolVersion::Legacy,
            my_privkey: Some(my_privkey),
            my_pubkey: Some(my_pubkey),
            other_pubkey: Some(other_pubkey),
            other_privkey: None,
            funding_tx: None,
            contract_tx,
            timelock_privkey,
            funding_amount,
            hash_preimage: None,
            swap_id: None,
            contract_redeemscript: Some(contract_redeemscript),
            hashlock_script: None,
            timelock_script: None,
            others_contract_sig: None,
            tap_tweak: None,
            internal_key: None,
            recovery_address: None,
            negotiated_feerate,
        }
    }

    /// Create a new Taproot (MuSig2) outgoing swap coin.
    pub fn new_taproot(
        timelock_privkey: SecretKey,
        hashlock_script: ScriptBuf,
        timelock_script: ScriptBuf,
        contract_tx: Transaction,
        funding_amount: Amount,
        negotiated_feerate: u64,
    ) -> Self {
        OutgoingSwapCoin {
            protocol: ProtocolVersion::Taproot,
            my_privkey: None,
            my_pubkey: None,
            other_pubkey: None,
            other_privkey: None,
            funding_tx: None,
            contract_tx,
            timelock_privkey,
            funding_amount,
            hash_preimage: None,
            swap_id: None,
            contract_redeemscript: None,
            hashlock_script: Some(hashlock_script),
            timelock_script: Some(timelock_script),
            others_contract_sig: None,
            tap_tweak: None,
            internal_key: None,
            recovery_address: None,
            negotiated_feerate,
        }
    }

    /// Returns our private key.
    pub fn privkey(&self) -> Result<SecretKey, WalletError> {
        self.my_privkey.ok_or_else(|| {
            WalletError::General("Outgoing swapcoin's privkey does not exist".to_string())
        })
    }

    /// Returns our public key.
    pub fn pubkey(&self) -> Result<PublicKey, WalletError> {
        self.my_pubkey.ok_or_else(|| {
            WalletError::General("Outgoing swapcoin's pubkey does not exist".to_string())
        })
    }

    /// Returns the counterparty's public key.
    pub fn other_pubkey(&self) -> Result<PublicKey, WalletError> {
        self.other_pubkey.ok_or_else(|| {
            WalletError::General("Outgoing swapcoin's other pubkey does not exist".to_string())
        })
    }

    /// Returns the hashlock script (Taproot).
    pub fn hashlock_script(&self) -> Option<&ScriptBuf> {
        self.hashlock_script.as_ref()
    }

    /// Returns the timelock script (Taproot).
    pub fn timelock_script(&self) -> Option<&ScriptBuf> {
        self.timelock_script.as_ref()
    }

    /// Returns the contract redeemscript (Legacy).
    pub fn contract_redeemscript(&self) -> Option<&ScriptBuf> {
        self.contract_redeemscript.as_ref()
    }

    /// Returns the tap tweak (Taproot).
    pub fn tap_tweak(&self) -> Result<Scalar, WalletError> {
        self.tap_tweak.ok_or_else(|| {
            WalletError::General("Outgoing swapcoin's tap tweak does not exist".to_string())
        })
    }

    /// Returns the internal key (Taproot).
    pub fn internal_key(&self) -> Result<XOnlyPublicKey, WalletError> {
        self.internal_key.ok_or_else(|| {
            WalletError::General("Outgoing swapcoin's internal key does not exist".to_string())
        })
    }

    /// Sets the preimage.
    pub fn set_preimage(&mut self, preimage: [u8; 32]) {
        self.hash_preimage = Some(preimage);
    }

    /// Sets the other party's private key.
    pub fn set_other_privkey(&mut self, privkey: SecretKey) {
        self.other_privkey = Some(privkey);
    }

    /// Sets the Taproot parameters.
    pub fn set_taproot_params(
        &mut self,
        my_privkey: SecretKey,
        my_pubkey: PublicKey,
        other_pubkey: PublicKey,
        internal_key: XOnlyPublicKey,
        tap_tweak: Scalar,
    ) {
        self.my_privkey = Some(my_privkey);
        self.my_pubkey = Some(my_pubkey);
        self.other_pubkey = Some(other_pubkey);
        self.internal_key = Some(internal_key);
        self.tap_tweak = Some(tap_tweak);
    }

    /// Extracts the timelock value from the script.
    pub fn get_timelock(&self) -> Option<u32> {
        if self.protocol == ProtocolVersion::Taproot {
            // Parse timelock from Taproot timelock script
            let timelock_script = self.timelock_script.as_ref()?;
            let script_bytes = timelock_script.as_bytes();

            if script_bytes.len() < 6 {
                return None;
            }

            // First byte is push opcode
            let locktime_len = script_bytes[0] as usize;
            if locktime_len == 0 || locktime_len > 5 || script_bytes.len() < locktime_len + 1 {
                return None;
            }

            // Parse little-endian locktime
            let mut locktime = 0u32;
            for i in 0..locktime_len {
                locktime |= (script_bytes[1 + i] as u32) << (i * 8);
            }

            Some(locktime)
        } else {
            // Legacy: parse from contract_redeemscript
            // The timelock is at a specific position in the script
            let redeemscript = self.contract_redeemscript.as_ref()?;
            crate::protocol::contract::read_contract_locktime(redeemscript)
                .ok()
                .map(|t| t as u32)
        }
    }

    /// Get the vout of the contract output in the contract_tx.
    ///
    /// For Taproot, the contract_tx may have multiple outputs (funding + change).
    /// Find the correct output by matching `funding_amount`.
    /// For Legacy (single-output contract tx), returns 0.
    pub fn get_contract_output_vout(&self) -> u32 {
        if self.protocol == ProtocolVersion::Taproot && self.contract_tx.output.len() > 1 {
            for (i, output) in self.contract_tx.output.iter().enumerate() {
                if output.value == self.funding_amount {
                    return i as u32;
                }
            }
        }
        0
    }

    /// Create a fully signed contract transaction for broadcast.
    ///
    /// For Legacy, the contract tx spends the P2WSH multisig funding output.
    /// It needs both our signature and the maker's signature applied to the witness.
    /// For Taproot, the contract tx is already self-contained (no multisig witness needed).
    pub fn create_signed_contract_tx(&self) -> Result<Transaction, WalletError> {
        let mut signed_tx = self.contract_tx.clone();

        match self.protocol {
            ProtocolVersion::Legacy => {
                let my_privkey = self.my_privkey.ok_or_else(|| {
                    WalletError::General("Missing my_privkey for contract tx signing".to_string())
                })?;
                let my_pubkey = self.my_pubkey.ok_or_else(|| {
                    WalletError::General("Missing my_pubkey for contract tx signing".to_string())
                })?;
                let other_pubkey = self.other_pubkey.ok_or_else(|| {
                    WalletError::General("Missing other_pubkey for contract tx signing".to_string())
                })?;
                let others_sig = self.others_contract_sig.ok_or_else(|| {
                    WalletError::General(
                        "Missing others_contract_sig for contract tx signing".to_string(),
                    )
                })?;

                let multisig_redeemscript = crate::protocol::contract::create_multisig_redeemscript(
                    &my_pubkey,
                    &other_pubkey,
                );

                let my_sig = crate::protocol::contract::sign_contract_tx(
                    &signed_tx,
                    &multisig_redeemscript,
                    self.funding_amount,
                    &my_privkey,
                )
                .map_err(|e| {
                    WalletError::General(format!("Failed to sign contract tx: {:?}", e))
                })?;

                if let Some(input) = signed_tx.input.get_mut(0) {
                    crate::protocol::contract::apply_two_signatures_to_2of2_multisig_spend(
                        &my_pubkey,
                        &other_pubkey,
                        &my_sig,
                        &others_sig,
                        input,
                        &multisig_redeemscript,
                    );
                }
            }
            ProtocolVersion::Taproot => {
                // Taproot contract txs don't need multisig witness signing
                // (they use different broadcast paths)
            }
        }

        Ok(signed_tx)
    }

    /// Sign a timelock recovery transaction.
    ///
    /// This signs a transaction that spends the contract output via the timelock path,
    /// allowing recovery of funds after the timelock has expired.
    pub fn sign_timelock_recovery(&self, mut tx: Transaction) -> Result<Transaction, WalletError> {
        use bitcoin::{
            secp256k1::Secp256k1,
            sighash::{Prevouts, SighashCache},
            taproot::LeafVersion,
            TapLeafHash, TapSighashType,
        };

        let secp = Secp256k1::new();

        // Get the contract output we're spending
        let contract_vout = self.get_contract_output_vout() as usize;
        let contract_output = self
            .contract_tx
            .output
            .get(contract_vout)
            .ok_or_else(|| WalletError::General("No output in contract tx".to_string()))?;

        if self.protocol == ProtocolVersion::Taproot {
            // Taproot: Sign using script-path spend with timelock script
            let timelock_script = self.timelock_script.as_ref().ok_or_else(|| {
                WalletError::General("No timelock script for Taproot swapcoin".to_string())
            })?;

            let internal_key = self.internal_key.ok_or_else(|| {
                WalletError::General("No internal key for Taproot swapcoin".to_string())
            })?;

            let _tap_tweak = self.tap_tweak.ok_or_else(|| {
                WalletError::General("No tap tweak for Taproot swapcoin".to_string())
            })?;

            // Create the control block for script-path spend
            // We need to build the TapTree from both scripts
            let hashlock_script = self.hashlock_script.as_ref().ok_or_else(|| {
                WalletError::General("No hashlock script for Taproot swapcoin".to_string())
            })?;

            let tap_leaf_hash = TapLeafHash::from_script(timelock_script, LeafVersion::TapScript);

            // Create sighash for script-path spend
            let mut sighash_cache = SighashCache::new(&tx);
            let sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    0,
                    &Prevouts::All(std::slice::from_ref(contract_output)),
                    tap_leaf_hash,
                    TapSighashType::Default,
                )
                .map_err(|e| WalletError::General(format!("Sighash error: {:?}", e)))?;

            // Sign with timelock privkey
            let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
            let keypair =
                bitcoin::secp256k1::Keypair::from_secret_key(&secp, &self.timelock_privkey);
            let sig = secp.sign_schnorr(&msg, &keypair);

            // Build witness for script-path spend
            // [signature] [timelock_script] [control_block]
            let taproot_builder = bitcoin::taproot::TaprootBuilder::new()
                .add_leaf(1, hashlock_script.clone())
                .map_err(|e| WalletError::General(format!("TaprootBuilder error: {:?}", e)))?
                .add_leaf(1, timelock_script.clone())
                .map_err(|e| WalletError::General(format!("TaprootBuilder error: {:?}", e)))?;

            let spend_info = taproot_builder.finalize(&secp, internal_key).map_err(|_| {
                WalletError::General("Failed to finalize TaprootBuilder".to_string())
            })?;

            let control_block = spend_info
                .control_block(&(timelock_script.clone(), LeafVersion::TapScript))
                .ok_or_else(|| {
                    WalletError::General(
                        "Failed to get control block for timelock script".to_string(),
                    )
                })?;

            let schnorr_sig = bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::Default,
            };

            let mut witness = bitcoin::Witness::new();
            witness.push(schnorr_sig.to_vec());
            witness.push(timelock_script.as_bytes());
            witness.push(control_block.serialize());

            tx.input[0].witness = witness;
        } else {
            // Legacy: Sign using OP_CSV path in redeemscript
            let redeemscript = self.contract_redeemscript.as_ref().ok_or_else(|| {
                WalletError::General("No redeemscript for Legacy swapcoin".to_string())
            })?;

            // Create sighash
            let mut sighash_cache = SighashCache::new(&tx);
            let sighash = sighash_cache
                .p2wsh_signature_hash(
                    0,
                    redeemscript,
                    contract_output.value,
                    bitcoin::sighash::EcdsaSighashType::All,
                )
                .map_err(|e| WalletError::General(format!("Sighash error: {:?}", e)))?;

            // Sign with timelock privkey
            let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_ecdsa_low_r(&msg, &self.timelock_privkey);

            let ecdsa_sig = bitcoin::ecdsa::Signature {
                signature: sig,
                sighash_type: bitcoin::sighash::EcdsaSighashType::All,
            };

            // Build witness for timelock path
            // [signature] [empty for timelock path] [redeemscript]
            let mut witness = bitcoin::Witness::new();
            witness.push(ecdsa_sig.to_vec());
            witness.push([]); // Empty element to indicate timelock path
            witness.push(redeemscript.as_bytes());

            tx.input[0].witness = witness;
        }
        Ok(tx)
    }
}

/// Watch-only view of a swap between two other parties.
///
/// Used by the taker to monitor openswaps between two makers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WatchOnlySwapCoin {
    /// Protocol version for this swap coin.
    pub protocol: ProtocolVersion,
    /// Sender's public key.
    pub sender_pubkey: PublicKey,
    /// Receiver's public key.
    pub receiver_pubkey: PublicKey,
    /// The contract transaction.
    pub contract_tx: Transaction,
    /// Contract redeemscript (Legacy) or placeholder (Taproot).
    pub contract_redeemscript: ScriptBuf,
    /// Hashlock script (Taproot only).
    pub hashlock_script: Option<ScriptBuf>,
    /// Timelock script (Taproot only).
    pub timelock_script: Option<ScriptBuf>,
    /// The funding amount.
    pub funding_amount: Amount,
}

impl WatchOnlySwapCoin {
    /// Returns the contract transaction ID.
    #[allow(dead_code)]
    pub fn contract_txid(&self) -> Txid {
        self.contract_tx.compute_txid()
    }

    /// Create a new Legacy watch-only swap coin.
    pub fn new_legacy(
        sender_pubkey: PublicKey,
        receiver_pubkey: PublicKey,
        contract_tx: Transaction,
        contract_redeemscript: ScriptBuf,
        funding_amount: Amount,
    ) -> Self {
        WatchOnlySwapCoin {
            protocol: ProtocolVersion::Legacy,
            sender_pubkey,
            receiver_pubkey,
            contract_tx,
            contract_redeemscript,
            hashlock_script: None,
            timelock_script: None,
            funding_amount,
        }
    }

    /// Create a new Taproot watch-only swap coin.
    pub fn new_taproot(
        sender_pubkey: PublicKey,
        receiver_pubkey: PublicKey,
        contract_tx: Transaction,
        hashlock_script: ScriptBuf,
        timelock_script: ScriptBuf,
        funding_amount: Amount,
    ) -> Self {
        WatchOnlySwapCoin {
            protocol: ProtocolVersion::Taproot,
            sender_pubkey,
            receiver_pubkey,
            contract_tx,
            contract_redeemscript: ScriptBuf::new(), // Not used in Taproot
            hashlock_script: Some(hashlock_script),
            timelock_script: Some(timelock_script),
            funding_amount,
        }
    }
}
