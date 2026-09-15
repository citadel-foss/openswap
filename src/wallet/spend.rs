//! Send regular Bitcoin payments.
//!
//! This module provides functionality for managing wallet transactions, including the creation of
//! direct sends. It leverages Bitcoin Core's RPC for wallet synchronization and implements various
//! parsing mechanisms for transaction inputs and outputs.

use bitcoin::{
    absolute::LockTime, script::PushBytesBuf, transaction::Version, Address, Amount, FeeRate,
    OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
};
use bitcoind::bitcoincore_rpc::json::ListUnspentResultEntry;

use crate::wallet::{api::UTXOSpendInfo, FidelityError};

use super::{error::WalletError, AddressType, Blockchain, Wallet};

/// Represents different destination options for a transaction.
#[derive(Debug, Clone, PartialEq)]
pub enum Destination {
    /// Sweep
    Sweep(Address),
    /// Multi
    Multi {
        /// List of outputs (address, amounts)
        outputs: Vec<(Address, Amount)>,
        /// OP_RETURN data, used to create a OP_RETURN TxOut
        op_return_data: Option<Box<[u8]>>,
        /// Address type for change output (defaults to P2WPKH if None)
        change_address_type: AddressType,
    },
}

impl Wallet {
    /// API to perform spending from wallet UTXOs, including descriptor coins and swap coins.
    ///
    /// The caller needs to specify a list of UTXO data and their corresponding `spend_info`.
    /// These can be extracted using various `list_utxo_*` Wallet APIs.
    ///
    /// ### Note
    /// This function should not be used to spend Fidelity Bonds or contract UTXOs
    /// (e.g., Hashlock or Timelock contracts). These UTXOs will be automatically skipped
    /// and not considered when creating the transaction.
    ///
    /// ### Behavior
    /// - If [Destination::Sweep] is used, the function creates a transaction for the maximum possible
    ///   value to the specified Address.
    /// - If [Destination::Multi] is used, a custom value is sent, and any remaining funds
    ///   are held in a change address, if applicable.
    pub fn spend_from_wallet(
        &mut self,
        feerate: f64,
        destination: Destination,
        coins_to_spend: &[(ListUnspentResultEntry, UTXOSpendInfo)],
    ) -> Result<Transaction, WalletError> {
        log::info!("Creating Direct-Spend from Wallet.");

        let mut coins = Vec::<(ListUnspentResultEntry, UTXOSpendInfo)>::new();

        for coin in coins_to_spend {
            // filter all contract and fidelity utxos.
            if let UTXOSpendInfo::FidelityBondCoin { .. }
            | UTXOSpendInfo::HashlockContract { .. }
            | UTXOSpendInfo::TimelockContract { .. } = coin.1
            {
                log::warn!("Skipping Fidelity Bond or Contract UTXO.");
                continue;
            } else {
                coins.push(coin.to_owned());
            }
        }

        let tx = self.spend_coins(&coins, destination, feerate)?;

        Ok(tx)
    }

    /// Redeem a Fidelity Bond.
    /// This function creates a spending transaction from the fidelity bond, signs and broadcasts it.
    /// Returns the txid of the spending tx, and mark the bond as spent.
    pub fn redeem_fidelity(
        &mut self,
        idx: u32,
        feerate: f64,
        destination_address_type: AddressType,
    ) -> Result<(), WalletError> {
        let bond = self
            .store
            .fidelity_bond
            .get(idx as usize)
            .ok_or(FidelityError::BondDoesNotExist)?;

        if bond.is_spent {
            log::info!("Fidelity bond already spent.");
            return Ok(());
        }

        let expired_fidelity_spend_info = UTXOSpendInfo::FidelityBondCoin {
            index: idx,
            input_value: bond.amount,
        };

        let change_addr = &self.get_next_internal_addresses(1, destination_address_type)?[0];
        let destination = Destination::Sweep(change_addr.clone());

        // Find utxo corresponding to expired fidelity bond.
        let utxo = self
            .list_fidelity_spend_info()
            .into_iter()
            .find(|(_, spend_info)| *spend_info == expired_fidelity_spend_info)
            .map(|(utxo, _)| utxo);

        let utxo = match utxo {
            Some(utxo) => utxo,
            None => {
                // If no UTXO is found for the expired fidelity bond, it means the bond was already spent,
                // but its `redeemed` flag was never updated. This is a known issue where the redemption
                // transaction was broadcasted, but the flag remained unset.
                // As a temporary fix, we mark the bond as redeemed and exit gracefully.
                log::info!("Fidelity bond already spent.");

                let bond = self
                    .store
                    .fidelity_bond
                    .get_mut(idx as usize)
                    .ok_or(FidelityError::BondDoesNotExist)?;
                bond.is_spent = true;

                return Ok(());
            }
        };

        let tx = self.spend_coins(&[(utxo, expired_fidelity_spend_info)], destination, feerate)?;
        let txid = self.send_tx(&tx)?;

        log::info!("Fidelity redeem transaction broadcasted. txid: {txid}");

        // No need to wait for confirmation as that will delay the rpc call. Just send back the txid.

        // mark is_spent
        {
            let bond = self
                .store
                .fidelity_bond
                .get_mut(idx as usize)
                .ok_or(FidelityError::BondDoesNotExist)?;

            bond.is_spent = true;
        }

        Ok(())
    }

    /// Creates a [`Transaction`] spending given UTXOs to a [`Destination`] with fee calculated from `feerate`.
    pub fn spend_coins(
        &mut self,
        coins: &[(ListUnspentResultEntry, UTXOSpendInfo)],
        destination: Destination,
        feerate: f64,
    ) -> Result<Transaction, WalletError> {
        // Set the Anti-Fee-Snipping locktime
        let current_height = self.blockchain.get_block_count()?;
        let lock_time = LockTime::from_height(current_height as u32)?;

        let mut tx = Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![],
            output: vec![],
        };

        let mut total_input_value = Amount::ZERO;
        let mut total_witness_size = 0;
        for (utxo_data, spend_info) in coins {
            match spend_info {
                UTXOSpendInfo::SeedCoin { .. } | UTXOSpendInfo::SweptCoin { .. } => {
                    tx.input.push(TxIn {
                        previous_output: OutPoint::new(utxo_data.txid, utxo_data.vout),
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                        script_sig: ScriptBuf::new(),
                    });
                    total_witness_size += spend_info.estimate_witness_size();
                    total_input_value += utxo_data.amount;
                }
                UTXOSpendInfo::IncomingSwapCoin { .. } | UTXOSpendInfo::OutgoingSwapCoin { .. } => {
                    tx.input.push(TxIn {
                        previous_output: OutPoint::new(utxo_data.txid, utxo_data.vout),
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                        script_sig: ScriptBuf::new(),
                    });
                    total_witness_size += spend_info.estimate_witness_size();
                    total_input_value += utxo_data.amount;
                }
                UTXOSpendInfo::FidelityBondCoin { index, input_value } => {
                    let bond = self
                        .store
                        .fidelity_bond
                        .get(*index as usize)
                        .ok_or(FidelityError::BondDoesNotExist)?;
                    if bond.is_spent {
                        return Err(FidelityError::BondAlreadyRedeemed.into());
                    }

                    tx.input.push(TxIn {
                        previous_output: bond.outpoint,
                        sequence: Sequence::ZERO,
                        script_sig: ScriptBuf::new(),
                        witness: Witness::new(),
                    });
                    total_witness_size += spend_info.estimate_witness_size();
                    total_input_value += *input_value;
                }
                UTXOSpendInfo::TimelockContract {
                    swapcoin_multisig_redeemscript,
                    input_value,
                } => {
                    let outgoing_swap_coin = self
                        .find_outgoing_swapcoin_by_multisig(swapcoin_multisig_redeemscript)
                        .ok_or_else(|| {
                            WalletError::General(
                                "outgoing swapcoin not found in wallet store".to_string(),
                            )
                        })?;
                    let timelock = outgoing_swap_coin.get_timelock().ok_or_else(|| {
                        WalletError::General("outgoing swapcoin has no timelock".to_string())
                    })?;
                    tx.input.push(TxIn {
                        previous_output: OutPoint {
                            txid: outgoing_swap_coin.contract_tx.compute_txid(),
                            vout: 0,
                        },
                        sequence: Sequence(timelock),
                        witness: Witness::new(),
                        script_sig: ScriptBuf::new(),
                    });
                    total_witness_size += spend_info.estimate_witness_size();
                    total_input_value += *input_value;
                }
                UTXOSpendInfo::HashlockContract {
                    swapcoin_multisig_redeemscript,
                    input_value,
                } => {
                    let incoming_swap_coin = self
                        .find_incoming_swapcoin_by_multisig(swapcoin_multisig_redeemscript)
                        .ok_or_else(|| {
                            WalletError::General(
                                "incoming swapcoin not found in wallet store".to_string(),
                            )
                        })?;
                    tx.input.push(TxIn {
                        previous_output: OutPoint {
                            txid: incoming_swap_coin.contract_tx.compute_txid(),
                            vout: 0,
                        },
                        sequence: Sequence::ZERO,
                        witness: Witness::new(),
                        script_sig: ScriptBuf::new(),
                    });
                    total_witness_size += spend_info.estimate_witness_size();
                    total_input_value += *input_value;
                }
            }
        }

        // Reject sub-1 sat/vB up front; `feerate as u64` would truncate it to a
        // zero rate and build a transaction that never relays.
        if feerate < 1.0 {
            return Err(WalletError::General(format!(
                "feerate {feerate} sat/vB is below the 1 sat/vB minimum"
            )));
        }
        let rate = FeeRate::from_sat_per_vb(feerate as u64).ok_or_else(|| {
            WalletError::General(format!("feerate {feerate} sat/vB is out of range"))
        })?;

        match destination {
            Destination::Sweep(addr) => {
                // Send Max Amount case
                let txout = TxOut {
                    script_pubkey: addr.script_pubkey(),
                    value: Amount::ZERO, // Temp Value
                };
                tx.output.push(txout);
                let base_size = tx.base_size();
                let vsize = (base_size * 4 + total_witness_size + 2).div_ceil(4); // base * 4 + witness size + marker + flag

                // An absurdly high feerate overflows the fee amount, so the
                // conversion fails instead of panicking.
                let fee = rate.fee_vb(vsize as u64).ok_or_else(|| {
                    WalletError::General(format!(
                        "fee at {feerate} sat/vB overflows for a {vsize} vB transaction"
                    ))
                })?;

                // I don't know if this case is even possible?
                if fee > total_input_value {
                    return Err(WalletError::InsufficientFund {
                        available: total_input_value.to_sat(),
                        required: fee.to_sat(),
                    });
                }
                tx.output[0].value = total_input_value - fee;
            }
            Destination::Multi {
                outputs,
                op_return_data,
                change_address_type,
            } => {
                let mut total_output_value = Amount::ZERO;
                for (address, amount) in outputs {
                    total_output_value += amount;
                    let txout = TxOut {
                        script_pubkey: address.script_pubkey(),
                        value: amount,
                    };
                    tx.output.push(txout);
                }
                if let Some(data) = op_return_data {
                    let mut push_bytes = PushBytesBuf::new();
                    push_bytes.extend_from_slice(&data).map_err(|_| {
                        WalletError::General(
                            "Failed to add OP_RETURN data to transaction output".to_owned(),
                        )
                    })?;
                    let op_return_script = ScriptBuf::new_op_return(&push_bytes);
                    let txout = TxOut {
                        script_pubkey: op_return_script,
                        value: Amount::ZERO,
                    };
                    tx.output.push(txout);
                }
                // Use specified change address type, default to P2WPKH
                let change_type = change_address_type;
                let internal_spk =
                    self.get_next_internal_addresses(1, change_type)?[0].script_pubkey();
                let minimal_nondust = internal_spk.minimal_non_dust();

                let mut tx_wchange = tx.clone();
                tx_wchange.output.push(TxOut {
                    value: Amount::ZERO, // Adjusted later
                    script_pubkey: internal_spk.clone(),
                });

                let base_wchange = tx_wchange.base_size();
                let vsize_wchange = (base_wchange * 4 + total_witness_size + 2).div_ceil(4); // base * 4 + witness size + marker + flag

                // Honor the caller's feerate here too; a fixed hardcoded fee
                // strands every ordinary send and funding tx in a busy mempool.
                let fee_wchange = rate.fee_vb(vsize_wchange as u64).ok_or_else(|| {
                    WalletError::General(format!(
                        "fee at {feerate} sat/vB overflows for a {vsize_wchange} vB transaction"
                    ))
                })?;

                let remaining_wchange =
                    if let Some(diff) = total_input_value.checked_sub(total_output_value) {
                        if let Some(diff) = diff.checked_sub(fee_wchange) {
                            diff
                        } else {
                            return Err(WalletError::InsufficientFund {
                                available: total_input_value.to_sat(),
                                required: (total_output_value + fee_wchange).to_sat(),
                            });
                        }
                    } else {
                        return Err(WalletError::InsufficientFund {
                            available: total_input_value.to_sat(),
                            required: (total_output_value + fee_wchange).to_sat(),
                        });
                    };

                if remaining_wchange > minimal_nondust {
                    tx.output.push(TxOut {
                        script_pubkey: internal_spk,
                        value: remaining_wchange,
                    });
                } else {
                    log::info!(
                        "Remaining change {} sats is below dust threshold. Skipping change output. (fee: {} sats)",
                        remaining_wchange.to_sat(),
                        fee_wchange.to_sat()
                    );
                }
            }
        }

        self.sign_transaction(&mut tx, coins.iter().map(|(_, usi)| usi.clone()))?;

        // The actual fee is the difference between the sum of output amounts from the total input amount
        let total_output_value = tx
            .output
            .iter()
            .map(|txo| txo.value)
            .try_fold(Amount::ZERO, |acc, val| acc.checked_add(val))
            .expect("output amount summation overflowed");
        let actual_fee = total_input_value - total_output_value;
        let tx_size = tx.weight().to_vbytes_ceil();
        let actual_feerate = actual_fee.to_sat() as f32 / tx_size as f32;

        log::info!(
            "Created tx, txid: {} | Size: {} vB | Fee: {} sats | Feerate: {:.2} sat/vB",
            tx.compute_txid(),
            tx_size,
            actual_fee.to_sat(),
            actual_feerate
        );

        if actual_feerate < feerate as f32 {
            log::warn!(
                "Actual feerate {:.2} sat/vB is below requested {:.2} sat/vB",
                actual_feerate,
                feerate
            );
        }

        Ok(tx)
    }
}
