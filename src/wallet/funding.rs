//! Various mechanisms of creating the swap funding transactions.
//!
//! This module contains routines for creating funding transactions within a wallet. It leverages
//! Bitcoin Core's RPC methods for wallet interactions, including `walletcreatefundedpsbt`

use bitcoin::{
    secp256k1::rand::{rngs::OsRng, RngCore},
    Address, Amount, OutPoint, Transaction,
};

use crate::{utill::calculate_fee_sats, wallet::Destination};

use super::Wallet;

use super::{api::infer_address_type, error::WalletError, AddressType};

#[derive(Debug)]
pub struct CreateFundingTxesResult {
    pub funding_txes: Vec<Transaction>,
    pub payment_output_positions: Vec<u32>,
    pub total_miner_fee: u64,
}

impl Wallet {
    // Attempts to create the funding transactions.
    /// Returns Ok(None) if there was no error but the wallet was unable to create funding txes
    pub fn create_funding_txes(
        &mut self,
        openswap_amount: Amount,
        destinations: &[Address],
        fee_rate: f64,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
        excluded_outpoints: Option<Vec<OutPoint>>,
        max_inputs_per_tx: Option<usize>,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        let ret = self.create_funding_txes_random_amounts(
            openswap_amount,
            destinations,
            fee_rate,
            manually_selected_outpoints,
            excluded_outpoints,
            max_inputs_per_tx,
        );

        if ret.is_err() {
            log::error!("Failed to create funding txes {ret:?}");
        }

        ret

        // let ret = self.create_funding_txes_utxo_max_sends(openswap_amount, destinations, fee_rate);
        // if ret.is_ok() {
        //     log::info!(target: "wallet", "created funding txes with fully-spending utxos");
        //     return ret;
        // }

        // let ret =
        //     self.create_funding_txes_use_biggest_utxos(openswap_amount, destinations, fee_rate);
        // if ret.is_ok() {
        //     log::info!(target: "wallet", "created funding txes with using the biggest utxos");
        //     return ret;
        // }
    }

    fn generate_amount_fractions_without_correction(
        count: usize,
        total_amount: Amount,
        lower_limit: u64,
    ) -> Result<Vec<f32>, WalletError> {
        for _ in 0..100000 {
            let mut knives = (1..count)
                .map(|_| (OsRng.next_u32() as f32) / (u32::MAX as f32))
                .collect::<Vec<f32>>();
            knives.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));

            let mut fractions = Vec::<f32>::new();
            let mut last: f32 = 1.0;
            for k in knives {
                fractions.push(last - k);
                last = k;
            }
            fractions.push(last);

            if fractions
                .iter()
                .all(|f| *f * (total_amount.to_sat() as f32) > (lower_limit as f32))
            {
                return Ok(fractions);
            }
        }
        Err(WalletError::General(
            "Unable to generate amount fractions, probably amount too small".to_string(),
        ))
    }

    pub(crate) fn generate_amount_fractions(
        count: usize,
        total_amount: Amount,
    ) -> Result<Vec<u64>, WalletError> {
        let mut output_values = Wallet::generate_amount_fractions_without_correction(
            count,
            total_amount,
            5000, //use 5000 satoshi as the lower limit for now
                  //there should always be enough to pay miner fees
        )?
        .iter()
        .map(|f| (*f * (total_amount.to_sat() as f32)) as u64)
        .collect::<Vec<u64>>();

        //rounding errors mean usually 1 or 2 satoshis are lost, add them back

        //this calculation works like this:
        //o = [a, b, c, ...]             | list of output values
        //t = openswap amount            | total desired value
        //a' <-- a + (t - (a+b+c+...))   | assign new first output value
        //a' <-- a + (t -a-b-c-...)      | rearrange
        //a' <-- t - b - c -...          |
        // Float rounding can push the fractions past the total; failing here
        // beats wrapping into a bogus first output value. After this the sum
        // equals the total by construction.
        let rest = output_values.iter().skip(1).sum::<u64>();
        let first = total_amount.to_sat().checked_sub(rest).ok_or_else(|| {
            log::error!(
                "Amount fractions sum {} exceeds total {} sats — refusing to build funding outputs",
                rest,
                total_amount.to_sat()
            );
            WalletError::General("amount fractions exceed total funding amount".to_string())
        })?;
        *output_values.first_mut().expect("value expected") = first;

        Ok(output_values)
    }

    // This function creates funding transactions with random amounts
    // The total `openswap_amount` is randomly distributed among number of destinations.
    fn create_funding_txes_random_amounts(
        &mut self,
        openswap_amount: Amount,
        destinations: &[Address],
        fee_rate: f64,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
        excluded_outpoints: Option<Vec<OutPoint>>,
        max_inputs_per_tx: Option<usize>,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        let output_values = Wallet::generate_amount_fractions(destinations.len(), openswap_amount)?;

        // Flow of Lock Step 1. Unlock all unspent UTXOs
        self.unlock_all_utxos();

        // FLow of Lock Step 2. Lock all unspendable UTXOs
        self.lock_unspendable_utxos()?;

        let mut funding_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        let mut total_miner_fee = 0;
        let mut locked_utxos = Vec::new();

        // Here, we are gonna use a closure to ensure proper cleanup on error (since we need a rollback)
        let result = (|| {
            for (i, (address, &output_value)) in
                destinations.iter().zip(output_values.iter()).enumerate()
            {
                let remaining = Amount::from_sat(output_value);
                let manual_for_split = if i == 0 {
                    manually_selected_outpoints.clone()
                } else {
                    None
                };
                let selected_utxo = self.coin_select(
                    remaining,
                    fee_rate,
                    infer_address_type(&address.script_pubkey()),
                    manual_for_split,
                    excluded_outpoints.clone(),
                )?;
                if let Some(max_inputs) = max_inputs_per_tx {
                    if selected_utxo.len() > max_inputs {
                        return Err(WalletError::General(format!(
                            "Funding transaction selected {} inputs, above negotiated maximum {}",
                            selected_utxo.len(),
                            max_inputs
                        )));
                    }
                }

                let outpoints: Vec<OutPoint> = selected_utxo
                    .iter()
                    .map(|(utxo, _)| OutPoint::new(utxo.txid, utxo.vout))
                    .collect();
                // Flow of Lock Step 3. Lock the selected UTXOs immediately after selection
                self.lock_utxos(&outpoints);
                // Flow of Lock Step 4. Store the locked UTXOs for later unlocking in case of error
                locked_utxos.extend(outpoints);

                // Here, prepare coins for spend_coins API, since this API would require owned data to avoid lifetime issues
                let coins_to_spend = selected_utxo
                    .iter()
                    .map(|(unspent, spend_info)| (unspent.clone(), spend_info.clone()))
                    .collect::<Vec<_>>();

                // Create destination with output - currently, destination is an array with a single address, i.e only a single transaction.
                let outputs = vec![(address.clone(), Amount::from_sat(output_value))];
                let destination = Destination::Multi {
                    outputs,
                    op_return_data: None,
                    change_address_type: AddressType::P2TR,
                };

                // Creates and Signs Transactions via the spend_coins API
                let funding_tx = self.spend_coins(&coins_to_spend, destination, fee_rate)?;

                let tx_size = funding_tx.weight().to_vbytes_ceil();

                // Record this transaction in our results.
                let payment_pos = 0; // assuming the payment output position is 0

                funding_txes.push(funding_tx);
                payment_output_positions.push(payment_pos);

                let fee_amount = calculate_fee_sats(tx_size);

                total_miner_fee += fee_amount;
            }
            Ok(CreateFundingTxesResult {
                funding_txes,
                payment_output_positions,
                total_miner_fee,
            })
        })();

        self.unlock_all_utxos();

        #[cfg(debug_assertions)]
        if let Ok(funding) = &result {
            log::debug!(
                "[FUNDING_STATE] Source: wallet::funding::create_funding_txes_random_amounts | Wallet: {} | Amount: {} | Destinations: {} | FundingTxs: {} | MinerFee: {} | ManualUtxos: {} | ExcludedUtxos: {}",
                self.get_name(),
                openswap_amount.to_sat(),
                destinations.len(),
                funding.funding_txes.len(),
                funding.total_miner_fee,
                manually_selected_outpoints
                    .as_ref()
                    .map(Vec::len)
                    .unwrap_or_default(),
                excluded_outpoints
                    .as_ref()
                    .map(Vec::len)
                    .unwrap_or_default()
            );
        }

        result
    }
}
