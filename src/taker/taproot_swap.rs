//! Taproot (MuSig2) specific swap methods for the Taker.

use std::time::Duration;

use bitcoin::{
    hashes::Hash,
    secp256k1::{self, rand::rngs::OsRng, Secp256k1, SecretKey},
    Amount, Network, OutPoint, PublicKey, ScriptBuf,
};

use crate::{
    protocol::{
        common_messages::{MakerToTakerMessage, TakerToMakerMessage},
        contract2::{create_hashlock_script, create_timelock_script},
        taproot_messages::{SerializableScalar, TaprootContractData},
    },
    utill::{read_message, send_message, MIN_FEE_RATE},
    wallet::{
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin},
        Blockchain, Wallet,
    },
};

use super::{
    api::Taker,
    error::{breach_or_wallet_error, TakerError},
    swap_tracker::SwapPhase,
};

impl Taker {
    /// Build contract data from a previous maker's response (for forwarding to the next maker).
    #[allow(clippy::type_complexity)]
    fn exchange_build_from_response(
        prev: &TaprootContractData,
    ) -> (
        Vec<PublicKey>,
        Vec<ScriptBuf>,
        Vec<ScriptBuf>,
        Vec<secp256k1::XOnlyPublicKey>,
        Vec<SerializableScalar>,
        Vec<bitcoin::Transaction>,
        Vec<Amount>,
    ) {
        (
            prev.pubkeys.clone(),
            vec![prev.hashlock_script.clone()],
            prev.timelock_scripts.clone(),
            prev.internal_keys.clone(),
            prev.tap_tweaks.clone(),
            prev.contract_txs.clone(),
            prev.amounts.clone(),
        )
    }
    /// Create Taproot (MuSig2) contract transactions and swapcoins
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn funding_create_taproot(
        wallet: &mut Wallet,
        multisig_pubkeys: &[PublicKey],
        hashlock_pubkeys: &[PublicKey],
        preimage: [u8; 32],
        locktime: u16,
        send_amount: Amount,
        swap_id: &str,
        network: Network,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
        reference_height: Option<u32>,
    ) -> Result<Vec<OutgoingSwapCoin>, TakerError> {
        let secp = Secp256k1::new();
        let mut swapcoins = Vec::new();

        // Taproot uses OP_CHECKLOCKTIMEVERIFY (absolute block height), so convert
        // the relative locktime offset to an absolute height.
        // Use the reference_height from negotiation for consistency, falling back
        // to current height if not available.
        let base_height = match reference_height {
            Some(h) => h,
            None => wallet
                .blockchain
                .get_block_count()
                .map_err(|e| TakerError::General(format!("RPC error: {:?}", e)))?
                as u32,
        };
        let absolute_locktime = base_height + locktime as u32;
        let mut contract_data = Vec::new();
        let mut taproot_addresses = Vec::new();

        for (multisig_pubkey, hashlock_pubkey) in
            multisig_pubkeys.iter().zip(hashlock_pubkeys.iter())
        {
            // Generate our keypair for this swap
            let my_privkey = SecretKey::new(&mut OsRng);
            let my_pubkey = PublicKey {
                compressed: true,
                inner: secp256k1::PublicKey::from_secret_key(&secp, &my_privkey),
            };

            // Convert to x-only pubkeys for Taproot
            let keypair = secp256k1::Keypair::from_secret_key(&secp, &my_privkey);
            let my_xonly = secp256k1::XOnlyPublicKey::from_keypair(&keypair).0;
            // Use the tweaked hashlock_pubkey (= tweakable_point + nonce * G).
            // The nonce is sent to the Maker so it can reconstruct hashlock_privkey.
            let (other_xonly, _parity) = hashlock_pubkey.inner.x_only_public_key();

            // Create hashlock and timelock scripts
            // For Taproot, use SHA256 hash of the preimage
            let sha256_hash: [u8; 32] =
                bitcoin::hashes::sha256::Hash::hash(&preimage).to_byte_array();
            let hashlock_script = create_hashlock_script(&sha256_hash, &other_xonly);
            let locktime_abs = bitcoin::absolute::LockTime::from_height(absolute_locktime)
                .map_err(|e| TakerError::General(format!("Invalid locktime: {:?}", e)))?;
            let timelock_script = create_timelock_script(locktime_abs, &my_xonly);

            let builder = bitcoin::taproot::TaprootBuilder::new()
                .add_leaf(1, hashlock_script.clone())
                .map_err(|e| TakerError::General(format!("Failed to add hashlock leaf: {:?}", e)))?
                .add_leaf(1, timelock_script.clone())
                .map_err(|e| {
                    TakerError::General(format!("Failed to add timelock leaf: {:?}", e))
                })?;

            // Create aggregated MuSig2 pubkey for internal key (allows cooperative key-path spend)
            // Order pubkeys lexicographically to match signing order
            let mut ordered_pubkeys = [my_pubkey, *multisig_pubkey];
            ordered_pubkeys.sort_by_key(|a| a.inner.serialize());
            let internal_key = crate::protocol::musig_interface::get_aggregated_pubkey_compat(
                ordered_pubkeys[0].inner,
                ordered_pubkeys[1].inner,
            )
            .map_err(|e| {
                TakerError::General(format!("Failed to create aggregated pubkey: {:?}", e))
            })?;

            let tap_info = builder
                .finalize(&secp, internal_key)
                .map_err(|e| TakerError::General(format!("Failed to finalize taproot: {:?}", e)))?;

            taproot_addresses.push(bitcoin::Address::p2tr_tweaked(
                tap_info.output_key(),
                network,
            ));
            contract_data.push((
                my_privkey,
                my_pubkey,
                *multisig_pubkey,
                hashlock_script,
                timelock_script,
                internal_key,
                tap_info.tap_tweak().to_scalar(),
            ));
        }

        let funding_result = wallet.create_funding_txes(
            send_amount,
            &taproot_addresses,
            MIN_FEE_RATE,
            manually_selected_outpoints,
            None,
            None,
        )?;

        for (
            (contract_tx, &output_pos),
            (
                my_privkey,
                my_pubkey,
                multisig_pubkey,
                hashlock_script,
                timelock_script,
                internal_key,
                tap_tweak,
            ),
        ) in funding_result
            .funding_txes
            .iter()
            .zip(funding_result.payment_output_positions.iter())
            .zip(contract_data)
        {
            let contract_amount = contract_tx.output[output_pos as usize].value;

            // Create outgoing swapcoin with Taproot data.
            let mut outgoing = OutgoingSwapCoin::new_taproot(
                my_privkey,
                hashlock_script,
                timelock_script,
                contract_tx.clone(),
                contract_amount,
            );
            outgoing.swap_id = Some(swap_id.to_string());
            outgoing.set_taproot_params(
                my_privkey,
                my_pubkey,
                multisig_pubkey,
                internal_key,
                tap_tweak,
            );

            swapcoins.push(outgoing);
        }

        Ok(swapcoins)
    }

    /// Broadcast outgoing contract transactions and exchange contract data
    /// with makers (Taproot protocol).
    ///
    /// This is the single entrypoint for the taproot exchange phase:
    /// 1. Broadcast our outgoing contract txs and wait for confirmation
    /// 2. Exchange contract data with each maker in the route
    pub(crate) fn exchange_taproot(&mut self) -> Result<(), TakerError> {
        // Ping every maker for the life of the march: while we negotiate one
        // hop, the others must not read our silence as a dropped swap.
        let _heartbeat = self
            .swap_state()
            .ok()
            .map(|swap| swap.id.clone())
            .and_then(|swap_id| self.start_route_heartbeat(&swap_id));

        // Makers verify that contract txs are on-chain before creating their
        // own outgoing, so we must broadcast first.
        self.swap_state_mut()?.phase = SwapPhase::FundsBroadcast;
        self.persist_swap(SwapPhase::FundsBroadcast)?;
        // funding_broadcast opens maker 0's connection before the
        // confirmation wait and keeps the whole route warm with keepalives,
        // returning the live maker 0 stream for the contract exchange.
        let maker0_stream = self.funding_broadcast()?;

        // Phase 2: Exchange contract data with makers.
        log::info!("Exchanging contract data with makers...");

        let num_makers = self.swap_state()?.makers.len();
        let hashlock_nonces = self.swap_state()?.hashlock_nonces.clone();
        let mut received_contracts: Vec<TaprootContractData> = Vec::new();

        let mut maker0_stream = Some(maker0_stream);

        for i in 0..num_makers {
            let maker_address = self.swap_state()?.makers[i].address.to_string();
            let mut stream = if i == 0 {
                // Reuse the warm, already-handshaked connection from funding_broadcast.
                maker0_stream
                    .take()
                    .ok_or_else(|| TakerError::General("Missing warm maker 0 stream".to_string()))?
            } else {
                let mut stream = self.net_connect(&maker_address)?;
                self.net_handshake(&mut stream)?;
                stream
            };
            self.swap_state_mut()?.makers[i]
                .taproot_exchange_mut()?
                .connected = true;

            let (
                pubkeys,
                hashlock_scripts,
                timelock_scripts,
                internal_keys,
                tap_tweaks,
                contract_txs,
                amounts,
            ) = if i == 0 {
                self.exchange_build_from_outgoing()?
            } else {
                Self::exchange_build_from_response(&received_contracts[i - 1])
            };

            #[cfg(feature = "integration-test")]
            let (pubkeys, timelock_scripts, internal_keys, tap_tweaks, contract_txs, amounts) = {
                let (
                    mut pubkeys,
                    mut timelock_scripts,
                    mut internal_keys,
                    mut tap_tweaks,
                    mut contract_txs,
                    mut amounts,
                ) = (
                    pubkeys,
                    timelock_scripts,
                    internal_keys,
                    tap_tweaks,
                    contract_txs,
                    amounts,
                );

                if self.behavior == super::api::TakerBehavior::DuplicateFundingOutpoint {
                    if let Some(first) = contract_txs.first().cloned() {
                        log::warn!(
                            "Test behavior: duplicating Taproot contract outpoint for maker {}",
                            i
                        );
                        pubkeys.push(pubkeys[0]);
                        timelock_scripts.push(timelock_scripts[0].clone());
                        internal_keys.push(internal_keys[0]);
                        tap_tweaks.push(tap_tweaks[0].clone());
                        contract_txs.push(first);
                        amounts.push(amounts[0]);
                    }
                }

                if self.behavior == super::api::TakerBehavior::InvalidTaprootContractAmount {
                    amounts = vec![Amount::from_sat(50_000); amounts.len()];
                }

                (
                    pubkeys,
                    timelock_scripts,
                    internal_keys,
                    tap_tweaks,
                    contract_txs,
                    amounts,
                )
            };

            let secp = Secp256k1::new();
            let my_privkey = SecretKey::new(&mut OsRng);
            let my_pubkey = PublicKey {
                compressed: true,
                inner: secp256k1::PublicKey::from_secret_key(&secp, &my_privkey),
            };

            let next_hop_point = if i + 1 < self.swap_state()?.makers.len() {
                self.swap_state()?.makers[i + 1]
                    .tweakable_point
                    .unwrap_or(my_pubkey)
            } else {
                my_pubkey
            };

            log::info!(
                "Sending contract data to maker {}: {} pubkeys, {} contract_txs",
                i,
                pubkeys.len(),
                contract_txs.len()
            );

            let contract_data = TaprootContractData::new(
                self.swap_state()?.id.clone(),
                pubkeys,
                next_hop_point,
                internal_keys,
                tap_tweaks,
                hashlock_scripts.first().cloned().unwrap_or_default(),
                timelock_scripts,
                contract_txs,
                amounts,
                hashlock_nonces.get(i).copied(),
                if i + 1 < num_makers {
                    hashlock_nonces.get(i + 1).copied()
                } else {
                    None
                },
            );
            let incoming_amount =
                contract_data
                    .amounts
                    .iter()
                    .try_fold(Amount::ZERO, |total, amount| {
                        total.checked_add(*amount).ok_or_else(|| {
                            TakerError::General("Taproot incoming amount overflow".to_string())
                        })
                    })?;

            #[cfg(feature = "integration-test")]
            if self.behavior == super::api::TakerBehavior::CloseAtSendersContract {
                log::warn!(
                    "Test behavior: closing at sender's contract (before sending to maker {})",
                    i
                );
                return Err(TakerError::General(
                    "Test: closing at sender's contract".to_string(),
                ));
            }

            send_message(
                &mut stream,
                &TakerToMakerMessage::TaprootContractData(Box::new(contract_data)),
            )?;
            self.swap_state_mut()?.makers[i]
                .taproot_exchange_mut()?
                .contract_data_sent = true;

            let msg_bytes = read_message(&mut stream)?;
            let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes)?;

            match msg {
                MakerToTakerMessage::TaprootContractData(maker_contract) => {
                    log::info!(
                        "Received Taproot contract data from maker {}: {} contract_txs",
                        i,
                        maker_contract.contract_txs.len()
                    );

                    #[cfg(feature = "integration-test")]
                    if self.behavior == super::api::TakerBehavior::CloseAtSendersContractFromMaker {
                        log::warn!(
                            "Test behavior: closing after receiving maker {}'s contract data",
                            i
                        );
                        return Err(TakerError::General(
                            "Test: closing at sender's contract from maker".to_string(),
                        ));
                    }

                    // Verify contract data before creating swapcoins
                    let expected_locktime = self.swap_state()?.makers[i].negotiated_timelock;
                    let expected_amount = self.expected_amount_for_hop(i, incoming_amount);
                    self.verify_maker_taproot_contract(
                        &maker_contract,
                        i,
                        next_hop_point,
                        expected_locktime,
                        expected_amount,
                    )?;

                    // Verify hashlock pubkey matches expected key
                    if i + 1 < num_makers {
                        // Non-last maker: pubkey should be derived from next_hop_point + nonce
                        if let (Some(nonce), Some(next_tp)) = (
                            hashlock_nonces.get(i + 1),
                            self.swap_state()?.makers[i + 1].tweakable_point,
                        ) {
                            crate::protocol::contract2::check_taproot_hashlock_has_pubkey(
                                &maker_contract.hashlock_script,
                                &next_tp,
                                nonce,
                            )
                            .map_err(|e| {
                                TakerError::General(format!(
                                    "Maker {} Taproot hashlock pubkey verification failed: {:?}",
                                    i, e
                                ))
                            })?;
                        }
                    } else {
                        // Last maker: hashlock pubkey should be taker's own key
                        let (expected_xonly, _) = my_pubkey.inner.x_only_public_key();
                        let mut hl_instructions = maker_contract.hashlock_script.instructions();
                        // Skip first 3 instructions to get to the pubkey
                        for _ in 0..3 {
                            hl_instructions.next();
                        }
                        if let Some(Ok(bitcoin::script::Instruction::PushBytes(pk_bytes))) =
                            hl_instructions.next()
                        {
                            let script_xonly =
                                secp256k1::XOnlyPublicKey::from_slice(pk_bytes.as_bytes())
                                    .map_err(|_| {
                                        TakerError::General(format!(
                                            "Last maker {} Taproot hashlock has invalid pubkey",
                                            i
                                        ))
                                    })?;
                            if script_xonly != expected_xonly {
                                return Err(TakerError::General(format!(
                                    "Last maker {} Taproot hashlock pubkey doesn't match taker's key",
                                    i
                                )));
                            }
                        }
                    }

                    self.swap_state_mut()?.makers[i]
                        .taproot_exchange_mut()?
                        .maker_contract_received = true;

                    let is_last_maker = i == num_makers - 1;
                    if is_last_maker {
                        // Only the last maker's contract is addressed to the taker.
                        self.exchange_create_incoming(&maker_contract, my_privkey)?;
                        self.persist_incoming_swapcoins()?;
                    } else {
                        // Intermediate contracts (maker→maker) are watch-only for the taker.
                        let mut watchonly = Vec::new();
                        for (j, contract_tx) in maker_contract.contract_txs.iter().enumerate() {
                            let sender_pubkey =
                                maker_contract.pubkeys.get(j).cloned().unwrap_or(my_pubkey);
                            let funding_amount = maker_contract
                                .amounts
                                .get(j)
                                .cloned()
                                .unwrap_or(Amount::ZERO);

                            watchonly.push(WatchOnlySwapCoin::new_taproot(
                                sender_pubkey,
                                maker_contract.next_hop_point,
                                contract_tx.clone(),
                                maker_contract.hashlock_script.clone(),
                                maker_contract.timelock_scripts[j].clone(),
                                funding_amount,
                            ));
                        }

                        let swap_id = self.swap_state()?.id.clone();
                        {
                            let mut wallet = self.write_wallet()?;
                            wallet.add_watchonly_swapcoins(&swap_id, watchonly.clone());
                            wallet.save_to_disk()?;
                        }
                        self.swap_state_mut()?.watchonly_swapcoins.extend(watchonly);
                    }

                    // Wait for this maker's funding (contract) tx to be broadcast and
                    // confirmed before moving on. In Taproot the contract tx IS the
                    // funding tx; the maker broadcasts it before responding, but it may
                    // not yet be visible/confirmed on the taker's node. Without this
                    // wait, finalization races ahead and the incoming-swapcoin sweep
                    // fails with "swept 0/1 incoming swapcoins".
                    let maker_funding_txids: Vec<bitcoin::Txid> = maker_contract
                        .contract_txs
                        .iter()
                        .map(|tx| tx.compute_txid())
                        .collect();
                    let required_confirms = self.swap_state()?.params.required_confirms;
                    log::info!(
                        "Waiting for maker {}'s Taproot funding to confirm ({} tx), keeping the swap alive...",
                        i,
                        maker_funding_txids.len()
                    );
                    self.wait_for_funding_confirmation(
                        &maker_funding_txids,
                        required_confirms,
                        super::api::MAKER_FUNDING_TIMEOUT,
                    )?;

                    received_contracts.push(*maker_contract);
                    self.swap_state_mut()?.makers[i]
                        .taproot_exchange_mut()?
                        .swapcoins_created = true;
                    self.swap_state_mut()?.makers[i]
                        .taproot_exchange_mut()?
                        .maker_funding_confirmed = true;
                    self.persist_progress()?;
                    #[cfg(debug_assertions)]
                    log::debug!(
                        "[TAPROOT_HOP] Source: taker::taproot_swap::exchange_taproot | SwapID: {} | MakerIndex: {} | ContractTxs: {} | RequiredConfirms: {} | IncomingTotal: {} | WatchOnlyTotal: {}",
                        self.swap_state()?.id,
                        i,
                        maker_funding_txids.len(),
                        required_confirms,
                        self.swap_state()?.incoming_swapcoins.len(),
                        self.swap_state()?.watchonly_swapcoins.len()
                    );
                }
                _ => {
                    return Err(TakerError::General(format!(
                        "Unexpected message from maker {}: expected TaprootContractData",
                        i
                    )));
                }
            }
        }

        // SP6-T: All makers responded, incoming/watchonly swapcoins created.
        self.persist_swap(super::swap_tracker::SwapPhase::ContractsExchanged)?;

        Ok(())
    }

    /// Build contract data from our outgoing swapcoins (first hop).
    #[allow(clippy::type_complexity)]
    fn exchange_build_from_outgoing(
        &self,
    ) -> Result<
        (
            Vec<PublicKey>,
            Vec<ScriptBuf>,
            Vec<ScriptBuf>,
            Vec<secp256k1::XOnlyPublicKey>,
            Vec<SerializableScalar>,
            Vec<bitcoin::Transaction>,
            Vec<Amount>,
        ),
        TakerError,
    > {
        let mut pubkeys = Vec::new();
        let mut hashlock_scripts = Vec::new();
        let mut timelock_scripts = Vec::new();
        let mut internal_keys = Vec::new();
        let mut tap_tweaks = Vec::new();
        let mut contract_txs = Vec::new();
        let mut amounts = Vec::new();

        for swapcoin in &self.swap_state()?.outgoing_swapcoins {
            if let Some(pubkey) = swapcoin.my_pubkey {
                pubkeys.push(pubkey);
            }

            if let Some(hl_script) = swapcoin.hashlock_script() {
                hashlock_scripts.push(hl_script.clone());
            }

            if let Some(tl_script) = swapcoin.timelock_script() {
                timelock_scripts.push(tl_script.clone());
            }

            contract_txs.push(swapcoin.contract_tx.clone());
            amounts.push(swapcoin.funding_amount);

            internal_keys.push(swapcoin.internal_key.ok_or_else(|| {
                TakerError::General("Outgoing swapcoin missing internal_key".to_string())
            })?);
            let tweak_bytes = swapcoin
                .tap_tweak
                .map(|s| s.to_be_bytes())
                .unwrap_or([0u8; 32]);
            tap_tweaks.push(SerializableScalar::from_bytes(tweak_bytes.to_vec()));
        }
        if internal_keys.is_empty() {
            return Err(TakerError::General("No outgoing swapcoins".to_string()));
        }

        Ok((
            pubkeys,
            hashlock_scripts,
            timelock_scripts,
            internal_keys,
            tap_tweaks,
            contract_txs,
            amounts,
        ))
    }

    /// Create swapcoins from received Taproot contract data.
    fn exchange_create_incoming(
        &mut self,
        contract: &TaprootContractData,
        my_privkey: SecretKey,
    ) -> Result<(), TakerError> {
        let secp = Secp256k1::new();
        let my_pubkey = PublicKey {
            compressed: true,
            inner: secp256k1::PublicKey::from_secret_key(&secp, &my_privkey),
        };
        let preimage = self.swap_state()?.preimage;

        for (j, contract_tx) in contract.contract_txs.iter().enumerate() {
            let amount = contract_tx
                .output
                .first()
                .map(|output| output.value)
                .ok_or_else(|| {
                    TakerError::General("No output in Taproot contract tx".to_string())
                })?;

            // The last maker's outgoing hashlock uses taker's my_pubkey (un-tweaked, no nonce),
            // so my_privkey is the correct signing key for the hashlock script.
            let mut swapcoin = IncomingSwapCoin::new_taproot(
                my_privkey,
                contract.hashlock_script.clone(),
                contract.timelock_scripts[j].clone(),
                contract_tx.clone(),
                amount,
            );

            let other_pubkey = contract.pubkeys.get(j).cloned().ok_or_else(|| {
                TakerError::General("No pubkey in Taproot contract data".to_string())
            })?;

            swapcoin.my_privkey = Some(my_privkey);
            swapcoin.my_pubkey = Some(my_pubkey);
            swapcoin.other_pubkey = Some(other_pubkey);
            swapcoin.internal_key = Some(contract.internal_keys[j]);
            swapcoin.tap_tweak = Some(contract.tap_tweak_scalar(j)?);

            swapcoin.swap_id = Some(contract.id.clone());
            swapcoin.set_preimage(preimage);
            self.swap_state_mut()?.incoming_swapcoins.push(swapcoin);
        }

        // PaySwap: pin the receiver before the coins are persisted.
        self.payment_stamp_targets()?;
        Ok(())
    }

    /// Broadcast contract transactions (Taproot) and wait for them to confirm.
    ///
    /// Opens maker 0's connection *before* the confirmation wait and keeps the
    /// route alive with `WaitingFundingConfirmation` keepalives, returning the
    /// live maker 0 stream so the contract exchange can reuse it.
    fn funding_broadcast(&mut self) -> Result<std::net::TcpStream, TakerError> {
        log::info!("Broadcasting contract transactions...");

        let wallet = self.write_wallet()?;

        for swapcoin in &self.swap_state()?.outgoing_swapcoins {
            let txid = wallet.send_tx(&swapcoin.contract_tx).map_err(|e| {
                TakerError::General(format!("Failed to broadcast contract tx: {:?}", e))
            })?;

            log::info!("Broadcast contract tx: {}", txid);

            let vout = swapcoin
                .contract_tx
                .output
                .iter()
                .position(|o| o.value == swapcoin.funding_amount)
                .unwrap_or(0) as u32;
            let outpoint = OutPoint { txid, vout };
            let script_pubkey = swapcoin.contract_tx.output[vout as usize]
                .script_pubkey
                .clone();
            // A contract we cannot watch is a contract we cannot defend:
            // fail the swap step instead of continuing blind.
            self.watch_service
                .register_watch_request(outpoint, script_pubkey)
                .map_err(|e| {
                    TakerError::General(format!(
                        "watch registration for {outpoint} failed (watcher gone): {e}"
                    ))
                })?;
        }

        wallet.save_to_disk()?;
        drop(wallet);

        let contract_txids: Vec<_> = self
            .swap_state()?
            .outgoing_swapcoins
            .iter()
            .map(|sc| sc.contract_tx.compute_txid())
            .collect();
        let required_confirms = self.swap_state()?.params.required_confirms;

        // Open and handshake maker 0 up front so its operational connection can
        // stay warm and be reused after the taker's funding confirms.
        let swap_id = self.swap_state()?.id.clone();
        let maker0_address = self.swap_state()?.makers[0].address.to_string();
        let mut stream = self.net_connect(&maker0_address)?;
        self.net_handshake(&mut stream)?;

        self.wait_for_funding_confirmation(
            &contract_txids,
            required_confirms,
            crate::utill::TX_BROADCAST_TIMEOUT,
        )?;

        #[cfg(debug_assertions)]
        log::debug!(
           "[FUNDING_STATE] Source: taker::taproot_swap::funding_broadcast | SwapID: {} | Protocol: Taproot | ContractTxs: {} | RequiredConfirms: {} | Status: confirmed",
            swap_id,
            contract_txids.len(),
            required_confirms
        );
        log::info!("Contract transactions broadcast and confirmed");
        Ok(stream)
    }

    /// Wait for contract (funding) txs to reach `required_confirms`.
    /// Waits on a fresh backend connection so no wallet lock is held for the
    /// wait's duration; the shared wait bounds arrival and confirmation.
    fn wait_for_funding_confirmation(
        &self,
        contract_txids: &[bitcoin::Txid],
        required_confirms: u32,
        arrival_timeout: Duration,
    ) -> Result<(), TakerError> {
        if required_confirms == 0 || contract_txids.is_empty() {
            return Ok(());
        }

        let chain = self.read_wallet()?.blockchain.new_connection()?;
        crate::wallet::wait_for_tx_confirmation(
            &chain,
            contract_txids,
            required_confirms,
            arrival_timeout,
            None,
            // Inert on taproot: no detector is started for it, and none is
            // needed — no counterparty can spend the contract output
            // mid-swap. Kept only for the shared wait helper's signature.
            Some(&|| {
                self.breach_detector
                    .as_ref()
                    .is_some_and(|d| d.is_breached())
            }),
        )
        .map_err(breach_or_wallet_error)?;
        Ok(())
    }
}
