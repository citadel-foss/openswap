//! Legacy (ECDSA) specific swap methods for the Taker.

use std::time::Duration;

use bitcoin::{
    hashes::{hash160::Hash as Hash160, Hash},
    secp256k1::{self, rand::rngs::OsRng, Secp256k1, SecretKey},
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Transaction, Txid,
};

use crate::{
    bip324_stream::Bip324Stream,
    protocol::{
        common_messages::{MakerToTakerMessage, TakerToMakerMessage},
        contract::{
            create_contract_redeemscript, create_multisig_redeemscript, create_senders_contract_tx,
            read_pubkeys_from_multisig_redeemscript, sign_contract_tx,
        },
        error::ProtocolError,
        legacy_messages::{
            ContractTxInfoForRecvr, ContractTxInfoForSender, FundingTxInfo, NextHopInfo,
            ProofOfFunding, ReqContractSigsForRecvr, ReqContractSigsForSender,
            RespContractSigsForRecvrAndSender, SenderContractTxInfo,
        },
    },
    utill::{generate_keypair, generate_maker_keys, MIN_FEE_RATE},
    wallet::{
        swapcoin::{IncomingSwapCoin, OutgoingSwapCoin, WatchOnlySwapCoin},
        Wallet,
    },
};

use super::{
    api::Taker,
    error::{breach_or_wallet_error, TakerError},
};

/// Delay to allow the Maker to broadcast its funding transactions before we poll.
const MAKER_BROADCAST_DELAY: Duration = Duration::from_secs(2);

impl Taker {
    /// Create Legacy (ECDSA) funding transactions and swapcoins (static version).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn funding_create_legacy(
        wallet: &mut Wallet,
        multisig_pubkeys: &[PublicKey],
        hashlock_pubkeys: &[PublicKey],
        hashvalue: Hash160,
        locktime: u16,
        send_amount: Amount,
        swap_id: &str,
        network: Network,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
    ) -> Result<Vec<OutgoingSwapCoin>, TakerError> {
        let secp = Secp256k1::new();
        let mut swapcoins = Vec::new();
        let mut contract_data = Vec::new();
        let mut openswap_addresses = Vec::new();

        for (multisig_pubkey, hashlock_pubkey) in
            multisig_pubkeys.iter().zip(hashlock_pubkeys.iter())
        {
            let my_multisig_privkey = SecretKey::new(&mut OsRng);
            let my_multisig_pubkey = PublicKey {
                compressed: true,
                inner: secp256k1::PublicKey::from_secret_key(&secp, &my_multisig_privkey),
            };

            let multisig_redeemscript =
                create_multisig_redeemscript(&my_multisig_pubkey, multisig_pubkey);

            let (timelock_pubkey, timelock_privkey) = generate_keypair();

            let contract_redeemscript = create_contract_redeemscript(
                hashlock_pubkey,
                &timelock_pubkey,
                &hashvalue,
                &locktime,
            );

            openswap_addresses.push(bitcoin::Address::p2wsh(&multisig_redeemscript, network));
            contract_data.push((
                my_multisig_privkey,
                *multisig_pubkey,
                timelock_privkey,
                contract_redeemscript,
            ));
        }

        let funding_result = wallet.create_funding_txes(
            send_amount,
            &openswap_addresses,
            MIN_FEE_RATE,
            manually_selected_outpoints,
            None,
        )?;

        for (
            (funding_tx, &output_pos),
            (my_multisig_privkey, multisig_pubkey, timelock_privkey, contract_redeemscript),
        ) in funding_result
            .funding_txes
            .iter()
            .zip(funding_result.payment_output_positions.iter())
            .zip(contract_data)
        {
            let funding_outpoint = OutPoint {
                txid: funding_tx.compute_txid(),
                vout: output_pos,
            };
            let funding_amount = funding_tx.output[output_pos as usize].value;

            let contract_tx = create_senders_contract_tx(
                funding_outpoint,
                funding_amount,
                &contract_redeemscript,
            )?;

            let mut outgoing = OutgoingSwapCoin::new_legacy(
                my_multisig_privkey,
                multisig_pubkey,
                contract_tx,
                contract_redeemscript,
                timelock_privkey,
                funding_amount,
            );
            outgoing.swap_id = Some(swap_id.to_string());
            outgoing.funding_tx = Some(funding_tx.clone());

            swapcoins.push(outgoing);
        }

        Ok(swapcoins)
    }

    /// Execute the multi-hop Legacy openswap flow.
    pub(crate) fn exchange_legacy(&mut self) -> Result<(), TakerError> {
        log::info!("Starting multi-hop Legacy swap with ProofOfFunding flow");

        let swap = self.swap_state()?;
        let swap_id = swap.id.clone();
        let maker_count = swap.makers.len();
        let tx_count = swap.params.tx_count;

        // Ping every maker for the life of the march: while we negotiate one
        // hop, the others must not read our silence as a dropped swap.
        let _heartbeat = self.start_route_heartbeat(&swap_id);

        let mut prev_senders_info: Option<Vec<SenderContractTxInfo>> = None;
        // Taker's own keys for the last hop (set during last iteration)
        let mut taker_multisig_privkeys: Option<Vec<SecretKey>> = None;
        let mut taker_hashlock_privkeys: Option<Vec<SecretKey>> = None;
        // Track the previous hop's confirmation height to verify timelock staggering.
        let mut prev_confirm_height: u32 = 0;

        // Flags to skip already-completed steps when retrying a maker iteration
        // after spare substitution (e.g., taker's funding is already on-chain).
        let mut taker_funding_broadcast = false;
        let mut _taker_funding_confirmed = false;

        let mut maker_idx = 0;
        'exchange: while maker_idx < maker_count {
            let maker_address = self.swap_state()?.makers[maker_idx].address.to_string();

            log::info!(
                "Processing maker {} of {}: {}",
                maker_idx + 1,
                maker_count,
                maker_address
            );

            // Reuse the authenticated channel negotiated earlier instead of
            // opening a fresh (unauthenticated) connection per phase.
            let mut stream = self.take_connection(maker_idx)?;
            self.swap_state_mut()?.makers[maker_idx]
                .legacy_exchange_mut()?
                .connected = true;
            // Determine our position
            let is_first_peer = maker_idx == 0;
            let is_last_peer = maker_idx == maker_count - 1;

            let outgoing_locktime = self.swap_state()?.makers[maker_idx].negotiated_timelock as u16;

            let (
                funding_txs,
                contract_redeemscripts,
                multisig_redeemscripts,
                multisig_nonces,
                hashlock_nonces,
            ) = if is_first_peer {
                let outgoing = &self.swap_state()?.outgoing_swapcoins;
                if outgoing.is_empty() {
                    return Err(TakerError::General(
                        "No outgoing swapcoins for first hop".to_string(),
                    ));
                }

                let funding_txs: Vec<Transaction> = outgoing
                    .iter()
                    .map(|sc| {
                        sc.funding_tx.clone().ok_or_else(|| {
                            TakerError::General("Outgoing swapcoin missing funding_tx".to_string())
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let contract_rs: Vec<ScriptBuf> = outgoing
                    .iter()
                    .map(|sc| {
                        sc.contract_redeemscript.clone().ok_or_else(|| {
                            TakerError::General(
                                "Outgoing swapcoin missing contract_redeemscript".to_string(),
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                let multisig_rs: Vec<ScriptBuf> = outgoing
                    .iter()
                    .map(|sc| {
                        let my_pub = sc.my_pubkey.ok_or_else(|| {
                            TakerError::General("Outgoing swapcoin missing my_pubkey".to_string())
                        })?;
                        let other_pub = sc.other_pubkey.ok_or_else(|| {
                            TakerError::General(
                                "Outgoing swapcoin missing other_pubkey".to_string(),
                            )
                        })?;
                        Ok(create_multisig_redeemscript(&my_pub, &other_pub))
                    })
                    .collect::<Result<Vec<_>, TakerError>>()?;

                (
                    funding_txs,
                    contract_rs,
                    multisig_rs,
                    self.swap_state()?.multisig_nonces.clone(),
                    self.swap_state()?.hashlock_nonces.clone(),
                )
            } else {
                let prev_info = prev_senders_info.as_ref().ok_or_else(|| {
                    TakerError::General("No previous maker info for multi-hop".to_string())
                })?;

                let funding_txs: Vec<Transaction> = prev_info
                    .iter()
                    .map(|info| info.funding_tx.clone())
                    .collect();
                let contract_rs: Vec<ScriptBuf> = prev_info
                    .iter()
                    .map(|info| info.contract_redeemscript.clone())
                    .collect();
                let multisig_rs: Vec<ScriptBuf> = prev_info
                    .iter()
                    .map(|info| info.multisig_redeemscript.clone())
                    .collect();
                let multisig_nonces: Vec<SecretKey> =
                    prev_info.iter().map(|info| info.multisig_nonce).collect();
                let hashlock_nonces: Vec<SecretKey> =
                    prev_info.iter().map(|info| info.hashlock_nonce).collect();

                (
                    funding_txs,
                    contract_rs,
                    multisig_rs,
                    multisig_nonces,
                    hashlock_nonces,
                )
            };

            #[cfg(feature = "integration-test")]
            let skip_sender_contract_sigs =
                is_first_peer && self.behavior == super::api::TakerBehavior::SkipSenderContractSigs;
            #[cfg(not(feature = "integration-test"))]
            let skip_sender_contract_sigs = false;

            if skip_sender_contract_sigs {
                // IT path: leave the maker's prevout-to-contract map
                // empty, but continue through real funding confirmation and
                // ProofOfFunding construction to exercise its fail-closed check.
                log::warn!(
                    "Test behavior: skipping sender contract signature request before funding"
                );
            }

            if is_first_peer && !skip_sender_contract_sigs {
                log::info!(
                    "Step 1: Requesting sender contract signatures from maker {}",
                    maker_idx
                );
                let sender_sigs = self.exchange_req_sender_sigs(
                    &mut stream,
                    &swap_id,
                    &self.swap_state()?.outgoing_swapcoins,
                    outgoing_locktime,
                )?;
                let swap = self.swap_state_mut()?;
                for (swapcoin, sig) in swap.outgoing_swapcoins.iter_mut().zip(sender_sigs) {
                    swapcoin.others_contract_sig = Some(sig);
                }
                let exch = self.swap_state_mut()?.makers[maker_idx].legacy_exchange_mut()?;
                exch.sender_sigs_requested = true;
                exch.sender_sigs_received = true;
            }

            if is_first_peer && !taker_funding_broadcast {
                if !self.watch_service.is_alive() {
                    return Err(TakerError::General(
                        "watchtower exited before funding".into(),
                    ));
                }
                log::info!("Broadcasting funding transactions and waiting for confirmation");
                {
                    let mut wallet = self.write_wallet()?;

                    // Persist the outgoing swapcoins (now carrying the maker's
                    // contract signatures) to disk BEFORE broadcasting the funding txs.
                    // Without this, a crash after broadcast leaves the wallet
                    // store missing `others_contract_sig`, blocking timelock recovery.
                    for swapcoin in &self.swap_state()?.outgoing_swapcoins {
                        wallet.add_outgoing_swapcoin(swapcoin);
                    }
                    wallet.save_to_disk()?;

                    for swapcoin in &self.swap_state()?.outgoing_swapcoins {
                        let funding_tx = swapcoin.funding_tx.as_ref().ok_or_else(|| {
                            TakerError::General("Outgoing swapcoin missing funding_tx".to_string())
                        })?;
                        wallet.send_tx(funding_tx).map_err(|e| {
                            TakerError::General(format!("Failed to broadcast funding tx: {:?}", e))
                        })?;
                    }
                    wallet.save_to_disk()?;
                }
                // Funding txs are now on-chain — mark the phase transition.
                // Point of no return. Persist nonces needed for legacy recovery.
                taker_funding_broadcast = true;
                self.swap_state_mut()?.makers[maker_idx]
                    .legacy_exchange_mut()?
                    .prev_funding_broadcast = true;
                self.swap_state_mut()?.phase = super::api::SwapPhase::FundsBroadcast;
                self.persist_swap(super::swap_tracker::SwapPhase::FundsBroadcast)?;
                let funding_txids: Vec<_> = self
                    .swap_state()?
                    .outgoing_swapcoins
                    .iter()
                    .filter_map(|sc| sc.funding_tx.as_ref().map(|tx| tx.compute_txid()))
                    .collect();
                let required_confirms = self.swap_state()?.params.required_confirms;
                prev_confirm_height = self.wait_for_legacy_funding_confirmation(
                    &funding_txids,
                    required_confirms,
                    crate::utill::TX_BROADCAST_TIMEOUT,
                )?;
                _taker_funding_confirmed = true;
                self.swap_state_mut()?.makers[maker_idx]
                    .legacy_exchange_mut()?
                    .prev_funding_confirmed = true;
                self.persist_progress()?;

                // Register outgoing funding outpoints as sentinels with the breach detector.
                // Each sentinel maps a funding outpoint to its expected contract txid.
                // Only a spend matching the contract txid is adversarial.
                let sentinels: Vec<(OutPoint, bitcoin::Txid, bitcoin::ScriptBuf)> = self
                    .swap_state()?
                    .outgoing_swapcoins
                    .iter()
                    .map(|sc| {
                        let contract_input = sc.contract_tx.input.first().ok_or_else(|| {
                            TakerError::General(
                                "Outgoing swapcoin contract tx has no inputs".to_string(),
                            )
                        })?;
                        let funding_outpoint = contract_input.previous_output;
                        let funding_tx = sc.funding_tx.as_ref().ok_or_else(|| {
                            TakerError::General("Outgoing swapcoin missing funding_tx".to_string())
                        })?;
                        let funding_spk = funding_tx
                            .output
                            .get(funding_outpoint.vout as usize)
                            .ok_or_else(|| {
                                TakerError::General(format!(
                                    "Funding tx has no output at vout {}",
                                    funding_outpoint.vout
                                ))
                            })?
                            .script_pubkey
                            .clone();
                        Ok((funding_outpoint, sc.contract_tx.compute_txid(), funding_spk))
                    })
                    .collect::<Result<Vec<_>, TakerError>>()?; // An error here means something big is internally broken
                if let Some(ref detector) = self.breach_detector {
                    detector.add_sentinels(&self.watch_service, &sentinels)?;
                }
                #[cfg(feature = "integration-test")]
                if self.behavior == super::api::TakerBehavior::StopWatcherAfterSentinels
                    && self.watch_service.is_alive()
                {
                    self.watch_service.stop_watcher_for_test();
                }
            }

            log::info!("Sending ProofOfFunding to maker {}", maker_idx);

            let (
                next_multisig_pubkeys,
                next_multisig_nonces,
                next_hashlock_pubkeys,
                next_hashlock_nonces,
            ) = if !is_last_peer {
                let next_maker = &self.swap_state()?.makers[maker_idx + 1];
                let tweakable_point = next_maker.tweakable_point.ok_or_else(|| {
                    TakerError::General(format!("Maker {} missing tweakable_point", maker_idx + 1))
                })?;
                generate_maker_keys(&tweakable_point, tx_count)?
            } else {
                // Last hop: taker is the next peer, generate our own keys
                let mut multisig_pubkeys = Vec::new();
                let mut multisig_privkeys = Vec::new();
                let mut nonces = Vec::new();
                let mut hashlock_pubkeys = Vec::new();
                let mut hashlock_privkeys = Vec::new();
                for _ in 0..tx_count {
                    let (multisig_pubkey, multisig_privkey) = generate_keypair();
                    let (hashlock_pubkey, hashlock_privkey) = generate_keypair();
                    multisig_pubkeys.push(multisig_pubkey);
                    multisig_privkeys.push(multisig_privkey);
                    nonces.push(SecretKey::new(&mut OsRng));
                    hashlock_pubkeys.push(hashlock_pubkey);
                    hashlock_privkeys.push(hashlock_privkey);
                }
                taker_multisig_privkeys = Some(multisig_privkeys);
                taker_hashlock_privkeys = Some(hashlock_privkeys);
                (multisig_pubkeys, nonces.clone(), hashlock_pubkeys, nonces)
            };

            let (receivers_contract_txs, senders_contract_txs_info) = self
                .exchange_send_proof_of_funding(
                    &mut stream,
                    &swap_id,
                    maker_idx,
                    &funding_txs,
                    &contract_redeemscripts,
                    &multisig_redeemscripts,
                    &multisig_nonces,
                    &hashlock_nonces,
                    &next_multisig_pubkeys,
                    &next_hashlock_pubkeys,
                    &next_multisig_nonces,
                    &next_hashlock_nonces,
                    outgoing_locktime,
                )?;
            {
                let exch = self.swap_state_mut()?.makers[maker_idx].legacy_exchange_mut()?;
                exch.proof_of_funding_sent = true;
                exch.maker_contracts_received = true;
            }
            self.persist_progress()?;

            // Verify the receiver contract txs are identical to the sender contract txs.
            // Both should produce the same txid (same outpoint, value, redeemscript).
            // A mismatch means the Maker sent a tampered receiver contract.
            {
                let expected_txids: Vec<Txid> = if is_first_peer {
                    self.swap_state()?
                        .outgoing_swapcoins
                        .iter()
                        .map(|sc| sc.contract_tx.compute_txid())
                        .collect()
                } else {
                    prev_senders_info
                        .as_ref()
                        .ok_or_else(|| {
                            TakerError::General(
                                "Missing prev_senders_info for receiver contract verification"
                                    .to_string(),
                            )
                        })?
                        .iter()
                        .map(|info| info.contract_tx.compute_txid())
                        .collect()
                };
                for (i, rx_tx) in receivers_contract_txs.iter().enumerate() {
                    if let Some(expected) = expected_txids.get(i) {
                        let actual = rx_tx.compute_txid();
                        if actual != *expected {
                            return Err(TakerError::General(format!(
                                "Receiver contract tx {} txid mismatch: expected {}, got {}",
                                i, expected, actual
                            )));
                        }
                    }
                }
            }

            let senders_sigs = if is_last_peer {
                log::info!("Signing sender contracts (we are last peer)");
                let privkeys = taker_multisig_privkeys.as_ref().ok_or_else(|| {
                    TakerError::General("Missing taker multisig privkeys for last hop".to_string())
                })?;
                senders_contract_txs_info
                    .iter()
                    .zip(privkeys.iter().cycle())
                    .map(|(info, privkey)| {
                        sign_contract_tx(
                            &info.contract_tx,
                            &info.multisig_redeemscript,
                            info.funding_amount,
                            privkey,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                // Try forwarding ReqContractSigsForSender to the next maker.
                // If the next maker fails (e.g., connection drop), attempt spare
                // substitution and retry the forward (not the whole iteration,
                // since maker[maker_idx] already processed ProofOfFunding).
                // Try forwarding ReqContractSigsForSender to the next maker.
                // If the next maker fails (e.g., connection drop), attempt spare
                // substitution and restart this iteration to redo ProofOfFunding
                // with the spare's keys for the next hop.
                log::info!("Requesting sender signatures from next maker");
                let forward_result = (|| -> Result<Vec<bitcoin::ecdsa::Signature>, TakerError> {
                    let next_idx = maker_idx + 1;
                    let hashvalue = Hash160::hash(&self.swap_state()?.preimage);
                    let next_locktime =
                        self.swap_state()?.makers[maker_idx + 1].negotiated_timelock as u16;

                    let mut next_stream = self.take_connection(next_idx)?;
                    let sigs = self.exchange_req_sender_sigs_forwarded(
                        &mut next_stream,
                        &swap_id,
                        &senders_contract_txs_info,
                        hashvalue,
                        next_locktime,
                    )?;
                    self.return_connection(next_idx, next_stream)?;
                    Ok(sigs)
                })();

                match forward_result {
                    Ok(sigs) => {
                        let next_exch =
                            self.swap_state_mut()?.makers[maker_idx + 1].legacy_exchange_mut()?;
                        next_exch.sender_sigs_requested = true;
                        next_exch.sender_sigs_received = true;
                        sigs
                    }
                    Err(e) => {
                        // Next maker failed — try substituting with a spare.
                        let spare = self.swap_state_mut()?.spare_makers.pop();
                        if let Some(spare_addr) = spare {
                            log::warn!(
                                "Next maker {} failed: {:?}. Substituting with spare at {}",
                                maker_idx + 1,
                                e,
                                spare_addr
                            );
                            self.substitute_and_negotiate_spare(maker_idx + 1, spare_addr)?;
                            // Restart current iteration: reconnect to maker[maker_idx],
                            // redo ProofOfFunding with the spare's keys for the next hop.
                            continue 'exchange;
                        }
                        return Err(e);
                    }
                }
            };
            self.swap_state_mut()?.makers[maker_idx]
                .legacy_exchange_mut()?
                .next_maker_sigs_obtained = true;

            let receivers_sigs = if is_first_peer {
                log::info!("Signing receiver contracts (we are first peer)");
                receivers_contract_txs
                    .iter()
                    .zip(self.swap_state()?.outgoing_swapcoins.iter())
                    .map(|(rx_tx, outgoing)| {
                        let privkey = outgoing.my_privkey.ok_or(
                            crate::protocol::error::ProtocolError::General(
                                "Outgoing swapcoin missing my_privkey for signing",
                            ),
                        )?;
                        let my_pubkey = outgoing.my_pubkey.ok_or(
                            crate::protocol::error::ProtocolError::General(
                                "Outgoing swapcoin missing my_pubkey for signing",
                            ),
                        )?;
                        let other_pubkey = outgoing.other_pubkey.ok_or(
                            crate::protocol::error::ProtocolError::General(
                                "Outgoing swapcoin missing other_pubkey for signing",
                            ),
                        )?;
                        let multisig_redeemscript =
                            create_multisig_redeemscript(&my_pubkey, &other_pubkey);
                        sign_contract_tx(
                            rx_tx,
                            &multisig_redeemscript,
                            outgoing.funding_amount,
                            &privkey,
                        )
                    })
                    .collect::<Result<Vec<_>, _>>()?
            } else {
                log::info!("Requesting receiver signatures from previous maker");
                // For subsequent hops, request from previous maker
                let prev_idx = maker_idx - 1;
                let mut prev_stream = self.take_connection(prev_idx)?;
                let receivers_sigs = self.exchange_req_receiver_sigs(
                    &mut prev_stream,
                    &swap_id,
                    &receivers_contract_txs,
                    prev_senders_info
                        .as_ref()
                        .ok_or(ProtocolError::General("missing previous hop sender info"))?,
                )?;
                self.return_connection(prev_idx, prev_stream)?;
                receivers_sigs
            };
            self.swap_state_mut()?.makers[maker_idx]
                .legacy_exchange_mut()?
                .prev_maker_sigs_obtained = true;

            log::info!(
                "Sending RespContractSigsForRecvrAndSender to maker {}",
                maker_idx
            );
            self.exchange_send_combined_sigs(&mut stream, &swap_id, receivers_sigs, senders_sigs)?;
            self.swap_state_mut()?.makers[maker_idx]
                .legacy_exchange_mut()?
                .combined_sigs_sent = true;
            self.persist_progress()?;

            // Store this maker's outgoing info for next hop
            prev_senders_info = Some(senders_contract_txs_info.clone());

            self.return_connection(maker_idx, stream)?;
            // For non-first hops, the taker doesn't own these contracts — track as watch-only
            if !is_first_peer {
                let watchonly_coins: Vec<WatchOnlySwapCoin> = senders_contract_txs_info
                    .iter()
                    .map(|info| {
                        let (pubkey1, pubkey2) =
                            read_pubkeys_from_multisig_redeemscript(&info.multisig_redeemscript)?;
                        Ok(WatchOnlySwapCoin::new_legacy(
                            pubkey1,
                            pubkey2,
                            info.contract_tx.clone(),
                            info.contract_redeemscript.clone(),
                            info.funding_amount,
                        ))
                    })
                    .collect::<Result<Vec<_>, TakerError>>()?;

                let swap_id = self.swap_state()?.id.clone();
                {
                    let mut wallet = self.write_wallet()?;
                    wallet.add_watchonly_swapcoins(&swap_id, watchonly_coins.clone());
                    wallet.save_to_disk()?;
                }
                self.swap_state_mut()?
                    .watchonly_swapcoins
                    .extend(watchonly_coins);
                self.swap_state_mut()?.makers[maker_idx]
                    .legacy_exchange_mut()?
                    .watchonly_created = true;
            }

            // Wait for this maker's funding to be broadcast and confirmed
            log::info!(
                "Waiting for maker {}'s funding to be confirmed...",
                maker_idx
            );
            // The maker broadcasts after receiving sigs - give it a moment then wait
            std::thread::sleep(MAKER_BROADCAST_DELAY);

            // Wait for the maker's specific funding txs to be confirmed
            let maker_funding_txids: Vec<Txid> = senders_contract_txs_info
                .iter()
                .map(|i| i.funding_tx.compute_txid())
                .collect();

            let required_confirms = self.swap_state()?.params.required_confirms;
            let maker_confirm_height = self.wait_for_legacy_funding_confirmation(
                &maker_funding_txids,
                required_confirms,
                super::api::MAKER_FUNDING_TIMEOUT,
            )?;

            // Verify that the maker's funding confirmed within a few blocks of the
            // previous hop. For legacy (CSV relative locktime), a large gap between
            // confirmations breaks the staggered timelock ordering.
            if prev_confirm_height > 0 && maker_confirm_height > 0 {
                let gap = maker_confirm_height.saturating_sub(prev_confirm_height);
                if gap > super::api::CONFIRMATION_HEIGHT_TOLERANCE {
                    return Err(TakerError::General(format!(
                        "Maker {} funding confirmed at height {} ({} blocks after previous hop at {}). \
                         Exceeds tolerance of {} blocks — timelock staggering may be compromised",
                        maker_idx,
                        maker_confirm_height,
                        gap,
                        prev_confirm_height,
                        super::api::CONFIRMATION_HEIGHT_TOLERANCE,
                    )));
                }
                log::info!(
                    "Maker {} funding confirmed at height {} ({} blocks after previous hop)",
                    maker_idx,
                    maker_confirm_height,
                    gap,
                );
            }
            prev_confirm_height = maker_confirm_height;

            self.swap_state_mut()?.makers[maker_idx]
                .legacy_exchange_mut()?
                .maker_funding_confirmed = true;

            // Register this maker's funding outpoints as sentinels for subsequent waits.
            // Each sentinel maps a funding outpoint to its expected contract txid.
            let maker_sentinels: Vec<(bitcoin::OutPoint, bitcoin::Txid, bitcoin::ScriptBuf)> =
                senders_contract_txs_info
                    .iter()
                    .map(|info| {
                        let funding_spk = bitcoin::ScriptBuf::new_p2wsh(
                            &info.multisig_redeemscript.wscript_hash(),
                        );
                        (
                            info.contract_tx.input[0].previous_output,
                            info.contract_tx.compute_txid(),
                            funding_spk,
                        )
                    })
                    .collect();
            if let Some(ref detector) = self.breach_detector {
                detector.add_sentinels(&self.watch_service, &maker_sentinels)?;
            }

            // This maker's funding is the previous hop for the next maker.
            if maker_idx + 1 < maker_count {
                let next_exch =
                    self.swap_state_mut()?.makers[maker_idx + 1].legacy_exchange_mut()?;
                next_exch.prev_funding_broadcast = true;
                next_exch.prev_funding_confirmed = true;
            }
            self.persist_progress()?;

            #[cfg(debug_assertions)]
            log::debug!(
                "[LEGACY_HOP] Source: taker::legacy_swap::exchange_legacy | SwapID: {} | MakerIndex: {} | FundingTxs: {} | ConfirmHeight: {} | ReceiverContracts: {} | SenderContracts: {} | WatchOnlyTotal: {}",
                swap_id,
                maker_idx,
                maker_funding_txids.len(),
                maker_confirm_height,
                receivers_contract_txs.len(),
                senders_contract_txs_info.len(),
                self.swap_state()?.watchonly_swapcoins.len()
            );
            log::info!("Maker {} processed successfully", maker_idx);
            maker_idx += 1;
        }

        // Create incoming swapcoins from the last maker's sender contract info.
        // These represent the taker's receivable coins from the last hop.
        if let Some(last_senders_info) = &prev_senders_info {
            let multisig_privkeys = taker_multisig_privkeys.ok_or_else(|| {
                TakerError::General(
                    "Missing taker multisig privkeys for incoming swapcoins".to_string(),
                )
            })?;
            let hashlock_privkeys = taker_hashlock_privkeys.ok_or_else(|| {
                TakerError::General(
                    "Missing taker hashlock privkeys for incoming swapcoins".to_string(),
                )
            })?;

            let secp = Secp256k1::new();
            for (info, (multisig_privkey, hashlock_privkey)) in last_senders_info.iter().zip(
                multisig_privkeys
                    .iter()
                    .cycle()
                    .zip(hashlock_privkeys.iter().cycle()),
            ) {
                // Extract the maker's pubkey from the multisig redeemscript
                let (pubkey1, pubkey2) =
                    crate::protocol::contract::read_pubkeys_from_multisig_redeemscript(
                        &info.multisig_redeemscript,
                    )?;
                let my_pubkey = PublicKey {
                    compressed: true,
                    inner: secp256k1::PublicKey::from_secret_key(&secp, multisig_privkey),
                };
                let other_pubkey = if pubkey1 == my_pubkey {
                    pubkey2
                } else {
                    pubkey1
                };

                let mut incoming = IncomingSwapCoin::new_legacy(
                    *multisig_privkey,
                    other_pubkey,
                    info.contract_tx.clone(),
                    info.contract_redeemscript.clone(),
                    *hashlock_privkey,
                    info.funding_amount,
                );
                incoming.swap_id = Some(swap_id.clone());
                incoming.set_preimage(self.swap_state()?.preimage);
                self.swap_state_mut()?.incoming_swapcoins.push(incoming);
            }

            log::info!(
                "Created {} incoming swapcoins from last maker",
                self.swap_state()?.incoming_swapcoins.len()
            );

            // Request the last maker's contract signature on the incoming contracts.
            // This allows the taker to broadcast the incoming contract tx during recovery
            // (for hashlock spending) without depending on the Maker.
            let last_idx = maker_count - 1;
            let last_maker_address = self.swap_state()?.makers[last_idx].address.to_string();
            log::info!(
                "Requesting receiver contract sigs from last maker: {}",
                last_maker_address
            );
            let incoming_contract_txs: Vec<Transaction> = last_senders_info
                .iter()
                .map(|info| info.contract_tx.clone())
                .collect();

            let mut last_stream = self.take_connection(last_idx)?;
            let receiver_sigs = self.exchange_req_receiver_sigs(
                &mut last_stream,
                &swap_id,
                &incoming_contract_txs,
                last_senders_info,
            )?;
            self.return_connection(last_idx, last_stream)?;

            // Store the maker's signatures on the incoming swapcoins
            let swap = self.swap_state_mut()?;
            for (incoming, sig) in swap.incoming_swapcoins.iter_mut().zip(receiver_sigs.iter()) {
                incoming.others_contract_sig = Some(*sig);
            }
            log::info!(
                "Stored {} receiver contract signatures on incoming swapcoins",
                receiver_sigs.len()
            );

            // Pin the PaySwap receiver only after every incoming coin has the
            // maker signature needed to publish its contract during recovery.
            self.payment_stamp_targets()?;
            self.persist_incoming_swapcoins()?;
        }

        // SP6-L: All makers responded, incoming swapcoins created.
        // Breach detector keeps running through finalization.
        self.persist_swap(super::swap_tracker::SwapPhase::ContractsExchanged)?;

        log::info!("Multi-hop Legacy swap contract exchange completed");
        Ok(())
    }

    /// Wait for Legacy funding to reach `required_confirms`, returning the
    /// highest height any of them was mined at. Waits on a fresh backend
    /// connection so no wallet lock is held for the wait's duration.
    fn wait_for_legacy_funding_confirmation(
        &self,
        funding_txids: &[Txid],
        required_confirms: u32,
        arrival_timeout: Duration,
    ) -> Result<u32, TakerError> {
        if required_confirms == 0 || funding_txids.is_empty() {
            return Ok(0);
        }

        let chain = self.read_wallet()?.blockchain.new_connection()?;
        crate::wallet::wait_for_tx_confirmation(
            &chain,
            funding_txids,
            required_confirms,
            arrival_timeout,
            None,
            Some(&|| {
                self.breach_detector
                    .as_ref()
                    .is_some_and(|detector| detector.requires_abort())
            }),
        )
        .map_err(breach_or_wallet_error)
    }

    /// Request contract signatures for sender from a maker.
    fn exchange_req_sender_sigs(
        &self,
        stream: &mut Bip324Stream,
        swap_id: &str,
        outgoing_swapcoins: &[OutgoingSwapCoin],
        locktime: u16,
    ) -> Result<Vec<bitcoin::ecdsa::Signature>, TakerError> {
        let secp = Secp256k1::new();

        // Use the correct nonces from swap state — these are the nonces that
        // were used to derive the maker's multisig/hashlock pubkeys during
        // setup_funding(). The maker needs them to derive the matching private
        // keys for signing.
        let swap_state = self.swap_state()?;

        let txs_info: Vec<ContractTxInfoForSender> = outgoing_swapcoins
            .iter()
            .zip(swap_state.multisig_nonces.iter())
            .zip(swap_state.hashlock_nonces.iter())
            .map(|((swapcoin, multisig_nonce), hashlock_nonce)| {
                let timelock_pubkey = PublicKey {
                    compressed: true,
                    inner: secp256k1::PublicKey::from_secret_key(&secp, &swapcoin.timelock_privkey),
                };

                let my_pub = swapcoin.my_pubkey.ok_or_else(|| {
                    TakerError::General("Outgoing swapcoin missing my_pubkey".to_string())
                })?;
                let other_pub = swapcoin.other_pubkey.ok_or_else(|| {
                    TakerError::General("Outgoing swapcoin missing other_pubkey".to_string())
                })?;
                let multisig_redeemscript = create_multisig_redeemscript(&my_pub, &other_pub);

                Ok(ContractTxInfoForSender {
                    multisig_nonce: *multisig_nonce,
                    hashlock_nonce: *hashlock_nonce,
                    timelock_pubkey,
                    senders_contract_tx: swapcoin.contract_tx.clone(),
                    multisig_redeemscript,
                    funding_input_value: swapcoin.funding_amount,
                })
            })
            .collect::<Result<Vec<_>, TakerError>>()?;

        let hashvalue = Hash160::hash(&self.swap_state()?.preimage);

        let req = ReqContractSigsForSender {
            id: swap_id.to_string(),
            txs_info,
            hashvalue,
            locktime,
        };

        stream.send_message(&TakerToMakerMessage::ReqContractSigsForSender(req))?;

        let msg: MakerToTakerMessage = stream.read_message()?;

        match msg {
            MakerToTakerMessage::RespContractSigsForSender(resp) => {
                if resp.sigs.len() != outgoing_swapcoins.len() {
                    return Err(TakerError::General(format!(
                        "Wrong number of signatures: expected {}, got {}",
                        outgoing_swapcoins.len(),
                        resp.sigs.len()
                    )));
                }
                log::info!(
                    "Received {} sender contract signatures from maker",
                    resp.sigs.len()
                );
                // Verify each signature against the corresponding outgoing swapcoin
                self.verify_sender_sigs(&resp.sigs)?;
                Ok(resp.sigs)
            }
            other => Err(TakerError::General(format!(
                "Unexpected message: expected RespContractSigsForSender, got {:?}",
                other
            ))),
        }
    }

    /// Test-only: claim our own funding output through the contract path and wait for
    /// that spend to be mined, so the ProofOfFunding sent next names an outpoint that
    /// no longer exists.
    #[cfg(feature = "integration-test")]
    fn spend_funding_outpoint_before_proof(&self) -> Result<(), TakerError> {
        use crate::wallet::Blockchain;

        log::warn!("Test behavior: spending the funding outpoint before ProofOfFunding");

        let swapcoin = self
            .swap_state()?
            .outgoing_swapcoins
            .first()
            .cloned()
            .ok_or_else(|| TakerError::General("No outgoing swapcoin to spend".to_string()))?;
        let funding_outpoint = swapcoin
            .contract_tx
            .input
            .first()
            .ok_or_else(|| TakerError::General("Contract tx has no inputs".to_string()))?
            .previous_output;
        let contract_tx = swapcoin.create_signed_contract_tx()?;

        let wallet = self.read_wallet()?;
        wallet.send_tx(&contract_tx)?;

        // Mempool variant: wait only until the backend can see the spend at all.
        // electrs indexes the mempool a moment after the broadcast, and the maker
        // reads the same server, so the wait is what makes the case reachable.
        let include_mempool =
            self.behavior == super::api::TakerBehavior::ReplaySpentFundingOutpointMempool;
        let deadline = std::time::Instant::now() + Duration::from_secs(120);
        while wallet
            .blockchain
            .get_tx_out(
                &funding_outpoint.txid,
                funding_outpoint.vout,
                if include_mempool { None } else { Some(false) },
            )?
            .is_some()
        {
            if std::time::Instant::now() > deadline {
                return Err(TakerError::General(
                    "Funding outpoint was not spent on-chain in time".to_string(),
                ));
            }
            std::thread::sleep(Duration::from_secs(2));
        }
        Ok(())
    }

    /// Test-only: hold the swap open while the route heartbeat keeps pinging, so the
    /// maker's refund deadline is the only thing that can end it. Long enough for the
    /// miner to push the tip past that deadline at the test block cadence.
    #[cfg(feature = "integration-test")]
    fn stall_past_refund_deadline(&self) {
        let stall = Duration::from_secs(180);
        log::warn!(
            "Test behavior: stalling {}s so the maker's refund deadline passes",
            stall.as_secs()
        );
        std::thread::sleep(stall);
    }

    /// Send proof of funding and receive ReqContractSigsAsRecvrAndSender.
    #[allow(clippy::type_complexity)]
    #[allow(clippy::too_many_arguments)]
    fn exchange_send_proof_of_funding(
        &self,
        stream: &mut Bip324Stream,
        swap_id: &str,
        maker_idx: usize,
        funding_txs: &[Transaction],
        contract_redeemscripts: &[ScriptBuf],
        multisig_redeemscripts: &[ScriptBuf],
        multisig_nonces: &[SecretKey],
        hashlock_nonces: &[SecretKey],
        next_multisig_pubkeys: &[PublicKey],
        next_hashlock_pubkeys: &[PublicKey],
        next_multisig_nonces: &[SecretKey],
        next_hashlock_nonces: &[SecretKey],
        refund_locktime: u16,
    ) -> Result<(Vec<Transaction>, Vec<SenderContractTxInfo>), TakerError> {
        let confirmed_funding_txes: Vec<FundingTxInfo> = {
            funding_txs
                .iter()
                .zip(multisig_redeemscripts.iter())
                .zip(contract_redeemscripts.iter())
                .zip(multisig_nonces.iter())
                .zip(hashlock_nonces.iter())
                .map(
                    |(
                        (((funding_tx, multisig_rs), contract_rs), &multisig_nonce),
                        &hashlock_nonce,
                    )| {
                        Ok(FundingTxInfo {
                            funding_tx: funding_tx.clone(),
                            multisig_redeemscript: multisig_rs.clone(),
                            multisig_nonce,
                            contract_redeemscript: contract_rs.clone(),
                            hashlock_nonce,
                        })
                    },
                )
                .collect::<Result<Vec<_>, TakerError>>()?
        };

        #[cfg(feature = "integration-test")]
        if maker_idx == 0
            && matches!(
                self.behavior,
                super::api::TakerBehavior::ReplaySpentFundingOutpoint
                    | super::api::TakerBehavior::ReplaySpentFundingOutpointMempool
            )
        {
            self.spend_funding_outpoint_before_proof()?;
        }

        #[cfg(feature = "integration-test")]
        let mut confirmed_funding_txes = confirmed_funding_txes;
        // The maker's guards run count, then declared sum, then duplication, so
        // each malice must keep the earlier guards satisfied to reach its own.
        #[cfg(feature = "integration-test")]
        {
            use super::api::TakerBehavior;

            let funding_value = |info: &FundingTxInfo| {
                crate::utill::redeemscript_to_scriptpubkey(&info.multisig_redeemscript)
                    .ok()
                    .and_then(|spk| {
                        info.funding_tx
                            .output
                            .iter()
                            .find(|o| o.script_pubkey == spk)
                            .map(|o| o.value)
                    })
                    .unwrap_or(Amount::ZERO)
            };
            match self.behavior {
                TakerBehavior::ExtraFundingTxEntry => {
                    if let Some(first) = confirmed_funding_txes.first().cloned() {
                        log::warn!(
                            "Test behavior: extra funding entry in ProofOfFunding for maker {maker_idx}"
                        );
                        confirmed_funding_txes.push(first);
                    }
                }
                TakerBehavior::OverstatedFundingAmount
                | TakerBehavior::DuplicateFundingOutpoint
                    if confirmed_funding_txes.len() > 1 =>
                {
                    let cheap = confirmed_funding_txes
                        .iter()
                        .enumerate()
                        .min_by_key(|(_, info)| funding_value(info))
                        .map(|(ix, _)| ix)
                        .unwrap_or(0);
                    let pricey = confirmed_funding_txes
                        .iter()
                        .enumerate()
                        .max_by_key(|(_, info)| funding_value(info))
                        .map(|(ix, _)| ix)
                        .unwrap_or(0);
                    let (from, to) = if self.behavior == TakerBehavior::OverstatedFundingAmount {
                        log::warn!(
                            "Test behavior: overstating incoming amount in ProofOfFunding for maker {maker_idx}"
                        );
                        (pricey, cheap)
                    } else {
                        log::warn!(
                            "Test behavior: duplicating funding outpoint in ProofOfFunding for maker {maker_idx}"
                        );
                        (cheap, pricey)
                    };
                    confirmed_funding_txes[to] = confirmed_funding_txes[from].clone();
                }
                _ => {}
            }
        }

        let next_openswap_info: Vec<NextHopInfo> = next_multisig_pubkeys
            .iter()
            .zip(next_hashlock_pubkeys.iter())
            .zip(next_multisig_nonces.iter())
            .zip(next_hashlock_nonces.iter())
            .map(
                |(
                    ((&next_multisig_pubkey, &next_hashlock_pubkey), &next_multisig_nonce),
                    &next_hashlock_nonce,
                )| NextHopInfo {
                    next_multisig_pubkey,
                    next_hashlock_pubkey,
                    next_multisig_nonce,
                    next_hashlock_nonce,
                },
            )
            .collect();

        let pof = ProofOfFunding {
            id: swap_id.to_string(),
            confirmed_funding_txes,
            next_openswap_info,
            refund_locktime,
            contract_feerate: MIN_FEE_RATE,
        };

        stream.send_message(&TakerToMakerMessage::ProofOfFunding(pof))?;

        let msg: MakerToTakerMessage = stream.read_message()?;

        match msg {
            MakerToTakerMessage::ReqContractSigsAsRecvrAndSender(req) => {
                log::info!(
                    "Received ReqContractSigsAsRecvrAndSender: {} receivers, {} senders",
                    req.receivers_contract_txs.len(),
                    req.senders_contract_txs_info.len()
                );
                // Verify the maker's sender contracts (structure, hashvalue, locktime, pubkeys, amounts)
                let expected_amount = self.expected_amount_for_hop(maker_idx);
                self.verify_maker_sender_contracts(
                    &req.senders_contract_txs_info,
                    next_multisig_pubkeys,
                    next_hashlock_pubkeys,
                    refund_locktime,
                    expected_amount,
                )?;
                // Verify the maker's receiver contract txs (structure, funding reference, scriptpubkey, amounts)
                self.verify_maker_receiver_contracts(
                    &req.receivers_contract_txs,
                    funding_txs,
                    contract_redeemscripts,
                )?;
                #[cfg(feature = "integration-test")]
                if self.behavior == super::api::TakerBehavior::StallAfterProofOfFunding {
                    self.stall_past_refund_deadline();
                }
                Ok((req.receivers_contract_txs, req.senders_contract_txs_info))
            }
            other => Err(TakerError::General(format!(
                "Unexpected message: expected ReqContractSigsAsRecvrAndSender, got {:?}",
                other
            ))),
        }
    }

    /// Send collected signatures for both receiver and sender contracts (Legacy protocol).
    fn exchange_send_combined_sigs(
        &self,
        stream: &mut Bip324Stream,
        swap_id: &str,
        receivers_sigs: Vec<bitcoin::ecdsa::Signature>,
        senders_sigs: Vec<bitcoin::ecdsa::Signature>,
    ) -> Result<(), TakerError> {
        let resp = RespContractSigsForRecvrAndSender {
            id: swap_id.to_string(),
            receivers_sigs,
            senders_sigs,
        };

        stream.send_message(&TakerToMakerMessage::RespContractSigsForRecvrAndSender(
            resp,
        ))?;

        log::info!(
            "Sent RespContractSigsForRecvrAndSender for swap {}",
            swap_id
        );
        Ok(())
    }

    /// Request sender contract signatures using SenderContractTxInfo.
    fn exchange_req_sender_sigs_forwarded(
        &self,
        stream: &mut Bip324Stream,
        swap_id: &str,
        senders_info: &[SenderContractTxInfo],
        hashvalue: Hash160,
        locktime: u16,
    ) -> Result<Vec<bitcoin::ecdsa::Signature>, TakerError> {
        // Build ContractTxInfoForSender from SenderContractTxInfo
        let txs_info: Vec<ContractTxInfoForSender> = senders_info
            .iter()
            .map(|info| ContractTxInfoForSender {
                multisig_nonce: info.multisig_nonce,
                hashlock_nonce: info.hashlock_nonce,
                timelock_pubkey: info.timelock_pubkey,
                senders_contract_tx: info.contract_tx.clone(),
                multisig_redeemscript: info.multisig_redeemscript.clone(),
                funding_input_value: info.funding_amount,
            })
            .collect();

        let req = ReqContractSigsForSender {
            id: swap_id.to_string(),
            txs_info,
            hashvalue,
            locktime,
        };

        stream.send_message(&TakerToMakerMessage::ReqContractSigsForSender(req))?;

        let msg: MakerToTakerMessage = stream.read_message()?;

        match msg {
            MakerToTakerMessage::RespContractSigsForSender(resp) => {
                log::info!("Received {} sender signatures", resp.sigs.len());
                // Verify each forwarded signature against the sender contract info
                self.verify_sender_sigs_from_info(&resp.sigs, senders_info)?;
                Ok(resp.sigs)
            }
            other => Err(TakerError::General(format!(
                "Unexpected message: expected RespContractSigsForSender, got {:?}",
                other
            ))),
        }
    }

    /// Request receiver signatures from previous maker.
    fn exchange_req_receiver_sigs(
        &self,
        stream: &mut Bip324Stream,
        swap_id: &str,
        receivers_txs: &[Transaction],
        prev_senders_info: &[SenderContractTxInfo],
    ) -> Result<Vec<bitcoin::ecdsa::Signature>, TakerError> {
        // Build ContractTxInfoForRecvr for each receiver contract
        let txs: Vec<ContractTxInfoForRecvr> = receivers_txs
            .iter()
            .zip(prev_senders_info.iter())
            .map(|(tx, info)| ContractTxInfoForRecvr {
                contract_tx: tx.clone(),
                multisig_redeemscript: info.multisig_redeemscript.clone(),
            })
            .collect();

        let req = ReqContractSigsForRecvr {
            id: swap_id.to_string(),
            txs,
        };

        stream.send_message(&TakerToMakerMessage::ReqContractSigsForRecvr(req))?;

        let msg: MakerToTakerMessage = stream.read_message()?;

        match msg {
            MakerToTakerMessage::RespContractSigsForRecvr(resp) => {
                log::info!("Received {} receiver signatures", resp.sigs.len());
                // Verify each receiver signature
                self.verify_receiver_sigs(&resp.sigs, receivers_txs, prev_senders_info)?;
                Ok(resp.sigs)
            }
            other => Err(TakerError::General(format!(
                "Unexpected message: expected RespContractSigsForRecvr, got {:?}",
                other
            ))),
        }
    }
}
