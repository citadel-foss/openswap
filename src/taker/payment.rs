//! PaySwap: settling the taker's final incoming swapcoin to a third-party
//! receiver for an exact amount.
//!
//! The requested amount is the net amount the receiver must get. The taker
//! reserves a settlement budget for the most expensive claim path and solves
//! the maker fee schedule backward to the gross first-hop amount; since every
//! maker deduction is replicable to the satoshi, the final hop's funding is
//! enforced by the existing exact amount check at contract verification. The
//! destination is pinned per-swapcoin as a [`PaymentTarget`], which every
//! settlement and recovery path honors across restarts.

use bitcoin::{Address, Amount, ScriptBuf};

use crate::{
    protocol::common_messages::Offer,
    utill::estimate_funding_tx_fee_sats,
    wallet::{payment_settlement_budget_sats, swapcoin::PaymentTarget},
};

use super::{
    api::{SwapParams, Taker, FUNDING_FEE_BUFFER, REFUND_LOCKTIME_BASE, REFUND_LOCKTIME_STEP},
    error::TakerError,
};

/// Dust floor per settlement output, enforced at quote time.
const MIN_PAYMENT_OUTPUT_SATS: u64 = 546;

/// PaySwap terms: solved at prepare time, carried in the ongoing swap, and
/// shown as the cost breakdown in the [`SwapSummary`](super::api::SwapSummary).
/// The gross route amount is the summary's `send_amount`.
#[derive(Debug, Clone)]
pub struct PaymentQuote {
    /// Receiver's address, validated against the wallet network.
    pub address: Address,
    /// Exact amount the receiver gets.
    pub amount: Amount,
    /// Fee budget for settling the final swapcoins; the final hop is funded
    /// with `amount + settlement_budget`.
    pub settlement_budget: Amount,
    /// Estimated mining fee for the taker's own funding transactions, paid by
    /// the wallet on top of the route amount.
    pub taker_funding_fee_estimate: Amount,
}

/// One hop's fee-relevant terms, extracted from a maker's offer so the solver
/// can be exercised without constructing full offers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct HopFeeTerms {
    pub(crate) base_fee: u64,
    pub(crate) amount_relative_fee_pct: f64,
    pub(crate) time_relative_fee_pct: f64,
    /// Locktime the fee is priced on: the refund locktime offset for this hop.
    pub(crate) locktime: u32,
}

impl HopFeeTerms {
    pub(crate) fn from_offer(offer: &Offer, locktime: u32) -> Self {
        HopFeeTerms {
            base_fee: offer.base_fee,
            amount_relative_fee_pct: offer.amount_relative_fee_pct,
            time_relative_fee_pct: offer.time_relative_fee_pct,
            locktime,
        }
    }
}

/// Replay one maker hop's deduction exactly as the maker computes it.
/// The single forward formula shared by the quote solver and
/// [`Taker::expected_amount_for_hop`] — any drift between them either
/// misprices the payment or aborts a correct swap.
pub(crate) fn hop_net_sats(terms: &HopFeeTerms, per_hop_mining_fee: u64, gross_sats: u64) -> u64 {
    let fee = (terms.base_fee as f64
        + (gross_sats as f64 * terms.amount_relative_fee_pct) / 100.0
        + (gross_sats as f64 * terms.locktime as f64 * terms.time_relative_fee_pct) / 100.0)
        .ceil() as u64;
    gross_sats.saturating_sub(fee + per_hop_mining_fee)
}

/// Binary search for the amount a maker must receive so that, after its fee,
/// it forwards exactly `net_sats` to the next hop. Errors if the maker's fee
/// schedule can never forward that much.
fn hop_gross_for_net(
    terms: &HopFeeTerms,
    per_hop_mining_fee: u64,
    net_sats: u64,
) -> Result<u64, TakerError> {
    let mut hi = net_sats.max(1);
    while hop_net_sats(terms, per_hop_mining_fee, hi) < net_sats {
        hi = hi.saturating_mul(2);
        if hi > Amount::MAX_MONEY.to_sat() {
            return Err(TakerError::General(format!(
                "Maker fee schedule cannot net {net_sats} sats at any fundable amount"
            )));
        }
    }

    let mut lo = net_sats;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if hop_net_sats(terms, per_hop_mining_fee, mid) >= net_sats {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }

    if hop_net_sats(terms, per_hop_mining_fee, lo) != net_sats {
        return Err(TakerError::General(format!(
            "Maker fee schedule skips over an exact net of {net_sats} sats"
        )));
    }
    Ok(lo)
}

/// Walk the route backward from the required final-hop funding to the gross
/// amount entering the first hop, then re-run the deductions forward as a
/// self-consistency check.
fn solve_route_gross_sats(
    hops: &[HopFeeTerms],
    per_hop_mining_fee: u64,
    final_net_sats: u64,
) -> Result<u64, TakerError> {
    let mut required = final_net_sats;
    for terms in hops.iter().rev() {
        required = hop_gross_for_net(terms, per_hop_mining_fee, required)?;
    }

    let mut forward = required;
    for terms in hops {
        forward = hop_net_sats(terms, per_hop_mining_fee, forward);
    }
    if forward != final_net_sats {
        return Err(TakerError::General(format!(
            "Payment route solve is inconsistent: gross {required} nets {forward}, expected {final_net_sats}"
        )));
    }

    Ok(required)
}

impl Taker {
    /// Validate the receiver address network and per-output dust floor.
    /// Returns the checked address, or `None` for regular swaps. Runs at the
    /// top of `prepare_swap`, before any swap state exists; the checked
    /// address then feeds [`Self::payment_prepare_route`].
    pub(crate) fn payment_validate_params(
        &self,
        params: &SwapParams,
    ) -> Result<Option<Address>, TakerError> {
        let Some(unchecked_address) = params.payment_address.clone() else {
            return Ok(None);
        };

        let network = self.read_wallet()?.store.network;
        let address = unchecked_address.require_network(network).map_err(|e| {
            TakerError::General(format!(
                "Receiver address is not valid for the wallet network {network}: {e}"
            ))
        })?;

        // The receiver amount is split across `tx_count` settlement outputs;
        // each must clear the dust floor.
        let tx_count = params.tx_count as u64;
        if tx_count == 0 {
            return Err(TakerError::General(
                "A payment swap needs at least one transaction split".into(),
            ));
        }
        if params.send_amount.to_sat() < MIN_PAYMENT_OUTPUT_SATS * tx_count {
            return Err(TakerError::General(format!(
                "Payment amount {} is below the {} sat minimum for {} settlement outputs",
                params.send_amount,
                MIN_PAYMENT_OUTPUT_SATS * tx_count,
                tx_count
            )));
        }

        Ok(Some(address))
    }

    /// Solve the payment route after maker selection and before negotiation:
    /// collect every selected maker's offer, size the settlement budget, and
    /// rewrite `params.send_amount` from the receiver's exact amount to the
    /// solved gross route amount. `address` is the validated receiver.
    pub(crate) fn payment_prepare_route(&mut self, address: Address) -> Result<(), TakerError> {
        let (receiver_amount, tx_count, protocol, maker_count) = {
            let swap = self.swap_state()?;
            (
                swap.params.send_amount,
                swap.params.tx_count as u64,
                swap.params.protocol,
                swap.makers.len(),
            )
        };

        // Discovery fills these from the offerbook synced moments earlier; a
        // preferred-maker route has none, so poll those makers directly (which
        // also verifies their fidelity proof). Negotiation refetches each offer
        // on the swap connection and aborts if a maker repriced in between.
        let mut hops = Vec::with_capacity(maker_count);
        for i in 0..maker_count {
            let maker_address = self.swap_state()?.makers[i].address.to_string();
            let offer = match self.swap_state()?.makers[i].offer.clone() {
                Some(offer) => offer,
                None => self
                    .poll_maker(maker_address.clone())?
                    .offer
                    .ok_or_else(|| {
                        TakerError::General(format!(
                            "Maker {maker_address} has no offer to price the payment route"
                        ))
                    })?,
            };
            // Checked against the receiver amount — the gross is unknown yet;
            // negotiation re-validates on the gross.
            Self::validate_offer(&offer, i, receiver_amount)?;
            let locktime =
                (REFUND_LOCKTIME_BASE + REFUND_LOCKTIME_STEP * (maker_count - i - 1) as u16) as u32;
            hops.push(HopFeeTerms::from_offer(&offer, locktime));
            self.swap_state_mut()?.makers[i].offer = Some(offer);
        }

        let settlement_budget = payment_settlement_budget_sats(protocol) * tx_count;
        let final_net = receiver_amount.to_sat() + settlement_budget;
        let per_hop_mining_fee = estimate_funding_tx_fee_sats() * tx_count;
        let gross = solve_route_gross_sats(&hops, per_hop_mining_fee, final_net)?;

        // Maker selection was sized on the receiver amount, since the gross is
        // only known once their fees are in hand. Re-check the solved gross
        // against each maker's advertised limits here: a maker whose max_size
        // falls between the two would otherwise be rejected mid-negotiation,
        // where a payment route cannot substitute it.
        // Every offer was stored on its maker in the loop above.
        for (i, maker) in self.swap_state()?.makers.iter().enumerate() {
            if let Some(offer) = maker.offer.as_ref() {
                Self::validate_offer(offer, i, Amount::from_sat(gross))?;
            }
        }

        // The prepare-entry balance check saw only the receiver amount; the
        // wallet must fund the gross. Fail before any maker is quoted.
        let available = self.read_wallet()?.get_balances()?.spendable;
        let required = Amount::from_sat(gross) + FUNDING_FEE_BUFFER;
        if available < required {
            return Err(TakerError::General(format!(
                "Insufficient balance for the payment route: available={available}, required={required}"
            )));
        }

        log::info!(
            "Payment route solved: receiver gets {} exactly, settlement budget {} sats, final hop funds {} sats, gross route amount {} sats",
            receiver_amount,
            settlement_budget,
            final_net,
            gross
        );

        let swap = self.swap_state_mut()?;
        swap.params.send_amount = Amount::from_sat(gross);
        swap.payment = Some(PaymentQuote {
            address,
            amount: receiver_amount,
            settlement_budget: Amount::from_sat(settlement_budget),
            taker_funding_fee_estimate: Amount::from_sat(per_hop_mining_fee),
        });
        Ok(())
    }

    /// Pin the receiver on every final incoming swapcoin, right after
    /// creation and before wallet persistence. No-op for regular swaps.
    ///
    /// Each coin surrenders an equal share of the settlement budget; the hop
    /// total was verified exact, so the outputs sum to the receiver amount.
    pub(crate) fn payment_stamp_targets(&mut self) -> Result<(), TakerError> {
        let Some(payment) = self.swap_state()?.payment.clone() else {
            return Ok(());
        };
        let script_pubkey: ScriptBuf = payment.address.script_pubkey();

        let swap = self.swap_state_mut()?;
        let coin_count = swap.incoming_swapcoins.len() as u64;
        if coin_count == 0 {
            return Err(TakerError::General(
                "Payment swap produced no incoming swapcoins to settle".into(),
            ));
        }
        let budget = payment.settlement_budget.to_sat();
        if budget % coin_count != 0 {
            return Err(TakerError::General(format!(
                "Settlement budget {budget} sats does not divide across {coin_count} swapcoins"
            )));
        }
        let per_coin_budget = budget / coin_count;

        let mut total = 0;
        for swapcoin in &mut swap.incoming_swapcoins {
            let output_sats = swapcoin
                .funding_amount
                .to_sat()
                .checked_sub(per_coin_budget)
                .filter(|v| *v >= MIN_PAYMENT_OUTPUT_SATS)
                .ok_or_else(|| {
                    TakerError::General(format!(
                        "Incoming swapcoin funding {} cannot carry a settlement output above dust \
                         after the {per_coin_budget} sat fee budget",
                        swapcoin.funding_amount
                    ))
                })?;
            swapcoin.payment_target = Some(PaymentTarget {
                script_pubkey: script_pubkey.clone(),
                amount: Amount::from_sat(output_sats),
            });
            total += output_sats;
        }

        // A mismatch means the swap must not commit to this payment.
        if total != payment.amount.to_sat() {
            return Err(TakerError::General(format!(
                "Settlement outputs total {total} sats, expected exactly {}",
                payment.amount.to_sat()
            )));
        }

        log::info!(
            "Pinned {} settlement outputs totaling exactly {} sats to receiver {}",
            coin_count,
            total,
            payment.address
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms(base_fee: u64, amount_pct: f64, time_pct: f64, locktime: u32) -> HopFeeTerms {
        HopFeeTerms {
            base_fee,
            amount_relative_fee_pct: amount_pct,
            time_relative_fee_pct: time_pct,
            locktime,
        }
    }

    #[test]
    fn hop_solve_round_trips_exactly() {
        let mining_fees = [0, 442, 442 * 3];
        let schedules = [
            terms(0, 0.0, 0.0, 20),
            terms(1000, 0.0, 0.0, 20),
            terms(100, 2.5, 0.0, 20),
            terms(100, 0.1, 0.0005, 150),
            terms(1000, 2.5, 0.005, 300),
            terms(0, 0.0, 0.001, 75),
        ];
        let targets = [546, 1_000, 99_999, 500_000, 10_000_000, 123_456_789];

        for schedule in &schedules {
            for &mining_fee in &mining_fees {
                for &target in &targets {
                    let gross = hop_gross_for_net(schedule, mining_fee, target).unwrap();
                    assert_eq!(
                        hop_net_sats(schedule, mining_fee, gross),
                        target,
                        "schedule {schedule:?} mining {mining_fee} target {target}"
                    );
                    // Smallest such gross: one satoshi less must fall short.
                    assert!(
                        hop_net_sats(schedule, mining_fee, gross - 1) < target,
                        "gross {} is not minimal for target {}",
                        gross,
                        target
                    );
                }
            }
        }
    }

    #[test]
    fn route_solve_matches_forward_replay() {
        let hops = [
            terms(1000, 2.5, 0.005, 170),
            terms(250, 0.75, 0.001, 95),
            terms(0, 1.0, 0.0005, 20),
        ];
        let mining_fee = 442 * 3;
        let final_net = 10_000_600;

        let gross = solve_route_gross_sats(&hops, mining_fee, final_net).unwrap();
        assert!(gross > final_net);

        let mut forward = gross;
        for hop in &hops {
            forward = hop_net_sats(hop, mining_fee, forward);
        }
        assert_eq!(forward, final_net);
    }

    #[test]
    fn confiscatory_fee_schedule_is_rejected() {
        // 60% per hop on the amount plus a time fee pushing past 100%:
        // the net can never reach the target however large the gross.
        let hop = terms(0, 60.0, 0.5, 100);
        assert!(hop_gross_for_net(&hop, 0, 500_000).is_err());
    }

    #[test]
    fn validate_offer_rejects_fee_exceeding_send_amount() {
        use bitcoin::hashes::Hash;

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey = bitcoin::PublicKey::new(secp_pubkey);

        let bond = crate::wallet::FidelityBond {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([2; 32]),
                vout: 0,
            },
            amount: Amount::from_sat(1000),
            lock_time: bitcoin::locktime::absolute::LockTime::from_height(1000)
                .expect("valid height locktime"),
            pubkey,
            conf_height: Some(1000),
            is_spent: false,
            bond_index: 0,
            tx: None,
        };

        let cert_hash = bond.generate_cert_hash("127.0.0.1:8000", &pubkey);
        let msg = bitcoin::secp256k1::Message::from_digest_slice(cert_hash.as_byte_array())
            .expect("32-byte digest");
        let cert_sig = secp.sign_ecdsa(&msg, &secret_key);

        let offer = crate::protocol::common_messages::Offer {
            base_fee: 1000,
            amount_relative_fee_pct: 10.0,
            time_relative_fee_pct: 0.1,
            required_confirms: 1,
            minimum_locktime: 100,
            max_size: 1_000_000,
            min_size: 100,
            tweakable_point: pubkey,
            fidelity: crate::protocol::common_messages::FidelityProof {
                bond,
                cert_hash,
                cert_sig,
            },
            tweak_chain_code: bitcoin::bip32::ChainCode::from([0u8; 32]),
        };

        // Send amount of 1,000 sats: base fee 1000 + rel fee 100 + time fee 100 = 1200 >= 1000 -> must error
        assert!(Taker::validate_offer(&offer, 0, Amount::from_sat(1000)).is_err());

        // Send amount of 2,000 sats: base fee 1000 + rel fee 200 + time fee 200 = 1400 < 2000 -> must pass
        assert!(Taker::validate_offer(&offer, 0, Amount::from_sat(2000)).is_ok());
    }

    #[test]
    fn cumulative_route_fees_consuming_send_amount() {
        use super::TakerError;
        use crate::protocol::{
            common_messages::{FidelityProof, Offer},
            ProtocolVersion,
        };
        use bitcoin::hashes::Hash;

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey = bitcoin::PublicKey::new(secp_pubkey);

        let bond = crate::wallet::FidelityBond {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([3; 32]),
                vout: 0,
            },
            amount: Amount::from_sat(1000),
            lock_time: bitcoin::locktime::absolute::LockTime::from_height(1000)
                .expect("valid height locktime"),
            pubkey,
            conf_height: Some(1000),
            is_spent: false,
            bond_index: 0,
            tx: None,
        };

        let cert_hash = bond.generate_cert_hash("127.0.0.1:8000", &pubkey);
        let msg = bitcoin::secp256k1::Message::from_digest_slice(cert_hash.as_byte_array())
            .expect("32-byte digest");
        let cert_sig = secp.sign_ecdsa(&msg, &secret_key);

        let mock_offer = |base_fee: u64| -> Option<Offer> {
            Some(Offer {
                base_fee,
                amount_relative_fee_pct: 0.0,
                time_relative_fee_pct: 0.0,
                required_confirms: 1,
                minimum_locktime: 100,
                max_size: 1_000_000,
                min_size: 100,
                tweakable_point: pubkey,
                fidelity: FidelityProof {
                    bond: bond.clone(),
                    cert_hash,
                    cert_sig,
                },
                tweak_chain_code: bitcoin::bip32::ChainCode::from([0u8; 32]),
            })
        };

        // Two hops with 600 sat base fee each on 1000 sat send amount:
        // Individual offers (< 1000) pass validate_offer, but cumulative route total (1200 sats) >= send_amount
        let hops = vec![
            (
                "127.0.0.1:8001".to_string(),
                ProtocolVersion::Taproot,
                mock_offer(600),
            ),
            (
                "127.0.0.1:8002".to_string(),
                ProtocolVersion::Taproot,
                mock_offer(600),
            ),
        ];

        let err = Taker::compute_route_maker_fees(Amount::from_sat(1000), &hops, 0).unwrap_err();
        assert!(
            matches!(err, TakerError::General(ref msg) if msg.contains("Cumulative maker fees consume the send amount")),
            "Expected cumulative fee exhaustion error, got: {:?}",
            err
        );
    }

    #[test]
    fn route_maker_fees_advances_forwarded_amount_with_mining_fee() {
        use super::Taker;
        use crate::protocol::{
            common_messages::{FidelityProof, Offer},
            ProtocolVersion,
        };
        use bitcoin::hashes::Hash;

        let secp = bitcoin::secp256k1::Secp256k1::new();
        let secret_key = bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap();
        let secp_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret_key);
        let pubkey = bitcoin::PublicKey::new(secp_pubkey);

        let bond = crate::wallet::FidelityBond {
            outpoint: bitcoin::OutPoint {
                txid: bitcoin::Txid::from_byte_array([4; 32]),
                vout: 0,
            },
            amount: Amount::from_sat(1000),
            lock_time: bitcoin::locktime::absolute::LockTime::from_height(1000)
                .expect("valid height locktime"),
            pubkey,
            conf_height: Some(1000),
            is_spent: false,
            bond_index: 0,
            tx: None,
        };

        let cert_hash = bond.generate_cert_hash("127.0.0.1:8000", &pubkey);
        let msg = bitcoin::secp256k1::Message::from_digest_slice(cert_hash.as_byte_array())
            .expect("32-byte digest");
        let cert_sig = secp.sign_ecdsa(&msg, &secret_key);

        // Hop 0: 10% amount fee, 0 base fee. On 10,000 sats -> 1,000 sats fee.
        // With per_hop_mining_fee = 500, amount forwarded to Hop 1 is 10,000 - 1,000 - 500 = 8,500 sats.
        // Hop 1: 10% amount fee. On 8,500 sats -> 850 sats fee.
        let hops = vec![
            (
                "127.0.0.1:8001".to_string(),
                ProtocolVersion::Taproot,
                Some(Offer {
                    base_fee: 0,
                    amount_relative_fee_pct: 10.0,
                    time_relative_fee_pct: 0.0,
                    required_confirms: 1,
                    minimum_locktime: 100,
                    max_size: 1_000_000,
                    min_size: 100,
                    tweakable_point: pubkey,
                    fidelity: FidelityProof {
                        bond: bond.clone(),
                        cert_hash,
                        cert_sig,
                    },
                    tweak_chain_code: bitcoin::bip32::ChainCode::from([0u8; 32]),
                }),
            ),
            (
                "127.0.0.1:8002".to_string(),
                ProtocolVersion::Taproot,
                Some(Offer {
                    base_fee: 0,
                    amount_relative_fee_pct: 10.0,
                    time_relative_fee_pct: 0.0,
                    required_confirms: 1,
                    minimum_locktime: 100,
                    max_size: 1_000_000,
                    min_size: 100,
                    tweakable_point: pubkey,
                    fidelity: FidelityProof {
                        bond,
                        cert_hash,
                        cert_sig,
                    },
                    tweak_chain_code: bitcoin::bip32::ChainCode::from([0u8; 32]),
                }),
            ),
        ];

        let (fees, total) =
            Taker::compute_route_maker_fees(Amount::from_sat(10_000), &hops, 500).unwrap();
        assert_eq!(fees[0].estimated_fee_sats, 1000);
        assert_eq!(fees[1].estimated_fee_sats, 850);
        assert_eq!(total, 1850);
    }
}
