//! Taker-side driver for Lightning submarine swaps.
//!
//! Both directions run over a single maker connection using the standard
//! hello/offer handshake followed by the `Lightning` message family. The
//! maker is chosen explicitly or from the offerbook (first good maker whose
//! offer advertises Lightning terms covering the amount).
//!
//! A third flow, [`Taker::lightning_swap_routed`], chains the two through
//! *two* makers: the taker pays on-chain to maker 1, maker 1 forwards over
//! Lightning to maker 2, and maker 2 pays the taker back on-chain. The taker
//! needs no Lightning node of its own for that one — Lightning is purely the
//! makers' settlement rail.
//!
//! Crash safety: an [`LnPendingSwap`] record is written to the (encrypted)
//! wallet store before any value is committed. A swap-in's record is removed
//! when the swap resolves; a swap-out's (and a routed second hop's) stays
//! until a spend of its funding outpoint confirms. That spend is usually our
//! claim, but a maker's refund also ends the record, so its removal is not
//! proof the claim confirmed. [`Taker::recover_lightning_swaps`] spends
//! whatever those records can still claim — the hashlock branch when the
//! preimage is ours (swap-out), the timelock branch otherwise (swap-in
//! refund) — and asks the maker again for swap-out funding whose reply was
//! lost.

use std::{
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use bitcoin::{
    hashes::sha256,
    secp256k1::rand::{rngs::OsRng, RngCore},
    Amount, OutPoint, ScriptBuf, Transaction, Txid,
};

use crate::{
    blocklist::BlocklistError,
    lightning::{
        invoice::verify_invoice, swap::SwapHtlc, InvoiceParams, LightningBackend, LnEvent,
        PaymentOutcome, Preimage,
    },
    protocol::{
        common_messages::{GetOffer, MakerToTakerMessage, Offer, TakerToMakerMessage},
        features::{choose_pins, unmet_for_flow},
        lightning_messages::{
            LightningMakerMessage, LightningOffer, LightningTakerMessage, LnHtlcFunded,
            LnSwapInRequest, LnSwapOutClaimed, LnSwapOutPaid, LnSwapOutRequest,
        },
    },
    utill::{generate_keypair, read_message, send_message, MIN_RELAY_FEE_RATE},
    wallet::{AddressType, AnyBlockchain, LnFundingResume, LnPendingSwap, Wallet},
};

use super::{
    api::{connect_to_maker, handshake_with_maker, Taker, TakerInitConfig},
    error::TakerError,
};

/// Bound on every wait for a maker message or Lightning event.
const LN_STEP_TIMEOUT: Duration = Duration::from_secs(300);

/// Safety margin (blocks) added over the invoice CLTV delta when deriving
/// the default swap-in locktime.
const CLTV_SAFETY_MARGIN: u16 = 12;

/// Default headroom over the CLTV floor for the swap-in refund locktime.
const DEFAULT_LOCKTIME_HEADROOM: u16 = 48;

/// Default swap-out refund locktime (maker's branch) in blocks.
const DEFAULT_SWAP_OUT_LOCKTIME: u16 = 144;

/// Extra blocks the first hop's refund gets over the second hop's in a
/// routed swap. The hop we fund must stay locked until after the hop we
/// claim from has resolved, or we could be refunded on one leg while still
/// exposed on the other.
const ROUTED_HOP_TIMELOCK_MARGIN: u16 = 48;

/// How long to listen for an early rejection from the first maker before
/// assuming it accepted and is working on the payment.
const EARLY_REJECT_WINDOW: Duration = Duration::from_secs(5);

/// Hard ceiling on a maker's fee, as a percentage of the swap amount.
///
/// `advertised_fee` alone is no protection: its inputs come from the
/// maker's own offer, so the maker sets both the ceiling and the charge.
/// This is the bound the taker applies regardless of what was advertised.
const MAX_FEE_PERCENT: u64 = 5;

/// Parameters of a Lightning submarine swap.
#[derive(Debug, Clone)]
pub struct LnSwapParams {
    /// Swap amount (what the taker receives).
    pub amount: Amount,
    /// Maker address; `None` picks the first suitable maker from the
    /// offerbook.
    pub maker_address: Option<String>,
    /// On-chain refund locktime override (blocks, CSV).
    pub locktime: Option<u16>,
    /// Confirmations required on the HTLC funding output.
    pub min_confirmations: u32,
}

/// Outcome of a completed Lightning swap.
#[derive(Debug, Clone)]
pub struct LnSwapReport {
    /// Swap identifier (hex payment hash).
    pub swap_id: String,
    /// Maker that served the swap.
    pub maker: String,
    /// Swap amount.
    pub amount: Amount,
    /// Fee paid to the maker.
    pub fee: Amount,
    /// The on-chain HTLC funding outpoint.
    pub funding_outpoint: OutPoint,
    /// The taker's on-chain claim (swap-out only).
    pub claim_txid: Option<Txid>,
}

/// Parameters of a routed (two-maker) Lightning swap.
#[derive(Debug, Clone)]
pub struct LnRoutedSwapParams {
    /// On-chain amount the taker receives back from the second maker. The
    /// taker funds this plus both makers' fees.
    pub amount: Amount,
    /// First maker: receives the taker's on-chain funds and forwards over
    /// Lightning. `None` picks one from the offerbook.
    pub first_maker: Option<String>,
    /// Second maker: receives Lightning and funds the taker's on-chain
    /// payout. `None` picks one from the offerbook.
    pub second_maker: Option<String>,
    /// Refund locktime of the second hop, in blocks. The first hop gets
    /// `ROUTED_HOP_TIMELOCK_MARGIN` more.
    pub locktime: Option<u16>,
    /// Confirmations required on each HTLC funding output.
    pub min_confirmations: u32,
}

/// Outcome of a completed routed swap.
#[derive(Debug, Clone)]
pub struct LnRoutedSwapReport {
    /// Swap identifier (hex payment hash), shared by both hops.
    pub swap_id: String,
    /// Maker that took the on-chain funds and paid over Lightning.
    pub first_maker: String,
    /// Maker that received Lightning and paid out on-chain.
    pub second_maker: String,
    /// Total on-chain amount the taker committed (amount + both fees).
    pub sent: Amount,
    /// On-chain amount the taker received back.
    pub received: Amount,
    /// Fee charged by the first maker.
    pub first_fee: Amount,
    /// Fee charged by the second maker.
    pub second_fee: Amount,
    /// Outpoint the taker funded for the first hop.
    pub funding_outpoint: OutPoint,
    /// The taker's claim of the second hop's HTLC.
    pub claim_txid: Txid,
}

/// Builds the taker's Lightning backend from config. Shared with the maker
/// so a fix to one reaches both.
pub(crate) fn init_lightning_backend(
    config: &TakerInitConfig,
    network: bitcoin::Network,
) -> Option<Arc<dyn LightningBackend>> {
    crate::lightning::backend_from_settings(
        config.ldk_server_url.as_ref(),
        config.ldk_api_key_path.as_ref(),
        config.ldk_tls_cert_path.as_ref(),
        network,
    )
}

/// The maker's advertised fee for this amount; the accepted fee must not
/// exceed it. Must mirror the maker's own formula.
///
/// The percentage is peer-supplied, so the arithmetic is done in a way that
/// cannot produce a negative, NaN, or wrapped result: a nonsensical offer
/// yields a fee the caller will reject rather than a panic.
fn advertised_fee(offer: &LightningOffer, amount: Amount) -> Amount {
    let pct = if offer.amount_relative_fee_pct.is_finite() {
        offer.amount_relative_fee_pct.max(0.0)
    } else {
        f64::INFINITY
    };
    let relative = amount.to_sat() as f64 * pct / 100.0;
    let total = offer.base_fee as f64 + relative;
    if !total.is_finite() || total < 0.0 || total > u64::MAX as f64 {
        return Amount::MAX_MONEY;
    }
    Amount::from_sat(total.ceil() as u64)
}

/// The most this taker will pay a maker for a swap of `amount`, whatever
/// the offer says.
fn max_acceptable_fee(amount: Amount) -> Amount {
    Amount::from_sat(amount.to_sat().saturating_mul(MAX_FEE_PERCENT) / 100)
}

/// Rejects a quoted fee that exceeds either the maker's own advertised
/// terms or this taker's hard ceiling.
fn check_fee(quoted: Amount, advertised: Amount, amount: Amount) -> Result<(), TakerError> {
    if quoted > advertised {
        return Err(general(format!(
            "maker fee {quoted} exceeds its advertised {advertised}"
        )));
    }
    let ceiling = max_acceptable_fee(amount);
    if quoted > ceiling {
        return Err(general(format!(
            "maker fee {quoted} exceeds {MAX_FEE_PERCENT}% of the swap amount ({ceiling})"
        )));
    }
    Ok(())
}

/// Satoshis as millisatoshis. A swap amount large enough to overflow the
/// conversion is rejected rather than wrapped into a small one.
fn msat(amount: Amount) -> Result<u64, TakerError> {
    amount
        .to_sat()
        .checked_mul(1000)
        .ok_or_else(|| general(format!("{amount} is too large to express in millisatoshis")))
}

/// `amount + fee`, rejected rather than panicking on overflow. The fee is
/// bounded by `check_fee` first, so this only fires on an absurd amount.
fn total_with_fee(amount: Amount, fee: Amount) -> Result<Amount, TakerError> {
    amount
        .checked_add(fee)
        .ok_or_else(|| general(format!("{amount} plus a fee of {fee} overflows")))
}

/// An invoice's final CLTV delta as a locktime-sized value. The wire
/// locktime is a `u16`, so a delta that does not fit cannot be covered by
/// any locktime we could send. Reject it rather than truncate: `as u16`
/// turns 65,536 into 0, which then passes every check below it.
fn cltv_delta_blocks(delta: u64) -> Result<u16, TakerError> {
    if delta > u16::MAX as u64 {
        return Err(general(format!(
            "invoice cltv delta {delta} exceeds the largest locktime this protocol can express"
        )));
    }
    Ok(delta as u16)
}

fn general(msg: impl Into<String>) -> TakerError {
    TakerError::General(msg.into())
}

/// A maker connection with the hello/offer handshake completed.
struct LnMakerConn {
    socket: TcpStream,
    address: String,
    ln_offer: LightningOffer,
    /// Exact feature names this swap uses, sent in its request.
    pins: Vec<String>,
}

impl LnMakerConn {
    fn send(&mut self, msg: LightningTakerMessage) -> Result<(), TakerError> {
        send_message(
            &mut self.socket,
            &TakerToMakerMessage::Lightning(Box::new(msg)),
        )
        .map_err(|e| general(format!("send to maker failed: {e:?}")))
    }

    /// Listens briefly for an early rejection. A maker that refuses replies
    /// at once, while one that accepted stays silent until its side of the
    /// swap resolves, so silence here means "working on it".
    ///
    /// The caller must not read this connection again afterwards: a read
    /// that times out mid-frame would leave the stream unaligned.
    fn check_no_early_reject(&mut self, window: Duration) -> Result<(), TakerError> {
        let previous = self.socket.read_timeout().ok().flatten();
        if self.socket.set_read_timeout(Some(window)).is_err() {
            return Ok(());
        }
        let early = read_message(&mut self.socket);
        let _ = self.socket.set_read_timeout(previous);
        match early {
            Ok(bytes) => match serde_cbor::from_slice::<MakerToTakerMessage>(&bytes) {
                Ok(MakerToTakerMessage::Lightning(ln)) => match *ln {
                    LightningMakerMessage::Reject(reject) => {
                        Err(general(format!("maker rejected swap: {}", reject.reason)))
                    }
                    other => Err(general(format!("unexpected early reply: {other}"))),
                },
                Ok(MakerToTakerMessage::Unsupported(unsupported)) => Err(general(format!(
                    "maker does not support {}: {}",
                    unsupported.what, unsupported.reason
                ))),
                Ok(other) => Err(general(format!("unexpected early reply: {other:?}"))),
                Err(e) => Err(general(format!("bad maker message: {e:?}"))),
            },
            Err(e) => {
                log::debug!("no early reply from maker (expected): {e:?}");
                Ok(())
            }
        }
    }

    /// Reads the next Lightning-family reply, surfacing `Reject` and
    /// `Unsupported` as errors.
    fn read_ln(&mut self) -> Result<LightningMakerMessage, TakerError> {
        read_ln_reply(&mut self.socket)
    }
}

/// Reads the next Lightning-family reply on `socket`, surfacing `Reject` and
/// `Unsupported` as errors.
fn read_ln_reply(socket: &mut TcpStream) -> Result<LightningMakerMessage, TakerError> {
    let bytes =
        read_message(socket).map_err(|e| general(format!("read from maker failed: {e:?}")))?;
    let msg: MakerToTakerMessage =
        serde_cbor::from_slice(&bytes).map_err(|e| general(format!("bad maker message: {e:?}")))?;
    match msg {
        MakerToTakerMessage::Lightning(ln) => match *ln {
            LightningMakerMessage::Reject(reject) => {
                Err(general(format!("maker rejected swap: {}", reject.reason)))
            }
            other => Ok(other),
        },
        MakerToTakerMessage::Unsupported(unsupported) => Err(general(format!(
            "maker does not support {}: {}",
            unsupported.what, unsupported.reason
        ))),
        other => Err(general(format!("unexpected maker message: {other:?}"))),
    }
}

impl Taker {
    /// Injects a Lightning backend (tests only).
    #[cfg(feature = "integration-test")]
    pub fn set_lightning_backend(&mut self, backend: Arc<dyn LightningBackend>) {
        self.lightning = Some(backend);
    }

    fn ln_backend(&self) -> Result<Arc<dyn LightningBackend>, TakerError> {
        self.lightning
            .clone()
            .ok_or_else(|| general("no lightning backend configured (set ldk_server_url)"))
    }

    /// Picks a maker for a Lightning swap: the explicit address, or the
    /// first good offerbook maker advertising suitable Lightning terms.
    fn select_lightning_maker(
        &self,
        explicit: Option<String>,
        swap_in: bool,
        amount: Amount,
    ) -> Result<String, TakerError> {
        if let Some(address) = explicit {
            return Ok(address);
        }
        let makers = self.offerbook.good_makers()?;
        makers
            .iter()
            .find(|m| {
                m.offer.lightning.is_some_and(|ln| {
                    let (served, max_size) = ln.direction_limits(swap_in);
                    served && amount.to_sat() >= ln.min_size && amount.to_sat() <= max_size
                })
            })
            .map(|m| m.address.to_string())
            .ok_or_else(|| general("no maker in the offerbook advertises suitable Lightning terms"))
    }

    /// Connects, runs the hello/offer handshake and checks the maker's live
    /// Lightning terms cover this swap.
    fn connect_ln_maker(
        &self,
        address: &str,
        swap_in: bool,
        amount: Amount,
    ) -> Result<LnMakerConn, TakerError> {
        let flow = if swap_in { "ln-swap-in" } else { "ln-swap-out" };
        let (mut socket, features) = self
            .net_connect_with(address, &[flow.to_string()])
            .map_err(|e| general(format!("hello failed: {e:?}")))?;
        let pins = choose_pins(flow, &features);
        // Checked before anything is funded or paid.
        unmet_for_flow(&self.require_features, &pins, flow).map_err(|missing| {
            general(format!("maker cannot meet required features {missing:?}"))
        })?;

        send_message(&mut socket, &TakerToMakerMessage::GetOffer(GetOffer))
            .map_err(|e| general(format!("get offer failed: {e:?}")))?;
        let bytes =
            read_message(&mut socket).map_err(|e| general(format!("offer reply: {e:?}")))?;
        let msg: MakerToTakerMessage =
            serde_cbor::from_slice(&bytes).map_err(|e| general(format!("bad offer: {e:?}")))?;
        let offer: Offer = match msg {
            MakerToTakerMessage::Offer(offer) => *offer,
            other => return Err(general(format!("expected Offer, got {other:?}"))),
        };
        let ln_offer = offer
            .lightning
            .ok_or_else(|| general("maker does not offer Lightning swaps"))?;
        let (served, max_size) = ln_offer.direction_limits(swap_in);
        if !served {
            return Err(general("maker does not offer this swap direction"));
        }
        if amount.to_sat() < ln_offer.min_size || amount.to_sat() > max_size {
            return Err(general(format!(
                "amount {} outside maker's {} range [{}, {}]",
                amount,
                if swap_in { "swap-in" } else { "swap-out" },
                ln_offer.min_size,
                max_size
            )));
        }
        Ok(LnMakerConn {
            socket,
            address: address.to_string(),
            ln_offer,
            pins,
        })
    }

    /// Waits for a matching Lightning event on our own node.
    fn wait_ln_event(
        &self,
        ln: &Arc<dyn LightningBackend>,
        payment_hash: &sha256::Hash,
        mut matches: impl FnMut(&LnEvent) -> bool,
        what: &str,
    ) -> Result<LnEvent, TakerError> {
        let deadline = Instant::now() + LN_STEP_TIMEOUT;
        loop {
            match ln
                .poll_event()
                .map_err(|e| general(format!("lightning poll: {e:?}")))?
            {
                Some(event) => {
                    let event_hash = match &event {
                        LnEvent::PaymentClaimable { payment_hash, .. }
                        | LnEvent::PaymentSuccessful { payment_hash, .. }
                        | LnEvent::PaymentFailed { payment_hash, .. } => *payment_hash,
                        LnEvent::PaymentReceived { payment_hash, .. } => *payment_hash,
                        _ => None,
                    };
                    if event_hash == Some(*payment_hash) && matches(&event) {
                        return Ok(event);
                    }
                    log::debug!("ignoring lightning event: {event:?}");
                    // Checked here too: a backend emitting a steady stream of
                    // events for other payments would otherwise never reach
                    // the deadline, and never sleep either.
                    if Instant::now() > deadline {
                        return Err(general(format!("timed out waiting for {what}")));
                    }
                }
                None => {
                    if Instant::now() > deadline {
                        return Err(general(format!("timed out waiting for {what}")));
                    }
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
    }

    fn save_pending_swap(&self, swap_id: &str, record: LnPendingSwap) -> Result<(), TakerError> {
        let mut wallet = self.write_wallet()?;
        wallet
            .store
            .ln_pending_swaps
            .insert(swap_id.to_string(), record);
        wallet.save_to_disk()?;
        Ok(())
    }

    fn remove_pending_swap(&self, swap_id: &str) -> Result<(), TakerError> {
        let mut wallet = self.write_wallet()?;
        wallet.store.ln_pending_swaps.remove(swap_id);
        wallet.save_to_disk()?;
        Ok(())
    }

    /// Funds `address` with `value` from the wallet and returns the
    /// confirmed outpoint.
    fn fund_htlc_output(
        &self,
        htlc: &SwapHtlc,
        value: Amount,
        min_confirmations: u32,
        swap_id: &str,
    ) -> Result<(OutPoint, Amount), TakerError> {
        let network = self.read_wallet()?.store.network;
        let address = htlc
            .address(network)
            .map_err(|e| general(format!("htlc address: {e}")))?;
        let spk = address.script_pubkey();

        // Build and record the funding, then broadcast. The transaction fixes
        // its own outpoint before it reaches the network, and a crash between
        // a broadcast and its record would strand the HTLC: recovery treats a
        // record without an outpoint as "nothing was committed" and discards
        // the only copy of our branch key.
        let (outpoint, actual_value) = {
            let mut wallet = self.write_wallet()?;
            // One split, one destination: an HTLC output is a single exact
            // payment, with no hop to reimburse and nothing to randomize.
            // A Lightning HTLC is a script-path P2WSH contract, priced like
            // the Legacy protocol's rather than Taproot's.
            let plan = wallet.plan_funding(
                value,
                1,
                MIN_RELAY_FEE_RATE,
                u32::MAX,
                None,
                None,
                None,
                crate::protocol::ProtocolVersion::Legacy,
            )?;
            let result = wallet.execute_funding_plan(&plan, &[address], MIN_RELAY_FEE_RATE)?;
            let tx = result
                .funding_txes
                .into_iter()
                .next()
                .ok_or_else(|| general("no funding tx created"))?;
            // Locate the HTLC by its script: a positional fallback could point
            // at the change output, whose value we cannot spend with the
            // HTLC's keys.
            let vout = tx
                .output
                .iter()
                .position(|output| output.script_pubkey == spk)
                .ok_or_else(|| general("funding tx has no HTLC output"))?
                as u32;
            let outpoint = OutPoint {
                txid: tx.compute_txid(),
                vout,
            };
            let actual_value = tx.output[vout as usize].value;
            if let Some(record) = wallet.store.ln_pending_swaps.get_mut(swap_id) {
                record.outpoint = Some(outpoint);
                record.value = Some(actual_value);
            }
            wallet.save_to_disk()?;
            wallet.send_tx(&tx)?;
            (outpoint, actual_value)
        };
        let _ = self.watch_service.register_watch_request(outpoint, spk);

        log::info!("HTLC funding broadcast: {outpoint}, waiting for {min_confirmations} conf");
        self.read_wallet()?.wait_for_tx_confirmation(
            &[outpoint.txid],
            min_confirmations,
            None,
            None,
        )?;
        Ok((outpoint, actual_value))
    }

    /// Swap-in: pay on-chain BTC, receive Lightning balance.
    pub fn lightning_swap_in(&mut self, params: LnSwapParams) -> Result<LnSwapReport, TakerError> {
        let ln = self.ln_backend()?;
        let address =
            self.select_lightning_maker(params.maker_address.clone(), true, params.amount)?;
        let mut conn = self.connect_ln_maker(&address, true, params.amount)?;
        let expected_fee = advertised_fee(&conn.ln_offer, params.amount);

        // Fresh preimage, hold invoice on our node, refund key.
        let mut preimage_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut preimage_bytes);
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let swap_id = payment_hash.to_string();
        let (timelock_pubkey, timelock_privkey) = generate_keypair();

        let invoice = ln
            .create_hold_invoice(
                payment_hash,
                InvoiceParams {
                    amount_msat: Some(msat(params.amount)?),
                    description: format!("swap-in {swap_id}"),
                    expiry_secs: 3600,
                },
            )
            .map_err(|e| general(format!("hold invoice: {e:?}")))?;

        // The refund locktime must clear our own invoice's CLTV window; the
        // maker enforces the same bound on its side.
        let cltv_delta = cltv_delta_blocks(
            verify_invoice(&invoice.invoice, &payment_hash, msat(params.amount)?)
                .map_err(|e| general(format!("own invoice failed verification: {e}")))?
                .min_final_cltv_expiry_delta,
        )?;
        let locktime = match params.locktime {
            Some(locktime) => locktime,
            None => cltv_delta
                .checked_add(DEFAULT_LOCKTIME_HEADROOM)
                .ok_or_else(|| {
                    general(format!(
                        "invoice cltv delta {cltv_delta} leaves no room for a default locktime"
                    ))
                })?,
        };
        if locktime < cltv_delta.saturating_add(CLTV_SAFETY_MARGIN) {
            return Err(general(format!(
                "locktime {locktime} too short for invoice cltv delta {cltv_delta}"
            )));
        }

        conn.send(LightningTakerMessage::SwapInRequest(LnSwapInRequest {
            swap_id: swap_id.clone(),
            invoice: invoice.invoice,
            payment_hash,
            amount: params.amount,
            locktime,
            min_confirmations: params.min_confirmations,
            taker_timelock_pubkey: timelock_pubkey,
            features: conn.pins.clone(),
        }))?;
        let accept = match conn.read_ln()? {
            LightningMakerMessage::SwapInAccept(accept) => accept,
            other => return Err(general(format!("expected SwapInAccept, got {other}"))),
        };
        if accept.swap_id != swap_id
            || accept.locktime != locktime
            || accept.min_confirmations != params.min_confirmations
        {
            return Err(general("maker echoed different terms"));
        }
        check_fee(accept.fee, expected_fee, params.amount)?;

        let htlc = SwapHtlc::new(
            &accept.maker_hashlock_pubkey,
            &timelock_pubkey,
            &payment_hash,
            locktime,
        );

        // Recovery record first, then commit funds.
        self.save_pending_swap(
            &swap_id,
            LnPendingSwap {
                is_swap_in: true,
                preimage: Some(preimage.0),
                redeemscript: htlc.redeemscript().clone(),
                locktime,
                privkey: timelock_privkey,
                outpoint: None,
                value: None,
                payout_script: None,
                resume: None,
            },
        )?;
        let funding_value = total_with_fee(params.amount, accept.fee)?;
        let (outpoint, actual_value) =
            self.fund_htlc_output(&htlc, funding_value, params.min_confirmations, &swap_id)?;

        #[cfg(feature = "integration-test")]
        let announced_value = if self.behavior == super::api::TakerBehavior::ForgeSwapInFundedValue
        {
            actual_value + Amount::from_sat(1)
        } else {
            actual_value
        };
        #[cfg(not(feature = "integration-test"))]
        let announced_value = actual_value;
        conn.send(LightningTakerMessage::SwapInFunded(LnHtlcFunded {
            swap_id: swap_id.clone(),
            outpoint,
            value: announced_value,
        }))?;

        // The maker verifies and pays our hold invoice; claim it with the
        // preimage the moment it parks.
        self.wait_ln_event(
            &ln,
            &payment_hash,
            |event| matches!(event, LnEvent::PaymentClaimable { .. }),
            "maker's payment",
        )?;
        ln.claim_held_payment(&preimage)
            .map_err(|e| general(format!("claim held payment: {e:?}")))?;
        log::info!("Swap-in {swap_id}: Lightning payment claimed");

        // The maker's completion note is informational; a dropped socket
        // here does not affect our side.
        match conn.read_ln() {
            Ok(LightningMakerMessage::SwapInComplete(_)) => {}
            Ok(other) => log::warn!("unexpected closing message: {other}"),
            Err(e) => log::debug!("no completion message from maker: {e:?}"),
        }

        self.remove_pending_swap(&swap_id)?;
        Ok(LnSwapReport {
            swap_id,
            maker: conn.address,
            amount: params.amount,
            fee: accept.fee,
            funding_outpoint: outpoint,
            claim_txid: None,
        })
    }

    /// Swap-out: pay Lightning balance, receive on-chain BTC.
    pub fn lightning_swap_out(&mut self, params: LnSwapParams) -> Result<LnSwapReport, TakerError> {
        let ln = self.ln_backend()?;
        let address =
            self.select_lightning_maker(params.maker_address.clone(), false, params.amount)?;
        let mut conn = self.connect_ln_maker(&address, false, params.amount)?;
        let expected_fee = advertised_fee(&conn.ln_offer, params.amount);

        let mut preimage_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut preimage_bytes);
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let swap_id = payment_hash.to_string();
        let (hashlock_pubkey, hashlock_privkey) = generate_keypair();
        let locktime = params.locktime.unwrap_or(DEFAULT_SWAP_OUT_LOCKTIME);

        conn.send(LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
            swap_id: swap_id.clone(),
            payment_hash,
            amount: params.amount,
            locktime,
            min_confirmations: params.min_confirmations,
            taker_hashlock_pubkey: hashlock_pubkey,
            features: conn.pins.clone(),
        }))?;
        let accept = match conn.read_ln()? {
            LightningMakerMessage::SwapOutAccept(accept) => accept,
            other => return Err(general(format!("expected SwapOutAccept, got {other}"))),
        };
        if accept.swap_id != swap_id
            || accept.locktime != locktime
            || accept.min_confirmations != params.min_confirmations
        {
            return Err(general("maker echoed different terms"));
        }
        check_fee(accept.fee, expected_fee, params.amount)?;
        // Never pay an invoice we did not verify: it must commit to OUR
        // payment hash and the agreed amount, or the maker could settle
        // instantly without funding anything.
        verify_invoice(
            &accept.invoice,
            &payment_hash,
            msat(total_with_fee(params.amount, accept.fee)?)?,
        )
        .map_err(|e| general(format!("maker invoice failed verification: {e}")))?;

        let htlc = SwapHtlc::new(
            &hashlock_pubkey,
            &accept.maker_timelock_pubkey,
            &payment_hash,
            locktime,
        );
        self.save_pending_swap(
            &swap_id,
            LnPendingSwap {
                is_swap_in: false,
                preimage: Some(preimage.0),
                redeemscript: htlc.redeemscript().clone(),
                locktime,
                privkey: hashlock_privkey,
                outpoint: None,
                value: None,
                payout_script: None,
                // Saved just before we pay, so from here on the maker may
                // fund, and a lost reply can be asked for again.
                resume: Some(LnFundingResume {
                    maker: conn.address.clone(),
                    amount: params.amount,
                    min_confirmations: params.min_confirmations,
                }),
            },
        )?;

        // Pay the hold invoice: the payment parks at the maker (it cannot
        // settle without our preimage) and prompts it to fund the HTLC.
        // Keep the payment's worst-case resolution inside the on-chain
        // window we are about to claim within, so a swap cannot straddle the
        // HTLC's timelock.
        let cltv_bound = (locktime as u32).saturating_sub(CLTV_SAFETY_MARGIN as u32);
        ln.pay_invoice(&accept.invoice, None, Some(cltv_bound))
            .map_err(|e| general(format!("pay invoice: {e:?}")))?;
        conn.send(LightningTakerMessage::SwapOutPaid(LnSwapOutPaid {
            swap_id: swap_id.clone(),
        }))?;
        #[cfg(feature = "integration-test")]
        if self.behavior == super::api::TakerBehavior::DropSwapOutFundingReply {
            return Err(general("dropped the connection before the funding reply"));
        }
        let funded = match conn.read_ln()? {
            LightningMakerMessage::SwapOutFunded(funded) => funded,
            other => return Err(general(format!("expected SwapOutFunded, got {other}"))),
        };
        if funded.swap_id != swap_id {
            return Err(general("funding for a different swap"));
        }

        // Verify the funding against our own script derivation, then claim.
        self.read_wallet()?.wait_for_tx_confirmation(
            &[funded.outpoint.txid],
            params.min_confirmations,
            None,
            None,
        )?;
        let funding_tx = {
            use crate::wallet::blockchain::Blockchain;
            self.read_wallet()?
                .blockchain
                .get_raw_transaction(&funded.outpoint.txid, None)?
        };
        let output = funding_tx
            .output
            .get(funded.outpoint.vout as usize)
            .ok_or_else(|| general("funding vout out of range"))?
            .clone();
        if funded.value != output.value {
            return Err(general("announced funding value mismatch"));
        }
        htlc.validate_funding_output(&output, params.amount)
            .map_err(|e| general(format!("bad funding output: {e}")))?;
        // Screen the transaction that confirmed, before recording its outpoint:
        // recovery claims any recorded outpoint, so a refused one must never
        // reach the record.
        self.screen_funding_tx(&funding_tx)?;
        let destination = record_funding(
            &mut *self.write_wallet()?,
            &swap_id,
            funded.outpoint,
            output.value,
        )?;
        let claim_tx = htlc
            .create_hashlock_spend(
                funded.outpoint,
                output.value,
                &hashlock_privkey,
                &preimage,
                destination,
            )
            .map_err(|e| general(format!("claim build: {e}")))?;
        let claim_txid = self.read_wallet()?.send_tx(&claim_tx)?;
        log::info!("Swap-out {swap_id}: on-chain claim broadcast: {claim_txid}");

        // Courtesy notification so the maker settles immediately.
        let _ = conn.send(LightningTakerMessage::SwapOutClaimed(LnSwapOutClaimed {
            swap_id: swap_id.clone(),
            claim_txid,
        }));
        match conn.read_ln() {
            Ok(LightningMakerMessage::SwapOutComplete(_)) => {}
            Ok(other) => log::warn!("unexpected closing message: {other}"),
            Err(e) => log::debug!("no completion message from maker: {e:?}"),
        }

        // Our Lightning payment settles when the maker uses the on-chain
        // preimage; informational for the report.
        if let Err(e) = self.wait_ln_event(
            &ln,
            &payment_hash,
            |event| matches!(event, LnEvent::PaymentSuccessful { .. }),
            "payment settlement",
        ) {
            log::warn!("swap-out {swap_id}: settlement not observed: {e:?}");
        }

        // The record stays until the claim confirms. The maker may already
        // have settled with the preimage, so a claim that is evicted or
        // reorged out must still be rebuilt. `recover_lightning_swaps` drops
        // it once the spend is confirmed.
        let _ = self.write_wallet()?.sync_and_save(&Default::default());
        Ok(LnSwapReport {
            swap_id,
            maker: conn.address,
            amount: params.amount,
            fee: accept.fee,
            funding_outpoint: funded.outpoint,
            claim_txid: Some(claim_txid),
        })
    }

    /// Routed swap: on-chain to maker 1, Lightning from maker 1 to maker 2,
    /// on-chain back to the taker. Needs no Lightning node on this side.
    ///
    /// The taker collects maker 2's hold invoice first and hands it to maker
    /// 1, so the single Lightning payment of the swap runs between the two
    /// makers. One preimage governs all three legs: the taker's claim of
    /// maker 2's HTLC publishes it on-chain, which lets maker 2 settle the
    /// held payment, which in turn releases it to maker 1 for its own claim.
    pub fn lightning_swap_routed(
        &mut self,
        params: LnRoutedSwapParams,
    ) -> Result<LnRoutedSwapReport, TakerError> {
        let mut preimage_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut preimage_bytes);
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let swap_id = payment_hash.to_string();
        // Distinct keys: both hops share the payment hash, but each needs its
        // own recovery record (different branch, key and outpoint).
        let in_key = format!("{swap_id}-in");
        let out_key = format!("{swap_id}-out");
        // Hop 1 is ours to refund; hop 2 is ours to claim.
        let (timelock_pubkey, timelock_privkey) = generate_keypair();
        let (hashlock_pubkey, hashlock_privkey) = generate_keypair();
        let out_locktime = params.locktime.unwrap_or(DEFAULT_SWAP_OUT_LOCKTIME);

        // ---- Hop 2 first: maker 1 cannot pay an invoice that does not exist ----
        let address2 =
            self.select_lightning_maker(params.second_maker.clone(), false, params.amount)?;
        let mut conn2 = self.connect_ln_maker(&address2, false, params.amount)?;
        let expected_fee2 = advertised_fee(&conn2.ln_offer, params.amount);

        conn2.send(LightningTakerMessage::SwapOutRequest(LnSwapOutRequest {
            swap_id: swap_id.clone(),
            payment_hash,
            amount: params.amount,
            locktime: out_locktime,
            min_confirmations: params.min_confirmations,
            taker_hashlock_pubkey: hashlock_pubkey,
            features: conn2.pins.clone(),
        }))?;
        let accept2 = match conn2.read_ln()? {
            LightningMakerMessage::SwapOutAccept(accept) => accept,
            other => return Err(general(format!("expected SwapOutAccept, got {other}"))),
        };
        if accept2.swap_id != swap_id
            || accept2.locktime != out_locktime
            || accept2.min_confirmations != params.min_confirmations
        {
            return Err(general("second maker echoed different terms"));
        }
        check_fee(accept2.fee, expected_fee2, params.amount)?;

        // What maker 1 must forward over Lightning: our payout plus maker 2's
        // fee. Verified against the invoice we are about to hand over, since
        // maker 1 will check the same thing and reject a mismatch.
        let middle_amount = total_with_fee(params.amount, accept2.fee)?;
        let cltv_delta = cltv_delta_blocks(
            verify_invoice(&accept2.invoice, &payment_hash, msat(middle_amount)?)
                .map_err(|e| general(format!("second maker's invoice failed verification: {e}")))?
                .min_final_cltv_expiry_delta,
        )?;

        // The hop we fund must outlive the hop we claim from, and must also
        // clear the Lightning claim window maker 1 is exposed to.
        let in_locktime = out_locktime.saturating_add(ROUTED_HOP_TIMELOCK_MARGIN);
        if in_locktime < cltv_delta.saturating_add(CLTV_SAFETY_MARGIN) {
            return Err(general(format!(
                "first hop locktime {in_locktime} too short for invoice cltv delta {cltv_delta}"
            )));
        }

        // ---- Hop 1: hand maker 2's invoice to maker 1 ----
        let address1 =
            self.select_lightning_maker(params.first_maker.clone(), true, middle_amount)?;
        if address1 == address2 {
            return Err(general(
                "routed swap needs two distinct makers; one maker would see both ends",
            ));
        }
        let mut conn1 = self.connect_ln_maker(&address1, true, middle_amount)?;
        let expected_fee1 = advertised_fee(&conn1.ln_offer, middle_amount);

        conn1.send(LightningTakerMessage::SwapInRequest(LnSwapInRequest {
            swap_id: swap_id.clone(),
            invoice: accept2.invoice.clone(),
            payment_hash,
            amount: middle_amount,
            locktime: in_locktime,
            min_confirmations: params.min_confirmations,
            taker_timelock_pubkey: timelock_pubkey,
            features: conn1.pins.clone(),
        }))?;
        let accept1 = match conn1.read_ln()? {
            LightningMakerMessage::SwapInAccept(accept) => accept,
            other => return Err(general(format!("expected SwapInAccept, got {other}"))),
        };
        if accept1.swap_id != swap_id
            || accept1.locktime != in_locktime
            || accept1.min_confirmations != params.min_confirmations
        {
            return Err(general("first maker echoed different terms"));
        }
        check_fee(accept1.fee, expected_fee1, middle_amount)?;

        let htlc1 = SwapHtlc::new(
            &accept1.maker_hashlock_pubkey,
            &timelock_pubkey,
            &payment_hash,
            in_locktime,
        );
        let htlc2 = SwapHtlc::new(
            &hashlock_pubkey,
            &accept2.maker_timelock_pubkey,
            &payment_hash,
            out_locktime,
        );

        // Recovery records before any value moves. Hop 2 has no outpoint yet;
        // it is filled in once maker 2 funds.
        self.save_pending_swap(
            &in_key,
            LnPendingSwap {
                is_swap_in: true,
                preimage: Some(preimage.0),
                redeemscript: htlc1.redeemscript().clone(),
                locktime: in_locktime,
                privkey: timelock_privkey,
                outpoint: None,
                value: None,
                payout_script: None,
                resume: None,
            },
        )?;
        self.save_pending_swap(
            &out_key,
            LnPendingSwap {
                is_swap_in: false,
                preimage: Some(preimage.0),
                redeemscript: htlc2.redeemscript().clone(),
                locktime: out_locktime,
                privkey: hashlock_privkey,
                outpoint: None,
                value: None,
                payout_script: None,
                resume: Some(LnFundingResume {
                    maker: conn2.address.clone(),
                    amount: params.amount,
                    min_confirmations: params.min_confirmations,
                }),
            },
        )?;

        let sent = total_with_fee(middle_amount, accept1.fee)?;
        let (outpoint1, value1) =
            self.fund_htlc_output(&htlc1, sent, params.min_confirmations, &in_key)?;
        conn1.send(LightningTakerMessage::SwapInFunded(LnHtlcFunded {
            swap_id: swap_id.clone(),
            outpoint: outpoint1,
            value: value1,
        }))?;
        // Maker 1 goes quiet here until it learns the preimage — which cannot
        // happen until we claim hop 2 — so only a rejection would arrive now.
        // Nothing is read from this connection afterwards; maker 1 sweeps on
        // its own once the preimage reaches it over Lightning.
        conn1.check_no_early_reject(EARLY_REJECT_WINDOW)?;
        log::info!("routed swap {swap_id}: hop 1 funded at {outpoint1}");

        // ---- Maker 1 pays maker 2; maker 2 then funds our payout ----
        conn2.send(LightningTakerMessage::SwapOutPaid(LnSwapOutPaid {
            swap_id: swap_id.clone(),
        }))?;
        let funded2 = match conn2.read_ln()? {
            LightningMakerMessage::SwapOutFunded(funded) => funded,
            other => return Err(general(format!("expected SwapOutFunded, got {other}"))),
        };
        if funded2.swap_id != swap_id {
            return Err(general("funding announced for a different swap"));
        }
        self.read_wallet()?.wait_for_tx_confirmation(
            &[funded2.outpoint.txid],
            params.min_confirmations,
            None,
            None,
        )?;
        let funding_tx = {
            use crate::wallet::blockchain::Blockchain;
            self.read_wallet()?
                .blockchain
                .get_raw_transaction(&funded2.outpoint.txid, None)?
        };
        let output2 = funding_tx
            .output
            .get(funded2.outpoint.vout as usize)
            .ok_or_else(|| general("funding vout out of range"))?
            .clone();
        if funded2.value != output2.value {
            return Err(general("announced funding value mismatch"));
        }
        htlc2
            .validate_funding_output(&output2, params.amount)
            .map_err(|e| general(format!("bad funding output: {e}")))?;
        // As in a swap-out: screen before recording, so recovery never claims
        // a refused hop 2. Not claiming keeps the preimage from maker 1.
        self.screen_funding_tx(&funding_tx)?;
        let destination = record_funding(
            &mut *self.write_wallet()?,
            &out_key,
            funded2.outpoint,
            output2.value,
        )?;

        // ---- Claim hop 2: publishes the preimage that unlocks hop 1 ----
        let claim_tx = htlc2
            .create_hashlock_spend(
                funded2.outpoint,
                output2.value,
                &hashlock_privkey,
                &preimage,
                destination,
            )
            .map_err(|e| general(format!("claim build: {e}")))?;
        let claim_txid = self.read_wallet()?.send_tx(&claim_tx)?;
        log::info!("routed swap {swap_id}: hop 2 claimed in {claim_txid}");

        let _ = conn2.send(LightningTakerMessage::SwapOutClaimed(LnSwapOutClaimed {
            swap_id: swap_id.clone(),
            claim_txid,
        }));
        match conn2.read_ln() {
            Ok(LightningMakerMessage::SwapOutComplete(_)) => {}
            Ok(other) => log::warn!("unexpected closing message: {other}"),
            Err(e) => log::debug!("no completion message from second maker: {e:?}"),
        }

        // Hop 2's record stays until its claim confirms, as in a swap-out.
        // Hop 1 needs nothing more from us: maker 1 sweeps it with the
        // preimage our claim publishes.
        self.remove_pending_swap(&in_key)?;
        let _ = self.write_wallet()?.sync_and_save(&Default::default());

        Ok(LnRoutedSwapReport {
            swap_id,
            first_maker: conn1.address.clone(),
            second_maker: conn2.address.clone(),
            sent,
            received: params.amount,
            first_fee: accept1.fee,
            second_fee: accept2.fee,
            funding_outpoint: outpoint1,
            claim_txid,
        })
    }

    /// Resolves persisted Lightning swap records: claims with the preimage
    /// where we hold it, refunds through the timelock otherwise. Returns a
    /// human-readable line per record describing what happened.
    pub fn recover_lightning_swaps(&mut self) -> Result<Vec<String>, TakerError> {
        let mut records: Vec<(String, LnPendingSwap)> = self
            .read_wallet()?
            .store
            .ln_pending_swaps
            .iter()
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect();
        // Claims and refunds we can already build go first: none of them
        // should wait behind a maker asked for funding it never confirmed.
        records.sort_by_key(|(_, record)| record.outpoint.is_none() || record.value.is_none());

        let mut outcomes = Vec::new();
        for (swap_id, record) in &records {
            let (outpoint, value) = match (record.outpoint, record.value) {
                (Some(outpoint), Some(value)) => (outpoint, value),
                _ => match self.recover_funding(swap_id, record, &records, &mut outcomes)? {
                    Some(funding) => funding,
                    None => continue,
                },
            };
            let htlc = SwapHtlc::from_redeemscript(record.redeemscript.clone(), record.locktime);
            let destination = payout_script(&mut *self.write_wallet()?, swap_id)?;
            let spend = if record.is_swap_in {
                // Our money, refund branch (CSV-gated).
                htlc.create_timelock_spend(outpoint, value, &record.privkey, destination)
            } else {
                // Claim with our own preimage.
                let preimage = Preimage(
                    record
                        .preimage
                        .ok_or_else(|| general("swap-out record without preimage"))?,
                );
                htlc.create_hashlock_spend(outpoint, value, &record.privkey, &preimage, destination)
            }
            .map_err(|e| general(format!("recovery spend build: {e}")))?;

            // A record is the only copy of the key that reaches this HTLC, so
            // it is dropped on one condition alone: the outpoint has a
            // *confirmed* spend. Neither a successful broadcast nor an
            // ambiguous backend error qualifies — a mempool spend can still
            // be evicted or reorged out, and deleting on one strands the
            // HTLC for good.
            let broadcast = self.read_wallet()?.send_tx(&spend);
            match &broadcast {
                Ok(txid) => log::info!("{swap_id}: recovery spend broadcast in {txid}"),
                Err(e) => log::debug!("{swap_id}: recovery spend not accepted: {e:?}"),
            }

            let script = htlc
                .script_pubkey()
                .map_err(|e| general(format!("htlc spk: {e}")))?;
            let settled = {
                use crate::wallet::blockchain::Blockchain;
                self.read_wallet()?
                    .blockchain
                    .is_confirmed_spend(&outpoint, &script)
            };
            match settled {
                Ok(true) => {
                    self.remove_pending_swap(swap_id)?;
                    outcomes.push(match broadcast {
                        Ok(txid) => format!("{swap_id}: recovered via {txid}"),
                        Err(_) => format!("{swap_id}: already resolved on-chain"),
                    });
                }
                Ok(false) => outcomes.push(match broadcast {
                    Ok(txid) => {
                        format!("{swap_id}: recovery {txid} broadcast, awaiting confirmation")
                    }
                    Err(e) if format!("{e:?}").contains("non-BIP68-final") => format!(
                        "{swap_id}: refund not yet mature (locktime {}); retry later",
                        record.locktime
                    ),
                    Err(e) => format!("{swap_id}: not yet recovered: {e:?}"),
                }),
                // The chain query itself failed, which says nothing about the
                // outpoint. Keep the record and retry later.
                Err(e) => outcomes.push(format!("{swap_id}: spend status unknown: {e:?}")),
            }
        }
        let _ = self.write_wallet()?.sync_and_save(&Default::default());
        Ok(outcomes)
    }

    /// Handles a record with no funding outpoint. Returns the funding once a
    /// resumed swap-out has it verified and saved; otherwise reports what
    /// happened in `outcomes`.
    fn recover_funding(
        &self,
        key: &str,
        record: &LnPendingSwap,
        records: &[(String, LnPendingSwap)],
        outcomes: &mut Vec<String>,
    ) -> Result<Option<(OutPoint, Amount)>, TakerError> {
        let ln = self.lightning.clone();
        let payment = |hash| ln.as_ref()?.payment_outcome(hash).ok();
        let first_hop_spent = |hop: &LnPendingSwap| {
            use crate::wallet::blockchain::Blockchain;
            let outpoint = hop.outpoint?;
            let script = SwapHtlc::from_redeemscript(hop.redeemscript.clone(), hop.locktime)
                .script_pubkey()
                .ok()?;
            let wallet = self.read_wallet().ok()?;
            wallet
                .blockchain
                .is_confirmed_spend(&outpoint, &script)
                .ok()
        };
        let resume = match unfunded_action(key, record, records, payment, first_hop_spent) {
            Unfunded::Forget(why) => {
                self.remove_pending_swap(key)?;
                outcomes.push(format!("{key}: {why}; forgotten"));
                return Ok(None);
            }
            Unfunded::Keep(why) => {
                outcomes.push(format!("{key}: {why}; kept"));
                return Ok(None);
            }
            Unfunded::Resume(resume) => resume,
        };
        match self.resume_funding(key, record, resume) {
            Ok(Some((outpoint, value))) => {
                record_funding(&mut *self.write_wallet()?, key, outpoint, value)?;
                log::info!("{key}: funding {outpoint} recovered from the maker");
                Ok(Some((outpoint, value)))
            }
            Ok(None) => {
                outcomes.push(format!(
                    "{key}: funding announced, waiting for {} confirmation(s)",
                    resume.min_confirmations
                ));
                Ok(None)
            }
            // The maker answers with the same funding every time, and we will
            // never claim this one, so the record has nothing left to do.
            Err(TakerError::Blocklist(BlocklistError::BlockedAddress { .. })) => {
                self.remove_pending_swap(key)?;
                outcomes.push(format!("{key}: funding refused by screening; forgotten"));
                Ok(None)
            }
            Err(e) => {
                outcomes.push(format!("{key}: funding not recovered yet: {e:?}"));
                Ok(None)
            }
        }
    }

    /// Asks the maker for a swap-out's funding again. `SwapOutPaid` is
    /// idempotent: once the maker has funded, it answers with the same
    /// `SwapOutFunded`. Returns the funding once it is checked, screened and
    /// confirmed, and `None` while it waits for confirmations.
    fn resume_funding(
        &self,
        key: &str,
        record: &LnPendingSwap,
        resume: &LnFundingResume,
    ) -> Result<Option<(OutPoint, Amount)>, TakerError> {
        let swap_id = key.strip_suffix("-out").unwrap_or(key);
        // Hello only: the offer and its limits were settled when the swap
        // was agreed, and a maker may stop offering swap-outs meanwhile.
        // Replies wait at most `LN_STEP_TIMEOUT`, not the general maker
        // timeout, so one silent maker cannot hold up the rest of the pass.
        let mut socket = connect_to_maker(
            &resume.maker,
            self.config.connection_type,
            self.config.socks_port,
            LN_STEP_TIMEOUT,
        )
        .map_err(|e| general(format!("hello failed: {e:?}")))?;
        handshake_with_maker(&mut socket, &["ln-swap-out".to_string()])
            .map_err(|e| general(format!("hello failed: {e:?}")))?;
        send_message(
            &mut socket,
            &TakerToMakerMessage::Lightning(Box::new(LightningTakerMessage::SwapOutPaid(
                LnSwapOutPaid {
                    swap_id: swap_id.to_string(),
                },
            ))),
        )
        .map_err(|e| general(format!("send to maker failed: {e:?}")))?;
        let funded = match read_ln_reply(&mut socket)? {
            LightningMakerMessage::SwapOutFunded(funded) => funded,
            other => return Err(general(format!("expected SwapOutFunded, got {other}"))),
        };
        let checked = check_resumed_funding(
            &self.read_wallet()?.blockchain,
            swap_id,
            record,
            resume,
            &funded,
        )?;
        let Some(funding_tx) = checked else {
            return Ok(None);
        };
        // As in the swap itself: never record funding we refuse to claim.
        self.screen_funding_tx(&funding_tx)?;
        Ok(Some((funded.outpoint, funded.value)))
    }
}

/// What recovery does with a record that has no funding outpoint.
#[derive(Debug, PartialEq)]
enum Unfunded<'a> {
    /// Nothing can have been funded for it: drop it.
    Forget(&'static str),
    /// Ask the maker for the funding again.
    Resume(&'a LnFundingResume),
    /// It may have been funded and there is no way to ask: keep it.
    Keep(&'static str),
}

/// Decides what to do with a record that has no funding outpoint. A missing
/// outpoint alone does not mean nothing was funded: a swap-out's funding
/// reply can be lost after we paid. `records` is the whole set, so a routed
/// second hop can look at its first; `payment` looks up our outbound
/// Lightning payment, and `first_hop_spent` whether a funded first hop has a
/// confirmed spend; each is `None` when it cannot be read.
fn unfunded_action<'a>(
    key: &str,
    record: &'a LnPendingSwap,
    records: &[(String, LnPendingSwap)],
    payment: impl FnOnce(sha256::Hash) -> Option<PaymentOutcome>,
    first_hop_spent: impl FnOnce(&LnPendingSwap) -> Option<bool>,
) -> Unfunded<'a> {
    // We fund a swap-in ourselves and save its outpoint before broadcasting.
    if record.is_swap_in {
        return Unfunded::Forget("no on-chain commitment");
    }
    if let Some(base) = key.strip_suffix("-out") {
        // Maker 2 funds only once maker 1 has paid it, and maker 1 pays only
        // for our first-hop funding, whose outpoint is saved before it is
        // broadcast.
        let first_hop = format!("{base}-in");
        match records.iter().find(|(id, _)| *id == first_hop) {
            Some((_, hop)) if hop.outpoint.is_none() => {
                return Unfunded::Forget("first hop never funded");
            }
            // The first hop's record goes once its spend confirms. While
            // this hop has no outpoint we have not claimed it, so nothing has
            // revealed the preimage maker 1 needs, and that spend was our
            // refund. Nothing on this hop is ours to claim, and claiming it
            // would reveal the preimage after we were refunded.
            None => return Unfunded::Forget("first hop already resolved"),
            // The same holds while the record is still here: decided from
            // the chain, not from which record this pass visits first.
            Some((_, hop)) => match first_hop_spent(hop) {
                Some(true) => return Unfunded::Forget("first hop already resolved"),
                Some(false) => {}
                None => return Unfunded::Keep("first hop status unknown"),
            },
        }
    } else if let Ok(hash) = key.parse() {
        // A payment that can no longer settle pays the maker for nothing.
        if payment(hash) == Some(PaymentOutcome::Failed) {
            return Unfunded::Forget("payment failed");
        }
    }
    match &record.resume {
        Some(resume) => Unfunded::Resume(resume),
        None => Unfunded::Keep("paid swap-out without a funding outpoint"),
    }
}

/// Checks a resent `SwapOutFunded` the way the swap does before claiming:
/// our swap, an output paying our HTLC exactly the agreed amount, the value
/// the maker announced, and the agreed confirmations. Returns the funding
/// transaction, or `None` while it lacks confirmations.
fn check_resumed_funding(
    chain: &AnyBlockchain,
    swap_id: &str,
    record: &LnPendingSwap,
    resume: &LnFundingResume,
    funded: &LnHtlcFunded,
) -> Result<Option<Transaction>, TakerError> {
    use crate::wallet::blockchain::Blockchain;
    if funded.swap_id != swap_id {
        return Err(general("funding for a different swap"));
    }
    let funding_tx = chain.get_raw_transaction(&funded.outpoint.txid, None)?;
    let output = funding_tx
        .output
        .get(funded.outpoint.vout as usize)
        .ok_or_else(|| general("funding vout out of range"))?;
    if funded.value != output.value {
        return Err(general("announced funding value mismatch"));
    }
    SwapHtlc::from_redeemscript(record.redeemscript.clone(), record.locktime)
        .validate_funding_output(output, resume.amount)
        .map_err(|e| general(format!("bad funding output: {e}")))?;
    let confirmations = chain
        .get_raw_transaction_info(&funded.outpoint.txid, None)?
        .confirmations
        .unwrap_or(0);
    if confirmations < resume.min_confirmations {
        return Ok(None);
    }
    Ok(Some(funding_tx))
}

/// Saves a verified funding outpoint, then the payout script, before the
/// claim that reveals the preimage is broadcast. Returns the payout script.
fn record_funding(
    wallet: &mut Wallet,
    key: &str,
    outpoint: OutPoint,
    value: Amount,
) -> Result<ScriptBuf, TakerError> {
    let record = wallet
        .store
        .ln_pending_swaps
        .get_mut(key)
        .ok_or_else(|| general(format!("{key}: recovery record missing")))?;
    record.outpoint = Some(outpoint);
    record.value = Some(value);
    wallet.save_to_disk()?;
    payout_script(wallet, key)
}

/// The script a record's claim or refund pays to. Chosen once and saved
/// with the record before any spend uses it, so a rebuilt spend is the same
/// transaction as the one it replaces and recovery passes do not walk the
/// wallet's receive addresses.
fn payout_script(wallet: &mut Wallet, key: &str) -> Result<ScriptBuf, TakerError> {
    let missing = || general(format!("{key}: recovery record missing"));
    let saved = wallet.store.ln_pending_swaps.get(key).ok_or_else(missing)?;
    if let Some(script) = &saved.payout_script {
        return Ok(script.clone());
    }
    let script = wallet
        .get_next_external_address(AddressType::P2WPKH)?
        .script_pubkey();
    wallet
        .store
        .ln_pending_swaps
        .get_mut(key)
        .ok_or_else(missing)?
        .payout_script = Some(script.clone());
    if let Err(e) = wallet.save_to_disk() {
        // Not on disk, so no spend may use it: the next try picks and saves
        // a script before anything is broadcast.
        if let Some(record) = wallet.store.ln_pending_swaps.get_mut(key) {
            record.payout_script = None;
        }
        return Err(e.into());
    }
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        lightning::MockLightningBackend,
        protocol::{common_messages::Hello, lightning_messages::LnReject},
        wallet::{
            blockchain::{mock_electrum, scripthash, MockElectrum},
            test_wallet, Electrum, ElectrumConfig,
        },
    };
    use bitcoin::{
        absolute::LockTime, consensus::encode::serialize_hex, hashes::Hash, transaction::Version,
        TxIn, TxOut,
    };
    use serde_json::{json, Value};
    use std::{
        net::TcpListener,
        sync::{
            atomic::{AtomicUsize, Ordering},
            Mutex,
        },
        thread,
    };

    /// The delta is a `u64` on the invoice but the wire locktime is a
    /// `u16`. A truncating cast maps 65,536 to 0, which then satisfies
    /// every locktime check and lets a counterparty hand us an invoice
    /// whose real claim window outlives our on-chain refund.
    #[test]
    fn cltv_delta_above_u16_is_rejected_not_truncated() {
        assert_eq!(cltv_delta_blocks(42).unwrap(), 42);
        assert_eq!(cltv_delta_blocks(u16::MAX as u64).unwrap(), u16::MAX);
        assert!(cltv_delta_blocks(u16::MAX as u64 + 1).is_err());
        assert!(cltv_delta_blocks(u64::MAX).is_err());
    }

    /// `amount + fee` and the millisatoshi conversion both take an amount
    /// that arrives unbounded from the CLI.
    #[test]
    fn oversized_amounts_are_rejected_not_wrapped() {
        assert_eq!(msat(Amount::from_sat(1)).unwrap(), 1000);
        assert!(msat(Amount::from_sat(u64::MAX)).is_err());
        assert_eq!(
            total_with_fee(Amount::from_sat(10), Amount::from_sat(5)).unwrap(),
            Amount::from_sat(15)
        );
        assert!(total_with_fee(Amount::from_sat(u64::MAX), Amount::from_sat(1)).is_err());
    }

    const AMOUNT: Amount = Amount::from_sat(50_000);

    /// What the mock Electrum server knows: each transaction with its height
    /// (0 in the mempool) and every broadcast it was sent.
    #[derive(Default)]
    struct Chain {
        txs: Vec<(Transaction, u64)>,
        broadcasts: Vec<Transaction>,
        /// Refuse every broadcast with this message.
        refuse: Option<&'static str>,
        /// Scripthashes and txids whose lookups get a server error.
        failing: Vec<String>,
    }

    impl Chain {
        /// Puts `tx` at `height`, or drops it with `None` (evicted, or
        /// reorged out without returning to the mempool).
        fn set(&mut self, tx: &Transaction, height: Option<u64>) {
            self.txs
                .retain(|(known, _)| known.compute_txid() != tx.compute_txid());
            if let Some(height) = height {
                self.txs.push((tx.clone(), height));
            }
        }

        fn script_of(&self, outpoint: &OutPoint) -> Option<ScriptBuf> {
            self.txs
                .iter()
                .find(|(tx, _)| tx.compute_txid() == outpoint.txid)
                .and_then(|(tx, _)| tx.output.get(outpoint.vout as usize))
                .map(|output| output.script_pubkey.clone())
        }

        /// Every transaction paying to, or spending from, the script.
        fn history(&self, hash: &str) -> Value {
            let touches = |tx: &Transaction| {
                tx.output
                    .iter()
                    .any(|o| scripthash(&o.script_pubkey) == hash)
                    || tx.input.iter().any(|i| {
                        self.script_of(&i.previous_output)
                            .is_some_and(|s| scripthash(&s) == hash)
                    })
            };
            Value::Array(
                self.txs
                    .iter()
                    .filter(|(tx, _)| touches(tx))
                    .map(|(tx, height)| json!({ "tx_hash": tx.compute_txid(), "height": height }))
                    .collect(),
            )
        }

        fn broadcast(&mut self, tx: Transaction) -> Result<Value, Value> {
            self.broadcasts.push(tx.clone());
            let txid = tx.compute_txid();
            let spends_same = |known: &Transaction| {
                known.input.iter().any(|i| {
                    tx.input
                        .iter()
                        .any(|j| i.previous_output == j.previous_output)
                })
            };
            let refusal = match self.refuse {
                Some(reason) => Some(reason),
                None if self.txs.iter().any(|(k, _)| k.compute_txid() == txid) => {
                    Some("txn-already-known")
                }
                None if self.txs.iter().any(|(k, _)| spends_same(k)) => {
                    Some("txn-mempool-conflict")
                }
                None => None,
            };
            if let Some(reason) = refusal {
                return Err(json!({ "code": -26, "message": reason }));
            }
            self.txs.push((tx, 0));
            Ok(json!(txid))
        }
    }

    fn serve(chain: &Arc<Mutex<Chain>>) -> MockElectrum {
        let chain = chain.clone();
        mock_electrum(move |method, params| {
            let mut chain = chain.lock().unwrap();
            let key = params[0].as_str().unwrap_or_default();
            if chain.failing.iter().any(|failing| failing == key)
                && method != "blockchain.transaction.broadcast"
            {
                return Err(json!({ "code": 1, "message": "daemon error" }));
            }
            match method {
                "blockchain.scripthash.get_history" => {
                    Ok(chain.history(params[0].as_str().unwrap()))
                }
                "blockchain.transaction.get" => {
                    let txid = params[0].as_str().unwrap();
                    chain
                        .txs
                        .iter()
                        .find(|(tx, _)| tx.compute_txid().to_string() == txid)
                        .map(|(tx, _)| json!(serialize_hex(tx)))
                        .ok_or_else(|| {
                            json!({ "code": 2, "message": "No such mempool or blockchain transaction" })
                        })
                }
                "blockchain.transaction.broadcast" => {
                    let hex = params[0].as_str().unwrap();
                    chain.broadcast(bitcoin::consensus::encode::deserialize_hex(hex).unwrap())
                }
                _ => Ok(Value::Null),
            }
        })
    }

    /// Reconnects the taker's wallet at `tip` with a fresh cache, as a
    /// restarted taker would see the chain.
    fn connect(taker: &Taker, server: &MockElectrum, tip: u64) {
        server.set_tip(
            tip,
            &bitcoin::constants::genesis_block(bitcoin::Network::Regtest).header,
        );
        taker.write_wallet().unwrap().blockchain = AnyBlockchain::Electrum(
            Electrum::new(&ElectrumConfig {
                url: server.url.clone(),
                // A failed lookup must fail at once, not back off and retry.
                max_retries: 0,
                ..Default::default()
            })
            .expect("connect to mock electrum"),
        );
    }

    /// A swap-out as the taker records it, and the maker's funding.
    struct SwapOut {
        id: String,
        record: LnPendingSwap,
        funding: Transaction,
        outpoint: OutPoint,
    }

    fn swap_out(maker: &str) -> SwapOut {
        let preimage = Preimage([7; 32]);
        let (taker_pubkey, taker_key) = generate_keypair();
        let (maker_pubkey, _) = generate_keypair();
        let htlc = SwapHtlc::new(&taker_pubkey, &maker_pubkey, &preimage.payment_hash(), 30);
        let funding = funding_paying(htlc.script_pubkey().unwrap(), AMOUNT);
        let outpoint = OutPoint::new(funding.compute_txid(), 0);
        SwapOut {
            id: preimage.payment_hash().to_string(),
            record: LnPendingSwap {
                is_swap_in: false,
                preimage: Some(preimage.0),
                redeemscript: htlc.redeemscript().clone(),
                locktime: 30,
                privkey: taker_key,
                outpoint: None,
                value: None,
                payout_script: None,
                resume: Some(LnFundingResume {
                    maker: maker.to_string(),
                    amount: AMOUNT,
                    min_confirmations: 1,
                }),
            },
            funding,
            outpoint,
        }
    }

    fn funding_paying(script_pubkey: ScriptBuf, value: Amount) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
                ..Default::default()
            }],
            output: vec![TxOut {
                value,
                script_pubkey,
            }],
        }
    }

    /// The record as the swap leaves it once the funding is confirmed.
    fn funded(swap: &SwapOut) -> LnPendingSwap {
        LnPendingSwap {
            outpoint: Some(swap.outpoint),
            value: Some(AMOUNT),
            ..swap.record.clone()
        }
    }

    fn taker_with(dir: &std::path::Path, chain: &Arc<Mutex<Chain>>) -> (Taker, MockElectrum) {
        let server = serve(chain);
        let taker = Taker::for_test(test_wallet(&dir.join("wallet")), dir);
        connect(&taker, &server, 101);
        (taker, server)
    }

    fn record(taker: &Taker, id: &str) -> Option<LnPendingSwap> {
        taker
            .read_wallet()
            .unwrap()
            .store
            .ln_pending_swaps
            .get(id)
            .cloned()
    }

    fn external_index(taker: &Taker) -> u32 {
        *taker.read_wallet().unwrap().get_external_index()
    }

    /// A kept swap-out record rebuilds the same claim on every pass: one
    /// payout script, saved before the first broadcast, and no new address
    /// per pass. So a claim evicted from the mempool goes back out unchanged.
    /// Before, each pass took a new address and built a different claim,
    /// which the mempool refused as a conflict while the first was there.
    #[test]
    fn kept_claim_is_rebuilt_unchanged_after_eviction() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        chain.lock().unwrap().set(&swap.funding, Some(100));
        let (mut taker, server) = taker_with(dir.path(), &chain);
        taker.save_pending_swap(&swap.id, funded(&swap)).unwrap();
        let index = external_index(&taker);

        let first = taker.recover_lightning_swaps().unwrap();
        assert!(first[0].contains("awaiting confirmation"), "{:?}", first);
        let claim = chain.lock().unwrap().broadcasts[0].clone();
        assert_eq!(claim.input[0].previous_output, swap.outpoint);
        let payout = record(&taker, &swap.id).unwrap().payout_script;
        assert_eq!(payout, Some(claim.output[0].script_pubkey.clone()));
        assert_eq!(external_index(&taker), index + 1);
        // The script is on disk, not only in memory.
        let path = dir.path().join("wallet");
        let (stored, _) =
            crate::wallet::WalletStore::read_from_disk(&path, Some("test-password".into()))
                .unwrap();
        assert_eq!(stored.ln_pending_swaps[&swap.id].payout_script, payout);

        // A pass with the claim still in the mempool sends the same claim.
        taker.recover_lightning_swaps().unwrap();
        // Evicted: the next pass sends it again, unchanged.
        chain.lock().unwrap().set(&claim, None);
        connect(&taker, &server, 101);
        let third = taker.recover_lightning_swaps().unwrap();
        assert!(third[0].contains("awaiting confirmation"), "{:?}", third);
        let chain = chain.lock().unwrap();
        assert_eq!(chain.broadcasts.len(), 3);
        assert!(chain.broadcasts.iter().all(|tx| *tx == claim));
        assert!(chain.txs.iter().any(|(tx, _)| *tx == claim));
        assert_eq!(external_index(&taker), index + 1);
        assert_eq!(record(&taker, &swap.id).unwrap().payout_script, payout);
    }

    /// The record goes only when the claim is confirmed on the chain the
    /// backend serves now: not while the claim waits in the mempool, not
    /// after a reorg drops the block that held it, and not while the lookup
    /// fails.
    #[test]
    fn kept_claim_is_dropped_only_once_confirmed() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        chain.lock().unwrap().set(&swap.funding, Some(100));
        let (mut taker, server) = taker_with(dir.path(), &chain);
        taker.save_pending_swap(&swap.id, funded(&swap)).unwrap();
        taker.recover_lightning_swaps().unwrap();
        let claim = chain.lock().unwrap().broadcasts[0].clone();

        // Mined at 102, then a reorg replaces that block and the claim is
        // gone. The kept record sends it again.
        chain.lock().unwrap().set(&claim, Some(102));
        chain.lock().unwrap().set(&claim, None);
        connect(&taker, &server, 103);
        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(
            outcomes[0].contains("awaiting confirmation"),
            "{:?}",
            outcomes
        );
        assert!(record(&taker, &swap.id).is_some());
        assert_eq!(chain.lock().unwrap().broadcasts.last(), Some(&claim));

        // A failed lookup says nothing about the spend.
        chain.lock().unwrap().failing = vec![scripthash(&swap.funding.output[0].script_pubkey)];
        connect(&taker, &server, 103);
        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(
            outcomes[0].contains("spend status unknown"),
            "{:?}",
            outcomes
        );
        assert!(record(&taker, &swap.id).is_some());

        // Confirmed on the current chain: dropped.
        chain.lock().unwrap().failing.clear();
        chain.lock().unwrap().set(&claim, Some(104));
        connect(&taker, &server, 104);
        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(outcomes[0].contains("already resolved"), "{:?}", outcomes);
        assert!(record(&taker, &swap.id).is_none());
        assert!(taker.recover_lightning_swaps().unwrap().is_empty());
    }

    /// Serves one maker connection per entry of `replies`: answers the
    /// Hello, checks the `SwapOutPaid` is for `swap_id`, then sends the reply,
    /// or closes on `None`.
    fn fake_maker(swap_id: &str, replies: Vec<Option<LightningMakerMessage>>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let swap_id = swap_id.to_string();
        thread::spawn(move || {
            for reply in replies {
                let (socket, _) = listener.accept().unwrap();
                answer_paid(socket, &swap_id, reply);
            }
        });
        address
    }

    /// A maker that answers every `SwapOutPaid` for `swap_id` with `reply`,
    /// and the number of connections it has served.
    fn counting_maker(swap_id: &str, reply: LightningMakerMessage) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let served = Arc::new(AtomicUsize::new(0));
        let (swap_id, count) = (swap_id.to_string(), served.clone());
        thread::spawn(move || {
            for socket in listener.incoming() {
                count.fetch_add(1, Ordering::SeqCst);
                answer_paid(socket.unwrap(), &swap_id, Some(reply.clone()));
            }
        });
        (address, served)
    }

    /// A maker that notes how many broadcasts `chain` had seen when each
    /// connection arrived, then rejects whatever it is asked.
    fn observing_maker(chain: &Arc<Mutex<Chain>>) -> (String, Arc<Mutex<Vec<usize>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (chain, noted) = (chain.clone(), seen.clone());
        thread::spawn(move || {
            for socket in listener.incoming() {
                let mut socket = socket.unwrap();
                noted
                    .lock()
                    .unwrap()
                    .push(chain.lock().unwrap().broadcasts.len());
                let read = |socket: &mut TcpStream| -> TakerToMakerMessage {
                    serde_cbor::from_slice(&read_message(socket).unwrap()).unwrap()
                };
                read(&mut socket);
                let hello = Hello {
                    features: vec!["ln-swap-out".to_string()],
                };
                send_message(&mut socket, &MakerToTakerMessage::Hello(hello)).unwrap();
                read(&mut socket);
                let reject = LightningMakerMessage::Reject(LnReject {
                    swap_id: String::new(),
                    reason: "unknown swap".into(),
                });
                let reject = MakerToTakerMessage::Lightning(Box::new(reject));
                send_message(&mut socket, &reject).unwrap();
            }
        });
        (address, seen)
    }

    /// Answers the Hello, checks the `SwapOutPaid` is for `swap_id`, then
    /// sends `reply`, or closes on `None`.
    fn answer_paid(mut socket: TcpStream, swap_id: &str, reply: Option<LightningMakerMessage>) {
        let read = |socket: &mut TcpStream| -> TakerToMakerMessage {
            serde_cbor::from_slice(&read_message(socket).unwrap()).unwrap()
        };
        assert!(matches!(read(&mut socket), TakerToMakerMessage::Hello(_)));
        let hello = Hello {
            features: vec!["ln-swap-out".to_string()],
        };
        send_message(&mut socket, &MakerToTakerMessage::Hello(hello)).unwrap();
        match read(&mut socket) {
            TakerToMakerMessage::Lightning(msg) => match *msg {
                LightningTakerMessage::SwapOutPaid(paid) => assert_eq!(paid.swap_id, swap_id),
                other => panic!("expected SwapOutPaid, got {}", other),
            },
            other => panic!("expected a Lightning message, got {:?}", other),
        }
        if let Some(reply) = reply {
            let reply = MakerToTakerMessage::Lightning(Box::new(reply));
            send_message(&mut socket, &reply).unwrap();
        }
    }

    fn funded_reply(swap: &SwapOut) -> LightningMakerMessage {
        LightningMakerMessage::SwapOutFunded(LnHtlcFunded {
            swap_id: swap.id.clone(),
            outpoint: swap.outpoint,
            value: AMOUNT,
        })
    }

    /// A paid swap-out whose funding reply was lost: recovery asks the maker
    /// again with `SwapOutPaid`, checks the answer, saves the outpoint and
    /// payout script, and claims. Before, the record was deleted as "no
    /// on-chain commitment" and the claim key with it.
    #[test]
    fn lost_funding_reply_is_resumed_and_claimed() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let mut swap = swap_out("unused:1");
        let maker = fake_maker(&swap.id, vec![Some(funded_reply(&swap))]);
        swap.record.resume.as_mut().unwrap().maker = maker;
        chain.lock().unwrap().set(&swap.funding, Some(101));
        let (mut taker, _server) = taker_with(dir.path(), &chain);
        taker
            .save_pending_swap(&swap.id, swap.record.clone())
            .unwrap();

        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(
            outcomes[0].contains("awaiting confirmation"),
            "{:?}",
            outcomes
        );
        let kept = record(&taker, &swap.id).unwrap();
        assert_eq!(
            (kept.outpoint, kept.value),
            (Some(swap.outpoint), Some(AMOUNT))
        );
        let claim = chain.lock().unwrap().broadcasts[0].clone();
        assert_eq!(claim.input[0].previous_output, swap.outpoint);
        assert_eq!(
            kept.payout_script,
            Some(claim.output[0].script_pubkey.clone())
        );
    }

    /// A resent funding is checked as the swap checks it before claiming.
    /// Anything short of a confirmed output paying our HTLC the agreed amount
    /// leaves the record as it was, with nothing broadcast, for a later pass.
    #[test]
    fn resumed_funding_is_checked_before_it_is_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        let (mut taker, server) = taker_with(dir.path(), &chain);
        let short = funding_paying(swap.funding.output[0].script_pubkey.clone(), AMOUNT / 2);
        let elsewhere = funding_paying(ScriptBuf::from_bytes(vec![0x51]), AMOUNT);
        let announce = |tx: &Transaction, value: Amount| {
            LightningMakerMessage::SwapOutFunded(LnHtlcFunded {
                swap_id: swap.id.clone(),
                outpoint: OutPoint::new(tx.compute_txid(), 0),
                value,
            })
        };
        let closed = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        let cases = vec![
            (
                "unconfirmed",
                Some(fake_maker(&swap.id, vec![Some(funded_reply(&swap))])),
                Some(0),
                false,
                "waiting for 1 confirmation",
            ),
            (
                "value announced wrong",
                Some(fake_maker(
                    &swap.id,
                    vec![Some(announce(&swap.funding, AMOUNT + Amount::ONE_SAT))],
                )),
                Some(101),
                false,
                "announced funding value mismatch",
            ),
            (
                "short funding",
                Some(fake_maker(
                    &swap.id,
                    vec![Some(announce(&short, AMOUNT / 2))],
                )),
                Some(101),
                false,
                "bad funding output",
            ),
            (
                "another script",
                Some(fake_maker(
                    &swap.id,
                    vec![Some(announce(&elsewhere, AMOUNT))],
                )),
                Some(101),
                false,
                "bad funding output",
            ),
            (
                "another swap",
                Some(fake_maker(
                    &swap.id,
                    vec![Some(LightningMakerMessage::SwapOutFunded(LnHtlcFunded {
                        swap_id: Preimage([8; 32]).payment_hash().to_string(),
                        outpoint: swap.outpoint,
                        value: AMOUNT,
                    }))],
                )),
                Some(101),
                false,
                "different swap",
            ),
            (
                "rejected",
                Some(fake_maker(
                    &swap.id,
                    vec![Some(LightningMakerMessage::Reject(LnReject {
                        swap_id: swap.id.clone(),
                        reason: "held payment not observed".into(),
                    }))],
                )),
                Some(101),
                false,
                "maker rejected swap",
            ),
            (
                "no reply",
                Some(fake_maker(&swap.id, vec![None])),
                Some(101),
                false,
                "read from maker failed",
            ),
            (
                "unreachable",
                Some(closed.to_string()),
                Some(101),
                false,
                "hello failed",
            ),
            (
                "lookup fails",
                Some(fake_maker(&swap.id, vec![Some(funded_reply(&swap))])),
                Some(101),
                true,
                "funding not recovered yet",
            ),
        ];
        for (case, maker, height, failing, expected) in cases {
            let mut pending = swap.record.clone();
            pending.resume.as_mut().unwrap().maker = maker.unwrap();
            taker.save_pending_swap(&swap.id, pending.clone()).unwrap();
            {
                let mut chain = chain.lock().unwrap();
                chain.failing = if failing {
                    vec![swap.funding.compute_txid().to_string()]
                } else {
                    Vec::new()
                };
                chain.set(&swap.funding, height);
                chain.set(&short, Some(101));
                chain.set(&elsewhere, Some(101));
            }
            connect(&taker, &server, 101);
            let outcomes = taker.recover_lightning_swaps().unwrap();
            assert_eq!(outcomes.len(), 1, "{case}: {outcomes:?}");
            assert!(outcomes[0].contains(expected), "{}: {:?}", case, outcomes);
            assert_eq!(record(&taker, &swap.id), Some(pending), "{case}");
            assert!(chain.lock().unwrap().broadcasts.is_empty(), "{}", case);
        }
    }

    /// Without an outpoint, a record is dropped only when nothing can have
    /// been funded for it. Before, every such record was dropped.
    #[test]
    fn unfunded_records_are_dropped_only_when_nothing_was_funded() {
        let swap = swap_out("maker:1");
        let legacy = LnPendingSwap {
            resume: None,
            ..swap.record.clone()
        };
        let swap_in = LnPendingSwap {
            is_swap_in: true,
            ..legacy.clone()
        };
        let resume = swap.record.resume.as_ref();
        let no_lookup = |_| -> Option<PaymentOutcome> { panic!("no payment to look up") };
        let no_spend = |_: &LnPendingSwap| -> Option<bool> { panic!("no hop to look up") };

        // A swap-in is ours to fund, and its outpoint is saved before that.
        assert_eq!(
            unfunded_action(&swap.id, &swap_in, &[], no_lookup, no_spend),
            Unfunded::Forget("no on-chain commitment")
        );

        // Direct swap-out: only a failed payment proves nothing was paid for.
        let preimage = Preimage([1; 32]);
        for (outcome, for_resume, for_legacy) in [
            (
                Some(PaymentOutcome::Failed),
                Unfunded::Forget("payment failed"),
                Unfunded::Forget("payment failed"),
            ),
            (
                Some(PaymentOutcome::Pending),
                Unfunded::Resume(resume.unwrap()),
                Unfunded::Keep("paid swap-out without a funding outpoint"),
            ),
            (
                Some(PaymentOutcome::Settled(preimage)),
                Unfunded::Resume(resume.unwrap()),
                Unfunded::Keep("paid swap-out without a funding outpoint"),
            ),
            (
                Some(PaymentOutcome::NotFound),
                Unfunded::Resume(resume.unwrap()),
                Unfunded::Keep("paid swap-out without a funding outpoint"),
            ),
            (
                None,
                Unfunded::Resume(resume.unwrap()),
                Unfunded::Keep("paid swap-out without a funding outpoint"),
            ),
        ] {
            assert_eq!(
                unfunded_action(&swap.id, &swap.record, &[], |_| outcome, no_spend),
                for_resume
            );
            assert_eq!(
                unfunded_action(&swap.id, &legacy, &[], |_| outcome, no_spend),
                for_legacy
            );
        }

        // Routed second hop: maker 2 funds only after our first hop is
        // funded, and that outpoint is saved before its broadcast.
        let out_key = format!("{}-out", swap.id);
        let in_key = format!("{}-in", swap.id);
        let first_hop = |outpoint| {
            vec![(
                in_key.clone(),
                LnPendingSwap {
                    outpoint,
                    ..swap_in.clone()
                },
            )]
        };
        for hop in [&swap.record, &legacy] {
            assert_eq!(
                unfunded_action(&out_key, hop, &first_hop(None), no_lookup, no_spend),
                Unfunded::Forget("first hop never funded")
            );
        }
        // Hop 1 funded and positively unspent: maker 2 may have funded hop 2.
        let funded_first_hop = first_hop(Some(swap.outpoint));
        let unspent = |_: &LnPendingSwap| Some(false);
        assert_eq!(
            unfunded_action(
                &out_key,
                &swap.record,
                &funded_first_hop,
                no_lookup,
                unspent
            ),
            Unfunded::Resume(resume.unwrap())
        );
        assert_eq!(
            unfunded_action(&out_key, &legacy, &funded_first_hop, no_lookup, unspent),
            Unfunded::Keep("paid swap-out without a funding outpoint")
        );
        for hop in [&swap.record, &legacy] {
            // Hop 1 funded but unreadable: kept, nobody asked.
            assert_eq!(
                unfunded_action(&out_key, hop, &funded_first_hop, no_lookup, |_| None),
                Unfunded::Keep("first hop status unknown")
            );
            // Hop 1's spend confirmed, or its record gone after that: the
            // spend can only be our refund while hop 2 has no outpoint.
            // Nothing on hop 2 is ours to claim.
            assert_eq!(
                unfunded_action(&out_key, hop, &funded_first_hop, no_lookup, |_| Some(true)),
                Unfunded::Forget("first hop already resolved")
            );
            assert_eq!(
                unfunded_action(&out_key, hop, &[], no_lookup, no_spend),
                Unfunded::Forget("first hop already resolved")
            );
        }
    }

    /// A routed second hop without an outpoint is asked for while its first
    /// hop is funded and unresolved. After a restart from the wallet on disk,
    /// the pass in which the first hop's refund confirms drops both records
    /// without contacting maker 2 again. Before, the second hop was kept and
    /// maker 2 was asked on every pass, with no end.
    #[test]
    fn resolved_first_hop_drops_second_hop_without_asking_the_maker() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let first = swap_out("unused:1");
        let mut second = swap_out("unused:1");
        let unknown = LightningMakerMessage::Reject(LnReject {
            swap_id: second.id.clone(),
            reason: "unknown swap".into(),
        });
        let (maker, asked) = counting_maker(&second.id, unknown);
        second.record.resume.as_mut().unwrap().maker = maker;
        let (in_key, out_key) = (format!("{}-in", first.id), format!("{}-out", first.id));
        chain.lock().unwrap().set(&first.funding, Some(100));
        chain.lock().unwrap().refuse = Some("non-BIP68-final");
        let (mut taker, server) = taker_with(dir.path(), &chain);
        let hop1 = LnPendingSwap {
            is_swap_in: true,
            resume: None,
            ..funded(&first)
        };
        taker.save_pending_swap(&in_key, hop1).unwrap();
        taker
            .save_pending_swap(&out_key, second.record.clone())
            .unwrap();

        // Hop 1 funded, refund not yet mature: maker 2 is asked, hop 2 kept.
        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert_eq!(outcomes.len(), 2, "{:?}", outcomes);
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(record(&taker, &out_key), Some(second.record.clone()));

        // Restart from the wallet on disk.
        drop(taker);
        let path = dir.path().join("wallet");
        let wallet = Wallet::load_or_init(
            &path,
            AnyBlockchain::Electrum(
                Electrum::new(&ElectrumConfig {
                    url: server.url.clone(),
                    max_retries: 0,
                    ..Default::default()
                })
                .unwrap(),
            ),
            Some("test-password".into()),
        )
        .unwrap();
        let mut taker = Taker::for_test(wallet, dir.path());
        assert_eq!(record(&taker, &out_key), Some(second.record.clone()));
        assert!(record(&taker, &in_key).is_some());

        // Our refund of hop 1 confirms: that pass drops both hops.
        let refund = Transaction {
            input: vec![TxIn {
                previous_output: first.outpoint,
                ..Default::default()
            }],
            ..funding_paying(ScriptBuf::from_bytes(vec![0x51]), AMOUNT)
        };
        chain.lock().unwrap().refuse = None;
        chain.lock().unwrap().set(&refund, Some(102));
        connect(&taker, &server, 103);
        let mut outcomes = taker.recover_lightning_swaps().unwrap();
        outcomes.sort();
        assert_eq!(
            outcomes,
            [
                format!("{in_key}: already resolved on-chain"),
                format!("{out_key}: first hop already resolved; forgotten"),
            ]
        );
        assert!(taker.recover_lightning_swaps().unwrap().is_empty());
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        let (stored, _) =
            crate::wallet::WalletStore::read_from_disk(&path, Some("test-password".into()))
                .unwrap();
        assert!(stored.ln_pending_swaps.is_empty());
    }

    /// Claims and refunds of records with a known outpoint go out before
    /// recovery asks any maker for missing funding, so a slow maker cannot
    /// hold them up.
    #[test]
    fn funded_records_are_claimed_before_any_maker_is_asked() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        chain.lock().unwrap().set(&swap.funding, Some(100));
        let (mut taker, _server) = taker_with(dir.path(), &chain);
        taker.save_pending_swap(&swap.id, funded(&swap)).unwrap();
        let (maker, seen) = observing_maker(&chain);
        for i in 0..10u8 {
            let id = Preimage([100 + i; 32]).payment_hash().to_string();
            let mut pending = swap.record.clone();
            pending.resume.as_mut().unwrap().maker = maker.clone();
            taker.save_pending_swap(&id, pending).unwrap();
        }

        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert_eq!(outcomes.len(), 11, "{:?}", outcomes);
        let seen = seen.lock().unwrap();
        assert_eq!(seen.len(), 10);
        assert!(
            seen.iter().all(|broadcasts| *broadcasts == 1),
            "a maker was asked before the funded claim went out: {:?}",
            seen
        );
    }

    /// A routed second hop without an outpoint is resumed only while its
    /// first hop is positively unspent. Once the first hop's refund is
    /// confirmed, the second hop is dropped without asking maker 2, whether
    /// it is considered before or after the first hop in the pass. While the
    /// first hop cannot be read, the second is kept and maker 2 not asked.
    #[test]
    fn second_hop_is_resumed_only_while_first_hop_is_unspent() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let first = swap_out("unused:1");
        let mut second = swap_out("unused:1");
        let unknown = LightningMakerMessage::Reject(LnReject {
            swap_id: second.id.clone(),
            reason: "unknown swap".into(),
        });
        let (maker, asked) = counting_maker(&second.id, unknown);
        second.record.resume.as_mut().unwrap().maker = maker;
        let (in_key, out_key) = (format!("{}-in", first.id), format!("{}-out", first.id));
        chain.lock().unwrap().set(&first.funding, Some(100));
        chain.lock().unwrap().refuse = Some("non-BIP68-final");
        let (mut taker, server) = taker_with(dir.path(), &chain);
        let hop1 = LnPendingSwap {
            is_swap_in: true,
            resume: None,
            ..funded(&first)
        };
        taker.save_pending_swap(&in_key, hop1.clone()).unwrap();
        taker
            .save_pending_swap(&out_key, second.record.clone())
            .unwrap();
        let records = vec![
            (in_key.clone(), hop1),
            (out_key.clone(), second.record.clone()),
        ];
        // Hop 2 considered while hop 1's record is still in the pass.
        let consider_hop2 = |taker: &Taker| {
            let mut outcomes = Vec::new();
            let funding = taker
                .recover_funding(&out_key, &second.record, &records, &mut outcomes)
                .unwrap();
            assert_eq!(funding, None);
            outcomes
        };

        // Hop 1 unspent: maker 2 is asked, hop 2 kept.
        let outcomes = consider_hop2(&taker);
        assert!(
            outcomes[0].contains("funding not recovered yet"),
            "{:?}",
            outcomes
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        // Hop 1 unreadable: hop 2 kept, maker 2 not asked.
        chain.lock().unwrap().failing = vec![scripthash(&first.funding.output[0].script_pubkey)];
        connect(&taker, &server, 101);
        assert_eq!(
            consider_hop2(&taker),
            [format!("{out_key}: first hop status unknown; kept")]
        );
        assert_eq!(asked.load(Ordering::SeqCst), 1);
        assert_eq!(record(&taker, &out_key), Some(second.record.clone()));

        // Hop 1's refund confirms; its record is still here. Hop 2 first:
        // dropped, maker 2 not asked.
        let refund = Transaction {
            input: vec![TxIn {
                previous_output: first.outpoint,
                ..Default::default()
            }],
            ..funding_paying(ScriptBuf::from_bytes(vec![0x51]), AMOUNT)
        };
        {
            let mut chain = chain.lock().unwrap();
            chain.failing.clear();
            chain.refuse = None;
            chain.set(&refund, Some(102));
        }
        connect(&taker, &server, 103);
        assert_eq!(
            consider_hop2(&taker),
            [format!("{out_key}: first hop already resolved; forgotten")]
        );
        assert!(record(&taker, &out_key).is_none());
        assert!(record(&taker, &in_key).is_some());
        assert_eq!(asked.load(Ordering::SeqCst), 1);

        // Hop 1 first, in a whole pass: both go, maker 2 not asked.
        taker
            .save_pending_swap(&out_key, second.record.clone())
            .unwrap();
        let mut outcomes = taker.recover_lightning_swaps().unwrap();
        outcomes.sort();
        assert_eq!(outcomes.len(), 2, "{:?}", outcomes);
        assert!(outcomes.contains(&format!("{out_key}: first hop already resolved; forgotten")));
        assert!(outcomes.contains(&format!("{in_key}: already resolved on-chain")));
        assert!(record(&taker, &out_key).is_none() && record(&taker, &in_key).is_none());
        assert_eq!(asked.load(Ordering::SeqCst), 1);
    }

    /// A swap-out record from before resume data existed is kept while our
    /// payment may still settle, and dropped once it has failed. The payment
    /// is read from the taker's own Lightning node.
    #[test]
    fn legacy_paid_swap_out_is_kept_until_its_payment_fails() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        let (mut taker, _server) = taker_with(dir.path(), &chain);
        let (maker_ln, taker_ln) = MockLightningBackend::new_pair();
        let hash = Preimage([7; 32]).payment_hash();
        let invoice = maker_ln
            .create_hold_invoice(hash, InvoiceParams::default())
            .unwrap();
        taker_ln
            .pay_invoice(&invoice.invoice, Some(1_000), None)
            .unwrap();
        taker.lightning = Some(taker_ln);
        let legacy = LnPendingSwap {
            resume: None,
            ..swap.record.clone()
        };
        taker.save_pending_swap(&swap.id, legacy).unwrap();

        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(outcomes[0].ends_with("kept"), "{:?}", outcomes);
        assert!(record(&taker, &swap.id).is_some());

        maker_ln.fail_held_payment(hash).unwrap();
        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(
            outcomes[0].contains("payment failed; forgotten"),
            "{:?}",
            outcomes
        );
        assert!(record(&taker, &swap.id).is_none());
    }

    /// A swap-in refund that is not yet mature is kept and retried to one
    /// payout script, as before, without a new address on every pass. A
    /// swap-in record without an outpoint is still dropped.
    #[test]
    fn swap_in_records_keep_their_recovery_behaviour() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        chain.lock().unwrap().set(&swap.funding, Some(100));
        chain.lock().unwrap().refuse = Some("non-BIP68-final");
        let (mut taker, _server) = taker_with(dir.path(), &chain);
        let swap_in = LnPendingSwap {
            is_swap_in: true,
            preimage: None,
            resume: None,
            ..funded(&swap)
        };
        taker.save_pending_swap("refund", swap_in.clone()).unwrap();
        taker
            .save_pending_swap(
                "unfunded",
                LnPendingSwap {
                    outpoint: None,
                    value: None,
                    ..swap_in
                },
            )
            .unwrap();
        let index = external_index(&taker);

        let mut outcomes = taker.recover_lightning_swaps().unwrap();
        outcomes.sort();
        assert!(
            outcomes[0].starts_with("refund: refund not yet mature"),
            "{:?}",
            outcomes
        );
        assert!(outcomes[1].starts_with("unfunded: no on-chain commitment; forgotten"));
        taker.recover_lightning_swaps().unwrap();
        let chain = chain.lock().unwrap();
        assert_eq!(chain.broadcasts.len(), 2);
        assert_eq!(chain.broadcasts[0], chain.broadcasts[1]);
        assert_eq!(external_index(&taker), index + 1);
        assert!(record(&taker, "refund").is_some());
        assert!(record(&taker, "unfunded").is_none());
    }

    /// Screening refuses resent funding from a listed address. The maker
    /// sends the same funding every time and we will never claim it, so the
    /// record is dropped without a claim.
    #[test]
    fn screened_out_resent_funding_is_dropped_unclaimed() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let (listed_key, _) = generate_keypair();
        let listed = bitcoin::Address::p2wpkh(
            &bitcoin::CompressedPublicKey(listed_key.inner),
            bitcoin::Network::Regtest,
        );
        let parent = funding_paying(listed.script_pubkey(), AMOUNT * 2);
        let mut swap = swap_out("unused:1");
        swap.funding.input[0].previous_output = OutPoint::new(parent.compute_txid(), 0);
        swap.outpoint = OutPoint::new(swap.funding.compute_txid(), 0);
        swap.record.resume.as_mut().unwrap().maker =
            fake_maker(&swap.id, vec![Some(funded_reply(&swap))]);
        chain.lock().unwrap().set(&parent, Some(99));
        chain.lock().unwrap().set(&swap.funding, Some(100));
        let (mut taker, _server) = taker_with(dir.path(), &chain);
        taker.config.check_blocklist = Some(true);
        taker.add_blocklist_entry(listed.to_string(), None).unwrap();
        taker
            .save_pending_swap(&swap.id, swap.record.clone())
            .unwrap();

        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert_eq!(
            outcomes,
            [format!(
                "{}: funding refused by screening; forgotten",
                swap.id
            )]
        );
        assert!(record(&taker, &swap.id).is_none());
        assert!(chain.lock().unwrap().broadcasts.is_empty());
    }

    /// If the payout script cannot be saved, nothing is broadcast and the
    /// record on disk still holds everything needed to claim later.
    #[test]
    fn unsaved_payout_script_broadcasts_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let chain = Arc::new(Mutex::new(Chain::default()));
        let swap = swap_out("unused:1");
        chain.lock().unwrap().set(&swap.funding, Some(100));
        let (mut taker, _server) = taker_with(dir.path(), &chain);
        taker.save_pending_swap(&swap.id, funded(&swap)).unwrap();

        let path = dir.path().join("wallet");
        let aside = dir.path().join("wallet-aside");
        std::fs::rename(&path, &aside).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(taker.recover_lightning_swaps().is_err());
        assert!(chain.lock().unwrap().broadcasts.is_empty());
        std::fs::remove_dir(&path).unwrap();
        std::fs::rename(&aside, &path).unwrap();
        let (stored, _) =
            crate::wallet::WalletStore::read_from_disk(&path, Some("test-password".into()))
                .unwrap();
        assert_eq!(stored.ln_pending_swaps[&swap.id], funded(&swap));
        assert_eq!(record(&taker, &swap.id).unwrap().payout_script, None);

        // The retry's claim pays the script that reached the disk.
        let outcomes = taker.recover_lightning_swaps().unwrap();
        assert!(
            outcomes[0].contains("awaiting confirmation"),
            "{:?}",
            outcomes
        );
        let (stored, _) =
            crate::wallet::WalletStore::read_from_disk(&path, Some("test-password".into()))
                .unwrap();
        let claim = chain.lock().unwrap().broadcasts[0].clone();
        assert_eq!(
            stored.ln_pending_swaps[&swap.id].payout_script,
            Some(claim.output[0].script_pubkey.clone())
        );
    }
}
