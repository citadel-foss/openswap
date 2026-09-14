//! Maker-side handlers for Lightning submarine swaps.
//!
//! Message flow (all initiated by the taker; the maker only replies):
//!
//! Swap-in (taker: on-chain BTC -> Lightning):
//! 1. `SwapInRequest`  -> validate terms + invoice, build HTLC -> `SwapInAccept`
//! 2. `SwapInFunded`   -> verify funding, pay hold invoice, learn preimage
//!    from settlement, sweep the HTLC on-chain -> `SwapInComplete`
//!
//! Swap-out (taker: Lightning -> on-chain BTC):
//! 1. `SwapOutRequest` -> validate terms, create hold invoice, build HTLC
//!    -> `SwapOutAccept`
//! 2. `SwapOutPaid`    -> verify the held payment arrived, fund the HTLC
//!    from the wallet -> `SwapOutFunded`
//! 3. `SwapOutClaimed` -> extract preimage from the claim tx, settle the
//!    held payment -> `SwapOutComplete`
//!
//! The connection-independent safety net lives in `ln_watchdog_tick`: it
//! settles swaps whose final message never arrived (crashed taker, dropped
//! connection) by watching the chain and the Lightning event stream, and
//! refunds expired swap-out HTLCs through the timelock branch.

use std::{
    collections::{HashMap, VecDeque},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bitcoin::{hashes::sha256, secp256k1::SecretKey, Amount, OutPoint};

use crate::{
    lightning::{swap::SwapHtlc, LightningBackend, LnEvent, Preimage},
    protocol::{
        common_messages::MakerToTakerMessage,
        lightning_messages::{
            LightningMakerMessage, LightningTakerMessage, LnHtlcFunded, LnReject, LnSwapInAccept,
            LnSwapInComplete, LnSwapInRequest, LnSwapOutAccept, LnSwapOutComplete,
            LnSwapOutRequest,
        },
    },
    utill::generate_keypair,
};

use super::{
    api::MakerServer,
    error::MakerError,
    handlers::{ConnectionState, Maker, SwapPhase},
};

/// How long a message handler waits for a Lightning event before giving up
/// and leaving the swap to the watchdog.
const INLINE_EVENT_TIMEOUT: Duration = Duration::from_secs(120);

/// Safety margin (blocks) the on-chain locktime must clear beyond the
/// invoice's final CLTV delta for a swap-in to be acceptable.
const CLTV_SAFETY_MARGIN: u64 = 12;

/// A swap-out taker gets this long to pay the hold invoice before the maker
/// cancels it and forgets the swap.
const SWAP_OUT_PAYMENT_DEADLINE: Duration = Duration::from_secs(3600);

/// The watchdog leaves states younger than this to their connection handler,
/// so inline waits and the watchdog never race for the same event.
const WATCHDOG_MIN_IDLE: Duration = Duration::from_secs(300);

/// Direction of a Lightning swap, from the taker's perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LnDirection {
    /// Taker pays on-chain, receives Lightning.
    SwapIn,
    /// Taker pays Lightning, receives on-chain.
    SwapOut,
}

/// Progress of a maker-side Lightning swap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LnMakerPhase {
    /// Swap-in accepted; awaiting the taker's HTLC funding announcement.
    InAccepted,
    /// Swap-in invoice paid; awaiting the settlement that reveals the
    /// preimage (then sweep on-chain).
    InPaid,
    /// Swap-out accepted (hold invoice created); awaiting payment.
    OutAccepted,
    /// Swap-out HTLC funded on-chain; awaiting the taker's claim.
    OutFunded,
}

/// Maker-side state of one Lightning swap.
#[derive(Debug, Clone)]
pub struct LnMakerSwap {
    /// Direction of the swap.
    pub direction: LnDirection,
    /// Current phase.
    pub phase: LnMakerPhase,
    /// Lightning payment hash (doubles as swap id in hex).
    pub payment_hash: sha256::Hash,
    /// Swap amount (what the taker receives).
    pub amount: Amount,
    /// Maker fee on top of `amount`.
    pub fee: Amount,
    /// On-chain refund locktime (blocks, CSV).
    pub locktime: u16,
    /// Confirmations required on the HTLC funding output.
    pub min_confirmations: u32,
    /// The on-chain HTLC both sides derived.
    pub htlc: SwapHtlc,
    /// The maker's branch key: hashlock (swap-in) or timelock (swap-out).
    pub privkey: SecretKey,
    /// The invoice: the taker's hold invoice (swap-in) or ours (swap-out).
    pub invoice: String,
    /// The confirmed/broadcast HTLC funding output, once known.
    pub funding: Option<(OutPoint, Amount)>,
    /// Block height when the funding was first seen (refund timing).
    pub funding_height: Option<u32>,
    /// Last phase-change time; the watchdog only touches idle states.
    pub updated_at: Instant,
}

impl LnMakerSwap {
    fn touch(&mut self) {
        self.updated_at = Instant::now();
    }
}

/// Routes Lightning node events into per-payment-hash mailboxes.
///
/// The backend's `poll_event` is a single at-most-once queue; with multiple
/// concurrent swaps, whoever polls steals everyone else's events. A single
/// pump thread drains the backend through [`LnEventRouter::pump_once`] and
/// files each event under its payment hash; swap logic reads only its own
/// mailbox.
pub struct LnEventRouter {
    ln: Arc<dyn LightningBackend>,
    mailboxes: Mutex<HashMap<sha256::Hash, VecDeque<LnEvent>>>,
}

impl LnEventRouter {
    /// Creates a router over the given backend.
    pub fn new(ln: Arc<dyn LightningBackend>) -> Arc<Self> {
        Arc::new(Self {
            ln,
            mailboxes: Mutex::new(HashMap::new()),
        })
    }

    /// Opens a mailbox for a payment hash. Idempotent.
    pub fn subscribe(&self, payment_hash: sha256::Hash) {
        if let Ok(mut boxes) = self.mailboxes.lock() {
            boxes.entry(payment_hash).or_default();
        }
    }

    /// Drops a mailbox and everything still queued in it.
    pub fn unsubscribe(&self, payment_hash: &sha256::Hash) {
        if let Ok(mut boxes) = self.mailboxes.lock() {
            boxes.remove(payment_hash);
        }
    }

    /// Takes the oldest undelivered event for a payment hash, if any.
    pub fn take_event(&self, payment_hash: &sha256::Hash) -> Option<LnEvent> {
        self.mailboxes
            .lock()
            .ok()
            .and_then(|mut boxes| boxes.get_mut(payment_hash).and_then(VecDeque::pop_front))
    }

    /// Drains the backend's event queue into the mailboxes. Returns how many
    /// events were moved; the pump thread sleeps when this is zero.
    pub fn pump_once(&self) -> usize {
        let mut moved = 0;
        loop {
            let event = match self.ln.poll_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(e) => {
                    log::warn!("lightning event poll failed: {e:?}");
                    break;
                }
            };
            let hash = match event_payment_hash(&event) {
                Some(hash) => hash,
                None => {
                    log::debug!("lightning event without payment hash dropped: {event:?}");
                    continue;
                }
            };
            let mut boxes = match self.mailboxes.lock() {
                Ok(boxes) => boxes,
                Err(_) => return moved,
            };
            match boxes.get_mut(&hash) {
                Some(mailbox) => {
                    mailbox.push_back(event);
                    moved += 1;
                }
                None => log::debug!("lightning event for unknown payment {hash} dropped"),
            }
        }
        moved
    }
}

fn event_payment_hash(event: &LnEvent) -> Option<sha256::Hash> {
    match event {
        LnEvent::PaymentReceived { payment_hash, .. } => *payment_hash,
        LnEvent::PaymentSuccessful { payment_hash, .. } => *payment_hash,
        LnEvent::PaymentFailed { payment_hash, .. } => *payment_hash,
        LnEvent::PaymentClaimable { payment_hash, .. } => *payment_hash,
        _ => None,
    }
}

/// Everything the Lightning handlers need from the maker; bails with a
/// graceful reject when the maker has no backend configured.
struct LnContext {
    ln: Arc<dyn LightningBackend>,
    router: Arc<LnEventRouter>,
}

fn ln_context<M: Maker>(maker: &Arc<M>) -> Option<LnContext> {
    Some(LnContext {
        ln: maker.lightning()?,
        router: maker.ln_router()?,
    })
}

fn reject(swap_id: &str, reason: impl Into<String>) -> Option<MakerToTakerMessage> {
    Some(MakerToTakerMessage::Lightning(Box::new(
        LightningMakerMessage::Reject(LnReject {
            swap_id: swap_id.to_string(),
            reason: reason.into(),
        }),
    )))
}

/// Entry point: routed here from `handle_message` for every
/// `TakerToMakerMessage::Lightning`.
pub fn handle_lightning_message<M: Maker>(
    maker: &Arc<M>,
    state: &mut ConnectionState,
    message: LightningTakerMessage,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    // Lightning swaps ride on the plain hello/offer handshake; any
    // post-hello phase is acceptable because reconnects re-enter at
    // AwaitingOfferRequest while first requests arrive at
    // AwaitingSwapDetails.
    state.expect_phase(&[
        SwapPhase::AwaitingOfferRequest,
        SwapPhase::AwaitingSwapDetails,
    ])?;

    let swap_id = message.swap_id().to_string();
    log::info!(
        "[{}] Dispatching Lightning message: {} (swap_id: {})",
        maker.network_port(),
        message,
        swap_id
    );

    let Some(ctx) = ln_context(maker) else {
        return Ok(Some(MakerToTakerMessage::Unsupported(
            crate::protocol::common_messages::UnsupportedMessage {
                what: "Lightning".to_string(),
                reason: "maker has no lightning backend configured".to_string(),
            },
        )));
    };

    match message {
        LightningTakerMessage::SwapInRequest(req) => handle_swap_in_request(maker, &ctx, req),
        LightningTakerMessage::SwapInFunded(funded) => handle_swap_in_funded(maker, &ctx, funded),
        LightningTakerMessage::SwapOutRequest(req) => handle_swap_out_request(maker, &ctx, req),
        LightningTakerMessage::SwapOutPaid(paid) => {
            handle_swap_out_paid(maker, &ctx, &paid.swap_id)
        }
        LightningTakerMessage::SwapOutClaimed(claimed) => {
            handle_swap_out_claimed(maker, &ctx, &claimed.swap_id, claimed.claim_txid)
        }
    }
}

/// Terms validation shared by both directions. Returns the maker fee.
fn validate_terms<M: Maker>(
    maker: &Arc<M>,
    amount: Amount,
    locktime: u16,
) -> Result<Amount, String> {
    let config = maker.get_config();
    let Some(offer) = config.lightning else {
        return Err("lightning swaps not offered".to_string());
    };
    if amount.to_sat() < offer.min_size || amount.to_sat() > offer.max_size {
        return Err(format!(
            "amount {} outside offered range [{}, {}]",
            amount, offer.min_size, offer.max_size
        ));
    }
    if locktime < super::handlers::MIN_CONTRACT_REACTION_TIME {
        return Err(format!(
            "locktime {} below minimum reaction time {}",
            locktime,
            super::handlers::MIN_CONTRACT_REACTION_TIME
        ));
    }
    let fee =
        offer.base_fee as f64 + amount.to_sat() as f64 * offer.amount_relative_fee_pct / 100.0;
    Ok(Amount::from_sat(fee.ceil() as u64))
}

fn store_swap<M: Maker>(
    maker: &Arc<M>,
    swap_id: &str,
    swap: LnMakerSwap,
) -> Result<(), MakerError> {
    maker.store_ln_swap(swap_id, swap)
}

// ---------------------------------------------------------------------------
// Swap-in (taker: on-chain -> Lightning; maker pays the invoice)
// ---------------------------------------------------------------------------

fn handle_swap_in_request<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    req: LnSwapInRequest,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let fee = match validate_terms(maker, req.amount, req.locktime) {
        Ok(fee) => fee,
        Err(reason) => return Ok(reject(&req.swap_id, reason)),
    };

    // The taker's hold invoice must commit to the hash and amount we swap
    // on, and the on-chain locktime must outlast the Lightning claim window
    // or the taker could claim the payment while its refund is spendable.
    let cltv_delta = match crate::lightning::invoice::verify_invoice(
        &req.invoice,
        &req.payment_hash,
        req.amount.to_sat() * 1000,
    ) {
        Ok(verified) => verified.min_final_cltv_expiry_delta,
        Err(reason) => return Ok(reject(&req.swap_id, reason)),
    };
    if (req.locktime as u64) < cltv_delta + CLTV_SAFETY_MARGIN {
        return Ok(reject(
            &req.swap_id,
            format!(
                "locktime {} too short for invoice cltv delta {} + margin {}",
                req.locktime, cltv_delta, CLTV_SAFETY_MARGIN
            ),
        ));
    }

    let (hashlock_pubkey, hashlock_privkey) = generate_keypair();
    let htlc = SwapHtlc::new(
        &hashlock_pubkey,
        &req.taker_timelock_pubkey,
        &req.payment_hash,
        req.locktime,
    );

    ctx.router.subscribe(req.payment_hash);
    store_swap(
        maker,
        &req.swap_id,
        LnMakerSwap {
            direction: LnDirection::SwapIn,
            phase: LnMakerPhase::InAccepted,
            payment_hash: req.payment_hash,
            amount: req.amount,
            fee,
            locktime: req.locktime,
            min_confirmations: req.min_confirmations,
            htlc,
            privkey: hashlock_privkey,
            invoice: req.invoice.clone(),
            funding: None,
            funding_height: None,
            updated_at: Instant::now(),
        },
    )?;

    log::info!(
        "[{}] Accepted swap-in {} amount={} fee={}",
        maker.network_port(),
        req.swap_id,
        req.amount,
        fee
    );
    Ok(Some(MakerToTakerMessage::Lightning(Box::new(
        LightningMakerMessage::SwapInAccept(LnSwapInAccept {
            swap_id: req.swap_id,
            maker_hashlock_pubkey: hashlock_pubkey,
            fee,
            locktime: req.locktime,
            min_confirmations: req.min_confirmations,
        }),
    ))))
}

fn handle_swap_in_funded<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    funded: LnHtlcFunded,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let mut swap = match maker.get_ln_swap(&funded.swap_id)? {
        Some(swap) if swap.phase == LnMakerPhase::InAccepted => swap,
        Some(_) => return Err(MakerError::General("swap-in not awaiting funding")),
        None => return Ok(reject(&funded.swap_id, "unknown swap")),
    };

    // Wait for the announced funding to confirm, then verify it against the
    // HTLC we derived ourselves — script and exact value.
    maker.wait_for_tx_on_chain(&funded.outpoint.txid, swap.min_confirmations)?;
    let funding_tx = maker.get_raw_transaction(&funded.outpoint.txid)?;
    let output = funding_tx
        .output
        .get(funded.outpoint.vout as usize)
        .ok_or(MakerError::General("funding vout out of range"))?;
    let expected = swap.amount + swap.fee;
    if funded.value != output.value {
        return Ok(reject(&funded.swap_id, "announced value mismatch"));
    }
    if let Err(e) = swap.htlc.validate_funding_output(output, expected) {
        return Ok(reject(&funded.swap_id, format!("bad funding output: {e}")));
    }
    let htlc_spk = swap
        .htlc
        .script_pubkey()
        .map_err(|e| MakerError::General(format!("htlc spk: {e}").leak()))?;
    maker.register_watch_outpoint(funded.outpoint, htlc_spk.clone())?;

    swap.funding = Some((funded.outpoint, output.value));
    swap.funding_height = maker.get_current_height().ok();
    swap.phase = LnMakerPhase::InPaid;
    swap.touch();
    store_swap(maker, &funded.swap_id, swap.clone())?;

    // The on-chain money is locked to our hashlock; paying the invoice is
    // now safe. The settlement event hands us the preimage.
    ctx.ln
        .pay_invoice(&swap.invoice, None)
        .map_err(|e| MakerError::General(format!("pay_invoice: {e:?}").leak()))?;
    log::info!(
        "[{}] Swap-in {}: invoice paid, awaiting settlement",
        maker.network_port(),
        funded.swap_id
    );

    let preimage = wait_for_preimage(maker, ctx, &swap.payment_hash)?;
    sweep_swap_in(maker, ctx, &funded.swap_id, &swap, &preimage)?;
    Ok(Some(MakerToTakerMessage::Lightning(Box::new(
        LightningMakerMessage::SwapInComplete(LnSwapInComplete {
            swap_id: funded.swap_id,
        }),
    ))))
}

/// Blocks until the settlement for `payment_hash` reveals the preimage, the
/// payment fails, or the inline timeout passes (the watchdog then owns the
/// swap).
fn wait_for_preimage<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    payment_hash: &sha256::Hash,
) -> Result<Preimage, MakerError> {
    let deadline = Instant::now() + INLINE_EVENT_TIMEOUT;
    loop {
        while let Some(event) = ctx.router.take_event(payment_hash) {
            match event {
                LnEvent::PaymentSuccessful {
                    preimage: Some(preimage),
                    ..
                } => {
                    if preimage.payment_hash() != *payment_hash {
                        return Err(MakerError::General("settlement preimage mismatch"));
                    }
                    return Ok(preimage);
                }
                LnEvent::PaymentFailed { payment_id, .. } => {
                    return Err(MakerError::General(
                        format!("lightning payment {payment_id} failed").leak(),
                    ));
                }
                other => log::debug!("ignoring event while waiting for settlement: {other:?}"),
            }
        }
        if Instant::now() > deadline || maker.shutdown_requested() {
            return Err(MakerError::General(
                "timed out waiting for settlement; watchdog will finish the sweep",
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// Sweeps a settled swap-in's HTLC to the wallet and forgets the swap.
fn sweep_swap_in<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    swap_id: &str,
    swap: &LnMakerSwap,
    preimage: &Preimage,
) -> Result<(), MakerError> {
    let (outpoint, value) = swap
        .funding
        .ok_or(MakerError::General("swap-in sweep without funding"))?;
    let destination = maker.get_receive_address()?.script_pubkey();
    let claim_tx = swap
        .htlc
        .create_hashlock_spend(outpoint, value, &swap.privkey, preimage, destination)
        .map_err(|e| MakerError::General(format!("claim build: {e}").leak()))?;
    let claim_txid = maker.broadcast_transaction(&claim_tx)?;
    log::info!(
        "[{}] Swap-in {} settled; on-chain sweep broadcast: {}",
        maker.network_port(),
        swap_id,
        claim_txid
    );
    if let Ok(spk) = swap.htlc.script_pubkey() {
        maker.unwatch_outpoint(outpoint, spk);
    }
    ctx.router.unsubscribe(&swap.payment_hash);
    maker.remove_ln_swap(swap_id)?;
    let _ = maker.sync_and_save_wallet();
    Ok(())
}

// ---------------------------------------------------------------------------
// Swap-out (taker: Lightning -> on-chain; maker funds the HTLC)
// ---------------------------------------------------------------------------

fn handle_swap_out_request<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    req: LnSwapOutRequest,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let fee = match validate_terms(maker, req.amount, req.locktime) {
        Ok(fee) => fee,
        Err(reason) => return Ok(reject(&req.swap_id, reason)),
    };

    let invoice_amount = req.amount + fee;
    let invoice = match ctx.ln.create_hold_invoice(
        req.payment_hash,
        crate::lightning::InvoiceParams {
            amount_msat: Some(invoice_amount.to_sat() * 1000),
            description: format!("swap-out {}", req.swap_id),
            expiry_secs: SWAP_OUT_PAYMENT_DEADLINE.as_secs() as u32,
        },
    ) {
        Ok(invoice) => invoice,
        Err(e) => return Ok(reject(&req.swap_id, format!("hold invoice failed: {e:?}"))),
    };

    let (timelock_pubkey, timelock_privkey) = generate_keypair();
    let htlc = SwapHtlc::new(
        &req.taker_hashlock_pubkey,
        &timelock_pubkey,
        &req.payment_hash,
        req.locktime,
    );

    ctx.router.subscribe(req.payment_hash);
    store_swap(
        maker,
        &req.swap_id,
        LnMakerSwap {
            direction: LnDirection::SwapOut,
            phase: LnMakerPhase::OutAccepted,
            payment_hash: req.payment_hash,
            amount: req.amount,
            fee,
            locktime: req.locktime,
            min_confirmations: req.min_confirmations,
            htlc,
            privkey: timelock_privkey,
            invoice: invoice.invoice.clone(),
            funding: None,
            funding_height: None,
            updated_at: Instant::now(),
        },
    )?;

    log::info!(
        "[{}] Accepted swap-out {} amount={} fee={}",
        maker.network_port(),
        req.swap_id,
        req.amount,
        fee
    );
    Ok(Some(MakerToTakerMessage::Lightning(Box::new(
        LightningMakerMessage::SwapOutAccept(LnSwapOutAccept {
            swap_id: req.swap_id,
            invoice: invoice.invoice,
            fee,
            maker_timelock_pubkey: timelock_pubkey,
            locktime: req.locktime,
            min_confirmations: req.min_confirmations,
        }),
    ))))
}

fn handle_swap_out_paid<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    swap_id: &str,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let mut swap = match maker.get_ln_swap(swap_id)? {
        Some(swap) if swap.phase == LnMakerPhase::OutAccepted => swap,
        Some(swap) if swap.phase == LnMakerPhase::OutFunded => {
            // Retransmission after a dropped connection: repeat the answer.
            let (outpoint, value) = swap.funding.expect("OutFunded always has funding");
            return Ok(Some(MakerToTakerMessage::Lightning(Box::new(
                LightningMakerMessage::SwapOutFunded(LnHtlcFunded {
                    swap_id: swap_id.to_string(),
                    outpoint,
                    value,
                }),
            ))));
        }
        Some(_) => return Err(MakerError::General("swap-out not awaiting payment")),
        None => return Ok(reject(swap_id, "unknown swap")),
    };

    // Never fund on the taker's word alone: the held payment must actually
    // be parked at our node.
    let deadline = Instant::now() + INLINE_EVENT_TIMEOUT;
    let held = loop {
        if let Some(event) = ctx.router.take_event(&swap.payment_hash) {
            match event {
                LnEvent::PaymentClaimable { .. } => break true,
                other => log::debug!("ignoring event while waiting for held payment: {other:?}"),
            }
        } else if Instant::now() > deadline || maker.shutdown_requested() {
            break false;
        } else {
            std::thread::sleep(Duration::from_millis(200));
        }
    };
    if !held {
        return Ok(reject(swap_id, "held payment not observed"));
    }

    // Fund the HTLC from the wallet with exactly `amount` (the fee is
    // collected on the Lightning side).
    let address = swap
        .htlc
        .address(maker.network())
        .map_err(|e| MakerError::General(format!("htlc address: {e}").leak()))?;
    let (funding_tx, vout) = maker.create_funding_transaction(swap.amount, address, None)?;
    let txid = maker.broadcast_transaction(&funding_tx)?;
    let outpoint = OutPoint { txid, vout };
    let value = funding_tx
        .output
        .get(vout as usize)
        .map(|o| o.value)
        .ok_or(MakerError::General("funding vout out of range"))?;
    let htlc_spk = swap
        .htlc
        .script_pubkey()
        .map_err(|e| MakerError::General(format!("htlc spk: {e}").leak()))?;
    maker.register_watch_outpoint(outpoint, htlc_spk)?;

    swap.funding = Some((outpoint, value));
    swap.funding_height = maker.get_current_height().ok();
    swap.phase = LnMakerPhase::OutFunded;
    swap.touch();
    store_swap(maker, swap_id, swap)?;
    let _ = maker.sync_and_save_wallet();

    log::info!(
        "[{}] Swap-out {}: HTLC funded at {}",
        maker.network_port(),
        swap_id,
        outpoint
    );
    Ok(Some(MakerToTakerMessage::Lightning(Box::new(
        LightningMakerMessage::SwapOutFunded(LnHtlcFunded {
            swap_id: swap_id.to_string(),
            outpoint,
            value,
        }),
    ))))
}

fn handle_swap_out_claimed<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    swap_id: &str,
    claim_txid: bitcoin::Txid,
) -> Result<Option<MakerToTakerMessage>, MakerError> {
    let swap = match maker.get_ln_swap(swap_id)? {
        Some(swap) if swap.phase == LnMakerPhase::OutFunded => swap,
        Some(_) => return Err(MakerError::General("swap-out not awaiting claim")),
        None => return Ok(reject(swap_id, "unknown swap")),
    };

    let claim_tx = maker.get_raw_transaction(&claim_txid)?;
    settle_swap_out_from_spend(maker, ctx, swap_id, &swap, &claim_tx)?;
    Ok(Some(MakerToTakerMessage::Lightning(Box::new(
        LightningMakerMessage::SwapOutComplete(LnSwapOutComplete {
            swap_id: swap_id.to_string(),
        }),
    ))))
}

/// Extracts the preimage from a spend of the swap-out HTLC and settles the
/// held Lightning payment with it.
fn settle_swap_out_from_spend<M: Maker>(
    maker: &Arc<M>,
    ctx: &LnContext,
    swap_id: &str,
    swap: &LnMakerSwap,
    spend_tx: &bitcoin::Transaction,
) -> Result<(), MakerError> {
    let preimage = swap
        .htlc
        .extract_preimage(spend_tx)
        .ok_or(MakerError::General("spend reveals no preimage"))?;
    if preimage.payment_hash() != swap.payment_hash {
        return Err(MakerError::General("revealed preimage does not match"));
    }
    ctx.ln
        .claim_held_payment(&preimage)
        .map_err(|e| MakerError::General(format!("claim held payment: {e:?}").leak()))?;
    log::info!(
        "[{}] Swap-out {} settled from on-chain preimage",
        maker.network_port(),
        swap_id
    );
    if let (Some((outpoint, _)), Ok(spk)) = (swap.funding, swap.htlc.script_pubkey()) {
        maker.unwatch_outpoint(outpoint, spk);
    }
    ctx.router.unsubscribe(&swap.payment_hash);
    maker.remove_ln_swap(swap_id)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Watchdog: connection-independent settlement and refunds
// ---------------------------------------------------------------------------

/// One pass over all Lightning swaps whose final message never arrived.
/// Runs on a maker background thread; states touched recently are left to
/// their connection handler.
pub(crate) fn ln_watchdog_tick(maker: &Arc<MakerServer>) {
    let (Some(ctx_ln), Some(router)) = (maker.lightning.clone(), maker.ln_router.clone()) else {
        return;
    };
    let ctx = LnContext { ln: ctx_ln, router };

    let swaps: Vec<(String, LnMakerSwap)> = match maker.ln_swaps.lock() {
        Ok(swaps) => swaps
            .iter()
            .filter(|(_, s)| s.updated_at.elapsed() > WATCHDOG_MIN_IDLE)
            .map(|(id, s)| (id.clone(), s.clone()))
            .collect(),
        Err(_) => return,
    };

    for (swap_id, swap) in swaps {
        let result = match (swap.direction, swap.phase) {
            // The invoice was paid but the settlement was missed inline:
            // watch the mailbox and finish the sweep when it lands.
            (LnDirection::SwapIn, LnMakerPhase::InPaid) => {
                watchdog_finish_swap_in(maker, &ctx, &swap_id, &swap)
            }
            // Accepted but never funded/paid: forget after the deadline.
            (_, LnMakerPhase::InAccepted) | (_, LnMakerPhase::OutAccepted) => {
                if swap.updated_at.elapsed() > SWAP_OUT_PAYMENT_DEADLINE {
                    log::info!("Lightning swap {swap_id} expired unfunded; forgetting");
                    if swap.direction == LnDirection::SwapOut {
                        let _ = ctx.ln.fail_held_payment(swap.payment_hash);
                    }
                    ctx.router.unsubscribe(&swap.payment_hash);
                    let _ = maker.remove_ln_swap(&swap_id);
                }
                Ok(())
            }
            // Funded swap-out: settle from the claim spend, or refund once
            // the timelock has passed.
            (LnDirection::SwapOut, LnMakerPhase::OutFunded) => {
                watchdog_resolve_swap_out(maker, &ctx, &swap_id, &swap)
            }
            _ => Ok(()),
        };
        if let Err(e) = result {
            log::warn!("Lightning watchdog on swap {swap_id}: {e:?}");
        }
    }
}

fn watchdog_finish_swap_in(
    maker: &Arc<MakerServer>,
    ctx: &LnContext,
    swap_id: &str,
    swap: &LnMakerSwap,
) -> Result<(), MakerError> {
    while let Some(event) = ctx.router.take_event(&swap.payment_hash) {
        if let LnEvent::PaymentSuccessful {
            preimage: Some(preimage),
            ..
        } = event
        {
            if preimage.payment_hash() == swap.payment_hash {
                return sweep_swap_in(maker, ctx, swap_id, swap, &preimage);
            }
        }
    }
    Ok(())
}

fn watchdog_resolve_swap_out(
    maker: &Arc<MakerServer>,
    ctx: &LnContext,
    swap_id: &str,
    swap: &LnMakerSwap,
) -> Result<(), MakerError> {
    use crate::watch_tower::watcher::WatcherEvent;
    let (outpoint, value) = swap
        .funding
        .ok_or(MakerError::General("OutFunded without funding"))?;

    match maker.watch_service.watch_request(outpoint) {
        Ok(WatcherEvent::UtxoSpent {
            spending_tx: Some(spending_tx),
            ..
        }) => {
            // Either the taker's claim (carries the preimage we need) or our
            // own refund landing; both close the swap.
            if swap.htlc.extract_preimage(&spending_tx).is_some() {
                settle_swap_out_from_spend(maker, ctx, swap_id, swap, &spending_tx)
            } else {
                log::info!("Swap-out {swap_id} HTLC spent without preimage (refund); closing");
                ctx.router.unsubscribe(&swap.payment_hash);
                maker.remove_ln_swap(swap_id)
            }
        }
        Ok(WatcherEvent::UtxoSpent {
            spending_tx: None, ..
        }) => Ok(()), // spent but tx unknown yet; retry next tick
        Ok(_) => {
            // Unspent: refund once the CSV window has passed. An early
            // attempt fails non-BIP68-final harmlessly and is retried.
            let current = maker.get_current_height()?;
            let refundable = swap
                .funding_height
                .map(|h| current >= h.saturating_add(swap.locktime as u32))
                .unwrap_or(false);
            if !refundable {
                return Ok(());
            }
            let destination = maker.get_receive_address()?.script_pubkey();
            let refund_tx = swap
                .htlc
                .create_timelock_spend(outpoint, value, &swap.privkey, destination)
                .map_err(|e| MakerError::General(format!("refund build: {e}").leak()))?;
            match maker.broadcast_transaction(&refund_tx) {
                Ok(txid) => {
                    log::info!("Swap-out {swap_id} refunded via timelock: {txid}");
                    let _ = ctx.ln.fail_held_payment(swap.payment_hash);
                    if let Ok(spk) = swap.htlc.script_pubkey() {
                        maker.unwatch_outpoint(outpoint, spk);
                    }
                    ctx.router.unsubscribe(&swap.payment_hash);
                    maker.remove_ln_swap(swap_id)?;
                    let _ = maker.sync_and_save_wallet();
                    Ok(())
                }
                Err(e) => {
                    log::debug!("swap-out {swap_id} refund not yet broadcastable: {e:?}");
                    Ok(())
                }
            }
        }
        Err(e) => Err(MakerError::General(
            format!("watch request failed: {e:?}").leak(),
        )),
    }
}
