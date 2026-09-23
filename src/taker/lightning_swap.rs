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
//! wallet store before any value is committed, and removed when the swap
//! resolves. [`Taker::recover_lightning_swaps`] spends whatever those
//! records can still claim — the hashlock branch when the preimage is ours
//! (swap-out), the timelock branch otherwise (swap-in refund).

use std::{
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use bitcoin::{
    hashes::sha256,
    secp256k1::rand::{rngs::OsRng, RngCore},
    Amount, OutPoint, Txid,
};

use crate::{
    lightning::{
        invoice::verify_invoice, swap::SwapHtlc, InvoiceParams, LightningBackend, LightningConfig,
        LnEvent, Preimage,
    },
    protocol::{
        common_messages::{GetOffer, MakerToTakerMessage, Offer, TakerHello, TakerToMakerMessage},
        lightning_messages::{
            LightningMakerMessage, LightningOffer, LightningTakerMessage, LnHtlcFunded,
            LnSwapInRequest, LnSwapOutClaimed, LnSwapOutPaid, LnSwapOutRequest,
        },
    },
    utill::{generate_keypair, read_message, send_message, MIN_FEE_RATE},
    wallet::{AddressType, LnPendingSwap},
};

use super::{
    api::{Taker, TakerInitConfig},
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

/// Builds the taker's Lightning backend from config, mirroring the maker's
/// behavior: misconfiguration disables Lightning instead of failing init.
pub(crate) fn init_lightning_backend(
    config: &TakerInitConfig,
) -> Option<Arc<dyn LightningBackend>> {
    use bitcoin::hashes::hex::DisplayHex;
    let url = config.ldk_server_url.as_ref()?;
    let api_key_path = match &config.ldk_api_key_path {
        Some(path) => path,
        None => {
            log::error!("ldk_server_url set but ldk_api_key_path missing; Lightning disabled");
            return None;
        }
    };
    let api_key = match std::fs::read(api_key_path) {
        Ok(bytes) => bytes.to_lower_hex_string(),
        Err(e) => {
            log::error!("cannot read LDK api key {api_key_path}: {e}; Lightning disabled");
            return None;
        }
    };
    let ln_config = LightningConfig {
        base_url: url.clone(),
        api_key,
        tls_cert_path: config
            .ldk_tls_cert_path
            .as_ref()
            .map(std::path::PathBuf::from),
        timeout_secs: crate::lightning::DEFAULT_TIMEOUT_SECS,
    };
    match crate::lightning::LdkServerBackend::new(&ln_config) {
        Ok(backend) => {
            log::info!("Lightning backend connected: {url}");
            Some(Arc::new(backend))
        }
        Err(e) => {
            log::error!("Lightning backend init failed: {e:?}; Lightning disabled");
            None
        }
    }
}

/// The maker's advertised fee for this amount; the accepted fee must not
/// exceed it. Must mirror the maker's own formula.
fn advertised_fee(offer: &LightningOffer, amount: Amount) -> Amount {
    let fee =
        offer.base_fee as f64 + amount.to_sat() as f64 * offer.amount_relative_fee_pct / 100.0;
    Amount::from_sat(fee.ceil() as u64)
}

fn general(msg: impl Into<String>) -> TakerError {
    TakerError::General(msg.into())
}

/// A maker connection with the hello/offer handshake completed.
struct LnMakerConn {
    socket: TcpStream,
    address: String,
    ln_offer: LightningOffer,
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
        let bytes = read_message(&mut self.socket)
            .map_err(|e| general(format!("read from maker failed: {e:?}")))?;
        let msg: MakerToTakerMessage = serde_cbor::from_slice(&bytes)
            .map_err(|e| general(format!("bad maker message: {e:?}")))?;
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
                    (if swap_in { ln.swap_in } else { ln.swap_out })
                        && amount.to_sat() >= ln.min_size
                        && amount.to_sat() <= ln.max_size
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
        let mut socket = self.net_connect(address)?;
        send_message(&mut socket, &TakerToMakerMessage::TakerHello(TakerHello))
            .map_err(|e| general(format!("hello failed: {e:?}")))?;
        let bytes =
            read_message(&mut socket).map_err(|e| general(format!("hello reply: {e:?}")))?;
        let msg: MakerToTakerMessage =
            serde_cbor::from_slice(&bytes).map_err(|e| general(format!("bad hello: {e:?}")))?;
        if !matches!(msg, MakerToTakerMessage::MakerHello(_)) {
            return Err(general("expected MakerHello"));
        }

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
        let supported = if swap_in {
            ln_offer.swap_in
        } else {
            ln_offer.swap_out
        };
        if !supported {
            return Err(general("maker does not offer this swap direction"));
        }
        if amount.to_sat() < ln_offer.min_size || amount.to_sat() > ln_offer.max_size {
            return Err(general(format!(
                "amount {} outside maker's range [{}, {}]",
                amount, ln_offer.min_size, ln_offer.max_size
            )));
        }
        Ok(LnMakerConn {
            socket,
            address: address.to_string(),
            ln_offer,
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

        let (tx, vout) = {
            let mut wallet = self.write_wallet()?;
            let result = wallet.create_funding_txes(value, &[address], MIN_FEE_RATE, None, None)?;
            let tx = result
                .funding_txes
                .into_iter()
                .next()
                .ok_or_else(|| general("no funding tx created"))?;
            let vout = result
                .payment_output_positions
                .first()
                .copied()
                .unwrap_or(0);
            wallet.send_tx(&tx)?;
            (tx, vout)
        };
        let outpoint = OutPoint {
            txid: tx.compute_txid(),
            vout,
        };
        let actual_value = tx
            .output
            .get(vout as usize)
            .map(|o| o.value)
            .ok_or_else(|| general("funding vout out of range"))?;

        // Update the recovery record with the now-committed outpoint before
        // anything else can go wrong.
        {
            let mut wallet = self.write_wallet()?;
            if let Some(record) = wallet.store.ln_pending_swaps.get_mut(swap_id) {
                record.outpoint = Some(outpoint);
                record.value = Some(actual_value);
            }
            wallet.save_to_disk()?;
        }
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
                    amount_msat: Some(params.amount.to_sat() * 1000),
                    description: format!("swap-in {swap_id}"),
                    expiry_secs: 3600,
                },
            )
            .map_err(|e| general(format!("hold invoice: {e:?}")))?;

        // The refund locktime must clear our own invoice's CLTV window; the
        // maker enforces the same bound on its side.
        let cltv_delta = verify_invoice(
            &invoice.invoice,
            &payment_hash,
            params.amount.to_sat() * 1000,
        )
        .map_err(|e| general(format!("own invoice failed verification: {e}")))?
        .min_final_cltv_expiry_delta as u16;
        let locktime = params
            .locktime
            .unwrap_or(cltv_delta + DEFAULT_LOCKTIME_HEADROOM);
        if locktime < cltv_delta + CLTV_SAFETY_MARGIN {
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
        if accept.fee > expected_fee {
            return Err(general(format!(
                "maker fee {} exceeds advertised {}",
                accept.fee, expected_fee
            )));
        }

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
            },
        )?;
        let funding_value = params.amount + accept.fee;
        let (outpoint, actual_value) =
            self.fund_htlc_output(&htlc, funding_value, params.min_confirmations, &swap_id)?;

        conn.send(LightningTakerMessage::SwapInFunded(LnHtlcFunded {
            swap_id: swap_id.clone(),
            outpoint,
            value: actual_value,
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
        if accept.fee > expected_fee {
            return Err(general(format!(
                "maker fee {} exceeds advertised {}",
                accept.fee, expected_fee
            )));
        }
        // Never pay an invoice we did not verify: it must commit to OUR
        // payment hash and the agreed amount, or the maker could settle
        // instantly without funding anything.
        verify_invoice(
            &accept.invoice,
            &payment_hash,
            (params.amount + accept.fee).to_sat() * 1000,
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
        {
            let mut wallet = self.write_wallet()?;
            if let Some(record) = wallet.store.ln_pending_swaps.get_mut(&swap_id) {
                record.outpoint = Some(funded.outpoint);
                record.value = Some(output.value);
            }
            wallet.save_to_disk()?;
        }

        let destination = self
            .write_wallet()?
            .get_next_external_address(AddressType::P2WPKH)?
            .script_pubkey();
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

        self.remove_pending_swap(&swap_id)?;
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
        if accept2.fee > expected_fee2 {
            return Err(general(format!(
                "second maker fee {} exceeds advertised {}",
                accept2.fee, expected_fee2
            )));
        }

        // What maker 1 must forward over Lightning: our payout plus maker 2's
        // fee. Verified against the invoice we are about to hand over, since
        // maker 1 will check the same thing and reject a mismatch.
        let middle_amount = params.amount + accept2.fee;
        let cltv_delta = verify_invoice(
            &accept2.invoice,
            &payment_hash,
            middle_amount.to_sat() * 1000,
        )
        .map_err(|e| general(format!("second maker's invoice failed verification: {e}")))?
        .min_final_cltv_expiry_delta as u16;

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
        if accept1.fee > expected_fee1 {
            return Err(general(format!(
                "first maker fee {} exceeds advertised {}",
                accept1.fee, expected_fee1
            )));
        }

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
            },
        )?;

        let sent = middle_amount + accept1.fee;
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
        {
            let mut wallet = self.write_wallet()?;
            if let Some(record) = wallet.store.ln_pending_swaps.get_mut(&out_key) {
                record.outpoint = Some(funded2.outpoint);
                record.value = Some(output2.value);
            }
            wallet.save_to_disk()?;
        }

        // ---- Claim hop 2: publishes the preimage that unlocks hop 1 ----
        let destination = self
            .write_wallet()?
            .get_next_external_address(AddressType::P2WPKH)?
            .script_pubkey();
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

        self.remove_pending_swap(&out_key)?;
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
        let records: Vec<(String, LnPendingSwap)> = self
            .read_wallet()?
            .store
            .ln_pending_swaps
            .iter()
            .map(|(id, record)| (id.clone(), record.clone()))
            .collect();

        let mut outcomes = Vec::new();
        for (swap_id, record) in records {
            let (outpoint, value) = match (record.outpoint, record.value) {
                (Some(outpoint), Some(value)) => (outpoint, value),
                _ => {
                    // Nothing was ever committed on-chain.
                    self.remove_pending_swap(&swap_id)?;
                    outcomes.push(format!("{swap_id}: no on-chain commitment; forgotten"));
                    continue;
                }
            };
            let htlc = SwapHtlc::from_redeemscript(record.redeemscript.clone(), record.locktime);
            let destination = self
                .write_wallet()?
                .get_next_external_address(AddressType::P2WPKH)?
                .script_pubkey();
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

            match self.read_wallet()?.send_tx(&spend) {
                Ok(txid) => {
                    self.remove_pending_swap(&swap_id)?;
                    outcomes.push(format!("{swap_id}: recovered via {txid}"));
                }
                Err(e) => {
                    let text = format!("{e:?}");
                    if text.contains("non-BIP68-final") {
                        outcomes.push(format!(
                            "{swap_id}: refund not yet mature (locktime {}); retry later",
                            record.locktime
                        ));
                    } else if text.contains("missingorspent")
                        || text.contains("already")
                        || text.contains("conflict")
                    {
                        // The outpoint is gone: counterparty claimed (they
                        // held the preimage/our payment settled) or an
                        // earlier recovery landed.
                        self.remove_pending_swap(&swap_id)?;
                        outcomes.push(format!("{swap_id}: already resolved on-chain"));
                    } else {
                        outcomes.push(format!("{swap_id}: broadcast failed: {text}"));
                    }
                }
            }
        }
        let _ = self.write_wallet()?.sync_and_save(&Default::default());
        Ok(outcomes)
    }
}
