//! Taker-side driver for Lightning submarine swaps.
//!
//! Both directions run over a single maker connection using the standard
//! hello/offer handshake followed by the `Lightning` message family. The
//! maker is chosen explicitly or from the offerbook (first good maker whose
//! offer advertises Lightning terms covering the amount).
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
        ln.pay_invoice(&accept.invoice, None)
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
