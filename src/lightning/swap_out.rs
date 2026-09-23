//! POC of a Lightning -> Bitcoin reverse submarine swap ("swap-out").
//!
//! A *taker* with Lightning balance buys on-chain BTC from a *maker* that has
//! on-chain funds:
//!
//! 1. The taker generates a random 32-byte preimage `P`, computes
//!    `H = sha256(P)` and sends [`SwapOutRequest`] (hash, terms and its
//!    hashlock pubkey) to the maker.
//! 2. The maker creates a hold invoice **for `H`** on its own node (it does
//!    not know `P`, so it cannot settle the payment by itself) and answers
//!    with [`SwapOutAccept`].
//! 3. The taker pays the invoice. The payment parks at the maker's node as
//!    `PaymentClaimable` — in-flight, settled by nobody yet.
//! 4. The maker, seeing the held payment, funds the on-chain HTLC built by
//!    `create_contract_redeemscript`: hashlock branch spendable by the taker
//!    with `P`, timelock branch refundable by the maker after `locktime`
//!    blocks (CSV).
//! 5. The taker verifies the funding output and claims it through the
//!    hashlock branch — necessarily publishing `P` in the witness.
//! 6. The maker extracts `P` from the taker's claim transaction
//!    ([`SwapHtlc::extract_preimage`]) and settles the held payment,
//!    collecting the Lightning amount.
//!
//! Atomicity mirrors the swap-in: the taker can only take the on-chain coins
//! by revealing `P`, and `P` is exactly what lets the maker settle the held
//! Lightning payment. If the maker never funds, the taker's payment fails
//! back at the Lightning HTLC's expiry; if the taker never claims, the maker
//! refunds through the timelock branch and the payment likewise fails back.
//!
//! # Timelock safety (documented, not enforced — POC)
//!
//! The maker is safe only while the held Lightning payment is still
//! claimable when `P` appears on-chain, so the invoice's
//! `min_final_cltv_expiry_delta` must exceed `locktime` plus the maker's
//! sweep margin. Stock ldk-node does not expose that knob and its default
//! window is only a few usable blocks before the node fails the held HTLC
//! back, which makes this direction demo-grade on regtest (where blocks are
//! mined on demand) but not production-safe without patching ldk-server to
//! raise the invoice delta.
//!
//! A second POC gap: the taker cannot parse BOLT11, so it trusts the echoed
//! [`SwapOutAccept::payment_hash`] instead of verifying that the invoice
//! string itself commits to `H` and the agreed amount. Production needs a
//! bolt11 decoder here — paying an invoice with a different hash would let
//! the maker settle instantly without funding anything.

use std::sync::Arc;

use bitcoin::{
    hashes::sha256,
    secp256k1::{
        rand::{rngs::OsRng, RngCore},
        SecretKey,
    },
    Amount, OutPoint, PublicKey, ScriptBuf, Transaction, TxOut,
};

use crate::utill::generate_keypair;

use super::{
    backend::LightningBackend,
    swap::{HtlcFunded, SwapError, SwapHtlc},
    types::{LnEvent, PaymentId, Preimage},
};

/// Economic and timing terms of a swap-out.
///
/// See the module docs for the timelock-safety constraint on `locktime`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapOutParams {
    /// On-chain amount the taker receives (the HTLC funding value).
    pub amount: Amount,
    /// Fee retained by the maker on top of `amount` in the Lightning invoice.
    pub maker_fee: Amount,
    /// Relative locktime (blocks, CSV) of the maker's refund branch.
    pub locktime: u16,
    /// Confirmations the taker requires on the HTLC funding output before
    /// claiming it (revealing the preimage).
    pub min_confirmations: u32,
}

impl SwapOutParams {
    /// Amount the taker must pay over Lightning: `amount + maker_fee`.
    pub fn invoice_amount(&self) -> Amount {
        self.amount + self.maker_fee
    }
}

/// Taker -> Maker: initial swap proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapOutRequest {
    /// The Lightning payment hash `H = sha256(P)`; only the taker knows `P`.
    pub payment_hash: sha256::Hash,
    /// Proposed swap terms.
    pub params: SwapOutParams,
    /// Taker pubkey for the hashlock (claim) branch of the HTLC script.
    pub taker_hashlock_pubkey: PublicKey,
}

/// Maker -> Taker: acceptance of a [`SwapOutRequest`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapOutAccept {
    /// BOLT11 hold invoice for `H` on the maker node, over
    /// [`SwapOutParams::invoice_amount`].
    pub invoice: String,
    /// The invoice payment hash (echo of the requested `H`).
    pub payment_hash: sha256::Hash,
    /// Maker pubkey for the timelock (refund) branch of the HTLC script.
    pub maker_timelock_pubkey: PublicKey,
    /// Agreed refund locktime (echo of the requested terms).
    pub locktime: u16,
    /// Agreed confirmation requirement (echo of the requested terms).
    pub min_confirmations: u32,
}

/// The taker role: holds the preimage, pays Lightning, receives on-chain BTC.
pub struct SwapOutTaker {
    ln: Arc<dyn LightningBackend>,
    params: SwapOutParams,
    preimage: Preimage,
    payment_hash: sha256::Hash,
    hashlock_pubkey: PublicKey,
    hashlock_privkey: SecretKey,
    invoice: Option<String>,
    htlc: Option<SwapHtlc>,
}

impl SwapOutTaker {
    /// Creates a taker with a fresh random preimage and hashlock keypair.
    pub fn new(ln: Arc<dyn LightningBackend>, params: SwapOutParams) -> Self {
        let mut preimage_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut preimage_bytes);
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let (hashlock_pubkey, hashlock_privkey) = generate_keypair();
        Self {
            ln,
            params,
            preimage,
            payment_hash,
            hashlock_pubkey,
            hashlock_privkey,
            invoice: None,
            htlc: None,
        }
    }

    /// The Lightning payment hash `H = sha256(P)`.
    pub fn payment_hash(&self) -> sha256::Hash {
        self.payment_hash
    }

    /// The swap preimage `P` (exposed for tests/demos only).
    pub fn preimage(&self) -> Preimage {
        self.preimage
    }

    /// The HTLC, available after [`SwapOutTaker::on_accept`].
    pub fn htlc(&self) -> Option<&SwapHtlc> {
        self.htlc.as_ref()
    }

    /// Builds the swap request for the maker.
    pub fn make_request(&self) -> SwapOutRequest {
        SwapOutRequest {
            payment_hash: self.payment_hash,
            params: self.params,
            taker_hashlock_pubkey: self.hashlock_pubkey,
        }
    }

    /// Validates the maker's acceptance and builds the on-chain HTLC.
    ///
    /// POC: verifies the echoed payment hash and terms, but trusts that the
    /// invoice string commits to them (no bolt11 parsing — see module docs).
    pub fn on_accept(&mut self, accept: &SwapOutAccept) -> Result<&SwapHtlc, SwapError> {
        if accept.payment_hash != self.payment_hash {
            return Err(SwapError::Validation(format!(
                "maker echoed wrong payment hash {}",
                accept.payment_hash
            )));
        }
        if accept.locktime != self.params.locktime
            || accept.min_confirmations != self.params.min_confirmations
        {
            return Err(SwapError::Validation(format!(
                "maker changed terms: locktime {} min_confirmations {}",
                accept.locktime, accept.min_confirmations
            )));
        }
        self.htlc = Some(SwapHtlc::new(
            &self.hashlock_pubkey,
            &accept.maker_timelock_pubkey,
            &self.payment_hash,
            accept.locktime,
        ));
        self.invoice = Some(accept.invoice.clone());
        Ok(self.htlc.as_ref().expect("just set"))
    }

    /// Pays the maker's hold invoice. The payment stays in-flight (held at
    /// the maker's node) until the taker's on-chain claim reveals `P`.
    pub fn pay_invoice(&self) -> Result<PaymentId, SwapError> {
        let invoice = self
            .invoice
            .as_ref()
            .ok_or(SwapError::NotReady("pay_invoice before on_accept"))?;
        Ok(self
            .ln
            .pay_invoice(invoice, None, Some(self.params.locktime as u32))?)
    }

    /// Verifies the maker's funding: the output pays the recreated HTLC
    /// script with exactly `amount` and has enough confirmations.
    pub fn verify_htlc(
        &self,
        funded: &HtlcFunded,
        funding_output: &TxOut,
        confirmations: u32,
    ) -> Result<(), SwapError> {
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("verify_htlc before on_accept"))?;
        if funded.value != funding_output.value {
            return Err(SwapError::Validation(format!(
                "announced value {} != actual output value {}",
                funded.value, funding_output.value
            )));
        }
        htlc.validate_funding_output(funding_output, self.params.amount)?;
        if confirmations < self.params.min_confirmations {
            return Err(SwapError::Validation(format!(
                "only {confirmations} confirmations, need {}",
                self.params.min_confirmations
            )));
        }
        Ok(())
    }

    /// Builds the signed claim transaction sweeping the HTLC through the
    /// hashlock branch. Broadcasting it publishes the preimage on-chain.
    pub fn claim_tx(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("claim_tx before on_accept"))?;
        htlc.create_hashlock_spend(
            outpoint,
            input_value,
            &self.hashlock_privkey,
            &self.preimage,
            destination,
        )
    }
}

/// The maker role: sells on-chain BTC, learns the preimage from the taker's
/// on-chain claim and settles the held Lightning payment.
pub struct SwapOutMaker {
    ln: Arc<dyn LightningBackend>,
    timelock_pubkey: PublicKey,
    timelock_privkey: SecretKey,
    request: Option<SwapOutRequest>,
    htlc: Option<SwapHtlc>,
}

impl SwapOutMaker {
    /// Creates a maker with a fresh timelock keypair.
    pub fn new(ln: Arc<dyn LightningBackend>) -> Self {
        let (timelock_pubkey, timelock_privkey) = generate_keypair();
        Self {
            ln,
            timelock_pubkey,
            timelock_privkey,
            request: None,
            htlc: None,
        }
    }

    /// The HTLC, available after [`SwapOutMaker::accept`].
    pub fn htlc(&self) -> Option<&SwapHtlc> {
        self.htlc.as_ref()
    }

    /// Accepts a swap request: creates the hold invoice for the taker's hash
    /// (over `amount + maker_fee`) and builds the HTLC from the agreed
    /// parameters. The maker never sees the preimage at this point.
    pub fn accept(&mut self, request: SwapOutRequest) -> Result<SwapOutAccept, SwapError> {
        let invoice = self.ln.create_hold_invoice(
            request.payment_hash,
            super::types::InvoiceParams {
                amount_msat: Some(request.params.invoice_amount().to_sat() * 1000),
                description: "swap-out".to_string(),
                expiry_secs: 3600,
            },
        )?;
        self.htlc = Some(SwapHtlc::new(
            &request.taker_hashlock_pubkey,
            &self.timelock_pubkey,
            &request.payment_hash,
            request.params.locktime,
        ));
        let accept = SwapOutAccept {
            invoice: invoice.invoice,
            payment_hash: request.payment_hash,
            maker_timelock_pubkey: self.timelock_pubkey,
            locktime: request.params.locktime,
            min_confirmations: request.params.min_confirmations,
        };
        self.request = Some(request);
        Ok(accept)
    }

    /// Polls the backend for the taker's held payment. Returns `true` once
    /// the payment is parked at the maker's node — the signal that it is safe
    /// to fund the on-chain HTLC ([`SwapHtlc::address`], value
    /// [`SwapOutParams::amount`]) and announce it via [`HtlcFunded`].
    pub fn try_await_payment(&self) -> Result<bool, SwapError> {
        let request = self
            .request
            .as_ref()
            .ok_or(SwapError::NotReady("try_await_payment before accept"))?;
        while let Some(event) = self.ln.poll_event()? {
            if let LnEvent::PaymentClaimable {
                payment_hash: Some(hash),
                ..
            } = &event
            {
                if *hash == request.payment_hash {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Extracts the preimage from the taker's on-chain claim transaction and
    /// settles the held Lightning payment with it.
    pub fn settle_from_spend(&self, spend_tx: &Transaction) -> Result<Preimage, SwapError> {
        let request = self
            .request
            .as_ref()
            .ok_or(SwapError::NotReady("settle_from_spend before accept"))?;
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("settle_from_spend before accept"))?;
        let preimage = htlc.extract_preimage(spend_tx).ok_or_else(|| {
            SwapError::Validation("transaction does not reveal the HTLC preimage".to_string())
        })?;
        if preimage.payment_hash() != request.payment_hash {
            return Err(SwapError::Validation(
                "revealed preimage does not match the payment hash".to_string(),
            ));
        }
        self.ln.claim_held_payment(&preimage)?;
        Ok(preimage)
    }

    /// Builds the signed refund transaction spending the HTLC through the
    /// timelock branch. Broadcastable only `locktime` blocks after the
    /// funding output confirms; used when the taker never claims.
    pub fn refund_tx(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("refund_tx before accept"))?;
        htlc.create_timelock_spend(outpoint, input_value, &self.timelock_privkey, destination)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lightning::MockLightningBackend;

    fn test_params() -> SwapOutParams {
        SwapOutParams {
            amount: Amount::from_sat(50_000),
            maker_fee: Amount::from_sat(2_000),
            locktime: 10,
            min_confirmations: 1,
        }
    }

    fn handshake() -> (SwapOutTaker, SwapOutMaker) {
        let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());
        let mut taker = SwapOutTaker::new(Arc::clone(&ln), test_params());
        let mut maker = SwapOutMaker::new(ln);
        let accept = maker.accept(taker.make_request()).unwrap();
        taker.on_accept(&accept).unwrap();
        (taker, maker)
    }

    #[test]
    fn invoice_amount_includes_maker_fee() {
        assert_eq!(test_params().invoice_amount(), Amount::from_sat(52_000));
    }

    #[test]
    fn both_roles_build_the_same_htlc() {
        let (taker, maker) = handshake();
        assert_eq!(taker.htlc().unwrap(), maker.htlc().unwrap());
    }

    #[test]
    fn taker_rejects_tampered_accept() {
        let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());
        let mut taker = SwapOutTaker::new(Arc::clone(&ln), test_params());
        let mut maker = SwapOutMaker::new(ln);
        let accept = maker.accept(taker.make_request()).unwrap();

        let mut wrong_hash = accept.clone();
        wrong_hash.payment_hash = Preimage([0x99; 32]).payment_hash();
        assert!(matches!(
            taker.on_accept(&wrong_hash),
            Err(SwapError::Validation(_))
        ));

        let mut wrong_locktime = accept.clone();
        wrong_locktime.locktime += 1;
        assert!(matches!(
            taker.on_accept(&wrong_locktime),
            Err(SwapError::Validation(_))
        ));

        taker.on_accept(&accept).unwrap();
    }

    #[test]
    fn settle_from_spend_learns_and_verifies_preimage() {
        let (taker, maker) = handshake();
        // Taker pays the hold invoice; maker sees the held payment.
        taker.pay_invoice().unwrap();
        assert!(maker.try_await_payment().unwrap());

        let claim = taker
            .claim_tx(
                OutPoint::default(),
                Amount::from_sat(50_000),
                ScriptBuf::new(),
            )
            .unwrap();
        let learned = maker.settle_from_spend(&claim).unwrap();
        assert_eq!(learned, taker.preimage());

        // A refund spend carries no preimage and must be rejected.
        let refund = maker
            .refund_tx(
                OutPoint::default(),
                Amount::from_sat(50_000),
                ScriptBuf::new(),
            )
            .unwrap();
        assert!(matches!(
            maker.settle_from_spend(&refund),
            Err(SwapError::Validation(_))
        ));
    }

    #[test]
    fn verify_htlc_checks_script_value_and_confirmations() {
        let (taker, _maker) = handshake();
        let htlc = taker.htlc().unwrap();
        let good = TxOut {
            value: test_params().amount,
            script_pubkey: htlc.script_pubkey().unwrap(),
        };
        let funded = HtlcFunded {
            outpoint: OutPoint::default(),
            value: test_params().amount,
        };
        taker.verify_htlc(&funded, &good, 1).unwrap();
        assert!(matches!(
            taker.verify_htlc(&funded, &good, 0),
            Err(SwapError::Validation(_))
        ));

        let short = TxOut {
            value: test_params().amount - Amount::from_sat(1),
            script_pubkey: htlc.script_pubkey().unwrap(),
        };
        let short_funded = HtlcFunded {
            outpoint: OutPoint::default(),
            value: short.value,
        };
        assert!(matches!(
            taker.verify_htlc(&short_funded, &short, 1),
            Err(SwapError::Validation(_))
        ));
    }
}
