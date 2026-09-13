//! POC of a Bitcoin -> Lightning submarine swap ("swap-in").
//!
//! A *taker* with on-chain BTC buys Lightning balance from a *maker* that has
//! outbound Lightning liquidity:
//!
//! 1. The taker generates a random 32-byte preimage `P`, computes
//!    `H = sha256(P)` and creates a hold invoice for `H` on its own node.
//! 2. The maker receives [`SwapInRequest`] and answers with [`SwapInAccept`]
//!    (its hashlock pubkey plus the echoed locktime parameters).
//! 3. The taker funds a P2WSH output paying to the on-chain HTLC script built
//!    by `create_contract_redeemscript`: hashlock branch spendable by the
//!    maker with `P`, timelock branch refundable by the taker after
//!    `locktime` blocks (CSV).
//! 4. The maker recreates the script from the agreed parameters, verifies the
//!    funding output and pays the hold invoice.
//! 5. The taker claims the held payment by revealing `P` (gaining Lightning
//!    balance); the maker learns `P` from its `PaymentSuccessful` event and
//!    sweeps the on-chain HTLC through the hashlock branch.
//!
//! Atomicity hinges on one preimage satisfying both layers: Lightning locks
//! on `sha256(P)` while the on-chain script locks on
//! `hash160(P) = ripemd160(sha256(P))`, so the maker can only learn `P` by
//! settling the taker's invoice, and `P` is exactly what arms the maker's
//! on-chain claim.
//!
//! This module is a standalone POC: the two roles exchange plain structs
//! in-process, and transaction broadcasting/mining is driven by the caller.
//!
//! The on-chain primitive [`SwapHtlc`] is direction-agnostic and is shared
//! with the reverse swap ([`super::swap_out`], Lightning -> on-chain BTC).

use std::sync::Arc;

use bitcoin::{
    absolute::LockTime,
    hashes::{ripemd160, sha256, Hash},
    secp256k1::{
        rand::{rngs::OsRng, RngCore},
        Message, Secp256k1, SecretKey,
    },
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
    Address, Amount, Network, OutPoint, PublicKey, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};

use crate::{
    protocol::{contract::create_contract_redeemscript, error::ProtocolError, Hash160},
    utill::{calculate_fee_sats, generate_keypair, redeemscript_to_scriptpubkey},
};

use super::{
    backend::LightningBackend,
    error::LightningError,
    types::{InvoiceParams, LnEvent, PaymentId, Preimage},
};

/// Virtual size (vB) assumed for HTLC spend transactions when computing the
/// fixed fee. POC simplification: no feerate estimation.
const SPEND_TX_VSIZE: u64 = 150;

/// Errors produced by the swap-in protocol.
#[derive(Debug)]
pub enum SwapError {
    /// The Lightning backend failed.
    Lightning(LightningError),
    /// A protocol-level primitive (script/sighash construction) failed.
    Protocol(ProtocolError),
    /// A message or transaction failed validation against the agreed terms.
    Validation(String),
    /// The role was driven out of order (e.g. claiming before accepting).
    NotReady(&'static str),
}

impl std::fmt::Display for SwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for SwapError {}

impl From<LightningError> for SwapError {
    fn from(value: LightningError) -> Self {
        Self::Lightning(value)
    }
}

impl From<ProtocolError> for SwapError {
    fn from(value: ProtocolError) -> Self {
        Self::Protocol(value)
    }
}

/// Economic and timing terms of a swap-in.
///
/// # Timelock safety (documented, not enforced — POC)
///
/// `locktime` must exceed the maximum CLTV delta of the Lightning payment
/// path plus a safety margin, otherwise the maker could be forced to settle
/// the invoice while the taker's on-chain refund is already spendable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapInParams {
    /// Lightning amount the taker receives (the hold-invoice amount).
    pub amount: Amount,
    /// Fee retained by the maker on top of `amount` in the on-chain HTLC.
    pub maker_fee: Amount,
    /// Relative locktime (blocks, CSV) of the taker's refund branch.
    pub locktime: u16,
    /// Confirmations the maker requires on the HTLC funding output before
    /// paying the invoice.
    pub min_confirmations: u32,
}

impl SwapInParams {
    /// Amount the taker must lock in the on-chain HTLC output:
    /// `amount + maker_fee`.
    pub fn funding_amount(&self) -> Amount {
        self.amount + self.maker_fee
    }
}

/// Taker -> Maker: initial swap proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapInRequest {
    /// BOLT11 hold invoice (payment hash `H = sha256(P)`) on the taker node.
    pub invoice: String,
    /// The invoice payment hash `H`.
    pub payment_hash: sha256::Hash,
    /// Proposed swap terms.
    pub params: SwapInParams,
    /// Taker pubkey for the timelock (refund) branch of the HTLC script.
    pub taker_timelock_pubkey: PublicKey,
}

/// Maker -> Taker: acceptance of a [`SwapInRequest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwapInAccept {
    /// Maker pubkey for the hashlock (claim) branch of the HTLC script.
    pub maker_hashlock_pubkey: PublicKey,
    /// Agreed refund locktime (echo of the requested terms).
    pub locktime: u16,
    /// Agreed confirmation requirement (echo of the requested terms).
    pub min_confirmations: u32,
}

/// Taker -> Maker: location of the confirmed on-chain HTLC funding output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HtlcFunded {
    /// Outpoint of the P2WSH HTLC output.
    pub outpoint: OutPoint,
    /// Value of the HTLC output.
    pub value: Amount,
}

/// Derives the on-chain hashlock value `hash160(P)` from the Lightning
/// payment hash `H = sha256(P)`, using `hash160(P) = ripemd160(sha256(P))`.
///
/// This lets the maker build the HTLC script knowing only `H`.
pub fn hashvalue_from_payment_hash(payment_hash: &sha256::Hash) -> Hash160 {
    Hash160::from_byte_array(ripemd160::Hash::hash(payment_hash.as_byte_array()).to_byte_array())
}

/// The on-chain side of a submarine swap (either direction): a P2WSH HTLC
/// reusing the coinswap contract script (`create_contract_redeemscript`).
///
/// The hashlock branch pays whoever ends up owning the coins (maker for
/// swap-in, taker for swap-out); the timelock branch refunds whoever funded
/// the output.
///
/// Pure data + transaction construction; no I/O. Broadcasting and mining are
/// the caller's responsibility.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SwapHtlc {
    redeemscript: ScriptBuf,
    locktime: u16,
}

impl SwapHtlc {
    /// Builds the HTLC for the given branch pubkeys, Lightning payment hash
    /// and refund locktime.
    pub fn new(
        hashlock_pubkey: &PublicKey,
        timelock_pubkey: &PublicKey,
        payment_hash: &sha256::Hash,
        locktime: u16,
    ) -> Self {
        let hashvalue = hashvalue_from_payment_hash(payment_hash);
        let redeemscript =
            create_contract_redeemscript(hashlock_pubkey, timelock_pubkey, &hashvalue, &locktime);
        Self {
            redeemscript,
            locktime,
        }
    }

    /// The HTLC witness script.
    pub fn redeemscript(&self) -> &ScriptBuf {
        &self.redeemscript
    }

    /// The refund locktime (blocks, CSV).
    pub fn locktime(&self) -> u16 {
        self.locktime
    }

    /// The P2WSH scriptPubKey of the HTLC.
    pub fn script_pubkey(&self) -> Result<ScriptBuf, SwapError> {
        Ok(redeemscript_to_scriptpubkey(&self.redeemscript)?)
    }

    /// The P2WSH address of the HTLC on `network`.
    pub fn address(&self, network: Network) -> Result<Address, SwapError> {
        let spk = self.script_pubkey()?;
        Address::from_script(&spk, network)
            .map_err(|e| SwapError::Validation(format!("address from script: {e:?}")))
    }

    /// Verifies that `output` pays the expected script and exactly
    /// `expected_value` (recreate-and-compare, like `is_contract_out_valid`).
    pub fn validate_funding_output(
        &self,
        output: &TxOut,
        expected_value: Amount,
    ) -> Result<(), SwapError> {
        if output.script_pubkey != self.script_pubkey()? {
            return Err(SwapError::Validation(
                "funding output does not pay the agreed HTLC script".to_string(),
            ));
        }
        if output.value != expected_value {
            return Err(SwapError::Validation(format!(
                "funding output value {} != expected {expected_value}",
                output.value
            )));
        }
        Ok(())
    }

    /// Builds and signs the maker's hashlock spend, revealing `preimage`.
    ///
    /// Witness: `[sig, preimage (32B), redeemscript]`, input sequence
    /// [`Sequence::ZERO`] (satisfies the `0 OP_CSV` of the hashlock branch).
    pub fn create_hashlock_spend(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        hashlock_privkey: &SecretKey,
        preimage: &Preimage,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let mut tx = self.build_spend(outpoint, input_value, Sequence::ZERO, destination)?;
        let sig = self.sign_input(&tx, input_value, hashlock_privkey)?;
        let witness = &mut tx.input[0].witness;
        witness.push(sig.to_vec());
        witness.push(preimage.0);
        witness.push(self.redeemscript.to_bytes());
        Ok(tx)
    }

    /// Builds and signs the taker's timelock refund spend.
    ///
    /// Witness: `[sig, <empty>, redeemscript]`, input sequence
    /// `Sequence::from_height(locktime)` (satisfies the `locktime OP_CSV` of
    /// the timelock branch). Valid only `locktime` blocks after the funding
    /// output confirms.
    pub fn create_timelock_spend(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        timelock_privkey: &SecretKey,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let mut tx = self.build_spend(
            outpoint,
            input_value,
            Sequence::from_height(self.locktime),
            destination,
        )?;
        let sig = self.sign_input(&tx, input_value, timelock_privkey)?;
        let witness = &mut tx.input[0].witness;
        witness.push(sig.to_vec());
        witness.push(Vec::new());
        witness.push(self.redeemscript.to_bytes());
        Ok(tx)
    }

    /// Extracts the swap preimage from a transaction spending this HTLC
    /// through the hashlock branch, or `None` if no input reveals one.
    ///
    /// This is how the swap-out maker learns `P`: the taker's on-chain claim
    /// necessarily publishes the preimage as the second witness element.
    pub fn extract_preimage(&self, spend_tx: &Transaction) -> Option<Preimage> {
        spend_tx.input.iter().find_map(|input| {
            let witness: Vec<_> = input.witness.iter().collect();
            match witness.as_slice() {
                [_sig, preimage, redeemscript]
                    if *redeemscript == self.redeemscript.as_bytes() && preimage.len() == 32 =>
                {
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(preimage);
                    Some(Preimage(bytes))
                }
                _ => None,
            }
        })
    }

    /// Builds the unsigned single-input single-output spend skeleton with a
    /// fixed fee of `calculate_fee_sats(150)`.
    fn build_spend(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        sequence: Sequence,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let fee = Amount::from_sat(calculate_fee_sats(SPEND_TX_VSIZE));
        let output_value = input_value.checked_sub(fee).ok_or_else(|| {
            SwapError::Validation(format!("fee {fee} exceeds input value {input_value}"))
        })?;
        Ok(Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: output_value,
                script_pubkey: destination,
            }],
        })
    }

    /// Produces the P2WSH ECDSA signature for input 0 of `tx`.
    fn sign_input(
        &self,
        tx: &Transaction,
        input_value: Amount,
        privkey: &SecretKey,
    ) -> Result<bitcoin::ecdsa::Signature, SwapError> {
        let secp = Secp256k1::new();
        let sighash = SighashCache::new(tx)
            .p2wsh_signature_hash(0, &self.redeemscript, input_value, EcdsaSighashType::All)
            .map_err(|e| SwapError::Validation(format!("sighash error: {e:?}")))?;
        let message = Message::from_digest_slice(&sighash[..])
            .map_err(|e| SwapError::Validation(format!("message creation error: {e:?}")))?;
        Ok(bitcoin::ecdsa::Signature {
            signature: secp.sign_ecdsa_low_r(&message, privkey),
            sighash_type: EcdsaSighashType::All,
        })
    }
}

/// The taker role: holds the preimage, receives Lightning balance.
///
/// POC event handling: [`SwapInTaker::try_claim`] drains the backend event
/// queue and discards non-matching events, which is fine for a dedicated (or
/// demo-shared) backend but would lose events in production.
pub struct SwapInTaker {
    ln: Arc<dyn LightningBackend>,
    params: SwapInParams,
    preimage: Preimage,
    payment_hash: sha256::Hash,
    timelock_pubkey: PublicKey,
    timelock_privkey: SecretKey,
    htlc: Option<SwapHtlc>,
}

impl SwapInTaker {
    /// Creates a taker with a fresh random preimage and timelock keypair.
    pub fn new(ln: Arc<dyn LightningBackend>, params: SwapInParams) -> Self {
        let mut preimage_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut preimage_bytes);
        let preimage = Preimage(preimage_bytes);
        let payment_hash = preimage.payment_hash();
        let (timelock_pubkey, timelock_privkey) = generate_keypair();
        Self {
            ln,
            params,
            preimage,
            payment_hash,
            timelock_pubkey,
            timelock_privkey,
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

    /// The HTLC, available after [`SwapInTaker::on_accept`].
    pub fn htlc(&self) -> Option<&SwapHtlc> {
        self.htlc.as_ref()
    }

    /// Creates the hold invoice on the taker's node and builds the swap
    /// request for the maker.
    pub fn make_request(&self) -> Result<SwapInRequest, SwapError> {
        let invoice = self.ln.create_hold_invoice(
            self.payment_hash,
            InvoiceParams {
                amount_msat: Some(self.params.amount.to_sat() * 1000),
                description: "swap-in".to_string(),
                expiry_secs: 3600,
            },
        )?;
        Ok(SwapInRequest {
            invoice: invoice.invoice,
            payment_hash: self.payment_hash,
            params: self.params,
            taker_timelock_pubkey: self.timelock_pubkey,
        })
    }

    /// Validates the maker's acceptance and builds the on-chain HTLC. The
    /// caller funds [`SwapHtlc::address`] with
    /// [`SwapInParams::funding_amount`] and reports it via [`HtlcFunded`].
    pub fn on_accept(&mut self, accept: &SwapInAccept) -> Result<&SwapHtlc, SwapError> {
        if accept.locktime != self.params.locktime
            || accept.min_confirmations != self.params.min_confirmations
        {
            return Err(SwapError::Validation(format!(
                "maker changed terms: locktime {} min_confirmations {}",
                accept.locktime, accept.min_confirmations
            )));
        }
        self.htlc = Some(SwapHtlc::new(
            &accept.maker_hashlock_pubkey,
            &self.timelock_pubkey,
            &self.payment_hash,
            accept.locktime,
        ));
        Ok(self.htlc.as_ref().expect("just set"))
    }

    /// Polls the backend for the incoming held payment and claims it with the
    /// preimage. Returns `true` once claimed, `false` if the payment has not
    /// arrived yet.
    pub fn try_claim(&self) -> Result<bool, SwapError> {
        while let Some(event) = self.ln.poll_event()? {
            if let LnEvent::PaymentClaimable {
                payment_hash: Some(hash),
                ..
            } = &event
            {
                if *hash == self.payment_hash {
                    self.ln.claim_held_payment(&self.preimage)?;
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    /// Builds the signed refund transaction spending the HTLC through the
    /// timelock branch. Broadcastable only `locktime` blocks after the
    /// funding output confirms.
    pub fn refund_tx(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("refund_tx before on_accept"))?;
        htlc.create_timelock_spend(outpoint, input_value, &self.timelock_privkey, destination)
    }
}

/// The maker role: pays the taker's hold invoice, learns the preimage from
/// settlement and sweeps the on-chain HTLC.
pub struct SwapInMaker {
    ln: Arc<dyn LightningBackend>,
    hashlock_pubkey: PublicKey,
    hashlock_privkey: SecretKey,
    request: Option<SwapInRequest>,
    htlc: Option<SwapHtlc>,
    preimage: Option<Preimage>,
}

impl SwapInMaker {
    /// Creates a maker with a fresh hashlock keypair.
    pub fn new(ln: Arc<dyn LightningBackend>) -> Self {
        let (hashlock_pubkey, hashlock_privkey) = generate_keypair();
        Self {
            ln,
            hashlock_pubkey,
            hashlock_privkey,
            request: None,
            htlc: None,
            preimage: None,
        }
    }

    /// The HTLC, available after [`SwapInMaker::accept`].
    pub fn htlc(&self) -> Option<&SwapHtlc> {
        self.htlc.as_ref()
    }

    /// Accepts a swap request, building the HTLC from the agreed parameters
    /// (the maker never sees the preimage, only the payment hash).
    pub fn accept(&mut self, request: SwapInRequest) -> Result<SwapInAccept, SwapError> {
        let accept = SwapInAccept {
            maker_hashlock_pubkey: self.hashlock_pubkey,
            locktime: request.params.locktime,
            min_confirmations: request.params.min_confirmations,
        };
        self.htlc = Some(SwapHtlc::new(
            &self.hashlock_pubkey,
            &request.taker_timelock_pubkey,
            &request.payment_hash,
            request.params.locktime,
        ));
        self.request = Some(request);
        Ok(accept)
    }

    /// Verifies the taker's funding: the output pays the recreated HTLC
    /// script with exactly `amount + maker_fee` and has enough confirmations.
    pub fn verify_htlc(
        &self,
        funded: &HtlcFunded,
        funding_output: &TxOut,
        confirmations: u32,
    ) -> Result<(), SwapError> {
        let request = self
            .request
            .as_ref()
            .ok_or(SwapError::NotReady("verify_htlc before accept"))?;
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("verify_htlc before accept"))?;
        if funded.value != funding_output.value {
            return Err(SwapError::Validation(format!(
                "announced value {} != actual output value {}",
                funded.value, funding_output.value
            )));
        }
        htlc.validate_funding_output(funding_output, request.params.funding_amount())?;
        if confirmations < request.params.min_confirmations {
            return Err(SwapError::Validation(format!(
                "only {confirmations} confirmations, need {}",
                request.params.min_confirmations
            )));
        }
        Ok(())
    }

    /// Pays the taker's hold invoice. Call only after
    /// [`SwapInMaker::verify_htlc`] succeeds.
    pub fn pay_invoice(&self) -> Result<PaymentId, SwapError> {
        let request = self
            .request
            .as_ref()
            .ok_or(SwapError::NotReady("pay_invoice before accept"))?;
        Ok(self.ln.pay_invoice(&request.invoice, None)?)
    }

    /// Polls the backend for the `PaymentSuccessful` settlement event and
    /// extracts the preimage revealed by the taker's claim. Returns the
    /// preimage once learned, `None` while the payment is still pending.
    pub fn try_learn_preimage(&mut self) -> Result<Option<Preimage>, SwapError> {
        let request = self
            .request
            .as_ref()
            .ok_or(SwapError::NotReady("try_learn_preimage before accept"))?;
        let payment_hash = request.payment_hash;
        while let Some(event) = self.ln.poll_event()? {
            if let LnEvent::PaymentSuccessful {
                payment_hash: Some(hash),
                preimage: Some(preimage),
                ..
            } = &event
            {
                if *hash == payment_hash {
                    if preimage.payment_hash() != payment_hash {
                        return Err(SwapError::Validation(
                            "backend returned preimage not matching payment hash".to_string(),
                        ));
                    }
                    self.preimage = Some(*preimage);
                    return Ok(Some(*preimage));
                }
            }
        }
        Ok(None)
    }

    /// Builds the signed claim transaction sweeping the HTLC through the
    /// hashlock branch with the learned preimage.
    pub fn claim_tx(
        &self,
        outpoint: OutPoint,
        input_value: Amount,
        destination: ScriptBuf,
    ) -> Result<Transaction, SwapError> {
        let htlc = self
            .htlc
            .as_ref()
            .ok_or(SwapError::NotReady("claim_tx before accept"))?;
        let preimage = self
            .preimage
            .as_ref()
            .ok_or(SwapError::NotReady("claim_tx before preimage is learned"))?;
        htlc.create_hashlock_spend(
            outpoint,
            input_value,
            &self.hashlock_privkey,
            preimage,
            destination,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::contract::{
        read_contract_locktime, read_hashlock_pubkey_from_contract, read_hashvalue_from_contract,
    };

    fn test_htlc() -> (SwapHtlc, Preimage, PublicKey, PublicKey) {
        let preimage = Preimage([0xAB; 32]);
        let (hashlock_pubkey, _) = generate_keypair();
        let (timelock_pubkey, _) = generate_keypair();
        let htlc = SwapHtlc::new(
            &hashlock_pubkey,
            &timelock_pubkey,
            &preimage.payment_hash(),
            20,
        );
        (htlc, preimage, hashlock_pubkey, timelock_pubkey)
    }

    #[test]
    fn preimage_links_lightning_and_onchain_hashlocks() {
        let preimage = Preimage([0x11; 32]);
        // hash160(P) == ripemd160(sha256(P)) == ripemd160(payment_hash).
        assert_eq!(
            Hash160::hash(&preimage.0),
            hashvalue_from_payment_hash(&preimage.payment_hash()),
            "one preimage must satisfy both the LN and on-chain hashlocks"
        );

        let (htlc, p, ..) = test_htlc();
        assert_eq!(
            read_hashvalue_from_contract(htlc.redeemscript()).unwrap(),
            Hash160::hash(&p.0),
            "script must commit to hash160 of the LN preimage"
        );
    }

    #[test]
    fn script_parameters_round_trip() {
        let (htlc, _, hashlock_pubkey, _) = test_htlc();
        assert_eq!(read_contract_locktime(htlc.redeemscript()).unwrap(), 20);
        assert_eq!(
            read_hashlock_pubkey_from_contract(htlc.redeemscript()).unwrap(),
            hashlock_pubkey
        );
    }

    #[test]
    fn validate_funding_output_checks_script_and_value() {
        let (htlc, ..) = test_htlc();
        let value = Amount::from_sat(100_000);
        let good = TxOut {
            value,
            script_pubkey: htlc.script_pubkey().unwrap(),
        };
        htlc.validate_funding_output(&good, value).unwrap();

        let wrong_value = htlc.validate_funding_output(&good, Amount::from_sat(99_999));
        assert!(matches!(wrong_value, Err(SwapError::Validation(_))));

        let (other_pk, _) = generate_keypair();
        let other_htlc = SwapHtlc::new(
            &other_pk,
            &other_pk,
            &Preimage([0xCD; 32]).payment_hash(),
            20,
        );
        let wrong_script = TxOut {
            value,
            script_pubkey: other_htlc.script_pubkey().unwrap(),
        };
        assert!(matches!(
            htlc.validate_funding_output(&wrong_script, value),
            Err(SwapError::Validation(_))
        ));
    }

    #[test]
    fn hashlock_spend_witness_and_sequence() {
        let (htlc, preimage, ..) = test_htlc();
        let (_, privkey) = generate_keypair();
        let outpoint = OutPoint::default();
        let tx = htlc
            .create_hashlock_spend(
                outpoint,
                Amount::from_sat(100_000),
                &privkey,
                &preimage,
                ScriptBuf::new(),
            )
            .unwrap();
        assert_eq!(tx.input[0].sequence, Sequence::ZERO);
        let witness: Vec<_> = tx.input[0].witness.iter().collect();
        assert_eq!(witness.len(), 3);
        assert_eq!(witness[1], preimage.0, "witness[1] must be the preimage");
        assert_eq!(witness[2], htlc.redeemscript().as_bytes());
        assert!(tx.output[0].value < Amount::from_sat(100_000), "fee taken");
    }

    #[test]
    fn timelock_spend_witness_and_sequence() {
        let (htlc, ..) = test_htlc();
        let (_, privkey) = generate_keypair();
        let tx = htlc
            .create_timelock_spend(
                OutPoint::default(),
                Amount::from_sat(100_000),
                &privkey,
                ScriptBuf::new(),
            )
            .unwrap();
        assert_eq!(tx.input[0].sequence, Sequence::from_height(20));
        let witness: Vec<_> = tx.input[0].witness.iter().collect();
        assert_eq!(witness.len(), 3);
        assert!(
            witness[1].is_empty(),
            "timelock branch requires an empty preimage slot"
        );
        assert_eq!(witness[2], htlc.redeemscript().as_bytes());
    }

    #[test]
    fn extract_preimage_from_hashlock_spend() {
        let (htlc, preimage, ..) = test_htlc();
        let (_, privkey) = generate_keypair();
        let claim = htlc
            .create_hashlock_spend(
                OutPoint::default(),
                Amount::from_sat(100_000),
                &privkey,
                &preimage,
                ScriptBuf::new(),
            )
            .unwrap();
        assert_eq!(htlc.extract_preimage(&claim), Some(preimage));

        // A timelock (refund) spend reveals nothing.
        let refund = htlc
            .create_timelock_spend(
                OutPoint::default(),
                Amount::from_sat(100_000),
                &privkey,
                ScriptBuf::new(),
            )
            .unwrap();
        assert_eq!(htlc.extract_preimage(&refund), None);

        // A spend of a *different* HTLC does not match.
        let (other_pk, _) = generate_keypair();
        let other = SwapHtlc::new(
            &other_pk,
            &other_pk,
            &Preimage([0xEE; 32]).payment_hash(),
            20,
        );
        assert_eq!(other.extract_preimage(&claim), None);
    }

    #[test]
    fn spend_fails_when_fee_exceeds_input() {
        let (htlc, preimage, ..) = test_htlc();
        let (_, privkey) = generate_keypair();
        let result = htlc.create_hashlock_spend(
            OutPoint::default(),
            Amount::from_sat(10),
            &privkey,
            &preimage,
            ScriptBuf::new(),
        );
        assert!(matches!(result, Err(SwapError::Validation(_))));
    }
}
