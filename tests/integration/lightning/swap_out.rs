//! Integration tests for the Lightning -> Bitcoin reverse submarine swap
//! POC (`openswap::lightning::swap_out`).
//!
//! The Lightning side runs on a single shared `MockLightningBackend` playing
//! both nodes (documented POC simplification: roles filter events by variant
//! and payment hash); the on-chain side runs against a real regtest bitcoind
//! so HTLC spends are validated by actual consensus rules.

use std::sync::Arc;

use bitcoin::{Amount, OutPoint, ScriptBuf, Witness};
use bitcoind::bitcoincore_rpc::RpcApi;

use openswap::lightning::{
    HtlcFunded, LightningBackend, LnEvent, MockLightningBackend, PaymentOutcome, SwapError,
    SwapOutMaker, SwapOutParams, SwapOutTaker,
};

use crate::test_framework::*;

fn test_params() -> SwapOutParams {
    SwapOutParams {
        amount: Amount::from_sat(50_000),
        maker_fee: Amount::from_sat(5_000),
        locktime: 20,
        min_confirmations: 1,
    }
}

/// Full happy path: request/accept, taker pays the hold invoice, maker funds
/// on-chain, taker claims through the hashlock (publishing the preimage), and
/// the maker settles the held Lightning payment from the claim witness.
#[world_test(backend = BitcoindBackend)]
fn swap_out_happy_path(node: &mut Node) {
    let bitcoind = node.bitcoind();
    // One shared mock backend plays both Lightning nodes (POC).
    let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());

    let params = test_params();
    let mut taker = SwapOutTaker::new(ln.clone(), params);
    let mut maker = SwapOutMaker::new(ln.clone());

    // 1-2. Request, accept (hold invoice for the taker's hash), HTLC on both
    // sides.
    let accept = maker.accept(taker.make_request()).unwrap();
    let htlc = taker.on_accept(&accept).unwrap();
    assert_eq!(
        htlc,
        maker.htlc().unwrap(),
        "both sides must derive the identical HTLC script"
    );
    let spk = htlc.script_pubkey().unwrap();

    // 3. Taker pays; the payment parks at the maker's node.
    taker.pay_invoice().unwrap();
    assert!(
        maker.try_await_payment().unwrap(),
        "maker must observe the held payment"
    );

    // 4. Maker funds the on-chain HTLC with exactly `amount`.
    let (funding_txid, outpoint, funding_output) = fund_script(bitcoind, &spk, params.amount);
    let funded = HtlcFunded {
        outpoint,
        value: funding_output.value,
    };

    // 5. Taker verifies and claims, publishing the preimage on-chain.
    taker
        .verify_htlc(
            &funded,
            &funding_output,
            confirmations(bitcoind, &funding_txid),
        )
        .unwrap();
    let claim_tx = taker
        .claim_tx(outpoint, funding_output.value, miner_spk(bitcoind))
        .unwrap();
    let claim_txid = bitcoind.client.send_raw_transaction(&claim_tx).unwrap();
    generate_blocks(bitcoind, 1);
    assert!(
        confirmations(bitcoind, &claim_txid) >= 1,
        "taker's hashlock claim must confirm"
    );

    // 6. Maker reads the preimage from the confirmed claim and settles the
    // held Lightning payment.
    let onchain_claim = raw_tx_with_retry(bitcoind, &claim_txid);
    let learned = maker.settle_from_spend(&onchain_claim).unwrap();
    assert_eq!(learned, taker.preimage());

    // Settlement releases the preimage back to the payer (taker) side.
    let mut settled = false;
    while let Some(event) = ln.poll_event().unwrap() {
        if let LnEvent::PaymentSuccessful {
            payment_hash: Some(hash),
            preimage: Some(released),
            ..
        } = event
        {
            assert_eq!(hash, taker.payment_hash());
            assert_eq!(released, taker.preimage());
            settled = true;
        }
    }
    assert!(settled, "settlement must emit PaymentSuccessful");
}

/// Refund path: the taker pays but never claims on-chain, so the maker
/// recovers the funds through the timelock branch — but only after
/// `locktime` blocks. The preimage is never revealed, so the maker cannot
/// settle the held payment (it would fail back at the LN HTLC expiry on a
/// real node).
#[world_test(backend = BitcoindBackend)]
fn swap_out_refund_path(node: &mut Node) {
    let bitcoind = node.bitcoind();
    let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());

    let params = test_params();
    let mut taker = SwapOutTaker::new(ln.clone(), params);
    let mut maker = SwapOutMaker::new(ln.clone());

    let accept = maker.accept(taker.make_request()).unwrap();
    let spk = taker.on_accept(&accept).unwrap().script_pubkey().unwrap();

    taker.pay_invoice().unwrap();
    assert!(maker.try_await_payment().unwrap());

    let (_txid, outpoint, funding_output) = fund_script(bitcoind, &spk, params.amount);

    let refund_tx = maker
        .refund_tx(outpoint, funding_output.value, miner_spk(bitcoind))
        .unwrap();

    // Too early: CSV not yet satisfied.
    let early = bitcoind.client.send_raw_transaction(&refund_tx);
    let err = format!("{:?}", early.expect_err("refund must be premature"));
    assert!(
        err.contains("non-BIP68-final"),
        "expected non-BIP68-final rejection, got: {}",
        err
    );

    // After `locktime` blocks the refund is valid.
    generate_blocks(bitcoind, params.locktime as u64);
    let refund_txid = bitcoind.client.send_raw_transaction(&refund_tx).unwrap();
    generate_blocks(bitcoind, 1);
    assert!(
        confirmations(bitcoind, &refund_txid) >= 1,
        "maker's timelock refund must confirm"
    );

    // The refund reveals nothing the maker could settle with, and is
    // rejected for exactly that reason.
    let err = maker
        .settle_from_spend(&refund_tx)
        .expect_err("a refund spend must not settle");
    assert!(
        matches!(&err, SwapError::Validation(msg)
            if msg == "transaction does not reveal the HTLC preimage"),
        "expected the no-preimage rejection, got: {:?}",
        err
    );

    // The rejection left the held payment untouched: still pending, neither
    // settled nor failed back.
    let outcome = ln.payment_outcome(taker.payment_hash()).unwrap();
    assert!(
        matches!(outcome, PaymentOutcome::Pending),
        "the held payment must stay pending after the refund, got: {:?}",
        outcome
    );
}

/// The maker only accepts a preimage that actually matches the payment hash:
/// a claim of this swap's HTLC whose witness carries 32 bytes that hash to
/// something else is rejected before touching the Lightning backend.
#[test]
fn swap_out_settle_rejects_foreign_spend() {
    let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());

    let params = test_params();
    let mut taker = SwapOutTaker::new(ln.clone(), params);
    let mut maker = SwapOutMaker::new(ln);
    let accept = maker.accept(taker.make_request()).unwrap();
    taker.on_accept(&accept).unwrap();
    taker.pay_invoice().unwrap();
    assert!(maker.try_await_payment().unwrap());

    // The real claim, with its preimage swapped for a different 32 bytes:
    // the redeemscript still matches this swap, so only the payment-hash
    // guard can reject it.
    let claim = taker
        .claim_tx(
            OutPoint::default(),
            Amount::from_sat(50_000),
            ScriptBuf::new(),
        )
        .unwrap();
    let mut forged_claim = claim.clone();
    let mut witness: Vec<Vec<u8>> = forged_claim.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    assert_eq!(
        witness.len(),
        3,
        "hashlock witness is [sig, preimage, script]"
    );
    assert_eq!(witness[1], taker.preimage().0.to_vec());
    witness[1] = [0xAB; 32].to_vec();
    forged_claim.input[0].witness = Witness::from_slice(&witness);

    let err = maker
        .settle_from_spend(&forged_claim)
        .expect_err("a preimage for another hash must not settle this swap");
    assert!(
        matches!(&err, SwapError::Validation(msg)
            if msg == "revealed preimage does not match the payment hash"),
        "expected the payment-hash mismatch rejection, got: {:?}",
        err
    );

    // The held payment is still claimable with the genuine preimage.
    assert_eq!(maker.settle_from_spend(&claim).unwrap(), taker.preimage());
}
