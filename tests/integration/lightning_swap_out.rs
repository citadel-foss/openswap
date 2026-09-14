//! Integration tests for the Lightning -> Bitcoin reverse submarine swap
//! POC (`openswap::lightning::swap_out`).
//!
//! The Lightning side runs on a single shared `MockLightningBackend` playing
//! both nodes (documented POC simplification: roles filter events by variant
//! and payment hash); the on-chain side runs against a real regtest bitcoind
//! so HTLC spends are validated by actual consensus rules.

use std::{path::PathBuf, sync::Arc};

use bip39::rand;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Transaction, Txid};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};

use openswap::lightning::{
    HtlcFunded, LightningBackend, LnEvent, MockLightningBackend, SwapOutMaker, SwapOutParams,
    SwapOutTaker,
};

use super::test_framework::{generate_blocks, init_bitcoind, send_to_address};

fn setup_bitcoind(test_name: &str) -> (BitcoinD, PathBuf) {
    let temp_dir = std::env::temp_dir()
        .join(format!("coinswap-{}", rand::random::<u64>()))
        .join("ln-swap-out-tests")
        .join(test_name);
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
    let port_zmq = 28332 + rand::random::<u16>() % 20000;
    let zmq_addr = format!("tcp://127.0.0.1:{port_zmq}");
    let bitcoind = init_bitcoind(&temp_dir, zmq_addr);
    (bitcoind, temp_dir)
}

fn test_params() -> SwapOutParams {
    SwapOutParams {
        amount: Amount::from_sat(50_000),
        maker_fee: Amount::from_sat(5_000),
        locktime: 20,
        min_confirmations: 1,
    }
}

/// Funds `spk` with `amount`, mines a block and returns the confirmed
/// funding outpoint and output.
fn fund_htlc(
    bitcoind: &BitcoinD,
    spk: &ScriptBuf,
    amount: Amount,
) -> (Txid, OutPoint, bitcoin::TxOut) {
    let address = bitcoin::Address::from_script(spk, Network::Regtest).unwrap();
    let txid = send_to_address(bitcoind, &address, amount);
    generate_blocks(bitcoind, 1);
    let funding_tx = raw_tx_with_retry(bitcoind, &txid);
    let vout = funding_tx
        .output
        .iter()
        .position(|o| &o.script_pubkey == spk)
        .expect("funding output present");
    let outpoint = OutPoint {
        txid,
        vout: vout as u32,
    };
    (txid, outpoint, funding_tx.output[vout].clone())
}

/// Fetches a transaction by txid, retrying briefly: the asynchronous txindex
/// can lag behind a freshly mined block under parallel test load.
fn raw_tx_with_retry(bitcoind: &BitcoinD, txid: &Txid) -> Transaction {
    for _ in 0..50 {
        if let Ok(tx) = bitcoind.client.get_raw_transaction(txid, None) {
            return tx;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("transaction {} not found after retries", txid);
}

fn confirmations(bitcoind: &BitcoinD, txid: &Txid) -> u32 {
    for _ in 0..50 {
        if let Ok(info) = bitcoind.client.get_raw_transaction_info(txid, None) {
            return info.confirmations.unwrap_or(0);
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    0
}

fn miner_spk(bitcoind: &BitcoinD) -> ScriptBuf {
    bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked()
        .script_pubkey()
}

/// Full happy path: request/accept, taker pays the hold invoice, maker funds
/// on-chain, taker claims through the hashlock (publishing the preimage), and
/// the maker settles the held Lightning payment from the claim witness.
#[test]
fn swap_out_happy_path() {
    let (bitcoind, _tmp) = setup_bitcoind("happy-path");
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
    let (funding_txid, outpoint, funding_output) = fund_htlc(&bitcoind, &spk, params.amount);
    let funded = HtlcFunded {
        outpoint,
        value: funding_output.value,
    };

    // 5. Taker verifies and claims, publishing the preimage on-chain.
    taker
        .verify_htlc(
            &funded,
            &funding_output,
            confirmations(&bitcoind, &funding_txid),
        )
        .unwrap();
    let claim_tx = taker
        .claim_tx(outpoint, funding_output.value, miner_spk(&bitcoind))
        .unwrap();
    let claim_txid = bitcoind.client.send_raw_transaction(&claim_tx).unwrap();
    generate_blocks(&bitcoind, 1);
    assert!(
        confirmations(&bitcoind, &claim_txid) >= 1,
        "taker's hashlock claim must confirm"
    );

    // 6. Maker reads the preimage from the confirmed claim and settles the
    // held Lightning payment.
    let onchain_claim = raw_tx_with_retry(&bitcoind, &claim_txid);
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
#[test]
fn swap_out_refund_path() {
    let (bitcoind, _tmp) = setup_bitcoind("refund-path");
    let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());

    let params = test_params();
    let mut taker = SwapOutTaker::new(ln.clone(), params);
    let mut maker = SwapOutMaker::new(ln);

    let accept = maker.accept(taker.make_request()).unwrap();
    let spk = taker.on_accept(&accept).unwrap().script_pubkey().unwrap();

    taker.pay_invoice().unwrap();
    assert!(maker.try_await_payment().unwrap());

    let (_txid, outpoint, funding_output) = fund_htlc(&bitcoind, &spk, params.amount);

    let refund_tx = maker
        .refund_tx(outpoint, funding_output.value, miner_spk(&bitcoind))
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
    generate_blocks(&bitcoind, params.locktime as u64);
    let refund_txid = bitcoind.client.send_raw_transaction(&refund_tx).unwrap();
    generate_blocks(&bitcoind, 1);
    assert!(
        confirmations(&bitcoind, &refund_txid) >= 1,
        "maker's timelock refund must confirm"
    );

    // The refund reveals nothing the maker could settle with.
    assert!(maker.settle_from_spend(&refund_tx).is_err());
}

/// The maker only accepts a preimage that actually matches the payment hash:
/// a witness carrying 32 bytes that hash to something else is rejected
/// before touching the Lightning backend.
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

    // A spend of a *different* swap's HTLC (different preimage, hence a
    // different redeemscript) must not extract anything.
    let other_taker = SwapOutTaker::new(
        Arc::new(MockLightningBackend::new()) as Arc<dyn LightningBackend>,
        params,
    );
    let mut other_maker =
        SwapOutMaker::new(Arc::new(MockLightningBackend::new()) as Arc<dyn LightningBackend>);
    let other_accept = other_maker.accept(other_taker.make_request()).unwrap();
    let mut other_taker = other_taker;
    other_taker.on_accept(&other_accept).unwrap();
    let foreign_claim = other_taker
        .claim_tx(
            OutPoint::default(),
            Amount::from_sat(50_000),
            ScriptBuf::new(),
        )
        .unwrap();
    assert!(
        maker.settle_from_spend(&foreign_claim).is_err(),
        "a foreign HTLC spend must not settle this swap"
    );
}
