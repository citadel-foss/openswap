//! Integration tests for the Bitcoin -> Lightning submarine swap-in POC
//! (`openswap::lightning::swap`).
//!
//! The Lightning side runs on a single shared `MockLightningBackend` playing
//! both nodes (documented POC simplification: roles filter events by variant
//! and payment hash); the on-chain side runs against a real regtest bitcoind
//! so HTLC spends are validated by actual consensus rules.

use std::{path::PathBuf, sync::Arc};

use bip39::rand;
use bitcoin::{
    secp256k1::{Secp256k1, SecretKey},
    Amount, Network, OutPoint, PublicKey, ScriptBuf, Transaction, Txid,
};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};

use openswap::lightning::{
    HtlcFunded, InvoiceParams, LightningBackend, LightningError, MockLightningBackend, Preimage,
    SwapHtlc, SwapInMaker, SwapInParams, SwapInTaker,
};

use super::test_framework::{generate_blocks, init_bitcoind, send_to_address};

fn setup_bitcoind(test_name: &str) -> (BitcoinD, PathBuf) {
    let temp_dir = std::env::temp_dir()
        .join(format!("coinswap-{}", rand::random::<u64>()))
        .join("ln-swap-tests")
        .join(test_name);
    if temp_dir.exists() {
        std::fs::remove_dir_all(&temp_dir).unwrap();
    }
    let port_zmq = 28332 + rand::random::<u16>() % 20000;
    let zmq_addr = format!("tcp://127.0.0.1:{port_zmq}");
    let bitcoind = init_bitcoind(&temp_dir, zmq_addr);
    (bitcoind, temp_dir)
}

fn test_params() -> SwapInParams {
    SwapInParams {
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

/// Full happy path: request/accept, on-chain funding, invoice payment, taker
/// claim, preimage learning and maker on-chain sweep through the hashlock.
#[test]
fn swap_in_happy_path() {
    let (bitcoind, _tmp) = setup_bitcoind("happy-path");
    // One shared mock backend plays both Lightning nodes (POC).
    let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());

    let params = test_params();
    let mut taker = SwapInTaker::new(ln.clone(), params);
    let mut maker = SwapInMaker::new(ln.clone());

    // 1-3. Request, accept, HTLC construction on both sides.
    let request = taker.make_request().unwrap();
    let accept = maker.accept(request).unwrap();
    let htlc = taker.on_accept(&accept).unwrap();
    assert_eq!(
        htlc,
        maker.htlc().unwrap(),
        "both sides must derive the identical HTLC script"
    );
    let spk = htlc.script_pubkey().unwrap();

    // 4-5. Taker funds the HTLC on-chain.
    let (funding_txid, outpoint, funding_output) =
        fund_htlc(&bitcoind, &spk, params.funding_amount());
    let funded = HtlcFunded {
        outpoint,
        value: funding_output.value,
    };

    // 6-7. Maker verifies the funding and pays the hold invoice.
    maker
        .verify_htlc(
            &funded,
            &funding_output,
            confirmations(&bitcoind, &funding_txid),
        )
        .unwrap();
    maker.pay_invoice().unwrap();

    // 8. Taker claims the held payment, revealing the preimage on Lightning.
    assert!(taker.try_claim().unwrap(), "held payment must be claimable");

    // 9. Maker learns the preimage from the settlement event.
    let preimage = maker
        .try_learn_preimage()
        .unwrap()
        .expect("settlement must reveal the preimage");
    assert_eq!(preimage, taker.preimage());

    // 10. Maker sweeps the on-chain HTLC through the hashlock branch.
    let claim_tx = maker
        .claim_tx(outpoint, funding_output.value, miner_spk(&bitcoind))
        .unwrap();
    let witness: Vec<_> = claim_tx.input[0].witness.iter().collect();
    assert_eq!(
        witness[1], preimage.0,
        "witness[1] must be the 32-byte Lightning preimage"
    );
    let claim_txid = bitcoind.client.send_raw_transaction(&claim_tx).unwrap();
    generate_blocks(&bitcoind, 1);
    assert!(
        confirmations(&bitcoind, &claim_txid) >= 1,
        "maker's hashlock claim must confirm"
    );
}

/// Refund path: the maker never pays, so the taker recovers the on-chain
/// funds through the timelock branch — but only after `locktime` blocks.
#[test]
fn swap_in_refund_path() {
    let (bitcoind, _tmp) = setup_bitcoind("refund-path");
    let ln: Arc<dyn LightningBackend> = Arc::new(MockLightningBackend::new());

    let params = test_params();
    let mut taker = SwapInTaker::new(ln.clone(), params);
    let mut maker = SwapInMaker::new(ln);

    let request = taker.make_request().unwrap();
    let accept = maker.accept(request).unwrap();
    let spk = taker.on_accept(&accept).unwrap().script_pubkey().unwrap();

    let (_txid, outpoint, funding_output) = fund_htlc(&bitcoind, &spk, params.funding_amount());

    // Maker never pays the invoice; nothing is claimable.
    assert!(!taker.try_claim().unwrap());

    let refund_tx = taker
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
        "taker's timelock refund must confirm"
    );
}

/// A tampered preimage fails both layers: the Lightning claim is rejected by
/// the backend and the on-chain hashlock spend is rejected by consensus.
#[test]
fn swap_in_wrong_preimage_fails_both_layers() {
    let (bitcoind, _tmp) = setup_bitcoind("wrong-preimage");
    let mock = MockLightningBackend::new();

    let preimage = Preimage([0x55; 32]);
    let mut wrong_bytes = preimage.0;
    wrong_bytes[0] ^= 0x01;
    let wrong_preimage = Preimage(wrong_bytes);
    let payment_hash = preimage.payment_hash();

    // Lightning layer: claiming a held payment with a tampered preimage fails.
    mock.create_hold_invoice(payment_hash, InvoiceParams::default())
        .unwrap();
    mock.simulate_htlc_arrival(payment_hash, 50_000_000);
    assert!(matches!(
        mock.claim_held_payment(&wrong_preimage),
        Err(LightningError::PaymentNotFound)
    ));

    // On-chain layer: a hashlock spend armed with the wrong preimage is
    // rejected by script validation even with a valid signature.
    let secp = Secp256k1::new();
    let hashlock_sk = SecretKey::from_slice(&[0x01; 32]).unwrap();
    let timelock_sk = SecretKey::from_slice(&[0x02; 32]).unwrap();
    let hashlock_pk = PublicKey::new(hashlock_sk.public_key(&secp));
    let timelock_pk = PublicKey::new(timelock_sk.public_key(&secp));
    let htlc = SwapHtlc::new(&hashlock_pk, &timelock_pk, &payment_hash, 20);
    let spk = htlc.script_pubkey().unwrap();

    let (_txid, outpoint, funding_output) = fund_htlc(&bitcoind, &spk, Amount::from_sat(55_000));

    let bad_claim = htlc
        .create_hashlock_spend(
            outpoint,
            funding_output.value,
            &hashlock_sk,
            &wrong_preimage,
            miner_spk(&bitcoind),
        )
        .unwrap();
    assert!(
        bitcoind.client.send_raw_transaction(&bad_claim).is_err(),
        "consensus must reject a hashlock spend with a wrong preimage"
    );

    // Sanity: the correct preimage makes the identical spend valid.
    let good_claim = htlc
        .create_hashlock_spend(
            outpoint,
            funding_output.value,
            &hashlock_sk,
            &preimage,
            miner_spk(&bitcoind),
        )
        .unwrap();
    bitcoind.client.send_raw_transaction(&good_claim).unwrap();
    generate_blocks(&bitcoind, 1);
}
