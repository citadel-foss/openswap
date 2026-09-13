//! Live demo of the Lightning -> Bitcoin reverse submarine swap POC
//! ([`openswap::lightning::swap_out`]) against two LDK Server instances on
//! regtest: node1 plays the maker (sells on-chain BTC for Lightning
//! balance), node2 plays the taker (spends Lightning balance for on-chain
//! BTC).
//!
//! Flow: taker requests a swap-out, maker creates a hold invoice for the
//! taker's payment hash, taker pays it (the payment parks at the maker's
//! node), maker funds the on-chain HTLC from the miner wallet, taker claims
//! it through the hashlock branch (publishing the preimage on-chain), maker
//! extracts the preimage from the claim transaction and settles the held
//! payment.
//!
//! Usage:
//! ```bash
//! cargo run --example ln_swap_out --features lightning -- \
//!     <data-dir-1> <grpc-addr-1> <data-dir-2> <grpc-addr-2>
//! ```
//!
//! Expects a regtest bitcoind at 127.0.0.1:18443 (user/pass `ldktest`) with a
//! loaded wallet named `miner`, and an existing usable channel between the
//! two nodes with enough taker-side balance — run the `ln_swap_in` example
//! first to set that up.
//!
//! Timing note: with stock ldk-node the held payment is failed back a few
//! blocks after it arrives (see the `swap_out` module docs), so the demo
//! mines only the minimum between payment and settlement.

use std::{env, path::Path, sync::Arc, time::Duration};

use bitcoin::{Amount, Network, OutPoint};
use openswap::{
    bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi},
    lightning::{
        HtlcFunded, LdkServerBackend, LightningBackend, LightningConfig, LnEvent, SwapOutMaker,
        SwapOutParams, SwapOutTaker,
    },
};

const POLL: Duration = Duration::from_millis(500);

fn connect(data_dir: &Path, grpc_addr: &str) -> LdkServerBackend {
    use bitcoin::hashes::hex::DisplayHex;
    let api_key = std::fs::read(data_dir.join("regtest/api_key"))
        .expect("api_key file")
        .to_lower_hex_string();
    LdkServerBackend::new(&LightningConfig {
        base_url: grpc_addr.to_string(),
        api_key,
        tls_cert_path: Some(data_dir.join("tls.crt")),
        timeout_secs: 10,
    })
    .expect("backend connects")
}

/// Retries `step` until it reports completion or `timeout` elapses.
fn wait_for(what: &str, timeout: Duration, mut step: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + timeout;
    while !step() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for: {}",
            what
        );
        std::thread::sleep(POLL);
    }
    println!("ok: {what}");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let [dir1, grpc1, dir2, grpc2] = match &args[1..] {
        [a, b, c, d] => [a, b, c, d],
        _ => panic!("usage: ln_swap_out <data-dir-1> <grpc-addr-1> <data-dir-2> <grpc-addr-2>"),
    };

    let rpc = Client::new(
        "http://127.0.0.1:18443/wallet/miner",
        Auth::UserPass("ldktest".to_string(), "ldktest".to_string()),
    )
    .expect("bitcoind rpc");
    let mine_addr = rpc
        .get_new_address(None, None)
        .expect("mine address")
        .assume_checked();
    let mine = |n: u64| {
        rpc.generate_to_address(n, &mine_addr).expect("mine");
    };

    // node1 = maker, node2 = taker.
    let maker_node: Arc<dyn LightningBackend> = Arc::new(connect(Path::new(dir1), grpc1));
    let taker_node: Arc<dyn LightningBackend> = Arc::new(connect(Path::new(dir2), grpc2));
    let info1 = maker_node.node_info().expect("node1 info");
    let info2 = taker_node.node_info().expect("node2 info");
    println!("maker (node1): {}", info1.node_id);
    println!("taker (node2): {}", info2.node_id);

    let params = SwapOutParams {
        amount: Amount::from_sat(50_000),
        maker_fee: Amount::from_sat(2_000),
        locktime: 20,
        min_confirmations: 1,
    };

    // ---- 1. Preconditions: usable channel and taker-side liquidity ----
    let has_channel = taker_node
        .list_channels()
        .expect("list_channels")
        .iter()
        .any(|c| c.counterparty == info1.node_id && c.is_usable);
    assert!(
        has_channel,
        "no usable channel between taker and maker; run the ln_swap_in example first"
    );
    let taker_ln_before = taker_node.balances().expect("balances").total_lightning;
    let maker_ln_before = maker_node.balances().expect("balances").total_lightning;
    assert!(
        taker_ln_before >= params.invoice_amount(),
        "taker lightning balance {} < invoice amount {}; run ln_swap_in first",
        taker_ln_before,
        params.invoice_amount()
    );

    // ---- 2. Swap-out message exchange ----
    let mut taker = SwapOutTaker::new(taker_node.clone(), params);
    let mut maker = SwapOutMaker::new(maker_node.clone());

    let accept = maker.accept(taker.make_request()).expect("accept");
    println!("maker hold invoice: {}", accept.invoice);
    let htlc = taker.on_accept(&accept).expect("on_accept");
    let htlc_address = htlc.address(Network::Regtest).expect("htlc address");
    let htlc_spk = htlc.script_pubkey().expect("htlc spk");
    println!("on-chain HTLC address: {htlc_address}");

    // ---- 3. Taker pays; the payment parks at the maker's node ----
    let payment_id = taker.pay_invoice().expect("pay_invoice");
    println!("taker paying hold invoice: payment_id={payment_id}");
    wait_for("maker sees held payment", Duration::from_secs(60), || {
        maker.try_await_payment().expect("try_await_payment")
    });

    // ---- 4. Maker funds the on-chain HTLC with exactly `amount` ----
    let funding_txid = rpc
        .send_to_address(
            &htlc_address,
            params.amount,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("fund htlc");
    mine(params.min_confirmations as u64);
    let funding_tx = rpc
        .get_transaction(&funding_txid, None)
        .expect("get_transaction")
        .transaction()
        .expect("decode funding tx");
    let vout = funding_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == htlc_spk)
        .expect("htlc output present");
    let funding_output = funding_tx.output[vout].clone();
    let outpoint = OutPoint {
        txid: funding_txid,
        vout: vout as u32,
    };
    println!("HTLC funded: {outpoint} value={}", funding_output.value);

    // ---- 5. Taker verifies and claims, revealing the preimage on-chain ----
    let confirmations = rpc
        .get_transaction(&funding_txid, None)
        .expect("get_transaction")
        .info
        .confirmations
        .max(0) as u32;
    taker
        .verify_htlc(
            &HtlcFunded {
                outpoint,
                value: funding_output.value,
            },
            &funding_output,
            confirmations,
        )
        .expect("verify_htlc");
    let claim_spk = rpc
        .get_new_address(None, None)
        .expect("claim address")
        .assume_checked()
        .script_pubkey();
    let claim_tx = taker
        .claim_tx(outpoint, funding_output.value, claim_spk)
        .expect("claim_tx");
    let claim_txid = rpc
        .send_raw_transaction(&claim_tx)
        .expect("broadcast claim");
    mine(1);
    println!("taker on-chain claim confirmed: {claim_txid}");

    // ---- 6. Maker extracts the preimage from the chain and settles ----
    let onchain_claim = rpc
        .get_raw_transaction(&claim_txid, None)
        .expect("fetch claim tx");
    let preimage = maker
        .settle_from_spend(&onchain_claim)
        .expect("settle_from_spend");
    println!("maker extracted preimage from chain: {}", preimage.to_hex());

    // ---- 7. Taker's payment completes with the same preimage ----
    wait_for("taker payment settles", Duration::from_secs(60), || {
        while let Some(event) = taker_node.poll_event().expect("poll_event") {
            if let LnEvent::PaymentSuccessful {
                payment_hash: Some(hash),
                ..
            } = event
            {
                if hash == taker.payment_hash() {
                    return true;
                }
            }
        }
        false
    });

    // ---- 8. Lightning balances moved by the invoice amount ----
    let taker_ln_after = taker_node.balances().expect("balances").total_lightning;
    let maker_ln_after = maker_node.balances().expect("balances").total_lightning;
    println!("taker lightning balance: {taker_ln_before} -> {taker_ln_after}");
    println!("maker lightning balance: {maker_ln_before} -> {maker_ln_after}");
    assert_eq!(
        maker_ln_after.to_sat() - maker_ln_before.to_sat(),
        params.invoice_amount().to_sat(),
        "maker must gain amount + fee on Lightning"
    );

    println!("== swap-out complete: Lightning balance swapped for on-chain BTC ==");
}
