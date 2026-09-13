//! Live demo of the Bitcoin -> Lightning submarine swap-in POC
//! ([`openswap::lightning::swap`]) against two LDK Server instances on
//! regtest: node1 plays the maker (needs outbound Lightning liquidity),
//! node2 plays the taker (receives Lightning balance for on-chain BTC).
//!
//! Flow: open channel maker -> taker, run the swap-in message exchange, fund
//! the on-chain HTLC from the miner wallet, maker pays the hold invoice,
//! taker claims (revealing the preimage), maker sweeps the HTLC on-chain.
//!
//! Usage:
//! ```bash
//! cargo run --example ln_swap_in --features lightning -- \
//!     <data-dir-1> <grpc-addr-1> <data-dir-2> <grpc-addr-2> <node2-ln-addr>
//! ```
//!
//! Expects a regtest bitcoind at 127.0.0.1:18443 (user/pass `ldktest`) with a
//! loaded wallet named `miner`, and node 1 funded on-chain.

use std::{env, path::Path, sync::Arc, time::Duration};

use bitcoin::{Amount, Network, OutPoint};
use openswap::{
    bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi},
    lightning::{
        ChannelState, HtlcFunded, LdkServerBackend, LightningBackend, LightningConfig,
        OpenChannelRequest, SwapInMaker, SwapInParams, SwapInTaker,
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
    let [dir1, grpc1, dir2, grpc2, ln_addr2] = match &args[1..] {
        [a, b, c, d, e] => [a, b, c, d, e],
        _ => panic!(
            "usage: ln_swap_in <data-dir-1> <grpc-addr-1> <data-dir-2> <grpc-addr-2> <node2-ln-addr>"
        ),
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

    // ---- 1. Give the maker outbound liquidity towards the taker ----
    let channel_id = maker_node
        .open_channel(OpenChannelRequest {
            node_pubkey: info2.node_id,
            address: ln_addr2.to_string(),
            channel_amount: Amount::from_sat(1_000_000),
            push_to_counterparty_msat: None,
            announce_channel: false,
        })
        .expect("open_channel");
    println!("open_channel: user_channel_id={channel_id}");
    wait_for("channel ready on maker", Duration::from_secs(120), || {
        mine(1);
        maker_node
            .list_channels()
            .expect("list_channels")
            .iter()
            .any(|c| {
                c.user_channel_id == channel_id && c.state == ChannelState::Ready && c.is_usable
            })
    });
    wait_for("channel usable on taker", Duration::from_secs(120), || {
        mine(1);
        taker_node
            .list_channels()
            .expect("list_channels")
            .iter()
            .any(|c| c.counterparty == info1.node_id && c.is_usable)
    });

    let taker_ln_before = taker_node.balances().expect("balances").total_lightning;

    // ---- 2. Swap-in message exchange ----
    let params = SwapInParams {
        amount: Amount::from_sat(100_000),
        maker_fee: Amount::from_sat(5_000),
        locktime: 144,
        min_confirmations: 1,
    };
    let mut taker = SwapInTaker::new(taker_node.clone(), params);
    let mut maker = SwapInMaker::new(maker_node.clone());

    let request = taker.make_request().expect("make_request");
    println!("taker hold invoice: {}", request.invoice);
    let accept = maker.accept(request).expect("accept");
    let htlc = taker.on_accept(&accept).expect("on_accept");
    let htlc_address = htlc.address(Network::Regtest).expect("htlc address");
    let htlc_spk = htlc.script_pubkey().expect("htlc spk");
    println!("on-chain HTLC address: {htlc_address}");

    // ---- 3. Fund the HTLC from the miner wallet and confirm ----
    let funding_txid = rpc
        .send_to_address(
            &htlc_address,
            params.funding_amount(),
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

    // ---- 4. Maker verifies the funding and pays the hold invoice ----
    let confirmations = rpc
        .get_transaction(&funding_txid, None)
        .expect("get_transaction")
        .info
        .confirmations
        .max(0) as u32;
    maker
        .verify_htlc(
            &HtlcFunded {
                outpoint,
                value: funding_output.value,
            },
            &funding_output,
            confirmations,
        )
        .expect("verify_htlc");
    let payment_id = maker.pay_invoice().expect("pay_invoice");
    println!("maker paying hold invoice: payment_id={payment_id}");

    // ---- 5. Taker claims the held payment (reveals the preimage on LN) ----
    wait_for("taker claims held payment", Duration::from_secs(60), || {
        taker.try_claim().expect("try_claim")
    });

    // ---- 6. Maker learns the preimage from settlement ----
    let mut learned = None;
    wait_for("maker learns preimage", Duration::from_secs(60), || {
        learned = maker.try_learn_preimage().expect("try_learn_preimage");
        learned.is_some()
    });
    let preimage = learned.expect("preimage");
    println!("maker learned preimage: {}", preimage.to_hex());

    // ---- 7. Maker sweeps the on-chain HTLC through the hashlock branch ----
    let sweep_spk = rpc
        .get_new_address(None, None)
        .expect("sweep address")
        .assume_checked()
        .script_pubkey();
    let claim_tx = maker
        .claim_tx(outpoint, funding_output.value, sweep_spk)
        .expect("claim_tx");
    let claim_txid = rpc
        .send_raw_transaction(&claim_tx)
        .expect("broadcast claim");
    mine(1);
    println!("maker on-chain claim confirmed: {claim_txid}");

    // ---- 8. Taker's Lightning balance grew by the swap amount ----
    let taker_ln_after = taker_node.balances().expect("balances").total_lightning;
    println!("taker lightning balance: {taker_ln_before} -> {taker_ln_after}");
    assert_eq!(
        taker_ln_after.to_sat() - taker_ln_before.to_sat(),
        params.amount.to_sat(),
        "taker must gain the swap amount on Lightning"
    );

    println!("== swap-in complete: on-chain BTC swapped for Lightning balance ==");
}
