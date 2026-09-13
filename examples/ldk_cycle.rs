//! Full channel-lifecycle test for [`openswap::lightning::LdkServerBackend`]
//! against two live LDK Server instances on regtest:
//!
//! open channel -> pay invoice -> hold invoice + external-preimage claim ->
//! cooperative close, verifying events and balances at each step.
//!
//! Usage:
//! ```bash
//! cargo run --example ldk_cycle --features lightning -- \
//!     <data-dir-1> <grpc-addr-1> <data-dir-2> <grpc-addr-2> <node2-ln-addr>
//! ```
//!
//! Expects a regtest bitcoind at 127.0.0.1:18443 (user/pass `ldktest`) with a
//! loaded wallet named `miner`, and node 1 funded on-chain.

use std::{env, path::Path, time::Duration};

use openswap::{
    bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi},
    lightning::{
        ChannelState, InvoiceParams, LdkServerBackend, LightningBackend, LightningConfig, LnEvent,
        OpenChannelRequest, Preimage,
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

/// Drains events until one matches `pred` or `timeout` elapses. Non-matching
/// events are printed and discarded.
fn wait_event(
    label: &str,
    backend: &dyn LightningBackend,
    timeout: Duration,
    pred: impl Fn(&LnEvent) -> bool,
) -> LnEvent {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        while let Some(event) = backend.poll_event().expect("poll_event") {
            if pred(&event) {
                println!("[{label}] event: {event:?}");
                return event;
            }
            println!("[{label}] (other event): {event:?}");
        }
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for event on {}",
            label
        );
        std::thread::sleep(POLL);
    }
}

/// Waits until `check` passes, mining a block every few polls so any broadcast
/// transaction (funding/closing) keeps confirming while we wait.
fn wait_until_mining(
    what: &str,
    timeout: Duration,
    mine: impl Fn(u64),
    mut check: impl FnMut() -> bool,
) {
    let deadline = std::time::Instant::now() + timeout;
    let mut polls = 0u32;
    while !check() {
        assert!(
            std::time::Instant::now() < deadline,
            "timed out waiting for: {}",
            what
        );
        std::thread::sleep(POLL);
        polls += 1;
        if polls.is_multiple_of(4) {
            mine(1);
        }
    }
    println!("ok: {what}");
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let [dir1, grpc1, dir2, grpc2, ln_addr2] = match &args[1..] {
        [a, b, c, d, e] => [a, b, c, d, e],
        _ => panic!(
            "usage: ldk_cycle <data-dir-1> <grpc-addr-1> <data-dir-2> <grpc-addr-2> <node2-ln-addr>"
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

    let node1 = connect(Path::new(dir1), grpc1);
    let node2 = connect(Path::new(dir2), grpc2);
    let info1 = node1.node_info().expect("node1 info");
    let info2 = node2.node_info().expect("node2 info");
    println!("node1: {}", info1.node_id);
    println!("node2: {}", info2.node_id);

    let initial_onchain_1 = node1.balances().expect("balances").spendable_onchain;
    println!("node1 spendable on-chain: {initial_onchain_1}");
    assert!(
        initial_onchain_1.to_sat() > 1_100_000,
        "node1 must be funded"
    );

    // ---- 1. Open a 1M-sat unannounced channel node1 -> node2 ----
    let channel_id = node1
        .open_channel(OpenChannelRequest {
            node_pubkey: info2.node_id,
            address: ln_addr2.to_string(),
            channel_amount: bitcoin::Amount::from_sat(1_000_000),
            push_to_counterparty_msat: None,
            announce_channel: false,
        })
        .expect("open_channel");
    println!("open_channel: user_channel_id={channel_id}");

    wait_until_mining(
        "channel ready+usable on node1",
        Duration::from_secs(120),
        mine,
        || {
            node1
                .list_channels()
                .expect("list_channels")
                .iter()
                .any(|c| {
                    c.user_channel_id == channel_id && c.state == ChannelState::Ready && c.is_usable
                })
        },
    );
    wait_until_mining(
        "channel visible+usable on node2",
        Duration::from_secs(120),
        mine,
        || {
            node2
                .list_channels()
                .expect("list_channels")
                .iter()
                .any(|c| c.counterparty == info1.node_id && c.is_usable)
        },
    );
    for ch in node1.list_channels().expect("list_channels") {
        println!(
            "node1 channel: value={} outbound={}msat inbound={}msat state={:?}",
            ch.value, ch.outbound_capacity_msat, ch.inbound_capacity_msat, ch.state
        );
    }

    // ---- 2. Regular invoice payment node1 -> node2 (50k sats) ----
    let ln2_before = node2.balances().expect("balances").total_lightning;
    let invoice = node2
        .create_invoice(InvoiceParams {
            amount_msat: Some(50_000_000),
            description: "cycle regular".to_string(),
            expiry_secs: 600,
        })
        .expect("create_invoice");
    let payment_id = node1
        .pay_invoice(&invoice.invoice, None)
        .expect("pay_invoice");
    println!("pay_invoice: payment_id={payment_id}");

    let success = wait_event("node1", &node1, Duration::from_secs(30), |e| {
        matches!(e, LnEvent::PaymentSuccessful { payment_hash, .. }
            if *payment_hash == Some(invoice.payment_hash))
    });
    if let LnEvent::PaymentSuccessful {
        preimage: Some(preimage),
        ..
    } = &success
    {
        assert_eq!(
            preimage.payment_hash(),
            invoice.payment_hash,
            "released preimage must hash to the invoice payment hash"
        );
        println!("preimage verified: sha256(preimage) == payment_hash");
    }
    wait_event("node2", &node2, Duration::from_secs(30), |e| {
        matches!(e, LnEvent::PaymentReceived { payment_hash, .. }
            if *payment_hash == Some(invoice.payment_hash))
    });

    // ---- 3. Hold invoice with an externally supplied preimage (25k sats) ----
    // The example plays the "taker" role: it knows P; node2 (the "maker") only
    // learns H and cannot settle until claim_held_payment(P).
    // Unique per run: nodes reject a payment hash they have already seen.
    let preimage = {
        let mut bytes = [0x77u8; 32];
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        bytes[..16].copy_from_slice(&nanos.to_le_bytes());
        Preimage(bytes)
    };
    let payment_hash = preimage.payment_hash();
    let hold = node2
        .create_hold_invoice(
            payment_hash,
            InvoiceParams {
                amount_msat: Some(25_000_000),
                description: "cycle hold".to_string(),
                expiry_secs: 600,
            },
        )
        .expect("create_hold_invoice");
    let hold_payment_id = node1.pay_invoice(&hold.invoice, None).expect("pay hold");
    println!("pay hold invoice: payment_id={hold_payment_id}");

    wait_event("node2", &node2, Duration::from_secs(30), |e| {
        matches!(e, LnEvent::PaymentClaimable { payment_hash: h, .. }
            if *h == Some(payment_hash))
    });
    println!("HTLC held by node2; claiming with the preimage..");
    node2.claim_held_payment(&preimage).expect("claim");

    let hold_success = wait_event("node1", &node1, Duration::from_secs(30), |e| {
        matches!(e, LnEvent::PaymentSuccessful { payment_hash: h, .. }
            if *h == Some(payment_hash))
    });
    if let LnEvent::PaymentSuccessful {
        preimage: Some(p), ..
    } = &hold_success
    {
        assert_eq!(*p, preimage, "payer must learn the exact preimage");
        println!("payer learned preimage {} via settlement", p.to_hex());
    }
    wait_event("node2", &node2, Duration::from_secs(30), |e| {
        matches!(e, LnEvent::PaymentReceived { payment_hash: h, .. }
            if *h == Some(payment_hash))
    });

    // ---- 4. Balances reflect both payments ----
    let ln2 = node2.balances().expect("balances").total_lightning;
    println!("node2 lightning balance: {ln2} (before: {ln2_before})");
    assert_eq!(
        ln2.to_sat() - ln2_before.to_sat(),
        75_000,
        "node2 must have received 50k + 25k sats"
    );

    // ---- 5. Cooperative close ----
    node1
        .close_channel(&channel_id, &info2.node_id, false)
        .expect("close_channel");
    println!("close_channel: requested cooperative close");

    wait_until_mining(
        "channel gone on node1",
        Duration::from_secs(120),
        mine,
        || {
            node1
                .list_channels()
                .expect("list_channels")
                .iter()
                .all(|c| c.user_channel_id != channel_id)
        },
    );

    // Sweep of the close output back into node wallets takes a few blocks.
    mine(6);
    std::thread::sleep(Duration::from_secs(5));
    let b1 = node1.balances().expect("balances");
    let b2 = node2.balances().expect("balances");
    println!("final node1 balances: {b1:?}");
    println!("final node2 balances: {b2:?}");

    println!("== full channel cycle passed ==");
}
