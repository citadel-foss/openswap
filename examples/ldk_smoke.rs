//! Smoke test for [`openswap::lightning::LdkServerBackend`] against a live
//! LDK Server instance on regtest.
//!
//! Usage:
//! ```bash
//! cargo run --example ldk_smoke --features lightning -- <ldk-server-data-dir>
//! ```
//!
//! The data dir is the ldk-server `storage.disk.dir_path`; the example reads
//! `tls.crt` and `regtest/api_key` from it. Optionally set `SMOKE_SEND_ADDR`
//! to also exercise `send_onchain` (requires a funded node).

use std::{env, path::PathBuf, time::Duration};

use openswap::lightning::{
    InvoiceParams, LdkServerBackend, LightningBackend, LightningConfig, Preimage,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(
        env::args()
            .nth(1)
            .expect("usage: ldk_smoke <ldk-server-data-dir>"),
    );

    // The api_key file holds 32 raw bytes; the server derives the actual key
    // as their lower-hex encoding.
    let api_key = {
        use bitcoin::hashes::hex::DisplayHex;
        std::fs::read(data_dir.join("regtest/api_key"))?.to_lower_hex_string()
    };
    let config = LightningConfig {
        base_url: "127.0.0.1:3536".to_string(),
        api_key,
        tls_cert_path: Some(data_dir.join("tls.crt")),
        timeout_secs: 10,
    };

    println!("== connecting to {} ==", config.base_url);
    let backend = LdkServerBackend::new(&config)?;

    // 1. Node info
    let info = backend.node_info()?;
    println!(
        "node_info: node_id={} height={} hash={}",
        info.node_id, info.block_height, info.block_hash
    );

    // 2. Balances
    let balances = backend.balances()?;
    println!("balances: {balances:?}");

    // 3. Channels (expected empty on a fresh node)
    let channels = backend.list_channels()?;
    println!("list_channels: {} channel(s)", channels.len());
    for ch in &channels {
        println!("  {ch:?}");
    }

    // 4. On-chain deposit address
    let address = backend.new_onchain_address()?;
    println!("new_onchain_address: {address}");

    // 5. Regular BOLT11 invoice
    let invoice = backend.create_invoice(InvoiceParams {
        amount_msat: Some(25_000_000), // 25k sats
        description: "coinswap smoke test".to_string(),
        expiry_secs: 600,
    })?;
    println!(
        "create_invoice: hash={} invoice={}...",
        invoice.payment_hash,
        &invoice.invoice[..60.min(invoice.invoice.len())]
    );

    // 6. Hold invoice for an externally supplied hash (the Track 2/3 primitive)
    let preimage = Preimage([0x42; 32]);
    let payment_hash = preimage.payment_hash();
    let hold = backend.create_hold_invoice(
        payment_hash,
        InvoiceParams {
            amount_msat: Some(50_000_000),
            description: "coinswap hold invoice".to_string(),
            expiry_secs: 600,
        },
    )?;
    assert_eq!(
        hold.payment_hash, payment_hash,
        "server must commit to our externally supplied hash"
    );
    println!(
        "create_hold_invoice: hash={} invoice={}...",
        hold.payment_hash,
        &hold.invoice[..60.min(hold.invoice.len())]
    );

    // 7. Cancel the held payment (nothing was paid; exercises Bolt11FailForHash)
    match backend.fail_held_payment(payment_hash) {
        Ok(()) => println!("fail_held_payment: ok"),
        Err(e) => println!("fail_held_payment: {e} (kind={})", e.kind()),
    }

    // 8. Optional: on-chain send if funded and target address provided
    if let Ok(addr) = env::var("SMOKE_SEND_ADDR") {
        let addr = addr
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()?
            .assume_checked();
        let txid = backend.send_onchain(&addr, Some(bitcoin::Amount::from_sat(10_000)), None)?;
        println!("send_onchain: txid={txid}");
    } else {
        println!("send_onchain: skipped (set SMOKE_SEND_ADDR to test)");
    }

    // 9. Drain any events the subscription stream picked up
    std::thread::sleep(Duration::from_secs(2));
    let mut count = 0;
    while let Some(event) = backend.poll_event()? {
        println!("event: {event:?}");
        count += 1;
    }
    println!("poll_event: drained {count} event(s)");

    println!("== smoke test passed ==");
    Ok(())
}
