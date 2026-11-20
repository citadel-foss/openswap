//! `Wallet::sweep_to_address` after the broadcast: what the caller gets back
//! when the wallet cannot refresh itself.

use bitcoind::bitcoincore_rpc::RpcApi;
use std::{fs, os::unix::fs::PermissionsExt};

use crate::test_framework::*;

/// The transaction is on the network once `send_tx` returns, so a refresh that
/// then fails (here: the wallet file cannot be written) must not turn a sent
/// sweep into an error and hide its txid from the caller.
#[world_test(
    makers = 0,
    takers = [Normal],
    setup = [fund_taker_default(3)],
    cases = [
        sweep_survives_a_failed_refresh_bitcoind(backend = BitcoindBackend),
        sweep_survives_a_failed_refresh_electrum(backend = ElectrumBackend),
    ],
)]
fn run_sweep_survives_a_failed_refresh(world: &mut World) {
    // The wallet file lives in `<taker dir>/wallets`. A read-only directory
    // makes the atomic save fail after the broadcast.
    let wallets = world.temp_dir().join("taker1").join("wallets");
    let writable = fs::metadata(&wallets).unwrap().permissions();
    let mut read_only = writable.clone();
    read_only.set_mode(0o555);
    fs::set_permissions(&wallets, read_only).unwrap();
    if fs::File::create(wallets.join("probe")).is_ok() {
        fs::set_permissions(&wallets, writable).unwrap();
        let _ = fs::remove_file(wallets.join("probe"));
        // Root ignores directory modes. Passing here would hide a regression.
        panic!("directory modes are not enforced; run this test as an unprivileged user");
    }

    let destination = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let result = world
        .taker()
        .inner()
        .get_wallet()
        .write()
        .unwrap()
        .sweep_to_address(destination.to_string(), Some(2.0));
    fs::set_permissions(&wallets, writable).unwrap();

    let sweep = result.expect("a sent sweep is reported even when the refresh fails");
    let tx = world
        .bitcoind()
        .client
        .get_raw_transaction(&sweep.txid, None)
        .expect("the reported txid is the broadcast transaction");
    assert_eq!(tx.compute_txid(), sweep.txid);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value, sweep.amount);
}
