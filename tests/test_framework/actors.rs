//! Maker and taker lifecycle, funding and balance helpers.

use bitcoin::Amount;
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use log::info;
use openswap::{
    maker::{start_server, MakerServer},
    taker::Taker,
    utill::NO_SHUTDOWN,
    wallet::AddressType,
};

use super::procs::bitcoind::{generate_blocks, send_to_address};

use super::wait::POLL;

/// Wait for all makers to complete setup, with a timeout.
///
/// Panics if any maker's `is_setup_complete` flag doesn't become true within `timeout_secs`.
#[allow(dead_code)]
pub fn wait_for_makers_setup(makers: &[Arc<MakerServer>], timeout_secs: u64) {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    for (i, maker) in makers.iter().enumerate() {
        if !maker.is_setup_complete.load(Relaxed) {
            log::info!("Waiting for maker {} setup completion", i);
        }
        while !maker.is_setup_complete.load(Relaxed) {
            if start.elapsed() > timeout {
                panic!(
                    "Maker {} did not complete setup within {} seconds",
                    i, timeout_secs
                );
            }
            thread::sleep(POLL);
        }
    }
}

/// Spawns every maker server on its own thread, in maker order.
#[allow(dead_code)]
pub fn spawn_makers(makers: &[Arc<MakerServer>]) -> Vec<JoinHandle<()>> {
    makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>()
}

/// Spawns all makers, waits for their setup, then mines one block.
#[allow(dead_code)]
pub fn spawn_ready_makers_and_mine(
    makers: &[Arc<MakerServer>],
    bitcoind: &bitcoind::BitcoinD,
) -> Vec<JoinHandle<()>> {
    let maker_threads = spawn_makers(makers);
    wait_for_makers_setup(makers, 120);
    generate_blocks(bitcoind, 1);
    maker_threads
}

/// Stops every maker server and joins its thread, in maker order.
#[allow(dead_code)]
pub fn shutdown_makers(makers: &[Arc<MakerServer>], maker_threads: Vec<JoinHandle<()>>) {
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
}

/// Syncs every maker's wallet against the backend and saves it.
#[allow(dead_code)]
pub fn sync_maker_wallets(makers: &[Arc<MakerServer>]) {
    for maker in makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }
}

/// Fund taker and verify balance
#[allow(dead_code)]
pub fn fund_taker(
    taker: &Taker,
    bitcoind: &bitcoind::BitcoinD,
    utxo_count: u32,
    utxo_value: Amount,
    address_type: AddressType,
) -> Amount {
    log::info!("Funding Taker...");

    let mut wallet = taker.get_wallet().write().unwrap();
    let prev_balances = wallet.get_balances().unwrap();

    // Fund with UTXOs
    for _ in 0..utxo_count {
        let addr = wallet.get_next_external_address(address_type).unwrap();
        send_to_address(bitcoind, &addr, utxo_value);
    }
    drop(wallet);

    generate_blocks(bitcoind, 1);

    // Poll sync until the wallet observes the expected balance. With a Bitcoin Core backend
    // the first iteration succeeds immediately; with an Electrum backend the indexer needs a
    // moment to pick up the new block.
    let expected_regular = prev_balances.regular + utxo_value * utxo_count.into();
    let balances = wait_for_balance(taker.get_wallet(), expected_regular, 30);
    assert_eq!(balances.regular, expected_regular);

    info!(
        "Taker funded successfully. Regular: {}, Spendable: {}",
        balances.regular, balances.spendable
    );

    balances.spendable
}

/// Fund the taker with `utxo_count` 0.05 BTC P2TR UTXOs.
#[allow(dead_code)]
pub fn fund_taker_default(taker: &Taker, bitcoind: &bitcoind::BitcoinD, utxo_count: u32) -> Amount {
    fund_taker(
        taker,
        bitcoind,
        utxo_count,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    )
}

/// Poll a wallet, calling `sync_and_save`, until its `regular` balance reaches `expected_regular`
/// or `timeout_secs` elapses. Returns the last observed balances either way.
fn wait_for_balance(
    wallet: &std::sync::Arc<std::sync::RwLock<openswap::wallet::Wallet>>,
    expected_regular: Amount,
    timeout_secs: u64,
) -> openswap::wallet::Balances {
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut last;
    loop {
        {
            let mut w = wallet.write().unwrap();
            w.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
            last = w.get_balances().unwrap();
        }
        if last.regular >= expected_regular || Instant::now() >= deadline {
            return last;
        }
        thread::sleep(Duration::from_millis(500));
    }
}

/// Fund makers and verify their balances
#[allow(dead_code)]
pub fn fund_makers(
    makers: &[Arc<MakerServer>],
    bitcoind: &bitcoind::BitcoinD,
    utxo_count: u32,
    utxo_value: Amount,
    address_type: AddressType,
) -> Vec<Amount> {
    log::info!("Funding Makers...");

    let mut spendable_balances = Vec::new();

    for maker in makers {
        let prev_regular = maker.wallet.read().unwrap().get_balances().unwrap().regular;

        // Send funds with the wallet locked just long enough to derive each address.
        for _ in 0..utxo_count {
            let mut wallet = maker.wallet.write().unwrap();
            let addr = wallet.get_next_external_address(address_type).unwrap();
            drop(wallet);
            send_to_address(bitcoind, &addr, utxo_value);
        }

        generate_blocks(bitcoind, 1);
        // Wait for the funding delta on top of whatever the wallet already
        // held, not an absolute target.
        let expected_regular = prev_regular + utxo_value * utxo_count.into();
        let balances = wait_for_balance(&maker.wallet, expected_regular, 30);

        assert!(
            balances.regular >= expected_regular,
            "Maker regular balance {} should be >= expected {}",
            balances.regular,
            expected_regular
        );

        info!(
            "Maker funded successfully. Regular: {}, Fidelity: {}",
            balances.regular, balances.fidelity
        );

        spendable_balances.push(balances.spendable);
    }

    spendable_balances
}

/// Fund makers with the usual four 0.05 BTC P2TR UTXOs each.
#[allow(dead_code)]
pub fn fund_makers_default(
    makers: &[Arc<MakerServer>],
    bitcoind: &bitcoind::BitcoinD,
) -> Vec<Amount> {
    fund_makers(
        makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    )
}

/// Verify maker pre-swap balances
#[allow(dead_code)]
pub fn verify_maker_pre_swap_balances(makers: &[Arc<MakerServer>]) -> Vec<Amount> {
    let mut maker_spendable_balance = Vec::new();

    info!("Testing maker balance verification");

    for (i, maker) in makers.iter().enumerate() {
        let wallet = maker.wallet.read().unwrap();
        let balances = wallet.get_balances().unwrap();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable
        );

        // Regular balance after fidelity bond creation
        let regular = balances.regular.to_sat();
        assert!(
            regular == 14999757,
            "Maker regular balance check after fidelity bond creation: {}",
            regular
        );

        assert_eq!(balances.swap, Amount::ZERO);
        assert_eq!(balances.contract, Amount::ZERO);

        assert_eq!(
            balances.fidelity,
            Amount::from_btc(0.05).unwrap(),
            "Fidelity bond should be exactly 0.05 BTC"
        );

        assert!(
            balances.spendable > Amount::ZERO,
            "Maker {} should have spendable balance",
            i
        );

        maker_spendable_balance.push(balances.spendable);
    }

    maker_spendable_balance
}
