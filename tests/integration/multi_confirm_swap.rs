//! Swaps with funding confirmation waits.
//!
//! Exercise both multiple confirmations and a first confirmation delayed beyond
//! the maker admission deadline. Route heartbeats must preserve swap activity
//! throughout these waits, and protocol sockets must not expire before use.
//!
//! Both protocols are covered: the wait sites differ (`legacy_swap.rs` vs
//! `taproot_swap.rs`) even though the keepalive message is shared.

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    utill::NO_SHUTDOWN,
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

/// Confirmations to wait for on every funding tx.
///
/// At the normal five-blocks-per-three-seconds mining cadence, 15 confirmations
/// usually require a polling delay. The paused-mining case below separately
/// forces a wall-clock wait beyond the maker's pending-connection deadline.
const REQUIRED_CONFIRMS: u32 = 15;

#[test]
fn test_legacy_multi_confirm_swap() {
    warn!("Running Test: Legacy Swap With required_confirms > 1");
    run_multi_confirm_swap(ProtocolVersion::Legacy, 2, false);
}

#[test]
fn test_taproot_multi_confirm_swap() {
    warn!("Running Test: Taproot Swap With required_confirms > 1");
    run_multi_confirm_swap(ProtocolVersion::Taproot, 2, false);
}

#[test]
fn test_legacy_confirmation_wait_exceeds_admission_deadline() {
    run_multi_confirm_swap(ProtocolVersion::Legacy, 2, true);
}

#[test]
fn test_taproot_confirmation_wait_exceeds_admission_deadline() {
    run_multi_confirm_swap(ProtocolVersion::Taproot, 2, true);
}

fn run_multi_confirm_swap(
    protocol: ProtocolVersion,
    maker_count: usize,
    delay_first_confirmation: bool,
) {
    let required_confirms = if delay_first_confirmation {
        1
    } else {
        REQUIRED_CONFIRMS
    };
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    info!("Starting Maker servers...");
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(required_confirms);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let swap_result = if delay_first_confirmation {
        test_framework.set_block_gen_paused(true);
        // Let any in-flight mining tick finish before broadcasting funding.
        thread::sleep(Duration::from_secs(4));
        let mempool_before = bitcoind.client.get_raw_mempool().unwrap();
        thread::scope(|scope| {
            let miner = scope.spawn(|| {
                // Resume mining even if an assertion fails, so the swap thread
                // cannot remain blocked in its confirmation wait during unwind.
                struct ResumeMining<'a>(&'a TestFramework);
                impl Drop for ResumeMining<'_> {
                    fn drop(&mut self) {
                        self.0.set_block_gen_paused(false);
                    }
                }
                let _resume = ResumeMining(&test_framework);
                let deadline = Instant::now() + Duration::from_secs(120);
                let funding_txids = loop {
                    let new_txids: Vec<_> = bitcoind
                        .client
                        .get_raw_mempool()
                        .unwrap()
                        .into_iter()
                        .filter(|txid| !mempool_before.contains(txid))
                        .collect();
                    if new_txids.len() == 3 {
                        break new_txids;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "funding never reached the mempool"
                    );
                    thread::sleep(Duration::from_millis(100));
                };
                let height = bitcoind.client.get_block_count().unwrap();
                info!("Holding taker funding unconfirmed for 30 seconds at height {height}");
                // The maker's pending connection deadline is 20 seconds in
                // both production and tests. Cross it with funding unconfirmed.
                thread::sleep(Duration::from_secs(30));
                assert_eq!(bitcoind.client.get_block_count().unwrap(), height);
                let mempool = bitcoind.client.get_raw_mempool().unwrap();
                assert!(funding_txids.iter().all(|txid| mempool.contains(txid)));
            });
            let result = taker.start_swap(&summary.swap_id);
            miner.join().expect("delayed miner panicked");
            result
        })
    } else {
        taker.start_swap(&summary.swap_id)
    };
    swap_result.expect("OpenSwap should complete successfully despite the longer funding wait");

    info!("OpenSwap completed with required_confirms = {required_confirms}");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    generate_blocks(bitcoind, 1);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    // Verify the requested confirmation count and that route heartbeats ran.
    test_framework.assert_log(
        &format!("Waiting for {required_confirms} confirmation(s)"),
        &log_path,
    );
    test_framework.assert_log("Taker is waiting for funding confirmation", &log_path);

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    let expected_taker_regular = 14499076;
    let expected_taker_swap = match protocol {
        ProtocolVersion::Legacy => 494587,
        ProtocolVersion::Taproot => 494815,
    };
    assert_eq!(
        taker_balances.regular.to_sat(),
        expected_taker_regular,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        expected_taker_swap,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // Waiting longer must not change what the swap costs.
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();
    info!("Taker fees paid: {} sats", balance_diff.to_sat());
    let expected_diff = match protocol {
        ProtocolVersion::Legacy => 6337,
        ProtocolVersion::Taproot => 6109,
    };
    assert_eq!(
        balance_diff.to_sat(),
        expected_diff,
        "Taker spendable balance change mismatch"
    );

    let expected_regular = [14500865u64, 14503103];
    let expected_swap = match protocol {
        ProtocolVersion::Legacy => [499100u64, 496825],
        ProtocolVersion::Taproot => [499328u64, 497053],
    };
    let expected_fee = match protocol {
        ProtocolVersion::Legacy => [451u64, 414],
        ProtocolVersion::Taproot => [679u64, 642],
    };

    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        assert_eq!(
            balances.regular.to_sat(),
            expected_regular[i],
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap[i],
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());

        let maker_fee = balances
            .spendable
            .checked_sub(original)
            .unwrap_or(Amount::ZERO);
        info!("Maker {} fee earned: {} sats", i, maker_fee.to_sat());
        assert_eq!(
            maker_fee.to_sat(),
            expected_fee[i],
            "Maker {} fee earned mismatch",
            i
        );
    }

    info!("Multi-confirmation swap test completed successfully!");

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
