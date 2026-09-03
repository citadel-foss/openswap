//! Integration test: Legacy maker reboot recovery preserves funded swapcoins.
//!
//! Legacy counterpart of taproot_reboot_recovery.
//! Route: Taker -> Maker1 (Normal) -> Maker2 (CloseAtHashPreimage) -> Taker
//!
//! Scenario:
//! 1. Taker initiates a Legacy openswap with 2 makers.
//! 2. Maker2 broadcasts its funding transaction and persists unfinished swapcoins.
//! 3. Maker2 closes at hash preimage / private key handover.
//! 4. Maker2 is restarted before idle recovery can write a tracker record.
//! 5. Startup recovery must not discard the persisted swapcoins merely because
//!    it cannot find a matching tracker record.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    utill::NO_SHUTDOWN,
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

/// Test: maker reboot recovery should preserve Legacy swapcoins when funding
/// was broadcast but the maker has not yet persisted an idle-recovery tracker
/// record for the original swap id.
#[test]
fn test_legacy_maker_reboot_recovery_preserves_funded_swapcoins() {
    warn!("Running Test: Legacy Maker Reboot Recovery Preserves Funded Swapcoins");

    let makers_config_map = vec![(8802, Some(21301)), (18802, Some(21302))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::CloseAtHashPreimage];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

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

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 closing at hash preimage handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    let victim = makers[1].clone();
    victim
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let before_outgoing = victim.wallet.read().unwrap().get_outgoing_swapcoins_count();
    let before_incoming = victim.wallet.read().unwrap().get_incoming_swapcoins_count();
    assert!(
        before_outgoing > 0,
        "victim maker should have unfinished outgoing swapcoins before reboot"
    );
    assert!(
        before_incoming > 0,
        "victim maker should have unfinished incoming swapcoins before reboot"
    );

    // The first init consumed the passphrase (`config.password.take()`), so
    // re-supply it to simulate the operator re-entering it on restart.
    let mut victim_config = victim.config.clone();
    victim_config.password = Some("integration-test".to_string());
    info!(
        "Restarting Maker2 before idle recovery: incoming={}, outgoing={}",
        before_incoming, before_outgoing
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(victim);
    drop(makers);

    let restarted = Arc::new(MakerServer::init(victim_config).unwrap());
    let restarted_thread = {
        let maker_clone = restarted.clone();
        thread::spawn(move || {
            start_server(maker_clone).unwrap();
        })
    };

    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    // Legacy has to broadcast each contract tx and wait for it to confirm before
    // it can sweep, so the swapcoins clear much later than in Taproot, where the
    // funding tx already is the contract tx.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let deadline = Instant::now() + Duration::from_secs(300);
    while !std::fs::read_to_string(&log_path)
        .unwrap()
        .contains("Removed outgoing swapcoin")
    {
        assert!(
            Instant::now() < deadline,
            "reboot recovery did not clear the outgoing swapcoins within 300s"
        );
        thread::sleep(Duration::from_secs(5));
    }

    let after_incoming = restarted
        .wallet
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
    test_framework.assert_log("Incomplete swaps detected on startup", &log_path);
    test_framework.assert_log("recover_from_swap started", &log_path);
    test_framework.assert_log("Removed outgoing swapcoin", &log_path);
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("Funding was never broadcast for swap"),
        "reboot recovery took the unsafe discard path"
    );
    let recovered_via_hashlock = log_contents.contains("incoming swapcoins via hashlock");

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();

    generate_blocks(bitcoind, 1);
    restarted
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let maker_balances = restarted.wallet.read().unwrap().get_balances().unwrap();
    info!(
        "Restarted maker balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
        maker_balances.regular,
        maker_balances.swap,
        maker_balances.contract,
        maker_balances.fidelity,
        maker_balances.spendable,
    );
    // Reboot recovery kept the swapcoins, so the maker still ends up with the
    // swept incoming funds rather than only its own refunded funding.
    assert_eq!(
        maker_balances.regular.to_sat(),
        14503103,
        "Restarted maker regular balance mismatch"
    );
    assert_eq!(
        maker_balances.swap.to_sat(),
        495925,
        "Restarted maker swap balance mismatch"
    );
    assert_eq!(
        maker_balances.contract.to_sat(),
        0,
        "Restarted maker contract balance mismatch"
    );
    assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());
    assert_eq!(
        maker_balances.spendable.to_sat(),
        14999028,
        "Restarted maker spendable balance mismatch"
    );

    info!("Waiting for the taker's recovery loop to finish...");
    let deadline = Instant::now() + Duration::from_secs(300);
    while !taker.is_recovery_complete() {
        assert!(
            Instant::now() < deadline,
            "taker recovery did not complete within 300s"
        );
        thread::sleep(Duration::from_secs(5));
    }

    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);
    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);
    let wallet = taker.get_wallet().read().unwrap();
    assert_eq!(wallet.get_incoming_swapcoins_count(), 0);
    assert_eq!(wallet.get_outgoing_swapcoins_count(), 0);

    test_framework.stop();
    block_generation_handle.join().unwrap();

    assert!(
        after_incoming > 0 || recovered_via_hashlock,
        "maker reboot recovery lost funded incoming swapcoins without hashlock recovery; before={}, after={}",
        before_incoming,
        after_incoming
    );
}
