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
use openswap::{maker::MakerServer, protocol::common_messages::ProtocolVersion, taker::SwapParams};

use super::test_framework::*;

use log::info;
use std::{
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

/// Test: maker reboot recovery should preserve Legacy swapcoins when funding
/// was broadcast but the maker has not yet persisted an idle-recovery tracker
/// record for the original swap id.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtHashPreimage],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
    ],
)]
fn test_legacy_maker_reboot_recovery_preserves_funded_swapcoins(
    world: &mut World,
    taker_original_balance: Amount,
) {
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 closing at hash preimage handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    let victim = &world.makers()[1];
    victim.sync();
    let before_outgoing = victim
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    let before_incoming = victim
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
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
    let mut victim_config = victim.inner().config.clone();
    victim_config.password = Some("integration-test".to_string());
    info!(
        "Restarting Maker2 before idle recovery: incoming={}, outgoing={}",
        before_incoming, before_outgoing
    );

    world.shutdown_makers();

    // Only Maker2 comes back; the world now holds it alone.
    world.drop_makers();
    world.adopt_makers([Arc::new(MakerServer::init(victim_config).unwrap())]);
    world.start_makers_without_sync(120);

    // Legacy has to broadcast each contract tx and wait for it to confirm before
    // it can sweep, so the swapcoins clear much later than in Taproot, where the
    // funding tx already is the contract tx.
    let log_path = world.taker_log_path();
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

    let after_incoming = world.makers()[0]
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
    assert_logged!(world, "Incomplete swaps detected on startup");
    assert_logged!(world, "recover_from_swap started");
    assert_logged!(world, "Removed outgoing swapcoin");
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("Funding was never broadcast for swap"),
        "reboot recovery took the unsafe discard path"
    );
    let recovered_via_hashlock = log_contents.contains("incoming swapcoins via hashlock");

    world.shutdown_makers();

    world.mine(1);
    world.makers()[0].sync();
    let maker_balances = world.makers()[0].balances();
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
        14502398,
        "Restarted maker regular balance mismatch"
    );
    assert_eq!(
        maker_balances.swap.to_sat(),
        497530,
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
        14999928,
        "Restarted maker spendable balance mismatch"
    );

    info!("Waiting for the taker's recovery loop to finish...");
    let deadline = Instant::now() + Duration::from_secs(300);
    while !world.taker().inner().is_recovery_complete() {
        assert!(
            Instant::now() < deadline,
            "taker recovery did not complete within 300s"
        );
        thread::sleep(Duration::from_secs(5));
    }

    world.mine(1);
    world.taker().sync();
    let taker_balances = world.taker().balances();
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
    let wallet = world.taker().inner().get_wallet().read().unwrap();
    assert_eq!(wallet.get_incoming_swapcoins_count(), 0);
    assert_eq!(wallet.get_outgoing_swapcoins_count(), 0);
    drop(wallet);

    assert!(
        after_incoming > 0 || recovered_via_hashlock,
        "maker reboot recovery lost funded incoming swapcoins without hashlock recovery; before={}, after={}",
        before_incoming,
        after_incoming
    );
}
