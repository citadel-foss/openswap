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

use crate::test_framework::*;

use log::info;
use std::{sync::Arc, time::Duration};

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
fn maker_reboot_preserves_funded_swapcoins(world: &mut World, taker_original_balance: Amount) {
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
    wait_until!(
        Duration::from_secs(300),
        every Duration::from_secs(5),
        "reboot recovery to clear the outgoing swapcoins",
        std::fs::read_to_string(&log_path)
            .unwrap()
            .contains("Removed outgoing swapcoin")
    );

    let after_incoming = world.makers()[0]
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
    assert_log!(world; {
        has "Incomplete swaps detected on startup",
        has "recover_from_swap started",
        has "Removed outgoing swapcoin",
        // Present means reboot recovery took the unsafe discard path.
        lacks "Funding was never broadcast for swap",
    });
    let recovered_via_hashlock = std::fs::read_to_string(&log_path)
        .unwrap()
        .contains("incoming swapcoins via hashlock");

    world.shutdown_makers();

    world.mine(1);
    world.makers()[0].sync();
    // Reboot recovery kept the swapcoins, so the restarted maker (the world's
    // only maker now) still ends up with the swept incoming funds rather than
    // only its own refunded funding.
    assert_balances!(world; {
        maker: {
            regular: 14_502_398,
            swap: 497_530,
            contract: 0,
            fidelity: BOND,
            spendable: 14_999_928,
        },
    });

    info!("Waiting for the taker's recovery loop to finish...");
    wait_until!(
        Duration::from_secs(300),
        every Duration::from_secs(5),
        "the taker recovery to complete",
        world.taker().inner().is_recovery_complete()
    );

    world.mine(1);
    world.taker().sync();
    let taker_spendable = world.taker().balances().spendable;
    let balance_diff = taker_original_balance
        .checked_sub(taker_spendable)
        .unwrap_or(Amount::ZERO);
    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_spendable,
    );
    assert_balances!(world; { taker: { contract: 0, fidelity: 0 } });
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
