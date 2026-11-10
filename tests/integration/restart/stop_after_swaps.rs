//! `maker-cli stop` while a swap is in progress. The maker refuses a new swap,
//! lets the live one finish, and then shuts itself down. Without the wait, the
//! live swap would break and settle on-chain after the restart. A swap that
//! never ends cannot hold the stop for ever: the maker stops at the wait limit.

use bitcoin::Amount;
use openswap::{
    maker::handlers::Maker as _, protocol::common_messages::ProtocolVersion, taker::SwapParams,
};

use crate::test_framework::*;

use log::info;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    thread,
    time::Duration,
};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal, Normal],
)]
fn taproot_stop_waits_for_the_swap_in_progress(world: &mut World) {
    for _ in 0..3 {
        world.fund_nth_taker_default(0, 1);
        world.fund_nth_taker_default(1, 1);
    }
    world.fund_makers_default();
    world.start_makers(120);
    world.mine(1);
    // Both offerbooks are ready, so the second taker's attempt below is quick:
    // the first swap has no keepalive until it starts.
    for taker in world.takers() {
        taker.sync();
        taker.wait_for_good_makers(1, Duration::from_secs(60));
    }

    let params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(2)
            .with_required_confirms(1)
    };
    let maker = world.makers()[0].inner().clone();

    // The first taker's swap is admitted. Then the operator asks to stop.
    let summary = world.takers_mut()[0]
        .prepare(params())
        .expect("the first swap is admitted");
    assert_eq!(
        maker.stop_after_swaps().unwrap().live_swaps,
        1,
        "the stop waits for the admitted swap"
    );

    // A new swap is refused, and the stop still waits.
    let refused = world.takers_mut()[1]
        .prepare(params())
        .expect_err("a stopping maker takes no new swap");
    assert!(
        format!("{refused:?}").contains("rejected swap"),
        "the maker must refuse the swap, not drop it: {:?}",
        refused
    );
    assert!(
        !maker.shutdown.load(Relaxed),
        "the live swap holds the stop"
    );

    // The live swap finishes as normal, then the maker stops on its own.
    let report = world.takers_mut()[0]
        .start(&summary.swap_id)
        .expect("the swap in progress completes");
    info!("Swap finished while the maker was stopping: {:?}", report);
    wait_until!(
        Duration::from_secs(60),
        "the maker to stop once the swap is done",
        maker.shutdown.load(Relaxed)
    );

    // The swap finished: nothing is left for recovery.
    assert!(!maker
        .has_unfinished_outgoing_swapcoin(&summary.swap_id)
        .unwrap());
    let contract = maker
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .contract;
    assert_eq!(contract, Amount::ZERO, "no coins wait in a contract");
    assert_wallet_has_deniability_proofs(&maker.wallet, "maker 0", 1);

    world.shutdown_makers();
}

/// A peer admits a swap, sends no funding, and keeps it alive with keepalives,
/// which is what `WaitingFundingConfirmation` does to the idle timer. The swap
/// never goes idle, so without a limit the stop would wait for ever. The maker
/// stops at the limit and the operator never has to guess why it hangs.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn stop_gives_up_on_a_swap_held_open_without_funding(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let maker_addr = world.makers()[0].address();
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect("the maker admits the swap");

    // The keepalives: refresh the swap's idle timer every second.
    let held = Arc::new(AtomicBool::new(true));
    let keepalives = {
        let (maker, held, swap_id) = (maker.clone(), held.clone(), summary.swap_id.clone());
        thread::spawn(move || {
            while held.load(Relaxed) {
                maker.touch_connection_state(&swap_id).unwrap();
                thread::sleep(Duration::from_secs(1));
            }
        })
    };

    let wait = maker
        .stop_after_swaps_within(Duration::from_secs(12))
        .unwrap();
    assert_eq!(wait.live_swaps, 1, "the held swap counts as in progress");

    thread::sleep(Duration::from_secs(5));
    assert!(maker.has_ongoing_swap(&summary.swap_id).unwrap());
    assert!(
        !maker.shutdown.load(Relaxed),
        "inside the limit the stop keeps waiting"
    );

    wait_until!(
        Duration::from_secs(40),
        "the stop to give up on the held swap at the limit",
        maker.shutdown.load(Relaxed)
    );
    assert!(
        maker.has_ongoing_swap(&summary.swap_id).unwrap(),
        "the keepalives held the swap open to the end"
    );

    held.store(false, Relaxed);
    keepalives.join().unwrap();
    world.shutdown_makers();
}
