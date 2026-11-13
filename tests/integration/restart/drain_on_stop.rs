//! `maker-cli stop` drains: the maker refuses new swaps, lets the swaps in
//! progress finish, and then stops itself. `stop --now` and the in-process
//! shutdown flag stay immediate, so a test can still stop a maker mid-swap.
//!
//! Without the drain, a live swap breaks when the maker stops and settles
//! on-chain after the restart, which costs the taker the refund timelock, the
//! recovery fees and the swap's privacy.

use bitcoin::Amount;
use openswap::{
    maker::handlers::Maker as _,
    protocol::common_messages::ProtocolVersion,
    taker::{MakerState, SwapParams},
};

use crate::test_framework::*;

use log::info;
use std::{
    fs,
    process::Command,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    thread,
    time::Duration,
};

/// One-maker route over `protocol`, pinned to `makers` in order: the first is
/// the route's maker and the rest are its spares.
fn route(protocol: ProtocolVersion, makers: Vec<String>) -> SwapParams {
    SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_preferred_makers(makers)
}

/// A swap in progress finishes after the drain starts, including a reconnect
/// for its known id. A second taker is turned away by the draining maker and
/// takes the spare, and the draining maker keeps its good standing. Once the
/// swap is settled, the maker stops by itself with nothing left to recover.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal, Normal],
    cases = [
        legacy_swap_finishes_and_a_new_taker_uses_the_spare(protocol = ProtocolVersion::Legacy),
        taproot_swap_finishes_and_a_new_taker_uses_the_spare(protocol = ProtocolVersion::Taproot),
    ],
)]
fn drain_lets_a_swap_finish_and_turns_new_swaps_away(world: &mut World, protocol: ProtocolVersion) {
    world.fund_nth_taker_default(0, 3);
    world.fund_nth_taker_default(1, 3);
    world.fund_makers_default();
    world.start_makers(120);
    world.mine(1);
    for taker in world.takers() {
        taker.sync();
        taker.wait_for_good_makers(2, Duration::from_secs(60));
    }
    let draining = world.makers()[0].inner().clone();
    let draining_address = world.makers()[0].address();
    let spare_address = world.makers()[1].address();

    // The first taker's swap is admitted. Then the operator stops the maker.
    let first = world.takers_mut()[0]
        .prepare(route(protocol, vec![draining_address.clone()]))
        .expect("the first swap is admitted");
    draining.start_drain();
    assert!(draining.is_draining());

    // A new swap is turned away and goes to the spare. The turned-away maker
    // is not banned or marked unavailable: it did nothing wrong.
    world.takers_mut()[1]
        .swap(route(
            protocol,
            vec![draining_address.clone(), spare_address],
        ))
        .expect("the spare maker takes the second swap");
    let standing = world.takers()[1]
        .inner()
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|maker| maker.address.to_string() == draining_address)
        .expect("the draining maker is still in the offerbook")
        .state;
    assert_eq!(standing, MakerState::Good);
    assert!(
        !draining.shutdown.load(Relaxed),
        "the swap in progress holds the drain"
    );

    // The first swap reconnects by its known id and finishes. Then the maker
    // stops by itself.
    let report = world.takers_mut()[0]
        .start(&first.swap_id)
        .expect("the swap in progress finishes");
    info!("Swap finished while the maker was draining: {:?}", report);
    wait_until!(
        Duration::from_secs(60),
        "the maker to stop once its swap is settled",
        draining.shutdown.load(Relaxed)
    );
    assert!(!draining.has_ongoing_swaps().unwrap());
    assert!(!draining
        .has_unfinished_outgoing_swapcoin(&first.swap_id)
        .unwrap());
    let contract = draining
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .contract;
    assert_eq!(contract, Amount::ZERO, "no coins wait in a contract");
    assert_wallet_has_deniability_proofs(&draining.wallet, "draining maker", 1);

    world.shutdown_makers();
}

/// A peer admits a swap, funds nothing, and keeps it alive with keepalives,
/// which is what `WaitingFundingConfirmation` does to the idle timer. The swap
/// never goes idle, so the drain would wait for ever. It stops at its deadline
/// instead, and asking again does not push the deadline out.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn drain_gives_up_on_a_swap_held_open_without_funding(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let maker_address = world.makers()[0].address();
    let summary = world
        .taker_mut()
        .prepare(route(ProtocolVersion::Taproot, vec![maker_address.clone()]))
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

    maker.start_drain_within(Duration::from_secs(12));
    maker.start_drain();
    thread::sleep(Duration::from_secs(5));
    assert!(maker.has_ongoing_swap(&summary.swap_id).unwrap());
    assert!(
        !maker.shutdown.load(Relaxed),
        "inside the limit the drain keeps waiting"
    );

    wait_until!(
        Duration::from_secs(40),
        "the drain to give up on the held swap at its deadline",
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

/// A drain that starts after a swap is planned and before it is stored ends in
/// one outcome: the swap is rejected and leaves no state, so the maker, which
/// holds nothing, stops. Only the re-check under the swaps lock can catch it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [DrainDuringAdmission],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn drain_during_admission_rejects_the_swap_and_leaves_no_state(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let maker_address = world.makers()[0].address();
    let refused = world
        .taker_mut()
        .prepare(route(ProtocolVersion::Taproot, vec![maker_address.clone()]))
        .expect_err("a draining maker takes no new swap");
    assert!(
        format!("{refused:?}").contains("rejected swap"),
        "the maker must refuse the swap, not drop it: {:?}",
        refused
    );

    assert!(maker.is_draining());
    assert!(!maker.has_ongoing_swaps().unwrap(), "no swap was stored");
    assert_eq!(maker.reserved_inputs().unwrap(), 0, "no coin was reserved");
    wait_until!(
        Duration::from_secs(30),
        "the maker, with nothing in progress, to stop",
        maker.shutdown.load(Relaxed)
    );
    world.shutdown_makers();
}

/// The real `maker-cli`: plain `stop` asks for a drain and returns at once with
/// the maker still running its swap, and `stop --now` still stops it on the
/// spot while the drain is under way, so the RPC server is never held up.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn maker_cli_stop_drains_and_stop_now_does_not(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let maker_address = world.makers()[0].address();
    world
        .taker_mut()
        .prepare(route(ProtocolVersion::Taproot, vec![maker_address.clone()]))
        .expect("the maker admits the swap");

    let data_dir = maker.config.data_dir.clone();
    assert!(fs::metadata(data_dir.join("rpc_cookie")).is_ok());
    let cli = |args: &[&str]| {
        let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
            .args(["-p", &format!("127.0.0.1:{}", maker.config.rpc_port)])
            .args(["-d", data_dir.to_str().unwrap()])
            .args(args)
            .output()
            .expect("failed to run maker-cli");
        (
            output.status.success(),
            String::from_utf8_lossy(&output.stdout).into_owned(),
        )
    };

    let (ok, stdout) = cli(&["stop"]);
    assert!(ok, "stop must be accepted: {}", stdout);
    assert!(stdout.contains("takes no new swaps"), "{}", stdout);
    assert!(maker.is_draining());
    thread::sleep(Duration::from_secs(3));
    assert!(
        !maker.shutdown.load(Relaxed),
        "the swap in progress holds the drain"
    );

    let (ok, stdout) = cli(&["stop", "--now"]);
    assert!(ok, "stop --now must be accepted during a drain: {}", stdout);
    wait_until!(
        Duration::from_secs(10),
        "stop --now to stop the maker at once",
        maker.shutdown.load(Relaxed)
    );
    world.shutdown_makers();
}

/// A swap whose taker is gone goes idle and moves into recovery. That stops
/// blocking the drain: the maker stops while the swap still needs recovery,
/// which is saved and resumes after the restart. Startup recovery does not
/// block a second drain either.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [BroadcastContractAfterFullSetup],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn drain_does_not_wait_for_a_swap_that_went_into_recovery(world: &mut World) {
    let maker = world.makers()[0].inner().clone();
    let maker_address = world.makers()[0].address();
    let summary = world
        .taker_mut()
        .prepare(route(ProtocolVersion::Taproot, vec![maker_address.clone()]))
        .expect("the maker admits the swap");
    let abandoned = world.taker_mut().start(&summary.swap_id);
    assert!(
        abandoned.is_err(),
        "the taker drops the swap: {:?}",
        abandoned
    );
    assert!(
        maker
            .has_unfinished_outgoing_swapcoin(&summary.swap_id)
            .unwrap(),
        "the maker funded its side and now waits on the taker"
    );

    // The swap is still live, so the drain waits. After the idle timeout the
    // swap moves to recovery and the maker stops.
    maker.start_drain();
    thread::sleep(Duration::from_secs(3));
    assert!(
        !maker.shutdown.load(Relaxed),
        "the swap has not gone idle yet"
    );
    wait_until!(
        Duration::from_secs(120),
        "the maker to stop once the idle swap moved into recovery",
        maker.shutdown.load(Relaxed)
    );
    assert!(
        maker
            .has_unfinished_outgoing_swapcoin(&summary.swap_id)
            .unwrap(),
        "the swap is saved for recovery, not lost"
    );

    // After the restart, recovery runs again. It is not a swap in progress, so
    // a drain does not wait for it.
    world.restart_maker(0, 120);
    let restarted = world.makers()[0].inner().clone();
    assert!(restarted
        .has_unfinished_outgoing_swapcoin(&summary.swap_id)
        .unwrap());
    restarted.start_drain();
    wait_until!(
        Duration::from_secs(30),
        "a drain after the restart not to wait for startup recovery",
        restarted.shutdown.load(Relaxed)
    );
    world.shutdown_makers();
}
