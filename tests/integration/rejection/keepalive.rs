//! Keepalives and idle drains: an admitted swap whose funding never shows
//! on-chain is drained once idle, and a keepalive only refreshes when the
//! funding it names is visible to the backend. A drained swap is admitted again
//! when its taker comes back, and a completed one is put back after a failed
//! sweep.

use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

use std::{
    thread,
    time::{Duration, Instant},
};

use super::support::wait_for_log_after;

/// The step every keepalive test shares once its maker is up: one admitted
/// swap that is not started yet. Returns its id and the log path.
fn keepalive_admission(world: &mut World, pause_mining: bool) -> (String, String) {
    let log_path = world.taker_log_path();
    let maker_addr = world.makers()[0].address();

    // Hold the tip still when the test needs contract txs mempool-visible.
    if pause_mining {
        world.framework().set_block_gen_paused(true);
    }

    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect("the maker must admit the swap");

    (summary.swap_id.clone(), log_path)
}

/// A keepalive naming funding the backend can see still refreshes: with
/// mining paused, the taker's contract txs sit mempool-visible, the maker
/// claims their txids, and the route heartbeat's keepalives pass the
/// evidence gate. Mining resumes and the swap completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [SkipFundingConfirmWait],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn keepalive_with_mempool_funding_still_refreshes(world: &mut World) {
    let (swap_id, log_path) = keepalive_admission(world, true);

    // The swap runs on its own thread, so the taker leaves the world here.
    let mut taker = world.take_taker();
    let swap_thread = thread::spawn(move || taker.start(&swap_id));

    // The maker claimed the taker's contract txids and is waiting for a
    // confirmation the paused miner will not give.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(90));

    // A keepalive sent after the claim passes the evidence gate: the funding
    // is mempool-visible, so the idle timer is refreshed.
    wait_for_new_log(&log_path, "Resetting timer", Duration::from_secs(60));

    // Wait past the 30s idle timeout: the swap must still be held.
    thread::sleep(Duration::from_secs(25));
    assert!(
        world.makers()[0].inner().has_ongoing_swaps().unwrap(),
        "a swap with mempool-visible funding must survive the idle timeout"
    );

    world.framework().set_block_gen_paused(false);
    swap_thread
        .join()
        .unwrap()
        .expect("the swap must complete once mining resumes");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("names funding the backend cannot see"),
        "no keepalive may be refused while the funding is mempool-visible"
    );
    assert!(
        !contents.contains("Released idle unfunded swap"),
        "a swap with mempool-visible funding must never be drained"
    );
}

/// A keepalive naming funding the backend cannot see must not refresh:
/// every post-claim keepalive is refused and the unfunded swap is drained
/// once idle.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [WithholdFundingBroadcast],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn keepalive_naming_unseen_funding_is_refused(world: &mut World) {
    let (swap_id, log_path) = keepalive_admission(world, true);

    // The swap runs on its own thread, so the taker leaves the world here.
    let mut taker = world.take_taker();
    let swap_thread = thread::spawn(move || taker.start(&swap_id));

    // The maker claimed the withheld txids and waits for a tx that will never
    // arrive. Everything logged after this point is post-claim.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(90));
    let claim_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // The heartbeat's keepalives hit the evidence gate and are refused.
    wait_for_log_after(
        &log_path,
        claim_offset,
        "names funding the backend cannot see",
        1,
        Duration::from_secs(90),
    );

    // The taker's own read deadline ends the swap; recovery discards the
    // never-broadcast contracts without putting them on-chain.
    swap_thread
        .join()
        .unwrap()
        .expect_err("the swap must fail: the maker never answers withheld funding");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let post_claim = contents
        .get(claim_offset as usize..)
        .unwrap_or(contents.as_str());
    assert!(
        post_claim.contains("names funding the backend cannot see"),
        "a post-claim keepalive must be refused"
    );
    assert!(
        !post_claim.contains("Resetting timer"),
        "a refused keepalive must not refresh the idle timer"
    );

    // With every keepalive refused, the swap goes idle and is drained: the
    // withheld funding is not on-chain evidence.
    wait_for_log(
        &log_path,
        "Released idle unfunded swap",
        Duration::from_secs(400),
    );
    assert!(
        !world.makers()[0].inner().has_ongoing_swaps().unwrap(),
        "the maker must hold no swap after the idle drain"
    );

    world.framework().set_block_gen_paused(false);
}

/// A taker that returns after the maker drained its idle admission is
/// admitted again by the re-check before funding, and the swap completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn slow_taker_is_readmitted_before_funding(world: &mut World) {
    let (swap_id, log_path) = keepalive_admission(world, false);

    wait_for_log(
        &log_path,
        "Released idle unfunded swap",
        Duration::from_secs(400),
    );
    world
        .taker_mut()
        .start(&swap_id)
        .expect("the re-check must re-admit the drained swap");
}

/// A failed sweep puts the completed swap's state back after it was removed.
/// That store must pass the stale-plan guard, or the maker loses the state.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailSweep],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Taproot, sats = 500_000, makers = 1, tx_count = 1),
)]
fn completed_swap_state_is_restored_after_a_failed_sweep(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap(params)
        .expect("the taker's side completes before the maker sweeps");

    wait_logged!(
        world,
        "Failed to sweep incoming swapcoins",
        Duration::from_secs(60)
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !world.makers()[0].inner().has_ongoing_swaps().unwrap() {
        assert!(
            Instant::now() < deadline,
            "the completed swap's state must be put back"
        );
        thread::sleep(Duration::from_millis(500));
    }
    let contents = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert!(
        !contents.contains("Rejecting late message"),
        "restoring a completed swap is not a late message"
    );
}
