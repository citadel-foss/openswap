//! Reboot and crash recovery, both protocols.
//!
//! A restarted node knows its live swaps only from what it persisted. This
//! file proves each piece of that: funded swapcoins survive a maker reboot
//! with no tracker record yet, startup rebuilds every contract watch, a
//! crash inside the contract-acceptance window loses nothing, and a coin
//! claim that nothing on disk owns is freed.
//!
//! Route for the reboot case: Taker -> Maker1 (Normal) -> Maker2 (closes at
//! handover) -> Taker. Maker2 broadcasts its funding transaction and persists
//! unfinished swapcoins, then is restarted before idle recovery can write a
//! tracker record. Startup recovery must not discard the persisted swapcoins
//! merely because it cannot find a matching tracker record.

use bitcoin::Amount;
use openswap::{
    maker::{
        start_server,
        swap_tracker::{
            MakerRecoveryPhase, MakerRecoveryState, MakerSwapPhase, MakerSwapRecord,
            MakerSwapTracker,
        },
        MakerBehavior, MakerServer,
    },
    protocol::common_messages::ProtocolVersion,
    taker::{swap_tracker::SwapTracker, SwapParams, Taker, TakerBehavior},
};

use super::test_framework::*;

use log::info;
use std::{
    net::TcpStream,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

/// Test: maker reboot recovery preserves funded Taproot swapcoins. Maker2 funds
/// its contracts, then drops at private key handover — before idle recovery can
/// write a tracker record for the swap. On restart, startup recovery must keep
/// or hashlock-recover those swapcoins instead of discarding them for want of a
/// tracker.
///
/// The coins come back via the hashlock path: the still-running taker sweeps
/// Maker2's outgoing contract, revealing the preimage on-chain; the restarted
/// maker's watchtower sees that spend and uses the preimage to sweep its
/// incoming contract from Maker1 — the same end state as a completed swap.
///
/// `watchtower_liveness` runs the same body with the maker's watcher stopped.
pub(crate) fn run_reboot_recovery(world: &mut World, params: SwapParams, watcher_available: bool) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 closing at private key handover"
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
    let mut restarted_server = MakerServer::init(victim_config).unwrap();
    if !watcher_available {
        restarted_server.behavior = MakerBehavior::StopWatcherOnStartup;
    }
    world.adopt_makers([Arc::new(restarted_server)]);
    world.spawn_makers();

    let log_path = world.taker_log_path();
    // Recovery takes longer under parallel load; wait for the markers instead
    // of asserting at a fixed wall-clock point.
    if watcher_available {
        world.wait_for_makers_setup(120);
        thread::sleep(Duration::from_secs(5));

        let after_incoming = world.makers()[0]
            .inner()
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count();
        wait_logged!(
            world,
            "Incomplete swaps detected on startup",
            Duration::from_secs(120)
        );
        wait_logged!(world, "recover_from_swap started", Duration::from_secs(120));
        wait_logged!(world, "Removed outgoing swapcoin", Duration::from_secs(120));
        let log_contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            !log_contents.contains("Funding was never broadcast for swap"),
            "reboot recovery took the unsafe discard path"
        );
        let recovered_via_hashlock = log_contents.contains("incoming swapcoins via hashlock");

        world.shutdown_makers();
        assert!(
            after_incoming > 0 || recovered_via_hashlock,
            "maker reboot recovery lost funded incoming swapcoins without hashlock recovery; before={}, after={}",
            before_incoming,
            after_incoming
        );
    } else {
        let restarted = world.makers()[0].inner();
        wait_logged!(
            world,
            "Incomplete swaps detected on startup",
            Duration::from_secs(120)
        );
        assert!(
            TcpStream::connect(("127.0.0.1", restarted.config.network_port)).is_err(),
            "recovery-only maker must not accept swap connections"
        );
        wait_logged!(
            world,
            &format!(
                "[{}] Recovered {} incoming swapcoins via hashlock",
                restarted.config.network_port, before_incoming
            ),
            Duration::from_secs(120)
        );
        assert!(!restarted.is_setup_complete.load(Relaxed));
        // The recovery-only maker exits on its own once recovery is done.
        world.join_makers();

        let wallet = world.makers()[0].inner().wallet.read().unwrap();
        assert_eq!(
            wallet.get_incoming_swapcoins_count(),
            0,
            "restarted maker did not sweep its incoming contracts"
        );
        assert_eq!(
            wallet.get_outgoing_swapcoins_count(),
            0,
            "restarted maker did not clean up its spent outgoing contracts"
        );
    }
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtPrivateKeyHandover],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taproot_maker_reboot_preserves_funded_swapcoins(world: &mut World, params: SwapParams) {
    run_reboot_recovery(world, params, true);
}

/// Test: everyone in the route crashes with funding on chain, then each restarts
/// with an empty watcher and claims its money back through the hashlock cascade.
///
/// The watcher registry is memory-only, so every restart begins with nothing
/// watched. Each party has to re-arm its live contracts from the wallet — on Core
/// by reading blocks back, on Electrum through the per-script history replay —
/// and recover unprompted at startup. Nothing here is triggered by the test.
///
/// The makers are the load-bearing part: only the taker already knows the
/// preimage. Each maker has to read it off the chain, so a missed rebuild costs
/// that maker its incoming amount.
///
/// ```text
/// t=0   funding is on chain; the taker drops without recovering, and neither
///       maker runs its idle recovery -> all three hold unclaimed contracts
/// t~2s  kill all three; every watcher is now gone
/// t~10s restart the taker -> rebuild -> claims via hashlock, which is what
///       first puts the preimage on chain
/// t~20s restart both makers -> rebuild -> each reads the preimage revealed by
///       the party downstream and claims via hashlock in turn
/// ```
#[world_test(
    // All three die holding unclaimed contracts, none of them recovering in
    // process, so only the restarts can settle anything.
    maker_behaviors = [CrashBeforeRecovery, CrashBeforeRecovery],
    takers = [crash_behavior],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = protocol, sats = 500_000, makers = 2, tx_count = 3),
    cases = [
        taproot_restart_rebuilds_watches(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
            crash_behavior = TakerBehavior::CrashBeforeRecovery,
        ),
        legacy_electrum_restart_rebuilds_watches(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            crash_behavior = TakerBehavior::CrashBeforeRecovery,
        ),
        // The taker dies right after the contract exchange — before the old code
        // ever persisted what it was owed. The pre-restart `incoming count > 0`
        // assertion is the proof: red without acceptance-time persistence, green
        // with it.
        taproot_crash_after_contract_exchange(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
            crash_behavior = TakerBehavior::CrashAfterContractExchange,
        ),
        legacy_electrum_crash_after_contract_exchange(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            crash_behavior = TakerBehavior::CrashAfterContractExchange,
        ),
    ],
)]
fn run_restart_rebuilds_watches(world: &mut World, params: SwapParams) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail because the taker crashes before finalization"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    // All three are left holding unclaimed contracts, and none of them recovers
    // in process. That holds by construction, not by timing.
    world.taker().sync();
    assert!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            > 0,
        "taker should still hold an incoming contract before the restart"
    );
    // The first init consumed the passphrases (`config.password.take()`), so
    // re-supply them to simulate the operator re-entering them on restart.
    let mut taker_config = world.taker().inner().config().clone();
    taker_config.password = Some("integration-test".to_string());
    let is_electrum = world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .is_electrum();

    let mut maker_configs = Vec::new();
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        assert!(
            maker
                .inner()
                .wallet
                .read()
                .unwrap()
                .get_incoming_swapcoins_count()
                > 0,
            "maker {} should still hold an incoming contract before the restart",
            i
        );
        let mut config = maker.inner().config.clone();
        config.password = Some("integration-test".to_string());
        maker_configs.push(config);
    }

    // Freeze the chain here. Left running, the miner races past every refund
    // deadline and each party takes the cheaper timelock refund instead of
    // waiting to learn the preimage — the cascade would never happen.
    world.framework().set_block_gen_paused(true);

    // Dropping the taker and stopping the makers leaves every watcher empty, so
    // each restart has to rebuild from its own wallet.
    world.drop_takers();
    world.shutdown_makers();
    world.drop_makers();

    // The claims still need confirmations, so mine by hand — slowly enough that
    // no timelock matures while the cascade runs.
    let mining = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let slow_miner = {
        let mining = mining.clone();
        let tf = world.framework().clone();
        thread::spawn(move || {
            while mining.load(Relaxed) {
                thread::sleep(Duration::from_secs(5));
                generate_blocks(&tf.bitcoind, 1);
            }
        })
    };

    let log_path = world.taker_log_path();
    let log_len = || std::fs::read_to_string(&log_path).unwrap_or_default().len();
    let since = |offset: usize| {
        let all = std::fs::read_to_string(&log_path).unwrap_or_default();
        all[offset.min(all.len())..].to_string()
    };

    // A crash can save the incoming coins before the tracker lists them. The
    // restart must still find them from the wallet and claim them.
    let taker_dir = world.temp_dir().join("taker1");
    let mut tracker = SwapTracker::load_or_create(&taker_dir).unwrap();
    let mut record = tracker.get_record(&summary.swap_id).unwrap().clone();
    record.incoming_contract_txids.clear();
    tracker.save_record(&record).unwrap();
    drop(tracker);

    // ---- The taker restarts first: its sweep is what puts the preimage on chain.
    let taker_offset = log_len();
    info!("Restarting the taker with an empty watcher...");
    world.adopt_taker(Taker::init(taker_config).expect("taker restart should succeed"));

    if !is_electrum {
        // Core has no per-script history, so it must read the blocks back.
        wait_for_log(&log_path, "Rescanning blocks", Duration::from_secs(120));
    }
    assert!(
        since(taker_offset).contains("Rebuilding"),
        "restarted taker never rebuilt its watches from the wallet"
    );
    // Startup recovery finishes inside `Taker::init`, so there is nothing to wait
    // for. Its hashlock spend is what first puts the preimage on chain.
    assert!(
        since(taker_offset).contains("hashlock"),
        "restarted taker did not claim via hashlock, so no preimage reached the chain"
    );

    world.taker().sync();
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_incoming_swapcoins_count(),
        0,
        "restarted taker still holds an incoming contract"
    );
    // Its outgoing contract stays open on purpose — Maker1 is the one who takes
    // it, with the preimage the sweep above just published.

    // ---- Now both makers. The preimage is on chain; only a rebuilt watch sees
    // it, and each maker's own claim reveals it to the one upstream.
    let maker_offset = log_len();
    info!("Restarting both makers with empty watchers...");
    world.adopt_makers(
        maker_configs
            .into_iter()
            .map(|cfg| Arc::new(MakerServer::init(cfg).expect("maker restart should succeed"))),
    );
    world.start_makers_without_sync(120);

    // Each maker must claim its *incoming* side with the preimage. A bare
    // "Recovered" also matches the outgoing timelock line, which proves nothing.
    for maker in world.makers() {
        let port = maker.inner().config.network_port;
        let claimed = format!("[{port}] Recovered");
        let deadline = std::time::Instant::now() + Duration::from_secs(300);
        loop {
            let hit = std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .lines()
                .any(|l| l.contains(&claimed) && l.contains("incoming swapcoins via hashlock"));
            if hit {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "maker {} never claimed its incoming contract with the preimage",
                port
            );
            thread::sleep(Duration::from_secs(5));
        }
    }
    assert!(
        since(maker_offset).contains("Rebuilding"),
        "restarted makers never rebuilt their watches from the wallet"
    );

    // Every claim is in. Let the chain run again so the spends bury.
    mining.store(false, Relaxed);
    slow_miner.join().unwrap();
    world.framework().set_block_gen_paused(false);
    world.mine(2);

    for maker in world.makers() {
        maker.sync();
        let balances = maker.balances();
        let port = maker.inner().config.network_port;
        info!(
            "Restarted maker {} balances: regular: {}, swap: {}, contract: {}",
            port, balances.regular, balances.swap, balances.contract,
        );
        assert_eq!(
            maker
                .inner()
                .wallet
                .read()
                .unwrap()
                .get_incoming_swapcoins_count(),
            0,
            "maker {} still holds an incoming contract",
            port
        );
    }

    // Maker1 took the taker's outgoing contract with the preimage, so nothing is
    // left locked on the taker's side either.
    world.taker().sync();
    let taker_balances = world.taker().balances();
    info!(
        "Restarted taker balances: regular: {}, swap: {}, contract: {}",
        taker_balances.regular, taker_balances.swap, taker_balances.contract,
    );
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "restarted taker left a contract unresolved"
    );
}

/// Test: a maker learns the preimage only after its sender refunded it.
///
/// ```text
/// t=0   funding on chain; the taker drops without recovering, Maker2 never
///       runs its recovery, Maker1 recovers normally
/// t~2m  Maker1 refunds its outgoing: Maker2's incoming is gone
/// then  the taker restarts and claims by hashlock: the preimage is on chain
/// then  Maker2 restarts and reads it, but its incoming can never be swept
/// ```
///
/// Maker2 must still finish the swap instead of retrying the sweep forever. The
/// same restart closes a record a crash left open with no coins behind it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CrashBeforeRecovery],
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taproot_maker_finishes_when_its_incoming_was_refunded(world: &mut World, params: SwapParams) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    assert!(
        world.taker_mut().start(&summary.swap_id).is_err(),
        "Swap should fail because the taker crashes before finalization"
    );

    let mut taker_config = world.taker().inner().config().clone();
    taker_config.password = Some("integration-test".to_string());

    info!("Waiting for Maker1 to refund Maker2's incoming...");
    let deadline = Instant::now() + Duration::from_secs(400);
    while world.makers()[0]
        .inner()
        .wallet
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count()
        != 0
    {
        assert!(
            Instant::now() < deadline,
            "Maker1 did not refund its outgoing"
        );
        thread::sleep(Duration::from_secs(2));
    }

    // The taker's claim is what first puts the preimage on chain.
    world.drop_takers();
    world.adopt_taker(Taker::init(taker_config).expect("taker restart should succeed"));
    let deadline = Instant::now() + Duration::from_secs(120);
    while world
        .taker()
        .inner()
        .get_wallet()
        .read()
        .unwrap()
        .get_incoming_swapcoins_count()
        != 0
    {
        assert!(
            Instant::now() < deadline,
            "restarted taker did not claim its incoming by hashlock"
        );
        thread::sleep(Duration::from_secs(2));
    }

    let mut victim_config = world.makers()[1].inner().config.clone();
    victim_config.password = Some("integration-test".to_string());
    // Only Maker2 stops; Maker1 keeps running.
    world.shutdown_maker(1);

    // A crash between a finish's wallet save and its tracker save: the record
    // still says recovering, and the wallet holds nothing for it.
    let mut tracker = MakerSwapTracker::load_or_create(&victim_config.data_dir).unwrap();
    tracker
        .save_record(&MakerSwapRecord {
            swap_id: "crashed-finish".to_string(),
            protocol: ProtocolVersion::Taproot,
            phase: MakerSwapPhase::Recovering,
            swap_amount_sat: 0,
            incoming_count: 0,
            outgoing_count: 0,
            funding_broadcast_txids: Vec::new(),
            recovery: MakerRecoveryState::default(),
            created_at: 0,
            updated_at: 0,
        })
        .unwrap();
    drop(tracker);

    info!("Restarting Maker2 after the preimage reached the chain...");
    let restarted = Arc::new(MakerServer::init(victim_config).expect("maker restart"));
    let restarted_thread = {
        let maker_clone = restarted.clone();
        thread::spawn(move || {
            start_server(maker_clone).unwrap();
        })
    };
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    let phase = |swap_id: &str| {
        restarted
            .swap_tracker
            .lock()
            .unwrap()
            .get_record(swap_id)
            .map(|record| record.recovery.phase)
    };
    assert_eq!(
        phase("crashed-finish"),
        Some(MakerRecoveryPhase::CleanedUp),
        "startup left a finished record open"
    );

    let deadline = Instant::now() + Duration::from_secs(180);
    while phase(&summary.swap_id) != Some(MakerRecoveryPhase::CleanedUp) {
        assert!(
            Instant::now() < deadline,
            "Maker2 kept retrying a sweep of an incoming its sender refunded"
        );
        thread::sleep(Duration::from_secs(2));
    }
    let wallet = restarted.wallet.read().unwrap();
    assert_eq!(wallet.get_incoming_swapcoins_count(), 0);
    assert_eq!(wallet.get_outgoing_swapcoins_count(), 0);
    drop(wallet);

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();
}

/// A maker that reserved inputs for a funding it never sent must still hold
/// them after a restart: that funding can still reach the network, and handing
/// those inputs to another swap would invite a conflicting transaction.
///
/// Route: Taker -> Maker1 (Normal) -> Maker2 (skips its funding broadcast and
/// records nothing). Maker2 is restarted inside the grace, and must come back
/// still holding what it reserved.
/// No Legacy variant: its skip-error path only fails the swap after the
/// response timeout, by which point the reservation is older than
/// UNBROADCAST_DISCARD_GRACE — expiring it then is the intended behavior, so
/// the survival invariant has nothing to pin there.
#[world_test(
    maker_behaviors = [Normal, SkipFundingBroadcastUnrecorded],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
    cases = [
        reservations_survive_a_maker_restart(backend = BitcoindBackend),
        /// Same restart on Electrum: the victim's startup recovery reads the indexer,
        /// not its own node, before it may free a reserved input.
        reservations_survive_a_maker_restart_electrum(backend = ElectrumBackend),
    ],
)]
fn run_reservations_survive_restart(world: &mut World, params: SwapParams) {
    world.mine(1);
    world.framework().wait_for_electrs_tip();

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail: Maker2 skips its funding broadcast"
    );

    let victim = world.makers()[1].inner();
    let before = victim.reserved_inputs().unwrap();
    assert!(
        before > 0,
        "Maker2 must reserve the inputs of the funding it planned"
    );
    info!("Maker2 holds {} reserved inputs before restart", before);

    // The first init consumed the passphrase, so re-supply it as an operator
    // would on restart.
    let mut victim_config = victim.config.clone();
    victim_config.password = Some("integration-test".to_string());

    world.shutdown_makers();
    world.drop_makers();

    // The marker must come from the restarted maker: the first Maker2's idle
    // recovery can log it before the restart, so only scan past this offset.
    let log_path = world.taker_log_path();
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // Init only reloads state; `start_server` is what runs startup recovery.
    // The reservation has to survive that too, or a maker could reuse an input
    // from a funding transaction that can still be broadcast.
    world.adopt_makers([Arc::new(MakerServer::init(victim_config).unwrap())]);
    world.start_makers_without_sync(120);
    // Startup recovery runs on its own thread, past is_setup_complete: wait
    // until it has started on the unfinished swap before reading the
    // reservation count, or the assertion can pass without recovery running.
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    loop {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if contents
            .get(log_offset as usize..)
            .is_some_and(|tail| tail.contains("recover_from_swap started"))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "restart recovery never started on the unfinished swap"
        );
        thread::sleep(Duration::from_millis(500));
    }

    let after = world.makers()[0].inner().reserved_inputs().unwrap();
    assert_eq!(
        after, before,
        "startup recovery must not free inputs the planned funding can still spend"
    );

    // The grace ages from the reservation, not the restart: past it, the swap
    // is provably never funded and the reservation is released with it.
    let deadline = std::time::Instant::now()
        + openswap::utill::UNBROADCAST_DISCARD_GRACE
        + Duration::from_secs(60);
    loop {
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if contents
            .get(log_offset as usize..)
            .is_some_and(|tail| tail.contains("nothing to recover. Discarding swapcoins."))
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the restarted maker never discarded the unbroadcast funding"
        );
        thread::sleep(Duration::from_secs(2));
    }
    let released = world.makers()[0].inner().reserved_inputs().unwrap();
    assert_eq!(
        released, 0,
        "past the grace the never-funded swap must release its inputs"
    );
}

/// A maker that dies after claiming its funding coins, before it saves any
/// record of the swap, leaves a reservation nothing owns. The next start
/// frees it instead of holding those coins forever.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [AbandonFundingClaim],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Taproot, sats = 500_000, makers = 1, tx_count = 1),
)]
fn orphan_reservation_is_released_on_restart(world: &mut World, params: SwapParams) {
    let summary = world.taker_mut().prepare(params).expect("prepare swap");
    let log_path = world.taker_log_path();
    let mut victim_config = world.makers()[0].inner().config.clone();
    victim_config.password = Some("integration-test".to_string());

    // Stop the maker while it still holds the abandoned claim: its idle drain
    // would otherwise free the coins before the restart.
    let mut taker = world.take_taker();
    let held = thread::scope(|scope| {
        let swap = scope.spawn(|| taker.start(&summary.swap_id));
        wait_for_log(
            &log_path,
            "Test behavior: abandoning the funding claim",
            Duration::from_secs(120),
        );
        let held = world.makers()[0].inner().reserved_inputs().unwrap();
        world.shutdown_makers();
        assert!(swap.join().unwrap().is_err(), "the swap must fail");
        held
    });
    assert!(held > 0, "the abandoned claim must hold the planned coins");

    world.drop_makers();
    world.adopt_makers([Arc::new(MakerServer::init(victim_config).unwrap())]);
    world.start_makers_without_sync(120);
    assert_logged!(world, "nothing left owns it");
    assert_eq!(
        world.makers()[0].inner().reserved_inputs().unwrap(),
        0,
        "no swap owns the claim, so the restart must free it"
    );

    world.shutdown_makers();
    drop(taker);
}
