//! Reboot and crash recovery, both protocols.
//!
//! A restarted node knows its live swaps only from what it persisted. This
//! file proves each piece of that: funded swapcoins survive a maker reboot
//! using its wallet records, startup rebuilds every contract watch, a
//! crash inside the contract-acceptance window loses nothing, and a coin
//! claim that nothing on disk owns is freed.
//!
//! Route for the reboot case: Taker -> Maker1 (Normal) -> Maker2 (closes at
//! handover) -> Taker. Maker2 broadcasts its funding transaction and persists
//! unfinished swapcoins, then is restarted before idle recovery runs.
//! Startup recovery must not discard the committed swapcoins.

use openswap::{
    maker::{start_server, MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker, TakerBehavior},
    wallet::SwapRole,
};

use crate::test_framework::*;

use log::info;
use std::{
    fs,
    net::TcpStream,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

/// Test: maker reboot recovery preserves funded Taproot swapcoins. Maker2 funds
/// its contracts, then drops at private key handover before idle recovery runs.
/// Startup recovery keeps or hashlock-recovers the committed coins.
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

    // Recovery takes longer under parallel load; wait for the markers instead
    // of asserting at a fixed wall-clock point.
    if watcher_available {
        world.wait_for_makers_setup(120);
        let restarted = world.makers()[0].inner();
        wait_logged!(
            world,
            "Incomplete swaps detected on startup",
            Duration::from_secs(120)
        );
        wait_logged!(world, "recover_from_swap started", Duration::from_secs(120));
        wait_logged!(
            world,
            &format!(
                "[{}] Recovered {} incoming swapcoins via hashlock",
                restarted.config.network_port, before_incoming
            ),
            Duration::from_secs(120)
        );
        // The sweep log precedes the atomic cleanup; wait for both sides to finish.
        wait_until!(
            Duration::from_secs(120),
            every Duration::from_secs(2),
            "reboot recovery to finish cleanup",
            {
                let wallet = restarted.wallet.read().unwrap();
                wallet.get_incoming_swapcoins_count() == 0
                    && wallet.get_outgoing_swapcoins_count() == 0
            }
        );

        world.shutdown_makers();
        let wallet = world.makers()[0].inner().wallet.read().unwrap();
        assert!(
            wallet.swap_reports().recovery.iter().any(|report| {
                report.swap_id == summary.swap_id
                    && report.recovery_type == "hashlock"
                    && report.recovery_txids.len() == before_incoming
            }),
            "maker reboot recovery must record the incoming hashlock claims"
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

    // Recovery derives all saved incoming coins from the wallet.
    // ---- The taker restarts first: its sweep is what puts the preimage on chain.
    let taker_offset = log_mark(&world);
    info!("Restarting the taker with an empty watcher...");
    world.adopt_taker(Taker::init(taker_config).expect("taker restart should succeed"));

    if !is_electrum {
        // Core has no per-script history, so it must read the blocks back.
        wait_for_log(&log_path, "Rescanning blocks", Duration::from_secs(120));
    }
    assert_log!(world, since taker_offset; {
        // The restarted taker rebuilt its watches from the wallet.
        has "Rebuilding",
        // Startup recovery finishes inside `Taker::init`, so there is nothing to
        // wait for. Its hashlock spend is what first puts the preimage on chain.
        has "hashlock",
    });

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
    let maker_offset = log_mark(&world);
    info!("Restarting both makers with empty watchers...");
    world.adopt_makers(
        maker_configs
            .into_iter()
            .map(|cfg| Arc::new(MakerServer::init(cfg).expect("maker restart should succeed"))),
    );
    world.start_makers_without_sync(120);

    // Each maker must claim its *incoming* side with the preimage. A bare
    // "Recovered" also matches the outgoing timelock line, which proves nothing.
    // The claim line can report a partial sweep (a contract still in the
    // mempool is swept on a later pass), so also wait, with the miner still
    // running, until every incoming contract is swept and confirmed.
    for maker in world.makers() {
        let port = maker.inner().config.network_port;
        let claimed = format!("[{port}] Recovered");
        wait_until!(
            Duration::from_secs(300),
            every Duration::from_secs(5),
            format!(
                "maker {} to claim all its incoming contracts with the preimage",
                port
            ),
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .lines()
                .any(|l| l.contains(&claimed) && l.contains("incoming swapcoins via hashlock"))
                && maker
                    .inner()
                    .wallet
                    .read()
                    .unwrap()
                    .get_incoming_swapcoins_count()
                    == 0
        );
    }
    assert_log!(world, since maker_offset; {
        // The restarted makers rebuilt their watches from the wallet.
        has "Rebuilding",
    });

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
    // left locked on the taker's side either: the restarted taker (adopted
    // into the world) left no contract unresolved.
    world.taker().sync();
    assert_balances!(world; { taker: { contract: 0 } });
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
/// wallet becomes empty only when the recovery cleanup is saved.
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
    wait_until!(
        Duration::from_secs(400),
        every Duration::from_secs(2),
        "Maker1 to refund its outgoing",
        world.makers()[0]
            .inner()
            .wallet
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count()
            == 0
    );

    // The taker's claim is what first puts the preimage on chain.
    world.drop_takers();
    world.adopt_taker(Taker::init(taker_config).expect("taker restart should succeed"));
    wait_until!(
        Duration::from_secs(120),
        every Duration::from_secs(2),
        "the restarted taker to claim its incoming by hashlock",
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            == 0
    );

    let mut victim_config = world.makers()[1].inner().config.clone();
    victim_config.password = Some("integration-test".to_string());
    // Only Maker2 stops; Maker1 keeps running.
    world.shutdown_maker(1);

    info!("Restarting Maker2 after the preimage reached the chain...");
    let restarted = Arc::new(MakerServer::init(victim_config).expect("maker restart"));
    let restarted_thread = {
        let maker_clone = restarted.clone();
        thread::spawn(move || {
            start_server(maker_clone).unwrap();
        })
    };
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    // Not cleaned up in time means Maker2 kept retrying a sweep of an incoming
    // its sender refunded.
    wait_until!(
        Duration::from_secs(180),
        every Duration::from_secs(2),
        "Maker2 to finish the swap whose incoming its sender refunded",
        {
            let wallet = restarted.wallet.read().unwrap();
            wallet.get_incoming_swapcoins_count() == 0
                && wallet.get_outgoing_swapcoins_count() == 0
        }
    );

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();
}

/// Test: a maker restarts with an incoming its own hashlock sweep already spent.
///
/// ```text
/// t=0   funding on chain; the taker drops before finalizing, so Maker2 holds
///       its incoming with no preimage and no handed-over key; its wallet is
///       copied here
/// then  the taker restarts and claims by hashlock; Maker2 learns the
///       preimage, sweeps its incoming and finishes
/// then  Maker2 restarts on the copy: a crash between the sweep and its cleanup
/// then  Maker2 restarts on its settled wallet, keeping the sweep report
/// ```
///
/// Maker2 must settle the swap from its confirmed sweep instead of retrying a
/// sweep with nothing left to spend. Both restarts must retain that sweep
/// exactly once in the wallet's recovery reports.
#[world_test(
    maker_behaviors = [Normal, Normal],
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = protocol, sats = 500_000, makers = 2, tx_count = 3),
    cases = [
        taproot_maker_settles_an_incoming_its_own_sweep_spent(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        /// A Legacy hashlock sweep spends the contract output too, and on
        /// Electrum the settling spend is read from the indexer.
        legacy_electrum_maker_settles_an_incoming_its_own_sweep_spent(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
        ),
    ],
)]
fn run_maker_settles_an_incoming_its_own_sweep_spent(world: &mut World, params: SwapParams) {
    world.mine(1);
    world.framework().wait_for_electrs_tip();

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

    // Nobody knows the preimage yet, so Maker2 has built no sweep. Hold the
    // wallet lock so no save lands mid-copy.
    let victim = world.makers()[1].inner().clone();
    let mut victim_config = victim.config.clone();
    victim_config.password = Some("integration-test".to_string());
    let wallet_path = victim_config
        .data_dir
        .join("wallets")
        .join(&victim_config.wallet_name);
    let snapshot = victim_config.data_dir.join("wallet-before-sweep");
    let before_incoming = {
        let wallet = victim.wallet.read().unwrap();
        assert!(wallet.get_incoming_swapcoins_count() > 0);
        assert!(wallet.get_outgoing_swapcoins_count() > 0);
        fs::copy(&wallet_path, &snapshot).unwrap();
        wallet.get_incoming_swapcoins_count()
    };

    // The taker's claim puts the preimage on chain, and Maker2 sweeps by it.
    world.drop_takers();
    world.adopt_taker(Taker::init(taker_config).expect("taker restart should succeed"));
    let recovery_txids = |maker: &MakerServer| {
        maker
            .wallet
            .read()
            .unwrap()
            .swap_reports()
            .recovery
            .into_iter()
            .filter(|report| {
                report.swap_id == summary.swap_id
                    && report.role == SwapRole::Maker
                    && report.recovery_type == "hashlock"
            })
            .flat_map(|report| report.recovery_txids)
            .collect::<Vec<_>>()
    };
    wait_until!(
        Duration::from_secs(300),
        every Duration::from_secs(2),
        "Maker2 to sweep its incoming by hashlock",
        {
            let wallet = victim.wallet.read().unwrap();
            wallet.get_incoming_swapcoins_count() == 0
                && wallet.get_outgoing_swapcoins_count() == 0
        }
    );
    let mut sweeps = recovery_txids(&victim);
    sweeps.sort();
    assert_eq!(
        sweeps.len(),
        before_incoming,
        "Maker2 must record a hashlock sweep for every incoming contract"
    );
    assert!(
        sweeps.windows(2).all(|pair| pair[0] != pair[1]),
        "Maker2 recorded a hashlock sweep more than once"
    );
    // Test builds stop a maker once its recovery is done.
    world.shutdown_maker(1);
    let settled_snapshot = victim_config.data_dir.join("wallet-after-sweep");
    fs::copy(&wallet_path, &settled_snapshot).unwrap();
    drop(victim);

    // #1137 saves recovery reports and coin removal atomically. A retained
    // report alongside stale coins is no longer a possible crash state; test
    // both the pre-cleanup wallet and an idempotent settled-wallet restart.
    for wallet_snapshot in [&snapshot, &settled_snapshot] {
        info!("Restarting Maker2 on {}", wallet_snapshot.display());
        fs::copy(wallet_snapshot, &wallet_path).unwrap();

        let restarted = Arc::new(MakerServer::init(victim_config.clone()).expect("maker restart"));
        let restarted_thread = {
            let maker_clone = restarted.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        };

        if wallet_snapshot == &settled_snapshot {
            // An already empty wallet must still run startup before we check
            // that it kept the reports without recording the sweeps again.
            wait_for_makers_setup(std::slice::from_ref(&restarted), 120);
        }

        // Coin removal and the recovery report share one wallet save, so an
        // empty wallet replaces the old tracker's CleanedUp phase check.
        wait_until!(
            Duration::from_secs(180),
            every Duration::from_secs(2),
            "Maker2 to stop retrying a sweep of an incoming it already swept",
            {
                let wallet = restarted.wallet.read().unwrap();
                wallet.get_incoming_swapcoins_count() == 0
                    && wallet.get_outgoing_swapcoins_count() == 0
            }
        );
        restarted.shutdown.store(true, Relaxed);
        restarted_thread.join().unwrap();

        let mut recorded_sweeps = recovery_txids(&restarted);
        recorded_sweeps.sort();
        assert_eq!(
            recorded_sweeps, sweeps,
            "the wallet reports must name each confirmed sweep, once"
        );
    }
}

/// A maker that reserved inputs for a funding it never sent must still hold
/// them after a restart: that funding can still reach the network, and handing
/// those inputs to another swap would invite a conflicting transaction.
///
/// Route: Taker -> Maker1 (Normal) -> Maker2 (skips its funding broadcast and
/// saves the write-ahead commitment). Maker2 must keep what it reserved.
#[world_test(
    maker_behaviors = [Normal, SkipFundingBroadcast],
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
    let log_offset = log_mark(&log_path);

    // Init only reloads state; `start_server` is what runs startup recovery.
    // The reservation has to survive that too, or a maker could reuse an input
    // from a funding transaction that can still be broadcast.
    world.adopt_makers([Arc::new(MakerServer::init(victim_config).unwrap())]);
    world.start_makers_without_sync(120);
    // Startup recovery runs on its own thread, past is_setup_complete: wait
    // until it has started on the unfinished swap before reading the
    // reservation count, or the assertion can pass without recovery running.
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_millis(500),
        "restart recovery to start on the unfinished swap",
        std::fs::read_to_string(&log_path)
            .unwrap_or_default()
            .get(log_offset as usize..)
            .is_some_and(|tail| tail.contains("recover_from_swap started"))
    );

    let after = world.makers()[0].inner().reserved_inputs().unwrap();
    assert_eq!(
        after, before,
        "startup recovery must not free inputs the planned funding can still spend"
    );

    // Absence from the chain never frees a committed transaction's inputs.
    let restarted = world.makers()[0].inner();
    let wallet = restarted.wallet.read().unwrap();
    assert!(wallet.get_outgoing_swapcoins_count() > 0);
    drop(wallet);
    assert_eq!(restarted.reserved_inputs().unwrap(), before);
}

/// A maker restarted inside the grace after its first Legacy funding send
/// failed still holds the inputs, then frees them when the grace ends,
/// counted from its funding claim, not the restart. The keys stay.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailFirstBroadcast],
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Legacy, sats = 500_000, makers = 1, tx_count = 1),
)]
fn unsent_funding_grace_survives_a_maker_restart(world: &mut World, params: SwapParams) {
    let summary = world.taker_mut().prepare(params).expect("prepare swap");
    let swap_id = summary.swap_id.clone();
    assert!(
        world.taker_mut().start(&swap_id).is_err(),
        "the swap must fail at the maker's first funding send"
    );
    let held = world.makers()[0].inner().reserved_inputs().unwrap();
    assert!(held > 0, "the failed send must keep its inputs reserved");

    // Restart well inside the grace.
    thread::sleep(Duration::from_secs(30));
    let log_path = world.taker_log_path();
    let mark = log_mark(&log_path);
    world.restart_maker(0, 120);
    let restarted_at = Instant::now();
    wait_until!(
        Duration::from_secs(60),
        every Duration::from_millis(500),
        "restart recovery to start on the unsent swap",
        fs::read_to_string(&log_path)
            .unwrap_or_default()
            .get(mark as usize..)
            .is_some_and(|tail| tail.contains("recover_from_swap started"))
    );
    let maker = world.makers()[0].inner().clone();
    assert_eq!(maker.reserved_inputs().unwrap(), held);

    wait_for_release(&log_path, &swap_id);
    assert!(
        restarted_at.elapsed() < openswap::utill::UNBROADCAST_DISCARD_GRACE,
        "the grace must count from the funding claim, not the restart"
    );
    assert_eq!(maker.reserved_inputs().unwrap(), 0);
    assert!(maker.has_unfinished_outgoing_swapcoin(&swap_id).unwrap());
    assert!(maker.wallet.read().unwrap().get_incoming_swapcoins_count() > 0);
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
    assert_log!(world; { has "nothing left owns it" });
    assert_eq!(
        world.makers()[0].inner().reserved_inputs().unwrap(),
        0,
        "no swap owns the claim, so the restart must free it"
    );

    world.shutdown_makers();
    drop(taker);
}
