//! Reboot and crash recovery, both protocols.
//!
//! A restarted node knows its live swaps only from what it persisted. This
//! file proves each piece of that: funded swapcoins survive a maker reboot
//! with no tracker record yet, startup rebuilds every contract watch, and a
//! crash inside the contract-acceptance window loses nothing.
//!
//! Route for the reboot case: Taker -> Maker1 (Normal) -> Maker2 (closes at
//! handover) -> Taker. Maker2 broadcasts its funding transaction and persists
//! unfinished swapcoins, then is restarted before idle recovery can write a
//! tracker record. Startup recovery must not discard the persisted swapcoins
//! merely because it cannot find a matching tracker record.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    net::TcpStream,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
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
pub(crate) fn run_reboot_recovery<B: TestBackend>() {
    run_reboot_recovery_with_watcher::<B>(true);
}

pub(crate) fn run_reboot_recovery_without_watcher<B: TestBackend>() {
    run_reboot_recovery_with_watcher::<B>(false);
}

fn run_reboot_recovery_with_watcher<B: TestBackend>(watcher_available: bool) {
    warn!("Running Test: Taproot Maker Reboot Recovery Preserves Funded Swapcoins");

    let makers_config_map = vec![(7602, Some(20601)), (17602, Some(20602))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::CloseAtPrivateKeyHandover,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
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
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to Maker2 closing at private key handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    let victim = makers[1].clone();
    victim
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
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

    let mut restarted_server = MakerServer::init(victim_config).unwrap();
    if !watcher_available {
        restarted_server.behavior = MakerBehavior::StopWatcherOnStartup;
    }
    let restarted = Arc::new(restarted_server);
    let restarted_thread = {
        let maker_clone = restarted.clone();
        thread::spawn(move || {
            start_server(maker_clone).unwrap();
        })
    };

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    // Recovery takes longer under parallel load; wait for the markers instead
    // of asserting at a fixed wall-clock point.
    if watcher_available {
        wait_for_makers_setup(std::slice::from_ref(&restarted), 120);
        thread::sleep(Duration::from_secs(5));

        let after_incoming = restarted
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count();
        wait_for_log(
            &log_path,
            "Incomplete swaps detected on startup",
            Duration::from_secs(120),
        );
        wait_for_log(
            &log_path,
            "recover_from_swap started",
            Duration::from_secs(120),
        );
        wait_for_log(
            &log_path,
            "Removed outgoing swapcoin",
            Duration::from_secs(120),
        );
        let log_contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            !log_contents.contains("Funding was never broadcast for swap"),
            "reboot recovery took the unsafe discard path"
        );
        let recovered_via_hashlock = log_contents.contains("incoming swapcoins via hashlock");

        restarted.shutdown.store(true, Relaxed);
        restarted_thread.join().unwrap();
        assert!(
            after_incoming > 0 || recovered_via_hashlock,
            "maker reboot recovery lost funded incoming swapcoins without hashlock recovery; before={}, after={}",
            before_incoming,
            after_incoming
        );
    } else {
        wait_for_log(
            &log_path,
            "Incomplete swaps detected on startup",
            Duration::from_secs(120),
        );
        assert!(
            TcpStream::connect(("127.0.0.1", restarted.config.network_port)).is_err(),
            "recovery-only maker must not accept swap connections"
        );
        wait_for_log(
            &log_path,
            &format!(
                "[{}] Recovered {} incoming swapcoins via hashlock",
                restarted.config.network_port, before_incoming
            ),
            Duration::from_secs(120),
        );
        assert!(!restarted.is_setup_complete.load(Relaxed));
        restarted_thread.join().unwrap();

        let wallet = restarted.wallet.read().unwrap();
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

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_taproot_maker_reboot_recovery_preserves_funded_swapcoins() {
    run_reboot_recovery::<BitcoindBackend>();
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
pub(crate) fn run_restart_rebuilds_watches<B: TestBackend>(
    protocol: ProtocolVersion,
    crash_behavior: TakerBehavior,
) {
    warn!("Running Test: Restart Rebuilds Watches ({protocol:?}, {crash_behavior:?})");

    // The framework assigns real ports itself; these entries only set the count.
    let makers_config_map = vec![(0, None), (0, None)];
    // All three die holding unclaimed contracts, none of them recovering in
    // process, so only the restarts can settle anything.
    let taker_behavior = vec![crash_behavior];
    let maker_behaviors = vec![
        MakerBehavior::CrashBeforeRecovery,
        MakerBehavior::CrashBeforeRecovery,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
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
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail because the taker crashes before finalization"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    // All three are left holding unclaimed contracts, and none of them recovers
    // in process. That holds by construction, not by timing.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    assert!(
        taker
            .get_wallet()
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            > 0,
        "taker should still hold an incoming contract before the restart"
    );
    // The first init consumed the passphrases (`config.password.take()`), so
    // re-supply them to simulate the operator re-entering them on restart.
    let mut taker_config = taker.config().clone();
    taker_config.password = Some("integration-test".to_string());
    let is_electrum = taker.get_wallet().read().unwrap().is_electrum();

    let mut maker_configs = Vec::new();
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        assert!(
            maker.wallet.read().unwrap().get_incoming_swapcoins_count() > 0,
            "maker {} should still hold an incoming contract before the restart",
            i
        );
        let mut config = maker.config.clone();
        config.password = Some("integration-test".to_string());
        maker_configs.push(config);
    }

    // Freeze the chain here. Left running, the miner races past every refund
    // deadline and each party takes the cheaper timelock refund instead of
    // waiting to learn the preimage — the cascade would never happen.
    test_framework.set_block_gen_paused(true);

    // Dropping the taker and stopping the makers leaves every watcher empty, so
    // each restart has to rebuild from its own wallet.
    drop(takers);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(makers);

    // The claims still need confirmations, so mine by hand — slowly enough that
    // no timelock matures while the cascade runs.
    let mining = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let slow_miner = {
        let mining = mining.clone();
        let tf = test_framework.clone();
        thread::spawn(move || {
            while mining.load(Relaxed) {
                thread::sleep(Duration::from_secs(5));
                generate_blocks(&tf.bitcoind, 1);
            }
        })
    };

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_len = || std::fs::read_to_string(&log_path).unwrap_or_default().len();
    let since = |offset: usize| {
        let all = std::fs::read_to_string(&log_path).unwrap_or_default();
        all[offset.min(all.len())..].to_string()
    };

    // ---- The taker restarts first: its sweep is what puts the preimage on chain.
    let taker_offset = log_len();
    info!("Restarting the taker with an empty watcher...");
    let restarted = Taker::init(taker_config).expect("taker restart should succeed");

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

    restarted
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    assert_eq!(
        restarted
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
    let remade: Vec<Arc<MakerServer>> = maker_configs
        .into_iter()
        .map(|cfg| Arc::new(MakerServer::init(cfg).expect("maker restart should succeed")))
        .collect();
    let remade_threads = remade
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&remade, 120);

    // Each maker must claim its *incoming* side with the preimage. A bare
    // "Recovered" also matches the outgoing timelock line, which proves nothing.
    for maker in &remade {
        let port = maker.config.network_port;
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
    test_framework.set_block_gen_paused(false);
    generate_blocks(bitcoind, 2);

    for maker in &remade {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Restarted maker {} balances: regular: {}, swap: {}, contract: {}",
            maker.config.network_port, balances.regular, balances.swap, balances.contract,
        );
        assert_eq!(
            maker.wallet.read().unwrap().get_incoming_swapcoins_count(),
            0,
            "maker {} still holds an incoming contract",
            maker.config.network_port
        );
    }

    // Maker1 took the taker's outgoing contract with the preimage, so nothing is
    // left locked on the taker's side either.
    restarted
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = restarted
        .get_wallet()
        .read()
        .unwrap()
        .get_balances()
        .unwrap();
    info!(
        "Restarted taker balances: regular: {}, swap: {}, contract: {}",
        taker_balances.regular, taker_balances.swap, taker_balances.contract,
    );
    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "restarted taker left a contract unresolved"
    );

    remade
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    remade_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_taproot_restart_rebuilds_watches() {
    run_restart_rebuilds_watches::<BitcoindBackend>(
        ProtocolVersion::Taproot,
        TakerBehavior::CrashBeforeRecovery,
    );
}

#[test]
fn test_legacy_electrum_restart_rebuilds_watches() {
    run_restart_rebuilds_watches::<ElectrumBackend>(
        ProtocolVersion::Legacy,
        TakerBehavior::CrashBeforeRecovery,
    );
}

// The taker dies right after the contract exchange — before the old code ever
// persisted what it was owed. The pre-restart `incoming count > 0` assertion
// above is the proof: red without acceptance-time persistence, green with it.
#[test]
fn test_taproot_crash_after_contract_exchange() {
    run_restart_rebuilds_watches::<BitcoindBackend>(
        ProtocolVersion::Taproot,
        TakerBehavior::CrashAfterContractExchange,
    );
}

#[test]
fn test_legacy_electrum_crash_after_contract_exchange() {
    run_restart_rebuilds_watches::<ElectrumBackend>(
        ProtocolVersion::Legacy,
        TakerBehavior::CrashAfterContractExchange,
    );
}
