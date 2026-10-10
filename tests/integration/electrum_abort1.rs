//! Abort 1 (Electrum backend): TAKER Drops After Full Setup.
//!
//! Same scenario as `abort1.rs`, but every participant runs on the Electrum
//! backend, and the scenario runs over both protocols (Taproot and Legacy).
//! This is the most Electrum-critical abort case: the taker vanishes after
//! broadcasting the funding transactions, so the makers must detect the
//! failure autonomously and recover via the preimage/hashlock cascade or
//! timelock. On Electrum that detection path has no ZMQ and no mempool scan —
//! it depends entirely on script subscriptions (`subscribe_script`/`poll_event`),
//! `get_tx_out` confirmation gating, and header-by-hash resolution.
//!
//! The Taker drops the connection after broadcasting all the funding transactions.
//! The Makers identify this and wait for a timeout (60s in test) for the Taker to come back.
//! If the Taker doesn't return, the Makers broadcast the contract transactions and reclaim
//! their funds via timelock.
//!
//! The Taker after coming live again will see unfinished openswaps in its wallet.
//! It can reclaim funds via broadcasting contract transactions and claiming via timelock.

use bitcoin::{Amount, OutPoint, Txid};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    fs, thread,
    time::{Duration, Instant},
};

/// Exact post-recovery balances for one protocol run. Fees differ between the
/// Legacy and Taproot transaction shapes (and locktime values), so each
/// protocol pins its own values.
pub(crate) struct ExpectedBalances {
    taker_regular: u64,
    taker_swap: u64,
    taker_spendable_diff: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    maker_spendable: [u64; 2],
}

pub(crate) const LEGACY_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14499538,
    taker_swap: 495997,
    taker_spendable_diff: 4465,
    maker_regular: [14500865, 14502398],
    maker_swap: [499100, 497530],
    maker_spendable: [14999965, 14999928],
};

pub(crate) const TAPROOT_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14499538,
    taker_swap: 496660,
    taker_spendable_diff: 3802,
    maker_regular: [14500751, 14502170],
    maker_swap: [499535, 498079],
    maker_spendable: [15000286, 15000249],
};

/// Run the abort1 scenario (taker drops after funds broadcast) with the given
/// protocol and assert the exact recovery balances.
///
/// Generic over the backend so `electrum_tor.rs` can run the identical body over
/// Tor and assert the same balances.
pub(crate) fn run_abort1<B: TestBackend>(protocol: ProtocolVersion, expected: &ExpectedBalances) {
    // ---- Setup ----
    warn!("Running Test: Taker Drops After Full Setup (Electrum backend, {protocol:?})");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::DropAfterFundsBroadcast];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each
    let taker_original_balance = fund_taker_default(taker, bitcoind, 3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

    // Start the maker server threads
    log::info!("Initiating Maker servers");

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup
    sync_maker_wallets(&makers);

    verify_maker_pre_swap_balances(&makers);

    // Initiate OpenSwap
    info!("Initiating openswap protocol");

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Start periodic swap tracker logging
    let tracker_logger = spawn_tracker_logger(
        test_framework.temp_dir.join("taker1"),
        Duration::from_secs(10),
    );

    // Prepare should succeed; execution should fail with DropAfterFundsBroadcast
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_result = taker.start_swap(&summary.swap_id);
    let swap_error = swap_result.expect_err("Swap should fail due to test behavior");
    assert!(
        matches!(
            &swap_error,
            openswap::taker::error::TakerError::General(message)
                if message == "Test: dropped after contract exchange"
        ),
        "Swap failed before the injected abort: {:?}",
        swap_error
    );
    info!("Swap failed as expected: {swap_error:?}");
    taker.log_tracker_state();

    // Wait for makers to detect the drop and the outer timelock to mature;
    // slower-cadence backends (Tor) wait proportionally longer.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(timelock_recovery_wait::<B>());

    // Verify maker balances after recovery
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.spendable,
        );
        assert_eq!(
            maker_balances.contract,
            Amount::ZERO,
            "Maker {} should have no contract balance after recovery",
            i
        );
    }

    info!("Makers shut down. Waiting for background recovery loop to complete...");

    // Wait for taker's background recovery loop to finish
    let recovery_timeout = Duration::from_secs(120);
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        if recovery_start.elapsed() > recovery_timeout {
            panic!("Background recovery did not complete within timeout");
        }
        thread::sleep(Duration::from_secs(5));
    }
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    generate_blocks(bitcoind, 1);
    // electrs indexes asynchronously; without the wait the sync can read a
    // stale tip and the exact balance assertions below flake.
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Verify taker balance
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    assert_eq!(
        taker_balances.regular.to_sat(),
        expected.taker_regular,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        expected.taker_swap,
        "Taker swap balance"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    assert_eq!(
        balance_diff.to_sat(),
        expected.taker_spendable_diff,
        "Taker spendable balance change"
    );

    // Verify maker balances - makers should have recovered via timelock
    for (i, maker) in makers.iter().enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let maker_balances = maker.wallet.read().unwrap().get_balances().unwrap();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            maker_balances.regular,
            maker_balances.swap,
            maker_balances.contract,
            maker_balances.fidelity,
            maker_balances.spendable,
        );

        assert_eq!(
            maker_balances.regular.to_sat(),
            expected.maker_regular[i],
            "Maker {i} regular balance"
        );
        assert_eq!(
            maker_balances.swap.to_sat(),
            expected.maker_swap[i],
            "Maker {i} swap balance"
        );
        assert_eq!(
            maker_balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(maker_balances.fidelity, Amount::from_btc(0.05).unwrap());

        assert_eq!(
            maker_balances.spendable.to_sat(),
            expected.maker_spendable[i],
            "Maker {i} spendable balance"
        );
    }

    taker.log_tracker_state();
    info!("Electrum abort1 test ({protocol:?}) completed successfully!");

    shutdown_makers(&makers, maker_threads);

    tracker_logger.stop();
    // Drop the taker while relay, electrs, and bitcoind are still up, so its
    // background services shut down against live servers instead of dead ones.
    test_framework.finish(takers, block_generation_handle);
}

#[test]
fn taker_abort_1_taproot_electrum() {
    run_abort1::<ElectrumBackend>(ProtocolVersion::Taproot, &TAPROOT_EXPECTED);
}

#[test]
fn taker_abort_1_legacy_electrum() {
    run_abort1::<ElectrumBackend>(ProtocolVersion::Legacy, &LEGACY_EXPECTED);
}

/// A breached taker recovers all its incoming coins once the contracts
/// confirm; recovery never blocks on an unconfirmed contract.
///
/// The last maker broadcasts the taker's incoming contract txs and closes.
/// Recovery skips each contract while it is unconfirmed and sweeps it on a
/// later cycle, well inside the timelock window. This test asserts the
/// outcome — every incoming coin swept, no hang.
#[test]
fn electrum_sweeps_after_breach() {
    let maker_count = 2;
    // Skip the funding waits so recovery can meet the contracts unconfirmed.
    let taker_behavior = vec![TakerBehavior::SkipFundingConfirmWait];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::BroadcastContractAfterSetup,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker_default(taker, bitcoind, 3);
    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);

    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    let swap_params =
        SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2).with_tx_count(3);

    generate_blocks(bitcoind, 1);
    let swap_start_height = chain_tip(bitcoind) + 1;

    let log_path = test_framework.taker_log_path();
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");

    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the last maker closes"
    );

    // Three incoming contracts, all swept: the loop tallies them in one line.
    wait_for_log(
        &log_path,
        "Recovery loop: swept 3 incoming swapcoins",
        Duration::from_secs(180),
    );
    // The log line only proves the sweeps were broadcast. Confirm them and
    // check the money actually landed, otherwise a wrong-amount sweep passes.
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    let swapcoins_left = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_incoming_swapcoins_count();
    info!(
        "Sweeps-after-breach taker: regular {}, swap {}, contract {}, spendable {}, incoming swapcoins {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
        swapcoins_left,
    );
    assert_eq!(
        swapcoins_left, 0,
        "Every incoming swapcoin should be swept out of the wallet"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        495_997,
        "Swept swap balance mismatch"
    );
    assert_eq!(
        taker_balances.regular.to_sat(),
        14_499_538,
        "Taker regular balance mismatch"
    );

    // Recovery sweeps sit at depth 2 (they spend the broadcast contract txs).
    // Each pays the relay floor at the 150 vB legacy spend model — the
    // accepted B12 fallback until recovery fees are estimated at spend time.
    // Depths 0 and 1 vary with how much of the sweep cascade lands before the
    // call, so this asserts the sweeps directly instead of pinning them.
    let depths = txs_by_spend_depth(bitcoind, swap_start_height);
    assert_eq!(
        depths.get(2).map_or(0, Vec::len),
        3,
        "exactly three recovery sweeps must sit at depth 2"
    );
    for txid in &depths[2] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(
            fee, 150,
            "recovery sweep {} must pay the 150 vB model",
            txid
        );
        assert!(
            vsize <= 150,
            "recovery sweep {} exceeds its 150 vB model",
            txid
        );
    }

    shutdown_makers(&makers, maker_threads);

    test_framework.finish(takers, block_generation_handle);
}

/// Plan A4: a swapcoin whose contract output is spent only in the mempool
/// must survive recovery; once that spend confirms, the coin is discarded.
///
/// The abort1 cascade makes maker 0 sweep the taker's outgoing contracts
/// with the hashlock preimage. Mining is paused while that sweep is a
/// mempool tx: the taker's recovery must keep its outgoing coins (a mempool
/// spend can be evicted). After the sweep confirms, they are discarded.
#[test]
fn electrum_discards_only_on_confirmed_spend() {
    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::DropAfterFundsBroadcast];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<ElectrumBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker_default(taker, bitcoind, 3);
    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);

    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    let swap_params =
        SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2).with_tx_count(3);

    generate_blocks(bitcoind, 1);

    let log_path = test_framework.taker_log_path();
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");

    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the last maker closes"
    );

    // The cascade: taker sweeps its incoming, maker 1 extracts the preimage
    // and sweeps its incoming, then maker 0 announces it will sweep too.
    wait_for_log(
        &log_path,
        "All preimages known, recovering via hashlock path",
        Duration::from_secs(300),
    );

    // Hold the chain still: maker 0's hashlock sweep of the taker's outgoing
    // contracts now sits in the mempool as an unconfirmed spend.
    test_framework.set_block_gen_paused(true);
    thread::sleep(Duration::from_secs(10));

    let surviving = taker
        .get_wallet()
        .read()
        .unwrap()
        .get_outgoing_swapcoins_count();
    assert_eq!(
        surviving, 3,
        "Outgoing swapcoins must survive a mempool-only spend of their contracts"
    );

    // Let the sweep confirm; the next recovery cycles must discard the coins.
    test_framework.set_block_gen_paused(false);
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let remaining = taker
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count();
        if remaining == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Outgoing swapcoins were not discarded after the spend confirmed"
        );
        thread::sleep(Duration::from_secs(5));
    }

    shutdown_makers(&makers, maker_threads);

    test_framework.finish(takers, block_generation_handle);
}

/// Recovery reads its fee estimate from here in test builds: regtest has none.
const FEERATE_ENV: &str = "OPENSWAP_RECOVERY_FEERATE";

/// Names the feerate recovery sees, and clears it on drop so it cannot leak
/// into another test in this process.
struct FeerateOverride;

impl FeerateOverride {
    fn set(&self, sat_per_vb: u64) {
        std::env::set_var(FEERATE_ENV, sat_per_vb.to_string());
    }
}

impl Drop for FeerateOverride {
    fn drop(&mut self) {
        std::env::remove_var(FEERATE_ENV);
    }
}

/// The mempool tx spending `outpoint`, straight from bitcoind.
fn mempool_spender(bitcoind: &BitcoinD, outpoint: &OutPoint) -> Option<Txid> {
    let spends: serde_json::Value = bitcoind
        .client
        .call(
            "gettxspendingprevout",
            &[serde_json::json!([{ "txid": outpoint.txid, "vout": outpoint.vout }])],
        )
        .unwrap();
    spends[0]["spendingtxid"]
        .as_str()
        .map(|txid| txid.parse().unwrap())
}

/// Every `(old, new)` pair the taker logged as a replaced refund.
fn logged_replacements(log_path: &str) -> Vec<(Txid, Txid)> {
    fs::read_to_string(log_path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| {
            let rest = line.split_once("Replaced timelock recovery tx ")?.1;
            let (old, rest) = rest.split_once(" with ")?;
            let new = rest.split_once(' ')?.0;
            Some((old.parse().ok()?, new.parse().ok()?))
        })
        .collect()
}

/// Polls `probe` until it answers, failing the test after `timeout`.
fn wait_until<T>(what: &str, timeout: Duration, mut probe: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(found) = probe() {
            return found;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {}", what);
        thread::sleep(Duration::from_millis(200));
    }
}

/// Follows a stuck timelock refund through its fee bumps on a real node.
///
/// The second maker drops once funding is on chain, so the taker refunds its
/// outgoing coin by timelock. Mining stops just before that refund goes out.
/// A recovery pass parks in its confirmation wait after every broadcast, so
/// the taker is restarted wherever the test needs a fresh pass.
///
/// `full` adds the checks the Electrum backend is tested for: no bump while
/// fees are flat, a second bump, and silence once the refund confirms.
pub(crate) fn run_refund_fee_bump<B: TestBackend>(
    protocol: ProtocolVersion,
    full: bool,
    expected_spendable_diff: u64,
) {
    warn!("Running Test: refund fee bump ({protocol:?})");

    let closing = match protocol {
        ProtocolVersion::Legacy => MakerBehavior::CloseAtContractSigsForRecvrAndSender,
        ProtocolVersion::Taproot => MakerBehavior::CloseAtContractSigsExchange,
    };
    let (test_framework, mut takers, makers, block_generation_handle) = TestFramework::init::<B>(
        2,
        vec![TakerBehavior::Normal],
        vec![MakerBehavior::Normal, closing],
    );
    let bitcoind = &test_framework.bitcoind;
    let mut taker = takers.remove(0);
    let feerate = FeerateOverride;

    let taker_original_balance = fund_taker_default(&taker, bitcoind, 3);
    fund_makers_default(&makers, bitcoind);
    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);

    // One outgoing coin, so the test follows exactly one refund.
    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    let swap_error = taker
        .start_swap(&summary.swap_id)
        .expect_err("Swap should fail once the second maker closes");
    info!("Swap failed as expected: {swap_error:?}");

    let log_path = test_framework.taker_log_path();
    let refund_targets =
        |taker: &Taker| taker.get_wallet().read().unwrap().outgoing_refund_targets();
    let targets = refund_targets(&taker);
    assert_eq!(targets.len(), 1, "expected one outgoing swapcoin");
    let (contract, timelock, _) = targets[0].clone();
    let timelock = i64::from(timelock.expect("outgoing coin has a timelock"));

    // ---- 1. The refund gets stuck ----
    // Taproot locks to a height; Legacy to confirmations of the contract tx,
    // which recovery broadcasts first.
    let blocks_left = || match protocol {
        ProtocolVersion::Taproot => {
            Some(timelock - bitcoind.client.get_block_count().unwrap() as i64)
        }
        ProtocolVersion::Legacy => bitcoind
            .client
            .get_raw_transaction_info(&contract.txid, None)
            .ok()
            .and_then(|info| info.confirmations)
            .map(|confirmations| timelock - i64::from(confirmations)),
    };
    // Stop the miner a few ticks short of the timelock, then step onto it by
    // hand: the refund goes out with nothing left to confirm it.
    wait_until(
        "the timelock to come close",
        Duration::from_secs(400),
        || blocks_left().filter(|left| *left <= 15),
    );
    test_framework.set_block_gen_paused(true);
    // A tick already under way may still land.
    thread::sleep(B::block_cadence().1 + Duration::from_secs(1));
    let left = blocks_left().unwrap();
    if left > 0 {
        generate_blocks(bitcoind, left as u64);
    }
    test_framework.wait_for_electrs_tip();

    let first = wait_until(
        "the refund to reach the mempool",
        Duration::from_secs(120),
        || mempool_spender(bitcoind, &contract),
    );
    let first_fee = bitcoind.client.get_mempool_entry(&first).unwrap().fees.base;
    assert_eq!(
        taker
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        1,
        "the outgoing swapcoin must stay while its refund is unconfirmed"
    );
    let recovery_script = refund_targets(&taker)[0]
        .2
        .clone()
        .expect("a broadcast refund saves its address")
        .assume_checked()
        .script_pubkey();
    let pays_saved_address = |txid: &Txid| {
        let tx = bitcoind.client.get_raw_transaction(txid, None).unwrap();
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.input[0].previous_output, contract);
        assert!(
            tx.input[0].sequence.is_rbf(),
            "refund {} must signal RBF",
            txid
        );
        assert_eq!(tx.output.len(), 1);
        assert_eq!(
            tx.output[0].script_pubkey, recovery_script,
            "refund {} must pay the saved recovery address",
            txid
        );
    };
    pays_saved_address(&first);

    // Starts a fresh taker on the same wallet: its startup pass and recovery
    // loop run while the previous loop's pass would still be waiting.
    let restart = |taker: Taker| {
        drop(taker);
        thread::sleep(Duration::from_secs(5));
        Taker::init(test_framework.taker_init_config::<B>(0))
            .expect("restarted taker should open the same wallet")
    };
    // A bump shows as a logged replacement of `old`, now in the mempool.
    let wait_for_bump = |old: Txid| {
        let new = wait_until(
            "the refund to be replaced",
            Duration::from_secs(120),
            || {
                logged_replacements(&log_path)
                    .into_iter()
                    .find(|(replaced, _)| *replaced == old)
                    .map(|(_, new)| new)
            },
        );
        assert_eq!(mempool_spender(bitcoind, &contract), Some(new));
        assert!(
            bitcoind.client.get_mempool_entry(&old).is_err(),
            "replaced refund {} must leave the mempool",
            old
        );
        pays_saved_address(&new);
        new
    };

    // ---- 2. No bump while fees stay flat ----
    taker = restart(taker);
    if full {
        // Several recovery passes run in this window.
        thread::sleep(Duration::from_secs(35));
        assert_eq!(mempool_spender(bitcoind, &contract), Some(first));
        assert!(logged_replacements(&log_path).is_empty());
    }

    // ---- 3. A bump once fees rise ----
    feerate.set(5);
    let mut latest = wait_for_bump(first);
    let entry = bitcoind.client.get_mempool_entry(&latest).unwrap();
    assert!(
        entry.fees.base >= first_fee + Amount::from_sat(entry.vsize),
        "replacement fee {} must beat {} by 1 sat/vB over {} vB",
        entry.fees.base,
        first_fee,
        entry.vsize
    );

    // ---- 4. A second bump works too ----
    if full {
        taker = restart(taker);
        feerate.set(12);
        latest = wait_for_bump(latest);
    }
    let bumps = logged_replacements(&log_path).len();

    // ---- 5. It confirms and settles ----
    test_framework.set_block_gen_paused(false);
    wait_until("recovery to complete", Duration::from_secs(180), || {
        taker.is_recovery_complete().then_some(())
    });
    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let confirmations = bitcoind
        .client
        .get_raw_transaction_info(&latest, None)
        .unwrap()
        .confirmations;
    assert!(
        confirmations.is_some_and(|c| c > 0),
        "the latest replacement {} must confirm",
        latest
    );
    assert_eq!(
        taker
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        0
    );
    let balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances after the bumped refund: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        balances.regular, balances.swap, balances.contract, balances.spendable,
    );
    assert_eq!(balances.contract, Amount::ZERO);
    let spendable_diff = taker_original_balance
        .checked_sub(balances.spendable)
        .unwrap();
    info!("Taker spendable diff after the bumped refund: {spendable_diff}");
    assert_eq!(
        spendable_diff.to_sat(),
        expected_spendable_diff,
        "Taker spendable balance change"
    );

    // ---- 6. Nothing happens after that ----
    if full {
        thread::sleep(Duration::from_secs(30));
        assert_eq!(logged_replacements(&log_path).len(), bumps);
        assert_eq!(mempool_spender(bitcoind, &contract), None);
    }

    shutdown_makers(&makers, maker_threads);
    test_framework.finish(vec![taker], block_generation_handle);
}

/// Real electrs must hide a contract output its mempool spends, or the bump
/// never fires: the unit tests only assume it does.
#[test]
fn electrum_bumps_a_stuck_taproot_refund() {
    run_refund_fee_bump::<ElectrumBackend>(ProtocolVersion::Taproot, true, 1834);
}

#[test]
fn electrum_bumps_a_stuck_legacy_refund() {
    run_refund_fee_bump::<ElectrumBackend>(ProtocolVersion::Legacy, true, 2008);
}
