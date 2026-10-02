//! Recovery on the Electrum backend: the taker drops after full setup (both
//! protocols, and over Tor), and a breached taker sweeps once contracts confirm.
//!
//! The drop is the scenario of `taker_abort::legacy_drop_after_funding`, but
//! every participant runs on the Electrum backend, over both protocols.
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

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams},
};

use super::test_framework::*;

use log::info;
use std::{
    thread,
    time::{Duration, Instant},
};

/// Exact post-recovery balances for one protocol run. Fees differ between the
/// Legacy and Taproot transaction shapes (and locktime values), so each
/// protocol pins its own values.
struct ExpectedBalances {
    taker_regular: u64,
    taker_swap: u64,
    taker_spendable_diff: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    maker_spendable: [u64; 2],
}

const LEGACY_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14499538,
    taker_swap: 495997,
    taker_spendable_diff: 4465,
    maker_regular: [14500865, 14502398],
    maker_swap: [499100, 497530],
    maker_spendable: [14999965, 14999928],
};

const TAPROOT_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14499538,
    taker_swap: 496660,
    taker_spendable_diff: 3802,
    maker_regular: [14500751, 14502170],
    maker_swap: [499535, 498079],
    maker_spendable: [15000286, 15000249],
};

/// Run the taker-drops-after-funding scenario with the given
/// protocol and assert the exact recovery balances.
///
/// The Tor rows run the identical body over [`TorElectrumBackend`] and assert
/// the same balances, so a Tor-specific divergence in any watchtower path fails
/// loudly. The taker vanishes after funding is on-chain, so makers must detect
/// it with no ZMQ and no mempool scan: `subscribe_script` / `poll_event`, the
/// preimage/hashlock cascade, timelock fallback, and `unsubscribe_script` on
/// cleanup. See the integration README for running the Tor rows.
#[world_test(
    maker_behaviors = [Normal, Normal],
    takers = [DropAfterFundsBroadcast],
    cases = [
        taproot_taker_drops_after_funding(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
            expected = &TAPROOT_EXPECTED,
        ),
        legacy_taker_drops_after_funding(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            expected = &LEGACY_EXPECTED,
        ),
        /// The Taproot drop over Tor: the widest watchtower path in the suite.
        #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
        tor_taproot_taker_drops_after_funding(
            backend = TorElectrumBackend,
            skip_unless = tor_it_enabled(),
            protocol = ProtocolVersion::Taproot,
            expected = &TAPROOT_EXPECTED,
        ),
        /// The Legacy drop over Tor. Same cascade, different contract shape.
        #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
        tor_legacy_taker_drops_after_funding(
            backend = TorElectrumBackend,
            skip_unless = tor_it_enabled(),
            protocol = ProtocolVersion::Legacy,
            expected = &LEGACY_EXPECTED,
        ),
    ],
)]
fn run_taker_drops_after_funding<B: TestBackend>(
    world: &mut World,
    protocol: ProtocolVersion,
    expected: &ExpectedBalances,
) {
    // Fund the taker with 3 UTXOs of 0.05 BTC each
    let taker_original_balance = world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    // Start the maker servers, wait for their setup, then sync their wallets
    log::info!("Initiating Maker servers");
    world.start_makers(120);

    world.verify_maker_pre_swap_balances();

    // Initiate OpenSwap
    info!("Initiating openswap protocol");

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Start periodic swap tracker logging
    let tracker_logger = world.spawn_tracker_logger(Duration::from_secs(10));

    // Prepare should succeed; execution should fail with DropAfterFundsBroadcast
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    let swap_error = swap_result.expect_err("Swap should fail due to test behavior");
    assert!(
        matches!(
            &swap_error,
            TakerError::General(message)
                if message == "Test: dropped after contract exchange"
        ),
        "Swap failed before the injected abort: {:?}",
        swap_error
    );
    info!("Swap failed as expected: {swap_error:?}");
    world.taker().log_tracker_state();

    // Wait for makers to detect the drop and the outer timelock to mature;
    // slower-cadence backends (Tor) wait proportionally longer.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(timelock_recovery_wait::<B>());

    world.assert_makers_contract_zero();

    // Wait for taker's background recovery loop to finish
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
    // electrs indexes asynchronously; without the wait the sync can read a
    // stale tip and the exact balance assertions below flake.
    world.framework().wait_for_electrs_tip();
    world.taker().sync();

    // Verify taker balance
    let taker_balances = world.taker().balances();

    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    BalanceExpect {
        regular: Some(Is::Sats(expected.taker_regular)),
        swap: Some(Is::Sats(expected.taker_swap)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::CheckedUnwrap,
            sats: expected.taker_spendable_diff,
        }),
    }
    .assert("Taker", &taker_balances);

    // Verify maker balances - makers should have recovered via timelock
    for (i, maker) in world.makers().iter().enumerate() {
        maker.sync();
        let balances = maker.balances();

        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );

        BalanceExpect {
            regular: Some(Is::Sats(expected.maker_regular[i])),
            swap: Some(Is::Sats(expected.maker_swap[i])),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: Some(Is::Sats(expected.maker_spendable[i])),
            delta: None,
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    world.taker().log_tracker_state();
    info!("Electrum taker-drop test ({protocol:?}) completed successfully!");

    world.shutdown_makers();
    tracker_logger.stop();
}

/// A breached taker recovers all its incoming coins once the contracts
/// confirm; recovery never blocks on an unconfirmed contract.
///
/// The last maker broadcasts the taker's incoming contract txs and closes.
/// Recovery skips each contract while it is unconfirmed and sweeps it on a
/// later cycle, well inside the timelock window. This test asserts the
/// outcome — every incoming coin swept, no hang.
#[world_test(
    backend = ElectrumBackend,
    maker_behaviors = [Normal, BroadcastContractAfterSetup],
    // Skip the funding waits so recovery can meet the contracts unconfirmed.
    takers = [SkipFundingConfirmWait],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn sweeps_after_breach(world: &mut World, params: SwapParams) {
    world.mine(1);
    let swap_start_height = chain_tip(world.bitcoind()) + 1;

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");

    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the last maker closes"
    );

    // Three incoming contracts, all swept: the loop tallies them in one line.
    wait_logged!(
        world,
        "Recovery loop: swept 3 incoming swapcoins",
        Duration::from_secs(180)
    );
    // The log line only proves the sweeps were broadcast. Confirm them and
    // check the money actually landed, otherwise a wrong-amount sweep passes.
    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();
    let taker_balances = world.taker().balances();
    let swapcoins_left = world
        .taker()
        .inner()
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
    // Swap is checked ahead of regular here, which is not BalanceExpect's
    // field order, so these stay plain asserts.
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
    let bitcoind = world.bitcoind();
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
}

/// Plan A4: a swapcoin whose contract output is spent only in the mempool
/// must survive recovery; once that spend confirms, the coin is discarded.
///
/// The taker-drop cascade makes maker 0 sweep the taker's outgoing contracts
/// with the hashlock preimage. Mining is paused while that sweep is a
/// mempool tx: the taker's recovery must keep its outgoing coins (a mempool
/// spend can be evicted). After the sweep confirms, they are discarded.
#[world_test(
    backend = ElectrumBackend,
    maker_behaviors = [Normal, Normal],
    takers = [DropAfterFundsBroadcast],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn discards_only_on_confirmed_spend(world: &mut World, params: SwapParams) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");

    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail once the last maker closes"
    );

    // The cascade: taker sweeps its incoming, maker 1 extracts the preimage
    // and sweeps its incoming, then maker 0 announces it will sweep too.
    wait_logged!(
        world,
        "All preimages known, recovering via hashlock path",
        Duration::from_secs(300)
    );

    // Hold the chain still: maker 0's hashlock sweep of the taker's outgoing
    // contracts now sits in the mempool as an unconfirmed spend.
    world.framework().set_block_gen_paused(true);
    thread::sleep(Duration::from_secs(10));

    let outgoing_swapcoins = || {
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count()
    };
    let surviving = outgoing_swapcoins();
    assert_eq!(
        surviving, 3,
        "Outgoing swapcoins must survive a mempool-only spend of their contracts"
    );

    // Let the sweep confirm; the next recovery cycles must discard the coins.
    world.framework().set_block_gen_paused(false);
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let remaining = outgoing_swapcoins();
        if remaining == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "Outgoing swapcoins were not discarded after the spend confirmed"
        );
        thread::sleep(Duration::from_secs(5));
    }
}
