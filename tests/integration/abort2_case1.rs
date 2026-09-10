//! Maker drops before sending sender's contract sigs. Taker finds a spare maker and completes the swap.
//!
//! Setup: 3 makers (maker[0] Normal, maker[1] CloseAtReqContractSigsForSender, maker[2] Normal).
//! The taker only needs 2 makers for the route, so when maker[1] drops, it retries with the spare.
//! The swap should succeed.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::{MakerToTakerMessage, ProtocolVersion},
    taker::{SwapParams, TakerBehavior},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    fs,
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

#[test]
fn maker_abort2_case1() {
    warn!("Running Test: Maker drops before sending sender's sigs. Taker continues with spare.");

    let makers_config_map = vec![(6102, None), (16102, None), (26102, None)];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::CloseAtReqContractSigsForSender,
        MakerBehavior::Normal,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Start the maker server threads
    log::info!("Starting Maker servers...");

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

    // Sync wallets after setup to ensure fidelity bonds are accounted for
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare and execute the swap — taker should retry with the spare maker
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("Swap should succeed with spare maker");

    // Sync wallets and verify results
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    generate_blocks(bitcoind, 1);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    // Verify taker balance
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balance: original={}, after={}",
        taker_original_balance, taker_balances.spendable
    );

    assert_eq!(
        taker_balances.spendable.to_sat(),
        14995661,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // Verify makers earned fees (only the two that participated)
    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: original={}, after={}",
            i, original, balances.spendable
        );
        let expected_spendable = [15000577, 14999757, 15000540][i];
        assert_eq!(
            balances.spendable.to_sat(),
            expected_spendable,
            "Maker {} spendable balance mismatch",
            i
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
    }

    info!("maker_abort2_case1 completed successfully!");
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Heterogeneous offers: a non-terminal maker drops pre-broadcast, and every
/// spare prices its hop differently. The spare's derived next hop cannot match
/// what the downstream maker already admitted, so the swap must abort on the
/// shape check — never re-negotiate the downstream maker or exhaust the spares.
#[test]
fn heterogeneous_substitution_aborts_without_cascade() {
    warn!("Running Test: Heterogeneous offers — spare shape mismatch aborts without cascade");

    // Route is [maker0, maker1]; spares are popped from the back, so maker3 is
    // tried first. maker0 drops at ReqContractSigsForSender: after both hops
    // admitted SwapDetails, before any funding is on-chain.
    let makers_config_map = vec![(6102, None), (16102, None), (26102, None), (36102, None)];
    let fee_overrides = vec![
        Some(MakerFeeOverride {
            base_fee: 500,
            amount_relative_fee_pct: 0.0025,
        }),
        Some(MakerFeeOverride {
            base_fee: 800,
            amount_relative_fee_pct: 0.005,
        }),
        Some(MakerFeeOverride {
            base_fee: 1200,
            amount_relative_fee_pct: 0.0075,
        }),
        Some(MakerFeeOverride {
            base_fee: 950,
            amount_relative_fee_pct: 0.004,
        }),
    ];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::CloseAtReqContractSigsForSender,
        MakerBehavior::Normal,
        MakerBehavior::Normal,
        MakerBehavior::Normal,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_fee_overrides::<BitcoindBackend>(
            makers_config_map,
            fee_overrides,
            taker_behavior,
            maker_behaviors,
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
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

    log::info!("Starting Maker servers...");
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

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");

    // Route order follows the maker index (ports ascend), so hop 0 is the
    // dropper and hop 1 is the downstream maker that must never be re-negotiated.
    assert_eq!(summary.makers.len(), 2, "route should have 2 makers");
    assert!(
        summary.makers[0]
            .address
            .ends_with(&makers[0].config.network_port.to_string()),
        "hop 0 should be maker0 (the dropper), got {}",
        summary.makers[0].address
    );
    assert!(
        summary.makers[1]
            .address
            .ends_with(&makers[1].config.network_port.to_string()),
        "hop 1 should be maker1 (downstream), got {}",
        summary.makers[1].address
    );

    // Baseline: hop 1 admitted these exact terms; a replay is still accepted.
    let downstream_details = taker
        .current_swap_details(1)
        .expect("downstream swap details should rebuild");
    match taker
        .test_resend_swap_details(1)
        .expect("baseline resend should get an answer")
    {
        MakerToTakerMessage::AckSwapDetails(ack) => assert!(
            ack.tweakable_point.is_some(),
            "baseline resend of the admitted terms must be accepted"
        ),
        other => panic!("baseline resend got unexpected response: {:?}", other),
    }

    // maker0 drops; the spare prices hop 0 differently, so its derived next
    // hop cannot match what hop 1 admitted. The swap aborts on the shape check.
    let err = taker
        .start_swap(&summary.swap_id)
        .expect_err("swap must abort on the spare shape mismatch");
    info!("Swap aborted as expected: {:?}", err);

    // Snapshot once: assert_log echoes its needle into the same file, which
    // would poison the substitution count.
    let taker_log = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let taker_log_contents = fs::read_to_string(&taker_log).unwrap();
    assert!(
        taker_log_contents
            .contains("forwards a different shape than the failed maker; aborting swap"),
        "the swap must abort on the spare shape mismatch"
    );

    // Exactly one spare is popped; the second stays unused. The pre-fix cascade
    // re-negotiated downstream and burned spares until none were left.
    assert_eq!(
        taker_log_contents
            .matches("Pre-funding exchange failure, substituting maker 0 with spare")
            .count(),
        1,
        "exactly one spare substitution must be attempted"
    );
    assert!(
        !taker_log_contents.contains("no spare makers available"),
        "the swap must not cascade into exhausting the spare pool"
    );

    // No downstream maker was re-negotiated: no param-mismatch rejection
    // logged. All process logs (maker modules included) land in this one file;
    // the maker-side admission line proves they are captured here.
    assert!(
        taker_log_contents.contains("Accepting swap"),
        "maker admission logs should be captured in this file"
    );
    assert!(
        !taker_log_contents.contains("parameters differ from stored swap"),
        "a downstream maker was re-negotiated with different terms"
    );
    assert!(
        !taker_log_contents.contains("SwapParamMismatch"),
        "a downstream maker rejected re-negotiated terms"
    );

    // Hop 1 still honors the originally admitted terms after the abort.
    match taker
        .resend_swap_details(&summary.makers[1].address, &downstream_details)
        .expect("post-abort resend should get an answer")
    {
        MakerToTakerMessage::AckSwapDetails(ack) => assert!(
            ack.tweakable_point.is_some(),
            "downstream maker must still accept the originally admitted terms"
        ),
        other => panic!("post-abort resend got unexpected response: {:?}", other),
    }

    // Nothing reached the chain: every maker keeps its pre-swap balance.
    generate_blocks(bitcoind, 1);
    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: original={}, after={}",
            i, original, balances.spendable
        );
        assert_eq!(
            balances.spendable, original,
            "Maker {} balance moved though nothing was broadcast",
            i
        );
        assert_eq!(balances.contract, Amount::ZERO);
    }

    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balance: original={}, after={}",
        taker_original_balance, taker_balances.spendable
    );
    assert_eq!(
        taker_balances.spendable, taker_original_balance,
        "Taker balance moved though nothing was broadcast"
    );
    assert_eq!(taker_balances.contract, Amount::ZERO);

    info!("heterogeneous_substitution_aborts_without_cascade completed successfully!");
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Heterogeneous offers, last hop: the cheap maker in the last slot drops at
/// ReqContractSigsForSender and the only spare is expensive. No downstream
/// admission pins the spare's price, so the last-hop guard compares what the
/// spare would forward against the failed maker's terms and aborts rather than
/// silently re-pricing above the confirmed ceiling; recovery then refunds the
/// taker's broadcast funding via timelock.
#[test]
fn last_hop_expensive_spare_aborts_instead_of_repricing() {
    warn!("Running Test: Last-hop drop with an expensive spare aborts instead of re-pricing");

    // Route is [maker0, maker1]; maker2 is the only spare. maker1 (last hop)
    // prices cheap and drops; maker2 prices the same hop ~20k sats higher.
    let makers_config_map = vec![(6102, None), (16102, None), (26102, None)];
    let fee_overrides = vec![
        Some(MakerFeeOverride {
            base_fee: 500,
            amount_relative_fee_pct: 0.0025,
        }),
        Some(MakerFeeOverride {
            base_fee: 100,
            amount_relative_fee_pct: 0.0005,
        }),
        Some(MakerFeeOverride {
            base_fee: 20000,
            amount_relative_fee_pct: 0.05,
        }),
    ];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::CloseAtReqContractSigsForSender,
        MakerBehavior::Normal,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_fee_overrides::<BitcoindBackend>(
            makers_config_map,
            fee_overrides,
            taker_behavior,
            maker_behaviors,
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
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

    log::info!("Starting Maker servers...");
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

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");

    // Route order follows the maker index (ports ascend): hop 1 is the cheap
    // dropper; the expensive spare waits in the pool.
    assert_eq!(summary.makers.len(), 2, "route should have 2 makers");
    assert!(
        summary.makers[1]
            .address
            .ends_with(&makers[1].config.network_port.to_string()),
        "hop 1 should be maker1 (the cheap dropper), got {}",
        summary.makers[1].address
    );

    let err = taker
        .start_swap(&summary.swap_id)
        .expect_err("swap must abort on the last-hop price guard");
    info!("Swap aborted as expected: {:?}", err);

    // Snapshot once: assert_log echoes its needle into the same file.
    let taker_log = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let taker_log_contents = fs::read_to_string(&taker_log).unwrap();
    assert!(
        taker_log_contents.contains("sats where the failed maker forwarded"),
        "the last-hop price guard must abort the swap"
    );
    assert_eq!(
        taker_log_contents
            .matches("Substituting maker 1 with spare")
            .count(),
        1,
        "exactly one spare substitution must be attempted"
    );

    // The taker broadcast its funding before the drop, so it recovers via
    // timelock: 225-block outer hop plus scheduling margin, mirroring
    // maker_abort2_case3.
    info!("Waiting for the taker's timelock recovery...");
    thread::sleep(Duration::from_secs(300));

    let recovery_timeout = Duration::from_secs(120);
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        assert!(
            recovery_start.elapsed() <= recovery_timeout,
            "Background recovery did not complete within timeout"
        );
        thread::sleep(Duration::from_secs(5));
    }

    generate_blocks(bitcoind, 1);
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);
    info!(
        "Taker after recovery: spendable={}, contract={}, lost to miner fees={}",
        taker_balances.spendable, taker_balances.contract, balance_diff
    );
    // Recovery returns everything but the miner fees of the funding and
    // refund transactions; no maker fee was earned by anyone.
    assert_eq!(taker_balances.contract, Amount::ZERO);
    assert_eq!(taker_balances.swap, Amount::ZERO);
    assert_eq!(taker_balances.fidelity, Amount::ZERO);
    // Pinned from a real run: 3 funding txs + 3 timelock refunds at 1 sat/vB.
    assert_eq!(
        taker_balances.spendable.to_sat(),
        14998662,
        "Taker spendable after recovery mismatch"
    );

    // No maker broadcast anything: the drop fired before the taker relayed
    // combined sigs, so every maker returns to its pre-swap balance.
    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances after recovery: original={}, after={}",
            i, original, balances.spendable
        );
        assert_eq!(
            balances.spendable, original,
            "Maker {} balance moved though it never funded",
            i
        );
        assert_eq!(balances.contract, Amount::ZERO);
        assert_eq!(balances.swap, Amount::ZERO);
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
    }

    info!("last_hop_expensive_spare_aborts_instead_of_repricing completed successfully!");
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Same drop at the last hop, but the spare prices the hop identically to the
/// failed maker: the guard compares derived receives, finds no re-pricing, and
/// the substitution completes the swap. This is the control proving the guard
/// does not block good substitutions.
#[test]
fn last_hop_equal_priced_spare_completes() {
    warn!("Running Test: Last-hop drop with an equally priced spare completes");

    let makers_config_map = vec![(6102, None), (16102, None), (26102, None)];
    let fee_overrides = vec![
        Some(MakerFeeOverride {
            base_fee: 500,
            amount_relative_fee_pct: 0.0025,
        }),
        Some(MakerFeeOverride {
            base_fee: 100,
            amount_relative_fee_pct: 0.0005,
        }),
        Some(MakerFeeOverride {
            base_fee: 100,
            amount_relative_fee_pct: 0.0005,
        }),
    ];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::Normal,
        MakerBehavior::CloseAtReqContractSigsForSender,
        MakerBehavior::Normal,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_fee_overrides::<BitcoindBackend>(
            makers_config_map,
            fee_overrides,
            taker_behavior,
            maker_behaviors,
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
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

    log::info!("Starting Maker servers...");
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

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("Swap with an equally priced spare must complete");

    let taker_log = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let taker_log_contents = fs::read_to_string(&taker_log).unwrap();
    assert_eq!(
        taker_log_contents
            .matches("Substituting maker 1 with spare")
            .count(),
        1,
        "the spare must be substituted exactly once"
    );
    assert!(
        !taker_log_contents.contains("sats where the failed maker forwarded"),
        "the price guard must not fire for an equally priced spare"
    );

    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    generate_blocks(bitcoind, 1);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balance: original={}, after={}",
        taker_original_balance, taker_balances.spendable
    );
    // Pinned from a real run: the taker paid the cheap last-hop fee schedule
    // (identical on the dropper and the spare) plus the default hop-0 fee.
    assert_eq!(
        taker_balances.spendable.to_sat(),
        14996071,
        "Taker spendable balance mismatch"
    );
    assert_eq!(taker_balances.contract, Amount::ZERO);
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // maker0 and maker2 (the spare) ran the route; maker1 dropped before
    // funding anything and keeps its pre-swap balance. Pinned from a real run:
    // hop 0 earns the default schedule, the spare earns the cheap one.
    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: original={}, after={}",
            i, original, balances.spendable
        );
        let expected_spendable = [15000577u64, 14999757, 15000130][i];
        assert_eq!(
            balances.spendable.to_sat(),
            expected_spendable,
            "Maker {} spendable balance mismatch",
            i
        );
        assert_eq!(balances.contract, Amount::ZERO);
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
    }

    info!("last_hop_equal_priced_spare_completes completed successfully!");
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
