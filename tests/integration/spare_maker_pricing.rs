//! Spare substitution when the makers price their hops differently. A spare
//! that would change an admitted hop's shape, or forward above the failed
//! maker's terms, must abort the swap rather than renegotiate or re-price; an
//! equally priced spare completes it.

use bitcoin::Amount;
use openswap::{protocol::common_messages::MakerToTakerMessage, taker::SwapParams};

use super::test_framework::*;

use log::info;
use std::{fs, thread, time::Duration};

/// One fee override per maker, as `(base_fee, amount_relative_fee_pct)`.
fn fees(overrides: &[(u64, f64)]) -> Vec<Option<MakerFeeOverride>> {
    overrides
        .iter()
        .map(|&(base_fee, amount_relative_fee_pct)| {
            Some(MakerFeeOverride {
                base_fee,
                amount_relative_fee_pct,
            })
        })
        .collect()
}

/// Heterogeneous offers: a non-terminal maker drops pre-broadcast, and every
/// spare prices its hop differently. The spare's derived next hop cannot match
/// what the downstream maker already admitted, so the swap must abort on the
/// shape check — never re-negotiate the downstream maker or exhaust the spares.
#[world_test(
    backend = BitcoindBackend,
    // Route is [maker0, maker1]; spares are popped from the back, so maker3 is
    // tried first. maker0 drops at ReqContractSigsForSender: after both hops
    // admitted SwapDetails, before any funding is on-chain.
    fee_overrides = fees(&[(500, 0.0025), (800, 0.005), (1200, 0.0075), (950, 0.004)]),
    maker_behaviors = [CloseAtReqContractSigsForSender, Normal, Normal, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
        mine(1),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn heterogeneous_substitution_aborts_without_cascade(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Failed to prepare openswap");

    // Route order follows the maker index (ports ascend), so hop 0 is the
    // dropper and hop 1 is the downstream maker that must never be re-negotiated.
    assert_eq!(summary.makers.len(), 2, "route should have 2 makers");
    assert!(
        summary.makers[0].address.ends_with(&format!(
            ":{}",
            world.makers()[0].inner().config.network_port
        )),
        "hop 0 should be maker0 (the dropper), got {}",
        summary.makers[0].address
    );
    assert!(
        summary.makers[1].address.ends_with(&format!(
            ":{}",
            world.makers()[1].inner().config.network_port
        )),
        "hop 1 should be maker1 (downstream), got {}",
        summary.makers[1].address
    );

    // Baseline: hop 1 admitted these exact terms; a replay is still accepted.
    let downstream_details = world
        .taker()
        .inner()
        .test_current_swap_details(1)
        .expect("downstream swap details should rebuild");
    match world
        .taker()
        .inner()
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
    let err = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect_err("swap must abort on the spare shape mismatch");
    info!("Swap aborted as expected: {:?}", err);

    // Snapshot once: assert_log echoes its needle into the same file, which
    // would poison the substitution count.
    let taker_log = world.taker_log_path();
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
        taker_log_contents.contains(&format!(
            "[{}] Accepting swap",
            world.makers()[3].inner().config.network_port
        )),
        "the cheaper maker3 spare must be selected first"
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
    match world
        .taker()
        .inner()
        .test_send_swap_details(&summary.makers[1].address, &downstream_details)
        .expect("post-abort resend should get an answer")
    {
        MakerToTakerMessage::AckSwapDetails(ack) => assert!(
            ack.tweakable_point.is_some(),
            "downstream maker must still accept the originally admitted terms"
        ),
        other => panic!("post-abort resend got unexpected response: {:?}", other),
    }

    // Nothing reached the chain: every maker keeps its pre-swap balance.
    world.mine(1);
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();
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

    world.taker().sync();
    let taker_balances = world.taker().balances();
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
}

/// Heterogeneous offers, last hop: the cheap maker in the last slot drops at
/// ReqContractSigsForSender and the only spare is expensive. No downstream
/// admission pins the spare's price, so the last-hop guard compares what the
/// spare would forward against the failed maker's terms and aborts rather than
/// silently re-pricing above the confirmed ceiling; recovery then refunds the
/// taker's broadcast funding via timelock.
#[world_test(
    backend = BitcoindBackend,
    // Route is [maker0, maker1]; maker2 is the only spare. maker1 (last hop)
    // prices cheap and drops; maker2 prices the same hop ~20k sats higher.
    fee_overrides = fees(&[(100, 0.0005), (100, 0.0005), (20000, 0.05)]),
    maker_behaviors = [Normal, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
        mine(1),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn last_hop_expensive_spare_aborts_instead_of_repricing(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Failed to prepare openswap");

    // Route order follows the maker index (ports ascend): hop 1 is the cheap
    // dropper; the expensive spare waits in the pool.
    assert_eq!(summary.makers.len(), 2, "route should have 2 makers");
    assert!(
        summary.makers[1].address.ends_with(&format!(
            ":{}",
            world.makers()[1].inner().config.network_port
        )),
        "hop 1 should be maker1 (the cheap dropper), got {}",
        summary.makers[1].address
    );

    let err = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect_err("swap must abort on the last-hop price guard");
    info!("Swap aborted as expected: {:?}", err);

    // Snapshot once: assert_log echoes its needle into the same file.
    let taker_log = world.taker_log_path();
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
    // `maker_abort::legacy_drop_at_proof_of_funding`.
    info!("Waiting for the taker's timelock recovery...");
    thread::sleep(Duration::from_secs(300));

    world.taker().await_recovery(Duration::from_secs(120));

    world.mine(1);
    world.taker().sync();

    let taker_balances = world.taker().balances();
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
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();
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
}

/// Same drop at the last hop, but the spare prices the hop identically to the
/// failed maker: the guard compares derived receives, finds no re-pricing, and
/// the substitution completes the swap. This is the control proving the guard
/// does not block good substitutions.
#[world_test(
    backend = BitcoindBackend,
    fee_overrides = fees(&[(100, 0.0005), (100, 0.0005), (100, 0.0005)]),
    maker_behaviors = [Normal, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
        mine(1),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn last_hop_equal_priced_spare_completes(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Failed to prepare openswap");

    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Swap with an equally priced spare must complete");

    let taker_log = world.taker_log_path();
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

    world.taker().sync();

    world.mine(1);

    world.sync_makers();

    let taker_balances = world.taker().balances();
    info!(
        "Taker balance: original={}, after={}",
        taker_original_balance, taker_balances.spendable
    );
    // Pinned from a real run: both selected hops use the cheap fee schedule.
    assert_eq!(
        taker_balances.spendable.to_sat(),
        14996805,
        "Taker spendable balance mismatch"
    );
    assert_eq!(taker_balances.contract, Amount::ZERO);
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // maker0 and maker2 (the spare) ran the route; maker1 dropped before
    // funding anything and keeps its pre-swap balance. Pinned from a real run:
    // hop 0 earns the default schedule, the spare earns the cheap one.
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        let balances = maker.balances();
        info!(
            "Maker {} balances: original={}, after={}",
            i, original, balances.spendable
        );
        let expected_spendable = [15000005u64, 14999757, 14999968][i];
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
}
