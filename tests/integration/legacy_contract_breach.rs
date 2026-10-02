use bitcoin::Amount;
use openswap::taker::SwapParams;

use super::test_framework::*;

use log::info;
use std::{thread, time::Duration};

/// Breach before maker 0 funds: maker 0 must not broadcast its funding txs.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [BroadcastContractBeforeMakerFunding],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn test_legacy_breach_before_maker_funding(world: &mut World, params: SwapParams) {
    let regular_before: Vec<Amount> = world
        .makers()
        .iter()
        .map(|m| m.balances().regular)
        .collect();

    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(swap_result.is_err(), "Swap must fail: maker 0 never funds");
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    // The first maker reached its funding step and saved the signed swapcoins,
    // then refused because of the breach rather than for any other reason.
    assert!(
        world.makers().iter().any(|m| m
            .inner()
            .has_unfinished_outgoing_swapcoin(&summary.swap_id)
            .unwrap()),
        "No maker saved the swap's outgoing swapcoins"
    );

    // Let any stray maker broadcast confirm before comparing balances.
    thread::sleep(Duration::from_secs(20));
    world.sync_makers();
    assert_breach_refused(world);

    for (i, maker) in world.makers().iter().enumerate() {
        let balances = maker.balances();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable
        );
        assert_eq!(
            balances.regular, regular_before[i],
            "Maker {i} regular balance changed: its funding must not have been broadcast"
        );
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "Maker {i} contract balance"
        );
    }
}

/// Breach after full setup: maker 0 must refuse the key handover and recover.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [BroadcastContractBeforeHandover],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn test_legacy_breach_before_handover(world: &mut World, params: SwapParams) {
    world.mine(1);

    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap must fail: maker 0 refuses the handover"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());

    info!("Waiting for makers to recover on-chain...");
    thread::sleep(timelock_recovery_wait::<BitcoindBackend>());
    world.sync_makers();
    assert_breach_refused(world);

    // Observed in a real run: each maker swept its incoming contract via the
    // hashlock. A maker that had handed over its outgoing leg would be ~500k short.
    let expected_regular = [14500865, 14502398];
    let expected_swap = [499100, 497530];
    for (i, maker) in world.makers().iter().enumerate() {
        let balances = maker.balances();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(expected_swap[i])),
            contract: Some(Is::Amount(Amount::ZERO)),
            fidelity: None,
            spendable: None,
            delta: None,
        }
        .assert(&format!("Maker {i}"), &balances);
    }
}

/// The maker refused because of the breach, not for any other reason.
fn assert_breach_refused(world: &World) {
    assert_logged!(world, "ContractBroadcast");
}
