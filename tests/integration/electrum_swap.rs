use super::test_framework::*;
use bitcoin::Amount;
use log::info;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

/// Exact post-swap balances for one protocol run. Legacy and taproot spend
/// different transaction shapes, so each protocol pins its own values.
struct ExpectedBalances {
    taker_regular: u64,
    taker_swap: u64,
    taker_fee: u64,
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    maker_earnings: [u64; 2],
}

const TAPROOT_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14_499_538,
    taker_swap: 496_789,
    taker_fee: 3_673,
    maker_regular: [14_500_751, 14_502_170],
    maker_swap: [499_664, 498_208],
    maker_earnings: [658, 621],
};

const LEGACY_EXPECTED: ExpectedBalances = ExpectedBalances {
    taker_regular: 14_499_538,
    taker_swap: 496_447,
    taker_fee: 4_015,
    maker_regular: [14_500_865, 14_502_398],
    maker_swap: [499_550, 497_980],
    maker_earnings: [658, 621],
};

/// Run an Electrum-only openswap with the given protocol version and assert the
/// exact post-swap taker / maker balances.
fn run_electrum_swap(protocol: ProtocolVersion, expected: &ExpectedBalances) {
    info!("Running Test: Electrum OpenSwap Procedure ({protocol:?})");
    let mut world = World::builder::<ElectrumBackend>()
        .makers(2)
        .maker_behaviors([MakerBehavior::Normal, MakerBehavior::Normal])
        .takers([TakerBehavior::Normal])
        .build();
    let taker_original_balance = world.fund_taker_default(3);
    world.fund_makers_default();
    info!("Initiating Maker servers");
    world.start_makers(180);
    let maker_spendable_balance = world.verify_maker_pre_swap_balances();
    let swap_params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    world.mine(1);
    // The taker's pre-swap sync must see the funding blocks, not a stale index.
    world.framework().wait_for_electrs_tip();
    let summary = world.taker_mut().prepare(swap_params).unwrap();
    world.taker_mut().start(&summary.swap_id).unwrap();
    // electrs indexes asynchronously; let it reach the tip before the
    // post-swap syncs so the asserted balances aren't computed from a
    // stale index.
    world.framework().wait_for_electrs_tip();
    world.taker().sync();
    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.sync_makers();
    let taker_balances = world.taker().balances();
    let maker_balances = world
        .makers()
        .iter()
        .map(|maker| maker.balances())
        .collect::<Vec<_>>();
    info!(
        "Electrum {protocol:?} taker: regular {}, swap {}, contract {}, spendable {}, original {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
        taker_original_balance,
    );
    for (i, balances) in maker_balances.iter().enumerate() {
        info!(
            "Electrum {protocol:?} maker {i}: regular {}, swap {}, contract {}, fidelity {}, spendable {}, earned {}",
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
            balances
                .spendable
                .checked_sub(maker_spendable_balance[i])
                .unwrap_or(Amount::ZERO),
        );
    }

    BalanceExpect {
        regular: Some(Is::Sats(expected.taker_regular)),
        swap: Some(Is::Sats(expected.taker_swap)),
        contract: Some(Is::Amount(Amount::ZERO)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::CheckedUnwrap,
            sats: expected.taker_fee,
        }),
    }
    .assert("Taker", &taker_balances);
    for (i, balances) in maker_balances.iter().enumerate() {
        BalanceExpect {
            regular: Some(Is::Sats(expected.maker_regular[i])),
            swap: Some(Is::Sats(expected.maker_swap[i])),
            contract: Some(Is::Amount(Amount::ZERO)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Gain {
                baseline: maker_spendable_balance[i],
                style: DiffStyle::UnwrapOrZero,
                sats: expected.maker_earnings[i],
            }),
        }
        .assert(&format!("Maker {i}"), balances);
    }
    info!("Electrum-only openswap test ({protocol:?}) completed successfully!");
    world.finish();
}

#[test]
fn test_taproot_openswap_electrum() {
    run_electrum_swap(ProtocolVersion::Taproot, &TAPROOT_EXPECTED);
}

#[test]
fn test_legacy_openswap_electrum() {
    run_electrum_swap(ProtocolVersion::Legacy, &LEGACY_EXPECTED);
}
