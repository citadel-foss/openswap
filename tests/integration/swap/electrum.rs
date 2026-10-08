use crate::test_framework::*;
use bitcoin::Amount;
use log::info;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

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
#[world_test(
    backend = ElectrumBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(180),
        verify_maker_pre_swap_balances(),
    ],
    cases = [
        taproot_swap_completes(protocol = ProtocolVersion::Taproot, expected = &TAPROOT_EXPECTED),
        legacy_swap_completes(protocol = ProtocolVersion::Legacy, expected = &LEGACY_EXPECTED),
    ],
)]
fn run_electrum_swap(world: &mut World, protocol: ProtocolVersion, expected: &ExpectedBalances) {
    let before = world.balances();
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
    assert_balances!(world, since before; {
        taker: {
            regular: expected.taker_regular,
            swap: expected.taker_swap,
            contract: 0,
            fidelity: 0,
            loss: expected.taker_fee,
        },
        makers: {
            regular: expected.maker_regular,
            swap: expected.maker_swap,
            contract: 0,
            fidelity: BOND,
            gain: expected.maker_earnings,
        },
    });
    info!("Electrum-only openswap test ({protocol:?}) completed successfully!");
}
