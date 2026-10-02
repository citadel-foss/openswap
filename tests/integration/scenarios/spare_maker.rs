//! Three makers for a two-hop route; one drops before any funding is on-chain,
//! the taker substitutes the spare, and the swap completes.
//!
//! Serves `abort2_case1::maker_abort2_case1`, `abort2_case2` and
//! `taproot_maker_abort3`, each of which declares its three makers.

use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use crate::test_framework::*;

use log::info;

/// The balances one spare-maker test asserts after the swap.
pub(crate) struct SpareMakerExpect {
    pub taker_spendable: u64,
    pub maker_spendable: [u64; 3],
}

/// Swaps over `protocol` on a world of three makers and one taker, expects the
/// swap to complete, and asserts the balances. The makers keep running.
pub(crate) fn complete_with_spare(
    world: &mut World,
    protocol: ProtocolVersion,
    prepare_failure: &str,
    expected: &SpareMakerExpect,
) {
    // Fund the taker with 3 UTXOs of 0.05 BTC each
    let taker_original_balance = world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    // Start the makers, wait for their setup, then sync their wallets so the
    // fidelity bonds are accounted for
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    let maker_spendable_balance = world.verify_maker_pre_swap_balances();

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare and execute the swap — taker should retry with the spare maker
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect(prepare_failure);
    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Swap should succeed with spare maker");

    // Sync wallets and verify results
    world.taker().sync();

    world.mine(1);

    world.sync_makers();

    // Verify taker balance. Spendable is checked ahead of contract and
    // fidelity in this family, which is not BalanceExpect's field order, so
    // these stay plain asserts.
    let taker_balances = world.taker().balances();

    info!(
        "Taker balance: original={}, after={}",
        taker_original_balance, taker_balances.spendable
    );

    assert_eq!(
        taker_balances.spendable.to_sat(),
        expected.taker_spendable,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // Verify makers earned fees (only the two that participated)
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
        assert_eq!(
            balances.spendable.to_sat(),
            expected.maker_spendable[i],
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
}
