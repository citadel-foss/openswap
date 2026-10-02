//! Integration test: Taproot maker abort1 - Not enough makers.
//!
//! Only 1 maker is available, but the swap requires 2 makers (maker_count: 2).
//! prepare_swap should FAIL because there are not enough makers.
//! No recovery is needed - balances should remain unchanged.

use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use super::test_framework::*;

use log::info;

/// Test: Not enough makers for Taproot swap.
///
/// Scenario:
/// 1. Only 1 maker is available but swap requires 2 (maker_count: 2).
/// 2. prepare_swap should fail because it cannot find enough makers.
/// 3. No funds are broadcast, so no recovery is needed.
/// 4. Verify balances are unchanged.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Taproot)
        fund_taker_default(3) as taker_original_balance,
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        // Start the maker server threads
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn test_taproot_maker_abort1(world: &mut World, taker_original_balance: Amount) {
    // Swap params: Taproot, requires 2 makers but only 1 is available
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // prepare_swap should FAIL because only 1 maker is available for a 2-maker swap
    let prepare_result = world.taker_mut().prepare(swap_params);
    assert!(
        prepare_result.is_err(),
        "prepare_swap should fail because only 1 maker is available for a 2-maker swap"
    );
    info!(
        "Prepare failed as expected: {:?}",
        prepare_result.err().unwrap()
    );

    // Sync taker wallet and verify balance is unchanged
    world.taker().sync();

    let taker_balances = world.taker().balances();

    info!(
        "Taker balances after failed prepare: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );

    // Balance should be unchanged since no funds were broadcast
    assert_eq!(
        taker_balances.spendable, taker_original_balance,
        "Taker balance should be unchanged. Original: {}, After: {}",
        taker_original_balance, taker_balances.spendable,
    );

    assert_eq!(
        taker_balances.contract,
        Amount::ZERO,
        "Taker should have no contract balance"
    );

    info!("Taproot maker abort1 test completed successfully!");
}
