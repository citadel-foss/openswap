use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use super::test_framework::*;

use log::info;
use std::{thread, time::Duration};

/// Test: Taker maliciously broadcasts contract txs after full setup.
///
/// The taker completes the full contract exchange, then broadcasts contract
/// transactions and closes. Makers detect the on-chain contracts and recover
/// their funds via timelock spending.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [BroadcastContractAfterFullSetup],
    setup = [
        // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
        fund_taker_default(3) as taker_original_balance,
        // Fund the makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
)]
fn test_malice1_taker_broadcast_contract(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare should succeed; execution should fail with BroadcastContractAfterFullSetup
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    let swap_result = world.taker_mut().start(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Swap should fail due to BroadcastContractAfterFullSetup behavior"
    );
    info!("Swap failed as expected: {:?}", swap_result.err().unwrap());
    world.taker().log_tracker_state();

    // Sleep budget: 60s maker idle timeout (test builds) + 225-block outer-hop
    // timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) ≈ 135s at
    // 5 blocks/3s; remaining ~105s is scheduling margin.
    info!("Waiting for makers to timeout and blocks to mature timelocks...");
    thread::sleep(Duration::from_secs(300));

    // Verify maker balances -- makers should have recovered their outgoing funds via timelock
    let expected_regular = [14998419, 14998419];
    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();
        info!(
            "Maker {} balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable,
        );
        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(0)),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: None,
        }
        .assert(&format!("Maker {i}"), &balances);

        // Makers lost some funds due to taker maliciously broadcasting contracts
        let maker_diff = original
            .checked_sub(balances.spendable)
            .unwrap_or(Amount::ZERO);
        info!(
            "Maker {} lost {} sats (pre-swap: {}, current: {})",
            i,
            maker_diff.to_sat(),
            original,
            balances.spendable,
        );
    }

    // Wait for taker's background recovery loop to finish
    info!("Waiting for background recovery loop to complete...");
    world.taker().await_recovery(Duration::from_secs(120));
    info!("Background recovery loop completed.");

    // Mine a block to confirm recovery txs, then sync wallet
    world.mine(1);
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

    // Only the contract and fidelity balances are asserted here.
    BalanceExpect {
        regular: None,
        swap: None,
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: None,
    }
    .assert("Taker", &taker_balances);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap_or(Amount::ZERO);

    info!(
        "Taker balance diff: {} sats (original: {}, current: {})",
        balance_diff.to_sat(),
        taker_original_balance,
        taker_balances.spendable,
    );

    world.taker().log_tracker_state();
    info!("Malice1 test completed successfully!");
}
