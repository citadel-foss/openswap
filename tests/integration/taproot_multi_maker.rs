use bitcoin::Amount;
use openswap::{protocol::common_messages::ProtocolVersion, taker::SwapParams};

use super::test_framework::*;

use log::info;

#[world_test(
    backend = BitcoindBackend,
    makers = 4,
    takers = [Normal],
    setup = [
        // Fund the taker with 5 UTXOs of 0.05 BTC each (P2TR for Taproot)
        // Need more UTXOs for a 4-maker route
        fund_taker_default(5) as taker_original_balance,
        // Fund makers with 4 UTXOs of 0.05 BTC each
        fund_makers_default(),
        // Start the makers, wait for their setup, then sync their wallets so the
        // fidelity bonds are accounted for
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
)]
fn test_taproot_multi_maker_openswap(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // Swap params for openswap (Taproot) with 4 makers
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 4)
        .with_tx_count(3)
        .with_required_confirms(1);

    // Mine some blocks before the swap to ensure wallet is ready
    world.mine(1);

    // Prepare the swap (negotiate with makers, get fee summary)
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Failed to prepare Taproot openswap with 4 makers");
    log::info!("Swap summary: {:?}", summary);

    // Execute the swap
    match world.taker_mut().start(&summary.swap_id) {
        Ok(report) => {
            log::info!("OpenSwap (Taproot, 4 makers) completed successfully!");
            log::info!("Swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
            panic!("OpenSwap (Taproot, 4 makers) failed: {:?}", e);
        }
    }

    log::info!("All openswaps processed successfully. Transaction complete.");

    // Sync wallets and verify results
    world.taker().sync();

    // Mine a block to confirm the sweep transactions
    world.mine(1);

    // Synchronize each maker's wallet
    for maker in world.makers() {
        maker.sync();
    }

    let taker_balances_after = world.taker().balances();
    info!("Taker balance after completing swap (Taproot, 4 makers):");
    info!(
        "  Regular: {}, Contract: {}, Spendable: {}, Swap: {}",
        taker_balances_after.regular,
        taker_balances_after.contract,
        taker_balances_after.spendable,
        taker_balances_after.swap,
    );

    // Verify swap results. Spendable is checked ahead of contract and
    // fidelity here, which is not BalanceExpect's field order, so these stay
    // plain asserts.
    let balance_diff = taker_original_balance - taker_balances_after.spendable;
    info!(
        "Taker (Taproot, 4 makers) balance verification passed. Original spendable: {}, After spendable: {} (fees paid: {})",
        taker_original_balance,
        taker_balances_after.spendable,
        balance_diff
    );

    assert_eq!(
        taker_balances_after.spendable.to_sat(),
        24993303,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances_after.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances_after.fidelity, Amount::ZERO);
    assert_eq!(balance_diff.to_sat(), 6697, "Taker fee paid mismatch");

    // Verify all 4 makers earned fees. Their wallets were synced above and are
    // read as they stand.
    let expected_regular = [14500826, 14502320, 14503776, 14505194];
    let expected_swap = [499664, 498133, 496639, 495183];
    let expected_fees = [733, 696, 658, 620];
    for (i, (maker, original_spendable)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        let balances = maker.balances();

        info!(
            "Maker {} final balances - Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.fidelity, balances.spendable,
        );

        BalanceExpect {
            regular: Some(Is::Sats(expected_regular[i])),
            swap: Some(Is::Sats(expected_swap[i])),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Gain {
                baseline: original_spendable,
                style: DiffStyle::UnwrapOrZero,
                sats: expected_fees[i],
            }),
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    info!("All multi-maker swap tests (Taproot, 4 makers) completed successfully!");
}
