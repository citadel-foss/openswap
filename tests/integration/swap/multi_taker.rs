//! Two takers swap one after the other through the same two makers, on
//! Legacy and on Taproot.

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion, taker::SwapParams, wallet::AddressType,
};

use crate::test_framework::*;

use log::info;

/// The balances one sequential multi-taker test asserts.
struct MultiTakerExpect {
    taker_spendable: [u64; 2],
    /// Each taker's funding minus its final spendable balance.
    taker_fee: [u64; 2],
    maker_regular: [u64; 2],
    maker_swap: [u64; 2],
    maker_fee: [u64; 2],
}

/// Funds two takers and two makers, runs taker 1's swap, mines, runs taker 2's
/// swap, and asserts every wallet.
#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    takers = [Normal, Normal],
    cases = [
        legacy_sequential_swaps(
            protocol = ProtocolVersion::Legacy,
            expected = &MultiTakerExpect {
                taker_spendable: [14995985, 14995985],
                taker_fee: [4015, 4015],
                maker_regular: [14001973, 14005039],
                maker_swap: [999100, 995960],
                maker_fee: [1316, 1242],
            },
        ),
        taproot_sequential_swaps(
            protocol = ProtocolVersion::Taproot,
            expected = &MultiTakerExpect {
                taker_spendable: [14996327, 14996327],
                taker_fee: [3673, 3673],
                maker_regular: [14001745, 14004583],
                maker_swap: [999328, 996416],
                maker_fee: [1316, 1242],
            },
        ),
    ],
)]
fn run_sequential_multi_taker(
    world: &mut World,
    protocol: ProtocolVersion,
    expected: &MultiTakerExpect,
) {
    // Fund each taker thrice with one 0.05 BTC UTXO (0.15 total), one per call so
    // each lands on a distinct address and coin_select doesn't group them.
    let mut taker1_original_balance = Amount::ZERO;
    let mut taker2_original_balance = Amount::ZERO;
    for _ in 0..3 {
        taker1_original_balance = world.fund_nth_taker_default(0, 1);
        taker2_original_balance = world.fund_nth_taker_default(1, 1);
    }

    // Fund the makers with 4 UTXOs of 0.05 BTC each, one per call (distinct addresses).
    for _ in 0..4 {
        world.fund_makers(1, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);
    }

    // Start the makers, wait for their setup, then sync their wallets so the
    // fidelity bonds are accounted for
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    let maker_spendable_balance = world.verify_maker_pre_swap_balances();

    // ---- Swap 1: First taker ----
    log::info!("Starting swap for Taker 1 ({:?} protocol)...", protocol);

    let swap_params1 = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    let taker1 = &mut world.takers_mut()[0];
    let summary1 = taker1.prepare(swap_params1).unwrap_or_else(|e| {
        panic!(
            "Failed to prepare {:?} openswap for Taker 1: {:?}",
            protocol, e
        )
    });
    log::info!("Taker 1 swap summary: {:?}", summary1);

    match taker1.start(&summary1.swap_id) {
        Ok(report) => {
            log::info!("Taker 1 openswap ({:?}) completed successfully!", protocol);
            log::info!("Taker 1 swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("Taker 1 openswap ({:?}) failed: {:?}", protocol, e);
            panic!("Taker 1 openswap ({:?}) failed: {:?}", protocol, e);
        }
    }

    // Mine blocks between swaps to confirm transactions
    world.mine(5);

    // Sync maker wallets between swaps
    world.sync_makers();

    // ---- Swap 2: Second taker ----
    log::info!("Starting swap for Taker 2 ({:?} protocol)...", protocol);

    let swap_params2 = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    let taker2 = &mut world.takers_mut()[1];
    let summary2 = taker2.prepare(swap_params2).unwrap_or_else(|e| {
        panic!(
            "Failed to prepare {:?} openswap for Taker 2: {:?}",
            protocol, e
        )
    });
    log::info!("Taker 2 swap summary: {:?}", summary2);

    match taker2.start(&summary2.swap_id) {
        Ok(report) => {
            log::info!("Taker 2 openswap ({:?}) completed successfully!", protocol);
            log::info!("Taker 2 swap report: {:?}", report);
        }
        Err(e) => {
            log::error!("Taker 2 openswap ({:?}) failed: {:?}", protocol, e);
            panic!("Taker 2 openswap ({:?}) failed: {:?}", protocol, e);
        }
    }

    log::info!("All openswaps processed successfully. Transactions complete.");

    // Sync all wallets
    for taker in world.takers() {
        taker.sync();
    }

    world.mine(1);

    for maker in world.makers() {
        maker.sync();
    }

    // ---- Verify both takers ----
    // Spendable is checked ahead of contract and fidelity here, which is not
    // BalanceExpect's field order, so these stay plain asserts.
    for (i, (taker, original)) in world
        .takers()
        .iter()
        .zip([taker1_original_balance, taker2_original_balance])
        .enumerate()
    {
        let n = i + 1;
        let balances = taker.balances();
        info!("Taker {} balance after swap ({:?}):", n, protocol);

        let balance_diff = original - balances.spendable;
        info!(
            "Taker {} balance verification passed. Original: {}, After: {} (fees paid: {})",
            n, original, balances.spendable, balance_diff
        );

        assert_eq!(
            balances.spendable.to_sat(),
            expected.taker_spendable[i],
            "Taker {} spendable balance mismatch",
            n
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Taker {} contract balance mismatch",
            n
        );
        assert_eq!(balances.fidelity, Amount::ZERO);
        assert_eq!(
            balance_diff.to_sat(),
            expected.taker_fee[i],
            "Taker {} fee paid mismatch",
            n
        );
    }

    // ---- Verify Makers earned fees ----
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
            regular: Some(Is::Sats(expected.maker_regular[i])),
            swap: Some(Is::Sats(expected.maker_swap[i])),
            contract: Some(Is::Sats(0)),
            fidelity: Some(Is::Amount(Amount::from_btc(0.05).unwrap())),
            spendable: None,
            delta: Some(Delta::Gain {
                baseline: original_spendable,
                style: DiffStyle::UnwrapOrZero,
                sats: expected.maker_fee[i],
            }),
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    info!(
        "All multi-taker swap tests ({:?}) completed successfully!",
        protocol
    );

    world.shutdown_makers();
}
