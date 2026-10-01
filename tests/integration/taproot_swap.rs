use bitcoin::Amount;
use openswap::taker::SwapParams;

use super::test_framework::*;

use log::info;

/// Taproot OpenSwap Basic Functionality
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        // 3 x 0.05 BTC P2TR for the taker, 4 x 0.05 BTC for each maker.
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        // Spawn, wait for setup, then sync so the fidelity bonds count.
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn test_taproot_openswap(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
    params: SwapParams,
) {
    log::info!("Starting end-to-end taproot swap test...");

    // Mine some blocks before the swap to ensure wallet is ready
    world.mine(1);
    let swap_start_height = chain_tip(world.bitcoind()) + 1;

    // Prepare and execute the swap
    world
        .taker_mut()
        .swap(params)
        .expect("Taproot openswap should complete successfully");
    log::info!("Taproot openswap completed successfully!");

    // Sync wallets and verify results
    world.taker().sync();

    // Mine a block to confirm the sweep transactions
    world.mine(1);

    for maker in world.makers() {
        maker.sync();
    }

    let taker_balances = world.taker().balances();

    info!(
        "Taproot Taker balance after swap: Regular: {}, Contract: {}, Spendable: {}, Swap: {}",
        taker_balances.regular,
        taker_balances.contract,
        taker_balances.spendable,
        taker_balances.swap,
    );

    BalanceExpect {
        regular: Some(Is::Sats(14499538)),
        swap: Some(Is::Sats(496789)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None,
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::CheckedUnwrap,
            sats: 3673,
        }),
    }
    .assert("Taker", &taker_balances);

    // Verify makers earned fees. Their wallets were synced above and are read
    // as they stand.
    let expected_regular = [14500751, 14502170];
    let expected_swap = [499664, 498208];
    let expected_fee = [658, 621];
    for (i, (maker, original_spendable)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        let balances = maker.balances();

        info!(
            "Taproot Maker {} final balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
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
                sats: expected_fee[i],
            }),
        }
        .assert(&format!("Maker {i}"), &balances);
    }

    // Every swap tx must pay the negotiated 1 sat/vB: funding txs price their
    // real vsize; sweeps pay the 112 vB taproot key-path model they were built
    // at. A completed swap mines 9 funding txs (3 splits x 3 parties), 9 sweeps.
    let bitcoind = world.bitcoind();
    let depths = wait_for_tx_depths(bitcoind, swap_start_height, &[9, 9]);
    for txid in &depths[0] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(
            fee, vsize as u64,
            "funding tx {txid} must pay exactly 1 sat/vB"
        );
    }
    for txid in &depths[1] {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        assert_eq!(fee, 112, "sweep tx {txid} must pay the 112 vB model");
        assert!(vsize <= 112, "sweep tx {} exceeds its 112 vB model", txid);
    }

    info!("All taproot swap tests completed successfully!");

    let taker_report_path = world
        .temp_dir()
        .join("taker1")
        .join("wallets")
        .join("taker1_swap_report.json");
    assert_report_has_deniability_proofs(&taker_report_path, "taproot taker", bitcoind, 1);

    for (i, maker) in world.makers().iter().enumerate() {
        assert_report_has_deniability_proofs(
            &maker.report_path(),
            &format!("taproot maker {i}"),
            bitcoind,
            1,
        );
    }
}
