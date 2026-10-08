use openswap::taker::SwapParams;

use crate::test_framework::*;

use log::info;

/// Taproot OpenSwap Basic Functionality
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        // 3 x 0.05 BTC P2TR for the taker, 4 x 0.05 BTC for each maker.
        fund_taker_default(3),
        fund_makers_default(),
        // Spawn, wait for setup, then sync so the fidelity bonds count.
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taproot_two_maker_swap_completes(world: &mut World, params: SwapParams) {
    let before = world.balances();

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

    world.sync_makers();

    assert_balances!(world, since before; {
        taker: { regular: 14_499_538, swap: 496_789, contract: 0, fidelity: 0, loss: 3_673 },
        makers: {
            regular: [14_500_751, 14_502_170],
            swap: [499_664, 498_208],
            contract: 0,
            fidelity: BOND,
            gain: [658, 621],
        },
    });

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
