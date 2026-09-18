//! First maker drops before sending sender's contract sigs. Taker continues with remaining makers.
//!
//! Setup: 3 makers (maker[0] CloseAtReqContractSigsForSender, maker[1] Normal, maker[2] Normal).
//! The taker only needs 2 makers for the route, so when maker[0] drops, it retries with the spare.
//! The swap should succeed.

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
};

use super::test_framework::*;

use log::{info, warn};
use std::thread;

#[test]
fn maker_abort2_case2() {
    warn!("Running Test: First maker drops before sending sender's sigs. Taker continues with remaining makers.");

    let makers_config_map = vec![(6102, None), (16102, None), (26102, None)];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![
        MakerBehavior::CloseAtReqContractSigsForSender,
        MakerBehavior::Normal,
        MakerBehavior::Normal,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker with 3 UTXOs of 0.05 BTC each (P2TR for Legacy)
    let taker_original_balance = fund_taker_default(taker, bitcoind, 3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

    // Start the maker server threads
    log::info!("Starting Maker servers...");

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    // Wait for makers to complete setup
    wait_for_makers_setup(&makers, 120);

    // Sync wallets after setup to ensure fidelity bonds are accounted for
    sync_maker_wallets(&makers);

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    // Swap params for openswap (Legacy)
    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    generate_blocks(bitcoind, 1);

    // Prepare and execute the swap — taker should retry with the spare maker
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("Swap should succeed with spare maker");

    // Sync wallets and verify results
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    generate_blocks(bitcoind, 1);

    sync_maker_wallets(&makers);

    // Verify taker balance
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taker balance: original={}, after={}",
        taker_original_balance, taker_balances.spendable
    );

    assert_eq!(
        taker_balances.spendable.to_sat(),
        14995985,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    // Verify makers earned fees (only the two that participated)
    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: original={}, after={}",
            i, original, balances.spendable
        );
        let expected_spendable = [14999757, 15000378, 15000415][i];
        assert_eq!(
            balances.spendable.to_sat(),
            expected_spendable,
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

    info!("maker_abort2_case2 completed successfully!");
    shutdown_makers(&makers, maker_threads);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
