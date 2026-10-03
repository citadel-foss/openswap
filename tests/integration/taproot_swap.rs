//! Integration test for Taproot OpenSwap implementation.
//!
//! This test demonstrates a taproot-based openswap between a Taker and 2 Makers using
//! the Taproot protocol with MuSig2 signatures.

use bitcoin::{Amount, OutPoint};
use bitcoind::bitcoincore_rpc::{json::ListUnspentResultEntry, RpcApi};
use openswap::{
    maker::{start_server, MakerBehavior},
    protocol::common_messages::ProtocolVersion,
    taker::{MakerFeeInfo, SwapParams, TakerBehavior},
    utill::{funding_fee_policy_sats, sweep_fee_policy_sats, MIN_RELAY_FEE_RATE},
};

use super::test_framework::*;

use log::{info, warn};
use std::{collections::HashSet, thread};

/// Test taproot openswap
#[test]
fn test_taproot_openswap() {
    // ---- Setup ----
    warn!("Running Test: Taproot OpenSwap Basic Functionality");

    let maker_count = 2;
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(maker_count, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the Taproot Taker with 3 UTXOs of 0.05 BTC each (P2TR)
    let taker_original_balance = fund_taker_default(taker, bitcoind, 3);

    // Fund the Taproot Makers with 4 UTXOs of 0.05 BTC each
    fund_makers_default(&makers, bitcoind);

    // Start the maker server threads
    log::info!("Initiating Taproot Makers...");

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
    log::info!("Starting end-to-end taproot swap test...");

    // Swap params for taproot openswap
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    // Mine some blocks before the swap to ensure wallet is ready
    generate_blocks(bitcoind, 1);
    let swap_start_height = chain_tip(bitcoind) + 1;

    // Prepare and execute the swap
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Failed to prepare Taproot openswap");
    taker
        .start_swap(&summary.swap_id)
        .expect("Taproot openswap should complete successfully");
    log::info!("Taproot openswap completed successfully!");

    // Sync wallets and verify results
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    // Mine a block to confirm the sweep transactions
    generate_blocks(bitcoind, 1);

    for maker in makers.iter() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();

    info!(
        "Taproot Taker balance after swap: Regular: {}, Contract: {}, Spendable: {}, Swap: {}",
        taker_balances.regular,
        taker_balances.contract,
        taker_balances.spendable,
        taker_balances.swap,
    );

    assert_eq!(
        taker_balances.regular.to_sat(),
        14499538,
        "Taker regular balance mismatch"
    );
    assert_eq!(taker_balances.swap.to_sat(), 496789, "Taker swap balance");
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    let balance_diff = taker_original_balance
        .checked_sub(taker_balances.spendable)
        .unwrap();

    info!("Taproot Taker fees paid: {} sats", balance_diff.to_sat());

    assert_eq!(
        balance_diff.to_sat(),
        3673,
        "Taker spendable balance change"
    );

    // Verify makers earned fees
    let expected_regular = [14500751, 14502170];
    let expected_swap = [499664, 498208];
    let expected_fee = [658, 621];
    for (i, (maker, original_spendable)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();

        info!(
            "Taproot Maker {} final balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.fidelity, balances.spendable,
        );

        assert_eq!(
            balances.regular.to_sat(),
            expected_regular[i],
            "Maker {i} regular balance"
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap[i],
            "Maker {i} swap balance"
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());

        let maker_fee = balances
            .spendable
            .checked_sub(original_spendable)
            .unwrap_or(Amount::ZERO);

        info!(
            "Taproot Maker {} fee earned: {} sats",
            i,
            maker_fee.to_sat()
        );

        assert_eq!(maker_fee.to_sat(), expected_fee[i], "Maker {i} fee earned");
    }

    // Every swap tx must pay the negotiated 1 sat/vB: funding txs price their
    // real vsize; sweeps pay the 112 vB taproot key-path model they were built
    // at. A completed swap mines 9 funding txs (3 splits x 3 parties), 9 sweeps.
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

    let temp_dir = makers[0]
        .data_dir
        .parent()
        .expect("maker data dir should live under test temp dir");
    let taker_report_path = temp_dir
        .join("taker1")
        .join("wallets")
        .join("taker1_swap_report.json");
    assert_report_has_deniability_proofs(&taker_report_path, "taproot taker", bitcoind, 1);

    for (i, maker) in makers.iter().enumerate() {
        let maker_report_path = maker
            .data_dir
            .join("wallets")
            .join(format!("{}_swap_report.json", maker.config.wallet_name));
        assert_report_has_deniability_proofs(
            &maker_report_path,
            &format!("taproot maker {i}"),
            bitcoind,
            1,
        );
    }

    shutdown_makers(&makers, maker_threads);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// An uneven `[1, 3, 2]` route through 2 makers prices each hop on its own
/// maximum and lands exactly that shape on chain. Every hop differs, so the
/// ceiling cannot match a uniform count or a sweep/forward index mix-up.
///
/// The cheapest maker takes hop 0 and refuses `SwapDetails`, so the spare
/// replaces it mid-negotiation and must still be asked to forward 3 splits.
#[test]
fn test_taproot_per_hop_splits_1_3_2() {
    warn!("Running Test: Taproot per-hop split maximums on a [1, 3, 2] route with a spare");

    // Fees order the selection: maker0 and maker1 form the route, maker2 is
    // the only spare.
    let fee = |base_fee, amount_relative_fee_pct| {
        Some(MakerFeeOverride {
            base_fee,
            amount_relative_fee_pct,
        })
    };
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init_with_fee_overrides::<BitcoindBackend>(
            vec![(0, None); 3],
            vec![fee(500, 0.0025), fee(800, 0.005), fee(1200, 0.0075)],
            vec![TakerBehavior::Normal],
            vec![
                MakerBehavior::RefuseSwapDetails,
                MakerBehavior::Normal,
                MakerBehavior::Normal,
            ],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    // Any one 0.05 BTC coin covers the swap, so hop 0 plans a single input.
    fund_taker_default(taker, bitcoind, 3);
    // Three coins beside the fidelity bond let the first maker forward 3 splits.
    fund_makers_default(&makers, bitcoind);

    let maker_threads = spawn_makers(&makers);
    wait_for_makers_setup(&makers, 120);
    sync_maker_wallets(&makers);
    generate_blocks(bitcoind, 1);
    let swap_start_height = chain_tip(bitcoind) + 1;

    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_counts(vec![1, 3, 2])
        .with_required_confirms(1);
    let max_input_budget = params.max_input_budget;
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should accept a [1, 3, 2] Taproot route");

    // The summary is built after negotiation, so hop 0 is already the spare.
    let route_maker = |hop: &MakerFeeInfo| {
        makers
            .iter()
            .position(|m| {
                hop.address
                    .ends_with(&format!(":{}", m.config.network_port))
            })
            .expect("every route maker is a test maker")
    };
    assert_eq!(
        summary.makers.iter().map(route_maker).collect::<Vec<_>>(),
        vec![2, 1],
        "the spare must replace the refusing maker at hop 0"
    );

    // The ceiling prices maker i's sweeps on hop i's maximum and its
    // forwarding on hop i + 1's: maker 0 sweeps 1 and forwards 3, maker 1
    // sweeps 3 and forwards 2.
    let feerate = MIN_RELAY_FEE_RATE;
    let split_funding =
        funding_fee_policy_sats(max_input_budget as usize, max_input_budget, feerate).unwrap();
    let sweep = sweep_fee_policy_sats(ProtocolVersion::Taproot, feerate).unwrap();
    let hop0_funding = funding_fee_policy_sats(1, u32::MAX, feerate).unwrap();
    let service_fees: u64 = summary.makers.iter().map(|m| m.estimated_fee_sats).sum();
    let expected_ceiling =
        service_fees + (sweep + 3 * split_funding) + (3 * sweep + 2 * split_funding) + hop0_funding;
    assert_eq!(
        summary.total_estimated_fee,
        Amount::from_sat(expected_ceiling),
        "the cost ceiling must price every hop on its own maximum"
    );

    // Pre-swap coins of each hop's funder in route order: the taker funds hop
    // 0, the maker at route position i funds hop i + 1.
    let outpoints = |utxos: Vec<ListUnspentResultEntry>| -> HashSet<OutPoint> {
        utxos
            .iter()
            .map(|u| OutPoint::new(u.txid, u.vout))
            .collect()
    };
    let mut hop_funders = vec![outpoints(
        taker.get_wallet().read().unwrap().list_all_utxo(),
    )];
    for hop in &summary.makers {
        let maker = &makers[route_maker(hop)];
        hop_funders.push(outpoints(maker.wallet.read().unwrap().list_all_utxo()));
    }

    taker
        .start_swap(&summary.swap_id)
        .expect("a [1, 3, 2] Taproot swap should complete");

    // 1 + 3 + 2 is the most the route can fund, so exactly 6 funding txs
    // proves every hop reached its maximum; each contract is swept once.
    let by_depth = wait_for_tx_depths(bitcoind, swap_start_height, &[6, 6]);

    // A uniform [2, 2, 2] also lands 6 + 6, so attribute each funding tx to
    // the hop whose funder owned its inputs and check the shape per hop.
    let mut hop_funding_txs = vec![0; hop_funders.len()];
    for txid in &by_depth[0] {
        let tx = bitcoind.client.get_raw_transaction(txid, None).unwrap();
        let hop = hop_funders
            .iter()
            .position(|coins| coins.contains(&tx.input[0].previous_output))
            .unwrap_or_else(|| panic!("funding tx {} spends no funder's pre-swap coin", txid));
        assert!(
            tx.input
                .iter()
                .all(|input| hop_funders[hop].contains(&input.previous_output)),
            "funding tx {} mixes coins of different funders",
            txid
        );
        hop_funding_txs[hop] += 1;
    }
    assert_eq!(
        hop_funding_txs,
        vec![1, 3, 2],
        "each hop must fund exactly its own maximum"
    );

    shutdown_makers(&makers, maker_threads);
    test_framework.finish(takers, block_generation_handle);
}
