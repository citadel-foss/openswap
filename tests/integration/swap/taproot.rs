//! Taproot swap between a taker and 2 makers, with MuSig2 signatures.
//!
//! Also pins the fee every swap tx pays at the negotiated 1 sat/vB.

use bitcoin::{Amount, OutPoint};
use bitcoind::bitcoincore_rpc::{json::ListUnspentResultEntry, RpcApi};
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{MakerFeeInfo, SwapParams},
    utill::{funding_fee_policy_sats, sweep_fee_policy_sats, MIN_RELAY_FEE_RATE},
};

use crate::test_framework::*;

use log::info;
use std::collections::HashSet;

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
    let report = world
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
        taker: { regular: 14_500_000, swap: 496_294, contract: 0, fidelity: 0, loss: 3_706 },
        makers: {
            regular: [14_501_246, 14_502_665],
            swap: [499_169, 497_713],
            contract: 0,
            fidelity: BOND,
            gain: [658, 621],
        },
    });
    assert_taker_report_exact(&report, Amount::from_sat(500_000), Amount::from_sat(3_706));

    // Every swap tx must pay the negotiated 1 sat/vB: maker funding txs price
    // their real vsize; the taker's own pay the 165 vB one-input model out of
    // the send amount, at or above their real vsize; sweeps pay the 112 vB
    // taproot key-path model they were built at.
    // A completed swap mines 9 funding txs (3 splits x 3 parties), 9 sweeps.
    let bitcoind = world.bitcoind();
    let depths = wait_for_tx_depths(bitcoind, swap_start_height, &[9, 9]);
    assert_taker_funding_pays_model(bitcoind, &depths[0], 1, 3);
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

/// One fee override, as `(base_fee, amount_relative_fee_pct)`.
fn fee(base_fee: u64, amount_relative_fee_pct: f64) -> Option<MakerFeeOverride> {
    Some(MakerFeeOverride {
        base_fee,
        amount_relative_fee_pct,
    })
}

/// An uneven `[1, 3, 2]` route through 2 makers prices each hop on its own
/// maximum and lands exactly that shape on chain. Every hop differs, so the
/// ceiling cannot match a uniform count or a sweep/forward index mix-up.
///
/// The cheapest maker takes hop 0 and refuses `SwapDetails`, so the spare
/// replaces it mid-negotiation and must still be asked to forward 3 splits.
#[world_test(
    backend = BitcoindBackend,
    // Fees order the selection: maker0 and maker1 form the route, maker2 is
    // the only spare.
    fee_overrides = vec![fee(500, 0.0025), fee(800, 0.005), fee(1200, 0.0075)],
    maker_behaviors = [RefuseSwapDetails, Normal, Normal],
    takers = [Normal],
    setup = [
        // Any one 0.05 BTC coin covers the swap, so hop 0 plans a single input.
        fund_taker_default(3),
        // Three coins beside the fidelity bond let the first maker forward 3 splits.
        fund_makers_default(),
        start_makers(120),
        mine(1),
    ],
)]
fn uneven_per_hop_splits_land_on_chain(world: &mut World) {
    let swap_start_height = chain_tip(world.bitcoind()) + 1;

    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_counts(vec![1, 3, 2])
        .with_required_confirms(1);
    let max_input_budget = params.max_input_budget;
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare should accept a [1, 3, 2] Taproot route");

    // The summary is built after negotiation, so hop 0 is already the spare.
    let route_maker = |hop: &MakerFeeInfo| {
        world
            .makers()
            .iter()
            .position(|m| {
                hop.address
                    .ends_with(&format!(":{}", m.inner().config.network_port))
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
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .list_all_utxo(),
    )];
    for hop in &summary.makers {
        let maker = world.makers()[route_maker(hop)].inner();
        hop_funders.push(outpoints(maker.wallet.read().unwrap().list_all_utxo()));
    }

    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("a [1, 3, 2] Taproot swap should complete");

    // 1 + 3 + 2 is the most the route can fund, so exactly 6 funding txs
    // proves every hop reached its maximum; each contract is swept once.
    let bitcoind = world.bitcoind();
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
}
