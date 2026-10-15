//! The maker checking the taker's funding: duplicated, overcounted, overstated,
//! spent or evicted outpoints, a proof with no contract binding, and a Taproot
//! contract amount that does not match its output.

use bitcoin::{consensus::encode::serialize_hex, Amount};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    taker::{SwapParams, TakerBehavior},
    utill::TX_BROADCAST_TIMEOUT,
    wallet::{AddressType, Destination},
};

use crate::test_framework::*;

use std::{thread, time::Duration};

use super::wait_for_log_after;

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [DuplicateFundingOutpoint],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn makers_reject_duplicate_funding_outpoints(world: &mut World, params: SwapParams) {
    // The Taproot behavior repeats one contract transaction together with all
    // aligned per-contract vectors, so length and script checks still pass.
    world.taker_mut().swap_fails(
        params,
        "Taproot maker must reject a duplicated contract outpoint",
    );

    // Assert both the taker side duplicate contract passing and the maker-side rejection.
    assert_log!(world; {
        has "Test behavior: duplicating Taproot contract outpoint",
        has "Duplicate Taproot contract outpoint",
        // The Taproot maker must reject before broadcasting outgoing funding.
        lacks "Broadcast Taproot contract tx",
    });
}

/// The maker guards a Legacy funding proof in order — entry count, declared
/// sum, then duplication — so each malice keeps the earlier guards satisfied
/// to reach its own. One maker is enough: the rejection is the point.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [behavior],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Legacy, sats = 500_000, makers = 1, tx_count = tx_count),
    cases = [
        maker_rejects_overcounted_proof_of_funding(
            behavior = TakerBehavior::ExtraFundingTxEntry,
            tx_count = 3,
            expected = "declared incoming count",
        ),
        maker_rejects_overstated_proof_of_funding(
            behavior = TakerBehavior::OverstatedFundingAmount,
            tx_count = 3,
            expected = "declared swap amount",
        ),
        maker_rejects_duplicated_funding_outpoint(
            behavior = TakerBehavior::DuplicateFundingOutpoint,
            tx_count = 2,
            expected = "Duplicate funding outpoint",
        ),
        /// The taker declares 600k in SwapDetails but funds the honest 500k. The
        /// maker priced and froze its plan on the declared amount, so the equality
        /// check — not a band — refuses the proof.
        maker_rejects_underdelivered_legacy_amount(
            behavior = TakerBehavior::ForgeBounds(Amount::from_sat(600_000)),
            tx_count = 3,
            expected = "declared swap amount",
        ),
        /// Same skew on Legacy: one funding output sits below the floor while the
        /// declared sum stays exact, so the per-output floor is what refuses.
        maker_rejects_legacy_funding_output_below_floor(
            behavior = TakerBehavior::SkewSplitBelowFloor,
            tx_count = 2,
            expected = "Legacy funding output below the contract floor",
        ),
    ],
)]
fn run_legacy_proof_guard(world: &mut World, expected: &str, params: SwapParams) {
    world
        .taker_mut()
        .swap_fails(params, "maker must reject the crafted ProofOfFunding");

    assert_log!(world; { has expected });
}

/// A confirmed funding txid proves nothing about its outputs. Here the taker claims
/// its own funding output through the contract path first, then still names that
/// outpoint in ProofOfFunding. The maker must refuse before funding the next hop.
#[world_test(
    maker_behaviors = [Normal, Normal],
    takers = [behavior],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
    cases = [
        maker_rejects_spent_funding_outpoint(
            backend = BitcoindBackend,
            behavior = TakerBehavior::ReplaySpentFundingOutpoint,
        ),
        maker_rejects_spent_funding_outpoint_mempool(
            backend = ElectrumBackend,
            behavior = TakerBehavior::ReplaySpentFundingOutpointMempool,
        ),
    ],
)]
fn run_rejects_spent_funding_outpoint(world: &mut World, params: SwapParams) {
    world.taker_mut().swap_fails(
        params,
        "Legacy maker must reject an already spent funding outpoint",
    );

    assert_log!(world; {
        has "Test behavior: spending the funding outpoint before ProofOfFunding",
        has "Funding output already spent",
        // The maker must reject before broadcasting outgoing funding.
        lacks "SECURITY: Broadcasting",
    });
}

/// A funding tx the maker has already seen can still vanish from the mempool
/// (evicted or replaced). The maker must error out of its confirmation wait
/// once the re-armed broadcast window expires, not wait forever.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [SkipFundingConfirmWait],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 1),
)]
fn maker_errors_when_seen_funding_tx_is_evicted(world: &mut World, params: SwapParams) {
    // Sign a double-spend of every taker UTXO up front, so it can replace the
    // funding tx (which signals RBF) the moment the maker reports seeing it.
    let conflict_tx = {
        let mut wallet = world.taker().inner().get_wallet().write().unwrap();
        wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
        let coins = wallet.list_all_utxo_spend_info();
        let destination = wallet
            .get_next_internal_addresses(1, AddressType::P2TR)
            .unwrap()
            .into_iter()
            .next()
            .unwrap();
        wallet
            .spend_coins(&coins, Destination::Sweep(destination), 200.0)
            .unwrap()
    };

    // The taker skips its confirmation wait, so the contract data arrives while
    // the funding tx is still in the mempool, which puts the maker into its wait.
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare_swap should succeed");

    let log_path = world.taker_log_path();

    // Mining is paused so the funding tx can never confirm; the maker stays in
    // its confirmation wait until the conflict evicts the tx from the mempool.
    world.framework().set_block_gen_paused(true);
    // The swap thread borrows the taker; the main thread keeps its own handle
    // on the framework.
    let framework = world.framework().clone();
    let taker = world.taker_mut();
    // Taken before the swap starts, so a "seen in mempool" logged before the
    // wait below begins still counts.
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
    let swap_result = thread::scope(|s| {
        let swap_handle = s.spawn(|| taker.start(&summary.swap_id));

        wait_for_log_after(
            &log_path,
            log_offset,
            "seen in mempool",
            1,
            Duration::from_secs(120),
        );
        // Sent through bitcoind, not the taker's wallet, whose lock the swap
        // thread holds for long stretches.
        framework
            .bitcoind
            .client
            .send_raw_transaction(serialize_hex(&conflict_tx))
            .expect("conflict tx should replace the funding tx in the mempool");

        // One re-armed broadcast window must pass before the maker errors. Derived,
        // not a fixed number: the poll backs off, so allow a second window for it
        // to notice.
        wait_for_log(&log_path, "did not reappear", TX_BROADCAST_TIMEOUT * 2);
        framework.set_block_gen_paused(false);
        swap_handle.join().expect("taker thread panicked")
    });
    assert!(
        swap_result.is_err(),
        "The swap must fail once the maker's funding wait errors out"
    );
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [SkipSenderContractSigs],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120)],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn maker_rejects_proof_of_funding_with_missing_contract_cache(
    world: &mut World,
    params: SwapParams,
) {
    let maker_spendable_before = world.makers()[0].balances().spendable;

    world.mine(1);

    world.taker_mut().swap_fails(
        params,
        "maker must reject ProofOfFunding without a cached contract binding",
    );

    // Assert both the adversarial action and the maker's fail-closed reason.
    assert_log!(world; {
        has "Test behavior: skipping sender contract signature request before funding",
        has "No cached sender contract for funding prevout",
        // Rejection must happen before the maker reaches the outgoing broadcast
        // boundary in process_resp_contract_sigs_for_recvr_and_sender.
        lacks "SECURITY: Broadcasting",
    });

    world.makers()[0].sync();
    let maker_spendable_after = world.makers()[0].balances().spendable;
    assert_eq!(
        maker_spendable_after, maker_spendable_before,
        "rejected proof must not spend maker liquidity"
    );
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [InvalidTaprootContractAmount],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3),
)]
fn taproot_maker_rejects_contract_amount_mismatch(world: &mut World, params: SwapParams) {
    world.taker_mut().swap_fails(
        params,
        "Taproot swap should fail when taker lies about contract amount",
    );

    assert_log!(world; { has "does not match output value" });
}
