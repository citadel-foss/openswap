//! Everything either side must refuse, in one place.
//!
//! The refusal point differs per case but nothing settles in any of them.
//! The maker refuses: out-of-bounds, forged, or resent `SwapDetails`;
//! insufficient liquidity at offerbook sync or admission; under-delivered
//! amounts; wrong incoming counts; duplicated, overcounted, overstated, or
//! spent funding outpoints; a proof of funding with no contract binding;
//! mismatched taproot contract amounts; and funding plans that cost more than
//! the hop earns. The taker refuses: malformed legacy funding outputs;
//! underfunded, inflated, duplicated, or shape-breaking taproot contracts; and
//! fee skimming on either protocol. A fail-closed guard that lets one through
//! costs someone real funds.

use bitcoin::{
    consensus::encode::serialize_hex,
    secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey},
    Address, Amount, Network,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{
        start_server,
        swap_tracker::{MakerSwapRecord, MakerSwapTracker},
        MakerBehavior, MakerServer,
    },
    protocol::common_messages::ProtocolVersion,
    taker::{
        error::TakerError,
        swap_tracker::{ExchangeProgress, SwapTracker},
        BanReason, BanRecord, MakerState, SwapParams, TakerBehavior, UnavailableReason,
        UnavailableState,
    },
    utill::{MAX_TX_COUNT, MIN_RELAY_FEE_RATE, TX_BROADCAST_TIMEOUT},
    wallet::{min_contract_value_sats, AddressType, Destination},
};

use super::test_framework::*;

use log::info;
use std::{
    fs,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        // 4 UTXOs, not the usual 3: the above-maximum cases need the taker to hold
        // more than the maker is willing to swap.
        fund_taker_default(4) as taker_original_balance,
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances() as maker_spendable_balance,
        mine(1),
    ],
)]
fn test_maker_rejects_out_of_bounds_swap_details(
    world: &mut World,
    taker_original_balance: Amount,
    maker_spendable_balance: Vec<Amount>,
) {
    // The maker advertises min = the smallest swap it accepts, and max = its
    // spendable liquidity. One sat under one relay-floor contract is below both.
    let maker_offer_max = world.makers()[0].balances().regular;
    let contract_floor =
        min_contract_value_sats(ProtocolVersion::Taproot, MIN_RELAY_FEE_RATE).unwrap();
    let below_min = Amount::from_sat(contract_floor - 1);
    let above_max = maker_offer_max + Amount::from_sat(100_000);
    info!(
        "Maker offer max: {}, testing below_min={} and above_max={}",
        maker_offer_max, below_min, above_max
    );

    let preferred: Vec<String> = world.makers().iter().map(|m| m.address()).collect();

    // ---- 1. Below minimum, taker-side offerbook filter ----
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, below_min, 2)
                .with_tx_count(1)
                .with_required_confirms(1),
        )
        .expect_err("an amount under the maker's min_size must not be routable");
    assert!(
        matches!(err, TakerError::NotEnoughMakersInOfferBook),
        "Expected NotEnoughMakersInOfferBook for below-minimum amount, got: {:?}",
        err
    );
    info!("Below-minimum request rejected by the offerbook filter");

    // ---- 2. Above maximum, taker-side offerbook filter ----
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, above_max, 2)
                .with_tx_count(1)
                .with_required_confirms(1),
        )
        .expect_err("an amount over the maker's max_size must not be routable");
    assert!(
        matches!(err, TakerError::NotEnoughMakersInOfferBook),
        "Expected NotEnoughMakersInOfferBook for above-maximum amount, got: {:?}",
        err
    );
    info!("Above-maximum request rejected by the offerbook filter");

    // ---- 3. Below minimum, past the filter: our own planner refuses the contract ----
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, below_min, 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred.clone()),
        )
        .expect_err("the taker must refuse to fund a contract under the floor");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains(&format!(
            "Amount {} sats is below the {} sat contract floor",
            below_min.to_sat(),
            contract_floor
        )),
        "Expected the contract floor refusal, got: {}",
        msg
    );
    info!("Taker refused below-minimum request: {}", msg);

    // ---- 4. Above maximum, past the filter, caught at negotiation ----
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, above_max, 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred.clone()),
        )
        .expect_err("negotiation must refuse an amount over the maker's maximum");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains(&format!(
            "Send amount ({} sats) exceeds maker 0 max_size",
            above_max.to_sat()
        )),
        "Expected the negotiation max_size guard, got: {}",
        msg
    );
    info!("Negotiation refused above-maximum request: {}", msg);

    // ---- 5. Taker aborts after maker selection, before negotiating ----
    world.taker_mut().set_behavior(TakerBehavior::CloseEarly);
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
                .with_tx_count(1)
                .with_required_confirms(1),
        )
        .expect_err("CloseEarly must abort prepare_swap");
    info!("Taker closed early after maker selection: {:?}", err);
    world.taker_mut().set_behavior(TakerBehavior::Normal);

    // ---- 6. Forged below-minimum reaches the maker's own guard ----
    // The nominal 500_000 passes both taker-side layers; the hook rewrites
    // the amount only on the wire, so the maker guard is what must refuse.
    world
        .taker_mut()
        .set_behavior(TakerBehavior::ForgeBounds(below_min));
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred.clone()),
        )
        .expect_err("the maker's own guard must refuse a forged below-minimum amount");
    info!("Maker guard refused forged below-minimum: {:?}", err);

    // ---- 7. Forged above-maximum reaches the maker's own guard ----
    world
        .taker_mut()
        .set_behavior(TakerBehavior::ForgeBounds(above_max));
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred.clone()),
        )
        .expect_err("the maker's own guard must refuse a forged above-maximum amount");
    info!("Maker guard refused forged above-maximum: {:?}", err);

    // ---- 8. Resent SwapDetails: identical refreshes, mutated is rejected ----
    // The hook resends the admitted details unchanged, then with +1 sat. The
    // error string it surfaces tells which arm the maker took for each.
    world
        .taker_mut()
        .set_behavior(TakerBehavior::ResendMutatedDetails);
    let err = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect_err("the resend hook must surface the maker's decision");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains("Maker rejected mutated resent SwapDetails"),
        "Expected the mutated resend to be rejected after the identical one was accepted, got: {}",
        msg
    );
    world.taker_mut().set_behavior(TakerBehavior::Normal);

    world.shutdown_makers();

    assert_logged!(world, "closing early after maker selection");
    // The forged amounts got past both taker-side layers, so the refusal must
    // come from the maker's own guard, logged as a handler error on drop.
    assert_logged!(world, "Swap amount below the incoming contract floor");
    assert_logged!(world, "Swap amount above maximum");
    // The mutated resend dies on the whole-agreement compare: one value, so
    // no single field — feerate included — can drift between connections.
    assert_logged!(world, "parameters differ from stored swap");

    // Nothing was funded, so nothing may have moved.
    world.taker().sync();
    let taker_balances = world.taker().balances();
    info!(
        "Taker balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );
    assert_eq!(
        taker_balances.spendable, taker_original_balance,
        "Taker spendable balance must be untouched after rejected requests"
    );
    // 4 UTXOs of 0.05 BTC, none of them spent.
    assert_eq!(
        taker_balances.regular.to_sat(),
        20000000,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.spendable.to_sat(),
        20000000,
        "Taker spendable balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker must hold no contract funds"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        0,
        "Taker must hold no swap funds"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);

    for (i, (maker, original)) in world
        .makers()
        .iter()
        .zip(maker_spendable_balance)
        .enumerate()
    {
        maker.sync();
        let balances = maker.balances();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
            i, balances.regular, balances.swap, balances.contract, balances.spendable,
        );
        assert_eq!(
            balances.spendable, original,
            "Maker {} spendable balance must be untouched",
            i
        );
        // 4 UTXOs of 0.05 BTC minus the fidelity bond and its fee.
        assert_eq!(
            balances.regular.to_sat(),
            14999757,
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.spendable.to_sat(),
            14999757,
            "Maker {} spendable balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            0,
            "Maker {} must hold no swap funds",
            i
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} must hold no contract funds",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
    }

    info!("Maker SwapDetails rejection test completed successfully!");
}

#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers_without_sync(120)],
    swap(protocol = Taproot, sats = 500_000, makers = 1),
)]
fn test_low_swap_liquidity(world: &mut World, params: SwapParams) {
    // Drain the Maker wallet after fidelity bond is created
    drain_maker_liquidity_after_fidelity(world.makers()[0].inner(), world.bitcoind());
    // Mine a block to confirm the drain, then sync maker wallet
    world.mine(1);
    world.makers()[0].sync();

    info!("Maker should be halted due to low swap liquidity");

    info!("Initiating openswap (Will fail due to maker not accepting any offer due to low swap liquidity)");

    // Attempt the swap - it will fail because maker has no liquidity
    let err = world
        .taker_mut()
        .prepare(params.clone())
        .expect_err("Swap should have failed due to insufficient maker liquidity");
    info!("OpenSwap failed as expected: {err:?}");

    info!("Adding sufficient funds to maker to perform a swap and avoid low swap liquidity");
    world.fund_makers_default();

    // The offerbook still holds the drained max_size=0 offer fetched moments
    // ago, and a sync round would skip re-polling it while it is within
    // OFFER_MAX_AGE_BEFORE_REFRESH, which is 10s for tests. Poll this maker directly so selection sees
    // the re-funded liquidity.
    world
        .taker()
        .inner()
        .poll_maker(world.makers()[0].address())
        .expect("re-poll of the re-funded maker should succeed");

    // Attempt the swap again, it should succeed
    world
        .taker_mut()
        .swap(params)
        .expect("the swap should succeed after re-funding");
}

fn drain_maker_liquidity_after_fidelity(maker: &MakerServer, bitcoind: &bitcoind::BitcoinD) {
    let secp = Secp256k1::new();
    let keypair = bitcoin::key::Keypair::from_secret_key(&secp, &SecretKey::new(&mut OsRng));
    let (xonly, _) = keypair.x_only_public_key();
    let addr = Address::p2tr(&secp, xonly, None, Network::Regtest);
    let coins = maker
        .wallet
        .read()
        .unwrap()
        .list_descriptor_utxo_spend_info();
    let mut wallet = maker.wallet.write().unwrap();
    let tx = wallet
        .spend_from_wallet(MIN_RELAY_FEE_RATE, Destination::Sweep(addr), &coins)
        .unwrap();
    bitcoind.client.send_raw_transaction(&tx).unwrap();
}

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
    let log_path = world.taker_log_path();
    assert_logged!(
        world,
        "Test behavior: duplicating Taproot contract outpoint"
    );
    assert_logged!(world, "Duplicate Taproot contract outpoint");

    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("Broadcast Taproot contract tx"),
        "Taproot maker must reject before broadcasting outgoing funding"
    );
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

    assert_logged!(world, expected);
}

/// The taker funds honestly; the hook forges only the SwapDetails
/// declaration, so the maker's own equality check is what refuses.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [behavior],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Taproot, sats = 500_000, makers = 1, tx_count = 3),
    cases = [
        /// Same under-delivery on Taproot: the declared amount is exact there too.
        maker_rejects_underdelivered_taproot_amount(
            behavior = TakerBehavior::ForgeBounds(Amount::from_sat(600_000)),
            expected = "does not match negotiated swap amount",
        ),
        /// The taker funds 2 incoming contracts but skews one a sat below the
        /// contract floor, keeping the total exact. The equality and count checks
        /// pass, so only the maker's per-contract floor can refuse.
        maker_rejects_taproot_contract_below_floor(
            behavior = TakerBehavior::SkewSplitBelowFloor,
            expected = "Taproot contract below the contract floor",
        ),
        /// The taker declares 2 incoming contracts but funds 3. The maker priced its
        /// sweep reimbursement on the declared count, so the equality check refuses.
        maker_rejects_wrong_taproot_incoming_count(
            behavior = TakerBehavior::ForgeIncomingCount(2),
            expected = "!= declared incoming count",
        ),
    ],
)]
fn run_taproot_declaration_guard(world: &mut World, expected: &str, params: SwapParams) {
    world.taker_mut().swap_fails(
        params,
        "maker must reject contract data that breaks the declaration",
    );

    assert_logged!(world, expected);
}

/// A taker holding a single UTXO cannot fund 2 splits, so negotiation plans
/// hop 0 as one split and declares 1. The maker's "with 1 funding txs" log
/// proves the declared count flowed through, and the swap still completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        // One UTXO, so the hop-0 plan must degrade below the requested tx_count.
        fund_taker_default(1),
        fund_makers_default(),
        start_makers(120),
        mine(1),
    ],
)]
fn one_utxo_taker_completes_degraded_swap(world: &mut World) {
    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);
    world
        .taker_mut()
        .swap(params)
        .expect("a degraded one-split swap must complete");

    assert_logged!(world, "with 1 funding txs");
}

/// The maker forwards 1,075 sats. Two splits net to 372 each, under the 485
/// taproot floor, but one split nets to 910, so admission must re-plan with one.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn maker_degrades_split_count_when_netting_breaks_the_floor(world: &mut World) {
    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(1_800), 1)
        .with_tx_count(2)
        .with_required_confirms(1);
    world
        .taker_mut()
        .prepare(params)
        .expect("admission must fall back to one split");
    world
        .framework()
        .assert_log("with 1 funding split(s)", &world.taker_log_path());
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

    let log_path = world.taker_log_path();
    assert_logged!(
        world,
        "Test behavior: spending the funding outpoint before ProofOfFunding"
    );
    assert_logged!(world, "Funding output already spent");

    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("SECURITY: Broadcasting"),
        "Maker must reject before broadcasting outgoing funding"
    );
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
    let swap_result = thread::scope(|s| {
        let swap_handle = s.spawn(|| taker.start(&summary.swap_id));

        wait_for_new_log(&log_path, "seen in mempool", Duration::from_secs(120));
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
    let log_path = world.taker_log_path();
    assert_logged!(
        world,
        "Test behavior: skipping sender contract signature request before funding"
    );
    assert_logged!(world, "No cached sender contract for funding prevout");

    // Rejection must happen before the maker reaches the outgoing broadcast
    // boundary in process_resp_contract_sigs_for_recvr_and_sender.
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("SECURITY: Broadcasting"),
        "maker must reject before broadcasting outgoing funding transactions"
    );

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
fn test_taproot_maker_rejects_contract_amount_mismatch(world: &mut World, params: SwapParams) {
    world.taker_mut().swap_fails(
        params,
        "Taproot swap should fail when taker lies about contract amount",
    );

    assert_logged!(world, "does not match output value");
}

#[world_test(
    backend = BitcoindBackend,
    // First maker returns Legacy sender contract data whose contract input points
    // at a real funding tx output, but not the advertised 2-of-2 multisig output.
    maker_behaviors = [MalformedLegacyFundingOutput, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn test_legacy_taker_rejects_malformed_maker_funding_output(world: &mut World, params: SwapParams) {
    // The taker must reject before signing/finalizing; otherwise it can later
    // report success while the incoming sweep is unspendable.
    let error = world.taker_mut().swap_fails(
        params,
        "taker must reject malformed maker sender contract data",
    );
    let error = format!("{error:?}");
    assert!(
        error.contains("funding output does not pay to advertised multisig"),
        "unexpected taker error: {}",
        error
    );

    // Pin the operator-visible rejection, not just the returned Rust error.
    assert_logged!(world, "funding output does not pay to advertised multisig");
}

#[world_test(
    backend = BitcoindBackend,
    // The maker funds a 10k-sat Taproot output but advertises the normal
    // post-fee amount in TaprootContractData. This models a maker trying to
    // make the taker accept an incoming swapcoin for more than the tx pays.
    maker_behaviors = [UnderfundTaprootContract],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers_without_sync(120), mine(1)],
    // A 30k-sat swap keeps the maker's 10k-sat underfunded output valid enough
    // to broadcast while still making the amount mismatch obvious.
    swap(protocol = Taproot, sats = 30_000, makers = 1, tx_count = 3),
)]
fn test_taproot_rejects_underfunded_maker_contract(world: &mut World, params: SwapParams) {
    // The taker must reject during maker contract verification, before storing
    // an incoming swapcoin from the underfunded contract data. The maker's
    // response amounts are read from its actual funding outputs, so the
    // underfunding is caught by the exact total-fee check.
    let error = world
        .taker_mut()
        .swap_fails(params, "taker must reject an underfunded maker contract");
    match error {
        TakerError::General(message) => {
            assert!(
                message.contains("does not match the negotiated hop total"),
                "unexpected taker error: {}",
                message
            );
        }
        other => panic!("unexpected taker error: {:?}", other),
    }

    // Assert the rejection came from the exact-amount check.
    assert_logged!(world, "does not match the negotiated hop total");
}

/// Admission plans but reserves nothing: coins are claimed only at funding, so a
/// second admission on the same liquidity is accepted and nothing stays locked.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
    takers = [Normal, Normal],
    setup = [
        // Fund two takers with enough for a 1 BTC swap each.
        fund_nth_taker_default(0, 4),
        fund_nth_taker_default(1, 4),
        // Fund the maker with four 0.05 BTC UTXOs. After the fidelity bond, its
        // spendable liquidity is ~15M sats, so two 9M-sat swaps cannot both be
        // funded, while each request is still below the advertised max_size.
        fund_makers_default(),
        start_makers(120),
    ],
)]
fn test_admission_reserves_no_liquidity(world: &mut World) {
    let maker_addr = world.makers()[0].address();

    // Taker 0 admits a swap with the maker. prepare_swap only negotiates;
    // it does not fund, so the maker reserves nothing yet.
    let first = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(9_000_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_addr.clone()]);
    world.takers_mut()[0]
        .prepare(first)
        .expect("first swap should be admitted");

    // Taker 1 asks for the same amount and is admitted too: nothing is locked
    // until one of them funds.
    let second = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(9_000_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_addr]);
    world.takers_mut()[1]
        .prepare(second)
        .expect("second swap should be admitted on the same liquidity");
    assert_eq!(
        world.makers()[0].inner().reserved_inputs().unwrap(),
        0,
        "admission must not reserve any input"
    );
}

/// Out-of-bounds swap parameters are refused by the taker's own prepare
/// guards, before any maker is contacted — so this needs no maker at all.
/// The maker's own admission guards stay as defense for clients that skip
/// these checks; `maker_rejects_forged_swap_details_at_admission` exercises
/// those with forged wire values.
#[world_test(
    backend = BitcoindBackend,
    makers = 0,
    takers = [Normal],
    setup = [fund_taker_default(3) as taker_original_balance],
)]
fn taker_rejects_out_of_bounds_params_at_prepare(
    world: &mut World,
    taker_original_balance: Amount,
) {
    let params = || SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1);
    let cases: Vec<(SwapParams, String)> = vec![
        (
            params().with_tx_count(0),
            format!(
                "Transaction count 0 is outside the protocol bounds 1..={}",
                MAX_TX_COUNT
            ),
        ),
        (
            params().with_tx_count(MAX_TX_COUNT + 1),
            format!(
                "Transaction count {} is outside the protocol bounds 1..={}",
                MAX_TX_COUNT + 1,
                MAX_TX_COUNT
            ),
        ),
        (
            params().with_max_input_budget(0),
            format!(
                "Max input budget 0 is outside the protocol bounds 1..={}",
                MAX_TX_COUNT
            ),
        ),
        (
            params().with_required_confirms(0),
            "Required confirmations must be at least 1".to_string(),
        ),
        (
            params().with_feerate(0),
            format!(
                "Swap feerate 0 sats/vB is below the {} sats/vB relay floor",
                MIN_RELAY_FEE_RATE as u64
            ),
        ),
    ];
    for (params, expected) in cases {
        let error = world
            .taker_mut()
            .prepare(params)
            .expect_err("an out-of-bounds parameter must fail at prepare time");
        assert!(
            format!("{error:?}").contains(&expected),
            "expected '{}', got: {:?}",
            expected,
            error
        );
    }
    let balance = world.taker().balances();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "prepare-time rejections must not spend anything"
    );
}

/// Honest parameters pass the taker's own guards; the behavior hook rewrites
/// exactly one SwapDetails field on the wire, so the refusal must come from
/// the maker's own admission guard — logged as a handler error on the dropped
/// connection. Nothing is funded in any case.
#[world_test(
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
    cases = [
        maker_rejects_forged_swap_details_at_admission(backend = BitcoindBackend),
        /// Same forgeries on Electrum: admission checks the maker's offer and
        /// liquidity against the indexer backend.
        maker_rejects_forged_swap_details_at_admission_electrum(backend = ElectrumBackend),
    ],
)]
fn run_maker_rejects_forged_swap_details_at_admission(
    world: &mut World,
    taker_original_balance: Amount,
) {
    let preferred = vec![world.makers()[0].address()];
    let params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(2)
            .with_required_confirms(1)
            .with_preferred_makers(preferred.clone())
    };
    // The taker funds this hop with 2 contracts, so the shape needs 2 floors in.
    let two_floors =
        2 * min_contract_value_sats(ProtocolVersion::Taproot, MIN_RELAY_FEE_RATE).unwrap();
    let cases: Vec<(TakerBehavior, &str)> = vec![
        (
            TakerBehavior::ForgeBounds(Amount::from_sat(two_floors - 1)),
            "Swap amount below the incoming contract floor",
        ),
        // Enough to cover the incoming contracts, but not our fee, the sweeps and one outgoing contract.
        (
            TakerBehavior::ForgeBounds(Amount::from_sat(two_floors)),
            "Swap amount below the minimum for its shape",
        ),
        (
            TakerBehavior::ForgeFeerate(0),
            "Swap feerate below the relay floor",
        ),
        (
            TakerBehavior::ForgeTxCount(0),
            "Transaction count must be non-zero",
        ),
        (
            TakerBehavior::ForgeTxCount(MAX_TX_COUNT + 1),
            "Transaction count above the protocol maximum",
        ),
        (
            TakerBehavior::ForgeMaxInputBudget(0),
            "Input budget must be non-zero",
        ),
        (
            TakerBehavior::ForgeMaxInputBudget(MAX_TX_COUNT + 1),
            "Input budget above the protocol maximum",
        ),
        (
            TakerBehavior::ForgeIncomingCount(0),
            "Incoming count outside the protocol bounds",
        ),
        (
            TakerBehavior::ForgeIncomingCount(MAX_TX_COUNT + 1),
            "Incoming count outside the protocol bounds",
        ),
    ];
    let log_path = world.taker_log_path();
    for (behavior, expected) in &cases {
        world.taker_mut().set_behavior(*behavior);
        let offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);
        let error = world
            .taker_mut()
            .prepare(params())
            .expect_err("the maker's admission guard must refuse the forged SwapDetails");
        // Each refusal must surface after its own forgery: two cases share a
        // message, so a whole-log check would let a missing guard pass.
        wait_for_log_after(&log_path, offset, expected, 1, Duration::from_secs(60));
        info!("forged {:?} refused at admission: {:?}", behavior, error);
    }
    world.taker_mut().set_behavior(TakerBehavior::Normal);

    // Nothing was funded: the taker's balance is untouched.
    let balance = world.taker().balances();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "admission rejections must not spend anything"
    );

    world.shutdown_makers();

    // The maker never reserved or spent anything either.
    world.makers()[0].sync();
    let maker_balances = world.makers()[0].balances();
    assert_eq!(
        maker_balances.spendable.to_sat(),
        14999757,
        "maker spendable must be untouched after rejected admissions"
    );
    assert_eq!(maker_balances.swap, Amount::ZERO);
    assert_eq!(maker_balances.contract, Amount::ZERO);
}

/// A maker whose contract response contradicts what the taker can check —
/// overcounted, repeating one funded output, funding shaped differently from
/// its Ack, or misstating amounts — is cheating; the taker must refuse it and
/// ban the maker.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [behavior],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = protocol, sats = sats, makers = 1, tx_count = tx_count),
    cases = [
        taker_rejects_overproduced_legacy_contracts(
            protocol = ProtocolVersion::Legacy,
            sats = 500_000,
            behavior = MakerBehavior::OverproduceContractData,
            tx_count = 3,
            expected = "its reported plan has",
        ),
        taker_rejects_overproduced_taproot_contracts(
            protocol = ProtocolVersion::Taproot,
            sats = 500_000,
            behavior = MakerBehavior::OverproduceContractData,
            tx_count = 3,
            expected = "its reported plan has",
        ),
        /// One funded Taproot output claimed twice, with the count and total amount
        /// still exact: only the taker's duplicate-outpoint check can catch it.
        taker_rejects_duplicated_taproot_contract_outpoint(
            protocol = ProtocolVersion::Taproot,
            sats = 500_000,
            behavior = MakerBehavior::DuplicateContractOutpoint,
            tx_count = 3,
            expected = "duplicate Taproot contract outpoint",
        ),
        /// The Legacy mirror: one funded output backing two sender contracts, count
        /// and total exact, so only the taker's duplicate-outpoint check can catch it.
        taker_rejects_duplicated_legacy_contract_outpoint(
            protocol = ProtocolVersion::Legacy,
            sats = 500_000,
            behavior = MakerBehavior::DuplicateContractOutpoint,
            tx_count = 3,
            expected = "duplicate sender contract for funding outpoint",
        ),
        /// An Ack that declares more inputs per split than the maker funds with
        /// would charge the taker for inputs nobody spends.
        test_taproot_rejects_overreported_funding_inputs(
            protocol = ProtocolVersion::Taproot,
            sats = 500_000,
            behavior = MakerBehavior::OverreportFundingInputs,
            tx_count = 2,
            expected = "its plan declared",
        ),
        test_legacy_rejects_overreported_funding_inputs(
            protocol = ProtocolVersion::Legacy,
            sats = 500_000,
            behavior = MakerBehavior::OverreportFundingInputs,
            tx_count = 2,
            expected = "its plan declared",
        ),
        test_legacy_taker_rejects_fee_skimming_maker(
            protocol = ProtocolVersion::Legacy,
            sats = 500_000,
            behavior = MakerBehavior::FeeSkimming,
            tx_count = 3,
            expected = "does not match the negotiated hop total",
        ),
        test_taproot_rejects_fee_skimming_maker(
            protocol = ProtocolVersion::Taproot,
            sats = 30_000,
            behavior = MakerBehavior::FeeSkimming,
            tx_count = 3,
            expected = "does not match the negotiated hop total",
        ),
        /// The maker funds honestly but claims one contract pays a sat more than its
        /// real output (and another a sat less, keeping the total exact). Only the
        /// taker's per-output amount binding can catch that.
        taker_rejects_inflated_taproot_contract_amount(
            protocol = ProtocolVersion::Taproot,
            sats = 30_000,
            behavior = MakerBehavior::InflateContractAmount,
            tx_count = 3,
            expected = "does not match output value",
        ),
    ],
)]
fn run_corrupt_contract_response(world: &mut World, expected: &str, params: SwapParams) {
    let error = world
        .taker_mut()
        .swap_fails(params, "a corrupt contract response must be rejected");
    assert!(
        format!("{error:?}").contains(expected),
        "unexpected error: {:?}",
        error
    );

    // The violation is arithmetically proven, so the maker's standing steps
    // off Good in the offerbook.
    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "a proven contract violation must ban the maker"
    );
}

/// A swap the maker cannot fund even degraded to one split must fail before
/// any broadcast. The pool sits below what a single 500k split costs the
/// maker (~499,133 sats at these fees), so the maker's advertised max_size
/// refuses the ask at negotiation.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        // Bond: exactly 5,000,000 + its 243 sat fee, leaving zero change.
        fund_makers(1, Amount::from_sat(5_000_243), AddressType::P2TR),
        fund_makers(1, Amount::from_sat(499_000), AddressType::P2TR),
        spawn_ready_makers_and_mine(),
    ],
)]
fn maker_without_fee_headroom_fails_before_any_broadcast(
    world: &mut World,
    taker_original_balance: Amount,
) {
    let maker_addr = world.makers()[0].address();
    let error = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect_err("a swap the maker cannot fund even degraded must fail at negotiation");
    let msg = format!("{error:?}");
    assert!(
        msg.contains("exceeds maker 0 max_size"),
        "unexpected error: {:?}",
        error
    );
    let balance = world.taker().balances();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "a negotiation rejection must not spend anything"
    );

    world.shutdown_makers();
    let log_path = world.taker_log_path();
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("SECURITY: Broadcasting"),
        "an unfundable swap must never reach a funding broadcast"
    );
}

/// A fragmented maker wallet at a high negotiated feerate can only fund the
/// hop by packing many inputs the taker never reimburses (`max_input_budget`
/// is 1). When that unreimbursed cost exceeds the hop's service fee, the
/// maker refuses at admission — before either side locks anything.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        // The fidelity bond needs one large UTXO (5,000,000 sats + its 243 sat
        // fee, leaving no change); the swap liquidity is eight small ones, so
        // funding 500k sats can only pack six of them into a single split.
        fund_makers(1, Amount::from_sat(5_000_243), AddressType::P2TR),
        fund_makers(8, Amount::from_sat(100_000), AddressType::P2TR),
        spawn_ready_makers_and_mine(),
    ],
)]
fn maker_rejects_over_budget_funding_plan(world: &mut World, taker_original_balance: Amount) {
    // The pool sum covers the amount, but the admission-time plan prices the
    // real input cost: six unreimbursed inputs at 100 sats/vB cost more than
    // the hop earns, so negotiation fails and nothing is locked.
    let error = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(2)
                .with_max_input_budget(1)
                .with_feerate(100)
                .with_required_confirms(1),
        )
        .expect_err("the maker must refuse an over-budget plan at admission");
    assert!(
        format!("{error:?}").contains("failed and no spare makers available"),
        "unexpected error: {:?}",
        error
    );
    let balance = world.taker().balances();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "an admission rejection must not spend anything"
    );

    world.shutdown_makers();
    assert_logged!(world, "above the taker's input budget");
}

/// Poll the maker's swap tracker until the swap's timelock recovery has
/// reclaimed an outgoing contract; panics after `timeout`.
/// The phase field regresses to TimelockWaiting on later passes, so the
/// recovered-txid list is the durable signal.
fn wait_for_maker_timelock_recovery(
    data_dir: &std::path::Path,
    swap_id: &str,
    timeout: Duration,
) -> MakerSwapRecord {
    let start = Instant::now();
    loop {
        if let Ok(tracker) = MakerSwapTracker::load_or_create(data_dir) {
            if let Some(record) = tracker.get_record(swap_id) {
                if !record.recovery.outgoing_recovered.is_empty() {
                    return record.clone();
                }
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "timed out waiting for maker timelock recovery of {}",
            swap_id
        );
        thread::sleep(Duration::from_secs(5));
    }
}

/// The maker's second funding broadcast fails with the first tx already sent.
/// The partial batch must not read as never broadcast: recovery keeps the
/// swap's material and reclaims the on-chain split via timelock.
#[world_test(
    maker_behaviors = [FailSecondBroadcast],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = protocol, sats = 500_000, makers = 1),
    cases = [
        maker_recovers_partial_broadcast_legacy(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_999_311,
        ),
        maker_recovers_partial_broadcast_taproot(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
            expected_spendable = 14_999_463,
        ),
        maker_recovers_partial_broadcast_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            expected_spendable = 14_999_311,
        ),
    ],
)]
fn run_maker_partial_broadcast<B: TestBackend>(
    world: &mut World,
    expected_spendable: u64,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail when the maker's second broadcast fails"
    );

    let log_path = world.taker_log_path();
    assert_logged!(world, "Test behavior: failing the second");

    // The 30s idle timeout starts recovery; the timelock path then needs the
    // maker's outgoing timelock (150 CSV blocks from the contract broadcast).
    let record = wait_for_maker_timelock_recovery(
        &world.makers()[0].inner().data_dir,
        &swap_id,
        timelock_recovery_wait::<B>() + Duration::from_secs(120),
    );

    // One tx of the two-tx batch was recorded before the failure — per-tx
    // state, not a single end-of-batch flag.
    assert_eq!(
        record.funding_broadcast_txids.len(),
        1,
        "exactly the first funding tx may be recorded as broadcast"
    );
    assert_eq!(
        record.recovery.outgoing_recovered.len(),
        1,
        "the on-chain split must be timelock-recovered"
    );

    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("nothing to recover. Discarding swapcoins"),
        "a partial batch must never be discarded as never broadcast"
    );

    // The unsent split's inputs must return to the pool without a restart.
    let deadline = Instant::now() + Duration::from_secs(180);
    while world.makers()[0].inner().reserved_inputs().unwrap() != 0 {
        assert!(
            Instant::now() < deadline,
            "recovery left the unsent split's inputs reserved"
        );
        thread::sleep(Duration::from_secs(2));
    }

    // Finished recovery stops the maker, and its exit rearms the wallet backend.
    // Join without sending another stop, which would cancel our sync again.
    world.join_makers();

    world.mine(1);
    world.framework().wait_for_electrs_tip();
    let maker = &world.makers()[0];
    maker.sync();
    let balances = maker.balances();
    info!(
        "Maker balances after partial-broadcast recovery: regular={}, swap={}, contract={}, spendable={}",
        balances.regular, balances.swap, balances.contract, balances.spendable
    );
    assert_eq!(balances.contract, Amount::ZERO);
    assert_eq!(balances.swap, Amount::ZERO);
    assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
    assert_eq!(
        balances.spendable.to_sat(),
        expected_spendable,
        "maker spendable after reclaiming the on-chain split"
    );
}

/// The taker's second funding broadcast fails with the first split already in
/// the mempool and a spare maker available. Substitution would delete the
/// on-chain split's recovery material, so the recorded phase — not the
/// backend's answer — must route the taker to recovery instead.
#[world_test(
    maker_behaviors = [Normal, Normal],
    takers = [FailSecondFundingBroadcast],
    setup = [
        fund_taker_default(3) as taker_original_balance,
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 1),
    cases = [
        taker_recovers_partial_broadcast_with_spare_maker(
            backend = BitcoindBackend,
            expected_spendable = 14_999_554,
        ),
        /// The same partial batch on Electrum: the backend can lag the session's own
        /// broadcast, so only the recorded phase keeps the spare maker unused and
        /// the recovery material intact.
        taker_recovers_partial_broadcast_with_spare_maker_electrum(
            backend = ElectrumBackend,
            expected_spendable = 14_999_554,
        ),
    ],
)]
fn run_taker_recovers_partial_broadcast_with_spare_maker(
    world: &mut World,
    taker_original_balance: Amount,
    expected_spendable: u64,
    params: SwapParams,
) {
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail at the taker's second funding broadcast"
    );

    let log_path = world.taker_log_path();
    assert_logged!(world, "Test behavior: failing the second funding broadcast");

    // The chain check found split 1 in the mempool, so the spare maker must
    // stay unused and the recovery material must survive.
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("substituting maker 0 with spare"),
        "substitution would delete the on-chain split's recovery material"
    );
    assert!(
        !log_contents.contains("Re-initializing funding after maker substitution"),
        "funding reinitialize destroys the on-chain split's swapcoins"
    );

    let tracker = SwapTracker::load_or_create(&world.temp_dir().join("taker1")).unwrap();
    let record = tracker
        .get_record(&swap_id)
        .expect("swap record must exist");
    assert_eq!(
        record.phase,
        openswap::taker::swap_tracker::SwapPhase::Failed
    );
    assert_eq!(
        record.failed_at_phase,
        Some(openswap::taker::swap_tracker::SwapPhase::FundsBroadcast),
        "the phase must be persisted before the broadcast loop"
    );
    assert!(
        matches!(
            record.makers[0].exchange,
            ExchangeProgress::Legacy(ref legacy) if legacy.prev_funding_broadcast
        ),
        "the broadcast milestone must be recorded before the loop, not after it"
    );
    assert_eq!(
        world
            .taker()
            .inner()
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        2,
        "both splits' swapcoins must survive — no substitution cleanup"
    );

    // Recovery reclaims the on-chain split once its timelock matures.
    let recovery_start = Instant::now();
    while !world.taker().inner().is_recovery_complete() {
        assert!(
            recovery_start.elapsed() <= Duration::from_secs(360),
            "taker recovery did not complete in time"
        );
        thread::sleep(Duration::from_secs(5));
    }

    world.mine(1);
    world.framework().wait_for_electrs_tip();
    world.taker().sync();
    let balances = world.taker().balances();
    info!(
        "Taker balances after partial-broadcast recovery: original={}, regular={}, swap={}, contract={}, spendable={}",
        taker_original_balance,
        balances.regular,
        balances.swap,
        balances.contract,
        balances.spendable
    );
    assert_eq!(balances.contract, Amount::ZERO);
    assert_eq!(balances.swap, Amount::ZERO);
    assert_eq!(
        balances.spendable.to_sat(),
        expected_spendable,
        "taker spendable after recovering the partial batch"
    );
}

/// One replay-guard scenario: swap 1 either completes or dies with the maker's
/// claim live, then swap 2 replays its funding under a fresh id and must be
/// rejected before the maker funds anything.
struct ReplayScenario {
    behavior: TakerBehavior,
    protocol: ProtocolVersion,
    taker_utxos: u32,
    pin_maker: bool,
    swap1_completes: bool,
    sync_after_swap1: bool,
    swapcoins_before: Option<(usize, &'static str)>,
    swap2_reject_msg: &'static str,
    needle: &'static str,
    needle_timeout_secs: u64,
    forbidden_in_tail: &'static [(&'static str, &'static str)],
    swapcoins_after: Option<(usize, &'static str)>,
}

const REPLAYED_TAPROOT_AFTER_COMPLETION: ReplayScenario = ReplayScenario {
    behavior: TakerBehavior::ReplayTaprootContractData,
    protocol: ProtocolVersion::Taproot,
    taker_utxos: 3,
    pin_maker: false,
    swap1_completes: true,
    sync_after_swap1: false,
    swapcoins_before: None,
    swap2_reject_msg: "the maker must reject replayed contract data",
    needle: "Taproot contract output already spent",
    needle_timeout_secs: 120,
    forbidden_in_tail: &[(
        "Broadcast Taproot contract tx",
        "the maker must not fund the replayed swap",
    )],
    swapcoins_after: Some((0, "the replay must not leave new incoming swapcoins behind")),
};

const REPLAYED_LEGACY_POF_IN_FLIGHT: ReplayScenario = ReplayScenario {
    behavior: TakerBehavior::ReplayLegacyProofOfFunding,
    protocol: ProtocolVersion::Legacy,
    taker_utxos: 4,
    pin_maker: true,
    swap1_completes: false,
    sync_after_swap1: true,
    swapcoins_before: None,
    swap2_reject_msg: "the maker must reject the replayed proof of funding",
    needle: "Legacy contract txid already in use",
    needle_timeout_secs: 60,
    forbidden_in_tail: &[(
        "SECURITY: Broadcasting",
        "the maker must not fund the replayed swap",
    )],
    swapcoins_after: None,
};

const REPLAYED_TAPROOT_IN_FLIGHT: ReplayScenario = ReplayScenario {
    behavior: TakerBehavior::ReplayTaprootContractDataInFlight,
    protocol: ProtocolVersion::Taproot,
    taker_utxos: 4,
    pin_maker: true,
    swap1_completes: false,
    sync_after_swap1: false,
    swapcoins_before: Some((1, "swap 1's incoming swapcoin must be live on the maker")),
    swap2_reject_msg: "the maker must reject the in-flight replayed contract data",
    needle: "Contract txid already in use",
    needle_timeout_secs: 60,
    forbidden_in_tail: &[
        (
            "Taproot contract txid already in use",
            "the atomic claim must fire before the per-contract seen-check",
        ),
        (
            "Broadcast Taproot contract tx",
            "the maker must not fund the replayed swap",
        ),
    ],
    swapcoins_after: Some((1, "the replay must not add incoming swapcoins")),
};

#[world_test(
    maker_behaviors = [Normal],
    takers = [s.behavior],
    setup = [
        fund_taker_default(s.taker_utxos),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
    cases = [
        /// A completed swap's Taproot contract data re-presented under a fresh swap id
        /// must be rejected: the outputs are already spent by the maker's sweep.
        /// The taker behavior resends its first swap's contract data verbatim.
        maker_rejects_replayed_taproot_contract_data(
            backend = BitcoindBackend,
            s = REPLAYED_TAPROOT_AFTER_COMPLETION,
        ),
        /// Same replay on Electrum: the spent-output answer comes from the indexer,
        /// not the wallet's own view of the mempool and chain.
        maker_rejects_replayed_taproot_contract_data_electrum(
            backend = ElectrumBackend,
            s = REPLAYED_TAPROOT_AFTER_COMPLETION,
        ),
        /// The Legacy mirror of the Taproot replay: one confirmed funding's proof
        /// re-presented under a fresh swap id must be rejected while the first
        /// swap's claim is still live.
        maker_rejects_replayed_legacy_contract_data(
            backend = BitcoindBackend,
            s = REPLAYED_LEGACY_POF_IN_FLIGHT,
        ),
        /// Same replay on Electrum: the confirmation and seen answers come from the
        /// indexer, which lags the session's own view of the chain.
        maker_rejects_replayed_legacy_contract_data_electrum(
            backend = ElectrumBackend,
            s = REPLAYED_LEGACY_POF_IN_FLIGHT,
        ),
        /// The in-flight arm of the Taproot replay guard: swap 2 presents swap 1's
        /// contract while swap 1's claim is still live on the maker — before any
        /// sweep, so only the atomic claim (not the spent check) can refuse it.
        /// The behavior hook dies right after the maker answers swap 1's contract
        /// data, then replays that data under swap 2's fresh id.
        maker_rejects_replayed_taproot_contract_data_in_flight(
            backend = BitcoindBackend,
            s = REPLAYED_TAPROOT_IN_FLIGHT,
        ),
        /// Same in-flight replay on Electrum: the claim is in-memory, but the
        /// confirmation wait it protects runs against the indexer.
        maker_rejects_replayed_taproot_contract_data_in_flight_electrum(
            backend = ElectrumBackend,
            s = REPLAYED_TAPROOT_IN_FLIGHT,
        ),
    ],
)]
fn run_replay_guard(world: &mut World, s: ReplayScenario) {
    let preferred = vec![world.makers()[0].address()];
    let params = || {
        let p = SwapParams::new(s.protocol, Amount::from_sat(500_000), 1).with_tx_count(1);
        if s.pin_maker {
            p.with_preferred_makers(preferred.clone())
        } else {
            p
        }
    };

    let summary1 = world
        .taker_mut()
        .prepare(params())
        .expect("prepare 1 must succeed");
    if s.swap1_completes {
        // Swap 1 completes normally; its contract data is cached for the replay.
        world
            .taker_mut()
            .start(&summary1.swap_id)
            .expect("swap 1 must succeed");

        // Wait until the maker's sweep is confirmed and the swap-1 swapcoin
        // has left the store, so only the chain can answer the replay.
        let sweep_wait = Instant::now();
        loop {
            let count = world.makers()[0]
                .inner()
                .wallet
                .read()
                .unwrap()
                .get_incoming_swapcoins_count();
            if count == 0 {
                break;
            }
            assert!(
                sweep_wait.elapsed() <= Duration::from_secs(120),
                "maker did not sweep and drop the swap-1 incoming swapcoin in time"
            );
            thread::sleep(Duration::from_secs(2));
        }
    } else {
        // Swap 1 dies right after the maker processed its funding, so the
        // maker's claim on the incoming contracts is still live.
        let swap1 = world.taker_mut().start(&summary1.swap_id);
        assert!(
            swap1.is_err(),
            "the behavior hook must abort swap 1 with the maker's claim in flight"
        );
        if let Some((count, msg)) = s.swapcoins_before {
            assert_eq!(
                world.makers()[0]
                    .inner()
                    .wallet
                    .read()
                    .unwrap()
                    .get_incoming_swapcoins_count(),
                count,
                "{}",
                msg
            );
        }
        // With recovery suppressed nothing syncs the wallet between swaps;
        // swap 2's funding must not re-pick swap 1's spent UTXOs.
        if s.sync_after_swap1 {
            world.taker().sync();
        }
        // Hold the chain still so the replay lands inside the claim's window.
        world.framework().set_block_gen_paused(true);
    }

    // Swap 2: fresh id, replayed funding. The maker must reject before
    // funding anything.
    let log_path = world.taker_log_path();
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let summary2 = world
        .taker_mut()
        .prepare(params())
        .expect("prepare 2 must succeed");
    assert_ne!(summary1.swap_id, summary2.swap_id);
    let swap2 = world.taker_mut().start(&summary2.swap_id);
    assert!(swap2.is_err(), "{}", s.swap2_reject_msg);

    wait_logged!(world, s.needle, Duration::from_secs(s.needle_timeout_secs));

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = contents
        .get(log_offset as usize..)
        .unwrap_or(contents.as_str());
    for (forbidden, msg) in s.forbidden_in_tail {
        assert!(!tail.contains(forbidden), "{}", msg);
    }
    if let Some((count, msg)) = s.swapcoins_after {
        assert_eq!(
            world.makers()[0]
                .inner()
                .wallet
                .read()
                .unwrap()
                .get_incoming_swapcoins_count(),
            count,
            "{}",
            msg
        );
    }

    if !s.swap1_completes {
        world.framework().set_block_gen_paused(false);
    }
}

/// `wait_for_log`, but matching only content past a pre-captured offset and
/// requiring at least `min_count` occurrences. `wait_for_new_log` snapshots
/// the offset at call time, which races a needle logged just before the call.
fn wait_for_log_after(
    log_path: &str,
    offset: u64,
    needle: &str,
    min_count: usize,
    timeout: Duration,
) {
    let start = Instant::now();
    loop {
        if let Ok(contents) = std::fs::read_to_string(log_path) {
            if contents
                .get(offset as usize..)
                .is_some_and(|tail| tail.matches(needle).count() >= min_count)
            {
                // Never echo the needle: callers count occurrences in the log
                // after this returns, and the echo would match itself.
                log::info!("wait_for_log_after satisfied");
                return;
            }
        }
        assert!(
            start.elapsed() <= timeout,
            "Timed out waiting for log message '{}' (x{}) in {}",
            needle,
            min_count,
            log_path
        );
        thread::sleep(Duration::from_secs(2));
    }
}

/// The step both concurrent-replay tests share once their maker is up: both
/// takers leave the world, and mining pauses so every swap stalls in the
/// confirmation wait. Returns the takers, the maker's address, the log path
/// and the log length at the pause.
fn concurrent_replay_setup(world: &mut World) -> (TakerHandle, TakerHandle, String, String, u64) {
    // Both takers run on their own threads, so they leave the world here.
    let taker1 = world.take_taker();
    let taker2 = world.take_taker();

    let maker_address = world.makers()[0].address();
    let log_path = world.taker_log_path();

    // Hold the swaps' funding unconfirmed: each maker handler blocks in the
    // confirmation wait.
    world.framework().set_block_gen_paused(true);
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    (taker1, taker2, maker_address, log_path, log_offset)
}

/// The genuinely concurrent arm of the Taproot replay guard: swap 1's
/// contract txs sit unconfirmed, so the seen-check has nothing to see and
/// the atomic claim must reject taker 2's replayed contract data.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [ReplayTaprootContractData, ReplayTaprootContractData],
    setup = [
        fund_nth_taker_default(0, 3),
        fund_nth_taker_default(1, 3),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
)]
fn maker_rejects_concurrent_replayed_taproot_contract_data(world: &mut World) {
    let (mut taker1, mut taker2, maker_address, log_path, log_offset) =
        concurrent_replay_setup(world);

    let params = |address: &str| {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_preferred_makers(vec![address.to_string()])
    };

    // Swap 1 runs on its own thread: it sends real contract data, then waits
    // on a maker response that cannot arrive while mining is paused.
    let swap1_address = maker_address.clone();
    let swap1 = thread::spawn(move || {
        let summary = taker1
            .prepare(params(&swap1_address))
            .expect("prepare 1 must succeed");
        taker1.start(&summary.swap_id)
    });

    // Barrier: the maker claimed swap 1's incoming txids and is inside the
    // confirmation wait.
    wait_for_log_after(
        &log_path,
        log_offset,
        "confirmation(s) on tx",
        1,
        Duration::from_secs(120),
    );

    // Swap 2 replays swap 1's contract data under a fresh id. The atomic
    // claim is the only guard that can refuse it this early.
    let summary2 = taker2
        .prepare(params(&maker_address))
        .expect("prepare 2 must succeed");
    let swap2 = taker2.start(&summary2.swap_id);
    assert!(
        swap2.is_err(),
        "the maker must reject the concurrent replayed contract data"
    );

    wait_for_log_after(
        &log_path,
        log_offset,
        "Contract txid already in use",
        1,
        Duration::from_secs(60),
    );
    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = contents
        .get(log_offset as usize..)
        .unwrap_or(contents.as_str());
    assert!(
        !tail.contains("Taproot contract txid already in use"),
        "the per-contract seen-check has nothing to see while swap 1 is unconfirmed"
    );
    assert!(
        !tail.contains("Broadcast Taproot contract tx"),
        "the maker must not fund anything while both swaps wait"
    );

    // Mining resumes: swap 1's handler wakes and funds exactly one hop.
    world.framework().set_block_gen_paused(false);
    wait_for_log_after(
        &log_path,
        log_offset,
        "Broadcast Taproot contract tx",
        1,
        Duration::from_secs(240),
    );
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert_eq!(
        contents
            .get(log_offset as usize..)
            .unwrap_or(contents.as_str())
            .matches("Broadcast Taproot contract tx")
            .count(),
        1,
        "the maker must fund exactly one hop across both swaps"
    );

    let _ = swap1.join().expect("swap 1 thread panicked");

    world.shutdown_makers();
    drop(taker2);
}

/// The genuinely concurrent Legacy arm: swap 1's handler parks in the proof's
/// confirmation wait holding the claim, so swap 2's replay is rejected at the
/// claim without ever waiting. Exactly one swap may be funded.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [ReplayLegacyProofOfFunding, ReplayLegacyProofOfFunding],
    setup = [
        fund_nth_taker_default(0, 4),
        fund_nth_taker_default(1, 4),
        fund_makers_default(),
        spawn_ready_makers_and_mine(),
    ],
)]
fn maker_rejects_concurrent_replayed_legacy_proof_of_funding(world: &mut World) {
    let (taker1, taker2, maker_address, log_path, log_offset) = concurrent_replay_setup(world);

    let params = |address: &str| {
        SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_preferred_makers(vec![address.to_string()])
    };

    let run_swap = |mut taker: TakerHandle, address: String| {
        thread::spawn(move || {
            let summary = taker
                .prepare(params(&address))
                .expect("prepare must succeed");
            taker.start(&summary.swap_id)
        })
    };
    let swap1 = run_swap(taker1, maker_address.clone());

    // Barrier: swap 1's handler is inside the confirmation wait.
    wait_for_log_after(
        &log_path,
        log_offset,
        "confirmation(s) on tx",
        1,
        Duration::from_secs(120),
    );

    let swap2 = run_swap(taker2, maker_address.clone());

    // The claim sits before the confirmation wait: swap 2's replay is
    // rejected while swap 1 is still parked — no block is needed for it.
    wait_for_log_after(
        &log_path,
        log_offset,
        "already in use",
        1,
        Duration::from_secs(120),
    );

    world.framework().set_block_gen_paused(false);

    // Swap 1's wait observes the confirmation and funds exactly one hop.
    wait_for_log_after(
        &log_path,
        log_offset,
        "outgoing swapcoins, requesting signatures",
        1,
        Duration::from_secs(180),
    );
    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = contents
        .get(log_offset as usize..)
        .unwrap_or(contents.as_str());
    assert_eq!(
        tail.matches("outgoing swapcoins, requesting signatures")
            .count(),
        1,
        "the maker must fund exactly one hop across both swaps"
    );

    let swap1_result = swap1.join().expect("swap 1 thread panicked");
    let swap2_result = swap2.join().expect("swap 2 thread panicked");
    assert!(
        swap1_result.is_err() && swap2_result.is_err(),
        "neither swap may complete: the loser is rejected, the winner's counterpart is gone"
    );
}

/// After a partial broadcast, the taker re-admits the same swap; the maker
/// must re-process its own contracts via the same-swap exemption in
/// `contract_txid_seen` instead of rejecting them as a replay.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailSecondBroadcast],
    takers = [ResumeAfterMakerDrop],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn maker_reprocesses_own_contracts_after_partial_broadcast(world: &mut World) {
    let preferred = vec![world.makers()[0].address()];
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(2)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail: the resumed pass cannot re-fund the frozen plan"
    );

    let log_path = world.taker_log_path();
    assert_logged!(world, "Test behavior: maker 0 dropped mid-exchange");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("already in use"),
        "the maker's own persisted contracts must not read as a replay"
    );
    // Two passes over the same contract data: the resume re-entered contract
    // processing and crossed the replay check (the fee log sits behind it).
    assert_eq!(
        contents
            .matches(&format!(
                "Processing Taproot contract data for swap {swap_id}"
            ))
            .count(),
        2,
        "the resumed pass must re-enter contract processing"
    );
    assert_eq!(
        contents.matches("Fee calculation: incoming_total").count(),
        2,
        "the resumed pass must cross the same-swap replay check"
    );
    // Only the first pass's first tx made it on the wire; the resumed pass
    // funds nothing.
    assert_eq!(
        contents.matches("Broadcast Taproot contract tx").count(),
        1,
        "the resumed pass must not broadcast new funding"
    );
    assert!(
        !contents.contains("completed successfully"),
        "the swap must not complete"
    );
}

/// A maker restarted mid-swap must refuse a SwapDetails whose id belongs
/// to the unfinished swap its wallet still holds — re-admission would
/// double-fund it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SkipFundingBroadcast],
    // CrashBeforeRecovery keeps the taker's negotiated state after the failed
    // swap, so the test can resend the same SwapDetails afterwards.
    takers = [CrashBeforeRecovery],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn maker_refuses_unfinished_swap_id_after_restart(world: &mut World) {
    let preferred = vec![world.makers()[0].address()];
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();

    // The maker persists both sides' swapcoins, then dies before funding: the
    // swap stays unfinished in its wallet.
    let swap_result = world.taker_mut().start(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail when the maker skips its funding broadcast"
    );
    assert!(
        world.makers()[0]
            .inner()
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            > 0,
        "the maker must hold unfinished swapcoins before the restart"
    );

    // Hold the timelocks still so the restarted maker's recovery cannot
    // resolve the swapcoins before the resend lands.
    world.framework().set_block_gen_paused(true);

    // Restart the maker the way the reboot tests do: the first init consumed
    // the passphrase, so re-supply it.
    let mut victim_config = world.makers()[0].inner().config.clone();
    victim_config.password = Some("integration-test".to_string());
    world.shutdown_makers();
    world.drop_makers();

    let restarted = Arc::new(MakerServer::init(victim_config).unwrap());
    let restarted_thread = {
        let maker = restarted.clone();
        thread::spawn(move || start_server(maker).unwrap())
    };
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    // The taker reconnects with the same swap id. Admission must refuse it:
    // the id belongs to the unfinished swap on disk.
    let response = world
        .taker()
        .inner()
        .test_resend_swap_details(0)
        .expect("the resend itself must get an answer");
    match response {
        openswap::protocol::common_messages::MakerToTakerMessage::AckSwapDetails(ack) => {
            assert!(
                ack.tweakable_point.is_none(),
                "the restarted maker must reject the unfinished swap's id"
            );
        }
        other => panic!("expected AckSwapDetails, got {:?}", other),
    }

    assert_logged!(world, "Swap id belongs to an unfinished swap");

    world.framework().set_block_gen_paused(false);

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();
}

/// A maker that funds at the relay floor against a negotiated 3 sat/vB swap:
/// the taker's real-fee check bans the maker for the proven shortfall, and the
/// swap still completes, since by then the fee is paid and every hop has funded.
#[world_test(
    maker_behaviors = [UnderpayFundingFee],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    cases = [
        test_taproot_bans_funding_fee_underpayment(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        test_legacy_bans_funding_fee_underpayment(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Legacy,
        ),
        /// Same underpayment on Electrum: the real-fee check reads the funding
        /// inputs' prev txs from the indexer.
        test_taproot_bans_funding_fee_underpayment_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        test_legacy_bans_funding_fee_underpayment_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
        ),
    ],
)]
fn run_bans_funding_fee_underpayment(world: &mut World, protocol: ProtocolVersion) {
    // The hook only bites above the floor: at the 1 sat/vB default the floor
    // and the negotiated rate coincide, so negotiate a custom rate.
    world
        .taker_mut()
        .swap(SwapParams::new(protocol, Amount::from_sat(500_000), 1).with_feerate(3))
        .expect("a fee shortfall must not abort a funded route");

    // The shortfall is arithmetically proven, so the maker's standing steps
    // off Good.
    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "a proven fee shortfall must ban the maker"
    );
}

/// The step every keepalive test shares once its maker is up: one admitted
/// swap that is not started yet. Returns its id and the log path.
fn keepalive_admission(world: &mut World, pause_mining: bool) -> (String, String) {
    let log_path = world.taker_log_path();
    let maker_addr = world.makers()[0].address();

    // Hold the tip still when the test needs contract txs mempool-visible.
    if pause_mining {
        world.framework().set_block_gen_paused(true);
    }

    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect("the maker must admit the swap");

    (summary.swap_id.clone(), log_path)
}

/// A keepalive naming funding the backend can see still refreshes: with
/// mining paused, the taker's contract txs sit mempool-visible, the maker
/// claims their txids, and the route heartbeat's keepalives pass the
/// evidence gate. Mining resumes and the swap completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [SkipFundingConfirmWait],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn keepalive_with_mempool_funding_still_refreshes(world: &mut World) {
    let (swap_id, log_path) = keepalive_admission(world, true);

    // The swap runs on its own thread, so the taker leaves the world here.
    let mut taker = world.take_taker();
    let swap_thread = thread::spawn(move || taker.start(&swap_id));

    // The maker claimed the taker's contract txids and is waiting for a
    // confirmation the paused miner will not give.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(90));

    // A keepalive sent after the claim passes the evidence gate: the funding
    // is mempool-visible, so the idle timer is refreshed.
    wait_for_new_log(&log_path, "Resetting timer", Duration::from_secs(60));

    // Wait past the 30s idle timeout: the swap must still be held.
    thread::sleep(Duration::from_secs(25));
    assert!(
        world.makers()[0].inner().has_ongoing_swaps().unwrap(),
        "a swap with mempool-visible funding must survive the idle timeout"
    );

    world.framework().set_block_gen_paused(false);
    swap_thread
        .join()
        .unwrap()
        .expect("the swap must complete once mining resumes");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("names funding the backend cannot see"),
        "no keepalive may be refused while the funding is mempool-visible"
    );
    assert!(
        !contents.contains("Released idle unfunded swap"),
        "a swap with mempool-visible funding must never be drained"
    );
}

/// A keepalive naming funding the backend cannot see must not refresh:
/// every post-claim keepalive is refused and the unfunded swap is drained
/// once idle.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [WithholdFundingBroadcast],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn keepalive_naming_unseen_funding_is_refused(world: &mut World) {
    let (swap_id, log_path) = keepalive_admission(world, true);

    // The swap runs on its own thread, so the taker leaves the world here.
    let mut taker = world.take_taker();
    let swap_thread = thread::spawn(move || taker.start(&swap_id));

    // The maker claimed the withheld txids and waits for a tx that will never
    // arrive. Everything logged after this point is post-claim.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(90));
    let claim_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // The heartbeat's keepalives hit the evidence gate and are refused.
    wait_for_log_after(
        &log_path,
        claim_offset,
        "names funding the backend cannot see",
        1,
        Duration::from_secs(90),
    );

    // The taker's own read deadline ends the swap; recovery discards the
    // never-broadcast contracts without putting them on-chain.
    swap_thread
        .join()
        .unwrap()
        .expect_err("the swap must fail: the maker never answers withheld funding");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let post_claim = contents
        .get(claim_offset as usize..)
        .unwrap_or(contents.as_str());
    assert!(
        post_claim.contains("names funding the backend cannot see"),
        "a post-claim keepalive must be refused"
    );
    assert!(
        !post_claim.contains("Resetting timer"),
        "a refused keepalive must not refresh the idle timer"
    );

    // With every keepalive refused, the swap goes idle and is drained: the
    // withheld funding is not on-chain evidence.
    wait_for_log(
        &log_path,
        "Released idle unfunded swap",
        Duration::from_secs(400),
    );
    assert!(
        !world.makers()[0].inner().has_ongoing_swaps().unwrap(),
        "the maker must hold no swap after the idle drain"
    );

    world.framework().set_block_gen_paused(false);
}

/// A taker that returns after the maker drained its idle admission is
/// admitted again by the re-check before funding, and the swap completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn slow_taker_is_readmitted_before_funding(world: &mut World) {
    let (swap_id, log_path) = keepalive_admission(world, false);

    wait_for_log(
        &log_path,
        "Released idle unfunded swap",
        Duration::from_secs(400),
    );
    world
        .taker_mut()
        .start(&swap_id)
        .expect("the re-check must re-admit the drained swap");
}

/// A Legacy maker hands its funding txs to the taker before it holds the
/// signatures for its refund. They go out unsigned, so a taker that tries to
/// broadcast them is refused and cannot strand the maker's coins.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [BroadcastHandedOutFunding],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Legacy, sats = 500_000, makers = 1, tx_count = 2),
)]
fn legacy_handed_out_funding_cannot_be_broadcast(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap_fails(params, "a taker broadcasting handed-out funding must fail");

    assert_logged!(world, "handed-out funding tx");
    let contents = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert!(
        !contents
            .lines()
            .any(|line| line.contains("handed-out funding tx") && line.ends_with("accepted")),
        "a handed-out funding tx must not be broadcastable"
    );
}

/// A maker that re-admits a drained swap with a different plan shape fails
/// the taker's re-check, before the taker funds anything.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
)]
fn readmission_with_a_new_shape_fails_before_funding(world: &mut World) {
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(2)
                .with_required_confirms(1),
        )
        .expect("the maker must admit the swap");
    assert_logged!(world, "with 2 funding split(s)");

    // Leave the maker one coin, so a fresh plan can have only one split.
    let maker = world.makers()[0].inner();
    let spendable = maker
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .spendable;
    let external = world
        .bitcoind()
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    maker
        .wallet
        .write()
        .unwrap()
        .send_to_address(
            spendable.to_sat() - 700_000,
            external.to_string(),
            Some(MIN_RELAY_FEE_RATE),
            None,
        )
        .unwrap();
    world.mine(1);
    world.sync_makers();

    wait_logged!(
        world,
        "Released idle unfunded swap",
        Duration::from_secs(400)
    );
    let before = world.taker().balances();
    let error = world
        .taker_mut()
        .start(&summary.swap_id)
        .expect_err("a changed plan shape must stop the swap");
    assert!(
        format!("{error:?}").contains("no longer holds this swap's plan"),
        "unexpected error: {:?}",
        error
    );
    let after = world.taker().balances();
    assert_eq!(
        after.spendable, before.spendable,
        "the taker funded nothing"
    );
    assert_eq!(after.contract, Amount::ZERO);
}

/// A failed sweep puts the completed swap's state back after it was removed.
/// That store must pass the stale-plan guard, or the maker loses the state.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FailSweep],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Taproot, sats = 500_000, makers = 1, tx_count = 1),
)]
fn completed_swap_state_is_restored_after_a_failed_sweep(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap(params)
        .expect("the taker's side completes before the maker sweeps");

    wait_logged!(
        world,
        "Failed to sweep incoming swapcoins",
        Duration::from_secs(60)
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !world.makers()[0].inner().has_ongoing_swaps().unwrap() {
        assert!(
            Instant::now() < deadline,
            "the completed swap's state must be put back"
        );
        thread::sleep(Duration::from_millis(500));
    }
    let contents = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert!(
        !contents.contains("Rejecting late message"),
        "restoring a completed swap is not a late message"
    );
}

/// The concurrency cap rejects before any admission planning runs: the
/// 31st admission is refused at the cap, and the absence of a planner
/// "cannot fund" log proves the order.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(1),
        // 31 UTXOs: the fidelity bond consumes one net (two inputs, one change
        // back), leaving exactly 30 — one per admission's single-input plan.
        fund_makers(31, Amount::from_btc(0.05).unwrap(), AddressType::P2TR),
        spawn_ready_makers_and_mine(),
    ],
)]
fn swap_cap_rejects_before_planning(world: &mut World) {
    let maker_addr = world.makers()[0].address();

    let _summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_max_input_budget(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr.clone()]),
        )
        .expect("the first admission must succeed");
    let template = world
        .taker()
        .inner()
        .test_current_swap_details(0)
        .expect("the negotiated SwapDetails rebuild");

    // Admissions 2..=30: the negotiated terms under fresh ids.
    for n in 1..30u64 {
        let mut details = template.clone();
        details.id = format!("{:016x}", n);
        match world
            .taker()
            .inner()
            .test_send_swap_details(&maker_addr, &details)
            .expect("every admission must get an answer")
        {
            openswap::protocol::common_messages::MakerToTakerMessage::AckSwapDetails(ack) => {
                assert!(
                    ack.tweakable_point.is_some(),
                    "admission {} must be accepted below the cap",
                    n + 1
                );
            }
            other => panic!("admission {} got unexpected response: {:?}", n + 1, other),
        }
    }

    // The 31st swap is refused at the cap.
    let mut details = template.clone();
    details.id = format!("{:016x}", 30u64);
    match world
        .taker()
        .inner()
        .test_send_swap_details(&maker_addr, &details)
        .expect("the capped admission must still get an answer")
    {
        openswap::protocol::common_messages::MakerToTakerMessage::AckSwapDetails(ack) => {
            assert!(
                ack.tweakable_point.is_none(),
                "the 31st admission must be rejected at the cap"
            );
        }
        other => panic!("the capped admission got unexpected response: {:?}", other),
    }

    let log_path = world.taker_log_path();
    assert_logged!(world, "30 active swaps at the 30 cap");
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("Rejecting swap at admission"),
        "the cap must fire before the planner runs"
    );
}

/// An offer whose minimum exceeds its maximum cannot price any amount. That is
/// also what a maker low on liquidity publishes, so it must sideline the maker
/// without banning it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SendMalformedOffer, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 1),
)]
fn an_unpriceable_offer_sidelines_without_banning(world: &mut World, params: SwapParams) {
    // One hop, so the honest maker alone can carry the route while the
    // malformed offer is judged during the same offerbook sync.
    let _ = world.taker_mut().prepare(params);

    let publisher = world.maker_standing(0);
    assert!(
        matches!(
            publisher,
            MakerState::Unavailable(UnavailableState {
                reason: UnavailableReason::UnpriceableOffer,
                ..
            })
        ),
        "an unpriceable offer must sideline its publisher, not ban it, got {:?}",
        publisher
    );

    assert_eq!(
        world.maker_ban_reason(1),
        None,
        "the honest maker must not be blamed"
    );

    info!("Unpriceable offer test completed successfully!");
}

/// Signatures made with a key nobody agreed to are well formed and still
/// wrong. Only the maker that produced them is banned.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SignSenderContractsWithWrongKey, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2),
)]
fn wrong_key_sender_signatures_ban_their_signer(world: &mut World, params: SwapParams) {
    // Both makers are on the route, so there is no spare to substitute and the
    // failure lands on the signer wherever it sits in the order.
    world
        .taker_mut()
        .swap_fails(params, "a swap signed with the wrong key must fail");

    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "the wrong-key signer must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(1),
        None,
        "the honest maker must not be blamed"
    );

    // Naming the banned maker by address must not get it back into a route:
    // the only candidate is refused, so no route can be built at all.
    let banned_address = world.makers()[0].address();
    let refusal = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 1)
                .with_tx_count(2)
                .with_required_confirms(1)
                .with_preferred_makers(vec![banned_address.clone()]),
        )
        .expect_err("a banned maker must not be usable by address");
    assert!(
        format!("{refusal:?}").contains("preferred makers"),
        "unexpected refusal for a banned preferred maker: {:?}",
        refusal
    );

    // A ban must outlive its bond. Expire both bonds so each maker redeems its
    // old one and posts a new one for the same address.
    let latest_bond = |maker: &MakerServer| {
        let wallet = maker.wallet.read().unwrap();
        wallet.get_fidelity_bonds().last().unwrap().clone()
    };
    let old_bonds: Vec<_> = world
        .makers()
        .iter()
        .map(|m| latest_bond(m.inner()))
        .collect();
    let expiry = old_bonds
        .iter()
        .map(|bond| bond.lock_time.to_consensus_u32())
        .max()
        .unwrap();
    let height = world.bitcoind().client.get_block_count().unwrap() as u32;
    let mut remaining = expiry.saturating_sub(height) + 10;
    while remaining > 0 {
        let batch = remaining.min(100);
        world.mine(batch as u64);
        remaining -= batch;
    }

    let renewal_start = Instant::now();
    while world
        .makers()
        .iter()
        .zip(&old_bonds)
        .any(|(maker, old)| latest_bond(maker.inner()).outpoint() == old.outpoint())
    {
        assert!(
            renewal_start.elapsed() < Duration::from_secs(180),
            "both makers must renew their expired bonds"
        );
        thread::sleep(Duration::from_secs(5));
    }

    // Only the taker runs discovery, so this line is its registry taking the
    // banned maker's new bond.
    let rebond_txid = latest_bond(world.makers()[0].inner())
        .outpoint()
        .txid
        .to_string();
    let log_path = world.temp_dir().join("taker/debug.log");
    let discovery_start = Instant::now();
    while !fs::read_to_string(&log_path).unwrap().lines().any(|line| {
        line.contains("Stored validated fidelity candidate") && line.contains(&rebond_txid)
    }) {
        assert!(
            discovery_start.elapsed() < Duration::from_secs(180),
            "the taker must discover the banned maker's new bond"
        );
        thread::sleep(Duration::from_secs(5));
    }

    // The sync now meets the expired bond and the new one for the same
    // address. Neither may lift the ban.
    world.taker().inner().sync_offerbook_and_wait().unwrap();
    let rebonded = world
        .taker()
        .inner()
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|m| m.address.to_string() == banned_address)
        .expect("the banned maker must still be in the offerbook");
    assert!(
        matches!(
            rebonded.state,
            MakerState::Banned(BanRecord {
                reason: BanReason::ProvenViolation,
                ..
            })
        ),
        "a new bond must not lift the ban, got {:?}",
        rebonded.state
    );
    assert_eq!(
        rebonded.fidelity_outpoint,
        Some(old_bonds[0].outpoint()),
        "the banned record must keep its old bond"
    );

    info!("Wrong-key signature test completed successfully!");
}

/// A hashlock built for a key nobody agreed to would pay the next hop to the
/// wrong key. Only the maker that built it is banned.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [WrongHashlockKey, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2),
)]
fn wrong_hashlock_key_bans_its_builder(world: &mut World, params: SwapParams) {
    // The builder is the first hop, so its hashlock must derive from the next
    // maker's key and the taker's nonce.
    let swap_error = world
        .taker_mut()
        .swap_fails(params, "a swap with a wrong-key hashlock must fail");
    assert!(
        format!("{:?}", swap_error).contains("hashlock pubkey verification failed"),
        "the hashlock check must be what stops the swap, got {:?}",
        swap_error
    );

    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "the wrong-hashlock builder must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(1),
        None,
        "the honest maker must not be blamed"
    );

    info!("Wrong hashlock key test completed successfully!");
}

/// The last maker takes the keys it was owed and hands back one that does not
/// match. It is banned, and the taker still claims its coins by hashlock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, SendWrongHandoverKey],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2),
)]
fn wrong_handover_key_bans_the_last_maker(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap_fails(params, "a swap with a wrong handover key must fail");

    assert_eq!(
        world.maker_ban_reason(1),
        Some(BanReason::ProvenViolation),
        "the maker handing over a wrong key must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(0),
        None,
        "the honest maker must not be blamed"
    );

    // The taker holds the preimage, so the background recovery claims the
    // last maker's contract by hashlock without waiting on any timelock.
    let recovery_start = Instant::now();
    while !world.taker().inner().is_recovery_complete() {
        assert!(
            recovery_start.elapsed() < Duration::from_secs(300),
            "background recovery did not complete within timeout"
        );
        thread::sleep(Duration::from_secs(5));
    }
    world.mine(1);
    world.taker().sync();
    let balances = world.taker().balances();
    info!(
        "Taker balances after recovery: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        balances.regular, balances.swap, balances.contract, balances.spendable,
    );
    assert_eq!(balances.regular.to_sat(), 14499692, "Taker regular balance");
    assert_eq!(balances.swap.to_sat(), 497369, "Taker swap balance");
    assert_eq!(balances.contract, Amount::ZERO, "Taker contract balance");

    info!("Wrong handover key test completed successfully!");
}

/// A legacy maker whose planned coin is taken re-plans onto two smaller coins
/// for a split it declared with one. The taker priced that split at one input,
/// so a split funded with more must still be accepted and the swap completes.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [ForceReplan, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        // The bond takes its exact coin. The 600k coin funds the split alone;
        // once it is taken, the split needs two 300k coins.
        fund_makers(1, Amount::from_sat(5_000_243), AddressType::P2TR),
        fund_makers(1, Amount::from_sat(600_000), AddressType::P2TR),
        fund_makers(3, Amount::from_sat(300_000), AddressType::P2TR),
        spawn_ready_makers_and_mine(),
    ],
)]
fn legacy_replan_with_extra_inputs_completes(world: &mut World) {
    let summary = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
                .with_tx_count(1)
                .with_required_confirms(1),
        )
        .expect("prepare swap");
    let swap_id = summary.swap_id.clone();
    world
        .taker_mut()
        .start(&swap_id)
        .expect("a split with extra inputs must be accepted");

    let log = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert!(log.contains(&format!("Re-planned funding for swap {swap_id}")));
    // Inputs per maker funding tx; the normal maker funds from its 600k coin.
    let inputs: Vec<usize> = log
        .lines()
        .filter_map(|line| line.split("Broadcast Legacy funding tx: ").nth(1))
        .map(|txid| {
            let txid = txid.trim().parse().unwrap();
            world
                .bitcoind()
                .client
                .get_raw_transaction(&txid, None)
                .unwrap()
                .input
                .len()
        })
        .collect();
    assert_eq!(
        inputs.iter().filter(|&&n| n == 2).count(),
        1,
        "only the re-planned split spends two coins against one declared: {inputs:?}"
    );
}
