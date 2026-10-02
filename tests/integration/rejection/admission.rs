//! Admission: what the maker refuses, or plans differently, before it reserves
//! anything. Out-of-bounds, forged or over-cap `SwapDetails`, liquidity it does
//! not have, parameters the taker refuses at prepare time, and split counts it
//! must degrade.

use bitcoin::{
    secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey},
    Address, Amount, Network,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::MakerServer,
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    utill::{MAX_TX_COUNT, MIN_RELAY_FEE_RATE},
    wallet::{min_contract_value_sats, AddressType, Destination},
};

use crate::test_framework::*;

use super::wait_for_log_after;

use log::info;
use std::time::Duration;

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
fn maker_rejects_out_of_bounds_swap_details(
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
fn low_swap_liquidity(world: &mut World, params: SwapParams) {
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
fn admission_reserves_no_liquidity(world: &mut World) {
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
