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
        MakerState, SwapParams, TakerBehavior,
    },
    utill::{MAX_TX_COUNT, MIN_RELAY_FEE_RATE, NO_SHUTDOWN},
    wallet::{AddressType, Destination},
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

#[test]
fn test_maker_rejects_out_of_bounds_swap_details() {
    warn!("Running Test: Maker Rejection of SwapDetails + CloseEarly");

    let makers_config_map = vec![(9202, Some(21501)), (19202, Some(21502))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // 4 UTXOs, not the usual 3: the above-maximum cases need the taker to hold
    // more than the maker is willing to swap.
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    info!("Starting Maker servers...");
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);
    generate_blocks(bitcoind, 1);

    // The maker advertises min = its `min_swap_amount`, max = its spendable
    // liquidity, so derive both bounds instead of hardcoding them.
    let maker_offer_max = makers[0]
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .regular;
    let below_min = Amount::from_sat(5_000);
    let above_max = maker_offer_max + Amount::from_sat(100_000);
    info!(
        "Maker offer max: {}, testing below_min={} and above_max={}",
        maker_offer_max, below_min, above_max
    );

    let preferred: Vec<String> = makers
        .iter()
        .map(|m| format!("127.0.0.1:{}", m.config.network_port))
        .collect();

    // ---- 1. Below minimum, taker-side offerbook filter ----
    let err = taker
        .prepare_swap(
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
    let err = taker
        .prepare_swap(
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

    // ---- 3. Below minimum, past the filter, caught at negotiation ----
    let err = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, below_min, 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred.clone()),
        )
        .expect_err("negotiation must refuse an amount under the maker's minimum");
    let msg = format!("{:?}", err);
    assert!(
        msg.contains(&format!(
            "Send amount ({} sats) is below maker 0 min_size",
            below_min.to_sat()
        )),
        "Expected the negotiation min_size guard, got: {}",
        msg
    );
    info!("Negotiation refused below-minimum request: {}", msg);

    // ---- 4. Above maximum, past the filter, caught at negotiation ----
    let err = taker
        .prepare_swap(
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
    taker.behavior = TakerBehavior::CloseEarly;
    let err = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
                .with_tx_count(1)
                .with_required_confirms(1),
        )
        .expect_err("CloseEarly must abort prepare_swap");
    info!("Taker closed early after maker selection: {:?}", err);
    taker.behavior = TakerBehavior::Normal;

    // ---- 6. Forged below-minimum reaches the maker's own guard ----
    // The nominal 500_000 passes both taker-side layers; the hook rewrites
    // the amount only on the wire, so the maker guard is what must refuse.
    taker.behavior = TakerBehavior::ForgeBounds(below_min);
    let err = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred.clone()),
        )
        .expect_err("the maker's own guard must refuse a forged below-minimum amount");
    info!("Maker guard refused forged below-minimum: {:?}", err);

    // ---- 7. Forged above-maximum reaches the maker's own guard ----
    taker.behavior = TakerBehavior::ForgeBounds(above_max);
    let err = taker
        .prepare_swap(
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
    taker.behavior = TakerBehavior::ResendMutatedDetails;
    let err = taker
        .prepare_swap(
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
    taker.behavior = TakerBehavior::Normal;

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("closing early after maker selection", &log_path);
    // The forged amounts got past both taker-side layers, so the refusal must
    // come from the maker's own guard, logged as a handler error on drop.
    test_framework.assert_log("Swap amount below minimum", &log_path);
    test_framework.assert_log("Swap amount above maximum", &log_path);
    // The mutated resend dies on the whole-agreement compare: one value, so
    // no single field — feerate included — can drift between connections.
    test_framework.assert_log("parameters differ from stored swap", &log_path);

    // Nothing was funded, so nothing may have moved.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
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

    for (i, (maker, original)) in makers.iter().zip(maker_spendable_balance).enumerate() {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
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

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_low_swap_liquidity() {
    // ---- Setup ----
    warn!("Running Test: Low Swap Liquidity check");

    // Create a maker with normal behaviour
    let makers_config_map = vec![(8402, None)];
    let taker_behavior = vec![TakerBehavior::Normal];

    // Initialize test framework
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let maker = &makers[0];

    info!("Funding taker and maker");
    // Fund the taker with 3 UTXOs of 0.05 BTC each (Taproot)
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund the Maker with 4 UTXOs of 0.05 BTC each (Taproot)
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Start the Maker Server thread
    info!("Initiating Maker server...");
    let maker_thread = {
        let maker_clone = maker.clone();
        std::thread::spawn(move || {
            start_server(maker_clone).unwrap();
        })
    };

    // Wait for maker to complete setup (including fidelity bond creation)
    wait_for_makers_setup(std::slice::from_ref(maker), 120);

    // Drain the Maker wallet after fidelity bond is created
    drain_maker_liquidity_after_fidelity(maker, bitcoind);
    // Mine a block to confirm the drain, then sync maker wallet
    generate_blocks(bitcoind, 1);
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    info!("Maker should be halted due to low swap liquidity");

    info!("Initiating openswap (Will fail due to maker not accepting any offer due to low swap liquidity)");

    // Swap params
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);

    // Attempt the swap - it will fail because maker has no liquidity
    let err = taker
        .prepare_swap(swap_params.clone())
        .expect_err("Swap should have failed due to insufficient maker liquidity");
    info!("OpenSwap failed as expected: {err:?}");

    info!("Adding sufficient funds to maker to perform a swap and avoid low swap liquidity");
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // The offerbook still holds the drained max_size=0 offer fetched moments
    // ago, and a sync round would skip re-polling it while it is within
    // OFFER_MAX_AGE_BEFORE_REFRESH, which is 10s for tests. Poll this maker directly so selection sees
    // the re-funded liquidity.
    taker
        .poll_maker(format!("127.0.0.1:{}", maker.config.network_port))
        .expect("re-poll of the re-funded maker should succeed");

    // Attempt the swap again, it should succeed
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("prepare_swap should succeed after funding");

    match taker.start_swap(&summary.swap_id) {
        Ok(_report) => {
            log::info!("OpenSwap completed successfully after re-funding!");
        }
        Err(e) => {
            log::error!("OpenSwap failed: {:?}", e);
            panic!("OpenSwap failed: {:?}", e);
        }
    }

    maker.shutdown.store(true, Relaxed);
    maker_thread.join().unwrap();
    test_framework.stop();
    block_generation_handle.join().unwrap();

    info!("Low Swap liquidity test passed");
}

fn drain_maker_liquidity_after_fidelity(maker: &Arc<MakerServer>, bitcoind: &bitcoind::BitcoinD) {
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

#[test]
fn makers_reject_duplicate_funding_outpoints() {
    let makers_config_map = vec![(8802, Some(21301)), (18802, Some(21302))];
    let taker_behaviors = vec![TakerBehavior::DuplicateFundingOutpoint];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behaviors, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    for taker in &mut takers {
        fund_taker(
            taker,
            bitcoind,
            3,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    // The Taproot behavior repeats one contract transaction together with all
    // aligned per-contract vectors, so length and script checks still pass.
    let taproot_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    let taproot_summary = takers[0]
        .prepare_swap(taproot_params)
        .expect("Taproot prepare_swap should succeed");
    assert!(
        takers[0].start_swap(&taproot_summary.swap_id).is_err(),
        "Taproot maker must reject a duplicated contract outpoint"
    );

    // Assert both the taker side duplicate contract passing and the maker-side rejection.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(
        "Test behavior: duplicating Taproot contract outpoint",
        &log_path,
    );
    test_framework.assert_log("Duplicate Taproot contract outpoint", &log_path);

    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("Broadcast Taproot contract tx"),
        "Taproot maker must reject before broadcasting outgoing funding"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The maker guards a Legacy funding proof in order — entry count, declared
/// sum, then outpoint duplication — so each malice keeps the earlier guards
/// satisfied to reach its own. Count and sum are exact since C2, so the
/// duplication case runs at tx_count 2, where the honest splits are equal and
/// replacing one keeps the declared sum intact. One maker is enough: the
/// rejection is the point.
fn run_legacy_proof_guard(
    port: u16,
    rpc: u16,
    behavior: TakerBehavior,
    tx_count: u32,
    expected: &str,
) {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(port, Some(rpc))],
            vec![behavior],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
        .with_tx_count(tx_count)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    assert!(
        taker.start_swap(&summary.swap_id).is_err(),
        "maker must reject the crafted ProofOfFunding"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(expected, &log_path);

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn maker_rejects_overcounted_proof_of_funding() {
    run_legacy_proof_guard(
        8808,
        21310,
        TakerBehavior::ExtraFundingTxEntry,
        3,
        "declared incoming count",
    );
}

#[test]
fn maker_rejects_overstated_proof_of_funding() {
    run_legacy_proof_guard(
        8810,
        21311,
        TakerBehavior::OverstatedFundingAmount,
        3,
        "declared swap amount",
    );
}

#[test]
fn maker_rejects_duplicated_funding_outpoint() {
    run_legacy_proof_guard(
        8812,
        21312,
        TakerBehavior::DuplicateFundingOutpoint,
        2,
        "Duplicate funding outpoint",
    );
}

/// The taker declares 600k in SwapDetails but funds the honest 500k. The
/// maker priced and froze its plan on the declared amount, so the equality
/// check — not a band — refuses the proof.
#[test]
fn maker_rejects_underdelivered_legacy_amount() {
    run_legacy_proof_guard(
        9704,
        21701,
        TakerBehavior::ForgeBounds(Amount::from_sat(600_000)),
        3,
        "declared swap amount",
    );
}

/// Same under-delivery on Taproot: the declared amount is exact there too.
#[test]
fn maker_rejects_underdelivered_taproot_amount() {
    run_taproot_declaration_guard(
        9706,
        21702,
        TakerBehavior::ForgeBounds(Amount::from_sat(600_000)),
        "does not match negotiated swap amount",
    );
}

/// The taker declares 2 incoming contracts but funds 3. The maker priced its
/// sweep reimbursement on the declared count, so the equality check refuses.
#[test]
fn maker_rejects_wrong_taproot_incoming_count() {
    run_taproot_declaration_guard(
        9708,
        21703,
        TakerBehavior::ForgeIncomingCount(2),
        "!= declared incoming count",
    );
}

/// The taker funds honestly; the hook forges only the SwapDetails
/// declaration, so the maker's own equality check is what refuses.
fn run_taproot_declaration_guard(port: u16, rpc: u16, behavior: TakerBehavior, expected: &str) {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(port, Some(rpc))],
            vec![behavior],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
        .with_tx_count(3)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    assert!(
        taker.start_swap(&summary.swap_id).is_err(),
        "maker must reject contract data that breaks the declaration"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(expected, &log_path);

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A taker holding a single UTXO cannot fund 2 splits, so negotiation plans
/// hop 0 as one split and declares 1. The maker's "with 1 funding txs" log
/// proves the declared count flowed through, and the swap still completes.
#[test]
fn one_utxo_taker_completes_degraded_swap() {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9710, Some(21704))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    // One UTXO, so the hop-0 plan must degrade below the requested tx_count.
    fund_taker(
        taker,
        bitcoind,
        1,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(params)
        .expect("prepare_swap should succeed");
    taker
        .start_swap(&summary.swap_id)
        .expect("a degraded one-split swap must complete");

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("with 1 funding txs", &log_path);

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A confirmed funding txid proves nothing about its outputs. Here the taker claims
/// its own funding output through the contract path first, then still names that
/// outpoint in ProofOfFunding. The maker must refuse before funding the next hop.
fn run_rejects_spent_funding_outpoint<B: TestBackend>(behavior: TakerBehavior) {
    let makers_config_map = vec![(8804, Some(21303)), (18804, Some(21304))];
    let taker_behaviors = vec![behavior];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behaviors, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    fund_taker(
        &takers[0],
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    let summary = takers[0]
        .prepare_swap(params)
        .expect("Legacy prepare_swap should succeed");
    assert!(
        takers[0].start_swap(&summary.swap_id).is_err(),
        "Legacy maker must reject an already spent funding outpoint"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(
        "Test behavior: spending the funding outpoint before ProofOfFunding",
        &log_path,
    );
    test_framework.assert_log("Funding output already spent", &log_path);

    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("SECURITY: Broadcasting"),
        "Maker must reject before broadcasting outgoing funding"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn maker_rejects_spent_funding_outpoint() {
    run_rejects_spent_funding_outpoint::<BitcoindBackend>(
        TakerBehavior::ReplaySpentFundingOutpoint,
    );
}

#[test]
fn maker_rejects_spent_funding_outpoint_mempool() {
    run_rejects_spent_funding_outpoint::<ElectrumBackend>(
        TakerBehavior::ReplaySpentFundingOutpointMempool,
    );
}

/// A funding tx the maker has already seen can still vanish from the mempool
/// (evicted or replaced). The maker must error out of its confirmation wait
/// once the re-armed broadcast window expires, not wait forever.
#[test]
fn maker_errors_when_seen_funding_tx_is_evicted() {
    let makers_config_map = vec![(8806, Some(21305)), (18806, Some(21306))];
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behaviors, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    // Sign a double-spend of every taker UTXO up front, so it can replace the
    // funding tx (which signals RBF) the moment the maker reports seeing it.
    let conflict_tx = {
        let mut wallet = taker.get_wallet().write().unwrap();
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

    // Zero required confirms sends the contract data while the funding tx is
    // still in the mempool, which is what puts the maker into its wait.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(1)
        .with_required_confirms(0);
    let summary = taker
        .prepare_swap(swap_params)
        .expect("prepare_swap should succeed");

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    // Mining is paused so the funding tx can never confirm; the maker stays in
    // its confirmation wait until the conflict evicts the tx from the mempool.
    test_framework.set_block_gen_paused(true);
    let swap_result = thread::scope(|s| {
        let swap_handle = s.spawn(|| taker.start_swap(&summary.swap_id));

        wait_for_new_log(&log_path, "seen in mempool", Duration::from_secs(120));
        // Sent through bitcoind, not the taker's wallet, whose lock the swap
        // thread holds for long stretches.
        bitcoind
            .client
            .send_raw_transaction(serialize_hex(&conflict_tx))
            .expect("conflict tx should replace the funding tx in the mempool");

        // One re-armed broadcast window must pass before the maker errors.
        wait_for_log(&log_path, "did not reappear", Duration::from_secs(240));
        test_framework.set_block_gen_paused(false);
        swap_handle.join().expect("taker thread panicked")
    });
    assert!(
        swap_result.is_err(),
        "The swap must fail once the maker's funding wait errors out"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn maker_rejects_proof_of_funding_with_missing_contract_cache() {
    let makers_config_map = vec![(6102, None), (16102, None)];
    let taker_behavior = vec![TakerBehavior::SkipSenderContractSigs];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_before = makers[0]
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .spendable;

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("prepare_swap should succeed");

    let result = taker.start_swap(&summary.swap_id);
    assert!(
        result.is_err(),
        "maker must reject ProofOfFunding without a cached contract binding"
    );

    // Assert both the adversarial action and the maker's fail-closed reason.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(
        "Test behavior: skipping sender contract signature request before funding",
        &log_path,
    );
    test_framework.assert_log("No cached sender contract for funding prevout", &log_path);

    // Rejection must happen before the maker reaches the outgoing broadcast
    // boundary in process_resp_contract_sigs_for_recvr_and_sender.
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("SECURITY: Broadcasting"),
        "maker must reject before broadcasting outgoing funding transactions"
    );

    makers[0]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();
    let maker_spendable_after = makers[0]
        .wallet
        .read()
        .unwrap()
        .get_balances()
        .unwrap()
        .spendable;
    assert_eq!(
        maker_spendable_after, maker_spendable_before,
        "rejected proof must not spend maker liquidity"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_taproot_maker_rejects_contract_amount_mismatch() {
    warn!("Running Test: Taproot maker rejects mismatched contract amount");
    let makers_config_map = vec![(7202, Some(19161)), (17202, Some(19162))];
    let taker_behavior = vec![TakerBehavior::InvalidTaprootContractAmount];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("Taproot swap preparation should succeed before contract validation");
    let swap_result = taker.start_swap(&summary.swap_id);
    assert!(
        swap_result.is_err(),
        "Taproot swap should fail when taker lies about contract amount"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("does not match output value", &log_path);

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_legacy_taker_rejects_malformed_maker_funding_output() {
    let makers_config_map = vec![(6102, Some(19051)), (16102, Some(19052))];
    let taker_behavior = vec![TakerBehavior::Normal];
    // First maker returns Legacy sender contract data whose contract input points
    // at a real funding tx output, but not the advertised 2-of-2 multisig output.
    let maker_behaviors = vec![
        MakerBehavior::MalformedLegacyFundingOutput,
        MakerBehavior::Normal,
    ];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)
            .unwrap();
    }

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("prepare_swap should succeed");

    // The taker must reject before signing/finalizing; otherwise it can later
    // report success while the incoming sweep is unspendable.
    let result = taker.start_swap(&summary.swap_id);
    assert!(
        result.is_err(),
        "taker must reject malformed maker sender contract data"
    );

    let error = format!("{:?}", result.unwrap_err());
    assert!(
        error.contains("funding output does not pay to advertised multisig"),
        "unexpected taker error: {}",
        error
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    // Pin the operator-visible rejection, not just the returned Rust error.
    test_framework.assert_log(
        "funding output does not pay to advertised multisig",
        &log_path,
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_legacy_taker_rejects_fee_skimming_maker() {
    let makers_config_map = vec![(6103, Some(19053))];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            makers_config_map,
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::FeeSkimming],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);
    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
                .with_tx_count(3)
                .with_required_confirms(1),
        )
        .expect("prepare Legacy swap");
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("reject fee skim");
    assert!(
        format!("{error:?}").contains("does not match expected"),
        "unexpected error: {:?}",
        error
    );
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_taproot_rejects_underfunded_maker_contract() {
    // ---- Setup ----
    let makers_config_map = vec![(7102, Some(19061))];
    let taker_behavior = vec![TakerBehavior::Normal];

    // The maker funds a 10k-sat Taproot output but advertises the normal
    // post-fee amount in TaprootContractData. This models a maker trying to
    // make the taker accept an incoming swapcoin for more than the tx pays.
    let maker_behaviors = vec![MakerBehavior::UnderfundTaprootContract];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    // Fund the taker and maker with P2TR coins so the swap runs through the
    // Taproot funding and contract-data exchange path.
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Start the malicious maker server.
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || start_server(maker_clone).unwrap())
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);

    // Mine one block before preparing the swap so wallet state and offer data
    // are settled.
    generate_blocks(bitcoind, 1);

    // A 30k-sat swap keeps the maker's 10k-sat underfunded output valid enough
    // to broadcast while still making the amount mismatch obvious.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(30_000), 1)
        .with_tx_count(3)
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(swap_params)
        .expect("failed to prepare Taproot openswap");

    // The taker must reject during maker contract verification, before storing
    // an incoming swapcoin from the underfunded contract data. The maker's
    // response amounts are read from its actual funding outputs, so the
    // underfunding is caught by the exact total-fee check.
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("taker must reject an underfunded maker contract");
    match error {
        TakerError::General(message) => {
            assert!(
                message.contains("does not match expected"),
                "unexpected taker error: {}",
                message
            );
        }
        other => panic!("unexpected taker error: {:?}", other),
    }

    // Assert the rejection came from the exact-amount check.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("does not match expected", &log_path);

    // ---- Cleanup ----
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_taproot_rejects_fee_skimming_maker() {
    test_taproot_rejection(
        7103,
        19062,
        MakerBehavior::FeeSkimming,
        "does not match expected",
    );
}

/// The maker funds honestly but claims one contract pays a sat more than its
/// real output (and another a sat less, keeping the total exact). Only the
/// taker's per-output amount binding can catch that.
#[test]
fn taker_rejects_inflated_taproot_contract_amount() {
    test_taproot_rejection(
        7104,
        19063,
        MakerBehavior::InflateContractAmount,
        "does not match output value",
    );
}

fn test_taproot_rejection(port: u16, rpc: u16, behavior: MakerBehavior, expected_error: &str) {
    let makers_config_map = vec![(port, Some(rpc))];
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            makers_config_map,
            vec![TakerBehavior::Normal],
            vec![behavior],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);
    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(30_000), 1)
                .with_tx_count(3)
                .with_required_confirms(1),
        )
        .expect("prepare Taproot swap");
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("the maker's Taproot response must be rejected");
    assert!(
        format!("{error:?}").contains(expected_error),
        "unexpected error: {:?}",
        error
    );

    // The lie is arithmetically proven, so the maker's standing steps off Good.
    let standing = taker
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|m| m.address.to_string() == format!("127.0.0.1:{}", makers[0].config.network_port))
        .expect("the maker must be in the offerbook");
    assert_eq!(
        standing.state,
        MakerState::Unresponsive { retries: 1 },
        "a proven contract violation must step the maker Good -> Unresponsive"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn test_maker_rejects_insufficient_liquidity_from_active_reservation() {
    warn!("Running Test: InsufficientLiquidity from active reservation");

    let makers_config_map = vec![(8602, None)];
    let taker_behavior = vec![TakerBehavior::Normal, TakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, vec![]);

    let bitcoind = &test_framework.bitcoind;
    let maker = &makers[0];

    // Fund two takers with enough for a 1 BTC swap each.
    fund_taker(
        &takers[0],
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_taker(
        &takers[1],
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    // Fund the maker with four 0.05 BTC UTXOs. After the fidelity bond, its
    // spendable liquidity is ~15M sats, so two 9M-sat reservations cannot both
    // be admitted, while each request is still below the advertised max_size.
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_thread = {
        let maker = maker.clone();
        thread::spawn(move || start_server(maker).unwrap())
    };

    wait_for_makers_setup(std::slice::from_ref(maker), 120);
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();

    let maker_addr = format!("127.0.0.1:{}", maker.config.network_port);

    // Taker 0 admits a swap with the maker. prepare_swap only negotiates;
    // it does not fund, so the maker keeps an active reservation for the amount.
    let first = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(9_000_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_addr.clone()]);
    takers[0]
        .prepare_swap(first)
        .expect("first swap should be admitted and create a reservation");

    // Taker 1 asks for the same amount. The advertised max_size is still large
    // enough, but the active reservation leaves the maker short of liquidity.
    let second = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(9_000_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_addr]);
    let _err = takers[1]
        .prepare_swap(second)
        .expect_err("second swap should fail due to reserved liquidity");

    // The wire rejection is intentionally terse (AckSwapDetails::reject), so the
    // precise reason is verified in the shared test log (maker warnings are
    // emitted through the root appender).
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Rejecting swap", &log_path);
    test_framework.assert_log("cannot fund", &log_path);
    test_framework.assert_log("sats forwardable", &log_path);

    maker.shutdown.store(true, Relaxed);
    maker_thread.join().unwrap();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Out-of-bounds swap parameters are refused by the taker's own prepare
/// guards, before any maker is contacted — so this needs no maker at all.
/// The maker's own admission guards stay as defense for clients that skip
/// these checks; `maker_rejects_forged_swap_details_at_admission` exercises
/// those with forged wire values.
#[test]
fn taker_rejects_out_of_bounds_params_at_prepare() {
    let (test_framework, mut takers, _makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(vec![], vec![TakerBehavior::Normal], vec![]);
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

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
            params().with_feerate(0),
            format!(
                "Swap feerate 0 sats/vB is below the {} sats/vB relay floor",
                MIN_RELAY_FEE_RATE as u64
            ),
        ),
    ];
    for (params, expected) in cases {
        let error = taker
            .prepare_swap(params)
            .expect_err("an out-of-bounds parameter must fail at prepare time");
        assert!(
            format!("{error:?}").contains(&expected),
            "expected '{}', got: {:?}",
            expected,
            error
        );
    }
    let balance = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "prepare-time rejections must not spend anything"
    );

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// Honest parameters pass the taker's own guards; the behavior hook rewrites
/// exactly one SwapDetails field on the wire, so the refusal must come from
/// the maker's own admission guard — logged as a handler error on the dropped
/// connection. Nothing is funded in any case.
#[test]
fn maker_rejects_forged_swap_details_at_admission() {
    run_maker_rejects_forged_swap_details_at_admission::<BitcoindBackend>();
}

/// Same forgeries on Electrum: admission checks the maker's offer and
/// liquidity against the indexer backend.
#[test]
fn maker_rejects_forged_swap_details_at_admission_electrum() {
    run_maker_rejects_forged_swap_details_at_admission::<ElectrumBackend>();
}

fn run_maker_rejects_forged_swap_details_at_admission<B: TestBackend>() {
    let (test_framework, mut takers, makers, block_generation_handle) = TestFramework::init::<B>(
        vec![(9104, Some(21602))],
        vec![TakerBehavior::Normal],
        vec![MakerBehavior::Normal],
    );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let preferred = vec![format!("127.0.0.1:{}", makers[0].config.network_port)];
    let params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(2)
            .with_required_confirms(1)
            .with_preferred_makers(preferred.clone())
    };
    let cases: Vec<(TakerBehavior, &str)> = vec![
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
    for (behavior, _) in &cases {
        taker.behavior = *behavior;
        let error = taker
            .prepare_swap(params())
            .expect_err("the maker's admission guard must refuse the forged SwapDetails");
        info!("forged {:?} refused at admission: {:?}", behavior, error);
    }
    taker.behavior = TakerBehavior::Normal;

    // Nothing was funded: the taker's balance is untouched.
    let balance = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "admission rejections must not spend anything"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    // Every refusal came from the maker's own admission guard, logged as a
    // handler error on the dropped connection.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    for (_, expected) in &cases {
        test_framework.assert_log(expected, &log_path);
    }

    // The maker never reserved or spent anything either.
    makers[0]
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let maker_balances = makers[0].wallet.read().unwrap().get_balances().unwrap();
    assert_eq!(
        maker_balances.spendable.to_sat(),
        14999757,
        "maker spendable must be untouched after rejected admissions"
    );
    assert_eq!(maker_balances.swap, Amount::ZERO);
    assert_eq!(maker_balances.contract, Amount::ZERO);

    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A maker whose contract response is corrupt — overcounted, or repeating one
/// funded output — is cheating; the taker must refuse it.
fn run_corrupt_contract_response(
    port: u16,
    rpc: u16,
    protocol: ProtocolVersion,
    behavior: MakerBehavior,
    expected: &str,
) {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(port, Some(rpc))],
            vec![TakerBehavior::Normal],
            vec![behavior],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let summary = taker
        .prepare_swap(
            SwapParams::new(protocol, Amount::from_sat(500_000), 1)
                .with_tx_count(3)
                .with_required_confirms(1),
        )
        .expect("prepare swap");
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("a corrupt contract response must be rejected");
    assert!(
        format!("{error:?}").contains(expected),
        "unexpected error: {:?}",
        error
    );

    // The corruption is arithmetically proven, so the maker's standing steps
    // off Good in the offerbook.
    let standing = taker
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|m| m.address.to_string() == format!("127.0.0.1:{}", makers[0].config.network_port))
        .expect("the maker must be in the offerbook");
    assert_eq!(
        standing.state,
        MakerState::Unresponsive { retries: 1 },
        "a proven contract violation must step the maker Good -> Unresponsive"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn taker_rejects_overproduced_legacy_contracts() {
    run_corrupt_contract_response(
        9106,
        21603,
        ProtocolVersion::Legacy,
        MakerBehavior::OverproduceContractData,
        "its reported plan has",
    );
}

#[test]
fn taker_rejects_overproduced_taproot_contracts() {
    run_corrupt_contract_response(
        9108,
        21604,
        ProtocolVersion::Taproot,
        MakerBehavior::OverproduceContractData,
        "its reported plan has",
    );
}

/// One funded Taproot output claimed twice, with the count and total amount
/// still exact: only the taker's duplicate-outpoint check can catch it.
#[test]
fn taker_rejects_duplicated_taproot_contract_outpoint() {
    run_corrupt_contract_response(
        9114,
        21607,
        ProtocolVersion::Taproot,
        MakerBehavior::DuplicateContractOutpoint,
        "duplicate Taproot contract outpoint",
    );
}

/// The Legacy mirror: one funded output backing two sender contracts, count
/// and total exact, so only the taker's duplicate-outpoint check can catch it.
#[test]
fn taker_rejects_duplicated_legacy_contract_outpoint() {
    run_corrupt_contract_response(
        9115,
        21609,
        ProtocolVersion::Legacy,
        MakerBehavior::DuplicateContractOutpoint,
        "duplicate sender contract for funding outpoint",
    );
}

/// A swap the maker cannot fund even degraded to one split must fail before
/// any broadcast. The pool sits below what a single 500k split costs the
/// maker (~499,133 sats at these fees), so the maker's advertised max_size
/// refuses the ask at negotiation.
#[test]
fn maker_without_fee_headroom_fails_before_any_broadcast() {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9110, Some(21605))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    // Bond: exactly 5,000,000 + its 243 sat fee, leaving zero change.
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_sat(5_000_243),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_sat(499_000),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let maker_addr = format!("127.0.0.1:{}", makers[0].config.network_port);
    let error = taker
        .prepare_swap(
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
    let balance = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "a negotiation rejection must not spend anything"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !log_contents.contains("SECURITY: Broadcasting"),
        "an unfundable swap must never reach a funding broadcast"
    );
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A fragmented maker wallet at a high negotiated feerate can only fund the
/// hop by packing many inputs the taker never reimburses (`max_input_budget`
/// is 1). When that unreimbursed cost exceeds the hop's service fee, the
/// maker refuses at admission — before either side locks anything.
#[test]
fn maker_rejects_over_budget_funding_plan() {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9116, Some(21608))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    // The fidelity bond needs one large UTXO (5,000,000 sats + its 243 sat
    // fee, leaving no change); the swap liquidity is eight small ones, so
    // funding 500k sats can only pack six of them into a single split.
    fund_makers(
        &makers,
        bitcoind,
        1,
        Amount::from_sat(5_000_243),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        8,
        Amount::from_sat(100_000),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    // The pool sum covers the amount, but the admission-time plan prices the
    // real input cost: six unreimbursed inputs at 100 sats/vB cost more than
    // the hop earns, so negotiation fails and nothing is locked.
    let error = taker
        .prepare_swap(
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
    let balance = taker.get_wallet().read().unwrap().get_balances().unwrap();
    assert_eq!(
        balance.spendable, taker_original_balance,
        "an admission rejection must not spend anything"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("above the taker's input budget", &log_path);
    test_framework.stop();
    block_generation_handle.join().unwrap();
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
fn run_maker_partial_broadcast<B: TestBackend>(protocol: ProtocolVersion, expected_spendable: u64) {
    warn!(
        "Running Test: maker partial funding broadcast recovery ({:?})",
        protocol
    );

    let makers_config_map = vec![(9402, Some(21401))];
    let taker_behaviors = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::FailSecondBroadcast];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behaviors, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }
    generate_blocks(bitcoind, 1);

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = taker.start_swap(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail when the maker's second broadcast fails"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Test behavior: failing the second", &log_path);

    // The 30s idle timeout starts recovery; the timelock path then needs the
    // maker's outgoing timelock (150 CSV blocks from the contract broadcast).
    // The record never reaches a terminal phase here: the recovery loop only
    // re-checks contract resolution on passes that recover something, and once
    // the maker's own coins are reclaimed every pass returns empty.
    let record = wait_for_maker_timelock_recovery(
        &makers[0].data_dir,
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

    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    let maker = &makers[0];
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let balances = maker.wallet.read().unwrap().get_balances().unwrap();
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

    // The recovery loop keeps polling until shutdown; the maker does not exit
    // on its own in this scenario.
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn maker_recovers_partial_broadcast_legacy() {
    run_maker_partial_broadcast::<BitcoindBackend>(ProtocolVersion::Legacy, 14_999_311);
}

#[test]
fn maker_recovers_partial_broadcast_taproot() {
    run_maker_partial_broadcast::<BitcoindBackend>(ProtocolVersion::Taproot, 14_999_463);
}

#[test]
fn maker_recovers_partial_broadcast_electrum() {
    run_maker_partial_broadcast::<ElectrumBackend>(ProtocolVersion::Legacy, 14_999_311);
}

/// The taker's second funding broadcast fails with the first split already in
/// the mempool and a spare maker available. Substitution would delete the
/// on-chain split's recovery material, so the recorded phase — not the
/// backend's answer — must route the taker to recovery instead.
fn run_taker_recovers_partial_broadcast_with_spare_maker<B: TestBackend>(expected_spendable: u64) {
    warn!("Running Test: taker partial funding broadcast, spare maker available");

    let makers_config_map = vec![(9502, Some(21411)), (19502, Some(21412))];
    let taker_behaviors = vec![TakerBehavior::FailSecondFundingBroadcast];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behaviors, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let swap_params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);

    let summary = taker
        .prepare_swap(swap_params)
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = taker.start_swap(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail at the taker's second funding broadcast"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(
        "Test behavior: failing the second funding broadcast",
        &log_path,
    );

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

    let tracker = SwapTracker::load_or_create(&test_framework.temp_dir.join("taker1")).unwrap();
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
        taker
            .get_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        2,
        "both splits' swapcoins must survive — no substitution cleanup"
    );

    // Recovery reclaims the on-chain split once its timelock matures.
    let recovery_start = Instant::now();
    while !taker.is_recovery_complete() {
        assert!(
            recovery_start.elapsed() <= Duration::from_secs(360),
            "taker recovery did not complete in time"
        );
        thread::sleep(Duration::from_secs(5));
    }

    generate_blocks(bitcoind, 1);
    test_framework.wait_for_electrs_tip();
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    let balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
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

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

#[test]
fn taker_recovers_partial_broadcast_with_spare_maker() {
    run_taker_recovers_partial_broadcast_with_spare_maker::<BitcoindBackend>(14_999_554);
}

/// The same partial batch on Electrum: the backend can lag the session's own
/// broadcast, so only the recorded phase keeps the spare maker unused and
/// the recovery material intact.
#[test]
fn taker_recovers_partial_broadcast_with_spare_maker_electrum() {
    run_taker_recovers_partial_broadcast_with_spare_maker::<ElectrumBackend>(14_999_554);
}

/// A completed swap's Taproot contract data re-presented under a fresh swap id
/// must be rejected: the outputs are already spent by the maker's sweep.
/// The taker behavior resends its first swap's contract data verbatim.
#[test]
fn maker_rejects_replayed_taproot_contract_data() {
    run_maker_rejects_replayed_taproot_contract_data::<BitcoindBackend>();
}

/// Same replay on Electrum: the spent-output answer comes from the indexer,
/// not the wallet's own view of the mempool and chain.
#[test]
fn maker_rejects_replayed_taproot_contract_data_electrum() {
    run_maker_rejects_replayed_taproot_contract_data::<ElectrumBackend>();
}

fn run_maker_rejects_replayed_taproot_contract_data<B: TestBackend>() {
    warn!("Running Test: maker rejects replayed Taproot contract data");

    let makers_config_map = vec![(9602, Some(21421))];
    let taker_behaviors = vec![TakerBehavior::ReplayTaprootContractData];
    let maker_behaviors = vec![MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<B>(makers_config_map, taker_behaviors, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let params = || {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_required_confirms(1)
    };

    // Swap 1 completes normally; its contract data is cached for the replay.
    let summary1 = taker
        .prepare_swap(params())
        .expect("prepare 1 must succeed");
    taker
        .start_swap(&summary1.swap_id)
        .expect("swap 1 must succeed");

    // Wait until the maker's sweep is confirmed and the swap-1 swapcoin has
    // left the store, so only the chain can answer the replay.
    let sweep_wait = Instant::now();
    loop {
        let count = makers[0]
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

    // Swap 2: fresh id, replayed contract data. The maker must reject before
    // funding anything.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let summary2 = taker
        .prepare_swap(params())
        .expect("prepare 2 must succeed");
    assert_ne!(summary1.swap_id, summary2.swap_id);
    let swap2 = taker.start_swap(&summary2.swap_id);
    assert!(
        swap2.is_err(),
        "the maker must reject replayed contract data"
    );

    wait_for_log(
        &log_path,
        "Taproot contract output already spent",
        Duration::from_secs(120),
    );

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = &contents[log_offset as usize..];
    assert!(
        !tail.contains("Broadcast Taproot contract tx"),
        "the maker must not fund the replayed swap"
    );
    assert_eq!(
        makers[0]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count(),
        0,
        "the replay must not leave new incoming swapcoins behind"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The Legacy mirror of the Taproot replay: one confirmed funding's proof
/// re-presented under a fresh swap id must be rejected while the first swap's
/// claim is still live — one incoming contract must never fund two outgoing
/// hops. The behavior hook caches the first swap's proof, dies right after
/// the maker answers it, and resends the cached proof under the second id.
/// The legacy handler runs the per-contract seen-check before the atomic
/// claim, so this serialized scenario always rejects with the seen-check
/// string; the claim's own string needs the concurrent window (see
/// maker_rejects_concurrent_replayed_legacy_proof_of_funding).
#[test]
fn maker_rejects_replayed_legacy_contract_data() {
    run_maker_rejects_replayed_legacy_contract_data::<BitcoindBackend>();
}

/// Same replay on Electrum: the confirmation and seen answers come from the
/// indexer, which lags the session's own view of the chain.
#[test]
fn maker_rejects_replayed_legacy_contract_data_electrum() {
    run_maker_rejects_replayed_legacy_contract_data::<ElectrumBackend>();
}

fn run_maker_rejects_replayed_legacy_contract_data<B: TestBackend>() {
    warn!("Running Test: maker rejects replayed Legacy contract data");

    let (test_framework, mut takers, makers, block_generation_handle) = TestFramework::init::<B>(
        vec![(9612, Some(21422))],
        vec![TakerBehavior::ReplayLegacyProofOfFunding],
        vec![MakerBehavior::Normal],
    );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let preferred = vec![format!("127.0.0.1:{}", makers[0].config.network_port)];
    let params = |confirms| {
        SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_required_confirms(confirms)
            .with_preferred_makers(preferred.clone())
    };

    // Swap 1 dies right after the maker processed its proof of funding, so
    // the maker's claim on the incoming contracts is still live.
    let summary1 = taker
        .prepare_swap(params(1))
        .expect("prepare 1 must succeed");
    let swap1 = taker.start_swap(&summary1.swap_id);
    assert!(
        swap1.is_err(),
        "the behavior hook must abort swap 1 with the maker's claim in flight"
    );

    // With recovery suppressed nothing syncs the wallet between swaps; swap
    // 2's funding must not re-pick swap 1's spent UTXOs.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();

    // Pause mining so swap 2 can skip its confirmation wait: the replay must
    // land while the maker's claim on swap 1 is still within its idle window.
    test_framework.set_block_gen_paused(true);

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // Swap 2 replays swap 1's confirmed funding under a fresh id. Its own
    // funding sits unconfirmed (0 confirms, mining paused); the replayed
    // funding confirmed before the pause.
    let summary2 = taker
        .prepare_swap(params(0))
        .expect("prepare 2 must succeed");
    assert_ne!(summary1.swap_id, summary2.swap_id);
    let swap2 = taker.start_swap(&summary2.swap_id);
    assert!(
        swap2.is_err(),
        "the maker must reject the replayed proof of funding"
    );

    wait_for_log(
        &log_path,
        "Legacy contract txid already in use",
        Duration::from_secs(60),
    );

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = &contents[log_offset as usize..];
    assert!(
        !tail.contains("SECURITY: Broadcasting"),
        "the maker must not fund the replayed swap"
    );

    test_framework.set_block_gen_paused(false);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The in-flight arm of the Taproot replay guard: swap 2 presents swap 1's
/// contract while swap 1's claim is still live on the maker — before any
/// sweep, so only the atomic claim (not the spent check) can refuse it.
/// The behavior hook dies right after the maker answers swap 1's contract
/// data, then replays that data under swap 2's fresh id.
#[test]
fn maker_rejects_replayed_taproot_contract_data_in_flight() {
    run_maker_rejects_replayed_taproot_contract_data_in_flight::<BitcoindBackend>();
}

/// Same in-flight replay on Electrum: the claim is in-memory, but the
/// confirmation wait it protects runs against the indexer.
#[test]
fn maker_rejects_replayed_taproot_contract_data_in_flight_electrum() {
    run_maker_rejects_replayed_taproot_contract_data_in_flight::<ElectrumBackend>();
}

fn run_maker_rejects_replayed_taproot_contract_data_in_flight<B: TestBackend>() {
    warn!("Running Test: maker rejects in-flight replayed Taproot contract data");

    let (test_framework, mut takers, makers, block_generation_handle) = TestFramework::init::<B>(
        vec![(9614, Some(21423))],
        vec![TakerBehavior::ReplayTaprootContractDataInFlight],
        vec![MakerBehavior::Normal],
    );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let preferred = vec![format!("127.0.0.1:{}", makers[0].config.network_port)];
    let params = |confirms| {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_required_confirms(confirms)
            .with_preferred_makers(preferred.clone())
    };

    // Swap 1 dies right after the maker's contract response: the maker has
    // claimed the incoming txid, saved the swapcoins and broadcast its own
    // funding, but no sweep has run.
    let summary1 = taker
        .prepare_swap(params(1))
        .expect("prepare 1 must succeed");
    let swap1 = taker.start_swap(&summary1.swap_id);
    assert!(
        swap1.is_err(),
        "the behavior hook must abort swap 1 with the maker's claim in flight"
    );
    assert_eq!(
        makers[0]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count(),
        1,
        "swap 1's incoming swapcoin must be live on the maker"
    );

    // Hold the timelocks still so the taker's own recovery cannot spend swap
    // 1's contract before the replay lands.
    test_framework.set_block_gen_paused(true);

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // Swap 2 replays swap 1's contract data under a fresh id.
    let summary2 = taker
        .prepare_swap(params(0))
        .expect("prepare 2 must succeed");
    assert_ne!(summary1.swap_id, summary2.swap_id);
    let swap2 = taker.start_swap(&summary2.swap_id);
    assert!(
        swap2.is_err(),
        "the maker must reject the in-flight replayed contract data"
    );

    // The claim's own string, not the generic substring: the per-contract
    // seen-check ("Taproot contract txid already in use") also contains
    // "already in use", so the old needle passed even with the claim deleted.
    wait_for_log(
        &log_path,
        "Contract txid already in use",
        Duration::from_secs(60),
    );

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = &contents[log_offset as usize..];
    assert!(
        !tail.contains("Taproot contract txid already in use"),
        "the atomic claim must fire before the per-contract seen-check"
    );
    assert!(
        !tail.contains("Broadcast Taproot contract tx"),
        "the maker must not fund the replayed swap"
    );
    assert_eq!(
        makers[0]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count(),
        1,
        "the replay must not add incoming swapcoins"
    );

    test_framework.set_block_gen_paused(false);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
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
                log::info!("✅ wait_for_log_after satisfied");
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

/// The genuinely concurrent arm of the Taproot replay guard: with mining
/// paused, swap 1's contract txs sit unconfirmed, so the maker claims their
/// txids and then blocks inside the confirmation wait — before persisting
/// swapcoins or funding anything. Taker 2's swap replays swap 1's contract
/// data (the replay cache is keyed by maker address, so a second taker can
/// resend what the first cached) and must be rejected by the atomic claim:
/// the per-contract seen-check has nothing to see yet, and the output is not
/// spent. Once mining resumes, the maker funds exactly one hop.
#[test]
fn maker_rejects_concurrent_replayed_taproot_contract_data() {
    warn!("Running Test: maker rejects concurrent replayed Taproot contract data");

    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9620, Some(21426))],
            vec![
                TakerBehavior::ReplayTaprootContractData,
                TakerBehavior::ReplayTaprootContractData,
            ],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let mut taker_iter = takers.into_iter();
    let mut taker1 = taker_iter.next().unwrap();
    let mut taker2 = taker_iter.next().unwrap();
    for taker in [&taker1, &taker2] {
        fund_taker(
            taker,
            bitcoind,
            3,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let maker_address = format!("127.0.0.1:{}", makers[0].config.network_port);
    let params = |address: &str| {
        SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_required_confirms(0)
            .with_preferred_makers(vec![address.to_string()])
    };

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    // Hold swap 1's contract txs unconfirmed: the maker claims their txids,
    // then blocks inside the confirmation wait.
    test_framework.set_block_gen_paused(true);
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // Swap 1 runs on its own thread: it sends real contract data, then waits
    // on a maker response that cannot arrive while mining is paused.
    let swap1_address = maker_address.clone();
    let swap1 = thread::spawn(move || {
        let summary = taker1
            .prepare_swap(params(&swap1_address))
            .expect("prepare 1 must succeed");
        taker1.start_swap(&summary.swap_id)
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
        .prepare_swap(params(&maker_address))
        .expect("prepare 2 must succeed");
    let swap2 = taker2.start_swap(&summary2.swap_id);
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
    let tail = &contents[log_offset as usize..];
    assert!(
        !tail.contains("Taproot contract txid already in use"),
        "the per-contract seen-check has nothing to see while swap 1 is unconfirmed"
    );
    assert!(
        !tail.contains("Broadcast Taproot contract tx"),
        "the maker must not fund anything while both swaps wait"
    );

    // Mining resumes: swap 1's handler wakes and funds exactly one hop.
    test_framework.set_block_gen_paused(false);
    wait_for_log_after(
        &log_path,
        log_offset,
        "Broadcast Taproot contract tx",
        1,
        Duration::from_secs(240),
    );
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert_eq!(
        contents[log_offset as usize..]
            .matches("Broadcast Taproot contract tx")
            .count(),
        1,
        "the maker must fund exactly one hop across both swaps"
    );

    let _ = swap1.join().expect("swap 1 thread panicked");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(taker2);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The genuinely concurrent Legacy arm: both swaps carry the same funding —
/// swap 2's via the replayed proof of funding — and both maker handlers block
/// in the proof's confirmation wait while mining is paused. When mining
/// resumes they race out of the wait: the per-contract seen-check and the
/// atomic claim together guarantee exactly one swap is rejected and the maker
/// funds exactly one hop. Which guard fires (and which swap wins) is a
/// scheduling race — the legacy handler runs the seen-check just before the
/// claim with no pausable gap, so a deterministic claim-string needle would
/// need a maker-side barrier hook the integration-test behaviors do not
/// provide.
#[test]
fn maker_rejects_concurrent_replayed_legacy_proof_of_funding() {
    warn!("Running Test: maker rejects concurrent replayed Legacy proof of funding");

    let (test_framework, takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9622, Some(21427))],
            vec![
                TakerBehavior::ReplayLegacyProofOfFunding,
                TakerBehavior::ReplayLegacyProofOfFunding,
            ],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let mut taker_iter = takers.into_iter();
    let taker1 = taker_iter.next().unwrap();
    let taker2 = taker_iter.next().unwrap();
    for taker in [&taker1, &taker2] {
        fund_taker(
            taker,
            bitcoind,
            4,
            Amount::from_btc(0.05).unwrap(),
            AddressType::P2TR,
        );
    }
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let maker_address = format!("127.0.0.1:{}", makers[0].config.network_port);
    let params = |address: &str| {
        SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
            .with_tx_count(1)
            .with_required_confirms(0)
            .with_preferred_makers(vec![address.to_string()])
    };

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());

    // Hold both swaps' funding unconfirmed: each maker handler blocks in the
    // proof's confirmation wait, swap 2's on swap 1's replayed funding txid.
    test_framework.set_block_gen_paused(true);
    let log_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    let run_swap = |mut taker: openswap::taker::Taker, address: String| {
        thread::spawn(move || {
            let summary = taker
                .prepare_swap(params(&address))
                .expect("prepare must succeed");
            taker.start_swap(&summary.swap_id)
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

    // Barrier: swap 2's replayed proof reached the maker and its handler is
    // blocked in the same wait. Both waits must observe the confirmation
    // within the maker's broadcast timeout once mining resumes.
    wait_for_log_after(
        &log_path,
        log_offset,
        "confirmation(s) on tx",
        2,
        Duration::from_secs(120),
    );

    test_framework.set_block_gen_paused(false);

    // Racing out of the wait, exactly one swap is rejected — by the claim or
    // by the seen-check, depending on how the handlers interleave.
    wait_for_log_after(
        &log_path,
        log_offset,
        "already in use",
        1,
        Duration::from_secs(180),
    );
    wait_for_log_after(
        &log_path,
        log_offset,
        "outgoing swapcoins, requesting signatures",
        1,
        Duration::from_secs(180),
    );
    let contents = std::fs::read_to_string(&log_path).unwrap();
    let tail = &contents[log_offset as usize..];
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

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The maker's second funding broadcast fails with the first tx already sent;
/// the taker re-admits the same swap and resends its contract data. The
/// maker must re-process its own swap's contracts — the same-swap exemption
/// in `contract_txid_seen` — instead of rejecting them as a replay. The
/// resumed pass still dies at the funding rebuild (the frozen plan's inputs
/// are spent by the first pass's broadcast), but never with the replay error.
#[test]
fn maker_reprocesses_own_contracts_after_partial_broadcast() {
    warn!("Running Test: maker reprocesses own contracts after partial broadcast");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9616, Some(21424))],
            vec![TakerBehavior::ResumeAfterMakerDrop],
            vec![MakerBehavior::FailSecondBroadcast],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let preferred = vec![format!("127.0.0.1:{}", makers[0].config.network_port)];
    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(2)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();
    let swap_result = taker.start_swap(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail: the resumed pass cannot re-fund the frozen plan"
    );

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Test behavior: maker 0 dropped mid-exchange", &log_path);

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

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A maker restarted mid-swap must refuse a SwapDetails whose id belongs to
/// the unfinished swap its wallet still holds — re-admission would double-
/// fund it. The taker reconnects with the same swap id, the way a resuming
/// client would. (A swap that only reached AckSwapDetails leaves nothing on
/// disk: the idle checker releases an unfunded reservation without a record,
/// so the refusal can only fire once the maker has persisted swapcoins.)
#[test]
fn maker_refuses_unfinished_swap_id_after_restart() {
    warn!("Running Test: maker refuses swap id from an unfinished swap after restart");

    // CrashBeforeRecovery keeps the taker's negotiated state after the failed
    // swap, so the test can resend the same SwapDetails afterwards.
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9618, Some(21425))],
            vec![TakerBehavior::CrashBeforeRecovery],
            vec![MakerBehavior::SkipFundingBroadcast],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let preferred = vec![format!("127.0.0.1:{}", makers[0].config.network_port)];
    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(preferred),
        )
        .expect("prepare must succeed");
    let swap_id = summary.swap_id.clone();

    // The maker persists both sides' swapcoins, then dies before funding: the
    // swap stays unfinished in its wallet.
    let swap_result = taker.start_swap(&swap_id);
    assert!(
        swap_result.is_err(),
        "the swap must fail when the maker skips its funding broadcast"
    );
    assert!(
        makers[0]
            .wallet
            .read()
            .unwrap()
            .get_incoming_swapcoins_count()
            > 0,
        "the maker must hold unfinished swapcoins before the restart"
    );

    // Hold the timelocks still so the restarted maker's recovery cannot
    // resolve the swapcoins before the resend lands.
    test_framework.set_block_gen_paused(true);

    // Restart the maker the way the reboot tests do: the first init consumed
    // the passphrase, so re-supply it.
    let mut victim_config = makers[0].config.clone();
    victim_config.password = Some("integration-test".to_string());
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(makers);

    let restarted = Arc::new(MakerServer::init(victim_config).unwrap());
    let restarted_thread = {
        let maker = restarted.clone();
        thread::spawn(move || start_server(maker).unwrap())
    };
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    // The taker reconnects with the same swap id. Admission must refuse it:
    // the id belongs to the unfinished swap on disk.
    let response = taker
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

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Swap id belongs to an unfinished swap", &log_path);

    test_framework.set_block_gen_paused(false);

    restarted.shutdown.store(true, Relaxed);
    restarted_thread.join().unwrap();
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A maker that funds at the relay floor against a negotiated 3 sat/vB swap:
/// the taker's real-fee check rejects the funding and the proven shortfall
/// steps the maker Good -> Unresponsive in the offerbook.
#[test]
fn test_taproot_rejects_funding_fee_underpayment() {
    run_rejects_funding_fee_underpayment::<BitcoindBackend>(ProtocolVersion::Taproot, 9702, 21431);
}

#[test]
fn test_legacy_rejects_funding_fee_underpayment() {
    run_rejects_funding_fee_underpayment::<BitcoindBackend>(ProtocolVersion::Legacy, 9703, 21432);
}

/// Same underpayment on Electrum: the real-fee check reads the funding
/// inputs' prev txs from the indexer.
#[test]
fn test_taproot_rejects_funding_fee_underpayment_electrum() {
    run_rejects_funding_fee_underpayment::<ElectrumBackend>(ProtocolVersion::Taproot, 9702, 21431);
}

#[test]
fn test_legacy_rejects_funding_fee_underpayment_electrum() {
    run_rejects_funding_fee_underpayment::<ElectrumBackend>(ProtocolVersion::Legacy, 9703, 21432);
}

fn run_rejects_funding_fee_underpayment<B: TestBackend>(
    protocol: ProtocolVersion,
    port: u16,
    rpc: u16,
) {
    let makers_config_map = vec![(port, Some(rpc))];
    let (test_framework, mut takers, makers, block_generation_handle) = TestFramework::init::<B>(
        makers_config_map,
        vec![TakerBehavior::Normal],
        vec![MakerBehavior::UnderpayFundingFee],
    );
    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();
    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    // The hook only bites above the floor: at the 1 sat/vB default the floor
    // and the negotiated rate coincide, so negotiate a custom rate.
    let summary = taker
        .prepare_swap(
            SwapParams::new(protocol, Amount::from_sat(500_000), 1)
                .with_tx_count(2)
                .with_feerate(3)
                .with_required_confirms(1),
        )
        .expect("prepare swap");
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("the underpaying maker's funding must be rejected");
    assert!(
        format!("{error:?}").contains("the agreed feerate requires"),
        "unexpected error: {:?}",
        error
    );

    // The shortfall is arithmetically proven, so the maker's standing steps
    // off Good.
    let standing = taker
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|m| m.address.to_string() == format!("127.0.0.1:{}", makers[0].config.network_port))
        .expect("the maker must be in the offerbook");
    assert_eq!(
        standing.state,
        MakerState::Unresponsive { retries: 1 },
        "a proven fee shortfall must step the maker Good -> Unresponsive"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// An admitted swap whose funding never shows on-chain must die at its
/// admission lifetime, no matter how faithfully the taker pings. The test
/// keeps the reservation warm two ways — a `WaitingFundingConfirmation`
/// keepalive every 10s (half the 30s idle timeout) and two identical
/// SwapDetails resends — and the maker must still release it at the 120s
/// unfunded lifetime, then admit a fresh swap into the freed slot.
#[test]
fn unfunded_swap_dies_at_lifetime_despite_keepalives() {
    warn!("Running Test: unfunded swap dies at its admission lifetime despite keepalives");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9811, Some(21441))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let maker = &makers[0];
    let maker_addr = format!("127.0.0.1:{}", maker.config.network_port);

    // prepare_swap negotiates but never funds: the maker holds an unfunded
    // reservation from here on.
    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr.clone()]),
        )
        .expect("the maker must admit the swap");
    let swap_id = summary.swap_id.clone();

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let start = Instant::now();
    let mut last_ping = Instant::now() - Duration::from_secs(10);
    // The identical resend is the second keepalive vector; both must refresh
    // right up to the lifetime.
    let mut resend_at = vec![Duration::from_secs(45), Duration::from_secs(100)];
    let mut alive_past_idle_cycles = false;
    loop {
        let elapsed = start.elapsed();
        if elapsed >= Duration::from_secs(90) && !alive_past_idle_cycles {
            // Three idle-timeout cycles in, the keepalives must still be
            // holding the reservation.
            alive_past_idle_cycles = maker.has_ongoing_swaps().unwrap();
        }
        if resend_at.first().is_some_and(|mark| elapsed >= *mark) {
            resend_at.remove(0);
            match taker.test_resend_swap_details(0) {
                Ok(openswap::protocol::common_messages::MakerToTakerMessage::AckSwapDetails(
                    ack,
                )) => {
                    assert!(
                        ack.tweakable_point.is_some(),
                        "an identical SwapDetails resend must be accepted while the swap lives"
                    );
                }
                other => panic!("resend got unexpected response: {:?}", other),
            }
        }
        if last_ping.elapsed() >= Duration::from_secs(10) {
            taker
                .test_send_keepalive(&maker_addr, &swap_id)
                .expect("the keepalive send itself must work");
            last_ping = Instant::now();
        }
        let contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if contents.contains("past its admission lifetime") {
            break;
        }
        assert!(
            elapsed < Duration::from_secs(200),
            "the unfunded swap must be released at its admission lifetime"
        );
        thread::sleep(Duration::from_secs(1));
    }

    assert!(
        alive_past_idle_cycles,
        "keepalives must hold the reservation past idle-timeout cycles before the lifetime"
    );
    test_framework.assert_log("Released unfunded swap", &log_path);
    // Accepted keepalives prove the idle timer was being refreshed; the drain
    // reason must be the lifetime, never the idle branch.
    test_framework.assert_log("Resetting timer", &log_path);
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("Released idle unfunded reservation"),
        "the idle branch must not fire while keepalives arrive"
    );

    // The reservation is gone and the slot is reusable.
    assert!(
        !maker.has_ongoing_swaps().unwrap(),
        "the maker must hold no swap after the lifetime drain"
    );
    taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect("a fresh swap must be admitted into the freed slot");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A keepalive naming funding the backend can see still refreshes: with
/// mining paused, the taker's contract txs sit mempool-visible, the maker
/// claims their txids, and the route heartbeat's keepalives pass the
/// evidence gate. Mining resumes and the swap completes.
#[test]
fn keepalive_with_mempool_funding_still_refreshes() {
    warn!("Running Test: keepalive with mempool-visible funding still refreshes");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9812, Some(21442))],
            vec![TakerBehavior::SkipFundingConfirmWait],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let maker_addr = format!("127.0.0.1:{}", makers[0].config.network_port);

    // Hold the tip still so the contract txs sit in the mempool unconfirmed.
    test_framework.set_block_gen_paused(true);

    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect("the maker must admit the swap");
    let swap_id = summary.swap_id.clone();

    let mut taker = takers.remove(0);
    let swap_thread = thread::spawn(move || taker.start_swap(&swap_id));

    // The maker claimed the taker's contract txids and is waiting for a
    // confirmation the paused miner will not give.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(90));

    // A keepalive sent after the claim passes the evidence gate: the funding
    // is mempool-visible, so the idle timer is refreshed.
    wait_for_new_log(&log_path, "Resetting timer", Duration::from_secs(60));

    // Wait past the 30s idle timeout: the swap must still be held.
    thread::sleep(Duration::from_secs(25));
    assert!(
        makers[0].has_ongoing_swaps().unwrap(),
        "a swap with mempool-visible funding must survive the idle timeout"
    );

    test_framework.set_block_gen_paused(false);
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
        !contents.contains("Released unfunded swap"),
        "the swap must be funded well before the admission lifetime"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// A keepalive naming funding the backend cannot see must NOT refresh. The
/// taker withholds its contract tx broadcast but sends the contract data, so
/// the maker claims txids that never reach the mempool; every post-claim
/// keepalive is refused, and the unfunded reservation still dies at its
/// admission lifetime. Mining stays paused so the refund deadline cannot
/// answer the keepalives first.
#[test]
fn keepalive_naming_unseen_funding_is_refused() {
    warn!("Running Test: keepalive naming unseen funding is refused");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9813, Some(21443))],
            vec![TakerBehavior::WithholdFundingBroadcast],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    let maker_addr = format!("127.0.0.1:{}", makers[0].config.network_port);

    test_framework.set_block_gen_paused(true);

    let summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr]),
        )
        .expect("the maker must admit the swap");
    let swap_id = summary.swap_id.clone();

    let mut taker = takers.remove(0);
    let swap_thread = thread::spawn(move || taker.start_swap(&swap_id));

    // The maker claimed the withheld txids and waits for a tx that will never
    // arrive. Everything logged after this point is post-claim.
    wait_for_log(&log_path, "confirmation(s) on tx", Duration::from_secs(90));
    let claim_offset = std::fs::metadata(&log_path).map(|m| m.len()).unwrap_or(0);

    // The heartbeat's keepalives hit the evidence gate and are refused.
    wait_for_log(
        &log_path,
        "names funding the backend cannot see",
        Duration::from_secs(90),
    );

    // The taker's own read deadline ends the swap; recovery discards the
    // never-broadcast contracts without putting them on-chain.
    swap_thread
        .join()
        .unwrap()
        .expect_err("the swap must fail: the maker never answers withheld funding");

    let contents = std::fs::read_to_string(&log_path).unwrap();
    let post_claim = &contents[claim_offset as usize..];
    assert!(
        post_claim.contains("names funding the backend cannot see"),
        "a post-claim keepalive must be refused"
    );
    assert!(
        !post_claim.contains("Resetting timer"),
        "a refused keepalive must not refresh the idle timer"
    );

    // The reservation still dies at the admission lifetime, not by idleness:
    // the withheld funding is not on-chain evidence.
    wait_for_log(
        &log_path,
        "past its admission lifetime",
        Duration::from_secs(240),
    );
    assert!(
        !makers[0].has_ongoing_swaps().unwrap(),
        "the maker must hold no swap after the lifetime drain"
    );

    test_framework.set_block_gen_paused(false);
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}

/// The concurrency cap rejects before any admission planning runs. Thirty
/// real admissions fill every slot — one negotiated prepare_swap plus 29
/// replays of its SwapDetails under fresh ids — and the 31st is refused at
/// the cap. The maker holds exactly enough UTXOs for the 30 reservations, so
/// a plan-first order would die inside the planner ("cannot fund"); the
/// absence of that log proves the cap fired first.
#[test]
fn swap_cap_rejects_before_planning() {
    warn!("Running Test: swap cap rejects before admission planning");

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(9814, Some(21444))],
            vec![TakerBehavior::Normal],
            vec![MakerBehavior::Normal],
        );

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    fund_taker(
        taker,
        bitcoind,
        1,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    // 31 UTXOs: the fidelity bond consumes one net (two inputs, one change
    // back), leaving exactly 30 — one per admission's single-input plan.
    fund_makers(
        &makers,
        bitcoind,
        31,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker = maker.clone();
            thread::spawn(move || start_server(maker).unwrap())
        })
        .collect::<Vec<_>>();
    wait_for_makers_setup(&makers, 120);
    generate_blocks(bitcoind, 1);

    let maker = &makers[0];
    let maker_addr = format!("127.0.0.1:{}", maker.config.network_port);

    let _summary = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(1)
                .with_max_input_budget(1)
                .with_required_confirms(1)
                .with_preferred_makers(vec![maker_addr.clone()]),
        )
        .expect("the first admission must succeed");
    let template = taker
        .current_swap_details(0)
        .expect("the negotiated SwapDetails rebuild");

    // Admissions 2..=30: the negotiated terms under fresh ids.
    for n in 1..30u64 {
        let mut details = template.clone();
        details.id = format!("{:016x}", n);
        match taker
            .resend_swap_details(&maker_addr, &details)
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
    match taker
        .resend_swap_details(&maker_addr, &details)
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

    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("30 active swaps at the 30 cap", &log_path);
    let contents = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !contents.contains("Rejecting swap at admission"),
        "the cap must fire before the planner runs"
    );

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
