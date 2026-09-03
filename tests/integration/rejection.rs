//! Everything either side must refuse, in one place.
//!
//! The refusal point differs per case but nothing settles in any of them.
//! The maker refuses: out-of-bounds, forged, or resent `SwapDetails`;
//! insufficient liquidity at offerbook sync or admission; duplicated,
//! overcounted, overstated, or spent funding outpoints; a proof of funding
//! with no contract binding; and mismatched taproot contract amounts. The
//! taker refuses: malformed legacy funding outputs, underfunded taproot
//! contracts, and fee skimming on either protocol. A fail-closed guard that
//! lets one through costs someone real funds.

use bitcoin::{
    consensus::encode::serialize_hex,
    secp256k1::{rand::rngs::OsRng, Secp256k1, SecretKey},
    Address, Amount, Network,
};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{start_server, MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    utill::{MIN_FEE_RATE, NO_SHUTDOWN},
    wallet::{AddressType, Destination},
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::Duration,
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
                .with_tx_count([1, 3])
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
            14999514,
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.spendable.to_sat(),
            14999514,
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
        .with_tx_count([2, 3])
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
        .with_tx_count([2, 3])
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
        .spend_from_wallet(MIN_FEE_RATE, Destination::Sweep(addr), &coins)
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
        .with_tx_count([3, 3])
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
/// satisfied to reach its own. One maker is enough: the rejection is the point.
fn run_legacy_proof_guard(port: u16, rpc: u16, behavior: TakerBehavior, expected: &str) {
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
        .with_tx_count([3, 3])
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
        "does not match negotiated",
    );
}

#[test]
fn maker_rejects_overstated_proof_of_funding() {
    run_legacy_proof_guard(
        8810,
        21311,
        TakerBehavior::OverstatedFundingAmount,
        "exceeds negotiated swap amount",
    );
}

#[test]
fn maker_rejects_duplicated_funding_outpoint() {
    run_legacy_proof_guard(
        8812,
        21312,
        TakerBehavior::DuplicateFundingOutpoint,
        "Duplicate funding outpoint",
    );
}

fn run_zero_tx_count_bound_rejection(port: u16, rpc: u16, tx_count: [u32; 2], expected: &str) {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(port, Some(rpc))],
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

    let err = taker
        .prepare_swap(
            SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 1)
                .with_tx_count(tx_count)
                .with_required_confirms(1),
        )
        .expect_err("maker must reject zero tx_count bound");
    let error = format!("{err:?}");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log(expected, &log_path);
    test_framework.stop();
    block_generation_handle.join().unwrap();

    assert!(
        error.contains("failed and no spare makers available"),
        "unexpected error: {}",
        error
    );
}

#[test]
fn maker_rejects_zero_forwarding_tx_count() {
    run_zero_tx_count_bound_rejection(8814, 21313, [0, 3], "Transaction count must be non-zero");
}

#[test]
fn maker_rejects_zero_forwarding_utxo_count() {
    run_zero_tx_count_bound_rejection(
        8816,
        21314,
        [3, 0],
        "UTXO count per transaction must be non-zero",
    );
}

#[test]
fn maker_rejects_forwarding_tx_above_utxo_count_limit() {
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(
            vec![(8818, Some(21315))],
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
        1,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        9,
        Amount::from_sat(80_000),
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
                .with_tx_count([3, 1])
                .with_required_confirms(1),
        )
        .expect("prepare swap should succeed before maker forwarding selection");
    let err = taker
        .start_swap(&summary.swap_id)
        .expect_err("maker must reject forwarding tx above UTXO limit");
    let error = format!("{err:?}");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    drop(takers);
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("above negotiated maximum", &log_path);
    test_framework.stop();
    block_generation_handle.join().unwrap();

    assert!(
        error.contains("failed to fill whole buffer"),
        "unexpected error: {}",
        error
    );
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
        .with_tx_count([3, 3])
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
        .with_tx_count([1, 3])
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
        .with_tx_count([3, 3])
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
        .with_tx_count([3, 3])
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
        .with_tx_count([3, 3])
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
    test_legacy_maker_contract_rejection(MakerBehavior::FeeSkimming, "does not match expected");
}

#[test]
fn test_legacy_taker_rejects_overproduced_maker_contracts() {
    test_legacy_maker_contract_rejection(
        MakerBehavior::OverproduceContractData,
        "Wrong number of maker sender contracts",
    );
}

#[test]
fn test_legacy_taker_rejects_maker_funding_inputs_above_limit() {
    test_legacy_maker_contract_rejection(
        MakerBehavior::OverconsumeFundingInputs,
        "above negotiated maximum",
    );
}

fn test_legacy_maker_contract_rejection(behavior: MakerBehavior, expected_error: &str) {
    let makers_config_map = match behavior {
        MakerBehavior::FeeSkimming => vec![(6103, Some(19053))],
        MakerBehavior::OverproduceContractData => vec![(6105, Some(19055))],
        MakerBehavior::OverconsumeFundingInputs => vec![(6107, Some(19057))],
        _ => vec![(6109, Some(19059))],
    };
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
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500_000), 1)
                .with_tx_count([3, 3])
                .with_required_confirms(1),
        )
        .expect("prepare Legacy swap");
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("reject malicious maker contract data");
    let error = format!("{error:?}");
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();

    assert!(
        error.contains(expected_error),
        "unexpected error: {}",
        error
    );
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
        .with_tx_count([3, 3])
        .with_required_confirms(1);
    let summary = taker
        .prepare_swap(swap_params)
        .expect("failed to prepare Taproot openswap");

    // The taker must reject during maker contract verification, before storing
    // an incoming swapcoin from the malicious contract data.
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("taker must reject maker contract data that claims more than the tx output");
    match error {
        TakerError::General(message) => {
            assert!(
                message.contains("Taproot claimed amount")
                    && message.contains("does not match output value"),
                "unexpected taker error: {}",
                message
            );
        }
        other => panic!("unexpected taker error: {:?}", other),
    }

    // Assert the rejection came from the contract amount binding check.
    let log_path = format!("{}/taker/debug.log", test_framework.temp_dir.display());
    test_framework.assert_log("Taproot claimed amount", &log_path);

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
    test_taproot_rejection(MakerBehavior::FeeSkimming, "does not match expected");
}

#[test]
fn test_taproot_rejects_overproduced_maker_contracts() {
    test_taproot_rejection(
        MakerBehavior::OverproduceContractData,
        "wrong Taproot contract count",
    );
}

#[test]
fn test_taproot_rejects_maker_funding_inputs_above_limit() {
    test_taproot_rejection(
        MakerBehavior::OverconsumeFundingInputs,
        "above negotiated maximum",
    );
}

fn test_taproot_rejection(behavior: MakerBehavior, expected_error: &str) {
    let makers_config_map = match behavior {
        MakerBehavior::FeeSkimming => vec![(7103, Some(19062))],
        MakerBehavior::OverproduceContractData => vec![(7107, Some(19066))],
        MakerBehavior::OverconsumeFundingInputs => vec![(7109, Some(19068))],
        _ => vec![(7111, Some(19070))],
    };
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
                .with_tx_count([3, 3])
                .with_required_confirms(1),
        )
        .expect("prepare Taproot swap");
    let error = taker
        .start_swap(&summary.swap_id)
        .expect_err("reject fee skim");
    let error = format!("{error:?}");
    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());
    test_framework.stop();
    block_generation_handle.join().unwrap();

    assert!(
        error.contains(expected_error),
        "unexpected error: {}",
        error
    );
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
        .with_tx_count([1, 3])
        .with_required_confirms(1)
        .with_preferred_makers(vec![maker_addr.clone()]);
    takers[0]
        .prepare_swap(first)
        .expect("first swap should be admitted and create a reservation");

    // Taker 1 asks for the same amount. The advertised max_size is still large
    // enough, but the active reservation leaves the maker short of liquidity.
    let second = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(9_000_000), 1)
        .with_tx_count([1, 3])
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
    test_framework.assert_log("active reservations", &log_path);
    test_framework.assert_log("requested", &log_path);

    maker.shutdown.store(true, Relaxed);
    maker_thread.join().unwrap();
    test_framework.stop();
    block_generation_handle.join().unwrap();
}
