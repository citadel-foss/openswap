//! This test demonstrates the scenario when the Maker violates the accepted fidelity_timelock limit.
//! During offerbook sync, the taker discovers this during offerbook sync and rejects maker's offer
//! leading to `NotEnoughMakersInOfferBook` error.
//! Later we restart the Maker with faulty config that is setting the fidelity_timelock to an
//! unacceptable block count, the Maker thus results an error saying "Invalid fidelity timelock".

use bitcoin::Amount;
use openswap::{
    maker::{start_server, MakerBehavior, MakerError, MakerServer, MakerServerConfig},
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams, TakerBehavior},
    wallet::{AddressType, WalletError},
};

use super::test_framework::*;

use log::{info, warn};
use std::{fs, sync::atomic::Ordering::Relaxed, thread};

#[test]
fn fidelity_limit_violation() {
    // ---- Setup ----
    warn!("Running Test: Fidelity Timelock violation");

    // Create a maker with InvalidFidelityTimelock behavior
    let makers_config_map = vec![(8302, None)];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::InvalidFidelityTimelock];

    // Initialize test framework
    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

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
        thread::spawn(move || {
            start_server(maker_clone).unwrap();
        })
    };

    // Wait for maker to complete setup
    wait_for_makers_setup(std::slice::from_ref(maker), 120);

    // Sync wallets after setup
    maker
        .wallet
        .write()
        .unwrap()
        .sync_and_save(&openswap::utill::NO_SHUTDOWN)
        .unwrap();

    info!("Initiating openswap (Will fail due to invalid fidelity timelock)");

    // Swap params - small amount for faster testing
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 1)
        .with_tx_count([2, 3])
        .with_required_confirms(1);

    // Prepare the swap - it will fail
    let err = taker
        .prepare_swap(swap_params)
        .expect_err("Swap should have failed due to NotEnoughMakersInOfferBook");
    assert!(
        matches!(err, TakerError::NotEnoughMakersInOfferBook),
        "Expected NotEnoughMakersInOfferBook, got: {:?}",
        err
    );
    info!("OpenSwap failed as expected: {err:?}");

    info!("Shutting down maker to simulate restart with corrupted config");
    maker.shutdown.store(true, Relaxed);
    maker_thread.join().unwrap();

    // Write the Maker config to disk so we can modify and reload it.
    // (The test framework creates makers with direct config, not from a file.)
    let config_path = maker.data_dir.join("config.toml");
    maker.config.write_to_file(&config_path).unwrap();

    // Change maker config fidelity_timelock to an unacceptable value
    // (must happen before test_framework.stop() which deletes the temp directory)
    let mut contents = fs::read_to_string(&config_path).unwrap();
    contents = contents.replace("fidelity_timelock = 950", "fidelity_timelock = 100");
    fs::write(&config_path, contents).unwrap();

    // Attempt restart with the corrupted config
    info!("Restarting maker with non-acceptable fidelity_timelock");
    let restart_result = MakerServerConfig::new(Some(&config_path)).map(MakerServer::init);

    match restart_result {
        Err(ref e) => {
            // Config loading itself failed with Fidelity error
            assert!(
                matches!(e, WalletError::Fidelity(_)),
                "Expected WalletError::Fidelity, got: {:?}",
                e
            );
            info!("Maker config rejected as expected: {:?}", e);
        }
        Ok(Err(ref e)) => {
            assert!(
                matches!(e, MakerError::Wallet(WalletError::Fidelity(_))),
                "Expected MakerError::Wallet(WalletError::Fidelity(_)), got: {:?}",
                e
            );
            info!("Maker did not start as expected: {:?}", e);
        }
        Ok(Ok(_)) => {
            panic!("Maker should not have started with invalid fidelity_timelock");
        }
    }

    info!("Fidelity Timelock violation test passed");

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
