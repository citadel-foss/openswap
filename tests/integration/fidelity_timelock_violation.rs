//! This test demonstrates the scenario when the Maker violates the accepted fidelity_timelock limit.
//! Discovery drops the bond announcement outright, so the swap fails with
//! `NotEnoughMakersInOfferBook`, and a direct poll of that maker sidelines it.
//! Later we restart the Maker with faulty config that is setting the fidelity_timelock to an
//! unacceptable block count, the Maker thus results an error saying "Invalid fidelity timelock".

use bitcoin::Amount;
use openswap::{
    maker::{MakerBehavior, MakerError, MakerServer, MakerServerConfig},
    protocol::common_messages::ProtocolVersion,
    taker::{
        error::TakerError, MakerState, SwapParams, TakerBehavior, UnavailableReason,
        UnavailableState,
    },
    wallet::WalletError,
};

use super::test_framework::*;

use log::{info, warn};
use std::fs;

#[test]
fn fidelity_limit_violation() {
    // ---- Setup ----
    warn!("Running Test: Fidelity Timelock violation");

    // Create a maker with InvalidFidelityTimelock behavior
    let maker_count = 1;
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::InvalidFidelityTimelock];

    // Initialize test framework
    let mut world = World::builder::<BitcoindBackend>()
        .makers(maker_count)
        .maker_behaviors(maker_behaviors)
        .takers(taker_behavior)
        .build();

    info!("Funding taker and maker");
    // Fund the taker with 3 UTXOs of 0.05 BTC each (Taproot)
    world.fund_taker_default(3);

    // Fund the Maker with 4 UTXOs of 0.05 BTC each (Taproot)
    world.fund_makers_default();

    // Start the Maker Server thread, wait for it to complete setup, then
    // sync its wallet
    info!("Initiating Maker server...");
    world.start_makers(120);

    info!("Initiating openswap (Will fail due to invalid fidelity timelock)");

    // Swap params - small amount for faster testing
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 1)
        .with_tx_count(2)
        .with_required_confirms(1);

    // Prepare the swap - it will fail
    let err = world
        .taker_mut()
        .prepare(swap_params)
        .expect_err("Swap should have failed due to NotEnoughMakersInOfferBook");
    assert!(
        matches!(err, TakerError::NotEnoughMakersInOfferBook),
        "Expected NotEnoughMakersInOfferBook, got: {:?}",
        err
    );
    info!("OpenSwap failed as expected: {err:?}");

    // Discovery drops an out-of-range bond before the offerbook ever sees it,
    // so reach the maker the way a user would: poll it by address.
    let address = format!(
        "127.0.0.1:{}",
        world.makers()[0].inner().config.network_port
    );
    assert!(
        world
            .taker()
            .inner()
            .fetch_offers()
            .unwrap()
            .all_makers()
            .iter()
            .all(|m| m.address.to_string() != address),
        "discovery must not admit a maker whose bond timelock is out of range"
    );

    // The range is measured from our own confirmation height, which an honest
    // bond can miss by confirming late, so it sidelines rather than bans.
    let standing = world
        .taker()
        .inner()
        .poll_maker(address)
        .expect("the poll must be recorded");
    assert!(
        matches!(
            standing.state,
            MakerState::Unavailable(UnavailableState {
                reason: UnavailableReason::BondUnverified,
                ..
            })
        ),
        "an out-of-range bond timelock must sideline the maker, got {:?}",
        standing.state
    );

    info!("Shutting down maker to simulate restart with corrupted config");
    world.shutdown_makers();
    let maker = world.makers()[0].inner();

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

    world.finish();
}
