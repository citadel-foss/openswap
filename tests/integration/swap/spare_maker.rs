//! Three makers for a two-hop route; one drops before any funding is on-chain,
//! the taker substitutes the spare, and the swap completes.
//!
//! `legacy_middle_maker_drops_before_sender_sigs` runs [`complete_with_spare`]
//! too, then checks that nobody was blamed for the drop.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{MakerState, SwapParams},
};

use crate::test_framework::*;

/// The balances one spare-maker test asserts after the swap.
struct SpareMakerExpect {
    taker_spendable: u64,
    maker_spendable: [u64; 3],
}

/// Swaps over `protocol` on a world of three makers and one taker, expects the
/// swap to complete, and asserts the balances. The makers keep running.
#[world_test(
    backend = BitcoindBackend,
    makers = 3,
    maker_behaviors = behaviors,
    takers = [Normal],
    cases = [
        /// The first maker drops before sending the sender's sigs; the taker
        /// continues with the remaining makers.
        legacy_first_maker_drops_before_sender_sigs(
            behaviors = [
                MakerBehavior::CloseAtReqContractSigsForSender,
                MakerBehavior::Normal,
                MakerBehavior::Normal,
            ],
            protocol = ProtocolVersion::Legacy,
            prepare_failure = "Failed to prepare openswap",
            expected = &SpareMakerExpect {
                taker_spendable: 14995985,
                maker_spendable: [14999757, 15000378, 15000415],
            },
        ),
        /// Maker drops after sending AckSwapDetails (Taproot). Taker finds spare maker.
        ///
        /// Scenario:
        /// 1. Taker initiates a Taproot openswap requiring 2 makers, 3 are available.
        /// 2. maker[1] drops after sending AckSwapDetails (before funding broadcast).
        /// 3. Taker detects the failure and retries with the spare maker (maker[2]).
        /// 4. Swap completes successfully with maker[0] and maker[2].
        /// 5. Verify: taker lost fees, makers gained fees.
        taproot_middle_maker_drops_after_ack(
            behaviors = [
                MakerBehavior::Normal,
                MakerBehavior::CloseAfterAckResponse,
                MakerBehavior::Normal,
            ],
            protocol = ProtocolVersion::Taproot,
            prepare_failure = "Failed to prepare Taproot openswap",
            expected = &SpareMakerExpect {
                taker_spendable: 14996327,
                maker_spendable: [15000415, 14999757, 15000378],
            },
        ),
    ],
)]
fn complete_with_spare(
    world: &mut World,
    protocol: ProtocolVersion,
    prepare_failure: &str,
    expected: &SpareMakerExpect,
) {
    // Fund the taker with 3 UTXOs of 0.05 BTC each
    world.fund_taker_default(3);

    // Fund the makers with 4 UTXOs of 0.05 BTC each
    world.fund_makers_default();

    // Start the makers, wait for their setup, then sync their wallets so the
    // fidelity bonds are accounted for
    log::info!("Starting Maker servers...");
    world.start_makers(120);

    world.verify_maker_pre_swap_balances();

    let swap_params = SwapParams::new(protocol, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);

    world.mine(1);

    // Prepare and execute the swap — taker should retry with the spare maker
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect(prepare_failure);
    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("Swap should succeed with spare maker");

    // Sync wallets and verify results
    world.taker().sync();

    world.mine(1);

    world.sync_makers();

    assert_balances!(world; {
        taker: { spendable: expected.taker_spendable, contract: 0, fidelity: 0 },
        makers: { spendable: expected.maker_spendable, contract: 0, fidelity: BOND },
    });
}

/// The middle maker drops before sending the sender's sigs; the taker
/// substitutes the spare, completes, and blames nobody for the drop.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
)]
fn legacy_middle_maker_drops_before_sender_sigs(world: &mut World) {
    complete_with_spare(
        world,
        ProtocolVersion::Legacy,
        "Failed to prepare openswap",
        &SpareMakerExpect {
            taker_spendable: 14995985,
            maker_spendable: [15000415, 14999757, 15000378],
        },
    );

    // Maker 1 dropped the connection. We cannot tell its failure from our own
    // link failing, so nothing about it may be recorded as its fault.
    let standings = world.taker().inner().fetch_offers().unwrap().all_makers();
    for maker in world.makers() {
        let address = maker.address();
        if let Some(standing) = standings.iter().find(|m| m.address.to_string() == address) {
            assert!(
                !matches!(standing.state, MakerState::Banned(_)),
                "a dropped connection must blame nobody, but {} is {:?}",
                address,
                standing.state
            );
        }
    }
}

/// Maker 0 has to re-plan its funding, then rebuild it for the spare's keys
/// after maker 1 drops. The rebuild must reuse the coins the re-plan claimed,
/// not the frozen plan's, or the substitution fails.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [ForceReplan, CloseAtReqContractSigsForSender, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 1),
)]
fn rebuild_after_replan_uses_the_claimed_coins(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap(params)
        .expect("the rebuild must reuse the re-planned coins");

    let contents = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert_eq!(
        contents.matches("Re-planned funding for swap").count(),
        1,
        "only the first pass re-plans; the rebuild reuses its claim"
    );
    assert!(
        contents.contains("Substituting maker 1 with spare"),
        "maker 0 must rebuild its funding for the spare"
    );
    assert_eq!(world.makers()[0].inner().reserved_inputs().unwrap(), 0);
}
