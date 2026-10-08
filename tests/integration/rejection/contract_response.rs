//! The taker checking the maker's contract data: malformed Legacy funding
//! outputs, underfunded or inflated Taproot contracts, overcounted or duplicated
//! contracts, over-reported funding inputs and fee skimming. A proven lie bans
//! the maker. A split funded with more inputs than declared is still accepted,
//! and Legacy funding handed to the taker unsigned cannot be broadcast by it.

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, BanReason, SwapParams},
    wallet::AddressType,
};

use crate::test_framework::*;

#[world_test(
    backend = BitcoindBackend,
    // First maker returns Legacy sender contract data whose contract input points
    // at a real funding tx output, but not the advertised 2-of-2 multisig output.
    maker_behaviors = [MalformedLegacyFundingOutput, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Legacy, sats = 500_000, makers = 2, tx_count = 3),
)]
fn legacy_taker_rejects_malformed_maker_funding_output(world: &mut World, params: SwapParams) {
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
    assert_log!(world; { has "funding output does not pay to advertised multisig" });
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
fn taproot_rejects_underfunded_maker_contract(world: &mut World, params: SwapParams) {
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
    assert_log!(world; { has "does not match the negotiated hop total" });
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
        taproot_rejects_overreported_funding_inputs(
            protocol = ProtocolVersion::Taproot,
            sats = 500_000,
            behavior = MakerBehavior::OverreportFundingInputs,
            tx_count = 2,
            expected = "its plan declared",
        ),
        legacy_rejects_overreported_funding_inputs(
            protocol = ProtocolVersion::Legacy,
            sats = 500_000,
            behavior = MakerBehavior::OverreportFundingInputs,
            tx_count = 2,
            expected = "its plan declared",
        ),
        legacy_taker_rejects_fee_skimming_maker(
            protocol = ProtocolVersion::Legacy,
            sats = 500_000,
            behavior = MakerBehavior::FeeSkimming,
            tx_count = 3,
            expected = "does not match the negotiated hop total",
        ),
        taproot_rejects_fee_skimming_maker(
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

    assert_log!(world; { has "handed-out funding tx" });
    let contents = std::fs::read_to_string(world.taker_log_path()).unwrap();
    assert!(
        !contents
            .lines()
            .any(|line| line.contains("handed-out funding tx") && line.ends_with("accepted")),
        "a handed-out funding tx must not be broadcastable"
    );
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

    assert_log!(world; { has format!("Re-planned funding for swap {swap_id}") });
    let log = std::fs::read_to_string(world.taker_log_path()).unwrap();
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
