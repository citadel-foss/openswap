//! Fees: a maker without headroom for even one split, a funding plan that costs
//! more than the hop earns, and a maker funding below the negotiated feerate.

use bitcoin::Amount;
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{BanReason, SwapParams},
    wallet::AddressType,
};

use crate::test_framework::*;

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

/// A maker that funds at the relay floor against a negotiated 3 sat/vB swap:
/// the taker's real-fee check bans the maker for the proven shortfall, and the
/// swap still completes, since by then the fee is paid and every hop has funded.
#[world_test(
    maker_behaviors = [UnderpayFundingFee],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), spawn_ready_makers_and_mine()],
    cases = [
        taproot_bans_funding_fee_underpayment(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        legacy_bans_funding_fee_underpayment(
            backend = BitcoindBackend,
            protocol = ProtocolVersion::Legacy,
        ),
        /// Same underpayment on Electrum: the real-fee check reads the funding
        /// inputs' prev txs from the indexer.
        taproot_bans_funding_fee_underpayment_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        legacy_bans_funding_fee_underpayment_electrum(
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
