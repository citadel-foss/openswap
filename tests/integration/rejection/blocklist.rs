//! Funding-source blocklist rejection through the real Legacy and Taproot swap paths.

use bitcoin::{Amount, Network};
use openswap::{
    blocklist::BlocklistError,
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, BanReason, MakerState, SwapParams},
    wallet::AddressType,
};

use crate::test_framework::*;

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    cases = [
        legacy_populated_blocklist_is_ignored_when_disabled(protocol = ProtocolVersion::Legacy),
        taproot_populated_blocklist_is_ignored_when_disabled(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_disabled_blocklist(world: &mut World, protocol: ProtocolVersion) {
    let blocked_taker_address = world
        .taker()
        .inner()
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..3 {
        send_to_address(
            world.bitcoind(),
            &blocked_taker_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    world.mine(1);
    world.taker().sync();

    let maker_deposit_address = world.makers()[0]
        .inner()
        .wallet
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..4 {
        send_to_address(
            world.bitcoind(),
            &maker_deposit_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    world.mine(1);
    world.makers()[0].sync();

    world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_taker_address.to_string(),
            Some("disabled maker-side check".to_string()),
        )
        .unwrap();

    world.start_makers_without_sync(120);
    world.makers()[0].sync();

    let maker_regular_utxos = world.makers()[0]
        .inner()
        .wallet
        .read()
        .unwrap()
        .list_descriptor_utxo_spend_info();
    assert_eq!(maker_regular_utxos.len(), 1);
    let blocked_maker_address = bitcoin::Address::from_script(
        maker_regular_utxos[0].0.script_pub_key.as_script(),
        Network::Regtest,
    )
    .unwrap();
    world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_maker_address.to_string(),
            Some("disabled taker-side check".to_string()),
        )
        .unwrap();

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1);
    world
        .taker_mut()
        .swap(params)
        .expect("a populated blocklist must be ignored when checking is disabled");
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    check_blocklist,
    cases = [
        maker_rejects_legacy_funding_from_blocked_address(protocol = ProtocolVersion::Legacy),
        maker_rejects_taproot_funding_from_blocked_address(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_maker_rejection(world: &mut World, protocol: ProtocolVersion) {
    // Every spendable taker UTXO comes from this address, so whichever coins
    // funding selects must trigger the maker's source-address check.
    let blocked_address = world
        .taker()
        .inner()
        .get_wallet()
        .write()
        .unwrap()
        .get_next_external_address(AddressType::P2TR)
        .unwrap();
    for _ in 0..3 {
        send_to_address(
            world.bitcoind(),
            &blocked_address,
            Amount::from_btc(0.05).unwrap(),
        );
    }
    world.mine(1);
    world.taker().sync();
    assert_balances!(world; { taker: { regular: 15_000_000 } });

    let outcome = world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.updated, 0);

    world.fund_makers_default();

    world.start_makers(120);
    world.verify_maker_pre_swap_balances();
    let before = world.balances();

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(1)
        .with_required_confirms(1);
    world.taker_mut().swap_fails(
        params,
        "the first maker must reject funding from the blocked source address",
    );
    // The taker only sees the dropped connection; the maker's log names why.
    assert_log!(world; { has format!("uses blocked address {blocked_address}") });

    // Blocklist rejection must happen before maker liquidity is spent.
    world.sync_makers();
    assert_balances!(world, since before; { makers: { gain: 0 } });
}

/// The maker skims a sat from its funding, which the taker can prove, and
/// funds from a listed address. The taker must reject on the violation and
/// ban the maker before it spends any backend queries screening that funding.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [FeeSkimming],
    takers = [Normal],
    check_blocklist,
    setup = [
        fund_taker_default(3),
        fund_maker_from_one_address(0, 4, Amount::from_btc(0.05).unwrap(), AddressType::P2TR),
        start_makers(120),
    ],
    cases = [
        legacy_proven_violation_precedes_blocklist_screen(protocol = ProtocolVersion::Legacy),
        taproot_proven_violation_precedes_blocklist_screen(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_violation_with_blocked_funding(world: &mut World, protocol: ProtocolVersion) {
    // The same funding source the blocklist-only tests refuse.
    let blocked_address = world.sole_regular_utxo_address(0);
    let outcome = world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test maker source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);

    let mark = log_mark(world);
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare_swap should succeed");
    match world.taker_mut().start(&summary.swap_id) {
        Err(TakerError::General(message)) => assert!(
            message.contains("does not match the negotiated hop total"),
            "unexpected taker error: {}",
            message
        ),
        Err(other) => panic!("expected the proven fee skim, got {:?}", other),
        Ok(_) => panic!("the taker accepted a fee-skimming maker's funding"),
    }

    // The screen logs every match. Its funding input is listed, so a screen
    // that ran would have logged this one.
    assert_log!(world, since mark; {
        lacks format!("uses blocked address {}", blocked_address),
    });
    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "a proven contract violation must ban the maker"
    );
}

/// Route `maker_count` makers and list the funding source of the maker at
/// route position `blocked_maker`. The taker must refuse its own incoming
/// funding, but respect an intermediate recipient's choice to disable screening.
#[world_test(
    backend = BitcoindBackend,
    makers = maker_count,
    takers = [Normal],
    check_blocklist,
    setup = [fund_taker_default(3)],
    cases = [
        taker_rejects_legacy_funding_from_blocked_address(
            protocol = ProtocolVersion::Legacy, maker_count = 1, blocked_maker = 0,
        ),
        taker_rejects_taproot_funding_from_blocked_address(
            protocol = ProtocolVersion::Taproot, maker_count = 1, blocked_maker = 0,
        ),
        taker_ignores_legacy_intermediate_funding_when_receiving_maker_disables_screening(
            protocol = ProtocolVersion::Legacy, maker_count = 2, blocked_maker = 0,
        ),
        taker_ignores_taproot_intermediate_funding_when_receiving_maker_disables_screening(
            protocol = ProtocolVersion::Taproot, maker_count = 2, blocked_maker = 0,
        ),
        taker_rejects_legacy_final_funding_on_multihop_route(
            protocol = ProtocolVersion::Legacy, maker_count = 2, blocked_maker = 1,
        ),
        taker_rejects_taproot_final_funding_on_multihop_route(
            protocol = ProtocolVersion::Taproot, maker_count = 2, blocked_maker = 1,
        ),
    ],
)]
fn run_taker_screening(
    world: &mut World,
    protocol: ProtocolVersion,
    maker_count: usize,
    blocked_maker: usize,
) {
    let reject_final_funding = blocked_maker + 1 == maker_count;
    if !reject_final_funding {
        // All roles share the populated list. Only the maker receiving the
        // listed intermediate funding opts out; the taker's check stays on.
        world.maker_mut(blocked_maker + 1).config.check_blocklist = false;
    }

    // Reuse one address per maker for the initial deposits. Fidelity setup
    // later consolidates them into the regular UTXO used for swap funding.
    for i in 0..maker_count {
        world.fund_maker_from_one_address(i, 4, Amount::from_btc(0.05).unwrap(), AddressType::P2TR);
    }
    world.start_makers(120);

    // Fidelity creation spends the deposits above. Block the resulting
    // regular change UTXO, which is the actual input to maker swap funding.
    let blocked_address = world.sole_regular_utxo_address(blocked_maker);
    let outcome = world
        .taker()
        .inner()
        .add_blocklist_entry(
            blocked_address.to_string(),
            Some("integration test maker source".to_string()),
        )
        .unwrap();
    assert_eq!(outcome.added, 1);
    assert_eq!(outcome.updated, 0);

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), maker_count)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare_swap should succeed");
    if reject_final_funding {
        match world.taker_mut().start(&summary.swap_id) {
            Err(TakerError::Blocklist(BlocklistError::BlockedAddress { entry, .. })) => {
                assert_eq!(entry.address, blocked_address.to_string());
            }
            Err(other) => panic!("expected blocked-address error, got {:?}", other),
            Ok(_) => panic!("the taker accepted funding from the maker's blocked source address"),
        }

        // Every hop funded before the rejection must recover its coins.
        world.wait_makers_settled(timelock_recovery_wait::<BitcoindBackend>());
        assert!(
            world.taker_mut().wait_for_recovery(),
            "the taker must recover its own funding after the rejection"
        );
    } else {
        world
            .taker_mut()
            .start(&summary.swap_id)
            .expect("the taker must not screen funding paid to a maker that disables screening");
        world.mine(1);
    }

    world.sync_all();
    assert_balances!(world; {
        taker: { contract: 0 },
        makers: { contract: 0, fidelity: BOND },
    });
    if reject_final_funding {
        assert_balances!(world; { makers: { swap: 0 } });
    } else {
        let balances = world.balances();
        assert!(balances.takers[0].swap > Amount::ZERO);
        for (i, maker) in balances.makers.iter().enumerate() {
            assert!(maker.swap > Amount::ZERO, "maker {} swap balance", i);
        }
    }

    // A listed source is local policy, never proof of misbehaviour: no maker
    // on the route may be banned for it.
    for i in 0..maker_count {
        assert!(
            !matches!(world.maker_standing(i), MakerState::Banned(_)),
            "maker {} was banned for a blocklist refusal: {:?}",
            i,
            world.maker_standing(i)
        );
    }
}
