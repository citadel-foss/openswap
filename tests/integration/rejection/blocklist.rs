//! Funding-source blocklist rejection through the real Legacy and Taproot swap paths.

use bitcoin::{Amount, Network};
use openswap::{
    blocklist::BlocklistError,
    protocol::common_messages::ProtocolVersion,
    taker::{error::TakerError, SwapParams},
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

    // Blocklist rejection must happen before maker liquidity is spent.
    world.sync_makers();
    assert_balances!(world, since before; { makers: { gain: 0 } });
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    check_blocklist,
    setup = [fund_taker_default(3)],
    cases = [
        taker_rejects_legacy_funding_from_blocked_address(protocol = ProtocolVersion::Legacy),
        taker_rejects_taproot_funding_from_blocked_address(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_taker_rejection(world: &mut World, protocol: ProtocolVersion) {
    // Reuse one maker address for the initial deposits. Fidelity setup later
    // consolidates them into the regular UTXO used for swap funding.
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
    assert_balances!(world; { maker: { regular: 20_000_000 } });

    world.start_makers_without_sync(120);
    world.makers()[0].sync();

    // Fidelity creation spends the deposits above. Block the resulting
    // regular change UTXO, which is the actual input to maker swap funding.
    let maker_regular_utxos = world.makers()[0]
        .inner()
        .wallet
        .read()
        .unwrap()
        .list_descriptor_utxo_spend_info();
    assert_eq!(maker_regular_utxos.len(), 1);
    let blocked_address = bitcoin::Address::from_script(
        maker_regular_utxos[0].0.script_pub_key.as_script(),
        Network::Regtest,
    )
    .unwrap();
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

    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 1)
        .with_tx_count(1)
        .with_required_confirms(1);
    let summary = world
        .taker_mut()
        .prepare(params)
        .expect("prepare_swap should succeed");
    match world.taker_mut().start(&summary.swap_id) {
        Err(TakerError::Blocklist(BlocklistError::BlockedAddress { entry, .. })) => {
            assert_eq!(entry.address, blocked_address.to_string());
        }
        Err(other) => panic!("expected blocked-address error, got {:?}", other),
        Ok(_) => panic!("the taker accepted funding from the maker's blocked source address"),
    }

    // The maker broadcast its funding before the taker rejected it, so those
    // coins stay locked in a contract until the timelock matures and the maker
    // sweeps them back. Rejecting must not strand maker funds.
    world.wait_makers_settled(timelock_recovery_wait::<BitcoindBackend>());
    world.sync_makers();
    assert_balances!(world; {
        makers: { swap: 0, contract: 0, fidelity: BOND },
    });
}
