//! Bans: who gets blamed for what. An unpriceable offer sidelines its publisher,
//! and wrong keys ban exactly the maker that produced them.

use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::MakerServer,
    protocol::common_messages::ProtocolVersion,
    taker::{BanReason, BanRecord, MakerState, SwapParams, UnavailableReason, UnavailableState},
};

use crate::test_framework::*;

use log::info;
use std::{
    fs, thread,
    time::{Duration, Instant},
};

/// An offer whose minimum exceeds its maximum cannot price any amount. That is
/// also what a maker low on liquidity publishes, so it must sideline the maker
/// without banning it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SendMalformedOffer, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 1),
)]
fn an_unpriceable_offer_sidelines_without_banning(world: &mut World, params: SwapParams) {
    // One hop, so the honest maker alone can carry the route while the
    // malformed offer is judged during the same offerbook sync.
    let _ = world.taker_mut().prepare(params);

    let publisher = world.maker_standing(0);
    assert!(
        matches!(
            publisher,
            MakerState::Unavailable(UnavailableState {
                reason: UnavailableReason::UnpriceableOffer,
                ..
            })
        ),
        "an unpriceable offer must sideline its publisher, not ban it, got {:?}",
        publisher
    );

    assert_eq!(
        world.maker_ban_reason(1),
        None,
        "the honest maker must not be blamed"
    );

    info!("Unpriceable offer test completed successfully!");
}

/// Signatures made with a key nobody agreed to are well formed and still
/// wrong. Only the maker that produced them is banned.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SignSenderContractsWithWrongKey, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Legacy, sats = 500_000, makers = 2),
)]
fn wrong_key_sender_signatures_ban_their_signer(world: &mut World, params: SwapParams) {
    // Both makers are on the route, so there is no spare to substitute and the
    // failure lands on the signer wherever it sits in the order.
    world
        .taker_mut()
        .swap_fails(params, "a swap signed with the wrong key must fail");

    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "the wrong-key signer must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(1),
        None,
        "the honest maker must not be blamed"
    );

    // Naming the banned maker by address must not get it back into a route:
    // the only candidate is refused, so no route can be built at all.
    let banned_address = world.makers()[0].address();
    let refusal = world
        .taker_mut()
        .prepare(
            SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 1)
                .with_tx_count(2)
                .with_required_confirms(1)
                .with_preferred_makers(vec![banned_address.clone()]),
        )
        .expect_err("a banned maker must not be usable by address");
    assert!(
        format!("{refusal:?}").contains("preferred makers"),
        "unexpected refusal for a banned preferred maker: {:?}",
        refusal
    );

    // A ban must outlive its bond. Expire both bonds so each maker redeems its
    // old one and posts a new one for the same address.
    let latest_bond = |maker: &MakerServer| {
        let wallet = maker.wallet.read().unwrap();
        wallet.get_fidelity_bonds().last().unwrap().clone()
    };
    let old_bonds: Vec<_> = world
        .makers()
        .iter()
        .map(|m| latest_bond(m.inner()))
        .collect();
    let expiry = old_bonds
        .iter()
        .map(|bond| bond.lock_time.to_consensus_u32())
        .max()
        .unwrap();
    let height = world.bitcoind().client.get_block_count().unwrap() as u32;
    let mut remaining = expiry.saturating_sub(height) + 10;
    while remaining > 0 {
        let batch = remaining.min(100);
        world.mine(batch as u64);
        remaining -= batch;
    }

    let renewal_start = Instant::now();
    while world
        .makers()
        .iter()
        .zip(&old_bonds)
        .any(|(maker, old)| latest_bond(maker.inner()).outpoint() == old.outpoint())
    {
        assert!(
            renewal_start.elapsed() < Duration::from_secs(180),
            "both makers must renew their expired bonds"
        );
        thread::sleep(Duration::from_secs(5));
    }

    // Only the taker runs discovery, so this line is its registry taking the
    // banned maker's new bond.
    let rebond_txid = latest_bond(world.makers()[0].inner())
        .outpoint()
        .txid
        .to_string();
    let log_path = world.temp_dir().join("taker/debug.log");
    let discovery_start = Instant::now();
    while !fs::read_to_string(&log_path).unwrap().lines().any(|line| {
        line.contains("Stored validated fidelity candidate") && line.contains(&rebond_txid)
    }) {
        assert!(
            discovery_start.elapsed() < Duration::from_secs(180),
            "the taker must discover the banned maker's new bond"
        );
        thread::sleep(Duration::from_secs(5));
    }

    // The sync now meets the expired bond and the new one for the same
    // address. Neither may lift the ban.
    world.taker().inner().sync_offerbook_and_wait().unwrap();
    let rebonded = world
        .taker()
        .inner()
        .fetch_offers()
        .unwrap()
        .all_makers()
        .into_iter()
        .find(|m| m.address.to_string() == banned_address)
        .expect("the banned maker must still be in the offerbook");
    assert!(
        matches!(
            rebonded.state,
            MakerState::Banned(BanRecord {
                reason: BanReason::ProvenViolation,
                ..
            })
        ),
        "a new bond must not lift the ban, got {:?}",
        rebonded.state
    );
    assert_eq!(
        rebonded.fidelity_outpoint,
        Some(old_bonds[0].outpoint()),
        "the banned record must keep its old bond"
    );

    info!("Wrong-key signature test completed successfully!");
}

/// A hashlock built for a key nobody agreed to would pay the next hop to the
/// wrong key. Only the maker that built it is banned.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [WrongHashlockKey, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2),
)]
fn wrong_hashlock_key_bans_its_builder(world: &mut World, params: SwapParams) {
    // The builder is the first hop, so its hashlock must derive from the next
    // maker's key and the taker's nonce.
    let swap_error = world
        .taker_mut()
        .swap_fails(params, "a swap with a wrong-key hashlock must fail");
    assert!(
        format!("{:?}", swap_error).contains("hashlock pubkey verification failed"),
        "the hashlock check must be what stops the swap, got {:?}",
        swap_error
    );

    assert_eq!(
        world.maker_ban_reason(0),
        Some(BanReason::ProvenViolation),
        "the wrong-hashlock builder must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(1),
        None,
        "the honest maker must not be blamed"
    );

    info!("Wrong hashlock key test completed successfully!");
}

/// The last maker takes the keys it was owed and hands back one that does not
/// match. It is banned, and the taker still claims its coins by hashlock.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, SendWrongHandoverKey],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers_without_sync(120),
        mine(1),
    ],
    swap(protocol = Taproot, sats = 500_000, makers = 2),
)]
fn wrong_handover_key_bans_the_last_maker(world: &mut World, params: SwapParams) {
    world
        .taker_mut()
        .swap_fails(params, "a swap with a wrong handover key must fail");

    assert_eq!(
        world.maker_ban_reason(1),
        Some(BanReason::ProvenViolation),
        "the maker handing over a wrong key must be banned"
    );

    assert_eq!(
        world.maker_ban_reason(0),
        None,
        "the honest maker must not be blamed"
    );

    // The taker holds the preimage, so the background recovery claims the
    // last maker's contract by hashlock without waiting on any timelock.
    let recovery_start = Instant::now();
    while !world.taker().inner().is_recovery_complete() {
        assert!(
            recovery_start.elapsed() < Duration::from_secs(300),
            "background recovery did not complete within timeout"
        );
        thread::sleep(Duration::from_secs(5));
    }
    world.mine(1);
    world.taker().sync();
    assert_balances!(world; { taker: { regular: 14_499_692, swap: 497_369, contract: 0 } });

    info!("Wrong handover key test completed successfully!");
}
