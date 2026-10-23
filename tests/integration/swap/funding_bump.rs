//! Funding bumps: a hop whose funding sits unconfirmed is replaced at a higher
//! feerate, and the swap completes on the replacement.
//!
//! Each row keeps one party's funding out of blocks, the way a fee spike
//! would: `StallFunding` takes its fee out of the miner's view, so only the
//! replacement, a different tx, can confirm. The taker bumps after 2 blocks.
//! On Electrum the hook acts on the Core node the test electrs indexes.

use bitcoin::Amount;
use openswap::{
    maker::MakerBehavior,
    protocol::common_messages::ProtocolVersion,
    taker::{FundingBumpPolicy, SwapParams, TakerBehavior},
};

use crate::test_framework::*;

/// The swap feerate is 1 sat/vB; the market the bump prices on is 4.
const MARKET_FEERATE: &str = "4";

#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    maker_behaviors = behaviors,
    takers = [taker],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        /// Our own hop-0 funding is stuck: we re-sign it at the market rate,
        /// out of the contract outputs, and maker 0 takes the smaller hop.
        taproot_taker_bumps_its_stuck_funding(
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::StallFunding,
            behaviors = [MakerBehavior::Normal, MakerBehavior::Normal],
            hop = 0,
        ),
        /// Maker 0's funding is stuck: it replaces it when we ask, and maker 1
        /// accepts the smaller hop at its admitted fee.
        taproot_maker_bumps_its_stuck_funding(
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::StallFunding, MakerBehavior::Normal],
            hop = 1,
        ),
        /// The last maker's funding pays us: our incoming coin follows the
        /// replacement.
        taproot_last_maker_bumps_its_stuck_funding(
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::Normal, MakerBehavior::StallFunding],
            hop = 2,
        ),
        /// Legacy hop 0: maker 0 signs the replacement's contract before it is
        /// broadcast, so we can still refund whichever version confirms.
        legacy_taker_bumps_its_stuck_funding(
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::StallFunding,
            behaviors = [MakerBehavior::Normal, MakerBehavior::Normal],
            hop = 0,
        ),
        /// Legacy maker 0 proposes the replacement unsigned, maker 1 signs its
        /// contract, and only then does maker 0 broadcast it.
        legacy_maker_bumps_its_stuck_funding(
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::StallFunding, MakerBehavior::Normal],
            hop = 1,
        ),
        /// Legacy last hop: we are the next hop, so we sign the replacement's
        /// contract ourselves.
        legacy_last_maker_bumps_its_stuck_funding(
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::Normal, MakerBehavior::StallFunding],
            hop = 2,
        ),
        // The same flows when every party reads the chain through Electrum.
        taproot_taker_bumps_its_stuck_funding_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::StallFunding,
            behaviors = [MakerBehavior::Normal, MakerBehavior::Normal],
            hop = 0,
        ),
        taproot_maker_bumps_its_stuck_funding_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::StallFunding, MakerBehavior::Normal],
            hop = 1,
        ),
        taproot_last_maker_bumps_its_stuck_funding_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::Normal, MakerBehavior::StallFunding],
            hop = 2,
        ),
        legacy_taker_bumps_its_stuck_funding_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::StallFunding,
            behaviors = [MakerBehavior::Normal, MakerBehavior::Normal],
            hop = 0,
        ),
        legacy_maker_bumps_its_stuck_funding_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::StallFunding, MakerBehavior::Normal],
            hop = 1,
        ),
        legacy_last_maker_bumps_its_stuck_funding_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::Normal, MakerBehavior::StallFunding],
            hop = 2,
        ),
    ],
)]
fn run_stuck_funding_bump(world: &mut World, protocol: ProtocolVersion, hop: usize) {
    std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", MARKET_FEERATE);
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_funding_bump(FundingBumpPolicy::new(10).with_after_blocks(2));

    world
        .taker_mut()
        .swap(params)
        .expect("a swap whose stuck hop was bumped must complete");

    assert_log!(world; {
        has format!("Bumping hop {hop} funding"),
        has format!("Funding bump broadcast for hop {hop}"),
        has format!("Hop {hop} confirmed"),
    });
    if hop > 0 {
        assert_log!(world; { has "Broadcast replacement funding" });
    }

    world.taker().sync();
    world.mine(1);
    world.sync_makers();
    // Every party settles: the replaced versions leave nothing to recover.
    for (i, maker) in world.makers().iter().enumerate() {
        let balances = maker.balances();
        assert_eq!(
            balances.contract,
            Amount::ZERO,
            "maker {i} must hold no contract after the swap"
        );
    }
    assert_eq!(world.taker().balances().contract, Amount::ZERO);

    // The losing versions outlive the swap until the winner is buried deep,
    // then the running taker and makers retire them on their own.
    world.mine(6);
    let swapcoins = |wallet: &openswap::wallet::Wallet| {
        wallet.get_outgoing_swapcoins_count() + wallet.get_incoming_swapcoins_count()
    };
    wait_until!(
        std::time::Duration::from_secs(120),
        "every party to retire the replaced funding versions",
        swapcoins(&world.taker().inner().get_wallet().read().unwrap()) == 0
            && world
                .makers()
                .iter()
                .all(|maker| swapcoins(&maker.inner().wallet.read().unwrap()) == 0)
    );
}

/// Our node takes our hop-0 replacement but its answer is lost, so the
/// broadcast reads as failed. The replacement is tracked from the moment it is
/// signed, so the hop settles on it when it confirms instead of timing out.
#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    takers = [StallFundingAndLoseBroadcastReply],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        taproot_taker_tracks_a_replacement_whose_broadcast_answer_was_lost(
            protocol = ProtocolVersion::Taproot,
        ),
        legacy_taker_tracks_a_replacement_whose_broadcast_answer_was_lost(
            protocol = ProtocolVersion::Legacy,
        ),
        taproot_taker_tracks_a_replacement_whose_broadcast_answer_was_lost_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        legacy_taker_tracks_a_replacement_whose_broadcast_answer_was_lost_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
        ),
    ],
)]
fn run_lost_broadcast_answer(world: &mut World, protocol: ProtocolVersion) {
    std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", MARKET_FEERATE);
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_funding_bump(FundingBumpPolicy::new(10).with_after_blocks(2));

    world
        .taker_mut()
        .swap(params)
        .expect("the hop settles on the replacement the node took");

    assert_log!(world; {
        has "Test behavior: losing the node's answer to broadcast",
        has "Bumping hop 0 funding",
        has "Hop 0 confirmed",
    });
    world.taker().sync();
    world.mine(1);
    world.sync_makers();
    assert_eq!(world.taker().balances().contract, Amount::ZERO);
}

/// The market sits below what a bump needs for the first intervals, then
/// rises. Intervals where no bump is due leave the budget alone, so the one
/// bump allowed still fires once fees climb, and the stuck hop confirms.
#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    takers = [StallFunding],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
)]
fn idle_bump_intervals_do_not_spend_the_bump_budget(world: &mut World) {
    // At the 1 sat/vB swap feerate, a bump needs the market at 2 or more.
    std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", "1");
    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_funding_bump(
            FundingBumpPolicy::new(10)
                .with_after_blocks(2)
                .with_max_bumps(1),
        );

    let log = world.taker_log_path();
    let fees_rise = std::thread::spawn(move || {
        wait_until!(
            std::time::Duration::from_secs(300),
            "two bump intervals with no bump due",
            std::fs::read_to_string(&log)
                .is_ok_and(|text| { text.matches("but no bump is due or allowed").count() >= 2 })
        );
        std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", MARKET_FEERATE);
    });

    world
        .taker_mut()
        .swap(params)
        .expect("the bump left in the budget frees the stuck hop");
    fees_rise.join().expect("fee rise thread");

    assert_log!(world; {
        has "Hop 0 funding is unconfirmed, but no bump is due or allowed",
        has "Funding bump broadcast for hop 0",
        has "Hop 0 confirmed",
    });
}

/// A route member who knows the swap id but not the taker's key cannot move a
/// maker's funding: the maker refuses the bump, and the swap completes once
/// the stuck funding confirms after all.
#[world_test(
    maker_behaviors = [StallFunding, Normal],
    takers = [ForgeFundingBumpKey],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        maker_refuses_a_funding_bump_the_taker_did_not_sign(backend = BitcoindBackend),
        maker_refuses_a_funding_bump_the_taker_did_not_sign_electrum(backend = ElectrumBackend),
    ],
)]
fn run_forged_bump_refused(world: &mut World) {
    std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", MARKET_FEERATE);
    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_funding_bump(
            FundingBumpPolicy::new(10)
                .with_after_blocks(2)
                .with_max_bumps(1),
        );

    // The stalled funding would wait out the whole confirmation window, so
    // once the forged bump is refused, give the market back its fee.
    let log = world.taker_log_path();
    let rpc_url = world.bitcoind().rpc_url();
    let cookie = world.bitcoind().params.cookie_file.clone();
    let unstall = std::thread::spawn(move || {
        wait_until!(
            std::time::Duration::from_secs(300),
            "the maker to refuse the forged bump",
            std::fs::read_to_string(&log)
                .is_ok_and(|text| text.contains("not signed by the swap's taker"))
        );
        restore_mempool_fees(&rpc_url, &cookie);
    });

    world
        .taker_mut()
        .swap(params)
        .expect("the swap completes once the stuck funding confirms");
    unstall.join().expect("unstall thread");

    assert_log!(world; {
        has "not signed by the swap's taker",
        lacks "Funding bump broadcast for hop 1",
        lacks "Broadcast replacement funding",
    });
}

/// Undo `StallFunding`: put every mempool tx's fee back in the miner's view.
fn restore_mempool_fees(rpc_url: &str, cookie: &std::path::Path) {
    use bitcoind::bitcoincore_rpc::{Auth, Client, RpcApi};

    let client = Client::new(rpc_url, Auth::CookieFile(cookie.to_path_buf()))
        .expect("rpc client for the test node");
    for txid in client.get_raw_mempool().expect("mempool") {
        let _: bool = client
            .call(
                "prioritisetransaction",
                &[
                    serde_json::json!(txid.to_string()),
                    serde_json::json!(0),
                    serde_json::json!(100_000_000i64),
                ],
            )
            .expect("prioritisetransaction");
    }
}

/// The taker never hears that a maker's replacement is out: the maker's
/// answer is lost and no bump is left to retry. The taker finds the
/// replacement spending the stalled original's coins, checks it is exactly
/// the bump, and the swap completes on it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [StallFunding, Normal],
    takers = [DropBumpReply],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        taproot_taker_finds_a_replacement_it_never_heard_of(protocol = ProtocolVersion::Taproot),
        legacy_taker_finds_a_replacement_it_never_heard_of(protocol = ProtocolVersion::Legacy),
        taproot_taker_finds_a_replacement_it_never_heard_of_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Taproot,
        ),
        legacy_taker_finds_a_replacement_it_never_heard_of_electrum(
            backend = ElectrumBackend,
            protocol = ProtocolVersion::Legacy,
        ),
    ],
)]
fn run_lost_bump_reply(world: &mut World, protocol: ProtocolVersion) {
    std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", MARKET_FEERATE);
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_funding_bump(
            FundingBumpPolicy::new(10)
                .with_after_blocks(2)
                .with_max_bumps(1),
        );

    world
        .taker_mut()
        .swap(params)
        .expect("the swap follows the replacement it found on chain");

    assert_log!(world; {
        has "Test behavior: losing the maker's answer",
        has "Broadcast replacement funding",
        has "that its maker never reported",
        has "Hop 1 confirmed",
    });
}

// The reorg tests run on Core only. Their reorg is `invalidateblock`, and
// electrs, which fetches blocks from the node over p2p, can wait forever for
// a block the node has marked invalid and never serves. A real reorg brings a
// competing chain instead; what these tests check is the makers' own logic,
// which reads the chain the same way on either backend.

/// A reorg orphans the block that mined maker 0's funding after maker 1 has
/// built on it, and the taker asks maker 0 to bump it. Maker 0 saw that
/// funding mined, so it refuses: the original is mined again and the swap
/// completes on it.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [ReorgAndBumpFirstMakerHop],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        /// Only the latch knows: Taproot hears of the next hop at handover.
        taproot_maker_refuses_to_bump_funding_it_saw_mined(
            protocol = ProtocolVersion::Taproot,
            refusal = "Every funding tx of this hop has confirmed",
        ),
        /// Legacy also knows from signing the next hop's receiver contract.
        legacy_maker_refuses_to_bump_funding_it_saw_mined(
            protocol = ProtocolVersion::Legacy,
            refusal = "This hop's funding is settled",
        ),
    ],
)]
fn run_bump_after_reorg_refused(world: &mut World, protocol: ProtocolVersion, refusal: &str) {
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1);

    world
        .taker_mut()
        .swap(params)
        .expect("the swap completes on the original funding");

    assert_log!(world; {
        has "it can no longer be bumped",
        has "Test behavior: orphaned the block that mined maker 0's funding",
        has refusal,
        has "post-reorg bump of maker 0 answered: refused",
        lacks "Broadcast replacement funding",
    });
}

/// Same reorg, but maker 0's node never saw the orphaned block, so it does
/// replace its funding. Maker 1 accepted the original; it finds the mined
/// replacement paying the same contract and claims that instead.
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [SkipFundingLatch, Normal],
    takers = [ReorgAndBumpFirstMakerHop],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
)]
fn taproot_next_maker_follows_a_replacement_after_reorg(world: &mut World) {
    let params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1);

    world
        .taker_mut()
        .swap(params)
        .expect("the swap completes on the replacement");

    assert_log!(world; {
        has "post-reorg bump of maker 0 answered: replaced",
        has "Broadcast replacement funding",
        has "; following it",
    });
    world.taker().sync();
    world.mine(1);
    world.sync_makers();
    assert_eq!(world.makers()[1].balances().contract, Amount::ZERO);
}

/// A reorg mines the replaced version of a bumped hop after the swap
/// completed on its replacement. The funder kept that version for just this,
/// and recovers the swap from it.
///
/// Settling it is the receiver's to do, who holds the keys by now, but makers
/// do not yet keep their replaced incoming versions. So this checks the
/// funder's side: the swap is back in recovery with the version kept. Our own
/// recovery holds the refund for the first maker's claim; a maker refunds
/// once the timelock passes, as with any contract left unclaimed.
#[world_test(
    backend = BitcoindBackend,
    makers = 2,
    maker_behaviors = behaviors,
    takers = [taker],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        /// Our own hop 0: our recovery loop sees it revived and keeps it.
        taker_recovers_a_replaced_funding_a_reorg_mines(
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::StallFunding,
            behaviors = [MakerBehavior::Normal, MakerBehavior::Normal],
            hop = 0,
            recovery = "is mined after a reorg; recovering",
            refunds = false,
        ),
        /// Maker 0's hop 1: its version retirement sees it revived and hands
        /// the swap to recovery.
        maker_recovers_a_replaced_funding_a_reorg_mines(
            protocol = ProtocolVersion::Taproot,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::StallFunding, MakerBehavior::Normal],
            hop = 1,
            recovery = "recover_from_swap started",
            refunds = true,
        ),
        /// Legacy keeps each version with its own contract signatures; the
        /// revived one is recovered on them.
        legacy_taker_recovers_a_replaced_funding_a_reorg_mines(
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::StallFunding,
            behaviors = [MakerBehavior::Normal, MakerBehavior::Normal],
            hop = 0,
            recovery = "is mined after a reorg; recovering",
            refunds = false,
        ),
        legacy_maker_recovers_a_replaced_funding_a_reorg_mines(
            protocol = ProtocolVersion::Legacy,
            taker = TakerBehavior::Normal,
            behaviors = [MakerBehavior::StallFunding, MakerBehavior::Normal],
            hop = 1,
            recovery = "recover_from_swap started",
            refunds = true,
        ),
    ],
)]
fn run_revived_replaced_funding(
    world: &mut World,
    protocol: ProtocolVersion,
    hop: usize,
    recovery: &str,
    refunds: bool,
) {
    use bitcoind::bitcoincore_rpc::RpcApi;

    std::env::set_var("OPENSWAP_FUNDING_BUMP_FEERATE", MARKET_FEERATE);
    // Keep the replaced versions past the winner's depth, so the reorg below
    // still finds them kept.
    std::env::set_var("OPENSWAP_REPLACED_VERSION_DISCARD_DEPTH", "1000");
    let params = SwapParams::new(protocol, Amount::from_sat(500_000), 2)
        .with_tx_count(2)
        .with_required_confirms(1)
        .with_funding_bump(FundingBumpPolicy::new(10).with_after_blocks(2));
    world
        .taker_mut()
        .swap(params)
        .expect("a swap whose stuck hop was bumped must complete");

    let funder_wallet = || match hop {
        0 => world.taker().inner().get_wallet().clone(),
        _ => world.makers()[hop - 1].inner().wallet.clone(),
    };
    let client = &world.bitcoind().client;
    // A version the node never mined is one that lost: its funding tx,
    // signed. The funder drops its winners once it finished the swap.
    let unmined = |tx: &bitcoin::Transaction| {
        client
            .get_raw_transaction(&tx.compute_txid(), None)
            .is_err()
    };
    let replaced = wait_for!(
        std::time::Duration::from_secs(120),
        "the funder to keep only its replaced versions",
        {
            let versions = funder_wallet()
                .read()
                .unwrap()
                .outgoing_funding_txs_for_test();
            (!versions.is_empty() && versions.iter().all(unmined)).then_some(versions)
        }
    );

    let log = world.taker_log_path();
    let mark = std::fs::read_to_string(&log).map_or(0, |text| text.len());

    // Orphan the lowest block that mined a winner, and every block after it.
    world.framework().set_block_gen_paused(true);
    let tip = client.get_block_count().unwrap();
    let beats = |tx: &bitcoin::Transaction, original: &bitcoin::Transaction| {
        tx.compute_txid() != original.compute_txid()
            && tx
                .input
                .iter()
                .any(|input| input.previous_output == original.input[0].previous_output)
    };
    let lowest = (tip.saturating_sub(200)..=tip)
        .find(|height| {
            let block = client
                .get_block(&client.get_block_hash(*height).unwrap())
                .unwrap();
            block
                .txdata
                .iter()
                .any(|tx| replaced.iter().any(|original| beats(tx, original)))
        })
        .expect("a winning version in the chain");
    client
        .invalidate_block(&client.get_block_hash(lowest).unwrap())
        .unwrap();
    // The winners are back in the mempool: outbid them in the miner's view
    // with the replaced versions, which the stall left deprioritised.
    for original in &replaced {
        let _: bool = client
            .call(
                "prioritisetransaction",
                &[
                    serde_json::json!(original.compute_txid().to_string()),
                    serde_json::json!(0),
                    serde_json::json!(1_000_000_000i64),
                ],
            )
            .unwrap();
        client.send_raw_transaction(original).unwrap();
    }
    world.framework().set_block_gen_paused(false);

    wait_until!(
        std::time::Duration::from_secs(180),
        "the funder to recover the swap from its revived funding",
        std::fs::read_to_string(&log).is_ok_and(|text| text[mark..].contains(recovery))
    );
    // The revived version's refund data is still there for recovery.
    assert_eq!(
        funder_wallet()
            .read()
            .unwrap()
            .get_outgoing_swapcoins_count(),
        replaced.len(),
        "the funder keeps every revived version"
    );
    if refunds {
        wait_until!(
            std::time::Duration::from_secs(900),
            every std::time::Duration::from_secs(2),
            "the funder to refund the revived contract by timelock",
            funder_wallet().read().unwrap().get_outgoing_swapcoins_count() == 0
        );
    }
}
