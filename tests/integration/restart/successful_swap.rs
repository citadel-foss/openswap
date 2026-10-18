//! Successful swaps are terminal across maker restarts.
//!
//! A completed maker has already swept every incoming contract and handed its
//! outgoing keys to the taker. Persisting those outgoing swapcoins makes the
//! next startup misclassify the successful swap as abandoned and launch
//! recovery. Exercise the complete protocol, restart both makers from the same
//! wallets, and prove that neither protocol leaves recovery material behind.

use bitcoin::{Amount, Network, OutPoint, Txid};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{MakerBehavior, MakerServer},
    protocol::common_messages::ProtocolVersion,
    taker::SwapParams,
    wallet::Wallet,
};

use crate::test_framework::*;

use std::{collections::HashSet, sync::Arc, time::Duration};

/// The `network` line `init` records in the maker's `config.toml`.
fn recorded_network(maker: &MakerServer) -> Option<String> {
    std::fs::read_to_string(maker.data_dir.join("config.toml"))
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("network = ").map(str::to_string))
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    cases = [
        successful_legacy_swap_stays_complete_after_maker_restart(protocol = ProtocolVersion::Legacy),
        successful_taproot_swap_stays_complete_after_maker_restart(protocol = ProtocolVersion::Taproot),
    ],
)]
fn run_successful_swap_restart(world: &mut World, protocol: ProtocolVersion) {
    let summary = world.takers_mut()[0]
        .prepare(
            SwapParams::new(protocol, Amount::from_sat(500_000), 2)
                .with_tx_count(2)
                .with_required_confirms(1),
        )
        .expect("prepare successful swap");
    world.takers_mut()[0]
        .start(&summary.swap_id)
        .expect("swap must complete successfully");

    // The taker can return just before the maker handler finishes its durable
    // cleanup. Wait for that cleanup, not for an arbitrary sleep.
    wait_until!(
        Duration::from_secs(120),
        format!(
            "the successful {:?} swap to clear the maker swapcoins on disk",
            protocol
        ),
        world.makers().iter().all(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            wallet.get_incoming_swapcoins_count() == 0 && wallet.get_outgoing_swapcoins_count() == 0
        })
    );

    // The first `init` records the wallet's network for readers that
    // can't unlock the wallet.
    for maker in world.makers() {
        assert_eq!(
            recorded_network(maker.inner()).as_deref(),
            Some("\"regtest\"")
        );
    }

    let configs = world
        .makers()
        .iter()
        .map(|maker| {
            let mut config = maker.inner().config.clone();
            // Initialization consumes the configured passphrase.
            config.password = Some("integration-test".to_string());
            // What `MakerServerConfig::new` yields for a stale
            // `network = "signet"`: the wallet must win on restart.
            config.network = Network::Signet;
            config.network_confirmed = true;
            config
        })
        .collect::<Vec<_>>();
    world.drop_takers();
    world.shutdown_makers();
    world.drop_makers();

    world.adopt_makers(
        configs
            .into_iter()
            .map(|config| Arc::new(MakerServer::init(config).unwrap())),
    );
    for maker in world.makers() {
        assert_eq!(maker.inner().config.network, Network::Regtest);
        assert_eq!(
            recorded_network(maker.inner()).as_deref(),
            Some("\"regtest\"")
        );
    }
    world.start_makers_without_sync(120);

    for maker in world.makers() {
        let wallet = maker.inner().wallet.read().unwrap();
        assert_eq!(
            wallet.get_incoming_swapcoins_count(),
            0,
            "restarted maker retained incoming swapcoins for a successful {protocol:?} swap"
        );
        assert_eq!(
            wallet.get_outgoing_swapcoins_count(),
            0,
            "restarted maker retained outgoing swapcoins for a successful {protocol:?} swap"
        );
    }
}

/// What each maker pays in all to sweep its handed-over incoming swapcoins on
/// restart.
const SWEEP_FEE: u64 = 224;

/// The wallet's swept incoming swapcoin UTXOs.
fn swept_outpoints(wallet: &Wallet) -> HashSet<OutPoint> {
    wallet
        .list_swept_incoming_swap_utxos()
        .into_iter()
        .map(|(utxo, _)| OutPoint::new(utxo.txid, utxo.vout))
        .collect()
}

/// The contract txid of every incoming swapcoin any wallet stored, per the log.
fn incoming_contract_txids(log_path: &str) -> HashSet<Txid> {
    std::fs::read_to_string(log_path)
        .unwrap()
        .split("Added incoming swapcoin to wallet store: ")
        .skip(1)
        .map(|rest| rest.split_whitespace().next().unwrap().parse().unwrap())
        .collect()
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [behavior, behavior],
    takers = [Normal],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = protocol, sats = 500_000, makers = 2),
    cases = [
        restart_sweeps_handed_over_incoming_swapcoins(
            protocol = ProtocolVersion::Taproot,
            behavior = MakerBehavior::CloseAfterHandoverResponse,
            incoming_remains = true,
        ),
        restart_removes_spent_outgoing_swapcoins_legacy(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseBeforeSwapFinalization,
            incoming_remains = false,
        ),
        restart_removes_spent_outgoing_swapcoins_taproot(
            protocol = ProtocolVersion::Taproot,
            behavior = MakerBehavior::CloseBeforeSwapFinalization,
            incoming_remains = false,
        ),
    ],
)]
fn run_interrupted_restart(world: &mut World, incoming_remains: bool, params: SwapParams) {
    let summary = world.takers_mut()[0]
        .prepare(params)
        .expect("prepare interrupted swap");
    world.takers_mut()[0]
        .start(&summary.swap_id)
        .expect("handover must complete before maker interruption");

    wait_until!(
        Duration::from_secs(120),
        "the test hook to leave the expected persisted swapcoins",
        !world.makers().iter().any(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            wallet.get_outgoing_swapcoins_count() == 0
                || incoming_remains != (wallet.get_incoming_swapcoins_count() != 0)
        })
    );

    // Record what each maker holds before the restart, so the restart must
    // sweep its incoming swapcoins into the wallet, not merely forget them.
    world.sync_makers();
    let before = world
        .makers()
        .iter()
        .map(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            (
                wallet.get_incoming_swapcoins_count(),
                swept_outpoints(&wallet),
                wallet.get_balances().unwrap().spendable,
            )
        })
        .collect::<Vec<_>>();
    // A Taproot incoming swapcoin is not a wallet UTXO, so its contract txid
    // comes from the log. The taker's own incoming coins land here too.
    let contract_txids = incoming_contract_txids(&world.taker_log_path());

    let configs = world
        .makers()
        .iter()
        .map(|maker| {
            let mut config = maker.inner().config.clone();
            config.password = Some("integration-test".to_string());
            config
        })
        .collect::<Vec<_>>();
    world.drop_takers();
    world.shutdown_makers();
    world.drop_makers();

    world.adopt_makers(
        configs
            .into_iter()
            .map(|config| Arc::new(MakerServer::init(config).unwrap())),
    );
    world.start_makers_without_sync(120);

    wait_until!(
        Duration::from_secs(120),
        "the restart to finish the interrupted successful swap",
        world.makers().iter().all(|maker| {
            let wallet = maker.inner().wallet.read().unwrap();
            wallet.get_incoming_swapcoins_count() == 0 && wallet.get_outgoing_swapcoins_count() == 0
        })
    );

    world.mine(1);
    world.sync_makers();
    let client = &world.bitcoind().client;
    for (i, (maker, (incoming, swept_before, spendable))) in
        world.makers().iter().zip(before).enumerate()
    {
        assert_eq!(
            incoming != 0,
            incoming_remains,
            "maker {i}: held {incoming} incoming swapcoins before the restart"
        );
        // The new swept coins are the outputs of the restart's sweeps.
        let wallet = maker.inner().wallet.read().unwrap();
        let swept = wallet
            .list_swept_incoming_swap_utxos()
            .into_iter()
            .filter(|(utxo, _)| !swept_before.contains(&OutPoint::new(utxo.txid, utxo.vout)))
            .collect::<Vec<_>>();
        let gain = wallet
            .get_balances()
            .unwrap()
            .spendable
            .checked_sub(spendable)
            .expect("the restart must not lose spendable funds");
        drop(wallet);
        let sweep_txids = swept
            .iter()
            .map(|(utxo, _)| utxo.txid)
            .collect::<HashSet<_>>();
        let mut spent = HashSet::new();
        let mut spent_value = Amount::ZERO;
        for txid in &sweep_txids {
            let info = client.get_raw_transaction_info(txid, None).unwrap();
            assert!(
                info.confirmations.is_some_and(|c| c > 0),
                "maker {}: sweep {} must be confirmed",
                i,
                txid
            );
            for input in &info.transaction().unwrap().input {
                let prev = input.previous_output;
                assert!(
                    contract_txids.contains(&prev.txid),
                    "maker {}: sweep {} spends {}, not an incoming contract",
                    i,
                    txid,
                    prev
                );
                spent_value += client.get_raw_transaction(&prev.txid, None).unwrap().output
                    [prev.vout as usize]
                    .value;
                spent.insert(prev);
            }
        }
        // One confirmed spend per incoming swapcoin, and the sweeps pay the
        // maker everything but their own fee.
        assert_eq!(
            spent.len(),
            incoming,
            "maker {i}: the sweeps spend {spent:?}, expected {incoming} incoming contracts"
        );
        assert_eq!(
            gain,
            swept.iter().map(|(utxo, _)| utxo.amount).sum::<Amount>(),
            "maker {i}: the spendable gain must be exactly the swept coins"
        );
        assert_eq!(
            spent_value - gain,
            Amount::from_sat(SWEEP_FEE * incoming_remains as u64),
            "maker {i}: spendable gained {gain} from {spent_value} of incoming swapcoins"
        );
    }
}
