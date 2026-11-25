//! A maker restarting with an unconfirmed bond: it adopts the bond instead of
//! locking a second one, advertises a live bond meanwhile instead of waiting,
//! and rebroadcasts the pending one when it fell out of the mempool, on Bitcoin
//! Core and on Electrum.

use bitcoin::{absolute::LockTime, consensus::encode::serialize_hex, Amount, Txid};
use bitcoind::bitcoincore_rpc::{Auth, RpcApi};
use openswap::{
    maker::{start_server, MakerServer},
    taker::TakerBehavior,
    utill::MIN_RELAY_FEE_RATE,
    wallet::{AddressType, CoreRpcConfig, ElectrumConfig},
};

use crate::test_framework::*;

use std::{
    fs,
    path::PathBuf,
    sync::{atomic::Ordering::Relaxed, Arc},
    thread,
    time::{Duration, Instant},
};

use super::{assert_single_adopted_bond, maker_restart_config};

// ---- Shared scaffolding for the maker-restart fidelity tests ----

/// Wait for run 1's bond-broadcast log line and parse the txid out of it.
fn wait_for_bond_broadcast(log_path: &str) -> Txid {
    wait_for_log(
        log_path,
        "Fidelity bond broadcast, waiting for confirmation",
        Duration::from_secs(120),
    );
    let line = std::fs::read_to_string(log_path)
        .unwrap()
        .lines()
        .find(|l| l.contains("Fidelity bond broadcast, waiting for confirmation"))
        .expect("run 1 must log the bond broadcast line")
        .to_string();
    line.rsplit(": ")
        .next()
        .and_then(|t| t.trim().parse().ok())
        .unwrap_or_else(|| panic!("could not parse bond txid from log line: {}", line))
}

/// Spawn a replacement bitcoind on an existing datadir. The old node releases
/// the datadir lock and ZMQ ports asynchronously, so retry until the
/// replacement can take them over.
fn spawn_replacement_bitcoind(staticdir: PathBuf, extra_args: &[&str]) -> bitcoind::BitcoinD {
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1");
    conf.args.push("-deprecatedrpc=warnings");
    conf.args.extend_from_slice(extra_args);
    conf.p2p = bitcoind::P2P::Yes;
    conf.staticdir = Some(staticdir);

    let exe_path = bitcoind::exe_path().unwrap();
    let mut attempt = 0;
    loop {
        match bitcoind::BitcoinD::with_conf(exe_path.clone(), &conf) {
            Ok(node) => break node,
            Err(e) if attempt < 30 => {
                attempt += 1;
                log::warn!("replacement bitcoind not ready yet ({}); retrying", e);
                thread::sleep(Duration::from_secs(2));
            }
            Err(e) => panic!("replacement bitcoind failed to start: {}", e),
        }
    }
}

/// Stops the node and starts a fresh one on its datadir with an empty mempool
/// and `extra_args`, returning it and a restart config for `maker` that points
/// at it.
fn evict_mempool_and_restart_node(
    world: &World,
    maker: &MakerServer,
    extra_args: &[&str],
) -> (bitcoind::BitcoinD, openswap::maker::MakerServerConfig) {
    let (wallet_name, zmq_addr) = match &maker.config.backend {
        openswap::wallet::BackendConfig::CoreRpc(cfg) => {
            (cfg.wallet_name.clone(), cfg.zmq_addr.clone())
        }
        _ => panic!("expected a CoreRpc backend"),
    };

    // Clean stop writes mempool.dat; the replacement node must not load it.
    let _ = world.framework().bitcoind.client.stop();

    // `-persistmempool=0` is the eviction: the mempool is not reloaded from
    // mempool.dat. `-walletbroadcast=0` stops the node wallet resurrecting
    // the evicted tx: Core rebroadcasts the wallet's unconfirmed
    // transactions on startup, which would put the bond right back.
    let raw_tx = format!("-zmqpubrawtx={zmq_addr}");
    let block_hash = format!("-zmqpubrawblock={zmq_addr}");
    let mut args = vec![
        "-persistmempool=0",
        "-walletbroadcast=0",
        raw_tx.as_str(),
        block_hash.as_str(),
    ];
    args.extend_from_slice(extra_args);
    let new_bitcoind = spawn_replacement_bitcoind(world.temp_dir().join(".bitcoin"), &args);

    // Point the backend at the replacement node.
    let mut restart_config = maker_restart_config(maker);
    restart_config.backend = openswap::wallet::BackendConfig::CoreRpc(CoreRpcConfig {
        url: new_bitcoind.rpc_url().split_at(7).1.to_string(),
        auth: Auth::CookieFile(new_bitcoind.params.cookie_file.clone()),
        wallet_name,
        zmq_addr,
    });
    (new_bitcoind, restart_config)
}

/// Regression test for <https://github.com/citadel-foss/openswap/issues/990>
///
/// A maker stopped after broadcasting its fidelity bond but before it confirms
/// restarts with a pending bond (`conf_height: None`) in the wallet. The
/// restart must adopt that bond - wait for its confirmation and use it -
/// instead of silently discarding it and creating a second bond, which would
/// doubly lock funds.
///
/// The behaviour is pinned on exact log lines:
/// - run 1 takes the create branch once and broadcasts the bond,
/// - run 2 must log the adopt-a-pending-bond lines and take the
///   existing-bond branch ("Highest bond at outpoint"),
/// - across both runs "No active Fidelity Bonds found. Creating one." appears
///   exactly once, and "Successfully created fidelity bond" never appears
///   (it only logs when a new bond is created, which the restart must not do).
#[world_test(
    makers = 1,
    takers = taker_behaviors,
    cases = [
        // A taker runs alongside, as in the original Core test; nothing reads it.
        unconfirmed_bond_not_duplicated(
            backend = BitcoindBackend,
            taker_behaviors = [TakerBehavior::Normal],
        ),
        /// Electrum variant: a maker that shuts down with an unconfirmed bond must
        /// adopt it on restart instead of creating a second one, this time over the
        /// Electrum backend.
        unconfirmed_bond_not_duplicated_electrum(
            backend = ElectrumBackend,
            taker_behaviors = [],
        ),
    ],
)]
fn run_unconfirmed_fidelity_bond_not_duplicated(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner();
    let log_path = world.taker_log_path();

    world.fund_makers(1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    // Pause the background miner so the bond tx cannot confirm while run 1 is up.
    world.framework().set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        // The shutdown below interrupts setup mid-wait and surfaces as an
        // error; that partial run is the point of the test, so don't unwrap.
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);

    // Pin the preconditions: the bond tx is still unconfirmed on-chain ...
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must still be unconfirmed for this test to mean anything",
        bond_txid
    );

    // ... and the create branch ran exactly once.
    assert_log!(world; { count("No active Fidelity Bonds found. Creating one.") == 1 });

    // Stop the maker while the bond is still unconfirmed.
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Run 2: the restart must adopt the pending bond, not create a new one -----

    // Resume mining so the restarted maker can wait out the confirmation.
    world.framework().set_block_gen_paused(false);

    let restarted = Arc::new(MakerServer::init(maker_restart_config(maker)).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    // ----- Assertions on the log of both runs -----
    assert_log!(world; {
        // The restart detected the pending bond and waited for it ...
        has "waiting for confirmation instead of creating a new one",
        has "confirmed at height",
        // ... then took the existing-bond branch with the adopted bond.
        has "Highest bond at outpoint",
        // Never the create branch again: that would lock funds twice.
        count("No active Fidelity Bonds found. Creating one.") == 1,
        lacks "Successfully created fidelity bond",
    });
}

/// A maker restarting with a live bond and a pending one advertises the live
/// bond at once: the pending bond gets one check, not an endless wait.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn live_bond_is_advertised_while_another_is_pending(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner();

    world.fund_makers(2, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: the maker confirms its first bond -----
    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });
    wait_for_makers_setup(std::slice::from_ref(maker), 120);
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();
    let live_outpoint = {
        let wallet = maker.wallet.read().unwrap();
        let bonds = wallet.get_fidelity_bonds();
        assert_eq!(bonds.len(), 1, "run 1 must create exactly one bond");
        bonds[0].outpoint()
    };

    // ----- A second bond is broadcast and kept unconfirmed -----
    world.framework().set_block_gen_paused(true);
    let locktime = bitcoind.client.get_block_count().unwrap() as u32 + 950;
    let (_, pending_txid) = maker
        .wallet
        .write()
        .unwrap()
        .create_fidelity(
            Amount::from_sat(5_000_000),
            LockTime::from_height(locktime).unwrap(),
            None,
            MIN_RELAY_FEE_RATE,
            AddressType::P2TR,
        )
        .unwrap();

    // ----- Run 2: setup completes while the second bond is still pending -----
    // Run 1 already published the live bond; only run 2's publication counts.
    let log_path = world.taker_log_path();
    let mark = log_mark(&log_path);
    let restarted = Arc::new(MakerServer::init(maker_restart_config(maker)).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    // Read before stopping, assert after: a failed assert must not leave the
    // restarted maker running.
    let still_pending = bitcoind.client.get_mempool_entry(&pending_txid).is_ok();
    // The restart must actually publish the live bond, not just log the intent:
    // a relay has to accept the event built right after an intent line. Every
    // attempt counts, since a failed first one is retried by the periodic
    // rebroadcast (every 30s) with a fresh event ID.
    let published = format!("Publishing fidelity bond to Nostr | outpoint={live_outpoint} ");
    let deadline = Instant::now() + Duration::from_secs(120);
    let published_in_run_2 = loop {
        let log = fs::read_to_string(&log_path).unwrap_or_default();
        let accepted = log.get(mark as usize..).is_some_and(|new| {
            new.match_indices(&published).any(|(intent, _)| {
                let after = &new[intent..];
                let Some(event_id) = after
                    .split("Nostr event built | event_id=")
                    .nth(1)
                    .and_then(|rest| rest.split_whitespace().next())
                else {
                    return false;
                };
                after.lines().any(|l| {
                    l.contains("Nostr relay accepted event")
                        && l.contains(&format!("event_id={event_id}"))
                })
            })
        });
        if accepted {
            break true;
        }
        if Instant::now() > deadline {
            break false;
        }
        thread::sleep(POLL);
    };
    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();
    world.framework().set_block_gen_paused(false);

    assert!(
        still_pending,
        "the second bond must still be unconfirmed when setup completes"
    );
    assert!(
        published_in_run_2,
        "the restarted maker must publish its live bond {} to Nostr",
        live_outpoint
    );
    // The restart advertised the live bond instead of waiting, and never the
    // pending one.
    assert_log!(log_path, since mark; {
        has format!(
            "Fidelity bond {pending_txid} still unconfirmed; advertising the live bond meanwhile"
        ),
        lacks format!("Publishing fidelity bond to Nostr | outpoint={pending_txid}:"),
    });
}

/// Eviction path: if the unconfirmed bond tx falls out of the mempool while
/// the maker is offline, the restart must rebroadcast the stored raw
/// transaction — keeping the original txid and creating no second bond.
///
/// Regtest has no "evict from mempool" RPC, so the eviction is simulated by
/// restarting bitcoind with `-persistmempool=0` on the same datadir: the
/// chain (and every confirmed coin) survives, the mempool does not.
///
/// Anchored to `unconfirmed_bond_not_duplicated`, which covers
/// the mempool-present early return; this test covers the rebroadcast branch
/// of `FidelityBond::ensure_broadcast`.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn evicted_bond_rebroadcast_on_restart(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner();
    let log_path = world.taker_log_path();

    world.fund_makers(1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    // Pause the background miner so the bond tx cannot confirm while run 1 is up.
    world.framework().set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must be in the mempool before the eviction",
        bond_txid
    );

    // Stop the maker while the bond is still unconfirmed.
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Evict the bond: restart bitcoind without mempool persistence -----

    let (new_bitcoind, restart_config) = evict_mempool_and_restart_node(world, maker, &[]);

    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_err(),
        "bond tx {} must be evicted after the mempool reset",
        bond_txid
    );

    // ----- Run 2: the restart must rebroadcast the stored bond tx -----

    let restarted = Arc::new(MakerServer::init(restart_config).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    // The restart must detect the eviction and rebroadcast the stored raw
    // transaction, which reproduces the original txid.
    wait_logged!(
        world,
        "evicted from mempool?); rebroadcasting",
        Duration::from_secs(120)
    );
    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "rebroadcast must put the original bond tx {} back in the mempool",
        bond_txid
    );

    // Confirm the rebroadcast tx so finalization completes (the background
    // miner stays paused: it talks to the dead node).
    generate_blocks(&new_bitcoind, 1);
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    // ----- Assertions on the log of both runs -----
    assert_log!(world; {
        // The restart took the rebroadcast branch for the evicted bond ...
        has "not visible to the backend (evicted from mempool?); rebroadcasting",
        has "confirmed at height",
        // ... and never the create branch again: that would lock funds twice.
        count("No active Fidelity Bonds found. Creating one.") == 1,
        lacks "Successfully created fidelity bond",
    });

    // Teardown: stop the replacement node first; the framework's original
    // node is already down (TestFramework::stop tolerates that).
    let _ = new_bitcoind.client.stop();
}

/// A maker restarted on a node that refuses its stored bond.
struct RefusedRestart {
    node: bitcoind::BitcoinD,
    maker: Arc<MakerServer>,
    thread: thread::JoinHandle<()>,
    /// The refused bond's transaction.
    bond: bitcoin::Transaction,
}

impl RefusedRestart {
    fn stop(self) {
        self.maker.shutdown.store(true, Relaxed);
        let _ = self.thread.join();
        let _ = self.node.client.stop();
    }
}

/// Run 1 broadcasts a bond at 1 sat/vB and stops before it confirms. The node
/// then restarts with an empty mempool and a 5 sat/vB relay minimum, so it
/// refuses the stored bond, and the maker restarts funding bonds at
/// `fidelity_feerate`.
fn restart_with_refused_bond(world: &World, fidelity_feerate: f64) -> RefusedRestart {
    let maker = world.makers()[0].inner();
    // Spare coins, so a replacement that ignored the refused bond could
    // fund itself from unrelated ones.
    world.fund_makers(4, Amount::ONE_BTC, AddressType::P2TR);

    world.framework().set_block_gen_paused(true);
    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });
    let bond_txid = wait_for_bond_broadcast(&world.taker_log_path());
    let bond = world
        .bitcoind()
        .client
        .get_raw_transaction(&bond_txid, None)
        .unwrap();
    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    let (node, mut restart_config) =
        evict_mempool_and_restart_node(world, maker, &["-minrelaytxfee=0.00005"]);
    restart_config.fidelity_feerate = fidelity_feerate;
    let restarted = Arc::new(MakerServer::init(restart_config).unwrap());
    let restarted_clone = restarted.clone();
    let thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });
    RefusedRestart {
        node,
        maker: restarted,
        thread,
        bond,
    }
}

/// Mines `tx` straight into a block: the node's relay rules don't apply.
fn mine_tx(node: &bitcoind::BitcoinD, tx: &bitcoin::Transaction) {
    let miner = node
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked();
    let _: serde_json::Value = node
        .client
        .call(
            "generateblock",
            &[
                serde_json::json!(miner.to_string()),
                serde_json::json!([serialize_hex(tx)]),
            ],
        )
        .unwrap();
}

/// Polls the log until `expected` appears `times` times.
fn wait_for_log_count(log_path: &str, expected: &str, times: usize, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while fs::read_to_string(log_path)
        .map(|log| log.matches(expected).count())
        .unwrap_or(0)
        < times
    {
        assert!(
            Instant::now() < deadline,
            "'{}' not logged {} times",
            expected,
            times
        );
        thread::sleep(Duration::from_millis(500));
    }
}

/// The first tx to reach `node`'s mempool.
fn wait_for_mempool_tx(node: &bitcoind::BitcoinD) -> Txid {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(txid) = node.client.get_raw_mempool().unwrap().first() {
            return *txid;
        }
        assert!(
            Instant::now() < deadline,
            "no replacement bond was broadcast"
        );
        thread::sleep(Duration::from_millis(500));
    }
}

/// A bond the node refuses on restart is skipped, and the bond funded in its
/// place spends one of its coins: the refused tx may still confirm from a
/// peer's mempool, and the two must never both lock funds.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn refused_bond_is_replaced_by_a_conflicting_bond(world: &mut World) {
    let run = restart_with_refused_bond(world, 10.0);
    let bond_txid = run.bond.compute_txid();

    let replacement_txid = wait_for_mempool_tx(&run.node);
    assert_ne!(replacement_txid, bond_txid);
    let replacement = run
        .node
        .client
        .get_raw_transaction(&replacement_txid, None)
        .unwrap();
    assert!(
        replacement.input.iter().any(|input| run
            .bond
            .input
            .iter()
            .any(|spent| spent.previous_output == input.previous_output)),
        "replacement {} must spend a coin of the refused bond {}",
        replacement_txid,
        bond_txid
    );

    generate_blocks(&run.node, 1);
    wait_for_makers_setup(std::slice::from_ref(&run.maker), 120);
    {
        let wallet = run.maker.wallet.read().unwrap();
        let index = wallet.get_highest_fidelity_index().unwrap().unwrap();
        let bond = wallet
            .get_fidelity_bonds()
            .iter()
            .find(|bond| bond.bond_index == index)
            .unwrap();
        assert_eq!(bond.outpoint().txid, replacement_txid);
    }
    run.stop();

    assert_log!(world; {
        has "cannot be broadcast",
        has "held by refused bonds",
    });
}

/// A refused bond that confirms while setup waits to fund its replacement is
/// adopted, and no second bond is funded.
///
/// On Core the first planning pass waits for the wallet to list the refused
/// bond's coins again. The bond is mined during that wait, so the next pass
/// finds it known.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn refused_bond_confirming_before_its_replacement_is_adopted(world: &mut World) {
    let run = restart_with_refused_bond(world, 10.0);
    let bond_txid = run.bond.compute_txid();

    wait_logged!(
        world,
        "Not creating a fidelity bond yet",
        Duration::from_secs(120)
    );
    mine_tx(&run.node, &run.bond);
    wait_for_makers_setup(std::slice::from_ref(&run.maker), 120);
    assert_single_adopted_bond(&run.maker, bond_txid);
    run.stop();

    assert_log!(world; {
        has "cannot be broadcast",
        has "adopting it instead of creating one",
        lacks "held by refused bonds",
        // Run 1's bond only; the trailing ": " skips the test's own wait line.
        count("Fidelity bond broadcast, waiting for confirmation: ") == 1,
    });
}

/// A refused bond that confirms after its replacement went out evicts the
/// replacement. Setup starts over instead of stopping, adopts the refused
/// bond, and still lists its bonds with the dead replacement's record kept.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn refused_bond_confirming_after_its_replacement_is_adopted(world: &mut World) {
    let run = restart_with_refused_bond(world, 10.0);
    let bond_txid = run.bond.compute_txid();

    let replacement_txid = wait_for_mempool_tx(&run.node);
    assert_ne!(replacement_txid, bond_txid);
    // A peer mines the refused bond: the conflicting replacement leaves the
    // mempool, and its rebroadcast is refused.
    mine_tx(&run.node, &run.bond);
    assert!(run.node.client.get_raw_mempool().unwrap().is_empty());

    wait_for_makers_setup(std::slice::from_ref(&run.maker), 180);
    assert!(!run.thread.is_finished(), "setup must not stop");
    {
        let wallet = run.maker.wallet.read().unwrap();
        let index = wallet.get_highest_fidelity_index().unwrap().unwrap();
        let bond = wallet
            .get_fidelity_bonds()
            .iter()
            .find(|bond| bond.bond_index == index)
            .unwrap();
        assert_eq!(bond.outpoint().txid, bond_txid, "the mined bond is adopted");

        let listing: serde_json::Value =
            serde_json::from_str(&wallet.display_fidelity_bonds().unwrap()).unwrap();
        let status = |txid: Txid| {
            listing
                .as_array()
                .unwrap()
                .iter()
                .find(|bond| {
                    bond["outpoint"]
                        .as_str()
                        .unwrap()
                        .starts_with(&txid.to_string())
                })
                .map(|bond| bond["status"].clone())
        };
        assert_eq!(status(bond_txid), Some("Live".into()));
        assert_eq!(status(replacement_txid), Some("Unconfirmed".into()));
    }
    run.stop();

    assert_log!(world; {
        has "held by refused bonds",
        has "was refused while awaiting confirmation",
        lacks "Fidelity Bond Creation failed",
    });
}

/// A replacement the node refuses does not stop setup: it starts over with
/// the same deposit address, and adopts the original bond once that confirms.
///
/// The maker funds bonds at 2 sat/vB, below the node's 5 sat/vB minimum, so
/// every replacement is refused.
#[world_test(
    backend = BitcoindBackend,
    makers = 1,
)]
fn refused_replacement_restarts_setup_instead_of_stopping(world: &mut World) {
    let run = restart_with_refused_bond(world, 2.0);
    let bond_txid = run.bond.compute_txid();

    let passes = |times| {
        wait_for_log_count(
            &world.taker_log_path(),
            "Checking the refused bonds again",
            times,
            Duration::from_secs(180),
        );
        *run.maker.wallet.read().unwrap().get_external_index()
    };
    let after_first = passes(1);
    let after_second = passes(2);
    assert!(!run.thread.is_finished(), "setup must not stop");
    // Every pass asks for funds at the same deposit address.
    assert_eq!(
        after_first, after_second,
        "a new setup pass must not allocate another deposit address"
    );

    mine_tx(&run.node, &run.bond);
    wait_for_makers_setup(std::slice::from_ref(&run.maker), 120);
    assert_single_adopted_bond(&run.maker, bond_txid);
    run.stop();

    assert_log!(world; {
        lacks "Fidelity Bond Creation failed",
    });
}

/// Electrum variant of `evicted_bond_rebroadcast_on_restart`:
/// the unconfirmed bond is evicted while the maker is offline (bitcoind
/// restarted with `-persistmempool=0`), and the restart must rebroadcast the
/// stored raw transaction over Electrum, keeping the original txid.
///
/// electrs follows bitcoind's mempool, so it must be restarted against the
/// replacement node as well; its mempool view is in-memory, so a fresh
/// electrs reflects the empty mempool immediately.
#[world_test(
    backend = ElectrumBackend,
    makers = 1,
)]
fn evicted_bond_rebroadcast_on_restart_electrum(world: &mut World) {
    let bitcoind = world.bitcoind();
    let maker = world.makers()[0].inner();
    let log_path = world.taker_log_path();

    world.fund_makers(1, Amount::ONE_BTC, AddressType::P2TR);

    // ----- Run 1: maker broadcasts a bond, then stops before it confirms -----

    world.framework().set_block_gen_paused(true);

    let maker_clone = maker.clone();
    let maker_thread = thread::spawn(move || {
        let _ = start_server(maker_clone);
    });

    let bond_txid = wait_for_bond_broadcast(&log_path);
    assert!(
        bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "bond tx {} must be in the mempool before the eviction",
        bond_txid
    );

    maker.shutdown.store(true, Relaxed);
    let _ = maker_thread.join();

    // ----- Evict the bond: restart bitcoind without mempool persistence -----

    let electrum_cfg = match &maker.config.backend {
        openswap::wallet::BackendConfig::Electrum(cfg) => cfg.clone(),
        _ => panic!("expected an Electrum backend"),
    };

    // electrs polls bitcoind, so it goes down before the node does.
    drop(world.framework().electrsd.lock().unwrap().take());
    // Clean stop writes mempool.dat; the replacement node must not load it.
    let _ = world.framework().bitcoind.client.stop();

    // `-persistmempool=0` is the eviction: the mempool is not reloaded from
    // mempool.dat. (No `-walletbroadcast=0` needed here: with the Electrum
    // backend no node-side wallet tracks the bond tx. No ZMQ args either:
    // electrs talks to the node over RPC/p2p only.)
    let new_bitcoind =
        spawn_replacement_bitcoind(world.temp_dir().join(".bitcoin"), &["-persistmempool=0"]);

    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_err(),
        "bond tx {} must be evicted after the mempool reset",
        bond_txid
    );

    // Fresh electrs against the replacement node (same db dir: the indexed
    // chain survives, the mempool view is rebuilt empty).
    thread::sleep(Duration::from_secs(2));
    let new_electrsd = init_electrsd(&new_bitcoind, world.temp_dir());
    let new_electrum_cfg = ElectrumConfig {
        url: format!("tcp://{}", new_electrsd.electrum_url),
        ..electrum_cfg
    };
    wait_for_electrs_tip(&new_bitcoind, &new_electrsd, &new_electrum_cfg);

    // ----- Run 2: the restart must rebroadcast the stored bond tx -----

    // Point the backend at the replacement electrs.
    let mut restart_config = maker_restart_config(maker);
    restart_config.backend = openswap::wallet::BackendConfig::Electrum(new_electrum_cfg.clone());

    let restarted = Arc::new(MakerServer::init(restart_config).unwrap());
    let restarted_clone = restarted.clone();
    let restarted_thread = thread::spawn(move || {
        let _ = start_server(restarted_clone);
    });

    wait_logged!(
        world,
        "evicted from mempool?); rebroadcasting",
        Duration::from_secs(120)
    );
    assert!(
        new_bitcoind.client.get_mempool_entry(&bond_txid).is_ok(),
        "rebroadcast must put the original bond tx {} back in the mempool",
        bond_txid
    );

    // Confirm the rebroadcast tx so finalization completes, and nudge electrs
    // to index the block (the background miner stays paused: it talks to the
    // dead node).
    generate_blocks(&new_bitcoind, 1);
    let _ = new_electrsd.trigger();
    wait_for_makers_setup(std::slice::from_ref(&restarted), 120);

    assert_single_adopted_bond(&restarted, bond_txid);

    restarted.shutdown.store(true, Relaxed);
    let _ = restarted_thread.join();

    assert_log!(world; {
        // The restart took the rebroadcast branch for the evicted bond ...
        has "not visible to the backend (evicted from mempool?); rebroadcasting",
        has "confirmed at height",
        // ... and never the create branch again: that would lock funds twice.
        count("No active Fidelity Bonds found. Creating one.") == 1,
        lacks "Successfully created fidelity bond",
    });

    // Teardown: electrs first (its datadir sits inside temp_dir), then the
    // replacement node; the framework's original node is already down.
    drop(new_electrsd);
    let _ = new_bitcoind.client.stop();
}
