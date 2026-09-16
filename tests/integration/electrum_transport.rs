//! Transport-level behaviour of the Electrum backend: the connection is held
//! across calls, a dropped connection is bridged by reconnecting, and an
//! unreachable server fails loudly instead of hanging.
//!
//! A dying Tor circuit is a live server behind a broken socket, so these drive a
//! local TCP forwarder rather than killing `electrsd`. That also avoids needing a
//! fixed electrs port, which `electrsd::Conf` does not offer.

use std::{
    io,
    net::{TcpListener, TcpStream},
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
};

use bitcoin::hashes::Hash;
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::wallet::{Blockchain, Electrum, ElectrumConfig, WalletError};

use super::test_framework::{
    generate_blocks, init_bitcoind, init_electrsd, send_to_address, wait_for_electrs_tip,
};

/// A TCP forwarder sitting between the client and electrs, so a test can break
/// the socket without touching the server.
struct Forwarder {
    port: u16,
    /// Client-side halves of live connections, kept so they can be shut down.
    live: Arc<Mutex<Vec<TcpStream>>>,
    /// When set, new connections are accepted then closed straight away. Models a
    /// proxy that is up but cannot reach the far side.
    refuse: Arc<AtomicBool>,
    accepted: Arc<(Mutex<u64>, Condvar)>,
}

impl Forwarder {
    fn start(target: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind forwarder");
        let port = listener.local_addr().unwrap().port();
        let live: Arc<Mutex<Vec<TcpStream>>> = Arc::new(Mutex::new(Vec::new()));
        let refuse = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new((Mutex::new(0), Condvar::new()));

        let (live_c, refuse_c, accepted_c) = (live.clone(), refuse.clone(), accepted.clone());
        thread::spawn(move || {
            for incoming in listener.incoming() {
                let Ok(client) = incoming else { continue };
                let (count, changed) = &*accepted_c;
                *count.lock().unwrap() += 1;
                changed.notify_all();
                if refuse_c.load(Ordering::SeqCst) {
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    continue;
                }
                let Ok(server) = TcpStream::connect(&target) else {
                    let _ = client.shutdown(std::net::Shutdown::Both);
                    continue;
                };
                live_c
                    .lock()
                    .unwrap()
                    .push(client.try_clone().expect("clone client"));

                let mut c_read = client.try_clone().expect("clone client");
                let mut c_write = client;
                let mut s_read = server.try_clone().expect("clone server");
                let mut s_write = server;
                thread::spawn(move || {
                    let _ = io::copy(&mut c_read, &mut s_write);
                });
                thread::spawn(move || {
                    let _ = io::copy(&mut s_read, &mut c_write);
                });
            }
        });

        Self {
            port,
            live,
            refuse,
            accepted,
        }
    }

    fn url(&self) -> String {
        format!("tcp://127.0.0.1:{}", self.port)
    }

    /// Break every live connection, leaving electrs itself untouched.
    fn drop_connections(&self) {
        let mut live = self.live.lock().unwrap();
        for stream in live.drain(..) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
    }

    /// Stop forwarding, so reconnects connect but immediately die.
    fn refuse_forwarding(&self) {
        self.refuse.store(true, Ordering::SeqCst);
        self.drop_connections();
    }

    /// Returns accepted connections so the retry test can wait for new work.
    fn connection_count(&self) -> u64 {
        *self.accepted.0.lock().unwrap()
    }

    /// Waits for a retry connection instead of relying on a timing sleep.
    fn wait_for_connection_after(&self, previous: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        let (count, changed) = &*self.accepted;
        let mut count = count.lock().unwrap();
        while *count <= previous {
            let remaining = deadline
                .checked_duration_since(std::time::Instant::now())
                .expect("electrum did not attempt a reconnect");
            let (next, timeout) = changed.wait_timeout(count, remaining).unwrap();
            count = next;
            assert!(!timeout.timed_out(), "electrum did not attempt a reconnect");
        }
    }
}

struct Setup {
    bitcoind: BitcoinD,
    _electrsd: electrsd::ElectrsD,
    forwarder: Forwarder,
    root_dir: std::path::PathBuf,
}

fn setup(name: &str) -> Setup {
    let root_dir = std::env::temp_dir().join(format!("openswap-transport-{}", std::process::id()));
    let temp_dir = root_dir.join(name);
    std::fs::create_dir_all(&temp_dir).unwrap();

    let bitcoind = init_bitcoind(&temp_dir, "tcp://127.0.0.1:48332".to_string())
        .expect("bitcoind failed to start");
    let electrsd = init_electrsd(&bitcoind, &temp_dir);
    generate_blocks(&bitcoind, 101);

    let direct = ElectrumConfig {
        url: format!("tcp://{}", electrsd.electrum_url),
        ..Default::default()
    };
    wait_for_electrs_tip(&bitcoind, &electrsd, &direct);

    let forwarder = Forwarder::start(electrsd.electrum_url.clone());
    Setup {
        bitcoind,
        _electrsd: electrsd,
        forwarder,
        root_dir,
    }
}

/// A stand-in watched outpoint. Only its identity matters to the refcount.
fn dummy_watch(vout: u32) -> bitcoin::OutPoint {
    bitcoin::OutPoint {
        txid: bitcoin::Txid::all_zeros(),
        vout,
    }
}

fn cleanup(root_dir: &Path) {
    if root_dir.exists() {
        let _ = std::fs::remove_dir_all(root_dir);
    }
}

/// The connection is held: many calls of the kinds a sync and a watch loop make
/// must not rebuild the transport even once.
#[test]
fn held_connection_is_reused_across_calls() {
    let s = setup("held");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    let electrum = Electrum::new(&cfg).expect("connect via forwarder");
    assert_eq!(
        electrum.reconnect_count(),
        0,
        "connect should not reconnect"
    );

    let spk = bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([7u8; 20]));
    electrum.watch_script(&spk, None);
    electrum
        .subscribe_script(&spk, dummy_watch(0))
        .expect("subscribe");

    for _ in 0..20 {
        electrum.get_block_count().expect("tip");
        electrum
            .list_unspent(Some(0), Some(9999999))
            .expect("utxos");
        let _ = electrum.poll_event();
    }

    assert_eq!(
        electrum.reconnect_count(),
        0,
        "held connection was rebuilt during ordinary sync/watch calls"
    );

    drop(electrum);
    cleanup(&s.root_dir);
}

/// Wait for electrs to index up to bitcoind's tip, polling over the connection
/// we already hold. A fresh connect fails outright while electrs is mid-index.
fn wait_for_tip(s: &Setup, electrum: &Electrum) {
    let expected = s.bitcoind.client.get_block_count().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let _ = s._electrsd.trigger();
        if electrum
            .get_block_count()
            .map(|tip| tip >= expected)
            .unwrap_or(false)
        {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "electrs did not reach tip {} within 60s",
            expected
        );
        thread::sleep(std::time::Duration::from_millis(200));
    }
}

/// A second confirmed deposit to the same script must not read as a spend of
/// the outpoint; only a confirmed tx whose input consumes it counts.
#[test]
fn confirmed_spend_requires_an_input_consuming_the_outpoint() {
    let s = setup("spend-check");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    let electrum = Electrum::new(&cfg).expect("connect via forwarder");

    let addr = s
        .bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let txid = send_to_address(&s.bitcoind, &addr, bitcoin::Amount::from_btc(1.0).unwrap());
    generate_blocks(&s.bitcoind, 1);
    wait_for_tip(&s, &electrum);

    let spk = addr.script_pubkey();
    let tx = electrum.get_raw_transaction(&txid, None).expect("fetch tx");
    let vout = tx
        .output
        .iter()
        .position(|o| o.script_pubkey == spk)
        .expect("output to our address") as u32;
    let outpoint = bitcoin::OutPoint { txid, vout };

    // Lock the outpoint before the second deposit, else coin selection may
    // fund that deposit from it and the tx really would spend it.
    s.bitcoind.client.lock_unspent(&[outpoint]).expect("lock");
    send_to_address(&s.bitcoind, &addr, bitcoin::Amount::from_sat(10_000));
    generate_blocks(&s.bitcoind, 1);
    wait_for_tip(&s, &electrum);

    assert!(
        !electrum.is_confirmed_spend(&outpoint, &spk).unwrap(),
        "an unrelated confirmed tx on the same script must not count as a spend"
    );

    // Drain the wallet, which really spends the outpoint, and confirm it.
    s.bitcoind
        .client
        .unlock_unspent(&[outpoint])
        .expect("unlock");
    let dest = s
        .bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    s.bitcoind
        .client
        .call::<serde_json::Value>(
            "sendall",
            &[
                serde_json::json!([dest.to_string()]),
                serde_json::Value::Null,
                serde_json::Value::Null,
                serde_json::json!(25),
            ],
        )
        .expect("sendall");
    generate_blocks(&s.bitcoind, 1);
    wait_for_tip(&s, &electrum);

    assert!(
        electrum.is_confirmed_spend(&outpoint, &spk).unwrap(),
        "a confirmed tx spending the outpoint must count as a spend"
    );

    drop(electrum);
    cleanup(&s.root_dir);
}

/// A broken socket in front of a live server must be bridged, not surfaced.
/// Two outpoints can share one script. Dropping one must not take the
/// subscription the other still needs.
#[test]
fn a_shared_script_stays_subscribed_until_the_last_watcher_goes() {
    let s = setup("refcount");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    let electrum = Electrum::new(&cfg).expect("connect via forwarder");

    let spk = bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([5u8; 20]));
    electrum
        .subscribe_script(&spk, dummy_watch(0))
        .expect("first subscribe");
    electrum
        .subscribe_script(&spk, dummy_watch(1))
        .expect("second subscribe");
    assert_eq!(electrum.subscription_watchers(&spk), 2);

    electrum
        .unsubscribe_script(&spk, dummy_watch(0))
        .expect("release first");
    assert_eq!(
        electrum.subscription_watchers(&spk),
        1,
        "the other outpoint still needs this script"
    );

    electrum
        .unsubscribe_script(&spk, dummy_watch(1))
        .expect("release last");
    assert_eq!(
        electrum.subscription_watchers(&spk),
        0,
        "last watcher gone, so the entry is dropped"
    );

    drop(electrum);
    let _ = &s.bitcoind;
    cleanup(&s.root_dir);
}

#[test]
fn reconnects_after_the_connection_drops() {
    let s = setup("drop");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    let electrum = Electrum::new(&cfg).expect("connect via forwarder");

    let before = electrum.get_block_count().expect("tip before drop");
    let addr = s
        .bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoin::Network::Regtest)
        .unwrap();
    let spk = addr.script_pubkey();
    electrum
        .subscribe_script(&spk, dummy_watch(0))
        .expect("subscribe before reconnect");
    s.forwarder.drop_connections();

    // Same answer, despite the socket having died underneath.
    let after = electrum.get_block_count().expect("tip after drop");
    assert_eq!(before, after);
    assert!(
        electrum.reconnect_count() >= 1,
        "expected at least one reconnect, got {}",
        electrum.reconnect_count()
    );

    send_to_address(&s.bitcoind, &addr, bitcoin::Amount::from_sat(10_000));
    generate_blocks(&s.bitcoind, 1);
    wait_for_tip(&s, &electrum);
    let expected_tip = s.bitcoind.client.get_block_count().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let (mut saw_tx, mut saw_tip) = (false, false);
    while !(saw_tx && saw_tip) && std::time::Instant::now() < deadline {
        if let Some(event) = electrum.poll_event() {
            let event = format!("{event:?}");
            saw_tx |= event.starts_with("TxSeen");
            saw_tip |= event.contains(&format!("height: {expected_tip}"));
        } else {
            thread::sleep(std::time::Duration::from_millis(100));
        }
    }
    assert!(saw_tx, "pre-reconnect script subscription was not re-armed");
    assert!(saw_tip, "header subscription was not re-armed");

    drop(electrum);
    let _ = &s.bitcoind;
    cleanup(&s.root_dir);
}

/// The opening connect retries too, so a circuit that is still settling does not
/// kill process startup. Each participant in a swap opens its own connection.
#[test]
fn connect_retries_until_the_server_answers() {
    let s = setup("connect-retry");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };

    // Refuse forwarding, then let it through again while the first connect is
    // still inside its backoff, so a retry is what makes it succeed.
    s.forwarder.refuse_forwarding();
    let allow = s.forwarder.refuse.clone();
    thread::spawn(move || {
        thread::sleep(std::time::Duration::from_secs(2));
        allow.store(false, Ordering::SeqCst);
    });

    let electrum = Electrum::new(&cfg).expect("connect should bridge the outage");
    electrum
        .get_block_count()
        .expect("tip after retried connect");

    drop(electrum);
    cleanup(&s.root_dir);
}

/// A server that never answers must fail at connect with the dedicated variant.
#[test]
fn connect_gives_up_with_unreachable() {
    let s = setup("connect-dead");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    s.forwarder.refuse_forwarding();

    match Electrum::new(&cfg) {
        Err(WalletError::ElectrumUnreachable { attempts, .. }) => {
            assert_eq!(attempts, 4, "unexpected attempt count");
        }
        other => panic!("expected ElectrumUnreachable, got {:?}", other.map(|_| ())),
    }

    cleanup(&s.root_dir);
}

/// When the server really is gone, fail with the dedicated variant rather than a
/// bare Electrum error, so callers can tell "transport down" from "call failed".
#[test]
fn unreachable_server_reports_exhausted_attempts() {
    let s = setup("unreachable");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    let electrum = Electrum::new(&cfg).expect("connect via forwarder");
    electrum.get_block_count().expect("tip while healthy");

    s.forwarder.refuse_forwarding();

    match electrum.get_block_count() {
        Err(WalletError::ElectrumUnreachable { attempts, .. }) => {
            // 1 initial attempt plus the default 3 retries.
            assert_eq!(attempts, 4, "unexpected attempt count");
        }
        other => panic!("expected ElectrumUnreachable, got {:?}", other),
    }

    drop(electrum);
    cleanup(&s.root_dir);
}

/// Proves shutdown interrupts an active Electrum retry before the caller joins.
#[test]
fn shutdown_interrupts_an_active_retry_and_allows_join() {
    let s = setup("shutdown-retry");
    let cfg = ElectrumConfig {
        url: s.forwarder.url(),
        ..Default::default()
    };
    let electrum = Electrum::new(&cfg).expect("connect via forwarder");
    electrum.get_block_count().expect("tip while healthy");
    let shutdown = electrum.shutdown_flag();
    let connections = s.forwarder.connection_count();
    s.forwarder.refuse_forwarding();

    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let handle = thread::spawn(move || {
        done_tx.send(electrum.get_block_count()).unwrap();
    });
    s.forwarder.wait_for_connection_after(connections);
    shutdown.store(true, Ordering::SeqCst);

    let result = done_rx
        .recv_timeout(std::time::Duration::from_secs(3))
        .expect("Electrum call did not stop after shutdown");
    assert!(matches!(result, Err(WalletError::Interrupted(_))));
    handle.join().expect("Electrum caller thread panicked");
    cleanup(&s.root_dir);
}
