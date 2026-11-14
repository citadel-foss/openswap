//! Spawning electrs against bitcoind and waiting for it to index the chain tip.

#[cfg(windows)]
use std::{
    net::TcpListener,
    process::{Child, Command, Stdio},
};
use std::{
    path::Path,
    thread,
    time::{Duration, Instant},
};

use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};

use openswap::wallet::{Blockchain, Electrum, ElectrumConfig};

/// Owns the electrs child for one test.
///
/// Unix uses crates.io `electrsd`. Windows spawns `ELECTRS_EXEC` itself:
/// electrsd 0.28.0 binds `0.0.0.0` and then connects to that address, which
/// Windows rejects.
pub struct TestElectrs {
    /// `host:port` of the Electrum RPC, without a scheme.
    pub electrum_url: String,
    inner: TestElectrsInner,
}

enum TestElectrsInner {
    #[cfg(unix)]
    Managed(electrsd::ElectrsD),
    #[cfg(windows)]
    Spawned(Child),
}

impl TestElectrs {
    /// Ask electrs to sync. No-op on Windows, which has no `SIGUSR1`.
    pub fn trigger(&self) {
        #[cfg(unix)]
        {
            // `Spawned` does not exist on Unix, so this pattern always matches.
            let TestElectrsInner::Managed(electrs) = &self.inner;
            let _ = electrs.trigger();
        }
    }
}

impl Drop for TestElectrs {
    fn drop(&mut self) {
        #[cfg(windows)]
        {
            let TestElectrsInner::Spawned(child) = &mut self.inner;
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Spawn an electrs process attached to `bitcoind`. The bitcoind instance must
/// have been started with P2P enabled (see [`init_bitcoind`](super::bitcoind::init_bitcoind) which now does so).
///
/// The returned value owns the electrs child process and kills it on drop.
#[allow(dead_code)]
pub(crate) fn init_electrsd(bitcoind: &BitcoinD, datadir: &Path) -> TestElectrs {
    #[cfg(windows)]
    {
        spawn_windows_electrs(bitcoind, datadir)
    }
    #[cfg(unix)]
    {
        let exe = electrsd::exe_path().expect(
            "no electrs binary available: run `export ELECTRS_EXEC=\"$(tests/install_electrs.sh)\"`",
        );
        let mut conf = electrsd::Conf::default();
        let electrs_dir = datadir.join("electrs");
        std::fs::create_dir_all(&electrs_dir).ok();
        conf.staticdir = Some(electrs_dir);
        // Surface electrs stderr only when explicitly requested via env var, to keep test output clean.
        conf.view_stderr = std::env::var("ELECTRS_LOG").is_ok();
        let electrs =
            electrsd::ElectrsD::with_conf(exe, bitcoind, &conf).expect("failed to spawn electrs");
        log::info!("electrs spawned at {}", electrs.electrum_url);
        TestElectrs {
            electrum_url: electrs.electrum_url.clone(),
            inner: TestElectrsInner::Managed(electrs),
        }
    }
}

/// Spawn electrs on loopback. electrsd 0.28.0 cannot do this on Windows.
#[cfg(windows)]
fn spawn_windows_electrs(bitcoind: &BitcoinD, datadir: &Path) -> TestElectrs {
    let exe = std::env::var("ELECTRS_EXEC")
        .unwrap_or_else(|_| panic!("no electrs binary available: set ELECTRS_EXEC"));
    let electrs_dir = datadir.join("electrs");
    std::fs::create_dir_all(&electrs_dir).ok();
    let electrum_port = TcpListener::bind(("127.0.0.1", 0))
        .expect("OS refused a free port")
        .local_addr()
        .unwrap()
        .port();
    let monitor_port = TcpListener::bind(("127.0.0.1", 0))
        .expect("OS refused a free port")
        .local_addr()
        .unwrap()
        .port();
    let electrum_url = format!("127.0.0.1:{electrum_port}");
    let db_dir = electrs_dir.display().to_string();
    let cookie = bitcoind.params.cookie_file.display().to_string();
    let rpc = bitcoind.params.rpc_socket.to_string();
    let p2p = bitcoind
        .params
        .p2p_socket
        .expect("electrs requires bitcoind with p2p port open")
        .to_string();
    let monitor = format!("127.0.0.1:{monitor_port}");
    let mut command = Command::new(&exe);
    command.args([
        "--db-dir",
        &db_dir,
        "--network",
        "regtest",
        "--cookie-file",
        &cookie,
        "--daemon-rpc-addr",
        &rpc,
        "--daemon-p2p-addr",
        &p2p,
        "--electrum-rpc-addr",
        &electrum_url,
        "--monitoring-addr",
        &monitor,
    ]);
    if std::env::var("ELECTRS_LOG").is_err() {
        command.stderr(Stdio::null()).stdout(Stdio::null());
    }
    let mut child = command
        .spawn()
        .unwrap_or_else(|error| panic!("failed to spawn electrs '{}': {}", exe, error));
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait().ok().flatten() {
            panic!("electrs exited before accepting connections: {}", status);
        }
        if std::net::TcpStream::connect(&electrum_url).is_ok() {
            break;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("electrs did not accept connections on {}", electrum_url);
        }
        thread::sleep(Duration::from_millis(200));
    }
    log::info!("electrs spawned at {electrum_url}");
    TestElectrs {
        electrum_url,
        inner: TestElectrsInner::Spawned(child),
    }
}

/// Wait until electrs has indexed up to bitcoind's tip.
///
/// electrs syncs asynchronously, so a wallet sync right after mining can read
/// a stale tip and cache UTXOs with outdated confirmation counts — which then
/// differs from a wallet synced after electrs caught up, failing equality
/// assertions. `trigger()` (SIGUSR1) nudges electrs to sync on each poll.
#[allow(dead_code)]
pub fn wait_for_electrs_tip(bitcoind: &BitcoinD, electrsd: &TestElectrs, cfg: &ElectrumConfig) {
    let expected = bitcoind.client.get_block_count().unwrap();
    // Connected lazily: while electrs is still indexing, connecting fails with
    // "unavailable index", which is just another not-ready-yet state.
    let mut probe = None;
    let mut last_connect_err = None;
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        electrsd.trigger();
        if probe.is_none() {
            match Electrum::new(cfg) {
                Ok(connected) => probe = Some(connected),
                Err(e) => last_connect_err = Some(e),
            }
        }
        if let Some(probe) = &probe {
            if probe
                .get_block_count()
                .map(|tip| tip >= expected)
                .unwrap_or(false)
            {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "electrs did not reach tip {} within 60s{}",
            expected,
            match (&probe, &last_connect_err) {
                (None, Some(e)) => format!("; never connected, last error: {e:?}"),
                _ => String::new(),
            }
        );
        thread::sleep(Duration::from_millis(200));
    }
}
