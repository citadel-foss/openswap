//! Spawning electrs against bitcoind and waiting for it to index the chain tip.

use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};

use electrsd::ElectrsD;
use openswap::wallet::{Blockchain, Electrum, ElectrumConfig};

/// Spawn an electrs process attached to `bitcoind`. The bitcoind instance must
/// have been started with P2P enabled (see [`init_bitcoind`](super::bitcoind::init_bitcoind) which now does so).
///
/// The returned [`ElectrsD`] owns the electrs child process and kills it on drop.
#[allow(dead_code)]
pub(crate) fn init_electrsd(bitcoind: &BitcoinD, datadir: &std::path::Path) -> ElectrsD {
    let exe = electrsd::exe_path().expect(
        "no electrs binary available: set ELECTRS_EXEC or enable the electrs_0_9_11 feature",
    );
    let mut conf = electrsd::Conf::default();
    let electrs_dir = datadir.join("electrs");
    std::fs::create_dir_all(&electrs_dir).ok();
    conf.staticdir = Some(electrs_dir);
    // Surface electrs stderr only when explicitly requested via env var, to keep test output clean.
    conf.view_stderr = std::env::var("ELECTRS_LOG").is_ok();
    let electrsd = ElectrsD::with_conf(exe, bitcoind, &conf).expect("failed to spawn electrs");
    log::info!("🔌 electrs spawned at {}", electrsd.electrum_url);
    electrsd
}

/// Wait until electrs has indexed up to bitcoind's tip.
///
/// electrs syncs asynchronously, so a wallet sync right after mining can read
/// a stale tip and cache UTXOs with outdated confirmation counts — which then
/// differs from a wallet synced after electrs caught up, failing equality
/// assertions. `trigger()` (SIGUSR1) nudges electrs to sync on each poll.
#[allow(dead_code)]
pub fn wait_for_electrs_tip(bitcoind: &BitcoinD, electrsd: &ElectrsD, cfg: &ElectrumConfig) {
    let expected = bitcoind.client.get_block_count().unwrap();
    // Connected lazily: while electrs is still indexing, connecting fails with
    // "unavailable index", which is just another not-ready-yet state.
    let mut probe = None;
    let mut last_connect_err = None;
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    loop {
        let _ = electrsd.trigger();
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
            std::time::Instant::now() < deadline,
            "electrs did not reach tip {} within 60s{}",
            expected,
            match (&probe, &last_connect_err) {
                (None, Some(e)) => format!("; never connected, last error: {e:?}"),
                _ => String::new(),
            }
        );
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
}
