//! Marker types selecting the wallet backend a test framework run configures.

use std::time::Duration;

use openswap::{
    protocol::common_messages::OPENSWAP_PORT,
    utill::get_ephemeral_address,
    wallet::{BackendConfig, CoreRpcConfig, ElectrumConfig},
};

use super::{
    procs::tor::{tor_password, warm_up_onion, TOR_CONTROL_PORT, TOR_SOCKS_PORT},
    timing::{BLOCKS_PER_TICK, BLOCK_TICK_INTERVAL},
};

/// Test-only marker selecting which backend a [`TestFramework::init`](super::TestFramework::init) run uses.
/// `init::<BitcoindBackend>` / `init::<ElectrumBackend>` pick the backend config;
/// the resulting `Taker`/`MakerServer` are non-generic and resolve the backend
/// at runtime.
pub trait TestBackend {
    fn make_backend_config(
        rpc_config: &CoreRpcConfig,
        zmq_addr: &str,
        ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig;

    /// Block cadence for the background miner: blocks per tick and tick interval.
    /// Protocol steps take far longer over Tor than clearnet, so a backend can
    /// slow the miner to keep block-denominated timelocks ahead of wall-clock delays.
    fn block_cadence() -> (u64, Duration) {
        (BLOCKS_PER_TICK, BLOCK_TICK_INTERVAL)
    }
}

/// Marker selecting the Bitcoin Core backend in tests.
pub struct BitcoindBackend;
/// Marker selecting the Electrum backend in tests.
pub struct ElectrumBackend;
/// Marker selecting the Electrum backend reached over a Tor SOCKS5 proxy.
///
/// Publishes the local `electrsd` as an ephemeral onion service so the client
/// has something a proxy can actually route to — Tor cannot reach a loopback
/// address. Requires a bootstrapped `tor`; see the integration README for the
/// gating.
pub struct TorElectrumBackend;

impl TestBackend for BitcoindBackend {
    fn make_backend_config(
        rpc_config: &CoreRpcConfig,
        zmq_addr: &str,
        _ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig {
        BackendConfig::CoreRpc(CoreRpcConfig {
            zmq_addr: zmq_addr.to_string(),
            ..rpc_config.clone()
        })
    }
}

impl TestBackend for ElectrumBackend {
    fn make_backend_config(
        _rpc_config: &CoreRpcConfig,
        _zmq_addr: &str,
        ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig {
        BackendConfig::Electrum(ElectrumConfig {
            url: ensure_electrum_url(),
            ..Default::default()
        })
    }
}

impl TestBackend for TorElectrumBackend {
    /// ~0.67 blocks/s instead of ~1.67: the 150-block refund locktime base must
    /// outlast Tor-paced setup plus recovery, which the default cadence does not allow.
    fn block_cadence() -> (u64, Duration) {
        (2, BLOCK_TICK_INTERVAL)
    }

    fn make_backend_config(
        _rpc_config: &CoreRpcConfig,
        _zmq_addr: &str,
        ensure_electrum_url: &mut dyn FnMut() -> String,
    ) -> BackendConfig {
        // `ensure_electrum_url` yields "tcp://host:port" for the local electrsd; we
        // only need its port, since the onion service maps to 127.0.0.1.
        let local = ensure_electrum_url();
        let local_port: u16 = local
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or_else(|| panic!("could not parse electrum port from {}", local));

        // `Flags=Detach` means the service outlives this process. Acceptable: the
        // CI job's tor is ephemeral and drops it on restart.
        let onion = get_ephemeral_address(
            TOR_CONTROL_PORT,
            local_port,
            &tor_password(),
            "NEW:ED25519-V3",
            None,
        )
        .expect("ADD_ONION failed; call tor_it_enabled() before using this backend");

        // The helper fixes the onion-side port to OPENSWAP_PORT and maps it to
        // electrsd's real local port.
        let url = format!("tcp://{onion}:{OPENSWAP_PORT}");
        log::info!("Tor electrum backend: {url} via socks 127.0.0.1:{TOR_SOCKS_PORT}");

        // `timeout` and `poll_interval_secs` are left at their derived proxied
        // defaults so the test exercises the cadence production actually ships.
        let cfg = ElectrumConfig {
            url,
            socks5: Some(format!("127.0.0.1:{TOR_SOCKS_PORT}")),
            ..Default::default()
        };
        warm_up_onion(&cfg);
        BackendConfig::Electrum(cfg)
    }
}
