//! [`Node`]: a regtest bitcoind under its own temp dir, with electrs when the
//! backend reads through Electrum, for tests that need a chain but no takers,
//! makers or relay.
//!
//! Nothing mines in the background: the chain moves only when the test mines.
//! Dropping the node stops electrs, then bitcoind, then deletes the temp dir; a
//! failing test's dir stays for inspection.

use std::{
    env, fs,
    marker::PhantomData,
    path::{Path, PathBuf},
    thread,
};

use bip39::rand;
use bitcoind::{bitcoincore_rpc::Auth, BitcoinD};
use openswap::wallet::{BackendConfig, CoreRpcConfig, ElectrumConfig};

use super::{
    backend::TestBackend,
    logs::{end_test_log_group, setup_test_logger},
    ports::free_ports,
    procs::{
        bitcoind::{generate_blocks, init_bitcoind},
        electrs::{init_electrsd, wait_for_electrs_tip, TestElectrs},
    },
};

/// Collects what [`Node::build`](NodeBuilder::build) takes: the backend and
/// bitcoind's keypool size.
pub struct NodeBuilder<B> {
    backend: PhantomData<fn() -> B>,
    keypool: Option<u32>,
}

impl<B: TestBackend> NodeBuilder<B> {
    /// Sets bitcoind's `keypool`. Core pads every descriptor range a wallet
    /// imports with it (1000 by default), which can hide a restore that stops
    /// short.
    pub fn keypool(mut self, size: u32) -> Self {
        self.keypool = Some(size);
        self
    }

    /// Starts bitcoind, and electrs if `B` reads through Electrum, with the
    /// test's logger writing under the node's temp dir.
    #[must_use = "dropping the Node stops it at once"]
    pub fn build(self) -> Node {
        let temp_dir = env::temp_dir().join(format!("openswap-node-{}", rand::random::<u64>()));
        setup_test_logger(&temp_dir);
        log::info!("temporary directory : {}", temp_dir.display());
        log::info!("test: {}", thread::current().name().unwrap_or("<unnamed>"));

        // A freed OS port can be taken before bitcoind binds it, so retry.
        // Each attempt has its own datadir: a failed start can leave the lock.
        let (bitcoind, zmq_addr) = (0..3)
            .find_map(|attempt| {
                let datadir = temp_dir.join(format!("bitcoind-{attempt}"));
                if let Some(size) = self.keypool {
                    fs::create_dir_all(datadir.join(".bitcoin")).unwrap();
                    fs::write(
                        datadir.join(".bitcoin/bitcoin.conf"),
                        format!("keypool={size}\n"),
                    )
                    .unwrap();
                }
                let zmq_addr = format!("tcp://127.0.0.1:{}", free_ports(1)[0]);
                init_bitcoind(&datadir, zmq_addr.clone())
                    .ok()
                    .map(|bitcoind| (bitcoind, zmq_addr))
            })
            .expect("bitcoind failed to start on three fresh ZMQ ports");
        let rpc_config = CoreRpcConfig {
            url: bitcoind.rpc_url().split_at(7).1.to_string(),
            auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
            ..Default::default()
        };

        // Building B's backend config is what starts electrs when B reads
        // through Electrum; the config itself is the test's to build.
        let mut electrsd = None;
        B::make_backend_config(&rpc_config, &zmq_addr, &mut || {
            let spawned = init_electrsd(&bitcoind, &temp_dir);
            let url = format!("tcp://{}", spawned.electrum_url);
            let config = ElectrumConfig {
                url: url.clone(),
                ..Default::default()
            };
            wait_for_electrs_tip(&bitcoind, &spawned, &config);
            electrsd = Some(spawned);
            url
        });
        Node {
            electrsd,
            bitcoind: Some(bitcoind),
            zmq_addr,
            rpc_config,
            temp_dir,
        }
    }
}

/// A regtest bitcoind, electrs when the backend needs it, and the temp dir both
/// keep their data in.
pub struct Node {
    // Dropped in this order: electrs polls bitcoind, so it goes first.
    electrsd: Option<TestElectrs>,
    bitcoind: Option<BitcoinD>,
    zmq_addr: String,
    rpc_config: CoreRpcConfig,
    temp_dir: PathBuf,
}

impl Node {
    /// Starts collecting a node over backend `B`.
    pub fn builder<B: TestBackend>() -> NodeBuilder<B> {
        NodeBuilder {
            backend: PhantomData,
            keypool: None,
        }
    }

    /// The regtest node.
    pub fn bitcoind(&self) -> &BitcoinD {
        self.bitcoind.as_ref().expect("bitcoind lives until drop")
    }

    /// This test's temp dir; bitcoind keeps its data in `.bitcoin` under it.
    pub fn temp_dir(&self) -> &Path {
        &self.temp_dir
    }

    /// The ZMQ address bitcoind publishes raw blocks and transactions on.
    pub fn zmq_addr(&self) -> &str {
        &self.zmq_addr
    }

    /// RPC access to the node; `wallet_name` is left at its default.
    pub fn rpc_config(&self) -> CoreRpcConfig {
        self.rpc_config.clone()
    }

    /// `B`'s wallet backend on this node, with `wallet_name` as Core's wallet:
    /// Core keeps one wallet per name. `B` must be the backend the node was
    /// built over, so an Electrum one has its electrs.
    #[track_caller]
    pub fn backend_config<B: TestBackend>(&self, wallet_name: &str) -> BackendConfig {
        let rpc_config = CoreRpcConfig {
            wallet_name: wallet_name.to_string(),
            ..self.rpc_config()
        };
        B::make_backend_config(&rpc_config, &self.zmq_addr, &mut || {
            format!("tcp://{}", self.electrsd().electrum_url)
        })
    }

    /// The electrs serving this node.
    #[track_caller]
    pub fn electrsd(&self) -> &TestElectrs {
        self.electrsd
            .as_ref()
            .expect("this node has no electrs; build it over an Electrum backend")
    }

    /// An Electrum client config pointing at this node's electrs.
    #[track_caller]
    pub fn electrum_config(&self) -> ElectrumConfig {
        ElectrumConfig {
            url: format!("tcp://{}", self.electrsd().electrum_url),
            ..Default::default()
        }
    }

    /// Mines `n` blocks, and waits for electrs to index them when there is one.
    pub fn mine(&self, n: u64) {
        generate_blocks(self.bitcoind(), n);
        if let Some(electrsd) = &self.electrsd {
            wait_for_electrs_tip(self.bitcoind(), electrsd, &self.electrum_config());
        }
    }

    /// Stops the node and deletes its temp dir; what dropping it does.
    pub fn finish(self) {}
}

impl Drop for Node {
    fn drop(&mut self) {
        drop(self.electrsd.take());
        // A persistent-datadir BitcoinD stops the node and waits for it on drop,
        // so its shutdown cannot write the datadir back after the delete.
        drop(self.bitcoind.take());
        if thread::panicking() {
            log::warn!("test failed; keeping {}", self.temp_dir.display());
        } else {
            let _ = fs::remove_dir_all(&self.temp_dir);
        }
        end_test_log_group();
    }
}
