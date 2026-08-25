use bitcoind::bitcoincore_rpc::Auth;
use clap::Parser;
use openswap::{
    lock_debug,
    maker::{bind_port_retry, start_server, MakerError, MakerServer, MakerServerConfig},
    utill::{parse_proxy_auth, print_new_wallet_seed, setup_maker_logger},
    wallet::{BackendConfig, CoreRpcConfig, ElectrumConfig},
};
use std::{path::PathBuf, sync::Arc};

/// OpenSwap Maker Server
///
/// The server requires a Bitcoin Core RPC connection or an Electrum server (via --electrum), running on the custom signet. It requires some starting balance, around 50,000 sats for Fidelity + Swap Liquidity (suggested 50,000 sats).
/// So topup with at least 0.001 BTC to start all the node processes. Suggested faucet (tor browser required): <http://s2ncekhezyo2tkwtftti3aiukfpqmxidatjrdqmwie6xnf2dfggyscad.onion/>
///
/// All server processes will start after the fidelity bond transaction is confirmed. This may take some time. Approx: 10 mins.
/// Once the bond is confirmed, the server starts listening for incoming swap requests. As it performs swaps for clients, it keeps earning fees.
///
/// The server is operated with the maker-cli app, for all basic wallet related operations.
///
/// For more detailed usage information, please refer the [Maker Doc]<https://github.com/citadel-foss/openswap/blob/master/docs/makerd.md>
///
/// This is early beta, and there are known and unknown bugs. Please report issues in the [Project Issue Board]<https://github.com/citadel-foss/openswap/issues>
#[derive(Parser, Debug)]
#[clap(version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
struct Cli {
    /// Optional DNS data directory. Default value: "~/.openswap/maker"
    #[clap(long, short = 'd')]
    data_directory: Option<PathBuf>,
    /// Bitcoin Core RPC network address.
    /// Conflicts with `--electrum`.
    #[clap(
        name = "ADDRESS:PORT",
        long,
        short = 'r',
        default_value = "127.0.0.1:38332"
    )]
    pub rpc: String,
    /// Bitcoin Core ZMQ address:port value. Defaults to the RPC host on port 28332.
    #[clap(name = "ZMQ", long, short = 'z')]
    pub zmq: Option<String>,
    /// Bitcoin Core RPC authentication string (username, password).
    /// Conflicts with `--electrum`.
    #[clap(
        name = "USER:PASSWORD",
        short = 'a',
        long,
        value_parser = parse_proxy_auth,
        default_value = "user:password",
    )]
    pub auth: (String, String),
    /// Electrum server URL (e.g. `tcp://localhost:50001`). When set, the wallet
    /// is initialised against an Electrum backend instead of Bitcoin Core.
    /// Mutually exclusive with the Bitcoin Core flags (--rpc/--zmq/--auth).
    #[clap(
        name = "ELECTRUM_URL",
        long = "electrum",
        conflicts_with_all = ["ADDRESS:PORT", "ZMQ", "USER:PASSWORD"]
    )]
    pub electrum_url: Option<String>,
    /// Route the Electrum backend through the Tor SOCKS proxy on `socks_port`.
    /// Works with an onion or a clearnet server; an onion URL needs it.
    /// Peer-to-peer Tor is unaffected either way.
    #[clap(long, requires = "ELECTRUM_URL")]
    pub electrum_tor: bool,
    #[clap(long, short = 't')]
    pub tor_auth: Option<String>,
    /// Optional wallet name. If the wallet exists, load the wallet, else create a new wallet with the given name. Default: maker
    #[clap(name = "WALLET", long, short = 'w')]
    pub(crate) wallet_name: Option<String>,
    /// Password for the encryption of the wallet. Required when creating a
    /// new wallet (wallet files are always encrypted) and to open an
    /// encrypted one.
    #[clap(name = "PASSWORD", long, short = 'p')]
    pub password: Option<String>,
}

fn main() -> Result<(), MakerError> {
    let args = Cli::parse();

    setup_maker_logger(log::LevelFilter::Info, args.data_directory.clone());

    let data_dir = match args.data_directory {
        Some(dir) => dir,
        None => openswap::utill::get_maker_dir()?,
    };

    // Load static settings from config file (auto-creates defaults if missing)
    let config_path = data_dir.join("config.toml");
    let mut config = MakerServerConfig::new(Some(&config_path))?;

    // Override with CLI / runtime args
    config.data_dir = data_dir;
    // "maker" predates this branch; changing it would strand an upgrading
    // operator's wallet and fidelity bond.
    let wallet_name = args.wallet_name.unwrap_or_else(|| "maker".to_string());
    config.wallet_name = wallet_name.clone();
    config.password = args.password;
    if let Some(tor_auth) = args.tor_auth {
        config.tor_auth_password = tor_auth;
    }

    // Set backend from CLI flags: --electrum takes precedence; otherwise Bitcoin Core.
    config.backend = match args.electrum_url {
        Some(url) => BackendConfig::Electrum(ElectrumConfig {
            url,
            socks5: args
                .electrum_tor
                .then(|| format!("127.0.0.1:{}", config.socks_port)),
            ..Default::default()
        }),
        None => BackendConfig::CoreRpc(CoreRpcConfig {
            zmq_addr: match args.zmq {
                Some(addr) => addr,
                None => CoreRpcConfig::default_zmq_addr(&args.rpc),
            },
            url: args.rpc,
            auth: Auth::UserPass(args.auth.0, args.auth.1),
            wallet_name,
        }),
    };

    // First run: discover available port and save to config
    const DEFAULT_NETWORK_PORT: u16 = 6102;
    if config.network_port == DEFAULT_NETWORK_PORT {
        let (_, port) = bind_port_retry(config.network_port)?;
        config.network_port = port;
        config.write_to_file(&config_path)?;
    }

    // Discover and save RPC port to config
    let (_, rpc_port) = bind_port_retry(config.rpc_port - 2)?;
    config.rpc_port = rpc_port;
    config.write_to_file(&config_path)?;

    let maker = Arc::new(MakerServer::init(config)?);

    // Display and consume the mnemonic phrase. On failure, create a new wallet to get a new phrase.
    if let Some(mnemonic) = lock_debug!(maker.wallet.write())
        .unwrap()
        .take_new_mnemonic()
    {
        print_new_wallet_seed(&mnemonic).inspect_err(|e| {
            log::error!(
                "Failed to display new wallet seed phrase: {e}. \
                 Delete the wallet and re-create it to get a new phrase."
            );
        })?;
    }

    start_server(maker)?;

    Ok(())
}
