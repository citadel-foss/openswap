use bitcoind::bitcoincore_rpc::Auth;
use clap::{Parser, Subcommand};
use openswap::{
    lock_debug,
    maker::{bind_port_retry, start_server, MakerError, MakerServer, MakerServerConfig},
    utill::{parse_proxy_auth, print_new_wallet_seed, setup_maker_logger},
    wallet::{BackendConfig, BondHint, CoreRpcConfig, ElectrumConfig, RestoreOptions},
};
use std::{path::PathBuf, sync::Arc};

/// OpenSwap Maker Server
///
/// The server requires a Bitcoin Core RPC connection or an Electrum server (via --electrum), running on the custom signet (mainnet use is experimental). It requires some starting balance — around 50,000 sats for Fidelity + Swap Liquidity.
/// A 0.001 BTC top-up covers this with margin. Suggested faucet: <https://faucet.openswap.live/>
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
    /// Mutually exclusive with the Bitcoin Core flags (-r/--ADDRESS:PORT, -z/--ZMQ,
    /// -a/--USER:PASSWORD).
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
    #[clap(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Restore the wallet from a backup file or its seed phrase, then exit.
    ///
    /// `--mnemonic` prompts for the phrase at a hidden prompt. Stop every
    /// process using the old wallet first. Open swaps are not recovered.
    #[clap(group(clap::ArgGroup::new("source").required(true).args(["mnemonic", "backup_file"])))]
    Restore {
        #[clap(long)]
        mnemonic: bool,
        #[clap(long, short = 'f')]
        backup_file: Option<PathBuf>,
        /// First block Bitcoin Core rescans from. Default: the backup's, else genesis.
        #[clap(long)]
        birthday: Option<u64>,
        /// Unused addresses in a row that end the search. Default: 100.
        #[clap(long)]
        address_gap: Option<u32>,
        /// A bond made without an announcement, as `INDEX:LOCKTIME`. Repeatable.
        #[clap(long)]
        bond_hint: Vec<BondHint>,
    },
    /// Write an encrypted backup of the existing wallet, then exit.
    ///
    /// Run it with the maker stopped and the Bitcoin Core or Electrum backend
    /// running. Open swaps are not in a backup.
    Backup {
        /// Backup file. Default: `<wallet>-backup.json` in the current directory.
        #[clap(long, short = 'o')]
        output: Option<PathBuf>,
    },
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

    match args.command {
        Some(Commands::Restore {
            backup_file,
            birthday,
            address_gap,
            bond_hint,
            ..
        }) => {
            let defaults = RestoreOptions::default();
            let options = RestoreOptions {
                birthday,
                address_gap: address_gap.unwrap_or(defaults.address_gap),
                bond_hints: bond_hint,
                ..defaults
            };
            return MakerServer::restore_wallet(&config, backup_file.as_deref(), options);
        }
        Some(Commands::Backup { output }) => return MakerServer::backup_wallet(config, output),
        None => {}
    }

    // First run: discover available port and save to config
    const DEFAULT_NETWORK_PORT: u16 = 6102;
    if config.network_port == DEFAULT_NETWORK_PORT {
        let (_, port) = bind_port_retry(config.network_port)?;
        config.network_port = port;
        config.write_to_file(&config_path)?;
    }

    // Discover and save RPC port to config
    let (_, rpc_port) = bind_port_retry(config.rpc_port)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(["makerd"].iter().chain(args))
    }

    #[test]
    fn plain_makerd_has_no_subcommand() {
        assert!(parse(&["-w", "m"]).unwrap().command.is_none());
    }

    #[test]
    fn restore_needs_exactly_one_source() {
        assert!(parse(&["restore"]).is_err());
        assert!(parse(&["restore", "--mnemonic", "-f", "b.json"]).is_err());
        assert!(parse(&["restore", "--mnemonic"]).is_ok());
        assert!(parse(&["-w", "m", "restore", "-f", "b.json"]).is_ok());
    }

    #[test]
    fn restore_and_backup_read_their_options() {
        let cli = parse(&[
            "restore",
            "--mnemonic",
            "--birthday",
            "7",
            "--address-gap",
            "250",
            "--bond-hint",
            "3:900000",
        ])
        .unwrap();
        let Some(Commands::Restore {
            birthday,
            address_gap,
            bond_hint,
            ..
        }) = cli.command
        else {
            panic!("expected restore")
        };
        assert_eq!(
            (birthday, address_gap, bond_hint[0].index),
            (Some(7), Some(250), 3)
        );
        assert!(parse(&["restore", "--mnemonic", "--bond-hint", "3"]).is_err());

        let cli = parse(&["backup", "-o", "x.json"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Backup { output: Some(_) })
        ));
    }
}
