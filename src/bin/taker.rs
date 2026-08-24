use bitcoin::Amount;
use bitcoind::bitcoincore_rpc::Auth;
use clap::Parser;
use log::LevelFilter;
use openswap::{
    lock_debug,
    protocol::ProtocolVersion,
    taker::{
        error::TakerError, format_state, MakerOfferCandidate, MakerState, SwapParams, Taker,
        TakerConfig, TakerInitConfig,
    },
    utill::{parse_proxy_auth, print_new_wallet_seed, setup_taker_logger, UTXO},
    wallet::{AddressType, CoreRpcConfig, Wallet},
};
use serde_json::{json, to_string_pretty};
use std::{path::PathBuf, str::FromStr};

/// A simple command line app to operate as openswap client.
///
/// The app works as a regular Bitcoin wallet with the added capability to perform openswaps.
/// It can talk to either a Bitcoin Core node (over RPC + ZMQ — the default) or an
/// Electrum-protocol server (via `--electrum`). Both paths support the full swap flow
/// and the `restore` subcommand. It currently only runs on the custom signet.
/// Suggested faucet for getting signet coins: <https://faucet.citadelfoss.xyz/>
///
/// For more detailed usage information, please refer: <https://github.com/citadel-foss/openswap/blob/master/docs/taker.md>
///
/// This is early beta, and there are known and unknown bugs. Please report issues at: <https://github.com/citadel-foss/openswap/issues>
#[derive(Parser, Debug)]
#[clap(version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
struct Cli {
    /// Optional data directory. Default value: "~/.openswap/taker"
    #[clap(long, short = 'd')]
    data_directory: Option<PathBuf>,

    /// Bitcoin Core RPC address:port value. Conflicts with `--electrum`.
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

    /// Bitcoin Core RPC authentication string. Ex: username:password.
    /// Conflicts with `--electrum`.
    #[clap(name="USER:PASSWORD",short='a',long, value_parser = parse_proxy_auth, default_value = "user:password")]
    pub auth: (String, String),
    #[clap(long, short = 't')]
    pub tor_auth: Option<String>,

    /// Electrum server URL (e.g. `tcp://localhost:50001`). When set, the wallet
    /// is initialised against an Electrum backend instead of Bitcoin Core.
    /// Mutually exclusive with the Bitcoin Core flags (--rpc/--zmq/--auth).
    /// Electrum servers do not serve full blocks, so chain-based fidelity-bond
    /// discovery is unavailable — maker discovery relies on nostr relays only.
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

    /// Sets the taker wallet's name. If the wallet file already exists, it will load that wallet. Default: taker-wallet
    #[clap(name = "WALLET", long, short = 'w')]
    pub wallet_name: Option<String>,

    /// Password for the encryption of the wallet. Required when creating a
    /// new wallet (wallet files are always encrypted) and to open an
    /// encrypted one.
    #[clap(name = "PASSWORD", long, short = 'p')]
    pub password: Option<String>,

    /// Sets the verbosity level of debug.log file
    #[arg(long, short = 'v', value_parser = ["off", "error", "warn", "info", "debug", "trace"], default_value = "info")]
    pub verbosity: String,

    /// List of commands for various wallet operations
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    // TODO: Design a better structure to display different utxos and balance groups.
    /// Lists all utxos we know about along with their spend info. This is useful for debugging
    ListUtxo,
    /// Lists all single signature wallet Utxos. These are all non-swap regular wallet utxos.
    ListUtxoRegular,
    /// Lists all utxos received in incoming swaps
    ListUtxoSwap,
    /// Lists all utxos that we need to claim via timelock. If you see entries in this list, do a `taker recover` to claim them.
    ListUtxoContract,
    /// Get total wallet balances of different categories.
    /// regular: All single signature regular wallet coins (seed balance).
    /// swap: All 2of2 multisig coins received in swaps.
    /// contract: All live contract transaction balance locked in timelocks. If you see value in this field, you have unfinished or malfinished swaps. You can claim them back with the recover command.
    /// spendable: Spendable amount in wallet (regular + swap balance).
    GetBalances,
    /// Returns a new address
    GetNewAddress,
    /// Send to an external wallet address.
    SendToAddress {
        /// Recipient's address.
        #[clap(long, short = 't')]
        address: String,
        /// Amount to send in sats
        #[clap(long, short = 'a')]
        amount: u64,
        /// Feerate in sats/vByte. Defaults to 2 sats/vByte
        #[clap(long, short = 'f')]
        feerate: Option<f64>,
    },
    /// Update the offerbook with current market offers and display them
    FetchOffers,

    /// List makers from the locally cached offerbook without triggering a network sync.
    ListOffers,
    /// Fetch an offer from a single maker address, verify the fidelity proof, and
    /// store the result in the offerbook. Adds the maker if absent.
    PollMaker {
        /// Maker onion address (e.g. `xyz.onion`).
        #[clap(long, short = 'm')]
        address: String,
    },
    /// Remove a maker from the local offerbook by address.
    RemoveMaker {
        /// Maker onion address (e.g. `xyz.onion`).
        #[clap(long, short = 'm')]
        address: String,
    },
    /// Add or update an address in the funding-source blocklist.
    BlocklistAdd {
        /// Bitcoin address to block.
        address: String,
        /// Optional note explaining why the address is blocked.
        #[clap(long, short = 'l')]
        label: Option<String>,
    },
    /// Remove an address from the funding-source blocklist.
    BlocklistRemove {
        /// Bitcoin address to remove.
        address: String,
    },
    /// Initiate the openswap process
    OpenSwap {
        /// Sets the Maker count to swap with. Swapping with less than 2 makers is not allowed to maintain client privacy.
        /// Adding more makers in the swap will incur more swap fees.
        #[clap(long, short = 'm', default_value = "2")]
        makers: usize,
        /// Sets the swap amount in sats.
        #[clap(long, short = 'a', default_value = "20000")]
        amount: u64,
        #[clap(long = "tx-count", default_value = "1")]
        tx_count: u32,
        /// Protocol version to use: "legacy" or "taproot"
        #[clap(long, default_value = "legacy")]
        protocol: String,
        /// Manually specify maker addresses (host:port). Can be repeated.
        /// When set, these makers are used directly instead of auto-discovery.
        #[clap(long = "maker-address")]
        maker_addresses: Vec<String>,
        /// Automatically select UTXOs instead of interactive picker.
        #[clap(long)]
        auto_select: bool,
        /// PaySwap: settle the swap to this third-party address. The swap
        /// amount then means the exact amount the receiver gets.
        #[clap(long = "payment-address")]
        payment_address: Option<String>,
        /// Skip the confirmation prompt and proceed immediately.
        #[clap(long, short = 'y')]
        yes: bool,
    },
    /// Recover from all failed swaps
    Recover,

    /// Backup the selected wallet.
    ///
    /// You can specify a custom wallet using the default `-w, --WALLET` parameter:
    ///
    /// -w, --wallet_name WALLET-NAME
    ///
    /// The backup will be created in the current working directory with the filename:
    /// `<wallet_name>-backup.json`.
    ///
    /// Backups contain the master key and are always encrypted; you will be
    /// prompted interactively to enter a passphrase.
    ///
    ///
    #[clap(verbatim_doc_comment)]
    Backup,

    /// Restore a wallet from a backup file.
    ///
    /// The `-f, --backup-file <FILE>` parameter specifies the backup file to restore from.
    ///
    /// You can optionally specify a wallet name using the default `-w, --WALLET` parameter.
    /// If no wallet name is provided, the wallet will be restored with its original name
    /// stored in the backup. If a wallet name is provided, the backup will be restored
    /// under that name instead.
    Restore {
        #[clap(long, short = 'f')]
        backup_file: String,
    },
    /// Verify the deniability proof for a specific swap.
    VerifyDeniability {
        /// The swap ID to verify.
        #[clap(long, short = 's')]
        swap_id: String,
    },
}

fn parse_protocol(s: &str) -> Result<ProtocolVersion, TakerError> {
    match s.to_lowercase().as_str() {
        "legacy" => Ok(ProtocolVersion::Legacy),
        "taproot" => Ok(ProtocolVersion::Taproot),
        _ => Err(TakerError::General(format!(
            "Unknown protocol '{}'. Use 'legacy' or 'taproot'.",
            s
        ))),
    }
}

/// Display all makers with per-state counts and a summary line.
fn display_makers_with_summary(
    wallet: &Wallet,
    makers: &[MakerOfferCandidate],
) -> Result<(), TakerError> {
    let (mut good, mut bad, mut unresponsive) = (0, 0, 0);
    let (tip_height, tip_time) = wallet.chain_tip()?;
    for maker in makers {
        match maker.state {
            MakerState::Good => good += 1,
            MakerState::Bad => bad += 1,
            MakerState::Unresponsive { .. } => unresponsive += 1,
        }
        println!("{}", display_offer(wallet, maker, tip_height, tip_time)?);
    }
    println!(
        "\nOfferbook summary → good: {}, bad: {}, unresponsive: {} (total: {})",
        good,
        bad,
        unresponsive,
        makers.len()
    );
    Ok(())
}

/// Format a maker offer candidate as a human-readable string.
fn display_offer(
    wallet: &Wallet,
    candidate: &MakerOfferCandidate,
    tip_height: u64,
    tip_time: u64,
) -> Result<String, TakerError> {
    let header = format!(
        r#"
    Maker
    ─────
    Address        : {address}
    Protocol       : {protocol}
    State          : {state}
    "#,
        address = candidate.address,
        protocol = candidate
            .protocol
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "Unknown".into()),
        state = format_state(&candidate.state),
    );

    let Some(offer) = &candidate.offer else {
        return Ok(header);
    };

    let bond = &offer.fidelity.bond;
    let bond_value = wallet.calculate_bond_value(bond, tip_height, tip_time)?;

    Ok(format!(
        r#"{header}

    Offer
    ─────
    Base Fee       : {base_fee}
    Amount Fee %   : {amount_fee:.4}
    Time Fee %     : {time_fee:.4}

    Limits
    ──────
    Min Size       : {min_size}
    Max Size       : {max_size}
    Required Conf. : {confirms}
    Min Locktime   : {locktime}

    Fidelity Bond
    ─────────────
    Outpoint       : {outpoint}
    Value          : {bond_value}
    Expiry         : {expiry}
    "#,
        header = header.trim_end(),
        base_fee = offer.base_fee,
        amount_fee = offer.amount_relative_fee_pct,
        time_fee = offer.time_relative_fee_pct,
        min_size = offer.min_size,
        max_size = offer.max_size,
        confirms = offer.required_confirms,
        locktime = offer.minimum_locktime,
        outpoint = bond.outpoint(),
        bond_value = bond_value,
        expiry = bond.lock_time,
    ))
}

fn main() -> Result<(), TakerError> {
    let args = Cli::parse();
    setup_taker_logger(
        LevelFilter::from_str(&args.verbosity).unwrap(),
        matches!(
            args.command,
            Commands::Recover
                | Commands::FetchOffers
                | Commands::Backup
                | Commands::Restore { .. }
                | Commands::OpenSwap { .. }
        ),
        args.data_directory.clone(), // default path handled inside the function.
    );

    let wallet_name = args
        .wallet_name
        .clone()
        .unwrap_or_else(|| "taker-wallet".to_string());

    let data_dir = match args.data_directory.clone() {
        Some(dir) => dir,
        None => openswap::utill::get_taker_dir()?,
    };
    // Static settings live in the file (auto-created with defaults if missing).
    // Read it here, before the backend bakes the proxy address in, so a
    // non-default `socks_port` reaches Tor instead of being silently ignored.
    let file_config = TakerConfig::new(Some(&data_dir.join("config.toml")))?;

    // Build the unified taker config (also used by the Restore branch).
    // `--electrum` selects the Electrum backend; otherwise Bitcoin Core.
    let backend = match args.electrum_url.as_ref() {
        Some(url) => openswap::wallet::BackendConfig::Electrum(openswap::wallet::ElectrumConfig {
            url: url.clone(),
            socks5: args
                .electrum_tor
                .then(|| format!("127.0.0.1:{}", file_config.socks_port)),
            ..Default::default()
        }),
        None => openswap::wallet::BackendConfig::CoreRpc(CoreRpcConfig {
            url: args.rpc.clone(),
            auth: Auth::UserPass(args.auth.0.clone(), args.auth.1.clone()),
            wallet_name: wallet_name.clone(),
            zmq_addr: args
                .zmq
                .clone()
                .unwrap_or_else(|| CoreRpcConfig::default_zmq_addr(&args.rpc)),
        }),
    };

    if let Commands::Restore { ref backup_file } = args.command {
        openswap::taker::Taker::restore_wallet(
            args.data_directory,
            Some(wallet_name), // Use the actual translated wallet name here.
            backend,
            backup_file,
        )?;
        return Ok(());
    }

    // CLI wins where a flag exists; the file fills in the rest.
    let config = TakerInitConfig {
        data_dir: Some(data_dir),
        socks_port: file_config.socks_port,
        check_blocklist: Some(file_config.check_blocklist),
        control_port: Some(file_config.control_port),
        tor_auth_password: args.tor_auth.clone().or_else(|| {
            (!file_config.tor_auth_password.is_empty()).then_some(file_config.tor_auth_password)
        }),
        password: args.password.clone(),
        wallet_name: wallet_name.clone(),
        ..TakerInitConfig::default()
    }
    .with_backend(backend.clone());

    let mut taker = Taker::init(config)?;

    // Display and consume the mnemonic phrase. On failure, create a new wallet to get a new phrase.
    if let Some(mnemonic) = lock_debug!(taker.get_wallet().write())
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

    // Sync wallet after initialization. Blocklist edits only touch the local
    // JSON file, so they skip the chain sync.
    if !matches!(
        args.command,
        Commands::BlocklistAdd { .. } | Commands::BlocklistRemove { .. }
    ) {
        lock_debug!(taker.get_wallet().write())
            .unwrap()
            .sync_and_save(&openswap::utill::NO_SHUTDOWN)?;
    }

    match &args.command {
        Commands::ListUtxo => {
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            let utxos = wallet.list_all_utxo_spend_info();
            for utxo in utxos {
                let utxo = UTXO::from_utxo_data(utxo);
                println!("{}", serde_json::to_string_pretty(&utxo)?);
            }
        }
        Commands::ListUtxoRegular => {
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            let utxos = wallet.list_descriptor_utxo_spend_info();
            for utxo in utxos {
                let utxo = UTXO::from_utxo_data(utxo);
                println!("{}", serde_json::to_string_pretty(&utxo)?);
            }
        }
        Commands::ListUtxoSwap => {
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            let utxos = wallet.list_incoming_swap_coin_utxo_spend_info();
            for utxo in utxos {
                let utxo = UTXO::from_utxo_data(utxo);
                println!("{}", serde_json::to_string_pretty(&utxo)?);
            }
        }
        Commands::ListUtxoContract => {
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            let utxos = wallet.list_live_timelock_contract_spend_info();
            for utxo in utxos {
                let utxo = UTXO::from_utxo_data(utxo);
                println!("{}", serde_json::to_string_pretty(&utxo)?);
            }
        }
        Commands::GetBalances => {
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            let balances = wallet.get_balances()?;
            println!(
                "{}",
                to_string_pretty(&json!({
                    "regular": balances.regular.to_sat(),
                    "contract": balances.contract.to_sat(),
                    "swap": balances.swap.to_sat(),
                    "spendable": balances.spendable.to_sat(),
                }))
                .unwrap()
            );
        }
        Commands::GetNewAddress => {
            let mut wallet = lock_debug!(taker.get_wallet().write()).unwrap();
            let address = wallet.get_next_external_address(AddressType::P2TR)?;
            println!("{address:?}");
        }
        Commands::SendToAddress {
            address,
            amount,
            feerate,
        } => {
            let amount = Amount::from_sat(*amount);

            #[cfg(not(feature = "integration-test"))]
            let manually_selected_outpoints = {
                let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
                Some(
                    openswap::utill::interactive_select(wallet.list_all_utxo_spend_info(), amount)?
                        .iter()
                        .map(|(utxo, _)| bitcoin::OutPoint::new(utxo.txid, utxo.vout))
                        .collect::<Vec<_>>(),
                )
            };
            #[cfg(feature = "integration-test")]
            let manually_selected_outpoints = None;

            let mut wallet = lock_debug!(taker.get_wallet().write()).unwrap();
            let txid = wallet.send_to_address(
                amount.to_sat(),
                address.clone(),
                *feerate,
                manually_selected_outpoints,
            )?;
            println!("{txid}");
        }
        Commands::FetchOffers => {
            use std::time::Instant;

            println!("Waiting for offerbook synchronization to complete…");
            let sync_start = Instant::now();

            // Block until the offerbook sync cycle completes (includes Nostr discovery wait).
            taker.sync_offerbook_and_wait()?;

            println!("Offerbook synchronized in {:.2?}", sync_start.elapsed());

            let offerbook = taker.fetch_offers()?;
            let makers = offerbook.all_makers();

            if makers.is_empty() {
                println!("No makers found in offerbook");
                return Ok(());
            }

            println!("\nDiscovered {} makers\n", makers.len());

            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            display_makers_with_summary(&wallet, &makers)?;
        }
        Commands::ListOffers => {
            let offerbook = taker.fetch_offers()?;
            let makers = offerbook.all_makers();

            if makers.is_empty() {
                println!(
                    "No makers in local offerbook. Run `fetch-offers` to sync from the network."
                );
                return Ok(());
            }

            println!("\n{} makers in local offerbook\n", makers.len());

            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            display_makers_with_summary(&wallet, &makers)?;
        }
        Commands::PollMaker { address } => {
            let result = taker.poll_maker(address.clone())?;
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            let (tip_height, tip_time) = wallet.chain_tip()?;
            println!("{}", display_offer(&wallet, &result, tip_height, tip_time)?);
        }
        Commands::RemoveMaker { address } => {
            let removed = taker.remove_maker(address.clone())?;
            if removed {
                println!("Removed maker {address} from offerbook");
            } else {
                println!("No maker with address {address} in offerbook");
            }
        }
        Commands::BlocklistAdd { address, label } => {
            let outcome = taker.add_blocklist_entry(address.clone(), label.clone())?;
            println!("Added: {}, updated: {}", outcome.added, outcome.updated);
        }
        Commands::BlocklistRemove { address } => {
            let removed = taker.remove_blocklist_entry(address.clone())?;
            println!("Removed: {removed}");
        }
        Commands::OpenSwap {
            makers,
            amount,
            tx_count,
            protocol,
            maker_addresses,
            auto_select,
            payment_address,
            yes,
        } => {
            let protocol_version = parse_protocol(protocol)?;

            #[cfg(not(feature = "integration-test"))]
            let manually_selected_outpoints = if !auto_select {
                let target_amount = Amount::from_sat(*amount);
                let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
                Some(
                    openswap::utill::interactive_select(
                        wallet.list_all_utxo_spend_info(),
                        target_amount,
                    )?
                    .iter()
                    .map(|(utxo, _)| bitcoin::OutPoint::new(utxo.txid, utxo.vout))
                    .collect::<Vec<_>>(),
                )
            } else {
                None
            };
            #[cfg(feature = "integration-test")]
            let manually_selected_outpoints = {
                let _ = auto_select;
                None
            };

            let mut swap_params =
                SwapParams::new(protocol_version, Amount::from_sat(*amount), *makers);
            swap_params.tx_count = *tx_count;
            swap_params.manually_selected_outpoints = manually_selected_outpoints;
            if !maker_addresses.is_empty() {
                swap_params.preferred_makers = Some(maker_addresses.clone());
            }
            if let Some(address) = payment_address {
                swap_params.payment_address = Some(address.parse().map_err(|e| {
                    TakerError::General(format!("Invalid payment address '{address}': {e}"))
                })?);
            }

            // Phase 1: Prepare — discover makers, negotiate, get fee summary.
            let summary = taker.prepare_swap(swap_params)?;

            println!("\n========== Swap Summary ==========");
            println!("Swap ID:   {}", summary.swap_id);
            println!("Protocol:  {:?}", summary.protocol);
            println!("Sending:   {}", summary.send_amount);
            println!();
            for (i, maker) in summary.makers.iter().enumerate() {
                println!("  Hop {}: {} ({:?})", i, maker.address, maker.protocol);
                println!(
                    "         Fees: base={} sats, amt={:.4}%, time={:.6}%",
                    maker.base_fee, maker.amount_relative_fee_pct, maker.time_relative_fee_pct
                );
                println!(
                    "         Locktime: {} blocks, Estimated fee: {} sats",
                    maker.locktime, maker.estimated_fee_sats
                );
            }
            println!();
            println!("Total estimated fee: {}", summary.total_estimated_fee);
            if let Some(payment) = &summary.payment {
                println!("Estimated receive:   0 (settled to the payment receiver)");
                println!();
                println!("--- Payment (PaySwap) ---");
                println!("Receiver:            {}", payment.address);
                println!("Receiver gets:       {} (exact)", payment.amount);
                println!("Settlement budget:   {}", payment.settlement_budget);
                println!("Route amount:        {}", summary.send_amount);
                println!(
                    "Funding fee (est.):  {}",
                    payment.taker_funding_fee_estimate
                );
                println!(
                    "Total openswap cost: {}",
                    summary.send_amount + payment.taker_funding_fee_estimate
                );
            } else {
                println!("Estimated receive:   {}", summary.estimated_receive_amount);
            }
            println!("==================================\n");

            // In integration tests, skip the confirmation prompt.
            #[cfg(feature = "integration-test")]
            let _ = yes;
            #[cfg(not(feature = "integration-test"))]
            if !yes {
                print!("Proceed with this swap? [y/N] ");
                use std::io::{self, Write};
                io::stdout().flush().unwrap();
                let mut input = String::new();
                io::stdin()
                    .read_line(&mut input)
                    .map_err(|e| TakerError::General(format!("Failed to read input: {:?}", e)))?;
                let input = input.trim().to_lowercase();
                if input != "y" && input != "yes" {
                    println!("Swap cancelled.");
                    return Ok(());
                }
            }

            taker.start_swap(&summary.swap_id)?;
        }
        Commands::Recover => {
            taker.recover_active_swap()?;
        }
        Commands::Backup => {
            let wallet = lock_debug!(taker.get_wallet().read()).unwrap();
            Wallet::backup_interactive(&wallet)?;
        }
        Commands::Restore { .. } => {
            // Handled above before taker init
            unreachable!()
        }
        Commands::VerifyDeniability { swap_id } => match taker.verify_deniability(swap_id) {
            Ok(true) => println!("Proof valid: swap participated in a completed openswap"),
            Ok(false) => println!("Proof invalid or not found for this swap ID"),
            Err(e) => println!("Error: {e}"),
        },
    }

    Ok(())
}
