//! Basic Taker API Example
//!
//! This example demonstrates how to use the OpenSwap Taker API:
//! - Initialize a Taker instance with Bitcoin Core RPC
//! - Check wallet balance and generate addresses
//! - Fund the wallet with test coins
//! - Demonstrate swap parameters setup
//!
//! ## Prerequisites
//!
//! This example requires Tor to be running for openswap connections.
//! See [Tor setup documentation](https://github.com/citadel-foss/openswap/blob/master/docs/tor.md)
//! for installation and configuration instructions.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example taker_basic
//! ```
//!
//! Wallet files are always encrypted, so the config sets a demo passphrase.
//! In production, supply your own via `-p`/`--password` on every start.

use bitcoin::Amount;
use bitcoind::{
    bitcoincore_rpc::{Auth, RpcApi},
    BitcoinD,
};
use openswap::{
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, Taker, TakerInitConfig},
    wallet::{AddressType, BackendConfig, CoreRpcConfig},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OpenSwap Taker Basic Example ===");

    // Clean up any existing wallet files to ensure fresh start
    let wallet_path = std::env::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".openswap")
        .join("taker")
        .join("wallets")
        .join("taker-example");

    if wallet_path.exists() {
        std::fs::remove_file(&wallet_path).ok();
        println!("Cleaned up previous wallet file");
    }

    // Setup bitcoind in regtest mode
    // NOTE: This example uses regtest for demonstration. In production,
    // you should run your own bitcoind node. See the bitcoind documentation
    // at https://github.com/citadel-foss/openswap/blob/master/docs/bitcoind.md
    let data_dir = std::env::temp_dir().join("openswap_taker_example");
    std::fs::create_dir_all(&data_dir)?;

    println!("Starting Bitcoin Core in regtest mode...");

    // bitcoind must publish on the same address the wallet's ZMQ subscriber connects to.
    const ZMQ_ADDR: &str = "tcp://127.0.0.1:28332";
    let zmq_rawtx = format!("-zmqpubrawtx={ZMQ_ADDR}");
    let zmq_rawblock = format!("-zmqpubrawblock={ZMQ_ADDR}");

    // Setup bitcoind configuration
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1"); // Required for wallet sync
    conf.args.push(&zmq_rawtx);
    conf.args.push(&zmq_rawblock);
    conf.staticdir = Some(data_dir.join(".bitcoin"));

    let exe_path = bitcoind::exe_path().unwrap();
    let bitcoind = BitcoinD::with_conf(exe_path, &conf).unwrap();

    // Generate initial 101 blocks (required for coinbase maturity)
    let mining_address = bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .require_network(bitcoind::bitcoincore_rpc::bitcoin::Network::Regtest)
        .unwrap();
    bitcoind
        .client
        .generate_to_address(101, &mining_address)
        .unwrap();

    println!("Bitcoin Core started and initial blocks generated");

    // Create RPC config from bitcoind instance
    let rpc_config = CoreRpcConfig {
        url: bitcoind.rpc_url().split_at(7).1.to_string(), // Remove "http://" prefix
        auth: Auth::CookieFile(bitcoind.params.cookie_file.clone()),
        wallet_name: "taker-example".to_string(), // Use specific wallet name
        zmq_addr: ZMQ_ADDR.to_string(),
    };

    // Initialize Taker with builder-style config
    println!("About to initialize taker...");

    // Wallet files are always encrypted; a passphrase is required.
    let config = TakerInitConfig {
        wallet_name: "taker-example".to_string(),
        password: Some("example-password".to_string()),
        ..TakerInitConfig::default()
    }
    .with_backend(BackendConfig::CoreRpc(rpc_config));

    let taker = Taker::init(config).unwrap();

    // Swap the two lines above for these to drive the same wallet through an electrs server instead of bitcoind RPC.
    //     use openswap::wallet::ElectrumConfig;
    //     let electrum_config = ElectrumConfig {
    //         url: "tcp://127.0.0.1:60401".to_string(),
    //     };
    //     let config = TakerInitConfig {
    //         wallet_name: "taker-example".to_string(),
    //         password: Some("example-password".to_string()),
    //         ..TakerInitConfig::default()
    //     }
    //     .with_backend(BackendConfig::Electrum(electrum_config));
    //     let taker = Taker::init(config).unwrap();

    println!("Taker initialized successfully!");

    // Check initial wallet balance and UTXOs
    {
        let wallet = taker.get_wallet().read().unwrap();
        let balances = wallet.get_balances().unwrap();
        let utxos = wallet.list_all_utxo();

        println!("Initial wallet state:");
        println!("  Spendable: {} BTC", balances.spendable.to_btc());
        println!("  Regular: {} BTC", balances.regular.to_btc());
        println!("  UTXOs: {}", utxos.len());
    }

    // Fund the wallet if empty
    {
        let balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
        if balances.spendable == Amount::ZERO {
            println!("\nFunding wallet with test coins...");

            let mut wallet = taker.get_wallet().write().unwrap();
            let funding_address = wallet.get_next_external_address(AddressType::P2TR).unwrap();

            // Send coins from bitcoind to the taker wallet
            let fund_amount = Amount::from_btc(0.01).unwrap();
            let _txid = bitcoind
                .client
                .send_to_address(
                    &funding_address,
                    fund_amount,
                    None,
                    None,
                    None,
                    None,
                    None,
                    None,
                )
                .unwrap();

            // Mine a block to confirm the transaction
            bitcoind
                .client
                .generate_to_address(1, &mining_address)
                .unwrap();

            // Sync wallet to see the new funds
            wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();

            let updated_balances = wallet.get_balances().unwrap();
            println!("Wallet funded successfully!");
            println!("  New balance: {} BTC", updated_balances.spendable.to_btc());
        }
    }

    // Generate a new receiving address
    {
        let mut wallet = taker.get_wallet().write().unwrap();
        let new_address = wallet.get_next_external_address(AddressType::P2TR).unwrap();
        println!("\nGenerated new receiving address: {}", new_address);

        // Demonstrate sending coins (send small amount to ourselves)
        println!("\nDemonstrating send functionality:");
        let send_amount = Amount::from_btc(0.001).unwrap();
        let internal_address = wallet
            .get_next_internal_addresses(1, AddressType::P2TR)
            .unwrap()[0]
            .clone();

        println!(
            "Sending {} BTC to internal address: {}",
            send_amount.to_btc(),
            internal_address
        );
        println!("(Send functionality ready - commented out to avoid spending coins in example)");

        // Show current balances
        let final_balances = wallet.get_balances().unwrap();
        println!("\nFinal wallet balances:");
        println!("  Spendable: {} BTC", final_balances.spendable.to_btc());
        println!("  Regular: {} BTC", final_balances.regular.to_btc());
        println!("  Swap: {} BTC", final_balances.swap.to_btc());
        println!("  Fidelity: {} BTC", final_balances.fidelity.to_btc());
        println!("  Contract: {} BTC", final_balances.contract.to_btc());

        // Show UTXOs
        let utxos = wallet.list_all_utxo();
        println!("\nUTXO information:");
        println!("  Total UTXOs: {}", utxos.len());
        if !utxos.is_empty() {
            println!(
                "  Sample UTXO: {} ({} BTC)",
                utxos[0].txid,
                utxos[0].amount.to_btc()
            );
        }
    }

    // OpenSwap setup
    println!("\nOpenSwap setup:");

    let swap_params = SwapParams {
        protocol: ProtocolVersion::Legacy,
        send_amount: Amount::from_btc(0.005).unwrap(),
        maker_count: 2,
        ..Default::default()
    };

    println!("Swap parameters:");
    println!(
        "  Amount: {} BTC ({} sats)",
        swap_params.send_amount.to_btc(),
        swap_params.send_amount.to_sat()
    );
    println!("  Makers needed: {}", swap_params.maker_count);
    println!("  Protocol: {:?}", swap_params.protocol);

    // In production, you would call:
    //   let summary = taker.prepare_swap(swap_params).unwrap();
    //   let report = taker.start_swap(&summary.swap_id).unwrap();

    println!("\nOpenSwap call commented out for this example.");
    println!("\nIn production, you would call:");
    println!("  let summary = taker.prepare_swap(swap_params).unwrap();");
    println!("  let report = taker.start_swap(&summary.swap_id).unwrap();");
    println!("\nThis would:");
    println!("- Connect to the tracker server to find makers");
    println!("- Negotiate with {} makers", swap_params.maker_count);
    println!("- Execute the openswap protocol");
    println!("- Return the final transaction details");

    println!("\nExample completed.");

    // stop bitcoind for cleanup
    let _ = bitcoind.client.stop();
    println!("Bitcoin Core stopped.");
    Ok(())
}
