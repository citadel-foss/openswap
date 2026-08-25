//! Basic Wallet API Example
//!
//! This example demonstrates comprehensive wallet operations using the Wallet API:
//! - Check all balance types (regular, swap, fidelity, contract)
//! - Generate external and internal addresses
//! - UTXO categorization and detailed spend info
//! - Coin selection algorithms
//! - Transaction creation and broadcasting
//! - UTXO management and locking
//! - Contract monitoring (timelock, hashlock)
//! - Swap coin operations
//!
//! ## Usage
//!
//! ```bash
//! cargo run --example wallet_basic
//! ```

use bitcoin::Amount;
use bitcoind::{
    bitcoincore_rpc::{Auth, RpcApi},
    BitcoinD,
};
use openswap::{
    utill::MIN_FEE_RATE,
    wallet::{AddressType, AnyBlockchain, CoreRPC, CoreRpcConfig, Destination, Wallet},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== OpenSwap Wallet Basic Example ===");

    // Clean up any existing wallet files to ensure fresh start
    let wallet_path = std::env::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(".openswap")
        .join("taker")
        .join("wallets")
        .join("wallet-example");

    if wallet_path.exists() {
        std::fs::remove_file(&wallet_path).ok();
        println!("Cleaned up previous wallet file");
    }

    // Setup bitcoind in regtest mode
    // NOTE: This example uses regtest for demonstration. In production,
    // you should run your own bitcoind node. See the bitcoind documentation
    // at https://github.com/citadel-foss/openswap/blob/master/docs/bitcoind.md
    let data_dir = std::env::temp_dir().join("openswap_wallet_example");
    std::fs::create_dir_all(&data_dir)?;

    println!("Starting Bitcoin Core in regtest mode...");

    // Setup bitcoind configuration
    let mut conf = bitcoind::Conf::default();
    conf.args.push("-txindex=1"); // Required for wallet sync
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
        wallet_name: "wallet-example".to_string(), // Use specific wallet name
        ..CoreRpcConfig::default()
    };

    // Initialize Wallet using Wallet::init()
    println!("About to initialize wallet...");

    // Ensure wallet directory exists
    std::fs::create_dir_all(wallet_path.parent().unwrap())?;

    let backend = AnyBlockchain::CoreRPC(CoreRPC::new(&rpc_config).unwrap());
    // Wallet files are always encrypted; a passphrase is required.
    let enc_material =
        openswap::security::KeyMaterial::new_from_password(Some("example-password".to_string()))
            .unwrap();
    let mut wallet = Wallet::init(&wallet_path, backend, enc_material).unwrap();

    // Replace the `backend` and `Wallet::init` lines above with these to drive
    // the same wallet through an electrs server instead of bitcoind RPC.
    //     use openswap::wallet::{Electrum, ElectrumConfig};
    //     let electrum_config = ElectrumConfig {
    //         url: "tcp://127.0.0.1:60401".to_string(),
    //     };
    //     let backend = AnyBlockchain::Electrum(Electrum::new(&electrum_config).unwrap());
    //     let mut wallet = Wallet::init(&wallet_path, backend, enc_material).unwrap();

    println!("Wallet initialized successfully!");

    // Sync wallet first
    wallet.sync_and_save(&openswap::utill::NO_SHUTDOWN).unwrap();
    println!("Wallet synced with blockchain");

    // Fund the wallet for demonstration
    let funding_address = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    let fund_amount = Amount::from_btc(0.05).unwrap();
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
    println!("Wallet funded with {} BTC", fund_amount.to_btc());

    // Check balances and explain what each type means
    println!("\nBalance Types:");
    let balances = wallet.get_balances().unwrap();
    println!(
        "  Spendable: {} BTC (regular + swap coins available for spending)",
        balances.spendable.to_btc()
    );
    println!(
        "  Regular: {} BTC (normal wallet UTXOs)",
        balances.regular.to_btc()
    );
    println!(
        "  Swap: {} BTC (completed swap coins)",
        balances.swap.to_btc()
    );
    println!(
        "  Fidelity: {} BTC (locked in fidelity bonds)",
        balances.fidelity.to_btc()
    );
    println!(
        "  Contract: {} BTC (locked in active contracts)",
        balances.contract.to_btc()
    );

    // Show total UTXOs and swap coin count
    println!("\nUTXO Summary:");
    let utxos = wallet.list_all_utxo();
    let incoming_count = wallet.get_incoming_swapcoins_count();
    let outgoing_count = wallet.get_outgoing_swapcoins_count();
    println!("  Total UTXOs: {}", utxos.len());
    println!(
        "  Swap coins: {} (incoming: {}, outgoing: {})",
        incoming_count + outgoing_count,
        incoming_count,
        outgoing_count
    );

    // Categorize UTXOs by type
    println!("\nUTXO Categories:");
    let regular_utxos_count = wallet.list_descriptor_utxo_spend_info().len();
    let swap_utxos_count = wallet.list_swap_coin_utxo_spend_info().len();
    let fidelity_utxos_count = wallet.list_fidelity_spend_info().len();
    let swept_utxos_count = wallet.list_swept_incoming_swap_utxos().len();
    println!("  Regular UTXOs: {}", regular_utxos_count);
    println!("  Swap UTXOs: {}", swap_utxos_count);
    println!("  Fidelity UTXOs: {}", fidelity_utxos_count);
    println!("  Swept swap UTXOs: {}", swept_utxos_count);

    // Generate addresses
    println!("\nAddress Generation:");
    let external_address = wallet.get_next_external_address(AddressType::P2TR).unwrap();
    let internal_addresses = wallet
        .get_next_internal_addresses(2, AddressType::P2TR)
        .unwrap();
    println!("  External (receiving): {external_address}");
    println!(
        "  Internal (change): {} {}",
        internal_addresses[0], internal_addresses[1]
    );

    // Show wallet state information
    println!("\nWallet State:");
    let external_index = *wallet.get_external_index();
    println!("  External address index: {external_index}");

    // Demonstrate UTXO management
    println!("\nUTXO Management:");
    wallet.lock_unspendable_utxos().unwrap();
    println!("  Locked unspendable UTXOs (fidelity bonds, contracts)");

    // Demonstrate coin selection and transaction operations
    if balances.spendable > Amount::ZERO {
        let select_amount = Amount::from_btc(0.001).unwrap();
        if balances.spendable >= select_amount {
            println!("\nCoin Selection Demo:");
            let selected_utxos = wallet
                .coin_select(select_amount, MIN_FEE_RATE, AddressType::P2TR, None, None)
                .unwrap();

            let total_selected: u64 = selected_utxos
                .iter()
                .map(|(utxo, _)| utxo.amount.to_sat())
                .sum();
            println!(
                "  Selected {} UTXOs for {} BTC",
                selected_utxos.len(),
                select_amount.to_btc()
            );
            println!(
                "  Total value: {} BTC",
                Amount::from_sat(total_selected).to_btc()
            );

            // Show types of selected UTXOs
            for (utxo, spend_info) in selected_utxos.iter().take(3) {
                println!(
                    "    UTXO: {} ({} BTC, type: {})",
                    utxo.txid,
                    utxo.amount.to_btc(),
                    spend_info
                );
            }

            // Demonstrate transaction creation
            println!("\nTransaction Creation Demo:");
            let destination_address = internal_addresses[0].clone();

            let transaction = wallet
                .spend_coins(
                    &selected_utxos,
                    Destination::Sweep(destination_address.clone()),
                    MIN_FEE_RATE,
                )
                .unwrap();

            let txid = transaction.compute_txid();
            println!("  Created transaction: {txid}");
            println!("  Inputs: {}", transaction.input.len());
            println!("  Outputs: {}", transaction.output.len());
            println!("  Size: {} bytes", transaction.vsize());
            println!("  Destination: {destination_address}");

            // This is how this will be broadcasted in production
            println!("  Transaction ready for broadcast with wallet.send_tx()");
            // let broadcast_txid = wallet.send_tx(&transaction).unwrap();
        } else {
            println!("\nCoin Selection Demo:");
            println!(
                "  Insufficient funds for coin selection demo (need {} BTC)",
                select_amount.to_btc()
            );
        }

        // Demonstrate swap operations
        println!("\nSwap Operations:");
        if swap_utxos_count > 0 {
            println!("  Found {} incoming swap coin UTXOs", swap_utxos_count);
            println!("  Use wallet.sweep_incoming_swapcoins() to sweep completed swaps");
        } else {
            println!("  No incoming swap coins to sweep");
        }
    }

    // Show advanced wallet operations
    println!("\nAdvanced Wallet Information:");

    // Get advanced wallet info
    let live_contracts = wallet.list_live_contract_spend_info();
    let timelock_contracts = wallet.list_live_timelock_contract_spend_info();
    let hashlock_contracts = wallet.list_live_hashlock_contract_spend_info();
    let all_utxo_info = wallet.list_all_utxo_spend_info();

    println!("  Live contracts: {}", live_contracts.len());
    println!("  Timelock contracts: {}", timelock_contracts.len());
    println!("  Hashlock contracts: {}", hashlock_contracts.len());
    println!(
        "  Detailed UTXO info available for {} UTXOs",
        all_utxo_info.len()
    );

    // Show first few UTXOs with their spend info
    for (utxo, spend_info) in all_utxo_info.iter().take(3) {
        println!(
            "    {} {} BTC ({})",
            utxo.txid,
            utxo.amount.to_btc(),
            spend_info
        );
    }

    println!("\nWallet is funded and ready for operations!");
    println!("\nExample completed.");

    // Stop bitcoind for cleanup
    let _ = bitcoind.client.stop();
    println!("Bitcoin Core stopped.");
    Ok(())
}
