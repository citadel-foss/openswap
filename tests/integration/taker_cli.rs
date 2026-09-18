//! Tests the `taker` binary CLI functionality and wallet operations.
//! This test exercises the taker CLI commands: get-new-address, get-balances, list-utxo,
//! and send-to-address, verifying correct wallet behavior through the command-line interface.

use bip39::rand;
use bitcoin::{address::NetworkChecked, Address, Amount};
use bitcoind::{bitcoincore_rpc::RpcApi, tempfile::env::temp_dir, BitcoinD};

use serde_json::Value;
use std::{fs, path::PathBuf, process::Command, str::FromStr};

use super::test_framework::{generate_blocks, init_bitcoind, send_to_address};

use log::info;

/// The taker-cli command struct
struct TakerCli {
    data_dir: PathBuf,
    temp_dir: PathBuf,
    bitcoind: BitcoinD,
    zmq_addr: String,
}

impl TakerCli {
    /// Construct a new [`TakerCli`] struct that also includes initiating bitcoind.
    fn new() -> TakerCli {
        // Initiate the bitcoind backend — unique dir for parallel test safety.
        let unique_id = format!("openswap-cli-{}", bip39::rand::random::<u64>());
        let temp_dir = temp_dir().join(unique_id);

        // Remove if previously existing
        if temp_dir.exists() {
            fs::remove_dir_all(&temp_dir).unwrap();
        }

        let port_zmq = 28332 + rand::random::<u16>() % 1000;

        let zmq_addr = format!("tcp://127.0.0.1:{port_zmq}");

        let bitcoind =
            init_bitcoind(&temp_dir, zmq_addr.clone()).expect("bitcoind failed to start");
        let data_dir = temp_dir.join("taker");

        TakerCli {
            data_dir,
            temp_dir,
            bitcoind,
            zmq_addr,
        }
    }

    // Execute a cli-command
    fn execute(&self, cmd: &[&str]) -> String {
        let mut args = vec!["--data-directory", self.data_dir.to_str().unwrap()];

        // RPC authentication (user:password) from the cookie file
        let cookie_file_path = &self.bitcoind.params.cookie_file;
        let rpc_auth = fs::read_to_string(cookie_file_path).expect("failed to read from file");
        args.push("--USER:PASSWORD");
        args.push(&rpc_auth);

        // Full node address for RPC connection
        let rpc_address = self.bitcoind.params.rpc_socket.to_string();
        args.push("--ADDRESS:PORT");
        args.push(&rpc_address);

        args.push("--WALLET");
        args.push("test_wallet");

        // Wallet files are always encrypted; a passphrase is required.
        args.push("--PASSWORD");
        args.push("integration-test");

        args.push("--ZMQ");
        args.push(&self.zmq_addr);

        for arg in cmd {
            args.push(arg);
        }

        let output = Command::new(env!("CARGO_BIN_EXE_taker"))
            .args(args)
            .output()
            .expect("Failed to execute taker");

        // Capture the standard output and error from the command execution
        let mut value = output.stdout;
        let error = output.stderr;

        // Panic if there is any error output
        if !error.is_empty() {
            panic!("Error: {:?}", String::from_utf8(error).unwrap());
        }

        // Remove the `\n` at the end of the output
        value.pop();

        // Convert the output bytes to a UTF-8 string
        let output_string = std::str::from_utf8(&value).unwrap().to_string();

        output_string
    }
}

#[test]
fn test_taker_cli() {
    info!("Running Test: Taker CLI functionality and wallet operations");

    let taker_cli = TakerCli::new();
    info!("TakerCli initialized successfully");

    let bitcoind = &taker_cli.bitcoind;

    info!("Funding taker with 3 UTXOs of 1 BTC each");
    // Fund the taker with 3 utxos of 1 BTC each.
    for _ in 0..3 {
        // The command that creates the wallet prints the seed phrase before its
        // result, so the address is the last line.
        let output = taker_cli.execute(&["get-new-address"]);
        let taker_address = output.lines().last().unwrap();

        let taker_address: Address<NetworkChecked> =
            Address::from_str(taker_address).unwrap().assume_checked();

        send_to_address(bitcoind, &taker_address, Amount::ONE_BTC);
    }

    // Confirm balance
    generate_blocks(bitcoind, 10);

    info!("Verifying initial balance - expecting 3 BTC");
    // Assert that total_balance & seed_balance must be 3 BTC
    let balances = taker_cli.execute(&["get-balances"]);
    let balances = serde_json::from_str::<Value>(&balances).unwrap();

    assert_eq!("300000000", balances["regular"].to_string());
    assert_eq!("0", balances["swap"].to_string());
    assert_eq!("0", balances["contract"].to_string());
    assert_eq!("300000000", balances["spendable"].to_string());

    info!("Checking UTXO count - expecting 3 UTXOs");
    // Assert that total no of seed-utxos are 3.
    let all_utxos = taker_cli.execute(&["list-utxo"]);

    let no_of_seed_utxos = all_utxos.matches("addr").count();
    assert_eq!(3, no_of_seed_utxos);
    info!("Initial setup verification successful");

    info!("Testing internal transfer - 100,000 sats with fee rate 2");
    // Send 100,000 sats to a new address within the wallet.

    // Get new external address
    let new_address = taker_cli.execute(&["get-new-address"]);

    let _ = taker_cli.execute(&[
        "send-to-address",
        "-t",
        &new_address,
        "-a",
        "100000",
        "-f",
        "2",
    ]);

    generate_blocks(bitcoind, 10);

    info!("Verifying balance after transfer - expecting only fee deduction");
    // Assert the total_amount & seed_amount must be initial (balance - fee)
    let balances = taker_cli.execute(&["get-balances"]);
    let balances = serde_json::from_str::<Value>(&balances).unwrap();

    // Since the amount is sent back to our wallet, the transaction fee is deducted from the balance.
    assert_eq!("299999692", balances["regular"].to_string());
    assert_eq!("0", balances["swap"].to_string());
    assert_eq!("0", balances["contract"].to_string());
    assert_eq!("299999692", balances["spendable"].to_string());

    info!("Checking final UTXO count - expecting 4 UTXOs");
    // Assert that no of seed utxos are 4
    let all_utxos = taker_cli.execute(&["list-utxo"]);

    let no_of_seed_utxos = all_utxos.matches("addr").count();
    assert_eq!(4, no_of_seed_utxos);
    info!("Transfer verification successful");

    info!("Shutting down bitcoind");
    bitcoind.client.stop().unwrap();

    // Wait for bitcoind to fully exit before removing its data directory.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Clean up temp directory
    if taker_cli.temp_dir.exists() {
        let _ = fs::remove_dir_all(&taker_cli.temp_dir);
    }

    info!("Taker CLI test completed successfully!");
}
