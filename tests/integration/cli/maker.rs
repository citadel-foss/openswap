//! Maker RPC server: every request variant, plus the unauthorized path.
//!
//! `rpc_port` is already assigned to every maker by the test framework, so the
//! RPC server has been running in all tests all along — nothing ever spoke to
//! it. Cookie *generation* has a unit test (`rpc/server.rs:285`); this covers
//! the wire: one connection per request, exactly as `maker-cli` does it.
//!
//! A normal swap runs first so `SwapUtxo` and `VerifyDeniability` have
//! something real to report.

use bitcoin::{Address, Amount, Txid};
use bitcoind::bitcoincore_rpc::RpcApi;
use openswap::{
    maker::{AuthenticatedRpcRequest, RpcMsgReq as Req, RpcMsgResp as Resp},
    protocol::common_messages::ProtocolVersion,
    taker::SwapParams,
    utill::{read_message, send_message, UTXO},
};
use serde_json::{json, Value};

use crate::test_framework::*;

use log::info;
use std::{
    fs, net::TcpStream, process::Command, str::FromStr, sync::atomic::Ordering::Relaxed,
    time::Duration,
};

/// The maker's RPC server as `maker-cli` reaches it: one connection per request.
struct Rpc {
    port: u16,
    cookie: String,
}

impl Rpc {
    /// One RPC round trip: connect, send an authenticated request, read the reply.
    fn call(&self, request: Req) -> Resp {
        let mut stream = TcpStream::connect(("127.0.0.1", self.port))
            .expect("maker RPC server should be listening");
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        send_message(
            &mut stream,
            &AuthenticatedRpcRequest {
                token: self.cookie.clone(),
                request,
            },
        )
        .expect("failed to send RPC request");
        let bytes = read_message(&mut stream).expect("failed to read RPC response");
        serde_cbor::from_slice(&bytes).expect("failed to decode RPC response")
    }
}

/// Each UTXO as JSON without its confirmation count, which the background
/// miner moves between reading the wallet and asking the RPC, sorted.
fn utxo_rows(utxos: &[UTXO]) -> Vec<String> {
    let mut rows: Vec<String> = utxos
        .iter()
        .map(|utxo| {
            let mut row = serde_json::to_value(utxo).unwrap();
            row.as_object_mut().unwrap().remove("confirmations");
            row.to_string()
        })
        .collect();
    rows.sort();
    rows
}

/// The bonds of a `ListFidelity` reply without their tip-dependent valuation,
/// which every live bond must carry.
fn bond_rows(list: &str) -> Vec<Value> {
    let mut bonds: Vec<Value> = serde_json::from_str(list).expect("ListFidelity must be JSON");
    for bond in &mut bonds {
        let bond = bond.as_object_mut().unwrap();
        let value = bond.remove("bond_value");
        assert_eq!(
            value.is_some(),
            bond["status"] == "Live",
            "only a live bond is valued: {bond:?}"
        );
    }
    bonds
}

/// Whether a `ListSwaps` reply is a history whose one swap is `swap_id`, a
/// success that earned `fee`.
fn history_has_swap(json: &str, swap_id: &str, fee: u64) -> bool {
    let history: Value = serde_json::from_str(json).expect("ListSwaps must be JSON");
    let swaps = history["swaps"].as_array().expect("a swaps list");
    swaps.len() == 1
        && swaps[0]["swap_id"] == swap_id
        && swaps[0]["role"] == "Maker"
        && swaps[0]["status"] == "Success"
        && swaps[0]["fee_earned"] == fee
        && history["totals"]["succeeded"] == 1
        && history["totals"]["fees_earned"] == fee
        && history["totals"]["unreadable_reports"] == 0
        && history["omitted"] == 0
}

/// Whether a one-swap `ListSwaps` reply holds the maker report of `swap_id`
/// and no deniability proof.
fn detail_has_swap(json: &str, swap_id: &str, fee: u64) -> bool {
    let detail: Value = serde_json::from_str(json).expect("ListSwaps must be JSON");
    let reports = detail["maker"].as_array().expect("a maker report");
    reports.len() == 1
        && reports[0]["swap_id"] == swap_id
        && reports[0]["fee_earned"] == fee
        && reports[0].get("deniability_proof").is_none()
}

/// `assert_rpc!(rpc, { request => reply pattern [if guard], .. })`: sends every
/// request in order, then fails once, listing every reply that did not match.
macro_rules! assert_rpc {
    ($rpc:expr, { $($req:expr => $pat:pat $(if $guard:expr)?),+ $(,)? }) => {{
        let rpc = &$rpc;
        let mut mismatches: Vec<String> = Vec::new();
        $(
            match rpc.call($req) {
                $pat $(if $guard)? => {}
                other => mismatches.push(format!(
                    "{}\n      expected `{}`\n      got {:?}",
                    stringify!($req),
                    stringify!($pat $(if $guard)?),
                    other
                )),
            }
        )+
        assert!(
            mismatches.is_empty(),
            "RPC replies do not match:\n  {}",
            mismatches.join("\n  ")
        );
    }};
}

/// The value inside the expected reply variant; any other reply panics with it.
macro_rules! expect_resp {
    ($resp:expr, $pat:pat => $value:expr) => {
        match $resp {
            $pat => $value,
            other => panic!("expected `{}`, got {:?}", stringify!($pat), other),
        }
    };
}

#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(3),
        fund_makers_default(),
        start_makers(120),
        verify_maker_pre_swap_balances(),
    ],
)]
fn rpc_server(world: &mut World) {
    let before = world.balances();

    // A completed swap gives the maker incoming swap coins and a swap id.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    world.mine(1);
    let summary = world
        .taker_mut()
        .prepare(swap_params)
        .expect("Prepare should succeed");
    world
        .taker_mut()
        .start(&summary.swap_id)
        .expect("OpenSwap should complete successfully");
    let swap_id = summary.swap_id.clone();
    info!("Swap {} completed, querying maker RPC", swap_id);

    // Same swap parameters as `taproot_swap`, so the same golden values apply.
    // Assert them before the RPC section, which moves funds via SendToAddress.
    world.taker().sync();
    world.mine(1);
    world.sync_makers();

    assert_balances!(world, since before; {
        taker: { regular: 14_500_000, swap: 496_294, contract: 0, fidelity: 0, loss: 3_706 },
        makers: {
            regular: [14_501_246, 14_502_665],
            swap: [499_169, 497_713],
            contract: 0,
            fidelity: BOND,
            gain: [658, 621],
        },
    });

    let target = world.makers()[0].inner();
    let data_dir = target.config.data_dir.clone();
    let rpc = Rpc {
        port: target.config.rpc_port,
        cookie: fs::read_to_string(data_dir.join("rpc_cookie"))
            .expect("makerd should have written an RPC cookie"),
    };
    // What the RPC reports must match what the wallet reports directly.
    let wallet = world.makers()[0].balances();
    let (wallet_utxos, wallet_fidelity_utxos, wallet_bonds) = {
        let wallet = target.wallet.read().unwrap();
        let rows = |coins: Vec<_>| {
            utxo_rows(
                &coins
                    .into_iter()
                    .map(UTXO::from_utxo_data)
                    .collect::<Vec<_>>(),
            )
        };
        let bonds = wallet
            .get_fidelity_bonds()
            .iter()
            .map(|bond| {
                json!({
                    "index": bond.bond_index,
                    "outpoint": bond.outpoint().to_string(),
                    "amount": bond.amount.to_sat(),
                    "status": if bond.is_spent() { "Redeemed" } else { "Live" },
                })
            })
            .collect::<Vec<_>>();
        (
            rows(wallet.list_all_utxo_spend_info()),
            rows(wallet.list_fidelity_spend_info()),
            bonds,
        )
    };
    assert!(!wallet_utxos.is_empty(), "the maker wallet must hold UTXOs");
    assert_eq!(
        wallet_bonds.len(),
        1,
        "the maker must hold exactly its bond"
    );

    // The fee the maker's own stored report says it earned.
    let fee_earned = target
        .wallet
        .read()
        .unwrap()
        .swap_reports()
        .maker
        .values()
        .flatten()
        .find(|report| report.swap_id == swap_id)
        .expect("the maker must hold a report for the swap")
        .fee_earned;
    assert!(fee_earned > 0, "the maker must have earned a fee");

    // ---- Queries ----
    assert_rpc!(rpc, {
        Req::Ping => Resp::Pong,
        Req::Utxo => Resp::UtxoResp { utxos } if utxo_rows(&utxos) == wallet_utxos,
        // Unswept incoming swapcoins only: the completed swap swept them, and
        // the proceeds show up under `Balances.swap`.
        Req::SwapUtxo => Resp::SwapUtxoResp { utxos } if utxos.is_empty(),
        // A swap that completed leaves no live contracts.
        Req::ContractUtxo => Resp::ContractUtxoResp { utxos } if utxos.is_empty(),
        Req::FidelityUtxo => Resp::FidelityUtxoResp { utxos }
            if utxos.len() == 1 && utxo_rows(&utxos) == wallet_fidelity_utxos,
        Req::Balances => Resp::TotalBalanceResp(b)
            if (b.regular, b.swap, b.contract, b.fidelity)
                == (wallet.regular, wallet.swap, wallet.contract, wallet.fidelity),
        Req::GetDataDir => Resp::GetDataDirResp(dir) if dir == data_dir,
        Req::GetTorAddress => Resp::GetTorAddressResp(addr)
            if addr == "Maker is not running on TOR",
        Req::ListFidelity => Resp::ListBonds(list) if bond_rows(&list) == wallet_bonds,
        Req::SyncWallet => Resp::Pong,
        Req::VerifyDeniability { swap_id: swap_id.clone() } => Resp::VerifyDeniabilityResp(true),
        // An unknown swap id is an error, not `false`.
        Req::VerifyDeniability { swap_id: "no-such-swap".to_string() } => Resp::ServerError(_),
        Req::ListSwaps { swap_id: None, limit: None } => Resp::SwapList(json)
            if history_has_swap(&json, &swap_id, fee_earned),
        Req::ListSwaps { swap_id: Some(swap_id.clone()), limit: None } => Resp::SwapList(json)
            if detail_has_swap(&json, &swap_id, fee_earned),
        Req::ListSwaps { swap_id: Some("no-such-swap".to_string()), limit: None }
            => Resp::ServerError(_),
        // A limit of 0 lists no rows, but the totals still count the swap.
        Req::ListSwaps { swap_id: None, limit: Some(0) } => Resp::SwapList(json)
            if serde_json::from_str::<Value>(&json).is_ok_and(|h| {
                h["swaps"] == json!([]) && h["omitted"] == 1 && h["totals"]["succeeded"] == 1
            }),
    });

    // ---- Mutating ----
    let new_address = expect_resp!(
        rpc.call(Req::NewAddress),
        Resp::NewAddressResp(addr) => Address::from_str(&addr)
            .expect("NewAddress must return a parseable address")
            .assume_checked()
    );
    let txid = expect_resp!(
        rpc.call(Req::SendToAddress {
            address: new_address.to_string(),
            amount: 100_000,
            feerate: 2.0,
        }),
        Resp::SendToAddressResp(txid) => Txid::from_str(&txid)
            .expect("SendToAddress must return a parseable txid")
    );
    // The reply names a real transaction that pays the requested output.
    let tx = world
        .bitcoind()
        .client
        .get_raw_transaction(&txid, None)
        .expect("SendToAddress txid must be known to bitcoind");
    assert!(
        tx.output
            .iter()
            .any(|out| out.script_pubkey == new_address.script_pubkey()
                && out.value == Amount::from_sat(100_000)),
        "SendToAddress tx {txid} must pay 100,000 sats to {new_address}: {:?}",
        tx.output
    );

    // ---- The cookie is actually checked ----
    let intruder = Rpc {
        cookie: "not-the-cookie".to_string(),
        ..rpc
    };
    assert_rpc!(intruder, {
        Req::Ping => Resp::ServerError(e) if e == "unauthorized",
    });

    // ---- The binary itself, so argument parsing is covered too ----
    let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
        .args([
            "-p",
            &format!("127.0.0.1:{}", rpc.port),
            "-d",
            data_dir.to_str().unwrap(),
            "send-ping",
        ])
        .output()
        .expect("failed to run maker-cli");
    let stdout = String::from_utf8(output.stdout).unwrap();
    info!("maker-cli send-ping: {}", stdout.trim());
    assert!(
        output.status.success(),
        "maker-cli send-ping exited with {:?}, stderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("success"),
        "maker-cli send-ping should print success, got: {} / stderr: {}",
        stdout,
        String::from_utf8_lossy(&output.stderr)
    );

    // A request makerd rejects fails the process, so scripts see the failure.
    let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
        .args([
            "-p",
            &format!("127.0.0.1:{}", rpc.port),
            "-d",
            data_dir.to_str().unwrap(),
            "blocklist-add",
            "not-an-address",
        ])
        .output()
        .expect("failed to run maker-cli");
    let stderr = String::from_utf8_lossy(&output.stderr);
    info!("maker-cli blocklist-add not-an-address: {}", stderr.trim());
    assert!(
        !output.status.success(),
        "maker-cli must exit nonzero on a rejected request, stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        stderr.contains("rejected"),
        "maker-cli should report the rejection on stderr, got: {}",
        stderr
    );

    // The same history through both binaries, so argument parsing is covered.
    let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
        .args([
            "-p",
            &format!("127.0.0.1:{}", rpc.port),
            "-d",
            data_dir.to_str().unwrap(),
            "list-swaps",
        ])
        .output()
        .expect("failed to run maker-cli");
    assert!(
        output.status.success(),
        "maker-cli list-swaps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        history_has_swap(&stdout, &swap_id, fee_earned),
        "maker-cli list-swaps printed: {}",
        stdout
    );

    // An id that does not exist is an error: stderr, and a failing exit code.
    let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
        .args([
            "-p",
            &format!("127.0.0.1:{}", rpc.port),
            "-d",
            data_dir.to_str().unwrap(),
            "list-swaps",
            "--swap-id",
            "no-such-swap",
        ])
        .output()
        .expect("failed to run maker-cli");
    assert!(!output.status.success(), "an unknown swap id must fail");
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("no swap with id no-such-swap"));

    // The taker lists its swap from the wallet file alone: its bitcoind
    // address is left out, and nothing connects to Tor.
    let output = Command::new(env!("CARGO_BIN_EXE_taker"))
        .args([
            "--data-directory",
            world.temp_dir().join("taker1").to_str().unwrap(),
            "--WALLET",
            "taker1",
            "--PASSWORD",
            "integration-test",
            "list-swaps",
        ])
        .output()
        .expect("failed to run taker");
    assert!(
        output.status.success(),
        "taker list-swaps failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let history: Value = serde_json::from_slice(&output.stdout).expect("taker prints JSON");
    let swaps = history["swaps"].as_array().unwrap();
    assert_eq!(swaps.len(), 1, "{history}");
    assert_eq!(swaps[0]["swap_id"], swap_id.as_str());
    assert_eq!(swaps[0]["role"], "Taker");
    assert_eq!(swaps[0]["status"], "Success");
    assert!(swaps[0]["fee_paid"].as_u64().unwrap() > 0, "{}", history);
    assert_eq!(history["totals"]["fees_paid"], swaps[0]["fee_paid"]);
    assert_eq!(history["omitted"], 0);

    // The file is only read: a limit of 0 lists no rows, and the wallet stays as it was.
    let wallet_file = world
        .temp_dir()
        .join("taker1")
        .join("wallets")
        .join("taker1");
    let before = fs::read(&wallet_file).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_taker"))
        .args([
            "--data-directory",
            world.temp_dir().join("taker1").to_str().unwrap(),
            "--WALLET",
            "taker1",
            "--PASSWORD",
            "integration-test",
            "list-swaps",
            "--limit",
            "0",
        ])
        .output()
        .expect("failed to run taker");
    assert!(output.status.success());
    let limited: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(limited["swaps"], json!([]));
    assert_eq!(limited["omitted"], 1);
    assert_eq!(fs::read(&wallet_file).unwrap(), before);

    // ---- Stop, last: it shuts the server down ----
    assert_rpc!(rpc, { Req::Stop => Resp::Shutdown });
    wait_until!(
        Duration::from_secs(60),
        "Stop to shut the maker down",
        world.makers()[0].inner().shutdown.load(Relaxed)
    );
    info!("Maker 0 shut down via RPC Stop");

    world.shutdown_makers();

    info!("Maker RPC server test completed successfully!");
}
