//! Maker RPC server: every request variant, plus the unauthorized path.
//!
//! `rpc_port` is already assigned to every maker by the test framework, so the
//! RPC server has been running in all tests all along — nothing ever spoke to
//! it. Cookie *generation* has a unit test (`rpc/server.rs:285`); this covers
//! the wire: one connection per request, exactly as `maker-cli` does it.
//!
//! A normal swap runs first so `SwapUtxo` and `VerifyDeniability` have
//! something real to report.

use bitcoin::{Address, Amount};
use openswap::{
    maker::{start_server, AuthenticatedRpcRequest, MakerBehavior, RpcMsgReq, RpcMsgResp},
    protocol::common_messages::ProtocolVersion,
    taker::{SwapParams, TakerBehavior},
    utill::{read_message, send_message, NO_SHUTDOWN},
    wallet::AddressType,
};

use super::test_framework::*;

use log::{info, warn};
use std::{
    fs,
    net::TcpStream,
    process::Command,
    str::FromStr,
    sync::atomic::Ordering::Relaxed,
    thread,
    time::{Duration, Instant},
};

/// One RPC round trip: connect, send an authenticated request, read the reply.
fn rpc_call(rpc_port: u16, cookie: &str, request: RpcMsgReq) -> RpcMsgResp {
    let mut stream =
        TcpStream::connect(("127.0.0.1", rpc_port)).expect("maker RPC server should be listening");
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    send_message(
        &mut stream,
        &AuthenticatedRpcRequest {
            token: cookie.to_owned(),
            request,
        },
    )
    .expect("failed to send RPC request");
    let bytes = read_message(&mut stream).expect("failed to read RPC response");
    serde_cbor::from_slice(&bytes).expect("failed to decode RPC response")
}

#[test]
fn test_maker_rpc_server() {
    warn!("Running Test: Maker RPC Server");

    let makers_config_map = vec![(9502, Some(21801)), (19502, Some(21802))];
    let taker_behavior = vec![TakerBehavior::Normal];
    let maker_behaviors = vec![MakerBehavior::Normal, MakerBehavior::Normal];

    let (test_framework, mut takers, makers, block_generation_handle) =
        TestFramework::init::<BitcoindBackend>(makers_config_map, taker_behavior, maker_behaviors);

    let bitcoind = &test_framework.bitcoind;
    let taker = takers.get_mut(0).unwrap();

    let taker_original_balance = fund_taker(
        taker,
        bitcoind,
        3,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );
    fund_makers(
        &makers,
        bitcoind,
        4,
        Amount::from_btc(0.05).unwrap(),
        AddressType::P2TR,
    );

    info!("Starting Maker servers...");
    let maker_threads = makers
        .iter()
        .map(|maker| {
            let maker_clone = maker.clone();
            thread::spawn(move || {
                start_server(maker_clone).unwrap();
            })
        })
        .collect::<Vec<_>>();

    wait_for_makers_setup(&makers, 120);

    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let maker_spendable_balance = verify_maker_pre_swap_balances(&makers);

    // A completed swap gives the maker incoming swap coins and a swap id.
    let swap_params = SwapParams::new(ProtocolVersion::Taproot, Amount::from_sat(500000), 2)
        .with_tx_count([3, 3])
        .with_required_confirms(1);
    generate_blocks(bitcoind, 1);
    let summary = taker
        .prepare_swap(swap_params)
        .expect("Prepare should succeed");
    taker
        .start_swap(&summary.swap_id)
        .expect("OpenSwap should complete successfully");
    let swap_id = summary.swap_id.clone();
    info!("Swap {} completed, querying maker RPC", swap_id);

    // Same swap parameters as `taproot_swap`, so the same golden values apply.
    // Assert them before the RPC section, which moves funds via SendToAddress.
    taker
        .get_wallet()
        .write()
        .unwrap()
        .sync_and_save(&NO_SHUTDOWN)
        .unwrap();
    generate_blocks(bitcoind, 1);
    for maker in &makers {
        maker
            .wallet
            .write()
            .unwrap()
            .sync_and_save(&NO_SHUTDOWN)
            .unwrap();
    }

    let taker_balances = taker.get_wallet().read().unwrap().get_balances().unwrap();
    info!(
        "Taker balances: Regular: {}, Swap: {}, Contract: {}, Spendable: {}",
        taker_balances.regular,
        taker_balances.swap,
        taker_balances.contract,
        taker_balances.spendable,
    );
    assert_eq!(
        taker_balances.regular.to_sat(),
        14499076,
        "Taker regular balance mismatch"
    );
    assert_eq!(
        taker_balances.swap.to_sat(),
        494815,
        "Taker swap balance mismatch"
    );
    assert_eq!(
        taker_balances.contract.to_sat(),
        0,
        "Taker contract balance mismatch"
    );
    assert_eq!(taker_balances.fidelity, Amount::ZERO);
    assert_eq!(
        taker_original_balance
            .checked_sub(taker_balances.spendable)
            .unwrap()
            .to_sat(),
        6109,
        "Taker spendable balance change mismatch"
    );

    let expected_regular = [14500865u64, 14503103];
    let expected_swap = [499328u64, 497053];
    let expected_fee = [679u64, 642];
    for (i, (maker, original)) in makers.iter().zip(&maker_spendable_balance).enumerate() {
        let balances = maker.wallet.read().unwrap().get_balances().unwrap();
        info!(
            "Maker {} balances: Regular: {}, Swap: {}, Contract: {}, Fidelity: {}, Spendable: {}",
            i,
            balances.regular,
            balances.swap,
            balances.contract,
            balances.fidelity,
            balances.spendable,
        );
        assert_eq!(
            balances.regular.to_sat(),
            expected_regular[i],
            "Maker {} regular balance mismatch",
            i
        );
        assert_eq!(
            balances.swap.to_sat(),
            expected_swap[i],
            "Maker {} swap balance mismatch",
            i
        );
        assert_eq!(
            balances.contract.to_sat(),
            0,
            "Maker {} contract balance mismatch",
            i
        );
        assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
        assert_eq!(
            balances
                .spendable
                .checked_sub(*original)
                .unwrap_or(Amount::ZERO)
                .to_sat(),
            expected_fee[i],
            "Maker {} fee earned mismatch",
            i
        );
    }

    let target = &makers[0];
    let rpc_port = target.config.rpc_port;
    let data_dir = target.config.data_dir.clone();
    let cookie = fs::read_to_string(data_dir.join("rpc_cookie"))
        .expect("makerd should have written an RPC cookie");

    // ---- Ping ----
    assert!(
        matches!(
            rpc_call(rpc_port, &cookie, RpcMsgReq::Ping),
            RpcMsgResp::Pong
        ),
        "Ping must answer Pong"
    );

    // ---- Wallet queries ----
    match rpc_call(rpc_port, &cookie, RpcMsgReq::Utxo) {
        RpcMsgResp::UtxoResp { utxos } => {
            info!("Utxo: {} entries", utxos.len());
            assert!(!utxos.is_empty(), "a funded maker must report utxos");
        }
        other => panic!("Utxo returned {:?}", other),
    }

    // Unswept incoming swapcoins only. The swap completed, so the maker already
    // swept them; the proceeds show up under `Balances.swap`, asserted above.
    match rpc_call(rpc_port, &cookie, RpcMsgReq::SwapUtxo) {
        RpcMsgResp::SwapUtxoResp { utxos } => {
            info!("SwapUtxo: {} entries", utxos.len());
            assert!(
                utxos.is_empty(),
                "a swept swap leaves no incoming swapcoin utxos"
            );
        }
        other => panic!("SwapUtxo returned {:?}", other),
    }

    match rpc_call(rpc_port, &cookie, RpcMsgReq::ContractUtxo) {
        RpcMsgResp::ContractUtxoResp { utxos } => {
            info!("ContractUtxo: {} entries", utxos.len());
            assert!(
                utxos.is_empty(),
                "a swap that completed leaves no live contracts"
            );
        }
        other => panic!("ContractUtxo returned {:?}", other),
    }

    match rpc_call(rpc_port, &cookie, RpcMsgReq::FidelityUtxo) {
        RpcMsgResp::FidelityUtxoResp { utxos } => {
            info!("FidelityUtxo: {} entries", utxos.len());
            assert_eq!(utxos.len(), 1, "the maker holds exactly one fidelity bond");
        }
        other => panic!("FidelityUtxo returned {:?}", other),
    }

    match rpc_call(rpc_port, &cookie, RpcMsgReq::Balances) {
        RpcMsgResp::TotalBalanceResp(balances) => {
            info!(
                "Balances: regular {}, swap {}, contract {}, fidelity {}",
                balances.regular, balances.swap, balances.contract, balances.fidelity
            );
            // Must match what the wallet reports directly, asserted above.
            assert_eq!(balances.regular.to_sat(), expected_regular[0]);
            assert_eq!(balances.swap.to_sat(), expected_swap[0]);
            assert_eq!(balances.fidelity, Amount::from_btc(0.05).unwrap());
            assert_eq!(balances.contract, Amount::ZERO);
        }
        other => panic!("Balances returned {:?}", other),
    }

    let new_address = match rpc_call(rpc_port, &cookie, RpcMsgReq::NewAddress) {
        RpcMsgResp::NewAddressResp(addr) => {
            info!("NewAddress: {}", addr);
            Address::from_str(&addr)
                .expect("NewAddress must return a parseable address")
                .assume_checked()
        }
        other => panic!("NewAddress returned {:?}", other),
    };

    match rpc_call(rpc_port, &cookie, RpcMsgReq::GetDataDir) {
        RpcMsgResp::GetDataDirResp(dir) => assert_eq!(dir, data_dir, "GetDataDir mismatch"),
        other => panic!("GetDataDir returned {:?}", other),
    }

    match rpc_call(rpc_port, &cookie, RpcMsgReq::GetTorAddress) {
        RpcMsgResp::GetTorAddressResp(addr) => {
            assert_eq!(
                addr, "Maker is not running on TOR",
                "GetTorAddress mismatch"
            );
        }
        other => panic!("GetTorAddress returned {:?}", other),
    }

    match rpc_call(rpc_port, &cookie, RpcMsgReq::ListFidelity) {
        RpcMsgResp::ListBonds(list) => {
            info!("ListFidelity: {}", list);
            assert!(!list.is_empty(), "ListFidelity must describe the bond");
        }
        other => panic!("ListFidelity returned {:?}", other),
    }

    assert!(
        matches!(
            rpc_call(rpc_port, &cookie, RpcMsgReq::SyncWallet),
            RpcMsgResp::Pong
        ),
        "SyncWallet must answer Pong on success"
    );

    match rpc_call(
        rpc_port,
        &cookie,
        RpcMsgReq::VerifyDeniability {
            swap_id: swap_id.clone(),
        },
    ) {
        RpcMsgResp::VerifyDeniabilityResp(valid) => {
            assert!(valid, "the completed swap must be deniable");
        }
        other => panic!("VerifyDeniability returned {:?}", other),
    }

    // An unknown swap id must come back as an error, not as `false`.
    match rpc_call(
        rpc_port,
        &cookie,
        RpcMsgReq::VerifyDeniability {
            swap_id: "no-such-swap".to_string(),
        },
    ) {
        RpcMsgResp::ServerError(e) => info!("VerifyDeniability on unknown swap: {}", e),
        other => panic!("VerifyDeniability on unknown swap returned {:?}", other),
    }

    // ---- Mutating ----
    match rpc_call(
        rpc_port,
        &cookie,
        RpcMsgReq::SendToAddress {
            address: new_address.to_string(),
            amount: 100_000,
            feerate: 2.0,
        },
    ) {
        RpcMsgResp::SendToAddressResp(txid) => {
            info!("SendToAddress: {}", txid);
            assert!(!txid.is_empty(), "SendToAddress must return a txid");
        }
        other => panic!("SendToAddress returned {:?}", other),
    }

    // ---- The cookie is actually checked ----
    match rpc_call(rpc_port, "not-the-cookie", RpcMsgReq::Ping) {
        RpcMsgResp::ServerError(e) => {
            assert_eq!(e, "unauthorized", "wrong token must be rejected");
            info!("Unauthenticated request rejected");
        }
        other => panic!("A bad token was accepted: {:?}", other),
    }

    // ---- The binary itself, so argument parsing is covered too ----
    let output = Command::new(env!("CARGO_BIN_EXE_maker-cli"))
        .args([
            "-p",
            &format!("127.0.0.1:{rpc_port}"),
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

    // ---- Stop, last: it shuts the server down ----
    assert!(
        matches!(
            rpc_call(rpc_port, &cookie, RpcMsgReq::Stop),
            RpcMsgResp::Shutdown
        ),
        "Stop must answer Shutdown"
    );
    let deadline = Instant::now() + Duration::from_secs(60);
    while !makers[0].shutdown.load(Relaxed) {
        assert!(
            Instant::now() < deadline,
            "Stop did not shut the maker down within 60s"
        );
        thread::sleep(Duration::from_secs(1));
    }
    info!("Maker 0 shut down via RPC Stop");

    makers
        .iter()
        .for_each(|maker| maker.shutdown.store(true, Relaxed));
    maker_threads
        .into_iter()
        .for_each(|thread| thread.join().unwrap());

    info!("Maker RPC server test completed successfully!");

    test_framework.stop();
    block_generation_handle.join().unwrap();
}
