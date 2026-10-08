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
    maker::{AuthenticatedRpcRequest, RpcMsgReq as Req, RpcMsgResp as Resp},
    protocol::common_messages::ProtocolVersion,
    taker::SwapParams,
    utill::{read_message, send_message},
};

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
        taker: { regular: 14_499_538, swap: 496_789, contract: 0, fidelity: 0, loss: 3_673 },
        makers: {
            regular: [14_500_751, 14_502_170],
            swap: [499_664, 498_208],
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

    // ---- Queries ----
    assert_rpc!(rpc, {
        Req::Ping => Resp::Pong,
        Req::Utxo => Resp::UtxoResp { utxos } if !utxos.is_empty(),
        // Unswept incoming swapcoins only: the completed swap swept them, and
        // the proceeds show up under `Balances.swap`.
        Req::SwapUtxo => Resp::SwapUtxoResp { utxos } if utxos.is_empty(),
        // A swap that completed leaves no live contracts.
        Req::ContractUtxo => Resp::ContractUtxoResp { utxos } if utxos.is_empty(),
        Req::FidelityUtxo => Resp::FidelityUtxoResp { utxos } if utxos.len() == 1,
        Req::Balances => Resp::TotalBalanceResp(b)
            if (b.regular, b.swap, b.contract, b.fidelity)
                == (wallet.regular, wallet.swap, wallet.contract, wallet.fidelity),
        Req::GetDataDir => Resp::GetDataDirResp(dir) if dir == data_dir,
        Req::GetTorAddress => Resp::GetTorAddressResp(addr)
            if addr == "Maker is not running on TOR",
        Req::ListFidelity => Resp::ListBonds(list) if !list.is_empty(),
        Req::SyncWallet => Resp::Pong,
        Req::VerifyDeniability { swap_id: swap_id.clone() } => Resp::VerifyDeniabilityResp(true),
        // An unknown swap id is an error, not `false`.
        Req::VerifyDeniability { swap_id: "no-such-swap".to_string() } => Resp::ServerError(_),
    });

    // ---- Mutating ----
    let new_address = expect_resp!(
        rpc.call(Req::NewAddress),
        Resp::NewAddressResp(addr) => Address::from_str(&addr)
            .expect("NewAddress must return a parseable address")
            .assume_checked()
    );
    assert_rpc!(rpc, {
        Req::SendToAddress {
            address: new_address.to_string(),
            amount: 100_000,
            feerate: 2.0,
        } => Resp::SendToAddressResp(txid) if !txid.is_empty(),
    });

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
