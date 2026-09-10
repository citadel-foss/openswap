use std::{fs, net::TcpStream, path::PathBuf, time::Duration};

use clap::Parser;
use openswap::{
    maker::{AuthenticatedRpcRequest, MakerError, RpcMsgReq, RpcMsgResp},
    utill::{get_maker_dir, read_message, send_message, MIN_RELAY_FEE_RATE},
};

/// A simple command line app to operate the makerd server.
///
/// The app works as an RPC client for makerd, useful to access the server, retrieve information, and manage server operations.
///
/// For more detailed usage information, please refer: <https://github.com/citadel-foss/openswap/blob/master/docs/maker-cli.md>
///
/// This is early beta, and there are known and unknown bugs. Please report issues at: <https://github.com/citadel-foss/openswap/issues>
#[derive(Parser, Debug)]
#[command(version = option_env ! ("CARGO_PKG_VERSION").unwrap_or("unknown"),
author = option_env ! ("CARGO_PKG_AUTHORS").unwrap_or(""))]
struct App {
    /// Sets the rpc-port of Makerd
    #[arg(long, short = 'p', default_value = "127.0.0.1:6103")]
    rpc_port: String,
    /// Maker data directory used to read the RPC authentication cookie
    #[arg(long, short = 'd')]
    data_directory: Option<PathBuf>,
    /// The command to execute
    #[command(subcommand)]
    command: Commands,
}

#[derive(Parser, Debug)]
enum Commands {
    /// Sends a ping to makerd. Will return a pong.
    SendPing,
    /// Lists all utxos in the wallet. Including fidelity bonds.
    ListUtxo,
    /// Lists utxos received from incoming swaps.
    ListUtxoSwap,
    /// Lists HTLC contract utxos.
    ListUtxoContract,
    /// Lists fidelity bond utxos.
    ListUtxoFidelity,
    /// Get total wallet balances of different categories.
    /// regular: All single signature regular wallet coins (seed balance).
    /// swap: All 2of2 multisig coins received in swaps.
    /// contract: All live contract transaction balance locked in timelocks. If you see value in this field, you have unfinished or malfinished swaps. You can claim them back with the recover command.
    /// fidelity: All coins locked in fidelity bonds.
    /// spendable: Spendable amount in wallet (regular + swap balance).
    GetBalances,
    /// Gets a new bitcoin receiving address
    GetNewAddress,
    /// Send Bitcoin to an external address and return the txid.
    SendToAddress {
        /// Recipient's address.
        #[arg(long, short = 't')]
        address: String,
        /// Amount to send in sats
        #[arg(long, short = 'a')]
        amount: u64,
        /// Feerate in sats/vByte. Defaults to the 1 sats/vByte relay floor;
        /// below-floor or non-finite values are rejected.
        #[arg(long, short = 'f')]
        feerate: Option<f64>,
    },
    /// Show the server tor address
    ShowTorAddress,
    /// Show the data directory path
    ShowDataDir,
    /// Shutdown the makerd server
    Stop,
    /// Show all the fidelity bonds, current and previous, with an (index, {bond_proof, is_spent}) tuple.
    ShowFidelity,
    /// Sync the Maker wallet with the current blockchain state.
    SyncWallet,
    /// Verify the deniability proof for a specific swap.
    VerifyDeniability {
        /// The swap ID to verify.
        #[arg(long, short = 's')]
        swap_id: String,
    },
}

fn main() -> Result<(), MakerError> {
    let cli = App::parse();
    let data_dir = match cli.data_directory {
        Some(dir) => dir,
        None => get_maker_dir()?,
    };
    let rpc_cookie = fs::read_to_string(data_dir.join("rpc_cookie"))?
        .trim()
        .to_owned();

    let stream = TcpStream::connect(cli.rpc_port)?;

    match cli.command {
        Commands::SendPing => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::Ping)?;
        }
        Commands::ListUtxoContract => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::ContractUtxo)?;
        }
        Commands::ListUtxoFidelity => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::FidelityUtxo)?;
        }
        Commands::GetBalances => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::Balances)?;
        }
        Commands::ListUtxo => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::Utxo)?;
        }
        Commands::ListUtxoSwap => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::SwapUtxo)?;
        }
        Commands::GetNewAddress => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::NewAddress)?;
        }
        Commands::SendToAddress {
            address,
            amount,
            feerate,
        } => {
            let feerate = match feerate {
                // Below the relay floor the tx would not propagate.
                Some(rate) if !rate.is_finite() || rate < MIN_RELAY_FEE_RATE => {
                    return Err(MakerError::General(
                        "feerate must be finite and at least the 1 sats/vB relay floor",
                    ));
                }
                Some(rate) => rate,
                None => MIN_RELAY_FEE_RATE,
            };
            send_rpc_req(
                stream,
                &rpc_cookie,
                RpcMsgReq::SendToAddress {
                    address,
                    amount,
                    feerate,
                },
            )?;
        }
        Commands::ShowTorAddress => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::GetTorAddress)?;
        }
        Commands::ShowDataDir => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::GetDataDir)?;
        }
        Commands::Stop => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::Stop)?;
        }
        Commands::ShowFidelity => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::ListFidelity)?;
        }
        Commands::SyncWallet => {
            send_rpc_req(stream, &rpc_cookie, RpcMsgReq::SyncWallet)?;
        }
        Commands::VerifyDeniability { swap_id } => {
            send_rpc_req(
                stream,
                &rpc_cookie,
                RpcMsgReq::VerifyDeniability { swap_id },
            )?;
        }
    }

    Ok(())
}

fn send_rpc_req(
    mut stream: TcpStream,
    rpc_cookie: &str,
    request: RpcMsgReq,
) -> Result<(), MakerError> {
    stream.set_read_timeout(Some(Duration::from_secs(20)))?;
    stream.set_write_timeout(Some(Duration::from_secs(20)))?;

    send_message(
        &mut stream,
        &AuthenticatedRpcRequest {
            token: rpc_cookie.to_owned(),
            request,
        },
    )?;

    let response_bytes = read_message(&mut stream)?;
    let response: RpcMsgResp = serde_cbor::from_slice(&response_bytes)?;

    if matches!(response, RpcMsgResp::Pong) {
        println!("success");
    } else {
        println!("{response}");
    }

    Ok(())
}
