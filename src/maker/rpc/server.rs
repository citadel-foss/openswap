use std::{
    fs::{self, OpenOptions},
    io::{ErrorKind, Write},
    net::{TcpListener, TcpStream},
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex,
    },
    thread::sleep,
    time::{Duration, Instant},
};

use bitcoin::{
    secp256k1::rand::{rngs::OsRng, RngCore},
    Amount,
};

use serde::Deserialize;
use serde_cbor::{value::from_value, Value};

use super::messages::RpcMsgReq;
#[cfg(not(feature = "integration-test"))]
use crate::utill::TorError;
use crate::{
    blocklist::AddressBlocklist,
    lock_debug,
    maker::{
        api::{MakerServerConfig, ShutdownSignal},
        error::MakerError,
        rpc::messages::RpcMsgResp,
    },
    utill::{
        is_unusable_fee_rate, parse_checked_address, read_message, send_message,
        HEART_BEAT_INTERVAL, UTXO,
    },
    wallet::{infer_address_type, AddressType, Destination, Wallet},
};
use std::{path::Path, sync::RwLock};

const RPC_COOKIE_FILE: &str = "rpc_cookie";

/// How long a client may stay silent, or a reply may stay unsent.
const RPC_IO_TIMEOUT: Duration = Duration::from_secs(20);

/// Waits for the client's first byte in one-second slices, so an idle client
/// cannot hold off shutdown. `Ok(false)`: shutdown came first.
///
/// Call it after parking the stream in [`MakerRpc::rpc_client`]: shutdown sets
/// the flag before it closes the parked stream, so a stream parked too late to
/// be closed fails the first check here.
fn wait_for_request(stream: &TcpStream, shutdown: &AtomicBool) -> std::io::Result<bool> {
    stream.set_read_timeout(Some(Duration::from_secs(1)))?;
    let deadline = Instant::now() + RPC_IO_TIMEOUT;
    loop {
        if shutdown.load(Relaxed) {
            return Ok(false);
        }
        match stream.peek(&mut [0; 1]) {
            // Data or EOF: `read_message` takes it from here.
            Ok(_) => break,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                if Instant::now() >= deadline {
                    return Err(e);
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    stream.set_read_timeout(Some(RPC_IO_TIMEOUT))?;
    Ok(true)
}

/// Parks `stream` where shutdown can close it; `None` clears the slot.
fn park_client<M: MakerRpc>(maker: &M, stream: Option<TcpStream>) {
    if let Some(Ok(mut slot)) = maker.rpc_client().map(|slot| lock_debug!(slot.lock())) {
        *slot = stream;
    }
}

/// Answers one client. Returns false if shutdown came before its request.
fn serve_client<M: MakerRpc>(maker: &Arc<M>, stream: &mut TcpStream, rpc_cookie: &str) -> bool {
    let handled = match wait_for_request(stream, maker.shutdown()) {
        Ok(true) => handle_request(maker, stream, rpc_cookie),
        Ok(false) => return false,
        Err(e) => Err(e.into()),
    };
    // Do not cause hard error if a rpc request fails
    if let Err(e) = handled {
        log::error!("Error processing RPC Request: {e:?}");
        // Send the error back to client.
        if let Err(e) = send_message(stream, &RpcMsgResp::ServerError(format!("{e:?}"))) {
            log::error!("Error sending RPC response {e:?}");
        };
    }
    true
}

fn write_rpc_cookie(data_dir: &Path) -> Result<String, MakerError> {
    let mut bytes = [0_u8; 32];
    OsRng.fill_bytes(&mut bytes);
    let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    let mut file = options.open(data_dir.join(RPC_COOKIE_FILE))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(token.as_bytes())?;
    file.sync_all()?;
    Ok(token)
}

fn cookie_matches(provided: &str, expected: &str) -> bool {
    provided.len() == expected.len()
        && provided
            .bytes()
            .zip(expected.bytes())
            .fold(0_u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}

pub trait MakerRpc {
    fn wallet(&self) -> &RwLock<Wallet>;
    fn data_dir(&self) -> &Path;
    fn config(&self) -> &MakerServerConfig;
    fn shutdown(&self) -> &ShutdownSignal;
    /// Where the client being served is parked, so shutdown can close it
    /// under a blocked read.
    fn rpc_client(&self) -> Option<&Mutex<Option<TcpStream>>> {
        None
    }
    #[cfg(feature = "integration-test")]
    fn take_reserved_rpc_listener(&self) -> Option<TcpListener> {
        None
    }
    #[cfg(not(feature = "integration-test"))]
    fn get_tor_hostname(&self) -> Result<String, TorError>;
}

/// [`super::messages::AuthenticatedRpcRequest`] with the request left undecoded, so the token is
/// checked first and a request this build doesn't know isn't called "unauthorized".
#[derive(Deserialize)]
struct RawRpcRequest {
    token: String,
    request: Value,
}

fn handle_request<M: MakerRpc>(
    maker: &Arc<M>,
    socket: &mut TcpStream,
    rpc_cookie: &str,
) -> Result<(), MakerError> {
    let msg_bytes = read_message(socket)?;
    let envelope = match serde_cbor::from_slice::<RawRpcRequest>(&msg_bytes) {
        Ok(envelope) if cookie_matches(&envelope.token, rpc_cookie) => envelope,
        _ => {
            log::warn!(
                "Rejected unauthenticated RPC request from {}",
                socket
                    .peer_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "<unknown>".into())
            );
            send_message(socket, &RpcMsgResp::ServerError("unauthorized".to_string()))?;
            return Ok(());
        }
    };
    let rpc_request = match from_value::<RpcMsgReq>(envelope.request) {
        Ok(request) => request,
        Err(e) => {
            log::warn!("Rejected unknown RPC request: {e}");
            send_message(
                socket,
                &RpcMsgResp::ServerError(format!("unknown request: {e}")),
            )?;
            return Ok(());
        }
    };
    log::info!("RPC request received: {rpc_request:?}");

    let resp = match rpc_request {
        RpcMsgReq::Ping => RpcMsgResp::Pong,
        RpcMsgReq::ContractUtxo => {
            let utxos = lock_debug!(maker.wallet().read())?
                .list_live_timelock_contract_spend_info()
                .into_iter()
                .map(|(utxo, spend_info)| UTXO::from_utxo_data((utxo.clone(), spend_info.clone())))
                .collect();
            RpcMsgResp::ContractUtxoResp { utxos }
        }
        RpcMsgReq::FidelityUtxo => {
            let utxos = lock_debug!(maker.wallet().read())?
                .list_fidelity_spend_info()
                .into_iter()
                .map(|(utxo, spend_info)| UTXO::from_utxo_data((utxo.clone(), spend_info.clone())))
                .collect();
            RpcMsgResp::FidelityUtxoResp { utxos }
        }
        RpcMsgReq::Utxo => {
            let utxos = lock_debug!(maker.wallet().read())?
                .list_all_utxo_spend_info()
                .into_iter()
                .map(|(utxo, spend_info)| UTXO::from_utxo_data((utxo.clone(), spend_info.clone())))
                .collect();
            RpcMsgResp::UtxoResp { utxos }
        }
        RpcMsgReq::SwapUtxo => {
            let utxos = lock_debug!(maker.wallet().read())?
                .list_incoming_swap_coin_utxo_spend_info()
                .into_iter()
                .map(|(utxo, spend_info)| UTXO::from_utxo_data((utxo.clone(), spend_info.clone())))
                .collect();
            RpcMsgResp::SwapUtxoResp { utxos }
        }
        RpcMsgReq::Balances => {
            let balances = lock_debug!(maker.wallet().read())?.get_balances()?;
            RpcMsgResp::TotalBalanceResp(balances)
        }
        RpcMsgReq::NewAddress => {
            let new_address = lock_debug!(maker.wallet().write())?
                .get_next_external_address(AddressType::P2TR)?;
            RpcMsgResp::NewAddressResp(new_address.to_string())
        }
        RpcMsgReq::SendToAddress {
            address,
            amount,
            feerate,
        } => {
            let amount = Amount::from_sat(amount);
            // Below the relay floor the tx would not propagate; an invalid
            // rate is the caller's error, not something to repair.
            if is_unusable_fee_rate(feerate) {
                RpcMsgResp::ServerError(
                    "SendToAddress feerate must be finite and at least the 1 sats/vB relay floor"
                        .to_string(),
                )
            } else {
                let destination_address = parse_checked_address(&address, maker.config().network)
                    .map_err(MakerError::from)?;

                let address_type = infer_address_type(&destination_address.script_pubkey());
                let outputs = vec![(destination_address, amount)];
                let destination = Destination::Multi {
                    outputs,
                    op_return_data: None,
                    change_address_type: AddressType::P2TR,
                };

                // One guard from selection through broadcast, so a swap thread
                // cannot claim the selected coins in between.
                let txid = {
                    let mut wallet = lock_debug!(maker.wallet().write())?;
                    let coins_to_send =
                        wallet.coin_select(amount, feerate, address_type, None, None)?;
                    let tx = wallet.spend_from_wallet(feerate, destination, &coins_to_send)?;
                    let txid = wallet.send_tx(&tx)?;
                    // The cache lists the spent coins until the sync below; lock
                    // them so no swap plans them in between.
                    let spent: Vec<_> =
                        tx.input.iter().map(|input| input.previous_output).collect();
                    wallet.lock_utxos(&spent);
                    txid
                };

                log::info!("Sync at:----handle_request----");
                lock_debug!(maker.wallet().write())?.sync_and_save(maker.shutdown())?;

                RpcMsgResp::SendToAddressResp(txid.to_string())
            }
        }
        RpcMsgReq::GetDataDir => RpcMsgResp::GetDataDirResp(maker.data_dir().to_path_buf()),
        RpcMsgReq::GetTorAddress => {
            #[cfg(feature = "integration-test")]
            {
                RpcMsgResp::GetTorAddressResp("Maker is not running on TOR".to_string())
            }
            #[cfg(not(feature = "integration-test"))]
            {
                let hostname = maker.get_tor_hostname()?;
                RpcMsgResp::GetTorAddressResp(hostname)
            }
        }
        RpcMsgReq::Stop => {
            maker.shutdown().store(true, Relaxed);
            RpcMsgResp::Shutdown
        }

        RpcMsgReq::ListFidelity => {
            let list = lock_debug!(maker.wallet().read())?.display_fidelity_bonds()?;
            RpcMsgResp::ListBonds(list)
        }
        RpcMsgReq::SyncWallet => {
            log::info!("Initializing wallet sync");
            let mut wallet = lock_debug!(maker.wallet().write())?;
            if let Err(e) = wallet.sync_and_save(maker.shutdown()) {
                RpcMsgResp::ServerError(e.to_string())
            } else {
                log::info!("Completed wallet sync");
                RpcMsgResp::Pong
            }
        }
        RpcMsgReq::VerifyDeniability { swap_id } => {
            match lock_debug!(maker.wallet().read())?.verify_deniability(&swap_id) {
                Ok(valid) => RpcMsgResp::VerifyDeniabilityResp(valid),
                Err(e) => RpcMsgResp::ServerError(e.to_string()),
            }
        }
        RpcMsgReq::BlocklistAdd { entries } => {
            match AddressBlocklist::load(maker.data_dir(), maker.config().network)
                .and_then(|mut blocklist| blocklist.add(entries))
            {
                Ok(outcome) => RpcMsgResp::BlocklistAddResp(outcome),
                Err(error) => RpcMsgResp::ServerError(error.to_string()),
            }
        }
        RpcMsgReq::BlocklistRemove { addresses } => {
            match AddressBlocklist::load(maker.data_dir(), maker.config().network)
                .and_then(|mut blocklist| blocklist.remove(addresses))
            {
                Ok(removed) => RpcMsgResp::BlocklistRemoveResp(removed),
                Err(error) => RpcMsgResp::ServerError(error.to_string()),
            }
        }
    };

    if let Err(e) = send_message(socket, &resp) {
        log::error!("Error sending RPC response {e:?}");
    }

    Ok(())
}

pub(crate) fn start_rpc_server<M: MakerRpc>(maker: Arc<M>) -> Result<(), MakerError> {
    let rpc_port = maker.config().rpc_port;
    // A reserved socket means the framework already holds this port; binding
    // again would fail against our own reservation.
    #[cfg(feature = "integration-test")]
    let reserved = maker.take_reserved_rpc_listener();
    #[cfg(not(feature = "integration-test"))]
    let reserved: Option<TcpListener> = None;
    let listener = match reserved {
        Some(listener) => listener,
        None => TcpListener::bind(("127.0.0.1", rpc_port))?,
    };
    let rpc_cookie = write_rpc_cookie(maker.data_dir())?;
    let rpc_socket = format!("127.0.0.1:{rpc_port}");
    let listener = Arc::new(listener);
    log::info!(
        "[{}] RPC socket binding successful at {}",
        rpc_port,
        rpc_socket
    );

    listener.set_nonblocking(true)?;

    while !maker.shutdown().load(Relaxed) {
        match listener.accept() {
            Ok((mut stream, addr)) => {
                log::info!("Got RPC request from: {addr}");
                stream.set_write_timeout(Some(RPC_IO_TIMEOUT))?;
                park_client(&*maker, Some(stream.try_clone()?));
                let served = serve_client(&maker, &mut stream, &rpc_cookie);
                park_client(&*maker, None);
                if !served {
                    break;
                }
            }

            Err(e) => {
                if e.kind() == ErrorKind::WouldBlock {
                    // do nothing
                } else {
                    log::error!("Error accepting RPC connection: {e:?}");
                }
            }
        }

        sleep(HEART_BEAT_INTERVAL);
    }

    if let Err(e) = fs::remove_file(maker.data_dir().join(RPC_COOKIE_FILE)) {
        if e.kind() != ErrorKind::NotFound {
            log::warn!("Failed to remove RPC cookie during shutdown: {e}");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{maker::rpc::messages::AuthenticatedRpcRequest, utill::MIN_RELAY_FEE_RATE};
    use serde::Serialize;
    use std::collections::BTreeMap;

    /// A maker double for the fee-rate guard tests; the guard fires before
    /// any wallet access, so `wallet()` is never reached.
    struct GuardDouble {
        config: MakerServerConfig,
        data_dir: std::path::PathBuf,
        shutdown: ShutdownSignal,
    }

    impl MakerRpc for GuardDouble {
        fn wallet(&self) -> &RwLock<Wallet> {
            unreachable!("the fee-rate guard fires before any wallet access")
        }
        fn data_dir(&self) -> &Path {
            &self.data_dir
        }
        fn config(&self) -> &MakerServerConfig {
            &self.config
        }
        fn shutdown(&self) -> &ShutdownSignal {
            &self.shutdown
        }
        #[cfg(not(feature = "integration-test"))]
        fn get_tor_hostname(&self) -> Result<String, TorError> {
            unreachable!("no request in these tests asks for the hostname")
        }
    }

    /// Sends `envelope(cookie)` to a fresh handler and returns its reply.
    fn rpc_round_trip<T: Serialize>(
        envelope: impl FnOnce(&str) -> T,
    ) -> Result<RpcMsgResp, MakerError> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut server, _) = listener.accept().unwrap();

        let dir = bitcoind::tempfile::tempdir().unwrap();
        let cookie = write_rpc_cookie(dir.path()).unwrap();
        let double = Arc::new(GuardDouble {
            config: MakerServerConfig::default(),
            data_dir: dir.path().to_path_buf(),
            shutdown: ShutdownSignal::new(),
        });

        send_message(&mut client, &envelope(&cookie)).unwrap();
        handle_request(&double, &mut server, &cookie)?;
        Ok(serde_cbor::from_slice(&read_message(&mut client).unwrap()).unwrap())
    }

    fn rpc_send_to_address(address: &str, feerate: f64) -> Result<RpcMsgResp, MakerError> {
        rpc_round_trip(|cookie| AuthenticatedRpcRequest {
            token: cookie.to_string(),
            request: RpcMsgReq::SendToAddress {
                address: address.to_string(),
                amount: 50_000,
                feerate,
            },
        })
    }

    #[test]
    fn rpc_checks_the_token_before_the_request() {
        let envelope = |token: &str| {
            Value::Map(BTreeMap::from([
                (Value::Text("token".into()), Value::Text(token.into())),
                (
                    Value::Text("request".into()),
                    Value::Text("FutureRequest".into()),
                ),
            ]))
        };
        let reply = rpc_round_trip(envelope).unwrap();
        assert!(
            matches!(&reply, RpcMsgResp::ServerError(e) if e.contains("unknown request")),
            "{:?}",
            reply
        );
        let reply = rpc_round_trip(|_| envelope("wrong")).unwrap();
        assert!(
            matches!(&reply, RpcMsgResp::ServerError(e) if e == "unauthorized"),
            "{:?}",
            reply
        );
    }

    #[test]
    fn compat_rpc_old_requests_and_future_envelope_fields_keep_working() {
        // Unit request names and envelope keys from the v0.2.3 writer.
        for request in ["Ping", "GetDataDir"] {
            let reply = rpc_round_trip(|cookie| {
                Value::Map(BTreeMap::from([
                    (Value::Text("token".into()), Value::Text(cookie.into())),
                    (Value::Text("request".into()), Value::Text(request.into())),
                    (
                        Value::Text("future_field".into()),
                        Value::Bytes(vec![1, 2, 3]),
                    ),
                ]))
            })
            .unwrap();
            assert!(if request == "Ping" {
                matches!(reply, RpcMsgResp::Pong)
            } else {
                matches!(reply, RpcMsgResp::GetDataDirResp(_))
            });
        }
    }

    #[test]
    fn compat_rpc_unknown_bodies_authenticate_before_request_decode() {
        for request in [
            Value::Text("FutureRequest".into()),
            Value::Map(BTreeMap::from([(
                Value::Text("FutureRequest".into()),
                Value::Map(BTreeMap::new()),
            )])),
            Value::Map(BTreeMap::from([(
                Value::Text("SendToAddress".into()),
                Value::Bool(true),
            )])),
        ] {
            for valid_token in [false, true] {
                let reply = rpc_round_trip(|cookie| {
                    Value::Map(BTreeMap::from([
                        (
                            Value::Text("token".into()),
                            Value::Text(if valid_token { cookie } else { "wrong" }.into()),
                        ),
                        (Value::Text("request".into()), request.clone()),
                    ]))
                })
                .unwrap();
                assert!(
                    matches!(reply, RpcMsgResp::ServerError(reason) if if valid_token { reason.starts_with("unknown request:") } else { reason == "unauthorized" })
                );
            }
        }
    }

    #[test]
    fn send_to_address_rejects_unusable_rates_over_rpc() {
        for rate in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 0.5] {
            let RpcMsgResp::ServerError(e) = rpc_send_to_address("bcrt1qinvalid", rate).unwrap()
            else {
                panic!("rate {} must be refused with a server error", rate);
            };
            assert!(
                e.contains("relay floor"),
                "rate {} must trip the floor guard: {}",
                rate,
                e
            );
        }
    }

    #[test]
    fn send_to_address_clears_the_relay_floor_over_rpc() {
        // The invalid address fails AFTER the rate check, so the propagated
        // error proves the floor rate cleared the guard instead of tripping it.
        let e = rpc_send_to_address("bcrt1qinvalid", MIN_RELAY_FEE_RATE).unwrap_err();
        assert!(
            !format!("{e:?}").contains("relay floor"),
            "the floor rate must clear the rate check: {:?}",
            e
        );
    }

    #[test]
    fn rpc_cookie_is_random_and_authenticated() {
        let dir = bitcoind::tempfile::tempdir().unwrap();

        let first = write_rpc_cookie(dir.path()).unwrap();
        let second = write_rpc_cookie(dir.path()).unwrap();
        assert_eq!(second.len(), 64);
        assert_ne!(first, second);
        assert!(cookie_matches(&second, &second));
        assert!(!cookie_matches(&first, &second));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dir.path().join(RPC_COOKIE_FILE))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }
}
