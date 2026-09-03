//! Various utility and helper functions for both Taker and Maker.

use bitcoin::{
    hashes::Hash,
    key::{rand::thread_rng, Keypair},
    secp256k1::{All, Secp256k1, SecretKey},
    Address, Amount, FeeRate, Network, PublicKey, ScriptBuf, WitnessProgram, WitnessVersion,
};
use bitcoind::bitcoincore_rpc::json::ListUnspentResultEntry;
#[cfg(not(feature = "integration-test"))]
use bitcoind::bitcoincore_rpc::jsonrpc::base64;
use crossterm::{
    cursor::MoveTo,
    event::{
        read, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, MouseButton, MouseEventKind,
    },
    execute, queue,
    style::Print,
    terminal::{disable_raw_mode, enable_raw_mode, size, Clear, ClearType},
};
use log::LevelFilter;
use log4rs::{
    append::{console::ConsoleAppender, file::FileAppender},
    config::{Appender, Logger, Root},
    Config,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::max,
    collections::HashMap,
    env, fs,
    io::{self, stdout, BufReader, BufWriter, ErrorKind, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{Once, OnceLock},
    time::Duration,
};

static LOGGER: OnceLock<()> = OnceLock::new();

/// Process-wide `Secp256k1<All>` context. `Secp256k1::new()` allocates a ~1.5 MiB
/// precomputation table; per the upstream secp256k1 docs the recommended
/// pattern is to construct one context per process and share references. We do
/// that here so address-derivation hot paths (which can iterate 2,000+ times
/// per sync at the production gap limit) don't repeatedly allocate.
pub(crate) fn global_secp() -> &'static Secp256k1<All> {
    static SECP: OnceLock<Secp256k1<All>> = OnceLock::new();
    SECP.get_or_init(Secp256k1::new)
}

use crate::{
    error::NetError,
    lock_debug,
    protocol::{contract::derive_maker_pubkey_and_nonce, error::ProtocolError},
    wallet::{SecretMnemonic, UTXOSpendInfo, WalletError},
};

const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &str = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const MASK_LOW_35_BITS: u64 = 0x7ffffffff;
const SHIFT_FOR_C0: u64 = 35;
const CHECKSUM_FINAL_XOR_VALUE: u64 = 1;

/// Global heartbeat interval used during waiting periods in critical situations.
pub(crate) const HEART_BEAT_INTERVAL: Duration = Duration::from_secs(3);

/// Never set. Passing this makes "this operation cannot be aborted" explicit
/// for callers that have no shutdown signal to wire in.
pub static NO_SHUTDOWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// How long to wait for a peer's tx to reach our mempool. Covers relay propagation
/// and backend lag only. Sized above a full Electrum reconnect cycle so a transport
/// blip does not fail an honest swap.
pub const TX_BROADCAST_TIMEOUT: Duration = Duration::from_secs(120);

/// Total deadline for a watched tx to confirm. Without it a low-fee counterparty
/// tx parks a swap thread forever and quietly spends the timelock reaction margin.
pub const TX_CONFIRMATION_TIMEOUT: Duration = Duration::from_secs(3600);

/// Floor for funding-tx confirmations: applied when the configured
/// `required_confirms` is absent or 0.
pub const MIN_REQUIRED_CONFIRM: u32 = 1;

/// Minimum fee rate in sats/vb for all transactions
/// This replaces the hardcoded MINER_FEE constant
pub const MIN_FEE_RATE: f64 = 2.0;

/// Absolute fee rate floor in sats/vb — Bitcoin Core's default
/// `minrelaytxfee`. Configurable fee rates (e.g. the fidelity bond) may go
/// below [`MIN_FEE_RATE`] but never below this, or transactions stop relaying.
pub const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Maximum size of a length-prefixed protocol or RPC message.
/// 10 MiB limit
pub const MAX_RPC_MESSAGE_SIZE: usize = 10 * 1024 * 1024;

/// Get the system specific home directory.
/// Uses "/tmp" directory for integration tests
fn get_home_dir() -> io::Result<PathBuf> {
    if cfg!(test) {
        Ok(env::temp_dir())
    } else {
        dirs::home_dir().ok_or_else(|| {
            io::Error::new(ErrorKind::NotFound, "could not determine home directory")
        })
    }
}

/// Get the default data directory. `~/.openswap`.
fn get_data_dir() -> io::Result<PathBuf> {
    Ok(get_home_dir()?.join(".openswap"))
}

/// Get the Maker Directory
pub fn get_maker_dir() -> io::Result<PathBuf> {
    Ok(get_data_dir()?.join("maker"))
}

/// Get the Taker Directory
pub fn get_taker_dir() -> io::Result<PathBuf> {
    Ok(get_data_dir()?.join("taker"))
}

/// Creates a FeeRate from the global MIN_FEE_RATE constant
/// This provides type-safe fee calculations throughout the codebase
pub fn get_min_fee_rate() -> Option<FeeRate> {
    FeeRate::from_sat_per_vb(MIN_FEE_RATE as u64)
}

/// Calculate fee in satoshis for given virtual bytes using MIN_FEE_RATE
pub fn calculate_fee_sats(vbytes: u64) -> u64 {
    let fee_rate = get_min_fee_rate().expect("MIN_FEE_RATE should be valid");
    fee_rate
        .fee_vb(vbytes)
        .expect("fee calculation should not overflow")
        .to_sat()
}

/// Estimated on-chain miner cost (sats) a maker bears per swap contract: a funding tx
/// (overhead 11 + P2WPKH input 68 + P2WSPK change 31 + (P2TR/P2WSPK) payment output 43 = 153 vB)
/// plus a sweep tx (overhead 11 + input 68 + self-payment output 43 = 122 vB).
///
/// Used both by the maker (for routed amount) and by taker's `expected_amount_for_hop`
pub fn estimate_funding_tx_fee_sats() -> u64 {
    calculate_fee_sats((11 + 68 + 31 + 43) + (11 + 68 + 43))
}

/// Sets up the logger for the taker component.
///
/// This method initializes the logging configuration for the taker, directing logs to both
/// the console and a file. It sets the `RUST_LOG` environment variable to provide default
/// log levels and configures log4rs with the specified filter level for fine-grained control
/// of log verbosity.
pub fn setup_taker_logger(filter: LevelFilter, is_stdout: bool, datadir: Option<PathBuf>) {
    LOGGER.get_or_init(|| {
        let filter = std::env::var("RUST_LOG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(filter);
        // File logging is best-effort: without a data dir or a writable log
        // file we still want stdout logging, not a panic.
        let file_appender = match datadir.map(Ok).unwrap_or_else(get_taker_dir) {
            Ok(dir) => {
                let log_path = dir.join("debug.log");
                match FileAppender::builder().build(&log_path) {
                    Ok(appender) => Some(appender),
                    Err(e) => {
                        eprintln!(
                            "failed to open log file {}: {e}; logging without file appender",
                            log_path.display()
                        );
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}; logging without file appender");
                None
            }
        };
        let has_file = file_appender.is_some();
        let stdout = ConsoleAppender::builder().build();

        let mut config = Config::builder();
        if let Some(file_appender) = file_appender {
            config = config.appender(Appender::builder().build("file", Box::new(file_appender)));
        }
        if is_stdout {
            config = config.appender(Appender::builder().build("stdout", Box::new(stdout)));
        }

        // Reference only appenders registered above, so config build stays
        // infallible when the file appender is missing.
        let mut root = Root::builder();
        if has_file {
            root = root.appender("file");
        }
        if is_stdout {
            root = root.appender("stdout");
        }

        let config = config
            .logger(Logger::builder().build("bitcoincore_rpc", LevelFilter::Off))
            .build(root.build(filter))
            .unwrap();
        match log4rs::init_config(config) {
            Ok(_) => log::info!("✅ Logger initialized successfully"),
            Err(e) => log::error!("❌ Failed to initialize logger: {e}"),
        }
    });
}

/// Sets up the logger for the Maker component.
///
/// This method initializes the logging configuration for the maker, directing logs to both
/// the console and a file. It sets the `RUST_LOG` environment variable to provide default
/// log levels and configures log4rs with the specified filter level for fine-grained control
/// of log verbosity.
pub fn setup_maker_logger(filter: LevelFilter, data_dir: Option<PathBuf>) {
    LOGGER.get_or_init(|| {
        let filter = std::env::var("RUST_LOG")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(filter);
        // File logging is best-effort: without a data dir or a writable log
        // file we still want stdout logging, not a panic.
        let file_appender = match data_dir.map(Ok).unwrap_or_else(get_maker_dir) {
            Ok(dir) => {
                let log_path = dir.join("debug.log");
                match FileAppender::builder().build(&log_path) {
                    Ok(appender) => Some(appender),
                    Err(e) => {
                        eprintln!(
                            "failed to open log file {}: {e}; logging without file appender",
                            log_path.display()
                        );
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("{e}; logging without file appender");
                None
            }
        };
        let has_file = file_appender.is_some();
        let stdout = ConsoleAppender::builder().build();

        let mut config =
            Config::builder().appender(Appender::builder().build("stdout", Box::new(stdout)));
        if let Some(file_appender) = file_appender {
            config = config.appender(Appender::builder().build("file", Box::new(file_appender)));
        }

        // The additive root logger already echoes maker lines to stdout, so the
        // no-file fallback adds no appender — an own stdout would print twice.
        let maker_logger = if has_file {
            Logger::builder().appender("file")
        } else {
            Logger::builder()
        };

        let config = config
            .logger(Logger::builder().build("bitcoincore_rpc", LevelFilter::Off))
            .logger(maker_logger.build("openswap::maker", filter))
            .build(Root::builder().appender("stdout").build(filter))
            .unwrap();

        match log4rs::init_config(config) {
            Ok(_) => log::info!("✅ Logger initialized successfully"),
            Err(e) => log::error!("❌ Failed to initialize logger: {e}"),
        }
    });
}

/// Setup function that will only run once, even if called multiple times.
/// Takes log level to set the desired logging verbosity
pub fn setup_logger(filter: LevelFilter, data_dir: Option<PathBuf>) {
    Once::new().call_once(|| {
        // env::set_var("RUST_LOG", "openswap=info");
        setup_taker_logger(filter, true, data_dir.as_ref().map(|d| d.join("taker")));
        setup_maker_logger(filter, data_dir.as_ref().map(|d| d.join("maker")));
    });
}

/// Logs the stable identity used to find a join without a matching completion.
pub(crate) fn log_shutdown_join_start(component: &str, thread: &std::thread::Thread) {
    log::info!(
        "shutdown_join_start pid={} component={} thread={} id={:?}",
        std::process::id(),
        component,
        thread.name().unwrap_or("unknown"),
        thread.id()
    );
}

/// Logs the matching completion and whether the owned thread panicked.
pub(crate) fn log_shutdown_join_done(component: &str, thread: &std::thread::Thread, outcome: &str) {
    log::info!(
        "shutdown_join_done pid={} component={} thread={} id={:?} outcome={}",
        std::process::id(),
        component,
        thread.name().unwrap_or("unknown"),
        thread.id(),
        outcome
    );
}

/// Sends a protocol or RPC message through a stream.
///
/// The wire format is a 4-byte big-endian u32 length prefix followed
/// by the CBOR-serialized message payload.
pub fn send_message(
    socket_writer: &mut TcpStream,
    message: &impl serde::Serialize,
) -> Result<(), NetError> {
    let mut writer = BufWriter::new(socket_writer);
    let msg_bytes = serde_cbor::ser::to_vec(message)?;
    let msg_len = (msg_bytes.len() as u32).to_be_bytes();
    let mut to_send = Vec::with_capacity(msg_bytes.len() + msg_len.len());
    to_send.extend(msg_len);
    to_send.extend(msg_bytes);
    writer.write_all(&to_send)?;
    writer.flush()?;
    Ok(())
}

/// Reads a protocol or RPC message from a stream.
///
/// Expects the same wire format written by [`send_message`]: a 4-byte big-endian u32 length
/// prefix followed by the CBOR-serialized message payload.
pub fn read_message(reader: &mut TcpStream) -> Result<Vec<u8>, NetError> {
    let mut reader = BufReader::new(reader);
    // length of incoming data
    let mut len_buff = [0u8; 4];
    reader.read_exact(&mut len_buff)?; // This can give UnexpectedEOF error if theres no data to read
    let length = u32::from_be_bytes(len_buff);

    if length as usize > MAX_RPC_MESSAGE_SIZE {
        return Err(NetError::MessageTooLarge);
    }

    // the actual data
    let mut buffer = vec![0; length as usize];
    let mut total_read = 0;

    while total_read < length as usize {
        match reader.read(&mut buffer[total_read..]) {
            Ok(0) => return Err(NetError::ReachedEOF), // Connection closed
            Ok(n) => total_read += n,
            // A read timeout also arrives as WouldBlock; looping on it turns a
            // silent peer into a permanent wedge instead of a timed-out read.
            Err(e) if matches!(e.kind(), ErrorKind::Interrupted) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(buffer)
}

/// Generate The Maker's Multisig and HashLock keys and respective nonce values.
/// Nonce values are random integers and resulting Pubkeys are derived by tweaking
///
/// the Maker's advertised Pubkey with these two nonces.
#[allow(clippy::type_complexity)]
/// Generate maker keys from the Maker's advertised Pubkey with nonces.
pub(crate) fn generate_maker_keys(
    tweakable_point: &PublicKey,
    count: u32,
) -> Result<
    (
        Vec<PublicKey>,
        Vec<SecretKey>,
        Vec<PublicKey>,
        Vec<SecretKey>,
    ),
    ProtocolError,
> {
    // Closure to derive public keys and nonces
    let derive_keys = |count: u32| {
        (0..count)
            .map(|_| derive_maker_pubkey_and_nonce(tweakable_point))
            .collect::<Result<Vec<_>, _>>()
    };

    // Generate multisig and hashlock keys.
    let (multisig_pubkeys, multisig_nonces): (Vec<_>, Vec<_>) =
        derive_keys(count)?.into_iter().unzip();
    let (hashlock_pubkeys, hashlock_nonces): (Vec<_>, Vec<_>) =
        derive_keys(count)?.into_iter().unzip();

    Ok((
        multisig_pubkeys,
        multisig_nonces,
        hashlock_pubkeys,
        hashlock_nonces,
    ))
}

/// Extracts hierarchical deterministic (HD) path components from a descriptor.
///
/// Parses an input descriptor string and returns `Some` with a tuple containing the HD path
/// components if it's an HD descriptor. If the descriptor doesn't have path info, it returns `None`.
/// This method only works for single key descriptors.
pub(crate) fn get_hd_path_from_descriptor(descriptor: &str) -> Option<(&str, u32, i32)> {
    let open = descriptor.find('[');
    let close = descriptor.find(']');

    let path = if let (Some(open), Some(close)) = (open, close) {
        &descriptor[open + 1..close]
    } else {
        // Debug log, because if it doesn't have path, its not an error.
        log::error!("Descriptor doesn't have path = {descriptor}");
        return None;
    };

    let path_chunks: Vec<&str> = path.split('/').collect();
    if path_chunks.len() != 3 {
        // Debug log, because if it doesn't have path, its not an error.
        //log::warn!("Path is not a triplet. Path chunks = {:?}", path_chunks);
        return None;
    }

    if let (Ok(addr_type), Ok(index)) =
        (path_chunks[1].parse::<u32>(), path_chunks[2].parse::<i32>())
    {
        Some((path_chunks[0], addr_type, index))
    } else {
        None
    }
}

/// Generates a keypair using the secp256k1 elliptic curve.
pub(crate) fn generate_keypair() -> (PublicKey, SecretKey) {
    let keypair = Keypair::new(&Secp256k1::new(), &mut thread_rng());
    let pubkey = PublicKey {
        compressed: true,
        inner: keypair.public_key(),
    };
    (pubkey, keypair.secret_key())
}

/// Convert a redeemscript into p2wsh scriptpubkey.
pub(crate) fn redeemscript_to_scriptpubkey(
    redeemscript: &ScriptBuf,
) -> Result<ScriptBuf, ProtocolError> {
    let witness_program = WitnessProgram::new(
        WitnessVersion::V0,
        &redeemscript.wscript_hash().to_byte_array(),
    )?;
    Ok(ScriptBuf::new_witness_program(&witness_program))
}

/// Parses a TOML file into a HashMap of key-value pairs.
pub(crate) fn parse_toml<P: AsRef<Path>>(path: P) -> io::Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)?;

    let mut config_map = HashMap::new();

    for line in content.lines().filter(|line| !line.is_empty()) {
        if let Some((key, value)) = line.split_once('=') {
            let value = value.trim();
            // Strip surrounding double quotes for TOML-style string values.
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or(value);
            config_map.insert(key.trim().to_string(), value.to_string());
        }
    }

    Ok(config_map)
}

/// Parses a value of type T from an Option<&String>, returning the default if parsing fails or is None
pub(crate) fn parse_field<T: std::str::FromStr>(value: Option<&String>, default: T) -> T {
    value
        .and_then(|value| value.parse::<T>().ok())
        .unwrap_or(default)
}

fn polynomial_modulus(mut checksum: u64, value: u64) -> u64 {
    let upper_bits = checksum >> SHIFT_FOR_C0;
    checksum = ((checksum & MASK_LOW_35_BITS) << 5) ^ value;

    static FEEDBACK_TERMS: [(u64, u64); 5] = [
        (0x1, 0xf5dee51989),
        (0x2, 0xa9fdca3312),
        (0x4, 0x1bab10e32d),
        (0x8, 0x3706b1677a),
        (0x10, 0x644d626ffd),
    ];

    for &(bit, term) in FEEDBACK_TERMS.iter() {
        if (upper_bits & bit) != 0 {
            checksum ^= term;
        }
    }

    checksum
}

/// Represents basic UTXO details, useful for pretty printing in the apps.
#[derive(Debug, Serialize, Deserialize)]
pub struct UTXO {
    addr: String,
    amount: Amount,
    confirmations: u32,
    utxo_type: String,
}

impl UTXO {
    /// Creates an UTXO from detailed internal utxo data
    pub fn from_utxo_data(data: (ListUnspentResultEntry, UTXOSpendInfo)) -> Self {
        let (entry, spend_info) = data;
        let addr = entry
            .address
            .as_ref()
            .map(|addr| addr.clone().assume_checked().to_string())
            .unwrap_or_else(|| format!("script_{}", entry.script_pub_key));
        Self {
            addr,
            amount: entry.amount,
            confirmations: entry.confirmations,
            utxo_type: spend_info.to_string(),
        }
    }
}

/// Parse a user-provided address and enforce the expected network.
pub(crate) fn parse_checked_address(
    address: &str,
    network: Network,
) -> Result<Address, WalletError> {
    let unchecked = Address::from_str(address).map_err(WalletError::InvalidAddress)?;
    unchecked.require_network(network).map_err(|e| {
        WalletError::General(format!(
            "Address Network Mismatch | Expected : {network} | Details: {e}"
        ))
    })
}

/// Compute the checksum of a descriptor
pub(crate) fn compute_checksum(descriptor: &str) -> Result<String, WalletError> {
    let mut checksum = CHECKSUM_FINAL_XOR_VALUE;
    let mut accumulated_value = 0;
    let mut group_count = 0;

    for character in descriptor.chars() {
        let position = INPUT_CHARSET
            .find(character)
            .ok_or(ProtocolError::General("Descriptor invalid"))? as u64;
        checksum = polynomial_modulus(checksum, position & 31);
        accumulated_value = accumulated_value * 3 + (position >> 5);
        group_count += 1;

        if group_count == 3 {
            checksum = polynomial_modulus(checksum, accumulated_value);
            accumulated_value = 0;
            group_count = 0;
        }
    }

    if group_count > 0 {
        checksum = polynomial_modulus(checksum, accumulated_value);
    }

    // Finalize checksum by feeding zeros.
    (0..8).for_each(|_| {
        checksum = polynomial_modulus(checksum, 0);
    });
    checksum ^= CHECKSUM_FINAL_XOR_VALUE;

    // Convert the checksum into a character string.
    let checksum_chars = (0..8)
        .map(|i| {
            CHECKSUM_CHARSET
                .chars()
                .nth(((checksum >> (5 * (7 - i))) & 31) as usize)
                .expect("checksum character expected")
        })
        .collect::<String>();

    Ok(checksum_chars)
}

/// Parse the proxy (Socket:Port) argument from the cli input.
pub fn parse_proxy_auth(s: &str) -> Result<(String, String), NetError> {
    let parts: Vec<_> = s.split(':').collect();
    if parts.len() != 2 {
        return Err(NetError::InvalidNetworkAddress);
    }

    let user = parts[0].to_string();
    let passwd = parts[1].to_string();

    Ok((user, passwd))
}

/// Tor Error grades
#[derive(Debug)]
pub enum TorError {
    /// Io error
    IO(std::io::Error),
    /// Generic error
    General(String),
    /// Cbor error
    Serde(serde_cbor::Error),
}

impl From<std::io::Error> for TorError {
    fn from(value: std::io::Error) -> Self {
        TorError::IO(value)
    }
}

impl From<serde_cbor::Error> for TorError {
    fn from(value: serde_cbor::Error) -> Self {
        TorError::Serde(value)
    }
}

/// Authenticate against the Tor control port and report bootstrap progress.
///
/// Returns `Ok(())` once the control connection authenticates. A still-starting
/// Tor is logged as a warning rather than an error, since callers only need the
/// daemon to be reachable.
pub fn check_tor_status(control_port: u16, password: &str) -> Result<(), TorError> {
    use std::{
        io::BufRead,
        net::{SocketAddr, ToSocketAddrs},
    };

    let addr: SocketAddr = format!("127.0.0.1:{control_port}")
        .to_socket_addrs()
        .map_err(|e| TorError::General(format!("Invalid address: {}", e)))?
        .next()
        .ok_or_else(|| TorError::General("Could not resolve address".to_string()))?;

    // Use connect_timeout to avoid blocking indefinitely if Tor is not running
    let timeout = Duration::from_secs(5);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).map_err(|e| {
        log::error!(
            "Failed to connect to Tor control port {}: {}",
            control_port,
            e
        );
        TorError::General(format!(
            "Cannot connect to Tor control port {}. Is Tor running? Error: {}",
            control_port, e
        ))
    })?;

    // Set read/write timeouts to avoid hanging on slow responses
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;

    let mut reader = BufReader::new(stream.try_clone()?);
    let auth_command = format!("AUTHENTICATE \"{password}\"\r\n");
    stream.write_all(auth_command.as_bytes())?;
    let mut response = String::new();
    reader.read_line(&mut response)?;
    if !response.starts_with("250") {
        log::error!("Tor authentication failed: {response}, please provide correct password");
        return Err(TorError::General("Tor authentication failed".to_string()));
    }
    stream.write_all(b"GETINFO status/bootstrap-phase\r\n")?;
    response.clear();
    reader.read_line(&mut response)?;

    if response.contains("PROGRESS=100") {
        log::info!("Tor is fully started and operational!");
    } else {
        log::warn!("Tor is still starting, try again later: {response}");
    }
    Ok(())
}

/// Connect to `target_host:target_port` through the local Tor SOCKS5 proxy,
/// with connect and handshake bounded by `timeout`. The `socks` crate does an
/// un-timed connect, so a wedged proxy would hang shutdown joins forever.
#[cfg(not(feature = "integration-test"))]
pub(crate) fn socks5_connect(
    socks_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Option<(&str, &str)>,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let proxy = std::net::SocketAddr::from(([127, 0, 0, 1], socks_port));
    let mut socket = TcpStream::connect_timeout(&proxy, timeout)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;

    // Greeting: always offer no-auth, plus password when credentials exist.
    let mut greeting = vec![5u8];
    match auth {
        Some(_) => greeting.extend_from_slice(&[2, 0, 2]),
        None => greeting.extend_from_slice(&[1, 0]),
    }
    socket.write_all(&greeting)?;

    let mut choice = [0u8; 2];
    socket.read_exact(&mut choice)?;
    if choice[0] != 5 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "invalid socks version",
        ));
    }
    match choice[1] {
        0 => {}
        2 => {
            let (username, password) = auth.ok_or_else(|| {
                io::Error::new(ErrorKind::PermissionDenied, "proxy demands password auth")
            })?;
            if username.is_empty() || username.len() > 255 || password.len() > 255 {
                return Err(io::Error::new(
                    ErrorKind::InvalidInput,
                    "bad socks credentials",
                ));
            }
            let mut req = vec![1u8, username.len() as u8];
            req.extend_from_slice(username.as_bytes());
            req.push(password.len() as u8);
            req.extend_from_slice(password.as_bytes());
            socket.write_all(&req)?;
            let mut status = [0u8; 2];
            socket.read_exact(&mut status)?;
            if status[1] != 0 {
                return Err(io::Error::new(
                    ErrorKind::PermissionDenied,
                    "socks auth failed",
                ));
            }
        }
        m => {
            return Err(io::Error::other(format!(
                "no acceptable socks auth method: {m}"
            )))
        }
    }

    // CONNECT with the target as a domain so .onion names resolve at the proxy.
    let host = target_host.as_bytes();
    if host.len() > 255 {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            "target host too long",
        ));
    }
    let mut req = vec![5u8, 1, 0, 3, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&target_port.to_be_bytes());
    socket.write_all(&req)?;

    let mut head = [0u8; 4];
    socket.read_exact(&mut head)?;
    if head[0] != 5 || head[1] != 0 {
        return Err(io::Error::other(format!(
            "socks connect failed, reply code {}",
            head[1]
        )));
    }
    // Drain the bound address; its length depends on the address type.
    match head[3] {
        1 => socket.read_exact(&mut [0u8; 6])?,
        3 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len)?;
            socket.read_exact(&mut vec![0u8; len[0] as usize + 2])?;
        }
        4 => socket.read_exact(&mut [0u8; 18])?,
        t => return Err(io::Error::other(format!("unknown socks address type: {t}"))),
    }
    Ok(socket)
}

struct RawModeGuard;

impl RawModeGuard {
    fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        Ok(Self)
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
    }
}
/// Returns the current time as seconds since the Unix epoch.
pub(crate) fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Prompts the user for a password using the given prompt string.
/// Temporarily disables canonical mode and echo to mask each typed
/// character with `*` as feedback.
pub fn prompt_password(message: String) -> io::Result<String> {
    let mut stdout = io::stdout();
    let stdin = io::stdin();

    print!("{message}");
    stdout.flush()?; // Ensure the prompt is printed

    let _guard = RawModeGuard::new()?;

    let mut password = String::new();
    let mut buf = [0u8; 1];

    while lock_debug!(stdin.lock()).read(&mut buf)? == 1 {
        let c = buf[0] as char;

        match c {
            '\n' | '\r' => {
                // - If the byte is newline (`\n`, ASCII 0x0A) or carriage return (`\r`, ASCII 0x0D),
                //   it signals the end of input, so we break the loop.
                println!();
                break;
            }
            '\x08' | '\x7f' => {
                // - If the byte is Backspace (ASCII 0x08 or 0x7f),
                //   we remove the last character from the password (if any),
                //   and erase the asterisk from the terminal by moving the cursor back,
                //   writing a space to overwrite, then moving the cursor back again.
                if !password.is_empty() {
                    password.pop();
                    print!("\x08 \x08");
                    stdout.flush()?;
                }
            }
            _ => {
                // - Otherwise, for any other character, we append it to the password string
                //   and print an asterisk '*' as a visual placeholder for the typed character.
                password.push(c);
                print!("*");
                stdout.flush()?;
            }
        }
    }

    println!(); // move to next line after input
    Ok(password.trim_end().to_string())
}

/// Writes a new wallet's seed phrase to stdout, shown once at wallet creation.
/// Returns write errors instead of panicking like `println!`.
pub fn print_new_wallet_seed(mnemonic: &SecretMnemonic) -> io::Result<()> {
    let mut out = lock_debug!(io::stdout().lock());
    writeln!(out, "\n========== New Wallet Seed Phrase ==========")?;
    writeln!(out, "{}", mnemonic.words())?;
    writeln!(
        out,
        "\nWrite these words down and store them offline. They will not be shown again."
    )?;
    out.flush()
}

/// Publish `local_port` as an ephemeral Tor onion service via `ADD_ONION`.
///
/// The service listens on [`OPENSWAP_PORT`](crate::protocol::common_messages::OPENSWAP_PORT)
/// and forwards to `127.0.0.1:local_port`. Pass `"NEW:ED25519-V3"` as
/// `private_key_data` for a fresh key, or `"ED25519-V3:<base64>"` to reuse one.
/// When `service_id_data` is set, that service is removed first.
///
/// Created with `Flags=Detach`, so the service outlives the control connection
/// and must be removed explicitly if it should not persist.
///
/// Returns the `<serviceid>.onion` hostname.
pub fn get_ephemeral_address(
    control_port: u16,
    local_port: u16,
    password: &str,
    private_key_data: &str,
    service_id_data: Option<&str>,
) -> Result<String, TorError> {
    use crate::protocol::common_messages::OPENSWAP_PORT;
    use std::io::BufRead;
    let mut stream = TcpStream::connect(format!("127.0.0.1:{control_port}"))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut response = String::new();
    let mut service_id = String::new();
    let auth_command = format!("AUTHENTICATE \"{password}\"\r\n");
    stream.write_all(auth_command.as_bytes())?;
    if let Some(service_id) = service_id_data {
        let remove_command = format!("DEL_ONION {service_id}\r\n");
        stream.write_all(remove_command.as_bytes())?;
    }

    let add_onion_command = format!(
        "ADD_ONION {private_key_data} Flags=Detach Port={OPENSWAP_PORT},127.0.0.1:{local_port}\r\n"
    );

    stream.write_all(add_onion_command.as_bytes())?;

    while reader.read_line(&mut response)? > 0 {
        if response.starts_with("250-ServiceID=") {
            service_id = response
                .trim_start_matches("250-ServiceID=")
                .trim()
                .to_string();
            break;
        }
        response.clear();
    }

    if service_id.is_empty() {
        return Err(TorError::General(
            "Failed to retrieve ephemeral onion service details".to_string(),
        ));
    }
    Ok(format!("{service_id}.onion"))
}

#[cfg(not(feature = "integration-test"))]
pub(crate) fn get_tor_hostname(
    data_dir: &Path,
    control_port: u16,
    local_port: u16,
    password: &str,
    tor_key: [u8; 64],
) -> Result<String, TorError> {
    let tor_config_path = data_dir.join("tor/hostname");
    let tor_private_key = format!("ED25519-V3:{}", base64::encode(tor_key));
    if tor_config_path.exists() {
        if let Ok(tor_metadata) = fs::read(&tor_config_path) {
            let hostname_data: String = serde_cbor::de::from_slice(&tor_metadata)?;

            let hostname = get_ephemeral_address(
                control_port,
                local_port,
                password,
                &tor_private_key,
                Some(hostname_data.trim_end_matches(".onion")),
            )?;

            if hostname != hostname_data {
                return Err(TorError::General(
                    "tor hostname mismatch between stored key and ADD_ONION response".to_string(),
                ));
            }

            log::info!("Generated existing Tor Hidden Service Hostname: {hostname}");

            return Ok(hostname);
        }
    }

    let hostname =
        get_ephemeral_address(control_port, local_port, password, &tor_private_key, None)?;

    if let Some(parent) = tor_config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&tor_config_path, serde_cbor::ser::to_vec(&hostname)?)?;

    log::info!("Generated new Tor Hidden Service Hostname: {hostname}");

    Ok(hostname)
}

/// Deserialize any generic type from a CBOR file. The type should impl [serde::de::Deserialize].
pub fn deserialize_from_cbor<T>(reader: &[u8]) -> Result<T, serde_cbor::Error>
where
    T: serde::de::DeserializeOwned,
{
    match serde_cbor::from_slice::<T>(reader) {
        Ok(store) => Ok(store),
        Err(e) => {
            let err_string = format!("{e:?}");
            if err_string.contains("code: TrailingData") {
                // Defensive error handling - monitor logs to confirm wallet files stay clean.
                log::info!("Wallet file has trailing data, trying to restore");
                let mut end = reader.len();
                loop {
                    if end == 0 {
                        break Err(e);
                    }
                    end -= 1;
                    match serde_cbor::from_slice::<T>(&reader[..end]) {
                        Ok(store) => break Ok(store),
                        Err(_) => continue,
                    }
                }
            } else {
                Err(e)
            }
        }
    }
}

/// Interactive Selection by User for Utxos
pub fn interactive_select(
    mut choices: Vec<(ListUnspentResultEntry, UTXOSpendInfo)>,
    required_amount: Amount,
) -> Result<Vec<(ListUnspentResultEntry, UTXOSpendInfo)>, WalletError> {
    if choices.is_empty() {
        return Err(WalletError::General("No UTXOs available".to_string()));
    }

    let total_available: Amount = choices.iter().map(|(utxo, _)| utxo.amount).sum();
    if total_available < required_amount {
        return Err(WalletError::General(format!(
            "Insufficient balance: {} sats available, {} sats required",
            total_available.to_sat(),
            required_amount.to_sat()
        )));
    }

    choices.sort_by_key(|(_, spend_info)| match spend_info {
        UTXOSpendInfo::SeedCoin { .. } => 0,
        UTXOSpendInfo::SweptCoin { .. } => 1,
        _ => 2,
    });
    let mut selected = vec![false; choices.len()];
    let mut stdout = stdout();

    enable_raw_mode()?;
    execute!(
        stdout,
        Clear(ClearType::All),
        EnableMouseCapture,
        MoveTo(0, 0)
    )?;

    let (terminal_width, terminal_height) = size().unwrap_or((100, 30));
    const BOX_WIDTH: usize = 18;
    const COL_SPACING: usize = 20;
    const MIN_MARGIN: usize = 4; // Minimum margin from terminal edges
    const HEADER_LINES: usize = 3; // Header + warning + blank line
    const LINES_PER_ROW: usize = 7; // 7 lines per row (5 for box + 2 spacing)

    let available_width = terminal_width as usize - MIN_MARGIN;
    let cols = max(1, available_width / COL_SPACING);

    let total_rows = (choices.len() + cols - 1).div_ceil(cols);

    let available_height = terminal_height as usize - HEADER_LINES;
    let visible_rows = max(1, available_height / LINES_PER_ROW);

    let mut scroll_offset = 0;
    let max_scroll = total_rows.saturating_sub(visible_rows);

    let render_header = |stdout: &mut io::Stdout| -> Result<(), WalletError> {
        queue!(
            stdout,
            MoveTo(0, 0),
            Print("\x1b[1m👆 CLICK on any UTXO to select/deselect, ↑↓ to scroll, Press ESC/Enter to exit\x1b[0m"),
            MoveTo(0, 1),
            Print("\x1b[1;31m⚠️  WARNING: Pick either Regular Coin OR Swap Coin, or else transaction will fail!\x1b[0m")
        )?;
        stdout.flush()?;
        Ok(())
    };

    // Render only a singular UTXO box (for selection updates)
    // Once this box has been rendered, we will only update those grids triggered by keyboard clicks
    let render_utxo_grid = |stdout: &mut io::Stdout,
                            choices: &[(ListUnspentResultEntry, UTXOSpendInfo)],
                            selected: &[bool],
                            scroll_offset: usize|
     -> Result<(), WalletError> {
        let selected_total = choices
            .iter()
            .zip(selected)
            .filter(|(_, sel)| **sel)
            .map(|((selected_choice, _), _)| selected_choice.amount.to_btc())
            .collect::<Vec<_>>();
        if max_scroll > 0 {
            queue!(
                stdout,
                MoveTo(0, 2),
                Print(format!(
                                "\x1b[90mScrolling: {} / {} (showing rows {}-{})\x1b[0m   Total Selected (In BTC) : {:.8}",
                                scroll_offset + 1,
                                max_scroll + 1,
                                scroll_offset + 1,
                                (scroll_offset + visible_rows).min(total_rows),
                                selected_total.iter().sum::<f64>()
                            ))
            )?;
        }
        // Clear only the grid area, not the entire screen
        let grid_start_row = HEADER_LINES;
        let grid_height = visible_rows * LINES_PER_ROW;

        for row in 0..grid_height {
            queue!(
                stdout,
                MoveTo(0, (grid_start_row + row) as u16),
                Print(" ".repeat(terminal_width as usize))
            )?;
        }

        let end_row = (scroll_offset + visible_rows).min(total_rows);

        for row in scroll_offset..end_row {
            let display_row = row - scroll_offset;
            let row_start = HEADER_LINES + display_row * LINES_PER_ROW;

            for col in 0..cols {
                let i = row * cols + col;
                if i >= choices.len() {
                    break;
                }

                let choice = &choices[i];
                let marker = if selected[i] { "✓" } else { " " };
                let col_offset = col * COL_SPACING;

                let lines = [
                    format!("┌{}┐", "─".repeat(BOX_WIDTH - 2)),
                    format!(
                        "│\x1b[1m[\x1b[32m{marker}\x1b[0m\x1b[1m] UTXO {:<7}\x1b[0m│",
                        i + 1
                    ),
                    match &choice.1 {
                        UTXOSpendInfo::SeedCoin { .. } => {
                            format!("│\x1b[33m Regular Coin \x1b[0m{:<2}│", "")
                        }
                        UTXOSpendInfo::SweptCoin { .. } => {
                            format!("│\x1b[34m Swap Coin \x1b[0m{:<5}│", "")
                        }
                        _ => format!("│{:<15}│", choice.1.to_string()),
                    },
                    format!("│\x1b[31m {:.8} BTC \x1b[0m│", choice.0.amount.to_btc()),
                    format!("│ Conf: {:<9}│", choice.0.confirmations),
                    format!("└{}┘", "─".repeat(BOX_WIDTH - 2)),
                ];

                for (line_idx, line) in lines.iter().enumerate() {
                    queue!(
                        stdout,
                        MoveTo(col_offset as u16, (row_start + line_idx) as u16),
                        Print(line)
                    )?;
                }
            }
        }
        stdout.flush()?;
        Ok(())
    };

    // Initial render
    render_header(&mut stdout)?;
    render_utxo_grid(&mut stdout, &choices, &selected, scroll_offset)?;

    loop {
        match read()? {
            Event::Mouse(mouse_event)
                if mouse_event.kind == MouseEventKind::Down(MouseButton::Left) =>
            {
                let click_row = mouse_event.row;
                let click_col = mouse_event.column;

                if click_row >= HEADER_LINES as u16 {
                    let display_row = (click_row - HEADER_LINES as u16) / LINES_PER_ROW as u16;
                    let actual_row = scroll_offset + display_row as usize;
                    let box_col = click_col / COL_SPACING as u16;
                    let i = actual_row * cols + box_col as usize;

                    if i < choices.len() {
                        selected[i] = !selected[i];

                        render_utxo_grid(&mut stdout, &choices, &selected, scroll_offset)?;
                    }
                }
            }
            Event::Key(key_event) => match key_event.code {
                KeyCode::PageUp if scroll_offset > 0 => {
                    scroll_offset -= 1;
                    render_utxo_grid(&mut stdout, &choices, &selected, scroll_offset)?;
                }
                KeyCode::PageDown if scroll_offset < max_scroll => {
                    scroll_offset += 1;
                    render_utxo_grid(&mut stdout, &choices, &selected, scroll_offset)?;
                }
                // Numlock your keyboard, key 3 is PageDown and key 9 is PageUp
                KeyCode::Up => {
                    scroll_offset = scroll_offset.saturating_sub(visible_rows);
                    render_utxo_grid(&mut stdout, &choices, &selected, scroll_offset)?;
                }
                KeyCode::Down => {
                    scroll_offset = (scroll_offset + visible_rows).min(max_scroll);
                    render_utxo_grid(&mut stdout, &choices, &selected, scroll_offset)?;
                }
                KeyCode::Esc | KeyCode::Enter => break,
                _ => {}
            },
            _ => {}
        }
    }

    execute!(stdout, DisableMouseCapture, Clear(ClearType::All))?;
    disable_raw_mode()?;

    let selected_utxo = choices
        .into_iter()
        .zip(selected)
        .filter(|(_, sel)| *sel)
        .map(|(choice, _)| choice)
        .collect::<Vec<_>>();

    println!("Selected UTXOs:");
    for utxo in selected_utxo.iter() {
        println!("  - {} BTC ({})", utxo.0.amount.to_btc(), utxo.0.txid);
    }

    let total_selected: Amount = selected_utxo.iter().map(|(u, _)| u.amount).sum();
    println!("Total selected amount: {} BTC", total_selected.to_btc());

    Ok(selected_utxo)
}

#[cfg(test)]
mod tests {
    use std::{net::TcpListener, thread};

    use bitcoin::{
        blockdata::{opcodes::all, script::Builder},
        secp256k1::Scalar,
        PubkeyHash,
    };

    use crate::protocol::common_messages::{MakerHello, MakerToTakerMessage, ProtocolVersion};

    use super::*;

    #[test]
    fn test_send_message() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let secp = Secp256k1::new();
        let (sk, _) = secp.generate_keypair(&mut thread_rng());
        let msg = bitcoin::secp256k1::Message::from_digest([0u8; 32]);
        let session_id_sig = secp.sign_ecdsa_low_r(&msg, &sk);
        let message = MakerToTakerMessage::MakerHello(MakerHello {
            supported_protocols: vec![ProtocolVersion::Legacy, ProtocolVersion::Taproot],
            session_id_sig,
        });

        thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let msg_bytes = read_message(&mut socket).unwrap();
            let msg: MakerToTakerMessage = serde_cbor::from_slice(&msg_bytes).unwrap();

            if let MakerToTakerMessage::MakerHello(hello) = msg {
                assert_eq!(hello.supported_protocols.len(), 2);
                assert!(hello.supported_protocols.contains(&ProtocolVersion::Legacy));
                assert!(hello
                    .supported_protocols
                    .contains(&ProtocolVersion::Taproot));
            } else {
                panic!(
                    "Received Wrong Message: Expected MakerHello variant, Got: {:?}",
                    msg,
                );
            }
        });

        let mut stream = TcpStream::connect(address).unwrap();
        send_message(&mut stream, &message).unwrap();
    }

    #[test]
    fn test_read_message_rejects_oversized_payload() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();

        let sender = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let oversized_length = (MAX_RPC_MESSAGE_SIZE as u32 + 1).to_be_bytes();
            socket.write_all(&oversized_length).unwrap();
        });

        let mut stream = TcpStream::connect(address).unwrap();
        let error = read_message(&mut stream).unwrap_err();

        assert!(matches!(error, NetError::MessageTooLarge));
        sender.join().unwrap();
    }

    #[test]
    fn test_redeemscript_to_scriptpubkey_custom() {
        // Create a custom puzzle script
        let puzzle_script = Builder::new()
            .push_opcode(all::OP_ADD)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_EQUAL)
            .into_script();
        // Compare the redeemscript_to_scriptpubkey output with the expected value in hex
        assert_eq!(
            redeemscript_to_scriptpubkey(&puzzle_script)
                .unwrap()
                .to_hex_string(),
            "0020c856c4dcad54542f34f0889a0c12acf2951f3104c85409d8b70387bbb2e95261"
        );
    }
    #[test]
    fn test_redeemscript_to_scriptpubkey_p2pkh() {
        let pubkeyhash = PubkeyHash::from_str("79fbfc3f34e7745860d76137da68f362380c606c").unwrap();
        let script = Builder::new()
            .push_opcode(all::OP_DUP)
            .push_opcode(all::OP_HASH160)
            .push_slice(pubkeyhash.to_byte_array())
            .push_opcode(all::OP_EQUALVERIFY)
            .push_opcode(all::OP_CHECKSIG)
            .into_script();
        assert_eq!(
            redeemscript_to_scriptpubkey(&script)
                .unwrap()
                .to_hex_string(),
            "0020de4c0f5b48361619b1cf09d5615bc3a2603c412bf4fcbc9acecf6786c854b741"
        );
    }

    #[test]
    fn test_redeemscript_to_scriptpubkey_1of2musig() {
        let pubkey1 = PublicKey::from_str(
            "03cccac45f4521514187be4b5650ecb241d4d898aa41daa7c5384b2d8055fbb509",
        )
        .unwrap();
        let pubkey2 = PublicKey::from_str(
            "0316665712a0b90de0bcf7cac70d3fd3cfd102050e99b5cd41a55f2c92e1d9e6f5",
        )
        .unwrap();
        let script = Builder::new()
            .push_opcode(all::OP_PUSHNUM_1)
            .push_key(&pubkey1)
            .push_key(&pubkey2)
            .push_opcode(all::OP_PUSHNUM_2)
            .push_opcode(all::OP_CHECKMULTISIG)
            .into_script();
        assert_eq!(
            redeemscript_to_scriptpubkey(&script)
                .unwrap()
                .to_hex_string(),
            "0020b5954ef36e6bd532c7e90f41927a3556b0fef6416695dbe50ff40c6a55a6232c"
        );
    }
    #[test]
    fn test_hd_path_from_descriptor() {
        assert_eq!(
            get_hd_path_from_descriptor(
                "wpkh([a945b5ca/1/1]020b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad)#aq759em9"
            ),
            Some(("a945b5ca", 1, 1))
        );
    }
    #[test]
    fn test_hd_path_from_descriptor_gets_none() {
        assert_eq!(
            get_hd_path_from_descriptor(
                "wsh(multi(2,[f67b69a3]0245ddf535f08a04fd86d794b76f8e3949f27f7ae039b641bf277c6a4552b4c387,[dbcd3c6e]030f781e9d2a6d3a823cee56be2d062ed4269f5a6294b20cb8817eb540c641d9a2))#8f70vn2q"
            ),
            None
        );
    }

    #[test]
    fn test_hd_path_from_descriptor_failure_cases() {
        let test_cases = [
            (
                "wpkh a945b5ca/1/1 029b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad aq759em9",
                None,
            ), // without brackets
            (
                "wpkh([a945b5ca/invalid/1]029b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad)#aq759em9",
                None,
            ), // invalid address type
            (
                "wpkh([a945b5ca/1/invalid]029b77637989868dcd502dbc07d6304dc2150301693ae84a60b379c3b696b289ad)#aq759em9",
                None,
            ), // invalid index
        ];

        for (descriptor, expected_output) in test_cases.iter() {
            let result = get_hd_path_from_descriptor(descriptor);
            assert_eq!(result, *expected_output);
        }
    }

    #[test]
    fn test_generate_maker_keys() {
        // generate_maker_keys: test that given a tweakable_point the return values satisfy the equation:
        // tweak_point * returned_nonce = returned_publickey
        let tweak_point = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let (multisig_pubkeys, multisig_nonces, hashlock_pubkeys, hashlock_nonces) =
            generate_maker_keys(&tweak_point, 1).unwrap();
        // test returned multisg part
        let returned_nonce = multisig_nonces[0];
        let returned_pubkey = multisig_pubkeys[0];
        let secp = Secp256k1::new();
        let pubkey_secp = bitcoin::secp256k1::PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let scalar_from_nonce: Scalar = Scalar::from(returned_nonce);
        let tweaked_pubkey = pubkey_secp
            .add_exp_tweak(&secp, &scalar_from_nonce)
            .unwrap();
        assert_eq!(returned_pubkey.to_string(), tweaked_pubkey.to_string());

        // test returned hashlock part
        let returned_nonce = hashlock_nonces[0];
        let returned_pubkey = hashlock_pubkeys[0];
        let scalar_from_nonce: Scalar = Scalar::from(returned_nonce);
        let tweaked_pubkey = pubkey_secp
            .add_exp_tweak(&secp, &scalar_from_nonce)
            .unwrap();
        assert_eq!(returned_pubkey.to_string(), tweaked_pubkey.to_string());
    }

    // ── parse_checked_address tests ──────────────────────────────────────────

    #[test]
    fn test_parse_checked_address_accepts_valid_mainnet() {
        // Standard P2PKH mainnet address
        let addr = parse_checked_address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", Network::Bitcoin);
        assert!(addr.is_ok(), "valid mainnet address must be accepted");
    }

    #[test]
    fn test_parse_checked_address_rejects_completely_invalid_string() {
        // Totally garbage input — must fail at the parse step
        let err = parse_checked_address("not-an-address", Network::Bitcoin)
            .expect_err("garbage string should fail");
        assert!(
            matches!(err, WalletError::InvalidAddress(_)),
            "expected InvalidAddress, got: {:?}",
            err
        );
        // Internal parse error detail must be non-empty
        if let WalletError::InvalidAddress(inner) = &err {
            let msg = inner.to_string();
            assert!(!msg.is_empty(), "inner parse error should have a message");
        }
    }

    #[test]
    fn test_parse_checked_address_rejects_empty_string() {
        let err =
            parse_checked_address("", Network::Bitcoin).expect_err("empty string should fail");
        assert!(
            matches!(err, WalletError::InvalidAddress(_)),
            "expected InvalidAddress, got: {:?}",
            err
        );
    }

    #[test]
    fn test_parse_checked_address_rejects_truncated_address() {
        // Valid prefix but truncated — checksum/length mismatch
        let err = parse_checked_address("1BoatSLRHtKNng", Network::Bitcoin)
            .expect_err("truncated address should fail");
        assert!(
            matches!(err, WalletError::InvalidAddress(_)),
            "expected InvalidAddress, got: {:?}",
            err
        );
        if let WalletError::InvalidAddress(inner) = &err {
            assert!(!inner.to_string().is_empty());
        }
    }

    #[test]
    fn test_parse_checked_address_rejects_address_with_invalid_chars() {
        // Base58 doesn't include 0, O, I, l — inserting one corrupts the address
        let err = parse_checked_address("1BoatSLRHtKNngkdXEeobR76b53LET0pyT", Network::Bitcoin)
            .expect_err("address with invalid base58 chars should fail");
        assert!(
            matches!(err, WalletError::InvalidAddress(_)),
            "expected InvalidAddress, got: {:?}",
            err
        );
    }

    #[test]
    fn test_parse_checked_address_rejects_wrong_network_mainnet_on_testnet() {
        // Mainnet address rejected on Testnet — fails at require_network step
        let err = parse_checked_address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", Network::Testnet)
            .expect_err("mainnet address should fail on testnet");
        assert!(
            matches!(err, WalletError::General(_)),
            "expected General (network mismatch), got: {:?}",
            err
        );
        if let WalletError::General(msg) = &err {
            assert!(
                msg.contains("Address Network Mismatch"),
                "error must mention mismatch, got: {}",
                msg
            );
            assert!(
                msg.contains("Expected"),
                "error must mention expected network, got: {}",
                msg
            );
            assert!(
                msg.contains("Details"),
                "error must contain internal detail, got: {}",
                msg
            );
        }
    }

    #[test]
    fn test_parse_checked_address_rejects_wrong_network_mainnet_on_regtest() {
        let err = parse_checked_address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", Network::Regtest)
            .expect_err("mainnet address should fail on regtest");
        assert!(matches!(err, WalletError::General(_)));
        if let WalletError::General(msg) = &err {
            assert!(msg.contains("Address Network Mismatch"));
            assert!(msg.contains("Details"));
        }
    }

    #[test]
    fn test_parse_checked_address_rejects_testnet_on_mainnet() {
        // A known testnet bech32 address (tb1q...)
        let err = parse_checked_address(
            "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            Network::Bitcoin,
        )
        .expect_err("testnet address should fail on mainnet");
        assert!(
            matches!(err, WalletError::General(_)),
            "expected General (network mismatch), got: {:?}",
            err
        );
        if let WalletError::General(msg) = &err {
            assert!(msg.contains("Address Network Mismatch"));
            assert!(msg.contains("Details"));
        }
    }

    #[test]
    fn test_parse_checked_address_invalid_and_wrong_network_produce_different_errors() {
        // The two error arms must be distinguishable — different variants
        let parse_err = parse_checked_address("complete-garbage-!!!", Network::Bitcoin)
            .expect_err("should fail");
        let network_err =
            parse_checked_address("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", Network::Regtest)
                .expect_err("should fail");

        // One is InvalidAddress, the other is General — they must not match each other
        assert!(
            matches!(parse_err, WalletError::InvalidAddress(_)),
            "parse error should be InvalidAddress"
        );
        assert!(
            matches!(network_err, WalletError::General(_)),
            "network mismatch should be General"
        );

        // Their display strings must differ
        assert_ne!(
            parse_err.to_string(),
            network_err.to_string(),
            "the two error cases must produce different messages"
        );
    }

    #[test]
    fn test_parse_checked_address_bech32_valid_mainnet() {
        // P2WPKH mainnet bech32
        let addr = parse_checked_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Bitcoin,
        );
        assert!(
            addr.is_ok(),
            "valid bech32 mainnet address must be accepted"
        );
    }

    #[test]
    fn test_parse_checked_address_bech32_wrong_network() {
        // mainnet bech32 on regtest
        let err = parse_checked_address(
            "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            Network::Regtest,
        )
        .expect_err("mainnet bech32 should fail on regtest");
        assert!(matches!(err, WalletError::General(_)));
        if let WalletError::General(msg) = &err {
            assert!(msg.contains("Address Network Mismatch"));
            assert!(msg.contains("Details"));
        }
    }
}
