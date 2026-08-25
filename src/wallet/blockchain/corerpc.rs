//! Bitcoin Core backend: drives JSON-RPC for wallet and watchtower queries and
//! a lazily-connected ZMQ subscriber for block/tx notifications.

use std::{
    net::{TcpStream, ToSocketAddrs},
    sync::Mutex,
    time::Duration,
};

use bitcoin::{
    address::NetworkUnchecked, block::Header, Address, Block, BlockHash, OutPoint, Script,
    Transaction, Txid,
};
use bitcoind::bitcoincore_rpc::{
    json::{
        EstimateMode, EstimateSmartFeeResult, GetAddressInfoResult, GetBlockchainInfoResult,
        GetRawTransactionResult, GetTxOutResult, ListTransactionResult, ListUnspentResultEntry,
        ScanningDetails,
    },
    jsonrpc, Auth, Client, Error as CoreRpcError, RpcApi,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BlockRef, Blockchain, WatchEvent};
use crate::{lock_debug, wallet::error::WalletError};

/// Configuration for connecting to a Bitcoin Core node via JSON-RPC + ZMQ.
#[derive(Debug, Clone)]
pub struct CoreRpcConfig {
    /// The Bitcoin node URL.
    pub url: String,
    /// The Bitcoin node authentication mechanism.
    // TODO: Make Auth take cookies too.
    pub auth: Auth,
    /// The wallet name in the Bitcoin node.
    pub wallet_name: String,
    /// ZMQ endpoint for block/tx notifications (e.g. `"tcp://127.0.0.1:28332"`).
    /// Consumed by the watchtower notification path.
    pub zmq_addr: String,
}

const RPC_HOSTPORT: &str = "localhost:18443";

/// Bitcoin Core's conventional ZMQ notification port.
const ZMQ_DEFAULT_PORT: u16 = 28332;

impl CoreRpcConfig {
    /// Default ZMQ endpoint on the RPC host. Deriving the host from the RPC url
    /// keeps a remote-node setup from silently subscribing to localhost.
    pub fn default_zmq_addr(rpc_url: &str) -> String {
        let host = rpc_url.rsplit_once(':').map(|(h, _)| h).unwrap_or(rpc_url);
        format!("tcp://{host}:{ZMQ_DEFAULT_PORT}")
    }
}

impl Default for CoreRpcConfig {
    fn default() -> Self {
        Self {
            url: RPC_HOSTPORT.to_string(),
            auth: Auth::UserPass("regtestrpcuser".to_string(), "regtestrpcpass".to_string()),
            wallet_name: "random-wallet-name".to_string(),
            zmq_addr: CoreRpcConfig::default_zmq_addr(RPC_HOSTPORT),
        }
    }
}

/// Lazily-connected ZMQ `rawtx`/`rawblock` subscriber for the watchtower.
///
/// The endpoint (`addr`) is always known up front; the SUB socket itself is
/// opened on demand the first time the watchtower primes or polls it. The
/// wallet's `CoreRPC` instance never does either, so it never opens a socket.
/// The socket sits behind a `Mutex` so `CoreRPC` stays `Sync` (a bare
/// `zmq::Socket` is not).
struct ZmqSubscriber {
    addr: String,
    socket: Mutex<Option<zmq::Socket>>,
}

impl ZmqSubscriber {
    fn new(addr: String) -> Self {
        Self {
            addr,
            socket: Mutex::new(None),
        }
    }

    /// Connect and subscribe to `rawtx`/`rawblock` if not already connected.
    /// Idempotent.
    ///
    /// Priming this **before** the watchtower's startup mempool scan is
    /// load-bearing: a SUB socket drops messages published during the
    /// slow-joiner handshake, so connecting first lets the subsequent mempool
    /// scan backstop the handshake window — without it, a transaction landing in
    /// that gap could be missed by both the scan and the ZMQ feed.
    fn ensure_connected(&self) -> Result<(), WalletError> {
        let mut guard = lock_debug!(self.socket.lock())
            .map_err(|_| WalletError::Zmq("ZMQ socket mutex poisoned".to_string()))?;
        if guard.is_some() {
            return Ok(());
        }
        let ctx = zmq::Context::new();
        let socket = ctx
            .socket(zmq::SUB)
            .map_err(|e| WalletError::Zmq(format!("ZMQ socket: {e}")))?;
        socket
            .connect(&self.addr)
            .map_err(|e| WalletError::Zmq(format!("ZMQ connect {}: {e}", self.addr)))?;
        socket
            .set_subscribe(b"rawtx")
            .map_err(|e| WalletError::Zmq(format!("ZMQ subscribe rawtx: {e}")))?;
        socket
            .set_subscribe(b"rawblock")
            .map_err(|e| WalletError::Zmq(format!("ZMQ subscribe rawblock: {e}")))?;
        *guard = Some(socket);
        Ok(())
    }

    /// Read the next raw ZMQ multipart message `(topic, payload)`, non-blocking.
    /// Connects the SUB socket on first call. `None` means nothing was queued.
    ///
    /// A transport error drops the socket so the next call reconnects —
    /// otherwise a dead socket would stay installed and notifications would
    /// never resume.
    fn recv_event(&self) -> Option<(String, Vec<u8>)> {
        if let Err(e) = self.ensure_connected() {
            log::warn!("ZMQ connect {}: {e:?}", self.addr);
            return None;
        }
        let mut guard = lock_debug!(self.socket.lock()).ok()?;
        let received = {
            let socket = guard.as_ref()?;
            socket.recv_multipart(zmq::DONTWAIT)
        };
        let msg = match received {
            Ok(msg) => msg,
            // The only non-failure outcome of a DONTWAIT recv: the queue is
            // empty right now. The socket stays healthy.
            Err(zmq::Error::EAGAIN) => return None,
            Err(e) => {
                *guard = None;
                log::warn!("ZMQ recv {}: {e}", self.addr);
                return None;
            }
        };
        // Core publishes topic/body/sequence, so a shorter message is malformed.
        if msg.len() < 2 {
            log::warn!(
                "ZMQ recv {}: malformed message with {} frames",
                self.addr,
                msg.len()
            );
            return None;
        }
        Some((String::from_utf8_lossy(&msg[0]).to_string(), msg[1].clone()))
    }
}

/// Bitcoin Core backend over JSON-RPC (+ ZMQ for notifications).
///
/// Holds the RPC client, the connection config (incl. the ZMQ endpoint), and a
/// lazily-connected ZMQ subscriber — the wallet's instance never primes or polls
/// it, so it never opens a socket.
pub struct CoreRPC {
    rpc: Client,
    config: CoreRpcConfig,
    /// `rawtx`/`rawblock` subscriber, established lazily by the watchtower.
    zmq: ZmqSubscriber,
}

#[derive(Deserialize)]
struct SpendingPrevout {
    spendingtxid: Option<Txid>,
}

impl std::fmt::Debug for CoreRPC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreRPC")
            .field("url", &self.config.url)
            .field("wallet_name", &self.config.wallet_name)
            .finish()
    }
}

impl CoreRPC {
    /// Connect an RPC client for the configured wallet endpoint. Cheap — the
    /// client connects lazily on first use. Used by `AnyBlockchain::from_config`.
    pub fn new(config: &CoreRpcConfig) -> Result<Self, WalletError> {
        let rpc = Client::new(
            &format!("http://{}/wallet/{}", config.url, config.wallet_name),
            config.auth.clone(),
        )?;
        Ok(Self {
            rpc,
            config: config.clone(),
            zmq: ZmqSubscriber::new(config.zmq_addr.clone()),
        })
    }

    /// Open a fresh, independent Bitcoin Core RPC connection with the same config.
    ///
    /// Used to give a separate consumer (e.g. the watchtower discovery thread)
    /// its own connection without threading the config around separately.
    pub fn reconnect(&self) -> Result<Self, WalletError> {
        Self::new(&self.config)
    }

    pub(crate) fn spending_transaction(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<Transaction>, WalletError> {
        let spends: Vec<SpendingPrevout> = self.rpc.call(
            "gettxspendingprevout",
            &[json!([{ "txid": outpoint.txid, "vout": outpoint.vout }])],
        )?;
        if let Some(txid) = spends.first().and_then(|spend| spend.spendingtxid) {
            return self.get_raw_transaction(&txid, None).map(Some);
        }
        if self
            .get_tx_out(&outpoint.txid, outpoint.vout, Some(true))?
            .is_some()
        {
            return Ok(None);
        }
        // None here means "funding never confirmed" or "node cannot serve
        // the tx" (fresh, pruned, mid-rescan) — indistinguishable at this
        // RPC, and only the first makes "no spend" true. Accepted as a rare
        // silent miss; the real fix passes the caller-known height and errs.
        let Some(start) = self.tx_block_height(&outpoint.txid)? else {
            return Ok(None);
        };
        for height in start..=self.get_block_count()? {
            if let Some(tx) = self.block_at_height(height)?.txdata.into_iter().find(|tx| {
                tx.input
                    .iter()
                    .any(|input| input.previous_output == *outpoint)
            }) {
                return Ok(Some(tx));
            }
        }
        Ok(None)
    }

    /// Name of the Bitcoin Core wallet this backend is bound to.
    ///
    /// Only meaningful for the Core backend (Electrum has no server-side wallet),
    /// so this is an inherent `CoreRPC` method rather than part of the
    /// [`Blockchain`] trait. The wallet loader matches on
    /// `AnyBlockchain::CoreRPC` and compares this against the on-disk wallet
    /// file name.
    pub fn wallet_name(&self) -> &str {
        &self.config.wallet_name
    }

    /// Connect and subscribe the ZMQ notification socket up front.
    ///
    /// The watchtower calls this **before** its startup mempool scan so the SUB
    /// socket's slow-joiner handshake completes first (see
    /// `ZmqSubscriber::ensure_connected`). Only the Core backend has a ZMQ
    /// feed, so this is an inherent `CoreRPC` method rather than part of the
    /// [`Blockchain`] trait.
    pub fn prime_subscription(&self) -> Result<(), WalletError> {
        self.zmq.ensure_connected()
    }

    /// Startup gate for node capabilities the swap path depends on. Without it,
    /// a missing txindex or a dead ZMQ feed only surfaces mid-swap — as a false
    /// rebroadcast failure or a silently blind watchtower.
    pub fn check_node_requirements(&self) -> Result<(), WalletError> {
        // getindexinfo lists "txindex" only when the node runs -txindex=1.
        let indexes: Value = self.rpc.call("getindexinfo", &[])?;
        if indexes.get("txindex").is_none() {
            return Err(WalletError::General(
                "Bitcoin Core must run with -txindex=1".to_string(),
            ));
        }

        // The node's own list of ZMQ publishers must carry both topics we subscribe to.
        #[derive(Deserialize)]
        struct ZmqNotification {
            #[serde(rename = "type")]
            kind: String,
        }
        let pubs: Vec<ZmqNotification> = self.rpc.call("getzmqnotifications", &[])?;
        for topic in ["pubrawtx", "pubrawblock"] {
            if !pubs.iter().any(|p| p.kind == topic) {
                return Err(WalletError::Zmq(format!(
                    "Bitcoin Core does not publish {topic}; set -zmq{topic}=<addr>"
                )));
            }
        }

        // A ZMQ SUB connect() to a dead endpoint "succeeds" and then stays
        // silent forever, so prove a listener exists with a real TCP dial.
        if let Some(hostport) = self.config.zmq_addr.strip_prefix("tcp://") {
            let addr = hostport
                .to_socket_addrs()
                .map_err(|e| WalletError::Zmq(format!("bad ZMQ address {hostport}: {e}")))?
                .next()
                .ok_or_else(|| {
                    WalletError::Zmq(format!("ZMQ address {hostport} resolves to nothing"))
                })?;
            TcpStream::connect_timeout(&addr, Duration::from_secs(5)).map_err(|e| {
                WalletError::Zmq(format!(
                    "nothing listening at ZMQ endpoint {}: {e}",
                    self.config.zmq_addr
                ))
            })?;
        }
        Ok(())
    }
}

impl Blockchain for CoreRPC {
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, WalletError> {
        Ok(self.rpc.get_blockchain_info()?)
    }

    fn get_block_count(&self) -> Result<u64, WalletError> {
        Ok(self.rpc.get_block_count()?)
    }

    fn get_block_hash(&self, height: u64) -> Result<BlockHash, WalletError> {
        Ok(self.rpc.get_block_hash(height)?)
    }

    fn header_at_height(&self, height: u64) -> Result<Header, WalletError> {
        let hash = self.rpc.get_block_hash(height)?;
        Ok(self.rpc.get_block_header(&hash)?)
    }

    fn block_at_height(&self, height: u64) -> Result<Block, WalletError> {
        let hash = self.rpc.get_block_hash(height)?;
        Ok(self.rpc.get_block(&hash)?)
    }

    fn tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, WalletError> {
        let info = match self.rpc.get_raw_transaction_info(txid, None) {
            Ok(info) => info,
            // An unknown txid is "not mined" per the trait contract, not an error.
            Err(CoreRpcError::JsonRpc(jsonrpc::Error::Rpc(ref e))) if e.code == -5 => {
                return Ok(None)
            }
            Err(e) => return Err(e.into()),
        };
        match info.blockhash {
            Some(hash) => Ok(Some(self.rpc.get_block_header_info(&hash)?.height as u64)),
            None => Ok(None),
        }
    }

    fn is_confirmed_spend(
        &self,
        outpoint: &OutPoint,
        _script: &Script,
    ) -> Result<bool, WalletError> {
        // Core's UTXO set ignores mempool spends: a mined tx whose output is
        // missing from the confirmed view was spent by a mined transaction.
        Ok(self.tx_block_height(&outpoint.txid)?.is_some()
            && self
                .get_tx_out(&outpoint.txid, outpoint.vout, Some(false))?
                .is_none())
    }

    fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<Transaction, WalletError> {
        Ok(self.rpc.get_raw_transaction(txid, block_hash)?)
    }

    fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<GetRawTransactionResult, WalletError> {
        Ok(self.rpc.get_raw_transaction_info(txid, block_hash)?)
    }

    fn is_tx_unknown(&self, txid: &Txid) -> Result<bool, WalletError> {
        let info = match self.rpc.get_raw_transaction_info(txid, None) {
            Ok(info) => info,
            // -5 (RPC_INVALID_ADDRESS_OR_KEY): Core's "no such mempool or
            // blockchain transaction" answer.
            Err(CoreRpcError::JsonRpc(jsonrpc::Error::Rpc(ref e))) if e.code == -5 => {
                return Ok(true)
            }
            Err(e) => return Err(e.into()),
        };
        if info.blockhash.is_some() {
            // Confirmed in a block.
            return Ok(false);
        }
        // Unconfirmed. `getrawtransaction` also returns wallet-record
        // transactions that were evicted from the mempool; those must count
        // as unknown so callers rebroadcast them. A live mempool entry is the
        // only proof of "known" here.
        match self.rpc.get_mempool_entry(txid) {
            Ok(_) => Ok(false),
            Err(CoreRpcError::JsonRpc(jsonrpc::Error::Rpc(ref e))) if e.code == -5 => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<GetTxOutResult>, WalletError> {
        Ok(self.rpc.get_tx_out(txid, vout, include_mempool)?)
    }

    fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
    ) -> Result<Vec<ListUnspentResultEntry>, WalletError> {
        Ok(self.rpc.list_unspent(minconf, maxconf, None, None, None)?)
    }

    fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, WalletError> {
        Ok(self.rpc.send_raw_transaction(tx)?)
    }

    fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<Address<NetworkUnchecked>>, WalletError> {
        Ok(self.rpc.derive_addresses(descriptor, range)?)
    }

    fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<ListTransactionResult>, WalletError> {
        Ok(self
            .rpc
            .list_transactions(label, count, skip, include_watchonly)?)
    }

    fn estimate_smart_fee(
        &self,
        conf_target: u16,
        estimate_mode: Option<EstimateMode>,
    ) -> Result<EstimateSmartFeeResult, WalletError> {
        Ok(self.rpc.estimate_smart_fee(conf_target, estimate_mode)?)
    }

    /// Load the watch-only wallet on the node, creating it if absent. Ported
    /// verbatim from the pre-refactor `Wallet::sync` Core bootstrap so behaviour
    /// is unchanged; only invoked on the Core sync path.
    fn prepare_backend_wallet(&self, wallet_name: &str) -> Result<(), WalletError> {
        if self.rpc.list_wallets()?.contains(&wallet_name.to_string()) {
            log::debug!("wallet already loaded: {wallet_name}");
        } else if list_wallet_dir(&self.rpc)?.contains(&wallet_name.to_string()) {
            self.rpc.load_wallet(wallet_name)?;
            log::debug!("wallet loaded: {wallet_name}");
        } else {
            // pre-0.21 uses legacy wallets
            if self.rpc.version()? < 210_000 {
                self.rpc
                    .create_wallet(wallet_name, Some(true), None, None, None)?;
            } else {
                // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/issues/225 is
                // still open, so we issue the call directly to request a descriptor wallet.
                let args = [
                    Value::String(wallet_name.to_string()),
                    Value::Bool(true),  // Disable Private Keys
                    Value::Bool(false), // Create a blank wallet
                    Value::Null,        // Optional Passphrase
                    Value::Bool(false), // Avoid Reuse
                    Value::Bool(true),  // Descriptor Wallet
                ];
                let _: Value = self.rpc.call("createwallet", &args)?;
            }
            log::debug!("wallet created: {wallet_name}");
        }
        Ok(())
    }

    fn get_address_info(&self, addr: &Address) -> Result<GetAddressInfoResult, WalletError> {
        Ok(self.rpc.get_address_info(addr)?)
    }

    fn import_descriptors(&self, requests: &[Value]) -> Result<(), WalletError> {
        let _res: Vec<Value> = self
            .rpc
            .call("importdescriptors", &[Value::Array(requests.to_vec())])?;
        Ok(())
    }

    fn wallet_scanning_status(&self) -> Result<Option<ScanningDetails>, WalletError> {
        #[derive(Deserialize)]
        struct WalletInfoScanningOnly {
            scanning: Option<ScanningDetails>,
        }
        // Parse only the field we need so upstream schema changes (e.g. v30
        // balance-field removals) do not break deserialization.
        let info: WalletInfoScanningOnly = self.rpc.call("getwalletinfo", &[])?;
        Ok(info.scanning)
    }

    fn poll_event(&self) -> Option<WatchEvent> {
        let (topic, payload) = self.zmq.recv_event()?;
        match topic.as_str() {
            "rawtx" => Some(WatchEvent::TxSeen { raw_tx: payload }),
            "rawblock" => Some(WatchEvent::BlockConnected(BlockRef {
                height: 0,
                hash: payload,
            })),
            // We only subscribe to the two topics above, so anything else means
            // the socket is not carrying what we asked for.
            other => {
                log::warn!("ZMQ unexpected topic {other:?}");
                None
            }
        }
    }

    fn get_raw_mempool(&self) -> Result<Vec<Txid>, WalletError> {
        Ok(self.rpc.get_raw_mempool()?)
    }

    fn chain_name(&self) -> Result<String, WalletError> {
        let name = self.rpc.get_blockchain_info()?.chain.to_string();
        super::validate_chain_name(&name)?;
        Ok(name)
    }
}

/// List the wallet names known to the node (`listwalletdir`).
fn list_wallet_dir(client: &Client) -> Result<Vec<String>, WalletError> {
    #[derive(Deserialize)]
    struct Name {
        name: String,
    }
    #[derive(Deserialize)]
    struct CallResult {
        wallets: Vec<Name>,
    }
    let result: CallResult = client.call("listwalletdir", &[])?;
    Ok(result.wallets.into_iter().map(|n| n.name).collect())
}
