//! Bitcoin Core backend: drives JSON-RPC for wallet and watchtower queries and
//! a lazily-connected ZMQ subscriber for block/tx notifications.

use std::{
    collections::HashMap,
    convert::TryFrom,
    net::{TcpStream, ToSocketAddrs},
    sync::Mutex,
    time::Duration,
};

use bitcoin::{
    address::NetworkUnchecked, block::Header, Address, Amount, Block, BlockHash, Network, OutPoint,
    Script, Transaction, Txid,
};
use bitcoind::bitcoincore_rpc::{
    json::{
        GetBlockchainInfoResult, GetRawTransactionResult, GetTxOutResult, ListTransactionResult,
        ListUnspentResultEntry, ScanningDetails,
    },
    jsonrpc, Auth, Client, Error as CoreRpcError, RpcApi,
};
use serde::Deserialize;
use serde_json::{json, Value};

use super::{BlockRef, Blockchain, FeePriority, WatchEvent};
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
///
/// ZMQ drops messages silently (a full queue, a reconnect, a Core restart),
/// so the subscriber checks Core's per-topic sequence numbers and flags any
/// loss it can detect. A loss Core never numbers, such as a topic Core stops
/// publishing, stays invisible here.
struct ZmqSubscriber {
    addr: String,
    state: Mutex<ZmqState>,
}

#[derive(Default)]
struct ZmqState {
    socket: Option<zmq::Socket>,
    /// Last sequence number seen per topic. Kept when the socket is rebuilt,
    /// so the first message after a reconnect is still checked against it.
    last_sequence: HashMap<String, u32>,
    /// Notifications were lost since the watcher last asked.
    missed: bool,
}

impl ZmqSubscriber {
    fn new(addr: String) -> Self {
        Self {
            addr,
            state: Mutex::new(ZmqState::default()),
        }
    }

    /// Whether notifications were lost since the last call; clears the flag.
    fn take_missed(&self) -> bool {
        lock_debug!(self.state.lock()).is_ok_and(|mut state| std::mem::take(&mut state.missed))
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
        let mut guard = lock_debug!(self.state.lock())
            .map_err(|_| WalletError::Zmq("ZMQ socket mutex poisoned".to_string()))?;
        if guard.socket.is_some() {
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
        guard.socket = Some(socket);
        Ok(())
    }

    /// Read the next raw ZMQ multipart message `(topic, payload)`, non-blocking.
    /// Connects the SUB socket on first call. `None` means nothing was queued,
    /// or a message was lost, which [`Self::take_missed`] then reports.
    ///
    /// A transport error drops the socket so the next call reconnects —
    /// otherwise a dead socket would stay installed and notifications would
    /// never resume.
    fn recv_event(&self) -> Option<(String, Vec<u8>)> {
        if let Err(e) = self.ensure_connected() {
            log::warn!("ZMQ connect {}: {e:?}", self.addr);
            return None;
        }
        let mut guard = lock_debug!(self.state.lock()).ok()?;
        let state = &mut *guard;
        let received = state.socket.as_ref()?.recv_multipart(zmq::DONTWAIT);
        let mut msg = match received {
            Ok(msg) => msg,
            // The only non-failure outcome of a DONTWAIT recv: the queue is
            // empty right now. The socket stays healthy.
            Err(zmq::Error::EAGAIN) => return None,
            Err(e) => {
                // Whatever Core publishes before the reconnect is lost.
                state.socket = None;
                state.missed = true;
                log::warn!("ZMQ recv {}: {e}", self.addr);
                return None;
            }
        };
        // Core sends topic, body, and a 4-byte little-endian sequence number
        // that counts each topic's messages separately.
        let sequence = match msg.as_slice() {
            [_, _, sequence] => <[u8; 4]>::try_from(sequence.as_slice())
                .ok()
                .map(u32::from_le_bytes),
            _ => None,
        };
        let Some(sequence) = sequence else {
            state.missed = true;
            log::warn!(
                "ZMQ recv {}: malformed message with {} frames, treating it as lost",
                self.addr,
                msg.len()
            );
            return None;
        };
        let body = msg.swap_remove(1);
        let topic = String::from_utf8_lossy(&msg[0]).to_string();
        // `wrapping_add` keeps Core's u32::MAX -> 0 rollover continuous. Any
        // other jump, including a reset to 0 when Core restarts, lost messages.
        if let Some(last) = state.last_sequence.insert(topic.clone(), sequence) {
            if sequence != last.wrapping_add(1) {
                state.missed = true;
                log::warn!(
                    "ZMQ {topic} sequence went from {last} to {sequence}: notifications were lost or Core restarted"
                );
            }
        }
        Some((topic, body))
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

    /// Returns the active-chain height for a block received through ZMQ.
    pub(crate) fn block_height(&self, block_hash: &BlockHash) -> Result<u64, WalletError> {
        Ok(self.rpc.get_block_header_info(block_hash)?.height as u64)
    }

    /// Confirmations of `txid` on the active chain; `None` when Core does not
    /// know it. A reorged-out transaction stays indexed under its stale block,
    /// and Core reports it with 0 confirmations, like a mempool one.
    pub(crate) fn tx_confirmations(&self, txid: &Txid) -> Result<Option<u32>, WalletError> {
        match self.rpc.get_raw_transaction_info(txid, None) {
            Ok(info) => Ok(Some(info.confirmations.unwrap_or(0))),
            Err(CoreRpcError::JsonRpc(jsonrpc::Error::Rpc(ref e))) if e.code == -5 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Whether the txindex has caught up with the chain. Until it has, Core
    /// cannot find every mined transaction.
    pub(crate) fn txindex_synced(&self) -> Result<bool, WalletError> {
        let indexes: Value = self.rpc.call("getindexinfo", &[])?;
        Ok(indexes["txindex"]["synced"].as_bool().unwrap_or(false))
    }

    /// Test hook: take `txid`'s fee out of the miner's view, so regtest mining
    /// leaves it in the mempool the way a fee spike would. A replacement has
    /// another txid and is mined as usual.
    #[cfg(feature = "integration-test")]
    pub(crate) fn deprioritise_for_test(&self, txid: &Txid) -> Result<(), WalletError> {
        self.prioritise_for_test(txid, -100_000_000)
    }

    /// Test hook: shift `txid`'s fee in the miner's view by `delta` sats.
    #[cfg(feature = "integration-test")]
    pub(crate) fn prioritise_for_test(&self, txid: &Txid, delta: i64) -> Result<(), WalletError> {
        let _: bool = self.rpc.call(
            "prioritisetransaction",
            &[json!(txid.to_string()), json!(0), json!(delta)],
        )?;
        Ok(())
    }

    /// Test hook: orphan the block that mined `txid`, and every block on top
    /// of it, as a reorg would. Its txs go back to the mempool.
    #[cfg(feature = "integration-test")]
    pub(crate) fn orphan_block_of_for_test(&self, txid: &Txid) -> Result<(), WalletError> {
        let hash = self
            .rpc
            .get_raw_transaction_info(txid, None)?
            .blockhash
            .ok_or_else(|| WalletError::General(format!("{txid} is not mined")))?;
        let _: Value = self
            .rpc
            .call("invalidateblock", &[json!(hash.to_string())])?;
        Ok(())
    }

    /// The node's `incrementalrelayfee` in sat/vB: what a replacement must
    /// add over the tx it replaces. `None` when the node does not report one.
    pub(crate) fn incremental_relay_feerate(&self) -> Result<Option<f64>, WalletError> {
        Ok(self
            .rpc
            .get_mempool_info()?
            .incremental_relay_fee
            .map(|per_kvb| per_kvb.to_sat() as f64 / 1000.0))
    }

    pub(crate) fn spending_transaction(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<Transaction>, WalletError> {
        match self.mempool_spending_transaction(outpoint)? {
            Some(tx) => Ok(Some(tx)),
            None => self.mined_spending_transaction(outpoint),
        }
    }

    /// The mempool transaction spending `outpoint`.
    pub(crate) fn mempool_spending_transaction(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<Transaction>, WalletError> {
        let spends: Vec<SpendingPrevout> = self.rpc.call(
            "gettxspendingprevout",
            &[json!([{ "txid": outpoint.txid, "vout": outpoint.vout }])],
        )?;
        match spends.first().and_then(|spend| spend.spendingtxid) {
            Some(txid) => self.get_raw_transaction(&txid, None).map(Some),
            None => Ok(None),
        }
    }

    /// The transaction spending `outpoint` in a block of the active chain,
    /// found by scanning from the funding block.
    pub(crate) fn mined_spending_transaction(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Option<Transaction>, WalletError> {
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

    /// Older nodes lack `listdescriptors` and `tr()`, so sync would fail
    /// and retry forever, whatever kind of wallet the node holds.
    pub(crate) fn require_v22(&self) -> Result<(), WalletError> {
        if self.rpc.version()? < 220_000 {
            return Err(WalletError::CoreTooOld);
        }
        Ok(())
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
        // The txindex keeps naming the block of a tx a reorg took out of the
        // active chain; only confirmations say it is mined now.
        match info.blockhash {
            Some(hash) if info.confirmations.unwrap_or(0) > 0 => {
                Ok(Some(self.rpc.get_block_header_info(&hash)?.height as u64))
            }
            _ => Ok(None),
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
        // Confirmed in a block of the active chain. The txindex keeps naming
        // the block of a tx a reorg took out, as `tx_block_height` notes; such
        // a tx is known only if it went back to the mempool.
        if info.blockhash.is_some() && info.confirmations.unwrap_or(0) > 0 {
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

    fn script_has_history(&self, script: &Script, network: Network) -> Result<bool, WalletError> {
        let address = Address::from_script(script, network)
            .map_err(|e| WalletError::General(e.to_string()))?;
        // The transaction list hides change outputs; the received total
        // still counts an address after it is emptied.
        match self.rpc.get_received_by_address(&address, Some(0)) {
            Ok(received) => Ok(received > Amount::ZERO),
            // -4: not imported yet. The gap loop imports the wider range and asks again.
            Err(CoreRpcError::JsonRpc(jsonrpc::Error::Rpc(ref e))) if e.code == -4 => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn estimate_feerate(&self, priority: FeePriority) -> Result<f64, WalletError> {
        let res = self.rpc.estimate_smart_fee(priority as u16, None)?;
        let per_kvb = res.fee_rate.ok_or_else(|| {
            WalletError::General(format!("no estimate: {:?}", res.errors.unwrap_or_default()))
        })?;
        Ok(per_kvb.to_sat() as f64 / 1000.0)
    }

    /// Load the watch-only wallet on the node, creating it if absent. Refuses
    /// Core older than v22; only invoked on the Core sync path.
    fn prepare_backend_wallet(&self, wallet_name: &str) -> Result<(), WalletError> {
        self.require_v22()?;
        if self.rpc.list_wallets()?.contains(&wallet_name.to_string()) {
            log::debug!("wallet already loaded: {wallet_name}");
        } else if list_wallet_dir(&self.rpc)?.contains(&wallet_name.to_string()) {
            self.rpc.load_wallet(wallet_name)?;
            log::debug!("wallet loaded: {wallet_name}");
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
            log::debug!("wallet created: {wallet_name}");
        }
        Ok(())
    }

    fn imported_range_covers(
        &self,
        descriptor: &str,
        last_index: u32,
    ) -> Result<bool, WalletError> {
        #[derive(Deserialize)]
        struct WalletKind {
            descriptors: Option<bool>,
        }
        let kind: WalletKind = self.rpc.call("getwalletinfo", &[])?;
        if kind.descriptors != Some(true) {
            // Legacy wallets have no `listdescriptors`: check that the first
            // and last address of the window are watched, as before.
            for index in [0, last_index] {
                let address = self
                    .rpc
                    .derive_addresses(descriptor, Some([index, index]))?
                    .swap_remove(0)
                    .assume_checked();
                #[derive(Deserialize)]
                struct Watched {
                    iswatchonly: Option<bool>,
                }
                let info: Watched = self.rpc.call("getaddressinfo", &[json!(address)])?;
                if info.iswatchonly != Some(true) {
                    return Ok(false);
                }
            }
            return Ok(true);
        }
        #[derive(Deserialize)]
        struct Listed {
            desc: String,
            range: Option<[u32; 2]>,
        }
        #[derive(Deserialize)]
        struct Descriptors {
            descriptors: Vec<Listed>,
        }
        let listed: Descriptors = self.rpc.call("listdescriptors", &[])?;
        // Core lists the range end inclusive, so `end == last_index` covers it.
        Ok(listed
            .descriptors
            .into_iter()
            .find(|listed| listed.desc == descriptor)
            .and_then(|listed| listed.range)
            // Like the legacy check, coverage must start at index 0.
            .is_some_and(|[start, end]| start == 0 && end >= last_index))
    }

    fn import_descriptors(&self, requests: &[Value]) -> Result<(), WalletError> {
        let results: Vec<Value> = self
            .rpc
            .call("importdescriptors", &[Value::Array(requests.to_vec())])?;
        // Core rejects a descriptor in its own result, not as an RPC error.
        let failures: Vec<String> = requests
            .iter()
            .zip(&results)
            .filter(|(_, result)| result["success"] != true)
            .map(|(request, result)| format!("{}: {}", request["desc"], result["error"]))
            .collect();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(WalletError::General(format!(
                "importdescriptors failed: {}",
                failures.join("; ")
            )))
        }
    }

    fn rescan_wallet_from(&self, height: u64) -> Result<(), WalletError> {
        let _: Value = self.rpc.call("rescanblockchain", &[json!(height)])?;
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
        // A loss flagged while reading the previous message is reported
        // before the next one, so the drain that read it also reports it.
        if self.zmq.take_missed() {
            return Some(WatchEvent::Missed);
        }
        let Some((topic, payload)) = self.zmq.recv_event() else {
            // A garbled message or failed read yields no message, only the loss.
            return self.zmq.take_missed().then_some(WatchEvent::Missed);
        };
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

#[cfg(test)]
pub(crate) mod tests {
    use std::{
        collections::HashSet,
        io::{BufRead, BufReader, Read, Write},
        net::TcpListener,
        thread,
        time::Instant,
    };

    use super::*;
    use crate::{
        security::KeyMaterial,
        wallet::{api::test_support::test_wallet, AnyBlockchain, BackendConfig, Wallet},
    };
    use zeroize::Zeroizing;

    /// Serves one canned reply per JSON-RPC method, failing on any other.
    fn mock_core(
        replies: Vec<(&'static str, Value)>,
    ) -> (CoreRPC, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock core");
        let addr = listener.local_addr().unwrap();
        let expected = replies.len();
        let server = thread::spawn(move || {
            let mut seen = Vec::new();
            while seen.len() < expected {
                let (stream, _) = listener.accept().expect("accept core client");
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                while seen.len() < expected && reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let mut body_len = 0;
                    while line.trim() != "" {
                        if let Some(n) = line.to_lowercase().strip_prefix("content-length:") {
                            body_len = n.trim().parse().unwrap();
                        }
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                    }
                    line.clear();
                    let mut body = vec![0; body_len];
                    reader.read_exact(&mut body).unwrap();
                    let request: Value = serde_json::from_slice(&body).unwrap();
                    let method = request["method"].as_str().unwrap().to_string();
                    let result = replies
                        .iter()
                        .find(|(m, _)| *m == method)
                        .unwrap_or_else(|| panic!("unexpected call {}", method))
                        .1
                        .clone();
                    seen.push(method);
                    let reply = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result, "error": null })
                        .to_string();
                    write!(
                        writer,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                        reply.len()
                    )
                    .unwrap();
                    writer.flush().unwrap();
                }
            }
            seen
        });
        let core = CoreRPC::new(&CoreRpcConfig {
            url: addr.to_string(),
            ..Default::default()
        })
        .unwrap();
        (core, server)
    }

    #[test]
    fn imported_range_covers_needs_the_range_to_start_at_zero() {
        let desc = "wpkh(xpub/0/*)#abcd1234";
        // `listdescriptors` reports both ends inclusive (`range_end - 1` in Core).
        for (range, last_index, expected) in [
            ([20, 200], 100, false),
            ([0, 200], 100, true),
            ([0, 100], 100, true),
            ([0, 99], 100, false),
        ] {
            let (core, server) = mock_core(vec![
                (
                    "getwalletinfo",
                    json!({ "walletname": "w", "descriptors": true }),
                ),
                (
                    "listdescriptors",
                    json!({ "wallet_name": "w", "descriptors": [{ "desc": desc, "range": range }] }),
                ),
            ]);
            assert_eq!(
                core.imported_range_covers(desc, last_index).unwrap(),
                expected,
                "range {range:?}, last index {last_index}"
            );
            server.join().unwrap();
        }
    }

    /// Core 0.21 has no `listdescriptors`, and its default wallets are legacy:
    /// the version is refused before any wallet is loaded or inspected.
    #[test]
    fn prepare_backend_wallet_refuses_core_before_v22() {
        let (core, server) = mock_core(vec![("getnetworkinfo", json!({ "version": 210100 }))]);
        assert!(matches!(
            core.prepare_backend_wallet("w"),
            Err(WalletError::CoreTooOld)
        ));
        assert_eq!(server.join().unwrap(), ["getnetworkinfo"]);
    }

    /// A Core 0.21 node answering only the backup/restore backend probe.
    fn mock_core_v21() -> (CoreRPC, thread::JoinHandle<Vec<String>>) {
        let info = json!({ "chain": "regtest", "blocks": 0, "headers": 0,
            "bestblockhash": "0".repeat(64), "difficulty": 0.0,
            "mediantime": 0, "verificationprogress": 1.0, "initialblockdownload": false,
            "chainwork": "00", "size_on_disk": 0, "pruned": false, "warnings": "" });
        mock_core(vec![
            ("getblockchaininfo", info),
            // Asked once by `get_blockchain_info` itself, once by the v22 gate.
            ("getnetworkinfo", json!({ "version": 210100 })),
            ("getnetworkinfo", json!({ "version": 210100 })),
        ])
    }

    /// The restore's backend probe refuses Core 0.21, so no wallet file is left.
    #[test]
    fn restore_refuses_core_before_v22_without_a_wallet_file() {
        let (core, server) = mock_core_v21();
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("w");
        let err = Wallet::restore_from_mnemonic(
            Zeroizing::new("abandon ".repeat(11) + "about"),
            &path,
            &BackendConfig::CoreRpc(core.config.clone()),
            Default::default(),
            Zeroizing::new("pass".to_string()),
        )
        .expect_err("Core 0.21 must be refused");
        assert!(matches!(err, WalletError::CoreTooOld), "{}", err);
        assert!(!path.exists());
        assert_eq!(
            server.join().unwrap(),
            ["getblockchaininfo", "getnetworkinfo", "getnetworkinfo"]
        );
    }

    /// A new CLI wallet refuses Core 0.21 before its file and sealed seed are written.
    #[test]
    fn init_interactive_refuses_core_before_v22_without_a_wallet_file() {
        let (core, server) = mock_core_v21();
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("w");
        let err = Wallet::init_interactive(
            &path,
            &BackendConfig::CoreRpc(core.config.clone()),
            Some("pass".to_string()),
        )
        .expect_err("Core 0.21 must be refused");
        assert!(matches!(err, WalletError::CoreTooOld), "{}", err);
        assert!(!path.exists());
        assert_eq!(
            server.join().unwrap(),
            ["getblockchaininfo", "getnetworkinfo", "getnetworkinfo"]
        );
    }

    /// Library callers (`MakerServer::init`, `Taker::init`) create wallets
    /// through `load_or_init`; Core 0.21 is refused there too, with no file.
    #[test]
    fn load_or_init_refuses_core_before_v22_without_a_wallet_file() {
        let (core, server) = mock_core_v21();
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("w");
        let err = Wallet::load_or_init(
            &path,
            AnyBlockchain::CoreRPC(core),
            Some("pass".to_string()),
        )
        .expect_err("Core 0.21 must be refused");
        assert!(matches!(err, WalletError::CoreTooOld), "{}", err);
        assert!(!path.exists());
        assert_eq!(
            server.join().unwrap(),
            ["getblockchaininfo", "getnetworkinfo", "getnetworkinfo"]
        );
    }

    /// Loading an existing wallet refuses Core 0.21 before the file is opened,
    /// and leaves the file untouched.
    #[test]
    fn load_or_init_refuses_core_before_v22_for_an_existing_wallet() {
        let (core, server) = mock_core(vec![("getnetworkinfo", json!({ "version": 210100 }))]);
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let path = dir.path().join("w");
        drop(test_wallet(&path));
        let before = std::fs::read(&path).unwrap();
        let err = Wallet::load_or_init(
            &path,
            AnyBlockchain::CoreRPC(core),
            Some("test-password".to_string()),
        )
        .expect_err("Core 0.21 must be refused");
        assert!(matches!(err, WalletError::CoreTooOld), "{}", err);
        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert_eq!(server.join().unwrap(), ["getnetworkinfo"]);
    }

    /// The backup's backend probe refuses Core 0.21, so no backup file is left.
    #[test]
    fn backup_refuses_core_before_v22_without_a_backup_file() {
        let (core, server) = mock_core_v21();
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let mut wallet = test_wallet(&dir.path().join("w"));
        wallet.blockchain = AnyBlockchain::CoreRPC(core);
        let path = dir.path().join("backup.json");
        let err = wallet
            .backup(
                &path,
                Zeroizing::new("test-password".to_string()),
                KeyMaterial::new_ephemeral(),
            )
            .expect_err("Core 0.21 must be refused");
        assert!(matches!(err, WalletError::CoreTooOld), "{}", err);
        assert!(!path.exists());
        assert_eq!(
            server.join().unwrap(),
            ["getblockchaininfo", "getnetworkinfo", "getnetworkinfo"]
        );
    }

    #[test]
    fn imported_range_covers_legacy_wallet_without_listdescriptors() {
        let addr = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";
        let (core, server) = mock_core(vec![
            (
                "getwalletinfo",
                json!({ "walletname": "w", "descriptors": false }),
            ),
            ("deriveaddresses", json!([addr])),
            (
                "getaddressinfo",
                json!({ "address": addr, "iswatchonly": false }),
            ),
        ]);
        assert!(!core.imported_range_covers("wpkh(xpub/0/*)", 99).unwrap());
        assert_eq!(
            server.join().unwrap(),
            ["getwalletinfo", "deriveaddresses", "getaddressinfo"],
            "a legacy wallet must not reach listdescriptors"
        );
    }

    /// Stands in for Core's ZMQ publisher.
    pub(crate) struct ZmqPublisher {
        socket: zmq::Socket,
        pub(crate) addr: String,
    }

    impl ZmqPublisher {
        pub(crate) fn bind(endpoint: &str) -> Self {
            // XPUB rather than PUB: it reports incoming subscriptions, so a
            // test can wait out the slow-joiner handshake instead of sleeping.
            let socket = zmq::Context::new().socket(zmq::XPUB).unwrap();
            socket.bind(endpoint).unwrap();
            let addr = socket.get_last_endpoint().unwrap().unwrap();
            Self { socket, addr }
        }

        /// Blocks until both topic subscriptions arrive; nothing published
        /// after that is lost to the handshake. `poll` must call into the
        /// subscriber: a SUB socket connects lazily and, after a reconnect,
        /// only re-sends its subscriptions while its owner keeps calling it.
        pub(crate) fn wait_for_subscriber(&self, mut poll: impl FnMut()) {
            self.socket.set_rcvtimeo(50).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            let mut topics = HashSet::new();
            while topics.len() < 2 {
                assert!(
                    Instant::now() < deadline,
                    "subscriber did not subscribe within 10s"
                );
                poll();
                if let Ok(frame) = self.socket.recv_bytes(0) {
                    if frame.first() == Some(&1) {
                        topics.insert(frame[1..].to_vec());
                    }
                }
            }
        }

        /// Publishes Core's three-frame message: topic, body, LE `u32` sequence.
        pub(crate) fn publish(&self, topic: &str, body: &[u8], sequence: u32) {
            self.send(&[topic.as_bytes(), body, &sequence.to_le_bytes()]);
        }

        pub(crate) fn send(&self, frames: &[&[u8]]) {
            self.socket
                .send_multipart(frames.iter().copied(), 0)
                .unwrap();
        }
    }

    /// A Core backend subscribed to `publisher`. The RPC side is never used.
    fn subscribed_core(publisher: &ZmqPublisher) -> CoreRPC {
        let core = CoreRPC::new(&CoreRpcConfig {
            zmq_addr: publisher.addr.clone(),
            ..CoreRpcConfig::default()
        })
        .unwrap();
        publisher.wait_for_subscriber(|| assert!(core.poll_event().is_none()));
        core
    }

    /// Polls until `messages` notifications have arrived, plus one more poll
    /// to catch a loss flagged by the last of them. Returns the event kinds.
    fn poll_kinds(core: &CoreRPC, messages: usize) -> Vec<&'static str> {
        let kind = |event: &WatchEvent| match event {
            WatchEvent::TxSeen { .. } => "tx",
            WatchEvent::BlockConnected(_) => "block",
            WatchEvent::Missed => "missed",
            WatchEvent::Unreachable => "unreachable",
            WatchEvent::Unfetched(_) => "unfetched",
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut kinds = Vec::new();
        while kinds.iter().filter(|k| **k != "missed").count() < messages {
            assert!(Instant::now() < deadline, "only got {:?}", kinds);
            match core.poll_event() {
                Some(event) => kinds.push(kind(&event)),
                None => thread::sleep(Duration::from_millis(5)),
            }
        }
        kinds.extend(core.poll_event().as_ref().map(kind));
        kinds
    }

    #[test]
    fn zmq_sequence_gap_is_reported() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        for sequence in [0, 1, 3] {
            publisher.publish("rawtx", b"tx", sequence);
        }
        assert_eq!(poll_kinds(&core, 3), ["tx", "tx", "tx", "missed"]);
    }

    #[test]
    fn zmq_sequence_wraparound_is_not_a_gap() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        // The first message only sets the baseline, wherever Core's count is.
        for sequence in [u32::MAX - 1, u32::MAX, 0, 1] {
            publisher.publish("rawtx", b"tx", sequence);
        }
        assert_eq!(poll_kinds(&core, 4), ["tx", "tx", "tx", "tx"]);
    }

    #[test]
    fn zmq_sequence_reset_is_reported() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        // A restarted Core counts from 0 again.
        for sequence in [5, 6, 0] {
            publisher.publish("rawblock", b"block", sequence);
        }
        assert_eq!(poll_kinds(&core, 3), ["block", "block", "block", "missed"]);
    }

    #[test]
    fn zmq_topics_are_sequenced_independently() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        publisher.publish("rawtx", b"tx", 0);
        publisher.publish("rawblock", b"block", 0);
        publisher.publish("rawtx", b"tx", 1);
        publisher.publish("rawblock", b"block", 1);
        publisher.publish("rawtx", b"tx", 2);
        assert_eq!(poll_kinds(&core, 5), ["tx", "block", "tx", "block", "tx"]);

        publisher.publish("rawblock", b"block", 3);
        assert_eq!(poll_kinds(&core, 1), ["block", "missed"]);
    }

    #[test]
    fn zmq_malformed_message_is_reported_as_missed() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        publisher.publish("rawtx", b"tx", 0);
        // No sequence frame, then a sequence frame of the wrong width.
        publisher.send(&[b"rawtx", b"tx"]);
        publisher.send(&[b"rawtx", b"tx", &[1, 0, 0]]);
        publisher.publish("rawtx", b"tx", 1);
        assert_eq!(poll_kinds(&core, 2), ["tx", "missed", "missed", "tx"]);
    }

    #[test]
    fn zmq_publisher_restart_is_reported() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        publisher.publish("rawtx", b"tx", 0);
        publisher.publish("rawtx", b"tx", 1);
        assert_eq!(poll_kinds(&core, 2), ["tx", "tx"]);

        // Core restarts on the same endpoint; libzmq reconnects on its own.
        let addr = publisher.addr.clone();
        drop(publisher);
        let publisher = ZmqPublisher::bind(&addr);
        publisher.wait_for_subscriber(|| assert!(core.poll_event().is_none()));
        publisher.publish("rawtx", b"tx", 0);
        assert_eq!(poll_kinds(&core, 1), ["tx", "missed"]);
    }

    #[test]
    fn zmq_receive_error_is_reported_and_reconnects() {
        let publisher = ZmqPublisher::bind("tcp://127.0.0.1:*");
        let core = subscribed_core(&publisher);
        // The replacement socket re-sends subscriptions the publisher may still
        // hold for the old one; have them reported anyway.
        publisher.socket.set_xpub_verbose(true).unwrap();
        publisher.publish("rawtx", b"tx", 0);
        assert_eq!(poll_kinds(&core, 1), ["tx"]);

        // A PUB socket cannot receive, so the next read fails.
        let broken = zmq::Context::new().socket(zmq::PUB).unwrap();
        core.zmq.state.lock().unwrap().socket = Some(broken);
        assert!(matches!(core.poll_event(), Some(WatchEvent::Missed)));

        // The next poll connects a new socket and reports nothing further.
        publisher.wait_for_subscriber(|| assert!(core.poll_event().is_none()));
        publisher.publish("rawtx", b"tx", 1);
        assert_eq!(poll_kinds(&core, 1), ["tx"]);
    }

    #[test]
    fn estimate_feerate_forwards_target_and_converts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock core");
        let addr = listener.local_addr().unwrap();

        // Answers one estimate, then Core's "no estimate" shape, on any connection.
        let server = thread::spawn(move || {
            let mut replies = vec![
                (2, json!({ "feerate": 0.0002, "blocks": 2 })),
                (
                    144,
                    json!({ "errors": ["Insufficient data or no feerate found"], "blocks": 0 }),
                ),
            ]
            .into_iter();
            while replies.len() > 0 {
                let (stream, _) = listener.accept().expect("accept core client");
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                while replies.len() > 0 && reader.read_line(&mut line).unwrap_or(0) > 0 {
                    let mut body_len = 0;
                    while line.trim() != "" {
                        if let Some(n) = line.to_lowercase().strip_prefix("content-length:") {
                            body_len = n.trim().parse().unwrap();
                        }
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                    }
                    line.clear();
                    let mut body = vec![0; body_len];
                    reader.read_exact(&mut body).unwrap();
                    let request: Value = serde_json::from_slice(&body).unwrap();
                    let (target, result) = replies.next().unwrap();
                    assert_eq!(request["method"], "estimatesmartfee");
                    assert_eq!(request["params"], json!([target]));
                    let reply = json!({ "jsonrpc": "2.0", "id": request["id"], "result": result, "error": null })
                        .to_string();
                    write!(
                        writer,
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{reply}",
                        reply.len()
                    )
                    .unwrap();
                    writer.flush().unwrap();
                }
            }
        });

        let core = CoreRPC::new(&CoreRpcConfig {
            url: addr.to_string(),
            ..Default::default()
        })
        .unwrap();
        assert_eq!(core.estimate_feerate(FeePriority::Urgent).unwrap(), 20.0);
        let err = format!(
            "{:?}",
            core.estimate_feerate(FeePriority::Economy).unwrap_err()
        );
        assert!(err.contains("Insufficient data"), "{}", err);
        server.join().unwrap();
    }
}
