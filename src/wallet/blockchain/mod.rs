//! Blockchain backend abstraction shared by the wallet and the watchtower.
//!
//! A single [`Blockchain`] trait covers every chain operation either component
//! needs — UTXO/transaction queries, broadcasting, descriptor import and rescan,
//! script tracking, and watchtower notifications. Two concrete backends implement
//! it: [`CoreRPC`] (Bitcoin Core over JSON-RPC + ZMQ) and [`Electrum`] (the
//! Electrum protocol). [`AnyBlockchain`] is a runtime selector enum that also
//! implements [`Blockchain`], so the wallet holds a single
//! `blockchain: AnyBlockchain` and the whole stack stays non-generic while the
//! backend is still chosen at runtime.
//!
//! All methods take `&self`: the concrete backends use interior mutability for
//! their caches and notification state, which keeps every backend `Send + Sync`
//! so the wallet can be shared as `Arc<RwLock<Wallet>>`.
//!
//! Think of this module as the thin scaffolding that lets the rest of the code
//! talk to "a blockchain" without caring whether that is Bitcoin Core or an
//! Electrum server.

mod corerpc;
mod electrum;

pub use corerpc::{CoreRPC, CoreRpcConfig};
pub use electrum::{Electrum, ElectrumConfig, WATCHER_READ_TIMEOUT_DIRECT_SECS};

use std::fmt::Debug;

use bitcoin::{
    address::NetworkUnchecked, block::Header, Address, Block, BlockHash, OutPoint, Script,
    Transaction, Txid,
};
use bitcoind::bitcoincore_rpc::json::{
    EstimateMode, EstimateSmartFeeResult, GetAddressInfoResult, GetBlockchainInfoResult,
    GetRawTransactionResult, GetTxOutResult, ListTransactionResult, ListUnspentResultEntry,
    ScanningDetails,
};
use serde_json::Value;

use super::error::WalletError;

/// Error for a [`Blockchain`] method the active backend does not support
/// (e.g. SPV proofs or `estimatesmartfee` on Electrum).
fn unsupported(method: &str) -> WalletError {
    WalletError::General(format!("{method} is not supported by this backend"))
}

/// HD-origin metadata for a watched script.
///
/// Returned by [`Blockchain::hd_origin_for_script`] so the wallet's UTXO
/// classifier can recognise an Electrum-sourced UTXO as a `SeedCoin`/`SweptCoin`
/// without a descriptor round-trip (Bitcoin Core carries the same info in the
/// descriptor string on each UTXO and returns `None` here).
#[derive(Debug, Clone)]
pub struct HdOrigin {
    /// Fingerprint of the account-level xpub the script was derived under.
    pub fingerprint: String,
    /// 0 for external (receive) chain, 1 for internal (change) chain.
    pub keychain_idx: u32,
    /// Index along the chosen chain.
    pub index: u32,
    /// True if derived under the P2TR descriptor, false for P2WPKH.
    pub is_taproot: bool,
}

/// Reference to a block surfaced by [`Blockchain::poll_event`].
///
/// Used by the watchtower to checkpoint the chain tip. The Bitcoin Core backend
/// ships full serialized block bytes in `hash`; the Electrum backend ships just
/// the 32-byte block hash (with `height` populated).
#[derive(Debug, Clone)]
pub struct BlockRef {
    /// Height of the block if known, `0` when unavailable.
    pub height: u64,
    /// Either the full serialized block (Core/ZMQ) or the 32-byte hash (Electrum).
    pub hash: Vec<u8>,
}

/// Events emitted by [`Blockchain::poll_event`], consumed by the watchtower loop.
#[derive(Debug, Clone)]
pub enum WatchEvent {
    /// A transaction was seen (mempool or block); carries its raw bytes.
    TxSeen {
        /// Raw transaction bytes.
        raw_tx: Vec<u8>,
    },
    /// The chain tip advanced; carries the new block reference.
    BlockConnected(BlockRef),
}

/// Resolved backend selector. Built from the user's init config (the single
/// source of truth) and handed to [`AnyBlockchain::from_config`] and the
/// watchtower service.
#[derive(Debug, Clone)]
pub enum BackendConfig {
    /// Drive RPC through Bitcoin Core.
    CoreRpc(CoreRpcConfig),
    /// Drive RPC through an Electrum-protocol server.
    Electrum(ElectrumConfig),
}

impl BackendConfig {
    /// The same backend, tuned for the watchtower. It answers preimage queries
    /// on the thread it does chain I/O on, so a wedged read delays those
    /// answers, and its own retry loops already cover a single failed call.
    pub fn for_watcher(&self) -> Self {
        match self {
            BackendConfig::CoreRpc(cfg) => BackendConfig::CoreRpc(cfg.clone()),
            BackendConfig::Electrum(cfg) => BackendConfig::Electrum(ElectrumConfig {
                max_retries: 1,
                // Only a direct link gets the short bound. A proxied round trip
                // cannot finish that fast, so it keeps its derived timeout.
                timeout: cfg.timeout.or_else(|| {
                    cfg.socks5
                        .is_none()
                        .then_some(WATCHER_READ_TIMEOUT_DIRECT_SECS)
                }),
                ..cfg.clone()
            }),
        }
    }
}

/// Backend abstraction over a blockchain data source.
///
/// Implemented by [`CoreRPC`], [`Electrum`], and [`AnyBlockchain`]. The wallet
/// holds an instance for its UTXO/sync operations; the watchtower holds its own
/// instance for queries and notifications. Methods that only make sense for one
/// backend (descriptor import, SPV proofs, watch-only wallet bootstrap) provide
/// defaults or return errors on the other.
pub trait Blockchain: Send + Sync + 'static {
    /// True only for the Electrum backend; selects the wallet's sync path.
    fn is_electrum(&self) -> bool {
        false
    }

    // ---- chain / transaction queries -----------------------------------

    /// Chain metadata (`chain`, `best_block_hash`, …). Used for network
    /// detection at wallet init and fidelity-bond tip lookups.
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, WalletError>;
    /// Current chain tip height.
    fn get_block_count(&self) -> Result<u64, WalletError>;
    /// Block hash at `height`.
    fn get_block_hash(&self, height: u64) -> Result<BlockHash, WalletError>;
    /// Block header at `height`.
    ///
    /// Height-keyed rather than hash-keyed on purpose: the Electrum protocol
    /// indexes blocks only by height and offers no hash→height lookup, so a
    /// hash-keyed accessor would force the backend to emulate one with a bounded
    /// scan down from the tip. Every caller here already holds a height (or gets
    /// one from [`tx_block_height`](Self::tx_block_height)).
    fn header_at_height(&self, height: u64) -> Result<Header, WalletError>;
    /// Full block at `height`. Bitcoin Core only: the watchtower rescans blocks
    /// with it to find spends it missed while down. Electrum answers the same
    /// question from per-script history, so it never needs this.
    fn block_at_height(&self, _height: u64) -> Result<Block, WalletError> {
        Err(unsupported("block_at_height"))
    }
    /// Height of the block that mined `txid`, or `None` if it is unconfirmed or
    /// unknown to the backend.
    fn tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, WalletError>;
    /// True only when the spend of `outpoint` is confirmed on chain.
    ///
    /// Recovery uses this to discard a swapcoin: deleting on a mempool-only
    /// spend is a fund-loss bug, since such a spend can still be evicted.
    /// `script` is the outpoint's scriptPubKey — Electrum answers from the
    /// script's history (a second confirmed tx touching it), Core from its
    /// mempool-blind UTXO set.
    fn is_confirmed_spend(&self, outpoint: &OutPoint, script: &Script)
        -> Result<bool, WalletError>;
    /// Fetch a raw transaction by txid.
    fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<Transaction, WalletError>;
    /// Verbose transaction info; consumers read `confirmations`.
    fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<GetRawTransactionResult, WalletError>;
    /// Whether the backend positively reports the transaction as unknown.
    ///
    /// "Unknown" means neither mempool-visible nor confirmed, so a caller can
    /// safely rebroadcast. `Ok(true)` on an explicit "no such transaction"
    /// answer (Core's `-5`, Electrum's unknown-txid protocol error) or — Core
    /// only — when the node returns a mere wallet record of a transaction
    /// that is neither in the mempool nor in a block (i.e. it was evicted).
    /// Any transport or server failure is propagated, so a failed query is
    /// never read as absence.
    fn is_tx_unknown(&self, txid: &Txid) -> Result<bool, WalletError>;
    /// Unspent output at `txid:vout`, following Core's `gettxout`.
    ///
    /// `include_mempool`:
    /// * `None` / `Some(true)` — mempool included: unconfirmed outputs exist, and
    ///   ones already spent by an unconfirmed tx do not.
    /// * `Some(false)` — confirmed state only. Callers use this as an
    ///   "is it mined yet?" gate before spending on top of an output.
    ///
    /// Result:
    /// * `Ok(Some(_))` — still unspent; `confirmations` is `0` if unconfirmed.
    /// * `Ok(None)` — not spendable, but *why* is ambiguous: spent, never
    ///   broadcast, or filtered out by `include_mempool`. Callers that need to
    ///   tell these apart follow up with
    ///   [`get_raw_transaction_info`](Self::get_raw_transaction_info).
    /// * `Err(_)` — the query itself failed; says nothing about the output.
    ///
    /// One backend divergence: for an output confirmed but spent only in the
    /// mempool, `Some(false)` reports it live on Core and gone on Electrum.
    fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<GetTxOutResult>, WalletError>;
    /// UTXOs the backend considers ours: Core's watch-only wallet, or the scripts
    /// registered via [`watch_script`](Self::watch_script) on Electrum.
    ///
    /// Both bounds are inclusive, and a mempool UTXO counts as `0` confirmations:
    /// * `minconf` — lower bound; `Some(0)` includes the mempool, `Some(1)` does
    ///   not. `None` means Core's default of `1` but Electrum's `0`, so pass it
    ///   explicitly.
    /// * `maxconf` — upper bound. `None` means no bound (Core's own default
    ///   is `9999999`).
    ///
    /// Result:
    /// * `Ok(entries)` — one per matching UTXO. Not every field is meaningful on
    ///   both backends:
    ///   * `txid`, `vout`, `amount`, `script_pub_key`, `confirmations` — always
    ///     populated; safe to rely on.
    ///   * `descriptor`, `address`, `label` — Core only. Electrum has no
    ///     server-side wallet to name a UTXO, so these are always `None` there;
    ///     to recover which key derived it, look the entry's `script_pub_key` up
    ///     with [`hd_origin_for_script`](Self::hd_origin_for_script).
    ///   * `spendable`, `solvable`, `safe` — Core's real assessment; Electrum
    ///     always reports `true`, so they carry no information there.
    /// * `Ok(empty)` — nothing matched (on Electrum, also the answer before any
    ///   script has been registered).
    /// * `Err(_)` — the query failed.
    ///
    /// Coin locking is wallet-side (`Wallet::locked_utxos`), so locked UTXOs are
    /// still listed here; callers doing coin selection must filter them out.
    fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
    ) -> Result<Vec<ListUnspentResultEntry>, WalletError>;
    /// Broadcast a fully-signed transaction.
    fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, WalletError>;
    /// Expand a descriptor to addresses over an optional `[start, end]` range.
    fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<Address<NetworkUnchecked>>, WalletError>;
    /// Recent wallet transactions, newest window first, ordered oldest-first
    /// like Core. Used by the FFI history view, so every backend must answer it.
    fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<ListTransactionResult>, WalletError>;
    /// `estimatesmartfee` for `conf_target` blocks. Defaults to an error on
    /// Electrum (callers fall back to the mempool.space/esplora estimators).
    fn estimate_smart_fee(
        &self,
        _conf_target: u16,
        _estimate_mode: Option<EstimateMode>,
    ) -> Result<EstimateSmartFeeResult, WalletError> {
        Err(unsupported("estimate_smart_fee"))
    }
    // ---- Core-only sync helpers ----------------------------------------
    // These are invoked by `Wallet::sync` only on the Bitcoin Core path
    // (after an early return for Electrum), so the Electrum stubs are never hit.

    /// Bootstrap the watch-only wallet on the node (load or create, version-gated).
    /// No-op on Electrum.
    fn prepare_backend_wallet(&self, _wallet_name: &str) -> Result<(), WalletError> {
        Ok(())
    }
    /// Address metadata used to detect already-imported descriptors. Defaults to
    /// an error on Electrum (never reached: the sync path early-returns first).
    fn get_address_info(&self, _addr: &Address) -> Result<GetAddressInfoResult, WalletError> {
        Err(unsupported("get_address_info"))
    }
    /// Import descriptor request objects and trigger a rescan. Defaults to a
    /// no-op (Electrum pre-derives and registers scripts via `watch_script`).
    fn import_descriptors(&self, _requests: &[Value]) -> Result<(), WalletError> {
        Ok(())
    }
    /// Current rescan status (`getwalletinfo.scanning`); `None` when not scanning.
    /// Defaults to `None` (Electrum never rescans).
    fn wallet_scanning_status(&self) -> Result<Option<ScanningDetails>, WalletError> {
        Ok(None)
    }

    // ---- script tracking -----------------------------------------------

    /// Register a scriptPubKey for UTXO lookups. No-op on Bitcoin Core (the
    /// server-side wallet tracks these); Electrum stores it in a local watch set
    /// with an optional HD-origin hint.
    fn watch_script(&self, _script: &Script, _hd: Option<HdOrigin>) {}
    /// HD-origin recorded for `script` (Electrum only; Core returns `None`).
    fn hd_origin_for_script(&self, _script: &Script) -> Option<HdOrigin> {
        None
    }
    /// True when the backend's history for `script` is non-empty, spent outputs
    /// included. Restore probing uses this to bridge runs of emptied addresses;
    /// the default `false` keeps Bitcoin Core on the UTXO-based path.
    fn script_has_history(&self, _script: &Script) -> Result<bool, WalletError> {
        Ok(false)
    }

    // ---- watchtower notifications --------------------------------------

    /// Non-blocking poll for the next chain event (new tx or connected block).
    /// Lazily establishes the notification channel (ZMQ socket / Electrum
    /// header subscription) on first call. `None` means no event is pending;
    /// transport failures are logged by the backend.
    fn poll_event(&self) -> Option<WatchEvent>;
    /// Arm a per-script notification so future activity surfaces via
    /// [`poll_event`](Self::poll_event). `watch` is the outpoint needing it; several
    /// outpoints can share one script. No-op on Bitcoin Core (the `rawtx`
    /// feed already sees everything).
    fn subscribe_script(&self, _spk: &Script, _watch: OutPoint) -> Result<(), WalletError> {
        Ok(())
    }
    /// Release one outpoint's reference to a per-script subscription. The server
    /// subscription drops only when the last one goes away. No-op on Bitcoin Core.
    fn unsubscribe_script(&self, _spk: &Script, _watch: OutPoint) -> Result<(), WalletError> {
        Ok(())
    }
    /// Txids currently in the node mempool (Core only; Electrum returns empty,
    /// which makes the watchtower skip its startup mempool scan).
    fn get_raw_mempool(&self) -> Result<Vec<Txid>, WalletError> {
        Ok(Vec::new())
    }
    /// Bitcoin chain name string: `"main"`/`"test"`/`"testnet4"`/`"signet"`/`"regtest"`.
    fn chain_name(&self) -> Result<String, WalletError>;
}

/// Runtime backend selector. Implements [`Blockchain`] by dispatching to the
/// active variant, so top-level `Taker`/`MakerServer` init stays non-generic
/// while still choosing the backend from user config at runtime.
//
// The variants differ in size (Electrum carries several local caches), but only
// a handful of instances ever exist per process, so the size difference is not
// worth an extra heap indirection on every backend call.
#[allow(clippy::large_enum_variant)]
pub enum AnyBlockchain {
    /// Bitcoin Core (JSON-RPC + ZMQ).
    CoreRPC(CoreRPC),
    /// Electrum protocol.
    Electrum(Electrum),
}

impl AnyBlockchain {
    /// Build the active backend from the resolved [`BackendConfig`]. Each
    /// consumer (wallet, watchtower watcher, discovery) builds its own instance.
    pub fn from_config(backend: &BackendConfig) -> Result<Self, WalletError> {
        Self::from_config_with_shutdown(
            backend,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        )
    }

    /// Binds backend retry cancellation to the role that owns the connection.
    pub(crate) fn from_config_with_shutdown(
        backend: &BackendConfig,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Self, WalletError> {
        match backend {
            BackendConfig::CoreRpc(cfg) => Ok(AnyBlockchain::CoreRPC(CoreRPC::new(cfg)?)),
            BackendConfig::Electrum(cfg) => Ok(AnyBlockchain::Electrum(
                Electrum::with_shutdown_flag(cfg, shutdown)?,
            )),
        }
    }

    /// Open a fresh, independent connection to the same backend.
    ///
    /// Lets a second consumer (e.g. the watchtower discovery thread) get its own
    /// live connection by rebuilding from the backend's own stored config, so
    /// neither the wallet nor the watchtower has to keep a separate
    /// [`BackendConfig`] around.
    pub fn new_connection(&self) -> Result<Self, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => Ok(AnyBlockchain::CoreRPC(b.reconnect()?)),
            AnyBlockchain::Electrum(b) => Ok(AnyBlockchain::Electrum(b.reconnect()?)),
        }
    }

    /// Open a connection with cancellation owned by the new consumer.
    pub(crate) fn new_connection_with_shutdown(
        &self,
        shutdown: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<Self, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => Ok(AnyBlockchain::CoreRPC(b.reconnect()?)),
            AnyBlockchain::Electrum(b) => Ok(AnyBlockchain::Electrum(
                b.reconnect_with_shutdown(shutdown)?,
            )),
        }
    }

    /// Return the mempool or confirmed transaction spending `outpoint`.
    pub(crate) fn spending_transaction(
        &self,
        outpoint: &OutPoint,
        script: &Script,
        expected_txid: Option<&Txid>,
    ) -> Result<Option<Transaction>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.spending_transaction(outpoint).map(|spend| {
                spend.filter(|tx| expected_txid.is_none_or(|txid| tx.compute_txid() == *txid))
            }),
            AnyBlockchain::Electrum(b) => b.spending_transaction(outpoint, script, expected_txid),
        }
    }
}

/// Dispatch each [`Blockchain`] method to the active backend variant.
impl Blockchain for AnyBlockchain {
    fn is_electrum(&self) -> bool {
        match self {
            AnyBlockchain::CoreRPC(b) => b.is_electrum(),
            AnyBlockchain::Electrum(b) => b.is_electrum(),
        }
    }
    fn get_blockchain_info(&self) -> Result<GetBlockchainInfoResult, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_blockchain_info(),
            AnyBlockchain::Electrum(b) => b.get_blockchain_info(),
        }
    }
    fn get_block_count(&self) -> Result<u64, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_block_count(),
            AnyBlockchain::Electrum(b) => b.get_block_count(),
        }
    }
    fn get_block_hash(&self, height: u64) -> Result<BlockHash, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_block_hash(height),
            AnyBlockchain::Electrum(b) => b.get_block_hash(height),
        }
    }
    fn header_at_height(&self, height: u64) -> Result<Header, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.header_at_height(height),
            AnyBlockchain::Electrum(b) => b.header_at_height(height),
        }
    }
    fn block_at_height(&self, height: u64) -> Result<Block, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.block_at_height(height),
            AnyBlockchain::Electrum(b) => b.block_at_height(height),
        }
    }
    fn tx_block_height(&self, txid: &Txid) -> Result<Option<u64>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.tx_block_height(txid),
            AnyBlockchain::Electrum(b) => b.tx_block_height(txid),
        }
    }
    fn is_confirmed_spend(
        &self,
        outpoint: &OutPoint,
        script: &Script,
    ) -> Result<bool, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.is_confirmed_spend(outpoint, script),
            AnyBlockchain::Electrum(b) => b.is_confirmed_spend(outpoint, script),
        }
    }
    fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<Transaction, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_raw_transaction(txid, block_hash),
            AnyBlockchain::Electrum(b) => b.get_raw_transaction(txid, block_hash),
        }
    }
    fn get_raw_transaction_info(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> Result<GetRawTransactionResult, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_raw_transaction_info(txid, block_hash),
            AnyBlockchain::Electrum(b) => b.get_raw_transaction_info(txid, block_hash),
        }
    }
    fn is_tx_unknown(&self, txid: &Txid) -> Result<bool, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.is_tx_unknown(txid),
            AnyBlockchain::Electrum(b) => b.is_tx_unknown(txid),
        }
    }
    fn get_tx_out(
        &self,
        txid: &Txid,
        vout: u32,
        include_mempool: Option<bool>,
    ) -> Result<Option<GetTxOutResult>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_tx_out(txid, vout, include_mempool),
            AnyBlockchain::Electrum(b) => b.get_tx_out(txid, vout, include_mempool),
        }
    }
    fn list_unspent(
        &self,
        minconf: Option<usize>,
        maxconf: Option<usize>,
    ) -> Result<Vec<ListUnspentResultEntry>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.list_unspent(minconf, maxconf),
            AnyBlockchain::Electrum(b) => b.list_unspent(minconf, maxconf),
        }
    }
    fn send_raw_transaction(&self, tx: &Transaction) -> Result<Txid, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.send_raw_transaction(tx),
            AnyBlockchain::Electrum(b) => b.send_raw_transaction(tx),
        }
    }
    fn derive_addresses(
        &self,
        descriptor: &str,
        range: Option<[u32; 2]>,
    ) -> Result<Vec<Address<NetworkUnchecked>>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.derive_addresses(descriptor, range),
            AnyBlockchain::Electrum(b) => b.derive_addresses(descriptor, range),
        }
    }
    fn list_transactions(
        &self,
        label: Option<&str>,
        count: Option<usize>,
        skip: Option<usize>,
        include_watchonly: Option<bool>,
    ) -> Result<Vec<ListTransactionResult>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.list_transactions(label, count, skip, include_watchonly),
            AnyBlockchain::Electrum(b) => {
                b.list_transactions(label, count, skip, include_watchonly)
            }
        }
    }
    fn estimate_smart_fee(
        &self,
        conf_target: u16,
        estimate_mode: Option<EstimateMode>,
    ) -> Result<EstimateSmartFeeResult, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.estimate_smart_fee(conf_target, estimate_mode),
            AnyBlockchain::Electrum(b) => b.estimate_smart_fee(conf_target, estimate_mode),
        }
    }
    fn prepare_backend_wallet(&self, wallet_name: &str) -> Result<(), WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.prepare_backend_wallet(wallet_name),
            AnyBlockchain::Electrum(b) => b.prepare_backend_wallet(wallet_name),
        }
    }
    fn get_address_info(&self, addr: &Address) -> Result<GetAddressInfoResult, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_address_info(addr),
            AnyBlockchain::Electrum(b) => b.get_address_info(addr),
        }
    }
    fn import_descriptors(&self, requests: &[Value]) -> Result<(), WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.import_descriptors(requests),
            AnyBlockchain::Electrum(b) => b.import_descriptors(requests),
        }
    }
    fn wallet_scanning_status(&self) -> Result<Option<ScanningDetails>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.wallet_scanning_status(),
            AnyBlockchain::Electrum(b) => b.wallet_scanning_status(),
        }
    }
    fn watch_script(&self, script: &Script, hd: Option<HdOrigin>) {
        match self {
            AnyBlockchain::CoreRPC(b) => b.watch_script(script, hd),
            AnyBlockchain::Electrum(b) => b.watch_script(script, hd),
        }
    }
    fn hd_origin_for_script(&self, script: &Script) -> Option<HdOrigin> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.hd_origin_for_script(script),
            AnyBlockchain::Electrum(b) => b.hd_origin_for_script(script),
        }
    }
    fn script_has_history(&self, script: &Script) -> Result<bool, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.script_has_history(script),
            AnyBlockchain::Electrum(b) => b.script_has_history(script),
        }
    }
    fn poll_event(&self) -> Option<WatchEvent> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.poll_event(),
            AnyBlockchain::Electrum(b) => b.poll_event(),
        }
    }
    fn subscribe_script(&self, spk: &Script, watch: OutPoint) -> Result<(), WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.subscribe_script(spk, watch),
            AnyBlockchain::Electrum(b) => b.subscribe_script(spk, watch),
        }
    }
    fn unsubscribe_script(&self, spk: &Script, watch: OutPoint) -> Result<(), WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.unsubscribe_script(spk, watch),
            AnyBlockchain::Electrum(b) => b.unsubscribe_script(spk, watch),
        }
    }
    fn get_raw_mempool(&self) -> Result<Vec<Txid>, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.get_raw_mempool(),
            AnyBlockchain::Electrum(b) => b.get_raw_mempool(),
        }
    }
    fn chain_name(&self) -> Result<String, WalletError> {
        match self {
            AnyBlockchain::CoreRPC(b) => b.chain_name(),
            AnyBlockchain::Electrum(b) => b.chain_name(),
        }
    }
}

/// Match an Electrum server's `server_features().genesis_hash` against the known
/// network genesis blocks. Used by [`Electrum::new`] and `chain_name` to detect
/// the network the server is serving.
pub fn network_from_electrum_genesis(genesis: &[u8]) -> Option<bitcoin::Network> {
    use bitcoin::hashes::Hash;
    for net in [
        bitcoin::Network::Bitcoin,
        bitcoin::Network::Testnet,
        bitcoin::Network::Testnet4,
        bitcoin::Network::Signet,
        bitcoin::Network::Regtest,
    ] {
        let mut local = bitcoin::constants::genesis_block(net)
            .block_hash()
            .to_raw_hash()
            .to_byte_array();
        // Electrum returns `genesis_hash` in display (big-endian) byte order, while
        // `to_byte_array()` returns internal little-endian bytes, hence the reverse.
        local.reverse();
        if local == genesis {
            return Some(net);
        }
    }
    None
}

/// Reject chain names outside the known set. Consumers join the name into the
/// watch-registry path, so a server-supplied string must never reach the filesystem.
pub(crate) fn validate_chain_name(name: &str) -> Result<(), WalletError> {
    match name {
        "main" | "test" | "testnet4" | "signet" | "regtest" => Ok(()),
        other => Err(WalletError::General(format!(
            "unknown chain name from backend: {other:?}"
        ))),
    }
}

/// Bitcoin Core's chain-name string for a network
/// (`"main"`/`"test"`/`"testnet4"`/`"signet"`/`"regtest"`).
pub fn chain_name_for(net: bitcoin::Network) -> &'static str {
    match net {
        bitcoin::Network::Bitcoin => "main",
        bitcoin::Network::Testnet => "test",
        bitcoin::Network::Testnet4 => "testnet4",
        bitcoin::Network::Signet => "signet",
        bitcoin::Network::Regtest => "regtest",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn electrum_cfg(socks5: Option<&str>) -> ElectrumConfig {
        ElectrumConfig {
            url: "tcp://localhost:50001".to_string(),
            socks5: socks5.map(str::to_string),
            timeout: None,
            poll_interval_secs: None,
            max_retries: 3,
        }
    }

    #[test]
    fn watcher_config_fails_fast_only_on_a_direct_link() {
        let direct = BackendConfig::Electrum(electrum_cfg(None)).for_watcher();
        let BackendConfig::Electrum(direct) = direct else {
            panic!("expected the Electrum variant back");
        };
        assert_eq!(direct.max_retries, 1);
        assert_eq!(direct.timeout, Some(WATCHER_READ_TIMEOUT_DIRECT_SECS));

        let proxied = BackendConfig::Electrum(electrum_cfg(Some("127.0.0.1:9050"))).for_watcher();
        let BackendConfig::Electrum(proxied) = proxied else {
            panic!("expected the Electrum variant back");
        };
        assert_eq!(proxied.max_retries, 1);
        assert_eq!(proxied.timeout, None, "proxied keeps its derived timeout");
    }

    #[test]
    fn watcher_config_keeps_an_explicit_timeout() {
        let mut cfg = electrum_cfg(None);
        cfg.timeout = Some(45);
        let BackendConfig::Electrum(tuned) = BackendConfig::Electrum(cfg).for_watcher() else {
            panic!("expected the Electrum variant back");
        };
        assert_eq!(tuned.timeout, Some(45));
    }
}
