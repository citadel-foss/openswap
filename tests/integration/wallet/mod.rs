//! The wallet and its backends: backup and restore, coin selection and
//! address grouping, transaction history, rebroadcasts, and the Electrum
//! transport.

mod backup;
mod broadcast_idempotency;
mod electrum_transport;
mod list_transactions;
mod utxo_behavior;
