//! The OpenSwap Wallet (unsecured). Used by both the Taker and Maker.

mod api;
mod backup;
pub(crate) mod blockchain;
pub mod deniability;
mod error;
pub mod ffi;
mod fidelity;
mod funding;
mod report;
mod spend;
mod storage;
pub(crate) mod swapcoin;

pub(crate) use api::{
    contract_and_timelock_vsize, infer_address_type, payment_settlement_budget_sats,
    wait_for_tx_confirmation, SpendKind,
};
pub use api::{Balances, RecoveryOutcome, SecretMnemonic, UTXOSpendInfo, Wallet};
pub use backup::WalletBackup;
pub use blockchain::{
    AnyBlockchain, BackendConfig, Blockchain, CoreRPC, CoreRpcConfig, Electrum, ElectrumConfig,
    HdOrigin,
};
pub use deniability::{verify_deniability, DeniabilityProof, DeniabilityProofData};
pub use error::WalletError;
pub use fidelity::FidelityBond;
pub(crate) use fidelity::{
    verify_fidelity_checks, FidelityError, MAX_FIDELITY_TIMELOCK, MIN_FIDELITY_TIMELOCK,
};
pub use report::{
    MakerFeeInfo, MakerReport, PaymentResult, RecoveryReport, ReportUtxo, SwapRole, SwapStatus,
    TakerReport,
};
pub use spend::Destination;
pub use storage::AddressType;
