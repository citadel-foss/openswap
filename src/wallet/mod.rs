//! The OpenSwap Wallet (unsecured). Used by both the Taker and Maker.

mod api;
#[cfg(test)]
pub(crate) use api::test_support::test_wallet;
mod backup;
pub(crate) mod blockchain;
pub mod deniability;
mod error;
pub mod ffi;
mod fidelity;
pub(crate) mod funding;
mod report;
mod seed;
pub mod seed_cli;
mod spend;
mod storage;
pub(crate) mod swapcoin;

pub(crate) use api::{
    contract_and_timelock_vsize, infer_address_type, p2tr_min_non_dust_sats,
    payment_settlement_budget_sats, replaced_version_discard_depth, wait_for_slots_confirmation,
    wait_for_tx_confirmation, SlotTrack, SlotWait, SlotWaitOutcome, SpendKind,
};
pub use api::{min_contract_value_sats, Balances, RecoveryOutcome, UTXOSpendInfo, Wallet};
pub use backup::{
    BondHint, OpenSwapsSummary, RestoreOptions, WalletBackup, RESTORE_OPEN_SWAPS_WARNING,
};
#[cfg(feature = "integration-test")]
#[doc(hidden)]
pub use blockchain::register_test_electrum_node;
pub use blockchain::{
    AnyBlockchain, BackendConfig, Blockchain, CoreRPC, CoreRpcConfig, Electrum, ElectrumConfig,
    FeePriority, HdOrigin,
};
pub use deniability::{verify_deniability, DeniabilityProof, DeniabilityProofData};
pub use error::WalletError;
pub use fidelity::FidelityBond;
pub(crate) use fidelity::{
    verify_fidelity_checks, FidelityError, MAX_FIDELITY_TIMELOCK, MIN_FIDELITY_BOND_AMOUNT_SATS,
    MIN_FIDELITY_TIMELOCK,
};
pub use report::{
    MakerFeeInfo, MakerReport, PaymentResult, RecoveryReport, ReportUtxo, SwapRole, SwapStatus,
    TakerReport,
};
pub use seed::SecretMnemonic;
pub use spend::Destination;
pub use storage::{AddressType, LnMakerDirection, LnMakerPhase, LnMakerSwapRecord, LnPendingSwap};

#[cfg(test)]
pub(crate) use backup::compat_backup;
#[cfg(test)]
pub(crate) use report::{compat_reports, SwapReportFile};
#[cfg(test)]
pub(crate) use storage::compat_support::{
    check_container, compat_assert_empty_extra, generate_storage,
};
#[cfg(test)]
pub(crate) use storage::{SwapReservation, WalletStore};
