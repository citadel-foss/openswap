//! Defines a OpenSwap Taker Client.
//!
//! This also contains the entire swap workflow as major decision makings are involved for the Taker. Makers are
//! simple request-response servers. The Taker handles all the necessary communications between one or many makers to route the swap across various makers. Description of
//! protocol workflow is described in the [protocol between takers and makers](https://github.com/citadel-foss/OpenSwap-Protocol-Specification/blob/main/v1/3_protocol-flow.md)

mod config;
pub mod error;
pub mod offers;

pub mod api;
mod background_services;
mod legacy_swap;
mod legacy_verification;
mod payment;
pub mod swap_tracker;
mod taproot_swap;
mod taproot_verification;

pub use config::TakerConfig;

#[cfg(feature = "integration-test")]
pub use api::TakerBehavior;
pub use api::{MakerFeeInfo, SwapParams, SwapSummary, Taker, TakerInitConfig};
pub use offers::{
    format_state, BanReason, BanRecord, MakerOfferCandidate, MakerProtocol, MakerState, OfferBook,
    UnavailableReason, UnavailableState,
};
pub use payment::PaymentQuote;
