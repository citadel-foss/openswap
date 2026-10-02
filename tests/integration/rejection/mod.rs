//! Everything either side must refuse, in one place.
//!
//! The refusal point differs per case but nothing settles in any of them.
//! The maker refuses: out-of-bounds, forged, or resent `SwapDetails`;
//! insufficient liquidity at offerbook sync or admission; under-delivered
//! amounts; wrong incoming counts; duplicated, overcounted, overstated, or
//! spent funding outpoints; a proof of funding with no contract binding;
//! mismatched taproot contract amounts; and funding plans that cost more than
//! the hop earns. The taker refuses: malformed legacy funding outputs;
//! underfunded, inflated, duplicated, or shape-breaking taproot contracts; and
//! fee skimming on either protocol. A fail-closed guard that lets one through
//! costs someone real funds.
//!
//! Each file holds one theme; see its module doc.

mod admission;
mod bans;
mod blocklist;
mod contract_response;
mod fees;
mod funding_proof;
mod keepalive;
mod partial_broadcast;
mod replay;
mod support;
