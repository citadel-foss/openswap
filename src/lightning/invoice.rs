//! BOLT11 invoice verification shared by both swap roles.
//!
//! Paying (or accepting) an invoice that does not commit to the swap's own
//! payment hash and amount forfeits atomicity, so both the maker (swap-in:
//! pays the taker's invoice) and the taker (swap-out: pays the maker's
//! invoice) must verify the invoice string itself — never a peer-asserted
//! echo of its fields.

use bitcoin::hashes::{sha256, Hash};

/// Facts extracted from a verified invoice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedInvoice {
    /// The invoice's `min_final_cltv_expiry_delta` — the Lightning claim
    /// window that on-chain locktimes must be measured against.
    pub min_final_cltv_expiry_delta: u64,
}

/// Parses `invoice` and checks it commits to `payment_hash` and exactly
/// `expected_msat`.
pub fn verify_invoice(
    invoice: &str,
    payment_hash: &sha256::Hash,
    expected_msat: u64,
) -> Result<VerifiedInvoice, String> {
    let parsed: lightning_invoice::Bolt11Invoice = invoice
        .parse()
        .map_err(|e| format!("invoice does not parse: {e:?}"))?;
    if parsed.payment_hash().to_byte_array() != payment_hash.to_byte_array() {
        return Err("invoice payment hash does not match the swap".to_string());
    }
    match parsed.amount_milli_satoshis() {
        Some(msat) if msat == expected_msat => {}
        other => {
            return Err(format!(
                "invoice amount {:?} msat != expected {} msat",
                other, expected_msat
            ))
        }
    }
    Ok(VerifiedInvoice {
        min_final_cltv_expiry_delta: parsed.min_final_cltv_expiry_delta(),
    })
}
