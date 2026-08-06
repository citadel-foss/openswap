//! Lightning backend error types.

use std::sync::{MutexGuard, PoisonError};

/// Errors that can occur while talking to a Lightning backend.
#[derive(Debug)]
pub enum LightningError {
    /// Failed to connect to or communicate with the backend node.
    Connection(String),
    /// The backend returned an API-level error.
    Api {
        /// A stable, backend-specific error code identifier.
        code: String,
        /// Human-readable error message. For logging only; do not parse.
        message: String,
    },
    /// The request timed out.
    Timeout,
    /// The backend returned a response we could not parse or that violated
    /// invariants (e.g. malformed hex, missing required fields).
    InvalidResponse(String),
    /// A BOLT11 invoice string could not be parsed or is otherwise unusable.
    InvalidInvoice(String),
    /// The referenced payment (by hash or id) is not known to the backend.
    PaymentNotFound,
    /// Not enough balance to perform the requested operation.
    InsufficientFunds,
    /// A Bitcoin address returned by or passed to the backend failed to parse.
    Address(bitcoin::address::ParseError),
    /// The event subscription stream failed.
    EventStream(String),
    /// Failure of the internal async runtime bridging layer.
    Runtime(String),
    /// A mutex protecting backend state was poisoned.
    MutexPoison,
    /// Generic error with a descriptive message.
    General(String),
}

impl std::fmt::Display for LightningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for LightningError {}

impl From<bitcoin::address::ParseError> for LightningError {
    fn from(value: bitcoin::address::ParseError) -> Self {
        LightningError::Address(value)
    }
}

impl<'a, T> From<PoisonError<MutexGuard<'a, T>>> for LightningError {
    fn from(_: PoisonError<MutexGuard<'a, T>>) -> Self {
        Self::MutexPoison
    }
}

impl LightningError {
    /// Returns a stable string identifier for the error variant.
    pub fn kind(&self) -> &'static str {
        match self {
            LightningError::Connection(_) => "Connection",
            LightningError::Api { .. } => "Api",
            LightningError::Timeout => "Timeout",
            LightningError::InvalidResponse(_) => "InvalidResponse",
            LightningError::InvalidInvoice(_) => "InvalidInvoice",
            LightningError::PaymentNotFound => "PaymentNotFound",
            LightningError::InsufficientFunds => "InsufficientFunds",
            LightningError::Address(_) => "Address",
            LightningError::EventStream(_) => "EventStream",
            LightningError::Runtime(_) => "Runtime",
            LightningError::MutexPoison => "MutexPoison",
            LightningError::General(_) => "General",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_kind_coverage() {
        let cases: Vec<(LightningError, &str)> = vec![
            (LightningError::Connection("x".to_string()), "Connection"),
            (
                LightningError::Api {
                    code: "InternalError".to_string(),
                    message: "boom".to_string(),
                },
                "Api",
            ),
            (LightningError::Timeout, "Timeout"),
            (
                LightningError::InvalidResponse("x".to_string()),
                "InvalidResponse",
            ),
            (
                LightningError::InvalidInvoice("x".to_string()),
                "InvalidInvoice",
            ),
            (LightningError::PaymentNotFound, "PaymentNotFound"),
            (LightningError::InsufficientFunds, "InsufficientFunds"),
            (LightningError::EventStream("x".to_string()), "EventStream"),
            (LightningError::Runtime("x".to_string()), "Runtime"),
            (LightningError::MutexPoison, "MutexPoison"),
            (LightningError::General("x".to_string()), "General"),
        ];
        for (error, kind) in cases {
            assert_eq!(error.kind(), kind);
            assert!(error.to_string().contains(kind));
        }

        let address_err = "not an address"
            .parse::<bitcoin::Address<bitcoin::address::NetworkUnchecked>>()
            .map(|_| ())
            .map_err(LightningError::from)
            .unwrap_err();
        assert_eq!(address_err.kind(), "Address");
    }
}
