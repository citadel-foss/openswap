//! Balance expectations: which fields of one wallet's [`Balances`] a test
//! asserts, and against what.
//!
//! A field left `None` is not asserted, so converting a test never adds an
//! assertion it did not make. Values are written by the test, never derived.

use bitcoin::Amount;
use openswap::wallet::Balances;

/// What one balance field must equal.
#[derive(Clone, Copy, Debug)]
pub enum Is {
    /// `field.to_sat() == n`.
    Sats(u64),
    /// `field == amount`, e.g. `Amount::ZERO` or the 0.05 BTC bond.
    Amount(Amount),
}

/// How a test subtracts one spendable balance from another. The styles differ
/// only when the result would be negative, and that difference is kept.
#[derive(Clone, Copy, Debug)]
pub enum DiffStyle {
    /// `a.checked_sub(b).unwrap()`: a negative result panics.
    CheckedUnwrap,
    /// `a.checked_sub(b).unwrap_or(Amount::ZERO)`: a negative result reads as zero.
    UnwrapOrZero,
}

/// The expected move of the spendable balance away from a baseline the test
/// captured (the funding return or the pre-swap maker balances).
#[derive(Clone, Copy, Debug)]
pub enum Delta {
    /// `baseline - spendable == sats`: what the wallet paid.
    Loss {
        baseline: Amount,
        style: DiffStyle,
        sats: u64,
    },
    /// `spendable - baseline == sats`: what the wallet earned.
    Gain {
        baseline: Amount,
        style: DiffStyle,
        sats: u64,
    },
}

/// The expected balances of one wallet, asserted in field order: `regular`,
/// `swap`, `contract`, `fidelity`, `spendable`, then `delta`.
#[derive(Clone, Copy, Debug)]
pub struct BalanceExpect {
    pub regular: Option<Is>,
    pub swap: Option<Is>,
    pub contract: Option<Is>,
    pub fidelity: Option<Is>,
    pub spendable: Option<Is>,
    pub delta: Option<Delta>,
}

impl BalanceExpect {
    /// Asserts every `Some` field of `self` against `balances`. `label` names
    /// the wallet in failure messages, e.g. `"Taker"` or `"Maker 1"`.
    #[track_caller]
    pub fn assert(&self, label: &str, balances: &Balances) {
        let fields = [
            ("regular", self.regular, balances.regular),
            ("swap", self.swap, balances.swap),
            ("contract", self.contract, balances.contract),
            ("fidelity", self.fidelity, balances.fidelity),
            ("spendable", self.spendable, balances.spendable),
        ];
        for (field, expected, actual) in fields {
            match expected {
                None => {}
                Some(Is::Sats(sats)) => assert_eq!(
                    actual.to_sat(),
                    sats,
                    "{} {} balance mismatch",
                    label,
                    field
                ),
                Some(Is::Amount(amount)) => {
                    assert_eq!(actual, amount, "{} {} balance mismatch", label, field)
                }
            }
        }
        match self.delta {
            None => {}
            Some(Delta::Loss {
                baseline,
                style,
                sats,
            }) => assert_eq!(
                diff(style, baseline, balances.spendable, label).to_sat(),
                sats,
                "{} spendable loss mismatch (baseline {}, spendable {})",
                label,
                baseline,
                balances.spendable
            ),
            Some(Delta::Gain {
                baseline,
                style,
                sats,
            }) => assert_eq!(
                diff(style, balances.spendable, baseline, label).to_sat(),
                sats,
                "{} spendable gain mismatch (baseline {}, spendable {})",
                label,
                baseline,
                balances.spendable
            ),
        }
    }
}

/// `minuend - subtrahend` in the given style.
#[track_caller]
fn diff(style: DiffStyle, minuend: Amount, subtrahend: Amount, label: &str) -> Amount {
    match (style, minuend.checked_sub(subtrahend)) {
        (_, Some(difference)) => difference,
        (DiffStyle::CheckedUnwrap, None) => panic!(
            "{} spendable difference is negative: {} - {}",
            label, minuend, subtrahend
        ),
        (DiffStyle::UnwrapOrZero, None) => Amount::ZERO,
    }
}
