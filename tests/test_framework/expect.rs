//! Balance expectations: which fields of one wallet's [`Balances`] a test
//! asserts, and against what.
//!
//! A field left `None` is not asserted, so converting a test never adds an
//! assertion it did not make. Values are written by the test, never derived.

use std::convert::TryFrom;

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

/// Every maker's fidelity bond in the default setup: 0.05 BTC.
pub const BOND: Amount = Amount::from_sat(5_000_000);

/// A value [`assert_balances!`] reads for each wallet of a row: sats or an
/// [`Amount`] that holds for every wallet, a list with one value per wallet, or
/// an `Option` of either, where `None` asserts nothing.
pub trait Column {
    /// The value for wallet `index`, or `None` to skip the field.
    fn at(&self, index: usize) -> Option<Amount>;
    /// How many wallets a list covers; `None` for a single value.
    fn len(&self) -> Option<usize> {
        None
    }
}

impl Column for u64 {
    fn at(&self, _: usize) -> Option<Amount> {
        Some(Amount::from_sat(*self))
    }
}

/// Integer literals default to `i32`, so `contract: 0` lands here.
impl Column for i32 {
    fn at(&self, _: usize) -> Option<Amount> {
        let sats = u64::try_from(*self).expect("a balance is never negative");
        Some(Amount::from_sat(sats))
    }
}

impl Column for Amount {
    fn at(&self, _: usize) -> Option<Amount> {
        Some(*self)
    }
}

impl<T: Column> Column for Option<T> {
    fn at(&self, index: usize) -> Option<Amount> {
        self.as_ref()?.at(index)
    }
    fn len(&self) -> Option<usize> {
        self.as_ref()?.len()
    }
}

impl<T: Column> Column for [T] {
    fn at(&self, index: usize) -> Option<Amount> {
        self[index].at(index)
    }
    fn len(&self) -> Option<usize> {
        Some(<[T]>::len(self))
    }
}

impl<T: Column, const N: usize> Column for [T; N] {
    fn at(&self, index: usize) -> Option<Amount> {
        self[..].at(index)
    }
    fn len(&self) -> Option<usize> {
        Some(N)
    }
}

impl<T: Column> Column for Vec<T> {
    fn at(&self, index: usize) -> Option<Amount> {
        self[..].at(index)
    }
    fn len(&self) -> Option<usize> {
        Some(<Vec<T>>::len(self))
    }
}

impl<T: Column + ?Sized> Column for &T {
    fn at(&self, index: usize) -> Option<Amount> {
        (**self).at(index)
    }
    fn len(&self) -> Option<usize> {
        (**self).len()
    }
}

/// `values` for wallet `index` of a row covering `wallets` wallets, or of a
/// one-wallet row when `wallets` is `None`. A list must have one value per
/// wallet of its row; `field` names it in the failure.
#[track_caller]
pub fn column<C: Column + ?Sized>(
    values: &C,
    index: usize,
    wallets: Option<usize>,
    field: &str,
) -> Option<Amount> {
    match (values.len(), wallets) {
        (Some(len), Some(wallets)) => assert_eq!(
            len, wallets,
            "`{}` lists {} values for {} wallets",
            field, len, wallets
        ),
        (Some(_), None) => panic!("`{}` lists values in a one-wallet row", field),
        (None, _) => {}
    }
    values.at(index)
}

/// What one wallet's balances must be. A field left unset is not asserted;
/// `loss` and `gain` compare `spendable` against the snapshot the assertion
/// runs `since`.
#[derive(Clone, Copy, Debug, Default)]
pub struct WalletExpect {
    regular: Option<Amount>,
    swap: Option<Amount>,
    contract: Option<Amount>,
    fidelity: Option<Amount>,
    spendable: Option<Amount>,
    /// Expected `spendable - before.spendable`, in sats: negative for a loss.
    change: Option<i64>,
}

impl WalletExpect {
    pub fn regular(mut self, value: Option<Amount>) -> Self {
        self.regular = value.or(self.regular);
        self
    }
    pub fn swap(mut self, value: Option<Amount>) -> Self {
        self.swap = value.or(self.swap);
        self
    }
    pub fn contract(mut self, value: Option<Amount>) -> Self {
        self.contract = value.or(self.contract);
        self
    }
    pub fn fidelity(mut self, value: Option<Amount>) -> Self {
        self.fidelity = value.or(self.fidelity);
        self
    }
    pub fn spendable(mut self, value: Option<Amount>) -> Self {
        self.spendable = value.or(self.spendable);
        self
    }
    /// The wallet's spendable balance fell by `value` since the snapshot.
    pub fn loss(mut self, value: Option<Amount>) -> Self {
        self.change = value.map(|v| -sats(v)).or(self.change);
        self
    }
    /// The wallet's spendable balance rose by `value` since the snapshot.
    pub fn gain(mut self, value: Option<Amount>) -> Self {
        self.change = value.map(sats).or(self.change);
        self
    }

    /// `self`, with every field `later` sets taking `later`'s value.
    fn merge(self, later: WalletExpect) -> Self {
        WalletExpect {
            regular: later.regular.or(self.regular),
            swap: later.swap.or(self.swap),
            contract: later.contract.or(self.contract),
            fidelity: later.fidelity.or(self.fidelity),
            spendable: later.spendable.or(self.spendable),
            change: later.change.or(self.change),
        }
    }

    /// One line per field that does not match, prefixed with `label`.
    #[track_caller]
    fn mismatches(&self, label: &str, actual: &Balances, before: Option<&Balances>) -> Vec<String> {
        let fields = [
            ("regular", self.regular, actual.regular),
            ("swap", self.swap, actual.swap),
            ("contract", self.contract, actual.contract),
            ("fidelity", self.fidelity, actual.fidelity),
            ("spendable", self.spendable, actual.spendable),
        ];
        let mut out: Vec<String> = fields
            .iter()
            .filter_map(|&(field, expected, got)| {
                let expected = expected?;
                (expected != got).then(|| {
                    format!(
                        "{label:<8} {field:<9}  expected {}, got {}",
                        expected.to_sat(),
                        got.to_sat()
                    )
                })
            })
            .collect();
        if let Some(expected) = self.change {
            let before = before
                .unwrap_or_else(|| panic!("{}: `loss` and `gain` need `since <snapshot>`", label));
            let got = sats(actual.spendable) - sats(before.spendable);
            if got != expected {
                let (field, expected, got) = if expected < 0 {
                    ("loss", -expected, -got)
                } else {
                    ("gain", expected, got)
                };
                out.push(format!(
                    "{label:<8} {field:<9}  expected {expected}, got {got} \
                     (spendable {} -> {})",
                    before.spendable.to_sat(),
                    actual.spendable.to_sat()
                ));
            }
        }
        out
    }
}

fn sats(amount: Amount) -> i64 {
    i64::try_from(amount.to_sat()).expect("a balance fits in i64 sats")
}

/// Every wallet's balances at one moment, for `assert_balances!(.., since ..)`.
pub struct WorldBalances {
    pub takers: Vec<Balances>,
    pub makers: Vec<Balances>,
}

/// The rows of one [`assert_balances!`], checked together: every mismatch of
/// every wallet is reported in one failure.
pub struct BalanceTable<'w> {
    world: &'w super::World,
    before: Option<&'w WorldBalances>,
    takers: Vec<WalletExpect>,
    makers: Vec<WalletExpect>,
}

impl<'w> BalanceTable<'w> {
    pub fn new(world: &'w super::World, before: Option<&'w WorldBalances>) -> Self {
        BalanceTable {
            world,
            before,
            takers: vec![WalletExpect::default(); world.takers().len()],
            makers: vec![WalletExpect::default(); world.makers().len()],
        }
    }

    pub fn taker_count(&self) -> usize {
        self.takers.len()
    }

    pub fn maker_count(&self) -> usize {
        self.makers.len()
    }

    /// Adds `expect` to taker `index`; a field set here replaces one an
    /// earlier row set.
    #[track_caller]
    pub fn taker(&mut self, index: usize, expect: WalletExpect) {
        let count = self.takers.len();
        let slot = self
            .takers
            .get_mut(index)
            .unwrap_or_else(|| panic!("taker {}: the world has {} takers", index, count));
        *slot = slot.merge(expect);
    }

    /// Adds `expect` to maker `index`; a field set here replaces one an
    /// earlier row set.
    #[track_caller]
    pub fn maker(&mut self, index: usize, expect: WalletExpect) {
        let count = self.makers.len();
        let slot = self
            .makers
            .get_mut(index)
            .unwrap_or_else(|| panic!("maker {}: the world has {} makers", index, count));
        *slot = slot.merge(expect);
    }

    /// Logs every wallet's balances, then fails with every mismatch at once.
    #[track_caller]
    pub fn assert(&self) {
        let mut mismatches = Vec::new();
        let takers = self.world.takers().iter().map(|taker| taker.balances());
        let makers = self.world.makers().iter().map(|maker| maker.balances());
        let wallets = takers
            .zip(&self.takers)
            .enumerate()
            .map(|(i, (actual, expect))| {
                let before = self.before.map(|b| &b.takers[i]);
                (format!("taker {i}"), actual, expect, before)
            })
            .chain(
                makers
                    .zip(&self.makers)
                    .enumerate()
                    .map(|(i, (actual, expect))| {
                        let before = self.before.map(|b| &b.makers[i]);
                        (format!("maker {i}"), actual, expect, before)
                    }),
            );
        for (label, actual, expect, before) in wallets {
            log::info!(
                "{label} balances: regular {}, swap {}, contract {}, fidelity {}, spendable {}",
                actual.regular,
                actual.swap,
                actual.contract,
                actual.fidelity,
                actual.spendable
            );
            mismatches.extend(expect.mismatches(&label, &actual, before));
        }
        assert!(
            mismatches.is_empty(),
            "balances do not match:\n  {}",
            mismatches.join("\n  ")
        );
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
    use openswap::wallet::Balances;

    use super::{column, WalletExpect};

    fn sats(n: u64) -> Option<Amount> {
        Some(Amount::from_sat(n))
    }

    fn wallet(regular: u64, swap: u64, spendable: u64) -> Balances {
        Balances {
            regular: Amount::from_sat(regular),
            swap: Amount::from_sat(swap),
            contract: Amount::ZERO,
            fidelity: Amount::ZERO,
            spendable: Amount::from_sat(spendable),
        }
    }

    #[test]
    fn every_wrong_field_is_reported_and_unset_ones_are_not() {
        let expect = WalletExpect::default()
            .regular(sats(100))
            .swap(sats(7))
            .contract(sats(0))
            .loss(sats(40));
        let before = wallet(0, 0, 1_000);
        let lines = expect.mismatches("taker 0", &wallet(100, 9, 950), Some(&before));
        assert_eq!(lines.len(), 2, "{:?}", lines);
        assert!(lines[0].contains("swap") && lines[0].contains("expected 7, got 9"));
        assert!(lines[1].contains("loss") && lines[1].contains("expected 40, got 50"));
        // fidelity and spendable were never set, so a mismatch there is no failure.
        assert!(expect
            .mismatches("taker 0", &wallet(100, 7, 960), Some(&before))
            .is_empty());
    }

    #[test]
    fn loss_and_gain_are_signed() {
        let before = wallet(0, 0, 1_000);
        let gained = wallet(0, 0, 1_010);
        // `loss: 0` used to pass a wallet that gained; now it does not.
        assert_eq!(
            WalletExpect::default()
                .loss(sats(0))
                .mismatches("maker 1", &gained, Some(&before))
                .len(),
            1
        );
        assert!(WalletExpect::default()
            .gain(sats(10))
            .mismatches("maker 1", &gained, Some(&before))
            .is_empty());
    }

    #[test]
    fn a_later_row_overrides_only_what_it_sets() {
        let group = WalletExpect::default().regular(sats(1)).swap(sats(2));
        let merged = group.merge(WalletExpect::default().swap(sats(3)).regular(None));
        let lines = merged.mismatches("maker 0", &wallet(1, 3, 0), None);
        assert!(lines.is_empty(), "{:?}", lines);
    }

    #[test]
    fn columns_give_one_value_per_wallet_or_skip() {
        assert_eq!(column(&5, 1, Some(3), "makers.swap"), sats(5));
        assert_eq!(column(&[4, 5, 6], 1, Some(3), "makers.swap"), sats(5));
        assert_eq!(column(&Some([4u64, 5]), 1, Some(2), "makers.swap"), sats(5));
        assert_eq!(column(&None::<u64>, 0, Some(2), "makers.swap"), None);
        assert_eq!(column(&[Some(1u64), None], 1, Some(2), "makers.swap"), None);
    }

    #[test]
    #[should_panic(expected = "`makers.swap` lists 2 values for 3 wallets")]
    fn a_list_must_cover_every_wallet() {
        column(&[1, 2], 0, Some(3), "makers.swap");
    }

    #[test]
    #[should_panic(expected = "need `since <snapshot>`")]
    fn loss_without_a_snapshot_is_refused() {
        WalletExpect::default()
            .loss(sats(1))
            .mismatches("taker 0", &wallet(0, 0, 0), None);
    }
}
