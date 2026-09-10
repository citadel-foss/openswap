//! Various mechanisms of creating the swap funding transactions.
//!
//! This module contains routines for creating funding transactions within a wallet. It leverages
//! Bitcoin Core's RPC methods for wallet interactions, including `walletcreatefundedpsbt`

use std::collections::HashSet;

use bitcoin::{Address, Amount, OutPoint, Transaction};
use bitcoind::bitcoincore_rpc::bitcoincore_rpc_json::ListUnspentResultEntry;

use crate::{
    utill::{fee_at_rate_sats, funding_fee_policy_sats, funding_tx_vsize},
    wallet::Destination,
};

use super::Wallet;

use super::{error::WalletError, AddressType};

#[derive(Debug)]
pub struct CreateFundingTxesResult {
    pub funding_txes: Vec<Transaction>,
    pub payment_output_positions: Vec<u32>,
    pub total_miner_fee: u64,
}

/// A split below this value pays more fee than it is worth.
const MIN_SPLIT_SATS: u64 = 5000;

/// One planned funding transaction: the UTXOs that fund it and the value it sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPlan {
    pub utxos: Vec<OutPoint>,
    pub value: Amount,
}

/// Plan how to split `total` into up to `max_splits` funding transactions from
/// one UTXO pool (regular or swept-swap, never mixed). Deterministic: the same
/// pool always yields the same plan.
///
/// Tries `max_splits` down to 1 and takes the first feasible count. Each split
/// sends an equal share; it is covered by the fewest UTXOs possible, ties
/// broken toward the smallest total value so later splits keep coins they can
/// combine. Splits stay
/// within `max_input_budget` inputs where the pool allows — only the 1-split
/// fallback may exceed it. Split values sum to `total`; the miner fee rides on
/// top of the inputs. Returns an empty Vec only when the pool cannot cover
/// the spend.
pub(crate) fn plan_funding_splits(
    pool_utxos: &[(OutPoint, Amount)],
    total: Amount,
    max_splits: u32,
    max_input_budget: u32,
    fee_rate: f64,
) -> Vec<SplitPlan> {
    let mut sorted = pool_utxos.to_vec();
    // Ties broken by outpoint so equal-value UTXOs plan identically every time.
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| b.0.cmp(&a.0)));

    for k in (1..=max_splits).rev() {
        if let Some(plan) = plan_with_k(&sorted, total.to_sat(), k, max_input_budget, fee_rate) {
            return plan;
        }
    }
    Vec::new()
}

fn plan_with_k(
    pool_desc: &[(OutPoint, Amount)],
    total: u64,
    k: u32,
    max_input_budget: u32,
    fee_rate: f64,
) -> Option<Vec<SplitPlan>> {
    if k == 0 || total < u64::from(k) * MIN_SPLIT_SATS {
        return None;
    }
    let mut remaining = pool_desc.to_vec();
    let mut plans = Vec::new();
    let mut assigned = 0u64;

    for i in 0..k {
        let splits_left = k - i;
        let target = (total - assigned) / u64::from(splits_left);

        // What the split's UTXOs must cover: value + the real fee, which the
        // wallet pays on top regardless of any reimbursement policy.
        let need = |inputs: usize| -> Option<u64> {
            fee_at_rate_sats(funding_tx_vsize(inputs), fee_rate)
                .and_then(|fee| target.checked_add(fee))
        };

        // Fewest inputs first, then the smallest covering total: grabbing a
        // bigger coin than needed can strand the exact coins a later split
        // must combine to reach its own target.
        let budget = (max_input_budget as usize).min(remaining.len());
        let mut picked =
            (1..=budget).find_map(|n| need(n).and_then(|need| smallest_cover(&remaining, n, need)));

        // Over-budget inputs are only acceptable for the 1-split fallback;
        // elsewhere a lower k gets a chance first.
        if picked.is_none() && k == 1 {
            let mut covered = 0u64;
            let mut positions = Vec::new();
            for (pos, (_, value)) in remaining.iter().enumerate() {
                if need(positions.len()).is_none_or(|need| covered >= need) {
                    break;
                }
                covered += value.to_sat();
                positions.push(pos);
            }
            if need(positions.len()).is_some_and(|need| covered >= need) {
                picked = Some(positions);
            }
        }

        // Remove highest index first so the lower positions stay valid.
        let mut positions = picked?;
        positions.sort_unstable();
        let mut utxos = Vec::with_capacity(positions.len());
        for pos in positions.into_iter().rev() {
            utxos.push(remaining.remove(pos).0);
        }

        if target < MIN_SPLIT_SATS {
            return None;
        }
        plans.push(SplitPlan {
            utxos,
            value: Amount::from_sat(target),
        });
        assigned += target;
    }
    Some(plans)
}

/// Indices into `pool_desc` of the `n` UTXOs with the smallest total value
/// that still covers `need`; `pool_desc` is sorted by value, descending.
/// Exact for 1-2 inputs (scan, then two-pointer), greedy above — exact
/// min-sum is exponential in pool size, and `n` stays capped by the input
/// budget, so the fill is cheap either way.
fn smallest_cover(pool_desc: &[(OutPoint, Amount)], n: usize, need: u64) -> Option<Vec<usize>> {
    let m = pool_desc.len();
    if m < n {
        return None;
    }
    if n == 1 {
        // Descending order: the last sufficient entry is the smallest.
        return pool_desc
            .iter()
            .rposition(|(_, value)| value.to_sat() >= need)
            .map(|pos| vec![pos]);
    }
    if n == 2 {
        // Two-pointer over ascending values (indices read back to front).
        let value = |i: usize| pool_desc[m - 1 - i].1.to_sat();
        let (mut lo, mut hi) = (0, m - 1);
        let mut best = None;
        while lo < hi {
            let sum = value(lo) + value(hi);
            if sum >= need {
                if best.is_none_or(|(b, _, _)| sum < b) {
                    best = Some((sum, lo, hi));
                }
                hi -= 1;
            } else {
                lo += 1;
            }
        }
        return best.map(|(_, lo, hi)| vec![m - 1 - lo, m - 1 - hi]);
    }
    // Greedy fill: the largest coin within the remaining deficit, else the
    // smallest coin above it.
    let mut chosen: Vec<usize> = Vec::with_capacity(n);
    let mut covered = 0u64;
    for _ in 0..n {
        let pick = (0..m)
            .filter(|i| !chosen.contains(i))
            .find(|i| pool_desc[*i].1.to_sat() <= need - covered)
            .or_else(|| {
                (0..m)
                    .filter(|i| !chosen.contains(i))
                    .rfind(|i| pool_desc[*i].1.to_sat() > need - covered)
            })?;
        covered += pool_desc[pick].1.to_sat();
        chosen.push(pick);
        if covered >= need {
            return Some(chosen);
        }
    }
    None
}

/// Rejects when the plan costs the maker more above the taker's input budget
/// than the hop earns. Extra inputs are real fees the taker never reimburses,
/// so a swap that costs more than it earns is a drain on the maker.
fn check_over_budget_spend(
    plan: &[SplitPlan],
    max_input_budget: u32,
    fee_rate: f64,
    swap_fee_sats: u64,
) -> Result<(), WalletError> {
    let real_fee = |inputs: usize| {
        fee_at_rate_sats(funding_tx_vsize(inputs), fee_rate)
            .ok_or_else(|| WalletError::General("funding fee arithmetic overflow".to_string()))
    };
    let mut over_budget = 0u64;
    for split in plan {
        let inputs = split.utxos.len();
        let priced = inputs.clamp(1, (max_input_budget as usize).max(1));
        let extra = real_fee(inputs)?
            .checked_sub(real_fee(priced)?)
            .ok_or_else(|| WalletError::General("funding fee arithmetic underflow".to_string()))?;
        over_budget = over_budget
            .checked_add(extra)
            .ok_or_else(|| WalletError::General("funding fee arithmetic overflow".to_string()))?;
    }
    if over_budget > swap_fee_sats {
        return Err(WalletError::General(format!(
            "funding plan spends {over_budget} sats above the taker's input budget, \
             exceeding the {swap_fee_sats} sats this hop earns"
        )));
    }
    Ok(())
}

/// Maker forwarding nets the taker-reimbursed fee out of each planned split's
/// value. Runs after planning because the fee depends on each split's final
/// input count. The taker's own hop skips this — its fee rides on top.
pub fn net_policy_fees(
    plan: &mut [SplitPlan],
    max_input_budget: u32,
    fee_rate: f64,
) -> Result<(), WalletError> {
    for split in plan.iter_mut() {
        let fee = funding_fee_policy_sats(split.utxos.len(), max_input_budget, fee_rate)
            .ok_or_else(|| WalletError::General("funding fee arithmetic overflow".to_string()))?;
        let value = split
            .value
            .to_sat()
            .checked_sub(fee)
            .filter(|value| *value >= MIN_SPLIT_SATS)
            .ok_or_else(|| {
                WalletError::General("funding fee pushes a split below the minimum".to_string())
            })?;
        split.value = Amount::from_sat(value);
    }
    Ok(())
}

/// Plans from the regular pool first, then the swept-swap pool; an empty plan
/// or a guard rejection falls through to the next pool. The sum against the
/// 1-input fee only orders the pools, so planning decides, not the sum.
#[allow(clippy::too_many_arguments)]
fn plan_from_pools(
    regular_pool: &[(OutPoint, Amount)],
    swap_pool: &[(OutPoint, Amount)],
    required: u64,
    total: Amount,
    max_splits: u32,
    max_input_budget: u32,
    fee_rate: f64,
    swap_fee_sats: Option<u64>,
) -> Result<Vec<SplitPlan>, WalletError> {
    let sum =
        |pool: &[(OutPoint, Amount)]| pool.iter().map(|(_, amount)| amount.to_sat()).sum::<u64>();
    let mut guard_error = None;
    for pool in [regular_pool, swap_pool] {
        if sum(pool) >= required {
            let plan = plan_funding_splits(pool, total, max_splits, max_input_budget, fee_rate);
            if plan.is_empty() {
                continue;
            }
            if let Some(swap_fee_sats) = swap_fee_sats {
                if let Err(e) =
                    check_over_budget_spend(&plan, max_input_budget, fee_rate, swap_fee_sats)
                {
                    guard_error = guard_error.or(Some(e));
                    continue;
                }
            }
            return Ok(plan);
        }
    }
    // A pool whose plan only failed the guard explains the refusal better
    // than a bare balance shortfall.
    if let Some(e) = guard_error {
        return Err(e);
    }
    Err(WalletError::InsufficientFund {
        available: sum(regular_pool) + sum(swap_pool),
        required,
    })
}

impl Wallet {
    /// Plans how to fund `total` across up to `max_splits` transactions from
    /// one UTXO pool — the regular pool, or the swept-swap pool when the
    /// regular pool cannot cover the spend; the two never mix. Manual
    /// selection caps the pool at the selected coins, so the split count
    /// degrades when they cannot support the request. Split values sum to
    /// `total`; the miner fee rides on top of the inputs (a maker nets its
    /// reimbursement afterwards via `net_policy_fees`).
    ///
    /// `swap_fee_sats` is `Some` only when a maker forwards a hop: it arms
    /// the over-budget guard, which rejects a plan whose unreimbursed input
    /// cost exceeds what the hop earns. The taker's own hop passes `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_funding(
        &self,
        total: Amount,
        max_splits: u32,
        fee_rate: f64,
        max_input_budget: u32,
        swap_fee_sats: Option<u64>,
        manually_selected_outpoints: Option<Vec<OutPoint>>,
        excluded_outpoints: Option<Vec<OutPoint>>,
    ) -> Result<Vec<SplitPlan>, WalletError> {
        let locked: HashSet<OutPoint> = self.list_lock_unspent().into_iter().collect();
        let excluded: HashSet<OutPoint> =
            excluded_outpoints.unwrap_or_default().into_iter().collect();
        let eligible = |entry: &ListUnspentResultEntry| {
            let outpoint = OutPoint::new(entry.txid, entry.vout);
            !locked.contains(&outpoint)
                && !excluded.contains(&outpoint)
                // A coin reserved by another in-flight swap is not plannable.
                && !self.is_swap_reserved(&outpoint)
        };
        // Coin selection never mixes pools: the regular pool funds the plan
        // unless it cannot cover the spend, then the swept-swap pool does.
        let regular_pool: Vec<(OutPoint, Amount)> = self
            .list_descriptor_utxo_spend_info()
            .into_iter()
            .filter(|(entry, _)| eligible(entry))
            .map(|(entry, _)| (OutPoint::new(entry.txid, entry.vout), entry.amount))
            .collect();
        let swap_pool: Vec<(OutPoint, Amount)> = self
            .list_swept_incoming_swap_utxos()
            .into_iter()
            .filter(|(entry, _)| eligible(entry))
            .map(|(entry, _)| (OutPoint::new(entry.txid, entry.vout), entry.amount))
            .collect();

        let cheapest_fee = fee_at_rate_sats(funding_tx_vsize(1), fee_rate)
            .ok_or_else(|| WalletError::General("funding fee arithmetic overflow".to_string()))?;
        let required = total.to_sat() + cheapest_fee;

        let manual = manually_selected_outpoints
            .filter(|outpoints| !outpoints.is_empty())
            .unwrap_or_default();
        let plan = if manual.is_empty() {
            plan_from_pools(
                &regular_pool,
                &swap_pool,
                required,
                total,
                max_splits,
                max_input_budget,
                fee_rate,
                swap_fee_sats,
            )?
        } else {
            let manual_set: HashSet<OutPoint> = manual.iter().copied().collect();
            let in_manual = |pool: &[(OutPoint, Amount)]| {
                pool.iter()
                    .filter(|(op, _)| manual_set.contains(op))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let in_regular = in_manual(&regular_pool);
            let in_swap = in_manual(&swap_pool);
            if in_regular.len() + in_swap.len() != manual_set.len() {
                return Err(WalletError::General(
                    "Some manually selected UTXOs are unavailable, locked, or excluded".to_string(),
                ));
            }
            if !in_regular.is_empty() && !in_swap.is_empty() {
                return Err(WalletError::General(
                    "Cannot mix regular and swap UTXOs in manual selection".to_string(),
                ));
            }
            let pool = if in_regular.is_empty() {
                in_swap
            } else {
                in_regular
            };
            let plan = plan_funding_splits(&pool, total, max_splits, max_input_budget, fee_rate);
            if plan.is_empty() {
                return Err(WalletError::InsufficientFund {
                    available: pool.iter().map(|(_, amount)| amount.to_sat()).sum(),
                    required,
                });
            }
            // Inputs past the taker's budget cost real fees the taker never
            // reimburses; manual selection has no fallback pool, so the guard
            // fails the swap here. The 68 vB model upper-bounds that cost.
            if let Some(swap_fee_sats) = swap_fee_sats {
                check_over_budget_spend(&plan, max_input_budget, fee_rate, swap_fee_sats)?;
            }
            plan
        };

        Ok(plan)
    }

    /// Spends exactly a frozen plan: one transaction per split, paired with
    /// the destinations in order. Every planned outpoint is re-checked
    /// against a fresh wallet listing before its transaction is built; a
    /// lost input fails the swap — the plan is never re-derived here.
    pub fn execute_funding_plan(
        &mut self,
        plan: &[SplitPlan],
        destinations: &[Address],
        fee_rate: f64,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        let result = self.execute_funding_plan_inner(plan, destinations, fee_rate);

        if let Err(e) = &result {
            log::error!("Failed to execute funding plan: {e:?}");
        }

        #[cfg(debug_assertions)]
        if let Ok(funding) = &result {
            log::debug!(
                "[FUNDING_STATE] Source: wallet::funding::execute_funding_plan | Wallet: {} | FundingTxs: {} | MinerFee: {}",
                self.get_name(),
                funding.funding_txes.len(),
                funding.total_miner_fee,
            );
        }

        result
    }

    fn execute_funding_plan_inner(
        &mut self,
        plan: &[SplitPlan],
        destinations: &[Address],
        fee_rate: f64,
    ) -> Result<CreateFundingTxesResult, WalletError> {
        if plan.is_empty() {
            return Err(WalletError::General(
                "cannot execute an empty funding plan".to_string(),
            ));
        }
        if destinations.len() < plan.len() {
            return Err(WalletError::General(format!(
                "funding plan has {} splits but only {} destinations",
                plan.len(),
                destinations.len()
            )));
        }
        let locked: HashSet<OutPoint> = self.list_lock_unspent().into_iter().collect();
        let mut available = self.list_descriptor_utxo_spend_info();
        available.extend(self.list_swept_incoming_swap_utxos());

        let mut funding_txes = Vec::<Transaction>::new();
        let mut payment_output_positions = Vec::<u32>::new();
        let mut total_miner_fee = 0;

        for (split, address) in plan.iter().zip(destinations.iter()) {
            let coins_to_spend: Vec<_> = split
                .utxos
                .iter()
                .map(|outpoint| {
                    if locked.contains(outpoint) {
                        return Err(WalletError::General(format!(
                            "planned funding input {outpoint} is locked"
                        )));
                    }
                    available
                        .iter()
                        .find(|(entry, _)| OutPoint::new(entry.txid, entry.vout) == *outpoint)
                        .cloned()
                        .ok_or_else(|| {
                            WalletError::General(format!(
                                "planned funding input {outpoint} is no longer in the wallet"
                            ))
                        })
                })
                .collect::<Result<Vec<_>, _>>()?;

            // Create destination with output - currently, destination is an array with a single address, i.e only a single transaction.
            let destination = Destination::Multi {
                outputs: vec![(address.clone(), split.value)],
                op_return_data: None,
                change_address_type: AddressType::P2TR,
            };

            // Creates and Signs Transactions via the spend_coins API
            let funding_tx = self.spend_coins(&coins_to_spend, destination, fee_rate)?;

            // Record this transaction in our results.
            let payment_pos = 0; // assuming the payment output position is 0

            // The exact fee is inputs minus outputs; the wallet built the
            // tx, so no vsize estimate is needed.
            let input_sum: u64 = coins_to_spend
                .iter()
                .map(|(entry, _)| entry.amount.to_sat())
                .sum();
            let output_sum: u64 = funding_tx.output.iter().map(|o| o.value.to_sat()).sum();
            total_miner_fee += input_sum.checked_sub(output_sum).ok_or_else(|| {
                WalletError::General("funding tx outputs exceed its inputs".to_string())
            })?;

            funding_txes.push(funding_tx);
            payment_output_positions.push(payment_pos);
        }

        Ok(CreateFundingTxesResult {
            funding_txes,
            payment_output_positions,
            total_miner_fee,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{hashes::Hash, Txid};

    fn utxo(index: u32, sats: u64) -> (OutPoint, Amount) {
        (
            OutPoint::new(Txid::from_byte_array([index as u8; 32]), index),
            Amount::from_sat(sats),
        )
    }

    fn pool(entries: &[(u32, u64)]) -> Vec<(OutPoint, Amount)> {
        entries.iter().map(|(i, s)| utxo(*i, *s)).collect()
    }

    #[test]
    fn full_split_count_when_pool_allows() {
        let plan = plan_funding_splits(
            &pool(&[(1, 100_000), (2, 100_000), (3, 100_000)]),
            Amount::from_sat(120_000),
            3,
            2,
            1.0,
        );
        assert_eq!(plan.len(), 3);
        assert!(plan.iter().all(|split| split.utxos.len() == 1));
        assert!(plan.iter().all(|split| split.value.to_sat() == 40_000));
    }

    #[test]
    fn degrades_to_one_split_when_splits_starve_each_other() {
        let plan = plan_funding_splits(
            &pool(&[(1, 60_000), (2, 50_000), (3, 40_000)]),
            Amount::from_sat(120_000),
            3,
            2,
            1.0,
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos.len(), 3);
        assert_eq!(plan[0].value.to_sat(), 120_000);
    }

    #[test]
    fn smallest_covering_combo_keeps_later_splits_feasible() {
        // 15k + 5k covers a 15k split (need 15_233) twice; largest-first
        // would burn both 15k coins on split one and degrade to a single
        // split.
        let plan = plan_funding_splits(
            &pool(&[(1, 15_000), (2, 15_000), (3, 5_000), (4, 5_000)]),
            Amount::from_sat(30_000),
            2,
            2,
            1.0,
        );
        assert_eq!(plan.len(), 2);
        for split in &plan {
            assert_eq!(split.value.to_sat(), 15_000);
            let mut vouts: Vec<u32> = split.utxos.iter().map(|op| op.vout).collect();
            vouts.sort_unstable();
            assert_eq!(vouts.len(), 2);
            assert!(vouts[0] <= 2 && vouts[1] >= 3);
        }
    }

    #[test]
    fn greedy_fill_packs_three_inputs_within_budget() {
        // No single (need 20_165) or pair (need 20_233) covers the split;
        // the fill takes 10k, then 9k, then the smallest coin above the
        // 1_301 sat deficit — 9k.
        let plan = plan_funding_splits(
            &pool(&[(1, 10_000), (2, 9_000), (3, 9_000), (4, 9_000)]),
            Amount::from_sat(20_000),
            1,
            3,
            1.0,
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos.len(), 3);
        assert_eq!(plan[0].value.to_sat(), 20_000);
    }

    #[test]
    fn stays_within_input_budget_when_possible() {
        // 6 dust UTXOs: every k > 1 needs 3+ inputs per split, over budget 2,
        // so the planner falls back to a single over-budget split.
        let plan = plan_funding_splits(
            &pool(&[
                (1, 10_000),
                (2, 10_000),
                (3, 10_000),
                (4, 10_000),
                (5, 10_000),
                (6, 10_000),
            ]),
            Amount::from_sat(50_000),
            2,
            2,
            1.0,
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos.len(), 6);
    }

    #[test]
    fn split_floor_forces_fewer_splits() {
        // 2 splits of 9000 sats would sit below the 5000 sat floor each.
        let plan = plan_funding_splits(&pool(&[(1, 20_000)]), Amount::from_sat(9_000), 2, 2, 1.0);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].value.to_sat(), 9_000);
    }

    #[test]
    fn empty_when_pool_cannot_cover_total_and_fee() {
        let plan = plan_funding_splits(&pool(&[(1, 10_000)]), Amount::from_sat(50_000), 3, 2, 1.0);
        assert!(plan.is_empty());
    }

    #[test]
    fn falls_through_to_swap_pool_when_regular_plan_misses() {
        // 6 x 8_800 clears the 1-input heuristic (52_800 >= 51_650) but the
        // 1-split plan needs 55_050; the swap pool's 60_000 coin covers it.
        let regular = pool(&[
            (1, 8_800),
            (2, 8_800),
            (3, 8_800),
            (4, 8_800),
            (5, 8_800),
            (6, 8_800),
        ]);
        let swap = pool(&[(7, 60_000)]);
        let required = 50_000 + fee_at_rate_sats(funding_tx_vsize(1), 10.0).unwrap();
        let plan = plan_from_pools(
            &regular,
            &swap,
            required,
            Amount::from_sat(50_000),
            2,
            2,
            10.0,
            None,
        )
        .unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos, vec![swap[0].0]);
        assert_eq!(plan[0].value.to_sat(), 50_000);
    }

    #[test]
    fn regular_pool_plans_first_when_it_covers() {
        let regular = pool(&[(1, 60_000)]);
        let swap = pool(&[(2, 60_000)]);
        let required = 50_000 + fee_at_rate_sats(funding_tx_vsize(1), 10.0).unwrap();
        let plan = plan_from_pools(
            &regular,
            &swap,
            required,
            Amount::from_sat(50_000),
            1,
            2,
            10.0,
            None,
        )
        .unwrap();
        assert_eq!(plan[0].utxos, vec![regular[0].0]);
    }

    #[test]
    fn insufficient_when_neither_pool_covers_the_plan() {
        // The regular pool misses the real plan and the swap pool fails the
        // heuristic; the error reports both pools' combined availability.
        let regular = pool(&[
            (1, 8_800),
            (2, 8_800),
            (3, 8_800),
            (4, 8_800),
            (5, 8_800),
            (6, 8_800),
        ]);
        let swap = pool(&[(7, 40_000)]);
        let required = 50_000 + fee_at_rate_sats(funding_tx_vsize(1), 10.0).unwrap();
        let result = plan_from_pools(
            &regular,
            &swap,
            required,
            Amount::from_sat(50_000),
            2,
            2,
            10.0,
            None,
        );
        assert!(matches!(
            result,
            Err(WalletError::InsufficientFund {
                available: 92_800,
                required: 51_650,
            })
        ));
    }

    #[test]
    fn guard_rejection_falls_through_to_the_swap_pool() {
        // Regular pool: only plan is one 6-input split costing 5 x 68 x 10 =
        // 3_400 sats over budget against a 501 sat hop. The swap pool's
        // single coin plans 1-input with zero over-budget spend.
        let regular = pool(&[
            (1, 10_000),
            (2, 10_000),
            (3, 10_000),
            (4, 10_000),
            (5, 10_000),
            (6, 10_000),
        ]);
        let swap = pool(&[(7, 60_000)]);
        let required = 50_000 + fee_at_rate_sats(funding_tx_vsize(1), 10.0).unwrap();
        let plan = plan_from_pools(
            &regular,
            &swap,
            required,
            Amount::from_sat(50_000),
            2,
            1,
            10.0,
            Some(501),
        )
        .unwrap();
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos, vec![swap[0].0]);
        assert_eq!(plan[0].value.to_sat(), 50_000);
    }

    #[test]
    fn guard_rejection_in_both_pools_keeps_the_loss_error() {
        // Both pools fragment into one 6-input split over the 501 sat hop;
        // the error must still say the swap costs more than it earns.
        let regular = pool(&[
            (1, 10_000),
            (2, 10_000),
            (3, 10_000),
            (4, 10_000),
            (5, 10_000),
            (6, 10_000),
        ]);
        let swap = pool(&[
            (7, 10_000),
            (8, 10_000),
            (9, 10_000),
            (10, 10_000),
            (11, 10_000),
            (12, 10_000),
        ]);
        let required = 50_000 + fee_at_rate_sats(funding_tx_vsize(1), 10.0).unwrap();
        let result = plan_from_pools(
            &regular,
            &swap,
            required,
            Amount::from_sat(50_000),
            2,
            1,
            10.0,
            Some(501),
        );
        assert!(matches!(
            result,
            Err(WalletError::General(message)) if message.contains("exceeding the 501 sats")
        ));
    }

    #[test]
    fn planner_is_deterministic() {
        let pool = pool(&[(1, 60_000), (2, 50_000), (3, 40_000), (4, 90_000)]);
        let first = plan_funding_splits(&pool, Amount::from_sat(100_000), 3, 2, 1.0);
        let second = plan_funding_splits(&pool, Amount::from_sat(100_000), 3, 2, 1.0);
        assert_eq!(first, second);
    }

    #[test]
    fn manual_selection_caps_the_pool() {
        // plan_funding passes only the selected coins as the pool; a request
        // they cannot cover comes back empty instead of funding later splits
        // from the rest of the wallet.
        let plan = plan_funding_splits(
            &pool(&[(1, 30_000), (2, 30_000)]),
            Amount::from_sat(120_000),
            2,
            2,
            1.0,
        );
        assert!(plan.is_empty());
    }

    #[test]
    fn manual_selection_degrades_the_split_count() {
        // One selected coin, two requested splits: split 1 has nothing left
        // to draw, so the plan degrades to a single split.
        let plan = plan_funding_splits(&pool(&[(1, 55_000)]), Amount::from_sat(50_000), 2, 2, 1.0);
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos.len(), 1);
        assert_eq!(plan[0].value.to_sat(), 50_000);
    }

    #[test]
    fn policy_fee_netting_prices_each_split_by_its_inputs() {
        // The planner nets nothing; the maker then deducts each split's
        // policy fee — 165 sats for a 1-input tx at 1 sat/vB.
        let mut plan = plan_funding_splits(
            &pool(&[(1, 100_000), (2, 100_000), (3, 100_000)]),
            Amount::from_sat(120_000),
            3,
            2,
            1.0,
        );
        assert!(plan.iter().all(|split| split.value.to_sat() == 40_000));
        net_policy_fees(&mut plan, 2, 1.0).unwrap();
        assert!(plan.iter().all(|split| split.value.to_sat() == 39_835));
        let forwarded: u64 = plan.iter().map(|split| split.value.to_sat()).sum();
        assert_eq!(forwarded, 120_000 - 3 * 165);
    }

    #[test]
    fn policy_fee_netting_ignores_inputs_above_budget_in_price() {
        // Dust pool forces one 6-input split at budget 2: the value loses
        // only the 2-input policy price; the maker eats the rest.
        let mut plan = plan_funding_splits(
            &pool(&[
                (1, 10_000),
                (2, 10_000),
                (3, 10_000),
                (4, 10_000),
                (5, 10_000),
                (6, 10_000),
            ]),
            Amount::from_sat(50_000),
            2,
            2,
            1.0,
        );
        assert_eq!(plan.len(), 1);
        net_policy_fees(&mut plan, 2, 1.0).unwrap();
        assert_eq!(plan[0].value.to_sat(), 50_000 - 233);
    }

    #[test]
    fn policy_fee_netting_rejects_a_split_pushed_below_the_floor() {
        // At 100 sat/vB the policy price of the 1-input split (16_500 sats)
        // exceeds its 5_000 sat value; netting must fail, not go negative.
        let mut plan =
            plan_funding_splits(&pool(&[(1, 20_000)]), Amount::from_sat(5_000), 1, 2, 1.0);
        assert_eq!(plan.len(), 1);
        assert!(net_policy_fees(&mut plan, 2, 100.0).is_err());
    }

    #[test]
    fn over_budget_guard_rejects_a_plan_that_costs_more_than_it_earns() {
        // Dust pool at 10 sat/vB, budget 1: the only feasible plan is one
        // 6-input split, so the maker pays 5 x 68 vB = 3400 sats itself.
        let plan = plan_funding_splits(
            &pool(&[
                (1, 10_000),
                (2, 10_000),
                (3, 10_000),
                (4, 10_000),
                (5, 10_000),
                (6, 10_000),
            ]),
            Amount::from_sat(50_000),
            2,
            1,
            10.0,
        );
        assert_eq!(plan.len(), 1);
        assert_eq!(plan[0].utxos.len(), 6);
        let over_budget = fee_at_rate_sats(funding_tx_vsize(6), 10.0).unwrap()
            - fee_at_rate_sats(funding_tx_vsize(1), 10.0).unwrap();
        assert_eq!(over_budget, 5 * 68 * 10);
        let result = check_over_budget_spend(&plan, 1, 10.0, 1_000);
        assert!(matches!(result, Err(WalletError::General(_))));
    }

    #[test]
    fn over_budget_guard_passes_when_the_hop_earns_more_than_it_costs() {
        // Same plan as above: a swap fee comfortably above the 3400 sat
        // over-budget spend passes the guard.
        let plan = plan_funding_splits(
            &pool(&[
                (1, 10_000),
                (2, 10_000),
                (3, 10_000),
                (4, 10_000),
                (5, 10_000),
                (6, 10_000),
            ]),
            Amount::from_sat(50_000),
            2,
            1,
            10.0,
        );
        assert!(check_over_budget_spend(&plan, 1, 10.0, 10_000).is_ok());
    }
}
