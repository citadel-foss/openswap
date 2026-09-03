//! Amount-splitting helpers for per-hop coinswap transaction splitting.

use bip39::rand::{thread_rng, Rng};

/// Global ceiling on transaction splits per hop, bounding `outgoing_tx_count`.
pub const MAX_SPLITS: usize = 5;

/// Splits `total` into `num_chunks` organic-looking amounts with an exact sum, so chunk
/// sizes don't look like proportional copies of some upstream amount.
///
/// reference :- (ε, δ)-indistinguishable Mixing for Cryptocurrencies
/// <https://eprint.iacr.org/2021/1197.pdf>
///
/// Never errors: returns `vec![total]` (with a warning) if `num_chunks > MAX_SPLITS`,
/// so callers must reject oversized counts themselves.
pub(crate) fn vary_amounts(total: u64, num_chunks: usize) -> Vec<u64> {
    let mut rng = thread_rng();

    match num_chunks {
        0 => vec![],
        1 => vec![total],
        2..=MAX_SPLITS => {
            let ratios = match num_chunks {
                2 => vec![1.05, 0.95],
                3 => vec![1.0, 1.05, 0.95],
                4 => vec![1.1, 0.9, 1.05, 0.95],
                5 => vec![1.0, 1.1, 0.9, 1.05, 0.95],
                _ => unreachable!(), // This line is safe because of the match guard
            };

            // Apply randomness (±5% of each ratio)
            let randomized: Vec<f64> = ratios
                .iter()
                .map(|&r| r * rng.gen_range(0.95..1.05))
                .collect();

            // Normalize to maintain total
            let sum: f64 = randomized.iter().sum();
            let normalized: Vec<u64> = randomized
                .iter()
                .map(|&r| (total as f64 * r / sum).round() as u64)
                .collect();

            // Fix rounding errors
            let mut sum_check: i64 = normalized.iter().sum::<u64>() as i64;
            let mut adjusted = normalized.clone();

            while sum_check != total as i64 {
                let idx = rng.gen_range(0..adjusted.len());
                let delta = if sum_check < total as i64 { 1 } else { -1 };
                adjusted[idx] = (adjusted[idx] as i64 + delta) as u64;
                sum_check += delta;
            }

            // Random output ordering
            for i in 0..adjusted.len() {
                let swap_with = rng.gen_range(0..adjusted.len());
                adjusted.swap(i, swap_with);
            }

            adjusted
        }
        _ => {
            log::warn!(
                "vary_amounts: num_chunks={num_chunks} exceeds maximum of {MAX_SPLITS}, returning single chunk",
            );
            vec![total]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{vary_amounts, MAX_SPLITS};

    #[test]
    fn vary_amounts_preserves_total_for_all_valid_counts() {
        let total = 1_234_567u64;
        for n in 1..=MAX_SPLITS {
            let chunks = vary_amounts(total, n);
            assert_eq!(chunks.len(), n, "expected {n} chunks");
            assert_eq!(
                chunks.iter().sum::<u64>(),
                total,
                "chunks for n={n} must sum exactly to the total"
            );
            assert!(chunks.iter().all(|&c| c > 0), "no chunk should be zero");
        }
    }

    #[test]
    fn vary_amounts_edge_counts() {
        assert!(vary_amounts(100, 0).is_empty());
        assert_eq!(vary_amounts(100, 1), vec![100]);
    }

    #[test]
    fn vary_amounts_over_max_collapses_to_single_chunk() {
        // Above the ceiling the helper never errors; it returns a single chunk. Callers
        // are responsible for rejecting oversized counts before calling.
        let chunks = vary_amounts(500, MAX_SPLITS + 1);
        assert_eq!(chunks, vec![500]);
    }
}
