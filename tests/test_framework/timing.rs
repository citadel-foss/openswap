//! Background miner cadence and the timelock wait derived from it.

use std::time::Duration;

use super::backend::TestBackend;

/// Blocks mined per tick by the background block-generation thread.
pub(super) const BLOCKS_PER_TICK: u64 = 5;
/// Interval between block-generation ticks. Together with [`BLOCKS_PER_TICK`]
/// this yields ~1.67 blocks/s, slow enough that block-denominated timelocks
/// outlast the wall-clock recovery delays exercised by the abort tests.
pub(super) const BLOCK_TICK_INTERVAL: Duration = Duration::from_secs(3);

/// How long abort tests must sleep for makers to detect a drop and for the
/// outer-hop timelock (225 blocks) to mature, at backend `B`'s block cadence.
pub(crate) fn timelock_recovery_wait<B: TestBackend>() -> Duration {
    let (per_tick, tick) = B::block_cadence();
    // 30s maker idle timeout (IDLE_CONNECTION_TIMEOUT in integration builds) + the
    // 225-block outer-hop timelock (REFUND_LOCKTIME_BASE 150 + STEP 75, 2 makers) +
    // scheduling margin.
    Duration::from_secs(175) + tick * (225u64.div_ceil(per_tick)) as u32
}
