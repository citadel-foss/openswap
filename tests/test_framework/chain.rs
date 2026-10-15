//! Chain inspection helpers that read bitcoind over RPC.

use bitcoin::{Amount, Txid};
use std::{
    collections::HashMap,
    thread,
    time::{Duration, Instant},
};

use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::wallet::TakerReport;

/// Current chain tip height.
pub fn chain_tip(bitcoind: &BitcoinD) -> u64 {
    bitcoind.client.get_block_count().unwrap()
}

/// A regular swap's taker report: the wallet sent exactly `send_amount`, the
/// report adds up, and its fee is what the wallet actually lost. The last
/// check keeps the second honest: `fee_paid` derives from the same sums.
pub fn assert_taker_report_exact(report: &TakerReport, send_amount: Amount, wallet_cost: Amount) {
    assert_eq!(
        report.outgoing_amount,
        send_amount.to_sat(),
        "report must send exactly the send amount"
    );
    assert_eq!(
        report.outgoing_amount - report.incoming_amount,
        report.fee_paid,
        "report must add up: outgoing - incoming == fee_paid"
    );
    assert_eq!(
        report.fee_paid,
        wallet_cost.to_sat(),
        "report fee must equal the taker's balance change"
    );
}

/// The vsize the taker's own funding txs are priced at: one input, whatever
/// they really spend, paid out of the send amount.
pub const TAKER_FUNDING_VSIZE_MODEL: u64 = 165;

/// Checks a swap's funding txs at `sat_per_vb`: a maker's pays its real vsize,
/// the taker's pay [`TAKER_FUNDING_VSIZE_MODEL`] at or above their real vsize,
/// and exactly `taker_txs` of them are the taker's.
#[track_caller]
pub fn assert_taker_funding_pays_model(
    bitcoind: &BitcoinD,
    funding_txids: &[Txid],
    sat_per_vb: u64,
    taker_txs: usize,
) {
    let mut taker_funding = 0;
    for txid in funding_txids {
        let (fee, vsize) = tx_fee_and_vsize(bitcoind, txid);
        if fee == vsize as u64 * sat_per_vb {
            continue;
        }
        assert_eq!(
            fee,
            TAKER_FUNDING_VSIZE_MODEL * sat_per_vb,
            "funding tx {} must pay {} sat/vB or the {} vB model at that rate",
            txid,
            sat_per_vb,
            TAKER_FUNDING_VSIZE_MODEL
        );
        assert!(
            vsize as u64 <= TAKER_FUNDING_VSIZE_MODEL,
            "taker funding tx {} exceeds its {} vB model",
            txid,
            TAKER_FUNDING_VSIZE_MODEL
        );
        taker_funding += 1;
    }
    assert_eq!(
        taker_funding, taker_txs,
        "only the taker's {} funding txs pay the model",
        taker_txs
    );
}

/// Fee and vsize of a transaction the node knows, derived from the chain:
/// prevout values minus output values, never the wallet's own books.
pub fn tx_fee_and_vsize(bitcoind: &BitcoinD, txid: &Txid) -> (u64, usize) {
    let client = &bitcoind.client;
    let tx = client
        .get_raw_transaction(txid, None)
        .unwrap_or_else(|e| panic!("getrawtransaction {} failed: {}", txid, e));
    let mut input_sats = 0u64;
    for input in &tx.input {
        let prev_txid = input.previous_output.txid;
        let prev = client
            .get_raw_transaction(&prev_txid, None)
            .unwrap_or_else(|e| panic!("prevout tx {} missing: {}", prev_txid, e));
        input_sats += prev.output[input.previous_output.vout as usize]
            .value
            .to_sat();
    }
    let output_sats: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
    (input_sats - output_sats, tx.vsize())
}

/// Non-coinbase transactions mined at or above `from_height`, grouped by spend
/// depth: funding txs (depth 0) spend pre-swap wallet coins; contract txs,
/// sweeps and recovery txs each spend an in-window parent.
pub fn txs_by_spend_depth(bitcoind: &BitcoinD, from_height: u64) -> Vec<Vec<Txid>> {
    let client = &bitcoind.client;
    let tip = client.get_block_count().unwrap();
    let mut depth_of: HashMap<Txid, usize> = HashMap::new();
    let mut by_depth: Vec<Vec<Txid>> = Vec::new();
    // Blocks are topologically ordered, so a single pass resolves every parent.
    for height in from_height..=tip {
        let hash = client.get_block_hash(height).unwrap();
        for tx in client.get_block(&hash).unwrap().txdata {
            if tx.is_coinbase() {
                continue;
            }
            let txid = tx.compute_txid();
            let depth = tx
                .input
                .iter()
                .filter_map(|i| depth_of.get(&i.previous_output.txid))
                .max()
                .map(|d| d + 1)
                .unwrap_or(0);
            depth_of.insert(txid, depth);
            if by_depth.len() <= depth {
                by_depth.resize_with(depth + 1, Vec::new);
            }
            by_depth[depth].push(txid);
        }
    }
    by_depth
}

/// Poll [`txs_by_spend_depth`] until each depth reaches its expected count, so
/// the caller does not race a broadcast-but-unmined sweep.
pub fn wait_for_tx_depths(
    bitcoind: &BitcoinD,
    from_height: u64,
    expected: &[usize],
) -> Vec<Vec<Txid>> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let by_depth = txs_by_spend_depth(bitcoind, from_height);
        // Exact counts, not minimums: an extra transaction at an expected
        // depth is a real anomaly, so fail fast instead of passing over it.
        let counts: Vec<usize> = by_depth.iter().map(Vec::len).collect();
        assert!(
            !expected
                .iter()
                .enumerate()
                .any(|(d, &n)| by_depth.get(d).map_or(0, Vec::len) > n),
            "more transactions than expected: wanted {:?}, got {:?}",
            expected,
            counts
        );
        let settled = expected
            .iter()
            .enumerate()
            .all(|(d, &n)| by_depth.get(d).map_or(0, Vec::len) == n);
        if settled {
            // No trailing-depth rejection: a recovery cascade can still be
            // landing past the asserted depths, and that count is timing,
            // not correctness.
            return by_depth;
        }
        assert!(
            Instant::now() < deadline,
            "expected {:?} txs per depth, got {:?}",
            expected,
            by_depth.iter().map(Vec::len).collect::<Vec<_>>()
        );
        thread::sleep(Duration::from_millis(500));
    }
}
