//! Lightning swaps against mock Lightning nodes, behind the `lightning`
//! feature.

mod draining_maker;
mod e2e;
mod maker_restart;
mod offer_limits;
mod routed;
mod swap_in;
mod swap_out;

use bitcoin::{Amount, Txid};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};
use openswap::lightning::swap::SPEND_FEERATE_ENV;

/// Names the market feerate HTLC spends see, and clears it on drop so it
/// cannot leak into another test in this process.
pub(crate) struct SpendFeerate;

impl SpendFeerate {
    pub(crate) fn set(rate: f64) -> Self {
        let guard = SpendFeerate;
        guard.set_rate(rate);
        guard
    }

    pub(crate) fn set_rate(&self, rate: f64) {
        std::env::set_var(SPEND_FEERATE_ENV, rate.to_string());
    }
}

impl Drop for SpendFeerate {
    fn drop(&mut self) {
        std::env::remove_var(SPEND_FEERATE_ENV);
    }
}

/// The fee `txid` paid: its inputs' values less its outputs'.
pub(crate) fn tx_fee(bitcoind: &BitcoinD, txid: &Txid) -> Amount {
    let tx = bitcoind.client.get_raw_transaction(txid, None).unwrap();
    let spent: Amount = tx
        .input
        .iter()
        .map(|input| {
            let prev = bitcoind
                .client
                .get_raw_transaction(&input.previous_output.txid, None)
                .unwrap();
            prev.output[input.previous_output.vout as usize].value
        })
        .sum();
    spent - tx.output.iter().map(|output| output.value).sum::<Amount>()
}
