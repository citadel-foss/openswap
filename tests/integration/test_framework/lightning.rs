//! Throwaway regtest nodes and chain helpers for the Lightning tests.

use std::{env, fs, path::PathBuf, thread, time::Duration};

use bip39::rand;
use bitcoin::{Amount, Txid};
use bitcoind::{bitcoincore_rpc::RpcApi, BitcoinD};

use super::procs::bitcoind::{generate_blocks, init_bitcoind, send_to_address};

/// A throwaway regtest node that deletes its data directory when it drops.
///
/// Derefs to the [`BitcoinD`] so callers use it like the node itself.
pub(crate) struct LnRegtest {
    node: Option<BitcoinD>,
    dir: PathBuf,
}

impl std::ops::Deref for LnRegtest {
    type Target = BitcoinD;
    fn deref(&self) -> &BitcoinD {
        self.node.as_ref().expect("node lives until drop")
    }
}

impl Drop for LnRegtest {
    fn drop(&mut self) {
        // Stop the node first: its data directory cannot be removed from
        // under a running process.
        drop(self.node.take());
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// Spawns a throwaway regtest bitcoind under a unique temp directory, which
/// is removed when the returned guard drops.
///
/// `suite` groups a test file's data directories; `test_name` names the run.
pub(crate) fn setup_bitcoind(suite: &str, test_name: &str) -> LnRegtest {
    // The unique root, not the leaf, is what gets removed: deleting only the
    // leaf would leave an empty shell behind on every run.
    let root = env::temp_dir().join(format!("coinswap-{}", rand::random::<u64>()));
    let dir = root.join(suite).join(test_name);
    let port_zmq = 28332 + rand::random::<u16>() % 20000;
    let zmq_addr = format!("tcp://127.0.0.1:{port_zmq}");
    let node = init_bitcoind(&dir, zmq_addr).expect("bitcoind starts");
    LnRegtest {
        node: Some(node),
        dir: root,
    }
}

/// Fetches a transaction by txid, retrying briefly: the asynchronous txindex
/// can lag behind a freshly mined block under parallel test load.
pub(crate) fn raw_tx_with_retry(bitcoind: &BitcoinD, txid: &Txid) -> bitcoin::Transaction {
    for _ in 0..50 {
        if let Ok(tx) = bitcoind.client.get_raw_transaction(txid, None) {
            return tx;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("transaction {} not found after retries", txid);
}

/// Funds `spk` with `amount`, mines a block and returns the confirmed
/// funding txid, outpoint and output.
pub(crate) fn fund_script(
    bitcoind: &BitcoinD,
    spk: &bitcoin::ScriptBuf,
    amount: Amount,
) -> (Txid, bitcoin::OutPoint, bitcoin::TxOut) {
    let address = bitcoin::Address::from_script(spk, bitcoin::Network::Regtest).unwrap();
    let txid = send_to_address(bitcoind, &address, amount);
    generate_blocks(bitcoind, 1);
    let funding_tx = raw_tx_with_retry(bitcoind, &txid);
    let vout = funding_tx
        .output
        .iter()
        .position(|o| &o.script_pubkey == spk)
        .expect("funding output present");
    let outpoint = bitcoin::OutPoint {
        txid,
        vout: vout as u32,
    };
    (txid, outpoint, funding_tx.output[vout].clone())
}

/// Confirmation count for `txid`, retrying while the txindex catches up.
pub(crate) fn confirmations(bitcoind: &BitcoinD, txid: &Txid) -> u32 {
    for _ in 0..50 {
        if let Ok(info) = bitcoind.client.get_raw_transaction_info(txid, None) {
            return info.confirmations.unwrap_or(0);
        }
        thread::sleep(Duration::from_millis(100));
    }
    0
}

/// A fresh address from the node's own wallet, as a spend destination.
pub(crate) fn miner_spk(bitcoind: &BitcoinD) -> bitcoin::ScriptBuf {
    bitcoind
        .client
        .get_new_address(None, None)
        .unwrap()
        .assume_checked()
        .script_pubkey()
}
