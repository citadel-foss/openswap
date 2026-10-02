//! Loopback port allocation for child processes and maker listeners.

use std::net::TcpListener;

/// Ask the OS for `n` unused ports, sorted as the taker will sort them: maker
/// addresses order as strings ('127.0.0.1:10000' < '127.0.0.1:9999'), and
/// that order decides route order and the golden balances.
///
/// Only for child processes (bitcoind, nostr relay), which cannot inherit a
/// socket: the port is released at return, so the caller must retry pick +
/// spawn as one operation. In-process consumers use [`reserve_listeners`].
pub(super) fn free_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)).expect("OS refused a free port"))
        .collect();
    let mut ports: Vec<u16> = listeners
        .iter()
        .map(|l| l.local_addr().unwrap().port())
        .collect();
    ports.sort_by_key(|port| format!("127.0.0.1:{port}"));
    ports
}

/// Bind `n` ports and keep the sockets, sorted like [`free_ports`]. Makers
/// take theirs at server start, closing the gap where another test's OS pick
/// could land on a released port.
pub(super) fn reserve_listeners(n: usize) -> Vec<TcpListener> {
    let mut listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind(("127.0.0.1", 0)).expect("OS refused a free port"))
        .collect();
    listeners.sort_by_key(|l| format!("127.0.0.1:{}", l.local_addr().unwrap().port()));
    listeners
}
