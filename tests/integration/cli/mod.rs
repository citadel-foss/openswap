//! The `makerd` RPC server and signal handling, and the `taker` CLI.

mod maker;
#[cfg(unix)]
mod makerd;
mod taker;
