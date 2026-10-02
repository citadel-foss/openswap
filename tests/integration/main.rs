#![cfg(feature = "integration-test")]

#[macro_use]
mod test_framework;

mod cli;
mod fidelity;
#[cfg(feature = "lightning")]
mod lightning;
mod offerbook;
mod recovery;
mod rejection;
mod restart;
mod swap;
mod wallet;
