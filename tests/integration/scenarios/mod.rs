//! Scenario bodies shared by tests in more than one file.
//!
//! Each `#[test]` stays in the file it always lived in, so its name is
//! unchanged, and calls a body here with its own data. A body is shared only
//! when the tests it serves ran the same steps and differed in data alone. A
//! test with extra checks runs the body's stages and puts its checks between
//! them.

pub(crate) mod maker_abort;
pub(crate) mod taker_abort;
