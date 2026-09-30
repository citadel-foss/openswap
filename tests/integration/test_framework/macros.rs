//! Macros that generate test items around hand-written scenario bodies.
//!
//! They reach the whole suite through `#[macro_use] mod test_framework;` in
//! `main.rs`. Neither generates test logic: a scenario body is a plain
//! generic function, and a matrix row only names it.

/// Returns from the enclosing test unless the Tor integration tests are
/// enabled, i.e. `if !tor_it_enabled() { return; }`.
///
/// Unset `OPENSWAP_TOR_IT` skips; set with Tor unreachable panics inside
/// [`tor_it_enabled`](crate::test_framework::tor_it_enabled), so a
/// misconfigured Tor never passes silently.
macro_rules! tor_gate {
    () => {
        if !$crate::test_framework::tor_it_enabled() {
            return;
        }
    };
}

/// One `#[test]` per row, each calling a shared scenario body over the row's
/// backend.
///
/// ```ignore
/// swap_matrix! {
///     run_abort1 => {
///         taker_abort_1_taproot_electrum: <ElectrumBackend>(ProtocolVersion::Taproot, &TAPROOT_EXPECTED),
///         /// Doc comments and attributes pass through to the generated test.
///         #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
///         tor_abort1_taproot: {
///             tor_gate!();
///             warn!("Running Test: abort1 (Taproot) over Tor Electrum");
///         } <TorElectrumBackend>(ProtocolVersion::Taproot, &TAPROOT_EXPECTED),
///     }
/// }
/// ```
///
/// expands the second row to
///
/// ```ignore
/// #[test]
/// /// Doc comments and attributes pass through to the generated test.
/// #[ignore = "requires a bootstrapped tor and OPENSWAP_TOR_IT=1"]
/// fn tor_abort1_taproot() {
///     {
///         tor_gate!();
///         warn!("Running Test: abort1 (Taproot) over Tor Electrum");
///     }
///     run_abort1::<TorElectrumBackend>(ProtocolVersion::Taproot, &TAPROOT_EXPECTED);
/// }
/// ```
///
/// - The test name is the row's identifier, written out in full. It is never
///   assembled from parts, so `grep` and nextest filters find the row.
/// - A row may open with a `{ ... }` prologue, which runs before the body.
///   Tor rows gate there with [`tor_gate!`], so the gate is visible on the row.
/// - Several `body => { rows }` groups may share one invocation; each body is
///   a function in scope, called as `body::<Backend>(args)`.
macro_rules! swap_matrix {
    ($($body:ident => { $($rows:tt)* })*) => {
        $( swap_matrix!(@rows $body; $($rows)*); )*
    };
    (@rows $body:ident;
        $(
            $(#[$attr:meta])*
            $name:ident : $($prologue:block)? <$backend:ty>($($arg:expr),* $(,)?)
        ),* $(,)?
    ) => {
        $(
            #[test]
            $(#[$attr])*
            fn $name() {
                $($prologue)?
                $body::<$backend>($($arg),*);
            }
        )*
    };
}
