# Integration tests

End-to-end tests of takers and makers swapping against a real regtest node.
Every test starts its own bitcoind, nostr relay and, on the Electrum backends,
electrs, so the suite is slow (several tests wait out timelocks) and runs one
test per process.

## Running

```bash
cargo nextest run --features integration-test                 # everything
cargo nextest run --features integration-test -E 'test(/^recovery::/)'  # one area
```

Use nextest, not `cargo test`: the logger is process-wide, so with every test
in one process all of them log into the first test's `debug.log` and the log
assertions fail. `.config/nextest.toml` holds the profiles; CI uses the `ci`
one (`NEXTEST_PROFILE=ci`).

What a run needs:

| dependency | how it is found |
| --- | --- |
| bitcoind 28.1 | downloaded once into `bin/`; `BITCOIND_TARBALL_FILE` points at a local tarball, `BITCOIND_DOWNLOAD_ENDPOINT` at a mirror |
| nostr-rs-relay | `nostr-rs-relay` on `PATH`, or `OPENSWAP_TEST_NOSTR_RELAY_BIN` |
| electrs 0.9.11 | the `electrsd` crate's bundled binary, or `ELECTRS_EXEC` |
| tor (Tor lane only) | a bootstrapped tor on control port 9051 / SOCKS 9050, `OPENSWAP_TOR_IT=1`, and `OPENSWAP_TOR_PASSWORD` if the control port needs one |

`ELECTRS_LOG=1` prints electrs' stderr. Logs go to the test's `debug.log` and
to stdout at debug level (`OPENSWAP_TEST_LOG=warn`, or `off`, lowers it), less
the lock WAIT/GOT traces, which `OPENSWAP_TEST_LOG_LOCKS=debug` brings back.
Each stdout line names its test, e.g. `[swap::electrum::taproot_swap_completes]`, so
interleaved CI output can be traced back.

The three Tor tests (`recovery::electrum::tor_taproot_taker_drops_after_funding`,
`recovery::electrum::tor_legacy_taker_drops_after_funding`,
`recovery::contract_breach::tor_maker_broadcasts_contract`) run their
scenario's body over `TorElectrumBackend` and assert the same balances as the
clearnet rows, so a Tor-specific divergence in a watchtower path fails loudly.
An onion service must upload its descriptor and the client fetch it back, so
they cannot work offline: they are `#[ignore]`d, and `skip_unless =
tor_it_enabled()` skips them unless `OPENSWAP_TOR_IT=1`. With the variable set
and Tor unreachable they panic, so a misconfigured Tor never passes silently:

```text
OPENSWAP_TOR_IT=1 cargo nextest run --features integration-test \
    --run-ignored only --test-threads=1 -E 'test(tor_)'
```

The onion services are created with `Flags=Detach` and outlive the test
process; CI's tor is ephemeral and drops them on restart.

Each test keeps its data in `$TMPDIR/openswap-<random>/`: logs in
`taker/debug.log` (every taker and maker writes there), wallets, swap trackers.
It is deleted when the test passes and kept when it fails; the log's first
lines name the test. CI uploads the kept directories of a failed job.

## Layout

```text
tests/
  integration/        the test binary: main.rs and one folder per area
    swap/             swaps that complete
    recovery/         a party drops or breaches; everyone recovers on-chain
    restart/          processes die and come back
    rejection/        everything either side must refuse, one file per theme
    fidelity/         fidelity bonds
    wallet/           the wallet and its backends
    offerbook/        the taker's offerbook
    cli/              the makerd RPC server and the taker CLI
    lightning/        Lightning swaps, behind the `lightning` feature
  test_framework/     the harness; nothing in here is a test. A module of the
                      integration binary, which main.rs pulls in with #[path]
    procs/            bitcoind, electrs, nostr relay, tor
    world.rs          TestFramework::init: starts the processes, builds takers/makers
    harness.rs        World, WorldBuilder, MakerHandle, TakerHandle, the steps
    node.rs           Node: a bare regtest bitcoind (+ electrs) for chain-only tests
    expect.rs         BalanceExpect: which balance fields a test asserts
    macros.rs         world_test, assert_logged!, wait_logged!
    actors.rs, chain.rs, logs.rs, reports.rs, tracker.rs, timing.rs
  macros/             the #[world_test] proc-macro crate (attribute macros need their own crate)
  TESTS.golden        every test name; check_test_names.sh diffs against it
```

## Writing a test

A test builds a `World`, drives it with steps, asserts, and finishes it:

```rust
#[test]
fn legacy_drop_at_contract_sigs_for_recvr() {
    warn!("Running Test: Maker Abort3 Case 2 - CloseAtContractSigsForRecvr");

    let mut world = World::builder::<BitcoindBackend>()
        .makers(2)
        .maker_behaviors([MakerBehavior::Normal, MakerBehavior::CloseAtContractSigsForRecvr])
        .takers([TakerBehavior::Normal])
        .build();

    let taker_original_balance = world.fund_taker_default(3); // 3 x 0.05 BTC
    world.fund_makers_default();                               // 4 x 0.05 BTC each
    world.start_makers(120);                                   // spawn, wait, sync
    world.mine(1);

    let params = SwapParams::new(ProtocolVersion::Legacy, Amount::from_sat(500000), 2)
        .with_tx_count(3)
        .with_required_confirms(1);
    let summary = world.taker_mut().prepare(params).expect("Prepare should succeed");
    assert!(world.taker_mut().start(&summary.swap_id).is_err());

    // ... wait, recover, sync ...

    BalanceExpect {
        regular: Some(Is::Sats(14499538)),
        swap: Some(Is::Sats(495997)),
        contract: Some(Is::Sats(0)),
        fidelity: Some(Is::Amount(Amount::ZERO)),
        spendable: None, // not asserted by this test
        delta: Some(Delta::Loss {
            baseline: taker_original_balance,
            style: DiffStyle::UnwrapOrZero,
            sats: 4465,
        }),
    }
    .assert("Taker", &world.taker().balances());

    world.finish();
}
```

When the test builds its own world, declare it with `#[world_test]` instead
and write only the scenario. It expands to the same builder chain, the setup
steps in the order listed, a call to the body and `world.finish()`:

```rust
/// A taker holding a single UTXO cannot fund 2 splits, ...
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [Normal],
    setup = [
        fund_taker_default(1) as baseline,
        fund_makers_default(),
        start_makers(120),
        mine(1),
    ],
)]
fn one_utxo_taker_completes_degraded_swap(world: &mut World, baseline: Amount) {
    // the scenario only
}
```

- The test keeps the body's name, so `TESTS.golden` does not change.
- `backend` is required. Every other key except `setup`, `swap` and `cases`
  calls the builder method of the same name (`check_blocklist`,
  `fee_overrides = ..`); `makers` is the length of a `maker_behaviors` list
  when omitted. Behaviors are written without the `MakerBehavior::` /
  `TakerBehavior::` prefix.
- `setup` steps are `World` methods; `step(..) as x` passes the result to the
  body parameter `x`. Do not end the body with `world.finish()`.
- `swap(protocol = Taproot, sats = 500_000, makers = 2, tx_count = 3)` builds
  the `SwapParams` passed to the body parameter `params`; unset `tx_count`
  and `confirms` keep the `SwapParams::new` defaults (2 and 1).
- The test logs `Running Test: <name> - <first doc line>` once the world is
  built, so the body needs no `warn!("Running Test: ..")`.
- The body stays a normal fn, so rustfmt and rust-analyzer still work on it.

Tests that share one body and differ in data list their rows in `cases`.
Each row is a `#[test]` with its own name and docs; its `name = value`
arguments are locals before the world is built, so keys can use them, and
the body takes the ones it needs by name:

```rust
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal],
    takers = [behavior],
    setup = [fund_taker_default(3), fund_makers_default(), start_makers(120), mine(1)],
    swap(protocol = Taproot, sats = 500_000, makers = 1, tx_count = 3),
    cases = [
        /// The taker declares 2 incoming contracts but funds 3. ...
        maker_rejects_wrong_taproot_incoming_count(
            behavior = TakerBehavior::ForgeIncomingCount(2),
            expected = "!= declared incoming count",
        ),
        // ... more rows
    ],
)]
fn run_taproot_declaration_guard(world: &mut World, expected: &str, params: SwapParams) {
    world.taker_mut().swap_fails(params, "maker must reject ...");
    assert_logged!(world, expected);
}
```

A row can also pick its backend: `backend = ElectrumBackend` is not a local
but the builder type for that row, and the shared `backend` key may be
dropped when every row gives one. A body that needs the type itself takes one
type parameter, which receives the row's backend:

```rust
#[world_test(
    maker_behaviors = [FailSecondBroadcast],
    ..
    cases = [
        maker_recovers_partial_broadcast_legacy(backend = BitcoindBackend, ..),
        maker_recovers_partial_broadcast_electrum(backend = ElectrumBackend, ..),
    ],
)]
fn run_maker_partial_broadcast<B: TestBackend>(world: &mut World, ..) {
    // .. timelock_recovery_wait::<B>() ..
}
```

Values the world needs before it exists go in `bind`: each `name = value` (or
`(a, b) = value`) is a local made before `build()`, usable in the other keys
and passed to the body by name. The Lightning tests bind their mock nodes this
way, because a maker takes its node at init:

```rust
#[world_test(
    backend = BitcoindBackend,
    bind = [(maker_ln, taker_ln) = maker_and_taker_nodes()],
    maker_behaviors = [Normal],
    takers = [Normal],
    maker_lightning = [maker_ln],
    taker_lightning = [taker_ln],
    setup = [..],
)]
fn lightning_submarine_swaps_e2e(world: &mut World) { .. }
```


The pieces:

- **`World::builder::<B>()`** picks the backend (`BitcoindBackend`,
  `ElectrumBackend`, `TorElectrumBackend`) and collects what `init` takes.
  Nothing is defaulted: no takers or makers unless named. `.fee_overrides(..)`
  and `.check_blocklist()` select the other init variants.
- **Steps** (`fund_taker_default`, `start_makers`, `mine`, `sync_makers`,
  `spawn_tracker_logger`, `assert_makers_contract_zero`, ...) each call the
  framework helper of the same name, so a step does exactly what the helper does.
  `world.framework()` reaches anything the world does not wrap.
- **Handles**: `world.taker()` / `world.makers()[i]` wrap one taker or maker
  (`sync`, `balances`, `prepare`, `start`, `await_recovery`); `.inner()` is
  the `Taker` or `MakerServer` underneath.
- **Teardown**: `world.finish()` drops the takers, shuts the makers down,
  stops the framework and joins the block generator, in that order. `Drop` runs
  the same teardown when a test panics, so a failure cleans up too.
- **Restarts**: `restart_maker(i, timeout)` stops one maker and brings it back
  from its own config; `shutdown_maker(i)` stops one while the rest keep
  running. For a whole restart, `drop_takers`, `shutdown_makers`, `drop_makers`,
  then `adopt_makers` / `adopt_taker` hand the re-initialised servers and takers
  back to the world, which tears them down like the originals. `take_taker`
  moves a taker out, e.g. into a swap thread.

## Balance expectations

`BalanceExpect` asserts each `Some` field and skips each `None`, in the order
regular, swap, contract, fidelity, spendable, then the delta. Converting a test
to it must not add or drop an assertion, so a field the test did not check stays
`None`. `DiffStyle` keeps how the test subtracted: `CheckedUnwrap` panics on a
negative difference, `UnwrapOrZero` reads it as zero.

The numbers are literals pinned from real runs. Never compute them from the fee
schedule at runtime: a test that derives its expectation from the code it tests
asserts nothing. When the fee schedule changes, re-pin the literals and say so
in the pull request.

A test whose assertions are not in `BalanceExpect`'s order (spendable checked
first, say) keeps plain `assert_eq!`s.

## Sharing a body

When several tests run the same steps and differ only in data, they are rows
of one `cases` block in one file (`recovery/maker_abort.rs`, `swap/spare_maker.rs`,
`recovery/taker_abort.rs`, `swap/multi_taker.rs`): the body once, then each test's name,
docs and data:

```rust
// recovery/maker_abort.rs
#[world_test(
    backend = BitcoindBackend,
    maker_behaviors = [Normal, behavior],
    takers = [Normal],
    cases = [
        /// Maker drops at hash preimage handover. Recovery via timelock.
        legacy_drop_at_hash_preimage(
            protocol = ProtocolVersion::Legacy,
            behavior = MakerBehavior::CloseAtHashPreimage,
            failure = "Swap should fail due to Maker2 closing at hash preimage handover",
            expected = &MakerAbortExpect { /* this test's balances */ },
        ),
        // ...
    ],
)]
fn run_maker_abort_recovery(world: &mut World, protocol: ProtocolVersion, ..) { .. }
```

A test with extra checks can run a body's stages itself and put its checks
between them (`MakerAbort::fail_swap`, `recover`, `assert_recovered`; see
`taproot_drop_at_contract_sigs_exchange` in `recovery/maker_abort.rs`). Do not add flags to a body to cover a test
that runs different steps; give that test its own body.

To run one body over several backends, give each row its own `backend = ..`
(see `recovery/electrum.rs`, whose Tor rows also carry `#[ignore]` and
`skip_unless = tor_it_enabled()`).

## Rules

- **Test names are pinned.** CI selects tests by name and nextest partitions
  them by name hash. `tests/TESTS.golden` lists every name; after adding,
  renaming or removing a test run `tests/check_test_names.sh --update` and
  commit the result.
- **Waits stay what they are.** A test that sleeps 300s keeps 300s;
  `timelock_recovery_wait::<B>()` is for tests that already scale with the
  backend.
- **Log needles are exact.** `assert_log` reads the log once; `wait_for_log`
  polls. Both echo the needle into the same log, so count a needle from one raw
  `fs::read_to_string` taken before any of them.
- **Log messages are ASCII.**

Tests that need a chain but no takers, makers or relay take a bare `Node`
instead: the body's first parameter picks the fixture, so `node: &mut Node`
builds a regtest bitcoind under its own temp dir, with electrs when the backend
is `ElectrumBackend`. Nothing mines in the background, and dropping the node
stops electrs, then bitcoind, then deletes the dir (a failing test's dir stays):

```rust
#[world_test(backend = ElectrumBackend, setup = [mine(101)])]
fn reconnects_after_the_connection_drops(node: &mut Node) {
    let forwarder = Forwarder::start(node.electrsd().electrum_url.clone());
    // ..
}
```

`wallet/electrum_transport.rs`, `wallet/backup.rs`, `cli/taker.rs`, the
`lightning/swap_*.rs` chain tests and `fidelity::spending::mempool_only_spend_reads_as_spent`
use it. Tests that touch no chain at all stay plain `#[test]`s.
