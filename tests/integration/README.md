# Integration tests

End-to-end tests of takers and makers swapping against a real regtest node.
Every test starts its own bitcoind, nostr relay and, on the Electrum backends,
electrs, so the suite is slow (several tests wait out timelocks) and runs one
test per process.

## Running

```bash
cargo nextest run --features integration-test                 # everything
cargo nextest run --features integration-test -E 'test(abort1::)'  # one file
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

`ELECTRS_LOG=1` prints electrs' stderr. The three Tor tests in
`electrum_tor.rs` are `#[ignore]`d; run them with `--run-ignored only`.

Each test keeps its data in `$TMPDIR/openswap-<random>/`: logs in
`taker/debug.log` (every taker and maker writes there), wallets, swap trackers.
It is deleted when the test passes and kept when it fails; the log's first
lines name the test. CI uploads the kept directories of a failed job.

## Layout

```text
test_framework/   the harness; nothing in here is a test
  procs/          bitcoind, electrs, nostr relay, tor
  world.rs        TestFramework::init: starts the processes, builds takers/makers
  harness.rs      World, WorldBuilder, MakerHandle, TakerHandle, the steps
  expect.rs       BalanceExpect: which balance fields a test asserts
  macros.rs       swap_matrix!, tor_gate!
  actors.rs, chain.rs, logs.rs, reports.rs, tracker.rs, timing.rs
scenarios/        bodies shared by tests in more than one file
*.rs              the tests, one file per scenario
```

## Writing a test

A test builds a `World`, drives it with steps, asserts, and finishes it:

```rust
#[test]
fn maker_abort3_case2() {
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

When several tests run the same steps and differ only in data, write the body
once in `scenarios/` and call it from each test, which stays in its own file so
its name does not change:

```rust
// abort3_case3.rs
#[test]
fn maker_abort3_case3() {
    warn!("Running Test: Maker Abort3 Case 3 - CloseAtHashPreimage");
    run_maker_abort_recovery(
        ProtocolVersion::Legacy,
        MakerBehavior::CloseAtHashPreimage,
        "Swap should fail due to Maker2 closing at hash preimage handover",
        &MakerAbortExpect { /* this test's balances */ },
    );
}
```

A test with extra checks can run a body's stages itself and put its checks
between them (`MakerAbort::fail_swap`, `recover`, `assert_recovered`; see
`taproot_timelock_recovery.rs`). Do not add flags to a body to cover a test
that runs different steps; give that test its own body.

To run one body over several backends or parameters in one file, use
`swap_matrix!` (see `electrum_tor.rs`). Each row becomes a `#[test]` with its
own name and attributes; `tor_gate!()` in a row skips it unless
`OPENSWAP_TOR_IT` is set.

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

Not every test fits the world. `electrum_transport.rs` (a TCP forwarder),
`wallet_backup.rs` (wallets only), `taker_cli.rs` (a subprocess) and the
`lightning_*.rs` tests (an LDK Server sidecar, behind the `lightning` feature)
keep their own harnesses; that is expected.
