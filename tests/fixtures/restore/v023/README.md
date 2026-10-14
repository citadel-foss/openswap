# v0.2.3 restore fixtures

Made once by the released v0.2.3 library, to prove today's restore reads what
v0.2.3 wrote. Regtest only; the phrase and password protect nothing real.

- `fixtures.json`: the 12-word phrase, the backup password, the addresses
  v0.2.3 handed out (P2WPKH and P2TR, external and internal, indexes
  0/1/25/150) and the public keys of its fidelity bonds 0-2.
- `backup.json`: the encrypted backup v0.2.3 wrote for that wallet, born at
  height 0.
- `backup-release.json`: a backup from a second run, built like a release
  (600,000 password hashing rounds). Same password, wallet name `w1`. Only
  checked to open; its other files were not kept.
- `generate.rs`: the program that made them.

## Source

- Tag `v0.2.3`, commit `dfa1423b5b0b7e9a68d191d4488fdc3d64bb3b15`.
- Rust stable, Bitcoin Core regtest (`/usr/local/bin/bitcoind` v31.1.0).
- `backup.json` and `fixtures.json`: built with `--features integration-test`,
  which cuts the password hashing to 1 round, as the tests do. That backup
  opens only in such builds.
- `backup-release.json`: built without the feature. It opens only in a
  released build, so the taker binary's unit tests check it.

## Regenerate

The tag has no fixtures folder, so copy the program out first.

```bash
cp tests/fixtures/restore/v023/generate.rs /tmp/gen_fixtures.rs
git checkout v0.2.3
cp /tmp/gen_fixtures.rs examples/gen_fixtures.rs
mkdir out release-out
CARGO_TARGET_DIR=/tmp/target-v023 BITCOIND_EXE=/path/to/bitcoind \
  cargo run --features integration-test --example gen_fixtures -- out
CARGO_TARGET_DIR=/tmp/target-v023 BITCOIND_EXE=/path/to/bitcoind \
  cargo run --example gen_fixtures -- release-out
```

Back on the branch, copy `out/*.json` here and `release-out/backup.json` to
`backup-release.json`.

Every run picks a new random phrase, so `backup.json` and `fixtures.json`
come from the same run; do not mix them with files from another run.
