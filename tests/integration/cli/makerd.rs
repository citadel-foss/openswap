//! `makerd` stops on SIGTERM (`docker stop`) and SIGINT (Ctrl-C) the way
//! `maker-cli stop` stops it: threads joined, wallet saved, exit status 0.

use std::{
    fs,
    io::Write,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    thread,
    time::{Duration, Instant},
};

use bitcoin::{Address, Amount};

use crate::test_framework::*;

use log::info;

/// Docker sends SIGKILL 10 s after SIGTERM; a clean stop must beat that.
const STOP_BOUND: Duration = Duration::from_secs(8);

/// A running `makerd`, killed if the test fails before it exits on its own.
struct Makerd {
    child: Child,
    data_dir: PathBuf,
}

impl Makerd {
    fn spawn(node: &Node, data_dir: &Path) -> Self {
        let _ = fs::remove_file(data_dir.join("debug.log"));
        let rpc_auth = fs::read_to_string(&node.bitcoind().params.cookie_file).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_makerd"))
            .args(["--data-directory", data_dir.to_str().unwrap()])
            .args([
                "--ADDRESS:PORT",
                &node.bitcoind().params.rpc_socket.to_string(),
            ])
            .args(["--USER:PASSWORD", &rpc_auth])
            .args(["--ZMQ", node.zmq_addr()])
            .args(["--WALLET", "signal-maker"])
            .args(["--PASSWORD", "integration-test"])
            .stdout(Stdio::null())
            .spawn()
            .expect("failed to start makerd");
        Makerd {
            child,
            data_dir: data_dir.to_path_buf(),
        }
    }

    fn log(&self) -> String {
        fs::read_to_string(self.data_dir.join("debug.log")).unwrap_or_default()
    }

    /// The first log line containing `needle`, once it appears.
    fn wait_for_line(&mut self, needle: &str, mut between_polls: impl FnMut()) -> String {
        wait_for!(
            Duration::from_secs(180),
            format!("makerd to log `{needle}`"),
            {
                let exited = self.child.try_wait().unwrap();
                assert!(exited.is_none(), "makerd exited early: {:?}", exited);
                between_polls();
                self.log()
                    .lines()
                    .find(|line| line.contains(needle))
                    .map(str::to_string)
            }
        )
    }

    /// Sends `signal` and returns how long the clean exit took.
    fn stop(mut self, signal: &str) -> Duration {
        let pid = self.child.id().to_string();
        let started = Instant::now();
        let sent = Command::new("kill")
            .args([&format!("-{signal}"), &pid])
            .status()
            .unwrap();
        assert!(sent.success(), "kill -{} {} failed", signal, pid);

        let what = format!("makerd to exit after SIG{signal}");
        let status = wait_for!(STOP_BOUND, what, self.child.try_wait().unwrap());
        let took = started.elapsed();
        info!("makerd exited {status} {took:?} after SIG{signal}");
        assert!(
            status.success(),
            "makerd exited {} on SIG{}",
            status,
            signal
        );

        let log = self.log();
        for line in ["phase=wallet_save outcome=ok", "Server shutdown complete"] {
            assert!(
                log.contains(line),
                "SIG{}: no `{}` in:\n{}",
                signal,
                line,
                log
            );
        }
        took
    }
}

impl Drop for Makerd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The word after `marker` in `line`, e.g. an address or socket.
fn token_after<'a>(line: &'a str, marker: &str) -> &'a str {
    let rest = line.split(marker).nth(1).expect("marker in line");
    rest.split_whitespace().next().unwrap()
}

#[world_test(backend = BitcoindBackend)]
fn makerd_stops_cleanly_on_sigterm_and_sigint(node: &mut Node) {
    let data_dir = node.temp_dir().join("makerd");
    // The default bond timelock is outside the range test builds accept.
    fs::create_dir_all(&data_dir).unwrap();
    fs::write(data_dir.join("config.toml"), "fidelity_timelock = 950\n").unwrap();

    // SIGINT while unfunded, parked in the bond funding wait.
    let mut makerd = Makerd::spawn(node, &data_dir);
    let ask = makerd.wait_for_line("Send at least", || {});
    let address = Address::from_str(token_after(&ask, " BTC to "))
        .unwrap()
        .assume_checked();
    let sigint = makerd.stop("INT");

    // Fully up on the saved wallet: bond confirmed, listening, RPC and Nostr
    // threads running, and an RPC client stalled mid-request.
    send_to_address(node.bitcoind(), &address, Amount::from_btc(0.1).unwrap());
    generate_blocks(node.bitcoind(), 1);
    let mut makerd = Makerd::spawn(node, &data_dir);
    // A block a second confirms the bond without racing the timelock.
    let mut mined_at = Instant::now();
    makerd.wait_for_line("Server setup complete", || {
        if mined_at.elapsed() >= Duration::from_secs(1) {
            generate_blocks(node.bitcoind(), 1);
            mined_at = Instant::now();
        }
    });
    let bound = makerd.wait_for_line("RPC socket binding successful", || {});
    makerd.wait_for_line("Spawning nostr background task", || {});
    // One byte of a 4-byte length prefix, then silence: the RPC thread
    // blocks in the frame read, which only closing the socket ends early.
    let mut stalled_client = TcpStream::connect(token_after(&bound, " at ")).unwrap();
    stalled_client.write_all(&[0]).unwrap();
    makerd.wait_for_line("Got RPC request from", || {});
    thread::sleep(Duration::from_secs(1));
    let sigterm = makerd.stop("TERM");

    info!("clean stops: SIGINT {sigint:?}, SIGTERM {sigterm:?}");
    assert!(data_dir.join("wallets").join("signal-maker").exists());
}
