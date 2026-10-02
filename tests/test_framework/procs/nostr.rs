//! The per-test nostr relay child process.

use std::{
    env,
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

/// Spawns a dedicated `nostr-rs-relay` process for a single test.
///
/// Each test gets its own relay on its own OS-assigned port with an in-memory
/// database, so concurrently running tests never share nostr state. The relay
/// binary is located via the `OPENSWAP_TEST_NOSTR_RELAY_BIN` env var, falling
/// back to `nostr-rs-relay` on `PATH`.
pub(in crate::test_framework) fn spawn_nostr_relay(temp_dir: &Path, port: u16) -> Child {
    let data_dir = temp_dir.join("nostr-relay");
    std::fs::create_dir_all(&data_dir).unwrap();

    // Minimal per-test relay config: bind the given port and use an in-memory
    // SQLite DB so nothing persists across or leaks between tests.
    let config_path = data_dir.join("config.toml");
    let config = format!(
        "[network]\naddress = \"127.0.0.1\"\nport = {port}\n\n[database]\ndata_directory = \"{data_dir}\"\nin_memory = true\nmin_conn = 4\nmax_conn = 8\n\n[diagnostics]\ntracing = false\n",
        data_dir = data_dir.display()
    );
    std::fs::write(&config_path, config).unwrap();

    let bin =
        env::var("OPENSWAP_TEST_NOSTR_RELAY_BIN").unwrap_or_else(|_| "nostr-rs-relay".to_string());

    Command::new(&bin)
        .arg("--config")
        .arg(&config_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|e| {
            panic!(
                "failed to spawn nostr relay binary '{}': {}. Install it with `cargo install nostr-rs-relay` or set OPENSWAP_TEST_NOSTR_RELAY_BIN.",
                bin, e
            )
        })
}

/// Healthy means the child is alive AND a real WebSocket handshake completes:
/// a bare TCP connect can answer from an unrelated listener holding the port
/// after our relay died mid-spawn.
pub(in crate::test_framework) fn wait_for_relay_healthy(port: u16, child: &mut Child) -> bool {
    let url = format!("ws://127.0.0.1:{port}");
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(Some(status)) = child.try_wait() {
            log::warn!("Nostr relay exited early ({status}) on port {port}");
            return false;
        }
        if tungstenite::connect(&url).is_ok() {
            log::info!("Nostr relay is alive on port {port}");
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    log::warn!("Nostr relay did not become healthy on port {port} within 10s");
    false
}
