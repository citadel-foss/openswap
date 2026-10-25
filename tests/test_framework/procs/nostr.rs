//! The per-test nostr relay.
//!
//! Unix starts `nostr-rs-relay`. Windows starts an in-process NIP-01 relay
//! because that binary does not compile there.

#[cfg(not(windows))]
use std::{env, process::Child};
use std::{
    io,
    path::Path,
    thread,
    time::{Duration, Instant},
};
#[cfg(windows)]
use std::{
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc, Mutex,
    },
    thread::JoinHandle,
};

/// A relay the test framework can stop. Unix owns a child process. Windows
/// owns the embedded relay thread.
pub(in crate::test_framework) struct TestNostrRelay {
    inner: TestNostrRelayInner,
}

enum TestNostrRelayInner {
    #[cfg(not(windows))]
    Process(Child),
    #[cfg(windows)]
    Embedded(EmbeddedRelay),
}

#[cfg(windows)]
struct EmbeddedRelay {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl TestNostrRelay {
    /// `Ok(true)` means the relay has already exited.
    pub(in crate::test_framework) fn try_wait(&mut self) -> io::Result<bool> {
        match &mut self.inner {
            #[cfg(not(windows))]
            TestNostrRelayInner::Process(child) => Ok(child.try_wait()?.is_some()),
            #[cfg(windows)]
            TestNostrRelayInner::Embedded(embedded) => Ok(embedded
                .thread
                .as_ref()
                .is_some_and(|thread| thread.is_finished())),
        }
    }

    pub(in crate::test_framework) fn kill(&mut self) -> io::Result<()> {
        match &mut self.inner {
            #[cfg(not(windows))]
            TestNostrRelayInner::Process(child) => child.kill(),
            #[cfg(windows)]
            TestNostrRelayInner::Embedded(embedded) => {
                embedded.shutdown.store(true, Relaxed);
                Ok(())
            }
        }
    }

    pub(in crate::test_framework) fn wait(&mut self) -> io::Result<()> {
        match &mut self.inner {
            #[cfg(not(windows))]
            TestNostrRelayInner::Process(child) => {
                child.wait()?;
                Ok(())
            }
            #[cfg(windows)]
            TestNostrRelayInner::Embedded(embedded) => {
                if let Some(thread) = embedded.thread.take() {
                    let _ = thread.join();
                }
                let workers = std::mem::take(&mut *embedded.workers.lock().unwrap());
                for worker in workers {
                    let _ = worker.join();
                }
                Ok(())
            }
        }
    }
}

impl Drop for TestNostrRelay {
    fn drop(&mut self) {
        let _ = self.kill();
        let _ = self.wait();
    }
}

/// Spawns a dedicated relay for a single test.
///
/// Each test gets its own port, so concurrently running tests never share
/// nostr state.
pub(in crate::test_framework) fn spawn_nostr_relay(temp_dir: &Path, port: u16) -> TestNostrRelay {
    #[cfg(windows)]
    {
        let _ = temp_dir;
        spawn_embedded_nostr_relay(port)
    }
    #[cfg(not(windows))]
    {
        let data_dir = temp_dir.join("nostr-relay");
        std::fs::create_dir_all(&data_dir).unwrap();

        let config_path = data_dir.join("config.toml");
        let config = format!(
            "[network]\naddress = \"127.0.0.1\"\nport = {port}\n\n[database]\ndata_directory = \"{data_dir}\"\nin_memory = true\nmin_conn = 4\nmax_conn = 8\n\n[diagnostics]\ntracing = false\n",
            data_dir = data_dir.display()
        );
        std::fs::write(&config_path, config).unwrap();

        let bin = env::var("OPENSWAP_TEST_NOSTR_RELAY_BIN")
            .unwrap_or_else(|_| "nostr-rs-relay".to_string());

        let child = std::process::Command::new(&bin)
            .arg("--config")
            .arg(&config_path)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap_or_else(|e| {
                panic!(
                    "failed to spawn nostr relay binary '{bin}': {e}. Install it with `cargo install nostr-rs-relay` or set OPENSWAP_TEST_NOSTR_RELAY_BIN."
                )
            });
        TestNostrRelay {
            inner: TestNostrRelayInner::Process(child),
        }
    }
}

/// Healthy means the relay is alive AND a real WebSocket handshake completes.
pub(in crate::test_framework) fn wait_for_relay_healthy(
    port: u16,
    relay: &mut TestNostrRelay,
) -> bool {
    let url = format!("ws://127.0.0.1:{port}");
    let start = Instant::now();

    while start.elapsed() < Duration::from_secs(10) {
        match relay.try_wait() {
            Ok(true) => {
                log::warn!("Nostr relay exited early on port {port}");
                return false;
            }
            Err(error) => {
                log::warn!("Nostr relay status check failed on port {port}: {error}");
                return false;
            }
            Ok(false) => {}
        }
        if tungstenite::connect(&url).is_ok() {
            log::info!("Nostr relay is alive on port {port}");
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }

    log::warn!("Nostr relay did not become healthy on port {port} within 10s");
    false
}

#[cfg(windows)]
fn spawn_embedded_nostr_relay(port: u16) -> TestNostrRelay {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", port)).expect("bind embedded nostr relay");
    listener
        .set_nonblocking(true)
        .expect("embedded nostr relay accept should not block shutdown");
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thread = Arc::clone(&shutdown);
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_thread = Arc::clone(&workers);
    let thread =
        thread::spawn(move || embedded_nostr_relay_loop(listener, shutdown_thread, workers_thread));
    TestNostrRelay {
        inner: TestNostrRelayInner::Embedded(EmbeddedRelay {
            shutdown,
            thread: Some(thread),
            workers,
        }),
    }
}

#[cfg(windows)]
fn embedded_nostr_relay_loop(
    listener: std::net::TcpListener,
    shutdown: Arc<AtomicBool>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    use std::sync::{atomic::AtomicU64, mpsc};

    use nostr::{filter::MatchEventOptions, ClientMessage, Event, Filter, JsonUtil, RelayMessage};

    struct LiveSub {
        conn: u64,
        id: String,
        filters: Vec<Filter>,
        tx: mpsc::Sender<String>,
    }

    struct Hub {
        events: Vec<Event>,
        subs: Vec<LiveSub>,
    }

    let hub = Arc::new(Mutex::new(Hub {
        events: Vec::new(),
        subs: Vec::new(),
    }));
    let next_conn = Arc::new(AtomicU64::new(1));

    while !shutdown.load(Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let hub = Arc::clone(&hub);
                let conn = next_conn.fetch_add(1, Relaxed);
                let shutdown_conn = Arc::clone(&shutdown);
                let worker = thread::spawn(move || {
                    embedded_nostr_connection(stream, hub, conn, shutdown_conn)
                });
                workers.lock().unwrap().push(worker);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => {
                log::warn!("Embedded nostr relay stopped accepting: {error}");
                break;
            }
        }
    }

    fn filters_match(filters: &[Filter], event: &Event) -> bool {
        filters.is_empty()
            || filters
                .iter()
                .any(|filter| filter.match_event(event, MatchEventOptions::new()))
    }

    fn embedded_nostr_connection(
        stream: std::net::TcpStream,
        hub: Arc<Mutex<Hub>>,
        conn: u64,
        shutdown: Arc<AtomicBool>,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(100)));
        let mut socket = match tungstenite::accept(stream) {
            Ok(socket) => socket,
            Err(error) => {
                log::warn!("Embedded nostr handshake failed: {error}");
                return;
            }
        };
        let (tx, rx) = mpsc::channel::<String>();

        loop {
            if shutdown.load(Relaxed) {
                let _ = socket.close(None);
                break;
            }
            while let Ok(frame) = rx.try_recv() {
                if socket.send(tungstenite::Message::text(frame)).is_err() {
                    hub.lock().unwrap().subs.retain(|sub| sub.conn != conn);
                    return;
                }
            }

            let message = match socket.read() {
                Ok(message) => message,
                Err(tungstenite::Error::Io(error))
                    if error.kind() == io::ErrorKind::TimedOut
                        || error.kind() == io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(_) => break,
            };

            let tungstenite::Message::Text(text) = message else {
                if matches!(message, tungstenite::Message::Close(_)) {
                    break;
                }
                continue;
            };

            let Ok(client_message) = ClientMessage::from_json(&text) else {
                continue;
            };

            match client_message {
                ClientMessage::Event(event) => {
                    let event = event.into_owned();
                    let event_id = event.id;
                    let accepted = event.verify().is_ok();
                    if accepted {
                        let frame_targets: Vec<(mpsc::Sender<String>, String)> = {
                            let mut hub = hub.lock().unwrap();
                            let frames: Vec<_> = hub
                                .subs
                                .iter()
                                .filter(|sub| filters_match(&sub.filters, &event))
                                .map(|sub| {
                                    let frame = RelayMessage::Event {
                                        subscription_id: std::borrow::Cow::Owned(
                                            nostr::SubscriptionId::new(sub.id.clone()),
                                        ),
                                        event: std::borrow::Cow::Borrowed(&event),
                                    }
                                    .as_json();
                                    (sub.tx.clone(), frame)
                                })
                                .collect();
                            if !hub.events.iter().any(|stored| stored.id == event.id) {
                                hub.events.push(event);
                            }
                            frames
                        };
                        for (target, frame) in frame_targets {
                            let _ = target.send(frame);
                        }
                    }
                    let reply = RelayMessage::Ok {
                        event_id,
                        status: accepted,
                        message: std::borrow::Cow::Borrowed(if accepted {
                            ""
                        } else {
                            "invalid: bad signature"
                        }),
                    }
                    .as_json();
                    if socket.send(tungstenite::Message::text(reply)).is_err() {
                        break;
                    }
                }
                ClientMessage::Req {
                    subscription_id,
                    filters,
                } => {
                    let filters: Vec<Filter> = filters
                        .into_iter()
                        .map(|filter| filter.into_owned())
                        .collect();
                    let id = subscription_id.to_string();
                    let stored = {
                        let mut hub = hub.lock().unwrap();
                        hub.subs.retain(|sub| !(sub.conn == conn && sub.id == id));
                        let stored: Vec<Event> = hub
                            .events
                            .iter()
                            .filter(|event| filters_match(&filters, event))
                            .cloned()
                            .collect();
                        hub.subs.push(LiveSub {
                            conn,
                            id: id.clone(),
                            filters,
                            tx: tx.clone(),
                        });
                        stored
                    };
                    let mut failed = false;
                    for event in stored {
                        let frame = RelayMessage::Event {
                            subscription_id: std::borrow::Cow::Owned(nostr::SubscriptionId::new(
                                id.clone(),
                            )),
                            event: std::borrow::Cow::Owned(event),
                        }
                        .as_json();
                        if socket.send(tungstenite::Message::text(frame)).is_err() {
                            failed = true;
                            break;
                        }
                    }
                    if failed {
                        break;
                    }
                    let eose = RelayMessage::EndOfStoredEvents(std::borrow::Cow::Owned(
                        nostr::SubscriptionId::new(id),
                    ))
                    .as_json();
                    if socket.send(tungstenite::Message::text(eose)).is_err() {
                        break;
                    }
                }
                ClientMessage::Close(subscription_id) => {
                    let id = subscription_id.to_string();
                    hub.lock()
                        .unwrap()
                        .subs
                        .retain(|sub| !(sub.conn == conn && sub.id == id));
                }
                _ => {}
            }
        }

        hub.lock().unwrap().subs.retain(|sub| sub.conn != conn);
    }
}
