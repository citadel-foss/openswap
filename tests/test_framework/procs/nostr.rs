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

    /// Live connection workers. Finished ones are joined by the accept loop,
    /// so this is zero again after a client disconnects.
    #[cfg(windows)]
    fn worker_count(&self) -> usize {
        match &self.inner {
            TestNostrRelayInner::Embedded(embedded) => embedded.workers.lock().unwrap().len(),
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
/// nostr state. A Windows bind failure is returned so the caller can retry
/// another port. A missing Unix relay binary still panics: that is not a race.
pub(in crate::test_framework) fn spawn_nostr_relay(
    temp_dir: &Path,
    port: u16,
) -> io::Result<TestNostrRelay> {
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
                    "failed to spawn nostr relay binary '{}': {}. Install it with `cargo install nostr-rs-relay` or set OPENSWAP_TEST_NOSTR_RELAY_BIN.",
                    bin, e
                )
            });
        Ok(TestNostrRelay {
            inner: TestNostrRelayInner::Process(child),
        })
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
fn spawn_embedded_nostr_relay(port: u16) -> io::Result<TestNostrRelay> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", port))?;
    listener.set_nonblocking(true)?;
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_thread = Arc::clone(&shutdown);
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_thread = Arc::clone(&workers);
    let thread =
        thread::spawn(move || embedded_nostr_relay_loop(listener, shutdown_thread, workers_thread));
    Ok(TestNostrRelay {
        inner: TestNostrRelayInner::Embedded(EmbeddedRelay {
            shutdown,
            thread: Some(thread),
            workers,
        }),
    })
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
        // A reconnecting test would otherwise keep every finished handle until
        // teardown. Join them here so the list stays the live connections.
        reap_finished_workers(&workers);
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

    fn reap_finished_workers(workers: &Mutex<Vec<JoinHandle<()>>>) {
        let finished = {
            let mut guard = workers.lock().unwrap();
            let mut still_running = Vec::with_capacity(guard.len());
            let mut finished = Vec::new();
            for worker in guard.drain(..) {
                if worker.is_finished() {
                    finished.push(worker);
                } else {
                    still_running.push(worker);
                }
            }
            *guard = still_running;
            finished
        };
        for worker in finished {
            let _ = worker.join();
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
        // The listener is nonblocking so accept can poll shutdown. Windows
        // inherited sockets stay that way, which makes the handshake fail with
        // Interrupted and the read loop spin on WouldBlock.
        if let Err(error) = stream.set_nonblocking(false) {
            log::warn!("Embedded nostr connection could not be made blocking: {error}");
            return;
        }
        // The handshake can arrive after the TCP accept on a loaded runner.
        // A read timeout does not bound writes: tungstenite flushes each
        // send, so a subscriber that stops reading would pin this worker and
        // block shutdown's join. The write bound also covers the handshake
        // reply.
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        if let Err(error) = stream.set_write_timeout(Some(Duration::from_secs(5))) {
            log::warn!("Embedded nostr connection could not bound writes: {error}");
            return;
        }
        let mut socket = match tungstenite::accept(stream) {
            Ok(socket) => socket,
            Err(error) => {
                log::warn!("Embedded nostr handshake failed: {error}");
                return;
            }
        };
        let _ = socket
            .get_ref()
            .set_read_timeout(Some(Duration::from_millis(100)));
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

/// A disconnect must not leave a finished worker until teardown, and the
/// relay must still accept the next connection.
#[cfg(windows)]
#[test]
fn embedded_relay_reaps_a_finished_connection() {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let mut relay = spawn_embedded_nostr_relay(port).unwrap();
    let url = format!("ws://127.0.0.1:{port}");

    let connect = || {
        let start = Instant::now();
        loop {
            if let Ok((socket, _)) = tungstenite::connect(&url) {
                return socket;
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "embedded relay did not accept a connection"
            );
            thread::sleep(Duration::from_millis(20));
        }
    };
    let wait_for_workers = |relay: &TestNostrRelay, expected: usize| {
        let start = Instant::now();
        while relay.worker_count() != expected {
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "worker count stayed at {}, expected {expected}",
                relay.worker_count()
            );
            thread::sleep(Duration::from_millis(20));
        }
    };

    assert_eq!(relay.worker_count(), 0);
    let mut socket = connect();
    wait_for_workers(&relay, 1);
    let _ = socket.close(None);
    drop(socket);
    wait_for_workers(&relay, 0);
    assert!(
        !relay.try_wait().unwrap(),
        "relay exited while reaping a finished connection"
    );

    let mut socket = connect();
    wait_for_workers(&relay, 1);
    let _ = socket.close(None);
    drop(socket);
    wait_for_workers(&relay, 0);
}

/// A bad signature must be refused and must not be stored or broadcast.
/// Removing `event.verify()` would otherwise leave this suite green.
#[cfg(windows)]
#[test]
fn embedded_relay_rejects_a_bad_signature() {
    use nostr::{
        event::{EventBuilder, Kind},
        key::Keys,
        ClientMessage, Event, Filter, JsonUtil, RelayMessage, SubscriptionId,
    };
    use tungstenite::{stream::MaybeTlsStream, Message, WebSocket};

    let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let relay = spawn_embedded_nostr_relay(port).unwrap();
    let url = format!("ws://127.0.0.1:{port}");

    let connect = || {
        let start = Instant::now();
        loop {
            if let Ok((socket, _)) = tungstenite::connect(&url) {
                return socket;
            }
            assert!(
                start.elapsed() < Duration::from_secs(2),
                "embedded relay did not accept a connection"
            );
            thread::sleep(Duration::from_millis(20));
        }
    };
    let set_read_timeout = |socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
                            timeout: Duration| {
        match socket.get_mut() {
            MaybeTlsStream::Plain(tcp) => tcp.set_read_timeout(Some(timeout)).unwrap(),
            _ => panic!("embedded relay is plaintext"),
        }
    };
    let read_relay =
        |socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>| match socket.read() {
            Ok(Message::Text(text)) => RelayMessage::from_json(text.as_str()).unwrap(),
            other => panic!("expected a relay text frame, got {:?}", other),
        };
    let send = |socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>,
                message: &ClientMessage| {
        socket.send(Message::text(message.as_json())).unwrap();
    };

    let keys = Keys::generate();
    let signed = |content: &str| {
        EventBuilder::new(Kind::Custom(1), content)
            .build(keys.public_key())
            .sign_with_keys(&keys)
            .unwrap()
    };
    let good = signed("good");
    let mut bad = signed("bad");
    bad.content = "tampered".to_string();
    assert!(good.verify().is_ok());
    assert!(bad.verify().is_err());

    let mut subscriber = connect();
    set_read_timeout(&mut subscriber, Duration::from_secs(2));
    send(
        &mut subscriber,
        &ClientMessage::req(SubscriptionId::new("live"), Filter::new()),
    );
    assert!(
        matches!(
            read_relay(&mut subscriber),
            RelayMessage::EndOfStoredEvents(_)
        ),
        "subscription was not registered"
    );

    let mut publisher = connect();
    set_read_timeout(&mut publisher, Duration::from_secs(2));
    let publish = |socket: &mut WebSocket<MaybeTlsStream<std::net::TcpStream>>, event: &Event| {
        send(socket, &ClientMessage::event(event.clone()));
        match read_relay(socket) {
            RelayMessage::Ok {
                event_id, status, ..
            } => {
                assert_eq!(event_id, event.id);
                status
            }
            other => panic!("expected OK, got {:?}", other),
        }
    };
    assert!(publish(&mut publisher, &good));
    match read_relay(&mut subscriber) {
        RelayMessage::Event { event, .. } => assert_eq!(event.id, good.id),
        other => panic!("subscriber missed the valid event: {:?}", other),
    }

    assert!(!publish(&mut publisher, &bad));
    set_read_timeout(&mut subscriber, Duration::from_millis(400));
    match subscriber.read() {
        Err(tungstenite::Error::Io(error))
            if error.kind() == io::ErrorKind::TimedOut
                || error.kind() == io::ErrorKind::WouldBlock => {}
        Ok(Message::Text(text)) => panic!("rejected event was broadcast: {}", text),
        other => panic!("unexpected frame after a rejected event: {:?}", other),
    }

    let mut later = connect();
    set_read_timeout(&mut later, Duration::from_secs(2));
    send(
        &mut later,
        &ClientMessage::req(SubscriptionId::new("later"), Filter::new()),
    );
    let mut stored = Vec::new();
    loop {
        match read_relay(&mut later) {
            RelayMessage::Event { event, .. } => stored.push(event.id),
            RelayMessage::EndOfStoredEvents(_) => break,
            other => panic!("expected stored events, got {:?}", other),
        }
    }
    assert_eq!(stored, vec![good.id]);
    drop(relay);
}
