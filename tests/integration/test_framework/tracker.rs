//! Background logging of the taker's swap tracker state.

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering::Relaxed},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

/// Handle returned by [`spawn_tracker_logger`] to stop the background thread.
pub struct TrackerLoggerHandle {
    shutdown: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl TrackerLoggerHandle {
    /// Signal the background logger to stop and wait for it to finish.
    #[allow(dead_code)]
    pub fn stop(mut self) {
        self.shutdown.store(true, Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for TrackerLoggerHandle {
    fn drop(&mut self) {
        self.shutdown.store(true, Relaxed);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Spawn a background thread that periodically reads the swap tracker CBOR file
/// from `data_dir` and logs its contents at INFO level.
///
/// Usage in a test:
/// ```ignore
/// let logger = spawn_tracker_logger(temp_dir.join("taker1"), Duration::from_secs(5));
/// // ... run test ...
/// logger.stop();
/// ```
#[allow(dead_code)]
pub fn spawn_tracker_logger(data_dir: PathBuf, interval: Duration) -> TrackerLoggerHandle {
    use openswap::taker::swap_tracker::SwapTracker;

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    let handle = thread::spawn(move || {
        while !shutdown_clone.load(Relaxed) {
            thread::sleep(interval);
            if shutdown_clone.load(Relaxed) {
                break;
            }
            match SwapTracker::load_or_create(&data_dir) {
                Ok(tracker) => tracker.log_state(),
                Err(e) => log::warn!("[TrackerLogger] Failed to load tracker: {:?}", e),
            }
        }
    });

    TrackerLoggerHandle {
        shutdown,
        handle: Some(handle),
    }
}
