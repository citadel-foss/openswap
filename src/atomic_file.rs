//! Shared file-locking and atomic JSON-writing helpers.

use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::OpenOptions,
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const LOCK_POLL_INTERVAL: Duration = Duration::from_millis(10);

pub(crate) struct FileLock {
    path: PathBuf,
}

impl FileLock {
    pub(crate) fn acquire(lock_path: &Path) -> io::Result<Self> {
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut deadline = Instant::now() + LOCK_TIMEOUT;

        loop {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(lock_path)
            {
                Ok(_) => {
                    return Ok(Self {
                        path: lock_path.to_owned(),
                    })
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if Instant::now() > deadline {
                        let is_stale = std::fs::metadata(lock_path)
                            .and_then(|metadata| metadata.modified())
                            .map(|modified| modified.elapsed().unwrap_or_default() > LOCK_TIMEOUT)
                            .unwrap_or(true);

                        if is_stale {
                            std::fs::remove_file(lock_path)?;
                        } else {
                            deadline = Instant::now() + LOCK_TIMEOUT;
                        }
                    }

                    std::thread::sleep(LOCK_POLL_INTERVAL);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

pub(crate) fn read_json<T: DeserializeOwned + Default>(path: &Path) -> io::Result<T> {
    if !path.exists() {
        return Ok(T::default());
    }

    let content = std::fs::read_to_string(path)?;
    serde_json::from_str(&content).map_err(io::Error::other)
}

pub(crate) fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    let json = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
    let temporary_path = path.with_extension("partial");

    {
        use io::Write;

        let mut temporary_file = std::fs::File::create(&temporary_path)?;
        temporary_file.write_all(json.as_bytes())?;
        temporary_file.sync_all()?;
    }

    std::fs::rename(&temporary_path, path)
}
