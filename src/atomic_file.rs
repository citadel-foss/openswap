//! Shared file-locking and atomic JSON-writing helpers.

use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io,
    path::Path,
};

/// An exclusive lock on a file, held while this value is alive.
///
/// The lock belongs to the operating system, so it is released when this value
/// is dropped and also if the process dies while holding it.
pub(crate) struct FileLock {
    /// Holding the handle is the lock; closing it releases.
    _file: File,
}

impl FileLock {
    /// Block until the lock at `lock_path` is held.
    ///
    /// The sentinel file is created if absent and never removed: deleting it
    /// would let another process lock a fresh inode under the same path while
    /// this one still holds the old one.
    pub(crate) fn acquire(lock_path: &Path) -> io::Result<Self> {
        if let Some(parent) = lock_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(lock_path)?;

        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                log::info!("Waiting for lock on {}", lock_path.display());
                file.lock()?;
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }

        Ok(Self { _file: file })
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

    std::fs::rename(&temporary_path, path)?;

    // The rename is atomic for anyone reading the file, but it is only durable
    // once the directory entry itself reaches disk. Without this, a power loss
    // or kernel panic can leave the previous file in place and lose a write that
    // already returned `Ok`, which for the offerbook means losing the bans it
    // just recorded. Writing the contents with `sync_all` above does not cover
    // the entry that points at them.
    //
    // Unix only: Windows cannot open a directory as a file, and needs a handle
    // opened with backup semantics instead. Windows support is not in the tree
    // yet, so this is left for whoever adds it.
    #[cfg(unix)]
    {
        // `parent` is `Some("")` for a bare file name, which cannot be opened,
        // so fall back to the working directory the name is relative to.
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let directory = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        File::open(directory)?.sync_all()?;
    }

    Ok(())
}
