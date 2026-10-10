//! Shared file-locking and atomic writing helpers.

use serde::{de::DeserializeOwned, Serialize};
use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{self, Write},
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
        std::fs::create_dir_all(parent_dir(lock_path))?;

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

/// Directory that should contain `path`.
///
/// A relative file name such as `wallet.cbor` has an empty parent. Creating
/// that empty path fails, so callers use `.` (the current directory) instead.
pub(crate) fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
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
    write_bytes_atomically(path, json.as_bytes())
}

/// Replace `path` with `bytes` so a crash cannot leave a truncated file.
///
/// The bytes are written to a uniquely named temporary file in the same
/// directory, flushed, then moved over `path`. A unique name avoids colliding
/// with another writer staging the same replacement. On Unix the containing
/// directory is synced after the rename. On Windows the move uses
/// `MOVEFILE_WRITE_THROUGH`, which does not return until the filesystem has
/// flushed the replacement. `std::fs::rename` can already replace an existing
/// file on Windows; that call alone does not wait for the metadata update to
/// reach disk.
pub(crate) fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = parent_dir(path);
    std::fs::create_dir_all(parent)?;

    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    // Close the handle before the replace. Windows rejects a move of a file
    // that this process still has open.
    let temporary = temporary.into_temp_path();
    replace_durable(&temporary, path)?;
    // Drop deletes the staging path. After a successful move that path is
    // gone, so the destination is left in place.

    #[cfg(unix)]
    sync_directory(parent)?;
    Ok(())
}

/// Move `from` onto `to`, replacing `to` when it already exists.
///
/// Unix uses `rename`, which is atomic on the same directory. Windows uses
/// `MoveFileExW` with replace and write-through flags so the call does not
/// return until the replacement is flushed.
fn replace_durable(from: &Path, to: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::rename(from, to)
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

        #[link(name = "kernel32")]
        extern "system" {
            fn MoveFileExW(existing_name: *const u16, new_name: *const u16, flags: u32) -> i32;
        }

        fn wide(path: &Path) -> Vec<u16> {
            path.as_os_str().encode_wide().chain(Some(0)).collect()
        }

        let from_wide = wide(from);
        let to_wide = wide(to);
        // SAFETY: both pointers address null-terminated buffers that live
        // until this call returns.
        let replaced = unsafe {
            MoveFileExW(
                from_wide.as_ptr(),
                to_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        std::fs::rename(from, to)
    }
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_parent_is_the_current_directory() {
        assert_eq!(parent_dir(Path::new("wallet.cbor")), Path::new("."));
        assert_eq!(
            parent_dir(&Path::new("dir").join("wallet.cbor")),
            Path::new("dir")
        );
    }

    #[test]
    fn write_bytes_atomically_replaces_existing_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data.bin");
        write_bytes_atomically(&path, b"one").unwrap();
        write_bytes_atomically(&path, b"two").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
    }
}
