//! Shared file-locking and atomic JSON-writing helpers.

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
    write_atomically(path, json.as_bytes())
}

/// Replace `path` with `bytes` so a crash leaves either the old or the new file.
pub(crate) fn write_atomically(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let temporary_path = path.with_extension("partial");

    {
        // Private from the first byte, and never a stale temp that keeps its old mode.
        match std::fs::remove_file(&temporary_path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
            _ => {}
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut temporary_file = options.open(&temporary_path)?;
        // The rename would otherwise change the mode the user gave the file.
        if let Ok(existing) = std::fs::metadata(path) {
            temporary_file.set_permissions(existing.permissions())?;
        }
        temporary_file.write_all(bytes)?;
        temporary_file.sync_all()?;
    }

    std::fs::rename(&temporary_path, path)?;

    // Without a directory sync, a power loss can undo the rename after `Ok` returned.
    // A sync failure only leaves durability unconfirmed; the rename already happened.
    #[cfg(unix)]
    {
        let parent = path.parent().unwrap_or_else(|| Path::new(""));
        let directory = if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        };
        if let Err(error) = File::open(directory).and_then(|dir| dir.sync_all()) {
            log::warn!(
                "Could not sync {} after writing {}: {error}",
                directory.display(),
                path.display()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::seed_cli::WalletInUse;
    use std::{
        io::Read,
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    struct LockProcess(Child);

    impl Drop for LockProcess {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for_lock(file: &File) {
        // A parallel subprocess can inherit the owner's descriptor until exec.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match file.try_lock() {
                Ok(()) => return,
                Err(TryLockError::WouldBlock) => {
                    assert!(
                        Instant::now() < deadline,
                        "the wallet lock was not released"
                    );
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("could not acquire the wallet lock: {}", error),
            }
        }
    }

    #[test]
    fn compat_wallet_lock_survives_atomic_wallet_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet.cbor");
        let lock_path = dir.path().join("wallet.cbor.lock");
        let owner = WalletInUse::owner(&wallet).unwrap();
        let contender = OpenOptions::new().write(true).open(&lock_path).unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        write_atomically(&wallet, b"old wallet").unwrap();
        write_atomically(&wallet, b"new wallet").unwrap();
        assert_eq!(std::fs::read(&wallet).unwrap(), b"new wallet");
        assert!(matches!(
            contender.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        drop(owner);
        wait_for_lock(&contender);
        contender.unlock().unwrap();
        assert!(
            lock_path.exists(),
            "the sentinel inode must remain reusable"
        );
        drop(WalletInUse::owner(&wallet).unwrap());
    }

    #[test]
    fn compat_wallet_lock_is_exclusive_until_its_process_exits() {
        const CHILD_LOCK_ENV: &str = "OPENSWAP_COMPAT_WALLET_LOCK_CHILD";
        if let Some(path) = std::env::var_os(CHILD_LOCK_ENV) {
            let lock_path = Path::new(&path);
            let _owner = WalletInUse::owner(&lock_path.with_extension("")).unwrap();
            std::fs::write(lock_path.with_extension("ready"), b"locked").unwrap();
            let _ = std::io::stdin().read_exact(&mut [0]);
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let lock_path = dir.path().join("wallet.cbor.lock");
        let ready = lock_path.with_extension("ready");
        let mut holder = LockProcess(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "atomic_file::tests::compat_wallet_lock_is_exclusive_until_its_process_exits",
                    "--nocapture",
                ])
                .env(CHILD_LOCK_ENV, &lock_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while !ready.exists() {
            assert!(
                Instant::now() < deadline,
                "the subprocess did not acquire its lock"
            );
            assert!(
                holder.0.try_wait().unwrap().is_none(),
                "the subprocess exited before taking its lock"
            );
            thread::sleep(Duration::from_millis(5));
        }
        let contender = OpenOptions::new().write(true).open(&lock_path).unwrap();
        assert!(matches!(
            contender.try_lock(),
            Err(TryLockError::WouldBlock)
        ));
        holder.0.kill().unwrap();
        holder.0.wait().unwrap();
        wait_for_lock(&contender);
        contender.unlock().unwrap();
        assert!(lock_path.exists());
        drop(WalletInUse::owner(&lock_path.with_extension("")).unwrap());
    }
}
