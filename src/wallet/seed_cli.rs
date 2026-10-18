//! The offline `show-seed` and `attach-seed` commands of `taker` and `makerd`.
//! They need an existing wallet file and no backend, take every secret at a
//! hidden prompt (never argv), and are never reachable over RPC or the network.

use std::{
    fs::{File, OpenOptions, TryLockError},
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

use bip39::rand::random;
use zeroize::Zeroizing;

use super::{api::Wallet, error::WalletError};
use crate::utill::prompt_password;

/// Held by every online `Wallet` for its lifetime: exclusive for a running
/// maker or taker, shared for library callers. Seed commands write only under
/// an exclusive lock on a fresh read, so they cannot overwrite live state.
pub struct WalletInUse {
    _file: File,
}

/// The sentinel next to the wallet file: `<wallet>.lock`.
fn in_use_path(wallet_path: &Path) -> PathBuf {
    let mut name = wallet_path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

fn open_sentinel(wallet_path: &Path) -> io::Result<File> {
    let path = in_use_path(wallet_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)
}

/// Fails closed: opening the wallet without the lock would let a seed command
/// overwrite it.
fn lock_failed(wallet_path: &Path, e: io::Error) -> WalletError {
    WalletError::General(format!(
        "could not lock {:?}: {e}; every open wallet holds this lock so that \
         show-seed and attach-seed never overwrite it, so the wallets directory \
         must be writable and support file locks",
        in_use_path(wallet_path)
    ))
}

impl WalletInUse {
    /// Marks a library wallet as in use until dropped. Waits while a daemon
    /// owns the wallet or a seed command is writing.
    pub(crate) fn shared(wallet_path: &Path) -> Result<Self, WalletError> {
        let failed = |e| lock_failed(wallet_path, e);
        let file = open_sentinel(wallet_path).map_err(failed)?;
        file.lock_shared().map_err(failed)?;
        Ok(Self { _file: file })
    }

    /// Single running owner per wallet. The returned guard must be passed
    /// into wallet loading, never followed by a shared lock on another fd:
    /// file locks on separate open file descriptions conflict even in-process.
    pub(crate) fn owner(wallet_path: &Path) -> Result<Self, WalletError> {
        let failed = |e| lock_failed(wallet_path, e);
        let file = open_sentinel(wallet_path).map_err(failed)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                log::info!("Waiting for lock on {}", in_use_path(wallet_path).display());
                file.lock().map_err(failed)?;
            }
            Err(TryLockError::Error(e)) => return Err(failed(e)),
        }
        Ok(Self { _file: file })
    }

    /// Integration restart tests construct the replacement daemon before
    /// dropping the old one (e.g. World::restart_maker). Keep their shared
    /// guard so seed commands still cannot write during those restarts.
    pub(crate) fn for_daemon(wallet_path: &Path) -> Result<Self, WalletError> {
        if cfg!(feature = "integration-test") {
            Self::shared(wallet_path)
        } else {
            Self::owner(wallet_path)
        }
    }

    /// Takes the wallet for writing, or `None` if any process runs on it.
    pub(crate) fn exclusive_if_idle(wallet_path: &Path) -> Result<Option<Self>, WalletError> {
        let failed = |e| lock_failed(wallet_path, e);
        let file = open_sentinel(wallet_path).map_err(failed)?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(e)) => Err(failed(e)),
        }
    }
}

pub(super) const IN_USE_MESSAGE: &str = "this wallet is in use by a running process, which would \
     overwrite the change; stop it and run the command again";

/// Writes `text` straight to `out`. `println!` would leave seed words in
/// stdout's shared buffer, which nothing wipes.
fn write_now(out: &mut impl Write, text: &[u8]) -> Result<(), WalletError> {
    out.write_all(text)
        .and_then(|()| out.flush())
        .map_err(|e| WalletError::General(format!("writing to the terminal failed: {e}")))
}

/// Words the user must re-type before the backup counts as confirmed.
const QUIZ_WORDS: usize = 3;

fn prompt(message: &str) -> Result<Zeroizing<String>, WalletError> {
    prompt_password(message.to_string()).map_err(|e| WalletError::prompt_failed("prompt failed", e))
}

/// Picks `count` distinct word positions below `total`, in ascending order.
fn quiz_positions(total: usize, count: usize, mut next: impl FnMut() -> u32) -> Vec<usize> {
    let mut picked = Vec::with_capacity(count);
    while picked.len() < count.min(total) {
        let position = next() as usize % total;
        if !picked.contains(&position) {
            picked.push(position);
        }
    }
    picked.sort_unstable();
    picked
}

/// Whether `answer` is the word at `position`, ignoring case and spaces at the ends.
fn answer_matches(words: &str, position: usize, answer: &str) -> bool {
    words
        .split(' ')
        .nth(position)
        .is_some_and(|word| word.eq_ignore_ascii_case(answer.trim()))
}

/// Shows the wallet's seed phrase on the terminal. While the wallet isn't
/// marked as backed up, asks for a few random words back and only then
/// records the backup. Writes nothing otherwise.
pub fn show_seed(wallet_path: &Path) -> Result<(), WalletError> {
    if !std::io::stdout().is_terminal() {
        return Err(WalletError::General(
            "show-seed prints the seed phrase and only runs with stdout on a terminal; \
             in Docker use `docker exec -it`"
                .to_string(),
        ));
    }
    if !wallet_path.exists() {
        return Err(WalletError::General(format!(
            "no wallet file at {wallet_path:?}"
        )));
    }
    let password = prompt("Enter wallet passphrase: ")?;
    let wallet = Wallet::open_offline(wallet_path, password.clone())?;
    let words = wallet.get_wallet_mnemonic(password.clone())?.words();
    {
        let mut out = io::stdout().lock();
        write_now(
            &mut out,
            b"\nWrite these words down, in order, on paper:\n\n",
        )?;
        let mut line = Zeroizing::new(String::with_capacity(words.len() + 16));
        for (i, word) in words.split(' ').enumerate() {
            line.clear();
            line.push_str(&format!("{:>3}. ", i + 1));
            line.push_str(word);
            line.push('\n');
            write_now(&mut out, line.as_bytes())?;
        }
    }
    if wallet.seed_backed_up() {
        println!("\nThis seed was already confirmed as backed up.");
        return Ok(());
    }
    println!("\nNow confirm the backup by typing the words asked for.");
    let total = words.split(' ').count();
    for position in quiz_positions(total, QUIZ_WORDS, random::<u32>) {
        let answer = prompt(&format!("Word #{}: ", position + 1))?;
        if !answer_matches(&words, position, &answer) {
            return Err(WalletError::General(
                "wrong word; backup not confirmed, run show-seed again".to_string(),
            ));
        }
    }
    drop(words);
    drop(wallet);
    // Only now, and on a fresh read, so nothing newer is overwritten.
    let Some(_owner) = WalletInUse::exclusive_if_idle(wallet_path)? else {
        println!("\nBackup not recorded: {IN_USE_MESSAGE}.");
        return Ok(());
    };
    let mut wallet = Wallet::open_offline(wallet_path, password.clone())?;
    wallet.confirm_seed_backup(password)?;
    println!("\nSeed backup confirmed.");
    Ok(())
}

/// Stores the user's original seed phrase in a wallet that has none.
pub fn attach_seed(wallet_path: &Path) -> Result<(), WalletError> {
    if !wallet_path.exists() {
        return Err(WalletError::General(format!(
            "no wallet file at {wallet_path:?}"
        )));
    }
    let password = prompt("Enter wallet passphrase: ")?;
    Wallet::open_offline(wallet_path, password.clone())?;
    let phrase = prompt("Enter the original seed phrase: ")?;
    let Some(_owner) = WalletInUse::exclusive_if_idle(wallet_path)? else {
        return Err(WalletError::General(IN_USE_MESSAGE.to_string()));
    };
    let mut wallet = Wallet::open_offline(wallet_path, password.clone())?;
    wallet.attach_wallet_mnemonic(password, phrase)?;
    println!("\nSeed phrase attached. Run show-seed to confirm your backup of it.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_commands_write_only_when_no_process_runs_on_the_wallet() {
        let dir = bitcoind::tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet");
        let running = WalletInUse::shared(&wallet).unwrap();
        // Multiple library readers may share the wallet.
        let second = WalletInUse::shared(&wallet).unwrap();
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_none());
        drop(running);
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_none());
        drop(second);
        let writer = WalletInUse::exclusive_if_idle(&wallet).unwrap();
        assert!(writer.is_some());
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_none());
        drop(writer);
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_some());
    }

    #[test]
    fn daemon_lock_mode_matches_restart_policy() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet");
        let owner = WalletInUse::for_daemon(&wallet).unwrap();
        let reader = open_sentinel(&wallet).unwrap();
        let shared = reader.try_lock_shared();
        if cfg!(feature = "integration-test") {
            // Restart tests retain the old daemon while constructing its replacement.
            shared.unwrap();
        } else {
            assert!(matches!(shared, Err(TryLockError::WouldBlock)));
        }
        // Even the integration exemption must retain the seed-write barrier.
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_none());
        drop(reader);
        drop(owner);
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_some());
    }

    #[test]
    fn owner_waits_for_library_readers_and_other_owners() {
        use std::{sync::mpsc, thread, time::Duration};

        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet");
        for guard in [WalletInUse::shared, WalletInUse::owner] {
            let running = guard(&wallet).unwrap();
            let path = wallet.clone();
            let (started_tx, started_rx) = mpsc::channel();
            let (acquired_tx, acquired_rx) = mpsc::channel();
            let waiter = thread::spawn(move || {
                started_tx.send(()).unwrap();
                let owner = WalletInUse::owner(&path).unwrap();
                acquired_tx.send(owner).unwrap();
            });
            started_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert!(matches!(
                acquired_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            drop(running);
            let owner = acquired_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_none());
            drop(owner);
            waiter.join().unwrap();
        }
        assert!(WalletInUse::exclusive_if_idle(&wallet).unwrap().is_some());
    }

    #[test]
    fn sentinel_open_failures_refuse_every_wallet_lock_mode() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = dir.path().join("wallet");
        let original = b"wallet bytes must remain untouched";
        std::fs::write(&wallet, original).unwrap();
        // A directory at the sentinel path fails on every platform, including
        // when tests run as root and Unix mode bits cannot simulate denial.
        let sentinel = in_use_path(&wallet);
        std::fs::create_dir(&sentinel).unwrap();
        for acquire in [
            WalletInUse::shared,
            WalletInUse::owner,
            WalletInUse::for_daemon,
        ] {
            let error = acquire(&wallet).err().expect("opening the lock must fail");
            assert!(error.to_string().contains("could not lock"));
        }
        // Seed commands must distinguish an I/O failure from an idle wallet.
        assert!(WalletInUse::exclusive_if_idle(&wallet).is_err());
        assert_eq!(std::fs::read(&wallet).unwrap(), original);
        assert!(
            sentinel.is_dir(),
            "a lock failure must not replace the sentinel"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn in_use_sentinel_sits_next_to_the_wallet_file() {
        assert_eq!(
            in_use_path(Path::new("/d/wallets/my.wallet")),
            PathBuf::from("/d/wallets/my.wallet.lock")
        );
    }

    #[test]
    fn quiz_positions_are_distinct_sorted_and_in_range() {
        let mut draws = [5u32, 5, 30, 1, 13].iter().copied();
        let picked = quiz_positions(12, 3, || draws.next().unwrap());
        // 5, then a repeat of 5 is skipped, 30 % 12 = 6, 1.
        assert_eq!(picked, vec![1, 5, 6]);
    }

    #[test]
    fn quiz_never_asks_for_more_words_than_exist() {
        let mut n = 0;
        let picked = quiz_positions(2, 3, || {
            n += 1;
            n
        });
        assert_eq!(picked, vec![0, 1]);
    }

    #[test]
    fn answers_match_the_exact_word_only() {
        let words = "abandon ability able about";
        assert!(answer_matches(words, 1, "ability"));
        assert!(answer_matches(words, 1, " Ability\n"));
        assert!(!answer_matches(words, 1, "able"));
        assert!(!answer_matches(words, 1, ""));
        assert!(!answer_matches(words, 9, "abandon"));
    }
}
