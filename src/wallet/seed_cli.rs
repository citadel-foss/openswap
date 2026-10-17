//! The offline `show-seed` and `attach-seed` commands of `taker` and `makerd`.
//! They need an existing wallet file and no backend, take every secret at a
//! hidden prompt (never argv), and are never reachable over RPC or the network.

use std::{io::IsTerminal, path::Path};

use bip39::rand::random;
use zeroize::Zeroizing;

use super::{api::Wallet, error::WalletError};
use crate::utill::prompt_password;

/// Words the user must re-type before the backup counts as confirmed.
const QUIZ_WORDS: usize = 3;

fn prompt(message: &str) -> Result<Zeroizing<String>, WalletError> {
    prompt_password(message.to_string())
        .map_err(|e| WalletError::General(format!("prompt failed: {e}")))
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
        .is_some_and(|word| word == answer.trim().to_lowercase())
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
    let mut wallet = Wallet::open_offline(wallet_path, password.clone())?;
    let words = wallet.get_wallet_mnemonic(password.clone())?.words();
    println!("\nWrite these words down, in order, on paper:\n");
    for (i, word) in words.split(' ').enumerate() {
        println!("{:>3}. {word}", i + 1);
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
    let mut wallet = Wallet::open_offline(wallet_path, password.clone())?;
    let phrase = prompt("Enter the original seed phrase: ")?;
    wallet.attach_wallet_mnemonic(password, phrase)?;
    println!("\nSeed phrase attached. Run show-seed to confirm your backup of it.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
