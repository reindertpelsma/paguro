//! The text-console prompt (no GOP, or a mode below 640×480): the same
//! Prompt state machine, echoed as text; the secret never reaches the
//! console.
#![allow(clippy::indexing_slicing)]

use std::collections::VecDeque;

use paguro_boot::platform::{Input, Row, Screen};
use paguro_boot::ui::Key;
use paguro_ui::driver::{Console, prompt_text};

struct Tty {
    out: String,
    keys: VecDeque<Key>,
}

impl Console for Tty {
    fn write_str(&mut self, s: &str) {
        self.out.push_str(s);
    }
    fn read_key(&mut self) -> Key {
        self.keys.pop_front().unwrap_or(Key::Escape)
    }
}

#[test]
fn secret_entry_echoes_bullets_only() {
    let screen = Screen::EnterSecret {
        row: Row::PasswordOrPin,
        unattested: false,
    };
    let mut t = Tty {
        out: String::new(),
        keys: "hunter2"
            .chars()
            .map(Key::Char)
            .chain([Key::Backspace, Key::Enter])
            .collect(),
    };
    let mut buf = [0u8; 32];
    assert_eq!(prompt_text(&mut t, &screen, &mut buf), Input::Secret(6));
    assert_eq!(&buf[..6], b"hunter");
    assert!(t.out.contains("Password or PIN:"));
    assert!(t.out.contains("\r   > ******"));
    assert!(!t.out.contains("hunter"), "the secret is never echoed");
}

#[test]
fn lists_take_digits_and_arrows() {
    let screen = Screen::Unlock(paguro_boot::platform::UnlockMenu {
        password_or_pin: true,
        recovery_passphrase: false,
        recovery_key: true,
        tpm: Ok(Some(3)),
        unattested: false,
        first_boot: false,
    });
    let mut t = Tty {
        out: String::new(),
        keys: [Key::Down, Key::Enter].into(),
    };
    assert_eq!(
        prompt_text(&mut t, &screen, &mut []),
        Input::Select(Row::RecoveryKey)
    );
    let mut t = Tty {
        out: String::new(),
        keys: [Key::Char('1')].into(),
    };
    assert_eq!(
        prompt_text(&mut t, &screen, &mut []),
        Input::Select(Row::PasswordOrPin)
    );
    assert!(t.out.contains("Unlock Linux"));
}
