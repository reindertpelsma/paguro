//! The compiled-in theme: every [`Screen`] as text, and the key → [`Input`]
//! mapping. Pure functions, so the firmware adapter only prints lines and
//! forwards keys, and all of this is tested on the host.
//!
//! Rules from DESIGN.md §4.1 "Screens" that apply to text: the name on every
//! screen; Esc always leads somewhere; rows labelled by cost; an unattested
//! prompt says so; error codes are not in the message.

use core::fmt::{self, Write};

use crate::platform::{Grey, Input, Notice, Row, Screen, UnlockMenu};

/// A key, already decoded from the firmware's `EFI_INPUT_KEY`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Escape,
    Backspace,
}

fn header(w: &mut dyn Write) -> fmt::Result {
    w.write_str("\r\n                     paguro\r\n\r\n")
}

fn tpm_note(menu: &UnlockMenu) -> &'static str {
    match menu.tpm {
        Ok(_) => "",
        Err(Grey::RecoveryMode) => "   [x] TPM unavailable until restart -- recovery mode",
        Err(Grey::Locked) => "   [x] TPM locked -- use another option",
        Err(Grey::Unavailable) => "",
    }
}

/// Render `screen` as CRLF-terminated lines.
pub fn render(screen: &Screen, w: &mut dyn Write) -> fmt::Result {
    header(w)?;
    match screen {
        Screen::Unlock(m) => {
            w.write_str("   Unlock Linux\r\n")?;
            if m.unattested {
                w.write_str("   (configuration unverified: this prompt is unattested)\r\n")?;
            }
            if m.first_boot {
                w.write_str("   From now on this replaces your Linux login password --\r\n")?;
                w.write_str("   and restarting into Linux from Windows skips it.\r\n")?;
            }
            w.write_str("\r\n")?;
            if m.password_or_pin {
                match m.tpm {
                    Ok(Some(n)) => write!(w, " 1 Password or PIN            {n} TPM attempts left\r\n")?,
                    _ => w.write_str(" 1 Password or PIN\r\n")?,
                }
            }
            if m.recovery_passphrase {
                w.write_str(" 2 Recovery passphrase        no attempt limit\r\n")?;
            }
            if m.recovery_key {
                w.write_str(" 3 Recovery key               48 digits\r\n")?;
            }
            let note = tpm_note(m);
            if !note.is_empty() {
                write!(w, "{note}\r\n")?;
            }
            w.write_str("\r\n   W Start Windows   R Recover   Esc other options\r\n")
        }
        Screen::EnterSecret { row, unattested } => {
            let what = match row {
                Row::PasswordOrPin => "Password or PIN",
                Row::RecoveryPassphrase => "Recovery passphrase",
                Row::RecoveryKey => "Recovery key (48 digits, aka.ms/myrecoverykey)",
            };
            if *unattested {
                w.write_str("   (unattested prompt)\r\n")?;
            }
            write!(w, "   {what}: ")
        }
        Screen::Incorrect => w.write_str("   That did not unlock the volume.\r\n"),
        Screen::CannotUnlock => w.write_str(
            "   Cannot unlock Linux\r\n\r\n   Windows will almost certainly start normally.\r\n   Try that first -- you probably do not need\r\n   your recovery key.\r\n\r\n   Enter Start Windows\r\n   R     I need Linux now -- enter recovery key\r\n",
        ),
        Screen::ConfigInvalid => w.write_str(
            "   Configuration is not valid\r\n\r\n   paguro.ini has changed since it was installed,\r\n   or is damaged. Linux cannot start from it.\r\n\r\n   If you did not change it, this may indicate\r\n   tampering.\r\n\r\n   Enter Start Windows\r\n   R     Recover Linux -- needs a password or key\r\n",
        ),
        Screen::TpmLocked => w.write_str(
            "   Too many incorrect attempts\r\n\r\n   The TPM has locked itself to prevent guessing.\r\n   Waiting will restore it -- nothing is damaged.\r\n   Your other unlock options still work.\r\n",
        ),
        Screen::NoInstallation => w.write_str(
            "   No Linux installation found\r\n\r\n   To fix   Start Windows and run the paguro repair tool\r\n\r\n   W Start Windows\r\n",
        ),
        Screen::SelectVolume { count } => {
            w.write_str("   Which volume holds your Linux installation?\r\n\r\n")?;
            for i in 0..*count {
                write!(w, " {} Volume {}\r\n", i + 1, i + 1)?;
            }
            Ok(())
        }
        Screen::Notice(n) => {
            let (title, body, actions) = match n {
                Notice::Hibernated => (
                    "Windows saved a session -- starting Linux read-only",
                    "This is normal after shutting Windows down.\r\n   Your disk is fine. Linux will start, but cannot\r\n   write until Windows resumes once.",
                    "Enter Continue read-only   W Restart into Windows",
                ),
                Notice::Dirty => (
                    "Windows didn't shut down cleanly last time",
                    "Your disk is fine. Linux will start read-only.",
                    "Enter Continue read-only   W Restart into Windows",
                ),
                Notice::Pcr12NotZero => (
                    "This firmware already used paguro's measurement slot",
                    "The TPM cannot be trusted to protect the key on this boot.",
                    "Enter Start Windows   R Recover Linux",
                ),
                Notice::SealOverPlaintext => (
                    "Refusing an illusory configuration",
                    "A TPM seal over an unencrypted volume protects nothing.",
                    "Enter Start Windows",
                ),
                Notice::VolumeMissing => (
                    "The Linux volume was not found",
                    "The configured volume is not on any disk.",
                    "Enter Start Windows   R Recover Linux",
                ),
                Notice::NotImplemented => (
                    "This build cannot finish starting Linux",
                    "A later stage is not implemented yet.",
                    "Any key",
                ),
            };
            write!(w, "   {title}\r\n\r\n   {body}\r\n\r\n   {actions}\r\n")
        }
    }
}

/// Whether a screen waits for a key. "That did not unlock" is shown and the
/// unlock list follows at once, so a retry costs no extra keystroke.
pub const fn needs_key(screen: &Screen) -> bool {
    !matches!(screen, Screen::Incorrect)
}

/// Map a key on a non-secret screen. `None`: ignore the key.
pub fn map_key(screen: &Screen, key: Key) -> Option<Input> {
    let c = match key {
        Key::Char(c) => Some(c.to_ascii_lowercase()),
        _ => None,
    };
    match screen {
        Screen::Unlock(m) => match (key, c) {
            (_, Some('1')) if m.password_or_pin => Some(Input::Select(Row::PasswordOrPin)),
            (_, Some('2')) if m.recovery_passphrase => Some(Input::Select(Row::RecoveryPassphrase)),
            (_, Some('3')) if m.recovery_key => Some(Input::Select(Row::RecoveryKey)),
            (_, Some('w')) => Some(Input::StartWindows),
            (_, Some('r')) => Some(Input::Recover),
            (Key::Escape, _) => Some(Input::Escape),
            _ => None,
        },
        Screen::CannotUnlock => match (key, c) {
            (Key::Enter, _) => Some(Input::StartWindows),
            (_, Some('r')) => Some(Input::Select(Row::RecoveryKey)),
            (Key::Escape, _) => Some(Input::Escape),
            _ => None,
        },
        Screen::ConfigInvalid
        | Screen::Notice(Notice::Pcr12NotZero)
        | Screen::Notice(Notice::VolumeMissing) => match (key, c) {
            (Key::Enter, _) => Some(Input::StartWindows),
            (_, Some('r')) => Some(Input::Recover),
            (Key::Escape, _) => Some(Input::Escape),
            _ => None,
        },
        Screen::Notice(Notice::Hibernated) | Screen::Notice(Notice::Dirty) => match (key, c) {
            (Key::Enter, _) => Some(Input::Continue),
            (_, Some('w')) => Some(Input::StartWindows),
            (Key::Escape, _) => Some(Input::Escape),
            _ => None,
        },
        Screen::NoInstallation => match (key, c) {
            (_, Some('w')) | (Key::Enter, _) => Some(Input::StartWindows),
            (Key::Escape, _) => Some(Input::Escape),
            _ => None,
        },
        Screen::SelectVolume { count } => match (key, c) {
            (_, Some(d @ '1'..='9')) => {
                let i = (d as u8) - b'1';
                (i < *count).then_some(Input::Choose(i))
            }
            (Key::Escape, _) => Some(Input::Escape),
            _ => None,
        },
        Screen::Incorrect
        | Screen::TpmLocked
        | Screen::Notice(Notice::SealOverPlaintext)
        | Screen::Notice(Notice::NotImplemented) => Some(Input::Continue),
        Screen::EnterSecret { .. } => None,
    }
}

/// Line editor for secret entry into a fixed buffer. Characters are stored
/// UTF-8 encoded; input beyond the buffer is dropped, never wrapped.
#[derive(Default)]
pub struct SecretEditor {
    len: usize,
}

/// What the editor wants the adapter to do after a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Edit {
    /// Echo one mask character.
    Echo,
    /// Erase one mask character.
    Erase,
    Nothing,
    Done(Input),
}

impl SecretEditor {
    pub const fn new() -> Self {
        SecretEditor { len: 0 }
    }

    pub fn feed(&mut self, key: Key, buf: &mut [u8]) -> Edit {
        match key {
            Key::Enter => Edit::Done(Input::Secret(self.len)),
            Key::Escape => {
                buf.iter_mut().for_each(|b| *b = 0);
                self.len = 0;
                Edit::Done(Input::Escape)
            }
            Key::Backspace => {
                let Some(s) = buf.get(..self.len) else {
                    return Edit::Nothing;
                };
                // Drop the last UTF-8 scalar.
                let Some(last) = core::str::from_utf8(s)
                    .ok()
                    .and_then(|t| t.chars().next_back())
                else {
                    return Edit::Nothing;
                };
                let new = self.len - last.len_utf8();
                if let Some(t) = buf.get_mut(new..self.len) {
                    t.fill(0);
                }
                self.len = new;
                Edit::Erase
            }
            Key::Char(c) => {
                if c.is_control() {
                    return Edit::Nothing;
                }
                let mut enc = [0u8; 4];
                let e = c.encode_utf8(&mut enc).as_bytes();
                match buf.get_mut(self.len..self.len + e.len()) {
                    Some(dst) => {
                        dst.copy_from_slice(e);
                        self.len += e.len();
                        Edit::Echo
                    }
                    None => Edit::Nothing,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;

    fn menu() -> UnlockMenu {
        UnlockMenu {
            password_or_pin: true,
            recovery_passphrase: false,
            recovery_key: true,
            tpm: Ok(Some(3)),
            unattested: false,
            first_boot: false,
        }
    }

    fn text(s: &Screen) -> String {
        let mut out = String::new();
        render(s, &mut out).unwrap();
        out
    }

    #[test]
    fn every_screen_renders_with_the_name() {
        let screens = [
            Screen::Unlock(menu()),
            Screen::Unlock(UnlockMenu {
                tpm: Err(Grey::RecoveryMode),
                unattested: true,
                first_boot: true,
                recovery_passphrase: true,
                ..menu()
            }),
            Screen::Unlock(UnlockMenu {
                tpm: Err(Grey::Locked),
                ..menu()
            }),
            Screen::Unlock(UnlockMenu {
                tpm: Err(Grey::Unavailable),
                ..menu()
            }),
            Screen::EnterSecret {
                row: Row::PasswordOrPin,
                unattested: true,
            },
            Screen::EnterSecret {
                row: Row::RecoveryPassphrase,
                unattested: false,
            },
            Screen::EnterSecret {
                row: Row::RecoveryKey,
                unattested: false,
            },
            Screen::Incorrect,
            Screen::CannotUnlock,
            Screen::ConfigInvalid,
            Screen::TpmLocked,
            Screen::NoInstallation,
            Screen::SelectVolume { count: 2 },
            Screen::Notice(Notice::Hibernated),
            Screen::Notice(Notice::Dirty),
            Screen::Notice(Notice::Pcr12NotZero),
            Screen::Notice(Notice::SealOverPlaintext),
            Screen::Notice(Notice::VolumeMissing),
            Screen::Notice(Notice::NotImplemented),
        ];
        for s in &screens {
            let t = text(s);
            assert!(t.contains("paguro"), "{s:?}");
            assert!(
                !t.contains("error"),
                "codes live behind D, not in messages: {s:?}"
            );
        }
        assert!(text(&screens[0]).contains("3 TPM attempts left"));
        assert!(text(&screens[1]).contains("unattested"));
        assert!(text(&screens[1]).contains("recovery mode"));
        assert!(text(&screens[1]).contains("replaces your Linux login password"));
        assert!(text(&screens[2]).contains("TPM locked"));
        assert!(text(&Screen::Notice(Notice::Hibernated)).contains("This is normal"));
        assert!(!text(&Screen::Notice(Notice::Hibernated)).contains("cannot start"));
    }

    #[test]
    fn unlock_keys() {
        let s = Screen::Unlock(menu());
        assert_eq!(
            map_key(&s, Key::Char('1')),
            Some(Input::Select(Row::PasswordOrPin))
        );
        assert_eq!(map_key(&s, Key::Char('2')), None, "absent row");
        assert_eq!(
            map_key(&s, Key::Char('3')),
            Some(Input::Select(Row::RecoveryKey))
        );
        assert_eq!(map_key(&s, Key::Char('W')), Some(Input::StartWindows));
        assert_eq!(map_key(&s, Key::Char('r')), Some(Input::Recover));
        assert_eq!(map_key(&s, Key::Escape), Some(Input::Escape));
        assert_eq!(map_key(&s, Key::Enter), None);
    }

    #[test]
    fn message_screen_keys() {
        assert_eq!(
            map_key(&Screen::CannotUnlock, Key::Enter),
            Some(Input::StartWindows)
        );
        assert_eq!(
            map_key(&Screen::CannotUnlock, Key::Char('r')),
            Some(Input::Select(Row::RecoveryKey))
        );
        assert_eq!(
            map_key(&Screen::CannotUnlock, Key::Escape),
            Some(Input::Escape)
        );
        assert_eq!(map_key(&Screen::CannotUnlock, Key::Char('x')), None);
        for s in [
            Screen::ConfigInvalid,
            Screen::Notice(Notice::Pcr12NotZero),
            Screen::Notice(Notice::VolumeMissing),
        ] {
            assert_eq!(map_key(&s, Key::Enter), Some(Input::StartWindows));
            assert_eq!(map_key(&s, Key::Char('R')), Some(Input::Recover));
            assert_eq!(map_key(&s, Key::Escape), Some(Input::Escape));
            assert_eq!(map_key(&s, Key::Backspace), None);
        }
        for s in [
            Screen::Notice(Notice::Hibernated),
            Screen::Notice(Notice::Dirty),
        ] {
            assert_eq!(map_key(&s, Key::Enter), Some(Input::Continue));
            assert_eq!(map_key(&s, Key::Char('w')), Some(Input::StartWindows));
            assert_eq!(map_key(&s, Key::Escape), Some(Input::Escape));
            assert_eq!(map_key(&s, Key::Char('z')), None);
        }
        assert_eq!(
            map_key(&Screen::NoInstallation, Key::Enter),
            Some(Input::StartWindows)
        );
        assert_eq!(
            map_key(&Screen::NoInstallation, Key::Escape),
            Some(Input::Escape)
        );
        assert_eq!(map_key(&Screen::NoInstallation, Key::Char('q')), None);
        let sv = Screen::SelectVolume { count: 2 };
        assert_eq!(map_key(&sv, Key::Char('2')), Some(Input::Choose(1)));
        assert_eq!(map_key(&sv, Key::Char('3')), None);
        assert_eq!(map_key(&sv, Key::Escape), Some(Input::Escape));
        assert_eq!(map_key(&sv, Key::Enter), None);
        assert_eq!(
            map_key(&Screen::Incorrect, Key::Char('x')),
            Some(Input::Continue)
        );
        assert!(!needs_key(&Screen::Incorrect));
        assert!(needs_key(&Screen::TpmLocked));
        assert_eq!(
            map_key(
                &Screen::EnterSecret {
                    row: Row::RecoveryKey,
                    unattested: false
                },
                Key::Enter
            ),
            None
        );
    }

    #[test]
    fn secret_editor() {
        let mut buf = [0u8; 6];
        let mut e = SecretEditor::new();
        assert_eq!(e.feed(Key::Backspace, &mut buf), Edit::Nothing);
        assert_eq!(e.feed(Key::Char('a'), &mut buf), Edit::Echo);
        assert_eq!(e.feed(Key::Char('é'), &mut buf), Edit::Echo);
        assert_eq!(e.feed(Key::Char('\u{7}'), &mut buf), Edit::Nothing);
        assert_eq!(e.feed(Key::Backspace, &mut buf), Edit::Erase);
        assert_eq!(&buf, b"a\0\0\0\0\0");
        for c in "bcdef".chars() {
            assert_eq!(e.feed(Key::Char(c), &mut buf), Edit::Echo);
        }
        assert_eq!(e.feed(Key::Char('g'), &mut buf), Edit::Nothing, "bounded");
        assert_eq!(e.feed(Key::Enter, &mut buf), Edit::Done(Input::Secret(6)));
        assert_eq!(&buf, b"abcdef");
        assert_eq!(e.feed(Key::Escape, &mut buf), Edit::Done(Input::Escape));
        assert_eq!(buf, [0; 6], "cancel wipes");
    }
}
