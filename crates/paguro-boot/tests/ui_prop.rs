//! Text entry (INTERFACES.md §13.3) under random keystrokes: never a panic,
//! never a secret byte past the entered text, the cursor always on a
//! character boundary, and every exit path leaves the buffer as the contract
//! says (Esc: all zero; Enter: exactly the text).
#![allow(clippy::indexing_slicing)]

use paguro_boot::platform::{DirListing, DirView, Input, Level, Listing, Row, Screen};
use paguro_boot::ui::{Browser, Field, FieldKind, Key, Prompt, RECOVERY_DIGITS, Reaction};
use proptest::prelude::*;

fn key() -> impl Strategy<Value = Key> {
    prop_oneof![
        4 => any::<char>().prop_map(Key::Char),
        3 => prop::sample::select(vec!['a', 'é', '€', '𝄞', '1', '7', '-', ' ', '\u{7}']).prop_map(Key::Char),
        1 => Just(Key::Backspace),
        1 => Just(Key::Delete),
        1 => Just(Key::Left),
        1 => Just(Key::Right),
        1 => Just(Key::Home),
        1 => Just(Key::End),
        1 => Just(Key::Insert),
        1 => Just(Key::Up),
        1 => Just(Key::Function(2)),
    ]
}

fn kind() -> impl Strategy<Value = FieldKind> {
    prop::sample::select(vec![
        FieldKind::Secret,
        FieldKind::RecoveryKey,
        FieldKind::Path,
    ])
}

/// A reference model: the text as a `Vec<char>` and a cursor in characters.
fn model(kind: FieldKind, keys: &[Key], cap: usize) -> (String, usize) {
    let mut t: Vec<char> = Vec::new();
    let mut c = 0usize;
    for k in keys {
        match *k {
            Key::Char(ch) => {
                let ok = match kind {
                    FieldKind::RecoveryKey => ch.is_ascii_digit() && t.len() < RECOVERY_DIGITS,
                    _ => !ch.is_control(),
                };
                let bytes: usize = t.iter().map(|x| x.len_utf8()).sum();
                if ok && bytes + ch.len_utf8() <= cap {
                    t.insert(c, ch);
                    c += 1;
                }
            }
            Key::Backspace if c > 0 => {
                t.remove(c - 1);
                c -= 1;
            }
            Key::Delete if c < t.len() => {
                t.remove(c);
            }
            Key::Left => c = c.saturating_sub(1),
            Key::Right => c = (c + 1).min(t.len()),
            Key::Home => c = 0,
            Key::End => c = t.len(),
            _ => {}
        }
    }
    (t.into_iter().collect(), c)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn field_matches_the_model_and_leaks_nothing(
        kind in kind(),
        keys in prop::collection::vec(key(), 0..80),
        cap in 0usize..40,
        junk in any::<u8>(),
    ) {
        let mut buf = vec![junk; cap];
        let mut f = Field::begin(kind, &mut buf);
        prop_assert!(buf.iter().all(|&b| b == 0), "begin wipes");
        for k in &keys {
            f.feed(*k, &mut buf);
            prop_assert!(f.cursor() <= f.len() && f.len() <= buf.len());
            prop_assert!(buf[f.len()..].iter().all(|&b| b == 0), "nothing past the text");
            prop_assert!(std::str::from_utf8(&buf[..f.len()]).is_ok());
            prop_assert!(f.text(&buf).is_char_boundary(f.cursor()));
        }
        let (text, cursor) = model(kind, &keys, cap);
        prop_assert_eq!(f.text(&buf), text.as_str());
        prop_assert_eq!(f.char_counts(&buf).0, cursor);
        let n = f.len();
        match f.feed(Key::Enter, &mut buf) {
            paguro_boot::ui::FieldEvent::Submit(m) => prop_assert_eq!(m, n),
            e => prop_assert!(false, "Enter gave {:?}", e),
        }
        f.feed(Key::Escape, &mut buf);
        prop_assert!(buf.iter().all(|&b| b == 0), "Esc wipes everything");
    }

    #[test]
    fn prompts_never_panic_and_every_exit_is_accounted_for(
        row in prop::sample::select(vec![Row::PasswordOrPin, Row::RecoveryPassphrase, Row::RecoveryKey]),
        keys in prop::collection::vec(prop_oneof![9 => key(), 1 => Just(Key::Enter), 1 => Just(Key::Escape)], 0..60),
    ) {
        let screen = Screen::EnterSecret { row, unattested: false };
        let mut buf = [0u8; 64];
        let mut p = Prompt::new(&screen, &mut buf);
        for k in keys {
            match p.feed(&screen, k, &mut buf) {
                Reaction::Done(Input::Escape) => {
                    prop_assert!(buf.iter().all(|&b| b == 0));
                    p = Prompt::new(&screen, &mut buf);
                }
                Reaction::Done(Input::Secret(n)) => {
                    prop_assert!(buf[n..].iter().all(|&b| b == 0));
                    // The caller consumes and wipes; a new prompt starts clean.
                    buf.fill(0);
                    p = Prompt::new(&screen, &mut buf);
                }
                Reaction::Done(other) => prop_assert!(false, "unexpected {:?}", other),
                Reaction::Redraw | Reaction::Ignore | Reaction::NextTheme | Reaction::ToggleMode => {}
            }
            let f = p.field().unwrap();
            prop_assert!(buf[f.len()..].iter().all(|&b| b == 0));
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    /// Any directory as read from disk (arbitrary UTF-16, sizes, kinds) and
    /// any keys: the listing stays bounded, sorted and valid; the browser
    /// only ever returns an entry that exists.
    #[test]
    fn listings_and_the_browser(
        names in prop::collection::vec(
            (prop::collection::vec(any::<u16>(), 0..40), any::<bool>(), any::<u64>(), prop::sample::select(vec!["", ".efi", ".VHD", ".vhdx", ".img", ".raw", ".txt"])),
            0..200,
        ),
        level in prop::sample::select(vec![Level::Volume, Level::EfiPartition, Level::Root]),
        keys in prop::collection::vec(prop_oneof![
            Just(Key::Up), Just(Key::Down), Just(Key::PageUp), Just(Key::PageDown),
            Just(Key::Home), Just(Key::End), Just(Key::Enter), Just(Key::Right),
            Just(Key::Left), Just(Key::Backspace), any::<char>().prop_map(Key::Char),
        ], 0..50),
        page in 1usize..20,
    ) {
        let mut d = Box::new(DirListing::new());
        d.clear(level);
        for (mut n, dir, bytes, ext) in names {
            n.extend(ext.encode_utf16());
            d.push(&n, dir, bytes);
        }
        d.sort();
        for i in 0..d.len() {
            let e = d.item(i).unwrap();
            prop_assert!(!e.name.is_empty() && !e.name.contains('\\') && !e.name.chars().any(char::is_control));
            if i > 0 {
                let p = d.item(i - 1).unwrap();
                let key = |e: &paguro_boot::platform::DirItem<'_>| (e.kind != paguro_boot::platform::EntryKind::Dir, e.name.to_lowercase());
                prop_assert!(key(&p) <= key(&e), "sorted: {:?} before {:?}", p.name, e.name);
            }
            match level {
                Level::EfiPartition => prop_assert!(e.kind != paguro_boot::platform::EntryKind::Disk),
                Level::Root => prop_assert!(e.kind != paguro_boot::platform::EntryKind::Efi),
                Level::Volume => {}
            }
        }
        let view = DirView { path: "\\x", listing: &*d, selected: 0, level };
        let mut b = Browser::new(&view);
        b.set_page(page);
        for k in keys {
            match b.feed(&view, k) {
                Reaction::Done(Input::Entry(i)) => prop_assert!(usize::from(i) < d.len()),
                Reaction::Done(Input::TypePath) => prop_assert_eq!(b.selected(), d.len()),
                Reaction::Done(Input::NoRoot) => {
                    prop_assert_eq!(level, Level::Root);
                    prop_assert_eq!(b.selected(), d.len() + 1);
                }
                _ => {}
            }
            prop_assert!(b.selected() < paguro_boot::ui::browse_rows(&view));
        }
    }
}

/// Scripted sessions: keys in, exact field state out.
#[test]
fn input_scripts() {
    struct Case {
        kind: FieldKind,
        keys: Vec<Key>,
        text: &'static str,
        cursor_chars: usize,
        revealed: bool,
    }
    let s = |t: &str| t.chars().map(Key::Char).collect::<Vec<_>>();
    let cat = |a: Vec<Key>, b: &[Key]| a.into_iter().chain(b.iter().copied()).collect::<Vec<_>>();
    let cases = [
        Case {
            kind: FieldKind::Secret,
            keys: cat(
                s("correct horse"),
                &[Key::Home, Key::Delete, Key::Char('C')],
            ),
            text: "Correct horse",
            cursor_chars: 1,
            revealed: false,
        },
        Case {
            kind: FieldKind::Secret,
            keys: cat(
                s("pässwörd"),
                &[Key::Left, Key::Left, Key::Backspace, Key::Insert],
            ),
            text: "pässwrd",
            cursor_chars: 5,
            revealed: true,
        },
        Case {
            kind: FieldKind::RecoveryKey,
            keys: cat(
                s("000011-000022 000033"),
                &[
                    Key::End,
                    Key::Backspace,
                    Key::Char('4'),
                    Key::Insert,
                    Key::Insert,
                ],
            ),
            text: "000011000022000034",
            cursor_chars: 18,
            revealed: false,
        },
        Case {
            kind: FieldKind::Path,
            keys: cat(
                s("\\pguro\\x.efi"),
                &[
                    Key::Home,
                    Key::Right,
                    Key::Right,
                    Key::Char('a'),
                    Key::Insert,
                ],
            ),
            text: "\\paguro\\x.efi",
            cursor_chars: 3,
            revealed: true,
        },
    ];
    for c in cases {
        let mut buf = [0u8; 128];
        let mut f = Field::begin(c.kind, &mut buf);
        for k in &c.keys {
            f.feed(*k, &mut buf);
        }
        assert_eq!(f.text(&buf), c.text);
        assert_eq!(f.char_counts(&buf).0, c.cursor_chars, "{}", c.text);
        assert_eq!(f.revealed(), c.revealed, "{}", c.text);
    }
}
