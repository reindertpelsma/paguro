//! Boot keyboard layouts (INTERFACES.md §13.5) against the X keyboard
//! configuration: every printable key of every layout, at every level,
//! typed the way US-mapped firmware reports it, must give what the layout's
//! xkb symbols give (`tests/keymaps/<layout>.tsv`, extracted by
//! `tools/xkb-keymaps.py` from xkeyboard-config; the source and version are
//! in each file's first line).
#![allow(clippy::indexing_slicing)]

use paguro_boot::keymap::{self, Keyboard, Purpose, Typed};
use proptest::prelude::*;

fn reference(k: Keyboard) -> Vec<(String, [Option<char>; 4])> {
    let path = format!(
        "{}/tests/keymaps/{}.tsv",
        env!("CARGO_MANIFEST_DIR"),
        k.name()
    );
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    assert!(text.starts_with(&format!("# {}: xkb ", k.name())));
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            assert_eq!(f.len(), 5, "{l}");
            let mut lv = [None; 4];
            for (i, v) in f[1..].iter().enumerate() {
                lv[i] = v
                    .strip_prefix("U+")
                    .map(|h| char::from_u32(u32::from_str_radix(h, 16).unwrap()).unwrap());
            }
            (f[0].to_string(), lv)
        })
        .collect()
}

/// What US firmware reports for physical key `key` at `level`.
fn us_report(key: usize, level: usize) -> char {
    let us = keymap::table(Keyboard::Us);
    us[key][level & 1]
}

#[test]
fn every_key_of_every_layout_matches_xkb() {
    let mut checked = 0;
    for k in Keyboard::ALL {
        let r = reference(k);
        assert_eq!(r.len(), keymap::KEYS, "{k:?}");
        for (key, (name, levels)) in r.iter().enumerate() {
            for (level, want) in levels.iter().enumerate() {
                let shift = level & 1 == 1;
                let altgr = level >= 2;
                let typed = Typed {
                    ch: us_report(key, level),
                    shift: Some(shift),
                    altgr,
                    caps: Some(false),
                };
                let got = keymap::remap(k, typed, Purpose::Text);
                assert_eq!(got, *want, "{k:?} {name} level {}", level + 1);
                // Without modifier state the character's case tells Shift.
                if !altgr {
                    let plain = Typed::plain(us_report(key, level));
                    assert_eq!(
                        keymap::remap(k, plain, Purpose::Text),
                        *want,
                        "{k:?} {name} level {} without shift state",
                        level + 1
                    );
                }
                checked += 1;
            }
        }
    }
    assert_eq!(checked, Keyboard::ALL.len() * keymap::KEYS * 4);
}

#[test]
fn every_layout_has_its_digits_and_letters() {
    // What a passphrase at boot can contain: all 26 letters in both cases
    // on every layout, and the 10 digits (with Shift on AZERTY).
    for k in Keyboard::ALL {
        let t = keymap::table(k);
        let all: String = t.iter().flat_map(|lv| lv[..2].iter()).collect();
        for c in ('a'..='z').chain('A'..='Z').chain('0'..='9') {
            assert!(all.contains(c), "{k:?} cannot type {c:?}");
        }
    }
}

proptest! {
    #[test]
    fn remap_is_total_and_never_yields_controls(
        layout in 0usize..8,
        c in any::<char>(),
        shift in proptest::option::of(any::<bool>()),
        altgr in any::<bool>(),
        caps in proptest::option::of(any::<bool>()),
        digits in any::<bool>(),
    ) {
        let k = Keyboard::ALL[layout];
        let p = if digits { Purpose::Digits } else { Purpose::Text };
        if let Some(out) = keymap::remap(k, Typed { ch: c, shift, altgr, caps }, p) {
            prop_assert!(!out.is_control());
        }
    }

    #[test]
    fn caps_lock_changes_only_the_case_of_letters(layout in 0usize..8, key in 0usize..keymap::KEYS, shift in any::<bool>()) {
        let k = Keyboard::ALL[layout];
        let ch = us_report(key, usize::from(shift));
        let t = |caps| Typed { ch, shift: Some(shift), altgr: false, caps: Some(caps) };
        let off = keymap::remap(k, t(false), Purpose::Text);
        let on = keymap::remap(k, t(true), Purpose::Text);
        match (off, on) {
            (Some(a), Some(b)) if a != b => {
                prop_assert!(a.is_alphabetic() && b.is_alphabetic());
                prop_assert!(a.to_lowercase().eq(b.to_lowercase()));
            }
            (a, b) => prop_assert_eq!(a, b),
        }
    }

    #[test]
    fn digits_purpose_gives_the_number_row(layout in 0usize..8, d in 0usize..10, shift in any::<bool>()) {
        let k = Keyboard::ALL[layout];
        let key = d + 1; // AE01..AE10
        let ch = us_report(key, usize::from(shift));
        let want = char::from_digit(((d + 1) % 10) as u32, 10).unwrap();
        prop_assert_eq!(keymap::remap(k, Typed::plain(ch), Purpose::Digits), Some(want));
    }
}
