//! Keyboard layouts at boot (INTERFACES.md §13.5).
//!
//! Firmware keyboard drivers map keys as a US keyboard, whatever is printed
//! on them. The key the user pressed is still known from what the US layout
//! made of it: this module inverts the US table to find the physical key,
//! takes the level from Shift and AltGr (`SimpleTextInputEx`'s shift state;
//! the character's case when the firmware gives no state), and looks the key
//! up in the chosen layout's compiled-in table (`keymap_tables.rs`,
//! generated from xkeyboard-config by `tools/xkb-keymaps.py`).
//!
//! - Dead keys give nothing: the loader does not compose.
//! - Caps Lock (when the firmware reports it) turns a letter into its other
//!   case, as it does for letters on every supported layout.
//! - [`Purpose::Digits`]: menus and the recovery key take the number row as
//!   digits on every layout — on AZERTY those need Shift in the table, and
//!   48 shifted digits are not what anyone types.
//! - The ISO key next to left Shift and the one next to Enter both reach
//!   the loader as US backslash: they are the key next to Enter here.
//!
//! Serial consoles send what the terminal's own layout produced and are not
//! remapped.

pub use paguro_core::config::Keyboard;

use crate::keymap_tables as t;

/// Physical keys in a table (see `keymap_tables.rs` for the order).
pub const KEYS: usize = 47;

/// Shift levels of a table row (xkb levels 1–4): base, Shift, AltGr,
/// AltGr+Shift. The Shift bit toggles between a level and its pair.
pub const LEVELS: usize = 4;
const LEVEL_SHIFT: usize = 1;
const LEVEL_ALTGR: usize = 2;
/// A key or level with no character (absent, or a dead key).
const NO_CHAR: char = '\0';

/// The number row's digit keys: `AE01`..`AE09` give '1'..'9', `AE10` gives '0'.
const KEY_AE01: usize = 1;
const KEY_AE09: usize = 9;
const KEY_AE10: usize = 10;

/// What the firmware reported for one key press, US-mapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Typed {
    /// The character the US layout gives (with the firmware's Shift and
    /// Caps Lock applied).
    pub ch: char,
    /// Shift is held (`None`: the firmware does not say).
    pub shift: Option<bool>,
    /// AltGr (right Alt) is held.
    pub altgr: bool,
    /// Caps Lock is on (`None`: the firmware does not say).
    pub caps: Option<bool>,
}

impl Typed {
    /// A plain character with no modifier information.
    pub const fn plain(ch: char) -> Typed {
        Typed {
            ch,
            shift: None,
            altgr: false,
            caps: None,
        }
    }
}

/// What the typed character is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Purpose {
    /// A passphrase, PIN or path: the layout's character.
    Text,
    /// Menus and the recovery key: the number row is digits.
    Digits,
}

/// The layout's table.
pub fn table(k: Keyboard) -> &'static [[char; LEVELS]; KEYS] {
    match k {
        Keyboard::Us => &t::US,
        Keyboard::Uk => &t::UK,
        Keyboard::De => &t::DE,
        Keyboard::Fr => &t::FR,
        Keyboard::Es => &t::ES,
        Keyboard::Be => &t::BE,
        Keyboard::ChDe => &t::CHDE,
        Keyboard::NlIntl => &t::NLINTL,
    }
}

/// The physical key and Shift level the US layout gives `c` on.
pub fn us_key(c: char) -> Option<(usize, bool)> {
    t::US.iter().enumerate().find_map(|(i, lv)| {
        if lv.first() == Some(&c) {
            Some((i, false))
        } else if lv.get(LEVEL_SHIFT) == Some(&c) {
            Some((i, true))
        } else {
            None
        }
    })
}

/// Number-row keys: `AE01`..`AE10` are table entries 1..=10.
fn number_row_digit(key: usize) -> Option<char> {
    match key {
        KEY_AE01..=KEY_AE09 => char::from_digit(key as u32, 10),
        KEY_AE10 => Some('0'),
        _ => None,
    }
}

/// The character `layout` produces for what the firmware reported, or
/// `None` (a dead key, a level the key does not have).
pub fn remap(layout: Keyboard, typed: Typed, purpose: Purpose) -> Option<char> {
    let c = typed.ch;
    if c == ' ' {
        return Some(' ');
    }
    let Some((key, us_shift)) = us_key(c) else {
        // Not on a US key (the firmware composed something itself): as is,
        // unless it is a control character.
        return (!c.is_control()).then_some(c);
    };
    if purpose == Purpose::Digits && !typed.altgr {
        if let Some(d) = number_row_digit(key) {
            return Some(d);
        }
    }
    // The US layout's letters follow Caps Lock: 'A' without Shift is a
    // lowercase key press with Caps Lock on.
    let shift = typed.shift.unwrap_or(us_shift);
    let level = usize::from(shift) * LEVEL_SHIFT + if typed.altgr { LEVEL_ALTGR } else { 0 };
    let row = table(layout).get(key)?;
    let out = *row.get(level)?;
    if out == NO_CHAR {
        return None;
    }
    // Caps Lock: a letter's other case, when its key has it.
    let caps = typed.caps.unwrap_or(false) && !typed.altgr;
    if caps && out.is_alphabetic() {
        let other = *row.get(level ^ LEVEL_SHIFT)?;
        let is_case_pair = other != NO_CHAR
            && other != out
            && (out.to_uppercase().eq(core::iter::once(other))
                || out.to_lowercase().eq(core::iter::once(other)));
        if is_case_pair {
            return Some(other);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(layout: Keyboard, s: &str) -> Option<[char; 16]> {
        let mut out = ['\0'; 16];
        for (o, c) in out.iter_mut().zip(s.chars()) {
            *o = remap(layout, Typed::plain(c), Purpose::Text)?;
        }
        Some(out)
    }

    fn eq(a: [char; 16], s: &str) -> bool {
        a.iter().take_while(|c| **c != '\0').copied().eq(s.chars())
    }

    #[test]
    fn us_is_the_identity_on_printable_ascii() {
        for b in 0x20u8..0x7f {
            let c = char::from(b);
            assert_eq!(remap(Keyboard::Us, Typed::plain(c), Purpose::Text), Some(c));
        }
    }

    #[test]
    fn the_well_known_swaps() {
        // German: z/y swapped; French: a/q, z/w, m moved to US ';'.
        assert!(eq(text(Keyboard::De, "zy;'[").unwrap(), "yzöäü"));
        assert!(eq(text(Keyboard::Fr, "qwaz;m").unwrap(), "azqwm,"));
        assert!(eq(text(Keyboard::Be, "qwaz;").unwrap(), "azqwm"));
        assert!(eq(text(Keyboard::ChDe, "zy[").unwrap(), "yzü"));
        assert!(eq(text(Keyboard::Es, ";").unwrap(), "ñ"));
        assert!(eq(text(Keyboard::Uk, "@\"#").unwrap(), "\"@£"));
        // AZERTY's number row: symbols unshifted, digits with Shift.
        assert!(eq(text(Keyboard::Fr, "1234567890").unwrap(), "&é\"'(-è_çà"));
        assert!(eq(text(Keyboard::Fr, "!@#$%^&*()").unwrap(), "1234567890"));
    }

    #[test]
    fn digits_purpose_keeps_the_number_row() {
        for k in Keyboard::ALL {
            for (us, d) in "1234567890".chars().zip("1234567890".chars()) {
                assert_eq!(
                    remap(k, Typed::plain(us), Purpose::Digits),
                    Some(d),
                    "{k:?}"
                );
            }
            for (us, d) in "!@#$%^&*()".chars().zip("1234567890".chars()) {
                assert_eq!(
                    remap(k, Typed::plain(us), Purpose::Digits),
                    Some(d),
                    "{k:?}"
                );
            }
        }
        // Letters still follow the layout: W on AZERTY is US 'z'.
        assert_eq!(
            remap(Keyboard::Fr, Typed::plain('z'), Purpose::Digits),
            Some('w')
        );
    }

    #[test]
    fn altgr_shift_and_caps() {
        let k = |ch, shift, altgr, caps| Typed {
            ch,
            shift,
            altgr,
            caps,
        };
        // German AltGr+Q is @, AltGr+E is €.
        assert_eq!(
            remap(Keyboard::De, k('q', Some(false), true, None), Purpose::Text),
            Some('@')
        );
        assert_eq!(
            remap(Keyboard::De, k('e', Some(false), true, None), Purpose::Text),
            Some('€')
        );
        // French AltGr+0 is @ (AE10, level 3).
        assert_eq!(
            remap(Keyboard::Fr, k('0', Some(false), true, None), Purpose::Text),
            Some('@')
        );
        // US has no AltGr level: nothing.
        assert_eq!(
            remap(Keyboard::Us, k('q', Some(false), true, None), Purpose::Text),
            None
        );
        // Caps Lock, no Shift: the firmware gave 'A' for US 'a'; German 'a'
        // key with Caps Lock is 'A'.
        assert_eq!(
            remap(
                Keyboard::De,
                k('A', Some(false), false, Some(true)),
                Purpose::Text
            ),
            Some('A')
        );
        // Caps Lock on a key that is a symbol in US but a letter here.
        assert_eq!(
            remap(
                Keyboard::De,
                k(';', Some(false), false, Some(true)),
                Purpose::Text
            ),
            Some('Ö')
        );
        assert_eq!(
            remap(
                Keyboard::De,
                k(':', Some(true), false, Some(true)),
                Purpose::Text
            ),
            Some('ö')
        );
        // Caps Lock does not touch AZERTY's comma on US 'm'.
        assert_eq!(
            remap(
                Keyboard::Fr,
                k('M', Some(false), false, Some(true)),
                Purpose::Text
            ),
            Some(',')
        );
        // Dead keys give nothing (German ^ and ´, French ^).
        assert_eq!(remap(Keyboard::De, Typed::plain('`'), Purpose::Text), None);
        assert_eq!(remap(Keyboard::De, Typed::plain('='), Purpose::Text), None);
        assert_eq!(remap(Keyboard::Fr, Typed::plain('['), Purpose::Text), None);
        // Space and what the firmware composed itself pass through.
        assert_eq!(
            remap(Keyboard::Fr, Typed::plain(' '), Purpose::Text),
            Some(' ')
        );
        assert_eq!(
            remap(Keyboard::De, Typed::plain('é'), Purpose::Text),
            Some('é')
        );
        assert_eq!(
            remap(Keyboard::De, Typed::plain('\u{7}'), Purpose::Text),
            None
        );
    }
}
