//! Keys from a serial console's bytes (INTERFACES.md §13.2a: input is
//! accepted from every console at once).
//!
//! While the graphical front end mirrors the text UI to a serial port, the
//! loader owns that port and decodes what the terminal sends itself: UTF-8
//! text, control characters, and the escape sequences of the terminal types
//! firmware console redirection uses — ANSI/VT100/xterm (`ESC [ … `,
//! `ESC O …`), the Linux console's `ESC [ [ A`, and EDK2's "VT100+"
//! (`ESC h`, `ESC +`, `ESC 2`…).
//!
//! The bytes come from whatever is on the other end of the cable, so this
//! is a parser of external data: a fixed 8-byte state, every byte either
//! completes a key, extends a bounded pending sequence or is dropped, and
//! nothing can panic (fuzzed by `fuzz/fuzz_targets/vt100.rs`). A lone
//! `ESC` is ambiguous until the line goes quiet: the caller reports that
//! with [`Decoder::idle`].

use crate::ui::Key;

/// The longest sequence kept; anything longer is dropped whole.
pub const MAX_PENDING: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoder {
    buf: [u8; MAX_PENDING],
    n: usize,
    /// The previous byte was CR: a following LF is the same Enter.
    after_cr: bool,
    /// Inside an over-long sequence: drop bytes up to its final byte.
    discard: bool,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

/// What a pending sequence is so far.
enum Seq {
    /// Needs more bytes.
    More,
    /// A complete key.
    Key(Key),
    /// Complete but meaningless (modifiers, unknown finals): drop it.
    Drop,
}

const ESC: u8 = 0x1b;

/// `ESC [ … ~` parameters: Home, Insert, Delete, End, PageUp, PageDown and
/// the function keys (xterm/VT220 numbering).
fn tilde(n: u32) -> Option<Key> {
    Some(match n {
        1 | 7 => Key::Home,
        2 => Key::Insert,
        3 => Key::Delete,
        4 | 8 => Key::End,
        5 => Key::PageUp,
        6 => Key::PageDown,
        11..=15 => Key::Function((n - 10) as u8),
        17..=21 => Key::Function((n - 11) as u8),
        23 | 24 => Key::Function((n - 12) as u8),
        _ => return None,
    })
}

/// Cursor and editing keys by their final letter (`ESC [ A`, `ESC O A`).
fn letter(b: u8) -> Option<Key> {
    Some(match b {
        b'A' => Key::Up,
        b'B' => Key::Down,
        b'C' => Key::Right,
        b'D' => Key::Left,
        b'H' => Key::Home,
        b'F' => Key::End,
        _ => return None,
    })
}

/// EDK2's VT100+ keys: `ESC` and one character.
fn vt100_plus(b: u8) -> Option<Key> {
    Some(match b {
        b'1'..=b'9' => Key::Function(b - b'0'),
        b'0' => Key::Function(10),
        b'!' => Key::Function(11),
        b'@' => Key::Function(12),
        b'h' => Key::Home,
        b'k' => Key::End,
        b'+' => Key::Insert,
        b'-' => Key::Delete,
        b'?' => Key::PageUp,
        b'/' => Key::PageDown,
        _ => return None,
    })
}

/// Classify `seq` (which starts with ESC).
fn classify(seq: &[u8]) -> Seq {
    match seq {
        [ESC] => Seq::More,
        [ESC, b'[' | b'O'] => Seq::More,
        [ESC, b] => vt100_plus(*b).map_or(Seq::Drop, Seq::Key),
        // SS3: application cursor keys and F1–F4.
        [ESC, b'O', b] => match b {
            b'P'..=b'S' => Seq::Key(Key::Function(b - b'P' + 1)),
            _ => letter(*b).map_or(Seq::Drop, Seq::Key),
        },
        // The Linux console's F1–F5.
        [ESC, b'[', b'['] => Seq::More,
        [ESC, b'[', b'[', b] => match b {
            b'A'..=b'E' => Seq::Key(Key::Function(b - b'A' + 1)),
            _ => Seq::Drop,
        },
        [ESC, b'[', rest @ ..] => {
            let Some((&last, params)) = rest.split_last() else {
                return Seq::More;
            };
            match last {
                // Parameter and intermediate bytes.
                0x20..=0x3f => Seq::More,
                0x40..=0x7e => {
                    // Private parameters or intermediates: not a key.
                    if params.iter().any(|&c| !(c.is_ascii_digit() || c == b';')) {
                        return Seq::Drop;
                    }
                    // The first parameter; modifiers after `;` are ignored
                    // (a Ctrl+arrow is still an arrow).
                    let first = params.split(|&c| c == b';').next().unwrap_or(&[]);
                    let mut n = 0u32;
                    for &d in first {
                        n = n
                            .saturating_mul(10)
                            .saturating_add(u32::from(d.wrapping_sub(b'0')));
                    }
                    let key = match last {
                        b'~' => tilde(n),
                        // `ESC [ 1 ; 5 A`: the parameter is a count or 1.
                        _ => letter(last),
                    };
                    key.map_or(Seq::Drop, Seq::Key)
                }
                _ => Seq::Drop,
            }
        }
        _ => Seq::Drop,
    }
}

impl Decoder {
    pub const fn new() -> Decoder {
        Decoder {
            buf: [0; MAX_PENDING],
            n: 0,
            after_cr: false,
            discard: false,
        }
    }

    /// Whether bytes are waiting for the rest of a sequence (the caller
    /// then reports a quiet line with [`Decoder::idle`]).
    pub const fn pending(&self) -> bool {
        self.n > 0
    }

    fn reset(&mut self) {
        self.buf = [0; MAX_PENDING];
        self.n = 0;
    }

    /// The line has been quiet since the last byte: a lone ESC was the Esc
    /// key; any other unfinished sequence is dropped.
    pub fn idle(&mut self) -> Option<Key> {
        let lone_esc = self.n == 1 && self.buf.first() == Some(&ESC);
        self.reset();
        self.discard = false;
        self.after_cr = false;
        lone_esc.then_some(Key::Escape)
    }

    /// One byte from the line. `Some` when it completes a key.
    pub fn feed(&mut self, b: u8) -> Option<Key> {
        let after_cr = core::mem::replace(&mut self.after_cr, b == b'\r');
        if self.discard {
            // An over-long CSI ends at its final byte.
            if (0x40..=0x7e).contains(&b) {
                self.discard = false;
            }
            return None;
        }
        if self.n == 0 {
            return match b {
                ESC => {
                    self.push(b);
                    None
                }
                b'\r' => Some(Key::Enter),
                b'\n' if after_cr => None,
                b'\n' => Some(Key::Enter),
                0x08 | 0x7f => Some(Key::Backspace),
                0x20..=0x7e => Some(Key::Char(char::from(b))),
                // UTF-8 lead bytes of 2, 3 and 4-byte sequences.
                0xc2..=0xf4 => {
                    self.push(b);
                    None
                }
                // Other control characters, stray continuation bytes.
                _ => None,
            };
        }
        if self.buf.first() == Some(&ESC) {
            if b == ESC && self.n == 1 {
                // ESC ESC: the first was the Esc key; the second may start
                // a sequence.
                return Some(Key::Escape);
            }
            if b == ESC {
                // A new sequence interrupts an unfinished one.
                self.reset();
                self.push(b);
                return None;
            }
            if !self.push(b) {
                self.reset();
                self.discard = !(0x40..=0x7e).contains(&b);
                return None;
            }
            let seq = self.buf.get(..self.n).unwrap_or(&[]);
            return match classify(seq) {
                Seq::More if self.n < MAX_PENDING => None,
                Seq::More => {
                    // Full and still unfinished: drop it and the rest.
                    self.reset();
                    self.discard = true;
                    None
                }
                Seq::Key(k) => {
                    self.reset();
                    Some(k)
                }
                Seq::Drop => {
                    self.reset();
                    None
                }
            };
        }
        // A UTF-8 sequence in progress.
        if b & 0xc0 != 0x80 {
            // Not a continuation: drop what we had and start over.
            self.reset();
            return self.feed(b);
        }
        self.push(b);
        let seq = self.buf.get(..self.n).unwrap_or(&[]);
        let want = match seq.first() {
            Some(0xc2..=0xdf) => 2,
            Some(0xe0..=0xef) => 3,
            _ => 4,
        };
        if self.n < want {
            return None;
        }
        let key = core::str::from_utf8(seq)
            .ok()
            .and_then(|s| s.chars().next())
            .filter(|c| !c.is_control())
            .map(Key::Char);
        self.reset();
        key
    }

    fn push(&mut self, b: u8) -> bool {
        match self.buf.get_mut(self.n) {
            Some(slot) => {
                *slot = b;
                self.n += 1;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn keys(bytes: &[u8]) -> Vec<Key> {
        let mut d = Decoder::new();
        let mut out: Vec<Key> = bytes.iter().filter_map(|&b| d.feed(b)).collect();
        out.extend(d.idle());
        out
    }

    #[test]
    fn text_and_controls() {
        assert_eq!(
            keys(b"ab 1\r"),
            [
                Key::Char('a'),
                Key::Char('b'),
                Key::Char(' '),
                Key::Char('1'),
                Key::Enter
            ]
        );
        assert_eq!(keys(b"\r\n"), [Key::Enter], "CRLF is one Enter");
        assert_eq!(keys(b"\n\n"), [Key::Enter, Key::Enter]);
        assert_eq!(keys(b"\r\r"), [Key::Enter, Key::Enter]);
        assert_eq!(keys(b"\x7f\x08"), [Key::Backspace, Key::Backspace]);
        assert_eq!(
            keys(b"\t\x00\x03\x80\xbf"),
            [],
            "other controls are dropped"
        );
        assert_eq!(
            keys("é€😀".as_bytes()),
            [Key::Char('é'), Key::Char('€'), Key::Char('😀')]
        );
        assert_eq!(
            keys(b"\xc3a"),
            [Key::Char('a')],
            "a broken UTF-8 lead is dropped"
        );
        assert_eq!(keys(b"\xc2\x85"), [], "C1 controls are not text");
        assert_eq!(keys(b"\xed\xa0\x80"), [], "no surrogates");
        assert_eq!(keys(b"\xc3"), [], "unfinished at idle: dropped");
    }

    #[test]
    fn escape_sequences() {
        let cases: &[(&[u8], Key)] = &[
            (b"\x1b[A", Key::Up),
            (b"\x1b[B", Key::Down),
            (b"\x1b[C", Key::Right),
            (b"\x1b[D", Key::Left),
            (b"\x1bOA", Key::Up),
            (b"\x1bOD", Key::Left),
            (b"\x1b[H", Key::Home),
            (b"\x1b[F", Key::End),
            (b"\x1bOH", Key::Home),
            (b"\x1bOF", Key::End),
            (b"\x1b[1~", Key::Home),
            (b"\x1b[7~", Key::Home),
            (b"\x1b[2~", Key::Insert),
            (b"\x1b[3~", Key::Delete),
            (b"\x1b[4~", Key::End),
            (b"\x1b[8~", Key::End),
            (b"\x1b[5~", Key::PageUp),
            (b"\x1b[6~", Key::PageDown),
            (b"\x1bOP", Key::Function(1)),
            (b"\x1bOQ", Key::Function(2)),
            (b"\x1bOR", Key::Function(3)),
            (b"\x1bOS", Key::Function(4)),
            (b"\x1b[11~", Key::Function(1)),
            (b"\x1b[12~", Key::Function(2)),
            (b"\x1b[13~", Key::Function(3)),
            (b"\x1b[15~", Key::Function(5)),
            (b"\x1b[17~", Key::Function(6)),
            (b"\x1b[21~", Key::Function(10)),
            (b"\x1b[24~", Key::Function(12)),
            (b"\x1b[[A", Key::Function(1)),
            (b"\x1b[[C", Key::Function(3)),
            (b"\x1b[1;5A", Key::Up),
            (b"\x1b[3;2~", Key::Delete),
            // EDK2 VT100+.
            (b"\x1bh", Key::Home),
            (b"\x1bk", Key::End),
            (b"\x1b+", Key::Insert),
            (b"\x1b-", Key::Delete),
            (b"\x1b?", Key::PageUp),
            (b"\x1b/", Key::PageDown),
            (b"\x1b2", Key::Function(2)),
            (b"\x1b3", Key::Function(3)),
            (b"\x1b0", Key::Function(10)),
        ];
        for (seq, k) in cases {
            assert_eq!(keys(seq), [*k], "{seq:?}");
            // And in the middle of text.
            let mut s = b"x".to_vec();
            s.extend_from_slice(seq);
            s.push(b'y');
            assert_eq!(keys(&s), [Key::Char('x'), *k, Key::Char('y')], "{seq:?}");
        }
    }

    #[test]
    fn lone_escape_needs_a_quiet_line() {
        let mut d = Decoder::new();
        assert_eq!(d.feed(ESC), None);
        assert!(d.pending());
        assert_eq!(d.idle(), Some(Key::Escape));
        assert!(!d.pending());
        assert_eq!(d.idle(), None);
        assert_eq!(keys(b"\x1b\x1b[A"), [Key::Escape, Key::Up]);
        assert_eq!(keys(b"\x1b\x1b"), [Key::Escape, Key::Escape]);
        // An unfinished sequence at idle is not Esc.
        assert_eq!(keys(b"\x1b["), []);
        assert_eq!(keys(b"\x1b[1"), []);
        assert_eq!(keys(b"\x1bO"), []);
    }

    #[test]
    fn unknown_and_hostile_sequences_are_dropped() {
        assert_eq!(keys(b"\x1b[Za"), [Key::Char('a')], "Shift+Tab");
        assert_eq!(keys(b"\x1b[99~a"), [Key::Char('a')]);
        assert_eq!(keys(b"\x1bxa"), [Key::Char('a')], "Alt+x is not text");
        assert_eq!(keys(b"\x1bOxa"), [Key::Char('a')]);
        assert_eq!(keys(b"\x1b[[Za"), [Key::Char('a')]);
        assert_eq!(keys(b"\x1b[?25ha"), [Key::Char('a')], "private parameters");
        assert_eq!(keys(b"\x1b[1$~a"), [Key::Char('a')]);
        // Over-long: dropped up to its final byte, then decoding resumes.
        assert_eq!(keys(b"\x1b[1111111111111111~a"), [Key::Char('a')]);
        assert_eq!(keys(b"\x1b[;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;A\x1b[B"), [Key::Down]);
        assert_eq!(keys(b"\x1b[4294967296~a"), [Key::Char('a')], "no overflow");
        // A sequence interrupted by another.
        assert_eq!(keys(b"\x1b[1\x1b[A"), [Key::Up]);
    }

    #[test]
    fn state_stays_bounded() {
        let mut d = Decoder::new();
        for i in 0..100_000u32 {
            let _ = d.feed((i.wrapping_mul(2654435761) >> 24) as u8);
            assert!(d.n <= MAX_PENDING);
        }
        let _ = d.idle();
        assert_eq!(d, Decoder::new());
    }
}
