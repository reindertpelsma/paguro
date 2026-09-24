//! The draw list: what a screen looks like, as rectangles, image blits and
//! text runs with the boxes they were fitted to. The layout builds it (pure,
//! testable: the layout-invariant properties read it), then [`paint`]
//! rasterises it into a [`Canvas`]. Fixed capacity, no allocation.

use core::fmt;

use crate::canvas::{Canvas, Rect};
use crate::text;
use crate::theme::{Color, Font, Image};

pub const MAX_CMDS: usize = 224;
pub const ARENA: usize = 4096;

/// Where a text run's characters come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextSrc<'a> {
    /// Borrowed: a label from the screen, the typed text, a theme string.
    Str(&'a str),
    /// `n` copies of one character (bullets).
    Repeat(char, usize),
    /// Composed at layout time into the list's arena (templates with
    /// arguments).
    Arena { start: u16, len: u16 },
}

/// A text run. Its ink never leaves `bounds` (the layout fitted it, with
/// an ellipsis when cut), and painting clips to `bounds` as well.
#[derive(Clone, Copy, Debug)]
pub struct TextRun<'a> {
    /// Pen start and baseline.
    pub x: i32,
    pub baseline: i32,
    pub font: &'static Font,
    pub color: Color,
    pub src: TextSrc<'a>,
    /// Drawn after the text when it was cut.
    pub ellipsis: Option<char>,
    pub bounds: Rect,
}

#[derive(Clone, Copy, Debug)]
pub enum Cmd<'a> {
    Nop,
    Fill {
        r: Rect,
        radius: i32,
        color: Color,
    },
    Stroke {
        r: Rect,
        radius: i32,
        width: i32,
        color: Color,
    },
    Image {
        img: &'static Image,
        x: i32,
        y: i32,
    },
    Text(TextRun<'a>),
}

pub struct DrawList<'a> {
    cmds: [Cmd<'a>; MAX_CMDS],
    n: usize,
    arena: [u8; ARENA],
    used: usize,
    /// Commands that did not fit (a layout bug; tests assert zero).
    pub dropped: usize,
    /// The frame's size.
    pub width: u32,
    pub height: u32,
}

impl<'a> DrawList<'a> {
    pub const fn new() -> Self {
        DrawList {
            cmds: [Cmd::Nop; MAX_CMDS],
            n: 0,
            arena: [0; ARENA],
            used: 0,
            dropped: 0,
            width: 0,
            height: 0,
        }
    }

    pub fn clear(&mut self, width: u32, height: u32) {
        self.n = 0;
        self.used = 0;
        self.dropped = 0;
        self.width = width;
        self.height = height;
        // The arena may have held typed text composed into a template.
        self.arena.fill(0);
    }

    pub fn push(&mut self, c: Cmd<'a>) {
        match self.cmds.get_mut(self.n) {
            Some(slot) => {
                *slot = c;
                self.n += 1;
            }
            None => self.dropped += 1,
        }
    }

    pub fn cmds(&self) -> &[Cmd<'a>] {
        self.cmds.get(..self.n).unwrap_or(&[])
    }

    /// Start composing text into the arena.
    pub fn compose(&mut self) -> Composer<'_, 'a> {
        let start = self.used;
        Composer { list: self, start }
    }

    /// The characters of `src` (without the ellipsis).
    pub fn chars(&self, src: &TextSrc<'a>) -> Chars<'_> {
        match *src {
            TextSrc::Str(s) => Chars::Str(s.chars()),
            TextSrc::Repeat(c, n) => Chars::Repeat(c, n),
            TextSrc::Arena { start, len } => Chars::Str(self.arena_str(start, len).chars()),
        }
    }

    fn arena_str(&self, start: u16, len: u16) -> &str {
        let (s, l) = (usize::from(start), usize::from(len));
        core::str::from_utf8(self.arena.get(s..s + l).unwrap_or(&[])).unwrap_or("")
    }

    /// `src` as a string slice (`None` for a repeat).
    pub fn as_str(&self, src: &TextSrc<'a>) -> Option<&str> {
        match *src {
            TextSrc::Str(s) => Some(s),
            TextSrc::Repeat(..) => None,
            TextSrc::Arena { start, len } => Some(self.arena_str(start, len)),
        }
    }

    /// The first `bytes` of `src` (or `count` repeats).
    pub fn prefix(&self, src: &TextSrc<'a>, bytes: usize) -> TextSrc<'a> {
        match *src {
            TextSrc::Str(s) => TextSrc::Str(s.get(..bytes).unwrap_or(s)),
            TextSrc::Repeat(c, n) => TextSrc::Repeat(c, bytes.min(n)),
            TextSrc::Arena { start, len } => TextSrc::Arena {
                start,
                len: u16::try_from(bytes).unwrap_or(len).min(len),
            },
        }
    }

    /// Bytes `from..` of `src` (a repeat drops `from` copies).
    pub fn suffix(&self, src: &TextSrc<'a>, from: usize) -> TextSrc<'a> {
        match *src {
            TextSrc::Str(s) => TextSrc::Str(s.get(from..).unwrap_or("")),
            TextSrc::Repeat(c, n) => TextSrc::Repeat(c, n.saturating_sub(from)),
            TextSrc::Arena { start, len } => {
                let f = u16::try_from(from).unwrap_or(len).min(len);
                TextSrc::Arena {
                    start: start + f,
                    len: len - f,
                }
            }
        }
    }

    /// The ink rectangle of a run as painted (before clipping).
    pub fn ink(&self, t: &TextRun<'a>) -> Rect {
        let (l, r) = text::extent(t.font, self.chars(&t.src).chain(t.ellipsis));
        Rect::new(
            t.x.saturating_add(l),
            t.baseline.saturating_sub(t.font.ascent),
            r.saturating_sub(l),
            t.font.ascent.saturating_sub(t.font.descent),
        )
    }
}

impl Default for DrawList<'_> {
    fn default() -> Self {
        Self::new()
    }
}

pub enum Chars<'s> {
    Str(core::str::Chars<'s>),
    Repeat(char, usize),
}

impl Iterator for Chars<'_> {
    type Item = char;
    fn next(&mut self) -> Option<char> {
        match self {
            Chars::Str(c) => c.next(),
            Chars::Repeat(c, n) => {
                if *n == 0 {
                    None
                } else {
                    *n -= 1;
                    Some(*c)
                }
            }
        }
    }
}

/// Writes into the arena; text past its end is dropped at a character
/// boundary.
pub struct Composer<'l, 'a> {
    list: &'l mut DrawList<'a>,
    start: usize,
}

impl<'a> Composer<'_, 'a> {
    pub fn finish(self) -> TextSrc<'a> {
        TextSrc::Arena {
            start: u16::try_from(self.start).unwrap_or(0),
            len: u16::try_from(self.list.used - self.start).unwrap_or(0),
        }
    }
}

impl fmt::Write for Composer<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for c in s.chars() {
            let mut b = [0u8; 4];
            let e = c.encode_utf8(&mut b).as_bytes();
            let at = self.list.used;
            match self.list.arena.get_mut(at..at + e.len()) {
                Some(dst) => {
                    dst.copy_from_slice(e);
                    self.list.used += e.len();
                }
                None => return Ok(()),
            }
        }
        Ok(())
    }
}

/// Rasterise `list` into `canvas`, in order.
pub fn paint(list: &DrawList<'_>, canvas: &mut Canvas<'_>) {
    let all = canvas.bounds();
    for c in list.cmds() {
        match *c {
            Cmd::Nop => {}
            Cmd::Fill { r, radius, color } => canvas.round_rect(r, radius, color, all),
            Cmd::Stroke {
                r,
                radius,
                width,
                color,
            } => canvas.round_stroke(r, radius, width, color, all),
            Cmd::Image { img, x, y } => canvas.blit(img, x, y, all),
            Cmd::Text(t) => {
                canvas.text(
                    t.font,
                    t.x,
                    t.baseline,
                    list.chars(&t.src).chain(t.ellipsis),
                    t.color,
                    t.bounds,
                );
            }
        }
    }
}
