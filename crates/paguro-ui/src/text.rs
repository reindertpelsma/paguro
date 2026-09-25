//! Measuring, fitting and wrapping text with a pre-rasterised [`Font`].
//! Widths are ink-accurate on the right (a glyph whose bitmap overhangs its
//! advance counts), so fitted text never spills out of its box.

use crate::theme::{Font, SUBPX, SUBPX_SHIFT};

/// A guard against a wrap that makes no progress (it always does).
const MAX_LINES: usize = 1000;

/// A running measurement: push characters, read the width so far.
#[derive(Clone, Copy)]
pub struct Measure<'f> {
    font: &'f Font,
    pen: i64,
    left: i64,
    right: i64,
}

impl<'f> Measure<'f> {
    pub fn new(font: &'f Font) -> Self {
        Measure {
            font,
            pen: 0,
            left: 0,
            right: 0,
        }
    }
    pub fn push(&mut self, c: char) {
        let Some(g) = self.font.glyph_or_fallback(c) else {
            return;
        };
        let gx = ((self.pen + SUBPX / 2) >> SUBPX_SHIFT) + i64::from(g.x);
        if g.w > 0 {
            self.left = self.left.min(gx);
            self.right = self.right.max(gx + i64::from(g.w));
        }
        self.pen += i64::from(g.adv);
        self.right = self.right.max((self.pen + SUBPX - 1) >> SUBPX_SHIFT);
    }
    /// Width with `c` appended, without appending it.
    pub fn with(&self, c: char) -> i32 {
        let mut m = *self;
        m.push(c);
        m.width()
    }
    pub fn width(&self) -> i32 {
        i32::try_from(self.right - self.left).unwrap_or(i32::MAX)
    }
    /// Left overhang (≤ 0).
    pub fn left(&self) -> i32 {
        i32::try_from(self.left).unwrap_or(0)
    }
}

/// Horizontal extent of `s` drawn with the pen at 0: `(left, right)` in
/// pixels, `left` ≤ 0.
pub fn extent(font: &Font, s: impl Iterator<Item = char>) -> (i32, i32) {
    let mut m = Measure::new(font);
    for c in s {
        m.push(c);
    }
    (
        i32::try_from(m.left).unwrap_or(i32::MIN),
        i32::try_from(m.right).unwrap_or(i32::MAX),
    )
}

/// Width in pixels (ink and advance), counting left overhang.
pub fn width(font: &Font, s: &str) -> i32 {
    let (l, r) = extent(font, s.chars());
    r.saturating_sub(l)
}

pub fn char_width(font: &Font, c: char) -> i32 {
    let (l, r) = extent(font, core::iter::once(c));
    r.saturating_sub(l)
}

/// How much of `s` fits in `max` pixels: the byte length of the prefix and
/// whether an ellipsis must follow it (the prefix then leaves room for it).
pub fn fit(font: &Font, s: &str, max: i32, ellipsis: char) -> (usize, bool) {
    if width(font, s) <= max {
        return (s.len(), false);
    }
    let mut m = Measure::new(font);
    let mut best = 0usize;
    for (i, c) in s.char_indices() {
        let mut next = m;
        next.push(c);
        if next.with(ellipsis) > max {
            break;
        }
        m = next;
        best = i + c.len_utf8();
    }
    // No dangling space before the ellipsis.
    let trimmed = s.get(..best).unwrap_or("").trim_end().len();
    (trimmed, true)
}

/// Same as [`fit`] for `n` copies of `c`: how many fit (with an ellipsis
/// when not all do).
pub fn fit_repeat(font: &Font, c: char, n: usize, max: i32, ellipsis: char) -> (usize, bool) {
    let one = font.glyph_or_fallback(c).map_or(0, |g| i64::from(g.adv));
    let total = |k: usize| {
        let (l, r) = extent(font, core::iter::repeat_n(c, k));
        r.saturating_sub(l)
    };
    if total(n) <= max {
        return (n, false);
    }
    let room = i64::from(max.saturating_sub(char_width(font, ellipsis)));
    let mut k = if one > 0 {
        usize::try_from((room * SUBPX / one).max(0))
            .unwrap_or(0)
            .min(n)
    } else {
        0
    };
    while k > 0 && i64::from(total(k)) > room {
        k -= 1;
    }
    (k, true)
}

/// Greedy word wrap: the next line of `s` that fits in `max` pixels, and
/// the rest. A word longer than the line is broken at a character.
pub fn next_line<'s>(font: &Font, s: &'s str, max: i32) -> (&'s str, &'s str) {
    let s = s.trim_start_matches(' ');
    if s.is_empty() {
        return ("", "");
    }
    if width(font, s) <= max {
        return (s, "");
    }
    let mut last_break = None;
    let mut fit_end = 0usize;
    let mut m = Measure::new(font);
    for (i, c) in s.char_indices() {
        if c == ' ' {
            last_break = Some(i);
        }
        m.push(c);
        if m.width() > max {
            break;
        }
        fit_end = i + c.len_utf8();
    }
    let cut = match last_break {
        Some(b) if b > 0 && b <= fit_end => b,
        // No space in reach: break the word (at least one character, so
        // wrapping always makes progress).
        _ => fit_end.max(s.chars().next().map_or(0, char::len_utf8)),
    };
    let line = s.get(..cut).unwrap_or("").trim_end();
    (line, s.get(cut..).unwrap_or(""))
}

/// Lines `s` wraps to in `max` pixels.
pub fn count_lines(font: &Font, s: &str, max: i32) -> usize {
    let mut n = 0;
    let mut rest = s;
    while !rest.trim_start_matches(' ').is_empty() {
        let (_, r) = next_line(font, rest, max);
        rest = r;
        n += 1;
        if n > MAX_LINES {
            break;
        }
    }
    n
}

/// How much of the *end* of `s` fits in `max` pixels after a leading
/// ellipsis: the byte offset where the shown tail starts (0: all of it
/// fits, no ellipsis). For paths, whose end matters most.
pub fn fit_tail(font: &Font, s: &str, max: i32, ellipsis: char) -> usize {
    if width(font, s) <= max {
        return 0;
    }
    let room = max.saturating_sub(char_width(font, ellipsis));
    let snap = |mut i: usize| {
        while i < s.len() && !s.is_char_boundary(i) {
            i += 1;
        }
        i
    };
    // The shown width only grows as the start moves left: bisect.
    let (mut lo, mut hi) = (0usize, s.len());
    while lo < hi {
        let mut mid = snap(lo + (hi - lo) / 2);
        if mid >= hi {
            // `lo` is a character boundary: test it.
            mid = lo;
        }
        if width(font, s.get(mid..).unwrap_or("")) <= room {
            hi = mid;
        } else {
            lo = snap(mid + 1);
        }
    }
    hi
}
