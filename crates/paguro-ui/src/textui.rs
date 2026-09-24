//! The text UI (INTERFACES.md §13.2a "Text mode"): the same screens as the
//! graphical front end — same strings from the compiled-in theme, same
//! blocks in the same order, same list and field state — laid out on an
//! 80×24 character grid instead of pixels.
//!
//! One grid, three ways out:
//! - [`write_vt100`]: a serial console (the mirror in `auto` mode), with
//!   VT100 cursor addressing and SGR attributes, redrawing only the rows
//!   that changed;
//! - [`conout_attr`]: the colours the firmware text console (ConOut) uses
//!   for each [`Tone`] — the adapter writes the rows through ConOut;
//! - [`paint_grid`]: onto a canvas, in the theme's colours and its field
//!   font set in fixed cells, for a display that ConOut does not cover.
//!
//! Typographic characters the theme strings use (dashes, ellipsis, arrows,
//! bullets, curly quotes) are written as ASCII so every terminal and the
//! firmware's console font can show them; Latin-1 passes through.

use core::fmt::{self, Write};

use paguro_boot::platform::{Row, Screen};
use paguro_boot::ui::{self, Field, FieldKind, Item, RECOVERY_DIGITS, RECOVERY_GROUP};

use crate::canvas::{Canvas, Rect};
use crate::draw::{DrawList, TextSrc};
use crate::layout::{self, Block, BlockKind, Rows, View, compose};
use crate::strings::Str;
use crate::text;
use crate::theme::{Color, Style, Theme};

pub const COLS: usize = 80;
pub const ROWS: usize = 24;
/// Left margin of the content column, and its width.
const INDENT: usize = 3;
const WIDTH: usize = COLS - 2 * INDENT;
/// Rows the list shows at most (the browser's limit in graphics too).
const LIST_MAX: usize = layout::BROWSER_ROWS;

/// How a cell is shown. Serial terminals get bold/dim/reverse video,
/// ConOut its 16 colours, a canvas the theme's palette.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Tone {
    #[default]
    Normal,
    /// Titles, the name, key caps.
    Strong,
    Muted,
    /// Greyed rows.
    Faint,
    /// The highlighted list row.
    Selected,
    /// "Unattested".
    Banner,
    /// "That did not unlock…".
    Toast,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub tone: Tone,
}

const BLANK: Cell = Cell {
    ch: ' ',
    tone: Tone::Normal,
};

/// One text-mode frame.
#[derive(Clone, PartialEq, Eq)]
pub struct Grid {
    cells: [Cell; COLS * ROWS],
    /// Where the text cursor is shown (the field's cursor), `(row, col)`.
    pub cursor: Option<(u8, u8)>,
}

impl Default for Grid {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Grid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for r in 0..ROWS {
            for c in self.row(r) {
                f.write_char(c.ch)?;
            }
            f.write_char('\n')?;
        }
        Ok(())
    }
}

impl Grid {
    pub const fn new() -> Grid {
        Grid {
            cells: [BLANK; COLS * ROWS],
            cursor: None,
        }
    }

    pub fn clear(&mut self) {
        self.cells = [BLANK; COLS * ROWS];
        self.cursor = None;
    }

    pub fn row(&self, r: usize) -> &[Cell] {
        self.cells.get(r * COLS..(r + 1) * COLS).unwrap_or(&[])
    }

    fn cell_mut(&mut self, r: usize, c: usize) -> Option<&mut Cell> {
        if c >= COLS {
            return None;
        }
        self.cells.get_mut(r * COLS + c)
    }

    /// Paint `tone` over `cols` of row `r` (a selection bar).
    fn fill(&mut self, r: usize, cols: core::ops::Range<usize>, tone: Tone) {
        for c in cols {
            if let Some(cell) = self.cell_mut(r, c) {
                cell.tone = tone;
            }
        }
    }

    /// Write `s` from column `c`, cut at `end`; returns the column after it.
    fn put(&mut self, r: usize, c: usize, s: &[char], tone: Tone, end: usize) -> usize {
        let mut c = c;
        for &ch in s {
            if c >= end.min(COLS) {
                break;
            }
            if let Some(cell) = self.cell_mut(r, c) {
                *cell = Cell { ch, tone };
            }
            c += 1;
        }
        c
    }

    /// Row `r` as a string, trailing blanks removed (tests, logs).
    pub fn line(&self, r: usize, out: &mut impl Write) -> fmt::Result {
        let row = self.row(r);
        let end = row.iter().rposition(|c| c.ch != ' ').map_or(0, |i| i + 1);
        for c in row.get(..end).unwrap_or(&[]) {
            out.write_char(c.ch)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Plain text

/// A bounded run of characters, after transliteration.
struct Chars {
    buf: [char; 640],
    n: usize,
}

impl Chars {
    const fn new() -> Chars {
        Chars {
            buf: [' '; 640],
            n: 0,
        }
    }
    fn as_slice(&self) -> &[char] {
        self.buf.get(..self.n).unwrap_or(&[])
    }
    fn push(&mut self, c: char) {
        if let Some(slot) = self.buf.get_mut(self.n) {
            *slot = c;
            self.n += 1;
        }
    }
    fn push_str(&mut self, s: &str) {
        for c in s.chars() {
            plain(c, |p| self.push(p));
        }
    }
}

/// `c` as characters any console shows: typographic punctuation and arrows
/// as ASCII, controls dropped, everything else as is.
pub fn plain(c: char, mut out: impl FnMut(char)) {
    let s: &str = match c {
        '\u{2014}' => "--",
        '\u{2013}' | '\u{2212}' => "-",
        '\u{2026}' => "...",
        '\u{2018}' | '\u{2019}' => "'",
        '\u{201c}' | '\u{201d}' | '\u{00ab}' | '\u{00bb}' => "\"",
        '\u{2022}' => "*",
        '\u{00b7}' => "-",
        '\u{2191}' => "Up",
        '\u{2193}' => "Down",
        '\u{2190}' => "Left",
        '\u{2192}' => "Right",
        '\u{00a0}' | '\u{202f}' => " ",
        c if c.is_control() => "",
        c => {
            out(c);
            return;
        }
    };
    s.chars().for_each(out);
}

/// A theme string, composed and made plain.
fn tr<'a>(list: &mut DrawList<'a>, theme: &Theme, s: Str) -> Chars {
    let src = compose(list, theme, s, &[], 0);
    chars_of(list, &src)
}

fn chars_of(list: &DrawList<'_>, src: &TextSrc<'_>) -> Chars {
    let mut c = Chars::new();
    for ch in list.chars(src) {
        plain(ch, |p| c.push(p));
    }
    c
}

/// Word-wrap `s` to `w` columns: the next line and where the rest starts.
fn next_line(s: &[char], w: usize) -> (usize, usize) {
    let s_len = s.len();
    if s_len <= w {
        return (s_len, s_len);
    }
    // The last space within the width (or a hard break).
    let cut = s
        .get(..=w)
        .and_then(|p| p.iter().rposition(|&c| c == ' '))
        .filter(|&i| i > 0)
        .unwrap_or(w);
    let mut rest = cut;
    while s.get(rest) == Some(&' ') {
        rest += 1;
    }
    (cut, rest)
}

fn count_lines(s: &[char], w: usize) -> usize {
    let mut n = 0;
    let mut at = 0;
    while at < s.len() {
        let (len, rest) = next_line(s.get(at..).unwrap_or(&[]), w);
        n += 1;
        if rest == 0 {
            break;
        }
        at += rest;
        let _ = len;
    }
    n.max(1)
}

// ---------------------------------------------------------------------------
// Layout

/// What differs between the places the text UI is shown.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Opts {
    /// The F3 hint's label: `HintGraphics` on the local display in text
    /// mode, `None` on a serial mirror (F3 acts on the local display).
    pub mode_hint: Option<Str>,
}

fn tone_of(theme: &Theme, c: Color) -> Tone {
    let p = &theme.palette;
    if c == p.faint {
        Tone::Faint
    } else if c == p.muted && c != p.text {
        Tone::Muted
    } else {
        Tone::Normal
    }
}

/// The digit that picks list row `i` directly on this screen
/// ([`ui::map_key`]), if any.
fn row_digit(screen: &Screen, item: Option<Item>, i: usize) -> Option<char> {
    let d = match (screen, item?) {
        (Screen::Unlock(_), Item::Unlock { row, .. }) => match row {
            Row::PasswordOrPin => 1,
            Row::RecoveryPassphrase => 2,
            Row::RecoveryKey => 3,
        },
        (Screen::SelectVolume(_), _) if i < 9 => i + 1,
        (Screen::DiskStart { .. }, _) if i < 3 => i + 1,
        _ => return None,
    };
    char::from_digit(d as u32, 10)
}

fn gap_before(prev: Option<BlockKind>, kind: BlockKind) -> usize {
    match (prev, kind) {
        (None, _) => 0,
        (Some(BlockKind::Title), BlockKind::Crumb | BlockKind::Name) => 0,
        (Some(BlockKind::Label), BlockKind::Field) => 0,
        (Some(BlockKind::Crumb), BlockKind::List) => 0,
        _ => 1,
    }
}

/// Lay out `screen` into `grid`. Returns the rows the list shows at once
/// (PageUp/PageDown in the browser).
pub fn render<'a>(
    screen: &'a Screen,
    view: &View<'a>,
    theme: &Theme,
    opts: &Opts,
    list: &mut DrawList<'a>,
    grid: &mut Grid,
) -> usize {
    grid.clear();
    list.clear(COLS as u32, ROWS as u32);
    let spec = layout::describe(screen, view, theme, list);
    let rows = Rows::of(screen, view);
    let n_rows = rows.len();

    // The name, and "Unattested" under it.
    let brand = tr(list, theme, Str::Brand);
    grid.put(0, 1, brand.as_slice(), Tone::Strong, COLS);
    let mut top = 2;
    if spec.unattested {
        let b = tr(list, theme, Str::Unattested);
        let mut line = Chars::new();
        line.push_str(" ! ");
        for &c in b.as_slice() {
            line.push(c);
        }
        line.push(' ');
        let end = grid.put(1, INDENT - 1, line.as_slice(), Tone::Banner, COLS - 1);
        let _ = end;
        top = 3;
    }

    // Key hints on the last row: [key] label, dropped from the end until
    // they fit. F2 changes nothing in text; F3 only where it acts.
    // Up to two lines of hints at the bottom.
    let lines_used: usize;
    {
        let mut all: [Option<(Str, Str)>; layout::MAX_HINTS + 1] = [None; layout::MAX_HINTS + 1];
        let mut k = 0;
        for h in spec.hints.iter().flatten() {
            if h.0 == Str::KeyTheme {
                continue;
            }
            if let Some(slot) = all.get_mut(k) {
                *slot = Some(*h);
                k += 1;
            }
        }
        if let (Some(l), Some(slot)) = (opts.mode_hint, all.get_mut(k)) {
            *slot = Some((Str::KeyMode, l));
        }
        // Lay out into lines of at most WIDTH columns: (line, start col).
        let mut placed: [(usize, usize); layout::MAX_HINTS + 1] = [(0, 0); layout::MAX_HINTS + 1];
        let mut n = 0;
        let (mut line_i, mut col) = (0usize, 0usize);
        for (key, label) in all.iter().flatten() {
            let need = tr(list, theme, *key).n + 3 + tr(list, theme, *label).n;
            let gap = if col > 0 { 3 } else { 0 };
            if col + gap + need > WIDTH {
                if line_i == 1 || col == 0 {
                    break;
                }
                line_i = 1;
                col = 0;
            }
            let gap = if col > 0 { 3 } else { 0 };
            if let Some(slot) = placed.get_mut(n) {
                *slot = (line_i, col + gap);
                n += 1;
            }
            col += gap + need;
        }
        lines_used = if n == 0 {
            0
        } else {
            placed.get(n - 1).map_or(0, |p| p.0) + 1
        };
        for (i, (key, label)) in all.iter().flatten().take(n).enumerate() {
            let (li, c0) = placed.get(i).copied().unwrap_or((0, 0));
            let row = ROWS - lines_used + li;
            let ks = tr(list, theme, *key);
            let ls = tr(list, theme, *label);
            let mut c = grid.put(row, INDENT + c0, &['['], Tone::Strong, COLS);
            c = grid.put(row, c, ks.as_slice(), Tone::Strong, COLS);
            c = grid.put(row, c, &[']', ' '], Tone::Strong, COLS);
            grid.put(row, c, ls.as_slice(), Tone::Muted, COLS);
        }
    }
    let bottom = if lines_used > 0 {
        ROWS - lines_used - 1
    } else {
        ROWS
    };

    // The content column: measure, shrink to fit, draw.
    let mut blocks = spec.blocks;
    let lines_of = |b: &Block<'a>, list: &DrawList<'a>| -> usize {
        match b.kind {
            BlockKind::Title | BlockKind::Para | BlockKind::Toast => {
                let w = WIDTH
                    - if b.bar || b.kind == BlockKind::Toast {
                        2
                    } else {
                        0
                    };
                count_lines(chars_of(list, &b.src).as_slice(), w).clamp(b.min, b.max)
            }
            BlockKind::List => {
                let max = b.max.min(LIST_MAX);
                n_rows.clamp(b.min, max) + if n_rows > max { 2 } else { 0 }
            }
            BlockKind::Actions => spec.actions.iter().flatten().count().clamp(1, b.max),
            _ => 1,
        }
    };
    let total = |blocks: &[Option<Block<'a>>; layout::MAX_BLOCKS], list: &DrawList<'a>| {
        let mut t = 0;
        let mut prev = None;
        for b in blocks.iter().flatten() {
            t += gap_before(prev, b.kind) + lines_of(b, list);
            prev = Some(b.kind);
        }
        t
    };
    let room = bottom.saturating_sub(top);
    let mut guard = 0;
    while total(&blocks, list) > room && guard < 64 {
        guard += 1;
        // Paragraphs from the last, then the list, then the title, then
        // whole paragraphs.
        let mut done = false;
        for b in blocks.iter_mut().rev().flatten() {
            if b.kind == BlockKind::Para {
                let cur = count_lines(chars_of(list, &b.src).as_slice(), WIDTH).min(b.max);
                if cur > 1 {
                    b.max = cur - 1;
                    done = true;
                    break;
                }
            }
        }
        if done {
            continue;
        }
        for b in blocks.iter_mut().flatten() {
            if b.kind == BlockKind::List && n_rows.min(b.max) > 1 {
                b.max = n_rows.min(b.max) - 1;
                done = true;
                break;
            }
            if b.kind == BlockKind::Title && b.max > 1 {
                b.max = 1;
                done = true;
                break;
            }
        }
        if done {
            continue;
        }
        match blocks
            .iter_mut()
            .rev()
            .find(|s| s.is_some_and(|b| b.kind == BlockKind::Para))
        {
            Some(slot) => *slot = None,
            None => break,
        }
    }

    let mut r = top;
    let mut prev = None;
    let mut page = 1;
    for b in blocks.iter().flatten() {
        r += gap_before(prev, b.kind);
        prev = Some(b.kind);
        if r >= bottom {
            break;
        }
        let limit = bottom;
        match b.kind {
            BlockKind::Toast | BlockKind::Title | BlockKind::Para => {
                let tone = match b.kind {
                    BlockKind::Toast => Tone::Toast,
                    BlockKind::Title => Tone::Strong,
                    _ => tone_of(theme, b.color),
                };
                let (prefix, pt): (&[char], Tone) = match b.kind {
                    BlockKind::Toast => (&['!', ' '], Tone::Toast),
                    _ if b.bar => (&['|', ' '], Tone::Strong),
                    _ => (&[], tone),
                };
                let s = chars_of(list, &b.src);
                let s = s.as_slice();
                let w = WIDTH - prefix.len();
                let mut at = 0;
                for i in 0..b.max {
                    if r >= limit || at >= s.len() {
                        break;
                    }
                    let rest = s.get(at..).unwrap_or(&[]);
                    let (len, next) = next_line(rest, w);
                    let c0 = grid.put(r, INDENT, prefix, pt, COLS);
                    let last = i + 1 == b.max && at + next < s.len();
                    if last {
                        // Cut, with an ellipsis.
                        let keep = len.min(w.saturating_sub(3));
                        let c = grid.put(r, c0, rest.get(..keep).unwrap_or(&[]), tone, COLS);
                        grid.put(r, c, &['.', '.', '.'], tone, COLS);
                    } else {
                        grid.put(r, c0, rest.get(..len).unwrap_or(&[]), tone, COLS);
                    }
                    if b.kind == BlockKind::Toast {
                        grid.fill(r, INDENT..INDENT + WIDTH, Tone::Toast);
                    }
                    r += 1;
                    at += next;
                    if next == 0 {
                        break;
                    }
                }
            }
            BlockKind::Label | BlockKind::Name | BlockKind::Note => {
                let s = chars_of(list, &b.src);
                let tone = if matches!(b.kind, BlockKind::Label | BlockKind::Note) {
                    Tone::Muted
                } else {
                    tone_of(theme, b.color)
                };
                grid.put(r, INDENT, s.as_slice(), tone, INDENT + WIDTH);
                r += 1;
            }
            BlockKind::Crumb => {
                let n = n_rows;
                let visible = blocks
                    .iter()
                    .flatten()
                    .find(|x| x.kind == BlockKind::List)
                    .map_or(1, |x| n.min(x.max).clamp(1, LIST_MAX));
                let mut pos = Chars::new();
                if n > visible {
                    let mut t = heapless_fmt::<16>();
                    let _ = write!(t, "{} / {}", view.selected.min(n.saturating_sub(1)) + 1, n);
                    pos.push_str(t.as_str());
                }
                let path = chars_of(list, &b.src);
                let p = path.as_slice();
                let room = WIDTH - if pos.n > 0 { pos.n + 2 } else { 0 };
                if p.len() > room {
                    // Cut at the front: the current folder stays visible.
                    let c = grid.put(r, INDENT, &['.', '.', '.'], Tone::Muted, COLS);
                    let from = p.len() - (room - 3);
                    grid.put(r, c, p.get(from..).unwrap_or(&[]), Tone::Muted, COLS);
                } else {
                    grid.put(r, INDENT, p, Tone::Muted, COLS);
                }
                grid.put(r, INDENT + WIDTH - pos.n, pos.as_slice(), Tone::Faint, COLS);
                r += 1;
            }
            BlockKind::List => {
                let max = b.max.min(LIST_MAX);
                let overflow = n_rows > max;
                let room = (limit - r).saturating_sub(if overflow { 2 } else { 0 });
                let visible = n_rows.min(max).min(room).max(1);
                page = visible;
                let sel = view.selected.min(n_rows.saturating_sub(1));
                let first = sel
                    .saturating_sub(visible - 1)
                    .min(n_rows.saturating_sub(visible));
                let items = ui::items(screen);
                let more = |list: &mut DrawList<'a>, s: Str, n: usize| -> Chars {
                    let src = compose(list, theme, s, &[layout::Arg::Num(n as u64)], 0);
                    let mut c = Chars::new();
                    for ch in list.chars(&src) {
                        match ch {
                            '\u{2191}' => c.push('^'),
                            '\u{2193}' => c.push('v'),
                            ch => plain(ch, |p| c.push(p)),
                        }
                    }
                    c
                };
                let below = n_rows - (first + visible).min(n_rows);
                if overflow {
                    if first > 0 {
                        let m = more(list, Str::MoreAbove, first);
                        grid.put(r, INDENT + 3, m.as_slice(), Tone::Muted, COLS);
                    }
                    r += 1;
                }
                for idx in first..(first + visible).min(n_rows) {
                    let enabled = rows.enabled(idx);
                    let selected = idx == sel && enabled;
                    let (label, detail) = rows.texts(idx, theme, list);
                    let (label, detail) = (chars_of(list, &label), chars_of(list, &detail));
                    let tone = if !enabled {
                        Tone::Faint
                    } else if selected {
                        Tone::Selected
                    } else {
                        Tone::Normal
                    };
                    let mut c = grid.put(
                        r,
                        INDENT - 2,
                        if selected { &['>', ' '] } else { &[' ', ' '] },
                        Tone::Strong,
                        COLS,
                    );
                    match row_digit(screen, items.get(idx), idx) {
                        Some(d) => c = grid.put(r, c, &[d, ' ', ' '], tone, COLS),
                        None => c = grid.put(r, c, &[' ', ' ', ' '], tone, COLS),
                    }
                    let end = INDENT + WIDTH;
                    let dl = detail.n.min((end - c) / 2);
                    let lw = end - c - if dl > 0 { dl + 2 } else { 0 };
                    let l = label.as_slice();
                    if l.len() > lw {
                        let cc = grid.put(
                            r,
                            c,
                            l.get(..lw.saturating_sub(3)).unwrap_or(&[]),
                            tone,
                            COLS,
                        );
                        grid.put(r, cc, &['.', '.', '.'], tone, COLS);
                    } else {
                        grid.put(r, c, l, tone, COLS);
                    }
                    if dl > 0 {
                        let d = detail.as_slice();
                        let dtone = if tone == Tone::Normal {
                            Tone::Muted
                        } else {
                            tone
                        };
                        if d.len() > dl {
                            // Cut at the end, with an ellipsis.
                            let c = grid.put(
                                r,
                                end - dl,
                                d.get(..dl.saturating_sub(3)).unwrap_or(&[]),
                                dtone,
                                COLS,
                            );
                            grid.put(r, c, &['.', '.', '.'], dtone, COLS);
                        } else {
                            grid.put(r, end - dl, d, dtone, COLS);
                        }
                    }
                    if selected {
                        grid.fill(r, INDENT..end, Tone::Selected);
                    }
                    r += 1;
                }
                if overflow {
                    if below > 0 {
                        let m = more(list, Str::MoreBelow, below);
                        grid.put(r, INDENT + 3, m.as_slice(), Tone::Muted, COLS);
                    }
                    r += 1;
                }
            }
            BlockKind::Field => {
                let f = view
                    .field
                    .or_else(|| ui::field_kind(screen).map(|k| Field::begin(k, &mut [])));
                if let Some(f) = f {
                    draw_field(grid, r, &f, view.buf, theme);
                }
                r += 1;
            }
            BlockKind::Actions => {
                for (k, l) in spec.actions.iter().flatten().take(b.max) {
                    if r >= limit {
                        break;
                    }
                    let ks = tr(list, theme, *k);
                    let ls = tr(list, theme, *l);
                    let mut c = grid.put(r, INDENT, &['['], Tone::Strong, COLS);
                    c = grid.put(r, c, ks.as_slice(), Tone::Strong, COLS);
                    c = grid.put(r, c, &[']', ' '], Tone::Strong, COLS);
                    grid.put(
                        r,
                        c.max(INDENT + 9),
                        ls.as_slice(),
                        Tone::Normal,
                        INDENT + WIDTH,
                    );
                    r += 1;
                }
            }
        }
    }
    page
}

/// The field on row `r`: `> ` then the text (bullets while hidden, the
/// recovery key in groups of six), windowed so the cursor stays visible.
fn draw_field(grid: &mut Grid, r: usize, f: &Field, buf: &[u8], theme: &Theme) {
    let c0 = grid.put(r, INDENT, &['>', ' '], Tone::Strong, COLS);
    let text = f.text(buf);
    let (before, total) = f.char_counts(buf);
    let mut bullet = '*';
    plain(theme.options.bullet, |c| bullet = c);
    if f.kind() == FieldKind::RecoveryKey {
        let mut digits = text.chars();
        let mut c = c0;
        let mut cur = c0;
        for k in 0..RECOVERY_DIGITS {
            if k > 0 && k % RECOVERY_GROUP == 0 {
                c = grid.put(r, c, &['-'], Tone::Muted, COLS);
            }
            if k == before {
                cur = c;
            }
            let (ch, tone) = if k < total {
                let d = digits.next().unwrap_or('?');
                (if f.revealed() { d } else { bullet }, Tone::Normal)
            } else {
                ('_', Tone::Faint)
            };
            c = grid.put(r, c, &[ch], tone, COLS);
        }
        if before >= RECOVERY_DIGITS {
            cur = c;
        }
        grid.cursor = Some((r as u8, cur as u8));
        return;
    }
    let room = COLS - 1 - c0;
    let start = before.saturating_sub(room.saturating_sub(1));
    let mut c = c0;
    for (i, ch) in text.chars().enumerate().skip(start).take(room) {
        let _ = i;
        let mut shown = [' '; 8];
        let mut n = 0;
        if f.revealed() {
            plain(ch, |p| {
                if let Some(s) = shown.get_mut(n) {
                    *s = p;
                    n += 1;
                }
            });
            // One column per character keeps the cursor honest.
            n = n.min(1);
            if n == 0 {
                shown[0] = '?';
                n = 1;
            }
        } else {
            shown[0] = bullet;
            n = 1;
        }
        c = grid.put(r, c, shown.get(..n).unwrap_or(&[]), Tone::Normal, COLS);
    }
    let cur = c0 + (before - start);
    grid.cursor = Some((r as u8, cur.min(COLS - 1) as u8));
}

/// A small `fmt::Write` buffer for numbers.
struct Small<const N: usize> {
    b: [u8; N],
    n: usize,
}

fn heapless_fmt<const N: usize>() -> Small<N> {
    Small { b: [0; N], n: 0 }
}

impl<const N: usize> Small<N> {
    fn as_str(&self) -> &str {
        core::str::from_utf8(self.b.get(..self.n).unwrap_or(&[])).unwrap_or("")
    }
}

impl<const N: usize> Write for Small<N> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for &byte in s.as_bytes() {
            let slot = self.b.get_mut(self.n).ok_or(fmt::Error)?;
            *slot = byte;
            self.n += 1;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Out: VT100

fn sgr(t: Tone) -> &'static str {
    match t {
        Tone::Normal | Tone::Muted => "\x1b[0m",
        Tone::Strong | Tone::Toast => "\x1b[0;1m",
        Tone::Faint => "\x1b[0;2m",
        Tone::Selected => "\x1b[0;7m",
        Tone::Banner => "\x1b[0;1;7m",
    }
}

/// Write `grid` to a VT100 terminal: everything after a clear when `prev`
/// is `None` (a new screen), else only the rows that differ from `prev`.
/// Rows are written whole at their own address, so a line of text is
/// never split between writes; the cursor is left on the field (shown) or
/// hidden.
pub fn write_vt100(prev: Option<&Grid>, grid: &Grid, w: &mut impl Write) -> fmt::Result {
    if prev.is_none() {
        w.write_str("\x1b[0m\x1b[?25l\x1b[2J")?;
    } else {
        w.write_str("\x1b[?25l")?;
    }
    for r in 0..ROWS {
        let row = grid.row(r);
        if let Some(p) = prev {
            if p.row(r) == row {
                continue;
            }
        }
        write!(w, "\x1b[{};1H", r + 1)?;
        // Up to the last cell that is not a plain blank.
        let end = row
            .iter()
            .rposition(|c| c.ch != ' ' || !matches!(c.tone, Tone::Normal | Tone::Muted))
            .map_or(0, |i| i + 1);
        let mut tone = None;
        for c in row.get(..end).unwrap_or(&[]) {
            if tone != Some(sgr(c.tone)) {
                w.write_str(sgr(c.tone))?;
                tone = Some(sgr(c.tone));
            }
            w.write_char(c.ch)?;
        }
        w.write_str("\x1b[0m\x1b[K")?;
        if prev.is_none() && r + 1 < ROWS {
            // A plain line end too, so a log of the port reads as text.
            w.write_str("\r\n")?;
        }
    }
    match grid.cursor {
        Some((r, c)) => write!(w, "\x1b[{};{}H\x1b[?25h", r + 1, c + 1),
        None => write!(w, "\x1b[{};1H", ROWS),
    }
}

/// ConOut colours for a tone: `(foreground, background)` as
/// `EFI_TEXT_ATTR` values (UEFI 2.10 §12.4: 0 black … 7 light grey, 8 dark
/// grey … 15 white).
pub const fn conout_attr(t: Tone) -> (u8, u8) {
    match t {
        Tone::Normal => (7, 0),
        Tone::Strong => (15, 0),
        Tone::Muted => (7, 0),
        Tone::Faint => (8, 0),
        Tone::Selected => (0, 7),
        // Backgrounds are 0..=7 only (EFI_TEXT_ATTR).
        Tone::Banner => (14, 6),
        Tone::Toast => (12, 0),
    }
}

// ---------------------------------------------------------------------------
// Out: a canvas

/// The fixed cell of the field font at `theme`'s step for a `w`×`h`
/// display, shrunk until 80×24 cells fit: `(font step index, cell w, h)`.
fn cell_metrics(theme: &Theme, w: u32, h: u32) -> Option<(&'static crate::theme::Step, i32, i32)> {
    let steps: &'static [crate::theme::Step] = theme.steps;
    let (wi, hi) = (i32::try_from(w).ok()?, i32::try_from(h).ok()?);
    for st in steps.iter().rev() {
        let f = st.font(Style::Field);
        let mut cw = 0;
        for c in ['M', 'W', '0', '@', '_'] {
            cw = cw.max(text::char_width(f, c));
        }
        let ch = f.line.max(f.ascent - f.descent).max(1);
        if cw * COLS as i32 <= wi * 96 / 100 && ch * ROWS as i32 <= hi * 96 / 100 {
            return Some((st, cw, ch));
        }
    }
    let st = steps.first()?;
    let f = st.font(Style::Field);
    Some((
        st,
        text::char_width(f, 'M').max(1),
        f.line.max(f.ascent - f.descent).max(1),
    ))
}

/// Draw `grid` onto `canvas` in the theme's colours: each character centred
/// in a fixed cell of the field font, the grid centred on the display.
pub fn paint_grid(grid: &Grid, theme: &Theme, canvas: &mut Canvas<'_>) {
    let p = &theme.palette;
    canvas.fill(p.background);
    let Some((st, cw, ch)) = cell_metrics(theme, canvas.width(), canvas.height()) else {
        return;
    };
    let f = st.font(Style::Field);
    let x0 = (canvas.width() as i32 - cw * COLS as i32) / 2;
    let y0 = (canvas.height() as i32 - ch * ROWS as i32) / 2;
    let all = canvas.bounds();
    for r in 0..ROWS {
        let y = y0 + r as i32 * ch;
        for (c, cell) in grid.row(r).iter().enumerate() {
            let x = x0 + c as i32 * cw;
            let (fg, bg) = match cell.tone {
                Tone::Normal => (p.text, None),
                Tone::Strong => (p.text, None),
                Tone::Muted => (p.muted, None),
                Tone::Faint => (p.faint, None),
                Tone::Selected => (p.text, Some(p.surface_selected)),
                Tone::Banner => (p.banner_text, Some(p.banner_background)),
                Tone::Toast => (p.toast_text, Some(p.toast_background)),
            };
            let cell_r = Rect::new(x, y, cw, ch);
            if let Some(bg) = bg {
                canvas.round_rect(cell_r, 0, bg, all);
            }
            if cell.ch != ' ' {
                let (l, rr) = text::extent(f, core::iter::once(cell.ch));
                let gx = x + (cw - (rr - l)) / 2 - l;
                let base = y + (ch - (f.ascent - f.descent)) / 2 + f.ascent;
                canvas.text(f, gx, base, core::iter::once(cell.ch), fg, cell_r);
            }
        }
    }
    if let Some((r, c)) = grid.cursor {
        let x = x0 + i32::from(c) * cw;
        let y = y0 + i32::from(r) * ch;
        canvas.round_rect(
            Rect::new(x, y + ch / 8, (cw / 8).max(2), ch - ch / 4),
            0,
            p.cursor,
            all,
        );
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::string::String;

    #[test]
    fn plain_text() {
        let mut s = String::new();
        for c in "a—b…↑ ↓•é’\u{7}".chars() {
            plain(c, |p| s.push(p));
        }
        assert_eq!(s, "a--b...Up Down*é'");
    }

    #[test]
    fn conout_backgrounds_are_valid() {
        for t in [
            Tone::Normal,
            Tone::Strong,
            Tone::Muted,
            Tone::Faint,
            Tone::Selected,
            Tone::Banner,
            Tone::Toast,
        ] {
            let (fg, bg) = conout_attr(t);
            assert!(fg <= 15 && bg <= 7, "{t:?}");
        }
    }

    #[test]
    fn wrapping() {
        let s: std::vec::Vec<char> = "aaa bbb ccc".chars().collect();
        assert_eq!(next_line(&s, 7), (7, 8));
        assert_eq!(next_line(&s, 5), (3, 4));
        assert_eq!(next_line(&s, 20), (11, 11));
        let long: std::vec::Vec<char> = "abcdefghij".chars().collect();
        assert_eq!(next_line(&long, 4), (4, 4), "hard break");
        assert_eq!(count_lines(&s, 5), 3);
        assert_eq!(count_lines(&[], 5), 1);
    }

    #[test]
    fn vt100_redraws_only_changed_rows() {
        let mut a = Grid::new();
        a.put(0, 1, &['h', 'i'], Tone::Strong, COLS);
        let mut out = String::new();
        write_vt100(None, &a, &mut out).unwrap();
        assert!(out.starts_with("\x1b[0m\x1b[?25l\x1b[2J"));
        assert!(
            out.contains("\x1b[1;1H\x1b[0m \x1b[0;1mhi\x1b[0m\x1b[K\r\n"),
            "{out:?}"
        );
        let mut b = a.clone();
        b.put(5, 0, &['x'], Tone::Normal, COLS);
        b.cursor = Some((5, 1));
        let mut out = String::new();
        write_vt100(Some(&a), &b, &mut out).unwrap();
        assert_eq!(
            out,
            "\x1b[?25l\x1b[6;1H\x1b[0mx\x1b[0m\x1b[K\x1b[6;2H\x1b[?25h"
        );
        let mut out = String::new();
        write_vt100(Some(&b), &b, &mut out).unwrap();
        assert_eq!(out, "\x1b[?25l\x1b[6;2H\x1b[?25h", "nothing changed");
    }
}
