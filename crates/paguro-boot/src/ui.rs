//! What every front end shares: the key model, the text-entry editor of
//! INTERFACES.md §13.3, list navigation, the key → [`Input`] mapping. Pure
//! functions and plain state, so the firmware adapter only draws and
//! forwards keys, and all of this is tested on the host. What screens say is
//! the theme's (`paguro-ui`, graphics and the text UI alike).
//!
//! Rules from DESIGN.md §4.1 "Screens" that apply here: the name on every
//! screen; Esc always leads somewhere; rows labelled by cost; an unattested
//! prompt says so; error codes are not in the message.
//!
//! A secret lives only in the caller's buffer. [`Field`] keeps offsets, never
//! a copy, and wipes whatever it removes; bytes past the entered text are
//! always zero.

use core::fmt;

use crate::platform::{DirView, EntryKind, Grey, Input, Level, Notice, Row, Screen, UnlockMenu};

/// A key, already decoded from the firmware's `EFI_INPUT_KEY` (or
/// `EFI_KEY_DATA`, whose modifiers the adapter applies before this point).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Enter,
    Escape,
    Backspace,
    Delete,
    Left,
    Right,
    Up,
    Down,
    Home,
    End,
    Insert,
    PageUp,
    PageDown,
    /// F1..F24.
    Function(u8),
}

/// The key that cycles the compiled-in theme variants (dark, light and a
/// high-contrast version of each; INTERFACES.md §13.2a).
pub const THEME_KEY: Key = Key::Function(2);
/// The key that toggles the local display between graphics and the text UI
/// (INTERFACES.md §13.2a).
pub const MODE_KEY: Key = Key::Function(3);
/// The key that opens the keyboard layout list (INTERFACES.md §13.5).
pub const KEYBOARD_KEY: Key = Key::Function(4);
/// The key that opens the language list (INTERFACES.md §13.5).
pub const LANGUAGE_KEY: Key = Key::Function(5);

// ---------------------------------------------------------------------------
// Text entry (INTERFACES.md §13.3)

/// The 48-digit BitLocker recovery password, entered without separators.
pub const RECOVERY_DIGITS: usize = 48;
/// Digits per displayed group of the recovery password.
pub const RECOVERY_GROUP: usize = 6;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldKind {
    /// Password, PIN or passphrase: bullets unless revealed.
    Secret,
    /// Digits only, at most [`RECOVERY_DIGITS`], shown grouped in sixes;
    /// bullets unless revealed.
    RecoveryKey,
    /// A path typed in recovery: not secret, always shown.
    Path,
}

impl FieldKind {
    pub const fn secret(self) -> bool {
        !matches!(self, FieldKind::Path)
    }
}

/// What a key did to a [`Field`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FieldEvent {
    Changed,
    Unchanged,
    /// Enter: this many bytes of text are in the buffer.
    Submit(usize),
    /// Esc: the buffer has been wiped.
    Cancel,
}

/// A one-line editor over a caller-owned buffer. Text is UTF-8; the cursor is
/// a byte offset on a character boundary; input beyond the buffer is dropped,
/// never wrapped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    kind: FieldKind,
    len: usize,
    cursor: usize,
    reveal: bool,
}

impl Field {
    /// A fresh, hidden, empty field. The buffer is wiped: nothing left in it
    /// by an earlier prompt can surface.
    pub fn begin(kind: FieldKind, buf: &mut [u8]) -> Field {
        wipe(buf);
        Field {
            kind,
            len: 0,
            cursor: 0,
            reveal: false,
        }
    }

    pub const fn kind(&self) -> FieldKind {
        self.kind
    }
    /// Bytes of text.
    pub const fn len(&self) -> usize {
        self.len
    }
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
    /// Byte offset of the cursor.
    pub const fn cursor(&self) -> usize {
        self.cursor
    }
    /// Whether a secret is shown in clear (Insert toggles; never for a path,
    /// which is always shown).
    pub const fn revealed(&self) -> bool {
        self.reveal || !self.kind.secret()
    }

    /// The text entered so far.
    pub fn text<'b>(&self, buf: &'b [u8]) -> &'b str {
        core::str::from_utf8(buf.get(..self.len).unwrap_or(&[])).unwrap_or("")
    }

    /// Characters before the cursor and in total (for bullets and layout).
    pub fn char_counts(&self, buf: &[u8]) -> (usize, usize) {
        let t = self.text(buf);
        let before = t.get(..self.cursor).map_or(0, |s| s.chars().count());
        (before, t.chars().count())
    }

    fn prev_len(&self, buf: &[u8]) -> Option<usize> {
        let s = core::str::from_utf8(buf.get(..self.cursor)?).ok()?;
        s.chars().next_back().map(char::len_utf8)
    }

    fn next_len(&self, buf: &[u8]) -> Option<usize> {
        let s = core::str::from_utf8(buf.get(self.cursor..self.len)?).ok()?;
        s.chars().next().map(char::len_utf8)
    }

    /// Remove `n` bytes at `at`, closing the gap and wiping the freed tail.
    fn remove(&mut self, buf: &mut [u8], at: usize, n: usize) -> bool {
        let (Some(end), true) = (at.checked_add(n), at <= self.len) else {
            return false;
        };
        if end > self.len || end > buf.len() {
            return false;
        }
        buf.copy_within(end..self.len, at);
        if let Some(tail) = buf.get_mut(self.len - n..self.len) {
            wipe(tail);
        }
        self.len -= n;
        true
    }

    fn insert(&mut self, buf: &mut [u8], c: char) -> bool {
        let accept = match self.kind {
            FieldKind::RecoveryKey => c.is_ascii_digit() && self.len < RECOVERY_DIGITS,
            FieldKind::Secret | FieldKind::Path => !c.is_control(),
        };
        if !accept {
            return false;
        }
        let mut enc = [0u8; 4];
        let n = c.encode_utf8(&mut enc).len();
        let Some(new_len) = self.len.checked_add(n).filter(|&l| l <= buf.len()) else {
            return false;
        };
        buf.copy_within(self.cursor..self.len, self.cursor + n);
        let (Some(dst), Some(src)) = (buf.get_mut(self.cursor..self.cursor + n), enc.get(..n))
        else {
            return false;
        };
        dst.copy_from_slice(src);
        wipe(&mut enc);
        self.len = new_len;
        self.cursor += n;
        true
    }

    /// Put the cursor before character `chars` (clamped to the text): a
    /// click in the field. `true` when it moved.
    pub fn move_to(&mut self, chars: usize, buf: &[u8]) -> bool {
        let t = self.text(buf);
        let at = t.char_indices().nth(chars).map_or(t.len(), |(i, _)| i);
        core::mem::replace(&mut self.cursor, at) != at
    }

    pub fn feed(&mut self, key: Key, buf: &mut [u8]) -> FieldEvent {
        let changed = match key {
            Key::Enter => return FieldEvent::Submit(self.len),
            Key::Escape => {
                wipe(buf);
                *self = Field::begin(self.kind, buf);
                return FieldEvent::Cancel;
            }
            Key::Char(c) => self.insert(buf, c),
            Key::Backspace => match self.prev_len(buf) {
                Some(n) => {
                    let at = self.cursor - n;
                    let ok = self.remove(buf, at, n);
                    if ok {
                        self.cursor = at;
                    }
                    ok
                }
                None => false,
            },
            Key::Delete => match self.next_len(buf) {
                Some(n) => self.remove(buf, self.cursor, n),
                None => false,
            },
            Key::Left => match self.prev_len(buf) {
                Some(n) => {
                    self.cursor -= n;
                    true
                }
                None => false,
            },
            Key::Right => match self.next_len(buf) {
                Some(n) => {
                    self.cursor += n;
                    true
                }
                None => false,
            },
            Key::Home => core::mem::replace(&mut self.cursor, 0) != 0,
            Key::End => core::mem::replace(&mut self.cursor, self.len) != self.len,
            Key::Insert if self.kind.secret() => {
                self.reveal = !self.reveal;
                true
            }
            _ => false,
        };
        if changed {
            FieldEvent::Changed
        } else {
            FieldEvent::Unchanged
        }
    }
}

/// Volatile zeroing, never elided as a dead store.
fn wipe(b: &mut [u8]) {
    zeroize::Zeroize::zeroize(b);
}

/// The field a screen edits, if any.
pub const fn field_kind(screen: &Screen) -> Option<FieldKind> {
    match screen {
        Screen::EnterSecret {
            row: Row::RecoveryKey,
            ..
        } => Some(FieldKind::RecoveryKey),
        Screen::EnterSecret { .. } => Some(FieldKind::Secret),
        Screen::EnterPath(_) => Some(FieldKind::Path),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Lists

/// One row of a list screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Item {
    /// An unlock row; a greyed row is shown but cannot be chosen.
    Unlock {
        row: Row,
        enabled: bool,
    },
    Volume(u8),
    TypePath,
    /// The disk screen's rows.
    DiskDefault,
    DiskBrowse,
    /// A keyboard layout (index in `Keyboard::ALL`) or a language.
    Keyboard(u8),
    Language(u8),
}

impl Item {
    pub const fn enabled(&self) -> bool {
        !matches!(self, Item::Unlock { enabled: false, .. })
    }
    /// What choosing the row means.
    pub const fn input(&self) -> Option<Input> {
        match *self {
            Item::Unlock { enabled: false, .. } => None,
            Item::Unlock { row, .. } => Some(Input::Select(row)),
            Item::Volume(i) => Some(Input::Choose(i)),
            Item::TypePath => Some(Input::TypePath),
            Item::DiskDefault => Some(Input::UseDefault),
            Item::DiskBrowse => Some(Input::BrowseDisk),
            Item::Keyboard(i) | Item::Language(i) => Some(Input::Choose(i)),
        }
    }
}

pub const MAX_ITEMS: usize = crate::platform::MAX_CHOICES + 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Items {
    items: [Item; MAX_ITEMS],
    count: usize,
}

impl Items {
    const fn new() -> Self {
        Items {
            items: [Item::TypePath; MAX_ITEMS],
            count: 0,
        }
    }
    fn push(&mut self, it: Item) {
        if let Some(slot) = self.items.get_mut(self.count) {
            *slot = it;
            self.count += 1;
        }
    }
    pub fn as_slice(&self) -> &[Item] {
        self.items.get(..self.count).unwrap_or(&[])
    }
    pub fn len(&self) -> usize {
        self.count
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn get(&self, i: usize) -> Option<Item> {
        self.as_slice().get(i).copied()
    }
}

/// Whether the password row is shown greyed rather than hidden: the two
/// reasons DESIGN.md §4.1 names ("unavailable until restart", "TPM locked").
/// A TPM that is merely unusable (no seal, no TPM) hides the row.
pub const fn greyed_password_row(m: &UnlockMenu) -> Option<Grey> {
    match m.tpm {
        Err(g @ (Grey::RecoveryMode | Grey::Locked)) if !m.password_or_pin => Some(g),
        _ => None,
    }
}

/// The rows of a list screen, in display order; empty for other screens.
pub fn items(screen: &Screen) -> Items {
    let mut out = Items::new();
    match screen {
        Screen::Unlock(m) => {
            if m.password_or_pin {
                out.push(Item::Unlock {
                    row: Row::PasswordOrPin,
                    enabled: true,
                });
            } else if greyed_password_row(m).is_some() {
                out.push(Item::Unlock {
                    row: Row::PasswordOrPin,
                    enabled: false,
                });
            }
            if m.recovery_passphrase {
                out.push(Item::Unlock {
                    row: Row::RecoveryPassphrase,
                    enabled: true,
                });
            }
            if m.recovery_key {
                out.push(Item::Unlock {
                    row: Row::RecoveryKey,
                    enabled: true,
                });
            }
        }
        Screen::SelectVolume(v) => {
            for i in 0..v.count.min(crate::platform::MAX_CHOICES as u8) {
                out.push(Item::Volume(i));
            }
        }
        Screen::DiskStart { .. } => {
            out.push(Item::DiskDefault);
            out.push(Item::DiskBrowse);
            out.push(Item::TypePath);
        }
        Screen::ChooseKeyboard { .. } => {
            for i in 0..paguro_core::config::Keyboard::ALL.len() {
                out.push(Item::Keyboard(i as u8));
            }
        }
        Screen::ChooseLanguage { count, .. } => {
            for i in 0..*count {
                out.push(Item::Language(i));
            }
        }
        _ => {}
    }
    out
}

/// Where a list starts: the current choice on the choosers, else the first
/// enabled row.
fn initial_row(screen: &Screen, items: &Items) -> usize {
    match screen {
        Screen::ChooseKeyboard { current } => paguro_core::config::Keyboard::ALL
            .iter()
            .position(|k| k == current)
            .unwrap_or(0),
        Screen::ChooseLanguage { current, count } => usize::from(*current.min(count)),
        _ => items.as_slice().iter().position(Item::enabled).unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// One prompt: keys in, an Input out

/// What a key did to a prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reaction {
    /// The view changed: draw again.
    Redraw,
    Ignore,
    /// Switch to the next compiled-in theme variant and draw again.
    NextTheme,
    /// Toggle the local display between graphics and text and draw again.
    ToggleMode,
    /// Open the keyboard layout list (and come back to this prompt).
    ChooseKeyboard,
    /// Open the language list (and come back to this prompt).
    ChooseLanguage,
    Done(Input),
}

/// The interaction state of one shown screen: the list cursor and the field.
/// Created per prompt, so a revealed secret is hidden again on the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prompt {
    selected: usize,
    field: Option<Field>,
    /// Rows the list shows at once (PageUp/PageDown).
    page: usize,
}

impl Prompt {
    /// Start a prompt for `screen`. A field's buffer is wiped first.
    pub fn new(screen: &Screen, buf: &mut [u8]) -> Prompt {
        let items = items(screen);
        let selected = initial_row(screen, &items);
        Prompt {
            selected,
            field: field_kind(screen).map(|k| Field::begin(k, buf)),
            page: 8,
        }
    }

    /// Rows per page, as many as the screen shows.
    pub fn set_page(&mut self, rows: usize) {
        self.page = rows.max(1);
    }

    /// The highlighted list row.
    pub const fn selected(&self) -> usize {
        self.selected
    }

    pub const fn field(&self) -> Option<&Field> {
        self.field.as_ref()
    }

    fn step(&mut self, items: &Items, forward: bool) -> bool {
        let mut i = self.selected;
        loop {
            let next = if forward {
                i.checked_add(1).filter(|&n| n < items.len())
            } else {
                i.checked_sub(1)
            };
            let Some(n) = next else {
                return false;
            };
            if items.get(n).is_some_and(|it| it.enabled()) {
                self.selected = n;
                return true;
            }
            i = n;
        }
    }

    /// A click on list row `i`: select it and act as Enter; a greyed or
    /// missing row does nothing.
    pub fn activate(&mut self, screen: &Screen, i: usize) -> Reaction {
        let items = items(screen);
        match items.get(i) {
            Some(it) if it.enabled() => {
                self.selected = i;
                match it.input() {
                    Some(input) => Reaction::Done(input),
                    None => Reaction::Redraw,
                }
            }
            _ => Reaction::Ignore,
        }
    }

    /// A click in the field, before character `chars`.
    pub fn click_field(&mut self, chars: usize, buf: &[u8]) -> Reaction {
        match self.field.as_mut().map(|f| f.move_to(chars, buf)) {
            Some(true) => Reaction::Redraw,
            _ => Reaction::Ignore,
        }
    }

    pub fn feed(&mut self, screen: &Screen, key: Key, buf: &mut [u8]) -> Reaction {
        if key == THEME_KEY {
            return Reaction::NextTheme;
        }
        if key == MODE_KEY {
            return Reaction::ToggleMode;
        }
        if key == KEYBOARD_KEY {
            return Reaction::ChooseKeyboard;
        }
        if key == LANGUAGE_KEY {
            return Reaction::ChooseLanguage;
        }
        if let Some(f) = self.field.as_mut() {
            return match f.feed(key, buf) {
                FieldEvent::Changed => Reaction::Redraw,
                FieldEvent::Unchanged => Reaction::Ignore,
                FieldEvent::Submit(n) => Reaction::Done(Input::Secret(n)),
                FieldEvent::Cancel => Reaction::Done(Input::Escape),
            };
        }
        let items = items(screen);
        if !items.is_empty() {
            match key {
                Key::Up | Key::Down | Key::PageUp | Key::PageDown => {
                    let forward = matches!(key, Key::Down | Key::PageDown);
                    let n = if matches!(key, Key::PageUp | Key::PageDown) {
                        self.page
                    } else {
                        1
                    };
                    let mut moved = false;
                    for _ in 0..n {
                        if !self.step(&items, forward) {
                            break;
                        }
                        moved = true;
                    }
                    return if moved {
                        Reaction::Redraw
                    } else {
                        Reaction::Ignore
                    };
                }
                Key::Home | Key::End => {
                    let old = self.selected;
                    let found = if key == Key::Home {
                        items.as_slice().iter().position(Item::enabled)
                    } else {
                        items.as_slice().iter().rposition(Item::enabled)
                    };
                    self.selected = found.unwrap_or(old);
                    return if self.selected != old {
                        Reaction::Redraw
                    } else {
                        Reaction::Ignore
                    };
                }
                Key::Enter => {
                    return match items.get(self.selected).and_then(|it| it.input()) {
                        Some(i) => Reaction::Done(i),
                        None => Reaction::Ignore,
                    };
                }
                _ => {}
            }
        }
        match map_key(screen, key) {
            Some(i) => Reaction::Done(i),
            None => Reaction::Ignore,
        }
    }
}

// ---------------------------------------------------------------------------
// The recovery browser

/// The browser's interaction state: the highlighted row (the listing's
/// entries, then "Type a path") and the page size the renderer reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Browser {
    selected: usize,
    page: usize,
}

/// The browser's rows: every entry, then "Type a path", then (for the root
/// hint) "No root".
pub fn browse_rows(dir: &DirView<'_>) -> usize {
    dir.listing.len() + if dir.level == Level::Root { 2 } else { 1 }
}

/// Whether `path` is a filesystem root (no parent).
pub fn is_root(path: &str) -> bool {
    path.trim_end_matches('\\').is_empty()
}

impl Browser {
    pub fn new(dir: &DirView<'_>) -> Browser {
        Browser {
            selected: dir.selected.min(browse_rows(dir) - 1),
            page: 8,
        }
    }

    pub const fn selected(&self) -> usize {
        self.selected
    }

    /// Rows per page (PageUp/PageDown), as many as the screen shows.
    pub fn set_page(&mut self, rows: usize) {
        self.page = rows.max(1);
    }

    fn go(&mut self, to: usize, rows: usize) -> Reaction {
        let to = to.min(rows - 1);
        if to == self.selected {
            Reaction::Ignore
        } else {
            self.selected = to;
            Reaction::Redraw
        }
    }

    /// A click on row `i`: select it and act as Enter.
    pub fn activate(&mut self, dir: &DirView<'_>, i: usize) -> Reaction {
        if i >= browse_rows(dir) {
            return Reaction::Ignore;
        }
        self.selected = i;
        self.feed(dir, Key::Enter)
    }

    pub fn feed(&mut self, dir: &DirView<'_>, key: Key) -> Reaction {
        let rows = browse_rows(dir);
        let entry = dir.listing.item(self.selected);
        match key {
            k if k == THEME_KEY => Reaction::NextTheme,
            k if k == MODE_KEY => Reaction::ToggleMode,
            k if k == KEYBOARD_KEY => Reaction::ChooseKeyboard,
            k if k == LANGUAGE_KEY => Reaction::ChooseLanguage,
            // Start typing a path, from anywhere in the browser.
            Key::Char('/' | '\\') => Reaction::Done(Input::TypePath),
            Key::Up => self.go(self.selected.saturating_sub(1), rows),
            Key::Down => self.go(self.selected + 1, rows),
            Key::PageUp => self.go(self.selected.saturating_sub(self.page), rows),
            Key::PageDown => self.go(self.selected + self.page, rows),
            Key::Home => self.go(0, rows),
            Key::End => self.go(rows - 1, rows),
            Key::Enter => match entry {
                Some(_) => Reaction::Done(Input::Entry(self.selected as u16)),
                None if self.selected == dir.listing.len() => Reaction::Done(Input::TypePath),
                None => Reaction::Done(Input::NoRoot),
            },
            Key::Right => match entry {
                Some(e) if e.kind == EntryKind::Dir => {
                    Reaction::Done(Input::Entry(self.selected as u16))
                }
                _ => Reaction::Ignore,
            },
            Key::Left | Key::Backspace if !is_root(dir.path) => Reaction::Done(Input::Parent),
            Key::Escape => Reaction::Done(Input::Escape),
            Key::Char(c) if !c.is_control() => {
                // Type to jump: the next entry starting with `c`.
                let n = dir.listing.len();
                let want = |i: usize| {
                    dir.listing.item(i).is_some_and(|e| {
                        e.name
                            .chars()
                            .next()
                            .is_some_and(|f| f.to_lowercase().eq(c.to_lowercase()))
                    })
                };
                match (1..=n)
                    .map(|k| (self.selected + k) % n.max(1))
                    .find(|&i| want(i))
                {
                    Some(i) => self.go(i, rows),
                    None => Reaction::Ignore,
                }
            }
            _ => Reaction::Ignore,
        }
    }
}

// ---------------------------------------------------------------------------
// Sizes

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unit {
    B,
    KB,
    MB,
    GB,
    TB,
}

/// A byte count for display: binary multiples (as Windows shows them), one
/// decimal below 10, whole numbers above.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub whole: u64,
    pub tenth: Option<u8>,
    pub unit: Unit,
}

impl Size {
    pub fn of(bytes: u64) -> Size {
        let units = [Unit::B, Unit::KB, Unit::MB, Unit::GB, Unit::TB];
        let mut i = 0usize;
        let mut div = 1u64;
        while i + 1 < units.len() && bytes / div >= 1024 {
            div *= 1024;
            i += 1;
        }
        let unit = units.get(i).copied().unwrap_or(Unit::TB);
        if bytes / div < 10 && i > 0 {
            // Tenths, rounded; 9.96 rounds to 10.0 and is shown as 10.
            let tenths = (u128::from(bytes) * 10 + u128::from(div) / 2) / u128::from(div);
            let tenths = u64::try_from(tenths).unwrap_or(u64::MAX);
            if tenths < 100 {
                return Size {
                    whole: tenths / 10,
                    tenth: Some((tenths % 10) as u8),
                    unit,
                };
            }
            return Size {
                whole: 10,
                tenth: None,
                unit,
            };
        }
        let whole = (u128::from(bytes) + u128::from(div / 2)) / u128::from(div);
        Size {
            whole: u64::try_from(whole).unwrap_or(u64::MAX),
            tenth: None,
            unit,
        }
    }
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let u = match self.unit {
            Unit::B => "B",
            Unit::KB => "KB",
            Unit::MB => "MB",
            Unit::GB => "GB",
            Unit::TB => "TB",
        };
        match self.tenth {
            Some(t) => write!(f, "{}.{} {u}", self.whole, t),
            None => write!(f, "{} {u}", self.whole),
        }
    }
}

/// A file name's stem as a `[Boot.*]`-style name (`[A-Za-z0-9_-]`, ≤ 32),
/// for the handoff; `fallback` when nothing usable remains.
pub fn entry_name<'o>(file: &str, out: &'o mut [u8; 32], fallback: &'o str) -> &'o str {
    let base = file.rsplit('\\').next().unwrap_or(file);
    let stem = match base.rfind('.') {
        Some(0) | None => base,
        Some(i) => base.get(..i).unwrap_or(base),
    };
    let mut n = 0usize;
    for b in stem.bytes() {
        let Some(slot) = out.get_mut(n) else {
            break;
        };
        *slot = if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' {
            b
        } else {
            b'_'
        };
        n += 1;
    }
    match core::str::from_utf8(out.get(..n).unwrap_or(&[])) {
        Ok(s) if !s.is_empty() => s,
        _ => fallback,
    }
}

/// How a typed path is classified: `*.efi` (any case) is an `efi_file`,
/// anything else a disk (INTERFACES.md §13.4).
pub fn classify_path(path: &str) -> EntryKind {
    let b = path.as_bytes();
    match b.len().checked_sub(4).and_then(|i| b.get(i..)) {
        Some(ext) if ext.eq_ignore_ascii_case(b".efi") => EntryKind::Efi,
        _ => EntryKind::Disk,
    }
}

/// A typed path as the volume knows it: `/` taken as `\\`, a leading drive
/// letter (`C:`) dropped — the loader cannot know Windows' drive letters —
/// runs of separators and a trailing one removed, and a leading `\\` added
/// (paths are on the chosen volume). Returns the path and whether a drive
/// letter was dropped; `None` when it does not fit `out`.
pub fn normalize_path<'o>(typed: &str, out: &'o mut [u8]) -> Option<(&'o str, bool)> {
    // Separators first ("/C:/…" from the browser's "/"), then a drive.
    let t = typed.trim().trim_start_matches(['\\', '/']);
    let mut c = t.chars();
    let drive = matches!((c.next(), c.next()), (Some(d), Some(':')) if d.is_ascii_alphabetic());
    let rest = if drive { t.get(2..).unwrap_or("") } else { t };
    let mut n = 0usize;
    let mut put = |b: &[u8], n: &mut usize| -> Option<()> {
        out.get_mut(*n..*n + b.len())?.copy_from_slice(b);
        *n += b.len();
        Some(())
    };
    for comp in rest.split(['\\', '/']).filter(|s| !s.is_empty()) {
        put(b"\\", &mut n)?;
        put(comp.as_bytes(), &mut n)?;
    }
    if n == 0 {
        put(b"\\", &mut n)?;
    }
    let s = core::str::from_utf8(out.get(..n)?).ok()?;
    Some((s, drive))
}

/// Whether a screen waits for a key. "That did not unlock" is shown and the
/// unlock list follows at once, so a retry costs no extra keystroke.
pub const fn needs_key(screen: &Screen) -> bool {
    !matches!(
        screen,
        Screen::Incorrect | Screen::PathRefused | Screen::NoEfiPartition
    )
}

/// Keys that act directly (without the list cursor). `None`: ignore the key.
pub fn map_key(screen: &Screen, key: Key) -> Option<Input> {
    let c = match key {
        Key::Char(c) => Some(c.to_ascii_lowercase()),
        _ => None,
    };
    let digit = |count: u8| match c {
        Some(d @ '1'..='9') => {
            let i = (d as u8) - b'1';
            (i < count).then_some(i)
        }
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
        Screen::SelectVolume(v) => match (key, c) {
            (Key::Escape, _) => Some(Input::Escape),
            (_, Some('w')) => Some(Input::StartWindows),
            _ => digit(v.count).map(Input::Choose),
        },
        Screen::DiskStart { .. } => match (key, c) {
            (Key::Escape, _) => Some(Input::Escape),
            (_, Some('1')) => Some(Input::UseDefault),
            (_, Some('2')) => Some(Input::BrowseDisk),
            (_, Some('3')) => Some(Input::TypePath),
            _ => None,
        },
        Screen::Incorrect
        | Screen::PathRefused
        | Screen::NoEfiPartition
        | Screen::TpmLocked
        | Screen::Notice(Notice::SealOverPlaintext)
        | Screen::Notice(Notice::NotImplemented)
        | Screen::Notice(Notice::StartFailed) => Some(Input::Continue),
        Screen::ChooseKeyboard { .. } | Screen::ChooseLanguage { .. } => match key {
            Key::Escape => Some(Input::Escape),
            _ => None,
        },
        Screen::EnterSecret { .. } | Screen::EnterPath(_) | Screen::Browse(_) => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::platform::{DirListing, Label, VolumeChoice, VolumeFormat, VolumeList};

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

    fn volumes(n: u8) -> VolumeList {
        let mut v = VolumeList::new();
        for i in 0..n {
            v.push(VolumeChoice {
                disk: i,
                partition: 3,
                bytes: 931 << 30,
                format: VolumeFormat::BitLocker,
                name: Label::new("Basic data partition").unwrap(),
            });
        }
        v
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
        let sv = Screen::SelectVolume(volumes(2));
        assert_eq!(map_key(&sv, Key::Char('2')), Some(Input::Choose(1)));
        assert_eq!(map_key(&sv, Key::Char('3')), None);
        assert_eq!(map_key(&sv, Key::Escape), Some(Input::Escape));
        assert_eq!(map_key(&sv, Key::Enter), None);
        let ds = Screen::DiskStart { disk: Label::EMPTY };
        assert_eq!(map_key(&ds, Key::Char('1')), Some(Input::UseDefault));
        assert_eq!(map_key(&ds, Key::Char('2')), Some(Input::BrowseDisk));
        assert_eq!(map_key(&ds, Key::Char('3')), Some(Input::TypePath));
        assert_eq!(map_key(&ds, Key::Char('4')), None);
        assert_eq!(map_key(&ds, Key::Escape), Some(Input::Escape));
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
    fn list_navigation_skips_greyed_rows() {
        let s = Screen::Unlock(UnlockMenu {
            password_or_pin: false,
            recovery_passphrase: true,
            tpm: Err(Grey::Locked),
            ..menu()
        });
        let it = items(&s);
        assert_eq!(
            it.as_slice(),
            &[
                Item::Unlock {
                    row: Row::PasswordOrPin,
                    enabled: false
                },
                Item::Unlock {
                    row: Row::RecoveryPassphrase,
                    enabled: true
                },
                Item::Unlock {
                    row: Row::RecoveryKey,
                    enabled: true
                },
            ]
        );
        let mut buf = [0u8; 0];
        let mut p = Prompt::new(&s, &mut buf);
        assert_eq!(p.selected(), 1, "the greyed row is never the cursor");
        assert_eq!(p.feed(&s, Key::Up, &mut buf), Reaction::Ignore);
        assert_eq!(p.feed(&s, Key::Down, &mut buf), Reaction::Redraw);
        assert_eq!(p.feed(&s, Key::Down, &mut buf), Reaction::Ignore);
        assert_eq!(
            p.feed(&s, Key::Enter, &mut buf),
            Reaction::Done(Input::Select(Row::RecoveryKey))
        );
        assert_eq!(p.feed(&s, Key::Home, &mut buf), Reaction::Redraw);
        assert_eq!(p.selected(), 1);
        assert_eq!(p.feed(&s, THEME_KEY, &mut buf), Reaction::NextTheme);
        // Unavailable (no seal, no TPM) hides the row rather than greying it.
        let hidden = Screen::Unlock(UnlockMenu {
            password_or_pin: false,
            tpm: Err(Grey::Unavailable),
            ..menu()
        });
        assert_eq!(items(&hidden).len(), 1);
    }

    #[test]
    fn disk_and_root_lists() {
        let ds = Screen::DiskStart { disk: Label::EMPTY };
        assert_eq!(
            items(&ds).as_slice(),
            &[Item::DiskDefault, Item::DiskBrowse, Item::TypePath]
        );
        let mut buf = [0u8; 0];
        let mut p = Prompt::new(&ds, &mut buf);
        assert_eq!(
            p.feed(&ds, Key::Enter, &mut buf),
            Reaction::Done(Input::UseDefault)
        );
        p.feed(&ds, Key::Down, &mut buf);
        assert_eq!(
            p.feed(&ds, Key::Enter, &mut buf),
            Reaction::Done(Input::BrowseDisk)
        );
    }

    fn typed(kind: FieldKind, keys: &[Key], buf: &mut [u8]) -> (Field, FieldEvent) {
        let mut f = Field::begin(kind, buf);
        let mut last = FieldEvent::Unchanged;
        for k in keys {
            last = f.feed(*k, buf);
        }
        (f, last)
    }

    fn chars(s: &str) -> std::vec::Vec<Key> {
        s.chars().map(Key::Char).collect()
    }

    #[test]
    fn field_cursor_editing() {
        let mut buf = [0xaau8; 16];
        let mut keys = chars("helo");
        keys.extend([Key::Left, Key::Char('l'), Key::End, Key::Char('!')]);
        let (f, _) = typed(FieldKind::Secret, &keys, &mut buf);
        assert_eq!(f.text(&buf), "hello!");
        assert_eq!(f.cursor(), 6);
        assert!(buf[6..].iter().all(|&b| b == 0), "begin wiped the buffer");

        let mut keys = chars("abcd");
        keys.extend([Key::Home, Key::Delete, Key::Right, Key::Backspace]);
        let (f, _) = typed(FieldKind::Secret, &keys, &mut buf);
        assert_eq!((f.text(&buf), f.cursor()), ("cd", 0));
        assert!(buf[2..].iter().all(|&b| b == 0), "removed bytes are wiped");

        // Multi-byte characters move and delete as one.
        let mut keys = chars("aéb");
        keys.extend([Key::Left, Key::Left, Key::Delete]);
        let (f, _) = typed(FieldKind::Secret, &keys, &mut buf);
        assert_eq!(f.text(&buf), "ab");
        assert_eq!(f.char_counts(&buf), (1, 2));
    }

    #[test]
    fn insert_reveals_a_secret_but_not_a_path() {
        let mut buf = [0u8; 8];
        let (f, e) = typed(FieldKind::Secret, &[Key::Char('x'), Key::Insert], &mut buf);
        assert_eq!(e, FieldEvent::Changed);
        assert!(f.revealed());
        let (f, _) = typed(
            FieldKind::Secret,
            &[Key::Insert, Key::Insert, Key::Char('x')],
            &mut buf,
        );
        assert!(!f.revealed());
        let (f, e) = typed(FieldKind::Path, &[Key::Insert], &mut buf);
        assert_eq!(e, FieldEvent::Unchanged);
        assert!(f.revealed(), "a path is always shown");
        // A new prompt starts hidden again.
        let s = Screen::EnterSecret {
            row: Row::PasswordOrPin,
            unattested: false,
        };
        let mut p = Prompt::new(&s, &mut buf);
        assert_eq!(p.feed(&s, Key::Insert, &mut buf), Reaction::Redraw);
        assert!(p.field().unwrap().revealed());
        let p = Prompt::new(&s, &mut buf);
        assert!(!p.field().unwrap().revealed());
    }

    #[test]
    fn recovery_key_takes_digits_only_up_to_48() {
        let mut buf = [0u8; 64];
        let mut keys = chars("12-34 5x6");
        keys.extend(chars(&"7".repeat(60)));
        let (f, _) = typed(FieldKind::RecoveryKey, &keys, &mut buf);
        assert_eq!(f.len(), RECOVERY_DIGITS);
        assert!(f.text(&buf).starts_with("123456777"));
        assert!(buf[48..].iter().all(|&b| b == 0));
    }

    #[test]
    fn field_is_bounded_and_escape_wipes() {
        let mut buf = [0u8; 6];
        let mut keys = chars("abcdefg");
        keys.push(Key::Enter);
        let (_, e) = typed(FieldKind::Secret, &keys, &mut buf);
        assert_eq!(e, FieldEvent::Submit(6));
        assert_eq!(&buf, b"abcdef");
        let mut keys = chars("aé");
        keys.push(Key::Char('\u{7}'));
        let (f, _) = typed(FieldKind::Secret, &keys, &mut buf);
        assert_eq!(f.len(), 3, "a control character is not text");
        let mut keys = chars("abc");
        keys.push(Key::Escape);
        let (f, e) = typed(FieldKind::Secret, &keys, &mut buf);
        assert_eq!(e, FieldEvent::Cancel);
        assert_eq!(buf, [0; 6], "cancel wipes");
        assert!(f.is_empty());
        // A multi-byte character that does not fit is dropped whole.
        let mut small = [0u8; 2];
        let (f, _) = typed(FieldKind::Secret, &chars("a€"), &mut small);
        assert_eq!(f.text(&small), "a");
    }

    #[test]
    fn prompt_turns_fields_into_inputs() {
        let s = Screen::EnterPath(Level::Volume);
        let mut buf = [0u8; 32];
        let mut p = Prompt::new(&s, &mut buf);
        for c in "\\paguro\\x.efi".chars() {
            assert_eq!(p.feed(&s, Key::Char(c), &mut buf), Reaction::Redraw);
        }
        assert_eq!(p.feed(&s, Key::Up, &mut buf), Reaction::Ignore);
        assert_eq!(
            p.feed(&s, Key::Enter, &mut buf),
            Reaction::Done(Input::Secret(13))
        );
        assert_eq!(&buf[..13], b"\\paguro\\x.efi");
        assert_eq!(
            p.feed(&s, Key::Escape, &mut buf),
            Reaction::Done(Input::Escape)
        );
        assert_eq!(buf, [0; 32]);
    }

    #[test]
    fn sizes() {
        let f = |b: u64| std::format!("{}", Size::of(b));
        assert_eq!(f(0), "0 B");
        assert_eq!(f(1023), "1023 B");
        assert_eq!(f(2 << 30), "2.0 GB");
        assert_eq!(f(214 << 30), "214 GB");
        assert_eq!(f(931 << 30), "931 GB");
        assert_eq!(f(1_900_000_000_000), "1.7 TB");
        assert_eq!(f(112 << 20), "112 MB");
        assert_eq!(f((10 << 20) - 1), "10 MB");
        assert_eq!(f(u64::MAX), "16777216 TB");
    }

    #[test]
    fn names_and_kinds_of_typed_paths() {
        let mut b = [0u8; 32];
        assert_eq!(entry_name("\\paguro\\debian.vhd", &mut b, "x"), "debian");
        assert_eq!(entry_name("rescue v2.efi", &mut b, "x"), "rescue_v2");
        assert_eq!(entry_name("\\", &mut b, "recovery"), "recovery");
        assert_eq!(entry_name(&"a".repeat(40), &mut b, "x").len(), 32);
        assert_eq!(classify_path("\\paguro\\R.EFI"), EntryKind::Efi);
        assert_eq!(classify_path("\\paguro\\r.vhd"), EntryKind::Disk);
        assert_eq!(classify_path("efi"), EntryKind::Disk);
    }

    fn utf16(s: &str) -> std::vec::Vec<u16> {
        s.encode_utf16().collect()
    }

    fn listing(level: Level, names: &[(&str, bool)]) -> std::boxed::Box<DirListing> {
        let mut d = std::boxed::Box::new(DirListing::new());
        d.clear(level);
        for (n, dir) in names {
            assert!(d.push(&utf16(n), *dir, 1 << 20));
        }
        d.sort();
        d
    }

    #[test]
    fn listings_filter_sort_and_bound() {
        use crate::platform::Listing;
        let d = listing(
            Level::Volume,
            &[
                ("zeta.vhd", false),
                ("Alpha.EFI", false),
                ("notes.txt", false),
                ("beta", true),
                ("$MFT", false),
                (".", true),
                ("..", true),
                ("Arch.img", false),
                ("disk.RAW", false),
                ("a.vhdx", false),
                ("Zdir", true),
            ],
        );
        let names: std::vec::Vec<_> = (0..d.len()).map(|i| d.item(i).unwrap().name).collect();
        assert_eq!(
            names,
            [
                "beta",
                "Zdir",
                "a.vhdx",
                "Alpha.EFI",
                "Arch.img",
                "disk.RAW",
                "zeta.vhd"
            ],
            "folders first, then case-insensitive"
        );
        assert_eq!(d.item(3).unwrap().kind, EntryKind::Efi);
        assert_eq!(d.item(4).unwrap().kind, EntryKind::Disk);
        assert_eq!(d.find("disk.RAW"), Some(5));
        // The EFI partition shows folders and UEFI images only.
        let f = listing(
            Level::EfiPartition,
            &[("x.vhd", false), ("BOOTX64.EFI", false), ("EFI", true)],
        );
        assert_eq!(f.len(), 2);
        // Bad names are skipped, not truncated.
        let mut d = std::boxed::Box::new(DirListing::new());
        d.clear(Level::Volume);
        assert!(
            d.push(&[0xd800, b'a' as u16], false, 0),
            "unpaired surrogate"
        );
        assert!(d.push(&utf16("a\\b.efi"), false, 0));
        assert!(d.push(&utf16("tab\t.efi"), false, 0));
        assert!(
            d.push(&std::vec![b'a' as u16; 256], true, 0),
            "over 255 units"
        );
        assert_eq!(d.len(), 0);
        // Full: the rest is "more".
        for i in 0..crate::platform::MAX_DIR_ENTRIES {
            assert!(d.push(&utf16(&std::format!("d{i}")), true, 0));
        }
        assert!(!d.more());
        assert!(!d.push(&utf16("one-more"), true, 0));
        assert!(d.more());
        assert_eq!(d.len(), crate::platform::MAX_DIR_ENTRIES);
    }

    #[test]
    fn clicks_select_and_act() {
        // Unlock rows: a click is select + Enter; greyed and missing rows
        // do nothing.
        let mut m = menu();
        m.tpm = Err(Grey::Locked);
        m.password_or_pin = false;
        let screen = Screen::Unlock(m);
        let mut p = Prompt::new(&screen, &mut []);
        assert_eq!(p.activate(&screen, 0), Reaction::Ignore, "greyed row");
        assert_eq!(
            p.activate(&screen, 1),
            Reaction::Done(Input::Select(Row::RecoveryKey))
        );
        assert_eq!(p.selected(), 1);
        assert_eq!(p.activate(&screen, 9), Reaction::Ignore);
        assert_eq!(p.feed(&screen, MODE_KEY, &mut []), Reaction::ToggleMode);
        assert_eq!(p.feed(&screen, THEME_KEY, &mut []), Reaction::NextTheme);
        // No list: nothing to click.
        let mut p = Prompt::new(&Screen::CannotUnlock, &mut []);
        assert_eq!(p.activate(&Screen::CannotUnlock, 0), Reaction::Ignore);
        assert_eq!(p.click_field(0, &[]), Reaction::Ignore);

        // A click in the field moves its cursor, by characters.
        let screen = Screen::EnterPath(Level::Volume);
        let mut buf = [0u8; 32];
        let mut p = Prompt::new(&screen, &mut buf);
        for c in "\\é\\x".chars() {
            p.feed(&screen, Key::Char(c), &mut buf);
        }
        assert_eq!(p.click_field(1, &buf), Reaction::Redraw);
        assert_eq!(p.field().unwrap().cursor(), 1);
        assert_eq!(p.click_field(2, &buf), Reaction::Redraw);
        assert_eq!(p.field().unwrap().cursor(), 3, "after the two-byte é");
        assert_eq!(p.click_field(2, &buf), Reaction::Ignore, "no move");
        assert_eq!(
            p.click_field(99, &buf),
            Reaction::Redraw,
            "clamped to the end"
        );
        assert_eq!(p.field().unwrap().cursor(), 5);
        p.feed(&screen, Key::Char('y'), &mut buf);
        assert_eq!(p.field().unwrap().text(&buf), "\\é\\xy");
    }

    #[test]
    fn browser_clicks() {
        let d = listing(Level::Root, &[("a", true), ("b.vhd", false)]);
        let view = DirView {
            path: "\\paguro",
            listing: &*d,
            selected: 0,
            level: Level::Root,
        };
        let mut b = Browser::new(&view);
        assert_eq!(b.activate(&view, 1), Reaction::Done(Input::Entry(1)));
        assert_eq!(b.activate(&view, 2), Reaction::Done(Input::TypePath));
        assert_eq!(b.activate(&view, 3), Reaction::Done(Input::NoRoot));
        assert_eq!(b.activate(&view, 4), Reaction::Ignore);
        assert_eq!(b.selected(), 3);
        assert_eq!(b.feed(&view, MODE_KEY), Reaction::ToggleMode);
    }

    #[test]
    fn browser_keys() {
        let d = listing(
            Level::Volume,
            &[
                ("boot", true),
                ("efi", true),
                ("arch.vhd", false),
                ("rescue.efi", false),
            ],
        );
        let view = DirView {
            path: "\\paguro",
            listing: &*d,
            selected: 0,
            level: Level::Volume,
        };
        let mut b = Browser::new(&view);
        assert_eq!(b.feed(&view, Key::Up), Reaction::Ignore);
        assert_eq!(b.feed(&view, Key::Down), Reaction::Redraw);
        assert_eq!(
            b.feed(&view, Key::Right),
            Reaction::Done(Input::Entry(1)),
            "open a folder"
        );
        assert_eq!(
            b.feed(&view, Key::Char('R')),
            Reaction::Redraw,
            "type to jump"
        );
        assert_eq!(b.selected(), 3);
        assert_eq!(
            b.feed(&view, Key::Right),
            Reaction::Ignore,
            "a file does not open with ->"
        );
        assert_eq!(b.feed(&view, Key::Enter), Reaction::Done(Input::Entry(3)));
        assert_eq!(b.feed(&view, Key::End), Reaction::Redraw);
        assert_eq!(b.feed(&view, Key::Enter), Reaction::Done(Input::TypePath));
        b.set_page(2);
        assert_eq!(b.feed(&view, Key::PageUp), Reaction::Redraw);
        assert_eq!(b.selected(), 2);
        assert_eq!(b.feed(&view, Key::Home), Reaction::Redraw);
        assert_eq!(b.feed(&view, Key::PageDown), Reaction::Redraw);
        assert_eq!(b.selected(), 2);
        assert_eq!(b.feed(&view, Key::Left), Reaction::Done(Input::Parent));
        assert_eq!(b.feed(&view, Key::Backspace), Reaction::Done(Input::Parent));
        assert_eq!(b.feed(&view, Key::Escape), Reaction::Done(Input::Escape));
        assert_eq!(b.feed(&view, Key::Char('q')), Reaction::Ignore);
        assert_eq!(b.feed(&view, THEME_KEY), Reaction::NextTheme);
        let root = DirView { path: "\\", ..view };
        assert_eq!(
            b.feed(&root, Key::Left),
            Reaction::Ignore,
            "no parent at the root"
        );
        // The start row is clamped; an empty folder has only "Type a path".
        let empty = listing(Level::Volume, &[]);
        let ev = DirView {
            path: "\\x",
            listing: &*empty,
            selected: 9,
            level: Level::Volume,
        };
        let mut b = Browser::new(&ev);
        assert_eq!(b.selected(), 0);
        assert_eq!(b.feed(&ev, Key::Enter), Reaction::Done(Input::TypePath));
        // The root hint adds "No root" after "Type a path".
        let root = listing(
            Level::Root,
            &[("a.vhd", false), ("b.efi", false), ("dir", true)],
        );
        assert_eq!(
            crate::platform::Listing::len(&*root),
            2,
            "no UEFI images when picking a root"
        );
        let rv = DirView {
            path: "\\paguro",
            listing: &*root,
            selected: 0,
            level: Level::Root,
        };
        let mut b = Browser::new(&rv);
        assert_eq!(b.feed(&rv, Key::End), Reaction::Redraw);
        assert_eq!(b.feed(&rv, Key::Enter), Reaction::Done(Input::NoRoot));
        assert_eq!(b.feed(&rv, Key::Up), Reaction::Redraw);
        assert_eq!(b.feed(&rv, Key::Enter), Reaction::Done(Input::TypePath));
        // '/' or '\\' starts typing a path from any row.
        assert_eq!(b.feed(&rv, Key::Char('/')), Reaction::Done(Input::TypePath));
        assert_eq!(
            b.feed(&view, Key::Char('\\')),
            Reaction::Done(Input::TypePath)
        );
        assert_eq!(b.feed(&view, KEYBOARD_KEY), Reaction::ChooseKeyboard);
        assert_eq!(b.feed(&view, LANGUAGE_KEY), Reaction::ChooseLanguage);
    }

    #[test]
    fn typed_paths_are_normalized() {
        let mut out = [0u8; 64];
        for (typed, want, drive) in [
            ("\\paguro\\debian.vhd", "\\paguro\\debian.vhd", false),
            ("/paguro/debian.vhd", "\\paguro\\debian.vhd", false),
            ("paguro\\debian.vhd", "\\paguro\\debian.vhd", false),
            ("C:\\paguro\\debian.vhd", "\\paguro\\debian.vhd", true),
            ("d:/paguro//x.efi/", "\\paguro\\x.efi", true),
            ("  \\a\\\\b  ", "\\a\\b", false),
            ("C:", "\\", true),
            ("", "\\", false),
            ("1:\\a", "\\1:\\a", false),
            ("\\C:\\a", "\\a", true),
        ] {
            assert_eq!(
                normalize_path(typed, &mut out),
                Some((want, drive)),
                "{typed:?}"
            );
        }
        assert_eq!(normalize_path("\\abcdef", &mut [0u8; 4]), None, "too long");
    }

    #[test]
    fn natural_order() {
        use crate::platform::natural_cmp;
        use core::cmp::Ordering::*;
        for (a, b, o) in [
            ("disk2", "disk10", Less),
            ("Disk2", "disk10", Less),
            ("disk10", "disk9", Greater),
            ("a", "B", Less),
            ("a01", "a1", Greater),
            ("a1", "a01", Less),
            ("a1b", "a1b", Equal),
            ("x", "x1", Less),
            ("v1.10.img", "v1.9.img", Greater),
            ("99999999999999999999999", "100000000000000000000000", Less),
            ("", "", Equal),
        ] {
            assert_eq!(natural_cmp(a, b), o, "{a} vs {b}");
            assert_eq!(natural_cmp(b, a), o.reverse(), "{b} vs {a}");
        }
    }

    #[test]
    fn choosers_start_on_the_current_choice() {
        use paguro_core::config::Keyboard;
        let s = Screen::ChooseKeyboard {
            current: Keyboard::Fr,
        };
        let mut p = Prompt::new(&s, &mut []);
        assert_eq!(p.selected(), 3);
        assert_eq!(items(&s).len(), Keyboard::ALL.len());
        assert_eq!(p.feed(&s, Key::Down, &mut []), Reaction::Redraw);
        assert_eq!(
            p.feed(&s, Key::Enter, &mut []),
            Reaction::Done(Input::Choose(4))
        );
        assert_eq!(
            p.feed(&s, Key::Escape, &mut []),
            Reaction::Done(Input::Escape)
        );
        let s = Screen::ChooseLanguage {
            current: 2,
            count: 5,
        };
        let mut p = Prompt::new(&s, &mut []);
        assert_eq!(p.selected(), 2);
        p.set_page(2);
        assert_eq!(p.feed(&s, Key::PageDown, &mut []), Reaction::Redraw);
        assert_eq!(p.selected(), 4);
        assert_eq!(p.feed(&s, Key::PageDown, &mut []), Reaction::Ignore);
        assert_eq!(p.feed(&s, Key::PageUp, &mut []), Reaction::Redraw);
        assert_eq!(p.selected(), 2);
        assert_eq!(p.feed(&s, KEYBOARD_KEY, &mut []), Reaction::ChooseKeyboard);
        assert_eq!(p.feed(&s, LANGUAGE_KEY, &mut []), Reaction::ChooseLanguage);
    }
}
