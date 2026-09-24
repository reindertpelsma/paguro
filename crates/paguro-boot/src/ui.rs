//! What every front end shares: the key model, the text-entry editor of
//! INTERFACES.md §13.3, list navigation, the key → [`Input`] mapping, and the
//! text rendering used when there is no graphics output. Pure functions and
//! plain state, so the firmware adapter only draws and forwards keys, and all
//! of this is tested on the host.
//!
//! Rules from DESIGN.md §4.1 "Screens" that apply here: the name on every
//! screen; Esc always leads somewhere; rows labelled by cost; an unattested
//! prompt says so; error codes are not in the message.
//!
//! A secret lives only in the caller's buffer. [`Field`] keeps offsets, never
//! a copy, and wipes whatever it removes; bytes past the entered text are
//! always zero.

use core::fmt::{self, Write};

use crate::platform::{
    Grey, Input, Notice, Row, Screen, TargetKind, UnlockMenu, VolumeChoice, VolumeFormat,
};

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

/// The key that cycles the compiled-in theme variants (high contrast…).
pub const THEME_KEY: Key = Key::Function(2);

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
        Screen::EnterPath => Some(FieldKind::Path),
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
    Target(u8),
    TypePath,
    Root(u8),
    NoRoot,
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
            Item::Volume(i) | Item::Target(i) | Item::Root(i) => Some(Input::Choose(i)),
            Item::TypePath => Some(Input::TypePath),
            Item::NoRoot => Some(Input::NoRoot),
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
            items: [Item::NoRoot; MAX_ITEMS],
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
        Screen::SelectTarget(t) => {
            for i in 0..t.count.min(crate::platform::MAX_CHOICES as u8) {
                out.push(Item::Target(i));
            }
            out.push(Item::TypePath);
        }
        Screen::SelectRoot { roots, .. } => {
            for i in 0..roots.count.min(crate::platform::MAX_CHOICES as u8) {
                out.push(Item::Root(i));
            }
            out.push(Item::NoRoot);
        }
        _ => {}
    }
    out
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
    Done(Input),
}

/// The interaction state of one shown screen: the list cursor and the field.
/// Created per prompt, so a revealed secret is hidden again on the next one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Prompt {
    selected: usize,
    field: Option<Field>,
}

impl Prompt {
    /// Start a prompt for `screen`. A field's buffer is wiped first.
    pub fn new(screen: &Screen, buf: &mut [u8]) -> Prompt {
        let items = items(screen);
        let selected = items.as_slice().iter().position(Item::enabled).unwrap_or(0);
        Prompt {
            selected,
            field: field_kind(screen).map(|k| Field::begin(k, buf)),
        }
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

    pub fn feed(&mut self, screen: &Screen, key: Key, buf: &mut [u8]) -> Reaction {
        if key == THEME_KEY {
            return Reaction::NextTheme;
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
                Key::Up | Key::PageUp => {
                    return if self.step(&items, false) {
                        Reaction::Redraw
                    } else {
                        Reaction::Ignore
                    };
                }
                Key::Down | Key::PageDown => {
                    return if self.step(&items, true) {
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
pub fn classify_path(path: &str) -> TargetKind {
    let b = path.as_bytes();
    match b.len().checked_sub(4).and_then(|i| b.get(i..)) {
        Some(ext) if ext.eq_ignore_ascii_case(b".efi") => TargetKind::EfiFile,
        _ => TargetKind::Disk,
    }
}

// ---------------------------------------------------------------------------
// Text fallback (no graphics output)

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

const UNATTESTED: &str = "   (configuration unverified: this prompt is unattested)\r\n";

fn volume_line(w: &mut dyn Write, i: usize, v: &VolumeChoice) -> fmt::Result {
    let fmt = match v.format {
        VolumeFormat::BitLocker => "BitLocker",
        VolumeFormat::Ntfs => "NTFS",
    };
    write!(
        w,
        " {} Disk {}, partition {}   {}   {fmt}",
        i + 1,
        v.disk,
        v.partition,
        Size::of(v.bytes)
    )?;
    if !v.name.is_empty() {
        write!(w, "   {}", v.name.as_str())?;
    }
    w.write_str("\r\n")
}

/// Render `screen` as CRLF-terminated lines (the no-GOP fallback, and the
/// serial mirror of what the graphical front end shows).
pub fn render(screen: &Screen, w: &mut dyn Write) -> fmt::Result {
    header(w)?;
    match screen {
        Screen::Unlock(m) => {
            w.write_str("   Unlock Linux\r\n")?;
            if m.unattested {
                w.write_str(UNATTESTED)?;
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
        Screen::PathRefused => w.write_str("   That is not a usable path on this volume.\r\n"),
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
        Screen::SelectVolume(v) => {
            w.write_str("   Which volume holds your Linux installation?\r\n")?;
            w.write_str(UNATTESTED)?;
            w.write_str("\r\n")?;
            for (i, c) in v.as_slice().iter().enumerate() {
                volume_line(w, i, c)?;
            }
            Ok(())
        }
        Screen::SelectTarget(t) => {
            w.write_str("   What should start?\r\n")?;
            w.write_str(UNATTESTED)?;
            w.write_str("\r\n")?;
            for (i, e) in t.as_slice().iter().enumerate() {
                let kind = match e.kind {
                    TargetKind::Disk => "disk",
                    TargetKind::EfiFile => "UEFI application",
                };
                write!(
                    w,
                    " {} \\paguro\\{}   {}   {kind}\r\n",
                    i + 1,
                    e.name.as_str(),
                    Size::of(e.bytes)
                )?;
            }
            write!(w, " {} Type a path\r\n", t.count as usize + 1)
        }
        Screen::EnterPath => {
            w.write_str(UNATTESTED)?;
            w.write_str("   Path on the volume: ")
        }
        Screen::SelectRoot { efi, roots } => {
            write!(w, "   Which disk is the Linux root for {}?\r\n", efi.as_str())?;
            w.write_str(UNATTESTED)?;
            w.write_str("\r\n")?;
            for (i, e) in roots.as_slice().iter().enumerate() {
                write!(w, " {} \\paguro\\{}\r\n", i + 1, e.name.as_str())?;
            }
            write!(w, " {} None -- Linux asks\r\n", roots.count as usize + 1)
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

/// The text fallback's field line after an edit: CR, the prompt's
/// indentation, the text (bullets while hidden, the recovery key grouped),
/// and blanks over what was there.
pub fn render_field_line(f: &Field, buf: &[u8], w: &mut dyn Write) -> fmt::Result {
    w.write_str("\r   > ")?;
    for (i, c) in f.text(buf).chars().enumerate() {
        if f.kind() == FieldKind::RecoveryKey && i > 0 && i % RECOVERY_GROUP == 0 {
            w.write_char('-')?;
        }
        w.write_char(if f.revealed() { c } else { '*' })?;
    }
    // One blank covers the character a Backspace or Delete removed.
    w.write_str(" ")
}

/// Whether a screen waits for a key. "That did not unlock" is shown and the
/// unlock list follows at once, so a retry costs no extra keystroke.
pub const fn needs_key(screen: &Screen) -> bool {
    !matches!(screen, Screen::Incorrect | Screen::PathRefused)
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
        Screen::SelectTarget(t) => match (key, c) {
            (Key::Escape, _) => Some(Input::Escape),
            (_, Some('w')) => Some(Input::StartWindows),
            _ => match digit(t.count.saturating_add(1)) {
                Some(i) if i == t.count => Some(Input::TypePath),
                other => other.map(Input::Choose),
            },
        },
        Screen::SelectRoot { roots, .. } => match (key, c) {
            (Key::Escape, _) => Some(Input::Escape),
            _ => match digit(roots.count.saturating_add(1)) {
                Some(i) if i == roots.count => Some(Input::NoRoot),
                other => other.map(Input::Choose),
            },
        },
        Screen::Incorrect
        | Screen::PathRefused
        | Screen::TpmLocked
        | Screen::Notice(Notice::SealOverPlaintext)
        | Screen::Notice(Notice::NotImplemented) => Some(Input::Continue),
        Screen::EnterSecret { .. } | Screen::EnterPath => None,
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::platform::{Label, Target, TargetList, VolumeList};
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

    fn targets(names: &[(&str, TargetKind)]) -> TargetList {
        let mut t = TargetList::new();
        for (n, k) in names {
            t.push(Target {
                name: Label::new(n).unwrap(),
                bytes: 214 << 30,
                kind: *k,
            });
        }
        t
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
            Screen::PathRefused,
            Screen::CannotUnlock,
            Screen::ConfigInvalid,
            Screen::TpmLocked,
            Screen::NoInstallation,
            Screen::SelectVolume(volumes(2)),
            Screen::SelectTarget(targets(&[("debian.vhd", TargetKind::Disk)])),
            Screen::EnterPath,
            Screen::SelectRoot {
                efi: Label::new("rescue.efi").unwrap(),
                roots: targets(&[("a.vhd", TargetKind::Disk)]),
            },
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
        let vl = text(&Screen::SelectVolume(volumes(2)));
        assert!(vl.contains("Disk 1, partition 3   931 GB   BitLocker   Basic data partition"));
        assert!(vl.contains("unattested"));
        let tl = text(&screens[14]);
        assert!(
            tl.contains("\\paguro\\debian.vhd   214 GB   disk") && tl.contains("2 Type a path")
        );
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
        let st = Screen::SelectTarget(targets(&[("a.vhd", TargetKind::Disk)]));
        assert_eq!(map_key(&st, Key::Char('1')), Some(Input::Choose(0)));
        assert_eq!(map_key(&st, Key::Char('2')), Some(Input::TypePath));
        assert_eq!(map_key(&st, Key::Char('3')), None);
        let sr = Screen::SelectRoot {
            efi: Label::EMPTY,
            roots: targets(&[("a.vhd", TargetKind::Disk), ("b.vhd", TargetKind::Disk)]),
        };
        assert_eq!(map_key(&sr, Key::Char('2')), Some(Input::Choose(1)));
        assert_eq!(map_key(&sr, Key::Char('3')), Some(Input::NoRoot));
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
    fn target_and_root_lists_end_with_their_escape_hatch() {
        let st = Screen::SelectTarget(TargetList::new());
        assert_eq!(items(&st).as_slice(), &[Item::TypePath]);
        let mut buf = [0u8; 0];
        let mut p = Prompt::new(&st, &mut buf);
        assert_eq!(
            p.feed(&st, Key::Enter, &mut buf),
            Reaction::Done(Input::TypePath)
        );
        let sr = Screen::SelectRoot {
            efi: Label::EMPTY,
            roots: targets(&[("a.vhd", TargetKind::Disk)]),
        };
        let mut p = Prompt::new(&sr, &mut buf);
        assert_eq!(p.feed(&sr, Key::End, &mut buf), Reaction::Redraw);
        assert_eq!(
            p.feed(&sr, Key::Enter, &mut buf),
            Reaction::Done(Input::NoRoot)
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
        let mut out = String::new();
        render_field_line(&f, &buf, &mut out).unwrap();
        assert!(out.starts_with("\r   > ******-******-"), "{out:?}");
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
        let s = Screen::EnterPath;
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
        assert_eq!(classify_path("\\paguro\\R.EFI"), TargetKind::EfiFile);
        assert_eq!(classify_path("\\paguro\\r.vhd"), TargetKind::Disk);
        assert_eq!(classify_path("efi"), TargetKind::Disk);
    }
}
