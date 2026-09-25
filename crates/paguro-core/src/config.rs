//! The `paguro.ini` schema v1 (INTERFACES.md §3.2) over the frozen grammar of
//! [`crate::ini`].
//!
//! Only reached in stage 2, after the whole file's SHA-256 matched the firmware
//! variable (or with Secure Boot off, after nothing — which is why it is still
//! hardened). Rules on top of the grammar (§3.1):
//!
//! - duplicate keys within a known section are an error (also across repeated
//!   `[section]` headers of the same name);
//! - unknown sections are ignored; unknown keys in a known section are an error;
//! - keys before the first `[section]` are an error;
//! - every value is typed and bounded here, so nothing downstream re-validates;
//! - errors about a section header (bad entry name, too many entries) carry the
//!   line of the section's first key: the grammar yields entries, not headers,
//!   and a header with no keys configures nothing.
//!
//! Output is borrowed from the input buffer: no allocation, fixed capacity
//! ([`MAX_ENTRIES`]).
//!
//! `#` starts a comment only at the beginning of a line (the frozen grammar);
//! the trailing annotations in §3.2's example are documentation, and an NTFS
//! path may legitimately contain `#`.

use crate::guid::{Guid, GuidError};
use crate::ini::{self, IniError};

pub const MAX_ENTRIES: usize = 16;
pub const MAX_NAME: usize = 32;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_COMPONENTS: usize = 32;
pub const MAX_COMPONENT_UTF16: usize = 255;
/// The UEFI image when `efi` is absent: the removable-media path for the
/// architecture the loader runs on.
#[cfg(not(target_arch = "aarch64"))]
pub const DEFAULT_EFI: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
#[cfg(target_arch = "aarch64")]
pub const DEFAULT_EFI: &str = "\\EFI\\BOOT\\BOOTAA64.EFI";
/// The first line [`write`] emits.
pub const HEADER_COMMENT: &str = "# paguro configuration. Not hand-editable: use `paguro config`.";
/// The section-name prefix of a boot entry.
pub const ENTRY_PREFIX: &str = "Boot.";
/// The only schema version (`[Paguro] version`).
pub const VERSION: &str = "1";
/// Characters NTFS/Win32 (and FAT long names) forbid in a path component,
/// besides controls.
const FORBIDDEN_PATH_CHARS: &str = "/:*?\"<>|";
/// DEL, refused like the C0 controls below `' '`.
const DEL: char = '\u{7f}';

/// Section names of schema v1 (INTERFACES.md §3.2); boot entries are
/// [`ENTRY_PREFIX`]`<name>`.
pub mod section {
    pub const PAGURO: &str = "Paguro";
    pub const TPM: &str = "TPM";
    pub const SETUP_TPM: &str = "SetupTPM";
    pub const PASSPHRASE: &str = "Passphrase";
    pub const UI: &str = "UI";
}

/// Keys of schema v1 (INTERFACES.md §3.2), by section.
pub mod key {
    /// `[Paguro]`
    pub const VERSION: &str = "version";
    pub const DEFAULT: &str = "default";
    /// `[Boot.<name>]`
    pub const VOLUME: &str = "volume";
    pub const ROOT: &str = "root";
    pub const EFI_DISK: &str = "efi_disk";
    pub const EFI: &str = "efi";
    pub const EFI_FILE: &str = "efi_file";
    /// `[TPM]`, `[SetupTPM]`, `[Passphrase]`
    pub const ENABLED: &str = "enabled";
    /// `[UI]`
    pub const THEME: &str = "theme";
    pub const MODE: &str = "mode";
    pub const KEYBOARD: &str = "keyboard";
}

/// Boolean values.
const FALSE: &str = "0";
const TRUE: &str = "1";

/// Where an entry's next UEFI image is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Efi<'a> {
    /// `efi` (FAT path) on the FAT32 of `efi_disk` (NTFS path; the entry's
    /// `root` when absent). The primary mode.
    Disk { disk: &'a str, path: &'a str },
    /// `efi_file`: a UEFI image directly on the NTFS volume, loaded from a
    /// buffer (no `DeviceHandle`). Excludes `efi_disk` and `efi`.
    File(&'a str),
}

/// One `[Boot.<name>]` section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub name: &'a str,
    /// GPT partition GUID of the NTFS volume holding all the entry's files.
    pub volume: Guid,
    /// The Linux root disk: an absolute NTFS path on `volume`. Required
    /// unless the UEFI image is an `efi_file`.
    pub root: Option<&'a str>,
    pub efi: Efi<'a>,
}

impl<'a> Entry<'a> {
    pub const EMPTY: Entry<'static> = Entry {
        name: "",
        volume: Guid::ZERO,
        root: None,
        efi: Efi::File(""),
    };

    /// The disk holding the UEFI image, if it is on a disk's FAT32.
    pub fn efi_disk(&self) -> Option<&'a str> {
        match self.efi {
            Efi::Disk { disk, .. } => Some(disk),
            Efi::File(_) => None,
        }
    }

    /// The UEFI image's file (disk or `efi_file`) when it is not the root:
    /// what the handoff forwards besides the root.
    pub fn separate_efi(&self) -> Option<&'a str> {
        let f = match self.efi {
            Efi::Disk { disk, .. } => disk,
            Efi::File(f) => f,
        };
        (Some(f) != self.root).then_some(f)
    }

    /// Whether this entry is well-formed: valid name and paths, and a root
    /// whenever the UEFI image is on a disk.
    pub fn is_valid(&self) -> bool {
        check_name(self.name)
            && self.root.is_none_or(|r| check_path(r).is_ok())
            && match self.efi {
                Efi::Disk { disk, path } => {
                    self.root.is_some() && check_path(disk).is_ok() && check_path(path).is_ok()
                }
                Efi::File(f) => check_path(f).is_ok(),
            }
    }
}

/// `[UI] theme`: the compiled-in theme variant the loader starts in
/// (INTERFACES.md §13.2a). An enum selecting compiled-in data, never display
/// data.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UiTheme {
    #[default]
    Dark,
    Light,
    DarkContrast,
    LightContrast,
}

impl UiTheme {
    /// In F2 order: the index of each variant in the compiled-in theme table.
    pub const ALL: [UiTheme; 4] = [
        UiTheme::Dark,
        UiTheme::Light,
        UiTheme::DarkContrast,
        UiTheme::LightContrast,
    ];

    /// The value in `paguro.ini`, and the compiled-in variant's name.
    pub const fn name(self) -> &'static str {
        match self {
            UiTheme::Dark => "dark",
            UiTheme::Light => "light",
            UiTheme::DarkContrast => "dark-contrast",
            UiTheme::LightContrast => "light-contrast",
        }
    }

    pub fn from_name(s: &str) -> Option<UiTheme> {
        UiTheme::ALL.into_iter().find(|t| t.name() == s)
    }
}

/// `[UI] mode`: graphics, text, or both (INTERFACES.md §13.2a).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UiMode {
    /// Graphics on every GOP device and the text UI on each serial console;
    /// the text UI on ConOut when there is no GOP.
    #[default]
    Auto,
    /// GOP only (the text UI on ConOut when there is no GOP).
    Graphics,
    /// The text UI only, on ConOut.
    Text,
}

impl UiMode {
    pub const ALL: [UiMode; 3] = [UiMode::Auto, UiMode::Graphics, UiMode::Text];

    pub const fn name(self) -> &'static str {
        match self {
            UiMode::Auto => "auto",
            UiMode::Graphics => "graphics",
            UiMode::Text => "text",
        }
    }

    pub fn from_name(s: &str) -> Option<UiMode> {
        UiMode::ALL.into_iter().find(|m| m.name() == s)
    }
}

/// `[UI] keyboard`: the layout typed text is read in (INTERFACES.md §13.5).
/// Firmware maps keys as a US keyboard; the loader turns that back into what
/// this layout produces for the same physical key, from a compiled-in table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Keyboard {
    #[default]
    Us,
    Uk,
    De,
    Fr,
    Es,
    Be,
    ChDe,
    NlIntl,
}

impl Keyboard {
    /// In F4 order.
    pub const ALL: [Keyboard; 8] = [
        Keyboard::Us,
        Keyboard::Uk,
        Keyboard::De,
        Keyboard::Fr,
        Keyboard::Es,
        Keyboard::Be,
        Keyboard::ChDe,
        Keyboard::NlIntl,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Keyboard::Us => "us",
            Keyboard::Uk => "uk",
            Keyboard::De => "de",
            Keyboard::Fr => "fr",
            Keyboard::Es => "es",
            Keyboard::Be => "be",
            Keyboard::ChDe => "ch-de",
            Keyboard::NlIntl => "nl-intl",
        }
    }

    pub fn from_name(s: &str) -> Option<Keyboard> {
        Keyboard::ALL.into_iter().find(|k| k.name() == s)
    }

    /// The next layout (F4).
    pub fn next(self) -> Keyboard {
        let i = Keyboard::ALL.iter().position(|k| *k == self).unwrap_or(0);
        Keyboard::ALL
            .get((i + 1) % Keyboard::ALL.len())
            .copied()
            .unwrap_or(Keyboard::Us)
    }
}

/// The `[UI]` section. Absent: dark / auto / us — which is also what
/// recovery, which never reads the file, starts with.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ui {
    pub theme: UiTheme,
    pub mode: UiMode,
    pub keyboard: Keyboard,
}

impl Ui {
    pub const DEFAULT: Ui = Ui {
        theme: UiTheme::Dark,
        mode: UiMode::Auto,
        keyboard: Keyboard::Us,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config<'a> {
    /// Index into `entries` of the `default` entry.
    pub default: usize,
    pub entries: [Entry<'a>; MAX_ENTRIES],
    pub entry_count: usize,
    pub tpm: bool,
    pub setup_tpm: bool,
    pub passphrase: bool,
    pub ui: Ui,
}

impl<'a> Config<'a> {
    pub fn entries(&self) -> &[Entry<'a>] {
        self.entries.get(..self.entry_count).unwrap_or(&[])
    }
    pub fn default_entry(&self) -> Option<&Entry<'a>> {
        self.entries().get(self.default)
    }
}

/// Which required key was missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    PaguroSection,
    Version,
    Default,
    /// An entry without `volume`; the index is the order of first appearance.
    EntryVolume(usize),
    /// An entry with neither `root` nor `efi_file`.
    EntryRoot(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    Empty,
    NotAbsolute,
    TooLong,
    TooManyComponents,
    EmptyComponent,
    DotComponent,
    ComponentTooLong,
    BadChar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Ini(IniError),
    KeyOutsideSection {
        line: usize,
    },
    DuplicateKey {
        line: usize,
    },
    UnknownKey {
        line: usize,
    },
    Missing(Missing),
    UnsupportedVersion {
        line: usize,
    },
    BadInteger {
        line: usize,
    },
    BadBool {
        line: usize,
    },
    /// A `[UI]` value that is not one of the documented names.
    BadChoice {
        line: usize,
    },
    BadGuid {
        line: usize,
        err: GuidError,
    },
    BadEntryName {
        line: usize,
    },
    TooManyEntries {
        line: usize,
    },
    BadPath {
        line: usize,
        err: PathError,
    },
    /// `efi_file` together with `efi_disk` or `efi` (the later key's line).
    EfiFileConflict {
        line: usize,
    },
    /// `default` names no `[Boot.*]` section.
    DefaultNotFound,
}

impl From<IniError> for ConfigError {
    fn from(e: IniError) -> Self {
        ConfigError::Ini(e)
    }
}

/// `[A-Za-z0-9_-]{1,32}`.
pub fn check_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// An absolute backslash path: `\a\b`, no empty, `.` or `..` components, at most
/// 32 components of at most 255 UTF-16 units, at most 1024 bytes, and none of
/// the characters NTFS/Win32 (and FAT long names) forbid.
pub fn check_path(s: &str) -> Result<(), PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    let Some(rest) = s.strip_prefix('\\') else {
        return Err(PathError::NotAbsolute);
    };
    let mut n = 0usize;
    for comp in rest.split('\\') {
        n += 1;
        if n > MAX_COMPONENTS {
            return Err(PathError::TooManyComponents);
        }
        if comp.is_empty() {
            return Err(PathError::EmptyComponent);
        }
        if comp == "." || comp == ".." {
            return Err(PathError::DotComponent);
        }
        if comp.chars().map(char::len_utf16).sum::<usize>() > MAX_COMPONENT_UTF16 {
            return Err(PathError::ComponentTooLong);
        }
        if comp
            .chars()
            .any(|c| c < ' ' || c == DEL || FORBIDDEN_PATH_CHARS.contains(c))
        {
            return Err(PathError::BadChar);
        }
    }
    Ok(())
}

fn parse_bool(v: &str, line: usize) -> Result<bool, ConfigError> {
    match v {
        FALSE => Ok(false),
        TRUE => Ok(true),
        _ => Err(ConfigError::BadBool { line }),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section<'a> {
    None,
    Paguro,
    Entry(usize),
    Tpm,
    SetupTpm,
    Passphrase,
    Ui,
    Ignored(&'a str),
}

/// Seen-key bits, one mask per known section.
const K_VERSION: u8 = 1;
const K_DEFAULT: u8 = 2;
const K_VOLUME: u8 = 1;
const K_ROOT: u8 = 2;
const K_EFI_DISK: u8 = 4;
const K_EFI: u8 = 8;
const K_EFI_FILE: u8 = 16;
const K_ENABLED: u8 = 1;
const K_THEME: u8 = 1;
const K_MODE: u8 = 2;
const K_KEYBOARD: u8 = 4;

fn mark(seen: &mut u8, bit: u8, line: usize) -> Result<(), ConfigError> {
    if *seen & bit != 0 {
        return Err(ConfigError::DuplicateKey { line });
    }
    *seen |= bit;
    Ok(())
}

fn path_value(v: &str, line: usize) -> Result<&str, ConfigError> {
    check_path(v).map_err(|err| ConfigError::BadPath { line, err })?;
    Ok(v)
}

/// Parse and validate. A malformed file is refused whole.
pub fn parse(input: &[u8]) -> Result<Config<'_>, ConfigError> {
    let mut cfg = Config {
        default: 0,
        entries: [Entry::EMPTY; MAX_ENTRIES],
        entry_count: 0,
        tpm: true,
        setup_tpm: true,
        passphrase: false,
        ui: Ui::DEFAULT,
    };
    let mut paguro_section = false;
    let mut paguro_seen = 0u8;
    let mut entry_seen = [0u8; MAX_ENTRIES];
    // Raw per-entry values, assembled into `Entry::efi` at the end.
    let mut efi_disk: [Option<&str>; MAX_ENTRIES] = [None; MAX_ENTRIES];
    let mut efi_path: [Option<&str>; MAX_ENTRIES] = [None; MAX_ENTRIES];
    let mut efi_file: [Option<&str>; MAX_ENTRIES] = [None; MAX_ENTRIES];
    let mut tpm_seen = 0u8;
    let mut setup_seen = 0u8;
    let mut pass_seen = 0u8;
    let mut ui_seen = 0u8;
    let mut default_name: Option<&str> = None;
    let mut cur_name: &str = "";
    let mut sect = Section::None;

    for entry in ini::parse(input)? {
        let e = entry?;
        let line = e.line;
        if e.section != cur_name || sect == Section::None {
            cur_name = e.section;
            sect = match e.section {
                "" => Section::None,
                section::PAGURO => {
                    paguro_section = true;
                    Section::Paguro
                }
                section::TPM => Section::Tpm,
                section::SETUP_TPM => Section::SetupTpm,
                section::PASSPHRASE => Section::Passphrase,
                section::UI => Section::Ui,
                s => match s.strip_prefix(ENTRY_PREFIX) {
                    Some(name) => {
                        if !check_name(name) {
                            return Err(ConfigError::BadEntryName { line });
                        }
                        let found = cfg.entries().iter().position(|i| i.name == name);
                        let idx = match found {
                            Some(i) => i,
                            None => {
                                let i = cfg.entry_count;
                                let slot = cfg
                                    .entries
                                    .get_mut(i)
                                    .ok_or(ConfigError::TooManyEntries { line })?;
                                slot.name = name;
                                cfg.entry_count += 1;
                                i
                            }
                        };
                        Section::Entry(idx)
                    }
                    None => Section::Ignored(s),
                },
            };
        }
        let v = e.value;
        match sect {
            Section::None => return Err(ConfigError::KeyOutsideSection { line }),
            Section::Ignored(_) => {}
            Section::Paguro => match e.key {
                key::VERSION => {
                    mark(&mut paguro_seen, K_VERSION, line)?;
                    if v != VERSION {
                        return Err(if !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()) {
                            ConfigError::UnsupportedVersion { line }
                        } else {
                            ConfigError::BadInteger { line }
                        });
                    }
                }
                key::DEFAULT => {
                    mark(&mut paguro_seen, K_DEFAULT, line)?;
                    if !check_name(v) {
                        return Err(ConfigError::BadEntryName { line });
                    }
                    default_name = Some(v);
                }
                _ => return Err(ConfigError::UnknownKey { line }),
            },
            Section::Entry(idx) => {
                let seen = entry_seen
                    .get_mut(idx)
                    .ok_or(ConfigError::TooManyEntries { line })?;
                let ent = cfg
                    .entries
                    .get_mut(idx)
                    .ok_or(ConfigError::TooManyEntries { line })?;
                match e.key {
                    key::VOLUME => {
                        mark(seen, K_VOLUME, line)?;
                        ent.volume =
                            Guid::parse(v).map_err(|err| ConfigError::BadGuid { line, err })?;
                    }
                    key::ROOT => {
                        mark(seen, K_ROOT, line)?;
                        ent.root = Some(path_value(v, line)?);
                    }
                    key::EFI_DISK | key::EFI | key::EFI_FILE => {
                        let (bit, store) = match e.key {
                            key::EFI_DISK => (K_EFI_DISK, &mut efi_disk),
                            key::EFI => (K_EFI, &mut efi_path),
                            _ => (K_EFI_FILE, &mut efi_file),
                        };
                        mark(seen, bit, line)?;
                        let others = if bit == K_EFI_FILE {
                            K_EFI_DISK | K_EFI
                        } else {
                            K_EFI_FILE
                        };
                        if *seen & others != 0 {
                            return Err(ConfigError::EfiFileConflict { line });
                        }
                        let dst = store
                            .get_mut(idx)
                            .ok_or(ConfigError::TooManyEntries { line })?;
                        *dst = Some(path_value(v, line)?);
                    }
                    _ => return Err(ConfigError::UnknownKey { line }),
                }
            }
            Section::Ui => match e.key {
                key::THEME => {
                    mark(&mut ui_seen, K_THEME, line)?;
                    cfg.ui.theme = UiTheme::from_name(v).ok_or(ConfigError::BadChoice { line })?;
                }
                key::MODE => {
                    mark(&mut ui_seen, K_MODE, line)?;
                    cfg.ui.mode = UiMode::from_name(v).ok_or(ConfigError::BadChoice { line })?;
                }
                key::KEYBOARD => {
                    mark(&mut ui_seen, K_KEYBOARD, line)?;
                    cfg.ui.keyboard =
                        Keyboard::from_name(v).ok_or(ConfigError::BadChoice { line })?;
                }
                _ => return Err(ConfigError::UnknownKey { line }),
            },
            Section::Tpm | Section::SetupTpm | Section::Passphrase => {
                if e.key != key::ENABLED {
                    return Err(ConfigError::UnknownKey { line });
                }
                let (seen, flag) = match sect {
                    Section::Tpm => (&mut tpm_seen, &mut cfg.tpm),
                    Section::SetupTpm => (&mut setup_seen, &mut cfg.setup_tpm),
                    _ => (&mut pass_seen, &mut cfg.passphrase),
                };
                mark(seen, K_ENABLED, line)?;
                *flag = parse_bool(v, line)?;
            }
        }
    }

    if !paguro_section {
        return Err(ConfigError::Missing(Missing::PaguroSection));
    }
    for (bit, what) in [(K_VERSION, Missing::Version), (K_DEFAULT, Missing::Default)] {
        if paguro_seen & bit == 0 {
            return Err(ConfigError::Missing(what));
        }
    }
    for (i, ((seen, ent), ((disk, path), file))) in entry_seen
        .iter()
        .zip(cfg.entries.iter_mut())
        .zip(efi_disk.iter().zip(efi_path.iter()).zip(efi_file.iter()))
        .take(cfg.entry_count)
        .enumerate()
    {
        if seen & K_VOLUME == 0 {
            return Err(ConfigError::Missing(Missing::EntryVolume(i)));
        }
        ent.efi = match (*file, ent.root) {
            (Some(f), _) => Efi::File(f),
            (None, Some(root)) => Efi::Disk {
                disk: disk.unwrap_or(root),
                path: path.unwrap_or(DEFAULT_EFI),
            },
            (None, None) => return Err(ConfigError::Missing(Missing::EntryRoot(i))),
        };
    }
    let default_name = default_name.ok_or(ConfigError::Missing(Missing::Default))?;
    cfg.default = cfg
        .entries()
        .iter()
        .position(|i| i.name == default_name)
        .ok_or(ConfigError::DefaultNotFound)?;
    Ok(cfg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The output buffer is too small.
    Full,
    /// The configuration would not parse back (bad name, path, default index…).
    Invalid,
}

impl From<crate::bytes::Full> for WriteError {
    fn from(_: crate::bytes::Full) -> Self {
        WriteError::Full
    }
}

/// Serialise canonically. `parse(write(c)) == c` for every valid `c` (checked
/// by property test), so the loader can author the configuration the initrd
/// writes on a provisioning boot and seal against its hash. `root` is written
/// when present; `efi_disk` only when it differs from `root`; `efi` (with a
/// disk) is always written, so an
/// authored file does not depend on the reader's architecture default;
/// `[UI]` only when it differs from dark / auto / us.
pub fn write(cfg: &Config<'_>, out: &mut [u8]) -> Result<usize, WriteError> {
    if cfg.entry_count == 0 || cfg.entry_count > MAX_ENTRIES {
        return Err(WriteError::Invalid);
    }
    let default = cfg.default_entry().ok_or(WriteError::Invalid)?;
    for (i, ent) in cfg.entries().iter().enumerate() {
        if !ent.is_valid() || cfg.entries().iter().take(i).any(|o| o.name == ent.name) {
            return Err(WriteError::Invalid);
        }
    }
    let mut w = crate::bytes::Writer::new(out);
    let b = |x: bool| if x { TRUE } else { FALSE };
    // `\n[<prefix><name>]` and `\n<key> = <value>`: every line the writer
    // emits after the header comment; each section ends with a newline, so
    // sections are separated by a blank line.
    let header = |w: &mut crate::bytes::Writer<'_>, prefix: &str, name: &[u8]| {
        w.put(b"\n[")?;
        w.put(prefix.as_bytes())?;
        w.put(name)?;
        w.put(b"]")
    };
    let kv = |w: &mut crate::bytes::Writer<'_>, k: &str, v: &[u8]| {
        w.put(b"\n")?;
        w.put(k.as_bytes())?;
        w.put(b" = ")?;
        w.put(v)
    };
    w.put(HEADER_COMMENT.as_bytes())?;
    header(&mut w, section::PAGURO, b"")?;
    kv(&mut w, key::VERSION, VERSION.as_bytes())?;
    kv(&mut w, key::DEFAULT, default.name.as_bytes())?;
    w.put(b"\n")?;
    for ent in cfg.entries() {
        header(&mut w, ENTRY_PREFIX, ent.name.as_bytes())?;
        kv(&mut w, key::VOLUME, &ent.volume.to_text())?;
        if let Some(root) = ent.root {
            kv(&mut w, key::ROOT, root.as_bytes())?;
        }
        match ent.efi {
            Efi::Disk { disk, path } => {
                if Some(disk) != ent.root {
                    kv(&mut w, key::EFI_DISK, disk.as_bytes())?;
                }
                kv(&mut w, key::EFI, path.as_bytes())?;
            }
            Efi::File(f) => kv(&mut w, key::EFI_FILE, f.as_bytes())?,
        }
        w.put(b"\n")?;
    }
    for (name, v) in [
        (section::TPM, cfg.tpm),
        (section::SETUP_TPM, cfg.setup_tpm),
        (section::PASSPHRASE, cfg.passphrase),
    ] {
        header(&mut w, name, b"")?;
        kv(&mut w, key::ENABLED, b(v).as_bytes())?;
        w.put(b"\n")?;
    }
    // Only when it says something: files written before `[UI]` existed
    // keep their exact bytes (and hash).
    if cfg.ui != Ui::DEFAULT {
        header(&mut w, section::UI, b"")?;
        kv(&mut w, key::THEME, cfg.ui.theme.name().as_bytes())?;
        kv(&mut w, key::MODE, cfg.ui.mode.name().as_bytes())?;
        kv(&mut w, key::KEYBOARD, cfg.ui.keyboard.name().as_bytes())?;
        w.put(b"\n")?;
    }
    if w.len() > ini::MAX_LEN {
        return Err(WriteError::Invalid);
    }
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    pub(crate) const GOOD: &str = "# paguro configuration. Not hand-editable: use `paguro config`.
[Paguro]
version     = 1
default     = debian

[Boot.debian]
volume      = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8
root        = \\paguro\\debian.vhd
efi_disk    = \\paguro\\debian-esp.vhd
efi         = \\EFI\\systemd\\systemd-bootx64.efi

[Boot.arch]
volume = 11111111-2222-3333-4444-555555555555
root   = \\paguro\\arch #1.img

[TPM]
enabled     = 1

[SetupTPM]
enabled     = 0

[Passphrase]
enabled     = 1

[Boot.rescue]
volume   = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8
efi_file = \\paguro\\rescue.efi

[Future]
anything = goes
";

    fn err(src: &str) -> ConfigError {
        parse(src.as_bytes()).unwrap_err()
    }

    fn with(replace: &str, by: &str) -> ConfigError {
        assert!(GOOD.contains(replace), "{replace}");
        err(&GOOD.replacen(replace, by, 1))
    }

    #[test]
    fn parses_the_documented_schema() {
        let c = parse(GOOD.as_bytes()).unwrap();
        assert_eq!(c.entry_count, 3);
        let d = c.default_entry().unwrap();
        assert_eq!(d.name, "debian");
        assert_eq!(
            d.volume,
            Guid::parse("6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8").unwrap()
        );
        assert_eq!(d.root, Some("\\paguro\\debian.vhd"));
        assert_eq!(
            d.efi,
            Efi::Disk {
                disk: "\\paguro\\debian-esp.vhd",
                path: "\\EFI\\systemd\\systemd-bootx64.efi"
            }
        );
        assert_eq!(d.separate_efi(), Some("\\paguro\\debian-esp.vhd"));
        let a = &c.entries()[1];
        assert_eq!(a.root, Some("\\paguro\\arch #1.img"));
        assert_eq!(a.efi_disk(), a.root, "efi_disk defaults to root");
        assert_eq!(a.separate_efi(), None);
        assert_eq!(
            a.efi,
            Efi::Disk {
                disk: "\\paguro\\arch #1.img",
                path: DEFAULT_EFI
            }
        );
        let r = &c.entries()[2];
        assert_eq!(r.root, None, "root is optional with efi_file");
        assert_eq!(r.efi, Efi::File("\\paguro\\rescue.efi"));
        assert_eq!(r.efi_disk(), None);
        assert_eq!(r.separate_efi(), Some("\\paguro\\rescue.efi"));
        assert_eq!(
            a.volume,
            Guid::parse("11111111-2222-3333-4444-555555555555").unwrap(),
            "entries may name different volumes"
        );
        assert!(c.tpm && !c.setup_tpm && c.passphrase);
    }

    #[test]
    fn default_selects_any_entry() {
        let src = GOOD.replacen("default     = debian", "default = arch", 1);
        let c = parse(src.as_bytes()).unwrap();
        assert_eq!(c.default, 1);
        assert_eq!(c.default_entry().unwrap().name, "arch");
    }

    #[test]
    fn default_efi_is_the_removable_media_path() {
        #[cfg(target_arch = "aarch64")]
        assert_eq!(DEFAULT_EFI, "\\EFI\\BOOT\\BOOTAA64.EFI");
        #[cfg(not(target_arch = "aarch64"))]
        assert_eq!(DEFAULT_EFI, "\\EFI\\BOOT\\BOOTX64.EFI");
    }

    #[test]
    fn crlf_and_repeated_headers_merge() {
        let src = GOOD.replace('\n', "\r\n");
        assert!(parse(src.as_bytes()).is_ok());
        let split = "[Paguro]\nversion=1\n[Boot.a]\nroot=\\a\n[Paguro]\ndefault=a\n[Boot.a]\nvolume=6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\n";
        let c = parse(split.as_bytes()).unwrap();
        assert_eq!(
            (
                c.entry_count,
                c.entries()[0].root,
                c.entries()[0].efi_disk()
            ),
            (1, Some("\\a"), Some("\\a"))
        );
        assert!(c.tpm && c.setup_tpm && !c.passphrase, "section defaults");
    }

    #[test]
    fn old_schema_keys_are_refused() {
        // `[Image.*]` is now an unknown (ignored) section; the removed keys
        // are unknown keys where they would have been.
        assert_eq!(
            with(
                "default     = debian",
                "default = debian\nvolume = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8"
            ),
            ConfigError::UnknownKey { line: 5 }
        );
        for key in [
            "format = vhd",
            "expose = block",
            "chain = \\x",
            "path = \\x",
        ] {
            assert_eq!(
                with("root        =", &std::format!("{key}\nroot =")),
                ConfigError::UnknownKey { line: 8 },
                "{key}"
            );
        }
        let old = "[Paguro]\nversion=1\ndefault=a\n[Image.a]\npath=\\a\nformat=vhd\n";
        assert_eq!(err(old), ConfigError::DefaultNotFound);
    }

    #[test]
    fn efi_file_rules() {
        let base = "[Paguro]\nversion=1\ndefault=r\n[Boot.r]\nvolume=6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\n";
        let ok = |extra: &str| {
            let src = std::format!("{base}{extra}");
            let c = parse(src.as_bytes()).map(|c| (c.entries()[0].root, c.entries()[0].efi));
            c.map(|(r, e)| (r.map(std::string::String::from), std::format!("{e:?}")))
        };
        assert!(ok("efi_file=\\a.efi\n").is_ok());
        let (root, _) = ok("root=\\r.vhd\nefi_file=\\a.efi\n").unwrap();
        assert_eq!(
            root.as_deref(),
            Some("\\r.vhd"),
            "a root may travel with an efi_file"
        );
        // Conflicts carry the line of whichever key came second.
        for (extra, line) in [
            ("efi_file=\\a.efi\nefi_disk=\\d.vhd\n", 7),
            ("efi_file=\\a.efi\nefi=\\x.efi\n", 7),
            ("efi_disk=\\d.vhd\nroot=\\r\nefi_file=\\a.efi\n", 8),
            ("efi=\\x.efi\nefi_file=\\a.efi\n", 7),
        ] {
            assert_eq!(
                ok(extra),
                Err(ConfigError::EfiFileConflict { line }),
                "{extra}"
            );
        }
        assert_eq!(
            ok("efi_file=\\a.efi\nefi_file=\\b.efi\n"),
            Err(ConfigError::DuplicateKey { line: 7 })
        );
        assert_eq!(
            ok("efi_file=a.efi\n"),
            Err(ConfigError::BadPath {
                line: 6,
                err: PathError::NotAbsolute
            })
        );
        // Neither root nor efi_file; efi_disk/efi alone do not replace root.
        assert_eq!(ok(""), Err(ConfigError::Missing(Missing::EntryRoot(0))));
        assert_eq!(
            ok("efi_disk=\\d.vhd\nefi=\\x.efi\n"),
            Err(ConfigError::Missing(Missing::EntryRoot(0)))
        );
    }

    #[test]
    fn every_error_variant() {
        assert_eq!(
            err("[x"),
            ConfigError::Ini(IniError::BadSection { line: 1 })
        );
        assert_eq!(
            err("a=b\n[Paguro]"),
            ConfigError::KeyOutsideSection { line: 1 }
        );
        assert_eq!(
            with("efi         =", "efi = \\x\nefi ="),
            ConfigError::DuplicateKey { line: 11 }
        );
        assert_eq!(
            with("root        =", "root = \\x\nroot ="),
            ConfigError::DuplicateKey { line: 9 }
        );
        assert_eq!(
            with("efi_disk    =", "efi_disk = \\x\nefi_disk ="),
            ConfigError::DuplicateKey { line: 10 }
        );
        assert_eq!(
            with(
                "volume = 1111",
                "volume = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\nvolume = 1111"
            ),
            ConfigError::DuplicateKey { line: 14 }
        );
        assert_eq!(
            with("version     = 1", "version = 1\n[TPM]\n[Paguro]\nversion=1"),
            ConfigError::DuplicateKey { line: 6 }
        );
        assert_eq!(
            with("[Boot.arch]", "[Boot.debian]\nroot = \\y\n[Boot.arch]"),
            ConfigError::DuplicateKey { line: 13 },
            "repeated entry headers merge, so their keys collide"
        );
        assert_eq!(
            with("efi_disk    =", "efi-disk ="),
            ConfigError::UnknownKey { line: 9 }
        );
        assert_eq!(
            with("enabled     = 1\n\n[SetupTPM]", "enable = 1\n\n[SetupTPM]"),
            ConfigError::UnknownKey { line: 17 }
        );
        assert_eq!(
            err("[Other]\nx=1\n"),
            ConfigError::Missing(Missing::PaguroSection)
        );
        assert_eq!(
            with("version     = 1\n", ""),
            ConfigError::Missing(Missing::Version)
        );
        assert_eq!(
            with("default     = debian\n", ""),
            ConfigError::Missing(Missing::Default)
        );
        assert_eq!(
            with("volume      = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\n", ""),
            ConfigError::Missing(Missing::EntryVolume(0))
        );
        assert_eq!(
            with("root        = \\paguro\\debian.vhd\n", ""),
            ConfigError::Missing(Missing::EntryRoot(0))
        );
        assert_eq!(
            with("root   = \\paguro\\arch #1.img\n", ""),
            ConfigError::Missing(Missing::EntryRoot(1))
        );
        assert_eq!(
            with("volume = 11111111-2222-3333-4444-555555555555\n", ""),
            ConfigError::Missing(Missing::EntryVolume(1))
        );
        assert_eq!(
            with("version     = 1", "version = 2"),
            ConfigError::UnsupportedVersion { line: 3 }
        );
        assert_eq!(
            with("version     = 1", "version = 01x"),
            ConfigError::BadInteger { line: 3 }
        );
        assert_eq!(
            with("version     = 1", "version ="),
            ConfigError::BadInteger { line: 3 }
        );
        assert_eq!(
            with("enabled     = 1", "enabled = yes"),
            ConfigError::BadBool { line: 17 }
        );
        assert_eq!(
            with("6c0a1b2c-3d4e", "6c0a1b2c_3d4e"),
            ConfigError::BadGuid {
                line: 7,
                err: GuidError::BadSeparator
            }
        );
        assert_eq!(
            with("volume = 1111", "volume = 111"),
            ConfigError::BadGuid {
                line: 13,
                err: GuidError::BadLength
            }
        );
        assert_eq!(
            with("[Boot.arch]", "[Boot.a.b]"),
            ConfigError::BadEntryName { line: 13 }
        );
        assert_eq!(
            with("[Boot.arch]", "[Boot.]"),
            ConfigError::BadEntryName { line: 13 }
        );
        assert_eq!(
            with("default     = debian", "default = de bian"),
            ConfigError::BadEntryName { line: 4 }
        );
        assert_eq!(
            with("\\paguro\\debian.vhd", "paguro\\debian.vhd"),
            ConfigError::BadPath {
                line: 8,
                err: PathError::NotAbsolute
            }
        );
        assert_eq!(
            with("\\paguro\\debian-esp.vhd", "\\paguro\\\\esp.vhd"),
            ConfigError::BadPath {
                line: 9,
                err: PathError::EmptyComponent
            }
        );
        assert_eq!(
            with("\\EFI\\systemd\\systemd-bootx64.efi", "\\EFI\\..\\x"),
            ConfigError::BadPath {
                line: 10,
                err: PathError::DotComponent
            }
        );
        assert_eq!(
            with("\\EFI\\systemd\\systemd-bootx64.efi", "\\EFI\\a:b"),
            ConfigError::BadPath {
                line: 10,
                err: PathError::BadChar
            }
        );
        assert_eq!(
            with("default     = debian", "default = gentoo"),
            ConfigError::DefaultNotFound
        );

        let mut many = std::string::String::from("[Paguro]\n");
        for i in 0..=MAX_ENTRIES {
            many.push_str(&std::format!(
                "[Boot.i{i}]\nroot=\\x\nvolume=6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\n"
            ));
        }
        assert_eq!(err(&many), ConfigError::TooManyEntries { line: 51 });
        let big = std::vec![b'#'; ini::MAX_LEN + 1];
        assert_eq!(
            parse(&big).unwrap_err(),
            ConfigError::Ini(IniError::TooLarge)
        );
    }

    #[test]
    fn ui_section() {
        let base = "[Paguro]\nversion=1\ndefault=r\n[Boot.r]\nvolume=6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\nefi_file=\\a.efi\n";
        let ui = |extra: &str| parse(std::format!("{base}{extra}").as_bytes()).map(|c| c.ui);
        assert_eq!(ui(""), Ok(Ui::DEFAULT), "absent: dark / auto");
        assert_eq!(ui("[UI]\n"), Ok(Ui::DEFAULT));
        for t in UiTheme::ALL {
            for m in UiMode::ALL {
                for k in Keyboard::ALL {
                    let src = std::format!(
                        "[UI]\ntheme = {}\nmode = {}\nkeyboard = {}\n",
                        t.name(),
                        m.name(),
                        k.name()
                    );
                    assert_eq!(
                        ui(&src),
                        Ok(Ui {
                            theme: t,
                            mode: m,
                            keyboard: k
                        }),
                        "{src}"
                    );
                }
            }
        }
        assert_eq!(
            ui("[UI]\nmode=text\n"),
            Ok(Ui {
                mode: UiMode::Text,
                ..Ui::DEFAULT
            }),
            "each key defaults on its own"
        );
        assert_eq!(
            ui("[UI]\ntheme=light\n[TPM]\nenabled=1\n[UI]\nmode=graphics\nkeyboard=fr\n"),
            Ok(Ui {
                theme: UiTheme::Light,
                mode: UiMode::Graphics,
                keyboard: Keyboard::Fr,
            }),
            "repeated headers merge"
        );
        // Values are exact names: no case folding, no aliases, no display data.
        for bad in [
            "theme=Dark",
            "theme=high-contrast",
            "theme=",
            "theme=dark ",
            "theme=light-contrast2",
            "mode=GRAPHICS",
            "mode=serial",
            "mode=",
            "theme=/EFI/x.png",
            "keyboard=US",
            "keyboard=ch",
            "keyboard=de-nodeadkeys",
            "keyboard=",
        ] {
            let v = ui(&std::format!("[UI]\n{bad}\n"));
            // `dark ` is trimmed by the grammar and so is valid.
            if bad == "theme=dark " {
                assert_eq!(v, Ok(Ui::DEFAULT));
                continue;
            }
            assert_eq!(v, Err(ConfigError::BadChoice { line: 8 }), "{bad}");
        }
        assert_eq!(
            ui("[UI]\ntheme=dark\ntheme=light\n"),
            Err(ConfigError::DuplicateKey { line: 9 })
        );
        assert_eq!(
            ui("[UI]\nmode=auto\n[UI]\nmode=text\n"),
            Err(ConfigError::DuplicateKey { line: 10 })
        );
        assert_eq!(
            ui("[UI]\nkeyboard=de\nkeyboard=de\n"),
            Err(ConfigError::DuplicateKey { line: 9 })
        );
        assert_eq!(
            ui("[UI]\nlanguage=en\n"),
            Err(ConfigError::UnknownKey { line: 8 })
        );
        assert_eq!(
            ui("[ui]\nanything=goes\n"),
            Ok(Ui::DEFAULT),
            "section names are case-sensitive; [ui] is an unknown section"
        );
        for t in UiTheme::ALL {
            assert_eq!(UiTheme::from_name(t.name()), Some(t));
        }
        for m in UiMode::ALL {
            assert_eq!(UiMode::from_name(m.name()), Some(m));
        }
        for k in Keyboard::ALL {
            assert_eq!(Keyboard::from_name(k.name()), Some(k));
        }
        // F4 visits every layout and comes back.
        let mut k = Keyboard::Us;
        for want in Keyboard::ALL.iter().skip(1).chain([&Keyboard::Us]) {
            k = k.next();
            assert_eq!(k, *want);
        }
    }

    #[test]
    fn ui_section_roundtrips_and_is_omitted_when_default() {
        let mut c = parse(GOOD.as_bytes()).unwrap();
        let mut buf = [0u8; 4096];
        let n = write(&c, &mut buf).unwrap();
        let text = std::string::String::from_utf8(buf[..n].to_vec()).unwrap();
        assert!(
            !text.contains("[UI]"),
            "default: no section, same bytes as before"
        );
        for t in UiTheme::ALL {
            for m in UiMode::ALL {
                for k in Keyboard::ALL {
                    c.ui = Ui {
                        theme: t,
                        mode: m,
                        keyboard: k,
                    };
                    let n = write(&c, &mut buf).unwrap();
                    let text = std::string::String::from_utf8(buf[..n].to_vec()).unwrap();
                    assert_eq!(text.contains("[UI]"), c.ui != Ui::DEFAULT, "{text}");
                    assert_eq!(parse(&buf[..n]).unwrap(), c);
                }
            }
        }
    }

    #[test]
    fn path_rules() {
        use PathError::*;
        let long_comp = std::format!("\\{}", "a".repeat(256));
        let ok_comp = std::format!("\\{}", "é".repeat(255));
        let too_many = "\\a".repeat(33);
        let too_long = std::format!("\\{}", "a".repeat(1024));
        let cases: &[(&str, Result<(), PathError>)] = &[
            ("\\a\\b.vhd", Ok(())),
            (&ok_comp, Ok(())),
            (&"\\a".repeat(32), Ok(())),
            ("", Err(Empty)),
            ("a", Err(NotAbsolute)),
            ("/a", Err(NotAbsolute)),
            (&too_long, Err(TooLong)),
            (&too_many, Err(TooManyComponents)),
            ("\\", Err(EmptyComponent)),
            ("\\a\\\\b", Err(EmptyComponent)),
            ("\\a\\", Err(EmptyComponent)),
            ("\\.", Err(DotComponent)),
            ("\\a\\..", Err(DotComponent)),
            (&long_comp, Err(ComponentTooLong)),
            ("\\a/b", Err(BadChar)),
            ("\\a:b", Err(BadChar)),
            ("\\a\u{1}", Err(BadChar)),
            ("\\a\u{7f}", Err(BadChar)),
        ];
        for (p, want) in cases {
            assert_eq!(check_path(p), *want, "{p:?}");
        }
        // 128 surrogate pairs = 256 UTF-16 units.
        assert_eq!(
            check_path(&std::format!("\\{}", "😀".repeat(128))),
            Err(ComponentTooLong)
        );
    }

    #[test]
    fn names() {
        assert!(check_name("a-B_9"));
        assert!(check_name(&"a".repeat(32)));
        assert!(!check_name(&"a".repeat(33)));
        assert!(!check_name(""));
        assert!(!check_name("a.b"));
    }

    #[test]
    fn write_roundtrips_and_refuses_invalid() {
        let c = parse(GOOD.as_bytes()).unwrap();
        let mut buf = [0u8; 4096];
        let n = write(&c, &mut buf).unwrap();
        let text = std::string::String::from_utf8(buf[..n].to_vec()).unwrap();
        assert!(text.contains("[Boot.rescue]\nvolume = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\nefi_file = \\paguro\\rescue.efi\n"));
        assert!(text.starts_with(HEADER_COMMENT));
        assert_eq!(parse(&buf[..n]).unwrap(), c);
        assert_eq!(
            text.matches("efi_disk = ").count(),
            1,
            "efi_disk only where it differs from root: {text}"
        );
        assert_eq!(write(&c, &mut buf[..10]), Err(WriteError::Full));

        let mut bad = c;
        bad.default = 5;
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.entry_count = 0;
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.entries[1].name = "debian";
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.entries[0].root = Some("x");
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.entries[0].root = None;
        assert_eq!(
            write(&bad, &mut buf),
            Err(WriteError::Invalid),
            "an efi disk needs a root"
        );
        let mut bad = c;
        bad.entries[0].efi = Efi::Disk {
            disk: "",
            path: DEFAULT_EFI,
        };
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.entries[0].efi = Efi::Disk {
            disk: "\\d",
            path: "\\..",
        };
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.entries[2].efi = Efi::File("rescue.efi");
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
    }
}
