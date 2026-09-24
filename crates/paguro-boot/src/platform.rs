//! What the stage machine needs from firmware, and nothing more.
//!
//! `paguro-efi` implements [`Platform`] over the `uefi` crate; the mock boot
//! tests implement it in memory (fake variables, a fake TPM that models PCR
//! extend and policy-bound unseal, an in-memory ESP and disks). Everything
//! the loader *decides* lives above this trait, in code both run.
//!
//! The trait deliberately has no disk-write and no chainload-by-path-to-Windows
//! operation: the loader never writes to disk, and "Start Windows" is
//! `BootNext` plus a reset.

use core::fmt;
use paguro_core::guid::Guid;

/// Firmware variable attributes (UEFI 2.10 §8.2).
pub mod attrs {
    pub const NON_VOLATILE: u32 = 0x1;
    pub const BOOTSERVICE_ACCESS: u32 = 0x2;
    pub const RUNTIME_ACCESS: u32 = 0x4;
    /// `B`: no OS can read it (DESIGN.md §6, "Where B lives").
    pub const NV_BS: u32 = NON_VOLATILE | BOOTSERVICE_ACCESS;
    pub const NV_BS_RT: u32 = NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformError {
    /// The object exists but is larger than the buffer offered. Callers treat
    /// an oversized variable or file as malformed, never truncate it.
    TooLarge,
    /// A device or protocol error; the payload is the firmware status or 0.
    Device(u64),
    /// No TPM, no RNG, no such disk…
    Unsupported,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiskInfo {
    pub block_size: u32,
    pub blocks: u64,
}

/// Rows of the unlock list (DESIGN.md §4.1, "Unlock prompt"), labelled by
/// attempt cost rather than mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Row {
    /// Free protectors first, then the TPM rung (which costs an attempt).
    PasswordOrPin,
    /// The opt-in `passphrase` rung: no attempt limit.
    RecoveryPassphrase,
    /// The volume's own 48-digit recovery password.
    RecoveryKey,
}

/// Why the TPM row is greyed (two reasons, two texts).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grey {
    /// "unavailable until restart — recovery mode"
    RecoveryMode,
    /// "TPM locked — use another option"
    Locked,
    /// Policy mismatch (firmware update, tamper) or no TPM.
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnlockMenu {
    /// Rows present, in display order; `None` entries are absent.
    pub password_or_pin: bool,
    pub recovery_passphrase: bool,
    pub recovery_key: bool,
    /// Whether the password row includes the TPM, and if not, why.
    pub tpm: Result<Option<u32>, Grey>,
    /// Shown while the configuration is unverified (recovery, SB off,
    /// missing hash): the prompt states it is unattested.
    pub unattested: bool,
    /// First boot: "From now on this replaces your Linux login password…"
    pub first_boot: bool,
}

/// Refusal / degrade screens: one frame, several texts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Notice {
    /// "Windows saved a session — starting Linux read-only".
    Hibernated,
    /// "Windows didn't shut down cleanly last time".
    Dirty,
    /// PCR 12 was not zero before the first extend.
    Pcr12NotZero,
    /// A TPM seal over an unencrypted volume (DESIGN.md §6, refused config).
    SealOverPlaintext,
    /// The volume named by the configuration was not found.
    VolumeMissing,
    /// A later stage is not implemented in this build.
    NotImplemented,
    /// The chosen entry's UEFI image could not be found, read or started
    /// (a missing file, a refused disk, `LoadImage` refusing it). The log
    /// says which.
    StartFailed,
}

/// Longest [`Label`] in bytes (a GPT partition name is at most 36 UTF-16
/// units, 108 bytes of UTF-8).
pub const LABEL_MAX: usize = 112;

/// A short display string held inline, so a [`Screen`] stays `Copy` and
/// needs no allocation. Always valid UTF-8.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Label {
    len: u8,
    bytes: [u8; LABEL_MAX],
}

impl Label {
    pub const EMPTY: Label = Label {
        len: 0,
        bytes: [0; LABEL_MAX],
    };

    /// `s`, or `None` when it does not fit (a path must never be shortened).
    pub fn new(s: &str) -> Option<Label> {
        let mut l = Label::EMPTY;
        l.bytes.get_mut(..s.len())?.copy_from_slice(s.as_bytes());
        l.len = u8::try_from(s.len()).ok()?;
        Some(l)
    }

    /// `s` cut at a character boundary to fit (display-only text).
    pub fn truncated(s: &str) -> Label {
        let mut end = s.len().min(LABEL_MAX);
        while !s.is_char_boundary(end) {
            end -= 1;
        }
        Label::new(s.get(..end).unwrap_or("")).unwrap_or(Label::EMPTY)
    }

    /// A GPT partition name: UTF-16LE up to the first NUL; unpaired
    /// surrogates become U+FFFD.
    pub fn from_utf16(units: &[u16]) -> Label {
        let mut l = Label::EMPTY;
        let mut n = 0usize;
        let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
        for c in char::decode_utf16(units.iter().take(end).copied()) {
            let c = c.unwrap_or(char::REPLACEMENT_CHARACTER);
            let mut enc = [0u8; 4];
            let e = c.encode_utf8(&mut enc).as_bytes();
            let Some(dst) = l.bytes.get_mut(n..n + e.len()) else {
                break;
            };
            dst.copy_from_slice(e);
            n += e.len();
        }
        l.len = u8::try_from(n).unwrap_or(0);
        l
    }

    pub fn as_str(&self) -> &str {
        core::str::from_utf8(self.bytes.get(..usize::from(self.len)).unwrap_or(&[])).unwrap_or("")
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}

/// Longest list on any screen (volumes, boot targets, root candidates).
pub const MAX_CHOICES: usize = 8;

/// What a candidate volume's first sector says it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeFormat {
    BitLocker,
    /// NTFS without encryption.
    Ntfs,
}

/// One row of the volume list (INTERFACES.md §13.4, step 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeChoice {
    /// Disk number, in the platform's stable order.
    pub disk: u8,
    /// 1-based GPT entry number.
    pub partition: u32,
    pub bytes: u64,
    pub format: VolumeFormat,
    /// The GPT partition name; may be empty. Display only.
    pub name: Label,
}

impl VolumeChoice {
    pub const EMPTY: VolumeChoice = VolumeChoice {
        disk: 0,
        partition: 0,
        bytes: 0,
        format: VolumeFormat::Ntfs,
        name: Label::EMPTY,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeList {
    pub items: [VolumeChoice; MAX_CHOICES],
    pub count: u8,
}

impl VolumeList {
    pub const fn new() -> Self {
        VolumeList {
            items: [VolumeChoice::EMPTY; MAX_CHOICES],
            count: 0,
        }
    }
    pub fn push(&mut self, v: VolumeChoice) -> bool {
        match self.items.get_mut(usize::from(self.count)) {
            Some(slot) => {
                *slot = v;
                self.count += 1;
                true
            }
            None => false,
        }
    }
    pub fn as_slice(&self) -> &[VolumeChoice] {
        self.items.get(..usize::from(self.count)).unwrap_or(&[])
    }
}

impl Default for VolumeList {
    fn default() -> Self {
        Self::new()
    }
}

/// Which filesystem the recovery browser walks (INTERFACES.md §13.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The unlocked NTFS volume: folders, disks and UEFI images.
    Volume,
    /// The FAT32 EFI partition inside a chosen disk: folders and UEFI
    /// images.
    EfiPartition,
    /// The unlocked NTFS volume again, for an `efi_file`'s root hint:
    /// folders and disks, and "no root".
    Root,
}

/// What a listed entry is, by the extension convention of INTERFACES.md
/// §13.4 (`.vhd`, `.vhdx`, `.img`, `.raw` are disks; `.efi` UEFI images).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    Dir,
    Disk,
    Efi,
}

/// One listed entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirItem<'a> {
    pub name: &'a str,
    pub kind: EntryKind,
    pub bytes: u64,
}

/// A directory as the browser shows it: sorted, filtered, bounded.
pub trait Listing {
    fn len(&self) -> usize;
    fn item(&self, i: usize) -> Option<DirItem<'_>>;
    /// Entries were left out (the directory exceeds the bounds).
    fn more(&self) -> bool;
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Entries kept per directory; the rest are counted as "more".
pub const MAX_DIR_ENTRIES: usize = 4096;
/// UTF-8 bytes of names kept per directory.
pub const DIR_NAME_BYTES: usize = 128 * 1024;
/// Longest name accepted, in UTF-16 units (NTFS and FAT long names).
pub const MAX_NAME_UNITS: usize = 255;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Slot {
    off: u32,
    len: u16,
    kind: EntryKind,
    bytes: u64,
}

/// A listing in fixed memory (it lives in [`crate::Buffers`]): what
/// [`Volume::list_dir`](crate::Volume::list_dir) fills, entry by entry,
/// from names as the filesystem stores them (UTF-16).
pub struct DirListing {
    slots: [Slot; MAX_DIR_ENTRIES],
    count: usize,
    names: [u8; DIR_NAME_BYTES],
    used: usize,
    more: bool,
    level: Level,
}

fn ascii_lower_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .all(|(x, y)| x.eq_ignore_ascii_case(&y))
}

/// The kind a file name has on `level`, or `None` when it is not shown.
pub fn file_kind(level: Level, name: &str) -> Option<EntryKind> {
    let ext = name.rsplit_once('.').map(|(_, e)| e)?;
    let is = |e: &str| ascii_lower_eq(ext, e);
    let disk = is("vhd") || is("vhdx") || is("img") || is("raw");
    match level {
        Level::Volume | Level::EfiPartition if is("efi") => Some(EntryKind::Efi),
        Level::Volume | Level::Root if disk => Some(EntryKind::Disk),
        _ => None,
    }
}

impl DirListing {
    pub const fn new() -> Self {
        DirListing {
            slots: [Slot {
                off: 0,
                len: 0,
                kind: EntryKind::Dir,
                bytes: 0,
            }; MAX_DIR_ENTRIES],
            count: 0,
            names: [0; DIR_NAME_BYTES],
            used: 0,
            more: false,
            level: Level::Volume,
        }
    }

    /// Start a listing for `level`.
    pub fn clear(&mut self, level: Level) {
        self.count = 0;
        self.used = 0;
        self.more = false;
        self.level = level;
    }

    pub const fn level(&self) -> Level {
        self.level
    }

    /// Offer one entry as read from the directory. `.`, `..`, names starting
    /// with `$` (NTFS metafiles), names with a control character, `\`, `/`
    /// or an unpaired surrogate, and files that are neither disks nor UEFI
    /// images are skipped. Returns `false` once the listing is full (the
    /// entry and any later ones count as [`Listing::more`]).
    pub fn push(&mut self, name: &[u16], is_dir: bool, bytes: u64) -> bool {
        if name.is_empty() || name.len() > MAX_NAME_UNITS {
            return true;
        }
        let at = self.used;
        let mut n = 0usize;
        for c in char::decode_utf16(name.iter().copied()) {
            let Ok(c) = c else {
                return true;
            };
            if c.is_control() || c == '\\' || c == '/' {
                return true;
            }
            let mut e = [0u8; 4];
            let e = c.encode_utf8(&mut e).as_bytes();
            let Some(dst) = self.names.get_mut(at + n..at + n + e.len()) else {
                self.more = true;
                return false;
            };
            dst.copy_from_slice(e);
            n += e.len();
        }
        let text = core::str::from_utf8(self.names.get(at..at + n).unwrap_or(&[])).unwrap_or("");
        if text == "." || text == ".." || text.starts_with('$') {
            return true;
        }
        let kind = if is_dir {
            EntryKind::Dir
        } else {
            match file_kind(self.level, text) {
                Some(k) => k,
                None => return true,
            }
        };
        let Some(slot) = self.slots.get_mut(self.count) else {
            self.more = true;
            return false;
        };
        *slot = Slot {
            off: at as u32,
            len: n as u16,
            kind,
            bytes,
        };
        self.count += 1;
        self.used += n;
        true
    }

    fn name_of(&self, s: &Slot) -> &str {
        let (o, l) = (s.off as usize, usize::from(s.len));
        core::str::from_utf8(self.names.get(o..o + l).unwrap_or(&[])).unwrap_or("")
    }

    /// Folders first, then case-insensitively by name (ties by exact name).
    pub fn sort(&mut self) {
        let names = &self.names;
        let name = |s: &Slot| {
            let (o, l) = (s.off as usize, usize::from(s.len));
            core::str::from_utf8(names.get(o..o + l).unwrap_or(&[])).unwrap_or("")
        };
        let n = self.count.min(MAX_DIR_ENTRIES);
        if let Some(slots) = self.slots.get_mut(..n) {
            slots.sort_unstable_by(|a, b| {
                let (da, db) = (a.kind != EntryKind::Dir, b.kind != EntryKind::Dir);
                da.cmp(&db)
                    .then_with(|| {
                        name(a)
                            .chars()
                            .flat_map(char::to_lowercase)
                            .cmp(name(b).chars().flat_map(char::to_lowercase))
                    })
                    .then_with(|| name(a).cmp(name(b)))
            });
        }
    }

    /// The index of the entry called `name`, if listed.
    pub fn find(&self, name: &str) -> Option<usize> {
        (0..self.count).find(|&i| self.item(i).is_some_and(|e| e.name == name))
    }
}

impl Default for DirListing {
    fn default() -> Self {
        Self::new()
    }
}

impl Listing for DirListing {
    fn len(&self) -> usize {
        self.count
    }
    fn item(&self, i: usize) -> Option<DirItem<'_>> {
        let s = self.slots.get(..self.count)?.get(i)?;
        Some(DirItem {
            name: self.name_of(s),
            kind: s.kind,
            bytes: s.bytes,
        })
    }
    fn more(&self) -> bool {
        self.more
    }
}

/// What the browser shows: the directory's path (for the breadcrumb), its
/// entries, the row to start on, and which browser it is.
#[derive(Clone, Copy)]
pub struct DirView<'a> {
    pub path: &'a str,
    pub listing: &'a dyn Listing,
    pub selected: usize,
    pub level: Level,
}

impl fmt::Debug for DirView<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirView")
            .field("path", &self.path)
            .field("entries", &self.listing.len())
            .field("selected", &self.selected)
            .field("level", &self.level)
            .finish()
    }
}

/// Every screen the loader can show. The theme is compiled in: no screen
/// takes display *markup*, only small typed parameters and inline labels
/// (partition and file names), which renderers treat as plain text.
// The volume list is held inline (~1 KiB): no allocation in the loader, and
// a Screen is small enough to pass by reference.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Unlock(UnlockMenu),
    /// Secret entry for a row.
    EnterSecret {
        row: Row,
        unattested: bool,
    },
    /// The candidate secret opened nothing.
    Incorrect,
    /// A typed path is not a usable NTFS path (shown like [`Screen::Incorrect`]:
    /// no key, the path field follows).
    PathRefused,
    /// "Cannot unlock Linux — Windows will almost certainly start normally."
    CannotUnlock,
    /// "Configuration is not valid" (hash mismatch, missing hash, parse error).
    ConfigInvalid,
    /// "Too many incorrect attempts" — the TPM row is greyed.
    TpmLocked,
    Notice(Notice),
    /// "No Linux installation found".
    NoInstallation,
    /// "Which volume holds your Linux installation?" (recovery, step 1).
    SelectVolume(VolumeList),
    /// The file browser (recovery, step 2): the entries come with
    /// [`Platform::prompt_browse`].
    Browse(Level),
    /// A path typed by hand, on the volume or on a disk's EFI partition.
    EnterPath(Level),
    /// A disk was chosen: start its default UEFI image, browse its EFI
    /// partition, or type a path there.
    DiskStart {
        /// The disk file's name.
        disk: Label,
    },
    /// The chosen disk has no FAT32 EFI partition the loader can read
    /// (shown like [`Screen::Incorrect`]: no key, the browser follows).
    NoEfiPartition,
}

/// What the user did on a screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Select(Row),
    /// A secret (or typed path) of this many bytes (UTF-8) is in the prompt
    /// buffer.
    Secret(usize),
    /// An index in a list (volume selection).
    Choose(u8),
    /// An entry of the browsed directory, by index in its listing.
    Entry(u16),
    /// The browser's parent directory.
    Parent,
    /// "Type a path" in the browser or on the disk screen.
    TypePath,
    /// The disk screen: start the default UEFI image.
    UseDefault,
    /// The disk screen: browse the disk's EFI partition.
    BrowseDisk,
    /// "No root" in the root-hint browser: the initrd asks.
    NoRoot,
    /// "Start Windows": `BootNext` + reset, never a chainload.
    StartWindows,
    /// "Recover Linux" / voluntary recovery.
    Recover,
    Continue,
    Escape,
}

pub trait Platform {
    /// Read `\EFI\paguro\<name>` into `buf`. `Ok(None)`: absent.
    /// `Err(TooLarge)`: the file exceeds `buf` (the caller's hard cap).
    fn read_esp_file(&mut self, name: &str, buf: &mut [u8])
    -> Result<Option<usize>, PlatformError>;

    /// `Ok(None)`: absent. `Err(TooLarge)`: exceeds `buf`.
    fn get_var(
        &mut self,
        name: &str,
        vendor: &Guid,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError>;
    fn set_var(
        &mut self,
        name: &str,
        vendor: &Guid,
        attrs: u32,
        data: &[u8],
    ) -> Result<(), PlatformError>;
    fn delete_var(&mut self, name: &str, vendor: &Guid) -> Result<(), PlatformError>;

    /// The `SecureBoot` global variable is 1 (and `SetupMode` 0).
    fn secure_boot(&mut self) -> bool;

    /// A TPM 2.0 is present (TCG2 protocol with a 2.0 device).
    fn tpm_present(&mut self) -> bool;
    /// `EFI_TCG2_PROTOCOL.HashLogExtendEvent`: extend `pcr` with
    /// SHA-256(`data`) and log `event` as an `EV_EVENT_TAG` event.
    fn hash_log_extend(&mut self, pcr: u32, data: &[u8], event: &[u8])
    -> Result<(), PlatformError>;
    /// `EFI_TCG2_PROTOCOL.SubmitCommand`. Returns the response length.
    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError>;

    /// Whole-disk block devices (no partitions), in a stable order.
    fn disk_count(&mut self) -> usize;
    fn disk_info(&mut self, disk: usize) -> Option<DiskInfo>;
    /// Read whole blocks; `buf.len()` is a multiple of the block size.
    fn read_blocks(&mut self, disk: usize, lba: u64, buf: &mut [u8]) -> Result<(), PlatformError>;

    /// `EFI_RNG_PROTOCOL`.
    fn random(&mut self, buf: &mut [u8]) -> Result<(), PlatformError>;

    /// Show a screen and wait for an action. A secret (or, on
    /// [`Screen::EnterPath`], the typed path) is written to `secret`, which is
    /// wiped when the prompt is left any other way.
    fn prompt(&mut self, screen: &Screen, secret: &mut [u8]) -> Input;

    /// The recovery file browser (INTERFACES.md §13.4): show `screen` (a
    /// [`Screen::Browse`]) over `dir` and return [`Input::Entry`],
    /// [`Input::Parent`], [`Input::TypePath`] or [`Input::Escape`].
    ///
    /// Defaults to `Escape` for platforms that never recover (test TPM
    /// harnesses).
    fn prompt_browse(&mut self, screen: &Screen, dir: &DirView<'_>) -> Input {
        let _ = (screen, dir);
        Input::Escape
    }

    /// The configuration's `[UI]` preferences (theme variant, graphics or
    /// text; INTERFACES.md §13.2a), once stage 2 has parsed them; the
    /// defaults (dark / auto) again when recovery takes over, which never
    /// reads the configuration. Defaults to ignoring them.
    fn ui_prefs(&mut self, ui: paguro_core::config::Ui) {
        let _ = ui;
    }

    /// Diagnostics (the serial log in QEMU). Never receives key material.
    fn log(&mut self, args: fmt::Arguments<'_>);

    /// Publish the handoff as an `EfiRuntimeServicesData` configuration table.
    fn publish_handoff(&mut self, blob: &[u8]) -> Result<(), PlatformError>;

    /// `LoadImage` + `StartImage` of an image named by a device path (the UKI,
    /// verified by shim / Secure Boot exactly as on any path).
    fn load_start_image(&mut self, device_path: &[u8]) -> Result<(), PlatformError>;

    /// `LoadImage(SourceBuffer)` + `StartImage` of a UEFI image read into
    /// memory (an entry's `efi_file`, INTERFACES.md §3.2). `LoadImage` runs the
    /// Secure Boot verification; the buffer is **never jumped to** directly,
    /// which would bypass it. The image gets no `DeviceHandle`.
    ///
    /// Defaults to `Unsupported` for platforms that never chain (test TPM
    /// harnesses).
    fn load_start_image_buffer(&mut self, image: &[u8]) -> Result<(), PlatformError> {
        let _ = image;
        Err(PlatformError::Unsupported)
    }

    /// Memory for an `efi_file` of `len` bytes, held until the image has been
    /// loaded (`AllocatePages` in UEFI).
    ///
    /// Defaults to `Unsupported` for platforms that never chain.
    fn alloc_image(&mut self, len: usize) -> Result<&'static mut [u8], PlatformError> {
        let _ = len;
        Err(PlatformError::Unsupported)
    }

    /// Publish a disk file as a **read-only** block device
    /// (`EFI_BLOCK_IO_PROTOCOL`, `WriteBlocks` → `EFI_WRITE_PROTECTED`) with a
    /// device path of its own, let the firmware's partition and FAT drivers
    /// bind it (`ConnectController`, recursive), find the file system `fat`
    /// names, and write the device path of `image` on it to `out`
    /// (INTERFACES.md §3.2; DESIGN.md §4.2 tier 1). Returns its length.
    ///
    /// Defaults to `Unsupported` for platforms that never chain.
    fn expose_disk(
        &mut self,
        disk: &crate::stage4::ExposedDisk<'_>,
        fat: crate::stage4::FatAt,
        image: &str,
        out: &mut [u8],
    ) -> Result<usize, PlatformError> {
        let _ = (disk, fat, image, out);
        Err(PlatformError::Unsupported)
    }

    /// `ResetSystem(EfiResetCold)`. Returns only in tests.
    fn reset(&mut self);
}

/// Lower-case hex for logs.
pub struct Hex<'a>(pub &'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}
