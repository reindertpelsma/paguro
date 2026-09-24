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

/// What a file in `\paguro\` is, by the convention of INTERFACES.md §13.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    /// A disk file (VHD or raw): `efi_disk`, and therefore also the root.
    Disk,
    /// A UEFI image directly on NTFS (`efi_file`).
    EfiFile,
}

/// One entry found in `\paguro\` on the unlocked volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    /// The file name inside `\paguro\` (exact: it becomes a path).
    pub name: Label,
    pub bytes: u64,
    pub kind: TargetKind,
}

impl Target {
    pub const EMPTY: Target = Target {
        name: Label::EMPTY,
        bytes: 0,
        kind: TargetKind::Disk,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetList {
    pub items: [Target; MAX_CHOICES],
    pub count: u8,
}

impl TargetList {
    pub const fn new() -> Self {
        TargetList {
            items: [Target::EMPTY; MAX_CHOICES],
            count: 0,
        }
    }
    pub fn push(&mut self, t: Target) -> bool {
        match self.items.get_mut(usize::from(self.count)) {
            Some(slot) => {
                *slot = t;
                self.count += 1;
                true
            }
            None => false,
        }
    }
    pub fn as_slice(&self) -> &[Target] {
        self.items.get(..usize::from(self.count)).unwrap_or(&[])
    }
    pub fn get(&self, i: usize) -> Option<&Target> {
        self.as_slice().get(i)
    }
}

impl Default for TargetList {
    fn default() -> Self {
        Self::new()
    }
}

/// Every screen the loader can show. The theme is compiled in: no screen
/// takes display *markup*, only small typed parameters and inline labels
/// (partition and file names), which renderers treat as plain text.
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
    /// What to boot from the unlocked volume's `\paguro\` (recovery, step 2):
    /// the entries found, then "type a path".
    SelectTarget(TargetList),
    /// A path typed by hand (recovery, step 2).
    EnterPath,
    /// The root hint for an `efi_file` (recovery, step 3): the candidates,
    /// then "no root".
    SelectRoot {
        /// The chosen UEFI image's name.
        efi: Label,
        roots: TargetList,
    },
}

/// What the user did on a screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Select(Row),
    /// A secret (or typed path) of this many bytes (UTF-8) is in the prompt
    /// buffer.
    Secret(usize),
    /// An index in a list (volume, boot target, root candidate).
    Choose(u8),
    /// "Type a path" on the boot-target list.
    TypePath,
    /// "No root" on the root list: the initrd asks.
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
