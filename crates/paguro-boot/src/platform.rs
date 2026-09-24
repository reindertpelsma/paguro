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

/// Every screen the loader can show. The theme is compiled in: no screen
/// takes attacker-authored display data, only small typed parameters.
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
    /// "Cannot unlock Linux — Windows will almost certainly start normally."
    CannotUnlock,
    /// "Configuration is not valid" (hash mismatch, missing hash, parse error).
    ConfigInvalid,
    /// "Too many incorrect attempts" — the TPM row is greyed.
    TpmLocked,
    Notice(Notice),
    /// "No Linux installation found".
    NoInstallation,
    /// "Which volume holds your Linux installation?"
    SelectVolume {
        count: u8,
    },
}

/// What the user did on a screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    Select(Row),
    /// A secret of this many bytes (UTF-8) is in the prompt buffer.
    Secret(usize),
    /// An index in a list (volume selection).
    Choose(u8),
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

    /// Show a screen and wait for an action. A secret, if any, is written to
    /// `secret`.
    fn prompt(&mut self, screen: &Screen, secret: &mut [u8]) -> Input;

    /// Diagnostics (the serial log in QEMU). Never receives key material.
    fn log(&mut self, args: fmt::Arguments<'_>);

    /// Publish the handoff as an `EfiRuntimeServicesData` configuration table.
    fn publish_handoff(&mut self, blob: &[u8]) -> Result<(), PlatformError>;

    /// `LoadImage` + `StartImage` of an image named by a device path (the UKI,
    /// verified by shim / Secure Boot exactly as on any path).
    fn load_start_image(&mut self, device_path: &[u8]) -> Result<(), PlatformError>;

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
