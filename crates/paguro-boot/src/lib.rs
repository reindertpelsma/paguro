//! `paguro-boot` — the loader's logic as a stage machine (DESIGN.md §4.1, §6),
//! generic over a [`Platform`] so the same code runs under UEFI (`paguro-efi`)
//! and in the mock boot tests.
//!
//! ```text
//! 0  delete the bootstrap Boot#### entry            -- first action
//! 1  read paguro.ini (64 KiB cap), SHA-256, compare  -- Secure Boot only
//! 2  parse; PCR 12 must be zero; LOAD TAINT          -- or the sentinel
//!    (recovery: cap PCR 12 first, never parse)
//! 3  B, seals, volume, rungs in escalation order; BOOT TAINT
//! 4  locate the image (Volume::locate), handoff, LoadImage
//! ```
//!
//! No allocation: every buffer is in [`Buffers`], which the caller places
//! (pages in UEFI, the heap in tests). No `unsafe`.
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod machine;
pub mod platform;
pub mod tpm;
pub mod ui;
pub mod volume;

use paguro_core::handoff::{EncodeError, Rung};
use paguro_core::{bootstrap, ini, seal};

pub use machine::run;
pub use platform::{Input, Platform, PlatformError, Screen};
pub use volume::{Unimplemented, Volume};

/// Names on the ESP (INTERFACES.md §2) and in firmware (§5).
pub mod names {
    pub const INI: &str = "paguro.ini";
    pub const VAR_B: &str = "PaguroB";
    pub const VAR_CONFIG_HASH: &str = "PaguroConfigHash";
    pub const VAR_SETUP: &str = "PaguroSetup";
    pub const VAR_TPM_BROKEN: &str = "PaguroTpmBroken";
    /// ASCII hashed for the boot taint (INTERFACES.md §6).
    pub const BOOT_TAINT: &[u8] = b"paguro/boot-taint/v1";
    /// Event-log text for the load taint (the hashed data is the `.ini`).
    pub const LOAD_TAINT_EVENT: &[u8] = b"paguro/load-taint/v1";
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    Platform(PlatformError),
    /// A buffer did not fit a block or record (a sizing bug, not input).
    Disk,
    Tpm(tpm::TpmFail),
    /// `EFI_RNG_PROTOCOL` failed: `B` cannot be created.
    Rng,
    /// No volume found (or the user gave up choosing one).
    NoVolume,
    /// The chosen partition is neither BitLocker nor NTFS.
    NotAVolume,
    /// A TPM seal over an unencrypted volume (DESIGN.md §6, refused).
    SealOverPlaintext,
    Handoff(EncodeError),
    /// No Windows Boot Manager entry to set as `BootNext`.
    NoWindowsEntry,
    /// The user left every prompt.
    UserAbort,
    NotImplemented(&'static str),
}

/// How the boot ended (the loader's `main` maps these to a status).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The handoff was published and the chain target started (and returned).
    Started(Rung),
    /// `BootNext` was set to Windows Boot Manager and the system reset.
    StartWindows,
    Halted(BootError),
}

/// Why the recovery path was entered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryReason {
    /// No `paguro.ini` and no bootstrap entry.
    NoConfig,
    /// `paguro.ini` over 64 KiB, or unreadable.
    ConfigUnreadable,
    /// Secure Boot on and `PaguroConfigHash` absent (NVRAM cleared).
    HashMissing,
    /// Secure Boot on and the hash differs.
    HashMismatch,
    /// The verified file does not parse.
    ConfigInvalid,
    /// PCR 12 was not zero.
    Pcr12NotZero,
    /// The configured volume was not found.
    VolumeMissing,
    /// Chosen from a healthy boot.
    Voluntary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// A verified (or, with Secure Boot off, unverified) parsed configuration.
    Normal,
    /// Never parses the configuration; PCR 12 capped on entry.
    Recovery(RecoveryReason),
    /// No configuration, bootstrap entry present: compiled-in defaults.
    FirstBoot,
}

/// Tunables that tests shrink. Production uses [`Params::PRODUCTION`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// BitLocker stretch iterations for `pass_hash` (0x100000 in production).
    pub stretch_iterations: u64,
}

impl Params {
    pub const PRODUCTION: Params = Params {
        stretch_iterations: paguro_crypto::STRETCH_ITERATIONS,
    };
}

/// `paguro.ini` is read into a buffer one byte larger than the cap, so a
/// full buffer means the file is too large (INTERFACES.md §3.1).
pub const INI_BUF: usize = ini::MAX_LEN + 1;

/// Every buffer the stage machine uses (~190 KiB): too large for a UEFI
/// stack, so the caller allocates it.
pub struct Buffers {
    pub ini: [u8; INI_BUF],
    /// The configuration authored on a provisioning boot.
    pub gen_ini: [u8; 4096],
    pub seals: [[u8; seal::MAX_FILE]; 4],
    pub var: [u8; bootstrap::MAX_LOAD_OPTION],
    pub gpt: volume::GptScratch,
    pub handoff: [u8; paguro_core::handoff::MAX_LEN],
    pub secret: [u8; 256],
    pub fvek_blob: [u8; 1024],
    pub created: tpm::CreatedObject,
    pub located: volume::Located,
}

impl Buffers {
    pub const fn new() -> Self {
        Buffers {
            ini: [0; INI_BUF],
            gen_ini: [0; 4096],
            seals: [[0; seal::MAX_FILE]; 4],
            var: [0; bootstrap::MAX_LOAD_OPTION],
            gpt: volume::GptScratch::new(),
            handoff: [0; paguro_core::handoff::MAX_LEN],
            secret: [0; 256],
            fvek_blob: [0; 1024],
            created: tpm::CreatedObject::new(),
            located: volume::Located::new(),
        }
    }
}

impl Default for Buffers {
    fn default() -> Self {
        Self::new()
    }
}
