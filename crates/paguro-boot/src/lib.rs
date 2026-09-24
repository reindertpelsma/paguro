//! `paguro-boot` — the loader's logic as a stage machine (DESIGN.md §4.1, §6),
//! generic over a [`Platform`] so the same code runs under UEFI (`paguro-efi`)
//! and in the mock boot tests.
//!
//! ```text
//! 0  delete the bootstrap Boot#### entry            -- first action
//! 1  read paguro.ini (64 KiB cap), SHA-256, compare  -- Secure Boot only
//! 2  parse; PCR 12 must be zero; LOAD TAINT          -- or the sentinel
//!    (recovery: cap PCR 12 first, never parse)
//! 3  B, the entry's volume and its seals, rungs in escalation order; BOOT TAINT
//! 4  locate the entry's disks (Volume::locate), handoff, LoadImage
//! ```
//!
//! No allocation: every buffer is in [`Buffers`], which the caller places
//! (pages in UEFI, the heap in tests). No `unsafe`.
#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::indexing_slicing))]

pub mod bde;
pub mod machine;
pub mod platform;
pub mod stage4;
pub mod tpm;
pub mod ui;
pub mod volume;
pub mod vt100;

use paguro_core::handoff::{EncodeError, Rung};
use paguro_core::{bootstrap, ini, seal};

pub use bde::BdeVolume;
pub use machine::run;
pub use platform::{Input, Platform, PlatformError, Screen};
pub use stage4::NtfsVolume;
pub use volume::{Unimplemented, Volume};

/// Names on the ESP (INTERFACES.md §2) and in firmware (§5).
pub mod names {
    use paguro_core::guid::Guid;
    use paguro_core::seal::Kind;

    pub const INI: &str = "paguro.ini";
    /// Longest seal path under `\EFI\paguro\`: `<guid>\tpm_pin_bypass_seal.bin`.
    pub const SEAL_PATH_MAX: usize = 64;

    /// `<volume-guid>\<seal file>` (lower-case canonical GUID), relative to
    /// `\EFI\paguro\`: each volume's seals live in its own directory.
    pub fn seal_path<'a>(volume: &Guid, kind: Kind, out: &'a mut [u8; SEAL_PATH_MAX]) -> &'a str {
        let g = volume.to_text();
        let f = kind.file_name().as_bytes();
        let n = g.len() + 1 + f.len();
        if let Some(dst) = out.get_mut(..n) {
            let (a, rest) = dst.split_at_mut(g.len());
            a.copy_from_slice(&g);
            if let Some((sep, b)) = rest.split_first_mut() {
                *sep = b'\\';
                b.copy_from_slice(f);
            }
        }
        core::str::from_utf8(out.get(..n).unwrap_or(&[])).unwrap_or("")
    }
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
    /// Stage 4 refused the entry's files (DESIGN.md §4.1, INTERFACES.md §3.2).
    Stage4(stage4::Stage4Error),
    /// The BitLocker volume's metadata or layout was refused (DESIGN.md §6).
    Bde(paguro_core::bde::BdeError),
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

/// Every buffer the stage machine uses (~390 KiB, half of it the recovery
/// browser's directory listing): too large for a UEFI stack, so the caller
/// allocates it.
pub struct Buffers {
    pub ini: [u8; INI_BUF],
    /// The configuration authored on a provisioning boot.
    pub gen_ini: [u8; 4096],
    pub seals: [[u8; seal::MAX_FILE]; 4],
    pub var: [u8; bootstrap::MAX_LOAD_OPTION],
    pub gpt: volume::GptScratch,
    pub handoff: [u8; paguro_core::handoff::MAX_LEN],
    pub secret: [u8; 256],
    /// A path typed in recovery (INTERFACES.md §13.4).
    pub path: [u8; machine::PATH_MAX],
    /// The directory recovery's browser shows.
    pub dir: platform::DirListing,
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
            path: [0; machine::PATH_MAX],
            dir: platform::DirListing::new(),
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

#[cfg(test)]
mod tests {
    use super::names;
    use paguro_core::guid::Guid;
    use paguro_core::seal::Kind;

    #[test]
    fn seal_paths_are_per_volume_lower_case() {
        let g = Guid::parse("6C0A1B2C-3D4E-5F60-7182-93A4B5C6D7E8").unwrap();
        let mut b = [0u8; names::SEAL_PATH_MAX];
        assert_eq!(
            names::seal_path(&g, Kind::Tpm, &mut b),
            "6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\\tpm_seal.bin"
        );
        for k in Kind::ALL {
            let mut b = [0u8; names::SEAL_PATH_MAX];
            let p = names::seal_path(&g, k, &mut b);
            assert!(p.ends_with(k.file_name()) && p.len() <= names::SEAL_PATH_MAX);
        }
    }
}
