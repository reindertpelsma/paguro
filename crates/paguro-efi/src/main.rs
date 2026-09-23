//! `paguro.efi` — the loader (DESIGN.md §4.1).
//!
//! Build: `cargo build -p paguro-efi --target x86_64-unknown-uefi`
//!
//! The execution contract is four stages, and the order is the design:
//!
//! 1. **Must be correct; nothing protects it.** Read `paguro.ini` (64 KB cap),
//!    SHA-256 the whole file, compare with the `paguro-config-hash` firmware
//!    variable. No parser runs before this comparison.
//! 2. **Behind stage 1.** Parse the file; LOAD TAINT: extend PCR 12 with the
//!    file's hash (sentinel instead when there is no `tpm_seal.bin`).
//! 3. **The key is still obtainable here.** Parse FVE metadata, try the rungs in
//!    escalation order, obtain the VMK; BOOT TAINT: extend PCR 12 with a fixed
//!    sentinel.
//! 4. **The TPM will not re-authorise.** Parse NTFS, locate the image, validate
//!    its map, hand the initrd its handoff, load the UKI through `LoadImage`.
//!
//! Invariants this binary must keep:
//! - it **never writes to disk** (firmware variables only);
//! - it **never chainloads Windows** — "Start Windows" is `BootNext` + reset;
//! - it implements **no asymmetric cryptography** (shim verifies the UKI);
//! - the theme is compiled in; no attacker-authored display data is parsed.
#![no_main]
#![no_std]

use log::info;
use uefi::prelude::*;

mod stages;

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    info!("paguro {}", env!("CARGO_PKG_VERSION"));
    match stages::run() {
        Ok(()) => Status::SUCCESS,
        Err(e) => {
            info!("paguro: {e:?}");
            Status::LOAD_ERROR
        }
    }
}
