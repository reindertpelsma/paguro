//! `paguro.efi` — the loader (DESIGN.md §4.1).
//!
//! Build: `cargo build -p paguro-efi --target x86_64-unknown-uefi`
//!
//! This binary is a thin [`Platform`](paguro_boot::Platform) over the `uefi`
//! crate plus this `main`. The execution contract — four stages, two taints,
//! recovery that never parses the configuration — is `paguro_boot::run`,
//! which the mock boot tests exercise on the host and `test/qemu/` exercises
//! under OVMF with swtpm.
//!
//! Invariants this binary must keep:
//! - it **never writes to disk** (firmware variables only);
//! - it **never chainloads Windows** — "Start Windows" is `BootNext` + reset;
//! - it implements **no asymmetric cryptography** (shim verifies the UKI);
//! - the theme is compiled in; no attacker-authored display data is parsed.
#![no_main]
#![no_std]

mod platform;

use core::ptr::{self, NonNull, addr_of_mut};

use log::info;
use paguro_boot::{Buffers, Outcome, Params, Unimplemented};
use uefi::boot::{self, AllocateType, MemoryType};
use uefi::prelude::*;

/// Place [`Buffers`] (~200 KiB, too large for the firmware stack) in pages.
fn buffers() -> Option<&'static mut Buffers> {
    let size = core::mem::size_of::<Buffers>();
    let pages = size.div_ceil(4096);
    let p: NonNull<u8> =
        boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages).ok()?;
    let b = p.as_ptr().cast::<Buffers>();
    // SAFETY: `p` is a fresh, page-aligned allocation of at least
    // `size_of::<Buffers>()` bytes, exclusively ours for the image's lifetime.
    // Zero is a valid value for every byte-array and integer field; the two
    // fields holding enums or constructors are written explicitly before the
    // reference is formed.
    unsafe {
        ptr::write_bytes(p.as_ptr(), 0, pages * 4096);
        addr_of_mut!((*b).located).write(paguro_boot::volume::Located::new());
        addr_of_mut!((*b).created).write(paguro_boot::tpm::CreatedObject::new());
        Some(&mut *b)
    }
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    info!("paguro {}", env!("CARGO_PKG_VERSION"));
    let Some(bufs) = buffers() else {
        info!("paguro: out of memory");
        return Status::OUT_OF_RESOURCES;
    };
    let mut p = match platform::Efi::new() {
        Ok(p) => p,
        Err(e) => {
            info!("paguro: platform init failed: {e:?}");
            return Status::DEVICE_ERROR;
        }
    };
    // Stage 3's FVE side and stage 4 are not written yet: Unimplemented
    // refuses them with a typed error after the rungs that need no volume
    // structures have run.
    let out = paguro_boot::run(&mut p, &mut Unimplemented, bufs, &Params::PRODUCTION);
    info!("paguro: outcome {out:?}");
    match out {
        Outcome::Started(_) => Status::SUCCESS,
        Outcome::StartWindows => Status::SUCCESS,
        Outcome::Halted(_) => Status::LOAD_ERROR,
    }
}
