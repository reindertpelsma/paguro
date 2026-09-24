//! `paguro.efi` — the loader (DESIGN.md §4.1).
//!
//! Build: `cargo build -p paguro-efi --target x86_64-unknown-uefi` (or
//! `aarch64-unknown-uefi`; the code is architecture-neutral)
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
//! - the theme is compiled in (`paguro-ui`, built from `themes/` by
//!   `PAGURO_THEME`/`PAGURO_LANG`); no PNG, TOML or font parser is linked, and
//!   no attacker-authored display data is parsed.
#![no_main]
#![no_std]

mod blockio;
mod console;
mod front;
mod gop;
mod input;
mod platform;

/// SBAT metadata (shim's revocation scheme). shim refuses to start a second
/// stage without a `.sbat` section, and paguro.efi is started by a
/// redistributed distribution shim (INTERFACES.md §2). Bump the `paguro`
/// generation when a security fix must revoke older builds.
#[used]
#[unsafe(link_section = ".sbat")]
static SBAT: [u8; include_bytes!("../sbat.csv").len()] = *include_bytes!("../sbat.csv");

use core::ptr::{self, NonNull, addr_of_mut};

use log::info;
use paguro_boot::stage4::Stage4;
use paguro_boot::{BdeVolume, Buffers, Outcome, Params};
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

/// Zeroed pages for a `T` for which all-zero bytes are a valid value.
///
/// # Safety
/// All-zero must be a valid `T`.
unsafe fn zeroed<T>() -> Option<&'static mut T> {
    let size = core::mem::size_of::<T>();
    let pages = size.div_ceil(4096);
    let p: NonNull<u8> =
        boot::allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages).ok()?;
    // SAFETY: a fresh, page-aligned allocation of at least `size` bytes,
    // exclusively ours; the caller vouches for the all-zero value.
    unsafe {
        ptr::write_bytes(p.as_ptr(), 0, pages * 4096);
        Some(&mut *p.as_ptr().cast::<T>())
    }
}

/// The volume's two large parts, in pages: stage 4's memory (~2.5 MiB) and
/// one 64 KiB FVE metadata region.
fn volume_memory() -> Option<(&'static mut Stage4, &'static mut [u8; 0x1_0000])> {
    // SAFETY: all-zero is a valid Stage4 (an unmounted volume; every field
    // is an integer, a bool, an array of those, or an `Option<&mut [u8]>`,
    // whose None is null) and a valid byte array.
    unsafe { Some((zeroed::<Stage4>()?, zeroed::<[u8; 0x1_0000]>()?)) }
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    // Our own log backend: ConOut until the graphical front end takes the
    // display, the serial port after (console.rs).
    console::init_logger();
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
    let Some((stage4, meta)) = volume_memory() else {
        info!("paguro: out of memory");
        return Status::OUT_OF_RESOURCES;
    };
    // BitLocker (stage 3) and NTFS (stage 4), or NTFS alone on an
    // unencrypted volume.
    let mut vol = BdeVolume::new(stage4, meta);
    let out = paguro_boot::run(&mut p, &mut vol, bufs, &Params::PRODUCTION);
    p.release_consoles();
    info!("paguro: outcome {out:?}");
    match out {
        Outcome::Started(_) => Status::SUCCESS,
        Outcome::StartWindows => Status::SUCCESS,
        Outcome::Halted(_) => Status::LOAD_ERROR,
    }
}
