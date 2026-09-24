//! `probe.efi` — what the QEMU scenarios chain into instead of a UKI.
//!
//! It proves the chain end to end, on the serial console:
//!
//! 1. how it was started: `LoadedImage.DeviceHandle`'s device path (the
//!    firmware's file system on paguro's synthetic block device), or that it
//!    has none (an `efi_file` loaded from a buffer);
//! 2. that the device is usable: it opens `SimpleFileSystem` on its own
//!    `DeviceHandle` and prints `\probe.txt` from **its own FAT32**;
//! 3. what paguro handed off: the handoff configuration table's `IMAGE`
//!    records, `STATE` flags and rung.
//!
//! Then it returns. Every line starts with `PAGURO-PROBE:`.
#![no_main]
#![no_std]

extern crate alloc;

use alloc::string::String;
use core::fmt::Write;

use paguro_core::guid::HANDOFF_TABLE;
use paguro_core::handoff::{self, MAX_LEN};
use uefi::boot;
use uefi::prelude::*;
use uefi::proto::device_path::text::{AllowShortcuts, DisplayOnly};
use uefi::proto::loaded_image::LoadedImage;
use uefi::proto::media::file::{File, FileAttribute, FileMode};

macro_rules! say {
    ($($t:tt)*) => {{
        let mut s = String::new();
        let _ = write!(s, $($t)*);
        uefi::system::with_stdout(|o| {
            let _ = o.write_str("PAGURO-PROBE: ");
            let _ = o.write_str(&s);
            let _ = o.write_str("\r\n");
        });
    }};
}

fn device_text(h: Handle) -> String {
    let Ok(dp) = boot::open_protocol_exclusive::<uefi::proto::device_path::DevicePath>(h) else {
        return "(no device path)".into();
    };
    match dp.to_string16(DisplayOnly(false), AllowShortcuts(false)) {
        Ok(s) => String::from(&s),
        Err(_) => "(device path not convertible)".into(),
    }
}

fn own_fat(h: Handle) {
    let Ok(mut fs) = boot::open_protocol_exclusive::<uefi::proto::media::fs::SimpleFileSystem>(h)
    else {
        say!("no SimpleFileSystem on the DeviceHandle");
        return;
    };
    let Ok(mut root) = fs.open_volume() else {
        say!("open_volume failed");
        return;
    };
    let Ok(f) = root.open(
        cstr16!("\\probe.txt"),
        FileMode::Read,
        FileAttribute::empty(),
    ) else {
        say!("\\probe.txt not found on own FAT");
        return;
    };
    let Some(mut f) = f.into_regular_file() else {
        say!("\\probe.txt is not a file");
        return;
    };
    let mut buf = [0u8; 512];
    match f.read(&mut buf) {
        Ok(n) => {
            let text = core::str::from_utf8(buf.get(..n).unwrap_or(&[])).unwrap_or("(not UTF-8)");
            say!("probe.txt: {}", text.trim());
        }
        Err(e) => say!("reading \\probe.txt failed: {:?}", e.status()),
    }
}

fn handoff() {
    let guid = uefi::Guid::from_bytes(HANDOFF_TABLE.0);
    let ptr = uefi::system::with_config_table(|t| {
        t.iter()
            .find(|e| e.guid == guid)
            .map(|e| e.address as *const u8)
    });
    let Some(p) = ptr.filter(|p| !p.is_null()) else {
        say!("no handoff table");
        return;
    };
    // SAFETY: paguro published a blob starting with the 16-byte header; the
    // total length is read from it and bounded before the whole is read.
    let blob = unsafe {
        let hdr = core::slice::from_raw_parts(p, 16);
        let total = hdr
            .get(8..12)
            .and_then(|b| b.try_into().ok())
            .map_or(0, |b| u32::from_le_bytes(b) as usize);
        if !(16..=MAX_LEN).contains(&total) {
            say!("handoff length {total} out of range");
            return;
        }
        core::slice::from_raw_parts(p, total)
    };
    match handoff::decode(blob) {
        Ok(h) => {
            say!(
                "handoff rung={:?} state=0x{:x} config={}",
                h.rung,
                h.state,
                h.config.map_or(0, <[u8]>::len)
            );
            for (role, img) in [
                ("root", h.root),
                ("efi_disk", h.efi_disk),
                ("efi_file", h.efi_file),
            ] {
                if let Some(i) = img {
                    say!(
                        "image role={role} name={} mft={} seq={}",
                        i.name,
                        i.mft_record,
                        i.mft_seq
                    );
                }
            }
        }
        Err(e) => say!("handoff refused: {e:?}"),
    }
}

#[entry]
fn main() -> Status {
    if uefi::helpers::init().is_err() {
        return Status::ABORTED;
    }
    let me = boot::image_handle();
    let dev = boot::open_protocol_exclusive::<LoadedImage>(me)
        .ok()
        .and_then(|li| li.device());
    match dev {
        Some(h) => {
            say!("started from {}", device_text(h));
            own_fat(h);
        }
        None => say!("started with no DeviceHandle (loaded from a buffer)"),
    }
    handoff();
    say!("done");
    Status::SUCCESS
}
