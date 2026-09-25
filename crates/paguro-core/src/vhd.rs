//! Fixed-VHD image files (DESIGN.md §2, §8b).
//!
//! A fixed VHD is the raw disk payload followed by a 512-byte footer, so one file
//! is both a bare-metal root for paguro and a disk `wsl --mount --vhd` accepts.
//! Dynamic VHD/VHDX is refused: its block allocation table cannot be followed by
//! a raw sector map.

use core::mem::{offset_of, size_of};

use crate::layout::field_size;

/// Hard disk footer, all fields big-endian (Microsoft Virtual Hard Disk Image
/// Format Specification, "Hard Disk Footer Format"). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct Footer {
    cookie: [u8; 8],
    features: u32,
    file_format_version: u32,
    data_offset: u64,
    time_stamp: u32,
    creator_application: [u8; 4],
    creator_version: u32,
    creator_host_os: u32,
    original_size: u64,
    current_size: u64,
    disk_geometry: u32,
    disk_type: u32,
    checksum: u32,
    unique_id: [u8; 16],
    saved_state: u8,
    reserved: [u8; 427],
}
const _: () = assert!(offset_of!(Footer, current_size) == 48);
const _: () = assert!(offset_of!(Footer, disk_type) == 60);
const _: () = assert!(offset_of!(Footer, checksum) == 64);
const _: () = assert!(size_of::<Footer>() == 512);

pub const FOOTER_LEN: u64 = size_of::<Footer>() as u64;
const COOKIE: &[u8; 8] = b"conectix";
/// `Disk Type` values: 2 fixed, 3 dynamic, 4 differencing.
const DISK_TYPE_FIXED: u32 = 2;

const FOOTER_COOKIE: usize = offset_of!(Footer, cookie);
const FOOTER_CURRENT_SIZE: usize = offset_of!(Footer, current_size);
const FOOTER_DISK_TYPE: usize = offset_of!(Footer, disk_type);
const FOOTER_CHECKSUM: usize = offset_of!(Footer, checksum);
const FOOTER_CHECKSUM_END: usize = FOOTER_CHECKSUM + field_size(|f: Footer| f.checksum);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VhdError {
    BadCookie,
    NotFixed(u32),
    BadChecksum,
    SizeMismatch,
}

fn be32(b: &[u8; 512], at: usize) -> u32 {
    let mut v = [0u8; 4];
    v.copy_from_slice(b.get(at..at + 4).unwrap_or(&[0; 4]));
    u32::from_be_bytes(v)
}

fn be64(b: &[u8; 512], at: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(b.get(at..at + 8).unwrap_or(&[0; 8]));
    u64::from_be_bytes(v)
}

/// Validate the footer of a file of `file_len` bytes and return the payload
/// length — the bytes that form the virtual disk, starting at offset 0.
pub fn fixed_payload_len(footer: &[u8; 512], file_len: u64) -> Result<u64, VhdError> {
    if footer.get(FOOTER_COOKIE..FOOTER_COOKIE + COOKIE.len()) != Some(&COOKIE[..]) {
        return Err(VhdError::BadCookie);
    }
    let disk_type = be32(footer, FOOTER_DISK_TYPE);
    if disk_type != DISK_TYPE_FIXED {
        return Err(VhdError::NotFixed(disk_type));
    }
    let stored = be32(footer, FOOTER_CHECKSUM);
    let mut sum: u32 = 0;
    for (i, b) in footer.iter().enumerate() {
        if !(FOOTER_CHECKSUM..FOOTER_CHECKSUM_END).contains(&i) {
            sum = sum.wrapping_add(u32::from(*b));
        }
    }
    if !sum != stored {
        return Err(VhdError::BadChecksum);
    }
    let current_size = be64(footer, FOOTER_CURRENT_SIZE);
    let payload = file_len
        .checked_sub(FOOTER_LEN)
        .ok_or(VhdError::SizeMismatch)?;
    if current_size != payload {
        return Err(VhdError::SizeMismatch);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn footer(disk_type: u32, size: u64) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[0..8].copy_from_slice(COOKIE);
        f[40..48].copy_from_slice(&size.to_be_bytes()); // original size
        f[48..56].copy_from_slice(&size.to_be_bytes()); // current size
        f[60..64].copy_from_slice(&disk_type.to_be_bytes());
        let sum = f.iter().fold(0u32, |a, b| a.wrapping_add(u32::from(*b)));
        f[64..68].copy_from_slice(&(!sum).to_be_bytes());
        f
    }

    #[test]
    fn accepts_fixed() {
        let f = footer(2, 1 << 30);
        assert_eq!(fixed_payload_len(&f, (1 << 30) + 512), Ok(1 << 30));
    }

    #[test]
    fn refuses_dynamic_and_mismatch() {
        assert_eq!(
            fixed_payload_len(&footer(3, 4096), 4096 + 512),
            Err(VhdError::NotFixed(3))
        );
        assert_eq!(
            fixed_payload_len(&footer(2, 4096), 8192),
            Err(VhdError::SizeMismatch)
        );
        let mut f = footer(2, 4096);
        f[100] ^= 1;
        assert_eq!(
            fixed_payload_len(&f, 4096 + 512),
            Err(VhdError::BadChecksum)
        );
    }
}
