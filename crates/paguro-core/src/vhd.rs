//! Fixed-VHD image files (DESIGN.md §2, §8b).
//!
//! A fixed VHD is the raw disk payload followed by a 512-byte footer, so one file
//! is both a bare-metal root for paguro and a disk `wsl --mount --vhd` accepts.
//! Dynamic VHD/VHDX is refused: its block allocation table cannot be followed by
//! a raw sector map.

pub const FOOTER_LEN: u64 = 512;
const COOKIE: &[u8; 8] = b"conectix";
const DISK_TYPE_FIXED: u32 = 2;

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
    if footer.get(0..8) != Some(&COOKIE[..]) {
        return Err(VhdError::BadCookie);
    }
    let disk_type = be32(footer, 60);
    if disk_type != DISK_TYPE_FIXED {
        return Err(VhdError::NotFixed(disk_type));
    }
    let stored = be32(footer, 64);
    let mut sum: u32 = 0;
    for (i, b) in footer.iter().enumerate() {
        if !(64..68).contains(&i) {
            sum = sum.wrapping_add(u32::from(*b));
        }
    }
    if !sum != stored {
        return Err(VhdError::BadChecksum);
    }
    let current_size = be64(footer, 48);
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
