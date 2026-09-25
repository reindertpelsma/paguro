//! What Linux recorded about its last boot, for the Windows pre-flight
//! (DESIGN.md §4.6, "Predicting a TPM failure instead of discovering one").
//!
//! **PROPOSED, not yet in INTERFACES.md** — neither the file's location nor
//! its layout is specified there; this is the Windows tool's reading of
//! §4.6 and must be ratified (or replaced) before the initrd writes it.
//!
//! ```text
//! \EFI\paguro\<volume-guid>\recorded.bin        (proposed location)
//! magic "PGRREC\0\x01" | pcr_mask u32 (= 0x95: PCRs 0, 2, 4, 7)
//! | pcr[4][32]                 SHA-256 values as the loader read them (handoff PCRS)
//! | secure_boot_config[32]     SHA-256 over the SHA-256 digests of PCR 7's
//!                              EV_EFI_VARIABLE_DRIVER_CONFIG events, in log order
//! | shim_sha256[32] | loader_sha256[32]
//! ```
//!
//! **Advisory, never authoritative**: the file is not a security input, only
//! a prediction's. A forged mismatch costs one `setupTPM` staging, which
//! still needs the passphrase.

use crate::bytes::{Full, Reader, Writer};
use core::mem::{offset_of, size_of};

pub const MAGIC: &[u8; 8] = b"PGRREC\x00\x01";
pub const FILE_NAME: &str = "recorded.bin";
/// PCRs 0, 2, 4, 7 — the handoff's `PCRS` selection.
pub const PCR_MASK: u32 = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 7;
/// Recorded PCRs, in file order (the set bits of [`PCR_MASK`], ascending).
const PCRS: [u32; 4] = [0, 2, 4, 7];
pub const SHA256_LEN: usize = 32;
pub const LEN: usize = size_of::<RecordedFile>();

/// `recorded.bin` (PROPOSED layout above). Layout only: never instantiated.
#[allow(dead_code)]
#[repr(C, packed)]
struct RecordedFile {
    magic: [u8; 8],
    pcr_mask: u32,
    pcrs: [[u8; SHA256_LEN]; PCRS.len()],
    secure_boot_config: [u8; SHA256_LEN],
    shim_sha256: [u8; SHA256_LEN],
    loader_sha256: [u8; SHA256_LEN],
}
const _: () = assert!(size_of::<RecordedFile>() == 8 + 4 + 4 * 32 + 3 * 32);
const _: () = assert!(PCRS.len() == PCR_MASK.count_ones() as usize);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecordedError {
    BadMagic,
    /// Not exactly [`LEN`] bytes.
    BadLength,
    BadMask,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Recorded {
    /// PCR 0, 2, 4, 7, in that order.
    pub pcrs: [[u8; SHA256_LEN]; PCRS.len()],
    pub secure_boot_config: [u8; SHA256_LEN],
    pub shim_sha256: [u8; SHA256_LEN],
    pub loader_sha256: [u8; SHA256_LEN],
}

impl Recorded {
    pub fn pcr(&self, index: u32) -> Option<&[u8; SHA256_LEN]> {
        let slot = PCRS.iter().position(|&p| p == index)?;
        self.pcrs.get(slot)
    }
}

pub fn parse(file: &[u8]) -> Result<Recorded, RecordedError> {
    if file.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(RecordedError::BadMagic);
    }
    if file.len() != LEN {
        return Err(RecordedError::BadLength);
    }
    let mut r = Reader::new(
        file.get(offset_of!(RecordedFile, pcr_mask)..)
            .unwrap_or(&[]),
    );
    let short = |_| RecordedError::BadLength;
    if r.u32_le().map_err(short)? != PCR_MASK {
        return Err(RecordedError::BadMask);
    }
    let mut out = Recorded::default();
    for p in out.pcrs.iter_mut() {
        *p = *r.array::<SHA256_LEN>().map_err(short)?;
    }
    out.secure_boot_config = *r.array::<SHA256_LEN>().map_err(short)?;
    out.shim_sha256 = *r.array::<SHA256_LEN>().map_err(short)?;
    out.loader_sha256 = *r.array::<SHA256_LEN>().map_err(short)?;
    Ok(out)
}

pub fn write(rec: &Recorded, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.put(MAGIC)?;
    w.u32_le(PCR_MASK)?;
    for p in &rec.pcrs {
        w.put(p)?;
    }
    w.put(&rec.secure_boot_config)?;
    w.put(&rec.shim_sha256)?;
    w.put(&rec.loader_sha256)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_and_refusals() {
        let rec = Recorded {
            pcrs: [[0; 32], [2; 32], [4; 32], [7; 32]],
            secure_boot_config: [8; 32],
            shim_sha256: [9; 32],
            loader_sha256: [10; 32],
        };
        let mut b = [0u8; LEN + 1];
        let n = write(&rec, &mut b).unwrap();
        assert_eq!(n, LEN);
        assert_eq!(parse(&b[..n]), Ok(rec));
        assert_eq!(rec.pcr(7), Some(&[7; 32]));
        assert_eq!(rec.pcr(12), None);
        assert_eq!(parse(&b[..n - 1]), Err(RecordedError::BadLength));
        assert_eq!(parse(&b[..n + 1]), Err(RecordedError::BadLength));
        let mut t = b;
        t[8] = 0xff;
        assert_eq!(parse(&t[..n]), Err(RecordedError::BadMask));
        t[0] = b'X';
        assert_eq!(parse(&t[..n]), Err(RecordedError::BadMagic));
    }
}
