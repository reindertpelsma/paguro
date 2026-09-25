//! The TCG crypto-agile event log (TCG PC Client Platform Firmware Profile
//! 1.05, §10.2): what `Tbsi_Get_TCG_Log` returns on Windows and
//! `binary_bios_measurements` on Linux. Read by the pre-flight (DESIGN.md
//! §4.6) to predict a PCR 7 change from the path-independent
//! `EV_EFI_VARIABLE_DRIVER_CONFIG` prefix instead of the register.
//!
//! ```text
//! first    TCG_PCR_EVENT (SHA-1 format): pcr u32 | type u32 | digest[20]
//!          | size u32 | TCG_EfiSpecIDEvent ("Spec ID Event03", the
//!          algorithm table)
//! then     TCG_PCR_EVENT2: pcr u32 | type u32 | count u32
//!          | { alg u16 | digest[size from the table] } × count
//!          | size u32 | data[size]
//! ```
//!
//! Bounded like every parser here: the log is capped at [`MAX_LOG`], events
//! at [`MAX_EVENTS`], the algorithm table at [`MAX_ALGS`]; a digest whose
//! algorithm the table does not list is an error (its size is unknown).

use crate::bytes::{Full, Reader, Writer};

pub const MAX_LOG: usize = 4 * 1024 * 1024;
pub const MAX_EVENTS: usize = 16 * 1024;
pub const MAX_ALGS: usize = 8;
pub const ALG_SHA256: u16 = 0x000B;
/// `TPM_ALG_SHA1` (TCG Algorithm Registry): the header event's digest and the
/// filler bank [`write`] emits.
pub const ALG_SHA1: u16 = 0x0004;
pub const SHA1_LEN: usize = 20;
pub const SHA256_LEN: usize = 32;
/// Largest digest size accepted in the algorithm table (SHA-512).
pub const MAX_DIGEST_LEN: usize = 64;
/// The PCR whose Secure Boot configuration prefix the pre-flight predicts.
pub const PCR_SECURE_BOOT: u32 = 7;

/// `TCG_EfiSpecIDEvent` (PC Client PFP §10.4.5.1): after the signature,
/// `platformClass` u32, `specVersionMinor`, `specVersionMajor`, `specErrata`,
/// `uintnSize` (one byte each) precede `numberOfAlgorithms`.
const SPEC_ID_FIXED_LEN: usize = 8;
/// `uintnSize` value for UINTN = u64 (2 = 64-bit), and the spec version 2.0.
const SPEC_ID_VERSION_MAJOR: u8 = 2;
const SPEC_ID_UINTN_64: u8 = 2;

pub const EV_NO_ACTION: u32 = 0x03;
pub const EV_SEPARATOR: u32 = 0x04;
pub const EV_EFI_VARIABLE_DRIVER_CONFIG: u32 = 0x8000_0001;
pub const EV_EFI_VARIABLE_AUTHORITY: u32 = 0x8000_00E0;

const SPEC_ID_SIGNATURE: &[u8; 16] = b"Spec ID Event03\0";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogError {
    TooLarge,
    Truncated,
    /// The first event is not a crypto-agile Spec ID event.
    NotCryptoAgile,
    /// Algorithm table empty, oversized, or with a zero/oversized digest size.
    BadAlgorithms,
    /// A digest names an algorithm the table does not list.
    UnknownAlgorithm,
    TooManyEvents,
    /// The log has no SHA-256 bank.
    NoSha256,
}

/// One `TCG_PCR_EVENT2`, with its SHA-256 digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Event<'a> {
    pub pcr: u32,
    pub kind: u32,
    pub sha256: &'a [u8; SHA256_LEN],
    pub data: &'a [u8],
}

/// Visit every event after the Spec ID header, in log order. Returns the
/// number of events visited.
pub fn walk<'a>(log: &'a [u8], mut visit: impl FnMut(Event<'a>)) -> Result<usize, LogError> {
    if log.len() > MAX_LOG {
        return Err(LogError::TooLarge);
    }
    let mut r = Reader::new(log);
    // Header event, SHA-1 format.
    r.u32_le().map_err(|_| LogError::Truncated)?;
    let kind = r.u32_le().map_err(|_| LogError::Truncated)?;
    r.take(SHA1_LEN).map_err(|_| LogError::Truncated)?;
    let size = r.u32_le().map_err(|_| LogError::Truncated)? as usize;
    let spec = r.take(size).map_err(|_| LogError::Truncated)?;
    if kind != EV_NO_ACTION {
        return Err(LogError::NotCryptoAgile);
    }
    let mut s = Reader::new(spec);
    if s.array::<{ SPEC_ID_SIGNATURE.len() }>()
        .map_err(|_| LogError::NotCryptoAgile)?
        != SPEC_ID_SIGNATURE
    {
        return Err(LogError::NotCryptoAgile);
    }
    // platformClass u32, minor, major, errata, uintnSize.
    s.take(SPEC_ID_FIXED_LEN)
        .map_err(|_| LogError::NotCryptoAgile)?;
    let n_algs = s.u32_le().map_err(|_| LogError::NotCryptoAgile)? as usize;
    if n_algs == 0 || n_algs > MAX_ALGS {
        return Err(LogError::BadAlgorithms);
    }
    let mut algs = [(0u16, 0usize); MAX_ALGS];
    for slot in algs.iter_mut().take(n_algs) {
        let id = s.u16_le().map_err(|_| LogError::BadAlgorithms)?;
        let len = usize::from(s.u16_le().map_err(|_| LogError::BadAlgorithms)?);
        if len == 0 || len > MAX_DIGEST_LEN {
            return Err(LogError::BadAlgorithms);
        }
        *slot = (id, len);
    }
    let algs = algs.get(..n_algs).unwrap_or(&[]);
    if !algs
        .iter()
        .any(|&(id, len)| id == ALG_SHA256 && len == SHA256_LEN)
    {
        return Err(LogError::NoSha256);
    }
    let mut count = 0usize;
    while !r.is_empty() {
        count += 1;
        if count > MAX_EVENTS {
            return Err(LogError::TooManyEvents);
        }
        let pcr = r.u32_le().map_err(|_| LogError::Truncated)?;
        let kind = r.u32_le().map_err(|_| LogError::Truncated)?;
        let n = r.u32_le().map_err(|_| LogError::Truncated)? as usize;
        if n > MAX_ALGS {
            return Err(LogError::BadAlgorithms);
        }
        let mut sha256 = None;
        for _ in 0..n {
            let id = r.u16_le().map_err(|_| LogError::Truncated)?;
            let len = algs
                .iter()
                .find(|a| a.0 == id)
                .map(|a| a.1)
                .ok_or(LogError::UnknownAlgorithm)?;
            let d = r.take(len).map_err(|_| LogError::Truncated)?;
            if id == ALG_SHA256 {
                sha256 =
                    Some(<&[u8; SHA256_LEN]>::try_from(d).map_err(|_| LogError::BadAlgorithms)?);
            }
        }
        let size = r.u32_le().map_err(|_| LogError::Truncated)? as usize;
        let data = r.take(size).map_err(|_| LogError::Truncated)?;
        let sha256 = sha256.ok_or(LogError::NoSha256)?;
        visit(Event {
            pcr,
            kind,
            sha256,
            data,
        });
    }
    Ok(count)
}

/// The SHA-256 digests of PCR 7's `EV_EFI_VARIABLE_DRIVER_CONFIG` events
/// (`SecureBoot`, `PK`, `KEK`, `db`, `dbx`), in log order: the
/// path-independent part of PCR 7. Returns how many there were.
pub fn driver_config_digests<'a>(
    log: &'a [u8],
    mut visit: impl FnMut(&'a [u8; SHA256_LEN]),
) -> Result<usize, LogError> {
    let mut n = 0usize;
    walk(log, |e| {
        if e.pcr == PCR_SECURE_BOOT && e.kind == EV_EFI_VARIABLE_DRIVER_CONFIG {
            n += 1;
            visit(e.sha256);
        }
    })?;
    Ok(n)
}

/// Write a log (tests, mock platforms): a Spec ID header with SHA-1 and
/// SHA-256 banks, then `(pcr, type, sha256, data)` events whose SHA-1
/// digest is a filler.
pub fn write(
    events: &[(u32, u32, [u8; SHA256_LEN], &[u8])],
    out: &mut [u8],
) -> Result<usize, Full> {
    // signature | fixed fields | numberOfAlgorithms | 2 × (algId, digestSize)
    // | vendorInfoSize.
    const SPEC_LEN: u32 = (SPEC_ID_SIGNATURE.len() + SPEC_ID_FIXED_LEN + 4 + 2 * 4 + 1) as u32;
    const N_BANKS: u32 = 2;
    let mut w = Writer::new(out);
    w.u32_le(0)?;
    w.u32_le(EV_NO_ACTION)?;
    w.put(&[0; SHA1_LEN])?;
    w.u32_le(SPEC_LEN)?;
    w.put(SPEC_ID_SIGNATURE)?;
    // platformClass 0, specVersionMinor 0, major 2, errata 0, uintnSize 2.
    w.put(&[0, 0, 0, 0, 0, SPEC_ID_VERSION_MAJOR, 0, SPEC_ID_UINTN_64])?;
    w.u32_le(N_BANKS)?;
    w.u16_le(ALG_SHA1)?;
    w.u16_le(SHA1_LEN as u16)?;
    w.u16_le(ALG_SHA256)?;
    w.u16_le(SHA256_LEN as u16)?;
    w.u8(0)?;
    for (pcr, kind, d, data) in events {
        w.u32_le(*pcr)?;
        w.u32_le(*kind)?;
        w.u32_le(N_BANKS)?;
        w.u16_le(ALG_SHA1)?;
        w.put(&[0xaa; SHA1_LEN])?;
        w.u16_le(ALG_SHA256)?;
        w.put(d)?;
        w.u32_le(u32::try_from(data.len()).map_err(|_| Full)?)?;
        w.put(data)?;
    }
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn log() -> Vec<u8> {
        let mut b = std::vec![0u8; 4096];
        let n = write(
            &[
                (0, 0x08, [1; 32], b"crtm"),
                (7, EV_EFI_VARIABLE_DRIVER_CONFIG, [2; 32], b"SecureBoot"),
                (7, EV_EFI_VARIABLE_DRIVER_CONFIG, [3; 32], b"dbx"),
                (7, EV_SEPARATOR, [4; 32], &[0; 4]),
                (7, EV_EFI_VARIABLE_AUTHORITY, [5; 32], b"MS PCA"),
                (4, 0x80000003, [6; 32], b"bootmgfw"),
            ],
            &mut b,
        )
        .unwrap();
        b.truncate(n);
        b
    }

    #[test]
    fn walks_and_selects_the_driver_config_prefix() {
        let l = log();
        let mut all = Vec::new();
        assert_eq!(walk(&l, |e| all.push((e.pcr, e.kind))), Ok(6));
        let mut d = Vec::new();
        assert_eq!(driver_config_digests(&l, |x| d.push(*x)), Ok(2));
        assert_eq!(d, [[2; 32], [3; 32]]);
    }

    #[test]
    fn refusals() {
        let l = log();
        assert_eq!(walk(&l[..l.len() - 1], |_| {}), Err(LogError::Truncated));
        let mut t = l.clone();
        t[4] = 1; // header type
        assert_eq!(walk(&t, |_| {}), Err(LogError::NotCryptoAgile));
        let mut t = l.clone();
        t[32] = b'X'; // signature
        assert_eq!(walk(&t, |_| {}), Err(LogError::NotCryptoAgile));
        // An event naming SHA-384, which the table lacks.
        let hdr_len = 32 + u32::from_le_bytes(l[28..32].try_into().unwrap()) as usize;
        let mut t = l.clone();
        t[hdr_len + 12] = 0x0C;
        assert_eq!(walk(&t, |_| {}), Err(LogError::UnknownAlgorithm));
        assert_eq!(walk(&[], |_| {}), Err(LogError::Truncated));
    }
}
