//! `C:\ProgramData\paguro\<volume-guid>\tpm-auth.bin` (INTERFACES.md §8.3,
//! §8.4 "The Windows-written TPM auth file"): the salted, stretched
//! passphrase hash the `tpm` rung mixes into its TPM object's `authValue`
//! (`paguro_crypto::tpm_auth`) and into `derive_vmk`'s wrapping key — the
//! same value `paguro-win`'s `keys::pass_hash` and `paguro-boot`'s
//! `Machine::stretch` both compute as `bitlocker_stretch(user_password_hash(pw),
//! salt, STRETCH_ITERATIONS)`.
//!
//! Deliberately **not** the raw password hash: `C:` is BitLocker-encrypted at
//! rest, so a stolen, powered-off machine cannot read this file at all, and
//! restricting even an unlocked machine's Administrators to *read* still
//! costs a live-admin reader the same 2^20-round stretch an offline attacker
//! already pays against `tpm_seal.bin`'s own salt — the file buys no cheaper
//! dictionary attack than the seal it sits beside already exposes.
//!
//! Written by the Windows tool whenever it re-prepares the loader's seal
//! material from a freshly typed passphrase (`paguro-win`'s `stage`); read by
//! `paguro-initrd` through the read-only ntfs3 mount it already has open for
//! `probe_ntfs`, to re-seal the `tpm` rung after `PaguroTpmBroken` without
//! asking for a PIN of its own.
//!
//! ```text
//! magic "PGTPMA\0\x01" | salt[16] | value[32]
//! ```
//!
//! `salt` is the same salt the new `tpm_seal.bin` must carry: `value` was
//! stretched against it, so a later `tpm`-rung boot only reproduces it by
//! stretching the same passphrase with that exact salt.

use crate::bytes::{Full, Reader, Writer};
use core::mem::size_of;

pub const MAGIC: &[u8; 8] = b"PGTPMA\x00\x01";
pub const FILE_NAME: &str = "tpm-auth.bin";
pub const SALT_LEN: usize = 16;
pub const VALUE_LEN: usize = 32;
pub const LEN: usize = size_of::<TpmAuthFile>();

/// Layout only: never instantiated.
#[allow(dead_code)]
#[repr(C, packed)]
struct TpmAuthFile {
    magic: [u8; 8],
    salt: [u8; SALT_LEN],
    value: [u8; VALUE_LEN],
}
const _: () = assert!(size_of::<TpmAuthFile>() == 8 + SALT_LEN + VALUE_LEN);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TpmAuthError {
    BadMagic,
    /// Not exactly [`LEN`] bytes.
    BadLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TpmAuth {
    pub salt: [u8; SALT_LEN],
    pub value: [u8; VALUE_LEN],
}

/// Refuses anything but exactly [`LEN`] bytes with the right magic; never
/// panics on truncated or garbage input (fuzzed in `tests`, and by
/// `fuzz/fuzz_targets/win_formats.rs`).
pub fn parse(file: &[u8]) -> Result<TpmAuth, TpmAuthError> {
    if file.len() != LEN {
        return Err(TpmAuthError::BadLength);
    }
    if file.get(..MAGIC.len()) != Some(&MAGIC[..]) {
        return Err(TpmAuthError::BadMagic);
    }
    let mut r = Reader::new(file.get(MAGIC.len()..).unwrap_or(&[]));
    let short = |_| TpmAuthError::BadLength;
    Ok(TpmAuth {
        salt: *r.array::<SALT_LEN>().map_err(short)?,
        value: *r.array::<VALUE_LEN>().map_err(short)?,
    })
}

pub fn write(a: &TpmAuth, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.put(MAGIC)?;
    w.put(&a.salt)?;
    w.put(&a.value)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TpmAuth {
        TpmAuth {
            salt: [0x11; SALT_LEN],
            value: [0x22; VALUE_LEN],
        }
    }

    #[test]
    fn roundtrip_and_refusals() {
        let a = sample();
        let mut b = [0u8; LEN + 1];
        let n = write(&a, &mut b).unwrap();
        assert_eq!(n, LEN);
        assert_eq!(parse(&b[..n]), Ok(a));
        assert_eq!(parse(&b[..n - 1]), Err(TpmAuthError::BadLength));
        assert_eq!(parse(&b[..n + 1]), Err(TpmAuthError::BadLength));
        assert_eq!(parse(&[]), Err(TpmAuthError::BadLength));
        let mut t = b;
        t[0] = b'X';
        assert_eq!(parse(&t[..n]), Err(TpmAuthError::BadMagic));
        // The version byte is part of the magic: an old/new version refuses
        // rather than misreading the layout.
        let mut t = b;
        t[7] = 2;
        assert_eq!(parse(&t[..n]), Err(TpmAuthError::BadMagic));
    }

    /// Fuzz-friendly: every length up to well past [`LEN`], and a few fixed
    /// patterns, must return a `Result` rather than panic (indexing,
    /// truncation, all these are exercised by `cargo fuzz` too, via
    /// `fuzz/fuzz_targets/win_formats.rs`). No allocation in this crate, so
    /// fixed buffers stand in for arbitrary lengths.
    #[test]
    fn parser_never_panics_on_arbitrary_bytes() {
        for fill in [0x00u8, 0xff, 0x41] {
            let buf = [fill; LEN + 8];
            for len in 0..=buf.len() {
                let _ = parse(&buf[..len]);
            }
        }
        // A right-length buffer with the right magic but garbage after it
        // still just decodes (every byte after the magic is unconstrained).
        let mut b = [0xAAu8; LEN];
        b[..MAGIC.len()].copy_from_slice(MAGIC);
        assert!(parse(&b).is_ok());
    }
}
