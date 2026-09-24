//! On-disk layouts of the `*_seal.bin` protector files, v1 (INTERFACES.md §4).
//!
//! One rule: `paguro.ini` is configuration; crypto material lives in these
//! files. They are inert at rest — a sealed object is encrypted under the TPM's
//! storage seed, and a wrapped VMK needs the passphrase — which is why they may
//! live on the unencrypted ESP. No field is trusted: a wrong value fails at the
//! TPM or at the FVEK unwrap (DESIGN.md §6, "Protector material is
//! self-validating"). The parser's job is only to refuse malformed shapes.
//!
//! ```text
//! header   magic[8]   "PGRTPM\0\x01" | "PGRSTP\0\x01" | "PGRPAS\0\x01" | "PGRBYP\0\x01"
//! tpm          pcr_bank u16 | pcr_mask u32 | wrapped_vmk[32] | salt[16] | sealed
//! setuptpm     wrapped_vmk[32] | salt[16]
//! passphrase   wrapped_vmk[32] | salt[16]
//! pin bypass   deadline u64 | pcr_bank u16 | pcr_mask u32
//!              | wrapped_vmk[32] | salt[16] | sealed
//! sealed       len u16 | TPM2B_PUBLIC | TPM2B_PRIVATE   (len ≤ 1024, exactly filled)
//! ```
//!
//! paguro integers are little-endian; the two TPM2B values keep TPM marshalling
//! (big-endian sizes).

use crate::bytes::{Full, Reader, Writer};

pub const VMK_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const MAGIC_LEN: usize = 8;
/// Whole-file cap, checked before the first byte is interpreted.
pub const MAX_FILE: usize = 4096;
/// Cap on the `sealed` field (both TPM2B values).
pub const MAX_SEALED: usize = 1024;
/// `TPM_ALG_SHA256`, the only bank v1 accepts.
pub const PCR_BANK_SHA256: u16 = 0x000B;
/// PCRs 0, 2, 4, 7 and 12 — the only selection v1 accepts.
pub const PCR_MASK_V1: u32 = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 7 | 1 << 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tpm,
    SetupTpm,
    Passphrase,
    PinBypass,
}

impl Kind {
    pub const ALL: [Kind; 4] = [Kind::Tpm, Kind::SetupTpm, Kind::Passphrase, Kind::PinBypass];

    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Kind::Tpm => b"PGRTPM\x00\x01",
            Kind::SetupTpm => b"PGRSTP\x00\x01",
            Kind::Passphrase => b"PGRPAS\x00\x01",
            Kind::PinBypass => b"PGRBYP\x00\x01",
        }
    }
    /// File name under `\EFI\paguro\` (INTERFACES.md §2).
    pub const fn file_name(self) -> &'static str {
        match self {
            Kind::Tpm => "tpm_seal.bin",
            Kind::SetupTpm => "setuptpm_seal.bin",
            Kind::Passphrase => "passphrase_seal.bin",
            Kind::PinBypass => "tpm_pin_bypass_seal.bin",
        }
    }
    pub const fn has_tpm_object(self) -> bool {
        matches!(self, Kind::Tpm | Kind::PinBypass)
    }
}

/// The TPM object: two TPM2B values in TPM marshalling. Both slices include
/// their own 2-byte big-endian size, so they can be copied into a
/// `TPM2_Load` command verbatim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sealed<'a> {
    pub public: &'a [u8],
    pub private: &'a [u8],
}

impl<'a> Sealed<'a> {
    /// The `TPMT_PUBLIC` inside `public` (what the object's name hashes).
    pub fn public_area(&self) -> &'a [u8] {
        self.public.get(2..).unwrap_or(&[])
    }
    /// Bytes this occupies after its `len` field.
    pub const fn len(&self) -> usize {
        self.public.len() + self.private.len()
    }
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pcrs {
    pub bank: u16,
    pub mask: u32,
}

impl Pcrs {
    pub const V1: Pcrs = Pcrs {
        bank: PCR_BANK_SHA256,
        mask: PCR_MASK_V1,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seal<'a> {
    pub kind: Kind,
    /// TPM `Clock` deadline in ms; only for [`Kind::PinBypass`].
    pub deadline: Option<u64>,
    /// Only for the kinds with a TPM object.
    pub pcrs: Option<Pcrs>,
    pub wrapped_vmk: &'a [u8; VMK_LEN],
    pub salt: &'a [u8; SALT_LEN],
    pub sealed: Option<Sealed<'a>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    /// Larger than [`MAX_FILE`].
    TooLarge,
    BadMagic,
    Truncated,
    /// `pcr_bank` is not SHA-256.
    BadPcrBank,
    /// `pcr_mask` is not exactly {0,2,4,7,12}.
    BadPcrMask,
    /// `len` exceeds [`MAX_SEALED`].
    SealedTooLarge,
    /// The two TPM2B values do not exactly fill `len`, or one is empty.
    SealedMalformed,
    TrailingBytes,
}

fn short(_: crate::bytes::Short) -> SealError {
    SealError::Truncated
}

fn read_sealed<'a>(r: &mut Reader<'a>) -> Result<Sealed<'a>, SealError> {
    let len = usize::from(r.u16_le().map_err(short)?);
    if len > MAX_SEALED {
        return Err(SealError::SealedTooLarge);
    }
    let field = r.take(len).map_err(short)?;
    let mut f = Reader::new(field);
    let mut tpm2b = || -> Result<&'a [u8], SealError> {
        let whole = f.rest();
        let size = usize::from(f.u16_be().map_err(|_| SealError::SealedMalformed)?);
        if size == 0 {
            return Err(SealError::SealedMalformed);
        }
        f.take(size).map_err(|_| SealError::SealedMalformed)?;
        whole.get(..size + 2).ok_or(SealError::SealedMalformed)
    };
    let public = tpm2b()?;
    let private = tpm2b()?;
    if !f.is_empty() {
        return Err(SealError::SealedMalformed);
    }
    Ok(Sealed { public, private })
}

/// Parse the body that follows the magic (also the handoff's `PROVISION`
/// value, INTERFACES.md §8, for [`Kind::Tpm`]).
pub fn read_body(kind: Kind, body: &[u8]) -> Result<Seal<'_>, SealError> {
    if body.len() > MAX_FILE {
        return Err(SealError::TooLarge);
    }
    let mut r = Reader::new(body);
    let deadline = match kind {
        Kind::PinBypass => Some(r.u64_le().map_err(short)?),
        _ => None,
    };
    let pcrs = if kind.has_tpm_object() {
        let bank = r.u16_le().map_err(short)?;
        let mask = r.u32_le().map_err(short)?;
        if bank != PCR_BANK_SHA256 {
            return Err(SealError::BadPcrBank);
        }
        if mask != PCR_MASK_V1 {
            return Err(SealError::BadPcrMask);
        }
        Some(Pcrs { bank, mask })
    } else {
        None
    };
    let wrapped_vmk = r.array::<VMK_LEN>().map_err(short)?;
    let salt = r.array::<SALT_LEN>().map_err(short)?;
    let sealed = if kind.has_tpm_object() {
        Some(read_sealed(&mut r)?)
    } else {
        None
    };
    if !r.is_empty() {
        return Err(SealError::TrailingBytes);
    }
    Ok(Seal {
        kind,
        deadline,
        pcrs,
        wrapped_vmk,
        salt,
        sealed,
    })
}

/// Parse a whole seal file of the expected `kind`.
pub fn read(kind: Kind, file: &[u8]) -> Result<Seal<'_>, SealError> {
    if file.len() > MAX_FILE {
        return Err(SealError::TooLarge);
    }
    let (magic, body) = file
        .split_at_checked(MAGIC_LEN)
        .ok_or(SealError::Truncated)?;
    if magic != kind.magic() {
        return Err(SealError::BadMagic);
    }
    read_body(kind, body)
}

/// Serialise the body (no magic). Fields irrelevant to `seal.kind` are ignored;
/// ones it requires but lacks are written as zero / empty, which [`read_body`]
/// then refuses — so only well-formed seals round-trip.
pub fn write_body(seal: &Seal<'_>, w: &mut Writer<'_>) -> Result<(), Full> {
    if seal.kind == Kind::PinBypass {
        w.u64_le(seal.deadline.unwrap_or(0))?;
    }
    if seal.kind.has_tpm_object() {
        let p = seal.pcrs.unwrap_or(Pcrs { bank: 0, mask: 0 });
        w.u16_le(p.bank)?;
        w.u32_le(p.mask)?;
    }
    w.put(seal.wrapped_vmk)?;
    w.put(seal.salt)?;
    if seal.kind.has_tpm_object() {
        let s = seal.sealed.unwrap_or(Sealed {
            public: &[],
            private: &[],
        });
        w.u16_le(u16::try_from(s.len()).map_err(|_| Full)?)?;
        w.put(s.public)?;
        w.put(s.private)?;
    }
    Ok(())
}

/// Serialise a whole file; returns its length.
pub fn write(seal: &Seal<'_>, out: &mut [u8]) -> Result<usize, Full> {
    let mut w = Writer::new(out);
    w.put(seal.kind.magic())?;
    write_body(seal, &mut w)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB: &[u8] = &[0, 3, 0xaa, 0xbb, 0xcc];
    const PRIV: &[u8] = &[0, 2, 0x11, 0x22];

    fn file(kind: Kind) -> ([u8; 256], usize) {
        let mut out = [0u8; 256];
        let s = Seal {
            kind,
            deadline: Some(77),
            pcrs: Some(Pcrs::V1),
            wrapped_vmk: &[0x5a; 32],
            salt: &[0xa5; 16],
            sealed: Some(Sealed {
                public: PUB,
                private: PRIV,
            }),
        };
        let n = write(&s, &mut out).unwrap();
        (out, n)
    }

    #[test]
    fn every_kind_roundtrips() {
        for kind in Kind::ALL {
            let (f, n) = file(kind);
            let s = read(kind, &f[..n]).unwrap();
            assert_eq!(s.kind, kind);
            assert_eq!(s.wrapped_vmk, &[0x5a; 32]);
            assert_eq!(s.salt, &[0xa5; 16]);
            assert_eq!(s.deadline.is_some(), kind == Kind::PinBypass);
            assert_eq!(s.pcrs.is_some(), kind.has_tpm_object());
            if let Some(sealed) = s.sealed {
                assert_eq!((sealed.public, sealed.private), (PUB, PRIV));
                assert_eq!(sealed.public_area(), &[0xaa, 0xbb, 0xcc]);
                assert!(!sealed.is_empty());
            }
            assert!(kind.file_name().ends_with("_seal.bin"));
        }
        let (f, n) = file(Kind::PinBypass);
        assert_eq!(n, 8 + 8 + 6 + 48 + 2 + 9);
        assert_eq!(read(Kind::PinBypass, &f[..n]).unwrap().deadline, Some(77));
    }

    #[test]
    fn every_error_variant() {
        let (f, n) = file(Kind::Tpm);
        let good = &f[..n];
        assert_eq!(
            read(Kind::Tpm, &[0; MAX_FILE + 1]),
            Err(SealError::TooLarge)
        );
        assert_eq!(
            read_body(Kind::Tpm, &[0; MAX_FILE + 1]),
            Err(SealError::TooLarge)
        );
        assert_eq!(read(Kind::Tpm, &good[..5]), Err(SealError::Truncated));
        assert_eq!(read(Kind::SetupTpm, good), Err(SealError::BadMagic));
        for cut in [9, 14, 40, 60, 63, n - 1] {
            assert_eq!(
                read(Kind::Tpm, &good[..cut]),
                Err(SealError::Truncated),
                "{cut}"
            );
        }
        let mut b = f;
        b[8] = 0x04; // TPM_ALG_SHA1
        assert_eq!(read(Kind::Tpm, &b[..n]), Err(SealError::BadPcrBank));
        let mut b = f;
        b[10] |= 2; // add PCR 1
        assert_eq!(read(Kind::Tpm, &b[..n]), Err(SealError::BadPcrMask));
        let mut b = f;
        b[62..64].copy_from_slice(&1025u16.to_le_bytes());
        assert_eq!(read(Kind::Tpm, &b[..n]), Err(SealError::SealedTooLarge));
        // len says 10 but the TPM2Bs fill 9: the tenth byte would be trailing
        // inside the field.
        let mut b = f;
        b[62..64].copy_from_slice(&10u16.to_le_bytes());
        assert_eq!(
            read(Kind::Tpm, &b[..n + 1]),
            Err(SealError::SealedMalformed)
        );
        // public claims more than len holds
        let mut b = f;
        b[65] = 9;
        assert_eq!(read(Kind::Tpm, &b[..n]), Err(SealError::SealedMalformed));
        // empty public
        let mut b = f;
        b[62..64].copy_from_slice(&6u16.to_le_bytes());
        b[64..70].copy_from_slice(&[0, 0, 0, 2, 0x11, 0x22]);
        assert_eq!(read(Kind::Tpm, &b[..70]), Err(SealError::SealedMalformed));
        let mut b = [0u8; 300];
        b[..n].copy_from_slice(good);
        assert_eq!(read(Kind::Tpm, &b[..n + 1]), Err(SealError::TrailingBytes));
        let (p, pn) = file(Kind::Passphrase);
        assert_eq!(
            read(Kind::Passphrase, &p[..pn + 1]),
            Err(SealError::TrailingBytes)
        );
    }

    #[test]
    fn writer_reports_full() {
        let (f, n) = file(Kind::Tpm);
        let seal = read(Kind::Tpm, &f[..n]).unwrap();
        let mut small = [0u8; 20];
        assert_eq!(write(&seal, &mut small), Err(Full));
    }
}
