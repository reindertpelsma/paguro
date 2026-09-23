//! On-disk layouts of the `*_seal.bin` protector files (DESIGN.md §6, "What
//! lives where").
//!
//! One rule: `paguro.ini` is configuration; crypto material lives in these
//! files. They are inert at rest — a sealed object is encrypted under the TPM's
//! storage seed, and a wrapped VMK needs the passphrase — which is why they may
//! live on the unencrypted ESP. Layouts are fixed and length-prefixed, so reading
//! them needs no parser worth the name.
//!
//! ```text
//! tpm_seal.bin             magic | wrapped VMK 32 | salt 16 | sealed object
//! setuptpm_seal.bin        magic | wrapped VMK 32 | salt 16
//! passphrase_seal.bin      magic | wrapped VMK 32 | salt 16
//! tpm_pin_bypass_seal.bin  magic | deadline u64 | wrapped VMK 32 | salt 16
//!                          | sealed object
//! sealed object            len u16 LE | TPM2B_PUBLIC ++ TPM2B_PRIVATE
//! ```

pub const VMK_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
/// A keyedhash sealed object is ~230 bytes; cap well above that.
pub const MAX_SEALED: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Tpm,
    SetupTpm,
    Passphrase,
    PinBypass,
}

impl Kind {
    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Kind::Tpm => b"PGRTPM\x00\x01",
            Kind::SetupTpm => b"PGRSTP\x00\x01",
            Kind::Passphrase => b"PGRPAS\x00\x01",
            Kind::PinBypass => b"PGRBYP\x00\x01",
        }
    }
    const fn has_sealed_object(self) -> bool {
        matches!(self, Kind::Tpm | Kind::PinBypass)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Seal<'a> {
    pub kind: Kind,
    /// TPM clock deadline, milliseconds; only for [`Kind::PinBypass`].
    pub deadline: Option<u64>,
    pub wrapped_vmk: &'a [u8; VMK_LEN],
    pub salt: &'a [u8; SALT_LEN],
    pub sealed_object: Option<&'a [u8]>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SealError {
    BadMagic,
    Truncated,
    SealedTooLarge,
    TrailingBytes,
}

fn take<'a>(b: &mut &'a [u8], n: usize) -> Result<&'a [u8], SealError> {
    let (head, tail) = b.split_at_checked(n).ok_or(SealError::Truncated)?;
    *b = tail;
    Ok(head)
}

pub fn read(kind: Kind, file: &[u8]) -> Result<Seal<'_>, SealError> {
    let mut b = file;
    if take(&mut b, 8)? != kind.magic() {
        return Err(SealError::BadMagic);
    }
    let deadline = if kind == Kind::PinBypass {
        let d: [u8; 8] = take(&mut b, 8)?
            .try_into()
            .map_err(|_| SealError::Truncated)?;
        Some(u64::from_le_bytes(d))
    } else {
        None
    };
    let wrapped_vmk = take(&mut b, VMK_LEN)?
        .try_into()
        .map_err(|_| SealError::Truncated)?;
    let salt = take(&mut b, SALT_LEN)?
        .try_into()
        .map_err(|_| SealError::Truncated)?;
    let sealed_object = if kind.has_sealed_object() {
        let l: [u8; 2] = take(&mut b, 2)?
            .try_into()
            .map_err(|_| SealError::Truncated)?;
        let len = usize::from(u16::from_le_bytes(l));
        if len > MAX_SEALED {
            return Err(SealError::SealedTooLarge);
        }
        Some(take(&mut b, len)?)
    } else {
        None
    };
    if !b.is_empty() {
        return Err(SealError::TrailingBytes);
    }
    Ok(Seal {
        kind,
        deadline,
        wrapped_vmk,
        salt,
        sealed_object,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_passphrase_and_tpm() {
        let mut f = [0u8; 8 + 32 + 16];
        f[..8].copy_from_slice(Kind::Passphrase.magic());
        f[8] = 0xaa;
        let s = read(Kind::Passphrase, &f).unwrap();
        assert_eq!(s.wrapped_vmk[0], 0xaa);
        assert!(s.sealed_object.is_none());

        let mut t = [0u8; 8 + 32 + 16 + 2 + 3];
        t[..8].copy_from_slice(Kind::Tpm.magic());
        t[56..58].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            read(Kind::Tpm, &t).unwrap().sealed_object,
            Some(&[0u8; 3][..])
        );
    }

    #[test]
    fn refuses_wrong_kind_and_trailing_bytes() {
        let mut f = [0u8; 8 + 32 + 16 + 1];
        f[..8].copy_from_slice(Kind::Passphrase.magic());
        assert_eq!(read(Kind::Tpm, &f), Err(SealError::BadMagic));
        assert_eq!(read(Kind::Passphrase, &f), Err(SealError::TrailingBytes));
    }
}
