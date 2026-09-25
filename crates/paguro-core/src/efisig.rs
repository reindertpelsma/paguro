//! `EFI_SIGNATURE_LIST` (UEFI 2.10 §32.4.1): the payload of `db`, `dbx`,
//! `MokList`/`MokListRT` and shim's `MokNew` enrolment request
//! (INTERFACES.md §11.6).
//!
//! ```text
//! list    SignatureType GUID | SignatureListSize u32 | SignatureHeaderSize u32
//!         | SignatureSize u32 | header[SignatureHeaderSize]
//!         | { SignatureOwner GUID | data[SignatureSize - 16] } × n
//! ```
//!
//! The writer produces exactly what `mokutil --import` writes for one DER
//! certificate (mokutil `src/mokutil.c`, `issue_mok_request`: X.509 type,
//! header size 0, owner = shim's GUID). The reader is bounded: the variable
//! is capped at [`MAX_VAR`], entries at [`MAX_ENTRIES`], and every size must
//! tile its list exactly.

use core::mem::{offset_of, size_of};

use crate::bytes::{Full, Reader, Writer};
use crate::guid::Guid;

/// `EFI_SIGNATURE_LIST` header (UEFI 2.10 §32.4.1). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct SignatureListHeader {
    signature_type: [u8; 16],
    signature_list_size: u32,
    signature_header_size: u32,
    signature_size: u32,
}
const _: () = assert!(offset_of!(SignatureListHeader, signature_size) == 24);
const _: () = assert!(size_of::<SignatureListHeader>() == 28);

/// `EFI_SIGNATURE_DATA` (UEFI 2.10 §32.4.1): the fixed part before the data.
/// Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct SignatureDataHeader {
    signature_owner: [u8; 16],
}
/// Bytes of `SignatureOwner` at the start of every signature.
const OWNER_LEN: usize = size_of::<SignatureDataHeader>();
const _: () = assert!(OWNER_LEN == 16);

/// Largest signature database the reader accepts. Real `db`/`dbx` values
/// are tens of KiB.
pub const MAX_VAR: usize = 256 * 1024;
/// Most signatures visited across all lists.
pub const MAX_ENTRIES: usize = 4096;
/// `sizeof(EFI_SIGNATURE_LIST)`.
pub const LIST_HEADER_LEN: usize = size_of::<SignatureListHeader>();

/// `605dab50-e046-4300-abb6-3dd810dd8b23`: shim's vendor GUID (`MokNew`,
/// `MokAuth`, `MokListRT`) and the owner mokutil writes.
pub const SHIM_LOCK: Guid = Guid([
    0x50, 0xab, 0x5d, 0x60, 0x46, 0xe0, 0x00, 0x43, 0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23,
]);
/// `d719b2cb-3d3a-4596-a3bc-dad00e67656f`: `db`, `dbx`.
pub const IMAGE_SECURITY_DATABASE: Guid = Guid([
    0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f,
]);
/// `a5c059a1-94e4-4aa7-87b5-ab155c2bf072`: `EFI_CERT_X509_GUID`.
pub const CERT_X509: Guid = Guid([
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
]);
/// `c1c41626-504c-4092-aca9-41f936934328`: `EFI_CERT_SHA256_GUID`.
pub const CERT_SHA256: Guid = Guid([
    0x26, 0x16, 0xc4, 0xc1, 0x4c, 0x50, 0x92, 0x40, 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28,
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigError {
    TooLarge,
    Truncated,
    /// `SignatureListSize` smaller than its own header, or past the end.
    BadListSize,
    /// `SignatureSize` < 16, or the entries do not tile the list exactly.
    BadSignatureSize,
    TooManyEntries,
}

/// One signature: its list's type, its owner and its data (a DER
/// certificate for [`CERT_X509`], a 32-byte digest for [`CERT_SHA256`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signature<'a> {
    pub kind: Guid,
    pub owner: Guid,
    pub data: &'a [u8],
}

/// Visit every signature in a database value, in order. Returns how many
/// there were. An empty value is an empty database.
pub fn for_each<'a>(
    var: &'a [u8],
    mut visit: impl FnMut(Signature<'a>),
) -> Result<usize, SigError> {
    if var.len() > MAX_VAR {
        return Err(SigError::TooLarge);
    }
    let mut r = Reader::new(var);
    let mut count = 0usize;
    while !r.is_empty() {
        let kind = Guid(*r.array::<16>().map_err(|_| SigError::Truncated)?);
        let list_size = r.u32_le().map_err(|_| SigError::Truncated)? as usize;
        let header_size = r.u32_le().map_err(|_| SigError::Truncated)? as usize;
        let sig_size = r.u32_le().map_err(|_| SigError::Truncated)? as usize;
        let body_len = list_size
            .checked_sub(LIST_HEADER_LEN)
            .ok_or(SigError::BadListSize)?;
        let body = r.take(body_len).map_err(|_| SigError::BadListSize)?;
        let mut b = Reader::new(body);
        b.take(header_size).map_err(|_| SigError::BadListSize)?;
        let entries = b.rest();
        if sig_size < OWNER_LEN || entries.len() % sig_size != 0 {
            return Err(SigError::BadSignatureSize);
        }
        for e in entries.chunks_exact(sig_size) {
            count += 1;
            if count > MAX_ENTRIES {
                return Err(SigError::TooManyEntries);
            }
            let (owner, data) = e.split_at(OWNER_LEN);
            let owner = Guid(owner.try_into().map_err(|_| SigError::Truncated)?);
            visit(Signature { kind, owner, data });
        }
    }
    Ok(count)
}

/// Length of [`write_x509`]'s output for a certificate of `der_len` bytes.
pub const fn x509_list_len(der_len: usize) -> usize {
    LIST_HEADER_LEN + OWNER_LEN + der_len
}

/// One `EFI_SIGNATURE_LIST` holding one X.509 certificate owned by `owner`:
/// the `MokNew` value for a single key.
pub fn write_x509(owner: &Guid, der: &[u8], out: &mut [u8]) -> Result<usize, Full> {
    let list = u32::try_from(x509_list_len(der.len())).map_err(|_| Full)?;
    let sig = u32::try_from(OWNER_LEN + der.len()).map_err(|_| Full)?;
    let mut w = Writer::new(out);
    w.put(&CERT_X509.0)?;
    w.u32_le(list)?;
    w.u32_le(0)?; // SignatureHeaderSize: none for X.509
    w.u32_le(sig)?;
    w.put(&owner.0)?;
    w.put(der)?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    #[test]
    fn guids_match_their_text() {
        for (g, t) in [
            (SHIM_LOCK, "605dab50-e046-4300-abb6-3dd810dd8b23"),
            (
                IMAGE_SECURITY_DATABASE,
                "d719b2cb-3d3a-4596-a3bc-dad00e67656f",
            ),
            (CERT_X509, "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"),
            (CERT_SHA256, "c1c41626-504c-4092-aca9-41f936934328"),
        ] {
            assert_eq!(Guid::parse(t), Ok(g), "{t}");
        }
    }

    #[test]
    fn mokutil_layout() {
        // 28-byte header, then owner and certificate: what mokutil writes.
        let der = [0x30u8, 0x82, 1, 2, 3];
        let mut b = [0u8; 64];
        let n = write_x509(&SHIM_LOCK, &der, &mut b).unwrap();
        assert_eq!(n, x509_list_len(der.len()));
        assert_eq!(&b[..16], &CERT_X509.0);
        assert_eq!(u32::from_le_bytes(b[16..20].try_into().unwrap()), 49);
        assert_eq!(u32::from_le_bytes(b[20..24].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(b[24..28].try_into().unwrap()), 21);
        assert_eq!(&b[28..44], &SHIM_LOCK.0);
        assert_eq!(&b[44..n], &der);
        let mut seen = Vec::new();
        assert_eq!(for_each(&b[..n], |s| seen.push(s)), Ok(1));
        assert_eq!(seen[0].data, &der);
        assert_eq!(seen[0].kind, CERT_X509);
    }

    #[test]
    fn several_lists_and_refusals() {
        let mut v = Vec::new();
        let mut b = [0u8; 64];
        let n = write_x509(&SHIM_LOCK, b"abc", &mut b).unwrap();
        v.extend_from_slice(&b[..n]);
        // a two-digest SHA-256 list
        v.extend_from_slice(&CERT_SHA256.0);
        v.extend_from_slice(&(28u32 + 2 * 48).to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        v.extend_from_slice(&48u32.to_le_bytes());
        v.extend_from_slice(&[1; 96]);
        assert_eq!(for_each(&v, |_| {}), Ok(3));
        assert_eq!(for_each(&[], |_| {}), Ok(0));
        let mut t = v.clone();
        t.pop();
        assert_eq!(for_each(&t, |_| {}), Err(SigError::BadListSize));
        let mut t = v.clone();
        t[n + 24] = 47; // SignatureSize no longer tiles
        assert_eq!(for_each(&t, |_| {}), Err(SigError::BadSignatureSize));
        let mut t = v.clone();
        t[16] = 3; // list smaller than its header
        t[17] = 0;
        assert_eq!(for_each(&t, |_| {}), Err(SigError::BadListSize));
        assert_eq!(for_each(&v[..20], |_| {}), Err(SigError::Truncated));
    }
}
