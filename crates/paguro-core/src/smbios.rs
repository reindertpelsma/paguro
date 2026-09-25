//! SMBIOS as Windows returns it from `GetSystemFirmwareTable('RSMB', 0)`:
//! the six DMI strings the host-hardware export carries (INTERFACES.md
//! §11.5), and nothing else.
//!
//! ```text
//! RawSMBIOSData  Used20CallingMethod u8 | Major u8 | Minor u8 | DmiRevision u8
//!                | Length u32 | table[Length]
//! structure      type u8 | length u8 | handle u16 | formatted[length - 4]
//!                | strings: NUL-terminated, the set ends with an extra NUL
//! ```
//!
//! Hostile-input rules as everywhere: the blob is capped at [`MAX_BLOB`],
//! `Length` must fit the blob exactly (trailing bytes are an error), at most
//! [`MAX_STRUCTURES`] are walked, every string index is checked against its
//! own structure's string set. Serial numbers and UUIDs are never read: the
//! export identifies a *model* of machine, not a machine.

use core::mem::{offset_of, size_of};

use crate::bytes::Reader;

/// `RawSMBIOSData` header (Win32 `GetSystemFirmwareTable`, "RSMB"). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct RawSmbiosHeader {
    used20_calling_method: u8,
    smbios_major_version: u8,
    smbios_minor_version: u8,
    dmi_revision: u8,
    length: u32,
}
const _: () = assert!(size_of::<RawSmbiosHeader>() == 8);

/// Structure header (DMTF DSP0134 3.x §6.1.2). Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct StructureHeader {
    kind: u8,
    length: u8,
    handle: u16,
}
const HEADER_LEN: usize = size_of::<StructureHeader>();
const _: () = assert!(HEADER_LEN == 4);

/// Leading fields of the BIOS Information structure, type 0 (DSP0134 §7.1).
#[allow(dead_code)]
#[repr(C, packed)]
struct BiosInformation {
    header: StructureHeader,
    vendor: u8,
    bios_version: u8,
}
const _: () = assert!(offset_of!(BiosInformation, vendor) == 0x04);
const _: () = assert!(offset_of!(BiosInformation, bios_version) == 0x05);

/// Leading fields of the System Information structure, type 1 (DSP0134 §7.2).
#[allow(dead_code)]
#[repr(C, packed)]
struct SystemInformation {
    header: StructureHeader,
    manufacturer: u8,
    product_name: u8,
}
const _: () = assert!(offset_of!(SystemInformation, manufacturer) == 0x04);
const _: () = assert!(offset_of!(SystemInformation, product_name) == 0x05);

/// Leading fields of the Baseboard Information structure, type 2 (DSP0134 §7.3).
#[allow(dead_code)]
#[repr(C, packed)]
struct BaseboardInformation {
    header: StructureHeader,
    manufacturer: u8,
    product: u8,
}
const _: () = assert!(offset_of!(BaseboardInformation, manufacturer) == 0x04);
const _: () = assert!(offset_of!(BaseboardInformation, product) == 0x05);

/// Structure types (DSP0134 §7).
const TYPE_BIOS_INFORMATION: u8 = 0;
const TYPE_SYSTEM_INFORMATION: u8 = 1;
const TYPE_BASEBOARD_INFORMATION: u8 = 2;
const TYPE_END_OF_TABLE: u8 = 127;

/// The double NUL that ends a structure's string set (DSP0134 §6.1.3).
const STRING_SET_END: [u8; 2] = [0, 0];

pub const MAX_BLOB: usize = 1024 * 1024;
pub const MAX_STRUCTURES: usize = 4096;
/// Longest string kept; longer ones are refused (SMBIOS strings are short).
pub const MAX_STRING: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmbiosError {
    TooLarge,
    Truncated,
    /// `Length` disagrees with the blob.
    BadLength,
    /// A structure's length is below the 4-byte header.
    BadStructure,
    /// A string set runs past the table or a string exceeds [`MAX_STRING`].
    BadStrings,
    TooManyStructures,
}

/// The `/sys/class/dmi/id` fields of §11.5, borrowed from the blob, trailing
/// spaces removed. `None`: the structure or string is absent (index 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Dmi<'a> {
    pub version: (u8, u8),
    pub bios_vendor: Option<&'a [u8]>,
    pub bios_version: Option<&'a [u8]>,
    pub sys_vendor: Option<&'a [u8]>,
    pub product_name: Option<&'a [u8]>,
    pub board_vendor: Option<&'a [u8]>,
    pub board_name: Option<&'a [u8]>,
}

struct Structure<'a> {
    kind: u8,
    formatted: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Structure<'a> {
    /// The string whose 1-based index is at `offset` in the structure
    /// (offset counted from the start of the header, as SMBIOS tables are).
    fn string(&self, offset: usize) -> Option<&'a [u8]> {
        let idx = *self.formatted.get(offset.checked_sub(HEADER_LEN)?)?;
        if idx == 0 {
            return None;
        }
        let s = self.strings.split(|&b| b == 0).nth(usize::from(idx) - 1)?;
        let end = s.iter().rposition(|&b| b != b' ').map_or(0, |i| i + 1);
        let s = s.get(..end)?;
        (!s.is_empty()).then_some(s)
    }
}

/// Split one structure off `r`.
fn next<'a>(r: &mut Reader<'a>) -> Result<Structure<'a>, SmbiosError> {
    let kind = r.u8().map_err(|_| SmbiosError::Truncated)?;
    let len = usize::from(r.u8().map_err(|_| SmbiosError::Truncated)?);
    r.u16_le().map_err(|_| SmbiosError::Truncated)?;
    let formatted = r
        .take(
            len.checked_sub(HEADER_LEN)
                .ok_or(SmbiosError::BadStructure)?,
        )
        .map_err(|_| SmbiosError::Truncated)?;
    // The string set ends at the first double NUL; an empty set is "\0\0".
    let rest = r.rest();
    let mut end = None;
    let mut i = 0usize;
    while let Some(pair) = rest.get(i..i + STRING_SET_END.len()) {
        if pair == STRING_SET_END {
            end = Some(i);
            break;
        }
        i += 1;
    }
    let end = end.ok_or(SmbiosError::BadStrings)?;
    let strings = r.take(end).map_err(|_| SmbiosError::BadStrings)?;
    r.take(STRING_SET_END.len())
        .map_err(|_| SmbiosError::BadStrings)?;
    if strings.split(|&b| b == 0).any(|s| s.len() > MAX_STRING) {
        return Err(SmbiosError::BadStrings);
    }
    Ok(Structure {
        kind,
        formatted,
        strings,
    })
}

/// Parse a `RawSMBIOSData` blob. The first structure of each of types 0, 1
/// and 2 supplies the fields; later duplicates are ignored.
pub fn parse(blob: &[u8]) -> Result<Dmi<'_>, SmbiosError> {
    if blob.len() > MAX_BLOB {
        return Err(SmbiosError::TooLarge);
    }
    let mut r = Reader::new(blob);
    r.u8().map_err(|_| SmbiosError::Truncated)?;
    let major = r.u8().map_err(|_| SmbiosError::Truncated)?;
    let minor = r.u8().map_err(|_| SmbiosError::Truncated)?;
    r.u8().map_err(|_| SmbiosError::Truncated)?;
    let len = r.u32_le().map_err(|_| SmbiosError::Truncated)? as usize;
    if len != r.rest().len() {
        return Err(SmbiosError::BadLength);
    }
    let mut dmi = Dmi {
        version: (major, minor),
        ..Dmi::default()
    };
    let (mut seen0, mut seen1, mut seen2) = (false, false, false);
    let mut n = 0usize;
    while !r.is_empty() {
        n += 1;
        if n > MAX_STRUCTURES {
            return Err(SmbiosError::TooManyStructures);
        }
        let s = next(&mut r)?;
        match s.kind {
            TYPE_BIOS_INFORMATION if !seen0 => {
                seen0 = true;
                dmi.bios_vendor = s.string(offset_of!(BiosInformation, vendor));
                dmi.bios_version = s.string(offset_of!(BiosInformation, bios_version));
            }
            TYPE_SYSTEM_INFORMATION if !seen1 => {
                seen1 = true;
                dmi.sys_vendor = s.string(offset_of!(SystemInformation, manufacturer));
                dmi.product_name = s.string(offset_of!(SystemInformation, product_name));
            }
            TYPE_BASEBOARD_INFORMATION if !seen2 => {
                seen2 = true;
                dmi.board_vendor = s.string(offset_of!(BaseboardInformation, manufacturer));
                dmi.board_name = s.string(offset_of!(BaseboardInformation, product));
            }
            // End-of-table; anything after it is padding firmware leaves.
            TYPE_END_OF_TABLE => break,
            _ => {}
        }
    }
    Ok(dmi)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn structure(kind: u8, formatted: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut v = std::vec![kind, 4 + formatted.len() as u8, 0, 0];
        v.extend_from_slice(formatted);
        if strings.is_empty() {
            v.push(0);
        }
        for s in strings {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v.push(0);
        v
    }

    fn blob(structs: &[Vec<u8>]) -> Vec<u8> {
        let table: Vec<u8> = structs.concat();
        let mut v = std::vec![0, 3, 4, 0];
        v.extend_from_slice(&(table.len() as u32).to_le_bytes());
        v.extend_from_slice(&table);
        v
    }

    fn sample() -> Vec<u8> {
        blob(&[
            structure(0, &[1, 2, 0, 0], &["LENOVO", "N3HET80W (1.52 )"]),
            structure(1, &[1, 2, 0, 3], &["LENOVO", "20QDCTO1WW", "SERIAL-SECRET"]),
            structure(2, &[1, 2], &["LENOVO", "20QDCTO1WW"]),
            structure(4, &[], &[]),
            structure(127, &[], &[]),
        ])
    }

    #[test]
    fn reads_the_six_fields() {
        let b = sample();
        let d = parse(&b).unwrap();
        assert_eq!(d.version, (3, 4));
        assert_eq!(d.bios_vendor, Some(&b"LENOVO"[..]));
        assert_eq!(d.bios_version, Some(&b"N3HET80W (1.52 )"[..]));
        assert_eq!(d.sys_vendor, Some(&b"LENOVO"[..]));
        assert_eq!(d.product_name, Some(&b"20QDCTO1WW"[..]));
        assert_eq!(d.board_name, Some(&b"20QDCTO1WW"[..]));
    }

    #[test]
    fn index_zero_trailing_spaces_and_bad_index() {
        let b = blob(&[structure(1, &[0, 3], &["Vendor   ", "x"])]);
        let d = parse(&b).unwrap();
        assert_eq!(d.sys_vendor, None, "index 0 means absent");
        assert_eq!(d.product_name, None, "index past the set means absent");
        let b = blob(&[structure(0, &[1, 1], &["Acme   "])]);
        assert_eq!(parse(&b).unwrap().bios_vendor, Some(&b"Acme"[..]));
    }

    #[test]
    fn refusals() {
        let b = sample();
        assert_eq!(parse(&b[..b.len() - 1]), Err(SmbiosError::BadLength));
        let mut t = b.clone();
        t.push(0);
        assert_eq!(parse(&t), Err(SmbiosError::BadLength));
        let mut t = b.clone();
        t[9] = 2; // type 0 length below its header
        assert_eq!(parse(&t), Err(SmbiosError::BadStructure));
        // No double NUL: the string set runs off the table.
        let t = blob(&[std::vec![1, 4, 0, 0, b'a']]);
        assert_eq!(parse(&t), Err(SmbiosError::BadStrings));
        assert_eq!(parse(&[0, 3]), Err(SmbiosError::Truncated));
    }
}
