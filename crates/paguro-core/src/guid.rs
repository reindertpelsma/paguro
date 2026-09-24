//! GUIDs in the two forms paguro meets them: the canonical 36-character text of
//! `paguro.ini` (INTERFACES.md §3.2) and the 16-byte mixed-endian layout UEFI
//! and GPT store (first three fields little-endian, the rest as written).

use core::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct Guid(pub [u8; 16]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuidError {
    /// Not exactly 36 characters.
    BadLength,
    /// A `-` is missing or misplaced.
    BadSeparator,
    /// A non-hex digit where a hex digit belongs.
    BadDigit,
}

const fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Byte order of the 16 stored bytes relative to the text: the text's byte `i`
/// (in reading order) lands at `ORDER[i]`.
const ORDER: [usize; 16] = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];

impl Guid {
    pub const ZERO: Guid = Guid([0; 16]);

    /// Parse `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`, either case.
    pub fn parse(s: &str) -> Result<Guid, GuidError> {
        let b = s.as_bytes();
        if b.len() != 36 {
            return Err(GuidError::BadLength);
        }
        let mut text = [0u8; 16];
        let mut n = 0usize;
        let mut i = 0usize;
        while let Some(&c) = b.get(i) {
            if matches!(i, 8 | 13 | 18 | 23) {
                if c != b'-' {
                    return Err(GuidError::BadSeparator);
                }
                i += 1;
                continue;
            }
            let hi = hex_val(c).ok_or(GuidError::BadDigit)?;
            let lo = hex_val(*b.get(i + 1).ok_or(GuidError::BadLength)?).ok_or(
                if b.get(i + 1) == Some(&b'-') {
                    GuidError::BadSeparator
                } else {
                    GuidError::BadDigit
                },
            )?;
            *text.get_mut(n).ok_or(GuidError::BadLength)? = hi << 4 | lo;
            n += 1;
            i += 2;
        }
        Ok(Guid::from_text_order(text))
    }

    /// From bytes in reading order (as the text shows them).
    pub fn from_text_order(text: [u8; 16]) -> Guid {
        let mut out = [0u8; 16];
        for (t, &pos) in text.iter().zip(ORDER.iter()) {
            if let Some(o) = out.get_mut(pos) {
                *o = *t;
            }
        }
        Guid(out)
    }

    fn text_order(&self) -> [u8; 16] {
        let mut text = [0u8; 16];
        for (t, &pos) in text.iter_mut().zip(ORDER.iter()) {
            *t = self.0.get(pos).copied().unwrap_or(0);
        }
        text
    }

    /// Canonical lower-case text, written into a fixed buffer.
    pub fn to_text(&self) -> [u8; 36] {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = [b'-'; 36];
        let mut o = 0usize;
        for (i, byte) in self.text_order().iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                o += 1;
            }
            let hi = HEX.get(usize::from(byte >> 4)).copied().unwrap_or(b'0');
            let lo = HEX.get(usize::from(byte & 0xf)).copied().unwrap_or(b'0');
            if let Some(d) = out.get_mut(o..o + 2) {
                d.copy_from_slice(&[hi, lo]);
            }
            o += 2;
        }
        out
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let t = self.to_text();
        f.write_str(core::str::from_utf8(&t).map_err(|_| fmt::Error)?)
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// `c648880d-36be-4eaf-8a1b-6f3a9c2926c9`, INTERFACES.md §1.
pub const PAGURO_VENDOR: Guid = Guid([
    0x0d, 0x88, 0x48, 0xc6, 0xbe, 0x36, 0xaf, 0x4e, 0x8a, 0x1b, 0x6f, 0x3a, 0x9c, 0x29, 0x26, 0xc9,
]);
/// `290e97f6-3835-4ea1-a6f5-847ccbc33a0a`, INTERFACES.md §1.
pub const HANDOFF_TABLE: Guid = Guid([
    0xf6, 0x97, 0x0e, 0x29, 0x35, 0x38, 0xa1, 0x4e, 0xa6, 0xf5, 0x84, 0x7c, 0xcb, 0xc3, 0x3a, 0x0a,
]);
/// `23fc424e-17ab-4b60-bf91-2bd392852091`, INTERFACES.md §1.
pub const PCR12_EVENT_TAG: Guid = Guid([
    0x4e, 0x42, 0xfc, 0x23, 0xab, 0x17, 0x60, 0x4b, 0xbf, 0x91, 0x2b, 0xd3, 0x92, 0x85, 0x20, 0x91,
]);
/// `8be4df61-93ca-11d2-aa0d-00e098032b8c`: `BootNext`, `Boot####`, `SecureBoot`.
pub const EFI_GLOBAL_VARIABLE: Guid = Guid([
    0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11, 0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
]);
/// `ebd0a0a2-b9e5-4433-87c0-68b6b72699c7`: Microsoft basic data (NTFS, BitLocker).
pub const GPT_BASIC_DATA: Guid = Guid([
    0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44, 0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7,
]);
/// `c12a7328-f81f-11d2-ba4b-00a0c93ec93b`: EFI System Partition.
pub const GPT_ESP: Guid = Guid([
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
]);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_match_their_text() {
        let cases = [
            (PAGURO_VENDOR, "c648880d-36be-4eaf-8a1b-6f3a9c2926c9"),
            (HANDOFF_TABLE, "290e97f6-3835-4ea1-a6f5-847ccbc33a0a"),
            (PCR12_EVENT_TAG, "23fc424e-17ab-4b60-bf91-2bd392852091"),
            (EFI_GLOBAL_VARIABLE, "8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            (GPT_BASIC_DATA, "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"),
            (GPT_ESP, "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"),
        ];
        for (g, s) in cases {
            assert_eq!(Guid::parse(s), Ok(g), "{s}");
            assert_eq!(&g.to_text(), s.as_bytes());
        }
    }

    #[test]
    fn accepts_upper_case() {
        assert_eq!(
            Guid::parse("C648880D-36BE-4EAF-8A1B-6F3A9C2926C9"),
            Ok(PAGURO_VENDOR)
        );
    }

    #[test]
    fn every_error_variant() {
        assert_eq!(Guid::parse(""), Err(GuidError::BadLength));
        assert_eq!(
            Guid::parse("c648880d-36be-4eaf-8a1b-6f3a9c2926c9x"),
            Err(GuidError::BadLength)
        );
        assert_eq!(
            Guid::parse("c648880d_36be-4eaf-8a1b-6f3a9c2926c9"),
            Err(GuidError::BadSeparator)
        );
        assert_eq!(
            Guid::parse("c648880-d36be-4eaf-8a1b-6f3a9c2926c9"),
            Err(GuidError::BadSeparator)
        );
        assert_eq!(
            Guid::parse("g648880d-36be-4eaf-8a1b-6f3a9c2926c9"),
            Err(GuidError::BadDigit)
        );
        assert_eq!(
            Guid::parse("c648880d-36be-4eaf-8a1b-6f3a9c2926cé"),
            Err(GuidError::BadLength),
            "multi-byte UTF-8 changes the byte length"
        );
        assert_eq!(
            Guid::parse("c648880d-36be-4eaf-8a1b-6f3a9c2926cz"),
            Err(GuidError::BadDigit)
        );
    }
}
