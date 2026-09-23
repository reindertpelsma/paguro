//! A bounded walk over BitLocker FVE metadata entries (DESIGN.md §6).
//!
//! This is **the** adversarial pre-key parser: plaintext on disk, rewritable by
//! anyone with physical access, and parsed while the key is still obtainable.
//! Containment rules from the design, enforced here structurally:
//!
//! - never follow an offset outside the metadata block handed in;
//! - a hard schema: every entry's size is checked against what remains, unknown
//!   types are skipped by declared length and never interpreted;
//! - fixed output capacity, no allocation derived from content;
//! - the caller cross-checks all three metadata copies and refuses on
//!   structural disagreement rather than picking one.
//!
//! Layout follows libbde's BitLocker Drive Encryption format specification.
//! Offsets are validated against the libbde/dislocker CI oracle (§11 Q10), not
//! trusted from this comment.

pub const SIGNATURE: &[u8; 8] = b"-FVE-FS-";
/// Minimum entry: size, entry type, value type, version (4 x u16).
pub const ENTRY_HEADER_LEN: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub entry_type: u16,
    pub value_type: u16,
    pub version: u16,
    pub data: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FveError {
    BadSignature,
    EntryTooSmall,
    EntryOverruns,
    TooManyEntries,
}

pub fn check_signature(block: &[u8]) -> Result<(), FveError> {
    if block.get(..8) == Some(&SIGNATURE[..]) {
        Ok(())
    } else {
        Err(FveError::BadSignature)
    }
}

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at + 2)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

/// Walk the entry list in `entries` (the region after the metadata header),
/// writing up to `out.len()` entries. A zero-size entry terminates the list.
pub fn walk<'a>(entries: &'a [u8], out: &mut [Entry<'a>]) -> Result<usize, FveError> {
    let mut pos = 0usize;
    let mut n = 0usize;
    while pos < entries.len() {
        let size = usize::from(u16_at(entries, pos).ok_or(FveError::EntryOverruns)?);
        if size == 0 {
            break;
        }
        if size < ENTRY_HEADER_LEN {
            return Err(FveError::EntryTooSmall);
        }
        let entry = entries
            .get(pos..pos + size)
            .ok_or(FveError::EntryOverruns)?;
        let e = Entry {
            entry_type: u16_at(entry, 2).ok_or(FveError::EntryOverruns)?,
            value_type: u16_at(entry, 4).ok_or(FveError::EntryOverruns)?,
            version: u16_at(entry, 6).ok_or(FveError::EntryOverruns)?,
            data: entry
                .get(ENTRY_HEADER_LEN..)
                .ok_or(FveError::EntryOverruns)?,
        };
        *out.get_mut(n).ok_or(FveError::TooManyEntries)? = e;
        n += 1;
        pos += size;
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: Entry<'static> = Entry {
        entry_type: 0,
        value_type: 0,
        version: 0,
        data: &[],
    };

    #[test]
    fn walks_and_stops_at_zero() {
        let buf = [
            10, 0, 2, 0, 8, 0, 1, 0, 0xaa, 0xbb, // one 10-byte entry
            0, 0, // terminator
        ];
        let mut out = [EMPTY; 4];
        assert_eq!(walk(&buf, &mut out), Ok(1));
        assert_eq!(out[0].entry_type, 2);
        assert_eq!(out[0].data, &[0xaa, 0xbb]);
    }

    #[test]
    fn refuses_overrun_and_undersize() {
        let mut out = [EMPTY; 4];
        assert_eq!(
            walk(&[40, 0, 0, 0, 0, 0, 0, 0], &mut out),
            Err(FveError::EntryOverruns)
        );
        assert_eq!(walk(&[4, 0, 0, 0], &mut out), Err(FveError::EntryTooSmall));
        assert_eq!(check_signature(b"-FVE-FS-rest"), Ok(()));
        assert_eq!(check_signature(b"NTFS    "), Err(FveError::BadSignature));
    }
}
