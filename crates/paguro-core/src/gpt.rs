//! GUID Partition Table: header and entry array (UEFI 2.10 §5.3), bounded.
//!
//! The loader walks GPTs to find the NTFS volume by its partition GUID (normal
//! path) or to enumerate candidate volumes (recovery, DESIGN.md §4.1). Disks are
//! attacker-writable, so every field is checked before it steers a read:
//!
//! - the header is parsed from one logical block and must carry a valid CRC32;
//! - the entry array is capped at [`MAX_ENTRY_ARRAY`] bytes *before* anything is
//!   read, and its CRC32 must match before any entry is interpreted;
//! - every entry must lie inside the usable range and have `first ≤ last`.
//!
//! Only the primary header is used. A damaged primary is refused rather than
//! repaired from the backup: the loader never writes, and guessing between two
//! disagreeing copies is how a parser gets steered.

use crate::bytes::Reader;
use crate::guid::Guid;

pub const SIGNATURE: &[u8; 8] = b"EFI PART";
pub const REVISION_1_0: u32 = 0x0001_0000;
pub const HEADER_MIN: u32 = 92;
/// Largest entry array the loader reads (128 × 128 bytes, the universal
/// default). Bigger arrays are refused, not truncated.
pub const MAX_ENTRY_ARRAY: usize = 16 * 1024;
pub const MIN_ENTRY_SIZE: u32 = 128;
pub const MAX_ENTRY_SIZE: u32 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GptError {
    /// Block size is not 512 or 4096, or the buffer is not one block.
    BadBlockSize,
    BadSignature,
    BadRevision,
    BadHeaderSize,
    HeaderCrc,
    /// `MyLBA` is not 1.
    NotPrimary,
    /// Usable range is empty, overlaps the header, or exceeds the disk.
    BadUsableRange,
    /// The entry array overlaps the header or the usable range, or runs off the disk.
    BadEntryLocation,
    /// Entry size not a multiple of 8 in `128..=1024`.
    BadEntrySize,
    /// `count × size` exceeds [`MAX_ENTRY_ARRAY`] (or is zero).
    EntryArrayTooLarge,
    EntryArrayCrc,
    /// The buffer handed to [`Header::entries`] is not exactly the array.
    EntryArrayLength,
    /// `first_lba > last_lba`, or outside the usable range.
    BadEntryRange,
    /// Index past `count`.
    NoSuchEntry,
}

/// IEEE 802.3 CRC-32 (reflected, polynomial 0xEDB88320), as GPT uses.
pub fn crc32(data: &[u8]) -> u32 {
    crc32_update(0, data)
}

/// Continue a CRC-32 over further data (`crc32(a ++ b) == crc32_update(crc32(a), b)`).
pub fn crc32_update(crc: u32, data: &[u8]) -> u32 {
    // Evaluated at compile time: an out-of-range index would fail the build.
    #[allow(clippy::indexing_slicing)]
    const TABLE: [u32; 256] = {
        let mut t = [0u32; 256];
        let mut i = 0;
        while i < 256 {
            let mut c = i as u32;
            let mut k = 0;
            while k < 8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
                k += 1;
            }
            t[i] = c;
            i += 1;
        }
        t
    };
    let mut c = !crc;
    for &b in data {
        let idx = usize::from((c as u8) ^ b);
        c = TABLE.get(idx).copied().unwrap_or(0) ^ (c >> 8);
    }
    !c
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub block_size: u32,
    pub disk_guid: Guid,
    pub first_usable: u64,
    pub last_usable: u64,
    pub alternate_lba: u64,
    pub entries_lba: u64,
    pub entry_count: u32,
    pub entry_size: u32,
    pub entries_crc: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub first_lba: u64,
    pub last_lba: u64,
    pub attributes: u64,
    /// UTF-16LE name, 36 code units, NUL padded; display only.
    pub name: [u16; 36],
}

impl Entry {
    pub fn is_unused(&self) -> bool {
        self.type_guid == Guid::ZERO
    }
    pub const fn sectors(&self) -> u64 {
        // first ≤ last is checked at parse time for used entries.
        self.last_lba
            .saturating_sub(self.first_lba)
            .saturating_add(1)
    }
}

impl Header {
    /// Parse the primary header from LBA 1 (`block` is that one logical block).
    /// `disk_blocks` is the medium's size in blocks, for range checks.
    pub fn parse(block: &[u8], disk_blocks: u64) -> Result<Header, GptError> {
        let block_size = u32::try_from(block.len()).map_err(|_| GptError::BadBlockSize)?;
        if block_size != 512 && block_size != 4096 {
            return Err(GptError::BadBlockSize);
        }
        let short = |_| GptError::BadHeaderSize;
        let mut r = Reader::new(block);
        if r.array::<8>().map_err(short)? != SIGNATURE {
            return Err(GptError::BadSignature);
        }
        if r.u32_le().map_err(short)? != REVISION_1_0 {
            return Err(GptError::BadRevision);
        }
        let header_size = r.u32_le().map_err(short)?;
        if header_size < HEADER_MIN || header_size > block_size {
            return Err(GptError::BadHeaderSize);
        }
        let stored_crc = r.u32_le().map_err(short)?;
        let _reserved = r.u32_le().map_err(short)?;
        let hs = header_size as usize;
        let hdr = block.get(..hs).ok_or(GptError::BadHeaderSize)?;
        // CRC over the header with its CRC field (bytes 16..20) zeroed.
        let mut crc = crc32_update(0, hdr.get(..16).unwrap_or(&[]));
        crc = crc32_update(crc, &[0; 4]);
        crc = crc32_update(crc, hdr.get(20..).unwrap_or(&[]));
        if crc != stored_crc {
            return Err(GptError::HeaderCrc);
        }
        let my_lba = r.u64_le().map_err(short)?;
        let alternate_lba = r.u64_le().map_err(short)?;
        let first_usable = r.u64_le().map_err(short)?;
        let last_usable = r.u64_le().map_err(short)?;
        let disk_guid = Guid(*r.array::<16>().map_err(short)?);
        let entries_lba = r.u64_le().map_err(short)?;
        let entry_count = r.u32_le().map_err(short)?;
        let entry_size = r.u32_le().map_err(short)?;
        let entries_crc = r.u32_le().map_err(short)?;
        if my_lba != 1 {
            return Err(GptError::NotPrimary);
        }
        if first_usable < 2 || first_usable > last_usable || last_usable >= disk_blocks {
            return Err(GptError::BadUsableRange);
        }
        if !(MIN_ENTRY_SIZE..=MAX_ENTRY_SIZE).contains(&entry_size) || entry_size % 8 != 0 {
            return Err(GptError::BadEntrySize);
        }
        let array_len = u64::from(entry_count) * u64::from(entry_size);
        if array_len == 0 || array_len > MAX_ENTRY_ARRAY as u64 {
            return Err(GptError::EntryArrayTooLarge);
        }
        let array_blocks = array_len.div_ceil(u64::from(block_size));
        let array_end = entries_lba
            .checked_add(array_blocks)
            .ok_or(GptError::BadEntryLocation)?;
        // The array must sit between the header and the usable range (primary),
        // entirely on the disk.
        if entries_lba < 2 || array_end > first_usable || array_end > disk_blocks {
            return Err(GptError::BadEntryLocation);
        }
        Ok(Header {
            block_size,
            disk_guid,
            first_usable,
            last_usable,
            alternate_lba,
            entries_lba,
            entry_count,
            entry_size,
            entries_crc,
        })
    }

    /// Bytes of the entry array (always ≤ [`MAX_ENTRY_ARRAY`]).
    pub const fn entries_len(&self) -> usize {
        (self.entry_count as usize) * (self.entry_size as usize)
    }

    /// Blocks to read starting at [`Header::entries_lba`].
    pub const fn entries_blocks(&self) -> u64 {
        (self.entries_len() as u64).div_ceil(self.block_size as u64)
    }

    /// Verify the entry array's CRC. `array` must be exactly
    /// [`Header::entries_len`] bytes; on success the returned view is the only
    /// way to reach entries, so none is read unverified.
    pub fn entries<'a>(&self, array: &'a [u8]) -> Result<Entries<'a>, GptError> {
        if array.len() != self.entries_len() {
            return Err(GptError::EntryArrayLength);
        }
        if crc32(array) != self.entries_crc {
            return Err(GptError::EntryArrayCrc);
        }
        Ok(Entries {
            header: *self,
            array,
        })
    }
}

/// A CRC-verified entry array.
#[derive(Clone, Copy, Debug)]
pub struct Entries<'a> {
    header: Header,
    array: &'a [u8],
}

impl Entries<'_> {
    pub const fn count(&self) -> u32 {
        self.header.entry_count
    }

    /// Entry `i`, validated. Unused entries (zero type GUID) are returned as-is
    /// without range checks; callers skip them with [`Entry::is_unused`].
    pub fn get(&self, i: u32) -> Result<Entry, GptError> {
        if i >= self.header.entry_count {
            return Err(GptError::NoSuchEntry);
        }
        let size = self.header.entry_size as usize;
        let at = (i as usize) * size;
        let raw = self
            .array
            .get(at..at + size)
            .ok_or(GptError::EntryArrayLength)?;
        let mut r = Reader::new(raw);
        let short = |_| GptError::EntryArrayLength;
        let type_guid = Guid(*r.array::<16>().map_err(short)?);
        let unique_guid = Guid(*r.array::<16>().map_err(short)?);
        let first_lba = r.u64_le().map_err(short)?;
        let last_lba = r.u64_le().map_err(short)?;
        let attributes = r.u64_le().map_err(short)?;
        let mut name = [0u16; 36];
        for n in name.iter_mut() {
            *n = r.u16_le().map_err(short)?;
        }
        let e = Entry {
            type_guid,
            unique_guid,
            first_lba,
            last_lba,
            attributes,
            name,
        };
        if !e.is_unused()
            && (first_lba > last_lba
                || first_lba < self.header.first_usable
                || last_lba > self.header.last_usable)
        {
            return Err(GptError::BadEntryRange);
        }
        Ok(e)
    }

    /// First used entry whose unique GUID is `id`.
    pub fn find(&self, id: &Guid) -> Result<Option<Entry>, GptError> {
        for i in 0..self.count() {
            let e = self.get(i)?;
            if !e.is_unused() && e.unique_guid == *id {
                return Ok(Some(e));
            }
        }
        Ok(None)
    }
}

/// Test and tooling support: serialise a GPT (header block + entry array) for
/// a disk of `disk_blocks` blocks. Used by the mock platform, the fuzz seeds and
/// the QEMU image builder so that all three agree with the parser.
pub mod build {
    use super::*;
    use crate::bytes::{Full, Writer};

    /// Write the header block (LBA 1) and entry array (LBA 2..) for `entries`
    /// into `header_out` (one block) and `array_out` (`count × 128` bytes).
    pub fn write(
        disk_guid: &Guid,
        disk_blocks: u64,
        block_size: u32,
        entries: &[Entry],
        count: u32,
        header_out: &mut [u8],
        array_out: &mut [u8],
    ) -> Result<(), Full> {
        let esz: u32 = 128;
        let array_len = (count as usize) * (esz as usize);
        let array_blocks = (array_len as u64).div_ceil(u64::from(block_size));
        {
            let arr = array_out.get_mut(..array_len).ok_or(Full)?;
            arr.fill(0);
            let mut w = Writer::new(arr);
            for i in 0..count as usize {
                let e = entries.get(i);
                let blank = Entry {
                    type_guid: Guid::ZERO,
                    unique_guid: Guid::ZERO,
                    first_lba: 0,
                    last_lba: 0,
                    attributes: 0,
                    name: [0; 36],
                };
                let e = e.unwrap_or(&blank);
                w.put(&e.type_guid.0)?;
                w.put(&e.unique_guid.0)?;
                w.u64_le(e.first_lba)?;
                w.u64_le(e.last_lba)?;
                w.u64_le(e.attributes)?;
                for n in e.name {
                    w.u16_le(n)?;
                }
            }
        }
        let array_crc = crc32(array_out.get(..array_len).ok_or(Full)?);
        let hdr = header_out.get_mut(..block_size as usize).ok_or(Full)?;
        hdr.fill(0);
        let mut w = Writer::new(hdr);
        w.put(SIGNATURE)?;
        w.u32_le(REVISION_1_0)?;
        w.u32_le(HEADER_MIN)?;
        w.u32_le(0)?; // CRC, patched below
        w.u32_le(0)?;
        w.u64_le(1)?;
        w.u64_le(disk_blocks.saturating_sub(1))?;
        w.u64_le(2 + array_blocks)?;
        w.u64_le(disk_blocks.saturating_sub(2 + array_blocks))?;
        w.put(&disk_guid.0)?;
        w.u64_le(2)?;
        w.u32_le(count)?;
        w.u32_le(esz)?;
        w.u32_le(array_crc)?;
        let crc = crc32(w.written());
        w.patch(16, &crc.to_le_bytes())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::build::write;
    use super::*;
    use crate::guid::GPT_BASIC_DATA;

    const DISK: u64 = 1 << 16;

    fn entry(first: u64, last: u64, id: u8) -> Entry {
        Entry {
            type_guid: GPT_BASIC_DATA,
            unique_guid: Guid([id; 16]),
            first_lba: first,
            last_lba: last,
            attributes: 0,
            name: [0; 36],
        }
    }

    fn disk(entries: &[Entry]) -> ([u8; 512], [u8; MAX_ENTRY_ARRAY]) {
        let mut h = [0u8; 512];
        let mut a = [0u8; MAX_ENTRY_ARRAY];
        write(&Guid([7; 16]), DISK, 512, entries, 128, &mut h, &mut a).unwrap();
        (h, a)
    }

    fn reseal(h: &mut [u8; 512]) {
        h[16..20].fill(0);
        let c = crc32(&h[..92]);
        h[16..20].copy_from_slice(&c.to_le_bytes());
    }

    #[test]
    fn crc32_known_answer() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32_update(crc32(b"1234"), b"56789"), 0xCBF4_3926);
    }

    #[test]
    fn roundtrip_and_find() {
        let (h, a) = disk(&[entry(34, 2047, 1), entry(2048, 4095, 2)]);
        let hdr = Header::parse(&h, DISK).unwrap();
        assert_eq!(hdr.entries_len(), 128 * 128);
        assert_eq!(hdr.entries_blocks(), 32);
        let es = hdr.entries(&a).unwrap();
        assert_eq!(es.count(), 128);
        let e = es.find(&Guid([2; 16])).unwrap().unwrap();
        assert_eq!((e.first_lba, e.sectors()), (2048, 2048));
        assert!(es.find(&Guid([3; 16])).unwrap().is_none());
        assert!(es.get(5).unwrap().is_unused());
        assert_eq!(es.get(128), Err(GptError::NoSuchEntry));
    }

    #[test]
    fn header_errors() {
        let (h, _) = disk(&[]);
        assert_eq!(Header::parse(&h[..100], DISK), Err(GptError::BadBlockSize));
        let mut b = h;
        b[0] = b'X';
        assert_eq!(Header::parse(&b, DISK), Err(GptError::BadSignature));
        let mut b = h;
        b[10] = 2;
        assert_eq!(Header::parse(&b, DISK), Err(GptError::BadRevision));
        let mut b = h;
        b[12..16].copy_from_slice(&91u32.to_le_bytes());
        assert_eq!(Header::parse(&b, DISK), Err(GptError::BadHeaderSize));
        let mut b = h;
        b[12..16].copy_from_slice(&513u32.to_le_bytes());
        assert_eq!(Header::parse(&b, DISK), Err(GptError::BadHeaderSize));
        let mut b = h;
        b[30] ^= 1;
        assert_eq!(Header::parse(&b, DISK), Err(GptError::HeaderCrc));

        let field = |at: usize, v: &[u8]| {
            let mut b = h;
            b[at..at + v.len()].copy_from_slice(v);
            reseal(&mut b);
            Header::parse(&b, DISK)
        };
        assert_eq!(field(24, &2u64.to_le_bytes()), Err(GptError::NotPrimary));
        assert_eq!(
            field(40, &1u64.to_le_bytes()),
            Err(GptError::BadUsableRange)
        );
        assert_eq!(
            field(48, &DISK.to_le_bytes()),
            Err(GptError::BadUsableRange)
        );
        assert_eq!(
            field(40, &(DISK - 1).to_le_bytes()),
            Err(GptError::BadUsableRange)
        );
        assert_eq!(
            field(84, &100u32.to_le_bytes()),
            Err(GptError::BadEntrySize)
        );
        assert_eq!(
            field(84, &2048u32.to_le_bytes()),
            Err(GptError::BadEntrySize)
        );
        assert_eq!(
            field(84, &132u32.to_le_bytes()),
            Err(GptError::BadEntrySize)
        );
        assert_eq!(
            field(80, &0u32.to_le_bytes()),
            Err(GptError::EntryArrayTooLarge)
        );
        assert_eq!(
            field(80, &129u32.to_le_bytes()),
            Err(GptError::EntryArrayTooLarge)
        );
        assert_eq!(
            field(80, &u32::MAX.to_le_bytes()),
            Err(GptError::EntryArrayTooLarge)
        );
        assert_eq!(
            field(72, &1u64.to_le_bytes()),
            Err(GptError::BadEntryLocation)
        );
        assert_eq!(
            field(72, &3u64.to_le_bytes()),
            Err(GptError::BadEntryLocation)
        );
        assert_eq!(
            field(72, &u64::MAX.to_le_bytes()),
            Err(GptError::BadEntryLocation)
        );
        let mut small = h;
        small[40..48].copy_from_slice(&2u64.to_le_bytes());
        small[48..56].copy_from_slice(&3u64.to_le_bytes());
        reseal(&mut small);
        assert_eq!(Header::parse(&small, 4), Err(GptError::BadEntryLocation));
    }

    #[test]
    fn four_k_blocks() {
        let mut h = [0u8; 4096];
        let mut a = [0u8; MAX_ENTRY_ARRAY];
        write(
            &Guid([1; 16]),
            1 << 20,
            4096,
            &[entry(6, 100, 9)],
            128,
            &mut h,
            &mut a,
        )
        .unwrap();
        let hdr = Header::parse(&h, 1 << 20).unwrap();
        assert_eq!(hdr.entries_blocks(), 4);
        assert!(
            hdr.entries(&a)
                .unwrap()
                .find(&Guid([9; 16]))
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn entry_errors() {
        let (h, a) = disk(&[entry(34, 2047, 1)]);
        let hdr = Header::parse(&h, DISK).unwrap();
        assert_eq!(
            hdr.entries(&a[..100]).err(),
            Some(GptError::EntryArrayLength)
        );
        let mut bad = a;
        bad[200] ^= 1;
        assert_eq!(hdr.entries(&bad).err(), Some(GptError::EntryArrayCrc));

        for (first, last) in [(40, 39), (33, 100), (34, DISK)] {
            let (h, a) = disk(&[entry(first, last, 1)]);
            let hdr = Header::parse(&h, DISK).unwrap();
            let es = hdr.entries(&a).unwrap();
            assert_eq!(es.get(0), Err(GptError::BadEntryRange), "{first}..{last}");
            assert_eq!(es.find(&Guid([1; 16])), Err(GptError::BadEntryRange));
        }
    }
}
