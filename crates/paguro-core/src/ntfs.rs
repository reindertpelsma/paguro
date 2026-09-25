//! NTFS: one file's extents, derived from the volume itself — the one parse
//! the kernel module performs, once per claim (DESIGN.md §4.3, INTERFACES.md
//! §10.1). Nothing in userspace can supply the map; it can only name a file.
//!
//! This is the **executable specification** for `kernel/dm-paguro/pg_ntfs.c`:
//! same checks, in the same order, with the same error for every input.
//! `paguro-harness` differential-tests the two over real `mkntfs` volumes,
//! mutations of them and fuzz corpora.
//!
//! The volume is attacker-authorable (an untrusted guest may have written it),
//! so every offset is bounds-checked before it is read, every count is capped
//! before it is used, and anything unusual is refused rather than tolerated.
//! No allocation; all buffers are fixed-size and caller-provided.
//!
//! Steps (INTERFACES §10.1): [`parse_boot`] (1), [`open`] maps `$MFT` (2),
//! [`file`] walks one file (3–5), [`extents`] converts to sectors (6),
//! [`volume_flags`] reads `$Volume` (7). Then, for claims: [`normalise`],
//! [`intersects`], [`grows`], [`coalesce`], [`gather`] and [`check_payload`].

use crate::range::Extent;
use crate::runlist::{self, Run, RunlistError};

/// Path lookup, directory listing and file reading for the loader.
pub mod dir;

/// Sector size of every read and every output extent.
pub const SECTOR: u64 = 512;
/// Largest MFT record accepted (4 KiB-sector volumes use 4 KiB records).
pub const MAX_RECORD: usize = 4096;
/// Largest `$ATTRIBUTE_LIST` value accepted.
pub const MAX_ALIST: usize = 65536;
/// At most this many `$DATA` segments may live outside the base record.
pub const MAX_EXTENSIONS: u32 = 64;
/// Largest cluster NTFS allows (Windows 10 1903+).
pub const MAX_CLUSTER: u64 = 2 << 20;
/// Output capacity (INTERFACES `PG_MAX_EXTENTS`).
pub const MAX_EXTENTS: usize = 65536;
/// Records below this are NTFS metadata (0–15) and `$MFT`'s reserved
/// extensions (16–23); never a user file.
pub const FIRST_USER_RECORD: u64 = 24;
/// `$VOLUME_INFORMATION` flag: the volume needs `chkdsk`.
pub const VOLUME_DIRTY: u16 = 0x0001;

const ATTR_LIST: u64 = 0x20;
const ATTR_VOLUME_INFO: u64 = 0x70;
const ATTR_DATA: u64 = 0x80;
const ATTR_END: u64 = 0xffff_ffff;
/// `USA offset` of an NTFS 3.1 FILE record; older layouts are refused.
const USA_OFFSET: usize = 0x30;
const ESP_TYPE: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];

/// The read callback failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoError;

/// A 512-byte-sector reader over the **plaintext** volume (or, for
/// [`check_payload`], over the gathered image).
pub trait Disk {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> core::result::Result<(), IoError>;
}

/// Every refusal. [`NtfsError::code`] is the C core's `PG_E_*` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NtfsError {
    Io,
    BootSignature,
    OemId,
    SectorSize,
    ClusterSize,
    VolumeSize,
    RecordSize,
    MftLcn,
    /// Record number below [`FIRST_USER_RECORD`], above 2³², or sequence 0.
    BadIdentity,
    /// The record lies beyond the mapped part of `$MFT`.
    NotMapped,
    RecordMagic,
    /// Update-sequence array, sizes or attribute offset out of shape.
    RecordLayout,
    FixupMismatch,
    /// The record's self-reference names another record: `$MFT` is misread.
    RecordNumber,
    NotInUse,
    Directory,
    Sequence,
    /// The named record is an extension record, not a file.
    NotBase,
    AttrBounds,
    NoData,
    DuplicateData,
    Resident,
    Compressed,
    Encrypted,
    Sparse,
    /// A `$DATA` segment does not start where the previous one ended.
    Gap,
    /// A segment's `highest_vcn` disagrees with its runlist, or it is empty.
    SegmentVcn,
    OutsideVolume,
    /// Duplicate, flagged or malformed `$ATTRIBUTE_LIST`.
    AttrList,
    AttrListSize,
    TooManyExtensions,
    /// An attribute-list entry names a `$DATA` segment that is not there.
    MissingSegment,
    /// An extension record does not point back at the file's base record.
    ExtensionBase,
    /// `$MFT` itself has an attribute list (hundreds of fragments): refused.
    MftAttrList,
    AllocatedSize,
    /// Valid data length short of the file size: the tail is stale disk.
    NotInitialized,
    /// File size not a whole number of sectors.
    Unaligned,
    TooManyExtents,
    NoVolumeInfo,
    /// File-order extents overlap each other.
    SelfOverlap,
    /// The payload's GPT header or entry array is malformed, or a
    /// partition lies outside the usable range.
    PayloadGpt,
    /// A GPT none of whose partitions could be verified (FAT ESP or ext4).
    PayloadNoKnownPartition,
    /// A partition typed ESP does not start with a FAT boot sector.
    PayloadNotFat,
    /// The primary GPT header's or entry array's CRC32 is wrong.
    PayloadGptCrc,
    /// The backup GPT header (or its entry array) is missing, damaged or
    /// disagrees with the primary.
    PayloadGptBackup,
    /// An ext4 superblock is implausible, or its backup in the block group
    /// it names (1, or `s_backup_bgs[0]`) is missing or disagrees.
    PayloadExt4,
    /// An ISO 9660 primary volume descriptor is malformed, its size is not
    /// the payload's, or its root directory record does not point at itself.
    PayloadIso,
    /// The payload is none of GPT, bare ext4 or ISO 9660.
    PayloadUnknown,
    Runlist(RunlistError),
}

impl NtfsError {
    /// The matching `PG_E_*` code in `pg_ntfs.h` (never 0).
    pub const fn code(self) -> i32 {
        use NtfsError::*;
        match self {
            Io => 1,
            BootSignature => 2,
            OemId => 3,
            SectorSize => 4,
            ClusterSize => 5,
            VolumeSize => 6,
            RecordSize => 7,
            MftLcn => 8,
            BadIdentity => 9,
            NotMapped => 10,
            RecordMagic => 11,
            RecordLayout => 12,
            FixupMismatch => 13,
            RecordNumber => 14,
            NotInUse => 15,
            Directory => 16,
            Sequence => 17,
            NotBase => 18,
            AttrBounds => 19,
            NoData => 20,
            DuplicateData => 21,
            Resident => 22,
            Compressed => 23,
            Encrypted => 24,
            Sparse => 25,
            Gap => 26,
            SegmentVcn => 27,
            OutsideVolume => 28,
            AttrList => 29,
            AttrListSize => 30,
            TooManyExtensions => 31,
            MissingSegment => 32,
            ExtensionBase => 33,
            MftAttrList => 34,
            AllocatedSize => 35,
            NotInitialized => 36,
            Unaligned => 37,
            TooManyExtents => 38,
            NoVolumeInfo => 39,
            SelfOverlap => 40,
            PayloadGpt => 41,
            PayloadNoKnownPartition => 42,
            PayloadNotFat => 43,
            PayloadGptCrc => 44,
            PayloadGptBackup => 45,
            PayloadExt4 => 46,
            PayloadIso => 47,
            PayloadUnknown => 48,
            Runlist(e) => match e {
                RunlistError::Truncated => 50,
                RunlistError::FieldTooWide => 51,
                RunlistError::Sparse => 52,
                RunlistError::ZeroLength => 53,
                RunlistError::NegativeLcn => 54,
                RunlistError::Overflow => 55,
                RunlistError::TooManyRuns => 56,
                RunlistError::Unterminated => 57,
            },
        }
    }
}

type Result<T> = core::result::Result<T, NtfsError>;
use NtfsError as E;

/// Geometry from the boot sector. Sizes in bytes unless named otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Volume {
    /// Whole clusters, in 512-byte sectors: no extent may reach past this.
    pub sectors: u64,
    pub clusters: u64,
    pub cluster_bytes: u64,
    pub record_bytes: u64,
    pub mft_lcn: u64,
}

/// A volume with `$MFT` mapped: record `r` lives at byte `r * record_bytes`
/// of the attribute `runs` describe, and only below `bytes`.
#[derive(Clone, Copy, Debug)]
pub struct Mft<'a> {
    pub vol: Volume,
    pub runs: &'a [Run],
    pub bytes: u64,
}

/// A file's unnamed `$DATA`: `runs` entries of the caller's buffer, in VCN
/// order, covering exactly its allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileMap {
    pub runs: usize,
    pub data_size: u64,
}

// Little-endian getters. Every caller bounds-checks first, so the `0` for an
// out-of-range read is never observed; debug builds (tests, fuzzing) assert it.
fn get(b: &[u8], at: usize, n: usize) -> u64 {
    let v = at
        .checked_add(n)
        .and_then(|end| b.get(at..end))
        .map(|s| s.iter().rev().fold(0u64, |a, &x| a << 8 | u64::from(x)));
    debug_assert!(v.is_some(), "unchecked read at {at}+{n}");
    v.unwrap_or(0)
}
fn g8(b: &[u8], at: usize) -> u64 {
    get(b, at, 1)
}
fn g16(b: &[u8], at: usize) -> u64 {
    get(b, at, 2)
}
fn g32(b: &[u8], at: usize) -> u64 {
    get(b, at, 4)
}
fn g64(b: &[u8], at: usize) -> u64 {
    get(b, at, 8)
}
/// `u64` → `usize` for values already bounded by a record or buffer length.
fn us(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Step 1. Validate the boot sector and derive the geometry.
pub fn parse_boot(b: &[u8; 512]) -> Result<Volume> {
    if g16(b, 510) != 0xaa55 {
        return Err(E::BootSignature);
    }
    if b.get(3..11) != Some(&b"NTFS    "[..]) {
        return Err(E::OemId);
    }
    let bps = g16(b, 0x0b);
    if bps != 512 && bps != 4096 {
        return Err(E::SectorSize);
    }
    // Sectors per cluster: 1..=128, or 2^(256 - raw) for clusters beyond 64 KiB.
    let raw = g8(b, 0x0d);
    let spc = if raw <= 0x80 {
        raw
    } else if 256 - raw <= 20 {
        1 << (256 - raw)
    } else {
        0
    };
    if spc == 0 || !spc.is_power_of_two() || bps * spc > MAX_CLUSTER {
        return Err(E::ClusterSize);
    }
    let cluster_bytes = bps * spc;
    let bytes = g64(b, 0x28).checked_mul(bps).ok_or(E::VolumeSize)?;
    let clusters = bytes / cluster_bytes;
    if clusters == 0 {
        return Err(E::VolumeSize);
    }
    // Record size: clusters per record if positive, else 2^-raw bytes.
    let raw = g8(b, 0x40);
    let record_bytes = if raw < 0x80 {
        raw * cluster_bytes
    } else if (256 - raw) <= 12 {
        1 << (256 - raw)
    } else {
        0
    };
    if !(1024..=MAX_RECORD as u64).contains(&record_bytes) || !record_bytes.is_power_of_two() {
        return Err(E::RecordSize);
    }
    let mft_lcn = g64(b, 0x30);
    if mft_lcn >= clusters || clusters - mft_lcn < record_bytes.div_ceil(cluster_bytes) {
        return Err(E::MftLcn);
    }
    Ok(Volume {
        sectors: clusters * (cluster_bytes / SECTOR),
        clusters,
        cluster_bytes,
        record_bytes,
        mft_lcn,
    })
}

/// The sector holding byte `off` of an attribute mapped by `runs` (already
/// checked to lie inside the volume), or `None` past the last run.
fn sector_of(vol: &Volume, runs: &[Run], off: u64) -> Option<u64> {
    let mut vcn = off / vol.cluster_bytes;
    for r in runs {
        if vcn < r.count {
            let byte = (r.lcn + vcn) * vol.cluster_bytes + off % vol.cluster_bytes;
            return Some(byte / SECTOR);
        }
        vcn -= r.count;
    }
    None
}

/// Read MFT record `recno` through `map` (bytes below `limit`), apply the
/// update-sequence fixups and check the header. Postcondition: the returned
/// record's `bytes_in_use` and attribute offset are in range, so the
/// attribute walk may trust them.
fn read_record<'b, D: Disk>(
    disk: &mut D,
    vol: &Volume,
    map: &[Run],
    limit: u64,
    recno: u64,
    buf: &'b mut [u8; MAX_RECORD],
) -> Result<&'b [u8]> {
    let rb = vol.record_bytes;
    let start = recno.checked_mul(rb).ok_or(E::NotMapped)?;
    if start > limit || limit - start < rb {
        return Err(E::NotMapped);
    }
    let rec = buf.get_mut(..us(rb)).ok_or(E::RecordSize)?;
    let mut off = start;
    for chunk in rec.chunks_exact_mut(512) {
        let s = sector_of(vol, map, off).ok_or(E::NotMapped)?;
        let chunk: &mut [u8; 512] = chunk.try_into().map_err(|_| E::RecordSize)?;
        disk.read(s, chunk).map_err(|_| E::Io)?;
        off += SECTOR;
    }
    if rec.get(0..4) != Some(&b"FILE"[..]) {
        return Err(E::RecordMagic);
    }
    // One update-sequence entry per 512 bytes, plus the USN itself.
    let count = us(g16(rec, 6));
    if us(g16(rec, 4)) != USA_OFFSET || count != rec.len() / 512 + 1 {
        return Err(E::RecordLayout);
    }
    let usn = g16(rec, USA_OFFSET);
    for i in 1..count {
        let at = i * 512 - 2;
        if g16(rec, at) != usn {
            return Err(E::FixupMismatch);
        }
        let fix = us(g16(rec, USA_OFFSET + 2 * i)).to_le_bytes();
        if let (Some(dst), Some(src)) = (rec.get_mut(at..at + 2), fix.get(..2)) {
            dst.copy_from_slice(src);
        }
    }
    let attrs = g16(rec, 0x14);
    let used = g32(rec, 0x18);
    if g32(rec, 0x1c) != rb
        || used > rb
        || used % 8 != 0
        || attrs % 8 != 0
        || attrs < (USA_OFFSET + 2 * count) as u64
        || attrs >= used
    {
        return Err(E::RecordLayout);
    }
    if g32(rec, 0x2c) != recno {
        return Err(E::RecordNumber);
    }
    Ok(rec)
}

/// Validate the attribute header at `pos` of a checked record: `None` at the
/// end marker, else its type and length. Postcondition: the header (0x18
/// bytes, 0x40 if non-resident), its name and any resident value lie inside
/// the attribute, which lies inside `bytes_in_use`.
fn attr_at(rec: &[u8], pos: usize) -> Result<Option<(u64, usize)>> {
    let used = us(g32(rec, 0x18));
    if pos + 4 > used {
        return Err(E::AttrBounds);
    }
    let ty = g32(rec, pos);
    if ty == ATTR_END {
        return Ok(None);
    }
    if pos + 0x18 > used {
        return Err(E::AttrBounds);
    }
    let len = us(g32(rec, pos + 4));
    if len < 0x18 || len % 8 != 0 || len > used - pos {
        return Err(E::AttrBounds);
    }
    let nonres = g8(rec, pos + 8);
    let name_len = us(g8(rec, pos + 9));
    if nonres > 1 || (name_len > 0 && us(g16(rec, pos + 0x0a)) + 2 * name_len > len) {
        return Err(E::AttrBounds);
    }
    if nonres == 1 && len < 0x40 {
        return Err(E::AttrBounds);
    }
    if nonres == 0 && us(g16(rec, pos + 0x14)) + us(g32(rec, pos + 0x10)) > len {
        return Err(E::AttrBounds);
    }
    Ok(Some((ty, len)))
}

/// Progress through a file's `$DATA` segments.
struct Seg {
    n: usize,
    vcn: u64,
    alloc: u64,
    size: u64,
    init: u64,
}

/// Decode one non-resident runlist (the attribute at `pos`) into `out`,
/// checking each run lies inside the volume. Returns the run count.
fn decode_runs(vol: &Volume, rec: &[u8], pos: usize, out: &mut [Run]) -> Result<usize> {
    let len = us(g32(rec, pos + 4));
    let mp = us(g16(rec, pos + 0x20));
    if mp < 0x40 || mp >= len {
        return Err(E::AttrBounds);
    }
    let src = rec.get(pos + mp..pos + len).ok_or(E::AttrBounds)?;
    let k = runlist::decode(src, out).map_err(E::Runlist)?;
    for r in out.get(..k).unwrap_or(&[]) {
        if r.lcn + r.count > vol.clusters {
            return Err(E::OutsideVolume);
        }
    }
    Ok(k)
}

/// Append the `$DATA` segment at `pos` to `out`. Invariant kept: `out[..n]`
/// maps VCNs `0..vcn` with no gap, every run inside the volume.
fn segment(vol: &Volume, rec: &[u8], pos: usize, st: &mut Seg, out: &mut [Run]) -> Result<()> {
    if g8(rec, pos + 8) == 0 {
        return Err(E::Resident);
    }
    // Sparse first: ntfs-3g gives sparse files a compression unit too.
    let flags = g16(rec, pos + 0x0c);
    if flags & 0x8000 != 0 {
        return Err(E::Sparse);
    }
    if flags & 0x4000 != 0 {
        return Err(E::Encrypted);
    }
    if flags & 0x00ff != 0 || g8(rec, pos + 0x22) != 0 {
        return Err(E::Compressed);
    }
    let lowest = g64(rec, pos + 0x10);
    if lowest != st.vcn {
        return Err(E::Gap);
    }
    if lowest == 0 {
        st.alloc = g64(rec, pos + 0x28);
        st.size = g64(rec, pos + 0x30);
        st.init = g64(rec, pos + 0x38);
    }
    let dst = out.get_mut(st.n..).unwrap_or(&mut []);
    let k = decode_runs(vol, rec, pos, dst)?;
    // Each run is inside the volume, so the sum cannot overflow before
    // 2^64 / clusters runs; checked anyway.
    let mut sum = 0u64;
    for r in dst.get(..k).unwrap_or(&[]) {
        sum = sum.checked_add(r.count).ok_or(E::SegmentVcn)?;
    }
    let next = lowest.checked_add(sum).ok_or(E::SegmentVcn)?;
    if k == 0 || g64(rec, pos + 0x18) != next - 1 {
        return Err(E::SegmentVcn);
    }
    st.n += k;
    st.vcn = next;
    Ok(())
}

/// Copy the `$ATTRIBUTE_LIST` at `pos` into `alist`, reading its clusters if
/// non-resident (its runs borrow `scratch`, which the caller reuses after).
fn load_list<D: Disk>(
    disk: &mut D,
    vol: &Volume,
    rec: &[u8],
    pos: usize,
    alist: &mut [u8; MAX_ALIST],
    scratch: &mut [Run],
) -> Result<usize> {
    if g8(rec, pos + 8) == 0 {
        let size = us(g32(rec, pos + 0x10));
        let voff = pos + us(g16(rec, pos + 0x14));
        let src = rec.get(voff..voff + size).ok_or(E::AttrBounds)?;
        alist
            .get_mut(..size)
            .ok_or(E::AttrListSize)?
            .copy_from_slice(src);
        return Ok(size);
    }
    if g16(rec, pos + 0x0c) != 0 || g64(rec, pos + 0x10) != 0 {
        return Err(E::AttrList);
    }
    let size = g64(rec, pos + 0x30);
    if size > MAX_ALIST as u64 {
        return Err(E::AttrListSize);
    }
    if g64(rec, pos + 0x38) != size {
        return Err(E::AttrList);
    }
    let k = decode_runs(vol, rec, pos, scratch)?;
    let runs = scratch.get(..k).unwrap_or(&[]);
    // MAX_ALIST is a whole number of sectors, so whole-sector reads fit.
    let whole = us(size.div_ceil(SECTOR) * SECTOR);
    let mut off = 0u64;
    for chunk in alist
        .get_mut(..whole)
        .unwrap_or(&mut [])
        .chunks_exact_mut(512)
    {
        let s = sector_of(vol, runs, off).ok_or(E::AttrList)?;
        let chunk: &mut [u8; 512] = chunk.try_into().map_err(|_| E::AttrList)?;
        disk.read(s, chunk).map_err(|_| E::Io)?;
        off += SECTOR;
    }
    Ok(us(size))
}

/// Offset of the unnamed `$DATA` attribute with this instance, if present.
fn find_segment(rec: &[u8], instance: u64) -> Result<Option<usize>> {
    let mut pos = us(g16(rec, 0x14));
    while let Some((ty, len)) = attr_at(rec, pos)? {
        if ty == ATTR_DATA && g8(rec, pos + 9) == 0 && g16(rec, pos + 0x0e) == instance {
            return Ok(Some(pos));
        }
        pos += len;
    }
    Ok(None)
}

/// Steps 3–5 for record `recno`, reading records through `map`. `seq == 0`
/// skips the sequence check (only for `$MFT` itself).
#[allow(clippy::too_many_arguments)]
fn walk<D: Disk>(
    disk: &mut D,
    vol: &Volume,
    map: &[Run],
    limit: u64,
    recno: u64,
    seq: u64,
    allow_list: bool,
    alist: &mut [u8; MAX_ALIST],
    out: &mut [Run],
) -> Result<FileMap> {
    let mut buf = [0u8; MAX_RECORD];
    let rec = read_record(disk, vol, map, limit, recno, &mut buf)?;
    let flags = g16(rec, 0x16);
    if flags & 1 == 0 {
        return Err(E::NotInUse);
    }
    if flags & 2 != 0 {
        return Err(E::Directory);
    }
    let own_seq = g16(rec, 0x10);
    if seq != 0 && own_seq != seq {
        return Err(E::Sequence);
    }
    if g64(rec, 0x20) != 0 {
        return Err(E::NotBase);
    }
    // One pass over the base record: the attribute list, and unnamed $DATA.
    let (mut list, mut data, mut ndata) = (None, 0usize, 0u32);
    let mut pos = us(g16(rec, 0x14));
    while let Some((ty, len)) = attr_at(rec, pos)? {
        if ty == ATTR_LIST {
            if list.is_some() {
                return Err(E::AttrList);
            }
            list = Some(pos);
        }
        if ty == ATTR_DATA && g8(rec, pos + 9) == 0 {
            if ndata == 0 {
                data = pos;
            }
            ndata += 1;
        }
        pos += len;
    }
    let mut st = Seg {
        n: 0,
        vcn: 0,
        alloc: 0,
        size: 0,
        init: 0,
    };
    match list {
        None => {
            if ndata == 0 {
                return Err(E::NoData);
            }
            if ndata > 1 {
                return Err(E::DuplicateData);
            }
            segment(vol, rec, data, &mut st, out)?;
        }
        Some(lp) => {
            if !allow_list {
                return Err(E::MftAttrList);
            }
            let size = load_list(disk, vol, rec, lp, alist, out)?;
            let base_ref = recno | own_seq << 48;
            // Entries are sorted by (type, name, lowest VCN); the Gap check
            // enforces that order for unnamed $DATA, one segment at a time.
            let (mut p, mut ext) = (0usize, 0u32);
            while p < size {
                if p + 0x1a > size {
                    return Err(E::AttrList);
                }
                let elen = us(g16(alist, p + 4));
                if elen < 0x1a || elen > size - p {
                    return Err(E::AttrList);
                }
                if g32(alist, p) == ATTR_DATA && g8(alist, p + 6) == 0 {
                    if g64(alist, p + 8) != st.vcn {
                        return Err(E::Gap);
                    }
                    let r = g64(alist, p + 0x10) & 0xffff_ffff_ffff;
                    let rseq = g64(alist, p + 0x10) >> 48;
                    if r != recno {
                        ext += 1;
                        if ext > MAX_EXTENSIONS {
                            return Err(E::TooManyExtensions);
                        }
                    }
                    let rec = read_record(disk, vol, map, limit, r, &mut buf)?;
                    if g16(rec, 0x16) & 1 == 0 {
                        return Err(E::NotInUse);
                    }
                    if g16(rec, 0x10) != rseq {
                        return Err(E::Sequence);
                    }
                    if g64(rec, 0x20) != if r == recno { 0 } else { base_ref } {
                        return Err(E::ExtensionBase);
                    }
                    let at = find_segment(rec, g16(alist, p + 0x18))?;
                    segment(vol, rec, at.ok_or(E::MissingSegment)?, &mut st, out)?;
                }
                p += elen;
            }
            if st.n == 0 {
                return Err(E::NoData);
            }
        }
    }
    let bytes = st.vcn.checked_mul(vol.cluster_bytes);
    if bytes != Some(st.alloc) || st.size > st.alloc {
        return Err(E::AllocatedSize);
    }
    if st.init != st.size {
        return Err(E::NotInitialized);
    }
    if st.size % SECTOR != 0 {
        return Err(E::Unaligned);
    }
    Ok(FileMap {
        runs: st.n,
        data_size: st.size,
    })
}

/// Steps 1–2: read the boot sector and map `$MFT` from record 0, whose own
/// location comes from the boot sector alone. `runs` receives `$MFT`'s map.
pub fn open<'a, D: Disk>(
    disk: &mut D,
    alist: &mut [u8; MAX_ALIST],
    runs: &'a mut [Run],
) -> Result<Mft<'a>> {
    let mut boot = [0u8; 512];
    disk.read(0, &mut boot).map_err(|_| E::Io)?;
    let vol = parse_boot(&boot)?;
    let boot_map = [Run {
        lcn: vol.mft_lcn,
        count: vol.record_bytes.div_ceil(vol.cluster_bytes),
    }];
    let m = walk(
        disk,
        &vol,
        &boot_map,
        vol.record_bytes,
        0,
        0,
        false,
        alist,
        runs,
    )?;
    Ok(Mft {
        vol,
        runs: runs.get(..m.runs).unwrap_or(&[]),
        bytes: m.data_size,
    })
}

/// Steps 3–5: the unnamed `$DATA` runs of file `(recno, seq)`, into `runs`.
pub fn file<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    recno: u64,
    seq: u16,
    alist: &mut [u8; MAX_ALIST],
    runs: &mut [Run],
) -> Result<FileMap> {
    if recno < FIRST_USER_RECORD || recno > u64::from(u32::MAX) || seq == 0 {
        return Err(E::BadIdentity);
    }
    let seq = u64::from(seq);
    walk(
        disk, &mft.vol, mft.runs, mft.bytes, recno, seq, true, alist, runs,
    )
}

/// Step 6: runs → 512-byte-sector extents in file order, physically adjacent
/// runs coalesced (so the representation is canonical for [`grows`]).
pub fn extents(vol: &Volume, runs: &[Run], out: &mut [Extent]) -> Result<usize> {
    let spc = vol.cluster_bytes / SECTOR;
    let mut n = 0usize;
    for r in runs {
        let start = r.lcn.checked_mul(spc).ok_or(E::OutsideVolume)?;
        let end = r
            .lcn
            .checked_add(r.count)
            .and_then(|e| e.checked_mul(spc))
            .ok_or(E::OutsideVolume)?;
        if end > vol.sectors {
            return Err(E::OutsideVolume);
        }
        if let Some(last) = n.checked_sub(1).and_then(|i| out.get_mut(i)) {
            if last.end == start {
                last.end = end;
                continue;
            }
        }
        *out.get_mut(n).ok_or(E::TooManyExtents)? = Extent { start, end };
        n += 1;
    }
    Ok(n)
}

/// Step 7: `$Volume`'s `$VOLUME_INFORMATION` flags ([`VOLUME_DIRTY`], …).
pub fn volume_flags<D: Disk>(disk: &mut D, mft: &Mft<'_>) -> Result<u16> {
    let mut buf = [0u8; MAX_RECORD];
    let rec = read_record(disk, &mft.vol, mft.runs, mft.bytes, 3, &mut buf)?;
    if g16(rec, 0x16) & 1 == 0 {
        return Err(E::NotInUse);
    }
    if g64(rec, 0x20) != 0 {
        return Err(E::NotBase);
    }
    let mut pos = us(g16(rec, 0x14));
    while let Some((ty, len)) = attr_at(rec, pos)? {
        if ty == ATTR_VOLUME_INFO && g8(rec, pos + 8) == 0 {
            if g32(rec, pos + 0x10) < 12 {
                return Err(E::NoVolumeInfo);
            }
            let flags = g16(rec, pos + us(g16(rec, pos + 0x14)) + 0x0a);
            return Ok(u16::try_from(flags).unwrap_or(u16::MAX));
        }
        pos += len;
    }
    Err(E::NoVolumeInfo)
}

// ---- claims: what the module does with a file's extents ------------------

/// Sorted, merged copy of a file's extents for the range test. Refuses
/// extents that overlap each other (a runlist naming a cluster twice).
pub fn normalise(file: &[Extent], out: &mut [Extent]) -> Result<usize> {
    let dst = out.get_mut(..file.len()).ok_or(E::TooManyExtents)?;
    dst.copy_from_slice(file);
    dst.sort_unstable_by_key(|e| e.start);
    let mut n = 0usize;
    for i in 0..dst.len() {
        let e = *dst.get(i).ok_or(E::TooManyExtents)?;
        if e.start >= e.end {
            return Err(E::SelfOverlap);
        }
        match n.checked_sub(1).and_then(|j| dst.get_mut(j)) {
            Some(last) if e.start < last.end => return Err(E::SelfOverlap),
            Some(last) if e.start == last.end => last.end = e.end,
            _ => {
                *dst.get_mut(n).ok_or(E::TooManyExtents)? = e;
                n += 1;
            }
        }
    }
    Ok(n)
}

/// Do two normalised extent lists share a sector? (Claims on one volume may
/// never intersect.)
pub fn intersects(a: &[Extent], b: &[Extent]) -> bool {
    let (mut i, mut j) = (0, 0);
    while let (Some(x), Some(y)) = (a.get(i), b.get(j)) {
        if x.intersects(y) {
            return true;
        }
        if x.end <= y.end {
            i += 1;
        } else {
            j += 1;
        }
    }
    false
}

/// Append-only growth (INTERFACES `PG_GROW`): every sector of the old file
/// maps where it did. With coalesced extents that is: all old extents but the
/// last unchanged, the last one extended in place or kept, then anything.
pub fn grows(old: &[Extent], new: &[Extent]) -> bool {
    let Some((last, head)) = old.split_last() else {
        return false;
    };
    let (Some(new_head), Some(new_last)) = (new.get(..head.len()), new.get(head.len())) else {
        return false;
    };
    new_head == head && new_last.start == last.start && new_last.end >= last.end
}

/// Merge file-order extents that are physically adjacent, in place, as
/// [`extents`] does (for comparing a FIEMAP claim). `None` if any is empty.
pub fn coalesce(e: &mut [Extent]) -> Option<usize> {
    let mut n = 0usize;
    for i in 0..e.len() {
        let x = *e.get(i)?;
        if x.start >= x.end {
            return None;
        }
        match n.checked_sub(1).and_then(|j| e.get_mut(j)) {
            Some(last) if last.end == x.start => last.end = x.end,
            _ => {
                *e.get_mut(n)? = x;
                n += 1;
            }
        }
    }
    Some(n)
}

/// The first `sectors` logical sectors of file-order extents, in place;
/// `None` if they hold fewer, any is empty, or `sectors` is 0. The
/// cross-check compares FIEMAP and the derived map up to the end of the
/// file's data this way (drivers report the unused tail of a partly used
/// last cluster differently; a fixed VHD always has one).
pub fn truncate(e: &mut [Extent], sectors: u64) -> Option<usize> {
    let mut left = sectors;
    for (i, x) in e.iter_mut().enumerate() {
        if left == 0 {
            break;
        }
        if x.start >= x.end {
            return None;
        }
        let len = x.end - x.start;
        if len >= left {
            x.end = x.start + left;
            return Some(i + 1);
        }
        left -= len;
    }
    None
}

/// View A's translation: logical sector `lsec` of the gathered file →
/// `(physical sector, sectors left in that extent)`, `None` beyond the end.
pub fn gather(file: &[Extent], lsec: u64) -> Option<(u64, u64)> {
    // Keeps: base <= lsec. Wrapping arithmetic only matters for input that
    // pg_ntfs_extents() never produces, and matches the C bit for bit.
    let mut base = 0u64;
    for e in file {
        let len = e.end.wrapping_sub(e.start);
        let into = lsec.wrapping_sub(base);
        if into < len {
            return Some((e.start.wrapping_add(into), len - into));
        }
        base = base.wrapping_add(len);
    }
    None
}

/// The mandatory structural assertion (DESIGN §4.3, INTERFACES §3.2 "the
/// structural assertion follows the content"), over the gathered image of
/// `sectors` 512-byte sectors, before anything can mount it:
///
/// | payload | checked |
/// |---|---|
/// | GPT (`EFI PART` at LBA 1, in units of `lbs`) | header and entry-array CRC32; the backup header at the primary's alternate LBA (the last LBA, or earlier on a disk that grew and has not moved it yet) agreeing field by field, with its own entry array; every used entry inside the usable range; each ESP a FAT boot sector, each partition holding an ext4 superblock checked as bare ext4; at least one partition verified |
/// | bare ext4 (`0xEF53` at byte 1080) | plausible geometry no larger than the payload, the primary naming group 0, and the backup superblock in group 1 (or `s_backup_bgs[0]` under `sparse_super2`) agreeing on UUID, block count and naming its own group |
/// | ISO 9660 (`CD001` at byte 32768) | the primary volume descriptor's both-endian fields agree, volume space size × block size = payload length, and the root directory's `.` record points at itself |
/// | anything else | refused |
///
/// Everything checked beyond the first sectors (the backup GPT, partition
/// starts, ext4's group-1 superblock) sits past a fragmented file's first
/// extent, so extents gathered in the wrong order fail here.
///
/// `lbs` is view A's logical block size (512 or 4096): a GPT counts its LBAs
/// in it, as the kernel's partition code will. Reads are always 512-byte
/// sectors; anything else is refused.
pub fn check_payload<D: Disk>(img: &mut D, sectors: u64, lbs: u64) -> Result<()> {
    let mut b = [0u8; 512];
    if (lbs != 512 && lbs != 4096) || sectors < 2 {
        return Err(E::PayloadUnknown);
    }
    let k = lbs / 512;
    if sectors > k {
        img.read(k, &mut b).map_err(|_| E::Io)?;
        if b.get(..8) == Some(&b"EFI PART"[..]) {
            return payload_gpt(img, sectors, k, &mut b);
        }
    }
    if sectors > 2 {
        img.read(2, &mut b).map_err(|_| E::Io)?;
        if g16(&b, 56) == EXT4_MAGIC {
            return payload_ext4(img, 0, sectors, &mut b);
        }
    }
    if sectors > ISO_PVD {
        img.read(ISO_PVD, &mut b).map_err(|_| E::Io)?;
        if b.get(..6) == Some(&b"\x01CD001"[..]) {
            return payload_iso(img, sectors, &mut b);
        }
    }
    Err(E::PayloadUnknown)
}

const EXT4_MAGIC: u64 = 0xef53;
/// Sector of the ISO 9660 primary volume descriptor (byte 32768).
const ISO_PVD: u64 = 64;

/// CRC-32 (IEEE) of the first `n` bytes of the header in `b`, with its own
/// CRC field (bytes 16..20) taken as zero. `n` ≤ 512.
fn header_crc(b: &[u8; 512], n: usize) -> u64 {
    let mut c = crate::gpt::crc32_update(0, b.get(..16).unwrap_or(&[]));
    c = crate::gpt::crc32_update(c, &[0; 4]);
    u64::from(crate::gpt::crc32_update(c, b.get(20..n).unwrap_or(&[])))
}

/// CRC-32 of a GPT entry array of `count` 128-byte entries at sector `at`.
fn array_crc<D: Disk>(img: &mut D, at: u64, count: u64, b: &mut [u8; 512]) -> Result<u64> {
    let (mut c, mut left) = (0u32, count * 128);
    let mut s = at;
    while left > 0 {
        img.read(s, b).map_err(|_| E::Io)?;
        let n = left.min(512);
        c = crate::gpt::crc32_update(c, b.get(..us(n)).unwrap_or(&[]));
        left -= n;
        s += 1;
    }
    Ok(u64::from(c))
}

/// `b` holds LBA 1, which starts `EFI PART`; an LBA is `k` sectors. Every
/// LBA is checked against `lbas` (the image in LBAs) before it is scaled.
fn payload_gpt<D: Disk>(img: &mut D, sectors: u64, k: u64, b: &mut [u8; 512]) -> Result<()> {
    let lbas = sectors / k;
    let hsize = g32(b, 12);
    if !(92..=512).contains(&hsize) || g64(b, 24) != 1 {
        return Err(E::PayloadGpt);
    }
    if header_crc(b, us(hsize)) != g32(b, 16) {
        return Err(E::PayloadGptCrc);
    }
    let (alt, first_usable, last_usable) = (g64(b, 32), g64(b, 40), g64(b, 48));
    let mut guid = [0u8; 16];
    guid.copy_from_slice(b.get(56..72).unwrap_or(&[0; 16]));
    let (lba, count, esize, acrc) = (g64(b, 72), g32(b, 80), g32(b, 84), g32(b, 88));
    if esize != 128 || count == 0 || count > 1024 {
        return Err(E::PayloadGpt);
    }
    // The array's size in LBAs.
    let asec = (count * 128).div_ceil(k * 512);
    // The array lies in [lba, first_usable), partitions in
    // [first_usable, last_usable], the backup array and header above that.
    if alt >= lbas
        || last_usable >= alt
        || first_usable > last_usable
        || lba < 2
        || lba > first_usable
        || first_usable - lba < asec
    {
        return Err(E::PayloadGpt);
    }
    if array_crc(img, lba * k, count, b)? != acrc {
        return Err(E::PayloadGptCrc);
    }
    img.read(alt * k, b).map_err(|_| E::Io)?;
    if b.get(..8) != Some(&b"EFI PART"[..])
        || g32(b, 12) != hsize
        || header_crc(b, us(hsize)) != g32(b, 16)
        || g64(b, 24) != alt
        || g64(b, 32) != 1
        || g64(b, 40) != first_usable
        || g64(b, 48) != last_usable
        || b.get(56..72) != Some(&guid[..])
        || g32(b, 80) != count
        || g32(b, 84) != esize
        || g32(b, 88) != acrc
    {
        return Err(E::PayloadGptBackup);
    }
    let blba = g64(b, 72);
    if blba <= last_usable || blba >= alt || alt - blba < asec {
        return Err(E::PayloadGptBackup);
    }
    if array_crc(img, blba * k, count, b)? != acrc {
        return Err(E::PayloadGptBackup);
    }
    let (mut verified, mut stale) = (0u32, true);
    for i in 0..count {
        if i % 4 == 0 || stale {
            img.read(lba * k + i / 4, b).map_err(|_| E::Io)?;
            stale = false;
        }
        let e = us(i % 4) * 128;
        let ty = b.get(e..e + 16).unwrap_or(&[]);
        if ty.iter().all(|&x| x == 0) {
            continue;
        }
        let esp = ty == ESP_TYPE;
        let (first, last) = (g64(b, e + 32), g64(b, e + 40));
        if first < first_usable || last > last_usable || first > last {
            return Err(E::PayloadGpt);
        }
        // In sectors from here on: last < alt < lbas, so no overflow.
        let (first, len) = (first * k, (last - first + 1) * k);
        stale = true;
        if esp {
            img.read(first, b).map_err(|_| E::Io)?;
            if !is_fat(b, len) {
                return Err(E::PayloadNotFat);
            }
            verified += 1;
        } else if len > 2 {
            img.read(first + 2, b).map_err(|_| E::Io)?;
            if g16(b, 56) == EXT4_MAGIC {
                payload_ext4(img, first, len, b)?;
                verified += 1;
            }
        }
    }
    if verified == 0 {
        return Err(E::PayloadNoKnownPartition);
    }
    Ok(())
}

/// A FAT boot sector for a partition of `len` sectors: signature, a FAT
/// type string, sane sector and cluster sizes, and no more sectors than the
/// partition holds.
fn is_fat(b: &[u8; 512], len: u64) -> bool {
    let name = b.get(0x36..0x39) == Some(&b"FAT"[..]) || b.get(0x52..0x57) == Some(&b"FAT32"[..]);
    let bps = g16(b, 11);
    let spc = g8(b, 13);
    let mut total = g16(b, 0x13);
    if total == 0 {
        total = g32(b, 0x20);
    }
    g16(b, 510) == 0xaa55
        && name
        && matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc.is_power_of_two()
        && total != 0
        && total * (bps / 512) <= len
}

/// ext4 at sector `base` of the image, `len` sectors long; `b` holds sector
/// `base + 2` (the first half of the superblock), whose magic matched.
fn payload_ext4<D: Disk>(img: &mut D, base: u64, len: u64, b: &mut [u8; 512]) -> Result<()> {
    let log = g32(b, 0x18);
    let first = g32(b, 0x14);
    let per_group = g32(b, 0x20);
    let (compat, incompat) = if g32(b, 0x4c) >= 1 {
        (g32(b, 0x5c), g32(b, 0x60))
    } else {
        (0, 0)
    };
    let wide = incompat & 0x80 != 0; // INCOMPAT_64BIT
    let blocks = |b: &[u8; 512]| g32(b, 4) | if wide { g32(b, 0x150) << 32 } else { 0 };
    let count = blocks(b);
    // The primary names group 0: a backup copy where the primary belongs
    // (extents misordered) is refused.
    // The superblock alone fills sectors 2-3: `len` > 3 bounds the read of
    // sector 3 below.
    if len < 4
        || log > 6
        || per_group == 0
        || first > 1
        || (log > 0 && first != 0)
        || g16(b, 0x5a) != 0
    {
        return Err(E::PayloadExt4);
    }
    let per_block = 2u64 << log; // sectors
    if count == 0 || count > len / per_block {
        return Err(E::PayloadExt4);
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(b.get(0x68..0x78).unwrap_or(&[0; 16]));
    // COMPAT_SPARSE_SUPER2: backups only where s_backup_bgs says.
    let group = if compat & 0x200 != 0 {
        img.read(base + 3, b).map_err(|_| E::Io)?;
        g32(b, 0x24c - 512)
    } else {
        1
    };
    let block = first + per_group * group;
    if group == 0 || block >= count {
        return Err(E::PayloadExt4);
    }
    img.read(base + block * per_block, b).map_err(|_| E::Io)?;
    if g16(b, 56) != EXT4_MAGIC
        || b.get(0x68..0x78) != Some(&uuid[..])
        || blocks(b) != count
        || g16(b, 0x5a) != group & 0xffff
    {
        return Err(E::PayloadExt4);
    }
    Ok(())
}

/// `b` holds the primary volume descriptor (type 1, `CD001`).
fn payload_iso<D: Disk>(img: &mut D, sectors: u64, b: &mut [u8; 512]) -> Result<()> {
    let be = |b: &[u8; 512], at: usize, n: usize| {
        b.get(at..at + n)
            .map_or(0, |s| s.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    };
    let (size, bs) = (g32(b, 80), g16(b, 128));
    if g8(b, 6) != 1 || be(b, 84, 4) != size || be(b, 130, 2) != bs {
        return Err(E::PayloadIso);
    }
    if !matches!(bs, 512 | 1024 | 2048) || size * (bs / 512) != sectors {
        return Err(E::PayloadIso);
    }
    // The root directory record (34 bytes at 156).
    let root = g32(b, 158);
    if g8(b, 156) != 34 || be(b, 162, 4) != root || g8(b, 181) & 2 == 0 || root == 0 || root >= size
    {
        return Err(E::PayloadIso);
    }
    img.read(root * (bs / 512), b).map_err(|_| E::Io)?;
    if g8(b, 0) < 34 || g32(b, 2) != root || g8(b, 25) & 2 == 0 || g8(b, 32) != 1 || g8(b, 33) != 0
    {
        return Err(E::PayloadIso);
    }
    Ok(())
}
