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

/// The on-disk structures read, as layout descriptions (pg_layout.h's twin).
#[macro_use]
pub mod layout;
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
/// Record numbers above this (32 bits) are refused.
pub const MAX_RECORD_NUMBER: u64 = 0xffff_ffff;
/// Records below this are NTFS metadata (0–15) and `$MFT`'s reserved
/// extensions (16–23); never a user file.
pub const FIRST_USER_RECORD: u64 = 24;
/// `$VOLUME_INFORMATION` flag: the volume needs `chkdsk`.
pub const VOLUME_DIRTY: u16 = 0x0001;

use layout::*;

const ATTR_LIST: u64 = NTFS_AT_ATTRIBUTE_LIST;
const ATTR_DATA: u64 = NTFS_AT_DATA;

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
/// A little-endian u16 at `at`, for what is not a layout field (the
/// update-sequence array and the sector ends it patches).
fn g16(b: &[u8], at: usize) -> u64 {
    get(b, at, 2)
}
/// `u64` → `usize` for values already bounded by a record or buffer length.
fn us(v: u64) -> usize {
    usize::try_from(v).unwrap_or(usize::MAX)
}

/// Step 1. Validate the boot sector and derive the geometry.
pub fn parse_boot(b: &[u8; 512]) -> Result<Volume> {
    if get!(b, ntfs_boot_sector, signature) != BOOT_SIGNATURE {
        return Err(E::BootSignature);
    }
    let oem = off!(ntfs_boot_sector, oem_id);
    if b.get(oem..oem + width!(ntfs_boot_sector, oem_id)) != Some(NTFS_OEM_ID) {
        return Err(E::OemId);
    }
    let bps = get!(b, ntfs_boot_sector, bytes_per_sector);
    if bps != 512 && bps != 4096 {
        return Err(E::SectorSize);
    }
    // Sectors per cluster: 1..=128, or 2^(256 - raw) for clusters beyond
    // 64 KiB (the byte, read as negative, is minus the exponent: 256 - raw).
    let raw = get!(b, ntfs_boot_sector, sectors_per_cluster);
    let spc = if raw <= NTFS_BS_NEGATIVE {
        raw
    } else if 256 - raw <= NTFS_BS_MAX_CLUSTER_SHIFT {
        1 << (256 - raw)
    } else {
        0
    };
    if spc == 0 || !spc.is_power_of_two() || bps * spc > MAX_CLUSTER {
        return Err(E::ClusterSize);
    }
    let cluster_bytes = bps * spc;
    let bytes = get!(b, ntfs_boot_sector, total_sectors)
        .checked_mul(bps)
        .ok_or(E::VolumeSize)?;
    let clusters = bytes / cluster_bytes;
    if clusters == 0 {
        return Err(E::VolumeSize);
    }
    // Record size: clusters per record if positive, else 2^-raw bytes.
    let raw = get!(b, ntfs_boot_sector, clusters_per_mft_record);
    let record_bytes = if raw < NTFS_BS_NEGATIVE {
        raw * cluster_bytes
    } else if (256 - raw) <= NTFS_BS_MAX_RECORD_SHIFT {
        1 << (256 - raw)
    } else {
        0
    };
    if !(1024..=MAX_RECORD as u64).contains(&record_bytes) || !record_bytes.is_power_of_two() {
        return Err(E::RecordSize);
    }
    let mft_lcn = get!(b, ntfs_boot_sector, mft_lcn);
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
    if rec.get(..width!(ntfs_file_record, magic)) != Some(NTFS_RECORD_MAGIC) {
        return Err(E::RecordMagic);
    }
    // One update-sequence entry per 512 bytes, plus the USN itself.
    let count = us(get!(rec, ntfs_file_record, usa_count));
    let usa = get!(rec, ntfs_file_record, usa_offset);
    if (usa != NTFS_USA_OFFSET_31 && usa != NTFS_USA_OFFSET_30)
        || count != rec.len() / us(SECTOR) + 1
    {
        return Err(E::RecordLayout);
    }
    let usa = us(usa);
    // Each sector's last two bytes hold the USN; the array (u16s) holds what
    // belongs there.
    let usn = g16(rec, usa);
    for i in 1..count {
        let at = i * us(SECTOR) - 2;
        if g16(rec, at) != usn {
            return Err(E::FixupMismatch);
        }
        let fix = us(g16(rec, usa + 2 * i)).to_le_bytes();
        if let (Some(dst), Some(src)) = (rec.get_mut(at..at + 2), fix.get(..2)) {
            dst.copy_from_slice(src);
        }
    }
    let attrs = get!(rec, ntfs_file_record, attrs_offset);
    let used = get!(rec, ntfs_file_record, bytes_in_use);
    // Attributes are 8-byte aligned.
    if get!(rec, ntfs_file_record, bytes_allocated) != rb
        || used > rb
        || used % 8 != 0
        || attrs % 8 != 0
        || attrs < (usa + 2 * count) as u64
        || attrs >= used
    {
        return Err(E::RecordLayout);
    }
    // Only the 3.1 layout says which record it is (3.0's array is there).
    if usa == NTFS_USA_OFFSET_31 as usize && get!(rec, ntfs_file_record, mft_record_number) != recno
    {
        return Err(E::RecordNumber);
    }
    Ok(rec)
}

/// Validate the attribute header at `pos` of a checked record: `None` at the
/// end marker, else its type and length. Postcondition: the header
/// (resident, or the longer non-resident one), its name (UTF-16) and any
/// resident value lie inside the attribute, which lies inside
/// `bytes_in_use`.
fn attr_at(rec: &[u8], pos: usize) -> Result<Option<(u64, usize)>> {
    let used = us(get!(rec, ntfs_file_record, bytes_in_use));
    if pos + width!(ntfs_attr, r#type) > used {
        return Err(E::AttrBounds);
    }
    let ty = get_at!(rec, pos, ntfs_attr, r#type);
    if ty == NTFS_AT_END {
        return Ok(None);
    }
    // The header every attribute has room for.
    if pos + size_of::<ntfs_attr_resident>() > used {
        return Err(E::AttrBounds);
    }
    let len = us(get_at!(rec, pos, ntfs_attr, length));
    if len < size_of::<ntfs_attr_resident>() || len % 8 != 0 || len > used - pos {
        return Err(E::AttrBounds);
    }
    let nonres = get_at!(rec, pos, ntfs_attr, non_resident);
    let name_len = us(get_at!(rec, pos, ntfs_attr, name_length));
    if nonres > 1
        || (name_len > 0 && us(get_at!(rec, pos, ntfs_attr, name_offset)) + 2 * name_len > len)
    {
        return Err(E::AttrBounds);
    }
    if nonres == 1 && len < size_of::<ntfs_attr_nonresident>() {
        return Err(E::AttrBounds);
    }
    if nonres == 0
        && us(get_at!(rec, pos, ntfs_attr_resident, value_offset))
            + us(get_at!(rec, pos, ntfs_attr_resident, value_length))
            > len
    {
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
    let len = us(get_at!(rec, pos, ntfs_attr, length));
    let mp = us(get_at!(
        rec,
        pos,
        ntfs_attr_nonresident,
        mapping_pairs_offset
    ));
    // Inside the attribute, after its header.
    if mp < size_of::<ntfs_attr_nonresident>() || mp >= len {
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
    if get_at!(rec, pos, ntfs_attr, non_resident) == 0 {
        return Err(E::Resident);
    }
    // Sparse first: ntfs-3g gives sparse files a compression unit too.
    let flags = get_at!(rec, pos, ntfs_attr, flags);
    if flags & NTFS_ATTR_IS_SPARSE != 0 {
        return Err(E::Sparse);
    }
    if flags & NTFS_ATTR_IS_ENCRYPTED != 0 {
        return Err(E::Encrypted);
    }
    let lowest = get_at!(rec, pos, ntfs_attr_nonresident, lowest_vcn);
    let mask = if lowest != 0 {
        NTFS_ATTR_IS_COMPRESSED
    } else {
        NTFS_ATTR_COMPRESSION_MASK
    };
    if flags & mask != 0 || get_at!(rec, pos, ntfs_attr_nonresident, compression_unit) != 0 {
        return Err(E::Compressed);
    }
    if lowest != st.vcn {
        return Err(E::Gap);
    }
    if lowest == 0 {
        st.alloc = get_at!(rec, pos, ntfs_attr_nonresident, allocated_size);
        st.size = get_at!(rec, pos, ntfs_attr_nonresident, data_size);
        st.init = get_at!(rec, pos, ntfs_attr_nonresident, initialized_size);
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
    if k == 0 || get_at!(rec, pos, ntfs_attr_nonresident, highest_vcn) != next - 1 {
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
    if get_at!(rec, pos, ntfs_attr, non_resident) == 0 {
        let size = us(get_at!(rec, pos, ntfs_attr_resident, value_length));
        let voff = pos + us(get_at!(rec, pos, ntfs_attr_resident, value_offset));
        let src = rec.get(voff..voff + size).ok_or(E::AttrBounds)?;
        alist
            .get_mut(..size)
            .ok_or(E::AttrListSize)?
            .copy_from_slice(src);
        return Ok(size);
    }
    if get_at!(rec, pos, ntfs_attr, flags) != 0
        || get_at!(rec, pos, ntfs_attr_nonresident, lowest_vcn) != 0
    {
        return Err(E::AttrList);
    }
    let size = get_at!(rec, pos, ntfs_attr_nonresident, data_size);
    if size > MAX_ALIST as u64 {
        return Err(E::AttrListSize);
    }
    if get_at!(rec, pos, ntfs_attr_nonresident, initialized_size) != size {
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
    let mut pos = us(get!(rec, ntfs_file_record, attrs_offset));
    while let Some((ty, len)) = attr_at(rec, pos)? {
        if ty == ATTR_DATA
            && get_at!(rec, pos, ntfs_attr, name_length) == 0
            && get_at!(rec, pos, ntfs_attr, instance) == instance
        {
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
    let flags = get!(rec, ntfs_file_record, flags);
    if flags & NTFS_RECORD_IN_USE == 0 {
        return Err(E::NotInUse);
    }
    if flags & NTFS_RECORD_IS_DIRECTORY != 0 {
        return Err(E::Directory);
    }
    let own_seq = get!(rec, ntfs_file_record, sequence_number);
    if seq != 0 && own_seq != seq {
        return Err(E::Sequence);
    }
    if get!(rec, ntfs_file_record, base_mft_record) != 0 {
        return Err(E::NotBase);
    }
    // One pass over the base record: the attribute list, and unnamed $DATA.
    let (mut list, mut data, mut ndata) = (None, 0usize, 0u32);
    let mut pos = us(get!(rec, ntfs_file_record, attrs_offset));
    while let Some((ty, len)) = attr_at(rec, pos)? {
        if ty == ATTR_LIST {
            if list.is_some() {
                return Err(E::AttrList);
            }
            list = Some(pos);
        }
        if ty == ATTR_DATA && get_at!(rec, pos, ntfs_attr, name_length) == 0 {
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
            let base_ref = recno | own_seq << NTFS_MFT_REF_SEQ_SHIFT;
            // Entries are sorted by (type, name, lowest VCN); the Gap check
            // enforces that order for unnamed $DATA, one segment at a time.
            let entry = size_of::<ntfs_attr_list_entry>();
            let (mut p, mut ext) = (0usize, 0u32);
            while p < size {
                if p + entry > size {
                    return Err(E::AttrList);
                }
                let elen = us(get_at!(alist, p, ntfs_attr_list_entry, length));
                if elen < entry || elen > size - p {
                    return Err(E::AttrList);
                }
                if get_at!(alist, p, ntfs_attr_list_entry, r#type) == ATTR_DATA
                    && get_at!(alist, p, ntfs_attr_list_entry, name_length) == 0
                {
                    if get_at!(alist, p, ntfs_attr_list_entry, lowest_vcn) != st.vcn {
                        return Err(E::Gap);
                    }
                    let mref = get_at!(alist, p, ntfs_attr_list_entry, mft_reference);
                    let r = mref & NTFS_MFT_REF_RECORD_MASK;
                    let rseq = mref >> NTFS_MFT_REF_SEQ_SHIFT;
                    if r != recno {
                        ext += 1;
                        if ext > MAX_EXTENSIONS {
                            return Err(E::TooManyExtensions);
                        }
                    }
                    let rec = read_record(disk, vol, map, limit, r, &mut buf)?;
                    if get!(rec, ntfs_file_record, flags) & NTFS_RECORD_IN_USE == 0 {
                        return Err(E::NotInUse);
                    }
                    if get!(rec, ntfs_file_record, sequence_number) != rseq {
                        return Err(E::Sequence);
                    }
                    if get!(rec, ntfs_file_record, base_mft_record)
                        != if r == recno { 0 } else { base_ref }
                    {
                        return Err(E::ExtensionBase);
                    }
                    let at = find_segment(rec, get_at!(alist, p, ntfs_attr_list_entry, instance))?;
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
    if !(FIRST_USER_RECORD..=MAX_RECORD_NUMBER).contains(&recno) || seq == 0 {
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
    let rec = read_record(
        disk,
        &mft.vol,
        mft.runs,
        mft.bytes,
        NTFS_MFT_RECORD_VOLUME,
        &mut buf,
    )?;
    if get!(rec, ntfs_file_record, flags) & NTFS_RECORD_IN_USE == 0 {
        return Err(E::NotInUse);
    }
    if get!(rec, ntfs_file_record, base_mft_record) != 0 {
        return Err(E::NotBase);
    }
    let mut pos = us(get!(rec, ntfs_file_record, attrs_offset));
    while let Some((ty, len)) = attr_at(rec, pos)? {
        if ty == NTFS_AT_VOLUME_INFORMATION && get_at!(rec, pos, ntfs_attr, non_resident) == 0 {
            if get_at!(rec, pos, ntfs_attr_resident, value_length)
                < size_of::<ntfs_volume_information>() as u64
            {
                return Err(E::NoVolumeInfo);
            }
            let value = pos + us(get_at!(rec, pos, ntfs_attr_resident, value_offset));
            let flags = get_at!(rec, value, ntfs_volume_information, flags);
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
        if b.get(..width!(gpt_header, signature)) == Some(GPT_SIGNATURE) {
            return payload_gpt(img, sectors, k, &mut b);
        }
    }
    if sectors > EXT4_SB_SECTOR {
        img.read(EXT4_SB_SECTOR, &mut b).map_err(|_| E::Io)?;
        if get!(&b, ext4_super_block, s_magic) == EXT4_SUPER_MAGIC {
            return payload_ext4(img, 0, sectors, &mut b);
        }
    }
    if sectors > ISO_PVD {
        img.read(ISO_PVD, &mut b).map_err(|_| E::Io)?;
        let id = off!(iso_primary_volume_descriptor, id);
        if get!(&b, iso_primary_volume_descriptor, r#type) == ISO_VD_PRIMARY
            && b.get(id..id + width!(iso_primary_volume_descriptor, id)) == Some(ISO_STANDARD_ID)
        {
            return payload_iso(img, sectors, &mut b);
        }
    }
    Err(E::PayloadUnknown)
}

/// Sector of the ISO 9660 primary volume descriptor.
const ISO_PVD: u64 = ISO_PVD_OFFSET / SECTOR;
/// The ext4 superblock's first sector.
const EXT4_SB_SECTOR: u64 = EXT4_SUPERBLOCK_OFFSET / SECTOR;

/// CRC-32 (IEEE) of the first `n` bytes of the header in `b`, with its own
/// CRC field taken as zero. `n` ≤ 512.
fn header_crc(b: &[u8; 512], n: usize) -> u64 {
    let at = off!(gpt_header, header_crc32);
    let after = at + width!(gpt_header, header_crc32);
    let mut c = crate::gpt::crc32_update(0, b.get(..at).unwrap_or(&[]));
    c = crate::gpt::crc32_update(c, &[0; 4]);
    u64::from(crate::gpt::crc32_update(c, b.get(after..n).unwrap_or(&[])))
}

/// CRC-32 of a GPT entry array of `count` entries at sector `at`.
fn array_crc<D: Disk>(img: &mut D, at: u64, count: u64, b: &mut [u8; 512]) -> Result<u64> {
    let (mut c, mut left) = (0u32, count * size_of::<gpt_entry>() as u64);
    let mut s = at;
    while left > 0 {
        img.read(s, b).map_err(|_| E::Io)?;
        let n = left.min(SECTOR);
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
    let ent = size_of::<gpt_entry>() as u64;
    let per_sector = SECTOR / ent; // entries
    let hsize = get!(b, gpt_header, header_size);
    if !(size_of::<gpt_header>() as u64..=GPT_MAX_HEADER_SIZE).contains(&hsize)
        || get!(b, gpt_header, my_lba) != 1
    {
        return Err(E::PayloadGpt);
    }
    if header_crc(b, us(hsize)) != get!(b, gpt_header, header_crc32) {
        return Err(E::PayloadGptCrc);
    }
    let alt = get!(b, gpt_header, alternate_lba);
    let first_usable = get!(b, gpt_header, first_usable_lba);
    let last_usable = get!(b, gpt_header, last_usable_lba);
    let g = off!(gpt_header, disk_guid);
    let mut guid = [0u8; 16];
    guid.copy_from_slice(
        b.get(g..g + width!(gpt_header, disk_guid))
            .unwrap_or(&[0; 16]),
    );
    let lba = get!(b, gpt_header, partition_entry_lba);
    let count = get!(b, gpt_header, number_of_partition_entries);
    let esize = get!(b, gpt_header, size_of_partition_entry);
    let acrc = get!(b, gpt_header, partition_entry_array_crc32);
    if esize != ent || count == 0 || count > GPT_MAX_ENTRIES {
        return Err(E::PayloadGpt);
    }
    // The array's size in LBAs.
    let asec = (count * ent).div_ceil(k * SECTOR);
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
    if b.get(..width!(gpt_header, signature)) != Some(GPT_SIGNATURE)
        || get!(b, gpt_header, header_size) != hsize
        || header_crc(b, us(hsize)) != get!(b, gpt_header, header_crc32)
        || get!(b, gpt_header, my_lba) != alt
        || get!(b, gpt_header, alternate_lba) != 1
        || get!(b, gpt_header, first_usable_lba) != first_usable
        || get!(b, gpt_header, last_usable_lba) != last_usable
        || b.get(g..g + guid.len()) != Some(&guid[..])
        || get!(b, gpt_header, number_of_partition_entries) != count
        || get!(b, gpt_header, size_of_partition_entry) != esize
        || get!(b, gpt_header, partition_entry_array_crc32) != acrc
    {
        return Err(E::PayloadGptBackup);
    }
    let blba = get!(b, gpt_header, partition_entry_lba);
    if blba <= last_usable || blba >= alt || alt - blba < asec {
        return Err(E::PayloadGptBackup);
    }
    if array_crc(img, blba * k, count, b)? != acrc {
        return Err(E::PayloadGptBackup);
    }
    let (mut verified, mut stale) = (0u32, true);
    for i in 0..count {
        if i % per_sector == 0 || stale {
            img.read(lba * k + i / per_sector, b).map_err(|_| E::Io)?;
            stale = false;
        }
        let e = us((i % per_sector) * ent);
        let t = e + off!(gpt_entry, partition_type_guid);
        let ty = b.get(t..t + GPT_ESP_TYPE.len()).unwrap_or(&[]);
        if ty.iter().all(|&x| x == 0) {
            continue;
        }
        let esp = ty == GPT_ESP_TYPE;
        let first = get_at!(b, e, gpt_entry, starting_lba);
        let last = get_at!(b, e, gpt_entry, ending_lba);
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
        } else if len > EXT4_SB_SECTOR {
            img.read(first + EXT4_SB_SECTOR, b).map_err(|_| E::Io)?;
            if get!(b, ext4_super_block, s_magic) == EXT4_SUPER_MAGIC {
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
/// partition holds. (The BPB, shared by FAT12/16/32, is read through
/// `fat16_boot_sector`.)
fn is_fat(b: &[u8; 512], len: u64) -> bool {
    let (t16, t32) = (
        off!(fat16_boot_sector, fs_type),
        off!(fat32_boot_sector, fs_type),
    );
    let name = b.get(t16..t16 + FAT_FS_TYPE.len()) == Some(FAT_FS_TYPE)
        || b.get(t32..t32 + FAT32_FS_TYPE.len()) == Some(FAT32_FS_TYPE);
    let bps = get!(b, fat16_boot_sector, bytes_per_sector);
    let spc = get!(b, fat16_boot_sector, sectors_per_cluster);
    let mut total = get!(b, fat16_boot_sector, total_sectors_16);
    if total == 0 {
        total = get!(b, fat16_boot_sector, total_sectors_32);
    }
    get!(b, fat16_boot_sector, signature) == BOOT_SIGNATURE
        && name
        && matches!(bps, 512 | 1024 | 2048 | 4096)
        && spc.is_power_of_two()
        && total != 0
        && total * (bps / SECTOR) <= len
}

/// ext4 at sector `base` of the image, `len` sectors long; `b` holds sector
/// `base + 2` (the first half of the superblock), whose magic matched.
fn payload_ext4<D: Disk>(img: &mut D, base: u64, len: u64, b: &mut [u8; 512]) -> Result<()> {
    let log = get!(b, ext4_super_block, s_log_block_size);
    let first = get!(b, ext4_super_block, s_first_data_block);
    let per_group = get!(b, ext4_super_block, s_blocks_per_group);
    let dynamic = get!(b, ext4_super_block, s_rev_level) >= EXT4_DYNAMIC_REV;
    let (compat, incompat) = if dynamic {
        (
            get!(b, ext4_super_block, s_feature_compat),
            get!(b, ext4_super_block, s_feature_incompat),
        )
    } else {
        (0, 0)
    };
    let wide = incompat & EXT4_FEATURE_INCOMPAT_64BIT != 0;
    let blocks = |b: &[u8; 512]| {
        get!(b, ext4_super_block, s_blocks_count_lo)
            | if wide {
                get!(b, ext4_super_block, s_blocks_count_hi) << 32
            } else {
                0
            }
    };
    let count = blocks(b);
    // The primary names group 0: a backup copy where the primary belongs
    // (extents misordered) is refused. The superblock alone fills sectors
    // 2-3: `len` > 3 bounds the read of sector 3 below.
    if len < EXT4_SB_SECTOR + (size_of::<ext4_super_block>() as u64) / SECTOR
        || log > EXT4_MAX_LOG_BLOCK_SIZE
        || per_group == 0
        || first > 1
        || (log > 0 && first != 0)
        || get!(b, ext4_super_block, s_block_group_nr) != 0
    {
        return Err(E::PayloadExt4);
    }
    let per_block = 2u64 << log; // a block is 1 KiB << log: sectors
    if count == 0 || count > len / per_block {
        return Err(E::PayloadExt4);
    }
    // A single block group (blocks first..count all in group 0) has no
    // backup superblock: the root directory is checked instead.
    if count - first <= per_group {
        return payload_ext4_root(img, base, first, count, log, wide, dynamic, b);
    }
    let u = off!(ext4_super_block, s_uuid);
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(
        b.get(u..u + width!(ext4_super_block, s_uuid))
            .unwrap_or(&[0; 16]),
    );
    // COMPAT_SPARSE_SUPER2: backups only where s_backup_bgs[0] says; it is
    // in the superblock's second sector.
    let group = if compat & EXT4_FEATURE_COMPAT_SPARSE_SUPER2 != 0 {
        img.read(base + EXT4_SB_SECTOR + 1, b).map_err(|_| E::Io)?;
        get(b, off!(ext4_super_block, s_backup_bgs) - us(SECTOR), 4)
    } else {
        1
    };
    let block = first + per_group * group;
    if group == 0 || block >= count {
        return Err(E::PayloadExt4);
    }
    // A backup sits at the start of its group's first block.
    img.read(base + block * per_block, b).map_err(|_| E::Io)?;
    if get!(b, ext4_super_block, s_magic) != EXT4_SUPER_MAGIC
        || b.get(u..u + uuid.len()) != Some(&uuid[..])
        || blocks(b) != count
        || get!(b, ext4_super_block, s_block_group_nr) != group & 0xffff
    // a u16 field
    {
        return Err(E::PayloadExt4);
    }
    Ok(())
}

/// A single-group ext4 at `base`: the root directory (inode 2), found
/// through group 0's descriptor and the inode table, must be a directory
/// whose `i_block` starts with an extent header. `b` holds the superblock's
/// first sector; every read is below `count` blocks, which the caller
/// bounded by the partition.
#[allow(clippy::too_many_arguments)]
fn payload_ext4_root<D: Disk>(
    img: &mut D,
    base: u64,
    first: u64,
    count: u64,
    log: u64,
    wide: bool,
    dynamic: bool,
    b: &mut [u8; 512],
) -> Result<()> {
    let (bs, per_block) = (1024u64 << log, 2u64 << log);
    let isz = if dynamic {
        get!(b, ext4_super_block, s_inode_size)
    } else {
        EXT4_GOOD_OLD_INODE_SIZE
    };
    let dsz = if wide {
        get!(b, ext4_super_block, s_desc_size)
    } else {
        EXT4_MIN_DESC_SIZE
    };
    if !isz.is_power_of_two()
        || isz < EXT4_GOOD_OLD_INODE_SIZE
        || isz > bs
        || !dsz.is_power_of_two()
        || !(EXT4_MIN_DESC_SIZE..=EXT4_MAX_DESC_SIZE).contains(&dsz)
        || (wide && dsz < EXT4_MIN_DESC_SIZE_64BIT)
        || get!(b, ext4_super_block, s_inodes_per_group) < EXT4_ROOT_INO
    {
        return Err(E::PayloadExt4);
    }
    // The group descriptors follow the superblock's block.
    let gdt = first + 1;
    if gdt >= count {
        return Err(E::PayloadExt4);
    }
    img.read(base + gdt * per_block, b).map_err(|_| E::Io)?;
    let table = get!(b, ext4_group_desc, bg_inode_table_lo)
        | if wide {
            get!(b, ext4_group_desc, bg_inode_table_hi) << 32
        } else {
            0
        };
    if table == 0 || table >= count {
        return Err(E::PayloadExt4);
    }
    // Inode 2 is the second of group 0's table: isz bytes in.
    let sector = table * per_block + isz * (EXT4_ROOT_INO - 1) / SECTOR;
    if sector >= count * per_block {
        return Err(E::PayloadExt4);
    }
    img.read(base + sector, b).map_err(|_| E::Io)?;
    let o = us(isz * (EXT4_ROOT_INO - 1) % SECTOR); // 0, 128 or 256: in `b`
    if get_at!(b, o, ext4_inode, i_mode) & EXT4_S_IFMT != EXT4_S_IFDIR
        || get_at!(
            b,
            o + off!(ext4_inode, i_block),
            ext4_extent_header,
            eh_magic
        ) != EXT4_EXT_MAGIC
    {
        return Err(E::PayloadExt4);
    }
    Ok(())
}

/// `b` holds the primary volume descriptor (type 1, `CD001`).
fn payload_iso<D: Disk>(img: &mut D, sectors: u64, b: &mut [u8; 512]) -> Result<()> {
    // A big-endian integer of n bytes at `at` (the `_be` halves).
    let be = |b: &[u8; 512], at: usize, n: usize| {
        b.get(at..at + n)
            .map_or(0, |s| s.iter().fold(0u64, |a, &x| a << 8 | u64::from(x)))
    };
    let rd = off!(iso_primary_volume_descriptor, root_directory_record);
    let size = get!(b, iso_primary_volume_descriptor, volume_space_size_le);
    let bs = get!(b, iso_primary_volume_descriptor, logical_block_size_le);
    let dir = size_of::<iso_directory_record>() as u64;
    if get!(b, iso_primary_volume_descriptor, version) != ISO_VD_VERSION
        || be(
            b,
            off!(iso_primary_volume_descriptor, volume_space_size_be),
            width!(iso_primary_volume_descriptor, volume_space_size_be),
        ) != size
        || be(
            b,
            off!(iso_primary_volume_descriptor, logical_block_size_be),
            width!(iso_primary_volume_descriptor, logical_block_size_be),
        ) != bs
    {
        return Err(E::PayloadIso);
    }
    if !matches!(bs, 512 | 1024 | 2048) || size * (bs / SECTOR) != sectors {
        return Err(E::PayloadIso);
    }
    let root = get_at!(b, rd, iso_directory_record, extent_le);
    if get_at!(b, rd, iso_directory_record, length) != dir
        || be(
            b,
            rd + off!(iso_directory_record, extent_be),
            width!(iso_directory_record, extent_be),
        ) != root
        || get_at!(b, rd, iso_directory_record, file_flags) & ISO_FLAG_DIRECTORY == 0
        || root == 0
        || root >= size
    {
        return Err(E::PayloadIso);
    }
    img.read(root * (bs / SECTOR), b).map_err(|_| E::Io)?;
    // Its first record is ".": itself, a directory, named by one 0 byte.
    if get!(b, iso_directory_record, length) < dir
        || get!(b, iso_directory_record, extent_le) != root
        || get!(b, iso_directory_record, file_flags) & ISO_FLAG_DIRECTORY == 0
        || get!(b, iso_directory_record, name_length) != 1
        || get!(b, iso_directory_record, name) != 0
    {
        return Err(E::PayloadIso);
    }
    Ok(())
}
