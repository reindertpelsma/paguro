//! NTFS for the loader: names, not just extents (DESIGN.md §4.1 stage 4,
//! INTERFACES.md §3.2 and §13.4).
//!
//! The module's parse ([`super::file`]) starts from a file identity it is
//! given. The loader starts from a *path*, so it also walks directory
//! indexes: `$INDEX_ROOT` and `$INDEX_ALLOCATION` (`$I30`), a B+tree ordered
//! by the volume's own `$UpCase` table. It lists directories for the
//! recovery browser (bounded), reads a file's data wherever it lives
//! (resident, or by runlist at any offset), and reads `hiberfil.sys`'s
//! header for the safety gate.
//!
//! Same discipline as the parent module, whose record and attribute
//! validators this code reuses unchanged (so the C-parity paths are not
//! touched): every offset is checked before it is read, every count is
//! capped before it is used, all memory is the caller's ([`Scratch`]), and
//! anything unusual is a typed refusal, never a guess. Every walk is
//! bounded: a lookup visits at most [`MAX_DEPTH`] index blocks, a listing at
//! most [`MAX_INDEX_BLOCKS`], and index entries are at least 16 bytes each.
//!
//! What the loader needs from this module is *which record* a path names;
//! the record itself is then validated by the same code that validates any
//! record, so a corrupt index can at worst name the wrong (valid) file,
//! which the handoff's identity then carries to the module, which
//! re-derives everything itself.

use core::cmp::Ordering;

use super::layout::*;
use super::{
    ATTR_DATA, ATTR_LIST, E, MAX_ALIST, MAX_RECORD, Mft, NtfsError, SECTOR, Seg, attr_at, g16,
    load_list, read_record, sector_of, segment, us,
};
use super::{Disk, Volume};
use crate::runlist::Run;

/// The root directory's MFT record.
pub const ROOT_DIR: u64 = 5;
/// `$UpCase`'s MFT record.
pub const UPCASE_RECORD: u64 = 10;
/// UTF-16 code units in `$UpCase`: one per unit, the whole BMP.
pub const UPCASE_LEN: usize = 65536;
/// Largest index block accepted (NTFS writes 4 KiB).
pub const MAX_INDEX_BLOCK: usize = 65536;
/// Deepest B+tree walked by a lookup (index blocks visited per component).
pub const MAX_DEPTH: usize = 16;
/// Index blocks a directory may have (a listing reads at most this many).
pub const MAX_INDEX_BLOCKS: u64 = 1 << 16;
/// Runs of an index's allocation or bitmap.
pub const MAX_INDEX_RUNS: usize = 1024;
/// Longest name, in UTF-16 units.
pub const MAX_NAME: usize = 255;
/// Path components followed.
pub const MAX_COMPONENTS: usize = 32;

const ATTR_FILE_NAME: u64 = NTFS_AT_FILE_NAME;
const ATTR_INDEX_ROOT: u64 = NTFS_AT_INDEX_ROOT;
const ATTR_INDEX_ALLOCATION: u64 = NTFS_AT_INDEX_ALLOCATION;
const ATTR_BITMAP: u64 = NTFS_AT_BITMAP;
const COLLATION_FILE_NAME: u64 = NTFS_COLLATION_FILE_NAME;
const I30: [u16; 4] = [b'$' as u16, b'I' as u16, b'3' as u16, b'0' as u16];
/// `FILE_NAME` flags: a directory (its record carries an `$I30` index).
const FN_DIRECTORY: u64 = NTFS_FILE_ATTR_DUP_FILE_NAME_INDEX_PRESENT;
/// `FILE_NAME` flags: a reparse point (junction, symlink…): never followed.
const FN_REPARSE: u64 = NTFS_FILE_ATTR_REPARSE_POINT;
/// Index entry flags.
const IE_SUBNODE: u64 = NTFS_INDEX_ENTRY_NODE;
const IE_LAST: u64 = NTFS_INDEX_ENTRY_END;
/// `FILE_NAME` namespace of a DOS-only (8.3) alias.
pub const NAMESPACE_DOS: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DirError {
    /// A record, attribute or runlist refused by the parent module's checks.
    Ntfs(NtfsError),
    /// A path component is not in its directory.
    NotFound,
    /// A path's intermediate component, or a listed record, is not a
    /// directory.
    NotDirectory,
    /// The path names a directory where a file was expected.
    IsDirectory,
    /// A path component is a reparse point (junction, symbolic link).
    ReparsePoint,
    /// Not absolute, an empty, `.` or `..` component, too many components,
    /// or a component longer than [`MAX_NAME`] units.
    BadPath,
    /// No `$I30` `$INDEX_ROOT`, or one that is not a file-name index.
    IndexRoot,
    /// Index block size not a power of two in 512..=[`MAX_INDEX_BLOCK`].
    BlockSize,
    /// An entry points below the root but there is no usable
    /// `$INDEX_ALLOCATION`, or it is resident or mis-sized.
    IndexAllocation,
    /// An index block is outside the allocation, or not `INDX`.
    IndexBlock,
    /// An index block's update sequence does not match.
    IndexFixup,
    /// An index block records a VCN other than the one it was read for.
    IndexVcn,
    /// A node header or entry is out of shape or out of bounds.
    IndexEntry,
    /// A lookup went deeper than [`MAX_DEPTH`].
    TooDeep,
    /// A directory has more than [`MAX_INDEX_BLOCKS`] blocks.
    TooLarge,
    /// The `$I30` `$BITMAP` is missing or too short for the allocation.
    Bitmap,
    /// `$UpCase` is not 128 KiB, or does not upcase ASCII.
    Upcase,
    /// A read would go past the file's data.
    Range,
    /// A resident value does not fit the caller's buffer.
    BufferTooSmall,
}

impl From<NtfsError> for DirError {
    fn from(e: NtfsError) -> Self {
        DirError::Ntfs(e)
    }
}

type Result<T> = core::result::Result<T, DirError>;

/// A file's identity: MFT record number and sequence number.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileRef {
    pub record: u64,
    pub seq: u16,
}

impl FileRef {
    pub const ROOT: FileRef = FileRef {
        record: ROOT_DIR,
        seq: ROOT_DIR as u16,
    };
    fn from_raw(v: u64) -> FileRef {
        FileRef {
            record: v & NTFS_MFT_REF_RECORD_MASK,
            seq: (v >> NTFS_MFT_REF_SEQ_SHIFT) as u16,
        }
    }
}

/// One directory entry as the index stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub file: FileRef,
    /// As stored (UTF-16, not NUL-terminated).
    pub name: &'a [u16],
    pub namespace: u8,
    pub is_dir: bool,
    pub reparse: bool,
    /// The size the index caches (NTFS updates it lazily: display only).
    pub size: u64,
}

/// Memory for the walks: one record, one attribute list, one index root,
/// one index block, one runlist and one bitmap (~210 KiB).
pub struct Scratch {
    pub rec: [u8; MAX_RECORD],
    pub alist: [u8; MAX_ALIST],
    pub root: [u8; MAX_RECORD],
    pub block: [u8; MAX_INDEX_BLOCK],
    pub runs: [Run; MAX_INDEX_RUNS],
    pub bitmap: [u8; (MAX_INDEX_BLOCKS / 8) as usize],
    pub name: [u16; MAX_NAME],
}

impl Scratch {
    pub const fn new() -> Self {
        Scratch {
            rec: [0; MAX_RECORD],
            alist: [0; MAX_ALIST],
            root: [0; MAX_RECORD],
            block: [0; MAX_INDEX_BLOCK],
            runs: [Run { lcn: 0, count: 0 }; MAX_INDEX_RUNS],
            bitmap: [0; (MAX_INDEX_BLOCKS / 8) as usize],
            name: [0; MAX_NAME],
        }
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

// ---- attributes -------------------------------------------------------------

/// An attribute's value, as [`attribute`] found it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Value {
    /// Copied into the caller's byte buffer: this many bytes.
    Resident(usize),
    /// Mapped by this many runs of the caller's run buffer, covering
    /// exactly `alloc` bytes of which the first `size` are the value and the
    /// first `init` were ever written.
    NonResident {
        runs: usize,
        alloc: u64,
        size: u64,
        init: u64,
    },
}

/// What [`attribute`] learned about the record besides the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecordInfo {
    pub is_dir: bool,
    pub seq: u16,
}

fn name_at(b: &[u8], at: usize, len: usize, want: &[u16]) -> bool {
    len == want.len()
        && want
            .iter()
            .enumerate()
            .all(|(i, &u)| b.get(at + 2 * i..at + 2 * i + 2) == Some(&u.to_le_bytes()[..]))
}

/// The attribute `(ty, name)` at `pos` of a checked record?
fn attr_is(rec: &[u8], pos: usize, ty: u64, name: &[u16]) -> bool {
    // attr_at() checked the name lies inside the attribute.
    get_at!(rec, pos, ntfs_attr, r#type) == ty
        && name_at(
            rec,
            pos + us(get_at!(rec, pos, ntfs_attr, name_offset)),
            us(get_at!(rec, pos, ntfs_attr, name_length)),
            name,
        )
}

/// Offset of the attribute `(ty, name)` with this instance, if present.
fn find_instance(rec: &[u8], ty: u64, name: &[u16], instance: u64) -> Result<Option<usize>> {
    let mut pos = us(get!(rec, ntfs_file_record, attrs_offset));
    while let Some((t, len)) = attr_at(rec, pos)? {
        if t == ty
            && attr_is(rec, pos, ty, name)
            && get_at!(rec, pos, ntfs_attr, instance) == instance
        {
            return Ok(Some(pos));
        }
        pos += len;
    }
    Ok(None)
}

/// Copy the resident value at `pos` of a checked record into `out`.
fn resident(rec: &[u8], pos: usize, out: &mut [u8]) -> Result<usize> {
    let size = us(get_at!(rec, pos, ntfs_attr_resident, value_length));
    let voff = pos + us(get_at!(rec, pos, ntfs_attr_resident, value_offset));
    let src = rec.get(voff..voff + size).ok_or(E::AttrBounds)?;
    out.get_mut(..size)
        .ok_or(DirError::BufferTooSmall)?
        .copy_from_slice(src);
    Ok(size)
}

/// Record `recno` (sequence `seq`, or any when 0): its attribute `(ty, name)`,
/// wherever the attribute list puts its segments. `None` when absent.
///
/// A resident value is copied into `bytes`; a non-resident one's runs go to
/// `runs`, gathered segment by segment in VCN order with the parent module's
/// checks (no gap, inside the volume, not compressed, sparse or encrypted,
/// highest VCN consistent), and `alloc` equal to the runs' length.
#[allow(clippy::too_many_arguments)]
pub fn attribute<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    recno: u64,
    seq: u16,
    ty: u64,
    name: &[u16],
    recbuf: &mut [u8; MAX_RECORD],
    alist: &mut [u8; MAX_ALIST],
    bytes: &mut [u8],
    runs: &mut [Run],
) -> Result<(Option<Value>, RecordInfo)> {
    let vol = &mft.vol;
    let rec = read_record(disk, vol, mft.runs, mft.bytes, recno, recbuf)?;
    let flags = get!(rec, ntfs_file_record, flags);
    if flags & NTFS_RECORD_IN_USE == 0 {
        return Err(E::NotInUse.into());
    }
    let own_seq = get!(rec, ntfs_file_record, sequence_number);
    if seq != 0 && own_seq != u64::from(seq) {
        return Err(E::Sequence.into());
    }
    if get!(rec, ntfs_file_record, base_mft_record) != 0 {
        return Err(E::NotBase.into());
    }
    let info = RecordInfo {
        is_dir: flags & NTFS_RECORD_IS_DIRECTORY != 0,
        seq: own_seq as u16,
    };
    let (mut list, mut found, mut n) = (None, 0usize, 0u32);
    let mut pos = us(get!(rec, ntfs_file_record, attrs_offset));
    while let Some((t, len)) = attr_at(rec, pos)? {
        if t == ATTR_LIST {
            if list.is_some() {
                return Err(E::AttrList.into());
            }
            list = Some(pos);
        } else if attr_is(rec, pos, ty, name) {
            if n == 0 {
                found = pos;
            }
            n += 1;
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
        None => match n {
            0 => return Ok((None, info)),
            1 if get_at!(rec, found, ntfs_attr, non_resident) == 0 => {
                return Ok((Some(Value::Resident(resident(rec, found, bytes)?)), info));
            }
            1 => segment(vol, rec, found, &mut st, runs)?,
            _ => return Err(E::DuplicateData.into()),
        },
        Some(lp) => {
            // The list's own runs need scratch of their own: `runs` may be empty.
            let mut lruns = [Run { lcn: 0, count: 0 }; 64];
            let size = load_list(disk, vol, rec, lp, alist, &mut lruns)?;
            let base_ref = recno | own_seq << NTFS_MFT_REF_SEQ_SHIFT;
            let entry = size_of::<ntfs_attr_list_entry>();
            let mut p = 0usize;
            let mut segments = 0u32;
            while p < size {
                if p + entry > size {
                    return Err(E::AttrList.into());
                }
                let elen = us(get_at!(&*alist, p, ntfs_attr_list_entry, length));
                if elen < entry || elen > size - p {
                    return Err(E::AttrList.into());
                }
                let nlen = us(get_at!(&*alist, p, ntfs_attr_list_entry, name_length));
                let noff = us(get_at!(&*alist, p, ntfs_attr_list_entry, name_offset));
                if nlen > 0 && noff + 2 * nlen > elen {
                    return Err(E::AttrList.into());
                }
                if get_at!(&*alist, p, ntfs_attr_list_entry, r#type) == ty
                    && name_at(&*alist, p + noff, nlen, name)
                {
                    segments += 1;
                    if segments > super::MAX_EXTENSIONS + 1 {
                        return Err(E::TooManyExtensions.into());
                    }
                    let mref = get_at!(&*alist, p, ntfs_attr_list_entry, mft_reference);
                    let r = mref & NTFS_MFT_REF_RECORD_MASK;
                    let rseq = mref >> NTFS_MFT_REF_SEQ_SHIFT;
                    let lowest = get_at!(&*alist, p, ntfs_attr_list_entry, lowest_vcn);
                    let instance = get_at!(&*alist, p, ntfs_attr_list_entry, instance);
                    let rec = read_record(disk, vol, mft.runs, mft.bytes, r, recbuf)?;
                    if get!(rec, ntfs_file_record, flags) & NTFS_RECORD_IN_USE == 0 {
                        return Err(E::NotInUse.into());
                    }
                    if get!(rec, ntfs_file_record, sequence_number) != rseq {
                        return Err(E::Sequence.into());
                    }
                    if get!(rec, ntfs_file_record, base_mft_record)
                        != if r == recno { 0 } else { base_ref }
                    {
                        return Err(E::ExtensionBase.into());
                    }
                    let at = find_instance(rec, ty, name, instance)?.ok_or(E::MissingSegment)?;
                    if get_at!(rec, at, ntfs_attr, non_resident) == 0 {
                        // A resident value is a single segment at VCN 0.
                        if segments != 1 || lowest != 0 {
                            return Err(E::AttrList.into());
                        }
                        let len = resident(rec, at, bytes)?;
                        // Nothing else may follow for this attribute.
                        let mut q = p + elen;
                        while q + entry <= size {
                            let el = us(get_at!(&*alist, q, ntfs_attr_list_entry, length));
                            if el < entry || el > size - q {
                                return Err(E::AttrList.into());
                            }
                            let nl = us(get_at!(&*alist, q, ntfs_attr_list_entry, name_length));
                            let no = us(get_at!(&*alist, q, ntfs_attr_list_entry, name_offset));
                            if get_at!(&*alist, q, ntfs_attr_list_entry, r#type) == ty
                                && name_at(&*alist, q + no, nl, name)
                            {
                                return Err(E::AttrList.into());
                            }
                            q += el;
                        }
                        return Ok((Some(Value::Resident(len)), info));
                    }
                    if lowest != st.vcn {
                        return Err(E::Gap.into());
                    }
                    segment(vol, rec, at, &mut st, runs)?;
                }
                p += elen;
            }
            if segments == 0 {
                return Ok((None, info));
            }
        }
    }
    let alloc = st.vcn.checked_mul(vol.cluster_bytes);
    if alloc != Some(st.alloc) || st.size > st.alloc || st.init > st.size {
        return Err(E::AllocatedSize.into());
    }
    Ok((
        Some(Value::NonResident {
            runs: st.n,
            alloc: st.alloc,
            size: st.size,
            init: st.init,
        }),
        info,
    ))
}

/// Read `buf.len()` bytes at byte `off` of an attribute mapped by `runs`
/// (whose first `limit` bytes are readable).
pub fn read_runs<D: Disk>(
    disk: &mut D,
    vol: &Volume,
    runs: &[Run],
    limit: u64,
    off: u64,
    buf: &mut [u8],
) -> Result<()> {
    let end = off.checked_add(buf.len() as u64).ok_or(DirError::Range)?;
    if end > limit {
        return Err(DirError::Range);
    }
    let mut sector = [0u8; 512];
    let mut done = 0usize;
    while done < buf.len() {
        let at = off + done as u64;
        let s = sector_of(vol, runs, at).ok_or(DirError::Range)?;
        disk.read(s, &mut sector).map_err(|_| E::Io)?;
        let within = us(at % SECTOR);
        let n = (512 - within).min(buf.len() - done);
        let src = sector.get(within..within + n).ok_or(DirError::Range)?;
        buf.get_mut(done..done + n)
            .ok_or(DirError::Range)?
            .copy_from_slice(src);
        done += n;
    }
    Ok(())
}

// ---- $UpCase --------------------------------------------------------------

/// Load `$UpCase` into `table`. It must be exactly 128 KiB, non-resident,
/// and map ASCII `a..=z` to `A..=Z` (a sanity check that the table is the
/// volume's collation and not garbage).
pub fn load_upcase<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    s: &mut Scratch,
    table: &mut [u16; UPCASE_LEN],
) -> Result<()> {
    let mut runs = [Run { lcn: 0, count: 0 }; 64];
    let (v, _) = attribute(
        disk,
        mft,
        UPCASE_RECORD,
        0,
        ATTR_DATA,
        &[],
        &mut s.rec,
        &mut s.alist,
        &mut [],
        &mut runs,
    )
    .map_err(|e| match e {
        DirError::BufferTooSmall => DirError::Upcase,
        e => e,
    })?;
    let Some(Value::NonResident {
        runs: n,
        size,
        init,
        ..
    }) = v
    else {
        return Err(DirError::Upcase);
    };
    if size != 2 * UPCASE_LEN as u64 || init != size {
        return Err(DirError::Upcase);
    }
    let runs = runs.get(..n).unwrap_or(&[]);
    let mut chunk = [0u8; 512];
    for (i, dst) in table.chunks_exact_mut(256).enumerate() {
        read_runs(disk, &mft.vol, runs, size, i as u64 * 512, &mut chunk)?;
        for (d, s) in dst.iter_mut().zip(chunk.chunks_exact(2)) {
            *d = u16::from_le_bytes([
                s.first().copied().unwrap_or(0),
                s.get(1).copied().unwrap_or(0),
            ]);
        }
    }
    let ascii_ok = (u16::from(b'a')..=u16::from(b'z'))
        .all(|c| table.get(usize::from(c)).copied() == Some(c - 32))
        && table.get(usize::from(b'A')).copied() == Some(u16::from(b'A'));
    if !ascii_ok {
        return Err(DirError::Upcase);
    }
    Ok(())
}

/// NTFS file-name collation: upcased code units, then length.
pub fn collate(up: &[u16; UPCASE_LEN], a: &[u16], b: &[u16]) -> Ordering {
    let u = |c: u16| up.get(usize::from(c)).copied().unwrap_or(c);
    for (x, y) in a.iter().zip(b.iter()) {
        match u(*x).cmp(&u(*y)) {
            Ordering::Equal => {}
            o => return o,
        }
    }
    a.len().cmp(&b.len())
}

// ---- index nodes ------------------------------------------------------------

/// One parsed index entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IndexEntry<'a> {
    /// `None` for the terminating entry, which carries no key.
    pub key: Option<Entry<'a>>,
    /// The child block's VCN, when the entry has a subnode.
    pub child: Option<u64>,
}

/// Walk the entries of a node: `node` is the region from the node header's
/// first entry to its index length. Calls `f` for every entry, in order,
/// until it returns `false`; the region must end with a terminating entry
/// (checked up to the point `f` stops). Entries are at least 16 bytes, so
/// the walk is bounded by the node's size.
pub fn node_entries(node: &[u8], mut f: impl FnMut(&IndexEntry<'_>) -> Result<bool>) -> Result<()> {
    let mut name = [0u16; MAX_NAME];
    let mut pos = 0usize;
    let head = size_of::<ntfs_index_entry>();
    let (key_head, vcn) = (size_of::<ntfs_file_name>(), size_of::<u64>());
    loop {
        if node.len() < head || pos > node.len() - head {
            return Err(DirError::IndexEntry);
        }
        let len = us(get_at!(node, pos, ntfs_index_entry, length));
        let key_len = us(get_at!(node, pos, ntfs_index_entry, key_length));
        let flags = get_at!(node, pos, ntfs_index_entry, flags);
        // Entries are 8-byte aligned.
        if len < head || len % 8 != 0 || len > node.len() - pos {
            return Err(DirError::IndexEntry);
        }
        // A subnode's VCN is the entry's last 8 bytes.
        let child = if flags & IE_SUBNODE != 0 {
            if len < head + vcn {
                return Err(DirError::IndexEntry);
            }
            Some(super::get(node, pos + len - vcn, vcn))
        } else {
            None
        };
        let last = flags & IE_LAST != 0;
        let mut n = 0usize;
        let key = if last {
            None
        } else {
            let room = len - head - if child.is_some() { vcn } else { 0 };
            if key_len < key_head || key_len > room {
                return Err(DirError::IndexEntry);
            }
            // The key: a $FILE_NAME, its UTF-16 name after the header.
            let k = pos + head;
            n = us(get_at!(node, k, ntfs_file_name, file_name_length));
            if n == 0 || key_head + 2 * n > key_len {
                return Err(DirError::IndexEntry);
            }
            let raw = node
                .get(k + key_head..k + key_head + 2 * n)
                .ok_or(DirError::IndexEntry)?;
            for (d, s) in name.iter_mut().zip(raw.chunks_exact(2)) {
                *d = u16::from_le_bytes([
                    s.first().copied().unwrap_or(0),
                    s.get(1).copied().unwrap_or(0),
                ]);
            }
            let fl = get_at!(node, k, ntfs_file_name, file_attributes);
            Some((
                FileRef::from_raw(get_at!(node, pos, ntfs_index_entry, indexed_file)),
                get_at!(node, k, ntfs_file_name, file_name_type) as u8,
                fl,
                get_at!(node, k, ntfs_file_name, data_size),
            ))
        };
        let e = IndexEntry {
            key: key.map(|(file, namespace, fl, size)| Entry {
                file,
                name: name.get(..n).unwrap_or(&[]),
                namespace,
                is_dir: fl & FN_DIRECTORY != 0,
                reparse: fl & FN_REPARSE != 0,
                size,
            }),
            child,
        };
        if !f(&e)? || last {
            return Ok(());
        }
        pos += len;
    }
}

/// A node header at `at` of `buf` (the node may use bytes up to `limit`):
/// the entry region's bounds, and whether entries have children.
fn node_region(buf: &[u8], at: usize, limit: usize) -> Result<(usize, usize, bool)> {
    let head = size_of::<ntfs_index_header>();
    if limit > buf.len() || at > limit || limit - at < head {
        return Err(DirError::IndexEntry);
    }
    let first = us(get_at!(buf, at, ntfs_index_header, entries_offset));
    let len = us(get_at!(buf, at, ntfs_index_header, index_length));
    let alloc = us(get_at!(buf, at, ntfs_index_header, allocated_size));
    let large = get_at!(buf, at, ntfs_index_header, flags) & NTFS_INDEX_LARGE != 0;
    if first < head || first % 8 != 0 || len < first || len > alloc || alloc > limit - at {
        return Err(DirError::IndexEntry);
    }
    Ok((at + first, at + len, large))
}

/// A directory's index, ready to walk: its root (copied into
/// [`Scratch::root`]) and, if it has one, its allocation's runs (in
/// [`Scratch::runs`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Index {
    pub dir: FileRef,
    root_len: usize,
    pub block_size: usize,
    /// Bytes per VCN of the allocation: the cluster, or 512 for blocks
    /// smaller than a cluster.
    vcn_bytes: u64,
    /// Bytes of `$INDEX_ALLOCATION` (0 = none), mapped by `runs` runs.
    alloc: u64,
    runs: usize,
}

/// Open directory `dir`'s `$I30` index. Refuses a record that is not a
/// directory.
pub fn open_index<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    dir: FileRef,
    s: &mut Scratch,
) -> Result<Index> {
    let (v, info) = attribute(
        disk,
        mft,
        dir.record,
        dir.seq,
        ATTR_INDEX_ROOT,
        &I30,
        &mut s.rec,
        &mut s.alist,
        &mut s.root,
        &mut [],
    )
    .map_err(|e| match e {
        // Non-resident, or larger than a record: malformed.
        DirError::Ntfs(NtfsError::Runlist(_)) | DirError::BufferTooSmall => DirError::IndexRoot,
        e => e,
    })?;
    if !info.is_dir {
        return Err(DirError::NotDirectory);
    }
    let Some(Value::Resident(root_len)) = v else {
        return Err(DirError::IndexRoot);
    };
    let r = s.root.get(..root_len).ok_or(DirError::IndexRoot)?;
    if r.len() < size_of::<ntfs_index_root>()
        || get!(r, ntfs_index_root, r#type) != ATTR_FILE_NAME
        || get!(r, ntfs_index_root, collation_rule) != COLLATION_FILE_NAME
    {
        return Err(DirError::IndexRoot);
    }
    let block_size = us(get!(r, ntfs_index_root, index_block_size));
    if !block_size.is_power_of_two() || !(512..=MAX_INDEX_BLOCK).contains(&block_size) {
        return Err(DirError::BlockSize);
    }
    let vcn_bytes = if block_size as u64 >= mft.vol.cluster_bytes {
        mft.vol.cluster_bytes
    } else {
        SECTOR
    };
    let (_, _, large) = node_region(r, off!(ntfs_index_root, index), r.len())?;
    let mut idx = Index {
        dir,
        root_len,
        block_size,
        vcn_bytes,
        alloc: 0,
        runs: 0,
    };
    if large {
        let (v, _) = attribute(
            disk,
            mft,
            dir.record,
            dir.seq,
            ATTR_INDEX_ALLOCATION,
            &I30,
            &mut s.rec,
            &mut s.alist,
            &mut [],
            &mut s.runs,
        )
        .map_err(|e| match e {
            DirError::BufferTooSmall => DirError::IndexAllocation,
            e => e,
        })?;
        let Some(Value::NonResident { runs, size, .. }) = v else {
            return Err(DirError::IndexAllocation);
        };
        if size == 0 || size % block_size as u64 != 0 {
            return Err(DirError::IndexAllocation);
        }
        if size / block_size as u64 > MAX_INDEX_BLOCKS {
            return Err(DirError::TooLarge);
        }
        idx.alloc = size;
        idx.runs = runs;
    }
    Ok(idx)
}

/// Read index block `vcn` into [`Scratch::block`], apply its fixups and check
/// its header. Returns the entry region's bounds within the block.
fn read_block<D: Disk>(
    disk: &mut D,
    vol: &Volume,
    idx: &Index,
    vcn: u64,
    s: &mut Scratch,
) -> Result<(usize, usize)> {
    let bs = idx.block_size;
    if idx.alloc == 0 {
        return Err(DirError::IndexAllocation);
    }
    let off = vcn.checked_mul(idx.vcn_bytes).ok_or(DirError::IndexBlock)?;
    if off % bs as u64 != 0 || off > idx.alloc || idx.alloc - off < bs as u64 {
        return Err(DirError::IndexBlock);
    }
    let runs = s.runs.get(..idx.runs).unwrap_or(&[]);
    let blk = s.block.get_mut(..bs).ok_or(DirError::BlockSize)?;
    read_runs(disk, vol, runs, idx.alloc, off, blk)?;
    if blk.get(..width!(ntfs_index_block, magic)) != Some(NTFS_INDEX_MAGIC) {
        return Err(DirError::IndexBlock);
    }
    let usa = us(get!(blk, ntfs_index_block, usa_offset));
    let count = us(get!(blk, ntfs_index_block, usa_count));
    // One update-sequence entry (u16) per 512 bytes, plus the USN itself.
    if count != bs / us(SECTOR) + 1
        || usa < size_of::<ntfs_index_block>()
        || usa % 2 != 0
        || usa + 2 * count > bs
    {
        return Err(DirError::IndexFixup);
    }
    let usn = g16(blk, usa);
    for i in 1..count {
        let at = i * us(SECTOR) - 2;
        if g16(blk, at) != usn {
            return Err(DirError::IndexFixup);
        }
        let fix = g16(blk, usa + 2 * i).to_le_bytes();
        if let (Some(d), Some(f)) = (blk.get_mut(at..at + 2), fix.get(..2)) {
            d.copy_from_slice(f);
        }
    }
    if get!(blk, ntfs_index_block, index_block_vcn) != vcn {
        return Err(DirError::IndexVcn);
    }
    let (a, b, _) = node_region(blk, off!(ntfs_index_block, index), bs)?;
    // The entries must not overlap the update sequence array.
    if a < usa + 2 * count {
        return Err(DirError::IndexEntry);
    }
    Ok((a, b))
}

/// Find `name` in directory index `idx` (case-insensitively, by the
/// volume's collation). Any namespace matches, as on Windows. Returns the
/// entry's file, and its cached directory and reparse flags.
pub fn lookup<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    up: &[u16; UPCASE_LEN],
    idx: &Index,
    name: &[u16],
    s: &mut Scratch,
) -> Result<Option<Hit>> {
    let (a, b, _) = node_region(&s.root, off!(ntfs_index_root, index), idx.root_len)?;
    let mut next = None;
    let mut found = None;
    walk_node(
        s.root.get(a..b).ok_or(DirError::IndexEntry)?,
        up,
        name,
        &mut found,
        &mut next,
    )?;
    let mut depth = 0usize;
    while found.is_none() {
        let Some(vcn) = next.take() else {
            return Ok(None);
        };
        depth += 1;
        if depth > MAX_DEPTH {
            return Err(DirError::TooDeep);
        }
        let (a, b) = read_block(disk, &mft.vol, idx, vcn, s)?;
        walk_node(
            s.block.get(a..b).ok_or(DirError::IndexEntry)?,
            up,
            name,
            &mut found,
            &mut next,
        )?;
    }
    Ok(found)
}

/// A lookup's match.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hit {
    pub file: FileRef,
    pub is_dir: bool,
    pub reparse: bool,
}

/// One node of a lookup: the match, or the child to descend into.
fn walk_node(
    region: &[u8],
    up: &[u16; UPCASE_LEN],
    name: &[u16],
    found: &mut Option<Hit>,
    next: &mut Option<u64>,
) -> Result<()> {
    node_entries(region, |e| match e.key {
        Some(k) => match collate(up, name, k.name) {
            Ordering::Equal => {
                *found = Some(Hit {
                    file: k.file,
                    is_dir: k.is_dir,
                    reparse: k.reparse,
                });
                Ok(false)
            }
            Ordering::Less => {
                *next = e.child;
                Ok(false)
            }
            Ordering::Greater => Ok(true),
        },
        None => {
            *next = e.child;
            Ok(false)
        }
    })
}

/// Every entry of directory index `idx`, root first, then each index
/// block the `$I30` bitmap marks in use (in VCN order, not name order),
/// until `f` returns `false`. DOS-only aliases are skipped.
pub fn list<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    idx: &Index,
    s: &mut Scratch,
    mut f: impl FnMut(&Entry<'_>) -> bool,
) -> Result<()> {
    let mut go = true;
    let (a, b, _) = node_region(&s.root, off!(ntfs_index_root, index), idx.root_len)?;
    node_entries(s.root.get(a..b).ok_or(DirError::IndexEntry)?, |e| {
        Ok(feed(e, &mut f, &mut go))
    })?;
    if !go || idx.alloc == 0 {
        return Ok(());
    }
    // The bitmap: which blocks are in use (free ones hold stale entries).
    let blocks = idx.alloc / idx.block_size as u64;
    let need = us(blocks.div_ceil(8));
    let mut bruns = [Run { lcn: 0, count: 0 }; 64];
    let (v, _) = attribute(
        disk,
        mft,
        idx.dir.record,
        idx.dir.seq,
        ATTR_BITMAP,
        &I30,
        &mut s.rec,
        &mut s.alist,
        &mut s.bitmap,
        &mut bruns,
    )
    .map_err(|e| match e {
        DirError::BufferTooSmall => DirError::Bitmap,
        e => e,
    })?;
    let have = match v {
        Some(Value::Resident(n)) => n,
        Some(Value::NonResident {
            runs, size, init, ..
        }) => {
            let n = us(size.min(init)).min(need);
            let r = bruns.get(..runs).unwrap_or(&[]);
            read_runs(
                disk,
                &mft.vol,
                r,
                size,
                0,
                s.bitmap.get_mut(..n).unwrap_or(&mut []),
            )?;
            n
        }
        None => return Err(DirError::Bitmap),
    };
    if have < need {
        return Err(DirError::Bitmap);
    }
    for i in 0..blocks {
        let byte = s.bitmap.get(us(i / 8)).copied().unwrap_or(0);
        if (byte >> (i % 8)) & 1 == 0 {
            continue;
        }
        let vcn = i * idx.block_size as u64 / idx.vcn_bytes;
        let (a, b) = read_block(disk, &mft.vol, idx, vcn, s)?;
        node_entries(s.block.get(a..b).ok_or(DirError::IndexEntry)?, |e| {
            Ok(feed(e, &mut f, &mut go))
        })?;
        if !go {
            break;
        }
    }
    Ok(())
}

fn feed(e: &IndexEntry<'_>, f: &mut impl FnMut(&Entry<'_>) -> bool, go: &mut bool) -> bool {
    if let Some(k) = e.key {
        if k.namespace != NAMESPACE_DOS {
            *go = f(&k);
        }
    }
    *go
}

// ---- paths ----------------------------------------------------------------

/// What a path names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub file: FileRef,
    pub is_dir: bool,
}

/// Resolve absolute path `path` (`\` separators; `\` alone is the root) from
/// the root directory. Every component but the last must be a directory;
/// reparse points are never followed; each step's record must be in use
/// with the sequence number its index entry names.
pub fn resolve<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    up: &[u16; UPCASE_LEN],
    path: &str,
    s: &mut Scratch,
) -> Result<Found> {
    let rest = path.strip_prefix('\\').ok_or(DirError::BadPath)?;
    let rest = rest.strip_suffix('\\').unwrap_or(rest);
    let mut cur = Found {
        file: FileRef::ROOT,
        is_dir: true,
    };
    if rest.is_empty() {
        return Ok(cur);
    }
    // The whole path is checked before anything is read.
    for (i, comp) in rest.split('\\').enumerate() {
        if i >= MAX_COMPONENTS
            || comp.is_empty()
            || comp == "."
            || comp == ".."
            || comp.encode_utf16().count() > MAX_NAME
        {
            return Err(DirError::BadPath);
        }
    }
    for comp in rest.split('\\') {
        let mut name = [0u16; MAX_NAME];
        let mut n = 0usize;
        for u in comp.encode_utf16() {
            *name.get_mut(n).ok_or(DirError::BadPath)? = u;
            n += 1;
        }
        if !cur.is_dir {
            return Err(DirError::NotDirectory);
        }
        let idx = open_index(disk, mft, cur.file, s)?;
        let hit = lookup(disk, mft, up, &idx, name.get(..n).unwrap_or(&[]), s)?
            .ok_or(DirError::NotFound)?;
        let file = hit.file;
        if hit.reparse {
            return Err(DirError::ReparsePoint);
        }
        // The record decides what it is, not the index's cached flags.
        let rec = read_record(disk, &mft.vol, mft.runs, mft.bytes, file.record, &mut s.rec)?;
        let flags = get!(rec, ntfs_file_record, flags);
        if flags & NTFS_RECORD_IN_USE == 0 {
            return Err(E::NotInUse.into());
        }
        if get!(rec, ntfs_file_record, sequence_number) != u64::from(file.seq) {
            return Err(E::Sequence.into());
        }
        if get!(rec, ntfs_file_record, base_mft_record) != 0 {
            return Err(E::NotBase.into());
        }
        cur = Found {
            file,
            is_dir: flags & NTFS_RECORD_IS_DIRECTORY != 0,
        };
    }
    Ok(cur)
}

// ---- file data ------------------------------------------------------------

/// A file's unnamed `$DATA`, for reading (not for claiming: the module's
/// stricter [`super::file`] is what validates a disk image's map).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Data {
    /// Copied into the caller's buffer: this many bytes.
    Resident(usize),
    /// `runs` runs of the caller's buffer; `size` bytes, all initialised.
    Runs { runs: usize, size: u64 },
}

/// Open file `file`'s unnamed `$DATA` for reading. Refuses directories,
/// compressed, sparse and encrypted data, and a valid-data length short of
/// the size (bytes past it would be stale disk).
pub fn data<D: Disk>(
    disk: &mut D,
    mft: &Mft<'_>,
    file: FileRef,
    s: &mut Scratch,
    resident_buf: &mut [u8],
    runs: &mut [Run],
) -> Result<Data> {
    let (v, info) = attribute(
        disk,
        mft,
        file.record,
        file.seq,
        ATTR_DATA,
        &[],
        &mut s.rec,
        &mut s.alist,
        resident_buf,
        runs,
    )?;
    if info.is_dir {
        return Err(DirError::IsDirectory);
    }
    match v {
        None => Err(E::NoData.into()),
        Some(Value::Resident(n)) => Ok(Data::Resident(n)),
        Some(Value::NonResident {
            runs, size, init, ..
        }) => {
            if init != size {
                return Err(E::NotInitialized.into());
            }
            Ok(Data::Runs { runs, size })
        }
    }
}

/// `hiberfil.sys`'s first bytes say an image is waiting to be resumed:
/// `hibr`/`HIBR` (hibernated, including Fast Startup) or `rstr`/`RSTR`
/// (a resume in progress). `wake`, zeroes and anything else mean the file
/// is kept for next time but holds nothing (DESIGN.md §4.1: existence alone
/// means nothing).
pub fn hibernation_active(header: &[u8]) -> bool {
    matches!(header.get(..4), Some(b"hibr" | b"HIBR" | b"rstr" | b"RSTR"))
}
