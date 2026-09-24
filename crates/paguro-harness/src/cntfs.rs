//! The kernel module's C NTFS core (`pg_ntfs.c`, `pg_claim.c`) and the Rust
//! specification (`paguro_core::ntfs`), behind one interface, so every input
//! can be run through both and compared: results, errors, and the exact
//! sequence of sectors each one reads.

use std::ffi::{c_int, c_void};

use paguro_core::ntfs::{self, Disk, IoError, MAX_ALIST, MAX_EXTENTS, NtfsError};
use paguro_core::range::Extent;
use paguro_core::runlist::{Run, RunlistError};

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PgRun {
    pub lcn: u64,
    pub count: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
pub struct PgExtent {
    pub start: u64,
    pub end: u64,
}

type ReadFn = unsafe extern "C" fn(*mut c_void, u64, *mut u8) -> c_int;

#[repr(C)]
struct PgNtfs {
    read: Option<ReadFn>,
    ctx: *mut c_void,
    rec: *mut u8,
    alist: *mut u8,
    mft: *mut PgRun,
    mft_cap: usize,
    sectors: u64,
    clusters: u64,
    cluster_bytes: u64,
    record_bytes: u64,
    mft_lcn: u64,
    nmft: usize,
    mft_bytes: u64,
}

unsafe extern "C" {
    fn pg_ntfs_open(v: *mut PgNtfs) -> c_int;
    fn pg_ntfs_file(
        v: *mut PgNtfs,
        rec: u64,
        seq: u16,
        runs: *mut PgRun,
        cap: usize,
        nruns: *mut usize,
        size: *mut u64,
    ) -> c_int;
    fn pg_ntfs_extents(
        v: *const PgNtfs,
        runs: *const PgRun,
        n: usize,
        out: *mut PgExtent,
        cap: usize,
        nout: *mut usize,
    ) -> c_int;
    fn pg_ntfs_volume_flags(v: *mut PgNtfs, flags: *mut u16) -> c_int;
    fn pg_payload_check(read: ReadFn, ctx: *mut c_void, sectors: u64, buf: *mut u8) -> c_int;
    fn pg_runlist_decode(
        input: *const u8,
        len: usize,
        out: *mut PgRun,
        cap: usize,
        n: *mut usize,
    ) -> c_int;
    fn pg_claim_normalise(
        file: *const PgExtent,
        n: usize,
        out: *mut PgExtent,
        cap: usize,
        nout: *mut usize,
    ) -> c_int;
    fn pg_claim_intersects(a: *const PgExtent, na: usize, b: *const PgExtent, nb: usize) -> c_int;
    fn pg_claim_grows(
        old: *const PgExtent,
        nold: usize,
        new: *const PgExtent,
        nnew: usize,
    ) -> c_int;
    fn pg_claim_coalesce(e: *mut PgExtent, n: usize) -> usize;
    fn pg_claim_gather(file: *const PgExtent, n: usize, lsec: u64, phys: *mut u64) -> u64;
    fn pg_range_normalise(e: *mut PgExtent, n: usize) -> usize;
}

/// Adapts any `Disk` to the C read callback.
unsafe extern "C" fn trampoline(ctx: *mut c_void, sector: u64, buf: *mut u8) -> c_int {
    // SAFETY: `ctx` is the `&mut &mut dyn Disk` built in `with_disk`, alive for
    // the whole C call; `buf` is 512 writable bytes per the pg_read_fn contract.
    let disk = unsafe { &mut *ctx.cast::<&mut dyn Disk>() };
    let buf = unsafe { &mut *buf.cast::<[u8; 512]>() };
    c_int::from(disk.read(sector, buf).is_err())
}

fn with_disk<T>(disk: &mut dyn Disk, f: impl FnOnce(*mut c_void) -> T) -> T {
    let mut d: &mut dyn Disk = disk;
    f((&raw mut d).cast())
}

/// A file's derivation, as both implementations report it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Derived {
    pub extents: Vec<Extent>,
    pub size: u64,
}

/// `Err` carries the `PG_E_*` / `NtfsError::code` value.
pub type Out = Result<Derived, i32>;

pub fn rust_file<D: Disk>(d: &mut D, rec: u64, seq: u16) -> Out {
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut mft = vec![Run { lcn: 0, count: 0 }; 2048];
    let m = ntfs::open(d, &mut alist, &mut mft).map_err(NtfsError::code)?;
    let mut runs = vec![Run { lcn: 0, count: 0 }; MAX_EXTENTS];
    let f = ntfs::file(d, &m, rec, seq, &mut alist, &mut runs).map_err(NtfsError::code)?;
    let mut ext = vec![Extent { start: 0, end: 0 }; MAX_EXTENTS];
    let n = ntfs::extents(&m.vol, runs.get(..f.runs).unwrap_or(&[]), &mut ext)
        .map_err(NtfsError::code)?;
    ext.truncate(n);
    Ok(Derived {
        extents: ext,
        size: f.data_size,
    })
}

pub fn rust_flags<D: Disk>(d: &mut D) -> Result<u16, i32> {
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut mft = vec![Run { lcn: 0, count: 0 }; 2048];
    let m = ntfs::open(d, &mut alist, &mut mft).map_err(NtfsError::code)?;
    ntfs::volume_flags(d, &m).map_err(NtfsError::code)
}

/// Buffers for one C parse, laid out as the kernel glue allocates them.
struct CState {
    rec: Vec<u8>,
    alist: Vec<u8>,
    mft: Vec<PgRun>,
}

impl CState {
    fn new() -> CState {
        CState {
            rec: vec![0; 4096],
            alist: vec![0; MAX_ALIST],
            mft: vec![PgRun::default(); 2048],
        }
    }

    fn vol(&mut self, ctx: *mut c_void) -> PgNtfs {
        PgNtfs {
            read: Some(trampoline),
            ctx,
            rec: self.rec.as_mut_ptr(),
            alist: self.alist.as_mut_ptr(),
            mft: self.mft.as_mut_ptr(),
            mft_cap: self.mft.len(),
            sectors: 0,
            clusters: 0,
            cluster_bytes: 0,
            record_bytes: 0,
            mft_lcn: 0,
            nmft: 0,
            mft_bytes: 0,
        }
    }
}

pub fn c_file(disk: &mut dyn Disk, rec: u64, seq: u16) -> Out {
    let mut st = CState::new();
    with_disk(disk, |ctx| {
        let mut v = st.vol(ctx);
        // SAFETY: every pointer in `v` refers to a live buffer of the size
        // the header documents; `runs`/`ext` likewise, with their capacity.
        unsafe {
            let e = pg_ntfs_open(&mut v);
            if e != 0 {
                return Err(e);
            }
            let mut runs = vec![PgRun::default(); MAX_EXTENTS];
            let (mut n, mut size) = (0usize, 0u64);
            let e = pg_ntfs_file(
                &mut v,
                rec,
                seq,
                runs.as_mut_ptr(),
                runs.len(),
                &mut n,
                &mut size,
            );
            if e != 0 {
                return Err(e);
            }
            let mut ext = vec![PgExtent::default(); MAX_EXTENTS];
            let mut k = 0usize;
            let e = pg_ntfs_extents(&v, runs.as_ptr(), n, ext.as_mut_ptr(), ext.len(), &mut k);
            if e != 0 {
                return Err(e);
            }
            Ok(Derived {
                extents: ext
                    .get(..k)
                    .unwrap_or(&[])
                    .iter()
                    .map(|e| Extent {
                        start: e.start,
                        end: e.end,
                    })
                    .collect(),
                size,
            })
        }
    })
}

pub fn c_flags(disk: &mut dyn Disk) -> Result<u16, i32> {
    let mut st = CState::new();
    with_disk(disk, |ctx| {
        let mut v = st.vol(ctx);
        let mut flags = 0u16;
        // SAFETY: as in `c_file`.
        let e = unsafe {
            let e = pg_ntfs_open(&mut v);
            if e != 0 {
                e
            } else {
                pg_ntfs_volume_flags(&mut v, &mut flags)
            }
        };
        if e != 0 { Err(e) } else { Ok(flags) }
    })
}

pub fn c_payload(disk: &mut dyn Disk, sectors: u64) -> Result<(), i32> {
    let mut buf = [0u8; 512];
    // SAFETY: `buf` is 512 bytes; the context is live for the call.
    let e = with_disk(disk, |ctx| unsafe {
        pg_payload_check(trampoline, ctx, sectors, buf.as_mut_ptr())
    });
    if e != 0 { Err(e) } else { Ok(()) }
}

pub fn c_runlist(input: &[u8], cap: usize) -> Result<Vec<Run>, i32> {
    let mut out = vec![PgRun::default(); cap];
    let mut n = 0usize;
    // SAFETY: `input` and `out` are valid for the lengths passed.
    let e =
        unsafe { pg_runlist_decode(input.as_ptr(), input.len(), out.as_mut_ptr(), cap, &mut n) };
    if e != 0 {
        return Err(e);
    }
    Ok(out
        .get(..n)
        .unwrap_or(&[])
        .iter()
        .map(|r| Run {
            lcn: r.lcn,
            count: r.count,
        })
        .collect())
}

pub fn rust_runlist(input: &[u8], cap: usize) -> Result<Vec<Run>, i32> {
    let mut out = vec![Run { lcn: 0, count: 0 }; cap];
    let n =
        paguro_core::runlist::decode(input, &mut out).map_err(|e| NtfsError::Runlist(e).code())?;
    out.truncate(n);
    Ok(out)
}

fn to_c(e: &[Extent]) -> Vec<PgExtent> {
    e.iter()
        .map(|e| PgExtent {
            start: e.start,
            end: e.end,
        })
        .collect()
}

fn from_c(e: &[PgExtent]) -> Vec<Extent> {
    e.iter()
        .map(|e| Extent {
            start: e.start,
            end: e.end,
        })
        .collect()
}

pub fn c_normalise(file: &[Extent], cap: usize) -> Result<Vec<Extent>, i32> {
    let f = to_c(file);
    let mut out = vec![PgExtent::default(); cap];
    let mut n = 0usize;
    // SAFETY: lengths match the buffers.
    let e = unsafe { pg_claim_normalise(f.as_ptr(), f.len(), out.as_mut_ptr(), cap, &mut n) };
    if e != 0 {
        return Err(e);
    }
    Ok(from_c(out.get(..n).unwrap_or(&[])))
}

pub fn c_intersects(a: &[Extent], b: &[Extent]) -> bool {
    let (a, b) = (to_c(a), to_c(b));
    // SAFETY: lengths match the buffers.
    unsafe { pg_claim_intersects(a.as_ptr(), a.len(), b.as_ptr(), b.len()) != 0 }
}

pub fn c_grows(old: &[Extent], new: &[Extent]) -> bool {
    let (a, b) = (to_c(old), to_c(new));
    // SAFETY: lengths match the buffers.
    unsafe { pg_claim_grows(a.as_ptr(), a.len(), b.as_ptr(), b.len()) != 0 }
}

/// `None` when the C returns 0 for a non-empty input (an empty extent).
pub fn c_coalesce(e: &[Extent]) -> Option<Vec<Extent>> {
    let mut c = to_c(e);
    // SAFETY: length matches the buffer.
    let n = unsafe { pg_claim_coalesce(c.as_mut_ptr(), c.len()) };
    if n == 0 && !e.is_empty() {
        return None;
    }
    Some(from_c(c.get(..n).unwrap_or(&[])))
}

pub fn c_gather(file: &[Extent], lsec: u64) -> Option<(u64, u64)> {
    let f = to_c(file);
    let mut phys = 0u64;
    // SAFETY: length matches the buffer.
    let left = unsafe { pg_claim_gather(f.as_ptr(), f.len(), lsec, &mut phys) };
    (left != 0).then_some((phys, left))
}

/// The range test's normalisation (pg_range.c), which merges overlaps.
pub fn c_range_normalise(e: &[Extent]) -> Vec<Extent> {
    let mut c = to_c(e);
    // SAFETY: length matches the buffer.
    let n = unsafe { pg_range_normalise(c.as_mut_ptr(), c.len()) };
    from_c(c.get(..n).unwrap_or(&[]))
}

// ---- disks ---------------------------------------------------------------

/// Records every sector read, so the two implementations' access patterns
/// can be compared (they must be identical).
pub struct Trace<'a, D: Disk + ?Sized> {
    pub inner: &'a mut D,
    pub reads: Vec<u64>,
}

impl<D: Disk + ?Sized> Disk for Trace<'_, D> {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), IoError> {
        self.reads.push(sector);
        self.inner.read(sector, buf)
    }
}

/// A volume as a list of `(sector, contents)`; unlisted sectors fail.
/// This is the fuzz-input format (`fuzz/`, `kernel/dm-paguro/test/fuzz/`):
///
/// ```text
/// rec u32 | seq u16 | reserved u16 | { sector u32 | 512 bytes }*
/// ```
///
/// A trailing partial entry is ignored; the first entry for a sector wins.
pub struct SparseDisk<'a> {
    pub entries: Vec<(u64, &'a [u8])>,
}

impl<'a> SparseDisk<'a> {
    pub fn parse(input: &'a [u8]) -> Option<(u64, u16, SparseDisk<'a>)> {
        let head = input.get(..8)?;
        let rec = u64::from(u32::from_le_bytes(head.get(..4)?.try_into().ok()?));
        let seq = u16::from_le_bytes(head.get(4..6)?.try_into().ok()?);
        let entries = input
            .get(8..)?
            .chunks_exact(516)
            .filter_map(|c| {
                let s = u32::from_le_bytes(c.get(..4)?.try_into().ok()?);
                Some((u64::from(s), c.get(4..)?))
            })
            .collect();
        Some((rec, seq, SparseDisk { entries }))
    }
}

impl Disk for SparseDisk<'_> {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), IoError> {
        let (_, data) = self
            .entries
            .iter()
            .find(|(s, _)| *s == sector)
            .ok_or(IoError)?;
        buf.copy_from_slice(data);
        Ok(())
    }
}

/// Encode a fuzz input from the sectors a parse read.
pub fn sparse_input(img: &[u8], rec: u64, seq: u16, sectors: &[u64]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend((rec as u32).to_le_bytes());
    out.extend(seq.to_le_bytes());
    out.extend([0, 0]);
    let mut seen = Vec::new();
    for &s in sectors {
        if seen.contains(&s) {
            continue;
        }
        seen.push(s);
        let at = s as usize * 512;
        if let Some(data) = img.get(at..at + 512) {
            out.extend((s as u32).to_le_bytes());
            out.extend(data);
        }
    }
    out
}

/// Every error, for name ↔ code tables.
pub fn all_errors() -> Vec<NtfsError> {
    use NtfsError::*;
    let mut v = vec![
        Io,
        BootSignature,
        OemId,
        SectorSize,
        ClusterSize,
        VolumeSize,
        RecordSize,
        MftLcn,
        BadIdentity,
        NotMapped,
        RecordMagic,
        RecordLayout,
        FixupMismatch,
        RecordNumber,
        NotInUse,
        Directory,
        Sequence,
        NotBase,
        AttrBounds,
        NoData,
        DuplicateData,
        Resident,
        Compressed,
        Encrypted,
        Sparse,
        Gap,
        SegmentVcn,
        OutsideVolume,
        AttrList,
        AttrListSize,
        TooManyExtensions,
        MissingSegment,
        ExtensionBase,
        MftAttrList,
        AllocatedSize,
        NotInitialized,
        Unaligned,
        TooManyExtents,
        NoVolumeInfo,
        SelfOverlap,
        PayloadGpt,
        PayloadNoEsp,
        PayloadNotFat,
    ];
    for e in [
        RunlistError::Truncated,
        RunlistError::FieldTooWide,
        RunlistError::Sparse,
        RunlistError::ZeroLength,
        RunlistError::NegativeLcn,
        RunlistError::Overflow,
        RunlistError::TooManyRuns,
        RunlistError::Unterminated,
    ] {
        v.push(Runlist(e));
    }
    v
}

/// `Sparse`, `Runlist.Unterminated`, ... (the manifest's spelling).
pub fn error_name(code: i32) -> String {
    all_errors()
        .into_iter()
        .find(|e| e.code() == code)
        .map(|e| format!("{e:?}").replace('(', ".").replace(')', ""))
        .unwrap_or_else(|| format!("code{code}"))
}
