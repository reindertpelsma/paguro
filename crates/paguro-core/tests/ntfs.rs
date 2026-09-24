//! `paguro_core::ntfs` over synthetic volumes: every error variant, and the
//! shapes real volumes take (fragmented `$MFT`, records straddling runs,
//! attribute lists resident and not, 4 KiB sectors, big clusters).
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod synth;

use paguro_core::ntfs::{self, Disk, IoError, MAX_ALIST, MAX_EXTENTS, NtfsError as E};
use paguro_core::range::Extent;
use paguro_core::runlist::{Run, RunlistError};
use synth::{Mem, NonRes, Record, USER, Vol, alist_entry, put, record_offset, resident, runs};

const ZERO: Run = Run { lcn: 0, count: 0 };

fn derive(img: &[u8], rec: u64, seq: u16) -> Result<(Vec<Extent>, u64), E> {
    derive_on(&mut Mem(img.to_vec()), rec, seq)
}

fn derive_on<D: Disk>(d: &mut D, rec: u64, seq: u16) -> Result<(Vec<Extent>, u64), E> {
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut mft = vec![ZERO; 2048];
    let m = ntfs::open(d, &mut alist, &mut mft)?;
    let mut runs = vec![ZERO; MAX_EXTENTS];
    let f = ntfs::file(d, &m, rec, seq, &mut alist, &mut runs)?;
    let mut ext = vec![Extent { start: 0, end: 0 }; MAX_EXTENTS];
    let n = ntfs::extents(&m.vol, &runs[..f.runs], &mut ext)?;
    Ok((ext[..n].to_vec(), f.data_size))
}

fn flags(img: &[u8]) -> Result<u16, E> {
    let mut d = Mem(img.to_vec());
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut mft = vec![ZERO; 2048];
    let m = ntfs::open(&mut d, &mut alist, &mut mft)?;
    ntfs::volume_flags(&mut d, &m)
}

fn ext(start: u64, end: u64) -> Extent {
    Extent { start, end }
}

/// A volume with one plain file at USER: runs (1000, 8) and (3000, 4).
fn simple() -> Vol {
    let mut v = Vol::new();
    v.add_file(USER, &[(1000, 8), (3000, 4)]);
    v
}

fn with_data(mut v: Vol, d: NonRes) -> Vec<u8> {
    let si = resident(0x10, &[0u8; 0x48], 0);
    v.records
        .insert(USER, Record::file(USER, 7, vec![si, d.bytes()]));
    v.image()
}

fn data() -> NonRes {
    NonRes::data(&[(1000, 8), (3000, 4)], 512)
}

// ---- the happy paths ----------------------------------------------------

#[test]
fn simple_file() {
    let img = simple().image();
    assert_eq!(
        derive(&img, USER, 7),
        Ok((vec![ext(1000, 1008), ext(3000, 3004)], 12 * 512))
    );
    assert_eq!(flags(&img), Ok(0));
}

#[test]
fn adjacent_runs_coalesce() {
    let mut v = Vol::new();
    v.add_file(USER, &[(1000, 8), (1008, 4), (500, 1), (501, 1)]);
    assert_eq!(
        derive(&v.image(), USER, 7).unwrap().0,
        vec![ext(1000, 1012), ext(500, 502)]
    );
}

#[test]
fn big_clusters_and_4k_sectors() {
    // 4 KiB sectors, 64 KiB clusters, 4 KiB records.
    let mut v = Vol::with(4096, 16, 4096, 256, vec![(4, 2)]);
    v.add_file(USER, &[(100, 3)]);
    assert_eq!(
        derive(&v.image(), USER, 7),
        Ok((vec![ext(100 * 128, 103 * 128)], 3 * 65536))
    );
    // 2 MiB clusters, encoded as 2^(256 - raw) sectors.
    let mut v = Vol::with(512, 4096, 1024, 8, vec![(1, 1)]);
    v.add_file(USER, &[(5, 2)]);
    assert_eq!(
        derive(&v.image(), USER, 7),
        Ok((vec![ext(5 * 4096, 7 * 4096)], 2 << 21))
    );
}

#[test]
fn fragmented_mft_with_records_straddling_runs() {
    // One-sector clusters, 1 KiB records: every record spans two runs, each
    // somewhere else on the volume.
    // Record 0 and its neighbours are contiguous at the boot sector's LCN,
    // as NTFS guarantees; everything after is one cluster per run.
    let mut mft = vec![(100u64, 32u64)];
    mft.extend((0..64).map(|i| (200 + 7 * i, 1)));
    let mut v = Vol::with(512, 1, 1024, 8192, mft);
    v.add_file(USER, &[(4000, 2)]);
    assert_eq!(
        derive(&v.image(), USER, 7).unwrap().0,
        vec![ext(4000, 4002)]
    );
    assert_eq!(flags(&v.image()), Ok(0));
}

/// A file split over the base record and `n` extension records, listed in a
/// resident or non-resident attribute list.
fn listed(n: u64, nonresident_list: bool) -> Vol {
    let mut v = Vol::new();
    let mut entries = alist_entry(0x10, 0, USER, 7, 0);
    // Segment 0 in the base record, then one 2-cluster segment per extension.
    let mut base_data = NonRes::data(&[(1000, 2)], 512);
    base_data.alloc = (2 + 2 * n) * 512;
    base_data.size = base_data.alloc;
    base_data.init = base_data.alloc;
    entries.extend(alist_entry(0x80, 0, USER, 7, 1));
    for i in 0..n {
        let r = USER + 1 + i;
        let seg = NonRes::segment(2 + 2 * i, &[(2000 + 10 * i, 2)], 3);
        v.records
            .insert(r, Record::extension(r, (USER, 7), vec![seg.bytes()]));
        entries.extend(alist_entry(0x80, 2 + 2 * i, r, 1, 3));
    }
    let si = resident(0x10, &[0u8; 0x48], 0);
    let list = if nonresident_list {
        let clusters = (entries.len() as u64).div_ceil(512);
        let mut a = NonRes::data(&[(6000, clusters)], 512);
        a.ty = 0x20;
        a.size = entries.len() as u64;
        a.init = a.size;
        v.raw.push((6000, entries));
        a.bytes()
    } else {
        resident(0x20, &entries, 2)
    };
    v.records.insert(
        USER,
        Record::file(USER, 7, vec![si, list, base_data.bytes()]),
    );
    v
}

fn listed_extents(n: u64) -> Vec<Extent> {
    let mut want = vec![ext(1000, 1002)];
    want.extend((0..n).map(|i| ext(2000 + 10 * i, 2002 + 10 * i)));
    want
}

#[test]
fn attribute_list_resident() {
    let v = listed(3, false);
    assert_eq!(
        derive(&v.image(), USER, 7),
        Ok((listed_extents(3), 8 * 512))
    );
}

#[test]
fn attribute_list_nonresident_at_the_limit() {
    let v = listed(64, true);
    assert_eq!(derive(&v.image(), USER, 7).unwrap().0, listed_extents(64));
}

// ---- step 1: boot sector ------------------------------------------------

fn boot_err(f: impl Fn(&mut [u8])) -> Result<ntfs::Volume, E> {
    let mut b = Vol::new().boot();
    f(&mut b);
    ntfs::parse_boot(&b)
}

#[test]
fn boot_sector_errors() {
    assert!(boot_err(|_| {}).is_ok());
    assert_eq!(boot_err(|b| b[511] = 0), Err(E::BootSignature));
    assert_eq!(boot_err(|b| b[3] = b'X'), Err(E::OemId));
    assert_eq!(boot_err(|b| put(b, 0x0b, 1024, 2)), Err(E::SectorSize));
    assert_eq!(boot_err(|b| b[0x0d] = 3), Err(E::ClusterSize));
    assert_eq!(boot_err(|b| b[0x0d] = 0), Err(E::ClusterSize));
    assert_eq!(boot_err(|b| b[0x0d] = 0xf3), Err(E::ClusterSize)); // 4 MiB
    assert_eq!(boot_err(|b| b[0x0d] = 0x81), Err(E::ClusterSize));
    assert_eq!(boot_err(|b| put(b, 0x28, 0, 8)), Err(E::VolumeSize));
    assert_eq!(boot_err(|b| put(b, 0x28, u64::MAX, 8)), Err(E::VolumeSize));
    assert_eq!(boot_err(|b| b[0x40] = 0xf5).unwrap().record_bytes, 2048);
    assert_eq!(boot_err(|b| b[0x40] = 0xf3), Err(E::RecordSize)); // 8 KiB
    assert_eq!(boot_err(|b| b[0x40] = 0), Err(E::RecordSize));
    assert_eq!(boot_err(|b| b[0x40] = 3), Err(E::RecordSize)); // 1536 bytes
    assert_eq!(boot_err(|b| put(b, 0x30, 8192, 8)), Err(E::MftLcn));
    assert_eq!(boot_err(|b| put(b, 0x30, 8191, 8)), Err(E::MftLcn)); // record spills
}

#[test]
fn io_errors_propagate() {
    struct Failing(Mem, u64);
    impl Disk for Failing {
        fn read(&mut self, s: u64, b: &mut [u8; 512]) -> Result<(), IoError> {
            if s == self.1 {
                return Err(IoError);
            }
            self.0.read(s, b)
        }
    }
    let img = simple().image();
    // Boot sector, then $MFT record 0, then the file's record.
    for s in [0, 16, 16 + 2 * USER] {
        assert_eq!(
            derive_on(&mut Failing(Mem(img.clone()), s), USER, 7),
            Err(E::Io)
        );
    }
}

// ---- steps 2–3: records ------------------------------------------------

fn mutate(v: &Vol, recno: u64, f: impl Fn(&mut [u8])) -> Vec<u8> {
    let mut img = v.image();
    let at = record_offset(v, recno);
    f(&mut img[at..at + v.record]);
    img
}

#[test]
fn identity_errors() {
    let img = simple().image();
    assert_eq!(derive(&img, 5, 5), Err(E::BadIdentity));
    assert_eq!(derive(&img, USER, 0), Err(E::BadIdentity));
    assert_eq!(derive(&img, 1 << 32, 1), Err(E::BadIdentity));
    assert_eq!(derive(&img, 256, 1), Err(E::NotMapped)); // $MFT holds 256
    assert_eq!(derive(&img, USER, 8), Err(E::Sequence));
    assert_eq!(derive(&img, USER + 1, 7), Err(E::RecordMagic)); // empty slot
}

#[test]
fn record_errors() {
    let v = simple();
    let r = |f: fn(&mut [u8])| derive(&mutate(&v, USER, f), USER, 7);
    assert_eq!(r(|b| b[0] = b'B'), Err(E::RecordMagic));
    assert_eq!(r(|b| put(b, 4, 0x28, 2)), Err(E::RecordLayout)); // USA offset
    assert_eq!(r(|b| put(b, 6, 2, 2)), Err(E::RecordLayout)); // USA count
    assert_eq!(r(|b| b[1022] ^= 1), Err(E::FixupMismatch));
    assert_eq!(r(|b| b[510] ^= 1), Err(E::FixupMismatch));
    assert_eq!(r(|b| put(b, 0x1c, 4096, 4)), Err(E::RecordLayout)); // allocated
    assert_eq!(r(|b| put(b, 0x18, 1032, 4)), Err(E::RecordLayout)); // in use
    assert_eq!(r(|b| put(b, 0x18, 0x1f4, 4)), Err(E::RecordLayout)); // unaligned
    assert_eq!(r(|b| put(b, 0x14, 0x3c, 2)), Err(E::RecordLayout)); // attrs unaligned
    assert_eq!(r(|b| put(b, 0x14, 0x30, 2)), Err(E::RecordLayout)); // attrs over USA
    assert_eq!(r(|b| put(b, 0x14, 0x3f8, 2)), Err(E::RecordLayout)); // attrs >= used
    assert_eq!(r(|b| put(b, 0x2c, 99, 4)), Err(E::RecordNumber));
    assert_eq!(r(|b| put(b, 0x16, 0, 2)), Err(E::NotInUse));
    assert_eq!(r(|b| put(b, 0x16, 3, 2)), Err(E::Directory));
    assert_eq!(r(|b| put(b, 0x20, 5, 8)), Err(E::NotBase));
}

#[test]
fn mft_record_errors() {
    let v = simple();
    let m = |f: fn(&mut [u8])| derive(&mutate(&v, 0, f), USER, 7);
    assert_eq!(m(|b| b[0] = 0), Err(E::RecordMagic));
    assert_eq!(m(|b| put(b, 0x2c, 1, 4)), Err(E::RecordNumber));
    // $MFT with an attribute list is refused outright.
    let mut v = simple();
    let d = NonRes::data(&[(16, 512)], 512);
    let list = resident(0x20, &alist_entry(0x80, 0, 0, 1, 1), 2);
    v.records
        .insert(0, Record::file(0, 1, vec![list, d.bytes()]));
    assert_eq!(derive(&v.image(), USER, 7), Err(E::MftAttrList));
    // $MFT smaller than the file's record number.
    let mut v = simple();
    let d = NonRes::data(&[(16, 40)], 512); // 20 records
    v.records.insert(0, Record::file(0, 1, vec![d.bytes()]));
    assert_eq!(derive(&v.image(), USER, 7), Err(E::NotMapped));
}

// ---- step 4: attributes ------------------------------------------------

#[test]
fn attribute_bounds() {
    let v = simple();
    // First attribute is at 0x38; its length, name and value are checked.
    let r = |f: fn(&mut [u8])| derive(&mutate(&v, USER, f), USER, 7);
    assert_eq!(r(|b| put(b, 0x3c, 0x10, 4)), Err(E::AttrBounds));
    assert_eq!(r(|b| put(b, 0x3c, 0x61, 4)), Err(E::AttrBounds));
    assert_eq!(r(|b| put(b, 0x3c, 0x800, 4)), Err(E::AttrBounds));
    assert_eq!(r(|b| b[0x38 + 8] = 2), Err(E::AttrBounds));
    assert_eq!(
        r(|b| {
            b[0x38 + 9] = 40;
            put(b, 0x38 + 0x0a, 0x18, 2)
        }),
        Err(E::AttrBounds)
    );
    assert_eq!(r(|b| put(b, 0x38 + 0x10, 0x49, 4)), Err(E::AttrBounds));
    // No end marker before bytes_in_use.
    assert_eq!(
        r(|b| {
            let used = u32::from_le_bytes(b[0x18..0x1c].try_into().unwrap()) as usize;
            put(b, used - 8, 0x10, 4);
        }),
        Err(E::AttrBounds)
    );
}

#[test]
fn nonresident_header_too_short() {
    let mut v = simple();
    let mut a = resident(0x30, &[0u8; 0x20], 4); // 0x38 bytes long
    a[8] = 1;
    let d = data().bytes();
    v.records.insert(USER, Record::file(USER, 7, vec![a, d]));
    assert_eq!(derive(&v.image(), USER, 7), Err(E::AttrBounds));
}

#[test]
fn data_attribute_errors() {
    let v = Vol::new();
    let si = resident(0x10, &[0u8; 0x48], 0);
    let rec = |attrs: Vec<Vec<u8>>| {
        let mut v = v.clone();
        v.records.insert(USER, Record::file(USER, 7, attrs));
        derive(&v.image(), USER, 7)
    };
    assert_eq!(rec(vec![si.clone()]), Err(E::NoData));
    assert_eq!(
        rec(vec![si.clone(), data().bytes(), data().bytes()]),
        Err(E::DuplicateData)
    );
    assert_eq!(
        rec(vec![si.clone(), resident(0x80, b"hello", 1)]),
        Err(E::Resident)
    );
    // A named stream alone is not the file's data...
    let mut named = data();
    named.name = "ads";
    assert_eq!(rec(vec![si.clone(), named.bytes()]), Err(E::NoData));
    // ...and beside the unnamed one it is ignored.
    assert!(rec(vec![si.clone(), data().bytes(), named.bytes()]).is_ok());
    // Other attribute types are skipped.
    assert!(rec(vec![si, resident(0x30, &[1u8; 0x42], 3), data().bytes()]).is_ok());
}

#[test]
fn data_flag_errors() {
    let w = |f: fn(&mut NonRes)| {
        let mut d = data();
        f(&mut d);
        derive(&with_data(Vol::new(), d), USER, 7)
    };
    assert_eq!(w(|d| d.flags = 0x0001), Err(E::Compressed));
    assert_eq!(w(|d| d.cu = 4), Err(E::Compressed));
    assert_eq!(w(|d| d.flags = 0x4000), Err(E::Encrypted));
    assert_eq!(w(|d| d.flags = 0x8000), Err(E::Sparse));
    assert_eq!(w(|d| d.lowest = 1), Err(E::Gap));
    assert_eq!(w(|d| d.highest = 12), Err(E::SegmentVcn));
    assert_eq!(w(|d| d.pairs = vec![0]), Err(E::SegmentVcn)); // empty runlist
    assert_eq!(w(|d| d.alloc += 512), Err(E::AllocatedSize));
    assert_eq!(w(|d| d.size = d.alloc + 512), Err(E::AllocatedSize));
    assert_eq!(w(|d| d.init -= 512), Err(E::NotInitialized));
    assert_eq!(
        w(|d| {
            d.size -= 100;
            d.init -= 100
        }),
        Err(E::Unaligned)
    );
    assert_eq!(w(|d| d.pairs = runs(&[(8190, 4)])), Err(E::OutsideVolume));
    // A shorter file in the same allocation is fine (size <= allocated).
    assert!(
        w(|d| {
            d.size -= 512;
            d.init -= 512
        })
        .is_ok()
    );
}

#[test]
fn mapping_pairs_errors() {
    let w = |pairs: Vec<u8>, mp: Option<u64>| {
        let mut d = data();
        d.pairs = pairs;
        let mut b = d.bytes();
        if let Some(mp) = mp {
            put(&mut b, 0x20, mp, 2);
        }
        let mut v = Vol::new();
        let si = resident(0x10, &[0u8; 0x48], 0);
        v.records.insert(USER, Record::file(USER, 7, vec![si, b]));
        derive(&v.image(), USER, 7)
    };
    let ok = runs(&[(1000, 8), (3000, 4)]);
    assert_eq!(w(ok.clone(), Some(0x38)), Err(E::AttrBounds));
    assert_eq!(w(ok.clone(), Some(0x200)), Err(E::AttrBounds));
    let rl = |e| Err(E::Runlist(e));
    assert_eq!(w(vec![0x01, 0x0c, 0], None), rl(RunlistError::Sparse));
    assert_eq!(w(vec![0x19, 0x0c, 0], None), rl(RunlistError::FieldTooWide));
    assert_eq!(
        w(vec![0x11, 0x00, 0x05, 0], None),
        rl(RunlistError::ZeroLength)
    );
    assert_eq!(
        w(vec![0x11, 0x0c, 0xff, 0], None),
        rl(RunlistError::NegativeLcn)
    );
    // Runs up to the end of the 8-byte-aligned attribute, no terminator.
    assert_eq!(
        w(vec![0x11, 0x01, 0x05, 0x11, 0x01, 0x05, 0x11, 0x01], None),
        rl(RunlistError::Truncated)
    );
    assert_eq!(
        w(vec![0x21, 0x01, 0x05, 0x00, 0x21, 0x01, 0x05, 0x00], None),
        rl(RunlistError::Unterminated)
    );
    // Eight-byte length of 2^64 - 1 at LCN 1: lcn + count overflows.
    let mut big = vec![0x18];
    big.extend([0xff; 8]);
    big.extend([0x01, 0]);
    assert_eq!(w(big, None), rl(RunlistError::Overflow));
}

#[test]
fn run_capacity() {
    let img = simple().image();
    let mut d = Mem(img);
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut mft = vec![ZERO; 16];
    let m = ntfs::open(&mut d, &mut alist, &mut mft).unwrap();
    let mut runs = [ZERO; 1];
    assert_eq!(
        ntfs::file(&mut d, &m, USER, 7, &mut alist, &mut runs),
        Err(E::Runlist(RunlistError::TooManyRuns))
    );
    let mut runs = [ZERO; 2];
    let f = ntfs::file(&mut d, &m, USER, 7, &mut alist, &mut runs).unwrap();
    let mut out = [ext(0, 0); 1];
    assert_eq!(
        ntfs::extents(&m.vol, &runs[..f.runs], &mut out),
        Err(E::TooManyExtents)
    );
    // $MFT's own map is capacity-bounded too.
    let mut mft = [ZERO; 0];
    assert_eq!(
        ntfs::open(&mut d, &mut alist, &mut mft).map(|_| ()),
        Err(E::Runlist(RunlistError::TooManyRuns))
    );
}

// ---- attribute lists ---------------------------------------------------

fn listed_with(f: impl Fn(&mut Vol)) -> Result<(Vec<Extent>, u64), E> {
    let mut v = listed(3, false);
    f(&mut v);
    derive(&v.image(), USER, 7)
}

fn set_list(v: &mut Vol, entries: Vec<u8>) {
    let r = v.records.get_mut(&USER).unwrap();
    r.attrs[1] = resident(0x20, &entries, 2);
}

fn entries(v: &Vol) -> Vec<u8> {
    let a = &v.records[&USER].attrs[1];
    a[0x18..0x18 + u32::from_le_bytes(a[0x10..0x14].try_into().unwrap()) as usize].to_vec()
}

#[test]
fn attribute_list_errors() {
    // Two lists.
    assert_eq!(
        listed_with(|v| {
            let l = v.records[&USER].attrs[1].clone();
            v.records.get_mut(&USER).unwrap().attrs.insert(1, l);
        }),
        Err(E::AttrList)
    );
    // An entry shorter than its header, or running past the list.
    for len in [0x10u64, 0x200] {
        assert_eq!(
            listed_with(|v| {
                let mut e = entries(v);
                put(&mut e, 0x20 + 4, len, 2);
                set_list(v, e);
            }),
            Err(E::AttrList)
        );
    }
    // Trailing partial entry.
    assert_eq!(
        listed_with(|v| {
            let mut e = entries(v);
            e.extend([0u8; 8]);
            set_list(v, e);
        }),
        Err(E::AttrList)
    );
    // Segments out of order: the second listed $DATA claims VCN 4.
    assert_eq!(
        listed_with(|v| {
            let mut e = entries(v);
            put(&mut e, 0x40 + 8, 4, 8);
            set_list(v, e);
        }),
        Err(E::Gap)
    );
    // The entry names the right VCN but the record's segment disagrees.
    assert_eq!(
        listed_with(|v| {
            let r = v.records.get_mut(&(USER + 1)).unwrap();
            r.attrs[0] = NonRes::segment(3, &[(2000, 2)], 3).bytes();
        }),
        Err(E::Gap)
    );
    // Wrong instance: the segment is not where the list says.
    assert_eq!(
        listed_with(|v| {
            let mut e = entries(v);
            put(&mut e, 0x40 + 0x18, 9, 2);
            set_list(v, e);
        }),
        Err(E::MissingSegment)
    );
    // Extension record pointing at another base, stale sequence, not in use.
    assert_eq!(
        listed_with(|v| v.records.get_mut(&(USER + 2)).unwrap().base = 12345),
        Err(E::ExtensionBase)
    );
    assert_eq!(
        listed_with(|v| v.records.get_mut(&(USER + 2)).unwrap().seq = 2),
        Err(E::Sequence)
    );
    assert_eq!(
        listed_with(|v| v.records.get_mut(&(USER + 2)).unwrap().flags = 0),
        Err(E::NotInUse)
    );
    assert_eq!(
        listed_with(|v| {
            v.records.remove(&(USER + 3));
        }),
        Err(E::RecordMagic)
    );
    // No $DATA in the list at all.
    assert_eq!(
        listed_with(|v| {
            let e = entries(v);
            set_list(v, e[..0x20].to_vec());
        }),
        Err(E::NoData)
    );
    // Allocation shorter than the segments.
    assert_eq!(
        listed_with(|v| {
            let r = v.records.get_mut(&USER).unwrap();
            let mut d = NonRes::data(&[(1000, 2)], 512);
            d.alloc = 6 * 512;
            d.size = d.alloc;
            d.init = d.alloc;
            r.attrs[2] = d.bytes();
        }),
        Err(E::AllocatedSize)
    );
}

#[test]
fn too_many_extensions() {
    let v = listed(65, true);
    assert_eq!(derive(&v.image(), USER, 7), Err(E::TooManyExtensions));
}

#[test]
fn nonresident_list_errors() {
    let w = |f: fn(&mut NonRes)| {
        let mut v = listed(64, true);
        let a = &v.records[&USER].attrs[1];
        let mut l = NonRes::data(&[(6000, 5)], 512);
        l.ty = 0x20;
        l.size = u64::from_le_bytes(a[0x30..0x38].try_into().unwrap());
        l.init = l.size;
        f(&mut l);
        v.records.get_mut(&USER).unwrap().attrs[1] = l.bytes();
        derive(&v.image(), USER, 7)
    };
    assert!(w(|_| {}).is_ok());
    assert_eq!(w(|l| l.flags = 0x8000), Err(E::AttrList));
    assert_eq!(w(|l| l.lowest = 1), Err(E::AttrList));
    assert_eq!(w(|l| l.init -= 1), Err(E::AttrList));
    assert_eq!(
        w(|l| {
            l.size = MAX_ALIST as u64 + 1;
            l.init = l.size
        }),
        Err(E::AttrListSize)
    );
    assert_eq!(
        w(|l| {
            l.size = 5 * 512 + 1;
            l.init = l.size
        }),
        Err(E::AttrList) // runs cover 5 clusters, list claims more
    );
    assert_eq!(w(|l| l.pairs = runs(&[(8191, 5)])), Err(E::OutsideVolume));
    assert_eq!(
        w(|l| l.pairs = vec![0x01, 0x05, 0]),
        Err(E::Runlist(RunlistError::Sparse))
    );
}

// ---- step 7: $Volume ---------------------------------------------------

#[test]
fn volume_flags_and_errors() {
    let mut v = simple();
    v.dirty = true;
    assert_eq!(flags(&v.image()), Ok(ntfs::VOLUME_DIRTY));
    let v = simple();
    let m = |f: fn(&mut [u8])| flags(&mutate(&v, 3, f));
    assert_eq!(m(|b| put(b, 0x16, 0, 2)), Err(E::NotInUse));
    assert_eq!(m(|b| put(b, 0x20, 9, 8)), Err(E::NotBase));
    assert_eq!(m(|b| b[0x38] = 0x60), Err(E::NoVolumeInfo)); // type changed
    assert_eq!(m(|b| put(b, 0x38 + 0x10, 8, 4)), Err(E::NoVolumeInfo));
    assert_eq!(m(|b| b[0] = 0), Err(E::RecordMagic));
}

// ---- claims -------------------------------------------------------------

#[test]
fn normalise_sorts_merges_and_refuses_overlap() {
    let mut out = [ext(0, 0); 4];
    let file = [ext(50, 60), ext(10, 20), ext(20, 30)];
    assert_eq!(ntfs::normalise(&file, &mut out), Ok(2));
    assert_eq!(out[..2], [ext(10, 30), ext(50, 60)]);
    assert_eq!(
        ntfs::normalise(&[ext(10, 20), ext(15, 25)], &mut out),
        Err(E::SelfOverlap)
    );
    assert_eq!(
        ntfs::normalise(&[ext(10, 20), ext(10, 20)], &mut out),
        Err(E::SelfOverlap)
    );
    assert_eq!(ntfs::normalise(&[ext(5, 5)], &mut out), Err(E::SelfOverlap));
    assert_eq!(
        ntfs::normalise(&[ext(1, 2); 5], &mut out),
        Err(E::TooManyExtents)
    );
}

#[test]
fn intersects_matches_brute_force() {
    let mut seed = 0x1234_5678_u64;
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for _ in 0..20_000 {
        let mut make = || {
            let mut v = Vec::new();
            let mut at = next(20);
            for _ in 0..next(5) {
                let len = 1 + next(10);
                v.push(ext(at, at + len));
                at += len + 1 + next(10);
            }
            v
        };
        let (a, b) = (make(), make());
        let brute = a.iter().any(|x| b.iter().any(|y| x.intersects(y)));
        assert_eq!(ntfs::intersects(&a, &b), brute, "{a:?} {b:?}");
    }
}

#[test]
fn growth_is_append_only() {
    let old = [ext(0, 10), ext(50, 60)];
    assert!(ntfs::grows(&old, &old));
    assert!(ntfs::grows(&old, &[ext(0, 10), ext(50, 70)])); // extended in place
    assert!(ntfs::grows(&old, &[ext(0, 10), ext(50, 60), ext(90, 99)]));
    assert!(!ntfs::grows(&old, &[ext(0, 10), ext(50, 59)])); // shrank
    assert!(!ntfs::grows(&old, &[ext(0, 10), ext(51, 70)])); // moved
    assert!(!ntfs::grows(&old, &[ext(0, 11), ext(50, 60)]));
    assert!(!ntfs::grows(&old, &[ext(0, 10)]));
    assert!(!ntfs::grows(&[], &old));
}

#[test]
fn coalesce_and_gather() {
    let mut e = [ext(10, 20), ext(20, 25), ext(5, 6), ext(6, 8), ext(30, 31)];
    assert_eq!(ntfs::coalesce(&mut e), Some(3));
    assert_eq!(e[..3], [ext(10, 25), ext(5, 8), ext(30, 31)]);
    assert_eq!(ntfs::coalesce(&mut [ext(1, 1)]), None);
    let file = [ext(10, 25), ext(5, 8), ext(30, 31)];
    assert_eq!(ntfs::gather(&file, 0), Some((10, 15)));
    assert_eq!(ntfs::gather(&file, 14), Some((24, 1)));
    assert_eq!(ntfs::gather(&file, 15), Some((5, 3)));
    assert_eq!(ntfs::gather(&file, 18), Some((30, 1)));
    assert_eq!(ntfs::gather(&file, 19), None);
}

// ---- the structural assertion -------------------------------------------

/// A GPT disk of `sectors` with an ESP at `first..=last` holding a FAT boot
/// sector.
pub fn gpt_disk(sectors: u64, first: u64, last: u64) -> Vec<u8> {
    let mut d = vec![0u8; sectors as usize * 512];
    let h = 512;
    d[h..h + 8].copy_from_slice(b"EFI PART");
    put(&mut d, h + 12, 92, 4);
    put(&mut d, h + 24, 1, 8);
    put(&mut d, h + 72, 2, 8);
    put(&mut d, h + 80, 128, 4);
    put(&mut d, h + 84, 128, 4);
    // Entry 5 (sector 3, second slot) is the ESP.
    let e = 3 * 512 + 128;
    d[e..e + 16].copy_from_slice(&[
        0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9,
        0x3b,
    ]);
    put(&mut d, e + 32, first, 8);
    put(&mut d, e + 40, last, 8);
    let f = first as usize * 512;
    d[f + 0x52..f + 0x57].copy_from_slice(b"FAT32");
    d[f + 510] = 0x55;
    d[f + 511] = 0xaa;
    d
}

#[test]
fn payload_check() {
    let ok = gpt_disk(100, 40, 90);
    let c = |d: &[u8]| ntfs::check_payload(&mut Mem(d.to_vec()), d.len() as u64 / 512);
    assert_eq!(c(&ok), Ok(()));
    let m = |at: usize, v: u64, n: usize| {
        let mut d = ok.clone();
        put(&mut d, at, v, n);
        c(&d)
    };
    assert_eq!(m(512, 0, 1), Err(E::PayloadGpt));
    assert_eq!(m(512 + 12, 91, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 24, 2, 8), Err(E::PayloadGpt));
    assert_eq!(m(512 + 84, 256, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 80, 0, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 80, 1025, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 72, 1, 8), Err(E::PayloadGpt));
    assert_eq!(m(512 + 72, 99, 8), Err(E::PayloadGpt)); // entries past the end
    assert_eq!(m(3 * 512 + 128, 0, 1), Err(E::PayloadNoEsp));
    assert_eq!(m(3 * 512 + 128 + 40, 100, 8), Err(E::PayloadGpt));
    assert_eq!(m(3 * 512 + 128 + 32, 91, 8), Err(E::PayloadGpt));
    assert_eq!(m(40 * 512 + 0x52, 0, 1), Err(E::PayloadNotFat));
    assert_eq!(m(40 * 512 + 510, 0, 1), Err(E::PayloadNotFat));
    let mut fat16 = ok.clone();
    fat16[40 * 512 + 0x52] = 0;
    fat16[40 * 512 + 0x36..40 * 512 + 0x39].copy_from_slice(b"FAT");
    assert_eq!(c(&fat16), Ok(()));
    assert_eq!(c(&ok[..1024]), Err(E::PayloadGpt));
    assert_eq!(
        ntfs::check_payload(&mut Mem(ok[..30 * 512].to_vec()), 100),
        Err(E::Io)
    );
}

#[test]
fn error_codes_are_distinct() {
    let all = [
        E::Io,
        E::BootSignature,
        E::OemId,
        E::SectorSize,
        E::ClusterSize,
        E::VolumeSize,
        E::RecordSize,
        E::MftLcn,
        E::BadIdentity,
        E::NotMapped,
        E::RecordMagic,
        E::RecordLayout,
        E::FixupMismatch,
        E::RecordNumber,
        E::NotInUse,
        E::Directory,
        E::Sequence,
        E::NotBase,
        E::AttrBounds,
        E::NoData,
        E::DuplicateData,
        E::Resident,
        E::Compressed,
        E::Encrypted,
        E::Sparse,
        E::Gap,
        E::SegmentVcn,
        E::OutsideVolume,
        E::AttrList,
        E::AttrListSize,
        E::TooManyExtensions,
        E::MissingSegment,
        E::ExtensionBase,
        E::MftAttrList,
        E::AllocatedSize,
        E::NotInitialized,
        E::Unaligned,
        E::TooManyExtents,
        E::NoVolumeInfo,
        E::SelfOverlap,
        E::PayloadGpt,
        E::PayloadNoEsp,
        E::PayloadNotFat,
    ];
    let mut codes: Vec<i32> = all.iter().map(|e| e.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
    assert!(codes.iter().all(|&c| c > 0 && c < 50));
}
