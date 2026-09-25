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
    let t = |n: u64| {
        let mut f = file;
        ntfs::truncate(&mut f, n).map(|k| f[..k].to_vec())
    };
    assert_eq!(t(0), None);
    assert_eq!(t(1), Some(vec![ext(10, 11)]));
    assert_eq!(t(15), Some(vec![ext(10, 25)]));
    assert_eq!(t(16), Some(vec![ext(10, 25), ext(5, 6)]));
    assert_eq!(t(19), Some(file.to_vec()));
    assert_eq!(t(20), None);
    assert_eq!(ntfs::truncate(&mut [ext(3, 3)], 1), None);
    assert_eq!(ntfs::gather(&file, 0), Some((10, 15)));
    assert_eq!(ntfs::gather(&file, 14), Some((24, 1)));
    assert_eq!(ntfs::gather(&file, 15), Some((5, 3)));
    assert_eq!(ntfs::gather(&file, 18), Some((30, 1)));
    assert_eq!(ntfs::gather(&file, 19), None);
}

// ---- the structural assertion -------------------------------------------
// Synthetic shapes, one test per refusal; real images from the real tools
// (and their corruptions, and misordered gathering) are in
// test/fixtures/payload, checked C against Rust by paguro-harness.

const ESP: [u8; 16] = [
    0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
];
const LINUX: [u8; 16] = [
    0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4,
];

fn payload(d: &[u8], sectors: u64) -> Result<(), E> {
    ntfs::check_payload(&mut Mem(d.to_vec()), sectors, 512)
}
fn check(d: &[u8]) -> Result<(), E> {
    payload(d, d.len() as u64 / 512)
}

/// An ext4 superblock at byte offset `at` of `d`: 1 KiB blocks, 8 blocks
/// per group, `blocks` blocks, group number `group`.
fn ext4_sb(d: &mut [u8], at: usize, blocks: u64, group: u64) {
    put(d, at + 4, blocks, 4);
    put(d, at + 0x14, 1, 4);
    put(d, at + 0x18, 0, 4);
    put(d, at + 0x20, 8, 4);
    put(d, at + 0x38, 0xef53, 2);
    put(d, at + 0x4c, 1, 4);
    put(d, at + 0x5a, group, 2);
    for i in 0..16 {
        d[at + 0x68 + i] = 0xa0 + i as u8;
    }
}

/// Bare ext4 of 32 KiB blocks: primary at 1024, backup at block 9 (group 1).
fn ext4_at(d: &mut [u8], base: usize, blocks: u64) {
    ext4_sb(d, base + 1024, blocks, 0);
    ext4_sb(d, base + 9 * 1024, blocks, 1);
}

fn ext4_image() -> Vec<u8> {
    let mut d = vec![0u8; 32 * 1024];
    ext4_at(&mut d, 0, 32);
    d
}

fn hdr_crc(d: &mut [u8], at: usize) {
    put(d, at + 16, 0, 4);
    let c = paguro_core::gpt::crc32(&d[at..at + 92]);
    put(d, at + 16, u64::from(c), 4);
}

/// Refresh every CRC after an edit of the primary array (copied to the
/// backup's array) or of either header; LBAs are `k` sectors.
fn gpt_crcs_k(d: &mut [u8], k: usize) {
    let l = 512 * k;
    let n = d.len() / l;
    let arr: Vec<u8> = d[2 * l..2 * l + 4 * 128].to_vec();
    let blba = (n - 2) * l;
    d[blba..blba + 512].copy_from_slice(&arr);
    let c = u64::from(paguro_core::gpt::crc32(&arr));
    for at in [l, (n - 1) * l] {
        put(d, at + 88, c, 4);
        hdr_crc(d, at);
    }
}
fn gpt_crcs(d: &mut [u8]) {
    gpt_crcs_k(d, 1);
}

/// A 200-LBA GPT disk (LBA = `k` sectors): 4-entry array at LBA 2, usable
/// 3..=197, backup array at 198 and header at 199; ESP (FAT, 40 LBAs) at
/// 10..=49, ext4 (32 KiB) at 64..=127.
fn gpt_image_k(k: usize) -> Vec<u8> {
    let l = 512 * k;
    let mut d = vec![0u8; 200 * l];
    for (at, my, alt, arr) in [(l, 1, 199, 2), (199 * l, 199, 1, 198)] {
        d[at..at + 8].copy_from_slice(b"EFI PART");
        put(&mut d, at + 8, 0x10000, 4);
        put(&mut d, at + 12, 92, 4);
        put(&mut d, at + 24, my, 8);
        put(&mut d, at + 32, alt, 8);
        put(&mut d, at + 40, 3, 8);
        put(&mut d, at + 48, 197, 8);
        d[at + 56..at + 72].copy_from_slice(&[0x5a; 16]);
        put(&mut d, at + 72, arr, 8);
        put(&mut d, at + 80, 4, 4);
        put(&mut d, at + 84, 128, 4);
    }
    let a = 2 * l;
    d[a..a + 16].copy_from_slice(&ESP);
    put(&mut d, a + 32, 10, 8);
    put(&mut d, a + 40, 49, 8);
    d[a + 128..a + 144].copy_from_slice(&LINUX);
    put(&mut d, a + 128 + 32, 64, 8);
    put(&mut d, a + 128 + 40, 127, 8);
    let f = 10 * l;
    put(&mut d, f + 11, 512, 2);
    d[f + 13] = 1;
    put(&mut d, f + 0x13, 40 * k as u64, 2);
    d[f + 0x36..f + 0x39].copy_from_slice(b"FAT");
    put(&mut d, f + 510, 0xaa55, 2);
    ext4_at(&mut d, 64 * l, 32);
    gpt_crcs_k(&mut d, k);
    d
}
fn gpt_image() -> Vec<u8> {
    gpt_image_k(1)
}

/// A 40-sector (10 × 2048-byte block) ISO 9660 image, root directory at 18.
fn iso_image() -> Vec<u8> {
    let mut d = vec![0u8; 10 * 2048];
    let p = 16 * 2048;
    d.resize(20 * 2048, 0);
    d[p..p + 7].copy_from_slice(b"\x01CD001\x01");
    put(&mut d, p + 80, 20, 4);
    d[p + 84..p + 88].copy_from_slice(&20u32.to_be_bytes());
    put(&mut d, p + 128, 2048, 2);
    d[p + 130..p + 132].copy_from_slice(&2048u16.to_be_bytes());
    d[p + 156] = 34;
    put(&mut d, p + 158, 18, 4);
    d[p + 162..p + 166].copy_from_slice(&18u32.to_be_bytes());
    d[p + 181] = 2;
    let r = 18 * 2048;
    d[r] = 34;
    put(&mut d, r + 2, 18, 4);
    d[r + 25] = 2;
    d[r + 32] = 1;
    d
}

#[test]
fn payload_shapes_accepted() {
    assert_eq!(check(&gpt_image()), Ok(()));
    assert_eq!(check(&ext4_image()), Ok(()));
    assert_eq!(check(&iso_image()), Ok(()));
    // A grown disk whose backup header has not moved yet.
    let mut g = gpt_image();
    g.resize(g.len() + 64 * 512, 0);
    assert_eq!(check(&g), Ok(()));
    // ext4 smaller than its payload (grown, not yet resized); FAT32 name.
    assert_eq!(payload(&ext4_image(), 64), Ok(()));
    let mut g = gpt_image();
    g[10 * 512 + 0x36] = 0;
    g[10 * 512 + 0x52..10 * 512 + 0x57].copy_from_slice(b"FAT32");
    assert_eq!(check(&g), Ok(()));
}

#[test]
fn payload_logical_block_size() {
    let g4 = gpt_image_k(8);
    let n = g4.len() as u64 / 512;
    let c = |d: &[u8], lbs| ntfs::check_payload(&mut Mem(d.to_vec()), d.len() as u64 / 512, lbs);
    assert_eq!(c(&g4, 4096), Ok(()));
    assert_eq!(c(&g4, 512), Err(E::PayloadUnknown));
    assert_eq!(c(&gpt_image(), 4096), Err(E::PayloadUnknown));
    assert_eq!(c(&gpt_image(), 1024), Err(E::PayloadUnknown));
    assert_eq!(c(&ext4_image(), 4096), Ok(()));
    assert_eq!(
        ntfs::check_payload(&mut Mem(g4.clone()), n - 8, 4096),
        Err(E::PayloadGpt)
    );
    // Partition bounds and contents are in 4 KiB units.
    let mut d = g4.clone();
    d[64 * 4096 + 9 * 1024 + 0x68] = 0;
    assert_eq!(c(&d, 4096), Err(E::PayloadExt4));
    let mut d = g4.clone();
    d[10 * 4096 + 510] = 0;
    assert_eq!(c(&d, 4096), Err(E::PayloadNotFat));
    let mut d = g4;
    d[199 * 4096] = 0;
    assert_eq!(c(&d, 4096), Err(E::PayloadGptBackup));
    // A tiny image is not probed for a 4 KiB LBA 1.
    assert_eq!(
        ntfs::check_payload(&mut Mem(vec![0; 8 * 512]), 8, 4096),
        Err(E::PayloadUnknown)
    );
}

#[test]
fn payload_unknown() {
    assert_eq!(payload(&[], 0), Err(E::PayloadUnknown));
    assert_eq!(payload(&[0; 512], 1), Err(E::PayloadUnknown));
    assert_eq!(check(&[0; 64 * 1024]), Err(E::PayloadUnknown));
    let mut i = iso_image();
    i[16 * 2048 + 1] = b'X';
    assert_eq!(check(&i), Err(E::PayloadUnknown));
    // Not probed past the image.
    assert_eq!(payload(&iso_image(), 64), Err(E::PayloadUnknown));
}

#[test]
fn payload_io() {
    let g = gpt_image();
    for cut in [1, 2, 5, 10, 64 + 2, 64 + 9 * 2, 198, 199] {
        assert_eq!(payload(&g[..cut * 512], 200), Err(E::Io), "cut {cut}");
    }
    let e = ext4_image();
    assert_eq!(payload(&e[..1024], 64), Err(E::Io));
    assert_eq!(payload(&e[..18 * 512], 64), Err(E::Io));
    let i = iso_image();
    assert_eq!(payload(&i[..64 * 512], 80), Err(E::Io));
    assert_eq!(payload(&i[..72 * 512], 80), Err(E::Io));
}

#[test]
fn payload_gpt_structure() {
    let m = |at: usize, v: u64, n: usize| {
        let mut d = gpt_image();
        put(&mut d, at, v, n);
        gpt_crcs(&mut d);
        check(&d)
    };
    assert_eq!(m(512 + 12, 91, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 24, 2, 8), Err(E::PayloadGpt));
    assert_eq!(m(512 + 84, 256, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 80, 0, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 80, 1025, 4), Err(E::PayloadGpt));
    assert_eq!(m(512 + 32, 200, 8), Err(E::PayloadGpt)); // backup past the end
    assert_eq!(m(512 + 48, 199, 8), Err(E::PayloadGpt)); // usable reaches the backup
    assert_eq!(m(512 + 40, 198, 8), Err(E::PayloadGpt)); // first usable > last
    assert_eq!(m(512 + 72, 1, 8), Err(E::PayloadGpt)); // array over the header
    assert_eq!(m(512 + 72, 4, 8), Err(E::PayloadGpt)); // array past first usable
    assert_eq!(m(1024 + 32, 2, 8), Err(E::PayloadGpt)); // partition before usable
    assert_eq!(m(1024 + 40, 198, 8), Err(E::PayloadGpt)); // ... past it
    assert_eq!(m(1024 + 40, 9, 8), Err(E::PayloadGpt)); // reversed
    assert_eq!(payload(&gpt_image(), 199), Err(E::PayloadGpt)); // payload short
}

#[test]
fn payload_gpt_crc() {
    let mut d = gpt_image();
    d[512 + 40] ^= 1;
    assert_eq!(check(&d), Err(E::PayloadGptCrc));
    let mut d = gpt_image();
    d[1024 + 60] ^= 1;
    assert_eq!(check(&d), Err(E::PayloadGptCrc));
    // Bytes past the header size are not covered.
    let mut d = gpt_image();
    d[512 + 100] ^= 1;
    assert_eq!(check(&d), Ok(()));
}

#[test]
fn payload_gpt_backup() {
    let b = 199 * 512;
    let m = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = gpt_image();
        f(&mut d);
        check(&d)
    };
    assert_eq!(m(&|d| d[b] = 0), Err(E::PayloadGptBackup));
    assert_eq!(m(&|d| d[b + 40] ^= 1), Err(E::PayloadGptBackup));
    for (at, v, n) in [
        (12, 96, 4),
        (24, 198, 8),
        (32, 2, 8),
        (40, 4, 8),
        (48, 196, 8),
        (56, 0, 1),
        (80, 8, 4),
        (84, 256, 4),
        (88, 0, 4),
        (72, 197, 8), // array inside the usable range
        (72, 199, 8), // array over the header
        (72, 250, 8), // array past the header (and the image)
    ] {
        assert_eq!(
            m(&|d| {
                put(d, b + at, v, n);
                hdr_crc(d, b);
            }),
            Err(E::PayloadGptBackup),
            "backup field {at}"
        );
    }
    assert_eq!(m(&|d| d[198 * 512 + 3] ^= 1), Err(E::PayloadGptBackup));
}

#[test]
fn payload_gpt_partitions() {
    let m = |f: &dyn Fn(&mut Vec<u8>)| {
        let mut d = gpt_image();
        f(&mut d);
        check(&d)
    };
    let f = 10 * 512;
    assert_eq!(m(&|d| d[f + 510] = 0), Err(E::PayloadNotFat));
    assert_eq!(m(&|d| d[f + 0x36] = b'X'), Err(E::PayloadNotFat));
    assert_eq!(m(&|d| put(d, f + 11, 768, 2)), Err(E::PayloadNotFat));
    assert_eq!(m(&|d| d[f + 13] = 3), Err(E::PayloadNotFat));
    assert_eq!(m(&|d| d[f + 13] = 0), Err(E::PayloadNotFat));
    assert_eq!(m(&|d| put(d, f + 0x13, 41, 2)), Err(E::PayloadNotFat));
    assert_eq!(m(&|d| put(d, f + 0x13, 0, 2)), Err(E::PayloadNotFat));
    // A 32-bit total, and 1 KiB sectors counted as two.
    assert_eq!(
        m(&|d| {
            put(d, f + 0x13, 0, 2);
            put(d, f + 0x20, 40, 4);
        }),
        Ok(())
    );
    assert_eq!(m(&|d| put(d, f + 11, 1024, 2)), Err(E::PayloadNotFat));
    // ext4 in a partition: checked as bare ext4, within the partition.
    let e = 64 * 512;
    assert_eq!(m(&|d| d[e + 9 * 1024 + 0x68] = 0), Err(E::PayloadExt4));
    assert_eq!(m(&|d| put(d, e + 1024 + 4, 33, 4)), Err(E::PayloadExt4));
    // Unknown content in a partition is skipped ...
    assert_eq!(m(&|d| d[e + 1024 + 0x38] = 0), Ok(()));
    // ... but something must verify.
    let none = |d: &mut Vec<u8>| {
        d[e + 1024 + 0x38] = 0;
        d[1024..1040].copy_from_slice(&LINUX);
        gpt_crcs(d);
    };
    assert_eq!(m(&none), Err(E::PayloadNoKnownPartition));
    // A one-sector partition is not probed for ext4.
    let tiny = |d: &mut Vec<u8>| {
        none(d);
        put(d, 1024 + 128 + 40, 65, 8);
        gpt_crcs(d);
    };
    assert_eq!(m(&tiny), Err(E::PayloadNoKnownPartition));
}

#[test]
fn payload_ext4() {
    let m = |at: usize, v: u64, n: usize| {
        let mut d = ext4_image();
        put(&mut d, at, v, n);
        check(&d)
    };
    let (p, b) = (1024, 9 * 1024);
    assert_eq!(m(p + 0x18, 7, 4), Err(E::PayloadExt4));
    assert_eq!(m(p + 0x20, 0, 4), Err(E::PayloadExt4));
    assert_eq!(m(p + 0x14, 2, 4), Err(E::PayloadExt4));
    assert_eq!(m(p + 0x14, 0, 4), Err(E::PayloadExt4)); // group 1 would start at block 8
    assert_eq!(m(p + 4, 0, 4), Err(E::PayloadExt4));
    assert_eq!(m(p + 4, 33, 4), Err(E::PayloadExt4)); // bigger than the payload
    assert_eq!(m(p + 0x20, 40, 4), Err(E::PayloadExt4)); // no group 1
    assert_eq!(m(b + 0x38, 0, 2), Err(E::PayloadExt4));
    assert_eq!(m(b + 0x68, 0, 1), Err(E::PayloadExt4));
    assert_eq!(m(b + 4, 31, 4), Err(E::PayloadExt4));
    assert_eq!(m(b + 0x5a, 3, 2), Err(E::PayloadExt4));
    assert_eq!(m(p + 0x5a, 1, 2), Err(E::PayloadExt4)); // a backup where the primary belongs
    // Three sectors cannot hold a superblock: sector 3 is never read.
    let mut d = ext4_image();
    put(&mut d, p + 0x5c, 0x200, 4);
    assert_eq!(
        ntfs::check_payload(&mut Mem(d[..3 * 512].to_vec()), 3, 512),
        Err(E::PayloadExt4)
    );
    // 4 KiB blocks need first data block 0.
    let mut d = vec![0u8; 64 * 4096];
    ext4_sb(&mut d, 1024, 64, 0);
    put(&mut d, 1024 + 0x18, 2, 4);
    put(&mut d, 1024 + 0x14, 0, 4);
    ext4_sb(&mut d, 8 * 4096, 64, 1);
    put(&mut d, 8 * 4096 + 0x18, 2, 4);
    assert_eq!(check(&d), Ok(()));
    put(&mut d, 1024 + 0x14, 1, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4));
    // 64-bit block counts: the high half is compared too.
    let mut d = ext4_image();
    put(&mut d, p + 0x60, 0x80, 4);
    assert_eq!(check(&d), Ok(()));
    put(&mut d, b + 0x150, 1, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4));
    // Revision 0: feature words ignored.
    let mut d = ext4_image();
    put(&mut d, p + 0x4c, 0, 4);
    put(&mut d, p + 0x5c, 0x200, 4);
    assert_eq!(check(&d), Ok(()));
    // sparse_super2: the backup named by s_backup_bgs[0].
    let mut d = ext4_image();
    put(&mut d, p + 0x5c, 0x200, 4);
    put(&mut d, p + 0x24c, 3, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4)); // group 3 has no copy
    ext4_sb(&mut d, 25 * 1024, 32, 3);
    assert_eq!(check(&d), Ok(()));
    put(&mut d, p + 0x24c, 0, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4));
    put(&mut d, p + 0x24c, 4, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4)); // past the last block
}

/// A single-group ext4 (32 blocks of 1 KiB, 64 per group): no backup; the
/// root directory at inode 2 of the table at block 5 (128-byte inodes).
fn ext4_single() -> Vec<u8> {
    let mut d = vec![0u8; 32 * 1024];
    ext4_sb(&mut d, 1024, 32, 0);
    put(&mut d, 1024 + 0x20, 64, 4);
    put(&mut d, 1024 + 0x28, 16, 4);
    put(&mut d, 1024 + 0x58, 128, 2);
    put(&mut d, 2 * 1024 + 8, 5, 4);
    let i = 5 * 1024 + 128;
    put(&mut d, i, 0x41ed, 2);
    put(&mut d, i + 0x28, 0xf30a, 2);
    d
}

#[test]
fn payload_ext4_single_group() {
    let m = |at: usize, v: u64, n: usize| {
        let mut d = ext4_single();
        put(&mut d, at, v, n);
        check(&d)
    };
    let (p, i) = (1024, 5 * 1024 + 128);
    assert_eq!(check(&ext4_single()), Ok(()));
    assert_eq!(m(i, 0x81a4, 2), Err(E::PayloadExt4)); // a regular file
    assert_eq!(m(i + 0x28, 0xf30b, 2), Err(E::PayloadExt4)); // no extent header
    assert_eq!(m(2 * 1024 + 8, 0, 4), Err(E::PayloadExt4)); // no inode table
    assert_eq!(m(2 * 1024 + 8, 32, 4), Err(E::PayloadExt4)); // past the end
    assert_eq!(m(2 * 1024 + 8, 31, 4), Err(E::PayloadExt4)); // reads zeros there
    assert_eq!(m(p + 0x58, 96, 2), Err(E::PayloadExt4)); // inode size
    assert_eq!(m(p + 0x58, 2048, 2), Err(E::PayloadExt4)); // bigger than a block
    assert_eq!(m(p + 0x28, 1, 4), Err(E::PayloadExt4)); // no inode 2
    assert_eq!(m(p + 4, 2, 4), Err(E::PayloadExt4)); // no room for descriptors
    // Revision 0: 128-byte inodes whatever the field says.
    let mut d = ext4_single();
    put(&mut d, p + 0x4c, 0, 4);
    put(&mut d, p + 0x58, 96, 2);
    assert_eq!(check(&d), Ok(()));
    // 64-bit: descriptors of s_desc_size, the table's high half counts.
    let mut d = ext4_single();
    put(&mut d, p + 0x60, 0x80, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4)); // desc size 0
    put(&mut d, p + 0xfe, 64, 2);
    assert_eq!(check(&d), Ok(()));
    put(&mut d, 2 * 1024 + 0x28, 1, 4);
    assert_eq!(check(&d), Err(E::PayloadExt4));
    // 256-byte inodes: inode 2 at 256.
    let mut d = ext4_single();
    put(&mut d, p + 0x58, 256, 2);
    assert_eq!(check(&d), Err(E::PayloadExt4));
    d.copy_within(5 * 1024 + 128..5 * 1024 + 256, 5 * 1024 + 256);
    assert_eq!(check(&d), Ok(()));
    // Failures at each of the two reads.
    assert_eq!(payload(&ext4_single()[..2 * 1024], 64), Err(E::Io));
    assert_eq!(payload(&ext4_single()[..5 * 1024], 64), Err(E::Io));
}

#[test]
fn payload_iso() {
    let m = |at: usize, v: &[u8]| {
        let mut d = iso_image();
        d[at..at + v.len()].copy_from_slice(v);
        check(&d)
    };
    let p = 16 * 2048;
    assert_eq!(m(p + 6, &[2]), Err(E::PayloadIso));
    assert_eq!(m(p + 84, &[1]), Err(E::PayloadIso));
    assert_eq!(m(p + 131, &[1]), Err(E::PayloadIso));
    assert_eq!(m(p + 128, &[0, 0x10]), Err(E::PayloadIso));
    assert_eq!(m(p + 156, &[33]), Err(E::PayloadIso));
    assert_eq!(m(p + 165, &[19]), Err(E::PayloadIso));
    assert_eq!(m(p + 181, &[0]), Err(E::PayloadIso));
    assert_eq!(m(p + 158, &[0, 0, 0, 0]), Err(E::PayloadIso));
    let mut d = iso_image();
    put(&mut d, p + 158, 20, 4);
    d[p + 162..p + 166].copy_from_slice(&20u32.to_be_bytes());
    assert_eq!(check(&d), Err(E::PayloadIso)); // root past the end
    let r = 18 * 2048;
    assert_eq!(m(r, &[33]), Err(E::PayloadIso));
    assert_eq!(m(r + 2, &[17]), Err(E::PayloadIso));
    assert_eq!(m(r + 25, &[0]), Err(E::PayloadIso));
    assert_eq!(m(r + 32, &[2]), Err(E::PayloadIso));
    assert_eq!(m(r + 33, &[1]), Err(E::PayloadIso));
    assert_eq!(payload(&iso_image(), 79), Err(E::PayloadIso));
    assert_eq!(payload(&iso_image(), 81), Err(E::PayloadIso));
    // 512-byte logical blocks: size counted in them.
    let mut d = iso_image();
    put(&mut d, p + 128, 512, 2);
    d[p + 130..p + 132].copy_from_slice(&512u16.to_be_bytes());
    put(&mut d, p + 80, 80, 4);
    d[p + 84..p + 88].copy_from_slice(&80u32.to_be_bytes());
    put(&mut d, p + 158, 72, 4);
    d[p + 162..p + 166].copy_from_slice(&72u32.to_be_bytes());
    put(&mut d, 72 * 512 + 2, 72, 4);
    d[72 * 512] = 34;
    d[72 * 512 + 25] = 2;
    d[72 * 512 + 32] = 1;
    assert_eq!(check(&d), Ok(()));
}

/// Extents gathered in the wrong order fail the check whenever a sector it
/// reads moved (the full sweep over real images is in paguro-harness).
#[test]
fn payload_misordered() {
    for img in [gpt_image(), ext4_image()] {
        let n = img.len() / 512;
        let q = n / 4;
        // Swap the second and last quarters, then the first and last.
        for (a, b) in [(1, 3), (0, 3)] {
            let mut d = img.clone();
            let (x, y) = (a * q * 512, b * q * 512);
            let tmp = d[x..x + q * 512].to_vec();
            d.copy_within(y..y + q * 512, x);
            d[y..y + q * 512].copy_from_slice(&tmp);
            assert!(check(&d).is_err(), "{a}<->{b}");
        }
    }
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
        E::PayloadNoKnownPartition,
        E::PayloadNotFat,
        E::PayloadGptCrc,
        E::PayloadGptBackup,
        E::PayloadExt4,
        E::PayloadIso,
        E::PayloadUnknown,
    ];
    let mut codes: Vec<i32> = all.iter().map(|e| e.code()).collect();
    codes.sort_unstable();
    codes.dedup();
    assert_eq!(codes.len(), all.len());
    assert!(codes.iter().all(|&c| c > 0 && c < 50));
}
