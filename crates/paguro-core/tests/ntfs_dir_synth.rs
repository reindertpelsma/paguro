//! `paguro_core::ntfs::dir` over synthetic volumes: every error variant,
//! built byte by byte (the real-volume differential tests are in
//! `ntfs_dir.rs`).
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod synth;

use paguro_core::ntfs::dir::{self, Data, DirError as D, FileRef, Scratch, UPCASE_LEN};
use paguro_core::ntfs::{self, MAX_ALIST, NtfsError};
use paguro_core::runlist::Run;
use synth::{Mem, NonRes, Record, Vol, put, resident};

const ZERO: Run = Run { lcn: 0, count: 0 };
const ROOT: u64 = 5;
const UPCASE_LCN: u64 = 4000;
const ALLOC_LCN: u64 = 5000;
const DATA_LCN: u64 = 6000;

fn align8(n: usize) -> usize {
    (n + 7) & !7
}

/// A named resident attribute.
fn named_resident(ty: u32, name: &str, value: &[u8], instance: u16) -> Vec<u8> {
    let n: Vec<u16> = name.encode_utf16().collect();
    let voff = align8(0x18 + 2 * n.len());
    let len = align8(voff + value.len());
    let mut a = vec![0u8; len];
    put(&mut a, 0, ty.into(), 4);
    put(&mut a, 4, len as u64, 4);
    a[9] = n.len() as u8;
    put(&mut a, 0x0a, 0x18, 2);
    put(&mut a, 0x0e, instance.into(), 2);
    put(&mut a, 0x10, value.len() as u64, 4);
    put(&mut a, 0x14, voff as u64, 2);
    for (i, c) in n.iter().enumerate() {
        put(&mut a, 0x18 + 2 * i, (*c).into(), 2);
    }
    a[voff..voff + value.len()].copy_from_slice(value);
    a
}

/// A `FILE_NAME` key.
fn key(name: &str, flags: u32) -> Vec<u8> {
    let n: Vec<u16> = name.encode_utf16().collect();
    let mut k = vec![0u8; 0x42 + 2 * n.len()];
    put(&mut k, 0, ROOT | 5 << 48, 8);
    put(&mut k, 0x30, 1234, 8);
    put(&mut k, 0x38, flags.into(), 4);
    k[0x40] = n.len() as u8;
    k[0x41] = 1;
    for (i, c) in n.iter().enumerate() {
        put(&mut k, 0x42 + 2 * i, (*c).into(), 2);
    }
    k
}

/// An index entry: `file` (record | seq << 48), key (None: the last entry),
/// child VCN.
fn entry(file: u64, k: Option<&[u8]>, child: Option<u64>) -> Vec<u8> {
    let klen = k.map_or(0, <[u8]>::len);
    let len = align8(0x10 + klen) + if child.is_some() { 8 } else { 0 };
    let mut e = vec![0u8; len];
    put(&mut e, 0, file, 8);
    put(&mut e, 8, len as u64, 2);
    put(&mut e, 10, klen as u64, 2);
    let flags = u64::from(child.is_some()) | if k.is_none() { 2 } else { 0 };
    put(&mut e, 12, flags, 2);
    if let Some(k) = k {
        e[0x10..0x10 + klen].copy_from_slice(k);
    }
    if let Some(c) = child {
        put(&mut e, len - 8, c, 8);
    }
    e
}

fn file_entry(rec: u64, name: &str) -> Vec<u8> {
    entry(rec | 7 << 48, Some(&key(name, 0x20)), None)
}

/// An `$INDEX_ROOT` value over `entries` (4 KiB blocks).
fn index_root(entries: &[Vec<u8>], large: bool) -> Vec<u8> {
    let region: Vec<u8> = entries.concat();
    let mut v = vec![0u8; 0x20];
    put(&mut v, 0, 0x30, 4);
    put(&mut v, 4, 1, 4);
    put(&mut v, 8, 4096, 4);
    v[12] = 8;
    put(&mut v, 0x10, 0x10, 4);
    put(&mut v, 0x14, (0x10 + region.len()) as u64, 4);
    put(&mut v, 0x18, (0x10 + region.len()) as u64, 4);
    v[0x1c] = u8::from(large);
    v.extend(region);
    v
}

/// A 4 KiB `INDX` block at `vcn`, update sequence applied.
fn indx(vcn: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    let region: Vec<u8> = entries.concat();
    let mut b = vec![0u8; 4096];
    b[..4].copy_from_slice(b"INDX");
    put(&mut b, 4, 0x28, 2);
    put(&mut b, 6, 9, 2);
    put(&mut b, 0x10, vcn, 8);
    put(&mut b, 0x18, 0x28, 4);
    put(&mut b, 0x1c, (0x28 + region.len()) as u64, 4);
    put(&mut b, 0x20, 4096 - 0x18, 4);
    b[0x40..0x40 + region.len()].copy_from_slice(&region);
    put(&mut b, 0x28, 0x77, 2);
    for i in 1..9 {
        let at = i * 512 - 2;
        b[0x28 + 2 * i] = b[at];
        b[0x28 + 2 * i + 1] = b[at + 1];
        put(&mut b, at, 0x77, 2);
    }
    b
}

fn dir_record(recno: u64, seq: u16, attrs: Vec<Vec<u8>>) -> Record {
    let mut r = Record::file(recno, seq, attrs);
    r.flags = 3;
    r
}

/// The upcase table as bytes (ASCII folding only).
fn upcase_bytes() -> Vec<u8> {
    (0..UPCASE_LEN as u32)
        .flat_map(|c| {
            let u = if (0x61..=0x7a).contains(&c) {
                c - 32
            } else {
                c
            };
            (u as u16).to_le_bytes()
        })
        .collect()
}

/// A volume: `$UpCase`, a root directory whose index is `root` (and, when
/// `blocks` is not empty, an allocation of those INDX blocks with a bitmap
/// marking all in use), and files 30 (`a.efi`, 1000 bytes), 31 (`b`, a
/// directory with an empty index), 32 (`link`, a reparse point).
fn volume(root: Vec<Vec<u8>>, blocks: Vec<Vec<u8>>) -> Vol {
    let mut v = Vol::new();
    let up = NonRes::data(&[(UPCASE_LCN, 256)], 512);
    v.records.insert(
        10,
        Record::file(10, 10, vec![resident(0x10, &[0; 0x48], 0), up.bytes()]),
    );
    v.raw.push((UPCASE_LCN, upcase_bytes()));
    let mut attrs = vec![resident(0x10, &[0; 0x48], 0)];
    attrs.push(named_resident(
        0x90,
        "$I30",
        &index_root(&root, !blocks.is_empty()),
        1,
    ));
    if !blocks.is_empty() {
        let n = blocks.len() as u64;
        let mut a = NonRes::data(&[(ALLOC_LCN, 8 * n)], 512);
        a.ty = 0xa0;
        a.name = "$I30";
        a.instance = 2;
        attrs.push(a.bytes());
        attrs.push(named_resident(0xb0, "$I30", &[0xff; 8], 3));
        v.raw.push((ALLOC_LCN, blocks.concat()));
    }
    v.records.insert(ROOT, dir_record(ROOT, 5, attrs));
    let mut d = NonRes::data(&[(DATA_LCN, 2)], 512);
    d.size = 1000;
    d.init = 1000;
    v.records.insert(
        30,
        Record::file(30, 7, vec![resident(0x10, &[0; 0x48], 0), d.bytes()]),
    );
    v.records.insert(
        31,
        dir_record(
            31,
            7,
            vec![named_resident(
                0x90,
                "$I30",
                &index_root(&[entry(0, None, None)], false),
                1,
            )],
        ),
    );
    v.records
        .insert(32, Record::file(32, 7, vec![resident(0x80, b"x", 0)]));
    v.raw
        .push((DATA_LCN, (0..1024u32).map(|i| i as u8).collect()));
    v
}

fn plain_root() -> Vec<Vec<u8>> {
    vec![
        file_entry(30, "a.efi"),
        entry(31 | 7 << 48, Some(&key("b", 0x1000_0000)), None),
        entry(32 | 7 << 48, Some(&key("link", 0x400)), None),
        entry(0, None, None),
    ]
}

struct T {
    disk: Mem,
    runs: Vec<Run>,
    vol: ntfs::Volume,
    bytes: u64,
    up: Box<[u16; UPCASE_LEN]>,
    s: Box<Scratch>,
}

fn scratch() -> Box<Scratch> {
    let mut b: Box<std::mem::MaybeUninit<Scratch>> = Box::new_uninit();
    // SAFETY: Scratch is integer arrays, zero is valid.
    unsafe {
        std::ptr::write_bytes(b.as_mut_ptr(), 0, 1);
        b.assume_init()
    }
}

impl T {
    fn new(img: Vec<u8>) -> Result<T, D> {
        let mut disk = Mem(img);
        let mut alist = Box::new([0u8; MAX_ALIST]);
        let mut runs = vec![ZERO; 64];
        let m = ntfs::open(&mut disk, &mut alist, &mut runs)?;
        let (vol, n, bytes) = (m.vol, m.runs.len(), m.bytes);
        runs.truncate(n);
        let mut t = T {
            disk,
            runs,
            vol,
            bytes,
            up: vec![0u16; UPCASE_LEN]
                .into_boxed_slice()
                .try_into()
                .unwrap(),
            s: scratch(),
        };
        let mft = ntfs::Mft {
            vol,
            runs: &t.runs,
            bytes,
        };
        dir::load_upcase(&mut t.disk, &mft, &mut t.s, &mut t.up)?;
        Ok(t)
    }
    fn resolve(&mut self, p: &str) -> Result<dir::Found, D> {
        let mft = ntfs::Mft {
            vol: self.vol,
            runs: &self.runs,
            bytes: self.bytes,
        };
        dir::resolve(&mut self.disk, &mft, &self.up, p, &mut self.s)
    }
    fn list(&mut self, d: FileRef) -> Result<Vec<String>, D> {
        let mft = ntfs::Mft {
            vol: self.vol,
            runs: &self.runs,
            bytes: self.bytes,
        };
        let idx = dir::open_index(&mut self.disk, &mft, d, &mut self.s)?;
        let mut out = Vec::new();
        dir::list(&mut self.disk, &mft, &idx, &mut self.s, |e| {
            out.push(String::from_utf16(e.name).unwrap());
            true
        })?;
        Ok(out)
    }
    fn data(&mut self, f: FileRef, res: usize) -> Result<Data, D> {
        let mft = ntfs::Mft {
            vol: self.vol,
            runs: &self.runs,
            bytes: self.bytes,
        };
        let mut r = vec![0u8; res];
        let mut runs = vec![ZERO; 8];
        dir::data(&mut self.disk, &mft, f, &mut self.s, &mut r, &mut runs)
    }
}

fn t(root: Vec<Vec<u8>>, blocks: Vec<Vec<u8>>) -> T {
    T::new(volume(root, blocks).image()).unwrap()
}

fn fr(record: u64, seq: u16) -> FileRef {
    FileRef { record, seq }
}

#[test]
fn a_flat_root() {
    let mut t = t(plain_root(), vec![]);
    assert_eq!(t.resolve("\\A.EFI").unwrap().file, fr(30, 7));
    assert!(t.resolve("\\b").unwrap().is_dir);
    assert_eq!(t.list(FileRef::ROOT).unwrap(), ["a.efi", "b", "link"]);
    assert_eq!(t.list(fr(31, 7)).unwrap(), Vec::<String>::new());
    assert_eq!(
        t.data(fr(30, 7), 0).unwrap(),
        Data::Runs {
            runs: 1,
            size: 1000
        }
    );
    assert_eq!(t.data(fr(32, 7), 16).unwrap(), Data::Resident(1));
    // Refusals of the walk.
    assert_eq!(t.resolve("\\zz").map(|_| ()), Err(D::NotFound));
    assert_eq!(t.resolve("\\0").map(|_| ()), Err(D::NotFound));
    assert_eq!(t.resolve("\\a.efi\\x").map(|_| ()), Err(D::NotDirectory));
    assert_eq!(t.resolve("\\link").map(|_| ()), Err(D::ReparsePoint));
    assert_eq!(t.resolve("a").map(|_| ()), Err(D::BadPath));
    assert_eq!(t.data(fr(31, 7), 0), Err(D::IsDirectory));
    assert_eq!(t.data(fr(32, 7), 0), Err(D::BufferTooSmall));
    assert_eq!(t.data(fr(30, 8), 0), Err(D::Ntfs(NtfsError::Sequence)));
    assert_eq!(t.list(fr(30, 7)), Err(D::NotDirectory));
    // Reads past the end.
    let mut b = [0u8; 8];
    let r = [Run {
        lcn: DATA_LCN,
        count: 2,
    }];
    assert_eq!(
        dir::read_runs(&mut t.disk, &t.vol, &r, 1000, 996, &mut b),
        Err(D::Range)
    );
    assert_eq!(
        dir::read_runs(&mut t.disk, &t.vol, &r, 1000, u64::MAX - 2, &mut b),
        Err(D::Range)
    );
    dir::read_runs(&mut t.disk, &t.vol, &r, 1000, 510, &mut b).unwrap();
    assert_eq!(b, [254, 255, 0, 1, 2, 3, 4, 5]);
}

/// Root → block 0 (a..m) and block 1 (n..z) through child pointers.
fn two_level() -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let root = vec![
        entry(30 | 7 << 48, Some(&key("m.efi", 0x20)), Some(0)),
        entry(0, None, Some(8)),
    ];
    let b0 = indx(0, &[file_entry(30, "c.efi"), entry(0, None, None)]);
    let b1 = indx(8, &[file_entry(30, "x.efi"), entry(0, None, None)]);
    (root, vec![b0, b1])
}

#[test]
fn a_two_level_tree() {
    let (root, blocks) = two_level();
    let mut t = t(root, blocks);
    for p in ["\\m.efi", "\\C.EFI", "\\x.efi"] {
        assert_eq!(t.resolve(p).unwrap().file, fr(30, 7), "{p}");
    }
    assert_eq!(t.resolve("\\d.efi").map(|_| ()), Err(D::NotFound));
    let mut l = t.list(FileRef::ROOT).unwrap();
    l.sort();
    assert_eq!(l, ["c.efi", "m.efi", "x.efi"]);
}

fn err(root: Vec<Vec<u8>>, blocks: Vec<Vec<u8>>, path: &str) -> D {
    let mut t = t(root, blocks);
    t.resolve(path).map(|_| ()).unwrap_err()
}

#[test]
fn index_block_refusals() {
    let (root, mut blocks) = two_level();
    // Not INDX.
    blocks[1][0] = b'X';
    assert_eq!(err(root.clone(), blocks, "\\x.efi"), D::IndexBlock);
    // A torn block.
    let (root, mut blocks) = two_level();
    blocks[1][1022] ^= 1;
    assert_eq!(err(root.clone(), blocks, "\\x.efi"), D::IndexFixup);
    // Wrong update-sequence count.
    let (root, mut blocks) = two_level();
    blocks[1][6] = 3;
    assert_eq!(err(root.clone(), blocks, "\\x.efi"), D::IndexFixup);
    // The block records another VCN.
    let (root, mut blocks) = two_level();
    blocks[1][0x10] = 16;
    assert_eq!(err(root.clone(), blocks, "\\x.efi"), D::IndexVcn);
    // A child outside the allocation, or not block-aligned.
    for bad in [16u64, 3, u64::MAX] {
        let (mut root, blocks) = two_level();
        root[1] = entry(0, None, Some(bad));
        assert_eq!(err(root, blocks, "\\x.efi"), D::IndexBlock, "{bad}");
    }
    // A node header out of shape (length past the allocation).
    let (root, mut blocks) = two_level();
    put(&mut blocks[1], 0x1c, 5000, 4);
    assert_eq!(err(root.clone(), blocks, "\\x.efi"), D::IndexEntry);
    // Entries overlapping the update sequence array.
    let (root, mut blocks) = two_level();
    put(&mut blocks[1], 0x18, 0x10, 4);
    put(&mut blocks[1], 0x1c, 0x20, 4);
    assert_eq!(err(root, blocks, "\\x.efi"), D::IndexEntry);
}

#[test]
fn loops_are_bounded() {
    // Block 0 points at itself: the walk stops at MAX_DEPTH.
    let root = vec![entry(0, None, Some(0))];
    let blocks = vec![indx(0, &[entry(0, None, Some(0))])];
    assert_eq!(err(root, blocks, "\\x"), D::TooDeep);
}

#[test]
fn entry_refusals() {
    let bad = |mutate: &dyn Fn(&mut Vec<u8>)| {
        let mut e = file_entry(30, "a.efi");
        mutate(&mut e);
        err(vec![e, entry(0, None, None)], vec![], "\\zz")
    };
    assert_eq!(bad(&|e| put(e, 8, 0x0c, 2)), D::IndexEntry); // too short
    assert_eq!(bad(&|e| put(e, 8, 0x13, 2)), D::IndexEntry); // unaligned
    assert_eq!(bad(&|e| put(e, 8, 0x4000, 2)), D::IndexEntry); // past the node
    assert_eq!(bad(&|e| put(e, 10, 0x20, 2)), D::IndexEntry); // key too short
    assert_eq!(bad(&|e| put(e, 10, 0x400, 2)), D::IndexEntry); // key past entry
    assert_eq!(bad(&|e| e[0x10 + 0x40] = 0), D::IndexEntry); // empty name
    assert_eq!(bad(&|e| e[0x10 + 0x40] = 200), D::IndexEntry); // name past key
    assert_eq!(bad(&|e| put(e, 12, 1, 2)), D::IndexEntry); // subnode, but no room
    // No terminating entry.
    assert_eq!(
        err(vec![file_entry(30, "a.efi")], vec![], "\\zz"),
        D::IndexEntry
    );
    // A child pointer with no allocation.
    assert_eq!(
        err(vec![entry(0, None, Some(0))], vec![], "\\zz"),
        D::IndexAllocation
    );
    // Node regions pure-parsed: nothing panics on junk.
    for n in [0usize, 1, 15, 16, 17, 64] {
        let _ = dir::node_entries(&vec![0xffu8; n], |_| Ok(true));
    }
}

fn with_root_attr(mutate: impl Fn(&mut Vol)) -> Result<T, D> {
    let mut v = volume(plain_root(), vec![]);
    mutate(&mut v);
    T::new(v.image())
}

#[test]
fn index_root_refusals() {
    let root_with = |value: Vec<u8>| {
        with_root_attr(|v| {
            v.records.insert(
                ROOT,
                dir_record(ROOT, 5, vec![named_resident(0x90, "$I30", &value, 1)]),
            );
        })
        .unwrap()
        .resolve("\\a.efi")
        .map(|_| ())
        .unwrap_err()
    };
    let good = index_root(&plain_root(), false);
    let mut v = good.clone();
    v[0] = 0x10; // not a file-name index
    assert_eq!(root_with(v), D::IndexRoot);
    let mut v = good.clone();
    v[4] = 2; // other collation
    assert_eq!(root_with(v), D::IndexRoot);
    for bs in [0u64, 100, 256, 3000, 1 << 17] {
        let mut v = good.clone();
        put(&mut v, 8, bs, 4);
        assert_eq!(root_with(v), D::BlockSize, "{bs}");
    }
    assert_eq!(root_with(good[..0x18].to_vec()), D::IndexRoot);
    let mut v = good.clone();
    put(&mut v, 0x14, 0x1000, 4);
    assert_eq!(root_with(v), D::IndexEntry);
    // No $I30 root, or a differently named one.
    let mut t = with_root_attr(|v| {
        v.records.insert(
            ROOT,
            dir_record(ROOT, 5, vec![named_resident(0x90, "$X30", &good, 1)]),
        );
    })
    .unwrap();
    assert_eq!(t.resolve("\\a.efi").map(|_| ()), Err(D::IndexRoot));
    // Large index flag with no allocation attribute.
    let mut t = with_root_attr(|v| {
        v.records.insert(
            ROOT,
            dir_record(
                ROOT,
                5,
                vec![named_resident(
                    0x90,
                    "$I30",
                    &index_root(&plain_root(), true),
                    1,
                )],
            ),
        );
    })
    .unwrap();
    assert_eq!(t.resolve("\\a.efi").map(|_| ()), Err(D::IndexAllocation));
    // A duplicate root.
    let mut t = with_root_attr(|v| {
        v.records.insert(
            ROOT,
            dir_record(
                ROOT,
                5,
                vec![
                    named_resident(0x90, "$I30", &good, 1),
                    named_resident(0x90, "$I30", &good, 2),
                ],
            ),
        );
    })
    .unwrap();
    assert_eq!(
        t.resolve("\\a.efi").map(|_| ()),
        Err(D::Ntfs(NtfsError::DuplicateData))
    );
}

#[test]
fn allocation_and_bitmap_refusals() {
    let (root, blocks) = two_level();
    let make = |alloc_clusters: u64, bitmap: &[u8]| {
        let mut v = volume(root.clone(), blocks.clone());
        let mut a = NonRes::data(&[(ALLOC_LCN, alloc_clusters)], 512);
        a.ty = 0xa0;
        a.name = "$I30";
        a.instance = 2;
        let mut attrs = vec![
            resident(0x10, &[0; 0x48], 0),
            named_resident(0x90, "$I30", &index_root(&root, true), 1),
            a.bytes(),
        ];
        if !bitmap.is_empty() {
            attrs.push(named_resident(0xb0, "$I30", bitmap, 3));
        }
        v.records.insert(ROOT, dir_record(ROOT, 5, attrs));
        T::new(v.image()).unwrap()
    };
    // Not a whole number of blocks.
    assert_eq!(
        make(12, &[3]).resolve("\\x.efi").map(|_| ()),
        Err(D::IndexAllocation)
    );
    // No bitmap: lookup works, listing refuses.
    let mut t = make(16, &[]);
    assert!(t.resolve("\\x.efi").is_ok());
    assert_eq!(t.list(FileRef::ROOT), Err(D::Bitmap));
    // Only block 1 in use: block 0's names are stale, not listed.
    let mut t = make(16, &[2]);
    let mut l = t.list(FileRef::ROOT).unwrap();
    l.sort();
    assert_eq!(l, ["m.efi", "x.efi"]);
    // Too many blocks.
    let big = (dir::MAX_INDEX_BLOCKS + 1) * 8;
    let mut v = volume(root.clone(), blocks.clone());
    v.clusters = big + 10;
    let mut a = NonRes::data(&[(1, big)], 512);
    a.ty = 0xa0;
    a.name = "$I30";
    a.instance = 2;
    v.records.insert(
        ROOT,
        dir_record(
            ROOT,
            5,
            vec![
                named_resident(0x90, "$I30", &index_root(&root, true), 1),
                a.bytes(),
            ],
        ),
    );
    // (a volume that large is not built in memory: only its first 4 MiB)
    let mut t = T::new(v.image_prefix(8192 * 512)).unwrap();
    assert_eq!(t.resolve("\\x.efi").map(|_| ()), Err(D::TooLarge));
}

#[test]
fn upcase_refusals() {
    // Wrong size.
    let mut v = volume(plain_root(), vec![]);
    let up = NonRes::data(&[(UPCASE_LCN, 128)], 512);
    v.records.insert(10, Record::file(10, 10, vec![up.bytes()]));
    assert_eq!(T::new(v.image()).map(|_| ()).unwrap_err(), D::Upcase);
    // Resident.
    let mut v = volume(plain_root(), vec![]);
    v.records
        .insert(10, Record::file(10, 10, vec![resident(0x80, b"AB", 0)]));
    assert_eq!(T::new(v.image()).map(|_| ()).unwrap_err(), D::Upcase);
    // Not a collation table.
    let mut v = volume(plain_root(), vec![]);
    v.raw.retain(|r| r.0 != UPCASE_LCN);
    v.raw.push((UPCASE_LCN, vec![0; 2 * UPCASE_LEN]));
    assert_eq!(T::new(v.image()).map(|_| ()).unwrap_err(), D::Upcase);
    // Missing.
    let mut v = volume(plain_root(), vec![]);
    v.records.remove(&10);
    assert!(matches!(
        T::new(v.image()).map(|_| ()).unwrap_err(),
        D::Ntfs(_)
    ));
}

#[test]
fn hibernation_header() {
    for (h, want) in [
        (&b"hibr"[..], true),
        (b"HIBR", true),
        (b"rstr", true),
        (b"RSTR", true),
        (b"wake", false),
        (b"WAKE", false),
        (b"\0\0\0\0", false),
        (b"hib", false),
        (b"", false),
    ] {
        assert_eq!(dir::hibernation_active(h), want, "{h:?}");
    }
}

#[test]
fn collation_is_by_upcase_then_length() {
    let up: Box<[u16; UPCASE_LEN]> = {
        let mut t = vec![0u16; UPCASE_LEN];
        for (i, u) in t.iter_mut().enumerate() {
            *u = if (0x61..=0x7a).contains(&i) {
                i as u16 - 32
            } else {
                i as u16
            };
        }
        t.into_boxed_slice().try_into().unwrap()
    };
    let w = |s: &str| s.encode_utf16().collect::<Vec<u16>>();
    use std::cmp::Ordering::*;
    assert_eq!(dir::collate(&up, &w("abc"), &w("ABC")), Equal);
    assert_eq!(dir::collate(&up, &w("ab"), &w("abc")), Less);
    // After upcasing 'a' is 0x41, below '_' (0x5f): the order Windows uses.
    assert_eq!(dir::collate(&up, &w("_"), &w("a")), Greater);
}

trait Prefix {
    fn image_prefix(&self, len: usize) -> Vec<u8>;
}

impl Prefix for Vol {
    fn image_prefix(&self, len: usize) -> Vec<u8> {
        let mut small = self.clone();
        let clusters = small.clusters;
        small.clusters = (len / 512) as u64;
        let mut img = small.image();
        // The boot sector still declares the full size.
        put(&mut img, 0x28, clusters, 8);
        img
    }
}

mod prop {
    use super::*;
    use proptest::prelude::*;

    /// A two-level tree over `names` (sorted by the ASCII collation): leaf
    /// blocks of up to `per` names, separated by root entries.
    fn tree(names: &[String], per: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut root = Vec::new();
        let mut blocks = Vec::new();
        let mut it = names.iter().enumerate().peekable();
        let mut vcn = 0u64;
        while it.peek().is_some() {
            let leaf: Vec<(usize, &String)> = it.by_ref().take(per).collect();
            let mut es: Vec<Vec<u8>> = leaf
                .iter()
                .map(|(i, n)| file_entry(100 + *i as u64, n))
                .collect();
            es.push(entry(0, None, None));
            blocks.push(indx(vcn, &es));
            match it.next() {
                Some((i, sep)) => root.push(entry(
                    (100 + i as u64) | 7 << 48,
                    Some(&key(sep, 0x20)),
                    Some(vcn),
                )),
                None => root.push(entry(0, None, Some(vcn))),
            }
            vcn += 8;
        }
        // The last separator had no names after it: terminate plainly.
        if root.last().is_none_or(|e| e[12] & 2 == 0) {
            root.push(entry(0, None, None));
        }
        (root, blocks)
    }

    fn upper(s: &str) -> String {
        s.to_ascii_uppercase()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]
        #[test]
        fn lookup_finds_every_name_and_list_lists_them(
            raw in proptest::collection::btree_set("[a-z0-9._-]{1,12}", 1..30),
            per in 5usize..10,
            probe in "[a-z0-9._-]{1,12}",
        ) {
            // ASCII-only upcase: sort by the upcased form (equal to sorting
            // lower-case names by bytes, but '_' etc. land after letters).
            prop_assume!(probe != "." && probe != "..");
            let mut names: Vec<String> = raw.into_iter().filter(|n| n != "." && n != "..").collect();
            prop_assume!(!names.is_empty());
            names.sort_by_key(|n| upper(n));
            names.dedup_by_key(|n| upper(n));
            let (root, blocks) = tree(&names, per);
            let mut v = volume(root, blocks.clone());
            // Records for every file the tree names (they must exist).
            for i in 0..names.len() as u64 {
                v.records.insert(100 + i, Record::file(100 + i, 7, vec![resident(0x80, b"x", 0)]));
            }
            // More index blocks than volume() sized for: redo its allocation.
            let n = blocks.len() as u64;
            let mut a = NonRes::data(&[(ALLOC_LCN, 8 * n)], 512);
            a.ty = 0xa0;
            a.name = "$I30";
            a.instance = 2;
            let (root, _) = tree(&names, per);
            let large = !blocks.is_empty();
            v.records.insert(ROOT, dir_record(ROOT, 5, vec![
                named_resident(0x90, "$I30", &index_root(&root, large), 1),
                a.bytes(),
                named_resident(0xb0, "$I30", &[0xff; 8], 3),
            ]));
            let mut t = T::new(v.image()).unwrap();
            for (i, name) in names.iter().enumerate() {
                let f = t.resolve(&format!("\\{}", upper(name))).unwrap();
                prop_assert_eq!(f.file, fr(100 + i as u64, 7));
            }
            let found = t.resolve(&format!("\\{probe}"));
            let present = names.iter().any(|n| upper(n) == upper(&probe));
            prop_assert_eq!(found.is_ok(), present);
            let mut l = t.list(FileRef::ROOT).unwrap();
            l.sort_by_key(|n| upper(n));
            prop_assert_eq!(l, names);
        }
    }
}
