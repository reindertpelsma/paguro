//! Differential testing of the kernel module's NTFS core (`pg_ntfs.c`,
//! `pg_claim.c`) against the Rust specification (`paguro_core::ntfs`), the
//! way kernel filesystems are tested against damaged images:
//!
//! - the named-corruption corpus in `test/fixtures/ntfs/manifest.txt`
//!   (e2fsprogs `f_*` style), each with the error both must return;
//! - exhaustive single-byte mutation of every sector either parser reads;
//! - truncation at every read sector and every 16 bytes within one;
//! - I/O failure at every read, torn sectors, and data that changes when
//!   re-read (a concurrent writer);
//! - fuzz corpora and random mutation of synthetic volumes.
//!
//! "Agree" always means: same result or same error, **and the same sequence
//! of sector reads**.

// Test tooling: an out-of-range index here is a harness bug worth a panic.
#![allow(clippy::indexing_slicing)]

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use paguro_core::ntfs::{self, Disk, IoError, NtfsError};
use paguro_core::range::{Extent, RangeSet};

use crate::cntfs::{self, Derived, Out, SparseDisk, Trace};
use crate::synth::{self, NonRes, Record, USER, Vol};

const IO: i32 = 1;

/// A borrowed image as a disk; reads past the end fail.
pub struct Slice<'a>(pub &'a [u8]);

impl Disk for Slice<'_> {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), IoError> {
        let at = usize::try_from(sector).map_err(|_| IoError)?;
        let src = at
            .checked_mul(512)
            .and_then(|o| self.0.get(o..o.checked_add(512)?))
            .ok_or(IoError)?;
        buf.copy_from_slice(src);
        Ok(())
    }
}

/// Run both implementations over fresh disks from `mk`; they must agree on
/// the result and on every sector read. Returns the result and the reads.
pub fn both<D: Disk>(
    mut mk: impl FnMut() -> D,
    rec: u64,
    seq: u16,
) -> Result<(Out, Vec<u64>), String> {
    let mut d = mk();
    let mut t = Trace {
        inner: &mut d,
        reads: Vec::new(),
    };
    let r = cntfs::rust_file(&mut t, rec, seq);
    let rust_reads = t.reads;
    let mut d = mk();
    let mut t = Trace {
        inner: &mut d,
        reads: Vec::new(),
    };
    let c = cntfs::c_file(&mut t, rec, seq);
    if r != c {
        return Err(format!(
            "rec {rec} seq {seq}: Rust {} vs C {}",
            show(&r),
            show(&c)
        ));
    }
    if rust_reads != t.reads {
        return Err(format!(
            "rec {rec}: same result, different reads: Rust {:?} vs C {:?}",
            rust_reads, t.reads
        ));
    }
    Ok((r, rust_reads))
}

pub fn both_flags<D: Disk>(mut mk: impl FnMut() -> D) -> Result<Result<u16, i32>, String> {
    let r = cntfs::rust_flags(&mut mk());
    let c = cntfs::c_flags(&mut mk());
    if r != c {
        return Err(format!("volume flags: Rust {r:?} vs C {c:?}"));
    }
    Ok(r)
}

fn show(o: &Out) -> String {
    match o {
        Ok(d) => format!("ok({} extents, {} bytes)", d.extents.len(), d.size),
        Err(e) => cntfs::error_name(*e),
    }
}

pub fn fnv(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x100_0000_01b3)
    })
}

/// The file's bytes, read through its extents (view A's gather).
pub fn gathered(img: &[u8], d: &Derived) -> Vec<u8> {
    let mut out = Vec::new();
    for e in &d.extents {
        out.extend_from_slice(
            img.get(e.start as usize * 512..e.end as usize * 512)
                .unwrap_or(&[]),
        );
    }
    out.truncate(d.size as usize);
    out
}

// ---- fixtures -------------------------------------------------------------

pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/ntfs")
}

/// One manifest line.
#[derive(Clone, Debug)]
pub struct Case {
    pub kind: String,
    pub name: String,
    pub image: String,
    pub rec: u64,
    pub seq: u16,
    pub expect: String,
    pub patches: Vec<(usize, u8)>,
    pub reserved: Vec<(u64, u64)>,
}

pub fn manifest() -> Vec<Case> {
    let text = std::fs::read_to_string(fixture_dir().join("manifest.txt")).unwrap_or_default();
    let mut out = Vec::new();
    for line in text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let t: Vec<&str> = line.split_whitespace().collect();
        let (Some(kind), Some(name), Some(image), Some(rec), Some(seq), Some(expect)) =
            (t.first(), t.get(1), t.get(2), t.get(3), t.get(4), t.get(5))
        else {
            continue;
        };
        let mut case = Case {
            kind: kind.to_string(),
            name: name.to_string(),
            image: image.to_string(),
            rec: rec.parse().unwrap_or(0),
            seq: seq.parse().unwrap_or(0),
            expect: expect.to_string(),
            patches: Vec::new(),
            reserved: Vec::new(),
        };
        for tok in t.iter().skip(6) {
            if let Some(r) = tok.strip_prefix('R') {
                let (s, l) = r.split_once('+').unwrap_or(("0", "0"));
                case.reserved
                    .push((s.parse().unwrap_or(0), l.parse().unwrap_or(0)));
            } else if let Some((o, v)) = tok.split_once('=') {
                case.patches.push((
                    o.parse().unwrap_or(0),
                    u8::from_str_radix(v, 16).unwrap_or(0),
                ));
            }
        }
        out.push(case);
    }
    out
}

/// A fixture volume (by manifest name, or a path to a `.gz`), decompressed
/// once per process.
pub fn image(name: &str) -> Vec<u8> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<u8>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut c = cache.lock().unwrap_or_else(|e| e.into_inner());
    c.entry(name.to_string())
        .or_insert_with(|| {
            let path = if name.contains('/') {
                PathBuf::from(format!("{name}.gz"))
            } else {
                fixture_dir().join(format!("{name}.gz"))
            };
            std::process::Command::new("gzip")
                .arg("-dc")
                .arg(&path)
                .output()
                .map(|o| o.stdout)
                .unwrap_or_default()
        })
        .clone()
}

pub fn patched(c: &Case) -> Vec<u8> {
    let mut img = image(&c.image);
    for &(o, v) in &c.patches {
        if let Some(b) = img.get_mut(o) {
            *b = v;
        }
    }
    img
}

/// The reserved-range test, both ways: normalise (Rust `RangeSet`, C
/// `pg_range_normalise`) and intersect with the claim's normalised extents.
fn reserved_hit(file: &[Extent], reserved: &[(u64, u64)]) -> Result<bool, String> {
    let mut set: RangeSet<8> = RangeSet::new();
    let mut raw = Vec::new();
    for &(s, l) in reserved {
        let e = Extent::new(s, l).ok_or("empty reserved range")?;
        set.insert(e).map_err(|e| format!("{e:?}"))?;
        raw.push(e);
    }
    if cntfs::c_range_normalise(&raw) != set.as_slice() {
        return Err("reserved ranges normalise differently".into());
    }
    let mut norm = vec![Extent { start: 0, end: 0 }; file.len()];
    let n = ntfs::normalise(file, &mut norm).map_err(|e| format!("{e:?}"))?;
    norm.truncate(n);
    if cntfs::c_normalise(file, file.len()) != Ok(norm.clone()) {
        return Err("claim normalises differently".into());
    }
    let r = ntfs::intersects(&norm, set.as_slice());
    if cntfs::c_intersects(&norm, set.as_slice()) != r {
        return Err("intersection differs".into());
    }
    Ok(r)
}

/// Run one manifest case through both implementations and check it.
pub fn check_case(c: &Case) -> Result<(), String> {
    let img = patched(c);
    if img.is_empty() {
        return Err(format!("{}: fixture {} missing", c.name, c.image));
    }
    let got = if c.kind == "volume" {
        match both_flags(|| Slice(&img))? {
            Ok(f) => format!("flags:{f:04x}"),
            Err(e) => cntfs::error_name(e),
        }
    } else {
        let (out, _) = both(|| Slice(&img), c.rec, c.seq)?;
        match out {
            Err(e) => cntfs::error_name(e),
            Ok(d) if reserved_hit(&d.extents, &c.reserved)? => "Reserved".into(),
            Ok(d) => {
                let data = gathered(&img, &d);
                let sectors = d.size / 512;
                let r = ntfs::check_payload(&mut Slice(&data), sectors).map_err(NtfsError::code);
                if cntfs::c_payload(&mut Slice(&data), sectors) != r {
                    return Err(format!("{}: payload check differs", c.name));
                }
                let p = if r.is_ok() { "gpt" } else { "-" };
                format!("ok:{}:{:016x}:{p}", d.size, fnv(&data))
            }
        }
    };
    if got != c.expect {
        return Err(format!("{}: expected {}, got {got}", c.name, c.expect));
    }
    Ok(())
}

// ---- damage ---------------------------------------------------------------

fn variants(orig: u8, rng: &mut u64) -> Vec<u8> {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    let mut v: Vec<u8> = (0..8).map(|b| orig ^ (1 << b)).collect();
    v.extend([0x00, 0xff, *rng as u8]);
    v.retain(|&x| x != orig);
    v
}

/// Statistics from a damage run.
#[derive(Debug, Default)]
pub struct Tally {
    pub runs: usize,
    pub refused: usize,
    pub same_map: usize,
    /// Accepted with a different map: possible for a runlist byte (the map
    /// *is* those bytes); the ntfs3 cross-check and payload check exist for
    /// this.
    pub other_map: usize,
}

impl Tally {
    fn add(&mut self, clean: &Out, got: &Out) {
        self.runs += 1;
        match got {
            Err(_) => self.refused += 1,
            Ok(_) if got == clean => self.same_map += 1,
            Ok(_) => self.other_map += 1,
        }
    }
}

/// Every byte (every `stride`-th) of every sector the clean parse reads, set
/// to each bit flip, 0x00, 0xff and a random value.
pub fn mutate_bytes(img: &[u8], rec: u64, seq: u16, stride: usize) -> Result<Tally, String> {
    let (clean, reads) = both(|| Slice(img), rec, seq)?;
    let mut sectors = reads;
    sectors.sort_unstable();
    sectors.dedup();
    let mut work = img.to_vec();
    let mut t = Tally::default();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64 ^ rec;
    for s in sectors {
        for off in (0..512).step_by(stride) {
            let at = s as usize * 512 + off;
            let Some(&orig) = work.get(at) else { continue };
            for v in variants(orig, &mut rng) {
                if let Some(b) = work.get_mut(at) {
                    *b = v;
                }
                let (got, _) = both(|| Slice(&work), rec, seq)
                    .map_err(|e| format!("byte {at}={v:#x}: {e}"))?;
                t.add(&clean, &got);
            }
            if let Some(b) = work.get_mut(at) {
                *b = orig;
            }
        }
    }
    Ok(t)
}

/// The image cut short at every sector the parse reads, and every read
/// sector zero-filled from every 16th byte on (a truncated structure).
pub fn truncations(img: &[u8], rec: u64, seq: u16) -> Result<Tally, String> {
    let (clean, reads) = both(|| Slice(img), rec, seq)?;
    let mut sectors = reads;
    sectors.sort_unstable();
    sectors.dedup();
    let mut t = Tally::default();
    for &s in &sectors {
        let cut = img.get(..s as usize * 512).unwrap_or(img);
        let (got, _) = both(|| Slice(cut), rec, seq)?;
        if got != Err(IO) {
            return Err(format!("cut at sector {s}: {}", show(&got)));
        }
        t.add(&clean, &got);
    }
    let mut work = img.to_vec();
    for &s in &sectors {
        let base = s as usize * 512;
        let orig: Vec<u8> = work.get(base..base + 512).unwrap_or(&[]).to_vec();
        for k in (0..512).step_by(16) {
            for b in work.get_mut(base + k..base + 512).unwrap_or(&mut []) {
                *b = 0;
            }
            let (got, _) = both(|| Slice(&work), rec, seq)?;
            t.add(&clean, &got);
            if let Some(dst) = work.get_mut(base..base + 512) {
                dst.copy_from_slice(&orig);
            }
        }
    }
    Ok(t)
}

/// The n-th read (counting from 0) misbehaves; everything else is `inner`.
pub struct Faulty<'a> {
    pub inner: Slice<'a>,
    pub at: usize,
    pub calls: usize,
    pub mode: Fault,
    pub seen: HashMap<u64, usize>,
}

#[derive(Clone, Copy, Debug)]
pub enum Fault {
    /// The read fails.
    Fail,
    /// It succeeds with the second half of the sector zeroed (a torn 512e
    /// write, or a short read reported as whole).
    Torn,
    /// Every re-read of a sector after the first returns different bytes
    /// (a concurrent writer); `at` picks which byte changes.
    Reread,
}

impl Faulty<'_> {
    pub fn new(img: &[u8], at: usize, mode: Fault) -> Faulty<'_> {
        Faulty {
            inner: Slice(img),
            at,
            calls: 0,
            mode,
            seen: HashMap::new(),
        }
    }
}

impl Disk for Faulty<'_> {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), IoError> {
        let n = self.calls;
        self.calls += 1;
        match self.mode {
            Fault::Fail if n == self.at => Err(IoError),
            Fault::Torn if n == self.at => {
                self.inner.read(sector, buf)?;
                buf[256..].fill(0);
                Ok(())
            }
            Fault::Reread => {
                self.inner.read(sector, buf)?;
                let seen = self.seen.entry(sector).or_insert(0);
                if *seen > 0 {
                    buf[self.at % 512] ^= 0x5a;
                }
                *seen += 1;
                Ok(())
            }
            _ => self.inner.read(sector, buf),
        }
    }
}

/// Failure at every read must refuse with `Io`; torn and changing reads must
/// agree between the two implementations.
pub fn faults(img: &[u8], rec: u64, seq: u16) -> Result<[Tally; 3], String> {
    let (clean, reads) = both(|| Slice(img), rec, seq)?;
    let mut t = [Tally::default(), Tally::default(), Tally::default()];
    for n in 0..reads.len() {
        let (got, _) = both(|| Faulty::new(img, n, Fault::Fail), rec, seq)?;
        if got != Err(IO) {
            return Err(format!("failure at read {n}: {}", show(&got)));
        }
        t[0].add(&clean, &got);
        let (got, _) = both(|| Faulty::new(img, n, Fault::Torn), rec, seq)?;
        t[1].add(&clean, &got);
    }
    for at in (0..512).step_by(7) {
        let (got, _) = both(|| Faulty::new(img, at, Fault::Reread), rec, seq)?;
        t[2].add(&clean, &got);
    }
    Ok(t)
}

// ---- synthetic volumes ------------------------------------------------------

/// A spread of synthetic volumes: plain, fragmented `$MFT`, attribute
/// lists resident and not, big clusters, 4 KiB sectors.
pub fn synthetic() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut v = Vol::new();
    v.add_file(USER, &[(1000, 8), (3000, 4), (3004, 1)]);
    out.push(("simple".into(), v.image()));
    let mut mft = vec![(100u64, 32u64)];
    mft.extend((0..64).map(|i| (200 + 7 * i, 1)));
    let mut v = Vol::with(512, 1, 1024, 8192, mft);
    v.add_file(USER, &[(4000, 2), (5000, 3)]);
    out.push(("fragmented_mft".into(), v.image()));
    let mut v = Vol::with(4096, 16, 4096, 256, vec![(4, 2)]);
    v.add_file(USER, &[(100, 3), (50, 1)]);
    out.push(("4kn".into(), v.image()));
    for (n, nonres) in [(3u64, false), (8, true)] {
        out.push((format!("listed{n}"), listed(n, nonres).image()));
    }
    out
}

/// A file split over the base record and `n` extension records.
pub fn listed(n: u64, nonresident: bool) -> Vol {
    let mut v = Vol::new();
    let mut entries = synth::alist_entry(0x10, 0, USER, 7, 0);
    let mut base = NonRes::data(&[(1000, 2)], 512);
    base.alloc = (2 + 2 * n) * 512;
    base.size = base.alloc;
    base.init = base.alloc;
    entries.extend(synth::alist_entry(0x80, 0, USER, 7, 1));
    for i in 0..n {
        let r = USER + 1 + i;
        let seg = NonRes::segment(2 + 2 * i, &[(2000 + 10 * i, 2)], 3);
        v.records
            .insert(r, Record::extension(r, (USER, 7), vec![seg.bytes()]));
        entries.extend(synth::alist_entry(0x80, 2 + 2 * i, r, 1, 3));
    }
    let si = synth::resident(0x10, &[0u8; 0x48], 0);
    let list = if nonresident {
        let clusters = (entries.len() as u64).div_ceil(512);
        let mut a = NonRes::data(&[(6000, clusters)], 512);
        a.ty = 0x20;
        a.size = entries.len() as u64;
        a.init = a.size;
        v.raw.push((6000, entries));
        a.bytes()
    } else {
        synth::resident(0x20, &entries, 2)
    };
    v.records
        .insert(USER, Record::file(USER, 7, vec![si, list, base.bytes()]));
    v
}

/// Random multi-byte mutation of synthetic volumes; both must agree.
pub fn random_synthetic(rounds: u64, seed: u64) -> Result<(), String> {
    let vols = synthetic();
    let mut rng = seed | 1;
    let mut next = |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n.max(1)
    };
    let reads: Vec<Vec<u64>> = vols
        .iter()
        .map(|(_, img)| both(|| Slice(img), USER, 7).map(|(_, r)| r))
        .collect::<Result<_, _>>()?;
    for round in 0..rounds {
        let i = next(vols.len() as u64) as usize;
        let (name, img) = &vols[i];
        let mut work = img.clone();
        for _ in 0..1 + next(4) {
            let s = reads[i][next(reads[i].len() as u64) as usize];
            let at = s as usize * 512 + next(512) as usize;
            work[at] = next(256) as u8;
        }
        let _ =
            both(|| Slice(&work), USER, 7).map_err(|e| format!("round {round} ({name}): {e}"))?;
    }
    Ok(())
}

/// Random claim-level inputs: normalise, intersects, grows, coalesce, gather.
pub fn random_claims(rounds: u64, seed: u64) -> Result<(), String> {
    let mut rng = seed | 1;
    let mut next = |n: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % n.max(1)
    };
    for round in 0..rounds {
        let list = |next: &mut dyn FnMut(u64) -> u64| {
            (0..next(8))
                .map(|_| {
                    let s = next(200);
                    Extent {
                        start: s,
                        end: s + next(12),
                    }
                })
                .collect::<Vec<_>>()
        };
        let (a, b) = (list(&mut next), list(&mut next));
        let cap = next(10) as usize;
        let mut out = vec![Extent { start: 0, end: 0 }; cap];
        let r = ntfs::normalise(&a, &mut out)
            .map(|n| out[..n].to_vec())
            .map_err(NtfsError::code);
        if r != cntfs::c_normalise(&a, cap) {
            return Err(format!("round {round}: normalise {a:?}"));
        }
        let (na, nb) = (cntfs::c_range_normalise(&a), cntfs::c_range_normalise(&b));
        if ntfs::intersects(&na, &nb) != cntfs::c_intersects(&na, &nb) {
            return Err(format!("round {round}: intersects {na:?} {nb:?}"));
        }
        if ntfs::grows(&a, &b) != cntfs::c_grows(&a, &b) {
            return Err(format!("round {round}: grows {a:?} {b:?}"));
        }
        let mut c = a.clone();
        let r = ntfs::coalesce(&mut c).map(|n| c[..n].to_vec());
        if r != cntfs::c_coalesce(&a) {
            return Err(format!("round {round}: coalesce {a:?}"));
        }
        let l = next(100);
        if ntfs::gather(&a, l) != cntfs::c_gather(&a, l) {
            return Err(format!("round {round}: gather {a:?} {l}"));
        }
        // Growth by construction: extend the last extent or append.
        if let Some(Ok(old)) = r.map(|v| if v.is_empty() { Err(()) } else { Ok(v) }) {
            let mut new = old.clone();
            if let Some(last) = new.last_mut() {
                last.end += next(3);
            }
            if next(2) == 0 {
                new.push(Extent {
                    start: 500,
                    end: 501,
                });
            }
            if !ntfs::grows(&old, &new) || !cntfs::c_grows(&old, &new) {
                return Err(format!("round {round}: growth refused {old:?} -> {new:?}"));
            }
        }
    }
    Ok(())
}

/// Differential over the runlist decoder alone.
pub fn random_runlists(rounds: u64, seed: u64) -> Result<(), String> {
    let mut rng = seed | 1;
    for round in 0..rounds {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        let len = (rng % 24) as usize;
        let mut bytes: Vec<u8> = (0..len)
            .map(|i| (rng.rotate_left(i as u32 * 7) >> 3) as u8)
            .collect();
        // Bias headers towards valid widths so decoding gets deep.
        if let Some(b) = bytes.first_mut() {
            *b = (*b & 0x33) | 0x11;
        }
        let cap = (rng % 5) as usize;
        if cntfs::rust_runlist(&bytes, cap) != cntfs::c_runlist(&bytes, cap) {
            return Err(format!("round {round}: {bytes:02x?} cap {cap}"));
        }
    }
    Ok(())
}

/// Every input in a fuzz corpus directory (sparse-volume format).
pub fn corpus(dir: &Path) -> Result<usize, String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(0);
    };
    let mut n = 0;
    for entry in rd.flatten() {
        let data = std::fs::read(entry.path()).unwrap_or_default();
        let Some((rec, seq, _)) = SparseDisk::parse(&data) else {
            continue;
        };
        let _ = both(
            || {
                SparseDisk::parse(&data)
                    .map(|p| p.2)
                    .unwrap_or(SparseDisk { entries: vec![] })
            },
            rec,
            seq,
        )
        .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        n += 1;
    }
    Ok(n)
}

/// Every input in a runlist corpus directory.
pub fn runlist_corpus(dir: &Path) -> Result<usize, String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(0);
    };
    let mut n = 0;
    for entry in rd.flatten() {
        let data = std::fs::read(entry.path()).unwrap_or_default();
        if cntfs::rust_runlist(&data, 64) != cntfs::c_runlist(&data, 64) {
            return Err(format!("{}", entry.path().display()));
        }
        n += 1;
    }
    Ok(n)
}

/// Fuzz seeds: every manifest file case and every synthetic volume, as the
/// sparse inputs their clean parses read.
pub fn write_seeds(dir: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut n = 0;
    let mut put = |name: &str, img: &[u8], rec: u64, seq: u16| -> Result<(), String> {
        let (_, reads) = both(|| Slice(img), rec, seq)?;
        let data = cntfs::sparse_input(img, rec, seq, &reads);
        std::fs::write(dir.join(format!("{name}.bin")), data).map_err(|e| e.to_string())?;
        n += 1;
        Ok(())
    };
    for c in manifest().iter().filter(|c| c.kind == "file") {
        put(&c.name, &patched(c), c.rec, c.seq)?;
    }
    for (name, img) in synthetic() {
        put(&format!("synth_{name}"), &img, USER, 7)?;
    }
    put("synth_listed65", &listed(65, true).image(), USER, 7)?;
    Ok(n)
}

/// Distinct sectors read by `volume_flags` then `file` (what PG_VOLUME_ADD
/// and PG_CLAIM read), in first-read order.
pub fn reads(img: &[u8], rec: u64, seq: u16) -> Vec<u64> {
    let mut d = Slice(img);
    let mut t = Trace {
        inner: &mut d,
        reads: Vec::new(),
    };
    let _ = cntfs::rust_flags(&mut t);
    let _ = cntfs::rust_file(&mut t, rec, seq);
    let mut out: Vec<u64> = Vec::new();
    for s in t.reads {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Everything, at full strength (CI runs this in release mode).
pub fn exhaustive() -> Result<(), String> {
    let cases = manifest();
    if cases.is_empty() {
        return Err("no fixtures".into());
    }
    for c in &cases {
        check_case(c)?;
    }
    println!("fixtures: {} manifest cases agree and match", cases.len());
    let mut clean: Vec<&Case> = cases
        .iter()
        .filter(|c| c.kind == "file" && c.expect.starts_with("ok") && c.patches.is_empty())
        .collect();
    let mut seen = std::collections::HashSet::new();
    clean.retain(|c| seen.insert((c.image.clone(), c.rec)));
    for c in &clean {
        let img = image(&c.image);
        let m = mutate_bytes(&img, c.rec, c.seq, 1)?;
        let t = truncations(&img, c.rec, c.seq)?;
        let [f, torn, rr] = faults(&img, c.rec, c.seq)?;
        println!(
            "{:<14} bytes {m:?}\n{:<14} trunc {t:?}\n{:<14} fail {} torn {torn:?} reread {rr:?}",
            c.name, "", "", f.runs
        );
    }
    for (name, img) in synthetic() {
        let m = mutate_bytes(&img, USER, 7, 1)?;
        let [f, torn, _] = faults(&img, USER, 7)?;
        println!("synth {name:<8} bytes {m:?} fail {} torn {torn:?}", f.runs);
    }
    for d in [
        "fuzz/corpus/ntfs_file",
        "fuzz/corpus/ntfs_diff",
        "kernel/dm-paguro/test/fuzz/corpus/ntfs",
    ] {
        println!("corpus {d}: {} inputs agree", corpus(&repo_root().join(d))?);
    }
    for d in [
        "fuzz/corpus/runlist",
        "kernel/dm-paguro/test/fuzz/corpus/runlist",
    ] {
        println!(
            "corpus {d}: {} inputs agree",
            runlist_corpus(&repo_root().join(d))?
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn manifest_cases() {
        let cases = manifest();
        assert!(cases.len() > 80, "fixtures missing: {}", cases.len());
        let failures: Vec<String> = cases.iter().filter_map(|c| check_case(c).err()).collect();
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn synthetic_agree() {
        for (name, img) in synthetic() {
            let (out, _) = both(|| Slice(&img), USER, 7).unwrap();
            assert!(out.is_ok(), "{name}: {out:?}");
        }
        random_synthetic(3000, 11).unwrap();
    }

    #[test]
    fn claims_agree() {
        random_claims(50_000, 5).unwrap();
    }

    #[test]
    fn runlists_agree() {
        random_runlists(200_000, 3).unwrap();
    }

    #[test]
    fn mutation_sampled() {
        // Full strength is `paguro-harness ntfs-exhaustive` (release, CI).
        let c = manifest()
            .into_iter()
            .find(|c| c.name == "alist.img")
            .unwrap();
        let img = image(&c.image);
        let t = mutate_bytes(&img, c.rec, c.seq, 61).unwrap();
        assert!(t.refused > 0 && t.same_map > 0, "{t:?}");
        let (img, _) = synthetic().into_iter().nth(3).map(|v| (v.1, ())).unwrap();
        mutate_bytes(&img, USER, 7, 5).unwrap();
    }

    #[test]
    fn io_failures_torn_and_changing_reads() {
        for name in ["frag.img", "links.img"] {
            let c = manifest().into_iter().find(|c| c.name == name).unwrap();
            let img = image(&c.image);
            let [fail, torn, _] = faults(&img, c.rec, c.seq).unwrap();
            assert_eq!(fail.refused, fail.runs);
            // A torn MFT record is caught by its update sequence.
            assert!(torn.refused > 0);
            truncations(&img, c.rec, c.seq).unwrap();
        }
    }

    #[test]
    fn fuzz_corpora_agree() {
        for d in [
            "fuzz/corpus/ntfs_file",
            "kernel/dm-paguro/test/fuzz/corpus/ntfs",
        ] {
            corpus(&repo_root().join(d)).unwrap();
        }
        runlist_corpus(&repo_root().join("fuzz/corpus/runlist")).unwrap();
    }
}
