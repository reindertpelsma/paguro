//! Differential testing of the structural assertion (`pg_payload_check` in
//! `pg_ntfs.c` against `ntfs::check_payload`, INTERFACES §3.2):
//!
//! - the named cases in `test/fixtures/payload/manifest.txt` (real GPT,
//!   ext4 and ISO 9660 images from the real tools, and corruptions of them),
//!   each with the result both must return;
//! - **misordered gathering**: each accepted image cut into equal extents
//!   and gathered with two swapped, or reversed. A misordering that changes
//!   a sector the clean check reads must be refused — with one tolerated
//!   outcome: a GPT partition's ext4 superblock replaced by something that is
//!   not an ext4 superblock (the partition then reads as unknown content,
//!   which the check skips and no ext4 mount accepts);
//! - every byte of every read sector mutated, truncation, I/O failure at
//!   every read, torn reads; synthetic images mutated at random; the fuzz
//!   corpus.
//!
//! "Agree" means same result **and the same sequence of sector reads**.

#![allow(clippy::indexing_slicing)]

use std::path::{Path, PathBuf};

use paguro_core::ntfs::{Disk, IoError};

use crate::cntfs::{self, SparseDisk, Trace};
use crate::ntfsdiff::{Fault, Faulty, Slice, Tally, image, repo_root};

/// The sector the `Disk` trait reads and manifests count in.
const SECTOR: usize = 512;
/// Logical block sizes a case or fuzz input can ask for.
const LBS_512: u32 = 512;
const LBS_4K: u32 = 4096;
/// Bit 0 of a fuzz input's flags field selects 4 KiB logical blocks.
const FUZZ_LBS_4K: u16 = 1;
/// ext4 `s_magic` (0xEF53, LE) at 0x38 in the superblock's first sector.
const EXT4_MAGIC_AT: usize = 0x38;
const EXT4_MAGIC: [u8; 2] = [0x53, 0xef];

pub type Res = Result<(), i32>;

pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/payload")
}

/// One manifest line: `payload <name> <image> <sectors|-> <expect> [patches]`.
#[derive(Clone, Debug)]
pub struct Case {
    pub name: String,
    pub image: String,
    pub sectors: Option<u64>,
    pub expect: String,
    pub lbs: u32,
    pub patches: Vec<(usize, u8)>,
}

pub fn manifest() -> Vec<Case> {
    let text = std::fs::read_to_string(fixture_dir().join("manifest.txt")).unwrap_or_default();
    text.lines()
        .filter(|l| l.starts_with("payload "))
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            Some(Case {
                name: t.get(1)?.to_string(),
                image: t.get(2)?.to_string(),
                sectors: t.get(3)?.parse().ok(),
                expect: t.get(4)?.to_string(),
                lbs: t
                    .iter()
                    .find_map(|tok| tok.strip_prefix("lbs=")?.parse().ok())
                    .unwrap_or(LBS_512),
                patches: t
                    .iter()
                    .skip(5)
                    .filter_map(|tok| {
                        let (o, v) = tok.split_once('=')?;
                        Some((o.parse().ok()?, u8::from_str_radix(v, 16).ok()?))
                    })
                    .collect(),
            })
        })
        .collect()
}

pub fn fixture(name: &str) -> Vec<u8> {
    image(&fixture_dir().join(name).to_string_lossy())
}

pub fn patched(c: &Case) -> (Vec<u8>, u64) {
    let mut img = fixture(&c.image);
    for &(o, v) in &c.patches {
        if let Some(b) = img.get_mut(o) {
            *b = v;
        }
    }
    let n = c.sectors.unwrap_or((img.len() / SECTOR) as u64);
    (img, n)
}

/// Both implementations over fresh disks from `mk`: same result, same reads.
pub fn both<D: Disk>(
    mut mk: impl FnMut() -> D,
    sectors: u64,
    lbs: u32,
) -> Result<(Res, Vec<u64>), String> {
    let mut d = mk();
    let mut t = Trace {
        inner: &mut d,
        reads: Vec::new(),
    };
    let r = cntfs::rust_payload(&mut t, sectors, lbs);
    let rust_reads = t.reads;
    let mut d = mk();
    let mut t = Trace {
        inner: &mut d,
        reads: Vec::new(),
    };
    let c = cntfs::c_payload(&mut t, sectors, lbs);
    if r != c {
        return Err(format!(
            "{sectors} sectors: Rust {} vs C {}",
            show(r),
            show(c)
        ));
    }
    if rust_reads != t.reads {
        return Err(format!(
            "same result {}, different reads: Rust {rust_reads:?} vs C {:?}",
            show(r),
            t.reads
        ));
    }
    Ok((r, rust_reads))
}

pub fn show(r: Res) -> String {
    match r {
        Ok(()) => "ok".into(),
        Err(e) => cntfs::error_name(e),
    }
}

pub fn check_case(c: &Case) -> Result<(), String> {
    let (img, n) = patched(c);
    if img.is_empty() {
        return Err(format!("{}: fixture {} missing", c.name, c.image));
    }
    let (r, _) = both(|| Slice(&img), n, c.lbs).map_err(|e| format!("{}: {e}", c.name))?;
    if show(r) != c.expect {
        return Err(format!(
            "{}: expected {}, got {}",
            c.name,
            c.expect,
            show(r)
        ));
    }
    Ok(())
}

/// The image gathered from `k` equal extents in the order `perm` (logical
/// extent i is physical extent perm[i]); a partial tail stays in place.
pub struct Permuted<'a> {
    pub img: &'a [u8],
    pub chunk: u64,
    pub perm: Vec<u64>,
}

impl Disk for Permuted<'_> {
    fn read(&mut self, s: u64, buf: &mut [u8; 512]) -> Result<(), IoError> {
        let (i, off) = (s / self.chunk, s % self.chunk);
        let p = self
            .perm
            .get(i as usize)
            .map_or(s, |&j| j * self.chunk + off);
        Slice(self.img).read(p, buf)
    }
}

/// Misordered gathering over every accepted, unpatched case: for `k` equal
/// extents, every swap of two and the full reversal. A permutation that
/// changes a sector the clean check reads must be refused, unless the only
/// changes are ext4 superblocks that stopped being ext4 superblocks.
/// Returns (permutations run, those that changed a read sector, of which
/// accepted because only an ext4 superblock vanished).
pub fn misorder(k: u64) -> Result<(usize, usize, usize), String> {
    let (mut runs, mut must, mut vanished) = (0, 0, 0);
    for c in manifest()
        .iter()
        .filter(|c| c.expect == "ok" && c.patches.is_empty() && c.sectors.is_none())
    {
        let (img, n) = patched(c);
        let chunk = n / k;
        let (_, reads) = both(|| Slice(&img), n, c.lbs)?;
        let mut perms: Vec<Vec<u64>> = Vec::new();
        for i in 0..k {
            for j in i + 1..k {
                let mut p: Vec<u64> = (0..k).collect();
                p.swap(i as usize, j as usize);
                perms.push(p);
            }
        }
        perms.push((0..k).rev().collect());
        for p in perms {
            let mk = || Permuted {
                img: &img,
                chunk,
                perm: p.clone(),
            };
            // Read sectors whose bytes the misordering changed.
            let mut changed = Vec::new();
            for &s in &reads {
                let (mut a, mut b) = ([0u8; SECTOR], [0u8; SECTOR]);
                let ra = Slice(&img).read(s, &mut a);
                let rb = mk().read(s, &mut b);
                if ra != rb || a != b {
                    changed.push((a, b));
                }
            }
            let (r, _) = both(mk, n, c.lbs).map_err(|e| format!("{} perm {p:?}: {e}", c.name))?;
            runs += 1;
            if changed.is_empty() {
                continue;
            }
            must += 1;
            if r.is_ok() {
                let ext4 = |x: &[u8; SECTOR]| {
                    x[EXT4_MAGIC_AT] == EXT4_MAGIC[0] && x[EXT4_MAGIC_AT + 1] == EXT4_MAGIC[1]
                };
                if !changed.iter().all(|(a, b)| ext4(a) && !ext4(b)) {
                    return Err(format!(
                        "{}: extents gathered as {p:?} (of {k}) accepted",
                        c.name
                    ));
                }
                vanished += 1;
            }
        }
    }
    Ok((runs, must, vanished))
}

fn variants(orig: u8, rng: &mut u64) -> Vec<u8> {
    *rng ^= *rng << 13;
    *rng ^= *rng >> 7;
    *rng ^= *rng << 17;
    let mut v: Vec<u8> = (0..8).map(|b| orig ^ (1 << b)).collect();
    v.extend([0x00, 0xff, *rng as u8]);
    v.retain(|&x| x != orig);
    v
}

fn tally(t: &mut Tally, clean: Res, got: Res) {
    t.runs += 1;
    match got {
        Err(_) => t.refused += 1,
        Ok(()) if clean.is_ok() => t.same_map += 1,
        Ok(()) => t.other_map += 1,
    }
}

/// Every `stride`-th byte of every sector the clean check reads, set to each
/// bit flip, 0x00, 0xff and a random value; C and Rust must agree.
pub fn mutate_bytes(img: &[u8], n: u64, lbs: u32, stride: usize) -> Result<Tally, String> {
    let (clean, mut sectors) = both(|| Slice(img), n, lbs)?;
    sectors.sort_unstable();
    sectors.dedup();
    let mut work = img.to_vec();
    let mut t = Tally::default();
    let mut rng = 0x9e37_79b9_7f4a_7c15u64 ^ n;
    for s in sectors {
        for off in (0..SECTOR).step_by(stride) {
            let at = s as usize * SECTOR + off;
            let Some(&orig) = work.get(at) else { continue };
            for v in variants(orig, &mut rng) {
                work[at] = v;
                let (got, _) =
                    both(|| Slice(&work), n, lbs).map_err(|e| format!("byte {at}={v:#x}: {e}"))?;
                tally(&mut t, clean, got);
            }
            work[at] = orig;
        }
    }
    Ok(t)
}

/// Cut short at every read sector (must be `Io`); I/O failure at every read
/// (must be `Io`); torn reads (must agree).
pub fn faults(img: &[u8], n: u64, lbs: u32) -> Result<[Tally; 2], String> {
    let (clean, reads) = both(|| Slice(img), n, lbs)?;
    let mut t = [Tally::default(), Tally::default()];
    let mut sectors = reads.clone();
    sectors.sort_unstable();
    sectors.dedup();
    for &s in &sectors {
        let cut = img.get(..s as usize * SECTOR).unwrap_or(img);
        let (got, _) = both(|| Slice(cut), n, lbs)?;
        if got != Err(1) {
            return Err(format!("cut at sector {s}: {}", show(got)));
        }
    }
    for i in 0..reads.len() {
        let (got, _) = both(|| Faulty::new(img, i, Fault::Fail), n, lbs)?;
        if got != Err(1) {
            return Err(format!("failure at read {i}: {}", show(got)));
        }
        tally(&mut t[0], clean, got);
        let (got, _) = both(|| Faulty::new(img, i, Fault::Torn), n, lbs)?;
        tally(&mut t[1], clean, got);
    }
    Ok(t)
}

/// Random multi-byte mutation of the read sectors of every manifest case.
pub fn random(rounds: u64, seed: u64) -> Result<(), String> {
    let cases: Vec<(Vec<u8>, u64, u32, Vec<u64>)> = manifest()
        .iter()
        .map(|c| {
            let (img, n) = patched(c);
            both(|| Slice(&img), n, c.lbs).map(|(_, r)| (img, n, c.lbs, r))
        })
        .collect::<Result<_, _>>()?;
    let mut rng = seed | 1;
    let mut next = |m: u64| {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng % m.max(1)
    };
    for round in 0..rounds {
        let (img, n, lbs, reads) = &cases[next(cases.len() as u64) as usize];
        if reads.is_empty() {
            continue;
        }
        let mut work = img.clone();
        for _ in 0..1 + next(4) {
            let s = reads[next(reads.len() as u64) as usize];
            let at = s as usize * SECTOR + next(SECTOR as u64) as usize;
            if let Some(b) = work.get_mut(at) {
                *b = next(256) as u8;
            }
        }
        let _ = both(|| Slice(&work), *n, *lbs).map_err(|e| format!("round {round}: {e}"))?;
    }
    Ok(())
}

/// The logical block size a fuzz input asks for: bit 0 of its u16 field.
pub fn fuzz_lbs(flags: u16) -> u32 {
    if flags & FUZZ_LBS_4K != 0 {
        LBS_4K
    } else {
        LBS_512
    }
}

/// Fuzz inputs: `SparseDisk` whose first u32 is the image length in sectors
/// and whose u16 field picks the logical block size (`fuzz_lbs`).
pub fn corpus(dir: &Path) -> Result<usize, String> {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Ok(0);
    };
    let mut n = 0;
    for entry in rd.flatten() {
        let data = std::fs::read(entry.path()).unwrap_or_default();
        let Some((sectors, flags, _)) = SparseDisk::parse(&data) else {
            continue;
        };
        let _ = both(
            || {
                SparseDisk::parse(&data)
                    .map(|p| p.2)
                    .unwrap_or(SparseDisk { entries: vec![] })
            },
            sectors,
            fuzz_lbs(flags),
        )
        .map_err(|e| format!("{}: {e}", entry.path().display()))?;
        n += 1;
    }
    Ok(n)
}

/// Seeds for `test/fuzz/corpus/payload` (and `ntfs_diff`): each manifest
/// case as the sectors its check reads.
pub fn write_seeds(dir: &Path) -> Result<usize, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let mut n = 0;
    for c in manifest() {
        let (img, sectors) = patched(&c);
        let (_, reads) = both(|| Slice(&img), sectors, c.lbs)?;
        let data = cntfs::sparse_input(&img, sectors, u16::from(c.lbs == LBS_4K), &reads);
        std::fs::write(dir.join(format!("payload_{}.bin", c.name)), data)
            .map_err(|e| e.to_string())?;
        n += 1;
    }
    Ok(n)
}

/// Full strength (CI, release).
pub fn exhaustive() -> Result<(), String> {
    let cases = manifest();
    if cases.len() < 50 {
        return Err(format!("payload fixtures missing ({} cases)", cases.len()));
    }
    for c in &cases {
        check_case(c)?;
    }
    println!("payload: {} manifest cases agree and match", cases.len());
    for k in [4, 7] {
        let (runs, must, vanished) = misorder(k)?;
        println!(
            "payload misorder k={k}: {runs} gatherings, {must} changed a read sector: \
             {} refused, {vanished} accepted with only an ext4 superblock gone",
            must - vanished
        );
    }
    for c in cases
        .iter()
        .filter(|c| c.expect == "ok" && c.patches.is_empty() && c.sectors.is_none())
    {
        let (img, n) = patched(c);
        // Every byte of the sectors the check reads; for a GPT (its CRCs make
        // each run read ~200 sectors) every 7th byte, to stay in CI's budget.
        let stride = if c.image.starts_with("gpt") { 7 } else { 1 };
        let m = mutate_bytes(&img, n, c.lbs, stride)?;
        let [fail, torn] = faults(&img, n, c.lbs)?;
        println!(
            "payload {:<14} bytes {m:?} fail {} torn {torn:?}",
            c.name, fail.runs
        );
    }
    println!(
        "corpus payload: {} inputs agree",
        corpus(&repo_root().join("kernel/dm-paguro/test/fuzz/corpus/payload"))?
    );
    random(200_000, 0x9a71)?;
    println!("payload random: 200000 rounds agree");
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn manifest_cases() {
        let cases = manifest();
        assert!(cases.len() > 50, "fixtures missing: {}", cases.len());
        let failures: Vec<String> = cases.iter().filter_map(|c| check_case(c).err()).collect();
        assert!(failures.is_empty(), "{failures:#?}");
    }

    #[test]
    fn misordered_extents_refused() {
        let (runs, must, vanished) = misorder(4).unwrap();
        assert!(
            must > 20 && runs > must && vanished < must / 4,
            "{runs} {must} {vanished}"
        );
    }

    #[test]
    fn mutation_and_faults_sampled() {
        for (name, stride) in [
            ("gpt", 97),
            ("gpt4k", 97),
            ("ext4_sparse2", 11),
            ("iso", 11),
        ] {
            let c = manifest().into_iter().find(|c| c.name == name).unwrap();
            let (img, n) = patched(&c);
            let t = mutate_bytes(&img, n, c.lbs, stride).unwrap();
            assert!(t.refused > 0 && t.same_map > 0, "{name} {t:?}");
            let [fail, _] = faults(&img, n, c.lbs).unwrap();
            assert_eq!(fail.refused, fail.runs);
        }
        random(2000, 7).unwrap();
    }

    #[test]
    fn fuzz_corpus_agrees() {
        corpus(&repo_root().join("kernel/dm-paguro/test/fuzz/corpus/payload")).unwrap();
    }
}
