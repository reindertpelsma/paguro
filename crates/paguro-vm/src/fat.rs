//! A FAT32 image writer for the VM's two small synthetic file systems: the
//! ESP (DESIGN.md §4.3, §12: `bootmgfw.efi` and a BCD with testsigning) and
//! the removable device carrying the `.BEK` (§6 "The VM boot").
//!
//! Built in memory from a list of files: every file and directory gets one
//! contiguous cluster run, names that are not plain upper-case 8.3 get VFAT
//! long names with a generated `BASIS~N` short name, and the layout is what
//! `mkfs.fat` writes (32 reserved sectors, two FATs, FSInfo in sector 1, the
//! backup boot sector in 6). It is read back by `paguro_core::fat` and, when
//! installed, `fsck.fat` in the tests.

use std::collections::BTreeMap;

pub const SECTOR: usize = 512;
const RESERVED_SECTORS: u32 = 32;
const NUM_FATS: u32 = 2;
const FS_INFO_SECTOR: u16 = 1;
const BACKUP_BOOT_SECTOR: u16 = 6;
const ROOT_CLUSTER: u32 = 2;
const FIRST_CLUSTER: u32 = 2;
/// FAT32 needs at least this many clusters (Microsoft's FAT specification).
const MIN_CLUSTERS: u32 = 65_525;
const FAT_ENTRY: u32 = 4;
const DIR_ENTRY: usize = 32;
const EOC: u32 = 0x0FFF_FFFF;
const MEDIA: u8 = 0xF8;
const FAT0: u32 = 0x0FFF_FF00 | MEDIA as u32;

const ATTR_DIR: u8 = 0x10;
const ATTR_ARCHIVE: u8 = 0x20;
const ATTR_LFN: u8 = 0x0F;
const LFN_LAST: u8 = 0x40;
const LFN_UNITS: usize = 13;
const LFN_OFFSETS: [usize; LFN_UNITS] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
/// 2026-01-01 00:00:00, FAT date/time encoding: a fixed stamp keeps the
/// image reproducible.
const FAT_DATE: u16 = ((2026 - 1980) << 9) | (1 << 5) | 1;
const FAT_TIME: u16 = 0;

// Boot sector (FAT32 BPB) offsets.
const BS_JMP: [u8; 3] = [0xEB, 0x58, 0x90];
const FSI_LEAD: u32 = 0x4161_5252;
const FSI_STRUC: u32 = 0x6141_7272;
const FSI_TRAIL: u32 = 0xAA55_0000;
const FSI_UNKNOWN: u32 = 0xFFFF_FFFF;

#[derive(Debug, PartialEq, Eq)]
pub enum FatError {
    TooSmall,
    BadName(String),
    Duplicate(String),
}

impl core::fmt::Display for FatError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FatError::TooSmall => write!(f, "the files do not fit the FAT32 image"),
            FatError::BadName(n) => write!(f, "not a FAT name: {n:?}"),
            FatError::Duplicate(n) => write!(f, "duplicate path: {n:?}"),
        }
    }
}

/// A directory's child: its name, and the directory or the file data.
type Child<'a> = (&'a String, Option<&'a Dir>, Option<&'a Vec<u8>>);

/// Copy `v` into `b` at `at`. Every caller computes `at` from the image's
/// own geometry; out of range would be a bug here, and is a no-op in
/// release rather than a panic.
fn put(b: &mut [u8], at: usize, v: &[u8]) {
    let dst = b.get_mut(at..at + v.len());
    debug_assert!(dst.is_some(), "fat: write outside the buffer");
    if let Some(d) = dst {
        d.copy_from_slice(v);
    }
}

#[derive(Default)]
struct Dir {
    dirs: BTreeMap<String, Dir>,
    files: BTreeMap<String, Vec<u8>>,
}

/// The files of an image, by `/`-separated path (directories implied).
#[derive(Default)]
pub struct Tree {
    root: Dir,
}

fn valid_name(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 255
        && n != "."
        && n != ".."
        && !n.chars().any(|c| c < ' ' || "\"*/:<>?\\|".contains(c))
        && !n.ends_with(' ')
        && !n.ends_with('.')
}

fn key(n: &str) -> String {
    n.to_uppercase()
}

impl Tree {
    pub fn new() -> Tree {
        Tree::default()
    }

    fn dir_mut(&mut self, comps: &[&str]) -> Result<&mut Dir, FatError> {
        let mut d = &mut self.root;
        for c in comps {
            if !valid_name(c) {
                return Err(FatError::BadName((*c).to_string()));
            }
            if d.files.keys().any(|k| key(k) == key(c)) {
                return Err(FatError::Duplicate((*c).to_string()));
            }
            let existing = d.dirs.keys().find(|k| key(k) == key(c)).cloned();
            d = d
                .dirs
                .entry(existing.unwrap_or_else(|| (*c).to_string()))
                .or_default();
        }
        Ok(d)
    }

    pub fn mkdir(&mut self, path: &str) -> Result<(), FatError> {
        let comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        self.dir_mut(&comps).map(|_| ())
    }

    pub fn add(&mut self, path: &str, data: Vec<u8>) -> Result<(), FatError> {
        let comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let (name, dir) = comps
            .split_last()
            .ok_or_else(|| FatError::BadName(path.into()))?;
        if !valid_name(name) {
            return Err(FatError::BadName((*name).to_string()));
        }
        let d = self.dir_mut(dir)?;
        if d.files
            .keys()
            .chain(d.dirs.keys())
            .any(|k| key(k) == key(name))
        {
            return Err(FatError::Duplicate(path.into()));
        }
        d.files.insert((*name).to_string(), data);
        Ok(())
    }

    /// Replace an existing file's data.
    pub fn replace(&mut self, path: &str, data: Vec<u8>) -> Result<(), FatError> {
        let comps: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        let (name, dirs) = comps
            .split_last()
            .ok_or_else(|| FatError::BadName(path.into()))?;
        let mut d = &mut self.root;
        for c in dirs {
            let k = d.dirs.keys().find(|k| key(k) == key(c)).cloned();
            d = k
                .and_then(|k| d.dirs.get_mut(&k))
                .ok_or_else(|| FatError::BadName(path.into()))?;
        }
        let k = d
            .files
            .keys()
            .find(|k| key(k) == key(name))
            .cloned()
            .ok_or_else(|| FatError::BadName(path.into()))?;
        d.files.insert(k, data);
        Ok(())
    }

    /// Total bytes of file data (for sizing the image).
    pub fn data_bytes(&self) -> u64 {
        fn walk(d: &Dir) -> u64 {
            d.files.values().map(|f| f.len() as u64).sum::<u64>()
                + d.dirs.values().map(walk).sum::<u64>()
        }
        walk(&self.root)
    }
}

/// An 8.3 name if `n` is one as stored (upper case, no long name needed).
fn plain_short(n: &str) -> Option<[u8; 11]> {
    let (base, ext) = match n.rsplit_once('.') {
        Some((b, e)) => (b, e),
        None => (n, ""),
    };
    let ok = |s: &str, max: usize| {
        s.len() <= max
            && s.bytes().all(|b| {
                b.is_ascii_uppercase() || b.is_ascii_digit() || b"!#$%&'()-@^_`{}~".contains(&b)
            })
    };
    if base.is_empty() || !ok(base, 8) || !ok(ext, 3) || (n.ends_with('.')) {
        return None;
    }
    let mut s = [b' '; 11];
    put(&mut s, 0, base.as_bytes());
    put(&mut s, 8, ext.as_bytes());
    Some(s)
}

/// A generated short name `BASIS~N.EXT`, unique among `taken`.
fn generated_short(n: &str, taken: &[[u8; 11]]) -> [u8; 11] {
    let clean = |s: &str| -> Vec<u8> {
        s.bytes()
            .filter(|b| b.is_ascii_alphanumeric() || b"!#$%&'()-@^_`{}~".contains(b))
            .map(|b| b.to_ascii_uppercase())
            .collect()
    };
    let (base, ext) = match n.rsplit_once('.') {
        Some((b, e)) if !b.is_empty() => (clean(b), clean(e)),
        _ => (clean(n), Vec::new()),
    };
    for i in 1u32.. {
        let tail = format!("~{i}");
        let keep = (8 - tail.len()).min(base.len());
        let mut s = [b' '; 11];
        let stem: Vec<u8> = if keep == 0 {
            b"X".to_vec()
        } else {
            base.iter().take(keep).copied().collect()
        };
        put(&mut s, 0, &stem);
        put(&mut s, stem.len(), tail.as_bytes());
        put(&mut s, 8, ext.get(..ext.len().min(3)).unwrap_or(&[]));
        if !taken.contains(&s) {
            return s;
        }
    }
    unreachable!()
}

fn checksum(s: &[u8; 11]) -> u8 {
    s.iter()
        .fold(0u8, |c, &b| c.rotate_right(1).wrapping_add(b))
}

fn short_entry(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> [u8; DIR_ENTRY] {
    let mut e = [0u8; DIR_ENTRY];
    e[..11].copy_from_slice(name);
    e[11] = attr;
    for at in [14usize, 22] {
        put(&mut e, at, &FAT_TIME.to_le_bytes());
    }
    for at in [16usize, 18, 24] {
        put(&mut e, at, &FAT_DATE.to_le_bytes());
    }
    e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    e[28..32].copy_from_slice(&size.to_le_bytes());
    e
}

fn lfn_entries(long: &str, short: &[u8; 11]) -> Vec<[u8; DIR_ENTRY]> {
    let units: Vec<u16> = long.encode_utf16().collect();
    let n = units.len().div_ceil(LFN_UNITS);
    let sum = checksum(short);
    (1..=n)
        .rev()
        .map(|seq| {
            let mut e = [0u8; DIR_ENTRY];
            e[0] = seq as u8 | if seq == n { LFN_LAST } else { 0 };
            e[11] = ATTR_LFN;
            e[13] = sum;
            for (k, off) in LFN_OFFSETS.iter().enumerate() {
                let i = (seq - 1) * LFN_UNITS + k;
                let u = match i.cmp(&units.len()) {
                    core::cmp::Ordering::Less => units.get(i).copied().unwrap_or(0),
                    core::cmp::Ordering::Equal => 0,
                    core::cmp::Ordering::Greater => 0xFFFF,
                };
                put(&mut e, *off, &u.to_le_bytes());
            }
            e
        })
        .collect()
}

struct Geometry {
    total: u32,
    spc: u32,
    fat_sectors: u32,
    clusters: u32,
}

impl Geometry {
    fn new(total: u32) -> Result<Geometry, FatError> {
        // One sector per cluster up to 260 MiB, as mkfs.fat does for
        // FAT32 at these sizes; larger images take 8.
        let spc = if u64::from(total) * SECTOR as u64 <= 260 << 20 {
            1
        } else {
            8
        };
        let mut fat = 1u32;
        loop {
            let data = total
                .checked_sub(RESERVED_SECTORS + NUM_FATS * fat)
                .ok_or(FatError::TooSmall)?;
            let clusters = data / spc;
            if fat * SECTOR as u32 >= (clusters + FIRST_CLUSTER) * FAT_ENTRY {
                if clusters < MIN_CLUSTERS {
                    return Err(FatError::TooSmall);
                }
                return Ok(Geometry {
                    total,
                    spc,
                    fat_sectors: fat,
                    clusters,
                });
            }
            fat += 1;
        }
    }
    fn cluster_bytes(&self) -> usize {
        self.spc as usize * SECTOR
    }
    fn cluster_offset(&self, c: u32) -> usize {
        ((RESERVED_SECTORS + NUM_FATS * self.fat_sectors + (c - FIRST_CLUSTER) * self.spc) as usize)
            * SECTOR
    }
}

struct Writer {
    g: Geometry,
    img: Vec<u8>,
    next: u32,
}

impl Writer {
    fn set_fat(&mut self, c: u32, v: u32) {
        for f in 0..NUM_FATS {
            let at = ((RESERVED_SECTORS + f * self.g.fat_sectors) as usize) * SECTOR
                + (c * FAT_ENTRY) as usize;
            put(&mut self.img, at, &v.to_le_bytes());
        }
    }
    /// A contiguous chain of clusters for `bytes` (at least one).
    fn alloc(&mut self, bytes: usize) -> Result<u32, FatError> {
        let n = bytes.div_ceil(self.g.cluster_bytes()).max(1) as u32;
        let first = self.next;
        if first + n > self.g.clusters + FIRST_CLUSTER {
            return Err(FatError::TooSmall);
        }
        for i in 0..n {
            self.set_fat(first + i, if i + 1 == n { EOC } else { first + i + 1 });
        }
        self.next += n;
        Ok(first)
    }
    fn write_at(&mut self, c: u32, data: &[u8]) {
        let at = self.g.cluster_offset(c);
        put(&mut self.img, at, data);
    }
    fn dir(&mut self, d: &Dir, cluster: u32, parent: u32) -> Result<(), FatError> {
        let mut entries: Vec<[u8; DIR_ENTRY]> = Vec::new();
        if cluster != ROOT_CLUSTER {
            entries.push(short_entry(b".          ", ATTR_DIR, cluster, 0));
            let p = if parent == ROOT_CLUSTER { 0 } else { parent };
            entries.push(short_entry(b"..         ", ATTR_DIR, p, 0));
        }
        let mut taken: Vec<[u8; 11]> = Vec::new();
        let mut children: Vec<Child<'_>> = Vec::new();
        for (n, sub) in &d.dirs {
            children.push((n, Some(sub), None));
        }
        for (n, f) in &d.files {
            children.push((n, None, Some(f)));
        }
        // Short names: the plain ones first, so a generated one never
        // takes a name a later file needs as is.
        let mut shorts: Vec<Option<[u8; 11]>> = children.iter().map(|c| plain_short(c.0)).collect();
        for s in shorts.iter().flatten() {
            taken.push(*s);
        }
        for (c, short) in children.iter().zip(shorts.iter_mut()) {
            if short.is_none() {
                let s = generated_short(c.0, &taken);
                taken.push(s);
                *short = Some(s);
            }
        }
        let mut subdirs = Vec::new();
        for ((name, sub, file), short) in children.iter().zip(&shorts) {
            let short = short.unwrap_or([b' '; 11]);
            if plain_short(name).is_none() {
                entries.extend(lfn_entries(name, &short));
            }
            if let Some(sub) = sub {
                // Size the directory: its entries (with long names) plus
                // `.`, `..` and the terminator.
                let c = self.alloc(dir_bytes(sub))?;
                entries.push(short_entry(&short, ATTR_DIR, c, 0));
                subdirs.push((c, *sub));
            } else if let Some(f) = file {
                let size = u32::try_from(f.len()).map_err(|_| FatError::TooSmall)?;
                let c = if f.is_empty() {
                    0
                } else {
                    self.alloc(f.len())?
                };
                if c != 0 {
                    self.write_at(c, f);
                }
                entries.push(short_entry(&short, ATTR_ARCHIVE, c, size));
            }
        }
        let bytes: Vec<u8> = entries.concat();
        self.write_at(cluster, &bytes);
        for (c, sub) in subdirs {
            self.dir(sub, c, cluster)?;
        }
        Ok(())
    }
}

/// Bytes a directory's entries take (upper bound: every name long).
fn dir_bytes(d: &Dir) -> usize {
    let names = d.dirs.keys().chain(d.files.keys());
    let n: usize = names
        .map(|n| {
            1 + if plain_short(n).is_some() {
                0
            } else {
                n.encode_utf16().count().div_ceil(LFN_UNITS)
            }
        })
        .sum();
    (n + 3) * DIR_ENTRY
}

/// The image: `total_sectors` 512-byte sectors, the given volume label
/// (11 bytes, space padded) and serial number.
pub fn build(
    tree: &Tree,
    total_sectors: u32,
    label: &str,
    serial: u32,
) -> Result<Vec<u8>, FatError> {
    let g = Geometry::new(total_sectors)?;
    let mut w = Writer {
        img: vec![0u8; g.total as usize * SECTOR],
        g,
        next: ROOT_CLUSTER,
    };
    let root = w.alloc(dir_bytes(&tree.root))?;
    debug_assert_eq!(root, ROOT_CLUSTER);
    w.set_fat(0, FAT0);
    w.set_fat(1, EOC);
    w.dir(&tree.root, ROOT_CLUSTER, ROOT_CLUSTER)?;

    let mut lab = [b' '; 11];
    let upper: Vec<u8> = label
        .bytes()
        .take(11)
        .map(|b| b.to_ascii_uppercase())
        .collect();
    put(&mut lab, 0, &upper);
    let mut bs = [0u8; SECTOR];
    bs[..3].copy_from_slice(&BS_JMP);
    bs[3..11].copy_from_slice(b"MSWIN4.1");
    bs[11..13].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    bs[13] = w.g.spc as u8;
    bs[14..16].copy_from_slice(&(RESERVED_SECTORS as u16).to_le_bytes());
    bs[16] = NUM_FATS as u8;
    bs[21] = MEDIA;
    bs[24..26].copy_from_slice(&63u16.to_le_bytes());
    bs[26..28].copy_from_slice(&255u16.to_le_bytes());
    bs[32..36].copy_from_slice(&w.g.total.to_le_bytes());
    bs[36..40].copy_from_slice(&w.g.fat_sectors.to_le_bytes());
    bs[44..48].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
    bs[48..50].copy_from_slice(&FS_INFO_SECTOR.to_le_bytes());
    bs[50..52].copy_from_slice(&BACKUP_BOOT_SECTOR.to_le_bytes());
    bs[64] = 0x80;
    bs[66] = 0x29;
    bs[67..71].copy_from_slice(&serial.to_le_bytes());
    bs[71..82].copy_from_slice(&lab);
    bs[82..90].copy_from_slice(b"FAT32   ");
    bs[510] = 0x55;
    bs[511] = 0xAA;
    let used = w.next - FIRST_CLUSTER;
    let mut fsi = [0u8; SECTOR];
    fsi[..4].copy_from_slice(&FSI_LEAD.to_le_bytes());
    fsi[484..488].copy_from_slice(&FSI_STRUC.to_le_bytes());
    fsi[488..492].copy_from_slice(&(w.g.clusters - used).to_le_bytes());
    let next_free = if w.next < w.g.clusters + FIRST_CLUSTER {
        w.next
    } else {
        FSI_UNKNOWN
    };
    fsi[492..496].copy_from_slice(&next_free.to_le_bytes());
    fsi[508..512].copy_from_slice(&FSI_TRAIL.to_le_bytes());
    for (at, s) in [(0usize, &bs), (1, &fsi), (6, &bs), (7, &fsi)] {
        put(&mut w.img, at * SECTOR, s);
    }
    // Sector 2 (and its backup, 8): the third boot sector, only its
    // signature.
    for at in [2usize, 8] {
        put(&mut w.img, at * SECTOR + 510, &[0x55, 0xAA]);
    }
    // A volume-label entry in the root, as mkfs.fat and Windows write.
    let root_at = w.g.cluster_offset(ROOT_CLUSTER);
    let mut end = root_at;
    while w.img.get(end).is_some_and(|&b| b != 0) {
        end += DIR_ENTRY;
    }
    let mut e = short_entry(&lab, 0x08, 0, 0);
    e[11] = 0x08;
    put(&mut w.img, end, &e);
    Ok(w.img)
}

/// Sectors for an image holding `data_bytes` of files with room to spare
/// (at least `min_bytes`, never below FAT32's minimum).
pub fn sectors_for(data_bytes: u64, min_bytes: u64) -> u32 {
    let floor = (u64::from(MIN_CLUSTERS) + 4096) * SECTOR as u64;
    let want = (data_bytes * 2 + (8 << 20)).max(min_bytes).max(floor);
    // Whole MiB, for the partition alignment.
    let mib = want.div_ceil(1 << 20);
    (mib * ((1 << 20) / SECTOR as u64)) as u32
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use paguro_core::fat::{Fs, SCRATCH, Sectors};

    struct Mem<'a>(&'a [u8]);
    impl Sectors for Mem<'_> {
        fn read(&mut self, s: u64, buf: &mut [u8]) -> Result<(), paguro_core::fat::FatError> {
            let at = s as usize * SECTOR;
            buf.copy_from_slice(
                self.0
                    .get(at..at + buf.len())
                    .ok_or(paguro_core::fat::FatError::Io)?,
            );
            Ok(())
        }
    }

    fn sample() -> Tree {
        let mut t = Tree::new();
        t.add("EFI/Microsoft/Boot/bootmgfw.efi", vec![1u8; 70_000])
            .unwrap();
        t.add("EFI/Microsoft/Boot/BCD", vec![2u8; 32_768]).unwrap();
        t.add("EFI/Microsoft/Boot/en-US/bootmgr.efi.mui", vec![3u8; 100])
            .unwrap();
        t.add("EFI/Boot/bootx64.efi", vec![1u8; 70_000]).unwrap();
        t.add("EFI/Boot/Empty", Vec::new()).unwrap();
        t.add("03EA97FB-B9C1-413D-9BA0-28EEE3D9DDE2.BEK", vec![4u8; 180])
            .unwrap();
        t.add("README.TXT", b"x".to_vec()).unwrap();
        for i in 0..40 {
            t.add(
                &format!("EFI/Microsoft/Boot/Fonts/long font name {i}.ttf"),
                vec![i as u8; 513],
            )
            .unwrap();
        }
        t
    }

    #[test]
    fn reads_back() {
        let t = sample();
        let img = build(&t, sectors_for(t.data_bytes(), 0), "ESP", 0x1234_5678).unwrap();
        let mut src = Mem(&img);
        let mut scratch = [0u8; SCRATCH];
        let fs = Fs::open(&mut src, img.len() as u64, &mut scratch).unwrap();
        let read = |path: &str, want: &[u8]| {
            let mut src = Mem(&img);
            let mut scratch = [0u8; SCRATCH];
            let f = fs.find(&mut src, path, &mut scratch).unwrap();
            assert!(!f.is_dir);
            assert_eq!(f.size as usize, want.len(), "{path}");
            if want.is_empty() {
                assert_eq!(f.cluster, 0);
                return;
            }
            let at = ((RESERVED_SECTORS
                + NUM_FATS * fs.bpb.fat_sectors
                + (f.cluster - 2) * u32::from(fs.bpb.sectors_per_cluster))
                as usize)
                * SECTOR;
            assert_eq!(&img[at..at + want.len()], want, "{path}");
        };
        read("\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &[1u8; 70_000]);
        read("\\efi\\microsoft\\boot\\BCD", &[2u8; 32_768]);
        read(
            "\\EFI\\Microsoft\\Boot\\en-US\\bootmgr.efi.mui",
            &[3u8; 100],
        );
        read("\\EFI\\BOOT\\BOOTX64.EFI", &[1u8; 70_000]);
        read("\\EFI\\Boot\\Empty", &[]);
        read("\\03EA97FB-B9C1-413D-9BA0-28EEE3D9DDE2.BEK", &[4u8; 180]);
        read("\\README.TXT", b"x");
        for i in 0..40 {
            read(
                &format!("\\EFI\\Microsoft\\Boot\\Fonts\\long font name {i}.ttf"),
                &[i as u8; 513],
            );
        }
    }

    #[test]
    fn short_names() {
        assert_eq!(plain_short("BCD"), Some(*b"BCD        "));
        assert_eq!(plain_short("README.TXT"), Some(*b"README  TXT"));
        assert_eq!(plain_short("bootmgfw.efi"), None);
        assert_eq!(plain_short("A.B.C"), None);
        let g = generated_short("bootmgfw.efi", &[]);
        assert_eq!(&g, b"BOOTMG~1EFI");
        let g2 = generated_short("bootmgfw.efi", &[g]);
        assert_eq!(&g2, b"BOOTMG~2EFI");
        assert_eq!(&generated_short(".hidden", &[]), b"HIDDEN~1   ");
    }

    #[test]
    fn refusals() {
        let mut t = Tree::new();
        t.add("a/b", vec![]).unwrap();
        assert!(matches!(t.add("A/B", vec![]), Err(FatError::Duplicate(_))));
        assert!(matches!(
            t.add("a/b/c", vec![]),
            Err(FatError::Duplicate(_))
        ));
        assert!(matches!(t.add("a/x:y", vec![]), Err(FatError::BadName(_))));
        assert_eq!(build(&t, 1000, "X", 0), Err(FatError::TooSmall));
    }

    /// `fsck.fat -n` agrees, when installed.
    #[test]
    fn fsck_agrees() {
        let Ok(out) = std::process::Command::new("fsck.fat")
            .arg("--help")
            .output()
        else {
            return;
        };
        let _ = out;
        let t = sample();
        let img = build(&t, sectors_for(t.data_bytes(), 0), "ESP", 1).unwrap();
        let dir = std::env::temp_dir().join(format!("paguro-vm-fat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("esp.img");
        std::fs::write(&p, &img).unwrap();
        let r = std::process::Command::new("fsck.fat")
            .arg("-n")
            .arg(&p)
            .output()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            r.status.success(),
            "{}{}",
            String::from_utf8_lossy(&r.stdout),
            String::from_utf8_lossy(&r.stderr)
        );
    }
}
