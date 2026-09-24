//! A read-only FAT32 directory reader: what recovery's EFI-partition
//! browser lists (INTERFACES.md §13.4) when the firmware's FAT driver does
//! not bind to the loader's block device (DESIGN.md §4.2, tier 2).
//!
//! It reads through a [`Sectors`] source in whole sectors into a caller
//! scratch buffer — no allocation — and trusts nothing it reads: the boot
//! sector is checked by [`crate::disk::parse_fat32`], every cluster number
//! is range-checked, cluster chains are bounded by the cluster count (a
//! loop ends in [`FatError::Loop`]), a directory by the FAT limit of 65 536
//! entries, a path by 32 components, and a long name by 255 UTF-16 units.
//! Long names (VFAT) are used only when their sequence and checksum match
//! the short entry they precede; otherwise the 8.3 name stands.

use crate::disk::{Fat32, Fat32Error, parse_fat32};

/// Entries a FAT directory may hold (FAT specification: 65 536 × 32 bytes).
pub const MAX_DIR_ENTRIES: u32 = 65_536;
/// Path components followed.
pub const MAX_DEPTH: usize = 32;
/// Longest long name, in UTF-16 units.
pub const MAX_NAME: usize = 255;
/// Scratch the reader needs: one sector of the largest size FAT32 allows.
pub const SCRATCH: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FatError {
    /// The boot sector is not a FAT32 one.
    Boot(Fat32Error),
    /// The source failed or the read was outside it.
    Io,
    /// A cluster number outside the volume, a bad-cluster mark, or a free
    /// cluster inside a chain.
    BadCluster(u32),
    /// A chain longer than the volume has clusters (a loop).
    Loop,
    /// A directory past [`MAX_DIR_ENTRIES`] entries, or a path past
    /// [`MAX_DEPTH`] components.
    TooLarge,
    /// A path component was not found, or is not a directory.
    NotFound,
    /// The path is not absolute (`\…`), or has an empty, `.` or `..`
    /// component.
    BadPath,
}

/// Where the reader gets sectors: `buf.len()` bytes starting at sector
/// `sector` (of the file system's sector size) of the file system.
pub trait Sectors {
    fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), FatError>;
}

/// One directory entry as [`Fs::list`] reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirEntry<'a> {
    /// The long name when valid, else the 8.3 name (with the NT case flags
    /// applied), as UTF-16.
    pub name: &'a [u16],
    pub is_dir: bool,
    pub size: u32,
    pub cluster: u32,
}

/// A validated FAT32 file system.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fs {
    pub bpb: Fat32,
}

const END: u32 = 0x0FFF_FFF8;
const BAD: u32 = 0x0FFF_FFF7;

const ATTR_VOLUME: u8 = 0x08;
const ATTR_DIR: u8 = 0x10;
const ATTR_LFN: u8 = 0x0F;

/// The VFAT checksum of an 8.3 name.
pub fn short_checksum(short: &[u8; 11]) -> u8 {
    short
        .iter()
        .fold(0u8, |s, &b| s.rotate_right(1).wrapping_add(b))
}

struct Lfn {
    units: [u16; 260],
    /// The sequence number the next entry must carry (0: none pending).
    expect: u8,
    count: u8,
    checksum: u8,
    ok: bool,
}

impl Lfn {
    const fn new() -> Self {
        Lfn {
            units: [0; 260],
            expect: 0,
            count: 0,
            checksum: 0,
            ok: false,
        }
    }
    fn reset(&mut self) {
        self.expect = 0;
        self.ok = false;
    }
    fn feed(&mut self, e: &[u8]) {
        let seq = e.first().copied().unwrap_or(0);
        let n = seq & 0x1f;
        let sum = e.get(13).copied().unwrap_or(0);
        if seq & 0x40 != 0 {
            if n == 0 || n > 20 {
                self.reset();
                return;
            }
            self.count = n;
            self.checksum = sum;
            self.units = [0xffff; 260];
            self.ok = true;
        } else if !self.ok || n != self.expect || sum != self.checksum {
            self.reset();
            return;
        }
        // 13 units: 5 at 1, 6 at 14, 2 at 28.
        let base = usize::from(n - 1) * 13;
        let at = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
        for (k, off) in at.iter().enumerate() {
            let u = u16::from_le_bytes([
                e.get(*off).copied().unwrap_or(0),
                e.get(off + 1).copied().unwrap_or(0),
            ]);
            if let Some(slot) = self.units.get_mut(base + k) {
                *slot = u;
            }
        }
        self.expect = n - 1;
    }
    /// The long name, if complete and matching `short`.
    fn name(&self, short: &[u8; 11]) -> Option<&[u16]> {
        if !self.ok || self.expect != 0 || self.checksum != short_checksum(short) {
            return None;
        }
        let all = self.units.get(..usize::from(self.count) * 13)?;
        let len = all.iter().position(|&u| u == 0).unwrap_or(all.len());
        // After the terminator only 0xFFFF padding is allowed.
        if all
            .get(len + 1..)
            .is_some_and(|rest| rest.iter().any(|&u| u != 0xffff))
        {
            return None;
        }
        let name = all.get(..len)?;
        (!name.is_empty() && name.len() <= MAX_NAME).then_some(name)
    }
}

/// The 8.3 name as UTF-16 into `out`; `None` for a byte outside printable
/// ASCII (the OEM code page is unknown, so such a name cannot be shown or
/// matched reliably).
fn short_name<'o>(short: &[u8; 11], nt: u8, out: &'o mut [u16; 12]) -> Option<&'o [u16]> {
    let (base, ext) = short.split_at(8);
    let trim = |s: &[u8]| s.len() - s.iter().rev().take_while(|&&b| b == b' ').count();
    let (bl, el) = (trim(base), trim(ext));
    let mut n = 0usize;
    let mut put = |b: u8, lower: bool, n: &mut usize| -> Option<()> {
        if !(0x20..0x7f).contains(&b) {
            return None;
        }
        let b = if lower { b.to_ascii_lowercase() } else { b };
        *out.get_mut(*n)? = u16::from(b);
        *n += 1;
        Some(())
    };
    for (i, &b) in base.iter().take(bl).enumerate() {
        // 0x05 stands for a leading 0xE5 byte (non-ASCII: refused below).
        let b = if i == 0 && b == 0x05 { 0xe5 } else { b };
        put(b, nt & 0x08 != 0, &mut n)?;
    }
    if el > 0 {
        put(b'.', false, &mut n)?;
        for &b in ext.iter().take(el) {
            put(b, nt & 0x10 != 0, &mut n)?;
        }
    }
    (n > 0).then(|| out.get(..n).unwrap_or(&[]))
}

fn eq_name(units: &[u16], s: &str) -> bool {
    let mut a = char::decode_utf16(units.iter().copied());
    let mut b = s.chars();
    loop {
        match (a.next(), b.next()) {
            (None, None) => return true,
            (Some(Ok(x)), Some(y)) => {
                if !x.to_lowercase().eq(y.to_lowercase()) {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

impl Fs {
    /// Read and check the boot sector. `space`: bytes the file system may
    /// occupy (the partition or the superfloppy payload).
    pub fn open<S: Sectors>(
        src: &mut S,
        space: u64,
        scratch: &mut [u8; SCRATCH],
    ) -> Result<Fs, FatError> {
        let boot = scratch.get_mut(..512).ok_or(FatError::Io)?;
        src.read(0, boot)?;
        let bpb = parse_fat32(boot, space).map_err(FatError::Boot)?;
        Ok(Fs { bpb })
    }

    fn bps(&self) -> usize {
        usize::from(self.bpb.bytes_per_sector)
    }

    fn check(&self, c: u32) -> Result<u32, FatError> {
        if c < 2 || u64::from(c) >= u64::from(self.bpb.clusters) + 2 {
            Err(FatError::BadCluster(c))
        } else {
            Ok(c)
        }
    }

    fn first_sector(&self, c: u32) -> u64 {
        let data = u64::from(self.bpb.reserved_sectors)
            + u64::from(self.bpb.fats) * u64::from(self.bpb.fat_sectors);
        data + u64::from(c - 2) * u64::from(self.bpb.sectors_per_cluster)
    }

    /// The cluster after `c`, or `None` at the end of the chain.
    fn next<S: Sectors>(
        &self,
        src: &mut S,
        c: u32,
        scratch: &mut [u8; SCRATCH],
    ) -> Result<Option<u32>, FatError> {
        let off = u64::from(c) * 4;
        let bps = self.bps() as u64;
        let sector = u64::from(self.bpb.reserved_sectors) + off / bps;
        let buf = scratch.get_mut(..self.bps()).ok_or(FatError::Io)?;
        src.read(sector, buf)?;
        let i = (off % bps) as usize;
        let raw: [u8; 4] = buf
            .get(i..i + 4)
            .and_then(|b| b.try_into().ok())
            .ok_or(FatError::Io)?;
        let v = u32::from_le_bytes(raw) & 0x0FFF_FFFF;
        match v {
            v if v >= END => Ok(None),
            BAD => Err(FatError::BadCluster(v)),
            v => self.check(v).map(Some),
        }
    }

    /// Visit every live entry of the directory starting at `cluster`, in
    /// order, until `f` returns `false`.
    fn walk<S: Sectors>(
        &self,
        src: &mut S,
        cluster: u32,
        scratch: &mut [u8; SCRATCH],
        mut f: impl FnMut(&DirEntry<'_>) -> bool,
    ) -> Result<(), FatError> {
        let mut c = self.check(cluster)?;
        let mut lfn = Lfn::new();
        let mut entries = 0u32;
        let mut clusters = 0u32;
        let spc = u64::from(self.bpb.sectors_per_cluster);
        loop {
            clusters += 1;
            if clusters > self.bpb.clusters {
                return Err(FatError::Loop);
            }
            for s in 0..spc {
                let buf = scratch.get_mut(..self.bps()).ok_or(FatError::Io)?;
                src.read(self.first_sector(c) + s, buf)?;
                for e in buf.chunks_exact(32) {
                    entries += 1;
                    if entries > MAX_DIR_ENTRIES {
                        return Err(FatError::TooLarge);
                    }
                    let first = e.first().copied().unwrap_or(0);
                    let attr = e.get(11).copied().unwrap_or(0);
                    if first == 0 {
                        return Ok(());
                    }
                    if first == 0xe5 {
                        lfn.reset();
                        continue;
                    }
                    if attr & 0x3f == ATTR_LFN {
                        lfn.feed(e);
                        continue;
                    }
                    let mut short = [0u8; 11];
                    short.copy_from_slice(e.get(..11).unwrap_or(&[0; 11]));
                    if attr & ATTR_VOLUME != 0 {
                        lfn.reset();
                        continue;
                    }
                    let hi = u16::from_le_bytes([
                        e.get(20).copied().unwrap_or(0),
                        e.get(21).copied().unwrap_or(0),
                    ]);
                    let lo = u16::from_le_bytes([
                        e.get(26).copied().unwrap_or(0),
                        e.get(27).copied().unwrap_or(0),
                    ]);
                    let size = u32::from_le_bytes([
                        e.get(28).copied().unwrap_or(0),
                        e.get(29).copied().unwrap_or(0),
                        e.get(30).copied().unwrap_or(0),
                        e.get(31).copied().unwrap_or(0),
                    ]);
                    let mut sbuf = [0u16; 12];
                    let nt = e.get(12).copied().unwrap_or(0);
                    let name = match lfn.name(&short) {
                        Some(n) => Some(n),
                        None => short_name(&short, nt, &mut sbuf),
                    };
                    if let Some(name) = name {
                        let d = DirEntry {
                            name,
                            is_dir: attr & ATTR_DIR != 0,
                            size,
                            cluster: u32::from(hi) << 16 | u32::from(lo),
                        };
                        if !f(&d) {
                            return Ok(());
                        }
                    }
                    lfn.reset();
                }
            }
            match self.next(src, c, scratch)? {
                Some(n) => c = n,
                None => return Ok(()),
            }
        }
    }

    /// The first cluster of directory `path` (`\` is the root).
    pub fn find_dir<S: Sectors>(
        &self,
        src: &mut S,
        path: &str,
        scratch: &mut [u8; SCRATCH],
    ) -> Result<u32, FatError> {
        let rest = path.strip_prefix('\\').ok_or(FatError::BadPath)?;
        let mut c = self.bpb.root_cluster;
        let mut depth = 0usize;
        for comp in rest.split('\\').filter(|s| !s.is_empty()) {
            if comp == "." || comp == ".." {
                return Err(FatError::BadPath);
            }
            depth += 1;
            if depth > MAX_DEPTH {
                return Err(FatError::TooLarge);
            }
            let mut found = None;
            self.walk(src, c, scratch, |e| {
                if e.is_dir && eq_name(e.name, comp) {
                    found = Some(e.cluster);
                    return false;
                }
                true
            })?;
            // A directory entry pointing at cluster 0 means the root.
            c = match found {
                Some(0) => self.bpb.root_cluster,
                Some(n) => self.check(n)?,
                None => return Err(FatError::NotFound),
            };
        }
        Ok(c)
    }

    /// Report every entry of directory `path` (`.` and `..` included, as
    /// stored) to `f` until it returns `false`.
    pub fn list<S: Sectors>(
        &self,
        src: &mut S,
        path: &str,
        scratch: &mut [u8; SCRATCH],
        f: impl FnMut(&DirEntry<'_>) -> bool,
    ) -> Result<(), FatError> {
        let c = self.find_dir(src, path, scratch)?;
        self.walk(src, c, scratch, f)
    }
}

impl Fs {
    /// The entry `path` names (a file or a directory): its first cluster,
    /// size and kind. `\` alone is refused (the root has no entry).
    pub fn find<S: Sectors>(
        &self,
        src: &mut S,
        path: &str,
        scratch: &mut [u8; SCRATCH],
    ) -> Result<Found, FatError> {
        let rest = path.strip_prefix('\\').ok_or(FatError::BadPath)?;
        let (dir, name) = match rest.rsplit_once('\\') {
            Some((d, n)) => (d, n),
            None => ("", rest),
        };
        if name.is_empty() || name == "." || name == ".." {
            return Err(FatError::BadPath);
        }
        let mut parent = [0u8; 1024];
        let plen = 1 + dir.len();
        let pb = parent.get_mut(..plen).ok_or(FatError::TooLarge)?;
        if let Some((first, tail)) = pb.split_first_mut() {
            *first = b'\\';
            tail.copy_from_slice(dir.as_bytes());
        }
        let parent = core::str::from_utf8(parent.get(..plen).unwrap_or(&[]))
            .map_err(|_| FatError::BadPath)?;
        let c = self.find_dir(src, parent, scratch)?;
        let mut found = None;
        self.walk(src, c, scratch, |e| {
            if eq_name(e.name, name) {
                found = Some(Found {
                    cluster: e.cluster,
                    size: e.size,
                    is_dir: e.is_dir,
                });
                return false;
            }
            true
        })?;
        found.ok_or(FatError::NotFound)
    }
}

/// What [`Fs::find`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    pub cluster: u32,
    pub size: u32,
    pub is_dir: bool,
}

/// Build FAT32 images in memory (tests).
#[cfg(test)]
mod build {
    extern crate std;
    use std::vec;
    use std::vec::Vec;

    use super::short_checksum;
    use crate::disk::{Fat32, build::fat32_boot_sector, parse_fat32};

    /// A FAT32 image with a cluster allocator and a directory writer.
    pub struct Image {
        pub data: Vec<u8>,
        pub bpb: Fat32,
        next: u32,
        serial: u32,
    }

    pub const ROOT: u32 = 2;

    impl Image {
        pub fn new(total_sectors: u32) -> Image {
            let boot = fat32_boot_sector(total_sectors);
            let bpb = parse_fat32(&boot, u64::from(total_sectors) * 512).expect("valid");
            let mut data = vec![0u8; total_sectors as usize * 512];
            data[..512].copy_from_slice(&boot);
            let mut img = Image {
                data,
                bpb,
                next: 3,
                serial: 0,
            };
            img.set_fat(0, 0x0FFF_FFF8);
            img.set_fat(1, 0x0FFF_FFFF);
            img.set_fat(ROOT, 0x0FFF_FFFF);
            img
        }

        pub fn set_fat(&mut self, c: u32, v: u32) {
            for f in 0..u32::from(self.bpb.fats) {
                let at = (u32::from(self.bpb.reserved_sectors) + f * self.bpb.fat_sectors) as usize
                    * 512
                    + c as usize * 4;
                self.data[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
        }

        pub fn cluster_bytes(&self) -> usize {
            usize::from(self.bpb.sectors_per_cluster) * 512
        }

        pub fn cluster_at(&self, c: u32) -> usize {
            let data = u32::from(self.bpb.reserved_sectors)
                + u32::from(self.bpb.fats) * self.bpb.fat_sectors;
            (data + (c - 2) * u32::from(self.bpb.sectors_per_cluster)) as usize * 512
        }

        /// A fresh chain of `n` clusters.
        pub fn alloc(&mut self, n: u32) -> u32 {
            let first = self.next;
            for i in 0..n {
                let c = first + i;
                self.set_fat(c, if i + 1 == n { 0x0FFF_FFFF } else { c + 1 });
            }
            self.next += n;
            first
        }

        /// The clusters of the chain starting at `c` (bounded).
        pub fn chain(&self, c: u32) -> Vec<u32> {
            let mut out = vec![c];
            let mut cur = c;
            while out.len() < 1000 {
                let at = u32::from(self.bpb.reserved_sectors) as usize * 512 + cur as usize * 4;
                let v = u32::from_le_bytes(self.data[at..at + 4].try_into().unwrap()) & 0x0FFF_FFFF;
                if !(2..0x0FFF_FFF7).contains(&v) || v >= self.bpb.clusters + 2 || out.contains(&v)
                {
                    break;
                }
                out.push(v);
                cur = v;
            }
            out
        }

        /// Write 32-byte entries into directory `dir` (a chain), after
        /// `skip` existing entries.
        pub fn write_entries(&mut self, dir: u32, skip: usize, entries: &[[u8; 32]]) {
            let per = self.cluster_bytes() / 32;
            let chain = self.chain(dir);
            for (i, e) in entries.iter().enumerate() {
                let k = skip + i;
                let c = chain[k / per];
                let at = self.cluster_at(c) + (k % per) * 32;
                self.data[at..at + 32].copy_from_slice(e);
            }
        }

        /// A short entry.
        pub fn short(name: &[u8; 11], attr: u8, nt: u8, cluster: u32, size: u32) -> [u8; 32] {
            let mut e = [0u8; 32];
            e[..11].copy_from_slice(name);
            e[11] = attr;
            e[12] = nt;
            e[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
            e[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
            e[28..32].copy_from_slice(&size.to_le_bytes());
            e
        }

        /// The VFAT entries for `long` (last first) followed by the short
        /// entry; the short name is generated (`LONG~N  EXT`).
        pub fn named(&mut self, long: &str, attr: u8, cluster: u32, size: u32) -> Vec<[u8; 32]> {
            self.serial += 1;
            let mut short = *b"           ";
            let tag = std::format!("F{:05}~1", self.serial);
            short[..8].copy_from_slice(tag.as_bytes());
            if let Some((_, ext)) = long.rsplit_once('.') {
                for (i, b) in ext
                    .bytes()
                    .filter(u8::is_ascii_alphanumeric)
                    .take(3)
                    .enumerate()
                {
                    short[8 + i] = b.to_ascii_uppercase();
                }
            }
            let units: Vec<u16> = long.encode_utf16().collect();
            let n = units.len().div_ceil(13);
            let sum = short_checksum(&short);
            let mut out = Vec::new();
            for seq in (1..=n).rev() {
                let mut e = [0u8; 32];
                e[0] = seq as u8 | if seq == n { 0x40 } else { 0 };
                e[11] = 0x0f;
                e[13] = sum;
                let offs = [1usize, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
                for (k, off) in offs.iter().enumerate() {
                    let i = (seq - 1) * 13 + k;
                    let u = match i.cmp(&units.len()) {
                        core::cmp::Ordering::Less => units[i],
                        core::cmp::Ordering::Equal => 0,
                        core::cmp::Ordering::Greater => 0xffff,
                    };
                    e[*off..off + 2].copy_from_slice(&u.to_le_bytes());
                }
                out.push(e);
            }
            out.push(Self::short(&short, attr, 0, cluster, size));
            out
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::build::{Image, ROOT};
    use super::*;
    use std::string::String;
    use std::vec;
    use std::vec::Vec;

    impl Sectors for Image {
        fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), FatError> {
            let at = usize::try_from(sector).map_err(|_| FatError::Io)? * 512;
            let src = self.data.get(at..at + buf.len()).ok_or(FatError::Io)?;
            buf.copy_from_slice(src);
            Ok(())
        }
    }

    fn names(img: &mut Image, path: &str) -> Result<Vec<(String, bool, u32)>, FatError> {
        let mut scratch = [0u8; SCRATCH];
        let space = img.data.len() as u64;
        let fs = Fs::open(img, space, &mut scratch)?;
        let mut out = Vec::new();
        fs.list(img, path, &mut scratch, |e| {
            out.push((String::from_utf16_lossy(e.name), e.is_dir, e.size));
            true
        })?;
        Ok(out)
    }

    /// `\EFI\BOOT\BOOTX64.EFI`, `\EFI\systemd\systemd-bootx64.efi`, a volume
    /// label, a deleted entry, a short-only name with NT case flags.
    fn esp() -> Image {
        let mut img = Image::new(4096);
        let efi = img.alloc(1);
        let boot = img.alloc(1);
        let sd = img.alloc(1);
        let mut root = vec![Image::short(b"ESP        ", ATTR_VOLUME, 0, 0, 0)];
        root.extend(img.named("EFI", ATTR_DIR, efi, 0));
        let mut gone = Image::short(b"OLD     TXT", 0x20, 0, 0, 1);
        gone[0] = 0xe5;
        root.push(gone);
        root.push(Image::short(b"README  TXT", 0x20, 0x18, 0, 12));
        img.write_entries(ROOT, 0, &root);
        let mut e = vec![
            Image::short(b".          ", ATTR_DIR, 0, efi, 0),
            Image::short(b"..         ", ATTR_DIR, 0, 0, 0),
        ];
        e.extend(img.named("BOOT", ATTR_DIR, boot, 0));
        e.extend(img.named("systemd", ATTR_DIR, sd, 0));
        img.write_entries(efi, 0, &e);
        let mut b = vec![Image::short(b".          ", ATTR_DIR, 0, boot, 0)];
        b.push(Image::short(b"BOOTX64 EFI", 0x20, 0, 0, 1234));
        img.write_entries(boot, 0, &b);
        let s = img.named("systemd-bootx64.efi", 0x20, 0, 98_304);
        img.write_entries(sd, 0, &s);
        img
    }

    #[test]
    fn lists_long_and_short_names() {
        let mut img = esp();
        assert_eq!(
            names(&mut img, "\\").unwrap(),
            [("EFI".into(), true, 0), ("readme.txt".into(), false, 12)],
            "label and deleted entry skipped; NT lower-case flags applied"
        );
        let efi: Vec<_> = names(&mut img, "\\EFI")
            .unwrap()
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(efi, [".", "..", "BOOT", "systemd"]);
        assert_eq!(
            names(&mut img, "\\efi\\boot").unwrap()[1],
            ("BOOTX64.EFI".into(), false, 1234),
            "paths match case-insensitively"
        );
        assert_eq!(
            names(&mut img, "\\EFI\\SYSTEMD\\").unwrap(),
            [("systemd-bootx64.efi".into(), false, 98_304)]
        );
        assert_eq!(names(&mut img, "\\EFI\\nope"), Err(FatError::NotFound));
        assert_eq!(
            names(&mut img, "\\README.TXT"),
            Err(FatError::NotFound),
            "not a directory"
        );
        assert_eq!(names(&mut img, "EFI"), Err(FatError::BadPath));
        assert_eq!(names(&mut img, "\\EFI\\..\\EFI"), Err(FatError::BadPath));
    }

    #[test]
    fn find_files_and_directories() {
        let mut img = esp();
        let mut scratch = [0u8; SCRATCH];
        let space = img.data.len() as u64;
        let fs = Fs::open(&mut img, space, &mut scratch).unwrap();
        let f = fs
            .find(&mut img, "\\efi\\BOOT\\bootx64.efi", &mut scratch)
            .unwrap();
        assert_eq!((f.size, f.is_dir), (1234, false));
        assert!(
            fs.find(&mut img, "\\EFI\\systemd", &mut scratch)
                .unwrap()
                .is_dir
        );
        assert!(fs.find(&mut img, "\\readme.TXT", &mut scratch).is_ok());
        assert_eq!(
            fs.find(&mut img, "\\EFI\\BOOT\\nope.efi", &mut scratch),
            Err(FatError::NotFound)
        );
        assert_eq!(
            fs.find(&mut img, "\\nope\\x.efi", &mut scratch),
            Err(FatError::NotFound)
        );
        for bad in ["\\", "EFI", "\\EFI\\", "\\EFI\\..", "\\EFI\\."] {
            assert_eq!(
                fs.find(&mut img, bad, &mut scratch),
                Err(FatError::BadPath),
                "{bad}"
            );
        }
        let long = std::format!("\\{}\\x", "d".repeat(1100));
        assert_eq!(
            fs.find(&mut img, &long, &mut scratch),
            Err(FatError::TooLarge)
        );
    }

    #[test]
    fn a_directory_spanning_clusters() {
        let mut img = Image::new(8192);
        let dir = img.alloc(5);
        let mut root = Vec::new();
        root.extend(img.named("many", ATTR_DIR, dir, 0));
        img.write_entries(ROOT, 0, &root);
        let mut all = Vec::new();
        for i in 0..150 {
            all.extend(img.named(
                &std::format!("kernel-{i:03}-with-a-long-name.efi"),
                0x20,
                0,
                i,
            ));
        }
        let per = img.cluster_bytes() / 32;
        assert!(all.len() > 4 * per, "spans five clusters");
        img.write_entries(dir, 0, &all);
        let got = names(&mut img, "\\many").unwrap();
        assert_eq!(got.len(), 150);
        assert_eq!(got[149].0, "kernel-149-with-a-long-name.efi");
    }

    #[test]
    fn broken_long_names_fall_back_to_the_short_name() {
        let mut img = Image::new(4096);
        let mut e = img.named("a-long-name.efi", 0x20, 0, 1);
        e[0][13] ^= 1; // checksum of one VFAT part
        let mut orphan = img.named("orphan-name.efi", 0x20, 0, 2);
        orphan.remove(0); // the first (highest) part missing
        let mut root = e;
        root.extend(orphan);
        img.write_entries(ROOT, 0, &root);
        let got: Vec<_> = names(&mut img, "\\")
            .unwrap()
            .into_iter()
            .map(|e| e.0)
            .collect();
        assert_eq!(got, ["F00001~1.EFI", "F00002~1.EFI"]);
    }

    #[test]
    fn hostile_chains_and_clusters_are_refused() {
        // A full directory cluster whose chain loops back to itself.
        let mut img = esp();
        let full = img.cluster_bytes() / 32;
        let fill: Vec<_> = (0..full)
            .map(|_| Image::short(b"X       EFI", 0x20, 0, 0, 0))
            .collect();
        img.write_entries(ROOT, 0, &fill);
        img.set_fat(ROOT, ROOT);
        assert_eq!(names(&mut img, "\\"), Err(FatError::Loop));
        // A chain into a bad cluster and past the volume.
        let mut img = esp();
        img.set_fat(ROOT, 0x0FFF_FFF7);
        img.write_entries(ROOT, 0, &fill);
        assert_eq!(
            names(&mut img, "\\"),
            Err(FatError::BadCluster(0x0FFF_FFF7))
        );
        img.set_fat(ROOT, 0x0FFF_0000);
        assert!(matches!(
            names(&mut img, "\\"),
            Err(FatError::BadCluster(_))
        ));
        // A subdirectory entry pointing outside the volume.
        let mut img = esp();
        let mut root = Vec::new();
        root.extend(img.named("far", ATTR_DIR, 0x0100_0000, 0));
        img.write_entries(ROOT, 0, &root);
        assert_eq!(
            names(&mut img, "\\far"),
            Err(FatError::BadCluster(0x0100_0000))
        );
        // Not FAT32 at all.
        let mut img = esp();
        img.data[82] = b'X';
        assert!(matches!(names(&mut img, "\\"), Err(FatError::Boot(_))));
    }

    #[test]
    fn paths_are_bounded() {
        let mut img = Image::new(4096);
        let mut c = ROOT;
        for _ in 0..40 {
            let d = img.alloc(1);
            let e = Image::short(b"D          ", ATTR_DIR, 0, d, 0);
            img.write_entries(c, 0, &[e]);
            c = d;
        }
        let deep: String = "\\D".repeat(32);
        assert!(names(&mut img, &deep).is_ok());
        let deeper: String = "\\D".repeat(33);
        assert_eq!(names(&mut img, &deeper), Err(FatError::TooLarge));
    }

    /// Cross-check against a third-party writer: `mkfs.fat` and `mcopy`
    /// (skipped when they are not installed).
    #[test]
    fn reads_what_mtools_writes() {
        use std::process::Command;
        let ok = |c: &mut Command| c.output().map(|o| o.status.success()).unwrap_or(false);
        let dir = std::env::temp_dir().join(std::format!("paguro-fat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("EFI/systemd")).unwrap();
        std::fs::write(dir.join("EFI/systemd/systemd-bootx64.efi"), b"MZ").unwrap();
        std::fs::create_dir_all(dir.join("EFI/Linux")).unwrap();
        std::fs::write(dir.join("EFI/Linux/linux-6.11.4-arch1-1.efi"), [0u8; 3000]).unwrap();
        let img = dir.join("esp.img");
        if !ok(Command::new("mkfs.fat")
            .args(["-F", "32", "-C"])
            .arg(&img)
            .arg("65536"))
            || !ok(Command::new("mcopy")
                .arg("-i")
                .arg(&img)
                .arg("-s")
                .arg(dir.join("EFI"))
                .arg("::/"))
        {
            std::eprintln!("mkfs.fat/mcopy unavailable: skipped");
            return;
        }
        let data = std::fs::read(&img).unwrap();
        let mut src = Mem(data);
        let mut scratch = [0u8; SCRATCH];
        let space = src.0.len() as u64;
        let fs = Fs::open(&mut src, space, &mut scratch).unwrap();
        let mut got = Vec::new();
        fs.list(&mut src, "\\EFI\\Linux", &mut scratch, |e| {
            got.push((String::from_utf16_lossy(e.name), e.size));
            true
        })
        .unwrap();
        assert!(
            got.contains(&("linux-6.11.4-arch1-1.efi".into(), 3000)),
            "{got:?}"
        );
        let mut sd = Vec::new();
        fs.list(&mut src, "\\efi\\SYSTEMD", &mut scratch, |e| {
            sd.push(String::from_utf16_lossy(e.name));
            true
        })
        .unwrap();
        assert!(sd.contains(&"systemd-bootx64.efi".into()), "{sd:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct Mem(Vec<u8>);

    impl Sectors for Mem {
        fn read(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), FatError> {
            let at = usize::try_from(sector).map_err(|_| FatError::Io)? * 512;
            buf.copy_from_slice(self.0.get(at..at + buf.len()).ok_or(FatError::Io)?);
            Ok(())
        }
    }
}
