//! Pure planning: device-mapper tables as text, testable without root.

use core::fmt::Write;

use paguro_core::bde::Cipher;
use paguro_core::gpt::Entry;
use paguro_core::guid::{GPT_ESP, Guid};
use paguro_core::handoff::FveLayout;

/// Sectors reserved for the primary GPT plus 1 MiB alignment, and for the
/// backup GPT (DESIGN.md §4.3, the dm-linear sandwich).
pub const GPT_HEAD_SECTORS: u64 = 2048;
pub const GPT_TAIL_SECTORS: u64 = 33;

/// Device-mapper's sector: every table start, length and offset is in
/// 512-byte units, whatever the device's logical block size.
pub const SECTOR: u64 = 512;
/// BitLocker sector sizes the loader accepts (as `bde::Layout::new`).
const BDE_SECTOR_SIZES: [u64; 2] = [512, 4096];

/// The BitLocker XTS ciphers (FVE metadata `encryption` field) and the
/// `aes-xts-plain64` key length each takes: two AES keys.
const XTS_AES_128: u16 = Cipher::XtsAes128.to_u16();
const XTS_AES_256: u16 = Cipher::XtsAes256.to_u16();
const XTS_AES_128_KEY_LEN: usize = 32;
const XTS_AES_256_KEY_LEN: usize = 64;

pub struct VmDisk<'a> {
    pub gpt_head: &'a str,
    pub esp: &'a str,
    pub msr: &'a str,
    /// The module's protected view B.
    pub volume: &'a str,
    pub gpt_tail: &'a str,
    pub esp_sectors: u64,
    pub msr_sectors: u64,
    pub volume_sectors: u64,
}

/// The synthetic disk handed to QEMU: stock `dm-linear`, built in userspace,
/// untrusted by construction — enforcement lives beneath it, in view B.
pub fn vm_disk_table(d: &VmDisk<'_>) -> String {
    let segs = [
        (GPT_HEAD_SECTORS, d.gpt_head),
        (d.esp_sectors, d.esp),
        (d.msr_sectors, d.msr),
        (d.volume_sectors, d.volume),
        (GPT_TAIL_SECTORS, d.gpt_tail),
    ];
    let mut out = String::new();
    let mut start = 0u64;
    for (len, dev) in segs {
        let _ = writeln!(out, "{start} {len} linear {dev} 0");
        start = start.saturating_add(len);
    }
    out
}

// ---------------------------------------------------------------------------
// The decrypted volume (DESIGN.md §4.3 "The decrypted volume is a handful of
// segments, not one target")

/// Where a stretch of the decrypted volume comes from. Sectors are 512-byte
/// units of the partition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seg {
    /// `crypt` over the partition from `dev`, IV sector `iv` at the start.
    /// Always `iv == dev`: BitLocker's tweak is the physical sector.
    Crypt { dev: u64, iv: u64 },
    /// `linear` over the partition from `dev`: stored in plaintext
    /// (beyond `encrypted_size`).
    Linear { dev: u64 },
    /// `zero`: metadata regions and the relocated boot-sector copy.
    Zero,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub start: u64,
    pub len: u64,
    pub kind: Seg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayoutError {
    SectorSize,
    /// An offset or size not a whole number of XTS data units.
    Unaligned,
    /// A region outside the volume, or an empty one.
    Outside,
    Overlap,
    EncryptedSize,
}

/// The five non-data regions, in bytes: `[0, reloc)`, the relocated copy,
/// the three metadata regions.
fn regions(l: &FveLayout) -> Option<[(u64, u64); 5]> {
    let reloc = u64::from(l.boot_sector_reloc_sectors).checked_mul(SECTOR)?;
    let [m0, m1, m2] = l.metadata_offsets;
    Some([
        (0, reloc),
        (l.boot_sector_reloc_offset, reloc),
        (m0, l.region_size),
        (m1, l.region_size),
        (m2, l.region_size),
    ])
}

/// Validate the handoff's layout against a partition of `volume_sectors`
/// 512-byte sectors — the same rules the loader applied when it read the
/// metadata (`paguro_core::bde::Layout::new`) — and return the volume's
/// length in bytes (whole data units).
pub fn check_layout(volume_sectors: u64, l: &FveLayout) -> Result<u64, LayoutError> {
    let bps = u64::from(l.sector_size);
    if !BDE_SECTOR_SIZES.contains(&bps) {
        return Err(LayoutError::SectorSize);
    }
    let bytes = volume_sectors
        .checked_mul(SECTOR)
        .ok_or(LayoutError::Outside)?;
    let volume = bytes - bytes % bps;
    let r = regions(l).ok_or(LayoutError::Outside)?;
    for (i, &(o, len)) in r.iter().enumerate() {
        if len == 0 || (i > 0 && o == 0) {
            return Err(LayoutError::Outside);
        }
        if o % bps != 0 || len % bps != 0 {
            return Err(LayoutError::Unaligned);
        }
    }
    for (i, &(o, len)) in r.iter().enumerate() {
        if o.checked_add(len).is_none_or(|end| end > volume) {
            return Err(LayoutError::Outside);
        }
        for &(o2, l2) in r.iter().skip(i + 1) {
            if o < o2.saturating_add(l2) && o2 < o.saturating_add(len) {
                return Err(LayoutError::Overlap);
            }
        }
    }
    // Windows 10+'s further region beside the metadata: reserved (never
    // part of a claim) but, like libbde, dislocker and cryptsetup, not
    // hidden from the decrypted view.
    if let Some(x) = extra(l) {
        if x % bps != 0 || l.region_size % bps != 0 {
            return Err(LayoutError::Unaligned);
        }
        if x.checked_add(l.region_size).is_none_or(|end| end > volume) {
            return Err(LayoutError::Outside);
        }
        if r.iter()
            .any(|&(o, len)| x < o.saturating_add(len) && o < x + l.region_size)
        {
            return Err(LayoutError::Overlap);
        }
    }
    if l.encrypted_size > volume || l.encrypted_size % bps != 0 {
        return Err(LayoutError::EncryptedSize);
    }
    Ok(volume)
}

/// The decrypted volume's segment table: O(1) segments whatever the files
/// on it look like. Mirrors `paguro_core::bde::Layout::map`, the loader's
/// own reader, unit for unit (tested exhaustively below).
pub fn crypt_segments(volume_sectors: u64, l: &FveLayout) -> Result<Vec<Segment>, LayoutError> {
    let volume = check_layout(volume_sectors, l)?;
    let r = regions(l).ok_or(LayoutError::Outside)?;
    let [(_, reloc), hidden @ ..] = r;
    let enc = l.encrypted_size;
    // Byte boundaries at which the source can change.
    let mut cuts = vec![0, volume, reloc, enc];
    let ro = l.boot_sector_reloc_offset;
    if enc > ro && enc - ro < reloc {
        cuts.push(enc - ro);
    }
    for (o, len) in hidden {
        cuts.push(o);
        cuts.push(o + len);
    }
    cuts.retain(|&c| c <= volume);
    cuts.sort_unstable();
    cuts.dedup();
    let source = |off: u64| -> Seg {
        let (phys, zero) = if off < reloc {
            (ro + off, false)
        } else {
            (
                off,
                hidden.iter().any(|&(o, len)| off >= o && off < o + len),
            )
        };
        match (zero, phys < enc) {
            (true, _) => Seg::Zero,
            (false, true) => Seg::Crypt {
                dev: phys / SECTOR,
                iv: phys / SECTOR,
            },
            (false, false) => Seg::Linear { dev: phys / SECTOR },
        }
    };
    let mut out: Vec<Segment> = Vec::new();
    for w in cuts.windows(2) {
        let (a, b) = match w {
            [a, b] if b > a => (*a, *b),
            _ => continue,
        };
        let seg = Segment {
            start: a / SECTOR,
            len: (b - a) / SECTOR,
            kind: source(a),
        };
        // Merge a continuation of the previous segment.
        if let Some(p) = out.last_mut() {
            let cont = match (p.kind, seg.kind) {
                (Seg::Zero, Seg::Zero) => true,
                (Seg::Crypt { dev, .. }, Seg::Crypt { dev: d2, .. })
                | (Seg::Linear { dev }, Seg::Linear { dev: d2 }) => dev + p.len == d2,
                _ => false,
            };
            if cont {
                p.len += seg.len;
                continue;
            }
        }
        out.push(seg);
    }
    Ok(out)
}

/// `dm-crypt`'s name for a BitLocker cipher, and its key length. Only the
/// ciphers the loader accepts (XTS, Windows 10 1511+).
pub fn dm_cipher(bitlocker: u16) -> Option<(&'static str, usize)> {
    match bitlocker {
        XTS_AES_128 => Some(("aes-xts-plain64", XTS_AES_128_KEY_LEN)),
        XTS_AES_256 => Some(("aes-xts-plain64", XTS_AES_256_KEY_LEN)),
        _ => None,
    }
}

/// One device-mapper target line: start, length, type, parameters.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub start: u64,
    pub len: u64,
    pub kind: &'static str,
    pub params: String,
}

/// The decrypted volume as a table over `dev` (the raw partition). The key
/// is never in the table: `keyref` names a kernel `logon` key
/// (`:<len>:logon:<desc>`), which `dm-crypt` copies at construction.
pub fn crypt_table(
    segs: &[Segment],
    dev: &str,
    cipher: &str,
    keyref: &str,
    sector_size: u32,
) -> Vec<Target> {
    let opts = if u64::from(sector_size) == SECTOR {
        String::new()
    } else {
        // IV counted in data units, not 512-byte sectors: iv_offset is
        // still given in 512-byte sectors and shifted by the kernel.
        format!(" 2 sector_size:{sector_size} iv_large_sectors")
    };
    segs.iter()
        .map(|s| {
            let (kind, params) = match s.kind {
                Seg::Crypt { dev: d, iv } => {
                    ("crypt", format!("{cipher} {keyref} {iv} {dev} {d}{opts}"))
                }
                Seg::Linear { dev: d } => ("linear", format!("{dev} {d}")),
                Seg::Zero => ("zero", String::new()),
            };
            Target {
                start: s.start,
                len: s.len,
                kind,
                params,
            }
        })
        .collect()
}

/// `PG_VOLUME_ADD`'s reserved ranges (INTERFACES.md §10.2), 512-byte
/// sectors: BitLocker's non-data regions.
pub fn reserved_ranges(l: &FveLayout) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = regions(l)
        .map(|r| {
            r.iter()
                .map(|&(o, len)| (o / SECTOR, len / SECTOR))
                .collect()
        })
        .unwrap_or_default();
    if let Some(x) = extra(l) {
        out.push((x / SECTOR, l.region_size / SECTOR));
    }
    out
}

fn extra(l: &FveLayout) -> Option<u64> {
    (l.extra_region_offset != 0).then_some(l.extra_region_offset)
}

// ---------------------------------------------------------------------------
// Which partition of a GPT root disk is the root

/// Discoverable Partitions: the root of this architecture.
#[cfg(target_arch = "x86_64")]
pub const ROOT_NATIVE: &str = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
#[cfg(target_arch = "aarch64")]
pub const ROOT_NATIVE: &str = "b921b045-1df0-41c3-af44-4c6f280d3fae";
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const ROOT_NATIVE: &str = "00000000-0000-0000-0000-000000000000";
/// Linux filesystem data.
pub const LINUX_DATA: &str = "0fc63daf-8483-4772-8e79-3d69d8477de4";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootChoice {
    /// Index into the entries.
    Index(usize),
    None,
    /// Several candidates and nothing to choose between them.
    Ambiguous,
}

/// `hint`: `paguro.root=` from the kernel command line — a partition
/// number (1-based GPT slot) or `PARTUUID=<guid>`. Without one: the single
/// partition typed as this architecture's root, else the single Linux
/// filesystem partition.
pub fn choose_root(entries: &[(u32, Entry)], hint: Option<&str>) -> RootChoice {
    if let Some(h) = hint {
        let found = if let Some(u) = h
            .strip_prefix("PARTUUID=")
            .or_else(|| h.strip_prefix("partuuid="))
        {
            let Ok(g) = Guid::parse(u) else {
                return RootChoice::None;
            };
            entries.iter().position(|(_, e)| e.unique_guid == g)
        } else {
            let Ok(n) = h.parse::<u32>() else {
                return RootChoice::None;
            };
            entries.iter().position(|(slot, _)| slot + 1 == n)
        };
        return found.map_or(RootChoice::None, RootChoice::Index);
    }
    for ty in [ROOT_NATIVE, LINUX_DATA] {
        let Ok(t) = Guid::parse(ty) else { continue };
        let hits: Vec<usize> = entries
            .iter()
            .enumerate()
            .filter(|(_, (_, e))| e.type_guid == t)
            .map(|(i, _)| i)
            .collect();
        match hits.as_slice() {
            [i] => return RootChoice::Index(*i),
            [] => continue,
            _ => return RootChoice::Ambiguous,
        }
    }
    RootChoice::None
}

pub fn is_esp(e: &Entry) -> bool {
    e.type_guid == GPT_ESP
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use paguro_core::bde::{Cipher, Layout, Source};

    #[test]
    fn sandwich_is_contiguous() {
        let t = vm_disk_table(&VmDisk {
            gpt_head: "h",
            esp: "e",
            msr: "m",
            volume: "v",
            gpt_tail: "t",
            esp_sectors: 10,
            msr_sectors: 20,
            volume_sectors: 30,
        });
        let lines: Vec<&str> = t.lines().collect();
        assert_eq!(lines[0], "0 2048 linear h 0");
        assert_eq!(lines[3], "2078 30 linear v 0");
        assert_eq!(lines[4], "2108 33 linear t 0");
    }

    fn fve(bps: u32, md: [u64; 3], reloc_off: u64, reloc_sectors: u32, enc: u64) -> FveLayout {
        FveLayout {
            metadata_offsets: md,
            region_size: 0x10000,
            boot_sector_reloc_offset: reloc_off,
            boot_sector_reloc_sectors: reloc_sectors,
            encrypted_size: enc,
            sector_size: bps,
            extra_region_offset: 0,
        }
    }

    /// Every data unit of the table agrees with the loader's reader.
    fn agrees(volume_sectors: u64, l: &FveLayout) {
        let segs = crypt_segments(volume_sectors, l).unwrap();
        let volume = check_layout(volume_sectors, l).unwrap();
        let reference = Layout {
            bytes_per_sector: l.sector_size,
            volume_size: volume,
            metadata_offsets: l.metadata_offsets,
            reloc_len: u64::from(l.boot_sector_reloc_sectors) * 512,
            reloc_offset: l.boot_sector_reloc_offset,
            extra_region: extra(l),
            encrypted_size: l.encrypted_size,
            cipher: Cipher::XtsAes128,
            partial: l.encrypted_size < volume,
        };
        // Contiguous from 0 to the end.
        let mut at = 0;
        for s in &segs {
            assert_eq!(s.start, at, "{segs:?}");
            assert!(s.len > 0);
            at += s.len;
        }
        assert_eq!(at * 512, volume);
        let bps = u64::from(l.sector_size);
        let per = bps / 512;
        for unit in 0..reference.units() {
            let sector = unit * per;
            let s = segs
                .iter()
                .find(|s| sector >= s.start && sector < s.start + s.len)
                .unwrap();
            // Data units never straddle a segment.
            assert!(s.start % per == 0 && s.len % per == 0, "{s:?}");
            let (src, _) = reference.map(unit).unwrap();
            let off = sector - s.start;
            match (s.kind, src) {
                (Seg::Zero, Source::Zero) => {}
                (
                    Seg::Crypt { dev, iv },
                    Source::Disk {
                        unit: p,
                        encrypted: true,
                    },
                ) => {
                    assert_eq!((dev + off) / per, p, "unit {unit}");
                    // dm-crypt's tweak: (iv_offset + offset) in data units.
                    assert_eq!((iv + off) / per, p, "tweak of unit {unit}");
                }
                (
                    Seg::Linear { dev },
                    Source::Disk {
                        unit: p,
                        encrypted: false,
                    },
                ) => assert_eq!((dev + off) / per, p),
                (k, r) => panic!("unit {unit}: table {k:?}, reader {r:?}"),
            }
        }
    }

    #[test]
    fn windows_like_layout() {
        // 64 MiB volume, regions spread as Windows places them.
        let l = fve(
            512,
            [0x0100_0000, 0x0200_0000, 0x0300_0000],
            0x0180_0000,
            16,
            64 << 20,
        );
        agrees(131_072, &l);
        let segs = crypt_segments(131_072, &l).unwrap();
        // reloc front, then data/zero alternating: a handful.
        assert!(segs.len() <= 10, "{segs:?}");
        assert_eq!(
            segs[0],
            Segment {
                start: 0,
                len: 16,
                kind: Seg::Crypt {
                    dev: 0xc000,
                    iv: 0xc000
                }
            }
        );
    }

    #[test]
    fn partial_encryption_and_4k() {
        for enc in [
            0u64,
            4096,
            0x0080_0000,
            0x0180_0000 + 4096,
            0x0280_0000,
            64 << 20,
        ] {
            let l = fve(
                4096,
                [0x0100_0000, 0x0200_0000, 0x0300_0000],
                0x0180_0000,
                16,
                enc,
            );
            agrees(131_072, &l);
            let l5 = FveLayout {
                sector_size: 512,
                ..l
            };
            agrees(131_072 + 7, &l5);
        }
        // The encrypted boundary inside the relocated copy.
        let l = fve(
            512,
            [0x10000, 0x40000, 0x80000],
            0x20000,
            16,
            0x20000 + 2048,
        );
        agrees(2048, &l);
    }

    #[test]
    fn randomised_layouts() {
        // xorshift: deterministic, no dependency.
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = |m: u64| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x % m
        };
        let mut tried = 0;
        while tried < 300 {
            let bps: u64 = if next(2) == 0 { 512 } else { 4096 };
            let vol_units = 64 + next(2000);
            let reloc_units = 1 + next(4);
            let region = 0x10000;
            let span = |len_units: u64| vol_units.saturating_sub(len_units).max(1);
            let md = [
                next(span(region / bps)) * bps,
                next(span(region / bps)) * bps,
                next(span(region / bps)) * bps,
            ];
            let ro = next(span(reloc_units)) * bps;
            let reloc_sectors = (reloc_units * bps / 512) as u32;
            let enc = next(vol_units + 1) * bps;
            let l = FveLayout {
                metadata_offsets: md,
                region_size: region,
                boot_sector_reloc_offset: ro,
                boot_sector_reloc_sectors: reloc_sectors,
                encrypted_size: enc,
                sector_size: bps as u32,
                extra_region_offset: if next(2) == 0 {
                    0
                } else {
                    next(vol_units) * bps
                },
            };
            let sectors = vol_units * bps / 512 + next(8);
            if check_layout(sectors, &l).is_err() {
                continue;
            }
            tried += 1;
            agrees(sectors, &l);
        }
    }

    #[test]
    fn refusals() {
        let ok = fve(512, [0x10000, 0x40000, 0x80000], 0x20000, 16, 0x100000);
        assert!(check_layout(2048, &ok).is_ok());
        let e = |l: FveLayout| check_layout(2048, &l).unwrap_err();
        assert_eq!(
            e(FveLayout {
                sector_size: 1024,
                ..ok
            }),
            LayoutError::SectorSize
        );
        assert_eq!(
            e(FveLayout {
                metadata_offsets: [0x10001, 0x40000, 0x80000],
                ..ok
            }),
            LayoutError::Unaligned
        );
        assert_eq!(
            e(FveLayout {
                metadata_offsets: [0, 0x40000, 0x80000],
                ..ok
            }),
            LayoutError::Outside
        );
        assert_eq!(
            e(FveLayout {
                metadata_offsets: [0x10000, 0x18000, 0x80000],
                ..ok
            }),
            LayoutError::Overlap
        );
        assert_eq!(
            e(FveLayout {
                metadata_offsets: [0x10000, 0x40000, 0xf8000],
                ..ok
            }),
            LayoutError::Outside
        );
        assert_eq!(
            e(FveLayout {
                boot_sector_reloc_sectors: 0,
                ..ok
            }),
            LayoutError::Outside
        );
        assert_eq!(
            e(FveLayout {
                boot_sector_reloc_offset: 0x10000,
                ..ok
            }),
            LayoutError::Overlap
        );
        assert_eq!(
            e(FveLayout {
                encrypted_size: 0x100200,
                ..ok
            }),
            LayoutError::EncryptedSize
        );
        let e4 = FveLayout {
            sector_size: 4096,
            encrypted_size: 0x100200,
            ..ok
        };
        assert_eq!(
            check_layout(2048, &e4).unwrap_err(),
            LayoutError::EncryptedSize
        );
    }

    #[test]
    fn table_text() {
        let l = fve(4096, [0x10000, 0x40000, 0x80000], 0x20000, 16, 0x80000);
        let segs = crypt_segments(2048, &l).unwrap();
        let t = crypt_table(
            &segs,
            "254:1",
            "aes-xts-plain64",
            ":32:logon:paguro:fvek",
            4096,
        );
        assert_eq!(t[0].kind, "crypt");
        assert_eq!(
            t[0].params,
            "aes-xts-plain64 :32:logon:paguro:fvek 256 254:1 256 2 sector_size:4096 iv_large_sectors"
        );
        assert!(t.iter().any(|t| t.kind == "zero" && t.params.is_empty()));
        let last = t.last().unwrap();
        assert_eq!((last.kind, last.params.as_str()), ("linear", "254:1 1152"));
        assert_eq!(
            reserved_ranges(&l),
            vec![(0, 16), (256, 16), (128, 128), (512, 128), (1024, 128)]
        );
        // Windows 10+: reserved, but still data in the table.
        let x = FveLayout {
            extra_region_offset: 0x30000,
            ..l
        };
        assert_eq!(reserved_ranges(&x).last(), Some(&(384, 128)));
        assert_eq!(crypt_segments(2048, &x).unwrap(), segs);
        let bad = FveLayout {
            extra_region_offset: 0x18000,
            ..l
        };
        assert_eq!(check_layout(2048, &bad).unwrap_err(), LayoutError::Overlap);
    }

    fn entry(ty: &str, uniq: &str) -> Entry {
        Entry {
            type_guid: Guid::parse(ty).unwrap(),
            unique_guid: Guid::parse(uniq).unwrap(),
            first_lba: 2048,
            last_lba: 4095,
            attributes: 0,
            name: [0; 36],
        }
    }

    #[test]
    fn root_choice() {
        let esp = entry(
            "c12a7328-f81f-11d2-ba4b-00a0c93ec93b",
            "11111111-1111-1111-1111-111111111111",
        );
        let data = entry(LINUX_DATA, "22222222-2222-2222-2222-222222222222");
        let root = entry(ROOT_NATIVE, "33333333-3333-3333-3333-333333333333");
        let es = [(0, esp), (1, data), (3, root)];
        assert_eq!(choose_root(&es, None), RootChoice::Index(2));
        assert_eq!(choose_root(&es[..2], None), RootChoice::Index(1));
        assert_eq!(choose_root(&es[..1], None), RootChoice::None);
        let two = [(0, data), (1, data)];
        assert_eq!(choose_root(&two, None), RootChoice::Ambiguous);
        assert_eq!(choose_root(&es, Some("2")), RootChoice::Index(1));
        assert_eq!(choose_root(&es, Some("4")), RootChoice::Index(2));
        assert_eq!(choose_root(&es, Some("3")), RootChoice::None);
        assert_eq!(
            choose_root(&es, Some("PARTUUID=22222222-2222-2222-2222-222222222222")),
            RootChoice::Index(1)
        );
        assert!(is_esp(&es[0].1));
    }
}
