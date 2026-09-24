//! The disks a boot entry names (INTERFACES.md §3.2, "Disk format is
//! detected, not configured").
//!
//! Two pure decisions, both over bytes the loader has already read and both
//! refusing rather than guessing:
//!
//! - [`detect`]: a file whose last 512 bytes are a valid fixed-VHD footer
//!   ([`crate::vhd`]) is a VHD whose payload is everything before the footer;
//!   anything else is a raw disk whose payload is the whole file.
//! - [`classify`]: where the FAT32 holding the next UEFI image is inside that
//!   payload: the one ESP of a GPT ([`crate::gpt`]), or the whole payload when
//!   it starts with a FAT32 boot sector (a "superfloppy"). Anything else,
//!   including a GPT with zero or several ESPs, is refused.
//!
//! Payloads are addressed in 512-byte sectors (a disk image file has no other
//! sector size). The GPT header must be at LBA 1 and its entry array inside the
//! first [`HEAD_LEN`] bytes — which every partitioning tool's default layout
//! satisfies; anything further out is refused, not chased.

use crate::bytes::Reader;
use crate::gpt::{self, GptError, Header};
use crate::guid::GPT_ESP;
use crate::vhd;

/// The sector size of a disk image payload.
pub const SECTOR: u64 = 512;
/// Bytes of a payload's start [`classify`] can use: LBA 0, the GPT header at
/// LBA 1, and the largest accepted entry array from LBA 2.
pub const HEAD_LEN: usize = 2 * SECTOR as usize + gpt::MAX_ENTRY_ARRAY;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Fixed VHD: payload followed by a 512-byte footer.
    Vhd,
    Raw,
}

/// The virtual disk inside a file: bytes `0..len`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Payload {
    pub format: Format,
    pub len: u64,
}

/// Classify a file of `file_len` bytes by its last 512 bytes (`tail`; any
/// content when the file is shorter than 512 bytes).
pub fn detect(file_len: u64, tail: &[u8; 512]) -> Payload {
    match vhd::fixed_payload_len(tail, file_len) {
        Ok(len) => Payload {
            format: Format::Vhd,
            len,
        },
        Err(_) => Payload {
            format: Format::Raw,
            len: file_len,
        },
    }
}

/// A FAT32 boot sector that passed [`parse_fat32`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fat32 {
    pub bytes_per_sector: u16,
    pub sectors_per_cluster: u8,
    pub reserved_sectors: u16,
    pub fats: u8,
    pub fat_sectors: u32,
    pub total_sectors: u32,
    pub root_cluster: u32,
    /// Data clusters (numbered from 2).
    pub clusters: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fat32Error {
    /// Fewer than 512 bytes.
    Truncated,
    /// Not `EB xx 90` or `E9 xx xx`.
    BadJump,
    /// No `55 AA` at offset 510.
    BadSignature,
    /// Not 512, 1024, 2048 or 4096.
    BytesPerSector,
    /// Not a power of two in 1..=128, or clusters over 64 KiB.
    SectorsPerCluster,
    ReservedSectors,
    /// Not 1 or 2 FATs.
    FatCount,
    /// Not 0xF0 or 0xF8..=0xFF.
    Media,
    /// A FAT12/16 field is non-zero (root entries, 16-bit total or FAT size).
    NotFat32,
    /// `BPB_FSVer` is not 0.0.
    Version,
    /// Extended boot signature (offset 66) is not 0x29.
    ExtendedSignature,
    /// `BS_FilSysType` is not `"FAT32   "`.
    FsType,
    /// Zero, or more sectors than the space it was found in.
    TotalSectors,
    /// Reserved sectors and FATs leave no cluster.
    NoData,
    /// The FATs cannot map every cluster.
    FatSize,
    /// Root directory cluster outside `2..clusters + 2`.
    RootCluster,
}

/// Validate a FAT32 boot sector strictly. `space` is the number of bytes the
/// file system may occupy (the partition or the whole payload).
pub fn parse_fat32(sector: &[u8], space: u64) -> Result<Fat32, Fat32Error> {
    let s = sector.get(..512).ok_or(Fat32Error::Truncated)?;
    let at = |i: usize| s.get(i).copied().unwrap_or(0);
    let jump_ok = (at(0) == 0xEB && at(2) == 0x90) || at(0) == 0xE9;
    if !jump_ok {
        return Err(Fat32Error::BadJump);
    }
    if s.get(510..512) != Some(&[0x55, 0xAA][..]) {
        return Err(Fat32Error::BadSignature);
    }
    let t = |_| Fat32Error::Truncated;
    let mut r = Reader::new(s.get(11..).unwrap_or(&[]));
    let bytes_per_sector = r.u16_le().map_err(t)?;
    let sectors_per_cluster = r.u8().map_err(t)?;
    let reserved_sectors = r.u16_le().map_err(t)?;
    let fats = r.u8().map_err(t)?;
    let root_entries = r.u16_le().map_err(t)?;
    let total16 = r.u16_le().map_err(t)?;
    let media = r.u8().map_err(t)?;
    let fat16_size = r.u16_le().map_err(t)?;
    let _geometry = r.take(8).map_err(t)?; // sectors/track, heads, hidden
    let total_sectors = r.u32_le().map_err(t)?;
    let fat_sectors = r.u32_le().map_err(t)?;
    let _ext_flags = r.u16_le().map_err(t)?;
    let version = r.u16_le().map_err(t)?;
    let root_cluster = r.u32_le().map_err(t)?;

    if !matches!(bytes_per_sector, 512 | 1024 | 2048 | 4096) {
        return Err(Fat32Error::BytesPerSector);
    }
    let cluster_bytes = u32::from(sectors_per_cluster) * u32::from(bytes_per_sector);
    if !sectors_per_cluster.is_power_of_two() || cluster_bytes > 64 * 1024 {
        return Err(Fat32Error::SectorsPerCluster);
    }
    if reserved_sectors == 0 {
        return Err(Fat32Error::ReservedSectors);
    }
    if fats != 1 && fats != 2 {
        return Err(Fat32Error::FatCount);
    }
    if media != 0xF0 && media < 0xF8 {
        return Err(Fat32Error::Media);
    }
    if root_entries != 0 || total16 != 0 || fat16_size != 0 {
        return Err(Fat32Error::NotFat32);
    }
    if version != 0 {
        return Err(Fat32Error::Version);
    }
    if at(66) != 0x29 {
        return Err(Fat32Error::ExtendedSignature);
    }
    if s.get(82..90) != Some(&b"FAT32   "[..]) {
        return Err(Fat32Error::FsType);
    }
    let bytes = u64::from(total_sectors) * u64::from(bytes_per_sector);
    if total_sectors == 0 || bytes > space {
        return Err(Fat32Error::TotalSectors);
    }
    let meta = u64::from(reserved_sectors) + u64::from(fats) * u64::from(fat_sectors);
    let data = u64::from(total_sectors)
        .checked_sub(meta)
        .filter(|d| *d >= u64::from(sectors_per_cluster))
        .ok_or(Fat32Error::NoData)?;
    // `data` < 2^32, so the cluster count fits.
    let clusters = u32::try_from(data / u64::from(sectors_per_cluster)).unwrap_or(u32::MAX);
    let fat_entries = u64::from(fat_sectors) * u64::from(bytes_per_sector) / 4;
    if fat_sectors == 0 || fat_entries < u64::from(clusters) + 2 {
        return Err(Fat32Error::FatSize);
    }
    if root_cluster < 2 || u64::from(root_cluster) >= u64::from(clusters) + 2 {
        return Err(Fat32Error::RootCluster);
    }
    Ok(Fat32 {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        fats,
        fat_sectors,
        total_sectors,
        root_cluster,
        clusters,
    })
}

/// Where the FAT32 holding the UEFI image is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EfiFs {
    /// The single ESP of a GPT, in payload sectors. Its boot sector is not
    /// read here: the caller reads it and checks it with [`parse_fat32`].
    Esp { first_lba: u64, sectors: u64 },
    /// The whole payload is one FAT32.
    Superfloppy(Fat32),
}

impl EfiFs {
    /// The byte range of the file system inside the payload.
    pub fn range(&self) -> (u64, u64) {
        match *self {
            EfiFs::Esp { first_lba, sectors } => (
                first_lba.saturating_mul(SECTOR),
                sectors.saturating_mul(SECTOR),
            ),
            EfiFs::Superfloppy(f) => (
                0,
                u64::from(f.total_sectors) * u64::from(f.bytes_per_sector),
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskError {
    /// The payload (or the head handed over) is shorter than one sector, or
    /// than the two sectors a GPT needs.
    TooSmall,
    /// LBA 1 says `EFI PART` but the GPT is refused.
    Gpt(GptError),
    /// The entry array does not lie within the first [`HEAD_LEN`] bytes.
    EntryArrayOutsideHead,
    NoEsp,
    SeveralEsps,
    /// LBA 0 has a boot-sector jump but is not a valid FAT32 boot sector.
    Fat32(Fat32Error),
    /// Neither a GPT nor a boot sector.
    Unrecognised,
}

/// Classify a payload of `payload_len` bytes by its first bytes (`head`: up to
/// [`HEAD_LEN`] of them; bytes past `payload_len` are ignored).
pub fn classify(payload_len: u64, head: &[u8]) -> Result<EfiFs, DiskError> {
    let usable = usize::try_from(payload_len).unwrap_or(usize::MAX);
    let head = head.get(..head.len().min(usable)).unwrap_or(&[]);
    let blocks = payload_len / SECTOR;
    let lba0 = head.get(..512).ok_or(DiskError::TooSmall)?;
    let lba1 = head.get(512..1024);
    if let Some(block) = lba1.filter(|b| b.get(..8) == Some(&gpt::SIGNATURE[..])) {
        let hdr = Header::parse(block, blocks).map_err(DiskError::Gpt)?;
        let start = usize::try_from(hdr.entries_lba)
            .ok()
            .and_then(|l| l.checked_mul(512))
            .ok_or(DiskError::EntryArrayOutsideHead)?;
        let array = start
            .checked_add(hdr.entries_len())
            .and_then(|end| head.get(start..end))
            .ok_or(DiskError::EntryArrayOutsideHead)?;
        let entries = hdr.entries(array).map_err(DiskError::Gpt)?;
        let mut esp = None;
        for i in 0..entries.count() {
            let e = entries.get(i).map_err(DiskError::Gpt)?;
            if e.is_unused() || e.type_guid != GPT_ESP {
                continue;
            }
            if esp.is_some() {
                return Err(DiskError::SeveralEsps);
            }
            esp = Some(EfiFs::Esp {
                first_lba: e.first_lba,
                sectors: e.sectors(),
            });
        }
        return esp.ok_or(DiskError::NoEsp);
    }
    match parse_fat32(lba0, payload_len) {
        Ok(f) => Ok(EfiFs::Superfloppy(f)),
        Err(Fat32Error::BadJump) => Err(DiskError::Unrecognised),
        Err(e) => Err(DiskError::Fat32(e)),
    }
}

/// Test and tooling support: a valid FAT32 boot sector for `total_sectors`
/// 512-byte sectors, 8 sectors per cluster, 32 reserved sectors, 2 FATs.
pub mod build {
    pub fn fat32_boot_sector(total_sectors: u32) -> [u8; 512] {
        let mut s = [0u8; 512];
        let spc = 8u32;
        let reserved = 32u32;
        // FAT size: enough 4-byte entries for every cluster plus two.
        let mut fat = 1u32;
        loop {
            let data = total_sectors.saturating_sub(reserved + 2 * fat);
            let need = (data / spc + 2) * 4;
            if fat * 512 >= need {
                break;
            }
            fat += 1;
        }
        let mut put = |at: usize, b: &[u8]| {
            if let Some(d) = s.get_mut(at..at + b.len()) {
                d.copy_from_slice(b);
            }
        };
        put(0, &[0xEB, 0x58, 0x90]);
        put(3, b"mkfs.fat");
        put(11, &512u16.to_le_bytes());
        put(13, &[spc as u8]);
        put(14, &(reserved as u16).to_le_bytes());
        put(16, &[2]);
        put(21, &[0xF8]);
        put(32, &total_sectors.to_le_bytes());
        put(36, &fat.to_le_bytes());
        put(44, &2u32.to_le_bytes());
        put(48, &1u16.to_le_bytes());
        put(50, &6u16.to_le_bytes());
        put(66, &[0x29]);
        put(71, b"NO NAME    ");
        put(82, b"FAT32   ");
        put(510, &[0x55, 0xAA]);
        s
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::gpt::Entry;
    use crate::guid::{GPT_BASIC_DATA, Guid};
    use std::vec::Vec;

    fn footer(size: u64) -> [u8; 512] {
        let mut f = [0u8; 512];
        f[0..8].copy_from_slice(b"conectix");
        f[40..48].copy_from_slice(&size.to_be_bytes());
        f[48..56].copy_from_slice(&size.to_be_bytes());
        f[60..64].copy_from_slice(&2u32.to_be_bytes());
        let sum = f.iter().fold(0u32, |a, b| a.wrapping_add(u32::from(*b)));
        f[64..68].copy_from_slice(&(!sum).to_be_bytes());
        f
    }

    #[test]
    fn detect_vhd_and_raw() {
        let f = footer(1 << 20);
        assert_eq!(
            detect((1 << 20) + 512, &f),
            Payload {
                format: Format::Vhd,
                len: 1 << 20
            }
        );
        // Wrong size, bad checksum, dynamic, short file, no footer: raw.
        for (len, tail) in [
            ((1 << 20) + 1024, f),
            (1 << 20, [0u8; 512]),
            (100, f),
            (0, [0u8; 512]),
        ] {
            assert_eq!(
                detect(len, &tail),
                Payload {
                    format: Format::Raw,
                    len
                },
                "{len}"
            );
        }
        let mut bad = f;
        bad[100] ^= 1;
        assert_eq!(detect((1 << 20) + 512, &bad).format, Format::Raw);
        let mut dynamic = footer(1 << 20);
        dynamic[63] = 3;
        assert_eq!(detect((1 << 20) + 512, &dynamic).format, Format::Raw);
    }

    const TOTAL: u32 = 140_000;

    #[test]
    fn superfloppy() {
        let mut head = [0u8; 1024];
        head[..512].copy_from_slice(&build::fat32_boot_sector(TOTAL));
        let len = u64::from(TOTAL) * 512;
        let got = classify(len, &head).unwrap();
        let EfiFs::Superfloppy(f) = got else {
            panic!("{got:?}")
        };
        assert_eq!(
            (
                f.bytes_per_sector,
                f.sectors_per_cluster,
                f.fats,
                f.root_cluster
            ),
            (512, 8, 2, 2)
        );
        assert_eq!(got.range(), (0, len));
        // One sector suffices.
        assert_eq!(classify(len, &head[..512]), Ok(got));
        // Too small for the file system it claims.
        assert_eq!(
            classify(len - 512, &head),
            Err(DiskError::Fat32(Fat32Error::TotalSectors))
        );
        assert_eq!(classify(511, &head), Err(DiskError::TooSmall));
        assert_eq!(classify(len, &head[..100]), Err(DiskError::TooSmall));
        assert_eq!(classify(len, &[0u8; 1024]), Err(DiskError::Unrecognised));
    }

    #[test]
    fn fat32_rules() {
        use Fat32Error::*;
        let good = build::fat32_boot_sector(TOTAL);
        let space = u64::from(TOTAL) * 512;
        assert!(parse_fat32(&good, space).is_ok());
        let mut e9 = good;
        e9[0] = 0xE9;
        e9[2] = 0;
        assert!(parse_fat32(&e9, space).is_ok(), "E9 near jump");
        let mut spc1 = good;
        spc1[13] = 1;
        spc1[36..40].copy_from_slice(&1200u32.to_le_bytes());
        assert!(parse_fat32(&spc1, space).is_ok());

        let set = |at: usize, b: &[u8]| {
            let mut s = good;
            s[at..at + b.len()].copy_from_slice(b);
            s
        };
        let cases: &[([u8; 512], Fat32Error)] = &[
            (set(0, &[0x00]), BadJump),
            (set(2, &[0x00]), BadJump),
            (set(510, &[0x55, 0xAB]), BadSignature),
            (set(11, &256u16.to_le_bytes()), BytesPerSector),
            (set(11, &513u16.to_le_bytes()), BytesPerSector),
            (set(13, &[0]), SectorsPerCluster),
            (set(13, &[3]), SectorsPerCluster),
            (set(13, &[6]), SectorsPerCluster),
            (
                {
                    let mut s = set(13, &[128]);
                    s[11..13].copy_from_slice(&1024u16.to_le_bytes());
                    s
                },
                SectorsPerCluster,
            ),
            (set(14, &[0, 0]), ReservedSectors),
            (set(16, &[0]), FatCount),
            (set(16, &[3]), FatCount),
            (set(21, &[0xF7]), Media),
            (set(17, &[1, 0]), NotFat32),
            (set(19, &[1, 0]), NotFat32),
            (set(22, &[1, 0]), NotFat32),
            (set(42, &[0, 1]), Version),
            (set(66, &[0x28]), ExtendedSignature),
            (set(82, b"FAT16   "), FsType),
            (set(32, &[0, 0, 0, 0]), TotalSectors),
            (set(32, &(TOTAL + 1).to_le_bytes()), TotalSectors),
            (set(36, &0x0100_0000u32.to_le_bytes()), NoData),
            (set(36, &0u32.to_le_bytes()), FatSize),
            (set(36, &10u32.to_le_bytes()), FatSize),
            (set(44, &1u32.to_le_bytes()), RootCluster),
            (set(44, &100_000u32.to_le_bytes()), RootCluster),
        ];
        for (s, want) in cases {
            assert_eq!(parse_fat32(s, space), Err(*want), "{want:?}");
        }
        assert_eq!(parse_fat32(&good[..511], space), Err(Truncated));
    }

    /// A GPT disk image head for `parts` (type, first, last) of `blocks` sectors.
    fn gpt_head(blocks: u64, parts: &[(Guid, u64, u64)]) -> Vec<u8> {
        let entries: Vec<Entry> = parts
            .iter()
            .enumerate()
            .map(|(i, (t, f, l))| Entry {
                type_guid: *t,
                unique_guid: Guid([i as u8 + 1; 16]),
                first_lba: *f,
                last_lba: *l,
                attributes: 0,
                name: [0; 36],
            })
            .collect();
        let mut h = [0u8; 512];
        let mut a = [0u8; gpt::MAX_ENTRY_ARRAY];
        gpt::build::write(
            &Guid([0xd1; 16]),
            blocks,
            512,
            &entries,
            128,
            &mut h,
            &mut a,
        )
        .unwrap();
        let mut head = std::vec![0u8; HEAD_LEN];
        head[510] = 0x55;
        head[511] = 0xAA;
        head[512..1024].copy_from_slice(&h);
        head[1024..].copy_from_slice(&a);
        head
    }

    #[test]
    fn gpt_with_one_esp() {
        let blocks = 1 << 16;
        let len = blocks * 512;
        let head = gpt_head(
            blocks,
            &[(GPT_BASIC_DATA, 2048, 4095), (GPT_ESP, 4096, 8191)],
        );
        let got = classify(len, &head).unwrap();
        assert_eq!(
            got,
            EfiFs::Esp {
                first_lba: 4096,
                sectors: 4096
            }
        );
        assert_eq!(got.range(), (4096 * 512, 4096 * 512));
        // A VHD's payload is classified the same way.
        let file_len = len + 512;
        let p = detect(file_len, &footer(len));
        assert_eq!(classify(p.len, &head), Ok(got));
    }

    #[test]
    fn gpt_refusals() {
        let blocks = 1 << 16;
        let len = blocks * 512;
        assert_eq!(
            classify(len, &gpt_head(blocks, &[(GPT_BASIC_DATA, 2048, 4095)])),
            Err(DiskError::NoEsp)
        );
        assert_eq!(
            classify(
                len,
                &gpt_head(blocks, &[(GPT_ESP, 2048, 4095), (GPT_ESP, 4096, 8191)])
            ),
            Err(DiskError::SeveralEsps)
        );
        let head = gpt_head(blocks, &[(GPT_ESP, 2048, 4095)]);
        // The disk is smaller than the GPT says.
        assert_eq!(
            classify(1024 * 512, &head),
            Err(DiskError::Gpt(GptError::BadUsableRange))
        );
        // Corrupt header: refused as a GPT, never re-read as FAT32.
        let mut bad = head.clone();
        bad[512 + 40] ^= 1;
        assert_eq!(
            classify(len, &bad),
            Err(DiskError::Gpt(GptError::HeaderCrc))
        );
        let mut bad = head.clone();
        bad[1024] ^= 1;
        assert_eq!(
            classify(len, &bad),
            Err(DiskError::Gpt(GptError::EntryArrayCrc))
        );
        // Entry array beyond the head handed over.
        assert_eq!(
            classify(len, &head[..HEAD_LEN - 1]),
            Err(DiskError::EntryArrayOutsideHead)
        );
        // Only LBA 0 available: not a GPT, and a protective MBR is no FAT32.
        assert_eq!(classify(len, &head[..512]), Err(DiskError::Unrecognised));
    }
}
