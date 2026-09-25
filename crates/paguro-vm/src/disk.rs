//! The guest's disk (DESIGN.md §4.3 "View B is a synthesised disk"):
//!
//! ```text
//! /dev/mapper/paguro-vmdisk = dm-linear concat of
//!    [ protective MBR + primary GPT, to 1 MiB   scratch ]
//!    [ ESP     the synthetic FAT32: bootmgfw.efi, a BCD with testsigning ]
//!    [ MSR     16 MiB of scratch zeros, for fidelity ]
//!    [ C:      view B (ciphertext, the images' extents EIO), except every
//!              sector BitLocker owns: those come from the session's FVE
//!              buffer, which absorbs the guest's writes (§6) ]
//!    [ backup GPT                               scratch ]
//! ```
//!
//! Everything but view B lives in one per-session **scratch** file (one
//! loop device): the two GPT halves, the ESP image, the MSR and the FVE
//! buffer at fixed offsets. The table is built here, as text, from the real
//! disk's identities — disk GUID, and the ESP's, MSR's and C:'s type and
//! unique GUIDs, attributes and names are carried over (the BCD resolves
//! partitions by GUID, and Windows records disk identity). Every other
//! partition, WinRE included, is absent.
//!
//! The table is untrusted by construction: a guest rewriting this GPT
//! writes to scratch; enforcement is view B's range test beneath it.

use paguro_core::gpt::{
    self, BLOCK_SIZE_4K, BLOCK_SIZE_512, DEFAULT_ENTRY_SIZE, ENTRY_NAME_UNITS, Entry,
    HEADER_CRC_END, HEADER_CRC_OFFSET, HEADER_MIN,
};
use paguro_core::guid::Guid;
use paguro_initrd::plan::Target;

/// Device-mapper's sector.
pub const SECTOR: u64 = 512;
/// Partition alignment, and the space before the first partition.
pub const ALIGN: u64 = 1 << 20;
/// The MSR Windows creates on GPT disks.
pub const MSR_BYTES: u64 = 16 << 20;
/// Entries in the partition array (16 KiB, as every tool writes).
pub const ENTRIES: u32 = 128;
const ARRAY_BYTES: u64 = ENTRIES as u64 * DEFAULT_ENTRY_SIZE as u64;

// Protective MBR (UEFI 2.10 §5.2.3).
const MBR_ENTRY: usize = 446;
const MBR_TYPE_GPT: u8 = 0xEE;
const MBR_SIGNATURE: [u8; 2] = [0x55, 0xAA];
const MBR_MAX_SECTORS: u64 = 0xFFFF_FFFF;
// GPT header fields patched for the backup copy.
const H_MY_LBA: usize = 24;
const H_ALTERNATE_LBA: usize = 32;
const H_ENTRIES_LBA: usize = 72;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part {
    pub type_guid: Guid,
    pub unique_guid: Guid,
    pub attributes: u64,
    pub name: [u16; ENTRY_NAME_UNITS],
}

impl Part {
    pub fn from_entry(e: &Entry) -> Part {
        Part {
            type_guid: e.type_guid,
            unique_guid: e.unique_guid,
            attributes: e.attributes,
            name: e.name,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spec {
    /// The guest's logical block: the real disk's (512 or 4096).
    pub block_size: u32,
    pub disk_guid: Guid,
    pub esp: Part,
    pub esp_bytes: u64,
    /// The real disk's MSR, if it has one.
    pub msr: Option<Part>,
    pub volume: Part,
    pub volume_bytes: u64,
    /// BitLocker-owned ranges of the volume, 512-byte sectors
    /// (`fve::owned_ranges`); empty for an unencrypted C:.
    pub owned: Vec<(u64, u64)>,
}

/// Byte offsets in the scratch file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scratch {
    pub head: u64,
    pub esp: u64,
    pub msr: u64,
    pub fve: u64,
    pub tail: u64,
    pub len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan {
    pub block_size: u32,
    pub disk_bytes: u64,
    /// Byte offsets on the guest's disk.
    pub esp_at: u64,
    pub msr_at: Option<u64>,
    pub volume_at: u64,
    pub volume_bytes: u64,
    pub esp_bytes: u64,
    pub scratch: Scratch,
    /// The first 1 MiB (protective MBR, primary header, array) and the
    /// last blocks (array, backup header).
    pub head: Vec<u8>,
    pub tail: Vec<u8>,
    /// `(volume sector, sectors, FVE-buffer sector)` per owned range.
    pub owned: Vec<(u64, u64, u64)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskError {
    BlockSize,
    /// A size not a whole number of blocks, or an ESP not whole MiB.
    Unaligned,
    /// Owned ranges outside the volume, unsorted or overlapping.
    Owned,
    TooLarge,
}

impl core::fmt::Display for DiskError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = match self {
            DiskError::BlockSize => "block size must be 512 or 4096",
            DiskError::Unaligned => "sizes must be whole blocks (the ESP whole MiB)",
            DiskError::Owned => "BitLocker ranges outside the volume or overlapping",
            DiskError::TooLarge => "disk too large",
        };
        f.write_str(s)
    }
}

fn put(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

pub fn plan(s: &Spec) -> Result<Plan, DiskError> {
    let bs = u64::from(s.block_size);
    if s.block_size != BLOCK_SIZE_512 && s.block_size != BLOCK_SIZE_4K {
        return Err(DiskError::BlockSize);
    }
    if s.esp_bytes == 0
        || s.esp_bytes % ALIGN != 0
        || s.volume_bytes == 0
        || s.volume_bytes % bs != 0
    {
        return Err(DiskError::Unaligned);
    }
    let vol_sectors = s.volume_bytes / SECTOR;
    let mut prev_end = 0u64;
    for &(start, len) in &s.owned {
        if len == 0 || start < prev_end || start.checked_add(len).is_none_or(|e| e > vol_sectors) {
            return Err(DiskError::Owned);
        }
        prev_end = start + len;
    }
    let array_blocks = ARRAY_BYTES.div_ceil(bs);
    let tail_bytes = (array_blocks + 1) * bs;
    let esp_at = ALIGN;
    let msr_at = s.msr.map(|_| esp_at + s.esp_bytes);
    let volume_at = esp_at + s.esp_bytes + msr_at.map_or(0, |_| MSR_BYTES);
    let disk_bytes = volume_at
        .checked_add(s.volume_bytes)
        .and_then(|v| v.checked_add(tail_bytes))
        .ok_or(DiskError::TooLarge)?;
    let blocks = disk_bytes / bs;
    let last = blocks - 1;

    // Partition entries: ESP, MSR, C:.
    let lba = |at: u64| at / bs;
    let mut entries = vec![Entry {
        type_guid: s.esp.type_guid,
        unique_guid: s.esp.unique_guid,
        first_lba: lba(esp_at),
        last_lba: lba(esp_at + s.esp_bytes) - 1,
        attributes: s.esp.attributes,
        name: s.esp.name,
    }];
    if let (Some(m), Some(at)) = (s.msr, msr_at) {
        entries.push(Entry {
            type_guid: m.type_guid,
            unique_guid: m.unique_guid,
            first_lba: lba(at),
            last_lba: lba(at + MSR_BYTES) - 1,
            attributes: m.attributes,
            name: m.name,
        });
    }
    entries.push(Entry {
        type_guid: s.volume.type_guid,
        unique_guid: s.volume.unique_guid,
        first_lba: lba(volume_at),
        last_lba: lba(volume_at + s.volume_bytes) - 1,
        attributes: s.volume.attributes,
        name: s.volume.name,
    });
    let mut header = vec![0u8; s.block_size as usize];
    let mut array = vec![0u8; ARRAY_BYTES as usize];
    gpt::build::write(
        &s.disk_guid,
        blocks,
        s.block_size,
        &entries,
        ENTRIES,
        &mut header,
        &mut array,
    )
    .map_err(|_| DiskError::TooLarge)?;

    let mut head = vec![0u8; ALIGN as usize];
    // Protective MBR: one 0xEE partition from LBA 1 over the disk.
    let mut pe = [0u8; 16];
    put(&mut pe, 1, &[0x00, 0x02, 0x00]);
    pe[4] = MBR_TYPE_GPT;
    put(&mut pe, 5, &[0xFF, 0xFF, 0xFF]);
    put(&mut pe, 8, &1u32.to_le_bytes());
    put(
        &mut pe,
        12,
        &(((blocks - 1).min(MBR_MAX_SECTORS)) as u32).to_le_bytes(),
    );
    put(&mut head, MBR_ENTRY, &pe);
    put(&mut head, 510, &MBR_SIGNATURE);
    put(&mut head, bs as usize, &header);
    put(&mut head, 2 * bs as usize, &array);

    // Backup: the array, then the header at the last LBA pointing back.
    let mut backup = header.clone();
    put(&mut backup, H_MY_LBA, &last.to_le_bytes());
    put(&mut backup, H_ALTERNATE_LBA, &1u64.to_le_bytes());
    put(
        &mut backup,
        H_ENTRIES_LBA,
        &(last - array_blocks).to_le_bytes(),
    );
    put(
        &mut backup,
        HEADER_CRC_OFFSET,
        &[0; HEADER_CRC_END - HEADER_CRC_OFFSET],
    );
    let crc = gpt::crc32(backup.get(..HEADER_MIN as usize).unwrap_or(&[]));
    put(&mut backup, HEADER_CRC_OFFSET, &crc.to_le_bytes());
    let mut tail = vec![0u8; tail_bytes as usize];
    put(&mut tail, 0, &array);
    put(&mut tail, (array_blocks * bs) as usize, &backup);

    // Scratch: head | ESP | MSR | FVE buffer | tail, each 1 MiB aligned.
    let fve_sectors: u64 = s.owned.iter().map(|&(_, l)| l).sum();
    let up = |x: u64| x.div_ceil(ALIGN) * ALIGN;
    let sc_esp = ALIGN;
    let sc_msr = sc_esp + s.esp_bytes;
    let sc_fve = sc_msr + msr_at.map_or(0, |_| MSR_BYTES);
    let sc_tail = sc_fve + up(fve_sectors * SECTOR);
    let scratch = Scratch {
        head: 0,
        esp: sc_esp,
        msr: sc_msr,
        fve: sc_fve,
        tail: sc_tail,
        len: sc_tail + up(tail_bytes),
    };
    let mut at = 0;
    let owned = s
        .owned
        .iter()
        .map(|&(st, l)| {
            let r = (st, l, at);
            at += l;
            r
        })
        .collect();
    Ok(Plan {
        block_size: s.block_size,
        disk_bytes,
        esp_at,
        msr_at,
        volume_at,
        volume_bytes: s.volume_bytes,
        esp_bytes: s.esp_bytes,
        scratch,
        head,
        tail,
        owned,
    })
}

fn linear(start: u64, len: u64, dev: &str, off: u64) -> Target {
    Target {
        start,
        len,
        kind: "linear",
        params: format!("{dev} {off}"),
    }
}

/// The `paguro-vmdisk` table: `scratch` is the scratch file's loop device,
/// `view_b` the module's view B of the volume (both `major:minor` or a
/// path).
pub fn table(p: &Plan, scratch: &str, view_b: &str) -> Vec<Target> {
    let sc = |b: u64| b / SECTOR;
    let mut t = vec![
        linear(0, sc(ALIGN), scratch, sc(p.scratch.head)),
        linear(sc(p.esp_at), sc(p.esp_bytes), scratch, sc(p.scratch.esp)),
    ];
    if let Some(m) = p.msr_at {
        t.push(linear(sc(m), sc(MSR_BYTES), scratch, sc(p.scratch.msr)));
    }
    let v0 = sc(p.volume_at);
    let mut at = 0u64;
    for &(start, len, buf) in &p.owned {
        if start > at {
            t.push(linear(v0 + at, start - at, view_b, at));
        }
        t.push(linear(v0 + start, len, scratch, sc(p.scratch.fve) + buf));
        at = start + len;
    }
    let vol = sc(p.volume_bytes);
    if vol > at {
        t.push(linear(v0 + at, vol - at, view_b, at));
    }
    let tail_at = sc(p.volume_at + p.volume_bytes);
    t.push(linear(
        tail_at,
        sc(p.disk_bytes) - tail_at,
        scratch,
        sc(p.scratch.tail),
    ));
    t
}

/// The table as `dmsetup` text (logs, tests).
pub fn table_text(t: &[Target]) -> String {
    t.iter()
        .map(|x| format!("{} {} {} {}\n", x.start, x.len, x.kind, x.params))
        .collect()
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use paguro_core::gpt::Header;
    use paguro_core::guid::{GPT_BASIC_DATA, GPT_ESP};

    fn part(t: Guid, id: u8) -> Part {
        let mut name = [0u16; ENTRY_NAME_UNITS];
        name[0] = u16::from(b'P');
        Part {
            type_guid: t,
            unique_guid: Guid([id; 16]),
            attributes: u64::from(id),
            name,
        }
    }

    fn spec(bs: u32, msr: bool) -> Spec {
        Spec {
            block_size: bs,
            disk_guid: Guid([0x77; 16]),
            esp: part(GPT_ESP, 1),
            esp_bytes: 100 << 20,
            msr: msr.then(|| {
                part(
                    Guid::parse("e3c9e316-0b5c-4db8-817d-f92df00215ae").unwrap(),
                    2,
                )
            }),
            volume: part(GPT_BASIC_DATA, 3),
            volume_bytes: 22_548_578_304,
            owned: vec![
                (0, 16),
                (0x11800, 128),
                (0x11880, 16),
                (0x212f10, 128),
                (0x413d60, 128),
            ],
        }
    }

    #[test]
    fn gpt_is_valid_and_preserves_identity() {
        for bs in [512u32, 4096] {
            for msr in [true, false] {
                let s = spec(bs, msr);
                let p = plan(&s).unwrap();
                let b = bs as usize;
                let blocks = p.disk_bytes / u64::from(bs);
                assert_eq!(&p.head[510..512], &MBR_SIGNATURE);
                assert_eq!(p.head[MBR_ENTRY + 4], MBR_TYPE_GPT);
                let h = Header::parse(&p.head[b..2 * b], blocks).unwrap();
                assert_eq!(h.disk_guid, s.disk_guid);
                assert_eq!(h.alternate_lba, blocks - 1);
                let arr = &p.head[2 * b..2 * b + ARRAY_BYTES as usize];
                assert_eq!(gpt::crc32(arr), h.entries_crc);
                let e0 = h.entries(arr).unwrap().get(0).unwrap();
                assert_eq!(e0.unique_guid, s.esp.unique_guid);
                assert_eq!(e0.first_lba * u64::from(bs), ALIGN);
                let c = h
                    .entries(arr)
                    .unwrap()
                    .get(if msr { 2 } else { 1 })
                    .unwrap();
                assert_eq!(
                    (c.type_guid, c.unique_guid, c.attributes),
                    (s.volume.type_guid, s.volume.unique_guid, 3)
                );
                assert_eq!(c.first_lba * u64::from(bs), p.volume_at);
                assert_eq!(c.sectors() * u64::from(bs), s.volume_bytes);
                assert!(c.last_lba <= h.last_usable);
                // backup: same array, header at the last LBA, CRC valid
                let tail_arr = &p.tail[..ARRAY_BYTES as usize];
                assert_eq!(tail_arr, arr);
                let bh = &p.tail[p.tail.len() - b..];
                assert_eq!(&bh[..8], b"EFI PART");
                assert_eq!(
                    u64::from_le_bytes(bh[24..32].try_into().unwrap()),
                    blocks - 1
                );
                assert_eq!(u64::from_le_bytes(bh[32..40].try_into().unwrap()), 1);
                let entries_lba = u64::from_le_bytes(bh[72..80].try_into().unwrap());
                assert_eq!(
                    entries_lba * u64::from(bs),
                    p.disk_bytes - p.tail.len() as u64
                );
                let mut z = bh[..92].to_vec();
                let crc = u32::from_le_bytes(z[16..20].try_into().unwrap());
                z[16..20].fill(0);
                assert_eq!(gpt::crc32(&z), crc);
            }
        }
    }

    #[test]
    fn table_is_contiguous_and_routes_owned_sectors() {
        let s = spec(512, true);
        let p = plan(&s).unwrap();
        let t = table(&p, "7:0", "254:3");
        let mut at = 0;
        for x in &t {
            assert_eq!(x.start, at, "{}", table_text(&t));
            assert!(x.len > 0);
            at += x.len;
        }
        assert_eq!(at * SECTOR, p.disk_bytes);
        // every volume sector: owned ones from the buffer, others from B
        let v0 = p.volume_at / SECTOR;
        let find = |sec: u64| {
            t.iter()
                .find(|x| sec >= x.start && sec < x.start + x.len)
                .unwrap()
        };
        let mut buf = 0;
        for &(st, l) in &s.owned {
            for k in [0, l - 1] {
                let x = find(v0 + st + k);
                let off: u64 = x.params.split(' ').nth(1).unwrap().parse().unwrap();
                assert!(x.params.starts_with("7:0 "));
                assert_eq!(
                    off + (v0 + st + k - x.start),
                    p.scratch.fve / SECTOR + buf + k
                );
            }
            buf += l;
            // just past it: view B at the same volume offset
            let x = find(v0 + st + l);
            if x.params.starts_with("254:3") {
                let off: u64 = x.params.split(' ').nth(1).unwrap().parse().unwrap();
                assert_eq!(off + (v0 + st + l - x.start), st + l);
            }
        }
        // the scratch areas do not overlap
        let sc = p.scratch;
        assert!(sc.esp >= ALIGN && sc.msr >= sc.esp + s.esp_bytes);
        assert!(sc.fve >= sc.msr + MSR_BYTES);
        assert!(sc.tail >= sc.fve + buf * SECTOR && sc.len >= sc.tail + p.tail.len() as u64);
    }

    #[test]
    fn unencrypted_volume_is_one_segment() {
        let mut s = spec(512, false);
        s.owned.clear();
        let t = table(&plan(&s).unwrap(), "7:0", "254:3");
        assert_eq!(
            t.iter().filter(|x| x.params.starts_with("254:3")).count(),
            1
        );
    }

    proptest::proptest! {
        /// Any valid owned set, any sizes: the table tiles the disk, every
        /// volume sector goes to view B at its own offset unless owned,
        /// and every owned sector to its own place in the FVE buffer.
        #[test]
        fn table_routes_every_sector(
            gaps in proptest::collection::vec((1u64..5000, 1u64..300), 0..7),
            tail in 1u64..5000,
            esp_mib in 1u64..300,
            msr in proptest::bool::ANY,
        ) {
            let mut owned = Vec::new();
            let mut at = 0;
            for (gap, len) in &gaps {
                owned.push((at + gap - 1, *len));
                at += gap - 1 + len;
            }
            let mut s = spec(512, msr);
            s.owned = owned.clone();
            s.esp_bytes = esp_mib << 20;
            s.volume_bytes = (at + tail) * SECTOR;
            let p = plan(&s).unwrap();
            let t = table(&p, "7:0", "254:3");
            let mut pos = 0;
            for x in &t {
                proptest::prop_assert_eq!(x.start, pos);
                pos += x.len;
            }
            proptest::prop_assert_eq!(pos * SECTOR, p.disk_bytes);
            let v0 = p.volume_at / SECTOR;
            let vol = s.volume_bytes / SECTOR;
            let map = |sec: u64| -> (String, u64) {
                let x = t.iter().find(|x| sec >= x.start && sec < x.start + x.len).unwrap();
                let mut it = x.params.split(' ');
                let dev = it.next().unwrap().to_string();
                let off: u64 = it.next().unwrap().parse().unwrap();
                (dev, off + sec - x.start)
            };
            // Sample the boundaries of every owned range and the gaps.
            let mut buf = 0;
            let mut probes = vec![0, vol - 1];
            for &(st, l) in &owned {
                probes.extend([st.saturating_sub(1), st, st + l - 1, st + l]);
            }
            for &q in &probes {
                if q >= vol {
                    continue;
                }
                let (dev, off) = map(v0 + q);
                match owned.iter().position(|&(st, l)| q >= st && q < st + l) {
                    Some(i) => {
                        let before: u64 = owned.iter().take(i).map(|x| x.1).sum();
                        proptest::prop_assert_eq!(dev, "7:0");
                        proptest::prop_assert_eq!(off, p.scratch.fve / SECTOR + before + (q - owned[i].0));
                    }
                    None => {
                        proptest::prop_assert_eq!(dev, "254:3");
                        proptest::prop_assert_eq!(off, q);
                    }
                }
            }
            buf += owned.iter().map(|x| x.1).sum::<u64>();
            proptest::prop_assert!(p.scratch.tail >= p.scratch.fve + buf * SECTOR);
        }
    }

    #[test]
    fn refusals() {
        let mut s = spec(512, true);
        s.block_size = 1024;
        assert_eq!(plan(&s), Err(DiskError::BlockSize));
        let mut s = spec(512, true);
        s.esp_bytes += 512;
        assert_eq!(plan(&s), Err(DiskError::Unaligned));
        let mut s = spec(4096, true);
        s.volume_bytes += 512;
        assert_eq!(plan(&s), Err(DiskError::Unaligned));
        for owned in [
            vec![(10, 5), (12, 5)],
            vec![(10, 0)],
            vec![(20, 1), (10, 1)],
            vec![(u64::MAX, 2)],
        ] {
            let mut s = spec(512, true);
            s.owned = owned;
            assert_eq!(plan(&s), Err(DiskError::Owned));
        }
    }
}
