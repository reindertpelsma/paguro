//! Finding the volume, and the BitLocker/NTFS operations stages 3 and 4 need.
//!
//! Partition discovery (GPT walk, BitLocker/NTFS signature probe) is
//! implemented here over [`Platform::read_blocks`]. The FVE-metadata side of
//! stage 3 (FVEK blob, clear key, recovery-password and FVEK unwrap) and all of
//! stage 4 (NTFS, the entry's disks, the UEFI image) sit behind [`Volume`], whose
//! production implementation is [`Unimplemented`] until `paguro-core::ntfs`
//! and the FVE parser land. The mock boot tests supply a fake.

use paguro_core::config::Entry;
use paguro_core::fve;
use paguro_core::gpt::{self, Header};
use paguro_core::guid::{GPT_BASIC_DATA, Guid};
use paguro_core::handoff::FveLayout;

use crate::BootError;
use crate::platform::Platform;

pub type Key = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Partition {
    pub disk: usize,
    pub guid: Guid,
    pub first_lba: u64,
    pub sectors: u64,
    pub block_size: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeKind {
    /// `-FVE-FS-` at offset 3 of the first sector.
    BitLocker,
    /// `NTFS    ` at offset 3.
    Ntfs,
    Other,
}

/// Classify a partition by its first sector.
pub fn probe<P: Platform>(
    p: &mut P,
    part: &Partition,
    block: &mut [u8],
) -> Result<VolumeKind, BootError> {
    let bs = part.block_size as usize;
    let buf = block.get_mut(..bs).ok_or(BootError::Disk)?;
    p.read_blocks(part.disk, part.first_lba, buf)
        .map_err(BootError::Platform)?;
    let oem = buf.get(3..11).unwrap_or(&[]);
    Ok(if fve::check_signature(oem).is_ok() {
        VolumeKind::BitLocker
    } else if oem == b"NTFS    " {
        VolumeKind::Ntfs
    } else {
        VolumeKind::Other
    })
}

/// Scratch for GPT walks: one block and the largest accepted entry array.
pub struct GptScratch {
    pub block: [u8; 4096],
    pub array: [u8; gpt::MAX_ENTRY_ARRAY],
}

impl GptScratch {
    pub const fn new() -> Self {
        GptScratch {
            block: [0; 4096],
            array: [0; gpt::MAX_ENTRY_ARRAY],
        }
    }
}

impl Default for GptScratch {
    fn default() -> Self {
        Self::new()
    }
}

/// Visit every used partition on every disk with a valid primary GPT. Disks
/// without one (or with a damaged one) are skipped, never repaired.
pub fn for_each_partition<P: Platform>(
    p: &mut P,
    s: &mut GptScratch,
    mut visit: impl FnMut(&mut P, &gpt::Entry, Partition) -> Result<bool, BootError>,
) -> Result<(), BootError> {
    for disk in 0..p.disk_count() {
        let Some(info) = p.disk_info(disk) else {
            continue;
        };
        let bs = info.block_size as usize;
        if bs != 512 && bs != 4096 {
            continue;
        }
        let Some(blk) = s.block.get_mut(..bs) else {
            continue;
        };
        if p.read_blocks(disk, 1, blk).is_err() {
            continue;
        }
        let Ok(hdr) = Header::parse(blk, info.blocks) else {
            p.log(format_args!("paguro: disk {disk}: no valid GPT"));
            continue;
        };
        let bytes = (hdr.entries_blocks() as usize) * bs;
        let Some(arr) = s.array.get_mut(..bytes) else {
            continue;
        };
        if p.read_blocks(disk, hdr.entries_lba, arr).is_err() {
            continue;
        }
        let Ok(entries) = hdr.entries(arr.get(..hdr.entries_len()).unwrap_or(&[])) else {
            p.log(format_args!("paguro: disk {disk}: GPT entry array refused"));
            continue;
        };
        for i in 0..entries.count() {
            let Ok(e) = entries.get(i) else {
                p.log(format_args!("paguro: disk {disk}: GPT entry {i} refused"));
                break;
            };
            if e.is_unused() {
                continue;
            }
            let part = Partition {
                disk,
                guid: e.unique_guid,
                first_lba: e.first_lba,
                sectors: e.sectors(),
                block_size: info.block_size,
            };
            if !visit(p, &e, part)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

/// The partition with unique GUID `id`, on any disk.
pub fn find_partition<P: Platform>(
    p: &mut P,
    s: &mut GptScratch,
    id: &Guid,
) -> Result<Option<Partition>, BootError> {
    let mut found = None;
    for_each_partition(p, s, |_, _, part| {
        if part.guid == *id {
            found = Some(part);
            return Ok(false);
        }
        Ok(true)
    })?;
    Ok(found)
}

pub const MAX_CANDIDATES: usize = 8;

/// Recovery enumeration: basic-data partitions that carry BitLocker or NTFS.
pub fn enumerate_candidates<P: Platform>(
    p: &mut P,
    s: &mut GptScratch,
    out: &mut [Option<(Partition, VolumeKind)>; MAX_CANDIDATES],
) -> Result<usize, BootError> {
    let mut n = 0usize;
    let mut probe_block = [0u8; 4096];
    for_each_partition(p, s, |p, e, part| {
        if e.type_guid != GPT_BASIC_DATA {
            return Ok(true);
        }
        let kind = probe(p, &part, &mut probe_block)?;
        if kind != VolumeKind::Other {
            if let Some(slot) = out.get_mut(n) {
                *slot = Some((part, kind));
                n += 1;
            }
        }
        Ok(n < MAX_CANDIDATES)
    })?;
    Ok(n)
}

/// A file's identity on the NTFS volume (never its location).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileId {
    pub mft_record: u64,
    pub mft_seq: u16,
}

/// Stage 4's result: the boot entry's disks, found on the unlocked volume.
///
/// Stage 4 reads each disk file's last 512 bytes and first sectors and
/// decides with `paguro_core::disk::{detect, classify}` where the FAT32
/// holding the UEFI image is.
pub struct Located {
    /// The boot entry's name: the configured entry, or in recovery and on a
    /// first boot the one stage 4 found.
    pub name: [u8; 32],
    pub name_len: u8,
    /// The Linux root disk; `None`: nothing to boot on this volume.
    pub root: Option<FileId>,
    /// The disk holding the UEFI image, when it is not the root.
    pub efi_disk: Option<FileId>,
    /// A UEFI image directly on NTFS (`efi_file`): started from a buffer
    /// ([`Volume::efi_image`]) instead of by device path.
    pub efi_file: Option<FileId>,
    /// `handoff::state::HIBERNATED` / `DIRTY`.
    pub flags: u32,
    /// Device path of the UEFI image on the published FAT32 (unused for an
    /// `efi_file`).
    pub chain: [u8; 512],
    pub chain_len: usize,
    /// NTFS paths of the root, the efi disk (when separate) and the efi file,
    /// from which the loader authors the configuration on a provisioning boot.
    pub root_path: [u8; 1024],
    pub root_path_len: usize,
    pub efi_disk_path: [u8; 1024],
    pub efi_disk_path_len: usize,
    pub efi_file_path: [u8; 1024],
    pub efi_file_path_len: usize,
}

fn text(b: &[u8], n: usize) -> &str {
    core::str::from_utf8(b.get(..n).unwrap_or(&[])).unwrap_or("")
}

impl Located {
    pub const fn new() -> Self {
        Located {
            name: [0; 32],
            name_len: 0,
            root: None,
            efi_disk: None,
            efi_file: None,
            flags: 0,
            chain: [0; 512],
            chain_len: 0,
            root_path: [0; 1024],
            root_path_len: 0,
            efi_disk_path: [0; 1024],
            efi_disk_path_len: 0,
            efi_file_path: [0; 1024],
            efi_file_path_len: 0,
        }
    }
    pub fn name(&self) -> &str {
        text(&self.name, usize::from(self.name_len))
    }
    pub fn chain(&self) -> &[u8] {
        self.chain.get(..self.chain_len).unwrap_or(&[])
    }
    /// The root's path, when there is a root.
    pub fn root_path(&self) -> Option<&str> {
        (self.root_path_len != 0).then(|| text(&self.root_path, self.root_path_len))
    }
    /// The efi disk's path; the root's when it has none of its own.
    pub fn efi_disk_path(&self) -> Option<&str> {
        match self.efi_disk_path_len {
            0 => self.root_path(),
            n => Some(text(&self.efi_disk_path, n)),
        }
    }
    pub fn efi_file_path(&self) -> Option<&str> {
        (self.efi_file_path_len != 0).then(|| text(&self.efi_file_path, self.efi_file_path_len))
    }
    /// Whether stage 4 found anything to start.
    pub fn bootable(&self) -> bool {
        self.efi_file.is_some() || self.root.is_some()
    }
}

impl Default for Located {
    fn default() -> Self {
        Self::new()
    }
}

/// The BitLocker volume's FVE side (stage 3) and the NTFS side (stage 4).
///
/// Every method that consumes volume bytes must be bounded and refuse
/// malformed input with a typed error (DESIGN.md §6, "Every parser is
/// hardened").
pub trait Volume<P: Platform> {
    /// Bind to the chosen partition.
    fn open(&mut self, p: &mut P, part: &Partition, kind: VolumeKind) -> Result<(), BootError>;
    /// The encrypted FVEK blob (the root gate's input); returns its length.
    fn fvek_blob(&mut self, p: &mut P, out: &mut [u8]) -> Result<usize, BootError>;
    /// A clear-key protector's VMK, if the volume has one.
    fn clear_key(&mut self, p: &mut P) -> Result<Option<Key>, BootError>;
    /// Try a candidate VMK against the FVEK's AES-CCM MAC. `Ok(true)` means
    /// correct; the FVEK is then retained for [`Volume::fvek`].
    fn try_vmk(&mut self, p: &mut P, vmk: &Key) -> Result<bool, BootError>;
    /// The unwrapped FVEK: `(cipher, key)`.
    fn fvek(&self) -> Option<(u16, &[u8])>;
    /// The FVE layout for the handoff.
    fn layout(&self) -> Option<FveLayout>;
    /// The VMK behind the recovery-password protector for this 16-byte key.
    fn recovery_key(&mut self, p: &mut P, key: &[u8; 16]) -> Result<Option<Key>, BootError>;
    /// Stage 4: parse NTFS, locate `entry`'s `root` and `efi_disk` or
    /// `efi_file` (or, in recovery and on a first boot, find an installation),
    /// validate their maps, and either publish the efi disk's FAT32 and name
    /// the UEFI image on it, or read the `efi_file` for [`Volume::efi_image`].
    fn locate(
        &mut self,
        p: &mut P,
        entry: Option<&Entry<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError>;
    /// The `efi_file` stage 4 read (when [`Located::efi_file`] is set), for
    /// `LoadImage(SourceBuffer)`.
    fn efi_image(&mut self, p: &mut P) -> Result<&[u8], BootError>;
}

/// Production stand-in until the FVE parser and `paguro-core::ntfs` land:
/// opens anything, reports no clear key, and refuses every operation that
/// needs parsed volume structures.
pub struct Unimplemented;

impl<P: Platform> Volume<P> for Unimplemented {
    fn open(&mut self, _: &mut P, _: &Partition, _: VolumeKind) -> Result<(), BootError> {
        Ok(())
    }
    fn fvek_blob(&mut self, _: &mut P, _: &mut [u8]) -> Result<usize, BootError> {
        Err(BootError::NotImplemented("stage 3: FVE metadata"))
    }
    fn clear_key(&mut self, _: &mut P) -> Result<Option<Key>, BootError> {
        Ok(None)
    }
    fn try_vmk(&mut self, _: &mut P, _: &Key) -> Result<bool, BootError> {
        Err(BootError::NotImplemented("stage 3: FVEK unwrap"))
    }
    fn fvek(&self) -> Option<(u16, &[u8])> {
        None
    }
    fn layout(&self) -> Option<FveLayout> {
        None
    }
    fn recovery_key(&mut self, _: &mut P, _: &[u8; 16]) -> Result<Option<Key>, BootError> {
        Err(BootError::NotImplemented("stage 3: recovery password"))
    }
    fn locate(
        &mut self,
        _: &mut P,
        _: Option<&Entry<'_>>,
        _: &mut Located,
    ) -> Result<(), BootError> {
        Err(BootError::NotImplemented("stage 4: NTFS + image"))
    }
    fn efi_image(&mut self, _: &mut P) -> Result<&[u8], BootError> {
        Err(BootError::NotImplemented("stage 4: efi_file read"))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryKeyError {
    /// Not 48 digits (optionally in 8 groups of 6 separated by `-` or spaces).
    Format,
    /// A group is not a multiple of 11 or is ≥ 720 896.
    Group(u8),
}

/// BitLocker's 48-digit recovery password → its 16-byte key: eight groups of
/// six digits, each divisible by 11, each quotient a little-endian u16.
pub fn parse_recovery_password(s: &[u8]) -> Result<[u8; 16], RecoveryKeyError> {
    if s.len() > 64 {
        return Err(RecoveryKeyError::Format);
    }
    let mut digits = [0u8; 48];
    let mut n = 0usize;
    for &c in s {
        match c {
            b'0'..=b'9' => {
                *digits.get_mut(n).ok_or(RecoveryKeyError::Format)? = c - b'0';
                n += 1;
            }
            b'-' | b' ' => {}
            _ => return Err(RecoveryKeyError::Format),
        }
    }
    if n != 48 {
        return Err(RecoveryKeyError::Format);
    }
    let mut key = [0u8; 16];
    for (g, (chunk, out)) in digits
        .chunks_exact(6)
        .zip(key.chunks_exact_mut(2))
        .enumerate()
    {
        let v = chunk.iter().fold(0u32, |a, &d| a * 10 + u32::from(d));
        let gi = g as u8;
        if v % 11 != 0 || v >= 720_896 {
            return Err(RecoveryKeyError::Group(gi));
        }
        out.copy_from_slice(&((v / 11) as u16).to_le_bytes());
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_password() {
        let pw = b"000011-000022-000033-000044-000055-000066-000077-720885";
        let k = parse_recovery_password(pw).unwrap();
        assert_eq!(&k[..4], &[1, 0, 2, 0]);
        assert_eq!(&k[14..], &65535u16.to_le_bytes());
        let spaced = b"000011 000022 000033 000044 000055 000066 000077 720885";
        assert_eq!(parse_recovery_password(spaced), Ok(k));
        assert_eq!(
            parse_recovery_password(b"12"),
            Err(RecoveryKeyError::Format)
        );
        assert_eq!(
            parse_recovery_password(&[b'1'; 65]),
            Err(RecoveryKeyError::Format)
        );
        assert_eq!(
            parse_recovery_password(&[b'0'; 49]),
            Err(RecoveryKeyError::Format)
        );
        let mut bad = *pw;
        bad[0] = b'x';
        assert_eq!(parse_recovery_password(&bad), Err(RecoveryKeyError::Format));
        let mut bad = *pw;
        bad[5] = b'2';
        assert_eq!(
            parse_recovery_password(&bad),
            Err(RecoveryKeyError::Group(0))
        );
        let big = b"000011-000022-000033-000044-000055-000066-000077-720896";
        assert_eq!(
            parse_recovery_password(big),
            Err(RecoveryKeyError::Group(7))
        );
    }
}
