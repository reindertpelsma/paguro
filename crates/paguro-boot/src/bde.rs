//! Stage 3's BitLocker reader: protectors → VMK → FVEK, and the decrypted
//! view (DESIGN.md §6 "Reading a BitLocker volume", INTERFACES.md §8, §12.2).
//!
//! The format is `paguro_core::bde` (pure parsing); the primitives are
//! `paguro_crypto::bitlocker`. This module joins them:
//!
//! - **unlock**: [`vmk_from_password`], [`vmk_from_recovery`],
//!   [`vmk_from_clear_key`], [`vmk_from_startup_key`] each try every
//!   protector of their kind and return the VMK whose AES-CCM MAC verifies;
//!   [`unlock_fvek`] unwraps the FVEK under a VMK and then authenticates the
//!   whole metadata block against its VMK-wrapped SHA-256 (Windows 8+).
//! - **reading**: [`DecryptingReader`] serves the volume as Windows sees
//!   it over any [`UnitRead`]: the relocated boot sectors at the front,
//!   zeros over the metadata regions and the relocated copy, XTS below
//!   `encrypted_size` with tweak = sector index, plaintext above.
//!   [`BdeSectors`] is the same view as stage 4's [`SectorRead`], so every
//!   NTFS read goes through it; the UEFI block device reuses the reader.
//! - **the loader**: [`BdeVolume`] is the production [`Volume`] for
//!   BitLocker and plain NTFS partitions: stage 3 here, stage 4 by
//!   [`Stage4`] over the decrypted (or plain) sectors.

use core::mem::size_of;
use paguro_core::bde::{
    self, BdeError, Ccm, Cipher, Layout, Metadata, ProtectorKind, Source, StartupKey, VolumeHeader,
};

use paguro_core::config::Entry;
use paguro_core::disk::SECTOR;
use paguro_core::handoff::{FveLayout, MAX_FVEK_KEY};
use paguro_core::ntfs;
use paguro_crypto::bitlocker::{CCM_NONCE_LEN, CCM_TAG_LEN, Xts, ccm_unwrap};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::BootError;
use crate::platform::{DirListing, Platform, PlatformError};
use crate::stage4::{PartitionReader, SectorRead, Stage4};
use crate::volume::{Key, Located, MAX_BLOCK, Partition, RECOVERY_KEY_LEN, Volume, VolumeKind};

/// A 256-bit key: the VMK, and the AES-CCM keys that wrap it (clear key,
/// stretched password or recovery key).
const KEY_LEN: usize = 32;
pub type Vmk = [u8; KEY_LEN];

/// Hash algorithm id of the validation entry's SHA-256, in the low 16 bits
/// of the key entry's method field (libbde "FVE key").
const VALIDATION_SHA256: u32 = 0x2005;
const KEY_METHOD_MASK: u32 = 0xffff;
const SHA256_LEN: usize = 32;

/// The 512-byte sectors stage 4 reads, as a buffer length.
const SECTOR_LEN: usize = SECTOR as usize;
/// The largest volume sector (`bytes_per_sector`) BitLocker uses.
const MAX_UNIT: usize = 4096;

/// The FVEK blob handed to the root gate: the FVE AES-CCM encrypted key's
/// nonce and tag, then its ciphertext (libbde "AES-CCM encrypted key").
/// Layout only.
#[allow(dead_code)]
#[repr(C, packed)]
struct FvekBlobHeader {
    nonce: [u8; CCM_NONCE_LEN],
    tag: [u8; CCM_TAG_LEN],
}
const _: () = assert!(size_of::<FvekBlobHeader>() == 28);

/// Unwrap `c` under `key` and parse the key entry inside. `Ok(None)`: the
/// MAC did not verify (wrong key). A verified but malformed plaintext is an
/// error — Windows never writes one.
fn unwrap<'b>(
    key: &[u8; KEY_LEN],
    c: &Ccm<'_>,
    buf: &'b mut [u8; bde::MAX_WRAPPED],
) -> Result<Option<bde::Key<'b>>, BdeError> {
    let n = c.ciphertext.len();
    let plain = buf.get_mut(..n).ok_or(BdeError::BadCcm)?;
    plain.copy_from_slice(c.ciphertext);
    if ccm_unwrap(key, &c.nonce, &c.tag, plain).is_err() {
        return Ok(None);
    }
    bde::parse_key(plain).map(Some)
}

fn unwrap_vmk(key: &[u8; KEY_LEN], c: &Ccm<'_>) -> Result<Option<Vmk>, BdeError> {
    let mut buf = [0u8; bde::MAX_WRAPPED];
    let r = match unwrap(key, c, &mut buf)? {
        None => None,
        Some(k) => Some(Vmk::try_from(k.key).map_err(|_| BdeError::BadKey)?),
    };
    buf.zeroize();
    Ok(r)
}

/// The VMK behind a clear-key protector (BitLocker suspended).
pub fn vmk_from_clear_key(m: &Metadata<'_>) -> Result<Option<Vmk>, BdeError> {
    for p in m.of_kind(ProtectorKind::ClearKey) {
        if let (Some(k), Some(c)) = (p.clear_key, p.wrapped_vmk) {
            if let Some(v) = unwrap_vmk(&k, &c)? {
                return Ok(Some(v));
            }
        }
    }
    Ok(None)
}

fn stretched(
    m: &Metadata<'_>,
    kind: ProtectorKind,
    initial: &[u8; KEY_LEN],
) -> Result<Option<Vmk>, BdeError> {
    for p in m.of_kind(kind) {
        if let (Some(salt), Some(c)) = (p.salt, p.wrapped_vmk) {
            let mut k =
                paguro_crypto::bitlocker_stretch(initial, &salt, paguro_crypto::STRETCH_ITERATIONS);
            let r = unwrap_vmk(&k, &c);
            k.zeroize();
            if let Some(v) = r? {
                return Ok(Some(v));
            }
        }
    }
    Ok(None)
}

/// The VMK behind a BitLocker password protector, from the user hash
/// (`SHA-256(SHA-256(UTF-16LE(password)))`, what the loader's password
/// row already computes).
pub fn vmk_from_password_hash(
    m: &Metadata<'_>,
    user: &[u8; KEY_LEN],
) -> Result<Option<Vmk>, BdeError> {
    stretched(m, ProtectorKind::Password, user)
}

/// The VMK behind a BitLocker password protector.
pub fn vmk_from_password(m: &Metadata<'_>, password: &str) -> Result<Option<Vmk>, BdeError> {
    let mut h = paguro_crypto::user_password_hash(password);
    let r = stretched(m, ProtectorKind::Password, &h);
    h.zeroize();
    r
}

/// The VMK behind a recovery-password protector; `key` is the 16 bytes
/// [`crate::volume::parse_recovery_password`] derives from the 48 digits.
pub fn vmk_from_recovery(
    m: &Metadata<'_>,
    key: &[u8; RECOVERY_KEY_LEN],
) -> Result<Option<Vmk>, BdeError> {
    let mut h: [u8; KEY_LEN] = Sha256::digest(key).into();
    let r = stretched(m, ProtectorKind::RecoveryPassword, &h);
    h.zeroize();
    r
}

/// The VMK behind the startup-key protector a `.BEK` file names.
pub fn vmk_from_startup_key(m: &Metadata<'_>, sk: &StartupKey) -> Result<Option<Vmk>, BdeError> {
    for p in m.of_kind(ProtectorKind::StartupKey) {
        if p.id == sk.id {
            if let Some(c) = p.wrapped_vmk {
                return unwrap_vmk(&sk.key, &c);
            }
        }
    }
    Ok(None)
}

/// The unwrapped full-volume encryption key. Zeroed on drop.
pub struct Fvek {
    pub cipher: Cipher,
    key: [u8; MAX_FVEK_KEY],
    len: usize,
}

impl Fvek {
    pub fn key(&self) -> &[u8] {
        self.key.get(..self.len).unwrap_or(&[])
    }
    pub fn xts(&self) -> Option<Xts> {
        Xts::new(self.key()).ok()
    }
}

impl core::fmt::Debug for Fvek {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Fvek({:?}, {} bytes)", self.cipher, self.len)
    }
}

impl Drop for Fvek {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

/// Unwrap the FVEK under `vmk`. `Ok(None)`: the VMK is wrong. A right VMK
/// then authenticates the metadata: the block's VMK-wrapped SHA-256
/// (Windows 8+) must match, or the metadata was altered and nothing it says
/// (layout included) may be used.
pub fn unlock_fvek(m: &Metadata<'_>, vmk: &Vmk) -> Result<Option<Fvek>, BdeError> {
    let mut buf = [0u8; bde::MAX_WRAPPED];
    let Some(k) = unwrap(vmk, &m.fvek, &mut buf)? else {
        return Ok(None);
    };
    let cipher = m.block.cipher;
    let want = cipher
        .key_len()
        .ok_or(BdeError::UnsupportedCipher(cipher.to_u16()))?;
    if k.method != u32::from(cipher.to_u16()) || k.key.len() != want {
        buf.zeroize();
        return Err(BdeError::FvekMismatch);
    }
    let mut f = Fvek {
        cipher,
        key: [0; MAX_FVEK_KEY],
        len: want,
    };
    if let Some(dst) = f.key.get_mut(..want) {
        dst.copy_from_slice(k.key);
    }
    buf.zeroize();
    if let Some(v) = m.block.validation {
        let mut hb = [0u8; bde::MAX_WRAPPED];
        let h = unwrap(vmk, &v, &mut hb)?.ok_or(BdeError::ValidationHash)?;
        let digest: [u8; SHA256_LEN] = Sha256::digest(m.block.raw).into();
        if h.method & KEY_METHOD_MASK != VALIDATION_SHA256 || h.key != digest {
            return Err(BdeError::ValidationHash);
        }
    }
    Ok(Some(f))
}

/// The read callback: whole volume sectors (units of the volume header's
/// `bytes_per_sector`), counted from the volume start.
pub trait UnitRead {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadError {
    /// The device read failed.
    Io,
    /// Past the end of the volume.
    Range,
    /// The buffer is not a whole number of sectors.
    Alignment,
}

/// The decrypted view over `dev`. `xts: None` serves an unencrypted
/// (plain NTFS) volume unchanged.
pub struct DecryptingReader<'k, R> {
    pub dev: R,
    layout: Option<Layout>,
    xts: Option<&'k Xts>,
    bps: u32,
    units: u64,
    /// One unit, for 512-byte reads on 4 KiB volumes.
    cache: [u8; MAX_UNIT],
    cached: Option<u64>,
}

impl<'k, R: UnitRead> DecryptingReader<'k, R> {
    pub fn new(dev: R, layout: Layout, xts: &'k Xts) -> Self {
        DecryptingReader {
            dev,
            bps: layout.bytes_per_sector,
            units: layout.units(),
            layout: Some(layout),
            xts: Some(xts),
            cache: [0; MAX_UNIT],
            cached: None,
        }
    }

    /// An unencrypted volume: `bytes_per_sector` ∈ {512, 4096}.
    pub fn passthrough(dev: R, bytes_per_sector: u32, units: u64) -> Self {
        DecryptingReader {
            dev,
            layout: None,
            xts: None,
            bps: bytes_per_sector,
            units,
            cache: [0; MAX_UNIT],
            cached: None,
        }
    }

    pub fn bytes_per_sector(&self) -> u32 {
        self.bps
    }

    pub fn units(&self) -> u64 {
        self.units
    }

    /// Read whole units starting at `unit` of the decrypted view.
    pub fn read(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let bps = self.bps as usize;
        if bps == 0 || buf.len() % bps != 0 {
            return Err(ReadError::Alignment);
        }
        let n = (buf.len() / bps) as u64;
        if unit.checked_add(n).is_none_or(|end| end > self.units) {
            return Err(ReadError::Range);
        }
        let (Some(layout), Some(xts)) = (self.layout, self.xts) else {
            return self.dev.read_units(unit, buf);
        };
        let mut u = unit;
        let mut rest = buf;
        while !rest.is_empty() {
            let (src, run) = layout.map(u).ok_or(ReadError::Range)?;
            let k = run.clamp(1, (rest.len() / bps) as u64);
            let (chunk, tail) = rest.split_at_mut(k as usize * bps);
            match src {
                Source::Zero => chunk.fill(0),
                Source::Disk { unit: p, encrypted } => {
                    self.dev.read_units(p, chunk)?;
                    if encrypted {
                        for (i, s) in chunk.chunks_exact_mut(bps).enumerate() {
                            xts.decrypt(u128::from(p) + i as u128, s)
                                .map_err(|_| ReadError::Alignment)?;
                        }
                    }
                }
            }
            u += k;
            rest = tail;
        }
        Ok(())
    }

    /// Read 512-byte sectors of the view, whatever the unit size: whole
    /// units straight through, partial ones via a one-unit cache.
    pub fn read_sectors(&mut self, sector: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        if buf.len() % SECTOR_LEN != 0 {
            return Err(ReadError::Alignment);
        }
        if u64::from(self.bps) == SECTOR {
            return self.read(sector, buf);
        }
        let per = u64::from(self.bps) / SECTOR;
        let n = (buf.len() / SECTOR_LEN) as u64;
        if sector
            .checked_add(n)
            .is_none_or(|e| e > self.units.saturating_mul(per))
        {
            return Err(ReadError::Range);
        }
        let mut done = 0u64;
        while done < n {
            let s = sector + done;
            let at = (done * SECTOR) as usize;
            if s % per == 0 && n - done >= per {
                let whole = (n - done) / per;
                let dst = buf
                    .get_mut(at..at + (whole * per * SECTOR) as usize)
                    .ok_or(ReadError::Range)?;
                self.read(s / per, dst)?;
                done += whole * per;
                continue;
            }
            let unit = s / per;
            if self.cached != Some(unit) {
                self.cached = None;
                let bps = self.bps as usize;
                let mut c = self.cache;
                let r = self.read(unit, c.get_mut(..bps).ok_or(ReadError::Alignment)?);
                self.cache = c;
                c.zeroize();
                r?;
                self.cached = Some(unit);
            }
            let within = s % per;
            let take = (per - within).min(n - done);
            let src = self
                .cache
                .get((within * SECTOR) as usize..((within + take) * SECTOR) as usize)
                .ok_or(ReadError::Range)?;
            buf.get_mut(at..at + src.len())
                .ok_or(ReadError::Range)?
                .copy_from_slice(src);
            done += take;
        }
        Ok(())
    }
}

impl<R: UnitRead> ntfs::Disk for DecryptingReader<'_, R> {
    fn read(&mut self, sector: u64, buf: &mut [u8; SECTOR_LEN]) -> Result<(), ntfs::IoError> {
        self.read_sectors(sector, buf).map_err(|_| ntfs::IoError)
    }
}

impl<R> Drop for DecryptingReader<'_, R> {
    fn drop(&mut self) {
        self.cache.zeroize();
    }
}

/// A partition read through [`Platform::read_blocks`], in units of
/// `unit_size` (a multiple of the disk's block size).
pub struct PartIo<'p, P> {
    pub p: &'p mut P,
    pub part: Partition,
    pub unit_size: u32,
}

impl<P: Platform> UnitRead for PartIo<'_, P> {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let bs = u64::from(self.part.block_size);
        let per = u64::from(self.unit_size) / bs.max(1);
        let lba = unit
            .checked_mul(per)
            .and_then(|b| b.checked_add(self.part.first_lba))
            .ok_or(ReadError::Range)?;
        self.p
            .read_blocks(self.part.disk, lba, buf)
            .map_err(|_| ReadError::Io)
    }
}

/// An unlocked BitLocker partition as stage 4 reads it: 512-byte sectors
/// of the decrypted view.
#[derive(Clone, Copy)]
pub struct BdeSectors<'k> {
    pub part: Partition,
    pub layout: Layout,
    pub xts: &'k Xts,
}

impl<P: Platform> SectorRead<P> for BdeSectors<'_> {
    fn read(&mut self, p: &mut P, sector: u64, buf: &mut [u8]) -> Result<(), PlatformError> {
        if buf.is_empty() {
            return Err(PlatformError::Unsupported);
        }
        let io = PartIo {
            p,
            part: self.part,
            unit_size: self.layout.bytes_per_sector,
        };
        DecryptingReader::new(io, self.layout, self.xts)
            .read_sectors(sector, buf)
            .map_err(|e| match e {
                ReadError::Io => PlatformError::Device(0),
                ReadError::Range => PlatformError::TooLarge,
                ReadError::Alignment => PlatformError::Unsupported,
            })
    }
    fn sectors(&self) -> u64 {
        self.layout.units() * (u64::from(self.layout.bytes_per_sector) / SECTOR)
    }
}

/// The loader's [`Volume`] for BitLocker and plain NTFS partitions.
///
/// It borrows its two large parts — stage 4's working memory (~2.5 MiB)
/// and one 64 KiB metadata region — so the loader can place them in pages
/// (all-zero is valid for both) and keep this small struct on the stack.
pub struct BdeVolume<'a> {
    pub stage4: &'a mut Stage4,
    /// Copy 0 of the FVE metadata (the whole 64 KiB region).
    meta: &'a mut [u8; bde::REGION_SIZE as usize],
    part: Option<Partition>,
    hdr: Option<VolumeHeader>,
    layout: Option<Layout>,
    fvek: Option<Fvek>,
    xts: Option<Xts>,
}

fn fail(e: BdeError) -> BootError {
    BootError::Bde(e)
}

impl<'a> BdeVolume<'a> {
    pub fn new(stage4: &'a mut Stage4, meta: &'a mut [u8; bde::REGION_SIZE as usize]) -> Self {
        BdeVolume {
            stage4,
            meta,
            part: None,
            hdr: None,
            layout: None,
            fvek: None,
            xts: None,
        }
    }

    /// The parsed metadata of the opened BitLocker volume.
    pub fn metadata(&self) -> Result<Metadata<'_>, BdeError> {
        let hdr = self.hdr.as_ref().ok_or(BdeError::NotBitLocker)?;
        Metadata::parse(bde::parse_block(&self.meta[..], 0, hdr)?)
    }

    pub fn layout_detail(&self) -> Option<&Layout> {
        self.layout.as_ref()
    }

    /// [`Volume::fvek`], without naming the platform.
    pub fn fvek(&self) -> Option<(u16, &[u8])> {
        self.fvek.as_ref().map(|f| (f.cipher.to_u16(), f.key()))
    }

    /// [`Volume::layout`], without naming the platform.
    pub fn layout(&self) -> Option<FveLayout> {
        self.layout.map(|l| l.fve_layout())
    }

    /// Unlock with a BitLocker password protector.
    pub fn unlock_password(&mut self, password: &str) -> Result<bool, BdeError> {
        let v = vmk_from_password(&self.metadata()?, password)?;
        self.accept(v)
    }

    /// Unlock with a startup key (`.BEK` file contents).
    pub fn unlock_startup_key(&mut self, bek: &[u8]) -> Result<bool, BdeError> {
        let sk = bde::parse_startup_key(bek)?;
        let v = vmk_from_startup_key(&self.metadata()?, &sk)?;
        self.accept(v)
    }

    fn accept(&mut self, v: Option<Vmk>) -> Result<bool, BdeError> {
        match v {
            Some(mut v) => {
                let r = self.try_vmk_inner(&v);
                v.zeroize();
                r
            }
            None => Ok(false),
        }
    }

    fn try_vmk_inner(&mut self, vmk: &Vmk) -> Result<bool, BdeError> {
        let Some(f) = unlock_fvek(&self.metadata()?, vmk)? else {
            return Ok(false);
        };
        self.xts = Some(f.xts().ok_or(BdeError::FvekMismatch)?);
        self.fvek = Some(f);
        Ok(true)
    }

    /// Read 512-byte sectors of the plaintext view (once unlocked, or of a
    /// plain NTFS volume).
    pub fn read_sectors<P: Platform>(
        &self,
        p: &mut P,
        sector: u64,
        buf: &mut [u8],
    ) -> Result<(), BootError> {
        match reader(
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )? {
            Reader::Plain(mut r) => r.read(p, sector, buf),
            Reader::Bde(mut r) => r.read(p, sector, buf),
        }
        .map_err(BootError::Platform)
    }

    fn open_bitlocker<P: Platform>(
        &mut self,
        p: &mut P,
        part: &Partition,
    ) -> Result<(), BootError> {
        let bs = part.block_size as usize;
        let size = part
            .sectors
            .checked_mul(u64::from(part.block_size))
            .ok_or(fail(BdeError::MetadataOffset))?;
        let mut scratch = [0u8; MAX_BLOCK];
        let first = scratch.get_mut(..bs).ok_or(BootError::Disk)?;
        p.read_blocks(part.disk, part.first_lba, first)
            .map_err(BootError::Platform)?;
        let hdr = bde::parse_volume_header(first).map_err(fail)?;
        if hdr.bytes_per_sector % part.block_size != 0 {
            return Err(fail(BdeError::SectorSize(hdr.bytes_per_sector as u16)));
        }
        let region = bde::REGION_SIZE;
        for o in hdr.metadata_offsets {
            if o.checked_add(region).is_none_or(|e| e > size) || o % u64::from(part.block_size) != 0
            {
                return Err(fail(BdeError::MetadataOffset));
            }
        }
        let lba = |o: u64| part.first_lba + o / u64::from(part.block_size);
        let [m0, m1, m2] = hdr.metadata_offsets;
        p.read_blocks(part.disk, lba(m0), &mut self.meta[..])
            .map_err(BootError::Platform)?;
        let agreed = bde::parse_block(&self.meta[..], 0, &hdr)
            .map_err(fail)?
            .agreed
            .len();
        // Copies 1 and 2: the same bytes, compared a block at a time.
        for o in [m1, m2] {
            let mut done = 0usize;
            let mut l = lba(o);
            while done < agreed {
                let blk = scratch.get_mut(..bs).ok_or(BootError::Disk)?;
                p.read_blocks(part.disk, l, blk)
                    .map_err(BootError::Platform)?;
                let n = bs.min(agreed - done);
                if blk.get(..n) != self.meta.get(done..done + n) {
                    return Err(fail(BdeError::CopiesDisagree));
                }
                done += n;
                l += 1;
            }
        }
        self.hdr = Some(hdr);
        let m = self.metadata().map_err(fail)?;
        let layout = Layout::new(&hdr, &m, size).map_err(fail)?;
        self.layout = Some(layout);
        Ok(())
    }
}

enum Reader<'k> {
    Plain(PartitionReader),
    Bde(BdeSectors<'k>),
}

fn reader<'k>(
    part: Option<Partition>,
    layout: Option<Layout>,
    xts: Option<&'k Xts>,
    bitlocker: bool,
) -> Result<Reader<'k>, BootError> {
    let part = part.ok_or(BootError::NoVolume)?;
    match (layout, xts) {
        (Some(layout), Some(xts)) => Ok(Reader::Bde(BdeSectors { part, layout, xts })),
        (None, None) if !bitlocker => Ok(Reader::Plain(PartitionReader { part })),
        // BitLocker, not unlocked: stage 4 never runs before a key.
        _ => Err(BootError::Bde(BdeError::FvekMismatch)),
    }
}

impl<P: Platform> Volume<P> for BdeVolume<'_> {
    fn open(&mut self, p: &mut P, part: &Partition, kind: VolumeKind) -> Result<(), BootError> {
        self.part = None;
        self.hdr = None;
        self.layout = None;
        self.fvek = None;
        self.xts = None;
        self.stage4.reset();
        match kind {
            VolumeKind::BitLocker => {
                let r = self.open_bitlocker(p, part);
                if r.is_err() {
                    self.hdr = None;
                    self.layout = None;
                    return r;
                }
            }
            VolumeKind::Ntfs => {}
            VolumeKind::Other => return Err(BootError::NotAVolume),
        }
        self.part = Some(*part);
        Ok(())
    }

    fn fvek_blob(&mut self, _: &mut P, out: &mut [u8]) -> Result<usize, BootError> {
        let m = self.metadata().map_err(fail)?;
        let f = m.fvek;
        let n = size_of::<FvekBlobHeader>() + f.ciphertext.len();
        let o = out.get_mut(..n).ok_or(BootError::Disk)?;
        let (nonce, rest) = o.split_at_mut(CCM_NONCE_LEN);
        let (tag, ct) = rest.split_at_mut(CCM_TAG_LEN);
        nonce.copy_from_slice(&f.nonce);
        tag.copy_from_slice(&f.tag);
        ct.copy_from_slice(f.ciphertext);
        Ok(n)
    }

    fn clear_key(&mut self, _: &mut P) -> Result<Option<Key>, BootError> {
        if self.hdr.is_none() {
            return Ok(None);
        }
        vmk_from_clear_key(&self.metadata().map_err(fail)?).map_err(fail)
    }

    fn try_vmk(&mut self, _: &mut P, vmk: &Key) -> Result<bool, BootError> {
        self.try_vmk_inner(vmk).map_err(fail)
    }

    fn fvek(&self) -> Option<(u16, &[u8])> {
        BdeVolume::fvek(self)
    }

    fn layout(&self) -> Option<FveLayout> {
        BdeVolume::layout(self)
    }

    fn recovery_key(
        &mut self,
        _: &mut P,
        key: &[u8; RECOVERY_KEY_LEN],
    ) -> Result<Option<Key>, BootError> {
        vmk_from_recovery(&self.metadata().map_err(fail)?, key).map_err(fail)
    }

    fn bitlocker_password(&mut self, _: &mut P, user: &Key) -> Result<Option<Key>, BootError> {
        if self.hdr.is_none() {
            return Ok(None);
        }
        vmk_from_password_hash(&self.metadata().map_err(fail)?, user).map_err(fail)
    }

    fn has_bitlocker_password(&self) -> bool {
        self.metadata()
            .is_ok_and(|m| m.of_kind(ProtectorKind::Password).next().is_some())
    }

    fn locate(
        &mut self,
        p: &mut P,
        entry: Option<&Entry<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError> {
        let part = self.part.ok_or(BootError::NoVolume)?;
        let fve = match (&self.fvek, self.layout) {
            (Some(f), Some(l)) => Some((f.cipher.to_u16(), f.key(), l)),
            _ => None,
        };
        match reader(
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )? {
            Reader::Plain(mut r) => self.stage4.locate(p, &mut r, &part, fve, entry, out),
            Reader::Bde(mut r) => self.stage4.locate(p, &mut r, &part, fve, entry, out),
        }
    }

    fn efi_image(&mut self, p: &mut P) -> Result<&[u8], BootError> {
        match reader(
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )? {
            Reader::Plain(mut r) => self.stage4.efi_image(p, &mut r),
            Reader::Bde(mut r) => self.stage4.efi_image(p, &mut r),
        }
    }

    fn list_dir(&mut self, p: &mut P, path: &str, out: &mut DirListing) -> Result<(), BootError> {
        match reader(
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )? {
            Reader::Plain(mut r) => self.stage4.list_dir(p, &mut r, path, out),
            Reader::Bde(mut r) => self.stage4.list_dir(p, &mut r, path, out),
        }
    }

    fn list_efi_dir(
        &mut self,
        p: &mut P,
        disk: &str,
        path: &str,
        out: &mut DirListing,
    ) -> Result<bool, BootError> {
        match reader(
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )? {
            Reader::Plain(mut r) => self.stage4.list_efi_dir(p, &mut r, disk, path, out),
            Reader::Bde(mut r) => self.stage4.list_efi_dir(p, &mut r, disk, path, out),
        }
    }
}
