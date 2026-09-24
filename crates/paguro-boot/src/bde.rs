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
//!   it over any [`SectorRead`]: the relocated boot sectors at the front,
//!   zeros over the metadata regions and the relocated copy, XTS below
//!   `encrypted_size` with tweak = sector index, plaintext above.
//! - **the loader**: [`BdeVolume`] implements the stage-3 half of
//!   [`Volume`] on a real partition and forwards stage 4 to a [`Stage4`]
//!   that reads through the decrypted view.

use paguro_core::bde::{
    self, BdeError, Ccm, Cipher, Layout, Metadata, ProtectorKind, Source, StartupKey, VolumeHeader,
};
use paguro_core::config::Entry;
use paguro_core::handoff::FveLayout;
use paguro_core::ntfs;
use paguro_crypto::bitlocker::{Xts, ccm_unwrap};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::BootError;
use crate::platform::{DirListing, Platform};
use crate::volume::{Key, Located, Partition, Volume, VolumeKind};

pub type Vmk = [u8; 32];

/// Hash algorithm id of the validation entry's SHA-256.
const VALIDATION_SHA256: u32 = 0x2005;

/// Unwrap `c` under `key` and parse the key entry inside. `Ok(None)`: the
/// MAC did not verify (wrong key). A verified but malformed plaintext is an
/// error — Windows never writes one.
fn unwrap<'b>(
    key: &[u8; 32],
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

fn unwrap_vmk(key: &[u8; 32], c: &Ccm<'_>) -> Result<Option<Vmk>, BdeError> {
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
    initial: &[u8; 32],
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

/// The VMK behind a BitLocker password protector.
pub fn vmk_from_password(m: &Metadata<'_>, password: &str) -> Result<Option<Vmk>, BdeError> {
    let mut h = paguro_crypto::user_password_hash(password);
    let r = stretched(m, ProtectorKind::Password, &h);
    h.zeroize();
    r
}

/// The VMK behind a recovery-password protector; `key` is the 16 bytes
/// [`crate::volume::parse_recovery_password`] derives from the 48 digits.
pub fn vmk_from_recovery(m: &Metadata<'_>, key: &[u8; 16]) -> Result<Option<Vmk>, BdeError> {
    let mut h: [u8; 32] = Sha256::digest(key).into();
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
    key: [u8; 64],
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
        key: [0; 64],
        len: want,
    };
    if let Some(dst) = f.key.get_mut(..want) {
        dst.copy_from_slice(k.key);
    }
    buf.zeroize();
    if let Some(v) = m.block.validation {
        let mut hb = [0u8; bde::MAX_WRAPPED];
        let h = unwrap(vmk, &v, &mut hb)?.ok_or(BdeError::ValidationHash)?;
        let digest: [u8; 32] = Sha256::digest(m.block.raw).into();
        if h.method & 0xffff != VALIDATION_SHA256 || h.key != digest {
            return Err(BdeError::ValidationHash);
        }
    }
    Ok(Some(f))
}

/// The read callback: whole volume sectors (units of the volume header's
/// `bytes_per_sector`), counted from the volume start.
pub trait SectorRead {
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
    /// One unit, for [`ntfs::Disk`]'s 512-byte reads on 4 KiB volumes.
    cache: [u8; 4096],
    cached: Option<u64>,
}

impl<'k, R: SectorRead> DecryptingReader<'k, R> {
    pub fn new(dev: R, layout: Layout, xts: &'k Xts) -> Self {
        DecryptingReader {
            dev,
            bps: layout.bytes_per_sector,
            units: layout.units(),
            layout: Some(layout),
            xts: Some(xts),
            cache: [0; 4096],
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
            cache: [0; 4096],
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
}

impl<R: SectorRead> ntfs::Disk for DecryptingReader<'_, R> {
    fn read(&mut self, sector: u64, buf: &mut [u8; 512]) -> Result<(), ntfs::IoError> {
        if self.bps == 512 {
            return DecryptingReader::read(self, sector, buf).map_err(|_| ntfs::IoError);
        }
        let per = u64::from(self.bps / 512);
        let unit = sector / per;
        if self.cached != Some(unit) {
            self.cached = None;
            let bps = self.bps as usize;
            let mut c = self.cache;
            let r = DecryptingReader::read(self, unit, c.get_mut(..bps).ok_or(ntfs::IoError)?);
            self.cache = c;
            c.zeroize();
            r.map_err(|_| ntfs::IoError)?;
            self.cached = Some(unit);
        }
        let at = ((sector % per) * 512) as usize;
        buf.copy_from_slice(self.cache.get(at..at + 512).ok_or(ntfs::IoError)?);
        Ok(())
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

impl<P: Platform> SectorRead for PartIo<'_, P> {
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

/// The plaintext of the chosen volume, as stage 4 reads it: an
/// [`ntfs::Disk`] (512-byte sectors) and whole-unit reads, plus the
/// platform for everything else.
pub type Plain<'a, P> = DecryptingReader<'a, PartIo<'a, P>>;

/// Stage 4 (INTERFACES.md §10.1, §13.4) over the decrypted view. Mirrors
/// the stage-4 half of [`Volume`]; the platform is `disk.dev.p`.
pub trait Stage4<P: Platform> {
    fn locate(
        &mut self,
        disk: &mut Plain<'_, P>,
        entry: Option<&Entry<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError>;
    fn efi_image(&mut self, disk: &mut Plain<'_, P>) -> Result<&[u8], BootError>;
    fn list_dir(
        &mut self,
        disk: &mut Plain<'_, P>,
        path: &str,
        out: &mut DirListing,
    ) -> Result<(), BootError>;
    fn list_efi_dir(
        &mut self,
        disk: &mut Plain<'_, P>,
        file: &str,
        path: &str,
        out: &mut DirListing,
    ) -> Result<bool, BootError>;
}

impl<P: Platform> Stage4<P> for crate::volume::Unimplemented {
    fn locate(
        &mut self,
        _: &mut Plain<'_, P>,
        _: Option<&Entry<'_>>,
        _: &mut Located,
    ) -> Result<(), BootError> {
        Err(BootError::NotImplemented("stage 4: NTFS + image"))
    }
    fn efi_image(&mut self, _: &mut Plain<'_, P>) -> Result<&[u8], BootError> {
        Err(BootError::NotImplemented("stage 4: efi_file read"))
    }
    fn list_dir(
        &mut self,
        _: &mut Plain<'_, P>,
        _: &str,
        _: &mut DirListing,
    ) -> Result<(), BootError> {
        Err(BootError::NotImplemented("stage 4: NTFS directories"))
    }
    fn list_efi_dir(
        &mut self,
        _: &mut Plain<'_, P>,
        _: &str,
        _: &str,
        _: &mut DirListing,
    ) -> Result<bool, BootError> {
        Err(BootError::NotImplemented(
            "stage 4: EFI partition directories",
        ))
    }
}

/// The loader's [`Volume`] for BitLocker and plain NTFS partitions.
///
/// ~72 KiB (one 64 KiB metadata region): allocate it in pages, not on the
/// firmware stack.
pub struct BdeVolume<S> {
    pub stage4: S,
    part: Option<Partition>,
    hdr: Option<VolumeHeader>,
    layout: Option<Layout>,
    fvek: Option<Fvek>,
    xts: Option<Xts>,
    /// Copy 0 of the FVE metadata (the whole 64 KiB region).
    meta: [u8; bde::REGION_SIZE as usize],
    scratch: [u8; 4096],
}

fn fail(e: BdeError) -> BootError {
    BootError::Bde(e)
}

impl<S> BdeVolume<S> {
    pub fn new(stage4: S) -> Self {
        BdeVolume {
            stage4,
            part: None,
            hdr: None,
            layout: None,
            fvek: None,
            xts: None,
            meta: [0; bde::REGION_SIZE as usize],
            scratch: [0; 4096],
        }
    }

    /// The parsed metadata of the opened BitLocker volume.
    pub fn metadata(&self) -> Result<Metadata<'_>, BdeError> {
        let hdr = self.hdr.as_ref().ok_or(BdeError::NotBitLocker)?;
        Metadata::parse(bde::parse_block(&self.meta, 0, hdr)?)
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

    /// Unlock with a BitLocker password protector (not a loader rung; the
    /// recovery browser and tests use it).
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

    /// The plaintext view, once unlocked (or of a plain NTFS volume).
    pub fn plain<'a, P: Platform>(&'a self, p: &'a mut P) -> Result<Plain<'a, P>, BootError> {
        plain_parts(
            p,
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )
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
        let first = self.scratch.get_mut(..bs).ok_or(BootError::Disk)?;
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
        p.read_blocks(part.disk, lba(m0), &mut self.meta)
            .map_err(BootError::Platform)?;
        let agreed = bde::parse_block(&self.meta, 0, &hdr)
            .map_err(fail)?
            .agreed
            .len();
        // Copies 1 and 2: the same bytes, compared a block at a time.
        for o in [m1, m2] {
            let mut done = 0usize;
            let mut l = lba(o);
            while done < agreed {
                let blk = self.scratch.get_mut(..bs).ok_or(BootError::Disk)?;
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

fn plain_parts<'a, P: Platform>(
    p: &'a mut P,
    part: Option<Partition>,
    layout: Option<Layout>,
    xts: Option<&'a Xts>,
    bitlocker: bool,
) -> Result<Plain<'a, P>, BootError> {
    let part = part.ok_or(BootError::NoVolume)?;
    match (layout, xts) {
        (Some(l), Some(x)) => Ok(DecryptingReader::new(
            PartIo {
                p,
                part,
                unit_size: l.bytes_per_sector,
            },
            l,
            x,
        )),
        (None, None) if !bitlocker => {
            let unit_size = part.block_size;
            Ok(DecryptingReader::passthrough(
                PartIo { p, part, unit_size },
                unit_size,
                part.sectors,
            ))
        }
        // BitLocker, not unlocked: stage 4 never runs before a key.
        _ => Err(BootError::Bde(BdeError::FvekMismatch)),
    }
}

impl<P: Platform, S: Stage4<P>> Volume<P> for BdeVolume<S> {
    fn open(&mut self, p: &mut P, part: &Partition, kind: VolumeKind) -> Result<(), BootError> {
        self.part = None;
        self.hdr = None;
        self.layout = None;
        self.fvek = None;
        self.xts = None;
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
        let n = 28 + f.ciphertext.len();
        let o = out.get_mut(..n).ok_or(BootError::Disk)?;
        let (nonce, rest) = o.split_at_mut(12);
        let (tag, ct) = rest.split_at_mut(16);
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

    fn recovery_key(&mut self, _: &mut P, key: &[u8; 16]) -> Result<Option<Key>, BootError> {
        vmk_from_recovery(&self.metadata().map_err(fail)?, key).map_err(fail)
    }

    fn locate(
        &mut self,
        p: &mut P,
        entry: Option<&Entry<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError> {
        let mut d = plain_parts(
            p,
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )?;
        self.stage4.locate(&mut d, entry, out)
    }

    fn efi_image(&mut self, p: &mut P) -> Result<&[u8], BootError> {
        let mut d = plain_parts(
            p,
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )?;
        self.stage4.efi_image(&mut d)
    }

    fn list_dir(&mut self, p: &mut P, path: &str, out: &mut DirListing) -> Result<(), BootError> {
        let mut d = plain_parts(
            p,
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )?;
        self.stage4.list_dir(&mut d, path, out)
    }

    fn list_efi_dir(
        &mut self,
        p: &mut P,
        disk: &str,
        path: &str,
        out: &mut DirListing,
    ) -> Result<bool, BootError> {
        let mut d = plain_parts(
            p,
            self.part,
            self.layout,
            self.xts.as_ref(),
            self.hdr.is_some(),
        )?;
        self.stage4.list_efi_dir(&mut d, disk, path, out)
    }
}
