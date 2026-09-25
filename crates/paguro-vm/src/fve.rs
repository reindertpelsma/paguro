//! The VM boot's FVE substitution (DESIGN.md §6 "The VM boot", §11 Q9/Q10).
//!
//! A BitLocker C: cannot TPM-unseal inside the VM, so the guest is shown
//! **substituted metadata**: the volume's own block with one extra VMK entry
//! of the *External Key* kind, `AES-CCM(K_ext, VMK)`, and QEMU presents the
//! matching `{G}.BEK` on a synthetic removable device. Nothing is written to
//! the user's volume: the substitute is served, with every other sector
//! BitLocker owns, from a per-session buffer ([`owned_buffer`]) that also
//! absorbs the guest's writes.
//!
//! The entry and the file are what Windows itself writes for
//! `manage-bde -protectors -add C: -StartupKey <dir>` (captured from a
//! Windows 11 25H2 volume, `test/vm/README.md`):
//!
//! ```text
//! VMK entry (0x0002/0x0008)   id G | FILETIME | 0 | protection 0x0200
//!   UNICODE "ExternalKey"
//!   USE_KEY (0x0004)          method 0x2002 | AES-CCM(VMK, KEY{0x2002, K_ext})
//!   AES_CCM                   AES-CCM(K_ext, KEY{0x2003, VMK})   (entry type 5)
//! inserted before the volume-header entry (0x000f); the block, its CRC-32
//! and its VMK-wrapped SHA-256 are rebuilt, the nonce counter advanced.
//!
//! {G}.BEK   FVE metadata header whose identifier is G, then
//!   STARTUP_KEY (0x0006/0x0009) G | FILETIME
//!     UNICODE "ExternalKey"
//!     0x0019/0x0017           the volume's identifier
//!     KEY                     0x2002 | K_ext
//! ```
//!
//! The substitution is checked before it is returned: the new block must
//! parse with `paguro_core::bde`, the new protector must yield the VMK
//! through `paguro_boot::bde::vmk_from_startup_key`, and the VMK must then
//! authenticate the new block (`unlock_fvek`). libbde and dislocker are the
//! independent oracles (`test/vm/fve-oracle.sh`).

use core::mem::size_of;

use paguro_boot::bde::{Vmk, unlock_fvek, vmk_from_startup_key};
use paguro_core::bde::{
    self, BdeError, Layout, Metadata, REGION_SIZE, cross_check, entry, parse_startup_key,
    parse_volume_header, value,
};
use paguro_crypto::bitlocker::ccm_wrap;
use sha2::{Digest, Sha256};

/// FVE entry header: `size u16 | entry type u16 | value type u16 | version u16`.
const ENTRY_HEADER: usize = 8;
/// The metadata block header and the FVE metadata header after it.
const BLOCK_HEADER: usize = bde::BLOCK_HEADER_LEN;
const METADATA_HEADER: usize = bde::METADATA_HEADER_LEN;
/// Block header fields (libbde §3.1).
const BLOCK_SIZE_AT: usize = 8;
const BLOCK_SIZE_UNIT: usize = 16;
/// FVE metadata header fields (libbde §3.2), relative to its start.
const MH_SIZE: usize = 0;
const MH_VERSION: usize = 4;
const MH_HEADER_SIZE: usize = 8;
const MH_SIZE_COPY: usize = 12;
const MH_ID: usize = 16;
const MH_NEXT_NONCE: usize = 32;
const MH_ENCRYPTION: usize = 36;
const MH_CREATED: usize = 40;
const METADATA_VERSION: u32 = 1;
/// Validation version carrying the VMK-wrapped SHA-256 (after `size u16`).
const VALIDATION_WITH_HASH: u16 = 2;

/// Key methods (the low half of a KEY value's method, libbde "FVE key").
const METHOD_EXTERNAL_KEY: u32 = 0x2002;
const METHOD_VMK: u32 = 0x2003;
const METHOD_VALIDATION: u32 = 0x2005;
/// VMK protection type of an external key (a startup key).
const PROTECTION_EXTERNAL_KEY: u16 = bde::protection::STARTUP_KEY;
/// The entry types Windows gives the two things only this protector has:
/// the `K_ext`-wrapped VMK key entry, and the volume identifier in the
/// `.BEK` file (captured, not documented by libbde).
const ENTRY_TYPE_EXTERNAL_VMK: u16 = 0x0005;
const BEK_ENTRY_VOLUME_ID: u16 = 0x0019;
const BEK_VALUE_VOLUME_ID: u16 = 0x0017;
/// The `.BEK` header's next-nonce counter as Windows writes it.
const BEK_NEXT_NONCE: u32 = 1;
const DESCRIPTION: &str = "ExternalKey";

const ID_LEN: usize = 16;
const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const NONCE_TIME_LEN: usize = 8;
/// A nonce counter this close to the top would wrap: refuse instead.
const NONCES_NEEDED: u32 = 3;

/// Seconds from 1601-01-01 (FILETIME's epoch) to 1970-01-01, and its unit.
const FILETIME_UNIX_OFFSET: u64 = 11_644_473_600;
const FILETIME_PER_SECOND: u64 = 10_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FveError {
    /// The volume's own metadata did not parse or cross-check.
    Metadata(BdeError),
    /// The VMK does not open this volume's metadata.
    WrongVmk,
    /// A protector with the chosen identifier already exists.
    DuplicateId,
    /// The substitute does not fit a 64 KiB region, or a counter would wrap.
    TooLarge,
    /// The rebuilt block failed its own round trip (a bug here, never
    /// served).
    RoundTrip(BdeError),
    /// The rebuilt block did not yield the VMK through the new protector.
    RoundTripVmk,
}

impl core::fmt::Display for FveError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FveError::Metadata(e) => write!(f, "FVE metadata: {e:?}"),
            FveError::WrongVmk => write!(f, "the VMK does not open this volume"),
            FveError::DuplicateId => write!(f, "protector id already present"),
            FveError::TooLarge => write!(f, "substituted metadata does not fit"),
            FveError::RoundTrip(e) => write!(f, "substituted metadata does not parse: {e:?}"),
            FveError::RoundTripVmk => write!(f, "substituted protector does not yield the VMK"),
        }
    }
}

/// The per-session choices: the protector's identifier `G`, the external
/// key, and the FILETIME the entries carry.
#[derive(Clone)]
pub struct Params {
    pub id: [u8; ID_LEN],
    pub ext_key: [u8; KEY_LEN],
    pub time: u64,
}

impl Drop for Params {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.ext_key);
    }
}

impl Params {
    /// Fresh random `G` and `K_ext` (getrandom), stamped now.
    pub fn random() -> std::io::Result<Params> {
        let mut id = [0u8; ID_LEN];
        let mut ext_key = [0u8; KEY_LEN];
        getrandom(&mut id)?;
        getrandom(&mut ext_key)?;
        // A version-4 GUID, as Windows makes protector ids.
        id[7] = (id[7] & 0x0f) | 0x40;
        id[8] = (id[8] & 0x3f) | 0x80;
        Ok(Params {
            id,
            ext_key,
            time: filetime_now(),
        })
    }
}

pub fn filetime_now() -> u64 {
    let s = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (s + FILETIME_UNIX_OFFSET) * FILETIME_PER_SECOND
}

fn getrandom(buf: &mut [u8]) -> std::io::Result<()> {
    let mut done = 0;
    while done < buf.len() {
        let rest = buf.get_mut(done..).unwrap_or(&mut []);
        // SAFETY: a valid writable buffer of the given length.
        let n = unsafe { libc::getrandom(rest.as_mut_ptr().cast(), rest.len(), 0) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e);
        }
        done += n as usize;
    }
    Ok(())
}

/// What the guest is shown instead of the three metadata regions, and the
/// key file that opens it.
pub struct Substitute {
    /// One 64 KiB region: served at all three metadata offsets.
    pub region: Vec<u8>,
    /// The `.BEK` file.
    pub bek: Vec<u8>,
    /// Its name as Windows writes it: `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX.BEK`.
    pub bek_name: String,
}

/// The protector id as Windows prints it (upper case, no braces).
pub fn guid_text(id: &[u8; ID_LEN]) -> String {
    let t = paguro_core::guid::Guid(*id).to_text();
    String::from_utf8_lossy(&t).to_ascii_uppercase()
}

fn put16(b: &mut Vec<u8>, v: u16) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut Vec<u8>, v: u64) {
    b.extend_from_slice(&v.to_le_bytes());
}

fn set(b: &mut [u8], at: usize, v: &[u8]) {
    if let Some(d) = b.get_mut(at..at + v.len()) {
        d.copy_from_slice(v);
    }
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}
fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// One FVE entry.
fn fve_entry(
    entry_type: u16,
    value_type: u16,
    version: u16,
    data: &[u8],
) -> Result<Vec<u8>, FveError> {
    let size = u16::try_from(ENTRY_HEADER + data.len()).map_err(|_| FveError::TooLarge)?;
    let mut e = Vec::with_capacity(usize::from(size));
    put16(&mut e, size);
    put16(&mut e, entry_type);
    put16(&mut e, value_type);
    put16(&mut e, version);
    e.extend_from_slice(data);
    Ok(e)
}

/// A KEY entry: `method | key`.
fn key_entry(entry_type: u16, version: u16, method: u32, key: &[u8]) -> Result<Vec<u8>, FveError> {
    let mut d = method.to_le_bytes().to_vec();
    d.extend_from_slice(key);
    let e = fve_entry(entry_type, value::KEY, version, &d);
    zeroize::Zeroize::zeroize(&mut d);
    e
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn nonce(time: u64, counter: u32) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    set(&mut n, 0, &time.to_le_bytes());
    set(&mut n, NONCE_TIME_LEN, &counter.to_le_bytes());
    n
}

/// An AES_CCM entry: `nonce | tag | AES-CCM(key, plain)`.
fn ccm_entry(key: &[u8; KEY_LEN], n: [u8; NONCE_LEN], plain: &[u8]) -> Result<Vec<u8>, FveError> {
    let mut ct = plain.to_vec();
    let tag = ccm_wrap(key, &n, &mut ct);
    let mut d = n.to_vec();
    d.extend_from_slice(&tag);
    d.extend_from_slice(&ct);
    fve_entry(entry::PROPERTY, value::AES_CCM, 1, &d)
}

/// The new protector's VMK entry (the module comment's layout).
fn external_key_vmk_entry(vmk: &Vmk, p: &Params, counter: u32) -> Result<Vec<u8>, FveError> {
    let mut nested = fve_entry(entry::PROPERTY, value::UNICODE, 1, &utf16z(DESCRIPTION))?;
    let mut kext_plain = key_entry(entry::PROPERTY, 1, METHOD_EXTERNAL_KEY, &p.ext_key)?;
    let mut use_key = METHOD_EXTERNAL_KEY.to_le_bytes().to_vec();
    use_key.extend(ccm_entry(vmk, nonce(p.time, counter), &kext_plain)?);
    zeroize::Zeroize::zeroize(&mut kext_plain);
    nested.extend(fve_entry(entry::PROPERTY, value::USE_KEY, 1, &use_key)?);
    let mut vmk_plain = key_entry(ENTRY_TYPE_EXTERNAL_VMK, 0, METHOD_VMK, vmk)?;
    nested.extend(ccm_entry(
        &p.ext_key,
        nonce(p.time, counter + 1),
        &vmk_plain,
    )?);
    zeroize::Zeroize::zeroize(&mut vmk_plain);
    let mut d = p.id.to_vec();
    put64(&mut d, p.time);
    put16(&mut d, 0);
    put16(&mut d, PROTECTION_EXTERNAL_KEY);
    d.extend(nested);
    fve_entry(entry::VMK, value::VMK, 1, &d)
}

/// Offsets of the entries in a block's entry list (bounded, as parsed by
/// `Metadata::parse` before this runs).
fn entry_offsets(list: &[u8]) -> Vec<(usize, u16)> {
    let mut out = Vec::new();
    let mut at = 0;
    while let (Some(size), Some(ty)) = (le16(list, at), le16(list, at + 2)) {
        let size = usize::from(size);
        if size < ENTRY_HEADER || at + size > list.len() {
            break;
        }
        out.push((at, ty));
        at += size;
    }
    out
}

/// Build the substitute from the volume's first sector and its three
/// metadata regions (64 KiB each, as read from the raw partition).
pub fn substitute(
    header_sector: &[u8],
    copies: [&[u8]; 3],
    vmk: &Vmk,
    p: &Params,
) -> Result<Substitute, FveError> {
    let hdr = parse_volume_header(header_sector).map_err(FveError::Metadata)?;
    let block = cross_check(copies, &hdr).map_err(FveError::Metadata)?;
    let m = Metadata::parse(block).map_err(FveError::Metadata)?;
    match unlock_fvek(&m, vmk) {
        Ok(Some(_)) => {}
        Ok(None) => return Err(FveError::WrongVmk),
        Err(e) => return Err(FveError::Metadata(e)),
    }
    if m.protectors().any(|q| q.id == p.id) {
        return Err(FveError::DuplicateId);
    }
    let raw = block.raw;
    let region0 = copies[0];
    let mhdr = raw
        .get(BLOCK_HEADER..BLOCK_HEADER + METADATA_HEADER)
        .ok_or(FveError::TooLarge)?;
    let counter = le32(mhdr, MH_NEXT_NONCE).ok_or(FveError::TooLarge)?;
    if counter.checked_add(NONCES_NEEDED).is_none() {
        return Err(FveError::TooLarge);
    }

    // The entry list, the new VMK entry before the volume-header entry
    // (where Windows puts it), or at the end.
    let list = block.entries;
    let insert_at = entry_offsets(list)
        .into_iter()
        .find(|&(_, ty)| ty == entry::VOLUME_HEADER_BLOCK)
        .map_or(list.len(), |(at, _)| at);
    let new_vmk = external_key_vmk_entry(vmk, p, counter)?;
    let mut entries = list.get(..insert_at).ok_or(FveError::TooLarge)?.to_vec();
    entries.extend_from_slice(&new_vmk);
    entries.extend_from_slice(list.get(insert_at..).ok_or(FveError::TooLarge)?);

    // Headers: sizes, the nonce counter; everything else as it was.
    let msize = u32::try_from(METADATA_HEADER + entries.len()).map_err(|_| FveError::TooLarge)?;
    let block_len = (BLOCK_HEADER + msize as usize).div_ceil(BLOCK_SIZE_UNIT) * BLOCK_SIZE_UNIT;
    let block_units = u16::try_from(block_len / BLOCK_SIZE_UNIT).map_err(|_| FveError::TooLarge)?;
    let mut nb = raw
        .get(..BLOCK_HEADER + METADATA_HEADER)
        .ok_or(FveError::TooLarge)?
        .to_vec();
    set(&mut nb, BLOCK_SIZE_AT, &block_units.to_le_bytes());
    set(&mut nb, BLOCK_HEADER + MH_SIZE, &msize.to_le_bytes());
    set(&mut nb, BLOCK_HEADER + MH_SIZE_COPY, &msize.to_le_bytes());
    set(
        &mut nb,
        BLOCK_HEADER + MH_NEXT_NONCE,
        &(counter + NONCES_NEEDED).to_le_bytes(),
    );
    nb.extend_from_slice(&entries);
    nb.resize(block_len, 0);

    // Validation: the same version as the volume's; CRC-32, and (version
    // 2) the block's SHA-256 wrapped under the VMK.
    let vver = le16(region0, raw.len() + 2).ok_or(FveError::TooLarge)?;
    let region_len = REGION_SIZE as usize;
    let vsize = u16::try_from(
        region_len
            .checked_sub(block_len)
            .ok_or(FveError::TooLarge)?,
    )
    .map_err(|_| FveError::TooLarge)?;
    let mut region = nb.clone();
    put16(&mut region, vsize);
    put16(&mut region, vver);
    put32(&mut region, bde::crc32(&nb));
    if vver == VALIDATION_WITH_HASH {
        let digest: [u8; 32] = Sha256::digest(&nb).into();
        let plain = key_entry(entry::PROPERTY, 0, METHOD_VALIDATION, &digest)?;
        region.extend(ccm_entry(vmk, nonce(p.time, counter + 2), &plain)?);
    }
    if region.len() > region_len {
        return Err(FveError::TooLarge);
    }
    region.resize(region_len, 0);

    let volume_id: [u8; ID_LEN] = mhdr
        .get(MH_ID..MH_ID + ID_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(FveError::TooLarge)?;
    let bek = bek_file(&volume_id, p)?;

    // Round trip through the reader the loader uses, before anything is
    // served.
    let copies = [region.as_slice(); 3];
    let b2 = cross_check(copies, &hdr).map_err(FveError::RoundTrip)?;
    let m2 = Metadata::parse(b2).map_err(FveError::RoundTrip)?;
    let sk = parse_startup_key(&bek).map_err(FveError::RoundTrip)?;
    let got = vmk_from_startup_key(&m2, &sk).map_err(FveError::RoundTrip)?;
    if got.as_ref() != Some(vmk) {
        return Err(FveError::RoundTripVmk);
    }
    match unlock_fvek(&m2, vmk) {
        Ok(Some(_)) => {}
        _ => return Err(FveError::RoundTripVmk),
    }
    Ok(Substitute {
        region,
        bek,
        bek_name: format!("{}.BEK", guid_text(&p.id)),
    })
}

/// The `.BEK` file (the module comment's layout).
fn bek_file(volume_id: &[u8; ID_LEN], p: &Params) -> Result<Vec<u8>, FveError> {
    let mut d = p.id.to_vec();
    put64(&mut d, p.time);
    d.extend(fve_entry(
        entry::PROPERTY,
        value::UNICODE,
        1,
        &utf16z(DESCRIPTION),
    )?);
    d.extend(fve_entry(
        BEK_ENTRY_VOLUME_ID,
        BEK_VALUE_VOLUME_ID,
        1,
        volume_id,
    )?);
    d.extend(key_entry(
        entry::PROPERTY,
        1,
        METHOD_EXTERNAL_KEY,
        &p.ext_key,
    )?);
    let body = fve_entry(entry::STARTUP_KEY, value::EXTERNAL_KEY, 1, &d)?;
    zeroize::Zeroize::zeroize(&mut d);
    let total = u32::try_from(METADATA_HEADER + body.len()).map_err(|_| FveError::TooLarge)?;
    let mut f = vec![0u8; METADATA_HEADER];
    set(&mut f, MH_SIZE, &total.to_le_bytes());
    set(&mut f, MH_VERSION, &METADATA_VERSION.to_le_bytes());
    set(
        &mut f,
        MH_HEADER_SIZE,
        &(METADATA_HEADER as u32).to_le_bytes(),
    );
    set(&mut f, MH_SIZE_COPY, &total.to_le_bytes());
    set(&mut f, MH_ID, &p.id);
    set(&mut f, MH_NEXT_NONCE, &BEK_NEXT_NONCE.to_le_bytes());
    set(&mut f, MH_ENCRYPTION, &0u32.to_le_bytes());
    set(&mut f, MH_CREATED, &p.time.to_le_bytes());
    f.extend(body);
    Ok(f)
}

/// Every sector BitLocker owns, as `(start, len)` 512-byte sectors of the
/// partition, sorted: the volume header, the relocated boot sectors, the
/// three metadata regions and Windows 10+'s further region
/// (`Layout::reserved_ranges`).
pub fn owned_ranges(layout: &Layout) -> Vec<(u64, u64)> {
    let mut r: Vec<(u64, u64)> = layout.reserved_ranges().collect();
    r.sort_unstable();
    r
}

/// The per-session buffer the owned ranges are served from, packed in
/// [`owned_ranges`] order: the substitute region at each metadata offset,
/// the volume's own bytes everywhere else (`read(start, len)` reads 512-byte
/// sectors of the raw partition).
pub fn owned_buffer<E>(
    owned: &[(u64, u64)],
    metadata_offsets: [u64; 3],
    region: &[u8],
    mut read: impl FnMut(u64, u64) -> Result<Vec<u8>, E>,
) -> Result<Vec<u8>, E> {
    let sector = paguro_core::disk::SECTOR;
    let mut out = Vec::new();
    for &(start, len) in owned {
        if metadata_offsets.contains(&(start * sector)) && len * sector == region.len() as u64 {
            out.extend_from_slice(region);
        } else {
            out.extend(read(start, len)?);
        }
    }
    Ok(out)
}

/// Where a volume-relative 512-byte sector of the owned set lives in the
/// buffer, for the ranges in [`owned_ranges`] order.
pub fn buffer_offsets(owned: &[(u64, u64)]) -> Vec<(u64, u64, u64)> {
    let mut at = 0;
    owned
        .iter()
        .map(|&(s, l)| {
            let r = (s, l, at);
            at += l;
            r
        })
        .collect()
}

/// Size of one KEY value's fixed part, for callers that size buffers.
pub const KEY_VALUE_HEADER: usize = size_of::<u32>();

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use paguro_boot::bde::vmk_from_recovery;

    /// A volume from the harness's writer shape: header, three metadata
    /// regions, a recovery protector — built here with the same
    /// primitives so the test needs no files.
    pub(crate) struct Vol {
        pub header: Vec<u8>,
        pub region: Vec<u8>,
        pub vmk: Vmk,
        pub recovery: [u8; 16],
    }

    fn ccm(key: &[u8; 32], counter: u32, plain: &[u8]) -> Vec<u8> {
        ccm_entry(key, nonce(0x01dc_0000_0000_0000, counter), plain).unwrap()
    }

    /// Windows' order: FVEK backup, description, VMK(s), FVEK, volume
    /// header entry (with the Windows 10+ trailing structure).
    pub(crate) fn volume(md: [u64; 3], validation_v2: bool) -> Vol {
        let vmk = [0x11u8; 32];
        let fvek = [0x22u8; 32];
        let recovery = [0x33u8; 16];
        let salt = [0x44u8; 16];
        let mut entries =
            fve_entry(entry::DESCRIPTION, value::UNICODE, 1, &utf16z("TEST")).unwrap();
        // recovery-password protector
        let h: [u8; 32] = Sha256::digest(recovery).into();
        let k = paguro_crypto::bitlocker_stretch(&h, &salt, paguro_crypto::STRETCH_ITERATIONS);
        let mut st = 0x1000u32.to_le_bytes().to_vec();
        st.extend(salt);
        let mut nested = fve_entry(entry::PROPERTY, value::STRETCH_KEY, 1, &st).unwrap();
        nested.extend(ccm(&k, 1, &key_entry(0, 0, METHOD_VMK, &vmk).unwrap()));
        let mut v = [0x55u8; 16].to_vec();
        put64(&mut v, 1);
        put16(&mut v, 0);
        put16(&mut v, bde::protection::RECOVERY_PASSWORD);
        v.extend(nested);
        entries.extend(fve_entry(entry::VMK, value::VMK, 1, &v).unwrap());
        let mut fk = 0x8004u32.to_le_bytes().to_vec();
        fk.extend(fvek);
        entries.extend(
            fve_entry(
                entry::FVEK,
                value::AES_CCM,
                1,
                &ccm(&vmk, 2, &fve_entry(0, value::KEY, 0, &fk).unwrap())[ENTRY_HEADER..],
            )
            .unwrap(),
        );
        let mut vhb = 0x40000u64.to_le_bytes().to_vec();
        put64(&mut vhb, 0x2000);
        entries.extend(
            fve_entry(entry::VOLUME_HEADER_BLOCK, value::OFFSET_AND_SIZE, 1, &vhb).unwrap(),
        );
        let msize = (METADATA_HEADER + entries.len()) as u32;
        let blen = (BLOCK_HEADER + msize as usize).div_ceil(16) * 16;
        let mut b = b"-FVE-FS-".to_vec();
        put16(&mut b, (blen / 16) as u16);
        put16(&mut b, 2);
        put16(&mut b, 4);
        put16(&mut b, 4);
        put64(&mut b, 8 << 20);
        put32(&mut b, 0);
        put32(&mut b, 16);
        for m in md {
            put64(&mut b, m);
        }
        put64(&mut b, 0x40000);
        for x in [msize, 1, 48, msize] {
            put32(&mut b, x);
        }
        b.extend([0x66u8; 16]);
        put32(&mut b, 3);
        put16(&mut b, 0x8004);
        put16(&mut b, 0);
        put64(&mut b, 7);
        b.extend(entries);
        b.resize(blen, 0);
        let mut region = b.clone();
        put16(&mut region, (0x10000 - blen) as u16);
        put16(&mut region, if validation_v2 { 2 } else { 1 });
        put32(&mut region, bde::crc32(&b));
        if validation_v2 {
            let d: [u8; 32] = Sha256::digest(&b).into();
            region.extend(ccm(
                &vmk,
                3,
                &key_entry(0, 0, METHOD_VALIDATION, &d).unwrap(),
            ));
        }
        region.resize(0x10000, 0);
        let mut header = vec![0u8; 512];
        header[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        header[3..11].copy_from_slice(b"-FVE-FS-");
        header[11..13].copy_from_slice(&512u16.to_le_bytes());
        header[160..176].copy_from_slice(&bde::GUID_NORMAL);
        for (i, m) in md.iter().enumerate() {
            header[176 + 8 * i..184 + 8 * i].copy_from_slice(&m.to_le_bytes());
        }
        header[510..].copy_from_slice(&[0x55, 0xaa]);
        Vol {
            header,
            region,
            vmk,
            recovery,
        }
    }

    fn params(seed: u8) -> Params {
        Params {
            id: [seed; 16],
            ext_key: [seed.wrapping_add(1); 32],
            time: 0x01dd_4d32_4985_28f0,
        }
    }

    #[test]
    fn substitute_round_trips() {
        for v2 in [true, false] {
            let v = volume([0x10000, 0x20000, 0x30000], v2);
            let s = substitute(&v.header, [&v.region; 3], &v.vmk, &params(9)).unwrap();
            assert_eq!(s.region.len(), 0x10000);
            let hdr = parse_volume_header(&v.header).unwrap();
            let b = cross_check([&s.region; 3], &hdr).unwrap();
            let m = Metadata::parse(b).unwrap();
            // the old protector still opens it
            let old = vmk_from_recovery(&m, &v.recovery).unwrap();
            assert_eq!(old, Some(v.vmk));
            // the new one, through the .BEK
            let sk = parse_startup_key(&s.bek).unwrap();
            assert_eq!(sk.id, [9; 16]);
            assert_eq!(sk.key, [10; 32]);
            assert_eq!(vmk_from_startup_key(&m, &sk).unwrap(), Some(v.vmk));
            assert!(unlock_fvek(&m, &v.vmk).unwrap().is_some());
            assert_eq!(s.bek_name, "09090909-0909-0909-0909-090909090909.BEK");
            // inserted before the volume-header entry, nonce counter +3
            let kinds: Vec<u16> = entry_offsets(b.entries).iter().map(|e| e.1).collect();
            assert_eq!(kinds, [7, 2, 3, 2, 0xf]);
            assert_eq!(b.next_nonce, 6);
            // the block's other fields are untouched
            let old_b = cross_check([&v.region; 3], &hdr).unwrap();
            assert_eq!(b.raw[..BLOCK_SIZE_AT], old_b.raw[..BLOCK_SIZE_AT]);
            assert_eq!(b.raw[10..64], old_b.raw[10..64]);
            assert_eq!(b.volume_id, old_b.volume_id);
            assert_eq!(b.validation.is_some(), v2);
        }
    }

    #[test]
    fn bek_matches_the_windows_shape() {
        let v = volume([0x10000, 0x20000, 0x30000], true);
        let s = substitute(&v.header, [&v.region; 3], &v.vmk, &params(1)).unwrap();
        let b = &s.bek;
        // header: size, version, header size, size copy, id, nonce 1, 0
        assert_eq!(le32(b, 0), Some(b.len() as u32));
        assert_eq!(le32(b, 12), Some(b.len() as u32));
        assert_eq!(&b[16..32], &[1u8; 16]);
        assert_eq!(le32(b, 32), Some(1));
        assert_eq!(le32(b, 36), Some(0));
        // the one entry, 0x84 bytes as in Windows' file
        assert_eq!(
            (le16(b, 48), le16(b, 50), le16(b, 52)),
            (Some(0x84), Some(6), Some(9))
        );
        assert_eq!(b.len(), 0xb4);
        // the volume identifier entry
        assert_eq!(
            &b[48 + 8 + 24 + 32..48 + 8 + 24 + 32 + 8],
            &[0x18, 0, 0x19, 0, 0x17, 0, 1, 0]
        );
        assert_eq!(&b[48 + 8 + 24 + 32 + 8..48 + 8 + 24 + 32 + 24], &[0x66; 16]);
    }

    /// Against a real Windows volume, when one is at hand (never
    /// committed): `PAGURO_VM_REF` holds `hdr-orig.bin`, `md-orig-{0,1,2}.bin`
    /// (the header and the three 64 KiB regions), `recovery-password.txt`,
    /// and `md-sk-0.bin`: the same volume after Windows added its own
    /// external key, whose entry must have the same shape as ours.
    #[test]
    fn windows_volume() {
        let Ok(dir) = std::env::var("PAGURO_VM_REF") else {
            return;
        };
        let rd = |n: &str| std::fs::read(format!("{dir}/{n}")).unwrap();
        let hdr = rd("hdr-orig.bin");
        let md: Vec<Vec<u8>> = (0..3).map(|i| rd(&format!("md-orig-{i}.bin"))).collect();
        let pw = String::from_utf8(rd("recovery-password.txt")).unwrap();
        let key = paguro_boot::volume::parse_recovery_password(pw.trim().as_bytes()).unwrap();
        let h = parse_volume_header(&hdr).unwrap();
        let m = Metadata::parse(cross_check([&md[0], &md[1], &md[2]], &h).unwrap()).unwrap();
        let vmk = vmk_from_recovery(&m, &key).unwrap().unwrap();
        let s = substitute(&hdr, [&md[0], &md[1], &md[2]], &vmk, &params(0x5a)).unwrap();
        let ours = Metadata::parse(cross_check([&s.region; 3], &h).unwrap()).unwrap();
        let win_region = rd("md-sk-0.bin");
        let win = Metadata::parse(cross_check([&win_region; 3], &h).unwrap()).unwrap();
        let shape = |m: &Metadata<'_>| -> Vec<(usize, u16)> {
            entry_offsets(m.block.entries)
                .iter()
                .map(|&(at, ty)| (le16(m.block.entries, at).unwrap() as usize, ty))
                .collect()
        };
        assert_eq!(shape(&ours), shape(&win));
        assert_eq!(ours.block.raw.len(), win.block.raw.len());
        assert_eq!(ours.block.next_nonce, win.block.next_nonce);
    }

    #[test]
    fn refusals() {
        let v = volume([0x10000, 0x20000, 0x30000], true);
        assert!(matches!(
            substitute(&v.header, [&v.region; 3], &[0u8; 32], &params(2)),
            Err(FveError::WrongVmk)
        ));
        assert!(matches!(
            substitute(&v.header, [&v.region; 3], &v.vmk, &params(0x55)),
            Err(FveError::DuplicateId)
        ));
        let mut bad = v.region.clone();
        bad[100] ^= 1;
        assert!(matches!(
            substitute(&v.header, [&v.region, &bad, &v.region], &v.vmk, &params(2)),
            Err(FveError::Metadata(_))
        ));
    }

    #[test]
    fn buffer_packs_owned_ranges() {
        let owned = [(0, 16), (128, 128), (512, 16)];
        let region = vec![0xabu8; 0x10000];
        let buf = owned_buffer(&owned, [0x10000, 0x70000, 0x90000], &region, |s, l| {
            Ok::<_, ()>(vec![s as u8; (l * 512) as usize])
        })
        .unwrap();
        assert_eq!(buf.len(), (16 + 128 + 16) * 512);
        assert!(buf[..16 * 512].iter().all(|&b| b == 0));
        assert!(buf[16 * 512..144 * 512].iter().all(|&b| b == 0xab));
        assert!(buf[144 * 512..].iter().all(|&b| b == 0));
        assert_eq!(
            buffer_offsets(&owned),
            vec![(0, 16, 0), (128, 128, 16), (512, 16, 144)]
        );
    }
}
