//! The loader → initrd handoff (INTERFACES.md §8): a header and TLV records in
//! one `EfiRuntimeServicesData` allocation, published as a configuration table.
//!
//! ```text
//! header   magic "PGRHOF\0\x01" | total_len u32 | record_count u16 | reserved u16
//! record   type u16 | len u32 | value[len]        (no padding)
//! ```
//!
//! `total_len` counts the whole blob, header included; the decoder requires the
//! input to be exactly that long. Every value has a fixed or self-describing
//! length that must match `len` exactly. Unknown types, duplicates of
//! at-most-once types, missing required types and unknown state flags are all
//! refused; the decoder never returns a partial result.
//!
//! [`encode`] writes records in canonical order (by type, images in order), so
//! `decode(encode(h)) == h` for every valid `h` (property-tested).

use crate::bytes::{Full, Reader, Writer};
use crate::config::check_name;
use crate::guid::Guid;
use crate::seal::{self, Kind, Seal, SealError};

pub const MAGIC: &[u8; 8] = b"PGRHOF\x00\x01";
pub const HEADER_LEN: usize = 16;
/// Hard cap on the whole blob: room for a maximal 64 KiB `paguro.ini` in `CONFIG` plus every other record.
pub const MAX_LEN: usize = 96 * 1024;
pub const MAX_IMAGES: usize = 16;
pub const MAX_FVEK_KEY: usize = 64;
/// PCRs are 0..=23.
pub const PCR_COUNT: u32 = 24;

pub mod rtype {
    pub const VOLUME: u16 = 1;
    pub const VMK: u16 = 2;
    pub const FVEK: u16 = 3;
    pub const FVE_LAYOUT: u16 = 4;
    pub const B: u16 = 5;
    pub const PCRS: u16 = 6;
    pub const CONFIG: u16 = 7;
    pub const IMAGE: u16 = 8;
    pub const STATE: u16 = 9;
    pub const RUNG: u16 = 10;
    pub const PROVISION: u16 = 11;
}

pub mod state {
    pub const HIBERNATED: u32 = 1;
    pub const DIRTY: u32 = 2;
    pub const CONFIG_UNVERIFIED: u32 = 4;
    pub const RECOVERY_PATH: u32 = 8;
    pub const ALL: u32 = HIBERNATED | DIRTY | CONFIG_UNVERIFIED | RECOVERY_PATH;
}

/// Which protector produced the VMK (the `RUNG` record).
///
/// Values 1–6 are INTERFACES.md §8. `ClearKey` (7) and `Unencrypted` (8) are
/// paguro-boot additions: a clear-key volume unlocks without any rung, and an
/// unencrypted volume has none to name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rung {
    Tpm = 1,
    SetupTpm = 2,
    Passphrase = 3,
    RecoveryKey = 4,
    PinBypass = 5,
    Bootstrap = 6,
    ClearKey = 7,
    Unencrypted = 8,
}

impl Rung {
    pub const fn from_u8(v: u8) -> Option<Rung> {
        Some(match v {
            1 => Rung::Tpm,
            2 => Rung::SetupTpm,
            3 => Rung::Passphrase,
            4 => Rung::RecoveryKey,
            5 => Rung::PinBypass,
            6 => Rung::Bootstrap,
            7 => Rung::ClearKey,
            8 => Rung::Unencrypted,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Volume {
    pub partition: Guid,
    pub first_lba: u64,
    pub sectors: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fvek<'a> {
    /// BitLocker encryption method id (e.g. `0x8004` XTS-AES-128).
    pub cipher: u16,
    pub key: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FveLayout {
    pub metadata_offsets: [u64; 3],
    pub region_size: u64,
    pub boot_sector_reloc_offset: u64,
    pub boot_sector_reloc_sectors: u32,
    pub encrypted_size: u64,
}

/// SHA-256 PCR values: `values` holds 32 bytes per set bit of `mask`,
/// ascending PCR order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pcrs<'a> {
    pub mask: u32,
    pub values: &'a [u8],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImageId<'a> {
    pub name: &'a str,
    pub mft_record: u64,
    pub mft_seq: u16,
}

impl ImageId<'_> {
    pub const EMPTY: ImageId<'static> = ImageId {
        name: "",
        mft_record: 0,
        mft_seq: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Handoff<'a> {
    pub volume: Volume,
    pub vmk: Option<&'a [u8; 32]>,
    pub fvek: Option<Fvek<'a>>,
    pub fve_layout: Option<FveLayout>,
    pub b: &'a [u8; 32],
    pub pcrs: Pcrs<'a>,
    pub config: Option<&'a [u8]>,
    pub images: [ImageId<'a>; MAX_IMAGES],
    pub image_count: usize,
    pub state: u32,
    pub rung: Rung,
    /// A new `tpm` seal body (INTERFACES.md §4) on a provisioning boot.
    pub provision: Option<Seal<'a>>,
}

impl<'a> Handoff<'a> {
    pub fn images(&self) -> &[ImageId<'a>] {
        self.images.get(..self.image_count).unwrap_or(&[])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    TooLarge,
    Truncated,
    BadMagic,
    /// `total_len` differs from the input length.
    LengthMismatch,
    ReservedNonZero,
    /// Fewer or more records than `record_count`.
    CountMismatch,
    UnknownType(u16),
    Duplicate(u16),
    Missing(u16),
    /// A value's length does not match what its type requires.
    BadLength(u16),
    /// A value is out of range (bad image name, PCR mask, rung, key length…).
    BadValue(u16),
    UnknownStateFlags,
    TooManyImages,
    Provision(SealError),
}

fn short(_: crate::bytes::Short) -> HandoffError {
    HandoffError::Truncated
}

fn pcr_value_len(mask: u32) -> Option<usize> {
    if mask == 0 || mask >> PCR_COUNT != 0 {
        return None;
    }
    Some(mask.count_ones() as usize * 32)
}

/// Decode and validate a whole handoff blob.
pub fn decode(blob: &[u8]) -> Result<Handoff<'_>, HandoffError> {
    if blob.len() > MAX_LEN {
        return Err(HandoffError::TooLarge);
    }
    let mut r = Reader::new(blob);
    if r.array::<8>().map_err(short)? != MAGIC {
        return Err(HandoffError::BadMagic);
    }
    let total = r.u32_le().map_err(short)?;
    let count = r.u16_le().map_err(short)?;
    if r.u16_le().map_err(short)? != 0 {
        return Err(HandoffError::ReservedNonZero);
    }
    if total as usize != blob.len() {
        return Err(HandoffError::LengthMismatch);
    }

    let mut seen = 0u16; // bit per type
    let mut volume = None;
    let mut vmk = None;
    let mut fvek = None;
    let mut fve_layout = None;
    let mut b = None;
    let mut pcrs = None;
    let mut config = None;
    let mut images = [ImageId::EMPTY; MAX_IMAGES];
    let mut image_count = 0usize;
    let mut st = None;
    let mut rung = None;
    let mut provision = None;

    let mut n = 0u16;
    while !r.is_empty() {
        if n == count {
            return Err(HandoffError::CountMismatch);
        }
        n += 1;
        let t = r.u16_le().map_err(short)?;
        let len = r.u32_le().map_err(short)? as usize;
        let value = r.take(len).map_err(short)?;
        if !(rtype::VOLUME..=rtype::PROVISION).contains(&t) {
            return Err(HandoffError::UnknownType(t));
        }
        let bit = 1u16 << t;
        if t != rtype::IMAGE {
            if seen & bit != 0 {
                return Err(HandoffError::Duplicate(t));
            }
            seen |= bit;
        }
        let bad_len = HandoffError::BadLength(t);
        let fixed = |want: usize| if len == want { Ok(()) } else { Err(bad_len) };
        let mut v = Reader::new(value);
        match t {
            rtype::VOLUME => {
                fixed(32)?;
                volume = Some(Volume {
                    partition: Guid(*v.array().map_err(short)?),
                    first_lba: v.u64_le().map_err(short)?,
                    sectors: v.u64_le().map_err(short)?,
                });
            }
            rtype::VMK => {
                fixed(32)?;
                vmk = Some(v.array::<32>().map_err(short)?);
            }
            rtype::FVEK => {
                let cipher = v.u16_le().map_err(|_| bad_len)?;
                let klen = usize::from(v.u16_le().map_err(|_| bad_len)?);
                if klen == 0 || klen > MAX_FVEK_KEY {
                    return Err(HandoffError::BadValue(t));
                }
                if v.remaining() != klen {
                    return Err(bad_len);
                }
                fvek = Some(Fvek {
                    cipher,
                    key: v.rest(),
                });
            }
            rtype::FVE_LAYOUT => {
                fixed(52)?;
                fve_layout = Some(FveLayout {
                    metadata_offsets: [
                        v.u64_le().map_err(short)?,
                        v.u64_le().map_err(short)?,
                        v.u64_le().map_err(short)?,
                    ],
                    region_size: v.u64_le().map_err(short)?,
                    boot_sector_reloc_offset: v.u64_le().map_err(short)?,
                    boot_sector_reloc_sectors: v.u32_le().map_err(short)?,
                    encrypted_size: v.u64_le().map_err(short)?,
                });
            }
            rtype::B => {
                fixed(32)?;
                b = Some(v.array::<32>().map_err(short)?);
            }
            rtype::PCRS => {
                let mask = v.u32_le().map_err(|_| bad_len)?;
                let want = pcr_value_len(mask).ok_or(HandoffError::BadValue(t))?;
                if v.remaining() != want {
                    return Err(bad_len);
                }
                pcrs = Some(Pcrs {
                    mask,
                    values: v.rest(),
                });
            }
            rtype::CONFIG => config = Some(value),
            rtype::IMAGE => {
                let nl = usize::from(v.u8().map_err(|_| bad_len)?);
                if len != 1 + nl + 10 {
                    return Err(bad_len);
                }
                let name = core::str::from_utf8(v.take(nl).map_err(short)?)
                    .map_err(|_| HandoffError::BadValue(t))?;
                if !check_name(name) {
                    return Err(HandoffError::BadValue(t));
                }
                let slot = images
                    .get_mut(image_count)
                    .ok_or(HandoffError::TooManyImages)?;
                *slot = ImageId {
                    name,
                    mft_record: v.u64_le().map_err(short)?,
                    mft_seq: v.u16_le().map_err(short)?,
                };
                image_count += 1;
            }
            rtype::STATE => {
                fixed(4)?;
                let s = v.u32_le().map_err(short)?;
                if s & !state::ALL != 0 {
                    return Err(HandoffError::UnknownStateFlags);
                }
                st = Some(s);
            }
            rtype::RUNG => {
                fixed(1)?;
                rung =
                    Some(Rung::from_u8(v.u8().map_err(short)?).ok_or(HandoffError::BadValue(t))?);
            }
            _ => {
                // rtype::PROVISION, the only type left in range.
                provision =
                    Some(seal::read_body(Kind::Tpm, value).map_err(HandoffError::Provision)?);
            }
        }
    }
    if n != count {
        return Err(HandoffError::CountMismatch);
    }
    if image_count == 0 {
        return Err(HandoffError::Missing(rtype::IMAGE));
    }
    Ok(Handoff {
        volume: volume.ok_or(HandoffError::Missing(rtype::VOLUME))?,
        vmk,
        fvek,
        fve_layout,
        b: b.ok_or(HandoffError::Missing(rtype::B))?,
        pcrs: pcrs.ok_or(HandoffError::Missing(rtype::PCRS))?,
        config,
        images,
        image_count,
        state: st.ok_or(HandoffError::Missing(rtype::STATE))?,
        rung: rung.ok_or(HandoffError::Missing(rtype::RUNG))?,
        provision,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// Output buffer (or [`MAX_LEN`]) exceeded — e.g. a `CONFIG` too large to
    /// travel beside the other records.
    Full,
    /// The handoff would not decode (bad name, mask, key length, no images…).
    Invalid,
}

impl From<Full> for EncodeError {
    fn from(_: Full) -> Self {
        EncodeError::Full
    }
}

fn record(
    w: &mut Writer<'_>,
    t: u16,
    body: impl FnOnce(&mut Writer<'_>) -> Result<(), Full>,
) -> Result<(), EncodeError> {
    w.u16_le(t)?;
    let len_at = w.len();
    w.u32_le(0)?;
    let start = w.len();
    body(w)?;
    let len = u32::try_from(w.len() - start).map_err(|_| EncodeError::Full)?;
    w.patch(len_at, &len.to_le_bytes())?;
    Ok(())
}

/// Encode canonically into `out`; returns the blob length.
pub fn encode(h: &Handoff<'_>, out: &mut [u8]) -> Result<usize, EncodeError> {
    if h.image_count == 0 || h.image_count > MAX_IMAGES {
        return Err(EncodeError::Invalid);
    }
    if h.images().iter().any(|i| !check_name(i.name)) {
        return Err(EncodeError::Invalid);
    }
    if pcr_value_len(h.pcrs.mask) != Some(h.pcrs.values.len()) {
        return Err(EncodeError::Invalid);
    }
    if h.state & !state::ALL != 0 {
        return Err(EncodeError::Invalid);
    }
    if let Some(f) = h.fvek {
        if f.key.is_empty() || f.key.len() > MAX_FVEK_KEY {
            return Err(EncodeError::Invalid);
        }
    }
    if let Some(p) = h.provision {
        if p.kind != Kind::Tpm {
            return Err(EncodeError::Invalid);
        }
    }
    let cap = out.len().min(MAX_LEN);
    let mut w = Writer::new(out.get_mut(..cap).ok_or(EncodeError::Full)?);
    w.put(MAGIC)?;
    w.u32_le(0)?;
    w.u16_le(0)?;
    w.u16_le(0)?;
    let mut count = 0u16;

    record(&mut w, rtype::VOLUME, |w| {
        w.put(&h.volume.partition.0)?;
        w.u64_le(h.volume.first_lba)?;
        w.u64_le(h.volume.sectors)
    })?;
    count += 1;
    if let Some(vmk) = h.vmk {
        record(&mut w, rtype::VMK, |w| w.put(vmk))?;
        count += 1;
    }
    if let Some(f) = h.fvek {
        record(&mut w, rtype::FVEK, |w| {
            w.u16_le(f.cipher)?;
            w.u16_le(u16::try_from(f.key.len()).map_err(|_| Full)?)?;
            w.put(f.key)
        })?;
        count += 1;
    }
    if let Some(l) = h.fve_layout {
        record(&mut w, rtype::FVE_LAYOUT, |w| {
            for o in l.metadata_offsets {
                w.u64_le(o)?;
            }
            w.u64_le(l.region_size)?;
            w.u64_le(l.boot_sector_reloc_offset)?;
            w.u32_le(l.boot_sector_reloc_sectors)?;
            w.u64_le(l.encrypted_size)
        })?;
        count += 1;
    }
    record(&mut w, rtype::B, |w| w.put(h.b))?;
    record(&mut w, rtype::PCRS, |w| {
        w.u32_le(h.pcrs.mask)?;
        w.put(h.pcrs.values)
    })?;
    count += 2;
    if let Some(c) = h.config {
        record(&mut w, rtype::CONFIG, |w| w.put(c))?;
        count += 1;
    }
    for img in h.images() {
        record(&mut w, rtype::IMAGE, |w| {
            w.u8(u8::try_from(img.name.len()).map_err(|_| Full)?)?;
            w.put(img.name.as_bytes())?;
            w.u64_le(img.mft_record)?;
            w.u16_le(img.mft_seq)
        })?;
        count += 1;
    }
    record(&mut w, rtype::STATE, |w| w.u32_le(h.state))?;
    record(&mut w, rtype::RUNG, |w| w.u8(h.rung as u8))?;
    count += 2;
    if let Some(p) = h.provision {
        record(&mut w, rtype::PROVISION, |w| seal::write_body(&p, w))?;
        count += 1;
    }
    let total = u32::try_from(w.len()).map_err(|_| EncodeError::Full)?;
    w.patch(8, &total.to_le_bytes())?;
    w.patch(12, &count.to_le_bytes())?;
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{Pcrs as SealPcrs, Sealed};

    static PCRV: [u8; 128] = [0x11; 128];

    pub(crate) fn sample() -> Handoff<'static> {
        let mut images = [ImageId::EMPTY; MAX_IMAGES];
        images[0] = ImageId {
            name: "debian",
            mft_record: 1234,
            mft_seq: 7,
        };
        images[1] = ImageId {
            name: "arch",
            mft_record: 99,
            mft_seq: 1,
        };
        Handoff {
            volume: Volume {
                partition: Guid([3; 16]),
                first_lba: 2048,
                sectors: 1 << 30,
            },
            vmk: Some(&[0x42; 32]),
            fvek: Some(Fvek {
                cipher: 0x8004,
                key: &[0x24; 32],
            }),
            fve_layout: Some(FveLayout {
                metadata_offsets: [1, 2, 3],
                region_size: 65536,
                boot_sector_reloc_offset: 4096,
                boot_sector_reloc_sectors: 16,
                encrypted_size: 1 << 40,
            }),
            b: &[0xbb; 32],
            pcrs: Pcrs {
                mask: 0x95,
                values: &PCRV,
            },
            config: Some(b"[Paguro]\n"),
            images,
            image_count: 2,
            state: state::HIBERNATED | state::DIRTY,
            rung: Rung::Tpm,
            provision: Some(Seal {
                kind: Kind::Tpm,
                deadline: None,
                pcrs: Some(SealPcrs::V1),
                wrapped_vmk: &[1; 32],
                salt: &[2; 16],
                sealed: Some(Sealed {
                    public: &[0, 1, 9],
                    private: &[0, 1, 8],
                }),
            }),
        }
    }

    fn enc(h: &Handoff<'_>) -> ([u8; 1024], usize) {
        let mut b = [0u8; 1024];
        let n = encode(h, &mut b).unwrap();
        (b, n)
    }

    /// Re-frame `records` (raw TLV bytes) under a fresh header.
    fn frame(records: &[u8], count: u16) -> ([u8; 1024], usize) {
        let mut b = [0u8; 1024];
        let n = HEADER_LEN + records.len();
        b[..8].copy_from_slice(MAGIC);
        b[8..12].copy_from_slice(&(n as u32).to_le_bytes());
        b[12..14].copy_from_slice(&count.to_le_bytes());
        b[16..n].copy_from_slice(records);
        (b, n)
    }

    #[test]
    fn roundtrip_full_and_minimal() {
        let h = sample();
        let (b, n) = enc(&h);
        assert_eq!(decode(&b[..n]), Ok(h));
        let mut m = sample();
        m.vmk = None;
        m.fvek = None;
        m.fve_layout = None;
        m.config = None;
        m.provision = None;
        m.image_count = 1;
        m.images[1] = ImageId::EMPTY;
        m.rung = Rung::Unencrypted;
        let (b, n) = enc(&m);
        assert_eq!(decode(&b[..n]), Ok(m));
        assert_eq!(decode(&b[..n]).unwrap().images().len(), 1);
    }

    #[test]
    fn rung_values() {
        for v in 0..=255u8 {
            match Rung::from_u8(v) {
                Some(r) => assert_eq!(r as u8, v),
                None => assert!(v == 0 || v > 8),
            }
        }
    }

    #[test]
    fn header_errors() {
        let (b, n) = enc(&sample());
        assert_eq!(decode(&[0; MAX_LEN + 1]), Err(HandoffError::TooLarge));
        assert_eq!(decode(&b[..10]), Err(HandoffError::Truncated));
        let mut x = b;
        x[0] = b'X';
        assert_eq!(decode(&x[..n]), Err(HandoffError::BadMagic));
        let mut x = b;
        x[7] = 2;
        assert_eq!(
            decode(&x[..n]),
            Err(HandoffError::BadMagic),
            "unknown version"
        );
        assert_eq!(decode(&b[..n - 1]), Err(HandoffError::LengthMismatch));
        let mut x = b;
        x[14] = 1;
        assert_eq!(decode(&x[..n]), Err(HandoffError::ReservedNonZero));
        let mut x = b;
        x[12] += 1;
        assert_eq!(decode(&x[..n]), Err(HandoffError::CountMismatch));
        let mut x = b;
        x[12] -= 1;
        assert_eq!(decode(&x[..n]), Err(HandoffError::CountMismatch));
    }

    #[test]
    fn record_errors() {
        let img = [8u8, 0, 12, 0, 0, 0, 1, b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let with = |extra: &[u8], count: u16| {
            let mut rec = [0u8; 512];
            rec[..extra.len()].copy_from_slice(extra);
            rec[extra.len()..extra.len() + img.len()].copy_from_slice(&img);
            let (b, n) = frame(&rec[..extra.len() + img.len()], count);
            decode(&b[..n]).map(|_| ())
        };
        assert_eq!(
            with(&[0, 0, 0, 0, 0, 0], 2),
            Err(HandoffError::UnknownType(0))
        );
        assert_eq!(
            with(&[12, 0, 0, 0, 0, 0], 2),
            Err(HandoffError::UnknownType(12))
        );
        assert_eq!(
            with(
                &[9, 0, 4, 0, 0, 0, 0, 0, 0, 0, 9, 0, 4, 0, 0, 0, 0, 0, 0, 0],
                3
            ),
            Err(HandoffError::Duplicate(9))
        );
        assert_eq!(
            with(&[9, 0, 3, 0, 0, 0, 0, 0, 0], 2),
            Err(HandoffError::BadLength(9))
        );
        assert_eq!(
            with(&[9, 0, 4, 0, 0, 0, 16, 0, 0, 0], 2),
            Err(HandoffError::UnknownStateFlags)
        );
        assert_eq!(
            with(&[10, 0, 1, 0, 0, 0, 9], 2),
            Err(HandoffError::BadValue(10))
        );
        assert_eq!(
            with(&[10, 0, 1, 0, 0, 0, 0], 2),
            Err(HandoffError::BadValue(10))
        );
        assert_eq!(
            with(&[6, 0, 4, 0, 0, 0, 0, 0, 0, 0], 2),
            Err(HandoffError::BadValue(6))
        );
        assert_eq!(
            with(&[6, 0, 4, 0, 0, 0, 0, 0, 0, 1], 2),
            Err(HandoffError::BadValue(6))
        );
        assert_eq!(
            with(&[6, 0, 5, 0, 0, 0, 1, 0, 0, 0, 0], 2),
            Err(HandoffError::BadLength(6))
        );
        assert_eq!(
            with(&[6, 0, 2, 0, 0, 0, 1, 0], 2),
            Err(HandoffError::BadLength(6))
        );
        assert_eq!(
            with(&[3, 0, 4, 0, 0, 0, 4, 0x80, 0, 0], 2),
            Err(HandoffError::BadValue(3))
        );
        assert_eq!(
            with(&[3, 0, 4, 0, 0, 0, 4, 0x80, 65, 0], 2),
            Err(HandoffError::BadValue(3))
        );
        assert_eq!(
            with(&[3, 0, 5, 0, 0, 0, 4, 0x80, 2, 0, 1], 2),
            Err(HandoffError::BadLength(3))
        );
        assert_eq!(
            with(&[3, 0, 1, 0, 0, 0, 4], 2),
            Err(HandoffError::BadLength(3))
        );
        assert_eq!(
            with(
                &[8, 0, 12, 0, 0, 0, 1, b'.', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                2
            ),
            Err(HandoffError::BadValue(8))
        );
        assert_eq!(
            with(
                &[8, 0, 12, 0, 0, 0, 1, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                2
            ),
            Err(HandoffError::BadValue(8))
        );
        assert_eq!(
            with(
                &[8, 0, 12, 0, 0, 0, 2, b'a', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                2
            ),
            Err(HandoffError::BadLength(8))
        );
        assert_eq!(
            with(&[8, 0, 0, 0, 0, 0], 2),
            Err(HandoffError::BadLength(8))
        );
        for t in [1u8, 2, 4, 5] {
            assert_eq!(
                with(&[t, 0, 1, 0, 0, 0, 0], 2),
                Err(HandoffError::BadLength(u16::from(t)))
            );
        }
        assert_eq!(
            with(&[11, 0, 1, 0, 0, 0, 0], 2),
            Err(HandoffError::Provision(SealError::Truncated))
        );
        assert_eq!(with(&[1, 0, 40, 0, 0, 0], 2), Err(HandoffError::Truncated));

        let mut many = [0u8; 17 * 18];
        for i in 0..17 {
            many[i * 18..i * 18 + 18].copy_from_slice(&img);
        }
        let (b, n) = frame(&many, 17);
        assert_eq!(decode(&b[..n]), Err(HandoffError::TooManyImages));

        let (b, n) = frame(&[9, 0, 4, 0, 0, 0, 0, 0, 0, 0], 1);
        assert_eq!(decode(&b[..n]), Err(HandoffError::Missing(rtype::IMAGE)));
        let (b, n) = frame(&img, 1);
        assert_eq!(decode(&b[..n]), Err(HandoffError::Missing(rtype::VOLUME)));
    }

    #[test]
    fn each_required_record_is_required() {
        let (full, n) = enc(&sample());
        // Walk records, drop each required one in turn.
        let mut at = HEADER_LEN;
        while at < n {
            let t = u16::from_le_bytes([full[at], full[at + 1]]);
            let len = u32::from_le_bytes([full[at + 2], full[at + 3], full[at + 4], full[at + 5]])
                as usize;
            let end = at + 6 + len;
            if matches!(
                t,
                rtype::VOLUME | rtype::B | rtype::PCRS | rtype::STATE | rtype::RUNG
            ) {
                let mut rec = [0u8; 1024];
                let rest = n - end;
                rec[..at - HEADER_LEN].copy_from_slice(&full[HEADER_LEN..at]);
                rec[at - HEADER_LEN..at - HEADER_LEN + rest].copy_from_slice(&full[end..n]);
                let count = u16::from_le_bytes([full[12], full[13]]) - 1;
                let (b, m) = frame(&rec[..at - HEADER_LEN + rest], count);
                assert_eq!(decode(&b[..m]), Err(HandoffError::Missing(t)));
            }
            at = end;
        }
    }

    #[test]
    fn encode_refuses_invalid() {
        let mut buf = [0u8; 1024];
        let mut h = sample();
        h.image_count = 0;
        assert_eq!(encode(&h, &mut buf), Err(EncodeError::Invalid));
        let mut h = sample();
        h.images[0].name = "a b";
        assert_eq!(encode(&h, &mut buf), Err(EncodeError::Invalid));
        let mut h = sample();
        h.pcrs.mask = 0x1;
        assert_eq!(encode(&h, &mut buf), Err(EncodeError::Invalid));
        let mut h = sample();
        h.state = 16;
        assert_eq!(encode(&h, &mut buf), Err(EncodeError::Invalid));
        let mut h = sample();
        h.fvek = Some(Fvek {
            cipher: 1,
            key: &[],
        });
        assert_eq!(encode(&h, &mut buf), Err(EncodeError::Invalid));
        let mut h = sample();
        if let Some(p) = h.provision.as_mut() {
            p.kind = Kind::PinBypass;
        }
        assert_eq!(encode(&h, &mut buf), Err(EncodeError::Invalid));
        assert_eq!(encode(&sample(), &mut buf[..100]), Err(EncodeError::Full));
    }
}
