//! BitLocker (BDE) volume structures: the volume header, the three FVE
//! metadata blocks and their cross-check, protector enumeration, and the
//! sector map of the decrypted view (DESIGN.md §6 "Reading a BitLocker
//! volume", INTERFACES.md §8 `FVE_LAYOUT`, §10.2 reserved ranges, §12.2).
//!
//! This is the loader's first-line adversarial parser: everything here is
//! plaintext on disk, rewritable with physical access, and parsed while the
//! VMK is still obtainable. So, structurally:
//!
//! - every read is bounded by the 64 KiB metadata region handed in; offsets
//!   taken from the metadata are range-checked against the volume;
//! - the entry lists are walked against a hard schema (entry type ↔ value
//!   type), unknown entries are skipped by declared length and never
//!   interpreted, and every count is capped ([`MAX_ENTRIES`],
//!   [`MAX_NESTED`], [`MAX_PROTECTORS`]);
//! - the three copies are a cross-check: each carries a CRC-32, and the
//!   bytes that describe the volume must be identical in all three —
//!   disagreement is a refusal, never a vote ([`cross_check`]);
//! - once a VMK is in hand the metadata is authenticated too: Windows 8+
//!   stores a VMK-wrapped SHA-256 of the block ([`Block::validation`]).
//!
//! No cryptography happens here (`paguro-crypto::bitlocker` does it); this
//! module says which bytes are the nonce, tag and ciphertext, and parses the
//! plaintext that comes back ([`parse_key`]).
//!
//! Layout references: libbde's "BitLocker Drive Encryption (BDE) format"
//! and cryptsetup's `lib/bitlk`; every field used here is exercised against
//! Windows-made volumes and two independent readers (libbde, dislocker) in
//! `test/fixtures/bde/`.

use crate::bytes::Reader;

/// `-FVE-FS-` at offset 3 of a BitLocker volume's first sector (Windows
/// Vista and later), and at the start of every FVE metadata block.
pub const SIGNATURE: &[u8; 8] = b"-FVE-FS-";
/// BitLocker To Go: a FAT32 "discovery volume" boot sector at offset 3.
pub const TOGO_SIGNATURE: &[u8; 8] = b"MSWIN4.1";
/// The identifier after the boot sector's BPB of a fully encrypted volume
/// (`4967d63b-2e29-4ad8-8399-f6a339e3d001`).
pub const GUID_NORMAL: [u8; 16] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];
/// … and of a used-space-only ("encrypt on write") volume
/// (`92a84d3b-dd80-4d0e-9e4e-b1e3284eaed8`).
pub const GUID_EOW: [u8; 16] = [
    0x3b, 0x4d, 0xa8, 0x92, 0x80, 0xdd, 0x0e, 0x4d, 0x9e, 0x4e, 0xb1, 0xe3, 0x28, 0x4e, 0xae, 0xd8,
];
/// Where the identifier and the three metadata offsets sit.
pub const HEADER_ID_OFFSET: usize = 160;
pub const TOGO_ID_OFFSET: usize = 424;

/// Every FVE metadata region is 64 KiB: block, validation, then zeros.
pub const REGION_SIZE: u64 = 0x1_0000;
pub const BLOCK_HEADER_LEN: usize = 64;
pub const METADATA_HEADER_LEN: usize = 48;
pub const ENTRY_HEADER_LEN: usize = 8;
/// Top-level entries per metadata block.
pub const MAX_ENTRIES: usize = 64;
/// Children of one entry.
pub const MAX_NESTED: usize = 16;
/// VMK entries per volume (Windows allows a handful of each kind).
pub const MAX_PROTECTORS: usize = 16;
/// Largest wrapped key accepted (a key entry is 44 or 76 bytes).
pub const MAX_WRAPPED: usize = 256;

/// FVE entry types (the "role" of an entry).
pub mod entry {
    pub const PROPERTY: u16 = 0x0000;
    pub const VMK: u16 = 0x0002;
    pub const FVEK: u16 = 0x0003;
    pub const VALIDATION: u16 = 0x0004;
    pub const STARTUP_KEY: u16 = 0x0006;
    pub const DESCRIPTION: u16 = 0x0007;
    pub const FVEK_BACKUP: u16 = 0x000b;
    pub const VOLUME_HEADER_BLOCK: u16 = 0x000f;
}

/// FVE value types (the encoding of an entry's data).
pub mod value {
    pub const ERASED: u16 = 0x0000;
    pub const KEY: u16 = 0x0001;
    pub const UNICODE: u16 = 0x0002;
    pub const STRETCH_KEY: u16 = 0x0003;
    pub const USE_KEY: u16 = 0x0004;
    pub const AES_CCM: u16 = 0x0005;
    pub const TPM_KEY: u16 = 0x0006;
    pub const VALIDATION: u16 = 0x0007;
    pub const VMK: u16 = 0x0008;
    pub const EXTERNAL_KEY: u16 = 0x0009;
    pub const UPDATE: u16 = 0x000a;
    pub const ERROR: u16 = 0x000b;
    pub const OFFSET_AND_SIZE: u16 = 0x000f;
}

/// Data-encryption methods (the metadata header's `encryption` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    /// Windows 10 1511+: supported.
    XtsAes128,
    XtsAes256,
    /// AES-CBC with the Elephant diffuser (Vista, 7): refused.
    CbcDiffuser128,
    CbcDiffuser256,
    /// AES-CBC without diffuser (8, 8.1, early 10): refused.
    Cbc128,
    Cbc256,
    Unknown(u16),
}

impl Cipher {
    pub const fn from_u16(v: u16) -> Cipher {
        match v {
            0x8000 => Cipher::CbcDiffuser128,
            0x8001 => Cipher::CbcDiffuser256,
            0x8002 => Cipher::Cbc128,
            0x8003 => Cipher::Cbc256,
            0x8004 => Cipher::XtsAes128,
            0x8005 => Cipher::XtsAes256,
            v => Cipher::Unknown(v),
        }
    }
    pub const fn to_u16(self) -> u16 {
        match self {
            Cipher::CbcDiffuser128 => 0x8000,
            Cipher::CbcDiffuser256 => 0x8001,
            Cipher::Cbc128 => 0x8002,
            Cipher::Cbc256 => 0x8003,
            Cipher::XtsAes128 => 0x8004,
            Cipher::XtsAes256 => 0x8005,
            Cipher::Unknown(v) => v,
        }
    }
    /// FVEK length for the ciphers paguro reads; `None`: refused.
    pub const fn key_len(self) -> Option<usize> {
        match self {
            Cipher::XtsAes128 => Some(32),
            Cipher::XtsAes256 => Some(64),
            _ => None,
        }
    }
}

/// Every refusal, typed (INTERFACES.md §12: each has a test).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BdeError {
    /// Neither `-FVE-FS-` nor a BitLocker To Go discovery volume.
    NotBitLocker,
    /// Windows Vista's layout (one metadata offset in the BPB, AES-CBC with
    /// the diffuser only): refused.
    Vista,
    /// `-FVE-FS-` (or `MSWIN4.1`) without a known BitLocker identifier.
    UnknownIdentifier,
    /// Bytes per sector other than 512 or 4096.
    SectorSize(u16),
    /// The boot sector's `55 AA` is missing.
    BootSignature,
    /// A metadata offset is zero, misaligned, repeated or past the volume.
    MetadataOffset,
    /// Metadata copy `n` (0-based) does not start with `-FVE-FS-`.
    BlockSignature(u8),
    /// A metadata block version other than 2 (Windows 7 and later).
    BlockVersion(u16),
    /// The block's size field does not fit the 64 KiB region.
    BlockSize,
    /// A copy's own offsets differ from the volume header's.
    BlockLocation,
    /// Copy `n`'s validation header is malformed.
    Validation(u8),
    /// Copy `n`'s CRC-32 does not match its bytes.
    Checksum(u8),
    /// The metadata header's sizes or version are inconsistent.
    MetadataHeader,
    /// The three copies differ where they must agree.
    CopiesDisagree,
    /// An entry shorter than its header, or a size the region cannot hold.
    EntryTooSmall,
    EntryOverruns,
    /// Bytes after a zero-size terminator are not zero.
    TrailingGarbage,
    TooManyEntries,
    TooManyProtectors,
    /// An entry whose value type is wrong for its role (the hard schema).
    Schema {
        entry_type: u16,
        value_type: u16,
    },
    /// A malformed field inside an otherwise well-formed entry.
    BadVmk,
    BadStretchKey,
    BadCcm,
    BadKey,
    MissingFvek,
    DuplicateFvek,
    MissingVolumeHeader,
    DuplicateVolumeHeader,
    /// The relocated boot-sector region disagrees between the block header
    /// and its entry, or is misaligned, empty or past the volume.
    Relocation,
    /// Two non-data regions overlap.
    Overlap,
    /// Encryption state other than encrypted, or paused/in-progress
    /// conversion with a pending conversion region.
    State {
        current: u16,
        next: u16,
    },
    /// Encrypted size past the volume or not a whole sector.
    EncryptedSize,
    /// AES-CBC (with or without the diffuser), or an unknown method.
    UnsupportedCipher(u16),
    /// The unwrapped key's method is not the volume's, or its length is not
    /// the cipher's.
    FvekMismatch,
    /// The metadata's VMK-wrapped SHA-256 does not match the block.
    ValidationHash,
    /// A startup-key (`.BEK`) file is malformed.
    BadStartupKey,
    /// Used-space-only ("encrypt on write") volume: recognised, not read.
    /// The only Windows-made sample stores its relocated boot sectors in
    /// plaintext, which neither libbde, dislocker nor cryptsetup models (all
    /// three refuse such volumes), and `FVE_LAYOUT` cannot express it
    /// (`test/fixtures/bde/README.md`).
    UsedSpaceOnly,
}

pub type Result<T> = core::result::Result<T, BdeError>;

fn le16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([*s.first()?, *s.get(1)?]))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    let s: [u8; 4] = b.get(at..at.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(s))
}

fn le64(b: &[u8], at: usize) -> Option<u64> {
    let s: [u8; 8] = b.get(at..at.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_le_bytes(s))
}

fn arr<const N: usize>(b: &[u8], at: usize) -> Option<[u8; N]> {
    b.get(at..at.checked_add(N)?)?.try_into().ok()
}

#[allow(clippy::indexing_slicing)] // const context: `i < 256` by the loop bound
const CRC_TABLE: [u32; 256] = {
    let mut t = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        t[i] = c;
        i += 1;
    }
    t
};

/// CRC-32 (IEEE 802.3, reflected), as the FVE validation block uses.
pub fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        let i = usize::from((c as u8) ^ b);
        c = CRC_TABLE.get(i).copied().unwrap_or(0) ^ (c >> 8);
    }
    !c
}

/// Which boot-sector layout identified the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderKind {
    /// `-FVE-FS-` in the OEM field (Windows 7 and later).
    Standard,
    /// BitLocker To Go: a FAT32 discovery volume over the encrypted one.
    ToGo,
}

/// The first sector of a BitLocker volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeHeader {
    pub kind: HeaderKind,
    /// Used-space-only encryption ("encrypt on write"): identified, then
    /// refused by [`Layout::new`] ([`BdeError::UsedSpaceOnly`]).
    pub eow: bool,
    /// The data unit: XTS runs over whole sectors of this size.
    pub bytes_per_sector: u32,
    /// Byte offsets of the three metadata blocks from the volume start.
    pub metadata_offsets: [u64; 3],
}

/// Parse the volume's first sector (at least 512 bytes of it).
pub fn parse_volume_header(s: &[u8]) -> Result<VolumeHeader> {
    let oem = s.get(3..11).ok_or(BdeError::NotBitLocker)?;
    let id_at = if oem == SIGNATURE {
        HEADER_ID_OFFSET
    } else if oem == TOGO_SIGNATURE {
        TOGO_ID_OFFSET
    } else {
        return Err(BdeError::NotBitLocker);
    };
    let id: [u8; 16] = arr(s, id_at).ok_or(BdeError::NotBitLocker)?;
    let eow = if id == GUID_NORMAL {
        false
    } else if id == GUID_EOW {
        true
    } else if oem == SIGNATURE && s.get(..3) == Some(&[0xeb, 0x52, 0x90][..]) {
        return Err(BdeError::Vista);
    } else if oem == TOGO_SIGNATURE {
        // An ordinary FAT32 volume formatted by Windows.
        return Err(BdeError::NotBitLocker);
    } else {
        return Err(BdeError::UnknownIdentifier);
    };
    if s.get(510..512) != Some(&[0x55, 0xaa][..]) {
        return Err(BdeError::BootSignature);
    }
    let bps = le16(s, 11).ok_or(BdeError::NotBitLocker)?;
    if bps != 512 && bps != 4096 {
        return Err(BdeError::SectorSize(bps));
    }
    let mut offs = [0u64; 3];
    for (i, o) in offs.iter_mut().enumerate() {
        *o = le64(s, id_at + 16 + 8 * i).ok_or(BdeError::NotBitLocker)?;
    }
    let a = u64::from(bps);
    let [x, y, z] = offs;
    if offs.iter().any(|&o| o == 0 || o % a != 0) || x == y || y == z || x == z {
        return Err(BdeError::MetadataOffset);
    }
    Ok(VolumeHeader {
        kind: if id_at == HEADER_ID_OFFSET {
            HeaderKind::Standard
        } else {
            HeaderKind::ToGo
        },
        eow,
        bytes_per_sector: u32::from(bps),
        metadata_offsets: offs,
    })
}

/// An AES-CCM-wrapped value: 12-byte nonce (FILETIME ‖ counter), 16-byte
/// tag, ciphertext.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ccm<'a> {
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub ciphertext: &'a [u8],
}

impl<'a> Ccm<'a> {
    /// The data of an `AES_CCM` entry.
    pub fn parse(data: &'a [u8]) -> Result<Ccm<'a>> {
        let mut r = Reader::new(data);
        let nonce = *r.array::<12>().map_err(|_| BdeError::BadCcm)?;
        let tag = *r.array::<16>().map_err(|_| BdeError::BadCcm)?;
        let ciphertext = r.rest();
        if ciphertext.len() < ENTRY_HEADER_LEN || ciphertext.len() > MAX_WRAPPED {
            return Err(BdeError::BadCcm);
        }
        Ok(Ccm {
            nonce,
            tag,
            ciphertext,
        })
    }
}

/// One FVE entry ("datum"): `size u16 | entry type u16 | value type u16 |
/// version u16 | data`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub entry_type: u16,
    pub value_type: u16,
    pub version: u16,
    pub data: &'a [u8],
}

/// A bounded walk over a list of entries. The list must tile its region
/// exactly, or end in a zero-size terminator followed only by zeros.
#[derive(Clone, Debug)]
pub struct Entries<'a> {
    rest: &'a [u8],
    left: usize,
    done: bool,
}

impl<'a> Entries<'a> {
    pub fn new(list: &'a [u8], max: usize) -> Self {
        Entries {
            rest: list,
            left: max,
            done: false,
        }
    }
}

impl<'a> Iterator for Entries<'a> {
    type Item = Result<Entry<'a>>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        let r = (|| {
            let size = usize::from(le16(self.rest, 0).ok_or(BdeError::EntryOverruns)?);
            if size == 0 {
                if self.rest.iter().any(|&b| b != 0) {
                    return Err(BdeError::TrailingGarbage);
                }
                return Ok(None);
            }
            if size < ENTRY_HEADER_LEN {
                return Err(BdeError::EntryTooSmall);
            }
            if self.left == 0 {
                return Err(BdeError::TooManyEntries);
            }
            let (e, tail) = self
                .rest
                .split_at_checked(size)
                .ok_or(BdeError::EntryOverruns)?;
            self.rest = tail;
            self.left -= 1;
            Ok(Some(Entry {
                entry_type: le16(e, 2).ok_or(BdeError::EntryOverruns)?,
                value_type: le16(e, 4).ok_or(BdeError::EntryOverruns)?,
                version: le16(e, 6).ok_or(BdeError::EntryOverruns)?,
                data: e.get(ENTRY_HEADER_LEN..).ok_or(BdeError::EntryOverruns)?,
            }))
        })();
        match r {
            Ok(Some(e)) => Some(Ok(e)),
            Ok(None) => {
                self.done = true;
                None
            }
            Err(e) => {
                self.done = true;
                Some(Err(e))
            }
        }
    }
}

/// A parsed key entry (`value::KEY`): `method u32 | key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key<'a> {
    pub method: u32,
    pub key: &'a [u8],
}

/// Parse the plaintext of an unwrapped CCM value: one `KEY` entry whose
/// size is exactly the plaintext's length.
pub fn parse_key(plain: &[u8]) -> Result<Key<'_>> {
    let mut it = Entries::new(plain, 1);
    let e = it.next().ok_or(BdeError::BadKey)??;
    let whole = usize::from(le16(plain, 0).ok_or(BdeError::BadKey)?);
    if e.value_type != value::KEY || whole != plain.len() {
        return Err(BdeError::BadKey);
    }
    key_value(e.data)
}

fn key_value(data: &[u8]) -> Result<Key<'_>> {
    let method = le32(data, 0).ok_or(BdeError::BadKey)?;
    let key = data.get(4..).ok_or(BdeError::BadKey)?;
    if key.is_empty() {
        return Err(BdeError::BadKey);
    }
    Ok(Key { method, key })
}

/// How a VMK is protected (the VMK entry's `protection` field).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtectorKind {
    /// BitLocker suspended: the VMK's key is stored in the clear.
    ClearKey,
    Tpm,
    /// A startup key on a USB stick (`.BEK` file).
    StartupKey,
    TpmPin,
    RecoveryPassword,
    SmartCard,
    Password,
    /// Recognised as a protector, never interpreted.
    Other(u16),
}

impl ProtectorKind {
    pub const fn from_u16(v: u16) -> ProtectorKind {
        match v {
            0x0000 => ProtectorKind::ClearKey,
            0x0100 => ProtectorKind::Tpm,
            0x0200 => ProtectorKind::StartupKey,
            0x0500 => ProtectorKind::TpmPin,
            0x0800 => ProtectorKind::RecoveryPassword,
            0x1000 => ProtectorKind::SmartCard,
            0x2000 => ProtectorKind::Password,
            v => ProtectorKind::Other(v),
        }
    }
    /// Whether the loader can obtain the VMK from it without a TPM or a
    /// smart card.
    pub const fn usable(self) -> bool {
        matches!(
            self,
            ProtectorKind::ClearKey
                | ProtectorKind::StartupKey
                | ProtectorKind::RecoveryPassword
                | ProtectorKind::Password
        )
    }
}

/// One VMK entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Protector<'a> {
    /// The protector's GUID, as stored (mixed-endian).
    pub id: [u8; 16],
    pub kind: ProtectorKind,
    /// The stretch-key salt (password and recovery-password protectors).
    pub salt: Option<[u8; 16]>,
    /// The clear key (clear-key protector).
    pub clear_key: Option<[u8; 32]>,
    /// The VMK wrapped under the protector's key.
    pub wrapped_vmk: Option<Ccm<'a>>,
}

const VMK_FIXED: usize = 28;

impl<'a> Protector<'a> {
    fn parse(data: &'a [u8]) -> Result<Protector<'a>> {
        let id: [u8; 16] = arr(data, 0).ok_or(BdeError::BadVmk)?;
        let kind = ProtectorKind::from_u16(le16(data, 26).ok_or(BdeError::BadVmk)?);
        let nested = data.get(VMK_FIXED..).ok_or(BdeError::BadVmk)?;
        let mut p = Protector {
            id,
            kind,
            salt: None,
            clear_key: None,
            wrapped_vmk: None,
        };
        let (mut ccm, mut stretch, mut keys) = (0u8, 0u8, 0u8);
        for e in Entries::new(nested, MAX_NESTED) {
            let e = e?;
            match e.value_type {
                value::AES_CCM => {
                    ccm += 1;
                    if p.wrapped_vmk.is_none() {
                        p.wrapped_vmk = Some(Ccm::parse(e.data)?);
                    }
                }
                value::STRETCH_KEY => {
                    stretch += 1;
                    // method u32 | salt[16] | nested (ignored)
                    le32(e.data, 0).ok_or(BdeError::BadStretchKey)?;
                    p.salt = Some(arr(e.data, 4).ok_or(BdeError::BadStretchKey)?);
                }
                value::KEY => {
                    keys += 1;
                    let k = key_value(e.data)?;
                    p.clear_key = Some(k.key.try_into().map_err(|_| BdeError::BadKey)?);
                }
                _ => {}
            }
        }
        // The hard schema, for the kinds the loader acts on. Other kinds are
        // listed but never touched, so their children are not constrained.
        let ok = match kind {
            ProtectorKind::Password | ProtectorKind::RecoveryPassword => {
                ccm == 1 && stretch == 1 && keys == 0
            }
            ProtectorKind::ClearKey => ccm == 1 && stretch == 0 && keys == 1,
            ProtectorKind::StartupKey => ccm == 1 && keys == 0,
            _ => true,
        };
        if !ok {
            return Err(BdeError::BadVmk);
        }
        if !kind.usable() {
            p.salt = None;
            p.clear_key = None;
            p.wrapped_vmk = None;
        }
        Ok(p)
    }
}

/// The parsed, validated content of one FVE metadata block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Block<'a> {
    /// `[0, size)` of the block: what the CRC and the SHA-256 cover.
    pub raw: &'a [u8],
    /// Everything that must agree across copies: `raw`, then the
    /// validation header and its entry.
    pub agreed: &'a [u8],
    pub current_state: u16,
    pub next_state: u16,
    /// Bytes from the volume start that are encrypted; past it, plaintext.
    pub encrypted_size: u64,
    pub conversion_size: u32,
    /// The relocated boot-sector region's length, in volume sectors.
    pub header_sectors: u32,
    pub metadata_offsets: [u64; 3],
    /// Where the boot sectors were relocated to (bytes).
    pub header_offset: u64,
    /// The volume identifier (as stored).
    pub volume_id: [u8; 16],
    pub next_nonce: u32,
    pub cipher: Cipher,
    pub created: u64,
    pub entries: &'a [u8],
    /// Windows 8+: the block's SHA-256, wrapped under the VMK.
    pub validation: Option<Ccm<'a>>,
}

/// Encryption states Windows writes (`current_state` / `next_state`).
pub mod state {
    pub const DECRYPTED: u16 = 1;
    pub const SWITCHING: u16 = 2;
    pub const EOW_ACTIVATED: u16 = 3;
    pub const ENCRYPTED: u16 = 4;
    pub const PAUSED: u16 = 5;
}

/// Parse one copy: `region` is the 64 KiB at a metadata offset (at least
/// as much of it as the block and its validation occupy). `copy` (0–2)
/// names the copy in errors; `hdr` is the volume header it must agree with.
pub fn parse_block<'a>(region: &'a [u8], copy: u8, hdr: &VolumeHeader) -> Result<Block<'a>> {
    let region = region.get(..REGION_SIZE as usize).unwrap_or(region);
    if region.get(..8) != Some(&SIGNATURE[..]) {
        return Err(BdeError::BlockSignature(copy));
    }
    let f = |at| le16(region, at).ok_or(BdeError::BlockSize);
    let size = usize::from(f(8)?) * 16;
    let version = f(10)?;
    if version != 2 {
        return Err(BdeError::BlockVersion(version));
    }
    if size < BLOCK_HEADER_LEN + METADATA_HEADER_LEN || size.saturating_add(8) > region.len() {
        return Err(BdeError::BlockSize);
    }
    let raw = region.get(..size).ok_or(BdeError::BlockSize)?;
    let g64 = |at| le64(raw, at).ok_or(BdeError::BlockSize);
    let g32 = |at| le32(raw, at).ok_or(BdeError::BlockSize);
    let metadata_offsets = [g64(32)?, g64(40)?, g64(48)?];
    if metadata_offsets != hdr.metadata_offsets {
        return Err(BdeError::BlockLocation);
    }

    // Validation: size u16 | version u16 | crc32 u32 | (v2) one AES-CCM entry.
    let v = region.get(size..).ok_or(BdeError::Validation(copy))?;
    let vsize = usize::from(le16(v, 0).ok_or(BdeError::Validation(copy))?);
    let vver = le16(v, 2).ok_or(BdeError::Validation(copy))?;
    let crc = le32(v, 4).ok_or(BdeError::Validation(copy))?;
    // `vsize` runs to the region's end (Windows); only the header and one
    // entry are read, so a caller may hand in less than the whole region.
    if vsize < 8 || vsize > REGION_SIZE as usize - size || !(1..=2).contains(&vver) {
        return Err(BdeError::Validation(copy));
    }
    if crc32(raw) != crc {
        // A cipher paguro never reads is the better reason to give: the one
        // Windows 7 sample (AES-CBC, diffuser) fails its own CRC.
        if let Some(c) = le16(raw, BLOCK_HEADER_LEN + 36).map(Cipher::from_u16) {
            if c.key_len().is_none() {
                return Err(BdeError::UnsupportedCipher(c.to_u16()));
            }
        }
        return Err(BdeError::Checksum(copy));
    }
    let (validation, vlen) = if vver == 2 {
        let body = v
            .get(8..vsize.min(v.len()))
            .ok_or(BdeError::Validation(copy))?;
        let n = usize::from(le16(body, 0).ok_or(BdeError::Validation(copy))?);
        let e = Entries::new(body.get(..n).ok_or(BdeError::Validation(copy))?, 1)
            .next()
            .ok_or(BdeError::Validation(copy))?
            .map_err(|_| BdeError::Validation(copy))?;
        if e.value_type != value::AES_CCM {
            return Err(BdeError::Validation(copy));
        }
        (
            Some(Ccm::parse(e.data).map_err(|_| BdeError::Validation(copy))?),
            8 + n,
        )
    } else {
        (None, 8)
    };
    let agreed = region
        .get(..size + vlen)
        .ok_or(BdeError::Validation(copy))?;

    // Metadata header at 64: size | version | header size | size copy |
    // volume id | next nonce | encryption u16 | unknown u16 | created.
    let m = raw
        .get(BLOCK_HEADER_LEN..)
        .ok_or(BdeError::MetadataHeader)?;
    let msize = le32(m, 0).ok_or(BdeError::MetadataHeader)? as usize;
    if le32(m, 4) != Some(1)
        || le32(m, 8) != Some(METADATA_HEADER_LEN as u32)
        || le32(m, 12) != Some(msize as u32)
        || msize < METADATA_HEADER_LEN
        || msize > m.len()
    {
        return Err(BdeError::MetadataHeader);
    }
    let entries = m
        .get(METADATA_HEADER_LEN..msize)
        .ok_or(BdeError::MetadataHeader)?;
    Ok(Block {
        raw,
        agreed,
        current_state: f(12)?,
        next_state: f(14)?,
        encrypted_size: g64(16)?,
        conversion_size: g32(24)?,
        header_sectors: g32(28)?,
        metadata_offsets,
        header_offset: g64(56)?,
        volume_id: arr(m, 16).ok_or(BdeError::MetadataHeader)?,
        next_nonce: le32(m, 32).ok_or(BdeError::MetadataHeader)?,
        cipher: Cipher::from_u16(le16(m, 36).ok_or(BdeError::MetadataHeader)?),
        created: le64(m, 40).ok_or(BdeError::MetadataHeader)?,
        entries,
        validation,
    })
}

/// Parse copy 0 and require copies 1 and 2 to carry the same bytes
/// ([`Block::agreed`]). Each copy's CRC is checked on its own first, so a
/// damaged copy is named ([`BdeError::Checksum`]) rather than outvoted.
pub fn cross_check<'a>(copies: [&'a [u8]; 3], hdr: &VolumeHeader) -> Result<Block<'a>> {
    let [a, b, c] = copies;
    let first = parse_block(a, 0, hdr)?;
    for (i, other) in [(1u8, b), (2, c)] {
        let o = parse_block(other, i, hdr)?;
        if o.agreed != first.agreed {
            return Err(BdeError::CopiesDisagree);
        }
    }
    Ok(first)
}

/// What the entry list of a block declares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Metadata<'a> {
    pub block: Block<'a>,
    pub fvek: Ccm<'a>,
    /// The relocated boot sectors: `(offset, size)` in bytes.
    pub volume_header: (u64, u64),
    /// UTF-16LE, as stored (NUL included when Windows wrote one).
    pub description: Option<&'a [u8]>,
    protectors: [Option<Protector<'a>>; MAX_PROTECTORS],
    count: usize,
}

impl<'a> Metadata<'a> {
    /// Walk `block`'s entries against the schema.
    pub fn parse(block: Block<'a>) -> Result<Metadata<'a>> {
        let mut m = Metadata {
            block,
            fvek: Ccm {
                nonce: [0; 12],
                tag: [0; 16],
                ciphertext: &[],
            },
            volume_header: (0, 0),
            description: None,
            protectors: [None; MAX_PROTECTORS],
            count: 0,
        };
        let (mut fvek, mut vhb) = (false, false);
        for e in Entries::new(block.entries, MAX_ENTRIES) {
            let e = e?;
            let schema = BdeError::Schema {
                entry_type: e.entry_type,
                value_type: e.value_type,
            };
            match e.entry_type {
                entry::VMK => {
                    if e.value_type != value::VMK {
                        return Err(schema);
                    }
                    let p = Protector::parse(e.data)?;
                    *m.protectors
                        .get_mut(m.count)
                        .ok_or(BdeError::TooManyProtectors)? = Some(p);
                    m.count += 1;
                }
                entry::FVEK => {
                    if e.value_type != value::AES_CCM {
                        return Err(schema);
                    }
                    if fvek {
                        return Err(BdeError::DuplicateFvek);
                    }
                    fvek = true;
                    m.fvek = Ccm::parse(e.data)?;
                }
                entry::VOLUME_HEADER_BLOCK => {
                    if e.value_type != value::OFFSET_AND_SIZE {
                        return Err(schema);
                    }
                    if vhb {
                        return Err(BdeError::DuplicateVolumeHeader);
                    }
                    vhb = true;
                    m.volume_header = (
                        le64(e.data, 0).ok_or(BdeError::Relocation)?,
                        le64(e.data, 8).ok_or(BdeError::Relocation)?,
                    );
                }
                entry::DESCRIPTION => {
                    if e.value_type != value::UNICODE {
                        return Err(schema);
                    }
                    m.description = Some(e.data);
                }
                // Validation, FVEK backup, properties, and whatever later
                // Windows adds: skipped by declared length, never read.
                _ => {}
            }
        }
        if !fvek {
            return Err(BdeError::MissingFvek);
        }
        if !vhb {
            return Err(BdeError::MissingVolumeHeader);
        }
        Ok(m)
    }

    pub fn protectors(&self) -> impl Iterator<Item = &Protector<'a>> {
        self.protectors.iter().take(self.count).flatten()
    }

    /// The protectors of one kind, in metadata order.
    pub fn of_kind(&self, kind: ProtectorKind) -> impl Iterator<Item = &Protector<'a>> {
        self.protectors().filter(move |p| p.kind == kind)
    }
}

/// A startup key (`.BEK` file): the external key and the protector it
/// opens. Same framing as the metadata header, then one `STARTUP_KEY`
/// entry holding an `EXTERNAL_KEY` value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StartupKey {
    pub id: [u8; 16],
    pub key: [u8; 32],
}

pub fn parse_startup_key(file: &[u8]) -> Result<StartupKey> {
    let bad = BdeError::BadStartupKey;
    let size = le32(file, 0).ok_or(bad)? as usize;
    if size != file.len()
        || size > 4096
        || le32(file, 4) != Some(1)
        || le32(file, 8) != Some(METADATA_HEADER_LEN as u32)
        || le32(file, 12) != Some(size as u32)
    {
        return Err(bad);
    }
    let list = file.get(METADATA_HEADER_LEN..).ok_or(bad)?;
    let mut found = None;
    for e in Entries::new(list, MAX_NESTED) {
        let e = e.map_err(|_| bad)?;
        if e.entry_type != entry::STARTUP_KEY {
            continue;
        }
        if e.value_type != value::EXTERNAL_KEY || found.is_some() {
            return Err(bad);
        }
        // guid[16] | modified u64 | nested: one KEY among others
        let id: [u8; 16] = arr(e.data, 0).ok_or(bad)?;
        let mut key = None;
        for n in Entries::new(e.data.get(24..).ok_or(bad)?, MAX_NESTED) {
            let n = n.map_err(|_| bad)?;
            if n.value_type == value::KEY {
                if key.is_some() {
                    return Err(bad);
                }
                let k = key_value(n.data).map_err(|_| bad)?;
                key = Some(<[u8; 32]>::try_from(k.key).map_err(|_| bad)?);
            }
        }
        found = Some(StartupKey {
            id,
            key: key.ok_or(bad)?,
        });
    }
    found.ok_or(bad)
}

/// Where the bytes of one data unit of the decrypted view come from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Read physical unit `unit`; decrypt with tweak `unit` if `encrypted`.
    Disk { unit: u64, encrypted: bool },
    /// A metadata region or the relocated copy's home: zeros, as libbde,
    /// dislocker and cryptsetup return (see `test/fixtures/bde/README.md`).
    Zero,
}

/// The decrypted view's map: which physical sectors, which tweak, which
/// regions read as zeros. One unit = one sector = one XTS data unit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub bytes_per_sector: u32,
    /// The whole volume (the partition), in bytes.
    pub volume_size: u64,
    pub metadata_offsets: [u64; 3],
    /// Bytes of the boot sectors relocated to `reloc_offset`.
    pub reloc_len: u64,
    pub reloc_offset: u64,
    /// Bytes from the volume start that are encrypted.
    pub encrypted_size: u64,
    pub cipher: Cipher,
    /// `encrypted_size < volume_size`: conversion paused or in progress.
    pub partial: bool,
}

impl Layout {
    /// Validate the metadata's layout against the volume: `volume_size` is
    /// the partition's length in bytes.
    pub fn new(hdr: &VolumeHeader, m: &Metadata<'_>, volume_size: u64) -> Result<Layout> {
        let b = &m.block;
        if hdr.eow {
            return Err(BdeError::UsedSpaceOnly);
        }
        let bps = u64::from(hdr.bytes_per_sector);
        // `VolumeHeader` is a plain struct: re-check what the map relies on
        // rather than trust that it came from `parse_volume_header`.
        if bps != 512 && bps != 4096 {
            return Err(BdeError::SectorSize(hdr.bytes_per_sector as u16));
        }
        if hdr.metadata_offsets.iter().any(|&o| o == 0 || o % bps != 0) {
            return Err(BdeError::MetadataOffset);
        }
        // A trailing partial sector is not part of the view.
        let volume_size = volume_size - volume_size % bps;
        let (reloc_offset, reloc_len) = m.volume_header;
        if reloc_offset != b.header_offset
            || Some(reloc_len) != u64::from(b.header_sectors).checked_mul(bps)
            || reloc_len == 0
            || reloc_offset % bps != 0
        {
            return Err(BdeError::Relocation);
        }
        let regions = [
            (0, reloc_len),
            (reloc_offset, reloc_len),
            (hdr.metadata_offsets[0], REGION_SIZE),
            (hdr.metadata_offsets[1], REGION_SIZE),
            (hdr.metadata_offsets[2], REGION_SIZE),
        ];
        for (i, &(o, l)) in regions.iter().enumerate() {
            match o.checked_add(l) {
                Some(end) if end <= volume_size => {}
                _ if i < 2 => return Err(BdeError::Relocation),
                _ => return Err(BdeError::MetadataOffset),
            }
            for &(o2, l2) in regions.iter().skip(i + 1) {
                if o < o2.saturating_add(l2) && o2 < o.saturating_add(l) {
                    return Err(BdeError::Overlap);
                }
            }
        }
        if b.encrypted_size > volume_size || b.encrypted_size % bps != 0 {
            return Err(BdeError::EncryptedSize);
        }
        let st = (b.current_state, b.next_state);
        let partial = b.encrypted_size < volume_size;
        let ok = match st {
            (state::ENCRYPTED, state::ENCRYPTED) => true,
            // Conversion paused or running: the boundary is encrypted_size,
            // and nothing may be mid-flight in a conversion region.
            (state::SWITCHING | state::PAUSED, state::ENCRYPTED) => b.conversion_size == 0,
            _ => false,
        };
        if !ok {
            return Err(BdeError::State {
                current: st.0,
                next: st.1,
            });
        }
        if b.cipher.key_len().is_none() {
            return Err(BdeError::UnsupportedCipher(b.cipher.to_u16()));
        }
        Ok(Layout {
            bytes_per_sector: hdr.bytes_per_sector,
            volume_size,
            metadata_offsets: hdr.metadata_offsets,
            reloc_len,
            reloc_offset,
            encrypted_size: b.encrypted_size,
            cipher: b.cipher,
            partial,
        })
    }

    fn bps(&self) -> u64 {
        u64::from(self.bytes_per_sector)
    }

    /// Units in the volume.
    pub fn units(&self) -> u64 {
        self.volume_size / self.bps()
    }

    /// Where unit `unit` of the decrypted view comes from, and for how many
    /// units from there on the answer continues in step (`Disk` units
    /// advance by one; the run ends at the next boundary). `None` past the
    /// volume.
    pub fn map(&self, unit: u64) -> Option<(Source, u64)> {
        let bps = self.bps();
        let off = unit.checked_mul(bps)?;
        if off >= self.volume_size {
            return None;
        }
        // Boundaries after `off`, for the run length.
        let mut next = self.volume_size;
        let mut bound = |b: u64| {
            if b > off && b < next {
                next = b;
            }
        };
        let encrypted = |o: u64| o < self.encrypted_size;
        if off < self.reloc_len {
            let phys = self.reloc_offset + off;
            bound(self.reloc_len);
            bound(self.encrypted_size.saturating_sub(self.reloc_offset));
            let run = (next - off) / bps;
            return Some((
                Source::Disk {
                    unit: phys / bps,
                    encrypted: encrypted(phys),
                },
                run,
            ));
        }
        let hidden = [
            (self.reloc_offset, self.reloc_len),
            (self.metadata_offsets[0], REGION_SIZE),
            (self.metadata_offsets[1], REGION_SIZE),
            (self.metadata_offsets[2], REGION_SIZE),
        ];
        for (o, l) in hidden {
            if off >= o && off < o + l {
                bound(o + l);
                return Some((Source::Zero, (next - off) / bps));
            }
            bound(o);
        }
        bound(self.encrypted_size);
        Some((
            Source::Disk {
                unit,
                encrypted: encrypted(off),
            },
            (next - off) / bps,
        ))
    }

    /// The non-data regions as `(start, length)` in 512-byte sectors, for
    /// `PG_VOLUME_ADD` (INTERFACES.md §10.2): `[0, reloc_len)`, the
    /// relocated copy, the three metadata regions.
    pub fn reserved_ranges(&self) -> [(u64, u64); 5] {
        let s = |o: u64, l: u64| (o / 512, l / 512);
        [
            s(0, self.reloc_len),
            s(self.reloc_offset, self.reloc_len),
            s(self.metadata_offsets[0], REGION_SIZE),
            s(self.metadata_offsets[1], REGION_SIZE),
            s(self.metadata_offsets[2], REGION_SIZE),
        ]
    }

    /// The handoff record (INTERFACES.md §8): byte offsets and sizes, the
    /// relocated length in 512-byte sectors.
    pub fn fve_layout(&self) -> crate::handoff::FveLayout {
        crate::handoff::FveLayout {
            metadata_offsets: self.metadata_offsets,
            region_size: REGION_SIZE,
            boot_sector_reloc_offset: self.reloc_offset,
            boot_sector_reloc_sectors: u32::try_from(self.reloc_len / 512).unwrap_or(u32::MAX),
            encrypted_size: self.encrypted_size,
        }
    }
}
