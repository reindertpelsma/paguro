//! A test-only BitLocker volume writer (INTERFACES.md §12.2 fixtures).
//!
//! Linux cannot create BitLocker volumes, so this turns a plain image (an
//! NTFS made by `mkntfs`) into one, laid out the way Windows 7+ lays it out:
//! the FVE volume header in sector 0, the first 8 KiB relocated and
//! encrypted at `--reloc`, three identical metadata blocks with CRC-32 and
//! a VMK-wrapped SHA-256, XTS-AES-128/256 with tweak = sector index, and
//! plaintext past `--encrypted-size`. Trust comes from outside: every
//! volume it writes is decrypted by libbde and dislocker (`make.sh`), which
//! must both see the original filesystem.
//!
//! It is deliberately written from the format description, not from
//! `paguro_core::bde`: the reader under test and the writer share only the
//! primitives (`paguro_crypto::bitlocker`, validated by published vectors).
//!
//! ```text
//! paguro-bde-write --input plain.img --output out.img
//!     --metadata OFF,OFF,OFF --reloc OFF      (bytes; 64 KiB / 8 KiB, unused by the filesystem)
//!     [--sector-size 512|4096] [--cipher xts128|xts256]
//!     [--password PW] [--recovery 48-DIGITS|auto] [--clear-key] [--startup-key FILE.BEK]
//!     [--encrypted-size BYTES] [--validation-v1] [--seed N]
//!     [--expect expected-plaintext.img] [--keys keys.txt]
//! ```
#![allow(clippy::indexing_slicing)]

use std::fs;
use std::io::Write;
use std::process::exit;

use core::mem::offset_of;

use paguro_crypto::bitlocker::{Xts, ccm_wrap};
use sha2::{Digest, Sha256};

// Sizes (libbde "BitLocker Drive Encryption (BDE) format" §§4–5).
/// One FVE metadata region (block, validation, padding).
const REGION: u64 = 0x1_0000;
/// The boot sectors relocated (and encrypted) at `--reloc`.
const RELOC_LEN: u64 = 0x2000;
/// Sector sizes BitLocker supports.
const SECTOR_SIZES: [u32; 2] = [512, 4096];
/// Default sector size when the input is not an NTFS image.
const DEFAULT_SECTOR: u32 = 512;
/// Metadata regions at 1/8, 3/8 and 5/8 of the image by default.
const DEFAULT_METADATA_EIGHTHS: [u64; 3] = [1, 3, 5];
const SHA256_LEN: usize = 32;
const KEY_LEN: usize = 32;
const ID_LEN: usize = 16;
const SALT_LEN: usize = 16;
/// XTS-AES-128 / -256 take two AES keys.
const FVEK_XTS_128_LEN: usize = 32;
const FVEK_XTS_256_LEN: usize = 64;

// FVE metadata block header (libbde §5.1): version, and encryption states.
const BLOCK_HEADER_LEN: usize = 64;
const BLOCK_VERSION: u16 = 2;
/// The block's size is stored in 16-byte units; the block is padded to it.
const BLOCK_UNIT: usize = 16;
const STATE_ENCRYPTED: u16 = 4;
const STATE_PAUSED: u16 = 5;
// FVE metadata header (libbde §5.2).
const METADATA_HEADER_LEN: u32 = 48;
const METADATA_VERSION: u32 = 1;
/// The BEK file's metadata header: its next nonce counter.
const BEK_NEXT_NONCE: u32 = 1;
// Metadata validation (libbde §5.4): v1 is a CRC-32, v2 adds a SHA-256.
const VALIDATION_V1: u16 = 1;
const VALIDATION_V2: u16 = 2;

// FVE entry header: size | entry type | value type | version (libbde §5.3).
const ENTRY_HEADER_LEN: usize = 8;
const ENTRY_VERSION: u16 = 1;
// Entry types.
const ET_PROPERTY: u16 = 0x0000;
const ET_VMK: u16 = 0x0002;
const ET_FVEK: u16 = 0x0003;
const ET_STARTUP_KEY: u16 = 0x0006;
const ET_DESCRIPTION: u16 = 0x0007;
const ET_VOLUME_HEADER_BLOCK: u16 = 0x000f;
// Value types.
const VT_KEY: u16 = 0x0001;
const VT_UNICODE: u16 = 0x0002;
const VT_STRETCH_KEY: u16 = 0x0003;
const VT_AES_CCM: u16 = 0x0005;
const VT_VMK: u16 = 0x0008;
const VT_EXTERNAL_KEY: u16 = 0x0009;
const VT_OFFSET_AND_SIZE: u16 = 0x000f;
// VMK protection types (libbde §5.3.4).
const PROTECTION_CLEAR_KEY: u16 = 0x0000;
const PROTECTION_STARTUP_KEY: u16 = 0x0200;
const PROTECTION_RECOVERY_PASSWORD: u16 = 0x0800;
const PROTECTION_PASSWORD: u16 = 0x2000;
// Key and stretch-key encryption methods, by what each entry carries.
const METHOD_STRETCH_RECOVERY: u32 = 0x1000;
const METHOD_STRETCH_PASSWORD: u32 = 0x1001;
const METHOD_CLEAR_KEY: u32 = 0x2000;
const METHOD_EXTERNAL_KEY: u32 = 0x2002;
const METHOD_VMK: u32 = 0x2003;
const METHOD_VALIDATION: u32 = 0x2005;
// Data-encryption methods.
const CIPHER_XTS_AES_128: u16 = 0x8004;
const CIPHER_XTS_AES_256: u16 = 0x8005;

/// AES-CCM nonce: a FILETIME and a 32-bit counter.
const NONCE_LEN: usize = 12;
const NONCE_TIME_LEN: usize = 8;

// Recovery password: 8 groups of 6 digits, each 11 × a 16-bit key word.
const RECOVERY_DIGITS: usize = 48;
const RECOVERY_GROUP_DIGITS: usize = 6;
const RECOVERY_DIVISOR: u32 = 11;
const RECOVERY_GROUP_LIMIT: u32 = 0x1_0000 * RECOVERY_DIVISOR;

/// CRC-32 (IEEE 802.3), reflected polynomial.
const CRC32_POLY: u32 = 0xedb8_8320;

/// The FVE volume header in sector 0 (libbde §4.1): a FAT32-shaped boot
/// sector. Layout only, for `offset_of!`; the sector is built as bytes.
#[allow(dead_code)]
#[repr(C, packed)]
struct VolumeHeader {
    jump: [u8; 3],
    signature: [u8; 8],
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sectors: u16,
    fats: u8,
    root_entries: u16,
    sectors16: u16,
    media: u8,
    fat_size16: u16,
    sectors_per_track: u16,
    heads: u16,
    hidden_sectors: u32,
    sectors32: u32,
    fat32: [u8; 28],
    drive_number: u8,
    reserved1: u8,
    boot_signature: u8,
    volume_serial: u32,
    label: [u8; 11],
    fs_type: [u8; 8],
    boot_code: [u8; 70],
    identifier: [u8; ID_LEN],
    metadata_offsets: [u64; 3],
    boot_code2: [u8; 310],
    boot_sector_signature: [u8; 2],
}
const _: () = assert!(size_of::<VolumeHeader>() == 512);
const _: () = assert!(offset_of!(VolumeHeader, drive_number) == 0x40);
const _: () = assert!(offset_of!(VolumeHeader, label) == 0x47);
const _: () = assert!(offset_of!(VolumeHeader, identifier) == 160);
const _: () = assert!(offset_of!(VolumeHeader, metadata_offsets) == 176);
const _: () = assert!(offset_of!(VolumeHeader, boot_sector_signature) == 510);
const JUMP: [u8; 3] = [0xeb, 0x58, 0x90];
const SIGNATURE: &[u8; 8] = b"-FVE-FS-";
const NTFS_OEM: &[u8; 8] = b"NTFS    ";
/// The media descriptor, CHS geometry and extended-BPB bytes Windows writes.
const MEDIA_FIXED: u8 = 0xf8;
const SECTORS_PER_TRACK: u16 = 0x3f;
const HEADS: u16 = 0xff;
const DRIVE_BOOT_SIG: [u8; 3] = [0x80, 0x00, 0x29];
const LABEL_AND_FS_TYPE: &[u8; 19] = b"NO NAME    FAT32   ";
const BOOT_SECTOR_SIGNATURE: [u8; 2] = [0x55, 0xaa];

const GUID_NORMAL: [u8; ID_LEN] = [
    0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3, 0xd0, 0x01,
];
/// 2024-01-01T00:00:00Z as a FILETIME.
const FILETIME: u64 = 133_485_408_000_000_000;

fn die(msg: &str) -> ! {
    eprintln!("paguro-bde-write: {msg}");
    exit(2)
}

/// Deterministic bytes from the seed (SHA-256 in counter mode).
struct Rng {
    seed: u64,
    ctr: u64,
}

impl Rng {
    fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(SHA256_LEN) {
            let mut h = Sha256::new();
            h.update(b"paguro-bde-write");
            h.update(self.seed.to_le_bytes());
            h.update(self.ctr.to_le_bytes());
            self.ctr += 1;
            let d = h.finalize();
            chunk.copy_from_slice(&d[..chunk.len()]);
        }
    }
    fn bytes<const N: usize>(&mut self) -> [u8; N] {
        let mut b = [0u8; N];
        self.fill(&mut b);
        b
    }
}

/// One FVE entry: size | entry type | value type | version 1 | data.
fn entry(entry_type: u16, value_type: u16, data: &[u8]) -> Vec<u8> {
    let size =
        u16::try_from(ENTRY_HEADER_LEN + data.len()).unwrap_or_else(|_| die("entry too large"));
    let mut v = Vec::with_capacity(usize::from(size));
    v.extend(size.to_le_bytes());
    v.extend(entry_type.to_le_bytes());
    v.extend(value_type.to_le_bytes());
    v.extend(ENTRY_VERSION.to_le_bytes());
    v.extend(data);
    v
}

fn key_entry(method: u32, key: &[u8]) -> Vec<u8> {
    let mut d = method.to_le_bytes().to_vec();
    d.extend(key);
    entry(ET_PROPERTY, VT_KEY, &d)
}

struct Nonces {
    next: u32,
}

impl Nonces {
    fn take(&mut self) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        n[..NONCE_TIME_LEN].copy_from_slice(&FILETIME.to_le_bytes());
        n[NONCE_TIME_LEN..].copy_from_slice(&self.next.to_le_bytes());
        self.next += 1;
        n
    }
}

/// An AES-CCM entry wrapping `plain` under `key`.
fn ccm_entry(entry_type: u16, key: &[u8; KEY_LEN], plain: &[u8], nonces: &mut Nonces) -> Vec<u8> {
    let nonce = nonces.take();
    let mut ct = plain.to_vec();
    let tag = ccm_wrap(key, &nonce, &mut ct);
    let mut d = nonce.to_vec();
    d.extend(tag);
    d.extend(ct);
    entry(entry_type, VT_AES_CCM, &d)
}

fn vmk_entry(id: [u8; ID_LEN], protection: u16, nested: &[u8]) -> Vec<u8> {
    let mut d = id.to_vec();
    d.extend(FILETIME.to_le_bytes());
    d.extend(0u16.to_le_bytes()); // unknown, zero
    d.extend(protection.to_le_bytes());
    d.extend(nested);
    entry(ET_VMK, VT_VMK, &d)
}

fn stretch(initial: &[u8; SHA256_LEN], salt: &[u8; SALT_LEN]) -> [u8; KEY_LEN] {
    paguro_crypto::bitlocker_stretch(initial, salt, paguro_crypto::STRETCH_ITERATIONS)
}

fn recovery_key(digits: &str) -> [u8; ID_LEN] {
    let d: Vec<u32> = digits
        .chars()
        .filter(char::is_ascii_digit)
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();
    if d.len() != RECOVERY_DIGITS {
        die("a recovery password has 48 digits");
    }
    let mut k = [0u8; ID_LEN];
    for (g, chunk) in d.chunks(RECOVERY_GROUP_DIGITS).enumerate() {
        let v = chunk.iter().fold(0u32, |a, &x| a * 10 + x);
        if v % RECOVERY_DIVISOR != 0 || v >= RECOVERY_GROUP_LIMIT {
            die("recovery password group not divisible by 11 or too large");
        }
        k[2 * g..2 * g + 2].copy_from_slice(&((v / RECOVERY_DIVISOR) as u16).to_le_bytes());
    }
    k
}

fn recovery_digits(key: &[u8; ID_LEN]) -> String {
    key.chunks(2)
        .map(|c| {
            format!(
                "{:06}",
                u32::from(u16::from_le_bytes([c[0], c[1]])) * RECOVERY_DIVISOR
            )
        })
        .collect::<Vec<_>>()
        .join("-")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn crc32(data: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in data {
        c ^= u32::from(b);
        for _ in 0..8 {
            c = if c & 1 != 0 {
                CRC32_POLY ^ (c >> 1)
            } else {
                c >> 1
            };
        }
    }
    !c
}

#[derive(Default)]
struct Opts {
    input: String,
    output: String,
    metadata: Option<[u64; 3]>,
    reloc: Option<u64>,
    sector: Option<u32>,
    xts256: bool,
    password: Option<String>,
    recovery: Option<String>,
    clear_key: bool,
    startup_key: Option<String>,
    encrypted_size: Option<u64>,
    validation_v1: bool,
    seed: u64,
    expect: Option<String>,
    keys: Option<String>,
}

fn parse_args() -> Opts {
    let mut o = Opts::default();
    let mut a = std::env::args().skip(1);
    let num = |s: Option<String>| -> u64 {
        let s = s.unwrap_or_else(|| die("missing value"));
        let r = if let Some(h) = s.strip_prefix("0x") {
            u64::from_str_radix(h, 16)
        } else {
            s.parse()
        };
        r.unwrap_or_else(|_| die(&format!("not a number: {s}")))
    };
    while let Some(k) = a.next() {
        match k.as_str() {
            "--input" => o.input = a.next().unwrap_or_default(),
            "--output" => o.output = a.next().unwrap_or_default(),
            "--metadata" => {
                let v: Vec<u64> = a
                    .next()
                    .unwrap_or_default()
                    .split(',')
                    .map(|s| num(Some(s.to_string())))
                    .collect();
                o.metadata = Some(
                    v.try_into()
                        .unwrap_or_else(|_| die("--metadata takes 3 offsets")),
                );
            }
            "--reloc" => o.reloc = Some(num(a.next())),
            "--sector-size" => o.sector = Some(num(a.next()) as u32),
            "--cipher" => match a.next().as_deref() {
                Some("xts128") => o.xts256 = false,
                Some("xts256") => o.xts256 = true,
                _ => die("--cipher xts128|xts256"),
            },
            "--password" => o.password = a.next(),
            "--recovery" => o.recovery = a.next(),
            "--clear-key" => o.clear_key = true,
            "--startup-key" => o.startup_key = a.next(),
            "--encrypted-size" => o.encrypted_size = Some(num(a.next())),
            "--validation-v1" => o.validation_v1 = true,
            "--seed" => o.seed = num(a.next()),
            "--expect" => o.expect = a.next(),
            "--keys" => o.keys = a.next(),
            "-h" | "--help" => {
                let usage: Vec<&str> = include_str!("paguro-bde-write.rs")
                    .lines()
                    .skip_while(|l| !l.starts_with("//! ```text"))
                    .skip(1)
                    .take_while(|l| !l.starts_with("//! ```"))
                    .collect();
                eprintln!("{}", usage.join("\n").replace("//! ", ""));
                exit(0)
            }
            _ => die(&format!("unknown option {k}")),
        }
    }
    if o.input.is_empty() || o.output.is_empty() {
        die("--input and --output are required");
    }
    o
}

fn main() {
    let o = parse_args();
    let mut plain = fs::read(&o.input).unwrap_or_else(|e| die(&format!("{}: {e}", o.input)));
    let size = plain.len() as u64;
    let bps = o.sector.unwrap_or_else(|| {
        let bps_at = offset_of!(VolumeHeader, bytes_per_sector);
        let oem_at = offset_of!(VolumeHeader, signature);
        let v = u16::from_le_bytes([plain[bps_at], plain[bps_at + 1]]);
        if &plain[oem_at..oem_at + NTFS_OEM.len()] == NTFS_OEM {
            u32::from(v)
        } else {
            DEFAULT_SECTOR
        }
    });
    if !SECTOR_SIZES.contains(&bps) {
        die("sector size must be 512 or 4096");
    }
    let b = u64::from(bps);
    if size % b != 0 || size < 4 * REGION + RELOC_LEN {
        die("image size must be a multiple of the sector size and at least 264 KiB");
    }
    let md = o
        .metadata
        .unwrap_or_else(|| DEFAULT_METADATA_EIGHTHS.map(|f| (size * f / 8) & !(REGION - 1)));
    let reloc = o.reloc.unwrap_or(md[0] + REGION);
    let enc = o.encrypted_size.unwrap_or(size);
    let regions = [
        (0, RELOC_LEN),
        (reloc, RELOC_LEN),
        (md[0], REGION),
        (md[1], REGION),
        (md[2], REGION),
    ];
    for (i, &(a, l)) in regions.iter().enumerate() {
        if a % b != 0 || a + l > size {
            die("regions must be sector-aligned and inside the image");
        }
        for &(c, m) in &regions[i + 1..] {
            if a < c + m && c < a + l {
                die("regions overlap");
            }
        }
    }
    if enc > size || enc % b != 0 {
        die("--encrypted-size must be a whole number of sectors within the image");
    }
    if o.password.is_none() && o.recovery.is_none() && !o.clear_key && o.startup_key.is_none() {
        die("at least one protector is required");
    }

    let mut rng = Rng {
        seed: o.seed,
        ctr: 0,
    };
    let vmk: [u8; KEY_LEN] = rng.bytes();
    let fvek: Vec<u8> = {
        let mut k = vec![
            0u8;
            if o.xts256 {
                FVEK_XTS_256_LEN
            } else {
                FVEK_XTS_128_LEN
            }
        ];
        rng.fill(&mut k);
        k
    };
    let cipher: u16 = if o.xts256 {
        CIPHER_XTS_AES_256
    } else {
        CIPHER_XTS_AES_128
    };
    let volume_id: [u8; ID_LEN] = rng.bytes();
    let mut nonces = Nonces { next: 1 };
    let mut keys_out = String::new();
    keys_out += &format!("vmk {}\nfvek {}\n", hex(&vmk), hex(&fvek));

    // Protectors, each wrapping the same VMK key entry.
    let vmk_plain = key_entry(METHOD_VMK, &vmk);
    let mut entries = entry(
        ET_DESCRIPTION,
        VT_UNICODE,
        &utf16z("PAGURO-TEST paguro-bde-write"),
    );
    if let Some(pw) = &o.password {
        let salt: [u8; SALT_LEN] = rng.bytes();
        let mut inner = Sha256::new();
        for u in pw.encode_utf16() {
            inner.update(u.to_le_bytes());
        }
        let h: [u8; SHA256_LEN] = Sha256::digest(inner.finalize()).into();
        let k = stretch(&h, &salt);
        let mut st = METHOD_STRETCH_PASSWORD.to_le_bytes().to_vec();
        st.extend(salt);
        let mut nested = entry(ET_PROPERTY, VT_STRETCH_KEY, &st);
        nested.extend(ccm_entry(ET_PROPERTY, &k, &vmk_plain, &mut nonces));
        entries.extend(vmk_entry(rng.bytes(), PROTECTION_PASSWORD, &nested));
        keys_out += &format!("password {pw}\n");
    }
    if let Some(r) = &o.recovery {
        // Any 16 bytes are a valid key: 65 535 × 11 < 720 896.
        let key = if r == "auto" {
            rng.bytes()
        } else {
            recovery_key(r)
        };
        let salt: [u8; SALT_LEN] = rng.bytes();
        let k = stretch(&Sha256::digest(key).into(), &salt);
        let mut st = METHOD_STRETCH_RECOVERY.to_le_bytes().to_vec();
        st.extend(salt);
        let mut nested = entry(ET_PROPERTY, VT_STRETCH_KEY, &st);
        nested.extend(ccm_entry(ET_PROPERTY, &k, &vmk_plain, &mut nonces));
        entries.extend(vmk_entry(
            rng.bytes(),
            PROTECTION_RECOVERY_PASSWORD,
            &nested,
        ));
        keys_out += &format!("recovery {}\n", recovery_digits(&key));
    }
    if o.clear_key {
        let ck: [u8; KEY_LEN] = rng.bytes();
        let mut nested = key_entry(METHOD_CLEAR_KEY, &ck);
        nested.extend(ccm_entry(ET_PROPERTY, &ck, &vmk_plain, &mut nonces));
        entries.extend(vmk_entry(rng.bytes(), PROTECTION_CLEAR_KEY, &nested));
        keys_out += "clear-key yes\n";
    }
    if let Some(path) = &o.startup_key {
        let id: [u8; ID_LEN] = rng.bytes();
        let ext: [u8; KEY_LEN] = rng.bytes();
        let nested = ccm_entry(ET_PROPERTY, &ext, &vmk_plain, &mut nonces);
        entries.extend(vmk_entry(id, PROTECTION_STARTUP_KEY, &nested));
        // The .BEK file: metadata header, then one startup-key entry.
        let mut ek = id.to_vec();
        ek.extend(FILETIME.to_le_bytes());
        ek.extend(entry(ET_PROPERTY, VT_UNICODE, &utf16z("ExternalKey")));
        ek.extend(key_entry(METHOD_EXTERNAL_KEY, &ext));
        let body = entry(ET_STARTUP_KEY, VT_EXTERNAL_KEY, &ek);
        let total = METADATA_HEADER_LEN + body.len() as u32;
        let mut bek = Vec::new();
        // Metadata header: size | version | header size | copy size.
        for v in [total, METADATA_VERSION, METADATA_HEADER_LEN, total] {
            bek.extend(v.to_le_bytes());
        }
        bek.extend(volume_id);
        bek.extend(BEK_NEXT_NONCE.to_le_bytes());
        bek.extend(0u32.to_le_bytes()); // encryption method: none
        bek.extend(FILETIME.to_le_bytes());
        bek.extend(body);
        fs::write(path, &bek).unwrap_or_else(|e| die(&format!("{path}: {e}")));
        keys_out += &format!("startup-key {path}\n");
    }
    let mut fvek_plain = u32::from(cipher).to_le_bytes().to_vec();
    fvek_plain.extend(&fvek);
    let fvek_plain = entry(ET_PROPERTY, VT_KEY, &fvek_plain);
    entries.extend(ccm_entry(ET_FVEK, &vmk, &fvek_plain, &mut nonces));
    let mut vhb = reloc.to_le_bytes().to_vec();
    vhb.extend(RELOC_LEN.to_le_bytes());
    entries.extend(entry(ET_VOLUME_HEADER_BLOCK, VT_OFFSET_AND_SIZE, &vhb));

    // Metadata header + entries, block header in front, padded to
    // BLOCK_UNIT bytes.
    let msize = METADATA_HEADER_LEN + entries.len() as u32;
    let bsize = (BLOCK_HEADER_LEN + msize as usize).div_ceil(BLOCK_UNIT) * BLOCK_UNIT;
    let partial = enc < size;
    let mut blk = Vec::with_capacity(bsize);
    // Block header: signature | size/16 | version | state | next state |
    // encrypted size | convert size | volume header sectors | metadata
    // offsets ×3 | volume header offset.
    blk.extend(SIGNATURE);
    blk.extend(((bsize / BLOCK_UNIT) as u16).to_le_bytes());
    blk.extend(BLOCK_VERSION.to_le_bytes());
    let state: u16 = if partial {
        STATE_PAUSED
    } else {
        STATE_ENCRYPTED
    };
    blk.extend(state.to_le_bytes());
    blk.extend(STATE_ENCRYPTED.to_le_bytes());
    blk.extend(enc.to_le_bytes());
    blk.extend(0u32.to_le_bytes());
    blk.extend(((RELOC_LEN / b) as u32).to_le_bytes());
    for m in md {
        blk.extend(m.to_le_bytes());
    }
    blk.extend(reloc.to_le_bytes());
    // Metadata header: size | version | header size | copy size | volume
    // GUID | next nonce counter | encryption method ×2 | creation time.
    for v in [msize, METADATA_VERSION, METADATA_HEADER_LEN, msize] {
        blk.extend(v.to_le_bytes());
    }
    blk.extend(volume_id);
    blk.extend(nonces.next.saturating_add(1).to_le_bytes());
    blk.extend(cipher.to_le_bytes());
    blk.extend(cipher.to_le_bytes());
    blk.extend(FILETIME.to_le_bytes());
    blk.extend(&entries);
    blk.resize(bsize, 0);
    // Validation: size (to the region's end) | version | CRC-32, then (v2)
    // the block's SHA-256 wrapped under the VMK.
    let mut region = blk.clone();
    region.extend(((REGION as usize - bsize) as u16).to_le_bytes());
    region.extend(
        (if o.validation_v1 {
            VALIDATION_V1
        } else {
            VALIDATION_V2
        })
        .to_le_bytes(),
    );
    region.extend(crc32(&blk).to_le_bytes());
    if !o.validation_v1 {
        let digest: [u8; SHA256_LEN] = Sha256::digest(&blk).into();
        region.extend(ccm_entry(
            ET_PROPERTY,
            &vmk,
            &key_entry(METHOD_VALIDATION, &digest),
            &mut nonces,
        ));
    }
    region.resize(REGION as usize, 0);

    // The expected decrypted view: the plaintext with the non-data regions
    // zeroed (what libbde and dislocker return).
    for &(a, l) in &regions[1..] {
        plain[a as usize..(a + l) as usize].fill(0);
    }
    // Relocated sectors keep the original boot sectors; nothing else moves.
    let mut out = plain.clone();
    let xts = Xts::new(&fvek).unwrap_or_else(|_| die("bad FVEK length"));
    let units = size / b;
    let bu = b as usize;
    let crypt = |buf: &mut [u8], unit: u64| {
        if unit * b < enc {
            xts.encrypt(u128::from(unit), buf)
                .unwrap_or_else(|_| die("xts"));
        }
    };
    for u in 0..units {
        let at = (u * b) as usize;
        crypt(&mut out[at..at + bu], u);
    }
    for u in 0..RELOC_LEN / b {
        let src = (u * b) as usize;
        let dst_unit = reloc / b + u;
        let dst = (dst_unit * b) as usize;
        let mut s = plain[src..src + bu].to_vec();
        crypt(&mut s, dst_unit);
        out[dst..dst + bu].copy_from_slice(&s);
    }
    for m in md {
        out[m as usize..(m + REGION) as usize].copy_from_slice(&region);
    }
    // The FVE volume header in sector 0: the BPB Windows writes, the
    // BitLocker identifier and the three metadata offsets.
    let mut h = vec![0u8; bu];
    let mut put = |at: usize, v: &[u8]| h[at..at + v.len()].copy_from_slice(v);
    put(offset_of!(VolumeHeader, jump), &JUMP);
    put(offset_of!(VolumeHeader, signature), SIGNATURE);
    put(
        offset_of!(VolumeHeader, bytes_per_sector),
        &(bps as u16).to_le_bytes(),
    );
    let spc = offset_of!(VolumeHeader, sectors_per_cluster);
    put(spc, &plain[spc..spc + 1]);
    put(offset_of!(VolumeHeader, media), &[MEDIA_FIXED]);
    put(
        offset_of!(VolumeHeader, sectors_per_track),
        &SECTORS_PER_TRACK.to_le_bytes(),
    );
    put(offset_of!(VolumeHeader, heads), &HEADS.to_le_bytes());
    let hidden = offset_of!(VolumeHeader, hidden_sectors);
    put(hidden, &plain[hidden..hidden + size_of::<u32>()]);
    put(offset_of!(VolumeHeader, drive_number), &DRIVE_BOOT_SIG);
    put(offset_of!(VolumeHeader, label), LABEL_AND_FS_TYPE);
    put(offset_of!(VolumeHeader, identifier), &GUID_NORMAL);
    for (i, m) in md.iter().enumerate() {
        put(
            offset_of!(VolumeHeader, metadata_offsets) + size_of::<u64>() * i,
            &m.to_le_bytes(),
        );
    }
    put(
        offset_of!(VolumeHeader, boot_sector_signature),
        &BOOT_SECTOR_SIGNATURE,
    );
    out[..bu].copy_from_slice(&h);

    let mut f = fs::File::create(&o.output).unwrap_or_else(|e| die(&format!("{}: {e}", o.output)));
    f.write_all(&out)
        .unwrap_or_else(|e| die(&format!("{}: {e}", o.output)));
    if let Some(p) = &o.expect {
        fs::write(p, &plain).unwrap_or_else(|e| die(&format!("{p}: {e}")));
    }
    keys_out += &format!(
        "sector-size {bps}\ncipher {}\nmetadata {:#x},{:#x},{:#x}\nreloc {reloc:#x}\nencrypted-size {enc}\n",
        if o.xts256 { "xts256" } else { "xts128" },
        md[0],
        md[1],
        md[2]
    );
    match &o.keys {
        Some(p) => fs::write(p, &keys_out).unwrap_or_else(|e| die(&format!("{p}: {e}"))),
        None => print!("{keys_out}"),
    }
}
