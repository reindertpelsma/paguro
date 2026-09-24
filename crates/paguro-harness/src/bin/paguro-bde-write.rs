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

use paguro_crypto::bitlocker::{Xts, ccm_wrap};
use sha2::{Digest, Sha256};

const REGION: u64 = 0x1_0000;
const RELOC_LEN: u64 = 0x2000;
const GUID_NORMAL: [u8; 16] = [
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
        for chunk in out.chunks_mut(32) {
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
    let size = u16::try_from(8 + data.len()).unwrap_or_else(|_| die("entry too large"));
    let mut v = Vec::with_capacity(usize::from(size));
    v.extend(size.to_le_bytes());
    v.extend(entry_type.to_le_bytes());
    v.extend(value_type.to_le_bytes());
    v.extend(1u16.to_le_bytes());
    v.extend(data);
    v
}

fn key_entry(method: u32, key: &[u8]) -> Vec<u8> {
    let mut d = method.to_le_bytes().to_vec();
    d.extend(key);
    entry(0, 1, &d)
}

struct Nonces {
    next: u32,
}

impl Nonces {
    fn take(&mut self) -> [u8; 12] {
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&FILETIME.to_le_bytes());
        n[8..].copy_from_slice(&self.next.to_le_bytes());
        self.next += 1;
        n
    }
}

/// An AES-CCM entry wrapping `plain` under `key`.
fn ccm_entry(entry_type: u16, key: &[u8; 32], plain: &[u8], nonces: &mut Nonces) -> Vec<u8> {
    let nonce = nonces.take();
    let mut ct = plain.to_vec();
    let tag = ccm_wrap(key, &nonce, &mut ct);
    let mut d = nonce.to_vec();
    d.extend(tag);
    d.extend(ct);
    entry(entry_type, 5, &d)
}

fn vmk_entry(id: [u8; 16], protection: u16, nested: &[u8]) -> Vec<u8> {
    let mut d = id.to_vec();
    d.extend(FILETIME.to_le_bytes());
    d.extend(0u16.to_le_bytes());
    d.extend(protection.to_le_bytes());
    d.extend(nested);
    entry(2, 8, &d)
}

fn stretch(initial: &[u8; 32], salt: &[u8; 16]) -> [u8; 32] {
    paguro_crypto::bitlocker_stretch(initial, salt, paguro_crypto::STRETCH_ITERATIONS)
}

fn recovery_key(digits: &str) -> [u8; 16] {
    let d: Vec<u32> = digits
        .chars()
        .filter(char::is_ascii_digit)
        .map(|c| c.to_digit(10).unwrap_or(0))
        .collect();
    if d.len() != 48 {
        die("a recovery password has 48 digits");
    }
    let mut k = [0u8; 16];
    for (g, chunk) in d.chunks(6).enumerate() {
        let v = chunk.iter().fold(0u32, |a, &x| a * 10 + x);
        if v % 11 != 0 || v >= 720_896 {
            die("recovery password group not divisible by 11 or too large");
        }
        k[2 * g..2 * g + 2].copy_from_slice(&((v / 11) as u16).to_le_bytes());
    }
    k
}

fn recovery_digits(key: &[u8; 16]) -> String {
    key.chunks(2)
        .map(|c| format!("{:06}", u32::from(u16::from_le_bytes([c[0], c[1]])) * 11))
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
                0xedb8_8320 ^ (c >> 1)
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
        let v = u16::from_le_bytes([plain[11], plain[12]]);
        if &plain[3..11] == b"NTFS    " {
            u32::from(v)
        } else {
            512
        }
    });
    if bps != 512 && bps != 4096 {
        die("sector size must be 512 or 4096");
    }
    let b = u64::from(bps);
    if size % b != 0 || size < 4 * REGION + RELOC_LEN {
        die("image size must be a multiple of the sector size and at least 264 KiB");
    }
    let md = o.metadata.unwrap_or_else(|| {
        let at = |f: u64| (size * f / 8) & !(REGION - 1);
        [at(1), at(3), at(5)]
    });
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
    let vmk: [u8; 32] = rng.bytes();
    let fvek: Vec<u8> = {
        let mut k = vec![0u8; if o.xts256 { 64 } else { 32 }];
        rng.fill(&mut k);
        k
    };
    let cipher: u16 = if o.xts256 { 0x8005 } else { 0x8004 };
    let volume_id: [u8; 16] = rng.bytes();
    let mut nonces = Nonces { next: 1 };
    let mut keys_out = String::new();
    keys_out += &format!("vmk {}\nfvek {}\n", hex(&vmk), hex(&fvek));

    // Protectors, each wrapping the same VMK key entry.
    let vmk_plain = key_entry(0x2003, &vmk);
    let mut entries = entry(7, 2, &utf16z("PAGURO-TEST paguro-bde-write"));
    if let Some(pw) = &o.password {
        let salt: [u8; 16] = rng.bytes();
        let mut inner = Sha256::new();
        for u in pw.encode_utf16() {
            inner.update(u.to_le_bytes());
        }
        let h: [u8; 32] = Sha256::digest(inner.finalize()).into();
        let k = stretch(&h, &salt);
        let mut st = 0x1001u32.to_le_bytes().to_vec();
        st.extend(salt);
        let mut nested = entry(0, 3, &st);
        nested.extend(ccm_entry(0, &k, &vmk_plain, &mut nonces));
        entries.extend(vmk_entry(rng.bytes(), 0x2000, &nested));
        keys_out += &format!("password {pw}\n");
    }
    if let Some(r) = &o.recovery {
        // Any 16 bytes are a valid key: 65 535 × 11 < 720 896.
        let key = if r == "auto" {
            rng.bytes()
        } else {
            recovery_key(r)
        };
        let salt: [u8; 16] = rng.bytes();
        let k = stretch(&Sha256::digest(key).into(), &salt);
        let mut st = 0x1000u32.to_le_bytes().to_vec();
        st.extend(salt);
        let mut nested = entry(0, 3, &st);
        nested.extend(ccm_entry(0, &k, &vmk_plain, &mut nonces));
        entries.extend(vmk_entry(rng.bytes(), 0x0800, &nested));
        keys_out += &format!("recovery {}\n", recovery_digits(&key));
    }
    if o.clear_key {
        let ck: [u8; 32] = rng.bytes();
        let mut nested = key_entry(0x2000, &ck);
        nested.extend(ccm_entry(0, &ck, &vmk_plain, &mut nonces));
        entries.extend(vmk_entry(rng.bytes(), 0x0000, &nested));
        keys_out += "clear-key yes\n";
    }
    if let Some(path) = &o.startup_key {
        let id: [u8; 16] = rng.bytes();
        let ext: [u8; 32] = rng.bytes();
        let nested = ccm_entry(0, &ext, &vmk_plain, &mut nonces);
        entries.extend(vmk_entry(id, 0x0200, &nested));
        // The .BEK file: metadata header, then one startup-key entry.
        let mut ek = id.to_vec();
        ek.extend(FILETIME.to_le_bytes());
        ek.extend(entry(0, 2, &utf16z("ExternalKey")));
        ek.extend(key_entry(0x2002, &ext));
        let body = entry(6, 9, &ek);
        let total = (48 + body.len()) as u32;
        let mut bek = Vec::new();
        for v in [total, 1, 48, total] {
            bek.extend(v.to_le_bytes());
        }
        bek.extend(volume_id);
        bek.extend(1u32.to_le_bytes());
        bek.extend(0u32.to_le_bytes());
        bek.extend(FILETIME.to_le_bytes());
        bek.extend(body);
        fs::write(path, &bek).unwrap_or_else(|e| die(&format!("{path}: {e}")));
        keys_out += &format!("startup-key {path}\n");
    }
    let mut fvek_plain = u32::from(cipher).to_le_bytes().to_vec();
    fvek_plain.extend(&fvek);
    let fvek_plain = entry(0, 1, &fvek_plain);
    entries.extend(ccm_entry(3, &vmk, &fvek_plain, &mut nonces));
    let mut vhb = reloc.to_le_bytes().to_vec();
    vhb.extend(RELOC_LEN.to_le_bytes());
    entries.extend(entry(0xf, 0xf, &vhb));

    // Metadata header (48) + entries, block header (64) in front, padded
    // to 16 bytes.
    let msize = (48 + entries.len()) as u32;
    let bsize = (64 + msize as usize).div_ceil(16) * 16;
    let partial = enc < size;
    let mut blk = Vec::with_capacity(bsize);
    blk.extend(b"-FVE-FS-");
    blk.extend(((bsize / 16) as u16).to_le_bytes());
    blk.extend(2u16.to_le_bytes());
    let state: u16 = if partial { 5 } else { 4 };
    blk.extend(state.to_le_bytes());
    blk.extend(4u16.to_le_bytes());
    blk.extend(enc.to_le_bytes());
    blk.extend(0u32.to_le_bytes());
    blk.extend(((RELOC_LEN / b) as u32).to_le_bytes());
    for m in md {
        blk.extend(m.to_le_bytes());
    }
    blk.extend(reloc.to_le_bytes());
    for v in [msize, 1, 48, msize] {
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
    region.extend((if o.validation_v1 { 1u16 } else { 2 }).to_le_bytes());
    region.extend(crc32(&blk).to_le_bytes());
    if !o.validation_v1 {
        let digest: [u8; 32] = Sha256::digest(&blk).into();
        region.extend(ccm_entry(0, &vmk, &key_entry(0x2005, &digest), &mut nonces));
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
    h[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
    h[3..11].copy_from_slice(b"-FVE-FS-");
    h[11..13].copy_from_slice(&(bps as u16).to_le_bytes());
    h[13] = plain[13];
    h[21] = 0xf8;
    h[24..26].copy_from_slice(&0x3fu16.to_le_bytes());
    h[26..28].copy_from_slice(&0xffu16.to_le_bytes());
    h[28..32].copy_from_slice(&plain[28..32]);
    h[0x40..0x43].copy_from_slice(&[0x80, 0x00, 0x29]);
    h[0x47..0x5a].copy_from_slice(b"NO NAME    FAT32   ");
    h[160..176].copy_from_slice(&GUID_NORMAL);
    for (i, m) in md.iter().enumerate() {
        h[176 + 8 * i..184 + 8 * i].copy_from_slice(&m.to_le_bytes());
    }
    h[510..512].copy_from_slice(&[0x55, 0xaa]);
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
