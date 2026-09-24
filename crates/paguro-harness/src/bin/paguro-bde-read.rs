//! paguro's BitLocker reader as a host tool: the differential side of
//! `test/fixtures/bde/diff.sh` (INTERFACES.md §12.2 "three implementations
//! agree"), and a way to look at a volume the way the loader does.
//!
//! ```text
//! paguro-bde-read --input vol.img
//!     [--password PW | --recovery DIGITS | --clear-key | --startup-key F.BEK]
//!     [--info]              bdeinfo-style summary on stdout (no key needed)
//!     [--output plain.img]  the decrypted view (needs a key)
//!     [--sparse out.bin]    the sectors a metadata-level test needs
//! ```
//!
//! Everything goes through `paguro_core::bde` and `paguro_boot::bde`, the
//! code the loader runs; nothing here re-implements the format.
#![allow(clippy::indexing_slicing)]

use std::fs::File;
use std::io::Write;
use std::os::unix::fs::FileExt;
use std::process::exit;

use paguro_boot::bde::{
    DecryptingReader, ReadError, UnitRead, unlock_fvek, vmk_from_clear_key, vmk_from_password,
    vmk_from_recovery, vmk_from_startup_key,
};
use paguro_boot::volume::parse_recovery_password;
use paguro_core::bde::{self, Cipher, Layout, Metadata, ProtectorKind};
use paguro_core::guid::Guid;

fn die(msg: &str) -> ! {
    eprintln!("paguro-bde-read: {msg}");
    exit(1)
}

struct Img(File, u32);

impl UnitRead for Img {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        self.0
            .read_exact_at(buf, unit * u64::from(self.1))
            .map_err(|_| ReadError::Io)
    }
}

fn method(c: Cipher) -> String {
    match c {
        Cipher::XtsAes128 => "AES-XTS 128-bit".into(),
        Cipher::XtsAes256 => "AES-XTS 256-bit".into(),
        Cipher::CbcDiffuser128 => "AES-CBC 128-bit with Diffuser".into(),
        Cipher::CbcDiffuser256 => "AES-CBC 256-bit with Diffuser".into(),
        Cipher::Cbc128 => "AES-CBC 128-bit".into(),
        Cipher::Cbc256 => "AES-CBC 256-bit".into(),
        Cipher::Unknown(v) => format!("Unknown (0x{v:04x})"),
    }
}

fn kind(k: ProtectorKind) -> String {
    match k {
        ProtectorKind::ClearKey => "Clear key".into(),
        ProtectorKind::Tpm => "TPM".into(),
        ProtectorKind::StartupKey => "Startup key".into(),
        ProtectorKind::TpmPin => "TPM and PIN".into(),
        ProtectorKind::RecoveryPassword => "Recovery password".into(),
        ProtectorKind::Password => "Password".into(),
        ProtectorKind::SmartCard => "Unknown (0x1000)".into(),
        ProtectorKind::Other(v) => format!("Unknown (0x{v:04x})"),
    }
}

fn utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u)
}

fn main() {
    let mut a = std::env::args().skip(1);
    let (mut input, mut output, mut sparse) = (None, None, None);
    let (mut pw, mut rp, mut clear, mut bek, mut info) = (None, None, false, None, false);
    while let Some(k) = a.next() {
        match k.as_str() {
            "--input" => input = a.next(),
            "--output" => output = a.next(),
            "--sparse" => sparse = a.next(),
            "--password" => pw = a.next(),
            "--recovery" => rp = a.next(),
            "--clear-key" => clear = true,
            "--startup-key" => bek = a.next(),
            "--info" => info = true,
            _ => die(&format!("unknown option {k}")),
        }
    }
    let input = input.unwrap_or_else(|| die("--input is required"));
    let f = File::open(&input).unwrap_or_else(|e| die(&format!("{input}: {e}")));
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut first = vec![0u8; 4096];
    f.read_exact_at(&mut first, 0)
        .unwrap_or_else(|e| die(&format!("read: {e}")));
    let hdr =
        bde::parse_volume_header(&first).unwrap_or_else(|e| die(&format!("volume header: {e:?}")));
    let mut regions = [
        vec![0u8; bde::REGION_SIZE as usize],
        vec![0u8; bde::REGION_SIZE as usize],
        vec![0u8; bde::REGION_SIZE as usize],
    ];
    for (r, o) in regions.iter_mut().zip(hdr.metadata_offsets) {
        f.read_exact_at(r, o)
            .unwrap_or_else(|e| die(&format!("metadata at {o:#x}: {e}")));
    }
    if let Some(path) = &sparse {
        // magic | volume size u64 | then (offset u64, len u32, bytes)*: the
        // first sector, each copy's block and validation, and the first
        // relocated 8 KiB (the boot sectors). Taken before any validation, so refused
        // volumes make fixtures too.
        let mut out = b"PGBDESP1".to_vec();
        out.extend(size.to_le_bytes());
        let bps = u64::from(hdr.bytes_per_sector);
        let mut put = |o: u64, len: u64| {
            let len = len.min(size.saturating_sub(o));
            let mut b = vec![0u8; len as usize];
            f.read_exact_at(&mut b, o)
                .unwrap_or_else(|e| die(&format!("sparse read: {e}")));
            out.extend(o.to_le_bytes());
            out.extend((len as u32).to_le_bytes());
            out.extend(b);
        };
        put(0, bps);
        for (r, o) in regions.iter().zip(hdr.metadata_offsets) {
            // block (size field × 16) + validation header + one CCM entry
            let used = u64::from(u16::from_le_bytes([r[8], r[9]])) * 16 + 8 + 0x60;
            put(o, used.div_ceil(bps).min(bde::REGION_SIZE / bps) * bps);
        }
        let reloc = u64::from_le_bytes(regions[0][56..64].try_into().unwrap_or([0; 8]));
        if reloc != 0 && reloc % bps == 0 && reloc + 8192 <= size {
            put(reloc, 8192);
        }
        std::fs::write(path, out).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    }

    let block = bde::cross_check([&regions[0], &regions[1], &regions[2]], &hdr)
        .unwrap_or_else(|e| die(&format!("metadata: {e:?}")));
    let m = Metadata::parse(block).unwrap_or_else(|e| die(&format!("entries: {e:?}")));

    if info {
        println!("Volume identifier\t: {}", Guid(m.block.volume_id));
        println!("Size\t: {size}");
        println!("Encryption method\t: {}", method(m.block.cipher));
        if let Some(d) = m.description {
            println!("Description\t: {}", utf16(d));
        }
        println!("Number of key protectors\t: {}", m.protectors().count());
        for (i, p) in m.protectors().enumerate() {
            println!("Key protector {i}:");
            println!("Identifier\t: {}", Guid(p.id));
            println!("Type\t: {}", kind(p.kind));
        }
    }

    let Some(out) = output else { return };
    let vmk = if let Some(p) = &pw {
        vmk_from_password(&m, p)
    } else if let Some(r) = &rp {
        let k = parse_recovery_password(r.as_bytes())
            .unwrap_or_else(|e| die(&format!("recovery password: {e:?}")));
        vmk_from_recovery(&m, &k)
    } else if clear {
        vmk_from_clear_key(&m)
    } else if let Some(b) = &bek {
        let data = std::fs::read(b).unwrap_or_else(|e| die(&format!("{b}: {e}")));
        let sk =
            bde::parse_startup_key(&data).unwrap_or_else(|e| die(&format!("startup key: {e:?}")));
        vmk_from_startup_key(&m, &sk)
    } else {
        die("--output needs a key")
    };
    let vmk = vmk
        .unwrap_or_else(|e| die(&format!("protector: {e:?}")))
        .unwrap_or_else(|| die("no protector accepted the key"));
    let layout = Layout::new(&hdr, &m, size).unwrap_or_else(|e| die(&format!("layout: {e:?}")));
    let fvek = unlock_fvek(&m, &vmk)
        .unwrap_or_else(|e| die(&format!("FVEK: {e:?}")))
        .unwrap_or_else(|| die("the VMK does not open the FVEK"));
    let xts = fvek.xts().unwrap_or_else(|| die("FVEK length"));
    let bps = layout.bytes_per_sector;
    let mut r = DecryptingReader::new(Img(f, bps), layout, &xts);
    let mut w = File::create(&out).unwrap_or_else(|e| die(&format!("{out}: {e}")));
    let units = r.units();
    let per = (1 << 20) / u64::from(bps);
    let mut buf = vec![0u8; 1 << 20];
    let mut u = 0;
    while u < units {
        let n = per.min(units - u);
        let b = &mut buf[..(n * u64::from(bps)) as usize];
        r.read(u, b)
            .unwrap_or_else(|e| die(&format!("read unit {u}: {e:?}")));
        w.write_all(b)
            .unwrap_or_else(|e| die(&format!("{out}: {e}")));
        u += n;
    }
}
