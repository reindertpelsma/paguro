//! The BitLocker reader on Windows-made volumes (INTERFACES.md §12.2):
//! metadata against bdeinfo, every protector the fixtures carry, the
//! decrypted boot sectors against dislocker/libbde, refusals, tampering
//! caught after unlock, the decrypted view against a model, and the whole
//! stage machine unlocking a real volume.
//!
//! The fixtures are `test/fixtures/bde/windows/*.sparse`: the sectors the
//! metadata level needs (first sector, the three metadata blocks, the first
//! relocated 8 KiB) of the cryptsetup and dfvfs volumes, with
//! `manifest.txt` recording what bdeinfo and the oracles said
//! (`test/fixtures/bde/diff.sh --update`). The whole-volume comparison is
//! `diff.sh` itself.
#![allow(clippy::indexing_slicing)]

mod mock;

use std::path::PathBuf;

use mock::*;
use paguro_boot::bde::*;
use paguro_boot::platform::{Input, Row};
use paguro_boot::volume::{Partition, Unimplemented, Volume, VolumeKind, parse_recovery_password};
use paguro_boot::{BootError, Buffers, Outcome};
use paguro_core::bde::{self as core, BdeError, Cipher, Layout, Metadata, ProtectorKind, Source};
use paguro_core::gpt;
use paguro_core::guid::{GPT_BASIC_DATA, Guid};
use paguro_core::handoff::Rung;
use paguro_crypto::bitlocker::{Xts, ccm_unwrap, ccm_wrap};
use proptest::prelude::*;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/bde/windows")
}

#[derive(Debug, Default, Clone)]
struct Fixture {
    name: String,
    size: u64,
    password: Option<String>,
    recovery: Vec<String>,
    startup_key: Option<String>,
    clear_key: bool,
    sha256: Option<String>,
    boot_sha256: Option<String>,
    refused: Option<String>,
    fields: Vec<String>,
}

fn manifest() -> Vec<Fixture> {
    let text = std::fs::read_to_string(dir().join("manifest.txt")).unwrap();
    let mut out = Vec::new();
    let mut f = Fixture::default();
    for l in text.lines().chain([""]) {
        if let Some(n) = l.strip_prefix('[') {
            f.name = n.trim_end_matches(']').into();
        } else if l.is_empty() {
            if !f.name.is_empty() {
                out.push(std::mem::take(&mut f));
            }
        } else if let Some((k, v)) = l.split_once('=') {
            let v = v.to_string();
            match k {
                "size" => f.size = v.parse().unwrap(),
                "password" => f.password = Some(v),
                "recovery" => f.recovery.push(v),
                "startup_key" => f.startup_key = Some(v),
                "clear_key" => f.clear_key = true,
                "sha256" => f.sha256 = Some(v),
                "boot_sha256" => f.boot_sha256 = Some(v),
                "refused" => f.refused = Some(v),
                _ => f.fields.push(l.to_string()),
            }
        }
    }
    assert!(out.len() >= 20, "manifest has {} fixtures", out.len());
    out
}

/// The whole volume, zeros where the sparse fixture has nothing.
fn volume(f: &Fixture) -> Vec<u8> {
    let s = std::fs::read(dir().join(format!("{}.sparse", f.name))).unwrap();
    assert_eq!(&s[..8], b"PGBDESP1");
    let size = u64::from_le_bytes(s[8..16].try_into().unwrap());
    assert_eq!(size, f.size);
    let mut v = vec![0u8; size as usize];
    let mut at = 16;
    while at < s.len() {
        let o = u64::from_le_bytes(s[at..at + 8].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(s[at + 8..at + 12].try_into().unwrap()) as usize;
        v[o..o + n].copy_from_slice(&s[at + 12..at + 12 + n]);
        at += 12 + n;
    }
    v
}

fn sha(b: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

fn utf16(b: &[u8]) -> String {
    let u: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&c| c != 0)
        .collect();
    String::from_utf16_lossy(&u)
}

fn method(c: Cipher) -> &'static str {
    match c {
        Cipher::XtsAes128 => "AES-XTS 128-bit",
        Cipher::XtsAes256 => "AES-XTS 256-bit",
        Cipher::CbcDiffuser128 => "AES-CBC 128-bit with Diffuser",
        Cipher::CbcDiffuser256 => "AES-CBC 256-bit with Diffuser",
        Cipher::Cbc128 => "AES-CBC 128-bit",
        Cipher::Cbc256 => "AES-CBC 256-bit",
        Cipher::Unknown(_) => "?",
    }
}

fn kind(k: ProtectorKind) -> String {
    match k {
        ProtectorKind::Password => "Password".into(),
        ProtectorKind::RecoveryPassword => "Recovery password".into(),
        ProtectorKind::ClearKey => "Clear key".into(),
        ProtectorKind::StartupKey => "Startup key".into(),
        ProtectorKind::SmartCard => "Unknown (0x1000)".into(),
        other => format!("{other:?}"),
    }
}

/// What bdeinfo said, from our parse (the manifest's key=value lines).
fn fields(m: &Metadata<'_>) -> Vec<String> {
    let mut v = vec![
        format!("volume_id={}", Guid(m.block.volume_id)),
        format!("method={}", method(m.block.cipher)),
    ];
    if let Some(d) = m.description {
        v.push(format!("description={}", utf16(d)));
    }
    for p in m.protectors() {
        v.push(format!("protector={} {}", kind(p.kind), Guid(p.id)));
    }
    v
}

/// A mock platform whose disk 0 is the bare volume.
fn platform(vol: Vec<u8>, block_size: u32) -> (Mock, Partition) {
    let mut m = Mock::new();
    let sectors = vol.len() as u64 / u64::from(block_size);
    m.disks.push(Disk {
        block_size,
        data: vol,
    });
    let part = Partition {
        disk: 0,
        index: 1,
        guid: Guid([0x11; 16]),
        first_lba: 0,
        sectors,
        block_size,
    };
    (m, part)
}

fn refusal(f: &Fixture) -> Option<String> {
    f.refused
        .as_ref()
        .map(|r| r.rsplit(": ").next().unwrap().to_string())
}

/// Every fixture, every key: bdeinfo's metadata, the oracles' boot
/// sectors, zeros over the non-data regions, the handoff layout.
fn check_fixture(f: &Fixture) {
    let vol = volume(f);
    let hdr = core::parse_volume_header(&vol[..512]).unwrap();
    let region = |i: usize| {
        let o = hdr.metadata_offsets[i] as usize;
        &vol[o..o + core::REGION_SIZE as usize]
    };
    let parsed =
        core::cross_check([region(0), region(1), region(2)], &hdr).and_then(Metadata::parse);
    let m = match parsed {
        Ok(m) => m,
        Err(e) => {
            assert_eq!(Some(format!("{e:?}")), refusal(f), "{}: metadata", f.name);
            return;
        }
    };
    if !f.fields.is_empty() {
        // (bdeinfo cannot open used-space-only volumes.)
        assert_eq!(fields(&m), f.fields, "{}: metadata vs bdeinfo", f.name);
    }

    // The protectors open the VMK even where the volume is refused: the
    // stretch and the unwrap are checked against every Windows sample.
    let mut vmks = Vec::new();
    if let Some(pw) = &f.password {
        vmks.push(vmk_from_password(&m, pw).unwrap().expect("password"));
        assert_eq!(vmk_from_password(&m, "wrong").unwrap(), None);
    }
    for rp in &f.recovery {
        let k = parse_recovery_password(rp.as_bytes()).unwrap();
        vmks.push(vmk_from_recovery(&m, &k).unwrap().expect("recovery"));
    }
    if !f.recovery.is_empty() {
        let wrong =
            parse_recovery_password(b"000000-000011-000022-000033-000044-000055-000066-000077")
                .unwrap();
        assert_eq!(vmk_from_recovery(&m, &wrong).unwrap(), None);
    }
    if let Some(b) = &f.startup_key {
        let sk = core::parse_startup_key(&std::fs::read(dir().join(b)).unwrap()).unwrap();
        vmks.push(vmk_from_startup_key(&m, &sk).unwrap().expect("startup key"));
    }
    // (images.conf does not list every clear-key protector.)
    let has_clear = m.of_kind(ProtectorKind::ClearKey).next().is_some();
    assert!(has_clear || !f.clear_key);
    match vmk_from_clear_key(&m).unwrap() {
        Some(v) => vmks.push(v),
        None => assert!(!has_clear, "{}: clear key", f.name),
    }
    assert!(!vmks.is_empty(), "{}: no key", f.name);
    assert!(
        vmks.windows(2).all(|w| w[0] == w[1]),
        "{}: protectors disagree",
        f.name
    );
    assert!(unlock_fvek(&m, &[0x5a; 32]).unwrap().is_none());

    // Through the loader's Volume, on 512-byte and (for 4Kn) 4 KiB disks.
    let mut sizes = vec![512];
    if hdr.bytes_per_sector == 4096 {
        sizes.push(4096);
    }
    for bs in sizes {
        let (mut p, part) = platform(vol.clone(), bs);
        let mut v = Box::new(BdeVolume::new(Unimplemented));
        let opened = v.open(&mut p, &part, VolumeKind::BitLocker);
        if let Some(r) = refusal(f) {
            let e = opened.err().or_else(|| {
                // Refused at the FVEK (a cipher the loader cannot read).
                v.try_vmk(&mut p, &vmks[0]).err()
            });
            assert_eq!(
                e.map(|e| format!("{e:?}")),
                Some(format!("Bde({r})")),
                "{}",
                f.name
            );
            continue;
        }
        opened.unwrap();
        assert!(v.clear_key(&mut p).unwrap().is_some() == f.clear_key);
        let mut blob = [0u8; 1024];
        let n = v.fvek_blob(&mut p, &mut blob).unwrap();
        assert_eq!(&blob[..12], &m.fvek.nonce);
        assert_eq!(n, 28 + m.fvek.ciphertext.len());
        assert!(!v.try_vmk(&mut p, &[0x5a; 32]).unwrap());
        assert!(v.fvek().is_none());
        assert!(v.plain(&mut p).is_err(), "no view before a key");
        let key = if let Some(rp) = f.recovery.first() {
            let k = parse_recovery_password(rp.as_bytes()).unwrap();
            v.recovery_key(&mut p, &k).unwrap().unwrap()
        } else {
            vmks[0]
        };
        assert!(v.try_vmk(&mut p, &key).unwrap());
        let (cipher, fvek) = v.fvek().unwrap();
        assert_eq!(cipher, m.block.cipher.to_u16());
        assert_eq!(fvek.len(), m.block.cipher.key_len().unwrap());
        let l = v.layout().unwrap();
        assert_eq!(l.metadata_offsets, hdr.metadata_offsets);
        assert_eq!(l.region_size, 0x10000);
        assert_eq!(l.boot_sector_reloc_offset, m.volume_header.0);
        assert_eq!(
            u64::from(l.boot_sector_reloc_sectors) * 512,
            m.volume_header.1
        );
        let detail = *v.layout_detail().unwrap();
        let bps = detail.bytes_per_sector;
        let mut d = v.plain(&mut p).unwrap();
        let mut boot = vec![0u8; 8192];
        d.read(0, &mut boot).unwrap();
        assert_eq!(
            Some(sha(&boot)),
            f.boot_sha256,
            "{}: boot sectors vs dislocker/libbde",
            f.name
        );
        // 512-byte reads for the NTFS parser, from any sector size.
        let mut s = [0u8; 512];
        for i in 0..16 {
            paguro_core::ntfs::Disk::read(&mut d, i, &mut s).unwrap();
            assert_eq!(&s[..], &boot[i as usize * 512..][..512]);
        }
        // The non-data regions read as zeros.
        for o in hdr.metadata_offsets.into_iter().chain([m.volume_header.0]) {
            let mut z = vec![0xffu8; 8192];
            DecryptingReader::read(&mut d, o / u64::from(bps), &mut z).unwrap();
            assert!(z.iter().all(|&b| b == 0), "{}: region at {o:#x}", f.name);
        }
    }
}

#[test]
fn windows_fixtures() {
    let all = manifest();
    std::thread::scope(|s| {
        for f in &all {
            s.spawn(move || check_fixture(f));
        }
    });
    let names: Vec<_> = all.iter().map(|f| f.name.as_str()).collect();
    for n in [
        "bitlk-aes-xts-128",
        "bitlk-aes-xts-256",
        "bitlk-aes-xts-128-4k",
        "bitlk-togo-aes-xts-128",
        "bitlk-aes-xts-128-crc",
    ] {
        assert!(names.contains(&n), "missing {n}");
    }
}

/// The plain xts-128 volume, unlocked, for tampering.
fn xts128() -> (Fixture, Vec<u8>, [u8; 32]) {
    let f = manifest()
        .into_iter()
        .find(|f| f.name == "bitlk-aes-xts-128")
        .unwrap();
    let vol = volume(&f);
    let hdr = core::parse_volume_header(&vol[..512]).unwrap();
    let o = hdr.metadata_offsets[0] as usize;
    let r = &vol[o..o + 0x10000];
    let m = Metadata::parse(core::cross_check([r, r, r], &hdr).unwrap()).unwrap();
    let vmk = vmk_from_password(&m, f.password.as_deref().unwrap())
        .unwrap()
        .unwrap();
    (f, vol, vmk)
}

/// Apply `edit` to every copy's block and fix each CRC.
fn edit_copies(vol: &mut [u8], copies: &[usize], edit: impl Fn(&mut [u8])) {
    let hdr = core::parse_volume_header(&vol[..512]).unwrap();
    for &i in copies {
        let o = hdr.metadata_offsets[i] as usize;
        let size = u16::from_le_bytes([vol[o + 8], vol[o + 9]]) as usize * 16;
        edit(&mut vol[o..o + size]);
        let c = core::crc32(&vol[o..o + size]);
        vol[o + size + 4..o + size + 8].copy_from_slice(&c.to_le_bytes());
    }
}

fn open(
    vol: Vec<u8>,
) -> (
    Mock,
    Partition,
    Box<BdeVolume<Unimplemented>>,
    Result<(), BootError>,
) {
    let (mut p, part) = platform(vol, 512);
    let mut v = Box::new(BdeVolume::new(Unimplemented));
    let r = v.open(&mut p, &part, VolumeKind::BitLocker);
    (p, part, v, r)
}

#[test]
fn tampered_metadata_with_valid_crcs_is_caught_after_unlock() {
    let (f, mut vol, vmk) = xts128();
    // The description, in all three copies, CRCs fixed: the copies agree
    // and pass their checksums; only the VMK-wrapped SHA-256 knows.
    edit_copies(&mut vol, &[0, 1, 2], |b| b[64 + 48 + 8] ^= 0x20);
    let (mut p, _, mut v, r) = open(vol);
    r.unwrap();
    assert_eq!(
        v.unlock_password(f.password.as_deref().unwrap()),
        Err(BdeError::ValidationHash)
    );
    assert_eq!(
        v.try_vmk(&mut p, &vmk).err(),
        Some(BootError::Bde(BdeError::ValidationHash))
    );
    assert!(v.fvek().is_none());
}

#[test]
fn an_fvek_of_the_wrong_cipher_is_refused() {
    let (_, mut vol, vmk) = xts128();
    // Re-wrap the FVEK entry with its method claiming XTS-256.
    let hdr = core::parse_volume_header(&vol[..512]).unwrap();
    let o = hdr.metadata_offsets[0] as usize;
    let fvek_at = {
        let r = &vol[o..o + 0x10000];
        let m = Metadata::parse(core::parse_block(r, 0, &hdr).unwrap()).unwrap();
        m.fvek.ciphertext.as_ptr() as usize - r.as_ptr() as usize
    };
    edit_copies(&mut vol, &[0, 1, 2], |b| {
        let nonce: [u8; 12] = b[fvek_at - 28..fvek_at - 16].try_into().unwrap();
        let tag: [u8; 16] = b[fvek_at - 16..fvek_at].try_into().unwrap();
        let ct = &mut b[fvek_at..fvek_at + 44];
        ccm_unwrap(&vmk, &nonce, &tag, ct).unwrap();
        assert_eq!(&ct[8..12], &0x8004u32.to_le_bytes());
        ct[8] = 0x05;
        let t = ccm_wrap(&vmk, &nonce, ct);
        b[fvek_at - 16..fvek_at].copy_from_slice(&t);
    });
    let (mut p, _, mut v, r) = open(vol);
    r.unwrap();
    assert_eq!(
        v.try_vmk(&mut p, &vmk).err(),
        Some(BootError::Bde(BdeError::FvekMismatch))
    );
}

#[test]
fn copies_disagreeing_on_disk_are_refused_by_the_loader() {
    let (_, vol, _) = xts128();
    for copy in [1, 2] {
        let mut v2 = vol.clone();
        edit_copies(&mut v2, &[copy], |b| b[64 + 48 + 8] ^= 0x20);
        let (_, _, _, r) = open(v2);
        assert_eq!(
            r,
            Err(BootError::Bde(BdeError::CopiesDisagree)),
            "copy {copy}"
        );
    }
    let mut v0 = vol.clone();
    edit_copies(&mut v0, &[0], |b| b[64 + 48 + 8] ^= 0x20);
    assert_eq!(open(v0).3, Err(BootError::Bde(BdeError::CopiesDisagree)));
    // A damaged first copy is named by its checksum.
    let hdr = core::parse_volume_header(&vol[..512]).unwrap();
    let mut v3 = vol.clone();
    v3[hdr.metadata_offsets[0] as usize + 200] ^= 1;
    assert_eq!(open(v3).3, Err(BootError::Bde(BdeError::Checksum(0))));
}

#[test]
fn volume_level_refusals() {
    let (_, vol, _) = xts128();
    // Metadata past the partition.
    let mut short = vol.clone();
    short.truncate(0x373a000);
    assert_eq!(open(short).3, Err(BootError::Bde(BdeError::MetadataOffset)));
    // Not BitLocker at all.
    let mut ntfs = vol.clone();
    ntfs[3..11].copy_from_slice(b"NTFS    ");
    assert_eq!(open(ntfs).3, Err(BootError::Bde(BdeError::NotBitLocker)));
    // 512-byte BitLocker sectors on a 4Kn disk cannot be.
    let (mut p, part) = platform(vol.clone(), 4096);
    let mut v = Box::new(BdeVolume::new(Unimplemented));
    assert_eq!(
        v.open(&mut p, &part, VolumeKind::BitLocker),
        Err(BootError::Bde(BdeError::SectorSize(512)))
    );
    assert_eq!(
        v.open(&mut p, &part, VolumeKind::Other),
        Err(BootError::NotAVolume)
    );
    // A plain NTFS volume: no FVE, the view is the disk.
    let (mut p, part) = platform(vec![7u8; 1 << 20], 512);
    let mut v = Box::new(BdeVolume::new(Unimplemented));
    v.open(&mut p, &part, VolumeKind::Ntfs).unwrap();
    assert_eq!(v.clear_key(&mut p), Ok(None));
    assert!(v.layout().is_none());
    let mut d = v.plain(&mut p).unwrap();
    let mut s = [0u8; 512];
    paguro_core::ntfs::Disk::read(&mut d, 5, &mut s).unwrap();
    assert!(s.iter().all(|&b| b == 7));
    assert_eq!(
        DecryptingReader::read(&mut d, 2048, &mut [0; 512]),
        Err(ReadError::Range)
    );
    drop(d);
    assert_eq!(
        v.fvek_blob(&mut p, &mut [0; 1024]).err(),
        Some(BootError::Bde(BdeError::NotBitLocker))
    );
}

// ---------------------------------------------------------------------------
// The decrypted view against a model

struct Mem(Vec<u8>, u32);

impl SectorRead for Mem {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let o = unit as usize * self.1 as usize;
        buf.copy_from_slice(self.0.get(o..o + buf.len()).ok_or(ReadError::Io)?);
        Ok(())
    }
}

const UNITS: u64 = 2048;

fn synthetic(bps: u32, enc_units: u64) -> (Layout, Vec<u8>, Xts) {
    let units = UNITS;
    let b = u64::from(bps);
    let l = Layout {
        bytes_per_sector: bps,
        volume_size: units * b,
        metadata_offsets: [300 * b, 700 * b, 1100 * b],
        reloc_len: 8192,
        reloc_offset: 1500 * b,
        encrypted_size: enc_units * b,
        cipher: Cipher::XtsAes128,
        partial: enc_units < units,
    };
    let disk: Vec<u8> = (0..units * b).map(|i| (i * 7 % 251) as u8).collect();
    (l, disk, Xts::new(&[3u8; 32]).unwrap())
}

/// One unit of the decrypted view, straight from the definition.
fn expected_unit(l: &Layout, disk: &[u8], xts: &Xts, u: u64) -> Vec<u8> {
    let b = l.bytes_per_sector as usize;
    match l.map(u).unwrap().0 {
        Source::Zero => vec![0; b],
        Source::Disk { unit, encrypted } => {
            let mut s = disk[unit as usize * b..][..b].to_vec();
            if encrypted {
                xts.decrypt(u128::from(unit), &mut s).unwrap();
            }
            s
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn any_read_equals_the_units_it_covers(
        four_k in any::<bool>(),
        enc in 0u64..=UNITS,
        start in 0u64..UNITS,
        len in 1u64..64,
    ) {
        let bps = if four_k { 4096 } else { 512 };
        let (l, disk, xts) = synthetic(bps, enc);
        let len = len.min(UNITS - start);
        let mut r = DecryptingReader::new(Mem(disk.clone(), bps), l, &xts);
        let mut got = vec![0u8; (len * u64::from(bps)) as usize];
        r.read(start, &mut got).unwrap();
        let want: Vec<u8> = (start..start + len).flat_map(|u| expected_unit(&l, &disk, &xts, u)).collect();
        prop_assert_eq!(&got, &want);
        // The same bytes through 512-byte NTFS reads.
        let per = u64::from(bps / 512);
        for (i, chunk) in want.chunks(512).enumerate().step_by(3) {
            let mut s = [0u8; 512];
            paguro_core::ntfs::Disk::read(&mut r, start * per + i as u64, &mut s).unwrap();
            prop_assert_eq!(&s[..], chunk);
        }
    }
}

#[test]
fn reader_refusals() {
    let (l, disk, xts) = synthetic(4096, UNITS);
    let mut r = DecryptingReader::new(Mem(disk, 4096), l, &xts);
    assert_eq!(r.read(0, &mut [0; 512]), Err(ReadError::Alignment));
    assert_eq!(r.read(UNITS, &mut [0; 4096]), Err(ReadError::Range));
    assert_eq!(r.read(UNITS - 1, &mut [0; 8192]), Err(ReadError::Range));
    assert_eq!(r.read(u64::MAX, &mut [0; 4096]), Err(ReadError::Range));
    assert!(r.read(UNITS - 1, &mut [0; 4096]).is_ok());
    assert!(r.read(0, &mut []).is_ok());
    let mut s = [0u8; 512];
    assert_eq!(r.read(0, &mut s), Err(ReadError::Alignment));
    assert!(paguro_core::ntfs::Disk::read(&mut r, UNITS * 8, &mut s).is_err());
    let mut io = DecryptingReader::new(Mem(vec![0; 4096], 4096), l, &xts);
    assert_eq!(io.read(50, &mut [0; 4096]), Err(ReadError::Io));
    assert_eq!(
        io.read(300, &mut [0; 4096]),
        Ok(()),
        "a hidden region needs no read"
    );
}

// ---------------------------------------------------------------------------
// The stage machine, unlocking a real Windows volume

/// A GPT disk whose one partition (at LBA 2048, `super::VOLUME`) is `vol`.
fn gpt_disk(vol: &[u8]) -> Disk {
    let first = 2048u64;
    let blocks = first + vol.len() as u64 / 512 + 64;
    let mut data = vec![0u8; blocks as usize * 512];
    data[first as usize * 512..][..vol.len()].copy_from_slice(vol);
    let e = gpt::Entry {
        type_guid: GPT_BASIC_DATA,
        unique_guid: VOLUME,
        first_lba: first,
        last_lba: first + vol.len() as u64 / 512 - 1,
        attributes: 0,
        name: [0; 36],
    };
    let mut h = [0u8; 512];
    let mut a = [0u8; gpt::MAX_ENTRY_ARRAY];
    gpt::build::write(&Guid([0xd1; 16]), blocks, 512, &[e], 128, &mut h, &mut a).unwrap();
    data[512..1024].copy_from_slice(&h);
    data[1024..1024 + a.len()].copy_from_slice(&a);
    Disk {
        block_size: 512,
        data,
    }
}

fn run(w: &mut World, v: &mut BdeVolume<Unimplemented>) -> Outcome {
    let mut bufs = Box::new(Buffers::new());
    paguro_boot::run(&mut w.m, v, &mut bufs, &PARAMS)
}

#[test]
fn the_loader_unlocks_a_windows_clear_key_volume() {
    let f = manifest()
        .into_iter()
        .find(|f| f.name == "bitlk-aes-xts-128-clearkey-only")
        .unwrap();
    let mut w = World::new();
    w.m.disks = vec![gpt_disk(&volume(&f))];
    let mut v = Box::new(BdeVolume::new(Unimplemented));
    // Stage 3 done by the real reader; stage 4 is not this module's.
    assert!(
        matches!(run(&mut w, &mut v), Outcome::Halted(BootError::NotImplemented(s)) if s.starts_with("stage 4")),
        "stage 3 unlocked; stage 4 is not written"
    );
    assert!(
        !w.m.screens
            .iter()
            .any(|s| matches!(s, paguro_boot::Screen::Unlock(_))),
        "a clear key is silent: {:?}",
        w.m.screens
    );
    assert!(v.fvek().is_some());
    assert_eq!(
        w.m.extends().last(),
        Some(&boot_taint()),
        "the boot taint follows the key"
    );
}

#[test]
fn the_loader_unlocks_a_windows_volume_with_its_recovery_password() {
    let f = manifest()
        .into_iter()
        .find(|f| f.name == "bitlk-aes-xts-256")
        .unwrap();
    let mut w = World::new();
    w.m.disks = vec![gpt_disk(&volume(&f))];
    w.m.put_var(
        "PaguroConfigHash",
        paguro_core::guid::PAGURO_VENDOR,
        7,
        &[0xee; 32],
    );
    w.m.input(Input::Recover)
        .input(Input::Select(Row::RecoveryKey))
        .secret(&f.recovery[0]);
    let mut v = Box::new(BdeVolume::new(Unimplemented));
    assert!(
        matches!(run(&mut w, &mut v), Outcome::Halted(BootError::NotImplemented(s)) if s.starts_with("stage 4")),
        "stage 3 unlocked; stage 4 is not written"
    );
    let (cipher, key) = v.fvek().unwrap();
    assert_eq!((cipher, key.len()), (0x8005, 64));
    let _ = Rung::RecoveryKey;
}

#[test]
fn windows_7_to_go_password_opens_its_vmk() {
    // dfvfs's bdetogo.raw (Windows 7, 2014): AES-CBC with the diffuser, so
    // refused; and its metadata fails its own CRC-32 and SHA-256, which is
    // why the cipher is the reason given. With the CRC recomputed, the
    // password protector still yields the VMK: the stretch matches Windows 7
    // as well as 10 and 11.
    let f = manifest()
        .into_iter()
        .find(|f| f.name == "dfvfs-bdetogo")
        .unwrap();
    assert_eq!(refusal(&f).as_deref(), Some("UnsupportedCipher(32768)"));
    let mut vol = volume(&f);
    edit_copies(&mut vol, &[0], |_| {});
    let hdr = core::parse_volume_header(&vol[..512]).unwrap();
    assert_eq!(hdr.kind, core::HeaderKind::ToGo);
    let o = hdr.metadata_offsets[0] as usize;
    let m = Metadata::parse(core::parse_block(&vol[o..o + 0x10000], 0, &hdr).unwrap()).unwrap();
    assert_eq!(fields(&m), f.fields);
    let vmk = vmk_from_password(&m, "bde-TEST")
        .unwrap()
        .expect("Windows 7 stretch");
    assert_eq!(vmk_from_password(&m, "bde-test").unwrap(), None);
    assert_eq!(
        unlock_fvek(&m, &vmk).err(),
        Some(BdeError::UnsupportedCipher(0x8000))
    );
}
