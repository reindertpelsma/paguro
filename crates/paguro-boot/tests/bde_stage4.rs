//! A BitLocker volume through the whole stage machine and a real stage 4:
//! an `mkntfs` NTFS holding a fixed VHD, encrypted by
//! `test/fixtures/bde/make.sh` (the writer libbde and dislocker vouch for),
//! unlocked by a BitLocker password (after a wrong one), a recovery password
//! and a clear key; the published disk, decrypted with the key and layout
//! the platform was handed, must be the VHD's bytes, and the handoff must
//! carry the FVEK and `FVE_LAYOUT`. Metadata copies that disagree stop the
//! boot. Skipped without the image tools or without `paguro-bde-write`
//! (`cargo build --release -p paguro-harness --bin paguro-bde-write`, or
//! `PAGURO_BDE_WRITE`).
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod mock;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mock::{Mock, PARAMS};
use paguro_boot::bde::{DecryptingReader, ReadError, UnitRead};
use paguro_boot::platform::{Input, Row};
use paguro_boot::stage4::Stage4;
use paguro_boot::{BdeVolume, BootError, Buffers, Outcome};
use paguro_core::bde::{BdeError, Layout};
use paguro_core::handoff::{self, Rung};
use paguro_core::ntfs;
use paguro_crypto::bitlocker::Xts;

const GUID: &str = "3a0c9e51-7b24-4f6d-8e13-5c2a9b7d0f46";

fn ok(c: &mut Command) -> bool {
    c.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn writer() -> Option<PathBuf> {
    let w = std::env::var_os("PAGURO_BDE_WRITE")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("target/release/paguro-bde-write"));
    w.exists().then_some(w)
}

fn tools() -> bool {
    let missing: Vec<&str> = [
        "mkfs.vfat",
        "mmd",
        "mcopy",
        "sgdisk",
        "qemu-img",
        "mkntfs",
        "ntfscp",
        "ntfsinfo",
    ]
    .into_iter()
    .filter(|t| !ok(Command::new("sh").arg("-c").arg(format!("command -v {t}"))))
    .collect();
    if !missing.is_empty() {
        eprintln!("missing {missing:?}: skipped");
    }
    missing.is_empty()
}

fn tmp(name: &str) -> PathBuf {
    let base = std::env::var_os("PAGURO_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let d = base.join(format!("paguro-bde-s4-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A 36 MiB GPT disk whose ESP holds `\EFI\BOOT\BOOTX64.EFI`, as a fixed VHD.
fn payload_vhd(d: &Path) -> Vec<u8> {
    let fat = d.join("esp.fat");
    assert!(ok(Command::new("mkfs.vfat")
        .args(["-F", "32", "-S", "512", "-s", "1", "-C"])
        .arg(&fat)
        .arg("34816")));
    std::fs::write(d.join("x.efi"), b"MZ-probe").unwrap();
    for dir in ["::/EFI", "::/EFI/BOOT"] {
        assert!(ok(Command::new("mmd").arg("-i").arg(&fat).arg(dir)));
    }
    assert!(ok(Command::new("mcopy")
        .arg("-i")
        .arg(&fat)
        .arg(d.join("x.efi"))
        .arg("::/EFI/BOOT/BOOTX64.EFI")));
    let raw = d.join("p.raw");
    std::fs::File::create(&raw)
        .unwrap()
        .set_len(36 << 20)
        .unwrap();
    assert!(ok(Command::new("sgdisk")
        .args(["-n", "1:2048:+34M", "-t", "1:ef00"])
        .arg(&raw)));
    let mut r = std::fs::read(&raw).unwrap();
    let f = std::fs::read(&fat).unwrap();
    r[2048 * 512..2048 * 512 + f.len()].copy_from_slice(&f);
    std::fs::write(&raw, r).unwrap();
    let vhd = d.join("p.vhd");
    assert!(ok(Command::new("qemu-img")
        .args([
            "convert",
            "-f",
            "raw",
            "-O",
            "vpc",
            "-o",
            "subformat=fixed,force_size=on"
        ])
        .arg(&raw)
        .arg(&vhd)));
    std::fs::read(vhd).unwrap()
}

struct Built {
    disk: Vec<u8>,
    vhd: Vec<u8>,
    keys: String,
}

const FIRST: u64 = 2048;

/// A GPT disk whose partition (`GUID`, at LBA 2048) is an NTFS holding
/// `\linux.vhd`, encrypted by make.sh with `opts`.
fn build(name: &str, sector: u32, opts: &[&str]) -> Option<Built> {
    if !tools() {
        return None;
    }
    let Some(w) = writer() else {
        eprintln!("paguro-bde-write not built: skipped");
        return None;
    };
    let d = tmp(name);
    let vhd = payload_vhd(&d);
    std::fs::write(d.join("linux.vhd"), &vhd).unwrap();
    let ntfs = d.join("ntfs.img");
    std::fs::File::create(&ntfs)
        .unwrap()
        .set_len(96 << 20)
        .unwrap();
    assert!(ok(Command::new("mkntfs")
        .args(["-F", "-f", "-q", "-s", &sector.to_string()])
        .arg(&ntfs)));
    assert!(ok(Command::new("ntfscp")
        .arg("-q")
        .arg(&ntfs)
        .arg(d.join("linux.vhd"))
        .arg("linux.vhd")));
    let enc = d.join("enc.img");
    let st = Command::new(root().join("test/fixtures/bde/make.sh"))
        .arg(&ntfs)
        .arg(&enc)
        .args(opts)
        .arg("--no-verify")
        .env("PAGURO_BDE_WRITE", &w)
        .output()
        .unwrap();
    assert!(
        st.status.success(),
        "{}",
        String::from_utf8_lossy(&st.stderr)
    );
    let disk = d.join("disk.img");
    std::fs::File::create(&disk)
        .unwrap()
        .set_len(100 << 20)
        .unwrap();
    assert!(ok(Command::new("sgdisk")
        .args(["-n", "1:2048:+96M", "-t", "1:0700", "-u"])
        .arg(format!("1:{GUID}"))
        .arg(&disk)));
    let mut data = std::fs::read(&disk).unwrap();
    let e = std::fs::read(&enc).unwrap();
    let at = FIRST as usize * 512;
    data[at..at + e.len()].copy_from_slice(&e);
    let keys = std::fs::read_to_string(d.join("enc.img.keys")).unwrap();
    let _ = std::fs::remove_dir_all(&d);
    Some(Built {
        disk: data,
        vhd,
        keys,
    })
}

fn key(b: &Built, k: &str) -> String {
    b.keys
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{k} ")))
        .unwrap()
        .to_string()
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn mock(disk: Vec<u8>) -> Mock {
    let mut m = Mock::new();
    m.secure_boot = false;
    m.tpm = None;
    m.disks.push(mock::Disk {
        block_size: 512,
        data: disk,
    });
    m.files.insert(
        "paguro.ini".into(),
        format!(
            "[Paguro]\nversion = 1\ndefault = linux\n\n[Boot.linux]\nvolume = {GUID}\nroot = \\linux.vhd\n"
        )
        .into_bytes(),
    );
    m
}

fn run(m: &mut Mock) -> (Outcome, Option<(u16, Vec<u8>)>) {
    let mut b: Box<std::mem::MaybeUninit<Stage4>> = Box::new_uninit();
    // SAFETY: all-zero is a valid Stage4 (documented in stage4).
    let mut s4 = unsafe {
        std::ptr::write_bytes(b.as_mut_ptr(), 0, 1);
        b.assume_init()
    };
    let mut meta = vec![0u8; 0x1_0000].into_boxed_slice();
    let mut v = BdeVolume::new(&mut s4, (&mut meta[..]).try_into().unwrap());
    let mut bufs = Box::new(Buffers::new());
    let out = paguro_boot::run(m, &mut v, &mut bufs, &PARAMS);
    let fvek = v.fvek().map(|(c, k)| (c, k.to_vec()));
    (out, fvek)
}

/// The partition's physical units, from the disk image.
struct Part<'a> {
    disk: &'a [u8],
    unit: usize,
}

impl UnitRead for Part<'_> {
    fn read_units(&mut self, unit: u64, buf: &mut [u8]) -> Result<(), ReadError> {
        let at = FIRST as usize * 512 + unit as usize * self.unit;
        buf.copy_from_slice(self.disk.get(at..at + buf.len()).ok_or(ReadError::Io)?);
        Ok(())
    }
}

/// The published disk as the chained image reads it: payload sectors
/// gathered through the extents, each volume sector decrypted with the
/// cipher, key and layout handed to the platform.
fn published(b: &Built, m: &Mock) -> Vec<u8> {
    let e = &m.exposed[0];
    let (_, k, l): &(u16, Vec<u8>, Layout) = e.fve.as_ref().expect("a BitLocker disk");
    let xts = Xts::new(k).unwrap();
    let part = Part {
        disk: &b.disk,
        unit: l.bytes_per_sector as usize,
    };
    let mut r = DecryptingReader::new(part, *l, &xts);
    let mut out = vec![0u8; e.sectors as usize * 512];
    for s in 0..e.sectors {
        let (vs, _) = ntfs::gather(&e.extents, s).unwrap();
        r.read_sectors(vs, &mut out[s as usize * 512..][..512])
            .unwrap();
    }
    out
}

fn check_started(b: &Built, m: &Mock, fvek: &Option<(u16, Vec<u8>)>) {
    assert_eq!(
        published(b, m),
        &b.vhd[..b.vhd.len() - 512],
        "the VHD, decrypted"
    );
    let h = m.handoff.clone().unwrap();
    let h = handoff::decode(&h).unwrap();
    let f = h.fvek.expect("FVEK in the handoff");
    let (c, k) = (f.cipher, f.key);
    assert_eq!(k, &hex(&key(b, "fvek"))[..]);
    assert_eq!(Some((c, k.to_vec())), *fvek);
    let l = h.fve_layout.expect("FVE_LAYOUT in the handoff");
    let md: Vec<u64> = key(b, "metadata")
        .split(',')
        .map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).unwrap())
        .collect();
    assert_eq!(l.metadata_offsets.to_vec(), md);
    assert_eq!(l.region_size, 0x10000);
    assert_eq!(
        l.boot_sector_reloc_offset,
        u64::from_str_radix(key(b, "reloc").trim_start_matches("0x"), 16).unwrap()
    );
    assert_eq!(l.boot_sector_reloc_sectors, 16);
    assert_eq!(
        l.encrypted_size,
        key(b, "encrypted-size").parse::<u64>().unwrap()
    );
    assert_eq!(
        h.vmk,
        Some(&<[u8; 32]>::try_from(hex(&key(b, "vmk"))).unwrap())
    );
}

#[test]
fn a_bitlocker_password_after_a_wrong_one() {
    let Some(b) = build("pw", 512, &["--password", "hunter2", "--seed", "21"]) else {
        return;
    };
    let mut m = mock(b.disk.clone());
    m.input(Input::Select(Row::PasswordOrPin))
        .secret("hunter3")
        .input(Input::Select(Row::PasswordOrPin))
        .secret("hunter2");
    let (out, fvek) = run(&mut m);
    assert_eq!(
        out,
        Outcome::Started(Rung::BitLockerPassword),
        "{:#?}",
        m.log
    );
    check_started(&b, &m, &fvek);
    assert_eq!(fvek.unwrap().0, 0x8004);
}

#[test]
fn a_recovery_password_on_a_4k_xts256_volume() {
    let Some(b) = build(
        "rp",
        4096,
        &["--recovery", "auto", "--cipher", "xts256", "--seed", "22"],
    ) else {
        return;
    };
    let mut m = mock(b.disk.clone());
    m.input(Input::Select(Row::RecoveryKey))
        .secret(&key(&b, "recovery"));
    let (out, fvek) = run(&mut m);
    assert_eq!(out, Outcome::Started(Rung::RecoveryKey), "{:#?}", m.log);
    // 4 KiB sectors: two relocated units.
    let h = m.handoff.clone().unwrap();
    assert_eq!(
        handoff::decode(&h)
            .unwrap()
            .fve_layout
            .unwrap()
            .boot_sector_reloc_sectors,
        16
    );
    assert_eq!(fvek.as_ref().unwrap().0, 0x8005);
    let e = &m.exposed[0];
    assert_eq!(e.fve.as_ref().unwrap().2.bytes_per_sector, 4096);
    assert_eq!(published(&b, &m), &b.vhd[..b.vhd.len() - 512]);
}

#[test]
fn a_clear_key_is_silent_and_a_partial_volume_reads() {
    let Some(b) = build(
        "ck",
        512,
        &[
            "--clear-key",
            "--encrypted-size",
            "50331648",
            "--seed",
            "23",
        ],
    ) else {
        return;
    };
    let mut m = mock(b.disk.clone());
    let (out, fvek) = run(&mut m);
    assert_eq!(out, Outcome::Started(Rung::ClearKey), "{:#?}", m.log);
    check_started(&b, &m, &fvek);
    assert!(m.exposed[0].fve.as_ref().unwrap().2.partial);
}

#[test]
fn metadata_copies_that_disagree_stop_the_boot() {
    let Some(mut b) = build("dis", 512, &["--password", "x", "--seed", "24"]) else {
        return;
    };
    let md: Vec<u64> = key(&b, "metadata")
        .split(',')
        .map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).unwrap())
        .collect();
    // The description in copy 2, with its CRC recomputed: a structural
    // disagreement, not damage.
    let o = (FIRST * 512 + md[2]) as usize;
    let size = u16::from_le_bytes([b.disk[o + 8], b.disk[o + 9]]) as usize * 16;
    b.disk[o + 64 + 48 + 8] ^= 0x20;
    let c = paguro_core::bde::crc32(&b.disk[o..o + size]);
    b.disk[o + size + 4..o + size + 8].copy_from_slice(&c.to_le_bytes());
    let mut m = mock(b.disk.clone());
    let (out, _) = run(&mut m);
    assert_eq!(
        out,
        Outcome::Halted(BootError::Bde(BdeError::CopiesDisagree))
    );
    assert!(m.handoff.is_none());
}
