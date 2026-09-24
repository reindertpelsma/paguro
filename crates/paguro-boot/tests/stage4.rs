//! Stage 4 ([`paguro_boot::NtfsVolume`]) through the whole stage machine,
//! over disks built by third-party tools (`sgdisk`, `mkntfs` + `ntfs-3g`,
//! `mkfs.vfat` + mtools, `qemu-img`) and held in the mock platform. What the
//! platform is asked to publish is checked against `ntfscat`: the extents
//! must gather to exactly the disk file's bytes. Skipped where the tools or
//! FUSE are missing.
#![allow(clippy::indexing_slicing, clippy::unwrap_used)]

mod mock;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use mock::{Event, MOCK_CHAIN, Mock, PARAMS};
use paguro_boot::platform::{Input, Notice, Screen};
use paguro_boot::stage4::{FatAt, PartitionReader, SectorRead, Stage4Error};
use paguro_boot::volume::{Partition, VolumeKind};
use paguro_boot::{BootError, Buffers, NtfsVolume, Outcome, Volume};
use paguro_core::guid::Guid;
use paguro_core::handoff::{self, Rung};
use paguro_core::ntfs;

const GUID: &str = "7d1f0c2a-5b3e-4c8d-9a61-0e2f4b6c8d90";

fn ok(c: &mut Command) -> bool {
    c.stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn tmp(name: &str) -> PathBuf {
    let base = std::env::var_os("PAGURO_TEST_TMP")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let d = base.join(format!("paguro-s4-{}-{name}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A 36 MiB GPT disk whose ESP holds `\EFI\BOOT\BOOTX64.EFI` (= `efi`) and
/// `\probe.txt`, as a fixed VHD.
fn payload_vhd(d: &Path, efi: &[u8]) -> Option<Vec<u8>> {
    if !tools() {
        return None;
    }
    let fat = d.join("esp.fat");
    if !ok(Command::new("mkfs.vfat")
        .args(["-F", "32", "-S", "512", "-s", "1", "-C"])
        .arg(&fat)
        .arg("34816"))
    {
        return None;
    }
    std::fs::write(d.join("x.efi"), efi).unwrap();
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
    if !ok(Command::new("sgdisk")
        .args(["-n", "1:2048:+34M", "-t", "1:ef00"])
        .arg(&raw))
    {
        return None;
    }
    let mut r = std::fs::read(&raw).unwrap();
    let f = std::fs::read(&fat).unwrap();
    r[2048 * 512..2048 * 512 + f.len()].copy_from_slice(&f);
    std::fs::write(&raw, r).unwrap();
    let vhd = d.join("p.vhd");
    if !ok(Command::new("qemu-img")
        .args([
            "convert",
            "-f",
            "raw",
            "-O",
            "vpc",
            "-o",
            "subformat=fixed,force_size=on",
        ])
        .arg(&raw)
        .arg(&vhd))
    {
        return None;
    }
    Some(std::fs::read(vhd).unwrap())
}

/// A GPT disk with one NTFS partition (`GUID`) that ntfs-3g filled; the
/// partition image; its first LBA.
struct Built {
    disk: Vec<u8>,
    ntfs: PathBuf,
    first: u64,
}

fn build(name: &str, fill: impl FnOnce(&Path)) -> Option<Built> {
    if !tools() {
        return None;
    }
    let d = tmp(name);
    let ntfs = d.join("ntfs.img");
    std::fs::File::create(&ntfs)
        .unwrap()
        .set_len(96 << 20)
        .unwrap();
    if !ok(Command::new("mkntfs").args(["-F", "-f", "-q"]).arg(&ntfs)) {
        eprintln!("mkntfs unavailable: skipped");
        return None;
    }
    let mnt = d.join("mnt");
    std::fs::create_dir_all(&mnt).unwrap();
    if !mount_ntfs(&ntfs, &mnt) {
        eprintln!("ntfs-3g unavailable: skipped");
        return None;
    }
    fill(&mnt);
    assert!(umount(&mnt));
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
    let n = std::fs::read(&ntfs).unwrap();
    data[2048 * 512..2048 * 512 + n.len()].copy_from_slice(&n);
    Some(Built {
        disk: data,
        ntfs,
        first: 2048,
    })
}

fn ntfscat(img: &Path, path: &str) -> Vec<u8> {
    Command::new("ntfscat")
        .arg(img)
        .arg(path)
        .output()
        .unwrap()
        .stdout
}

fn identity(img: &Path, path: &str) -> (u64, u16) {
    let out = Command::new("ntfsinfo")
        .arg("-F")
        .arg(path)
        .arg(img)
        .output()
        .unwrap();
    let t = String::from_utf8_lossy(&out.stdout);
    let num = |k: &str| -> u64 {
        let l = t.lines().find(|l| l.starts_with(k)).unwrap();
        l[k.len()..]
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    (num("Dumping Inode"), num("MFT Record Seq. Numb.:") as u16)
}

fn mock(disk: Vec<u8>, ini: Option<&str>) -> Mock {
    let mut m = Mock::new();
    m.secure_boot = false;
    m.tpm = None;
    m.disks.push(mock::Disk {
        block_size: 512,
        data: disk,
    });
    if let Some(i) = ini {
        m.files.insert(
            "paguro.ini".into(),
            format!(
                "[Paguro]\nversion = 1\ndefault = linux\n\n[Boot.linux]\nvolume = {GUID}\n{i}\n"
            )
            .into_bytes(),
        );
    }
    m
}

fn vol() -> Box<NtfsVolume> {
    let mut b: Box<std::mem::MaybeUninit<NtfsVolume>> = Box::new_uninit();
    // SAFETY: all-zero is a valid NtfsVolume (documented in stage4).
    unsafe {
        std::ptr::write_bytes(b.as_mut_ptr(), 0, 1);
        b.assume_init()
    }
}

fn run(m: &mut Mock) -> Outcome {
    let mut v = vol();
    let mut bufs = Box::new(Buffers::new());
    paguro_boot::run(m, &mut *v, &mut bufs, &PARAMS)
}

/// The published payload, gathered from the disk as the block device would.
fn gathered(disk: &[u8], first: u64, e: &mock::Exposed) -> Vec<u8> {
    let mut out = Vec::with_capacity(e.sectors as usize * 512);
    for s in 0..e.sectors {
        let (vs, _) = ntfs::gather(&e.extents, s).unwrap();
        let at = ((first + vs) * 512) as usize;
        out.extend_from_slice(&disk[at..at + 512]);
    }
    out
}

#[test]
fn a_vhd_entry_is_published_and_chained() {
    let d = tmp("vhd");
    let Some(vhd) = payload_vhd(&d, b"MZ-probe") else {
        return;
    };
    let v2 = vhd.clone();
    let Some(b) = build("vhd", move |m| {
        std::fs::create_dir_all(m.join("paguro")).unwrap();
        std::fs::write(m.join("paguro/linux.vhd"), &v2).unwrap();
        std::fs::write(m.join("hiberfil.sys"), b"wake and nothing else").unwrap();
    }) else {
        return;
    };
    let mut m = mock(b.disk.clone(), Some("root = \\paguro\\linux.vhd"));
    assert_eq!(
        run(&mut m),
        Outcome::Started(Rung::Unencrypted),
        "{:#?}",
        m.log
    );
    let e = &m.exposed[0];
    assert_eq!(
        e.fat,
        FatAt::Partition {
            first_lba: 2048,
            sectors: 34 * 2048
        }
    );
    assert_eq!(e.image, "\\EFI\\BOOT\\BOOTX64.EFI");
    assert_eq!(e.part.first_lba, b.first);
    assert_eq!(
        e.sectors * 512,
        vhd.len() as u64 - 512,
        "the footer is not published"
    );
    assert_eq!(
        gathered(&b.disk, b.first, e),
        &ntfscat(&b.ntfs, "/paguro/linux.vhd")[..vhd.len() - 512]
    );
    assert!(m.events.contains(&Event::Start(MOCK_CHAIN.to_vec())));
    let h = m.handoff.clone().unwrap();
    let h = handoff::decode(&h).unwrap();
    let (rec, seq) = identity(&b.ntfs, "/paguro/linux.vhd");
    let root = h.root.unwrap();
    assert_eq!(
        (root.name, root.mft_record, root.mft_seq),
        ("linux", rec, seq)
    );
    assert!(h.efi_disk.is_none() && h.efi_file.is_none());
    assert_eq!(
        h.state,
        handoff::state::CONFIG_UNVERIFIED,
        "an inactive hiberfil.sys is no gate"
    );
    // The published payload is what classify saw: an ESP at LBA 2048.
    assert_eq!(e.file.mft_record, rec);
}

/// Tier 2 (our own FAT32 SimpleFileSystem) is not built: when the firmware
/// binds no file system to the published disk, the boot stops with the
/// typed reason and the "could not be started" screen, nothing chained.
#[test]
fn no_firmware_fat_binding_is_a_clean_refusal() {
    let d = tmp("tier2");
    let Some(vhd) = payload_vhd(&d, b"MZ") else {
        return;
    };
    let Some(b) = build("tier2", move |m| {
        std::fs::create_dir_all(m.join("paguro")).unwrap();
        std::fs::write(m.join("paguro/linux.vhd"), &vhd).unwrap();
    }) else {
        return;
    };
    let mut m = mock(b.disk, Some("root = \\paguro\\linux.vhd"));
    m.expose_fails = true;
    assert_eq!(
        run(&mut m),
        Outcome::Halted(BootError::Stage4(Stage4Error::Expose(
            paguro_boot::PlatformError::Unsupported
        )))
    );
    assert_eq!(m.screens.last(), Some(&Screen::Notice(Notice::StartFailed)));
    assert!(!m.events.iter().any(|e| matches!(e, Event::Start(_))));
}

#[test]
fn an_efi_file_is_read_whole() {
    let image: Vec<u8> = (0..300_001u32).map(|i| (i * 7) as u8).collect();
    let img2 = image.clone();
    let Some(b) = build("efifile", move |m| {
        std::fs::create_dir_all(m.join("paguro")).unwrap();
        std::fs::write(m.join("paguro/rescue.efi"), &img2).unwrap();
        std::fs::write(m.join("hiberfil.sys"), b"hibr").unwrap();
    }) else {
        return;
    };
    let mut m = mock(b.disk.clone(), Some("efi_file = \\paguro\\rescue.efi"));
    // The hibernation notice: Enter continues read-only.
    m.script.push_back((Input::Continue, None));
    assert_eq!(
        run(&mut m),
        Outcome::Started(Rung::Unencrypted),
        "{:#?}",
        m.log
    );
    assert!(m.screens.contains(&Screen::Notice(Notice::Hibernated)));
    assert!(m.events.contains(&Event::StartBuffer(image.clone())));
    let h = m.handoff.clone().unwrap();
    let h = handoff::decode(&h).unwrap();
    assert!(h.root.is_none());
    let f = h.efi_file.unwrap();
    assert_eq!(
        (f.mft_record, f.mft_seq),
        identity(&b.ntfs, "/paguro/rescue.efi")
    );
    assert_eq!(
        h.state & handoff::state::HIBERNATED,
        handoff::state::HIBERNATED
    );
    assert!(m.exposed.is_empty());
}

#[test]
fn refusals_show_the_start_failed_screen() {
    let Some(b) = build("refuse", |m| {
        std::fs::create_dir_all(m.join("paguro")).unwrap();
        std::fs::write(m.join("paguro/zero.img"), vec![0u8; 1 << 20]).unwrap();
    }) else {
        return;
    };
    for (entry, want) in [
        (
            "root = \\paguro\\missing.vhd",
            Stage4Error::File(
                paguro_boot::stage4::Role::Root,
                paguro_core::ntfs::dir::DirError::NotFound,
            ),
        ),
        (
            "root = \\paguro\\zero.img",
            Stage4Error::Payload(paguro_core::disk::DiskError::Unrecognised),
        ),
        (
            "efi_file = \\paguro",
            Stage4Error::File(
                paguro_boot::stage4::Role::EfiFile,
                paguro_core::ntfs::dir::DirError::IsDirectory,
            ),
        ),
    ] {
        let mut m = mock(b.disk.clone(), Some(entry));
        assert_eq!(
            run(&mut m),
            Outcome::Halted(BootError::Stage4(want)),
            "{entry}"
        );
        assert_eq!(m.screens.last(), Some(&Screen::Notice(Notice::StartFailed)));
        assert!(m.handoff.is_none());
    }
}

#[test]
fn listings_come_from_the_volume() {
    let d = tmp("list");
    let Some(vhd) = payload_vhd(&d, b"MZ") else {
        return;
    };
    let Some(b) = build("list", move |m| {
        std::fs::create_dir_all(m.join("paguro/sub")).unwrap();
        std::fs::write(m.join("paguro/a.vhd"), &vhd).unwrap();
        std::fs::write(m.join("paguro/b.efi"), b"MZ").unwrap();
        std::fs::write(m.join("paguro/notes.txt"), b"x").unwrap();
    }) else {
        return;
    };
    let mut m = mock(b.disk, None);
    let mut v = vol();
    let part = Partition {
        disk: 0,
        index: 1,
        guid: Guid::parse(GUID).unwrap(),
        first_lba: 2048,
        sectors: 96 * 2048,
        block_size: 512,
    };
    v.open(&mut m, &part, VolumeKind::Ntfs).unwrap();
    let mut dl = Box::new(paguro_boot::platform::DirListing::new());
    use paguro_boot::platform::{Level, Listing};
    dl.clear(Level::Volume);
    v.list_dir(&mut m, "\\paguro", &mut dl).unwrap();
    dl.sort();
    let names: Vec<_> = (0..dl.len())
        .map(|i| dl.item(i).unwrap().name.to_string())
        .collect();
    assert_eq!(
        names,
        ["sub", "a.vhd", "b.efi"],
        "folders first; .txt filtered"
    );
    dl.clear(Level::Volume);
    v.list_dir(&mut m, "\\nope", &mut dl).unwrap();
    assert!(dl.is_empty(), "a missing directory lists empty");
    dl.clear(Level::EfiPartition);
    assert!(
        v.list_efi_dir(&mut m, "\\paguro\\a.vhd", "\\EFI\\BOOT", &mut dl)
            .unwrap()
    );
    assert_eq!(dl.item(0).unwrap().name, "BOOTX64.EFI");
    dl.clear(Level::EfiPartition);
    assert!(
        !v.list_efi_dir(&mut m, "\\paguro\\b.efi", "\\", &mut dl)
            .unwrap()
    );
}

/// The partition reader over 4 KiB physical blocks: any 512-byte sector
/// range, aligned or not, reads what a 512-byte view of the same bytes has.
#[test]
fn partition_reader_handles_4k_blocks() {
    let data: Vec<u8> = (0..64 * 4096u32)
        .map(|i| (i / 512) as u8 ^ (i as u8))
        .collect();
    let mut m = Mock::new();
    m.disks.push(mock::Disk {
        block_size: 4096,
        data: data.clone(),
    });
    let part = Partition {
        disk: 0,
        index: 1,
        guid: Guid::ZERO,
        first_lba: 3,
        sectors: 50,
        block_size: 4096,
    };
    let mut r = PartitionReader { part };
    assert_eq!(SectorRead::<Mock>::sectors(&r), 400);
    for (s, n) in [
        (0u64, 1u64),
        (1, 1),
        (7, 2),
        (3, 20),
        (8, 8),
        (5, 64),
        (399, 1),
        (390, 10),
    ] {
        let mut buf = vec![0u8; n as usize * 512];
        r.read(&mut m, s, &mut buf).unwrap();
        let at = (3 * 4096 + s * 512) as usize;
        assert_eq!(buf, &data[at..at + buf.len()], "{s}+{n}");
    }
    let mut buf = vec![0u8; 1024];
    assert!(r.read(&mut m, 399, &mut buf).is_err(), "past the partition");
    assert!(
        r.read(&mut m, 0, &mut buf[..100]).is_err(),
        "not whole sectors"
    );
}

/// `cmd`, through `sudo -n` when not root (CI runners mount FUSE that way),
/// owned by the current user.
fn privileged(cmd: &str) -> Command {
    let uid = current_uid();
    if uid == 0 {
        Command::new(cmd)
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(cmd);
        c
    }
}

fn current_uid() -> u32 {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

fn mount_ntfs(img: &Path, mnt: &Path) -> bool {
    let gid = Command::new("id")
        .arg("-g")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0);
    ok(privileged("ntfs-3g")
        .arg("-o")
        .arg(format!("uid={},gid={gid}", current_uid()))
        .arg(img)
        .arg(mnt))
}

fn umount(mnt: &Path) -> bool {
    ok(privileged("umount").arg(mnt))
}

/// Every tool these tests build disks with; without one they are skipped.
fn tools() -> bool {
    let missing: Vec<&str> = [
        "mkfs.vfat",
        "mmd",
        "mcopy",
        "sgdisk",
        "qemu-img",
        "mkntfs",
        "ntfs-3g",
        "ntfscat",
        "ntfsinfo",
    ]
    .into_iter()
    .filter(|t| !ok(Command::new("sh").arg("-c").arg(format!("command -v {t}"))))
    .collect();
    if !missing.is_empty() {
        eprintln!("{missing:?} unavailable: skipped");
    }
    missing.is_empty()
}
