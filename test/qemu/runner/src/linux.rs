//! Linux end to end (DESIGN.md §3a): OVMF → `paguro.efi` → the UKI inside
//! the image's own ESP (or an `efi_file` on NTFS) → `paguro-initrd` in the
//! UKI's initramfs → the root mounted from dm-paguro's view A → a marker
//! service (`test/qemu/linux/marker.sh`) that checks the result and powers
//! off. The images come from `test/qemu/linux-e2e.sh` (`--linux DIR`:
//! `uki.efi`, `rootfs/`); everything else is built here with the same
//! third-party tools as stage 4 (`mkfs.ext4 -d`, `sgdisk`, `mkfs.vfat` +
//! mtools, `qemu-img`, `mkntfs` + ntfs-3g, `test/fixtures/bde/make.sh`).
//!
//! After the VM, the host reads the disk back independently: `ntfscat`
//! (and, for BitLocker, `paguro-bde-read`) extracts the image, and
//! `e2fsck -fn` must find the root clean.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::stage4::{
    NTFS_VOLUME, Part, boot_disk, fat32, fragment, gpt, identity, ini, io, mkntfs, ntfscat,
    set_dirty, vhd, with_ntfs, write,
};
use crate::{BOOT_WAIT, Env, R, STRETCH_WAIT, Vm, fresh, sh};

const ESP_MIB: u64 = 48;
const ROOT_MIB: u64 = 64;
const NTFS_MIB: u64 = 400;
/// The loader's ESP in `boot_disk`.
const BOOT_ESP_MIB: u64 = 34;

fn dir(env: &Env) -> R<PathBuf> {
    let d = env.work.join("linux-images");
    io(std::fs::create_dir_all(&d))?;
    // boot_disk writes under work/stage4.
    io(std::fs::create_dir_all(env.work.join("stage4")))?;
    Ok(d)
}

fn inputs(env: &Env) -> R<(PathBuf, PathBuf)> {
    let l = env
        .linux
        .as_ref()
        .ok_or("no --linux (run test/qemu/linux-e2e.sh)")?;
    Ok((l.join("uki.efi"), l.join("rootfs")))
}

/// An ext4 of `mib` MiB populated from the root directory.
fn ext4(env: &Env, out: &Path, mib: u64) -> R<()> {
    let (_, rootfs) = inputs(env)?;
    let _ = std::fs::remove_file(out);
    sh(Command::new("mkfs.ext4")
        .args([
            "-q",
            "-F",
            "-L",
            "paguro-root",
            // Several block groups: the payload check needs group 1's
            // backup superblock, and one 4 KiB-block group would hold all
            // 64 MiB.
            "-g",
            "4096",
            "-E",
            "root_owner=0:0",
            "-d",
        ])
        .arg(&rootfs)
        .arg(out)
        .arg(format!("{mib}M"))
        .stdout(Stdio::null()))
}

/// A fixed VHD: GPT with an ESP (the UKI as the removable-media default)
/// and an x86-64 root partition.
fn gpt_vhd(env: &Env, name: &str) -> R<PathBuf> {
    let d = dir(env)?;
    let (uki, _) = inputs(env)?;
    let uki = io(std::fs::read(uki))?;
    let esp = d.join(format!("{name}.esp"));
    fat32(&esp, ESP_MIB, &[("EFI/BOOT/BOOTX64.EFI", &uki)])?;
    let root = d.join(format!("{name}.ext4"));
    ext4(env, &root, ROOT_MIB)?;
    let raw = d.join(format!("{name}.raw"));
    gpt(
        &raw,
        ESP_MIB + ROOT_MIB + 2,
        &[
            Part {
                code: "ef00",
                mib: ESP_MIB,
                image: Some(&esp),
                guid: None,
            },
            Part {
                code: "8304",
                mib: ROOT_MIB,
                image: Some(&root),
                guid: None,
            },
        ],
    )?;
    let out = d.join(format!("{name}.vhd"));
    vhd(&raw, &out, "fixed")?;
    for p in [esp, root, raw] {
        let _ = std::fs::remove_file(p);
    }
    Ok(out)
}

/// A fixed VHD holding one bare ext4 (the paguro host's shape, INTERFACES
/// §3.2).
fn bare_vhd(env: &Env, name: &str) -> R<PathBuf> {
    let d = dir(env)?;
    let raw = d.join(format!("{name}.ext4"));
    ext4(env, &raw, ROOT_MIB)?;
    let out = d.join(format!("{name}.vhd"));
    vhd(&raw, &out, "fixed")?;
    let _ = std::fs::remove_file(raw);
    Ok(out)
}

/// A fresh NTFS volume holding `files` (NTFS path, source).
fn ntfs(env: &Env, name: &str, files: &[(&str, &Path)]) -> R<PathBuf> {
    let img = dir(env)?.join(format!("{name}.ntfs"));
    mkntfs(&img, NTFS_MIB)?;
    with_ntfs(&img, |m| {
        for (dst, src) in files {
            io(std::fs::create_dir_all(m.join(dst).parent().unwrap_or(m)))?;
            io(std::fs::copy(src, m.join(dst)))?;
        }
        Ok(())
    })?;
    Ok(img)
}

/// What a boot is expected to show.
struct Expect<'a> {
    /// The root device paguro-initrd names.
    root: &'a str,
    /// The device-mapper chain under the root, top first.
    chain: &'a str,
    /// The root image's identity (the claim).
    id: (u64, u16),
    ro: bool,
    /// The module itself made the claim read-only (dirty volume). A
    /// hibernated Windows is the initrd's call alone: the module cannot
    /// see `hiberfil.sys`.
    claim_ro: bool,
    boot: u32,
}

/// Run the VM until the marker service reports, then wait for poweroff.
fn run_linux(
    env: &Env,
    name: &str,
    disk: &Path,
    snapshot: bool,
    unlock: impl FnOnce(&mut Vm) -> R<()>,
    e: &Expect<'_>,
) -> R<String> {
    let (vars, state) = fresh(env, name, "OVMF_VARS_4M.fd")?;
    let mut vm = Vm::launch_disks(
        env,
        name,
        false,
        &[(disk, snapshot)],
        &vars,
        &state,
        None,
        &[],
        1024,
    )?;
    let r = (|| {
        vm.expect("paguro 0.0.0", BOOT_WAIT)?;
        unlock(&mut vm)?;
        vm.expect("PAGURO-INITRD: start", 240)?;
        let va = format!("paguro-initrd: PG_CLAIM 1 (MFT {} seq {})", e.id.0, e.id.1);
        vm.expect(&va, 120)?;
        vm.expect("(payload check passed)", 60)?;
        let mode = if e.ro { "ro" } else { "rw" };
        vm.expect(
            &format!("PAGURO-INITRD: root {} mounted {mode}", e.root),
            60,
        )?;
        vm.expect(&format!("PAGURO-LINUX: root={} up", e.root), 120)?;
        vm.expect(&format!("PAGURO-LINUX: chain: {}", e.chain), 20)?;
        vm.expect(
            &format!(
                "PAGURO-LINUX: status claim 1 volume 1 mft {} seq {} state {}",
                e.id.0,
                e.id.1,
                if e.claim_ro {
                    "readonly,checked"
                } else {
                    "checked"
                }
            ),
            20,
        )?;
        vm.expect("PAGURO-LINUX: handoff consumed and zeroed", 30)?;
        if e.ro {
            vm.expect("PAGURO-LINUX: root read-only (write refused)", 30)?;
        } else {
            if e.boot > 1 {
                vm.expect("PAGURO-LINUX: data from boot 1 intact", 60)?;
            }
            vm.expect(&format!("PAGURO-LINUX: boot count {}", e.boot), 60)?;
        }
        vm.expect("PAGURO-LINUX: done", 60)?;
        // poweroff -f; -no-reboot makes QEMU exit.
        let t0 = Instant::now();
        while t0.elapsed() < Duration::from_secs(60) {
            if let Ok(Some(_)) = vm.child.try_wait() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let t = vm.text();
        for bad in ["CHECK FAILED", "PAGURO-INITRD: FAIL", "Kernel panic"] {
            if let Some(i) = t.find(bad) {
                let line = t[i..].lines().next().unwrap_or("");
                return Err(line.to_string());
            }
        }
        Ok(())
    })();
    let text = vm.stop();
    r.map(|()| text)
}

fn no_unlock(_: &mut Vm) -> R<()> {
    Ok(())
}

/// Bytes `[at, at + len)` of `img` into `out`.
fn extract(img: &Path, at: u64, len: u64, out: &Path) -> R<()> {
    let _ = std::fs::remove_file(out);
    sh(Command::new("dd")
        .arg(format!("if={}", img.display()))
        .arg(format!("of={}", out.display()))
        .args([
            "bs=1M",
            "iflag=skip_bytes,count_bytes",
            "status=none",
            "conv=sparse",
        ])
        .arg(format!("skip={at}"))
        .arg(format!("count={len}")))
}

/// The NTFS partition of a boot disk (`boot_disk`'s layout).
fn ntfs_of(disk: &Path, out: &Path) -> R<()> {
    extract(
        disk,
        (2048 + BOOT_ESP_MIB * 2048) * 512,
        NTFS_MIB << 20,
        out,
    )
}

/// `e2fsck -fn` on the root inside `vhd_path` on the NTFS image `ntfs_img`
/// (read with ntfs-3g's `ntfscat`, independent of paguro).
fn fsck_root(ntfs_img: &Path, vhd_path: &str, gpt: bool) -> R<()> {
    let data = ntfscat(ntfs_img, vhd_path)?;
    let tmp = ntfs_img.with_extension("root.ext4");
    let (at, len) = if gpt {
        ((2048 + ESP_MIB * 2048) * 512, ROOT_MIB << 20)
    } else {
        (0, ROOT_MIB << 20)
    };
    let slice = data
        .get(at as usize..(at + len) as usize)
        .ok_or("the image is shorter than its root")?;
    io(std::fs::write(&tmp, slice))?;
    let out = io(Command::new("e2fsck").args(["-fn"]).arg(&tmp).output())?;
    let _ = std::fs::remove_file(&tmp);
    if !out.status.success() {
        return Err(format!(
            "e2fsck -fn: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

const ROOT_P2: &str = "/dev/mapper/paguro-linux-p2";
const CHAIN_PLAIN: &str = "paguro-linux-p2 paguro-linux\n";

/// Unencrypted NTFS, GPT VHD with the UKI in its own ESP.
pub fn plain(env: &Env) -> R<()> {
    let v = gpt_vhd(env, "plain")?;
    let n = ntfs(env, "plain", &[("paguro/linux.vhd", &v)])?;
    let id = identity(&n, "/paguro/linux.vhd")?;
    let disk = boot_disk(
        env,
        "linux-plain",
        &env.efi,
        "EFI/BOOT/BOOTX64.EFI",
        Some(&ini("root = \\paguro\\linux.vhd")),
        &n,
        NTFS_VOLUME,
        &[],
        None,
    )?;
    let e = Expect {
        root: ROOT_P2,
        chain: CHAIN_PLAIN,
        id,
        ro: false,
        claim_ro: false,
        boot: 1,
    };
    run_linux(env, "linux-plain", &disk, true, no_unlock, &e)?;
    for p in [disk, n, v] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// Two boots of one disk, written through: boot 2 sees boot 1's data, and
/// afterwards the host finds the root's ext4 clean.
pub fn persist(env: &Env) -> R<()> {
    let v = gpt_vhd(env, "persist")?;
    let n = ntfs(env, "persist", &[("paguro/linux.vhd", &v)])?;
    let id = identity(&n, "/paguro/linux.vhd")?;
    let disk = boot_disk(
        env,
        "linux-persist",
        &env.efi,
        "EFI/BOOT/BOOTX64.EFI",
        Some(&ini("root = \\paguro\\linux.vhd")),
        &n,
        NTFS_VOLUME,
        &[],
        None,
    )?;
    for boot in 1..=2 {
        let e = Expect {
            root: ROOT_P2,
            chain: CHAIN_PLAIN,
            id,
            ro: false,
            claim_ro: false,
            boot,
        };
        run_linux(
            env,
            &format!("linux-persist-{boot}"),
            &disk,
            false,
            no_unlock,
            &e,
        )?;
    }
    let after = n.with_extension("after");
    ntfs_of(&disk, &after)?;
    fsck_root(&after, "/paguro/linux.vhd", true)?;
    for p in [disk, n, v, after] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

const BDE_PASSWORD: &str = "paguro-linux";

/// BitLocker NTFS (password typed): the decrypted volume is BitLocker's own
/// segment table under dm-crypt. Two boots written through; afterwards the
/// host decrypts the volume with paguro's own reader and fscks the root.
pub fn bde(env: &Env) -> R<()> {
    bde_case(env, "linux-bde", &[])
}

/// A partially encrypted volume (conversion paused) whose boundary cuts
/// through the root partition: the table's `crypt` segment ends and a
/// `linear` one begins inside the image, and both halves are written.
pub fn bde_partial(env: &Env) -> R<()> {
    bde_case(env, "linux-bde-partial", &["--encrypted-size", "half"])
}

/// The first run of `path` on `img`: (LCN, clusters), from ntfsinfo.
fn first_run(img: &Path, path: &str) -> R<(u64, u64)> {
    let out = io(Command::new("ntfsinfo")
        .args(["-v", "-F", path])
        .arg(img)
        .output())?;
    let t = String::from_utf8_lossy(&out.stdout);
    let mut lines = t.lines().skip_while(|l| !l.contains("Runlist:")).skip(1);
    let l = lines.next().ok_or("ntfsinfo: no runlist")?;
    let f: Vec<u64> = l
        .split_whitespace()
        .filter_map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16).ok())
        .collect();
    match f.as_slice() {
        [_, lcn, len, ..] => Ok((*lcn, *len)),
        _ => Err(format!("ntfsinfo: bad run line {l:?}")),
    }
}

fn bde_case(env: &Env, name: &str, extra: &[&str]) -> R<()> {
    let v = gpt_vhd(env, name)?;
    let n = ntfs(env, name, &[("paguro/linux.vhd", &v)])?;
    let id = identity(&n, "/paguro/linux.vhd")?;
    let half;
    let mut extra = extra.to_vec();
    if let Some(x) = extra.iter_mut().find(|x| **x == "half") {
        let (lcn, len) = first_run(&n, "/paguro/linux.vhd")?;
        half = ((lcn + len / 2) * 4096).to_string();
        *x = &half;
    }
    let enc = n.with_extension("bde");
    let top = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
    let mut c = Command::new(top.join("test/fixtures/bde/make.sh"));
    c.arg(&n)
        .arg(&enc)
        .args(["--password", BDE_PASSWORD, "--seed", "51", "--no-verify"])
        .args(&extra);
    let w = top.join("target/release/paguro-bde-write");
    if w.exists() {
        c.env("PAGURO_BDE_WRITE", w);
    }
    sh(c.stdout(Stdio::null()))?;
    let disk = boot_disk(
        env,
        name,
        &env.efi,
        "EFI/BOOT/BOOTX64.EFI",
        Some(&ini("root = \\paguro\\linux.vhd")),
        &enc,
        NTFS_VOLUME,
        &[],
        None,
    )?;
    let unlock = |vm: &mut Vm| -> R<()> {
        vm.expect("Unlock Linux", 60)?;
        vm.send("1")?;
        vm.expect("Enter your password or PIN", 10)?;
        vm.send(BDE_PASSWORD)?;
        vm.send("\r")?;
        vm.expect("handoff published", STRETCH_WAIT)
    };
    for boot in 1..=2 {
        let e = Expect {
            root: ROOT_P2,
            chain: "paguro-linux-p2 paguro-linux paguro-volume\n",
            id,
            ro: false,
            claim_ro: false,
            boot,
        };
        let t = run_linux(env, &format!("{name}-{boot}"), &disk, false, unlock, &e)?;
        if !t.contains("(BitLocker)") || !t.contains("paguro-initrd: decrypted volume:") {
            return Err("no decrypted volume in the initrd's log".into());
        }
    }
    // The host's independent check: paguro's BitLocker reader decrypts the
    // partition, ntfs-3g reads the image, e2fsck reads the root.
    let part = n.with_extension("after.bde");
    ntfs_of(&disk, &part)?;
    let plainv = n.with_extension("after.plain");
    let reader = top.join("target/release/paguro-bde-read");
    if !reader.exists() {
        sh(Command::new("cargo")
            .args([
                "build",
                "-q",
                "--release",
                "-p",
                "paguro-harness",
                "--bin",
                "paguro-bde-read",
            ])
            .current_dir(&top))?;
    }
    sh(Command::new(reader)
        .arg("--input")
        .arg(&part)
        .args(["--password", BDE_PASSWORD, "--output"])
        .arg(&plainv)
        .stdout(Stdio::null()))?;
    fsck_root(&plainv, "/paguro/linux.vhd", true)?;
    for p in [disk, n, v, enc, part, plainv] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// The paguro host's shape: the UKI as an `efi_file` on NTFS, the root a
/// VHD holding one bare ext4.
pub fn bare(env: &Env) -> R<()> {
    let (uki, _) = inputs(env)?;
    let v = bare_vhd(env, "bare")?;
    let n = ntfs(
        env,
        "bare",
        &[("paguro/host.vhd", &v), ("paguro/host.efi", &uki)],
    )?;
    let id = identity(&n, "/paguro/host.vhd")?;
    let disk = boot_disk(
        env,
        "linux-bare",
        &env.efi,
        "EFI/BOOT/BOOTX64.EFI",
        Some(&ini(
            "root = \\paguro\\host.vhd\nefi_file = \\paguro\\host.efi",
        )),
        &n,
        NTFS_VOLUME,
        &[],
        None,
    )?;
    let e = Expect {
        root: "/dev/mapper/paguro-linux",
        chain: "paguro-linux\n",
        id,
        ro: false,
        claim_ro: false,
        boot: 1,
    };
    run_linux(env, "linux-bare", &disk, false, no_unlock, &e)?;
    let after = n.with_extension("after");
    ntfs_of(&disk, &after)?;
    fsck_root(&after, "/paguro/host.vhd", false)?;
    for p in [disk, n, v, after] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// The VHD fragmented on NTFS (16 runs, stored in reverse): view A gathers
/// it, and the payload check reads past the first extent.
pub fn frag(env: &Env) -> R<()> {
    let v = gpt_vhd(env, "frag")?;
    let n = ntfs(env, "frag", &[("paguro/linux.vhd", &v)])?;
    fragment(&n, "/paguro/linux.vhd", 16)?;
    let id = identity(&n, "/paguro/linux.vhd")?;
    let disk = boot_disk(
        env,
        "linux-frag",
        &env.efi,
        "EFI/BOOT/BOOTX64.EFI",
        Some(&ini("root = \\paguro\\linux.vhd")),
        &n,
        NTFS_VOLUME,
        &[],
        None,
    )?;
    let e = Expect {
        root: ROOT_P2,
        chain: CHAIN_PLAIN,
        id,
        ro: false,
        claim_ro: false,
        boot: 1,
    };
    let t = run_linux(env, "linux-frag", &disk, false, no_unlock, &e)?;
    if !t.contains("paguro-initrd: PG_CLAIM 1")
        || !t.contains(" 17 extents,") && !t.contains(" 16 extents,")
    {
        return Err("the claim is not fragmented".into());
    }
    let after = n.with_extension("after");
    ntfs_of(&disk, &after)?;
    fsck_root(&after, "/paguro/linux.vhd", true)?;
    for p in [disk, n, v, after] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

fn degraded(
    env: &Env,
    name: &str,
    patch: impl FnOnce(&Path) -> R<()>,
    notice: &str,
    claim_ro: bool,
) -> R<()> {
    let v = gpt_vhd(env, name)?;
    let n = ntfs(env, name, &[("paguro/linux.vhd", &v)])?;
    // ntfsinfo refuses a dirty volume: the identity first.
    let id = identity(&n, "/paguro/linux.vhd")?;
    patch(&n)?;
    let disk = boot_disk(
        env,
        name,
        &env.efi,
        "EFI/BOOT/BOOTX64.EFI",
        Some(&ini("root = \\paguro\\linux.vhd")),
        &n,
        NTFS_VOLUME,
        &[],
        None,
    )?;
    let ntfs_before = n.with_extension("before");
    ntfs_of(&disk, &ntfs_before)?;
    let e = Expect {
        root: ROOT_P2,
        chain: CHAIN_PLAIN,
        id,
        ro: true,
        claim_ro,
        boot: 1,
    };
    let notice = notice.to_string();
    run_linux(
        env,
        name,
        &disk,
        false,
        move |vm: &mut Vm| {
            vm.expect(&notice, 60)?;
            vm.send("\r")
        },
        &e,
    )?;
    // Read-only all the way down: not one byte of the volume changed (the
    // ESP's recorded.bin is written on every boot, degraded or not).
    let ntfs_after = n.with_extension("after");
    ntfs_of(&disk, &ntfs_after)?;
    if io(std::fs::read(&ntfs_after))? != io(std::fs::read(&ntfs_before))? {
        return Err("a read-only boot changed the NTFS volume".into());
    }
    for p in [disk, n, v, ntfs_before, ntfs_after] {
        let _ = std::fs::remove_file(p);
    }
    Ok(())
}

/// The NTFS dirty bit: the root comes up read-only.
pub fn dirty(env: &Env) -> R<()> {
    degraded(
        env,
        "linux-dirty",
        set_dirty,
        "Windows didn't shut down cleanly last time",
        true,
    )
}

/// A hibernated Windows (`hiberfil.sys` starting `HIBR`): read-only too —
/// initrd policy, since only the loader sees the hibernation file.
pub fn hibernated(env: &Env) -> R<()> {
    degraded(
        env,
        "linux-hibernated",
        |img| {
            with_ntfs(img, |m| {
                let mut h = b"HIBR".to_vec();
                h.resize(64 << 10, 0);
                write(&m.join("hiberfil.sys"), &h)
            })
        },
        "Windows saved a session",
        false,
    )
}
