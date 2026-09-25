//! Stage 4 end to end (DESIGN.md §4.1–4.2, INTERFACES.md §3.2, §8, §13.4):
//! the loader finds the entry's files on a real NTFS volume, publishes the
//! efi disk as a read-only block device, lets the firmware's own FAT driver
//! bind it, and starts `probe.efi` from it — which prints how it was
//! started, reads `\probe.txt` from its **own** FAT32 through its
//! `DeviceHandle`, and prints the handoff's records.
//!
//! Every disk is built with third-party tools: `sgdisk`, `mkfs.vfat` +
//! mtools, `mkntfs` + `ntfs-3g` (FUSE), `qemu-img` (fixed and dynamic VHD).
//! One NTFS volume holds every payload; each scenario differs only in its
//! `paguro.ini` (and, for the gates, a patched copy of the volume).

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

use paguro_core::guid::PAGURO_VENDOR;

use crate::{BOOT_WAIT, Env, R, Vm, fresh, sh, sha256, vars};

/// The NTFS partition's GPT unique GUID (the entries' `volume`).
pub const NTFS_VOLUME: &str = "7d1f0c2a-5b3e-4c8d-9a61-0e2f4b6c8d90";

fn io<T>(r: std::io::Result<T>) -> R<T> {
    r.map_err(|e| e.to_string())
}

fn write(p: &Path, data: &[u8]) -> R<()> {
    if let Some(d) = p.parent() {
        io(std::fs::create_dir_all(d))?;
    }
    io(std::fs::write(p, data))
}

// ---------------------------------------------------------------------------
// FAT32, GPT, VHD

/// A FAT32 file system image of `mib` MiB holding `files` (`/`-separated
/// paths). One sector per cluster keeps small images above the 65 525
/// clusters that make a volume FAT32 to the firmware's driver.
fn fat32(path: &Path, mib: u64, files: &[(&str, &[u8])]) -> R<()> {
    let _ = std::fs::remove_file(path);
    sh(Command::new("mkfs.vfat")
        .args(["-F", "32", "-S", "512", "-s", "1", "-n", "PAYLOAD", "-C"])
        .arg(path)
        .arg((mib * 1024).to_string())
        .stdout(Stdio::null()))?;
    let mut dirs: Vec<String> = Vec::new();
    for (name, _) in files {
        let parts: Vec<&str> = name.split('/').collect();
        for k in 1..parts.len() {
            let d = parts[..k].join("/");
            if !dirs.contains(&d) {
                dirs.push(d);
            }
        }
    }
    for d in &dirs {
        sh(Command::new("mmd")
            .arg("-i")
            .arg(path)
            .arg(format!("::/{d}")))?;
    }
    let stage = path.with_extension("files");
    let _ = std::fs::remove_dir_all(&stage);
    for (i, (name, data)) in files.iter().enumerate() {
        let src = stage.join(format!("{i}"));
        write(&src, data)?;
        sh(Command::new("mcopy")
            .arg("-o")
            .arg("-i")
            .arg(path)
            .arg(&src)
            .arg(format!("::/{name}")))?;
    }
    let _ = std::fs::remove_dir_all(&stage);
    Ok(())
}

/// A partition for [`gpt`]: sgdisk type code, size in MiB, content.
struct Part<'a> {
    code: &'a str,
    mib: u64,
    image: Option<&'a Path>,
    guid: Option<&'a str>,
}

/// A GPT disk of `mib` MiB with `parts` laid out from LBA 2048, each
/// image written into its partition.
fn gpt(path: &Path, mib: u64, parts: &[Part<'_>]) -> R<()> {
    let _ = std::fs::remove_file(path);
    let f = io(std::fs::File::create(path))?;
    io(f.set_len(mib << 20))?;
    drop(f);
    let mut cmd = Command::new("sgdisk");
    let mut start = 2048u64;
    let mut starts = Vec::new();
    for (i, p) in parts.iter().enumerate() {
        let n = i + 1;
        let end = start + (p.mib << 11) - 1;
        cmd.arg("-n").arg(format!("{n}:{start}:{end}"));
        cmd.arg("-t").arg(format!("{n}:{}", p.code));
        if let Some(g) = p.guid {
            cmd.arg("-u").arg(format!("{n}:{g}"));
        }
        starts.push(start);
        start = end + 1;
    }
    sh(cmd.arg(path).stdout(Stdio::null()))?;
    for (p, s) in parts.iter().zip(starts) {
        if let Some(img) = p.image {
            sh(Command::new("dd")
                .arg(format!("if={}", img.display()))
                .arg(format!("of={}", path.display()))
                .args(["bs=1M", "conv=notrunc,sparse", "status=none"])
                .arg("oflag=seek_bytes")
                .arg(format!("seek={}", s * 512)))?;
        }
    }
    Ok(())
}

fn vhd(raw: &Path, out: &Path, subformat: &str) -> R<()> {
    let _ = std::fs::remove_file(out);
    sh(Command::new("qemu-img")
        .args(["convert", "-q", "-f", "raw", "-O", "vpc", "-o"])
        .arg(format!("subformat={subformat},force_size=on"))
        .arg(raw)
        .arg(out))
}

// ---------------------------------------------------------------------------
// NTFS

fn uid_gid() -> (u32, u32) {
    let id = |f: &str| {
        Command::new("id")
            .arg(f)
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    };
    (id("-u"), id("-g"))
}

/// Run `cmd` directly as root, else through `sudo -n` (CI runners).
fn privileged(cmd: &str) -> Command {
    if uid_gid().0 == 0 {
        Command::new(cmd)
    } else {
        let mut c = Command::new("sudo");
        c.arg("-n").arg(cmd);
        c
    }
}

/// Mount the NTFS image `img` with ntfs-3g, let `fill` write into it,
/// unmount.
fn with_ntfs(img: &Path, fill: impl FnOnce(&Path) -> R<()>) -> R<()> {
    let mnt = img.with_extension("mnt");
    let _ = std::fs::remove_dir_all(&mnt);
    io(std::fs::create_dir_all(&mnt))?;
    let (u, g) = uid_gid();
    sh(privileged("ntfs-3g")
        .arg("-o")
        .arg(format!("uid={u},gid={g},umask=022"))
        .arg(img)
        .arg(&mnt))?;
    let r = fill(&mnt);
    let um = sh(privileged("umount").arg(&mnt));
    let _ = std::fs::remove_dir_all(&mnt);
    r?;
    um
}

/// `mkntfs` a volume of `mib` MiB (4 KiB clusters).
fn mkntfs(img: &Path, mib: u64) -> R<()> {
    let _ = std::fs::remove_file(img);
    let f = io(std::fs::File::create(img))?;
    io(f.set_len(mib << 20))?;
    drop(f);
    sh(Command::new("mkntfs")
        .args(["-F", "-f", "-q", "-c", "4096", "-L", "Windows"])
        .arg(img)
        .stderr(Stdio::null()))
}

/// `(MFT record, sequence)` of `path` (`/`-separated) on `img`, as ntfs-3g's
/// `ntfsinfo` reports them: the reference for the handoff's IMAGE records.
pub fn identity(img: &Path, path: &str) -> R<(u64, u16)> {
    let out = Command::new("ntfsinfo")
        .arg("-F")
        .arg(path)
        .arg(img)
        .output()
        .map_err(|e| format!("ntfsinfo: {e}"))?;
    let t = String::from_utf8_lossy(&out.stdout);
    let num = |key: &str| -> Option<u64> {
        let l = t.lines().find(|l| l.starts_with(key))?;
        l[key.len()..]
            .split_whitespace()
            .next()
            .and_then(|v| v.parse().ok())
    };
    let rec = num("Dumping Inode").ok_or_else(|| format!("ntfsinfo {path}: no inode\n{t}"))?;
    let seq = num("MFT Record Seq. Numb.:").ok_or("ntfsinfo: no sequence number")?;
    Ok((rec, seq as u16))
}

/// Rewrite MFT record `recno` of the NTFS image `img` in place: fixups
/// undone, `edit` applied, fixups redone. Only the update-sequence rules
/// are handled here; `edit` keeps the record valid.
fn patch_record(img: &Path, recno: u64, edit: impl FnOnce(&mut Vec<u8>) -> R<()>) -> R<()> {
    use paguro_core::ntfs::{self, Disk, IoError, MAX_ALIST};
    use paguro_core::runlist::Run;
    struct F(std::fs::File);
    impl Disk for F {
        fn read(&mut self, s: u64, b: &mut [u8; 512]) -> Result<(), IoError> {
            use std::os::unix::fs::FileExt;
            self.0.read_exact_at(b, s * 512).map_err(|_| IoError)
        }
    }
    let mut d = F(io(std::fs::File::open(img))?);
    let mut alist = Box::new([0u8; MAX_ALIST]);
    let mut runs = vec![Run { lcn: 0, count: 0 }; 256];
    let m = ntfs::open(&mut d, &mut alist, &mut runs).map_err(|e| format!("{e:?}"))?;
    let rb = m.vol.record_bytes;
    let cb = m.vol.cluster_bytes;
    // The record's byte offset: records never straddle a run here (the
    // volume is fresh from mkntfs and 4 KiB clusters hold whole records).
    let mut off = recno * rb;
    let mut at = None;
    for r in m.runs {
        if off < r.count * cb {
            at = Some(r.lcn * cb + off);
            break;
        }
        off -= r.count * cb;
    }
    let at = at.ok_or("record outside $MFT")?;
    let mut data = io(std::fs::read(img))?;
    let rec = &mut data[at as usize..(at + rb) as usize];
    let count = u16::from_le_bytes([rec[6], rec[7]]) as usize;
    let usa = u16::from_le_bytes([rec[4], rec[5]]) as usize;
    let usn = [rec[usa], rec[usa + 1]];
    for i in 1..count {
        let e = i * 512 - 2;
        rec[e] = rec[usa + 2 * i];
        rec[e + 1] = rec[usa + 2 * i + 1];
    }
    let mut v = rec.to_vec();
    edit(&mut v)?;
    rec.copy_from_slice(&v);
    for i in 1..count {
        let e = i * 512 - 2;
        rec[usa + 2 * i] = rec[e];
        rec[usa + 2 * i + 1] = rec[e + 1];
        rec[e] = usn[0];
        rec[e + 1] = usn[1];
    }
    io(std::fs::write(img, data))
}

fn u16_at(b: &[u8], at: usize) -> usize {
    u16::from_le_bytes([b[at], b[at + 1]]) as usize
}
fn u32_at(b: &[u8], at: usize) -> usize {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap_or([0; 4])) as usize
}

/// Attribute offsets of a (fixed-up) record: `(type, offset, length)`.
fn attrs(rec: &[u8]) -> Vec<(usize, usize, usize)> {
    let mut out = Vec::new();
    let mut pos = u16_at(rec, 0x14);
    while pos + 8 <= rec.len() {
        let ty = u32_at(rec, pos);
        if ty == 0xffff_ffff {
            break;
        }
        let len = u32_at(rec, pos + 4);
        if len == 0 {
            break;
        }
        out.push((ty, pos, len));
        pos += len;
    }
    out
}

/// Set `$Volume`'s dirty bit, as an unclean Windows shutdown leaves it.
fn set_dirty(img: &Path) -> R<()> {
    patch_record(img, 3, |rec| {
        let (_, pos, _) = *attrs(rec)
            .iter()
            .find(|a| a.0 == 0x70)
            .ok_or("no $VOLUME_INFORMATION")?;
        let v = pos + u16_at(rec, pos + 0x14);
        rec[v + 0x0a] |= 1;
        Ok(())
    })
}

/// Mapping pairs for `(lcn, count)` runs.
fn pairs(list: &[(u64, u64)]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut prev = 0i64;
    for &(lcn, count) in list {
        let len: Vec<u8> = {
            let b = count.to_le_bytes();
            let n = (8 - count.leading_zeros() as usize / 8).max(1);
            b[..n].to_vec()
        };
        let delta = lcn as i64 - prev;
        prev = lcn as i64;
        let off: Vec<u8> = {
            let b = delta.to_le_bytes();
            let mut n = 8;
            for k in 1..8 {
                let s = 64 - 8 * k;
                if (delta << s) >> s == delta {
                    n = k;
                    break;
                }
            }
            b[..n].to_vec()
        };
        out.push((off.len() as u8) << 4 | len.len() as u8);
        out.extend(len);
        out.extend(off);
    }
    out.push(0);
    out
}

/// Deliberately fragment the file `path` of the NTFS image `img`, which
/// must be contiguous: its clusters are split into `k` chunks stored in
/// reverse order within the same clusters, and its runlist rewritten to
/// match — `k` runs, none adjacent to the next in file order. The data
/// read through the new map is unchanged (checked with `ntfscat`).
fn fragment(img: &Path, path: &str, k: u64) -> R<()> {
    let (recno, _) = identity(img, path)?;
    let before = ntfscat(img, path)?;
    let mut moved = None;
    patch_record(img, recno, |rec| {
        let (_, pos, len) = *attrs(rec)
            .iter()
            .find(|a| a.0 == 0x80 && rec[a.1 + 9] == 0 && rec[a.1 + 8] == 1)
            .ok_or("no non-resident $DATA")?;
        let is_last = attrs(rec).last().map(|a| a.1) == Some(pos);
        if !is_last {
            return Err("$DATA is not the last attribute".into());
        }
        let mp = u16_at(rec, pos + 0x20);
        let mut runs = [paguro_core::runlist::Run { lcn: 0, count: 0 }; 4];
        let n = paguro_core::runlist::decode(&rec[pos + mp..pos + len], &mut runs)
            .map_err(|e| format!("{e:?}"))?;
        if n != 1 {
            return Err(format!("{path} is already in {n} runs"));
        }
        let (lcn, count) = (runs[0].lcn, runs[0].count);
        let c = count / k;
        if c == 0 {
            return Err("file too small to fragment".into());
        }
        // Chunk i (VCN i*c) is stored at LCN lcn + (k-1-i)*c; the remainder
        // stays where it was, at the end.
        let mut list: Vec<(u64, u64)> = (0..k).map(|i| (lcn + (k - 1 - i) * c, c)).collect();
        if count > k * c {
            list.push((lcn + k * c, count - k * c));
        }
        let p = pairs(&list);
        let new_len = (mp + p.len()).div_ceil(8) * 8;
        let end = pos + new_len;
        if end + 8 > rec.len() {
            return Err("runlist does not fit the record".into());
        }
        rec[pos + mp..pos + mp + p.len()].copy_from_slice(&p);
        for b in &mut rec[pos + mp + p.len()..end] {
            *b = 0;
        }
        rec[pos + 4..pos + 8].copy_from_slice(&(new_len as u32).to_le_bytes());
        rec[end..end + 8].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0]);
        rec[0x18..0x1c].copy_from_slice(&((end + 8) as u32).to_le_bytes());
        moved = Some((lcn, c, k));
        Ok(())
    })?;
    // Move the data to match the new map.
    let (lcn, c, k) = moved.ok_or("nothing moved")?;
    let cb = 4096u64;
    let mut data = io(std::fs::read(img))?;
    let base = (lcn * cb) as usize;
    let chunk = (c * cb) as usize;
    let orig = data[base..base + (k as usize) * chunk].to_vec();
    for i in 0..k as usize {
        let dst = base + (k as usize - 1 - i) * chunk;
        data[dst..dst + chunk].copy_from_slice(&orig[i * chunk..(i + 1) * chunk]);
    }
    io(std::fs::write(img, data))?;
    if ntfscat(img, path)? != before {
        return Err(format!("{path}: ntfscat disagrees after fragmenting"));
    }
    Ok(())
}

fn ntfscat(img: &Path, path: &str) -> R<Vec<u8>> {
    let out = Command::new("ntfscat")
        .arg(img)
        .arg(path)
        .output()
        .map_err(|e| format!("ntfscat: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "ntfscat {path}: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

// ---------------------------------------------------------------------------
// The shared volume

/// Everything the scenarios boot from.
pub struct Volume {
    /// The NTFS partition image.
    pub ntfs: PathBuf,
}

/// The payloads' `\probe.txt` markers.
const GPT_MARK: &str = "own FAT of gpt.vhd";

fn probe_bytes(env: &Env, signed: bool) -> R<Vec<u8>> {
    let p = if signed {
        env.probe_signed.as_ref().ok_or("no signed probe")?
    } else {
        env.probe.as_ref().ok_or("no --probe")?
    };
    io(std::fs::read(p))
}

/// A GPT disk image (raw) with one ESP holding the probe as the
/// removable-media default for both architectures, at a non-default path,
/// signed, a garbage "image", and `\probe.txt` = `mark`.
fn esp_disk(env: &Env, dir: &Path, name: &str, mark: &str) -> R<PathBuf> {
    let probe = probe_bytes(env, false)?;
    let mut files: Vec<(String, Vec<u8>)> = vec![
        ("EFI/BOOT/BOOTX64.EFI".into(), probe.clone()),
        ("EFI/other/probe.efi".into(), probe.clone()),
        (
            "EFI/bad/garbage.efi".into(),
            b"MZ this is not a PE image at all".repeat(64),
        ),
        ("probe.txt".into(), mark.as_bytes().to_vec()),
    ];
    if env.probe_signed.is_some() {
        files.push(("EFI/signed/probe.efi".into(), probe_bytes(env, true)?));
    }
    if let Some(p) = &env.probe_aa64 {
        files.push(("EFI/BOOT/BOOTAA64.EFI".into(), io(std::fs::read(p))?));
    }
    let fat = dir.join(format!("{name}.fat"));
    let refs: Vec<(&str, &[u8])> = files
        .iter()
        .map(|(a, b)| (a.as_str(), b.as_slice()))
        .collect();
    fat32(&fat, 34, &refs)?;
    let raw = dir.join(format!("{name}.raw"));
    gpt(
        &raw,
        36,
        &[Part {
            code: "ef00",
            mib: 34,
            image: Some(&fat),
            guid: None,
        }],
    )?;
    let _ = std::fs::remove_file(&fat);
    Ok(raw)
}

/// Build the shared NTFS volume once per run.
pub fn volume(env: &Env) -> R<&'static Volume> {
    static V: OnceLock<Result<Volume, String>> = OnceLock::new();
    V.get_or_init(|| build_volume(env))
        .as_ref()
        .map_err(Clone::clone)
}

fn build_volume(env: &Env) -> R<Volume> {
    let dir = env.work.join("stage4");
    let _ = std::fs::remove_dir_all(&dir);
    io(std::fs::create_dir_all(&dir))?;
    let t0 = std::time::Instant::now();

    // Payloads.
    let gpt_raw = esp_disk(env, &dir, "gpt", GPT_MARK)?;
    let gpt_vhd = dir.join("gpt.vhd");
    vhd(&gpt_raw, &gpt_vhd, "fixed")?;
    let img_raw = esp_disk(env, &dir, "raw", "own FAT of raw.img")?;
    let frag_raw = esp_disk(env, &dir, "frag", "own FAT of frag.vhd")?;
    let frag_vhd = dir.join("frag.vhd");
    vhd(&frag_raw, &frag_vhd, "fixed")?;
    let dyn_vhd = dir.join("dynamic.vhd");
    vhd(&gpt_raw, &dyn_vhd, "dynamic")?;
    // A superfloppy: FAT32 on the whole disk.
    let sf = dir.join("sf.fat");
    let probe = probe_bytes(env, false)?;
    let mut sf_files: Vec<(&str, &[u8])> = vec![
        ("EFI/BOOT/BOOTX64.EFI", &probe),
        ("probe.txt", b"own FAT of superfloppy.vhd"),
    ];
    let aa;
    if let Some(p) = &env.probe_aa64 {
        aa = io(std::fs::read(p))?;
        sf_files.push(("EFI/BOOT/BOOTAA64.EFI", &aa));
    }
    fat32(&sf, 34, &sf_files)?;
    let sf_vhd = dir.join("superfloppy.vhd");
    vhd(&sf, &sf_vhd, "fixed")?;
    // Refusals: no ESP, two ESPs, a broken FAT32 boot sector.
    let small = dir.join("small.fat");
    fat32(&small, 1, &[])?;
    let noesp = dir.join("noesp.img");
    gpt(
        &noesp,
        4,
        &[Part {
            code: "8300",
            mib: 1,
            image: Some(&small),
            guid: None,
        }],
    )?;
    let twoesp = dir.join("twoesp.img");
    gpt(
        &twoesp,
        4,
        &[
            Part {
                code: "ef00",
                mib: 1,
                image: None,
                guid: None,
            },
            Part {
                code: "ef00",
                mib: 1,
                image: None,
                guid: None,
            },
        ],
    )?;
    let badfat = dir.join("badfat.fat");
    let mut b = io(std::fs::read(&gpt_raw))?;
    // The ESP's boot sector: the FS type and signature broken.
    let at = 2048 * 512;
    b[at + 82..at + 90].copy_from_slice(b"NOTAFAT!");
    let badfat_img = dir.join("badfat.img");
    io(std::fs::write(&badfat_img, &b))?;
    let _ = std::fs::remove_file(&badfat);
    // A root disk the loader must not read (a bare ext4-shaped blob).
    let root = dir.join("root.img");
    io(std::fs::write(&root, vec![0x5au8; 1 << 20]))?;

    let ntfs = dir.join("ntfs.img");
    mkntfs(&ntfs, 400)?;
    let copies: Vec<(&str, &Path)> = vec![
        ("paguro/gpt.vhd", &gpt_vhd),
        ("paguro/raw.img", &img_raw),
        ("paguro/frag.vhd", &frag_vhd),
        ("paguro/superfloppy.vhd", &sf_vhd),
        ("paguro/dynamic.vhd", &dyn_vhd),
        ("paguro/noesp.img", &noesp),
        ("paguro/twoesp.img", &twoesp),
        ("paguro/badfat.img", &badfat_img),
        ("paguro/root.img", &root),
    ];
    let probe_file = probe.clone();
    with_ntfs(&ntfs, |m| {
        for (dst, src) in &copies {
            io(std::fs::create_dir_all(m.join(dst).parent().unwrap_or(m)))?;
            io(std::fs::copy(src, m.join(dst)))?;
        }
        write(&m.join("paguro/probe.efi"), &probe_file)?;
        // Existence alone means nothing: a kept, inactive hibernation file.
        let mut hib = b"wake".to_vec();
        hib.resize(64 << 10, 0);
        write(&m.join("hiberfil.sys"), &hib)?;
        // A sparse disk (a hole where data should be).
        let f = io(std::fs::File::create(m.join("paguro/sparse.vhd")))?;
        io(f.set_len(8 << 20))?;
        drop(f);
        // A compressed disk: files created in a compressed directory are.
        let cdir = m.join("compressed");
        io(std::fs::create_dir_all(&cdir))?;
        let _ = Command::new("setfattr")
            .args(["-h", "-v", "0x00000800", "-n", "system.ntfs_attrib_be"])
            .arg(&cdir)
            .output();
        io(std::fs::copy(&gpt_vhd, cdir.join("gpt.vhd")))?;
        Ok(())
    })?;
    fragment(&ntfs, "/paguro/frag.vhd", 16)?;
    for p in [
        gpt_raw, img_raw, frag_raw, sf, small, gpt_vhd, frag_vhd, dyn_vhd, sf_vhd, noesp, twoesp,
        badfat_img, root,
    ] {
        let _ = std::fs::remove_file(p);
    }
    println!(
        "  (stage 4 volume built in {:.1}s)",
        t0.elapsed().as_secs_f32()
    );
    Ok(Volume { ntfs })
}

// ---------------------------------------------------------------------------
// Boot disks and scenarios

/// A boot disk: GPT with the loader's ESP (`paguro.efi` as the
/// removable-media default, `\EFI\paguro\paguro.ini` when given) and the
/// NTFS partition `ntfs` under `guid`.
#[allow(clippy::too_many_arguments)]
fn boot_disk(
    env: &Env,
    name: &str,
    efi: &Path,
    arch_default: &str,
    ini: Option<&[u8]>,
    ntfs: &Path,
    guid: &str,
    extra: &[(&str, &[u8])],
) -> R<PathBuf> {
    let dir = env.work.join("stage4");
    let esp = dir.join(format!("{name}-esp.fat"));
    let loader = io(std::fs::read(efi))?;
    let mut files: Vec<(&str, &[u8])> = vec![(arch_default, &loader)];
    // Firmware that boots its built-in shell first runs this (see make_esp).
    let nsh = format!("FS0:\r\n\\{}\r\n", arch_default.replace('/', "\\"));
    files.push(("startup.nsh", nsh.as_bytes()));
    if let Some(i) = ini {
        files.push(("EFI/paguro/paguro.ini", i));
    }
    files.extend_from_slice(extra);
    fat32(&esp, 34, &files)?;
    let ntfs_mib = io(std::fs::metadata(ntfs))?.len() >> 20;
    let disk = dir.join(format!("{name}-disk.img"));
    gpt(
        &disk,
        34 + ntfs_mib + 2,
        &[
            Part {
                code: "ef00",
                mib: 34,
                image: Some(&esp),
                guid: None,
            },
            Part {
                code: "0700",
                mib: ntfs_mib,
                image: Some(ntfs),
                guid: Some(guid),
            },
        ],
    )?;
    let _ = std::fs::remove_file(&esp);
    Ok(disk)
}

fn ini(entry: &str) -> Vec<u8> {
    format!(
        "# paguro configuration. Not hand-editable: use `paguro config`.\n[Paguro]\nversion = 1\ndefault = linux\n\n[Boot.linux]\nvolume = {NTFS_VOLUME}\n{entry}\n"
    )
    .into_bytes()
}

/// What a scenario boots.
struct Case<'a> {
    name: &'a str,
    ini: Option<Vec<u8>>,
    secure: bool,
    /// Patch the NTFS copy (dirty bit, hibernation file).
    ntfs: Option<PathBuf>,
    guid: &'a str,
}

fn boot(env: &Env, c: &Case<'_>, script: impl FnOnce(&mut Vm) -> R<()>) -> R<()> {
    let v = volume(env)?;
    let efi = if c.secure {
        env.efi_signed.as_ref().ok_or("no signed loader")?
    } else {
        &env.efi
    };
    let ntfs = c.ntfs.as_deref().unwrap_or(&v.ntfs);
    let disk = boot_disk(
        env,
        c.name,
        efi,
        "EFI/BOOT/BOOTX64.EFI",
        c.ini.as_deref(),
        ntfs,
        c.guid,
        &[],
    )?;
    let template = if c.secure {
        "OVMF_VARS_4M.snakeoil.fd"
    } else {
        "OVMF_VARS_4M.fd"
    };
    let (vars, state) = fresh(env, c.name, template)?;
    if let (true, Some(i)) = (c.secure, &c.ini) {
        vars::inject(&vars, "PaguroConfigHash", &PAGURO_VENDOR, 7, &sha256(&[i]))?;
    }
    let mut vm = Vm::start_disks(env, c.name, c.secure, &[&disk], &vars, &state)?;
    let r = (|| {
        vm.expect("paguro 0.0.0", BOOT_WAIT)?;
        script(&mut vm)
    })();
    vm.stop();
    let _ = std::fs::remove_file(&disk);
    r
}

fn probe_ok(vm: &mut Vm, mark: &str) -> R<String> {
    let from = vm.capture("PAGURO-PROBE: started from ", 60)?;
    if !from.contains("VenMedia(") {
        return Err(format!("probe not started from paguro's disk: {from}"));
    }
    vm.expect(&format!("PAGURO-PROBE: probe.txt: {mark}"), 20)?;
    Ok(from)
}

fn image_line(role: &str, name: &str, id: (u64, u16)) -> String {
    format!(
        "PAGURO-PROBE: image role={role} name={name} mft={} seq={}",
        id.0, id.1
    )
}

/// `efi_disk` = a fixed VHD with GPT + ESP: the firmware's FAT driver binds
/// paguro's block device (tier 1), the probe reads its own FAT32 through
/// its DeviceHandle, and the handoff names the root (the same file).
pub fn vhd_gpt(env: &Env) -> R<()> {
    let v = volume(env)?;
    let id = identity(&v.ntfs, "/paguro/gpt.vhd")?;
    let c = Case {
        name: "s4-vhd-gpt",
        ini: Some(ini("root = \\paguro\\gpt.vhd")),
        secure: false,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        vm.expect("stage4 ntfs mounted", 60)?;
        vm.expect("stage4 gates: state=0x0", 20)?;
        vm.expect("Vhd payload of", 20)?;
        vm.expect("tier 1: firmware FAT bound", 60)?;
        vm.expect("handoff published", 20)?;
        let from = probe_ok(vm, GPT_MARK)?;
        if !from.contains("HD(1,GPT") {
            return Err(format!("not the ESP child: {from}"));
        }
        vm.expect("PAGURO-PROBE: handoff rung=Unencrypted state=0x4", 10)?;
        vm.expect(&image_line("root", "linux", id), 10)?;
        vm.expect("PAGURO-PROBE: done", 10)?;
        vm.expect("the chained image returned", 20)
    })
}

/// A superfloppy fixed VHD, a raw GPT `.img`, and a non-default `efi` path.
pub fn vhd_superfloppy_raw_other(env: &Env) -> R<()> {
    for (name, entry, mark, bound) in [
        (
            "s4-superfloppy",
            "root = \\paguro\\superfloppy.vhd",
            "own FAT of superfloppy.vhd",
            "on the whole disk",
        ),
        (
            "s4-raw-img",
            "root = \\paguro\\raw.img",
            "own FAT of raw.img",
            "in its ESP",
        ),
        (
            "s4-efi-other",
            "root = \\paguro\\gpt.vhd\nefi = \\EFI\\other\\probe.efi",
            GPT_MARK,
            "in its ESP",
        ),
    ] {
        let c = Case {
            name,
            ini: Some(ini(entry)),
            secure: false,
            ntfs: None,
            guid: NTFS_VOLUME,
        };
        boot(env, &c, |vm| {
            vm.expect(bound, 60)?;
            let from = probe_ok(vm, mark)?;
            if name == "s4-superfloppy" && from.contains("HD(") {
                return Err(format!("superfloppy bound through a partition: {from}"));
            }
            vm.expect("PAGURO-PROBE: done", 10)
        })
        .map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

/// `efi_file`: the probe straight from NTFS, loaded from a buffer: no
/// DeviceHandle, and the handoff's IMAGE record is role efi_file.
pub fn efi_file(env: &Env) -> R<()> {
    let v = volume(env)?;
    let id = identity(&v.ntfs, "/paguro/probe.efi")?;
    let c = Case {
        name: "s4-efi-file",
        ini: Some(ini("efi_file = \\paguro\\probe.efi")),
        secure: false,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        vm.expect("starting efi_file (", 60)?;
        vm.expect("PAGURO-PROBE: started with no DeviceHandle", 60)?;
        vm.expect(&image_line("efi_file", "linux", id), 10)?;
        vm.expect("PAGURO-PROBE: done", 10)
    })
}

/// `root` separate from `efi_disk`, and a fragmented efi disk: both IMAGE
/// records carry ntfs-3g's identities, and the block device gathers 16+
/// extents correctly (the probe reads its FAT through them).
pub fn separate_root_fragmented(env: &Env) -> R<()> {
    let v = volume(env)?;
    let root = identity(&v.ntfs, "/paguro/root.img")?;
    let disk = identity(&v.ntfs, "/paguro/frag.vhd")?;
    let c = Case {
        name: "s4-root-frag",
        ini: Some(ini(
            "root = \\paguro\\root.img\nefi_disk = \\paguro\\frag.vhd",
        )),
        secure: false,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        let line = vm.capture("stage4 efi_disk \\paguro\\frag.vhd = ", 60)?;
        let n: u64 = line
            .split(", ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("no extent count in {line:?}"))?;
        if n < 16 {
            return Err(format!("frag.vhd in only {n} extents"));
        }
        probe_ok(vm, "own FAT of frag.vhd")?;
        vm.expect(&image_line("root", "linux", root), 10)?;
        vm.expect(&image_line("efi_disk", "linux", disk), 10)?;
        vm.expect("PAGURO-PROBE: done", 10)
    })
}

/// Refusals: each reaches the "could not be started" screen and halts with
/// the typed reason, without a hang.
pub fn refusals(env: &Env) -> R<()> {
    for (name, entry, reason) in [
        (
            "s4-missing",
            "root = \\paguro\\missing.vhd",
            "Stage4(File(Root, NotFound))",
        ),
        (
            "s4-sparse",
            "root = \\paguro\\sparse.vhd",
            "Stage4(File(Root, Ntfs(Sparse)))",
        ),
        (
            "s4-compressed",
            "root = \\compressed\\gpt.vhd",
            "Stage4(File(Root, Ntfs(Compressed)))",
        ),
        (
            "s4-dynamic",
            "root = \\paguro\\dynamic.vhd",
            "Stage4(Payload(Unrecognised))",
        ),
        (
            "s4-noesp",
            "root = \\paguro\\noesp.img",
            "Stage4(Payload(NoEsp))",
        ),
        (
            "s4-twoesp",
            "root = \\paguro\\twoesp.img",
            "Stage4(Payload(SeveralEsps))",
        ),
        (
            "s4-badfat",
            "root = \\paguro\\badfat.img",
            "Stage4(Fat(Boot(FsType)))",
        ),
        (
            "s4-no-efi",
            "root = \\paguro\\gpt.vhd\nefi = \\EFI\\nope.efi",
            "Stage4(EfiMissing)",
        ),
    ] {
        let c = Case {
            name,
            ini: Some(ini(entry)),
            secure: false,
            ntfs: None,
            guid: NTFS_VOLUME,
        };
        boot(env, &c, |vm| {
            vm.expect(&format!("halted: {reason}"), 90)?;
            vm.expect("Linux could not be started", 20)
        })
        .map_err(|e| format!("{name}: {e}"))?;
    }
    Ok(())
}

/// A garbage `.efi`: LoadImage refuses it, the error screen shows, no hang.
pub fn invalid_pe(env: &Env) -> R<()> {
    let c = Case {
        name: "s4-invalid-pe",
        ini: Some(ini(
            "root = \\paguro\\gpt.vhd\nefi = \\EFI\\bad\\garbage.efi",
        )),
        secure: false,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        vm.expect("tier 1: firmware FAT bound", 60)?;
        vm.expect("LoadImage/StartImage failed: Device(", 60)?;
        vm.expect("Linux could not be started", 20)?;
        vm.send("\r")?;
        vm.expect("halted: Platform(Device(", 20)
    })
}

/// Secure Boot (snakeoil db): an unsigned probe is refused by LoadImage,
/// a snakeoil-signed one boots.
pub fn secure_boot(env: &Env) -> R<()> {
    if env.efi_signed.is_none() || env.probe_signed.is_none() {
        eprintln!("  (skipped: no signed loader or probe)");
        return Ok(());
    }
    let c = Case {
        name: "s4-sb-unsigned",
        ini: Some(ini("root = \\paguro\\gpt.vhd")),
        secure: true,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        vm.expect("stage1 ok (verified)", 30)?;
        vm.expect("tier 1: firmware FAT bound", 60)?;
        // Refused by verification: EFI_ACCESS_DENIED (0x…0f, what OVMF
        // returns for an unsigned image) or EFI_SECURITY_VIOLATION (0x…1a).
        let st = vm.capture("LoadImage/StartImage failed: Device(", 60)?;
        if st != "9223372036854775823)" && st != "9223372036854775834)" {
            return Err(format!(
                "unsigned probe refused with an unexpected status {st}"
            ));
        }
        vm.expect("Linux could not be started", 20)
    })?;
    let c = Case {
        name: "s4-sb-signed",
        ini: Some(ini(
            "root = \\paguro\\gpt.vhd\nefi = \\EFI\\signed\\probe.efi",
        )),
        secure: true,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        vm.expect("stage1 ok (verified)", 30)?;
        probe_ok(vm, GPT_MARK)?;
        // Verified configuration: CONFIG_UNVERIFIED is clear.
        vm.expect("PAGURO-PROBE: handoff rung=Unencrypted state=0x0", 10)?;
        vm.expect("PAGURO-PROBE: done", 10)
    })
}

/// The safety gates degrade, they do not refuse: the dirty bit and an
/// active hibernation header each show their notice, and after Enter the
/// boot continues with the STATE flag in the handoff.
pub fn gates(env: &Env) -> R<()> {
    let v = volume(env)?;
    let dir = env.work.join("stage4");
    let dirty = dir.join("ntfs-dirty.img");
    io(std::fs::copy(&v.ntfs, &dirty))?;
    set_dirty(&dirty)?;
    let hib = dir.join("ntfs-hiber.img");
    io(std::fs::copy(&v.ntfs, &hib))?;
    with_ntfs(&hib, |m| {
        let mut h = b"HIBR".to_vec();
        h.resize(64 << 10, 0);
        write(&m.join("hiberfil.sys"), &h)
    })?;
    for (name, img, notice, flags) in [
        (
            "s4-dirty",
            &dirty,
            "Windows didn't shut down cleanly last time",
            "0x6",
        ),
        ("s4-hibernated", &hib, "Windows saved a session", "0x5"),
    ] {
        let c = Case {
            name,
            ini: Some(ini("root = \\paguro\\gpt.vhd")),
            secure: false,
            ntfs: Some(img.clone()),
            guid: NTFS_VOLUME,
        };
        boot(env, &c, |vm| {
            vm.expect(notice, 60)?;
            vm.send("\r")?;
            probe_ok(vm, GPT_MARK)?;
            vm.expect(
                &format!("PAGURO-PROBE: handoff rung=Unencrypted state={flags}"),
                10,
            )?;
            vm.expect("PAGURO-PROBE: done", 10)
        })
        .map_err(|e| format!("{name}: {e}"))?;
    }
    let _ = std::fs::remove_file(dirty);
    let _ = std::fs::remove_file(hib);
    Ok(())
}

/// The configured volume is not on any disk: the volume-missing screen.
pub fn volume_missing(env: &Env) -> R<()> {
    let c = Case {
        name: "s4-volume-missing",
        ini: Some(ini("root = \\paguro\\gpt.vhd")),
        secure: false,
        ntfs: None,
        guid: "0badc0de-0000-4000-8000-000000000001",
    };
    boot(env, &c, |vm| {
        vm.expect(&format!("configured volume {NTFS_VOLUME} not found"), 60)?;
        vm.expect("The Linux volume was not found", 20)
    })
}

/// Recovery (no configuration): the browser over the real NTFS listing,
/// driven by keys — `\paguro\`, `gpt.vhd`, "choose one on its EFI
/// partition", `\EFI\other\probe.efi` — boots the probe, flagged recovery.
pub fn recovery_browser(env: &Env) -> R<()> {
    let c = Case {
        name: "s4-recovery-browser",
        ini: None,
        secure: false,
        ntfs: None,
        guid: NTFS_VOLUME,
    };
    boot(env, &c, |vm| {
        vm.expect("recovery (NoConfig)", 30)?;
        vm.expect("entries in \\paguro\\", 60)?;
        // The browser: the rows are drawn on GOP, the log marks each
        // listing. Type to jump to gpt.vhd, open it.
        vm.expect("stage4 listing \\paguro\n", 20)?;
        vm.send("g")?;
        vm.send("\r")?;
        vm.expect("How should this disk start?", 20)?;
        vm.expect("gpt.vhd", 5)?;
        vm.send("2")?;
        // The FAT32 browser: EFI, other, probe.efi.
        vm.expect("stage4 listing \\paguro\\gpt.vhd \\\n", 30)?;
        vm.send("e")?;
        vm.send("\r")?;
        vm.expect("stage4 listing \\paguro\\gpt.vhd \\EFI\n", 30)?;
        vm.send("o")?;
        vm.send("\r")?;
        vm.expect("stage4 listing \\paguro\\gpt.vhd \\EFI\\other\n", 30)?;
        vm.send("p")?;
        vm.send("\r")?;
        vm.expect(
            "recovery target \\paguro\\gpt.vhd efi \\EFI\\other\\probe.efi",
            20,
        )?;
        probe_ok(vm, GPT_MARK)?;
        vm.expect("PAGURO-PROBE: handoff rung=Unencrypted state=0xc", 10)?;
        vm.expect("PAGURO-PROBE: done", 10)
    })
}

/// aarch64 under AAVMF: the first scenario — a fixed VHD with GPT + ESP,
/// firmware FAT bound to paguro's block device, the probe reading its own
/// FAT32. No TPM (the loader runs without one).
pub fn aarch64(env: &Env) -> R<()> {
    let (Some(efi), Some(_)) = (&env.efi_aa64, &env.probe_aa64) else {
        eprintln!("  (skipped: no --efi-aa64/--probe-aa64)");
        return Ok(());
    };
    let v = volume(env)?;
    let name = "s4-aarch64";
    let ini = ini("root = \\paguro\\gpt.vhd");
    let disk = boot_disk(
        env,
        name,
        efi,
        "EFI/BOOT/BOOTAA64.EFI",
        Some(&ini),
        &v.ntfs,
        NTFS_VOLUME,
        &[],
    )?;
    let dir = env.work.join("stage4");
    // AAVMF pflash images must be exactly 64 MiB.
    let code = dir.join(format!("{name}-code.fd"));
    let vars = dir.join(format!("{name}-vars.fd"));
    io(std::fs::copy(
        env.aavmf.join("AAVMF_CODE.no-secboot.fd"),
        &code,
    ))?;
    io(std::fs::copy(env.aavmf.join("AAVMF_VARS.fd"), &vars))?;
    for f in [&code, &vars] {
        io(std::fs::OpenOptions::new()
            .write(true)
            .open(f)
            .and_then(|h| h.set_len(64 << 20)))?;
    }
    let mut cmd = Command::new("qemu-system-aarch64");
    cmd.args(["-M", "virt", "-cpu", "cortex-a72", "-m", "1024"])
        .args(["-display", "none", "-serial", "stdio", "-monitor", "none"])
        .args(["-no-reboot", "-net", "none"])
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            code.display()
        ))
        .arg("-drive")
        .arg(format!("if=pflash,format=raw,file={}", vars.display()))
        .arg("-drive")
        .arg(format!(
            "if=none,id=d0,format=raw,snapshot=on,file={}",
            disk.display()
        ))
        .args([
            "-device",
            "virtio-blk-pci,drive=d0",
            "-device",
            "virtio-rng-pci",
        ]);
    let id = identity(&v.ntfs, "/paguro/gpt.vhd")?;
    let mut vm = Vm::spawn(cmd, env.work.join(format!("{name}.serial.log")), None)?;
    let r = (|| {
        vm.expect("paguro 0.0.0", 300)?;
        vm.expect("stage4 ntfs mounted", 300)?;
        vm.expect("tier 1: firmware FAT bound", 300)?;
        probe_ok(&mut vm, GPT_MARK)?;
        vm.expect(&image_line("root", "linux", id), 30)?;
        vm.expect("PAGURO-PROBE: done", 30)
    })();
    vm.stop();
    for f in [&disk, &code, &vars] {
        let _ = std::fs::remove_file(f);
    }
    r
}

// ---------------------------------------------------------------------------
// BitLocker (DESIGN.md §6, INTERFACES.md §8, §12.2)

/// The shared NTFS volume, encrypted by `test/fixtures/bde/make.sh` with
/// `opts` (the writer libbde and dislocker vouch for, CI `bde` job); built
/// once per option set. Returns the image and its `.keys`.
fn bde_volume(env: &Env, tag: &str, opts: &[&str]) -> R<(PathBuf, String)> {
    let v = volume(env)?;
    let dir = env.work.join("stage4");
    let out = dir.join(format!("bde-{tag}.img"));
    let keys = dir.join(format!("bde-{tag}.img.keys"));
    if !out.exists() || !keys.exists() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut c = Command::new(root.join("test/fixtures/bde/make.sh"));
        c.arg(&v.ntfs).arg(&out).args(opts).arg("--no-verify");
        let w = root.join("target/release/paguro-bde-write");
        if w.exists() {
            c.env("PAGURO_BDE_WRITE", w);
        }
        let o = io(c.output())?;
        if !o.status.success() {
            return Err(format!(
                "make.sh: {}",
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        let _ = std::fs::remove_file(dir.join(format!("bde-{tag}.img.expect")));
    }
    Ok((out, io(std::fs::read_to_string(keys))?))
}

fn key<'k>(keys: &'k str, k: &str) -> R<&'k str> {
    keys.lines()
        .find_map(|l| l.strip_prefix(k)?.strip_prefix(' '))
        .ok_or_else(|| format!("no {k} in the keys"))
}

/// The probe's view of the handoff's FVE_LAYOUT, from make.sh's keys.
fn layout_line(keys: &str) -> R<String> {
    let md = key(keys, "metadata")?;
    Ok(format!(
        "PAGURO-PROBE: handoff fve_layout md={md} region=0x10000 reloc={}+16 enc={:#x}",
        key(keys, "reloc")?,
        key(keys, "encrypted-size")?
            .parse::<u64>()
            .map_err(|e| e.to_string())?
    ))
}

/// Stage 4 through the BitLocker layer: the probe starts from the VHD inside
/// the encrypted NTFS, reads its own FAT through paguro's decrypting block
/// device, and the handoff carries the FVEK and FVE_LAYOUT.
fn bde_started(vm: &mut Vm, keys: &str, rung: &str) -> R<()> {
    vm.expect("stage4 ntfs mounted", crate::STRETCH_WAIT)?;
    vm.expect("paguro: blockio: BitLocker, 512-byte units", 60)?;
    vm.expect("tier 1: firmware FAT bound", 60)?;
    vm.expect("handoff published", 20)?;
    probe_ok(vm, GPT_MARK)?;
    vm.expect(&format!("PAGURO-PROBE: handoff rung={rung} "), 10)?;
    vm.expect("PAGURO-PROBE: handoff fvek cipher=0x8004 len=32", 10)?;
    vm.expect(&layout_line(keys)?, 10)?;
    vm.expect("PAGURO-PROBE: done", 10)
}

fn bde_case<'a>(name: &'a str, ntfs: &Path) -> Case<'a> {
    Case {
        name,
        ini: Some(ini("root = \\paguro\\gpt.vhd")),
        secure: false,
        ntfs: Some(ntfs.to_path_buf()),
        guid: NTFS_VOLUME,
    }
}

const BDE_PASSWORD: &str = "paguro-bde";

/// A BitLocker password protector, typed after a wrong one.
pub fn bde_password(env: &Env) -> R<()> {
    let (img, keys) = bde_volume(
        env,
        "pw",
        &[
            "--password",
            BDE_PASSWORD,
            "--recovery",
            "auto",
            "--seed",
            "31",
        ],
    )?;
    boot(env, &bde_case("s4-bde-password", &img), |vm| {
        vm.expect("Unlock Linux", 60)?;
        vm.send("1")?;
        vm.expect("Enter your password or PIN", 10)?;
        vm.send("not-it\r")?;
        vm.expect("That did not unlock Linux", crate::STRETCH_WAIT)?;
        vm.expect("Unlock Linux", 10)?;
        vm.send("1")?;
        vm.expect("Enter your password or PIN", 10)?;
        vm.send(BDE_PASSWORD)?;
        vm.send("\r")?;
        bde_started(vm, &keys, "BitLockerPassword")
    })
}

/// The volume's recovery password.
pub fn bde_recovery(env: &Env) -> R<()> {
    let (img, keys) = bde_volume(
        env,
        "pw",
        &[
            "--password",
            BDE_PASSWORD,
            "--recovery",
            "auto",
            "--seed",
            "31",
        ],
    )?;
    let rp = key(&keys, "recovery")?.to_string();
    boot(env, &bde_case("s4-bde-recovery", &img), |vm| {
        vm.expect("Unlock Linux", 60)?;
        vm.send("3")?;
        vm.expect("Enter your recovery key", 10)?;
        vm.send(&rp)?;
        vm.send("\r")?;
        bde_started(vm, &keys, "RecoveryKey")
    })
}

/// A clear key (BitLocker suspended): no prompt at all.
pub fn bde_clear_key(env: &Env) -> R<()> {
    let (img, keys) = bde_volume(env, "ck", &["--clear-key", "--seed", "32"])?;
    boot(env, &bde_case("s4-bde-clear-key", &img), |vm| {
        bde_started(vm, &keys, "ClearKey")?;
        if vm.text().contains("Unlock Linux") {
            return Err("a clear key must not prompt".into());
        }
        Ok(())
    })
}

/// Metadata copies that disagree (copy 2's description changed, its CRC
/// made to match): refused before any protector is tried.
pub fn bde_disagree(env: &Env) -> R<()> {
    let (img, keys) = bde_volume(
        env,
        "pw",
        &[
            "--password",
            BDE_PASSWORD,
            "--recovery",
            "auto",
            "--seed",
            "31",
        ],
    )?;
    let md: Vec<u64> = key(&keys, "metadata")?
        .split(',')
        .map(|x| u64::from_str_radix(x.trim_start_matches("0x"), 16))
        .collect::<Result<_, _>>()
        .map_err(|e| e.to_string())?;
    let dir = env.work.join("stage4");
    let bad = dir.join("bde-disagree.img");
    io(std::fs::copy(&img, &bad))?;
    let mut f = io(std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&bad))?;
    use std::io::{Read, Seek, SeekFrom, Write};
    let o = *md.get(2).ok_or("three offsets")?;
    let mut blk = vec![0u8; 0x10000];
    io(f.seek(SeekFrom::Start(o)))?;
    io(f.read_exact(&mut blk))?;
    let size = usize::from(u16::from_le_bytes([blk[8], blk[9]])) * 16;
    blk[64 + 48 + 8] ^= 0x20;
    let c = paguro_core::bde::crc32(&blk[..size]);
    blk[size + 4..size + 8].copy_from_slice(&c.to_le_bytes());
    io(f.seek(SeekFrom::Start(o)))?;
    io(f.write_all(&blk))?;
    drop(f);
    let r = boot(env, &bde_case("s4-bde-disagree", &bad), |vm| {
        vm.expect("halted: Bde(CopiesDisagree)", 60)?;
        if vm.text().contains("Unlock Linux") {
            return Err("protectors were offered over disagreeing metadata".into());
        }
        Ok(())
    });
    let _ = std::fs::remove_file(&bad);
    r
}

/// Every notice the real disks lead to — NTFS dirty, hibernation (Fast
/// Startup), the configured volume missing, a start that fails, a TPM seal
/// over a plaintext volume — in every variant (graphics and auto) and in
/// text mode, with `[UI]` in the configuration: the variant's background
/// on screen (screendump) where graphics show, the notice's title on the
/// serial port where the text UI does (the mirror in auto, ConOut in text).
pub fn notice_screens(env: &Env) -> R<()> {
    use paguro_core::config::{UiMode, UiTheme};
    let v = volume(env)?;
    let dir = env.work.join("stage4");
    let dirty = dir.join("ntfs-dirty-ui.img");
    io(std::fs::copy(&v.ntfs, &dirty))?;
    set_dirty(&dirty)?;
    let hib = dir.join("ntfs-hiber-ui.img");
    io(std::fs::copy(&v.ntfs, &hib))?;
    with_ntfs(&hib, |m| {
        let mut h = b"HIBR".to_vec();
        h.resize(64 << 10, 0);
        write(&m.join("hiberfil.sys"), &h)
    })?;
    let seal_path = format!("EFI/paguro/{NTFS_VOLUME}/tpm_seal.bin");
    let seal: &[u8] = b"PGRTPM\x00\x01not-a-seal";
    let gpt = "root = \\paguro\\gpt.vhd";
    // name, title, entry, patched volume, volume GUID, a seal on the ESP
    type Notice<'a> = (&'a str, &'a str, &'a str, Option<&'a Path>, &'a str, bool);
    let cases: [Notice<'_>; 5] = [
        (
            "dirty",
            "Windows didn't shut down cleanly last time",
            gpt,
            Some(&dirty),
            NTFS_VOLUME,
            false,
        ),
        (
            "hibernated",
            "Windows saved a session",
            gpt,
            Some(&hib),
            NTFS_VOLUME,
            false,
        ),
        (
            "volume-missing",
            "The Linux volume was not found",
            gpt,
            None,
            "0badc0de-0000-4000-8000-000000000001",
            false,
        ),
        (
            "start-failed",
            "Linux could not be started",
            "root = \\paguro\\gpt.vhd\nefi = \\EFI\\bad\\garbage.efi",
            None,
            NTFS_VOLUME,
            false,
        ),
        (
            "plaintext",
            "This configuration protects nothing",
            gpt,
            None,
            NTFS_VOLUME,
            true,
        ),
    ];
    let runs = [
        (UiTheme::Dark, UiMode::Auto),
        (UiTheme::Light, UiMode::Graphics),
        (UiTheme::DarkContrast, UiMode::Auto),
        (UiTheme::LightContrast, UiMode::Graphics),
        (UiTheme::Light, UiMode::Text),
    ];
    let mut done = 0;
    for (case, title, entry, ntfs, guid, with_seal) in cases {
        for (theme, mode) in runs {
            let name = format!("ui-{case}-{}-{}", theme.name(), mode.name());
            let mut ini = ini(entry);
            ini.extend_from_slice(
                format!("\n[UI]\ntheme = {}\nmode = {}\n", theme.name(), mode.name()).as_bytes(),
            );
            let extra: Vec<(&str, &[u8])> = if with_seal {
                vec![(seal_path.as_str(), seal)]
            } else {
                Vec::new()
            };
            let disk = boot_disk(
                env,
                &name,
                &env.efi,
                "EFI/BOOT/BOOTX64.EFI",
                Some(&ini),
                ntfs.unwrap_or(&v.ntfs),
                guid,
                &extra,
            )?;
            let (vars, state) = fresh(env, &name, "OVMF_VARS_4M.fd")?;
            let sock = state.join("qmp.sock");
            let mut vm = Vm::launch(env, &name, false, &[&disk], &vars, &state, Some(&sock), &[])?;
            let bg = paguro_ui::builtin::THEMES
                [UiTheme::ALL.iter().position(|t| *t == theme).unwrap_or(0)]
            .palette
            .background;
            let r = (|| -> R<()> {
                vm.expect("paguro 0.0.0", BOOT_WAIT)?;
                vm.expect("paguro: screen notice", 120)?;
                if mode != UiMode::Text {
                    crate::wait_colour(env, &sock, &name, None, bg, true)?;
                }
                if mode != UiMode::Graphics {
                    vm.expect(title, 30)?;
                }
                if mode == UiMode::Text {
                    crate::wait_colour(env, &sock, &name, None, bg, false)?;
                }
                if mode == UiMode::Graphics {
                    std::thread::sleep(std::time::Duration::from_secs(1));
                    if vm.text().contains(title) {
                        return Err("the text UI reached the serial port in graphics mode".into());
                    }
                }
                Ok(())
            })();
            vm.stop();
            let _ = std::fs::remove_file(&disk);
            r.map_err(|e| format!("{name}: {e}"))?;
            done += 1;
        }
    }
    let _ = std::fs::remove_file(dirty);
    let _ = std::fs::remove_file(hib);
    println!("  {done} boots: 5 notices × 4 variants and text mode");
    Ok(())
}
