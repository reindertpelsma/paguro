//! The machine's ESP: `recorded.bin` every boot (INTERFACES.md §5), and on
//! a provisioning boot `paguro.ini`, `PaguroConfigHash` and `tpm_seal.bin`
//! (§3.3, §8.1). The ESP is found by content — the ESP-typed partition of
//! a real disk holding `\EFI\paguro\paguro.ini` — never by configuration.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use paguro_core::guid::PAGURO_VENDOR;
use paguro_core::handoff::Rung;
use paguro_core::recorded::{self, Recorded};
use paguro_core::seal::Kind;
use paguro_core::tcglog;
use sha2::{Digest, Sha256};

use crate::setup::{Taken, log, read_gpt};
use crate::sys::{self, R};

const MNT: &str = "/run/paguro/esp";
const EFIVARS: &str = "/sys/firmware/efi/efivars";

/// ESP partitions on real (non device-mapper) disks.
fn esp_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/block") else {
        return out;
    };
    for d in rd.flatten() {
        let name = d.file_name().to_string_lossy().into_owned();
        if name.starts_with("dm-") || name.starts_with("loop") || name.starts_with("ram") {
            continue;
        }
        let Ok((_, es)) = read_gpt(&Path::new("/dev").join(&name)) else {
            continue;
        };
        for (slot, e) in es {
            if !crate::plan::is_esp(&e) {
                continue;
            }
            // Partition nodes: vda1, nvme0n1p1, mmcblk0p1.
            let n = slot + 1;
            for cand in [format!("{name}{n}"), format!("{name}p{n}")] {
                let p = Path::new("/dev").join(&cand);
                if p.exists() {
                    out.push(p);
                    break;
                }
            }
        }
    }
    out
}

/// Write `data` to `path` via `path.new` + rename, only if it differs.
fn replace(path: &Path, data: &[u8]) -> R<bool> {
    if std::fs::read(path).is_ok_and(|old| old == data) {
        return Ok(false);
    }
    let tmp = path.with_extension("new");
    let mut f = File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(data)
        .and_then(|()| f.sync_all())
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(true)
}

fn sha256_file(p: &Path) -> [u8; 32] {
    std::fs::read(p).map_or([0; 32], |b| Sha256::digest(&b).into())
}

/// SHA-256 over PCR 7's EV_EFI_VARIABLE_DRIVER_CONFIG digests, in log
/// order (INTERFACES.md §5); zeros without a TPM event log.
fn secure_boot_config() -> [u8; 32] {
    let sec = Path::new("/sys/kernel/security");
    if !sec.join("tpm0").exists() {
        let _ = sys::mount("securityfs", sec, "securityfs", 0, "");
    }
    let Ok(log) = std::fs::read(sec.join("tpm0/binary_bios_measurements")) else {
        return [0; 32];
    };
    let mut h = Sha256::new();
    match tcglog::driver_config_digests(&log, |d| h.update(d)) {
        Ok(_) => h.finalize().into(),
        Err(_) => [0; 32],
    }
}

fn recorded(t: &Taken, dir: &Path) -> R<Recorded> {
    let mut rec = Recorded::default();
    // PCRS carries 32 bytes per set bit, ascending.
    let mut vals = t.pcrs.chunks_exact(32);
    for pcr in 0..24u32 {
        if t.pcr_mask & (1 << pcr) == 0 {
            continue;
        }
        let v = vals.next().ok_or("PCRS shorter than its mask")?;
        let slot = match pcr {
            0 => 0,
            2 => 1,
            4 => 2,
            7 => 3,
            _ => continue,
        };
        if let Some(s) = rec.pcrs.get_mut(slot) {
            s.copy_from_slice(v);
        }
    }
    rec.secure_boot_config = secure_boot_config();
    rec.shim_sha256 = sha256_file(&dir.join("shimx64.efi"));
    rec.loader_sha256 = sha256_file(&dir.join("paguro.efi"));
    Ok(rec)
}

/// `PaguroConfigHash` (NV | BS | RT) through efivarfs.
fn set_config_hash(hash: &[u8; 32]) -> R<()> {
    let vars = Path::new(EFIVARS);
    if !vars.join(".").exists()
        || std::fs::read_dir(vars)
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
    {
        let _ = sys::mount("efivarfs", vars, "efivarfs", 0, "");
    }
    let p = vars.join(format!("PaguroConfigHash-{PAGURO_VENDOR}"));
    if let Ok(f) = File::open(&p) {
        sys::clear_immutable(&f);
    }
    let mut data = Vec::with_capacity(36);
    data.extend_from_slice(&7u32.to_le_bytes());
    data.extend_from_slice(hash);
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(false)
        .open(&p)
        .map_err(|e| format!("{}: {e}", p.display()))?;
    // efivarfs takes attributes + data in one write.
    f.write_all(&data)
        .map_err(|e| format!("{}: {e}", p.display()))
}

fn with_esp(t: &Taken) -> R<()> {
    let mnt = Path::new(MNT);
    let _ = std::fs::create_dir_all(mnt);
    for dev in esp_candidates() {
        if sys::mount(
            dev.to_str().unwrap_or_default(),
            mnt,
            "vfat",
            libc::MS_NOATIME | libc::MS_NODEV | libc::MS_NOEXEC | libc::MS_NOSUID,
            "",
        )
        .is_err()
        {
            continue;
        }
        let dir = mnt.join("EFI/paguro");
        let ours = dir.join("paguro.ini").exists() || t.provision.is_some() && dir.exists();
        if !ours {
            let _ = sys::umount(mnt);
            continue;
        }
        let r = write_files(t, &dir);
        let _ = sys::umount(mnt);
        log(&format!("ESP {}: done", dev.display()));
        return r;
    }
    Err("no ESP holding \\EFI\\paguro\\paguro.ini".into())
}

fn write_files(t: &Taken, dir: &Path) -> R<()> {
    let vol = dir.join(t.volume.partition.to_string());
    std::fs::create_dir_all(&vol).map_err(|e| format!("{}: {e}", vol.display()))?;
    let rec = recorded(t, dir)?;
    let mut buf = [0u8; recorded::LEN];
    let n = recorded::write(&rec, &mut buf).map_err(|_| "recorded.bin")?;
    if replace(&vol.join(recorded::FILE_NAME), buf.get(..n).unwrap_or(&[]))? {
        log("recorded.bin written");
    }
    // A provisioning boot: the loader authored the configuration and a
    // seal against its load taint; the initrd is the writer (§8.1). Order
    // per §3.3: .ini.new, the hash variable, rename.
    if let (Some(cfg), Some(seal)) = (&t.config, &t.provision) {
        let ini = dir.join("paguro.ini");
        let tmp = dir.join("paguro.ini.new");
        std::fs::write(&tmp, cfg).map_err(|e| format!("{}: {e}", tmp.display()))?;
        set_config_hash(&Sha256::digest(cfg).into())?;
        std::fs::rename(&tmp, &ini).map_err(|e| format!("{}: {e}", ini.display()))?;
        replace(&vol.join(Kind::Tpm.file_name()), seal)?;
        log("provisioned: paguro.ini, PaguroConfigHash, tpm_seal.bin");
    }
    // The PIN bypass is one-shot: its seal goes once used.
    if t.rung == Rung::PinBypass {
        let _ = std::fs::remove_file(vol.join(Kind::PinBypass.file_name()));
    }
    Ok(())
}

pub fn write(t: &Taken) -> R<()> {
    with_esp(t)
}
