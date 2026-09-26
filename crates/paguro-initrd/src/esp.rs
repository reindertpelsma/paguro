//! The machine's ESP: `recorded.bin` every boot (INTERFACES.md §5), and on
//! a provisioning boot `paguro.ini`, `PaguroConfigHash` and `tpm_seal.bin`
//! (§3.3, §8.1). The ESP is found by content — the ESP-typed partition of
//! a real disk holding `\EFI\paguro\paguro.ini` — never by configuration.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use paguro_boot::tpm::pcr12_after_load_taint;
use paguro_core::guid::PAGURO_VENDOR;
use paguro_core::handoff::{self, Rung};
use paguro_core::recorded::{self, Recorded};
use paguro_core::seal::Kind;
use paguro_core::tcglog;
use paguro_core::tpm::SHA256_LEN;
use sha2::{Digest, Sha256};

use crate::reseal::{self, ResealInput};
use crate::setup::{Taken, log, read_gpt};
use crate::sys::{self, R};

const MNT: &str = "/run/paguro/esp";
const EFIVARS: &str = "/sys/firmware/efi/efivars";
/// EFI_VARIABLE_NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS (UEFI
/// 2.10 §8.2): the attributes efivarfs takes ahead of the data.
const NV_BS_RT: u32 = 0x7;
/// `PaguroTpmBroken` (INTERFACES.md §5): a 1-byte NV|BS|RT variable, so an
/// efivarfs read is the 4-byte attribute header plus that one byte.
const TPM_BROKEN_FILE_LEN: usize = size_of::<u32>() + 1;

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
/// Durable when it returns: the file is fsynced before the rename and the
/// directory entry after it (INTERFACES.md §12.1, "power loss after every
/// write") — callers that gate a follow-up action (clearing
/// `PaguroTpmBroken`) on "durably written" may do so as soon as this returns
/// `Ok`.
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
    if let Some(dir) = path.parent() {
        if let Ok(d) = File::open(dir) {
            let _ = d.sync_all();
        }
    }
    Ok(true)
}

fn sha256_file(p: &Path) -> [u8; SHA256_LEN] {
    std::fs::read(p).map_or([0; SHA256_LEN], |b| Sha256::digest(&b).into())
}

/// SHA-256 over PCR 7's EV_EFI_VARIABLE_DRIVER_CONFIG digests, in log
/// order (INTERFACES.md §5); zeros without a TPM event log.
fn secure_boot_config() -> [u8; SHA256_LEN] {
    let sec = Path::new("/sys/kernel/security");
    if !sec.join("tpm0").exists() {
        let _ = sys::mount("securityfs", sec, "securityfs", 0, "");
    }
    let Ok(log) = std::fs::read(sec.join("tpm0/binary_bios_measurements")) else {
        return [0; SHA256_LEN];
    };
    let mut h = Sha256::new();
    match tcglog::driver_config_digests(&log, |d| h.update(d)) {
        Ok(_) => h.finalize().into(),
        Err(_) => [0; SHA256_LEN],
    }
}

fn recorded(t: &Taken, dir: &Path) -> R<Recorded> {
    let mut rec = Recorded::default();
    // PCRS carries one SHA-256 value per set bit, ascending.
    let mut vals = t.pcrs.chunks_exact(SHA256_LEN);
    for pcr in 0..handoff::PCR_COUNT {
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

/// Mount efivarfs if it is not already (both `PaguroConfigHash` and
/// `PaguroTpmBroken` need it).
fn ensure_efivarfs() -> &'static Path {
    let vars = Path::new(EFIVARS);
    if !vars.join(".").exists()
        || std::fs::read_dir(vars)
            .map(|mut d| d.next().is_none())
            .unwrap_or(true)
    {
        let _ = sys::mount("efivarfs", vars, "efivarfs", 0, "");
    }
    vars
}

/// `PaguroConfigHash` (NV | BS | RT) through efivarfs.
fn set_config_hash(hash: &[u8; SHA256_LEN]) -> R<()> {
    let vars = ensure_efivarfs();
    let p = vars.join(format!("PaguroConfigHash-{PAGURO_VENDOR}"));
    if let Ok(f) = File::open(&p) {
        sys::clear_immutable(&f);
    }
    let mut data = Vec::with_capacity(size_of::<u32>() + hash.len());
    data.extend_from_slice(&NV_BS_RT.to_le_bytes());
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

fn tpm_broken_path() -> PathBuf {
    ensure_efivarfs().join(format!("PaguroTpmBroken-{PAGURO_VENDOR}"))
}

/// `PaguroTpmBroken` (INTERFACES.md §5): `false` when absent, or on any size
/// mismatch — "treated as absent" is the spec's own rule, so a variable an
/// older or newer paguro wrote in a different shape never wedges this open.
fn tpm_broken() -> bool {
    match std::fs::read(tpm_broken_path()) {
        Ok(d) if d.len() == TPM_BROKEN_FILE_LEN => d.get(size_of::<u32>()) == Some(&1),
        _ => false,
    }
}

/// Clear `PaguroTpmBroken`. Only called once the new `tpm_seal.bin` is
/// durably on disk (§5: "cleared after the file is written").
fn clear_tpm_broken() {
    let p = tpm_broken_path();
    if let Ok(f) = File::open(&p) {
        sys::clear_immutable(&f);
    }
    match std::fs::remove_file(&p) {
        Ok(()) => log("PaguroTpmBroken cleared"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => log(&format!("clearing PaguroTpmBroken failed: {e}")),
    }
}

/// BitLocker's encrypted FVEK blob (an input to `root_gate`, DESIGN.md §6):
/// **not yet implemented**. The parser that reads it
/// (`paguro_boot::bde`) is private to the loader crate; duplicating its
/// offsets here without a test oracle risks a silently wrong key, which is
/// worse than skipping the re-seal (`crate::reseal` module doc has the full
/// account). Once a shared reader exists, this is the only piece left to
/// wire up.
fn fvek_blob(_t: &Taken) -> Option<Vec<u8>> {
    None
}

/// Whether this boot can even attempt a re-seal, and why not otherwise
/// (INTERFACES.md §5, §8.3). Only a `passphrase`-rung boot carries the
/// passphrase-derived material (`USER_HASH`) a re-seal needs; `recovery`
/// never does (no PIN is typed), so it always falls through to the second
/// arm — pure, so it is tested without a handoff or a TPM.
fn reseal_readiness(rung: Rung, have_secrets: bool, have_blob: bool) -> Result<(), &'static str> {
    if rung != Rung::Passphrase {
        return Err(
            "this boot's rung carries no passphrase to re-derive the tpm rung's auth from \
             (needs a passphrase-rung boot)",
        );
    }
    if !have_secrets {
        return Err("VMK/USER_HASH/CONFIG are not all present in the handoff");
    }
    if !have_blob {
        return Err("no encrypted FVEK blob reader is wired up yet (see esp::fvek_blob)");
    }
    Ok(())
}

/// The durability contract (INTERFACES.md §5: "cleared after the file is
/// written"): `clear` runs if and only if `write` succeeds, and after it —
/// never on a write failure, so a failed attempt leaves the flag set for a
/// later boot to retry. Split out from [`maybe_reseal`] so the ordering is
/// tested with mock closures, without real files or a TPM.
fn finish_reseal(file: &[u8], write: impl FnOnce(&[u8]) -> R<bool>, clear: impl FnOnce()) -> R<()> {
    write(file)?;
    clear();
    Ok(())
}

/// Re-seal the `tpm` rung after `PaguroTpmBroken` (INTERFACES.md §5, §8.3),
/// when this boot can supply everything it needs; otherwise logs why and
/// leaves the flag set for a later boot. Never fails the boot. `rec` is this
/// boot's own `recorded()` (so PCR 0/2/4/7 are read once, not twice).
fn maybe_reseal(t: &Taken, vol: &Path, rec: &Recorded) {
    if !tpm_broken() {
        return;
    }
    let have_secrets = t.vmk.is_some() && t.user_hash.is_some() && t.config.is_some();
    let blob = fvek_blob(t);
    if let Err(why) = reseal_readiness(t.rung, have_secrets, blob.is_some()) {
        log(&format!("PaguroTpmBroken set, but {why}; skipping"));
        return;
    }
    // `reseal_readiness` just confirmed all three are present.
    let (Some(vmk), Some(user_hash), Some(cfg), Some(blob)) =
        (&t.vmk, &t.user_hash, &t.config, blob)
    else {
        return;
    };
    let input = ResealInput {
        b: &t.b,
        vmk,
        user_hash,
        blob: &blob,
        pcr0247: &rec.pcrs,
        pcr12: pcr12_after_load_taint(cfg),
    };
    let mut tpm = match reseal::LinuxTpm::open(Path::new(reseal::TPMRM0)) {
        Ok(t) => t,
        Err(e) => {
            log(&format!("re-seal: opening {}: {e}", reseal::TPMRM0));
            return;
        }
    };
    let file = match reseal::reseal(&mut tpm, &input) {
        Ok(f) => f,
        Err(e) => {
            log(&format!("re-seal: {e:?}"));
            return;
        }
    };
    let seal_path = vol.join(Kind::Tpm.file_name());
    let r = finish_reseal(&file, |bytes| replace(&seal_path, bytes), clear_tpm_broken);
    match r {
        Ok(()) => log("tpm_seal.bin re-sealed against this boot's PCR values"),
        Err(e) => log(&format!("re-seal: writing tpm_seal.bin: {e}")),
    }
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
    // Re-seal the `tpm` rung if `PaguroTpmBroken` is set and this boot can
    // (INTERFACES.md §5, §8.3); a provisioning boot needs none of this (it
    // already sealed above), so skip it there.
    if t.provision.is_none() {
        maybe_reseal(t, &vol, &rec);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn only_a_passphrase_rung_with_every_secret_is_ready() {
        assert_eq!(
            reseal_readiness(Rung::Passphrase, true, true),
            Ok(()),
            "the one case a re-seal can proceed"
        );
        for rung in [
            Rung::Tpm,
            Rung::SetupTpm,
            Rung::RecoveryKey,
            Rung::PinBypass,
            Rung::Bootstrap,
            Rung::ClearKey,
            Rung::Unencrypted,
            Rung::BitLockerPassword,
        ] {
            assert!(
                reseal_readiness(rung, true, true).is_err(),
                "{rung:?} carries no passphrase"
            );
        }
        assert!(reseal_readiness(Rung::Passphrase, false, true).is_err());
        assert!(reseal_readiness(Rung::Passphrase, true, false).is_err());
    }

    #[test]
    fn clear_runs_only_after_a_successful_write() {
        let log = RefCell::new(Vec::new());
        let r = finish_reseal(
            b"seal-bytes",
            |bytes| {
                log.borrow_mut().push(format!("write:{}", bytes.len()));
                Ok(true)
            },
            || log.borrow_mut().push("clear".to_string()),
        );
        assert!(r.is_ok());
        assert_eq!(
            *log.borrow(),
            vec!["write:10".to_string(), "clear".to_string()],
            "write, then clear, in that order"
        );
    }

    #[test]
    fn a_failed_write_never_clears_the_flag() {
        let log = RefCell::new(Vec::new());
        let r = finish_reseal(
            b"seal-bytes",
            |_| Err("disk full".to_string()),
            || log.borrow_mut().push("clear".to_string()),
        );
        assert!(r.is_err());
        assert!(
            log.borrow().is_empty(),
            "clear must not run when the write failed: {:?}",
            log.borrow()
        );
    }

    #[test]
    fn an_unchanged_write_still_clears() {
        // `replace` returns `Ok(false)` when the bytes on disk already
        // match; the file is still durable, so the flag still clears.
        let log = RefCell::new(Vec::new());
        let r = finish_reseal(
            b"seal-bytes",
            |_| Ok(false),
            || log.borrow_mut().push("clear".to_string()),
        );
        assert!(r.is_ok());
        assert_eq!(*log.borrow(), vec!["clear".to_string()]);
    }
}
