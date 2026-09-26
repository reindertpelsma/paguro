//! The machine's ESP: `recorded.bin` every boot (INTERFACES.md §5), and on
//! a provisioning boot `paguro.ini`, `PaguroConfigHash` and `tpm_seal.bin`
//! (§3.3, §8.1). The ESP is found by content — the ESP-typed partition of
//! a real disk holding `\EFI\paguro\paguro.ini` — never by configuration.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use paguro_boot::tpm::pcr12_after_load_taint;
use paguro_core::bde;
use paguro_core::guid::PAGURO_VENDOR;
use paguro_core::handoff::{self, FveLayout, Rung};
use paguro_core::recorded::{self, Recorded};
use paguro_core::seal::Kind;
use paguro_core::tcglog;
use paguro_core::tpm::SHA256_LEN;
use sha2::{Digest, Sha256};

use crate::reseal::{self, ResealInput};
use crate::setup::{Taken, log, read_at, read_gpt};
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

/// BitLocker's encrypted FVEK blob (an input to `root_gate`, DESIGN.md §6,
/// "The Linux-side seal": nonce ‖ tag ‖ ciphertext of the FVE metadata's
/// AES-CCM-wrapped key, unchanged by a re-seal). Reads the three metadata
/// copies straight off the raw (still-BitLocker) partition at
/// `layout.metadata_offsets` and cross-checks them exactly as the loader
/// does (`paguro_core::bde::cross_check`) — the same pure, already
/// libbde/dislocker-verified parser (`paguro_core::bde`), not a
/// reimplementation of its offsets. `hdr.bytes_per_sector`/`kind`/`eow` are
/// not consulted by `parse_block`/`cross_check`, only `metadata_offsets`, so
/// the placeholders below cost nothing.
fn fvek_blob(part: &Path, layout: &FveLayout) -> R<Vec<u8>> {
    let f = File::open(part).map_err(|e| format!("{}: {e}", part.display()))?;
    let region = usize::try_from(bde::REGION_SIZE).map_err(|_| "REGION_SIZE overflow")?;
    let copies: Vec<Vec<u8>> = layout
        .metadata_offsets
        .iter()
        .map(|&o| read_at(&f, o, region))
        .collect::<R<_>>()
        .map_err(|e| format!("reading FVE metadata: {e}"))?;
    let [c0, c1, c2] = copies.as_slice() else {
        unreachable!("exactly 3 metadata_offsets")
    };
    let hdr = bde::VolumeHeader {
        kind: bde::HeaderKind::Standard,
        eow: false,
        bytes_per_sector: layout.sector_size,
        metadata_offsets: layout.metadata_offsets,
    };
    let block = bde::cross_check([c0.as_slice(), c1.as_slice(), c2.as_slice()], &hdr)
        .map_err(|e| format!("FVE metadata: {e:?}"))?;
    let m = bde::Metadata::parse(block).map_err(|e| format!("FVE metadata: {e:?}"))?;
    let mut out =
        Vec::with_capacity(m.fvek.nonce.len() + m.fvek.tag.len() + m.fvek.ciphertext.len());
    out.extend_from_slice(&m.fvek.nonce);
    out.extend_from_slice(&m.fvek.tag);
    out.extend_from_slice(m.fvek.ciphertext);
    Ok(out)
}

/// Whether this boot can even attempt a re-seal, and why not otherwise
/// (INTERFACES.md §5, §8.3). No PIN is typed for this any more — the `tpm`
/// rung's auth material comes from `tpm-auth.bin` on the NTFS volume
/// (§8.4), not from anything the loader forwards — so a `recovery`-rung
/// boot is as able to re-seal as a `passphrase`-rung one; only rungs that
/// never reach a normal Linux boot with that file readable are excluded
/// (`tpm` itself would have cleared the flag on success; the one-shot rungs
/// exist for a single provisioning or repair boot, not standing use). Pure,
/// so it is tested without a handoff, a TPM or a real NTFS mount.
fn reseal_readiness(rung: Rung, have_secrets: bool, have_layout: bool) -> Result<(), &'static str> {
    if !matches!(rung, Rung::Passphrase | Rung::RecoveryKey) {
        return Err(
            "this boot's rung is not one that re-seals (needs a passphrase- or recovery-rung boot)",
        );
    }
    if !have_secrets {
        return Err("VMK/tpm-auth.bin/CONFIG are not all present");
    }
    if !have_layout {
        return Err("no FVE_LAYOUT in the handoff (an unencrypted volume takes no tpm seal)");
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

/// [`maybe_reseal_attempt`], then drops this boot's copies of the VMK and
/// the Windows-written auth material regardless of the outcome:
/// `maybe_reseal` runs at most once a boot, so there is no reason to hold
/// them any longer, let alone to process exit (`B` stays — §8.3 keeps it for
/// the session, in case a later process needs it).
fn maybe_reseal(t: &mut Taken, vol: &Path, rec: &Recorded, part: &Path) {
    maybe_reseal_attempt(t, vol, rec, part);
    t.vmk = None;
    t.win_auth = None;
}

/// Re-seal the `tpm` rung after `PaguroTpmBroken` (INTERFACES.md §5, §8.3),
/// when this boot can supply everything it needs; otherwise logs why and
/// leaves the flag set for a later boot. Never fails the boot. `rec` is this
/// boot's own `recorded()` (so PCR 0/2/4/7 are read once, not twice); `part`
/// is the raw (still-BitLocker) partition, to read the FVE metadata from.
fn maybe_reseal_attempt(t: &Taken, vol: &Path, rec: &Recorded, part: &Path) {
    if !tpm_broken() {
        return;
    }
    let have_secrets = t.vmk.is_some() && t.win_auth.is_some() && t.config.is_some();
    if let Err(why) = reseal_readiness(t.rung, have_secrets, t.layout.is_some()) {
        log(&format!("PaguroTpmBroken set, but {why}; skipping"));
        return;
    }
    // `reseal_readiness` just confirmed all four are present.
    let (Some(vmk), Some(win_auth), Some(cfg), Some(layout)) =
        (&t.vmk, &t.win_auth, &t.config, t.layout)
    else {
        return;
    };
    let blob = match fvek_blob(part, &layout) {
        Ok(b) => b,
        Err(e) => {
            log(&format!("re-seal: reading the FVE metadata: {e}"));
            return;
        }
    };
    let input = ResealInput {
        b: t.b.as_bytes(),
        vmk: vmk.as_bytes(),
        ph: win_auth.value.as_bytes(),
        salt: &win_auth.salt,
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

fn with_esp(t: &mut Taken, part: &Path) -> R<()> {
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
        let r = write_files(t, &dir, part);
        let _ = sys::umount(mnt);
        log(&format!("ESP {}: done", dev.display()));
        return r;
    }
    Err("no ESP holding \\EFI\\paguro\\paguro.ini".into())
}

fn write_files(t: &mut Taken, dir: &Path, part: &Path) -> R<()> {
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
        maybe_reseal(t, &vol, &rec, part);
    }
    // The PIN bypass is one-shot: its seal goes once used.
    if t.rung == Rung::PinBypass {
        let _ = std::fs::remove_file(vol.join(Kind::PinBypass.file_name()));
    }
    Ok(())
}

pub fn write(t: &mut Taken, part: &Path) -> R<()> {
    with_esp(t, part)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn passphrase_and_recovery_rungs_with_every_secret_are_ready() {
        for rung in [Rung::Passphrase, Rung::RecoveryKey] {
            assert_eq!(
                reseal_readiness(rung, true, true),
                Ok(()),
                "{rung:?}: no PIN is needed any more, so this rung can re-seal too"
            );
        }
        for rung in [
            Rung::Tpm,
            Rung::SetupTpm,
            Rung::PinBypass,
            Rung::Bootstrap,
            Rung::ClearKey,
            Rung::Unencrypted,
            Rung::BitLockerPassword,
        ] {
            assert!(
                reseal_readiness(rung, true, true).is_err(),
                "{rung:?} does not reach a standing re-seal"
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

    /// A real, libbde/dislocker-verified BitLocker volume
    /// (`test/fixtures/bde/windows/bitlk-aes-xts-128.sparse`, the same
    /// fixtures `paguro-boot/tests/bde.rs` checks the loader against):
    /// `fvek_blob`'s own file-offset arithmetic, run against the file, must
    /// land on exactly the same three metadata regions as parsing them
    /// straight out of the reconstructed in-memory volume.
    #[test]
    #[allow(clippy::indexing_slicing)]
    fn fvek_blob_matches_a_real_bitlocker_fixture() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/bde/windows");
        let sparse = match std::fs::read(dir.join("bitlk-aes-xts-128.sparse")) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("fixture unavailable ({e}): skipping");
                return;
            }
        };
        assert_eq!(&sparse[..8], b"PGBDESP1");
        let size = u64::from_le_bytes(sparse[8..16].try_into().unwrap()) as usize;
        let mut volume = vec![0u8; size];
        let mut at = 16;
        while at < sparse.len() {
            let o = u64::from_le_bytes(sparse[at..at + 8].try_into().unwrap()) as usize;
            let n = u32::from_le_bytes(sparse[at + 8..at + 12].try_into().unwrap()) as usize;
            volume[o..o + n].copy_from_slice(&sparse[at + 12..at + 12 + n]);
            at += 12 + n;
        }

        let hdr = bde::parse_volume_header(&volume[..512]).unwrap();
        let layout = FveLayout {
            metadata_offsets: hdr.metadata_offsets,
            region_size: 0,
            boot_sector_reloc_offset: 0,
            boot_sector_reloc_sectors: 0,
            encrypted_size: 0,
            sector_size: hdr.bytes_per_sector,
            extra_region_offset: 0,
        };

        let tmp = std::env::temp_dir().join(format!(
            "paguro-initrd-bde-fixture-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::write(&tmp, &volume).unwrap();
        let got = fvek_blob(&tmp, &layout);
        let _ = std::fs::remove_file(&tmp);
        let got = got.unwrap();

        let region = bde::REGION_SIZE as usize;
        let regions: Vec<&[u8]> = layout
            .metadata_offsets
            .iter()
            .map(|&o| &volume[o as usize..o as usize + region])
            .collect();
        let block = bde::cross_check([regions[0], regions[1], regions[2]], &hdr).unwrap();
        let m = bde::Metadata::parse(block).unwrap();
        let mut want = Vec::new();
        want.extend_from_slice(&m.fvek.nonce);
        want.extend_from_slice(&m.fvek.tag);
        want.extend_from_slice(m.fvek.ciphertext);

        assert!(!m.fvek.ciphertext.is_empty());
        assert_eq!(
            got, want,
            "fvek_blob's file reads must match the real metadata"
        );
    }
}
