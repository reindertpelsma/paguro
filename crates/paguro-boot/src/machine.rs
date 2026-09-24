//! The stage machine. Read top to bottom: [`Machine::go`] is the execution
//! contract of DESIGN.md §4.1, and every branch in it is a mock boot test.

use paguro_core::bootstrap;
use paguro_core::config::{self, Config, Efi, Entry, MAX_ENTRIES};
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, Guid, PAGURO_VENDOR, PCR12_EVENT_TAG};
use paguro_core::handoff::{self, Handoff, ImageId, Pcrs, Rung, state};
use paguro_core::ini;
use paguro_core::seal::{self, Kind, Seal, Sealed};
use paguro_core::tpm::RcClass;
use paguro_crypto as kdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::names;
use crate::platform::{
    DirListing, DirView, EntryKind, Grey, Hex, Input, Label, Level, Listing, Notice, Platform,
    PlatformError, Row, Screen, UnlockMenu, VolumeChoice, VolumeFormat, VolumeList, attrs,
};
use crate::tpm::{self, Tpm};
use crate::ui;
use crate::volume::{self, Key, Located, Partition, Volume, VolumeKind};
use crate::{BootError, Buffers, Mode, Outcome, Params, RecoveryReason};

const PCR12: u32 = 12;
/// PCRs recorded for the handoff (0, 2, 4, 7), for re-seals from Linux.
pub const RECORDED_PCRS: u32 = 1 << 0 | 1 << 2 | 1 << 4 | 1 << 7;

enum Step<T> {
    Go(T),
    Done(Outcome),
}

macro_rules! go {
    ($e:expr) => {
        match $e? {
            Step::Go(v) => v,
            Step::Done(o) => return Ok(Step::Done(o)),
        }
    };
}

#[derive(Clone, Copy)]
struct BootstrapData {
    volume: Guid,
    salt: [u8; 16],
    wrapped: [u8; 32],
}

/// Everything the machine learns, including the secrets it must wipe.
struct State {
    mode: Mode,
    flags: u32,
    tpm: bool,
    capped: bool,
    pcr12_was_zero: bool,
    ini_hash: Option<[u8; 32]>,
    b: [u8; 32],
    s: Option<[u8; 32]>,
    bootstrap: Option<BootstrapData>,
    pcrs: [[u8; 32]; 4],
    vmk: Option<Key>,
    user_hash: Option<Key>,
    blob_len: Option<usize>,
    tpm_grey: Option<Grey>,
    tpm_attempts: Option<u32>,
    /// The configuration's `[UI]` preferences are in effect (recovery
    /// hands back the defaults).
    ui_from_ini: bool,
}

impl Drop for State {
    fn drop(&mut self) {
        self.b.zeroize();
        if let Some(s) = self.s.as_mut() {
            s.zeroize();
        }
        if let Some(v) = self.vmk.as_mut() {
            v.zeroize();
        }
        if let Some(u) = self.user_hash.as_mut() {
            u.zeroize();
        }
        if let Some(bs) = self.bootstrap.as_mut() {
            bs.wrapped.zeroize();
        }
    }
}

struct Machine<'a, P: Platform, V: Volume<P>> {
    p: &'a mut P,
    v: &'a mut V,
    params: Params,
    st: State,
}

/// Run the loader to completion.
pub fn run<P: Platform, V: Volume<P>>(
    p: &mut P,
    v: &mut V,
    bufs: &mut Buffers,
    params: &Params,
) -> Outcome {
    let mut m = Machine {
        p,
        v,
        params: *params,
        st: State {
            mode: Mode::Normal,
            flags: 0,
            tpm: false,
            capped: false,
            pcr12_was_zero: false,
            ini_hash: None,
            b: [0; 32],
            s: None,
            bootstrap: None,
            pcrs: [[0; 32]; 4],
            vmk: None,
            user_hash: None,
            blob_len: None,
            tpm_grey: None,
            tpm_attempts: None,
            ui_from_ini: false,
        },
    };
    let out = match m.go(bufs) {
        Ok(Step::Go(o) | Step::Done(o)) => o,
        Err(e) => {
            m.p.log(format_args!("paguro: halted: {e:?}"));
            match e {
                BootError::NotImplemented(_) => {
                    m.p.prompt(&Screen::Notice(Notice::NotImplemented), &mut []);
                }
                BootError::Stage4(_) => {
                    m.p.prompt(&Screen::Notice(Notice::StartFailed), &mut []);
                }
                _ => {}
            }
            Outcome::Halted(e)
        }
    };
    bufs.secret.zeroize();
    bufs.handoff.zeroize();
    bufs.fvek_blob.zeroize();
    out
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// `Boot####` for entry `n`.
fn boot_var_name(n: u16) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = *b"Boot0000";
    for (i, o) in out.iter_mut().skip(4).enumerate() {
        let nib = (n >> (12 - 4 * i)) & 0xf;
        *o = HEX.get(usize::from(nib)).copied().unwrap_or(b'0');
    }
    out
}

fn ascii(b: &[u8]) -> &str {
    core::str::from_utf8(b).unwrap_or("")
}

/// The unwrapped VMK for a standing rung: `key XOR wrapped_vmk`.
fn derive_vmk(env: &Key, salt: &[u8; 16], blob: &[u8], pass_hash: &Key, wrapped: &[u8; 32]) -> Key {
    let mut rg = kdf::root_gate(env, salt, blob);
    let mut key = kdf::final_key(&rg, pass_hash);
    let vmk = kdf::xor32(&key, wrapped);
    rg.zeroize();
    key.zeroize();
    vmk
}

impl<P: Platform, V: Volume<P>> Machine<'_, P, V> {
    fn log(&mut self, args: core::fmt::Arguments<'_>) {
        self.p.log(args);
    }

    fn go(&mut self, b: &mut Buffers) -> Result<Step<Outcome>, BootError> {
        let Buffers {
            ini,
            gen_ini,
            seals,
            var,
            gpt,
            handoff,
            secret,
            path,
            dir,
            fvek_blob,
            created,
            located,
        } = b;
        self.log(format_args!("paguro: stage machine start"));

        // 0 — the bootstrap entry goes first, before anything can fail.
        self.take_bootstrap(var);

        // 1 — read, hash, compare. No parser.
        let ini_len = go!(self.stage1(ini, var));
        let ini_bytes: &[u8] = ini_len.and_then(|n| ini.get(..n)).unwrap_or(&[]);

        // 2 — parse; or recovery / first boot, which cap.
        self.st.tpm = self.p.tpm_present();
        let mut cfg = go!(self.stage2(ini_bytes));
        let entry: Option<Entry<'_>> = cfg.as_ref().and_then(|c| c.default_entry()).copied();

        // The chosen volume: the entry's, the bootstrap payload's on a first
        // boot, or (recovery) whichever enumeration finds. Its seal files are
        // read from its own directory; presence of tpm_seal.bin picks the taint.
        let target = match self.st.mode {
            Mode::Normal => entry.map(|e| e.volume),
            Mode::FirstBoot => self.st.bootstrap.map(|b| b.volume),
            Mode::Recovery(_) => None,
        };
        let mut seal_len = [None; 4];
        let mut seals_for = None;
        if let Some(g) = target {
            self.read_seals(&g, seals, &mut seal_len);
            seals_for = Some(g);
        }
        if self.st.mode == Mode::Normal {
            let tpm_seal_present = seal_len.first().copied().flatten().is_some();
            go!(self.ratchet(ini_bytes, tpm_seal_present));
        }

        // 3 — B, S, recorded PCRs, the volume, the rungs.
        self.load_secrets()?;
        let (part, kind) = go!(self.select_volume(target, gpt, var));
        if self.st.mode != Mode::Normal {
            cfg = None;
        }
        if seals_for != Some(part.guid) {
            self.read_seals(&part.guid, seals, &mut seal_len);
        }
        let tpm_seal_present = seal_len.first().copied().flatten().is_some();
        let seals: &[[u8; seal::MAX_FILE]; 4] = seals;
        let mut parsed: [Option<Seal<'_>>; 4] = [None; 4];
        for (((kind, buf), len), out) in Kind::ALL
            .iter()
            .zip(seals.iter())
            .zip(seal_len)
            .zip(parsed.iter_mut())
        {
            let Some(n) = len else {
                continue;
            };
            match seal::read(*kind, buf.get(..n).unwrap_or(&[])) {
                Ok(s) => *out = Some(s),
                Err(e) => self.log(format_args!(
                    "paguro: {}\\{} refused: {e:?}",
                    part.guid,
                    kind.file_name()
                )),
            }
        }
        self.v.open(self.p, &part, kind)?;
        let rung = match kind {
            VolumeKind::BitLocker => {
                go!(self.unlock(cfg.as_ref(), &parsed, secret, fvek_blob, var))
            }
            VolumeKind::Ntfs => {
                if tpm_seal_present {
                    self.p
                        .prompt(&Screen::Notice(Notice::SealOverPlaintext), &mut []);
                    return Err(BootError::SealOverPlaintext);
                }
                Rung::Unencrypted
            }
            VolumeKind::Other => return Err(BootError::NotAVolume),
        };
        if self.st.mode != Mode::Normal {
            cfg = None;
        }
        self.log(format_args!("paguro: stage3 rung={rung:?}"));
        // BOOT TAINT: the moment a key exists (or before NTFS, when none is needed).
        self.cap("boot taint")?;

        // 4 — locate, degrade gates, provision, handoff, chain.
        *located = Located::new();
        if let Mode::Recovery(_) = self.st.mode {
            // Recovery never reads the configuration: what to boot is chosen
            // on screen (INTERFACES.md §13.4, steps 2 and 3).
            let mut chosen = Chosen::new();
            go!(self.choose_target(path, dir, var, &mut chosen));
            let e = chosen.entry(part.guid);
            match e.efi {
                Efi::Disk { disk, path } => self.log(format_args!(
                    "paguro: recovery target {disk} efi {path} (root {})",
                    e.root.unwrap_or("none")
                )),
                Efi::File(f) => self.log(format_args!(
                    "paguro: recovery target {f} (root {})",
                    e.root.unwrap_or("none")
                )),
            }
            self.v.locate(self.p, Some(&e), located)?;
        } else {
            let entry = cfg.as_ref().and(entry);
            self.v.locate(self.p, entry.as_ref(), located)?;
        }
        if !located.bootable() {
            self.p.prompt(&Screen::NoInstallation, &mut []);
            return Err(BootError::NoVolume);
        }
        for (flag, notice) in [
            (state::HIBERNATED, Notice::Hibernated),
            (state::DIRTY, Notice::Dirty),
        ] {
            if located.flags & flag != 0 {
                match self.p.prompt(&Screen::Notice(notice), &mut []) {
                    Input::StartWindows => return Ok(Step::Done(self.start_windows(var))),
                    _ => self.st.flags |= flag,
                }
            }
        }

        let mut prov = Provision::new();
        let gen_len = if rung == Rung::Bootstrap && self.st.mode == Mode::FirstBoot {
            self.provision(&part, located, gen_ini, fvek_blob, created, &mut prov)
        } else {
            None
        };

        if self.st.s.is_some() {
            // One-shot: S never survives a handoff.
            if let Err(e) = self.p.delete_var(names::VAR_SETUP, &PAGURO_VENDOR) {
                self.log(format_args!("paguro: deleting PaguroSetup failed: {e:?}"));
            }
        }

        let config_bytes = match self.st.mode {
            Mode::Normal => Some(ini_bytes),
            Mode::FirstBoot => gen_len.and_then(|n| gen_ini.get(..n)),
            Mode::Recovery(_) => None,
        };
        let n = self.build_handoff(&part, rung, located, config_bytes, created, &prov, handoff)?;
        self.p
            .publish_handoff(handoff.get(..n).unwrap_or(&[]))
            .map_err(BootError::Platform)?;
        self.log(format_args!(
            "paguro: handoff published ({n} bytes, rung {rung:?})"
        ));
        handoff.zeroize();
        let started = if located.efi_file.is_some() {
            // An efi_file: LoadImage(SourceBuffer), never a jump.
            let image = self.v.efi_image(self.p)?;
            self.p.log(format_args!(
                "paguro: starting efi_file ({} bytes) from a buffer",
                image.len()
            ));
            self.p.load_start_image_buffer(image)
        } else {
            self.log(format_args!(
                "paguro: starting the image by device path ({} bytes)",
                located.chain().len()
            ));
            self.p.load_start_image(located.chain())
        };
        if let Err(e) = started {
            self.log(format_args!("paguro: LoadImage/StartImage failed: {e:?}"));
            self.p.prompt(&Screen::Notice(Notice::StartFailed), &mut []);
            return Err(BootError::Platform(e));
        }
        self.log(format_args!("paguro: the chained image returned"));
        Ok(Step::Go(Outcome::Started(rung)))
    }

    // -----------------------------------------------------------------------
    // Stage 0

    /// If this boot came through the installer's one-shot entry, keep its
    /// payload and delete the entry — the first firmware write of every boot.
    fn take_bootstrap(&mut self, var: &mut [u8]) {
        let mut cur = [0u8; 2];
        let Ok(Some(2)) = self
            .p
            .get_var("BootCurrent", &EFI_GLOBAL_VARIABLE, &mut cur)
        else {
            return;
        };
        let name_b = boot_var_name(u16::from_le_bytes(cur));
        let name = ascii(&name_b);
        let Ok(Some(n)) = self.p.get_var(name, &EFI_GLOBAL_VARIABLE, var) else {
            return;
        };
        let Ok(lo) = bootstrap::parse_load_option(var.get(..n).unwrap_or(&[])) else {
            return;
        };
        match bootstrap::parse_optional_data(lo.optional_data) {
            Ok(bs) => {
                self.st.bootstrap = Some(BootstrapData {
                    volume: bs.volume,
                    salt: *bs.salt,
                    wrapped: *bs.wrapped_vmk,
                });
            }
            Err(bootstrap::BootstrapError::NotBootstrap) => return,
            Err(e) => self.log(format_args!("paguro: malformed bootstrap entry: {e:?}")),
        }
        var.zeroize();
        match self.p.delete_var(name, &EFI_GLOBAL_VARIABLE) {
            Ok(()) => self.log(format_args!("paguro: bootstrap entry {name} deleted")),
            Err(e) => self.log(format_args!("paguro: deleting {name} failed: {e:?}")),
        }
    }

    // -----------------------------------------------------------------------
    // Stage 1: must be correct; nothing protects it.

    /// Returns the verified length of `paguro.ini` in `ini` when the mode is
    /// [`Mode::Normal`], `None` otherwise.
    fn stage1(
        &mut self,
        ini_buf: &mut [u8],
        var: &mut [u8],
    ) -> Result<Step<Option<usize>>, BootError> {
        let n = match self.p.read_esp_file(names::INI, ini_buf) {
            Ok(Some(n)) if n <= ini::MAX_LEN => n,
            Ok(None) => {
                self.log(format_args!("paguro: stage1 no-config"));
                self.st.mode = if self.st.bootstrap.is_some() {
                    Mode::FirstBoot
                } else {
                    Mode::Recovery(RecoveryReason::NoConfig)
                };
                return Ok(Step::Go(None));
            }
            Ok(Some(_)) | Err(_) => {
                self.log(format_args!(
                    "paguro: stage1 config unreadable or over 64 KiB"
                ));
                self.st.mode = Mode::Recovery(RecoveryReason::ConfigUnreadable);
                return Ok(Step::Go(None));
            }
        };
        let hash = sha256(ini_buf.get(..n).unwrap_or(&[]));
        self.st.ini_hash = Some(hash);
        if !self.p.secure_boot() {
            // The loader itself is substitutable: the hash would protect
            // nothing. PCR 12 still binds the TPM rung (INTERFACES.md §3.3).
            self.log(format_args!("paguro: stage1 skipped (secure boot off)"));
            self.st.flags |= state::CONFIG_UNVERIFIED;
            return Ok(Step::Go(Some(n)));
        }
        let mut stored = [0u8; 33];
        let stored_len = self
            .p
            .get_var(names::VAR_CONFIG_HASH, &PAGURO_VENDOR, &mut stored)
            .unwrap_or(None);
        if stored_len != Some(32) {
            // Absent or wrong size — treated as absent (§5): NVRAM cleared.
            self.log(format_args!("paguro: stage1 hash variable missing"));
            self.st.mode = Mode::Recovery(RecoveryReason::HashMissing);
            return Ok(Step::Go(None));
        }
        if !tpm::ct_eq(stored.get(..32).unwrap_or(&[]), &hash) {
            self.log(format_args!("paguro: stage1 hash mismatch"));
            return match self.p.prompt(&Screen::ConfigInvalid, &mut []) {
                Input::Recover => {
                    self.st.mode = Mode::Recovery(RecoveryReason::HashMismatch);
                    Ok(Step::Go(None))
                }
                _ => Ok(Step::Done(self.start_windows(var))),
            };
        }
        self.log(format_args!("paguro: stage1 ok (verified)"));
        Ok(Step::Go(Some(n)))
    }

    // -----------------------------------------------------------------------
    // Stage 2: behind stage 1; small.

    fn stage2<'i>(&mut self, ini: &'i [u8]) -> Result<Step<Option<Config<'i>>>, BootError> {
        match self.st.mode {
            Mode::Recovery(reason) => {
                self.enter_recovery(reason)?;
                return Ok(Step::Go(None));
            }
            Mode::FirstBoot => {
                self.st.flags |= state::CONFIG_UNVERIFIED;
                self.st.pcr12_was_zero = self.pcr12_is_zero();
                self.log(format_args!(
                    "paguro: first boot (bootstrap), compiled-in defaults"
                ));
                self.cap("first boot")?;
                return Ok(Step::Go(None));
            }
            Mode::Normal => {}
        }
        let cfg = match config::parse(ini) {
            Ok(c) => c,
            Err(e) => {
                self.log(format_args!("paguro: stage2 config refused: {e:?}"));
                return match self.p.prompt(&Screen::ConfigInvalid, &mut []) {
                    Input::Recover => {
                        self.enter_recovery(RecoveryReason::ConfigInvalid)?;
                        Ok(Step::Go(None))
                    }
                    _ => Ok(Step::Done(self.start_windows_no_var())),
                };
            }
        };
        self.log(format_args!(
            "paguro: stage2 ok ({} entries, default {})",
            cfg.entry_count,
            cfg.default_entry().map_or("", |e| e.name)
        ));
        if cfg.ui != config::Ui::DEFAULT {
            // Enums selecting compiled-in data (INTERFACES.md §13.2a).
            self.log(format_args!(
                "paguro: ui {} {} {}",
                cfg.ui.theme.name(),
                cfg.ui.mode.name(),
                cfg.ui.keyboard.name()
            ));
            self.p.ui_prefs(cfg.ui);
            self.st.ui_from_ini = true;
        }
        Ok(Step::Go(Some(cfg)))
    }

    /// Normal mode: PCR 12 must be zero; then the load taint, or the sentinel
    /// when the chosen volume has no `tpm_seal.bin`.
    fn ratchet(&mut self, ini: &[u8], tpm_seal_present: bool) -> Result<Step<()>, BootError> {
        if self.st.tpm {
            if !self.pcr12_is_zero() {
                self.log(format_args!(
                    "paguro: refusing: PCR 12 not zero before first extend"
                ));
                return match self
                    .p
                    .prompt(&Screen::Notice(Notice::Pcr12NotZero), &mut [])
                {
                    Input::Recover => {
                        self.enter_recovery(RecoveryReason::Pcr12NotZero)?;
                        Ok(Step::Go(()))
                    }
                    _ => Ok(Step::Done(self.start_windows_no_var())),
                };
            }
            self.st.pcr12_was_zero = true;
            if tpm_seal_present {
                self.extend12(ini, names::LOAD_TAINT_EVENT)?;
                self.log_pcr12("load taint");
            } else {
                // No seal: poison PCR 12 now, so deleting the seal cannot skip
                // the ratchet (DESIGN.md §6, "The ratchet").
                self.cap("no tpm_seal.bin")?;
            }
        }
        Ok(Step::Go(()))
    }

    /// Bounded reads of `volume`'s seal files; unreadable counts as absent.
    fn read_seals(
        &mut self,
        volume: &Guid,
        bufs: &mut [[u8; seal::MAX_FILE]; 4],
        lens: &mut [Option<usize>; 4],
    ) {
        for ((kind, buf), len) in Kind::ALL.iter().zip(bufs.iter_mut()).zip(lens.iter_mut()) {
            let mut path = [0u8; names::SEAL_PATH_MAX];
            let path = names::seal_path(volume, *kind, &mut path);
            *len = match self.p.read_esp_file(path, buf) {
                Ok(n) => n,
                Err(e) => {
                    self.log(format_args!("paguro: {path} unreadable: {e:?}"));
                    None
                }
            };
        }
    }

    fn pcr12_is_zero(&mut self) -> bool {
        if !self.st.tpm {
            return false;
        }
        match Tpm::new(self.p).pcr_read(1 << PCR12) {
            Ok(v) => v.get(PCR12) == Some(&[0; 32]),
            Err(e) => {
                self.log(format_args!("paguro: PCR 12 read failed: {e:?}"));
                false
            }
        }
    }

    fn extend12(&mut self, data: &[u8], label: &[u8]) -> Result<(), BootError> {
        let mut event = [0u8; 64];
        let n = 16 + label.len();
        let ev = event.get_mut(..n).ok_or(BootError::Disk)?;
        let (g, l) = ev.split_at_mut(16);
        g.copy_from_slice(&PCR12_EVENT_TAG.0);
        l.copy_from_slice(label);
        self.p
            .hash_log_extend(PCR12, data, event.get(..n).unwrap_or(&[]))
            .map_err(|e| BootError::Tpm(tpm::TpmFail::Platform(e)))
    }

    fn log_pcr12(&mut self, what: &str) {
        match Tpm::new(self.p).pcr_read(1 << PCR12) {
            Ok(v) => {
                let val = v.get(PCR12).copied().unwrap_or([0; 32]);
                self.log(format_args!("paguro: pcr12={} ({what})", Hex(&val)));
            }
            Err(e) => self.log(format_args!("paguro: pcr12 unreadable: {e:?}")),
        }
    }

    /// Extend the boot-taint sentinel once (no-op without a TPM).
    fn cap(&mut self, why: &str) -> Result<(), BootError> {
        if !self.st.tpm || self.st.capped {
            return Ok(());
        }
        self.extend12(names::BOOT_TAINT, names::BOOT_TAINT)?;
        self.st.capped = true;
        self.log_pcr12(why);
        Ok(())
    }

    /// Any path that parses unverified input caps first.
    fn enter_recovery(&mut self, reason: RecoveryReason) -> Result<(), BootError> {
        self.st.mode = Mode::Recovery(reason);
        self.st.flags |= state::RECOVERY_PATH | state::CONFIG_UNVERIFIED;
        self.st.tpm_grey = Some(Grey::RecoveryMode);
        self.log(format_args!("paguro: recovery ({reason:?})"));
        if core::mem::take(&mut self.st.ui_from_ini) {
            // Recovery does not read the configuration, so it starts in
            // dark / auto (INTERFACES.md §13.2a).
            self.p.ui_prefs(config::Ui::DEFAULT);
        }
        if self.st.tpm && !self.st.capped {
            self.cap("recovery")?;
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Stage 3: the VMK is still obtainable here.

    fn load_secrets(&mut self) -> Result<(), BootError> {
        // B, eagerly, before any rung (DESIGN.md §6).
        let mut b = [0u8; 33];
        match self.p.get_var(names::VAR_B, &PAGURO_VENDOR, &mut b) {
            Ok(Some(32)) => {
                self.st.b.copy_from_slice(b.get(..32).unwrap_or(&[0; 32]));
            }
            _ => {
                self.p.random(&mut self.st.b).map_err(|_| BootError::Rng)?;
                match self
                    .p
                    .set_var(names::VAR_B, &PAGURO_VENDOR, attrs::NV_BS, &self.st.b)
                {
                    Ok(()) => self.log(format_args!("paguro: created B")),
                    Err(e) => self.log(format_args!("paguro: storing B failed: {e:?}")),
                }
            }
        }
        b.zeroize();
        let mut s = [0u8; 33];
        if let Ok(Some(32)) = self.p.get_var(names::VAR_SETUP, &PAGURO_VENDOR, &mut s) {
            let mut v = [0u8; 32];
            v.copy_from_slice(s.get(..32).unwrap_or(&[0; 32]));
            self.st.s = Some(v);
        }
        s.zeroize();
        if self.st.tpm {
            match Tpm::new(self.p).pcr_read(RECORDED_PCRS) {
                Ok(v) => {
                    for (i, pcr) in [0u32, 2, 4, 7].iter().enumerate() {
                        if let (Some(dst), Some(src)) = (self.st.pcrs.get_mut(i), v.get(*pcr)) {
                            *dst = *src;
                        }
                    }
                    let p = self.st.pcrs;
                    self.log(format_args!(
                        "paguro: pcrs 0={} 2={} 4={} 7={}",
                        Hex(&p[0]),
                        Hex(&p[1]),
                        Hex(&p[2]),
                        Hex(&p[3])
                    ));
                }
                Err(e) => self.log(format_args!("paguro: PCR read failed: {e:?}")),
            }
        }
        Ok(())
    }

    /// The chosen entry's volume (normal) or the bootstrap payload's (first
    /// boot), on any disk; otherwise, or when it is missing and the user
    /// recovers, whatever enumeration finds.
    fn select_volume(
        &mut self,
        target: Option<Guid>,
        gpt: &mut volume::GptScratch,
        var: &mut [u8],
    ) -> Result<Step<(Partition, VolumeKind)>, BootError> {
        if let (Mode::Normal | Mode::FirstBoot, Some(id)) = (self.st.mode, target) {
            if let Some(part) = volume::find_partition(self.p, gpt, &id)? {
                let kind = volume::probe(self.p, &part, &mut gpt.block)?;
                self.log(format_args!(
                    "paguro: volume {} ({kind:?}) on disk {}",
                    part.guid, part.disk
                ));
                return Ok(Step::Go((part, kind)));
            }
            self.log(format_args!("paguro: configured volume {id} not found"));
            match self
                .p
                .prompt(&Screen::Notice(Notice::VolumeMissing), &mut [])
            {
                Input::Recover => self.enter_recovery(RecoveryReason::VolumeMissing)?,
                _ => return Ok(Step::Done(self.start_windows(var))),
            }
        }
        // Recovery: always enumerate; the configuration cannot steer where to
        // look.
        let mut cands = [None; volume::MAX_CANDIDATES];
        let n = volume::enumerate_candidates(self.p, gpt, &mut cands)?;
        self.log(format_args!("paguro: {n} candidate volume(s)"));
        let pick = match n {
            0 => {
                return match self.p.prompt(&Screen::NoInstallation, &mut []) {
                    Input::StartWindows => Ok(Step::Done(self.start_windows(var))),
                    _ => Err(BootError::NoVolume),
                };
            }
            1 => 0usize,
            _ => {
                let mut list = VolumeList::new();
                for c in cands.iter().flatten() {
                    list.push(VolumeChoice {
                        disk: u8::try_from(c.part.disk).unwrap_or(u8::MAX),
                        partition: c.part.index,
                        bytes: c.part.sectors.saturating_mul(u64::from(c.part.block_size)),
                        format: match c.kind {
                            VolumeKind::BitLocker => VolumeFormat::BitLocker,
                            _ => VolumeFormat::Ntfs,
                        },
                        name: c.name,
                    });
                }
                match self.p.prompt(&Screen::SelectVolume(list), &mut []) {
                    Input::Choose(i) if usize::from(i) < n => usize::from(i),
                    Input::StartWindows => return Ok(Step::Done(self.start_windows(var))),
                    _ => return Err(BootError::NoVolume),
                }
            }
        };
        let c = cands
            .get(pick)
            .copied()
            .flatten()
            .ok_or(BootError::NoVolume)?;
        self.log(format_args!(
            "paguro: volume {} ({:?})",
            c.part.guid, c.kind
        ));
        Ok(Step::Go((c.part, c.kind)))
    }

    /// A path typed on `level`, checked; `None` after Esc or a refused path
    /// (which says so). The buffer is wiped either way.
    fn typed_path(&mut self, level: Level, path: &mut [u8], out: &mut PathText) -> Option<()> {
        let got = match self.p.prompt(&Screen::EnterPath(level), path) {
            Input::Secret(n) => path.get(..n).and_then(|b| core::str::from_utf8(b).ok()),
            _ => None,
        };
        let Some(typed) = got else {
            path.zeroize();
            return None;
        };
        let mut norm = [0u8; config::MAX_PATH_BYTES + 1];
        let ok = match ui::normalize_path(typed, &mut norm) {
            Some((t, drive)) => {
                if drive {
                    self.log(format_args!("paguro: typed path: drive letter ignored"));
                }
                config::check_path(t).is_ok() && out.set(t)
            }
            None => false,
        };
        path.zeroize();
        if !ok {
            self.log(format_args!("paguro: typed path refused"));
            self.p.prompt(&Screen::PathRefused, &mut []);
            return None;
        }
        Some(())
    }

    /// Recovery, steps 2 and 3 (INTERFACES.md §13.4): browse the unlocked
    /// volume from `\paguro\` (or type a path) for a disk or a UEFI image.
    /// A disk is its own root, and starts its default UEFI image or one
    /// chosen on its EFI partition (browsed or typed); a UEFI image gets a
    /// root hint — the only disk in `\paguro\`, one browsed for among several, or
    /// none. When `\paguro\` holds exactly one file and nothing else it is
    /// taken silently (a disk with its default image; DESIGN.md §4.1: each
    /// step is skipped when exactly one candidate qualifies) until the user
    /// backs out of a later step.
    fn choose_target(
        &mut self,
        typed: &mut [u8],
        dir: &mut DirListing,
        var: &mut [u8],
        out: &mut Chosen,
    ) -> Result<Step<()>, BootError> {
        dir.clear(Level::Volume);
        self.v.list_dir(self.p, PAGURO_DIR, dir)?;
        dir.sort();
        // Root candidates: the disks in \paguro\ (the only one is taken).
        let mut disks = 0usize;
        let mut only_disk = PathText::new();
        for i in 0..dir.len() {
            if let Some(e) = dir.item(i).filter(|e| e.kind == EntryKind::Disk) {
                disks += 1;
                if disks == 1 && !only_disk.join(PAGURO_DIR, e.name) {
                    only_disk.clear();
                }
            }
        }
        self.log(format_args!(
            "paguro: {} entries in \\paguro\\, {disks} disk(s)",
            dir.len()
        ));
        let mut auto = dir.len() == 1 && dir.item(0).is_some_and(|e| e.kind != EntryKind::Dir);
        let mut cwd = PathText::new();
        cwd.set(PAGURO_DIR);
        let mut came_from = PathText::new();
        loop {
            // Step 2: a disk or a UEFI image on the volume.
            let kind = if auto {
                let Some(e) = dir.item(0) else {
                    return Err(BootError::NoVolume);
                };
                if !out.efi.join(PAGURO_DIR, e.name) {
                    return Err(BootError::NoVolume);
                }
                if e.kind == EntryKind::Disk {
                    // Nothing asked: the default image, as on a normal boot.
                    out.fat.clear();
                    out.kind = EntryKind::Disk;
                    out.root_is_efi();
                    return Ok(Step::Go(()));
                }
                auto = false;
                EntryKind::Efi
            } else {
                dir.clear(Level::Volume);
                self.v.list_dir(self.p, cwd.as_str(), dir)?;
                dir.sort();
                let selected = came_from
                    .get()
                    .and_then(|n| dir.find(n.rsplit('\\').next().unwrap_or(n)))
                    .unwrap_or(0);
                came_from.clear();
                let view = DirView {
                    path: cwd.as_str(),
                    listing: dir,
                    selected,
                    level: Level::Volume,
                };
                match self.p.prompt_browse(&Screen::Browse(Level::Volume), &view) {
                    Input::Entry(i) => {
                        let Some(e) = dir.item(usize::from(i)) else {
                            continue;
                        };
                        match e.kind {
                            EntryKind::Dir => {
                                if !cwd.push(e.name) {
                                    self.p.prompt(&Screen::PathRefused, &mut []);
                                }
                                continue;
                            }
                            EntryKind::Disk | EntryKind::Efi => {
                                if !out.efi.join(cwd.as_str(), e.name) {
                                    self.p.prompt(&Screen::PathRefused, &mut []);
                                    continue;
                                }
                                e.kind
                            }
                        }
                    }
                    Input::Parent => {
                        came_from = cwd;
                        if !cwd.pop() {
                            came_from.clear();
                        }
                        continue;
                    }
                    Input::TypePath => {
                        if self
                            .typed_path(Level::Volume, typed, &mut out.efi)
                            .is_none()
                        {
                            continue;
                        }
                        ui::classify_path(out.efi.as_str())
                    }
                    Input::StartWindows => return Ok(Step::Done(self.start_windows(var))),
                    _ => return Err(BootError::UserAbort),
                }
            };
            out.kind = kind;
            out.fat.clear();
            out.root.clear();
            // Backing out of step 3 returns to the browser, on this entry.
            came_from = out.efi;
            // Step 3.
            if kind == EntryKind::Disk {
                match self.disk_start(typed, dir, out)? {
                    true => {
                        out.root_is_efi();
                        return Ok(Step::Go(()));
                    }
                    false => continue,
                }
            }
            match disks {
                0 => return Ok(Step::Go(())),
                1 => {
                    out.root = only_disk;
                    return Ok(Step::Go(()));
                }
                _ => {
                    if self.browse_root(typed, dir, out)? {
                        return Ok(Step::Go(()));
                    }
                }
            }
        }
    }

    /// The root hint for an `efi_file` among several disks: the browser
    /// again, from `\paguro\`, over folders and disks, with "no root" (the
    /// initrd asks). `false`: back to the first browser.
    fn browse_root(
        &mut self,
        typed: &mut [u8],
        dir: &mut DirListing,
        out: &mut Chosen,
    ) -> Result<bool, BootError> {
        let mut cwd = PathText::new();
        cwd.set(PAGURO_DIR);
        let mut came_from = PathText::new();
        loop {
            dir.clear(Level::Root);
            self.v.list_dir(self.p, cwd.as_str(), dir)?;
            dir.sort();
            let selected = came_from
                .get()
                .and_then(|n| dir.find(n.rsplit('\\').next().unwrap_or(n)))
                .unwrap_or(0);
            came_from.clear();
            let view = DirView {
                path: cwd.as_str(),
                listing: dir,
                selected,
                level: Level::Root,
            };
            match self.p.prompt_browse(&Screen::Browse(Level::Root), &view) {
                Input::Entry(i) => {
                    let Some(e) = dir.item(usize::from(i)) else {
                        continue;
                    };
                    let ok = if e.kind == EntryKind::Dir {
                        cwd.push(e.name)
                    } else if out.root.join(cwd.as_str(), e.name) {
                        return Ok(true);
                    } else {
                        false
                    };
                    if !ok {
                        self.p.prompt(&Screen::PathRefused, &mut []);
                    }
                }
                Input::Parent => {
                    came_from = cwd;
                    if !cwd.pop() {
                        came_from.clear();
                    }
                }
                Input::TypePath => {
                    if self.typed_path(Level::Root, typed, &mut out.root).is_some() {
                        return Ok(true);
                    }
                }
                Input::NoRoot => {
                    out.root.clear();
                    return Ok(true);
                }
                _ => return Ok(false),
            }
        }
    }

    /// A disk was chosen: its default UEFI image, one browsed on its EFI
    /// partition, or a typed one. `false`: the user went back.
    fn disk_start(
        &mut self,
        typed: &mut [u8],
        dir: &mut DirListing,
        out: &mut Chosen,
    ) -> Result<bool, BootError> {
        loop {
            let screen = Screen::DiskStart {
                disk: Label::truncated(out.efi_name()),
            };
            match self.p.prompt(&screen, &mut []) {
                Input::UseDefault => {
                    out.fat.clear();
                    return Ok(true);
                }
                Input::TypePath => {
                    if self
                        .typed_path(Level::EfiPartition, typed, &mut out.fat)
                        .is_some()
                    {
                        return Ok(true);
                    }
                }
                Input::BrowseDisk => {
                    if self.browse_efi_partition(typed, dir, out)? {
                        return Ok(true);
                    }
                }
                _ => return Ok(false),
            }
        }
    }

    /// The browser on the chosen disk's EFI partition: folders and UEFI
    /// images. `false`: back to the disk screen.
    fn browse_efi_partition(
        &mut self,
        typed: &mut [u8],
        dir: &mut DirListing,
        out: &mut Chosen,
    ) -> Result<bool, BootError> {
        let mut cwd = PathText::new();
        cwd.set("\\");
        let mut came_from = PathText::new();
        loop {
            dir.clear(Level::EfiPartition);
            if !self
                .v
                .list_efi_dir(self.p, out.efi.as_str(), cwd.as_str(), dir)?
            {
                self.log(format_args!(
                    "paguro: no EFI partition on {}",
                    out.efi.as_str()
                ));
                self.p.prompt(&Screen::NoEfiPartition, &mut []);
                return Ok(false);
            }
            dir.sort();
            let selected = came_from
                .get()
                .and_then(|n| dir.find(n.rsplit('\\').next().unwrap_or(n)))
                .unwrap_or(0);
            came_from.clear();
            let view = DirView {
                path: cwd.as_str(),
                listing: dir,
                selected,
                level: Level::EfiPartition,
            };
            match self
                .p
                .prompt_browse(&Screen::Browse(Level::EfiPartition), &view)
            {
                Input::Entry(i) => {
                    let Some(e) = dir.item(usize::from(i)) else {
                        continue;
                    };
                    if e.kind == EntryKind::Dir {
                        if !cwd.push(e.name) {
                            self.p.prompt(&Screen::PathRefused, &mut []);
                        }
                        continue;
                    }
                    if out.fat.join(cwd.as_str(), e.name) {
                        return Ok(true);
                    }
                    self.p.prompt(&Screen::PathRefused, &mut []);
                }
                Input::Parent => {
                    came_from = cwd;
                    if !cwd.pop() {
                        came_from.clear();
                    }
                }
                Input::TypePath => {
                    if self
                        .typed_path(Level::EfiPartition, typed, &mut out.fat)
                        .is_some()
                    {
                        return Ok(true);
                    }
                }
                _ => return Ok(false),
            }
        }
    }

    fn blob<'b>(&mut self, buf: &'b mut [u8]) -> Result<&'b [u8], BootError> {
        let n = match self.st.blob_len {
            Some(n) => n,
            None => {
                let n = self.v.fvek_blob(self.p, buf)?;
                self.st.blob_len = Some(n);
                n
            }
        };
        buf.get(..n).ok_or(BootError::Disk)
    }

    fn accept(&mut self, vmk: Key) -> Result<bool, BootError> {
        if self.v.try_vmk(self.p, &vmk)? {
            self.st.vmk = Some(vmk);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// The standing seal matched and its key opened the volume (the FVEK
    /// unwrap is the confirmation, not the unseal), so a `PaguroTpmBroken`
    /// left by an earlier boot is stale (INTERFACES.md §5). Read first so a
    /// normal boot writes nothing to NVRAM.
    fn clear_tpm_broken(&mut self) {
        let mut flag = [0u8; 1];
        if let Ok(Some(_)) = self
            .p
            .get_var(names::VAR_TPM_BROKEN, &PAGURO_VENDOR, &mut flag)
        {
            if let Err(e) = self.p.delete_var(names::VAR_TPM_BROKEN, &PAGURO_VENDOR) {
                self.log(format_args!(
                    "paguro: clearing PaguroTpmBroken failed: {e:?}"
                ));
            }
        }
    }

    fn tpm_usable(&self, cfg: Option<&Config<'_>>, parsed: &[Option<Seal<'_>>; 4]) -> bool {
        self.st.tpm
            && self.st.mode == Mode::Normal
            && self.st.tpm_grey.is_none()
            && parsed.first().copied().flatten().is_some()
            && cfg.is_some_and(|c| c.tpm)
    }

    fn setup_usable(&self, cfg: Option<&Config<'_>>, parsed: &[Option<Seal<'_>>; 4]) -> bool {
        self.st.s.is_some()
            && self.st.ini_hash.is_some()
            && parsed.get(1).copied().flatten().is_some()
            && (self.st.mode != Mode::Normal || cfg.is_some_and(|c| c.setup_tpm))
    }

    fn passphrase_usable(&self, cfg: Option<&Config<'_>>, parsed: &[Option<Seal<'_>>; 4]) -> bool {
        parsed.get(2).copied().flatten().is_some()
            && (self.st.mode != Mode::Normal || cfg.is_some_and(|c| c.passphrase))
    }

    fn unlock(
        &mut self,
        cfg: Option<&Config<'_>>,
        parsed: &[Option<Seal<'_>>; 4],
        secret: &mut [u8; 256],
        blob_buf: &mut [u8],
        var: &mut [u8],
    ) -> Result<Step<Rung>, BootError> {
        // Input-free paths, silently: the PIN bypass, then a clear key.
        if let Some(r) = self.try_pin_bypass(cfg, parsed)? {
            return Ok(Step::Go(r));
        }
        if let Some(vmk) = self.v.clear_key(self.p)? {
            if self.accept(vmk)? {
                return Ok(Step::Go(Rung::ClearKey));
            }
        }
        if self.tpm_usable(cfg, parsed) {
            match Tpm::new(self.p).lockout() {
                Ok(l) if l.in_lockout => self.st.tpm_grey = Some(Grey::Locked),
                Ok(l) => self.st.tpm_attempts = Some(l.attempts_left()),
                Err(e) => self.log(format_args!("paguro: lockout query failed: {e:?}")),
            }
        }
        loop {
            let cfg = if self.st.mode == Mode::Normal {
                cfg
            } else {
                None
            };
            let tpm_row = self.tpm_usable(cfg, parsed);
            let free_pw = self.setup_usable(cfg, parsed)
                || self.passphrase_usable(cfg, parsed)
                || self.st.bootstrap.is_some()
                || self.v.has_bitlocker_password();
            let menu = UnlockMenu {
                password_or_pin: tpm_row || free_pw,
                recovery_passphrase: self.passphrase_usable(cfg, parsed),
                recovery_key: true,
                tpm: if tpm_row {
                    Ok(self.st.tpm_attempts)
                } else {
                    Err(self.st.tpm_grey.unwrap_or(Grey::Unavailable))
                },
                unattested: self.st.flags & state::CONFIG_UNVERIFIED != 0,
                first_boot: self.st.mode == Mode::FirstBoot,
            };
            let input = self.p.prompt(&Screen::Unlock(menu), &mut []);
            let row = match input {
                Input::Select(Row::PasswordOrPin) if menu.password_or_pin => Row::PasswordOrPin,
                Input::Select(Row::RecoveryPassphrase) if menu.recovery_passphrase => {
                    Row::RecoveryPassphrase
                }
                Input::Select(Row::RecoveryKey) => Row::RecoveryKey,
                Input::StartWindows => return Ok(Step::Done(self.start_windows(var))),
                Input::Recover if self.st.mode == Mode::Normal => {
                    self.enter_recovery(RecoveryReason::Voluntary)?;
                    continue;
                }
                _ => match self.p.prompt(&Screen::CannotUnlock, &mut []) {
                    Input::Select(Row::RecoveryKey) => Row::RecoveryKey,
                    Input::StartWindows | Input::Continue => {
                        return Ok(Step::Done(self.start_windows(var)));
                    }
                    _ => return Err(BootError::UserAbort),
                },
            };
            let screen = Screen::EnterSecret {
                row,
                unattested: menu.unattested,
            };
            let len = match self.p.prompt(&screen, secret) {
                Input::Secret(n) if n <= secret.len() => n,
                _ => continue,
            };
            let got = {
                let s = secret.get(..len).unwrap_or(&[]);
                let mut copy = [0u8; 256];
                if let Some(d) = copy.get_mut(..len) {
                    d.copy_from_slice(s);
                }
                secret.zeroize();
                let r = match row {
                    Row::RecoveryKey => self.try_recovery_key(copy.get(..len).unwrap_or(&[])),
                    Row::PasswordOrPin => self.try_password(
                        copy.get(..len).unwrap_or(&[]),
                        true,
                        cfg,
                        parsed,
                        blob_buf,
                    ),
                    Row::RecoveryPassphrase => self.try_password(
                        copy.get(..len).unwrap_or(&[]),
                        false,
                        cfg,
                        parsed,
                        blob_buf,
                    ),
                };
                copy.zeroize();
                r?
            };
            if let Some(rung) = got {
                return Ok(Step::Go(rung));
            }
            if self.st.tpm_grey == Some(Grey::Locked) {
                self.p.prompt(&Screen::TpmLocked, &mut []);
            } else {
                self.p.prompt(&Screen::Incorrect, &mut []);
            }
        }
    }

    fn try_pin_bypass(
        &mut self,
        cfg: Option<&Config<'_>>,
        parsed: &[Option<Seal<'_>>; 4],
    ) -> Result<Option<Rung>, BootError> {
        let Some(Some(seal)) = parsed.get(3).copied() else {
            return Ok(None);
        };
        if !self.st.tpm || self.st.mode != Mode::Normal || cfg.is_none_or(|c| !c.tpm) {
            return Ok(None);
        }
        let (Some(sealed), Some(pcrs), Some(deadline)) = (seal.sealed, seal.pcrs, seal.deadline)
        else {
            return Ok(None);
        };
        match Tpm::new(self.p).read_clock() {
            Ok(c) if !c.safe => {
                self.log(format_args!(
                    "paguro: pin bypass refused: TPM clock not safe"
                ));
                return Ok(None);
            }
            Ok(c) if c.clock >= deadline => {
                self.log(format_args!("paguro: pin bypass expired"));
                return Ok(None);
            }
            Ok(_) => {}
            Err(e) => {
                self.log(format_args!("paguro: ReadClock failed: {e:?}"));
                return Ok(None);
            }
        }
        let mut d = [0u8; 32];
        let r = Tpm::new(self.p).unseal(
            sealed.private,
            sealed.public,
            pcrs.mask,
            Some(deadline),
            &[],
            &mut d,
        );
        match r {
            Ok(()) => {
                self.log(format_args!("paguro: rung pin-bypass: unsealed"));
                // Deviation (documented): the bypass payload D is the pad itself.
                let vmk = kdf::xor32(&d, seal.wrapped_vmk);
                d.zeroize();
                Ok(self.accept(vmk)?.then_some(Rung::PinBypass))
            }
            Err(e) => {
                self.log(format_args!("paguro: pin bypass failed: {e:?}"));
                Ok(None)
            }
        }
    }

    fn try_recovery_key(&mut self, digits: &[u8]) -> Result<Option<Rung>, BootError> {
        let Ok(mut key) = volume::parse_recovery_password(digits) else {
            return Ok(None);
        };
        let vmk = self.v.recovery_key(self.p, &key)?;
        key.zeroize();
        match vmk {
            Some(v) if self.accept(v)? => Ok(Some(Rung::RecoveryKey)),
            _ => Ok(None),
        }
    }

    /// Free protectors first, then the TPM: a correct password never costs a
    /// dictionary-attack attempt, whichever row was chosen.
    fn try_password(
        &mut self,
        pw: &[u8],
        include_tpm: bool,
        cfg: Option<&Config<'_>>,
        parsed: &[Option<Seal<'_>>; 4],
        blob_buf: &mut [u8],
    ) -> Result<Option<Rung>, BootError> {
        let Ok(pw) = core::str::from_utf8(pw) else {
            return Ok(None);
        };
        let mut user = kdf::user_password_hash(pw);
        let r = self.try_password_hash(&user, include_tpm, cfg, parsed, blob_buf);
        if matches!(r, Ok(Some(_))) {
            self.st.user_hash = Some(user);
        }
        user.zeroize();
        r
    }

    fn stretch(&self, user: &Key, salt: &[u8; 16]) -> Key {
        kdf::bitlocker_stretch(user, salt, self.params.stretch_iterations)
    }

    fn try_password_hash(
        &mut self,
        user: &Key,
        include_tpm: bool,
        cfg: Option<&Config<'_>>,
        parsed: &[Option<Seal<'_>>; 4],
        blob_buf: &mut [u8],
    ) -> Result<Option<Rung>, BootError> {
        // setupTPM: S + H(paguro.ini) + passphrase.
        if include_tpm && self.setup_usable(cfg, parsed) {
            if let (Some(Some(seal)), Some(s), Some(h)) =
                (parsed.get(1).copied(), self.st.s, self.st.ini_hash)
            {
                let mut ph = self.stretch(user, seal.salt);
                let env = kdf::env_setup(&s, &h);
                let blob = self.blob(blob_buf)?;
                let vmk = derive_vmk(&env, seal.salt, blob, &ph, seal.wrapped_vmk);
                ph.zeroize();
                if self.accept(vmk)? {
                    return Ok(Some(Rung::SetupTpm));
                }
            }
        }
        // passphrase: a public env; opt-in.
        if self.passphrase_usable(cfg, parsed) {
            if let Some(Some(seal)) = parsed.get(2).copied() {
                let mut ph = self.stretch(user, seal.salt);
                let blob = self.blob(blob_buf)?;
                let vmk = derive_vmk(
                    &kdf::env_passphrase(),
                    seal.salt,
                    blob,
                    &ph,
                    seal.wrapped_vmk,
                );
                ph.zeroize();
                if self.accept(vmk)? {
                    return Ok(Some(Rung::Passphrase));
                }
            }
        }
        // bootstrap: single-factor wrapping, sound only because nothing but
        // the FVEK unwrap can test it.
        if include_tpm {
            if let Some(bs) = self.st.bootstrap {
                let mut ph = self.stretch(user, &bs.salt);
                let mut k = kdf::bootstrap_key(&ph, &bs.salt);
                let vmk = kdf::xor32(&k, &bs.wrapped);
                ph.zeroize();
                k.zeroize();
                if self.accept(vmk)? {
                    return Ok(Some(Rung::Bootstrap));
                }
            }
        }
        // A BitLocker password protector on the volume itself (FVE-sourced,
        // unsigned, self-validating: the FVEK's MAC is the check).
        if let Some(vmk) = self.v.bitlocker_password(self.p, user)? {
            if self.accept(vmk)? {
                return Ok(Some(Rung::BitLockerPassword));
            }
        }
        // tpm: the only rung that costs an attempt.
        if include_tpm && self.tpm_usable(cfg, parsed) {
            if let Some(Some(seal)) = parsed.first().copied() {
                return self.try_tpm(user, &seal, blob_buf);
            }
        }
        Ok(None)
    }

    fn try_tpm(
        &mut self,
        user: &Key,
        seal: &Seal<'_>,
        blob_buf: &mut [u8],
    ) -> Result<Option<Rung>, BootError> {
        let (Some(sealed), Some(pcrs)) = (seal.sealed, seal.pcrs) else {
            return Ok(None);
        };
        let mut ph = self.stretch(user, seal.salt);
        let mut auth = kdf::tpm_auth(&ph);
        let mut d = [0u8; 32];
        let r = Tpm::new(self.p).unseal(
            sealed.private,
            sealed.public,
            pcrs.mask,
            None,
            &auth,
            &mut d,
        );
        auth.zeroize();
        let out = match r {
            Ok(()) => {
                self.log(format_args!("paguro: rung tpm: unsealed"));
                let env = kdf::env_tpm(&self.st.b, &d);
                d.zeroize();
                let blob = self.blob(blob_buf)?;
                let vmk = derive_vmk(&env, seal.salt, blob, &ph, seal.wrapped_vmk);
                if self.accept(vmk)? {
                    self.clear_tpm_broken();
                    Some(Rung::Tpm)
                } else {
                    None
                }
            }
            Err(e) => {
                self.log(format_args!("paguro: rung tpm failed: {e:?}"));
                match e.class() {
                    RcClass::AuthFail => {
                        self.st.tpm_attempts = self.st.tpm_attempts.map(|a| a.saturating_sub(1));
                    }
                    RcClass::Lockout => self.st.tpm_grey = Some(Grey::Locked),
                    RcClass::PolicyFail => {
                        self.st.tpm_grey = Some(Grey::Unavailable);
                        // Tell Windows so it can stage setupTPM (DESIGN.md §6).
                        if let Err(e) = self.p.set_var(
                            names::VAR_TPM_BROKEN,
                            &PAGURO_VENDOR,
                            attrs::NV_BS_RT,
                            &[1],
                        ) {
                            self.log(format_args!(
                                "paguro: setting PaguroTpmBroken failed: {e:?}"
                            ));
                        }
                    }
                    _ => self.st.tpm_grey = Some(Grey::Unavailable),
                }
                None
            }
        };
        ph.zeroize();
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // Stage 4 helpers

    /// On a bootstrap boot, author the configuration, seal a fresh `D` against
    /// the PCR 12 it will produce, and forward both. Failures only mean no
    /// seal this boot (the next boot falls back to setupTPM or recovery).
    fn provision(
        &mut self,
        part: &Partition,
        located: &Located,
        gen_ini: &mut [u8],
        blob_buf: &mut [u8],
        created: &mut tpm::CreatedObject,
        prov: &mut Provision,
    ) -> Option<usize> {
        // The volume is the bootstrap payload's (select_volume found it by
        // that GUID), so the authored entry names the volume the seals are for.
        let mut entries = [Entry::EMPTY; MAX_ENTRIES];
        let slot = entries.first_mut()?;
        let root = located.root_path();
        let efi = match (located.efi_file_path(), located.efi_disk_path()) {
            (Some(f), _) => Efi::File(f),
            (None, disk) => Efi::Disk {
                disk: disk.unwrap_or(""),
                path: config::DEFAULT_EFI,
            },
        };
        *slot = Entry {
            name: located.name(),
            volume: part.guid,
            root,
            efi,
        };
        let cfg = Config {
            default: 0,
            entries,
            entry_count: 1,
            tpm: true,
            setup_tpm: true,
            passphrase: false,
            ui: config::Ui::DEFAULT,
        };
        let n = match config::write(&cfg, gen_ini) {
            Ok(n) => n,
            Err(e) => {
                self.log(format_args!(
                    "paguro: provisioning: config not authored: {e:?}"
                ));
                return None;
            }
        };
        if !self.st.tpm || !self.st.pcr12_was_zero {
            self.log(format_args!(
                "paguro: provisioning: no TPM seal (TPM absent or PCR 12 dirty)"
            ));
            return Some(n);
        }
        let (Some(user), Some(vmk)) = (self.st.user_hash, self.st.vmk) else {
            return Some(n);
        };
        let pcr12 = tpm::pcr12_after_load_taint(gen_ini.get(..n).unwrap_or(&[]));
        let [p0, p2, p4, p7] = self.st.pcrs;
        let policy = tpm::policy_digest(seal::PCR_MASK_V1, &[p0, p2, p4, p7, pcr12], None);
        let mut rnd = [0u8; 48];
        if self.p.random(&mut rnd).is_err() {
            self.log(format_args!("paguro: provisioning: RNG failed"));
            return Some(n);
        }
        let mut d = [0u8; 32];
        d.copy_from_slice(rnd.get(..32).unwrap_or(&[0; 32]));
        prov.salt
            .copy_from_slice(rnd.get(32..48).unwrap_or(&[0; 16]));
        rnd.zeroize();
        let mut ph = self.stretch(&user, &prov.salt);
        let mut auth = kdf::tpm_auth(&ph);
        let r = Tpm::new(self.p).create_sealed(&auth, &d, &policy, created);
        auth.zeroize();
        let res = match (r, self.blob(blob_buf)) {
            (Ok(()), Ok(blob)) => {
                let env = kdf::env_tpm(&self.st.b, &d);
                let mut rg = kdf::root_gate(&env, &prov.salt, blob);
                let mut key = kdf::final_key(&rg, &ph);
                prov.wrapped = kdf::xor32(&key, &vmk);
                rg.zeroize();
                key.zeroize();
                prov.ok = true;
                self.log(format_args!(
                    "paguro: provisioning: sealed for pcr12={}",
                    Hex(&pcr12)
                ));
                Some(n)
            }
            (Err(e), _) => {
                self.log(format_args!(
                    "paguro: provisioning: TPM2_Create failed: {e:?}"
                ));
                Some(n)
            }
            (_, Err(e)) => {
                self.log(format_args!("paguro: provisioning: {e:?}"));
                Some(n)
            }
        };
        d.zeroize();
        ph.zeroize();
        res
    }

    #[allow(clippy::too_many_arguments)]
    fn build_handoff(
        &mut self,
        part: &Partition,
        rung: Rung,
        located: &Located,
        config_bytes: Option<&[u8]>,
        created: &tpm::CreatedObject,
        prov: &Provision,
        out: &mut [u8],
    ) -> Result<usize, BootError> {
        let per = u64::from(part.block_size / 512);
        let name = located.name();
        let id = |f: volume::FileId| ImageId {
            name,
            mft_record: f.mft_record,
            mft_seq: f.mft_seq,
        };
        let root = located.root.map(id);
        // Only the chosen entry's files, and the UEFI image's file only when
        // it is not the root (INTERFACES.md §8).
        let other = |f: &volume::FileId| root.is_none_or(|r| r.mft_record != f.mft_record);
        let efi_file = located.efi_file.filter(other).map(id);
        let efi_disk = located
            .efi_disk
            .filter(|_| root.is_some() && located.efi_file.is_none())
            .filter(other)
            .map(id);
        let mut pcrv = [0u8; 128];
        for (dst, src) in pcrv.chunks_exact_mut(32).zip(self.st.pcrs.iter()) {
            dst.copy_from_slice(src);
        }
        let provision = prov.ok.then_some(Seal {
            kind: Kind::Tpm,
            deadline: None,
            pcrs: Some(seal::Pcrs::V1),
            wrapped_vmk: &prov.wrapped,
            salt: &prov.salt,
            sealed: Some(Sealed {
                public: created.public(),
                private: created.private(),
            }),
        });
        let fvek = self
            .v
            .fvek()
            .map(|(cipher, key)| handoff::Fvek { cipher, key });
        let h = Handoff {
            volume: handoff::Volume {
                partition: part.guid,
                first_lba: part.first_lba.saturating_mul(per),
                sectors: part.sectors.saturating_mul(per),
            },
            vmk: self.st.vmk.as_ref(),
            fvek,
            fve_layout: self.v.layout(),
            b: &self.st.b,
            pcrs: Pcrs {
                mask: RECORDED_PCRS,
                values: &pcrv,
            },
            config: config_bytes,
            root,
            efi_disk,
            efi_file,
            state: self.st.flags,
            rung,
            provision,
        };
        handoff::encode(&h, out).map_err(BootError::Handoff)
    }

    // -----------------------------------------------------------------------
    // "Start Windows": BootNext + reset, never a chainload.

    fn start_windows_no_var(&mut self) -> Outcome {
        let mut var = [0u8; bootstrap::MAX_LOAD_OPTION];
        self.start_windows(&mut var)
    }

    fn start_windows(&mut self, var: &mut [u8]) -> Outcome {
        let mut order = [0u8; 256];
        let n = match self
            .p
            .get_var("BootOrder", &EFI_GLOBAL_VARIABLE, &mut order)
        {
            Ok(Some(n)) => n,
            _ => 0,
        };
        let mut target = None;
        for pair in order.get(..n).unwrap_or(&[]).chunks_exact(2) {
            let id = u16::from_le_bytes([
                pair.first().copied().unwrap_or(0),
                pair.get(1).copied().unwrap_or(0),
            ]);
            let name = boot_var_name(id);
            if let Ok(Some(len)) = self.p.get_var(ascii(&name), &EFI_GLOBAL_VARIABLE, var) {
                if let Ok(lo) = bootstrap::parse_load_option(var.get(..len).unwrap_or(&[])) {
                    if lo.is_windows_boot_manager() {
                        target = Some(id);
                        break;
                    }
                }
            }
        }
        let Some(id) = target else {
            self.log(format_args!("paguro: no Windows Boot Manager entry"));
            return Outcome::Halted(BootError::NoWindowsEntry);
        };
        if let Err(e) = self.p.set_var(
            "BootNext",
            &EFI_GLOBAL_VARIABLE,
            attrs::NV_BS_RT,
            &id.to_le_bytes(),
        ) {
            self.log(format_args!("paguro: setting BootNext failed: {e:?}"));
            return Outcome::Halted(BootError::Platform(e));
        }
        self.log(format_args!(
            "paguro: BootNext={} (Windows), resetting",
            ascii(&boot_var_name(id))
        ));
        self.p.reset();
        Outcome::StartWindows
    }
}

/// Longest path recovery builds or accepts (`Buffers::path`), as
/// `paguro.ini` allows (INTERFACES.md §3.2).
pub const PATH_MAX: usize = config::MAX_PATH_BYTES;
const PAGURO_DIR: &str = "\\paguro";

/// An absolute backslash path in fixed memory, always valid by
/// [`config::check_path`] (or empty, or the root `\`).
#[derive(Clone, Copy)]
struct PathText {
    b: [u8; PATH_MAX],
    n: usize,
}

impl PathText {
    const fn new() -> Self {
        PathText {
            b: [0; PATH_MAX],
            n: 0,
        }
    }
    fn clear(&mut self) {
        self.n = 0;
    }
    fn as_str(&self) -> &str {
        core::str::from_utf8(self.b.get(..self.n).unwrap_or(&[])).unwrap_or("")
    }
    fn get(&self) -> Option<&str> {
        (self.n != 0).then(|| self.as_str())
    }
    /// Replace with `s`; `false` (unchanged) when it does not fit.
    fn set(&mut self, s: &str) -> bool {
        match self.b.get_mut(..s.len()) {
            Some(d) => {
                d.copy_from_slice(s.as_bytes());
                self.n = s.len();
                true
            }
            None => false,
        }
    }
    /// `dir\name`, checked; `false` (unchanged) when the result is not a
    /// usable path (too long, too deep, a forbidden character).
    fn join(&mut self, dir: &str, name: &str) -> bool {
        let mut t = PathText::new();
        let dir = dir.trim_end_matches('\\');
        let parts = [dir, "\\", name];
        let mut n = 0usize;
        for p in parts {
            let Some(d) = t.b.get_mut(n..n + p.len()) else {
                return false;
            };
            d.copy_from_slice(p.as_bytes());
            n += p.len();
        }
        t.n = n;
        if config::check_path(t.as_str()).is_err() {
            return false;
        }
        *self = t;
        true
    }
    /// Append a component.
    fn push(&mut self, name: &str) -> bool {
        let cur = *self;
        self.join(cur.as_str(), name)
    }
    /// Drop the last component; `false` at the root.
    fn pop(&mut self) -> bool {
        let s = self.as_str();
        match s.rfind('\\') {
            Some(0) if s.len() > 1 => {
                self.n = 1;
                true
            }
            Some(i) if i > 0 => {
                self.n = i;
                true
            }
            _ => false,
        }
    }
}

/// What recovery chose on screen, as paths: the disk or `efi_file` on the
/// volume, the UEFI image on the disk's EFI partition (empty: the default),
/// and the root hint (empty: none).
struct Chosen {
    efi: PathText,
    kind: EntryKind,
    fat: PathText,
    root: PathText,
    name: [u8; 32],
}

impl Chosen {
    const fn new() -> Self {
        Chosen {
            efi: PathText::new(),
            kind: EntryKind::Disk,
            fat: PathText::new(),
            root: PathText::new(),
            name: [0; 32],
        }
    }

    fn root_is_efi(&mut self) {
        self.root = self.efi;
    }

    fn efi_name(&self) -> &str {
        let p = self.efi.as_str();
        p.rsplit('\\').next().unwrap_or(p)
    }

    fn entry(&mut self, volume: Guid) -> Entry<'_> {
        let mut name = [0u8; 32];
        let n = ui::entry_name(self.efi.as_str(), &mut name, "recovery").len();
        self.name = name;
        Entry {
            name: core::str::from_utf8(self.name.get(..n).unwrap_or(&[])).unwrap_or("recovery"),
            volume,
            root: self.root.get(),
            efi: match self.kind {
                EntryKind::Efi => Efi::File(self.efi.as_str()),
                _ => Efi::Disk {
                    disk: self.efi.as_str(),
                    path: self.fat.get().unwrap_or(config::DEFAULT_EFI),
                },
            },
        }
    }
}

/// The provisioning outputs that outlive [`Machine::provision`].
struct Provision {
    ok: bool,
    salt: [u8; 16],
    wrapped: [u8; 32],
}

impl Provision {
    const fn new() -> Self {
        Provision {
            ok: false,
            salt: [0; 16],
            wrapped: [0; 32],
        }
    }
}

impl Drop for Provision {
    fn drop(&mut self) {
        self.wrapped.zeroize();
    }
}

/// `PlatformError` is also what the volume layer reports for disk failures.
impl From<PlatformError> for BootError {
    fn from(e: PlatformError) -> Self {
        BootError::Platform(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_var_names() {
        assert_eq!(&boot_var_name(0x0001), b"Boot0001");
        assert_eq!(&boot_var_name(0xBEEF), b"BootBEEF");
        assert_eq!(&boot_var_name(0x0a10), b"Boot0A10");
    }

    #[test]
    fn derive_is_an_involution_of_the_wrap() {
        let vmk = [7u8; 32];
        let (env, salt, ph) = ([1u8; 32], [2u8; 16], [3u8; 32]);
        let key = kdf::final_key(&kdf::root_gate(&env, &salt, b"blob"), &ph);
        let wrapped = kdf::xor32(&key, &vmk);
        assert_eq!(derive_vmk(&env, &salt, b"blob", &ph, &wrapped), vmk);
        assert_ne!(derive_vmk(&env, &salt, b"blob2", &ph, &wrapped), vmk);
    }
}
