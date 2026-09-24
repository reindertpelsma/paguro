//! The stage machine. Read top to bottom: [`Machine::go`] is the execution
//! contract of DESIGN.md §4.1, and every branch in it is a mock boot test.

use paguro_core::bootstrap;
use paguro_core::config::{self, Config, Expose, Image, MAX_IMAGES};
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, PAGURO_VENDOR, PCR12_EVENT_TAG};
use paguro_core::handoff::{self, Handoff, ImageId, Pcrs, Rung, state};
use paguro_core::ini;
use paguro_core::seal::{self, Kind, Seal, Sealed};
use paguro_core::tpm::RcClass;
use paguro_crypto as kdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::names;
use crate::platform::{
    Grey, Hex, Input, Notice, Platform, PlatformError, Row, Screen, UnlockMenu, attrs,
};
use crate::tpm::{self, Tpm};
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
        },
    };
    let out = match m.go(bufs) {
        Ok(Step::Go(o) | Step::Done(o)) => o,
        Err(e) => {
            m.p.log(format_args!("paguro: halted: {e:?}"));
            if let BootError::NotImplemented(_) = e {
                m.p.prompt(&Screen::Notice(Notice::NotImplemented), &mut []);
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

        // Seal files: bounded reads; presence of tpm_seal.bin picks the taint.
        let mut seal_len = [None; 4];
        for ((kind, buf), len) in Kind::ALL
            .iter()
            .zip(seals.iter_mut())
            .zip(seal_len.iter_mut())
        {
            *len = match self.p.read_esp_file(kind.file_name(), buf) {
                Ok(n) => n,
                Err(e) => {
                    self.log(format_args!(
                        "paguro: {} unreadable: {e:?}",
                        kind.file_name()
                    ));
                    None
                }
            };
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
                Err(e) => self.log(format_args!("paguro: {} refused: {e:?}", kind.file_name())),
            }
        }

        // 2 — parse, then the ratchet; or recovery / first boot, which cap.
        self.st.tpm = self.p.tpm_present();
        let mut cfg = go!(self.stage2(ini_bytes, tpm_seal_present));

        // 3 — B, S, recorded PCRs, the volume, the rungs.
        self.load_secrets()?;
        let (part, kind) = go!(self.select_volume(cfg.as_ref(), gpt, var));
        if self.st.mode != Mode::Normal {
            cfg = None;
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
        self.v.locate(self.p, cfg.as_ref(), located)?;
        if located.image_count == 0 {
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
        let gen_len = if rung == Rung::Bootstrap {
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
        self.p
            .load_start_image(located.chain())
            .map_err(BootError::Platform)?;
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

    fn stage2<'i>(
        &mut self,
        ini: &'i [u8],
        tpm_seal_present: bool,
    ) -> Result<Step<Option<Config<'i>>>, BootError> {
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
            "paguro: stage2 ok ({} images)",
            cfg.image_count
        ));
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
                        Ok(Step::Go(None))
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
        Ok(Step::Go(Some(cfg)))
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

    fn select_volume(
        &mut self,
        cfg: Option<&Config<'_>>,
        gpt: &mut volume::GptScratch,
        var: &mut [u8],
    ) -> Result<Step<(Partition, VolumeKind)>, BootError> {
        if let (Mode::Normal, Some(c)) = (self.st.mode, cfg) {
            if let Some(part) = volume::find_partition(self.p, gpt, &c.volume)? {
                let kind = volume::probe(self.p, &part, &mut gpt.block)?;
                self.log(format_args!("paguro: volume {} ({kind:?})", part.guid));
                return Ok(Step::Go((part, kind)));
            }
            self.log(format_args!(
                "paguro: configured volume {} not found",
                c.volume
            ));
            match self
                .p
                .prompt(&Screen::Notice(Notice::VolumeMissing), &mut [])
            {
                Input::Recover => self.enter_recovery(RecoveryReason::VolumeMissing)?,
                _ => return Ok(Step::Done(self.start_windows(var))),
            }
        }
        // Recovery and first boot: always enumerate; the configuration cannot
        // steer where to look.
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
            _ => match self.p.prompt(
                &Screen::SelectVolume {
                    count: u8::try_from(n).unwrap_or(u8::MAX),
                },
                &mut [],
            ) {
                Input::Choose(i) if usize::from(i) < n => usize::from(i),
                Input::StartWindows => return Ok(Step::Done(self.start_windows(var))),
                _ => return Err(BootError::NoVolume),
            },
        };
        let (part, kind) = cands
            .get(pick)
            .copied()
            .flatten()
            .ok_or(BootError::NoVolume)?;
        self.log(format_args!("paguro: volume {} ({kind:?})", part.guid));
        Ok(Step::Go((part, kind)))
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
                || self.st.bootstrap.is_some();
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
        let first = located.images.first()?;
        let mut images = [Image::EMPTY; MAX_IMAGES];
        let slot = images.first_mut()?;
        *slot = Image {
            name: first.name(),
            path: located.default_path(),
            format: located.default_format,
            expose: Expose::Block,
            chain: config::DEFAULT_CHAIN,
        };
        let cfg = Config {
            volume: part.guid,
            default: 0,
            images,
            image_count: 1,
            tpm: true,
            setup_tpm: true,
            passphrase: false,
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
        let mut images = [ImageId::EMPTY; handoff::MAX_IMAGES];
        for (dst, src) in images
            .iter_mut()
            .zip(located.images.iter().take(located.image_count))
        {
            *dst = ImageId {
                name: src.name(),
                mft_record: src.mft_record,
                mft_seq: src.mft_seq,
            };
        }
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
            images,
            image_count: located.image_count,
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
