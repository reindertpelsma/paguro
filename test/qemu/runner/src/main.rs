//! QEMU boot tests for `paguro.efi`: OVMF (with and without Secure Boot),
//! swtpm as TPM 2.0, an ESP built with mtools, a GPT data disk built with
//! sgdisk. Assertions are on the loader's own serial-log markers.
//!
//! ```text
//! paguro-qemu --efi paguro.efi [--efi-signed paguro.signed.efi]
//!             [--ovmf /usr/share/OVMF] [--work DIR] [--accel auto|kvm|tcg]
//!             [SCENARIO...]
//! ```
//!
//! Scenarios needing a signed loader are skipped without `--efi-signed`.
//! KVM is used when `/dev/kvm` is usable, TCG otherwise.
#![allow(clippy::indexing_slicing)]

mod stage4;
mod vars;

use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::tpm::{CreatedObject, Tpm, pcr12_after_load_taint, policy_digest};
use paguro_core::guid::{Guid, PAGURO_VENDOR};
use paguro_core::seal::{self, Kind, Seal, Sealed};
use paguro_crypto as kdf;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type R<T> = Result<T, String>;

const PIN: &str = "correct horse";
const VOLUME: &str = "6c0a1b2c-3d4e-4f60-8182-93a4b5c6d7e8";
const RECOVERY_PW: &str = "000011-000022-000033-000044-000055-000066-000077-720885";

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if s.len() != 64 {
        return None;
    }
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

fn boot_taint() -> [u8; 32] {
    sha256(&[paguro_boot::names::BOOT_TAINT])
}

/// PCR 12 after the recovery cap (and after `n` caps in one boot).
fn capped(n: usize) -> [u8; 32] {
    let mut v = [0u8; 32];
    for _ in 0..n {
        v = sha256(&[&v, &boot_taint()]);
    }
    v
}

fn sh(cmd: &mut Command) -> R<()> {
    let out = cmd.output().map_err(|e| format!("{cmd:?}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{cmd:?} failed: {}\n{}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

#[derive(Clone)]
struct Env {
    efi: PathBuf,
    efi_signed: Option<PathBuf>,
    /// `probe.efi` (test/uefi-probe), unsigned and snakeoil-signed.
    probe: Option<PathBuf>,
    probe_signed: Option<PathBuf>,
    /// The aarch64 loader and probe, and AAVMF.
    efi_aa64: Option<PathBuf>,
    probe_aa64: Option<PathBuf>,
    aavmf: PathBuf,
    ovmf: PathBuf,
    work: PathBuf,
    kvm: bool,
}

// ---------------------------------------------------------------------------
// Images

/// Where the volume's `tpm_seal.bin` lives under `\EFI\paguro\`.
fn tpm_seal_path() -> String {
    format!("{VOLUME}/tpm_seal.bin")
}

fn ini_text() -> Vec<u8> {
    format!(
        "# paguro configuration. Not hand-editable: use `paguro config`.\n[Paguro]\nversion = 1\ndefault = debian\n\n[Boot.debian]\nvolume = {VOLUME}\nroot = \\paguro\\debian.vhd\n"
    )
    .into_bytes()
}

/// A FAT ESP holding the loader as the removable-media default and the given
/// `\EFI\paguro\` files (`/` in a name makes a subdirectory).
fn make_esp(env: &Env, name: &str, efi: &Path, files: &[(&str, &[u8])]) -> R<PathBuf> {
    let dir = env.work.join(format!("{name}-esp"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("EFI/BOOT")).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(dir.join("EFI/paguro")).map_err(|e| e.to_string())?;
    std::fs::copy(efi, dir.join("EFI/BOOT/BOOTX64.EFI")).map_err(|e| e.to_string())?;
    for (f, data) in files {
        let path = dir.join("EFI/paguro").join(f);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, data).map_err(|e| e.to_string())?;
    }
    // Scenarios that let the loader return expect the firmware to run it again
    // in the same boot. Newer OVMF (Ubuntu 26.04) does that through its
    // default platform-recovery option; older builds (Ubuntu 24.04, the CI
    // runner) boot the built-in UEFI Shell first, which runs this script.
    std::fs::write(
        dir.join("startup.nsh"),
        "FS0:\r\n\\EFI\\BOOT\\BOOTX64.EFI\r\n",
    )
    .map_err(|e| e.to_string())?;
    let img = env.work.join(format!("{name}-esp.img"));
    let _ = std::fs::remove_file(&img);
    sh(Command::new("mkfs.vfat")
        .arg("-C")
        .arg(&img)
        .arg("32768")
        .stdout(Stdio::null()))?;
    sh(Command::new("mcopy")
        .arg("-i")
        .arg(&img)
        .arg("-s")
        .arg(dir.join("EFI"))
        .arg(dir.join("startup.nsh"))
        .arg("::/"))?;
    Ok(img)
}

/// A 64 MiB GPT disk (written by sgdisk, so the loader's GPT parser meets a
/// third-party writer) with one basic-data partition whose first sector
/// carries the BitLocker signature.
/// The data disk: a GPT partition (`VOLUME`) holding a real BitLocker
/// volume — an empty NTFS encrypted by `test/fixtures/bde/make.sh` with
/// `RECOVERY_PW` as its recovery password. Built once per run.
fn make_data_disk(env: &Env) -> R<PathBuf> {
    let img = env.work.join("data.img");
    let bde = env.work.join("data-bde.img");
    if !bde.exists() {
        let ntfs = env.work.join("data-ntfs.img");
        let f = std::fs::File::create(&ntfs).map_err(|e| e.to_string())?;
        f.set_len(32 << 20).map_err(|e| e.to_string())?;
        drop(f);
        sh(Command::new("mkntfs")
            .args(["-F", "-f", "-q", "-L", "data"])
            .arg(&ntfs)
            .stdout(Stdio::null()))?;
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..");
        let mut c = Command::new(root.join("test/fixtures/bde/make.sh"));
        c.arg(&ntfs)
            .arg(&bde)
            .args(["--recovery", RECOVERY_PW, "--seed", "40", "--no-verify"]);
        let w = root.join("target/release/paguro-bde-write");
        if w.exists() {
            c.env("PAGURO_BDE_WRITE", w);
        }
        sh(c.stdout(Stdio::null()))?;
        let _ = std::fs::remove_file(&ntfs);
    }
    let _ = std::fs::remove_file(&img);
    let f = std::fs::File::create(&img).map_err(|e| e.to_string())?;
    f.set_len(64 << 20).map_err(|e| e.to_string())?;
    drop(f);
    sh(Command::new("sgdisk")
        .args(["-n", "1:2048:+32M", "-t", "1:0700", "-u"])
        .arg(format!("1:{VOLUME}"))
        .arg(&img)
        .stdout(Stdio::null()))?;
    let mut data = std::fs::read(&img).map_err(|e| e.to_string())?;
    let vol = std::fs::read(&bde).map_err(|e| e.to_string())?;
    let at = 2048 * 512;
    data[at..at + vol.len()].copy_from_slice(&vol);
    std::fs::write(&img, data).map_err(|e| e.to_string())?;
    Ok(img)
}

// ---------------------------------------------------------------------------
// swtpm

struct Swtpm {
    child: Child,
    sock: PathBuf,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_for(path: &Path) -> R<()> {
    let t0 = Instant::now();
    while !path.exists() {
        if t0.elapsed() > Duration::from_secs(10) {
            return Err(format!("{} never appeared", path.display()));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(())
}

/// swtpm as QEMU's TPM (the firmware sends TPM2_Startup).
fn swtpm_for_qemu(state: &Path) -> R<Swtpm> {
    std::fs::create_dir_all(state).map_err(|e| e.to_string())?;
    let sock = state.join("qemu.sock");
    let _ = std::fs::remove_file(&sock);
    let child = Command::new("swtpm")
        .args(["socket", "--tpm2"])
        .arg("--tpmstate")
        .arg(format!("dir={}", state.display()))
        .arg("--ctrl")
        .arg(format!("type=unixio,path={}", sock.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("swtpm: {e}"))?;
    wait_for(&sock)?;
    Ok(Swtpm { child, sock })
}

/// swtpm on the same state, spoken to directly (to make seals the way the
/// Windows tool or a previous boot would).
struct ToolTpm {
    _swtpm: Swtpm,
    stream: UnixStream,
    rng: u64,
}

fn swtpm_for_tool(state: &Path) -> R<ToolTpm> {
    let sock = state.join("tool.sock");
    let ctrl = state.join("tool-ctrl.sock");
    let _ = std::fs::remove_file(&sock);
    let _ = std::fs::remove_file(&ctrl);
    let child = Command::new("swtpm")
        .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
        .arg("--tpmstate")
        .arg(format!("dir={}", state.display()))
        .arg("--server")
        .arg(format!("type=unixio,path={}", sock.display()))
        .arg("--ctrl")
        .arg(format!("type=unixio,path={}", ctrl.display()))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("swtpm: {e}"))?;
    let sw = Swtpm {
        child,
        sock: sock.clone(),
    };
    wait_for(&sock)?;
    let stream = UnixStream::connect(&sock).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    Ok(ToolTpm {
        _swtpm: sw,
        stream,
        rng: 0x9e37_79b9,
    })
}

impl Platform for ToolTpm {
    fn read_esp_file(&mut self, _: &str, _: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        Ok(None)
    }
    fn get_var(&mut self, _: &str, _: &Guid, _: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        Ok(None)
    }
    fn set_var(&mut self, _: &str, _: &Guid, _: u32, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn delete_var(&mut self, _: &str, _: &Guid) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn secure_boot(&mut self) -> bool {
        false
    }
    fn tpm_present(&mut self) -> bool {
        true
    }
    fn hash_log_extend(&mut self, _: u32, _: &[u8], _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        self.stream
            .write_all(cmd)
            .map_err(|_| PlatformError::Device(1))?;
        let mut hdr = [0u8; 10];
        self.stream
            .read_exact(&mut hdr)
            .map_err(|_| PlatformError::Device(2))?;
        let n = u32::from_be_bytes([hdr[2], hdr[3], hdr[4], hdr[5]]) as usize;
        if n < 10 || n > resp.len() {
            return Err(PlatformError::TooLarge);
        }
        resp[..10].copy_from_slice(&hdr);
        self.stream
            .read_exact(&mut resp[10..n])
            .map_err(|_| PlatformError::Device(3))?;
        Ok(n)
    }
    fn disk_count(&mut self) -> usize {
        0
    }
    fn disk_info(&mut self, _: usize) -> Option<DiskInfo> {
        None
    }
    fn read_blocks(&mut self, _: usize, _: u64, _: &mut [u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn random(&mut self, buf: &mut [u8]) -> Result<(), PlatformError> {
        for b in buf.iter_mut() {
            self.rng ^= self.rng << 13;
            self.rng ^= self.rng >> 7;
            self.rng ^= self.rng << 17;
            *b = self.rng as u8;
        }
        Ok(())
    }
    fn prompt(&mut self, _: &Screen, _: &mut [u8]) -> Input {
        Input::Escape
    }
    fn log(&mut self, _: std::fmt::Arguments<'_>) {}
    fn publish_handoff(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn load_start_image(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn reset(&mut self) {}
}

/// `tpm_seal.bin` sealed to the PCR 0/2/4/7 values a previous boot logged and
/// to the PCR 12 the given configuration's load taint produces.
fn make_tpm_seal(state: &Path, pcrs: &[[u8; 32]; 4], ini: &[u8]) -> R<Vec<u8>> {
    let salt = [0x5a; 16];
    let ph = kdf::bitlocker_stretch(
        &kdf::user_password_hash(PIN),
        &salt,
        kdf::STRETCH_ITERATIONS,
    );
    let auth = kdf::tpm_auth(&ph);
    let pcr12 = pcr12_after_load_taint(ini);
    let policy = policy_digest(
        seal::PCR_MASK_V1,
        &[pcrs[0], pcrs[1], pcrs[2], pcrs[3], pcr12],
        None,
    );
    let mut t = swtpm_for_tool(state)?;
    let mut obj = CreatedObject::new();
    Tpm::new(&mut t)
        .create_sealed(&auth, &[0xdd; 32], &policy, &mut obj)
        .map_err(|e| format!("TPM2_Create: {e:?}"))?;
    let s = Seal {
        kind: Kind::Tpm,
        deadline: None,
        pcrs: Some(seal::Pcrs::V1),
        wrapped_vmk: &[0x11; 32],
        salt: &salt,
        sealed: Some(Sealed {
            public: obj.public(),
            private: obj.private(),
        }),
    };
    let mut buf = vec![0u8; seal::MAX_FILE];
    let n = seal::write(&s, &mut buf).map_err(|_| "seal too large".to_string())?;
    buf.truncate(n);
    Ok(buf)
}

// ---------------------------------------------------------------------------
// QEMU

struct Vm {
    child: Child,
    stdin: ChildStdin,
    out: Arc<Mutex<String>>,
    cursor: usize,
    log_path: PathBuf,
    _tpm: Option<Swtpm>,
}

/// Strip ANSI escape sequences and carriage returns from the serial stream.
fn clean(raw: &[u8], esc: &mut bool, out: &mut String) {
    for &b in raw {
        if *esc {
            if b.is_ascii_alphabetic() {
                *esc = false;
            }
            continue;
        }
        match b {
            0x1b => *esc = true,
            b'\r' => {}
            b if b == b'\n' || b == b'\t' || (0x20..0x7f).contains(&b) => out.push(b as char),
            _ => {}
        }
    }
}

impl Vm {
    fn start(
        env: &Env,
        name: &str,
        secure: bool,
        esp: &Path,
        data: &Path,
        vars: &Path,
        state: &Path,
    ) -> R<Vm> {
        Self::start_with(env, name, secure, esp, data, vars, state, None)
    }

    /// Boot OVMF with these disks (the first holds the loader's ESP).
    fn start_disks(
        env: &Env,
        name: &str,
        secure: bool,
        disks: &[&Path],
        vars: &Path,
        state: &Path,
    ) -> R<Vm> {
        Self::launch(env, name, secure, disks, vars, state, None)
    }

    /// As [`Vm::start`], with a QMP socket at `qmp` (for screendumps).
    #[allow(clippy::too_many_arguments)]
    fn start_with(
        env: &Env,
        name: &str,
        secure: bool,
        esp: &Path,
        data: &Path,
        vars: &Path,
        state: &Path,
        qmp: Option<&Path>,
    ) -> R<Vm> {
        Self::launch(env, name, secure, &[esp, data], vars, state, qmp)
    }

    #[allow(clippy::too_many_arguments)]
    fn launch(
        env: &Env,
        name: &str,
        secure: bool,
        disks: &[&Path],
        vars: &Path,
        state: &Path,
        qmp: Option<&Path>,
    ) -> R<Vm> {
        let tpm = swtpm_for_qemu(state)?;
        let code = env.ovmf.join(if secure {
            "OVMF_CODE_4M.secboot.fd"
        } else {
            "OVMF_CODE_4M.fd"
        });
        let mut cmd = Command::new("qemu-system-x86_64");
        cmd.arg("-machine")
            .arg(format!(
                "q35,accel={}{}",
                if env.kvm { "kvm" } else { "tcg" },
                if secure { ",smm=on" } else { "" }
            ))
            .args([
                "-m", "512", "-display", "none", "-serial", "stdio", "-monitor", "none",
            ])
            .args(["-no-reboot", "-net", "none"]);
        if let Some(q) = qmp {
            let _ = std::fs::remove_file(q);
            cmd.arg("-qmp")
                .arg(format!("unix:{},server=on,wait=off", q.display()));
        }
        if secure {
            cmd.args(["-global", "driver=cfi.pflash01,property=secure,value=on"]);
        }
        cmd.arg("-drive")
            .arg(format!(
                "if=pflash,format=raw,readonly=on,file={}",
                code.display()
            ))
            .arg("-drive")
            .arg(format!("if=pflash,format=raw,file={}", vars.display()));
        for d in disks {
            // snapshot: the guest can never change the images (the loader
            // must not write anyway; this keeps a shared image pristine).
            cmd.arg("-drive").arg(format!(
                "format=raw,file={},if=virtio,snapshot=on",
                d.display()
            ));
        }
        cmd.args(["-device", "virtio-rng-pci"])
            .arg("-chardev")
            .arg(format!("socket,id=chrtpm,path={}", tpm.sock.display()))
            .args([
                "-tpmdev",
                "emulator,id=tpm0,chardev=chrtpm",
                "-device",
                "tpm-tis,tpmdev=tpm0",
            ]);
        Self::spawn(cmd, env.work.join(format!("{name}.serial.log")), Some(tpm))
    }

    /// Start `cmd` (a QEMU with `-serial stdio`) and collect its serial log.
    fn spawn(mut cmd: Command, log_path: PathBuf, tpm: Option<Swtpm>) -> R<Vm> {
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|e| format!("qemu: {e}"))?;
        let stdin = child.stdin.take().ok_or("no stdin")?;
        let mut stdout = child.stdout.take().ok_or("no stdout")?;
        let mut stderr = child.stderr.take().ok_or("no stderr")?;
        let out = Arc::new(Mutex::new(String::new()));
        let sink = out.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut esc = false;
            while let Ok(n) = stdout.read(&mut buf) {
                if n == 0 {
                    break;
                }
                let mut s = String::new();
                clean(&buf[..n], &mut esc, &mut s);
                if let Ok(mut o) = sink.lock() {
                    o.push_str(&s);
                }
            }
        });
        let errsink = out.clone();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = stderr.read_to_string(&mut s);
            if !s.is_empty() {
                if let Ok(mut o) = errsink.lock() {
                    o.push_str("\n[qemu stderr] ");
                    o.push_str(&s);
                }
            }
        });
        Ok(Vm {
            child,
            stdin,
            out,
            cursor: 0,
            log_path,
            _tpm: tpm,
        })
    }

    fn text(&self) -> String {
        self.out.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// Wait for `needle` after the cursor; move the cursor past it.
    fn expect(&mut self, needle: &str, secs: u64) -> R<()> {
        let t0 = Instant::now();
        loop {
            let t = self.text();
            if let Some(i) = t.get(self.cursor..).and_then(|s| s.find(needle)) {
                self.cursor += i + needle.len();
                return Ok(());
            }
            if t.is_empty() && t0.elapsed() > Duration::from_secs(30) {
                return Err("firmware silent for 30 s (no console output at all)".into());
            }
            if t0.elapsed() > Duration::from_secs(secs) {
                let tail: String = t
                    .chars()
                    .rev()
                    .take(1500)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                return Err(format!(
                    "timed out waiting for {needle:?}; serial tail:\n{tail}"
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Text between the cursor and the next `until` (cursor moves past it).
    fn section(&mut self, until: &str, secs: u64) -> R<String> {
        let start = self.cursor;
        self.expect(until, secs)?;
        Ok(self.text()[start..self.cursor].to_string())
    }

    /// Capture the rest of the line after `prefix`.
    fn capture(&mut self, prefix: &str, secs: u64) -> R<String> {
        self.expect(prefix, secs)?;
        self.expect("\n", 5)?;
        let t = self.text();
        let seg = &t[..self.cursor - 1];
        let start = seg
            .rfind(prefix)
            .map(|i| i + prefix.len())
            .unwrap_or(self.cursor);
        Ok(seg[start..].to_string())
    }

    fn send(&mut self, s: &str) -> R<()> {
        for b in s.bytes() {
            self.stdin.write_all(&[b]).map_err(|e| e.to_string())?;
            self.stdin.flush().map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(30));
        }
        Ok(())
    }

    fn stop(mut self) -> String {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let t = self.text();
        let _ = std::fs::write(&self.log_path, &t);
        t
    }
}

// ---------------------------------------------------------------------------
// Scenarios

/// A fresh per-scenario directory: VARS copy, swtpm state.
fn fresh(env: &Env, name: &str, vars_template: &str) -> R<(PathBuf, PathBuf)> {
    let vars = env.work.join(format!("{name}-vars.fd"));
    std::fs::copy(env.ovmf.join(vars_template), &vars).map_err(|e| e.to_string())?;
    // swtpm state and sockets live under the system temp dir: distribution
    // AppArmor profiles for swtpm only allow a few locations (e.g. /tmp).
    let state = std::env::temp_dir()
        .join(format!("paguro-qemu-{}", std::process::id()))
        .join(format!("{name}-tpm"));
    let _ = std::fs::remove_dir_all(&state);
    std::fs::create_dir_all(&state).map_err(|e| e.to_string())?;
    Ok((vars, state))
}

const BOOT_WAIT: u64 = 120;
const STRETCH_WAIT: u64 = 300;

/// No configuration: recovery caps PCR 12 first; `B` is created once and
/// persists in real NVRAM; the loader's GPT walk finds the sgdisk partition.
fn recovery_no_config(env: &Env) -> R<()> {
    let name = "recovery-no-config";
    let (vars, state) = fresh(env, name, "OVMF_VARS_4M.fd")?;
    let esp = make_esp(env, name, &env.efi, &[])?;
    let data = make_data_disk(env)?;
    let mut vm = Vm::start(env, name, false, &esp, &data, &vars, &state)?;
    let r = (|| {
        vm.expect("paguro 0.0.0", BOOT_WAIT)?;
        vm.expect("stage1 no-config", 10)?;
        vm.expect("recovery (NoConfig)", 10)?;
        vm.expect(&format!("pcr12={} (recovery)", hex(&capped(1))), 10)?;
        vm.expect("created B", 10)?;
        vm.expect("pcrs 0=", 10)?;
        vm.expect(&format!("volume {VOLUME} (BitLocker)"), 10)?;
        vm.expect("Unlock Linux", 10)?;
        vm.expect("unattested", 5)?;
        vm.expect("[x] TPM unavailable until restart -- recovery mode", 5)?;
        vm.send("3")?;
        vm.expect("Recovery key (48 digits", 10)?;
        vm.send(RECOVERY_PW)?;
        vm.send("\r")?;
        // The data disk is a real BitLocker volume (make.sh): the recovery
        // password opens it, stage 4 mounts the (empty) NTFS, and recovery
        // offers its browser. Leaving it ends this run of the loader.
        vm.expect("stage3 rung=RecoveryKey", STRETCH_WAIT)?;
        vm.expect("stage4 ntfs mounted", 60)?;
        vm.expect("Choose what to start", 30)?;
        vm.send("\x1b")?;
        // The firmware tries the next boot option: the loader runs again in
        // the same boot. B now exists in NVRAM; PCR 12 is capped twice.
        vm.expect("stage machine start", BOOT_WAIT)?;
        let second = vm.section(&format!("pcr12={} (recovery)", hex(&capped(2))), 20)?;
        let rest = vm.section("Unlock Linux", 20)?;
        if second.contains("created B") || rest.contains("created B") {
            return Err("B was not persisted across loader runs".into());
        }
        Ok(())
    })();
    vm.stop();
    r
}

/// Secure Boot off: no hash check, the configuration is parsed, the load taint
/// lands, and a real TPM2 policy session unseals `tpm_seal.bin` after a wrong
/// PIN is refused. The loader then runs a second time in the same boot and
/// refuses because PCR 12 is no longer zero.
fn load_taint_and_unseal(env: &Env) -> R<()> {
    let name = "load-taint-unseal";
    let (vars, state) = fresh(env, name, "OVMF_VARS_4M.fd")?;
    let ini = ini_text();
    let data = make_data_disk(env)?;

    // Phase 1: learn PCR 0/2/4/7 as this firmware leaves them (as the
    // Windows pre-flight would from the event log).
    let esp = make_esp(
        env,
        &format!("{name}-probe"),
        &env.efi,
        &[("paguro.ini", &ini)],
    )?;
    let mut vm = Vm::start(
        env,
        &format!("{name}-probe"),
        false,
        &esp,
        &data,
        &vars,
        &state,
    )?;
    let pcrs = (|| {
        vm.expect("stage1 skipped (secure boot off)", BOOT_WAIT)?;
        vm.expect("stage2 ok (1 entries, default debian)", 10)?;
        vm.expect(&format!("pcr12={} (no tpm_seal.bin)", hex(&capped(1))), 10)?;
        let line = vm.capture("pcrs ", 10)?;
        let mut v = [[0u8; 32]; 4];
        for (i, part) in line.split_whitespace().take(4).enumerate() {
            let hexv = part.split('=').nth(1).ok_or("bad pcrs line")?;
            v[i] = unhex(hexv).ok_or("bad pcr hex")?;
        }
        Ok::<_, String>(v)
    })();
    vm.stop();
    let pcrs = pcrs?;

    // Seal against those values and the load taint of this very file.
    let seal_file = make_tpm_seal(&state, &pcrs, &ini)?;

    // Phase 2: boot with the seal.
    let esp = make_esp(
        env,
        name,
        &env.efi,
        &[("paguro.ini", &ini), (&tpm_seal_path(), &seal_file)],
    )?;
    let mut vm = Vm::start(env, name, false, &esp, &data, &vars, &state)?;
    let r = (|| {
        vm.expect("stage1 skipped (secure boot off)", BOOT_WAIT)?;
        vm.expect("stage2 ok (1 entries, default debian)", 10)?;
        let load = pcr12_after_load_taint(&ini);
        vm.expect(&format!("pcr12={} (load taint)", hex(&load)), 10)?;
        vm.expect(&format!("volume {VOLUME} (BitLocker)"), 10)?;
        vm.expect("Unlock Linux", 10)?;
        vm.expect("TPM attempts left", 5)?;
        vm.send("1")?;
        vm.expect("Password or PIN:", 10)?;
        vm.send("wrong\r")?;
        vm.expect("rung tpm failed: Rc(", STRETCH_WAIT)?;
        vm.expect("That did not unlock the volume", 10)?;
        vm.expect("Unlock Linux", 10)?;
        vm.send("1")?;
        vm.expect("Password or PIN:", 10)?;
        vm.send(PIN)?;
        vm.send("\r")?;
        vm.expect("rung tpm: unsealed", STRETCH_WAIT)?;
        // The sealed secret is not this volume's: the FVEK's MAC refuses
        // the derived VMK (the only check there is), and the menu returns.
        vm.expect("That did not unlock the volume", STRETCH_WAIT)?;
        vm.expect("Unlock Linux", 10)?;
        vm.send("\x1b")?;
        vm.expect("Cannot unlock Linux", 10)?;
        vm.send("\r")?; // Enter: Start Windows
        vm.expect("no Windows Boot Manager entry", 20)?;
        // Second run in the same boot: PCR 12 is not zero any more.
        vm.expect("stage machine start", BOOT_WAIT)?;
        vm.expect("refusing: PCR 12 not zero before first extend", 20)?;
        vm.send("\r")?; // Enter: Start Windows
        vm.expect("no Windows Boot Manager entry", 20)?;
        Ok(())
    })();
    vm.stop();
    r
}

fn signed(env: &Env) -> Option<&Path> {
    env.efi_signed.as_deref()
}

/// Secure Boot on with snakeoil keys: the unsigned loader does not run.
fn secure_boot_refuses_unsigned(env: &Env) -> R<()> {
    let name = "sb-unsigned";
    let (vars, state) = fresh(env, name, "OVMF_VARS_4M.snakeoil.fd")?;
    let esp = make_esp(env, name, &env.efi, &[])?;
    let data = make_data_disk(env)?;
    let mut vm = Vm::start(env, name, true, &esp, &data, &vars, &state)?;
    let r = vm.expect("No bootable option", BOOT_WAIT);
    let t = vm.stop();
    r?;
    if t.contains("paguro 0.0.0") {
        return Err("unsigned loader ran under Secure Boot".into());
    }
    Ok(())
}

fn secure_boot_case(
    env: &Env,
    name: &str,
    hash: Option<[u8; 32]>,
    script: impl FnOnce(&mut Vm) -> R<()>,
) -> R<()> {
    let Some(efi) = signed(env) else {
        eprintln!("  (skipped: no --efi-signed)");
        return Ok(());
    };
    let (vars, state) = fresh(env, name, "OVMF_VARS_4M.snakeoil.fd")?;
    if let Some(h) = hash {
        vars::inject(&vars, "PaguroConfigHash", &PAGURO_VENDOR, 7, &h)?;
    }
    let ini = ini_text();
    let esp = make_esp(
        env,
        name,
        efi,
        &[
            ("paguro.ini", &ini),
            (&tpm_seal_path(), b"PGRTPM\x00\x01not-a-seal"),
        ],
    )?;
    let data = make_data_disk(env)?;
    let mut vm = Vm::start(env, name, true, &esp, &data, &vars, &state)?;
    let r = (|| {
        vm.expect("paguro 0.0.0", BOOT_WAIT)?;
        script(&mut vm)
    })();
    vm.stop();
    r
}

fn secure_boot_hash_missing(env: &Env) -> R<()> {
    secure_boot_case(env, "sb-hash-missing", None, |vm| {
        vm.expect("stage1 hash variable missing", 10)?;
        vm.expect("recovery (HashMissing)", 10)?;
        vm.expect(&format!("pcr12={} (recovery)", hex(&capped(1))), 10)?;
        vm.expect("Unlock Linux", 20)
    })
}

fn secure_boot_hash_mismatch(env: &Env) -> R<()> {
    secure_boot_case(env, "sb-hash-mismatch", Some([0xee; 32]), |vm| {
        vm.expect("stage1 hash mismatch", 10)?;
        vm.expect("Configuration is not valid", 10)?;
        vm.send("r")?;
        vm.expect("recovery (HashMismatch)", 10)?;
        vm.expect(&format!("pcr12={} (recovery)", hex(&capped(1))), 10)?;
        vm.expect("unattested", 20)
    })
}

fn secure_boot_verified(env: &Env) -> R<()> {
    let ini = ini_text();
    secure_boot_case(env, "sb-verified", Some(sha256(&[&ini])), |vm| {
        vm.expect("stage1 ok (verified)", 10)?;
        vm.expect("stage2 ok (1 entries, default debian)", 10)?;
        // A malformed seal (in the volume's directory) still counts as
        // present for the ratchet.
        vm.expect(
            &format!("pcr12={} (load taint)", hex(&pcr12_after_load_taint(&ini))),
            10,
        )?;
        vm.expect(&format!("{VOLUME}\\tpm_seal.bin refused"), 20)?;
        vm.expect("Unlock Linux", 20)
    })
}

// ---------------------------------------------------------------------------
// The graphical front end

/// One QMP command; returns the reply line (`return` or `error`).
fn qmp(
    stream: &mut UnixStream,
    reader: &mut std::io::BufReader<UnixStream>,
    cmd: &str,
) -> R<String> {
    use std::io::BufRead;
    stream
        .write_all(cmd.as_bytes())
        .map_err(|e| format!("qmp write: {e}"))?;
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .map_err(|e| format!("qmp read: {e}"))?
            == 0
        {
            return Err("qmp closed".into());
        }
        if line.contains("\"return\"") || line.contains("\"error\"") {
            return Ok(line);
        }
    }
}

/// `screendump` to a PPM and read it back as (width, height, RGB).
fn screendump(sock: &Path, out: &Path) -> R<(usize, usize, Vec<u8>)> {
    use std::io::BufRead;
    let mut s = UnixStream::connect(sock).map_err(|e| format!("qmp connect: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let mut r = std::io::BufReader::new(s.try_clone().map_err(|e| e.to_string())?);
    let mut greeting = String::new();
    r.read_line(&mut greeting).map_err(|e| e.to_string())?;
    qmp(&mut s, &mut r, "{\"execute\":\"qmp_capabilities\"}\n")?;
    let _ = std::fs::remove_file(out);
    let reply = qmp(
        &mut s,
        &mut r,
        &format!(
            "{{\"execute\":\"screendump\",\"arguments\":{{\"filename\":\"{}\"}}}}\n",
            out.display()
        ),
    )?;
    if reply.contains("\"error\"") {
        return Err(format!("screendump: {reply}"));
    }
    let data = std::fs::read(out).map_err(|e| format!("{}: {e}", out.display()))?;
    // P6 <w> <h> 255, then RGB.
    let mut fields = Vec::new();
    let mut at = 0usize;
    while fields.len() < 4 {
        while data.get(at).is_some_and(u8::is_ascii_whitespace) {
            at += 1;
        }
        let start = at;
        while data.get(at).is_some_and(|b| !b.is_ascii_whitespace()) {
            at += 1;
        }
        fields.push(String::from_utf8_lossy(&data[start..at]).to_string());
    }
    at += 1;
    let (w, h): (usize, usize) = (
        fields[1].parse().map_err(|_| "ppm width")?,
        fields[2].parse().map_err(|_| "ppm height")?,
    );
    if fields[0] != "P6" || fields[3] != "255" || data.len() < at + w * h * 3 {
        return Err(format!("not a P6 PPM: {fields:?}"));
    }
    Ok((w, h, data[at..at + w * h * 3].to_vec()))
}

/// The loader draws the unlock screen through GOP under OVMF. Compared
/// loosely (firmware output is not pixel-stable): the most common colour is
/// the theme's background, the frame's corners are background, and the
/// middle holds text (many pixels of other colours).
fn graphical_unlock(env: &Env) -> R<()> {
    let name = "graphical-unlock";
    let (vars, state) = fresh(env, name, "OVMF_VARS_4M.fd")?;
    let esp = make_esp(env, name, &env.efi, &[])?;
    let data = make_data_disk(env)?;
    let sock = state.join("qmp.sock");
    let mut vm = Vm::start_with(env, name, false, &esp, &data, &vars, &state, Some(&sock))?;
    let r = (|| {
        let line = vm.capture("paguro: graphics ", BOOT_WAIT)?;
        vm.expect("Unlock Linux", 30)?;
        // The frame is presented right after the serial mirror.
        std::thread::sleep(Duration::from_secs(2));
        let (w, h, rgb) = screendump(&sock, &env.work.join(format!("{name}.ppm")))?;
        if !line.starts_with(&format!("{w}x{h}")) {
            return Err(format!("loader reported {line:?}, screen is {w}x{h}"));
        }
        let bg = paguro_ui::builtin::THEMES[0].palette.background;
        let near = |p: &[u8]| {
            p[0].abs_diff(bg.r) <= 4 && p[1].abs_diff(bg.g) <= 4 && p[2].abs_diff(bg.b) <= 4
        };
        let px = |x: usize, y: usize| &rgb[(y * w + x) * 3..(y * w + x) * 3 + 3];
        let mut counts = std::collections::HashMap::new();
        for p in rgb.chunks_exact(3) {
            *counts.entry((p[0], p[1], p[2])).or_insert(0usize) += 1;
        }
        let (dominant, n) = counts
            .iter()
            .max_by_key(|(_, n)| **n)
            .map(|(c, n)| (*c, *n))
            .ok_or("empty frame")?;
        if !near(&[dominant.0, dominant.1, dominant.2]) || n * 2 < w * h {
            return Err(format!(
                "dominant colour {dominant:?} ({n} of {} pixels), theme background {bg:?}",
                w * h
            ));
        }
        for (x, y) in [(1, 1), (w - 2, 1), (1, h - 2), (w - 2, h - 2)] {
            if !near(px(x, y)) {
                return Err(format!("corner ({x},{y}) is {:?}", px(x, y)));
            }
        }
        let mut text = 0usize;
        for y in h / 4..h * 3 / 4 {
            for x in w / 4..w * 3 / 4 {
                if !near(px(x, y)) {
                    text += 1;
                }
            }
        }
        if text < 2000 {
            return Err(format!("only {text} non-background pixels in the middle"));
        }
        println!("  {w}x{h}, background {dominant:?} on {n} pixels, {text} content pixels");
        Ok(())
    })();
    vm.stop();
    r
}

type Scenario = (&'static str, fn(&Env) -> R<()>);

const SCENARIOS: &[Scenario] = &[
    ("recovery-no-config", recovery_no_config),
    ("load-taint-unseal", load_taint_and_unseal),
    ("sb-unsigned", secure_boot_refuses_unsigned),
    ("sb-hash-missing", secure_boot_hash_missing),
    ("sb-hash-mismatch", secure_boot_hash_mismatch),
    ("sb-verified", secure_boot_verified),
    ("graphical-unlock", graphical_unlock),
    ("s4-vhd-gpt", stage4::vhd_gpt),
    (
        "s4-superfloppy-raw-other",
        stage4::vhd_superfloppy_raw_other,
    ),
    ("s4-efi-file", stage4::efi_file),
    ("s4-root-frag", stage4::separate_root_fragmented),
    ("s4-refusals", stage4::refusals),
    ("s4-invalid-pe", stage4::invalid_pe),
    ("s4-secure-boot", stage4::secure_boot),
    ("s4-gates", stage4::gates),
    ("s4-volume-missing", stage4::volume_missing),
    ("s4-recovery-browser", stage4::recovery_browser),
    ("s4-bde-password", stage4::bde_password),
    ("s4-bde-recovery", stage4::bde_recovery),
    ("s4-bde-clear-key", stage4::bde_clear_key),
    ("s4-bde-disagree", stage4::bde_disagree),
    ("s4-aarch64", stage4::aarch64),
];

fn main() {
    let mut args = std::env::args().skip(1);
    let mut efi = None;
    let mut efi_signed = None;
    let mut probe = None;
    let mut probe_signed = None;
    let mut efi_aa64 = None;
    let mut probe_aa64 = None;
    let mut aavmf = PathBuf::from("/usr/share/AAVMF");
    let mut ovmf = PathBuf::from("/usr/share/OVMF");
    let mut work = std::env::temp_dir().join("paguro-qemu");
    let mut accel = "auto".to_string();
    let mut only = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--efi" => efi = args.next().map(PathBuf::from),
            "--efi-signed" => efi_signed = args.next().map(PathBuf::from),
            "--probe" => probe = args.next().map(PathBuf::from),
            "--probe-signed" => probe_signed = args.next().map(PathBuf::from),
            "--efi-aa64" => efi_aa64 = args.next().map(PathBuf::from),
            "--probe-aa64" => probe_aa64 = args.next().map(PathBuf::from),
            "--aavmf" => aavmf = args.next().map(PathBuf::from).unwrap_or(aavmf),
            "--ovmf" => ovmf = args.next().map(PathBuf::from).unwrap_or(ovmf),
            "--work" => work = args.next().map(PathBuf::from).unwrap_or(work),
            "--accel" => accel = args.next().unwrap_or(accel),
            "--list" => {
                for (n, _) in SCENARIOS {
                    println!("{n}");
                }
                return;
            }
            s => only.push(s.to_string()),
        }
    }
    let Some(efi) = efi else {
        eprintln!(
            "usage: paguro-qemu --efi paguro.efi [--efi-signed signed.efi] [--ovmf DIR] [--work DIR] [--accel auto|kvm|tcg] [SCENARIO...]"
        );
        std::process::exit(2);
    };
    let kvm = match accel.as_str() {
        "kvm" => true,
        "tcg" => false,
        _ => std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .is_ok(),
    };
    std::fs::create_dir_all(&work).expect("work dir");
    let env = Env {
        efi,
        efi_signed,
        probe,
        probe_signed,
        efi_aa64,
        probe_aa64,
        aavmf,
        ovmf,
        work,
        kvm,
    };
    println!("accelerator: {}", if kvm { "kvm" } else { "tcg" });
    let mut failed = 0;
    for (name, f) in SCENARIOS {
        // `NAME`, or `PREFIX*` for a group (CI runs `s4-*` as its own job).
        let wanted = |o: &String| match o.strip_suffix('*') {
            Some(p) => name.starts_with(p),
            None => o == name,
        };
        if !only.is_empty() && !only.iter().any(wanted) {
            continue;
        }
        let t0 = Instant::now();
        let mut r = f(&env);
        if let (Err(e), true) = (&r, env.kvm) {
            // OVMF + swtpm under (nested) KVM intermittently stops getting TPM
            // responses, inside the firmware itself (TIS/CRB status polling),
            // whenever a second disk is attached. A failure that also
            // reproduces under TCG is real; one that does not is that flake.
            let first = e.lines().next().unwrap_or("");
            println!("  note: {name} failed under kvm ({first}); retrying under tcg");
            let tcg = Env {
                kvm: false,
                ..env.clone()
            };
            r = f(&tcg);
        }
        match r {
            Ok(()) => println!("PASS {name} ({:.1}s)", t0.elapsed().as_secs_f32()),
            Err(e) => {
                failed += 1;
                println!("FAIL {name}: {e}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(
        std::env::temp_dir().join(format!("paguro-qemu-{}", std::process::id())),
    );
    println!("serial logs: {}", env.work.display());
    if failed > 0 {
        std::process::exit(1);
    }
}
