//! The loader's TPM client against a real TPM 2.0 implementation (swtpm), so
//! marshalling, session HMACs and policy digests are checked by something
//! other than code we wrote. Skipped (with a message) when `swtpm` is not
//! installed; CI installs it.
#![allow(clippy::indexing_slicing)]

use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::tpm::{CreatedObject, Tpm, TpmFail, pcr12_after_load_taint, policy_digest};
use paguro_core::guid::Guid;
use paguro_core::seal;
use paguro_core::tpm::{RcClass, cc};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Swtpm {
    child: Child,
    dir: PathBuf,
    sock: UnixStream,
    rng: u64,
    /// Answer the next command with this code `TPM_RC_RETRY` without sending
    /// it, as a TPM does that must first commit DA state to NV.
    retry_once: Option<u32>,
    /// Command codes as submitted by the client, in order.
    submitted: Vec<u32>,
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn start() -> Option<Swtpm> {
    // Check the exit status too: under qemu-user (the arm64 CI job) spawning a
    // missing program "succeeds" and the child exits non-zero instead.
    let present = Command::new("swtpm")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !present {
        eprintln!("swtpm not installed: skipping real-TPM tests");
        return None;
    }
    let dir = std::env::temp_dir().join(format!(
        "paguro-swtpm-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("tpm.sock");
    let child = Command::new("swtpm")
        .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
        .arg("--tpmstate")
        .arg(format!("dir={}", dir.display()))
        .arg("--server")
        .arg(format!("type=unixio,path={}", sock.display()))
        .arg("--ctrl")
        .arg(format!(
            "type=unixio,path={}",
            dir.join("ctrl.sock").display()
        ))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut child = child;
    let t0 = Instant::now();
    loop {
        if let Ok(s) = UnixStream::connect(&sock) {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            return Some(Swtpm {
                child,
                dir,
                sock: s,
                rng: 0,
                retry_once: None,
                submitted: Vec::new(),
            });
        }
        if t0.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("swtpm did not start");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

impl Swtpm {
    fn raw(&mut self, cmd: &[u8]) -> Vec<u8> {
        self.sock.write_all(cmd).unwrap();
        let mut hdr = [0u8; 10];
        self.sock.read_exact(&mut hdr).unwrap();
        let n = u32::from_be_bytes(hdr[2..6].try_into().unwrap()) as usize;
        let mut rest = vec![0u8; n - 10];
        self.sock.read_exact(&mut rest).unwrap();
        [&hdr[..], &rest].concat()
    }

    /// `TPM2_PCR_Extend(pcr, sha256: digest)` with an empty password session.
    fn pcr_extend(&mut self, pcr: u32, digest: &[u8; 32]) {
        let mut c = vec![0x80, 0x02, 0, 0, 0, 0, 0, 0, 0x01, 0x82];
        c.extend(pcr.to_be_bytes());
        c.extend(9u32.to_be_bytes());
        c.extend([0x40, 0, 0, 9, 0, 0, 1, 0, 0]);
        c.extend(1u32.to_be_bytes());
        c.extend(0x000Bu16.to_be_bytes());
        c.extend(digest);
        let n = c.len() as u32;
        c[2..6].copy_from_slice(&n.to_be_bytes());
        let r = self.raw(&c);
        assert_eq!(&r[6..10], &[0, 0, 0, 0], "PCR_Extend failed");
    }
}

impl Platform for Swtpm {
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
    fn hash_log_extend(&mut self, pcr: u32, data: &[u8], _: &[u8]) -> Result<(), PlatformError> {
        self.pcr_extend(pcr, &Sha256::digest(data).into());
        Ok(())
    }
    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        let code = u32::from_be_bytes(cmd[6..10].try_into().unwrap());
        self.submitted.push(code);
        if self.retry_once == Some(code) {
            self.retry_once = None;
            let r = [0x80, 0x01, 0, 0, 0, 10, 0, 0, 0x09, 0x22];
            resp[..10].copy_from_slice(&r);
            return Ok(10);
        }
        let r = self.raw(cmd);
        resp.get_mut(..r.len())
            .ok_or(PlatformError::TooLarge)?
            .copy_from_slice(&r);
        Ok(r.len())
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
            self.rng = self
                .rng
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            *b = (self.rng >> 33) as u8;
        }
        Ok(())
    }
    fn prompt(&mut self, _: &Screen, _: &mut [u8]) -> Input {
        Input::Escape
    }
    fn log(&mut self, _: std::fmt::Arguments<'_>) {}
    fn publish_handoff(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn load_start_image(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn reset(&mut self) {}
}

fn values(t: &mut Swtpm, pcr12: [u8; 32]) -> [[u8; 32]; 5] {
    let v = Tpm::new(t).pcr_read(0x95).unwrap();
    [
        *v.get(0).unwrap(),
        *v.get(2).unwrap(),
        *v.get(4).unwrap(),
        *v.get(7).unwrap(),
        pcr12,
    ]
}

fn seal(
    t: &mut Swtpm,
    pcr12: [u8; 32],
    deadline: Option<u64>,
    auth: &[u8; 32],
    d: &[u8; 32],
) -> CreatedObject {
    let vals = values(t, pcr12);
    let policy = policy_digest(seal::PCR_MASK_V1, &vals, deadline);
    let mut obj = CreatedObject::new();
    Tpm::new(t)
        .create_sealed(auth, d, &policy, &mut obj)
        .unwrap();
    obj
}

#[test]
fn seal_and_unseal_against_swtpm() {
    let Some(mut t) = start() else { return };
    // Firmware-ish measurements in 0/2/4/7, as a real boot would leave.
    for pcr in [0u32, 2, 4, 7] {
        t.pcr_extend(pcr, &[pcr as u8 + 1; 32]);
    }
    let ini = b"[Paguro]\nversion = 1\n";
    let expected12 = pcr12_after_load_taint(ini);
    let auth = [0x3c; 32];
    let d = [0xd0; 32];
    let obj = seal(&mut t, expected12, None, &auth, &d);

    // Before the load taint PCR 12 is zero: the policy does not match.
    let mut out = [0u8; 32];
    let e = Tpm::new(&mut t)
        .unseal(
            obj.private(),
            obj.public(),
            seal::PCR_MASK_V1,
            None,
            &auth,
            &mut out,
        )
        .unwrap_err();
    assert_eq!(e.class(), RcClass::PolicyFail, "{e:?}");

    // Load taint, as the loader does it.
    t.hash_log_extend(12, ini, &[]).unwrap();
    let v = Tpm::new(&mut t).pcr_read(1 << 12).unwrap();
    assert_eq!(
        v.get(12),
        Some(&expected12),
        "computed PCR 12 equals the TPM's"
    );

    Tpm::new(&mut t)
        .unseal(
            obj.private(),
            obj.public(),
            seal::PCR_MASK_V1,
            None,
            &auth,
            &mut out,
        )
        .unwrap();
    assert_eq!(out, d);

    // A wrong authValue is an authorisation failure and costs a DA attempt.
    let before = Tpm::new(&mut t).lockout().unwrap();
    let e = Tpm::new(&mut t)
        .unseal(
            obj.private(),
            obj.public(),
            seal::PCR_MASK_V1,
            None,
            &[0x3d; 32],
            &mut out,
        )
        .unwrap_err();
    assert_eq!(e.class(), RcClass::AuthFail, "{e:?}");
    let after = Tpm::new(&mut t).lockout().unwrap();
    assert_eq!(after.counter, before.counter + 1, "noDA is clear");
    assert!(after.max > 0);

    // Boot taint: nothing unseals for the rest of the boot.
    t.hash_log_extend(12, paguro_boot::names::BOOT_TAINT, &[])
        .unwrap();
    let e = Tpm::new(&mut t)
        .unseal(
            obj.private(),
            obj.public(),
            seal::PCR_MASK_V1,
            None,
            &auth,
            &mut out,
        )
        .unwrap_err();
    assert_eq!(e.class(), RcClass::PolicyFail, "{e:?}");

    // Tampered private blob: refused by the TPM, not by us.
    let mut private = obj.private().to_vec();
    let last = private.len() - 1;
    private[last] ^= 1;
    let e = Tpm::new(&mut t)
        .unseal(
            &private,
            obj.public(),
            seal::PCR_MASK_V1,
            None,
            &auth,
            &mut out,
        )
        .unwrap_err();
    assert!(matches!(e, TpmFail::Rc(_)), "{e:?}");
}

#[test]
fn pin_bypass_policy_against_swtpm() {
    let Some(mut t) = start() else { return };
    let clock = Tpm::new(&mut t).read_clock().unwrap();
    // A freshly manufactured swtpm may report `safe` either way; the parse is
    // what matters here.
    let _ = clock.safe;
    let pcr12 = [0u8; 32];
    let d = [0xbd; 32];
    let live = seal(&mut t, pcr12, Some(clock.clock + 3_600_000), &[0; 32], &d);
    let mut out = [0u8; 32];
    Tpm::new(&mut t)
        .unseal(
            live.private(),
            live.public(),
            seal::PCR_MASK_V1,
            Some(clock.clock + 3_600_000),
            &[],
            &mut out,
        )
        .unwrap();
    assert_eq!(out, d);

    let expired_deadline = clock.clock.saturating_sub(1).max(1);
    let expired = seal(&mut t, pcr12, Some(expired_deadline), &[0; 32], &d);
    let e = Tpm::new(&mut t)
        .unseal(
            expired.private(),
            expired.public(),
            seal::PCR_MASK_V1,
            Some(expired_deadline),
            &[],
            &mut out,
        )
        .unwrap_err();
    assert_eq!(e.class(), RcClass::PolicyFail, "{e:?}");
}

/// `TPM_RC_RETRY` means "not executed, send it again" (Part 1 §12.2.3); libtpms
/// 0.9 answers the first DA-protected authorisation after Startup with it.
/// Injected here so the resubmission is tested whatever the swtpm version.
#[test]
fn a_retry_response_is_resubmitted() {
    let Some(mut t) = start() else { return };
    let d = [0x5e; 32];
    let obj = seal(&mut t, [0; 32], None, &[7; 32], &d);
    t.retry_once = Some(cc::UNSEAL);
    t.submitted.clear();
    let mut out = [0u8; 32];
    Tpm::new(&mut t)
        .unseal(
            obj.private(),
            obj.public(),
            seal::PCR_MASK_V1,
            None,
            &[7; 32],
            &mut out,
        )
        .unwrap();
    assert_eq!(out, d);
    let unseals = t.submitted.iter().filter(|&&c| c == cc::UNSEAL).count();
    // Two, or three where the swtpm itself answers the first one "retry".
    assert!(unseals >= 2, "the refused Unseal was sent again");
}

#[test]
fn every_transient_handle_is_flushed() {
    let Some(mut t) = start() else { return };
    let obj = seal(&mut t, [0; 32], None, &[1; 32], &[2; 32]);
    let mut out = [0u8; 32];
    for _ in 0..8 {
        // Wrong auth (at most 3 before swtpm's default lockout is irrelevant:
        // we alternate) and policy failures must not exhaust the TPM's slots.
        let _ = Tpm::new(&mut t).unseal(
            obj.private(),
            obj.public(),
            0x1095,
            None,
            &[1; 32],
            &mut out,
        );
        t.pcr_extend(16, &[0; 32]);
    }
    // GetCapability(TPM_CAP_HANDLES, TRANSIENT_FIRST, 16): expect zero handles.
    let mut c = vec![0x80, 0x01, 0, 0, 0, 22, 0, 0, 0x01, 0x7A];
    c.extend(1u32.to_be_bytes());
    c.extend(0x8000_0000u32.to_be_bytes());
    c.extend(16u32.to_be_bytes());
    let r = t.raw(&c);
    assert_eq!(&r[6..10], &[0, 0, 0, 0]);
    assert_eq!(
        u32::from_be_bytes(r[15..19].try_into().unwrap()),
        0,
        "transient objects leaked"
    );
}
