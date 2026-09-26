//! Re-seal the `tpm` rung from Linux after `PaguroTpmBroken`
//! (INTERFACES.md §5, §8.3; DESIGN.md §6 "Changing the PIN, and firmware
//! updates"). The PCR values moved (a firmware update, `dbx`, MOK
//! enrolment…), so the *old* `tpm_seal.bin`'s policy no longer matches: its
//! `D` cannot be recovered (that unseal is exactly what now fails), so this
//! seals a fresh `D'` under a policy computed from **this boot's recorded**
//! PCR values (handoff `PCRS` + the load taint), with the same `auth` a
//! future `tpm`-rung boot will derive from the same passphrase.
//!
//! `paguro_boot::tpm::Tpm` is the loader's own TPM client; it only needs
//! `tpm_submit` and `random` from its `Platform`, so [`LinuxTpm`] adapts
//! `/dev/tpmrm0` to it — the same trick `paguro-win`'s `TbsPlatform` uses for
//! Windows' TBS (`crates/paguro-win/src/tpmwin.rs`). Linux therefore produces
//! byte-for-byte the same marshalling, session salting and policy digest the
//! loader's unseal path checks.
//!
//! **What this needs that a plain boot does not carry today** (see the
//! module doc and README for the fuller account):
//! - `B` and this boot's recorded PCR 0/2/4/7 — already in the handoff.
//! - the BitLocker Volume Master Key (`VMK`) — already in the handoff (§8,
//!   type 2), just not previously retained by [`crate::setup::take`].
//! - the Linux password's fast hash (`user_hash`) — added to the handoff
//!   (type 12, `USER_HASH`), forwarded **only** on a `passphrase`-rung boot,
//!   since that rung's own `env` is already a public constant (DESIGN.md
//!   §6): a compromised Linux process able to read the handoff learns
//!   nothing it could not already reach with ESP + raw-disk access alone.
//! - the encrypted FVEK blob (BitLocker's own AES-CCM-wrapped key, an input
//!   to `root_gate` that never changes on this volume) — read from the raw
//!   partition's FVE metadata by `crate::esp::fvek_blob`, over the same
//!   pure, already libbde/dislocker-verified parser the loader uses
//!   (`paguro_core::bde::{cross_check, Metadata}`), not a reimplementation
//!   of its offsets.
//!
//! A boot with none of these (a `recovery`-rung boot: no PIN is typed, so
//! there is no `user_hash` anywhere, and recovery never parses
//! `paguro.ini`, so there is no PCR 12 either) cannot re-seal automatically;
//! [`crate::setup`] logs why and leaves `PaguroTpmBroken` set for a later
//! `passphrase`- or `tpm`-rung boot to clear.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::tpm::{CreatedObject, Tpm, TpmFail, policy_digest};
use paguro_core::guid::Guid;
use paguro_core::seal::{self, Kind, Pcrs as SealPcrs, Seal, Sealed};
use zeroize::{Zeroize, Zeroizing};

/// `/dev/tpmrm0`: the kernel's TPM resource manager. One write is one
/// command; the matching response is the next read (no session bookkeeping
/// needed — the kernel does that).
pub const TPMRM0: &str = "/dev/tpmrm0";

pub struct LinuxTpm {
    dev: File,
}

impl LinuxTpm {
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let dev = OpenOptions::new().read(true).write(true).open(path)?;
        Ok(LinuxTpm { dev })
    }
}

impl Platform for LinuxTpm {
    fn read_esp_file(&mut self, _: &str, _: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn get_var(&mut self, _: &str, _: &Guid, _: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        Err(PlatformError::Unsupported)
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
        self.dev
            .write_all(cmd)
            .map_err(|e| PlatformError::Device(e.raw_os_error().map_or(0, |c| c as u64)))?;
        self.dev
            .read(resp)
            .map_err(|e| PlatformError::Device(e.raw_os_error().map_or(0, |c| c as u64)))
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
        File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(buf))
            .map_err(|_| PlatformError::Unsupported)
    }
    fn prompt(&mut self, _: &Screen, _: &mut [u8]) -> Input {
        Input::Escape
    }
    fn log(&mut self, args: std::fmt::Arguments<'_>) {
        crate::setup::log(&args.to_string());
    }
    fn publish_handoff(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn load_start_image(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn reset(&mut self) {}
}

#[derive(Debug)]
pub enum ResealError {
    Tpm(TpmFail),
    /// The created object does not fit a seal file (`seal::MAX_FILE`).
    Seal,
}

/// Everything a re-seal needs beyond the TPM itself. `pcr0247` and `pcr12`
/// are this boot's *recorded* values (handoff `PCRS`, and
/// `pcr12_after_load_taint` of the `CONFIG` the same boot carried) — never a
/// live PCR read, which by the time Linux runs no longer matches what the
/// loader saw (DESIGN.md §6, "Changing the PIN").
pub struct ResealInput<'a> {
    pub b: &'a [u8; 32],
    pub vmk: &'a [u8; 32],
    pub user_hash: &'a [u8; 32],
    /// BitLocker's encrypted FVEK blob (nonce ‖ tag ‖ ciphertext,
    /// `crate::esp::fvek_blob`): an input to `root_gate`, unchanged by this
    /// re-seal.
    pub blob: &'a [u8],
    pub pcr0247: &'a [[u8; 32]; 4],
    pub pcr12: [u8; 32],
}

/// Seal a fresh `D'` under a policy over `input`'s PCR values, with `auth`
/// derived from `input.user_hash` exactly as the loader will at the next
/// `tpm`-rung boot, and wrap the current `VMK` under the matching key.
/// Returns the whole `tpm_seal.bin` file (magic included).
pub fn reseal<P: Platform>(
    p: &mut P,
    input: &ResealInput<'_>,
) -> Result<Zeroizing<Vec<u8>>, ResealError> {
    let pcrs = [
        input.pcr0247[0],
        input.pcr0247[1],
        input.pcr0247[2],
        input.pcr0247[3],
        input.pcr12,
    ];
    let policy = policy_digest(seal::PCR_MASK_V1, &pcrs, None);

    let mut salt = [0u8; seal::SALT_LEN];
    p.random(&mut salt)
        .map_err(|e| ResealError::Tpm(TpmFail::Platform(e)))?;
    let mut d = [0u8; 32];
    p.random(&mut d)
        .map_err(|e| ResealError::Tpm(TpmFail::Platform(e)))?;

    let mut ph =
        paguro_crypto::bitlocker_stretch(input.user_hash, &salt, paguro_crypto::STRETCH_ITERATIONS);
    let mut auth = paguro_crypto::tpm_auth(&ph);

    let mut created = Box::new(CreatedObject::new());
    let r = Tpm::new(p).create_sealed(&auth, &d, &policy, &mut created);
    auth.zeroize();
    if let Err(e) = r {
        d.zeroize();
        ph.zeroize();
        return Err(ResealError::Tpm(e));
    }

    let mut env = paguro_crypto::env_tpm(input.b, &d);
    d.zeroize();
    let mut root_gate = paguro_crypto::root_gate(&env, &salt, input.blob);
    env.zeroize();
    let mut key = paguro_crypto::final_key(&root_gate, &ph);
    root_gate.zeroize();
    ph.zeroize();
    let mut wrapped = paguro_crypto::xor32(&key, input.vmk);
    key.zeroize();

    let s = Seal {
        kind: Kind::Tpm,
        deadline: None,
        pcrs: Some(SealPcrs::V1),
        wrapped_vmk: &wrapped,
        salt: &salt,
        sealed: Some(Sealed {
            public: created.public(),
            private: created.private(),
        }),
    };
    let mut buf = Zeroizing::new(vec![0u8; seal::MAX_FILE]);
    let n = seal::write(&s, &mut buf);
    wrapped.zeroize();
    created.private.zeroize();
    let n = n.map_err(|_| ResealError::Seal)?;
    buf.truncate(n);
    Ok(buf)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use paguro_boot::tpm::pcr12_after_load_taint;
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    /// A minimal swtpm harness (mirrors `paguro-boot/tests/swtpm.rs`): only
    /// `tpm_submit` and `random` are exercised by [`reseal`].
    struct Swtpm {
        child: Child,
        dir: PathBuf,
        sock: UnixStream,
        rng: u64,
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn start() -> Option<Swtpm> {
        let present = Command::new("swtpm")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !present {
            eprintln!("swtpm not installed: skipping real-TPM reseal tests");
            return None;
        }
        let dir = std::env::temp_dir().join(format!(
            "paguro-initrd-swtpm-{}-{:?}",
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
        fn get_var(
            &mut self,
            _: &str,
            _: &Guid,
            _: &mut [u8],
        ) -> Result<Option<usize>, PlatformError> {
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
        fn hash_log_extend(
            &mut self,
            pcr: u32,
            data: &[u8],
            _: &[u8],
        ) -> Result<(), PlatformError> {
            use sha2::{Digest, Sha256};
            self.pcr_extend(pcr, &Sha256::digest(data).into());
            Ok(())
        }
        fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
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

    /// The re-seal produces a seal whose policy digest is exactly what the
    /// loader's own `policy_digest` over the same (mask, PCR values,
    /// deadline) computes — "same inputs, same policy digest" — and a real
    /// TPM accepts an `Unseal` against it (same object template).
    #[test]
    fn policy_and_template_match_the_loader() {
        let Some(mut t) = start() else { return };
        for pcr in [0u32, 2, 4, 7] {
            t.pcr_extend(pcr, &[pcr as u8 + 1; 32]);
        }
        let ini = b"[Paguro]\nversion = 1\n";
        t.hash_log_extend(12, ini, &[]).unwrap();

        // `policy_digest` is computed offline from whatever PCR values are
        // given; seal against the values `pcr_extend` actually produced so
        // the TPM's own live registers satisfy the policy on unseal.
        let live = paguro_boot::tpm::Tpm::new(&mut t).pcr_read(0x95).unwrap();
        let pcr0247 = [
            *live.get(0).unwrap(),
            *live.get(2).unwrap(),
            *live.get(4).unwrap(),
            *live.get(7).unwrap(),
        ];
        let input = ResealInput {
            b: &[0x11; 32],
            vmk: &[0x22; 32],
            user_hash: &[0x33; 32],
            blob: b"encrypted-fvek-blob-stand-in",
            pcr0247: &pcr0247,
            pcr12: pcr12_after_load_taint(ini),
        };

        let file = reseal(&mut t, &input).unwrap();
        let parsed = seal::read(Kind::Tpm, &file).unwrap();
        assert_eq!(parsed.pcrs, Some(SealPcrs::V1));

        // The loader's own unseal recomputes the policy internally
        // (PolicyPCR over the live registers): accepting the object proves
        // the template and policy match, without re-deriving it by hand.
        let sealed = parsed.sealed.unwrap();
        let auth = paguro_crypto::tpm_auth(&paguro_crypto::bitlocker_stretch(
            input.user_hash,
            parsed.salt,
            paguro_crypto::STRETCH_ITERATIONS,
        ));
        let mut d = [0u8; 32];
        paguro_boot::tpm::Tpm::new(&mut t)
            .unseal(
                sealed.private,
                sealed.public,
                seal::PCR_MASK_V1,
                None,
                &auth,
                &mut d,
            )
            .unwrap();

        // The wrapped VMK really does recover the original VMK once D is
        // known (mirrors the loader's `derive_vmk`).
        let env = paguro_crypto::env_tpm(input.b, &d);
        let root_gate = paguro_crypto::root_gate(&env, parsed.salt, input.blob);
        let ph = paguro_crypto::bitlocker_stretch(
            input.user_hash,
            parsed.salt,
            paguro_crypto::STRETCH_ITERATIONS,
        );
        let key = paguro_crypto::final_key(&root_gate, &ph);
        let vmk = paguro_crypto::xor32(&key, parsed.wrapped_vmk);
        assert_eq!(&vmk, input.vmk, "the loader's unseal path recovers our VMK");
    }

    /// A wrong PCR value (a policy that does not match the live registers)
    /// is refused by the TPM, not silently accepted.
    #[test]
    fn wrong_pcr_values_are_refused() {
        let Some(mut t) = start() else { return };
        let input = ResealInput {
            b: &[1; 32],
            vmk: &[2; 32],
            user_hash: &[3; 32],
            blob: b"blob",
            pcr0247: &[[9; 32]; 4],
            pcr12: [9; 32],
        };
        let file = reseal(&mut t, &input).unwrap();
        let parsed = seal::read(Kind::Tpm, &file).unwrap();
        let sealed = parsed.sealed.unwrap();
        let auth = paguro_crypto::tpm_auth(&paguro_crypto::bitlocker_stretch(
            input.user_hash,
            parsed.salt,
            paguro_crypto::STRETCH_ITERATIONS,
        ));
        let mut d = [0u8; 32];
        let e = paguro_boot::tpm::Tpm::new(&mut t)
            .unseal(
                sealed.private,
                sealed.public,
                seal::PCR_MASK_V1,
                None,
                &auth,
                &mut d,
            )
            .unwrap_err();
        assert_eq!(
            e.class(),
            paguro_core::tpm::RcClass::PolicyFail,
            "swtpm's live registers do not match the fabricated pcr0247/pcr12"
        );
    }
}
