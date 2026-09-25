//! Shared test machinery: running the CLI against the mock, the Windows-made
//! BitLocker fixtures of `test/fixtures/bde/windows`, and swtpm.
#![allow(dead_code, clippy::indexing_slicing)]

use std::path::PathBuf;

use paguro_core::guid::Guid;
use paguro_win::api::{BitLocker, Output};
use paguro_win::mock::{C_OFFSET, MockApi, MockFile};
use serde_json::Value;

pub struct Run {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
    pub json: Value,
}

/// `paguro --json <args>` against `m`.
pub fn run(m: &MockApi, args: &[&str]) -> Run {
    let mut v = vec!["paguro", "--json"];
    v.extend_from_slice(args);
    let r = paguro_win::cli::run(m, v);
    let json = serde_json::from_str(&r.stdout).unwrap_or(Value::Null);
    Run {
        code: r.code,
        stdout: r.stdout,
        stderr: r.stderr,
        json,
    }
}

pub fn ok(m: &MockApi, args: &[&str]) -> Value {
    let r = run(m, args);
    assert_eq!(r.code, 0, "{args:?}: {}{}", r.stdout, r.stderr);
    assert_eq!(r.json["schema"], "paguro-cli/1");
    assert_eq!(r.json["ok"], true);
    r.json["data"].clone()
}

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test/fixtures/bde/windows")
}

/// A `PGBDESP1` sparse fixture, expanded.
pub fn sparse_volume(name: &str) -> Vec<u8> {
    let s = std::fs::read(fixtures().join(format!("{name}.sparse"))).unwrap();
    assert_eq!(&s[..8], b"PGBDESP1");
    let size = u64::from_le_bytes(s[8..16].try_into().unwrap());
    let mut v = vec![0u8; size as usize];
    let mut at = 16;
    while at < s.len() {
        let o = u64::from_le_bytes(s[at..at + 8].try_into().unwrap()) as usize;
        let n = u32::from_le_bytes(s[at + 8..at + 12].try_into().unwrap()) as usize;
        v[o..o + n].copy_from_slice(&s[at + 12..at + 12 + n]);
        at += 12 + n;
    }
    v
}

pub const FIXTURE: &str = "bitlk-aes-xts-128";
pub const RECOVERY: &str = "235818-357951-253979-013365-241120-245575-342914-591910";

/// Make C: a BitLocker volume (the fixture's metadata on disk 0 at C:'s
/// offset) whose recovery password WMI hands to administrators.
pub fn with_bitlocker(m: &MockApi) {
    let vol = sparse_volume(FIXTURE);
    let mut d = MockFile::zeros(C_OFFSET + vol.len() as u64);
    // Only the non-zero regions matter; keep the mock small.
    for (i, chunk) in vol.chunks(4096).enumerate() {
        if chunk.iter().any(|&b| b != 0) {
            d.write_at(C_OFFSET + (i * 4096) as u64, chunk);
        }
    }
    m.raw_disks.borrow_mut().insert(0, d);
    m.bitlocker.borrow_mut().insert(
        "c:".into(),
        BitLocker {
            protection_status: 1,
            conversion_status: 1,
            encryption_percentage: 100,
            encryption_method: 6,
            protector_types: vec![1, 3],
        },
    );
    m.recovery
        .borrow_mut()
        .insert("c:".into(), vec![RECOVERY.into()]);
}

/// The fixture's metadata, parsed the loader's way, and a VMK check.
pub fn vmk_opens_fixture(vmk: &[u8; 32]) -> bool {
    let vol = sparse_volume(FIXTURE);
    let hdr = paguro_core::bde::parse_volume_header(&vol[..512]).unwrap();
    let r = paguro_core::bde::REGION_SIZE as usize;
    let c: Vec<&[u8]> = hdr
        .metadata_offsets
        .iter()
        .map(|&o| &vol[o as usize..o as usize + r])
        .collect();
    let block = paguro_core::bde::cross_check([c[0], c[1], c[2]], &hdr).unwrap();
    let m = paguro_core::bde::Metadata::parse(block).unwrap();
    paguro_boot::bde::unlock_fvek(&m, vmk).unwrap().is_some()
}

/// A process runner where every listed program "succeeds" and anything else
/// fails, recording nothing extra (the mock records commands itself).
pub fn runner(succeed: &'static [&'static str]) -> impl Fn(&str, &[&str]) -> Option<Output> {
    move |prog, args| {
        let line = std::iter::once(prog)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        let ok = succeed.iter().any(|p| line.starts_with(p));
        Some(Output {
            status: if ok { 0 } else { 1 },
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

pub fn c_guid() -> Guid {
    Guid::parse(paguro_win::mock::C_GUID).unwrap()
}

pub fn pe(tag: &str) -> Vec<u8> {
    let mut v = b"MZ".to_vec();
    v.extend_from_slice(tag.as_bytes());
    v
}

/// ESP files installed from inputs on C:.
pub fn install_esp(m: &MockApi) {
    m.put_file("C:\\in\\shimx64.efi", &pe("shim"));
    m.put_file("C:\\in\\mmx64.efi", &pe("mm"));
    m.put_file("C:\\in\\paguro.efi", &pe("loader"));
    ok(
        m,
        &[
            "esp",
            "install",
            "--shim",
            "C:\\in\\shimx64.efi",
            "--mm",
            "C:\\in\\mmx64.efi",
            "--loader",
            "C:\\in\\paguro.efi",
        ],
    );
}

// ---- swtpm -----------------------------------------------------------------

#[cfg(unix)]
#[allow(unused_imports)]
pub use tpm::*;

#[cfg(unix)]
mod tpm {
    use std::cell::RefCell;
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
    use paguro_core::guid::Guid;
    use paguro_win::mock::MockApi;

    pub struct Swtpm {
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

    pub fn swtpm() -> Option<Rc<RefCell<Swtpm>>> {
        let present = Command::new("swtpm")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success());
        if !present {
            eprintln!("swtpm not installed: skipping real-TPM tests");
            return None;
        }
        let dir = std::env::temp_dir().join(format!(
            "paguro-win-swtpm-{}-{:?}",
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
                return Some(Rc::new(RefCell::new(Swtpm {
                    child,
                    dir,
                    sock: s,
                    rng: 7,
                })));
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
        pub fn raw(&mut self, cmd: &[u8]) -> Vec<u8> {
            self.sock.write_all(cmd).unwrap();
            let mut hdr = [0u8; 10];
            self.sock.read_exact(&mut hdr).unwrap();
            let n = u32::from_be_bytes(hdr[2..6].try_into().unwrap()) as usize;
            let mut rest = vec![0u8; n - 10];
            self.sock.read_exact(&mut rest).unwrap();
            [&hdr[..], &rest].concat()
        }

        /// `TPM2_PCR_Extend(pcr, sha256: digest)`.
        pub fn pcr_extend(&mut self, pcr: u32, digest: &[u8; 32]) {
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

    /// Plug the swtpm into the mock as its TBS.
    pub fn attach(m: &MockApi, t: &Rc<RefCell<Swtpm>>) {
        let t = t.clone();
        m.set_tpm(move |cmd| Ok(t.borrow_mut().raw(cmd)));
    }

    /// The loader's side of the same TPM.
    pub struct LoaderTpm(pub Rc<RefCell<Swtpm>>);

    impl Platform for LoaderTpm {
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
        fn hash_log_extend(&mut self, _: u32, _: &[u8], _: &[u8]) -> Result<(), PlatformError> {
            Err(PlatformError::Unsupported)
        }
        fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
            let r = self.0.borrow_mut().raw(cmd);
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
            let mut t = self.0.borrow_mut();
            for b in buf.iter_mut() {
                t.rng = t
                    .rng
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                *b = (t.rng >> 33) as u8;
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
}
