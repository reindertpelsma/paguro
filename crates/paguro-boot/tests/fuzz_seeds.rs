//! Writes seed corpora for the loader's fuzz targets (`fuzz/corpus/<target>/`)
//! from the same builders the tests use, so every target starts from inputs
//! that reach deep into its parser. Ignored by default:
//!
//! ```text
//! PAGURO_FUZZ_SEEDS=fuzz/corpus cargo test -p paguro-boot --test fuzz_seeds -- --ignored
//! ```
#![allow(clippy::indexing_slicing)]

mod mock;

use mock::FakeTpm;
use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::tpm::{CreatedObject, Tpm, policy_digest};
use paguro_core::guid::Guid;
use paguro_core::handoff;
use paguro_core::seal::{self, Kind, Seal, Sealed};
use paguro_core::{bootstrap, config, gpt};
use std::path::PathBuf;

fn dir(target: &str) -> Option<PathBuf> {
    let base = std::env::var_os("PAGURO_FUZZ_SEEDS")?;
    let d = PathBuf::from(base).join(target);
    std::fs::create_dir_all(&d).unwrap();
    Some(d)
}

fn put(target: &str, name: &str, data: &[u8]) {
    if let Some(d) = dir(target) {
        std::fs::write(d.join(format!("seed-{name}")), data).unwrap();
    }
}

/// A platform whose only job is to relay TPM commands to the fake TPM and
/// record the responses, with the RNG the `tpm_client` target uses.
struct Recorder {
    tpm: FakeTpm,
    record: bool,
    log: Vec<u8>,
}

impl Platform for Recorder {
    fn read_esp_file(&mut self, _: &str, _: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        Ok(None)
    }
    fn get_var(&mut self, _: &str, _: &Guid, _: &mut [u8]) -> Result<Option<usize>, PlatformError> {
        Ok(None)
    }
    fn set_var(&mut self, _: &str, _: &Guid, _: u32, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn delete_var(&mut self, _: &str, _: &Guid) -> Result<(), PlatformError> {
        Ok(())
    }
    fn secure_boot(&mut self) -> bool {
        false
    }
    fn tpm_present(&mut self) -> bool {
        true
    }
    fn hash_log_extend(&mut self, _: u32, _: &[u8], _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        let r = self.tpm.submit(cmd);
        if self.record {
            self.log.extend((r.len() as u16).to_le_bytes());
            self.log.extend(&r);
        }
        resp[..r.len()].copy_from_slice(&r);
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
        buf.fill(0x5a);
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

fn tpm_client_seed(which: u8, deadline: Option<u64>, auth: &[u8; 32]) -> Vec<u8> {
    let mut r = Recorder {
        tpm: FakeTpm::new(3),
        record: false,
        log: Vec::new(),
    };
    r.tpm.clock = 10;
    let pcrs = [[0u8; 32]; 5];
    let policy = policy_digest(seal::PCR_MASK_V1, &pcrs, deadline);
    let mut obj = CreatedObject::new();
    Tpm::new(&mut r)
        .create_sealed(auth, &[7; 32], &policy, &mut obj)
        .unwrap();
    r.record = true;
    let mut out = [0u8; 32];
    let a: &[u8] = if deadline.is_some() { &[] } else { auth };
    Tpm::new(&mut r)
        .unseal(
            obj.private(),
            obj.public(),
            seal::PCR_MASK_V1,
            deadline,
            a,
            &mut out,
        )
        .unwrap();
    assert_eq!(out, [7; 32]);
    let mut seed = vec![which];
    seed.extend(obj.public());
    seed.extend(obj.private());
    seed.extend(&r.log);
    seed
}

#[test]
#[ignore]
fn write_fuzz_seeds() {
    // ini_config
    put("ini_config", "schema", &mock::ini_text(&mock::VOLUME, true));
    let ini = mock::ini_text(&mock::VOLUME, false);
    let c = config::parse(&ini).unwrap();
    let mut buf = vec![0u8; 8192];
    let n = config::write(&c, &mut buf).unwrap();
    put("ini_config", "canonical", &buf[..n]);

    // seal
    for kind in Kind::ALL {
        let s = Seal {
            kind,
            deadline: Some(1 << 40),
            pcrs: Some(seal::Pcrs::V1),
            wrapped_vmk: &[1; 32],
            salt: &[2; 16],
            sealed: Some(Sealed {
                public: &[0, 4, 0, 8, 0, 11],
                private: &[0, 3, 9, 9, 9],
            }),
        };
        let mut b = [0u8; seal::MAX_FILE];
        let n = seal::write(&s, &mut b).unwrap();
        put("seal", kind.file_name(), &b[..n]);
    }

    // fve: two entries and a terminator
    put(
        "fve",
        "entries",
        &[
            12, 0, 2, 0, 8, 0, 1, 0, 1, 2, 3, 4, 10, 0, 3, 0, 1, 0, 1, 0, 9, 9, 0, 0,
        ],
    );

    // gpt: fix-flag, disk size, header block, entry array
    let d = mock::disk(&[(mock::VOLUME, mock::BITLOCKER)]);
    let mut g = vec![0u8];
    g.extend((d.data.len() as u64 / 512).to_le_bytes());
    g.extend(&d.data[512..1024]);
    g.extend(&d.data[1024..1024 + gpt::MAX_ENTRY_ARRAY]);
    put("gpt", "one-partition", &g);

    // handoff: from a real mock boot
    let mut w = mock::World::new();
    w.v.clear_key = Some(mock::VMK);
    w.run();
    put("handoff", "clear-key-boot", w.m.handoff.as_ref().unwrap());
    let h = handoff::decode(w.m.handoff.as_ref().unwrap()).unwrap();
    let mut b = vec![0u8; handoff::MAX_LEN];
    let n = handoff::encode(&handoff::Handoff { config: None, ..h }, &mut b).unwrap();
    put("handoff", "no-config", &b[..n]);

    // bootstrap
    let od = bootstrap::write_optional_data(&[1; 16], &[2; 32]);
    let mut lo = [0u8; 512];
    let n =
        bootstrap::write_load_option(1, "paguro setup", "\\EFI\\paguro\\paguro.efi", &od, &mut lo)
            .unwrap();
    put("bootstrap", "entry", &lo[..n]);
    let n = bootstrap::write_load_option(
        1,
        "Windows Boot Manager",
        "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
        &[],
        &mut lo,
    )
    .unwrap();
    put("bootstrap", "windows", &lo[..n]);

    // tpm_client + tpm_response: real conversations with the fake TPM
    let tpm = tpm_client_seed(0, None, &[1; 32]);
    put("tpm_client", "unseal", &tpm);
    put(
        "tpm_client",
        "bypass",
        &tpm_client_seed(1, Some(99), &[0; 32]),
    );
    // tpm_response: each recorded response, prefixed by a selector byte
    let mut rest = &tpm[1..];
    for _ in 0..2 {
        let n = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        rest = &rest[2 + n..];
    }
    let mut i = 0;
    while rest.len() >= 2 {
        let n = u16::from_le_bytes([rest[0], rest[1]]) as usize;
        let resp = &rest[2..2 + n];
        for sel in [0u8, 1, 2, 3] {
            let mut s = vec![sel];
            s.extend(resp);
            put("tpm_response", &format!("{i}-{sel}"), &s);
        }
        rest = &rest[2 + n..];
        i += 1;
    }
}
