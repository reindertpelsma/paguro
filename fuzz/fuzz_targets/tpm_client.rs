//! The loader's whole TPM conversation (paguro-boot's client: unseal, create,
//! PCR read, clock, lockout) against a TPM that answers with fuzzer bytes.
//! Input: `which u8 | public TPM2B | private TPM2B` (the object to unseal,
//! size-prefixed as in a seal file), then `len u16 LE | response` records, one
//! per command. Seeds are recorded from the mock TPM with the same RNG, so the
//! fuzzer starts from a conversation that succeeds.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::tpm::{CreatedObject, Tpm};
use paguro_core::guid::Guid;

struct Replay<'a> {
    rest: &'a [u8],
}

impl Platform for Replay<'_> {
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
    fn tpm_submit(&mut self, _cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        if self.rest.len() < 2 {
            return Err(PlatformError::Device(0));
        }
        let n = usize::from(u16::from_le_bytes([self.rest[0], self.rest[1]]));
        let body = &self.rest[2..];
        let n = n.min(body.len()).min(resp.len());
        resp[..n].copy_from_slice(&body[..n]);
        self.rest = &body[n..];
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
        buf.fill(0x5a);
        Ok(())
    }
    fn prompt(&mut self, _: &Screen, _: &mut [u8]) -> Input {
        Input::Escape
    }
    fn log(&mut self, _: core::fmt::Arguments<'_>) {}
    fn publish_handoff(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn load_start_image(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Ok(())
    }
    fn reset(&mut self) {}
}

fn tpm2b(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let n = usize::from(u16::from_be_bytes([*b.first()?, *b.get(1)?]));
    let whole = b.get(..2 + n)?;
    Some((whole, &b[2 + n..]))
}

fuzz_target!(|data: &[u8]| {
    let Some((&which, rest)) = data.split_first() else { return };
    let Some((public, rest)) = tpm2b(rest) else { return };
    let Some((private, rest)) = tpm2b(rest) else { return };
    let mut p = Replay { rest };
    let mut t = Tpm::new(&mut p);
    let mut out = [0u8; 32];
    match which % 5 {
        0 => {
            let _ = t.unseal(private, public, 0x1095, None, &[1; 32], &mut out);
        }
        1 => {
            let _ = t.unseal(private, public, 0x1095, Some(99), &[], &mut out);
        }
        2 => {
            let mut obj = CreatedObject::new();
            if t.create_sealed(&[1; 32], &[2; 32], &[3; 32], &mut obj).is_ok() {
                assert!(obj.private().len() <= 1024 && obj.public().len() <= 1024);
            }
        }
        3 => {
            let _ = t.pcr_read(0x1095).map(|v| v.get(12).copied());
        }
        _ => {
            let _ = t.read_clock();
            let _ = t.lockout();
        }
    }
});
