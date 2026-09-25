//! The TPM from Windows (TBS), through the loader's own TPM client.
//!
//! `paguro_boot::tpm::Tpm` is the code that seals and unseals at boot; it
//! only needs `tpm_submit` and `random` from its platform, so
//! [`TbsPlatform`] adapts [`WinApi`] to it and everything else refuses.
//! Windows therefore creates the PIN-bypass object with byte-for-byte the
//! same marshalling and policy computation the loader will check it with.

use core::fmt;

use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen};
use paguro_boot::tpm::{CreatedObject, Tpm, TpmFail, pcr12_after_load_taint, policy_digest};
use paguro_core::guid::Guid;
use paguro_core::recorded::Recorded;
use paguro_core::seal::{self, Kind, Pcrs, Seal, Sealed};
use paguro_core::tpm::{PcrValues, TimeInfo};
use zeroize::{Zeroize, Zeroizing};

use crate::api::WinApi;

/// How long a PIN-bypass seal stays usable: long enough for a slow firmware
/// POST, short enough that a copy is inert soon after (DESIGN.md §6).
pub const BYPASS_VALIDITY_MS: u64 = 10 * 60 * 1000;

pub struct TbsPlatform<'a> {
    pub api: &'a dyn WinApi,
}

impl Platform for TbsPlatform<'_> {
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
        self.api.tpm_present()
    }
    fn hash_log_extend(&mut self, _: u32, _: &[u8], _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        let r = self
            .api
            .tpm_submit(cmd)
            .map_err(|e| PlatformError::Device(e.code.map_or(0, |c| c as u64)))?;
        let dst = resp.get_mut(..r.len()).ok_or(PlatformError::TooLarge)?;
        dst.copy_from_slice(&r);
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
        self.api.random(buf).map_err(|_| PlatformError::Unsupported)
    }
    fn prompt(&mut self, _: &Screen, _: &mut [u8]) -> Input {
        Input::Escape
    }
    fn log(&mut self, _: fmt::Arguments<'_>) {}
    fn publish_handoff(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn load_start_image(&mut self, _: &[u8]) -> Result<(), PlatformError> {
        Err(PlatformError::Unsupported)
    }
    fn reset(&mut self) {}
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TpmError {
    Absent,
    Tpm(String),
    /// `TPMS_CLOCK_INFO.safe` is clear: refuse the bypass (DESIGN.md §6).
    ClockUnsafe,
    Seal,
}

impl fmt::Display for TpmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TpmError::Absent => f.write_str("no TPM 2.0"),
            TpmError::Tpm(s) => write!(f, "TPM: {s}"),
            TpmError::ClockUnsafe => f.write_str("TPM clock not safe (unexpected power loss)"),
            TpmError::Seal => f.write_str("sealed object does not fit a seal file"),
        }
    }
}

fn tpm_err(e: TpmFail) -> TpmError {
    TpmError::Tpm(format!("{e:?}"))
}

pub fn pcr_read(api: &dyn WinApi, mask: u32) -> Result<PcrValues, TpmError> {
    if !api.tpm_present() {
        return Err(TpmError::Absent);
    }
    let mut p = TbsPlatform { api };
    Tpm::new(&mut p).pcr_read(mask).map_err(tpm_err)
}

pub fn read_clock(api: &dyn WinApi) -> Result<TimeInfo, TpmError> {
    if !api.tpm_present() {
        return Err(TpmError::Absent);
    }
    let mut p = TbsPlatform { api };
    Tpm::new(&mut p).read_clock().map_err(tpm_err)
}

/// The PCR values the loader will see, in `PCR_MASK_V1` order (0, 2, 4, 7,
/// 12): 0/2/4/7 as Linux recorded them, 12 computed from `paguro.ini`.
pub fn loader_pcrs(rec: &Recorded, ini: &[u8]) -> [[u8; 32]; 5] {
    [
        rec.pcrs[0],
        rec.pcrs[1],
        rec.pcrs[2],
        rec.pcrs[3],
        pcr12_after_load_taint(ini),
    ]
}

/// Write `tpm_pin_bypass_seal.bin` (INTERFACES.md §4, §8.1): a fresh `D`
/// sealed to PCR 0/2/4/7/12 and `Clock < now + validity`, empty `authValue`,
/// and `wrapped_vmk = VMK XOR D`. Returns the file bytes and the deadline.
pub fn create_pin_bypass(
    api: &dyn WinApi,
    rec: &Recorded,
    ini: &[u8],
    vmk: &[u8; 32],
    validity_ms: u64,
) -> Result<(Zeroizing<Vec<u8>>, u64), TpmError> {
    let clock = read_clock(api)?;
    if !clock.safe {
        return Err(TpmError::ClockUnsafe);
    }
    let deadline = clock.clock.saturating_add(validity_ms);
    let pcrs = loader_pcrs(rec, ini);
    let policy = policy_digest(seal::PCR_MASK_V1, &pcrs, Some(deadline));
    let mut d = Zeroizing::new([0u8; 32]);
    api.random(&mut d[..])
        .map_err(|e| TpmError::Tpm(e.to_string()))?;
    let mut created = Box::new(CreatedObject::new());
    {
        let mut p = TbsPlatform { api };
        // An all-zero authValue is the empty one: the TPM strips trailing
        // zeros wherever an authValue is used (Part 1 §19.6.4.3), and the
        // loader unseals the bypass with an empty authorisation.
        Tpm::new(&mut p)
            .create_sealed(&[0; 32], &d, &policy, &mut created)
            .map_err(tpm_err)?;
    }
    let mut wrapped = paguro_crypto::xor32(vmk, &d);
    let mut salt = [0u8; 16];
    api.random(&mut salt)
        .map_err(|e| TpmError::Tpm(e.to_string()))?;
    let s = Seal {
        kind: Kind::PinBypass,
        deadline: Some(deadline),
        pcrs: Some(Pcrs::V1),
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
    let n = n.map_err(|_| TpmError::Seal)?;
    buf.truncate(n);
    Ok((buf, deadline))
}
