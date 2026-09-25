//! Key material from a logged-in Windows session (DESIGN.md §7: "Windows
//! touches key material in three places": the bootstrap, `setupTPM`
//! staging, and the PIN bypass).
//!
//! The VMK comes from **Windows' own protector**, never from a paguro file:
//! the volume's recovery password, which an administrator can read through
//! WMI (`GetKeyProtectorNumericalPassword`), opens the recovery protector in
//! the raw FVE metadata; a clear key (BitLocker suspended) opens directly.
//! Parsing is `paguro_core::bde`, unwrapping is `paguro_boot::bde` — the
//! loader's code — and the VMK is accepted only if it also unwraps the FVEK,
//! the same check the loader makes.
//!
//! Everything here is zeroised on drop and never logged.

use paguro_boot::bde::{unlock_fvek, vmk_from_clear_key, vmk_from_recovery};
use paguro_boot::volume::parse_recovery_password;
use paguro_core::bde::{self, Metadata};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::{Volume, WinApi};
use crate::out::{CmdError, Exit};

/// What `setupTPM` staging, the PIN bypass and the bootstrap need.
pub struct VolumeKeys {
    pub vmk: Zeroizing<[u8; 32]>,
    /// `nonce[12] ‖ tag[16] ‖ ciphertext`: the encrypted FVEK exactly as the
    /// loader folds it into the root gate (`paguro-boot` `BdeVolume::fvek_blob`).
    pub fvek_blob: Vec<u8>,
    /// How the VMK was obtained, for the report.
    pub source: &'static str,
}

impl std::fmt::Debug for VolumeKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeKeys")
            .field("vmk", &"<redacted>")
            .field("fvek_blob_len", &self.fvek_blob.len())
            .field("source", &self.source)
            .finish()
    }
}

/// The encrypted FVEK blob the root gate binds (DESIGN.md §6).
pub fn fvek_blob(m: &Metadata<'_>) -> Vec<u8> {
    let f = m.fvek;
    let mut b = Vec::with_capacity(28 + f.ciphertext.len());
    b.extend_from_slice(&f.nonce);
    b.extend_from_slice(&f.tag);
    b.extend_from_slice(f.ciphertext);
    b
}

fn bde_err(e: bde::BdeError) -> CmdError {
    CmdError::new(Exit::Platform, format!("BitLocker metadata: {e:?}"))
}

/// A volume header and its three metadata regions.
pub type RawMetadata = (bde::VolumeHeader, [Vec<u8>; 3]);

/// Read the three FVE metadata copies of the partition at `offset` on
/// `disk`, below BitLocker. `Ok(None)`: the partition is not BitLocker.
pub fn read_metadata(
    api: &dyn WinApi,
    disk: u32,
    offset: u64,
) -> Result<Option<RawMetadata>, CmdError> {
    let first = api.read_disk(disk, offset, 512)?;
    let hdr = match bde::parse_volume_header(&first) {
        Ok(h) => h,
        Err(bde::BdeError::NotBitLocker) => return Ok(None),
        Err(e) => return Err(bde_err(e)),
    };
    let region = bde::REGION_SIZE as usize;
    let mut copies: [Vec<u8>; 3] = Default::default();
    for (c, o) in copies.iter_mut().zip(hdr.metadata_offsets) {
        let at = offset
            .checked_add(o)
            .ok_or_else(|| bde_err(bde::BdeError::MetadataOffset))?;
        *c = api.read_disk(disk, at, region)?;
    }
    Ok(Some((hdr, copies)))
}

/// The VMK and FVEK blob of `volume`. `Ok(None)`: not a BitLocker volume
/// (the loader's "unencrypted volume" rung; there is nothing to wrap).
pub fn from_windows(api: &dyn WinApi, volume: &Volume) -> Result<Option<VolumeKeys>, CmdError> {
    let loc = volume.location.as_ref().ok_or_else(|| {
        CmdError::refused(format!("{}: not a partition on a disk", volume.guid_path))
    })?;
    let Some((hdr, copies)) = read_metadata(api, loc.disk_number, loc.offset)? else {
        return Ok(None);
    };
    let block = bde::cross_check([&copies[0], &copies[1], &copies[2]], &hdr).map_err(bde_err)?;
    let m = Metadata::parse(block).map_err(bde_err)?;
    let accept = |v: [u8; 32], source: &'static str| -> Result<Option<VolumeKeys>, CmdError> {
        let vmk = Zeroizing::new(v);
        match unlock_fvek(&m, &vmk).map_err(bde_err)? {
            Some(_) => Ok(Some(VolumeKeys {
                vmk,
                fvek_blob: fvek_blob(&m),
                source,
            })),
            None => Ok(None),
        }
    };
    if let Some(v) = vmk_from_clear_key(&m).map_err(bde_err)? {
        if let Some(k) = accept(v, "clear key (BitLocker suspended)")? {
            return Ok(Some(k));
        }
    }
    let drive = volume.drive().ok_or_else(|| {
        CmdError::refused("the volume has no drive letter; BitLocker's WMI needs one")
    })?;
    for pw in api.bitlocker_recovery_passwords(drive)? {
        let Ok(key) = parse_recovery_password(pw.as_bytes()) else {
            continue;
        };
        let key = Zeroizing::new(key);
        if let Some(v) = vmk_from_recovery(&m, &key).map_err(bde_err)? {
            if let Some(k) = accept(v, "recovery password protector (via WMI)")? {
                return Ok(Some(k));
            }
        }
    }
    Err(CmdError::refused(format!(
        "{drive}: BitLocker is on but no protector Windows can open for paguro \
         (needs a recovery password protector or suspended protection)"
    )))
}

/// `SHA-256(paguro.ini)`, the value `PaguroConfigHash` holds.
pub fn ini_hash(ini: &[u8]) -> [u8; 32] {
    Sha256::digest(ini).into()
}

/// The passphrase hash every rung stretches: BitLocker's user-password hash
/// followed by its stretch with the seal's own salt (INTERFACES.md §8.1;
/// `paguro-boot` `Machine::stretch`).
pub fn pass_hash(passphrase: &str, salt: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let user = Zeroizing::new(paguro_crypto::user_password_hash(passphrase));
    Zeroizing::new(paguro_crypto::bitlocker_stretch(
        &user,
        salt,
        paguro_crypto::STRETCH_ITERATIONS,
    ))
}

/// `setuptpm_seal.bin`'s wrapped VMK: `VMK XOR final(root_gate(env_setup(S,
/// H(ini)), salt, blob), pass_hash)` — the loader's `derive_vmk` inverted.
pub fn wrap_setup(
    keys: &VolumeKeys,
    s: &[u8; 32],
    ini: &[u8],
    salt: &[u8; 16],
    pass_hash: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let env = Zeroizing::new(paguro_crypto::env_setup(s, &ini_hash(ini)));
    let rg = Zeroizing::new(paguro_crypto::root_gate(&env, salt, &keys.fvek_blob));
    let k = Zeroizing::new(paguro_crypto::final_key(&rg, pass_hash));
    Zeroizing::new(paguro_crypto::xor32(&keys.vmk, &k))
}

/// The bootstrap payload's wrapped VMK (INTERFACES.md §9).
pub fn wrap_bootstrap(
    vmk: &[u8; 32],
    salt: &[u8; 16],
    pass_hash: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let k = Zeroizing::new(paguro_crypto::bootstrap_key(pass_hash, salt));
    Zeroizing::new(paguro_crypto::xor32(vmk, &k))
}
