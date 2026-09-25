//! The pre-flight check before "Restart into Linux" (DESIGN.md §4.6).
//!
//! It moves diagnosis from the worst environment (a boot screen) to the best one
//! (a running Windows with a browser). Everything it compares is advisory:
//! what Linux recorded is ground truth, and Windows is only predicting it.

/// What Linux recorded on its last boot, as read from the encrypted volume.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recorded {
    pub pcr0: [u8; 32],
    pub pcr2: [u8; 32],
    /// SHA-256 over the TCG log's `EV_EFI_VARIABLE_DRIVER_CONFIG` entries
    /// (PK, KEK, db, dbx). PCR 7's *value* is path-dependent — it carries the
    /// authority events of whichever chain booted — so it is never compared.
    pub secure_boot_config: [u8; 32],
    pub shim_sha256: [u8; 32],
    pub loader_sha256: [u8; 32],
}

/// The same facts as observed from the running Windows.
pub type Observed = Recorded;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case", tag = "action", content = "reason")]
pub enum Action {
    /// The seal will unseal: write the PIN bypass and restart.
    Restart,
    /// The seal will not unseal: prompt for the Linux passphrase in Windows,
    /// stage a one-shot `setupTPM`, then restart.
    StageSetupTpm(Reason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    Firmware,
    SecureBootDatabases,
    Loader,
    /// The loader set `PaguroTpmBroken` on a failed unseal (DESIGN.md §4.6,
    /// "The TPM-failure handshake").
    LoaderReported,
}

impl Reason {
    pub const fn explain(self) -> &'static str {
        match self {
            Reason::Firmware => {
                "the firmware changed (PCR 0/2): a firmware update or settings change"
            }
            Reason::SecureBootDatabases => {
                "the Secure Boot databases changed (usually a dbx update from Windows Update)"
            }
            Reason::Loader => "shim or paguro.efi on the ESP changed since the last Linux boot",
            Reason::LoaderReported => "the last attempt to start Linux could not unseal the TPM",
        }
    }
}

/// `secure_boot_config` of a TCG log: SHA-256 over the SHA-256 digests of
/// PCR 7's `EV_EFI_VARIABLE_DRIVER_CONFIG` events, in log order (the value
/// `paguro_core::recorded` proposes Linux records).
pub fn secure_boot_config(log: &[u8]) -> Result<[u8; 32], paguro_core::tcglog::LogError> {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    paguro_core::tcglog::driver_config_digests(log, |d| h.update(d))?;
    Ok(h.finalize().into())
}

impl Recorded {
    pub fn from_record(r: &paguro_core::recorded::Recorded) -> Self {
        Recorded {
            pcr0: r.pcrs[0],
            pcr2: r.pcrs[1],
            secure_boot_config: r.secure_boot_config,
            shim_sha256: r.shim_sha256,
            loader_sha256: r.loader_sha256,
        }
    }
}

pub fn decide(rec: &Recorded, obs: &Observed) -> Action {
    if rec.pcr0 != obs.pcr0 || rec.pcr2 != obs.pcr2 {
        Action::StageSetupTpm(Reason::Firmware)
    } else if rec.secure_boot_config != obs.secure_boot_config {
        // The routine case: a dbx update shipped through Windows Update.
        Action::StageSetupTpm(Reason::SecureBootDatabases)
    } else if rec.shim_sha256 != obs.shim_sha256 || rec.loader_sha256 != obs.loader_sha256 {
        Action::StageSetupTpm(Reason::Loader)
    } else {
        Action::Restart
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn rec() -> Recorded {
        Recorded {
            pcr0: [0; 32],
            pcr2: [2; 32],
            secure_boot_config: [7; 32],
            shim_sha256: [1; 32],
            loader_sha256: [4; 32],
        }
    }

    #[test]
    fn unchanged_machine_restarts_without_prompt() {
        assert_eq!(decide(&rec(), &rec()), Action::Restart);
    }

    #[test]
    fn dbx_update_is_predicted() {
        let mut o = rec();
        o.secure_boot_config = [8; 32];
        assert_eq!(
            decide(&rec(), &o),
            Action::StageSetupTpm(Reason::SecureBootDatabases)
        );
    }

    #[test]
    fn shim_update_is_predicted() {
        let mut o = rec();
        o.shim_sha256 = [9; 32];
        assert_eq!(decide(&rec(), &o), Action::StageSetupTpm(Reason::Loader));
    }

    #[test]
    fn firmware_change_is_predicted_first() {
        let mut o = rec();
        o.pcr0 = [1; 32];
        o.shim_sha256 = [9; 32];
        assert_eq!(decide(&rec(), &o), Action::StageSetupTpm(Reason::Firmware));
    }

    #[test]
    fn secure_boot_config_hashes_only_the_driver_config_prefix() {
        use paguro_core::tcglog::{
            EV_EFI_VARIABLE_AUTHORITY, EV_EFI_VARIABLE_DRIVER_CONFIG, write,
        };
        let mut a = vec![0u8; 4096];
        let n = write(
            &[
                (7, EV_EFI_VARIABLE_DRIVER_CONFIG, [1; 32], b"db"),
                (7, EV_EFI_VARIABLE_AUTHORITY, [2; 32], b"Windows PCA"),
            ],
            &mut a,
        )
        .unwrap();
        let mut b = vec![0u8; 4096];
        let m = write(
            &[
                (7, EV_EFI_VARIABLE_DRIVER_CONFIG, [1; 32], b"db"),
                (7, EV_EFI_VARIABLE_AUTHORITY, [3; 32], b"UEFI CA + MOK"),
            ],
            &mut b,
        )
        .unwrap();
        // The authority events differ by boot path; the prediction must not.
        assert_eq!(secure_boot_config(&a[..n]), secure_boot_config(&b[..m]));
        let mut c = vec![0u8; 4096];
        let k = write(
            &[(7, EV_EFI_VARIABLE_DRIVER_CONFIG, [9; 32], b"dbx")],
            &mut c,
        )
        .unwrap();
        assert_ne!(secure_boot_config(&a[..n]), secure_boot_config(&c[..k]));
    }
}
