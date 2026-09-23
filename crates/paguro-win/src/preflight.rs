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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// The seal will unseal: write the PIN bypass and restart.
    Restart,
    /// The seal will not unseal: prompt for the Linux passphrase in Windows,
    /// stage a one-shot `setupTPM`, then restart.
    StageSetupTpm(Reason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Firmware,
    SecureBootDatabases,
    Loader,
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
}
