//! What every command gets: the platform and the global flags.

use zeroize::Zeroizing;

use crate::api::{Volume, WinApi, join};
use crate::esp;
use crate::out::{CmdError, Exit};

pub struct Ctx<'a> {
    pub api: &'a dyn WinApi,
    /// Plan and report; change nothing.
    pub dry_run: bool,
    /// Consent to the irreversible step (a restart, deleting images).
    pub yes: bool,
    /// `--esp`: an explicit ESP volume path.
    pub esp: Option<String>,
    /// `--passphrase-stdin`: read the passphrase from standard input.
    pub passphrase_stdin: bool,
}

/// Longest passphrase accepted (UTF-8 bytes).
pub const MAX_PASSPHRASE: usize = 1024;

impl<'a> Ctx<'a> {
    pub fn new(api: &'a dyn WinApi) -> Self {
        Ctx {
            api,
            dry_run: false,
            yes: false,
            esp: None,
            passphrase_stdin: false,
        }
    }

    pub fn need_admin(&self) -> Result<(), CmdError> {
        if self.api.is_elevated() {
            Ok(())
        } else {
            Err(CmdError::new(
                Exit::NeedsElevation,
                "this needs an elevated (administrator) prompt",
            ))
        }
    }

    pub fn need_uefi(&self) -> Result<(), CmdError> {
        if self.api.firmware_is_uefi() {
            Ok(())
        } else {
            Err(CmdError::refused(
                "this machine boots in legacy BIOS mode; paguro needs UEFI",
            ))
        }
    }

    pub fn esp(&self) -> Result<Volume, CmdError> {
        esp::find(self.api, self.esp.as_deref())
    }

    /// `%ProgramData%\paguro`.
    pub fn data_dir(&self) -> String {
        join(&self.api.program_data(), "paguro")
    }

    /// The user's Linux passphrase. It is never verified here — there is no
    /// oracle by design (DESIGN.md §6) — so interactive entry asks twice.
    pub fn passphrase(&self, what: &str) -> Result<Zeroizing<String>, CmdError> {
        let s = if self.passphrase_stdin {
            let raw = self.api.read_stdin(MAX_PASSPHRASE + 2)?;
            let t = std::str::from_utf8(&raw)
                .map_err(|_| CmdError::refused("the passphrase is not UTF-8"))?;
            Zeroizing::new(t.trim_end_matches(['\r', '\n']).to_string())
        } else {
            let a = self.api.read_secret(&format!("{what}: "))?;
            let b = self.api.read_secret(&format!("{what} (again): "))?;
            if *a != *b {
                return Err(CmdError::refused("the two entries differ"));
            }
            a
        };
        if s.is_empty() {
            return Err(CmdError::refused("the passphrase is empty"));
        }
        if s.len() > MAX_PASSPHRASE {
            return Err(CmdError::refused("the passphrase is too long"));
        }
        Ok(s)
    }
}
