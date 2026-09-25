//! What every command gets: the platform and the global flags.

use serde::Serialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::api::{Volume, WinApi, join};
use crate::esp;
use crate::out::{CmdError, Exit};

pub struct Ctx<'a> {
    pub api: &'a dyn WinApi,
    /// Plan and report; change nothing.
    pub dry_run: bool,
    /// `--esp`: an explicit ESP volume path.
    pub esp: Option<String>,
    /// `--passphrase-stdin`: read the passphrase from standard input.
    pub passphrase_stdin: bool,
    /// May prompt on this process's console. `false` in the service: a
    /// secret it needs and was not given is asked back from the client
    /// (a `needs_input` refusal, see [`Ctx::secret`]).
    pub interactive: bool,
    /// Secrets the request carried, by name ([`Secret`]).
    pub secrets: Vec<(Secret, Zeroizing<String>)>,
    /// Step progress of long operations (install, uninstall), for the
    /// service's `progress` notifications.
    pub progress: Option<&'a dyn Fn(&Progress)>,
}

/// A secret a command may need, and the request parameter that carries it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Secret {
    /// The user's Linux passphrase (stage-setup, repair, install).
    LinuxPassphrase,
    /// The PIN or passphrase chosen on the protection screen.
    Pin,
    /// MokManager's one-time password, when the caller chooses it.
    MokPassword,
}

impl Secret {
    pub const fn param(self) -> &'static str {
        match self {
            Secret::LinuxPassphrase => "linux_passphrase",
            Secret::Pin => "pin",
            Secret::MokPassword => "mok_password",
        }
    }
}

/// One step of a long operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Progress {
    pub operation: &'static str,
    pub step: String,
    /// `running`, then one of the journal's states.
    pub state: String,
    pub index: usize,
    pub total: usize,
    pub detail: String,
}

/// Longest passphrase accepted (UTF-8 bytes).
pub const MAX_PASSPHRASE: usize = 1024;

impl<'a> Ctx<'a> {
    pub fn new(api: &'a dyn WinApi) -> Self {
        Ctx {
            api,
            dry_run: false,
            esp: None,
            passphrase_stdin: false,
            interactive: true,
            secrets: Vec::new(),
            progress: None,
        }
    }

    /// Report a step of a long operation (nothing without a sink).
    pub fn step(&self, operation: &'static str, index: usize, total: usize, step: &str, state: &str, detail: &str) {
        if let Some(p) = self.progress {
            p(&Progress {
                operation,
                step: step.into(),
                state: state.into(),
                index,
                total,
                detail: detail.into(),
            });
        }
    }

    /// A secret the request carried; `None` when it did not.
    pub fn given(&self, which: Secret) -> Option<&Zeroizing<String>> {
        self.secrets.iter().find(|(k, _)| *k == which).map(|(_, v)| v)
    }

    /// The refusal that asks the client for a secret and to call again.
    pub fn needs_input(which: Secret, prompt: &str, confirm: bool) -> CmdError {
        CmdError::refused(format!("{prompt}: not given (pass it as `{}`)", which.param()))
            .with_data(json!({ "needs_input": which, "param": which.param(), "prompt": prompt, "confirm": confirm }))
    }

    /// A secret: from the request, from standard input, or typed at the
    /// console (twice when `confirm`, since nothing can verify it).
    pub fn secret(&self, which: Secret, what: &str, confirm: bool) -> Result<Zeroizing<String>, CmdError> {
        let s = if let Some(s) = self.given(which) {
            s.clone()
        } else if self.passphrase_stdin {
            let raw = self.api.read_stdin(MAX_PASSPHRASE + "\r\n".len())?;
            let t = std::str::from_utf8(&raw)
                .map_err(|_| CmdError::refused(format!("{what}: not UTF-8")))?;
            Zeroizing::new(t.trim_end_matches(['\r', '\n']).to_string())
        } else if !self.interactive {
            return Err(Self::needs_input(which, what, confirm));
        } else {
            let a = self.api.read_secret(&format!("{what}: "))?;
            if confirm {
                let b = self.api.read_secret(&format!("{what} (again): "))?;
                if *a != *b {
                    return Err(CmdError::refused("the two entries differ"));
                }
            }
            a
        };
        if s.is_empty() {
            return Err(CmdError::refused(format!("{what}: empty")));
        }
        if s.len() > MAX_PASSPHRASE {
            return Err(CmdError::refused(format!("{what}: too long")));
        }
        Ok(s)
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
        self.secret(Secret::LinuxPassphrase, what, true)
    }
}
