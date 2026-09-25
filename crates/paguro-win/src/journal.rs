//! Resumable multi-step operations (install, uninstall): a journal file per
//! operation under `%ProgramData%\paguro\journal\`, rewritten
//! (write-new-then-rename) after every step, so an interrupted run resumes
//! where it stopped and a finished step is never repeated.
//!
//! ```json
//! { "version": 1, "operation": "install", "key": "debian",
//!   "args": { … }, "started_unix": 0, "updated_unix": 0,
//!   "steps": [ { "id": "hw-export", "state": "done", "at_unix": 0,
//!                "detail": "…" } ] }
//! ```
//!
//! The journal holds no secrets: steps that need the passphrase ask for it
//! when they run.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::api::{WinApi, join};
use crate::esp::write_atomic;
use crate::out::CmdError;

pub const VERSION: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepState {
    Pending,
    Done,
    Skipped,
    Failed,
    /// Done up to a reboot; the next run finishes it.
    AwaitingReboot,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub id: String,
    pub state: StepState,
    pub at_unix: u64,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Journal {
    pub version: u32,
    pub operation: String,
    pub key: String,
    pub args: Value,
    pub started_unix: u64,
    pub updated_unix: u64,
    pub steps: Vec<Step>,
}

pub fn dir(api: &dyn WinApi) -> String {
    join(&api.program_data(), "paguro\\journal")
}

pub fn path(api: &dyn WinApi, operation: &str, key: &str) -> String {
    join(&dir(api), &format!("{operation}-{key}.json"))
}

impl Journal {
    pub fn new(api: &dyn WinApi, operation: &str, key: &str, args: Value, ids: &[&str]) -> Self {
        let now = api.now_unix();
        Journal {
            version: VERSION,
            operation: operation.into(),
            key: key.into(),
            args,
            started_unix: now,
            updated_unix: now,
            steps: ids
                .iter()
                .map(|id| Step {
                    id: (*id).into(),
                    state: StepState::Pending,
                    at_unix: 0,
                    detail: String::new(),
                })
                .collect(),
        }
    }

    /// The saved journal, or `None` when this operation has not started.
    pub fn load(api: &dyn WinApi, operation: &str, key: &str) -> Result<Option<Self>, CmdError> {
        let p = path(api, operation, key);
        let Some(b) = api.read_file(&p, 1 << 20)? else {
            return Ok(None);
        };
        let j: Journal =
            serde_json::from_slice(&b).map_err(|e| CmdError::refused(format!("{p}: {e}")))?;
        if j.version != VERSION || j.operation != operation {
            return Err(CmdError::refused(format!(
                "{p}: not a v{VERSION} {operation} journal"
            )));
        }
        Ok(Some(j))
    }

    pub fn save(&mut self, api: &dyn WinApi) -> Result<(), CmdError> {
        self.updated_unix = api.now_unix();
        api.create_dir_all(&dir(api))?;
        let body =
            serde_json::to_vec_pretty(self).map_err(|e| CmdError::internal(e.to_string()))?;
        write_atomic(api, &path(api, &self.operation, &self.key), &body)
    }

    pub fn state(&self, id: &str) -> Option<StepState> {
        self.steps.iter().find(|s| s.id == id).map(|s| s.state)
    }

    pub fn set(&mut self, api: &dyn WinApi, id: &str, state: StepState, detail: impl Into<String>) {
        let now = api.now_unix();
        if let Some(s) = self.steps.iter_mut().find(|s| s.id == id) {
            s.state = state;
            s.at_unix = now;
            s.detail = detail.into();
        }
    }

    pub fn finished(&self) -> bool {
        self.steps
            .iter()
            .all(|s| matches!(s.state, StepState::Done | StepState::Skipped))
    }

    pub fn remove(api: &dyn WinApi, operation: &str, key: &str) -> Result<(), CmdError> {
        api.remove_file(&path(api, operation, key))?;
        Ok(())
    }
}
