//! Output: the versioned `--json` envelope, human text, and exit codes.
//!
//! Every command returns a [`Report`] or a [`CmdError`]. With `--json`, stdout
//! carries exactly one JSON document:
//!
//! ```json
//! { "schema": "paguro-cli/1", "command": "disk create", "ok": true,
//!   "dry_run": false, "data": { … }, "warnings": [ … ] }
//! { "schema": "paguro-cli/1", "command": "disk create", "ok": false,
//!   "error": { "code": "refused", "message": "…", "exit": 3 } }
//! ```
//!
//! `schema` is bumped when a field is removed or changes meaning; adding a
//! field is not a bump. The per-command `data` shapes are documented in
//! `crates/paguro-win/JSON.md`. **Secrets never appear in either form**: the
//! VMK, the passphrase, `S`, the MOK private key. The one exception by
//! design is `mok enroll`'s generated one-time password, which exists to be
//! shown and is useless after the next boot.

use std::fmt;

use paguro_core::guid::Guid;
use serde::{Serialize, Serializer};
use serde_json::{Value, json};

use crate::api::ApiError;

pub const SCHEMA: &str = "paguro-cli/1";

static NULL: Value = Value::Null;

/// `value.at("key")`: a field, or `null` — JSON lookups that cannot panic.
pub trait At {
    fn at(&self, key: &str) -> &Value;
}

impl At for Value {
    fn at(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

/// Process exit codes. Stable: scripts and the PowerShell module rely on them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Exit {
    Ok = 0,
    /// A bug: an invariant the tool relies on did not hold.
    Internal = 1,
    /// Bad arguments (clap's own code).
    Usage = 2,
    /// A precondition or safety check refused the operation; nothing changed.
    Refused = 3,
    NotFound = 4,
    /// An OS call failed.
    Platform = 5,
    /// `verify`/`validate`/pre-flight found problems; nothing changed.
    CheckFailed = 6,
    /// Needs an elevated (administrator) process.
    NeedsElevation = 7,
    /// The operation is half done and can be resumed by running it again
    /// (uninstall waiting for its reboot, an install step pending).
    Pending = 8,
}

impl Exit {
    pub const fn code(self) -> i32 {
        self as i32
    }
    pub const fn name(self) -> &'static str {
        match self {
            Exit::Ok => "ok",
            Exit::Internal => "internal",
            Exit::Usage => "usage",
            Exit::Refused => "refused",
            Exit::NotFound => "not_found",
            Exit::Platform => "platform",
            Exit::CheckFailed => "check_failed",
            Exit::NeedsElevation => "needs_elevation",
            Exit::Pending => "pending",
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CmdError {
    pub exit: Exit,
    pub message: String,
    /// Extra structured detail (e.g. the failing checks).
    pub data: Option<Value>,
}

impl CmdError {
    pub fn new(exit: Exit, message: impl Into<String>) -> Self {
        CmdError {
            exit,
            message: message.into(),
            data: None,
        }
    }
    pub fn refused(message: impl Into<String>) -> Self {
        Self::new(Exit::Refused, message)
    }
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(Exit::NotFound, message)
    }
    pub fn check_failed(message: impl Into<String>, data: Value) -> Self {
        CmdError {
            exit: Exit::CheckFailed,
            message: message.into(),
            data: Some(data),
        }
    }
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(Exit::Internal, message)
    }
    pub fn with_data(mut self, data: Value) -> Self {
        self.data = Some(data);
        self
    }
}

impl fmt::Display for CmdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<ApiError> for CmdError {
    fn from(e: ApiError) -> Self {
        use crate::api::ErrorKind as K;
        let exit = match e.kind {
            K::NotFound => Exit::NotFound,
            K::AccessDenied => Exit::NeedsElevation,
            K::Unsupported => Exit::Refused,
            K::InvalidData | K::Other => Exit::Platform,
        };
        CmdError::new(exit, e.to_string())
    }
}

pub type CmdResult = Result<Report, CmdError>;

/// A command's successful result.
#[derive(Clone, Debug, PartialEq)]
pub struct Report {
    pub data: Value,
    /// Human-readable lines for the non-JSON form.
    pub human: Vec<String>,
    pub warnings: Vec<String>,
    /// The exit code for a *successful* run: normally `Ok`, `Pending` when
    /// the run must be resumed later.
    pub exit: Exit,
}

impl Report {
    pub fn new(data: Value) -> Self {
        Report {
            data,
            human: Vec::new(),
            warnings: Vec::new(),
            exit: Exit::Ok,
        }
    }
    pub fn line(mut self, s: impl Into<String>) -> Self {
        self.human.push(s.into());
        self
    }
    pub fn lines(mut self, it: impl IntoIterator<Item = String>) -> Self {
        self.human.extend(it);
        self
    }
    pub fn warn(mut self, s: impl Into<String>) -> Self {
        self.warnings.push(s.into());
        self
    }
    pub fn exit(mut self, e: Exit) -> Self {
        self.exit = e;
        self
    }
}

/// The rendered form of a command's result.
pub struct Rendered {
    pub stdout: String,
    pub stderr: String,
    pub code: i32,
}

pub fn render(command: &str, dry_run: bool, json: bool, r: &CmdResult) -> Rendered {
    match (r, json) {
        (Ok(rep), true) => {
            let v = json!({
                "schema": SCHEMA,
                "command": command,
                "ok": true,
                "dry_run": dry_run,
                "data": rep.data,
                "warnings": rep.warnings,
            });
            Rendered {
                stdout: pretty(&v),
                stderr: String::new(),
                code: rep.exit.code(),
            }
        }
        (Err(e), true) => {
            let mut err = json!({
                "code": e.exit.name(),
                "message": e.message,
                "exit": e.exit.code(),
            });
            if let (Some(d), Some(o)) = (&e.data, err.as_object_mut()) {
                o.insert("data".into(), d.clone());
            }
            let v = json!({
                "schema": SCHEMA,
                "command": command,
                "ok": false,
                "dry_run": dry_run,
                "error": err,
            });
            Rendered {
                stdout: pretty(&v),
                stderr: String::new(),
                code: e.exit.code(),
            }
        }
        (Ok(rep), false) => {
            let mut s = String::new();
            if dry_run {
                s.push_str("(dry run: nothing was changed)\n");
            }
            for l in &rep.human {
                s.push_str(l);
                s.push('\n');
            }
            let mut w = String::new();
            for l in &rep.warnings {
                w.push_str("warning: ");
                w.push_str(l);
                w.push('\n');
            }
            Rendered {
                stdout: s,
                stderr: w,
                code: rep.exit.code(),
            }
        }
        (Err(e), false) => {
            let mut s = format!("paguro {command}: {}\n", e.message);
            if let Some(d) = &e.data {
                s.push_str(&pretty(d));
            }
            Rendered {
                stdout: String::new(),
                stderr: s,
                code: e.exit.code(),
            }
        }
    }
}

fn pretty(v: &Value) -> String {
    let mut s = serde_json::to_string_pretty(v).unwrap_or_else(|_| "{}".into());
    s.push('\n');
    s
}

/// Lower-case hex.
pub fn to_hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

/// Parse hex (either case, no separators).
pub fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|p| u8::from_str_radix(p, 16).ok()))
        .collect()
}

pub fn guid_text(g: &Guid) -> String {
    String::from_utf8_lossy(&g.to_text()).into_owned()
}

pub fn hex<S: Serializer>(b: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&to_hex(b))
}

pub fn opt_guid<S: Serializer>(g: &Option<Guid>, s: S) -> Result<S::Ok, S::Error> {
    match g {
        Some(g) => s.serialize_str(&guid_text(g)),
        None => s.serialize_none(),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn envelope_shapes() {
        let ok: CmdResult = Ok(Report::new(json!({"x": 1})).warn("w"));
        let r = render("status", false, true, &ok);
        let v: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(v["schema"], SCHEMA);
        assert_eq!(v["ok"], true);
        assert_eq!(v["data"]["x"], 1);
        assert_eq!(v["warnings"][0], "w");
        assert_eq!(r.code, 0);
        let e: CmdResult = Err(CmdError::refused("no").with_data(json!([1])));
        let r = render("disk create", true, true, &e);
        let v: Value = serde_json::from_str(&r.stdout).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["dry_run"], true);
        assert_eq!(v["error"]["code"], "refused");
        assert_eq!(v["error"]["exit"], 3);
        assert_eq!(v["error"]["data"][0], 1);
        assert_eq!(r.code, 3);
        let r = render("disk create", false, false, &e);
        assert!(r.stderr.starts_with("paguro disk create: no"));
    }

    #[test]
    fn hex_roundtrip() {
        assert_eq!(to_hex(&[0, 0xab]), "00ab");
        assert_eq!(from_hex("00AB"), Some(vec![0, 0xab]));
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("é1"), None);
    }
}
