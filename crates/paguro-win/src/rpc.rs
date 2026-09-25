//! The one API of the Windows side (INTERFACES.md §11.7): JSON-RPC 2.0
//! methods, their parameters, their access, and the dispatch onto the
//! commands of [`crate::cmd`].
//!
//! The contract is `windows/api/paguro-api.json` (JSON Schema). The
//! parameter types here are hand-written and `tests/api_contract.rs` checks
//! them, [`METHODS`], and every method's real output against that schema;
//! the C# types are generated from it.
//!
//! Every front end goes through [`call`]: the service for its pipe clients,
//! and `paguro.exe` in direct mode (in-process), so a method behaves the
//! same whichever way it is reached.
//!
//! ```text
//! request  {"jsonrpc":"2.0","id":1,"method":"disk.create",
//!           "params":{"path":"C:\\paguro\\debian.vhd","size":"32G","dry_run":true}}
//! result   {"data":{…},"warnings":[…],"lines":[…],"exit":"ok"|"pending","dry_run":true}
//! error    {"code":-32003,"message":"…","data":{"code":"refused","exit":3,"data":{…}}}
//! notes    {"jsonrpc":"2.0","method":"progress","params":{"id":1,"operation":"install",…}}
//! ```
//!
//! Parameters common to every method: `dry_run`, `esp`, and the secrets
//! `linux_passphrase`, `pin`, `mok_password` (never logged, never echoed). A
//! method that needs a secret it was not given fails with
//! `data.data.needs_input` naming it; the front end asks the user and calls
//! again.

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::api::WinApi;
use crate::cmd::{
    checks, config, disk, distro, efi, esp, hw, install, mok, protection, secureboot, status,
    transition, uninstall,
};
use crate::ctx::{Ctx, Progress, Secret};
use crate::out::{CmdError, CmdResult, Exit, Report};

/// `paguro-api.json`'s `version`. Minor: methods or fields added; major:
/// removed or changed meaning.
pub const API_VERSION: &str = "1.0";
/// The named pipe (INTERFACES.md §11.7).
pub const PIPE: &str = r"\\.\pipe\paguro";
/// Its name (the part after `\\.\pipe\`).
pub const PIPE_NAME: &str = "paguro";
/// Largest request or response line on the pipe.
pub const MAX_MESSAGE: usize = 4 << 20;

/// Who may call a method (INTERFACES.md §11.7: "local administrators + the
/// interactive user (read-only methods)").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    /// Anyone the pipe admits: the interactive user.
    Read,
    /// A member of Administrators, elevated or not (the unelevated GUI of
    /// an administrator: "UAC only when the service is installed").
    Admin,
    /// An elevated administrator: the raw expert tools (firmware variables,
    /// boot entries, ESP files, MOK requests), which the GUI never uses.
    Elevated,
}

#[derive(Clone, Copy, Debug)]
pub struct Method {
    pub name: &'static str,
    pub access: Access,
    /// Parameters that need [`Access::Admin`] when set, on a `Read` method
    /// (a path the service would open as SYSTEM, a repair).
    pub gated: &'static [&'static str],
    /// A `dry_run` call needs only [`Access::Read`] (plans and summaries
    /// the GUI shows before asking for consent).
    pub dry_run_read: bool,
    /// Sends `progress` notifications.
    pub progress: bool,
    /// Parts of it are a stub (INTERFACES gaps, Linux side not built).
    pub stub: bool,
}

const fn m(name: &'static str, access: Access) -> Method {
    Method {
        name,
        access,
        gated: &[],
        dry_run_read: false,
        progress: false,
        stub: false,
    }
}

use Access::{Admin, Elevated, Read};

pub const METHODS: &[Method] = &[
    m("service.info", Read),
    m("status", Read),
    m("checks.list", Read),
    Method {
        dry_run_read: true,
        ..m("checks.fix", Admin)
    },
    m("hw.export", Read),
    m("hw.modalias", Read),
    m("disk.create", Admin),
    m("disk.inspect", Admin),
    m("config.show", Read),
    m("config.validate", Read),
    m("config.set", Admin),
    m("efi.vars.list", Read),
    m("efi.vars.get", Read),
    m("efi.vars.set", Elevated),
    m("efi.vars.delete", Elevated),
    m("efi.boot-entry.list", Read),
    m("efi.boot-entry.create", Elevated),
    m("efi.boot-entry.delete", Elevated),
    m("efi.bootnext", Elevated),
    m("esp.install", Elevated),
    m("esp.verify", Read),
    m("esp.repair", Admin),
    m("mok.enroll", Elevated),
    Method {
        gated: &["cert"],
        ..m("mok.status", Read)
    },
    Method {
        gated: &["repair"],
        ..m("preflight", Read)
    },
    Method {
        dry_run_read: true,
        ..m("restart-linux", Admin)
    },
    Method {
        dry_run_read: true,
        ..m("stage-setup", Admin)
    },
    Method {
        dry_run_read: true,
        ..m("repair", Admin)
    },
    Method {
        progress: true,
        stub: true,
        ..m("install", Admin)
    },
    Method {
        dry_run_read: true,
        progress: true,
        ..m("uninstall", Admin)
    },
    m("distro.list", Read),
    m("distro.rename", Admin),
    m("distro.remove", Admin),
    Method {
        stub: true,
        ..m("distro.grow", Admin)
    },
    Method {
        stub: true,
        ..m("distro.enter", Admin)
    },
    m("distro.leave", Admin),
    m("protection.options", Read),
    Method {
        stub: true,
        ..m("protection.set", Admin)
    },
    m("protection.check", Read),
    m("secure-boot.status", Read),
];

pub fn method(name: &str) -> Option<&'static Method> {
    METHODS.iter().find(|m| m.name == name)
}

/// The envelope's `command` for a method (`efi.boot-entry.list` →
/// `efi boot-entry list`): the CLI's subcommand path.
pub fn command_name(method: &str) -> String {
    method.replace('.', " ")
}

/// The pipe client, as the service identified it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Caller {
    pub user: String,
    /// Member of Administrators (possibly through a UAC-filtered token).
    pub admin: bool,
    /// Its token is elevated.
    pub elevated: bool,
    pub pid: Option<u32>,
}

impl Caller {
    /// The process itself (direct mode): what the OS lets it do.
    pub fn local(api: &dyn WinApi) -> Self {
        let e = api.is_elevated();
        Caller {
            user: String::new(),
            admin: e,
            elevated: e,
            pid: Some(std::process::id()),
        }
    }
    pub fn may(&self, a: Access) -> bool {
        match a {
            Access::Read => true,
            Access::Admin => self.admin || self.elevated,
            Access::Elevated => self.elevated,
        }
    }
}

pub struct Options<'a> {
    pub caller: Caller,
    /// Enforce [`Access`] (the service). Direct mode leaves it to the OS.
    pub enforce: bool,
    /// Commands may prompt on this process's console (direct mode).
    pub interactive: bool,
    pub passphrase_stdin: bool,
    /// Running inside the service (for `service.info`).
    pub service: bool,
    pub progress: Option<&'a dyn Fn(&Progress)>,
}

/// A JSON-RPC error object.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcError {
    pub code: i64,
    pub message: String,
    pub data: Value,
}

pub mod codes {
    pub const PARSE: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const INVALID_PARAMS: i64 = -32602;
    /// A command's error: `-32000 - exit` (refused = -32003, …).
    pub const COMMAND_BASE: i64 = -32000;
}

impl RpcError {
    pub fn new(code: i64, message: impl Into<String>) -> Self {
        RpcError {
            code,
            message: message.into(),
            data: Value::Null,
        }
    }
    pub fn to_json(&self) -> Value {
        let mut e = json!({ "code": self.code, "message": self.message });
        if !self.data.is_null() {
            if let Some(o) = e.as_object_mut() {
                o.insert("data".into(), self.data.clone());
            }
        }
        e
    }
    pub fn from_json(v: &Value) -> Self {
        RpcError {
            code: v
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or(codes::INVALID_REQUEST),
            message: v
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string(),
            data: v.get("data").cloned().unwrap_or(Value::Null),
        }
    }
}

impl From<CmdError> for RpcError {
    fn from(e: CmdError) -> Self {
        let mut data = json!({ "code": e.exit.name(), "exit": e.exit.code() });
        if let (Some(o), Some(d)) = (data.as_object_mut(), e.data) {
            o.insert("data".into(), d);
        }
        RpcError {
            code: codes::COMMAND_BASE - i64::from(e.exit.code()),
            message: e.message,
            data,
        }
    }
}

fn exit_from_name(s: &str) -> Option<Exit> {
    [
        Exit::Ok,
        Exit::Internal,
        Exit::Usage,
        Exit::Refused,
        Exit::NotFound,
        Exit::Platform,
        Exit::CheckFailed,
        Exit::NeedsElevation,
        Exit::Pending,
    ]
    .into_iter()
    .find(|e| e.name() == s)
}

/// Back to a command error, on the client side.
pub fn to_cmd_error(e: &RpcError) -> CmdError {
    let exit = match e.code {
        codes::INVALID_PARAMS | codes::METHOD_NOT_FOUND => Exit::Usage,
        codes::PARSE | codes::INVALID_REQUEST => Exit::Internal,
        _ => e
            .data
            .get("code")
            .and_then(Value::as_str)
            .and_then(exit_from_name)
            .unwrap_or(Exit::Internal),
    };
    CmdError {
        exit,
        message: e.message.clone(),
        data: e.data.get("data").cloned(),
    }
}

/// A successful method's `result`.
pub fn result_json(r: &Report, dry_run: bool) -> Value {
    json!({
        "data": r.data,
        "warnings": r.warnings,
        "lines": r.human,
        "exit": r.exit.name(),
        "dry_run": dry_run,
    })
}

/// Back to a report, on the client side.
pub fn to_report(v: &Value) -> Report {
    let strings = |k: &str| -> Vec<String> {
        v.get(k)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    Report {
        data: v.get("data").cloned().unwrap_or(Value::Null),
        human: strings("lines"),
        warnings: strings("warnings"),
        exit: v
            .get("exit")
            .and_then(Value::as_str)
            .and_then(exit_from_name)
            .unwrap_or(Exit::Ok),
    }
}

/// Parameters every method takes.
pub const COMMON: [&str; 5] = ["dry_run", "esp", "linux_passphrase", "pin", "mok_password"];

struct Common {
    dry_run: bool,
    esp: Option<String>,
    secrets: Vec<(Secret, Zeroizing<String>)>,
}

fn invalid(msg: impl Into<String>) -> RpcError {
    let msg = msg.into();
    RpcError {
        code: codes::INVALID_PARAMS,
        data: json!({ "code": Exit::Usage.name(), "exit": Exit::Usage.code() }),
        message: msg,
    }
}

fn split(params: &Value) -> Result<(Common, Map<String, Value>), RpcError> {
    let mut rest = match params {
        Value::Null => Map::new(),
        Value::Object(o) => o.clone(),
        _ => return Err(invalid("params must be an object")),
    };
    let dry_run = match rest.remove("dry_run") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => b,
        Some(_) => return Err(invalid("dry_run must be a boolean")),
    };
    let esp = match rest.remove("esp") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s),
        Some(_) => return Err(invalid("esp must be a string")),
    };
    let mut secrets = Vec::new();
    for s in [Secret::LinuxPassphrase, Secret::Pin, Secret::MokPassword] {
        match rest.remove(s.param()) {
            None | Some(Value::Null) => {}
            Some(Value::String(v)) => secrets.push((s, Zeroizing::new(v))),
            Some(_) => return Err(invalid(format!("{} must be a string", s.param()))),
        }
    }
    Ok((
        Common {
            dry_run,
            esp,
            secrets,
        },
        rest,
    ))
}

fn parse<T: DeserializeOwned>(rest: Map<String, Value>) -> Result<T, RpcError> {
    serde_json::from_value(Value::Object(rest)).map_err(|e| invalid(e.to_string()))
}

fn truthy(v: Option<&Value>) -> bool {
    !matches!(v, None | Some(Value::Null) | Some(Value::Bool(false)))
}

fn authorize(
    m: &Method,
    c: &Caller,
    dry_run: bool,
    rest: &Map<String, Value>,
) -> Result<(), RpcError> {
    let need = if dry_run && m.dry_run_read {
        Access::Read
    } else {
        m.access
    };
    let gated = m.gated.iter().find(|g| truthy(rest.get(**g)));
    let need = match (need, gated) {
        (Access::Read, Some(_)) => Access::Admin,
        (n, _) => n,
    };
    if c.may(need) {
        return Ok(());
    }
    let why = match (need, gated) {
        (Access::Elevated, _) => format!("{} needs an elevated administrator", m.name),
        (_, Some(g)) => format!("{} with {g} needs an administrator", m.name),
        _ => format!("{} needs an administrator", m.name),
    };
    Err(CmdError::new(Exit::NeedsElevation, why).into())
}

// ---------------------------------------------------------------------------
// Parameters (the `params` of each method, beyond the common ones)

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NoParams {}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Path {
    pub path: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiskCreate {
    pub path: String,
    pub size: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hardware {
    pub hardware: Value,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Name {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VarSet {
    pub name: String,
    pub hex: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub entry: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct BootNext {
    pub entry: Option<String>,
    pub clear: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EspInstall {
    pub shim: String,
    pub mm: String,
    pub loader: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MokEnroll {
    pub cert: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct MokStatus {
    pub cert: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Preflight {
    pub repair: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct RestartLinux {
    pub yes: bool,
    pub entry: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Repair {
    pub stage: bool,
    pub bootstrap: bool,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Uninstall {
    pub yes: bool,
    pub delete_images: bool,
    pub skip_final_boot: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CheckFix {
    pub id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistroRename {
    pub name: String,
    pub new_name: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistroRemove {
    pub name: String,
    #[serde(default)]
    pub delete_image: bool,
    #[serde(default)]
    pub yes: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DistroGrow {
    pub name: String,
    pub size: String,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct DistroTarget {
    pub name: Option<String>,
    pub path: Option<String>,
}

#[derive(Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ProtectionOptions {
    pub target: protection::Target,
    /// The front end's keyboard layout id (Windows `KLID`, `00000407`).
    pub klid: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectionCheck {
    pub keyboard: String,
}

// ---------------------------------------------------------------------------

/// Run `method` with `params` (a JSON object) against `api`.
pub fn call(
    api: &dyn WinApi,
    method: &str,
    params: &Value,
    o: &Options<'_>,
) -> Result<(Report, bool), RpcError> {
    let m = self::method(method)
        .ok_or_else(|| RpcError::new(codes::METHOD_NOT_FOUND, format!("no method {method:?}")))?;
    let (common, rest) = split(params)?;
    if o.enforce {
        authorize(m, &o.caller, common.dry_run, &rest)?;
    }
    let ctx = Ctx {
        api,
        dry_run: common.dry_run,
        esp: common.esp,
        passphrase_stdin: o.passphrase_stdin,
        interactive: o.interactive,
        secrets: common.secrets,
        progress: o.progress,
    };
    let dry = ctx.dry_run;
    let r = dispatch(&ctx, m, rest, o)?;
    Ok((r.map_err(RpcError::from)?, dry))
}

/// `Ok(Err(_))` is the command's own failure; `Err(_)` bad parameters.
fn dispatch(
    ctx: &Ctx<'_>,
    m: &Method,
    rest: Map<String, Value>,
    o: &Options<'_>,
) -> Result<CmdResult, RpcError> {
    let none = |rest: Map<String, Value>| parse::<NoParams>(rest).map(|_| ());
    Ok(match m.name {
        "service.info" => {
            none(rest)?;
            Ok(service_info(o))
        }
        "status" => {
            none(rest)?;
            status::status(ctx)
        }
        "checks.list" => {
            none(rest)?;
            checks::list(ctx)
        }
        "checks.fix" => checks::fix(ctx, &parse::<CheckFix>(rest)?.id),
        "hw.export" => {
            none(rest)?;
            hw::export(ctx, None)
        }
        "hw.modalias" => hw::modalias(ctx, &parse::<Hardware>(rest)?.hardware),
        "disk.create" => {
            let p: DiskCreate = parse(rest)?;
            disk::create(ctx, &p.path, &p.size)
        }
        "disk.inspect" => disk::inspect(ctx, &parse::<Path>(rest)?.path),
        "config.show" => {
            none(rest)?;
            config::show(ctx)
        }
        "config.validate" => {
            none(rest)?;
            config::validate(ctx)
        }
        "config.set" => config::set(ctx, &parse::<config::SetArgs>(rest)?),
        "efi.vars.list" => {
            none(rest)?;
            efi::vars_list(ctx)
        }
        "efi.vars.get" => efi::vars_get(ctx, &parse::<Name>(rest)?.name),
        "efi.vars.set" => {
            let p: VarSet = parse(rest)?;
            efi::vars_set(ctx, &p.name, &p.hex)
        }
        "efi.vars.delete" => efi::vars_delete(ctx, &parse::<Name>(rest)?.name),
        "efi.boot-entry.list" => {
            none(rest)?;
            efi::entries_list(ctx)
        }
        "efi.boot-entry.create" => {
            none(rest)?;
            efi::entry_create(ctx)
        }
        "efi.boot-entry.delete" => efi::entry_delete(ctx, &parse::<Entry>(rest)?.entry),
        "efi.bootnext" => {
            let p: BootNext = parse(rest)?;
            efi::bootnext(ctx, p.entry.as_deref(), p.clear)
        }
        "esp.install" => {
            let p: EspInstall = parse(rest)?;
            esp::install(ctx, &p.shim, &p.mm, &p.loader)
        }
        "esp.verify" => {
            none(rest)?;
            esp::verify(ctx)
        }
        "esp.repair" => {
            none(rest)?;
            esp::repair(ctx)
        }
        "mok.enroll" => mok::enroll(ctx, &parse::<MokEnroll>(rest)?.cert, false),
        "mok.status" => mok::status(ctx, parse::<MokStatus>(rest)?.cert.as_deref()),
        "preflight" => transition::preflight_cmd(ctx, parse::<Preflight>(rest)?.repair),
        "restart-linux" => {
            let p: RestartLinux = parse(rest)?;
            transition::restart_linux(ctx, p.entry.as_deref(), p.yes)
        }
        "stage-setup" => {
            none(rest)?;
            transition::stage_setup(ctx)
        }
        "repair" => {
            let p: Repair = parse(rest)?;
            transition::repair(ctx, p.stage, p.bootstrap)
        }
        "install" => install::install(ctx, &parse::<install::InstallArgs>(rest)?),
        "uninstall" => {
            let p: Uninstall = parse(rest)?;
            uninstall::uninstall(ctx, p.delete_images, p.skip_final_boot, p.yes)
        }
        "distro.list" => {
            none(rest)?;
            distro::list(ctx)
        }
        "distro.rename" => {
            let p: DistroRename = parse(rest)?;
            distro::rename(ctx, &p.name, &p.new_name)
        }
        "distro.remove" => {
            let p: DistroRemove = parse(rest)?;
            distro::remove(ctx, &p.name, p.delete_image, p.yes)
        }
        "distro.grow" => {
            let p: DistroGrow = parse(rest)?;
            distro::grow(ctx, &p.name, &p.size)
        }
        "distro.enter" => {
            let p: DistroTarget = parse(rest)?;
            distro::enter(ctx, p.name.as_deref(), p.path.as_deref())
        }
        "distro.leave" => {
            let p: DistroTarget = parse(rest)?;
            distro::leave(ctx, p.name.as_deref(), p.path.as_deref())
        }
        "protection.options" => {
            let p: ProtectionOptions = parse(rest)?;
            protection::options(ctx, p.target, p.klid.as_deref())
        }
        "protection.set" => protection::set(ctx, &parse::<protection::SetArgs>(rest)?),
        "protection.check" => protection::check(ctx, &parse::<ProtectionCheck>(rest)?.keyboard),
        "secure-boot.status" => {
            none(rest)?;
            secureboot::status(ctx)
        }
        other => {
            return Err(RpcError::new(
                codes::METHOD_NOT_FOUND,
                format!("no method {other:?}"),
            ));
        }
    })
}

fn service_info(o: &Options<'_>) -> Report {
    let methods: Vec<Value> = METHODS
        .iter()
        .filter(|m| o.caller.may(m.access))
        .map(|m| json!(m.name))
        .collect();
    Report::new(json!({
        "api_version": API_VERSION,
        "version": env!("CARGO_PKG_VERSION"),
        "service": o.service,
        "pipe": PIPE,
        "caller": o.caller,
        "methods": methods,
    }))
    .line(format!(
        "paguro API {API_VERSION} ({}), caller {} ({})",
        if o.service { "service" } else { "direct" },
        if o.caller.user.is_empty() {
            "this process"
        } else {
            &o.caller.user
        },
        if o.caller.elevated {
            "elevated administrator"
        } else if o.caller.admin {
            "administrator"
        } else {
            "read-only"
        }
    ))
}

/// One JSON-RPC notification.
pub fn notification(method: &str, params: Value) -> Value {
    json!({ "jsonrpc": "2.0", "method": method, "params": params })
}

/// A `progress` notification for request `id`.
pub fn progress_note(id: &Value, p: &Progress) -> Value {
    let mut v = serde_json::to_value(p).unwrap_or(Value::Null);
    if let Some(o) = v.as_object_mut() {
        o.insert("id".into(), id.clone());
    }
    notification("progress", v)
}

/// Serve one request line: the response line, or `None` for a
/// notification (no `id`). Notifications the call emits go to `note`.
pub fn handle_line(
    api: &dyn WinApi,
    line: &str,
    caller: &Caller,
    service: bool,
    note: &dyn Fn(&Value),
) -> Option<Value> {
    let req: Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            return Some(json!({ "jsonrpc": "2.0", "id": Value::Null,
                "error": RpcError::new(codes::PARSE, e.to_string()).to_json() }));
        }
    };
    let id = req.get("id").cloned();
    let bad = |msg: &str| {
        Some(
            json!({ "jsonrpc": "2.0", "id": id.clone().unwrap_or(Value::Null),
            "error": RpcError::new(codes::INVALID_REQUEST, msg).to_json() }),
        )
    };
    if req.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return bad("not a JSON-RPC 2.0 request");
    }
    let Some(method) = req.get("method").and_then(Value::as_str) else {
        return bad("no method");
    };
    let params = req.get("params").cloned().unwrap_or(Value::Null);
    let rid = id.clone().unwrap_or(Value::Null);
    let prog = |p: &Progress| note(&progress_note(&rid, p));
    let o = Options {
        caller: caller.clone(),
        enforce: true,
        interactive: false,
        passphrase_stdin: false,
        service,
        progress: Some(&prog),
    };
    let out = call(api, method, &params, &o);
    let id = id?;
    Some(match out {
        Ok((r, dry)) => json!({ "jsonrpc": "2.0", "id": id, "result": result_json(&r, dry) }),
        Err(e) => json!({ "jsonrpc": "2.0", "id": id, "error": e.to_json() }),
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mock::MockApi;

    fn user() -> Caller {
        Caller {
            user: "u".into(),
            admin: false,
            elevated: false,
            pid: None,
        }
    }

    fn line(api: &MockApi, c: &Caller, v: Value) -> Value {
        handle_line(api, &v.to_string(), c, true, &|_| {}).unwrap()
    }

    #[test]
    fn methods_are_unique_and_named_like_commands() {
        for (i, a) in METHODS.iter().enumerate() {
            assert!(
                METHODS[i + 1..].iter().all(|b| b.name != a.name),
                "{}",
                a.name
            );
            assert!(
                a.name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c == '.' || c == '-')
            );
        }
    }

    #[test]
    fn access_policy() {
        let m = MockApi::standard();
        let u = user();
        let admin = Caller {
            admin: true,
            ..user()
        };
        let r = line(
            &m,
            &u,
            json!({"jsonrpc":"2.0","id":1,"method":"config.set","params":{"tpm":false}}),
        );
        assert_eq!(r["error"]["code"], codes::COMMAND_BASE - 7);
        assert_eq!(r["error"]["data"]["code"], "needs_elevation");
        // dry-run plans are readable where the GUI shows them.
        let r = line(
            &m,
            &u,
            json!({"jsonrpc":"2.0","id":2,"method":"uninstall","params":{"dry_run":true}}),
        );
        assert!(r.get("result").is_some(), "{r}");
        // A gated parameter.
        let r = line(
            &m,
            &u,
            json!({"jsonrpc":"2.0","id":3,"method":"preflight","params":{"repair":true}}),
        );
        assert_eq!(r["error"]["data"]["code"], "needs_elevation");
        let r = line(
            &m,
            &u,
            json!({"jsonrpc":"2.0","id":3,"method":"preflight","params":{"repair":false}}),
        );
        assert!(r["error"]["data"]["code"] != "needs_elevation", "{r}");
        // Raw firmware writes need elevation even for an administrator.
        let r = line(
            &m,
            &admin,
            json!({"jsonrpc":"2.0","id":4,"method":"efi.vars.delete","params":{"name":"PaguroSetup"}}),
        );
        assert_eq!(r["error"]["data"]["code"], "needs_elevation");
        assert!(
            m.mutations
                .borrow()
                .iter()
                .all(|x| !x.contains("PaguroSetup"))
        );
    }

    #[test]
    fn protocol_errors() {
        let m = MockApi::standard();
        let u = user();
        let r = handle_line(&m, "{not json", &u, true, &|_| {}).unwrap();
        assert_eq!(r["error"]["code"], codes::PARSE);
        let r = line(&m, &u, json!({"id":1,"method":"status"}));
        assert_eq!(r["error"]["code"], codes::INVALID_REQUEST);
        let r = line(&m, &u, json!({"jsonrpc":"2.0","id":1,"method":"nope"}));
        assert_eq!(r["error"]["code"], codes::METHOD_NOT_FOUND);
        let r = line(
            &m,
            &u,
            json!({"jsonrpc":"2.0","id":1,"method":"status","params":{"bogus":1}}),
        );
        assert_eq!(r["error"]["code"], codes::INVALID_PARAMS);
        let r = line(
            &m,
            &u,
            json!({"jsonrpc":"2.0","id":1,"method":"status","params":[1]}),
        );
        assert_eq!(r["error"]["code"], codes::INVALID_PARAMS);
        // A notification gets no response.
        assert!(
            handle_line(
                &m,
                r#"{"jsonrpc":"2.0","method":"status"}"#,
                &u,
                true,
                &|_| {}
            )
            .is_none()
        );
    }

    #[test]
    fn a_missing_secret_is_asked_back() {
        let m = MockApi::standard();
        let admin = Caller {
            admin: true,
            ..user()
        };
        crate::cmd::protection::tests_support::bitlocker_tpm(&m);
        let r = line(
            &m,
            &admin,
            json!({"jsonrpc":"2.0","id":1,"method":"protection.set","params":{"choice":"passphrase"}}),
        );
        assert_eq!(r["error"]["data"]["data"]["needs_input"], "pin", "{r}");
        assert_eq!(r["error"]["data"]["data"]["confirm"], true);
        let r = line(
            &m,
            &admin,
            json!({"jsonrpc":"2.0","id":1,"method":"protection.set","params":{"choice":"passphrase","pin":"correct horse"}}),
        );
        assert_eq!(r["result"]["data"]["choice"], "passphrase", "{r}");
    }

    #[test]
    fn roundtrip_to_client_types() {
        let r = Report::new(json!({"a":1}))
            .line("x")
            .warn("w")
            .exit(Exit::Pending);
        let back = to_report(&result_json(&r, true));
        assert_eq!(back, r);
        let e = CmdError::refused("no").with_data(json!({"k":2}));
        let back = to_cmd_error(&RpcError::from(e.clone()));
        assert_eq!(back, e);
    }
}
