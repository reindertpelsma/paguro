//! The `paguro` command line (INTERFACES.md §11.2, §11.7).
//!
//! Every command is one method of the API ([`crate::rpc`]): the command line
//! is turned into a request, the request runs — in the service when one is
//! installed (`\\.\pipe\paguro`), in this process otherwise or with
//! `--direct` — and the result is rendered. Both paths run the same
//! [`rpc::call`], so they cannot disagree. What only a front end can do
//! stays here: reading and writing the caller's own files, prompting for a
//! secret the service asks back for, and running an interactive shell.
//!
//! Direct-only: `paguro service install|uninstall|start|stop` (the service
//! cannot install itself).

use std::cell::RefCell;

use clap::{Args, Parser, Subcommand, ValueEnum};
use serde_json::{Map, Value, json};

use crate::api::WinApi;
use crate::cmd::{hw, install, service};
use crate::ctx::Ctx;
use crate::out::{self, At, CmdError, CmdResult, Exit, Rendered, Report};
use crate::rpc::{self, RpcError};

#[derive(Parser, Debug)]
#[command(
    name = "paguro",
    version,
    about = "paguro on Windows: disks, ESP, firmware, and the way into Linux"
)]
pub struct Cli {
    /// One JSON document on stdout (schema paguro-cli/1), for scripts.
    #[arg(long, global = true)]
    pub json: bool,
    /// Report what would change; change nothing.
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// The EFI System Partition to use (a \\?\Volume{…}\ path) when there are several.
    #[arg(long, global = true, value_name = "VOLUME")]
    pub esp: Option<String>,
    /// Read a secret the command needs (the Linux passphrase, a PIN) from standard input instead of prompting.
    #[arg(long, global = true)]
    pub passphrase_stdin: bool,
    /// Run in this process even when the paguro service is installed.
    #[arg(long, global = true)]
    pub direct: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Volumes, BitLocker, images, ESP, firmware variables, MOK, WSL2, pre-flight.
    Status,
    /// The installer's checks, each explained and fixable (INTERFACES §11.8).
    Checks {
        #[command(subcommand)]
        cmd: ChecksCmd,
    },
    /// Host hardware export for the installer (INTERFACES §11.5).
    Hw {
        #[command(subcommand)]
        cmd: HwCmd,
    },
    /// Fixed-VHD image files.
    Disk {
        #[command(subcommand)]
        cmd: DiskCmd,
    },
    /// paguro.ini: the only editor (INTERFACES §3).
    Config {
        #[command(subcommand)]
        cmd: ConfigCmd,
    },
    /// paguro's firmware variables and boot entries.
    Efi {
        #[command(subcommand)]
        cmd: EfiCmd,
    },
    /// shim, MokManager and paguro.efi on the ESP.
    Esp {
        #[command(subcommand)]
        cmd: EspCmd,
    },
    /// Machine Owner Key enrolment through shim.
    Mok {
        #[command(subcommand)]
        cmd: MokCmd,
    },
    /// What the Secure Boot step will do (MokManager, db).
    SecureBoot {
        #[command(subcommand)]
        cmd: SecureBootCmd,
    },
    /// How Linux unlocks: TPM + PIN, passphrase, TPM only (DESIGN §8d).
    Protection {
        #[command(subcommand)]
        cmd: ProtectionCmd,
    },
    /// Bootable images and WSL2 distributions.
    Distro {
        #[command(subcommand)]
        cmd: DistroCmd,
    },
    /// Check everything the next Linux boot depends on (DESIGN §4.6).
    Preflight {
        /// Also fix what can be fixed (ESP files, boot entry).
        #[arg(long)]
        repair: bool,
    },
    /// Pre-flight, PIN bypass or setupTPM staging, BootNext, restart.
    RestartLinux {
        /// Actually restart (otherwise everything but the restart).
        #[arg(long)]
        yes: bool,
        /// Boot this [Boot.*] entry once instead of the default (or disk:<Boot#### hex>).
        #[arg(long)]
        entry: Option<String>,
    },
    /// Stage a one-shot setupTPM for the next boot (asks for the Linux passphrase).
    StageSetup,
    /// Re-install ESP files and the boot entry; stage or bootstrap when needed (DESIGN §7).
    Repair {
        /// Stage setupTPM if the TPM seal is predicted to fail.
        #[arg(long)]
        stage: bool,
        /// Re-run the bootstrap (after a firmware NVRAM clear).
        #[arg(long)]
        bootstrap: bool,
    },
    /// Build a distribution image through WSL2 and make it bootable (INTERFACES §11.4).
    Install(Box<InstallCli>),
    /// Remove paguro (DESIGN §6b); resumable, two phases around a reboot.
    Uninstall {
        #[arg(long)]
        yes: bool,
        /// Also delete the image files paguro.ini names.
        #[arg(long)]
        delete_images: bool,
        /// Do not boot once through paguro to remove PaguroB and the machine key.
        #[arg(long)]
        skip_final_boot: bool,
    },
    /// The paguro service: its API, and installing it.
    Service {
        #[command(subcommand)]
        cmd: ServiceCmd,
    },
}

#[derive(Subcommand, Debug)]
pub enum ChecksCmd {
    List,
    /// Fix one check where Windows allows it (wsl2, fast_startup, bitlocker).
    Fix {
        id: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum HwCmd {
    /// Write host-hardware.json (or print it).
    Export {
        #[arg(long, short)]
        output: Option<String>,
    },
    /// The modaliases an export presents to the installer.
    Modalias { input: String },
}

#[derive(Subcommand, Debug)]
pub enum DiskCmd {
    /// Create a fixed, fully allocated VHD and verify it.
    Create {
        #[arg(long)]
        size: String,
        #[arg(long)]
        path: String,
    },
    /// Format, extents, attributes and the UEFI file system of a disk file.
    Inspect { path: String },
}

#[derive(Subcommand, Debug)]
pub enum ConfigCmd {
    Show,
    /// Parse, check the firmware hash and that the named files exist.
    Validate,
    /// Change entries or settings; writes paguro.ini and PaguroConfigHash.
    Set(Box<SetCli>),
}

#[derive(Args, Debug, Default)]
pub struct SetCli {
    /// The [Boot.NAME] entry to add or change.
    #[arg(long)]
    pub entry: Option<String>,
    /// GPT partition GUID of the entry's NTFS volume (implied by Windows paths).
    #[arg(long)]
    pub volume: Option<String>,
    /// The Linux root disk: C:\… or \path on the volume.
    #[arg(long)]
    pub root: Option<String>,
    #[arg(long)]
    pub efi_disk: Option<String>,
    /// FAT path of the UEFI image on efi_disk.
    #[arg(long)]
    pub efi: Option<String>,
    /// A UEFI image directly on NTFS (excludes --efi-disk/--efi).
    #[arg(long)]
    pub efi_file: Option<String>,
    #[arg(long)]
    pub default: Option<String>,
    #[arg(long, value_name = "NAME")]
    pub remove_entry: Option<String>,
    #[arg(long, value_name = "0|1")]
    pub tpm: Option<String>,
    #[arg(long, value_name = "0|1")]
    pub setup_tpm: Option<String>,
    #[arg(long, value_name = "0|1")]
    pub passphrase: Option<String>,
    #[arg(long)]
    pub theme: Option<String>,
    #[arg(long)]
    pub mode: Option<String>,
    /// [UI] keyboard: the layout secrets are typed in at boot (us, de, fr, …).
    #[arg(long)]
    pub keyboard: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum EfiCmd {
    Vars {
        #[command(subcommand)]
        cmd: VarsCmd,
    },
    BootEntry {
        #[command(subcommand)]
        cmd: EntryCmd,
    },
    /// Set BootNext (default: paguro's entry) or clear it.
    Bootnext {
        entry: Option<String>,
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum VarsCmd {
    List,
    Get { name: String },
    Set { name: String, hex: String },
    Delete { name: String },
}

#[derive(Subcommand, Debug)]
pub enum EntryCmd {
    List,
    /// Create or repair paguro's entry (appended to BootOrder).
    Create,
    Delete {
        entry: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum EspCmd {
    Install {
        /// A distribution's Microsoft-signed shim (unchanged).
        #[arg(long)]
        shim: String,
        /// Its MokManager.
        #[arg(long)]
        mm: String,
        /// paguro.efi, signed with the machine key.
        #[arg(long)]
        loader: String,
    },
    Verify,
    Repair,
}

#[derive(Subcommand, Debug)]
pub enum MokCmd {
    /// Request enrolment of a DER certificate (MokNew/MokAuth).
    Enroll {
        #[arg(long)]
        cert: String,
        /// Read the one-time password from stdin instead of generating one.
        #[arg(long)]
        password_stdin: bool,
    },
    Status {
        #[arg(long)]
        cert: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum SecureBootCmd {
    Status,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum TargetArg {
    Image,
    Disk,
}

#[derive(Subcommand, Debug)]
pub enum ProtectionCmd {
    /// The choices offered on this machine, and why.
    Options {
        #[arg(long, value_enum, default_value = "image")]
        target: TargetArg,
        /// The keyboard layout to suggest, as a Windows KLID (00000407).
        #[arg(long)]
        klid: Option<String>,
    },
    /// Choose: tpm_pin, passphrase, tpm_only (asks for the PIN or passphrase).
    Set {
        choice: String,
        /// The layout it is typed in at boot.
        #[arg(long, default_value = "us")]
        keyboard: String,
        /// Always ask for the PIN, also after "Restart into Linux".
        #[arg(long)]
        no_pin_bypass: bool,
        #[arg(long, value_enum, default_value = "image")]
        target: TargetArg,
    },
    /// Check that a PIN or passphrase can be typed at boot on a layout.
    Check {
        #[arg(long, default_value = "us")]
        keyboard: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum DistroCmd {
    List,
    Rename {
        name: String,
        new_name: String,
    },
    /// Remove an entry (and with --delete-image its disk file).
    Remove {
        name: String,
        #[arg(long)]
        delete_image: bool,
        #[arg(long)]
        yes: bool,
    },
    /// STUB: needs the Linux side (DESIGN §5.6).
    Grow {
        name: String,
        #[arg(long)]
        size: String,
    },
    /// Attach an image (or any .vhd/.vhdx) to WSL2 and open a root shell.
    Enter {
        name: Option<String>,
        #[arg(long)]
        path: Option<String>,
        /// Only attach; do not start the shell.
        #[arg(long)]
        no_shell: bool,
    },
    /// Detach it again.
    Leave {
        name: Option<String>,
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// The API version, and what this caller may do.
    Info,
    /// Register and start paguro-service.exe (direct mode, elevated).
    Install {
        /// Default: paguro-service.exe next to paguro.exe.
        #[arg(long)]
        exe: Option<String>,
    },
    Uninstall,
    Start,
    Stop,
}

#[derive(Args, Debug)]
pub struct InstallCli {
    pub distro: String,
    #[arg(long)]
    pub path: String,
    #[arg(long, default_value = "32G")]
    pub size: String,
    /// The distribution's ISO: its own installer in a WSL2 container.
    #[arg(long, conflicts_with_all = ["script", "from_wsl"])]
    pub iso: Option<String>,
    /// Make this WSL2 distribution bootable on the metal.
    #[arg(long, conflicts_with = "script")]
    pub from_wsl: Option<String>,
    /// The scripted fallback: a script run as root inside WSL2.
    #[arg(long)]
    pub script: Option<String>,
    /// Manual mode: attach the disk and open a root shell; finish with --finish.
    #[arg(long)]
    pub shell: bool,
    /// Check what was built by hand and complete the install.
    #[arg(long, conflicts_with = "shell")]
    pub finish: bool,
    #[arg(long)]
    pub shim: Option<String>,
    #[arg(long)]
    pub mm: Option<String>,
    #[arg(long)]
    pub loader: Option<String>,
    #[arg(long)]
    pub mok_cert: Option<String>,
    /// Restart at the end.
    #[arg(long)]
    pub yes: bool,
}

fn target(t: TargetArg) -> &'static str {
    match t {
        TargetArg::Image => "image",
        TargetArg::Disk => "disk",
    }
}

fn bool01(name: &str, v: &Option<String>) -> Result<Option<bool>, CmdError> {
    v.as_deref()
        .map(|s| {
            crate::cfgfile::parse_bool(s)
                .map_err(|e| CmdError::new(Exit::Usage, format!("--{name}: {}", e.message)))
        })
        .transpose()
}

/// Drop `null`s: absent and null mean the same, and requests stay short.
fn obj(v: Value) -> Value {
    match v {
        Value::Object(o) => Value::Object(o.into_iter().filter(|(_, v)| !v.is_null()).collect()),
        v => v,
    }
}

/// The request a command line makes: `(method, params)` without the
/// common parameters, or `None` for a direct-only command.
pub fn request(c: &Command) -> Result<Option<(&'static str, Value)>, CmdError> {
    use Command as C;
    let r = |m: &'static str, p: Value| Ok(Some((m, obj(p))));
    match c {
        C::Status => r("status", json!({})),
        C::Checks { cmd } => match cmd {
            ChecksCmd::List => r("checks.list", json!({})),
            ChecksCmd::Fix { id } => r("checks.fix", json!({ "id": id })),
        },
        C::Hw { cmd } => match cmd {
            HwCmd::Export { .. } => r("hw.export", json!({})),
            // The file is read by the front end (see `pre`).
            HwCmd::Modalias { .. } => r("hw.modalias", json!({})),
        },
        C::Disk { cmd } => match cmd {
            DiskCmd::Create { size, path } => {
                r("disk.create", json!({ "path": path, "size": size }))
            }
            DiskCmd::Inspect { path } => r("disk.inspect", json!({ "path": path })),
        },
        C::Config { cmd } => match cmd {
            ConfigCmd::Show => r("config.show", json!({})),
            ConfigCmd::Validate => r("config.validate", json!({})),
            ConfigCmd::Set(s) => r(
                "config.set",
                json!({
                    "entry": s.entry, "volume": s.volume, "root": s.root, "efi_disk": s.efi_disk,
                    "efi": s.efi, "efi_file": s.efi_file, "default": s.default,
                    "remove_entry": s.remove_entry, "tpm": bool01("tpm", &s.tpm)?,
                    "setup_tpm": bool01("setup-tpm", &s.setup_tpm)?,
                    "passphrase": bool01("passphrase", &s.passphrase)?, "theme": s.theme,
                    "mode": s.mode, "keyboard": s.keyboard,
                }),
            ),
        },
        C::Efi { cmd } => match cmd {
            EfiCmd::Vars { cmd } => match cmd {
                VarsCmd::List => r("efi.vars.list", json!({})),
                VarsCmd::Get { name } => r("efi.vars.get", json!({ "name": name })),
                VarsCmd::Set { name, hex } => {
                    r("efi.vars.set", json!({ "name": name, "hex": hex }))
                }
                VarsCmd::Delete { name } => r("efi.vars.delete", json!({ "name": name })),
            },
            EfiCmd::BootEntry { cmd } => match cmd {
                EntryCmd::List => r("efi.boot-entry.list", json!({})),
                EntryCmd::Create => r("efi.boot-entry.create", json!({})),
                EntryCmd::Delete { entry } => r("efi.boot-entry.delete", json!({ "entry": entry })),
            },
            EfiCmd::Bootnext { entry, clear } => {
                r("efi.bootnext", json!({ "entry": entry, "clear": clear }))
            }
        },
        C::Esp { cmd } => match cmd {
            EspCmd::Install { shim, mm, loader } => r(
                "esp.install",
                json!({ "shim": shim, "mm": mm, "loader": loader }),
            ),
            EspCmd::Verify => r("esp.verify", json!({})),
            EspCmd::Repair => r("esp.repair", json!({})),
        },
        C::Mok { cmd } => match cmd {
            MokCmd::Enroll { cert, .. } => r("mok.enroll", json!({ "cert": cert })),
            MokCmd::Status { cert } => r("mok.status", json!({ "cert": cert })),
        },
        C::SecureBoot {
            cmd: SecureBootCmd::Status,
        } => r("secure-boot.status", json!({})),
        C::Protection { cmd } => match cmd {
            ProtectionCmd::Options { target: t, klid } => r(
                "protection.options",
                json!({ "target": target(*t), "klid": klid }),
            ),
            ProtectionCmd::Set {
                choice,
                keyboard,
                no_pin_bypass,
                target: t,
            } => r(
                "protection.set",
                json!({ "choice": choice, "keyboard": keyboard, "pin_bypass": !no_pin_bypass, "target": target(*t) }),
            ),
            ProtectionCmd::Check { keyboard } => {
                r("protection.check", json!({ "keyboard": keyboard }))
            }
        },
        C::Distro { cmd } => match cmd {
            DistroCmd::List => r("distro.list", json!({})),
            DistroCmd::Rename { name, new_name } => r(
                "distro.rename",
                json!({ "name": name, "new_name": new_name }),
            ),
            DistroCmd::Remove {
                name,
                delete_image,
                yes,
            } => r(
                "distro.remove",
                json!({ "name": name, "delete_image": delete_image, "yes": yes }),
            ),
            DistroCmd::Grow { name, size } => {
                r("distro.grow", json!({ "name": name, "size": size }))
            }
            DistroCmd::Enter { name, path, .. } => {
                r("distro.enter", json!({ "name": name, "path": path }))
            }
            DistroCmd::Leave { name, path } => {
                r("distro.leave", json!({ "name": name, "path": path }))
            }
        },
        C::Preflight { repair } => r("preflight", json!({ "repair": repair })),
        C::RestartLinux { yes, entry } => r("restart-linux", json!({ "yes": yes, "entry": entry })),
        C::StageSetup => r("stage-setup", json!({})),
        C::Repair { stage, bootstrap } => {
            r("repair", json!({ "stage": stage, "bootstrap": bootstrap }))
        }
        C::Install(i) => {
            let source = if i.iso.is_some() {
                install::Source::Iso
            } else if i.from_wsl.is_some() {
                install::Source::Wsl
            } else {
                install::Source::Script
            };
            r(
                "install",
                json!({
                    "distro": i.distro, "path": i.path, "size": i.size, "source": source,
                    "script": i.script, "iso": i.iso, "wsl_distro": i.from_wsl,
                    "shell": i.shell, "finish": i.finish, "shim": i.shim, "mm": i.mm,
                    "loader": i.loader, "mok_cert": i.mok_cert, "yes": i.yes,
                }),
            )
        }
        C::Uninstall {
            yes,
            delete_images,
            skip_final_boot,
        } => r(
            "uninstall",
            json!({ "yes": yes, "delete_images": delete_images, "skip_final_boot": skip_final_boot }),
        ),
        C::Service {
            cmd: ServiceCmd::Info,
        } => r("service.info", json!({})),
        C::Service { .. } => Ok(None),
    }
}

/// How a front end reaches the API.
pub trait Transport {
    /// Call `method`; notifications arriving meanwhile go to `note`.
    fn call(
        &self,
        method: &str,
        params: &Value,
        note: &mut dyn FnMut(&Value),
    ) -> Result<Value, RpcError>;
    /// A service (not this process).
    fn remote(&self) -> bool;
}

/// Direct mode: [`rpc::call`] in this process, which may prompt.
pub struct Local<'a> {
    pub api: &'a dyn WinApi,
    pub passphrase_stdin: bool,
}

impl Transport for Local<'_> {
    fn call(
        &self,
        method: &str,
        params: &Value,
        note: &mut dyn FnMut(&Value),
    ) -> Result<Value, RpcError> {
        let note = RefCell::new(note);
        let prog = |p: &crate::ctx::Progress| {
            if let Ok(mut n) = note.try_borrow_mut() {
                n(&rpc::progress_note(&Value::Null, p));
            }
        };
        let o = rpc::Options {
            caller: rpc::Caller::local(self.api),
            enforce: false,
            interactive: true,
            passphrase_stdin: self.passphrase_stdin,
            service: false,
            progress: Some(&prog),
        };
        rpc::call(self.api, method, params, &o).map(|(r, dry)| rpc::result_json(&r, dry))
    }
    fn remote(&self) -> bool {
        false
    }
}

/// A progress notification as one stderr line.
pub fn progress_line(n: &Value) -> Option<String> {
    let p = n.at("params");
    (n.at("method") == "progress").then(|| {
        format!(
            "[{}/{}] {}: {}{}",
            p.at("index").as_u64().unwrap_or(0) + 1,
            p.at("total").as_u64().unwrap_or(0),
            p.at("step").as_str().unwrap_or("?"),
            p.at("state").as_str().unwrap_or("?"),
            match p.at("detail").as_str() {
                Some(d) if !d.is_empty() => format!(" — {d}"),
                _ => String::new(),
            }
        )
    })
}

/// Paths the service resolves: made absolute against this process's
/// directory, since the service's is not the caller's.
const PATH_PARAMS: [&str; 8] = [
    "path", "shim", "mm", "loader", "cert", "script", "iso", "mok_cert",
];

pub fn absolutize(params: &mut Map<String, Value>, abs: &dyn Fn(&str) -> Option<String>) {
    for k in PATH_PARAMS {
        if let Some(Value::String(p)) = params.get(k) {
            if let Some(a) = abs(p) {
                params.insert(k.into(), Value::String(a));
            }
        }
    }
}

/// How many times a secret is asked back before giving up.
const MAX_ASKS: usize = 3;

fn call_with_secrets(
    api: &dyn WinApi,
    t: &dyn Transport,
    cli: &Cli,
    method: &str,
    mut params: Map<String, Value>,
    note: &mut dyn FnMut(&Value),
) -> CmdResult {
    for _ in 0..=MAX_ASKS {
        match t.call(method, &Value::Object(params.clone()), note) {
            Ok(v) => return Ok(rpc::to_report(&v)),
            Err(e) => {
                let ce = rpc::to_cmd_error(&e);
                let ask = ce.data.as_ref().map(|d| d.at("needs_input").clone());
                let Some(Value::String(name)) = ask else {
                    return Err(ce);
                };
                let d = ce.data.clone().unwrap_or(Value::Null);
                let param = d.at("param").as_str().unwrap_or(&name).to_string();
                if params.contains_key(&param) {
                    return Err(ce);
                }
                let what = d.at("prompt").as_str().unwrap_or("secret").to_string();
                // A throwaway context only for the prompt logic.
                let ctx = Ctx {
                    passphrase_stdin: cli.passphrase_stdin,
                    ..Ctx::new(api)
                };
                let which = match name.as_str() {
                    "pin" => crate::ctx::Secret::Pin,
                    "mok_password" => crate::ctx::Secret::MokPassword,
                    _ => crate::ctx::Secret::LinuxPassphrase,
                };
                let s = ctx.secret(which, &what, d.at("confirm") == true)?;
                params.insert(param, Value::String(s.as_str().to_string()));
            }
        }
    }
    Err(CmdError::refused("a secret was asked for too many times"))
}

/// Front-end work before the call: the caller's own files and stdin.
fn pre(api: &dyn WinApi, c: &Command, params: &mut Map<String, Value>) -> Result<(), CmdError> {
    match c {
        Command::Hw {
            cmd: HwCmd::Modalias { input },
        } => {
            params.insert("hardware".into(), hw::read_export(api, input)?);
        }
        Command::Mok {
            cmd:
                MokCmd::Enroll {
                    password_stdin: true,
                    ..
                },
        } => {
            let raw = api.read_stdin(crate::cmd::mok::MAX_PASSWORD_STDIN)?;
            let s = std::str::from_utf8(&raw)
                .map_err(|_| CmdError::refused("the password is not UTF-8"))?;
            params.insert(
                "mok_password".into(),
                Value::String(s.trim_end_matches(['\r', '\n']).to_string()),
            );
        }
        _ => {}
    }
    Ok(())
}

/// Front-end work after the call: writing the caller's files, shells.
fn post(
    api: &dyn WinApi,
    t: &dyn Transport,
    cli: &Cli,
    params: &Map<String, Value>,
    mut r: Report,
    note: &mut dyn FnMut(&Value),
) -> CmdResult {
    match &cli.command {
        Command::Hw {
            cmd: HwCmd::Export { output: Some(p) },
        } => {
            if !cli.dry_run {
                let mut body = serde_json::to_vec_pretty(&r.data)
                    .map_err(|e| CmdError::internal(e.to_string()))?;
                body.push(b'\n');
                api.write_file(p, &body)?;
            }
            // The last line is the document itself: say where it went instead.
            r.human.pop();
            r.human.push(format!("written to {p}"));
            Ok(r)
        }
        Command::Distro {
            cmd: DistroCmd::Enter {
                no_shell: false, ..
            },
        } if !cli.dry_run => {
            let shell: Vec<String> = r
                .data
                .at("command")
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some((prog, args)) = shell.split_first() {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                let code = api.run_interactive(prog, &args)?;
                r.human.push(format!("shell exited ({code})"));
                let back = t
                    .call("distro.leave", &Value::Object(params.clone()), note)
                    .map_err(|e| rpc::to_cmd_error(&e))?;
                let back = rpc::to_report(&back);
                if let Some(o) = r.data.as_object_mut() {
                    o.insert("shell_exit".into(), json!(code));
                    o.insert("detached".into(), back.data.at("detached").clone());
                }
                r.human.extend(back.human);
            }
            Ok(r)
        }
        Command::Install(i) if i.shell && r.exit == Exit::Pending && !cli.dry_run => {
            let shell: Vec<String> = r
                .data
                .at("shell")
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|s| s.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            if let Some((prog, args)) = shell.split_first() {
                let args: Vec<&str> = args.iter().map(String::as_str).collect();
                let code = api.run_interactive(prog, &args)?;
                r.human.push(format!("shell exited ({code})"));
                if let Some(o) = r.data.as_object_mut() {
                    o.insert("shell_exit".into(), json!(code));
                }
                r.human.push(format!(
                    "when the system is installed: paguro install {} --path {} --finish",
                    i.distro, i.path
                ));
            }
            Ok(r)
        }
        _ => Ok(r),
    }
}

/// `paguro service install|uninstall|start|stop`: this process only.
fn direct_only(api: &dyn WinApi, cli: &Cli) -> CmdResult {
    let ctx = Ctx {
        dry_run: cli.dry_run,
        esp: cli.esp.clone(),
        ..Ctx::new(api)
    };
    match &cli.command {
        Command::Service { cmd } => match cmd {
            ServiceCmd::Install { exe } => {
                let exe = match exe {
                    Some(e) => e.clone(),
                    None => std::env::current_exe()
                        .ok()
                        .and_then(|p| p.parent().map(|d| d.join("paguro-service.exe")))
                        .map(|p| p.display().to_string())
                        .ok_or_else(|| {
                            CmdError::not_found("cannot find paguro-service.exe; pass --exe")
                        })?,
                };
                service::install(&ctx, &exe)
            }
            ServiceCmd::Uninstall => service::uninstall(&ctx),
            ServiceCmd::Start => service::control(&ctx, true),
            ServiceCmd::Stop => service::control(&ctx, false),
            ServiceCmd::Info => Err(CmdError::internal("service info is a method")),
        },
        _ => Err(CmdError::internal("not a direct-only command")),
    }
}

fn command_name(c: &Command) -> String {
    match request(c) {
        Ok(Some((m, _))) => rpc::command_name(m),
        _ => match c {
            Command::Service { cmd } => format!(
                "service {}",
                match cmd {
                    ServiceCmd::Info => "info",
                    ServiceCmd::Install { .. } => "install",
                    ServiceCmd::Uninstall => "uninstall",
                    ServiceCmd::Start => "start",
                    ServiceCmd::Stop => "stop",
                }
            ),
            _ => "paguro".into(),
        },
    }
}

/// Parse `args` and run in this process against `api` (tests, and
/// `--direct`). Never panics; clap's own errors (and `--help`/`--version`)
/// come back as rendered output too.
pub fn run<I, T>(api: &dyn WinApi, args: I) -> Rendered
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    run_with(api, args, &|| None, &|_| {}, &|_| None)
}

/// Parse `args` and run: through `connect()`'s transport (the service)
/// when it gives one and the command is not direct-only, else in this
/// process. Progress lines go to `live` as they come; `abs` makes a
/// relative path absolute for the service.
pub fn run_with<I, T>(
    api: &dyn WinApi,
    args: I,
    connect: &dyn Fn() -> Option<Box<dyn Transport>>,
    live: &dyn Fn(&str),
    abs: &dyn Fn(&str) -> Option<String>,
) -> Rendered
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let code = if e.use_stderr() {
                Exit::Usage.code()
            } else {
                Exit::Ok.code()
            };
            let text = e.to_string();
            return if e.use_stderr() {
                Rendered {
                    stdout: String::new(),
                    stderr: text,
                    code,
                }
            } else {
                Rendered {
                    stdout: text,
                    stderr: String::new(),
                    code,
                }
            };
        }
    };
    let name = command_name(&cli.command);
    let r = execute(api, &cli, connect, live, abs);
    out::render(&name, cli.dry_run, cli.json, &r)
}

fn execute(
    api: &dyn WinApi,
    cli: &Cli,
    connect: &dyn Fn() -> Option<Box<dyn Transport>>,
    live: &dyn Fn(&str),
    abs: &dyn Fn(&str) -> Option<String>,
) -> CmdResult {
    let Some((method, params)) = request(&cli.command)? else {
        return direct_only(api, cli);
    };
    let mut params = match params {
        Value::Object(o) => o,
        _ => Map::new(),
    };
    if cli.dry_run {
        params.insert("dry_run".into(), Value::Bool(true));
    }
    if let Some(e) = &cli.esp {
        params.insert("esp".into(), Value::String(e.clone()));
    }
    pre(api, &cli.command, &mut params)?;
    let remote = if cli.direct { None } else { connect() };
    let local = Local {
        api,
        passphrase_stdin: cli.passphrase_stdin,
    };
    let t: &dyn Transport = match &remote {
        Some(t) => {
            absolutize(&mut params, abs);
            t.as_ref()
        }
        None => &local,
    };
    let mut note = |n: &Value| {
        if let Some(l) = progress_line(n) {
            live(&l);
        }
    };
    let r = call_with_secrets(api, t, cli, method, params.clone(), &mut note)?;
    post(api, t, cli, &params, r, &mut note)
}
