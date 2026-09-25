//! The `paguro` command line (INTERFACES.md §11.2). Parsing and dispatch
//! only; every command lives in [`crate::cmd`].

use clap::{Args, Parser, Subcommand};

use crate::api::WinApi;
use crate::cmd::{config, disk, efi, esp, hw, install, mok, status, transition, uninstall};
use crate::ctx::Ctx;
use crate::out::{self, CmdResult, Exit, Rendered};

#[derive(Parser, Debug)]
#[command(
    name = "paguro",
    version,
    about = "paguro on Windows: disks, ESP, firmware, and the way into Linux"
)]
pub struct Cli {
    /// One JSON document on stdout (schema paguro-cli/1), for scripts and the PowerShell module.
    #[arg(long, global = true)]
    pub json: bool,
    /// Report what would change; change nothing.
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// The EFI System Partition to use (a \\?\Volume{…}\ path) when there are several.
    #[arg(long, global = true, value_name = "VOLUME")]
    pub esp: Option<String>,
    /// Read the Linux passphrase from standard input instead of prompting.
    #[arg(long, global = true)]
    pub passphrase_stdin: bool,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Volumes, BitLocker, images, ESP, firmware variables, MOK, WSL2, pre-flight.
    Status,
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

#[derive(Args, Debug)]
pub struct InstallCli {
    pub distro: String,
    #[arg(long)]
    pub path: String,
    #[arg(long, default_value = "32G")]
    pub size: String,
    /// STUB for §11.4 step 4: a script run as root inside WSL2.
    #[arg(long)]
    pub script: Option<String>,
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

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Command::Status => "status",
            Command::Hw {
                cmd: HwCmd::Export { .. },
            } => "hw export",
            Command::Hw {
                cmd: HwCmd::Modalias { .. },
            } => "hw modalias",
            Command::Disk {
                cmd: DiskCmd::Create { .. },
            } => "disk create",
            Command::Disk {
                cmd: DiskCmd::Inspect { .. },
            } => "disk inspect",
            Command::Config {
                cmd: ConfigCmd::Show,
            } => "config show",
            Command::Config {
                cmd: ConfigCmd::Validate,
            } => "config validate",
            Command::Config {
                cmd: ConfigCmd::Set(_),
            } => "config set",
            Command::Efi {
                cmd: EfiCmd::Vars { cmd },
            } => match cmd {
                VarsCmd::List => "efi vars list",
                VarsCmd::Get { .. } => "efi vars get",
                VarsCmd::Set { .. } => "efi vars set",
                VarsCmd::Delete { .. } => "efi vars delete",
            },
            Command::Efi {
                cmd: EfiCmd::BootEntry { cmd },
            } => match cmd {
                EntryCmd::List => "efi boot-entry list",
                EntryCmd::Create => "efi boot-entry create",
                EntryCmd::Delete { .. } => "efi boot-entry delete",
            },
            Command::Efi {
                cmd: EfiCmd::Bootnext { .. },
            } => "efi bootnext",
            Command::Esp {
                cmd: EspCmd::Install { .. },
            } => "esp install",
            Command::Esp {
                cmd: EspCmd::Verify,
            } => "esp verify",
            Command::Esp {
                cmd: EspCmd::Repair,
            } => "esp repair",
            Command::Mok {
                cmd: MokCmd::Enroll { .. },
            } => "mok enroll",
            Command::Mok {
                cmd: MokCmd::Status { .. },
            } => "mok status",
            Command::Preflight { .. } => "preflight",
            Command::RestartLinux { .. } => "restart-linux",
            Command::StageSetup => "stage-setup",
            Command::Repair { .. } => "repair",
            Command::Install(_) => "install",
            Command::Uninstall { .. } => "uninstall",
        }
    }
}

pub fn dispatch(ctx: &mut Ctx<'_>, cmd: &Command) -> CmdResult {
    match cmd {
        Command::Status => status::status(ctx),
        Command::Hw { cmd } => match cmd {
            HwCmd::Export { output } => hw::export(ctx, output.as_deref()),
            HwCmd::Modalias { input } => hw::modalias(ctx, input),
        },
        Command::Disk { cmd } => match cmd {
            DiskCmd::Create { size, path } => disk::create(ctx, path, size),
            DiskCmd::Inspect { path } => disk::inspect(ctx, path),
        },
        Command::Config { cmd } => match cmd {
            ConfigCmd::Show => config::show(ctx),
            ConfigCmd::Validate => config::validate(ctx),
            ConfigCmd::Set(s) => config::set(
                ctx,
                &config::SetArgs {
                    entry: s.entry.clone(),
                    volume: s.volume.clone(),
                    root: s.root.clone(),
                    efi_disk: s.efi_disk.clone(),
                    efi: s.efi.clone(),
                    efi_file: s.efi_file.clone(),
                    default: s.default.clone(),
                    remove_entry: s.remove_entry.clone(),
                    tpm: s.tpm.clone(),
                    setup_tpm: s.setup_tpm.clone(),
                    passphrase: s.passphrase.clone(),
                    theme: s.theme.clone(),
                    mode: s.mode.clone(),
                },
            ),
        },
        Command::Efi { cmd } => match cmd {
            EfiCmd::Vars { cmd } => match cmd {
                VarsCmd::List => efi::vars_list(ctx),
                VarsCmd::Get { name } => efi::vars_get(ctx, name),
                VarsCmd::Set { name, hex } => efi::vars_set(ctx, name, hex),
                VarsCmd::Delete { name } => efi::vars_delete(ctx, name),
            },
            EfiCmd::BootEntry { cmd } => match cmd {
                EntryCmd::List => efi::entries_list(ctx),
                EntryCmd::Create => efi::entry_create(ctx),
                EntryCmd::Delete { entry } => efi::entry_delete(ctx, entry),
            },
            EfiCmd::Bootnext { entry, clear } => efi::bootnext(ctx, entry.as_deref(), *clear),
        },
        Command::Esp { cmd } => match cmd {
            EspCmd::Install { shim, mm, loader } => esp::install(ctx, shim, mm, loader),
            EspCmd::Verify => esp::verify(ctx),
            EspCmd::Repair => esp::repair(ctx),
        },
        Command::Mok { cmd } => match cmd {
            MokCmd::Enroll {
                cert,
                password_stdin,
            } => mok::enroll(ctx, cert, *password_stdin),
            MokCmd::Status { cert } => mok::status(ctx, cert.as_deref()),
        },
        Command::Preflight { repair } => transition::preflight_cmd(ctx, *repair),
        Command::RestartLinux { yes } => {
            ctx.yes = *yes;
            transition::restart_linux(ctx)
        }
        Command::StageSetup => transition::stage_setup(ctx),
        Command::Repair { stage, bootstrap } => transition::repair(ctx, *stage, *bootstrap),
        Command::Install(i) => {
            ctx.yes = i.yes;
            install::install(
                ctx,
                &install::InstallArgs {
                    distro: i.distro.clone(),
                    path: i.path.clone(),
                    size: i.size.clone(),
                    script: i.script.clone(),
                    shim: i.shim.clone(),
                    mm: i.mm.clone(),
                    loader: i.loader.clone(),
                    mok_cert: i.mok_cert.clone(),
                },
            )
        }
        Command::Uninstall {
            yes,
            delete_images,
            skip_final_boot,
        } => {
            ctx.yes = *yes;
            uninstall::uninstall(ctx, *delete_images, *skip_final_boot)
        }
    }
}

/// Parse `args` and run against `api`. Never panics; clap's own errors
/// (and `--help`/`--version`) come back as rendered output too.
pub fn run<I, T>(api: &dyn WinApi, args: I) -> Rendered
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
    let mut ctx = Ctx {
        api,
        dry_run: cli.dry_run,
        yes: false,
        esp: cli.esp.clone(),
        passphrase_stdin: cli.passphrase_stdin,
    };
    let r = dispatch(&mut ctx, &cli.command);
    out::render(cli.command.name(), cli.dry_run, cli.json, &r)
}
