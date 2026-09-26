//! `paguro` (Linux side) — DESIGN.md §5c "Shells, the same command both
//! ways", "The paguro service in the VM" item 3, "The private link".
//!
//! ```text
//! paguro shell windows                    SSH into the Windows VM (PowerShell)
//! paguro shell <distro>                   a local shell (the booted entry) or
//! paguro distro enter <distro>            <distro>'s container (systemd-nspawn)
//! paguro status [--json]
//!     [--samba-state DIR] [--ssh-unit NAME] [--vm-work DIR]
//! paguro link setup [--user NAME] [--windows-key FILE]
//!     [--state-dir DIR] [--unit-dir DIR] [--sshd PATH]
//! paguro link teardown [--purge] [--state-dir DIR] [--unit-dir DIR]
//! ```

use std::path::{Path, PathBuf};
use std::process::exit;

use paguro_linux::{link, shell, status};

fn usage() -> ! {
    let u: Vec<&str> = include_str!("main.rs")
        .lines()
        .skip_while(|l| !l.starts_with("//! ```text"))
        .skip(1)
        .take_while(|l| !l.starts_with("//! ```"))
        .map(|l| l.strip_prefix("//! ").unwrap_or(""))
        .collect();
    eprintln!("usage:\n{}", u.join("\n"));
    exit(2)
}

struct Args {
    it: std::vec::IntoIter<String>,
}

impl Args {
    fn val(&mut self, k: &str) -> String {
        self.it.next().unwrap_or_else(|| {
            eprintln!("paguro: {k} needs a value");
            exit(2)
        })
    }
}

fn fail(e: &str) -> ! {
    eprintln!("paguro: error: {e}");
    exit(1)
}

/// `--flag value` pairs anywhere after the positional args; returns the
/// remaining positionals in order.
fn take_flags(
    args: Vec<String>,
    known: &[&str],
) -> (Vec<String>, std::collections::BTreeMap<String, String>) {
    let mut pos = Vec::new();
    let mut flags = std::collections::BTreeMap::new();
    let mut a = Args {
        it: args.into_iter(),
    };
    while let Some(x) = a.it.next() {
        if let Some(name) = x.strip_prefix("--") {
            if known.contains(&name) {
                flags.insert(name.to_string(), a.val(&x));
                continue;
            }
            if name == "json" || name == "purge" {
                flags.insert(name.to_string(), String::new());
                continue;
            }
        }
        pos.push(x);
    }
    (pos, flags)
}

fn main() {
    let mut args: Vec<String> = std::env::args().collect();
    args.remove(0);
    if args.is_empty() {
        usage();
    }
    let cmd = args.remove(0);
    match cmd.as_str() {
        "shell" => {
            let (pos, flags) = take_flags(args, &["key"]);
            let Some(target) = pos.first() else { usage() };
            run_shell(target, flags.get("key").map(PathBuf::from));
        }
        "distro" => {
            if args.first().map(String::as_str) != Some("enter") {
                usage();
            }
            args.remove(0);
            let (pos, flags) = take_flags(args, &["key"]);
            let Some(target) = pos.first() else { usage() };
            run_shell(target, flags.get("key").map(PathBuf::from));
        }
        "status" => {
            let (_, flags) = take_flags(args, &["samba-state", "ssh-unit", "vm-work"]);
            let samba_state = PathBuf::from(
                flags
                    .get("samba-state")
                    .cloned()
                    .unwrap_or_else(|| "/run/paguro/samba".into()),
            );
            let ssh_unit = flags
                .get("ssh-unit")
                .cloned()
                .unwrap_or_else(link::socket_unit_name);
            let vm_work = PathBuf::from(
                flags
                    .get("vm-work")
                    .cloned()
                    .unwrap_or_else(|| "/run/paguro/vm".into()),
            );
            let s = status::gather(&samba_state, &ssh_unit, &vm_work);
            if flags.contains_key("json") {
                println!("{}", status::to_json(&s));
            } else {
                println!("link:   {}", if s.link_up { "up" } else { "down" });
                println!("samba:  {}", if s.samba_up { "up" } else { "down" });
                println!("ssh:    {}", if s.ssh_socket_up { "up" } else { "down" });
                println!(
                    "vm:     {}",
                    if s.vm_running {
                        "running"
                    } else {
                        "not running"
                    }
                );
                if s.stray_listeners.is_empty() {
                    println!("link-only: yes");
                } else {
                    println!("link-only: NO");
                    for l in &s.stray_listeners {
                        println!("  {l}");
                    }
                }
            }
        }
        "link" => {
            let sub = args.first().cloned().unwrap_or_else(|| usage());
            args.remove(0);
            match sub.as_str() {
                "setup" => {
                    let (_, flags) = take_flags(
                        args,
                        &["user", "windows-key", "state-dir", "unit-dir", "sshd"],
                    );
                    let mut o = link::SetupOpts::default();
                    if let Some(u) = flags.get("user") {
                        o.user = u.clone();
                    }
                    if let Some(f) = flags.get("windows-key") {
                        o.windows_pubkey = Some(
                            std::fs::read_to_string(f)
                                .unwrap_or_else(|e| fail(&format!("{f}: {e}"))),
                        );
                    }
                    if let Some(d) = flags.get("state-dir") {
                        o.state_dir = PathBuf::from(d);
                    }
                    if let Some(d) = flags.get("unit-dir") {
                        o.unit_dir = PathBuf::from(d);
                    }
                    if let Some(s) = flags.get("sshd") {
                        o.sshd_path = s.clone();
                    }
                    match link::setup(&o) {
                        Ok(lines) => lines.iter().for_each(|l| println!("{l}")),
                        Err(e) => fail(&e),
                    }
                }
                "teardown" => {
                    let (_, flags) = take_flags(args, &["state-dir", "unit-dir"]);
                    let unit_dir = PathBuf::from(
                        flags
                            .get("unit-dir")
                            .cloned()
                            .unwrap_or_else(|| link::DEFAULT_UNIT_DIR.into()),
                    );
                    let state_dir = PathBuf::from(
                        flags
                            .get("state-dir")
                            .cloned()
                            .unwrap_or_else(|| link::DEFAULT_STATE_DIR.into()),
                    );
                    let purge = flags.contains_key("purge");
                    match link::teardown(&unit_dir, purge.then_some(state_dir.as_path())) {
                        Ok(lines) => lines.iter().for_each(|l| println!("{l}")),
                        Err(e) => fail(&e),
                    }
                }
                _ => usage(),
            }
        }
        _ => usage(),
    }
}

fn run_shell(target: &str, key_override: Option<PathBuf>) -> ! {
    let booted = shell::current_entry(std::path::Path::new(shell::ROOT_ENV_FILE));
    let plan = shell::resolve(target, booted.as_deref());
    let code = match plan {
        shell::Plan::Windows => {
            let key = key_override
                .unwrap_or_else(|| link::client_key_path(Path::new(link::DEFAULT_STATE_DIR)));
            let known_hosts = link::known_hosts_path(Path::new(link::DEFAULT_STATE_DIR));
            let argv = shell::windows_ssh_argv(&key, &known_hosts);
            shell::run_in_netns(&argv).unwrap_or_else(|e| fail(&e))
        }
        shell::Plan::LocalShell => fail(&shell::exec_local_shell()),
        shell::Plan::Container { name, .. } => match shell::attach_view_a(&name) {
            Ok(dev) => {
                let mnt = PathBuf::from("/run/paguro/nspawn").join(&name);
                if let Err(e) = std::fs::create_dir_all(&mnt) {
                    fail(&format!("{}: {e}", mnt.display()));
                }
                let st = std::process::Command::new("mount")
                    .arg(&dev)
                    .arg(&mnt)
                    .status();
                match st {
                    Ok(s) if s.success() => {
                        let argv = shell::nspawn_argv(&mnt, &name);
                        let (prog, rest) = argv.split_first().expect("non-empty argv");
                        match std::process::Command::new(prog).args(rest).status() {
                            Ok(s) => s.code().unwrap_or(1),
                            Err(e) => fail(&format!("{prog}: {e}")),
                        }
                    }
                    Ok(s) => fail(&format!("mount {}: {s}", dev.display())),
                    Err(e) => fail(&format!("mount: {e}")),
                }
            }
            Err(e) => fail(&e),
        },
    };
    exit(code);
}
