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
//! paguro image attach <file-on-C:> [--name NAME] [--volume ID] [--format raw|vhd]
//! paguro image detach <name> --claim ID [--agent-socket PATH] [--windows-path PATH]
//! paguro image grow <name> --claim ID --by SIZE --path LOCAL_PATH
//!     [--windows-path PATH] [--agent-socket PATH] [--timeout SECS]
//! ```

use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::{Duration, Instant};

use paguro_initrd::pg;
use paguro_linux::image;
use paguro_linux::{link, shell, status};

/// Where `paguro-vm`'s session writes the guest-agent virtio-serial
/// socket (`crates/paguro-vm/src/session.rs`'s `o.work.join("agent.sock")`,
/// with `o.work` defaulting to `/run/paguro/vm`, this CLI's own
/// `--vm-work` default above).
const DEFAULT_AGENT_SOCKET: &str = "/run/paguro/vm/agent.sock";

/// `SIZE` as `paguro image grow --by` takes it: a plain number of 512-byte
/// sectors, or a byte count with a `K`/`M`/`G` suffix (binary, rounded up
/// to a whole sector).
fn parse_size_sectors(s: &str) -> Result<u64, String> {
    let t = s.trim();
    let last = t.chars().next_back().map(|c| c.to_ascii_uppercase());
    let (digits, mul) = match last {
        Some('K') => (t.get(..t.len() - 1).unwrap_or(""), 1024u64),
        Some('M') => (t.get(..t.len() - 1).unwrap_or(""), 1024 * 1024),
        Some('G') => (t.get(..t.len() - 1).unwrap_or(""), 1024 * 1024 * 1024),
        _ => (t, 512),
    };
    let n: u64 = digits
        .trim()
        .parse()
        .map_err(|_| format!("bad size {s:?}"))?;
    let bytes = n
        .checked_mul(mul)
        .ok_or_else(|| format!("size {s:?} overflows"))?;
    Ok(bytes.div_ceil(512))
}

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
        "image" => {
            let sub = args.first().cloned().unwrap_or_else(|| usage());
            args.remove(0);
            match sub.as_str() {
                "attach" => {
                    let (pos, flags) = take_flags(args, &["name", "volume", "format"]);
                    let Some(file) = pos.first() else { usage() };
                    let file = PathBuf::from(file);
                    let name = flags.get("name").cloned().unwrap_or_else(|| {
                        file.file_stem()
                            .and_then(|s| s.to_str())
                            .unwrap_or("image")
                            .to_string()
                    });
                    let format = match flags.get("format").map(String::as_str) {
                        Some("vhd") => pg::FORMAT_VHD,
                        Some("raw") | None => pg::FORMAT_RAW,
                        Some(f) => fail(&format!("unknown --format {f:?} (raw or vhd)")),
                    };
                    let mut backend = image::KernelBackend::open().unwrap_or_else(|e| fail(&e));
                    let volume_id = match flags.get("volume") {
                        Some(v) => v.parse().unwrap_or_else(|_| fail("bad --volume")),
                        None => image::sole_volume_id(&backend.ctl).unwrap_or_else(|e| fail(&e)),
                    };
                    match image::attach(&mut backend, volume_id, &file, &name, format) {
                        Ok(a) => {
                            println!("{}", a.device.display());
                            eprintln!("claim {} ({} sectors)", a.claim_id, a.sectors);
                        }
                        Err(e) => fail(&e),
                    }
                }
                "detach" => {
                    let (pos, flags) = take_flags(args, &["claim", "agent-socket", "windows-path"]);
                    let Some(name) = pos.first() else { usage() };
                    let claim_id: u32 = flags
                        .get("claim")
                        .unwrap_or_else(|| fail("--claim is required"))
                        .parse()
                        .unwrap_or_else(|_| fail("bad --claim"));
                    let mut backend = image::KernelBackend::open().unwrap_or_else(|e| fail(&e));
                    let socket = PathBuf::from(
                        flags
                            .get("agent-socket")
                            .cloned()
                            .unwrap_or_else(|| DEFAULT_AGENT_SOCKET.into()),
                    );
                    let file = image::FileRef {
                        windows_path: flags.get("windows-path").cloned().unwrap_or_default(),
                    };
                    let r = match image::UnixAgentChannel::connect(&socket) {
                        Ok(mut ch) => image::detach(&mut backend, &mut ch, name, claim_id, &file),
                        Err(_) => {
                            eprintln!(
                                "paguro: no live guest-agent channel ({}); releasing without telling Windows",
                                socket.display()
                            );
                            let mut ch = image::NullChannel;
                            image::detach(&mut backend, &mut ch, name, claim_id, &file)
                        }
                    };
                    match r {
                        Ok(()) => println!("detached {name}"),
                        Err(e) => fail(&e),
                    }
                }
                "grow" => {
                    let (pos, flags) = take_flags(
                        args,
                        &[
                            "claim",
                            "by",
                            "path",
                            "agent-socket",
                            "windows-path",
                            "timeout",
                        ],
                    );
                    let Some(name) = pos.first() else { usage() };
                    let claim_id: u32 = flags
                        .get("claim")
                        .unwrap_or_else(|| fail("--claim is required"))
                        .parse()
                        .unwrap_or_else(|_| fail("bad --claim"));
                    let by_sectors = parse_size_sectors(
                        flags.get("by").unwrap_or_else(|| fail("--by is required")),
                    )
                    .unwrap_or_else(|e| fail(&e));
                    // Where the file is reachable *on Linux* right now (the
                    // same already-mounted, read-only ntfs3 view `attach`
                    // used): needed for the fresh `PG_CROSSCHECK` a grow's
                    // reload requires (INTERFACES.md §10.1a).
                    let local_path = PathBuf::from(
                        flags
                            .get("path")
                            .unwrap_or_else(|| fail("--path is required")),
                    );
                    let socket = PathBuf::from(
                        flags
                            .get("agent-socket")
                            .cloned()
                            .unwrap_or_else(|| DEFAULT_AGENT_SOCKET.into()),
                    );
                    let timeout = flags
                        .get("timeout")
                        .and_then(|t| t.parse().ok())
                        .unwrap_or(30u64);
                    let file = image::FileRef {
                        windows_path: flags.get("windows-path").cloned().unwrap_or_default(),
                    };
                    let mut backend = image::KernelBackend::open().unwrap_or_else(|e| fail(&e));
                    let mut ch = image::UnixAgentChannel::connect(&socket).unwrap_or_else(|e| {
                        fail(&format!(
                            "{e}: growth needs a live Windows guest to extend the file"
                        ))
                    });
                    let deadline = Instant::now() + Duration::from_secs(timeout);
                    let target = image::GrowTarget {
                        name,
                        claim_id,
                        local_path: &local_path,
                        file: &file,
                    };
                    match image::grow(&mut backend, &mut ch, &target, by_sectors, deadline) {
                        Ok(g) => println!("grown: {} sectors", g.sectors),
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
        shell::Plan::Container { name, .. } => {
            let mut backend = image::KernelBackend::open().unwrap_or_else(|e| fail(&e));
            match shell::enter_container(
                &mut backend,
                &shell::UnresolvedLocator,
                &shell::SystemdNspawn,
                &name,
            ) {
                Ok(code) => code,
                Err(e) => fail(&e),
            }
        }
    };
    exit(code);
}
