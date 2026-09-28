//! DESIGN.md §5c "The paguro service in the VM", duties 2 and 3: the
//! private link and SSH over it, provisioned by the service itself once the
//! driver is armed (INTERFACES.md §11.3's `link-request`/`link` and
//! `ssh-keys`/`ssh-keys-ack` frames). The scripts are `paguro-link`'s, the
//! same text the Linux side's tooling prints, so the two cannot drift.
//!
//! - **The link:** ask the host for the per-installation secrets, run the
//!   provisioning script (address, the C: share and its account, firewall
//!   scoping, `L:`) with the secrets on **stdin**, never on a command line,
//!   and report the outcome.
//! - **SSH, for the signed-in console user:** OpenSSH Server and the user's
//!   own link key prepared, keys exchanged over the agent port, the host's
//!   key authorized and pinned. `ssh.json` and `known_hosts` are what `paguro
//!   distro enter` then uses (`crate::cmd::distro`), with
//!   `StrictHostKeyChecking=yes`: nothing is ever trusted on first use.
//!
//! One user for now, the console's (DESIGN.md §4.7: one interactive session
//! at a time); per-user identities are DESIGN.md §5d's next step.

use std::time::Duration;

use paguro_link as link;
use serde_json::json;

use crate::agent::{self, PORT_NAME};
use crate::api::{AgentPort, WinApi, join};
use crate::arming::Backoff;
use crate::cmd::distro::SSH_LINK_CONFIG_FILE;

const RETRY_START: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(120);

/// `%ProgramData%\paguro\link\known_hosts`.
pub const KNOWN_HOSTS_FILE: &str = "link\\known_hosts";

/// `known_hosts` and `ssh.json`: SYSTEM and Administrators write, every
/// signed-in user reads (their SSH client reads both; neither is secret).
/// Protected DACL, so nothing is inherited that could let a user rewrite
/// the pinned host key.
pub const PUBLIC_SDDL: &str = "O:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;AU)";

/// Both duties, each retried with backoff until it succeeds (the host's
/// link may not be set up yet; nobody may be signed in yet). Blocks: run it
/// off the service's own thread, after arming.
pub fn run(api: &dyn WinApi, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) {
    retry(sleep, log, "link", &|| provision_link(api, log));
    retry(sleep, log, "ssh", &|| provision_ssh(api, log));
}

fn retry(
    sleep: &dyn Fn(Duration),
    log: &dyn Fn(&str),
    what: &str,
    f: &dyn Fn() -> Result<(), String>,
) {
    let mut backoff = Backoff::new(RETRY_START, RETRY_MAX);
    loop {
        match f() {
            Ok(()) => return,
            Err(e) => log(&format!("{what}: {e}")),
        }
        sleep(backoff.wait());
    }
}

fn open_port(api: &dyn WinApi) -> Result<Box<dyn AgentPort>, String> {
    api.open_agent_port(PORT_NAME)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "the agent port is not present".to_string())
}

/// `script` on `powershell.exe`'s stdin (`paguro_link::PS_STDIN_ARGS`);
/// its stdout, or the last thing it said on failure.
fn powershell(api: &dyn WinApi, script: &str) -> Result<String, String> {
    let o = api
        .run(
            "powershell.exe",
            &link::PS_STDIN_ARGS,
            Some(script.as_bytes()),
        )
        .map_err(|e| e.to_string())?;
    if o.ok() {
        Ok(o.stdout)
    } else {
        let last = |s: &str| {
            s.lines()
                .rev()
                .find(|l| !l.trim().is_empty())
                .map(str::to_string)
        };
        Err(last(&o.stderr)
            .or_else(|| last(&o.stdout))
            .unwrap_or_else(|| format!("powershell exited {}", o.status)))
    }
}

/// The link's Windows side (§5c duty 2).
pub fn provision_link(api: &dyn WinApi, log: &dyn Fn(&str)) -> Result<(), String> {
    let mut port = open_port(api)?;
    let cfg = agent::exchange(&mut *port, &link::link_request(), &link::parse_link)
        .map_err(|e| e.to_string())??;
    let r = powershell(api, &link::provision_invocation(&cfg)).and_then(|out| {
        if out.contains("paguro: private link ready") {
            Ok(())
        } else {
            Err("the provisioning script stopped before the end".to_string())
        }
    });
    let ready = link::link_ready(r.as_ref().map(|_| ()).map_err(String::as_str));
    if let Err(e) = port.write_all(&agent::encode(&ready)) {
        log(&format!("link: reporting to the host: {e}"));
    }
    if r.is_ok() {
        log("link: Windows' side in place (address, the C: share, firewall, L:)");
    }
    r
}

/// The user signed in at the console, `DOMAIN\name` as Windows reports it.
pub fn console_user(api: &dyn WinApi) -> Result<String, String> {
    let out = powershell(api, "(Get-CimInstance Win32_ComputerSystem).UserName")?;
    let user = out.trim();
    if user.is_empty() {
        return Err("nobody is signed in yet".into());
    }
    if !link::windows_user_ok(user) {
        return Err(format!(
            "{user:?}: not a name the link's sshd can admit (letters, digits, '.', '_', '-')"
        ));
    }
    Ok(user.to_string())
}

/// SSH over the link for the console user (§5c duty 3).
pub fn provision_ssh(api: &dyn WinApi, log: &dyn Fn(&str)) -> Result<(), String> {
    let user = console_user(api)?;
    let short = user.rsplit('\\').next().unwrap_or(&user);
    let prep = link::parse_ssh_prepare(&powershell(api, &link::windows_ssh_prepare_ps1(&user))?)
        .ok_or("the SSH preparation reported no keys")?;
    let mut port = open_port(api)?;
    let ack = agent::exchange(
        &mut *port,
        &link::ssh_keys_frame(&prep.user_pub, &prep.host_pub),
        &link::parse_ssh_keys_ack,
    )
    .map_err(|e| e.to_string())??;
    let out = powershell(
        api,
        &link::windows_ssh_provision_ps1_detect(short, &ack.linux_user_pub),
    )?;
    if !out.contains("paguro: SSH ready") {
        return Err("the SSH provisioning script stopped before the end".into());
    }
    let dir = join(&api.program_data(), "paguro");
    api.create_dir_all(&join(&dir, "link"))
        .map_err(|e| e.to_string())?;
    let kh = join(&dir, KNOWN_HOSTS_FILE);
    let line = link::known_hosts_line(link::HOST_ADDR, &ack.linux_host_pub);
    api.write_protected_file(&kh, format!("{line}\n").as_bytes(), PUBLIC_SDDL)
        .map_err(|e| e.to_string())?;
    let cfg = json!({ "linux_user": ack.linux_user, "key_path": prep.key_path, "known_hosts": kh });
    api.write_protected_file(
        &join(&dir, SSH_LINK_CONFIG_FILE),
        cfg.to_string().as_bytes(),
        PUBLIC_SDDL,
    )
    .map_err(|e| e.to_string())?;
    log(&format!(
        "ssh: {user} <-> {}@{} over the link, host keys pinned both ways",
        ack.linux_user,
        link::HOST_ADDR
    ));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::Output;
    use crate::ctx::Ctx;
    use crate::mock::{MockAgentState, MockApi};
    use serde_json::Value;
    use std::cell::RefCell;
    use std::rc::Rc;

    const SMB: &str = "0123456789abcdef0123456789abcdef";
    const HOST: &str = "fedcba9876543210fedcba9876543210";

    fn ok(stdout: &str) -> Option<Output> {
        Some(Output {
            status: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    /// A VM-side machine: the agent port answers with `replies` in order,
    /// and each script piped to PowerShell gets a plausible answer.
    fn machine(replies: &[Value], user: &'static str) -> (MockApi, Rc<RefCell<MockAgentState>>) {
        let m = MockApi::standard();
        let port = Rc::new(RefCell::new(MockAgentState {
            writes: Vec::new(),
            reads: replies.iter().map(|v| Ok(agent::encode(v))).collect(),
        }));
        *m.agent_port.borrow_mut() = Some(port.clone());
        m.set_stdin_runner(move |_p, _a, stdin| {
            let s = String::from_utf8_lossy(stdin);
            if s.contains("Win32_ComputerSystem") {
                ok(user)
            } else if s.contains("the service's preparation for one user") {
                ok("PAGURO-SSH {\"user_pub\":\"ssh-ed25519 WWWW paguro@VM\",\"host_pub\":\"ssh-ed25519 HHHH\",\"key\":\"C:\\\\Users\\\\anna\\\\.ssh\\\\paguro_link_ed25519\"}")
            } else if s.contains("the private link, Windows side") {
                ok("paguro: private link ready")
            } else if s.contains("SSH Windows side") {
                ok("paguro: SSH ready on 169.254.244.2:22")
            } else {
                None
            }
        });
        (m, port)
    }

    fn written(port: &Rc<RefCell<MockAgentState>>) -> Vec<Value> {
        let mut f = agent::Framer::default();
        port.borrow()
            .writes
            .iter()
            .flat_map(|w| f.feed(w))
            .collect()
    }

    #[test]
    fn provisions_the_link_and_ssh() {
        let cfg = link::LinkConfig {
            smb_secret: SMB.into(),
            host_secret: HOST.into(),
        };
        let (m, port) = machine(
            &[
                link::link_frame(&cfg),
                link::ssh_keys_ack_frame(
                    "alice",
                    "ssh-ed25519 LLLL paguro@host",
                    "ssh-ed25519 KKKK",
                ),
            ],
            "DESKTOP-1\\anna\r\n",
        );
        run(&m, &|_| panic!("no retry needed"), &|_| {});

        let w = written(&port);
        assert!(link::is_link_request(&w[0]));
        assert_eq!(link::parse_link_ready(&w[1]), Some(Ok(())));
        assert_eq!(w[2]["type"], "ssh-keys");
        assert_eq!(w[2]["windows_user_pub"], "ssh-ed25519 WWWW paguro@VM");

        // Secrets only ever on stdin, never in a command line.
        let cmds = m.commands.borrow().join("\n");
        assert!(!cmds.contains(SMB) && !cmds.contains(HOST));
        assert!(
            m.stdins
                .borrow()
                .iter()
                .any(|i| i.contains(&format!("-SmbSecret '{SMB}'")))
        );
        // The console user's short name, and the host's key authorized.
        assert!(
            m.stdins
                .borrow()
                .iter()
                .any(|i| i.contains("AllowUsers anna") && i.contains("ssh-ed25519 LLLL"))
        );

        let kh = join(&join(&m.program_data(), "paguro"), KNOWN_HOSTS_FILE);
        assert_eq!(m.file(&kh).unwrap(), b"169.254.244.1 ssh-ed25519 KKKK\n");
        // What `distro enter` reads back: the key in the user's profile,
        // the Linux account, the pinned host key.
        let c = crate::cmd::distro::read_ssh_link_config_for_test(&Ctx::new(&m)).unwrap();
        assert_eq!(c.linux_user, "alice");
        assert_eq!(c.key_path, r"C:\Users\anna\.ssh\paguro_link_ed25519");
        assert_eq!(c.known_hosts, kh);
    }

    #[test]
    fn a_host_without_the_link_provisions_nothing() {
        let (m, port) = machine(
            &[link::link_error("the link is not set up on this host")],
            "",
        );
        assert_eq!(
            provision_link(&m, &|_| {}),
            Err("the link is not set up on this host".into())
        );
        assert!(m.stdins.borrow().iter().all(|i| !i.contains("-SmbSecret")));
        assert_eq!(written(&port).len(), 1, "only the request");
    }

    #[test]
    fn a_failed_script_is_reported_to_the_host() {
        let cfg = link::LinkConfig {
            smb_secret: SMB.into(),
            host_secret: HOST.into(),
        };
        let (m, port) = machine(&[link::link_frame(&cfg)], "");
        m.set_stdin_runner(|_p, _a, _i| {
            Some(Output {
                status: 1,
                stdout: String::new(),
                stderr: "paguro: no adapter with MAC 02-70-67-00-00-02\n".into(),
            })
        });
        let e = provision_link(&m, &|_| {}).unwrap_err();
        assert!(e.contains("no adapter"), "{e}");
        assert_eq!(link::parse_link_ready(&written(&port)[1]), Some(Err(e)));
    }

    #[test]
    fn ssh_waits_for_a_usable_signed_in_user() {
        let (m, port) = machine(&[], "\r\n");
        assert_eq!(
            provision_ssh(&m, &|_| {}),
            Err("nobody is signed in yet".into())
        );
        assert!(written(&port).is_empty(), "the port is not even opened");
        let (m, _) = machine(&[], "DESKTOP-1\\John Smith");
        assert!(
            provision_ssh(&m, &|_| {})
                .unwrap_err()
                .contains("sshd can admit")
        );
    }

    #[test]
    fn a_bad_ack_writes_nothing() {
        let (m, _) = machine(
            &[link::ssh_keys_ack_frame(
                "Alice",
                "ssh-ed25519 LLLL",
                "ssh-ed25519 KKKK",
            )],
            "anna",
        );
        assert!(provision_ssh(&m, &|_| {}).is_err());
        let kh = join(&join(&m.program_data(), "paguro"), KNOWN_HOSTS_FILE);
        assert!(m.file(&kh).is_none());
    }
}
