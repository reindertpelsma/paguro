//! The private link's Linux-side SSH (DESIGN.md §5c "Shells, the same
//! command both ways", "Windows → Linux"):
//!
//! ```text
//! paguro-ssh.socket   [Socket] ListenStream=169.254.244.1:22
//!                     NetworkNamespacePath=/run/netns/paguro, Accept=yes
//!   -- hands each connection to --
//! paguro-ssh@.service [Service] ExecStart=sshd -i -e -f <our own sshd_config>
//! ```
//!
//! The listener exists only inside netns `paguro` (nothing else can ever
//! bind it), but the `sshd -i` it spawns runs in the *manager's* namespace —
//! the host's own, an ordinary namespace with the ordinary network — because
//! `NetworkNamespacePath` is a property of the socket unit alone, not of
//! units that pair with it. That is the whole reason this needs a socket
//! *unit* (systemd) rather than an `sshd` bound inside the netns: a plain
//! `sshd -D` started with `ip netns exec paguro` would give shells cut off
//! from the network (DESIGN.md §5c).
//!
//! Nothing here touches the host's own `sshd` or its `/etc/ssh`: this is a
//! second, independent `sshd` instance, its own host key, its own
//! `authorized_keys`, reachable only on the private link.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use paguro_vm::net::{HOST_ADDR, NETNS};
// The single source of truth for these two: `paguro_vm::net` also uses
// them from the agent-port handler (INTERFACES.md §11.3's "ssh-keys"
// frames), which needs to agree with this CLI on where the state lives and
// how an `authorized_keys` line is shaped.
pub use paguro_vm::net::{LINK_STATE_DIR as DEFAULT_STATE_DIR, authorized_keys_line};

/// SSH's own default; kept separate from `paguro_vm::net::SSH_PORT` (the
/// *other* direction, Linux → Windows) so the two are never confused, even
/// though today they're numerically the same.
pub const SSH_PORT: u16 = 22;
/// Both unit files share this stem: systemd pairs an `Accept=yes` socket
/// unit with the identically-stemmed `@.service` template automatically.
pub const UNIT_STEM: &str = "paguro-ssh";
pub const DEFAULT_UNIT_DIR: &str = "/etc/systemd/system";

pub fn socket_unit_name() -> String {
    format!("{UNIT_STEM}.socket")
}

pub fn service_unit_name() -> String {
    format!("{UNIT_STEM}@.service")
}

/// `HostKey`, `AuthorizedKeysFile`: paths inside `state_dir`.
pub fn host_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("ssh_host_ed25519_key")
}
pub fn authorized_keys_path(state_dir: &Path) -> PathBuf {
    state_dir.join("authorized_keys")
}
/// This installation's own key for the other direction (`paguro shell
/// windows`, `paguro_vm::net::windows_ssh_provision_ps1`'s `linux_pubkey`
/// argument comes from `{this}.pub`).
pub fn client_key_path(state_dir: &Path) -> PathBuf {
    state_dir.join("id_ed25519")
}
pub fn sshd_config_path(state_dir: &Path) -> PathBuf {
    state_dir.join("sshd_config")
}
/// Where the Windows side's pinned host key lives (`ssh -o
/// UserKnownHostsFile=`, `paguro shell windows`): populated by the
/// agent-port handshake (INTERFACES.md §11.3's "ssh-keys-ack" frame),
/// never trust-on-first-use.
pub fn known_hosts_path(state_dir: &Path) -> PathBuf {
    state_dir.join("known_hosts")
}

/// The socket: link-only by construction (`NetworkNamespacePath`), one
/// connection per instance.
pub fn socket_unit() -> String {
    format!(
        "# paguro: the private link's SSH socket (DESIGN.md §5c). Generated.\n\
         [Unit]\n\
         Description=paguro: SSH on the private link, Windows -> Linux\n\
         [Socket]\n\
         ListenStream={HOST_ADDR}:{SSH_PORT}\n\
         NetworkNamespacePath=/run/netns/{NETNS}\n\
         Accept=yes\n\
         [Install]\n\
         WantedBy=sockets.target\n"
    )
}

/// The per-connection service: an ordinary `sshd -i` in the manager's own
/// (host) namespace, reading the inherited socket on stdio.
pub fn service_unit(sshd_config: &Path, sshd_path: &str) -> String {
    format!(
        "# paguro: one sshd per connection over the private link. Generated.\n\
         [Unit]\n\
         Description=paguro: SSH from the Windows VM (%i)\n\
         [Service]\n\
         ExecStart={sshd_path} -i -e -f {}\n\
         StandardInput=socket\n\
         StandardError=journal\n",
        sshd_config.display()
    )
}

/// A dedicated `sshd_config`: key-only, one account, this link's own host
/// key and `authorized_keys` (never the system's).
pub fn sshd_config(state_dir: &Path, user: &str) -> String {
    format!(
        "# paguro: the private link's own sshd (DESIGN.md §5c). Generated.\n\
         # A second, independent instance; the system's own sshd and\n\
         # /etc/ssh are untouched.\n\
         Port {SSH_PORT}\n\
         ListenAddress {HOST_ADDR}\n\
         HostKey {}\n\
         AuthorizedKeysFile {}\n\
         AllowUsers {user}\n\
         PubkeyAuthentication yes\n\
         PasswordAuthentication no\n\
         KbdInteractiveAuthentication no\n\
         UsePAM no\n\
         X11Forwarding no\n\
         PrintMotd no\n\
         PidFile none\n",
        host_key_path(state_dir).display(),
        authorized_keys_path(state_dir).display(),
    )
}

fn run(cmd: &mut Command) -> Result<(), String> {
    let out = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{cmd:?}: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "{cmd:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// A fresh ed25519 keypair at `path` (and `path.pub`), if not already
/// there. Shells out to `ssh-keygen`: standard tooling, not a
/// hand-rolled Ed25519 implementation.
pub fn ensure_keypair(path: &Path, comment: &str) -> Result<bool, String> {
    if path.exists() {
        return Ok(false);
    }
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
    }
    run(Command::new("ssh-keygen")
        .args(["-q", "-t", "ed25519", "-N", "", "-C", comment, "-f"])
        .arg(path))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", path.display()))?;
    }
    Ok(true)
}

pub struct SetupOpts {
    pub user: String,
    pub state_dir: PathBuf,
    pub unit_dir: PathBuf,
    /// The Windows side's public key line, when already known (normally
    /// provisioned by the guest agent channel, INTERFACES.md §11.3 — not
    /// wired yet, see the crate's README/report). Appended to
    /// `authorized_keys` if not already present.
    pub windows_pubkey: Option<String>,
    /// `sshd`'s path (a test harness may want a copied-in binary).
    pub sshd_path: String,
}

impl Default for SetupOpts {
    fn default() -> Self {
        SetupOpts {
            user: std::env::var("USER").unwrap_or_else(|_| "root".into()),
            state_dir: PathBuf::from(DEFAULT_STATE_DIR),
            unit_dir: PathBuf::from(DEFAULT_UNIT_DIR),
            windows_pubkey: None,
            sshd_path: "/usr/sbin/sshd".into(),
        }
    }
}

/// Generate and install everything (idempotent): the netns, both keypairs,
/// `sshd_config`, `authorized_keys`, the two unit files, then
/// `daemon-reload` and `enable --now` the socket.
pub fn setup(o: &SetupOpts) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    paguro_vm::net::ensure_netns()?;
    lines.push(format!("netns {NETNS}: ready"));

    std::fs::create_dir_all(&o.state_dir).map_err(|e| format!("{}: {e}", o.state_dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&o.state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("{}: {e}", o.state_dir.display()))?;
    }

    if ensure_keypair(&host_key_path(&o.state_dir), "paguro-link-host")? {
        lines.push("host key: generated".into());
    }
    if ensure_keypair(
        &client_key_path(&o.state_dir),
        &format!("paguro@{}", o.user),
    )? {
        lines.push("client key (Linux -> Windows): generated".into());
    }

    let akey = authorized_keys_path(&o.state_dir);
    let mut existing = std::fs::read_to_string(&akey).unwrap_or_default();
    if let Some(k) = &o.windows_pubkey {
        let line = authorized_keys_line(k);
        if !existing.lines().any(|l| l == line) {
            if !existing.is_empty() && !existing.ends_with('\n') {
                existing.push('\n');
            }
            existing.push_str(&line);
            existing.push('\n');
        }
    }
    std::fs::write(&akey, &existing).map_err(|e| format!("{}: {e}", akey.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&akey, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("{}: {e}", akey.display()))?;
    }
    lines.push(format!(
        "authorized_keys: {}",
        if o.windows_pubkey.is_some() {
            "the Windows key is present"
        } else {
            "no Windows key given yet (pass one, or add it later)"
        }
    ));

    let conf = sshd_config_path(&o.state_dir);
    std::fs::write(&conf, sshd_config(&o.state_dir, &o.user))
        .map_err(|e| format!("{}: {e}", conf.display()))?;

    std::fs::create_dir_all(&o.unit_dir).map_err(|e| format!("{}: {e}", o.unit_dir.display()))?;
    std::fs::write(o.unit_dir.join(socket_unit_name()), socket_unit())
        .map_err(|e| e.to_string())?;
    std::fs::write(
        o.unit_dir.join(service_unit_name()),
        service_unit(&conf, &o.sshd_path),
    )
    .map_err(|e| e.to_string())?;
    lines.push(format!(
        "units: {} {}",
        socket_unit_name(),
        service_unit_name()
    ));

    run(Command::new("systemctl").arg("daemon-reload"))?;
    run(Command::new("systemctl")
        .args(["enable", "--now"])
        .arg(socket_unit_name()))?;
    lines.push(format!("{}: enabled and started", socket_unit_name()));
    Ok(lines)
}

/// Stop and remove the units (the netns, keys and `authorized_keys` are
/// left alone — `--purge` at the CLI layer removes `state_dir` too).
pub fn teardown(unit_dir: &Path, state_dir: Option<&Path>) -> Result<Vec<String>, String> {
    let mut lines = Vec::new();
    let _ = Command::new("systemctl")
        .args(["disable", "--now"])
        .arg(socket_unit_name())
        .status();
    for name in [socket_unit_name(), service_unit_name()] {
        let p = unit_dir.join(&name);
        if std::fs::remove_file(&p).is_ok() {
            lines.push(format!("removed {}", p.display()));
        }
    }
    run(Command::new("systemctl").arg("daemon-reload"))?;
    if let Some(d) = state_dir {
        if std::fs::remove_dir_all(d).is_ok() {
            lines.push(format!("removed {}", d.display()));
        }
    }
    lines.push(format!("{}: stopped", socket_unit_name()));
    Ok(lines)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn socket_is_link_only_and_pairs_by_stem() {
        let s = socket_unit();
        assert!(s.contains("ListenStream=169.254.244.1:22"));
        assert!(s.contains("NetworkNamespacePath=/run/netns/paguro"));
        assert!(s.contains("Accept=yes"));
        assert_eq!(socket_unit_name(), "paguro-ssh.socket");
        assert_eq!(service_unit_name(), "paguro-ssh@.service");
    }

    #[test]
    fn service_runs_sshd_dash_i_on_the_socket() {
        let s = service_unit(Path::new("/etc/paguro/link/sshd_config"), "/usr/sbin/sshd");
        assert!(s.contains("ExecStart=/usr/sbin/sshd -i -e -f /etc/paguro/link/sshd_config"));
        assert!(s.contains("StandardInput=socket"));
        // Nothing here re-namespaces the service: only the socket unit
        // above carries NetworkNamespacePath.
        assert!(!s.contains("NetworkNamespacePath"));
    }

    #[test]
    fn sshd_config_is_key_only_and_scoped() {
        let c = sshd_config(Path::new("/etc/paguro/link"), "anna");
        assert!(c.contains("ListenAddress 169.254.244.1"));
        assert!(c.contains("AllowUsers anna"));
        assert!(c.contains("PasswordAuthentication no"));
        assert!(c.contains("KbdInteractiveAuthentication no"));
        assert!(c.contains("HostKey /etc/paguro/link/ssh_host_ed25519_key"));
        assert!(c.contains("AuthorizedKeysFile /etc/paguro/link/authorized_keys"));
    }

    #[test]
    fn authorized_keys_restricted_by_address() {
        let l = authorized_keys_line(" ssh-ed25519 AAAA windows@host \n");
        assert_eq!(l, "from=\"169.254.244.2\" ssh-ed25519 AAAA windows@host");
    }
}
