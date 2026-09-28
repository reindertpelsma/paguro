//! The private link `paguro0` (DESIGN.md §5c) and the two shares over it
//! (§5b Mode 1, §5c):
//!
//! ```text
//! Windows VM  169.254.244.2/30  ── paguro0 ──  169.254.244.1/30  netns "paguro"
//!   \\169.254.244.1\l   → L:\<distro>    Samba, bound to paguro0 only
//!   \\169.254.244.2\paguro-c  → /mnt/c   mounted from inside the netns
//! ```
//!
//! The host side of the link lives in its own network namespace, so the
//! Samba serving it can bind nothing else and a user's own `smbd` is
//! untouched; the kernel's SMB client mounts `/mnt/c` from inside the same
//! namespace (a CIFS socket belongs to the namespace of the mounting
//! task; the mount itself is visible everywhere). Authentication, not
//! encryption: a generated per-installation secret for a dedicated
//! account on each side, signing on (§5c).
//!
//! Everything here that decides something is text generation, tested
//! below; the glue shells out to iproute2 and Samba's own tools.

use std::path::Path;
use std::process::{Command, Stdio};

pub const NETNS: &str = "paguro";
// The link's constants and the Windows side's provisioning scripts live in
// `paguro-link`, shared with the paguro service that runs them in the VM.
pub use paguro_link::{
    C_SHARE, GUEST_ADDR, HOST_ADDR, IFNAME, L_SHARE, LINK_NET, LINUX_SMB_USER, OUTBOUND_ALLOW_RULE,
    OUTBOUND_BLOCK_RULE, PREFIX, RDP_PORT, SSH_PORT, WINDOWS_SMB_USER, WINDOWS_SSH_FIREWALL_RULE,
    authorized_keys_line, known_hosts_line, windows_outbound_pin_ps1, windows_provision_ps1,
    windows_ssh_provision_ps1,
};
/// Where the Linux side's own SSH state lives (keys, `sshd_config`,
/// `authorized_keys`, `known_hosts`): one constant so `paguro-linux`'s CLI
/// and the agent-port handler below never disagree on the path.
pub const LINK_STATE_DIR: &str = "/etc/paguro/link";

/// `smb.conf` for the netns Samba: one share, the distributions' roots
/// under `root` (`/mnt/l`), bound to `paguro0` only.
pub fn smb_conf(root: &Path, state_dir: &Path) -> String {
    let s = state_dir.display();
    format!(
        "# paguro: the private link's Samba (DESIGN.md §5c). Generated.\n\
         [global]\n\
         \tworkgroup = PAGURO\n\
         \tnetbios name = PAGURO-LINUX\n\
         \tserver role = standalone server\n\
         \tinterfaces = {IFNAME}\n\
         \tbind interfaces only = yes\n\
         \tsmb ports = 445\n\
         \tserver min protocol = SMB3\n\
         \tserver signing = mandatory\n\
         \tsmb encrypt = off\n\
         \tmap to guest = never\n\
         \trestrict anonymous = 2\n\
         \tdisable netbios = yes\n\
         \tload printers = no\n\
         \tprinting = bsd\n\
         \tprintcap name = /dev/null\n\
         \tdisable spoolss = yes\n\
         \tpassdb backend = tdbsam:{s}/passdb.tdb\n\
         \tprivate dir = {s}/private\n\
         \tlock directory = {s}/lock\n\
         \tstate directory = {s}/state\n\
         \tcache directory = {s}/cache\n\
         \tpid directory = {s}\n\
         \tlog file = {s}/log.smbd\n\
         \tncalrpc dir = {s}/ncalrpc\n\
         [{L_SHARE}]\n\
         \tpath = {}\n\
         \tvalid users = {LINUX_SMB_USER}\n\
         \tread only = no\n\
         \tbrowseable = yes\n",
        root.display()
    )
}

/// The CIFS mount options for `/mnt/c` (the password goes in through
/// `password=` in the mount data only; never on a command line).
/// `mode`: how Linux modes are kept. [`CifsModes::Fixed`] gives every file
/// 0644 and every directory 0755; [`CifsModes::FromSid`] (DESIGN.md §5d
/// "The execute bit is the one trust flag") stores `chmod`'s mode in an
/// ACE Windows ignores for access (`S-1-5-88-3-<mode>`), so the bit
/// persists. *Still being verified in the rig* (test/vm/split-e2e.sh's
/// "modefromsid" checks) before anything builds on it.
pub fn cifs_options(user: &str, secret: &str, uid: u32, gid: u32, mode: CifsModes) -> String {
    // A comma would end the option: Samba's convention doubles it.
    let pw = secret.replace(',', ",,");
    let modes = match mode {
        CifsModes::Fixed => "file_mode=0644,dir_mode=0755",
        CifsModes::FromSid => "modefromsid",
    };
    format!(
        "vers=3.1.1,sign,username={user},password={pw},uid={uid},gid={gid},\
         {modes},noserverino,nosharesock,soft,echo_interval=10"
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CifsModes {
    Fixed,
    FromSid,
}

pub fn cifs_source() -> String {
    format!("//{GUEST_ADDR}/{C_SHARE}")
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

/// The netns (created if absent) with its loopback up.
pub fn ensure_netns() -> Result<(), String> {
    if !Path::new("/run/netns").join(NETNS).exists() {
        run(Command::new("ip").args(["netns", "add", NETNS]))?;
    }
    run(Command::new("ip").args(["-n", NETNS, "link", "set", "lo", "up"]))
}

/// Move `ifname` (QEMU's tap, or the test VM's NIC) into the netns and
/// address it.
pub fn attach_link(ifname: &str) -> Result<(), String> {
    run(Command::new("ip").args(["link", "set", ifname, "netns", NETNS]))?;
    if ifname != IFNAME {
        run(Command::new("ip").args(["-n", NETNS, "link", "set", ifname, "name", IFNAME]))?;
    }
    let addr = format!("{HOST_ADDR}/{PREFIX}");
    run(Command::new("ip").args(["-n", NETNS, "addr", "replace", &addr, "dev", IFNAME]))?;
    run(Command::new("ip").args(["-n", NETNS, "link", "set", IFNAME, "up"]))
}

/// Run `f` on a thread that has joined the netns: sockets it opens
/// (a CIFS mount's included) belong to the private link.
pub fn in_netns<T: Send + 'static>(
    f: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    std::thread::spawn(move || {
        let p = Path::new("/run/netns").join(NETNS);
        let ns = std::fs::File::open(&p).map_err(|e| format!("{}: {e}", p.display()))?;
        use std::os::fd::AsRawFd;
        // SAFETY: setns on a valid netns fd, this thread only.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(format!("setns: {}", std::io::Error::last_os_error()));
        }
        f()
    })
    .join()
    .map_err(|_| "netns thread panicked".to_string())?
}

/// Samba for `L:`: `smb.conf` under `state`, the share's account with
/// `secret` (on smbpasswd's stdin), and `smbd` started inside the netns
/// (a daemon: it detaches). `root` holds a folder per distribution.
pub fn start_samba(root: &Path, state: &Path, secret: &str) -> Result<(), String> {
    for d in ["private", "lock", "state", "cache", "ncalrpc"] {
        std::fs::create_dir_all(state.join(d)).map_err(|e| format!("{}: {e}", state.display()))?;
    }
    let conf = state.join("smb.conf");
    std::fs::write(&conf, smb_conf(root, state)).map_err(|e| format!("{}: {e}", conf.display()))?;
    let mut c = Command::new("smbpasswd")
        .arg("-c")
        .arg(&conf)
        .args(["-a", "-s", LINUX_SMB_USER])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .map_err(|e| format!("smbpasswd: {e}"))?;
    {
        use std::io::Write;
        let mut i = c.stdin.take().ok_or("smbpasswd: stdin")?;
        write!(i, "{secret}\n{secret}\n").map_err(|e| format!("smbpasswd: {e}"))?;
    }
    let st = c.wait().map_err(|e| format!("smbpasswd: {e}"))?;
    if !st.success() {
        return Err(format!("smbpasswd: {st}"));
    }
    let pidfile = state.join("smbd.pid");
    let _ = std::fs::remove_file(&pidfile);
    in_netns(move || run(Command::new("smbd").arg("-D").arg("-s").arg(&conf)))?;
    // smbd -D returns before it has set up; it may still give up (a
    // missing guest account, a port in use). Running means its pid file
    // names a live process a moment later.
    for _ in 0..SMBD_POLLS {
        std::thread::sleep(std::time::Duration::from_millis(SMBD_POLL_MS));
        if let Ok(p) = std::fs::read_to_string(&pidfile) {
            if Path::new("/proc").join(p.trim()).exists() {
                return Ok(());
            }
        }
    }
    Err(format!(
        "smbd did not stay up; see {}",
        state.join("log.smbd").display()
    ))
}

const SMBD_POLLS: u32 = 30;
const SMBD_POLL_MS: u64 = 200;

/// Mount `/mnt/c` (Mode 1) from inside the netns.
pub fn mount_c(
    target: &Path,
    secret: &str,
    uid: u32,
    gid: u32,
    mode: CifsModes,
) -> Result<(), String> {
    let target = target.to_path_buf();
    let data = cifs_options(WINDOWS_SMB_USER, secret, uid, gid, mode);
    in_netns(move || {
        std::fs::create_dir_all(&target).map_err(|e| format!("{}: {e}", target.display()))?;
        paguro_initrd::sys::mount(&cifs_source(), &target, "cifs", 0, &data)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn samba_binds_the_link_only() {
        let c = smb_conf(Path::new("/mnt/l"), Path::new("/run/paguro/samba"));
        assert!(c.contains("\tinterfaces = paguro0\n\tbind interfaces only = yes\n"));
        assert!(c.contains("server signing = mandatory"));
        assert!(c.contains("smb encrypt = off"));
        assert!(c.contains("map to guest = never"));
        assert!(c.contains("[l]\n\tpath = /mnt/l\n\tvalid users = paguro\n"));
        assert!(!c.contains("guest ok = yes"));
        assert!(c.contains("passdb backend = tdbsam:/run/paguro/samba/passdb.tdb"));
    }

    #[test]
    fn cifs() {
        let o = cifs_options("paguro-smb", "a,b", 1000, 1000, CifsModes::Fixed);
        assert!(o.contains("password=a,,b,"));
        assert!(o.contains(",file_mode=0644,dir_mode=0755,"));
        let o = cifs_options("paguro-smb", "x", 0, 0, CifsModes::FromSid);
        assert!(o.contains(",modefromsid,") && !o.contains("file_mode"));
        assert!(o.starts_with("vers=3.1.1,sign,"));
        assert_eq!(cifs_source(), "//169.254.244.2/paguro-c");
    }
}
