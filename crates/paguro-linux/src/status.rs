//! `paguro status` (INTERFACES.md §11.2's `paguro config`/JSON conventions,
//! mirrored on the Linux side): is the private link up, is the netns Samba
//! serving `L:`, is the reverse-direction SSH socket listening, is the VM
//! running.

use std::path::Path;
use std::process::Command;

use paguro_vm::net;
use serde::Serialize;
use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct Status {
    pub link_up: bool,
    pub samba_up: bool,
    pub ssh_socket_up: bool,
    pub vm_running: bool,
    /// DESIGN.md §5c "The control channel, and keeping the link to
    /// itself": nothing of paguro's own should ever be reachable outside
    /// the private link. Empty is clean; each entry names what and where.
    pub stray_listeners: Vec<String>,
}

/// `paguro0`'s address inside netns `paguro`, from `ip -n paguro -o addr
/// show paguro0` (parsed rather than trusted blindly: hostile-input rules
/// apply to command output same as anything else here).
pub fn link_up_from_ip_output(out: &str) -> bool {
    out.lines()
        .any(|l| l.contains(net::IFNAME) && l.contains(net::HOST_ADDR))
}

fn netns_link_up() -> bool {
    net::in_netns(|| {
        let o = Command::new("ip")
            .args(["-o", "addr", "show", net::IFNAME])
            .output()
            .map_err(|e| e.to_string())?;
        Ok(o.status.success() && link_up_from_ip_output(&String::from_utf8_lossy(&o.stdout)))
    })
    .unwrap_or(false)
}

/// `state_dir`'s `smbd.pid` (the same file `paguro_vm::net::start_samba`
/// writes and polls) names a live process.
pub fn samba_up(state_dir: &Path) -> bool {
    let pidfile = state_dir.join("smbd.pid");
    std::fs::read_to_string(&pidfile)
        .ok()
        .is_some_and(|p| Path::new("/proc").join(p.trim()).exists())
}

/// `systemctl is-active <unit>` (a plain glue call: this is exactly what
/// the command is for, no reason to open `/run/systemd` sockets by hand).
pub fn ssh_socket_up(unit: &str) -> bool {
    Command::new("systemctl")
        .args(["is-active", "--quiet", unit])
        .status()
        .is_ok_and(|s| s.success())
}

/// A live QEMU: `paguro_vm::session::read_session` succeeding on
/// `work_dir` (the same directory `paguro-vm launch --work` was given).
pub fn vm_running(work_dir: &Path) -> bool {
    paguro_vm::session::read_session(work_dir).is_ok()
}

/// The leading `host:port` of a socket unit's `systemctl show -p Listen
/// --value` (e.g. `"169.254.244.1:22 (Stream)"`); parsed, not trusted
/// blindly, same as any other command output.
pub fn parse_listen_address(show_value: &str) -> Option<(String, u16)> {
    let first = show_value.split_whitespace().next()?;
    let (host, port) = first.rsplit_once(':')?;
    Some((host.trim().to_string(), port.parse().ok()?))
}

fn ssh_socket_listen_address(unit: &str) -> Option<(String, u16)> {
    let o = Command::new("systemctl")
        .args(["show", unit, "-p", "Listen", "--value"])
        .output()
        .ok()?;
    if !o.status.success() {
        return None;
    }
    parse_listen_address(String::from_utf8_lossy(&o.stdout).trim())
}

/// Pure: given where the SSH socket is actually listening (`None`: not
/// listening at all, nothing to flag), the report `stray_listeners`
/// produces for it.
fn check_ssh_socket(unit: &str, listen: Option<(String, u16)>) -> Vec<String> {
    match listen {
        Some((host, port)) if host != net::HOST_ADDR => vec![format!(
            "{unit}: listening on {host}:{port}, not the private link ({})",
            net::HOST_ADDR
        )],
        _ => Vec::new(),
    }
}

/// Anything of paguro's own bound outside the private link. Today: the
/// reverse-direction SSH socket, the one thing here with an address
/// systemd will report directly; Samba's confinement
/// (`net::smb_conf`'s `bind interfaces only`) is enforced by generation
/// and covered there, not by a second runtime probe.
pub fn stray_listeners(ssh_unit: &str) -> Vec<String> {
    check_ssh_socket(ssh_unit, ssh_socket_listen_address(ssh_unit))
}

pub fn gather(samba_state_dir: &Path, ssh_unit: &str, vm_work_dir: &Path) -> Status {
    Status {
        link_up: netns_link_up(),
        samba_up: samba_up(samba_state_dir),
        ssh_socket_up: ssh_socket_up(ssh_unit),
        vm_running: vm_running(vm_work_dir),
        stray_listeners: stray_listeners(ssh_unit),
    }
}

pub fn to_json(s: &Status) -> Value {
    serde_json::to_value(s).unwrap_or(Value::Null)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn parses_ip_addr_show_for_the_link_address() {
        let up = "5: paguro0    inet 169.254.244.1/30 scope global paguro0\\       valid_lft forever preferred_lft forever";
        assert!(link_up_from_ip_output(up));
        assert!(!link_up_from_ip_output(
            "5: paguro0    inet 10.0.0.5/24 scope global paguro0"
        ));
        assert!(!link_up_from_ip_output(""));
    }

    #[test]
    fn listen_address_parsed_from_systemctl_show() {
        assert_eq!(
            parse_listen_address("169.254.244.1:22 (Stream)"),
            Some(("169.254.244.1".to_string(), 22))
        );
        assert_eq!(parse_listen_address(""), None);
        assert_eq!(parse_listen_address("garbage"), None);
    }

    #[test]
    fn stray_listener_flagged_when_off_the_link() {
        let clean = check_ssh_socket("paguro-ssh.socket", Some(("169.254.244.1".into(), 22)));
        assert!(clean.is_empty());

        let stray = check_ssh_socket("paguro-ssh.socket", Some(("0.0.0.0".into(), 22)));
        assert_eq!(stray.len(), 1);
        assert!(stray[0].contains("0.0.0.0:22"));
        assert!(stray[0].contains("paguro-ssh.socket"));

        assert!(check_ssh_socket("paguro-ssh.socket", None).is_empty());
    }

    #[test]
    fn samba_up_false_without_a_live_pid() {
        let d = std::env::temp_dir().join(format!("paguro-status-test-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        assert!(!samba_up(&d));
        std::fs::write(d.join("smbd.pid"), "1").unwrap();
        assert!(samba_up(&d), "pid 1 (init) always exists");
        std::fs::write(d.join("smbd.pid"), "999999999").unwrap();
        assert!(!samba_up(&d), "no such pid");
        let _ = std::fs::remove_dir_all(&d);
    }
}
