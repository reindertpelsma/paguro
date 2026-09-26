//! `paguro shell <target>` / `paguro distro enter <target>` (DESIGN.md §5c
//! "Shells, the same command both ways", the "From Linux (metal)" column):
//!
//! | target | what happens |
//! |---|---|
//! | `windows` | SSH into the running VM, over the private link |
//! | the running host's own entry | a local shell |
//! | another paguro distribution | its view A, in a `systemd-nspawn` container |

use std::path::{Path, PathBuf};
use std::process::Command;

use paguro_vm::net;

/// Where `paguro-initrd`'s `setup::run` writes `PAGURO_ENTRY=` (among
/// others) at boot (`crates/paguro-initrd/src/main.rs`'s default
/// `--env`). `/run` is tmpfs, mounted before the real root and kept across
/// the pivot on every init system paguro targets, so it is still readable
/// here at runtime.
pub const ROOT_ENV_FILE: &str = "/run/paguro/root.env";

/// The entry this machine booted as (`None`: not a paguro boot, or the
/// file is gone).
pub fn current_entry(env_file: &Path) -> Option<String> {
    std::fs::read_to_string(env_file)
        .ok()?
        .lines()
        .find_map(|l| l.strip_prefix("PAGURO_ENTRY="))
        .map(str::to_string)
}

/// View A's device name (`paguro-initrd::setup::boot`, `paguro-{entry}`):
/// the root image's claim, asserted by the kernel module at load.
pub fn view_a_path(entry: &str) -> PathBuf {
    Path::new("/dev/mapper").join(format!("paguro-{entry}"))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Plan {
    Windows,
    LocalShell,
    Container { device: PathBuf, name: String },
}

/// Pure decision: what `shell <target>` resolves to, given what booted this
/// machine (`current_entry()`). Whether another distribution's view A can
/// actually be reached is decided separately, by [`attach_view_a`] (it may
/// need to attach it first, or refuse with the STUB below) — `resolve`
/// only names the device it would be at.
pub fn resolve(target: &str, booted: Option<&str>) -> Plan {
    if target == "windows" {
        return Plan::Windows;
    }
    if booted == Some(target) {
        return Plan::LocalShell;
    }
    Plan::Container {
        device: view_a_path(target),
        name: target.to_string(),
    }
}

/// Attach an unbooted distribution's view A at runtime, so its container
/// can be entered. **STUB.** `paguro-initrd::setup::boot` claims only the
/// entry chosen at boot (`PG_VOLUME_ADD` + `PG_CLAIM` + the ntfs3
/// cross-check, DESIGN.md §4.3) through `/dev/paguro`
/// (`paguro_initrd::pg::Ctl`, `paguro_initrd::dm::Dm`) — the same calls
/// exist and are exercised by the kernel module's own harness
/// (`kernel/dm-paguro/test/vm-lib.sh`), but only from the initrd's one-shot
/// boot path. Claiming a *second*, already-running system's distribution
/// from a live system needs the same sequence run against a volume that is
/// not the one already mounted as `/` — which raw device holds it, whether
/// it's already added (`PG_VOLUME_ADD` is once per volume), and locking
/// against a concurrent claim of the same volume — none of which exists
/// outside the initrd yet. Until it does, this refuses explicitly instead
/// of guessing.
pub fn attach_view_a(entry: &str) -> Result<PathBuf, String> {
    let dev = view_a_path(entry);
    if dev.exists() {
        return Ok(dev);
    }
    Err(format!(
        "STUB: {entry:?} is not the booted distribution and its view A ({}) does not exist; \
         attaching another distribution's image at runtime needs the pgctl claim path \
         (paguro_initrd::pg::Ctl::{{volume_add,claim,crosscheck}}) wired to a live control \
         device, which is not implemented yet (see kernel/dm-paguro/test/vm-lib.sh for the \
         harness this would be tested with)",
        dev.display()
    ))
}

/// `ssh -i <key> <GUEST_ADDR>`: run from inside netns `paguro`, the only
/// place the private link is reachable (§The private link). This reuses
/// `paguro_vm::net::in_netns` (a `setns` on a dedicated thread) rather than
/// shelling out to `ip netns exec ssh ...`: it is already this codebase's
/// one mechanism for "do this on the link" (`start_samba`, `mount_c` use
/// the same call), so entering the netns gets one implementation instead of
/// a second, argv-based one living beside it.
///
/// `known_hosts` is pinned, never trust-on-first-use (DESIGN.md §5c "The
/// control channel, and keeping the link to itself"): the agent port
/// delivers Windows' host key ahead of time (INTERFACES.md §11.3's
/// "ssh-keys" frame, `crate::link::known_hosts_path`), so
/// `StrictHostKeyChecking` can be `yes` from the very first connection.
pub fn windows_ssh_argv(key_path: &Path, known_hosts: &Path) -> Vec<String> {
    vec![
        "ssh".into(),
        "-i".into(),
        key_path.display().to_string(),
        "-o".into(),
        "StrictHostKeyChecking=yes".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.display()),
        net::GUEST_ADDR.into(),
    ]
}

/// `systemd-nspawn -D <root> --machine=<name> -b`: an ordinary booted
/// container over an already-mounted view A.
pub fn nspawn_argv(root: &Path, name: &str) -> Vec<String> {
    vec![
        "systemd-nspawn".into(),
        "--quiet".into(),
        format!("--machine={name}"),
        "-D".into(),
        root.display().to_string(),
        "-b".into(),
    ]
}

/// Run `argv` from inside netns `paguro`, inheriting this process's stdio
/// (an interactive shell): the child, forked from the netns'd thread,
/// starts in that namespace.
pub fn run_in_netns(argv: &[String]) -> Result<i32, String> {
    let argv = argv.to_vec();
    net::in_netns(move || {
        let (prog, args) = argv.split_first().ok_or("empty command")?;
        let st = Command::new(prog)
            .args(args)
            .status()
            .map_err(|e| format!("{prog}: {e}"))?;
        Ok(st.code().unwrap_or(1))
    })
}

/// Exec (replacing this process) the login shell of whoever is running
/// `paguro`: DESIGN.md's "a local shell", for the running host's own entry.
pub fn exec_local_shell() -> String {
    // Only returns on failure (`execvp` replaces the process on success).
    use std::os::unix::process::CommandExt;
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    let err = Command::new(&shell).exec();
    format!("{shell}: {err}")
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn resolve_windows() {
        assert_eq!(resolve("windows", Some("alpine")), Plan::Windows);
    }

    #[test]
    fn resolve_the_booted_entry_is_local() {
        assert_eq!(resolve("alpine", Some("alpine")), Plan::LocalShell);
    }

    #[test]
    fn resolve_another_entry_is_a_container() {
        match resolve("debian", Some("alpine")) {
            Plan::Container { device, name } => {
                assert_eq!(name, "debian");
                assert_eq!(device, Path::new("/dev/mapper/paguro-debian"));
            }
            other => panic!("expected Container, got {other:?}"),
        }
    }

    #[test]
    fn current_entry_reads_the_env_file() {
        let dir = std::env::temp_dir().join(format!("paguro-linux-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("root.env");
        std::fs::write(&f, "PAGURO_ROOT=/dev/mapper/x\nPAGURO_ENTRY=alpine\n").unwrap();
        assert_eq!(current_entry(&f).as_deref(), Some("alpine"));
        assert_eq!(current_entry(&dir.join("missing")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ssh_argv_targets_the_guest_address_and_pins_known_hosts() {
        let a = windows_ssh_argv(
            Path::new("/etc/paguro/link/id_ed25519"),
            Path::new("/etc/paguro/link/known_hosts"),
        );
        assert_eq!(a[0], "ssh");
        assert!(a.contains(&"169.254.244.2".to_string()));
        assert!(a.iter().any(|x| x == "/etc/paguro/link/id_ed25519"));
        assert!(a.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert!(!a.iter().any(|x| x.contains("accept-new")));
        assert!(
            a.iter()
                .any(|x| x == "UserKnownHostsFile=/etc/paguro/link/known_hosts")
        );
    }

    #[test]
    fn nspawn_argv_shape() {
        let a = nspawn_argv(Path::new("/dev/mapper/paguro-debian"), "debian");
        assert_eq!(a[0], "systemd-nspawn");
        assert!(a.contains(&"--machine=debian".to_string()));
        assert!(a.contains(&"-b".to_string()));
        assert!(a.contains(&"/dev/mapper/paguro-debian".to_string()));
    }

    #[test]
    fn attach_view_a_stub_when_absent() {
        let e = attach_view_a("no-such-distro-xyz").unwrap_err();
        assert!(e.starts_with("STUB"));
        assert!(e.contains("pgctl"));
    }
}
