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

use crate::image::{self, ImageBackend};
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

/// Where to find an unbooted distribution's own file and the volume it
/// lives on — the piece `attach_view_a` needs and does not itself derive.
/// A trait because the real answer needs `paguro.ini` (INTERFACES.md §3.2's
/// `[Boot.<entry>]` `volume`/`root`), which **the running Linux system does
/// not keep a copy of after the handoff** (§8.3 lists what survives it, and
/// the `.ini` is not among them) — resolving this for real needs either a
/// live re-read of the NTFS volume's `paguro.ini` (wherever it is
/// currently mounted) or a cached copy this codebase does not maintain yet.
/// [`UnresolvedLocator`] names that gap explicitly; tests supply a
/// [`FixedLocator`] instead, to exercise everything downstream of it for
/// real.
pub trait DistroLocator {
    /// The distribution's own file (already reachable at this path — e.g.
    /// under a read-only ntfs3 mount of view C) and the `/dev/paguro`
    /// volume id it was registered under.
    fn locate(&self, entry: &str) -> Result<(PathBuf, u32), String>;
}

/// The honest gap: see [`DistroLocator`].
pub struct UnresolvedLocator;

impl DistroLocator for UnresolvedLocator {
    fn locate(&self, entry: &str) -> Result<(PathBuf, u32), String> {
        Err(format!(
            "{entry:?}: locating another distribution's file needs paguro.ini's \
             [Boot.{entry}] (volume, root), which this running system does not keep a copy \
             of after the handoff (INTERFACES.md §8.3); not wired yet. The claim/cross-check/\
             view-A path itself (paguro_linux::image::attach) is implemented and tested — only \
             this lookup is missing."
        ))
    }
}

/// Attach an unbooted distribution's view A at runtime, so its container
/// can be entered: [`DistroLocator::locate`] finds the file and volume,
/// [`crate::image::attach`] claims it by its own ntfs3 identity,
/// cross-checks and loads the table (INTERFACES.md §10.1a, §10.2 — the
/// same sequence `paguro-initrd::setup::boot` runs once at boot, here
/// callable at runtime against a second, not-yet-claimed volume).
pub fn attach_view_a<B: ImageBackend>(
    backend: &mut B,
    locator: &dyn DistroLocator,
    entry: &str,
) -> Result<PathBuf, String> {
    let dev = view_a_path(entry);
    if dev.exists() {
        return Ok(dev);
    }
    let (file, volume_id) = locator.locate(entry)?;
    let attached = image::attach(
        backend,
        volume_id,
        &file,
        entry,
        paguro_initrd::pg::FORMAT_RAW,
    )?;
    Ok(attached.device)
}

/// Mounting a claimed view A and booting a `systemd-nspawn` container over
/// it — behind a trait so the attach path above can be tested without
/// `systemd-nspawn` (not available in every build/test environment).
/// [`SystemdNspawn`] is the real thing.
pub trait ContainerLauncher {
    /// Mount `device` (a `paguro-image` view A) somewhere private to
    /// `name` and return the mount point.
    fn mount(&self, device: &Path, name: &str) -> Result<PathBuf, String>;
    /// Boot `name`'s container rooted at `root`; the exit code once it
    /// stops.
    fn boot(&self, root: &Path, name: &str) -> Result<i32, String>;
}

/// The real launcher: `mount <device> <mnt>` then `systemd-nspawn -D <mnt>
/// -b` ([`nspawn_argv`]).
pub struct SystemdNspawn;

impl ContainerLauncher for SystemdNspawn {
    fn mount(&self, device: &Path, name: &str) -> Result<PathBuf, String> {
        let mnt = PathBuf::from("/run/paguro/nspawn").join(name);
        std::fs::create_dir_all(&mnt).map_err(|e| format!("{}: {e}", mnt.display()))?;
        let st = Command::new("mount")
            .arg(device)
            .arg(&mnt)
            .status()
            .map_err(|e| format!("mount: {e}"))?;
        if !st.success() {
            return Err(format!("mount {}: {st}", device.display()));
        }
        Ok(mnt)
    }

    fn boot(&self, root: &Path, name: &str) -> Result<i32, String> {
        let argv = nspawn_argv(root, name);
        let (prog, rest) = argv.split_first().expect("non-empty argv");
        Command::new(prog)
            .args(rest)
            .status()
            .map(|s| s.code().unwrap_or(1))
            .map_err(|e| format!("{prog}: {e}"))
    }
}

/// `paguro shell`/`paguro distro enter` for another distribution's
/// container: attach its view A if needed, mount it, boot it.
pub fn enter_container<B: ImageBackend, L: ContainerLauncher>(
    backend: &mut B,
    locator: &dyn DistroLocator,
    launcher: &L,
    entry: &str,
) -> Result<i32, String> {
    let device = attach_view_a(backend, locator, entry)?;
    let root = launcher.mount(&device, entry)?;
    launcher.boot(&root, entry)
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
    fn unresolved_locator_names_the_gap_explicitly() {
        let e = UnresolvedLocator.locate("no-such-distro-xyz").unwrap_err();
        assert!(e.contains("no-such-distro-xyz"));
        assert!(e.contains("paguro.ini"));
        assert!(e.contains("not wired"));
    }

    /// A canned [`DistroLocator`] for tests: everything downstream of the
    /// lookup ([`attach_view_a`], [`enter_container`]) is real.
    struct FixedLocator(PathBuf, u32);
    impl DistroLocator for FixedLocator {
        fn locate(&self, _entry: &str) -> Result<(PathBuf, u32), String> {
            Ok((self.0.clone(), self.1))
        }
    }

    /// A minimal fake [`ImageBackend`], just enough for `attach` to reach
    /// `dm_create` (mirrors `image::tests`'s fake, kept separate since that
    /// one is private to its own module).
    #[derive(Default)]
    struct FakeImageBackend {
        crosscheck_state: u32,
    }
    impl ImageBackend for FakeImageBackend {
        fn identity(&self, _file: &Path) -> Result<image::Identity, String> {
            Ok(image::Identity::default())
        }
        fn fiemap(&self, _file: &Path) -> Result<Vec<(u64, u64)>, String> {
            Ok(vec![(1, 1)])
        }
        fn claim(
            &mut self,
            _volume_id: u32,
            _format: u32,
            _id: image::Identity,
        ) -> Result<image::ClaimResult, String> {
            Ok(image::ClaimResult {
                claim_id: 9,
                sectors: 4096,
                state: 0,
            })
        }
        fn crosscheck(&mut self, _claim_id: u32, _ranges: &[(u64, u64)]) -> Result<u32, String> {
            Ok(self.crosscheck_state)
        }
        fn grow(&mut self, _claim_id: u32) -> Result<image::GrowResult, String> {
            unimplemented!("not exercised by these tests")
        }
        fn release(&mut self, _claim_id: u32) -> Result<(), String> {
            Ok(())
        }
        fn dm_create(
            &mut self,
            name: &str,
            _claim_id: u32,
            _sectors: u64,
        ) -> Result<PathBuf, String> {
            Ok(Path::new("/dev/mapper").join(name))
        }
        fn dm_reload(&mut self, _name: &str, _claim_id: u32, _sectors: u64) -> Result<(), String> {
            Ok(())
        }
        fn dm_remove(&mut self, _name: &str) -> Result<(), String> {
            Ok(())
        }
        fn presence(&self, _name: &str) -> Result<image::Presence, String> {
            Ok(image::Presence::Absent)
        }
    }

    #[test]
    fn attach_view_a_claims_and_crosschecks_through_the_locator() {
        let mut backend = FakeImageBackend {
            crosscheck_state: image::CLAIM_CHECKED,
        };
        let locator = FixedLocator(PathBuf::from("/mnt/c/paguro/debian.vhd"), 3);
        let dev = attach_view_a(&mut backend, &locator, "debian-not-booted").unwrap();
        assert_eq!(dev, Path::new("/dev/mapper/paguro-debian-not-booted"));
    }

    #[test]
    fn attach_view_a_surfaces_a_refused_crosscheck() {
        let mut backend = FakeImageBackend {
            crosscheck_state: image::CLAIM_REFUSED,
        };
        let locator = FixedLocator(PathBuf::from("/mnt/c/paguro/x.vhd"), 3);
        let e = attach_view_a(&mut backend, &locator, "x-not-booted").unwrap_err();
        assert!(e.contains("disagrees"));
    }

    /// Records `mount`/`boot` calls instead of running them: `nspawn` is
    /// not available in every environment this crate is tested in.
    #[derive(Default)]
    struct FakeLauncher {
        log: std::cell::RefCell<Vec<String>>,
    }
    impl ContainerLauncher for FakeLauncher {
        fn mount(&self, device: &Path, name: &str) -> Result<PathBuf, String> {
            self.log
                .borrow_mut()
                .push(format!("mount {} {name}", device.display()));
            Ok(PathBuf::from("/run/paguro/nspawn").join(name))
        }
        fn boot(&self, root: &Path, name: &str) -> Result<i32, String> {
            self.log
                .borrow_mut()
                .push(format!("boot {} {name}", root.display()));
            Ok(0)
        }
    }

    #[test]
    fn enter_container_attaches_mounts_then_boots_in_order() {
        let mut backend = FakeImageBackend {
            crosscheck_state: image::CLAIM_CHECKED,
        };
        let locator = FixedLocator(PathBuf::from("/mnt/c/paguro/debian.vhd"), 3);
        let launcher = FakeLauncher::default();
        let code = enter_container(&mut backend, &locator, &launcher, "debian-not-booted").unwrap();
        assert_eq!(code, 0);
        assert_eq!(
            *launcher.log.borrow(),
            vec![
                "mount /dev/mapper/paguro-debian-not-booted debian-not-booted".to_string(),
                "boot /run/paguro/nspawn/debian-not-booted debian-not-booted".to_string(),
            ]
        );
    }
}
