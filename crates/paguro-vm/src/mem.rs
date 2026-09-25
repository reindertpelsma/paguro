//! Memory policy for the VM (DESIGN.md §4.5): the guest is never the OOM
//! victim, and the host's own workloads are held to what the VM leaves.
//!
//! - QEMU gets `oom_score_adj = -1000`;
//! - the host workloads' cgroup gets a static `memory.max` of
//!   `RAM − the VM's size − QEMU's own overhead` for the VM's lifetime,
//!   restored when it stops.
//!
//! Dynamic lending (free-page reporting, standby purge, the balloon) is
//! §4.5's "later"; nothing here inflates or deflates anything.

use std::fs;
use std::path::{Path, PathBuf};

/// The lowest `oom_score_adj`: never chosen by the OOM killer.
pub const OOM_SCORE_ADJ_MIN: i32 = -1000;
/// QEMU's own memory beside the guest's RAM (device models, page tables,
/// the display): kept out of the host workloads' share.
pub const QEMU_OVERHEAD: u64 = 512 << 20;
/// Never hold the host below this, whatever the VM's size: a limit that
/// small would stall the desktop the VM runs under.
pub const HOST_FLOOR: u64 = 1 << 30;

/// `MemTotal` from `/proc/meminfo`, in bytes.
pub fn mem_total(meminfo: &str) -> Option<u64> {
    meminfo.lines().find_map(|l| {
        let rest = l.strip_prefix("MemTotal:")?;
        let kib: u64 = rest.trim().strip_suffix("kB")?.trim().parse().ok()?;
        kib.checked_mul(1024)
    })
}

/// The host workloads' `memory.max` while a VM of `vm_bytes` runs.
/// `None`: the machine is too small for the VM and a floor for the host.
pub fn host_limit(total: u64, vm_bytes: u64) -> Option<u64> {
    let l = total.checked_sub(vm_bytes)?.checked_sub(QEMU_OVERHEAD)?;
    (l >= HOST_FLOOR).then_some(l)
}

/// `oom_score_adj = -1000` for `pid`.
pub fn protect(pid: u32) -> Result<(), String> {
    let p = format!("/proc/{pid}/oom_score_adj");
    fs::write(&p, OOM_SCORE_ADJ_MIN.to_string()).map_err(|e| format!("{p}: {e}"))
}

/// A cgroup's `memory.max` set for the VM's lifetime.
pub struct HostLimit {
    file: PathBuf,
    previous: String,
}

impl HostLimit {
    pub fn apply(cgroup: &Path, bytes: u64) -> Result<HostLimit, String> {
        let file = cgroup.join("memory.max");
        let previous = fs::read_to_string(&file)
            .map_err(|e| format!("{}: {e}", file.display()))?
            .trim()
            .to_string();
        fs::write(&file, bytes.to_string()).map_err(|e| format!("{}: {e}", file.display()))?;
        Ok(HostLimit { file, previous })
    }
}

impl Drop for HostLimit {
    fn drop(&mut self) {
        let _ = fs::write(&self.file, &self.previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits() {
        let mi = "MemTotal:       32768000 kB\nMemFree:  1 kB\n";
        let total = mem_total(mi).unwrap();
        assert_eq!(total, 32_768_000 * 1024);
        assert_eq!(
            host_limit(total, 8 << 30),
            Some(total - (8 << 30) - QEMU_OVERHEAD)
        );
        assert_eq!(host_limit(8 << 30, 8 << 30), None);
        assert_eq!(host_limit(9 << 30, 8 << 30), None);
        assert_eq!(mem_total("nothing"), None);
    }

    #[test]
    fn restores_on_drop() {
        let d = std::env::temp_dir().join(format!("paguro-vm-cg-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        fs::write(d.join("memory.max"), "max\n").unwrap();
        {
            let _l = HostLimit::apply(&d, 1 << 33).unwrap();
            assert_eq!(
                fs::read_to_string(d.join("memory.max")).unwrap(),
                "8589934592"
            );
        }
        assert_eq!(fs::read_to_string(d.join("memory.max")).unwrap(), "max");
        let _ = fs::remove_dir_all(&d);
    }
}
