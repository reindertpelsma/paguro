//! Wires the two VM-mode-only background jobs into the service, without
//! ever blocking its own startup (DESIGN.md §4.4): protecting the images,
//! then arming, on one thread (`crate::vmprotect`, `crate::arming`), and
//! the chkdsk guard (`crate::bootexec`). Skipped entirely, at once, on
//! a native boot (`crate::vmmode`) -- `spawn` itself does only one
//! `smbios()` call before returning; both background threads it may start
//! run independently of the service's own worker (`paguro-service::Worker`)
//! and pipe.
//!
//! Each thread builds its own [`WinApi`] from `make`, called again on every
//! iteration: a platform handle is used from one thread, for one call (or a
//! short burst of them), at a time -- the same rule `paguro-service::Worker`
//! documents for the mock.

use std::sync::Arc;
use std::time::Duration;

use crate::api::WinApi;
use crate::ctx::Ctx;

pub type MakeApi = Arc<dyn Fn() -> Box<dyn WinApi> + Send + Sync>;
pub type Log = Arc<dyn Fn(&str) + Send + Sync>;

/// How often the chkdsk guard re-checks `BootExecute`: cheap (`reg.exe` and
/// `fsutil.exe`), so this can be short without cost.
const CHKDSK_WATCH_INTERVAL: Duration = Duration::from_secs(60);

/// Spawns the background threads and returns at once. `make` and `log` are
/// cloned into each.
pub fn spawn(make: MakeApi, log: Log) {
    let probe = make();
    if !crate::vmmode::detect(probe.as_ref()) {
        log("vm: no paguro-vm/1 marker: native boot, nothing VM-only runs");
        return;
    }
    drop(probe);
    log("vm: paguro-vm/1 marker present: arming and the chkdsk guard are active");
    {
        let (make2, log2) = (make.clone(), log.clone());
        let spawned = std::thread::Builder::new()
            .name("paguro-arm".into())
            .spawn(move || {
                let api = make2();
                let sleep = |d| std::thread::sleep(d);
                // Every image protected first: arming waits on the filter's
                // count, and must not report the driver ready half-way.
                let _pins = crate::vmprotect::run(api.as_ref(), &sleep, &|m| {
                    log2(&format!("protect: {m}"))
                });
                crate::arming::run(api.as_ref(), &sleep, &|m| log2(&format!("arm: {m}")));
                // The pins hold the images' clusters in place for as long
                // as the service runs; this thread's only remaining job.
                loop {
                    std::thread::park();
                }
            });
        if let Err(e) = spawned {
            log(&format!("arm: could not start its thread: {e}"));
        }
    }
    {
        let log2 = log.clone();
        let spawned = std::thread::Builder::new()
            .name("paguro-chkdsk".into())
            .spawn(move || {
                loop {
                    let api = make();
                    crate::bootexec::enforce(&Ctx::new(api.as_ref()), &|m| log2(m));
                    drop(api);
                    std::thread::sleep(CHKDSK_WATCH_INTERVAL);
                }
            });
        if let Err(e) = spawned {
            log(&format!("chkdsk-guard: could not start its thread: {e}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::MockApi;
    use std::sync::Mutex;

    #[test]
    fn native_never_spawns_anything() {
        let calls = Arc::new(Mutex::new(0u32));
        let c = calls.clone();
        let make: MakeApi = Arc::new(move || {
            *c.lock().unwrap() += 1;
            Box::new(MockApi::standard()) as Box<dyn WinApi>
        });
        let logs = Arc::new(Mutex::new(Vec::<String>::new()));
        let l = logs.clone();
        spawn(
            make,
            Arc::new(move |m: &str| l.lock().unwrap().push(m.to_string())),
        );
        // `spawn` only ever probes once, synchronously, before deciding.
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(
            logs.lock()
                .unwrap()
                .iter()
                .any(|l| l.contains("nothing VM-only runs"))
        );
    }
}
