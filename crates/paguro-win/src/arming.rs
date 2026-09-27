//! DESIGN.md §4.4 "Until the driver arms: the tripwire" — the paguro
//! service's half (INTERFACES.md §11.3, "Arming"). In the paguro VM only
//! (`crate::vmmode::detect`), once the minifilter reports its own
//! protections in place (`FilterPort::query_status`, `Protected > 0`), send
//! the driver frame on the agent port (`crate::agent`), wait for the host's
//! ack, and only on `ok:true` tell the filter it is armed
//! (`FilterPort::send_armed`). [`run`] never blocks the service's own
//! startup: `crate::vmservice::spawn` runs it on its own thread, and it
//! retries with backoff wherever DESIGN.md says the port may not be there
//! yet.
//!
//! `sleep` and `log` are injected so the retry policy is exercised without
//! real timing in tests (see the `mod tests` below); production passes
//! `std::thread::sleep` and the service's own log.

use std::time::Duration;

use serde_json::json;

use crate::agent::{self, PORT_NAME};
use crate::api::{WinApi, join};

/// `%ProgramData%\paguro\vm-arm.json`: the last outcome, read by `paguro
/// status` (`crate::cmd::status`).
pub fn state_path(api: &dyn WinApi) -> String {
    join(&api.program_data(), "paguro\\vm-arm.json")
}

fn save(api: &dyn WinApi, armed: bool, detail: &str) {
    let _ = api.create_dir_all(&join(&api.program_data(), "paguro"));
    let body = json!({ "armed": armed, "at_unix": api.now_unix(), "detail": detail }).to_string();
    let _ = api.write_file(&state_path(api), body.as_bytes());
}

/// Exponential backoff, capped, doubling from `start` to `max`. Pure and
/// tested on its own, below.
pub struct Backoff {
    cur: Duration,
    max: Duration,
}

impl Backoff {
    pub fn new(start: Duration, max: Duration) -> Self {
        Backoff { cur: start, max }
    }
    /// The wait for this attempt; primes the next, longer one.
    pub fn wait(&mut self) -> Duration {
        let d = self.cur;
        self.cur = self.cur.saturating_mul(2).min(self.max);
        d
    }
}

const RETRY_START: Duration = Duration::from_millis(250);
const RETRY_MAX: Duration = Duration::from_secs(30);

/// Waits for the filter to report at least one protection in place.
/// Returns only once that holds, or once it is already armed (in which
/// case the caller has nothing left to do).
enum FilterWait {
    Ready,
    AlreadyArmed,
}

fn wait_for_filter(api: &dyn WinApi, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) -> FilterWait {
    let mut backoff = Backoff::new(RETRY_START, RETRY_MAX);
    loop {
        match api.open_filter_port() {
            Ok(Some(mut p)) => match p.query_status() {
                Ok(s) if s.armed => return FilterWait::AlreadyArmed,
                Ok(s) if s.protected > 0 => return FilterWait::Ready,
                Ok(_) => log("driver: loaded, waiting for its protections to be in place"),
                Err(e) => log(&format!("driver: \\PaguroPort: {e}")),
            },
            Ok(None) => log("driver: \\PaguroPort not present yet"),
            Err(e) => log(&format!("driver: {e}")),
        }
        sleep(backoff.wait());
    }
}

/// One attempt of the agent handshake once the filter is ready. `Some(())`:
/// armed (the filter was told so); `None`: not armed this attempt, try
/// again after a backoff.
fn try_arm(api: &dyn WinApi, log: &dyn Fn(&str)) -> Option<()> {
    let mut port = match api.open_agent_port(PORT_NAME) {
        Ok(Some(p)) => p,
        Ok(None) => {
            log("agent: the port is not present yet");
            return None;
        }
        Err(e) => {
            log(&format!("agent: {e}"));
            return None;
        }
    };
    match agent::handshake(&mut *port) {
        Ok(true) => {
            log("driver: reported; the host acked; armed");
            match api.open_filter_port() {
                Ok(Some(mut p)) => match p.send_armed() {
                    Ok(()) => {
                        save(api, true, "armed after the host's ack");
                        Some(())
                    }
                    Err(e) => {
                        log(&format!("driver: ARMED: {e}"));
                        save(
                            api,
                            false,
                            &format!("the host acked but the filter refused ARMED: {e}"),
                        );
                        None
                    }
                },
                Ok(None) => {
                    log("driver: the filter port went away before ARMED could be sent");
                    save(
                        api,
                        false,
                        "the filter port went away before ARMED could be sent",
                    );
                    None
                }
                Err(e) => {
                    log(&format!("driver: {e}"));
                    None
                }
            }
        }
        Ok(false) => {
            log("driver: reported; the host refused the ack (not armed)");
            save(api, false, "the host refused the ack");
            None
        }
        Err(e) => {
            log(&format!("agent: {e}"));
            None
        }
    }
}

/// Runs until armed, or forever if it never is (DESIGN.md §4.4: there is no
/// timeout on the driver's side of this handshake either -- see
/// `crate::agent`'s module documentation).
pub fn run(api: &dyn WinApi, sleep: &dyn Fn(Duration), log: &dyn Fn(&str)) {
    if !crate::vmmode::detect(api) {
        log("not the paguro VM (no paguro-vm/1 marker): nothing to arm");
        return;
    }
    if matches!(wait_for_filter(api, sleep, log), FilterWait::AlreadyArmed) {
        log("driver: already armed");
        save(api, true, "already armed at service start");
        return;
    }
    let mut backoff = Backoff::new(RETRY_START, RETRY_MAX);
    while try_arm(api, log).is_none() {
        sleep(backoff.wait());
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::mock::MockApi;
    use serde_json::Value;
    use std::cell::{Cell, RefCell};

    #[test]
    fn backoff_doubles_and_caps() {
        let mut b = Backoff::new(Duration::from_millis(100), Duration::from_millis(500));
        assert_eq!(b.wait(), Duration::from_millis(100));
        assert_eq!(b.wait(), Duration::from_millis(200));
        assert_eq!(b.wait(), Duration::from_millis(400));
        assert_eq!(b.wait(), Duration::from_millis(500)); // capped, not 800
        assert_eq!(b.wait(), Duration::from_millis(500));
    }

    /// A no-op sleep that also lets a test script state changes between
    /// retries, the way real time would let the filter or the host move.
    fn ticking<'a>(m: &'a MockApi, on_tick: impl Fn(&MockApi, u32) + 'a) -> impl Fn(Duration) + 'a {
        let n = Cell::new(0u32);
        move |_d| {
            n.set(n.get() + 1);
            on_tick(m, n.get());
        }
    }

    fn silent(_msg: &str) {}

    fn logging(sink: &RefCell<Vec<String>>) -> impl Fn(&str) + '_ {
        move |m: &str| sink.borrow_mut().push(m.to_string())
    }

    #[test]
    fn native_does_nothing() {
        let m = MockApi::standard(); // no smbios marker
        let logs = RefCell::new(Vec::new());
        run(&m, &|_| {}, &logging(&logs));
        assert!(logs.borrow().iter().any(|l| l.contains("nothing to arm")));
        assert!(m.filter_port.borrow().is_none());
    }

    fn with_marker(m: &MockApi) {
        let table: Vec<u8> = [
            11u8, 5, 0, 0, 1, b'p', b'a', b'g', b'u', b'r', b'o', b'-', b'v', b'm', b'/', b'1', 0,
            0,
        ]
        .to_vec();
        let mut blob = vec![0u8, 3, 4, 0];
        blob.extend_from_slice(&(table.len() as u32).to_le_bytes());
        blob.extend_from_slice(&table);
        *m.smbios_blob.borrow_mut() = blob;
    }

    #[test]
    fn arms_after_ok_true() {
        let m = MockApi::standard();
        with_marker(&m);
        let status = std::rc::Rc::new(Cell::new(crate::api::FilterStatus::default()));
        *m.filter_port.borrow_mut() = Some(status.clone());
        // Ready (protected > 0) from the first query.
        status.set(crate::api::FilterStatus {
            protected: 1,
            armed: false,
        });
        let agent_state = std::rc::Rc::new(RefCell::new(crate::mock::MockAgentState {
            writes: Vec::new(),
            reads: [Ok(agent::encode(
                &serde_json::json!({"type": "armed", "ok": true}),
            ))]
            .into_iter()
            .collect(),
        }));
        *m.agent_port.borrow_mut() = Some(agent_state);
        run(&m, &|_| {}, &silent);
        assert!(status.get().armed, "the filter was told ARMED");
        let saved: Value =
            serde_json::from_slice(&m.read_file(&state_path(&m), 1 << 16).unwrap().unwrap())
                .unwrap();
        assert_eq!(saved["armed"], true);
    }

    #[test]
    fn ok_false_is_not_armed_and_retries() {
        let m = MockApi::standard();
        with_marker(&m);
        let status = std::rc::Rc::new(Cell::new(crate::api::FilterStatus {
            protected: 1,
            armed: false,
        }));
        *m.filter_port.borrow_mut() = Some(status.clone());
        let agent_state = std::rc::Rc::new(RefCell::new(crate::mock::MockAgentState {
            writes: Vec::new(),
            reads: [
                Ok(agent::encode(
                    &serde_json::json!({"type": "armed", "ok": false, "error": "no"}),
                )),
                Ok(agent::encode(
                    &serde_json::json!({"type": "armed", "ok": true}),
                )),
            ]
            .into_iter()
            .collect(),
        }));
        *m.agent_port.borrow_mut() = Some(agent_state);
        let logs = RefCell::new(Vec::new());
        // Stop the (otherwise unbounded) retry loop's sleeps from spinning
        // forever if something regresses: bail after a generous bound.
        let ticks = Cell::new(0u32);
        run(
            &m,
            &|_| {
                ticks.set(ticks.get() + 1);
                assert!(ticks.get() < 100, "did not converge");
            },
            &logging(&logs),
        );
        assert!(status.get().armed);
        assert!(logs.borrow().iter().any(|l| l.contains("refused the ack")));
    }

    #[test]
    fn waits_for_the_filter_before_touching_the_agent_port() {
        let m = MockApi::standard();
        with_marker(&m);
        let status = std::rc::Rc::new(Cell::new(crate::api::FilterStatus::default()));
        *m.filter_port.borrow_mut() = Some(status.clone());
        // No agent port at all yet: if `run` reached for it before the
        // filter was ready, `open_agent_port` would return `Ok(None)`
        // forever and this test would spin -- the tick bound below catches it.
        let ticks = Cell::new(0u32);
        let sleep = ticking(&m, |m, n| {
            if n == 3 {
                m.filter_port
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .set(crate::api::FilterStatus {
                        protected: 1,
                        armed: false,
                    });
                *m.agent_port.borrow_mut() = Some(std::rc::Rc::new(RefCell::new(
                    crate::mock::MockAgentState {
                        writes: Vec::new(),
                        reads: [Ok(agent::encode(
                            &serde_json::json!({"type": "armed", "ok": true}),
                        ))]
                        .into_iter()
                        .collect(),
                    },
                )));
            }
            ticks.set(ticks.get() + 1);
            assert!(ticks.get() < 100, "did not converge");
        });
        run(&m, &sleep, &silent);
        assert!(status.get().armed);
    }
}
