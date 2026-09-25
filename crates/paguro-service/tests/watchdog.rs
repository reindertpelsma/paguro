//! Shared by the service tests: a hang fails fast, with a name, instead of
//! holding a CI job for hours.
#![allow(dead_code)]

use std::time::Duration;

/// Abort the whole test process if `what` is still running after `secs`.
pub fn watchdog(secs: u64, what: &'static str) -> Guard {
    let (tx, rx) = std::sync::mpsc::channel::<()>();
    std::thread::spawn(move || {
        if rx.recv_timeout(Duration::from_secs(secs)) == Err(std::sync::mpsc::RecvTimeoutError::Timeout) {
            eprintln!("\nWATCHDOG: {what} still running after {secs} s: a hang (a pipe read or a process wait without an answer)");
            std::process::exit(124);
        }
    });
    Guard(Some(tx))
}

/// Dropping it (the test ended) stops the watchdog.
pub struct Guard(Option<std::sync::mpsc::Sender<()>>);

impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}
