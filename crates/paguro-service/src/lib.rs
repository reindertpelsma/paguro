//! `paguro-service` (INTERFACES.md §11.7): the one process that owns every
//! privileged action, serving the API of `paguro_win::rpc` as JSON-RPC 2.0
//! over `\\.\pipe\paguro`, one message per line.
//!
//! - [`Worker`]: one thread owns the platform ([`paguro_win::api::WinApi`])
//!   and runs calls one at a time, in arrival order. Firmware variables,
//!   the ESP and `paguro.ini` are single resources; serialising every call
//!   is the simple way to never interleave two writers.
//! - [`serve`]: one connection, over any byte stream: lines in, the
//!   call's notifications and its response out. The pipe (Windows,
//!   [`win`]) and the Unix socket used by tests and the C# front ends'
//!   development on Linux both use it.
//! - At start, [`startup`] runs the one-shot cleanup of INTERFACES.md §5.
//!
//! Hostile clients (INTERFACES.md §12.0): a line longer than
//! [`paguro_win::rpc::MAX_MESSAGE`] closes the connection; malformed JSON
//! gets a parse error; access is decided per call from the caller's
//! token ([`paguro_win::rpc::Caller`]), never from anything it sends.

use std::io::{self, BufReader, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};

use paguro_win::api::WinApi;
use paguro_win::rpc::{self, Caller};
use serde_json::{Value, json};

#[cfg(windows)]
pub mod win;

/// What a call sends back to its connection.
pub enum Out {
    Note(Value),
    Done(Option<Value>),
}

struct Job {
    line: String,
    caller: Caller,
    out: mpsc::Sender<Out>,
}

/// The platform's owner: one thread, one call at a time.
pub struct Worker {
    tx: mpsc::Sender<Job>,
    busy: Arc<AtomicBool>,
    queued: Arc<AtomicUsize>,
}

/// Builds the platform inside the worker thread (the mock is not `Send`).
pub type MakeApi = Box<dyn FnOnce() -> Box<dyn WinApi> + Send>;
/// Runs first on the worker, with the platform.
pub type OnStart = Box<dyn FnOnce(&dyn WinApi) + Send>;

impl Worker {
    /// Start the worker. `service`: answers as the service (`service.info`).
    /// `on_start` runs first, on the worker, with the platform (the
    /// one-shot cleanup).
    pub fn spawn(make: MakeApi, service: bool, on_start: OnStart) -> Worker {
        let (tx, rx) = mpsc::channel::<Job>();
        let busy = Arc::new(AtomicBool::new(false));
        let queued = Arc::new(AtomicUsize::new(0));
        let (b, q) = (busy.clone(), queued.clone());
        std::thread::Builder::new()
            .name("paguro-worker".into())
            .spawn(move || {
                let api = make();
                on_start(api.as_ref());
                for job in rx {
                    q.fetch_sub(1, Ordering::SeqCst);
                    b.store(true, Ordering::SeqCst);
                    let out = job.out.clone();
                    let note = move |n: &Value| {
                        let _ = out.send(Out::Note(n.clone()));
                    };
                    let r = rpc::handle_line(api.as_ref(), &job.line, &job.caller, service, &note);
                    b.store(false, Ordering::SeqCst);
                    let _ = job.out.send(Out::Done(r));
                }
            })
            .ok();
        Worker { tx, busy, queued }
    }

    /// Queue one request line; its notifications and response arrive on the
    /// receiver, ending with [`Out::Done`].
    pub fn submit(&self, line: String, caller: Caller) -> mpsc::Receiver<Out> {
        let (out, rx) = mpsc::channel();
        let waiting = self.busy.load(Ordering::SeqCst) || self.queued.load(Ordering::SeqCst) > 0;
        if waiting {
            let _ = out.send(Out::Note(rpc::notification(
                "log",
                json!({ "level": "info", "message": "waiting for another operation to finish" }),
            )));
        }
        self.queued.fetch_add(1, Ordering::SeqCst);
        if self
            .tx
            .send(Job {
                line,
                caller,
                out: out.clone(),
            })
            .is_err()
        {
            self.queued.fetch_sub(1, Ordering::SeqCst);
            let _ = out.send(Out::Done(Some(
                json!({ "jsonrpc": "2.0", "id": Value::Null,
                "error": { "code": -32603, "message": "the service's worker has stopped" } }),
            )));
        }
        rx
    }
}

pub use paguro_win::rpc::read_line;

fn write_value<W: Write>(w: &mut W, v: &Value) -> io::Result<()> {
    let mut s = v.to_string();
    s.push('\n');
    w.write_all(s.as_bytes())?;
    w.flush()
}

/// Serve one connection until the client closes it. Write failures (the
/// client went away mid-call) end the connection after the call finishes.
pub fn serve<R: Read, W: Write>(r: R, w: W, caller: &Caller, worker: &Worker) -> io::Result<()> {
    serve_as(r, w, || caller.clone(), worker)
}

/// [`serve`], with the caller identified after the first line arrives: a
/// named pipe's client can only be impersonated once something has been
/// read from it.
pub fn serve_as<R: Read, W: Write>(
    r: R,
    mut w: W,
    identify: impl FnOnce() -> Caller,
    worker: &Worker,
) -> io::Result<()> {
    let mut br = BufReader::new(r);
    let mut identify = Some(identify);
    let mut caller: Option<Caller> = None;
    loop {
        let line = match read_line(&mut br, rpc::MAX_MESSAGE) {
            Ok(Some(l)) => l,
            Ok(None) => return Ok(()),
            Err(e) if e.kind() == io::ErrorKind::InvalidData => {
                let _ = write_value(
                    &mut w,
                    &json!({ "jsonrpc": "2.0", "id": Value::Null,
                        "error": { "code": rpc::codes::INVALID_REQUEST, "message": "message too long: closing" } }),
                );
                return Err(e);
            }
            Err(e) => return Err(e),
        };
        let text = match String::from_utf8(line) {
            Ok(t) => t,
            Err(_) => {
                write_value(
                    &mut w,
                    &json!({ "jsonrpc": "2.0", "id": Value::Null,
                        "error": { "code": rpc::codes::PARSE, "message": "not UTF-8" } }),
                )?;
                continue;
            }
        };
        if text.trim().is_empty() {
            continue;
        }
        if caller.is_none() {
            caller = identify.take().map(|f| f());
        }
        let Some(who) = caller.clone() else {
            return Ok(());
        };
        let rx = worker.submit(text, who);
        let mut alive = true;
        for out in rx {
            let v = match out {
                Out::Note(n) => Some(n),
                Out::Done(r) => {
                    if let (Some(v), true) = (r, alive) {
                        alive = write_value(&mut w, &v).is_ok();
                    }
                    break;
                }
            };
            if let (Some(v), true) = (v, alive) {
                alive = write_value(&mut w, &v).is_ok();
            }
        }
        if !alive {
            return Ok(());
        }
    }
}

/// The one-shot cleanup at service start (INTERFACES.md §5), logged.
pub fn startup(api: &dyn WinApi, log: &dyn Fn(&str)) {
    match paguro_win::cmd::service::startup_cleanup(api) {
        Ok(v) => log(&format!("startup cleanup: {v}")),
        Err(e) => log(&format!("startup cleanup failed: {}", e.message)),
    }
}

/// Development and tests on Unix: the same service on a Unix socket, with
/// a fixed caller (there is no Windows token to read). .NET's
/// `NamedPipeClientStream("x")` connects to `/tmp/CoreFxPipe_x`.
#[cfg(unix)]
pub fn serve_unix(path: &std::path::Path, worker: Arc<Worker>, caller: Caller) -> io::Result<()> {
    use std::os::unix::net::UnixListener;
    let _ = std::fs::remove_file(path);
    let l = UnixListener::bind(path)?;
    for s in l.incoming() {
        let s = s?;
        let (w, c) = (worker.clone(), caller.clone());
        std::thread::spawn(move || {
            if let Ok(r) = s.try_clone() {
                let _ = serve(r, s, &c, &w);
            }
        });
    }
    Ok(())
}
