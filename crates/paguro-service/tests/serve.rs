//! The service's logic on any host: the worker, the connection loop and
//! the JSON-RPC exchange, over a Unix socket pair with the mock machine.
//! The pipe itself and its ACL are tested on Windows (`tests/pipe.rs`).
#![cfg(unix)]
#![allow(clippy::indexing_slicing)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use paguro_service::{Worker, serve};
use paguro_win::api::{Output, WinApi, attr};
use paguro_win::mock::MockApi;
use paguro_win::rpc::Caller;
use serde_json::{Value, json};

fn caller(admin: bool) -> Caller {
    Caller {
        user: if admin { "admin" } else { "user" }.into(),
        admin,
        elevated: admin,
        pid: Some(4242),
    }
}

fn worker_with(f: impl FnOnce() -> MockApi + Send + 'static) -> Arc<Worker> {
    Arc::new(Worker::spawn(
        Box::new(move || Box::new(f()) as Box<dyn WinApi>),
        true,
        Box::new(|api| paguro_service::startup(api, &|_| {})),
    ))
}

struct Conn {
    w: UnixStream,
    r: BufReader<UnixStream>,
}

impl Conn {
    fn open(worker: &Arc<Worker>, c: Caller) -> Conn {
        let (a, b) = UnixStream::pair().unwrap();
        let w = worker.clone();
        std::thread::spawn(move || {
            let r = b.try_clone().unwrap();
            let _ = serve(r, b, &c, &w);
        });
        a.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        Conn {
            r: BufReader::new(a.try_clone().unwrap()),
            w: a,
        }
    }
    fn send(&mut self, s: &str) {
        self.w.write_all(s.as_bytes()).unwrap();
        self.w.write_all(b"\n").unwrap();
    }
    fn next(&mut self) -> Value {
        let mut l = String::new();
        assert!(self.r.read_line(&mut l).unwrap() > 0, "connection closed");
        serde_json::from_str(&l).unwrap()
    }
    /// Notifications, then the response to `id`.
    fn call(&mut self, id: u64, method: &str, params: Value) -> (Vec<Value>, Value) {
        self.send(
            &json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string(),
        );
        let mut notes = Vec::new();
        loop {
            let v = self.next();
            if v.get("id").is_some() && v.get("method").is_none() {
                assert_eq!(v["id"], id);
                return (notes, v);
            }
            notes.push(v);
        }
    }
}

#[test]
fn calls_on_one_connection() {
    let w = worker_with(MockApi::demo);
    let mut c = Conn::open(&w, caller(false));
    let (_, r) = c.call(1, "service.info", json!({}));
    assert_eq!(r["result"]["data"]["service"], true);
    assert_eq!(r["result"]["data"]["caller"]["pid"], 4242);
    // A read-only caller sees only what it may call.
    let methods = r["result"]["data"]["methods"].as_array().unwrap();
    assert!(methods.contains(&json!("status")));
    assert!(!methods.contains(&json!("uninstall")));
    let (_, r) = c.call(2, "distro.list", json!({}));
    assert_eq!(r["result"]["data"]["distributions"][0]["name"], "debian");
    let (_, r) = c.call(3, "config.set", json!({ "tpm": false }));
    assert_eq!(r["error"]["data"]["code"], "needs_elevation");
}

#[test]
fn progress_arrives_before_the_response() {
    let w = worker_with(MockApi::demo);
    let mut c = Conn::open(&w, caller(true));
    let (notes, r) = c.call(
        7,
        "install",
        json!({ "distro": "fedora", "path": "C:\\paguro\\fedora.vhd", "source": "iso", "iso": "C:\\f.iso" }),
    );
    assert!(r["error"]["message"].as_str().unwrap().contains("STUB"));
    assert!(notes.len() >= 8, "{notes:?}");
    assert!(
        notes
            .iter()
            .all(|n| n["method"] == "progress" && n["params"]["id"] == 7)
    );
    assert_eq!(notes[0]["params"]["step"], "host");
    assert_eq!(notes.last().unwrap()["params"]["state"], "failed");
}

#[test]
fn hostile_input() {
    let w = worker_with(MockApi::demo);
    let mut c = Conn::open(&w, caller(true));
    c.send("{not json");
    assert_eq!(c.next()["error"]["code"], -32700);
    c.w.write_all(&[0xff, 0xfe, b'\n']).unwrap();
    assert_eq!(c.next()["error"]["code"], -32700);
    // A notification (no id) gets no answer; the next call still does.
    c.send(r#"{"jsonrpc":"2.0","method":"status"}"#);
    let (_, r) = c.call(9, "service.info", json!({}));
    assert_eq!(r["result"]["exit"], "ok");
    // Longer than the limit: an error, then the connection closes.
    let big = vec![b'x'; paguro_win::rpc::MAX_MESSAGE + 10];
    let _ = c.w.write_all(&big);
    let _ = c.w.write_all(b"\n");
    assert_eq!(c.next()["error"]["code"], -32600);
    let mut rest = String::new();
    assert_eq!(c.r.read_line(&mut rest).unwrap_or(0), 0);
}

#[test]
fn one_call_at_a_time_and_the_second_is_told() {
    let w = worker_with(|| {
        let m = MockApi::demo();
        m.set_runner(|prog, _| {
            if prog == "wsl.exe" {
                std::thread::sleep(Duration::from_millis(400));
            }
            Some(Output {
                status: 0,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        m
    });
    let mut a = Conn::open(&w, caller(true));
    let mut b = Conn::open(&w, caller(true));
    a.send(r#"{"jsonrpc":"2.0","id":1,"method":"checks.list"}"#);
    std::thread::sleep(Duration::from_millis(100));
    let (notes, r) = b.call(2, "service.info", json!({}));
    assert!(r.get("result").is_some());
    assert_eq!(notes.len(), 1, "{notes:?}");
    assert_eq!(notes[0]["method"], "log");
    assert!(a.next().get("result").is_some());
}

#[test]
fn startup_deletes_one_shots() {
    let w = worker_with(|| {
        let m = MockApi::demo();
        for v in ["PaguroSetup", "PaguroBootTarget", "PaguroBootstrap"] {
            m.set_var_raw(v, &paguro_core::guid::PAGURO_VENDOR, &[1], attr::NV_BS_RT);
        }
        m
    });
    let mut c = Conn::open(&w, caller(true));
    let (_, r) = c.call(1, "efi.vars.list", json!({}));
    let vars = r["result"]["data"]["variables"].as_array().unwrap();
    for name in ["PaguroSetup", "PaguroBootstrap"] {
        let v = vars.iter().find(|v| v["name"] == name).unwrap();
        assert_eq!(v["present"], false, "{name}");
    }
}
