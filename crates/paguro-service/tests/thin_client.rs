//! `paguro.exe` as a thin client (INTERFACES.md §11.7): the same command
//! lines, run in-process and through the service, render the same output
//! and exit code — including secrets the service asks back for, progress,
//! and the front end's own work (writing an export, the distro shell).
#![cfg(unix)]
#![allow(clippy::indexing_slicing)]

#[path = "watchdog.rs"]
mod watchdog;

use std::cell::RefCell;
use std::os::unix::net::UnixStream;
use std::sync::Arc;

use paguro_service::{Worker, serve};
use paguro_win::api::WinApi;
use paguro_win::cli::{self, Transport};
use paguro_win::client::StreamTransport;
use paguro_win::mock::MockApi;
use paguro_win::rpc::Caller;

fn admin() -> Caller {
    Caller {
        user: "t".into(),
        admin: true,
        elevated: true,
        pid: None,
    }
}

/// A service with its own demo machine, and a transport to it.
fn service(c: Caller) -> Box<dyn Transport> {
    let w = Arc::new(Worker::spawn(
        Box::new(|| Box::new(MockApi::demo()) as Box<dyn WinApi>),
        true,
        Box::new(|_| {}),
    ));
    let (a, b) = UnixStream::pair().unwrap();
    std::thread::spawn(move || {
        let r = b.try_clone().unwrap();
        let _ = serve(r, b, &c, &w);
    });
    let r = a.try_clone().unwrap();
    Box::new(StreamTransport::new(Box::new(r), Box::new(a)))
}

struct Run {
    code: i32,
    stdout: String,
    live: Vec<String>,
    local: MockApi,
}

fn run(args: &[&str], remote: Option<Caller>, prep: &dyn Fn(&MockApi)) -> Run {
    let local = MockApi::demo();
    prep(&local);
    let mut argv = vec!["paguro", "--json"];
    argv.extend_from_slice(args);
    let live = RefCell::new(Vec::new());
    let t = RefCell::new(remote.map(service));
    let connect = || t.borrow_mut().take();
    let r = cli::run_with(
        &local,
        argv,
        &connect,
        &|l| live.borrow_mut().push(l.to_string()),
        &|_| None,
    );
    Run {
        code: r.code,
        stdout: r.stdout,
        live: live.into_inner(),
        local,
    }
}

const SAME: &[&[&str]] = &[
    &["status"],
    &["checks", "list"],
    &["--dry-run", "checks", "fix", "fast_startup"],
    &["distro", "list"],
    &["config", "show"],
    &["config", "validate"],
    &["--dry-run", "config", "set", "--keyboard", "de"],
    &["config", "set", "--keyboard", "de", "--tpm", "0"],
    &["config", "set", "--tpm", "2"],
    &["efi", "vars", "list"],
    &["efi", "vars", "get", "PaguroConfigHash"],
    &["efi", "boot-entry", "list"],
    &["esp", "verify"],
    &["mok", "status"],
    &["preflight"],
    &["--dry-run", "restart-linux", "--entry", "debian"],
    &["restart-linux", "--entry", "nosuch"],
    &["--dry-run", "uninstall"],
    &["uninstall"],
    &["protection", "options", "--klid", "00000407"],
    &["secure-boot", "status"],
    &["disk", "inspect", "C:\\paguro\\debian.vhd"],
    &[
        "--dry-run",
        "disk",
        "create",
        "--size",
        "1G",
        "--path",
        "C:\\paguro\\x.vhd",
    ],
    &[
        "--dry-run",
        "install",
        "fedora",
        "--path",
        "C:\\paguro\\f.vhd",
        "--iso",
        "C:\\f.iso",
    ],
    &[
        "install",
        "fedora",
        "--path",
        "C:\\paguro\\f.vhd",
        "--iso",
        "C:\\f.iso",
    ],
    &["distro", "grow", "debian", "--size", "64G"],
    &["--dry-run", "distro", "rename", "debian", "deb"],
    &["--dry-run", "distro", "remove", "debian", "--delete-image"],
];

#[test]
fn direct_and_through_the_service_render_the_same() {
    let _watchdog = watchdog::watchdog(120, "direct_and_through_the_service_render_the_same");
    for args in SAME {
        let d = run(args, None, &|_| {});
        let s = run(args, Some(admin()), &|_| {});
        assert_eq!(d.code, s.code, "{args:?}\n{}\n---\n{}", d.stdout, s.stdout);
        assert_eq!(d.stdout, s.stdout, "{args:?}");
    }
}

#[test]
fn secrets_asked_back_are_prompted_by_the_front_end() {
    let _watchdog = watchdog::watchdog(120, "secrets_asked_back_are_prompted_by_the_front_end");
    let secret = |m: &MockApi| {
        m.push_secret("azerty");
        m.push_secret("azerty");
    };
    for args in [
        &["protection", "set", "passphrase", "--keyboard", "fr"][..],
        &["protection", "check", "--keyboard", "fr"][..],
    ] {
        let d = run(args, None, &secret);
        let s = run(args, Some(admin()), &secret);
        assert_eq!(d.code, 0, "{args:?}: {}", d.stdout);
        assert_eq!((d.code, &d.stdout), (s.code, &s.stdout), "{args:?}");
    }
    // Refused characters: same refusal both ways.
    let dead = |m: &MockApi| {
        m.push_secret("aê");
        m.push_secret("aê");
    };
    let d = run(
        &["protection", "set", "passphrase", "--keyboard", "fr"],
        None,
        &dead,
    );
    let s = run(
        &["protection", "set", "passphrase", "--keyboard", "fr"],
        Some(admin()),
        &dead,
    );
    assert_eq!(d.code, 3);
    assert_eq!(d.stdout, s.stdout);
    // --passphrase-stdin answers the question from standard input.
    let stdin = |m: &MockApi| *m.stdin.borrow_mut() = b"azerty\n".to_vec();
    let s = run(
        &[
            "--passphrase-stdin",
            "protection",
            "check",
            "--keyboard",
            "fr",
        ],
        Some(admin()),
        &stdin,
    );
    assert_eq!(s.code, 0, "{}", s.stdout);
}

#[test]
fn progress_is_shown_live_through_the_service() {
    let _watchdog = watchdog::watchdog(120, "progress_is_shown_live_through_the_service");
    let s = run(
        &[
            "install",
            "fedora",
            "--path",
            "C:\\paguro\\f.vhd",
            "--iso",
            "C:\\f.iso",
        ],
        Some(admin()),
        &|_| {},
    );
    assert!(
        s.live.iter().any(|l| l.starts_with("[1/9] host: running")),
        "{:?}",
        s.live
    );
    assert!(
        s.live.iter().any(|l| l.contains("build: failed")),
        "{:?}",
        s.live
    );
}

#[test]
fn the_front_end_writes_its_own_files_and_runs_the_shell() {
    let _watchdog = watchdog::watchdog(120, "the_front_end_writes_its_own_files_and_runs_the_shell");
    let s = run(
        &["hw", "export", "-o", "C:\\ProgramData\\hw.json"],
        Some(admin()),
        &|_| {},
    );
    assert_eq!(s.code, 0);
    let body = s
        .local
        .file("C:\\ProgramData\\hw.json")
        .expect("written by the front end");
    assert!(String::from_utf8_lossy(&body).contains("\"version\": 1"));
    let modal = |m: &MockApi| {
        m.put_file("C:\\hw.json", br#"{"version":1,"cpu":{"vendor":"x","family":6,"model":1,"stepping":1},"dmi":{"sys_vendor":"","product_name":"","board_vendor":"","board_name":"","bios_vendor":"","bios_version":""},"pci":[{"vendor":"10de","device":"28a0","subvendor":"1043","subdevice":"1f3a","class":"030000"}],"usb":[],"acpi":[],"storage":[]}"#)
    };
    let d = run(&["hw", "modalias", "C:\\hw.json"], None, &modal);
    let r = run(&["hw", "modalias", "C:\\hw.json"], Some(admin()), &modal);
    assert_eq!(d.code, 0, "{}", d.stdout);
    assert_eq!(d.stdout, r.stdout);
    let e = run(&["distro", "enter", "debian"], Some(admin()), &|_| {});
    assert_eq!(e.code, 0, "{}", e.stdout);
    assert_eq!(
        e.local.interactive.borrow().as_slice(),
        ["wsl.exe --user root"]
    );
    assert!(e.stdout.contains("detached"), "{}", e.stdout);
}

#[test]
fn a_read_only_caller_is_refused_what_needs_an_administrator() {
    let _watchdog = watchdog::watchdog(120, "a_read_only_caller_is_refused_what_needs_an_administrator");
    let s = run(
        &["config", "set", "--tpm", "0"],
        Some(Caller {
            admin: false,
            elevated: false,
            ..admin()
        }),
        &|_| {},
    );
    assert_eq!(s.code, 7, "{}", s.stdout);
    let v: serde_json::Value = serde_json::from_str(&s.stdout).unwrap();
    assert_eq!(v["error"]["code"], "needs_elevation");
    let s = run(
        &["--dry-run", "uninstall"],
        Some(Caller {
            admin: false,
            elevated: false,
            ..admin()
        }),
        &|_| {},
    );
    assert_eq!(s.code, 0, "the uninstall summary is readable: {}", s.stdout);
    let s = run(
        &["service", "info"],
        Some(Caller {
            admin: false,
            elevated: false,
            ..admin()
        }),
        &|_| {},
    );
    let v: serde_json::Value = serde_json::from_str(&s.stdout).unwrap();
    assert_eq!(v["data"]["service"], true);
    assert_eq!(v["data"]["caller"]["admin"], false);
}
