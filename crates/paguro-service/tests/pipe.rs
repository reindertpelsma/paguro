//! The named pipe on a real Windows (the CI runner, elevated): its ACL,
//! squatting, who the caller is taken to be, and calls through it — with
//! the mock machine behind, so nothing on the runner changes.
//!
//! The account tests (`PAGURO_PIPE_ACCOUNT_TESTS=1`, set in CI) create a
//! local standard user to connect as, and delete it again.
#![cfg(windows)]
#![allow(unsafe_code, clippy::indexing_slicing)]

#[path = "watchdog.rs"]
mod watchdog;

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::windows::io::AsRawHandle;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use paguro_service::Worker;
use paguro_service::win;
use paguro_win::api::WinApi;
use paguro_win::mock::MockApi;
use serde_json::{Value, json};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    CreateRestrictedToken, CreateWellKnownSid, DISABLE_MAX_PRIVILEGE, GetTokenInformation,
    ImpersonateLoggedOnUser, IsWellKnownSid, LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK,
    LOGON32_PROVIDER_DEFAULT, LogonUserW, PSID, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_ALL_ACCESS,
    TOKEN_GROUPS, TOKEN_QUERY, TokenGroups, WinBuiltinAdministratorsSid, WinInteractiveSid,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::HSTRING;

fn start(name: &str) -> Arc<Worker> {
    let w = Arc::new(Worker::spawn(
        Box::new(|| Box::new(MockApi::demo()) as Box<dyn WinApi>),
        true,
        Box::new(|_| {}),
    ));
    let (n, w2) = (name.to_string(), w.clone());
    std::thread::spawn(move || {
        let _ = win::serve_pipe(
            &n,
            w2,
            Arc::new(AtomicBool::new(false)),
            Arc::new(|m: &str| eprintln!("{m}")),
        );
    });
    std::thread::sleep(Duration::from_millis(300));
    w
}

fn unique(tag: &str) -> String {
    format!("paguro-test-{tag}-{}", std::process::id())
}

fn open(name: &str) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    OpenOptions::new()
        .access_mode(win::CLIENT_ACCESS)
        .open(win::pipe_path(name))
}

fn call(f: &File, method: &str, params: Value) -> Value {
    let mut w = f;
    w.write_all(
        format!(
            "{}\n",
            json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params })
        )
        .as_bytes(),
    )
    .unwrap();
    let mut r = BufReader::new(f);
    loop {
        let mut l = String::new();
        r.read_line(&mut l).unwrap();
        let v: Value = serde_json::from_str(&l).unwrap();
        if v.get("id").is_some() {
            return v;
        }
    }
}

#[test]
fn acl_owner_and_calls() {
    let _watchdog = watchdog::watchdog(60, "acl_owner_and_calls");
    let name = unique("acl");
    let _w = start(&name);
    let f = open(&name).expect("connect");
    let sddl = win::sddl_of(HANDLE(f.as_raw_handle())).unwrap();
    eprintln!("pipe SDDL: {sddl}");
    assert!(sddl.starts_with("O:BA"), "{sddl}");
    assert!(sddl.contains(";;;SY)") && sddl.contains(";;;BA)"), "{sddl}");
    assert!(
        sddl.contains("(A;;0x12018b;;;IU)"),
        "interactive user: read/write, no FILE_CREATE_PIPE_INSTANCE: {sddl}"
    );
    for other in [";;;WD)", ";;;AU)", ";;;BU)", ";;;AN)", ";;;NU)"] {
        assert!(!sddl.contains(other), "{other} in {sddl}");
    }
    let r = call(&f, "service.info", json!({}));
    let c = &r["result"]["data"]["caller"];
    eprintln!("caller: {c}");
    assert_eq!(c["admin"], true);
    assert_eq!(c["elevated"], true, "the runner is elevated");
    assert!(c["user"].as_str().unwrap().contains('\\'));
    assert_eq!(c["pid"], std::process::id());
    let r = call(&f, "distro.list", json!({}));
    assert_eq!(r["result"]["data"]["distributions"][0]["name"], "debian");
}

/// GENERIC_WRITE includes FILE_CREATE_PIPE_INSTANCE: the elevated runner
/// has full control; the ACL is what keeps the interactive user from it.
#[test]
fn generic_write_is_more_than_a_client_needs() {
    let _watchdog = watchdog::watchdog(60, "generic_write_is_more_than_a_client_needs");
    let name = unique("gw");
    let _w = start(&name);
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .open(win::pipe_path(&name));
    assert!(f.is_ok(), "the elevated runner has full control: {f:?}");
}

#[test]
fn a_squatted_name_is_refused() {
    let _watchdog = watchdog::watchdog(60, "a_squatted_name_is_refused");
    let name = unique("squat");
    let _w = start(&name);
    let w2 = Arc::new(Worker::spawn(
        Box::new(|| Box::new(MockApi::demo()) as Box<dyn WinApi>),
        true,
        Box::new(|_| {}),
    ));
    let e = win::serve_pipe(
        &name,
        w2,
        Arc::new(AtomicBool::new(false)),
        Arc::new(|_: &str| {}),
    )
    .expect_err("FILE_FLAG_FIRST_PIPE_INSTANCE");
    eprintln!("second server: {e}");
}

fn sid(kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE) -> Vec<u8> {
    let mut buf = vec![0u8; 68];
    let mut n = buf.len() as u32;
    unsafe { CreateWellKnownSid(kind, None, Some(PSID(buf.as_mut_ptr().cast())), &mut n) }.unwrap();
    buf.truncate(n as usize);
    buf
}

fn has_group(tok: HANDLE, kind: windows::Win32::Security::WELL_KNOWN_SID_TYPE) -> bool {
    let mut len = 0;
    let _ = unsafe { GetTokenInformation(tok, TokenGroups, None, 0, &mut len) };
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    unsafe {
        GetTokenInformation(
            tok,
            TokenGroups,
            Some(buf.as_mut_ptr().cast()),
            len,
            &mut len,
        )
    }
    .unwrap();
    let groups = unsafe {
        let tg = &*(buf.as_ptr().cast::<TOKEN_GROUPS>());
        std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
    };
    groups
        .iter()
        .any(|g| unsafe { IsWellKnownSid(g.Sid, kind) }.as_bool())
}

/// Run `f` on a thread impersonating `tok`.
fn as_token<T: Send + 'static>(tok: HANDLE, f: impl FnOnce() -> T + Send + 'static) -> T {
    let raw = tok.0 as usize;
    std::thread::spawn(move || {
        unsafe { ImpersonateLoggedOnUser(HANDLE(raw as *mut _)) }.unwrap();
        let r = f();
        unsafe { RevertToSelf() }.unwrap();
        r
    })
    .join()
    .unwrap()
}

/// A UAC-filtered administrator: Administrators deny-only. The pipe admits
/// it through the interactive-user ACE; the service takes it for an
/// unelevated administrator.
#[test]
fn a_filtered_administrator_is_admin_but_not_elevated() {
    let _watchdog = watchdog::watchdog(60, "a_filtered_administrator_is_admin_but_not_elevated");
    let name = unique("uac");
    let _w = start(&name);
    let mut me = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut me) }.unwrap();
    let interactive = has_group(me, WinInteractiveSid);
    let mut ba = sid(WinBuiltinAdministratorsSid);
    let disable = [SID_AND_ATTRIBUTES {
        Sid: PSID(ba.as_mut_ptr().cast()),
        Attributes: 0,
    }];
    let mut filtered = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            me,
            DISABLE_MAX_PRIVILEGE,
            Some(&disable),
            None,
            None,
            &mut filtered,
        )
    }
    .unwrap();
    let n = name.clone();
    let got = as_token(filtered, move || {
        open(&n).map(|f| call(&f, "service.info", json!({})))
    });
    eprintln!("interactive token: {interactive}; filtered caller: {got:?}");
    match got {
        Ok(r) => {
            assert!(interactive, "admitted without the interactive-user group");
            let c = &r["result"]["data"]["caller"];
            assert_eq!(c["admin"], true);
            assert_eq!(c["elevated"], false);
        }
        Err(e) => {
            assert!(!interactive, "an interactive token must get in: {e}");
            assert_eq!(e.raw_os_error(), Some(5), "access denied");
        }
    }
    unsafe {
        let _ = CloseHandle(filtered);
        let _ = CloseHandle(me);
    }
}

struct TempUser(String);
impl Drop for TempUser {
    fn drop(&mut self) {
        let _ = std::process::Command::new("net")
            .args(["user", &self.0, "/delete"])
            .output();
    }
}

/// A standard user: read-only through the interactive ACE; a network
/// logon (no interactive group) is not admitted at all.
#[test]
fn a_standard_user_is_read_only_and_a_network_logon_is_refused() {
    let _watchdog = watchdog::watchdog(60, "a_standard_user_is_read_only_and_a_network_logon_is_refused");
    if std::env::var_os("PAGURO_PIPE_ACCOUNT_TESTS").is_none() {
        eprintln!("skipped: set PAGURO_PIPE_ACCOUNT_TESTS=1 (creates a local user)");
        return;
    }
    let name = unique("user");
    let _w = start(&name);
    let user = format!("pgpipe{}", std::process::id() % 100000);
    let pass = format!("Pg!{}x{}", std::process::id(), 7919 * 13);
    let o = std::process::Command::new("net")
        .args(["user", &user, &pass, "/add"])
        .output()
        .unwrap();
    assert!(
        o.status.success(),
        "net user /add: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    let _cleanup = TempUser(user.clone());
    let logon = |kind| {
        let mut t = HANDLE::default();
        unsafe {
            LogonUserW(
                &HSTRING::from(user.as_str()),
                &HSTRING::from("."),
                &HSTRING::from(pass.as_str()),
                kind,
                LOGON32_PROVIDER_DEFAULT,
                &mut t,
            )
        }
        .unwrap();
        t
    };
    let t = logon(LOGON32_LOGON_INTERACTIVE);
    let n = name.clone();
    let (info, set) = as_token(t, move || {
        let f = open(&n).expect("a standard interactive user connects");
        (
            call(&f, "service.info", json!({})),
            call(&f, "config.set", json!({ "tpm": false })),
        )
    });
    let c = &info["result"]["data"]["caller"];
    eprintln!("standard user: {c}");
    assert_eq!(c["admin"], false);
    assert_eq!(c["elevated"], false);
    assert!(c["user"].as_str().unwrap().ends_with(&user));
    assert_eq!(set["error"]["data"]["code"], "needs_elevation");
    let t2 = logon(LOGON32_LOGON_NETWORK);
    let n = name.clone();
    let e = as_token(t2, move || {
        open(&n)
            .map(|_| ())
            .expect_err("no interactive group: refused")
    });
    assert_eq!(e.raw_os_error(), Some(5));
    unsafe {
        let _ = CloseHandle(t);
        let _ = CloseHandle(t2);
    }
    let _ = TOKEN_QUERY;
}
