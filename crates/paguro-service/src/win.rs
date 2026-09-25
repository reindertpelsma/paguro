//! The Windows half: the named pipe with its ACL, who the client is, and
//! the service control manager.
//!
//! **ACL** (INTERFACES.md §11.7: "local administrators + the interactive
//! user (read-only methods)"): SYSTEM and Administrators full control; the
//! interactive user read, write and attributes, but **not**
//! `FILE_CREATE_PIPE_INSTANCE`, so it cannot add instances of its own to
//! the name. Nobody else connects; remote clients are rejected. The first
//! instance is created with `FILE_FLAG_FIRST_PIPE_INSTANCE`: if someone
//! squatted the name first, the service fails to start instead of sharing
//! it. The owner is Administrators, which is what clients check before
//! sending a passphrase (`paguro_win::real::pipe`, the C# client).
//!
//! **Who is calling** is read from the client's token, by impersonating it
//! for the length of the lookup: Administrators present at all (a
//! UAC-filtered token has it deny-only) makes an administrator; enabled
//! makes an elevated one; SYSTEM is both.
#![allow(unsafe_code)]

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use paguro_win::rpc::Caller;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree,
};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, GetTokenInformation, IsWellKnownSid, LookupAccountSidW,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, RevertToSelf, SECURITY_ATTRIBUTES,
    SID_NAME_USE, TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    ImpersonateNamedPipeClient, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{GetCurrentThread, OpenThreadToken};
use windows::core::{HSTRING, PWSTR};

use crate::Worker;

/// The pipe's security descriptor (see the module documentation).
/// `0x12018b` = `FILE_GENERIC_READ | FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES`:
/// everything a client needs, but not `FILE_APPEND_DATA`, which on a pipe is
/// `FILE_CREATE_PIPE_INSTANCE`. `GENERIC_WRITE` includes it, so clients open
/// the pipe with exactly [`CLIENT_ACCESS`] instead.
pub const SDDL: &str = "O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12018b;;;IU)";
/// What a client asks for when it opens the pipe (see [`SDDL`]).
pub const CLIENT_ACCESS: u32 = paguro_win::rpc::PIPE_CLIENT_ACCESS;
/// Connections served at once; more are refused (denial of service).
pub const MAX_CONNECTIONS: usize = 16;
const BUFFER: u32 = 64 * 1024;
/// `SE_GROUP_ENABLED`.
const GROUP_ENABLED: u32 = 0x4;

struct Sd(PSECURITY_DESCRIPTOR);

impl Drop for Sd {
    fn drop(&mut self) {
        // SAFETY: allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
        unsafe {
            LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

fn descriptor() -> io::Result<Sd> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out-pointer to a local; freed by Sd.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            &HSTRING::from(SDDL),
            SDDL_REVISION_1,
            &mut sd,
            None,
        )
    }
    .map_err(io::Error::other)?;
    Ok(Sd(sd))
}

/// `\\.\pipe\<name>`.
pub fn pipe_path(name: &str) -> String {
    format!(r"\\.\pipe\{name}")
}

fn create(path: &str, sd: &Sd, first: bool) -> io::Result<HANDLE> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0.0,
        bInheritHandle: false.into(),
    };
    let mut open = PIPE_ACCESS_DUPLEX;
    if first {
        open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    // SAFETY: valid name and attributes for the call's duration.
    let h = unsafe {
        CreateNamedPipeW(
            &HSTRING::from(path),
            open,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER,
            BUFFER,
            0,
            Some(&sa),
        )
    };
    if h == INVALID_HANDLE_VALUE || h.is_invalid() {
        return Err(io::Error::last_os_error());
    }
    Ok(h)
}

fn token_info(
    tok: HANDLE,
    class: windows::Win32::Security::TOKEN_INFORMATION_CLASS,
) -> Option<Vec<u64>> {
    let mut len = 0u32;
    // SAFETY: size query.
    let _ = unsafe { GetTokenInformation(tok, class, None, 0, &mut len) };
    if len == 0 {
        return None;
    }
    // u64 for alignment of the structures inside.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    // SAFETY: buffer of `len` bytes.
    unsafe { GetTokenInformation(tok, class, Some(buf.as_mut_ptr().cast()), len, &mut len) }
        .ok()?;
    Some(buf)
}

fn account(sid: PSID) -> String {
    let mut name = [0u16; 256];
    let mut dom = [0u16; 256];
    let (mut nl, mut dl) = (name.len() as u32, dom.len() as u32);
    let mut use_ = SID_NAME_USE::default();
    // SAFETY: buffers and their lengths.
    let ok = unsafe {
        LookupAccountSidW(
            None,
            sid,
            Some(PWSTR(name.as_mut_ptr())),
            &mut nl,
            Some(PWSTR(dom.as_mut_ptr())),
            &mut dl,
            &mut use_,
        )
    };
    if ok.is_err() {
        return "?".into();
    }
    let n = String::from_utf16_lossy(name.get(..nl as usize).unwrap_or(&[]));
    let d = String::from_utf16_lossy(dom.get(..dl as usize).unwrap_or(&[]));
    if d.is_empty() { n } else { format!("{d}\\{n}") }
}

/// Who is on the other end of `pipe` (see the module documentation). A
/// client that cannot be identified is read-only.
pub fn identify(pipe: HANDLE) -> Caller {
    let mut c = Caller {
        user: "?".into(),
        admin: false,
        elevated: false,
        pid: None,
    };
    let mut pid = 0u32;
    // SAFETY: out-pointer to a local.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) }.is_ok() {
        c.pid = Some(pid);
    }
    // SAFETY: impersonation is reverted below on every path.
    if unsafe { ImpersonateNamedPipeClient(pipe) }.is_err() {
        return c;
    }
    let mut tok = HANDLE::default();
    // SAFETY: the current thread's impersonation token, opened as ourselves.
    let opened = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut tok) };
    // SAFETY: stop impersonating before anything else runs on this thread.
    let reverted = unsafe { RevertToSelf() };
    if reverted.is_err() {
        // Never keep running as the client.
        std::process::abort();
    }
    if opened.is_err() {
        return c;
    }
    if let Some(buf) = token_info(tok, TokenUser) {
        // SAFETY: GetTokenInformation(TokenUser) filled a TOKEN_USER.
        let tu = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
        c.user = account(tu.User.Sid);
        // SAFETY: a SID inside `buf`.
        if unsafe { IsWellKnownSid(tu.User.Sid, WinLocalSystemSid) }.as_bool() {
            c.admin = true;
            c.elevated = true;
        }
    }
    if let Some(buf) = token_info(tok, TokenGroups) {
        // SAFETY: GetTokenInformation(TokenGroups) filled a TOKEN_GROUPS
        // with GroupCount entries.
        let groups = unsafe {
            let tg = &*(buf.as_ptr().cast::<TOKEN_GROUPS>());
            std::slice::from_raw_parts(tg.Groups.as_ptr(), tg.GroupCount as usize)
        };
        for g in groups {
            // SAFETY: SIDs inside `buf`.
            if unsafe { IsWellKnownSid(g.Sid, WinBuiltinAdministratorsSid) }.as_bool() {
                c.admin = true;
                if g.Attributes & GROUP_ENABLED != 0 {
                    c.elevated = true;
                }
            }
        }
    }
    // SAFETY: opened above.
    let _ = unsafe { CloseHandle(tok) };
    c
}

/// The pipe's owner and DACL as SDDL (tests, diagnostics).
pub fn sddl_of(h: HANDLE) -> io::Result<String> {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out-pointers; the descriptor is freed below.
    let e = unsafe {
        GetSecurityInfo(
            h,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if e.is_err() {
        return Err(io::Error::from_raw_os_error(e.0 as i32));
    }
    let sd = Sd(sd);
    let mut s = PWSTR::null();
    // SAFETY: a descriptor from GetSecurityInfo; the string is freed below.
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.0,
            SDDL_REVISION_1,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut s,
            None,
        )
    }
    .map_err(io::Error::other)?;
    // SAFETY: a NUL-terminated string from the call above.
    let out = unsafe { s.to_string() }.unwrap_or_default();
    // SAFETY: allocated by the call above.
    unsafe {
        LocalFree(Some(HLOCAL(s.0.cast())));
    }
    Ok(out)
}

/// Serve `\\.\pipe\<name>` until `stop` is set (then [`wake`] it).
pub fn serve_pipe(
    name: &str,
    worker: Arc<Worker>,
    stop: Arc<AtomicBool>,
    log: Arc<dyn Fn(&str) + Send + Sync>,
) -> io::Result<()> {
    let path = pipe_path(name);
    let sd = descriptor()?;
    let active = Arc::new(AtomicUsize::new(0));
    let mut first = true;
    loop {
        let h = create(&path, &sd, first)?;
        first = false;
        // SAFETY: a pipe handle we own.
        if let Err(e) = unsafe { ConnectNamedPipe(h, None) } {
            if e.code() != ERROR_PIPE_CONNECTED.to_hresult() {
                // SAFETY: ours.
                let _ = unsafe { CloseHandle(h) };
                log(&format!("ConnectNamedPipe: {e}"));
                continue;
            }
        }
        if stop.load(Ordering::SeqCst) {
            // SAFETY: ours.
            let _ = unsafe { CloseHandle(h) };
            return Ok(());
        }
        // SAFETY: we own the handle; the File closes it.
        let file = unsafe { File::from_raw_handle(h.0) };
        let (w, a, l) = (worker.clone(), active.clone(), log.clone());
        std::thread::spawn(move || {
            if a.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                let _ = io::Write::write_all(
                    &mut &file,
                    b"{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"too many connections\"}}\n",
                );
            } else {
                let raw = file.as_raw_handle() as usize;
                let l2 = l.clone();
                let who = move || {
                    let c = identify(HANDLE(raw as *mut core::ffi::c_void));
                    l2(&format!(
                        "connection: {} (pid {:?}, {})",
                        c.user,
                        c.pid,
                        if c.elevated {
                            "elevated"
                        } else if c.admin {
                            "administrator"
                        } else {
                            "read-only"
                        }
                    ));
                    c
                };
                if let Err(e) = crate::serve_as(&file, &file, who, &w) {
                    l(&format!("connection: {e}"));
                }
            }
            a.fetch_sub(1, Ordering::SeqCst);
            // SAFETY: still open (the File is dropped after).
            let _ = unsafe { DisconnectNamedPipe(HANDLE(file.as_raw_handle())) };
        });
    }
}

/// Unblock [`serve_pipe`]'s accept after setting its stop flag.
pub fn wake(name: &str) {
    use std::os::windows::fs::OpenOptionsExt;
    let _ = std::fs::OpenOptions::new()
        .access_mode(CLIENT_ACCESS)
        .open(pipe_path(name));
}

// ---------------------------------------------------------------------------
// The service control manager

pub const SERVICE_NAME: &str = paguro_win::cmd::service::NAME;

/// `%ProgramData%\paguro\service.log`: one line per event; never a
/// parameter (they may hold secrets).
pub fn file_log() -> Arc<dyn Fn(&str) + Send + Sync> {
    let dir = std::env::var_os("ProgramData")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\ProgramData"))
        .join("paguro");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("service.log");
    let lock = std::sync::Mutex::new(());
    Arc::new(move |line: &str| {
        let _g = lock.lock();
        let secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = io::Write::write_all(&mut f, format!("{secs} {line}\n").as_bytes());
        }
    })
}

windows_service::define_windows_service!(ffi_service_main, service_main);

/// `paguro-service run`: hand the process to the service control manager.
pub fn run_service() -> windows_service::Result<()> {
    windows_service::service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

fn service_main(_args: Vec<OsString>) {
    let log = file_log();
    if let Err(e) = run(log.clone()) {
        log(&format!("service failed: {e}"));
    }
}

fn run(log: Arc<dyn Fn(&str) + Send + Sync>) -> windows_service::Result<()> {
    use windows_service::service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};

    let stop = Arc::new(AtomicBool::new(false));
    let s2 = stop.clone();
    let handle = service_control_handler::register(SERVICE_NAME, move |c| match c {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            s2.store(true, Ordering::SeqCst);
            wake(paguro_win::rpc::PIPE_NAME);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    })?;
    let status = |state, accept| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(10),
        process_id: None,
    };
    handle.set_service_status(status(
        ServiceState::StartPending,
        ServiceControlAccept::empty(),
    ))?;
    let l2 = log.clone();
    let worker = Arc::new(Worker::spawn(
        Box::new(|| Box::new(paguro_win::real::RealApi::new()) as Box<dyn paguro_win::api::WinApi>),
        true,
        Box::new(move |api| crate::startup(api, &|m| l2(m))),
    ));
    handle.set_service_status(status(
        ServiceState::Running,
        ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
    ))?;
    log(&format!("started, API {}", paguro_win::rpc::API_VERSION));
    if let Err(e) = serve_pipe(paguro_win::rpc::PIPE_NAME, worker, stop, log.clone()) {
        log(&format!("pipe: {e}"));
    }
    log("stopped");
    handle.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty()))?;
    Ok(())
}
