//! Connecting `paguro.exe` to the service (INTERFACES.md §11.7). The pipe
//! must be owned by SYSTEM or Administrators before anything is sent over
//! it: a name squatted by another user never receives a passphrase.

use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;

use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
use windows::Win32::Security::{
    IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    WinBuiltinAdministratorsSid, WinLocalSystemSid,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;
use windows::core::HSTRING;

use crate::cli::Transport;
use crate::client::StreamTransport;

pub enum Connect {
    Service(Box<dyn Transport>),
    /// No service installed (or not running): run directly.
    NoService,
    /// There is a pipe, but it is not usable or not trustworthy.
    Refused(String),
}

const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_ACCESS_DENIED: i32 = 5;
const ERROR_PIPE_BUSY: i32 = 231;
const BUSY_WAIT_MS: u32 = 5000;

/// Whether `f`'s owner is SYSTEM or Administrators.
pub fn owned_by_service(f: &File) -> Result<bool, String> {
    let mut owner = PSID::default();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: out-pointers; the descriptor is freed below.
    let e = unsafe {
        GetSecurityInfo(
            HANDLE(f.as_raw_handle()),
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut sd),
        )
    };
    if e.is_err() {
        return Err(format!("GetSecurityInfo: {}", e.0));
    }
    // SAFETY: `owner` points into `sd`, alive until LocalFree.
    let ok = unsafe {
        IsWellKnownSid(owner, WinLocalSystemSid).as_bool()
            || IsWellKnownSid(owner, WinBuiltinAdministratorsSid).as_bool()
    };
    // SAFETY: allocated by GetSecurityInfo.
    unsafe {
        LocalFree(Some(HLOCAL(sd.0)));
    }
    Ok(ok)
}

pub fn connect_to(path: &str) -> Connect {
    let mut tried_wait = false;
    let f = loop {
        match OpenOptions::new()
            .access_mode(crate::rpc::PIPE_CLIENT_ACCESS)
            .open(path)
        {
            Ok(f) => break f,
            Err(e) => match e.raw_os_error() {
                Some(ERROR_FILE_NOT_FOUND) => return Connect::NoService,
                Some(ERROR_PIPE_BUSY) if !tried_wait => {
                    tried_wait = true;
                    // SAFETY: a valid name.
                    let _ = unsafe { WaitNamedPipeW(&HSTRING::from(path), BUSY_WAIT_MS) };
                }
                Some(ERROR_ACCESS_DENIED) => {
                    return Connect::Refused("access to the paguro service is denied".into());
                }
                _ => return Connect::Refused(format!("{path}: {e}")),
            },
        }
    };
    match owned_by_service(&f) {
        Ok(true) => {}
        Ok(false) => {
            return Connect::Refused(format!("{path} is not owned by SYSTEM or Administrators"));
        }
        Err(e) => return Connect::Refused(e),
    }
    match f.try_clone() {
        Ok(r) => Connect::Service(Box::new(StreamTransport::new(Box::new(r), Box::new(f)))),
        Err(e) => Connect::Refused(e.to_string()),
    }
}

/// `\\.\pipe\paguro`.
pub fn connect() -> Connect {
    connect_to(crate::rpc::PIPE)
}
