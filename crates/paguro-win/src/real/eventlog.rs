//! One line in the Windows Application event log, source `paguro`
//! (`RegisterEventSourceW`/`ReportEventW`): a user-visible notice for
//! things like DESIGN.md §4.4's chkdsk guard, alongside the service's own
//! log and the status channel (`crate::bootexec`). No message-table DLL is
//! registered, so the Event Viewer shows a generic "description cannot be
//! found" header with `message` appended verbatim as the event's one
//! string -- acceptable for a diagnostic that is never machine-parsed.
#![allow(unsafe_code)]

use windows::Win32::System::EventLog::{
    DeregisterEventSource, EVENTLOG_WARNING_TYPE, RegisterEventSourceW, ReportEventW,
};
use windows::core::{HSTRING, PCWSTR};

use crate::api::ApiResult;

use super::win_err;

const SOURCE: &str = "paguro";
/// Generic ("no message table") event id: high bit set marks it as one
/// Windows should not try to look up in a resource DLL.
const EVENT_ID: u32 = 0x8000_0001;

pub fn report(message: &str) -> ApiResult<()> {
    // SAFETY: a well-formed source name; the handle is deregistered below.
    let h = unsafe { RegisterEventSourceW(None, &HSTRING::from(SOURCE)) }
        .map_err(|e| win_err("RegisterEventSourceW", e))?;
    let s = HSTRING::from(message);
    let strings = [PCWSTR(s.as_ptr())];
    // SAFETY: `h` is open for the call's duration; `strings` outlives it.
    let r = unsafe {
        ReportEventW(
            h,
            EVENTLOG_WARNING_TYPE,
            0,
            EVENT_ID,
            None,
            0,
            Some(&strings),
            None,
        )
    };
    // SAFETY: opened above, closed exactly once.
    let _ = unsafe { DeregisterEventSource(h) };
    r.map_err(|e| win_err("ReportEventW", e))
}
