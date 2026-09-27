//! `\PaguroPort` (INTERFACES.md §11.1, §11.3): a thin translation to
//! `FilterConnectCommunicationPort`/`FilterSendMessage`. All policy (what to
//! ask, when, and what to do about it) lives in `crate::arming`; this only
//! moves the bytes `crate::fltmsg` already defines and cross-checks against
//! the driver's own header.
#![allow(unsafe_code)]

use windows::Win32::Storage::InstallableFileSystems::{
    FilterConnectCommunicationPort, FilterSendMessage,
};
use windows::core::HSTRING;

use crate::api::{ApiError, ApiResult, ErrorKind, FilterPort, FilterStatus};
use crate::fltmsg;

use super::{Owned, win_err};

struct RealFilterPort(Owned);

impl FilterPort for RealFilterPort {
    fn query_status(&mut self) -> ApiResult<FilterStatus> {
        let msg = fltmsg::Message::query_status().encode();
        let mut out = [0u8; fltmsg::STATUS_REPLY_SIZE];
        let mut got = 0u32;
        // SAFETY: `msg` and `out` are live, correctly sized buffers for the
        // call's duration; the filter only ever reads `msg` and writes
        // within `out`'s bounds (it is handed `out`'s exact length).
        unsafe {
            FilterSendMessage(
                self.0.0,
                msg.as_ptr().cast(),
                msg.len() as u32,
                Some(out.as_mut_ptr().cast()),
                out.len() as u32,
                &mut got,
            )
        }
        .map_err(|e| win_err("FilterSendMessage(QUERY_STATUS)", e))?;
        let reply = out
            .get(..got as usize)
            .and_then(fltmsg::StatusReply::decode)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorKind::InvalidData,
                    "FilterSendMessage(QUERY_STATUS)",
                    "malformed reply",
                )
            })?;
        Ok(FilterStatus {
            protected: reply.protected,
            armed: reply.armed,
        })
    }

    fn send_armed(&mut self) -> ApiResult<()> {
        let msg = fltmsg::Message::armed().encode();
        let mut got = 0u32;
        // SAFETY: `msg` is a live, correctly sized buffer for the call's
        // duration; no output buffer is passed.
        unsafe {
            FilterSendMessage(
                self.0.0,
                msg.as_ptr().cast(),
                msg.len() as u32,
                None,
                0,
                &mut got,
            )
        }
        .map_err(|e| win_err("FilterSendMessage(ARMED)", e))
    }
}

/// `Ok(None)`: no such port (native Windows, or the filter has not started
/// filtering yet -- retried by the caller, never treated as a hard error).
pub fn open() -> ApiResult<Option<Box<dyn FilterPort>>> {
    // SAFETY: a well-formed port name; no context, default ACL (the
    // filter's own security descriptor on the port applies).
    match unsafe { FilterConnectCommunicationPort(&HSTRING::from(fltmsg::PORT), 0, None, 0, None) }
    {
        Ok(h) => Ok(Some(Box::new(RealFilterPort(Owned(h))))),
        Err(e) => {
            let err = win_err("FilterConnectCommunicationPort", e);
            if err.kind == ErrorKind::NotFound {
                Ok(None)
            } else {
                Err(err)
            }
        }
    }
}
