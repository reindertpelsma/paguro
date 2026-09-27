//! `\\.\Global\<name>` (INTERFACES.md §11.3): the guest agent virtio-serial
//! port, opened the same way `test/vm/agent-report.ps1` does. Present only
//! in the paguro VM; `CreateFile` failing with "not found" is native
//! Windows, not an error -- the same shape as `super::open_query` for a
//! physical disk.
#![allow(unsafe_code)]

use std::fs;
use std::io::{Read, Write};
use std::os::windows::fs::OpenOptionsExt;

use crate::api::{AgentPort, ApiResult};

use super::io_err;

struct RealAgentPort(fs::File);

impl AgentPort for RealAgentPort {
    fn write_all(&mut self, buf: &[u8]) -> ApiResult<()> {
        self.0
            .write_all(buf)
            .map_err(|e| io_err("WriteFile", "agent port", e))?;
        self.0
            .flush()
            .map_err(|e| io_err("FlushFileBuffers", "agent port", e))
    }

    fn read(&mut self, buf: &mut [u8]) -> ApiResult<usize> {
        self.0
            .read(buf)
            .map_err(|e| io_err("ReadFile", "agent port", e))
    }
}

/// `Ok(None)`: the device does not exist (native Windows).
pub fn open(name: &str) -> ApiResult<Option<Box<dyn AgentPort>>> {
    match fs::OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .open(name)
    {
        Ok(f) => Ok(Some(Box::new(RealAgentPort(f)))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(io_err("CreateFileW", name, e)),
    }
}
