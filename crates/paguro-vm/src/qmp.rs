//! A minimal QMP client: commands, and events collected as they arrive.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serde_json::{Value, json};

pub struct Qmp {
    r: BufReader<UnixStream>,
    w: UnixStream,
    /// Events seen while waiting for replies, oldest first.
    pub events: Vec<Value>,
}

impl Qmp {
    pub fn connect(path: &Path) -> Result<Qmp, String> {
        let s = UnixStream::connect(path).map_err(|e| format!("QMP {}: {e}", path.display()))?;
        s.set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| e.to_string())?;
        let w = s.try_clone().map_err(|e| e.to_string())?;
        let mut q = Qmp {
            r: BufReader::new(s),
            w,
            events: Vec::new(),
        };
        q.read()?; // greeting
        q.cmd("qmp_capabilities", json!({}))?;
        Ok(q)
    }

    fn read(&mut self) -> Result<Value, String> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .r
                .read_line(&mut line)
                .map_err(|e| format!("QMP read: {e}"))?;
            if n == 0 {
                return Err("QMP closed".into());
            }
            let v: Value = serde_json::from_str(&line).map_err(|e| format!("QMP: {e}"))?;
            if v.get("event").is_some() {
                self.events.push(v);
                continue;
            }
            return Ok(v);
        }
    }

    pub fn cmd(&mut self, execute: &str, args: Value) -> Result<Value, String> {
        let req = if args.as_object().is_some_and(|o| !o.is_empty()) {
            json!({ "execute": execute, "arguments": args })
        } else {
            json!({ "execute": execute })
        };
        let mut s = req.to_string();
        s.push('\n');
        self.w
            .write_all(s.as_bytes())
            .map_err(|e| format!("QMP write: {e}"))?;
        let v = self.read()?;
        if let Some(e) = v.get("error") {
            return Err(format!("QMP {execute}: {e}"));
        }
        Ok(v.get("return").cloned().unwrap_or(Value::Null))
    }

    /// Read pending events for up to `wait` (no command sent).
    pub fn poll_events(&mut self, wait: Duration) -> Result<(), String> {
        self.r
            .get_ref()
            .set_read_timeout(Some(wait))
            .map_err(|e| e.to_string())?;
        let mut line = String::new();
        let r = loop {
            line.clear();
            match self.r.read_line(&mut line) {
                Ok(0) => break Err("QMP closed".into()),
                Ok(_) => {
                    if let Ok(v) = serde_json::from_str::<Value>(&line) {
                        if v.get("event").is_some() {
                            self.events.push(v);
                        }
                    }
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    break Ok(());
                }
                Err(e) => break Err(format!("QMP read: {e}")),
            }
        };
        self.r
            .get_ref()
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| e.to_string())?;
        r
    }

    /// Read-operation count of a block device (by the QOM id of the device
    /// it sits under — a usb-storage's disk is
    /// `/machine/peripheral/<id>/<id>.0/legacy[0]` — or its node name),
    /// from `query-blockstats`.
    pub fn reads(&mut self, id: &str) -> Result<Option<u64>, String> {
        let v = self.cmd("query-blockstats", json!({ "query-nodes": false }))?;
        Ok(v.as_array().and_then(|a| {
            a.iter().find_map(|d| {
                let matches = d
                    .get("qdev")
                    .and_then(Value::as_str)
                    .is_some_and(|q| q.split('/').any(|c| c == id))
                    || d.get("node-name").and_then(Value::as_str) == Some(id);
                matches
                    .then(|| d.pointer("/stats/rd_operations").and_then(Value::as_u64))
                    .flatten()
            })
        }))
    }
}
