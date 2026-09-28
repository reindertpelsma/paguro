//! The guest agent port (INTERFACES.md §11.3, "Arming"): `u32` little-endian
//! length, then that many bytes of UTF-8 JSON, over
//! `\\.\Global\org.paguro.agent.0` (DESIGN.md §4.4 "Until the driver arms").
//!
//! This framing is not shared code with the host side
//! (`paguro-vm::session::agent_frame`/`agent_frames`) -- different
//! processes on different machines -- but the same format; `test/winvm`
//! exercises the two against each other over a real virtio-serial device.
//!
//! [`handshake`] blocks (writes the report, then reads until the host's ack
//! decodes, or the port breaks): callers run it off a thread that must stay
//! responsive (`crate::arming`, spawned by `crate::vmservice`). There is
//! deliberately no read timeout here -- see [`crate::api::AgentPort::read`]'s
//! documentation -- so a stuck host merely leaves this one thread waiting,
//! exactly as the host's own `supervise()` loop waits for the guest with no
//! timeout of its own (DESIGN.md §4.4: "There is no timeout on the driver
//! either").

use serde_json::{Value, json};

use crate::api::{AgentPort, ApiError, ApiResult, ErrorKind};

pub const PORT_NAME: &str = r"\\.\Global\org.paguro.agent.0";
/// Largest frame accepted (matches `paguro-vm::session::agent_frames`).
const MAX_FRAME: usize = 64 << 10;

/// `{"type":"driver","driver":"PaguroFlt","state":"ok"}` (DESIGN.md §4.4,
/// INTERFACES.md §11.3).
pub fn driver_report() -> Value {
    json!({ "type": "driver", "driver": "PaguroFlt", "state": "ok" })
}

/// A frame: length prefix, then the JSON.
pub fn encode(v: &Value) -> Vec<u8> {
    let b = v.to_string().into_bytes();
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend(b);
    out
}

/// Accumulates bytes from the port and yields the frames that complete.
/// Same shape as the host's `agent_frames`: an over-long claimed length
/// drops everything buffered (not a valid frame stream any more).
#[derive(Default)]
pub struct Framer(Vec<u8>);

impl Framer {
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Value> {
        self.0.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(len) = self
            .0
            .get(..4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_le_bytes)
        {
            let len = len as usize;
            if len > MAX_FRAME {
                self.0.clear();
                break;
            }
            let Some(body) = self.0.get(4..4 + len) else {
                break;
            };
            if let Ok(v) = serde_json::from_slice::<Value>(body) {
                out.push(v);
            }
            self.0.drain(..4 + len);
        }
        out
    }
}

/// The host's ack, decoded: `Some(true/false)` for
/// `{"type":"armed","ok":...}`; `None` for anything else (ignored: not a
/// message this side reacts to).
pub fn armed_ok(v: &Value) -> Option<bool> {
    (v.get("type")?.as_str()? == "armed")
        .then(|| v.get("ok").and_then(Value::as_bool).unwrap_or(false))
}

/// Send the driver report on `port` and read frames from it until an
/// `armed` reply decodes (`Ok(true)`/`Ok(false)`), or the port breaks
/// (`Err`, including a clean close: there is no valid reason for the host
/// to hang up mid-handshake).
pub fn handshake(port: &mut dyn AgentPort) -> ApiResult<bool> {
    port.write_all(&encode(&driver_report()))?;
    let mut framer = Framer::default();
    let mut buf = [0u8; 4096];
    loop {
        let n = port.read(&mut buf)?;
        if n == 0 {
            return Err(ApiError::new(
                ErrorKind::Other,
                "ReadFile",
                "the agent port closed before an ack arrived",
            ));
        }
        for v in framer.feed(buf.get(..n).unwrap_or(&[])) {
            if let Some(ok) = armed_ok(&v) {
                return Ok(ok);
            }
        }
    }
}

/// Write `frame` on `port`, then read frames until `pick` accepts one
/// (INTERFACES.md §11.3's request/reply frames: `link-request` → `link`,
/// `ssh-keys` → `ssh-keys-ack`). Frames `pick` declines are skipped. A
/// clean close before the reply is an error, like [`handshake`]'s.
pub fn exchange<T>(
    port: &mut dyn AgentPort,
    frame: &Value,
    pick: &dyn Fn(&Value) -> Option<T>,
) -> ApiResult<T> {
    port.write_all(&encode(frame))?;
    let mut framer = Framer::default();
    let mut buf = [0u8; 4096];
    loop {
        let n = port.read(&mut buf)?;
        if n == 0 {
            return Err(ApiError::new(
                ErrorKind::Other,
                "ReadFile",
                "the agent port closed before the reply arrived",
            ));
        }
        for v in framer.feed(buf.get(..n).unwrap_or(&[])) {
            if let Some(t) = pick(&v) {
                return Ok(t);
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::api::WinApi;
    use crate::mock::{MockAgentState, MockApi};
    use std::collections::VecDeque;
    use std::rc::Rc;

    #[test]
    fn frame_round_trip() {
        let v = json!({"a": 1});
        let bytes = encode(&v);
        assert_eq!(&bytes[..4], &(bytes.len() as u32 - 4).to_le_bytes());
        let mut f = Framer::default();
        // Fed in two pieces: the framer must hold the partial frame.
        let (a, b) = bytes.split_at(3);
        assert_eq!(f.feed(a), Vec::<Value>::new());
        assert_eq!(f.feed(b), vec![v]);
    }

    #[test]
    fn two_frames_in_one_read() {
        let mut bytes = encode(&json!({"x": 1}));
        bytes.extend(encode(&json!({"y": 2})));
        let mut f = Framer::default();
        assert_eq!(f.feed(&bytes), vec![json!({"x": 1}), json!({"y": 2})]);
    }

    #[test]
    fn oversized_length_clears_the_buffer() {
        let mut f = Framer::default();
        let mut bad = (MAX_FRAME as u32 + 1).to_le_bytes().to_vec();
        bad.extend_from_slice(b"junk");
        assert_eq!(f.feed(&bad), Vec::<Value>::new());
        // The buffer was cleared, not left holding "junk" as a partial frame.
        assert_eq!(f.feed(&encode(&json!("ok"))), vec![json!("ok")]);
    }

    #[test]
    fn armed_ok_parses_only_armed_messages() {
        assert_eq!(armed_ok(&json!({"type": "armed", "ok": true})), Some(true));
        assert_eq!(
            armed_ok(&json!({"type": "armed", "ok": false, "error": "x"})),
            Some(false)
        );
        assert_eq!(armed_ok(&json!({"type": "driver"})), None);
        assert_eq!(armed_ok(&json!({"type": "armed"})), Some(false));
    }

    fn scripted(
        reads: Vec<ApiResult<Vec<u8>>>,
    ) -> (MockApi, Rc<std::cell::RefCell<MockAgentState>>) {
        let m = MockApi::standard();
        let state = Rc::new(std::cell::RefCell::new(MockAgentState {
            writes: Vec::new(),
            reads: VecDeque::from(reads),
        }));
        *m.agent_port.borrow_mut() = Some(state.clone());
        (m, state)
    }

    #[test]
    fn handshake_ok_true() {
        let (m, state) = scripted(vec![Ok(encode(&json!({"type": "armed", "ok": true})))]);
        let mut port = m.open_agent_port(PORT_NAME).unwrap().unwrap();
        assert!(handshake(&mut *port).unwrap());
        assert_eq!(state.borrow().writes.len(), 1);
        assert_eq!(
            serde_json::from_slice::<Value>(&state.borrow().writes[0][4..]).unwrap(),
            driver_report()
        );
    }

    #[test]
    fn handshake_ok_false() {
        let (m, _) = scripted(vec![Ok(encode(
            &json!({"type": "armed", "ok": false, "error": "no"}),
        ))]);
        let mut port = m.open_agent_port(PORT_NAME).unwrap().unwrap();
        assert!(!handshake(&mut *port).unwrap());
    }

    #[test]
    fn handshake_ignores_unrelated_frames_first() {
        let (m, _) = scripted(vec![
            Ok(encode(&json!({"type": "other"}))),
            Ok(encode(&json!({"type": "armed", "ok": true}))),
        ]);
        let mut port = m.open_agent_port(PORT_NAME).unwrap().unwrap();
        assert!(handshake(&mut *port).unwrap());
    }

    #[test]
    fn handshake_errors_on_close() {
        let (m, _) = scripted(vec![]);
        let mut port = m.open_agent_port(PORT_NAME).unwrap().unwrap();
        assert!(handshake(&mut *port).is_err());
    }
}
