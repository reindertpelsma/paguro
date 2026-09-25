//! The front-end side of the pipe: a [`Transport`] over any byte stream
//! (the named pipe on Windows, a Unix socket in tests), speaking the
//! service's line protocol (`crate::rpc`).

use std::cell::{Cell, RefCell};
use std::io::{BufReader, Read, Write};

use serde_json::{Value, json};

use crate::cli::Transport;
use crate::rpc::{self, RpcError, codes};

pub struct StreamTransport {
    r: RefCell<BufReader<Box<dyn Read>>>,
    w: RefCell<Box<dyn Write>>,
    next: Cell<u64>,
}

impl StreamTransport {
    pub fn new(r: Box<dyn Read>, w: Box<dyn Write>) -> Self {
        StreamTransport {
            r: RefCell::new(BufReader::new(r)),
            w: RefCell::new(w),
            next: Cell::new(1),
        }
    }
}

fn lost(e: impl std::fmt::Display) -> RpcError {
    RpcError {
        code: codes::COMMAND_BASE - 5,
        message: format!("the paguro service: {e}"),
        data: json!({ "code": "platform", "exit": 5 }),
    }
}

impl Transport for StreamTransport {
    fn call(
        &self,
        method: &str,
        params: &Value,
        note: &mut dyn FnMut(&Value),
    ) -> Result<Value, RpcError> {
        let id = self.next.get();
        self.next.set(id + 1);
        let mut line =
            json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }).to_string();
        line.push('\n');
        {
            let mut w = self.w.borrow_mut();
            w.write_all(line.as_bytes()).map_err(lost)?;
            w.flush().map_err(lost)?;
        }
        let mut r = self.r.borrow_mut();
        loop {
            let l = rpc::read_line(&mut *r, rpc::MAX_MESSAGE)
                .map_err(lost)?
                .ok_or_else(|| lost("closed the connection"))?;
            if l.is_empty() {
                continue;
            }
            let v: Value = serde_json::from_slice(&l).map_err(lost)?;
            match v.get("id") {
                Some(i) if !i.is_null() || v.get("method").is_none() => {
                    if i.as_u64() != Some(id) {
                        continue;
                    }
                    if let Some(e) = v.get("error") {
                        return Err(RpcError::from_json(e));
                    }
                    return v
                        .get("result")
                        .cloned()
                        .ok_or_else(|| lost("a response without a result"));
                }
                _ => note(&v),
            }
        }
    }
    fn remote(&self) -> bool {
        true
    }
}
