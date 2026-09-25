//! The `\PaguroPort` messages (INTERFACES.md §11.1) as the service speaks
//! them. The driver's definition is `windows/minifilter/pg_msg.h`; a test
//! reads that header and checks every constant and offset here against it,
//! so the two cannot drift.
//!
//! ```text
//! 0  magic u32 "PGFM" | 4 version u16 | 6 type u16 | 8 volume GUID[16]
//! 24 file id [16] | 40 deny u32 | 44 operation u32 | 48 process id u32
//! 52 status i32                                       (56 bytes, LE)
//! ```

use core::mem::{offset_of, size_of};

pub const MAGIC: u32 = 0x4D46_4750;
pub const VERSION: u16 = 1;
pub const SIZE: usize = 56;
pub const PORT: &str = "\\PaguroPort";

pub const PROTECT: u16 = 1;
pub const UNPROTECT: u16 = 2;
pub const ALLOW_UNLOAD: u16 = 3;
pub const EVENT: u16 = 4;

pub const DENY_OPEN: u32 = 0x01;
pub const DENY_SETINFO: u32 = 0x02;
pub const DENY_WRITE: u32 = 0x04;
pub const DENY_FSCTL: u32 = 0x08;
pub const DENY_ALL: u32 = 0x0F;

pub const MAX_PROTECTED: usize = 32;

/// Volume GUID and FILE_ID_128 are both 16 bytes.
const ID_LEN: usize = 16;

/// `PG_MESSAGE` (pg_msg.h) as laid out on the port: layout only, used
/// through `offset_of!` to place fields; never cast from a buffer.
#[allow(dead_code)]
#[repr(C)]
struct PgMessage {
    magic: u32,
    version: u16,
    kind: u16,
    volume: [u8; ID_LEN],
    file_id: [u8; ID_LEN],
    deny_flags: u32,
    operation: u32,
    process_id: u32,
    status: i32,
}

const OFF_MAGIC: usize = offset_of!(PgMessage, magic);
const OFF_VERSION: usize = offset_of!(PgMessage, version);
const OFF_TYPE: usize = offset_of!(PgMessage, kind);
const OFF_VOLUME: usize = offset_of!(PgMessage, volume);
const OFF_FILE_ID: usize = offset_of!(PgMessage, file_id);
const OFF_DENY: usize = offset_of!(PgMessage, deny_flags);
const OFF_OPERATION: usize = offset_of!(PgMessage, operation);
const OFF_PROCESS_ID: usize = offset_of!(PgMessage, process_id);
const OFF_STATUS: usize = offset_of!(PgMessage, status);
const _: () = assert!(size_of::<PgMessage>() == SIZE);
const _: () = assert!(OFF_VOLUME == 8 && OFF_FILE_ID == 24 && OFF_DENY == 40);
const _: () = assert!(OFF_STATUS == 52);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub kind: u16,
    /// GUID in memory layout (what `paguro_core::guid::Guid` holds).
    pub volume: [u8; ID_LEN],
    pub file_id: [u8; ID_LEN],
    pub deny: u32,
    pub operation: u32,
    pub process_id: u32,
    pub status: i32,
}

impl Message {
    pub fn protect(volume: [u8; ID_LEN], file_id: [u8; ID_LEN], deny: u32) -> Self {
        Message {
            kind: PROTECT,
            volume,
            file_id,
            deny,
            ..Message::default()
        }
    }

    pub fn encode(&self) -> [u8; SIZE] {
        let mut b = [0u8; SIZE];
        let mut put = |at: usize, v: &[u8]| {
            if let Some(d) = b.get_mut(at..at + v.len()) {
                d.copy_from_slice(v);
            }
        };
        put(OFF_MAGIC, &MAGIC.to_le_bytes());
        put(OFF_VERSION, &VERSION.to_le_bytes());
        put(OFF_TYPE, &self.kind.to_le_bytes());
        put(OFF_VOLUME, &self.volume);
        put(OFF_FILE_ID, &self.file_id);
        put(OFF_DENY, &self.deny.to_le_bytes());
        put(OFF_OPERATION, &self.operation.to_le_bytes());
        put(OFF_PROCESS_ID, &self.process_id.to_le_bytes());
        put(OFF_STATUS, &self.status.to_le_bytes());
        b
    }

    /// An EVENT from the filter; `None` for anything else or malformed.
    pub fn decode_event(b: &[u8]) -> Option<Message> {
        let b: &[u8; SIZE] = b.try_into().ok()?;
        let u32_at = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(
                b.get(at..at + size_of::<u32>())?.try_into().ok()?,
            ))
        };
        let u16_at = |at: usize| -> Option<u16> {
            Some(u16::from_le_bytes(
                b.get(at..at + size_of::<u16>())?.try_into().ok()?,
            ))
        };
        if u32_at(OFF_MAGIC)? != MAGIC
            || u16_at(OFF_VERSION)? != VERSION
            || u16_at(OFF_TYPE)? != EVENT
        {
            return None;
        }
        Some(Message {
            kind: EVENT,
            volume: b.get(OFF_VOLUME..OFF_VOLUME + ID_LEN)?.try_into().ok()?,
            file_id: b.get(OFF_FILE_ID..OFF_FILE_ID + ID_LEN)?.try_into().ok()?,
            deny: u32_at(OFF_DENY)?,
            operation: u32_at(OFF_OPERATION)?,
            process_id: u32_at(OFF_PROCESS_ID)?,
            status: u32_at(OFF_STATUS)? as i32,
        })
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn layout() {
        let m = Message::protect([1; 16], [2; 16], DENY_ALL);
        let b = m.encode();
        assert_eq!(&b[..4], b"PGFM");
        assert_eq!(b[6], 1);
        assert_eq!(&b[8..24], &[1; 16]);
        assert_eq!(&b[24..40], &[2; 16]);
        assert_eq!(b[40], 0x0F);
        let mut e = Message {
            kind: EVENT,
            operation: 3,
            process_id: 1234,
            status: 0xC000_0022u32 as i32,
            ..m
        }
        .encode();
        let d = Message::decode_event(&e).unwrap();
        assert_eq!(
            (d.operation, d.process_id, d.status),
            (3, 1234, 0xC000_0022u32 as i32)
        );
        e[0] ^= 1;
        assert_eq!(Message::decode_event(&e), None);
        assert_eq!(Message::decode_event(&b), None, "not an EVENT");
        assert_eq!(Message::decode_event(&b[..55]), None);
    }

    /// The C header is the other half of this interface: same constants.
    #[test]
    fn matches_pg_msg_h() {
        let h = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../windows/minifilter/pg_msg.h"
        ))
        .unwrap();
        let def = |name: &str| -> u64 {
            let line = h
                .lines()
                .find(|l| l.split_whitespace().nth(1) == Some(name) && l.starts_with("#define"))
                .unwrap_or_else(|| panic!("{name} not in pg_msg.h"));
            let v = line
                .split_whitespace()
                .nth(2)
                .unwrap()
                .trim_end_matches('u');
            if let Some(x) = v.strip_prefix("0x") {
                u64::from_str_radix(x, 16).unwrap()
            } else {
                v.parse().unwrap()
            }
        };
        assert_eq!(def("PG_MSG_MAGIC"), u64::from(MAGIC));
        assert_eq!(def("PG_MSG_VERSION"), u64::from(VERSION));
        assert_eq!(def("PG_MESSAGE_SIZE"), SIZE as u64);
        assert_eq!(def("PG_MSG_PROTECT"), u64::from(PROTECT));
        assert_eq!(def("PG_MSG_UNPROTECT"), u64::from(UNPROTECT));
        assert_eq!(def("PG_MSG_ALLOW_UNLOAD"), u64::from(ALLOW_UNLOAD));
        assert_eq!(def("PG_MSG_EVENT"), u64::from(EVENT));
        assert_eq!(def("PG_DENY_OPEN"), u64::from(DENY_OPEN));
        assert_eq!(def("PG_DENY_SETINFO"), u64::from(DENY_SETINFO));
        assert_eq!(def("PG_DENY_WRITE"), u64::from(DENY_WRITE));
        assert_eq!(def("PG_DENY_FSCTL"), u64::from(DENY_FSCTL));
        assert_eq!(def("PG_DENY_ALL"), u64::from(DENY_ALL));
        assert_eq!(def("PG_MAX_PROTECTED"), MAX_PROTECTED as u64);
        assert!(h.contains("L\"\\\\PaguroPort\""));
    }
}
