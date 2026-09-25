//! `/dev/paguro` (INTERFACES.md §10.2, `kernel/dm-paguro/paguro_uapi.h`):
//! the structs mirrored field for field.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;

use crate::sys::{self, R};

pub const MAX_RESERVED: usize = 8;
pub const MAX_VOLUMES: usize = 8;
pub const MAX_CLAIMS: usize = 16;

pub const FORMAT_RAW: u32 = 0;
pub const FORMAT_VHD: u32 = 1;

pub const CLAIM_READONLY: u32 = 1;
pub const CLAIM_CHECKED: u32 = 2;
pub const CLAIM_REFUSED: u32 = 4;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Range {
    pub start: u64,
    pub len: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct VolumeAdd {
    pub raw_major: u32,
    pub raw_minor: u32,
    pub plain_major: u32,
    pub plain_minor: u32,
    pub guid: [u8; 16],
    pub nreserved: u32,
    pub pad0: u32,
    pub reserved: [Range; MAX_RESERVED],
    pub volume_id: u32,
    pub volume_flags: u32,
    pub sectors: u64,
    pub error: i32,
    pub pad1: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Claim {
    pub volume_id: u32,
    pub format: u32,
    pub mft_record: u64,
    pub mft_seq: u16,
    pub pad0: [u16; 3],
    pub claim_id: u32,
    pub extents: u32,
    pub sectors: u64,
    pub state: u32,
    pub error: i32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Crosscheck {
    pub claim_id: u32,
    pub count: u32,
    pub ranges: u64,
    pub state: u32,
    pub pad0: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct StatusVolume {
    pub id: u32,
    pub flags: u32,
    pub view: u32,
    pub view_tables: u32,
    pub sectors: u64,
    pub guard_hits: u64,
    pub readahead_hits: u64,
    pub guid: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct StatusClaim {
    pub id: u32,
    pub volume_id: u32,
    pub state: u32,
    pub extents: u32,
    pub mft_record: u64,
    pub sectors: u64,
    pub refused: u64,
    pub mft_seq: u16,
    pub image_tables: u16,
    pub format: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct Status {
    pub volume: [StatusVolume; MAX_VOLUMES],
    pub claim: [StatusClaim; MAX_CLAIMS],
}

const _: () = assert!(size_of::<VolumeAdd>() == 192);
const _: () = assert!(size_of::<Claim>() == 48);
const _: () = assert!(size_of::<Crosscheck>() == 24);
const _: () = assert!(size_of::<Status>() == 8 * 56 + 16 * 48);

const VOLUME_ADD: libc::c_ulong = sys::iowr(b'p', 1, size_of::<VolumeAdd>());
const CLAIM: libc::c_ulong = sys::iowr(b'p', 2, size_of::<Claim>());
const CROSSCHECK: libc::c_ulong = sys::iowr(b'p', 4, size_of::<Crosscheck>());
const STATUS: libc::c_ulong = sys::iowr(b'p', 6, size_of::<Status>());

pub struct Ctl {
    f: File,
}

impl Ctl {
    pub fn open() -> R<Ctl> {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/paguro")
            .map_err(|e| format!("/dev/paguro: {e} (dm-paguro not loaded?)"))?;
        Ok(Ctl { f })
    }

    fn call<T>(
        &self,
        what: &str,
        req: libc::c_ulong,
        arg: &mut T,
        error: impl Fn(&T) -> i32,
    ) -> R<()> {
        // SAFETY: `arg` is the struct `req` names.
        unsafe { sys::ioctl(self.f.as_raw_fd(), req, arg) }
            .map_err(|e| format!("{what}: {e} (error {})", error(arg)))
    }

    pub fn volume_add(&self, v: &mut VolumeAdd) -> R<()> {
        self.call("PG_VOLUME_ADD", VOLUME_ADD, v, |v| v.error)
    }

    pub fn claim(&self, c: &mut Claim) -> R<()> {
        self.call("PG_CLAIM", CLAIM, c, |c| c.error)
    }

    pub fn crosscheck(&self, claim_id: u32, ranges: &[(u64, u64)]) -> R<u32> {
        let list: Vec<Range> = ranges
            .iter()
            .map(|&(start, len)| Range { start, len })
            .collect();
        let mut x = Crosscheck {
            claim_id,
            count: list.len() as u32,
            ranges: list.as_ptr() as u64,
            ..Default::default()
        };
        self.call("PG_CROSSCHECK", CROSSCHECK, &mut x, |_| 0)?;
        Ok(x.state)
    }

    pub fn status(&self) -> R<Box<Status>> {
        let mut s = Box::<Status>::default();
        self.call("PG_STATUS", STATUS, &mut *s, |_| 0)?;
        Ok(s)
    }
}

pub fn state_text(s: u32) -> String {
    let mut v = Vec::new();
    if s & CLAIM_READONLY != 0 {
        v.push("readonly");
    }
    if s & CLAIM_CHECKED != 0 {
        v.push("checked");
    }
    if s & CLAIM_REFUSED != 0 {
        v.push("refused");
    }
    if v.is_empty() {
        v.push("unchecked");
    }
    v.join(",")
}
