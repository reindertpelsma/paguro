//! `/dev/paguro` (INTERFACES.md §10.2, `kernel/dm-paguro/paguro_uapi.h`):
//! the structs mirrored field for field.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;

use crate::sys::{self, R};

pub const MAX_RESERVED: usize = 8;
pub const MAX_VOLUMES: usize = 8;
pub const MAX_CLAIMS: usize = 16;

/// `PG_VOLUME_ADD` flag: every claim and view on the volume read-only.
pub const VOLUME_READ_ONLY: u32 = 1;

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
    /// `VOLUME_READ_ONLY`.
    pub flags: u32,
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
const _: () = assert!(size_of::<StatusVolume>() == 56 && size_of::<StatusClaim>() == 48);
const _: () = assert!(size_of::<Status>() == MAX_VOLUMES * 56 + MAX_CLAIMS * 48);

/// The `/dev/paguro` ioctl type byte, and the numbers paguro_uapi.h
/// gives each request (`PG_VOLUME_ADD` = `_IOWR('p', 1, …)`, …).
const PG_IOCTL: u8 = b'p';
const NR_VOLUME_ADD: u8 = 1;
const NR_CLAIM: u8 = 2;
const NR_CROSSCHECK: u8 = 4;
const NR_STATUS: u8 = 6;

const VOLUME_ADD: libc::c_ulong = sys::iowr(PG_IOCTL, NR_VOLUME_ADD, size_of::<VolumeAdd>());
const CLAIM: libc::c_ulong = sys::iowr(PG_IOCTL, NR_CLAIM, size_of::<Claim>());
const CROSSCHECK: libc::c_ulong = sys::iowr(PG_IOCTL, NR_CROSSCHECK, size_of::<Crosscheck>());
const STATUS: libc::c_ulong = sys::iowr(PG_IOCTL, NR_STATUS, size_of::<Status>());

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
