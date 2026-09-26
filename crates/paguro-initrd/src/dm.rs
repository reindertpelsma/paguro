//! Device-mapper through its ioctl interface (linux/dm-ioctl.h), without
//! libdevmapper: the initrd is one static binary, and a table naming a key
//! never leaves this process.

use std::fs::{File, OpenOptions};
use std::mem::{offset_of, size_of};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::plan::Target;
use crate::sys::{self, R};

/// DM_NAME_LEN, DM_UUID_LEN, DM_MAX_TYPE_NAME (dm-ioctl.h).
const NAME_LEN: usize = 128;
const UUID_LEN: usize = 129;
const MAX_TYPE_NAME: usize = 16;

/// `struct dm_ioctl` (linux/dm-ioctl.h): layout only, used through
/// `offset_of!`; the buffer is built with `put`, never cast.
#[allow(dead_code)]
#[repr(C)]
struct DmIoctl {
    version: [u32; 3],
    data_size: u32,
    data_start: u32,
    target_count: u32,
    open_count: i32,
    flags: u32,
    event_nr: u32,
    padding: u32,
    dev: u64,
    name: [u8; NAME_LEN],
    uuid: [u8; UUID_LEN],
    data: [u8; 7],
}

/// `struct dm_target_spec` (linux/dm-ioctl.h), followed by its
/// NUL-terminated parameter string.
#[allow(dead_code)]
#[repr(C)]
struct DmTargetSpec {
    sector_start: u64,
    length: u64,
    status: i32,
    next: u32,
    target_type: [u8; MAX_TYPE_NAME],
}

const HDR: usize = size_of::<DmIoctl>();
const SPEC: usize = size_of::<DmTargetSpec>();
const _: () = assert!(HDR == 312 && SPEC == 40);
const _: () = assert!(offset_of!(DmIoctl, dev) == 40 && offset_of!(DmIoctl, name) == 48);
const _: () = assert!(offset_of!(DmTargetSpec, target_type) == 24);

/// DM_VERSION_MAJOR: the interface version this header speaks.
const VERSION_MAJOR: u32 = 4;
/// DM_IOCTL, the ioctl type byte.
const DM_IOCTL: u8 = 0xfd;
/// Each target spec (with its parameters) starts 8-byte aligned.
const SPEC_ALIGN: usize = 8;

// DM_*_CMD ioctl numbers (dm-ioctl.h, enum).
const CMD_CREATE: u8 = 3;
const CMD_REMOVE: u8 = 4;
const CMD_SUSPEND: u8 = 6;
const CMD_STATUS: u8 = 7;
const CMD_LOAD: u8 = 9;
const CMD_TARGET_MSG: u8 = 14;

/// DM_READONLY_FLAG.
pub const READONLY: u32 = 1;
/// DM_SECURE_DATA_FLAG: ask the kernel to wipe the ioctl buffer (tables
/// naming key material).
const SECURE_DATA: u32 = 1 << 15;

// `dev` is new_encode_dev(): minor bits 0..8, major bits 8..20, minor
// bits 8..20 at 20..32 (include/linux/kdev_t.h).
const DEV_MAJOR_MASK: u64 = 0xfff00;
const DEV_MAJOR_SHIFT: u32 = 8;
const DEV_MINOR_LOW_MASK: u64 = 0xff;
const DEV_MINOR_HIGH_SHIFT: u32 = 12;
const DEV_MINOR_HIGH_MASK: u64 = 0xfff00;

/// How long to wait for devtmpfs to create /dev/dm-N: polls × interval.
const DEVNODE_POLLS: u32 = 200;
const DEVNODE_POLL_MS: u64 = 10;
/// Mode of the device nodes made when devtmpfs does not.
const NODE_MODE: libc::mode_t = 0o600;

pub struct Dm {
    ctl: File,
}

/// A mapped device: its number and the node devtmpfs created for it.
#[derive(Clone, Debug)]
pub struct Mapped {
    pub name: String,
    pub major: u32,
    pub minor: u32,
    pub node: PathBuf,
}

impl Mapped {
    pub fn devt(&self) -> String {
        format!("{}:{}", self.major, self.minor)
    }
}

/// `DM_DEV_STATUS`'s header fields ([`Dm::info`]).
#[derive(Clone, Copy, Debug)]
pub struct DevInfo {
    pub major: u32,
    pub minor: u32,
    pub open_count: i32,
    pub target_count: u32,
}

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    if let Some(d) = buf.get_mut(at..at + bytes.len()) {
        d.copy_from_slice(bytes);
    }
}

fn header(name: &str, flags: u32, size: usize) -> R<Vec<u8>> {
    if name.is_empty() || name.len() >= NAME_LEN || name.contains('/') {
        return Err(format!("bad device-mapper name {name:?}"));
    }
    let mut b = vec![0u8; size];
    put(
        &mut b,
        offset_of!(DmIoctl, version),
        &VERSION_MAJOR.to_le_bytes(),
    );
    put(
        &mut b,
        offset_of!(DmIoctl, data_size),
        &(size as u32).to_le_bytes(),
    );
    put(
        &mut b,
        offset_of!(DmIoctl, data_start),
        &(HDR as u32).to_le_bytes(),
    );
    put(&mut b, offset_of!(DmIoctl, flags), &flags.to_le_bytes());
    put(&mut b, offset_of!(DmIoctl, name), name.as_bytes());
    Ok(b)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + size_of::<u64>())
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
}

fn i32_at(b: &[u8], at: usize) -> i32 {
    b.get(at..at + size_of::<i32>())
        .and_then(|s| s.try_into().ok())
        .map_or(0, i32::from_le_bytes)
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    b.get(at..at + size_of::<u32>())
        .and_then(|s| s.try_into().ok())
        .map_or(0, u32::from_le_bytes)
}

/// `new_encode_dev()` (include/linux/kdev_t.h): minor bits 0..8 and 20..32,
/// major bits 8..20.
fn devt_major_minor(dev: u64) -> (u32, u32) {
    let major = ((dev & DEV_MAJOR_MASK) >> DEV_MAJOR_SHIFT) as u32;
    let minor =
        ((dev & DEV_MINOR_LOW_MASK) | ((dev >> DEV_MINOR_HIGH_SHIFT) & DEV_MINOR_HIGH_MASK)) as u32;
    (major, minor)
}

impl Dm {
    pub fn open() -> R<Dm> {
        let p = Path::new("/dev/mapper/control");
        if !p.exists() {
            // devtmpfs names it /dev/mapper/control; make it if missing.
            let _ = std::fs::create_dir_all("/dev/mapper");
            let d = std::fs::read_to_string("/sys/class/misc/device-mapper/dev")
                .map_err(|e| format!("device-mapper not loaded: {e}"))?;
            let (ma, mi) = d.trim().split_once(':').ok_or("bad dev")?;
            let (ma, mi): (u32, u32) = (
                ma.parse().map_err(|_| "bad dev")?,
                mi.parse().map_err(|_| "bad dev")?,
            );
            let c = sys::cstr("/dev/mapper/control")?;
            // SAFETY: mknod with a valid path.
            unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | NODE_MODE, libc::makedev(ma, mi)) };
        }
        let ctl = OpenOptions::new()
            .read(true)
            .write(true)
            .open(p)
            .map_err(|e| format!("/dev/mapper/control: {e}"))?;
        Ok(Dm { ctl })
    }

    fn call(&self, cmd: u8, buf: &mut [u8]) -> std::io::Result<()> {
        // SAFETY: `buf` is a dm_ioctl header of data_size bytes.
        unsafe {
            sys::ioctl(
                self.ctl.as_raw_fd(),
                sys::iowr(DM_IOCTL, cmd, HDR),
                buf.as_mut_ptr(),
            )
        }
    }

    /// Create `name`, load `targets` and resume it.
    pub fn setup(&self, name: &str, targets: &[Target], flags: u32) -> R<Mapped> {
        let mut b = header(name, 0, HDR)?;
        self.call(CMD_CREATE, &mut b)
            .map_err(|e| format!("dm create {name}: {e}"))?;
        let dev = u64_at(&b, offset_of!(DmIoctl, dev));
        let r = self.load_resume(name, targets, flags);
        if let Err(e) = r {
            let _ = self.remove(name);
            return Err(e);
        }
        let (major, minor) = devt_major_minor(dev);
        let node = PathBuf::from(format!("/dev/dm-{minor}"));
        for _ in 0..DEVNODE_POLLS {
            if node.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(DEVNODE_POLL_MS));
        }
        if !node.exists() {
            // No devtmpfs: make the node ourselves.
            let c = sys::cstr(node.to_str().unwrap_or_default())?;
            // SAFETY: mknod with a valid path.
            unsafe {
                libc::mknod(
                    c.as_ptr(),
                    libc::S_IFBLK | NODE_MODE,
                    libc::makedev(major, minor),
                )
            };
        }
        let _ = std::fs::create_dir_all("/dev/mapper");
        let link = Path::new("/dev/mapper").join(name);
        if std::fs::symlink_metadata(&link).is_err() {
            let _ = std::os::unix::fs::symlink(format!("../dm-{minor}"), &link);
        }
        Ok(Mapped {
            name: name.to_string(),
            major,
            minor,
            node,
        })
    }

    fn load_resume(&self, name: &str, targets: &[Target], flags: u32) -> R<()> {
        let mut specs = Vec::new();
        for t in targets {
            let mut params = t.params.clone().into_bytes();
            params.push(0);
            while (SPEC + params.len()) % SPEC_ALIGN != 0 {
                params.push(0);
            }
            let mut s = vec![0u8; SPEC];
            put(
                &mut s,
                offset_of!(DmTargetSpec, sector_start),
                &t.start.to_le_bytes(),
            );
            put(
                &mut s,
                offset_of!(DmTargetSpec, length),
                &t.len.to_le_bytes(),
            );
            put(
                &mut s,
                offset_of!(DmTargetSpec, next),
                &((SPEC + params.len()) as u32).to_le_bytes(),
            );
            if t.kind.len() >= MAX_TYPE_NAME {
                return Err(format!("bad target type {}", t.kind));
            }
            put(
                &mut s,
                offset_of!(DmTargetSpec, target_type),
                t.kind.as_bytes(),
            );
            specs.extend_from_slice(&s);
            specs.extend_from_slice(&params);
            zeroize::Zeroize::zeroize(&mut params);
        }
        let secure = targets.iter().any(|t| t.kind == "crypt");
        let lflags = (flags & READONLY) | if secure { SECURE_DATA } else { 0 };
        let mut b = header(name, lflags, HDR + specs.len())?;
        put(
            &mut b,
            offset_of!(DmIoctl, target_count),
            &(targets.len() as u32).to_le_bytes(),
        );
        put(&mut b, HDR, &specs);
        zeroize::Zeroize::zeroize(&mut specs);
        let r = self.call(CMD_LOAD, &mut b);
        zeroize::Zeroize::zeroize(&mut b);
        r.map_err(|e| format!("dm load {name}: {e}"))?;
        let mut b = header(name, 0, HDR)?;
        self.call(CMD_SUSPEND, &mut b)
            .map_err(|e| format!("dm resume {name}: {e}"))
    }

    /// `dmsetup message <name> <sector> <msg>`: a message to the target
    /// at `sector` of a live table (struct dm_target_msg after the header).
    pub fn message(&self, name: &str, sector: u64, msg: &str) -> R<()> {
        if msg.is_empty() || msg.contains('\0') {
            return Err(format!("bad dm message {msg:?}"));
        }
        let mut body = sector.to_le_bytes().to_vec();
        body.extend_from_slice(msg.as_bytes());
        body.push(0);
        while body.len() % SPEC_ALIGN != 0 {
            body.push(0);
        }
        let mut b = header(name, 0, HDR + body.len())?;
        put(&mut b, HDR, &body);
        self.call(CMD_TARGET_MSG, &mut b)
            .map_err(|e| format!("dm message {name} {msg:?}: {e}"))
    }

    /// Reload an already-created device's table and resume it (`dmsetup
    /// reload && dmsetup resume`): growth (INTERFACES.md §10.3 last bullet)
    /// reloads `paguro-image` at the new, larger length.
    pub fn reload(&self, name: &str, targets: &[Target], flags: u32) -> R<()> {
        self.load_resume(name, targets, flags)
    }

    /// `DM_DEV_STATUS`: whether `name` exists, and if so its open count —
    /// `> 0` means it is mounted or otherwise held open, and must not be
    /// removed (INTERFACES.md §11.3 "Release": Linux checks the device is
    /// unused and unmounted before removing it).
    pub fn info(&self, name: &str) -> R<Option<DevInfo>> {
        let mut b = header(name, 0, HDR)?;
        match self.call(CMD_STATUS, &mut b) {
            Ok(()) => {
                let (major, minor) = devt_major_minor(u64_at(&b, offset_of!(DmIoctl, dev)));
                Ok(Some(DevInfo {
                    major,
                    minor,
                    open_count: i32_at(&b, offset_of!(DmIoctl, open_count)),
                    target_count: u32_at(&b, offset_of!(DmIoctl, target_count)),
                }))
            }
            Err(e) if e.raw_os_error() == Some(libc::ENXIO) => Ok(None),
            Err(e) => Err(format!("dm status {name}: {e}")),
        }
    }

    pub fn remove(&self, name: &str) -> R<()> {
        let mut b = header(name, 0, HDR)?;
        self.call(CMD_REMOVE, &mut b)
            .map_err(|e| format!("dm remove {name}: {e}"))?;
        let _ = std::fs::remove_file(Path::new("/dev/mapper").join(name));
        Ok(())
    }
}
