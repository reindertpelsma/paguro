//! Loop devices through their ioctls (`linux/loop.h`), without losetup:
//! the session's scratch file becomes one block device for the sandwich.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use paguro_initrd::sys::{self, R};

const LOOP_CTL_GET_FREE: libc::c_ulong = 0x4C82;
const LOOP_CLR_FD: libc::c_ulong = 0x4C01;
const LOOP_CONFIGURE: libc::c_ulong = 0x4C0A;
/// LO_FLAGS_AUTOCLEAR: the device detaches itself on last close after
/// LOOP_CLR_FD, or when nothing holds it.
const LO_FLAGS_AUTOCLEAR: u32 = 4;
const LO_NAME_SIZE: usize = 64;
const LO_KEY_SIZE: usize = 32;
/// Attempts when another process takes the free device first.
const TRIES: u32 = 16;

/// `struct loop_info64` (linux/loop.h).
#[repr(C)]
struct LoopInfo64 {
    device: u64,
    inode: u64,
    rdevice: u64,
    offset: u64,
    sizelimit: u64,
    number: u32,
    encrypt_type: u32,
    encrypt_key_size: u32,
    flags: u32,
    file_name: [u8; LO_NAME_SIZE],
    crypt_name: [u8; LO_NAME_SIZE],
    encrypt_key: [u8; LO_KEY_SIZE],
    init: [u64; 2],
}

/// `struct loop_config` (linux/loop.h, 5.8+).
#[repr(C)]
struct LoopConfig {
    fd: u32,
    block_size: u32,
    info: LoopInfo64,
    reserved: [u64; 8],
}
const _: () = assert!(size_of::<LoopInfo64>() == 232);
const _: () = assert!(size_of::<LoopConfig>() == 304);

/// An attached loop device; detached on drop.
pub struct Loop {
    pub path: PathBuf,
    dev: File,
}

impl Loop {
    /// Attach `file` (read-write) with the given logical block size.
    pub fn attach(file: &Path, block_size: u32) -> R<Loop> {
        let backing = OpenOptions::new()
            .read(true)
            .write(true)
            .open(file)
            .map_err(|e| format!("{}: {e}", file.display()))?;
        let ctl = File::open("/dev/loop-control").map_err(|e| format!("/dev/loop-control: {e}"))?;
        for _ in 0..TRIES {
            // SAFETY: LOOP_CTL_GET_FREE takes no argument, returns a number.
            let n = unsafe { libc::ioctl(ctl.as_raw_fd(), LOOP_CTL_GET_FREE as _) };
            if n < 0 {
                return sys::err("LOOP_CTL_GET_FREE");
            }
            let path = PathBuf::from(format!("/dev/loop{n}"));
            let dev = match OpenOptions::new().read(true).write(true).open(&path) {
                Ok(d) => d,
                Err(e) => return Err(format!("{}: {e}", path.display())),
            };
            let mut cfg = LoopConfig {
                fd: backing.as_raw_fd() as u32,
                block_size,
                // SAFETY: an all-zero loop_info64 is valid.
                info: unsafe { core::mem::zeroed() },
                reserved: [0; 8],
            };
            cfg.info.flags = LO_FLAGS_AUTOCLEAR;
            // SAFETY: LOOP_CONFIGURE takes a struct loop_config.
            match unsafe { sys::ioctl(dev.as_raw_fd(), LOOP_CONFIGURE, &mut cfg) } {
                Ok(()) => return Ok(Loop { path, dev }),
                // Taken by someone else meanwhile: next free one.
                Err(e) if e.raw_os_error() == Some(libc::EBUSY) => continue,
                Err(e) => return Err(format!("LOOP_CONFIGURE {}: {e}", path.display())),
            }
        }
        Err("no free loop device".into())
    }

    pub fn devt(&self) -> R<String> {
        let (ma, mi) = sys::devno(&self.path)?;
        Ok(format!("{ma}:{mi}"))
    }

    /// Keep the device after this process exits (the session outlives
    /// `prepare`); `detach_path` undoes it.
    pub fn persist(self) {
        core::mem::forget(self);
    }
}

impl Drop for Loop {
    fn drop(&mut self) {
        // SAFETY: LOOP_CLR_FD takes no argument.
        unsafe { libc::ioctl(self.dev.as_raw_fd(), LOOP_CLR_FD as _) };
    }
}

/// Detach a loop device by path (teardown of a persisted session).
pub fn detach_path(path: &Path) -> R<()> {
    let dev = File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    // SAFETY: LOOP_CLR_FD takes no argument.
    if unsafe { libc::ioctl(dev.as_raw_fd(), LOOP_CLR_FD as _) } != 0 {
        return sys::err(&format!("LOOP_CLR_FD {}", path.display()));
    }
    Ok(())
}
