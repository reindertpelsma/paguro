//! Device-mapper through its ioctl interface (linux/dm-ioctl.h), without
//! libdevmapper: the initrd is one static binary, and a table naming a key
//! never leaves this process.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

use crate::plan::Target;
use crate::sys::{self, R};

const HDR: usize = 312;
const SPEC: usize = 40;
const NAME_LEN: usize = 128;

const CMD_CREATE: u8 = 3;
const CMD_REMOVE: u8 = 4;
const CMD_SUSPEND: u8 = 6;
const CMD_LOAD: u8 = 9;

pub const READONLY: u32 = 1;
/// Ask the kernel to wipe the ioctl buffer (tables naming key material).
const SECURE_DATA: u32 = 1 << 15;

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
    put(&mut b, 0, &4u32.to_le_bytes());
    put(&mut b, 12, &(size as u32).to_le_bytes());
    put(&mut b, 16, &(HDR as u32).to_le_bytes());
    put(&mut b, 28, &flags.to_le_bytes());
    put(&mut b, 48, name.as_bytes());
    Ok(b)
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    b.get(at..at + 8)
        .and_then(|s| s.try_into().ok())
        .map_or(0, u64::from_le_bytes)
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
            unsafe { libc::mknod(c.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(ma, mi)) };
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
                sys::iowr(0xfd, cmd, HDR),
                buf.as_mut_ptr(),
            )
        }
    }

    /// Create `name`, load `targets` and resume it.
    pub fn setup(&self, name: &str, targets: &[Target], flags: u32) -> R<Mapped> {
        let mut b = header(name, 0, HDR)?;
        self.call(CMD_CREATE, &mut b)
            .map_err(|e| format!("dm create {name}: {e}"))?;
        let dev = u64_at(&b, 40);
        let r = self.load_resume(name, targets, flags);
        if let Err(e) = r {
            let _ = self.remove(name);
            return Err(e);
        }
        let major = ((dev & 0xfff00) >> 8) as u32;
        let minor = ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32;
        let node = PathBuf::from(format!("/dev/dm-{minor}"));
        for _ in 0..200 {
            if node.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if !node.exists() {
            // No devtmpfs: make the node ourselves.
            let c = sys::cstr(node.to_str().unwrap_or_default())?;
            // SAFETY: mknod with a valid path.
            unsafe {
                libc::mknod(
                    c.as_ptr(),
                    libc::S_IFBLK | 0o600,
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
            while (SPEC + params.len()) % 8 != 0 {
                params.push(0);
            }
            let mut s = vec![0u8; SPEC];
            put(&mut s, 0, &t.start.to_le_bytes());
            put(&mut s, 8, &t.len.to_le_bytes());
            put(&mut s, 20, &((SPEC + params.len()) as u32).to_le_bytes());
            if t.kind.len() >= 16 {
                return Err(format!("bad target type {}", t.kind));
            }
            put(&mut s, 24, t.kind.as_bytes());
            specs.extend_from_slice(&s);
            specs.extend_from_slice(&params);
            zeroize::Zeroize::zeroize(&mut params);
        }
        let secure = targets.iter().any(|t| t.kind == "crypt");
        let lflags = (flags & READONLY) | if secure { SECURE_DATA } else { 0 };
        let mut b = header(name, lflags, HDR + specs.len())?;
        put(&mut b, 20, &(targets.len() as u32).to_le_bytes());
        put(&mut b, HDR, &specs);
        zeroize::Zeroize::zeroize(&mut specs);
        let r = self.call(CMD_LOAD, &mut b);
        zeroize::Zeroize::zeroize(&mut b);
        r.map_err(|e| format!("dm load {name}: {e}"))?;
        let mut b = header(name, 0, HDR)?;
        self.call(CMD_SUSPEND, &mut b)
            .map_err(|e| format!("dm resume {name}: {e}"))
    }

    pub fn remove(&self, name: &str) -> R<()> {
        let mut b = header(name, 0, HDR)?;
        self.call(CMD_REMOVE, &mut b)
            .map_err(|e| format!("dm remove {name}: {e}"))?;
        let _ = std::fs::remove_file(Path::new("/dev/mapper").join(name));
        Ok(())
    }
}
