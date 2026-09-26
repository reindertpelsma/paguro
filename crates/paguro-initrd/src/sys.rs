//! Thin wrappers over the system calls the initrd needs. Nothing here
//! decides anything.

use std::ffi::CString;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::Path;

pub type R<T> = Result<T, String>;

pub fn cstr(s: &str) -> R<CString> {
    CString::new(s).map_err(|_| format!("NUL in {s:?}"))
}

fn cpath(p: &Path) -> R<CString> {
    cstr(p.to_str().ok_or("path not UTF-8")?)
}

pub fn err<T>(what: &str) -> R<T> {
    Err(format!("{what}: {}", io::Error::last_os_error()))
}

// The ioctl request encoding (include/uapi/asm-generic/ioctl.h).
const IOC_READ_WRITE: libc::c_ulong = 3; // _IOC_READ | _IOC_WRITE
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = 8;
const IOC_SIZESHIFT: u32 = 16;
const IOC_DIRSHIFT: u32 = 30;

/// `_IOWR(ty, nr, size)`.
pub const fn iowr(ty: u8, nr: u8, size: usize) -> libc::c_ulong {
    (IOC_READ_WRITE << IOC_DIRSHIFT)
        | ((size as libc::c_ulong) << IOC_SIZESHIFT)
        | ((ty as libc::c_ulong) << IOC_TYPESHIFT)
        | ((nr as libc::c_ulong) << IOC_NRSHIFT)
}

/// The unit FIEMAP extents are checked against and converted to.
const SECTOR: u64 = 512;

/// `ioctl(fd, req, arg)`, the raw errno on failure.
///
/// # Safety
/// `arg` must be what `req` expects.
pub unsafe fn ioctl<T>(fd: RawFd, req: libc::c_ulong, arg: *mut T) -> io::Result<()> {
    // SAFETY: the caller guarantees `arg` matches `req`.
    let r = unsafe { libc::ioctl(fd, req as _, arg) };
    if r < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

pub fn mount(src: &str, dst: &Path, fstype: &str, flags: libc::c_ulong, data: &str) -> R<()> {
    let (s, d, t, o) = (cstr(src)?, cpath(dst)?, cstr(fstype)?, cstr(data)?);
    // SAFETY: all pointers are valid NUL-terminated strings.
    let r = unsafe { libc::mount(s.as_ptr(), d.as_ptr(), t.as_ptr(), flags, o.as_ptr().cast()) };
    if r != 0 {
        return err(&format!("mount {fstype} {src} on {}", dst.display()));
    }
    Ok(())
}

pub fn umount(dst: &Path) -> R<()> {
    let d = cpath(dst)?;
    // SAFETY: valid string.
    if unsafe { libc::umount2(d.as_ptr(), 0) } != 0 {
        return err(&format!("umount {}", dst.display()));
    }
    Ok(())
}

/// `(major, minor)` of a block device node.
pub fn devno(path: &Path) -> R<(u32, u32)> {
    let m = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !m.file_type().is_block_device() {
        return Err(format!("{} is not a block device", path.display()));
    }
    let rdev = m.rdev();
    Ok((libc::major(rdev), libc::minor(rdev)))
}

/// Size of a block device in bytes, and its logical block size.
pub fn blk_geometry(f: &File) -> R<(u64, u32)> {
    const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
    const BLKSSZGET: libc::c_ulong = 0x1268;
    let mut size = 0u64;
    let mut lbs: libc::c_int = 0;
    // SAFETY: BLKGETSIZE64 writes a u64, BLKSSZGET an int.
    unsafe {
        ioctl(f.as_raw_fd(), BLKGETSIZE64, &mut size).map_err(|e| format!("BLKGETSIZE64: {e}"))?;
        ioctl(f.as_raw_fd(), BLKSSZGET, &mut lbs).map_err(|e| format!("BLKSSZGET: {e}"))?;
    }
    Ok((size, lbs as u32))
}

/// Add a `logon` key (readable by the kernel only, never by userspace) to
/// this thread's keyring; its serial.
pub fn add_logon_key(desc: &str, payload: &[u8]) -> R<i32> {
    let ty = cstr("logon")?;
    let d = cstr(desc)?;
    // SAFETY: add_key(type, desc, payload, plen, keyring).
    let r = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            ty.as_ptr(),
            d.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            libc::KEY_SPEC_THREAD_KEYRING,
        )
    };
    if r < 0 {
        return err("add_key");
    }
    Ok(r as i32)
}

/// Add a `logon` key to this **session** keyring: it survives this process
/// exiting, for a later re-seal tool in the same login session to read
/// (INTERFACES.md §8.3). Root-only: `logon` keys are never readable by
/// userspace, only by the kernel on the creating (or a permitted) process's
/// behalf.
pub fn add_session_logon_key(desc: &str, payload: &[u8]) -> R<i32> {
    let ty = cstr("logon")?;
    let d = cstr(desc)?;
    // SAFETY: add_key(type, desc, payload, plen, keyring).
    let r = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            ty.as_ptr(),
            d.as_ptr(),
            payload.as_ptr(),
            payload.len(),
            libc::KEY_SPEC_SESSION_KEYRING,
        )
    };
    if r < 0 {
        return err("add_key (session)");
    }
    Ok(r as i32)
}

/// Invalidate a key: gone from every keyring at once.
pub fn invalidate_key(serial: i32) {
    const KEYCTL_INVALIDATE: libc::c_long = 21;
    // SAFETY: keyctl with integer arguments only.
    unsafe {
        libc::syscall(libc::SYS_keyctl, KEYCTL_INVALIDATE, serial as libc::c_long);
    }
}

/// Open the file whose inode is `ino` with generation `gen` on the file
/// system mounted at `mnt` (ntfs3: MFT record number and sequence number).
pub fn open_by_ino_gen(mnt: &File, ino: u32, generation: u32) -> io::Result<File> {
    #[repr(C)]
    struct Handle {
        bytes: u32,
        ty: i32,
        ino: u32,
        generation: u32,
    }
    const FILEID_INO32_GEN: i32 = 1;
    let mut h = Handle {
        // f_handle: the ino and generation that follow the header.
        bytes: (size_of::<Handle>() - std::mem::offset_of!(Handle, ino)) as u32,
        ty: FILEID_INO32_GEN,
        ino,
        generation,
    };
    // SAFETY: a file_handle with 8 bytes of f_handle.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_open_by_handle_at,
            mnt.as_raw_fd(),
            &mut h as *mut Handle,
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a fresh descriptor we own.
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

/// A file's physical extents as FIEMAP reports them, in 512-byte sectors
/// of the device the file system is mounted on, file order.
pub fn fiemap(f: &File) -> R<Vec<(u64, u64)>> {
    // FS_IOC_FIEMAP is _IOWR('f', 11, struct fiemap), the fixed header
    // without its extents (include/uapi/linux/fs.h, fiemap.h).
    const FS_IOC_FIEMAP: libc::c_ulong = iowr(b'f', 11, std::mem::offset_of!(Map, extents));
    const _: () = assert!(std::mem::offset_of!(Map, extents) == 32);
    const FIEMAP_FLAG_SYNC: u32 = 1;
    const FIEMAP_EXTENT_LAST: u32 = 1;
    /// Extents fetched per call.
    const N: usize = 256;
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Extent {
        logical: u64,
        physical: u64,
        length: u64,
        reserved64: [u64; 2],
        flags: u32,
        reserved: [u32; 3],
    }
    #[repr(C)]
    struct Map {
        start: u64,
        length: u64,
        flags: u32,
        mapped: u32,
        count: u32,
        reserved: u32,
        extents: [Extent; N],
    }
    let zero = Extent {
        logical: 0,
        physical: 0,
        length: 0,
        reserved64: [0; 2],
        flags: 0,
        reserved: [0; 3],
    };
    let mut m = Box::new(Map {
        start: 0,
        length: u64::MAX,
        flags: FIEMAP_FLAG_SYNC,
        mapped: 0,
        count: N as u32,
        reserved: 0,
        extents: [zero; N],
    });
    let mut out = Vec::new();
    let mut start = 0u64;
    loop {
        m.start = start;
        m.length = u64::MAX - start;
        m.mapped = 0;
        // SAFETY: a struct fiemap followed by N extents, count = N.
        unsafe { ioctl(f.as_raw_fd(), FS_IOC_FIEMAP, &mut *m) }
            .map_err(|e| format!("FIEMAP: {e}"))?;
        if m.mapped == 0 {
            break;
        }
        let mut last = false;
        for e in m.extents.iter().take(m.mapped as usize) {
            if e.physical % SECTOR != 0 || e.length % SECTOR != 0 {
                return Err("FIEMAP: extent not sector-aligned".into());
            }
            out.push((e.physical / SECTOR, e.length / SECTOR));
            start = e.logical + e.length;
            last |= e.flags & FIEMAP_EXTENT_LAST != 0;
        }
        if last {
            break;
        }
    }
    Ok(out)
}

pub fn mlock(buf: &[u8]) {
    // SAFETY: locking our own buffer; failure only means it may be swapped
    // (there is no swap in an initramfs).
    unsafe {
        libc::mlock(buf.as_ptr().cast(), buf.len());
    }
}

/// Clear FS_IMMUTABLE_FL on an efivarfs file so it can be rewritten.
pub fn clear_immutable(f: &File) {
    const FS_IOC_GETFLAGS: libc::c_ulong = 0x8008_6601;
    const FS_IOC_SETFLAGS: libc::c_ulong = 0x4008_6602;
    const FS_IMMUTABLE_FL: libc::c_int = 0x10;
    let mut flags: libc::c_int = 0;
    // SAFETY: GETFLAGS/SETFLAGS take an int.
    unsafe {
        if ioctl(f.as_raw_fd(), FS_IOC_GETFLAGS, &mut flags).is_ok() && flags & FS_IMMUTABLE_FL != 0
        {
            flags &= !FS_IMMUTABLE_FL;
            let _ = ioctl(f.as_raw_fd(), FS_IOC_SETFLAGS, &mut flags);
        }
    }
}
