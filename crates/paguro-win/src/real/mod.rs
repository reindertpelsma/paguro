//! [`WinApi`] on Windows: a thin, decision-free translation to Win32.
//!
//! Every `unsafe` block here is a Win32 call with buffers this module owns
//! and sizes it passes explicitly; nothing parses what the OS returns
//! beyond fixed Win32 structures (anything with a format goes back to the
//! caller as bytes, for `paguro-core`). Privileges are enabled once, at
//! construction, and only the three the tool needs.
#![allow(unsafe_code)]

mod console;
mod devices;
mod wmi;

use std::ffi::c_void;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::windows::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::os::windows::io::AsRawHandle;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use paguro_core::guid::Guid;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ACCESS_DENIED, ERROR_CALL_NOT_IMPLEMENTED, ERROR_ENVVAR_NOT_FOUND,
    ERROR_FILE_NOT_FOUND, ERROR_HANDLE_EOF, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_FUNCTION,
    ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS, ERROR_NOT_SUPPORTED, ERROR_PATH_NOT_FOUND,
    ERROR_PRIVILEGE_NOT_HELD, ERROR_SUCCESS, GetLastError, HANDLE, LUID, MAX_PATH, WIN32_ERROR,
};
use windows::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TokenElevation,
};
use windows::Win32::Storage::FileSystem::{
    BusTypeAta, BusTypeFileBackedVirtual, BusTypeMmc, BusTypeNvme, BusTypeRAID, BusTypeSCM,
    BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd, BusTypeSpaces, BusTypeUfs, BusTypeUsb,
    BusTypeVirtual, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, FILE_STANDARD_INFO, FileIdInfo, FileStandardInfo, FindFirstVolumeW,
    FindNextVolumeW, FindVolumeClose, GetDiskFreeSpaceExW, GetDiskFreeSpaceW,
    GetFileInformationByHandleEx, GetVolumeInformationW, GetVolumeNameForVolumeMountPointW,
    GetVolumePathNameW, GetVolumePathNamesForVolumeNameW, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW, STORAGE_BUS_TYPE,
};
use windows::Win32::Storage::Vhd::{
    ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER, ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME,
    ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY, ATTACH_VIRTUAL_DISK_PARAMETERS,
    ATTACH_VIRTUAL_DISK_VERSION_1, AttachVirtualDisk,
    CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION, CREATE_VIRTUAL_DISK_PARAMETERS,
    CREATE_VIRTUAL_DISK_VERSION_1, CreateVirtualDisk, DETACH_VIRTUAL_DISK_FLAG_NONE,
    DetachVirtualDisk, GetVirtualDiskPhysicalPath, OPEN_VIRTUAL_DISK_FLAG_NONE, OpenVirtualDisk,
    VIRTUAL_DISK_ACCESS_ALL, VIRTUAL_STORAGE_TYPE, VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
    VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
};
use windows::Win32::System::IO::DeviceIoControl;
use windows::Win32::System::Ioctl::{
    FSCTL_GET_RETRIEVAL_POINTERS, GET_LENGTH_INFORMATION, IOCTL_DISK_GET_LENGTH_INFO,
    IOCTL_DISK_GET_PARTITION_INFO_EX, IOCTL_STORAGE_GET_DEVICE_NUMBER,
    IOCTL_STORAGE_QUERY_PROPERTY, PARTITION_INFORMATION_EX, PARTITION_STYLE_GPT,
    PropertyStandardQuery, STARTING_VCN_INPUT_BUFFER, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_DEVICE_NUMBER, STORAGE_PROPERTY_QUERY, StorageDeviceProperty,
};
use windows::Win32::System::Shutdown::{
    InitiateSystemShutdownExW, SHTDN_REASON_FLAG_PLANNED, SHTDN_REASON_MAJOR_OTHER,
};
use windows::Win32::System::SystemInformation::{
    FIRMWARE_TYPE, FirmwareTypeUefi, GetFirmwareType, GetSystemFirmwareTable, RSMB,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::TpmBaseServices::{
    TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL, TBS_CONTEXT_PARAMS,
    TBS_CONTEXT_PARAMS2, TBS_CONTEXT_VERSION_TWO, TBS_SUCCESS, TPM_DEVICE_INFO, TPM_VERSION_20,
    Tbsi_Context_Create, Tbsi_Get_TCG_Log, Tbsi_GetDeviceInfo, Tbsip_Context_Close,
    Tbsip_Submit_Command,
};
use windows::Win32::System::WindowsProgramming::{
    GetFirmwareEnvironmentVariableExW, SetFirmwareEnvironmentVariableExW,
};
use windows::core::{HSTRING, PCWSTR, PWSTR};
use zeroize::Zeroizing;

use crate::api::*;

/// Largest firmware variable read (a big `db` is tens of KiB).
const MAX_VAR: usize = 1 << 20;
/// First buffer tried for a firmware variable; grown ×`VAR_GROWTH` on
/// ERROR_INSUFFICIENT_BUFFER up to `MAX_VAR`.
const VAR_FIRST_BUF: usize = 4096;
const VAR_GROWTH: usize = 4;

/// A path buffer with room for MAX_PATH characters and the NUL.
const PATH_BUF: usize = MAX_PATH as usize + 1;
/// A long path buffer (volume roots, the mount-point multi-string).
const LONG_PATH_BUF: usize = 1024;
/// `\\?\Volume{GUID}\` is 49 characters; the buffer rounds up.
const VOLUME_NAME_BUF: usize = 64;

/// `\\.\PhysicalDriveN` numbers probed by `disks`.
const MAX_PHYSICAL_DRIVES: u32 = 64;
/// IOCTL_STORAGE_QUERY_PROPERTY output: the descriptor and its strings.
const DEVICE_DESCRIPTOR_BUF: usize = 1024;
/// Raw disk reads go through this alignment (covers 512e and 4Kn).
const RAW_READ_ALIGN: u64 = 4096;
/// Tbsip_Submit_Command response buffer (a TPM response fits in 4 KiB).
const TPM_RESPONSE_BUF: usize = 4096;
/// Sector size of a VHD `vhd_create_fixed` makes.
const VHD_SECTOR: u32 = 512;

/// FSCTL_GET_RETRIEVAL_POINTERS output as u64 words: ExtentCount (u32,
/// padded) and StartingVcn, then { NextVcn, Lcn } per extent.
const RP_HEADER_WORDS: usize = 2;
const RP_WORDS_PER_EXTENT: usize = 2;
/// Extents fetched per call.
const RP_EXTENTS_PER_CALL: usize = 512;

/// TBS_CONTEXT_PARAMS2 bitfield: bit 2 is `includeTpm20` (tbs.h).
const TBS_INCLUDE_TPM20: u32 = 1 << 2;

fn wide(s: &str) -> HSTRING {
    HSTRING::from(s)
}

fn from_wide(b: &[u16]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf16_lossy(b.get(..end).unwrap_or(&[]))
}

fn last_error() -> WIN32_ERROR {
    // SAFETY: reads the calling thread's last-error value.
    unsafe { GetLastError() }
}

/// The Win32 error code in an HRESULT's low 16 bits (HRESULT_CODE).
fn win32_code(e: &windows::core::Error) -> WIN32_ERROR {
    const HRESULT_CODE_MASK: u32 = 0xffff;
    WIN32_ERROR((e.code().0 as u32) & HRESULT_CODE_MASK)
}

fn win_err(op: &'static str, e: windows::core::Error) -> ApiError {
    let code = e.code().0 as i64;
    let kind = match win32_code(&e) {
        ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_ENVVAR_NOT_FOUND => ErrorKind::NotFound,
        ERROR_ACCESS_DENIED | ERROR_PRIVILEGE_NOT_HELD => ErrorKind::AccessDenied,
        ERROR_NOT_SUPPORTED | ERROR_CALL_NOT_IMPLEMENTED | ERROR_INVALID_FUNCTION => {
            ErrorKind::Unsupported
        }
        _ => ErrorKind::Other,
    };
    ApiError::new(kind, op, e.message()).with_code(code)
}

fn w32(op: &'static str, e: WIN32_ERROR) -> ApiError {
    win_err(op, windows::core::Error::from(e.to_hresult()))
}

fn io_err(op: &'static str, path: &str, e: std::io::Error) -> ApiError {
    let kind = match e.kind() {
        std::io::ErrorKind::NotFound => ErrorKind::NotFound,
        std::io::ErrorKind::PermissionDenied => ErrorKind::AccessDenied,
        _ => ErrorKind::Other,
    };
    let mut a = ApiError::new(kind, op, format!("{path}: {e}"));
    if let Some(c) = e.raw_os_error() {
        a = a.with_code(i64::from(c));
    }
    a
}

/// `{xxxxxxxx-…}`, the form the firmware-variable API takes.
fn guid_braced(g: &Guid) -> HSTRING {
    let t = g.to_text();
    wide(&format!("{{{}}}", String::from_utf8_lossy(&t)))
}

/// A handle closed on drop.
struct Owned(HANDLE);

impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_invalid() && !self.0.0.is_null() {
            // SAFETY: the handle was returned open by a Win32 call and is closed once.
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

fn enable_privilege(name: &str) -> bool {
    let mut token = HANDLE::default();
    // SAFETY: the pseudo-handle of this process; `token` receives a handle we close.
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
    }
    .is_err()
    {
        return false;
    }
    let token = Owned(token);
    let mut luid = LUID::default();
    // SAFETY: `luid` is a valid out-pointer; the name is NUL-terminated.
    if unsafe { LookupPrivilegeValueW(PCWSTR::null(), &wide(name), &mut luid) }.is_err() {
        return false;
    }
    let mut tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        ..Default::default()
    };
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    // SAFETY: `tp` is a complete one-entry TOKEN_PRIVILEGES.
    let ok = unsafe { AdjustTokenPrivileges(token.0, false, Some(&tp), 0, None, None) }.is_ok();
    ok && last_error() == ERROR_SUCCESS
}

pub struct RealApi {
    elevated: bool,
}

impl Default for RealApi {
    fn default() -> Self {
        Self::new()
    }
}

impl RealApi {
    pub fn new() -> Self {
        for p in [
            "SeSystemEnvironmentPrivilege",
            "SeShutdownPrivilege",
            "SeManageVolumePrivilege",
        ] {
            let _ = enable_privilege(p);
        }
        RealApi {
            elevated: token_elevated(),
        }
    }
}

fn token_elevated() -> bool {
    let mut token = HANDLE::default();
    // SAFETY: as in `enable_privilege`.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    let token = Owned(token);
    let mut e = TOKEN_ELEVATION::default();
    let mut len = 0u32;
    // SAFETY: `e` is exactly the size passed.
    let r = unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut e as *mut _ as *mut c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut len,
        )
    };
    r.is_ok() && e.TokenIsElevated != 0
}

/// FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE.
const SHARE_ALL: u32 = FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0 | FILE_SHARE_DELETE.0;

fn open_device(path: &str) -> Result<fs::File, ApiError> {
    fs::OpenOptions::new()
        .read(true)
        .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE).0)
        .open(path)
        .map_err(|e| io_err("CreateFileW", path, e))
}

/// An open handle for metadata IOCTLs only (no read access needed).
fn open_query(path: &str) -> Result<fs::File, ApiError> {
    fs::OpenOptions::new()
        .access_mode(0)
        .share_mode(SHARE_ALL)
        .open(path)
        .map_err(|e| io_err("CreateFileW", path, e))
}

fn ioctl<I, O: Default>(f: &fs::File, code: u32, input: Option<&I>) -> Result<O, WIN32_ERROR> {
    let mut out = O::default();
    let mut ret = 0u32;
    // SAFETY: `input` and `out` are live, correctly sized values of the
    // types the IOCTL documents; the handle is open for the call's duration.
    let r = unsafe {
        DeviceIoControl(
            HANDLE(f.as_raw_handle()),
            code,
            input.map(|i| i as *const I as *const c_void),
            input.map_or(0, |_| std::mem::size_of::<I>() as u32),
            Some(&mut out as *mut O as *mut c_void),
            std::mem::size_of::<O>() as u32,
            Some(&mut ret),
            None,
        )
    };
    match r {
        Ok(()) => Ok(out),
        Err(_) => Err(last_error()),
    }
}

// The `windows` crate keeps the SDK's CamelCase enum-constant names.
#[allow(non_upper_case_globals)]
fn bus_name(t: STORAGE_BUS_TYPE) -> &'static str {
    match t {
        BusTypeScsi => "scsi",
        BusTypeAta => "ata",
        BusTypeUsb => "usb",
        BusTypeRAID => "raid",
        BusTypeSas => "sas",
        BusTypeSata => "sata",
        BusTypeSd => "sd",
        BusTypeMmc => "mmc",
        BusTypeVirtual | BusTypeFileBackedVirtual => "virtual",
        BusTypeSpaces => "spaces",
        BusTypeNvme => "nvme",
        BusTypeSCM => "scm",
        BusTypeUfs => "ufs",
        _ => "other",
    }
}

impl RealApi {
    fn volume(&self, guid_path: &str) -> Volume {
        let mut names = vec![0u16; LONG_PATH_BUF];
        let mut len = 0u32;
        // SAFETY: `names` is a writable buffer of the length passed.
        let mounts = match unsafe {
            GetVolumePathNamesForVolumeNameW(&wide(guid_path), Some(&mut names), &mut len)
        } {
            Ok(()) => names
                .split(|&c| c == 0)
                .take_while(|s| !s.is_empty())
                .map(String::from_utf16_lossy)
                .collect(),
            Err(_) => Vec::new(),
        };
        let mut label = [0u16; PATH_BUF];
        let mut fsname = [0u16; PATH_BUF];
        // SAFETY: both buffers are writable and sized.
        let _ = unsafe {
            GetVolumeInformationW(
                &wide(guid_path),
                Some(&mut label),
                None,
                None,
                None,
                Some(&mut fsname),
            )
        };
        let (mut total, mut free) = (0u64, 0u64);
        // SAFETY: out-pointers to locals.
        let _ = unsafe {
            GetDiskFreeSpaceExW(&wide(guid_path), None, Some(&mut total), Some(&mut free))
        };
        let dev = format!(
            "\\\\.\\{}",
            guid_path
                .trim_start_matches("\\\\?\\")
                .trim_end_matches('\\')
        );
        let location = open_query(&dev).ok().and_then(|f| {
            let p: PARTITION_INFORMATION_EX =
                ioctl::<(), _>(&f, IOCTL_DISK_GET_PARTITION_INFO_EX, None).ok()?;
            let n: STORAGE_DEVICE_NUMBER =
                ioctl::<(), _>(&f, IOCTL_STORAGE_GET_DEVICE_NUMBER, None).ok()?;
            let (t, id) = if p.PartitionStyle == PARTITION_STYLE_GPT {
                // SAFETY: the union member PartitionStyle names.
                let g = unsafe { p.Anonymous.Gpt };
                (
                    Some(guid_from(&g.PartitionType)),
                    Some(guid_from(&g.PartitionId)),
                )
            } else {
                (None, None)
            };
            Some(DiskLocation {
                disk_number: n.DeviceNumber,
                partition_number: p.PartitionNumber,
                offset: p.StartingOffset as u64,
                length: p.PartitionLength as u64,
                gpt_type: t,
                partition_guid: id,
            })
        });
        Volume {
            guid_path: guid_path.to_string(),
            mount_points: mounts,
            filesystem: from_wide(&fsname),
            label: from_wide(&label),
            size: total,
            free,
            location,
        }
    }
}

fn guid_from(g: &windows::core::GUID) -> Guid {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..].copy_from_slice(&g.data4);
    Guid(b)
}

fn storage_type() -> VIRTUAL_STORAGE_TYPE {
    VIRTUAL_STORAGE_TYPE {
        DeviceId: VIRTUAL_STORAGE_TYPE_DEVICE_VHD,
        VendorId: VIRTUAL_STORAGE_TYPE_VENDOR_MICROSOFT,
    }
}

fn open_vhd(path: &str) -> Result<Owned, ApiError> {
    let mut h = HANDLE::default();
    let st = storage_type();
    // SAFETY: `st` and `h` are live locals; the path is NUL-terminated.
    let r = unsafe {
        OpenVirtualDisk(
            &st,
            &wide(path),
            VIRTUAL_DISK_ACCESS_ALL,
            OPEN_VIRTUAL_DISK_FLAG_NONE,
            None,
            &mut h,
        )
    };
    if r != ERROR_SUCCESS {
        return Err(w32("OpenVirtualDisk", r));
    }
    Ok(Owned(h))
}

impl WinApi for RealApi {
    fn is_elevated(&self) -> bool {
        self.elevated
    }

    fn firmware_is_uefi(&self) -> bool {
        let mut t = FIRMWARE_TYPE::default();
        // SAFETY: out-pointer to a local.
        unsafe { GetFirmwareType(&mut t) }.is_ok() && t == FirmwareTypeUefi
    }

    fn arch(&self) -> &'static str {
        if cfg!(target_arch = "aarch64") {
            "aa64"
        } else {
            "x64"
        }
    }

    fn fw_get(&self, name: &str, vendor: &Guid) -> ApiResult<Option<FwVar>> {
        let mut buf = vec![0u8; VAR_FIRST_BUF];
        loop {
            let mut attrs = 0u32;
            // SAFETY: `buf` is writable for the length passed.
            let n = unsafe {
                GetFirmwareEnvironmentVariableExW(
                    &wide(name),
                    &guid_braced(vendor),
                    Some(buf.as_mut_ptr() as *mut c_void),
                    buf.len() as u32,
                    Some(&mut attrs),
                )
            };
            if n > 0 {
                buf.truncate(n as usize);
                return Ok(Some(FwVar {
                    data: buf,
                    attributes: attrs,
                }));
            }
            match last_error() {
                ERROR_ENVVAR_NOT_FOUND => return Ok(None),
                ERROR_INSUFFICIENT_BUFFER if buf.len() < MAX_VAR => {
                    buf.resize(buf.len() * VAR_GROWTH, 0)
                }
                e => return Err(w32("GetFirmwareEnvironmentVariableExW", e)),
            }
        }
    }

    fn fw_set(&self, name: &str, vendor: &Guid, data: &[u8], attributes: u32) -> ApiResult<()> {
        if data.is_empty() {
            return Err(ApiError::new(
                ErrorKind::Other,
                "SetFirmwareEnvironmentVariableExW",
                "empty value (use fw_delete)",
            ));
        }
        // SAFETY: `data` is readable for the length passed.
        unsafe {
            SetFirmwareEnvironmentVariableExW(
                &wide(name),
                &guid_braced(vendor),
                Some(data.as_ptr() as *const c_void),
                data.len() as u32,
                attributes,
            )
        }
        .map_err(|e| win_err("SetFirmwareEnvironmentVariableExW", e))
    }

    fn fw_delete(&self, name: &str, vendor: &Guid) -> ApiResult<()> {
        // SAFETY: a zero-length write deletes the variable.
        match unsafe {
            SetFirmwareEnvironmentVariableExW(&wide(name), &guid_braced(vendor), None, 0, 0)
        } {
            Ok(()) => Ok(()),
            Err(e) if win32_code(&e) == ERROR_ENVVAR_NOT_FOUND => Ok(()),
            Err(e) => Err(win_err("SetFirmwareEnvironmentVariableExW", e)),
        }
    }

    fn read_file(&self, path: &str, max: usize) -> ApiResult<Option<Vec<u8>>> {
        let f = match fs::File::open(path) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err("CreateFileW", path, e)),
        };
        let mut v = Vec::new();
        f.take(max as u64 + 1)
            .read_to_end(&mut v)
            .map_err(|e| io_err("ReadFile", path, e))?;
        if v.len() > max {
            return Err(ApiError::new(
                ErrorKind::InvalidData,
                "ReadFile",
                format!("{path}: larger than {max} bytes"),
            ));
        }
        Ok(Some(v))
    }

    fn read_file_at(&self, path: &str, offset: u64, len: usize) -> ApiResult<Vec<u8>> {
        let mut f = fs::File::open(path).map_err(|e| io_err("CreateFileW", path, e))?;
        f.seek(SeekFrom::Start(offset))
            .map_err(|e| io_err("SetFilePointerEx", path, e))?;
        let mut v = vec![0u8; len];
        f.read_exact(&mut v)
            .map_err(|e| io_err("ReadFile", path, e))?;
        Ok(v)
    }

    fn write_file(&self, path: &str, data: &[u8]) -> ApiResult<()> {
        let mut f = fs::File::create(path).map_err(|e| io_err("CreateFileW", path, e))?;
        f.write_all(data)
            .map_err(|e| io_err("WriteFile", path, e))?;
        f.sync_all()
            .map_err(|e| io_err("FlushFileBuffers", path, e))
    }

    fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        // SAFETY: both paths are NUL-terminated.
        unsafe {
            MoveFileExW(
                &wide(from),
                &wide(to),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        }
        .map_err(|e| win_err("MoveFileExW", e))
    }

    fn remove_file(&self, path: &str) -> ApiResult<bool> {
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_err("DeleteFileW", path, e)),
        }
    }

    fn create_dir_all(&self, path: &str) -> ApiResult<()> {
        fs::create_dir_all(path).map_err(|e| io_err("CreateDirectoryW", path, e))
    }

    fn remove_dir(&self, path: &str) -> ApiResult<bool> {
        match fs::remove_dir(path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io_err("RemoveDirectoryW", path, e)),
        }
    }

    fn list_dir(&self, path: &str) -> ApiResult<Option<Vec<DirEntry>>> {
        let rd = match fs::read_dir(path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err("FindFirstFileW", path, e)),
        };
        let mut out = Vec::new();
        for e in rd {
            let e = e.map_err(|e| io_err("FindNextFileW", path, e))?;
            let md = e
                .metadata()
                .map_err(|er| io_err("GetFileAttributesExW", path, er))?;
            out.push(DirEntry {
                name: e.file_name().to_string_lossy().into_owned(),
                is_dir: md.is_dir(),
                len: md.len(),
            });
        }
        Ok(Some(out))
    }

    fn file_facts(&self, path: &str) -> ApiResult<Option<FileFacts>> {
        let f = match fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0)
            .share_mode(SHARE_ALL)
            .open(path)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err("CreateFileW", path, e)),
        };
        let md = f
            .metadata()
            .map_err(|e| io_err("GetFileInformationByHandle", path, e))?;
        let mut id = FILE_ID_INFO::default();
        let mut std_info = FILE_STANDARD_INFO::default();
        let h = HANDLE(f.as_raw_handle());
        // SAFETY: each buffer is exactly the size passed, for its class.
        unsafe {
            GetFileInformationByHandleEx(
                h,
                FileIdInfo,
                &mut id as *mut _ as *mut c_void,
                std::mem::size_of::<FILE_ID_INFO>() as u32,
            )
            .map_err(|e| win_err("GetFileInformationByHandleEx", e))?;
            GetFileInformationByHandleEx(
                h,
                FileStandardInfo,
                &mut std_info as *mut _ as *mut c_void,
                std::mem::size_of::<FILE_STANDARD_INFO>() as u32,
            )
            .map_err(|e| win_err("GetFileInformationByHandleEx", e))?;
        }
        Ok(Some(FileFacts {
            len: md.file_size(),
            allocated: std_info.AllocationSize as u64,
            attributes: md.file_attributes(),
            file_id: id.FileId.Identifier,
            volume_serial: id.VolumeSerialNumber,
        }))
    }

    fn retrieval_pointers(&self, path: &str) -> ApiResult<Extents> {
        let f = fs::OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES.0)
            .share_mode(SHARE_ALL)
            .open(path)
            .map_err(|e| io_err("CreateFileW", path, e))?;
        let mut root = [0u16; PATH_BUF];
        // SAFETY: `root` is writable for its length.
        unsafe { GetVolumePathNameW(&wide(path), &mut root) }
            .map_err(|e| win_err("GetVolumePathNameW", e))?;
        let (mut spc, mut bps) = (0u32, 0u32);
        // SAFETY: out-pointers to locals.
        unsafe {
            GetDiskFreeSpaceW(
                PCWSTR(root.as_ptr()),
                Some(&mut spc),
                Some(&mut bps),
                None,
                None,
            )
        }
        .map_err(|e| win_err("GetDiskFreeSpaceW", e))?;
        let mut extents = Vec::new();
        let mut next_vcn = 0i64;
        // RETRIEVAL_POINTERS_BUFFER: count u32, pad, StartingVcn i64, then
        // { NextVcn i64, Lcn i64 } × count. Read into a u64-aligned buffer.
        let mut buf = vec![0u64; RP_HEADER_WORDS + RP_WORDS_PER_EXTENT * RP_EXTENTS_PER_CALL];
        loop {
            let input = STARTING_VCN_INPUT_BUFFER {
                StartingVcn: next_vcn,
            };
            let mut ret = 0u32;
            // SAFETY: `input` and `buf` are live and sized as passed.
            let r = unsafe {
                DeviceIoControl(
                    HANDLE(f.as_raw_handle()),
                    FSCTL_GET_RETRIEVAL_POINTERS,
                    Some(&input as *const _ as *const c_void),
                    std::mem::size_of::<STARTING_VCN_INPUT_BUFFER>() as u32,
                    Some(buf.as_mut_ptr() as *mut c_void),
                    (buf.len() * size_of::<u64>()) as u32,
                    Some(&mut ret),
                    None,
                )
            };
            let more = match r {
                Ok(()) => false,
                Err(_) => match last_error() {
                    ERROR_MORE_DATA => true,
                    // An empty (resident or zero-length) file has no extents.
                    ERROR_HANDLE_EOF => break,
                    e => return Err(w32("FSCTL_GET_RETRIEVAL_POINTERS", e)),
                },
            };
            let at = |i: usize| buf.get(i).copied().unwrap_or(0);
            // Word 0: ExtentCount in its low 32 bits; word 1: StartingVcn.
            let count = (at(0) & u64::from(u32::MAX)) as usize;
            let mut vcn = at(1) as i64;
            for i in 0..count.min(RP_EXTENTS_PER_CALL) {
                let nv = at(RP_HEADER_WORDS + RP_WORDS_PER_EXTENT * i) as i64;
                let lcn = at(RP_HEADER_WORDS + RP_WORDS_PER_EXTENT * i + 1) as i64;
                extents.push(Extent {
                    vcn: vcn as u64,
                    lcn: (lcn >= 0).then_some(lcn as u64),
                    clusters: (nv - vcn) as u64,
                });
                vcn = nv;
            }
            next_vcn = vcn;
            if !more || count == 0 {
                break;
            }
        }
        Ok(Extents {
            cluster_size: spc * bps,
            extents,
        })
    }

    fn vhd_create_fixed(&self, path: &str, size: u64) -> ApiResult<()> {
        let st = storage_type();
        let mut p = CREATE_VIRTUAL_DISK_PARAMETERS {
            Version: CREATE_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        p.Anonymous.Version1.MaximumSize = size;
        p.Anonymous.Version1.BlockSizeInBytes = 0;
        p.Anonymous.Version1.SectorSizeInBytes = VHD_SECTOR;
        let mut h = HANDLE::default();
        // SAFETY: all pointers are to live locals; synchronous (no OVERLAPPED).
        let r = unsafe {
            CreateVirtualDisk(
                &st,
                &wide(path),
                VIRTUAL_DISK_ACCESS_ALL,
                None,
                CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION,
                0,
                &p,
                None,
                &mut h,
            )
        };
        if r != ERROR_SUCCESS {
            return Err(w32("CreateVirtualDisk", r));
        }
        drop(Owned(h));
        Ok(())
    }

    fn vhd_attach(&self, path: &str, read_only: bool) -> ApiResult<String> {
        let h = open_vhd(path)?;
        let p = ATTACH_VIRTUAL_DISK_PARAMETERS {
            Version: ATTACH_VIRTUAL_DISK_VERSION_1,
            ..Default::default()
        };
        let mut flags =
            ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER | ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME;
        if read_only {
            flags |= ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY;
        }
        // SAFETY: `h` is an open virtual disk; `p` a live parameter block.
        let r = unsafe { AttachVirtualDisk(h.0, None, flags, 0, Some(&p), None) };
        if r != ERROR_SUCCESS {
            return Err(w32("AttachVirtualDisk", r));
        }
        let mut buf = [0u16; MAX_PATH as usize];
        let mut len = (buf.len() * size_of::<u16>()) as u32;
        // SAFETY: `buf` is writable for `len` bytes.
        let r = unsafe { GetVirtualDiskPhysicalPath(h.0, &mut len, PWSTR(buf.as_mut_ptr())) };
        if r != ERROR_SUCCESS {
            return Err(w32("GetVirtualDiskPhysicalPath", r));
        }
        Ok(from_wide(&buf))
    }

    fn vhd_detach(&self, path: &str) -> ApiResult<()> {
        let h = open_vhd(path)?;
        // SAFETY: `h` is an open virtual disk.
        let r = unsafe { DetachVirtualDisk(h.0, DETACH_VIRTUAL_DISK_FLAG_NONE, 0) };
        if r != ERROR_SUCCESS {
            return Err(w32("DetachVirtualDisk", r));
        }
        Ok(())
    }

    fn volumes(&self) -> ApiResult<Vec<Volume>> {
        let mut name = [0u16; VOLUME_NAME_BUF];
        // SAFETY: `name` is writable for its length.
        let find =
            unsafe { FindFirstVolumeW(&mut name) }.map_err(|e| win_err("FindFirstVolumeW", e))?;
        let mut out = vec![self.volume(&from_wide(&name))];
        loop {
            // SAFETY: `find` is the open search handle.
            if unsafe { FindNextVolumeW(find, &mut name) }.is_err() {
                break;
            }
            out.push(self.volume(&from_wide(&name)));
        }
        // SAFETY: closes the search handle once.
        let _ = unsafe { FindVolumeClose(find) };
        let _ = ERROR_NO_MORE_ITEMS;
        Ok(out)
    }

    fn volume_for_path(&self, path: &str) -> ApiResult<Volume> {
        let mut root = [0u16; LONG_PATH_BUF];
        // SAFETY: `root` is writable for its length.
        unsafe { GetVolumePathNameW(&wide(path), &mut root) }
            .map_err(|e| win_err("GetVolumePathNameW", e))?;
        let mut name = [0u16; VOLUME_NAME_BUF];
        // SAFETY: `name` is writable for its length.
        unsafe { GetVolumeNameForVolumeMountPointW(PCWSTR(root.as_ptr()), &mut name) }
            .map_err(|e| win_err("GetVolumeNameForVolumeMountPointW", e))?;
        Ok(self.volume(&from_wide(&name)))
    }

    fn read_disk(&self, disk_number: u32, offset: u64, len: usize) -> ApiResult<Vec<u8>> {
        let path = format!("\\\\.\\PhysicalDrive{disk_number}");
        let f = open_device(&path)?;
        // Raw disk reads must be sector-aligned: read the covering span.
        const S: u64 = RAW_READ_ALIGN;
        let start = offset / S * S;
        let end = (offset + len as u64).div_ceil(S) * S;
        let mut v = vec![0u8; (end - start) as usize];
        let mut done = 0usize;
        while done < v.len() {
            let n = f
                .seek_read(v.get_mut(done..).unwrap_or(&mut []), start + done as u64)
                .map_err(|e| io_err("ReadFile", &path, e))?;
            if n == 0 {
                return Err(ApiError::new(
                    ErrorKind::InvalidData,
                    "ReadFile",
                    "past the end of the disk",
                ));
            }
            done += n;
        }
        let a = (offset - start) as usize;
        Ok(v.get(a..a + len).unwrap_or(&[]).to_vec())
    }

    fn bitlocker(&self, drive: &str) -> ApiResult<Option<BitLocker>> {
        wmi::bitlocker(drive)
    }

    fn bitlocker_recovery_passwords(&self, drive: &str) -> ApiResult<Vec<Zeroizing<String>>> {
        wmi::recovery_passwords(drive)
    }

    fn smbios(&self) -> ApiResult<Vec<u8>> {
        // The raw SMBIOS provider has one table, ID 0.
        const RSMB_TABLE_ID: u32 = 0;
        // SAFETY: a size query with no buffer.
        let n = unsafe { GetSystemFirmwareTable(RSMB, RSMB_TABLE_ID, None) };
        if n == 0 {
            return Err(w32("GetSystemFirmwareTable", last_error()));
        }
        let mut b = vec![0u8; n as usize];
        // SAFETY: `b` is writable for its length.
        let m = unsafe { GetSystemFirmwareTable(RSMB, RSMB_TABLE_ID, Some(&mut b)) };
        if m == 0 || m > n {
            return Err(w32("GetSystemFirmwareTable", last_error()));
        }
        b.truncate(m as usize);
        Ok(b)
    }

    fn cpuid(&self, leaf: u32, subleaf: u32) -> Option<[u32; 4]> {
        #[cfg(target_arch = "x86_64")]
        {
            // SAFETY: CPUID exists on every x86_64 processor (the call is
            // safe on newer toolchains; `unsafe` keeps the MSRV building).
            #[allow(unused_unsafe)]
            let r = unsafe { core::arch::x86_64::__cpuid_count(leaf, subleaf) };
            Some([r.eax, r.ebx, r.ecx, r.edx])
        }
        #[cfg(not(target_arch = "x86_64"))]
        {
            let _ = (leaf, subleaf);
            None
        }
    }

    fn pnp_devices(&self) -> ApiResult<Vec<PnpDevice>> {
        devices::pnp_devices()
    }

    fn disks(&self) -> ApiResult<Vec<DiskDevice>> {
        let mut out = Vec::new();
        for n in 0..MAX_PHYSICAL_DRIVES {
            let Ok(f) = open_query(&format!("\\\\.\\PhysicalDrive{n}")) else {
                continue;
            };
            let q = STORAGE_PROPERTY_QUERY {
                PropertyId: StorageDeviceProperty,
                QueryType: PropertyStandardQuery,
                ..Default::default()
            };
            let mut buf = vec![0u8; DEVICE_DESCRIPTOR_BUF];
            let mut ret = 0u32;
            // SAFETY: `q` and `buf` are live and sized as passed.
            let ok = unsafe {
                DeviceIoControl(
                    HANDLE(f.as_raw_handle()),
                    IOCTL_STORAGE_QUERY_PROPERTY,
                    Some(&q as *const _ as *const c_void),
                    std::mem::size_of::<STORAGE_PROPERTY_QUERY>() as u32,
                    Some(buf.as_mut_ptr() as *mut c_void),
                    buf.len() as u32,
                    Some(&mut ret),
                    None,
                )
            }
            .is_ok();
            if !ok || (ret as usize) < std::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
                continue;
            }
            // SAFETY: the buffer holds at least one descriptor (checked above);
            // read unaligned since `buf` is a byte vector.
            let d: STORAGE_DEVICE_DESCRIPTOR =
                unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const _) };
            let cstr = |off: u32| -> String {
                let o = off as usize;
                if o == 0 || o >= buf.len() {
                    return String::new();
                }
                let s = buf.get(o..).unwrap_or(&[]);
                let e = s.iter().position(|&c| c == 0).unwrap_or(s.len());
                String::from_utf8_lossy(s.get(..e).unwrap_or(&[]))
                    .trim()
                    .to_string()
            };
            let model = [cstr(d.VendorIdOffset), cstr(d.ProductIdOffset)]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect::<Vec<_>>()
                .join(" ");
            let size = ioctl::<(), GET_LENGTH_INFORMATION>(&f, IOCTL_DISK_GET_LENGTH_INFO, None)
                .map(|l| l.Length as u64)
                .unwrap_or(0);
            out.push(DiskDevice {
                number: n,
                bus: bus_name(d.BusType).into(),
                model,
                size,
            });
        }
        Ok(out)
    }

    fn tpm_present(&self) -> bool {
        let mut info = TPM_DEVICE_INFO::default();
        // SAFETY: `info` is exactly the size passed.
        let r = unsafe {
            Tbsi_GetDeviceInfo(
                std::mem::size_of::<TPM_DEVICE_INFO>() as u32,
                &mut info as *mut _ as *mut c_void,
            )
        };
        r == TBS_SUCCESS && info.tpmVersion == TPM_VERSION_20
    }

    fn tpm_submit(&self, cmd: &[u8]) -> ApiResult<Vec<u8>> {
        let ctx = Tbs::open()?;
        let mut out = vec![0u8; TPM_RESPONSE_BUF];
        let mut len = out.len() as u32;
        // SAFETY: `out` is writable for `len` bytes.
        let r = unsafe {
            Tbsip_Submit_Command(
                ctx.0,
                TBS_COMMAND_LOCALITY_ZERO,
                TBS_COMMAND_PRIORITY_NORMAL,
                cmd,
                out.as_mut_ptr(),
                &mut len,
            )
        };
        if r != TBS_SUCCESS {
            return Err(ApiError::new(
                ErrorKind::Other,
                "Tbsip_Submit_Command",
                "TBS refused the command",
            )
            .with_code(i64::from(r)));
        }
        out.truncate(len as usize);
        Ok(out)
    }

    fn tcg_log(&self) -> ApiResult<Vec<u8>> {
        let ctx = Tbs::open()?;
        let mut len = 0u32;
        // SAFETY: a size query.
        let _ = unsafe { Tbsi_Get_TCG_Log(ctx.0, None, &mut len) };
        if len == 0 || len as usize > paguro_core::tcglog::MAX_LOG {
            return Err(ApiError::new(
                ErrorKind::Unsupported,
                "Tbsi_Get_TCG_Log",
                "no log, or too large",
            ));
        }
        let mut b = vec![0u8; len as usize];
        // SAFETY: `b` is writable for `len` bytes.
        let r = unsafe { Tbsi_Get_TCG_Log(ctx.0, Some(b.as_mut_ptr()), &mut len) };
        if r != TBS_SUCCESS {
            return Err(
                ApiError::new(ErrorKind::Other, "Tbsi_Get_TCG_Log", "failed")
                    .with_code(i64::from(r)),
            );
        }
        b.truncate(len as usize);
        Ok(b)
    }

    fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> ApiResult<Output> {
        let mut c = Command::new(program);
        c.args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = c
            .spawn()
            .map_err(|e| io_err("CreateProcessW", program, e))?;
        if let (Some(data), Some(mut si)) = (stdin, child.stdin.take()) {
            si.write_all(data)
                .map_err(|e| io_err("WriteFile", program, e))?;
        }
        let o = child
            .wait_with_output()
            .map_err(|e| io_err("WaitForSingleObject", program, e))?;
        Ok(Output {
            status: o.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
        })
    }

    fn restart(&self) -> ApiResult<()> {
        // SAFETY: plain arguments; SeShutdownPrivilege was enabled at start.
        unsafe {
            InitiateSystemShutdownExW(
                PCWSTR::null(),
                PCWSTR::null(),
                0,
                false,
                true,
                SHTDN_REASON_MAJOR_OTHER | SHTDN_REASON_FLAG_PLANNED,
            )
        }
        .map_err(|e| win_err("InitiateSystemShutdownExW", e))
    }

    fn random(&self, buf: &mut [u8]) -> ApiResult<()> {
        // SAFETY: `buf` is writable for its length.
        let s = unsafe { BCryptGenRandom(None, buf, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if s.is_err() {
            return Err(ApiError::new(ErrorKind::Other, "BCryptGenRandom", "failed")
                .with_code(i64::from(s.0)));
        }
        Ok(())
    }

    fn now_unix(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs())
    }

    fn program_data(&self) -> String {
        std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into())
    }

    fn system_drive(&self) -> String {
        std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())
    }

    fn read_secret(&self, prompt: &str) -> ApiResult<Zeroizing<String>> {
        console::read_secret(prompt)
    }

    fn read_stdin(&self, max: usize) -> ApiResult<Zeroizing<Vec<u8>>> {
        let mut v = Zeroizing::new(Vec::new());
        std::io::stdin()
            .take(max as u64 + 1)
            .read_to_end(&mut v)
            .map_err(|e| io_err("ReadFile", "stdin", e))?;
        if v.len() > max {
            return Err(ApiError::new(
                ErrorKind::InvalidData,
                "ReadFile",
                "stdin too large",
            ));
        }
        Ok(v)
    }
}

/// A TBS context, closed on drop.
struct Tbs(*mut c_void);

impl Tbs {
    fn open() -> ApiResult<Tbs> {
        let mut p = TBS_CONTEXT_PARAMS2 {
            version: TBS_CONTEXT_VERSION_TWO,
            ..Default::default()
        };
        p.Anonymous.asUINT32 = TBS_INCLUDE_TPM20;
        let mut h: *mut c_void = std::ptr::null_mut();
        // SAFETY: `p` is a TBS_CONTEXT_PARAMS2, which TBS accepts through
        // the version-one pointer type; `h` receives the context.
        let r = unsafe { Tbsi_Context_Create(&p as *const _ as *const TBS_CONTEXT_PARAMS, &mut h) };
        if r != TBS_SUCCESS {
            return Err(ApiError::new(
                ErrorKind::Unsupported,
                "Tbsi_Context_Create",
                "no TPM 2.0 through TBS",
            )
            .with_code(i64::from(r)));
        }
        Ok(Tbs(h))
    }
}

impl Drop for Tbs {
    fn drop(&mut self) {
        // SAFETY: closes the context once.
        let _ = unsafe { Tbsip_Context_Close(self.0) };
    }
}
