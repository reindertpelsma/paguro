//! Every operating-system touchpoint of the Windows tool, as one trait.
//!
//! Command logic is written against [`WinApi`] only, so all of it runs — and
//! is tested — on any host with [`crate::mock::MockApi`]. The real
//! implementation ([`crate::real::RealApi`], `cfg(windows)`) is a thin
//! translation to Win32 and holds no decisions.
//!
//! Rules for implementations:
//! - no method panics; every failure is an [`ApiError`];
//! - paths are Windows paths (`C:\x`, `\\?\Volume{…}\x`); the mock treats
//!   them case-insensitively, as NTFS and FAT do;
//! - secrets come back in [`Zeroizing`] containers and are never logged.

use std::fmt;

use paguro_core::guid::Guid;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorKind {
    NotFound,
    AccessDenied,
    /// Not available on this machine (no TPM, BIOS firmware, no WSL…).
    Unsupported,
    /// The OS returned data paguro refuses to interpret.
    InvalidData,
    Other,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    pub kind: ErrorKind,
    /// The operation, e.g. `"SetFirmwareEnvironmentVariableExW"`.
    pub op: &'static str,
    /// The Win32/HRESULT/process code, when there is one.
    pub code: Option<i64>,
    pub message: String,
}

impl ApiError {
    pub fn new(kind: ErrorKind, op: &'static str, message: impl Into<String>) -> Self {
        ApiError {
            kind,
            op,
            code: None,
            message: message.into(),
        }
    }
    pub fn not_found(op: &'static str, what: impl Into<String>) -> Self {
        Self::new(ErrorKind::NotFound, op, what)
    }
    pub fn unsupported(op: &'static str, what: impl Into<String>) -> Self {
        Self::new(ErrorKind::Unsupported, op, what)
    }
    pub fn with_code(mut self, code: i64) -> Self {
        self.code = Some(code);
        self
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.op, self.message)?;
        if let Some(c) = self.code {
            write!(f, " (0x{c:08x})")?;
        }
        Ok(())
    }
}

impl std::error::Error for ApiError {}

pub type ApiResult<T> = Result<T, ApiError>;

/// UEFI variable attributes (UEFI 2.10 §8.2).
pub mod attr {
    pub const NV: u32 = 0x1;
    pub const BS: u32 = 0x2;
    pub const RT: u32 = 0x4;
    pub const NV_BS_RT: u32 = NV | BS | RT;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FwVar {
    pub data: Vec<u8>,
    pub attributes: u32,
}

/// `FILE_ATTRIBUTE_*` bits the tool checks (winnt.h).
pub mod fattr {
    pub const READONLY: u32 = 0x1;
    pub const ARCHIVE: u32 = 0x20;
    pub const HIDDEN: u32 = 0x2;
    pub const SYSTEM: u32 = 0x4;
    pub const DIRECTORY: u32 = 0x10;
    pub const SPARSE: u32 = 0x200;
    pub const COMPRESSED: u32 = 0x800;
    pub const ENCRYPTED: u32 = 0x4000;
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileFacts {
    pub len: u64,
    /// Bytes allocated on disk.
    pub allocated: u64,
    pub attributes: u32,
    /// `FILE_ID_128` (NTFS: MFT record number ‖ sequence in the low 8 bytes).
    #[serde(serialize_with = "crate::out::hex")]
    pub file_id: [u8; 16],
    pub volume_serial: u64,
}

/// One run of `FSCTL_GET_RETRIEVAL_POINTERS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Extent {
    pub vcn: u64,
    /// `None`: a hole (sparse) or a compression unit without clusters.
    pub lcn: Option<u64>,
    pub clusters: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Extents {
    pub cluster_size: u32,
    pub extents: Vec<Extent>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub len: u64,
}

/// Where a volume lives on a physical disk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiskLocation {
    pub disk_number: u32,
    pub partition_number: u32,
    pub offset: u64,
    pub length: u64,
    /// GPT partition type and unique GUID; `None` on MBR disks.
    #[serde(serialize_with = "crate::out::opt_guid")]
    pub gpt_type: Option<Guid>,
    #[serde(serialize_with = "crate::out::opt_guid")]
    pub partition_guid: Option<Guid>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Volume {
    /// `\\?\Volume{…}\`
    pub guid_path: String,
    /// Drive letters and folders, each with a trailing `\` (`C:\`).
    pub mount_points: Vec<String>,
    pub filesystem: String,
    pub label: String,
    pub size: u64,
    pub free: u64,
    pub location: Option<DiskLocation>,
}

impl Volume {
    /// The drive letter mount point without its backslash (`C:`), if any.
    pub fn drive(&self) -> Option<&str> {
        self.mount_points
            .iter()
            .find(|m| m.len() == 3 && m.ends_with(":\\"))
            .and_then(|m| m.get(..2))
    }
    pub fn is_esp(&self) -> bool {
        self.location
            .as_ref()
            .and_then(|l| l.gpt_type)
            .is_some_and(|t| t == paguro_core::guid::GPT_ESP)
    }
    pub fn partition_guid(&self) -> Option<Guid> {
        self.location.as_ref().and_then(|l| l.partition_guid)
    }
}

/// `Win32_EncryptableVolume`, as far as paguro reads it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BitLocker {
    /// `GetProtectionStatus`: 0 off, 1 on, 2 unknown (locked).
    pub protection_status: u32,
    /// `GetConversionStatus`: 0 fully decrypted, 1 fully encrypted,
    /// 2 encrypting, 3 decrypting, 4 encryption paused, 5 decryption paused.
    pub conversion_status: u32,
    pub encryption_percentage: u32,
    /// `GetEncryptionMethod`.
    pub encryption_method: u32,
    /// `GetKeyProtectors` types (1 TPM, 3 numerical password, 8 password…).
    pub protector_types: Vec<u32>,
}

impl BitLocker {
    pub fn is_encrypted(&self) -> bool {
        self.conversion_status != 0
    }
}

/// A present PnP device node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PnpDevice {
    pub instance_id: String,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DiskDevice {
    pub number: u32,
    /// `STORAGE_BUS_TYPE` as a Linux-ish name: nvme, sata, usb, scsi, sd, virtual…
    pub bus: String,
    pub model: String,
    pub size: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub status: i32,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn ok(&self) -> bool {
        self.status == 0
    }
}

/// Every OS call the tool makes.
pub trait WinApi {
    // -- identity -----------------------------------------------------------
    fn is_elevated(&self) -> bool;
    /// UEFI (not legacy BIOS) firmware.
    fn firmware_is_uefi(&self) -> bool;
    /// `x64` or `aa64` (INTERFACES.md §0.1).
    fn arch(&self) -> &'static str;

    // -- firmware variables (SE_SYSTEM_ENVIRONMENT_NAME) --------------------
    /// `Ok(None)`: absent (or not visible to the OS, like a BS-only variable).
    fn fw_get(&self, name: &str, vendor: &Guid) -> ApiResult<Option<FwVar>>;
    fn fw_set(&self, name: &str, vendor: &Guid, data: &[u8], attributes: u32) -> ApiResult<()>;
    /// Deleting an absent variable is not an error.
    fn fw_delete(&self, name: &str, vendor: &Guid) -> ApiResult<()>;

    // -- files --------------------------------------------------------------
    /// The whole file, `Ok(None)` when absent; `InvalidData` above `max`.
    fn read_file(&self, path: &str, max: usize) -> ApiResult<Option<Vec<u8>>>;
    /// `len` bytes at `offset` (short read at EOF is an error).
    fn read_file_at(&self, path: &str, offset: u64, len: usize) -> ApiResult<Vec<u8>>;
    /// Create or truncate, write, flush to disk.
    fn write_file(&self, path: &str, data: &[u8]) -> ApiResult<()>;
    /// Replace `to` if it exists, write-through.
    fn rename(&self, from: &str, to: &str) -> ApiResult<()>;
    /// `Ok(false)`: was not there.
    fn remove_file(&self, path: &str) -> ApiResult<bool>;
    fn create_dir_all(&self, path: &str) -> ApiResult<()>;
    /// Removes an empty directory; `Ok(false)`: was not there.
    fn remove_dir(&self, path: &str) -> ApiResult<bool>;
    fn list_dir(&self, path: &str) -> ApiResult<Option<Vec<DirEntry>>>;
    fn file_facts(&self, path: &str) -> ApiResult<Option<FileFacts>>;
    /// `FSCTL_GET_RETRIEVAL_POINTERS` over the whole file.
    fn retrieval_pointers(&self, path: &str) -> ApiResult<Extents>;

    // -- disks and volumes --------------------------------------------------
    /// A fixed VHD, fully allocated (`CREATE_VIRTUAL_DISK_FLAG_FULL_PHYSICAL_ALLOCATION`).
    fn vhd_create_fixed(&self, path: &str, size: u64) -> ApiResult<()>;
    /// Attach without a drive letter; returns `\\.\PhysicalDriveN`.
    fn vhd_attach(&self, path: &str, read_only: bool) -> ApiResult<String>;
    fn vhd_detach(&self, path: &str) -> ApiResult<()>;
    fn volumes(&self) -> ApiResult<Vec<Volume>>;
    /// The volume holding `path`.
    fn volume_for_path(&self, path: &str) -> ApiResult<Volume>;
    /// Raw read from `\\.\PhysicalDriveN` (below BitLocker).
    fn read_disk(&self, disk_number: u32, offset: u64, len: usize) -> ApiResult<Vec<u8>>;
    /// `Ok(None)`: the volume is not encryptable / WMI class absent.
    fn bitlocker(&self, drive: &str) -> ApiResult<Option<BitLocker>>;
    /// Numerical-password protectors (`GetKeyProtectorNumericalPassword`).
    fn bitlocker_recovery_passwords(&self, drive: &str) -> ApiResult<Vec<Zeroizing<String>>>;

    // -- hardware -----------------------------------------------------------
    /// `GetSystemFirmwareTable('RSMB', 0)`.
    fn smbios(&self) -> ApiResult<Vec<u8>>;
    /// `None` where CPUID does not exist (aarch64).
    fn cpuid(&self, leaf: u32, subleaf: u32) -> Option<[u32; 4]>;
    fn pnp_devices(&self) -> ApiResult<Vec<PnpDevice>>;
    fn disks(&self) -> ApiResult<Vec<DiskDevice>>;

    // -- TPM (TBS) ----------------------------------------------------------
    fn tpm_present(&self) -> bool;
    fn tpm_submit(&self, cmd: &[u8]) -> ApiResult<Vec<u8>>;
    /// `Tbsi_Get_TCG_Log`.
    fn tcg_log(&self) -> ApiResult<Vec<u8>>;

    // -- processes ----------------------------------------------------------
    fn run(&self, program: &str, args: &[&str], stdin: Option<&[u8]>) -> ApiResult<Output>;
    /// A restart (never a shutdown: DESIGN.md §4.6).
    fn restart(&self) -> ApiResult<()>;

    // -- environment --------------------------------------------------------
    fn random(&self, buf: &mut [u8]) -> ApiResult<()>;
    fn now_unix(&self) -> u64;
    /// `%ProgramData%` (`C:\ProgramData`).
    fn program_data(&self) -> String;
    /// `%SystemDrive%` (`C:`).
    fn system_drive(&self) -> String;
    /// Prompt on the console without echo.
    fn read_secret(&self, prompt: &str) -> ApiResult<Zeroizing<String>>;
    /// Standard input, whole (for `--passphrase-stdin`), capped at `max`.
    fn read_stdin(&self, max: usize) -> ApiResult<Zeroizing<Vec<u8>>>;
}

/// `a\b` joined Windows-style.
pub fn join(base: &str, rel: &str) -> String {
    let rel = rel.trim_start_matches('\\');
    if base.ends_with('\\') {
        format!("{base}{rel}")
    } else {
        format!("{base}\\{rel}")
    }
}
