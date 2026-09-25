//! An in-memory Windows machine for testing every command on any host.
//!
//! It models what the commands depend on and nothing more: firmware
//! variables with UEFI's attribute rules (a variable without `RT` is
//! invisible to the OS), a case-insensitive filesystem whose files may be
//! huge and mostly zero, volumes and disks, BitLocker's WMI answers, a TPM
//! behind a pluggable transport, and processes with scripted results.
//!
//! Every mutating call is appended to [`MockApi::mutations`], so a test can
//! assert that `--dry-run` changed nothing.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet};

use paguro_core::guid::Guid;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::api::*;

/// A file: a length and the byte ranges ever written; everything else reads
/// as zero (so a 20 GiB VHD costs its footer).
#[derive(Clone, Debug, Default)]
pub struct MockFile {
    pub len: u64,
    segments: BTreeMap<u64, Vec<u8>>,
    pub attributes: u32,
    /// `None`: one contiguous extent is synthesised.
    pub extents: Option<Extents>,
    pub file_id: [u8; 16],
}

impl MockFile {
    pub fn new(data: &[u8]) -> Self {
        let mut f = MockFile {
            len: data.len() as u64,
            attributes: fattr::ARCHIVE,
            ..MockFile::default()
        };
        if !data.is_empty() {
            f.segments.insert(0, data.to_vec());
        }
        f
    }

    pub fn zeros(len: u64) -> Self {
        MockFile {
            len,
            attributes: fattr::ARCHIVE,
            ..MockFile::default()
        }
    }

    pub fn write_at(&mut self, offset: u64, data: &[u8]) {
        self.segments.insert(offset, data.to_vec());
        self.len = self.len.max(offset + data.len() as u64);
    }

    pub fn read_at(&self, offset: u64, len: usize) -> Option<Vec<u8>> {
        if offset.checked_add(len as u64)? > self.len {
            return None;
        }
        let mut out = vec![0u8; len];
        let end = offset + len as u64;
        for (&o, d) in &self.segments {
            let (so, se) = (o, o + d.len() as u64);
            let (a, b) = (so.max(offset), se.min(end));
            if a < b {
                let src = d.get((a - so) as usize..(b - so) as usize)?;
                out.get_mut((a - offset) as usize..(b - offset) as usize)?
                    .copy_from_slice(src);
            }
        }
        Some(out)
    }

    pub fn all(&self) -> Option<Vec<u8>> {
        self.read_at(0, usize::try_from(self.len).ok()?)
    }
}

type TpmFn = Box<dyn FnMut(&[u8]) -> ApiResult<Vec<u8>>>;
type RunFn = Box<dyn Fn(&str, &[&str]) -> Option<Output>>;

pub struct MockApi {
    pub elevated: Cell<bool>,
    pub uefi: Cell<bool>,
    pub vars: RefCell<BTreeMap<(String, [u8; 16]), FwVar>>,
    pub files: RefCell<BTreeMap<String, MockFile>>,
    pub dirs: RefCell<BTreeSet<String>>,
    pub volumes: RefCell<Vec<Volume>>,
    /// Raw disks by number, same sparse representation as files.
    pub raw_disks: RefCell<BTreeMap<u32, MockFile>>,
    pub bitlocker: RefCell<BTreeMap<String, BitLocker>>,
    pub recovery: RefCell<BTreeMap<String, Vec<String>>>,
    pub attached: RefCell<BTreeMap<String, String>>,
    pub smbios_blob: RefCell<Vec<u8>>,
    pub cpuid_leaves: RefCell<BTreeMap<(u32, u32), [u32; 4]>>,
    pub pnp: RefCell<Vec<PnpDevice>>,
    pub disk_devices: RefCell<Vec<DiskDevice>>,
    pub tpm: RefCell<Option<TpmFn>>,
    pub log: RefCell<Vec<u8>>,
    pub runner: RefCell<Option<RunFn>>,
    pub secrets: RefCell<Vec<String>>,
    pub stdin: RefCell<Vec<u8>>,
    pub now: Cell<u64>,
    rng: Cell<u64>,
    /// Every call that changed state, in order.
    pub mutations: RefCell<Vec<String>>,
    /// Every process started, as `program arg arg…`.
    pub commands: RefCell<Vec<String>>,
    pub restarted: Cell<bool>,
    pub uptime: Cell<u64>,
    /// Interactive programs started (`run_interactive`).
    pub interactive: RefCell<Vec<String>>,
}

fn key(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
}

fn parent(path: &str) -> Option<String> {
    let k = key(path);
    let k = k.trim_end_matches('\\');
    k.rfind('\\').map(|i| k.get(..i).unwrap_or("").to_string())
}

/// The C: partition GUID of [`MockApi::standard`].
pub const C_GUID: &str = "6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8";
pub const ESP_GUID: &str = "11111111-2222-3333-4444-555555555555";
pub const ESP_PATH: &str = "\\\\?\\Volume{aaaaaaaa-0000-0000-0000-000000000001}\\";
pub const C_VOLUME_PATH: &str = "\\\\?\\Volume{aaaaaaaa-0000-0000-0000-000000000002}\\";
/// Byte offset of C: on disk 0.
pub const C_OFFSET: u64 = 0x1000_0000;
/// The mock NTFS volume's cluster size.
const CLUSTER: u64 = 4096;

impl MockApi {
    pub fn empty() -> Self {
        MockApi {
            elevated: Cell::new(true),
            uefi: Cell::new(true),
            vars: RefCell::default(),
            files: RefCell::default(),
            dirs: RefCell::default(),
            volumes: RefCell::default(),
            raw_disks: RefCell::default(),
            bitlocker: RefCell::default(),
            recovery: RefCell::default(),
            attached: RefCell::default(),
            smbios_blob: RefCell::default(),
            cpuid_leaves: RefCell::default(),
            pnp: RefCell::default(),
            disk_devices: RefCell::default(),
            tpm: RefCell::new(None),
            log: RefCell::default(),
            runner: RefCell::new(None),
            secrets: RefCell::default(),
            stdin: RefCell::default(),
            now: Cell::new(1_760_000_000),
            rng: Cell::new(0),
            mutations: RefCell::default(),
            commands: RefCell::default(),
            restarted: Cell::new(false),
            uptime: Cell::new(600),
            interactive: RefCell::default(),
        }
    }

    /// A typical machine: an ESP and an NTFS C: on one GPT disk, Windows'
    /// boot entry, Secure Boot on, `C:\ProgramData` present.
    pub fn standard() -> Self {
        let m = Self::empty();
        let esp_guid = Guid::parse(ESP_GUID).unwrap_or(Guid::ZERO);
        let c_guid = Guid::parse(C_GUID).unwrap_or(Guid::ZERO);
        m.volumes.borrow_mut().extend([
            Volume {
                guid_path: ESP_PATH.into(),
                mount_points: vec![],
                filesystem: "FAT32".into(),
                label: "".into(),
                size: 100 << 20,
                free: 70 << 20,
                location: Some(DiskLocation {
                    disk_number: 0,
                    partition_number: 1,
                    offset: 1 << 20,
                    length: 100 << 20,
                    gpt_type: Some(paguro_core::guid::GPT_ESP),
                    partition_guid: Some(esp_guid),
                }),
            },
            Volume {
                guid_path: C_VOLUME_PATH.into(),
                mount_points: vec!["C:\\".into()],
                filesystem: "NTFS".into(),
                label: "Windows".into(),
                size: 500 << 30,
                free: 200 << 30,
                location: Some(DiskLocation {
                    disk_number: 0,
                    partition_number: 3,
                    offset: C_OFFSET,
                    length: 500 << 30,
                    gpt_type: Some(paguro_core::guid::GPT_BASIC_DATA),
                    partition_guid: Some(c_guid),
                }),
            },
        ]);
        m.dirs.borrow_mut().extend([
            key(ESP_PATH).trim_end_matches('\\').to_string(),
            key(&join(ESP_PATH, "EFI")),
            key(&join(ESP_PATH, "EFI\\Microsoft\\Boot")),
            "c:".into(),
            "c:\\programdata".into(),
        ]);
        m.set_var_raw(
            "SecureBoot",
            &paguro_core::guid::EFI_GLOBAL_VARIABLE,
            &[1],
            attr::BS | attr::RT,
        );
        m.set_var_raw(
            "SetupMode",
            &paguro_core::guid::EFI_GLOBAL_VARIABLE,
            &[0],
            attr::BS | attr::RT,
        );
        let mut b = [0u8; 256];
        let n = paguro_core::bootstrap::write_load_option(
            paguro_core::bootstrap::LOAD_OPTION_ACTIVE,
            "Windows Boot Manager",
            "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            &[],
            &mut b,
        )
        .unwrap_or(0);
        m.set_var_raw(
            "Boot0000",
            &paguro_core::guid::EFI_GLOBAL_VARIABLE,
            b.get(..n).unwrap_or(&[]),
            attr::NV_BS_RT,
        );
        m.set_var_raw(
            "BootOrder",
            &paguro_core::guid::EFI_GLOBAL_VARIABLE,
            &[0, 0],
            attr::NV_BS_RT,
        );
        m.disk_devices.borrow_mut().push(DiskDevice {
            number: 0,
            bus: "nvme".into(),
            model: "Mock NVMe 1TB".into(),
            size: 1_000_204_886_016,
        });
        m
    }

    /// [`MockApi::standard`] plus what a machine with paguro installed has:
    /// BitLocker (TPM + recovery password) on C:, a TPM, the ESP files, one
    /// image and its `paguro.ini` entry, WSL2 with an Ubuntu distribution,
    /// Fast Startup on. The service's `--mock` mode serves it, and the API
    /// fixtures and GUI tests are made from it.
    pub fn demo() -> Self {
        let m = Self::standard();
        m.bitlocker.borrow_mut().insert(
            "c:".into(),
            BitLocker {
                protection_status: 1,
                conversion_status: 1,
                encryption_percentage: 100,
                encryption_method: 7,
                protector_types: vec![protector::TPM, protector::NUMERICAL_PASSWORD],
                encryption_flags: Some(0),
            },
        );
        // A TPM that answers nothing: present, but every command fails.
        m.set_tpm(|_| Err(ApiError::unsupported("Tbsip_Submit_Command", "mock TPM")));
        let vhd = "C:\\paguro\\debian.vhd";
        let size: u64 = 32 << 30;
        let mut f = MockFile::zeros(size + 512);
        f.write_at(size, &fixed_vhd_footer(size));
        m.put_mock_file(vhd, f);
        m.set_runner(|prog, args| {
            let line = std::iter::once(prog)
                .chain(args.iter().copied())
                .collect::<Vec<_>>()
                .join(" ");
            let out = |status: i32, stdout: &str| {
                Some(Output {
                    status,
                    stdout: stdout.into(),
                    stderr: String::new(),
                })
            };
            if line == "wsl.exe --list --verbose" {
                out(0, "  NAME      STATE           VERSION\r\n* Ubuntu    Stopped         2\r\n")
            } else if line.starts_with("reg.exe query") {
                out(0, "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power\r\n    HiberbootEnabled    REG_DWORD    0x1\r\n")
            } else if line == "sc.exe query paguro" {
                out(1060, "")
            } else {
                out(0, "")
            }
        });
        let ctx = crate::ctx::Ctx::new(&m);
        for (f, tag) in [
            ("shimx64.efi", "shim"),
            ("mmx64.efi", "mm"),
            ("paguro.efi", "loader"),
        ] {
            m.put_file(
                &format!("C:\\paguro\\in\\{f}"),
                format!("MZ{tag}").as_bytes(),
            );
        }
        let _ = crate::cmd::esp::install(
            &ctx,
            "C:\\paguro\\in\\shimx64.efi",
            "C:\\paguro\\in\\mmx64.efi",
            "C:\\paguro\\in\\paguro.efi",
        );
        let _ = crate::cmd::config::set(
            &ctx,
            &crate::cmd::config::SetArgs {
                entry: Some("debian".into()),
                root: Some(vhd.into()),
                ..Default::default()
            },
        );
        m.mutations.borrow_mut().clear();
        m.commands.borrow_mut().clear();
        m
    }

    fn mutated(&self, s: String) {
        self.mutations.borrow_mut().push(s);
    }

    /// Set a variable as firmware would (no attribute rules, no log).
    pub fn set_var_raw(&self, name: &str, vendor: &Guid, data: &[u8], attributes: u32) {
        self.vars.borrow_mut().insert(
            (name.to_string(), vendor.0),
            FwVar {
                data: data.to_vec(),
                attributes,
            },
        );
    }

    pub fn var(&self, name: &str, vendor: &Guid) -> Option<Vec<u8>> {
        self.vars
            .borrow()
            .get(&(name.to_string(), vendor.0))
            .map(|v| v.data.clone())
    }

    pub fn put_file(&self, path: &str, data: &[u8]) {
        if let Some(p) = parent(path) {
            self.mkdirs(&p);
        }
        self.files
            .borrow_mut()
            .insert(key(path), MockFile::new(data));
    }

    pub fn put_mock_file(&self, path: &str, f: MockFile) {
        if let Some(p) = parent(path) {
            self.mkdirs(&p);
        }
        self.files.borrow_mut().insert(key(path), f);
    }

    pub fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.files.borrow().get(&key(path)).and_then(|f| f.all())
    }

    pub fn exists(&self, path: &str) -> bool {
        self.files.borrow().contains_key(&key(path))
    }

    fn mkdirs(&self, path: &str) {
        let mut p = Some(key(path).trim_end_matches('\\').to_string());
        while let Some(x) = p {
            if x.is_empty() {
                break;
            }
            p = parent(&x);
            self.dirs.borrow_mut().insert(x);
        }
    }

    pub fn push_secret(&self, s: &str) {
        self.secrets.borrow_mut().insert(0, s.to_string());
    }

    pub fn set_runner(&self, f: impl Fn(&str, &[&str]) -> Option<Output> + 'static) {
        *self.runner.borrow_mut() = Some(Box::new(f));
    }

    pub fn set_tpm(&self, f: impl FnMut(&[u8]) -> ApiResult<Vec<u8>> + 'static) {
        *self.tpm.borrow_mut() = Some(Box::new(f));
    }
}

impl WinApi for MockApi {
    fn is_elevated(&self) -> bool {
        self.elevated.get()
    }
    fn firmware_is_uefi(&self) -> bool {
        self.uefi.get()
    }
    fn arch(&self) -> &'static str {
        "x64"
    }

    fn fw_get(&self, name: &str, vendor: &Guid) -> ApiResult<Option<FwVar>> {
        if !self.uefi.get() {
            return Err(ApiError::unsupported(
                "GetFirmwareEnvironmentVariableExW",
                "not UEFI",
            ));
        }
        Ok(self
            .vars
            .borrow()
            .get(&(name.to_string(), vendor.0))
            .filter(|v| v.attributes & attr::RT != 0)
            .cloned())
    }

    fn fw_set(&self, name: &str, vendor: &Guid, data: &[u8], attributes: u32) -> ApiResult<()> {
        if !self.elevated.get() {
            return Err(ApiError::new(
                ErrorKind::AccessDenied,
                "SetFirmwareEnvironmentVariableExW",
                "privilege not held",
            ));
        }
        if attributes & attr::RT == 0 || attributes & attr::BS == 0 {
            return Err(ApiError::new(
                ErrorKind::Other,
                "SetFirmwareEnvironmentVariableExW",
                "invalid attributes",
            ));
        }
        let k = (name.to_string(), vendor.0);
        if let Some(old) = self.vars.borrow().get(&k) {
            if old.attributes & attr::RT == 0 {
                return Err(ApiError::new(
                    ErrorKind::AccessDenied,
                    "SetFirmwareEnvironmentVariableExW",
                    "boot-services-only variable",
                ));
            }
        }
        self.mutated(format!("fw_set {name} {}", data.len()));
        self.vars.borrow_mut().insert(
            k,
            FwVar {
                data: data.to_vec(),
                attributes,
            },
        );
        Ok(())
    }

    fn fw_delete(&self, name: &str, vendor: &Guid) -> ApiResult<()> {
        if !self.elevated.get() {
            return Err(ApiError::new(
                ErrorKind::AccessDenied,
                "SetFirmwareEnvironmentVariableExW",
                "privilege not held",
            ));
        }
        let k = (name.to_string(), vendor.0);
        let visible = self
            .vars
            .borrow()
            .get(&k)
            .map(|v| v.attributes & attr::RT != 0);
        match visible {
            None => Ok(()),
            Some(false) => Err(ApiError::not_found(
                "SetFirmwareEnvironmentVariableExW",
                name,
            )),
            Some(true) => {
                self.mutated(format!("fw_delete {name}"));
                self.vars.borrow_mut().remove(&k);
                Ok(())
            }
        }
    }

    fn read_file(&self, path: &str, max: usize) -> ApiResult<Option<Vec<u8>>> {
        let files = self.files.borrow();
        let Some(f) = files.get(&key(path)) else {
            return Ok(None);
        };
        if f.len > max as u64 {
            return Err(ApiError::new(
                ErrorKind::InvalidData,
                "ReadFile",
                format!("{path}: larger than {max} bytes"),
            ));
        }
        f.all()
            .map(Some)
            .ok_or_else(|| ApiError::new(ErrorKind::Other, "ReadFile", path))
    }

    fn read_file_at(&self, path: &str, offset: u64, len: usize) -> ApiResult<Vec<u8>> {
        let files = self.files.borrow();
        let f = files
            .get(&key(path))
            .ok_or_else(|| ApiError::not_found("ReadFile", path))?;
        f.read_at(offset, len)
            .ok_or_else(|| ApiError::new(ErrorKind::InvalidData, "ReadFile", "short read"))
    }

    fn write_file(&self, path: &str, data: &[u8]) -> ApiResult<()> {
        let p = parent(path).unwrap_or_default();
        if !self.dirs.borrow().contains(&p) {
            return Err(ApiError::not_found(
                "CreateFileW",
                format!("{path}: no parent directory"),
            ));
        }
        self.mutated(format!("write {} {}", key(path), data.len()));
        self.files
            .borrow_mut()
            .insert(key(path), MockFile::new(data));
        Ok(())
    }

    fn rename(&self, from: &str, to: &str) -> ApiResult<()> {
        let f = self
            .files
            .borrow_mut()
            .remove(&key(from))
            .ok_or_else(|| ApiError::not_found("MoveFileExW", from))?;
        self.mutated(format!("rename {} {}", key(from), key(to)));
        self.files.borrow_mut().insert(key(to), f);
        Ok(())
    }

    fn remove_file(&self, path: &str) -> ApiResult<bool> {
        let had = self.files.borrow_mut().remove(&key(path)).is_some();
        if had {
            self.mutated(format!("remove {}", key(path)));
        }
        Ok(had)
    }

    fn create_dir_all(&self, path: &str) -> ApiResult<()> {
        if !self.dirs.borrow().contains(&key(path)) {
            self.mutated(format!("mkdir {}", key(path)));
            self.mkdirs(path);
        }
        Ok(())
    }

    fn remove_dir(&self, path: &str) -> ApiResult<bool> {
        let k = key(path);
        let prefix = format!("{k}\\");
        if self.files.borrow().keys().any(|f| f.starts_with(&prefix))
            || self.dirs.borrow().iter().any(|d| d.starts_with(&prefix))
        {
            return Err(ApiError::new(
                ErrorKind::Other,
                "RemoveDirectoryW",
                format!("{path}: not empty"),
            ));
        }
        let had = self.dirs.borrow_mut().remove(&k);
        if had {
            self.mutated(format!("rmdir {k}"));
        }
        Ok(had)
    }

    fn list_dir(&self, path: &str) -> ApiResult<Option<Vec<DirEntry>>> {
        let k = key(path);
        let k = k.trim_end_matches('\\').to_string();
        if !self.dirs.borrow().contains(&k) {
            return Ok(None);
        }
        let prefix = format!("{k}\\");
        let mut out = Vec::new();
        for d in self.dirs.borrow().iter() {
            if let Some(rest) = d.strip_prefix(&prefix) {
                if !rest.is_empty() && !rest.contains('\\') {
                    out.push(DirEntry {
                        name: rest.to_string(),
                        is_dir: true,
                        len: 0,
                    });
                }
            }
        }
        for (f, mf) in self.files.borrow().iter() {
            if let Some(rest) = f.strip_prefix(&prefix) {
                if !rest.contains('\\') {
                    out.push(DirEntry {
                        name: rest.to_string(),
                        is_dir: false,
                        len: mf.len,
                    });
                }
            }
        }
        Ok(Some(out))
    }

    fn file_facts(&self, path: &str) -> ApiResult<Option<FileFacts>> {
        let files = self.files.borrow();
        Ok(files.get(&key(path)).map(|f| {
            let sparse = f.attributes & fattr::SPARSE != 0;
            FileFacts {
                len: f.len,
                allocated: if sparse {
                    0
                } else {
                    f.len.div_ceil(CLUSTER) * CLUSTER
                },
                attributes: f.attributes,
                file_id: f.file_id,
                volume_serial: 0x1234_5678,
            }
        }))
    }

    fn retrieval_pointers(&self, path: &str) -> ApiResult<Extents> {
        let files = self.files.borrow();
        let f = files
            .get(&key(path))
            .ok_or_else(|| ApiError::not_found("FSCTL_GET_RETRIEVAL_POINTERS", path))?;
        if let Some(e) = &f.extents {
            return Ok(e.clone());
        }
        let clusters = f.len.div_ceil(CLUSTER);
        let extents = if clusters == 0 {
            vec![]
        } else if f.attributes & fattr::SPARSE != 0 {
            vec![Extent {
                vcn: 0,
                lcn: None,
                clusters,
            }]
        } else {
            vec![Extent {
                vcn: 0,
                lcn: Some(0x10_0000),
                clusters,
            }]
        };
        Ok(Extents {
            cluster_size: CLUSTER as u32,
            extents,
        })
    }

    fn vhd_create_fixed(&self, path: &str, size: u64) -> ApiResult<()> {
        if self.exists(path) {
            return Err(
                ApiError::new(ErrorKind::Other, "CreateVirtualDisk", "file exists").with_code(80),
            );
        }
        let p = parent(path).unwrap_or_default();
        if !self.dirs.borrow().contains(&p) {
            return Err(ApiError::not_found("CreateVirtualDisk", "path not found"));
        }
        self.mutated(format!("vhd_create {} {size}", key(path)));
        let mut f = MockFile::zeros(size + paguro_core::vhd::FOOTER_LEN);
        f.write_at(size, &fixed_vhd_footer(size));
        self.files.borrow_mut().insert(key(path), f);
        Ok(())
    }

    fn vhd_attach(&self, path: &str, _read_only: bool) -> ApiResult<String> {
        if !self.exists(path) {
            return Err(ApiError::not_found("AttachVirtualDisk", path));
        }
        let n = self.attached.borrow().len() + 1;
        let dev = format!("\\\\.\\PhysicalDrive{n}");
        self.mutated(format!("vhd_attach {}", key(path)));
        self.attached.borrow_mut().insert(key(path), dev.clone());
        Ok(dev)
    }

    fn vhd_detach(&self, path: &str) -> ApiResult<()> {
        self.mutated(format!("vhd_detach {}", key(path)));
        self.attached
            .borrow_mut()
            .remove(&key(path))
            .map(|_| ())
            .ok_or_else(|| ApiError::not_found("DetachVirtualDisk", path))
    }

    fn volumes(&self) -> ApiResult<Vec<Volume>> {
        Ok(self.volumes.borrow().clone())
    }

    fn volume_for_path(&self, path: &str) -> ApiResult<Volume> {
        let k = key(path);
        self.volumes
            .borrow()
            .iter()
            .find(|v| {
                k.starts_with(&key(&v.guid_path))
                    || v.mount_points.iter().any(|m| k.starts_with(&key(m)))
            })
            .cloned()
            .ok_or_else(|| ApiError::not_found("GetVolumePathNameW", path))
    }

    fn read_disk(&self, disk_number: u32, offset: u64, len: usize) -> ApiResult<Vec<u8>> {
        let disks = self.raw_disks.borrow();
        let d = disks.get(&disk_number).ok_or_else(|| {
            ApiError::not_found("CreateFileW", format!("PhysicalDrive{disk_number}"))
        })?;
        d.read_at(offset, len)
            .ok_or_else(|| ApiError::new(ErrorKind::InvalidData, "ReadFile", "past end of disk"))
    }

    fn bitlocker(&self, drive: &str) -> ApiResult<Option<BitLocker>> {
        Ok(self.bitlocker.borrow().get(&key(drive)).cloned())
    }

    fn bitlocker_recovery_passwords(&self, drive: &str) -> ApiResult<Vec<Zeroizing<String>>> {
        Ok(self
            .recovery
            .borrow()
            .get(&key(drive))
            .map(|v| v.iter().map(|s| Zeroizing::new(s.clone())).collect())
            .unwrap_or_default())
    }

    fn smbios(&self) -> ApiResult<Vec<u8>> {
        let b = self.smbios_blob.borrow();
        if b.is_empty() {
            return Err(ApiError::unsupported("GetSystemFirmwareTable", "no SMBIOS"));
        }
        Ok(b.clone())
    }

    fn cpuid(&self, leaf: u32, subleaf: u32) -> Option<[u32; 4]> {
        self.cpuid_leaves.borrow().get(&(leaf, subleaf)).copied()
    }

    fn pnp_devices(&self) -> ApiResult<Vec<PnpDevice>> {
        Ok(self.pnp.borrow().clone())
    }

    fn disks(&self) -> ApiResult<Vec<DiskDevice>> {
        Ok(self.disk_devices.borrow().clone())
    }

    fn tpm_present(&self) -> bool {
        self.tpm.borrow().is_some()
    }

    fn tpm_submit(&self, cmd: &[u8]) -> ApiResult<Vec<u8>> {
        match self.tpm.borrow_mut().as_mut() {
            Some(f) => f(cmd),
            None => Err(ApiError::unsupported("Tbsip_Submit_Command", "no TPM")),
        }
    }

    fn tcg_log(&self) -> ApiResult<Vec<u8>> {
        let l = self.log.borrow();
        if l.is_empty() {
            return Err(ApiError::unsupported("Tbsi_Get_TCG_Log", "no log"));
        }
        Ok(l.clone())
    }

    fn run(&self, program: &str, args: &[&str], _stdin: Option<&[u8]>) -> ApiResult<Output> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.commands.borrow_mut().push(line.clone());
        self.mutated(format!("run {line}"));
        let r = self.runner.borrow().as_ref().and_then(|f| f(program, args));
        Ok(r.unwrap_or(Output {
            status: 0,
            stdout: String::new(),
            stderr: String::new(),
        }))
    }

    fn run_interactive(&self, program: &str, args: &[&str]) -> ApiResult<i32> {
        let line = std::iter::once(program)
            .chain(args.iter().copied())
            .collect::<Vec<_>>()
            .join(" ");
        self.interactive.borrow_mut().push(line);
        Ok(0)
    }

    fn restart(&self) -> ApiResult<()> {
        self.mutated("restart".into());
        self.restarted.set(true);
        Ok(())
    }

    fn random(&self, buf: &mut [u8]) -> ApiResult<()> {
        for chunk in buf.chunks_mut(32) {
            let n = self.rng.get();
            self.rng.set(n + 1);
            let d = Sha256::digest(n.to_le_bytes());
            let l = chunk.len();
            chunk.copy_from_slice(d.get(..l).unwrap_or(&[]));
        }
        Ok(())
    }

    fn now_unix(&self) -> u64 {
        self.now.get()
    }

    fn uptime_secs(&self) -> u64 {
        self.uptime.get()
    }

    fn program_data(&self) -> String {
        "C:\\ProgramData".into()
    }

    fn system_drive(&self) -> String {
        "C:".into()
    }

    fn read_secret(&self, _prompt: &str) -> ApiResult<Zeroizing<String>> {
        self.secrets
            .borrow_mut()
            .pop()
            .map(Zeroizing::new)
            .ok_or_else(|| ApiError::new(ErrorKind::Other, "ReadConsoleW", "no input"))
    }

    fn read_stdin(&self, max: usize) -> ApiResult<Zeroizing<Vec<u8>>> {
        let s = self.stdin.borrow();
        if s.len() > max {
            return Err(ApiError::new(
                ErrorKind::InvalidData,
                "ReadFile",
                "stdin too large",
            ));
        }
        Ok(Zeroizing::new(s.clone()))
    }
}

/// The footer `CreateVirtualDisk` writes for a fixed VHD of `size` bytes
/// (VHD specification rev 1.0, "Hard Disk Footer Format"): what the mock's
/// "virtdisk" produces, checked by `paguro_core::vhd` like a real one.
pub fn fixed_vhd_footer(size: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    let mut put = |at: usize, b: &[u8]| {
        if let Some(d) = f.get_mut(at..at + b.len()) {
            d.copy_from_slice(b);
        }
    };
    put(0, b"conectix");
    put(8, &2u32.to_be_bytes()); // features: reserved bit
    put(12, &0x0001_0000u32.to_be_bytes()); // format version
    put(16, &u64::MAX.to_be_bytes()); // data offset: none (fixed)
    put(28, b"win ");
    put(32, &0x000a_0000u32.to_be_bytes());
    put(36, b"Wi2k");
    put(40, &size.to_be_bytes()); // original size
    put(48, &size.to_be_bytes()); // current size
    put(56, &[0x04, 0x00, 0x10, 0x3f]); // geometry (not checked)
    put(60, &2u32.to_be_bytes()); // disk type: fixed
    put(68, &[0x42; 16]); // unique id
    let sum: u32 = f.iter().map(|&b| u32::from(b)).sum();
    let ck = !sum;
    if let Some(d) = f.get_mut(64..68) {
        d.copy_from_slice(&ck.to_be_bytes());
    }
    f
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn footer_is_a_valid_fixed_vhd() {
        let f = fixed_vhd_footer(1 << 20);
        assert_eq!(
            paguro_core::vhd::fixed_payload_len(&f, (1 << 20) + 512),
            Ok(1 << 20)
        );
    }

    #[test]
    fn sparse_files_read_back() {
        let mut f = MockFile::zeros(10);
        f.write_at(4, b"ab");
        assert_eq!(f.read_at(3, 4).unwrap(), b"\0ab\0");
        assert_eq!(f.read_at(8, 3), None);
    }

    #[test]
    fn boot_services_only_variables_are_invisible() {
        let m = MockApi::standard();
        m.set_var_raw(
            "PaguroB",
            &paguro_core::guid::PAGURO_VENDOR,
            &[1; 32],
            attr::NV | attr::BS,
        );
        assert_eq!(
            m.fw_get("PaguroB", &paguro_core::guid::PAGURO_VENDOR),
            Ok(None)
        );
        assert!(
            m.fw_delete("PaguroB", &paguro_core::guid::PAGURO_VENDOR)
                .is_err()
        );
    }
}
