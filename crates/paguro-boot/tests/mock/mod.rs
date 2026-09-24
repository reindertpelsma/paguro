//! An in-memory platform for mock boots: fake firmware variables, an in-memory
//! ESP, in-memory GPT disks, a scripted console, a fake TPM (see [`tpm`]) and
//! a fake BitLocker volume. Everything the loader does is recorded in order.
#![allow(dead_code, clippy::indexing_slicing)]

pub mod tpm;

use paguro_boot::platform::{DiskInfo, Input, Platform, PlatformError, Screen, attrs};
use paguro_boot::volume::{Key, Located, LocatedImage, Partition, Volume, VolumeKind};
use paguro_boot::{BootError, Buffers, Outcome, Params};
use paguro_core::bootstrap;
use paguro_core::config::{Config, Format};
use paguro_core::gpt;
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, GPT_BASIC_DATA, Guid, PAGURO_VENDOR};
use paguro_core::handoff::{self, FveLayout};
use paguro_core::seal::{self, Kind, Seal, Sealed};
use paguro_crypto as kdf;
use std::collections::{HashMap, VecDeque};
use std::fmt;

pub use tpm::{FakeTpm, sha256};

pub const PARAMS: Params = Params {
    stretch_iterations: 16,
};

/// Everything observable, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    SetVar(String, u32, Vec<u8>),
    DeleteVar(String),
    /// PCR, SHA-256(data), event bytes.
    Extend(u32, [u8; 32], Vec<u8>),
    Publish,
    Start(Vec<u8>),
    Reset,
}

pub struct Disk {
    pub block_size: u32,
    pub data: Vec<u8>,
}

pub struct Mock {
    pub files: HashMap<String, Vec<u8>>,
    pub vars: HashMap<(String, Guid), (u32, Vec<u8>)>,
    pub secure_boot: bool,
    pub tpm: Option<FakeTpm>,
    pub disks: Vec<Disk>,
    pub script: VecDeque<(Input, Option<Vec<u8>>)>,
    pub screens: Vec<Screen>,
    pub events: Vec<Event>,
    pub log: Vec<String>,
    pub handoff: Option<Vec<u8>>,
    pub rng: u64,
    pub rng_fails: bool,
    pub start_fails: bool,
    /// When non-empty, TPM responses come from here instead of the fake.
    pub raw_tpm: VecDeque<Vec<u8>>,
    pub extend_fails: bool,
}

impl Mock {
    pub fn new() -> Self {
        Mock {
            files: HashMap::new(),
            vars: HashMap::new(),
            secure_boot: true,
            tpm: Some(FakeTpm::new(7)),
            disks: Vec::new(),
            script: VecDeque::new(),
            screens: Vec::new(),
            events: Vec::new(),
            log: Vec::new(),
            handoff: None,
            rng: 0,
            rng_fails: false,
            start_fails: false,
            raw_tpm: VecDeque::new(),
            extend_fails: false,
        }
    }

    pub fn input(&mut self, i: Input) -> &mut Self {
        self.script.push_back((i, None));
        self
    }

    pub fn secret(&mut self, s: &str) -> &mut Self {
        self.script
            .push_back((Input::Secret(s.len()), Some(s.as_bytes().to_vec())));
        self
    }

    pub fn var(&self, name: &str) -> Option<&(u32, Vec<u8>)> {
        self.vars
            .get(&(name.to_string(), PAGURO_VENDOR))
            .or_else(|| self.vars.get(&(name.to_string(), EFI_GLOBAL_VARIABLE)))
    }

    pub fn put_var(&mut self, name: &str, vendor: Guid, attrs: u32, data: &[u8]) {
        self.vars
            .insert((name.to_string(), vendor), (attrs, data.to_vec()));
    }

    pub fn logged(&self, needle: &str) -> bool {
        self.log.iter().any(|l| l.contains(needle))
    }

    pub fn extends(&self) -> Vec<[u8; 32]> {
        self.events
            .iter()
            .filter_map(|e| match e {
                Event::Extend(12, d, _) => Some(*d),
                _ => None,
            })
            .collect()
    }

    pub fn pcr12(&self) -> [u8; 32] {
        self.tpm.as_ref().map_or([0; 32], |t| t.pcrs[12])
    }

    pub fn tpm(&mut self) -> &mut FakeTpm {
        self.tpm.as_mut().unwrap()
    }

    pub fn decoded(&self) -> handoff::Handoff<'_> {
        handoff::decode(self.handoff.as_ref().expect("no handoff published")).unwrap()
    }
}

impl Platform for Mock {
    fn read_esp_file(
        &mut self,
        name: &str,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        let Some(f) = self.files.get(name) else {
            return Ok(None);
        };
        if f.len() > buf.len() {
            return Err(PlatformError::TooLarge);
        }
        buf[..f.len()].copy_from_slice(f);
        Ok(Some(f.len()))
    }

    fn get_var(
        &mut self,
        name: &str,
        vendor: &Guid,
        buf: &mut [u8],
    ) -> Result<Option<usize>, PlatformError> {
        let Some((_, v)) = self.vars.get(&(name.to_string(), *vendor)) else {
            return Ok(None);
        };
        if v.len() > buf.len() {
            return Err(PlatformError::TooLarge);
        }
        buf[..v.len()].copy_from_slice(v);
        Ok(Some(v.len()))
    }

    fn set_var(
        &mut self,
        name: &str,
        vendor: &Guid,
        attrs: u32,
        data: &[u8],
    ) -> Result<(), PlatformError> {
        self.events
            .push(Event::SetVar(name.to_string(), attrs, data.to_vec()));
        self.vars
            .insert((name.to_string(), *vendor), (attrs, data.to_vec()));
        Ok(())
    }

    fn delete_var(&mut self, name: &str, vendor: &Guid) -> Result<(), PlatformError> {
        self.events.push(Event::DeleteVar(name.to_string()));
        self.vars
            .remove(&(name.to_string(), *vendor))
            .map(|_| ())
            .ok_or(PlatformError::Device(14))
    }

    fn secure_boot(&mut self) -> bool {
        self.secure_boot
    }

    fn tpm_present(&mut self) -> bool {
        self.tpm.is_some()
    }

    fn hash_log_extend(
        &mut self,
        pcr: u32,
        data: &[u8],
        event: &[u8],
    ) -> Result<(), PlatformError> {
        if self.extend_fails {
            return Err(PlatformError::Device(7));
        }
        let d = sha256(&[data]);
        self.events.push(Event::Extend(pcr, d, event.to_vec()));
        let t = self.tpm.as_mut().ok_or(PlatformError::Unsupported)?;
        t.extend(pcr as usize, &d);
        Ok(())
    }

    fn tpm_submit(&mut self, cmd: &[u8], resp: &mut [u8]) -> Result<usize, PlatformError> {
        let t = self.tpm.as_mut().ok_or(PlatformError::Unsupported)?;
        let r = match self.raw_tpm.pop_front() {
            Some(raw) => raw,
            None => t.submit(cmd),
        };
        if r.len() > resp.len() {
            return Err(PlatformError::TooLarge);
        }
        resp[..r.len()].copy_from_slice(&r);
        Ok(r.len())
    }

    fn disk_count(&mut self) -> usize {
        self.disks.len()
    }

    fn disk_info(&mut self, disk: usize) -> Option<DiskInfo> {
        self.disks.get(disk).map(|d| DiskInfo {
            block_size: d.block_size,
            blocks: d.data.len() as u64 / u64::from(d.block_size),
        })
    }

    fn read_blocks(&mut self, disk: usize, lba: u64, buf: &mut [u8]) -> Result<(), PlatformError> {
        let d = self.disks.get(disk).ok_or(PlatformError::Unsupported)?;
        assert_eq!(buf.len() % d.block_size as usize, 0, "partial-block read");
        let at = lba as usize * d.block_size as usize;
        let src = d
            .data
            .get(at..at + buf.len())
            .ok_or(PlatformError::Device(3))?;
        buf.copy_from_slice(src);
        Ok(())
    }

    fn random(&mut self, buf: &mut [u8]) -> Result<(), PlatformError> {
        if self.rng_fails {
            return Err(PlatformError::Unsupported);
        }
        for chunk in buf.chunks_mut(32) {
            self.rng += 1;
            let r = sha256(&[b"rng", &self.rng.to_le_bytes()]);
            chunk.copy_from_slice(&r[..chunk.len()]);
        }
        Ok(())
    }

    fn prompt(&mut self, screen: &Screen, secret: &mut [u8]) -> Input {
        self.screens.push(*screen);
        // Message-only screens are acknowledged without consuming the script.
        if matches!(
            screen,
            Screen::Incorrect
                | Screen::TpmLocked
                | Screen::Notice(paguro_boot::platform::Notice::NotImplemented)
        ) {
            return Input::Continue;
        }
        match self.script.pop_front() {
            Some((i, Some(s))) => {
                let n = s.len().min(secret.len());
                secret[..n].copy_from_slice(&s[..n]);
                let _ = i;
                Input::Secret(n)
            }
            Some((i, None)) => i,
            None => Input::Escape,
        }
    }

    fn log(&mut self, args: fmt::Arguments<'_>) {
        self.log.push(args.to_string());
    }

    fn publish_handoff(&mut self, blob: &[u8]) -> Result<(), PlatformError> {
        self.events.push(Event::Publish);
        self.handoff = Some(blob.to_vec());
        Ok(())
    }

    fn load_start_image(&mut self, device_path: &[u8]) -> Result<(), PlatformError> {
        self.events.push(Event::Start(device_path.to_vec()));
        if self.start_fails {
            return Err(PlatformError::Device(26));
        }
        Ok(())
    }

    fn reset(&mut self) {
        self.events.push(Event::Reset);
    }
}

/// A fake BitLocker volume: knows its VMK, FVEK blob, protectors and images.
pub struct FakeVolume {
    pub vmk: Key,
    pub blob: Vec<u8>,
    pub clear_key: Option<Key>,
    pub recovery: Option<([u8; 16], Key)>,
    pub images: Vec<(&'static str, u64, u16)>,
    pub flags: u32,
    pub default_path: &'static str,
    pub opened: Option<(Partition, VolumeKind)>,
    pub unlocked: bool,
    pub tries: usize,
    pub locate_saw_config: Option<bool>,
}

pub const FVEK: [u8; 32] = [0xfe; 32];

impl FakeVolume {
    pub fn new(vmk: Key) -> Self {
        FakeVolume {
            vmk,
            blob: b"encrypted-fvek-blob".to_vec(),
            clear_key: None,
            recovery: None,
            images: vec![("debian", 1234, 7)],
            flags: 0,
            default_path: "\\paguro\\debian.vhd",
            opened: None,
            unlocked: false,
            tries: 0,
            locate_saw_config: None,
        }
    }
}

impl<P: Platform> Volume<P> for FakeVolume {
    fn open(&mut self, _: &mut P, part: &Partition, kind: VolumeKind) -> Result<(), BootError> {
        self.opened = Some((*part, kind));
        Ok(())
    }
    fn fvek_blob(&mut self, _: &mut P, out: &mut [u8]) -> Result<usize, BootError> {
        out[..self.blob.len()].copy_from_slice(&self.blob);
        Ok(self.blob.len())
    }
    fn clear_key(&mut self, _: &mut P) -> Result<Option<Key>, BootError> {
        Ok(self.clear_key)
    }
    fn try_vmk(&mut self, _: &mut P, vmk: &Key) -> Result<bool, BootError> {
        self.tries += 1;
        self.unlocked = *vmk == self.vmk;
        Ok(self.unlocked)
    }
    fn fvek(&self) -> Option<(u16, &[u8])> {
        self.unlocked.then_some((0x8004, &FVEK[..]))
    }
    fn layout(&self) -> Option<FveLayout> {
        self.unlocked.then_some(FveLayout {
            metadata_offsets: [0x1000, 0x2000, 0x3000],
            region_size: 0x10000,
            boot_sector_reloc_offset: 0x4000,
            boot_sector_reloc_sectors: 16,
            encrypted_size: 1 << 30,
        })
    }
    fn recovery_key(&mut self, _: &mut P, key: &[u8; 16]) -> Result<Option<Key>, BootError> {
        Ok(self.recovery.and_then(|(k, v)| (k == *key).then_some(v)))
    }
    fn locate(
        &mut self,
        _: &mut P,
        cfg: Option<&Config<'_>>,
        out: &mut Located,
    ) -> Result<(), BootError> {
        self.locate_saw_config = Some(cfg.is_some());
        for (i, (name, rec, seq)) in self.images.iter().enumerate() {
            let mut n = [0u8; 32];
            n[..name.len()].copy_from_slice(name.as_bytes());
            out.images[i] = LocatedImage {
                name: n,
                name_len: name.len() as u8,
                mft_record: *rec,
                mft_seq: *seq,
            };
        }
        out.image_count = self.images.len();
        out.flags = self.flags;
        let chain = b"chain-device-path";
        out.chain[..chain.len()].copy_from_slice(chain);
        out.chain_len = chain.len();
        out.default_path[..self.default_path.len()].copy_from_slice(self.default_path.as_bytes());
        out.default_path_len = self.default_path.len();
        out.default_format = Format::Vhd;
        Ok(())
    }
}

/// A disk with one GPT partition per `(guid, first sector's OEM id)`.
pub fn disk(parts: &[(Guid, &[u8; 8])]) -> Disk {
    let blocks = 4096u64;
    let mut data = vec![0u8; blocks as usize * 512];
    let mut entries = Vec::new();
    for (i, (id, oem)) in parts.iter().enumerate() {
        let first = 64 + i as u64 * 256;
        entries.push(gpt::Entry {
            type_guid: GPT_BASIC_DATA,
            unique_guid: *id,
            first_lba: first,
            last_lba: first + 255,
            attributes: 0,
            name: [0; 36],
        });
        let at = first as usize * 512;
        data[at + 3..at + 11].copy_from_slice(*oem);
    }
    let mut h = [0u8; 512];
    let mut a = [0u8; gpt::MAX_ENTRY_ARRAY];
    gpt::build::write(
        &Guid([0xd1; 16]),
        blocks,
        512,
        &entries,
        128,
        &mut h,
        &mut a,
    )
    .unwrap();
    data[512..1024].copy_from_slice(&h);
    data[1024..1024 + a.len()].copy_from_slice(&a);
    Disk {
        block_size: 512,
        data,
    }
}

pub const BITLOCKER: &[u8; 8] = b"-FVE-FS-";
pub const NTFS: &[u8; 8] = b"NTFS    ";
pub const VOLUME: Guid = Guid([0x5c; 16]);
pub const VMK: Key = [0x42; 32];
pub const B: Key = [0xbb; 32];
pub const S: Key = [0x55; 32];
pub const PIN: &str = "correct horse";

pub fn ini_text(volume: &Guid, passphrase: bool) -> Vec<u8> {
    format!(
        "# paguro configuration. Not hand-editable: use `paguro config`.\n[Paguro]\nversion = 1\ndefault = debian\nvolume = {volume}\n\n[Image.debian]\npath = \\paguro\\debian.vhd\nformat = vhd\n\n[Passphrase]\nenabled = {}\n",
        u8::from(passphrase)
    )
    .into_bytes()
}

pub fn pass_hash(pw: &str, salt: &[u8; 16]) -> Key {
    kdf::bitlocker_stretch(
        &kdf::user_password_hash(pw),
        salt,
        PARAMS.stretch_iterations,
    )
}

pub fn wrap(env: &Key, salt: &[u8; 16], blob: &[u8], ph: &Key, vmk: &Key) -> Key {
    kdf::xor32(&kdf::final_key(&kdf::root_gate(env, salt, blob), ph), vmk)
}

pub fn write_seal(
    kind: Kind,
    deadline: Option<u64>,
    wrapped: &Key,
    salt: &[u8; 16],
    obj: Option<(&[u8], &[u8])>,
) -> Vec<u8> {
    let s = Seal {
        kind,
        deadline,
        pcrs: kind.has_tpm_object().then_some(seal::Pcrs::V1),
        wrapped_vmk: wrapped,
        salt,
        sealed: obj.map(|(public, private)| Sealed { public, private }),
    };
    let mut buf = vec![0u8; seal::MAX_FILE];
    let n = seal::write(&s, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

/// The PCR values firmware leaves (0, 2, 4, 7), distinct per index.
pub fn firmware_pcrs(t: &mut FakeTpm) {
    for (i, pcr) in [0usize, 2, 4, 7].iter().enumerate() {
        t.pcrs[*pcr] = [0x10 + i as u8; 32];
    }
}

pub fn pcr_values(t: &FakeTpm, pcr12: [u8; 32]) -> [[u8; 32]; 5] {
    [t.pcrs[0], t.pcrs[2], t.pcrs[4], t.pcrs[7], pcr12]
}

/// Seal `D` in the fake TPM with the policy for `pcr12` (and a deadline for
/// the bypass), through the loader's own TPM client — so the marshalling that
/// creates is the marshalling that unseals.
pub fn seal_object(
    m: &mut Mock,
    pcr12: [u8; 32],
    deadline: Option<u64>,
    auth: &Key,
    d: &Key,
) -> (Vec<u8>, Vec<u8>) {
    let vals = pcr_values(m.tpm(), pcr12);
    let policy = paguro_boot::tpm::policy_digest(seal::PCR_MASK_V1, &vals, deadline);
    let mut created = paguro_boot::tpm::CreatedObject::new();
    paguro_boot::tpm::Tpm::new(m)
        .create_sealed(auth, d, &policy, &mut created)
        .unwrap();
    // Creation leaves no trace in the command log the tests look at.
    m.tpm().commands.clear();
    (created.public().to_vec(), created.private().to_vec())
}

/// A standard machine: Secure Boot on, verified `paguro.ini`, `B` present,
/// firmware PCRs set, one BitLocker volume, a Windows Boot Manager entry.
pub struct World {
    pub m: Mock,
    pub v: FakeVolume,
    pub ini: Vec<u8>,
}

pub const TPM_SALT: [u8; 16] = [0x71; 16];
pub const PASS_SALT: [u8; 16] = [0x72; 16];
pub const SETUP_SALT: [u8; 16] = [0x73; 16];
pub const BYPASS_SALT: [u8; 16] = [0x74; 16];
pub const D: Key = [0xdd; 32];

impl World {
    pub fn new() -> Self {
        let mut m = Mock::new();
        firmware_pcrs(m.tpm());
        let ini = ini_text(&VOLUME, true);
        m.files.insert("paguro.ini".into(), ini.clone());
        m.put_var(
            "PaguroConfigHash",
            PAGURO_VENDOR,
            attrs::NV_BS_RT,
            &sha256(&[&ini]),
        );
        m.put_var("PaguroB", PAGURO_VENDOR, attrs::NV_BS, &B);
        m.disks.push(disk(&[(VOLUME, BITLOCKER)]));
        let mut lo = [0u8; 512];
        let n = bootstrap::write_load_option(
            1,
            "Windows Boot Manager",
            "\\EFI\\Microsoft\\Boot\\bootmgfw.efi",
            &[],
            &mut lo,
        )
        .unwrap();
        m.put_var("Boot0000", EFI_GLOBAL_VARIABLE, attrs::NV_BS_RT, &lo[..n]);
        m.put_var("BootOrder", EFI_GLOBAL_VARIABLE, attrs::NV_BS_RT, &[0, 0]);
        World {
            m,
            v: FakeVolume::new(VMK),
            ini,
        }
    }

    /// Set a new `paguro.ini` and (optionally) its matching hash.
    pub fn set_ini(&mut self, ini: Vec<u8>, hash: bool) {
        self.m.files.insert("paguro.ini".into(), ini.clone());
        if hash {
            self.m.put_var(
                "PaguroConfigHash",
                PAGURO_VENDOR,
                attrs::NV_BS_RT,
                &sha256(&[&ini]),
            );
        }
        self.ini = ini;
    }

    /// Write `tpm_seal.bin`, sealed against the load taint of the current ini.
    pub fn with_tpm_seal(&mut self, pin: &str) -> &mut Self {
        let pcr12 = paguro_boot::tpm::pcr12_after_load_taint(&self.ini);
        self.with_tpm_seal_at(pin, pcr12)
    }

    pub fn with_tpm_seal_at(&mut self, pin: &str, pcr12: [u8; 32]) -> &mut Self {
        let ph = pass_hash(pin, &TPM_SALT);
        let auth = kdf::tpm_auth(&ph);
        let (public, private) = seal_object(&mut self.m, pcr12, None, &auth, &D);
        let wrapped = wrap(&kdf::env_tpm(&B, &D), &TPM_SALT, &self.v.blob, &ph, &VMK);
        let f = write_seal(
            Kind::Tpm,
            None,
            &wrapped,
            &TPM_SALT,
            Some((&public, &private)),
        );
        self.m.files.insert(Kind::Tpm.file_name().into(), f);
        self
    }

    pub fn with_passphrase_seal(&mut self, pw: &str) -> &mut Self {
        let ph = pass_hash(pw, &PASS_SALT);
        let wrapped = wrap(&kdf::env_passphrase(), &PASS_SALT, &self.v.blob, &ph, &VMK);
        let f = write_seal(Kind::Passphrase, None, &wrapped, &PASS_SALT, None);
        self.m.files.insert(Kind::Passphrase.file_name().into(), f);
        self
    }

    pub fn with_setup_seal(&mut self, pw: &str) -> &mut Self {
        let ph = pass_hash(pw, &SETUP_SALT);
        let env = kdf::env_setup(&S, &sha256(&[&self.ini]));
        let wrapped = wrap(&env, &SETUP_SALT, &self.v.blob, &ph, &VMK);
        let f = write_seal(Kind::SetupTpm, None, &wrapped, &SETUP_SALT, None);
        self.m.files.insert(Kind::SetupTpm.file_name().into(), f);
        self.m
            .put_var("PaguroSetup", PAGURO_VENDOR, attrs::NV_BS_RT, &S);
        self
    }

    pub fn with_bypass_seal(&mut self, deadline: u64) -> &mut Self {
        let pcr12 = paguro_boot::tpm::pcr12_after_load_taint(&self.ini);
        let bypass_d = [0xbd; 32];
        let (public, private) =
            seal_object(&mut self.m, pcr12, Some(deadline), &[0; 32], &bypass_d);
        let wrapped = kdf::xor32(&bypass_d, &VMK);
        let f = write_seal(
            Kind::PinBypass,
            Some(deadline),
            &wrapped,
            &BYPASS_SALT,
            Some((&public, &private)),
        );
        self.m.files.insert(Kind::PinBypass.file_name().into(), f);
        self
    }

    pub fn run(&mut self) -> Outcome {
        let mut bufs = Box::new(Buffers::new());
        paguro_boot::run(&mut self.m, &mut self.v, &mut bufs, &PARAMS)
    }
}

/// The boot-taint digest.
pub fn boot_taint() -> [u8; 32] {
    sha256(&[paguro_boot::names::BOOT_TAINT])
}

pub fn extend(old: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    sha256(&[old, digest])
}
