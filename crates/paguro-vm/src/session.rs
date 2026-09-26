//! The glue: one VM session from the claimed volume to a running QEMU.
//!
//! `prepare` (root; the paguro host stack loaded, view B's volume
//! registered): reads the real disk's GPT and the volume's BitLocker
//! metadata, builds the substitute and the `.BEK`, the synthetic ESP and
//! the scratch file, and assembles `/dev/mapper/paguro-vmdisk` (view B
//! loaded here: B and C are exclusive, the module refuses B while C is
//! loaded). `launch` runs QEMU on it with the host's identity, hot-unplugs
//! the `.BEK` once the guest has read it, applies the memory policy and
//! the driver gate. `teardown` undoes `prepare`.
//!
//! Session state lives in `<work>/session.json`; nothing here writes to the
//! real disk.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use paguro_boot::bde::Vmk;
use paguro_core::bde::{self, Layout, Metadata, REGION_SIZE};
use paguro_core::gpt::Header;
use paguro_core::guid::{GPT_ESP, Guid};
use paguro_initrd::dm::Dm;
use paguro_initrd::plan::Target;
use paguro_initrd::sys;
use serde_json::{Value, json};

use crate::disk::{self, Part, Spec};
use crate::esp;
use crate::fve::{self, Params};
use crate::gpu::{self, VmInfo};
use crate::identity;
use crate::loopdev::{self, Loop};
use crate::mem;
use crate::net;
use crate::qemu::{self, Bus, DiskSource, HostOnly, VmConfig};
use crate::qmp::Qmp;

pub type R<T> = Result<T, String>;

/// The Microsoft Reserved Partition's type.
pub const GPT_MSR: &str = "e3c9e316-0b5c-4db8-817d-f92df00215ae";
pub const SESSION_FILE: &str = "session.json";
/// The QOM id of the `.BEK` stick (`qemu::argv`).
pub const BEK_DEVICE: &str = "paguro-bek";
/// Log every this many I/O errors reported to the guest.
const IO_ERROR_LOG_EVERY: u64 = 100;
/// Written to the work directory when the tripwire stopped the VM.
pub const TRIPPED_FILE: &str = "tripped.json";

/// A JSON object's field, `Null` when absent.
fn field<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

pub fn log(msg: &str) {
    eprintln!("paguro-vm: {msg}");
}

fn read_at(f: &File, off: u64, len: usize) -> R<Vec<u8>> {
    let mut b = vec![0u8; len];
    f.read_exact_at(&mut b, off)
        .map_err(|e| format!("read {len} bytes at {off}: {e}"))?;
    Ok(b)
}

/// The real disk: its GUID, block size and used entries.
pub struct RealDisk {
    pub guid: Guid,
    pub block_size: u32,
    pub entries: Vec<paguro_core::gpt::Entry>,
}

pub fn read_disk(dev: &Path) -> R<RealDisk> {
    let f = File::open(dev).map_err(|e| format!("{}: {e}", dev.display()))?;
    let (size, lbs) = sys::blk_geometry(&f)?;
    let block = read_at(&f, u64::from(lbs), lbs as usize)?;
    let hdr = Header::parse(&block, size / u64::from(lbs)).map_err(|e| format!("GPT: {e:?}"))?;
    let arr = read_at(&f, hdr.entries_lba * u64::from(lbs), hdr.entries_len())?;
    let es = hdr
        .entries(&arr)
        .map_err(|e| format!("GPT entries: {e:?}"))?;
    let mut entries = Vec::new();
    for i in 0..es.count() {
        let e = es.get(i).map_err(|e| format!("GPT entry {i}: {e:?}"))?;
        if !e.is_unused() {
            entries.push(e);
        }
    }
    Ok(RealDisk {
        guid: hdr.disk_guid,
        block_size: lbs,
        entries,
    })
}

/// Where view B comes from.
pub enum ViewB {
    /// An existing device (built by someone else).
    Device(PathBuf),
    /// A `/dev/paguro` volume id: `prepare` loads `paguro-volume <id> b`.
    Volume(u32),
}

pub struct PrepareOpts {
    pub disk: PathBuf,
    pub partition: PathBuf,
    pub volume_guid: Guid,
    pub view_b: ViewB,
    pub vmk: Option<Vmk>,
    pub esp_dir: PathBuf,
    pub testsigning: bool,
    pub work: PathBuf,
    pub name: String,
}

/// The BitLocker side of a volume: its metadata as read, and the layout.
pub struct Bitlocker {
    pub header: Vec<u8>,
    pub regions: [Vec<u8>; 3],
    pub layout: Layout,
}

pub fn read_bitlocker(part: &File, volume_bytes: u64) -> R<Option<Bitlocker>> {
    let header = read_at(part, 0, bde::SIGNATURE.len() * 512)?;
    let hdr = match bde::parse_volume_header(&header) {
        Ok(h) => h,
        Err(bde::BdeError::NotBitLocker) => return Ok(None),
        Err(e) => return Err(format!("BitLocker header: {e:?}")),
    };
    let mut regions: [Vec<u8>; 3] = Default::default();
    for (r, &o) in regions.iter_mut().zip(&hdr.metadata_offsets) {
        *r = read_at(part, o, REGION_SIZE as usize)?;
    }
    let layout = {
        let b = bde::cross_check([&regions[0], &regions[1], &regions[2]], &hdr)
            .map_err(|e| format!("FVE metadata: {e:?}"))?;
        let m = Metadata::parse(b).map_err(|e| format!("FVE metadata: {e:?}"))?;
        Layout::new(&hdr, &m, volume_bytes).map_err(|e| format!("FVE layout: {e:?}"))?
    };
    Ok(Some(Bitlocker {
        header,
        regions,
        layout,
    }))
}

fn devt_of(p: &Path) -> R<String> {
    let (a, b) = sys::devno(p)?;
    Ok(format!("{a}:{b}"))
}

pub fn prepare(o: &PrepareOpts) -> R<Value> {
    fs::create_dir_all(&o.work).map_err(|e| format!("{}: {e}", o.work.display()))?;
    let real = read_disk(&o.disk)?;
    let msr_type = Guid::parse(GPT_MSR).map_err(|_| "MSR GUID")?;
    let vol = real
        .entries
        .iter()
        .find(|e| e.unique_guid == o.volume_guid)
        .ok_or("the volume's GUID is not on this disk")?;
    let esp_e = real
        .entries
        .iter()
        .find(|e| e.type_guid == GPT_ESP)
        .ok_or("no ESP on this disk")?;
    let msr_e = real.entries.iter().find(|e| e.type_guid == msr_type);
    let bs = u64::from(real.block_size);
    let volume_bytes = vol.sectors() * bs;

    let part = File::open(&o.partition).map_err(|e| format!("{}: {e}", o.partition.display()))?;
    let (psize, _) = sys::blk_geometry(&part)?;
    if psize != volume_bytes {
        return Err(format!(
            "{}: {psize} bytes, but the GPT entry says {volume_bytes}",
            o.partition.display()
        ));
    }

    // BitLocker: the substitute, the .BEK, and every owned sector.
    let bl = read_bitlocker(&part, volume_bytes)?;
    let (owned, fve_buf, bek) = match &bl {
        None => (Vec::new(), Vec::new(), None),
        Some(b) => {
            let vmk = o
                .vmk
                .as_ref()
                .ok_or("BitLocker volume: a VMK is needed (--vmk-file)")?;
            let p = Params::random().map_err(|e| format!("getrandom: {e}"))?;
            let s = fve::substitute(
                &b.header,
                [&b.regions[0], &b.regions[1], &b.regions[2]],
                vmk,
                &p,
            )
            .map_err(|e| e.to_string())?;
            let owned = fve::owned_ranges(&b.layout);
            let buf = fve::owned_buffer(&owned, b.layout.metadata_offsets, &s.region, |st, l| {
                read_at(&part, st * disk::SECTOR, (l * disk::SECTOR) as usize)
            })?;
            log(&format!(
                "FVE: external key protector {} added to the substitute; {} owned ranges ({} sectors) served from the session",
                fve::guid_text(&p.id),
                owned.len(),
                owned.iter().map(|x| x.1).sum::<u64>()
            ));
            (owned, buf, Some(s))
        }
    };

    // The ESP.
    let esp_min = esp_e.sectors() * bs;
    let e = esp::build(
        &o.esp_dir,
        o.testsigning,
        esp_min.div_ceil(disk::ALIGN) * disk::ALIGN,
    )?;
    log(&format!(
        "ESP: {} files, {} MiB{}",
        e.files,
        e.image.len() >> 20,
        e.testsigning
            .as_ref()
            .map(|x| format!(", testsigning on {x}"))
            .unwrap_or_default()
    ));

    // The disk.
    let plan = disk::plan(&Spec {
        block_size: real.block_size,
        disk_guid: real.guid,
        esp: Part::from_entry(esp_e),
        esp_bytes: e.image.len() as u64,
        msr: msr_e.map(Part::from_entry),
        volume: Part::from_entry(vol),
        volume_bytes,
        owned: owned.clone(),
    })
    .map_err(|e| e.to_string())?;

    // The scratch file: sparse, the pieces at their offsets.
    let scratch = o.work.join("scratch.img");
    {
        let f = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(&scratch)
            .map_err(|e| format!("{}: {e}", scratch.display()))?;
        f.set_len(plan.scratch.len).map_err(|e| e.to_string())?;
        let w = |off: u64, d: &[u8]| {
            f.write_all_at(d, off)
                .map_err(|e| format!("{}: {e}", scratch.display()))
        };
        w(plan.scratch.head, &plan.head)?;
        w(plan.scratch.esp, &e.image)?;
        w(plan.scratch.fve, &fve_buf)?;
        w(plan.scratch.tail, &plan.tail)?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    // The pristine FVE buffer, to show afterwards what the guest wrote.
    fs::write(o.work.join("fve-served.bin"), &fve_buf).map_err(|e| e.to_string())?;

    let (bek_image, bek_name) = match &bek {
        Some(s) => {
            let img = esp::bek_stick(&s.bek_name, &s.bek)?;
            let p = o.work.join("bek.img");
            fs::write(&p, img).map_err(|e| format!("{}: {e}", p.display()))?;
            (Some(p), Some(s.bek_name.clone()))
        }
        None => (None, None),
    };

    // Devices.
    let lo = Loop::attach(&scratch, real.block_size)?;
    let dmc = Dm::open()?;
    let (view_b, view_b_name) = match &o.view_b {
        ViewB::Device(p) => (devt_of(p)?, None),
        ViewB::Volume(id) => {
            let name = format!("{}-b", o.name);
            let m = dmc
                .setup(
                    &name,
                    &[Target {
                        start: 0,
                        len: volume_bytes / disk::SECTOR,
                        kind: "paguro-volume",
                        params: format!("{id} b"),
                    }],
                    0,
                )
                .map_err(|e| format!("view B: {e}"))?;
            log(&format!("view B {name}: {} (volume {id})", m.devt()));
            (m.devt(), Some(name))
        }
    };
    let table = disk::table(&plan, &lo.devt()?, &view_b);
    let m = dmc.setup(&o.name, &table, 0).inspect_err(|_| {
        if let Some(n) = &view_b_name {
            let _ = dmc.remove(n);
        }
    })?;
    fs::write(o.work.join("table.txt"), disk::table_text(&table)).map_err(|e| e.to_string())?;
    log(&format!(
        "{}: {} ({} bytes, {} segments)",
        o.name,
        m.devt(),
        plan.disk_bytes,
        table.len()
    ));
    let s = json!({
        "name": o.name,
        "node": m.node,
        "view_b": view_b,
        "view_b_name": view_b_name,
        "loop": lo.path,
        "scratch": scratch,
        "scratch_fve": plan.scratch.fve,
        "bek_image": bek_image,
        "bek_name": bek_name,
        "disk_bytes": plan.disk_bytes,
        "block_size": real.block_size,
        "volume_at": plan.volume_at,
        "volume_bytes": volume_bytes,
        "owned": plan.owned,
        "owned_names": bl.as_ref().map(|b| owned_names(&b.layout, &owned)).unwrap_or_default(),
        "testsigning": e.testsigning,
    });
    lo.persist();
    fs::write(
        o.work.join(SESSION_FILE),
        serde_json::to_string_pretty(&s).unwrap_or_default(),
    )
    .map_err(|e| e.to_string())?;
    Ok(s)
}

/// What each owned range is, for logs and the Q24 report.
pub fn owned_names(l: &Layout, owned: &[(u64, u64)]) -> Vec<String> {
    let sec = |b: u64| b / disk::SECTOR;
    owned
        .iter()
        .map(|&(start, _)| {
            if start == 0 {
                "volume-header".to_string()
            } else if start == sec(l.reloc_offset) {
                "relocated-boot-sectors".to_string()
            } else if let Some(i) = l.metadata_offsets.iter().position(|&m| sec(m) == start) {
                format!("metadata-{i}")
            } else if l.extra_region.is_some_and(|x| sec(x) == start) {
                "extra-region".to_string()
            } else {
                "owned".to_string()
            }
        })
        .collect()
}

/// Which sectors of the FVE buffer the guest changed: `(range name,
/// sector within the range, count)` runs, comparing the session's buffer
/// with what was served (DESIGN.md §6: absorbed, never passed through;
/// §11 Q24).
pub fn absorbed_writes(work: &Path) -> R<Vec<(String, u64, u64)>> {
    let s = read_session(work)?;
    let served = fs::read(work.join("fve-served.bin")).map_err(|e| e.to_string())?;
    let f = File::open(work.join("scratch.img")).map_err(|e| e.to_string())?;
    let at = field(&s, "scratch_fve")
        .as_u64()
        .ok_or("session: scratch_fve")?;
    let now = read_at(&f, at, served.len())?;
    let names: Vec<String> = field(&s, "owned_names")
        .as_array()
        .map(|a| {
            a.iter()
                .map(|v| v.as_str().unwrap_or("?").to_string())
                .collect()
        })
        .unwrap_or_default();
    let mut out = Vec::new();
    for (i, r) in field(&s, "owned")
        .as_array()
        .into_iter()
        .flatten()
        .enumerate()
    {
        let (len, buf) = (
            r.get(1).and_then(Value::as_u64),
            r.get(2).and_then(Value::as_u64),
        );
        let (Some(len), Some(buf)) = (len, buf) else {
            continue;
        };
        let mut run: Option<(u64, u64)> = None;
        for k in 0..len {
            let o = ((buf + k) * disk::SECTOR) as usize;
            let a = served.get(o..o + disk::SECTOR as usize);
            let b = now.get(o..o + disk::SECTOR as usize);
            let changed = a != b;
            match (&mut run, changed) {
                (Some((_, n)), true) => *n += 1,
                (None, true) => run = Some((k, 1)),
                (Some((st, n)), false) => {
                    out.push((names.get(i).cloned().unwrap_or_default(), *st, *n));
                    run = None;
                }
                (None, false) => {}
            }
        }
        if let Some((st, n)) = run {
            out.push((names.get(i).cloned().unwrap_or_default(), st, n));
        }
    }
    Ok(out)
}

pub fn read_session(work: &Path) -> R<Value> {
    let p = work.join(SESSION_FILE);
    let t = fs::read_to_string(&p).map_err(|e| format!("{}: {e}", p.display()))?;
    serde_json::from_str(&t).map_err(|e| format!("{}: {e}", p.display()))
}

pub fn teardown(work: &Path) -> R<()> {
    let s = read_session(work)?;
    // What the guest wrote to BitLocker's regions: kept nowhere but here.
    match absorbed_writes(work) {
        Ok(w) if w.is_empty() => log("FVE: the guest wrote nothing to BitLocker's regions"),
        Ok(w) => {
            for (name, at, n) in &w {
                log(&format!(
                    "FVE: the guest wrote {n} sector(s) of {name} at +{at}: absorbed, not kept \
                     (BitLocker changes belong in native Windows)"
                ));
            }
            let _ = fs::write(
                work.join("absorbed.json"),
                serde_json::to_string(&w).unwrap_or_default(),
            );
        }
        Err(e) => log(&format!("FVE: could not compare the buffer: {e}")),
    }
    let d = Dm::open()?;
    let mut errs = Vec::new();
    if let Some(n) = field(&s, "name").as_str() {
        if let Err(e) = d.remove(n) {
            errs.push(e);
        }
    }
    if let Some(n) = field(&s, "view_b_name").as_str() {
        if let Err(e) = d.remove(n) {
            errs.push(e);
        }
    }
    if let Some(l) = field(&s, "loop").as_str() {
        // Autoclear may have detached it already.
        let _ = loopdev::detach_path(Path::new(l));
    }
    for f in ["scratch.img", "bek.img", "fve-served.bin"] {
        let _ = fs::remove_file(work.join(f));
    }
    let _ = fs::remove_file(work.join(SESSION_FILE));
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

// ---------------------------------------------------------------------------
// launch

pub enum HostOnlyOpt {
    None,
    Tap(String),
    Socket(PathBuf),
}

pub struct LaunchOpts {
    pub work: PathBuf,
    pub disk: DiskSource,
    pub bek_image: Option<PathBuf>,
    pub block_size: u32,
    pub memory_mib: u64,
    pub cpus: u32,
    pub bus: Bus,
    pub nat_model: String,
    pub nat_hostfwd: Vec<String>,
    pub hostonly: HostOnlyOpt,
    pub hostonly_model: String,
    pub vsock_cid: Option<u32>,
    pub record_writes: Option<PathBuf>,
    pub ovmf_code: PathBuf,
    pub ovmf_vars_template: PathBuf,
    pub ovmf_vars: PathBuf,
    pub system_partition: Option<String>,
    pub sysroot: PathBuf,
    pub vnc: Option<String>,
    pub host_cgroup: Option<PathBuf>,
    pub driver_timeout: Option<Duration>,
    pub bek_unplug_after: Duration,
    pub print_argv: bool,
    pub scope_memory_max: Option<String>,
    pub rtc_localtime: bool,
    /// Hyper-V enlightenments (default on). `--no-hv-enlightenments` is for
    /// labs where Windows runs under a hypervisor that is itself a guest:
    /// enlightened, it froze after logon there; without, it booted too
    /// slowly to be useful either (test/vm/README.md).
    pub hv_enlightenments: bool,
    pub extra: Vec<String>,
    /// View B's tripwire (DESIGN.md §4.4 "Until the driver arms"): set on
    /// every QEMU before it runs, cleared when the driver arms.
    pub tripwire: Option<Tripwire>,
}

/// Who sets and clears the tripwire.
#[derive(Clone, Debug)]
pub enum Tripwire {
    /// View B's device-mapper name: `message <name> 0 tripwire <pid|off>`.
    Dm(String),
    /// An executable run as `<hook> on <qemu-pid>` / `<hook> off` (the split
    /// test, whose view B is in another VM).
    Hook(PathBuf),
}

impl Tripwire {
    fn set(&self, pid: u32) -> R<()> {
        self.run(&format!("{pid}"))
    }
    fn off(&self) -> R<()> {
        self.run("off")
    }
    fn run(&self, arg: &str) -> R<()> {
        match self {
            Tripwire::Dm(name) => Dm::open()?.message(name, 0, &format!("tripwire {arg}")),
            Tripwire::Hook(h) => {
                let mut c = Command::new(h);
                if arg == "off" {
                    c.arg("off");
                } else {
                    c.args(["on", arg]);
                }
                let st = c.status().map_err(|e| format!("{}: {e}", h.display()))?;
                if st.success() {
                    Ok(())
                } else {
                    Err(format!("{} {arg}: {st}", h.display()))
                }
            }
        }
    }
}

/// How one QEMU ended.
enum End {
    /// The guest rebooted (`-action reboot=shutdown`): start the next QEMU.
    Reboot,
    Exit,
}

/// The QEMU configuration `launch` runs.
pub fn config(o: &LaunchOpts, gpu_args: Vec<String>) -> R<VmConfig> {
    let id = identity::read_host(&o.sysroot, o.system_partition.as_deref(), identity::MARKER);
    for m in &id.missing {
        log(&format!("identity: not passed through: {m}"));
    }
    let smbios_file = o.work.join("smbios.bin");
    fs::write(&smbios_file, &id.smbios).map_err(|e| format!("{}: {e}", smbios_file.display()))?;
    Ok(VmConfig {
        name: "paguro-windows".into(),
        memory_mib: o.memory_mib,
        cpus: o.cpus,
        ovmf_code: o.ovmf_code.clone(),
        ovmf_vars: o.ovmf_vars.clone(),
        disk: o.disk.clone(),
        bus: o.bus,
        logical_block: o.block_size,
        record_writes: o.record_writes.clone(),
        record_append: false,
        bek_image: o.bek_image.clone(),
        identity: id,
        smbios_file,
        nat_model: o.nat_model.clone(),
        nat_hostfwd: o.nat_hostfwd.clone(),
        hostonly: match &o.hostonly {
            HostOnlyOpt::None => HostOnly::None,
            HostOnlyOpt::Tap(n) => HostOnly::Tap { ifname: n.clone() },
            HostOnlyOpt::Socket(p) => HostOnly::Socket { path: p.clone() },
        },
        hostonly_model: o.hostonly_model.clone(),
        vsock_cid: o.vsock_cid,
        agent_socket: Some(o.work.join("agent.sock")),
        qmp_socket: o.work.join("qmp.sock"),
        pidfile: Some(o.work.join("qemu.pid")),
        gpu_args,
        rtc_localtime: o.rtc_localtime,
        hv_enlightenments: o.hv_enlightenments,
        vnc: o.vnc.clone(),
        extra: o.extra.clone(),
    })
}

/// Agent frames (INTERFACES.md §11.3): `u32` little-endian length, then
/// that many bytes of JSON. The driver's report is
/// `{"type":"driver","state":"ok"}` (DESIGN.md §4.4).
pub fn agent_frame(v: &Value) -> Vec<u8> {
    let b = v.to_string().into_bytes();
    let mut out = (b.len() as u32).to_le_bytes().to_vec();
    out.extend(b);
    out
}

/// Frames in `buf` (consumed from the front as they complete).
pub fn agent_frames(buf: &mut Vec<u8>) -> Vec<Value> {
    const MAX_FRAME: usize = 64 << 10;
    let mut out = Vec::new();
    while let Some(len) = buf
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
    {
        let len = len as usize;
        if len > MAX_FRAME {
            // Not a frame: drop the stream's contents.
            buf.clear();
            break;
        }
        let Some(body) = buf.get(4..4 + len) else {
            break;
        };
        if let Ok(v) = serde_json::from_slice::<Value>(body) {
            out.push(v);
        }
        buf.drain(..4 + len);
    }
    out
}

pub fn driver_ok(v: &Value) -> bool {
    field(v, "type") == "driver" && field(v, "state") == "ok"
}

fn wait_for(p: &Path, t: Duration) -> bool {
    let end = Instant::now() + t;
    while Instant::now() < end {
        if p.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

pub fn launch(o: &LaunchOpts) -> R<()> {
    fs::create_dir_all(&o.work).map_err(|e| e.to_string())?;
    let backends = gpu::registry();
    let (order, skipped) = gpu::candidates(&backends);
    for s in &skipped {
        log(s);
    }
    let &first = order.first().ok_or("no GPU backend available")?;
    let backend = backends.get(first).ok_or("GPU backend")?;
    log(&format!("gpu: using {}", backend.name()));
    let info = VmInfo {
        memory_mib: o.memory_mib,
        name: "paguro-windows".into(),
    };
    if o.bek_image.is_none() {
        log(
            "no .BEK stick (no session.json in the work directory, no --bek): a BitLocker C: stops at the recovery screen",
        );
    }
    let mut cfg = config(o, backend.qemu_args(&info))?;
    let argv = qemu::argv(&cfg);
    if o.print_argv {
        println!("{}", serde_json::to_string(&argv).unwrap_or_default());
        return Ok(());
    }
    if !o.ovmf_vars.exists() {
        fs::copy(&o.ovmf_vars_template, &o.ovmf_vars)
            .map_err(|e| format!("{}: {e}", o.ovmf_vars.display()))?;
    }
    if let Some(w) = &o.record_writes {
        // blklogwrites writes into an existing file.
        File::create(w).map_err(|e| format!("{}: {e}", w.display()))?;
    }
    let _limit = match &o.host_cgroup {
        Some(cg) => {
            let total = fs::read_to_string("/proc/meminfo")
                .ok()
                .and_then(|m| mem::mem_total(&m))
                .ok_or("MemTotal")?;
            let l = mem::host_limit(total, o.memory_mib << 20)
                .ok_or("not enough memory for the VM and the host")?;
            let h = mem::HostLimit::apply(cg, l)?;
            log(&format!("memory: {}/memory.max = {l}", cg.display()));
            Some(h)
        }
        None => None,
    };
    let _ = fs::remove_file(o.work.join(TRIPPED_FILE));
    match &o.tripwire {
        Some(t) => log(&format!("tripwire: {t:?}")),
        None => log(
            "tripwire: NONE: a refusal before the driver arms reaches the guest as EIO (DESIGN.md §4.4)",
        ),
    }
    // One QEMU per guest boot: each starts paused, gets the tripwire, then
    // runs; a guest reboot ends it (-action reboot=shutdown).
    let mut boot = 0u32;
    loop {
        boot += 1;
        cfg.record_append = boot > 1;
        let argv = qemu::argv(&cfg);
        let (mut child, pid) = spawn_qemu(o, &argv)?;
        if let HostOnlyOpt::Tap(name) = &o.hostonly {
            net::ensure_netns()?;
            net::attach_link(name)?;
            log(&format!(
                "link: {name} in netns {}, {}/{}",
                net::NETNS,
                net::HOST_ADDR,
                net::PREFIX
            ));
        }
        let r = supervise(o, &o.work.join("qmp.sock"), &mut child, pid, boot);
        let st = child.wait().map_err(|e| e.to_string())?;
        log(&format!("QEMU exited: {st}"));
        let (r, armed) = match r {
            Ok((end, armed)) => (Ok(end), armed),
            Err(e) => (Err(e), false),
        };
        // Killed while under the tripwire: the module did it (a SIGKILL from
        // anyone else before arming is reported the same way, and is as safe).
        if st.signal() == Some(libc::SIGKILL) && o.tripwire.is_some() && !armed {
            let msg = "tripwire: Windows read or wrote the Linux image before paguro's driver \
                had armed, and the VM was stopped before Windows could see the refusal. \
                This is usually a disk check scheduled in Windows (chkdsk /r): start Windows \
                natively once to let it finish there, where it is harmless. Windows may \
                first show Automatic Repair because this boot did not complete: choose \
                Continue.";
            log(msg);
            let _ = fs::write(
                o.work.join(TRIPPED_FILE),
                json!({ "boot": boot, "qemu_pid": pid, "message": msg }).to_string(),
            );
            if let Some(t) = &o.tripwire {
                let _ = t.off();
            }
            return Err("stopped by the tripwire".into());
        }
        match r {
            Ok(End::Reboot) => {
                log("guest rebooted: a new QEMU, paused until the tripwire is set");
            }
            Ok(End::Exit) => break,
            Err(e) => {
                if let Some(t) = &o.tripwire {
                    let _ = t.off();
                }
                return Err(e);
            }
        }
    }
    if let Some(t) = &o.tripwire {
        let _ = t.off();
    }
    Ok(())
}

/// Start QEMU (paused: `-S`) and wait for its QMP socket and pid.
fn spawn_qemu(o: &LaunchOpts, argv: &[String]) -> R<(std::process::Child, u32)> {
    for f in ["qmp.sock", "agent.sock", "qemu.pid"] {
        let _ = fs::remove_file(o.work.join(f));
    }
    let qlog = OpenOptions::new()
        .create(true)
        .append(true)
        .open(o.work.join("qemu.log"))
        .map_err(|e| e.to_string())?;
    let mut cmd = match &o.scope_memory_max {
        Some(max) => {
            let mut c = Command::new("systemd-run");
            c.args(["--user", "--scope", "--collect", "-p"])
                .arg(format!("MemoryMax={max}"))
                .arg("--");
            c.args(argv);
            c
        }
        None => {
            let mut c = Command::new(argv.first().ok_or("argv")?);
            c.args(argv.get(1..).unwrap_or(&[]));
            c
        }
    };
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(qlog.try_clone().map_err(|e| e.to_string())?)
        .stderr(qlog)
        .spawn()
        .map_err(|e| format!("qemu: {e}"))?;
    let qmp_path = o.work.join("qmp.sock");
    if !wait_for(&qmp_path, Duration::from_secs(30)) {
        let _ = child.kill();
        return Err(format!(
            "QEMU did not start; see {}",
            o.work.join("qemu.log").display()
        ));
    }
    let pid: u32 = fs::read_to_string(o.work.join("qemu.pid"))
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .ok_or_else(|| format!("no QEMU pid; see {}", o.work.join("qemu.log").display()))?;
    log(&format!("QEMU pid {pid}"));
    match mem::protect(pid) {
        Ok(()) => log("memory: QEMU oom_score_adj -1000"),
        Err(e) => log(&format!("memory: {e}")),
    }
    Ok((child, pid))
}

fn supervise(
    o: &LaunchOpts,
    qmp_path: &Path,
    child: &mut std::process::Child,
    pid: u32,
    boot: u32,
) -> R<(End, bool)> {
    let mut q = Qmp::connect(qmp_path)?;
    // QEMU is paused (-S): nothing of the guest has run yet.
    if let Some(t) = &o.tripwire {
        if let Err(e) = t.set(pid) {
            let _ = child.kill();
            return Err(format!("tripwire: not set, so the VM does not run: {e}"));
        }
        log(&format!("tripwire: set on QEMU pid {pid} (boot {boot})"));
    }
    q.cmd("cont", json!({}))?;
    let start = Instant::now();
    let mut bek_first_read: Option<Instant> = None;
    let mut bek_gone = o.bek_image.is_none();
    let mut armed = false;
    let mut warned = false;
    let mut agent: Option<std::os::unix::net::UnixStream> = None;
    let mut abuf = Vec::new();
    let mut last_note = Instant::now();
    let mut io_errors = 0u64;
    let mut end = End::Exit;
    loop {
        // QEMU (or systemd-run, which execs it) gone: reaped here, so an
        // exited QEMU is never mistaken for a running one.
        if !matches!(child.try_wait(), Ok(None)) {
            if io_errors > 0 {
                log(&format!(
                    "disk: {io_errors} I/O error(s) reported to the guest in all"
                ));
            }
            return Ok((end, armed));
        }
        // The .BEK: unplugged once bootmgr has read it and Windows has had
        // time to start. Each boot is a new QEMU, with the stick in again.
        if !bek_gone {
            match q.reads(BEK_DEVICE) {
                Ok(Some(n)) if n > 0 && bek_first_read.is_none() => {
                    bek_first_read = Some(Instant::now());
                    log(&format!(
                        "BEK: read by the guest after {:.1}s ({n} reads)",
                        start.elapsed().as_secs_f64()
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    if e.contains("closed") {
                        return Ok((end, armed));
                    }
                }
            }
            if bek_first_read.is_some_and(|t| t.elapsed() >= o.bek_unplug_after) {
                match q.cmd("device_del", json!({ "id": BEK_DEVICE })) {
                    Ok(_) => log("BEK: device_del sent"),
                    Err(e) => log(&format!("BEK: {e}")),
                }
                bek_gone = true;
            }
        }
        // The agent port: the driver asks to be armed; the tripwire comes
        // off first, and only then is it told it is armed (INTERFACES.md
        // §11.3). Without the ack it is not armed, and the tripwire stays.
        if agent.is_none() {
            agent = std::os::unix::net::UnixStream::connect(o.work.join("agent.sock")).ok();
            if let Some(a) = &agent {
                let _ = a.set_read_timeout(Some(Duration::from_millis(200)));
            }
        }
        if let Some(a) = agent.as_mut() {
            let mut b = [0u8; 4096];
            if let Ok(n) = a.read(&mut b) {
                abuf.extend_from_slice(b.get(..n).unwrap_or(&[]));
                for f in agent_frames(&mut abuf) {
                    log(&format!("agent: {f}"));
                    if !driver_ok(&f) || armed {
                        continue;
                    }
                    let r = o.tripwire.as_ref().map_or(Ok(()), Tripwire::off);
                    let ack = match &r {
                        Ok(()) => {
                            armed = true;
                            log(&format!(
                                "driver: reported after {:.1}s; armed: the tripwire is off, refusals reach Windows as EIO",
                                start.elapsed().as_secs_f64()
                            ));
                            json!({"type": "armed", "ok": true})
                        }
                        Err(e) => {
                            log(&format!(
                                "driver: reported, but the tripwire could not be cleared ({e}): not armed"
                            ));
                            json!({"type": "armed", "ok": false, "error": e})
                        }
                    };
                    if let Err(e) = a.write_all(&agent_frame(&ack)) {
                        log(&format!("agent: ack: {e}"));
                    }
                }
            }
        }
        if let Some(t) = o.driver_timeout {
            if !armed && !warned && start.elapsed() > t {
                log(&format!(
                    "driver: no report within {}s: Windows runs under the tripwire (DESIGN.md §4.4)",
                    t.as_secs()
                ));
                warned = true;
            }
        }
        if let Err(e) = q.poll_events(Duration::from_millis(500)) {
            if e.contains("closed") {
                // QEMU is exiting: wait for it rather than spin.
                let _ = child.wait();
            }
        }
        let events = std::mem::take(&mut q.events);
        for e in events {
            let name = field(&e, "event").as_str().unwrap_or("");
            match name {
                "DEVICE_DELETED"
                    if e.pointer("/data/device").and_then(Value::as_str) == Some(BEK_DEVICE) =>
                {
                    log("BEK: removed from the guest");
                    for n in ["bek", "bek-file"] {
                        let _ = q.cmd("blockdev-del", json!({ "node-name": n }));
                    }
                }
                // View B's EIO reaching the guest (DESIGN.md §4.3): counted,
                // the first of each run logged.
                "BLOCK_IO_ERROR" => {
                    io_errors += 1;
                    if io_errors == 1 || io_errors % IO_ERROR_LOG_EVERY == 0 {
                        log(&format!(
                            "disk: {io_errors} I/O error(s) reported to the guest (last: {} {})",
                            e.pointer("/data/operation")
                                .and_then(Value::as_str)
                                .unwrap_or("?"),
                            e.pointer("/data/reason")
                                .and_then(Value::as_str)
                                .unwrap_or("?")
                        ));
                    }
                }
                "SHUTDOWN" => {
                    log(&format!("qmp: {e}"));
                    if e.pointer("/data/reason").and_then(Value::as_str) == Some("guest-reset") {
                        end = End::Reboot;
                    }
                }
                "SUSPEND" | "WAKEUP" | "STOP" | "RESUME" | "RESET" => {
                    log(&format!("qmp: {e}"));
                }
                _ => {}
            }
        }
        if last_note.elapsed() > Duration::from_secs(300) {
            last_note = Instant::now();
            log(&format!("running {:.0}s", start.elapsed().as_secs_f64()));
        }
    }
}

/// The substitute and the `.BEK` for a volume (a device or an image
/// file) into `out`: `region.bin`, `<G>.BEK`, `owned.txt`; with `apply`, a
/// copy of the volume (same size) gets the substitute at all three
/// metadata offsets — what the guest reads, for the libbde and dislocker
/// oracles (DESIGN.md §11 Q10).
pub fn fve_files(volume: &Path, vmk: &Vmk, out: &Path, apply: Option<&Path>) -> R<Value> {
    let f = File::open(volume).map_err(|e| format!("{}: {e}", volume.display()))?;
    let size = match sys::blk_geometry(&f) {
        Ok((s, _)) => s,
        Err(_) => f.metadata().map_err(|e| e.to_string())?.len(),
    };
    let b = read_bitlocker(&f, size)?.ok_or("not a BitLocker volume")?;
    let p = Params::random().map_err(|e| format!("getrandom: {e}"))?;
    let s = fve::substitute(
        &b.header,
        [&b.regions[0], &b.regions[1], &b.regions[2]],
        vmk,
        &p,
    )
    .map_err(|e| e.to_string())?;
    fs::create_dir_all(out).map_err(|e| e.to_string())?;
    fs::write(out.join("region.bin"), &s.region).map_err(|e| e.to_string())?;
    fs::write(out.join(&s.bek_name), &s.bek).map_err(|e| e.to_string())?;
    let owned = fve::owned_ranges(&b.layout);
    let text: String = owned.iter().map(|(a, l)| format!("{a} {l}\n")).collect();
    fs::write(out.join("owned.txt"), text).map_err(|e| e.to_string())?;
    if let Some(copy) = apply {
        let c = OpenOptions::new()
            .write(true)
            .open(copy)
            .map_err(|e| format!("{}: {e}", copy.display()))?;
        for &o in &b.layout.metadata_offsets {
            c.write_all_at(&s.region, o).map_err(|e| e.to_string())?;
        }
    }
    Ok(json!({
        "bek": out.join(&s.bek_name),
        "protector": fve::guid_text(&p.id),
        "owned": owned,
        "metadata_offsets": b.layout.metadata_offsets,
    }))
}

/// Stand-in for the initrd (DESIGN.md §6): the VMK from a recovery
/// password or a `.BEK`, and optionally the decrypted volume registered
/// with the module. Returns the VMK and the volume id.
pub struct Unlocked {
    pub vmk: Vmk,
    pub volume_id: Option<u32>,
    pub plain: Option<PathBuf>,
}

pub fn unlock(
    partition: &Path,
    recovery: Option<&str>,
    bek: Option<&[u8]>,
    volume_add: bool,
) -> R<Unlocked> {
    use paguro_boot::bde::{unlock_fvek, vmk_from_recovery, vmk_from_startup_key};
    let part = File::open(partition).map_err(|e| format!("{}: {e}", partition.display()))?;
    let (size, _) = sys::blk_geometry(&part)?;
    let b = read_bitlocker(&part, size)?.ok_or("not a BitLocker volume")?;
    let hdr = bde::parse_volume_header(&b.header).map_err(|e| format!("{e:?}"))?;
    let blk = bde::cross_check([&b.regions[0], &b.regions[1], &b.regions[2]], &hdr)
        .map_err(|e| format!("{e:?}"))?;
    let m = Metadata::parse(blk).map_err(|e| format!("{e:?}"))?;
    let vmk = if let Some(rp) = recovery {
        let key = paguro_boot::volume::parse_recovery_password(rp.trim().as_bytes())
            .map_err(|e| format!("recovery password: {e:?}"))?;
        vmk_from_recovery(&m, &key).map_err(|e| format!("{e:?}"))?
    } else if let Some(f) = bek {
        let sk = bde::parse_startup_key(f).map_err(|e| format!(".BEK: {e:?}"))?;
        vmk_from_startup_key(&m, &sk).map_err(|e| format!("{e:?}"))?
    } else {
        return Err("a recovery password or a .BEK is needed".into());
    }
    .ok_or("no protector opens the volume with that key")?;
    let fvek = unlock_fvek(&m, &vmk)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("the VMK does not open the FVEK")?;
    if !volume_add {
        return Ok(Unlocked {
            vmk,
            volume_id: None,
            plain: None,
        });
    }
    // The decrypted volume, exactly as the initrd builds it.
    let l = b.layout.fve_layout();
    let segs = paguro_initrd::plan::crypt_segments(size / disk::SECTOR, &l)
        .map_err(|e| format!("layout: {e:?}"))?;
    let (cipher, klen) = paguro_initrd::plan::dm_cipher(fvek.cipher.to_u16()).ok_or("cipher")?;
    if fvek.key().len() != klen {
        return Err("FVEK length".into());
    }
    let desc = format!("paguro:fvek-{}", std::process::id());
    let serial = sys::add_logon_key(&desc, fvek.key())?;
    let raw = devt_of(partition)?;
    let table = paguro_initrd::plan::crypt_table(
        &segs,
        &raw,
        cipher,
        &format!(":{klen}:logon:{desc}"),
        l.sector_size,
    );
    let d = Dm::open()?;
    let r = d.setup("paguro-plain", &table, 0);
    sys::invalidate_key(serial);
    let plain = r?;
    let (pma, pmi) = sys::devno(&plain.node)?;
    let (rma, rmi) = sys::devno(partition)?;
    let reserved = paguro_initrd::plan::reserved_ranges(&l);
    let ctl = paguro_initrd::pg::Ctl::open()?;
    let mut va = paguro_initrd::pg::VolumeAdd {
        raw_major: rma,
        raw_minor: rmi,
        plain_major: pma,
        plain_minor: pmi,
        nreserved: reserved.len() as u32,
        ..Default::default()
    };
    for (slot, &(start, len)) in va.reserved.iter_mut().zip(&reserved) {
        *slot = paguro_initrd::pg::Range { start, len };
    }
    ctl.volume_add(&mut va)?;
    log(&format!(
        "PG_VOLUME_ADD: volume {} ({} sectors, {} segments decrypted)",
        va.volume_id,
        va.sectors,
        segs.len()
    ));
    Ok(Unlocked {
        vmk,
        volume_id: Some(va.volume_id),
        plain: Some(plain.node),
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn agent_framing() {
        let mut b = agent_frame(&json!({"type": "driver", "state": "ok"}));
        let mut two = agent_frame(&json!({"type": "hello"}));
        b.append(&mut two);
        let tail = b.split_off(b.len() - 3);
        let f = agent_frames(&mut b);
        assert_eq!(f.len(), 1);
        assert!(driver_ok(&f[0]));
        b.extend(tail);
        let f = agent_frames(&mut b);
        assert_eq!(f.len(), 1);
        assert!(!driver_ok(&f[0]));
        assert!(b.is_empty());
        let mut junk = vec![0xff, 0xff, 0xff, 0xff, 1, 2];
        assert!(agent_frames(&mut junk).is_empty());
        assert!(junk.is_empty());
    }
}
