//! `paguro-vm` — boot the machine's own Windows as a VM (DESIGN.md §4.5).
//!
//! ```text
//! paguro-vm prepare --disk DEV --partition DEV --volume-guid GUID
//!                   (--volume-id N | --view-b DEV) [--vmk-file F]
//!                   --esp-dir DIR [--no-testsigning] --work DIR [--name NAME]
//!     the synthesised disk: /dev/mapper/NAME (default paguro-vmdisk),
//!     <work>/bek.img, <work>/session.json
//! paguro-vm launch --work DIR [--disk-dev DEV | --nbd HOST:PORT/EXPORT]
//!                  [--bek FILE] [--memory MIB] [--cpus N] [--bus nvme|ahci|virtio]
//!                  [--nat-model M] [--nat-hostfwd RULE]... [--hostonly tap:IF|socket:PATH|none]
//!                  [--vsock-cid N | --no-vsock] [--record-writes FILE]
//!                  [--ovmf-code F] [--ovmf-vars F] [--system-partition NAME]
//!                  [--vnc ADDR] [--host-cgroup DIR] [--driver-timeout S]
//!                  [--bek-unplug-after S] [--scope-memory-max SIZE] [--rtc utc]
//!                  [--print-argv]
//!     QEMU with the host's identity; unplugs the .BEK once read
//! paguro-vm teardown --work DIR
//! paguro-vm absorbed --work DIR     what the guest wrote to BitLocker's regions
//! paguro-vm unlock --partition DEV (--recovery-password PW | --bek F)
//!                  --vmk-out F [--volume-add]
//!     stand-in for the initrd: the VMK; with --volume-add the decrypted
//!     volume registered with dm-paguro (prints the volume id)
//! paguro-vm fve --volume DEV|FILE --vmk-file F --out DIR [--apply COPY]
//!     the substitute, the .BEK and the owned ranges (the oracle's input)
//! paguro-vm identity [--system-partition NAME]      what would be passed through
//! paguro-vm windows-provision [--mac MAC]           the guest's link script
//! paguro-vm smb-conf --root DIR --state DIR         the netns Samba's smb.conf
//! paguro-vm samba --root DIR --state DIR --secret-file F   L: over the link
//! paguro-vm mount-c --target DIR --secret-file F [--uid N --gid N]
//! paguro-vm link --ifname IF                        IF into netns paguro as paguro0
//! ```

use std::path::{Path, PathBuf};
use std::process::exit;
use std::time::Duration;

use paguro_core::guid::Guid;
use paguro_vm::qemu::{Bus, DiskSource};
use paguro_vm::session::{self, HostOnlyOpt, LaunchOpts, PrepareOpts, ViewB};
use paguro_vm::{identity, net};

const OVMF_CODE: &str = "/usr/share/OVMF/OVMF_CODE_4M.fd";
const OVMF_VARS: &str = "/usr/share/OVMF/OVMF_VARS_4M.fd";
const DEFAULT_MEMORY_MIB: u64 = 8192;
const DEFAULT_CPUS: u32 = 4;
const DEFAULT_VSOCK_CID: u32 = 3;
const DEFAULT_DRIVER_TIMEOUT: u64 = 60;
const DEFAULT_BEK_UNPLUG: u64 = 30;

fn usage() -> ! {
    let u: Vec<&str> = include_str!("main.rs")
        .lines()
        .skip_while(|l| !l.starts_with("//! ```text"))
        .skip(1)
        .take_while(|l| !l.starts_with("//! ```"))
        .map(|l| l.strip_prefix("//! ").unwrap_or(""))
        .collect();
    eprintln!("usage:\n{}", u.join("\n"));
    exit(2)
}

struct Args {
    it: std::vec::IntoIter<String>,
}

impl Args {
    fn val(&mut self, k: &str) -> String {
        self.it.next().unwrap_or_else(|| {
            eprintln!("paguro-vm: {k} needs a value");
            exit(2)
        })
    }
    fn num<T: std::str::FromStr>(&mut self, k: &str) -> T {
        let v = self.val(k);
        v.parse().unwrap_or_else(|_| {
            eprintln!("paguro-vm: {k}: not a number: {v}");
            exit(2)
        })
    }
}

fn fail(e: String) -> ! {
    session::log(&format!("error: {e}"));
    exit(1)
}

fn read_secret(p: &Path) -> String {
    std::fs::read_to_string(p)
        .unwrap_or_else(|e| fail(format!("{}: {e}", p.display())))
        .trim()
        .to_string()
}

fn main() {
    let mut all: Vec<String> = std::env::args().skip(1).collect();
    if all.is_empty() {
        usage();
    }
    let cmd = all.remove(0);
    let mut a = Args {
        it: all.into_iter(),
    };
    match cmd.as_str() {
        "prepare" => {
            let (mut disk, mut part, mut guid, mut vid, mut vb, mut vmk, mut esp, mut work) =
                (None, None, None, None, None, None, None, None);
            let mut ts = true;
            let mut name = "paguro-vmdisk".to_string();
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--disk" => disk = Some(PathBuf::from(a.val(&k))),
                    "--partition" => part = Some(PathBuf::from(a.val(&k))),
                    "--volume-guid" => {
                        guid = Some(
                            Guid::parse(a.val(&k).trim_matches(['{', '}']))
                                .unwrap_or_else(|_| usage()),
                        )
                    }
                    "--volume-id" => vid = Some(a.num::<u32>(&k)),
                    "--view-b" => vb = Some(PathBuf::from(a.val(&k))),
                    "--vmk-file" => vmk = Some(PathBuf::from(a.val(&k))),
                    "--esp-dir" => esp = Some(PathBuf::from(a.val(&k))),
                    "--no-testsigning" => ts = false,
                    "--work" => work = Some(PathBuf::from(a.val(&k))),
                    "--name" => name = a.val(&k),
                    _ => usage(),
                }
            }
            let vmk = vmk.map(|p| {
                let b = std::fs::read(&p).unwrap_or_else(|e| fail(format!("{}: {e}", p.display())));
                <[u8; 32]>::try_from(b.as_slice())
                    .unwrap_or_else(|_| fail("VMK file: 32 bytes".into()))
            });
            let o = PrepareOpts {
                disk: disk.unwrap_or_else(|| usage()),
                partition: part.unwrap_or_else(|| usage()),
                volume_guid: guid.unwrap_or_else(|| usage()),
                view_b: match (vid, vb) {
                    (Some(i), None) => ViewB::Volume(i),
                    (None, Some(p)) => ViewB::Device(p),
                    _ => usage(),
                },
                vmk,
                esp_dir: esp.unwrap_or_else(|| usage()),
                testsigning: ts,
                work: work.unwrap_or_else(|| usage()),
                name,
            };
            match session::prepare(&o) {
                Ok(s) => println!("{}", serde_json::to_string_pretty(&s).unwrap_or_default()),
                Err(e) => fail(e),
            }
        }
        "teardown" => {
            let mut work = None;
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--work" => work = Some(PathBuf::from(a.val(&k))),
                    _ => usage(),
                }
            }
            session::teardown(&work.unwrap_or_else(|| usage())).unwrap_or_else(|e| fail(e));
        }
        "launch" => launch(a),
        "absorbed" => {
            let mut work = None;
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--work" => work = Some(PathBuf::from(a.val(&k))),
                    _ => usage(),
                }
            }
            let w = session::absorbed_writes(&work.unwrap_or_else(|| usage()))
                .unwrap_or_else(|e| fail(e));
            println!("{}", serde_json::to_string(&w).unwrap_or_default());
        }
        "unlock" => {
            let (mut part, mut rp, mut bek, mut out) = (None, None, None, None);
            let mut add = false;
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--partition" => part = Some(PathBuf::from(a.val(&k))),
                    "--recovery-password" => rp = Some(a.val(&k)),
                    "--recovery-password-file" => rp = Some(read_secret(Path::new(&a.val(&k)))),
                    "--bek" => bek = Some(PathBuf::from(a.val(&k))),
                    "--vmk-out" => out = Some(PathBuf::from(a.val(&k))),
                    "--volume-add" => add = true,
                    _ => usage(),
                }
            }
            let bek = bek.map(|p| {
                std::fs::read(&p).unwrap_or_else(|e| fail(format!("{}: {e}", p.display())))
            });
            let u = session::unlock(
                &part.unwrap_or_else(|| usage()),
                rp.as_deref(),
                bek.as_deref(),
                add,
            )
            .unwrap_or_else(|e| fail(e));
            let out = out.unwrap_or_else(|| usage());
            {
                use std::io::Write;
                use std::os::unix::fs::OpenOptionsExt;
                let mut f = std::fs::OpenOptions::new()
                    .create(true)
                    .truncate(true)
                    .write(true)
                    .mode(0o600)
                    .open(&out)
                    .unwrap_or_else(|e| fail(format!("{}: {e}", out.display())));
                f.write_all(&u.vmk).unwrap_or_else(|e| fail(e.to_string()));
            }
            if let Some(id) = u.volume_id {
                println!("{id}");
            }
        }
        "fve" => {
            let (mut vol, mut vmk, mut out, mut apply) = (None, None, None, None);
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--volume" => vol = Some(PathBuf::from(a.val(&k))),
                    "--vmk-file" => vmk = Some(PathBuf::from(a.val(&k))),
                    "--vmk-hex" => {
                        let h = a.val(&k);
                        let b: Vec<u8> = (0..h.len() / 2)
                            .filter_map(|i| {
                                h.get(2 * i..2 * i + 2)
                                    .and_then(|x| u8::from_str_radix(x, 16).ok())
                            })
                            .collect();
                        let p = std::env::temp_dir()
                            .join(format!("paguro-vm-vmk-{}", std::process::id()));
                        std::fs::write(&p, b).unwrap_or_else(|e| fail(e.to_string()));
                        vmk = Some(p);
                    }
                    "--out" => out = Some(PathBuf::from(a.val(&k))),
                    "--apply" => apply = Some(PathBuf::from(a.val(&k))),
                    _ => usage(),
                }
            }
            let vp = vmk.unwrap_or_else(|| usage());
            let v = std::fs::read(&vp).unwrap_or_else(|e| fail(format!("{}: {e}", vp.display())));
            if vp.starts_with(std::env::temp_dir()) {
                let _ = std::fs::remove_file(&vp);
            }
            let v =
                <[u8; 32]>::try_from(v.as_slice()).unwrap_or_else(|_| fail("VMK: 32 bytes".into()));
            match session::fve_files(
                &vol.unwrap_or_else(|| usage()),
                &v,
                &out.unwrap_or_else(|| usage()),
                apply.as_deref(),
            ) {
                Ok(s) => println!("{s}"),
                Err(e) => fail(e),
            }
        }
        "identity" => {
            let mut sp = None;
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--system-partition" => sp = Some(a.val(&k)),
                    _ => usage(),
                }
            }
            let id = identity::read_host(Path::new("/"), sp.as_deref(), identity::MARKER);
            println!(
                "{}",
                serde_json::json!({
                    "smbios_bytes": id.smbios.len(),
                    "smbios3": id.smbios3,
                    "uuid": id.uuid,
                    "acpi_tables": id.acpi_tables,
                    "mac": id.mac,
                    "disk_serial": id.disk_serial,
                    "missing": id.missing,
                })
            );
        }
        "windows-provision" => {
            let mut mac = paguro_vm::qemu::HOSTONLY_MAC.to_string();
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--mac" => mac = a.val(&k),
                    _ => usage(),
                }
            }
            print!("{}", net::windows_provision_ps1(&mac));
        }
        "smb-conf" => {
            let (mut root, mut state) = (None, None);
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--root" => root = Some(PathBuf::from(a.val(&k))),
                    "--state" => state = Some(PathBuf::from(a.val(&k))),
                    _ => usage(),
                }
            }
            print!(
                "{}",
                net::smb_conf(
                    &root.unwrap_or_else(|| usage()),
                    &state.unwrap_or_else(|| usage())
                )
            );
        }
        "samba" => {
            let (mut root, mut state, mut secret) = (None, None, None);
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--root" => root = Some(PathBuf::from(a.val(&k))),
                    "--state" => state = Some(PathBuf::from(a.val(&k))),
                    "--secret-file" => secret = Some(read_secret(Path::new(&a.val(&k)))),
                    _ => usage(),
                }
            }
            net::start_samba(
                &root.unwrap_or_else(|| usage()),
                &state.unwrap_or_else(|| usage()),
                &secret.unwrap_or_else(|| usage()),
            )
            .unwrap_or_else(|e| fail(e));
        }
        "mount-c" => {
            let (mut target, mut secret) = (None, None);
            let (mut uid, mut gid) = (0u32, 0u32);
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--target" => target = Some(PathBuf::from(a.val(&k))),
                    "--secret-file" => secret = Some(read_secret(Path::new(&a.val(&k)))),
                    "--uid" => uid = a.num(&k),
                    "--gid" => gid = a.num(&k),
                    _ => usage(),
                }
            }
            net::mount_c(
                &target.unwrap_or_else(|| usage()),
                &secret.unwrap_or_else(|| usage()),
                uid,
                gid,
            )
            .unwrap_or_else(|e| fail(e));
        }
        "link" => {
            let mut ifname = None;
            while let Some(k) = a.it.next() {
                match k.as_str() {
                    "--ifname" => ifname = Some(a.val(&k)),
                    _ => usage(),
                }
            }
            net::ensure_netns().unwrap_or_else(|e| fail(e));
            net::attach_link(&ifname.unwrap_or_else(|| usage())).unwrap_or_else(|e| fail(e));
        }
        _ => usage(),
    }
}

fn launch(mut a: Args) {
    let mut o = LaunchOpts {
        work: PathBuf::new(),
        disk: DiskSource::Device("/dev/mapper/paguro-vmdisk".into()),
        bek_image: None,
        block_size: 0,
        memory_mib: DEFAULT_MEMORY_MIB,
        cpus: DEFAULT_CPUS,
        bus: Bus::Nvme,
        nat_model: "virtio-net-pci".into(),
        nat_hostfwd: Vec::new(),
        hostonly: HostOnlyOpt::Tap(net::IFNAME.into()),
        hostonly_model: "virtio-net-pci".into(),
        vsock_cid: Some(DEFAULT_VSOCK_CID),
        record_writes: None,
        ovmf_code: OVMF_CODE.into(),
        ovmf_vars_template: OVMF_VARS.into(),
        ovmf_vars: PathBuf::new(),
        system_partition: None,
        sysroot: "/".into(),
        vnc: None,
        host_cgroup: None,
        driver_timeout: Some(Duration::from_secs(DEFAULT_DRIVER_TIMEOUT)),
        bek_unplug_after: Duration::from_secs(DEFAULT_BEK_UNPLUG),
        print_argv: false,
        scope_memory_max: None,
        rtc_localtime: true,
        extra: Vec::new(),
    };
    let mut bus_set = false;
    let mut vars = None;
    while let Some(k) = a.it.next() {
        match k.as_str() {
            "--work" => o.work = PathBuf::from(a.val(&k)),
            "--disk-dev" => o.disk = DiskSource::Device(PathBuf::from(a.val(&k))),
            "--nbd" => {
                let v = a.val(&k);
                let (hp, export) = v.split_once('/').unwrap_or((v.as_str(), ""));
                let (host, port) = hp.rsplit_once(':').unwrap_or_else(|| usage());
                o.disk = DiskSource::Nbd {
                    host: host.into(),
                    port: port.parse().unwrap_or_else(|_| usage()),
                    export: export.into(),
                };
            }
            "--bek" => o.bek_image = Some(PathBuf::from(a.val(&k))),
            "--memory" => o.memory_mib = a.num(&k),
            "--cpus" => o.cpus = a.num(&k),
            "--bus" => {
                o.bus = Bus::parse(&a.val(&k)).unwrap_or_else(|| usage());
                bus_set = true;
            }
            "--nat-model" => o.nat_model = a.val(&k),
            "--nat-hostfwd" => o.nat_hostfwd.push(a.val(&k)),
            "--hostonly" => {
                let v = a.val(&k);
                o.hostonly = if v == "none" {
                    HostOnlyOpt::None
                } else if let Some(i) = v.strip_prefix("tap:") {
                    HostOnlyOpt::Tap(i.into())
                } else if let Some(p) = v.strip_prefix("socket:") {
                    HostOnlyOpt::Socket(p.into())
                } else {
                    usage()
                };
            }
            "--hostonly-model" => o.hostonly_model = a.val(&k),
            "--vsock-cid" => o.vsock_cid = Some(a.num(&k)),
            "--no-vsock" => o.vsock_cid = None,
            "--record-writes" => o.record_writes = Some(PathBuf::from(a.val(&k))),
            "--ovmf-code" => o.ovmf_code = PathBuf::from(a.val(&k)),
            "--ovmf-vars-template" => o.ovmf_vars_template = PathBuf::from(a.val(&k)),
            "--ovmf-vars" => vars = Some(PathBuf::from(a.val(&k))),
            "--system-partition" => o.system_partition = Some(a.val(&k)),
            "--sysroot" => o.sysroot = PathBuf::from(a.val(&k)),
            "--vnc" => o.vnc = Some(a.val(&k)),
            "--host-cgroup" => o.host_cgroup = Some(PathBuf::from(a.val(&k))),
            "--driver-timeout" => {
                let s: u64 = a.num(&k);
                o.driver_timeout = (s > 0).then(|| Duration::from_secs(s));
            }
            "--bek-unplug-after" => o.bek_unplug_after = Duration::from_secs(a.num(&k)),
            "--scope-memory-max" => o.scope_memory_max = Some(a.val(&k)),
            "--rtc" => o.rtc_localtime = a.val(&k) != "utc",
            "--print-argv" => o.print_argv = true,
            "--" => o.extra.extend(a.it.by_ref()),
            _ => usage(),
        }
    }
    if o.work.as_os_str().is_empty() {
        usage();
    }
    // What `prepare` recorded, unless given.
    if let Ok(s) = session::read_session(&o.work) {
        if o.bek_image.is_none() {
            o.bek_image = s
                .get("bek_image")
                .and_then(|v| v.as_str())
                .map(PathBuf::from);
        }
        if o.block_size == 0 {
            o.block_size = s.get("block_size").and_then(|v| v.as_u64()).unwrap_or(512) as u32;
        }
    }
    if o.block_size == 0 {
        o.block_size = 512;
    }
    if !bus_set {
        if let Some(p) = &o.system_partition {
            o.bus = Bus::for_host_disk(p);
        }
    }
    o.ovmf_vars = vars.unwrap_or_else(|| o.work.join("vars.fd"));
    session::launch(&o).unwrap_or_else(|e| fail(e));
}
