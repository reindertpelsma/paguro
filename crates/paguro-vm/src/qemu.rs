//! QEMU's command line for the Windows VM (DESIGN.md §4.5), as pure data.
//!
//! - OVMF without Secure Boot (testsigning lives in the synthetic ESP's
//!   BCD, §12) and a per-machine variable store; no TPM (§6);
//! - the synthesised disk (§4.3) on the bus the host's system disk uses,
//!   `werror=report,rerror=report` so view B's `EIO` reaches the guest
//!   (§11 Q8), the host disk's serial;
//! - the `.BEK` on a removable USB stick (`usb-storage,removable=on`), which
//!   the session hot-unplugs once Windows has booted (§6);
//! - the host's identity (`identity`): SMBIOS table with the marker,
//!   `-uuid`, MSDM/SLIC, `-cpu host` (the hypervisor bit stays set);
//! - a NAT adapter with the host's MAC, and the host-only `paguro0` link
//!   (§5c) — a tap in paguro's network namespace, or (tests) a socket to
//!   the Linux side;
//! - vsock (§5c shells), the agent's virtio-serial port
//!   `org.paguro.agent.0` (INTERFACES.md §11.3; the driver's report, §4.4),
//!   QMP;
//! - the display device from the GPU backend (INTERFACES.md §11.9).
//!
//! Memory is static (`-m`), no balloon yet (§4.5 "later").

use std::path::PathBuf;

use crate::identity::HostIdentity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bus {
    Nvme,
    Ahci,
    Virtio,
}

impl Bus {
    pub fn parse(s: &str) -> Option<Bus> {
        match s {
            "nvme" => Some(Bus::Nvme),
            "ahci" | "sata" => Some(Bus::Ahci),
            "virtio" => Some(Bus::Virtio),
            _ => None,
        }
    }
    /// The bus of the host disk holding the system partition: NVMe stays
    /// NVMe (Windows' boot driver for it is loaded), anything else AHCI.
    pub fn for_host_disk(partition: &str) -> Bus {
        if partition.starts_with("nvme") {
            Bus::Nvme
        } else if partition.starts_with("vd") {
            Bus::Virtio
        } else {
            Bus::Ahci
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DiskSource {
    /// `/dev/mapper/paguro-vmdisk`.
    Device(PathBuf),
    /// An NBD export of it (the split test: the disk stack in one VM,
    /// Windows in another).
    Nbd {
        host: String,
        port: u16,
        export: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HostOnly {
    None,
    /// A tap interface (`paguro0`), moved into paguro's network namespace
    /// once QEMU holds it.
    Tap {
        ifname: String,
    },
    /// A stream socket to the other end of the link (tests).
    Socket {
        path: PathBuf,
    },
}

/// A locally administered MAC for the VM's side of `paguro0` (`02:`, "pg").
pub const HOSTONLY_MAC: &str = "02:70:67:00:00:02";
/// The agent's virtio-serial port (INTERFACES.md §11.3).
pub const AGENT_PORT: &str = "org.paguro.agent.0";
/// Hyper-V enlightenments for a Windows guest; the hypervisor CPUID bit
/// stays set (DESIGN.md §11 Q32).
pub const HV: &str = "hv_relaxed,hv_vapic,hv_spinlocks=0x1fff,hv_vpindex,hv_runtime,hv_synic,hv_stimer,hv_time,hv_frequencies,hv_reset";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmConfig {
    pub name: String,
    pub memory_mib: u64,
    pub cpus: u32,
    pub ovmf_code: PathBuf,
    pub ovmf_vars: PathBuf,
    pub disk: DiskSource,
    pub bus: Bus,
    /// The guest's logical block size: the real disk's.
    pub logical_block: u32,
    /// Record every write to the disk (QEMU `blklogwrites`, the
    /// `dm-log-writes` format) — DESIGN.md §11 Q24's instrument.
    pub record_writes: Option<PathBuf>,
    /// Append to it (every boot after the first: each boot is a new QEMU).
    pub record_append: bool,
    pub bek_image: Option<PathBuf>,
    pub identity: HostIdentity,
    /// Where the SMBIOS blob is written for `-smbios file=`.
    pub smbios_file: PathBuf,
    pub nat_model: String,
    /// `hostfwd` rules on the NAT adapter (tests reach the guest's SSH).
    pub nat_hostfwd: Vec<String>,
    pub hostonly: HostOnly,
    pub hostonly_model: String,
    pub vsock_cid: Option<u32>,
    pub agent_socket: Option<PathBuf>,
    pub qmp_socket: PathBuf,
    pub pidfile: Option<PathBuf>,
    pub gpu_args: Vec<String>,
    pub rtc_localtime: bool,
    pub hv_enlightenments: bool,
    pub vnc: Option<String>,
    pub extra: Vec<String>,
}

fn s(x: &str) -> String {
    x.to_string()
}

fn json(v: serde_json::Value) -> String {
    v.to_string()
}

pub fn argv(c: &VmConfig) -> Vec<String> {
    let mut a = vec![s("qemu-system-x86_64")];
    let mut push = |xs: &[String]| a.extend_from_slice(xs);
    push(&[
        s("-name"),
        format!("{},process={}", c.name, c.name),
        s("-nodefaults"),
        s("-no-user-config"),
        // Paused until the launcher has set view B's tripwire; a guest
        // reboot ends this QEMU so the next boot gets a fresh one, set
        // the same way (DESIGN.md §4.4 "Until the driver arms").
        s("-S"),
        s("-action"),
        s("reboot=shutdown"),
    ]);
    let mut machine = s("q35,accel=kvm,vmport=off");
    if c.identity.smbios3 {
        machine.push_str(",smbios-entry-point-type=64");
    }
    push(&[s("-machine"), machine]);
    let cpu = if c.hv_enlightenments {
        format!("host,{HV}")
    } else {
        s("host")
    };
    push(&[
        s("-cpu"),
        cpu,
        s("-smp"),
        c.cpus.to_string(),
        s("-m"),
        c.memory_mib.to_string(),
    ]);
    push(&[
        s("-rtc"),
        if c.rtc_localtime {
            s("base=localtime,driftfix=slew")
        } else {
            s("base=utc,driftfix=slew")
        },
        s("-global"),
        s("kvm-pit.lost_tick_policy=discard"),
    ]);
    push(&[
        s("-drive"),
        format!(
            "if=pflash,format=raw,unit=0,readonly=on,file={}",
            c.ovmf_code.display()
        ),
        s("-drive"),
        format!("if=pflash,format=raw,unit=1,file={}", c.ovmf_vars.display()),
    ]);

    // Identity.
    push(&[s("-smbios"), format!("file={}", c.smbios_file.display())]);
    if let Some(u) = &c.identity.uuid {
        push(&[s("-uuid"), u.clone()]);
    }
    for t in &c.identity.acpi_tables {
        push(&[s("-acpitable"), format!("file={}", t.display())]);
    }

    // The disk.
    let file = match &c.disk {
        DiskSource::Device(p) => serde_json::json!({
            "driver": "host_device", "filename": p.display().to_string(),
            "node-name": "disk0-file", "cache": {"direct": true, "no-flush": false},
            "aio": "native", "discard": "unmap"
        }),
        DiskSource::Nbd { host, port, export } => serde_json::json!({
            "driver": "nbd", "node-name": "disk0-file", "export": export,
            "server": {"type": "inet", "host": host, "port": port.to_string()},
            // A server stopped by the tripwire must stall the guest's
            // request, not fail it: a failure would reach Windows.
            "reconnect-delay": 3600
        }),
    };
    push(&[s("-blockdev"), json(file)]);
    let top = if let Some(log) = &c.record_writes {
        push(&[
            s("-blockdev"),
            json(
                serde_json::json!({"driver": "raw", "file": "disk0-file", "node-name": "disk0-raw"}),
            ),
            s("-blockdev"),
            json(
                serde_json::json!({"driver": "file", "filename": log.display().to_string(), "node-name": "wlog-file"}),
            ),
            s("-blockdev"),
            json(if c.record_append {
                // An appended log keeps the sector size it was created with;
                // QEMU refuses both options together.
                serde_json::json!({
                    "driver": "blklogwrites", "file": "disk0-raw", "log": "wlog-file",
                    "log-append": true, "node-name": "disk0"
                })
            } else {
                serde_json::json!({
                    "driver": "blklogwrites", "file": "disk0-raw", "log": "wlog-file",
                    "log-sector-size": 512, "log-append": false, "node-name": "disk0"
                })
            }),
        ]);
        "disk0"
    } else {
        push(&[
            s("-blockdev"),
            json(serde_json::json!({"driver": "raw", "file": "disk0-file", "node-name": "disk0"})),
        ]);
        "disk0"
    };
    let serial = c
        .identity
        .disk_serial
        .as_ref()
        .map(|x| format!(",serial={}", x.replace(',', "")))
        .unwrap_or_default();
    let lbs = c.logical_block;
    let dev = match c.bus {
        Bus::Nvme => format!(
            "nvme,drive={top},id=disk0dev,bootindex=0,logical_block_size={lbs},physical_block_size={lbs}{serial}"
        ),
        Bus::Ahci => format!(
            "ide-hd,drive={top},id=disk0dev,bus=ide.0,bootindex=0,rotation_rate=1,werror=report,rerror=report{serial}"
        ),
        Bus::Virtio => format!(
            "virtio-blk-pci,drive={top},id=disk0dev,bootindex=0,werror=report,rerror=report,logical_block_size={lbs},physical_block_size={lbs}{serial}"
        ),
    };
    push(&[s("-device"), dev]);

    // USB: the tablet, and the .BEK stick.
    push(&[
        s("-device"),
        s("qemu-xhci,id=xhci"),
        s("-device"),
        s("usb-tablet,bus=xhci.0"),
    ]);
    if let Some(bek) = &c.bek_image {
        push(&[
            s("-blockdev"),
            json(
                serde_json::json!({"driver": "file", "filename": bek.display().to_string(), "node-name": "bek-file", "read-only": true}),
            ),
            s("-blockdev"),
            json(
                serde_json::json!({"driver": "raw", "file": "bek-file", "node-name": "bek", "read-only": true}),
            ),
            s("-device"),
            s("usb-storage,bus=xhci.0,drive=bek,removable=on,id=paguro-bek"),
        ]);
    }

    // Network: NAT with the host's MAC; the host-only link.
    let mac = c
        .identity
        .mac
        .as_ref()
        .map(|m| format!(",mac={m}"))
        .unwrap_or_default();
    let fwd: String = c
        .nat_hostfwd
        .iter()
        .map(|f| format!(",hostfwd={f}"))
        .collect();
    push(&[
        s("-netdev"),
        format!("user,id=nat{fwd}"),
        s("-device"),
        format!("{},netdev=nat,id=natdev{mac}", c.nat_model),
    ]);
    let ho = match &c.hostonly {
        HostOnly::None => None,
        HostOnly::Tap { ifname } => Some(format!(
            "tap,id=hostonly,ifname={ifname},script=no,downscript=no,vhost=off"
        )),
        HostOnly::Socket { path } => Some(format!(
            "stream,id=hostonly,server=off,addr.type=unix,addr.path={}",
            path.display()
        )),
    };
    if let Some(n) = ho {
        push(&[
            s("-netdev"),
            n,
            s("-device"),
            format!(
                "{},netdev=hostonly,id=hostonlydev,mac={HOSTONLY_MAC}",
                c.hostonly_model
            ),
        ]);
    }
    if let Some(cid) = c.vsock_cid {
        push(&[s("-device"), format!("vhost-vsock-pci,guest-cid={cid}")]);
    }
    if let Some(p) = &c.agent_socket {
        push(&[
            s("-device"),
            s("virtio-serial-pci,id=vser"),
            s("-chardev"),
            format!("socket,id=agent,path={},server=on,wait=off", p.display()),
            s("-device"),
            format!("virtserialport,bus=vser.0,chardev=agent,name={AGENT_PORT}"),
        ]);
    }
    push(&c.gpu_args);
    push(&[s("-display"), s("none")]);
    if let Some(v) = &c.vnc {
        push(&[s("-vnc"), v.clone()]);
    }
    push(&[
        s("-qmp"),
        format!("unix:{},server=on,wait=off", c.qmp_socket.display()),
    ]);
    if let Some(p) = &c.pidfile {
        push(&[s("-pidfile"), p.display().to_string()]);
    }
    push(&c.extra);
    a
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    pub(crate) fn config() -> VmConfig {
        VmConfig {
            name: "paguro-windows".into(),
            memory_mib: 8192,
            cpus: 4,
            ovmf_code: "/usr/share/OVMF/OVMF_CODE_4M.fd".into(),
            ovmf_vars: "/var/lib/paguro/vm/vars.fd".into(),
            disk: DiskSource::Device("/dev/mapper/paguro-vmdisk".into()),
            bus: Bus::Nvme,
            logical_block: 512,
            record_writes: None,
            record_append: false,
            bek_image: Some("/run/paguro/vm/bek.img".into()),
            identity: HostIdentity {
                smbios: vec![],
                smbios3: true,
                uuid: Some("00112233-4455-6677-8899-aabbccddeeff".into()),
                acpi_tables: vec!["/sys/firmware/acpi/tables/MSDM".into()],
                mac: Some("a4:b1:c1:00:11:22".into()),
                disk_serial: Some("S4EWNX0R12345".into()),
                missing: vec![],
            },
            smbios_file: "/run/paguro/vm/smbios.bin".into(),
            nat_model: "virtio-net-pci".into(),
            nat_hostfwd: vec![],
            hostonly: HostOnly::Tap {
                ifname: "paguro0".into(),
            },
            hostonly_model: "virtio-net-pci".into(),
            vsock_cid: Some(3),
            agent_socket: Some("/run/paguro/vm/agent.sock".into()),
            qmp_socket: "/run/paguro/vm/qmp.sock".into(),
            pidfile: None,
            gpu_args: crate::gpu::NoneBackend.qemu_args_default(),
            rtc_localtime: true,
            hv_enlightenments: true,
            vnc: None,
            extra: vec![],
        }
    }

    impl crate::gpu::NoneBackend {
        fn qemu_args_default(&self) -> Vec<String> {
            use crate::gpu::GpuBackend;
            self.qemu_args(&crate::gpu::VmInfo::default())
        }
    }

    fn after<'a>(a: &'a [String], flag: &str) -> Vec<&'a str> {
        a.windows(2)
            .filter(|w| w[0] == flag)
            .map(|w| w[1].as_str())
            .collect()
    }

    #[test]
    fn host_identity_by_default() {
        let a = argv(&config());
        assert_eq!(after(&a, "-cpu")[0].split(',').next(), Some("host"));
        assert!(!after(&a, "-cpu")[0].contains("hypervisor=off"));
        assert_eq!(after(&a, "-uuid"), ["00112233-4455-6677-8899-aabbccddeeff"]);
        assert_eq!(after(&a, "-smbios"), ["file=/run/paguro/vm/smbios.bin"]);
        assert_eq!(
            after(&a, "-acpitable"),
            ["file=/sys/firmware/acpi/tables/MSDM"]
        );
        assert!(after(&a, "-machine")[0].contains("smbios-entry-point-type=64"));
        assert!(
            a.iter().any(|x| x == "-S"),
            "starts paused, for the tripwire"
        );
        assert_eq!(after(&a, "-action"), vec!["reboot=shutdown"]);
        let devs = after(&a, "-device");
        assert!(
            devs.iter()
                .any(|d| d.starts_with("nvme,") && d.ends_with(",serial=S4EWNX0R12345"))
        );
        assert!(
            devs.iter()
                .any(|d| d.starts_with("virtio-net-pci,netdev=nat")
                    && d.ends_with("mac=a4:b1:c1:00:11:22"))
        );
        // NAT, never bridged: the host MAC is on a user-mode netdev
        assert!(after(&a, "-netdev").contains(&"user,id=nat"));
    }

    #[test]
    fn no_tpm_no_secure_boot_marker_and_devices() {
        let a = argv(&config());
        let joined = a.join(" ");
        assert!(!joined.contains("tpm"));
        assert!(!joined.contains("secboot") && !joined.contains("secure=on"));
        assert!(joined.contains("OVMF_CODE_4M.fd"));
        let devs = after(&a, "-device");
        assert!(devs.contains(&"usb-storage,bus=xhci.0,drive=bek,removable=on,id=paguro-bek"));
        assert!(devs.contains(&"vhost-vsock-pci,guest-cid=3"));
        assert!(devs.contains(&"virtserialport,bus=vser.0,chardev=agent,name=org.paguro.agent.0"));
        assert!(devs.iter().any(|d| d.starts_with("VGA,")));
        assert!(
            after(&a, "-netdev")
                .iter()
                .any(|n| n.starts_with("tap,id=hostonly,ifname=paguro0"))
        );
        assert!(!joined.contains("balloon"));
    }

    #[test]
    fn eio_reaches_the_guest() {
        for bus in [Bus::Ahci, Bus::Virtio] {
            let mut c = config();
            c.bus = bus;
            let a = argv(&c);
            let d = after(&a, "-device");
            assert!(d.iter().any(|d| d.contains("drive=disk0") && d.contains("werror=report,rerror=report")), "{bus:?}");
        }
    }

    #[test]
    fn nbd_and_recording() {
        let mut c = config();
        c.disk = DiskSource::Nbd {
            host: "127.0.0.1".into(),
            port: 10809,
            export: "vmdisk".into(),
        };
        c.record_writes = Some("/tmp/w.log".into());
        c.hostonly = HostOnly::Socket {
            path: "/tmp/p0.sock".into(),
        };
        c.vsock_cid = None;
        let a = argv(&c);
        let b = after(&a, "-blockdev");
        let v: serde_json::Value = serde_json::from_str(b[0]).unwrap();
        assert_eq!(v["driver"], "nbd");
        assert_eq!(v["server"]["port"], "10809");
        assert_eq!(
            v["reconnect-delay"], 3600,
            "a stopped server stalls, never fails, the guest"
        );
        assert!(b.iter().any(|x| x.contains("\"blklogwrites\"")));
        c.record_append = true;
        let a2 = argv(&c);
        let appended = after(&a2, "-blockdev");
        let w = appended
            .iter()
            .find(|x| x.contains("blklogwrites"))
            .unwrap();
        assert!(
            w.contains("\"log-append\":true") && !w.contains("log-sector-size"),
            "{w}"
        );
        assert!(after(&a, "-netdev").iter().any(|n| {
            n.starts_with("stream,id=hostonly,server=off,addr.type=unix,addr.path=/tmp/p0.sock")
        }));
        assert!(!a.join(" ").contains("vsock"));
    }

    #[test]
    fn bus_for_host_disk() {
        assert_eq!(Bus::for_host_disk("nvme0n1p3"), Bus::Nvme);
        assert_eq!(Bus::for_host_disk("sda3"), Bus::Ahci);
        assert_eq!(Bus::for_host_disk("vda3"), Bus::Virtio);
    }
}
