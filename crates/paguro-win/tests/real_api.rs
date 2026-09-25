//! Safe real-API tests: they run on a Windows machine (CI's `windows-2022`
//! runner) against Win32 itself. **Nothing here writes a firmware variable,
//! a boot entry or the ESP** — firmware state is only ever read; everything
//! that changes firmware is covered by the mock tests.
//!
//! What is exercised for real: fixed-VHD creation, attach, raw read and
//! detach through virtdisk; retrieval pointers and file IDs on NTFS; volume
//! and partition discovery; the hardware export; the config write protocol
//! on a temp directory; firmware-variable and TPM *reads*.
#![cfg(windows)]
#![allow(clippy::indexing_slicing)]

use paguro_core::guid::EFI_GLOBAL_VARIABLE;
use paguro_win::api::{WinApi, fattr};
use paguro_win::real::RealApi;

fn temp_dir(name: &str) -> String {
    let d = std::env::temp_dir().join(format!("paguro-real-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d.to_string_lossy().into_owned()
}

fn admin(api: &RealApi) -> bool {
    if !api.is_elevated() {
        eprintln!("not elevated: skipping");
        return false;
    }
    true
}

#[test]
fn fixed_vhd_create_attach_inspect_detach() {
    let api = RealApi::new();
    if !admin(&api) {
        return;
    }
    let dir = temp_dir("vhd");
    let path = format!("{dir}\\t.vhd");
    api.vhd_create_fixed(&path, 64 << 20).unwrap();
    let facts = api.file_facts(&path).unwrap().unwrap();
    assert_eq!(facts.len, (64 << 20) + 512);
    assert_eq!(
        facts.attributes & (fattr::SPARSE | fattr::COMPRESSED | fattr::ENCRYPTED),
        0
    );
    assert!(facts.allocated >= facts.len, "fully allocated: {facts:?}");
    let i = paguro_win::cmd::disk::inspect_path(&api, &path).unwrap();
    assert!(i.problems.is_empty(), "{:?}", i.problems);
    assert_eq!(
        i.json["format"], "fixed_vhd",
        "virtdisk's footer is what paguro-core accepts"
    );
    assert_eq!(i.json["payload_len"], 64u64 << 20);
    assert_eq!(i.json["holes"], 0);
    let dev = api.vhd_attach(&path, true).unwrap();
    assert!(
        dev.to_ascii_lowercase().starts_with("\\\\.\\physicaldrive"),
        "{dev}"
    );
    let n: u32 = dev
        .trim_start_matches(|c: char| !c.is_ascii_digit())
        .parse()
        .unwrap();
    let head = api.read_disk(n, 0, 512).unwrap();
    assert_eq!(head, vec![0u8; 512], "a new disk reads as zeros");
    api.vhd_detach(&path).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn retrieval_pointers_cover_an_ntfs_file() {
    let api = RealApi::new();
    let dir = temp_dir("rp");
    let path = format!("{dir}\\data.bin");
    std::fs::write(&path, vec![0x5au8; 3 << 20]).unwrap();
    let e = api.retrieval_pointers(&path).unwrap();
    assert!(e.cluster_size >= 512 && e.cluster_size.is_power_of_two());
    let clusters: u64 = e.extents.iter().map(|x| x.clusters).sum();
    assert!(clusters * u64::from(e.cluster_size) >= 3 << 20, "{e:?}");
    assert!(
        e.extents.iter().all(|x| x.lcn.is_some()),
        "no holes in a written file"
    );
    let f = api.file_facts(&path).unwrap().unwrap();
    assert_ne!(f.file_id, [0; 16]);
    let (rec, _) = paguro_win::cmd::disk::mft_identity(&f.file_id);
    assert!(rec > 0);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn volumes_and_the_system_drive() {
    let api = RealApi::new();
    let vols = api.volumes().unwrap();
    let sys = api.system_drive();
    let c = vols
        .iter()
        .find(|v| v.drive().is_some_and(|d| d.eq_ignore_ascii_case(&sys)))
        .unwrap_or_else(|| panic!("{sys} among {vols:#?}"));
    assert_eq!(c.filesystem, "NTFS");
    let v = api.volume_for_path(&format!("{sys}\\Windows")).unwrap();
    assert_eq!(v.guid_path, c.guid_path);
    if api.firmware_is_uefi() {
        // A UEFI runner has an ESP on a GPT disk (not asserted: some VMs hide it).
        eprintln!(
            "ESPs: {:?}",
            vols.iter()
                .filter(|v| v.is_esp())
                .map(|v| &v.guid_path)
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn hardware_export_on_this_machine() {
    let api = RealApi::new();
    let c = paguro_win::hw::collect(&api).unwrap();
    let h = paguro_win::hw::convert(&c);
    assert_eq!(h.version, 1);
    if cfg!(target_arch = "x86_64") {
        assert!(!h.cpu.vendor.is_empty());
        assert!(h.cpu.family > 0);
    }
    assert!(!c.devices.is_empty(), "SetupAPI found no devices");
    assert!(!h.storage.is_empty(), "no disks");
    let s = serde_json::to_string(&h).unwrap();
    let back: paguro_win::hw::HostHardware = serde_json::from_str(&s).unwrap();
    assert_eq!(back, h);
    eprintln!("{}", serde_json::to_string_pretty(&h).unwrap());
    // Every exported device yields a modalias.
    assert!(paguro_win::hw::modaliases(&h).len() > h.pci.len() + h.usb.len());
}

#[test]
fn config_write_protocol_on_a_temp_dir() {
    let api = RealApi::new();
    let dir = temp_dir("cfg");
    let mut c = paguro_win::cfgfile::OwnedConfig::empty();
    c.entries.push(paguro_win::cfgfile::OwnedEntry {
        name: "debian".into(),
        volume: paguro_core::guid::Guid::parse("6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8").unwrap(),
        root: Some("\\paguro\\debian.vhd".into()),
        efi: paguro_win::cfgfile::OwnedEfi::Disk {
            disk: "\\paguro\\debian.vhd".into(),
            path: "\\EFI\\BOOT\\BOOTX64.EFI".into(),
        },
    });
    c.default = "debian".into();
    let bytes = c.to_bytes().unwrap();
    let p = format!("{dir}\\paguro.ini");
    paguro_win::esp::write_atomic(&api, &p, &bytes).unwrap();
    assert!(api.read_file(&format!("{p}.new"), 1).unwrap().is_none());
    let back = api.read_file(&p, 65536).unwrap().unwrap();
    assert_eq!(back, bytes);
    let parsed = paguro_core::config::parse(&back).unwrap();
    assert_eq!(paguro_win::cfgfile::OwnedConfig::from_core(&parsed), c);
    // Rename replaces an existing file.
    paguro_win::esp::write_atomic(&api, &p, b"x").unwrap();
    assert_eq!(api.read_file(&p, 16).unwrap().unwrap(), b"x");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn firmware_and_tpm_reads_only() {
    let api = RealApi::new();
    if !api.firmware_is_uefi() || !admin(&api) {
        return;
    }
    // Reading is safe; nothing in this file writes a variable.
    let sb = api.fw_get("SecureBoot", &EFI_GLOBAL_VARIABLE).unwrap();
    eprintln!("SecureBoot = {sb:?}");
    let order = api.fw_get("BootOrder", &EFI_GLOBAL_VARIABLE).unwrap();
    assert!(order.is_some_and(|v| v.data.len() % 2 == 0));
    let entries = paguro_win::bootent::list(&api).unwrap();
    assert!(!entries.is_empty());
    assert!(
        api.fw_get("PaguroNoSuchVariable", &paguro_core::guid::PAGURO_VENDOR)
            .unwrap()
            .is_none()
    );
    if api.tpm_present() {
        let pcrs = paguro_win::tpmwin::pcr_read(&api, 1 << 0 | 1 << 7).unwrap();
        assert!(pcrs.get(0).is_some());
        if let Ok(log) = api.tcg_log() {
            eprintln!(
                "secure boot config: {:?}",
                paguro_win::preflight::secure_boot_config(&log)
            );
        }
    }
}

#[test]
fn random_and_cli_status_run() {
    let api = RealApi::new();
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    api.random(&mut a).unwrap();
    api.random(&mut b).unwrap();
    assert_ne!(a, b);
    let r = paguro_win::cli::run(&api, ["paguro", "--json", "status"]);
    assert_eq!(r.code, 0, "{}{}", r.stdout, r.stderr);
    let v: serde_json::Value = serde_json::from_str(&r.stdout).unwrap();
    assert_eq!(v["schema"], "paguro-cli/1");
}
