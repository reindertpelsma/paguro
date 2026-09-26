//! Every command of `paguro.exe`, end to end through the CLI parser and the
//! `--json` envelope, against the in-memory Windows machine. What the
//! commands write is checked with `paguro-core`'s parsers and, for key
//! material, with the loader's own derivations (`paguro-crypto`,
//! `paguro-boot`) against Windows-made BitLocker fixtures.
#![allow(clippy::indexing_slicing)]

mod common;

use common::*;
use paguro_core::guid::{EFI_GLOBAL_VARIABLE, Guid, PAGURO_VENDOR};
use paguro_core::{bootstrap, config, efisig, seal};
use paguro_win::api::{Extent, Extents, PnpDevice, WinApi, attr, fattr};
use paguro_win::mock::{ESP_PATH, MockApi, MockFile};
use sha2::{Digest, Sha256};

fn esp_file(name: &str) -> String {
    format!("{ESP_PATH}EFI\\paguro\\{name}")
}

fn vhd(m: &MockApi, path: &str, size: u64) {
    let mut f = MockFile::zeros(size + 512);
    f.write_at(size, &paguro_win::mock::fixed_vhd_footer(size));
    m.put_mock_file(path, f);
}

/// A machine with ESP files, a valid paguro.ini for `C:\paguro\debian.vhd`
/// (hash in firmware) and the image itself.
fn installed() -> MockApi {
    let m = MockApi::standard();
    install_esp(&m);
    vhd(&m, "C:\\paguro\\debian.vhd", 64 << 20);
    ok(
        &m,
        &[
            "config",
            "set",
            "--entry",
            "debian",
            "--root",
            "C:\\paguro\\debian.vhd",
        ],
    );
    m
}

// ---- the envelope ------------------------------------------------------------

#[test]
fn usage_errors_are_exit_2_and_help_is_0() {
    let m = MockApi::standard();
    assert_eq!(run(&m, &["frobnicate"]).code, 2);
    assert_eq!(run(&m, &["disk", "create"]).code, 2);
    let h = paguro_win::cli::run(&m, ["paguro", "--help"]);
    assert_eq!(h.code, 0);
    assert!(h.stdout.contains("restart-linux"));
}

#[test]
fn junk_arguments_never_panic() {
    let m = MockApi::standard();
    let words = [
        "status",
        "disk",
        "create",
        "inspect",
        "--size",
        "0",
        "-1",
        "99999999999T",
        "--path",
        "",
        "\\\\?\\",
        "C:",
        "config",
        "set",
        "--entry",
        "é",
        "--root",
        "efi",
        "vars",
        "get",
        "PaguroB",
        "set",
        "zz",
        "boot-entry",
        "delete",
        "FFFFF",
        "bootnext",
        "mok",
        "enroll",
        "--cert",
        "uninstall",
        "--yes",
        "--dry-run",
        "install",
        "x",
        "hw",
        "modalias",
        "esp",
        "repair",
        "--json",
        "\u{0}",
    ];
    let mut seed = 0x1234_5678_u64;
    for _ in 0..400 {
        let mut args = vec!["paguro"];
        for _ in 0..(seed % 6) {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            args.push(words[(seed >> 33) as usize % words.len()]);
        }
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            paguro_win::cli::run(&m, args.clone())
        }));
        assert!(r.is_ok(), "panicked on {args:?}");
    }
}

#[test]
fn writes_need_elevation() {
    let m = MockApi::standard();
    m.elevated.set(false);
    let r = run(&m, &["efi", "vars", "set", "PaguroTpmBroken", "01"]);
    assert_eq!(r.code, 7);
    assert_eq!(r.json["error"]["code"], "needs_elevation");
    assert!(m.mutations.borrow().is_empty());
}

// ---- status ------------------------------------------------------------------

#[test]
fn status_on_a_bare_machine_and_an_installed_one() {
    let m = MockApi::standard();
    let d = ok(&m, &["status"]);
    assert_eq!(d["uefi"], true);
    assert_eq!(d["firmware"]["secure_boot"], true);
    assert_eq!(d["esp"]["volume"], ESP_PATH);
    assert_eq!(d["config"]["present"], false);
    assert_eq!(d["preflight"]["ready"], false);
    assert!(
        m.mutations.borrow().iter().all(|x| x.starts_with("run ")),
        "status only reads: {:?}",
        m.mutations.borrow()
    );

    let m = installed();
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    let d = ok(&m, &["status"]);
    assert_eq!(d["config"]["valid"], true);
    assert_eq!(d["config"]["hash_matches"], true);
    assert_eq!(d["images"][0]["file"]["format"], "fixed_vhd");
    assert_eq!(d["images"][0]["windows_path"], "C:\\paguro\\debian.vhd");
    assert_eq!(d["preflight"]["ready"], true, "{}", d["preflight"]);
}

// ---- hw export ---------------------------------------------------------------

fn smbios_blob() -> Vec<u8> {
    fn st(kind: u8, fmt: &[u8], strings: &[&str]) -> Vec<u8> {
        let mut v = vec![kind, 4 + fmt.len() as u8, 0, 0];
        v.extend_from_slice(fmt);
        for s in strings {
            v.extend_from_slice(s.as_bytes());
            v.push(0);
        }
        v.push(0);
        if strings.is_empty() {
            v.push(0);
        }
        v
    }
    let t = [
        st(0, &[1, 2], &["LENOVO", "N3HET80W (1.52 )"]),
        st(1, &[1, 2, 0, 3], &["LENOVO", "20QDCTO1WW", "PF-SECRET"]),
        st(2, &[1, 2], &["LENOVO", "20QDCTO1WW"]),
        st(127, &[], &[]),
    ]
    .concat();
    let mut b = vec![0, 3, 2, 0];
    b.extend_from_slice(&(t.len() as u32).to_le_bytes());
    b.extend_from_slice(&t);
    b
}

fn pnp(ids: &[&str], compat: &[&str]) -> PnpDevice {
    PnpDevice {
        instance_id: ids[0].into(),
        hardware_ids: ids.iter().map(|s| s.to_string()).collect(),
        compatible_ids: compat.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn hw_export_is_interfaces_11_5() {
    let m = MockApi::standard();
    *m.smbios_blob.borrow_mut() = smbios_blob();
    m.cpuid_leaves
        .borrow_mut()
        .insert((0, 0), [0x20, 0x756e_6547, 0x6c65_746e, 0x4965_6e69]);
    m.cpuid_leaves
        .borrow_mut()
        .insert((1, 0), [0x000A_06A4, 0, 0, 0]);
    m.pnp.borrow_mut().extend([
        pnp(
            &[
                "PCI\\VEN_10DE&DEV_28A0&SUBSYS_1F3A1043&REV_A1",
                "PCI\\VEN_10DE&DEV_28A0",
            ],
            &["PCI\\VEN_10DE&CC_030000", "PCI\\CC_0300"],
        ),
        pnp(
            &["USB\\VID_8087&PID_0033&REV_0000"],
            &["USB\\Class_e0&SubClass_01&Prot_01", "USB\\Class_e0"],
        ),
        pnp(
            &["USB\\VID_046D&PID_C52B&REV_2400&MI_00"],
            &["USB\\Class_03&SubClass_01&Prot_01"],
        ),
        pnp(&["ACPI\\PNP0C50"], &["*PNP0C50"]),
        pnp(&["ACPI\\VEN_INT&DEV_33D2"], &[]),
        pnp(&["ACPI\\PNP0C50"], &[]),
        pnp(&["ROOT\\LEGACY_FOO"], &[]),
    ]);
    let d = ok(
        &m,
        &["hw", "export", "--output", "C:\\ProgramData\\hh.json"],
    );
    let want = serde_json::json!({
        "version": 1,
        "cpu": { "vendor": "GenuineIntel", "family": 6, "model": 170, "stepping": 4 },
        "dmi": { "sys_vendor": "LENOVO", "product_name": "20QDCTO1WW", "board_vendor": "LENOVO",
                 "board_name": "20QDCTO1WW", "bios_vendor": "LENOVO", "bios_version": "N3HET80W (1.52 )" },
        "pci": [ { "vendor": "10de", "device": "28a0", "subvendor": "1043", "subdevice": "1f3a", "class": "030000" } ],
        "usb": [ { "vendor": "8087", "product": "0033", "class": "e0" } ],
        "acpi": [ "PNP0C50", "INT33D2" ],
        "storage": [ { "bus": "nvme", "model": "Mock NVMe 1TB", "size": 1_000_204_886_016u64 } ],
    });
    assert_eq!(d, want);
    let written: serde_json::Value =
        serde_json::from_slice(&m.file("C:\\ProgramData\\hh.json").unwrap()).unwrap();
    assert_eq!(written, want);
    assert!(
        !String::from_utf8_lossy(&m.file("C:\\ProgramData\\hh.json").unwrap()).contains("SECRET"),
        "no serials"
    );
    let d = ok(&m, &["hw", "modalias", "C:\\ProgramData\\hh.json"]);
    let ma: Vec<&str> = d["modaliases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(
        ma[0],
        "pci:v000010DEd000028A0sv00001043sd00001F3Abc03sc00i00"
    );
    assert_eq!(ma[1], "usb:v8087p0033d0000dcE0dsc00dp00ic00isc00ip00in00");
    assert_eq!(ma[2], "acpi:PNP0C50:");
    assert!(ma[4].starts_with("dmi:bvnLENOVO:bvrN3HET80W(1.52):"));
}

#[test]
fn hw_export_dry_run_writes_nothing() {
    let m = MockApi::standard();
    let r = run(
        &m,
        &[
            "--dry-run",
            "hw",
            "export",
            "-o",
            "C:\\ProgramData\\hh.json",
        ],
    );
    assert_eq!(r.code, 0);
    assert!(!m.exists("C:\\ProgramData\\hh.json"));
    assert!(r.json["warnings"][0].as_str().unwrap().contains("SMBIOS"));
}

// ---- disk --------------------------------------------------------------------

#[test]
fn disk_create_makes_a_verified_fixed_vhd() {
    let m = MockApi::standard();
    let d = ok(
        &m,
        &[
            "disk",
            "create",
            "--size",
            "1G",
            "--path",
            "C:\\paguro\\a.vhd",
        ],
    );
    assert_eq!(d["format"], "fixed_vhd");
    assert_eq!(d["payload_len"], 1u64 << 30);
    assert_eq!(d["holes"], 0);
    let facts = m.file_facts("C:\\paguro\\a.vhd").unwrap().unwrap();
    assert_eq!(facts.len, (1 << 30) + 512);
    // Never overwrite.
    let r = run(
        &m,
        &[
            "disk",
            "create",
            "--size",
            "1G",
            "--path",
            "C:\\paguro\\a.vhd",
        ],
    );
    assert_eq!(r.code, 3);
}

#[test]
fn disk_create_refusals_and_dry_run() {
    let m = MockApi::standard();
    for (size, path) in [
        ("1000", "C:\\x.vhd"),
        ("65M", "C:\\x.vhdx"),
        ("63M", "C:\\x.vhd"),
        ("100G", "C:\\x.vhdx"),
        ("300G", "C:\\x.vhd"),
        ("1G", &format!("{ESP_PATH}x.vhd")),
    ] {
        let r = run(&m, &["disk", "create", "--size", size, "--path", path]);
        assert_eq!(r.code, 3, "{size} {path}: {}", r.stdout);
    }
    let r = run(
        &m,
        &[
            "--dry-run",
            "disk",
            "create",
            "--size",
            "2G",
            "--path",
            "C:\\x.vhd",
        ],
    );
    assert_eq!(r.code, 0);
    assert_eq!(r.json["dry_run"], true);
    assert!(m.mutations.borrow().is_empty());
}

#[test]
fn disk_inspect_refuses_what_the_module_cannot_map() {
    let m = MockApi::standard();
    vhd(&m, "C:\\ok.vhd", 64 << 20);
    ok(&m, &["disk", "inspect", "C:\\ok.vhd"]);
    for (attr_bits, why) in [
        (fattr::SPARSE, "sparse"),
        (fattr::COMPRESSED, "compressed"),
        (fattr::ENCRYPTED, "EFS"),
    ] {
        let mut f = MockFile::zeros(64 << 20);
        f.attributes |= attr_bits;
        m.put_mock_file("C:\\bad.vhd", f);
        let r = run(&m, &["disk", "inspect", "C:\\bad.vhd"]);
        assert_eq!(r.code, 6, "{why}");
        assert!(r.json["error"]["message"].as_str().unwrap().contains(why));
    }
    let mut f = MockFile::zeros(1 << 20);
    f.extents = Some(Extents {
        cluster_size: 4096,
        extents: vec![
            Extent {
                vcn: 0,
                lcn: Some(10),
                clusters: 128,
            },
            Extent {
                vcn: 128,
                lcn: None,
                clusters: 128,
            },
        ],
    });
    m.put_mock_file("C:\\holes.img", f);
    let r = run(&m, &["disk", "inspect", "C:\\holes.img"]);
    assert_eq!(r.code, 6);
    assert_eq!(r.json["error"]["data"]["holes"], 1);
    assert_eq!(r.json["error"]["data"]["format"], "raw");
    assert_eq!(run(&m, &["disk", "inspect", "C:\\none"]).code, 4);
}

#[test]
fn disk_inspect_finds_the_uefi_file_system() {
    let m = MockApi::standard();
    let mut f = MockFile::zeros(64 << 20);
    f.write_at(
        0,
        &paguro_core::disk::build::fat32_boot_sector((64 << 20) / 512),
    );
    m.put_mock_file("C:\\esp.img", f);
    let d = ok(&m, &["disk", "inspect", "C:\\esp.img"]);
    assert_eq!(d["efi_fs"]["kind"], "superfloppy");
}

// ---- config ------------------------------------------------------------------

#[test]
fn config_set_writes_the_file_and_its_hash() {
    let m = MockApi::standard();
    vhd(&m, "C:\\paguro\\debian.vhd", 64 << 20);
    let d = ok(
        &m,
        &[
            "config",
            "set",
            "--entry",
            "debian",
            "--root",
            "C:\\paguro\\debian.vhd",
        ],
    );
    assert_eq!(d["changes"][0], "added [Boot.debian]");
    let ini = m.file(&esp_file("paguro.ini")).unwrap();
    let c = config::parse(&ini).unwrap();
    let e = c.default_entry().unwrap();
    assert_eq!(e.name, "debian");
    assert_eq!(e.volume, c_guid());
    assert_eq!(e.root, Some("\\paguro\\debian.vhd"));
    assert_eq!(
        e.efi,
        config::Efi::Disk {
            disk: "\\paguro\\debian.vhd",
            path: "\\EFI\\BOOT\\BOOTX64.EFI"
        }
    );
    let h: [u8; 32] = Sha256::digest(&ini).into();
    assert_eq!(m.var("PaguroConfigHash", &PAGURO_VENDOR).unwrap(), h);
    assert!(!m.exists(&esp_file("paguro.ini.new")));
    ok(&m, &["config", "validate"]);

    // Second edit keeps a .bak and warns about the seal.
    let r = run(&m, &["config", "set", "--tpm", "0", "--theme", "light"]);
    assert_eq!(r.code, 0);
    assert!(
        r.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("stage-setup")
    );
    assert_eq!(m.file(&esp_file("paguro.ini.bak")).unwrap(), ini);
    let c2 = m.file(&esp_file("paguro.ini")).unwrap();
    let p = config::parse(&c2).unwrap();
    assert!(!p.tpm);
    assert_eq!(p.ui.theme, config::UiTheme::Light);

    // An efi_file entry and a default switch, then a removal.
    m.put_file("C:\\paguro\\rescue.efi", b"MZ");
    ok(
        &m,
        &[
            "config",
            "set",
            "--entry",
            "rescue",
            "--efi-file",
            "C:\\paguro\\rescue.efi",
            "--default",
            "rescue",
        ],
    );
    let ini3 = m.file(&esp_file("paguro.ini")).unwrap();
    let c3 = config::parse(&ini3).unwrap();
    assert_eq!(
        c3.default_entry().unwrap().efi,
        config::Efi::File("\\paguro\\rescue.efi")
    );
    ok(&m, &["config", "set", "--remove-entry", "rescue"]);
    let s = ok(&m, &["config", "show"]);
    assert_eq!(s["config"]["default"], "debian");
    assert_eq!(s["hash_matches"], true);
}

#[test]
fn config_refusals() {
    let m = MockApi::standard();
    let before = m.mutations.borrow().len();
    for args in [
        vec!["config", "set", "--root", "C:\\x.vhd"], // no --entry
        vec![
            "config",
            "set",
            "--entry",
            "bad name",
            "--root",
            "C:\\x.vhd",
        ], // name
        vec!["config", "set", "--entry", "a", "--root", "\\x.vhd"], // no volume
        vec![
            "config",
            "set",
            "--entry",
            "a",
            "--root",
            "C:\\x.vhd",
            "--efi-file",
            "C:\\y.efi",
            "--efi",
            "\\a",
        ],
        vec![
            "config",
            "set",
            "--entry",
            "a",
            "--root",
            &format!("{ESP_PATH}x.vhd"),
        ], // not NTFS
        vec!["config", "set", "--default", "nothere"],
        vec!["config", "set", "--tpm", "maybe"],
    ] {
        let r = run(&m, &args);
        assert_ne!(r.code, 0, "{args:?}");
    }
    assert_eq!(m.mutations.borrow().len(), before);
    assert_eq!(run(&m, &["config", "show"]).code, 4);
}

#[test]
fn config_validate_catches_a_stale_hash_and_missing_files() {
    let m = installed();
    m.set_var_raw("PaguroConfigHash", &PAGURO_VENDOR, &[0; 32], attr::NV_BS_RT);
    let r = run(&m, &["config", "validate"]);
    assert_eq!(r.code, 6);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not match")
    );
    let m = installed();
    m.remove_file("C:\\paguro\\debian.vhd").unwrap();
    let r = run(&m, &["config", "validate"]);
    assert_eq!(r.code, 6);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("does not exist")
    );
}

#[test]
fn config_dry_run_changes_nothing() {
    let m = installed();
    m.mutations.borrow_mut().clear();
    let r = run(&m, &["--dry-run", "config", "set", "--passphrase", "1"]);
    assert_eq!(r.code, 0);
    assert_eq!(r.json["data"]["written"], false);
    assert!(m.mutations.borrow().is_empty());
}

// ---- efi -----------------------------------------------------------------------

#[test]
fn efi_vars_never_show_key_material() {
    let m = MockApi::standard();
    m.set_var_raw("PaguroSetup", &PAGURO_VENDOR, &[0xab; 32], attr::NV_BS_RT);
    m.set_var_raw("PaguroB", &PAGURO_VENDOR, &[0xcd; 32], attr::NV | attr::BS);
    let r = run(&m, &["efi", "vars", "list"]);
    assert_eq!(r.code, 0);
    assert!(!r.stdout.contains("abab"), "S leaked");
    assert!(!r.stdout.contains("cdcd"), "B leaked");
    let d = ok(&m, &["efi", "vars", "get", "PaguroSetup"]);
    assert_eq!(d["present"], true);
    assert!(d["value"].is_null());
    assert_eq!(run(&m, &["efi", "vars", "get", "PaguroB"]).code, 4);
    assert_eq!(
        run(&m, &["efi", "vars", "set", "PaguroSetup", &"00".repeat(32)]).code,
        3
    );
    assert_eq!(
        run(&m, &["efi", "vars", "set", "BootOrder", "0000"]).code,
        2
    );
    assert_eq!(
        run(&m, &["efi", "vars", "set", "PaguroTpmBroken", "0101"]).code,
        3
    );
    ok(
        &m,
        &["efi", "vars", "set", "paguroconfighash", &"11".repeat(32)],
    );
    assert_eq!(
        m.var("PaguroConfigHash", &PAGURO_VENDOR).unwrap(),
        vec![0x11; 32]
    );
    ok(&m, &["efi", "vars", "set", "PaguroUninstall", "01"]);
    ok(&m, &["efi", "vars", "delete", "PaguroUninstall"]);
    assert_eq!(m.var("PaguroUninstall", &PAGURO_VENDOR), None);
}

#[test]
fn boot_entry_is_shim_with_paguro_as_second_stage() {
    let m = MockApi::standard();
    let d = ok(&m, &["efi", "boot-entry", "create"]);
    assert_eq!(d["entry"], "Boot0001");
    assert_eq!(
        m.var("BootOrder", &EFI_GLOBAL_VARIABLE).unwrap(),
        vec![0, 0, 1, 0],
        "appended; Windows stays first"
    );
    let v = m.var("Boot0001", &EFI_GLOBAL_VARIABLE).unwrap();
    let lo = bootstrap::parse_load_option(&v).unwrap();
    let mut nodes = Vec::new();
    bootstrap::walk_device_path(lo.file_path, |n| nodes.push(n)).unwrap();
    let hd = bootstrap::parse_hard_drive(&nodes[0]).unwrap();
    assert_eq!(
        hd.partition_guid,
        Guid::parse(paguro_win::mock::ESP_GUID).unwrap()
    );
    assert_eq!(
        (hd.partition_number, hd.start_lba, hd.size_lba),
        (1, 2048, 204_800)
    );
    let path: Vec<u16> = nodes[1]
        .data
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(
        String::from_utf16_lossy(&path),
        "\\EFI\\paguro\\shimx64.efi\0"
    );
    let opt: Vec<u16> = lo
        .optional_data
        .chunks(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    assert_eq!(
        String::from_utf16_lossy(&opt),
        "\\EFI\\paguro\\paguro.efi\0"
    );
    // Idempotent.
    m.mutations.borrow_mut().clear();
    let d = ok(&m, &["efi", "boot-entry", "create"]);
    assert_eq!(d["changed"], false);
    assert!(m.mutations.borrow().is_empty());
    // BootNext, then deletion (which also clears a BootNext pointing at it).
    ok(&m, &["efi", "bootnext"]);
    assert_eq!(m.var("BootNext", &EFI_GLOBAL_VARIABLE).unwrap(), vec![1, 0]);
    let l = ok(&m, &["efi", "boot-entry", "list"]);
    assert_eq!(l["boot_next"], "0001");
    assert_eq!(l["entries"][1]["ours"], true);
    assert_eq!(
        run(&m, &["efi", "boot-entry", "delete", "0000"]).code,
        3,
        "never someone else's"
    );
    ok(&m, &["efi", "boot-entry", "delete", "Boot0001"]);
    assert_eq!(m.var("Boot0001", &EFI_GLOBAL_VARIABLE), None);
    assert_eq!(m.var("BootNext", &EFI_GLOBAL_VARIABLE), None);
    assert_eq!(
        m.var("BootOrder", &EFI_GLOBAL_VARIABLE).unwrap(),
        vec![0, 0]
    );
    assert!(m.var("Boot0000", &EFI_GLOBAL_VARIABLE).is_some());
}

#[test]
fn legacy_bios_is_refused() {
    let m = MockApi::standard();
    m.uefi.set(false);
    assert_eq!(run(&m, &["efi", "vars", "list"]).code, 3);
    assert_eq!(run(&m, &["restart-linux"]).code, 6);
}

// ---- esp -------------------------------------------------------------------------

#[test]
fn esp_install_verify_repair() {
    let m = MockApi::standard();
    install_esp(&m);
    for n in ["shimx64.efi", "mmx64.efi", "paguro.efi", "grubx64.efi"] {
        assert!(m.exists(&esp_file(n)), "{n}");
        assert!(
            m.exists(&format!("C:\\ProgramData\\paguro\\esp\\{n}")),
            "saved {n}"
        );
    }
    assert_eq!(
        m.file(&esp_file("grubx64.efi")),
        m.file(&esp_file("paguro.efi"))
    );
    ok(&m, &["esp", "verify"]);
    // A feature update wipes and rewrites.
    m.remove_file(&esp_file("paguro.efi")).unwrap();
    m.put_file(&esp_file("shimx64.efi"), b"MZother");
    let r = run(&m, &["esp", "verify"]);
    assert_eq!(r.code, 6);
    let d = ok(&m, &["--dry-run", "esp", "repair"]);
    assert_eq!(d["restored"].as_array().unwrap().len(), 2);
    assert!(!m.exists(&esp_file("paguro.efi")));
    ok(&m, &["esp", "repair"]);
    ok(&m, &["esp", "verify"]);
    // A tampered saved copy is never restored.
    m.put_file("C:\\ProgramData\\paguro\\esp\\paguro.efi", b"MZevil");
    m.remove_file(&esp_file("paguro.efi")).unwrap();
    assert_eq!(run(&m, &["esp", "repair"]).code, 3);
    // Not a PE: refused.
    m.put_file("C:\\in\\junk", b"ELF");
    let r = run(
        &m,
        &[
            "esp",
            "install",
            "--shim",
            "C:\\in\\junk",
            "--mm",
            "C:\\in\\mmx64.efi",
            "--loader",
            "C:\\in\\paguro.efi",
        ],
    );
    assert_eq!(r.code, 3);
}

// ---- mok ---------------------------------------------------------------------------

fn der() -> Vec<u8> {
    let mut d = vec![0x30, 0x82, 0x01, 0x00];
    d.extend((0..256).map(|i| i as u8));
    d
}

#[test]
fn mok_enroll_writes_what_mokmanager_checks() {
    let m = MockApi::standard();
    m.put_file("C:\\k\\mok.der", &der());
    let d = ok(&m, &["mok", "enroll", "--cert", "C:\\k\\mok.der"]);
    let pw = d["one_time_password"].as_str().unwrap().to_string();
    assert_eq!(pw.len(), 10);
    let new = m.var("MokNew", &efisig::SHIM_LOCK).unwrap();
    let mut certs = Vec::new();
    efisig::for_each(&new, |s| certs.push((s.kind, s.owner, s.data.to_vec()))).unwrap();
    assert_eq!(certs, vec![(efisig::CERT_X509, efisig::SHIM_LOCK, der())]);
    // MokManager.c compute_pw_hash: SHA-256(MokNew || UCS-2 password).
    let mut h = Sha256::new();
    h.update(&new);
    for u in pw.encode_utf16() {
        h.update(u.to_le_bytes());
    }
    assert_eq!(
        m.var("MokAuth", &efisig::SHIM_LOCK).unwrap(),
        h.finalize().to_vec()
    );
    let attrs = m.vars.borrow()[&("MokAuth".to_string(), efisig::SHIM_LOCK.0)].attributes;
    assert_eq!(attrs, attr::NV_BS_RT);
    let s = ok(&m, &["mok", "status"]);
    assert_eq!(s["pending_request"], true);
    // Once enrolled, nothing is requested again.
    m.set_var_raw("MokListRT", &efisig::SHIM_LOCK, &new, attr::BS | attr::RT);
    let d = ok(&m, &["mok", "enroll", "--cert", "C:\\k\\mok.der"]);
    assert_eq!(d["enrolled"], true);
    assert!(d["one_time_password"].is_null());
}

#[test]
fn mok_enroll_refusals() {
    let m = MockApi::standard();
    m.put_file("C:\\k\\bad.der", b"-----BEGIN CERTIFICATE-----");
    assert_eq!(
        run(&m, &["mok", "enroll", "--cert", "C:\\k\\bad.der"]).code,
        3
    );
    m.put_file("C:\\k\\mok.der", &der());
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    assert_eq!(
        run(&m, &["mok", "enroll", "--cert", "C:\\k\\mok.der"]).code,
        3
    );
    assert_eq!(m.var("MokNew", &efisig::SHIM_LOCK), None);
}

// ---- stage-setup, with the loader's derivation on a Windows-made volume -----------

fn stage_ready() -> MockApi {
    let m = installed();
    with_bitlocker(&m);
    m
}

#[test]
fn stage_setup_wraps_the_real_vmk_the_way_the_loader_unwraps_it() {
    let m = stage_ready();
    *m.stdin.borrow_mut() = b"correct horse\r\n".to_vec();
    m.set_var_raw("PaguroTpmBroken", &PAGURO_VENDOR, &[1], attr::NV_BS_RT);
    let r = run(&m, &["--passphrase-stdin", "stage-setup"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(!r.stdout.contains("correct horse"));
    let dir = format!("{}\\", paguro_win::mock::C_GUID);
    let file = m
        .file(&esp_file(&format!("{dir}setuptpm_seal.bin")))
        .unwrap();
    let s = seal::read(seal::Kind::SetupTpm, &file).unwrap();
    let sv: [u8; 32] = m
        .var("PaguroSetup", &PAGURO_VENDOR)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        !r.stdout.contains(&paguro_win::out::to_hex(&sv)),
        "S leaked"
    );
    assert_eq!(
        m.var("PaguroTpmBroken", &PAGURO_VENDOR),
        None,
        "staging clears the flag"
    );
    // The loader (paguro-boot machine.rs, setupTPM row): stretch, env_setup,
    // root gate over the FVEK blob, final key, XOR.
    let ini = m.file(&esp_file("paguro.ini")).unwrap();
    let ini_h: [u8; 32] = Sha256::digest(&ini).into();
    let user = paguro_crypto::user_password_hash("correct horse");
    let ph = paguro_crypto::bitlocker_stretch(&user, s.salt, paguro_crypto::STRETCH_ITERATIONS);
    let env = paguro_crypto::env_setup(&sv, &ini_h);
    let vol = sparse_volume(FIXTURE);
    let hdr = paguro_core::bde::parse_volume_header(&vol[..512]).unwrap();
    let rs = paguro_core::bde::REGION_SIZE as usize;
    let c: Vec<&[u8]> = hdr
        .metadata_offsets
        .iter()
        .map(|&o| &vol[o as usize..o as usize + rs])
        .collect();
    let md = paguro_core::bde::Metadata::parse(
        paguro_core::bde::cross_check([c[0], c[1], c[2]], &hdr).unwrap(),
    )
    .unwrap();
    let blob = paguro_win::keys::fvek_blob(&md);
    let key = paguro_crypto::final_key(&paguro_crypto::root_gate(&env, s.salt, &blob), &ph);
    let vmk = paguro_crypto::xor32(&key, s.wrapped_vmk);
    assert!(
        vmk_opens_fixture(&vmk),
        "the staged seal must open the real volume"
    );
    assert!(
        !r.stdout.contains(&paguro_win::out::to_hex(&vmk)),
        "VMK leaked"
    );
    // A wrong passphrase gives a key that does not open it (no oracle, just failure).
    let ph2 = paguro_crypto::bitlocker_stretch(
        &paguro_crypto::user_password_hash("wrong"),
        s.salt,
        paguro_crypto::STRETCH_ITERATIONS,
    );
    let k2 = paguro_crypto::final_key(&paguro_crypto::root_gate(&env, s.salt, &blob), &ph2);
    assert!(!vmk_opens_fixture(&paguro_crypto::xor32(
        &k2,
        s.wrapped_vmk
    )));

    // `tpm-auth.bin` (INTERFACES.md §8.4): the same salt and stretched
    // passphrase hash as the setupTPM seal above, so `paguro-initrd` can
    // re-seal the *standing* `tpm` rung too, restricted to SYSTEM (full) and
    // Administrators (read/delete only).
    let auth_path = format!(
        "C:\\ProgramData\\paguro\\{}\\tpm-auth.bin",
        paguro_win::mock::C_GUID
    );
    let auth_file = m.file(&auth_path).expect("tpm-auth.bin written");
    let auth = paguro_core::tpm_auth::parse(&auth_file).unwrap();
    assert_eq!(auth.salt, *s.salt);
    assert_eq!(
        auth.value, ph,
        "must be the same stretched value the seal was wrapped with"
    );
    assert_eq!(
        m.files
            .borrow()
            .get(&auth_path.to_lowercase())
            .unwrap()
            .acl
            .as_deref(),
        Some(paguro_win::tpm_auth::SDDL)
    );
    assert!(
        !r.stdout.contains(&paguro_win::out::to_hex(&auth.value)),
        "auth value leaked"
    );
}

#[test]
fn stage_setup_refusals() {
    // Unencrypted volume: nothing to stage.
    let m = installed();
    m.raw_disks
        .borrow_mut()
        .insert(0, MockFile::zeros(paguro_win::mock::C_OFFSET + (1 << 20)));
    *m.stdin.borrow_mut() = b"pw\n".to_vec();
    let r = run(&m, &["--passphrase-stdin", "stage-setup"]);
    assert_eq!(r.code, 3, "{}", r.stdout);
    // No protector Windows can open.
    let m = stage_ready();
    m.recovery.borrow_mut().clear();
    *m.stdin.borrow_mut() = b"pw\n".to_vec();
    assert_eq!(run(&m, &["--passphrase-stdin", "stage-setup"]).code, 3);
    // [SetupTPM] disabled.
    let m = stage_ready();
    ok(&m, &["config", "set", "--setup-tpm", "0"]);
    *m.stdin.borrow_mut() = b"pw\n".to_vec();
    assert_eq!(run(&m, &["--passphrase-stdin", "stage-setup"]).code, 3);
    // Interactive entries that differ.
    let m = stage_ready();
    m.push_secret("one");
    m.push_secret("two");
    assert_eq!(run(&m, &["stage-setup"]).code, 3);
    assert_eq!(m.var("PaguroSetup", &PAGURO_VENDOR), None);
}

// ---- restart-linux -------------------------------------------------------------------

#[test]
fn restart_linux_happy_path_without_a_tpm() {
    let m = installed();
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    let r = run(&m, &["restart-linux"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["data"]["restarting"], false);
    assert_eq!(
        r.json["data"]["pin_bypass"]["skipped"]
            .as_str()
            .map(|s| !s.is_empty()),
        Some(true)
    );
    let next = m.var("BootNext", &EFI_GLOBAL_VARIABLE).unwrap();
    let entry = format!("Boot{:04X}", u16::from_le_bytes([next[0], next[1]]));
    let lo = m.var(&entry, &EFI_GLOBAL_VARIABLE).unwrap();
    assert!(String::from_utf8_lossy(&lo).contains("s\0h\0i\0m\0"));
    assert!(!m.restarted.get());
    ok(&m, &["restart-linux", "--yes"]);
    assert!(m.restarted.get());
}

#[test]
fn restart_linux_repairs_what_it_can_and_refuses_the_rest() {
    let m = installed();
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    // bcdboot ran: loader gone, our entry gone.
    m.remove_file(&esp_file("paguro.efi")).unwrap();
    let d = ok(&m, &["preflight", "--repair"]);
    let checks = d["checks"].as_array().unwrap();
    let st = |id: &str| checks.iter().find(|c| c["id"] == id).unwrap()["state"].clone();
    assert_eq!(st("esp_files"), "repaired");
    assert_eq!(st("boot_entry"), "repaired");
    assert!(m.exists(&esp_file("paguro.efi")));
    // A dry run reports but does not repair.
    m.remove_file(&esp_file("paguro.efi")).unwrap();
    let r = run(&m, &["--dry-run", "restart-linux", "--yes"]);
    assert_eq!(r.code, 0);
    assert!(!m.exists(&esp_file("paguro.efi")));
    assert!(!m.restarted.get());
    // An image that became sparse: refused, with the reason.
    let mut f = MockFile::zeros(64 << 20);
    f.attributes |= fattr::SPARSE;
    m.put_mock_file("C:\\paguro\\debian.vhd", f);
    let r = run(&m, &["restart-linux", "--yes"]);
    assert_eq!(r.code, 6);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("images")
    );
    assert!(!m.restarted.get());
    // NVRAM cleared: refused, pointing at the bootstrap.
    let m = installed();
    m.vars
        .borrow_mut()
        .remove(&("PaguroConfigHash".to_string(), PAGURO_VENDOR.0));
    let r = run(&m, &["restart-linux"]);
    assert_eq!(r.code, 6);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--bootstrap")
    );
}

#[test]
fn restart_linux_with_secure_boot_needs_the_mok() {
    let m = installed();
    m.put_file("C:\\ProgramData\\paguro\\mok\\mok.der", &der());
    let r = run(&m, &["restart-linux"]);
    assert_eq!(r.code, 6);
    assert!(r.json["error"]["message"].as_str().unwrap().contains("mok"));
    // Pending enrolment is fine (MokManager asks on this boot).
    ok(
        &m,
        &[
            "mok",
            "enroll",
            "--cert",
            "C:\\ProgramData\\paguro\\mok\\mok.der",
        ],
    );
    ok(&m, &["restart-linux"]);
}

#[test]
fn loader_reported_tpm_failure_stages_setup() {
    let m = stage_ready();
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    m.set_var_raw("PaguroTpmBroken", &PAGURO_VENDOR, &[1], attr::NV_BS_RT);
    *m.stdin.borrow_mut() = b"pw\n".to_vec();
    let r = run(&m, &["--passphrase-stdin", "restart-linux"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["data"]["action"]["action"], "stage_setup_tpm");
    assert_eq!(r.json["data"]["action"]["reason"], "loader_reported");
    assert!(m.var("PaguroSetup", &PAGURO_VENDOR).is_some());
    assert!(m.var("BootNext", &EFI_GLOBAL_VARIABLE).is_some());
}

#[test]
fn repair_bootstrap_after_an_nvram_clear() {
    let m = stage_ready();
    m.set_var_raw(
        "SecureBoot",
        &EFI_GLOBAL_VARIABLE,
        &[0],
        attr::BS | attr::RT,
    );
    m.vars
        .borrow_mut()
        .remove(&("PaguroConfigHash".to_string(), PAGURO_VENDOR.0));
    assert_eq!(run(&m, &["repair"]).code, 6);
    *m.stdin.borrow_mut() = b"pass phrase\n".to_vec();
    let r = run(&m, &["--passphrase-stdin", "repair", "--bootstrap"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    check_bootstrap(&m, "pass phrase");
    // Re-running replaces the payload and the entry: still exactly one.
    *m.stdin.borrow_mut() = b"pass phrase\n".to_vec();
    let r = run(&m, &["--passphrase-stdin", "repair", "--bootstrap"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    check_bootstrap(&m, "pass phrase");
    let r = run(&m, &["efi", "boot-entry", "list"]);
    let setups = r.json["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["bootstrap"] == true)
        .count();
    assert_eq!(setups, 1);
}

/// The bootstrap as INTERFACES.md §9 has it: `PaguroBootstrap` opens the
/// fixture with the loader's derivation (paguro-boot machine.rs, bootstrap
/// row), and `BootNext` names a one-shot entry that starts shim with
/// `paguro.efi` as its second stage.
fn check_bootstrap(m: &MockApi, pass: &str) {
    let payload = m.var(bootstrap::VAR_NAME, &PAGURO_VENDOR).unwrap();
    let attrs = m.vars.borrow()[&(bootstrap::VAR_NAME.to_string(), PAGURO_VENDOR.0)].attributes;
    assert_eq!(attrs, attr::NV_BS_RT);
    let bs = bootstrap::parse_payload(&payload).unwrap();
    assert_eq!(bs.volume, c_guid());
    let ph = paguro_crypto::bitlocker_stretch(
        &paguro_crypto::user_password_hash(pass),
        bs.salt,
        paguro_crypto::STRETCH_ITERATIONS,
    );
    let k = paguro_crypto::bootstrap_key(&ph, bs.salt);
    assert!(vmk_opens_fixture(&paguro_crypto::xor32(&k, bs.wrapped_vmk)));

    let next = m.var("BootNext", &EFI_GLOBAL_VARIABLE).unwrap();
    let n = u16::from_le_bytes([next[0], next[1]]);
    let var = m
        .var(&format!("Boot{n:04X}"), &EFI_GLOBAL_VARIABLE)
        .unwrap();
    let lo = bootstrap::parse_load_option(&var).unwrap();
    assert!(lo.is_paguro());
    let utf16 = |d: &[u8]| {
        let u: Vec<u16> = d
            .chunks(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16_lossy(&u)
    };
    assert_eq!(utf16(lo.description), "paguro setup");
    let mut path = String::new();
    bootstrap::walk_device_path(lo.file_path, |n| {
        if n.sub == bootstrap::DP_MEDIA_FILE_PATH {
            path = utf16(n.data);
        }
    })
    .unwrap();
    assert_eq!(
        path, "\\EFI\\paguro\\shimx64.efi\0",
        "INTERFACES §9: the entry points at shim"
    );
    assert_eq!(
        utf16(lo.optional_data),
        "\\EFI\\paguro\\paguro.efi\0",
        "paguro.efi is shim's second stage"
    );
    let order = m.var("BootOrder", &EFI_GLOBAL_VARIABLE).unwrap_or_default();
    assert!(
        !order
            .chunks(2)
            .any(|c| u16::from_le_bytes([c[0], c[1]]) == n),
        "one-shot: not in BootOrder"
    );
}

// ---- install ------------------------------------------------------------------------

#[test]
fn install_runs_resumes_and_bootstraps() {
    let m = MockApi::standard();
    with_bitlocker(&m);
    m.put_file("C:\\in\\shimx64.efi", &pe("shim"));
    m.put_file("C:\\in\\mmx64.efi", &pe("mm"));
    m.put_file("C:\\in\\paguro.efi", &pe("loader"));
    m.put_file("C:\\in\\build.sh", b"#!/bin/sh\n");
    let args = [
        "install",
        "debian",
        "--path",
        "C:\\paguro\\debian.vhd",
        "--size",
        "1G",
        "--script",
        "C:\\in\\build.sh",
        "--shim",
        "C:\\in\\shimx64.efi",
        "--mm",
        "C:\\in\\mmx64.efi",
        "--loader",
        "C:\\in\\paguro.efi",
    ];
    // Dry run: the plan, nothing else.
    let d = ok(&m, &[&["--dry-run"][..], &args[..]].concat());
    assert_eq!(d["steps"].as_array().unwrap().len(), 9);
    assert!(m.mutations.borrow().is_empty());
    // WSL mount fails the first time.
    m.set_runner(runner(&["wsl.exe --status"]));
    *m.stdin.borrow_mut() = b"hunter2\n".to_vec();
    let r = run(&m, &[&["--passphrase-stdin"][..], &args[..]].concat());
    assert_eq!(r.code, 5, "{}", r.stdout);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("wsl-mount")
    );
    let j: serde_json::Value = serde_json::from_slice(
        &m.file("C:\\ProgramData\\paguro\\journal\\install-debian.json")
            .unwrap(),
    )
    .unwrap();
    assert_eq!(j["steps"][2]["state"], "done");
    assert_eq!(j["steps"][3]["state"], "failed");
    // Fixed: the same command resumes; the disk is not recreated.
    m.set_runner(runner(&["wsl.exe"]));
    m.commands.borrow_mut().clear();
    let r = run(&m, &[&["--passphrase-stdin"][..], &args[..]].concat());
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(!r.stdout.contains("hunter2"));
    let cmds = m.commands.borrow().clone();
    assert!(
        cmds.iter()
            .any(|c| c.starts_with("wsl.exe --mount --vhd C:\\paguro\\debian.vhd --bare")),
        "{cmds:?}"
    );
    assert!(
        cmds.iter()
            .any(|c| c.contains("PAGURO_DISTRO=debian") && c.ends_with("sh /mnt/c/in/build.sh")),
        "{cmds:?}"
    );
    assert!(cmds.iter().any(|c| c.starts_with("wsl.exe --unmount")));
    assert!(m.exists("C:\\ProgramData\\paguro\\host-hardware.json"));
    assert!(m.exists(&esp_file("paguro.efi")));
    assert!(
        !m.exists(&esp_file("paguro.ini")),
        "the first boot authors paguro.ini (INTERFACES §11.2)"
    );
    check_bootstrap(&m, "hunter2");
    // Run again: everything already done.
    let r = run(&m, &[&["--passphrase-stdin"][..], &args[..]].concat());
    assert_eq!(r.code, 0);
}

#[test]
fn install_without_wsl_is_refused_and_names_are_checked() {
    let m = MockApi::standard();
    m.set_runner(runner(&[]));
    let r = run(&m, &["install", "debian", "--path", "C:\\d.vhd"]);
    assert_eq!(r.code, 3);
    assert!(
        r.json["error"]["message"]
            .as_str()
            .unwrap()
            .contains("WSL2")
    );
    assert_eq!(
        run(&m, &["install", "bad name", "--path", "C:\\d.vhd"]).code,
        2
    );
}

// ---- uninstall ------------------------------------------------------------------------

#[test]
fn uninstall_two_phases_and_leaves_the_rest_alone() {
    let m = installed();
    ok(&m, &["efi", "boot-entry", "create"]);
    // A bootstrap that never ran (INTERFACES.md §9): its payload goes too.
    m.set_var_raw(
        "PaguroBootstrap",
        &PAGURO_VENDOR,
        &[0x42; 72],
        attr::NV_BS_RT,
    );
    m.put_file("C:\\ProgramData\\paguro\\mok\\mok.der", &der());
    // The key is enrolled: the final boot queues its removal.
    let mut list = vec![0u8; efisig::x509_list_len(der().len())];
    efisig::write_x509(&efisig::SHIM_LOCK, &der(), &mut list).unwrap();
    m.set_var_raw("MokListRT", &efisig::SHIM_LOCK, &list, attr::BS | attr::RT);
    // The minifilter is installed and loaded until the reboot.
    m.set_runner(runner(&[
        "sc.exe query paguroflt",
        "sc.exe config",
        "sc.exe delete",
        "fltmc.exe instances",
    ]));
    assert_eq!(run(&m, &["uninstall"]).code, 3, "needs --yes");
    m.mutations.borrow_mut().clear();
    let d = ok(&m, &["--dry-run", "uninstall"]);
    assert_eq!(d["steps"].as_array().unwrap().len(), 13);
    assert!(m.mutations.borrow().is_empty());

    let r = run(&m, &["uninstall", "--yes", "--keep-images"]);
    assert_eq!(r.code, 8, "{}", r.stdout);
    assert_eq!(r.json["ok"], true);
    assert_eq!(m.var("PaguroUninstall", &PAGURO_VENDOR).unwrap(), vec![1]);
    assert!(m.var("MokDel", &efisig::SHIM_LOCK).is_some());
    assert_eq!(m.var("MokDelAuth", &efisig::SHIM_LOCK).unwrap().len(), 32);
    assert!(m.var("BootNext", &EFI_GLOBAL_VARIABLE).is_some());
    assert!(
        m.exists(&esp_file("paguro.efi")),
        "the final boot still needs the loader"
    );

    // Still before the reboot: nothing more happens.
    assert_eq!(run(&m, &["uninstall", "--yes", "--keep-images"]).code, 8);
    // The reboot: the driver is gone, the loader consumed the request.
    m.set_runner(runner(&["sc.exe query paguroflt", "sc.exe delete"]));
    m.vars
        .borrow_mut()
        .remove(&("PaguroUninstall".to_string(), PAGURO_VENDOR.0));
    let r = run(&m, &["uninstall", "--yes", "--keep-images"]);
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        m.list_dir(&format!("{ESP_PATH}EFI\\paguro"))
            .unwrap()
            .is_none()
    );
    for v in [
        "PaguroConfigHash",
        "PaguroSetup",
        "PaguroTpmBroken",
        "PaguroBootstrap",
        "PaguroUninstall",
    ] {
        assert_eq!(m.var(v, &PAGURO_VENDOR), None, "{v}");
    }
    assert!(
        m.var("Boot0000", &EFI_GLOBAL_VARIABLE).is_some(),
        "Windows' entry untouched"
    );
    assert_eq!(
        m.var("BootOrder", &EFI_GLOBAL_VARIABLE).unwrap(),
        vec![0, 0]
    );
    assert!(
        m.exists("C:\\paguro\\debian.vhd"),
        "images kept without --delete-images"
    );
    assert!(!m.exists("C:\\ProgramData\\paguro\\mok\\mok.der"));
    assert!(!m.exists("C:\\ProgramData\\paguro\\esp\\manifest.json"));
    assert!(!m.exists("C:\\ProgramData\\paguro\\journal\\uninstall-machine.json"));
    assert!(
        m.commands
            .borrow()
            .iter()
            .any(|c| c == "sc.exe delete paguroflt")
    );
}

#[test]
fn uninstall_skip_final_boot_and_delete_images() {
    let m = installed();
    m.set_runner(runner(&[]));
    let r = run(
        &m,
        &["uninstall", "--yes", "--skip-final-boot", "--delete-images"],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert!(
        r.json["warnings"][0]
            .as_str()
            .unwrap()
            .contains("32 inert bytes")
    );
    assert!(!m.exists("C:\\paguro\\debian.vhd"));
    assert_eq!(m.var("PaguroUninstall", &PAGURO_VENDOR), None);
    // Idempotent: a second run on a clean machine succeeds.
    ok(
        &m,
        &["uninstall", "--yes", "--keep-images", "--skip-final-boot"],
    );
}

#[test]
fn a_boot_services_only_b_is_never_touched() {
    let m = installed();
    m.set_var_raw("PaguroB", &PAGURO_VENDOR, &[9; 32], attr::NV | attr::BS);
    m.set_runner(runner(&[]));
    ok(
        &m,
        &["uninstall", "--yes", "--keep-images", "--skip-final-boot"],
    );
    assert_eq!(m.var("PaguroB", &PAGURO_VENDOR).unwrap(), vec![9; 32]);
}

/// Unelevated, firmware variables and `fltmc` cannot be read: `status`
/// says so instead of reporting "Secure Boot: null" or "not loaded".
#[test]
fn status_unelevated_reports_unknown_not_a_wrong_value() {
    let m = MockApi::standard();
    m.set_runner(|prog, _| {
        (prog == "fltmc.exe").then(|| paguro_win::api::Output {
            status: 0,
            stdout: "Filter Name\n----\nPaguroFlt      0      385100\n".into(),
            stderr: String::new(),
        })
    });
    m.elevated.set(false);
    let r = paguro_win::cli::run(&m, ["paguro", "status"]);
    assert_eq!(r.code, 0, "{}", r.stderr);
    assert!(
        r.stdout
            .contains("secure boot: unknown: needs an elevated prompt"),
        "{}",
        r.stdout
    );
    assert!(
        r.stdout
            .contains("minifilter: unknown: needs an elevated prompt"),
        "{}",
        r.stdout
    );
    assert!(!r.stdout.contains("not loaded"), "{}", r.stdout);
    let d = common::ok(&m, &["status"]);
    assert!(d["firmware"]["secure_boot"].is_null());
    assert!(d["firmware"]["unknown"].is_string());
    assert!(d["minifilter"]["loaded"].is_null());
    // Elevated, the same machine reads both.
    m.elevated.set(true);
    let r = paguro_win::cli::run(&m, ["paguro", "status"]);
    assert!(r.stdout.contains("secure boot: on"), "{}", r.stdout);
    assert!(r.stdout.contains("minifilter: loaded"), "{}", r.stdout);
}

// ---- paguro itself: install, repair, uninstall (INTERFACES §11.7a) -----------

#[test]
fn install_without_a_distribution_installs_paguro() {
    let m = MockApi::standard();
    m.put_file("C:\\Users\\me\\Downloads\\paguro.exe", b"MZpaguro");
    let d = common::ok(&m, &["install"]);
    assert_eq!(d["state"]["installed"], true);
    assert!(m.exists("C:\\Program Files\\paguro\\paguro.exe"));
    assert!(m.exists("C:\\ProgramData\\paguro\\setup\\paguro.exe"));
    let cmds = m.commands.borrow().join("\n");
    assert!(
        cmds.contains("Uninstall\\paguro /v UninstallString"),
        "{cmds}"
    );
    // A distribution still needs --path.
    let r = common::run(&m, &["install", "debian"]);
    assert_eq!(r.code, 2, "{}", r.stderr);
}

#[test]
fn install_unelevated_relaunches_elevated_and_relays_the_report() {
    let m = MockApi::standard();
    m.elevated.set(false);
    let r = paguro_win::cli::run(&m, ["paguro", "install"]);
    let runs = m.elevated_runs.borrow().clone();
    assert_eq!(runs.len(), 1, "{runs:?}");
    assert!(runs[0].starts_with("C:\\Users\\me\\Downloads\\paguro.exe install --direct --report C:\\Users\\me\\AppData\\Local\\Temp\\paguro-"), "{runs:?}");
    assert_eq!(r.code, 0);
    assert!(
        m.mutations
            .borrow()
            .iter()
            .all(|x| !x.contains("Program Files")),
        "nothing done unelevated"
    );
}

#[test]
fn uninstall_never_deletes_images_silently() {
    let m = MockApi::standard();
    // No console to ask at: refused, nothing done.
    let r = common::run(&m, &["uninstall", "--yes"]);
    assert_eq!(r.code, 3, "{}", r.stdout);
    assert_eq!(r.json["error"]["data"]["needs_choice"], "images");
    assert!(m.mutations.borrow().is_empty());
    // Asked at the console: "n" keeps them.
    m.lines.borrow_mut().push("n".into());
    let r = common::run(&m, &["uninstall", "--yes", "--skip-final-boot"]);
    assert!(r.code == 0 || r.code == 8, "{}", r.stdout);
    assert!(m.lines.borrow().is_empty(), "the question was asked");
    // Both flags: a usage error.
    let r = common::run(
        &m,
        &["uninstall", "--yes", "--keep-images", "--delete-images"],
    );
    assert_eq!(r.code, 2);
}

#[test]
fn uninstall_removes_what_install_added() {
    let m = MockApi::standard();
    m.put_file("C:\\Users\\me\\Downloads\\paguro.exe", b"MZpaguro");
    common::ok(&m, &["install"]);
    m.put_file("C:\\ProgramData\\paguro\\service.log", b"log");
    let r = common::run(
        &m,
        &["uninstall", "--yes", "--keep-images", "--skip-final-boot"],
    );
    assert!(r.code == 0 || r.code == 8, "{}", r.stdout);
    let cmds = m.commands.borrow().join("\n");
    if r.code == 8 {
        assert!(
            cmds.contains("RunOnce /v paguro-uninstall"),
            "phase 2 at the next logon: {cmds}"
        );
        // After the reboot: the minifilter is gone.
        m.set_runner(|prog, _| {
            (prog == "fltmc.exe").then(|| paguro_win::api::Output {
                status: 1,
                stdout: String::new(),
                stderr: String::new(),
            })
        });
        let r = common::run(
            &m,
            &["uninstall", "--yes", "--keep-images", "--skip-final-boot"],
        );
        assert_eq!(r.code, 0, "{}", r.stdout);
    }
    assert!(!m.exists("C:\\Program Files\\paguro\\paguro.exe"));
    assert!(!m.exists("C:\\ProgramData\\paguro\\setup\\paguro.exe"));
    assert!(
        m.list_dir("C:\\ProgramData\\paguro").unwrap().is_none(),
        "nothing left in ProgramData"
    );
    let cmds = m.commands.borrow().join("\n");
    assert!(cmds.contains("reg.exe delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\paguro /f"), "{cmds}");
}

#[test]
fn repair_app_only_never_touches_images_or_firmware() {
    let m = MockApi::standard();
    m.put_file("C:\\Users\\me\\Downloads\\paguro.exe", b"MZpaguro");
    common::ok(&m, &["install"]);
    m.put_file("C:\\paguro\\debian.vhd", b"image");
    m.mutations.borrow_mut().clear();
    let d = common::ok(&m, &["repair", "--app-only"]);
    assert!(d["app"].is_array(), "{d}");
    let muts = m.mutations.borrow().join("\n");
    assert!(!muts.contains("debian.vhd"), "{muts}");
    assert!(
        !muts.contains("fw_set") && !muts.contains("fw_delete"),
        "{muts}"
    );
}

/// A minifilter that was installed but never started needs no restart.
#[test]
fn uninstall_needs_no_restart_for_a_driver_that_never_ran() {
    let m = MockApi::standard();
    m.set_runner(|prog, args| {
        let stdout = if prog == "sc.exe" && args == ["query", "paguroflt"] {
            "SERVICE_NAME: paguroflt\n        STATE              : 1  STOPPED\n"
        } else {
            ""
        };
        let status = i32::from(prog == "sc.exe" && args == ["query", "paguro"]) * 1060;
        Some(paguro_win::api::Output {
            status,
            stdout: stdout.into(),
            stderr: String::new(),
        })
    });
    let r = common::run(
        &m,
        &["uninstall", "--yes", "--keep-images", "--skip-final-boot"],
    );
    assert_eq!(r.code, 0, "{}", r.stdout);
    assert_eq!(r.json["data"]["finished"], true);
}
