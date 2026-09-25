//! Resources of `paguro.exe` (INTERFACES.md §11.7a), for the MSVC targets:
//!
//! - the application manifest (`RT_MANIFEST` 1): `asInvoker`, Windows 10/11,
//!   and the **detached console allocation policy** (Windows 11 24H2 and
//!   Windows Server 2025 on): a double-click gets no console window, a
//!   terminal still gets a console program;
//! - the payloads, when `PAGURO_PAYLOAD_DIR` names a directory: every file
//!   under it as an `RT_RCDATA` resource (ids from 1001), listed by resource
//!   1000 (JSON: name, id, length, SHA-256; see `paguro_win::cmd::setup`).
//!   Without the `gui` feature, `app/` is left out: the CLI-only build.
//!
//! The `.res` file is written here directly (the format is a sequence of
//! headers and DWORD-aligned data) and handed to the linker, which takes
//! `.res` inputs: no resource compiler needed, on Windows or with
//! `cargo xwin` on Linux.
#![allow(clippy::indexing_slicing)]

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

const RT_RCDATA: u16 = 10;
const RT_MANIFEST: u16 = 24;
const MANIFEST_ID: u16 = 1000;
const FIRST_PAYLOAD: u16 = 1001;
/// MEMORYFLAGS: MOVEABLE | PURE (what rc.exe writes).
const MEMORY_FLAGS: u16 = 0x0030;
/// LANG_NEUTRAL, SUBLANG_NEUTRAL.
const LANGUAGE: u16 = 0;

const APP_MANIFEST: &str = r#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0" xmlns:asmv3="urn:schemas-microsoft-com:asm.v3">
  <assemblyIdentity type="win32" name="paguro.paguro" version="1.0.0.0" processorArchitecture="*"/>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
        <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"/>
    </application>
  </compatibility>
  <asmv3:application>
    <asmv3:windowsSettings>
      <consoleAllocationPolicy xmlns="http://schemas.microsoft.com/SMI/2024/WindowsSettings">detached</consoleAllocationPolicy>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
    </asmv3:windowsSettings>
  </asmv3:application>
</assembly>
"#;

fn pad4(v: &mut Vec<u8>) {
    while v.len() % 4 != 0 {
        v.push(0);
    }
}

/// One `.res` entry with numeric type and name.
fn entry(out: &mut Vec<u8>, ty: u16, id: u16, data: &[u8]) {
    let mut h = Vec::new();
    h.extend_from_slice(&(data.len() as u32).to_le_bytes()); // DataSize
    h.extend_from_slice(&0u32.to_le_bytes()); // HeaderSize, fixed below
    h.extend_from_slice(&0xffffu16.to_le_bytes());
    h.extend_from_slice(&ty.to_le_bytes());
    h.extend_from_slice(&0xffffu16.to_le_bytes());
    h.extend_from_slice(&id.to_le_bytes());
    pad4(&mut h);
    h.extend_from_slice(&0u32.to_le_bytes()); // DataVersion
    h.extend_from_slice(&MEMORY_FLAGS.to_le_bytes());
    h.extend_from_slice(&LANGUAGE.to_le_bytes());
    h.extend_from_slice(&0u32.to_le_bytes()); // Version
    h.extend_from_slice(&0u32.to_le_bytes()); // Characteristics
    let hl = h.len() as u32;
    h[4..8].copy_from_slice(&hl.to_le_bytes());
    out.extend_from_slice(&h);
    out.extend_from_slice(data);
    pad4(out);
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<(String, PathBuf)>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .expect("PAGURO_PAYLOAD_DIR")
        .filter_map(Result::ok)
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for e in entries {
        let p = e.path();
        if p.is_dir() {
            walk(&p, base, out);
        } else {
            let rel = p
                .strip_prefix(base)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, p));
        }
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=PAGURO_PAYLOAD_DIR");
    println!("cargo:rerun-if-changed=build.rs");
    let target = std::env::var("TARGET").unwrap_or_default();
    if !target.ends_with("-windows-msvc") {
        return;
    }
    let gui = std::env::var_os("CARGO_FEATURE_GUI").is_some();
    let mut res = Vec::new();
    // The empty entry every .res file starts with.
    res.extend_from_slice(&[
        0, 0, 0, 0, 0x20, 0, 0, 0, 0xff, 0xff, 0, 0, 0xff, 0xff, 0, 0,
    ]);
    res.extend_from_slice(&[0u8; 16]);
    entry(&mut res, RT_MANIFEST, 1, APP_MANIFEST.as_bytes());

    if let Some(dir) = std::env::var_os("PAGURO_PAYLOAD_DIR").map(PathBuf::from) {
        println!("cargo:rerun-if-changed={}", dir.display());
        let mut files = Vec::new();
        walk(&dir, &dir, &mut files);
        let mut list = Vec::new();
        let mut id = FIRST_PAYLOAD;
        for (name, path) in files {
            if !gui && name.starts_with("app/") {
                continue;
            }
            println!("cargo:rerun-if-changed={}", path.display());
            let data = fs::read(&path).expect("payload file");
            let sha: String = Sha256::digest(&data)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            list.push(
                serde_json::json!({ "name": name, "id": id, "len": data.len(), "sha256": sha }),
            );
            entry(&mut res, RT_RCDATA, id, &data);
            id += 1;
        }
        let manifest = serde_json::json!({
            "version": 1,
            "build": std::env::var("CARGO_PKG_VERSION").unwrap_or_default(),
            "files": list,
        });
        entry(
            &mut res,
            RT_RCDATA,
            MANIFEST_ID,
            manifest.to_string().as_bytes(),
        );
    }
    let out = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR")).join("paguro.res");
    fs::write(&out, &res).expect("write paguro.res");
    println!("cargo:rustc-link-arg-bins={}", out.display());
}
