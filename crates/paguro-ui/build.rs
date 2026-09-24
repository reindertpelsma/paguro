//! Compile the theme named by `PAGURO_THEME` (default `default`) for the
//! language `PAGURO_LANG` (default `en`) into statics (INTERFACES.md §13.1).
//! An invalid theme fails the build with the validator's message.
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-env-changed=PAGURO_THEME");
    println!("cargo:rerun-if-env-changed=PAGURO_LANG");
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let themes_dir = manifest.join("../../themes");
    let themes_dir = themes_dir.canonicalize().unwrap_or(themes_dir);
    let theme = std::env::var("PAGURO_THEME").unwrap_or_else(|_| "default".into());
    let lang = std::env::var("PAGURO_LANG").unwrap_or_else(|_| "en".into());
    match paguro_theme::compile(&paguro_theme::Options {
        themes_dir,
        theme,
        lang,
        out_dir,
    }) {
        Ok(out) => {
            for p in out.inputs {
                println!("cargo:rerun-if-changed={}", p.display());
            }
        }
        Err(e) => {
            eprintln!("\npaguro theme error: {e}\n");
            println!("cargo:warning=paguro theme error: {e}");
            std::process::exit(1);
        }
    }
}
