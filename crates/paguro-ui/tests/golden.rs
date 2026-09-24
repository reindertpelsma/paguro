//! Golden snapshots: every fixture screen × {800×600, 1366×768, 1920×1080,
//! 3840×2160} × every compiled-in theme variant, rendered on the host.
//!
//! - 800×600 (all fixtures, all variants) and a curated 1920×1080 set are
//!   committed as PNGs under `tests/golden/` and compared with a small
//!   tolerance (a changed pixel must differ by more than 2 per channel, and
//!   at most 0.05 % of pixels may);
//! - every render is also pinned by the SHA-256 of its pixels in
//!   `tests/golden/hashes.txt` (the renderer is integer-only, so exact).
//!
//! `PAGURO_BLESS=1 cargo test -p paguro-ui --test golden` rewrites both.
//! Mismatches are written to `target/golden-diff/` (actual and diff PNGs).
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use paguro_ui::builtin::THEMES;
use paguro_ui::fixtures::{self, RESOLUTIONS};
use paguro_ui::{Canvas, render};
use sha2::{Digest, Sha256};

/// Committed as full PNGs at 1920×1080 (default theme).
const FULL_HD: &[&str] = &[
    "unlock",
    "unlock-recovery",
    "password-revealed",
    "recovery-key-half",
    "volumes-8",
    "hibernated",
    "roots",
];

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/golden")
}

fn diff_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/golden-diff")
}

fn to_rgb(bgra: &[u8]) -> Vec<u8> {
    bgra.chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect()
}

fn write_png(path: &Path, w: u32, h: u32, rgb: &[u8]) {
    let f = std::fs::File::create(path).unwrap();
    let mut e = png::Encoder::new(std::io::BufWriter::new(f), w, h);
    e.set_color(png::ColorType::Rgb);
    e.set_depth(png::BitDepth::Eight);
    e.set_compression(png::Compression::High);
    e.write_header().unwrap().write_image_data(rgb).unwrap();
}

fn read_png(path: &Path) -> Option<(u32, u32, Vec<u8>)> {
    let f = std::fs::File::open(path).ok()?;
    let mut r = png::Decoder::new(std::io::BufReader::new(f))
        .read_info()
        .ok()?;
    let mut buf = vec![0; r.output_buffer_size()?];
    let info = r.next_frame(&mut buf).ok()?;
    if info.color_type != png::ColorType::Rgb {
        return None;
    }
    buf.truncate(info.buffer_size());
    Some((info.width, info.height, buf))
}

/// Pixels that differ by more than 2 in any channel.
fn differing(a: &[u8], b: &[u8]) -> (usize, Vec<u8>) {
    let mut n = 0;
    let mut diff = Vec::with_capacity(a.len());
    for (pa, pb) in a.chunks_exact(3).zip(b.chunks_exact(3)) {
        let d = pa
            .iter()
            .zip(pb)
            .map(|(x, y)| x.abs_diff(*y))
            .max()
            .unwrap_or(0);
        if d > 2 {
            n += 1;
            diff.extend_from_slice(&[255, 0, 255]);
        } else {
            diff.extend_from_slice(&[pa[0] / 4, pa[1] / 4, pa[2] / 4]);
        }
    }
    (n, diff)
}

#[test]
fn goldens() {
    let bless = std::env::var_os("PAGURO_BLESS").is_some_and(|v| v == "1");
    let dir = golden_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let hashes_path = dir.join("hashes.txt");
    let committed: BTreeMap<String, String> = std::fs::read_to_string(&hashes_path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .filter_map(|l| {
            l.rsplit_once(' ')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();
    let mut hashes = BTreeMap::new();
    let mut failures = Vec::new();
    let mut pngs = 0usize;
    let fx = fixtures::all();
    for theme in THEMES.iter() {
        for &(w, h) in &RESOLUTIONS {
            let mut buf = vec![0u8; (w * h * 4) as usize];
            for f in &fx {
                let mut c = Canvas::new(&mut buf, w, h, w).unwrap();
                assert!(render(&f.screen, &f.view(), theme, &mut c));
                let key = format!("{} {} {w}x{h}", theme.name, f.name);
                let hash: String = Sha256::digest(&buf)
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect();
                let as_png = (w, h) == (800, 600)
                    || ((w, h) == (1920, 1080)
                        && theme.name == THEMES[0].name
                        && FULL_HD.contains(&f.name));
                let file = format!("{}-{}-{w}x{h}.png", theme.name, f.name);
                if as_png {
                    pngs += 1;
                    let path = dir.join(&file);
                    let rgb = to_rgb(&buf);
                    if bless {
                        write_png(&path, w, h, &rgb);
                    } else {
                        match read_png(&path) {
                            Some((gw, gh, g)) if (gw, gh) == (w, h) => {
                                let (n, diff) = differing(&rgb, &g);
                                if n * 2000 > (w * h) as usize {
                                    std::fs::create_dir_all(diff_dir()).unwrap();
                                    write_png(&diff_dir().join(&file), w, h, &rgb);
                                    write_png(
                                        &diff_dir().join(format!("diff-{file}")),
                                        w,
                                        h,
                                        &diff,
                                    );
                                    failures.push(format!("{key}: {n} pixels differ"));
                                }
                            }
                            _ => failures.push(format!("{key}: no golden {file}")),
                        }
                    }
                } else if !bless {
                    match committed.get(&key) {
                        Some(h) if *h == hash => {}
                        Some(_) => {
                            std::fs::create_dir_all(diff_dir()).unwrap();
                            write_png(&diff_dir().join(&file), w, h, &to_rgb(&buf));
                            failures.push(format!("{key}: pixels changed (hash)"));
                        }
                        None => failures.push(format!("{key}: no committed hash")),
                    }
                }
                hashes.insert(key, hash);
            }
        }
    }
    if bless {
        let mut out = String::from(
            "# SHA-256 of the BGRA pixels of every golden render (tests/golden.rs).\n\
             # Regenerate: PAGURO_BLESS=1 cargo test -p paguro-ui --test golden\n",
        );
        for (k, v) in &hashes {
            out.push_str(&format!("{k} {v}\n"));
        }
        std::fs::write(&hashes_path, out).unwrap();
        // Remove PNGs no fixture produces any more.
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name.ends_with(".png") {
                let known = hashes.keys().any(|k| {
                    let parts: Vec<_> = k.split(' ').collect();
                    name == format!("{}-{}-{}.png", parts[0], parts[1], parts[2])
                });
                if !known {
                    std::fs::remove_file(p).unwrap();
                }
            }
        }
        eprintln!("blessed {} renders ({pngs} as PNG)", hashes.len());
        return;
    }
    assert_eq!(
        hashes.len(),
        THEMES.len() * RESOLUTIONS.len() * fixtures::FIXTURES,
        "every fixture rendered"
    );
    assert!(
        failures.is_empty(),
        "{} golden mismatch(es) (actual images in target/golden-diff/; \
         PAGURO_BLESS=1 regenerates after a deliberate change):\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn golden_budget() {
    // Keep the committed goldens small.
    let total: u64 = std::fs::read_dir(golden_dir())
        .map(|d| {
            d.filter_map(|e| e.ok()?.metadata().ok())
                .map(|m| m.len())
                .sum()
        })
        .unwrap_or(0);
    assert!(
        total < 5 << 20,
        "goldens are {total} bytes; keep them under 5 MiB"
    );
}
