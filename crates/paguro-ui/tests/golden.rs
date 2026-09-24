//! Golden snapshots, rendered on the host:
//!
//! - every fixture screen × {800×600, 1366×768, 1920×1080, 3840×2160} ×
//!   every compiled-in variant (dark, light, dark-contrast, light-contrast),
//!   in the starting language;
//! - a set of screens in every other compiled-in language (German and
//!   French strings are the longest);
//! - screens with the pointer's cursor over them, on dark and light;
//! - the text UI: every fixture's 80×24 grid (`tests/golden/text-ui.txt`),
//!   and the grid painted for a display the firmware console does not
//!   cover.
//!
//! What is committed as PNG (compared with a small tolerance: a changed
//! pixel must differ by more than 2 per channel, and at most 0.05 % of
//! pixels may): 800×600 of every fixture in dark and light, a curated set
//! of the contrast variants, a curated 1920×1080 set, the cursor and
//! painted-text renders. Every render is also pinned by the SHA-256 of its
//! pixels in `tests/golden/hashes.txt` (the renderer is integer-only, so
//! exact).
//!
//! `PAGURO_BLESS=1 cargo test -p paguro-ui --test golden` rewrites all of
//! it. Mismatches are written to `target/golden-diff/`. The goldens are for
//! the `en` build; with another `PAGURO_LANG` the test only checks that
//! everything renders.
#![allow(clippy::indexing_slicing)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use paguro_ui::builtin::{BY_LANG, LANG, LANGS, THEMES};
use paguro_ui::draw::DrawList;
use paguro_ui::fixtures::{self, RESOLUTIONS};
use paguro_ui::pointer::{Cursor, composite};
use paguro_ui::textui::{self, Grid, ROWS};
use paguro_ui::{Canvas, Rect, render};
use sha2::{Digest, Sha256};

/// Committed as full PNGs at 1920×1080: (variant, fixture).
const FULL_HD: &[(&str, &str)] = &[
    ("dark", "unlock"),
    ("dark", "unlock-recovery"),
    ("dark", "password-revealed"),
    ("dark", "recovery-key-half"),
    ("dark", "volumes-8"),
    ("dark", "hibernated"),
    ("dark", "browse-long-scrolled"),
    ("dark", "browse-esp"),
    ("dark", "browse-root-none"),
    ("dark", "disk-start"),
    ("light", "unlock"),
    ("light", "browse-esp"),
    ("light", "password-keyboard-de"),
];

/// The contrast variants' 800×600 PNGs.
const CONTRAST: &[&str] = &[
    "unlock",
    "unlock-recovery",
    "password-hidden",
    "recovery-key-half",
    "cannot-unlock",
    "browse-long-scrolled",
    "keyboards",
];

/// Rendered in every other language (hashes).
const LANG_FIXTURES: &[&str] = &[
    "unlock",
    "unlock-first-boot",
    "password-keyboard-de",
    "recovery-key-half",
    "cannot-unlock",
    "config-invalid",
    "hibernated",
    "volumes-8",
    "browse-long-scrolled",
    "path-typing",
    "keyboards",
    "languages",
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

struct Golden {
    bless: bool,
    dir: PathBuf,
    committed: BTreeMap<String, String>,
    hashes: BTreeMap<String, String>,
    pngs: Vec<String>,
    failures: Vec<String>,
}

impl Golden {
    /// Check (or bless) one render: `key` names it in hashes.txt, `file`
    /// is its PNG when committed as one.
    fn check(&mut self, key: String, file: Option<String>, w: u32, h: u32, bgra: &[u8]) {
        let hash: String = Sha256::digest(bgra)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        if let Some(file) = file {
            let path = self.dir.join(&file);
            let rgb = to_rgb(bgra);
            if self.bless {
                write_png(&path, w, h, &rgb);
            } else {
                match read_png(&path) {
                    Some((gw, gh, g)) if (gw, gh) == (w, h) => {
                        let (n, diff) = differing(&rgb, &g);
                        if n * 2000 > (w * h) as usize {
                            std::fs::create_dir_all(diff_dir()).unwrap();
                            write_png(&diff_dir().join(&file), w, h, &rgb);
                            write_png(&diff_dir().join(format!("diff-{file}")), w, h, &diff);
                            self.failures.push(format!("{key}: {n} pixels differ"));
                        }
                    }
                    _ => self.failures.push(format!("{key}: no golden {file}")),
                }
            }
            self.pngs.push(file);
        } else if !self.bless {
            match self.committed.get(&key) {
                Some(h) if *h == hash => {}
                other => {
                    std::fs::create_dir_all(diff_dir()).unwrap();
                    let name = key.replace([' ', ':', '+'], "-");
                    write_png(&diff_dir().join(format!("{name}.png")), w, h, &to_rgb(bgra));
                    self.failures.push(format!(
                        "{key}: {}",
                        if other.is_some() {
                            "pixels changed (hash)"
                        } else {
                            "no committed hash"
                        }
                    ));
                }
            }
        }
        self.hashes.insert(key, hash);
    }
}

fn grid_text(g: &Grid) -> String {
    let mut out = String::new();
    for r in 0..ROWS {
        let mut line = String::new();
        g.line(r, &mut line).unwrap();
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

#[test]
fn goldens() {
    let fx = fixtures::all();
    if LANG != "en" {
        // Another starting language: everything must still render.
        for theme in THEMES.iter() {
            for f in &fx {
                let (w, h) = (800, 600);
                let mut buf = vec![0u8; (w * h * 4) as usize];
                let mut c = Canvas::new(&mut buf, w, h, w).unwrap();
                assert!(render(&f.screen, &f.view(), theme, &mut c));
            }
        }
        eprintln!("PAGURO_LANG={LANG}: goldens are for the en build; rendered only");
        return;
    }
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
    let mut g = Golden {
        bless,
        dir: dir.clone(),
        committed,
        hashes: BTreeMap::new(),
        pngs: Vec::new(),
        failures: Vec::new(),
    };

    // Every fixture, every resolution, every variant.
    for theme in THEMES.iter() {
        for &(w, h) in &RESOLUTIONS {
            let mut buf = vec![0u8; (w * h * 4) as usize];
            for f in &fx {
                let mut c = Canvas::new(&mut buf, w, h, w).unwrap();
                assert!(render(&f.screen, &f.view(), theme, &mut c));
                let key = format!("{} {} {w}x{h}", theme.name, f.name);
                let png = ((w, h) == (800, 600)
                    && (["dark", "light"].contains(&theme.name) || CONTRAST.contains(&f.name)))
                    || ((w, h) == (1920, 1080) && FULL_HD.contains(&(theme.name, f.name)));
                let file = png.then(|| format!("{}-{}-{w}x{h}.png", theme.name, f.name));
                g.check(key, file, w, h, &buf);
            }
        }
    }

    // The other languages.
    for (li, lang) in LANGS.iter().enumerate().skip(1) {
        for theme in BY_LANG[li].iter().take(2) {
            for &(w, h) in &[(800, 600), (1920, 1080)] {
                let mut buf = vec![0u8; (w * h * 4) as usize];
                for f in fx.iter().filter(|f| LANG_FIXTURES.contains(&f.name)) {
                    let mut c = Canvas::new(&mut buf, w, h, w).unwrap();
                    assert!(render(&f.screen, &f.view(), theme, &mut c));
                    let key = format!("{lang}:{} {} {w}x{h}", theme.name, f.name);
                    g.check(key, None, w, h, &buf);
                }
            }
        }
    }

    // The pointer's cursor over a screen, on a dark and a light variant.
    for theme in THEMES.iter().take(2) {
        let (w, h) = (800, 600);
        for f in fx
            .iter()
            .filter(|f| ["unlock", "browse-esp"].contains(&f.name))
        {
            let mut buf = vec![0u8; (w * h * 4) as usize];
            let mut c = Canvas::new(&mut buf, w, h, w).unwrap();
            assert!(render(&f.screen, &f.view(), theme, &mut c));
            let img = theme
                .step_for(w, h)
                .image(theme.options.pointer)
                .expect("the pointer image");
            let cur = Cursor {
                img,
                x: 420,
                y: 300,
            };
            let mut out = vec![0u8; (w * h * 4) as usize];
            let r = composite(
                &buf,
                w,
                h,
                Rect::new(0, 0, w as i32, h as i32),
                Some(&cur),
                &mut out,
            );
            assert_eq!(r, Rect::new(0, 0, w as i32, h as i32));
            let key = format!("{} {}+cursor {w}x{h}", theme.name, f.name);
            let file = format!("{}-{}+cursor-{w}x{h}.png", theme.name, f.name);
            g.check(key, Some(file), w, h, &out);
        }
    }

    // The text UI: every fixture's grid, and grids painted on a display.
    let mut text = String::from(
        "# The text UI (80×24) of every fixture in the starting language\n\
         # (tests/golden.rs; PAGURO_BLESS=1 regenerates).\n",
    );
    let mut list = DrawList::new();
    let mut grid = Grid::new();
    for f in &fx {
        let view = f.view();
        let opts = textui::Opts {
            mode_hint: Some(paguro_ui::strings::Str::HintGraphics),
        };
        textui::render(&f.screen, &view, &THEMES[0], &opts, &mut list, &mut grid);
        text.push_str(&format!("\n== {} ==\n", f.name));
        text.push_str(&grid_text(&grid));
        for theme in THEMES.iter() {
            let (w, h) = (1366, 768);
            let mut buf = vec![0u8; (w * h * 4) as usize];
            let mut c = Canvas::new(&mut buf, w, h, w).unwrap();
            textui::paint_grid(&grid, theme, &mut c);
            let key = format!("{} {}+text {w}x{h}", theme.name, f.name);
            let png = f.name == "unlock" && ["dark", "light"].contains(&theme.name);
            let file = png.then(|| format!("{}-{}+text-{w}x{h}.png", theme.name, f.name));
            g.check(key, file, w, h, &buf);
        }
    }
    let text_path = dir.join("text-ui.txt");
    if bless {
        std::fs::write(&text_path, &text).unwrap();
    } else if std::fs::read_to_string(&text_path).ok().as_deref() != Some(text.as_str()) {
        std::fs::create_dir_all(diff_dir()).unwrap();
        std::fs::write(diff_dir().join("text-ui.txt"), &text).unwrap();
        g.failures
            .push("text UI grids changed (see target/golden-diff/text-ui.txt)".into());
    }

    if bless {
        let mut out = String::from(
            "# SHA-256 of the BGRA pixels of every golden render (tests/golden.rs).\n\
             # Regenerate: PAGURO_BLESS=1 cargo test -p paguro-ui --test golden\n",
        );
        for (k, v) in &g.hashes {
            out.push_str(&format!("{k} {v}\n"));
        }
        std::fs::write(&hashes_path, out).unwrap();
        // Remove PNGs no render produces any more.
        for e in std::fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().to_string();
            if name.ends_with(".png") && !g.pngs.contains(&name) {
                std::fs::remove_file(p).unwrap();
            }
        }
        eprintln!(
            "blessed {} renders ({} as PNG)",
            g.hashes.len(),
            g.pngs.len()
        );
        return;
    }
    assert_eq!(
        g.hashes.len(),
        g.committed.len(),
        "every committed render was produced"
    );
    assert!(
        g.failures.is_empty(),
        "{} golden mismatch(es) (actual images in target/golden-diff/; \
         PAGURO_BLESS=1 regenerates after a deliberate change):\n{}",
        g.failures.len(),
        g.failures.join("\n")
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

#[test]
fn the_variants_are_the_ones_paguro_ini_names() {
    for (t, v) in THEMES.iter().zip(paguro_core::config::UiTheme::ALL) {
        assert_eq!(t.name, v.name());
    }
    assert!(LANGS.contains(&"en"), "English is always compiled in");
    assert_eq!(LANGS[0], LANG);
}
