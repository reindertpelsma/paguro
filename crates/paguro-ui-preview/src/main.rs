//! Render the loader's screens to PNG on the host, with the theme compiled
//! into this build (`PAGURO_THEME`, `PAGURO_LANG`), for theme authors:
//!
//! ```text
//! cargo run -p paguro-ui-preview -- --screen unlock --res 1920x1080 --theme default --out x.png
//! cargo run -p paguro-ui-preview -- --all [--out-dir DIR] [--res WxH ...]
//! cargo run -p paguro-ui-preview -- --list
//! PAGURO_THEME=mytheme cargo run -p paguro-ui-preview -- --all
//! ```
//!
//! `--screen` takes a fixture name (`--list` prints them); `--theme` a
//! compiled-in variant (`default`, `high-contrast`, …).

#![allow(clippy::indexing_slicing)] // host tool

use std::path::{Path, PathBuf};
use std::process::exit;

use paguro_ui::builtin::THEMES;
use paguro_ui::fixtures::{self, Fixture, RESOLUTIONS};
use paguro_ui::{Canvas, render};

fn usage() -> ! {
    eprintln!(
        "usage: paguro-ui-preview --screen NAME [--res WxH] [--theme NAME] --out FILE.png\n       \
         paguro-ui-preview --all [--out-dir DIR] [--res WxH]... [--theme NAME]...\n       \
         paguro-ui-preview --list"
    );
    exit(2)
}

fn parse_res(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

fn rgb(canvas: &Canvas<'_>) -> Vec<u8> {
    canvas
        .bytes()
        .chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect()
}

fn write_png(path: &Path, w: u32, h: u32, rgb: &[u8]) -> Result<(), String> {
    let f = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), w, h);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.set_compression(png::Compression::High);
    let mut wr = enc.write_header().map_err(|e| e.to_string())?;
    wr.write_image_data(rgb).map_err(|e| e.to_string())
}

fn render_one(fx: &Fixture, theme: usize, (w, h): (u32, u32), out: &Path) -> Result<(), String> {
    let t = THEMES
        .get(theme)
        .ok_or_else(|| "no such theme".to_string())?;
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let mut c = Canvas::new(&mut buf, w, h, w).ok_or("bad size")?;
    if !render(&fx.screen, &fx.view(), t, &mut c) {
        return Err(format!(
            "{w}x{h} is below the smallest supported size (640x480): the loader uses the text console"
        ));
    }
    write_png(out, w, h, &rgb(&c))
}

fn theme_index(name: &str) -> usize {
    THEMES
        .iter()
        .position(|t| t.name == name)
        .unwrap_or_else(|| {
            let names: Vec<_> = THEMES.iter().map(|t| t.name).collect();
            eprintln!("unknown theme {name:?}; compiled in: {}", names.join(", "));
            exit(2)
        })
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut screen, mut out, mut out_dir) = (None, None, PathBuf::from("target/ui-gallery"));
    let (mut all, mut list) = (false, false);
    let mut res: Vec<(u32, u32)> = Vec::new();
    let mut themes: Vec<usize> = Vec::new();
    while let Some(a) = args.next() {
        match a.as_str() {
            "--screen" => screen = args.next(),
            "--out" => out = args.next().map(PathBuf::from),
            "--out-dir" => out_dir = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            "--res" => res.push(
                args.next()
                    .and_then(|r| parse_res(&r))
                    .unwrap_or_else(|| usage()),
            ),
            "--theme" => themes.push(theme_index(&args.next().unwrap_or_else(|| usage()))),
            "--all" => all = true,
            "--list" => list = true,
            _ => usage(),
        }
    }
    let fx = fixtures::all();
    if list {
        for f in &fx {
            println!("{}", f.name);
        }
        return;
    }
    if all {
        if res.is_empty() {
            res = RESOLUTIONS.to_vec();
        }
        if themes.is_empty() {
            themes = (0..THEMES.len()).collect();
        }
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            eprintln!("{}: {e}", out_dir.display());
            exit(1)
        }
        let mut n = 0;
        for &t in &themes {
            for &(w, h) in &res {
                for f in &fx {
                    let p = out_dir.join(format!("{}-{}-{w}x{h}.png", THEMES[t].name, f.name));
                    if let Err(e) = render_one(f, t, (w, h), &p) {
                        eprintln!("{}: {e}", p.display());
                        exit(1)
                    }
                    n += 1;
                }
            }
        }
        println!("wrote {n} images to {}", out_dir.display());
        return;
    }
    let (Some(name), Some(out)) = (screen, out) else {
        usage()
    };
    let Some(f) = fx.iter().find(|f| f.name == name) else {
        eprintln!("unknown screen {name:?} (--list shows them)");
        exit(2)
    };
    let t = themes.first().copied().unwrap_or(0);
    let r = res.first().copied().unwrap_or((1920, 1080));
    if let Err(e) = render_one(f, t, r, &out) {
        eprintln!("{e}");
        exit(1)
    }
}
