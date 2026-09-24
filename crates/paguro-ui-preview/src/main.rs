//! Render the loader's screens to PNG on the host, with the theme compiled
//! into this build (`PAGURO_THEME`; every language in its `strings/`), for
//! theme authors and translators:
//!
//! ```text
//! cargo run -p paguro-ui-preview -- --screen unlock --res 1920x1080 --theme light --out x.png
//! cargo run -p paguro-ui-preview -- --all [--out-dir DIR] [--res WxH ...] [--theme NAME ...] [--lang CODE ...]
//! cargo run -p paguro-ui-preview -- --all --screens unlock,browse-esp --lang de --lang fr
//! cargo run -p paguro-ui-preview -- --screen unlock --text          # the text UI, on stdout
//! cargo run -p paguro-ui-preview -- --list
//! PAGURO_THEME=mytheme cargo run -p paguro-ui-preview -- --all
//! ```
//!
//! `--screen`/`--screens` take fixture names (`--list` prints them),
//! `--theme` a compiled-in variant (`dark`, `light`, `dark-contrast`,
//! `light-contrast`, …), `--lang` a compiled-in language (`en`, `nl`, `de`,
//! …). `--cursor X,Y` draws the pointer's cursor; `--text` prints the 80×24
//! text UI instead of a PNG (with `--out`, paints it as the loader does on
//! a display the firmware console does not cover).

#![allow(clippy::indexing_slicing)] // host tool

use std::path::{Path, PathBuf};
use std::process::exit;

use paguro_ui::builtin::{BY_LANG, LANGS, THEMES};
use paguro_ui::draw::DrawList;
use paguro_ui::fixtures::{self, Fixture, RESOLUTIONS};
use paguro_ui::pointer::{Cursor, composite};
use paguro_ui::textui::{self, Grid, ROWS};
use paguro_ui::{Canvas, Rect, render};

fn usage() -> ! {
    eprintln!(
        "usage: paguro-ui-preview --screen NAME [--res WxH] [--theme NAME] [--lang CODE] [--cursor X,Y] [--text] --out FILE.png\n       \
         paguro-ui-preview --screen NAME --text [--lang CODE]\n       \
         paguro-ui-preview --all [--out-dir DIR] [--res WxH]... [--theme NAME]... [--lang CODE]... [--screens A,B,...]\n       \
         paguro-ui-preview --list"
    );
    exit(2)
}

fn parse_res(s: &str) -> Option<(u32, u32)> {
    let (w, h) = s.split_once('x')?;
    Some((w.parse().ok()?, h.parse().ok()?))
}

fn parse_xy(s: &str) -> Option<(i32, i32)> {
    let (x, y) = s.split_once(',')?;
    Some((x.parse().ok()?, y.parse().ok()?))
}

fn write_png(path: &Path, w: u32, h: u32, bgra: &[u8]) -> Result<(), String> {
    let rgb: Vec<u8> = bgra
        .chunks_exact(4)
        .flat_map(|p| [p[2], p[1], p[0]])
        .collect();
    let f = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut enc = png::Encoder::new(std::io::BufWriter::new(f), w, h);
    enc.set_color(png::ColorType::Rgb);
    enc.set_depth(png::BitDepth::Eight);
    enc.set_compression(png::Compression::High);
    let mut wr = enc.write_header().map_err(|e| e.to_string())?;
    wr.write_image_data(&rgb).map_err(|e| e.to_string())
}

struct Opts {
    theme: usize,
    lang: usize,
    cursor: Option<(i32, i32)>,
    text: bool,
}

fn grid_of(fx: &Fixture, o: &Opts) -> Grid {
    let mut list = DrawList::new();
    let mut grid = Grid::new();
    let opts = textui::Opts {
        mode_hint: Some(paguro_ui::strings::Str::HintGraphics),
    };
    textui::render(
        &fx.screen,
        &fx.view(),
        &BY_LANG[o.lang][o.theme],
        &opts,
        &mut list,
        &mut grid,
    );
    grid
}

fn render_one(fx: &Fixture, o: &Opts, (w, h): (u32, u32), out: &Path) -> Result<(), String> {
    let t = BY_LANG
        .get(o.lang)
        .and_then(|l| l.get(o.theme))
        .ok_or_else(|| "no such theme".to_string())?;
    let mut buf = vec![0u8; (w * h * 4) as usize];
    let mut c = Canvas::new(&mut buf, w, h, w).ok_or("bad size")?;
    if o.text {
        textui::paint_grid(&grid_of(fx, o), t, &mut c);
    } else if !render(&fx.screen, &fx.view(), t, &mut c) {
        return Err(format!(
            "{w}x{h} is below the smallest supported size (640x480): the loader uses the text console"
        ));
    }
    if let Some((x, y)) = o.cursor {
        let img = t
            .step_for(w, h)
            .image(t.options.pointer)
            .ok_or("no pointer image")?;
        let mut out_px = vec![0u8; buf.len()];
        composite(
            &buf,
            w,
            h,
            Rect::new(0, 0, w as i32, h as i32),
            Some(&Cursor { img, x, y }),
            &mut out_px,
        );
        buf = out_px;
    }
    write_png(out, w, h, &buf)
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

fn lang_index(code: &str) -> usize {
    LANGS.iter().position(|l| *l == code).unwrap_or_else(|| {
        eprintln!(
            "unknown language {code:?}; compiled in: {}",
            LANGS.join(", ")
        );
        exit(2)
    })
}

fn main() {
    let mut args = std::env::args().skip(1);
    let (mut screen, mut out, mut out_dir) = (None, None, PathBuf::from("target/ui-gallery"));
    let (mut all, mut list, mut text) = (false, false, false);
    let mut res: Vec<(u32, u32)> = Vec::new();
    let mut themes: Vec<usize> = Vec::new();
    let mut langs: Vec<usize> = Vec::new();
    let mut screens: Vec<String> = Vec::new();
    let mut cursor = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--screen" => screen = args.next(),
            "--screens" => {
                screens = args
                    .next()
                    .unwrap_or_else(|| usage())
                    .split(',')
                    .map(String::from)
                    .collect()
            }
            "--out" => out = args.next().map(PathBuf::from),
            "--out-dir" => out_dir = args.next().map(PathBuf::from).unwrap_or_else(|| usage()),
            "--res" => res.push(
                args.next()
                    .and_then(|r| parse_res(&r))
                    .unwrap_or_else(|| usage()),
            ),
            "--theme" => themes.push(theme_index(&args.next().unwrap_or_else(|| usage()))),
            "--lang" => langs.push(lang_index(&args.next().unwrap_or_else(|| usage()))),
            "--cursor" => {
                cursor = Some(
                    args.next()
                        .and_then(|s| parse_xy(&s))
                        .unwrap_or_else(|| usage()),
                )
            }
            "--text" => text = true,
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
        if langs.is_empty() {
            langs = vec![0];
        }
        if let Err(e) = std::fs::create_dir_all(&out_dir) {
            eprintln!("{}: {e}", out_dir.display());
            exit(1)
        }
        let mut n = 0;
        for &l in &langs {
            for &t in &themes {
                for &(w, h) in &res {
                    for f in fx
                        .iter()
                        .filter(|f| screens.is_empty() || screens.iter().any(|s| s == f.name))
                    {
                        let lang = if langs.len() > 1 || l != 0 {
                            format!("{}-", LANGS[l])
                        } else {
                            String::new()
                        };
                        let p = out_dir
                            .join(format!("{lang}{}-{}-{w}x{h}.png", THEMES[t].name, f.name));
                        let o = Opts {
                            theme: t,
                            lang: l,
                            cursor,
                            text,
                        };
                        if let Err(e) = render_one(f, &o, (w, h), &p) {
                            eprintln!("{}: {e}", p.display());
                            exit(1)
                        }
                        n += 1;
                    }
                }
            }
        }
        println!("wrote {n} images to {}", out_dir.display());
        return;
    }
    let Some(name) = screen else { usage() };
    let Some(f) = fx.iter().find(|f| f.name == name) else {
        eprintln!("unknown screen {name:?} (--list shows them)");
        exit(2)
    };
    let o = Opts {
        theme: themes.first().copied().unwrap_or(0),
        lang: langs.first().copied().unwrap_or(0),
        cursor,
        text,
    };
    let Some(out) = out else {
        if !text {
            usage()
        }
        let g = grid_of(f, &o);
        for r in 0..ROWS {
            let mut line = String::new();
            let _ = g.line(r, &mut line);
            println!("{line}");
        }
        return;
    };
    let r = res.first().copied().unwrap_or((1920, 1080));
    if let Err(e) = render_one(f, &o, r, &out) {
        eprintln!("{e}");
        exit(1)
    }
}
