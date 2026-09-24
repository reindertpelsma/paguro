//! Lists that scroll (INTERFACES.md §13.4 browser, the unlock and volume
//! menus, the layout and language choosers): for random list lengths,
//! selections and screen sizes, in every variant and in the text UI, the
//! selected row is visible and the "more above / below" indicators appear
//! exactly on the sides that have rows out of view, with the right counts.
#![allow(clippy::indexing_slicing)]

use paguro_boot::platform::{
    DirItem, DirView, EntryKind, Label, Level, Listing, Screen, VolumeChoice, VolumeFormat,
    VolumeList,
};
use paguro_boot::ui::{self, Key};
use paguro_ui::builtin::THEMES;
use paguro_ui::draw::{DrawList, Target};
use paguro_ui::textui::{self, Grid, ROWS};
use paguro_ui::{View, layout};
use proptest::prelude::*;

struct Names(Vec<String>);

impl Listing for Names {
    fn len(&self) -> usize {
        self.0.len()
    }
    fn item(&self, i: usize) -> Option<DirItem<'_>> {
        self.0.get(i).map(|n| DirItem {
            name: n,
            kind: EntryKind::Disk,
            bytes: 1 << 30,
        })
    }
    fn more(&self) -> bool {
        false
    }
}

fn check_graphics(
    screen: &Screen,
    view: &View<'_>,
    rows: usize,
    w: u32,
    h: u32,
    theme: usize,
) -> Result<(), TestCaseError> {
    let mut list = DrawList::new();
    layout(screen, view, &THEMES[theme], w, h, &mut list);
    let shown: Vec<usize> = list
        .hits
        .as_slice()
        .iter()
        .filter_map(|h| match h.target {
            Target::Row(i) => Some(i),
            _ => None,
        })
        .collect();
    prop_assert!(!shown.is_empty(), "no rows at {w}x{h}");
    let sel = view.selected.min(rows - 1);
    prop_assert!(
        shown.contains(&sel),
        "selection {sel} not in {shown:?} at {w}x{h}"
    );
    let (first, last) = (shown[0], *shown.last().unwrap());
    prop_assert_eq!(shown.len(), last - first + 1, "contiguous");
    let key = |k: Key| {
        list.hits
            .as_slice()
            .iter()
            .any(|h| h.target == Target::Key(k))
    };
    prop_assert_eq!(
        key(Key::PageUp),
        first > 0,
        "above indicator, first {}",
        first
    );
    prop_assert_eq!(
        key(Key::PageDown),
        last + 1 < rows,
        "below indicator, last {} of {}",
        last,
        rows
    );
    Ok(())
}

fn check_text(screen: &Screen, view: &View<'_>, rows: usize) -> Result<(), TestCaseError> {
    let mut list = DrawList::new();
    let mut grid = Grid::new();
    let page = textui::render(
        screen,
        view,
        &THEMES[0],
        &textui::Opts::default(),
        &mut list,
        &mut grid,
    );
    let lines: Vec<String> = (0..ROWS)
        .map(|r| {
            let mut s = String::new();
            grid.line(r, &mut s).unwrap();
            s
        })
        .collect();
    prop_assert_eq!(
        lines.iter().filter(|l| l.starts_with(" > ")).count(),
        1,
        "one selected row:\n{}",
        lines.join("\n")
    );
    let sel = view.selected.min(rows - 1);
    let first = sel.saturating_sub(page - 1).min(rows.saturating_sub(page));
    let below = rows - (first + page).min(rows);
    let above_line = lines.iter().find(|l| l.trim_start().starts_with("^ "));
    let below_line = lines.iter().find(|l| l.trim_start().starts_with("v "));
    prop_assert_eq!(above_line.is_some(), first > 0);
    prop_assert_eq!(below_line.is_some(), below > 0);
    if let Some(l) = above_line {
        prop_assert!(l.contains(&format!("^ {first} ")), "{l}");
    }
    if let Some(l) = below_line {
        prop_assert!(l.contains(&format!("v {below} ")), "{l}");
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(160))]

    #[test]
    fn the_browser_keeps_the_selection_in_view(
        n in 0usize..60,
        sel in 0usize..70,
        w in 640u32..2600,
        h in 480u32..1600,
        theme in 0usize..4,
        root in any::<bool>(),
    ) {
        let names = Names((0..n).map(|i| format!("disk{i}.vhd")).collect());
        let level = if root { Level::Root } else { Level::Volume };
        let dir = DirView { path: "\\paguro", listing: &names, selected: sel, level };
        let rows = ui::browse_rows(&dir);
        let view = View { selected: sel.min(rows - 1), dir: Some(dir), ..View::IDLE };
        let screen = Screen::Browse(level);
        check_graphics(&screen, &view, rows, w, h, theme)?;
        check_text(&screen, &view, rows)?;
    }

    #[test]
    fn menus_keep_the_selection_in_view(
        n in 1u8..=8,
        sel in 0usize..8,
        w in 640u32..1400,
        h in 480u32..900,
        theme in 0usize..4,
    ) {
        let mut v = VolumeList::new();
        for i in 0..n {
            v.push(VolumeChoice {
                disk: i,
                partition: 1,
                bytes: 1 << 40,
                format: VolumeFormat::BitLocker,
                name: Label::truncated("Basic data partition"),
            });
        }
        let screen = Screen::SelectVolume(v);
        let rows = usize::from(n);
        let view = View { selected: sel.min(rows - 1), ..View::IDLE };
        check_graphics(&screen, &view, rows, w, h, theme)?;
        check_text(&screen, &view, rows)?;
        let kb = Screen::ChooseKeyboard { current: paguro_core::config::Keyboard::ALL[sel] };
        let view = View { selected: sel, ..View::IDLE };
        check_graphics(&kb, &view, 8, w, h, theme)?;
        check_text(&kb, &view, 8)?;
    }
}
