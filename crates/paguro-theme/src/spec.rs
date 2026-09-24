//! The schema every theme is checked against: the string catalogue, colour
//! roles, text styles and screen kinds. The runtime types in `paguro-ui`
//! mirror these lists; the generated code does not compile if they drift.

/// One user-visible string: its key in `strings/<lang>.toml` and the
/// placeholders it may use, in the order the renderer passes them.
pub struct StringSpec {
    pub key: &'static str,
    /// The text style the renderer draws it in (its glyphs are rasterised
    /// for that style only).
    pub style: &'static str,
    pub args: &'static [&'static str],
}

const fn s(key: &'static str, style: &'static str) -> StringSpec {
    StringSpec {
        key,
        style,
        args: &[],
    }
}

/// Every string, in `Str` order.
pub const STRINGS: &[StringSpec] = &[
    s("brand", "brand"),
    s("unattested", "banner"),
    s("incorrect", "banner"),
    s("path_refused", "banner"),
    s("hint_select", "hint"),
    s("hint_continue", "hint"),
    s("hint_back", "hint"),
    s("hint_other", "hint"),
    s("hint_show", "hint"),
    s("hint_hide", "hint"),
    s("hint_contrast", "hint"),
    s("hint_windows", "hint"),
    s("key_arrows", "key"),
    s("key_enter", "key"),
    s("key_esc", "key"),
    s("key_insert", "key"),
    s("key_theme", "key"),
    s("key_w", "key"),
    s("key_r", "key"),
    s("unlock_title", "title"),
    s("first_boot", "body"),
    s("row_password", "label"),
    s("row_passphrase", "label"),
    s("row_recovery_key", "label"),
    StringSpec {
        key: "attempts",
        style: "detail",
        args: &["n"],
    },
    s("attempt_last", "detail"),
    s("no_limit", "detail"),
    s("digits", "detail"),
    s("grey_restart", "detail"),
    s("grey_restart_why", "detail"),
    s("grey_locked", "detail"),
    s("grey_locked_why", "detail"),
    s("secret_password", "title"),
    s("secret_passphrase", "title"),
    s("secret_recovery_key", "title"),
    s("recovery_key_help", "body"),
    s("cannot_title", "title"),
    s("cannot_body", "body"),
    s("act_start_windows", "label"),
    s("act_need_linux", "label"),
    s("config_title", "title"),
    s("config_body", "body"),
    s("act_recover", "label"),
    s("locked_title", "title"),
    s("locked_body", "body"),
    s("act_try_another", "label"),
    s("hibernated_title", "title"),
    s("hibernated_body", "body"),
    s("dirty_title", "title"),
    s("dirty_body", "body"),
    s("act_continue_ro", "label"),
    s("act_restart_windows", "label"),
    s("pcr12_title", "title"),
    s("pcr12_body", "body"),
    s("plaintext_title", "title"),
    s("plaintext_body", "body"),
    s("missing_title", "title"),
    s("missing_body", "body"),
    s("act_recover_short", "label"),
    s("notimpl_title", "title"),
    s("notimpl_body", "body"),
    s("act_continue", "label"),
    s("noinst_title", "title"),
    s("noinst_body", "body"),
    s("noinst_fix", "body"),
    s("volumes_title", "title"),
    StringSpec {
        key: "volume_row",
        style: "label",
        args: &["disk", "part"],
    },
    s("format_bitlocker", "detail"),
    s("format_ntfs", "detail"),
    s("targets_title", "title"),
    s("targets_body", "body"),
    s("targets_empty", "body"),
    s("target_disk", "detail"),
    s("target_efi", "detail"),
    s("type_path", "label"),
    s("type_path_why", "detail"),
    s("path_title", "title"),
    s("path_help", "body"),
    s("path_label", "detail"),
    s("roots_title", "title"),
    s("roots_body", "body"),
    s("no_root", "label"),
    s("no_root_why", "detail"),
    s("unit_b", "detail"),
    s("unit_kb", "detail"),
    s("unit_mb", "detail"),
    s("unit_gb", "detail"),
    s("unit_tb", "detail"),
    s("decimal", "detail"),
];

/// Colour roles, in `Palette` field order.
pub const COLORS: &[&str] = &[
    "background",
    "text",
    "muted",
    "faint",
    "accent",
    "surface",
    "surface_selected",
    "border",
    "border_focus",
    "cursor",
    "key_border",
    "key_text",
    "banner_background",
    "banner_text",
    "toast_background",
    "toast_text",
];

/// Text styles, in `Style` order. The second field: the style shows text
/// not known at build time (typed text, file and partition names), so it
/// must carry all of Latin-1.
pub const STYLES: &[(&str, bool)] = &[
    ("brand", false),
    ("title", false),
    ("body", false),
    ("label", true),
    ("detail", false),
    ("field", true),
    ("hint", false),
    ("key", false),
    ("banner", false),
];

/// Screen kinds with their own layout, in `ScreenKind` order, and the
/// primitive each belongs to (DESIGN.md §4.1: five primitives).
pub const SCREENS: &[(&str, &str)] = &[
    ("unlock", "list"),
    ("secret", "field"),
    ("recovery_key", "field"),
    ("path", "field"),
    ("message", "message"),
    ("volumes", "list"),
    ("targets", "list"),
    ("roots", "list"),
];

pub const PRIMITIVES: &[&str] = &["list", "field", "message"];

pub const ANCHORS: &[(&str, &str)] = &[
    ("top-left", "TopLeft"),
    ("top-center", "TopCenter"),
    ("top-right", "TopRight"),
    ("center-left", "CenterLeft"),
    ("center", "Center"),
    ("center-right", "CenterRight"),
    ("bottom-left", "BottomLeft"),
    ("bottom-center", "BottomCenter"),
    ("bottom-right", "BottomRight"),
];

/// Characters every theme rasterises for every style regardless of the
/// strings: digits and separators for numbers, the fallback glyph.
pub const ALWAYS: &str = "0123456789 .,:-+?()/%·";

/// `snake_case` → `CamelCase` (the generated enum variants).
pub fn camel(key: &str) -> String {
    key.split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(f) => f.to_ascii_uppercase().to_string() + c.as_str(),
                None => String::new(),
            }
        })
        .collect()
}
