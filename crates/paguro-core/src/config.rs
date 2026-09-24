//! The `paguro.ini` schema v1 (INTERFACES.md §3.2) over the frozen grammar of
//! [`crate::ini`].
//!
//! Only reached in stage 2, after the whole file's SHA-256 matched the firmware
//! variable (or with Secure Boot off, after nothing — which is why it is still
//! hardened). Rules on top of the grammar (§3.1):
//!
//! - duplicate keys within a known section are an error (also across repeated
//!   `[section]` headers of the same name);
//! - unknown sections are ignored; unknown keys in a known section are an error;
//! - keys before the first `[section]` are an error;
//! - every value is typed and bounded here, so nothing downstream re-validates;
//! - errors about a section header (bad image name, too many images) carry the
//!   line of the section's first key: the grammar yields entries, not headers,
//!   and a header with no keys configures nothing.
//!
//! Output is borrowed from the input buffer: no allocation, fixed capacity
//! ([`MAX_IMAGES`]).
//!
//! `#` starts a comment only at the beginning of a line (the frozen grammar);
//! the trailing annotations in §3.2's example are documentation, and an NTFS
//! path may legitimately contain `#`.

use crate::guid::{Guid, GuidError};
use crate::ini::{self, IniError};

pub const MAX_IMAGES: usize = 16;
pub const MAX_NAME: usize = 32;
pub const MAX_PATH_BYTES: usize = 1024;
pub const MAX_COMPONENTS: usize = 32;
pub const MAX_COMPONENT_UTF16: usize = 255;
/// The chain target when `chain` is absent.
pub const DEFAULT_CHAIN: &str = "\\EFI\\BOOT\\BOOTX64.EFI";
/// The first line [`write`] emits.
pub const HEADER_COMMENT: &str = "# paguro configuration. Not hand-editable: use `paguro config`.";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Format {
    /// Fixed VHD: payload followed by a 512-byte footer.
    Vhd,
    Raw,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expose {
    Block,
    File,
}

impl Format {
    pub const fn as_str(self) -> &'static str {
        match self {
            Format::Vhd => "vhd",
            Format::Raw => "raw",
        }
    }
}

impl Expose {
    pub const fn as_str(self) -> &'static str {
        match self {
            Expose::Block => "block",
            Expose::File => "file",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Image<'a> {
    pub name: &'a str,
    /// Absolute NTFS path, validated by [`check_path`].
    pub path: &'a str,
    pub format: Format,
    pub expose: Expose,
    /// Path inside the nested ESP; [`DEFAULT_CHAIN`] when absent.
    pub chain: &'a str,
}

impl Image<'_> {
    pub const EMPTY: Image<'static> = Image {
        name: "",
        path: "",
        format: Format::Vhd,
        expose: Expose::Block,
        chain: DEFAULT_CHAIN,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config<'a> {
    /// GPT partition GUID of the NTFS volume.
    pub volume: Guid,
    /// Index into `images` of the `default` image.
    pub default: usize,
    pub images: [Image<'a>; MAX_IMAGES],
    pub image_count: usize,
    pub tpm: bool,
    pub setup_tpm: bool,
    pub passphrase: bool,
}

impl<'a> Config<'a> {
    pub fn images(&self) -> &[Image<'a>] {
        self.images.get(..self.image_count).unwrap_or(&[])
    }
    pub fn default_image(&self) -> Option<&Image<'a>> {
        self.images().get(self.default)
    }
}

/// Which required key was missing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Missing {
    PaguroSection,
    Version,
    Default,
    Volume,
    /// An image without `path`; the index is the order of first appearance.
    ImagePath(usize),
    ImageFormat(usize),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathError {
    Empty,
    NotAbsolute,
    TooLong,
    TooManyComponents,
    EmptyComponent,
    DotComponent,
    ComponentTooLong,
    BadChar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigError {
    Ini(IniError),
    KeyOutsideSection {
        line: usize,
    },
    DuplicateKey {
        line: usize,
    },
    UnknownKey {
        line: usize,
    },
    Missing(Missing),
    UnsupportedVersion {
        line: usize,
    },
    BadInteger {
        line: usize,
    },
    BadBool {
        line: usize,
    },
    BadGuid {
        line: usize,
        err: GuidError,
    },
    BadImageName {
        line: usize,
    },
    TooManyImages {
        line: usize,
    },
    BadFormat {
        line: usize,
    },
    BadExpose {
        line: usize,
    },
    BadPath {
        line: usize,
        err: PathError,
    },
    /// `default` names no `[Image.*]` section.
    DefaultNotFound,
}

impl From<IniError> for ConfigError {
    fn from(e: IniError) -> Self {
        ConfigError::Ini(e)
    }
}

/// `[A-Za-z0-9_-]{1,32}`.
pub fn check_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

/// An absolute backslash path: `\a\b`, no empty, `.` or `..` components, at most
/// 32 components of at most 255 UTF-16 units, at most 1024 bytes, and none of
/// the characters NTFS/Win32 forbid in names.
pub fn check_path(s: &str) -> Result<(), PathError> {
    if s.is_empty() {
        return Err(PathError::Empty);
    }
    if s.len() > MAX_PATH_BYTES {
        return Err(PathError::TooLong);
    }
    let Some(rest) = s.strip_prefix('\\') else {
        return Err(PathError::NotAbsolute);
    };
    let mut n = 0usize;
    for comp in rest.split('\\') {
        n += 1;
        if n > MAX_COMPONENTS {
            return Err(PathError::TooManyComponents);
        }
        if comp.is_empty() {
            return Err(PathError::EmptyComponent);
        }
        if comp == "." || comp == ".." {
            return Err(PathError::DotComponent);
        }
        if comp.chars().map(char::len_utf16).sum::<usize>() > MAX_COMPONENT_UTF16 {
            return Err(PathError::ComponentTooLong);
        }
        if comp
            .chars()
            .any(|c| c < ' ' || c == '\u{7f}' || "/:*?\"<>|".contains(c))
        {
            return Err(PathError::BadChar);
        }
    }
    Ok(())
}

fn parse_bool(v: &str, line: usize) -> Result<bool, ConfigError> {
    match v {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(ConfigError::BadBool { line }),
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section<'a> {
    None,
    Paguro,
    Image(usize),
    Tpm,
    SetupTpm,
    Passphrase,
    Ignored(&'a str),
}

/// Seen-key bits, one mask per known section.
const K_VERSION: u8 = 1;
const K_DEFAULT: u8 = 2;
const K_VOLUME: u8 = 4;
const K_PATH: u8 = 1;
const K_FORMAT: u8 = 2;
const K_EXPOSE: u8 = 4;
const K_CHAIN: u8 = 8;
const K_ENABLED: u8 = 1;

fn mark(seen: &mut u8, bit: u8, line: usize) -> Result<(), ConfigError> {
    if *seen & bit != 0 {
        return Err(ConfigError::DuplicateKey { line });
    }
    *seen |= bit;
    Ok(())
}

/// Parse and validate. A malformed file is refused whole.
pub fn parse(input: &[u8]) -> Result<Config<'_>, ConfigError> {
    let mut cfg = Config {
        volume: Guid::ZERO,
        default: 0,
        images: [Image::EMPTY; MAX_IMAGES],
        image_count: 0,
        tpm: true,
        setup_tpm: true,
        passphrase: false,
    };
    let mut paguro_section = false;
    let mut paguro_seen = 0u8;
    let mut image_seen = [0u8; MAX_IMAGES];
    let mut tpm_seen = 0u8;
    let mut setup_seen = 0u8;
    let mut pass_seen = 0u8;
    let mut default_name: Option<&str> = None;
    let mut cur_name: &str = "";
    let mut sect = Section::None;

    for entry in ini::parse(input)? {
        let e = entry?;
        let line = e.line;
        if e.section != cur_name || sect == Section::None {
            cur_name = e.section;
            sect = match e.section {
                "" => Section::None,
                "Paguro" => {
                    paguro_section = true;
                    Section::Paguro
                }
                "TPM" => Section::Tpm,
                "SetupTPM" => Section::SetupTpm,
                "Passphrase" => Section::Passphrase,
                s => match s.strip_prefix("Image.") {
                    Some(name) => {
                        if !check_name(name) {
                            return Err(ConfigError::BadImageName { line });
                        }
                        let found = cfg.images().iter().position(|i| i.name == name);
                        let idx = match found {
                            Some(i) => i,
                            None => {
                                let i = cfg.image_count;
                                let slot = cfg
                                    .images
                                    .get_mut(i)
                                    .ok_or(ConfigError::TooManyImages { line })?;
                                slot.name = name;
                                cfg.image_count += 1;
                                i
                            }
                        };
                        Section::Image(idx)
                    }
                    None => Section::Ignored(s),
                },
            };
        }
        let v = e.value;
        match sect {
            Section::None => return Err(ConfigError::KeyOutsideSection { line }),
            Section::Ignored(_) => {}
            Section::Paguro => match e.key {
                "version" => {
                    mark(&mut paguro_seen, K_VERSION, line)?;
                    if v != "1" {
                        return Err(if !v.is_empty() && v.bytes().all(|c| c.is_ascii_digit()) {
                            ConfigError::UnsupportedVersion { line }
                        } else {
                            ConfigError::BadInteger { line }
                        });
                    }
                }
                "default" => {
                    mark(&mut paguro_seen, K_DEFAULT, line)?;
                    if !check_name(v) {
                        return Err(ConfigError::BadImageName { line });
                    }
                    default_name = Some(v);
                }
                "volume" => {
                    mark(&mut paguro_seen, K_VOLUME, line)?;
                    cfg.volume =
                        Guid::parse(v).map_err(|err| ConfigError::BadGuid { line, err })?;
                }
                _ => return Err(ConfigError::UnknownKey { line }),
            },
            Section::Image(idx) => {
                let seen = image_seen
                    .get_mut(idx)
                    .ok_or(ConfigError::TooManyImages { line })?;
                let img = cfg
                    .images
                    .get_mut(idx)
                    .ok_or(ConfigError::TooManyImages { line })?;
                match e.key {
                    "path" => {
                        mark(seen, K_PATH, line)?;
                        check_path(v).map_err(|err| ConfigError::BadPath { line, err })?;
                        img.path = v;
                    }
                    "format" => {
                        mark(seen, K_FORMAT, line)?;
                        img.format = match v {
                            "vhd" => Format::Vhd,
                            "raw" => Format::Raw,
                            _ => return Err(ConfigError::BadFormat { line }),
                        };
                    }
                    "expose" => {
                        mark(seen, K_EXPOSE, line)?;
                        img.expose = match v {
                            "block" => Expose::Block,
                            "file" => Expose::File,
                            _ => return Err(ConfigError::BadExpose { line }),
                        };
                    }
                    "chain" => {
                        mark(seen, K_CHAIN, line)?;
                        check_path(v).map_err(|err| ConfigError::BadPath { line, err })?;
                        img.chain = v;
                    }
                    _ => return Err(ConfigError::UnknownKey { line }),
                }
            }
            Section::Tpm | Section::SetupTpm | Section::Passphrase => {
                if e.key != "enabled" {
                    return Err(ConfigError::UnknownKey { line });
                }
                let (seen, flag) = match sect {
                    Section::Tpm => (&mut tpm_seen, &mut cfg.tpm),
                    Section::SetupTpm => (&mut setup_seen, &mut cfg.setup_tpm),
                    _ => (&mut pass_seen, &mut cfg.passphrase),
                };
                mark(seen, K_ENABLED, line)?;
                *flag = parse_bool(v, line)?;
            }
        }
    }

    if !paguro_section {
        return Err(ConfigError::Missing(Missing::PaguroSection));
    }
    for (bit, what) in [
        (K_VERSION, Missing::Version),
        (K_DEFAULT, Missing::Default),
        (K_VOLUME, Missing::Volume),
    ] {
        if paguro_seen & bit == 0 {
            return Err(ConfigError::Missing(what));
        }
    }
    for (i, seen) in image_seen.iter().take(cfg.image_count).enumerate() {
        if seen & K_PATH == 0 {
            return Err(ConfigError::Missing(Missing::ImagePath(i)));
        }
        if seen & K_FORMAT == 0 {
            return Err(ConfigError::Missing(Missing::ImageFormat(i)));
        }
    }
    let default_name = default_name.ok_or(ConfigError::Missing(Missing::Default))?;
    cfg.default = cfg
        .images()
        .iter()
        .position(|i| i.name == default_name)
        .ok_or(ConfigError::DefaultNotFound)?;
    Ok(cfg)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// The output buffer is too small.
    Full,
    /// The configuration would not parse back (bad name, path, default index…).
    Invalid,
}

impl From<crate::bytes::Full> for WriteError {
    fn from(_: crate::bytes::Full) -> Self {
        WriteError::Full
    }
}

/// Serialise canonically. `parse(write(c)) == c` for every valid `c` (checked
/// by property test), so the loader can author the configuration the initrd
/// writes on a provisioning boot and seal against its hash.
pub fn write(cfg: &Config<'_>, out: &mut [u8]) -> Result<usize, WriteError> {
    if cfg.image_count == 0 || cfg.image_count > MAX_IMAGES {
        return Err(WriteError::Invalid);
    }
    let default = cfg.default_image().ok_or(WriteError::Invalid)?;
    for (i, img) in cfg.images().iter().enumerate() {
        if !check_name(img.name)
            || check_path(img.path).is_err()
            || check_path(img.chain).is_err()
            || cfg.images().iter().take(i).any(|o| o.name == img.name)
        {
            return Err(WriteError::Invalid);
        }
    }
    let mut w = crate::bytes::Writer::new(out);
    let b = |x: bool| if x { "1" } else { "0" };
    w.put(HEADER_COMMENT.as_bytes())?;
    w.put(b"\n[Paguro]\nversion = 1\ndefault = ")?;
    w.put(default.name.as_bytes())?;
    w.put(b"\nvolume = ")?;
    w.put(&cfg.volume.to_text())?;
    w.put(b"\n")?;
    for img in cfg.images() {
        w.put(b"\n[Image.")?;
        w.put(img.name.as_bytes())?;
        w.put(b"]\npath = ")?;
        w.put(img.path.as_bytes())?;
        w.put(b"\nformat = ")?;
        w.put(img.format.as_str().as_bytes())?;
        w.put(b"\nexpose = ")?;
        w.put(img.expose.as_str().as_bytes())?;
        w.put(b"\nchain = ")?;
        w.put(img.chain.as_bytes())?;
        w.put(b"\n")?;
    }
    for (name, v) in [
        ("TPM", cfg.tpm),
        ("SetupTPM", cfg.setup_tpm),
        ("Passphrase", cfg.passphrase),
    ] {
        w.put(b"\n[")?;
        w.put(name.as_bytes())?;
        w.put(b"]\nenabled = ")?;
        w.put(b(v).as_bytes())?;
        w.put(b"\n")?;
    }
    if w.len() > ini::MAX_LEN {
        return Err(WriteError::Invalid);
    }
    Ok(w.len())
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    pub(crate) const GOOD: &str = "# paguro configuration. Not hand-editable: use `paguro config`.
[Paguro]
version     = 1
default     = debian
volume      = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8

[Image.debian]
path        = \\paguro\\debian.vhd
format      = vhd
expose      = block
chain       = \\EFI\\BOOT\\BOOTX64.EFI

[Image.arch]
path   = \\paguro\\arch #1.img
format = raw

[TPM]
enabled     = 1

[SetupTPM]
enabled     = 0

[Passphrase]
enabled     = 1

[Future]
anything = goes
";

    fn err(src: &str) -> ConfigError {
        parse(src.as_bytes()).unwrap_err()
    }

    fn with(replace: &str, by: &str) -> ConfigError {
        assert!(GOOD.contains(replace), "{replace}");
        err(&GOOD.replacen(replace, by, 1))
    }

    #[test]
    fn parses_the_documented_schema() {
        let c = parse(GOOD.as_bytes()).unwrap();
        assert_eq!(c.image_count, 2);
        assert_eq!(c.default_image().unwrap().name, "debian");
        assert_eq!(c.images()[1].path, "\\paguro\\arch #1.img");
        assert_eq!(c.images()[1].format, Format::Raw);
        assert_eq!(c.images()[1].expose, Expose::Block);
        assert_eq!(c.images()[1].chain, DEFAULT_CHAIN);
        assert_eq!(
            c.volume,
            Guid::parse("6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8").unwrap()
        );
        assert!(c.tpm && !c.setup_tpm && c.passphrase);
    }

    #[test]
    fn crlf_and_repeated_headers_merge() {
        let src = GOOD.replace('\n', "\r\n");
        assert!(parse(src.as_bytes()).is_ok());
        let split = "[Paguro]\nversion=1\n[Image.a]\npath=\\a\n[Paguro]\ndefault=a\nvolume=6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\n[Image.a]\nformat=raw\n";
        let c = parse(split.as_bytes()).unwrap();
        assert_eq!((c.image_count, c.images()[0].format), (1, Format::Raw));
        assert!(c.tpm && c.setup_tpm && !c.passphrase, "section defaults");
    }

    #[test]
    fn every_error_variant() {
        assert_eq!(
            err("[x"),
            ConfigError::Ini(IniError::BadSection { line: 1 })
        );
        assert_eq!(
            err("a=b\n[Paguro]"),
            ConfigError::KeyOutsideSection { line: 1 }
        );
        assert_eq!(
            with("format      = vhd", "format = vhd\nformat = raw"),
            ConfigError::DuplicateKey { line: 10 }
        );
        assert_eq!(
            with("version     = 1", "version = 1\n[TPM]\n[Paguro]\nversion=1"),
            ConfigError::DuplicateKey { line: 6 }
        );
        assert_eq!(
            with("expose      = block", "exposé = block"),
            ConfigError::UnknownKey { line: 10 }
        );
        assert_eq!(
            with("volume ", "volumes "),
            ConfigError::UnknownKey { line: 5 }
        );
        assert_eq!(
            with("enabled     = 1\n\n[SetupTPM]", "enable = 1\n\n[SetupTPM]"),
            ConfigError::UnknownKey { line: 18 }
        );
        assert_eq!(
            err("[Other]\nx=1\n"),
            ConfigError::Missing(Missing::PaguroSection)
        );
        assert_eq!(
            with("version     = 1\n", ""),
            ConfigError::Missing(Missing::Version)
        );
        assert_eq!(
            with("default     = debian\n", ""),
            ConfigError::Missing(Missing::Default)
        );
        assert_eq!(
            with("volume      = 6c0a1b2c-3d4e-5f60-7182-93a4b5c6d7e8\n", ""),
            ConfigError::Missing(Missing::Volume)
        );
        assert_eq!(
            with("path        = \\paguro\\debian.vhd\n", ""),
            ConfigError::Missing(Missing::ImagePath(0))
        );
        assert_eq!(
            with("format = raw\n", ""),
            ConfigError::Missing(Missing::ImageFormat(1))
        );
        assert_eq!(
            with("version     = 1", "version = 2"),
            ConfigError::UnsupportedVersion { line: 3 }
        );
        assert_eq!(
            with("version     = 1", "version = 01x"),
            ConfigError::BadInteger { line: 3 }
        );
        assert_eq!(
            with("version     = 1", "version ="),
            ConfigError::BadInteger { line: 3 }
        );
        assert_eq!(
            with("enabled     = 1", "enabled = yes"),
            ConfigError::BadBool { line: 18 }
        );
        assert_eq!(
            with("6c0a1b2c-3d4e", "6c0a1b2c_3d4e"),
            ConfigError::BadGuid {
                line: 5,
                err: GuidError::BadSeparator
            }
        );
        assert_eq!(
            with("[Image.arch]", "[Image.a.b]"),
            ConfigError::BadImageName { line: 14 }
        );
        assert_eq!(
            with("[Image.arch]", "[Image.]"),
            ConfigError::BadImageName { line: 14 }
        );
        assert_eq!(
            with("default     = debian", "default = de bian"),
            ConfigError::BadImageName { line: 4 }
        );
        assert_eq!(
            with("format      = vhd", "format = vhdx"),
            ConfigError::BadFormat { line: 9 }
        );
        assert_eq!(
            with("expose      = block", "expose = both"),
            ConfigError::BadExpose { line: 10 }
        );
        assert_eq!(
            with("\\paguro\\debian.vhd", "paguro\\debian.vhd"),
            ConfigError::BadPath {
                line: 8,
                err: PathError::NotAbsolute
            }
        );
        assert_eq!(
            with(
                "chain       = \\EFI\\BOOT\\BOOTX64.EFI",
                "chain = \\EFI\\..\\x"
            ),
            ConfigError::BadPath {
                line: 11,
                err: PathError::DotComponent
            }
        );
        assert_eq!(
            with("default     = debian", "default = gentoo"),
            ConfigError::DefaultNotFound
        );

        let mut many = std::string::String::from("[Paguro]\n");
        for i in 0..=MAX_IMAGES {
            many.push_str(&std::format!("[Image.i{i}]\npath=\\x\nformat=raw\n"));
        }
        assert_eq!(err(&many), ConfigError::TooManyImages { line: 51 });
        let big = std::vec![b'#'; ini::MAX_LEN + 1];
        assert_eq!(
            parse(&big).unwrap_err(),
            ConfigError::Ini(IniError::TooLarge)
        );
    }

    #[test]
    fn path_rules() {
        use PathError::*;
        let long_comp = std::format!("\\{}", "a".repeat(256));
        let ok_comp = std::format!("\\{}", "é".repeat(255));
        let too_many = "\\a".repeat(33);
        let too_long = std::format!("\\{}", "a".repeat(1024));
        let cases: &[(&str, Result<(), PathError>)] = &[
            ("\\a\\b.vhd", Ok(())),
            (&ok_comp, Ok(())),
            (&"\\a".repeat(32), Ok(())),
            ("", Err(Empty)),
            ("a", Err(NotAbsolute)),
            ("/a", Err(NotAbsolute)),
            (&too_long, Err(TooLong)),
            (&too_many, Err(TooManyComponents)),
            ("\\", Err(EmptyComponent)),
            ("\\a\\\\b", Err(EmptyComponent)),
            ("\\a\\", Err(EmptyComponent)),
            ("\\.", Err(DotComponent)),
            ("\\a\\..", Err(DotComponent)),
            (&long_comp, Err(ComponentTooLong)),
            ("\\a/b", Err(BadChar)),
            ("\\a:b", Err(BadChar)),
            ("\\a\u{1}", Err(BadChar)),
            ("\\a\u{7f}", Err(BadChar)),
        ];
        for (p, want) in cases {
            assert_eq!(check_path(p), *want, "{p:?}");
        }
        // 128 surrogate pairs = 256 UTF-16 units.
        assert_eq!(
            check_path(&std::format!("\\{}", "😀".repeat(128))),
            Err(ComponentTooLong)
        );
    }

    #[test]
    fn names() {
        assert!(check_name("a-B_9"));
        assert!(check_name(&"a".repeat(32)));
        assert!(!check_name(&"a".repeat(33)));
        assert!(!check_name(""));
        assert!(!check_name("a.b"));
    }

    #[test]
    fn write_roundtrips_and_refuses_invalid() {
        let c = parse(GOOD.as_bytes()).unwrap();
        let mut buf = [0u8; 4096];
        let n = write(&c, &mut buf).unwrap();
        assert!(buf[..n].starts_with(HEADER_COMMENT.as_bytes()));
        assert_eq!(parse(&buf[..n]).unwrap(), c);
        assert_eq!(write(&c, &mut buf[..10]), Err(WriteError::Full));

        let mut bad = c;
        bad.default = 5;
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.image_count = 0;
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.images[1].name = "debian";
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.images[0].path = "x";
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
        let mut bad = c;
        bad.images[0].chain = "\\..";
        assert_eq!(write(&bad, &mut buf), Err(WriteError::Invalid));
    }
}
