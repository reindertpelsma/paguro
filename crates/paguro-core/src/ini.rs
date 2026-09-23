//! The frozen `paguro.ini` grammar (DESIGN.md §6).
//!
//! `[section]`, `key=value`, `#comment`; surrounding whitespace stripped; blank
//! lines and unknown keys ignored by the caller. **No includes, continuations,
//! escapes or interpolation** — every future feature lands above this parser,
//! never inside it.
//!
//! The parser only ever sees bytes whose SHA-256 already matched
//! `paguro-config-hash` (stage 1). It is hardened anyway: every parser in the
//! loader is (§6, "Every parser is hardened").

/// Configuration files larger than this are refused before being read.
pub const MAX_LEN: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IniError {
    TooLarge,
    NotUtf8 { line: usize },
    BadSection { line: usize },
    MissingEquals { line: usize },
    EmptyKey { line: usize },
}

/// One `key=value` with the section it appeared under (`""` before any header).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    pub section: &'a str,
    pub key: &'a str,
    pub value: &'a str,
    pub line: usize,
}

/// Iterate entries. Allocation-free; errors are yielded, and callers stop at the
/// first one — a malformed configuration is refused, never partially applied.
type Lines<'a> = core::iter::Enumerate<core::slice::Split<'a, u8, fn(&u8) -> bool>>;

pub struct Parser<'a> {
    lines: Lines<'a>,
    section: &'a str,
}

fn is_nl(b: &u8) -> bool {
    *b == b'\n'
}

pub fn parse(input: &[u8]) -> Result<Parser<'_>, IniError> {
    if input.len() > MAX_LEN {
        return Err(IniError::TooLarge);
    }
    let split: core::slice::Split<'_, u8, fn(&u8) -> bool> = input.split(is_nl);
    Ok(Parser {
        lines: split.enumerate(),
        section: "",
    })
}

impl<'a> Iterator for Parser<'a> {
    type Item = Result<Entry<'a>, IniError>;

    fn next(&mut self) -> Option<Self::Item> {
        for (idx, raw) in self.lines.by_ref() {
            let line = idx + 1;
            let Ok(text) = core::str::from_utf8(raw) else {
                return Some(Err(IniError::NotUtf8 { line }));
            };
            let t = text.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            if let Some(rest) = t.strip_prefix('[') {
                let Some(name) = rest.strip_suffix(']') else {
                    return Some(Err(IniError::BadSection { line }));
                };
                let name = name.trim();
                if name.is_empty() || name.contains(['[', ']']) {
                    return Some(Err(IniError::BadSection { line }));
                }
                self.section = name;
                continue;
            }
            let Some((k, v)) = t.split_once('=') else {
                return Some(Err(IniError::MissingEquals { line }));
            };
            let key = k.trim();
            if key.is_empty() {
                return Some(Err(IniError::EmptyKey { line }));
            }
            return Some(Ok(Entry {
                section: self.section,
                key,
                value: v.trim(),
                line,
            }));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sections_and_ignores_comments() {
        let src = b"# header\n[Paguro]\nimage = \\\\linux.vhd\n\n[TPM]\npcrs=0,2,4,7\n";
        let got: [Entry<'_>; 2] = {
            let mut it = parse(src).unwrap();
            [it.next().unwrap().unwrap(), it.next().unwrap().unwrap()]
        };
        assert_eq!(
            (got[0].section, got[0].key, got[0].value),
            ("Paguro", "image", "\\\\linux.vhd")
        );
        assert_eq!(
            (got[1].section, got[1].key, got[1].value),
            ("TPM", "pcrs", "0,2,4,7")
        );
    }

    #[test]
    fn refuses_malformed_input() {
        assert_eq!(
            parse(b"[Paguro\n").unwrap().next(),
            Some(Err(IniError::BadSection { line: 1 }))
        );
        assert_eq!(
            parse(b"novalue\n").unwrap().next(),
            Some(Err(IniError::MissingEquals { line: 1 }))
        );
        assert_eq!(
            parse(b" = x\n").unwrap().next(),
            Some(Err(IniError::EmptyKey { line: 1 }))
        );
        assert_eq!(
            parse(&[0xff, b'\n']).unwrap().next(),
            Some(Err(IniError::NotUtf8 { line: 1 }))
        );
    }

    #[test]
    fn refuses_oversized_file() {
        static BIG: [u8; MAX_LEN + 1] = [b'#'; MAX_LEN + 1];
        assert!(matches!(parse(&BIG), Err(IniError::TooLarge)));
    }
}
