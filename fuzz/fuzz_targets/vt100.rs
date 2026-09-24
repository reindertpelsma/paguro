//! Serial console input (INTERFACES.md §13.2a): bytes from whatever is on
//! the other end of the cable, decoded into keys. `0xff` stands for "the
//! line went quiet" (it is never valid UTF-8, so no key is lost to it).
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_boot::ui::Key;
use paguro_boot::vt100::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut d = Decoder::new();
    let mut n = 0usize;
    for &b in data {
        let k = if b == 0xff { d.idle() } else { d.feed(b) };
        if let Some(Key::Char(c)) = k {
            assert!(!c.is_control());
        }
        n += usize::from(k.is_some());
    }
    let _ = d.idle();
    assert!(!d.pending());
    assert!(n <= data.len());
    // Printable ASCII alone is exactly its characters.
    if !data.is_empty() && data.iter().all(|b| (0x20..0x7f).contains(b)) {
        let mut d = Decoder::new();
        let keys: Vec<Key> = data.iter().filter_map(|&b| d.feed(b)).collect();
        let want: Vec<Key> = data.iter().map(|&b| Key::Char(char::from(b))).collect();
        assert_eq!(keys, want);
    }
});
