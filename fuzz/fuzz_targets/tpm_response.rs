//! TPM 2.0 response parsing (INTERFACES.md §12: "TPM response parsing") —
//! the framing parser under every command shape, and each command's
//! parameter parser.
#![no_main]

use libfuzzer_sys::fuzz_target;
use paguro_core::tpm;

fuzz_target!(|data: &[u8]| {
    let Some((&sel, body)) = data.split_first() else { return };
    let has_handle = sel & 1 == 1;
    let sessions = usize::from((sel >> 1) & 3);
    if let Ok(r) = tpm::response(body, has_handle, sessions) {
        assert!(r.params.len() <= body.len());
        assert_eq!(r.session_count, sessions);
        let _ = tpm::parse_pcr_read(r.params);
    }
    let _ = tpm::parse_pcr_read(body).map(|v| {
        for i in 0..32 {
            let _ = v.get(i);
        }
    });
    let _ = tpm::parse_create_primary(body);
    if let Ok(c) = tpm::parse_create(body) {
        assert!(c.private.len() + c.public.len() <= body.len());
    }
    let _ = tpm::parse_load(body);
    let _ = tpm::parse_start_auth_session(body);
    let _ = tpm::parse_unseal(body);
    let _ = tpm::parse_read_clock(body);
    let _ = tpm::parse_get_properties(body).map(|p| p.get(tpm::PT_LOCKOUT_COUNTER));
    let _ = tpm::parse_empty(body);
});
