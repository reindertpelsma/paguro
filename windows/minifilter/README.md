# windows/minifilter

The Windows guest's filesystem minifilter (DESIGN.md §4.4). **Quality of
experience, not correctness** — the Linux module refuses every access to the
image's extents whether or not this driver is loaded. What it adds is clean
refusals instead of `EIO`:

- `FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP`; refuse detach for the session
- hold the image open with `MARK_HANDLE_PROTECT_CLUSTERS` so defrag skips it
- `dwShareMode = 0` on the image, which also blocks deletion over SMB
- refuse volume-wide transformations (BitLocker conversion) cleanly

Language: **C against the WDK** for now. `windows-drivers-rs` supports WDM/KMDF
drivers but has no filter-manager (`FltRegisterFilter`) bindings worth shipping
on, and this driver must pass attestation signing and HVCI compatibility
(§12, §11 Q17–Q20) — the conservative toolchain is the right one for a driver
that is not on the correctness path.
