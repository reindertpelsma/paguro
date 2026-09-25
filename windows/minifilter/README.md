# windows/minifilter

The paguro minifilter (DESIGN.md §4.4, INTERFACES.md §11.1). **Quality of
experience, not correctness**: the Linux module refuses every access to an
image's extents whether or not this driver is loaded. Inside the paguro VM,
this driver turns what would be `EIO` from the disk into clean refusals at the
filesystem (`STATUS_ACCESS_DENIED`), so Windows never half-writes a metadata
change against rejected sectors.

Language: **C against the WDK**. `windows-drivers-rs` has no filter-manager
bindings worth shipping on, and the driver must pass attestation signing and
HVCI (DESIGN.md §12); the conservative toolchain is right for a driver that is
not on the correctness path.

## Reviewing the driver

| File | Lines | What |
|---|---|---|
| `paguro_flt.c` | ~660 (≈140 comment) | the driver: table, callbacks, port, load/unload |
| `pg_smbios.c` / `.h` | ~90 / 30 | the VM marker in SMBIOS type 11 — pure C, unit-tested in user mode |
| `pg_msg.h` | ~70 | the port messages; mirrored in Rust (`crates/paguro-win/src/fltmsg.rs`, a test checks the constants) |
| `paguro_flt.inf`, `paguro_flt.vcxproj` | | install (boot-start, primitive driver) and build |
| `test/smbios_test.c` | | the SMBIOS parser: samples, malformed tables, truncations, 20 000 mutations (ASan/UBSan on Linux) |
| `test/pgflt_test.c` | | user-mode test of every deny path against the loaded driver |

Every function in `paguro_flt.c` carries a comment stating its invariant.
Read in this order: the header comment, `DriverEntry` (bottom), `PgMessage`
(the only input from user mode), `PgUpdate`/`PgLookup` (the table), then the
four callbacks.

### Invariants

- **All policy is in user mode.** The driver enforces one fixed table
  (`PG_MAX_PROTECTED` = 32 entries) of (volume GUID, 128-bit file id) → deny
  flags, set only through `\PaguroPort`.
- **The port is admin-only and single-client.** `FltBuildDefaultSecurityDescriptor`
  (Administrators, SYSTEM), `MaxConnections = 1`. The connected process is the
  paguro service and is **exempt**; every other requestor — other processes,
  the SMB server (so `rm /mnt/c/linux.vhd` over SMB is refused), non-paging
  kernel requests — is refused.
- **Inputs are fixed-size.** A message is accepted only if it is exactly
  `sizeof(PG_MESSAGE)` (56 bytes), copied once under `__try`, and every field
  validates (magic, version, known type, known flag bits, unused fields zero,
  non-zero volume). The only other parsed input is SMBIOS, once, at
  `DriverEntry`, by a bounded parser that treats anything malformed as
  "native".
- **Unknown means allow.** Whenever the driver cannot tell (no volume GUID yet,
  not `PASSIVE_LEVEL`, a query failed), it allows: it is never the correctness
  boundary, and a wrongful refusal is worse than a missed one.
- **Native boots are inert.** Without the `paguro-vm/1` OEM string
  (`-smbios type=11,value=paguro-vm/1` on the QEMU command line — the VM
  launcher must set it) `DriverEntry` registers nothing — no filter, no
  instances, no port — sets `DriverUnload` and returns success, so `sc stop`
  unloads it like any legacy driver. `DBG` builds also accept
  `HKLM\SYSTEM\CurrentControlSet\Services\PaguroFlt\Parameters\ForceVmMode = 1`
  (for the hosted test runner); release builds compile that out.
- **In the VM it does not unload** (`FLTFL_REGISTRATION_DO_NOT_SUPPORT_SERVICE_STOP`;
  unload and manual detach answer `STATUS_FLT_DO_NOT_DETACH`) until the
  service sends `ALLOW_UNLOAD`, the one explicit admin request.
- **No state across reboots.** The service re-sends `PROTECT` for every image
  at start; a service disconnect keeps the table (clean refusals continue)
  and ends only the exemption.

### Deny paths

| Flag | Operation | Where | Test (`pgflt_test`) |
|---|---|---|---|
| `PG_DENY_OPEN` | `IRP_MJ_CREATE`, any access, by path or by file id | post-create: the id is known only once open; `FltCancelFileOpen` | open by path, `OpenFileById`, `DeleteFile`, `MoveFile`, hard link |
| `PG_DENY_SETINFO` | delete (incl. `Ex`), rename (incl. `Ex`), hard link, end of file, allocation, valid data length, short name | pre-set-information | disposition, rename, EOF, allocation through a handle opened before protection |
| `PG_DENY_WRITE` | non-paging `IRP_MJ_WRITE` | pre-write | write through a pre-existing handle |
| `PG_DENY_FSCTL` | `FSCTL_MOVE_FILE` naming the file (what defragmenters use), `MARK_HANDLE`, `SET_SPARSE`, `SET_ZERO_DATA`, `SET_COMPRESSION`, reparse set/delete, `SET_INTEGRITY_INFORMATION`, `FILE_LEVEL_TRIM`, `DUPLICATE_EXTENTS_TO_FILE`, `SET_ZERO_ON_DEALLOCATION`, `SET_ENCRYPTION` | pre-FSCTL | `MOVE_FILE`, `MARK_HANDLE`, `SET_SPARSE`, `SET_ZERO_DATA` |

Each refusal is reported to the service as an `EVENT` (file id, operation,
process id, status), best effort: zero timeout, never blocking. The test also
checks the control case — after `UNPROTECT` the same operations reach NTFS —
the exemption of the service, message validation (13 malformed messages), the
single-client rule, and the unload refusal before and after `ALLOW_UNLOAD`.

### What it deliberately does not do

- **Pin or protect clusters itself.** `MARK_HANDLE_PROTECT_CLUSTERS` and the
  share-mode-0 handle are the service's (user-mode, exempt); the driver only
  stops anyone else from undoing them. Pinning at `DriverEntry` is impossible
  anyway (DESIGN.md §4.4: instances attach when C: mounts).
- **Paging I/O.** Not registered: the cache and memory managers write data an
  earlier, already-checked write produced; failing them corrupts nothing but
  helps nothing.
- **Volume-wide transformations.** BitLocker conversion runs in `fvevol`
  below the filesystem, and `FSCTL_SHRINK_VOLUME` moves clusters through
  `FSCTL_MOVE_FILE` (covered). §5.7's clean refusal of a conversion is **not
  covered** by this driver.
- **Raw volume writes** (`\\.\C:` opened for write) bypass file identity; the
  Linux module refuses those sectors.
- **Anything across reboots**, and any parsing beyond the two inputs above.

## Building and testing

CI (`.github/workflows/windows.yml`, `windows-2022`): `msbuild` Debug and
Release x64, `/analyze` (PREfast with the driver rules) and CodeQL; the test
certificate signs `paguro_flt.sys` and the catalog; the runner (test signing
on) installs it, loads it **inert** (no marker on a hosted runner) and runs
`pgflt_test inert` and `sc stop`; then sets `ForceVmMode = 1`, loads the
Debug build **active** and runs `pgflt_test active`.

Locally, the parser test runs anywhere:

```sh
cc -std=c99 -Wall -Wextra -Werror -fsanitize=address,undefined -Iwindows/minifilter \
   windows/minifilter/pg_smbios.c windows/minifilter/test/smbios_test.c -o /tmp/smbios_test && /tmp/smbios_test
```
