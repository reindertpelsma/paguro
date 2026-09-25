# paguro-win

The Windows side, terminal first: the `paguro` command-line tool — pre-flight
checks, install, repair, uninstall, and reading host hardware for the WSL2
on-ramp. Runs on Windows (the real Win32 backend); command logic also runs
and is tested on Linux/macOS against an in-memory mock. `#![deny(unsafe_code)]`
outside the Win32 adapter.

## Its place in paguro

Every command is written against `WinApi`, a trait covering every
OS touchpoint, so the same logic runs against `mock::MockApi` (any host) or
`real::RealApi` (Windows only, Win32 calls). Formats are never reimplemented
here: `paguro.ini`, seals, load options, signature lists, SMBIOS, the TCG log,
BitLocker metadata and the TPM client all come from
[`paguro-core`](../paguro-core), [`paguro-crypto`](../paguro-crypto) and
[`paguro-boot`](../paguro-boot) — the loader and Windows share one
implementation of the TPM client and BitLocker unlock. Every command is one
method of the Windows API (`rpc`, INTERFACES §11.7; the contract is
[`windows/api/paguro-api.json`](../../windows/api/paguro-api.json)):
[`paguro-service`](../paguro-service) serves it over `\\.\pipe\paguro`, and
`paguro.exe` is a thin client of that service when it is installed, running
the same method in-process otherwise (`--direct`). The PowerShell module and
the GUI call the pipe too; nobody parses `--json` text. See [`docs/INTERFACES.md`](../../docs/INTERFACES.md) §11 and
[`docs/DESIGN.md`](../../docs/DESIGN.md) §4.6, §6b, §7.

## Modules

| group | modules | purpose |
|---|---|---|
| OS boundary | `api`, `real`, `mock` | `WinApi` trait; Win32 implementation (Windows only); in-memory mock for any host |
| API | `rpc`, `client` | the methods, their access and parameters, JSON-RPC shapes; the front end's stream transport |
| CLI | `cli`, `cmd`, `ctx`, `out` | command line → request (direct or through the service), command logic, shared context, the `--json` envelope/exit codes |
| on-disk state | `bootent`, `cfgfile`, `esp`, `journal` | `Boot####`/`BootNext`; `paguro.ini` read/edit/write with its hash; ESP files; resumable install/uninstall steps |
| keys & TPM | `keys`, `tpmwin` | key material from a logged-in session; the TPM via TBS, through the loader's own client |
| WSL2/pre-flight | `hw`, `preflight` | `host-hardware.json` for the WSL2 installer; the check before "Restart into Linux" |
| driver IPC | `fltmsg` | `\PaguroPort` messages, checked against the minifilter's own header so they can't drift |

## Invariants

- Every OS call goes through `WinApi` — no direct Win32 call outside `real`.
- `#![deny(unsafe_code)]`; `unsafe` is confined to `real`.
- Command logic is tested with `mock::MockApi` on any host, including Linux
  CI, before it ever touches real Win32.
- `fltmsg`'s constants/offsets are checked by a test against
  `windows/minifilter/pg_msg.h` so the two cannot drift.

## Build & test

```sh
cargo test -p paguro-win              # command logic against the mock, any host
PAGURO_BLESS=1 cargo test -p paguro-win --test api_contract   # rewrite windows/api/fixtures
cargo build -p paguro-win --target x86_64-pc-windows-gnu   # cross-compile from Linux
```

Covered on Windows by `.github/workflows/windows.yml` (`rust`, `pester`
jobs, real `paguro.exe`) and on Linux by the same workflow's `linux` job
(cross-compile, Pester with a mocked process, `win_formats` fuzzing).
