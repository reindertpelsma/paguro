# paguro-service: paguro.exe

**`paguro.exe`** (INTERFACES.md §11.7a): one binary that is the command line, the
Windows service (`paguro.exe service`) and its own installer. No arguments
(a double-click, the Start menu) open the GUI, or offer to install paguro first.

The service (§11.7) is the one process that owns
every privileged action, serving the API of [`paguro-win`](../paguro-win)'s
`rpc` module as JSON-RPC 2.0 over `\\.\pipe\paguro`, one message per line.
`paguro.exe`, the PowerShell module and the GUI are its clients.

## Its place in paguro

It adds no logic of its own: every method is `paguro_win::rpc::call` on the
real platform. What it adds is the process and the door:

| piece | where | what |
|---|---|---|
| worker | `lib.rs` | one thread owns the platform and runs calls one at a time; progress and `log` notifications stream to the caller |
| connection | `lib.rs` (`serve`) | lines in, notifications and the response out, over any byte stream; 4 MiB per line |
| pipe and ACL | `win.rs` | SYSTEM/Administrators full, the interactive user read/write without creating instances, owner Administrators, remote clients rejected, first instance exclusive |
| caller | `win.rs` (`identify`) | from the client's token: Administrators present = administrator (also UAC-filtered), enabled = elevated; access per method (`rpc::Access`) |
| startup | `lib.rs` (`startup`) | deletes the one-shot variables of INTERFACES §5, once per Windows boot |
| SCM | `win.rs` | `paguro service` under the service control manager; log in `%ProgramData%\paguro\service.log` (never parameters) |

Installed and removed by `paguro service install|uninstall` (direct mode).

## Build & test

```sh
cargo test -p paguro-service          # worker, connection loop, thin-client parity, on Linux
cargo run -p paguro-service -- service console --mock --unix /tmp/CoreFxPipe_paguro   # the demo machine for the C# front ends
PAGURO_PAYLOAD_DIR=payload cargo xwin build -p paguro-service --release --target x86_64-pc-windows-msvc   # with the payloads
cargo build -p paguro-service --no-default-features   # the CLI-only build (no GUI embedded)
```

On Windows (`.github/workflows/windows.yml`), `tests/pipe.rs` checks the
pipe's ACL and owner, squatting, a UAC-filtered administrator and a
temporary standard user; the job then installs the real service, calls it
through `paguro.exe`, and removes it.

## Resources (`build.rs`, MSVC targets)

- the application manifest: `asInvoker`, and the **detached console
  allocation policy** (Windows 11 24H2 / Server 2025 on): a double-click gets
  no console window, a terminal still gets a proper console program. On
  older Windows `paguro.exe` releases a console it alone owns at once.
- with `PAGURO_PAYLOAD_DIR`: every file under it as `RT_RCDATA` (from 1001),
  listed by resource 1000; `paguro install` extracts them
  (`paguro_win::cmd::setup`). The `gui` feature (default) includes `app/`.
