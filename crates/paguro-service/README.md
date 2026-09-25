# paguro-service

The paguro Windows service (INTERFACES.md §11.7): the one process that owns
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
| SCM | `win.rs` | `paguro-service run` under the service control manager; log in `%ProgramData%\paguro\service.log` (never parameters) |

Installed and removed by `paguro service install|uninstall` (direct mode).

## Build & test

```sh
cargo test -p paguro-service          # worker, connection loop, thin-client parity, on Linux
cargo run -p paguro-service -- console --mock --unix /tmp/CoreFxPipe_paguro   # the demo machine for the C# front ends
```

On Windows (`.github/workflows/windows.yml`), `tests/pipe.rs` checks the
pipe's ACL and owner, squatting, a UAC-filtered administrator and a
temporary standard user; the job then installs the real service, calls it
through `paguro.exe`, and removes it.
