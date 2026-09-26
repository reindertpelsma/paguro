# paguro-linux

The Linux-side `paguro` CLI: `paguro shell`/`paguro distro enter` (DESIGN.md
§5c "Shells, the same command both ways"), `paguro status`, `paguro link
setup`/`teardown` (the private link's Linux-side SSH), and `paguro image
attach`/`detach`/`grow` (INTERFACES.md §10, §11.3). Runs on the booted Linux
system, not in the initrd.

```text
paguro shell windows                    SSH into the Windows VM (PowerShell)
paguro shell <distro>                   a local shell (the booted entry) or
paguro distro enter <distro>            <distro>'s container (systemd-nspawn)
paguro status [--json]
paguro link setup|teardown ...
paguro image attach <file-on-C:> [--name NAME] [--volume ID] [--format raw|vhd]
paguro image detach <name> --claim ID [--agent-socket PATH] [--windows-path PATH]
paguro image grow <name> --claim ID --by SIZE [--windows-path PATH] [--agent-socket PATH]
```

## Modules

| module | purpose |
|---|---|
| `shell` | `paguro shell`/`distro enter`'s target resolution and container attach/mount/boot |
| `status` | `paguro status`: link/samba/ssh/VM up-or-down |
| `link` | the private link's Linux-side `sshd` socket unit and `authorized_keys` |
| `image` | `paguro image attach/detach/grow`: `/dev/paguro` + device-mapper orchestration, and the guest-agent lifecycle frames |

## `image`: attach, detach, grow (INTERFACES.md §10.2–§10.3, §11.3)

Depends on [`paguro-initrd`](../paguro-initrd) as a library for `/dev/paguro`
(`pg::Ctl`) and device-mapper (`dm::Dm`) — the same calls the initrd's own
boot-time claim path uses, and the kernel module's own harness exercises
(`kernel/dm-paguro/test/vm-test.sh`) — and on
[`paguro-vm`](../paguro-vm)'s `session::agent_frame`/`agent_frames` for the
guest-agent virtio-serial wire format (`org.paguro.agent.0`).

- **`attach(file, volume_id, name, format)`**: identity via ntfs3's own
  `name_to_handle_at` (`paguro_initrd::sys::file_identity`, exactly `pgctl
  ident`'s discovery), `PG_CLAIM`, then `PG_CROSSCHECK` against the same
  file's FIEMAP. A disagreeing cross-check releases the claim and refuses —
  no view A, ever (INTERFACES.md §10.1a: the cross-check is mandatory). On
  success, loads `0 <len> paguro-image <claim_id>` as `/dev/mapper/paguro-<name>`.
- **`detach(name, claim_id)`**: refuses up front (touching nothing) while the
  view A device is open — mounted or otherwise held, checked via
  `DM_DEV_STATUS`'s open count and `/proc/self/mountinfo` for a human reason.
  Otherwise removes the dm device, `PG_RELEASE`s the claim, and **only then**
  sends `image-released` so Windows can unprotect the file. If there is no
  live guest-agent channel right now (Windows is not currently running as a
  VM), the CLI falls back to a `NullChannel`: the release still happens, the
  guest is just not reachable to be told.
- **`grow(target, by_sectors)`**: sends `image-grow-request`, waits for
  `image-grown`, then `PG_GROW` — accepted only if the new extents are an
  append (`error == 0`). `PG_GROW` clears the claim's cross-checked state
  (§10.1a), so a fresh `PG_CROSSCHECK` against `target.local_path` (the same
  already-mounted, read-only ntfs3 view `attach` used) is required before
  view A's table can be reloaded at the new length — exactly what
  `kernel/dm-paguro/test/vm-test.body`'s own growth test proves at the
  module level. Either way, acks back with `image-grow-ack`. Growth has no
  offline fallback: it needs a live Windows guest to actually extend the
  file.

`ImageBackend` and `AgentChannel` are traits so the ordering above is
unit-tested without a live kernel module or guest: `image::tests` uses a
recording `FakeBackend` (asserts the exact call order, and that failing a
step never lets a later one run — e.g. `detach` never sends `image-released`
if `PG_RELEASE` itself fails) and a scriptable `FakeChannel`. `KernelBackend`
and `UnixAgentChannel` are the real things.

### `shell::attach_view_a` / `distro enter`

`paguro distro enter <name>` needs `<name>`'s own file and the `/dev/paguro`
volume it lives on before it can call `image::attach` — and the running
Linux system does not currently keep a copy of `paguro.ini` after the
handoff (INTERFACES.md §8.3 lists what survives it; the `.ini` is not among
them), so that lookup is behind a `DistroLocator` trait.
`shell::UnresolvedLocator` (what `main.rs` wires today) names the gap
explicitly rather than guessing; a real locator — re-reading `paguro.ini`
off wherever the volume is currently mounted, or a cached copy this crate
does not maintain yet — is a follow-up. Everything downstream of the lookup
(`attach_view_a`'s claim/cross-check/view-A path, and `enter_container`'s
mount + `systemd-nspawn` boot, itself behind a `ContainerLauncher` trait
since `systemd-nspawn` is not available in every build/test environment) is
implemented and unit-tested against a fixed locator and fake backend/launcher.

## Build & test

```sh
cargo test -p paguro-linux
cargo clippy -p paguro-linux --all-targets -- -D warnings
cargo fmt --check -p paguro-linux
```

The kernel-module semantics `image` relies on (`PG_CLAIM`/`PG_CROSSCHECK`
mandatory, `PG_RELEASE` refusing while a view is live, `PG_GROW` accepting
only an append) are proved against the real module, in a throwaway VM, by
`test/vm/lifecycle.sh` (`kernel/dm-paguro/test/vm-test.sh`'s pattern) — this
crate's own tests cover the orchestration and ordering around those ioctls,
not the module's C.
