# paguro-vm

The Windows VM launcher: synthesises the disk view Windows boots from,
substitutes FVE metadata so BitLocker's ladder still resolves, and runs QEMU
with the host's own identity so the network and Windows Activation see one
machine, booted natively or in the VM.

## Its place in paguro

`paguro-vm` is the `paguro-vm` binary invoked by the higher-level `paguro`
CLI (and directly by `test/vm/*.sh`) once Linux has decided the machine
should boot into Windows as a guest. It depends on
[`paguro-core`](../paguro-core) (formats), [`paguro-crypto`](../paguro-crypto)
(primitives), [`paguro-boot`](../paguro-boot) (the BitLocker/TPM ladder,
shared with the loader) and [`paguro-initrd`](../paguro-initrd) (mount/dm
helpers). See [`docs/DESIGN.md`](../../docs/DESIGN.md) §4.3, §4.5 and §6 for
the disk/FVE/identity design this crate implements, and §5c for the VM's
network (this README's own focus).

## Modules

| module | purpose |
|---|---|
| `session` | the whole lifecycle: `prepare` (claim the volume, build the synthetic disk and `.BEK`), `launch` (the boot loop — one QEMU per guest boot, the tripwire, the LAN session), `teardown` |
| `qemu` | QEMU's command line as pure data (`VmConfig` → `argv`) — disk, identity, network, agent, GPU, all just text generation, tested without ever invoking QEMU |
| `identity` | reads the host's own SMBIOS/UUID/ACPI/MAC/disk-serial so the VM presents as the same machine (§4.5) |
| `disk`, `fve`, `fat`, `regf`, `esp` | the synthesised disk: view A/B, the FVE substitute, the synthetic ESP's FAT and registry hives |
| `loopdev`, `mem` | loop-device and cgroup/OOM plumbing the session needs |
| `gpu` | the display backend registry (`GpuBackend` trait, candidates by capability) |
| `rdp`, `qmp` | RDP passthrough helpers and a small QMP client (also a CLI diagnostic: `paguro-vm qmp`) |
| `net` | the **private link** `paguro0` (§5c "The private link"): the host-only virtio-net adapter in netns `paguro`, its Samba share for `L:`, and the CIFS mount for `/mnt/c` |
| `lan` | the **VM's LAN adapter** (§5c "The VM's network"): the tap, its subnet, the `inet paguro` nftables ruleset (masquerade, forward, the DMZ), Docker/firewalld/ufw coexistence, and the layered DNS setup — see below |
| `dhcp` | the single-lease DHCPv4 server `lan`'s tap uses in place of slirp's built-in one — packet encode/decode (fuzzed) plus the socket loop |
| `main` | the CLI: `prepare`/`launch`/`teardown`/`unlock`/`fve`/`qmp`/`identity` and the link/Samba/DHCP-adjacent plumbing subcommands, including the hidden `net-up`/`net-down` (below) |

`net` (the private link, `paguro0`) and `lan` (the LAN adapter, the VM's
route to the outside world) are deliberately separate modules and separate
network namespaces: the private link's Samba/SSH stay reachable only from
inside netns `paguro`, and the LAN tap stays in the host's own namespace
because it needs the host's routing table. They must never be confused for
each other or merged.

## The VM's network (`lan.rs`, `dhcp.rs`)

DESIGN.md §5c: the VM's LAN adapter is a tap with vhost-net, routed (not
bridged) on a small private subnet, NATed and — opt-in — DMZ'd by paguro's
own `inet paguro` nftables table, with a single-lease DHCP server standing in
for what slirp used to provide.

- **`--net user` (old slirp) vs `--net tap` (default).** `qemu::Lan` picks
  the netdev; `--nat-hostfwd` only means anything in `user` mode. Existing
  tests and `test/vm/nested-e2e.sh`/`split-e2e.sh` still use `--net user`
  (they need `hostfwd` into a guest with no LAN peer to dial in from).
- **The subnet defaults to `198.19.249.0/24`** (`lan::DEFAULT_SUBNET`) —
  inside RFC 2544's benchmarking range, which nothing on a real LAN or
  Docker's default bridges ever uses. Configurable with `--lan-subnet`.
- **The nftables ruleset is one file, loaded whole with `nft -f` and deleted
  whole at teardown** (`lan::nft_ruleset`/`nft_apply`/`nft_delete_table`):
  masquerade out of the WAN interface (autodetected from the default route,
  or `--lan-wan` to pin it); the `forward` chain accepts the VM's own
  outbound traffic and its replies (`ct state established,related`)
  unconditionally, but anything *new* forwarded towards the tap is dropped
  unless it is a DMZ'd connection (`ct status dnat`) — a routed LAN or VPN
  host cannot reach the VM merely by adding a route for its subnet through
  this machine, DMZ or not; and — with `--dmz` — a `dmz` chain. The DMZ is a
  rule ladder over three named sets
  (`pinned_windows`, `pinned_linux`, `linux_ports`) plus a literal
  never-forward set (`lan::NEVER_FORWARD`: 22, 445, 3389, 5985, 5986) that
  only a `--pin-port PORT:windows` can override; `linux_ports` is reseeded
  from `ss -Hltn`/`-Hlun` every few seconds by a background thread
  (`LanSession`'s poll loop) so a service Linux starts listening on stops
  being forwarded without a restart.
- **Coexistence is not optional.** Docker's `FORWARD` policy is `DROP`
  (jumping through `DOCKER-USER` first); a plain `iptables`/`nft` accept
  added elsewhere races that policy and usually loses — the fix is an
  accept rule *inside* `DOCKER-USER` itself, which Docker's own chain
  consults before its policy applies. firewalld gets the same treatment via
  a runtime (never `--permanent`) direct rule. **ufw needs it too, and for
  more than the DMZ**: its default-deny INPUT policy blocks the tap's own
  DHCP and DNS traffic (both are ordinary INPUT-chain packets addressed to
  the host itself, not forwarded ones), so `lan::coexistence_setup` also
  runs `ufw allow in on <tap>` and `ufw route allow in|out on <tap>` when
  `ufw status` reports active. (`ufw`'s own CLI is asymmetric: adding a
  routed rule is `ufw route allow ...`, removing it is `ufw route delete
  allow ...` — `route` moves from the middle to the front.) All three are
  torn down with the rest of the session in `LanSession`'s `Drop`.
- **DHCP** (`dhcp.rs`): one fixed lease, keyed to the VM's MAC (the host's
  own, carried through to the LAN adapter same as native boot, §4.5).
  `Message::encode`/`decode` are pure and total — `decode` never panics on
  any input, fuzzed with `proptest` (a raw byte soup, and a well-formed
  header with an arbitrary options tail) — and `dhcp::server` is a thin
  `SO_BINDTODEVICE`-scoped socket loop around them, run as an RAII guard
  (`dhcp::server::Guard`) that is restarted every guest boot (a reboot gets
  a fresh tap, hence a fresh bound socket).
- **DNS, layered simplest-first** (`lan::setup_dns`): `systemd-resolved`
  active → a drop-in adds the tap address to `DNSStubListenerExtra` (removed
  and reloaded out at teardown); else `dnsmasq` if present → started bound
  to the tap, forwarding to the host's own upstreams; else → the DHCP lease
  hands out the host's `/etc/resolv.conf` nameservers directly (loopback
  ones, i.e. some other stub, are skipped — they are not reachable from the
  tap).
- **`paguro-vm net-up`/`net-down`** are hidden subcommands whose entire
  purpose is testing: they run the exact same `lan.rs`/`dhcp.rs` production
  code (`LanSession::setup`, `dhcp::server::Guard`) without a Windows
  session at all, so `test/vm/net-smoke.sh` can exercise the real nftables
  ruleset, the real DHCP server and the real coexistence rules against a
  disposable guest. `net-up` blocks in the foreground until SIGINT/SIGTERM,
  then tears everything down through the same `Drop` `launch` relies on;
  `net-down` is a manual, idempotent safety net for whatever `net-up` didn't
  get to clean up itself.

### Testing it

`crates/paguro-vm`'s own `cargo test` covers every text generator (the
nftables ruleset, the DMZ port-set computation including the never-forward
override, the DHCP packet codec) and the CLI's option parsing. The one thing
unit tests cannot cover — real `nft`/`iptables`/`ufw`/a real kernel's
forwarding path — is `test/vm/net-smoke.sh`: a throwaway busybox guest (the
host's own kernel, an initramfs built the same way
`kernel/dm-paguro/test/vm-lib.sh` builds one) booted with a tap exactly as
`--net tap` configures it, `paguro-vm net-up --dmz` standing in for
`launch`'s LAN setup, and a private veth pair standing in for the host's
real LAN/WAN interface (so a DMZ test never touches the one NIC a shared
host actually depends on). It checks: DHCP hands out the lease, DNS resolves
a real name, TCP egress works, an unlisted port reaches the guest under
`--dmz`, 22/445/80 do not, and every table/tap/sysctl/coexistence rule the
run created is gone afterward — even if an assertion above it failed.

```bash
cargo test -p paguro-vm                 # every generator, pure
bash test/vm/net-smoke.sh                # the real thing (root, KVM)
```
