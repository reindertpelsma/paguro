# kernel/paguro-mod

The enforcement module (DESIGN.md §4.3): **a protected view over a block
device**. Everything above it — `dm-crypt` over the BitLocker volume, the
`dm-linear` GPT sandwich for the VM, which partitions the guest sees — is stock
device-mapper driven by userspace (`crates/paguro-initrd`).

## Why Rust, and the gap to close first

The request-path logic is `crates/paguro-core/src/range.rs`, included here by
`#[path]` so the exact code the kernel runs is the code CI tests on every push.

**Open decision:** the module must forward bios to the underlying device for
ranges it allows. Upstream Rust-for-Linux has blk-mq abstractions (see `rnull`)
but no bio-remapping or device-mapper target abstractions yet. Options, in order
of preference:

1. **A device-mapper target** with a thin C `dm_target` shim whose `map`
   callback asks the Rust range check for a verdict — the verdict logic stays
   Rust, the bio plumbing is ~100 lines of C.
2. Write the missing Rust bio abstractions (and upstream them).
3. The whole module in C, with `range.rs` as the executable specification it is
   tested against.

Decide before writing the module; §11's storage harness does not depend on it —
it can drive a `dm-error`/`dm-linear` stack that implements the same verdicts.

## Build

```
make KDIR=/path/to/kernel/build   # kernel with CONFIG_RUST=y, LLVM=1
```
