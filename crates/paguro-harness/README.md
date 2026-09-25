# paguro-harness

The storage torture harness — DESIGN.md is explicit that this is built
**before anything else**. Stage 1 (implemented): a model check of the range
test against a naive oracle, and differential tests of the kernel module's C
core (range test, NTFS parser, claim checks, payload structure) against the
Rust specification in `paguro-core`. Stage 2 (planned): drive QEMU and a
Windows guest over a dm-error-backed image and inspect `$LogFile`,
`$BadClus` and the runlist after every scenario. Runs on a Linux host.

## Its place in paguro

Depends on [`paguro-core`](../paguro-core) (the Rust specification),
[`paguro-crypto`](../paguro-crypto) and [`paguro-boot`](../paguro-boot).
Its C-vs-Rust differential tests are what let `kernel/dm-paguro`'s
dependency-free core be reviewed and trusted as one small module — see
[`docs/DESIGN.md`](../../docs/DESIGN.md) §1b ("GPU sharing") and §11 ("Open
questions — verify before building") for why this harness comes first, and
§5.5 for the testability argument it makes concrete. Also builds
`paguro-bde-read`/`paguro-bde-write`, used by `loader.yml`'s BitLocker job to
cross-check against `libbde`/`dislocker`.

## Modules

| module | purpose |
|---|---|
| `ntfsdiff` | C-vs-Rust differential test of the NTFS parser: fixtures, exhaustive byte mutation, truncation, I/O faults, fuzz corpora |
| `payloaddiff` | the structural-assertion check alone (`payload-exhaustive`) |
| `cntfs`, `cref` | bindings/glue to the C core and the Rust reference being compared |
| `model` | the range-test model check against a naive oracle |
| `replay` | power-loss replay checks |
| `synth` | `#[path]`-included from `paguro-core/tests/synth` — the shared synthetic-disk builder |

## Invariants

- This is a **test/dev tool**, not shipped; it exists to make the C core's
  small size credible by comparing it against the Rust specification on
  every push.
- Differential tests must cover every fixture, exhaustive byte mutation,
  truncation and injected I/O fault — not just the happy path.

## Build & test

```sh
cargo run --release -p paguro-harness -- 1000000        # range/NTFS/claims/runlist model rounds
cargo run --release -p paguro-harness -- ntfs-exhaustive # fixtures + mutation + fuzz corpora, C vs Rust
cargo run --release -p paguro-harness -- payload-exhaustive
cargo run --release -p paguro-harness -- ntfs-seeds seeds/    # fuzz seeds for fuzz/ and the C fuzzer
```

Covered by `.github/workflows/ci.yml` (1M-round differential) and
`.github/workflows/kernel.yml`'s `differential` job (`ntfs-exhaustive` and
1M rounds against the C core).
