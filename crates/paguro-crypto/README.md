# paguro-crypto

The key-derivation chain of [`docs/DESIGN.md`](../../docs/DESIGN.md) §6 ("Every
standing rung requires the passphrase"), implemented exactly as specified
there, plus BitLocker's symmetric primitives. `no_std`, symmetric only. Runs
everywhere paguro-core runs: `paguro-efi` (UEFI), the Linux initrd,
`paguro-win`.

## Its place in paguro

Depended on directly by [`paguro-boot`](../paguro-boot),
[`paguro-efi`](../paguro-efi), `paguro-initrd`, `paguro-win` and
`paguro-harness` for key derivation and BitLocker unwrap/decrypt. See
DESIGN.md §6 for the ladder this crate implements and
[`docs/INTERFACES.md`](../../docs/INTERFACES.md) §7 ("Key derivation") and §6
("Seal files") for the wire contracts around it. The loader's one asymmetric
operation — the ECDH that salts TPM sessions — lives in `paguro-boot`'s TPM
client, not here; this crate verifies no signatures.

## Modules

| module | purpose |
|---|---|
| `bitlocker` | AES-CCM key wrap (VMK, FVEK, metadata validation) and XTS-AES over one data unit (IEEE 1619-2007, no ciphertext stealing) |
| `tpm` | TPM 2.0 session cryptography: `KDFa`, `KDFe`, and CFB parameter encryption (TPM 2.0 Library Part 1 §11.4.10, §21.3) |
| (crate root) | the rung-derivation chain: `HMAC(key, message)` with per-rung `env` labels, `pass_hash` |

## Invariants

- `no_std`, symmetric primitives only.
- **Deliberately no authentication tag on the wrapped VMK and no convenience
  check anywhere in this crate**: a wrong passphrase yields a
  plausible-looking VMK, and the first real check is the FVEK unwrap against
  metadata on the raw volume. An early "incorrect password" would be an
  offline oracle by another name.
- Every rung's `env` label is unique so no two rungs can collide;
  `pass_hash` never appears raw in two places.
- Key material is zeroized (`zeroize`) where it is held past its use.

## Build & test

```sh
cargo test -p paguro-crypto
cargo clippy -p paguro-crypto --all-targets -- -D warnings
```

Covered by `.github/workflows/ci.yml` (`cargo test`) and `loader.yml`'s
BitLocker job (`bde`), which checks the FVEK/VMK path against `libbde` and
`dislocker` as independent oracles (INTERFACES.md §12.2).
