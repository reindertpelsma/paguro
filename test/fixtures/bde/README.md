# BitLocker fixtures

Linux cannot create BitLocker volumes. The fixtures here come from two
places, and both are checked against two independent readers, **libbde**
(`libbde-utils`: `bdeinfo`, `bdemount`) and **dislocker**
(`dislocker-file`, `dislocker-metadata`).

## Generated: `make.sh`

```sh
test/fixtures/bde/make.sh <plain-ntfs.img> <out.img> [options]
```

turns a plain NTFS image (from `mkntfs`) into a BitLocker volume laid out as
Windows 7+ lays one out, using `paguro-bde-write`
(`crates/paguro-harness/src/bin/paguro-bde-write.rs`):

- the first 8 KiB (16 × 512 or 2 × 4096 sectors) relocated, encrypted, and an
  FVE volume header (`-FVE-FS-`, BitLocker identifier, three metadata
  offsets) in sector 0;
- three identical 64 KiB FVE metadata regions: block header, metadata header,
  entries (description, VMK per protector, FVEK, volume-header block), and
  the validation block (CRC-32 and the VMK-wrapped SHA-256 of the block, or
  CRC-only with `--validation-v1`);
- XTS-AES-128 or -256 over whole sectors, tweak = sector index from the
  volume start; plaintext from `--encrypted-size` on (partially encrypted);
- protectors: `--password`, `--recovery auto|DIGITS`, `--clear-key`,
  `--startup-key FILE.BEK`; `--seed N` makes keys, salts and nonces
  deterministic.

The four non-data regions are reserved *inside* the NTFS as ordinary files
(`FVE2.{…}.1-3` and `FVE2.{…}`, with `ntfscp`), the way Windows keeps them in
`System Volume Information`, so the filesystem stays consistent. Outputs:
`<out.img>`, `<out.img>.expect` (the decrypted view every reader must return:
the input with the reserved regions zeroed) and `<out.img>.keys` (VMK, FVEK,
protector secrets, layout).

Unless `--no-verify`, the volume is decrypted by **both** dislocker and
libbde and must equal `<out.img>.expect` byte for byte (dislocker returns
only `encrypted_size`, rounded up to 8 KiB, of a partially encrypted volume;
libbde covers the plaintext tail), and the result must be a valid NTFS. That
is what makes the writer trustworthy: the reader under test
(`paguro_core::bde`, `paguro_boot::bde`) shares nothing with it but the
vector-tested primitives in `paguro_crypto::bitlocker`.

Needs `ntfs-3g`, `libbde-utils`, `dislocker`, FUSE and cargo.
