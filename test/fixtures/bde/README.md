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

## Windows-made: `windows/`

| Fixture | Source | Licence |
|---|---|---|
| `bitlk-images.tar.xz` (vendored unchanged; 21 volumes + 2 `.BEK`) | cryptsetup, [`tests/bitlk-images.tar.xz`](https://gitlab.com/cryptsetup/cryptsetup/-/blob/4eb729da3f46642d6fe1fabbbedb127078eccb95/tests/bitlk-images.tar.xz) at `4eb729da`, sha256 `68bf5669…37bd30` | GPL-2.0-or-later (cryptsetup's; no separate notice on the images) |
| `dfvfs-bdetogo.sparse` | dfvfs, [`test_data/bdetogo.raw`](https://github.com/log2timeline/dfvfs/blob/64fde7c153ae63983d18c5f446bdc0ce3ef796ba/test_data/bdetogo.raw) at `64fde7c1` (64 MiB, not vendored: ciphertext does not compress), sha256 `ed7982a1…71b` | Apache-2.0 |

The cryptsetup volumes were made by Windows 10/11 (2019–2025): XTS-AES-128
and -256, AES-CBC with and without the diffuser, 512 and 4096-byte sectors,
BitLocker To Go (XTS and CBC), password, recovery-password (one and two),
startup-key, smart-card and clear-key protectors, a used-space-only volume, a
"partially encrypted" one, and one whose first two metadata copies carry a
bad CRC. Their data areas were trimmed by cryptsetup (only the header,
metadata and relocated sectors survive), so the decrypted volumes are not
mountable, but every reader must still return the same bytes.
Passwords are in `images.conf` inside the tarball (`anaconda`, `anaconda£`,
recovery passwords per volume) and copied into `windows/manifest.txt`.
`bdetogo.raw` is Windows 7 BitLocker To Go, AES-CBC-128 with the diffuser,
password `bde-TEST`.

`windows/*.sparse` and `windows/manifest.txt` are derived from those by
`diff.sh --update`: the sectors the metadata level needs (first sector, the
three metadata blocks with validation, the relocated 8 KiB) and what
bdeinfo and the oracles said. `cargo test -p paguro-boot --test bde` runs on
them; `diff.sh` checks whole volumes.

## Oracle results (`diff.sh`)

- **Every XTS volume, every key it has** (password, recovery password — both
  of a two-recovery volume —, startup key, clear key; 512 and 4096-byte
  sectors; XTS-128/256; To Go): our decryption of the whole volume equals
  dislocker's, libbde's and cryptsetup's recorded SHA-256 byte for byte. (libbde
  tries only the first recovery-password protector, so the second one of
  `two-recovery` is dislocker and cryptsetup only.)
- **Metadata**: volume identifier, encryption method, description, and every
  protector's GUID and type equal bdeinfo's on every volume bdeinfo opens.
- **`bitlocker_stretch` matches**: the password and recovery-password
  protectors of every Windows volume (Windows 7 through 11, including the
  non-ASCII password `anaconda£`) unwrap with it; the CCM tag is the check.
- **Refused, as intended**: AES-CBC with and without the diffuser
  (`UnsupportedCipher`; both oracles read these), used-space-only
  (`UsedSpaceOnly`; libbde, dislocker and cryptsetup all refuse it too), and
  `crc` (`Checksum(0)`: copies 0 and 1 fail their CRC-32; libbde and
  dislocker silently use copy 0 anyway, cryptsetup falls back to copy 2 — we
  treat the three copies as a cross-check, DESIGN.md §6).
- **Windows 7** (`dfvfs-bdetogo`): its metadata fails its own CRC-32 *and*
  its VMK-wrapped SHA-256 (no byte range matches either), in all three
  copies; libbde and dislocker check neither. It is AES-CBC with the
  diffuser, so the refusal names the cipher. With the CRC recomputed, its
  password protector opens the VMK with our stretch.
- **Generated volumes** (512/4096, XTS-128/256, every protector kind,
  partially encrypted, CRC-only validation): ours = dislocker = libbde =
  the expected view.

## What the readers return for the non-data regions

All three independent readers (libbde, dislocker, and cryptsetup's dm table,
whose recorded SHA-256 agrees with both) return:

| Region | Decrypted view |
|---|---|
| sectors `[0, reloc_len)` | the relocated copy at `boot_sector_reloc_offset`, decrypted with tweak = the copy's **physical** sector index |
| the relocated copy's home | zeros |
| each 64 KiB metadata region | zeros |
| sectors past `encrypted_size` | the disk, unchanged (plaintext) |
| everything else | XTS, tweak = sector index from the volume start |

Whether Windows itself returns zeros there is not established by any of
them; NTFS sees those clusters as allocated to hidden files
(`System Volume Information\FVE2.*`), so no file reads them. INTERFACES.md
§12.2 asks for a test on Windows' own view; that needs a Windows run.

Two things the oracles do not settle:

- **Used-space-only volumes** store the relocated boot sectors in plaintext
  (the only sample, `bitlk-aes-xts-128-eow`); no reader models it, and
  `FVE_LAYOUT` cannot express it, so paguro refuses them for now.
- Windows 10+ adds a structure after the offset/size in the volume-header
  entry naming a further 64 KiB region at `reloc_offset + 8 KiB`; none of
  the readers hides it, and neither does paguro.

## Where the fixtures are used

| Test | What |
|---|---|
| `cargo test -p paguro-crypto --test bitlocker` | IEEE 1619 XTS, Wycheproof AES-256-CCM |
| `cargo test -p paguro-core --test bde` | every parser error, the map against a model, never-panic properties |
| `cargo test -p paguro-boot --test bde` | `windows/`: metadata = bdeinfo, every key, boot sectors = the oracles, refusals, tampering, the stage machine |
| `cargo test -p paguro-boot --test bde_stage4` | make.sh volumes through the stage machine and a real stage 4 (needs `paguro-bde-write` built) |
| `test/fixtures/bde/diff.sh` | whole volumes: ours = dislocker = libbde (CI `bde` job) |
| `test/qemu/run.sh 's4-bde-*'` | OVMF: password, recovery password, clear key, disagreeing copies; the probe boots from the VHD inside the encrypted NTFS |
| `fuzz/`: `bde_metadata`, `bde_unlock` | seeded from `windows/` |
