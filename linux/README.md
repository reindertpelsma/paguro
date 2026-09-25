# linux/ — the initramfs side of the `paguro` package (INTERFACES.md §11.6)

| Path | Installs to | What |
|---|---|---|
| `initramfs-tools/hooks/paguro` | `/usr/share/initramfs-tools/hooks/` | adds `paguro-initrd`, `dm-paguro`, `paguro-handoff`, `dm-crypt`, `dm-zero`, `ntfs3`, `vfat`, `efivarfs`; **fails the build** when `dm-paguro` or `paguro-handoff` is not built for the kernel |
| `initramfs-tools/scripts/local-top/paguro` | `/usr/share/initramfs-tools/scripts/local-top/` | on a paguro boot: `paguro-handoff` (address from `paguro-initrd systab`), `paguro-initrd setup`, unload the reader, `ROOT=`/`ROOTFSTYPE=`/`readonly=` into `/conf/param.conf` |
| `dracut/90paguro/` | `/usr/lib/dracut/modules.d/` | the same for dracut: `root=paguro` (or none) becomes `block:/dev/paguro-root` |

Not a paguro boot (no handoff table): both do nothing. `paguro-initrd`
(`crates/paguro-initrd`, a static binary) does the work; its `setup`
always links the root at `/dev/paguro-root`.

**Tested:** the same sequence, in the self-contained test initramfs
(`test/qemu/linux/init`), end to end in QEMU (`test/qemu/linux-e2e.sh`).
The initramfs-tools and dracut wrappers themselves are not yet exercised
in a VM (that needs a full distribution root in the image); they are
`sh -n`/shellcheck clean.
