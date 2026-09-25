#!/usr/bin/env python3
"""Build the coexistence test's disks on the host (no root, no mounts):

    mkimages.py <outdir>

    vol512.img   1 GiB NTFS, 512-byte sectors, 4 KiB clusters (empty)
    vol4kn.img   1 GiB NTFS, 4096-byte sectors, 4 KiB clusters (empty)
    disk.vhd     fixed VHD: GPT, FAT32 ESP + ext4 root (512-byte LBAs)
    bare.img     bare ext4, raw
    disk4k.vhd   fixed VHD: GPT with 4096-byte LBAs, FAT ESP + ext4 root
    bare4k.img   bare ext4, raw (for the 4Kn volume)
    layout.env   partition offsets inside the disks, in 512-byte sectors
    frag.img     (root and ntfs-3g only) 1 GiB NTFS, 512-byte sectors, holding
                 disk.vhd and bare.img fragmented: written through ntfs-3g
                 into 1 MiB holes (every fourth 1 MiB file of a full volume
                 kept)
    guard.img    (root, ntfs-3g and setfattr only) 512 MiB NTFS for the guard
                 test: "paguro/Paguro Root Disk.img" (bare ext4) with the 8.3
                 alias PAGURO~1.IMG, a hard link and an alternate data
                 stream, beside ordinary files and directories

The VM puts the images into the other volumes itself (coexist.body). Needs
mkntfs, sgdisk, mkfs.vfat, mkfs.ext4.
"""
import os
import struct
import subprocess
import sys
import time
import uuid
import zlib

MIB = 1 << 20


def sh(*a):
    subprocess.run(a, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def sparse(path, size):
    with open(path, "wb") as f:
        f.truncate(size)


def ext4(path, mib, *opts):
    sparse(path, mib * MIB)
    sh("mkfs.ext4", "-q", "-F", "-b", "4096", "-E",
       "lazy_itable_init=0,lazy_journal_init=0", *opts, path)


def fat(path, mib, *opts):
    if os.path.exists(path):
        os.unlink(path)
    sh("mkfs.vfat", *opts, "-C", path, str(mib * 1024))


def vhd_footer(size):
    """A fixed-VHD footer for a payload of `size` bytes."""
    f = bytearray(512)
    cyl, heads, spt = 65535, 16, 255
    secs = size // 512
    if secs < cyl * heads * spt:
        spt, heads = 17, 4
        cyl = secs // (spt * heads)
    f[0:8] = b"conectix"
    struct.pack_into(">IIQI4sII", f, 8, 2, 0x10000, 0xFFFFFFFFFFFFFFFF,
                     int(time.time()) - 946684800, b"pgro", 0x10000, 0x5769326B)
    struct.pack_into(">QQHBBI", f, 40, size, size, min(cyl, 65535), heads, spt, 2)
    f[68:84] = uuid.uuid4().bytes
    struct.pack_into(">I", f, 64, ~sum(f) & 0xFFFFFFFF)
    return bytes(f)


def gpt4k(path, lbas, parts):
    """GPT with 4096-byte LBAs; parts = [(first, last, type_guid, file)]."""
    lbs = 4096
    arr = bytearray(128 * 128)
    with open(path, "r+b") as img:
        for i, (first, last, ty, content) in enumerate(parts):
            e = 128 * i
            arr[e:e + 16] = uuid.UUID(ty).bytes_le
            arr[e + 16:e + 32] = uuid.uuid4().bytes
            struct.pack_into("<QQ", arr, e + 32, first, last)
            with open(content, "rb") as c:
                img.seek(first * lbs)
                while True:
                    b = c.read(MIB)
                    if not b:
                        break
                    img.write(b)
        asz = len(arr) // lbs
        fu, lu = 2 + asz, lbas - 2 - asz
        dg = uuid.uuid4().bytes
        for my, alt, at in [(1, lbas - 1, 2), (lbas - 1, 1, lbas - 1 - asz)]:
            h = bytearray(92)
            h[0:8] = b"EFI PART"
            struct.pack_into("<IIIIQQQQ", h, 8, 0x10000, 92, 0, 0, my, alt, fu, lu)
            h[56:72] = dg
            struct.pack_into("<QIII", h, 72, at, 128, 128, zlib.crc32(bytes(arr)))
            struct.pack_into("<I", h, 16, zlib.crc32(bytes(h)))
            img.seek(my * lbs)
            img.write(h)
            img.seek(at * lbs)
            img.write(arr)
        # protective MBR
        mbr = bytearray(512)
        struct.pack_into("<BBBBBBBBII", mbr, 446, 0, 0, 2, 0, 0xEE, 0xFF, 0xFF, 0xFF,
                         1, min(lbas - 1, 0xFFFFFFFF))
        mbr[510:512] = b"\x55\xaa"
        img.seek(0)
        img.write(mbr)


def append(path, data):
    with open(path, "ab") as f:
        f.write(data)


def main():
    out = sys.argv[1]
    os.makedirs(out, exist_ok=True)
    p = lambda n: os.path.join(out, n)
    for name, s in [("vol512.img", 512), ("vol4kn.img", 4096)]:
        sparse(p(name), 1024 * MIB)
        sh("mkntfs", "-F", "-Q", "-q", "-s", str(s), "-c", "4096", p(name))
    env = []
    # disk.vhd: 256 MiB GPT (512-byte LBAs), ESP 64 MiB, root the rest.
    disk = p("disk.vhd")
    sparse(disk, 256 * MIB)
    esp_s, esp_n = 2048, 64 * 2048
    root_s = esp_s + esp_n
    root_n = 190 * 2048
    sh("sgdisk", "-n", "1:%d:%d" % (esp_s, esp_s + esp_n - 1), "-t", "1:ef00",
       "-n", "2:%d:%d" % (root_s, root_s + root_n - 1), "-t", "2:8304", disk)
    fat(p("esp.fat"), 64, "-F", "32")
    ext4(p("root.ext4"), root_n // 2048)
    with open(disk, "r+b") as d:
        for s, f in [(esp_s, p("esp.fat")), (root_s, p("root.ext4"))]:
            d.seek(s * 512)
            with open(f, "rb") as src:
                while True:
                    b = src.read(MIB)
                    if not b:
                        break
                    d.write(b)
    append(disk, vhd_footer(256 * MIB))
    env += ["D1_ESP_START=%d" % esp_s, "D1_ESP_LEN=%d" % esp_n,
            "D1_ROOT_START=%d" % root_s, "D1_ROOT_LEN=%d" % root_n]
    ext4(p("bare.img"), 160)
    # disk4k.vhd: 256 MiB GPT with 4096-byte LBAs (65536 LBAs).
    d4 = p("disk4k.vhd")
    sparse(d4, 256 * MIB)
    fat(p("esp4.fat"), 32, "-S", "4096")
    r4_first, r4_last = 256 + 8192, 65536 - 6 - 1   # after a 32 MiB ESP at LBA 256
    r4_mib = (r4_last - r4_first + 1) * 4096 // MIB
    ext4(p("root4.ext4"), r4_mib)
    r4_last = r4_first + r4_mib * 256 - 1
    gpt4k(d4, 65536, [(256, 256 + 8191, "C12A7328-F81F-11D2-BA4B-00A0C93EC93B", p("esp4.fat")),
                      (r4_first, r4_last, "4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", p("root4.ext4"))])
    append(d4, vhd_footer(256 * MIB))
    env += ["D4_ESP_START=%d" % (256 * 8), "D4_ESP_LEN=%d" % (8192 * 8),
            "D4_ROOT_START=%d" % (r4_first * 8), "D4_ROOT_LEN=%d" % (r4_mib * 2048)]
    ext4(p("bare4k.img"), 160)
    for f in ["esp.fat", "root.ext4", "esp4.fat", "root4.ext4"]:
        os.unlink(p(f))
    frag(p)
    guard(out, p)
    with open(p("layout.env"), "w") as f:
        f.write("\n".join(env) + "\n")


def fuse_ok():
    import shutil
    return os.geteuid() == 0 and shutil.which("ntfs-3g") and os.path.exists("/dev/fuse")


def frag(p):
    """ntfs-3g, not ntfscp: libntfs-3g's ntfscp cannot allocate a file into
    fragmented free space in one go (ENOSPC); written progressively, it
    can. Written with plain writes (no holes: a sparse file is refused)."""
    import shutil
    import tempfile
    if not fuse_ok():
        print("mkimages: no frag.img (needs root, ntfs-3g, /dev/fuse)")
        return
    g = p("frag.img")
    sparse(g, 1024 * MIB)
    sh("mkntfs", "-F", "-Q", "-q", "-s", "512", "-c", "4096", g)
    mnt = tempfile.mkdtemp()
    sh("ntfs-3g", g, mnt)
    try:
        os.mkdir(os.path.join(mnt, "paguro"))
        pads, i = [], 0
        while True:
            f = os.path.join(mnt, "pad%d" % i)
            try:
                with open(f, "wb") as o:
                    o.write(b"\0" * MIB)
            except OSError:
                os.unlink(f)
                break
            pads.append(f)
            i += 1
        for k, f in enumerate(pads):
            if k % 4 != 3:
                os.unlink(f)
        for name in ["disk.vhd", "bare.img"]:
            with open(p(name), "rb") as src, open(os.path.join(mnt, "paguro", name), "wb") as dst:
                while True:
                    b = src.read(MIB)
                    if not b:
                        break
                    dst.write(b)
        for f in pads:
            if os.path.exists(f):
                os.unlink(f)
    finally:
        sh("umount", mnt)
        os.rmdir(mnt)


def guard(out, p):
    """ntfs-3g, not ntfs3: ntfs3 creates NTFS 3.0-layout MFT records (which
    the core refuses) and cannot give a file an 8.3 name."""
    import shutil
    import tempfile
    if not fuse_ok() or not shutil.which("setfattr"):
        print("mkimages: no guard.img (needs root, ntfs-3g, setfattr, /dev/fuse)")
        return
    g = p("guard.img")
    sparse(g, 512 * MIB)
    sh("mkntfs", "-F", "-Q", "-q", "-s", "512", "-c", "4096", g)
    mnt = tempfile.mkdtemp()
    sh("ntfs-3g", g, mnt)
    try:
        d = os.path.join(mnt, "paguro")
        os.makedirs(os.path.join(d, "sub", "deeper"))
        img = os.path.join(d, "Paguro Root Disk.img")
        shutil.copyfile(p("bare.img"), img)
        sh("setfattr", "-n", "system.ntfs_dos_name", "-v", "PAGURO~1.IMG", img)
        os.link(img, os.path.join(d, "hardlink.img"))
        sh("setfattr", "-n", "user.stream", "-v", "an alternate data stream", img)
        for i in range(20):
            with open(os.path.join(d, "sub" if i % 2 else "sub/deeper", "f%02d" % i), "wb") as f:
                f.write(os.urandom(4096 * (i + 1)))
        with open(os.path.join(d, "notes.txt"), "w") as f:
            f.write("siblings of the image, for find/du/tar/rm -rf\n")
    finally:
        sh("umount", mnt)
        os.rmdir(mnt)


if __name__ == "__main__":
    main()
