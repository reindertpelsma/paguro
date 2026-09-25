#!/usr/bin/env python3
"""Regenerate the payload fixtures for the structural assertion
(pg_payload_check / ntfs::check_payload; INTERFACES §3.2 "the structural
assertion follows the content").

    test/fixtures/payload/generate.py     # needs sgdisk, mkfs.vfat, mkfs.ext4,
                                          # genisoimage, gzip; no root

Builds real images with the real tools, then writes:

    *.img.gz      the images (gzip -n)
    manifest.txt  what the check must return for each image and each named
                  corruption of one

manifest.txt lines (the Rust harness and the C unit test both read them):

    payload <name> <image> <sectors|-> <expect> [lbs=4096] [<offset>=<hex>...]

<sectors> overrides the image length handed to the check ("-": the file's
own), <expect> is `ok` or an NtfsError name (`PayloadGptCrc`, ...), `lbs=`
the logical block size the check is told (default 512). Patches
are absolute offsets into the decompressed image. Corruptions that must keep
a CRC valid carry the recomputed CRC bytes among their patches; this script
computes them with its own GPT writer, independent of both checkers.
"""
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
S = 512
UUID = "8d7a2c1e-5b3f-4e0a-9c6d-1f2e3a4b5c6d"
ESP = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B"


def sh(*args, **kw):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, **kw)


def env():
    e = dict(os.environ)
    e["E2FSPROGS_FAKE_TIME"] = "1700000000"
    e["SOURCE_DATE_EPOCH"] = "1700000000"
    return e


def populate(d):
    """A small tree for mkfs -d / genisoimage: a few files of pattern."""
    os.makedirs(os.path.join(d, "etc"), exist_ok=True)
    for i in range(12):
        with open(os.path.join(d, "etc", "f%02d" % i), "wb") as f:
            f.write((b"paguro payload file %02d " % i) * (200 * (i + 1)))


def ext4(path, mib, *opts, work):
    """mkfs.ext4 on a new file of `mib` MiB, populated from a small tree."""
    src = os.path.join(work, "tree")
    if not os.path.isdir(src):
        populate(src)
    with open(path, "wb") as f:
        f.truncate(mib << 20)
    sh("mkfs.ext4", "-q", "-F", "-U", UUID, "-E", "hash_seed=" + UUID,
       "-d", src, *opts, path, env=env())


def gpt_disk(path, mib, parts, work):
    """A GPT disk of `mib` MiB; parts = [(first, last, typecode, content)]
    in sectors, content a file to copy in (or None)."""
    with open(path, "wb") as f:
        f.truncate(mib << 20)
    args = ["sgdisk", "-a", "1", "-U", "5a6b7c8d-0000-4000-8000-00000000d15c"]
    for i, (first, last, code, _) in enumerate(parts, 1):
        args += ["-n", "%d:%d:%d" % (i, first, last), "-t", "%d:%s" % (i, code),
                 "-u", "%d:5a6b7c8d-0000-4000-8000-%012d" % (i, i)]
    sh(*args, path)
    with open(path, "r+b") as f:
        for first, _, _, content in parts:
            if content:
                f.seek(first * S)
                f.write(open(content, "rb").read())


def fat(path, sectors):
    if os.path.exists(path):
        os.unlink(path)
    sh("mkfs.vfat", "-i", "12345678", "--invariant", "-C", path, str(sectors // 2))


# ---- a GPT writer of our own, for corruptions that keep CRCs valid ---------

class Gpt:
    def __init__(self, img):
        self.img = img
        self.sectors = len(img) // S

    def hdr(self, lba):
        return bytearray(self.img[lba * S:lba * S + S])

    def put_hdr(self, lba, h):
        size = struct.unpack_from("<I", h, 12)[0]
        struct.pack_into("<I", h, 16, 0)
        struct.pack_into("<I", h, 16, zlib.crc32(bytes(h[:size])))
        self.img[lba * S:lba * S + S] = h

    def fix_arrays(self):
        """Recompute the entry-array CRC in both headers (from the primary
        array, copied to the backup array)."""
        p = self.hdr(1)
        lba, count, esize = struct.unpack_from("<QII", p, 72)
        n = count * esize
        arr = self.img[lba * S:lba * S + n]
        alt = struct.unpack_from("<Q", p, 32)[0]
        b = self.hdr(alt)
        blba = struct.unpack_from("<Q", b, 72)[0]
        self.img[blba * S:blba * S + n] = arr
        for at in (1, alt):
            h = self.hdr(at)
            struct.pack_into("<I", h, 88, zlib.crc32(bytes(arr)))
            self.put_hdr(at, h)

    def entry(self, i):
        p = self.hdr(1)
        lba = struct.unpack_from("<Q", p, 72)[0]
        return lba * S + 128 * i


def write_gpt(path, lbs, lbas, parts):
    """A GPT with `lbs`-byte LBAs written by hand (sgdisk only does 512 on a
    file): parts = [(first, last, type_guid_bytes, content_file)]."""
    img = bytearray(lbs * lbas)
    arr = bytearray(128 * 128)
    for i, (first, last, ty, content) in enumerate(parts):
        e = 128 * i
        arr[e:e + 16] = ty
        arr[e + 16:e + 32] = bytes([0x40 + i]) * 16
        struct.pack_into("<QQ", arr, e + 32, first, last)
        if content:
            data = open(content, "rb").read()
            img[first * lbs:first * lbs + len(data)] = data
    asz = len(arr) // lbs
    fu, lu = 2 + asz, lbas - 2 - asz
    for my, alt, at in [(1, lbas - 1, 2), (lbas - 1, 1, lbas - 1 - asz)]:
        h = bytearray(92)
        h[0:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", h, 8, 0x10000, 92, 0, 0, my, alt, fu, lu)
        h[56:72] = bytes(range(16))
        struct.pack_into("<QIII", h, 72, at, 128, 128, zlib.crc32(bytes(arr)))
        struct.pack_into("<I", h, 16, zlib.crc32(bytes(h)))
        img[my * lbs:my * lbs + 92] = h
        img[at * lbs:at * lbs + len(arr)] = arr
    with open(path, "wb") as f:
        f.write(img)


def diff(a, b):
    out = []
    for o in range(0, len(a), 4096):
        if a[o:o + 4096] != b[o:o + 4096]:
            out += ["%d=%02x" % (i, b[i]) for i in range(o, min(o + 4096, len(a)))
                    if a[i] != b[i]]
    return out


def main():
    work = tempfile.mkdtemp()
    lines = []
    images = {}

    def image(name, path):
        images[name] = bytearray(open(path, "rb").read())
        dst = os.path.join(HERE, name + ".gz")
        with open(path, "rb") as f, open(dst + ".tmp", "wb") as o:
            subprocess.run(["gzip", "-9", "-n"], stdin=f, stdout=o, check=True)
        os.replace(dst + ".tmp", dst)

    def case(name, img, expect, mutate=None, sectors="-", lbs=512):
        toks = [] if lbs == 512 else ["lbs=%d" % lbs]
        if mutate:
            m = bytearray(images[img])
            mutate(m)
            toks += diff(images[img], m)
            assert toks, name
        lines.append(" ".join(["payload", name, img, str(sectors), expect] + toks))

    def put(at, fmt, *v):
        return lambda m: struct.pack_into(fmt, m, at, *v)

    # -- GPT: ESP (FAT16) + ext4 root (1 KiB blocks, 2 MiB groups) -------
    esp = os.path.join(work, "esp.bin")
    fat(esp, 6144)
    root = os.path.join(work, "root.ext4")
    ext4(root, 12, "-b", "1024", "-g", "2048", "-N", "256", work=work)
    p = os.path.join(work, "gpt.img")
    gpt_disk(p, 21, [(2048, 8191, "ef00", esp),
                     (8192, 8192 + 12 * 2048 - 1, "8304", root)], work)
    image("gpt.img", p)
    # the same disk grown by 1 MiB, backup header not moved yet
    with open(p, "ab") as f:
        f.write(b"\0" * (1 << 20))
    image("gpt_grown.img", p)
    # the same shape with 4096-byte LBAs (a 4Kn view A)
    esp4 = os.path.join(work, "esp4.bin")
    if os.path.exists(esp4):
        os.unlink(esp4)
    sh("mkfs.vfat", "-i", "12345678", "--invariant", "-S", "4096", "-C", esp4, "4096")
    root4 = os.path.join(work, "root4.ext4")
    ext4(root4, 10, "-b", "4096", "-g", "1024", "-N", "256", work=work)
    p = os.path.join(work, "gpt4k.img")
    linux = bytes.fromhex("af3dc60f838472478e793d69d8477de4")
    esp_t = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    write_gpt(p, 4096, 4096, [(256, 1279, esp_t, esp4), (1280, 1280 + 2560 - 1, linux, root4)])
    image("gpt4k.img", p)
    # a GPT whose only partition holds nothing we know (swap-typed, zeros)
    p = os.path.join(work, "gpt_unknown.img")
    gpt_disk(p, 2, [(64, 3000, "8200", None)], work)
    image("gpt_unknown.img", p)
    # -- bare ext4 ---------------------------------------------------------
    for name, mib, opts in [
        ("ext4_1k.img", 8, ["-b", "1024", "-g", "1024"]),
        ("ext4_4k.img", 16, ["-b", "4096", "-g", "1024", "-O", "^64bit"]),
        ("ext4_64bit.img", 16, ["-b", "4096", "-g", "1024", "-O", "64bit"]),
        ("ext4_sparse2.img", 16, ["-b", "4096", "-g", "1024", "-O", "sparse_super2"]),
    ]:
        p = os.path.join(work, name)
        ext4(p, mib, *opts, work=work)
        image(name, p)
    # single block group: no backup superblock, the root directory instead
    for name, mib, opts in [
        ("ext4_small_1k.img", 4, ["-b", "1024"]),
        ("ext4_small_4k.img", 16, ["-b", "4096", "-O", "^64bit"]),
        ("ext4_small_64bit.img", 16, ["-b", "4096", "-O", "64bit", "-I", "512"]),
    ]:
        p = os.path.join(work, name)
        ext4(p, mib, *opts, work=work)
        image(name, p)
    # -- ISO 9660 ----------------------------------------------------------
    p = os.path.join(work, "iso.img")
    sh("genisoimage", "-quiet", "-R", "-V", "PAGURO", "-o", p, os.path.join(work, "tree"))
    image("iso.img", p)

    g = images["gpt.img"]
    n = len(g) // S
    gp = Gpt(bytearray(g))
    alt = struct.unpack_from("<Q", gp.hdr(1), 32)[0]
    assert alt == n - 1, alt
    blba = struct.unpack_from("<Q", gp.hdr(alt), 72)[0]

    def hdr_field(lba, at, fmt, v):
        def f(m):
            x = Gpt(m)
            h = x.hdr(lba)
            struct.pack_into(fmt, h, at, v)
            x.put_hdr(lba, h)
        return f

    def entry_field(i, at, fmt, v):
        def f(m):
            x = Gpt(m)
            struct.pack_into(fmt, m, x.entry(i) + at, v)
            x.fix_arrays()
        return f

    case("gpt", "gpt.img", "ok")
    case("gpt_told_4096", "gpt.img", "PayloadUnknown", lbs=4096)
    case("gpt4k", "gpt4k.img", "ok", lbs=4096)
    case("gpt4k_told_512", "gpt4k.img", "PayloadUnknown")
    case("gpt4k_backup_missing", "gpt4k.img", "PayloadGptBackup",
         put(4095 * 4096, "<Q", 0), lbs=4096)
    case("gpt4k_esp_not_fat", "gpt4k.img", "PayloadNotFat",
         put(256 * 4096 + 510, "<H", 0), lbs=4096)
    case("gpt4k_root_backup_uuid", "gpt4k.img", "PayloadExt4",
         put(1280 * 4096 + 1024 * 4096 + 0x68, "<B", 0), lbs=4096)
    case("gpt4k_truncated", "gpt4k.img", "PayloadGpt", sectors=4095 * 8, lbs=4096)
    case("ext4_told_4096", "ext4_4k.img", "ok", lbs=4096)
    case("gpt_grown", "gpt_grown.img", "ok")
    case("gpt_unknown", "gpt_unknown.img", "PayloadNoKnownPartition")
    case("gpt_truncated", "gpt.img", "PayloadGpt", sectors=n - 1)
    case("gpt_too_small", "gpt.img", "PayloadUnknown", sectors=1)
    case("gpt_header_crc", "gpt.img", "PayloadGptCrc", put(S + 40, "<B", 0x23))
    case("gpt_header_size", "gpt.img", "PayloadGpt", hdr_field(1, 12, "<I", 91))
    case("gpt_my_lba", "gpt.img", "PayloadGpt", hdr_field(1, 24, "<Q", 2))
    case("gpt_entry_size", "gpt.img", "PayloadGpt", hdr_field(1, 84, "<I", 256))
    case("gpt_entry_count_zero", "gpt.img", "PayloadGpt", hdr_field(1, 80, "<I", 0))
    case("gpt_alt_past_end", "gpt.img", "PayloadGpt", hdr_field(1, 32, "<Q", n))
    case("gpt_usable_overlaps_array", "gpt.img", "PayloadGpt", hdr_field(1, 40, "<Q", 20))
    case("gpt_array_crc", "gpt.img", "PayloadGptCrc", put(gp.entry(0) + 56, "<B", 0x41))
    case("gpt_backup_missing", "gpt.img", "PayloadGptBackup", put(alt * S, "<Q", 0))
    case("gpt_backup_crc", "gpt.img", "PayloadGptBackup", put(alt * S + 40, "<B", 0x23))
    case("gpt_backup_guid", "gpt.img", "PayloadGptBackup", hdr_field(alt, 56, "<B", 0x77))
    case("gpt_backup_my_lba", "gpt.img", "PayloadGptBackup", hdr_field(alt, 24, "<Q", alt - 1))
    case("gpt_backup_array", "gpt.img", "PayloadGptBackup", put(blba * S + 60, "<B", 0x41))
    case("gpt_backup_array_lba", "gpt.img", "PayloadGptBackup", hdr_field(alt, 72, "<Q", 30))
    case("gpt_part_before_usable", "gpt.img", "PayloadGpt", entry_field(0, 32, "<Q", 20))
    case("gpt_part_past_usable", "gpt.img", "PayloadGpt", entry_field(1, 40, "<Q", alt - 1))
    case("gpt_part_reversed", "gpt.img", "PayloadGpt", entry_field(1, 40, "<Q", 8000))
    case("gpt_esp_no_signature", "gpt.img", "PayloadNotFat", put(2048 * S + 510, "<H", 0))
    case("gpt_esp_not_fat", "gpt.img", "PayloadNotFat",
         lambda m: (put(2048 * S + 0x36, "<3s", b"XYZ")(m), put(2048 * S + 0x52, "<5s", b"XYZ32")(m)))
    case("gpt_esp_bigger_than_partition", "gpt.img", "PayloadNotFat",
         lambda m: (put(2048 * S + 0x13, "<H", 0)(m), put(2048 * S + 0x20, "<I", 6145)(m)))
    case("gpt_esp_bytes_per_sector", "gpt.img", "PayloadNotFat", put(2048 * S + 11, "<H", 768))
    case("gpt_esp_cluster_size", "gpt.img", "PayloadNotFat", put(2048 * S + 13, "<B", 3))
    case("gpt_esp_retyped", "gpt.img", "ok",   # ext4 still verifies
         entry_field(0, 0, "<16s", bytes.fromhex("af3dc60f838472478e793d69d8477de4")))
    case("gpt_root_backup_uuid", "gpt.img", "PayloadExt4",
         put(8192 * S + (1 + 2048) * 1024 + 0x68, "<B", 0))
    case("gpt_root_no_magic", "gpt.img", "ok",   # unknown content is skipped
         put(8192 * S + 1024 + 56, "<H", 0))
    case("gpt_root_no_magic_no_esp", "gpt.img", "PayloadNoKnownPartition",
         lambda m: (put(8192 * S + 1024 + 56, "<H", 0)(m), entry_field(0, 0, "<16s", b"\x01" * 16)(m)))
    case("gpt_root_bigger_than_partition", "gpt.img", "PayloadExt4",
         put(8192 * S + 1024 + 4, "<I", 12 * 1024 + 1))

    def ext4_cases(img, bs, first, per_group, group=1):
        sb = 1024
        backup = (first + per_group * group) * bs
        size = len(images[img])
        case(img[:-4], img, "ok")
        case(img[:-4] + "_no_magic", img, "PayloadUnknown", put(sb + 56, "<H", 0))
        case(img[:-4] + "_backup_magic", img, "PayloadExt4", put(backup + 56, "<H", 0))
        case(img[:-4] + "_backup_uuid", img, "PayloadExt4", put(backup + 0x68, "<B", 0))
        case(img[:-4] + "_backup_count", img, "PayloadExt4", put(backup + 4, "<I", 1234))
        case(img[:-4] + "_backup_group_nr", img, "PayloadExt4", put(backup + 0x5a, "<H", 3))
        case(img[:-4] + "_primary_group_nr", img, "PayloadExt4", put(sb + 0x5a, "<H", 1))
        case(img[:-4] + "_log_block_size", img, "PayloadExt4", put(sb + 0x18, "<I", 7))
        case(img[:-4] + "_per_group_zero", img, "PayloadExt4", put(sb + 0x20, "<I", 0))
        case(img[:-4] + "_first_block", img, "PayloadExt4", put(sb + 0x14, "<I", 2))
        # Told it has one group, it is checked by its root directory: fine.
        case(img[:-4] + "_one_group", img, "ok", put(sb + 0x20, "<I", 1 << 20))
        case(img[:-4] + "_payload_short", img, "PayloadExt4", sectors=size // S - 1)
        case(img[:-4] + "_payload_long", img, "ok", sectors=size // S + 8)

    ext4_cases("ext4_1k.img", 1024, 1, 1024)
    ext4_cases("ext4_4k.img", 4096, 0, 1024)
    ext4_cases("ext4_64bit.img", 4096, 0, 1024)
    case("ext4_64bit_backup_count_hi", "ext4_64bit.img", "PayloadExt4",
         put(1024 * 4096 + 0x150, "<I", 1))
    s2 = images["ext4_sparse2.img"]
    bg = struct.unpack_from("<II", s2, 1024 + 0x24C)
    assert struct.unpack_from("<I", s2, 1024 + 0x5C)[0] & 0x200 and bg[0] >= 1, bg
    ext4_cases("ext4_sparse2.img", 4096, 0, 1024, bg[0])
    case("ext4_sparse2_no_backup", "ext4_sparse2.img", "PayloadExt4", put(1024 + 0x24C, "<I", 0))
    case("ext4_sparse2_last_backup", "ext4_sparse2.img", "ok", put(1024 + 0x24C, "<I", bg[1]))
    case("ext4_sparse2_group_beyond", "ext4_sparse2.img", "PayloadExt4", put(1024 + 0x24C, "<I", 4))

    def single(img, bs, first):
        d = images[img]
        assert struct.unpack_from("<I", d, 1024 + 0x20)[0] >= struct.unpack_from("<I", d, 1024 + 4)[0] - first
        wide = struct.unpack_from("<I", d, 1024 + 0x60)[0] & 0x80
        gdt = (first + 1) * bs
        table = struct.unpack_from("<I", d, gdt + 8)[0]
        isz = struct.unpack_from("<H", d, 1024 + 0x58)[0]
        ino = table * bs + isz
        n = img[:-4]
        case(n, img, "ok")
        case(n + "_root_not_dir", img, "PayloadExt4", put(ino, "<H", 0x81a4))
        case(n + "_root_no_extents", img, "PayloadExt4", put(ino + 0x28, "<H", 0))
        case(n + "_table_zero", img, "PayloadExt4", put(gdt + 8, "<I", 0))
        case(n + "_table_past_end", img, "PayloadExt4",
             put(gdt + 8, "<I", struct.unpack_from("<I", d, 1024 + 4)[0]))
        case(n + "_inode_size", img, "PayloadExt4", put(1024 + 0x58, "<H", 100))
        case(n + "_inodes_per_group", img, "PayloadExt4", put(1024 + 0x28, "<I", 1))
        case(n + "_payload_short", img, "PayloadExt4", sectors=len(d) // S - 1)
        case(n + "_payload_long", img, "ok", sectors=len(d) // S + 8)
        if wide:
            case(n + "_desc_size", img, "PayloadExt4", put(1024 + 0xFE, "<H", 32))
            case(n + "_table_hi", img, "PayloadExt4", put(gdt + 0x28, "<I", 1))

    single("ext4_small_1k.img", 1024, 1)
    single("ext4_small_4k.img", 4096, 0)
    single("ext4_small_64bit.img", 4096, 0)
    iso = images["iso.img"]
    pvd = 32768
    case("iso", "iso.img", "ok")
    case("iso_short", "iso.img", "PayloadIso", sectors=len(iso) // S - 4)
    case("iso_long", "iso.img", "PayloadIso", sectors=len(iso) // S + 4)
    case("iso_not_cd001", "iso.img", "PayloadUnknown", put(pvd + 1, "<B", 0x44))
    case("iso_version", "iso.img", "PayloadIso", put(pvd + 6, "<B", 2))
    case("iso_size_endian", "iso.img", "PayloadIso", put(pvd + 84, "<B", 0x7f))
    case("iso_block_size", "iso.img", "PayloadIso",
         lambda m: (put(pvd + 128, "<H", 4096)(m), put(pvd + 130, ">H", 4096)(m)))
    root = struct.unpack_from("<I", iso, pvd + 158)[0]
    case("iso_root_not_dir", "iso.img", "PayloadIso", put(pvd + 181, "<B", 0))
    case("iso_root_past_end", "iso.img", "PayloadIso",
         lambda m: (put(pvd + 158, "<I", 1 << 24)(m), put(pvd + 162, ">I", 1 << 24)(m)))
    case("iso_root_self", "iso.img", "PayloadIso", put(root * 2048 + 2, "<I", root + 1))
    case("iso_root_name", "iso.img", "PayloadIso", put(root * 2048 + 33, "<B", 0x41))

    with open(os.path.join(work, "zero.img"), "wb") as f:
        f.write(b"\0" * 65536)
    image("zero.img", os.path.join(work, "zero.img"))
    case("zero", "zero.img", "PayloadUnknown")
    with open(os.path.join(HERE, "manifest.txt"), "w") as out:
        out.write("# generated by generate.py; see its docstring for the format\n")
        out.write("\n".join(lines) + "\n")
    shutil.rmtree(work)


if __name__ == "__main__":
    sys.exit(main())
