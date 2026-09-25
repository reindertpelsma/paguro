#!/usr/bin/env python3
"""Regenerate the NTFS fixtures for the paguro NTFS core (INTERFACES §10.1, §12).

    sudo test/fixtures/ntfs/generate.py        # needs mkntfs, ntfs-3g (FUSE),
                                               # sgdisk, mkfs.vfat, mtools, gzip
    sudo test/fixtures/ntfs/generate.py vol4kn # rebuild one volume, keep the
                                               # others and their manifest lines

Builds real volumes with mkntfs and writes files into them through ntfs-3g
(fragmented by filling the volume with small files, deleting every other one
and writing into the holes; attribute lists by fragmenting further and by hard
links), then writes:

    *.img.gz      the volumes (gzip -n)
    manifest.txt  what the parsers must return for each named file, and for each
                  named corruption of a clean volume (e2fsprogs f_* style)

manifest.txt lines (the Rust harness and the C unit test both read it):

    file    <name> <image> <rec> <seq> <expect> [<offset>=<hex>...]
    volume  <name> <image> -     -     <expect> [<offset>=<hex>...]

Tokens `R<start>+<len>` give the volume's reserved ranges (PG_VOLUME_ADD,
512-byte sectors); a claim intersecting one is refused as `Reserved`.
<expect> is `ok:<bytes>:<fnv1a64>:<gpt|->` (size, content hash, whether the
payload check passes, with the volume's sector size as view A's logical block
size), `flags:<hex>` for volume lines, or an NtfsError name
(`Sparse`, `Runlist.Unterminated`, ...). Patches are absolute image offsets,
applied to the decompressed image before parsing. This script locates records
and attributes with its own small NTFS reader, independent of both parsers.
"""
import os
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SECTOR = 512


def sh(*args, **kw):
    subprocess.run(args, check=True, **kw)


def fnv(data):
    h = 0xCBF29CE484222325
    for b in data:
        h = ((h ^ b) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return h


# ---- the payload: a small GPT disk with a FAT ESP -------------------------

def payload(work):
    """512 KiB GPT disk: ESP (FAT12) at sectors 64..895, patterned data."""
    disk = os.path.join(work, "disk.bin")
    pattern = b"".join(
        (b"paguro payload sector %08d " % i).ljust(SECTOR, b".") for i in range(1024)
    )
    with open(disk, "wb") as f:
        f.write(pattern)
    sh("sgdisk", "-a", "1", "-n", "1:64:895", "-t", "1:ef00", disk,
       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    esp = os.path.join(work, "esp.bin")
    if os.path.exists(esp):
        os.unlink(esp)
    sh("mkfs.vfat", "-C", esp, "416", stdout=subprocess.DEVNULL)
    blob = os.path.join(work, "blob.txt")
    with open(blob, "wb") as f:
        f.write(pattern[: 300 * 1024])
    sh("mcopy", "-i", esp, blob, "::PATTERN.TXT")
    with open(disk, "r+b") as f, open(esp, "rb") as e:
        f.seek(64 * SECTOR)
        f.write(e.read())
    return open(disk, "rb").read()


def payload4k(work):
    """The same 512 KiB disk with 4096-byte LBAs, for the 4Kn volume (a GPT
    counts LBAs in the view's logical block size): ESP (FAT12, 4096-byte
    sectors) at LBAs 16..111; written with our own GPT writer, as sgdisk
    only does 512-byte LBAs on a file."""
    import zlib
    lbs, lbas = 4096, 128
    img = bytearray(b"".join(
        (b"paguro payload4k sector %08d " % i).ljust(SECTOR, b".") for i in range(1024)))
    esp = os.path.join(work, "esp4k.bin")
    if os.path.exists(esp):
        os.unlink(esp)
    sh("mkfs.vfat", "-i", "4b4b4b4b", "--invariant", "-S", "4096", "-C", esp, "384",
       stdout=subprocess.DEVNULL)
    blob = os.path.join(work, "blob4k.txt")
    with open(blob, "wb") as f:
        f.write(bytes(img[: 200 * 1024]))
    sh("mcopy", "-i", esp, blob, "::PATTERN.TXT")
    e = open(esp, "rb").read()
    img[16 * lbs:16 * lbs + len(e)] = e
    arr = bytearray(128 * 128)
    arr[0:16] = bytes.fromhex("28732ac11ff8d211ba4b00a0c93ec93b")
    arr[16:32] = bytes(range(16, 32))
    struct.pack_into("<QQ", arr, 32, 16, 111)
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
    return bytes(img)


# ---- building volumes through ntfs-3g -------------------------------------

class Mounted:
    def __init__(self, img, mnt):
        self.img, self.mnt = img, mnt

    def __enter__(self):
        sh("ntfs-3g", self.img, self.mnt)
        return self.mnt

    def __exit__(self, *exc):
        sh("umount", self.mnt)


def fill(path):
    """Write zeros until the volume is full."""
    with open(path, "wb", buffering=0) as f:
        for chunk in (65536, 512):
            while True:
                try:
                    f.write(b"\0" * chunk)
                except OSError:
                    break


def holes(img, mnt, tag, n, size):
    """n small files of `size` bytes, the rest of the volume filled, then
    every other one *in disk order* deleted: the holes are all the free
    space left, alternating with live files. (ntfs-3g does not allocate in
    creation order, so disk order comes from reading the runlists.)"""
    with Mounted(img, mnt) as m:
        d = os.path.join(m, tag)
        os.mkdir(d)
        ino = {}
        for i in range(n):
            p = os.path.join(d, str(i))
            write(p, b"h" * size)
            ino[p[len(m):]] = os.stat(p).st_ino
        fill(os.path.join(m, "filler"))
    v = Vol(open(img, "rb").read())
    order = sorted(ino, key=lambda p: v.runs(v.record(ino[p]), v.attr(ino[p], 0x80)[0])[0][0])
    with Mounted(img, mnt) as m:
        for p in order[::2]:
            os.unlink(m + p)


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def big(disk):
    """The payload followed by more pattern, to 2 MiB."""
    tail = b"".join((b"paguro tail sector %08d " % i).ljust(SECTOR, b"-")
                    for i in range(4096 - len(disk) // SECTOR))
    return disk + tail


def build_vol512(img, mnt, disk):
    sh("truncate", "-s", "32M", img)
    sh("mkntfs", "-F", "-Q", "-q", "-c", "512", img, stderr=subprocess.DEVNULL)
    with Mounted(img, mnt) as m:
        write(f"{m}/contig.img", disk)
        write(f"{m}/ads.img", disk)
        sh("setfattr", "-n", "user.stream", "-v", "x" * 3000, f"{m}/ads.img")
        write(f"{m}/small.txt", b"resident data\n")
        write(f"{m}/odd.bin", b"o" * 3000)
        os.mkdir(f"{m}/dir")
        # Phase C's file, with 40 long hard links first: a non-resident list.
        write(f"{m}/links.img", b"")
        for i in range(40):
            os.link(f"{m}/links.img", f"{m}/link{i:03d}" + "L" * 200)
    # Phase A: 8-cluster holes -> ~128 runs, no attribute list.
    holes(img, mnt, "a", 300, 4096)
    with Mounted(img, mnt) as m:
        write(f"{m}/frag.img", disk)
        os.unlink(f"{m}/filler")
    # Phase B: the same with a 2 MiB file -> ~512 runs, spilling into
    # extension records. (Smaller holes make ntfs-3g refuse the write.)
    holes(img, mnt, "b", 1100, 4096)
    with Mounted(img, mnt) as m:
        write(f"{m}/alist.img", big(disk))
        os.unlink(f"{m}/filler")
    # Phase C: the same for links.img.
    holes(img, mnt, "c", 1100, 4096)
    with Mounted(img, mnt) as m:
        write(f"{m}/links.img", big(disk))
        os.unlink(f"{m}/filler")


def build_vol4k(img, mnt, disk):
    sh("truncate", "-s", "8M", img)
    sh("mkntfs", "-F", "-Q", "-q", img, stderr=subprocess.DEVNULL)
    with Mounted(img, mnt) as m:
        write(f"{m}/plain.img", disk)
        os.mkdir(f"{m}/comp")
        sh("setfattr", "-h", "-v", "0x00000800", "-n", "system.ntfs_attrib_be", f"{m}/comp")
        write(f"{m}/comp/c.bin", b"compress me " * 20000)
        with open(f"{m}/sparse.bin", "wb") as f:
            f.seek(256 * 1024)
            f.write(b"s" * 4096)


def build_vol4kn(img, mnt, disk):
    sh("truncate", "-s", "16M", img)
    sh("mkntfs", "-F", "-Q", "-q", "-s", "4096", "-c", "65536", img,
       stderr=subprocess.DEVNULL)
    with Mounted(img, mnt) as m:
        write(f"{m}/plain.img", payload4k(os.path.dirname(img)))


# ---- an independent little NTFS reader, to locate things ------------------

class Vol:
    def __init__(self, data):
        self.d = bytearray(data)
        b = self.d
        self.bps = struct.unpack_from("<H", b, 0x0B)[0]
        raw = b[0x0D]
        spc = raw if raw <= 0x80 else 1 << (256 - raw)
        self.cb = self.bps * spc
        raw = b[0x40]
        self.rb = raw * self.cb if raw < 0x80 else 1 << (256 - raw)
        self.mft_lcn = struct.unpack_from("<Q", b, 0x30)[0]
        self.mft = [(self.mft_lcn, -(-self.rb // self.cb))]
        self.mft = self.runs(self.record(0), self.attr(0, 0x80)[0])

    def off(self, rec, k):
        """Disk offset of byte k of record rec."""
        o = rec * self.rb + k
        for lcn, n in self.mft:
            if o < n * self.cb:
                return lcn * self.cb + o
            o -= n * self.cb
        raise ValueError("record %d outside $MFT" % rec)

    def record(self, rec):
        r = bytearray(self.d[self.off(rec, i)] for i in range(self.rb))
        usa, cnt = struct.unpack_from("<HH", r, 4)
        for i in range(1, cnt):
            r[i * 512 - 2 : i * 512] = r[usa + 2 * i : usa + 2 * i + 2]
        return r

    def attrs(self, rec):
        r = self.record(rec)
        pos = struct.unpack_from("<H", r, 0x14)[0]
        out = []
        while struct.unpack_from("<I", r, pos)[0] != 0xFFFFFFFF:
            ty, ln = struct.unpack_from("<II", r, pos)
            out.append((pos, ty, ln, r[pos + 8], r[pos + 9]))
            pos += ln
        return out

    def attr(self, rec, ty, unnamed=True):
        return [a[0] for a in self.attrs(rec) if a[1] == ty and (a[4] == 0 or not unnamed)]

    def runs(self, r, pos):
        mp = struct.unpack_from("<H", r, pos + 0x20)[0]
        p, lcn, out = pos + mp, 0, []
        while r[p]:
            ls, os_ = r[p] & 15, r[p] >> 4
            n = int.from_bytes(r[p + 1 : p + 1 + ls], "little")
            lcn += int.from_bytes(r[p + 1 + ls : p + 1 + ls + os_], "little", signed=True)
            out.append((lcn, n))
            p += 1 + ls + os_
        return out

    def seq(self, rec):
        return struct.unpack_from("<H", self.record(rec), 0x10)[0]

    def alist(self, rec):
        """The attribute list's bytes and entries (type, lowest, ref, inst, pos)."""
        r = self.record(rec)
        pos = self.attr(rec, 0x20)[0]
        if r[pos + 8] == 0:
            vl, vo = struct.unpack_from("<IH", r, pos + 0x10)
            data = bytes(r[pos + vo : pos + vo + vl])
        else:
            size = struct.unpack_from("<Q", r, pos + 0x30)[0]
            data = b"".join(
                self.d[l * self.cb : (l + n) * self.cb] for l, n in self.runs(r, pos)
            )[:size]
        out, p = [], 0
        while p < len(data):
            ty, ln = struct.unpack_from("<IH", data, p)
            low, ref, inst = struct.unpack_from("<QQH", data, p + 8)
            out.append((ty, low, ref, inst, p))
            p += ln
        return data, out

    # Patches in record coordinates, emitted in disk coordinates: bytes
    # hidden under the update sequence are written to its array instead.
    def patch(self, rec, k, value):
        ops = []
        usa = struct.unpack_from("<H", self.record(rec), 4)[0]
        for i, byte in enumerate(value):
            o = k + i
            if o % 512 >= 510:
                o = usa + 2 * (o // 512 + 1) + (o % 512 - 510)
            ops.append((self.off(rec, o), byte))
        return ops


def fmt(ops):
    return " ".join("%d=%02x" % (o, b) for o, b in ops)


def raw(offset, value):
    return [(offset + i, b) for i, b in enumerate(value)]


# ---- the manifest ---------------------------------------------------------

def main():
    if os.geteuid() != 0:
        sys.exit("needs root (ntfs-3g FUSE mounts)")
    work = tempfile.mkdtemp()
    mnt = os.path.join(work, "mnt")
    os.mkdir(mnt)
    disk = payload(work)
    ok = "ok:%d:%016x:gpt" % (len(disk), fnv(disk))
    lines = []

    def add(kind, name, img, rec, seq, expect, ops=(), extra=()):
        toks = [kind, name, img, rec, seq, expect] + ([fmt(ops)] if ops else []) + list(extra)
        lines.append(" ".join(map(str, toks)))

    only = sys.argv[1] if len(sys.argv) > 1 else None
    for name, build in [("vol512", build_vol512), ("vol4k", build_vol4k),
                        ("vol4kn", build_vol4kn)]:
        if only and name != only:
            continue
        img = os.path.join(work, name + ".img")
        build(img, mnt, disk)
        ino = {}
        with Mounted(img, mnt) as m:
            for root, dirs, files in os.walk(m):
                for f in dirs + files:
                    p = os.path.join(root, f)
                    ino[os.path.relpath(p, m)] = os.stat(p).st_ino
        v = Vol(open(img, "rb").read())
        gz = name + ".img"

        def f(path, expect, label=None, seq=None, ops=()):
            rec = ino[path]
            add("file", label or path.replace("/", "_"), gz, rec,
                v.seq(rec) if seq is None else seq, expect, ops)

        add("volume", "clean", gz, "-", "-", "flags:0000")
        if name == "vol512":
            for p in ["contig.img", "ads.img", "frag.img"]:
                f(p, ok)
            b = big(disk)
            for p in ["alist.img", "links.img"]:
                f(p, "ok:%d:%016x:gpt" % (len(b), fnv(b)))
            f("small.txt", "Resident")
            f("odd.bin", "Unaligned")
            f("dir", "Directory")
            f("contig.img", "Sequence", label="wrong_seq", seq=v.seq(ino["contig.img"]) + 1)
            data, ents = v.alist(ino["alist.img"])
            ext = [e for e in ents if e[0] == 0x80 and e[2] & 0xFFFFFFFFFFFF != ino["alist.img"]]
            assert len(ext) >= 2, "alist.img did not spill into extension records"
            _, lents = v.alist(ino["links.img"])
            assert v.record(ino["links.img"])[v.attr(ino["links.img"], 0x20)[0] + 8] == 1
            ext_rec = ext[0][2] & 0xFFFFFFFFFFFF
            add("file", "extension_record", gz, ext_rec, v.seq(ext_rec), "NotBase")
            freed = next(i for i in range(ino["contig.img"], 4000)
                         if v.record(i)[0:4] == b"FILE" and not v.record(i)[0x16] & 1)
            add("file", "deleted_record", gz, freed, v.seq(freed), "NotInUse")
            add("file", "system_record", gz, 5, 5, "BadIdentity")
            add("file", "record_past_32_bits", gz, 1 << 32, 1, "BadIdentity")
            mft_records = struct.unpack_from("<Q", v.record(0), v.attr(0, 0x80)[0] + 0x30)[0] // v.rb
            add("file", "last_slot", gz, mft_records - 1, 1, "NotInUse")
            add("file", "past_mft_end", gz, mft_records, 1, "NotMapped")
            corrupt_vol512(v, ino, gz, add)
            reserved_vol512(v, ino, gz, add, ok)
        if name == "vol4k":
            f("plain.img", ok)
            f("comp/c.bin", "Compressed")
            f("sparse.bin", "Sparse")
            f("comp", "Directory")
        if name == "vol4kn":
            d4 = payload4k(work)
            f("plain.img", "ok:%d:%016x:gpt" % (len(d4), fnv(d4)))
        sh("gzip", "-9", "-n", "-f", img)
        os.replace(img + ".gz", os.path.join(HERE, gz + ".gz"))
    if only:
        # Keep every other volume's lines, in place.
        old = open(os.path.join(HERE, "manifest.txt")).read().splitlines()[1:]
        mine = only + ".img"
        kept = [l for l in old if l.split()[2] != mine]
        at = next((i for i, l in enumerate(old) if l.split()[2] == mine), len(kept))
        lines = kept[:at] + lines + kept[at:]
    with open(os.path.join(HERE, "manifest.txt"), "w") as out:
        out.write("# generated by generate.py; see its docstring for the format\n")
        out.write("\n".join(lines) + "\n")


def corrupt_vol512(v, ino, gz, add):
    """One named corruption per line, each of a clean volume (e2fsprogs f_*)."""
    c = ino["contig.img"]
    fr = ino["frag.img"]
    al = ino["alist.img"]
    seq = v.seq
    rec = lambda n: v.record(n)
    data = lambda n: v.attr(n, 0x80)[0]

    def bad(name, target, expect, ops, s=None):
        add("file", "f_" + name, gz, target, seq(target) if s is None else s, expect, ops)

    # Boot sector.
    bad("boot_signature", c, "BootSignature", raw(510, b"\0"))
    bad("boot_oem", c, "OemId", raw(3, b"FAT32   "))
    bad("boot_sector_size", c, "SectorSize", raw(0x0B, struct.pack("<H", 1024)))
    bad("cluster_size_zero", c, "ClusterSize", raw(0x0D, b"\0"))
    bad("cluster_size_huge", c, "ClusterSize", raw(0x0D, b"\xf0"))  # 32 MiB
    bad("volume_size_zero", c, "VolumeSize", raw(0x28, bytes(8)))
    bad("record_size_mismatch", c, "RecordLayout", raw(0x40, b"\xf4"))  # 4 KiB
    bad("record_size_invalid", c, "RecordSize", raw(0x40, b"\xf8"))  # 256 B
    bad("mft_lcn_past_end", c, "MftLcn", raw(0x30, struct.pack("<Q", 1 << 40)))
    # $MFT record 0.
    mp = struct.unpack_from("<H", rec(0), data(0) + 0x20)[0]
    bad("mft_runlist_past_end", c, "OutsideVolume",
        v.patch(0, data(0) + mp, bytes([0x41, 0x10, 0, 0, 0, 0x7F, 0])))
    bad("mft_fixup", c, "FixupMismatch", v.patch(0, 0x30, b"\x00\x00"))
    # The file's record header.
    bad("fixup_mismatch", c, "FixupMismatch", raw(v.off(c, 510), b"\x00\x00"))
    bad("usa_count_past_end", c, "RecordLayout", v.patch(c, 6, struct.pack("<H", 0x20)))
    bad("usa_offset", c, "RecordLayout", v.patch(c, 4, struct.pack("<H", 0x28)))
    bad("magic_baad", c, "RecordMagic", v.patch(c, 0, b"BAAD"))
    bad("attrs_offset_misaligned", c, "RecordLayout", v.patch(c, 0x14, struct.pack("<H", 0x3C)))
    bad("bytes_in_use_past_end", c, "RecordLayout", v.patch(c, 0x18, struct.pack("<I", 2048)))
    bad("record_number", c, "RecordNumber", v.patch(c, 0x2C, struct.pack("<I", c + 1)))
    bad("not_in_use", c, "NotInUse", v.patch(c, 0x16, b"\0\0"))
    bad("directory_flag", c, "Directory", v.patch(c, 0x16, b"\3\0"))
    bad("base_reference", c, "NotBase", v.patch(c, 0x20, struct.pack("<Q", 12)))
    # Attributes.
    first = struct.unpack_from("<H", rec(c), 0x14)[0]
    bad("attr_length_zero", c, "AttrBounds", v.patch(c, first + 4, bytes(4)))
    bad("attr_length_past_end", c, "AttrBounds", v.patch(c, first + 4, struct.pack("<I", 0x1000)))
    bad("attr_length_unaligned", c, "AttrBounds", v.patch(c, first + 4, struct.pack("<I", 0x61)))
    bad("attr_overlap", c, "AttrBounds", v.patch(c, first + 4, struct.pack("<I", 0x18)))
    bad("attr_name_past_end", c, "AttrBounds", v.patch(c, first + 9, b"\x7f"))
    bad("attr_no_end_marker", c, "AttrBounds",
        v.patch(c, struct.unpack_from("<I", rec(c), 0x18)[0] - 8, b"\x10\0\0\0"))
    d = data(c)
    bad("data_resident_flag", c, "AttrBounds", v.patch(c, d + 8, b"\x02"))
    bad("data_sparse", c, "Sparse", v.patch(c, d + 0x0C, struct.pack("<H", 0x8000)))
    bad("data_compressed", c, "Compressed", v.patch(c, d + 0x0C, struct.pack("<H", 1)))
    bad("data_compression_unit", c, "Compressed", v.patch(c, d + 0x22, b"\x04"))
    bad("data_encrypted", c, "Encrypted", v.patch(c, d + 0x0C, struct.pack("<H", 0x4000)))
    alloc = struct.unpack_from("<Q", rec(c), d + 0x28)[0]
    bad("allocated_size", c, "AllocatedSize", v.patch(c, d + 0x28, struct.pack("<Q", alloc + 512)))
    bad("data_size_past_alloc", c, "AllocatedSize",
        v.patch(c, d + 0x30, struct.pack("<Q", alloc + 512)))
    bad("initialized_size", c, "NotInitialized", v.patch(c, d + 0x38, struct.pack("<Q", 512)))
    bad("highest_vcn", c, "SegmentVcn",
        v.patch(c, d + 0x18, struct.pack("<Q", struct.unpack_from("<Q", rec(c), d + 0x18)[0] + 1)))
    bad("lowest_vcn", c, "Gap", v.patch(c, d + 0x10, struct.pack("<Q", 1)))
    bad("mapping_pairs_offset", c, "AttrBounds", v.patch(c, d + 0x20, struct.pack("<H", 0x38)))
    # Runlists, on the fragmented file (room for long mapping pairs).
    d = data(fr)
    r = rec(fr)
    mp = struct.unpack_from("<H", r, d + 0x20)[0]
    room = struct.unpack_from("<I", r, d + 4)[0] - mp
    unterm = bytes([0x11, 0x01, 0x01]) * (room // 3) + bytes([0x21, 0x01, 0x01, 0x00])[: room % 3]
    bad("runlist_unterminated", fr, "Runlist.Unterminated" if room % 3 == 0 else
        ("Runlist.Truncated"), v.patch(fr, d + mp, unterm))
    bad("runlist_zero_width_length", fr, "Runlist.FieldTooWide", v.patch(fr, d + mp, b"\x20"))
    bad("runlist_wide_field", fr, "Runlist.FieldTooWide", v.patch(fr, d + mp, b"\x19"))
    bad("runlist_sparse_run", fr, "Runlist.Sparse", v.patch(fr, d + mp, b"\x01\x05"))
    bad("runlist_zero_length", fr, "Runlist.ZeroLength", v.patch(fr, d + mp, b"\x11\x00"))
    bad("runlist_lcn_underflow", fr, "Runlist.NegativeLcn", v.patch(fr, d + mp, b"\x11\x01\xff"))
    big = bytes([0x81, 0x01]) + b"\xff" * 7 + b"\x7f"
    bad("runlist_lcn_overflow", fr, "Runlist.Overflow", v.patch(fr, d + mp, big * 3))
    bad("runlist_past_volume", fr, "OutsideVolume",
        v.patch(fr, d + mp, bytes([0x41, 0x01, 0, 0, 0, 0x40, 0])))
    bad("runlist_truncated", fr, "Runlist.Truncated",
        v.patch(fr, d + mp, bytes([0x11, 1, 1]) * ((room - 1) // 3) + b"\x88" +
                b"\x01" * ((room - 1) % 3)))
    # Attribute lists: gaps, overlaps, loops, bad targets.
    lst, ents = v.alist(al)
    dents = [e for e in ents if e[0] == 0x80]
    base = al
    e2 = dents[1]
    ext_rec = e2[2] & 0xFFFFFFFFFFFF
    seg = [p for p in v.attr(ext_rec, 0x80)][0]
    low = struct.unpack_from("<Q", rec(ext_rec), seg + 0x10)[0]
    bad("alist_vcn_gap", al, "Gap", v.patch(ext_rec, seg + 0x10, struct.pack("<Q", low + 1)))
    bad("alist_vcn_overlap", al, "Gap", v.patch(ext_rec, seg + 0x10, struct.pack("<Q", low - 1)))
    # ntfs-3g always moves a list this long out of the record; the unit
    # tests cover resident lists.
    lpos = v.attr(al, 0x20)[0]
    assert rec(al)[lpos + 8] == 1
    lruns = v.runs(rec(al), lpos)
    assert len(lruns) == 1

    def ent(e, k, val):
        return raw(lruns[0][0] * v.cb + e[4] + k, val)

    bad("alist_entry_vcn", al, "Gap", ent(e2, 8, struct.pack("<Q", e2[1] + 1)))
    bad("alist_self_reference", al, "MissingSegment",
        ent(e2, 0x10, struct.pack("<Q", base | seq(base) << 48)))
    bad("alist_repeat_entry", al, "Gap", ent(e2, 0, lst[dents[0][4] : dents[0][4] + 0x20]))
    freed = next(i for i in range(ino["contig.img"], 4000)
                 if v.record(i)[0:4] == b"FILE" and not v.record(i)[0x16] & 1)
    bad("alist_unused_record", al, "NotInUse",
        ent(e2, 0x10, struct.pack("<Q", freed | seq(freed) << 48)))
    bad("alist_wrong_seq", al, "Sequence",
        ent(e2, 0x10, struct.pack("<Q", ext_rec | (seq(ext_rec) + 1) << 48)))
    bad("alist_missing_instance", al, "MissingSegment", ent(e2, 0x18, b"\xee\xee"))
    bad("alist_entry_short", al, "AttrList", ent(dents[0], 4, b"\x10\x00"))
    bad("alist_entry_past_end", al, "AttrList", ent(dents[0], 4, b"\x00\x10"))
    bad("alist_ext_base", al, "ExtensionBase", v.patch(ext_rec, 0x20, struct.pack("<Q", 12)))
    bad("alist_ext_record_number", al, "RecordNumber", v.patch(ext_rec, 0x2C, b"\x01\0\0\0"))
    bad("alist_ext_resident", al, "Resident", v.patch(ext_rec, seg + 8, b"\x00") +
        v.patch(ext_rec, seg + 0x10, struct.pack("<I", 0)) +
        v.patch(ext_rec, seg + 0x14, struct.pack("<H", 0x18)))
    # $Volume.
    vi = v.attr(3, 0x70)[0]
    vo = struct.unpack_from("<H", rec(3), vi + 0x14)[0]
    add("volume", "f_volume_dirty", gz, "-", "-", "flags:0001",
        v.patch(3, vi + vo + 0x0A, b"\x01\x00"))
    add("volume", "f_volume_no_info", gz, "-", "-", "NoVolumeInfo", v.patch(3, vi, b"\x60"))
    add("volume", "f_volume_not_in_use", gz, "-", "-", "NotInUse", v.patch(3, 0x16, b"\0\0"))
    add("volume", "f_volume_not_base", gz, "-", "-", "NotBase", v.patch(3, 0x20, b"\x05"))
    add("volume", "f_volume_info_short", gz, "-", "-", "NoVolumeInfo",
        v.patch(3, vi + 0x10, struct.pack("<I", 8)))


def reserved_vol512(v, ino, gz, add, ok):
    """BitLocker's reserved ranges (INTERFACES §10.2 PG_VOLUME_ADD): a claim
    whose extents intersect one is refused (`Reserved`); touching is fine.
    Tokens `R<start>+<len>` (512-byte sectors) give a volume's ranges."""
    fr = ino["frag.img"]
    spc = v.cb // SECTOR
    runs = v.runs(v.record(fr), v.attr(fr, 0x80)[0])
    ext = [(l * spc, (l + n) * spc) for l, n in runs]
    a, b = ext[len(ext) // 2]  # an extent in the middle of the file
    last = max(e for _, e in ext)
    free = [x for x in range(16, last) if not any(s <= x < e for s, e in ext)]

    cases = [
        # one of each kind overlapping the file
        ("boot_area", "Reserved", [(0, a + 1)]),
        ("reloc_copy", "Reserved", [(a + 1, 2)]),
        ("fve_meta_head", "Reserved", [(a - 7, 8)]),
        ("fve_meta_tail", "Reserved", [(b - 1, 16)]),
        ("fve_meta_whole", "Reserved", [(a - 1, b - a + 2)]),
        # touching, not intersecting: accepted
        ("touch_before", ok, [(a - 8, 8)]),
        ("touch_after", ok, [(b, 8)]),
        ("touch_both", ok, [(a - 8, 8), (b, 8)]),
        ("none", ok, []),
        # eight disjoint ranges clear of the file: accepted
        ("eight_clear", ok, [(0, 16)] + [(x, 1) for x in free[:7]]),
        # eight ranges, only the last overlapping
        ("eight_last_hits", "Reserved", [(0, 16)] + [(x, 1) for x in free[:6]] + [(a, 1)]),
    ]
    for name, expect, ranges in cases:
        toks = ["R%d+%d" % (s, n) for s, n in ranges]
        add("file", "r_" + name, gz, fr, v.seq(fr), expect, (), toks)


if __name__ == "__main__":
    main()
