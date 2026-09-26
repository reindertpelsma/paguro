#!/usr/bin/env python3
"""DESIGN.md §11 Q24's instrument: which sectors the guest wrote where.

Reads a dm-log-writes log (what QEMU's blklogwrites writes, 512-byte log
sectors) of the Windows VM's disk and the session's layout (session.json
from `paguro-vm prepare`), and reports every write that touched a
BitLocker-owned range of C:, and a summary of writes per area of the
synthesised disk (GPT, ESP, MSR, C: data).

    q24.py writes.log session.json [--phases FILE]
    q24.py --count writes.log          entries so far (a phase boundary)

--phases: lines "<name> <entry count>", in order: each write is attributed
to the first phase whose boundary is above its index.
"""
import json
import struct
import sys

MAGIC = 0x6A736677736872
FLUSH, FUA, DISCARD, MARK, METADATA = 1, 2, 4, 8, 16


def entries(path):
    with open(path, "rb") as f:
        sup = f.read(512)
        magic, version, nr, ssz = struct.unpack_from("<QQQI", sup)
        if magic != MAGIC:
            sys.exit(f"{path}: not a dm-log-writes log")
        pos = ssz
        i = 0
        while True:
            f.seek(pos)
            h = f.read(ssz)
            if len(h) < 32:
                break
            sector, nsec, flags, dlen = struct.unpack_from("<QQQQ", h)
            if i >= nr and sector == 0 and nsec == 0 and flags == 0 and dlen == 0:
                break
            yield i, sector, nsec, flags, dlen
            # dm-log-writes: data_len bytes follow; QEMU's blklogwrites
            # leaves data_len 0 and writes nr_sectors of data (not for a
            # discard).
            data = dlen if dlen else (0 if flags & DISCARD else nsec * ssz)
            pos += ssz + (data + ssz - 1) // ssz * ssz
            i += 1


def main():
    if sys.argv[1] == "--count":
        print(sum(1 for _ in entries(sys.argv[2])))
        return
    log, sess = sys.argv[1], json.load(open(sys.argv[2]))
    phases = []
    if "--phases" in sys.argv:
        for line in open(sys.argv[sys.argv.index("--phases") + 1]):
            parts = line.split()
            # A phase recorded after QEMU was killed has no count: skip it.
            if len(parts) == 2 and parts[1].isdigit():
                phases.append((int(parts[1]), parts[0]))

    def phase(i):
        for n, name in phases:
            if i < n:
                return name
        return "after"

    v0 = sess["volume_at"] // 512
    vol = sess["volume_bytes"] // 512
    disk = sess["disk_bytes"] // 512
    owned = [(v0 + s, n, name) for (s, n, _), name in zip(sess["owned"], sess["owned_names"])]
    areas = {"gpt-head": (0, 2048), "gpt-tail": (v0 + vol, disk - v0 - vol)}
    # ESP and MSR from the table: ESP at 1 MiB up to the MSR/volume.
    areas["esp+msr"] = (2048, v0 - 2048)
    stats = {k: [0, 0] for k in list(areas) + ["C:data", "C:owned"]}
    hits = []
    n = 0
    for i, sector, nsec, flags, dlen in entries(log):
        if flags & (FLUSH | MARK) and nsec == 0:
            continue
        if nsec == 0:
            continue
        n += 1
        end = sector + nsec
        kind = "discard" if flags & DISCARD else "write"
        touched = False
        for s, l, name in owned:
            if sector < s + l and s < end:
                a, b = max(sector, s), min(end, s + l)
                hits.append((i, kind, name, a - s, b - a, flags))
                touched = True
        if touched:
            stats["C:owned"][0] += 1
            stats["C:owned"][1] += nsec
        elif v0 <= sector < v0 + vol:
            stats["C:data"][0] += 1
            stats["C:data"][1] += nsec
        else:
            for k, (s, l) in areas.items():
                if s <= sector < s + l:
                    stats[k][0] += 1
                    stats[k][1] += nsec
    print(f"writes logged: {n}")
    for k, (c, s) in stats.items():
        print(f"  {k:10s} {c:8d} writes {s * 512 / 2**20:10.1f} MiB")
    print(f"writes into BitLocker-owned ranges: {len(hits)}")
    for i, kind, name, off, cnt, flags in hits:
        f = "+".join(x for x, b in (("FUA", FUA), ("META", METADATA)) if flags & b)
        print(f"  #{i:7d} {phase(i):16s} {kind:7s} {name:24s} +{off:4d} x{cnt:4d} {f}")


if __name__ == "__main__":
    main()
