// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * paguro NTFS core: see pg_ntfs.h. Mirrors crates/paguro-core/src/ntfs.rs
 * function for function; keep them in step.
 *
 * Every read of an on-disk field is preceded by a check that it lies inside
 * the buffer that holds it. Those checks carry a "bound:" comment; a read
 * without one is covered by an earlier check named there.
 */
#include "pg_ntfs.h"

#define SECTOR 512u
#define ATTR_LIST 0x20
#define ATTR_VOLUME_INFO 0x70
#define ATTR_DATA 0x80
#define ATTR_END 0xffffffffu
#define USA_OFFSET 0x30u	/* NTFS 3.1 FILE records; others refused */

static const pg_u8 esp_type[16] = {
	0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
	0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b,
};

/* Little-endian field of n bytes at b + at. The caller has bounds-checked. */
static pg_u64 get(const pg_u8 *b, pg_size at, unsigned int n)
{
	pg_u64 v = 0;

	while (n--)
		v = v << 8 | b[at + n];
	return v;
}
#define G8(b, at) get(b, at, 1)
#define G16(b, at) get(b, at, 2)
#define G32(b, at) get(b, at, 4)
#define G64(b, at) get(b, at, 8)

static int same(const pg_u8 *a, const char *b, pg_size n)
{
	while (n--)
		if (a[n] != (pg_u8)b[n])
			return 0;
	return 1;
}

static int is_pow2(pg_u64 x)
{
	return x && !(x & (x - 1));
}

int pg_runlist_decode(const pg_u8 *in, pg_size len, struct pg_run *out,
		      pg_size cap, pg_size *n)
{
	pg_size pos = 0, k = 0;
	pg_u64 lcn = 0;

	/* Terminates: pos grows by >= 2 per run and is bounded by len. */
	for (;;) {
		unsigned int h, lsz, osz, i;
		pg_u64 count = 0, delta = 0;

		if (pos >= len)
			return PG_E_RL_UNTERMINATED;
		h = in[pos];
		if (h == 0) {
			*n = k;
			return 0;
		}
		pos++;
		lsz = h & 0xf;
		osz = h >> 4;
		if (lsz == 0 || lsz > 8 || osz > 8)
			return PG_E_RL_FIELD_TOO_WIDE;
		if (osz == 0)
			return PG_E_RL_SPARSE;
		if (len - pos < lsz)		/* bound: length field */
			return PG_E_RL_TRUNCATED;
		for (i = 0; i < lsz; i++)
			count |= (pg_u64)in[pos + i] << (8 * i);
		pos += lsz;
		if (len - pos < osz)		/* bound: offset field */
			return PG_E_RL_TRUNCATED;
		for (i = 0; i < osz; i++)
			delta |= (pg_u64)in[pos + i] << (8 * i);
		pos += osz;
		if (osz < 8 && (delta >> (8 * osz - 1) & 1))
			delta |= ~(pg_u64)0 << (8 * osz);	/* sign-extend */
		if (count == 0)
			return PG_E_RL_ZERO_LENGTH;
		if (delta >> 63) {			/* negative delta */
			pg_u64 back = ~delta + 1;	/* its magnitude */

			if (back > lcn)
				return PG_E_RL_NEGATIVE_LCN;
			lcn -= back;
		} else {
			if (lcn + delta < lcn)
				return PG_E_RL_OVERFLOW;
			lcn += delta;
		}
		if (lcn + count < lcn)
			return PG_E_RL_OVERFLOW;
		if (k == cap)				/* bound: out[] */
			return PG_E_RL_TOO_MANY_RUNS;
		out[k].lcn = lcn;
		out[k].count = count;
		k++;
	}
}

int pg_ntfs_boot(struct pg_ntfs *v, const pg_u8 *b)
{
	pg_u64 bps, raw, spc, bytes, rb;

	if (G16(b, 510) != 0xaa55)
		return PG_E_BOOT_SIGNATURE;
	if (!same(b + 3, "NTFS    ", 8))
		return PG_E_OEM_ID;
	bps = G16(b, 0x0b);
	if (bps != 512 && bps != 4096)
		return PG_E_SECTOR_SIZE;
	/* Sectors per cluster: 1..128, or 2^(256 - raw) beyond 64 KiB. */
	raw = G8(b, 0x0d);
	spc = raw <= 0x80 ? raw : 256 - raw <= 20 ? (pg_u64)1 << (256 - raw) : 0;
	/* bound: bps <= 4096 and spc <= 2^20, so the product cannot wrap */
	if (!is_pow2(spc) || bps * spc > PG_NTFS_MAX_CLUSTER)
		return PG_E_CLUSTER_SIZE;
	v->cluster_bytes = bps * spc;
	if (G64(b, 0x28) > ~(pg_u64)0 / bps)
		return PG_E_VOLUME_SIZE;
	bytes = G64(b, 0x28) * bps;
	v->clusters = bytes / v->cluster_bytes;
	if (v->clusters == 0)
		return PG_E_VOLUME_SIZE;
	/* Record size: clusters per record if positive, else 2^-raw bytes. */
	raw = G8(b, 0x40);
	rb = raw < 0x80 ? raw * v->cluster_bytes :
	     256 - raw <= 12 ? (pg_u64)1 << (256 - raw) : 0;
	if (rb < 1024 || rb > PG_NTFS_MAX_RECORD || !is_pow2(rb))
		return PG_E_RECORD_SIZE;
	v->record_bytes = rb;
	v->mft_lcn = G64(b, 0x30);
	if (v->mft_lcn >= v->clusters ||
	    v->clusters - v->mft_lcn < (rb + v->cluster_bytes - 1) / v->cluster_bytes)
		return PG_E_MFT_LCN;
	v->sectors = v->clusters * (v->cluster_bytes / SECTOR);
	return 0;
}

/*
 * The sector holding byte `off` of an attribute mapped by `runs` (each
 * already checked to lie inside the volume, so nothing here can wrap).
 * Returns 0 past the last run.
 */
static int sector_of(const struct pg_ntfs *v, const struct pg_run *runs,
		     pg_size n, pg_u64 off, pg_u64 *sector)
{
	pg_u64 vcn = off / v->cluster_bytes;
	pg_size i;

	for (i = 0; i < n; i++) {
		if (vcn < runs[i].count) {
			*sector = ((runs[i].lcn + vcn) * v->cluster_bytes +
				   off % v->cluster_bytes) / SECTOR;
			return 1;
		}
		vcn -= runs[i].count;
	}
	return 0;
}

/*
 * Read record `recno` through `map` (bytes below `limit`) into v->rec, apply
 * the update-sequence fixups and check the header. Afterwards the record's
 * bytes_in_use (0x18) <= record size and attrs offset (0x14) < bytes_in_use.
 */
static int read_record(struct pg_ntfs *v, const struct pg_run *map,
		       pg_size nmap, pg_u64 limit, pg_u64 recno)
{
	pg_u8 *r = v->rec;
	pg_u64 rb = v->record_bytes, start, s, usn, attrs, used;
	pg_size i, count;

	if (recno > ~(pg_u64)0 / rb)
		return PG_E_NOT_MAPPED;
	start = recno * rb;
	if (start > limit || limit - start < rb)
		return PG_E_NOT_MAPPED;
	/* bound: rb <= PG_NTFS_MAX_RECORD, the size of v->rec */
	for (i = 0; i < rb / SECTOR; i++) {
		if (!sector_of(v, map, nmap, start + i * SECTOR, &s))
			return PG_E_NOT_MAPPED;
		if (v->read(v->ctx, s, r + i * SECTOR))
			return PG_E_IO;
	}
	if (!same(r, "FILE", 4))
		return PG_E_RECORD_MAGIC;
	/* One update-sequence entry per 512 bytes, plus the USN itself. */
	count = G16(r, 6);
	if (G16(r, 4) != USA_OFFSET || count != rb / SECTOR + 1)
		return PG_E_RECORD_LAYOUT;
	/* bound: the array ends at 0x30 + 2 * 9 < 512 */
	usn = G16(r, USA_OFFSET);
	for (i = 1; i < count; i++) {
		if (G16(r, i * SECTOR - 2) != usn)
			return PG_E_FIXUP_MISMATCH;
		r[i * SECTOR - 2] = r[USA_OFFSET + 2 * i];
		r[i * SECTOR - 1] = r[USA_OFFSET + 2 * i + 1];
	}
	attrs = G16(r, 0x14);
	used = G32(r, 0x18);
	if (G32(r, 0x1c) != rb || used > rb || used % 8 || attrs % 8 ||
	    attrs < USA_OFFSET + 2 * count || attrs >= used)
		return PG_E_RECORD_LAYOUT;
	if (G32(r, 0x2c) != recno)
		return PG_E_RECORD_NUMBER;
	return 0;
}

/*
 * Validate the attribute header at `pos` of a checked record. *type is
 * ATTR_END at the end marker. Afterwards the header (0x18 bytes, 0x40 if
 * non-resident), its name and any resident value lie inside the attribute,
 * and the attribute inside bytes_in_use.
 */
static int attr_at(const pg_u8 *r, pg_size pos, pg_u64 *type, pg_size *len)
{
	pg_size used = G32(r, 0x18), name_len;
	pg_u64 nonres;

	if (pos + 4 > used)			/* bound: type */
		return PG_E_ATTR_BOUNDS;
	*type = G32(r, pos);
	if (*type == ATTR_END)
		return 0;
	if (pos + 0x18 > used)			/* bound: common header */
		return PG_E_ATTR_BOUNDS;
	*len = G32(r, pos + 4);
	if (*len < 0x18 || *len % 8 || *len > used - pos)
		return PG_E_ATTR_BOUNDS;
	nonres = G8(r, pos + 8);
	name_len = G8(r, pos + 9);
	if (nonres > 1 ||
	    (name_len > 0 && G16(r, pos + 0x0a) + 2 * name_len > *len))
		return PG_E_ATTR_BOUNDS;
	if (nonres == 1 && *len < 0x40)		/* bound: non-resident header */
		return PG_E_ATTR_BOUNDS;
	if (nonres == 0 && G16(r, pos + 0x14) + G32(r, pos + 0x10) > *len)
		return PG_E_ATTR_BOUNDS;	/* bound: resident value */
	return 0;
}

/* Decode the runlist of the non-resident attribute at `pos`, in-volume. */
static int decode_runs(const struct pg_ntfs *v, const pg_u8 *r, pg_size pos,
		       struct pg_run *out, pg_size cap, pg_size *k)
{
	pg_size len = G32(r, pos + 4), mp = G16(r, pos + 0x20), i;
	int e;

	if (mp < 0x40 || mp >= len)		/* bound: inside the attribute */
		return PG_E_ATTR_BOUNDS;
	e = pg_runlist_decode(r + pos + mp, len - mp, out, cap, k);
	if (e)
		return e;
	for (i = 0; i < *k; i++)	/* lcn + count cannot wrap: decoder */
		if (out[i].lcn + out[i].count > v->clusters)
			return PG_E_OUTSIDE_VOLUME;
	return 0;
}

/* Progress through a file's $DATA segments. */
struct seg {
	pg_size n;
	pg_u64 vcn, alloc, size, init;
};

/*
 * Append the $DATA segment at `pos` to out[]. Keeps: out[0..n) maps VCNs
 * 0..vcn with no gap, every run inside the volume.
 */
static int segment(const struct pg_ntfs *v, const pg_u8 *r, pg_size pos,
		   struct seg *st, struct pg_run *out, pg_size cap)
{
	pg_u64 flags, lowest, sum = 0, next;
	pg_size k, i;
	int e;

	if (G8(r, pos + 8) == 0)
		return PG_E_RESIDENT;
	/* bound: non-resident, so attr_at checked 0x40 header bytes */
	/* Sparse first: ntfs-3g gives sparse files a compression unit too. */
	flags = G16(r, pos + 0x0c);
	if (flags & 0x8000)
		return PG_E_SPARSE;
	if (flags & 0x4000)
		return PG_E_ENCRYPTED;
	if ((flags & 0x00ff) || G8(r, pos + 0x22))
		return PG_E_COMPRESSED;
	lowest = G64(r, pos + 0x10);
	if (lowest != st->vcn)
		return PG_E_GAP;
	if (lowest == 0) {
		st->alloc = G64(r, pos + 0x28);
		st->size = G64(r, pos + 0x30);
		st->init = G64(r, pos + 0x38);
	}
	e = decode_runs(v, r, pos, out + st->n, cap - st->n, &k);
	if (e)
		return e;
	for (i = 0; i < k; i++) {
		if (sum + out[st->n + i].count < sum)
			return PG_E_SEGMENT_VCN;
		sum += out[st->n + i].count;
	}
	if (lowest + sum < lowest)
		return PG_E_SEGMENT_VCN;
	next = lowest + sum;
	if (k == 0 || G64(r, pos + 0x18) != next - 1)
		return PG_E_SEGMENT_VCN;
	st->n += k;
	st->vcn = next;
	return 0;
}

/*
 * Copy the $ATTRIBUTE_LIST at `pos` into v->alist, reading its clusters if
 * non-resident (its runs borrow scratch[], which the caller reuses after).
 */
static int load_list(struct pg_ntfs *v, pg_size pos, struct pg_run *scratch,
		     pg_size cap, pg_size *size)
{
	const pg_u8 *r = v->rec;
	pg_u64 bytes, off, s;
	pg_size k, i;
	int e;

	if (G8(r, pos + 8) == 0) {
		/* bound: attr_at kept the value inside the record, < 4 KiB */
		*size = G32(r, pos + 0x10);
		for (i = 0; i < *size; i++)
			v->alist[i] = r[pos + G16(r, pos + 0x14) + i];
		return 0;
	}
	if (G16(r, pos + 0x0c) || G64(r, pos + 0x10))
		return PG_E_ATTR_LIST;
	bytes = G64(r, pos + 0x30);
	if (bytes > PG_NTFS_MAX_ALIST)		/* bound: v->alist */
		return PG_E_ATTR_LIST_SIZE;
	if (G64(r, pos + 0x38) != bytes)
		return PG_E_ATTR_LIST;
	e = decode_runs(v, r, pos, scratch, cap, &k);
	if (e)
		return e;
	/* Whole sectors: PG_NTFS_MAX_ALIST is a multiple of 512. */
	for (off = 0; off < bytes; off += SECTOR) {
		if (!sector_of(v, scratch, k, off, &s))
			return PG_E_ATTR_LIST;
		if (v->read(v->ctx, s, v->alist + off))
			return PG_E_IO;
	}
	*size = bytes;
	return 0;
}

/* Offset of the unnamed $DATA with this instance in v->rec, or 0. */
static int find_segment(const pg_u8 *r, pg_u64 instance, pg_size *at)
{
	pg_size pos = G16(r, 0x14), len;
	pg_u64 type;
	int e;

	*at = 0;
	/* Terminates: every attribute is at least 0x18 bytes. */
	while (!(e = attr_at(r, pos, &type, &len)) && type != ATTR_END) {
		if (type == ATTR_DATA && G8(r, pos + 9) == 0 &&
		    G16(r, pos + 0x0e) == instance) {
			*at = pos;
			return 0;
		}
		pos += len;
	}
	return e;
}

/*
 * Steps 3-5 for record `recno`, reading records through `map`. seq == 0
 * skips the sequence check (only for $MFT itself).
 */
static int walk(struct pg_ntfs *v, const struct pg_run *map, pg_size nmap,
		pg_u64 limit, pg_u64 recno, pg_u64 seq, int allow_list,
		struct pg_run *out, pg_size cap, pg_size *nruns,
		pg_u64 *data_size)
{
	const pg_u8 *r = v->rec;
	const pg_u8 *al = v->alist;
	struct seg st = { 0, 0, 0, 0, 0 };
	pg_u64 flags, own_seq, base_ref, type, ref;
	pg_size pos, len, list = 0, data = 0, ndata = 0, size, p, elen, at;
	unsigned int ext = 0;
	int e, has_list = 0;

	e = read_record(v, map, nmap, limit, recno);
	if (e)
		return e;
	flags = G16(r, 0x16);
	if (!(flags & 1))
		return PG_E_NOT_IN_USE;
	if (flags & 2)
		return PG_E_DIRECTORY;
	own_seq = G16(r, 0x10);
	if (seq && own_seq != seq)
		return PG_E_SEQUENCE;
	if (G64(r, 0x20))
		return PG_E_NOT_BASE;
	/* One pass over the base record: the attribute list, unnamed $DATA. */
	pos = G16(r, 0x14);
	while (!(e = attr_at(r, pos, &type, &len)) && type != ATTR_END) {
		if (type == ATTR_LIST) {
			if (has_list)
				return PG_E_ATTR_LIST;
			has_list = 1;
			list = pos;
		}
		if (type == ATTR_DATA && G8(r, pos + 9) == 0) {
			if (ndata == 0)
				data = pos;
			ndata++;
		}
		pos += len;
	}
	if (e)
		return e;
	if (!has_list) {
		if (ndata == 0)
			return PG_E_NO_DATA;
		if (ndata > 1)
			return PG_E_DUPLICATE_DATA;
		e = segment(v, r, data, &st, out, cap);
		if (e)
			return e;
	} else {
		if (!allow_list)
			return PG_E_MFT_ATTR_LIST;
		e = load_list(v, list, out, cap, &size);
		if (e)
			return e;
		base_ref = recno | own_seq << 48;
		/*
		 * Entries are sorted by (type, name, lowest VCN); the Gap check
		 * enforces that order for unnamed $DATA. Terminates: every
		 * entry is at least 0x1a bytes.
		 */
		for (p = 0; p < size; p += elen) {
			if (p + 0x1a > size)	/* bound: entry header */
				return PG_E_ATTR_LIST;
			elen = G16(al, p + 4);
			if (elen < 0x1a || elen > size - p)
				return PG_E_ATTR_LIST;
			if (G32(al, p) != ATTR_DATA || G8(al, p + 6) != 0)
				continue;
			if (G64(al, p + 8) != st.vcn)
				return PG_E_GAP;
			ref = G64(al, p + 0x10) & 0xffffffffffffull;
			if (ref != recno && ++ext > PG_NTFS_MAX_EXTENSIONS)
				return PG_E_TOO_MANY_EXTENSIONS;
			e = read_record(v, map, nmap, limit, ref);
			if (e)
				return e;
			if (!(G16(r, 0x16) & 1))
				return PG_E_NOT_IN_USE;
			if (G16(r, 0x10) != G64(al, p + 0x10) >> 48)
				return PG_E_SEQUENCE;
			if (G64(r, 0x20) != (ref == recno ? 0 : base_ref))
				return PG_E_EXTENSION_BASE;
			e = find_segment(r, G16(al, p + 0x18), &at);
			if (e)
				return e;
			if (!at)
				return PG_E_MISSING_SEGMENT;
			e = segment(v, r, at, &st, out, cap);
			if (e)
				return e;
		}
		if (st.n == 0)
			return PG_E_NO_DATA;
	}
	if (st.vcn > ~(pg_u64)0 / v->cluster_bytes ||
	    st.vcn * v->cluster_bytes != st.alloc || st.size > st.alloc)
		return PG_E_ALLOCATED_SIZE;
	if (st.init != st.size)
		return PG_E_NOT_INITIALIZED;
	if (st.size % SECTOR)
		return PG_E_UNALIGNED;
	*nruns = st.n;
	*data_size = st.size;
	return 0;
}

int pg_ntfs_open(struct pg_ntfs *v)
{
	struct pg_run boot_map;
	int e;

	if (v->read(v->ctx, 0, v->rec))
		return PG_E_IO;
	e = pg_ntfs_boot(v, v->rec);
	if (e)
		return e;
	/* Record 0 is at the boot sector's LCN; nothing else is known yet. */
	boot_map.lcn = v->mft_lcn;
	boot_map.count = (v->record_bytes + v->cluster_bytes - 1) /
			 v->cluster_bytes;
	return walk(v, &boot_map, 1, v->record_bytes, 0, 0, 0, v->mft,
		    v->mft_cap, &v->nmft, &v->mft_bytes);
}

int pg_ntfs_file(struct pg_ntfs *v, pg_u64 rec, pg_u16 seq,
		 struct pg_run *runs, pg_size cap, pg_size *nruns,
		 pg_u64 *data_size)
{
	if (rec < PG_NTFS_FIRST_USER_RECORD || rec > 0xffffffffu || seq == 0)
		return PG_E_BAD_IDENTITY;
	return walk(v, v->mft, v->nmft, v->mft_bytes, rec, seq, 1, runs, cap,
		    nruns, data_size);
}

int pg_ntfs_extents(const struct pg_ntfs *v, const struct pg_run *runs,
		    pg_size n, struct pg_extent *out, pg_size cap,
		    pg_size *nout)
{
	pg_u64 spc = v->cluster_bytes / SECTOR, start, end;
	pg_size i, k = 0;

	for (i = 0; i < n; i++) {
		if (runs[i].lcn > ~(pg_u64)0 / spc ||
		    runs[i].lcn + runs[i].count < runs[i].lcn ||
		    runs[i].lcn + runs[i].count > ~(pg_u64)0 / spc)
			return PG_E_OUTSIDE_VOLUME;
		start = runs[i].lcn * spc;
		end = (runs[i].lcn + runs[i].count) * spc;
		if (end > v->sectors)
			return PG_E_OUTSIDE_VOLUME;
		if (k > 0 && out[k - 1].end == start) {
			out[k - 1].end = end;
			continue;
		}
		if (k == cap)			/* bound: out[] */
			return PG_E_TOO_MANY_EXTENTS;
		out[k].start = start;
		out[k].end = end;
		k++;
	}
	*nout = k;
	return 0;
}

int pg_ntfs_volume_flags(struct pg_ntfs *v, pg_u16 *flags)
{
	const pg_u8 *r = v->rec;
	pg_size pos, len;
	pg_u64 type;
	int e;

	e = read_record(v, v->mft, v->nmft, v->mft_bytes, 3);
	if (e)
		return e;
	if (!(G16(r, 0x16) & 1))
		return PG_E_NOT_IN_USE;
	if (G64(r, 0x20))
		return PG_E_NOT_BASE;
	pos = G16(r, 0x14);
	while (!(e = attr_at(r, pos, &type, &len)) && type != ATTR_END) {
		if (type == ATTR_VOLUME_INFO && G8(r, pos + 8) == 0) {
			/* bound: attr_at kept the value inside the record */
			if (G32(r, pos + 0x10) < 12)
				return PG_E_NO_VOLUME_INFO;
			*flags = (pg_u16)G16(r, pos + G16(r, pos + 0x14) + 0x0a);
			return 0;
		}
		pos += len;
	}
	return e ? e : PG_E_NO_VOLUME_INFO;
}

int pg_payload_check(pg_read_fn read, void *ctx, pg_u64 sectors, pg_u8 *b)
{
	pg_u64 hsize, lba, count, esize, i, first, last;
	pg_size e;

	if (sectors < 3)
		return PG_E_PAYLOAD_GPT;
	if (read(ctx, 1, b))
		return PG_E_IO;
	hsize = G32(b, 12);
	if (!same(b, "EFI PART", 8) || hsize < 92 || hsize > 512 ||
	    G64(b, 24) != 1)
		return PG_E_PAYLOAD_GPT;
	lba = G64(b, 72);
	count = G32(b, 80);
	esize = G32(b, 84);
	if (esize != 128 || count == 0 || count > 1024 || lba < 2 ||
	    lba >= sectors)
		return PG_E_PAYLOAD_GPT;
	if (sectors - lba < (count + 3) / 4)	/* bound: the entry array */
		return PG_E_PAYLOAD_GPT;
	for (i = 0; i < count; i++) {
		if (i % 4 == 0 && read(ctx, lba + i / 4, b))
			return PG_E_IO;
		e = (i % 4) * 128;
		if (!same(b + e, (const char *)esp_type, 16))
			continue;
		first = G64(b, e + 32);
		last = G64(b, e + 40);
		if (first < 2 || first > last || last >= sectors)
			return PG_E_PAYLOAD_GPT;
		if (read(ctx, first, b))
			return PG_E_IO;
		if (G16(b, 510) != 0xaa55 ||
		    !(same(b + 0x36, "FAT", 3) || same(b + 0x52, "FAT32", 5)))
			return PG_E_PAYLOAD_NOT_FAT;
		return 0;
	}
	return PG_E_PAYLOAD_NO_ESP;
}
