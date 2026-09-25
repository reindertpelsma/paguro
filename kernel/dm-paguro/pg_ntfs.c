// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * paguro NTFS core: see pg_ntfs.h. Mirrors crates/paguro-core/src/ntfs.rs
 * function for function; keep them in step.
 *
 * Every read of an on-disk field is preceded by a check that it lies inside
 * the buffer that holds it. Those checks carry a "bound:" comment; a read
 * without one is covered by an earlier check named there.
 */
#include "pg_layout.h"
#include "pg_ntfs.h"

#define SECTOR 512u

static const pg_u8 esp_type[16] = GPT_ESP_TYPE;

/* Little-endian field of n bytes at b + at. The caller has bounds-checked. */
static pg_u64 get(const pg_u8 *b, pg_size at, unsigned int n)
{
	pg_u64 v = 0;

	while (n--)
		v = v << 8 | b[at + n];
	return v;
}
/* A field of a pg_layout.h structure at b (+ at): offset and width from it. */
#define GET(b, T, f) get(b, PG_OFF(T, f), (unsigned int)PG_SIZE(T, f))
#define GET_AT(b, at, T, f) \
	get(b, (at) + PG_OFF(T, f), (unsigned int)PG_SIZE(T, f))
/* A little-endian integer of n bytes at b + at, for what is not a field. */
#define G16(b, at) get(b, at, 2)

static int same(const pg_u8 *a, const char *b, pg_size n)
{
	while (n--)
		if (a[n] != (pg_u8)b[n])
			return 0;
	return 1;
}

static int eq(const pg_u8 *a, const pg_u8 *b, pg_size n)
{
	while (n--)
		if (a[n] != b[n])
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
		lsz = h & NTFS_RUN_LENGTH_SIZE_MASK;
		osz = h >> NTFS_RUN_OFFSET_SIZE_SHIFT;
		if (lsz == 0 || lsz > NTFS_RUN_MAX_FIELD || osz > NTFS_RUN_MAX_FIELD)
			return PG_E_RL_FIELD_TOO_WIDE;
		if (osz == 0)
			return PG_E_RL_SPARSE;
		if (len - pos < lsz)		/* bound: length field */
			return PG_E_RL_TRUNCATED;
		for (i = 0; i < lsz; i++)	/* little-endian, i bytes */
			count |= (pg_u64)in[pos + i] << (8 * i);
		pos += lsz;
		if (len - pos < osz)		/* bound: offset field */
			return PG_E_RL_TRUNCATED;
		for (i = 0; i < osz; i++)
			delta |= (pg_u64)in[pos + i] << (8 * i);
		pos += osz;
		/* Sign-extend an osz-byte two's-complement delta to 64 bits. */
		if (osz < NTFS_RUN_MAX_FIELD && (delta >> (8 * osz - 1) & 1))
			delta |= ~(pg_u64)0 << (8 * osz);
		if (count == 0)
			return PG_E_RL_ZERO_LENGTH;
		if (delta >> 63) {			/* sign bit: negative */
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

	if (GET(b, struct ntfs_boot_sector, signature) != BOOT_SIGNATURE)
		return PG_E_BOOT_SIGNATURE;
	if (!same(b + PG_OFF(struct ntfs_boot_sector, oem_id), NTFS_OEM_ID,
		  PG_SIZE(struct ntfs_boot_sector, oem_id)))
		return PG_E_OEM_ID;
	bps = GET(b, struct ntfs_boot_sector, bytes_per_sector);
	if (bps != 512 && bps != 4096)
		return PG_E_SECTOR_SIZE;
	/*
	 * Sectors per cluster: 1..128, or 2^(256 - raw) beyond 64 KiB (the
	 * byte, read as negative, is minus the exponent: 256 - raw).
	 */
	raw = GET(b, struct ntfs_boot_sector, sectors_per_cluster);
	spc = raw <= NTFS_BS_NEGATIVE ? raw :
	      256 - raw <= NTFS_BS_MAX_CLUSTER_SHIFT ? (pg_u64)1 << (256 - raw) : 0;
	/* bound: bps <= 4096 and spc <= 2^20, so the product cannot wrap */
	if (!is_pow2(spc) || bps * spc > PG_NTFS_MAX_CLUSTER)
		return PG_E_CLUSTER_SIZE;
	v->cluster_bytes = bps * spc;
	if (GET(b, struct ntfs_boot_sector, total_sectors) > ~(pg_u64)0 / bps)
		return PG_E_VOLUME_SIZE;
	bytes = GET(b, struct ntfs_boot_sector, total_sectors) * bps;
	v->clusters = bytes / v->cluster_bytes;
	if (v->clusters == 0)
		return PG_E_VOLUME_SIZE;
	/* Record size: clusters per record if positive, else 2^-raw bytes. */
	raw = GET(b, struct ntfs_boot_sector, clusters_per_mft_record);
	rb = raw < NTFS_BS_NEGATIVE ? raw * v->cluster_bytes :
	     256 - raw <= NTFS_BS_MAX_RECORD_SHIFT ? (pg_u64)1 << (256 - raw) : 0;
	if (rb < 1024 || rb > PG_NTFS_MAX_RECORD || !is_pow2(rb))
		return PG_E_RECORD_SIZE;
	v->record_bytes = rb;
	v->mft_lcn = GET(b, struct ntfs_boot_sector, mft_lcn);
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
 * bytes_in_use <= record size and attrs_offset < bytes_in_use.
 */
static int read_record(struct pg_ntfs *v, const struct pg_run *map,
		       pg_size nmap, pg_u64 limit, pg_u64 recno)
{
	pg_u8 *r = v->rec;
	pg_u64 rb = v->record_bytes, start, s, usn, attrs, used, usa;
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
	if (!same(r, NTFS_RECORD_MAGIC, PG_SIZE(struct ntfs_file_record, magic)))
		return PG_E_RECORD_MAGIC;
	/* One update-sequence entry per 512 bytes, plus the USN itself. */
	count = GET(r, struct ntfs_file_record, usa_count);
	usa = GET(r, struct ntfs_file_record, usa_offset);
	if ((usa != NTFS_USA_OFFSET_31 && usa != NTFS_USA_OFFSET_30) ||
	    count != rb / SECTOR + 1)
		return PG_E_RECORD_LAYOUT;
	/*
	 * bound: the array (u16s) ends at 0x30 + 2 * 9 < 512. Each sector's
	 * last two bytes hold the USN; the array holds what belongs there.
	 */
	usn = G16(r, usa);
	for (i = 1; i < count; i++) {
		if (G16(r, i * SECTOR - 2) != usn)
			return PG_E_FIXUP_MISMATCH;
		r[i * SECTOR - 2] = r[usa + 2 * i];
		r[i * SECTOR - 1] = r[usa + 2 * i + 1];
	}
	attrs = GET(r, struct ntfs_file_record, attrs_offset);
	used = GET(r, struct ntfs_file_record, bytes_in_use);
	/* Attributes are 8-byte aligned. */
	if (GET(r, struct ntfs_file_record, bytes_allocated) != rb || used > rb ||
	    used % 8 || attrs % 8 || attrs < usa + 2 * count || attrs >= used)
		return PG_E_RECORD_LAYOUT;
	/* Only the 3.1 layout says which record it is (3.0's array is there). */
	if (usa == NTFS_USA_OFFSET_31 &&
	    GET(r, struct ntfs_file_record, mft_record_number) != recno)
		return PG_E_RECORD_NUMBER;
	return 0;
}

/*
 * Validate the attribute header at `pos` of a checked record. *type is
 * NTFS_AT_END at the end marker. Afterwards the header (resident, or the
 * longer non-resident one), its name (UTF-16) and any resident value lie
 * inside the attribute, and the attribute inside bytes_in_use.
 */
static int attr_at(const pg_u8 *r, pg_size pos, pg_u64 *type, pg_size *len)
{
	pg_size used = GET(r, struct ntfs_file_record, bytes_in_use), name_len;
	pg_u64 nonres;

	/* bound: type */
	if (pos + PG_SIZE(struct ntfs_attr, type) > used)
		return PG_E_ATTR_BOUNDS;
	*type = GET_AT(r, pos, struct ntfs_attr, type);
	if (*type == NTFS_AT_END)
		return 0;
	/* bound: the header every attribute has room for */
	if (pos + sizeof(struct ntfs_attr_resident) > used)
		return PG_E_ATTR_BOUNDS;
	*len = GET_AT(r, pos, struct ntfs_attr, length);
	if (*len < sizeof(struct ntfs_attr_resident) || *len % 8 ||
	    *len > used - pos)
		return PG_E_ATTR_BOUNDS;
	nonres = GET_AT(r, pos, struct ntfs_attr, non_resident);
	name_len = GET_AT(r, pos, struct ntfs_attr, name_length);
	if (nonres > 1 ||
	    (name_len > 0 &&
	     GET_AT(r, pos, struct ntfs_attr, name_offset) + 2 * name_len > *len))
		return PG_E_ATTR_BOUNDS;
	/* bound: non-resident header */
	if (nonres == 1 && *len < sizeof(struct ntfs_attr_nonresident))
		return PG_E_ATTR_BOUNDS;
	/* bound: resident value */
	if (nonres == 0 &&
	    GET_AT(r, pos, struct ntfs_attr_resident, value_offset) +
	    GET_AT(r, pos, struct ntfs_attr_resident, value_length) > *len)
		return PG_E_ATTR_BOUNDS;
	return 0;
}

/* Decode the runlist of the non-resident attribute at `pos`, in-volume. */
static int decode_runs(const struct pg_ntfs *v, const pg_u8 *r, pg_size pos,
		       struct pg_run *out, pg_size cap, pg_size *k)
{
	pg_size len = GET_AT(r, pos, struct ntfs_attr, length), i;
	pg_size mp = GET_AT(r, pos, struct ntfs_attr_nonresident,
			    mapping_pairs_offset);
	int e;

	/* bound: inside the attribute, after its header */
	if (mp < sizeof(struct ntfs_attr_nonresident) || mp >= len)
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

	if (GET_AT(r, pos, struct ntfs_attr, non_resident) == 0)
		return PG_E_RESIDENT;
	/* bound: non-resident, so attr_at checked its whole header */
	/* Sparse first: ntfs-3g gives sparse files a compression unit too. */
	flags = GET_AT(r, pos, struct ntfs_attr, flags);
	if (flags & NTFS_ATTR_IS_SPARSE)
		return PG_E_SPARSE;
	if (flags & NTFS_ATTR_IS_ENCRYPTED)
		return PG_E_ENCRYPTED;
	lowest = GET_AT(r, pos, struct ntfs_attr_nonresident, lowest_vcn);
	if ((flags & (lowest ? NTFS_ATTR_IS_COMPRESSED :
			       NTFS_ATTR_COMPRESSION_MASK)) ||
	    GET_AT(r, pos, struct ntfs_attr_nonresident, compression_unit))
		return PG_E_COMPRESSED;
	if (lowest != st->vcn)
		return PG_E_GAP;
	if (lowest == 0) {
		st->alloc = GET_AT(r, pos, struct ntfs_attr_nonresident,
				   allocated_size);
		st->size = GET_AT(r, pos, struct ntfs_attr_nonresident, data_size);
		st->init = GET_AT(r, pos, struct ntfs_attr_nonresident,
				  initialized_size);
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
	if (k == 0 ||
	    GET_AT(r, pos, struct ntfs_attr_nonresident, highest_vcn) != next - 1)
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

	if (GET_AT(r, pos, struct ntfs_attr, non_resident) == 0) {
		/* bound: attr_at kept the value inside the record, < 4 KiB */
		*size = GET_AT(r, pos, struct ntfs_attr_resident, value_length);
		for (i = 0; i < *size; i++)
			v->alist[i] = r[pos + GET_AT(r, pos, struct ntfs_attr_resident,
						     value_offset) + i];
		return 0;
	}
	if (GET_AT(r, pos, struct ntfs_attr, flags) ||
	    GET_AT(r, pos, struct ntfs_attr_nonresident, lowest_vcn))
		return PG_E_ATTR_LIST;
	bytes = GET_AT(r, pos, struct ntfs_attr_nonresident, data_size);
	if (bytes > PG_NTFS_MAX_ALIST)		/* bound: v->alist */
		return PG_E_ATTR_LIST_SIZE;
	if (GET_AT(r, pos, struct ntfs_attr_nonresident, initialized_size) != bytes)
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
	pg_size pos = GET(r, struct ntfs_file_record, attrs_offset), len;
	pg_u64 type;
	int e;

	*at = 0;
	/* Terminates: attr_at makes every attribute a header long at least. */
	while (!(e = attr_at(r, pos, &type, &len)) && type != NTFS_AT_END) {
		if (type == NTFS_AT_DATA &&
		    GET_AT(r, pos, struct ntfs_attr, name_length) == 0 &&
		    GET_AT(r, pos, struct ntfs_attr, instance) == instance) {
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
	flags = GET(r, struct ntfs_file_record, flags);
	if (!(flags & NTFS_RECORD_IN_USE))
		return PG_E_NOT_IN_USE;
	if (flags & NTFS_RECORD_IS_DIRECTORY)
		return PG_E_DIRECTORY;
	own_seq = GET(r, struct ntfs_file_record, sequence_number);
	if (seq && own_seq != seq)
		return PG_E_SEQUENCE;
	if (GET(r, struct ntfs_file_record, base_mft_record))
		return PG_E_NOT_BASE;
	/* One pass over the base record: the attribute list, unnamed $DATA. */
	pos = GET(r, struct ntfs_file_record, attrs_offset);
	while (!(e = attr_at(r, pos, &type, &len)) && type != NTFS_AT_END) {
		if (type == NTFS_AT_ATTRIBUTE_LIST) {
			if (has_list)
				return PG_E_ATTR_LIST;
			has_list = 1;
			list = pos;
		}
		if (type == NTFS_AT_DATA &&
		    GET_AT(r, pos, struct ntfs_attr, name_length) == 0) {
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
		base_ref = recno | own_seq << NTFS_MFT_REF_SEQ_SHIFT;
		/*
		 * Entries are sorted by (type, name, lowest VCN); the Gap check
		 * enforces that order for unnamed $DATA. Terminates: every
		 * entry is at least a header long.
		 */
		for (p = 0; p < size; p += elen) {
			/* bound: entry header */
			if (p + sizeof(struct ntfs_attr_list_entry) > size)
				return PG_E_ATTR_LIST;
			elen = GET_AT(al, p, struct ntfs_attr_list_entry, length);
			if (elen < sizeof(struct ntfs_attr_list_entry) ||
			    elen > size - p)
				return PG_E_ATTR_LIST;
			if (GET_AT(al, p, struct ntfs_attr_list_entry, type) !=
			    NTFS_AT_DATA ||
			    GET_AT(al, p, struct ntfs_attr_list_entry,
				   name_length) != 0)
				continue;
			if (GET_AT(al, p, struct ntfs_attr_list_entry,
				   lowest_vcn) != st.vcn)
				return PG_E_GAP;
			ref = GET_AT(al, p, struct ntfs_attr_list_entry,
				     mft_reference) & NTFS_MFT_REF_RECORD_MASK;
			if (ref != recno && ++ext > PG_NTFS_MAX_EXTENSIONS)
				return PG_E_TOO_MANY_EXTENSIONS;
			e = read_record(v, map, nmap, limit, ref);
			if (e)
				return e;
			if (!(GET(r, struct ntfs_file_record, flags) &
			      NTFS_RECORD_IN_USE))
				return PG_E_NOT_IN_USE;
			if (GET(r, struct ntfs_file_record, sequence_number) !=
			    GET_AT(al, p, struct ntfs_attr_list_entry,
				   mft_reference) >> NTFS_MFT_REF_SEQ_SHIFT)
				return PG_E_SEQUENCE;
			if (GET(r, struct ntfs_file_record, base_mft_record) !=
			    (ref == recno ? 0 : base_ref))
				return PG_E_EXTENSION_BASE;
			e = find_segment(r, GET_AT(al, p,
						   struct ntfs_attr_list_entry,
						   instance), &at);
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
	if (rec < PG_NTFS_FIRST_USER_RECORD || rec > PG_NTFS_MAX_RECORD_NUMBER ||
	    seq == 0)
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

	e = read_record(v, v->mft, v->nmft, v->mft_bytes,
			NTFS_MFT_RECORD_VOLUME);
	if (e)
		return e;
	if (!(GET(r, struct ntfs_file_record, flags) & NTFS_RECORD_IN_USE))
		return PG_E_NOT_IN_USE;
	if (GET(r, struct ntfs_file_record, base_mft_record))
		return PG_E_NOT_BASE;
	pos = GET(r, struct ntfs_file_record, attrs_offset);
	while (!(e = attr_at(r, pos, &type, &len)) && type != NTFS_AT_END) {
		if (type == NTFS_AT_VOLUME_INFORMATION &&
		    GET_AT(r, pos, struct ntfs_attr, non_resident) == 0) {
			/* bound: attr_at kept the value inside the record */
			if (GET_AT(r, pos, struct ntfs_attr_resident, value_length) <
			    sizeof(struct ntfs_volume_information))
				return PG_E_NO_VOLUME_INFO;
			*flags = (pg_u16)GET_AT(r, pos + GET_AT(r, pos,
					struct ntfs_attr_resident, value_offset),
					struct ntfs_volume_information, flags);
			return 0;
		}
		pos += len;
	}
	return e ? e : PG_E_NO_VOLUME_INFO;
}

/*
 * The structural assertion (INTERFACES 3.2, "the structural assertion follows
 * the content"). Mirrors check_payload() in ntfs.rs read for read; every
 * helper below takes the one 512-byte buffer and says what it holds. All
 * sector numbers are bounded by `sectors` before they are read.
 */
#define ISO_PVD (ISO_PVD_OFFSET / SECTOR)	/* the PVD's sector */
/* The superblock's first sector, and the sector that holds its byte 512 on. */
#define EXT4_SB_SECTOR (EXT4_SUPERBLOCK_OFFSET / SECTOR)
#define EXT4_SB_HIGH(f) (PG_OFF(struct ext4_super_block, f) - SECTOR)

#ifdef PG_CBMC_STUB_EXT4
int pg_cbmc_payload_ext4(pg_read_fn read, void *ctx, pg_u64 base, pg_u64 len,
			 pg_u8 *b);
#endif
#ifdef PG_CBMC_FREE_CRC
/* Model checking only (test/cbmc/payload.c): a free function there. */
pg_u32 pg_crc32(pg_u32 c, const pg_u8 *p, pg_size n);
#else
/* Bitwise CRC-32 (IEEE, reflected), continuing from `c`. */
static pg_u32 pg_crc32(pg_u32 c, const pg_u8 *p, pg_size n)
{
	unsigned int k;

	c = ~c;
	while (n--) {
		c ^= *p++;
		for (k = 0; k < 8; k++)
			/* shift out a bit; if it was 1, xor the polynomial */
			c = (c >> 1) ^ (CRC32_POLY & (0u - (c & 1)));
	}
	return ~c;
}
#endif

/* CRC of the first n (<= 512) bytes of a GPT header, its CRC field as 0. */
static pg_u64 header_crc(const pg_u8 *b, pg_size n)
{
	static const pg_u8 zero[PG_SIZE(struct gpt_header, header_crc32)];
	const pg_size at = PG_OFF(struct gpt_header, header_crc32);
	const pg_size after = at + sizeof(zero);
	pg_u32 c;

	c = pg_crc32(0, b, at);
	c = pg_crc32(c, zero, sizeof(zero));
	return pg_crc32(c, b + after, n - after);
}

static int array_crc(pg_read_fn read, void *ctx, pg_u64 lba, pg_u64 count,
		     pg_u8 *b, pg_u64 *crc)
{
	pg_u64 left = count * sizeof(struct gpt_entry), n;
	pg_u32 c = 0;

	while (left) {
		if (read(ctx, lba, b))
			return PG_E_IO;
		n = left < SECTOR ? left : SECTOR;
		c = pg_crc32(c, b, (pg_size)n);
		left -= n;
		lba++;
	}
	*crc = c;
	return 0;
}

/* A big-endian integer of n bytes at b + at (ISO 9660's _be halves). */
static pg_u64 be(const pg_u8 *b, pg_size at, unsigned int n)
{
	pg_u64 v = 0;
	unsigned int i;

	for (i = 0; i < n; i++)
		v = v << 8 | b[at + i];
	return v;
}

#define BPB struct fat16_boot_sector	/* the BPB FAT12/16/32 share */

/* A FAT boot sector (in b) for a partition of len sectors. */
static int is_fat(const pg_u8 *b, pg_u64 len)
{
	pg_u64 bps = GET(b, BPB, bytes_per_sector);
	pg_u64 spc = GET(b, BPB, sectors_per_cluster);
	pg_u64 total = GET(b, BPB, total_sectors_16);

	if (!total)
		total = GET(b, BPB, total_sectors_32);
	return GET(b, BPB, signature) == BOOT_SIGNATURE &&
	       (same(b + PG_OFF(struct fat16_boot_sector, fs_type), FAT_FS_TYPE,
		     sizeof(FAT_FS_TYPE) - 1) ||
		same(b + PG_OFF(struct fat32_boot_sector, fs_type), FAT32_FS_TYPE,
		     sizeof(FAT32_FS_TYPE) - 1)) &&
	       (bps == 512 || bps == 1024 || bps == 2048 || bps == 4096) &&
	       is_pow2(spc) && total && total * (bps / SECTOR) <= len;
}
#undef BPB

/*
 * A single-group ext4 at `base` (ntfs.rs payload_ext4_root): the root
 * directory (inode 2), found through group 0's descriptor and the inode
 * table, must be a directory whose i_block starts with an extent header
 * (0xF30A). b holds the superblock's first sector. Bounds: every sector
 * read is below count * per_block, which the caller bounded by len.
 */
#define SB struct ext4_super_block

static int payload_ext4_root(pg_read_fn read, void *ctx, pg_u64 base,
			     pg_u64 first, pg_u64 count, pg_u64 log, int wide,
			     int dynamic, pg_u8 *b)
{
	/* A block is 1 KiB << log: (2 << log) sectors. */
	pg_u64 bs = 1024ull << log, per_block = 2ull << log;
	pg_u64 isz = dynamic ? GET(b, SB, s_inode_size) : EXT4_GOOD_OLD_INODE_SIZE;
	pg_u64 dsz = wide ? GET(b, SB, s_desc_size) : EXT4_MIN_DESC_SIZE;
	pg_u64 gdt = first + 1, table, sector;
	pg_size o;

	if (!is_pow2(isz) || isz < EXT4_GOOD_OLD_INODE_SIZE || isz > bs ||
	    !is_pow2(dsz) || dsz < EXT4_MIN_DESC_SIZE || dsz > EXT4_MAX_DESC_SIZE ||
	    (wide && dsz < EXT4_MIN_DESC_SIZE_64BIT) ||
	    GET(b, SB, s_inodes_per_group) < EXT4_ROOT_INO)
		return PG_E_PAYLOAD_EXT4;
	/* The group descriptors follow the superblock's block. */
	if (gdt >= count)
		return PG_E_PAYLOAD_EXT4;
	if (read(ctx, base + gdt * per_block, b))
		return PG_E_IO;
	table = GET(b, struct ext4_group_desc, bg_inode_table_lo) |
		(wide ? GET(b, struct ext4_group_desc, bg_inode_table_hi) << 32 : 0);
	if (!table || table >= count)
		return PG_E_PAYLOAD_EXT4;
	/* Inode 2 is the second of group 0's table: isz bytes in. */
	sector = table * per_block + isz * (EXT4_ROOT_INO - 1) / SECTOR;
	if (sector >= count * per_block)
		return PG_E_PAYLOAD_EXT4;
	if (read(ctx, base + sector, b))
		return PG_E_IO;
	/* 0, 128 or 256: the fields read lie in b */
	o = (pg_size)(isz * (EXT4_ROOT_INO - 1) % SECTOR);
	if ((GET_AT(b, o, struct ext4_inode, i_mode) & EXT4_S_IFMT) != EXT4_S_IFDIR ||
	    GET_AT(b, o + PG_OFF(struct ext4_inode, i_block),
		   struct ext4_extent_header, eh_magic) != EXT4_EXT_MAGIC)
		return PG_E_PAYLOAD_EXT4;
	return 0;
}

/*
 * ext4 at sector `base`, `len` sectors long; b holds sector base + 2, whose
 * magic matched. Bounds: count <= len / per_block, block < count, so every
 * read is inside [base, base + len).
 */
static int payload_ext4(pg_read_fn read, void *ctx, pg_u64 base, pg_u64 len,
			pg_u8 *b)
{
	pg_u64 log = GET(b, SB, s_log_block_size);
	pg_u64 first = GET(b, SB, s_first_data_block);
	pg_u64 per_group = GET(b, SB, s_blocks_per_group), compat = 0, incompat = 0;
	pg_u64 count, per_block, group, block;
	pg_u8 uuid[PG_SIZE(SB, s_uuid)];
	pg_size i;

	if (GET(b, SB, s_rev_level) >= EXT4_DYNAMIC_REV) {
		compat = GET(b, SB, s_feature_compat);
		incompat = GET(b, SB, s_feature_incompat);
	}
#define BLOCKS(b) (GET(b, SB, s_blocks_count_lo) | \
		   (incompat & EXT4_FEATURE_INCOMPAT_64BIT ? \
		    GET(b, SB, s_blocks_count_hi) << 32 : 0))
	count = BLOCKS(b);
	/*
	 * The primary names group 0: a backup copy where it belongs is refused.
	 * The superblock alone fills sectors 2-3: len > 3 bounds the read of
	 * sector 3 below.
	 */
	/* sectors 2-3: the superblock */
	if (len < EXT4_SB_SECTOR + sizeof(SB) / SECTOR ||
	    log > EXT4_MAX_LOG_BLOCK_SIZE || !per_group || first > 1 ||
	    (log && first) || GET(b, SB, s_block_group_nr) != 0)
		return PG_E_PAYLOAD_EXT4;
	per_block = 2ull << log;
	if (!count || count > len / per_block)
		return PG_E_PAYLOAD_EXT4;
	/* A single block group has no backup: check the root directory. */
	if (count - first <= per_group)
		return payload_ext4_root(read, ctx, base, first, count, log,
					 incompat & EXT4_FEATURE_INCOMPAT_64BIT,
					 GET(b, SB, s_rev_level) >= EXT4_DYNAMIC_REV,
					 b);
	for (i = 0; i < sizeof(uuid); i++)
		uuid[i] = b[PG_OFF(SB, s_uuid) + i];
	group = 1;
	if (compat & EXT4_FEATURE_COMPAT_SPARSE_SUPER2) {
		/* s_backup_bgs[0], in the superblock's second sector */
		if (read(ctx, base + EXT4_SB_SECTOR + 1, b))
			return PG_E_IO;
		group = get(b, EXT4_SB_HIGH(s_backup_bgs), 4);
	}
	block = first + per_group * group;	/* < 2^64: both factors < 2^32 */
	if (!group || block >= count)
		return PG_E_PAYLOAD_EXT4;
	/* A backup sits at the start of its group's first block. */
	if (read(ctx, base + block * per_block, b))
		return PG_E_IO;
	if (GET(b, SB, s_magic) != EXT4_SUPER_MAGIC ||
	    !eq(b + PG_OFF(SB, s_uuid), uuid, sizeof(uuid)) ||
	    BLOCKS(b) != count ||
	    GET(b, SB, s_block_group_nr) != (group & 0xffff))	/* a u16 field */
		return PG_E_PAYLOAD_EXT4;
#undef BLOCKS
	return 0;
}
#undef SB

#define PVD struct iso_primary_volume_descriptor
#define ISODIR struct iso_directory_record
#define BE(b, at, T, f) be(b, (at) + PG_OFF(T, f), (unsigned int)PG_SIZE(T, f))

/* b holds the primary volume descriptor (type 1, CD001). */
static int payload_iso(pg_read_fn read, void *ctx, pg_u64 sectors, pg_u8 *b)
{
	const pg_size rd = PG_OFF(PVD, root_directory_record);
	pg_u64 size = GET(b, PVD, volume_space_size_le);
	pg_u64 bs = GET(b, PVD, logical_block_size_le);
	pg_u64 root = GET_AT(b, rd, ISODIR, extent_le);

	if (GET(b, PVD, version) != ISO_VD_VERSION ||
	    BE(b, 0, PVD, volume_space_size_be) != size ||
	    BE(b, 0, PVD, logical_block_size_be) != bs)
		return PG_E_PAYLOAD_ISO;
	if ((bs != 512 && bs != 1024 && bs != 2048) ||
	    size * (bs / SECTOR) != sectors)
		return PG_E_PAYLOAD_ISO;
	if (GET_AT(b, rd, ISODIR, length) != sizeof(ISODIR) ||
	    BE(b, rd, ISODIR, extent_be) != root ||
	    !(GET_AT(b, rd, ISODIR, file_flags) & ISO_FLAG_DIRECTORY) ||
	    !root || root >= size)
		return PG_E_PAYLOAD_ISO;
	if (read(ctx, root * (bs / SECTOR), b))
		return PG_E_IO;
	/* Its first record is ".": itself, a directory, named by one 0 byte. */
	if (GET(b, ISODIR, length) < sizeof(ISODIR) || GET(b, ISODIR, extent_le) != root ||
	    !(GET(b, ISODIR, file_flags) & ISO_FLAG_DIRECTORY) ||
	    GET(b, ISODIR, name_length) != 1 || GET(b, ISODIR, name) != 0)
		return PG_E_PAYLOAD_ISO;
	return 0;
}
#undef BE
#undef ISODIR
#undef PVD

/*
 * b holds LBA 1, which starts "EFI PART"; an LBA is k sectors. Every LBA is
 * checked against lbas (the image in LBAs) before it is scaled.
 */
static int payload_gpt(pg_read_fn read, void *ctx, pg_u64 sectors, pg_u64 k,
		       pg_u8 *b)
{
#define H struct gpt_header
#define ENT struct gpt_entry
	pg_u64 hsize = GET(b, H, header_size), alt, fu, lu, lba, count, esize, acrc;
	pg_u64 asec, blba, crc, i, first, last, len, lbas = sectors / k;
	pg_u8 guid[PG_SIZE(H, disk_guid)];
	pg_size e, j;
	unsigned int verified = 0;
	int stale = 1, err, esp, used;
	const pg_u64 per_sector = SECTOR / sizeof(ENT);	/* entries */

	if (hsize < sizeof(H) || hsize > GPT_MAX_HEADER_SIZE ||
	    GET(b, H, my_lba) != 1)
		return PG_E_PAYLOAD_GPT;
	if (header_crc(b, (pg_size)hsize) != GET(b, H, header_crc32))
		return PG_E_PAYLOAD_GPT_CRC;
	alt = GET(b, H, alternate_lba);
	fu = GET(b, H, first_usable_lba);
	lu = GET(b, H, last_usable_lba);
	for (j = 0; j < sizeof(guid); j++)
		guid[j] = b[PG_OFF(H, disk_guid) + j];
	lba = GET(b, H, partition_entry_lba);
	count = GET(b, H, number_of_partition_entries);
	esize = GET(b, H, size_of_partition_entry);
	acrc = GET(b, H, partition_entry_array_crc32);
	if (esize != sizeof(ENT) || !count || count > GPT_MAX_ENTRIES)
		return PG_E_PAYLOAD_GPT;
	/* the array, in LBAs of k sectors */
	asec = (count * sizeof(ENT) + k * SECTOR - 1) / (k * SECTOR);
	if (alt >= lbas || lu >= alt || fu > lu || lba < 2 || lba > fu ||
	    fu - lba < asec)
		return PG_E_PAYLOAD_GPT;
	err = array_crc(read, ctx, lba * k, count, b, &crc);
	if (err)
		return err;
	if (crc != acrc)
		return PG_E_PAYLOAD_GPT_CRC;
	if (read(ctx, alt * k, b))
		return PG_E_IO;
	if (!same(b, GPT_SIGNATURE, PG_SIZE(H, signature)) ||
	    GET(b, H, header_size) != hsize ||
	    header_crc(b, (pg_size)hsize) != GET(b, H, header_crc32) ||
	    GET(b, H, my_lba) != alt || GET(b, H, alternate_lba) != 1 ||
	    GET(b, H, first_usable_lba) != fu || GET(b, H, last_usable_lba) != lu ||
	    !eq(b + PG_OFF(H, disk_guid), guid, sizeof(guid)) ||
	    GET(b, H, number_of_partition_entries) != count ||
	    GET(b, H, size_of_partition_entry) != esize ||
	    GET(b, H, partition_entry_array_crc32) != acrc)
		return PG_E_PAYLOAD_GPT_BACKUP;
	blba = GET(b, H, partition_entry_lba);
	if (blba <= lu || blba >= alt || alt - blba < asec)
		return PG_E_PAYLOAD_GPT_BACKUP;
	err = array_crc(read, ctx, blba * k, count, b, &crc);
	if (err)
		return err;
	if (crc != acrc)
		return PG_E_PAYLOAD_GPT_BACKUP;
	for (i = 0; i < count; i++) {
		if (i % per_sector == 0 || stale) {
			if (read(ctx, lba * k + i / per_sector, b))
				return PG_E_IO;
			stale = 0;
		}
		e = (pg_size)(i % per_sector) * sizeof(ENT);
		for (used = 0, j = 0; j < sizeof(esp_type); j++)
			used |= b[e + PG_OFF(ENT, partition_type_guid) + j];
		if (!used)
			continue;
		esp = eq(b + e + PG_OFF(ENT, partition_type_guid), esp_type,
			 sizeof(esp_type));
		first = GET_AT(b, e, ENT, starting_lba);
		last = GET_AT(b, e, ENT, ending_lba);
		if (first < fu || last > lu || first > last)
			return PG_E_PAYLOAD_GPT;
		/* In sectors from here on: last < alt < lbas, no overflow. */
		len = (last - first + 1) * k;
		first *= k;
		stale = 1;
		if (esp) {
			if (read(ctx, first, b))
				return PG_E_IO;
			if (!is_fat(b, len))
				return PG_E_PAYLOAD_NOT_FAT;
			verified++;
		} else if (len > EXT4_SB_SECTOR) {
			if (read(ctx, first + EXT4_SB_SECTOR, b))
				return PG_E_IO;
			if (GET(b, struct ext4_super_block, s_magic) ==
			    EXT4_SUPER_MAGIC) {
#ifdef PG_CBMC_STUB_EXT4
				/* Model checking: proved on its own (cbmc/payload.c). */
				err = pg_cbmc_payload_ext4(read, ctx, first, len, b);
#else
				err = payload_ext4(read, ctx, first, len, b);
#endif
				if (err)
					return err;
				verified++;
			}
		}
	}
	return verified ? 0 : PG_E_PAYLOAD_NO_KNOWN_PARTITION;
#undef ENT
#undef H
}

int pg_payload_check(pg_read_fn read, void *ctx, pg_u64 sectors,
		     unsigned int lbs, pg_u8 *b)
{
	pg_u64 k = lbs / 512;

	if ((lbs != 512 && lbs != 4096) || sectors < 2)
		return PG_E_PAYLOAD_UNKNOWN;
	if (sectors > k) {
		if (read(ctx, k, b))
			return PG_E_IO;
		if (same(b, GPT_SIGNATURE, PG_SIZE(struct gpt_header, signature)))
			return payload_gpt(read, ctx, sectors, k, b);
	}
	if (sectors > EXT4_SB_SECTOR) {
		if (read(ctx, EXT4_SB_SECTOR, b))
			return PG_E_IO;
		if (GET(b, struct ext4_super_block, s_magic) == EXT4_SUPER_MAGIC)
			return payload_ext4(read, ctx, 0, sectors, b);
	}
	if (sectors > ISO_PVD) {
		if (read(ctx, ISO_PVD, b))
			return PG_E_IO;
		if (GET(b, struct iso_primary_volume_descriptor, type) ==
		    ISO_VD_PRIMARY &&
		    same(b + PG_OFF(struct iso_primary_volume_descriptor, id),
			 ISO_STANDARD_ID,
			 PG_SIZE(struct iso_primary_volume_descriptor, id)))
			return payload_iso(read, ctx, sectors, b);
	}
	return PG_E_PAYLOAD_UNKNOWN;
}
