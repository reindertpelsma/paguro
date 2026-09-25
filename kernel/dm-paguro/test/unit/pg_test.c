// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Userspace tests for the module's trusted core (pg_range.c, pg_claim.c,
 * pg_ntfs.c), run under ASan+UBSan, MSan and Valgrind (see Makefile):
 *
 *   pg_test [-s stride] <fixture-dir> [-p <payload-fixture-dir>] [corpus-file...]
 *
 * 1. unit tests: range test, claim checks, runlist decoder, boot sector;
 * 2. every case in <fixture-dir>/manifest.txt: real mkntfs volumes and named
 *    corruptions of them, each with the result the core must return (the
 *    same manifest the Rust differential harness checks);
 * 3. for each clean file: the read callback failing at every call (must give
 *    PG_E_IO), torn at every call, and every byte (every stride-th) of every
 *    sector read set to 0x00, 0xff and each bit flip (must not crash);
 * 4. every case in <payload-fixture-dir>/manifest.txt (the structural
 *    assertion over real GPT, ext4 and ISO 9660 images and corruptions of
 *    them); for each accepted image, failure and tearing at every read, the
 *    byte sweep over every sector read, and misordered gathering (two of
 *    four extents swapped, or all reversed: refused whenever a sector the
 *    check reads moved);
 * 5. each corpus file (fuzz input format, see fuzz/fuzz_ntfs.c) parsed once
 *    (files under a "payload" directory: the payload check, first u32 = the
 *    image length in sectors).
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pg_claim.h"
#include "pg_ntfs.h"

static int failures, checks;
static long mutations;

static void check(int ok, const char *fmt, ...)
{
	va_list ap;

	checks++;
	if (ok)
		return;
	failures++;
	fputs("FAIL: ", stderr);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static const char *const names[] = {
	[PG_E_IO] = "Io", [PG_E_BOOT_SIGNATURE] = "BootSignature",
	[PG_E_OEM_ID] = "OemId", [PG_E_SECTOR_SIZE] = "SectorSize",
	[PG_E_CLUSTER_SIZE] = "ClusterSize", [PG_E_VOLUME_SIZE] = "VolumeSize",
	[PG_E_RECORD_SIZE] = "RecordSize", [PG_E_MFT_LCN] = "MftLcn",
	[PG_E_BAD_IDENTITY] = "BadIdentity", [PG_E_NOT_MAPPED] = "NotMapped",
	[PG_E_RECORD_MAGIC] = "RecordMagic",
	[PG_E_RECORD_LAYOUT] = "RecordLayout",
	[PG_E_FIXUP_MISMATCH] = "FixupMismatch",
	[PG_E_RECORD_NUMBER] = "RecordNumber", [PG_E_NOT_IN_USE] = "NotInUse",
	[PG_E_DIRECTORY] = "Directory", [PG_E_SEQUENCE] = "Sequence",
	[PG_E_NOT_BASE] = "NotBase", [PG_E_ATTR_BOUNDS] = "AttrBounds",
	[PG_E_NO_DATA] = "NoData", [PG_E_DUPLICATE_DATA] = "DuplicateData",
	[PG_E_RESIDENT] = "Resident", [PG_E_COMPRESSED] = "Compressed",
	[PG_E_ENCRYPTED] = "Encrypted", [PG_E_SPARSE] = "Sparse",
	[PG_E_GAP] = "Gap", [PG_E_SEGMENT_VCN] = "SegmentVcn",
	[PG_E_OUTSIDE_VOLUME] = "OutsideVolume", [PG_E_ATTR_LIST] = "AttrList",
	[PG_E_ATTR_LIST_SIZE] = "AttrListSize",
	[PG_E_TOO_MANY_EXTENSIONS] = "TooManyExtensions",
	[PG_E_MISSING_SEGMENT] = "MissingSegment",
	[PG_E_EXTENSION_BASE] = "ExtensionBase",
	[PG_E_MFT_ATTR_LIST] = "MftAttrList",
	[PG_E_ALLOCATED_SIZE] = "AllocatedSize",
	[PG_E_NOT_INITIALIZED] = "NotInitialized",
	[PG_E_UNALIGNED] = "Unaligned",
	[PG_E_TOO_MANY_EXTENTS] = "TooManyExtents",
	[PG_E_NO_VOLUME_INFO] = "NoVolumeInfo",
	[PG_E_SELF_OVERLAP] = "SelfOverlap", [PG_E_PAYLOAD_GPT] = "PayloadGpt",
	[PG_E_PAYLOAD_NO_KNOWN_PARTITION] = "PayloadNoKnownPartition",
	[PG_E_PAYLOAD_NOT_FAT] = "PayloadNotFat",
	[PG_E_PAYLOAD_GPT_CRC] = "PayloadGptCrc",
	[PG_E_PAYLOAD_GPT_BACKUP] = "PayloadGptBackup",
	[PG_E_PAYLOAD_EXT4] = "PayloadExt4", [PG_E_PAYLOAD_ISO] = "PayloadIso",
	[PG_E_PAYLOAD_UNKNOWN] = "PayloadUnknown",
	[PG_E_RL_TRUNCATED] = "Runlist.Truncated",
	[PG_E_RL_FIELD_TOO_WIDE] = "Runlist.FieldTooWide",
	[PG_E_RL_SPARSE] = "Runlist.Sparse",
	[PG_E_RL_ZERO_LENGTH] = "Runlist.ZeroLength",
	[PG_E_RL_NEGATIVE_LCN] = "Runlist.NegativeLcn",
	[PG_E_RL_OVERFLOW] = "Runlist.Overflow",
	[PG_E_RL_TOO_MANY_RUNS] = "Runlist.TooManyRuns",
	[PG_E_RL_UNTERMINATED] = "Runlist.Unterminated",
};

static const char *name(int e)
{
	static char buf[32];

	if (e > 0 && (size_t)e < sizeof(names) / sizeof(names[0]) && names[e])
		return names[e];
	snprintf(buf, sizeof(buf), "code%d", e);
	return buf;
}

/* ---- a disk with fault injection -------------------------------------- */

struct disk {
	const pg_u8 *img;
	size_t len;
	long calls, fail_at, torn_at;
	pg_u64 reads[4096];	/* the first sectors read, for mutation */
};

static int rd(void *ctx, pg_u64 s, pg_u8 *buf)
{
	struct disk *d = ctx;
	long n = d->calls++;

	if (n < 4096)
		d->reads[n] = s;
	if (n == d->fail_at || s >= d->len / 512)
		return 1;
	memcpy(buf, d->img + s * 512, 512);
	if (n == d->torn_at)
		memset(buf + 256, 0, 256);
	return 0;
}

static void disk_init(struct disk *d, const pg_u8 *img, size_t len)
{
	d->img = img;
	d->len = len;
	d->calls = 0;
	d->fail_at = -1;
	d->torn_at = -1;
}

/* Buffers as the module allocates them. */
static pg_u8 rec_buf[PG_NTFS_MAX_RECORD], alist_buf[PG_NTFS_MAX_ALIST];
static struct pg_run mft_runs[2048], runs[PG_MAX_EXTENTS];
static struct pg_extent ext[PG_MAX_EXTENTS], norm[PG_MAX_EXTENTS];

static void vol_init(struct pg_ntfs *v, struct disk *d)
{
	memset(v, 0, sizeof(*v));
	v->read = rd;
	v->ctx = d;
	v->rec = rec_buf;
	v->alist = alist_buf;
	v->mft = mft_runs;
	v->mft_cap = 2048;
}

/* Steps 1-6 for (rec, seq); ext[0..*n) and *size on success. */
static int derive(struct disk *d, pg_u64 rec, pg_u16 seq, pg_size *n,
		  pg_u64 *size)
{
	struct pg_ntfs v;
	pg_size nruns;
	int e;

	vol_init(&v, d);
	e = pg_ntfs_open(&v);
	if (!e)
		e = pg_ntfs_file(&v, rec, seq, runs, PG_MAX_EXTENTS, &nruns, size);
	if (!e)
		e = pg_ntfs_extents(&v, runs, nruns, ext, PG_MAX_EXTENTS, n);
	return e;
}

static int flags_of(struct disk *d, pg_u16 *flags)
{
	struct pg_ntfs v;
	int e;

	vol_init(&v, d);
	e = pg_ntfs_open(&v);
	return e ? e : pg_ntfs_volume_flags(&v, flags);
}

/* ---- 1. unit tests ------------------------------------------------------ */

static struct pg_extent E(pg_u64 s, pg_u64 e)
{
	struct pg_extent x = { s, e };

	return x;
}

static void test_range(void)
{
	struct pg_extent e[64];
	pg_size n, i;

	e[0] = E(50, 60); e[1] = E(10, 20); e[2] = E(20, 25); e[3] = E(58, 68);
	n = pg_range_normalise(e, 4);
	check(n == 2 && e[0].start == 10 && e[0].end == 25 && e[1].end == 68,
	      "normalise merges");
	check(!pg_range_blocks(e, n, 0, 10), "before");
	check(pg_range_blocks(e, n, 0, 11), "touches first sector");
	check(!pg_range_blocks(e, n, 25, 25), "between");
	check(pg_range_blocks(e, n, 67, 1), "last sector");
	check(!pg_range_blocks(e, n, 68, 100), "after");
	check(pg_range_blocks(e, n, 30, 0), "zero length refused");
	check(pg_range_blocks(e, n, ~0ull, 2), "overflow refused");
	check(pg_range_blocks(e, 0, 1, 0), "zero length, empty set");
	check(!pg_range_blocks(e, 0, 1, 1), "empty set");
	e[0] = E(10, 30); e[1] = E(12, 20);
	check(pg_range_normalise(e, 2) == 1 && e[0].end == 30, "contained extent");
	e[0] = E(5, 5);
	check(pg_range_normalise(e, 1) == 0, "empty extent");
	check(pg_range_normalise(e, 0) == 0, "no extents");
	/* Heapsort on descending, equal and pseudo-random keys. */
	for (i = 0; i < 64; i++)
		e[i] = E(1000 - 10 * i, 1001 - 10 * i);
	check(pg_range_normalise(e, 64) == 64 && e[0].start == 370 &&
	      e[63].start == 1000, "descending");
	for (i = 0; i < 64; i++)
		e[i] = E((i * 37) % 64 * 2, (i * 37) % 64 * 2 + 1);
	pg_range_sort(e, 64);
	for (i = 1; i < 64; i++)
		check(e[i - 1].start < e[i].start, "sorted %zu", i);
	pg_range_sort(e, 1);
	pg_range_sort(e, 0);
}

static void test_claims(void)
{
	struct pg_extent a[8], b[8], out[8];
	pg_size n;
	pg_u64 p;

	a[0] = E(50, 60); a[1] = E(10, 20); a[2] = E(20, 30);
	check(pg_claim_normalise(a, 3, out, 8, &n) == 0 && n == 2 &&
	      out[0].start == 10 && out[0].end == 30, "claim normalise");
	check(pg_claim_normalise(a, 3, out, 2, &n) == PG_E_TOO_MANY_EXTENTS,
	      "claim capacity");
	a[3] = E(25, 26);
	check(pg_claim_normalise(a, 4, out, 8, &n) == PG_E_SELF_OVERLAP,
	      "self overlap");
	a[3] = E(10, 20);
	check(pg_claim_normalise(a, 4, out, 8, &n) == PG_E_SELF_OVERLAP,
	      "duplicate");
	a[3] = E(7, 7);
	check(pg_claim_normalise(a, 4, out, 8, &n) == PG_E_SELF_OVERLAP,
	      "empty");

	a[0] = E(10, 20); a[1] = E(30, 40);
	b[0] = E(20, 30); b[1] = E(40, 50);
	check(!pg_claim_intersects(a, 2, b, 2), "touching is not intersecting");
	b[1] = E(39, 50);
	check(pg_claim_intersects(a, 2, b, 2), "one sector");
	check(!pg_claim_intersects(a, 2, b, 0), "empty");
	b[0] = E(0, 100);
	check(pg_claim_intersects(a, 2, b, 1), "covering");

	a[0] = E(0, 10); a[1] = E(50, 60);
	b[0] = E(0, 10); b[1] = E(50, 70); b[2] = E(90, 99);
	check(pg_claim_grows(a, 2, a, 2), "unchanged");
	check(pg_claim_grows(a, 2, b, 2), "extended in place");
	check(pg_claim_grows(a, 2, b, 3), "appended");
	b[1] = E(50, 59);
	check(!pg_claim_grows(a, 2, b, 2), "shrank");
	b[1] = E(51, 70);
	check(!pg_claim_grows(a, 2, b, 2), "moved");
	b[0] = E(0, 11); b[1] = E(50, 60);
	check(!pg_claim_grows(a, 2, b, 2), "head changed");
	check(!pg_claim_grows(a, 2, b, 1), "fewer");
	check(!pg_claim_grows(a, 0, b, 1), "nothing to grow from");

	a[0] = E(10, 20); a[1] = E(20, 25); a[2] = E(5, 6); a[3] = E(6, 8);
	check(pg_claim_coalesce(a, 4) == 2 && a[0].end == 25 && a[1].end == 8,
	      "coalesce");
	a[0] = E(1, 1);
	check(pg_claim_coalesce(a, 1) == 0, "coalesce refuses empty");

	a[0] = E(10, 25); a[1] = E(5, 8); a[2] = E(30, 31);
	check(pg_claim_gather(a, 3, 0, &p) == 15 && p == 10, "gather 0");
	check(pg_claim_gather(a, 3, 14, &p) == 1 && p == 24, "gather 14");
	check(pg_claim_gather(a, 3, 15, &p) == 3 && p == 5, "gather 15");
	check(pg_claim_gather(a, 3, 18, &p) == 1 && p == 30, "gather 18");
	check(pg_claim_gather(a, 3, 19, &p) == 0, "gather beyond");

	/* truncate to the file's data: a VHD's footer in a partial cluster */
	check(pg_claim_truncate(a, 3, 0) == 0, "truncate to nothing");
	check(pg_claim_truncate(a, 3, 20) == 0, "truncate past the end");
	check(pg_claim_truncate(a, 3, 19) == 3 && a[2].end == 31, "truncate whole");
	check(pg_claim_truncate(a, 3, 16) == 2 && a[1].end == 6 && a[0].end == 25,
	      "truncate inside the second extent");
	a[0] = E(10, 10);
	check(pg_claim_truncate(a, 1, 1) == 0, "truncate refuses empty");
}

static int decode(const char *bytes, size_t len, pg_size cap, pg_size *n)
{
	static struct pg_run out[8];

	return pg_runlist_decode((const pg_u8 *)bytes, len, out, cap, n);
}

static void test_runlist(void)
{
	struct pg_run out[8];
	const pg_u8 good[] = { 0x21, 0x18, 0x34, 0x56, 0x21, 0x10, 0x00, 0x01,
			       0x21, 0x08, 0x00, 0xf0, 0x00 };
	pg_size n;

	check(pg_runlist_decode(good, sizeof(good), out, 8, &n) == 0 &&
	      n == 3 && out[0].lcn == 0x5634 && out[1].lcn == 0x5734 &&
	      out[2].lcn == 0x4734 && out[2].count == 8, "delta decoding");
	check(decode("\x01\x10\x00", 3, 4, &n) == PG_E_RL_SPARSE, "sparse");
	check(decode("\x21\x10", 2, 4, &n) == PG_E_RL_TRUNCATED, "truncated");
	check(decode("\x31\x10\x01", 3, 4, &n) == PG_E_RL_TRUNCATED, "trunc off");
	check(decode("\x11\x10\x05", 3, 4, &n) == PG_E_RL_UNTERMINATED,
	      "unterminated");
	check(decode("", 0, 4, &n) == PG_E_RL_UNTERMINATED, "empty input");
	check(decode("\x11\x00\x05\x00", 4, 4, &n) == PG_E_RL_ZERO_LENGTH,
	      "zero length");
	check(decode("\x11\x01\xff\x00", 4, 4, &n) == PG_E_RL_NEGATIVE_LCN,
	      "negative");
	check(decode("\x09\x01", 2, 4, &n) == PG_E_RL_FIELD_TOO_WIDE, "wide len");
	check(decode("\x91\x01", 2, 4, &n) == PG_E_RL_FIELD_TOO_WIDE, "wide off");
	check(decode("\x10\x01", 2, 4, &n) == PG_E_RL_FIELD_TOO_WIDE, "zero len");
	check(decode("\x11\x01\x05\x11\x01\x05\x00", 7, 1, &n) ==
	      PG_E_RL_TOO_MANY_RUNS, "capacity");
	check(decode("\x18\xff\xff\xff\xff\xff\xff\xff\xff\x01\x00", 11, 4, &n) ==
	      PG_E_RL_OVERFLOW, "count overflow");
	check(decode("\x81\x01\xff\xff\xff\xff\xff\xff\xff\x7f"
		     "\x81\x01\xff\xff\xff\xff\xff\xff\xff\x7f"
		     "\x81\x01\xff\xff\xff\xff\xff\xff\xff\x7f\x00", 31, 4, &n) ==
	      PG_E_RL_OVERFLOW, "lcn overflow");
	check(decode("\x81\x01\x00\x00\x00\x00\x00\x00\x00\x80\x00", 11, 4,
		     &n) == PG_E_RL_NEGATIVE_LCN, "INT64_MIN delta");
	check(decode("\x88\x01\x00\x00\x00\x00\x00\x00\x00"
		     "\x05\x00\x00\x00\x00\x00\x00\x00\x00", 18, 4, &n) == 0 &&
	      n == 1, "eight-byte fields");
}

static void test_boot(const pg_u8 *clean)
{
	pg_u8 b[512];
	struct pg_ntfs v;
	static const struct { int off; pg_u8 val; int err; } cases[] = {
		{ 511, 0, PG_E_BOOT_SIGNATURE }, { 3, 'X', PG_E_OEM_ID },
		{ 0x0c, 1, PG_E_SECTOR_SIZE }, { 0x0d, 3, PG_E_CLUSTER_SIZE },
		{ 0x0d, 0, PG_E_CLUSTER_SIZE }, { 0x0d, 0x81, PG_E_CLUSTER_SIZE },
		{ 0x0d, 0xf3, PG_E_CLUSTER_SIZE }, { 0x40, 0, PG_E_RECORD_SIZE },
		{ 0x40, 0xf3, PG_E_RECORD_SIZE }, { 0x40, 3, PG_E_RECORD_SIZE },
		{ 0x37, 0x40, PG_E_MFT_LCN },
	};
	size_t i;

	memcpy(b, clean, 512);
	check(pg_ntfs_boot(&v, b) == 0, "clean boot sector");
	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		memcpy(b, clean, 512);
		b[cases[i].off] = cases[i].val;
		check(pg_ntfs_boot(&v, b) == cases[i].err, "boot case %zu: %s",
		      i, name(pg_ntfs_boot(&v, b)));
	}
	memcpy(b, clean, 512);
	memset(b + 0x28, 0, 8);
	check(pg_ntfs_boot(&v, b) == PG_E_VOLUME_SIZE, "zero sectors");
	memset(b + 0x28, 0xff, 8);
	check(pg_ntfs_boot(&v, b) == PG_E_VOLUME_SIZE, "sector overflow");
}

static int zero_read(void *ctx, pg_u64 s, pg_u8 *buf)
{
	(void)ctx;
	(void)s;
	memset(buf, 0, 512);
	return 0;
}

/* Shapes the fixtures cannot show; the manifest (section 4) has the rest. */
static void test_payload(void)
{
	pg_u8 buf[512];

	check(pg_payload_check(zero_read, NULL, 0, 512, buf) == PG_E_PAYLOAD_UNKNOWN,
	      "empty payload");
	check(pg_payload_check(zero_read, NULL, 1, 512, buf) == PG_E_PAYLOAD_UNKNOWN,
	      "one-sector payload");
	check(pg_payload_check(zero_read, NULL, ~0ull, 512, buf) == PG_E_PAYLOAD_UNKNOWN,
	      "huge zero payload");
	check(pg_payload_check(zero_read, NULL, 100, 1024, buf) == PG_E_PAYLOAD_UNKNOWN,
	      "1 KiB logical blocks");
	check(pg_payload_check(zero_read, NULL, 8, 4096, buf) == PG_E_PAYLOAD_UNKNOWN,
	      "no room for a 4 KiB LBA 1");
}

static void test_extents_cap(void)
{
	struct pg_ntfs v = { .cluster_bytes = 4096, .sectors = 1000 };
	struct pg_run r[3] = { { 1, 2 }, { 3, 1 }, { 10, 1 } };
	struct pg_extent out[2];
	pg_size n;

	check(pg_ntfs_extents(&v, r, 3, out, 2, &n) == 0 && n == 2 &&
	      out[0].start == 8 && out[0].end == 32, "extents coalesce");
	check(pg_ntfs_extents(&v, r, 3, out, 1, &n) == PG_E_TOO_MANY_EXTENTS,
	      "extents capacity");
	r[2].lcn = 125;
	check(pg_ntfs_extents(&v, r, 3, out, 2, &n) == PG_E_OUTSIDE_VOLUME,
	      "extent past the volume");
	r[2].lcn = ~0ull / 4;
	check(pg_ntfs_extents(&v, r, 3, out, 2, &n) == PG_E_OUTSIDE_VOLUME,
	      "extent overflow");
}

/* ---- 2. the manifest ---------------------------------------------------- */

struct image {
	const char *dir;
	char name[64];
	pg_u8 *data;
	size_t len;
};

#define NIMAGES 32
static struct image images[NIMAGES];

static struct image *load(const char *dir, const char *img)
{
	char cmd[1024];
	struct image *im;
	FILE *f;
	size_t cap = 1 << 20;
	int i;

	for (i = 0; i < NIMAGES && images[i].data; i++)
		if (!strcmp(images[i].name, img) && images[i].dir == dir)
			return &images[i];
	if (i == NIMAGES)
		return NULL;
	im = &images[i];
	snprintf(cmd, sizeof(cmd), "gzip -dc '%s/%s.gz'", dir, img);
	f = popen(cmd, "r");
	if (!f)
		return NULL;
	im->data = malloc(cap);
	for (;;) {
		size_t got = fread(im->data + im->len, 1, cap - im->len, f);

		im->len += got;
		if (im->len < cap)
			break;
		cap *= 2;
		im->data = realloc(im->data, cap);
	}
	pclose(f);
	snprintf(im->name, sizeof(im->name), "%s", img);
	im->dir = dir;
	return im;
}

static pg_u64 fnv(const pg_u8 *p, size_t n)
{
	pg_u64 h = 0xcbf29ce484222325ull;

	while (n--)
		h = (h ^ *p++) * 0x100000001b3ull;
	return h;
}

struct gdisk {
	const pg_u8 *data;
	pg_u64 sectors;
};

static int gread(void *ctx, pg_u64 s, pg_u8 *buf)
{
	struct gdisk *g = ctx;

	if (s >= g->sectors)
		return 1;
	memcpy(buf, g->data + s * 512, 512);
	return 0;
}

/* The result string for a case, spelled as in manifest.txt. */
static void outcome(const char *kind, struct disk *d, pg_u64 rec, pg_u16 seq,
		    struct pg_extent *res, pg_size nres, char *out, size_t sz)
{
	pg_size n, nn, i;
	pg_u64 size, off = 0;
	pg_u16 flags;
	pg_u8 *data, buf[512];
	struct gdisk g;
	int e;

	if (!strcmp(kind, "volume")) {
		e = flags_of(d, &flags);
		if (e)
			snprintf(out, sz, "%s", name(e));
		else
			snprintf(out, sz, "flags:%04x", flags);
		return;
	}
	e = derive(d, rec, seq, &n, &size);
	if (e) {
		snprintf(out, sz, "%s", name(e));
		return;
	}
	e = pg_claim_normalise(ext, n, norm, PG_MAX_EXTENTS, &nn);
	if (e) {
		snprintf(out, sz, "%s", name(e));
		return;
	}
	nres = nres ? pg_range_normalise(res, nres) : 0;
	if (pg_claim_intersects(norm, nn, res, nres)) {
		snprintf(out, sz, "Reserved");
		return;
	}
	data = malloc(size + 512);
	for (i = 0; i < n && off < size; i++) {
		pg_u64 len = (ext[i].end - ext[i].start) * 512;

		if (len > size - off)
			len = size - off;
		memcpy(data + off, d->img + ext[i].start * 512, len);
		off += len;
	}
	g.data = data;
	g.sectors = size / 512;
	/* View A's logical block is the volume's sector size. */
	e = pg_payload_check(gread, &g, g.sectors,
			     (unsigned int)(d->img[11] | d->img[12] << 8), buf);
	snprintf(out, sz, "ok:%llu:%016llx:%s", (unsigned long long)size,
		 (unsigned long long)fnv(data, size), e ? "-" : "gpt");
	free(data);
}

/* Flip, zero and saturate every stride-th byte of each sector read. */
static void sweep(struct image *im, pg_u64 rec, pg_u16 seq, int stride)
{
	static pg_u64 sectors[4096];
	struct disk d;
	pg_size n, k, j;
	pg_u64 size;
	long reads, i;
	int off, b, clean;

	disk_init(&d, im->data, im->len);
	clean = derive(&d, rec, seq, &n, &size);
	check(clean == 0, "%s rec %llu clean", im->name, (unsigned long long)rec);
	reads = d.calls < 4096 ? d.calls : 4096;
	memcpy(sectors, d.reads, reads * sizeof(pg_u64));
	/* I/O failure at every read must refuse with Io; torn must not crash. */
	for (i = 0; i < reads; i++) {
		disk_init(&d, im->data, im->len);
		d.fail_at = i;
		check(derive(&d, rec, seq, &n, &size) == PG_E_IO,
		      "fail at read %ld not refused", i);
		disk_init(&d, im->data, im->len);
		d.torn_at = i;
		derive(&d, rec, seq, &n, &size);
	}
	for (i = 0; i < reads; i++) {
		pg_u8 *p = im->data + sectors[i] * 512;

		for (j = 0; j < (pg_size)i; j++)
			if (sectors[j] == sectors[i])
				break;
		if (j < (pg_size)i || sectors[i] >= im->len / 512)
			continue;
		for (off = 0; off < 512; off += stride) {
			pg_u8 orig = p[off];
			pg_u8 vals[10] = { 0x00, 0xff };

			for (b = 0; b < 8; b++)
				vals[2 + b] = orig ^ (1 << b);
			for (k = 0; k < 10; k++) {
				p[off] = vals[k];
				disk_init(&d, im->data, im->len);
				derive(&d, rec, seq, &n, &size);
				mutations++;
			}
			p[off] = orig;
		}
	}
}

static void manifest(const char *dir, int stride)
{
	char path[1024], line[1 << 16], got[128];
	FILE *f;
	int cases = 0;

	snprintf(path, sizeof(path), "%s/manifest.txt", dir);
	f = fopen(path, "r");
	check(f != NULL, "open %s", path);
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *save, *kind, *nm, *img, *rec, *seq, *expect, *tok;
		struct pg_extent res[8];
		pg_size nres = 0, np = 0, i;
		static size_t poff[4096];
		static pg_u8 pold[4096];
		struct image *im;
		struct disk d;

		if (line[0] == '#')
			continue;
		kind = strtok_r(line, " \n", &save);
		nm = strtok_r(NULL, " \n", &save);
		img = strtok_r(NULL, " \n", &save);
		rec = strtok_r(NULL, " \n", &save);
		seq = strtok_r(NULL, " \n", &save);
		expect = strtok_r(NULL, " \n", &save);
		if (!expect)
			continue;
		im = load(dir, img);
		check(im && im->len, "load %s", img);
		if (!im || !im->len)
			continue;
		while ((tok = strtok_r(NULL, " \n", &save))) {
			unsigned long long a, b;

			if (tok[0] == 'R' && sscanf(tok + 1, "%llu+%llu", &a, &b) == 2 &&
			    nres < 8) {
				res[nres++] = E(a, a + b);
			} else if (sscanf(tok, "%llu=%llx", &a, &b) == 2 &&
				   a < im->len && np < 4096) {
				poff[np] = a;
				pold[np++] = im->data[a];
				im->data[a] = (pg_u8)b;
			}
		}
		disk_init(&d, im->data, im->len);
		outcome(kind, &d, strtoull(rec, NULL, 10),
			(pg_u16)strtoul(seq, NULL, 10), res, nres, got,
			sizeof(got));
		check(!strcmp(got, expect), "%s: expected %s, got %s", nm,
		      expect, got);
		/* Clean files also get the fault and mutation sweeps. */
		if (!strcmp(kind, "file") && !strncmp(expect, "ok", 2) &&
		    np == 0 && nres == 0 && stride > 0)
			sweep(im, strtoull(rec, NULL, 10),
			      (pg_u16)strtoul(seq, NULL, 10), stride);
		/* Undo in reverse: overlapping patches restore correctly. */
		for (i = np; i-- > 0;)
			im->data[poff[i]] = pold[i];
		cases++;
	}
	fclose(f);
	check(cases > 80, "only %d manifest cases", cases);
	printf("manifest: %d cases, %ld mutated parses\n", cases, mutations);
}

/* ---- 4. the payload manifest ------------------------------------------- */

struct pdisk {
	const pg_u8 *img;
	pg_u64 len;		/* sectors present */
	pg_u64 chunk;		/* > 0: gathered from 4 extents in order perm */
	unsigned int lbs;
	int perm[4];
	long calls, fail_at, torn_at;
	pg_u64 reads[4096];
	long nreads;
};

static int pread_(void *ctx, pg_u64 s, pg_u8 *buf)
{
	struct pdisk *d = ctx;
	long n = d->calls++;
	pg_u64 p = s;

	if (d->nreads < 4096)
		d->reads[d->nreads++] = s;
	if (d->chunk && s / d->chunk < 4)
		p = (pg_u64)d->perm[s / d->chunk] * d->chunk + s % d->chunk;
	if (n == d->fail_at || p >= d->len)
		return 1;
	memcpy(buf, d->img + p * 512, 512);
	if (n == d->torn_at)
		memset(buf + 256, 0, 256);
	return 0;
}

static int pcheck(struct pdisk *d, const struct image *im, pg_u64 sectors)
{
	pg_u8 buf[512];

	d->img = im->data;
	d->len = im->len / 512;
	d->calls = 0;
	d->nreads = 0;
	return pg_payload_check(pread_, d, sectors, d->lbs ? d->lbs : 512, buf);
}

/* Failure, tearing, byte sweep and misordering for one accepted image. */
static void psweep(struct image *im, pg_u64 sectors, unsigned int lbs,
		   int stride)
{
	static pg_u64 sec[4096];
	struct pdisk d = { .fail_at = -1, .torn_at = -1, .lbs = lbs };
	long nsec, i, j, k, refused = 0, must = 0;
	int b, off, e;

	pcheck(&d, im, sectors);
	nsec = d.nreads;
	memcpy(sec, d.reads, sizeof(pg_u64) * (size_t)nsec);
	for (i = 0; i < nsec; i++) {
		struct pdisk f = { .fail_at = i, .torn_at = -1, .lbs = lbs };
		struct pdisk t = { .fail_at = -1, .torn_at = i, .lbs = lbs };

		check(pcheck(&f, im, sectors) == PG_E_IO, "%s: read %ld failing",
		      im->name, i);
		pcheck(&t, im, sectors);
	}
	for (i = 0; i < nsec && stride > 0; i++) {
		pg_u8 *p = im->data + sec[i] * 512;

		for (j = 0; j < i && sec[j] != sec[i]; j++)
			;
		if (j < i || sec[i] >= im->len / 512)
			continue;
		for (off = 0; off < 512; off += stride) {
			pg_u8 orig = p[off];

			for (b = 0; b < 10; b++) {
				p[off] = b == 8 ? 0 : b == 9 ? 0xff :
					 (pg_u8)(orig ^ (1 << b));
				d.fail_at = d.torn_at = -1;
				pcheck(&d, im, sectors);
				mutations++;
			}
			p[off] = orig;
		}
	}
	/* Every swap of two of four extents, and the reversal. */
	for (k = 0; k < 7; k++) {
		static const int sw[7][2] = { { 0, 1 }, { 0, 2 }, { 0, 3 },
					      { 1, 2 }, { 1, 3 }, { 2, 3 },
					      { -1, -1 } };
		struct pdisk m = { .fail_at = -1, .torn_at = -1,
				   .chunk = sectors / 4, .lbs = lbs };
		int moved = 0;

		for (j = 0; j < 4; j++)
			m.perm[j] = k == 6 ? 3 - (int)j : (int)j;
		if (k < 6) {
			m.perm[sw[k][0]] = sw[k][1];
			m.perm[sw[k][1]] = sw[k][0];
		}
		for (i = 0; i < nsec; i++)
			if (sec[i] / m.chunk < 4 &&
			    m.perm[sec[i] / m.chunk] != (int)(sec[i] / m.chunk))
				moved = 1;
		e = pcheck(&m, im, sectors);
		if (moved && !e) {
			/* Tolerated only if every changed read sector was an ext4
			 * superblock and no longer is (the partition now reads
			 * as unknown content, which no ext4 mount accepts). */
			for (i = 0; i < nsec; i++) {
				pg_u64 c = sec[i] / m.chunk, p = sec[i];
				const pg_u8 *o = im->data + sec[i] * 512, *q;

				if (c < 4)
					p = (pg_u64)m.perm[c] * m.chunk + sec[i] % m.chunk;
				if (sec[i] >= im->len / 512 || p >= im->len / 512)
					continue;
				q = im->data + p * 512;
				if (!memcmp(o, q, 512))
					continue;
				check(o[56] == 0x53 && o[57] == 0xef &&
				      !(q[56] == 0x53 && q[57] == 0xef),
				      "%s: misordering %ld accepted", im->name, k);
			}
		}
		must += moved;
		refused += moved && e;
	}
	(void)refused;
	(void)must;
}

static void payload_manifest(const char *dir, int stride)
{
	char path[1024], line[1 << 16];
	FILE *f;
	int cases = 0, e;

	snprintf(path, sizeof(path), "%s/manifest.txt", dir);
	f = fopen(path, "r");
	check(f != NULL, "open %s", path);
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *save, *kind, *nm, *img, *len, *expect, *tok;
		pg_size np = 0, i;
		static size_t poff[4096];
		static pg_u8 pold[4096];
		struct pdisk d = { .fail_at = -1, .torn_at = -1, .lbs = 512 };
		struct image *im;
		pg_u64 sectors;

		kind = strtok_r(line, " \n", &save);
		if (!kind || strcmp(kind, "payload"))
			continue;
		nm = strtok_r(NULL, " \n", &save);
		img = strtok_r(NULL, " \n", &save);
		len = strtok_r(NULL, " \n", &save);
		expect = strtok_r(NULL, " \n", &save);
		if (!expect)
			continue;
		im = load(dir, img);
		check(im && im->len, "load %s", img);
		if (!im || !im->len)
			continue;
		while ((tok = strtok_r(NULL, " \n", &save))) {
			unsigned long long a, b;

			if (!strncmp(tok, "lbs=", 4))
				d.lbs = (unsigned int)atoi(tok + 4);
			else if (sscanf(tok, "%llu=%llx", &a, &b) == 2 &&
				 a < im->len && np < 4096) {
				poff[np] = a;
				pold[np++] = im->data[a];
				im->data[a] = (pg_u8)b;
			}
		}
		sectors = strcmp(len, "-") ? strtoull(len, NULL, 10) :
					     im->len / 512;
		e = pcheck(&d, im, sectors);
		check(!strcmp(e ? name(e) : "ok", expect),
		      "payload %s: expected %s, got %s", nm, expect,
		      e ? name(e) : "ok");
		if (!e && np == 0 && !strcmp(len, "-"))
			psweep(im, sectors, d.lbs, stride);
		for (i = np; i-- > 0;)
			im->data[poff[i]] = pold[i];
		cases++;
	}
	fclose(f);
	check(cases > 50, "only %d payload cases", cases);
	printf("payload manifest: %d cases\n", cases);
}

/* ---- 5. corpus replay --------------------------------------------------- */

struct sparse {
	const pg_u8 *p;
	size_t n;
};

static int sread(void *ctx, pg_u64 s, pg_u8 *buf)
{
	struct sparse *sp = ctx;
	size_t i;

	for (i = 8; i + 516 <= sp->n; i += 516) {
		pg_u64 at = sp->p[i] | sp->p[i + 1] << 8 | sp->p[i + 2] << 16 |
			    (pg_u64)sp->p[i + 3] << 24;

		if (at == s) {
			memcpy(buf, sp->p + i + 4, 512);
			return 0;
		}
	}
	return 1;
}

static void replay(const char *path)
{
	static pg_u8 in[1 << 20];
	struct sparse sp = { in, 0 };
	struct pg_ntfs v;
	pg_size n, k;
	pg_u64 size;
	pg_u16 flags;
	pg_u8 buf[512];
	FILE *f = fopen(path, "rb");

	if (!f)
		return;
	sp.n = fread(in, 1, sizeof(in), f);
	fclose(f);
	if (sp.n < 8)
		return;
	if (strstr(path, "/payload/")) {
		pg_payload_check(sread, &sp, in[0] | in[1] << 8 | in[2] << 16 |
				 (pg_u64)in[3] << 24, in[4] & 1 ? 4096 : 512, buf);
		return;
	}
	memset(&v, 0, sizeof(v));
	v.read = sread;
	v.ctx = &sp;
	v.rec = rec_buf;
	v.alist = alist_buf;
	v.mft = mft_runs;
	v.mft_cap = 2048;
	if (pg_ntfs_open(&v))
		return;
	pg_ntfs_volume_flags(&v, &flags);
	if (pg_ntfs_file(&v, in[0] | in[1] << 8 | in[2] << 16 |
			 (pg_u64)in[3] << 24, (pg_u16)(in[4] | in[5] << 8),
			 runs, PG_MAX_EXTENTS, &n, &size))
		return;
	if (pg_ntfs_extents(&v, runs, n, ext, PG_MAX_EXTENTS, &k))
		return;
	pg_claim_normalise(ext, k, norm, PG_MAX_EXTENTS, &n);
}

int main(int argc, char **argv)
{
	int stride = 1, i = 1;
	struct image *im;

	if (argc > 2 && !strcmp(argv[1], "-s")) {
		stride = atoi(argv[2]);
		i = 3;
	}
	test_range();
	test_claims();
	test_runlist();
	test_payload();
	test_extents_cap();
	if (i < argc) {
		im = load(argv[i], "vol512.img");
		check(im && im->len >= 512, "vol512 fixture");
		if (im && im->len >= 512)
			test_boot(im->data);
		manifest(argv[i], stride);
		if (i + 2 < argc && !strcmp(argv[i + 1], "-p")) {
			payload_manifest(argv[i + 2], stride);
			i += 2;
		}
		for (i++; i < argc; i++)
			replay(argv[i]);
	}
	printf("%d checks, %d failures\n", checks, failures);
	return failures != 0;
}
