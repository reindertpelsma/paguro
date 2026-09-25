// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * pgstress: a busybox-friendly filesystem stress with self-checking data,
 * for the coexistence and power-loss tests (kernel/dm-paguro/test/coexist).
 * Static, no dependencies beyond libc.
 *
 *   pgstress tree  <dir> <seed> <ops> <manifest>    create/overwrite/append/
 *                  truncate/rename/unlink/mkdir churn; the surviving files'
 *                  expected state is written to <manifest>
 *   pgstress fill  <dir> <seed> <manifest>          files until ENOSPC, then
 *                  every other one deleted; survivors to <manifest>
 *   pgstress verify <dir> <manifest>                every listed file intact
 *                  and nothing else under <dir>
 *   pgstress blocks <file> <MiB> <seed> <ops> <state> [direct]
 *                  random 4 KiB block overwrites of one preallocated file,
 *                  fdatasync now and then; generation per block to <state>
 *   pgstress blockverify <file> <state>
 *
 * Every file is self-describing: a 64-byte header (magic, id, generation,
 * length, CRC-32 of the body) and a body generated from (id, generation), so
 * a block from anywhere else -- another file, another filesystem, zeros --
 * is caught. Block mode stamps each 4 KiB block with (seed, block, gen).
 * Exit status: 0 clean; 1 corruption or an unexpected error (printed).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAGIC 0x5347525453504750ull	/* "PGSTRSSG" */
#define HDR 64
#define MAXF 20000
#define MAXLEN (256 * 1024)
#define BLK 4096

static uint64_t rng;

static uint64_t next(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static uint64_t below(uint64_t n)
{
	return n ? next() % n : 0;
}

static void die(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("pgstress: ", stderr);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
	exit(1);
}

static uint32_t crc32(const uint8_t *p, size_t n)
{
	uint32_t c = ~0u;
	int k;

	while (n--) {
		c ^= *p++;
		for (k = 0; k < 8; k++)
			c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1)));
	}
	return ~c;
}

/* The body of file (id, gen): len bytes of a stream seeded from both. */
static void body(uint8_t *b, size_t len, uint64_t id, uint64_t gen)
{
	uint64_t s = (id * 0x9e3779b97f4a7c15ull) ^ (gen + 0x632be59bd9b4e019ull);
	size_t i;

	s |= 1;
	for (i = 0; i < len; i++) {
		if (i % 8 == 0) {
			s ^= s << 13;
			s ^= s >> 7;
			s ^= s << 17;
		}
		b[i] = (uint8_t)(s >> (8 * (i % 8)));
	}
}

static void put64(uint8_t *b, uint64_t v)
{
	memcpy(b, &v, 8);
}

static uint64_t get64(const uint8_t *b)
{
	uint64_t v;

	memcpy(&v, b, 8);
	return v;
}

static uint8_t buf[HDR + MAXLEN], cmp[HDR + MAXLEN];

/* Whole file content for (id, gen, len): header + body. */
static size_t content(uint64_t id, uint64_t gen, size_t len)
{
	body(buf + HDR, len, id, gen);
	memset(buf, 0, HDR);
	put64(buf, MAGIC);
	put64(buf + 8, id);
	put64(buf + 16, gen);
	put64(buf + 24, len);
	put64(buf + 32, crc32(buf + HDR, len));
	put64(buf + 40, crc32(buf, 40));
	return HDR + len;
}

struct file {
	char path[64];
	uint64_t id, gen, len;
	int live;
};

static struct file files[MAXF];
static int nfiles;
static uint64_t enospc;

/* Write a whole file; 0, or ENOSPC (file removed), else fatal. */
static int write_file(const char *path, uint64_t id, uint64_t gen,
		      size_t len, int sync)
{
	size_t n = content(id, gen, len), off = 0;
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (fd < 0) {
		if (errno == ENOSPC)
			return ENOSPC;
		die("open %s: %s", path, strerror(errno));
	}
	while (off < n) {
		ssize_t w = write(fd, buf + off, n - off);

		if (w < 0) {
			int e = errno;

			close(fd);
			if (e == ENOSPC) {
				unlink(path);
				enospc++;
				return ENOSPC;
			}
			die("write %s: %s", path, strerror(e));
		}
		off += (size_t)w;
	}
	if (sync && fsync(fd) && errno != ENOSPC)
		die("fsync %s: %s", path, strerror(errno));
	if (close(fd)) {
		if (errno == ENOSPC) {
			unlink(path);
			enospc++;
			return ENOSPC;
		}
		die("close %s: %s", path, strerror(errno));
	}
	return 0;
}

static int check_file(const char *path, uint64_t id, uint64_t gen,
		      uint64_t len)
{
	struct stat st;
	size_t n, got = 0;
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		printf("CORRUPT %s: %s\n", path, strerror(errno));
		return 1;
	}
	if (fstat(fd, &st) || (uint64_t)st.st_size != HDR + len) {
		printf("CORRUPT %s: size %lld, expected %llu\n", path,
		       (long long)st.st_size, (unsigned long long)(HDR + len));
		close(fd);
		return 1;
	}
	n = content(id, gen, len);
	while (got < n) {
		ssize_t r = read(fd, cmp + got, n - got);

		if (r <= 0) {
			printf("CORRUPT %s: read: %s\n", path,
			       r ? strerror(errno) : "short");
			close(fd);
			return 1;
		}
		got += (size_t)r;
	}
	close(fd);
	if (memcmp(buf, cmp, n)) {
		size_t i;

		for (i = 0; i < n && buf[i] == cmp[i]; i++)
			;
		printf("CORRUPT %s: id %llu gen %llu: first bad byte %zu\n",
		       path, (unsigned long long)id, (unsigned long long)gen, i);
		return 1;
	}
	return 0;
}

static void save(const char *manifest)
{
	FILE *f = fopen(manifest, "w");
	int i;

	if (!f)
		die("%s: %s", manifest, strerror(errno));
	for (i = 0; i < nfiles; i++)
		if (files[i].live)
			fprintf(f, "%s %llu %llu %llu\n", files[i].path,
				(unsigned long long)files[i].id,
				(unsigned long long)files[i].gen,
				(unsigned long long)files[i].len);
	fclose(f);
}

static size_t pick_len(void)
{
	switch (below(4)) {
	case 0:
		return below(512);
	case 1:
		return below(8192);
	case 2:
		return below(65536);
	default:
		return below(MAXLEN);
	}
}

static int tree(const char *dir, uint64_t seed, long ops, const char *manifest)
{
	char path[64], to[64];
	long op;
	int ndirs = 1, i;

	rng = seed | 1;
	if (mkdir(dir, 0755) && errno != EEXIST)
		die("mkdir %s: %s", dir, strerror(errno));
	if (chdir(dir))
		die("chdir %s: %s", dir, strerror(errno));
	mkdir("d0", 0755);
	for (op = 0; op < ops; op++) {
		struct file *f = &files[below(nfiles ? nfiles : 1)];
		uint64_t r = below(100);
		int dosync = below(64) == 0;

		if (nfiles < MAXF && (r < 40 || !nfiles)) {	/* create */
			f = &files[nfiles];
			snprintf(f->path, sizeof(f->path), "d%d/f%d",
				 (int)below(ndirs), nfiles);
			f->id = seed << 20 | (uint64_t)nfiles;
			f->gen = 0;
			f->len = pick_len();
			if (!write_file(f->path, f->id, f->gen, f->len, dosync)) {
				f->live = 1;
				nfiles++;
			}
		} else if (r < 55 && f->live) {			/* overwrite */
			uint64_t len = pick_len();

			if (!write_file(f->path, f->id, f->gen + 1, len, dosync)) {
				f->gen++;
				f->len = len;
			} else {
				f->live = 0;
			}
		} else if (r < 62 && f->live) {			/* rename */
			snprintf(to, sizeof(to), "d%d/r%ld", (int)below(ndirs), op);
			/* A full volume may have no room for the new name. */
			if (rename(f->path, to)) {
				if (errno != ENOSPC)
					die("rename %s: %s", f->path, strerror(errno));
				enospc++;
			} else {
				memcpy(f->path, to, sizeof(to));
			}
		} else if (r < 92 && f->live) {			/* unlink */
			if (unlink(f->path))
				die("unlink %s: %s", f->path, strerror(errno));
			f->live = 0;
		} else if (r < 94 && ndirs < 64) {		/* mkdir */
			snprintf(path, sizeof(path), "d%d", ndirs);
			if (!mkdir(path, 0755))
				ndirs++;
			else if (errno != ENOSPC)
				die("mkdir %s: %s", path, strerror(errno));
		} else if (r < 97) {				/* whole-tree sync */
			sync();
		}
	}
	for (i = 0; i < nfiles; i++)
		if (files[i].live && check_file(files[i].path, files[i].id,
						 files[i].gen, files[i].len))
			return 1;
	save(manifest);
	printf("tree %s: %d files made, %ld ops, %llu ENOSPC\n", dir, nfiles,
	       ops, (unsigned long long)enospc);
	return 0;
}

static int fill(const char *dir, uint64_t seed, const char *manifest)
{
	int i, live = 0;

	rng = seed | 1;
	if (mkdir(dir, 0755) && errno != EEXIST)
		die("mkdir %s: %s", dir, strerror(errno));
	if (chdir(dir))
		die("chdir %s: %s", dir, strerror(errno));
	/* Big files first, then small ones into what is left. */
	for (nfiles = 0; nfiles < MAXF; nfiles++) {
		struct file *f = &files[nfiles];

		snprintf(f->path, sizeof(f->path), "x%d", nfiles);
		f->id = seed << 20 | (uint64_t)nfiles;
		f->len = enospc < 4 ? MAXLEN - 64 : below(4096);
		if (write_file(f->path, f->id, 0, f->len, 0)) {
			if (enospc > 64)
				break;
			continue;
		}
		f->live = 1;
	}
	sync();
	for (i = 0; i < nfiles; i += 2)
		if (files[i].live) {
			if (unlink(files[i].path))
				die("unlink %s: %s", files[i].path, strerror(errno));
			files[i].live = 0;
		}
	for (i = 0; i < nfiles; i++)
		if (files[i].live) {
			if (check_file(files[i].path, files[i].id, 0, files[i].len))
				return 1;
			live++;
		}
	save(manifest);
	printf("fill %s: %d files to ENOSPC (%llu refusals), %d kept\n", dir,
	       nfiles, (unsigned long long)enospc, live);
	return 0;
}

/* Count regular files under the current directory. */
static long walk(const char *d)
{
	DIR *dir = opendir(d);
	struct dirent *e;
	char p[512];
	long n = 0;

	if (!dir)
		die("opendir %s: %s", d, strerror(errno));
	while ((e = readdir(dir))) {
		struct stat st;

		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		snprintf(p, sizeof(p), "%s/%s", d, e->d_name);
		if (lstat(p, &st))
			die("stat %s: %s", p, strerror(errno));
		n += S_ISDIR(st.st_mode) ? walk(p) : 1;
	}
	closedir(dir);
	return n;
}

static int verify(const char *dir, const char *manifest)
{
	FILE *f = fopen(manifest, "r");
	char path[64];
	unsigned long long id, gen, len;
	long n = 0, bad = 0, found;

	if (!f)
		die("%s: %s", manifest, strerror(errno));
	if (chdir(dir))
		die("chdir %s: %s", dir, strerror(errno));
	while (fscanf(f, "%63s %llu %llu %llu", path, &id, &gen, &len) == 4) {
		bad += check_file(path, id, gen, len);
		n++;
	}
	fclose(f);
	found = walk(".");
	if (found != n) {
		printf("CORRUPT %s: %ld files present, %ld expected\n", dir,
		       found, n);
		bad++;
	}
	printf("verify %s: %ld files, %ld bad\n", dir, n, bad);
	return bad != 0;
}

/* ---- block mode --------------------------------------------------------- */

static void stamp(uint8_t *b, uint64_t seed, uint64_t blk, uint64_t gen)
{
	body(b + 32, BLK - 32, seed ^ blk << 1, gen);
	put64(b, MAGIC);
	put64(b + 8, seed);
	put64(b + 16, blk);
	put64(b + 24, gen);
}

static int blocks(const char *path, long mib, uint64_t seed, long ops,
		  const char *state, int direct)
{
	uint64_t n = (uint64_t)mib * (1 << 20) / BLK, i;
	uint32_t *gen = calloc(n, sizeof(*gen));
	uint8_t *b;
	FILE *f;
	long op;
	int fd = open(path, O_RDWR | O_CREAT | (direct ? O_DIRECT : 0), 0644);

	if (fd < 0 || !gen || posix_memalign((void **)&b, BLK, BLK))
		die("%s: %s", path, strerror(errno));
	rng = seed | 1;
	for (i = 0; i < n; i++) {
		stamp(b, seed, i, 0);
		if (pwrite(fd, b, BLK, (off_t)(i * BLK)) != BLK)
			die("fill %s: %s", path, strerror(errno));
	}
	if (fdatasync(fd))
		die("fdatasync: %s", strerror(errno));
	for (op = 0; op < ops; op++) {
		uint64_t k = below(n), run = 1 + below(16);

		for (i = k; i < k + run && i < n; i++) {
			gen[i]++;
			stamp(b, seed, i, gen[i]);
			if (pwrite(fd, b, BLK, (off_t)(i * BLK)) != BLK)
				die("pwrite %s: %s", path, strerror(errno));
		}
		if (below(32) == 0 && fdatasync(fd))
			die("fdatasync: %s", strerror(errno));
	}
	if (fsync(fd) || close(fd))
		die("fsync %s: %s", path, strerror(errno));
	f = fopen(state, "w");
	if (!f)
		die("%s: %s", state, strerror(errno));
	fprintf(f, "%llu %llu\n", (unsigned long long)seed, (unsigned long long)n);
	for (i = 0; i < n; i++)
		fprintf(f, "%u\n", gen[i]);
	fclose(f);
	printf("blocks %s: %llu blocks, %ld ops\n", path, (unsigned long long)n, ops);
	return 0;
}

static int blockverify(const char *path, const char *state)
{
	FILE *f = fopen(state, "r");
	unsigned long long seed, n, i, bad = 0;
	uint8_t *b, *want;
	unsigned int g;
	int fd = open(path, O_RDONLY);

	if (!f || fd < 0 || fscanf(f, "%llu %llu", &seed, &n) != 2 ||
	    posix_memalign((void **)&b, BLK, BLK) ||
	    posix_memalign((void **)&want, BLK, BLK))
		die("%s/%s: %s", path, state, strerror(errno));
	for (i = 0; i < n; i++) {
		if (fscanf(f, "%u", &g) != 1)
			die("%s: short", state);
		stamp(want, seed, i, g);
		if (pread(fd, b, BLK, (off_t)(i * BLK)) != BLK || memcmp(b, want, BLK)) {
			if (bad++ < 10)
				printf("CORRUPT %s: block %llu (gen %u): holds seed %llu block %llu gen %llu\n",
				       path, i, g, (unsigned long long)get64(b + 8),
				       (unsigned long long)get64(b + 16),
				       (unsigned long long)get64(b + 24));
		}
	}
	close(fd);
	fclose(f);
	printf("blockverify %s: %llu blocks, %llu bad\n", path, n, bad);
	return bad != 0;
}

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "";
	static char cwd[4096], abs[8][4200];
	int i;

	setvbuf(stdout, NULL, _IOLBF, 0);
	/* tree/fill/verify chdir into <dir>: make every path absolute first. */
	if (!getcwd(cwd, sizeof(cwd)))
		die("getcwd: %s", strerror(errno));
	for (i = 2; i < argc && i < 8; i++)
		if (argv[i][0] != '/' && strchr("0123456789", argv[i][0]) == NULL &&
		    strcmp(argv[i], "direct")) {
			snprintf(abs[i], sizeof(abs[i]), "%s/%s", cwd, argv[i]);
			argv[i] = abs[i];
		}
	if (!strcmp(m, "tree") && argc == 6)
		return tree(argv[2], strtoull(argv[3], NULL, 0), atol(argv[4]), argv[5]);
	if (!strcmp(m, "fill") && argc == 5)
		return fill(argv[2], strtoull(argv[3], NULL, 0), argv[4]);
	if (!strcmp(m, "verify") && argc == 4)
		return verify(argv[2], argv[3]);
	if (!strcmp(m, "blocks") && (argc == 7 || argc == 8))
		return blocks(argv[2], atol(argv[3]), strtoull(argv[4], NULL, 0),
			      atol(argv[5]), argv[6], argc == 8);
	if (!strcmp(m, "blockverify") && argc == 4)
		return blockverify(argv[2], argv[3]);
	fprintf(stderr, "usage: see the comment at the top of pgstress.c\n");
	return 2;
}
