// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * pgctl: a minimal /dev/paguro client for tests and bring-up.
 *
 *   pgctl add <raw-dev> <plain-dev> [R<start>+<len>...]   -> volume id
 *   pgctl claim <volume> <mft-record> <mft-seq> [raw|vhd]  -> claim id
 *   pgctl grow <claim>
 *   pgctl crosscheck <claim> <file-on-ntfs3>               (FIEMAP -> module)
 *   pgctl release <claim>
 *   pgctl remove <volume>
 *   pgctl status
 *   pgctl ident <file>              "<mft-record> <mft-seq>" (ntfs3 inode)
 *   pgctl fiemap <file>             "<start> <len>" per extent, 512-byte sectors
 *   pgctl fadvise <dev> <sector> <count>    readahead (POSIX_FADV_WILLNEED)
 *   pgctl dio <dev> <byte-offset> <bytes>   one O_DIRECT read; prints errno
 *
 * Exit status 0 on success; on refusal prints "error <code>" (PG_E_* or
 * PG_ERR_*) and exits 1.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "../paguro_uapi.h"

static int ctl(unsigned long cmd, void *arg)
{
	int fd = open("/dev/paguro", O_RDWR), r;

	if (fd < 0) {
		perror("/dev/paguro");
		exit(2);
	}
	r = ioctl(fd, cmd, arg);
	if (r)
		r = errno;
	close(fd);
	return r;
}

static void fail(int r, int code)
{
	printf("error %d (%s)\n", code, strerror(r));
	exit(1);
}

static dev_t devof(const char *path)
{
	struct stat st;

	if (stat(path, &st) || !S_ISBLK(st.st_mode)) {
		fprintf(stderr, "%s: not a block device\n", path);
		exit(2);
	}
	return st.st_rdev;
}

/* FIEMAP a file: physical extents in 512-byte sectors, file order. */
static struct pg_uapi_range *fiemap(const char *path, unsigned int *n)
{
	struct pg_uapi_range *out = NULL;
	struct fiemap *fm;
	unsigned long long start = 0;
	unsigned int cap = 0, i, last = 0;
	int fd = open(path, O_RDONLY);

	if (fd < 0) {
		perror(path);
		exit(2);
	}
	fm = calloc(1, sizeof(*fm) + 512 * sizeof(struct fiemap_extent));
	*n = 0;
	while (!last) {
		fm->fm_start = start;
		fm->fm_length = ~0ull - start;
		fm->fm_flags = FIEMAP_FLAG_SYNC;
		fm->fm_extent_count = 512;
		if (ioctl(fd, FS_IOC_FIEMAP, fm)) {
			perror("FIEMAP");
			exit(2);
		}
		if (fm->fm_mapped_extents == 0)
			break;
		for (i = 0; i < fm->fm_mapped_extents; i++) {
			struct fiemap_extent *e = &fm->fm_extents[i];

			if (*n == cap) {
				cap = cap ? cap * 2 : 64;
				out = realloc(out, cap * sizeof(*out));
			}
			out[*n].start = e->fe_physical / 512;
			out[*n].len = (e->fe_length + 511) / 512;
			(*n)++;
			start = e->fe_logical + e->fe_length;
			last = e->fe_flags & FIEMAP_EXTENT_LAST;
		}
	}
	close(fd);
	free(fm);
	return out;
}

int main(int argc, char **argv)
{
	const char *cmd = argc > 1 ? argv[1] : "";
	int r, i;

	if (!strcmp(cmd, "add") && argc >= 4) {
		struct pg_volume_add a = { 0 };
		dev_t raw = devof(argv[2]), plain = devof(argv[3]);

		a.raw_major = major(raw);
		a.raw_minor = minor(raw);
		a.plain_major = major(plain);
		a.plain_minor = minor(plain);
		for (i = 4; i < argc && a.nreserved < PG_MAX_RESERVED; i++) {
			unsigned long long s, l;

			if (sscanf(argv[i], "R%llu+%llu", &s, &l) == 2) {
				a.reserved[a.nreserved].start = s;
				a.reserved[a.nreserved++].len = l;
			}
		}
		r = ctl(PG_VOLUME_ADD, &a);
		if (r)
			fail(r, a.error);
		printf("%u\n", a.volume_id);
		fprintf(stderr, "volume %u: %llu sectors, flags %#x\n",
			a.volume_id, (unsigned long long)a.sectors, a.volume_flags);
	} else if (!strcmp(cmd, "claim") && argc >= 5) {
		struct pg_claim c = { 0 };

		c.volume_id = atoi(argv[2]);
		c.mft_record = strtoull(argv[3], NULL, 0);
		c.mft_seq = (unsigned short)strtoul(argv[4], NULL, 0);
		c.format = argc > 5 && !strcmp(argv[5], "vhd") ? PG_FORMAT_VHD
							       : PG_FORMAT_RAW;
		r = ctl(PG_CLAIM, &c);
		if (r)
			fail(r, c.error);
		printf("%u\n", c.claim_id);
		fprintf(stderr, "claim %u: %u extents, %llu sectors, state %#x\n",
			c.claim_id, c.extents, (unsigned long long)c.sectors,
			c.state);
	} else if (!strcmp(cmd, "grow") && argc == 3) {
		struct pg_grow g = { .claim_id = atoi(argv[2]) };

		r = ctl(PG_GROW, &g);
		if (r)
			fail(r, g.error);
		printf("state %u sectors %llu extents %u error %d\n", g.state,
		       (unsigned long long)g.sectors, g.extents, g.error);
	} else if (!strcmp(cmd, "crosscheck") && argc == 4) {
		struct pg_crosscheck x = { .claim_id = atoi(argv[2]) };
		struct pg_uapi_range *e = fiemap(argv[3], &x.count);

		x.ranges = (unsigned long)e;
		r = ctl(PG_CROSSCHECK, &x);
		if (r)
			fail(r, 0);
		printf("state %u\n", x.state);
		return !(x.state & PG_CLAIM_CHECKED);
	} else if (!strcmp(cmd, "release") && argc == 3) {
		struct pg_release rel = { .claim_id = atoi(argv[2]) };

		r = ctl(PG_RELEASE, &rel);
		if (r)
			fail(r, 0);
	} else if (!strcmp(cmd, "remove") && argc == 3) {
		struct pg_volume_remove rm = { .volume_id = atoi(argv[2]) };

		r = ctl(PG_VOLUME_REMOVE, &rm);
		if (r)
			fail(r, 0);
	} else if (!strcmp(cmd, "status")) {
		static struct pg_status s;

		r = ctl(PG_STATUS, &s);
		if (r)
			fail(r, 0);
		for (i = 0; i < PG_MAX_VOLUMES; i++)
			if (s.volume[i].id)
				printf("volume %u sectors %llu flags %#x view %c tables %u guard %llu readahead %llu\n",
				       s.volume[i].id,
				       (unsigned long long)s.volume[i].sectors,
				       s.volume[i].flags,
				       s.volume[i].view ? s.volume[i].view : '-',
				       s.volume[i].view_tables,
				       (unsigned long long)s.volume[i].guard_hits,
				       (unsigned long long)s.volume[i].readahead_hits);
		for (i = 0; i < PG_MAX_CLAIMS; i++)
			if (s.claim[i].id)
				printf("claim %u volume %u record %llu seq %u state %#x extents %u sectors %llu refused %llu tables %u\n",
				       s.claim[i].id, s.claim[i].volume_id,
				       (unsigned long long)s.claim[i].mft_record,
				       s.claim[i].mft_seq, s.claim[i].state,
				       s.claim[i].extents,
				       (unsigned long long)s.claim[i].sectors,
				       (unsigned long long)s.claim[i].refused,
				       s.claim[i].image_tables);
	} else if (!strcmp(cmd, "ident") && argc == 3) {
		/* ntfs3's file handle is FILEID_INO32_GEN: {record, sequence}. */
		struct { struct file_handle h; unsigned int f[2]; } fh;
		int mnt;

		fh.h.handle_bytes = sizeof(fh.f);
		if (name_to_handle_at(AT_FDCWD, argv[2], &fh.h, &mnt, 0) ||
		    fh.h.handle_type != 1) {
			perror(argv[2]);
			return 2;
		}
		printf("%u %u\n", fh.f[0], fh.f[1] & 0xffff);
	} else if (!strcmp(cmd, "fiemap") && argc == 3) {
		unsigned int n, k;
		struct pg_uapi_range *e = fiemap(argv[2], &n);

		for (k = 0; k < n; k++)
			printf("%llu %llu\n", (unsigned long long)e[k].start,
			       (unsigned long long)e[k].len);
	} else if (!strcmp(cmd, "fadvise") && argc == 5) {
		int fd = open(argv[2], O_RDONLY);

		if (fd < 0)
			return 2;
		r = posix_fadvise(fd, strtoll(argv[3], NULL, 0) * 512,
				  strtoll(argv[4], NULL, 0) * 512,
				  POSIX_FADV_WILLNEED);
		sleep(1);	/* readahead is asynchronous */
		close(fd);
		return r != 0;
	} else if (!strcmp(cmd, "dio") && argc == 5) {
		size_t len = strtoull(argv[4], NULL, 0);
		void *buf;
		int fd = open(argv[2], O_RDONLY | O_DIRECT);

		if (fd < 0 || posix_memalign(&buf, 4096, len + 4096))
			return 2;
		r = pread(fd, buf, len, strtoll(argv[3], NULL, 0)) == (ssize_t)len ? 0 : errno;
		printf("%s\n", r ? strerror(r) : "ok");
		return r != 0;
	} else {
		fprintf(stderr, "usage: see the comment at the top of pgctl.c\n");
		return 2;
	}
	return 0;
}
