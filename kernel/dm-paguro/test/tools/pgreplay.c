// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * pgreplay: replay a dm-log-writes log onto a device and check every
 * interesting prefix of it (INTERFACES 12.1). A small reimplementation of
 * xfstests' src/log-writes/replay-log, written from the log format in
 * drivers/md/dm-log-writes.c so the test carries no GPL-only code:
 *
 *   super   @0            magic u64, version u64, nr_entries u64, sectorsize u32
 *   entry   @sectorsize   sector u64, nr_sectors u64, flags u64, data_len u64
 *                         (a mark's text follows in the same log sector)
 *   data    after it      nr_sectors * sectorsize bytes (writes only)
 *
 * Sectors and lengths are in units of the logged device's logical block
 * (`sectorsize`). Entries appear in completion order; a FLUSH entry makes
 * everything before it durable, a FUA write itself.
 *
 *   pgreplay info <log>
 *   pgreplay walk <log> <dev> [options] -- <check command...>
 *     Replays the log onto <dev> in order (the device must hold the state
 *     the log started from) and runs the check command, with PG_STATE set,
 *     at each chosen state; stops at the first failing check (exit 1).
 *     States:
 *       every FLUSH/FUA entry (--flush-every K: every Kth of them)
 *       --every N     also every Nth write         (power cut after write n)
 *       --subsets P   for P% of flush intervals, before replaying it: a cut
 *                     point inside it and a random subset of its writes up to
 *                     there (FUA writes up to the cut always kept), checked,
 *                     then undone                  (drive cache reordering)
 *       --torn P      in those subsets, P% of the writes land only a random
 *                     subset of their 512-byte sectors (torn 512e writes)
 *       --seed S      randomness
 *       --max N       stop after N checks
 *       --mark NAME   start checking only after the mark NAME
 *     Discards are replayed as zeros.
 *
 * PG_STATE is "flush <entry>", "write <entry>" or "subset <entry> <cut>
 * <kept>/<of>". The check command runs with the device fsync'ed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define LOG_MAGIC 0x6a736677736872ull
#define F_FLUSH 1
#define F_FUA 2
#define F_DISCARD 4
#define F_MARK 8

struct entry {
	uint64_t sector, nr, flags, off;	/* off: of the data in the log */
	char mark[64];
};

static struct entry *ent;
static uint64_t nent, ssz;
static int logfd, devfd;
static uint64_t rng = 1;

static void die(const char *what)
{
	fprintf(stderr, "pgreplay: %s: %s\n", what, strerror(errno));
	exit(2);
}

static uint64_t below(uint64_t n)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return n ? rng % n : 0;
}

static void load(const char *log)
{
	uint8_t s[4096];
	uint64_t i, pos;

	logfd = open(log, O_RDONLY);
	if (logfd < 0 || pread(logfd, s, 32, 0) != 32)
		die(log);
	if (*(uint64_t *)s != LOG_MAGIC) {
		fprintf(stderr, "pgreplay: %s: not a log-writes log\n", log);
		exit(2);
	}
	nent = *(uint64_t *)(s + 16);
	ssz = *(uint32_t *)(s + 24);
	if (ssz < 512 || ssz > 4096 || (ssz & (ssz - 1))) {
		fprintf(stderr, "pgreplay: bad sector size %llu\n",
			(unsigned long long)ssz);
		exit(2);
	}
	ent = calloc(nent ? nent : 1, sizeof(*ent));
	if (!ent)
		die("calloc");
	pos = ssz;
	for (i = 0; i < nent; i++) {
		struct entry *e = &ent[i];
		uint64_t len;

		if (pread(logfd, s, ssz, (off_t)pos) != (ssize_t)ssz)
			die("reading an entry");
		e->sector = *(uint64_t *)s;
		e->nr = *(uint64_t *)(s + 8);
		e->flags = *(uint64_t *)(s + 16);
		len = *(uint64_t *)(s + 24);
		pos += ssz;
		e->off = pos;
		if (e->flags & F_MARK) {
			if (len > sizeof(e->mark) - 1)
				len = sizeof(e->mark) - 1;
			memcpy(e->mark, s + 32, len);
			e->nr = 0;
		} else if (!(e->flags & F_DISCARD)) {
			pos += e->nr * ssz;
		}
	}
}

static uint8_t *buf;
static uint64_t bufcap;

static void grow(uint64_t n)
{
	if (n <= bufcap)
		return;
	free(buf);
	bufcap = n;
	buf = malloc(n);
	if (!buf)
		die("malloc");
}

/* Apply entry i: writes land, discards zero; `mask` (bit per 512-byte
 * sector, all ones = whole) selects the sectors of a torn write. */
static void apply(uint64_t i, const uint8_t *mask)
{
	struct entry *e = &ent[i];
	uint64_t n = e->nr * ssz, k;

	if (!e->nr || e->flags & F_MARK)
		return;
	grow(n);
	if (e->flags & F_DISCARD)
		memset(buf, 0, n);
	else if (pread(logfd, buf, n, (off_t)e->off) != (ssize_t)n)
		die("reading data");
	if (!mask) {
		if (pwrite(devfd, buf, n, (off_t)(e->sector * ssz)) != (ssize_t)n)
			die("writing the device");
		return;
	}
	for (k = 0; k < n / 512; k++)
		if (mask[k / 8] & 1 << k % 8 &&
		    pwrite(devfd, buf + k * 512, 512,
			   (off_t)(e->sector * ssz + k * 512)) != 512)
			die("writing the device");
}

static int check(char **cmd, const char *state)
{
	pid_t pid;
	int st;

	if (fsync(devfd))
		die("fsync");
	setenv("PG_STATE", state, 1);
	pid = fork();
	if (pid < 0)
		die("fork");
	if (!pid) {
		execvp(cmd[0], cmd);
		_exit(127);
	}
	if (waitpid(pid, &st, 0) < 0)
		die("waitpid");
	if (!WIFEXITED(st) || WEXITSTATUS(st)) {
		fprintf(stderr, "pgreplay: check failed at %s\n", state);
		return 1;
	}
	return 0;
}

struct undo {
	uint64_t at, n;
	uint8_t *old;
};

/* A cut inside (from, to], a random subset of the writes up to it (FUA
 * ones kept), checked, then undone. */
static int subset(uint64_t from, uint64_t to, int torn, char **cmd)
{
	struct undo *u = calloc(to - from, sizeof(*u));
	uint64_t cut = from + 1 + below(to - from), i, kept = 0, of = 0;
	char state[128];
	uint8_t mask[64];
	int r;

	if (!u)
		die("calloc");
	for (i = from; i < cut; i++) {
		struct entry *e = &ent[i];
		struct undo *x = &u[i - from];
		uint8_t *m = NULL;

		if (!e->nr || e->flags & F_MARK)
			continue;
		of++;
		if (!(e->flags & F_FUA) && below(2))
			continue;
		x->at = e->sector * ssz;
		x->n = e->nr * ssz;
		x->old = malloc(x->n);
		if (!x->old || pread(devfd, x->old, x->n, (off_t)x->at) != (ssize_t)x->n)
			die("saving for undo");
		if (!(e->flags & F_FUA) && x->n / 512 <= 8 * sizeof(mask) &&
		    x->n > 512 && (int)below(100) < torn) {
			uint64_t k;

			for (k = 0; k < sizeof(mask); k++)
				mask[k] = (uint8_t)below(256);
			m = mask;
		}
		apply(i, m);
		kept++;
	}
	snprintf(state, sizeof(state), "subset %llu %llu %llu/%llu",
		 (unsigned long long)from, (unsigned long long)cut,
		 (unsigned long long)kept, (unsigned long long)of);
	r = check(cmd, state);
	for (i = cut; i-- > from;) {
		struct undo *x = &u[i - from];

		if (x->old && pwrite(devfd, x->old, x->n, (off_t)x->at) != (ssize_t)x->n)
			die("undo");
		free(x->old);
	}
	free(u);
	if (fsync(devfd))
		die("fsync");
	return r;
}

int main(int argc, char **argv)
{
	uint64_t every = 0, subsets = 0, torn = 0, max = ~0ull, checks = 0;
	uint64_t fevery = 1, flushes = 0;
	uint64_t i, last = 0, writes = 0;
	const char *mark = NULL;
	char state[128], **cmd = NULL;
	int a, started;

	if (argc == 3 && !strcmp(argv[1], "info")) {
		uint64_t f = 0, u = 0, w = 0, m = 0;

		load(argv[2]);
		for (i = 0; i < nent; i++) {
			f += !!(ent[i].flags & F_FLUSH);
			u += !!(ent[i].flags & F_FUA);
			m += !!(ent[i].flags & F_MARK);
			w += ent[i].nr && !(ent[i].flags & F_MARK);
			if (ent[i].flags & F_MARK)
				printf("mark %llu %s\n", (unsigned long long)i, ent[i].mark);
		}
		printf("entries %llu sectorsize %llu writes %llu flush %llu fua %llu marks %llu\n",
		       (unsigned long long)nent, (unsigned long long)ssz,
		       (unsigned long long)w, (unsigned long long)f,
		       (unsigned long long)u, (unsigned long long)m);
		return 0;
	}
	if (argc < 6 || strcmp(argv[1], "walk")) {
		fprintf(stderr, "usage: see the comment at the top of pgreplay.c\n");
		return 2;
	}
	for (a = 4; a < argc; a++) {
		if (!strcmp(argv[a], "--")) {
			cmd = argv + a + 1;
			break;
		}
		if (a + 1 >= argc)
			break;
		if (!strcmp(argv[a], "--every"))
			every = strtoull(argv[++a], NULL, 0);
		else if (!strcmp(argv[a], "--subsets"))
			subsets = strtoull(argv[++a], NULL, 0);
		else if (!strcmp(argv[a], "--torn"))
			torn = strtoull(argv[++a], NULL, 0);
		else if (!strcmp(argv[a], "--seed"))
			rng = strtoull(argv[++a], NULL, 0) | 1;
		else if (!strcmp(argv[a], "--flush-every"))
			fevery = strtoull(argv[++a], NULL, 0) ? strtoull(argv[a], NULL, 0) : 1;
		else if (!strcmp(argv[a], "--max"))
			max = strtoull(argv[++a], NULL, 0);
		else if (!strcmp(argv[a], "--mark"))
			mark = argv[++a];
	}
	if (!cmd || !*cmd) {
		fprintf(stderr, "pgreplay: no check command\n");
		return 2;
	}
	load(argv[2]);
	devfd = open(argv[3], O_RDWR);
	if (devfd < 0)
		die(argv[3]);
	started = !mark;
	for (i = 0; i < nent && checks < max; i++) {
		struct entry *e = &ent[i];

		if (!started && e->flags & F_MARK && !strcmp(e->mark, mark))
			started = 1;
		/* Before replaying a flush interval: maybe a subset trial. */
		if (started && i == last && subsets) {
			uint64_t j = i;

			while (j < nent && !(ent[j].flags & (F_FLUSH | F_FUA)))
				j++;
			if (j > i && below(100) < subsets) {
				checks++;
				if (subset(i, j, (int)torn, cmd))
					return 1;
			}
		}
		apply(i, NULL);
		if (e->nr && !(e->flags & F_MARK))
			writes++;
		if (e->flags & (F_FLUSH | F_FUA)) {
			last = i + 1;
			if (!started || flushes++ % fevery)
				continue;
			snprintf(state, sizeof(state), "flush %llu", (unsigned long long)i);
			checks++;
			if (check(cmd, state))
				return 1;
		} else if (started && every && e->nr && writes % every == 0) {
			snprintf(state, sizeof(state), "write %llu", (unsigned long long)i);
			checks++;
			if (check(cmd, state))
				return 1;
		}
	}
	snprintf(state, sizeof(state), "end %llu", (unsigned long long)nent);
	checks++;
	if (check(cmd, state))
		return 1;
	printf("pgreplay: %llu entries, %llu writes, %llu states checked\n",
	       (unsigned long long)nent, (unsigned long long)writes,
	       (unsigned long long)checks);
	return 0;
}
