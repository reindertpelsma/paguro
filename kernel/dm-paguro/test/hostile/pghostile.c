// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * pghostile: /dev/paguro treated as a hostile caller would (INTERFACES
 * 12.0). Every subcommand prints "PASS: ..."/"FAIL: ..." lines; the VM
 * script (hostile.body) runs them under a KASAN/UBSAN/lockdep/kmemleak or a
 * KCSAN kernel and fails on any kernel report.
 *
 *   pghostile numbers                every ioctl number, direction and size:
 *                                    only the seven exact ones are accepted
 *   pghostile pointers               NULL, kernel, unmapped and page-straddling
 *                                    argument and range pointers: EFAULT
 *   pghostile fuzz <n> <seed>        n random structs to each ioctl (ids
 *                                    biased small so they reach deep)
 *   pghostile bounds <dev> <rec> <seq>   overflowing counts, lengths, ranges,
 *                                    unknown flags and formats, capacity
 *   pghostile race <secs>            a thread rewrites the argument while
 *                                    another issues ioctls with it
 *   pghostile privilege              without CAP_SYS_ADMIN, as another uid on
 *                                    a 0666 node, and as root of a user
 *                                    namespace: EPERM for every ioctl
 *   pghostile churn <secs> <threads> <dev> <rec> <seq>
 *                                    concurrent add/claim/grow/crosscheck/
 *                                    release/remove/status on one volume
 *   pghostile flood <n>              n PG_STATUS calls; prints calls/s
 *
 * Exit 1 if any FAIL was printed.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/capability.h>

#include "../../paguro_uapi.h"

static int fails;

static void pass(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("PASS: ", stdout);
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
}

static void fail(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("FAIL: ", stdout);
	vprintf(fmt, ap);
	putchar('\n');
	va_end(ap);
	fails++;
}

static int ctl(void)
{
	int fd = open("/dev/paguro", O_RDWR);

	if (fd < 0) {
		perror("/dev/paguro");
		exit(2);
	}
	return fd;
}

/* The ioctl's errno (0 on success). */
static int io(int fd, unsigned long cmd, void *arg)
{
	return ioctl(fd, cmd, arg) ? errno : 0;
}

static uint64_t rng = 88172645463325252ull;

static uint64_t rnd(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static const struct {
	unsigned long cmd;
	const char *name;
	size_t size;
} cmds[] = {
	{ PG_VOLUME_ADD, "VOLUME_ADD", sizeof(struct pg_volume_add) },
	{ PG_CLAIM, "CLAIM", sizeof(struct pg_claim) },
	{ PG_GROW, "GROW", sizeof(struct pg_grow) },
	{ PG_CROSSCHECK, "CROSSCHECK", sizeof(struct pg_crosscheck) },
	{ PG_RELEASE, "RELEASE", sizeof(struct pg_release) },
	{ PG_STATUS, "STATUS", sizeof(struct pg_status) },
	{ PG_VOLUME_REMOVE, "VOLUME_REMOVE", sizeof(struct pg_volume_remove) },
};
#define NCMDS (sizeof(cmds) / sizeof(cmds[0]))

static struct pg_status snap(int fd)
{
	struct pg_status s;

	memset(&s, 0, sizeof(s));
	if (io(fd, PG_STATUS, &s))
		fail("PG_STATUS: %s", strerror(errno));
	return s;
}

/* Status without the counters that legitimately move. */
static int same_state(struct pg_status a, struct pg_status b)
{
	int i;

	for (i = 0; i < PG_MAX_VOLUMES; i++) {
		a.volume[i].guard_hits = b.volume[i].guard_hits = 0;
		a.volume[i].readahead_hits = b.volume[i].readahead_hits = 0;
	}
	for (i = 0; i < PG_MAX_CLAIMS; i++)
		a.claim[i].refused = b.claim[i].refused = 0;
	return !memcmp(&a, &b, sizeof(a));
}

/* ---- numbers ------------------------------------------------------------- */

static int numbers(void)
{
	static const size_t sizes[] = { 0, 1, 7, 8, 16, 23, 24, 25, 47, 48,
					183, 184, 185, 1024, 16383 };
	static const unsigned int dirs[] = { _IOC_NONE, _IOC_READ, _IOC_WRITE,
					     _IOC_READ | _IOC_WRITE };
	static unsigned char buf[1 << 15];
	int fd = ctl(), accepted = 0, tried = 0, bad = 0;
	unsigned int nr, d, s, k;
	char types[] = { 'p', 'q', 0, (char)0xff };

	for (k = 0; k < sizeof(types); k++)
		for (nr = 0; nr < 32; nr++)
			for (d = 0; d < 4; d++)
				for (s = 0; s < sizeof(sizes) / sizeof(sizes[0]); s++) {
					unsigned long cmd = _IOC(dirs[d], (unsigned char)types[k],
								 nr, sizes[s]);
					int e, known = 0;
					size_t c;

					for (c = 0; c < NCMDS; c++)
						known |= cmds[c].cmd == cmd;
					/* FIBMAP, FIGETBSZ: the VFS answers those. */
					if (types[k] == 0 && _IOC_DIR(cmd) == _IOC_NONE &&
					    (nr == 1 || nr == 2) && sizes[s] == 0)
						continue;
					memset(buf, 0, sizeof(buf));
					e = io(fd, cmd, buf);
					tried++;
					if (known) {
						accepted++;
						continue;
					}
					if (e != ENOTTY) {
						bad++;
						if (bad < 5)
							fail("cmd %#lx: %s, not ENOTTY", cmd,
							     e ? strerror(e) : "accepted");
					}
				}
	/* A zero argument and a bare cmd 0. */
	if (io(fd, 0, NULL) != ENOTTY)
		fail("cmd 0 not ENOTTY");
	if (!bad)
		pass("numbers: %d unknown commands refused with ENOTTY (%d known)",
		     tried - accepted, accepted);
	close(fd);
	return 0;
}

/* ---- pointers ------------------------------------------------------------ */

static int pointers(void)
{
	long pg = sysconf(_SC_PAGESIZE);
	unsigned char *m = mmap(NULL, 2 * pg, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	void *bad[] = { NULL, (void *)1, (void *)0xffff888000000000ull,
			(void *)0xffffffffffffff00ull, (void *)(uintptr_t)-1 };
	struct pg_status before, after;
	int fd = ctl(), ok = 1;
	size_t c, b;

	mprotect(m + pg, pg, PROT_NONE);
	before = snap(fd);
	for (c = 0; c < NCMDS; c++) {
		for (b = 0; b < sizeof(bad) / sizeof(bad[0]); b++)
			if (io(fd, cmds[c].cmd, bad[b]) != EFAULT) {
				fail("%s with pointer %p: not EFAULT", cmds[c].name, bad[b]);
				ok = 0;
			}
		/* The struct's last byte on the PROT_NONE page. */
		memset(m, 0, pg);
		if (io(fd, cmds[c].cmd, m + pg - cmds[c].size + 1) != EFAULT) {
			fail("%s straddling an unmapped page: not EFAULT", cmds[c].name);
			ok = 0;
		}
		/* Readable but not writable: the out-fields cannot be returned. */
		{
			unsigned char *ro = mmap(NULL, pg, PROT_READ | PROT_WRITE,
						 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
			int e;

			memset(ro, 0, pg);
			mprotect(ro, pg, PROT_READ);
			e = io(fd, cmds[c].cmd, ro);
			if (e != EFAULT && e != ENOENT && e != EINVAL && e != ENODEV &&
			    e != EPERM) {
				fail("%s with a read-only argument: %s", cmds[c].name,
				     e ? strerror(e) : "accepted");
				ok = 0;
			}
			munmap(ro, pg);
		}
	}
	/* PG_CROSSCHECK's ranges pointer, wherever the struct is fine. */
	{
		struct pg_crosscheck x = { .claim_id = 1, .count = 2 };
		uint64_t rp[] = { 0, 1, 0xffff888000000000ull,
				  (uint64_t)(uintptr_t)(m + pg - 8) };

		for (b = 0; b < 4; b++) {
			int e;

			x.ranges = rp[b];
			e = io(fd, PG_CROSSCHECK, &x);
			if (e != EFAULT && e != ENOENT && e != EPERM) {
				fail("crosscheck ranges %#llx: %s", (unsigned long long)rp[b],
				     e ? strerror(e) : "accepted");
				ok = 0;
			}
		}
	}
	after = snap(fd);
	if (!same_state(before, after)) {
		fail("pointers: state changed");
		ok = 0;
	}
	if (ok)
		pass("pointers: bad argument and range pointers refused (EFAULT), state unchanged");
	close(fd);
	return 0;
}

/* ---- fuzz ------------------------------------------------------------------- */

static void randomise(unsigned char *p, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		p[i] = (unsigned char)rnd();
}

static int fuzz(long n, uint64_t seed)
{
	static unsigned char buf[sizeof(struct pg_status)];
	static struct pg_uapi_range ranges[64];
	struct pg_status before, after;
	int fd = ctl(), hist[NCMDS][4] = { { 0 } };
	long i;

	rng = seed | 1;
	before = snap(fd);
	for (i = 0; i < n; i++) {
		size_t c = rnd() % NCMDS;
		int e;

		randomise(buf, cmds[c].size);
		/* Bias ids, counts and pointers so the ioctls get past the
		 * first check now and then. */
		switch (cmds[c].cmd) {
		case PG_CLAIM:
			((struct pg_claim *)buf)->volume_id = rnd() % 10;
			((struct pg_claim *)buf)->format = rnd() % 3;
			break;
		case PG_GROW:
			((struct pg_grow *)buf)->claim_id = rnd() % 18;
			break;
		case PG_CROSSCHECK: {
			struct pg_crosscheck *x = (void *)buf;

			x->claim_id = rnd() % 18;
			x->count = rnd() % 70;
			randomise((void *)ranges, sizeof(ranges));
			x->ranges = rnd() % 4 ? (uint64_t)(uintptr_t)ranges : rnd();
			break;
		}
		case PG_RELEASE:
		case PG_VOLUME_REMOVE:
			*(uint32_t *)buf = rnd() % 18;
			break;
		case PG_VOLUME_ADD: {
			struct pg_volume_add *a = (void *)buf;

			a->nreserved = rnd() % 11;
			a->flags = rnd() % 3;
			/* Mostly devices that exist: loop, null, zero, ram. */
			a->plain_major = a->raw_major = rnd() % 2 ? 7 : 1;
			a->plain_minor = a->raw_minor = rnd() % 8;
			break;
		}
		}
		e = io(fd, cmds[c].cmd, buf);
		hist[c][e == 0 ? 0 : e == EINVAL ? 1 : e == ENOENT ? 2 : 3]++;
	}
	after = snap(fd);
	/* Random volume adds may have added a volume on a loop device: undo. */
	{
		int v;

		for (v = 0; v < PG_MAX_VOLUMES; v++)
			if (after.volume[v].id && !before.volume[v].id) {
				struct pg_volume_remove rm = { .volume_id = after.volume[v].id };

				io(fd, PG_VOLUME_REMOVE, &rm);
			}
		after = snap(fd);
	}
	for (size_t c = 0; c < NCMDS; c++)
		printf("INFO: fuzz %s: ok %d EINVAL %d ENOENT %d other %d\n", cmds[c].name,
		       hist[c][0], hist[c][1], hist[c][2], hist[c][3]);
	if (hist[5][0] == 0)
		fail("fuzz: PG_STATUS never succeeded");
	pass("fuzz: %ld random ioctls, %s", n,
	     same_state(before, after) ? "state unchanged" : "state changed (by valid calls)");
	close(fd);
	return 0;
}

/* ---- bounds -------------------------------------------------------------- */

static dev_t devof(const char *p)
{
	struct stat st;

	if (stat(p, &st) || !S_ISBLK(st.st_mode)) {
		fprintf(stderr, "%s: not a block device\n", p);
		exit(2);
	}
	return st.st_rdev;
}

static void add_args(struct pg_volume_add *a, dev_t d)
{
	memset(a, 0, sizeof(*a));
	a->raw_major = a->plain_major = major(d);
	a->raw_minor = a->plain_minor = minor(d);
}

static void expect(int got, int want, const char *what)
{
	if (got == want)
		pass("bounds: %s -> %s", what, want ? strerror(want) : "ok");
	else
		fail("bounds: %s -> %s, expected %s", what, got ? strerror(got) : "ok",
		     want ? strerror(want) : "ok");
}

static int bounds(const char *dev, uint64_t rec, unsigned int seq)
{
	struct pg_volume_add a;
	struct pg_claim c;
	struct pg_crosscheck x;
	struct pg_volume_remove rm;
	struct pg_release rel;
	struct pg_uapi_range *big;
	dev_t d = devof(dev);
	struct pg_status before = snap(ctl());
	int fd = ctl(), e, i;
	uint32_t vid, cid;

	add_args(&a, d);
	a.nreserved = PG_MAX_RESERVED + 1;
	expect(io(fd, PG_VOLUME_ADD, &a), EINVAL, "nreserved 9");
	add_args(&a, d);
	a.nreserved = 0xffffffffu;
	expect(io(fd, PG_VOLUME_ADD, &a), EINVAL, "nreserved 2^32-1");
	add_args(&a, d);
	a.flags = 2;
	expect(io(fd, PG_VOLUME_ADD, &a), EINVAL, "unknown flag");
	add_args(&a, d);
	a.nreserved = 1;
	a.reserved[0].start = ~0ull - 1;
	a.reserved[0].len = 4;
	expect(io(fd, PG_VOLUME_ADD, &a), EINVAL, "reserved range wrapping 2^64");
	add_args(&a, d);
	a.nreserved = 1;
	a.reserved[0].start = 1;
	a.reserved[0].len = 0;
	expect(io(fd, PG_VOLUME_ADD, &a), EINVAL, "empty reserved range");
	add_args(&a, d);
	a.nreserved = 1;
	a.reserved[0].start = 1ull << 40;
	a.reserved[0].len = 1;
	expect(io(fd, PG_VOLUME_ADD, &a), EINVAL, "reserved range past the volume");
	add_args(&a, makedev(1, 3));
	e = io(fd, PG_VOLUME_ADD, &a);
	expect(e == ENODEV || e == ENOTBLK || e == ENXIO ? ENODEV : e, ENODEV, "a character device");
	add_args(&a, makedev(4095, 1048575));
	e = io(fd, PG_VOLUME_ADD, &a);
	expect(e == ENODEV || e == ENXIO ? ENODEV : e, ENODEV, "a device that does not exist");
	add_args(&a, d);
	a.raw_major = 1;
	a.raw_minor = 3;
	expect(io(fd, PG_VOLUME_ADD, &a), ENODEV, "raw device not a block device");

	add_args(&a, d);
	e = io(fd, PG_VOLUME_ADD, &a);
	if (e) {
		fail("bounds: a valid volume add: %s", strerror(e));
		return 1;
	}
	vid = a.volume_id;
	add_args(&a, d);
	expect(io(fd, PG_VOLUME_ADD, &a), EBUSY, "the same device twice");

	memset(&c, 0, sizeof(c));
	c.volume_id = vid;
	c.mft_record = rec;
	c.mft_seq = seq;
	c.format = 2;
	expect(io(fd, PG_CLAIM, &c), EINVAL, "unknown format");
	c.format = 0;
	c.mft_record = 1ull << 40;
	expect(io(fd, PG_CLAIM, &c), EINVAL, "record past 2^32");
	c.mft_record = rec;
	c.mft_seq = 0;
	expect(io(fd, PG_CLAIM, &c), EINVAL, "sequence 0");
	c.mft_seq = seq;
	c.volume_id = 0;
	expect(io(fd, PG_CLAIM, &c), ENOENT, "volume 0");
	c.volume_id = PG_MAX_VOLUMES + 1;
	expect(io(fd, PG_CLAIM, &c), ENOENT, "volume past the table");
	c.volume_id = vid;
	e = io(fd, PG_CLAIM, &c);
	if (e) {
		fail("bounds: a valid claim: %s", strerror(e));
		return 1;
	}
	cid = c.claim_id;

	memset(&x, 0, sizeof(x));
	x.claim_id = cid;
	x.count = 0;
	expect(io(fd, PG_CROSSCHECK, &x), EINVAL, "crosscheck count 0");
	x.count = 65537;
	expect(io(fd, PG_CROSSCHECK, &x), EINVAL, "crosscheck count 65537");
	x.count = 0xffffffffu;
	expect(io(fd, PG_CROSSCHECK, &x), EINVAL, "crosscheck count 2^32-1");
	/* 65536 ranges from a 1 MiB buffer whose tail is unmapped. */
	big = mmap(NULL, 65536 * sizeof(*big), PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	for (i = 0; i < 65536; i++) {
		big[i].start = (uint64_t)i * 8;
		big[i].len = 8;
	}
	mprotect((char *)big + 65536 * sizeof(*big) - 4096, 4096, PROT_NONE);
	x.count = 65536;
	x.ranges = (uint64_t)(uintptr_t)big;
	expect(io(fd, PG_CROSSCHECK, &x), EFAULT, "crosscheck ranges partly unmapped");
	if (snap(fd).claim[cid - 1].state & PG_CLAIM_REFUSED)
		fail("bounds: a faulting crosscheck refused the claim");
	else
		pass("bounds: a faulting crosscheck leaves the claim alone");
	/* Overflowing ranges: refuse the claim (compare only), not crash. */
	mprotect((char *)big + 65536 * sizeof(*big) - 4096, 4096, PROT_READ | PROT_WRITE);
	big[0].start = ~0ull;
	big[0].len = 2;
	x.count = 1;
	e = io(fd, PG_CROSSCHECK, &x);
	expect(e, 0, "crosscheck with a wrapping range (compared, not trusted)");
	if (!(x.state & PG_CLAIM_REFUSED))
		fail("bounds: a wrapping range did not refuse the claim");
	x.count = 65536;
	big[0].start = 0;
	big[0].len = 8;
	e = io(fd, PG_CROSSCHECK, &x);
	expect(e == 0 || e == EPERM ? 0 : e, 0, "crosscheck with 65536 ranges");
	munmap(big, 65536 * sizeof(*big));

	rel.claim_id = cid;
	expect(io(fd, PG_RELEASE, &rel), 0, "release");
	expect(io(fd, PG_RELEASE, &rel), ENOENT, "release twice");
	rel.claim_id = 0;
	expect(io(fd, PG_RELEASE, &rel), ENOENT, "release claim 0");
	rel.claim_id = 0xffffffffu;
	expect(io(fd, PG_RELEASE, &rel), ENOENT, "release claim 2^32-1");
	rm.volume_id = vid;
	expect(io(fd, PG_VOLUME_REMOVE, &rm), 0, "volume remove");
	expect(io(fd, PG_VOLUME_REMOVE, &rm), ENOENT, "volume remove twice");
	if (!same_state(before, snap(fd)))
		fail("bounds: state not back where it started");
	else
		pass("bounds: state back where it started");
	close(fd);
	return 0;
}

/* ---- race: the argument rewritten while the ioctl runs ------------------ */

static volatile int stop;
static unsigned char shared[sizeof(struct pg_status)];

static void *scribbler(void *p)
{
	(void)p;
	while (!stop) {
		size_t i;

		for (i = 0; i < 64; i++)
			shared[i] = (unsigned char)rnd();
		((struct pg_crosscheck *)shared)->count = rnd() % 70;
	}
	return NULL;
}

static int race(int secs)
{
	pthread_t t;
	time_t end = time(NULL) + secs;
	long calls = 0;
	int fd = ctl();

	pthread_create(&t, NULL, scribbler, NULL);
	while (time(NULL) < end) {
		size_t c = calls % NCMDS;

		if (cmds[c].cmd == PG_CROSSCHECK)
			((struct pg_crosscheck *)shared)->ranges =
				(uint64_t)(uintptr_t)(shared + 64);
		io(fd, cmds[c].cmd, shared);
		calls++;
	}
	stop = 1;
	pthread_join(t, NULL);
	pass("race: %ld ioctls with their argument rewritten concurrently", calls);
	close(fd);
	return 0;
}

/* ---- privilege ----------------------------------------------------------- */

static int all_eperm(const char *who)
{
	static unsigned char buf[sizeof(struct pg_status)];
	int fd = open("/dev/paguro", O_RDWR), bad = 0;
	size_t c;

	if (fd < 0) {
		pass("privilege (%s): cannot even open /dev/paguro (%s)", who, strerror(errno));
		return 0;
	}
	for (c = 0; c < NCMDS; c++) {
		int e;

		memset(buf, 0, sizeof(buf));
		e = io(fd, cmds[c].cmd, buf);
		if (e != EPERM) {
			fail("privilege (%s): %s -> %s", who, cmds[c].name,
			     e ? strerror(e) : "accepted");
			bad++;
		}
	}
	if (!bad)
		pass("privilege (%s): every ioctl EPERM", who);
	close(fd);
	return bad;
}

static int child(int (*fn)(void))
{
	pid_t p = fork();
	int st;

	if (!p) {
		fflush(stdout);
		_exit(fn());
	}
	waitpid(p, &st, 0);
	return WIFEXITED(st) ? WEXITSTATUS(st) : 99;
}

static int no_cap(void)
{
	struct __user_cap_header_struct h = { _LINUX_CAPABILITY_VERSION_3, 0 };
	struct __user_cap_data_struct d[2];

	syscall(SYS_capget, &h, d);
	d[CAP_SYS_ADMIN / 32].effective &= ~(1u << (CAP_SYS_ADMIN % 32));
	d[CAP_SYS_ADMIN / 32].permitted &= ~(1u << (CAP_SYS_ADMIN % 32));
	if (syscall(SYS_capset, &h, d))
		return perror("capset"), 98;
	return all_eperm("root without CAP_SYS_ADMIN");
}

static int nobody(void)
{
	if (setgid(65534) || setuid(65534))
		return perror("setuid"), 98;
	return all_eperm("uid 65534, node 0666");
}

static int userns(void)
{
	if (setgid(65534) || setuid(65534))
		return perror("setuid"), 98;
	if (unshare(CLONE_NEWUSER))
		return perror("unshare(CLONE_NEWUSER)"), 98;
	/* Now "root" with every capability, in a namespace it owns. */
	return all_eperm("root of a user namespace");
}

static int privilege(void)
{
	struct stat st;
	int r = 0;

	stat("/dev/paguro", &st);
	chmod("/dev/paguro", 0666);
	r |= child(no_cap);
	r |= child(nobody);
	r |= child(userns);
	chmod("/dev/paguro", st.st_mode & 07777);
	if (r)
		fail("privilege: a child failed (%d)", r);
	return 0;
}

/* ---- churn ----------------------------------------------------------------- */

static dev_t churn_dev;
static uint64_t churn_rec;
static unsigned int churn_seq;
static long churn_ops[8];

static void *churner(void *p)
{
	long id = (long)p;
	int fd = ctl();
	uint64_t r = 0x9e3779b97f4a7c15ull * (uint64_t)(id + 1);

	while (!stop) {
		struct pg_status s;
		unsigned int vol = 0, claim = 0;
		int i, op;

		r ^= r << 13;
		r ^= r >> 7;
		r ^= r << 17;
		op = (int)(r % 7);
		memset(&s, 0, sizeof(s));
		io(fd, PG_STATUS, &s);
		for (i = 0; i < PG_MAX_VOLUMES; i++)
			if (s.volume[i].id)
				vol = s.volume[i].id;
		for (i = 0; i < PG_MAX_CLAIMS; i++)
			if (s.claim[i].id)
				claim = s.claim[i].id;
		switch (op) {
		case 0: {
			struct pg_volume_add a;

			add_args(&a, churn_dev);
			io(fd, PG_VOLUME_ADD, &a);
			break;
		}
		case 1: {
			struct pg_claim c = { .volume_id = vol, .mft_record = churn_rec,
					      .mft_seq = (uint16_t)churn_seq };

			io(fd, PG_CLAIM, &c);
			break;
		}
		case 2: {
			struct pg_grow g = { .claim_id = claim };

			io(fd, PG_GROW, &g);
			break;
		}
		case 3: {
			struct pg_uapi_range rg = { 0, 8 };
			struct pg_crosscheck x = { .claim_id = claim, .count = 1,
						   .ranges = (uint64_t)(uintptr_t)&rg };

			io(fd, PG_CROSSCHECK, &x);
			break;
		}
		case 4: {
			struct pg_release rel = { .claim_id = claim };

			io(fd, PG_RELEASE, &rel);
			break;
		}
		case 5: {
			struct pg_volume_remove rm = { .volume_id = vol };

			io(fd, PG_VOLUME_REMOVE, &rm);
			break;
		}
		default:
			break;
		}
		churn_ops[id % 8]++;
	}
	close(fd);
	return NULL;
}

static int churn(int secs, int threads, const char *dev, uint64_t rec, unsigned int seq)
{
	pthread_t t[64];
	long i, total = 0;

	churn_dev = devof(dev);
	churn_rec = rec;
	churn_seq = seq;
	if (threads > 64)
		threads = 64;
	for (i = 0; i < threads; i++)
		pthread_create(&t[i], NULL, churner, (void *)i);
	sleep(secs);
	stop = 1;
	for (i = 0; i < threads; i++)
		pthread_join(t[i], NULL);
	for (i = 0; i < 8; i++)
		total += churn_ops[i];
	pass("churn: %ld operations from %d threads in %d s", total, threads, secs);
	return 0;
}

/* ---- flood ---------------------------------------------------------------- */

static int flood(long n)
{
	struct timespec a, b;
	struct pg_status s;
	int fd = ctl();
	long i;
	double dt;

	clock_gettime(CLOCK_MONOTONIC, &a);
	for (i = 0; i < n; i++)
		if (io(fd, PG_STATUS, &s)) {
			fail("flood: call %ld: %s", i, strerror(errno));
			break;
		}
	clock_gettime(CLOCK_MONOTONIC, &b);
	dt = (double)(b.tv_sec - a.tv_sec) + (double)(b.tv_nsec - a.tv_nsec) / 1e9;
	pass("flood: %ld PG_STATUS in %.2f s (%.0f/s)", n, dt, (double)n / dt);
	close(fd);
	return 0;
}

int main(int argc, char **argv)
{
	const char *m = argc > 1 ? argv[1] : "";

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!strcmp(m, "numbers"))
		numbers();
	else if (!strcmp(m, "pointers"))
		pointers();
	else if (!strcmp(m, "fuzz") && argc == 4)
		fuzz(atol(argv[2]), strtoull(argv[3], NULL, 0));
	else if (!strcmp(m, "bounds") && argc == 5)
		bounds(argv[2], strtoull(argv[3], NULL, 0), (unsigned int)atoi(argv[4]));
	else if (!strcmp(m, "race") && argc == 3)
		race(atoi(argv[2]));
	else if (!strcmp(m, "privilege"))
		privilege();
	else if (!strcmp(m, "churn") && argc == 7)
		churn(atoi(argv[2]), atoi(argv[3]), argv[4], strtoull(argv[5], NULL, 0),
		      (unsigned int)atoi(argv[6]));
	else if (!strcmp(m, "flood") && argc == 3)
		flood(atol(argv[2]));
	else {
		fprintf(stderr, "usage: see the comment at the top of pghostile.c\n");
		return 2;
	}
	return fails != 0;
}
