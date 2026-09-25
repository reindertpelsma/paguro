// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * pgguard: loads the view-C guard (pgguard.bpf.c; INTERFACES 10.4) and
 * manages its image list.
 *
 *   pgguard load [--exempt-cgroup <dir>] [--pin <bpffs-dir>] [<image>...]
 *        load, attach every hook, pin the links and the image map under the
 *        pin directory (default /sys/fs/bpf/paguro), protect them, and guard
 *        the images named. Needs lsm=...,bpf.
 *   pgguard add <image> [<claim>]   (from the exempt cgroup only, afterwards)
 *   pgguard del <image>             (likewise)
 *   pgguard status                  denials per hook
 *   pgguard try <path>              test helper: every operation the guard
 *                                   covers, one "<op> <result>" line each
 *
 * The object is embedded (ld -r -b binary); libbpf is linked statically.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

extern const char _binary_pgguard_bpf_o_start[], _binary_pgguard_bpf_o_end[];

struct pg_key {
	__u64 dev;
	__u64 ino;
};

struct pg_val {
	__u32 kind;
	__u32 claim;
};

#define PG_IMAGE 1
#define PG_SELF 2
#define PG_MAX_IDS 16

struct pg_cfg {
	__u64 exempt_cgroup;
	__u64 bpffs_dev;
	__u32 link_ids[PG_MAX_IDS];
	__u32 map_ids[4];
};

static const char *pin = "/sys/fs/bpf/paguro";

static void die(const char *what)
{
	fprintf(stderr, "pgguard: %s: %s\n", what, strerror(errno));
	exit(1);
}

/* (dev, ino) as the kernel sees them: dev_t is major << 20 | minor. */
static struct pg_key key_of(const char *path)
{
	struct pg_key k = { 0 };
	struct stat st;

	if (stat(path, &st))
		die(path);
	k.dev = (__u64)major(st.st_dev) << 20 | minor(st.st_dev);
	k.ino = st.st_ino;
	return k;
}

static int images_fd(void)
{
	char p[512];
	int fd;

	snprintf(p, sizeof(p), "%s/images", pin);
	fd = bpf_obj_get(p);
	if (fd < 0)
		die("the image map (only the exempt cgroup may change it)");
	return fd;
}

static int add(int fd, const char *path, __u32 kind, __u32 claim)
{
	struct pg_key k = key_of(path);
	struct pg_val v = { .kind = kind, .claim = claim };

	if (bpf_map_update_elem(fd, &k, &v, BPF_ANY))
		die(path);
	return 0;
}

static int has_func(const char *name)
{
	struct btf *btf = btf__load_vmlinux_btf();
	int r;

	if (!btf)
		return 0;
	r = btf__find_by_name_kind(btf, name, BTF_KIND_FUNC) >= 0;
	btf__free(btf);
	return r;
}

static __u32 id_of_map(int fd)
{
	struct bpf_map_info info = { 0 };
	__u32 len = sizeof(info);

	if (bpf_map_get_info_by_fd(fd, &info, &len))
		die("map info");
	return info.id;
}

static int load(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, oo, .object_name = "pgguard");
	struct bpf_object *obj;
	struct bpf_program *prog;
	struct pg_cfg cfg = { 0 };
	const char *exempt = NULL;
	struct stat st;
	char p[512];
	int i, n = 0, cfd, ifd, zero = 0;

	for (i = 0; i < argc; i++) {
		if (!strcmp(argv[i], "--exempt-cgroup") && i + 1 < argc)
			exempt = argv[++i];
		else if (!strcmp(argv[i], "--pin") && i + 1 < argc)
			pin = argv[++i];
		else
			break;
	}
	argc -= i;
	argv += i;
	if (exempt) {
		if (stat(exempt, &st))
			die(exempt);
		cfg.exempt_cgroup = st.st_ino;	/* cgroup v2: the id */
	}
	if (mkdir(pin, 0700) && errno != EEXIST)
		die(pin);
	if (stat(pin, &st))
		die(pin);
	cfg.bpffs_dev = (__u64)major(st.st_dev) << 20 | minor(st.st_dev);
	obj = bpf_object__open_mem(_binary_pgguard_bpf_o_start,
				   _binary_pgguard_bpf_o_end - _binary_pgguard_bpf_o_start, &oo);
	if (!obj)
		die("open the BPF object");
	if (!has_func("bpf_lsm_inode_file_setattr")) {
		prog = bpf_object__find_program_by_name(obj, "pg_inode_file_setattr");
		if (prog)
			bpf_program__set_autoload(prog, false);
		fprintf(stderr, "pgguard: no inode_file_setattr hook on this kernel (< 6.17)\n");
	}
	if (bpf_object__load(obj))
		die("load (is the kernel booted with lsm=...,bpf?)");
	cfd = bpf_map__fd(bpf_object__find_map_by_name(obj, "pg_cfg"));
	ifd = bpf_map__fd(bpf_object__find_map_by_name(obj, "pg_images"));
	cfg.map_ids[0] = id_of_map(ifd);
	cfg.map_ids[1] = id_of_map(cfd);
	if (bpf_map_update_elem(cfd, &zero, &cfg, BPF_ANY))
		die("configure");
	for (i = 0; i < argc; i++)
		add(ifd, argv[i], PG_IMAGE, 0);
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link_info info = { 0 };
		__u32 len = sizeof(info);
		struct bpf_link *l;

		if (!bpf_program__autoload(prog))
			continue;
		l = bpf_program__attach_lsm(prog);
		if (!l)
			die(bpf_program__name(prog));
		if (bpf_link_get_info_by_fd(bpf_link__fd(l), &info, &len))
			die("link info");
		if (n < PG_MAX_IDS)
			cfg.link_ids[n++] = info.id;
		snprintf(p, sizeof(p), "%s/%s", pin, bpf_program__name(prog));
		if (bpf_link__pin(l, p))
			die(p);
		add(ifd, p, PG_SELF, 0);
	}
	snprintf(p, sizeof(p), "%s/images", pin);
	if (bpf_obj_pin(ifd, p))
		die(p);
	add(ifd, p, PG_SELF, 0);
	if (bpf_map_update_elem(cfd, &zero, &cfg, BPF_ANY))
		die("configure");
	printf("links:");
	for (i = 0; i < n; i++)
		printf(" %u", cfg.link_ids[i]);
	printf("\nguard: %d hooks attached and pinned in %s; %d images; exempt cgroup %llu\n",
	       n, pin, argc, (unsigned long long)cfg.exempt_cgroup);
	return 0;
}

static int status(void)
{
	static const char *const hook[] = {
		"file_open", "file_permission", "path_truncate", "inode_setattr",
		"inode_unlink", "inode_rename", "inode_link", "inode_setxattr",
		"inode_removexattr", "inode_file_setattr", "sb_umount", "bpf",
		"bpf_map",
	};
	__u32 id = 0, k;

	while (!bpf_map_get_next_id(id, &id)) {
		struct bpf_map_info info = { 0 };
		__u32 len = sizeof(info);
		int fd = bpf_map_get_fd_by_id(id);

		if (fd < 0)
			continue;
		if (!bpf_map_get_info_by_fd(fd, &info, &len) &&
		    !strcmp(info.name, "pg_hits")) {
			for (k = 0; k < sizeof(hook) / sizeof(hook[0]); k++) {
				__u64 v = 0;

				bpf_map_lookup_elem(fd, &k, &v);
				printf("%s %llu\n", hook[k], (unsigned long long)v);
			}
			close(fd);
			return 0;
		}
		close(fd);
	}
	fprintf(stderr, "pgguard: not loaded\n");
	return 1;
}

static const char *res(int r)
{
	static char buf[32];

	if (r >= 0)
		return "ok";
	switch (errno) {
	case EACCES: return "EACCES";
	case EPERM: return "EPERM";
	case EBUSY: return "EBUSY";
	case EIO: return "EIO";
	case ENOENT: return "ENOENT";
	case EOPNOTSUPP: return "EOPNOTSUPP";
	case ENODATA: return "ENODATA";
	case EINVAL: return "EINVAL";
	default:
		snprintf(buf, sizeof(buf), "errno%d", errno);
		return buf;
	}
}

/* Every operation the guard covers, on `path`; nothing is left changed if
 * one unexpectedly succeeds except what that operation did. */
static int try(const char *path)
{
	char dir[512], other[600], tmp[600];
	struct { struct file_handle h; unsigned char f[64]; } fh;
	char *slash;
	int fd, mnt, r;

	snprintf(dir, sizeof(dir), "%s", path);
	slash = strrchr(dir, '/');
	if (slash)
		*slash = 0;
	else
		strcpy(dir, ".");
	snprintf(other, sizeof(other), "%s/.pgguard-renamed", dir);
	snprintf(tmp, sizeof(tmp), "%s/.pgguard-tmp", dir);
#define T(name, expr) do { r = (expr); printf("%s %s\n", name, res(r)); \
	if (r >= 0 && !strncmp(name, "open", 4)) close(r); } while (0)
	T("open_read", open(path, O_RDONLY));
	T("open_write", open(path, O_WRONLY));
	T("open_trunc", open(path, O_WRONLY | O_TRUNC));
	T("open_direct", open(path, O_RDONLY | O_DIRECT));
	T("truncate", truncate(path, 0));
	T("chmod", chmod(path, 0600));
	T("chown", chown(path, 1, 1));
	T("utimes", utimensat(AT_FDCWD, path, NULL, 0));
	T("setxattr", setxattr(path, "user.pgguard", "x", 1, 0));
	T("removexattr", removexattr(path, "user.pgguard"));
	T("link", link(path, other));
	T("rename", rename(path, other));
	fd = open(tmp, O_WRONLY | O_CREAT, 0600);
	if (fd >= 0)
		close(fd);
	T("rename_over", rename(tmp, path));
	unlink(tmp);
	T("unlink", unlink(path));
	fh.h.handle_bytes = sizeof(fh.f);
	if (name_to_handle_at(AT_FDCWD, path, &fh.h, &mnt, 0) == 0) {
		int mfd = open(dir, O_RDONLY | O_DIRECTORY);

		T("open_by_handle", open_by_handle_at(mfd, &fh.h, O_RDONLY));
		close(mfd);
	} else {
		printf("open_by_handle %s\n", res(-1));
	}
	return 0;
}

int main(int argc, char **argv)
{
	const char *cmd = argc > 1 ? argv[1] : "";

	if (!strcmp(cmd, "load"))
		return load(argc - 2, argv + 2);
	if (!strcmp(cmd, "add") && (argc == 3 || argc == 4))
		return add(images_fd(), argv[2], PG_IMAGE,
			   argc == 4 ? (__u32)atoi(argv[3]) : 0);
	if (!strcmp(cmd, "del") && argc == 3) {
		struct pg_key k = key_of(argv[2]);

		if (bpf_map_delete_elem(images_fd(), &k))
			die(argv[2]);
		return 0;
	}
	if (!strcmp(cmd, "status"))
		return status();
	if (!strcmp(cmd, "try") && argc == 3)
		return try(argv[2]);
	fprintf(stderr, "usage: see the comment at the top of pgguard.c\n");
	return 2;
}
