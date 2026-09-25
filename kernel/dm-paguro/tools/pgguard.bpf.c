// SPDX-License-Identifier: GPL-2.0
/*
 * The view-C guard (INTERFACES 10.4, DESIGN 5b Rule 2): a BPF-LSM program
 * keyed on the claimed images' (dev, ino). Quality of experience, not
 * correctness -- the module's range test is the floor -- so that nobody
 * walking the mounted volume ever meets an EIO from a claimed image:
 *
 *   file_open, file_permission, path_truncate, inode_setattr,
 *   inode_setxattr, inode_removexattr, inode_file_setattr   -> EACCES
 *   inode_unlink, inode_rename (either end), inode_link     -> EBUSY
 *
 * except for one cgroup (the growth service). It also guards itself: its
 * pins (links and the image map) cannot be unlinked, renamed or changed
 * (EPERM), the bpffs holding them cannot be unmounted, its links cannot be
 * fetched by id, and a new file descriptor for its maps -- by id or by pin
 * -- is given only to the exempt cgroup. Only a reboot removes it.
 *
 * CO-RE: the kernel types below are the few fields read, relocated against
 * the running kernel's BTF by libbpf. Built by tools/Makefile.
 */
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1
#define EACCES 13
#define EBUSY 16

typedef __u32 dev_t;
typedef unsigned long size_t;

struct super_block {
	dev_t s_dev;
} __attribute__((preserve_access_index));

struct inode {
	unsigned long i_ino;
	struct super_block *i_sb;
} __attribute__((preserve_access_index));

struct dentry {
	struct inode *d_inode;
} __attribute__((preserve_access_index));

struct vfsmount {
	struct super_block *mnt_sb;
} __attribute__((preserve_access_index));

struct path {
	struct vfsmount *mnt;
	struct dentry *dentry;
} __attribute__((preserve_access_index));

struct file {
	struct inode *f_inode;
} __attribute__((preserve_access_index));

struct bpf_map {
	__u32 id;
} __attribute__((preserve_access_index));

struct iattr;
struct mnt_idmap;
struct file_kattr;

/* Shared with pgguard.c. */
struct pg_key {
	__u64 dev;			/* kernel dev_t: major << 20 | minor */
	__u64 ino;
};

#define PG_IMAGE 1			/* a claimed image */
#define PG_SELF 2			/* one of our own pins */

struct pg_val {
	__u32 kind;
	__u32 claim;
};

#define PG_MAX_IDS 16

struct pg_cfg {
	__u64 exempt_cgroup;		/* 0: none */
	__u64 bpffs_dev;
	__u32 link_ids[PG_MAX_IDS];
	__u32 map_ids[4];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct pg_key);
	__type(value, struct pg_val);
} pg_images SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct pg_cfg);
} pg_cfg SEC(".maps");

/* Denials so far, per hook (for the test and `pgguard status`). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 16);
	__type(key, __u32);
	__type(value, __u64);
} pg_hits SEC(".maps");

char LICENSE[] SEC("license") = "GPL";

static __always_inline struct pg_cfg *cfg(void)
{
	__u32 zero = 0;

	return bpf_map_lookup_elem(&pg_cfg, &zero);
}

static __always_inline int exempt(void)
{
	struct pg_cfg *c = cfg();

	return c && c->exempt_cgroup &&
	       bpf_get_current_cgroup_id() == c->exempt_cgroup;
}

static __always_inline void hit(__u32 hook)
{
	__u64 *n = bpf_map_lookup_elem(&pg_hits, &hook);

	if (n)
		__sync_fetch_and_add(n, 1);
}

/* 0, PG_IMAGE or PG_SELF for an inode. */
static __always_inline __u32 kind_of(struct inode *inode)
{
	struct pg_key k = {};
	struct pg_val *v;

	if (!inode)
		return 0;
	k.dev = BPF_CORE_READ(inode, i_sb, s_dev);
	k.ino = BPF_CORE_READ(inode, i_ino);
	v = bpf_map_lookup_elem(&pg_images, &k);
	return v ? v->kind : 0;
}

/* The verdict for an operation on `inode`: images refuse with `err` unless
 * the caller is exempt; our own pins refuse everyone with EPERM. */
static __always_inline int judge(struct inode *inode, int err, __u32 hook)
{
	__u32 kind = kind_of(inode);

	if (kind == PG_SELF) {
		hit(hook);
		return -EPERM;
	}
	if (kind == PG_IMAGE && !exempt()) {
		hit(hook);
		return -err;
	}
	return 0;
}

static __always_inline struct inode *d_inode(struct dentry *d)
{
	return d ? BPF_CORE_READ(d, d_inode) : 0;
}

SEC("lsm/file_open")
int BPF_PROG(pg_file_open, struct file *file)
{
	struct inode *i = BPF_CORE_READ(file, f_inode);

	/* Reading one of our pins (bpftool) is harmless. */
	if (kind_of(i) == PG_SELF)
		return 0;
	return judge(i, EACCES, 0);
}

SEC("lsm/file_permission")
int BPF_PROG(pg_file_permission, struct file *file, int mask)
{
	struct inode *i = BPF_CORE_READ(file, f_inode);

	if (kind_of(i) == PG_SELF)
		return 0;
	return judge(i, EACCES, 1);
}

SEC("lsm/path_truncate")
int BPF_PROG(pg_path_truncate, const struct path *path)
{
	return judge(d_inode(BPF_CORE_READ(path, dentry)), EACCES, 2);
}

SEC("lsm/inode_setattr")
int BPF_PROG(pg_inode_setattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     struct iattr *attr)
{
	return judge(d_inode(dentry), EACCES, 3);
}

SEC("lsm/inode_unlink")
int BPF_PROG(pg_inode_unlink, struct inode *dir, struct dentry *dentry)
{
	return judge(d_inode(dentry), EBUSY, 4);
}

SEC("lsm/inode_rename")
int BPF_PROG(pg_inode_rename, struct inode *old_dir, struct dentry *old_dentry,
	     struct inode *new_dir, struct dentry *new_dentry)
{
	int r = judge(d_inode(old_dentry), EBUSY, 5);

	/* Renaming something over an image would unlink it. */
	return r ? r : judge(d_inode(new_dentry), EBUSY, 5);
}

SEC("lsm/inode_link")
int BPF_PROG(pg_inode_link, struct dentry *old_dentry, struct inode *dir,
	     struct dentry *new_dentry)
{
	return judge(d_inode(old_dentry), EBUSY, 6);
}

SEC("lsm/inode_setxattr")
int BPF_PROG(pg_inode_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	return judge(d_inode(dentry), EACCES, 7);
}

SEC("lsm/inode_removexattr")
int BPF_PROG(pg_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	return judge(d_inode(dentry), EACCES, 8);
}

/* Linux >= 6.17 (file_setattr(2), FS_IOC_FSSETXATTR); loaded when present. */
SEC("lsm/inode_file_setattr")
int BPF_PROG(pg_inode_file_setattr, struct dentry *dentry, struct file_kattr *fa)
{
	return judge(d_inode(dentry), EACCES, 9);
}

SEC("lsm/sb_umount")
int BPF_PROG(pg_sb_umount, struct vfsmount *mnt, int flags)
{
	struct pg_cfg *c = cfg();

	if (c && c->bpffs_dev && BPF_CORE_READ(mnt, mnt_sb, s_dev) == c->bpffs_dev) {
		hit(10);
		return -EPERM;
	}
	return 0;
}

/* No file descriptor for one of our links by id: nothing can detach them. */
SEC("lsm/bpf")
int BPF_PROG(pg_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
	struct pg_cfg *c = cfg();
	__u32 id;
	int i;

	if (!c || cmd != BPF_LINK_GET_FD_BY_ID)
		return 0;
	id = BPF_CORE_READ(attr, link_id);
	for (i = 0; i < PG_MAX_IDS; i++)
		if (id && c->link_ids[i] == id) {
			hit(11);
			return -EPERM;
		}
	return 0;
}

/* A new file descriptor for our maps (by id, or from the image map's pin)
 * only for the exempt cgroup: nobody else can edit the image list. */
SEC("lsm/bpf_map")
int BPF_PROG(pg_bpf_map, struct bpf_map *map, unsigned int fmode)
{
	struct pg_cfg *c = cfg();
	__u32 id = BPF_CORE_READ(map, id);
	int i;

	if (!c || exempt())
		return 0;
	for (i = 0; i < 4; i++)
		if (id && c->map_ids[i] == id) {
			hit(12);
			return -EPERM;
		}
	return 0;
}
