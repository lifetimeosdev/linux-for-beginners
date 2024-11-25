// SPDX-License-Identifier: GPL-2.0
#include <linux/syscalls.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/statfs.h>
#include <linux/security.h>
#include <linux/uaccess.h>
#include <linux/compat.h>
#include "internal.h"

static int flags_by_mnt(int mnt_flags)
{
	int flags = 0;

	if (mnt_flags & MNT_READONLY)
		flags |= ST_RDONLY;
	if (mnt_flags & MNT_NOSUID)
		flags |= ST_NOSUID;
	if (mnt_flags & MNT_NODEV)
		flags |= ST_NODEV;
	if (mnt_flags & MNT_NOEXEC)
		flags |= ST_NOEXEC;
	if (mnt_flags & MNT_NOATIME)
		flags |= ST_NOATIME;
	if (mnt_flags & MNT_NODIRATIME)
		flags |= ST_NODIRATIME;
	if (mnt_flags & MNT_RELATIME)
		flags |= ST_RELATIME;
	if (mnt_flags & MNT_NOSYMFOLLOW)
		flags |= ST_NOSYMFOLLOW;
	return flags;
}

static int flags_by_sb(int s_flags)
{
	int flags = 0;
	if (s_flags & SB_SYNCHRONOUS)
		flags |= ST_SYNCHRONOUS;
	if (s_flags & SB_MANDLOCK)
		flags |= ST_MANDLOCK;
	if (s_flags & SB_RDONLY)
		flags |= ST_RDONLY;
	return flags;
}

static int calculate_f_flags(struct vfsmount *mnt)
{
	return ST_VALID | flags_by_mnt(mnt->mnt_flags) |
		flags_by_sb(mnt->mnt_sb->s_flags);
}

static int statfs_by_dentry(struct dentry *dentry, struct kstatfs *buf)
{
	int retval;

	if (!dentry->d_sb->s_op->statfs)
		return -ENOSYS;

	memset(buf, 0, sizeof(*buf));
	// retval = security_sb_statfs(dentry);
	// if (retval)
	// 	return retval;
	retval = dentry->d_sb->s_op->statfs(dentry, buf);
	if (retval == 0 && buf->f_frsize == 0)
		buf->f_frsize = buf->f_bsize;
	return retval;
}

int vfs_get_fsid(struct dentry *dentry, __kernel_fsid_t *fsid)
{
	struct kstatfs st;
	int error;

	error = statfs_by_dentry(dentry, &st);
	if (error)
		return error;

	*fsid = st.f_fsid;
	return 0;
}
EXPORT_SYMBOL(vfs_get_fsid);

int vfs_statfs(const struct path *path, struct kstatfs *buf)
{
	int error;

	error = statfs_by_dentry(path->dentry, buf);
	if (!error)
		buf->f_flags = calculate_f_flags(path->mnt);
	return error;
}
EXPORT_SYMBOL(vfs_statfs);

int user_statfs(const char __user *pathname, struct kstatfs *st)
{
	struct path path;
	int error;
	unsigned int lookup_flags = LOOKUP_FOLLOW|LOOKUP_AUTOMOUNT;
retry:
	error = user_path_at(AT_FDCWD, pathname, lookup_flags, &path);
	if (!error) {
		error = vfs_statfs(&path, st);
		path_put(&path);
		if (retry_estale(error, lookup_flags)) {
			lookup_flags |= LOOKUP_REVAL;
			goto retry;
		}
	}
	return error;
}

int fd_statfs(int fd, struct kstatfs *st)
{
	struct fd f = fdget_raw(fd);
	int error = -EBADF;
	if (f.file) {
		error = vfs_statfs(&f.file->f_path, st);
		fdput(f);
	}
	return error;
}

static int do_statfs_native(struct kstatfs *st, struct statfs __user *p)
{
	struct statfs buf;

	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		memset(&buf, 0, sizeof(buf));
		if (sizeof buf.f_blocks == 4) {
			if ((st->f_blocks | st->f_bfree | st->f_bavail |
			     st->f_bsize | st->f_frsize) &
			    0xffffffff00000000ULL)
				return -EOVERFLOW;
			/*
			 * f_files and f_ffree may be -1; it's okay to stuff
			 * that into 32 bits
			 */
			if (st->f_files != -1 &&
			    (st->f_files & 0xffffffff00000000ULL))
				return -EOVERFLOW;
			if (st->f_ffree != -1 &&
			    (st->f_ffree & 0xffffffff00000000ULL))
				return -EOVERFLOW;
		}

		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

static int do_statfs64(struct kstatfs *st, struct statfs64 __user *p)
{
	struct statfs64 buf;
	if (sizeof(buf) == sizeof(*st))
		memcpy(&buf, st, sizeof(*st));
	else {
		memset(&buf, 0, sizeof(buf));
		buf.f_type = st->f_type;
		buf.f_bsize = st->f_bsize;
		buf.f_blocks = st->f_blocks;
		buf.f_bfree = st->f_bfree;
		buf.f_bavail = st->f_bavail;
		buf.f_files = st->f_files;
		buf.f_ffree = st->f_ffree;
		buf.f_fsid = st->f_fsid;
		buf.f_namelen = st->f_namelen;
		buf.f_frsize = st->f_frsize;
		buf.f_flags = st->f_flags;
	}
	if (copy_to_user(p, &buf, sizeof(buf)))
		return -EFAULT;
	return 0;
}

static inline long __do_sys_statfs(const char *pathname, struct statfs *buf)
{
	struct kstatfs st;
	int error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

long __arm64_sys_statfs(const struct pt_regs *regs)
{
	long ret = __do_sys_statfs((const char *)regs->regs[0], (struct statfs *)regs->regs[1]);
	return ret;
}

static inline long __do_sys_statfs64(const char *pathname, size_t sz, struct statfs64 *buf)
{
	struct kstatfs st;
	int error;
	if (sz != sizeof(*buf))
		return -EINVAL;
	error = user_statfs(pathname, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

long __arm64_sys_statfs64(const struct pt_regs *regs)
{
	long ret = __do_sys_statfs64((const char *)regs->regs[0], (size_t)regs->regs[1], (struct statfs64 *)regs->regs[2]);
	return ret;
}

static inline long __do_sys_fstatfs(unsigned int fd, struct statfs *buf)
{
	struct kstatfs st;
	int error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs_native(&st, buf);
	return error;
}

long __arm64_sys_fstatfs(const struct pt_regs *regs)
{
	long ret = __do_sys_fstatfs((unsigned int)regs->regs[0], (struct statfs *)regs->regs[1]);
	return ret;
}

static inline long __do_sys_fstatfs64(unsigned int fd, size_t sz, struct statfs64 *buf)
{
	struct kstatfs st;
	int error;

	if (sz != sizeof(*buf))
		return -EINVAL;

	error = fd_statfs(fd, &st);
	if (!error)
		error = do_statfs64(&st, buf);
	return error;
}

long __arm64_sys_fstatfs64(const struct pt_regs *regs)
{
	long ret = __do_sys_fstatfs64((unsigned int)regs->regs[0], (size_t)regs->regs[1], (struct statfs64 *)regs->regs[2]);
	return ret;
}

static int vfs_ustat(dev_t dev, struct kstatfs *sbuf)
{
	struct super_block *s = user_get_super(dev);
	int err;
	if (!s)
		return -EINVAL;

	err = statfs_by_dentry(s->s_root, sbuf);
	drop_super(s);
	return err;
}

static inline long __do_sys_ustat(unsigned dev, struct ustat *ubuf)
{
	struct ustat tmp;
	struct kstatfs sbuf;
	int err = vfs_ustat(new_decode_dev(dev), &sbuf);
	if (err)
		return err;

	memset(&tmp,0,sizeof(struct ustat));
	tmp.f_tfree = sbuf.f_bfree;
	tmp.f_tinode = sbuf.f_ffree;

	return copy_to_user(ubuf, &tmp, sizeof(struct ustat)) ? -EFAULT : 0;
}

long __arm64_sys_ustat(const struct pt_regs *regs)
{
	long ret = __do_sys_ustat((unsigned)regs->regs[0], (struct ustat *)regs->regs[1]);
	return ret;
}
