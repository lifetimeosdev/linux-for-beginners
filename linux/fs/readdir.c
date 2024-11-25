// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/readdir.c
 *
 *  Copyright (C) 1995  Linus Torvalds
 */

#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/time.h>
#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/stat.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/fsnotify.h>
#include <linux/dirent.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <linux/unistd.h>
#include <linux/compat.h>
#include <linux/uaccess.h>

#include <asm/unaligned.h>

/*
 * Note the "unsafe_put_user() semantics: we goto a
 * label for errors.
 */
#define unsafe_copy_dirent_name(_dst, _src, _len, label) do {	\
	char __user *dst = (_dst);				\
	const char *src = (_src);				\
	size_t len = (_len);					\
	unsafe_put_user(0, dst+len, label);			\
	unsafe_copy_to_user(dst, src, len, label);		\
} while (0)


int iterate_dir(struct file *file, struct dir_context *ctx)
{
	struct inode *inode = file_inode(file);
	bool shared = false;
	int res = -ENOTDIR;
	if (file->f_op->iterate_shared)
		shared = true;
	else if (!file->f_op->iterate)
		goto out;

	// res = security_file_permission(file, MAY_READ);
	// if (res)
	// 	goto out;

	if (shared)
		res = down_read_killable(&inode->i_rwsem);
	else
		res = down_write_killable(&inode->i_rwsem);
	if (res)
		goto out;

	res = -ENOENT;
	if (!IS_DEADDIR(inode)) {
		ctx->pos = file->f_pos;
		if (shared)
			res = file->f_op->iterate_shared(file, ctx);
		else
			res = file->f_op->iterate(file, ctx);
		file->f_pos = ctx->pos;
		fsnotify_access(file);
		file_accessed(file);
	}
	if (shared)
		inode_unlock_shared(inode);
	else
		inode_unlock(inode);
out:
	return res;
}
EXPORT_SYMBOL(iterate_dir);

/*
 * POSIX says that a dirent name cannot contain NULL or a '/'.
 *
 * It's not 100% clear what we should really do in this case.
 * The filesystem is clearly corrupted, but returning a hard
 * error means that you now don't see any of the other names
 * either, so that isn't a perfect alternative.
 *
 * And if you return an error, what error do you use? Several
 * filesystems seem to have decided on EUCLEAN being the error
 * code for EFSCORRUPTED, and that may be the error to use. Or
 * just EIO, which is perhaps more obvious to users.
 *
 * In order to see the other file names in the directory, the
 * caller might want to make this a "soft" error: skip the
 * entry, and return the error at the end instead.
 *
 * Note that this should likely do a "memchr(name, 0, len)"
 * check too, since that would be filesystem corruption as
 * well. However, that case can't actually confuse user space,
 * which has to do a strlen() on the name anyway to find the
 * filename length, and the above "soft error" worry means
 * that it's probably better left alone until we have that
 * issue clarified.
 *
 * Note the PATH_MAX check - it's arbitrary but the real
 * kernel limit on a possible path component, not NAME_MAX,
 * which is the technical standard limit.
 */
static int verify_dirent_name(const char *name, int len)
{
	if (len <= 0 || len >= PATH_MAX)
		return -EIO;
	if (memchr(name, '/', len))
		return -EIO;
	return 0;
}

/*
 * New, all-improved, singing, dancing, iBCS2-compliant getdents()
 * interface. 
 */
struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

struct getdents_callback {
	struct dir_context ctx;
	struct linux_dirent __user * current_dir;
	int prev_reclen;
	int count;
	int error;
};

static int filldir(struct dir_context *ctx, const char *name, int namlen,
		   loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent __user *dirent, *prev;
	struct getdents_callback *buf =
		container_of(ctx, struct getdents_callback, ctx);
	unsigned long d_ino;
	int reclen = ALIGN(offsetof(struct linux_dirent, d_name) + namlen + 2,
		sizeof(long));
	int prev_reclen;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return buf->error;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	d_ino = ino;
	if (sizeof(d_ino) < sizeof(ino) && d_ino != ino) {
		buf->error = -EOVERFLOW;
		return -EOVERFLOW;
	}
	prev_reclen = buf->prev_reclen;
	if (prev_reclen && signal_pending(current))
		return -EINTR;
	dirent = buf->current_dir;
	prev = (void __user *) dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(d_ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, (char __user *) dirent + reclen - 1, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();

	buf->current_dir = (void __user *)dirent + reclen;
	buf->prev_reclen = reclen;
	buf->count -= reclen;
	return 0;
efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

static inline long __do_sys_getdents(unsigned int fd, struct linux_dirent *dirent,
				     unsigned int count)
{
	struct fd f;
	struct getdents_callback buf = {
		.ctx.actor = filldir,
		.count = count,
		.current_dir = dirent
	};
	int error;

	f = fdget_pos(fd);
	if (!f.file)
		return -EBADF;

	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct linux_dirent __user * lastdirent;
		lastdirent = (void __user *)buf.current_dir - buf.prev_reclen;

		if (put_user(buf.ctx.pos, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput_pos(f);
	return error;
}

long __arm64_sys_getdents(const struct pt_regs *regs)
{
	long ret = __do_sys_getdents((unsigned int)regs->regs[0], (struct linux_dirent *)regs->regs[1],
				     (unsigned int)regs->regs[2]);
	return ret;
}

struct getdents_callback64 {
	struct dir_context ctx;
	struct linux_dirent64 __user * current_dir;
	int prev_reclen;
	int count;
	int error;
};

static int filldir64(struct dir_context *ctx, const char *name, int namlen,
		     loff_t offset, u64 ino, unsigned int d_type)
{
	struct linux_dirent64 __user *dirent, *prev;
	struct getdents_callback64 *buf =
		container_of(ctx, struct getdents_callback64, ctx);
	int reclen = ALIGN(offsetof(struct linux_dirent64, d_name) + namlen + 1,
		sizeof(u64));
	int prev_reclen;

	buf->error = verify_dirent_name(name, namlen);
	if (unlikely(buf->error))
		return buf->error;
	buf->error = -EINVAL;	/* only used if we fail.. */
	if (reclen > buf->count)
		return -EINVAL;
	prev_reclen = buf->prev_reclen;
	if (prev_reclen && signal_pending(current))
		return -EINTR;
	dirent = buf->current_dir;
	prev = (void __user *)dirent - prev_reclen;
	if (!user_write_access_begin(prev, reclen + prev_reclen))
		goto efault;

	/* This might be 'dirent->d_off', but if so it will get overwritten */
	unsafe_put_user(offset, &prev->d_off, efault_end);
	unsafe_put_user(ino, &dirent->d_ino, efault_end);
	unsafe_put_user(reclen, &dirent->d_reclen, efault_end);
	unsafe_put_user(d_type, &dirent->d_type, efault_end);
	unsafe_copy_dirent_name(dirent->d_name, name, namlen, efault_end);
	user_write_access_end();

	buf->prev_reclen = reclen;
	buf->current_dir = (void __user *)dirent + reclen;
	buf->count -= reclen;
	return 0;

efault_end:
	user_write_access_end();
efault:
	buf->error = -EFAULT;
	return -EFAULT;
}

static inline long __do_sys_getdents64(unsigned int fd, struct linux_dirent64 *dirent,
				       unsigned int count)
{
	struct fd f;
	struct getdents_callback64 buf = {
		.ctx.actor = filldir64,
		.count = count,
		.current_dir = dirent
	};
	int error;

	f = fdget_pos(fd);
	if (!f.file)
		return -EBADF;

	error = iterate_dir(f.file, &buf.ctx);
	if (error >= 0)
		error = buf.error;
	if (buf.prev_reclen) {
		struct linux_dirent64 __user * lastdirent;
		typeof(lastdirent->d_off) d_off = buf.ctx.pos;

		lastdirent = (void __user *) buf.current_dir - buf.prev_reclen;
		if (put_user(d_off, &lastdirent->d_off))
			error = -EFAULT;
		else
			error = count - buf.count;
	}
	fdput_pos(f);
	return error;
}

long __arm64_sys_getdents64(const struct pt_regs *regs)
{
	long ret = __do_sys_getdents64((unsigned int)regs->regs[0], (struct linux_dirent64 *)regs->regs[1],
				       (unsigned int)regs->regs[2]);
	return ret;
}
