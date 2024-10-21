// SPDX-License-Identifier: GPL-2.0
/*
 * sys_ipc() is the old de-multiplexer for the SysV IPC calls.
 *
 * This is really horribly ugly, and new architectures should just wire up
 * the individual syscalls instead.
 */
#include <linux/unistd.h>
#include <linux/syscalls.h>
#include <linux/security.h>
#include <linux/ipc_namespace.h>
#include "util.h"

#ifdef __ARCH_WANT_SYS_IPC
#include <linux/errno.h>
#include <linux/ipc.h>
#include <linux/shm.h>
#include <linux/uaccess.h>

int ksys_ipc(unsigned int call, int first, unsigned long second,
	unsigned long third, void __user * ptr, long fifth)
{
	int version, ret;

	version = call >> 16; /* hack for backward compatibility */
	call &= 0xffff;

	switch (call) {
	case SEMOP:
		return ksys_semtimedop(first, (struct sembuf __user *)ptr,
				       second, NULL);
	case SEMTIMEDOP:
		if (IS_ENABLED(CONFIG_64BIT))
			return ksys_semtimedop(first, ptr, second,
			        (const struct __kernel_timespec __user *)fifth);
		else if (IS_ENABLED(CONFIG_COMPAT_32BIT_TIME))
			return compat_ksys_semtimedop(first, ptr, second,
			        (const struct old_timespec32 __user *)fifth);
		else
			return -ENOSYS;

	case SEMGET:
		return ksys_semget(first, second, third);
	case SEMCTL: {
		unsigned long arg;
		if (!ptr)
			return -EINVAL;
		if (get_user(arg, (unsigned long __user *) ptr))
			return -EFAULT;
		return ksys_old_semctl(first, second, third, arg);
	}

	case MSGSND:
		return ksys_msgsnd(first, (struct msgbuf __user *) ptr,
				  second, third);
	case MSGRCV:
		switch (version) {
		case 0: {
			struct ipc_kludge tmp;
			if (!ptr)
				return -EINVAL;

			if (copy_from_user(&tmp,
					   (struct ipc_kludge __user *) ptr,
					   sizeof(tmp)))
				return -EFAULT;
			return ksys_msgrcv(first, tmp.msgp, second,
					   tmp.msgtyp, third);
		}
		default:
			return ksys_msgrcv(first,
					   (struct msgbuf __user *) ptr,
					   second, fifth, third);
		}
	case MSGGET:
		return ksys_msgget((key_t) first, second);
	case MSGCTL:
		return ksys_old_msgctl(first, second,
				   (struct msqid_ds __user *)ptr);

	case SHMAT:
		switch (version) {
		default: {
			unsigned long raddr;
			ret = do_shmat(first, (char __user *)ptr,
				       second, &raddr, SHMLBA);
			if (ret)
				return ret;
			return put_user(raddr, (unsigned long __user *) third);
		}
		case 1:
			/*
			 * This was the entry point for kernel-originating calls
			 * from iBCS2 in 2.2 days.
			 */
			return -EINVAL;
		}
	case SHMDT:
		return ksys_shmdt((char __user *)ptr);
	case SHMGET:
		return ksys_shmget(first, second, third);
	case SHMCTL:
		return ksys_old_shmctl(first, second,
				   (struct shmid_ds __user *) ptr);
	default:
		return -ENOSYS;
	}
}

SYSCALL_DEFINE6(ipc, unsigned int, call, int, first, unsigned long, second,
		unsigned long, third, void __user *, ptr, long, fifth)
{
	return ksys_ipc(call, first, second, third, ptr, fifth);
}
#endif
