/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_COMPAT_H
#define _LINUX_COMPAT_H
/*
 * These are the type definitions for the architecture specific
 * syscall compatibility layer.
 */

#include <linux/types.h>
#include <linux/time.h>

#include <linux/stat.h>
#include <linux/param.h>	/* for HZ */
#include <linux/sem.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/fs.h>
#include <linux/aio_abi.h>	/* for aio_context_t */
#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/compat.h>

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
/*
 * It may be useful for an architecture to override the definitions of the
 * COMPAT_SYSCALL_DEFINE0 and COMPAT_SYSCALL_DEFINEx() macros, in particular
 * to use a different calling convention for syscalls. To allow for that,
 + the prototypes for the compat_sys_*() functions below will *not* be included
 * if CONFIG_ARCH_HAS_SYSCALL_WRAPPER is enabled.
 */
#include <asm/syscall_wrapper.h>
#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */

#ifndef COMPAT_USE_64BIT_TIME
#define COMPAT_USE_64BIT_TIME 0
#endif

#ifndef __SC_DELOUSE
#define __SC_DELOUSE(t,v) ((__force t)(unsigned long)(v))
#endif

#ifndef COMPAT_SYSCALL_DEFINE0
#define COMPAT_SYSCALL_DEFINE0(name) \
	asmlinkage long compat_sys_##name(void); \
	ALLOW_ERROR_INJECTION(compat_sys_##name, ERRNO); \
	asmlinkage long compat_sys_##name(void)
#endif /* COMPAT_SYSCALL_DEFINE0 */

#define COMPAT_SYSCALL_DEFINE1(name, ...) \
        COMPAT_SYSCALL_DEFINEx(1, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE2(name, ...) \
	COMPAT_SYSCALL_DEFINEx(2, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE3(name, ...) \
	COMPAT_SYSCALL_DEFINEx(3, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE4(name, ...) \
	COMPAT_SYSCALL_DEFINEx(4, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE5(name, ...) \
	COMPAT_SYSCALL_DEFINEx(5, _##name, __VA_ARGS__)
#define COMPAT_SYSCALL_DEFINE6(name, ...) \
	COMPAT_SYSCALL_DEFINEx(6, _##name, __VA_ARGS__)

/*
 * The asmlinkage stub is aliased to a function named __se_compat_sys_*() which
 * sign-extends 32-bit ints to longs whenever needed. The actual work is
 * done within __do_compat_sys_*().
 */
#ifndef COMPAT_SYSCALL_DEFINEx
#define COMPAT_SYSCALL_DEFINEx(x, name, ...)					\
	__diag_push();								\
	__diag_ignore(GCC, 8, "-Wattribute-alias",				\
		      "Type aliasing is used to sanitize syscall arguments");\
	asmlinkage long compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	asmlinkage long compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))	\
		__attribute__((alias(__stringify(__se_compat_sys##name))));	\
	ALLOW_ERROR_INJECTION(compat_sys##name, ERRNO);				\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));\
	asmlinkage long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));	\
	asmlinkage long __se_compat_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))	\
	{									\
		long ret = __do_compat_sys##name(__MAP(x,__SC_DELOUSE,__VA_ARGS__));\
		__MAP(x,__SC_TEST,__VA_ARGS__);					\
		return ret;							\
	}									\
	__diag_pop();								\
	static inline long __do_compat_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))
#endif /* COMPAT_SYSCALL_DEFINEx */

struct compat_iovec {
	compat_uptr_t	iov_base;
	compat_size_t	iov_len;
};

#define is_compat_task() (0)
/* Ensure no one redefines in_compat_syscall() under !CONFIG_COMPAT */
#define in_compat_syscall in_compat_syscall
static inline bool in_compat_syscall(void) { return false; }

/*
 * Some legacy ABIs like the i386 one use less than natural alignment for 64-bit
 * types, and will need special compat treatment for that.  Most architectures
 * don't need that special handling even for compat syscalls.
 */
#ifndef compat_need_64bit_alignment_fixup
#define compat_need_64bit_alignment_fixup()		false
#endif

/*
 * A pointer passed in from user mode. This should not
 * be used for syscall parameters, just declare them
 * as pointers because the syscall entry code will have
 * appropriately converted them already.
 */
#ifndef compat_ptr
static inline void __user *compat_ptr(compat_uptr_t uptr)
{
	return (void __user *)(unsigned long)uptr;
}
#endif

static inline compat_uptr_t ptr_to_compat(void __user *uptr)
{
	return (u32)(unsigned long)uptr;
}

#endif /* _LINUX_COMPAT_H */
