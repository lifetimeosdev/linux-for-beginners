/* SPDX-License-Identifier: GPL-2.0 */
/*
 * syscall_wrapper.h - arm64 specific wrappers to syscall definitions
 *
 * Based on arch/x86/include/asm_syscall_wrapper.h
 */

#ifndef __ASM_SYSCALL_WRAPPER_H
#define __ASM_SYSCALL_WRAPPER_H

#include <asm/ptrace.h>

#define SC_ARM64_REGS_TO_ARGS(x, ...)				\
	__MAP(x,__SC_ARGS					\
	      ,,regs->regs[0],,regs->regs[1],,regs->regs[2]	\
	      ,,regs->regs[3],,regs->regs[4],,regs->regs[5])

#define __SYSCALL_DEFINEx(x, name, ...)						\
	asmlinkage long __arm64_sys##name(const struct pt_regs *regs);		\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__));		\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__));	\
	asmlinkage long __arm64_sys##name(const struct pt_regs *regs)		\
	{									\
		return __se_sys##name(SC_ARM64_REGS_TO_ARGS(x,__VA_ARGS__));	\
	}									\
	static long __se_sys##name(__MAP(x,__SC_LONG,__VA_ARGS__))		\
	{									\
		long ret = __do_sys##name(__MAP(x,__SC_CAST,__VA_ARGS__));	\
		__MAP(x,__SC_TEST,__VA_ARGS__);					\
		__PROTECT(x, ret,__MAP(x,__SC_ARGS,__VA_ARGS__));		\
		return ret;							\
	}									\
	static inline long __do_sys##name(__MAP(x,__SC_DECL,__VA_ARGS__))

#define SYSCALL_DEFINE0(sname)							\
	asmlinkage long __arm64_sys_##sname(const struct pt_regs *__unused);	\
	asmlinkage long __arm64_sys_##sname(const struct pt_regs *__unused)

#define COND_SYSCALL(name)							\
	asmlinkage long __weak __arm64_sys_##name(const struct pt_regs *regs)	\
	{									\
		return sys_ni_syscall();					\
	}

#define SYS_NI(name) SYSCALL_ALIAS(__arm64_sys_##name, sys_ni_posix_timers);

#endif /* __ASM_SYSCALL_WRAPPER_H */
