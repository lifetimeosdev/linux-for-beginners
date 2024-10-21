/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * include/asm-generic/seccomp.h
 *
 * Copyright (C) 2014 Linaro Limited
 * Author: AKASHI Takahiro <takahiro.akashi@linaro.org>
 */
#ifndef _ASM_GENERIC_SECCOMP_H
#define _ASM_GENERIC_SECCOMP_H

#include <linux/unistd.h>

#if defined(CONFIG_COMPAT) && !defined(__NR_seccomp_read_32)
#define __NR_seccomp_read_32		__NR_read
#define __NR_seccomp_write_32		__NR_write
#define __NR_seccomp_exit_32		__NR_exit
#ifndef __NR_seccomp_sigreturn_32
#define __NR_seccomp_sigreturn_32	__NR_rt_sigreturn
#endif
#endif /* CONFIG_COMPAT && ! already defined */

#define __NR_seccomp_read		__NR_read
#define __NR_seccomp_write		__NR_write
#define __NR_seccomp_exit		__NR_exit
#ifndef __NR_seccomp_sigreturn
#define __NR_seccomp_sigreturn		__NR_rt_sigreturn
#endif

#endif /* _ASM_GENERIC_SECCOMP_H */
