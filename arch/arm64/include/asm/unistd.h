/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */

#define __ARCH_WANT_SYS_CLONE

#ifndef __COMPAT_SYSCALL_NR
#include <uapi/asm/unistd.h>
#endif

#define NR_syscalls (__NR_syscalls)
