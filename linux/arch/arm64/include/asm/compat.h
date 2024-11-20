/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_COMPAT_H
#define __ASM_COMPAT_H

#include <asm-generic/compat.h>

static inline int is_compat_thread(struct thread_info *thread)
{
	return 0;
}

#endif /* __ASM_COMPAT_H */
