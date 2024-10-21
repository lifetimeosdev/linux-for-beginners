/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_SIGNAL32_H
#define __ASM_SIGNAL32_H

static inline int compat_setup_frame(int usid, struct ksignal *ksig,
				     sigset_t *set, struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline int compat_setup_rt_frame(int usig, struct ksignal *ksig, sigset_t *set,
					struct pt_regs *regs)
{
	return -ENOSYS;
}

static inline void compat_setup_restart_syscall(struct pt_regs *regs)
{
}
#endif /* __ASM_SIGNAL32_H */
