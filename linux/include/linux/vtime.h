/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_KERNEL_VTIME_H
#define _LINUX_KERNEL_VTIME_H

#include <linux/context_tracking_state.h>

struct task_struct;

/*
 * vtime_accounting_enabled_this_cpu() definitions/declarations
 */
static inline bool vtime_accounting_enabled_cpu(int cpu) {return false; }
static inline bool vtime_accounting_enabled_this_cpu(void) { return false; }

#endif /* _LINUX_KERNEL_VTIME_H */
