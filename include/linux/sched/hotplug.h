/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_SCHED_HOTPLUG_H
#define _LINUX_SCHED_HOTPLUG_H

/*
 * Scheduler interfaces for hotplug CPU support:
 */

extern int sched_cpu_starting(unsigned int cpu);
extern int sched_cpu_activate(unsigned int cpu);
extern int sched_cpu_deactivate(unsigned int cpu);

# define sched_cpu_dying	NULL

static inline void idle_task_exit(void) {}

#endif /* _LINUX_SCHED_HOTPLUG_H */
