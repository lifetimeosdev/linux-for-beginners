/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_HW_BREAKPOINT_H
#define _LINUX_HW_BREAKPOINT_H

#include <linux/perf_event.h>
#include <uapi/linux/hw_breakpoint.h>

static inline int __init init_hw_breakpoint(void) { return 0; }

static inline struct perf_event *
register_user_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context,
			    struct task_struct *tsk)	{ return NULL; }
static inline int
modify_user_hw_breakpoint(struct perf_event *bp,
			  struct perf_event_attr *attr)	{ return -ENOSYS; }
static inline int
modify_user_hw_breakpoint_check(struct perf_event *bp, struct perf_event_attr *attr,
				bool check)	{ return -ENOSYS; }

static inline struct perf_event *
register_wide_hw_breakpoint_cpu(struct perf_event_attr *attr,
				perf_overflow_handler_t	 triggered,
				void *context,
				int cpu)		{ return NULL; }
static inline struct perf_event * __percpu *
register_wide_hw_breakpoint(struct perf_event_attr *attr,
			    perf_overflow_handler_t triggered,
			    void *context)		{ return NULL; }
static inline int
register_perf_hw_breakpoint(struct perf_event *bp)	{ return -ENOSYS; }
static inline void unregister_hw_breakpoint(struct perf_event *bp)	{ }
static inline void
unregister_wide_hw_breakpoint(struct perf_event * __percpu *cpu_events)	{ }
static inline int
reserve_bp_slot(struct perf_event *bp)			{return -ENOSYS; }
static inline void release_bp_slot(struct perf_event *bp) 		{ }

static inline void flush_ptrace_hw_breakpoint(struct task_struct *tsk)	{ }

static inline struct arch_hw_breakpoint *counter_arch_bp(struct perf_event *bp)
{
	return NULL;
}

#endif /* _LINUX_HW_BREAKPOINT_H */
