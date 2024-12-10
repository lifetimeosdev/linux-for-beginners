/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM raw_syscalls
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE syscalls

#if !defined(_TRACE_EVENTS_SYSCALLS_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_EVENTS_SYSCALLS_H

#include <linux/tracepoint.h>

#include <asm/ptrace.h>
#include <asm/syscall.h>

#endif /* _TRACE_EVENTS_SYSCALLS_H */

/* This part must be outside protection */
#include <trace/define_trace.h>

