/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM rcu

#if !defined(_TRACE_RCU_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_RCU_H

#include <linux/tracepoint.h>

#ifdef CONFIG_RCU_TRACE
#define TRACE_EVENT_RCU TRACE_EVENT
#else
#define TRACE_EVENT_RCU TRACE_EVENT_NOP
#endif

#if defined(CONFIG_TREE_RCU)

#ifdef CONFIG_RCU_NOCB_CPU
#endif


#endif /* #if defined(CONFIG_TREE_RCU) */

#endif /* _TRACE_RCU_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
