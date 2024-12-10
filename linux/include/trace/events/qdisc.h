#undef TRACE_SYSTEM
#define TRACE_SYSTEM qdisc

#if !defined(_TRACE_QDISC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_QDISC_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/tracepoint.h>
#include <linux/ftrace.h>
#include <linux/pkt_sched.h>
#include <net/sch_generic.h>

#endif /* _TRACE_QDISC_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
