/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM irq

#if !defined(_TRACE_IRQ_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_IRQ_H

#include <linux/tracepoint.h>

struct irqaction;
struct softirq_action;

#define SOFTIRQ_NAME_LIST				\
			 softirq_name(HI)		\
			 softirq_name(TIMER)		\
			 softirq_name(NET_TX)		\
			 softirq_name(NET_RX)		\
			 softirq_name(BLOCK)		\
			 softirq_name(IRQ_POLL)		\
			 softirq_name(TASKLET)		\
			 softirq_name(SCHED)		\
			 softirq_name(HRTIMER)		\
			 softirq_name_end(RCU)

#undef softirq_name
#undef softirq_name_end

#define softirq_name(sirq) TRACE_DEFINE_ENUM(sirq##_SOFTIRQ);
#define softirq_name_end(sirq)  TRACE_DEFINE_ENUM(sirq##_SOFTIRQ);

SOFTIRQ_NAME_LIST

#undef softirq_name
#undef softirq_name_end

#define softirq_name(sirq) { sirq##_SOFTIRQ, #sirq },
#define softirq_name_end(sirq) { sirq##_SOFTIRQ, #sirq }

#define show_softirq_name(val)				\
	__print_symbolic(val, SOFTIRQ_NAME_LIST)

#endif /*  _TRACE_IRQ_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
