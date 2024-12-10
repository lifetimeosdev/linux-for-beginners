/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM signal

#if !defined(_TRACE_SIGNAL_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_SIGNAL_H

#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/tracepoint.h>

#define TP_STORE_SIGINFO(__entry, info)				\
	do {							\
		if (info == SEND_SIG_NOINFO) {			\
			__entry->errno	= 0;			\
			__entry->code	= SI_USER;		\
		} else if (info == SEND_SIG_PRIV) {		\
			__entry->errno	= 0;			\
			__entry->code	= SI_KERNEL;		\
		} else {					\
			__entry->errno	= info->si_errno;	\
			__entry->code	= info->si_code;	\
		}						\
	} while (0)

#ifndef TRACE_HEADER_MULTI_READ
enum {
	TRACE_SIGNAL_DELIVERED,
	TRACE_SIGNAL_IGNORED,
	TRACE_SIGNAL_ALREADY_PENDING,
	TRACE_SIGNAL_OVERFLOW_FAIL,
	TRACE_SIGNAL_LOSE_INFO,
};
#endif

#endif /* _TRACE_SIGNAL_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
