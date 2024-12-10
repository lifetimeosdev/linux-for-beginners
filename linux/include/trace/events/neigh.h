#undef TRACE_SYSTEM
#define TRACE_SYSTEM neigh

#if !defined(_TRACE_NEIGH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NEIGH_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/tracepoint.h>
#include <net/neighbour.h>

#define neigh_state_str(state)				\
	__print_symbolic(state,				\
		{ NUD_INCOMPLETE, "incomplete" },	\
		{ NUD_REACHABLE, "reachable" },		\
		{ NUD_STALE, "stale" },			\
		{ NUD_DELAY, "delay" },			\
		{ NUD_PROBE, "probe" },			\
		{ NUD_FAILED, "failed" },		\
		{ NUD_NOARP, "noarp" },			\
		{ NUD_PERMANENT, "permanent"})

#endif /* _TRACE_NEIGH_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
